"""Self-hosting step S15b.1 (ADR-288): the store verifier's object rejections rendered as exact diagnostics by XAX.

The store verifier (``xax_selfhost_verify``) decides every object rejection and records it as a site and payload
words; until now the host rendered those words into the bootstrap's diagnostic (``object_diagnostic``,
``object_entity``, ``_xax_verify_store``).  Its last phase now renders them itself: for every rejected object it
writes the diagnostic record (``xax_selfhost_diagnostics`` values) into a bank in its output view, and the store's
own rejection (a cycle, unreachable objects) after them.  The bank is what the general compiler driver reports; the
host only decodes words.

Bank layout (output-view words):

* ``BANK_CURSOR``: the next free record word; ``BANK_BAD``: set while a record quotes an index that names no stored
  object (the verifier recorded ``NONE`` where the bootstrap fails earlier, on the missing object); that record is
  dropped.
* ``INDEX_AT + INDEX_WORDS * o`` for object ``o`` (``o = O``: the store): the record's start, its middle, its end,
  the entity's mode, and its value.  Start 0: no record (no rejection, or one this phase does not render).
  A record is its code value (start .. middle), then its rule, expected, and actual values (middle .. end); the
  entity is not in it: ``ENTITY_OBJECT`` names object ``value``, ``ENTITY_MISSING`` reference ``value % 2**32`` of
  object ``value // 2**32`` (a reference no stored object has, so only the reader of the store knows its CID), and
  ``ENTITY_STORE`` the text ``store``.
* Records from ``BANK_AT``; a record that would pass ``BANK_END`` is dropped (start 0).

Rendering only quotes what the verifier recorded or what the object table holds; each site's code, rule, and the
shape of its values are the bootstrap's (``object_diagnostic`` and its helpers).  Store order is CID order (the
container requires it), so sorting CIDs is sorting object indices.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
import xax_selfhost_verify as V
from xax_compiler import BOARD_PROFILE, JVM_ARCHITECTURE, RISCV64_ARCHITECTURE, SPIRV_ARCHITECTURE, Kind
from xax_selfhost_facts import NONE, E, _function

BANK_CURSOR = 7 << 20
BANK_BAD = BANK_CURSOR + 1  # set when a record would quote an object the table does not hold
INDEX_AT, INDEX_WORDS = (7 << 20) + 8, 5
BANK_AT, BANK_END = 8 << 20, 11 << 20  # BANK_END itself absorbs dropped words
ENTITY_OBJECT, ENTITY_MISSING, ENTITY_STORE = 0, 1, 2
ENUM = {name: index for index, name in enumerate(D.ENUM_NAMES)}
OBJECT = {name: index for index, name in enumerate(D.OBJECT_NAMES)}
SITE = V.S
assert V.REJECTS_AT + V.REJECT_WORDS * (1 << 16) <= V.GRAPHS_AT and V.GRAPHS_AT + (1 << 17) <= BANK_CURSOR
assert INDEX_AT + INDEX_WORDS * ((1 << 16) + 1) <= BANK_AT and BANK_END < V.ARENA_AT


class VerifierTable:
    """The store verifier's object table (its input view, records located by ``G_REC``)."""

    def __init__(self, e: E):
        self.e = e

    def objects(self):
        return V._g(self.e, V.G_O)

    def kind(self, o):
        return V._kind(self.e, o)

    def references(self, o):
        return V._references(self.e, o)

    def reference(self, o, k):
        return V._reference(self.e, o, k)

    def cid_word(self, o, k):
        return V._cid_word(self.e, o, k)

    def body(self, o):
        return body_at(self.e, o)


class Writer:
    """Values written at a record cursor (``xax_selfhost_diagnostics`` tags): by default the bank's, quoting the
    verifier's object table."""

    def __init__(self, e: E, table=None, cursor: int = BANK_CURSOR, end: int = BANK_END, bad: int = BANK_BAD, functions=None):
        self.e = e
        self.table = table if table is not None else VerifierTable(e)
        self.cursor, self.end, self.bad = cursor, end, bad
        self.functions = functions if functions is not None else _FN
        self.serial = 0

    def fresh(self, prefix: str) -> str:
        self.serial += 1
        return f"{prefix}{self.serial}"

    def put(self, value):
        """One word at the cursor (``put_function``: a call, so a record's many words stay small)."""
        self.e.call(self.functions["put"], value)

    def text(self, value: str):
        data = value.encode("ascii")
        self.put(D.T_STR)
        self.put(len(data))
        for start in range(0, len(data), 8):
            self.put(int.from_bytes(data[start:start + 8], "little"))

    def const(self, value):
        """A Python constant: text, integer (an enumeration member keeps its class), None, bool, list, or tuple."""
        if isinstance(value, str):
            self.text(value)
        elif value is None:
            self.put(D.T_NONE)
        elif isinstance(value, bool):
            self.put(D.T_BOOL)
            self.put(int(value))
        elif isinstance(value, int) and type(value).__name__ in ENUM:
            self.member(type(value).__name__, int(value))
        elif isinstance(value, int):
            self.integer(int(value))
        else:
            self.put(D.T_TUPLE if isinstance(value, tuple) else D.T_LIST)
            self.put(len(value))
            for item in value:
                self.const(item)

    def integer(self, value):
        self.put(D.T_INT)
        self.put(value)

    def tagged(self, tag: int, *words):
        self.put(tag)
        for word in words:
            self.put(word)

    def name(self, enum: str, value):
        self.tagged(D.T_NAME, ENUM[enum], value)

    def member(self, enum: str, value):
        self.tagged(D.T_ENUM, ENUM[enum], value)

    def fmt(self, template: str, *values):
        self.put(D.T_FORMAT)
        self.text(template)
        self.put(len(values))
        for value in values:
            self.integer(value)

    def check(self, o):
        """Mark the record bad when ``o`` names no stored object."""
        e = self.e
        e.if_(e.le(self.table.objects(), o), lambda: e.st(self.bad, 1))

    def cid(self, o):
        self.e.call(self.functions["cid"], o)

    def seq(self, tag: int, count, item):
        """A list (``tag`` T_LIST) or tuple of ``count`` values; ``item(i)`` writes value ``i``."""
        e = self.e
        name = self.fresh("sq")
        self.put(tag)
        self.put(count)
        e.for_(name, 0, count, lambda: item(e.p[name]))

    def packed(self, tag: int, length, emit):
        """HEX or BYTES of ``length`` bytes; ``emit(byte)`` calls ``byte(value)`` for each byte in order."""
        e, p = self.e, self.e.p
        self.put(tag)
        self.put(length)
        e.var("pk_acc", 0)
        e.var("pk_mul", 1)
        e.var("pk_n", 0)

        def byte(value):
            e.set("pk_acc", e.add(p["pk_acc"], e.mul(value, p["pk_mul"])))
            e.set("pk_mul", e.mul(p["pk_mul"], 256))
            e.set("pk_n", e.add(p["pk_n"], 1))
            e.if_(e.eq(e.and_(p["pk_n"], 7), 0), lambda: (self.put(p["pk_acc"]), e.set("pk_acc", 0), e.set("pk_mul", 1)))

        emit(byte)
        e.if_(e.ne(e.and_(p["pk_n"], 7), 0), lambda: self.put(p["pk_acc"]))

    def body_bytes(self, tag: int, o, offset, length):
        """``obj.body[offset:offset + length]`` as HEX or BYTES."""
        e = self.e
        name = self.fresh("bb")
        self.packed(tag, length, lambda byte: e.for_(name, 0, length, lambda: byte(e.rd(e.add(self.table.body(o), e.add(offset, e.p[name]))))))

    def cid_bytes(self, o, prefix: bytes = b""):
        """``prefix + objects[o].cid`` as BYTES."""
        e = self.e
        self.check(o)

        def emit(byte):
            for value in prefix:
                byte(value)
            for k in range(4):
                word = self.table.cid_word(o, k)
                for j in range(8):
                    byte(e.and_(e.udiv(word, 1 << (8 * (7 - j))), 255))

        self.packed(D.T_BYTES, len(prefix) + 32, emit)


_FN: dict = {}  # the verifier's writer functions (``add_functions``)


def put_function(cursor: int, end: int):
    """``put(value)``: the value at the record cursor (past ``end`` it is dropped on the word ``end``), cursor + 1."""
    def build(e: E):
        p = e.p
        at = e.ld(cursor)
        e.var("at", at)
        e.st(e.sel(e.lt(p["at"], end), p["at"], end), p["value"])
        e.st(cursor, e.add(p["at"], 1))
        e.give(0)
    return _function(("value",), build, None)


def cid_function(table_of, functions):
    """``cid(o)``: object ``o``'s CID value (the record marked bad when ``o`` names no stored object)."""
    def build(e: E):
        p = e.p
        w = Writer(e, table_of(e), functions=functions)
        w.check(p["o"])
        w.put(D.T_CID)
        for k in range(4):
            w.put(w.table.cid_word(p["o"], k))
        e.give(0)
    return build


def body_at(e: E, o):
    """The input-view word of object ``o``'s first body byte (after a graph's decoder stream)."""
    payload = V._payload(e, o)
    stream_end = e.add(payload, e.rd(e.sub(payload, 1)))
    return e.sel(e.eq(V._kind(e, o), int(Kind.GRAPH_FRAGMENT)), e.add(stream_end, 1), payload)


def _references_sorted(w: Writer, o, counts, marks=None, unique=False):
    """``sorted(objects[r].cid.hex() for r in o's references [if marked])`` as a list of CIDs (``unique``: of the set)."""
    e, p = w.e, w.e.p
    refs = V._references(e, o)
    k, q = w.fresh("rk"), w.fresh("rq")
    selected = (lambda: e.ne(e.ld(e.add(e.add(marks, 1), p[k])), 0)) if marks is not None else (lambda: e.eq(0, 0))

    def count():
        target = V._reference(e, o, p[k])
        e.if_(selected(), lambda: e.st(e.add(counts, target), e.add(e.ld(e.add(counts, target)), 1)))

    e.for_(k, 0, refs, count)
    total = w.fresh("rt")
    e.var(total, 0)
    e.for_(q, 0, V._g(e, V.G_O), lambda: e.set(total, e.add(p[total], e.sel(e.ne(e.ld(e.add(counts, p[q])), 0),
                                                                            1 if unique else e.ld(e.add(counts, p[q])), 0))))
    w.put(D.T_LIST)
    w.put(p[total])
    q2, m = w.fresh("rq"), w.fresh("rm")

    def emit():
        e.var(m, e.sel(e.ne(e.ld(e.add(counts, p[q2])), 0), 1 if unique else e.ld(e.add(counts, p[q2])), 0))
        e.for_(w.fresh("rr"), 0, p[m], lambda: w.cid(p[q2]))
        e.st(e.add(counts, p[q2]), 0)

    e.for_(q2, 0, V._g(e, V.G_O), emit)


def _cids(w: Writer, at, count):
    """``[objects[i].cid.hex() for i in ld(at .. at + count)]``."""
    w.seq(D.T_LIST, count, lambda i: w.cid(w.e.ld(w.e.add(at, i))))


def _ints(w: Writer, tag: int, at, count, enum: str | None = None):
    e = w.e
    if enum is None:
        w.seq(tag, count, lambda i: w.integer(e.ld(e.add(at, i))))
    else:
        w.seq(tag, count, lambda i: w.member(enum, e.ld(e.add(at, i))))


def _pair(w: Writer, at):
    """``[n, words n, m, words m]`` at ``at``: the two CID lists."""
    e = w.e
    first = e.ld(at)
    _cids(w, e.add(at, 1), first)
    second_at = e.add(e.add(at, 1), first)
    _cids(w, e.add(second_at, 1), e.ld(second_at))


TRAILING = "XAX.CANON.TRAILING_BYTES"


def _simple(tables):
    """The structural object sites (lists, contracts, functions, groups, graphs, ULEBs, cursor faults, build enums)."""
    def build(e: E):
        p = e.p
        w = Writer(e)
        o, site = p["o"], p["site"]
        at = e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS))
        for k in range(7):
            e.var(f"x{k}", e.ld(e.add(at, k + 1)))
        x, y, z = p["x0"], p["x1"], p["x2"]
        cases = {}

        def case(name):
            def register(body):
                cases[name] = body
                return body
            return register

        def four(code, rule, expected, actual):
            w.text(code)
            e.st(e.add(INDEX_AT, e.add(e.mul(o, INDEX_WORDS), 1)), e.ld(BANK_CURSOR))
            w.text(rule)
            expected()
            actual()

        less = lambda value: lambda: w.fmt("< {}", value)  # noqa: E731
        integer = lambda value: lambda: w.integer(value)  # noqa: E731
        const = lambda value: lambda: w.const(value)  # noqa: E731

        def listed(at, tag=D.T_TUPLE):
            return lambda: _ints(w, tag, e.add(at, 1), e.ld(at))

        def unused(unique):
            return lambda: four("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", lambda: _references_sorted(w, o, p["counts"]),
                                lambda: _references_sorted(w, o, p["counts"], x if not unique else y, unique))

        case("LIST_TRAILING")(lambda: four(TRAILING, "SCHEMA-BODY", const(0), integer(x)))
        case("LIST_REF_INDEX")(lambda: four("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", less(x), listed(y)))
        case("LIST_REFERENCE_BODY")(lambda: four("XAX.CANON.REFERENCE_BODY", "SER-REF-BODY-CANONICAL",
                                                 lambda: w.seq(D.T_TUPLE, x, lambda i: w.integer(i)), listed(y)))

        def child_kind():
            module = sorted(kind.name for kind in V.MODULE_CHILDREN)
            four("XAX.STRUCT.CHILD_KIND", "GRAPH-CHILD-KIND",
                 lambda: e.if_(e.eq(V._kind(e, o), int(Kind.MODULE)), lambda: w.const(module), lambda: w.const([Kind.MODULE.name])),
                 lambda: w.name("Kind", x))

        case("LIST_CHILD_KIND")(child_kind)
        case("CONTRACT_REF_INDEX")(lambda: four("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", less(x), integer(y)))
        case("CONTRACT_TRUNCATED")(lambda: four("XAX.CANON.TRUNCATED", "SER-BOUNDS", const("1 available bytes"), const(0)))
        case("CONTRACT_BOOL")(lambda: four("XAX.CANON.BOOL", "SER-BOOL-CANONICAL", const("00 or 01"), lambda: w.fmt("{:02x}", x)))
        case("CONTRACT_TRAILING")(lambda: four(TRAILING, "CALL-CONTRACT-BODY", const(0), integer(x)))
        # CONTRACT_UNUSED keeps duplicates; the others quote the set of used references.
        cases["CONTRACT_UNUSED"] = lambda: four("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", lambda: _references_sorted(w, o, p["counts"]),
                                                lambda: _references_sorted(w, o, p["counts"], x))
        case("FUNCTION_REF_INDEX")(lambda: four("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", less(x), integer(y)))
        case("FUNCTION_MEMBER_RANGE")(lambda: four("XAX.STRUCT.RECURSION_MEMBER", "GRAPH-RECURSION-MEMBER", less(x), integer(y)))
        case("FUNCTION_MEMBER_TRAILING")(lambda: four(TRAILING, "FUNCTION-GROUP-MEMBER-BODY", const(0), integer(x)))
        case("FUNCTION_TRAILING")(lambda: four(TRAILING, "FUNCTION-BODY", const(0), integer(x)))
        carrier = lambda: four("XAX.STRUCT.FUNCTION_GRAPH", "GRAPH-FUNCTION-CARRIER", const(Kind.GRAPH_FRAGMENT.name), lambda: w.name("Kind", x))  # noqa: E731
        cases["FUNCTION_CARRIER"] = carrier
        cases["GROUP_CARRIER"] = carrier
        for prefix, at_word in (("FUNCTION", y), ("GROUP", y)):
            cases[f"{prefix}_ENTRY_CONTRACT"] = lambda at_word=at_word: four("XAX.STRUCT.ENTRY_CONTRACT", "GRAPH-ENTRY-CONTRACT", *_pair_values(w, at_word))
            cases[f"{prefix}_RETURN_CONTRACT"] = lambda at_word=at_word: four("XAX.STRUCT.RETURN_CONTRACT", "GRAPH-RETURN-CONTRACT", *_pair_values(w, at_word))
        cases["FUNCTION_UNUSED"] = lambda: four("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", lambda: _references_sorted(w, o, p["counts"]),
                                                lambda: _references_sorted(w, o, p["counts"], y, True))
        case("FUNCTION_GROUP_CONTEXT")(lambda: four("XAX.STRUCT.GROUP_CALL_CONTEXT", "GRAPH-GROUP-CALL-CONTEXT", const(Kind.RECURSION_GROUP.name),
                                                    const(Kind.FUNCTION.name)))
        case("GROUP_EMPTY")(lambda: four("XAX.STRUCT.RECURSION_GROUP_EMPTY", "GRAPH-RECURSION-GROUP-NONEMPTY", const(">= 1"), const(0)))
        case("GROUP_REF_INDEX")(lambda: four("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", less(x), integer(y)))
        case("GROUP_TRAILING")(lambda: four(TRAILING, "RECURSION-GROUP-BODY", const(0), integer(x)))
        cases["GROUP_UNUSED"] = lambda: four("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", lambda: _references_sorted(w, o, p["counts"]),
                                             lambda: _references_sorted(w, o, p["counts"], x, True))
        cases["GRAPH_UNUSED"] = cases["GROUP_UNUSED"]
        case("GROUP_MEMBER_RANGE")(lambda: four("XAX.STRUCT.RECURSION_MEMBER", "GRAPH-RECURSION-MEMBER", lambda: w.fmt("< {}", e.ld(z)), integer(y)))

        def call_contract():
            e.var("cc_at", y)

            def part():
                n = e.ld(p["cc_at"])
                e.var("cc_n", n)
                _cids(w, e.add(p["cc_at"], 1), p["cc_n"])
                e.set("cc_at", e.add(e.add(p["cc_at"], 1), p["cc_n"]))

            def two():
                w.put(D.T_LIST)
                w.put(2)
                part()
                part()

            four("XAX.STRUCT.CALL_CONTRACT", "GRAPH-CALL-CONTRACT", two, two)

        case("GROUP_CALL_CONTRACT")(call_contract)

        def order():
            count = e.ld(y)
            four("XAX.CANON.RECURSION_ORDER", "GRAPH-RECURSION-ORDER", lambda: _ints(w, D.T_LIST, e.add(y, 1), count),
                 lambda: w.seq(D.T_LIST, count, lambda i: w.integer(i)))

        case("GROUP_ORDER")(order)

        def scc():
            def calls():
                e.var("sc_at", e.add(y, 1))

                def member(_i):
                    e.var("sc_n", e.ld(p["sc_at"]))
                    _ints(w, D.T_LIST, e.add(p["sc_at"], 1), p["sc_n"])
                    e.set("sc_at", e.add(e.add(p["sc_at"], 1), p["sc_n"]))

                w.seq(D.T_LIST, e.ld(y), member)

            four("XAX.STRUCT.RECURSION_SCC", "GRAPH-RECURSION-SCC", const("one recursive strongly connected component"), calls)

        case("GROUP_SCC")(scc)

        def trap():
            def error():
                for k, message in enumerate(V.TRAP_ERRORS):
                    e.if_(e.eq(x, k + 1), lambda message=message: w.text(message))

            four("XAX.CONTROL.TRAP_PAYLOAD", "TRAP-PAYLOAD-CANONICAL", const("empty or canonical u16 ULEB reason with optional target bytes"), error)

        case("GRAPH_TRAP_PAYLOAD")(trap)

        def uleb():
            def expected():
                e.if_(e.eq(x, 1), lambda: w.text("terminating byte"))
                e.if_(e.eq(x, 3), lambda: w.text("at most 10 bytes"))
                e.if_(e.eq(x, 2), minimal)

            def minimal():
                # ``uleb(value)``: the encoding without its trailing zero groups.
                e.var("ul_last", 0)
                e.for_("ul_k", 0, z, lambda: e.if_(e.ne(e.and_(e.rd(e.add(body_at(e, o), e.add(y, p["ul_k"]))), 127), 0),
                                                    lambda: e.set("ul_last", p["ul_k"])))
                w.packed(D.T_HEX, e.add(p["ul_last"], 1), lambda byte: e.for_("ul_q", 0, e.add(p["ul_last"], 1), lambda: byte(e.sel(
                    e.eq(p["ul_q"], p["ul_last"]), e.and_(e.rd(e.add(body_at(e, o), e.add(y, p["ul_q"]))), 127),
                    e.rd(e.add(body_at(e, o), e.add(y, p["ul_q"])))))))

            def actual():
                e.if_(e.eq(x, 1), lambda: w.text("end of input"))
                e.if_(e.eq(x, 3), lambda: w.text("more than 10 bytes"))
                e.if_(e.eq(x, 2), lambda: w.body_bytes(D.T_HEX, o, y, z))

            for status, (code, rule) in enumerate(V.ULEB_FAULTS, 1):
                e.if_(e.eq(x, status), lambda code=code, rule=rule: four(code, rule, expected, actual))

        case("BODY_ULEB")(uleb)
        case("OBJECT_MISSING")(lambda: four("XAX.IDENTITY.OBJECT_MISSING", "ID-REFERENCE-RESOLVED", const("stored object"), const("missing")))
        case("BODY_TAKE")(lambda: four("XAX.CANON.TRUNCATED", "SER-BOUNDS", lambda: w.fmt("{} available bytes", x), integer(y)))
        case("BODY_BOOL")(lambda: four("XAX.CANON.BOOL", "SER-BOOL-CANONICAL", const("00 or 01"), lambda: w.fmt("{:02x}", x)))

        def trailing():
            for k, rule in enumerate(V.BODY_RULES):
                e.if_(e.eq(x, k), lambda rule=rule: four(TRAILING, rule, const(0), integer(y)))

        case("BODY_TRAILING")(trailing)
        case("BUILD_REF_INDEX")(lambda: four("XAX.STRUCT.REF_INDEX", "BUILD-REF-INDEX", less(x), integer(y)))

        def build_enum():
            import xax_build

            for k, name in enumerate(V.BUILD_ENUMS):
                rule = ("BUILD-FORM", "BUILD-MODE", "BUILD-CAPABILITY-KIND", "BUILD-ARTIFACT-KIND", "OPT-OBJECTIVE")[k]
                values = sorted(item.value for item in getattr(xax_build, name))
                e.if_(e.eq(x, k + 1), lambda rule=rule, values=values: four("XAX.BUILD.ENUM", rule, const(values), integer(y)))

        case("BUILD_ENUM")(build_enum)
        case("BUILD_KIND_OF")(lambda: four("XAX.BUILD.KIND", "BUILD-KIND", const(Kind.BUILD.name), lambda: w.name("Kind", V._kind(e, x))))
        for name, body in cases.items():
            e.if_(e.eq(site, SITE[name]), body)
        e.give(e.flag(e.either(*(e.eq(site, SITE[name]) for name in cases))))
    return _function(("o", "site", "counts"), build, tables)


def _pair_values(w: Writer, at):
    """The expected and actual CID lists of a contract mismatch's ``[n, words, m, words]``."""
    e = w.e
    return (lambda: _cids(w, e.add(at, 1), e.ld(at)),
            lambda: _cids(w, e.add(e.add(at, 2), e.ld(at)), e.ld(e.add(e.add(at, 1), e.ld(at)))))


# -- targets (``_target_diagnostic``, ``_target_section_diagnostic``, ``_target_rule_diagnostic``) --------------------

def _target(tables):
    import xax_compiler as X

    def build(e: E):
        p = e.p
        w = Writer(e)
        o, site = p["o"], p["site"]
        at = e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS))
        for k in range(7):
            e.var(f"x{k}", e.ld(e.add(at, k + 1)))
        x, y = p["x0"], p["x1"]

        def four(code, rule, expected, actual):
            w.text(code)
            e.st(e.add(INDEX_AT, e.add(e.mul(o, INDEX_WORDS), 1)), e.ld(BANK_CURSOR))
            w.text(rule)
            expected()
            actual()

        const = lambda value: lambda: w.const(value)  # noqa: E731
        integer = lambda value: lambda: w.integer(value)  # noqa: E731
        cases = {}
        cases["TARGET_REFERENCES"] = lambda: four("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", const([]), lambda: w.seq(
            D.T_LIST, V._references(e, o), lambda k: w.cid(V._reference(e, o, k))))
        cases["TARGET_IDENTITY_TRUNCATED"] = lambda: four("XAX.CANON.TRUNCATED", "SER-BOUNDS", lambda: w.fmt("{} available bytes", x), integer(y))
        cases["TARGET_IDENTITY_EMPTY"] = lambda: four("XAX.STRUCT.TARGET_IDENTITY", "TARGET-IDENTITY-NONEMPTY", const(">= 1 byte"), const(0))
        cases["TARGET_ARCHITECTURE"] = lambda: four("XAX.TARGET.ARCHITECTURE", "TARGET-ARCHITECTURE-SUPPORTED",
                                                    const([1, 2, 3, 4, X.JVM_ARCHITECTURE, X.RISCV64_ARCHITECTURE, X.SPIRV_ARCHITECTURE]), integer(x))
        cases["TARGET_TRAILING"] = lambda: four(TRAILING, "TARGET-NATIVE-BODY", const(0), integer(x))
        cases["TARGET_PROFILE"] = lambda: four("XAX.TARGET.PROFILE", "TARGET-PROFILE-SUPPORTED", const([1, 2, 3, 4, X.BOARD_PROFILE]), integer(x))
        machine = lambda k: e.ld(e.add(x, k))  # noqa: E731  profile, abi, format, word, pointer, stack, shadow

        def fields(*ks):
            return lambda: (w.put(D.T_LIST), w.put(len(ks)), [w.integer(machine(k)) for k in ks])

        x86 = ((1, 1, 64, 64, 16, 32), (X.X86_64_LINUX_ABI, X.X86_64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 32),
               (X.X86_64_LINUX_ABI, X.X86_64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 32))
        cases["TARGET_X86_64"] = lambda: four("XAX.TARGET.MACHINE", "TARGET-X86-64-PROFILE", const([list(item) for item in x86]), fields(1, 2, 3, 4, 5, 6))
        aarch64 = ((3, 1, 64, 64, 16, 0), (4, X.ANDROID_ELF_FORMAT, 64, 64, 16, 0), (4, X.ANDROID_ELF_PACKED_FORMAT, 64, 64, 16, 0),
                   (X.AARCH64_LINUX_ABI, X.AARCH64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 0), (X.AARCH64_LINUX_ABI, X.AARCH64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 0),
                   (3, X.AARCH64_BOARD_ELF_FORMAT, 64, 64, 16, 0))
        cases["TARGET_AARCH64"] = lambda: four("XAX.TARGET.MACHINE", "TARGET-AARCH64-PROFILE", const([list(item) for item in aarch64]), fields(1, 2, 3, 4, 5, 6))
        cases["TARGET_ANDROID"] = lambda: four("XAX.TARGET.MACHINE", "TARGET-ANDROID-PROFILE", const(4), lambda: w.integer(machine(0)))
        cases["TARGET_AARCH64_LINUX"] = lambda: four("XAX.TARGET.MACHINE", "TARGET-AARCH64-LINUX-PROFILE", const(1), lambda: w.integer(machine(0)))
        cases["TARGET_BAREMETAL"] = lambda: four("XAX.TARGET.MACHINE", "TARGET-AARCH64-BAREMETAL-PROFILE", const([1, 2, X.BOARD_PROFILE]),
                                                 lambda: w.integer(machine(0)))
        cases["TARGET_BOARD"] = lambda: four("XAX.TARGET.MACHINE", "TARGET-AARCH64-BOARD-PROFILE", const("board format with board profile"), fields(2, 0))
        cases["TARGET_WASM32"] = lambda: four("XAX.TARGET.MACHINE", "TARGET-WASM32-CORE", const([2, 2, 64, 32]), fields(1, 2, 3, 4))
        for name, rule, expected in (("TARGET_RISCV64", "TARGET-RISCV64-RAW", [1, X.RISCV64_LP64_ABI, X.RISCV64_RAW_FORMAT, 64, 64]),
                                     ("TARGET_SPIRV", "TARGET-SPIRV-COMPUTE", [1, X.SPIRV_VULKAN_ABI, X.SPIRV_MODULE_FORMAT, 32, 32]),
                                     ("TARGET_JVM", "TARGET-JVM-CLASSFILE", [1, X.JVM_ABI, X.JVM_JAR_FORMAT, 64, 64]),
                                     ("TARGET_ACCELERATOR", "TARGET-ACCELERATOR-PROFILE", [3, 4, 3, 32, 64])):
            cases[name] = lambda rule=rule, expected=expected: four("XAX.TARGET.MACHINE", rule, const(expected), fields(0, 1, 2, 3, 4))

        def section():
            z = p["x2"]
            enums = ("AtomicScope", "AtomicFamily", "EffectDomain", "TargetValueConstraintKind")

            def actual(code):
                for kind, (fault, _rule) in enumerate(V.ULEB_FAULTS, 1):
                    e.if_(e.eq(y, kind), lambda fault=fault: w.text(fault))
                e.if_(e.eq(y, 5), lambda: w.text("XAX.CANON.TRUNCATED"))
                e.if_(e.eq(y, 6), lambda: w.text(code))
                for kind, enum in enumerate(enums, 7):
                    e.if_(e.eq(y, kind), lambda enum=enum: w.fmt("{} is not a valid " + enum, z))

            for number, (code, rule, expected) in enumerate(V.SECTIONS, 1):
                e.if_(e.eq(x, number), lambda code=code, rule=rule, expected=expected: four(code, rule, const(expected), lambda: actual(code)))

        cases["TARGET_SECTION"] = section
        for name, body in cases.items():
            e.if_(e.eq(site, SITE[name]), body)
        e.give(e.flag(e.either(*(e.eq(site, SITE[name]) for name in cases))))
    return _function(("o", "site"), build, tables)


def _target_words(tables):
    """``_target_rule_diagnostic``: the target's recorded words walked as ``target_fields`` reads them."""
    def build(e: E):
        p = e.p
        w = Writer(e)
        o, site = p["o"], p["site"]
        at = e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS))
        for k in range(7):
            e.var(f"x{k}", e.ld(e.add(at, k + 1)))
        words, item, check, sub = p["x0"], p["x2"], p["x3"], p["x4"]
        e.var("tw", e.add(words, 1))  # after the identity length

        def take(name):
            e.var(name, e.ld(p["tw"]))
            e.set("tw", e.add(p["tw"], 1))
            return p[name]

        def many(name):
            """A ``[count, values]`` list: its start (the count word); advances past it."""
            e.var(name, p["tw"])
            e.set("tw", e.add(e.add(p["tw"], 1), e.ld(p[name])))
            return p[name]

        for name in ("profile", "arch", "abi", "format", "word", "pointer"):
            take(f"f_{name}")
        for name in ("args", "scratch", "operations", "terminators", "widths", "scopes", "families", "handlers", "acc_scopes", "spaces", "contracts"):
            e.var(f"at_{name}", 0)
        for name in ("result", "lane", "groups"):
            e.var(f"f_{name}", 0)
        e.if_(e.either(e.eq(p["f_arch"], 1), e.eq(p["f_arch"], 3)), lambda: (
            take("f_stack"), take("f_shadow"), e.set("at_args", many("m_args")), e.set("f_result", take("t_result")),
            e.set("at_scratch", many("m_scratch"))))
        e.set("at_operations", many("m_operations"))
        e.set("at_terminators", many("m_terminators"))

        def handler_skip():
            e.set("tw", e.add(p["tw"], 7))
            many("m_domains")
            e.set("tw", e.add(p["tw"], 2))

        def concurrency():
            e.set("at_widths", many("m_widths"))
            e.set("at_scopes", many("m_scopes"))
            e.set("at_families", many("m_families"))
            e.set("at_handlers", p["tw"])
            e.for_("hk", 0, take("t_handlers"), handler_skip)

        def contract_skip():
            e.set("tw", e.add(p["tw"], 3))
            for _signature in range(2):
                e.var("cn", e.ld(p["tw"]))
                e.set("tw", e.add(e.add(p["tw"], 1), e.mul(p["cn"], 3)))
            many("m_cscopes")
            e.set("tw", e.add(p["tw"], 5))

        def contracts():
            e.set("at_contracts", p["tw"])
            e.for_("ck", 0, take("t_contracts"), contract_skip)

        def space_skip():
            e.set("tw", e.add(p["tw"], 4))
            many("m_swidths")
            many("m_svisible")
            e.set("tw", e.add(p["tw"], 2))

        def accelerator():
            e.set("f_lane", take("t_lane"))
            e.set("f_groups", take("t_groups"))
            e.set("at_acc_scopes", many("m_acc_scopes"))
            e.set("at_spaces", p["tw"])
            e.for_("sk", 0, take("t_spaces"), space_skip)
            contracts()

        e.if_(e.either(e.eq(p["f_profile"], 2), e.eq(p["f_profile"], BOARD_PROFILE)), concurrency)
        e.if_(e.eq(p["f_profile"], 3), accelerator)
        e.if_(e.either(e.eq(p["f_profile"], 4), e.eq(p["f_profile"], BOARD_PROFILE)), contracts)

        def four(code, rule, expected, actual):
            w.text(code)
            e.st(e.add(INDEX_AT, e.add(e.mul(o, INDEX_WORDS), 1)), e.ld(BANK_CURSOR))
            w.text(rule)
            expected()
            actual()

        const = lambda value: lambda: w.const(value)  # noqa: E731

        def values(at_name, tag=D.T_TUPLE, enum=None):
            return lambda: _ints(w, tag, e.add(p[at_name], 1), e.ld(p[at_name]), enum)

        def registers():
            w.put(D.T_LIST)
            w.put(3)
            values("at_args", D.T_LIST)()
            w.integer(p["f_result"])
            values("at_scratch", D.T_LIST)()

        def nth(start: str, index, skip):
            """The word of item ``index`` of the counted list of records at ``p[start]`` (``skip`` passes one)."""
            e.set("tw", e.add(p[start], 1))
            e.for_("nk", 0, index, skip)
            return p["tw"]

        def spaces_ids(tag):
            """The memory spaces' identities (first field of each)."""
            def item(_i):
                w.integer(e.ld(p["tw"]))
                space_skip()

            e.set("tw", e.add(p["at_spaces"], 1))
            w.seq(tag, e.ld(p["at_spaces"]), item)

        def space():
            e.var("sp_at", nth("at_spaces", item, space_skip))
            w.tagged(D.T_OBJECT, OBJECT["AcceleratorMemorySpace"], 8)
            for k in range(4):
                w.integer(e.ld(e.add(p["sp_at"], k)))
            e.var("sp_w", e.add(p["sp_at"], 4))
            _ints(w, D.T_TUPLE, e.add(p["sp_w"], 1), e.ld(p["sp_w"]))
            e.var("sp_v", e.add(e.add(p["sp_w"], 1), e.ld(p["sp_w"])))
            _ints(w, D.T_TUPLE, e.add(p["sp_v"], 1), e.ld(p["sp_v"]), "AtomicScope")
            e.var("sp_f", e.add(e.add(p["sp_v"], 1), e.ld(p["sp_v"])))
            w.tagged(D.T_BOOL, e.ld(p["sp_f"]))
            w.tagged(D.T_BOOL, e.ld(e.add(p["sp_f"], 1)))

        def operation_ids():
            def item(_i):
                w.integer(e.ld(p["tw"]))
                contract_skip()

            e.set("tw", e.add(p["at_contracts"], 1))
            w.seq(D.T_TUPLE, e.ld(p["at_contracts"]), item)

        def sorted_unique_spaces():
            """``sorted(set(space identities))``: ascending, each once."""
            e.var("su_last", 0)
            e.var("su_first", 1)
            e.var("su_count", 0)
            e.var("su_more", 1)

            def smallest():
                """The smallest identity above the last one written (``su_found`` 0: none)."""
                e.var("su_found", 0)
                e.var("su_best", 0)
                e.set("tw", e.add(p["at_spaces"], 1))

                def visit():
                    e.var("su_id", e.ld(p["tw"]))
                    above = e.either(e.ne(p["su_first"], 0), e.lt(p["su_last"], p["su_id"]))
                    e.if_(e.both(above, e.either(e.eq(p["su_found"], 0), e.lt(p["su_id"], p["su_best"]))),
                          lambda: (e.set("su_best", p["su_id"]), e.set("su_found", 1)))
                    space_skip()

                e.for_("su_k", 0, e.ld(p["at_spaces"]), visit)

            def count():
                smallest()
                e.if_(e.ne(p["su_found"], 0), lambda: (e.set("su_count", e.add(p["su_count"], 1)), e.set("su_last", p["su_best"]),
                                                        e.set("su_first", 0)), lambda: e.set("su_more", 0))

            e.while_(lambda: e.ne(p["su_more"], 0), count)
            w.put(D.T_LIST)
            w.put(p["su_count"])
            e.set("su_first", 1)
            e.set("su_last", 0)
            e.for_("su_q", 0, p["su_count"], lambda: (smallest(), w.integer(p["su_best"]), e.set("su_last", p["su_best"]), e.set("su_first", 0)))

        def contract_rule(accelerator: bool):
            code = "XAX.TARGET.OPERATION" if accelerator else "XAX.TARGET.PLATFORM"
            prefix = "TARGET-OPERATION" if accelerator else "TARGET-PLATFORM"
            e.var("ct_at", nth("at_contracts", item, contract_skip))
            ident, semantic, encoding = (e.ld(e.add(p["ct_at"], k)) for k in range(3))
            e.var("ct_ops", e.add(p["ct_at"], 3))  # operand constraints [n, (kind, primary, secondary) ...]
            e.var("ct_res", e.add(e.add(p["ct_ops"], 1), e.mul(e.ld(p["ct_ops"]), 3)))
            e.var("ct_scopes", e.add(e.add(p["ct_res"], 1), e.mul(e.ld(p["ct_res"]), 3)))
            e.var("ct_tail", e.add(e.add(p["ct_scopes"], 1), e.ld(p["ct_scopes"])))  # source, destination, synchronizes, may block, dependency
            e.var("ct_check", check if accelerator else e.sel(e.eq(check, 1), 1, e.sel(e.eq(check, 2), 4, 5)))
            k_ = p["ct_check"]
            if accelerator:
                e.if_(e.eq(k_, 1), lambda: four(code, "TARGET-OPERATION-ENCODING", const("positive semantic code and byte opcode"),
                                                 lambda: (w.put(D.T_LIST), w.put(2), w.integer(semantic), w.integer(encoding))))
                e.if_(e.eq(k_, 2), lambda: four(code, "TARGET-OPERATION-SCOPES", values("at_acc_scopes", enum="AtomicScope"),
                                                 lambda: _ints(w, D.T_TUPLE, e.add(p["ct_scopes"], 1), e.ld(p["ct_scopes"]), "AtomicScope")))
                e.if_(e.eq(k_, 3), lambda: four(code, "TARGET-OPERATION-MEMORY-SPACES", sorted_unique_spaces, lambda: (
                    w.put(D.T_LIST), w.put(2), w.integer(e.ld(p["ct_tail"])), w.integer(e.ld(e.add(p["ct_tail"], 1))))))
            else:
                e.if_(e.eq(k_, 1), lambda: four(code, "TARGET-PLATFORM-OPERATION-CONTRACT", const("positive semantic code and canonical scopes"),
                                                 lambda: w.integer(ident)))

            def constraint():
                at_ = e.add(e.add(p["ct_ops"], 1), e.mul(sub, 3))
                at_ = e.sel(e.lt(sub, e.ld(p["ct_ops"])), at_, e.add(e.add(p["ct_res"], 1), e.mul(e.sub(sub, e.ld(p["ct_ops"])), 3)))
                e.var("cs_at", at_)
                four(code, f"{prefix}-VALUE-CONSTRAINT", const("canonical bits/resource/effect constraint"), lambda: (
                    w.put(D.T_LIST), w.put(3), [w.integer(e.ld(e.add(p["cs_at"], k))) for k in range(3)]))

            e.if_(e.eq(k_, 4), constraint)
            e.if_(e.eq(k_, 5), lambda: four(code, f"{prefix}-RUNTIME-DEPENDENCY", const("empty or 32-byte identity"),
                                             lambda: w.integer(e.ld(e.add(p["ct_tail"], 4)))))

        def handler_field(field_: int):
            def item(_i):
                w.integer(e.ld(e.add(p["tw"], field_)))
                handler_skip()

            e.set("tw", e.add(p["at_handlers"], 1))
            w.seq(D.T_LIST, e.ld(p["at_handlers"]), item)

        def handler():
            e.var("hd_at", nth("at_handlers", item, handler_skip))
            e.var("hd_dom", e.add(p["hd_at"], 7))
            w.put(D.T_LIST)
            w.put(2)
            _ints(w, D.T_TUPLE, e.add(p["hd_dom"], 1), e.ld(p["hd_dom"]), "EffectDomain")
            w.integer(e.ld(e.add(e.add(p["hd_dom"], 1), e.ld(p["hd_dom"]))))

        cases = {
            "TARGET_X86_REGISTERS": lambda: four("XAX.TARGET.ABI", "TARGET-WINDOWS-X64-REGISTERS", const([[1, 2, 8, 9], 0, [10, 11]]), registers),
            "TARGET_AAPCS64_REGISTERS": lambda: four("XAX.TARGET.ABI", "TARGET-AAPCS64-REGISTERS", const([list(range(8)), 0, [9, 10]]), registers),
            "TARGET_ACC_TOPOLOGY": lambda: four("XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-TOPOLOGY", const("positive lane width and max groups"),
                                                lambda: (w.put(D.T_LIST), w.put(2), w.integer(p["f_lane"]), w.integer(p["f_groups"]))),
            "TARGET_ACC_SCOPES": lambda: four("XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-SCOPES-CANONICAL", const("sorted unique nonempty scopes"),
                                              values("at_acc_scopes", enum="AtomicScope")),
            "TARGET_ACC_SPACES": lambda: four("XAX.TARGET.MEMORY_SPACE", "TARGET-MEMORY-SPACES-CANONICAL", const("sorted unique nonempty memory spaces"),
                                              lambda: spaces_ids(D.T_TUPLE)),
            "TARGET_ACC_SPACE": lambda: four("XAX.TARGET.MEMORY_SPACE", "TARGET-MEMORY-SPACE-CONTRACT",
                                             const("positive widths, power-of-two alignment, canonical widths/scopes"), space),
            "TARGET_ACC_OPERATIONS": lambda: four("XAX.TARGET.OPERATION", "TARGET-OPERATIONS-CONTRACT-CANONICAL",
                                                  const("sorted unique nonempty target operation IDs"), operation_ids),
            "TARGET_PLATFORM_OPERATIONS": lambda: four("XAX.TARGET.PLATFORM", "TARGET-PLATFORM-OPERATIONS-CANONICAL",
                                                       const("sorted unique nonempty target operation IDs"), operation_ids),
            "TARGET_ACC_CONTRACT": lambda: contract_rule(True),
            "TARGET_PLATFORM_CONTRACT": lambda: contract_rule(False),
            "TARGET_OPERATIONS": lambda: four("XAX.TARGET.OPERATIONS", "TARGET-OPERATIONS-CANONICAL", const("sorted supported operation IDs"),
                                              values("at_operations")),
            "TARGET_TERMINATORS": lambda: four("XAX.TARGET.TERMINATORS", "TARGET-TERMINATORS-CANONICAL", const("sorted supported terminator IDs"),
                                               values("at_terminators")),
            "TARGET_ATOMIC_WIDTHS": lambda: four("XAX.TARGET.ATOMICS", "TARGET-ATOMIC-WIDTHS-CANONICAL", const("sorted positive widths"),
                                                 values("at_widths")),
            "TARGET_ATOMIC_CAPABILITIES": lambda: four("XAX.TARGET.ATOMICS", "TARGET-ATOMIC-CAPABILITIES-CANONICAL", const("sorted unique scopes/families"),
                                                       lambda: (w.put(D.T_LIST), w.put(2), values("at_scopes", enum="AtomicScope")(),
                                                                values("at_families", enum="AtomicFamily")())),
            "TARGET_HANDLER_ORDER": lambda: four("XAX.TARGET.HANDLER", "TARGET-HANDLER-ENTRIES-CANONICAL", const("sorted unique event kinds"),
                                                 lambda: handler_field(0)),
            "TARGET_HANDLER": lambda: four("XAX.TARGET.HANDLER", "TARGET-HANDLER-CONTRACT", const("sorted unique effect domains and positive stack bound"),
                                           handler),
        }
        for name, body in cases.items():
            e.if_(e.eq(site, SITE[name]), body)
        e.give(e.flag(e.either(*(e.eq(site, SITE[name]) for name in cases))))
    return _function(("o", "site"), build, tables)


# -- build objects (``_build_rule_diagnostic``, ``_composite_rule_diagnostic``) ---------------------------------------

class _Body:
    """A ULEB cursor over an object's body bytes (input view, one byte per word)."""

    def __init__(self, e: E, name: str):
        self.e, self.name = e, name
        e.var(name, 0)

    def at(self, o):
        self.e.set(self.name, body_at(self.e, o))

    def uleb(self):
        e, p, cur = self.e, self.e.p, self.name
        e.var("bu_value", 0)
        e.var("bu_shift", 1)
        e.var("bu_more", 1)

        def step():
            e.var("bu_byte", e.rd(p[cur]))
            e.set("bu_value", e.add(p["bu_value"], e.mul(e.and_(p["bu_byte"], 127), p["bu_shift"])))
            e.set("bu_shift", e.mul(p["bu_shift"], 128))
            e.set("bu_more", e.flag(e.le(128, p["bu_byte"])))
            e.set(cur, e.add(p[cur], 1))

        e.while_(lambda: e.ne(p["bu_more"], 0), step)
        return p["bu_value"]

    def string(self, prefix: str):
        """``(input word of the first byte, length)`` of a byte string; advances past it."""
        e, p = self.e, self.e.p
        e.var(f"{prefix}_len", self.uleb())
        e.var(f"{prefix}_at", p[self.name])
        e.set(self.name, e.add(p[self.name], p[f"{prefix}_len"]))
        return p[f"{prefix}_at"], p[f"{prefix}_len"]


def _input_bytes(w: Writer, tag: int, start, length):
    """``length`` input-view bytes from word ``start``."""
    e = w.e
    name = w.fresh("ib")
    w.packed(tag, length, lambda byte: e.for_(name, 0, length, lambda: byte(e.rd(e.add(start, e.p[name])))))


def _sorted_objects(w: Writer, counts, count, index):
    """``sorted(objects[index(i)].cid.hex() for i in range(count))`` (duplicates kept) as a list of CIDs."""
    e, p = w.e, w.e.p
    k = w.fresh("so")
    e.for_(k, 0, count, lambda: e.st(e.add(counts, index(p[k])), e.add(e.ld(e.add(counts, index(p[k]))), 1)))
    w.put(D.T_LIST)
    w.put(count)
    q = w.fresh("so")

    def emit():
        e.for_(w.fresh("sr"), 0, e.ld(e.add(counts, p[q])), lambda: w.cid(p[q]))
        e.st(e.add(counts, p[q]), 0)

    e.for_(q, 0, V._g(e, V.G_O), emit)


def _build(tables):
    def build(e: E):
        p = e.p
        w = Writer(e)
        o = p["o"]
        at = e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS))
        for k in range(7):
            e.var(f"x{k}", e.ld(e.add(at, k + 1)))
        rule, item, extra = p["x0"], p["x3"], p["x4"]
        e.var("bw", p["x1"])
        body = body_at(e, o)
        e.var("body", body)

        def take(name):
            e.var(name, e.ld(p["bw"]))
            e.set("bw", e.add(p["bw"], 1))
            return p[name]

        def string(prefix):
            take(f"{prefix}_l")
            take(f"{prefix}_a")
            return e.add(p["body"], p[f"{prefix}_a"]), p[f"{prefix}_l"]

        def four(code, name, expected, actual):
            w.text(code)
            e.st(e.add(INDEX_AT, e.add(e.mul(o, INDEX_WORDS), 1)), e.ld(BANK_CURSOR))
            w.text(name)
            expected()
            actual()
            e.give(1)

        const = lambda value: lambda: w.const(value)  # noqa: E731

        def canonical(name, keys):
            four("XAX.BUILD.CANONICAL", name, const("sorted unique values"), keys)

        def when(number, body_):
            e.if_(e.eq(rule, number), body_)

        def refs_exact():
            marks = item
            e.var("re_n", 0)
            e.for_("re_k", 0, e.ld(marks), lambda: e.if_(e.ne(e.ld(e.add(e.add(marks, 1), p["re_k"])), 0), lambda: e.set("re_n", e.add(p["re_n"], 1))))

            def marked():
                w.put(D.T_TUPLE)
                w.put(p["re_n"])
                e.for_("re_q", 0, e.ld(marks), lambda: e.if_(e.ne(e.ld(e.add(e.add(marks, 1), p["re_q"])), 0), lambda: w.integer(p["re_q"])))

            four("XAX.CANON.UNUSED_REFERENCE", "BUILD-REFS-EXACT", lambda: w.seq(D.T_TUPLE, V._references(e, o), lambda i: w.integer(i)), marked)

        when(V.BUILD_REFS_EXACT, refs_exact)
        e.if_(e.eq(V._kind(e, o), int(Kind.BUILD)), lambda: take("form"))
        when(V.BUILD_IDENTITY, lambda: four("XAX.PACKAGE.IDENTITY", "PACKAGE-LOGICAL-IDENTITY", const("nonempty bytes"), const("empty")))
        when(V.BUILD_MODULES, lambda: four("XAX.PACKAGE.MODULE", "PACKAGE-MODULES", const(">= 1"), const(0)))
        when(V.BUILD_MODULE_KIND, lambda: four("XAX.PACKAGE.MODULE", "PACKAGE-MODULE-KIND", const(Kind.MODULE.name), lambda: w.name("Kind", extra)))
        when(V.BUILD_EXACT_KIND, lambda: four("XAX.PACKAGE.DEPENDENCY", "PACKAGE-EXACT-KIND", const(Kind.PACKAGE.name), lambda: w.name("Kind", extra)))
        when(V.BUILD_DEPENDENCY_FORM, lambda: four("XAX.PACKAGE.DEPENDENCY", "PACKAGE-DEPENDENCY-FORM", const([1, 2]), lambda: w.integer(extra)))

        def package():
            string("identity")
            e.var("modules", take("module_count"))
            e.var("modules_at", p["bw"])
            e.set("bw", e.add(p["bw"], p["modules"]))
            when(V.BUILD_MODULES_CANONICAL, lambda: canonical("PACKAGE-MODULES-CANONICAL", lambda: w.seq(
                D.T_TUPLE, p["modules"], lambda i: w.cid_bytes(V._reference(e, o, e.ld(e.add(p["modules_at"], i)))))))
            e.var("dependencies", take("dependency_count"))
            e.var("dependencies_at", p["bw"])

            def dependency():
                take("dep_form")
                e.if_(e.eq(p["dep_form"], 1), lambda: take("dep_ref"), lambda: string("dep"))

            e.for_("dk", 0, p["dependencies"], dependency)

            def keys():
                e.set("bw", p["dependencies_at"])

                def key(_i):
                    take("dep_form")

                    def logical():
                        start, length = string("dep")
                        e.var("dk_start", start)
                        e.var("dk_size", 1)
                        e.var("dk_v", length)
                        e.while_(lambda: e.le(128, p["dk_v"]), lambda: (e.set("dk_v", e.udiv(p["dk_v"], 128)), e.set("dk_size", e.add(p["dk_size"], 1))))
                        total = e.add(e.add(p["dk_size"], length), 1)
                        w.packed(D.T_BYTES, total, lambda byte: (byte(2), e.for_("dk_q", 0, e.add(p["dk_size"], length), lambda: byte(
                            e.rd(e.add(e.sub(p["dk_start"], p["dk_size"]), p["dk_q"]))))))

                    e.if_(e.eq(p["dep_form"], 1), lambda: w.cid_bytes(V._reference(e, o, take("dep_ref")), b"\x01"), logical)

                w.seq(D.T_TUPLE, p["dependencies"], key)

            when(V.BUILD_DEPENDENCIES_CANONICAL, lambda: canonical("PACKAGE-DEPENDENCIES-CANONICAL", keys))
            for number, expected_kind in enumerate((Kind.FUNCTION, Kind.TYPE, Kind.TYPE)):
                e.var("named", take("named_count"))
                e.var("named_at", p["bw"])

                def named(number=number, expected_kind=expected_kind):
                    e.set("bw", e.add(p["named_at"], e.mul(extra, 3)))
                    start, length = string("nm")
                    e.var("nm_start", start)
                    e.var("nm_child", V._reference(e, o, take("nm_ref")))
                    four("XAX.PACKAGE.SCHEMA", "PACKAGE-NAMED-REFERENCE", const(["nonempty", expected_kind.name]), lambda: (
                        w.put(D.T_LIST), w.put(2), _input_bytes(w, D.T_HEX, p["nm_start"], length), w.name("Kind", V._kind(e, p["nm_child"]))))

                def names(number=number):
                    def name_(i):
                        e.set("bw", e.add(p["named_at"], e.mul(i, 3)))
                        start, length = string("nn")
                        _input_bytes(w, D.T_BYTES, start, length)

                    canonical("PACKAGE-NAMES-CANONICAL", lambda: w.seq(D.T_TUPLE, p["named"], name_))

                e.if_(e.both(e.eq(rule, V.BUILD_NAMED_REFERENCE), e.eq(item, number)), named)
                e.if_(e.both(e.eq(rule, V.BUILD_NAMES_CANONICAL), e.eq(item, number)), names)
                e.set("bw", e.add(p["named_at"], e.mul(p["named"], 3)))
            e.var("capabilities", take("capability_count"))
            e.var("capabilities_at", p["bw"])

            def capability(i):
                e.set("bw", e.add(p["capabilities_at"], e.mul(i, 3)))
                w.tagged(D.T_OBJECT, OBJECT["BuildCapability"], 2)
                w.member("BuildCapabilityKind", take("cap_kind"))
                start, length = string("cap")
                _input_bytes(w, D.T_BYTES, start, length)

            when(V.BUILD_CAPABILITIES_CANONICAL, lambda: canonical("PACKAGE-CAPABILITIES-CANONICAL", lambda: w.seq(
                D.T_TUPLE, p["capabilities"], capability)))

        e.if_(e.eq(V._kind(e, o), int(Kind.PACKAGE)), package)

        def grants():
            e.set("bw", e.add(p["bw"], 3))  # mode, optimization, verification
            e.var("grants", take("grant_count"))
            e.var("grants_at", p["bw"])

            def grant(i):
                e.set("bw", e.add(p["grants_at"], e.mul(i, 5)))
                w.put(D.T_TUPLE)
                w.put(3)
                start, length = string("gi")
                _input_bytes(w, D.T_BYTES, start, length)
                w.member("BuildCapabilityKind", take("gk"))
                start, length = string("gs")
                _input_bytes(w, D.T_BYTES, start, length)

            canonical("BUILD-GRANTS-CANONICAL", lambda: w.seq(D.T_TUPLE, p["grants"], grant))

        when(V.BUILD_GRANTS_CANONICAL, grants)

        def trust():
            e.set("bw", e.add(p["bw"], 2))  # the two flags
            e.var("algorithms", take("algorithm_count"))
            e.var("algorithms_at", p["bw"])
            e.set("bw", e.add(p["bw"], e.mul(p["algorithms"], 2)))
            e.var("signers", take("signer_count"))
            e.var("signers_at", p["bw"])

            def strings(count: str, at_: str):
                def string_(i):
                    e.set("bw", e.add(p[at_], e.mul(i, 2)))
                    start, length = string("ts")
                    _input_bytes(w, D.T_BYTES, start, length)

                return lambda: w.seq(D.T_TUPLE, p[count], string_)

            when(V.BUILD_ALGORITHMS_CANONICAL, lambda: canonical("TRUST-ALGORITHMS-CANONICAL", strings("algorithms", "algorithms_at")))
            when(V.BUILD_SIGNERS_CANONICAL, lambda: canonical("TRUST-SIGNERS-CANONICAL", strings("signers", "signers_at")))
            when(V.BUILD_TRUST_NONEMPTY, lambda: four("XAX.TRUST.EMPTY", "TRUST-IDENTITY-NONEMPTY", const("nonempty identities"), const("empty")))
            when(V.BUILD_TRUST_REQUIRED, lambda: four("XAX.TRUST.EMPTY", "TRUST-REQUIRED-SETS", const("accepted algorithms and signers"), lambda: (
                w.put(D.T_LIST), w.put(2), strings("algorithms", "algorithms_at")(), strings("signers", "signers_at")())))

        e.if_(e.either(*(e.eq(rule, number) for number in (V.BUILD_ALGORITHMS_CANONICAL, V.BUILD_SIGNERS_CANONICAL, V.BUILD_TRUST_NONEMPTY,
                                                           V.BUILD_TRUST_REQUIRED))), trust)

        def signature():
            take("signed")

            def field(_i):
                start, length = string("sf")
                _input_bytes(w, D.T_HEX, start, length)

            four("XAX.TRUST.SIGNATURE", "TRUST-SIGNATURE-NONEMPTY", const("nonempty fields"), lambda: w.seq(D.T_LIST, 3, field))

        when(V.BUILD_SIGNATURE_NONEMPTY, signature)
        when(V.BUILD_OPT_REFERENCES, lambda: four("XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", const([]), lambda: w.seq(
            D.T_LIST, V._references(e, o), lambda k: w.cid(V._reference(e, o, k)))))
        e.give(0)
    return _function(("o",), build, tables)


def _composite(tables):
    def build(e: E):
        p = e.p
        w = Writer(e)
        o, counts = p["o"], p["counts"]
        at = e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS))
        for k in range(7):
            e.var(f"x{k}", e.ld(e.add(at, k + 1)))
        rule, item, extra, more = p["x0"], p["x3"], p["x4"], p["x6"]
        e.var("bw", p["x1"])
        e.var("body", body_at(e, o))
        cursor = _Body(e, "cur")

        def take(name):
            e.var(name, e.ld(p["bw"]))
            e.set("bw", e.add(p["bw"], 1))
            return p[name]

        def string(prefix):
            take(f"{prefix}_l")
            take(f"{prefix}_a")
            return e.add(p["body"], p[f"{prefix}_a"]), p[f"{prefix}_l"]

        def ref(name):
            e.var(name, V._reference(e, o, take(f"{name}_i")))
            return p[name]

        def four(code, name, expected, actual):
            w.text(code)
            e.st(e.add(INDEX_AT, e.add(e.mul(o, INDEX_WORDS), 1)), e.ld(BANK_CURSOR))
            w.text(name)
            expected()
            actual()
            e.give(1)

        const = lambda value: lambda: w.const(value)  # noqa: E731

        def when(number, body_):
            e.if_(e.eq(rule, number), body_)

        def canonical(name, keys):
            four("XAX.BUILD.CANONICAL", name, const("sorted unique values"), keys)

        def names(*values):
            def emit():
                w.put(D.T_LIST)
                w.put(len(values))
                for enum, value in values:
                    w.name(enum, value)
            return emit

        when(V.BUILD_REQUEST_KINDS, lambda: four("XAX.BUILD.REQUEST", "BUILD-REQUEST-REFERENCE-KINDS",
                                                 const([Kind.PACKAGE.name, Kind.TARGET.name, "PROFILE"]),
                                                 names(("Kind", item), ("Kind", extra), ("BuildForm", more))))
        when(V.BUILD_TYPED_VALUE, lambda: four("XAX.BUILD.VALUE", "BUILD-TYPED-VALUE", const(Kind.CONSTANT.name), lambda: w.name("Kind", item)))
        when(V.BUILD_CONSTANT_TYPE, lambda: four("XAX.STRUCT.REF_INDEX", "BUILD-CONSTANT-TYPE", lambda: w.fmt("< {}", item), lambda: w.integer(extra)))
        when(V.BUILD_BINDING_TYPE, lambda: four("XAX.BUILD.VALUE_TYPE", "BUILD-BINDING-TYPE", lambda: w.cid(item), lambda: w.cid(extra)))
        when(V.BUILD_ARTIFACT_REQUIRED, lambda: four("XAX.BUILD.ARTIFACT", "BUILD-ARTIFACT-REQUIRED", const(">= 1"), const(0)))

        def request():
            take("form")
            ref("package")
            start, length = string("entry")
            e.var("entry_at", start)
            e.var("entry_len", length)
            take("target_i")
            take("profile_i")

            # The package's three named collections (``decode_package``): build entries, feature and configuration types.
            def collection(number: int):
                """The cursor at collection ``number``'s count."""
                cursor.at(p["package"])
                cursor.string("pi")
                e.for_("pm", 0, cursor.uleb(), cursor.uleb)
                e.for_("pd", 0, cursor.uleb(), lambda: e.if_(e.eq(cursor.uleb(), 1), cursor.uleb, lambda: cursor.string("pds")))
                for _ in range(number):
                    e.for_("pc", 0, cursor.uleb(), lambda: (cursor.string("pcs"), cursor.uleb()))

            def collection_names(number: int, tag: int):
                collection(number)
                e.var("cn_count", cursor.uleb())

                def name_(_i):
                    start_, length_ = cursor.string("cnn")
                    _input_bytes(w, tag, start_, length_)
                    cursor.uleb()

                w.seq(D.T_LIST, p["cn_count"], name_)

            when(V.BUILD_ENTRY_DECLARED, lambda: four("XAX.BUILD.ENTRY", "BUILD-ENTRY-DECLARED", lambda: collection_names(0, D.T_HEX),
                                                      lambda: _input_bytes(w, D.T_HEX, p["entry_at"], p["entry_len"])))
            for number in range(2):
                e.var("bind", take("bind_count"))
                e.var("bind_at", p["bw"])

                def bound(tag):
                    def name_(i):
                        e.set("bw", e.add(p["bind_at"], e.mul(i, 3)))
                        start_, length_ = string("bn")
                        _input_bytes(w, tag, start_, length_)
                    return lambda: w.seq(D.T_TUPLE if tag == D.T_BYTES else D.T_LIST, p["bind"], name_)

                e.if_(e.both(e.eq(rule, V.BUILD_BINDINGS_CANONICAL), e.eq(item, number)), lambda: canonical("BUILD-BINDINGS-CANONICAL", bound(D.T_BYTES)))
                e.if_(e.both(e.eq(rule, V.BUILD_BINDINGS_COMPLETE), e.eq(item, number)), lambda number=number: four(
                    "XAX.BUILD.INPUT_CLOSURE", "BUILD-BINDINGS-COMPLETE", lambda: collection_names(number + 1, D.T_HEX), bound(D.T_HEX)))
                e.set("bw", e.add(p["bind_at"], e.mul(p["bind"], 3)))
            canonical("BUILD-ARTIFACTS-CANONICAL", lambda: w.seq(D.T_TUPLE, take("artifact_count"), lambda _i: w.member("ArtifactKind", take("artifact"))))

        e.if_(e.either(*(e.eq(rule, number) for number in (V.BUILD_ENTRY_DECLARED, V.BUILD_BINDINGS_CANONICAL, V.BUILD_BINDINGS_COMPLETE,
                                                           V.BUILD_ARTIFACTS_CANONICAL))), request)

        def provenance():
            take("form")
            for name in ("snapshot", "request", "target", "profile"):
                ref(name)
            when(V.BUILD_PROVENANCE_KINDS, lambda: four("XAX.PROVENANCE.REFERENCE", "PROVENANCE-REFERENCE-KINDS", const("snapshot/request/target/profile"),
                                                        names(*(("Kind", V._kind(e, p[name])) for name in ("snapshot", "request", "target", "profile")))))
            four("XAX.PROVENANCE.CLOSURE", "PROVENANCE-EXACT-CLOSURE", lambda: (w.put(D.T_LIST), w.put(3), w.cid(item), w.cid(extra), w.cid(more)),
                 lambda: (w.put(D.T_LIST), w.put(3), w.cid(p["request"]), w.cid(p["target"]), w.cid(p["profile"])))

        e.if_(e.either(e.eq(rule, V.BUILD_PROVENANCE_KINDS), e.eq(rule, V.BUILD_PROVENANCE_CLOSURE)), provenance)

        # Snapshots.
        take("form")
        ref("request")
        start, length = string("identity")
        e.var("identity_at", start)
        e.var("identity_len", length)
        ref("policy")
        when(V.BUILD_SNAPSHOT_HEADER, lambda: four("XAX.SNAPSHOT.HEADER", "SNAPSHOT-HEADER", const("request, resolver identity, trust policy"), lambda: (
            w.put(D.T_LIST), w.put(3), w.name("Kind", V._kind(e, p["request"])), _input_bytes(w, D.T_HEX, p["identity_at"], p["identity_len"]),
            w.name("Kind", V._kind(e, p["policy"])))))
        when(V.BUILD_RESOLVE_EXACT, lambda: four("XAX.RESOLVE.MISSING", "RESOLVE-EXACT-ROOT", lambda: w.cid(item), const("missing")))

        def logical():
            quoted = item  # [n, candidate objects]
            matches = lambda: _sorted_objects(w, counts, e.ld(quoted), lambda i: e.ld(e.add(e.add(quoted, 1), i)))  # noqa: E731
            e.if_(e.ne(e.ld(quoted), 0), lambda: four("XAX.RESOLVE.AMBIGUOUS", "RESOLVE-LOGICAL-IDENTITY", const("exactly one candidate"), matches),
                  lambda: four("XAX.RESOLVE.MISSING", "RESOLVE-LOGICAL-IDENTITY", const("exactly one candidate"), matches))

        when(V.BUILD_RESOLVE_LOGICAL, logical)
        e.var("packages", take("package_count"))
        e.var("packages_at", p["bw"])
        e.set("bw", e.add(p["bw"], p["packages"]))
        e.var("signatures", take("signature_count"))
        e.var("signatures_at", p["bw"])
        e.set("bw", e.add(p["bw"], p["signatures"]))
        package = lambda i: V._reference(e, o, e.ld(e.add(p["packages_at"], i)))  # noqa: E731
        signed = lambda i: V._reference(e, o, e.ld(e.add(p["signatures_at"], i)))  # noqa: E731
        when(V.BUILD_SNAPSHOT_PACKAGE_KIND, lambda: four("XAX.SNAPSHOT.PACKAGE", "SNAPSHOT-PACKAGE-KIND", const(Kind.PACKAGE.name), lambda: w.seq(
            D.T_LIST, p["packages"], lambda i: w.name("Kind", V._kind(e, package(i))))))
        when(V.BUILD_SNAPSHOT_SIGNATURE_KIND, lambda: four("XAX.SNAPSHOT.SIGNATURE", "SNAPSHOT-SIGNATURE-KIND", const("SIGNATURE"), lambda: w.seq(
            D.T_LIST, p["signatures"], lambda i: w.name("BuildForm", e.rd(body_at(e, signed(i)))))))
        when(V.BUILD_SNAPSHOT_PACKAGES_CANONICAL, lambda: canonical("SNAPSHOT-PACKAGES-CANONICAL", lambda: w.seq(
            D.T_TUPLE, p["packages"], lambda i: w.cid_bytes(package(i)))))
        when(V.BUILD_SNAPSHOT_SIGNATURES_CANONICAL, lambda: canonical("SNAPSHOT-SIGNATURES-CANONICAL", lambda: w.seq(
            D.T_TUPLE, p["signatures"], lambda i: w.cid_bytes(signed(i)))))

        def external():
            e.var("externals", take("external_count"))
            e.var("externals_at", p["bw"])
            w.seq(D.T_TUPLE, p["externals"], lambda i: _input_bytes(w, D.T_BYTES, e.add(p["body"], e.ld(e.add(p["externals_at"], i))), 32))

        when(V.BUILD_SNAPSHOT_EXTERNAL_CANONICAL, lambda: canonical("SNAPSHOT-EXTERNAL-CANONICAL", external))
        when(V.BUILD_SNAPSHOT_ROOT, lambda: four("XAX.SNAPSHOT.ROOT", "SNAPSHOT-ROOT-PACKAGE", lambda: w.cid(more), const("missing")))

        def closure():
            quoted = item  # one flag per package: reached

            def reached():
                e.var("cl_n", 0)
                e.for_("cl_k", 0, p["packages"], lambda: e.if_(e.ne(e.ld(e.add(e.add(quoted, 1), p["cl_k"])), 0), lambda: (
                    e.st(e.add(counts, package(p["cl_k"])), e.add(e.ld(e.add(counts, package(p["cl_k"]))), 1)), e.set("cl_n", e.add(p["cl_n"], 1)))))
                w.put(D.T_LIST)
                w.put(p["cl_n"])

                def emit():
                    e.for_("cl_r", 0, e.ld(e.add(counts, p["cl_q"])), lambda: w.cid(p["cl_q"]))
                    e.st(e.add(counts, p["cl_q"]), 0)

                e.for_("cl_q", 0, V._g(e, V.G_O), emit)

            four("XAX.SNAPSHOT.CLOSURE", "SNAPSHOT-EXACT-CLOSURE", reached, lambda: _sorted_objects(w, counts, p["packages"], package))

        when(V.BUILD_SNAPSHOT_CLOSURE, closure)

        def grant_declared():
            def identities():
                """The packages' logical identities, each once, in package order."""
                def identity_of(i, prefix):
                    cursor.at(package(i))
                    return cursor.string(prefix)

                e.var("gd_n", 0)

                def first(i, emit):
                    start_, length_ = identity_of(i, "gda")
                    e.var("gd_start", start_)
                    e.var("gd_len", length_)
                    e.var("gd_new", 1)

                    def earlier():
                        start2, length2 = identity_of(p["gd_j"], "gdb")
                        e.var("gd_same", e.flag(e.eq(length2, p["gd_len"])))
                        e.for_("gd_b", 0, e.sel(e.ne(p["gd_same"], 0), p["gd_len"], 0), lambda: e.set("gd_same", e.and_(p["gd_same"], e.flag(
                            e.eq(e.rd(e.add(start2, p["gd_b"])), e.rd(e.add(p["gd_start"], p["gd_b"])))))))
                        e.if_(e.ne(p["gd_same"], 0), lambda: e.set("gd_new", 0))

                    e.for_("gd_j", 0, i, earlier)
                    e.if_(e.ne(p["gd_new"], 0), lambda: emit(p["gd_start"], p["gd_len"]))

                e.for_("gd_i", 0, p["packages"], lambda: first(p["gd_i"], lambda _s, _l: e.set("gd_n", e.add(p["gd_n"], 1))))
                w.put(D.T_LIST)
                w.put(p["gd_n"])
                e.for_("gd_i", 0, p["packages"], lambda: first(p["gd_i"], lambda start_, length_: _input_bytes(w, D.T_HEX, start_, length_)))

            def grant():
                cursor.at(more)  # the profile: form, mode, optimization, verification, grants
                for _ in range(4):
                    cursor.uleb()
                cursor.uleb()
                e.for_("gr_k", 0, item, lambda: (cursor.string("grs"), cursor.uleb(), cursor.string("grc")))
                start_, length_ = cursor.string("gri")
                e.var("gr_start", start_)
                e.var("gr_len", length_)
                e.var("gr_kind", cursor.uleb())
                scope_at, scope_len = cursor.string("grc")
                w.put(D.T_LIST)
                w.put(2)
                _input_bytes(w, D.T_HEX, p["gr_start"], p["gr_len"])
                w.tagged(D.T_OBJECT, OBJECT["BuildCapability"], 2)
                w.member("BuildCapabilityKind", p["gr_kind"])
                _input_bytes(w, D.T_BYTES, scope_at, scope_len)

            four("XAX.BUILD.CAPABILITY", "BUILD-GRANT-DECLARED", identities, grant)

        when(V.BUILD_GRANT_DECLARED, grant_declared)

        def coverage(code, name):
            def roots(i):
                cursor.at(signed(i))
                cursor.uleb()  # the form
                w.cid(V._reference(e, signed(i), cursor.uleb()))

            four(code, name, lambda: w.seq(D.T_LIST, p["packages"], lambda i: w.cid(package(i))), lambda: w.seq(D.T_LIST, p["signatures"], roots))

        when(V.BUILD_SIGNATURE_PACKAGE, lambda: coverage("XAX.TRUST.SNAPSHOT", "TRUST-SIGNATURE-PACKAGE"))
        when(V.BUILD_SIGNATURE_COVERAGE, lambda: coverage("XAX.TRUST.REQUIRED", "TRUST-SNAPSHOT-COVERAGE"))
        e.give(0)
    return _function(("o", "counts"), build, tables)


# -- the phase ------------------------------------------------------------------------------------------------------

def _render(tables, functions):
    """Render object ``o``'s rejection (its verdict is REJECTED) into the bank."""
    def build(e: E):
        p = e.p
        o = p["o"]
        at = e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS))
        e.var("site", e.ld(at))
        e.var("x0", e.ld(e.add(at, 1)))
        e.var("x5", e.ld(e.add(at, 6)))
        e.var("index", e.add(INDEX_AT, e.mul(o, INDEX_WORDS)))
        e.var("start", e.ld(BANK_CURSOR))
        e.st(BANK_BAD, 0)
        e.st(p["index"], p["start"])
        e.st(e.add(p["index"], 3), ENTITY_OBJECT)
        e.st(e.add(p["index"], 4), o)
        site = p["site"]
        e.if_(e.eq(site, SITE["OBJECT_MISSING"]), lambda: (e.st(e.add(p["index"], 3), ENTITY_MISSING),
                                                           e.st(e.add(p["index"], 4), e.add(e.mul(o, 1 << 32), p["x0"]))))
        e.if_(e.eq(site, SITE["BUILD_KIND_OF"]), lambda: e.st(e.add(p["index"], 4), p["x0"]))
        e.if_(e.both(e.eq(site, SITE["BUILD_RULE"]), e.ne(p["x5"], NONE)), lambda: e.st(e.add(p["index"], 4), p["x5"]))
        e.var("done", e.call(functions["simple"], o, site, p["counts"]))
        e.if_(e.eq(p["done"], 0), lambda: e.set("done", e.call(functions["target"], o, site)))
        e.if_(e.eq(p["done"], 0), lambda: e.set("done", e.call(functions["target_words"], o, site)))
        e.if_(e.both(e.eq(p["done"], 0), e.eq(site, SITE["BUILD_RULE"])), lambda: e.set("done", e.sel(
            e.lt(p["x0"], V.BUILD_REQUEST_KINDS), e.call(functions["build"], o), e.call(functions["composite"], o, p["counts"]))))
        overflow = e.either(e.lt(BANK_END, e.ld(BANK_CURSOR)), e.ne(e.ld(BANK_BAD), 0))
        e.if_(e.either(e.eq(p["done"], 0), overflow), lambda: (e.st(p["index"], 0), e.st(BANK_CURSOR, p["start"])),
              lambda: e.st(e.add(p["index"], 2), e.ld(BANK_CURSOR)))
        e.give(0)
    return _function(("o", "counts"), build, tables)


def _store(tables):
    """The store's own rejection (``STORE_FAULT``): a cycle re-entering an object, or unreachable objects (the colours
    at word ``STORE_FAULT + 1``: 2 reachable)."""
    def build(e: E):
        p = e.p
        w = Writer(e)
        objects = V._g(e, V.G_O)
        e.var("index", e.add(INDEX_AT, e.mul(objects, INDEX_WORDS)))
        e.var("start", e.ld(BANK_CURSOR))
        e.var("fault", e.ld(V.STORE_FAULT))
        e.var("value", e.ld(V.STORE_FAULT + 1))
        e.st(p["index"], 0)
        e.if_(e.both(e.ne(p["fault"], 1), e.ne(p["fault"], 2)), lambda: e.give(0))
        e.st(p["index"], p["start"])

        def cycle():
            w.text("XAX.IDENTITY.CID_CYCLE")
            e.st(e.add(p["index"], 1), e.ld(BANK_CURSOR))
            w.text("ID-MERKLE-ACYCLIC")
            w.text("acyclic references")
            w.text("cycle")
            e.st(e.add(p["index"], 3), ENTITY_OBJECT)
            e.st(e.add(p["index"], 4), p["value"])

        def unreachable():
            w.text("XAX.IDENTITY.UNREACHABLE_OBJECT")
            e.st(e.add(p["index"], 1), e.ld(BANK_CURSOR))
            w.text("ID-ROOTED-STORE")
            w.seq(D.T_LIST, objects, lambda i: w.cid(i))
            e.var("reached", 0)
            e.for_("rk", 0, objects, lambda: e.if_(e.eq(e.ld(e.add(p["value"], p["rk"])), 2), lambda: e.set("reached", e.add(p["reached"], 1))))
            w.put(D.T_LIST)
            w.put(p["reached"])
            e.for_("rq", 0, objects, lambda: e.if_(e.eq(e.ld(e.add(p["value"], p["rq"])), 2), lambda: w.cid(p["rq"])))
            e.st(e.add(p["index"], 3), ENTITY_STORE)

        e.if_(e.eq(p["fault"], 1), cycle, unreachable)
        e.if_(e.lt(BANK_END, e.ld(BANK_CURSOR)), lambda: (e.st(p["index"], 0), e.st(BANK_CURSOR, p["start"])),
              lambda: e.st(e.add(p["index"], 2), e.ld(BANK_CURSOR)))
        e.give(0)
    return _function((), build, tables)


# -- verify_store's order (S15b.1) ----------------------------------------------------------------------------------

PLAN_AT = 11 << 20  # [outcome, object, graph count, graphs ...]
PLAN_LIMIT = 1 << 16
# The general driver keeps, in its workspace (words), each object's typing rejection site, the plan, and the outcome's
# record ``[middle, length, entity mode, entity value, words ...]`` while the graph checks reuse the output view.
TYPES_AT, WORK_PLAN, WORK_RECORD = 32 << 20, 33 << 20, 34 << 20
RECORD_LIMIT = 1 << 20
P_ACCEPT, P_BANK, P_TYPE, P_DECODER, P_DECLINE = range(5)
STRUCTURAL = (Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.CALL_CONTRACT, Kind.RECURSION_GROUP, Kind.TARGET, Kind.PACKAGE, Kind.BUILD,
              Kind.GRAPH_FRAGMENT)
assert PLAN_AT + 3 + (1 << 16) <= V.ARENA_AT


def _plan(tables):
    """``verify_store``'s order over the verdicts: the graphs it parses, in order (each once), until the first object
    it rejects; then the outcome.

    Objects are verified in store order (``verify_object``): a missing reference first; a rejected object's own
    diagnostic, after the graphs its check parses first (a function's graph, a group's first member graphs); a proven
    function parses its graph, a proven group its member graphs, a graph object itself; a structural object the
    verifier did not decide, or a type or constant the typing program did not prove, is the bootstrap's (``P_DECLINE``,
    ``P_TYPE``: the driver reads the typing verdict).  A graph parse that fails in this order is the graph's own
    rejection: its glue record (``P_BANK``), the graph decoder's (``P_DECODER``) when every reference it holds is a
    stored, proven type or a stored object (else the parse may fail earlier on one of them: ``P_DECLINE``), or the
    driver's graph checks (the graph listed).  The store's own rejection comes last (``P_BANK`` of the object count)."""
    def build(e: E):
        p = e.p
        objects = V._g(e, V.G_O)
        e.var("pO", objects)
        e.var("memo", e.alloc(e.add(p["pO"], 1)))
        e.var("term", NONE)
        e.var("tobj", 0)
        e.var("pn", 0)

        def finish(kind, obj=0):
            e.set("term", kind)
            e.set("tobj", obj)

        e.if_(e.eq(p["memo"], NONE), lambda: finish(P_DECLINE))
        e.if_(e.ne(p["memo"], NONE), lambda: e.for_("pz", 0, p["pO"], lambda: e.st(e.add(p["memo"], p["pz"]), 0)))
        verdict = lambda o: e.ld(e.add(V.VERDICTS_AT, o))  # noqa: E731
        site = lambda o: e.ld(e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS)))  # noqa: E731
        payload = lambda o, k: e.ld(e.add(e.add(V.REJECTS_AT, e.mul(o, V.REJECT_WORDS)), k + 1))  # noqa: E731

        def parse(g):
            e.var("pg", g)

            def decoder():
                e.var("pd_ok", 1)
                e.for_("pd_k", 0, V._references(e, p["pg"]), lambda: (
                    e.var("pd_r", V._reference(e, p["pg"], p["pd_k"])),
                    e.if_(e.either(e.eq(p["pd_r"], NONE), e.both(e.eq(V._kind(e, p["pd_r"]), int(Kind.TYPE)), e.not_(V._type_ok(e, p["pd_r"])))),
                          lambda: e.set("pd_ok", 0))))
                e.if_(e.ne(p["pd_ok"], 0), lambda: finish(P_DECODER, p["pg"]), lambda: finish(P_DECLINE))

            def append():
                e.st(e.add(e.add(PLAN_AT, 3), p["pn"]), p["pg"])
                e.set("pn", e.add(p["pn"], 1))

            def fresh():
                e.st(e.add(p["memo"], p["pg"]), 1)
                e.if_(e.eq(verdict(p["pg"]), V.REJECTED), lambda: e.if_(e.eq(site(p["pg"]), SITE["OBJECT_MISSING"]), lambda: finish(P_DECLINE),
                                                                        lambda: finish(P_BANK, p["pg"])),
                      lambda: e.if_(V._graph_rejected(e, p["pg"]), decoder, lambda: e.if_(e.eq(verdict(p["pg"]), 1), append,
                                                                                             lambda: finish(P_DECLINE))))

            ok = e.both(e.eq(p["term"], NONE), e.lt(p["pg"], p["pO"]))
            e.if_(ok, lambda: e.if_(e.ne(V._kind(e, p["pg"]), int(Kind.GRAPH_FRAGMENT)), lambda: finish(P_DECLINE),
                                    lambda: e.if_(e.eq(e.ld(e.add(p["memo"], p["pg"])), 0), fresh)))
            e.if_(e.both(e.eq(p["term"], NONE), e.le(p["pO"], p["pg"])), lambda: finish(P_DECLINE))

        def parse_list(at, count):
            e.var("pl_at", at)
            e.for_("pl_k", 0, count, lambda: parse(e.ld(e.add(e.add(p["pl_at"], 1), p["pl_k"]))))

        def visit():
            o = p["po"]
            e.var("pkind", V._kind(e, o))
            e.var("pverdict", verdict(o))
            e.var("psite", site(o))

            def rejected():
                after = e.either(*(e.eq(p["psite"], SITE[name]) for name in V.AFTER_PARSE))
                group = e.either(*(e.eq(p["psite"], SITE[name]) for name in V.GROUP_AFTER_PARSE))
                e.if_(after, lambda: parse(payload(o, 0)))
                e.if_(group, lambda: parse_list(payload(o, 2), payload(o, 0)))
                e.if_(e.eq(p["term"], NONE), lambda: finish(P_BANK, o))

            def proven():
                e.if_(e.both(e.eq(p["pkind"], int(Kind.FUNCTION)), e.ne(e.ld(e.add(V.GRAPHS_AT, o)), NONE)), lambda: parse(e.ld(e.add(V.GRAPHS_AT, o))))
                e.if_(e.eq(p["pkind"], int(Kind.RECURSION_GROUP)), lambda: parse_list(e.ld(e.add(V.GRAPHS_AT, o)), e.ld(e.ld(e.add(V.GRAPHS_AT, o)))))

            def undecided_function():
                """``_verify_function`` of a function the verifier left undecided: ``_decode_function_interface`` decodes
                the group a member function names (its own rejection, when the group decoder makes that check), or
                verifies an ordinary function's parameter and return types in body order (the first unproven one)."""
                cursor = _Body(e, "pc")
                cursor.at(o)
                e.var("pf_g", V._reference(e, o, cursor.uleb()))
                group_sites = ("GROUP_EMPTY", "GROUP_REF_INDEX", "GROUP_CARRIER", "GROUP_TRAILING", "GROUP_UNUSED", "BODY_ULEB")

                def member():
                    named = e.both(e.eq(verdict(p["pf_g"]), V.REJECTED), e.either(*(e.eq(site(p["pf_g"]), SITE[name]) for name in group_sites)))
                    e.if_(named, lambda: finish(P_BANK, p["pf_g"]), lambda: e.if_(e.eq(verdict(p["pf_g"]), 0), member_types,
                                                                                    lambda: finish(P_DECLINE)))

                def member_types():
                    """S15b.3d (ADR-296): ``_decode_recursion_group`` of an undecided group: each member's parameter
                    and return types are verified in body order (``_type_reference``); the first one the typing
                    program did not prove is that type's own rejection (``P_TYPE``)."""
                    group = _Body(e, "pm")
                    group.at(p["pf_g"])

                    def types():
                        e.for_("pm_t", 0, group.uleb(), lambda: e.if_(e.eq(p["term"], NONE), lambda: (
                            e.var("pm_type", V._reference(e, p["pf_g"], group.uleb())),
                            e.if_(e.eq(p["pm_type"], NONE), lambda: finish(P_DECLINE),
                                  lambda: e.if_(e.not_(V._type_ok(e, p["pm_type"])), lambda: finish(P_TYPE, p["pm_type"]))))))

                    def each():
                        e.var("pm_graph", V._reference(e, p["pf_g"], group.uleb()))
                        e.if_(e.either(e.eq(p["pm_graph"], NONE), e.ne(V._kind(e, p["pm_graph"]), int(Kind.GRAPH_FRAGMENT))), lambda: finish(P_DECLINE))
                        e.if_(e.eq(p["term"], NONE), types)
                        e.if_(e.eq(p["term"], NONE), types)

                    e.for_("pm_k", 0, group.uleb(), lambda: e.if_(e.eq(p["term"], NONE), each))
                    e.if_(e.eq(p["term"], NONE), lambda: finish(P_DECLINE))

                def ordinary():
                    def types():
                        e.for_("pf_k", 0, cursor.uleb(), lambda: e.if_(e.eq(p["term"], NONE), lambda: (
                            e.var("pf_t", V._reference(e, o, cursor.uleb())),
                            e.if_(e.either(e.eq(p["pf_t"], NONE), e.ne(V._kind(e, p["pf_t"]), int(Kind.TYPE))), lambda: finish(P_DECLINE),
                                  lambda: e.if_(e.not_(V._type_ok(e, p["pf_t"])), lambda: finish(P_TYPE, p["pf_t"]))))))

                    types()
                    e.if_(e.eq(p["term"], NONE), types)
                    e.if_(e.eq(p["term"], NONE), lambda: parse(p["pf_g"]))  # then its graph; what follows is the bootstrap's
                    e.if_(e.eq(p["term"], NONE), lambda: finish(P_DECLINE))

                e.if_(e.eq(p["pf_g"], NONE), lambda: finish(P_DECLINE), lambda: e.if_(
                    e.eq(V._kind(e, p["pf_g"]), int(Kind.RECURSION_GROUP)), member, lambda: e.if_(
                        e.eq(V._kind(e, p["pf_g"]), int(Kind.GRAPH_FRAGMENT)), ordinary, lambda: finish(P_DECLINE))))

            def snapshot():
                """S15b.3d (ADR-296): ``decode_snapshot`` of a snapshot the verifier left to a nested decoder (its own
                checks hold): ``decode_request``, then each package's ``decode_package``, raise their own rejections."""
                body = _Body(e, "ps")
                body.at(o)
                body.uleb()  # the form
                e.var("ps_req", V._reference(e, o, body.uleb()))
                body.string("ps_id")
                body.uleb()  # the trust policy
                own = lambda x: e.both(e.eq(verdict(x), V.REJECTED), e.ne(site(x), SITE["OBJECT_MISSING"]))  # noqa: E731

                def packages():
                    e.for_("ps_k", 0, body.uleb(), lambda: e.if_(e.eq(p["term"], NONE), lambda: (
                        e.var("ps_pkg", V._reference(e, o, body.uleb())),
                        e.if_(e.eq(p["ps_pkg"], NONE), lambda: finish(P_DECLINE), lambda: e.if_(
                            own(p["ps_pkg"]), lambda: finish(P_BANK, p["ps_pkg"]), lambda: e.if_(
                                e.ne(verdict(p["ps_pkg"]), 1), lambda: finish(P_DECLINE)))))))

                e.if_(e.eq(p["ps_req"], NONE), lambda: finish(P_DECLINE), lambda: e.if_(
                    own(p["ps_req"]), lambda: finish(P_BANK, p["ps_req"]), lambda: e.if_(e.eq(verdict(p["ps_req"]), 1), packages)))
                e.if_(e.eq(p["term"], NONE), lambda: finish(P_DECLINE))

            def other():
                e.if_(e.both(e.eq(p["pkind"], int(Kind.BUILD)), e.eq(e.rd(body_at(e, o)), 3)), snapshot)
                structural = e.either(*(e.eq(p["pkind"], int(kind)) for kind in STRUCTURAL if kind != Kind.FUNCTION))
                typed = e.either(e.eq(p["pkind"], int(Kind.TYPE)), e.eq(p["pkind"], int(Kind.CONSTANT)))
                e.if_(e.eq(p["pkind"], int(Kind.FUNCTION)), undecided_function)
                e.if_(e.both(structural, e.eq(p["term"], NONE)), lambda: finish(P_DECLINE))
                e.if_(e.both(typed, e.not_(V._type_ok(e, o))), lambda: finish(P_TYPE, o))

            e.if_(e.eq(p["pverdict"], V.REJECTED), rejected, lambda: e.if_(
                e.eq(p["pkind"], int(Kind.GRAPH_FRAGMENT)), lambda: parse(o), lambda: e.if_(e.eq(p["pverdict"], 1), proven, other)))

        e.for_("po", 0, p["pO"], lambda: e.if_(e.eq(p["term"], NONE), visit))
        fault = e.ld(V.STORE_FAULT)
        e.if_(e.eq(p["term"], NONE), lambda: e.if_(e.eq(e.ld(1), 1), lambda: finish(P_ACCEPT), lambda: e.if_(
            e.either(e.eq(fault, 1), e.eq(fault, 2)), lambda: finish(P_BANK, p["pO"]), lambda: finish(P_DECLINE))))
        e.st(PLAN_AT, p["term"])
        e.st(PLAN_AT + 1, p["tobj"])
        e.st(PLAN_AT + 2, p["pn"])
        e.give(0)
    return _function((), build, tables)


def add_functions(add, tables) -> dict:
    """The rendering functions, added to the verifier program (``add(name, (function, objects))``)."""
    _FN["put"] = add("render_put", put_function(BANK_CURSOR, BANK_END))
    _FN["cid"] = add("render_cid", _function(("o",), cid_function(VerifierTable, _FN), tables))
    functions = {}
    for name, made in (("simple", _simple), ("target", _target), ("target_words", _target_words), ("build", _build), ("composite", _composite)):
        functions[name] = add(f"render_{name}", made(tables))
    functions["render"] = add("render", _render(tables, functions))
    functions["store"] = add("render_store", _store(tables))
    functions["plan"] = add("render_plan", _plan(tables))
    return functions


def render_phase(e: E, functions, verdicts_at: int, rejected: int):
    """The verifier's last phase: every rejected object's record, ``OTHER_OBJECT`` copying the other's, then the store's."""
    p = e.p
    e.st(BANK_CURSOR, BANK_AT)
    objects = V._g(e, V.G_O)
    e.var("rcounts", e.alloc(e.add(objects, 1)))

    def phase():
        e.for_("rz", 0, objects, lambda: e.st(e.add(p["rcounts"], p["rz"]), 0))

        def one():
            index = e.add(INDEX_AT, e.mul(p["ro"], INDEX_WORDS))
            e.st(index, 0)
            e.if_(e.eq(e.ld(e.add(verdicts_at, p["ro"])), rejected), lambda: e.call(functions["render"], p["ro"], p["rcounts"]))

        e.for_("ro", 0, objects, one)

        def other():
            at = e.add(V.REJECTS_AT, e.mul(p["ro"], V.REJECT_WORDS))
            source = e.add(INDEX_AT, e.mul(e.ld(e.add(at, 1)), INDEX_WORDS))
            index = e.add(INDEX_AT, e.mul(p["ro"], INDEX_WORDS))
            e.for_("rw", 0, INDEX_WORDS, lambda: e.st(e.add(index, p["rw"]), e.ld(e.add(source, p["rw"]))))

        e.for_("ro", 0, objects, lambda: e.if_(e.both(e.eq(e.ld(e.add(verdicts_at, p["ro"])), rejected),
                                                       e.eq(e.ld(e.add(V.REJECTS_AT, e.mul(p["ro"], V.REJECT_WORDS))), SITE["OTHER_OBJECT"])), other))
        e.call(functions["store"])

    e.if_(e.ne(p["rcounts"], NONE), phase, lambda: e.st(BANK_CURSOR, 0))  # cursor 0: no bank
    e.call(functions["plan"])


# -- host side --------------------------------------------------------------------------------------------------------

def entity_words(mode: int, value: int, cid_of, missing_cid) -> list[int]:
    """The entity value's words: an object's CID, a missing reference's CID, or ``store``."""
    if mode == ENTITY_STORE:
        return [D.T_STR, 5, int.from_bytes(b"store", "little")]
    cid = cid_of(value) if mode == ENTITY_OBJECT else missing_cid(value >> 32, value & 0xFFFFFFFF)
    return [D.T_CID, *(int.from_bytes(cid[k:k + 8], "big") for k in range(0, 32, 8))]


def decode_bank(read, count: int, cid_of, missing_cid) -> dict:
    """``{object: Diagnostic}`` (``count``: the store's rejection) for every record in the bank."""
    if read(BANK_CURSOR, 1)[0] == 0:
        return {}
    records = {}
    for o in range(count + 1):
        start, middle, end, mode, value = read(INDEX_AT + INDEX_WORDS * o, INDEX_WORDS)
        if start:
            words = [*read(start, middle - start), *entity_words(mode, value, cid_of, missing_cid), *read(middle, end - middle)]
            records[o] = D.decode_record(words)
    return records


# -- the host's reference (tests) -------------------------------------------------------------------------------------

STATS = {"same": 0, "diff": 0, "unrendered": 0, "stores": 0, "host_error": 0}
SITES: dict = {}


def expected_bank(listed, rejections) -> dict:
    """The host's rendering of the verifier's records (``_xax_verify_store``): the reference the bank is tested against."""
    from xax_compiler import Diagnostic
    from xax_selfhost_verify import OBJECT_SITES, object_diagnostic, object_entity

    out = {}
    for position, record in rejections.items():
        if not isinstance(position, int) or OBJECT_SITES[record[0] - 1] == "OTHER_OBJECT":
            continue
        code, rule, expected, actual = object_diagnostic(listed[position], record, listed)
        entity = object_entity(listed[position], record, listed)
        out[position] = Diagnostic(code, (entity or listed[position].cid).hex(), rule, expected, actual)
    for position, record in rejections.items():
        if isinstance(position, int) and OBJECT_SITES[record[0] - 1] == "OTHER_OBJECT" and record[1][0] in out:
            out[position] = out[record[1][0]]
    store = rejections.get("store")
    if store is not None:
        kind, value = store
        if kind == "cycle":
            out[len(listed)] = Diagnostic("XAX.IDENTITY.CID_CYCLE", listed[value].cid.hex(), "ID-MERKLE-ACYCLIC", "acyclic references", "cycle")
        else:
            out[len(listed)] = Diagnostic("XAX.IDENTITY.UNREACHABLE_OBJECT", "store", "ID-ROOTED-STORE", sorted(obj.cid.hex() for obj in listed),
                                          sorted(listed[o].cid.hex() for o in value))
    return out


def compare(listed, out_words, rejections) -> None:
    """Count (``STATS``, ``SITES``) and report every bank record that differs from the host's rendering."""
    import sys

    read = lambda start, length: list(out_words[start:start + length])  # noqa: E731
    try:
        expected = expected_bank(listed, rejections)
    except (IndexError, KeyError, ValueError):
        STATS["host_error"] += 1  # the host cannot render a record the bootstrap never reaches
        return
    produced = decode_bank(read, len(listed), lambda o: listed[o].cid, lambda o, k: listed[o].references[k])
    STATS["stores"] += 1
    from xax_selfhost_verify import OBJECT_SITES

    for position, diagnostic in expected.items():
        record = rejections.get(position)
        site = "STORE" if record is None else OBJECT_SITES[record[0] - 1] + (f":{record[1][0]}" if OBJECT_SITES[record[0] - 1] == "BUILD_RULE" else "")
        SITES[site] = SITES.get(site, 0) + 1
        got = produced.get(position)
        if got is None:
            STATS["unrendered"] += 1
            sys.stderr.write(f"\nRENDER-MISSING {position} {diagnostic}\n")
        elif (got.code, got.entity, got.rule, got.expected, got.actual) == (diagnostic.code, diagnostic.entity, diagnostic.rule, diagnostic.expected,
                                                                              diagnostic.actual) and repr(got) == repr(diagnostic):
            STATS["same"] += 1
        else:
            STATS["diff"] += 1
            sys.stderr.write(f"\nRENDER-DIFF {position}\n  xax={got}\n  host={diagnostic}\n")
    for position in set(produced) - set(expected):
        STATS["diff"] += 1
        sys.stderr.write(f"\nRENDER-EXTRA {position} {produced[position]}\n")
