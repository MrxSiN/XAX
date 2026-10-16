"""Self-hosting step S15d.1 (ADR-304): semantic transactions on a canonical store, as XAX functions.

The production compiler's ``edit <store> <edit record> <output store>`` applies a transaction to a verified store and
writes the store it makes, as ``xax_workspace.Workspace.commit`` does for the same mutations: each mutated graph is
re-encoded, every transitive user (graph, function, module, program root, package, build request) is rebuilt with its
references in CID order and its body re-indexed, unreachable objects are dropped, and the S9 writer writes the store.
These functions have the S10e helper convention (``xax_selfhost_facts._function``): the input view is the store
verifier's object table (``index_objects`` located each record in ``OBJAT``), the output view the driver's workspace,
from ``EB`` on.

The edit record (``RECORD_MAGIC``), a tooling carrier, not program source:

    magic "XAXEDIT1" | expected root CID (32 bytes; all zero: no root precondition) | ULEB count | mutation*
    mutation: ULEB kind | function CID (32 bytes) | ULEB block | ULEB node | operands
      SET_OPERATION (1): ULEB expected operation, ULEB operation   (``SetOperation``: wrapping add, sub, mul)
      SET_CONSTANT (2):  ULEB expected value, ULEB value             (``SetConstant``: an integer constant node)

A mutation names its node by the function's CID and the node's block and position, so a changed function is stale by
construction; the expected root and the expected operation or value are its other preconditions.

* ``begin`` parses the record, checks every precondition with the workspace's diagnostics, makes each new constant,
  and marks the affected objects (the mutated graphs and their transitive users).
* ``next`` gives the next object whose references are all final: a new constant, then each affected object once
  all its affected references are done.  It writes the object's CID preimage (after the domain) at ``PRE`` and where
  the driver puts its CID (``E_SLOT``).
* ``reach`` marks the old objects the new root still reaches (``COPY``): with the new objects, the output store.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_compiler import ATTRIBUTE_OPERATIONS, ENTITY_OPERATIONS, Kind, Operation, uleb
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_semantic import _cid_word, _kind, _nrefs, _payload, _ref

RECORD_MAGIC = b"XAXEDIT1"
SET_OPERATION, SET_CONSTANT = 1, 2
EB = 52 << 20  # workspace words
(E_STATUS, E_LENGTH, E_MUTATIONS, E_EXTRAS, E_EXTRAS_DONE, E_OBJECTS, E_SLOT, E_KIND, E_NREFS, E_REFS_AT, E_BODY_AT, E_BODY_LENGTH,
 E_PRE_LENGTH, E_OBJECT, E_ROOT, E_AFFECTED, E_PRE_AT, E_NEW, E_BATCH_LENGTH, E_PRE_END) = range(20)
OK, REJECT, MORE, DONE = 0, 1, 2, 3
EC = EB  # control words (64)
OPF = EB + 64  # per operation code: 1 entity, 2 attributes
EIN = EB + 256  # the edit record, one byte per word
EIN_LIMIT = 1 << 16
MUT = EIN + EIN_LIMIT  # 8 words per mutation: kind, function, graph, block, node, expected, value, extra
MUT_WORDS, MUT_LIMIT = 8, 256
EXTRA = MUT + MUT_WORDS * MUT_LIMIT  # 16 words per new constant: type, length, value, alias, CID (4) ...
EXTRA_WORDS = 16
ENTITY_AT = EXTRA + EXTRA_WORDS * MUT_LIMIT  # per mutation: its node's entity reference index + 1 (0: none)
STATE = EB + (1 << 17)  # per object: 0 untouched, 1 affected, 2 rebuilt
NEWCID = STATE + (1 << 16)  # 4 words per object
ALIAS = NEWCID + (1 << 18)  # per object: the old object whose CID its new version has, or NONE
COPY = ALIAS + (1 << 16)  # per object: 1 when the output store keeps it
RSTART = COPY + (1 << 16)  # per rebuilt object: its new references' sources
RCOUNT = RSTART + (1 << 16)
REFL = RCOUNT + (1 << 16)  # the sources: an object position, or EXTRA_TAG + extra index
REFL_LIMIT = 1 << 20
RC_LIMIT = 1 << 16  # distinct references of one object
SR = REFL + REFL_LIMIT  # an object's references, sorted and distinct: CID (4 words) and source
SRS = SR + 4 * RC_LIMIT
STACK = SRS + RC_LIMIT  # reachability
BODY = STACK + (1 << 17)  # the re-encoded body, one byte per word
BODY_LIMIT = 1 << 22
PRE = BODY + BODY_LIMIT  # every new object's CID preimage after the domain, one byte per word, in order
PRE_LIMIT = 1 << 24
NEWT = PRE + PRE_LIMIT  # per new object: preimage start, length, references at, count, body at, length, kind, object, alias
NEWT_WORDS, NEWT_LIMIT = 9, 1 << 16
BATCH = NEWT + NEWT_WORDS * NEWT_LIMIT  # the S9 writer's batch, one byte per word (``xax_selfhost_writer``'s layout)
BATCH_LIMIT = (1 << 25) - 4096  # the writer's input view less its slack
BATCH_AT = 58  # control word: the batch bytes written
EXTRA_TAG = 1 << 40
assert BATCH + BATCH_LIMIT < 128 << 20
ENTITY = sorted(int(op) for op in ENTITY_OPERATIONS)
ATTRIBUTE = sorted(int(op) for op in ATTRIBUTE_OPERATIONS)
WRAPPING = (int(Operation.ADD_WRAP), int(Operation.SUB_WRAP), int(Operation.MUL_WRAP))
LOCATE, COLLECT, EMIT = 0, 1, 2


def _ctrl(e: E, field: int):
    return e.ld(EC + field)


def _set(e: E, field: int, value):
    e.st(EC + field, value)


def _graph_body(e: E, o):
    """``(length, first byte word)`` of graph ``o``'s body (after its stream in the object table)."""
    pay = _payload(e, o)
    at = e.add(e.add(pay, 1), e.rd(pay))
    return e.rd(at), e.add(at, 1)


def _plain_body(e: E, o):
    pay = _payload(e, o)
    return e.rd(pay), e.add(pay, 1)


def _body_of(e: E, o, name: str):
    """Declare ``{name}_length`` and ``{name}_at``: object ``o``'s body."""
    p = e.p
    e.var(f"{name}_length", 0)
    e.var(f"{name}_at", 0)

    def graph():
        length, at = _graph_body(e, o)
        e.set(f"{name}_length", length)
        e.set(f"{name}_at", at)

    def plain():
        length, at = _plain_body(e, o)
        e.set(f"{name}_length", length)
        e.set(f"{name}_at", at)

    e.if_(e.eq(_kind(e, o), int(Kind.GRAPH_FRAGMENT)), graph, plain)
    return p[f"{name}_length"], p[f"{name}_at"]


# The cursor lives in control words, so the scanners are functions of their own: ``CUR`` (the object table word read
# next), ``OUT`` (the ``BODY`` word written next), ``MODE`` (LOCATE, COLLECT, EMIT).
CUR, OUT, MODE, KEY, HIT, RCUR = 48, 49, 50, 52, 56, 57
_F: dict = {}


def _call(e: E, name: str, *arguments):
    return e.call(_F[name], *arguments)


def _put(e: E, value):
    e.var("put_at", _ctrl(e, OUT))
    e.st(e.add(BODY, e.p["put_at"]), value)
    _set(e, OUT, e.add(e.p["put_at"], 1))


def _uleb_read_function():
    """The next ULEB at ``CUR``; ``CUR`` moves past it."""
    def build(e: E):
        p = e.p
        e.var("cur", _ctrl(e, CUR))
        e.var("u_value", 0)
        e.var("u_shift", 1)
        e.var("u_more", 1)

        def step():
            e.var("u_byte", e.rd(p["cur"]))
            e.set("u_value", e.add(p["u_value"], e.mul(e.and_(p["u_byte"], 127), p["u_shift"])))
            e.set("u_shift", e.mul(p["u_shift"], 128))
            e.set("u_more", e.flag(e.le(128, p["u_byte"])))
            e.set("cur", e.add(p["cur"], 1))

        e.while_(lambda: e.ne(p["u_more"], 0), step)
        _set(e, CUR, p["cur"])
        e.give(p["u_value"])
    return _function((), build, None)


def _put_uleb_function():
    def build(e: E):
        p = e.p
        e.var("pu", p["value"])
        e.var("pu_more", 1)

        def step():
            e.var("pu_low", e.and_(p["pu"], 127))
            e.set("pu", e.udiv(p["pu"], 128))
            _put(e, e.add(p["pu_low"], e.mul(e.flag(e.ne(p["pu"], 0)), 128)))
            e.set("pu_more", e.flag(e.ne(p["pu"], 0)))

        e.while_(lambda: e.ne(p["pu_more"], 0), step)
        e.give(0)
    return _function(("value",), build, None)


def _copy_uleb_function():
    """The next ULEB's value; copied to ``BODY`` in EMIT mode."""
    def build(e: E):
        p = e.p
        e.var("cv", _call(e, "uleb_read"))
        e.if_(e.eq(_ctrl(e, MODE), EMIT), lambda: _call(e, "put_uleb", p["cv"]))
        e.give(p["cv"])
    return _function((), build, None)


def _copy_string_function():
    """A length-prefixed byte string, copied in EMIT mode."""
    def build(e: E):
        p = e.p
        e.var("cs_n", _call(e, "copy_uleb"))
        e.var("cs_at", _ctrl(e, CUR))
        e.if_(e.eq(_ctrl(e, MODE), EMIT), lambda: e.for_("cs_k", 0, p["cs_n"], lambda: _put(e, e.rd(e.add(p["cs_at"], p["cs_k"])))))
        _set(e, CUR, e.add(p["cs_at"], p["cs_n"]))
        e.give(0)
    return _function((), build, None)


def _source_cid(e: E, source, k: int):
    """CID word ``k`` of a reference source's current version: a new constant's, a rebuilt object's, or an old one's."""
    extra = e.le(EXTRA_TAG, source)
    index = e.sub(source, EXTRA_TAG)
    rebuilt = e.eq(e.ld(e.add(STATE, source)), 2)
    return e.sel(extra, e.ld(e.add(e.add(EXTRA, e.mul(index, EXTRA_WORDS)), 4 + k)),
                 e.sel(rebuilt, e.ld(e.add(e.add(NEWCID, e.mul(source, 4)), k)), _cid_word(e, source, k)))


def _search_function():
    """Binary search of the CID in ``KEY`` among the ``EC + 41`` sorted references at ``SR``: its position (or where
    it goes); ``HIT`` is 1 when present."""
    def build(e: E):
        p = e.p
        for k in range(4):
            e.var(f"key{k}", _ctrl(e, KEY + k))
        e.var("lo", 0)
        e.var("hi", e.ld(EC + 41))
        e.var("hit", 0)

        def step():
            e.var("mid", e.udiv(e.add(p["lo"], p["hi"]), 2))
            at = e.add(SR, e.mul(p["mid"], 4))
            e.var("below", 0)  # the entry is below the key
            e.var("same", 1)
            for k in range(4):
                e.var(f"c{k}", e.ld(e.add(at, k)))
                e.if_(e.ne(p["same"], 0), lambda k=k: e.if_(e.lt(p[f"c{k}"], p[f"key{k}"]), lambda: (e.set("below", 1), e.set("same", 0)),
                                                            lambda: e.if_(e.lt(p[f"key{k}"], p[f"c{k}"]), lambda: e.set("same", 0))))
            e.if_(e.ne(p["same"], 0), lambda: (e.set("hit", 1), e.set("lo", p["mid"]), e.set("hi", p["mid"])),
                  lambda: e.if_(e.ne(p["below"], 0), lambda: e.set("lo", e.add(p["mid"], 1)), lambda: e.set("hi", p["mid"])))

        e.while_(lambda: e.lt(p["lo"], p["hi"]), step)
        _set(e, HIT, p["hit"])
        e.give(p["lo"])
    return _function((), build, None)


def _insert_function():
    """Add the current version of ``source`` to the sorted references at ``SR`` (``EC + 41`` of them), once; past
    ``RC_LIMIT`` of them ``EC + 43`` is set."""
    def build(e: E):
        p = e.p
        for k in range(4):
            _set(e, KEY + k, _source_cid(e, p["source"], k))
        e.var("ipos", _call(e, "search"))

        def place():
            e.var("it", e.ld(EC + 41))
            e.if_(e.le(RC_LIMIT, p["it"]), lambda: e.st(EC + 43, 1))

            def shift():
                e.set("it", e.sub(p["it"], 1))
                for k in range(4):
                    e.st(e.add(e.add(SR, e.mul(e.add(p["it"], 1), 4)), k), e.ld(e.add(e.add(SR, e.mul(p["it"], 4)), k)))
                e.st(e.add(SRS, e.add(p["it"], 1)), e.ld(e.add(SRS, p["it"])))

            e.while_(lambda: e.both(e.lt(p["ipos"], p["it"]), e.eq(e.ld(EC + 43), 0)), shift)

            def write():
                for k in range(4):
                    e.st(e.add(e.add(SR, e.mul(p["ipos"], 4)), k), _ctrl(e, KEY + k))
                e.st(e.add(SRS, p["ipos"]), p["source"])
                e.st(EC + 41, e.add(e.ld(EC + 41), 1))

            e.if_(e.eq(e.ld(EC + 43), 0), write)

        e.if_(e.both(e.eq(_ctrl(e, HIT), 0), e.eq(e.ld(EC + 43), 0)), place)
        e.give(0)
    return _function(("source",), build, None)


def _reference_function():
    """One reference index in the body of object ``o``: COLLECT inserts its source's CID among the sorted references
    (``SR``); EMIT writes the index of its CID there.  ``extra``: the new constant replacing it (NONE: none).  Gives the
    old index."""
    def build(e: E):
        p = e.p
        e.var("ri", _call(e, "uleb_read"))
        e.var("rsrc", e.sel(e.ne(p["extra"], NONE), e.add(EXTRA_TAG, p["extra"]), _ref(e, p["o"], p["ri"])))
        e.var("rmode", _ctrl(e, MODE))
        e.if_(e.eq(p["rmode"], COLLECT), lambda: _call(e, "insert", p["rsrc"]))

        def emit():
            for k in range(4):
                _set(e, KEY + k, _source_cid(e, p["rsrc"], k))
            _call(e, "put_uleb", _call(e, "search"))

        e.if_(e.eq(p["rmode"], EMIT), emit)
        e.give(p["ri"])
    return _function(("o", "extra"), build, None)


def _record_uleb_function():
    """The edit record's next ULEB at ``RCUR`` (a workspace word); a ULEB past the record or past 64 bits is
    EDIT-RECORD-ULEB."""
    def build(e: E):
        p = e.p
        e.var("at", _ctrl(e, RCUR))
        e.var("end", e.add(EIN, _ctrl(e, E_LENGTH)))
        e.var("value", 0)
        e.var("shift", 1)
        e.var("more", 1)

        def malformed():
            _reject(e, "XAX.EDIT.RECORD", lambda: D.text(e, "edit"), "EDIT-RECORD-ULEB", lambda: D.text(e, "xax-edit-v1"),
                    lambda: D.integer(e, e.sub(p["at"], EIN)))
            e.set("more", 0)

        def step():
            e.if_(e.either(e.le(p["end"], p["at"]), e.eq(p["shift"], 0)), malformed)  # past the record; an eleventh byte

            def read():
                e.var("byte", e.ld(p["at"]))
                e.set("at", e.add(p["at"], 1))
                # The tenth byte carries bit 63 only.
                e.if_(e.both(e.eq(p["shift"], 1 << 63), e.lt(1, e.and_(p["byte"], 127))), malformed, lambda: (
                    e.set("value", e.add(p["value"], e.mul(e.and_(p["byte"], 127), p["shift"]))),
                    e.set("shift", e.mul(p["shift"], 128)),
                    e.set("more", e.flag(e.le(128, p["byte"])))))

            e.if_(e.ne(p["more"], 0), read)

        e.while_(lambda: e.both(e.ne(p["more"], 0), e.eq(_ctrl(e, E_STATUS), OK)), step)
        _set(e, RCUR, p["at"])
        e.give(p["value"])
    return _function((), build, None)


def _mutation(e: E, m, field: int):
    return e.ld(e.add(e.add(MUT, e.mul(m, MUT_WORDS)), field))


def _scan_graph_function():
    """``graph_fragment``'s body grammar over graph ``o`` from ``CUR``, applying its mutations.  In LOCATE mode it
    records each mutated node's operation (``MUT`` field 7) and its entity's reference index (``ENTITY_AT``)."""
    def build(e: E):
        p = e.p
        e.var("mode", _ctrl(e, MODE))
        e.var("nblocks", _call(e, "copy_uleb"))
        _call(e, "copy_uleb")  # the entry block
        e.var("gb", 0)

        def block():
            e.var("np", _call(e, "copy_uleb"))
            e.for_("gp", 0, p["np"], lambda: _call(e, "reference", p["o"], NONE))
            e.var("nn", _call(e, "copy_uleb"))
            e.var("gn", 0)

            def node():
                e.var("gm", NONE)
                e.for_("mq", 0, _ctrl(e, E_MUTATIONS), lambda: e.if_(e.both(
                    e.eq(_mutation(e, p["mq"], 2), p["o"]), e.eq(_mutation(e, p["mq"], 3), p["gb"]), e.eq(_mutation(e, p["mq"], 4), p["gn"])),
                    lambda: e.set("gm", p["mq"])))
                e.var("gop", _call(e, "uleb_read"))
                e.var("gout", p["gop"])
                e.var("edited", e.flag(e.ne(p["gm"], NONE)))
                e.if_(e.both(e.ne(p["edited"], 0), e.eq(_mutation(e, e.sel(e.ne(p["edited"], 0), p["gm"], 0), 0), SET_OPERATION), e.ne(p["mode"], LOCATE)),
                      lambda: e.set("gout", _mutation(e, p["gm"], 6)))
                e.if_(e.both(e.ne(p["edited"], 0), e.eq(p["mode"], LOCATE)),
                      lambda: e.st(e.add(e.add(MUT, e.mul(p["gm"], MUT_WORDS)), 7), e.add(p["gop"], 1 << 32)))  # located
                e.if_(e.eq(p["mode"], EMIT), lambda: _call(e, "put_uleb", p["gout"]))
                e.var("gflags", e.ld(e.add(OPF, e.sel(e.lt(p["gop"], 128), p["gop"], 0))))
                e.if_(e.eq(p["gop"], int(Operation.CALL_GROUP_MEMBER)), lambda: _call(e, "copy_uleb"))

                def entity():
                    e.var("gx", NONE)
                    e.if_(e.both(e.ne(p["edited"], 0), e.ne(p["mode"], LOCATE)), lambda: e.if_(
                        e.eq(_mutation(e, p["gm"], 0), SET_CONSTANT), lambda: e.set("gx", _mutation(e, p["gm"], 7))))
                    e.var("gent", _call(e, "reference", p["o"], p["gx"]))
                    e.if_(e.both(e.ne(p["edited"], 0), e.eq(p["mode"], LOCATE)), lambda: e.st(e.add(ENTITY_AT, p["gm"]), e.add(p["gent"], 1)))

                e.if_(e.ne(e.and_(p["gflags"], 1), 0), entity)

                def operand():
                    e.var("vt", _call(e, "copy_uleb"))
                    _call(e, "copy_uleb")
                    _call(e, "copy_uleb")
                    e.if_(e.eq(p["vt"], 1), lambda: _call(e, "copy_uleb"))

                e.for_("go", 0, _call(e, "copy_uleb"), operand)
                e.for_("gr", 0, _call(e, "copy_uleb"), lambda: _call(e, "reference", p["o"], NONE))
                e.if_(e.ne(e.and_(p["gflags"], 2), 0), lambda: e.for_("ga", 0, _call(e, "copy_uleb"), lambda: _call(e, "copy_uleb")))
                e.set("gn", e.add(p["gn"], 1))

            e.while_(lambda: e.lt(p["gn"], p["nn"]), node)

            def value():
                e.var("tv", _call(e, "copy_uleb"))
                _call(e, "copy_uleb")
                _call(e, "copy_uleb")
                e.if_(e.eq(p["tv"], 1), lambda: _call(e, "copy_uleb"))

            def edge():
                _call(e, "copy_uleb")  # the target
                e.for_("te", 0, _call(e, "copy_uleb"), value)

            e.var("tk", _call(e, "copy_uleb"))
            e.if_(e.eq(p["tk"], 1), edge)
            e.if_(e.eq(p["tk"], 2), lambda: (value(), edge(), edge()))
            e.if_(e.eq(p["tk"], 3), lambda: e.for_("tr", 0, _call(e, "copy_uleb"), value))
            e.if_(e.eq(p["tk"], 4), lambda: _call(e, "copy_string"))
            e.set("gb", e.add(p["gb"], 1))

        e.while_(lambda: e.lt(p["gb"], p["nblocks"]), block)
        e.give(0)
    return _function(("o",), build, None)


def _scan_other_function():
    """The reference-carrying bodies of a function, a package, and a build request, from ``CUR``."""
    def build(e: E):
        p = e.p
        e.var("kind", _kind(e, p["o"]))
        ref = lambda: _call(e, "reference", p["o"], NONE)  # noqa: E731

        def function_():
            ref()
            e.for_("fp", 0, _call(e, "copy_uleb"), ref)
            e.for_("fr", 0, _call(e, "copy_uleb"), ref)

        def package():
            _call(e, "copy_string")
            # Modules: their indices ascend with their CIDs; the emitted one-byte indices are sorted again.
            e.var("pm_count", _call(e, "copy_uleb"))
            e.var("pm_out", _ctrl(e, OUT))
            e.for_("pm", 0, p["pm_count"], ref)

            def sort_modules():
                def inner():
                    e.var("ps_a", e.ld(e.add(BODY, e.add(p["pm_out"], p["ps_j"]))))
                    e.var("ps_b", e.ld(e.add(BODY, e.add(e.add(p["pm_out"], p["ps_j"]), 1))))
                    e.if_(e.lt(p["ps_b"], p["ps_a"]), lambda: (e.st(e.add(BODY, e.add(p["pm_out"], p["ps_j"])), p["ps_b"]),
                                                               e.st(e.add(BODY, e.add(e.add(p["pm_out"], p["ps_j"]), 1)), p["ps_a"])))

                e.for_("ps_i", 0, p["pm_count"], lambda: e.for_("ps_j", 0, e.sub(e.sub(p["pm_count"], 1), p["ps_i"]), inner))

            e.if_(e.eq(_ctrl(e, MODE), EMIT), sort_modules)

            def dependency():
                e.var("pd_form", _call(e, "copy_uleb"))
                e.if_(e.eq(p["pd_form"], 1), ref, lambda: _call(e, "copy_string"))

            e.for_("pd", 0, _call(e, "copy_uleb"), dependency)
            for name in ("pe", "pf", "pc"):
                e.for_(name, 0, _call(e, "copy_uleb"), lambda: (_call(e, "copy_string"), ref()))
            e.for_("pk", 0, _call(e, "copy_uleb"), lambda: (_call(e, "copy_uleb"), _call(e, "copy_string")))

        def request():
            _call(e, "copy_uleb")  # the form
            ref()
            _call(e, "copy_string")
            ref()
            ref()
            for name in ("rf", "rc"):
                e.for_(name, 0, _call(e, "copy_uleb"), lambda: (_call(e, "copy_string"), ref()))
            e.for_("ra", 0, _call(e, "copy_uleb"), lambda: _call(e, "copy_uleb"))

        e.if_(e.eq(p["kind"], int(Kind.FUNCTION)), function_)
        e.if_(e.eq(p["kind"], int(Kind.PACKAGE)), package)
        e.if_(e.eq(p["kind"], int(Kind.BUILD)), request)
        e.give(0)
    return _function(("o",), build, None)


def _reject(e: E, code: str, entity, rule: str, expected, actual):
    D.begin(e)
    D.text(e, code)
    entity()
    D.text(e, rule)
    expected()
    actual()
    _set(e, E_STATUS, REJECT)


def _cid_of(e: E, o):
    D.cid(e, [_cid_word(e, o, k) for k in range(4)])


def _record_cid(e: E, at):
    """A CID quoted from the edit record at word ``at`` (32 bytes)."""
    words = []
    for k in range(4):
        value = e.c(0)
        for j in range(8):
            value = e.add(e.mul(value, 256), e.ld(e.add(at, 8 * k + j)))
        words.append(value)
    D.cid(e, words)


def _begin(tables):
    """``begin``'s stages, each its own function (a function's block arguments carry every variable in scope)."""
    def parse(e: E):
        p = e.p
        _set(e, E_STATUS, OK)
        _set(e, E_EXTRAS, 0)
        _set(e, E_EXTRAS_DONE, 0)
        _set(e, E_MUTATIONS, 0)
        e.st(EC + 42, 0)  # the new references' sources written so far
        _set(e, E_NEW, 0)
        _set(e, E_PRE_END, 0)
        e.var("objects", e.rd(0))
        e.var("root", e.rd(1))
        _set(e, E_OBJECTS, p["objects"])
        _set(e, E_ROOT, p["root"])
        for op in range(128):
            e.st(OPF + op, (1 if op in ENTITY else 0) + (2 if op in ATTRIBUTE else 0))
        e.for_("z", 0, p["objects"], lambda: (e.st(e.add(STATE, p["z"]), 0), e.st(e.add(ALIAS, p["z"]), NONE), e.st(e.add(COPY, p["z"]), 0)))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        e.var("length", _ctrl(e, E_LENGTH))
        e.var("at", EIN)

        def malformed(rule: str):
            def write():
                _reject(e, "XAX.EDIT.RECORD", lambda: D.text(e, "edit"), rule, lambda: D.text(e, "xax-edit-v1"), lambda: D.integer(e, e.sub(p["at"], EIN)))
            return write

        def need(count, rule: str):
            e.if_(e.both(running(), e.lt(e.add(EIN, p["length"]), e.add(p["at"], count))), malformed(rule))

        def byte():
            value = e.ld(p["at"])
            e.set("at", e.add(p["at"], 1))
            return value

        def uleb(name: str):
            _set(e, RCUR, p["at"])
            e.var(name, _call(e, "record_uleb"))
            e.set("at", _ctrl(e, RCUR))
            return p[name]

        need(len(RECORD_MAGIC) + 32, "EDIT-RECORD-MAGIC")

        def magic():
            e.var("magic_ok", 1)
            for k, value in enumerate(RECORD_MAGIC):
                e.set("magic_ok", e.and_(p["magic_ok"], e.flag(e.eq(e.ld(EIN + k), value))))
            e.if_(e.eq(p["magic_ok"], 0), malformed("EDIT-RECORD-MAGIC"))
            e.set("at", EIN + len(RECORD_MAGIC))

        e.if_(running(), magic)

        def expected_root():
            e.var("any_root", 1)
            e.var("same_root", 1)
            for k in range(4):
                e.var(f"er{k}", 0)
                for j in range(8):
                    e.set(f"er{k}", e.add(e.mul(p[f"er{k}"], 256), e.ld(EIN + len(RECORD_MAGIC) + 8 * k + j)))
                e.set("any_root", e.and_(p["any_root"], e.flag(e.eq(p[f"er{k}"], 0))))
                e.set("same_root", e.and_(p["same_root"], e.flag(e.eq(p[f"er{k}"], _cid_word(e, p["root"], k)))))
            e.if_(e.both(e.eq(p["any_root"], 0), e.eq(p["same_root"], 0)), lambda: _reject(
                e, "XAX.WORKSPACE.STALE_ROOT", lambda: D.text(e, "R0"), "WORKSPACE-EXPECTED-ROOT",
                lambda: _record_cid(e, EIN + len(RECORD_MAGIC)), lambda: _cid_of(e, p["root"])))
            e.set("at", EIN + len(RECORD_MAGIC) + 32)

        e.if_(running(), expected_root)
        e.var("count", 0)
        e.if_(running(), lambda: e.set("count", uleb("mutation_count")))
        e.if_(e.both(running(), e.lt(MUT_LIMIT, p["count"])), malformed("EDIT-RECORD-COUNT"))
        e.var("mi", 0)

        def mutation():
            row = e.add(MUT, e.mul(p["mi"], MUT_WORDS))
            e.var("row", row)
            e.var("mkind", uleb("m_kind"))
            e.if_(e.both(running(), e.ne(p["mkind"], SET_OPERATION), e.ne(p["mkind"], SET_CONSTANT)), malformed("EDIT-RECORD-KIND"))
            need(32, "EDIT-RECORD-TARGET")
            e.var("target_at", p["at"])
            e.set("at", e.add(p["at"], 32))
            # The function with that CID.
            for k in range(4):
                e.var(f"tw{k}", 0)
                for j in range(8):
                    e.set(f"tw{k}", e.add(e.mul(p[f"tw{k}"], 256), e.ld(e.add(p["target_at"], 8 * k + j))))
            e.var("function", NONE)
            e.for_("fo", 0, p["objects"], lambda: e.if_(e.both(*(e.eq(_cid_word(e, p["fo"], k), p[f"tw{k}"]) for k in range(4))),
                                                        lambda: e.set("function", p["fo"])))
            e.var("mblock", uleb("m_block"))
            e.var("mnode", uleb("m_node"))
            e.var("mexpected", uleb("m_expected"))
            e.var("mvalue", uleb("m_value"))

            def located():
                e.if_(e.either(e.eq(p["function"], NONE), e.ne(_kind(e, e.sel(e.eq(p["function"], NONE), 0, p["function"])), int(Kind.FUNCTION))),
                      lambda: _reject(e, "XAX.WORKSPACE.HANDLE", lambda: _record_cid(e, p["target_at"]), "WORKSPACE-HANDLE-GENERATION",
                                      lambda: D.text(e, "function at the current root"), lambda: D.text(e, "unbound or stale")))

                def graph():
                    length, at = _plain_body(e, p["function"])
                    e.var("fcur", at)
                    e.var("gidx", 0)
                    e.var("gidx_shift", 1)
                    e.var("gidx_more", 1)

                    def step():
                        e.var("gb_byte", e.rd(p["fcur"]))
                        e.set("gidx", e.add(p["gidx"], e.mul(e.and_(p["gb_byte"], 127), p["gidx_shift"])))
                        e.set("gidx_shift", e.mul(p["gidx_shift"], 128))
                        e.set("gidx_more", e.flag(e.le(128, p["gb_byte"])))
                        e.set("fcur", e.add(p["fcur"], 1))

                    e.while_(lambda: e.ne(p["gidx_more"], 0), step)
                    e.var("graph", _ref(e, p["function"], p["gidx"]))
                    e.var("dup", 0)
                    e.for_("dq", 0, p["mi"], lambda: e.if_(e.both(
                        e.eq(_mutation(e, p["dq"], 2), p["graph"]), e.eq(_mutation(e, p["dq"], 3), p["mblock"]), e.eq(_mutation(e, p["dq"], 4), p["mnode"])),
                        lambda: e.set("dup", 1)))
                    e.if_(e.ne(p["dup"], 0), lambda: _reject(
                        e, "XAX.WORKSPACE.DUPLICATE_MUTATION", lambda: _record_cid(e, p["target_at"]), "WORKSPACE-MUTATION-TARGET-UNIQUE",
                        lambda: D.text(e, "one mutation per node, except one matching disconnect/connect edge-argument pair"), lambda: D.text(e, "duplicate")))
                    for field, value in enumerate((p["mkind"], p["function"], p["graph"], p["mblock"], p["mnode"], p["mexpected"], p["mvalue"], 0)):
                        e.st(e.add(p["row"], field), value)
                    e.st(e.add(ENTITY_AT, p["mi"]), 0)
                    _set(e, E_MUTATIONS, e.add(p["mi"], 1))

                e.if_(running(), graph)

            e.if_(running(), located)
            e.set("mi", e.add(p["mi"], 1))

        e.while_(lambda: e.both(e.lt(p["mi"], p["count"]), running()), mutation)
        e.if_(e.both(running(), e.ne(p["at"], e.add(EIN, p["length"]))), malformed("EDIT-RECORD-END"))
        e.if_(e.both(running(), e.eq(p["count"], 0)), lambda: _reject(
            e, "XAX.WORKSPACE.EMPTY_TRANSACTION", lambda: D.text(e, "R0"), "WORKSPACE-MUTATION-NONEMPTY", lambda: D.text(e, ">= 1 mutation"),
            lambda: D.integer(e, 0)))

        e.give(_ctrl(e, E_STATUS))

    def locate(e: E):
        p = e.p
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("root", _ctrl(e, E_ROOT))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        # Locate every mutated node (one pass per mutated graph) and check its preconditions.
        def check(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            length, at = _graph_body(e, p["cm_graph"])
            e.var("cm_at", at)
            e.var("cm_seen", e.ld(e.add(p["cm_row"], 7)))

            def scan():
                _set(e, CUR, p["cm_at"])
                _set(e, MODE, LOCATE)
                _call(e, "scan_graph", p["cm_graph"])

            e.if_(e.eq(p["cm_seen"], 0), scan)  # a graph with several mutations is scanned once
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def missing():
                _reject(e, "XAX.WORKSPACE.HANDLE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-NODE-INDEX",
                        lambda: D.text(e, "a node of the function's graph"),
                        lambda: (D.put(e, D.T_LIST), D.put(e, 2), D.integer(e, _mutation(e, m, 3)), D.integer(e, _mutation(e, m, 4))))

            e.if_(e.eq(p["cm_located"], 0), missing)

        def precondition(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def preconditions():
                e.var("cm_op", e.sub(p["cm_located"], 1 << 32))
                e.var("cm_kind", _mutation(e, m, 0))

                def operation():
                    def conflict():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-PRECONDITION",
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, _mutation(e, m, 5))),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], _mutation(e, m, 5)), conflict)
                    wrapping = lambda value: e.either(*(e.eq(value, op) for op in WRAPPING))  # noqa: E731

                    def unsupported():
                        _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-CONTRACT-PRESERVED",
                                lambda: D.text(e, "wrapping arithmetic replacement"), lambda: D.integer(e, _mutation(e, m, 6)))

                    e.if_(e.both(running(), e.not_(e.both(wrapping(_mutation(e, m, 6)), wrapping(p["cm_op"])))), unsupported)

                def constant():
                    def not_constant():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-NODE",
                                lambda: D.text(e, Operation.CONSTANT.name),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], int(Operation.CONSTANT)), not_constant)

                    def value():
                        e.var("cm_entity", _ref(e, p["cm_graph"], e.sub(e.ld(e.add(ENTITY_AT, m)), 1)))
                        clen, cat = _plain_body(e, p["cm_entity"])
                        e.var("cm_at", cat)
                        e.var("cm_bytes", e.rd(e.add(p["cm_at"], 1)))  # after the type's reference index (0)
                        e.var("cm_type", _ref(e, p["cm_entity"], 0))
                        tlen, tat = _plain_body(e, p["cm_type"])
                        e.var("cm_form", e.rd(tat))
                        e.var("cm_width", e.rd(e.add(tat, 1)))  # bits<N>, N < 128 (one ULEB byte)

                        def unsupported():
                            _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "EDIT-CONSTANT-BITS",
                                    lambda: D.text(e, "an integer constant of at most 64 bits"), lambda: D.integer(e, p["cm_bytes"]))

                        e.if_(e.either(e.ne(p["cm_form"], 1), e.lt(8, p["cm_bytes"]), e.le(128, p["cm_width"])), unsupported)

                        def checked():
                            e.var("cm_old", 0)
                            e.for_("cb", 0, p["cm_bytes"], lambda: e.set("cm_old", e.add(p["cm_old"], e.mul(
                                e.rd(e.add(e.add(p["cm_at"], 2), p["cb"])), _pow256(e, p["cb"])))))

                            def stale():
                                _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-PRECONDITION",
                                        lambda: D.integer(e, _mutation(e, m, 5)), lambda: D.integer(e, p["cm_old"]))

                            e.if_(e.ne(p["cm_old"], _mutation(e, m, 5)), stale)
                            e.var("cm_value", _mutation(e, m, 6))
                            fits = e.either(e.le(64, p["cm_width"]), e.lt(p["cm_value"], _pow2(e, e.sel(e.lt(p["cm_width"], 64), p["cm_width"], 0))))

                            def range_():
                                _reject(e, "XAX.WORKSPACE.INVALID_VALUE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-RANGE",
                                        lambda: (D.put(e, D.T_FORMAT), D.text(e, "value fitting {}"), D.put(e, 1), _cid_of(e, p["cm_type"])),
                                        lambda: D.integer(e, p["cm_value"]))

                            e.if_(e.both(running(), e.not_(fits)), range_)

                            def extra():
                                e.var("xe", _ctrl(e, E_EXTRAS))
                                e.var("xrow", e.add(EXTRA, e.mul(p["xe"], EXTRA_WORDS)))
                                e.st(p["xrow"], p["cm_type"])
                                e.st(e.add(p["xrow"], 1), p["cm_bytes"])
                                e.st(e.add(p["xrow"], 2), p["cm_value"])
                                e.st(e.add(p["xrow"], 3), NONE)
                                e.st(e.add(p["cm_row"], 7), p["xe"])
                                _set(e, E_EXTRAS, e.add(p["xe"], 1))

                            e.if_(running(), extra)

                        e.if_(running(), checked)

                    e.if_(running(), value)

                e.if_(e.eq(p["cm_kind"], SET_OPERATION), operation, constant)

            e.if_(running(), preconditions)

        e.for_("cmq", 0, e.sel(running(), _ctrl(e, E_MUTATIONS), 0), lambda: e.if_(running(), lambda: check(p["cmq"])))
        e.give(_ctrl(e, E_STATUS))

    def affected_stage(e: E):
        p = e.p
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("root", _ctrl(e, E_ROOT))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        # The affected objects: the mutated graphs and every transitive user.
        def affected():
            e.for_("ag", 0, _ctrl(e, E_MUTATIONS), lambda: e.st(e.add(STATE, _mutation(e, p["ag"], 2)), 1))
            e.var("changed", 1)

            def sweep():
                e.set("changed", 0)

                def each():
                    def users():
                        e.var("hit", 0)
                        e.for_("ar", 0, _nrefs(e, p["ao"]), lambda: e.if_(e.ne(_ref(e, p["ao"], p["ar"]), NONE), lambda: e.if_(
                            e.eq(e.ld(e.add(STATE, _ref(e, p["ao"], p["ar"]))), 1), lambda: e.set("hit", 1))))
                        e.if_(e.ne(p["hit"], 0), lambda: (e.st(e.add(STATE, p["ao"]), 1), e.set("changed", 1)))

                    e.if_(e.eq(e.ld(e.add(STATE, p["ao"])), 0), users)

                e.for_("ao", 0, p["objects"], each)

            e.while_(lambda: e.ne(p["changed"], 0), sweep)
            e.var("count_affected", 0)

            def kind_check():
                def check_one():
                    e.set("count_affected", e.add(p["count_affected"], 1))
                    e.var("ak", _kind(e, p["kc"]))
                    e.var("ak_supported", e.flag(e.either(*(e.eq(p["ak"], int(kind)) for kind in (Kind.GRAPH_FRAGMENT, Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT,
                                                                                 Kind.PACKAGE)))))
                    blen, bat = _plain_body(e, p["kc"])
                    e.var("ak_request", e.flag(e.both(e.eq(p["ak"], int(Kind.BUILD)), e.eq(e.rd(bat), 2))))

                    def group():
                        _reject(e, "XAX.WORKSPACE.TOPOLOGY", lambda: _cid_of(e, p["kc"]), "WORKSPACE-RECURSION-REBUILD",
                                lambda: D.text(e, "non-recursive direct-call users"), lambda: D.text(e, Kind.RECURSION_GROUP.name))

                    def other():
                        _reject(e, "XAX.WORKSPACE.TOPOLOGY", lambda: _cid_of(e, p["kc"]), "WORKSPACE-SUPPORTED-USER",
                                lambda: D.text(e, "graph, function, module, program root, package, or build request"),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Kind")), D.put(e, p["ak"])))

                    e.if_(running(), lambda: e.if_(e.eq(p["ak"], int(Kind.RECURSION_GROUP)), group,
                                                   lambda: e.if_(e.both(e.eq(p["ak_supported"], 0), e.eq(p["ak_request"], 0)), other)))

                e.if_(e.eq(e.ld(e.add(STATE, p["kc"])), 1), check_one)

            e.for_("kc", 0, p["objects"], kind_check)
            _set(e, E_AFFECTED, p["count_affected"])

        e.if_(running(), affected)
        e.give(_ctrl(e, E_STATUS))

    def check_stage(e: E):
        p = e.p
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("root", _ctrl(e, E_ROOT))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        # Locate every mutated node (one pass per mutated graph) and check its preconditions.
        def check(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            length, at = _graph_body(e, p["cm_graph"])
            e.var("cm_at", at)
            e.var("cm_seen", e.ld(e.add(p["cm_row"], 7)))

            def scan():
                _set(e, CUR, p["cm_at"])
                _set(e, MODE, LOCATE)
                _call(e, "scan_graph", p["cm_graph"])

            e.if_(e.eq(p["cm_seen"], 0), scan)  # a graph with several mutations is scanned once
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def missing():
                _reject(e, "XAX.WORKSPACE.HANDLE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-NODE-INDEX",
                        lambda: D.text(e, "a node of the function's graph"),
                        lambda: (D.put(e, D.T_LIST), D.put(e, 2), D.integer(e, _mutation(e, m, 3)), D.integer(e, _mutation(e, m, 4))))

            e.if_(e.eq(p["cm_located"], 0), missing)

        def precondition(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def preconditions():
                e.var("cm_op", e.sub(p["cm_located"], 1 << 32))
                e.var("cm_kind", _mutation(e, m, 0))

                def operation():
                    def conflict():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-PRECONDITION",
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, _mutation(e, m, 5))),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], _mutation(e, m, 5)), conflict)
                    wrapping = lambda value: e.either(*(e.eq(value, op) for op in WRAPPING))  # noqa: E731

                    def unsupported():
                        _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-CONTRACT-PRESERVED",
                                lambda: D.text(e, "wrapping arithmetic replacement"), lambda: D.integer(e, _mutation(e, m, 6)))

                    e.if_(e.both(running(), e.not_(e.both(wrapping(_mutation(e, m, 6)), wrapping(p["cm_op"])))), unsupported)

                def constant():
                    def not_constant():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-NODE",
                                lambda: D.text(e, Operation.CONSTANT.name),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], int(Operation.CONSTANT)), not_constant)

                    def value():
                        e.var("cm_entity", _ref(e, p["cm_graph"], e.sub(e.ld(e.add(ENTITY_AT, m)), 1)))
                        clen, cat = _plain_body(e, p["cm_entity"])
                        e.var("cm_at", cat)
                        e.var("cm_bytes", e.rd(e.add(p["cm_at"], 1)))  # after the type's reference index (0)
                        e.var("cm_type", _ref(e, p["cm_entity"], 0))
                        tlen, tat = _plain_body(e, p["cm_type"])
                        e.var("cm_form", e.rd(tat))
                        e.var("cm_width", e.rd(e.add(tat, 1)))  # bits<N>, N < 128 (one ULEB byte)

                        def unsupported():
                            _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "EDIT-CONSTANT-BITS",
                                    lambda: D.text(e, "an integer constant of at most 64 bits"), lambda: D.integer(e, p["cm_bytes"]))

                        e.if_(e.either(e.ne(p["cm_form"], 1), e.lt(8, p["cm_bytes"]), e.le(128, p["cm_width"])), unsupported)

                        def checked():
                            e.var("cm_old", 0)
                            e.for_("cb", 0, p["cm_bytes"], lambda: e.set("cm_old", e.add(p["cm_old"], e.mul(
                                e.rd(e.add(e.add(p["cm_at"], 2), p["cb"])), _pow256(e, p["cb"])))))

                            def stale():
                                _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-PRECONDITION",
                                        lambda: D.integer(e, _mutation(e, m, 5)), lambda: D.integer(e, p["cm_old"]))

                            e.if_(e.ne(p["cm_old"], _mutation(e, m, 5)), stale)
                            e.var("cm_value", _mutation(e, m, 6))
                            fits = e.either(e.le(64, p["cm_width"]), e.lt(p["cm_value"], _pow2(e, e.sel(e.lt(p["cm_width"], 64), p["cm_width"], 0))))

                            def range_():
                                _reject(e, "XAX.WORKSPACE.INVALID_VALUE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-RANGE",
                                        lambda: (D.put(e, D.T_FORMAT), D.text(e, "value fitting {}"), D.put(e, 1), _cid_of(e, p["cm_type"])),
                                        lambda: D.integer(e, p["cm_value"]))

                            e.if_(e.both(running(), e.not_(fits)), range_)

                            def extra():
                                e.var("xe", _ctrl(e, E_EXTRAS))
                                e.var("xrow", e.add(EXTRA, e.mul(p["xe"], EXTRA_WORDS)))
                                e.st(p["xrow"], p["cm_type"])
                                e.st(e.add(p["xrow"], 1), p["cm_bytes"])
                                e.st(e.add(p["xrow"], 2), p["cm_value"])
                                e.st(e.add(p["xrow"], 3), NONE)
                                e.st(e.add(p["cm_row"], 7), p["xe"])
                                _set(e, E_EXTRAS, e.add(p["xe"], 1))

                            e.if_(running(), extra)

                        e.if_(running(), checked)

                    e.if_(running(), value)

                e.if_(e.eq(p["cm_kind"], SET_OPERATION), operation, constant)

            e.if_(running(), preconditions)

        # The workspace checks the users' topology before each node's precondition.
        e.for_("cpq", 0, e.sel(running(), _ctrl(e, E_MUTATIONS), 0), lambda: e.if_(running(), lambda: precondition(p["cpq"])))
        e.give(_ctrl(e, E_STATUS))

    stages = [_function((), stage, tables) for stage in (parse, locate, affected_stage, check_stage)]

    def build(e: E):
        _set(e, E_STATUS, OK)
        for function, _items in stages:
            e.if_(e.eq(_ctrl(e, E_STATUS), OK), lambda function=function: e.call(function))
        e.give(_ctrl(e, E_STATUS))
    function, items = _function((), build, tables)
    return function, tuple(item for _function_, objects in stages for item in objects) + items


def _pow256(e: E, k):
    """``256 ** k`` for ``k`` below 8."""
    result = e.c(1)
    for bit in range(3):
        result = e.mul(result, e.sel(e.ne(e.and_(e.udiv(k, 1 << bit), 1), 0), 256 ** (1 << bit), 1))
    return result


def _pow2(e: E, k):
    """``2 ** k`` for ``k`` below 64."""
    result = e.c(1)
    for bit in range(6):
        result = e.mul(result, e.sel(e.ne(e.and_(e.udiv(k, 1 << bit), 1), 0), (1 << (1 << bit)) & ((1 << 64) - 1), 1))
    return result


def _pre_uleb(e: E, value):
    p = e.p
    e.var("pv", value)
    e.var("pv_more", 1)

    def step():
        e.var("pv_low", e.and_(p["pv"], 127))
        e.set("pv", e.udiv(p["pv"], 128))
        e.st(e.add(PRE, p["pre"]), e.add(p["pv_low"], e.mul(e.flag(e.ne(p["pv"], 0)), 128)))
        e.set("pre", e.add(p["pre"], 1))
        e.set("pv_more", e.flag(e.ne(p["pv"], 0)))

    e.while_(lambda: e.ne(p["pv_more"], 0), step)


def _pre_byte(e: E, value):
    p = e.p
    e.st(e.add(PRE, p["pre"]), value)
    e.set("pre", e.add(p["pre"], 1))


def _pre_cid(e: E, words):
    for word in words:
        for j in range(8):
            _pre_byte(e, e.and_(e.udiv(word, 1 << (8 * (7 - j))), 255))


def _next(tables):
    def build(e: E):
        p = e.p
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("pre_start", _ctrl(e, E_PRE_END))
        e.var("pre", p["pre_start"])
        e.var("result", DONE)

        def header(kind, nrefs):
            _set(e, E_KIND, kind)
            _set(e, E_NREFS, nrefs)
            _pre_uleb(e, kind)
            _pre_byte(e, 1)
            _pre_uleb(e, nrefs)
            _set(e, E_REFS_AT, p["pre"])

        def body_from(at_word, length):
            _set(e, E_BODY_LENGTH, length)
            _pre_uleb(e, length)
            _set(e, E_BODY_AT, p["pre"])
            e.for_("bq", 0, length, lambda: _pre_byte(e, e.ld(e.add(at_word, p["bq"]))))

        def extra():
            e.var("x", _ctrl(e, E_EXTRAS_DONE))
            e.var("xrow", e.add(EXTRA, e.mul(p["x"], EXTRA_WORDS)))
            e.var("xtype", e.ld(p["xrow"]))
            header(int(Kind.CONSTANT), 1)
            _pre_cid(e, [_cid_word(e, p["xtype"], k) for k in range(4)])
            e.var("xbytes", e.ld(e.add(p["xrow"], 1)))
            e.var("xvalue", e.ld(e.add(p["xrow"], 2)))
            _set(e, E_BODY_LENGTH, e.add(p["xbytes"], 2))
            _pre_uleb(e, e.add(p["xbytes"], 2))
            _set(e, E_BODY_AT, p["pre"])
            _pre_byte(e, 0)
            _pre_byte(e, p["xbytes"])
            e.for_("xb", 0, p["xbytes"], lambda: _pre_byte(e, e.and_(e.udiv(p["xvalue"], _pow256(e, p["xb"])), 255)))
            _set(e, E_SLOT, e.add(p["xrow"], 4))
            _set(e, E_OBJECT, e.add(EXTRA_TAG, p["x"]))
            _set(e, E_EXTRAS_DONE, e.add(p["x"], 1))
            e.set("result", MORE)

        def objects_():
            # The first affected object whose affected references are all rebuilt.
            e.var("ready", NONE)
            e.var("o", 0)

            def find():
                def candidate():
                    e.var("blocked", 0)
                    e.for_("nr", 0, _nrefs(e, p["o"]), lambda: e.if_(e.ne(_ref(e, p["o"], p["nr"]), NONE), lambda: e.if_(
                        e.eq(e.ld(e.add(STATE, _ref(e, p["o"], p["nr"]))), 1), lambda: e.set("blocked", 1))))
                    e.if_(e.eq(p["blocked"], 0), lambda: e.set("ready", p["o"]))

                e.if_(e.eq(e.ld(e.add(STATE, p["o"])), 1), candidate)
                e.set("o", e.add(p["o"], 1))

            e.while_(lambda: e.both(e.lt(p["o"], p["objects"]), e.eq(p["ready"], NONE)), find)
            e.if_(e.ne(p["ready"], NONE), lambda: rebuild(p["ready"]))

        def rebuild(o):
            e.var("ro", o)
            o = p["ro"]
            e.var("rkind", _kind(e, o))
            e.st(EC + 41, 0)  # the sorted references so far
            e.st(EC + 43, 0)  # 1: more references than ``RC_LIMIT``
            # A comparison is kept as a 64-bit flag across control flow: the general backend's register-resident lowering
            # does not carry a ``bits<1>`` value from one branch's block into a later one.
            e.var("is_module", e.flag(e.either(e.eq(p["rkind"], int(Kind.MODULE)), e.eq(p["rkind"], int(Kind.PROGRAM_ROOT)))))

            def module_refs():
                e.for_("mr", 0, _nrefs(e, o), lambda: _module_ref(e, o, p["mr"]))

            def collect():
                _set(e, MODE, COLLECT)
                length, at = _body_of(e, o, "rb")
                _set(e, CUR, at)
                e.if_(e.eq(p["rkind"], int(Kind.GRAPH_FRAGMENT)), lambda: _call(e, "scan_graph", o), lambda: _call(e, "scan_other", o))

            e.if_(e.ne(p["is_module"], 0), module_refs, collect)
            e.if_(e.ne(e.ld(EC + 43), 0), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: _cid_of(e, o), "DRIVER-EDIT-CAPACITY",
                                                           lambda: D.integer(e, RC_LIMIT), lambda: D.text(e, "larger")))
            e.var("m", e.ld(EC + 41))
            # The new references' sources, for ``reach``.
            e.var("rl", e.ld(EC + 42))
            e.st(e.add(RSTART, o), p["rl"])
            e.st(e.add(RCOUNT, o), p["m"])
            e.for_("rs", 0, p["m"], lambda: e.st(e.add(REFL, e.add(p["rl"], p["rs"])), e.ld(e.add(SRS, p["rs"]))))
            e.st(EC + 42, e.add(p["rl"], p["m"]))
            # The body, re-encoded with the new indices.
            _set(e, OUT, 0)

            def module_body():
                _call(e, "put_uleb", p["m"])
                e.for_("mb", 0, p["m"], lambda: _call(e, "put_uleb", p["mb"]))

            def emit():
                _set(e, MODE, EMIT)
                length, at = _body_of(e, o, "eb")
                _set(e, CUR, at)
                e.if_(e.eq(p["rkind"], int(Kind.GRAPH_FRAGMENT)), lambda: _call(e, "scan_graph", o), lambda: _call(e, "scan_other", o))

            e.if_(e.ne(p["is_module"], 0), module_body, emit)
            header(p["rkind"], p["m"])
            e.for_("hc", 0, p["m"], lambda: _pre_cid(e, [e.ld(e.add(e.add(SR, e.mul(p["hc"], 4)), k)) for k in range(4)]))
            body_from(BODY, _ctrl(e, OUT))
            _set(e, E_SLOT, e.add(NEWCID, e.mul(o, 4)))
            _set(e, E_OBJECT, o)
            e.st(e.add(STATE, o), 2)
            e.set("result", MORE)

        def full():
            _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "edit"), "DRIVER-EDIT-CAPACITY", lambda: D.integer(e, PRE_LIMIT), lambda: D.text(e, "larger"))

        room = e.both(e.le(e.add(p["pre_start"], BODY_LIMIT + 32 * RC_LIMIT + 64), PRE_LIMIT), e.lt(_ctrl(e, E_NEW), NEWT_LIMIT))
        e.if_(e.not_(room), full, lambda: e.if_(e.lt(_ctrl(e, E_EXTRAS_DONE), _ctrl(e, E_EXTRAS)), extra, objects_))
        _set(e, E_PRE_AT, e.add(PRE, p["pre_start"]))
        _set(e, E_PRE_LENGTH, e.sub(p["pre"], p["pre_start"]))
        _set(e, E_PRE_END, p["pre"])

        def log():
            e.var("nt", _ctrl(e, E_NEW))
            e.var("ntrow", e.add(NEWT, e.mul(p["nt"], NEWT_WORDS)))
            for field, value in enumerate((p["pre_start"], e.sub(p["pre"], p["pre_start"]), _ctrl(e, E_REFS_AT), _ctrl(e, E_NREFS), _ctrl(e, E_BODY_AT),
                                           _ctrl(e, E_BODY_LENGTH), _ctrl(e, E_KIND), _ctrl(e, E_OBJECT), 0)):
                e.st(e.add(p["ntrow"], field), value)
            _set(e, E_NEW, e.add(p["nt"], 1))

        e.if_(e.eq(p["result"], MORE), log)
        e.give(p["result"])
    return _function((), build, tables)


def _module_ref(e: E, o, k):
    """A module's or program root's reference ``k``, collected."""
    _call(e, "insert", _ref(e, o, k))


def _reach(tables):
    """``COPY``: the old objects the new root reaches, through rebuilt objects' new references (an alias is the old
    object whose CID a new one has) and old objects' own references."""
    def build(e: E):
        p = e.p
        e.var("sp", 0)

        def push(source):
            e.st(e.add(STACK, p["sp"]), source)
            e.set("sp", e.add(p["sp"], 1))

        push(_ctrl(e, E_ROOT))

        def visit():
            e.set("sp", e.sub(p["sp"], 1))
            e.var("s", e.ld(e.add(STACK, p["sp"])))

            def extra():
                e.var("xa", e.ld(e.add(e.add(EXTRA, e.mul(e.sub(p["s"], EXTRA_TAG), EXTRA_WORDS)), 3)))
                e.if_(e.ne(p["xa"], NONE), lambda: push(p["xa"]))

            def object_():
                e.var("st", e.ld(e.add(STATE, p["s"])))
                e.var("al", e.ld(e.add(ALIAS, p["s"])))

                def rebuilt():
                    def fresh():
                        e.st(e.add(COPY, p["s"]), 2)  # visited: its new version is written by the driver, not copied
                        e.for_("rr", 0, e.ld(e.add(RCOUNT, p["s"])), lambda: push(e.ld(e.add(REFL, e.add(e.ld(e.add(RSTART, p["s"])), p["rr"])))))

                    e.if_(e.ne(p["al"], NONE), lambda: e.if_(e.ne(p["al"], p["s"]), lambda: push(p["al"]), lambda: old()), fresh)

                def old():
                    def first():
                        e.st(e.add(COPY, p["s"]), 1)
                        e.for_("or", 0, _nrefs(e, p["s"]), lambda: push(_ref(e, p["s"], p["or"])))

                    e.if_(e.eq(e.ld(e.add(COPY, p["s"])), 0), first)

                e.if_(e.both(e.eq(p["st"], 2), e.eq(e.ld(e.add(COPY, p["s"])), 0)), rebuilt, lambda: e.if_(e.ne(p["st"], 2), old))

            e.if_(e.le(EXTRA_TAG, p["s"]), extra, object_)

        e.while_(lambda: e.ne(p["sp"], 0), visit)
        e.give(0)
    return _function((), build, tables)


def _place(tables):
    """After the driver wrote the newest object's CID at ``E_SLOT``: when an object of the store already has that CID,
    the new object is an alias of it (it is not written again)."""
    def build(e: E):
        p = e.p
        e.var("slot", _ctrl(e, E_SLOT))
        for k in range(4):
            e.var(f"key{k}", e.ld(e.add(p["slot"], k)))
        e.var("lo", 0)
        e.var("hi", _ctrl(e, E_OBJECTS))
        e.var("found", NONE)

        def step():
            e.var("mid", e.udiv(e.add(p["lo"], p["hi"]), 2))
            e.var("below", 0)
            e.var("same", 1)
            for k in range(4):
                e.var(f"c{k}", _cid_word(e, p["mid"], k))
                e.if_(e.ne(p["same"], 0), lambda k=k: e.if_(e.lt(p[f"c{k}"], p[f"key{k}"]), lambda: (e.set("below", 1), e.set("same", 0)),
                                                            lambda: e.if_(e.lt(p[f"key{k}"], p[f"c{k}"]), lambda: e.set("same", 0))))
            e.if_(e.ne(p["same"], 0), lambda: (e.set("found", p["mid"]), e.set("lo", p["hi"])),
                  lambda: e.if_(e.ne(p["below"], 0), lambda: e.set("lo", e.add(p["mid"], 1)), lambda: e.set("hi", p["mid"])))

        e.while_(lambda: e.lt(p["lo"], p["hi"]), step)

        def alias():
            e.var("made", _ctrl(e, E_OBJECT))
            e.if_(e.le(EXTRA_TAG, p["made"]), lambda: e.st(e.add(e.add(EXTRA, e.mul(e.sub(p["made"], EXTRA_TAG), EXTRA_WORDS)), 3), p["found"]),
                  lambda: e.st(e.add(ALIAS, p["made"]), p["found"]))
            e.st(e.add(e.add(NEWT, e.mul(e.sub(_ctrl(e, E_NEW), 1), NEWT_WORDS)), 8), 1)

        e.if_(e.ne(p["found"], NONE), alias)
        e.give(0)
    return _function((), build, tables)


def _batch_byte(e: E, value):
    e.var("bb_at", e.ld(EC + BATCH_AT))
    e.st(e.add(BATCH, e.p["bb_at"]), value)
    e.st(EC + BATCH_AT, e.add(e.p["bb_at"], 1))


def _batch_word(e: E, value):
    e.var("bw_value", value)
    for k in range(8):
        _batch_byte(e, e.and_(e.udiv(e.p["bw_value"], 1 << (8 * k)), 255))


def _batch_cid(e: E, words):
    for word in words:
        e.var("bc_word", word)
        for j in range(8):
            _batch_byte(e, e.and_(e.udiv(e.p["bc_word"], 1 << (8 * (7 - j))), 255))


def _batch(tables):
    """The S9 writer's batch (one byte per word at ``BATCH``): the count, a zero, the end, the root's CID, then each new
    object that is no alias (from its preimage) and each old object ``reach`` kept (from the object table)."""
    def build(e: E):
        p = e.p
        e.st(EC + BATCH_AT, 24)
        e.var("root", _ctrl(e, E_ROOT))
        e.var("root_alias", e.ld(e.add(ALIAS, p["root"])))
        e.var("root_new", e.flag(e.both(e.eq(e.ld(e.add(STATE, p["root"])), 2), e.eq(p["root_alias"], NONE))))
        e.var("root_old", e.sel(e.eq(p["root_alias"], NONE), p["root"], p["root_alias"]))
        e.if_(e.ne(p["root_new"], 0), lambda: _batch_cid(e, [e.ld(e.add(e.add(NEWCID, e.mul(p["root"], 4)), k)) for k in range(4)]),
              lambda: _batch_cid(e, [_cid_word(e, p["root_old"], k) for k in range(4)]))
        e.var("count", 0)
        e.var("full", 0)

        def fits(more):
            return e.le(e.add(e.ld(EC + BATCH_AT), more), BATCH_LIMIT)

        def new_object():
            e.var("row", e.add(NEWT, e.mul(p["nq"], NEWT_WORDS)))

            def write():
                e.var("n_pre", e.add(PRE, e.ld(p["row"])))
                e.var("n_refs", e.ld(e.add(p["row"], 3)))
                e.var("n_body", e.ld(e.add(p["row"], 5)))
                e.var("n_object", e.ld(e.add(p["row"], 7)))
                e.var("n_slot", e.sel(e.le(EXTRA_TAG, p["n_object"]), e.add(e.add(EXTRA, e.mul(e.sub(p["n_object"], EXTRA_TAG), EXTRA_WORDS)), 4),
                                      e.add(NEWCID, e.mul(p["n_object"], 4))))

                def body():
                    _batch_word(e, e.ld(e.add(p["row"], 6)))
                    _batch_word(e, 1)
                    _batch_word(e, p["n_refs"])
                    _batch_word(e, p["n_body"])
                    _batch_cid(e, [e.ld(e.add(p["n_slot"], k)) for k in range(4)])
                    e.var("n_ra", e.add(PRE, e.ld(e.add(p["row"], 2))))
                    e.for_("nr", 0, e.mul(p["n_refs"], 32), lambda: _batch_byte(e, e.ld(e.add(p["n_ra"], p["nr"]))))
                    e.var("n_ba", e.add(PRE, e.ld(e.add(p["row"], 4))))
                    e.for_("nb", 0, p["n_body"], lambda: _batch_byte(e, e.ld(e.add(p["n_ba"], p["nb"]))))
                    e.set("count", e.add(p["count"], 1))

                e.if_(fits(e.add(64, e.add(e.mul(p["n_refs"], 32), p["n_body"]))), body, lambda: e.set("full", 1))

            e.if_(e.eq(e.ld(e.add(p["row"], 8)), 0), write)

        e.for_("nq", 0, _ctrl(e, E_NEW), new_object)

        def old_object():
            def write():
                e.var("o_refs", _nrefs(e, p["oq"]))
                e.var("o_graph", e.flag(e.eq(_kind(e, p["oq"]), int(Kind.GRAPH_FRAGMENT))))
                glen, gat = _graph_body(e, p["oq"])
                plen, pat = _plain_body(e, p["oq"])
                e.var("o_len", e.sel(e.ne(p["o_graph"], 0), glen, plen))
                e.var("o_at", e.sel(e.ne(p["o_graph"], 0), gat, pat))

                def body():
                    _batch_word(e, _kind(e, p["oq"]))
                    _batch_word(e, 1)
                    _batch_word(e, p["o_refs"])
                    _batch_word(e, p["o_len"])
                    _batch_cid(e, [_cid_word(e, p["oq"], k) for k in range(4)])
                    e.for_("or_", 0, p["o_refs"], lambda: _batch_cid(e, [_cid_word(e, _ref(e, p["oq"], p["or_"]), k) for k in range(4)]))
                    e.for_("ob", 0, p["o_len"], lambda: _batch_byte(e, e.rd(e.add(p["o_at"], p["ob"]))))
                    e.set("count", e.add(p["count"], 1))

                e.if_(fits(e.add(64, e.add(e.mul(p["o_refs"], 32), p["o_len"]))), body, lambda: e.set("full", 1))

            e.if_(e.eq(e.ld(e.add(COPY, p["oq"])), 1), write)

        e.for_("oq", 0, _ctrl(e, E_OBJECTS), old_object)
        e.var("end", e.ld(EC + BATCH_AT))
        e.st(EC + BATCH_AT, 0)
        _batch_word(e, p["count"])
        _batch_word(e, 0)
        _batch_word(e, p["end"])
        _set(e, E_BATCH_LENGTH, p["end"])
        e.if_(e.ne(p["full"], 0), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "edit"), "DRIVER-SNAPSHOT-CAPACITY",
                                                  lambda: D.integer(e, BATCH_LIMIT), lambda: D.text(e, "larger")))
        e.give(0)
    return _function((), build, tables)


def build_functions():
    """``{name: function}`` and the objects they need."""
    functions, objects = {}, []
    for name, builder in (("record_uleb", _record_uleb_function), ("uleb_read", _uleb_read_function), ("put_uleb", _put_uleb_function), ("copy_uleb", _copy_uleb_function),
                          ("copy_string", _copy_string_function), ("search", _search_function), ("insert", _insert_function),
                          ("reference", _reference_function), ("scan_graph", _scan_graph_function), ("scan_other", _scan_other_function)):
        _F[name], items = builder()
        objects.extend(items)
    for name, builder in (("edit_begin", _begin), ("edit_next", _next), ("edit_place", _place), ("edit_reach", _reach), ("edit_batch", _batch)):
        function, items = builder(None)
        functions[name] = function
        objects.extend(items)
    return functions, tuple(objects)


def edit_record(mutations, expected_root: bytes = bytes(32)) -> bytes:
    """The edit record for ``mutations``: ``(kind, function CID, block, node, expected, value)`` each."""
    data = bytearray(RECORD_MAGIC + expected_root + uleb(len(mutations)))
    for kind, function_cid, block, node, expected, value in mutations:
        data += uleb(kind) + function_cid + uleb(block) + uleb(node) + uleb(expected) + uleb(value)
    return bytes(data)


def parse_record(record: bytes):
    """``(expected root or None, ((kind, function CID, block, node, expected, value), ...))`` of a well-formed record."""
    from xax_compiler import Cursor

    if record[:len(RECORD_MAGIC)] != RECORD_MAGIC:
        raise ValueError("not an edit record")
    root = record[len(RECORD_MAGIC):len(RECORD_MAGIC) + 32]
    cursor = Cursor(record[len(RECORD_MAGIC) + 32:], "edit")
    mutations = []
    for _ in range(cursor.uleb()):
        kind = cursor.uleb()
        function_cid = cursor.take(32)
        mutations.append((kind, function_cid, cursor.uleb(), cursor.uleb(), cursor.uleb(), cursor.uleb()))
    cursor.end("EDIT-RECORD-END")
    return (None if root == bytes(32) else root), tuple(mutations)


def apply_reference(reader, record: bytes):
    """The store ``edit`` makes from ``reader`` for a well-formed, applicable ``record``, computed in Python: the
    reference the XAX engine is compared with (``tests/test_xax_selfhost_edit.py``), equal to ``Workspace.commit`` for
    the same mutations.  It checks the root and each node's expected operation or value, and nothing else."""
    from xax_compiler import Cursor, SemanticObject, StoreReader, ref_body, write_store

    root, mutations = parse_record(record)
    if root is not None and root != reader.root_cid:
        raise ValueError("stale root")
    objects = {item.cid: item for item in reader.objects()}
    edits: dict[bytes, dict[tuple[int, int], tuple]] = {}
    extras: dict[tuple[bytes, int, int], SemanticObject] = {}
    for kind, function_cid, block, node, expected, value in mutations:
        function_object = objects[function_cid]
        graph = objects[function_object.references[Cursor(function_object.body, "").uleb()]]
        edits.setdefault(graph.cid, {})[(block, node)] = (kind, expected, value)

    def scan(owner: SemanticObject, on_reference, emit: bool) -> bytes:
        cursor, out = Cursor(owner.body, owner.cid.hex()), bytearray()
        edited = edits.get(owner.cid, {})

        def copy():
            number = cursor.uleb()
            out.extend(uleb(number))
            return number

        def string():
            out.extend(cursor.take(copy()))

        def reference(site=None):
            out.extend(on_reference(cursor.uleb(), site))

        def value():
            tag = copy()
            copy()
            copy()
            if tag == 1:
                copy()

        if owner.kind == Kind.GRAPH_FRAGMENT:
            blocks = copy()
            copy()
            for b in range(blocks):
                for _ in range(copy()):
                    reference()
                for n in range(copy()):
                    operation = cursor.uleb()
                    mutation = edited.get((b, n))
                    if mutation is not None and mutation[0] == SET_OPERATION:
                        if operation != mutation[1]:
                            raise ValueError("operation precondition")
                        out.extend(uleb(mutation[2]))
                    else:
                        out.extend(uleb(operation))
                    if operation == int(Operation.CALL_GROUP_MEMBER):
                        copy()
                    if operation in ENTITY:
                        reference((b, n) if mutation is not None and mutation[0] == SET_CONSTANT else None)
                    for _ in range(copy()):
                        value()
                    for _ in range(copy()):
                        reference()
                    if operation in ATTRIBUTE:
                        for _ in range(copy()):
                            copy()
                terminator = copy()
                if terminator == 1:
                    copy()
                    for _ in range(copy()):
                        value()
                elif terminator == 2:
                    value()
                    for _edge in range(2):
                        copy()
                        for _ in range(copy()):
                            value()
                elif terminator == 3:
                    for _ in range(copy()):
                        value()
                elif terminator == 4:
                    string()
        elif owner.kind == Kind.FUNCTION:
            reference()
            for _ in range(copy()):
                reference()
            for _ in range(copy()):
                reference()
        elif owner.kind == Kind.BUILD:
            copy()
            reference()
            string()
            reference()
            reference()
            for _ in range(2):
                for _ in range(copy()):
                    string()
                    reference()
            for _ in range(copy()):
                copy()
        elif owner.kind == Kind.PACKAGE:
            string()
            modules = [cursor.uleb() for _ in range(cursor.uleb())]
            out.extend(uleb(len(modules)))
            for encoded in sorted((on_reference(index, None) for index in modules), key=lambda item: Cursor(item, "").uleb()):
                out.extend(encoded)
            for _ in range(copy()):
                if copy() == 1:
                    reference()
                else:
                    string()
            for _ in range(3):
                for _ in range(copy()):
                    string()
                    reference()
            for _ in range(copy()):
                copy()
                string()
        else:
            raise ValueError(f"unsupported user {owner.kind.name}")
        cursor.end("EDIT-SCAN")
        return bytes(out)

    users: dict[bytes, list[bytes]] = {}
    for item in objects.values():
        for child in item.references:
            users.setdefault(child, []).append(item.cid)
    affected, pending = set(edits), list(edits)
    while pending:
        for user in users.get(pending.pop(), ()):
            if user not in affected:
                affected.add(user)
                pending.append(user)
    for cid in affected:
        if objects[cid].kind not in (Kind.GRAPH_FRAGMENT, Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.PACKAGE, Kind.BUILD):
            raise ValueError(f"unsupported user {objects[cid].kind.name}")
    # The new constants.
    for graph_cid, nodes in edits.items():
        def locate(index, site, graph_cid=graph_cid):
            if site is not None:
                old = objects[objects[graph_cid].references[index]]
                kind, expected, value = edits[graph_cid][site]
                if int.from_bytes(old.body[2:], "little") != expected:
                    raise ValueError("constant precondition")
                extras[(graph_cid, *site)] = SemanticObject.create(Kind.CONSTANT, old.body[:2] + value.to_bytes(old.body[1], "little"), old.references)
            return b""
        scan(objects[graph_cid], locate, False)
    new: dict[bytes, SemanticObject] = {}

    def current(cid: bytes) -> bytes:
        return new[cid].cid if cid in new else cid

    done: set[bytes] = set()
    while len(done) < len(affected):
        for cid in sorted(affected):
            owner = objects[cid]
            if cid in done or any(child in affected and child not in done for child in owner.references):
                continue
            if owner.kind in (Kind.MODULE, Kind.PROGRAM_ROOT):
                references = sorted({current(child) for child in owner.references})
                body = ref_body(range(len(references)))
            else:
                collected: list[bytes] = []

                def collect(index, site, owner=owner):
                    extra = extras.get((owner.cid, *site)) if site is not None else None
                    collected.append(extra.cid if extra is not None else current(owner.references[index]))
                    return b""

                scan(owner, collect, False)
                references = sorted(set(collected))
                order = iter(collected)
                body = scan(owner, lambda _index, _site: uleb(references.index(next(order))), True)
            new[cid] = SemanticObject.create(owner.kind, body, references)
            done.add(cid)
    pool = {**objects, **{item.cid: item for item in new.values()}, **{item.cid: item for item in extras.values()}}
    root_cid = current(reader.root_cid)
    reached, pending = {}, [root_cid]
    while pending:
        cid = pending.pop()
        if cid not in reached:
            reached[cid] = pool[cid]
            pending.extend(pool[cid].references)
    return StoreReader(write_store(root_cid, tuple(reached.values())))


__all__ = ["EB", "RECORD_MAGIC", "SET_CONSTANT", "SET_OPERATION", "apply_reference", "build_functions", "edit_record", "parse_record"]
