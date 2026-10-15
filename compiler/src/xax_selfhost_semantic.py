"""Self-hosting step S10e (ADR-266): the semantic-verification inputs ``verify_store`` marshals, as XAX functions.

``verify_store`` asks five XAX programs for their decisions (ADR-251), but Python builds their inputs: the type and
constant verdict stream (``xax_selfhost_typing.marshal(objects=...)``), the store verifier's object table
(``xax_selfhost_verify.object_table``), each graph's CFG input (``_cfg_tables``, ``_cfg_uses``), and each graph's
typing-and-facts stream (``marshal`` with ``_facts_section``, ``_callee_summary``, ``_callee_links``).  This module
builds the same words in XAX, so the compiler driver (``xax_selfhost_driver``) verifies a store without Python.

Every function here has the facts engine's helper convention (``xax_selfhost_facts._function``): the input view is
the store verifier's object table (built by the driver; ``index_objects`` locates each record), the output view a
workspace whose words are laid out below.  Arguments travel in the workspace's control words (``CTRL``), so each
function has no machine arguments and a host test can call it alone.  A capacity overflow sets ``C_STATUS`` to
``DECLINE``; the driver then makes no claim.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation, TerminatorKind
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_typing import ATTRIBUTE_LIMIT, COVERED, PADDING

# -- the workspace (64-bit words of the output view) ------------------------------------------------------------------
MAX_OBJECTS, MAX_ENTRIES, MAX_BLOCKS, MAX_NODES, MAX_VALUES = 1 << 16, 1 << 16, 1 << 16, 1 << 19, 1 << 20
BLOCK_WORDS, NODE_WORDS, ENTRY_WORDS = 7, 10, 4


def _layout():
    regions = (("CTRL", 64), ("OBJAT", MAX_OBJECTS), ("MEMO", MAX_OBJECTS), ("LISTED", MAX_OBJECTS), ("ENT", ENTRY_WORDS * MAX_ENTRIES),
               ("ARENA", 1 << 20), ("STACK", 2 * MAX_ENTRIES), ("BLK", BLOCK_WORDS * MAX_BLOCKS), ("NODE", NODE_WORDS * MAX_NODES),
               ("VT", MAX_VALUES), ("VNUM", MAX_VALUES), ("ORDER", MAX_BLOCKS), ("SITE", MAX_NODES), ("KEYIDX", MAX_NODES),
               ("EDGEBASE", MAX_BLOCKS), ("INCCOUNT", MAX_BLOCKS), ("INCAT", MAX_BLOCKS), ("INCLIST", 1 << 18), ("LINKS", 1 << 12),
               ("SCRATCH", 1 << 14), ("CUT", MAX_BLOCKS))
    at, table = 0, {}
    for name, size in regions:
        table[name] = at
        at += size
    return table, at


_REGIONS, _END = _layout()
globals().update(_REGIONS)
MARSHAL_AT, MARSHAL_LIMIT = 12 << 20, 8 << 20  # the typing program's input words (IN_WORDS)
NODES_TMP, SECTION_TMP, FACTS_TMP = 20 << 20, 23 << 20, 24 << 20
NODES_LIMIT, SECTION_LIMIT, FACTS_LIMIT = 3 << 20, 1 << 20, 5 << 20
CFG_AT, CFG_LIMIT = 29 << 20, 2 << 20  # the CFG program's input words (its IN_WORDS)
assert _END <= MARSHAL_AT

# Control words: status, the graph object, lengths and counts.
(C_STATUS, C_GRAPH, C_LENGTH, C_ENTRIES, C_ARENA, C_BLOCKS, C_ENTRY, C_NODES, C_VALUES, C_KEYS, C_VCOUNT, C_CFG_LENGTH, C_OBJECTS,
 C_EDGES, C_KINDS, C_SP, C_TOP, C_USES) = range(18)  # ``C_USES``: the CFG input's use count word (S15b.3c)
OK, DECLINE = 0, 1
MODE_OTHER, MODE_FULL, MODE_KIND = 0, 1, 2
BODY_LIMIT, TARGET_BODY_LIMIT, NATIVE_TARGET_LIMIT = 64, 4096, 1 << 16  # ``type_info_from``
ENTITY_CODES = (5, 6, 30, 41, 42, 43)
ATTRIBUTE_CODES = tuple(sorted(int(op) for op in __import__("xax_compiler").ATTRIBUTE_OPERATIONS))
STACK_OWNER_BODY = (4, 1, 1)  # ``_is_stack_owner``
TYPE_, CONSTANT_, FUNCTION_, TARGET_, GRAPH_, GROUP_, CONTRACT_ = (int(Kind.TYPE), int(Kind.CONSTANT), int(Kind.FUNCTION), int(Kind.TARGET),
                                                                  int(Kind.GRAPH_FRAGMENT), int(Kind.RECURSION_GROUP), int(Kind.CALL_CONTRACT))

_FN: dict = {}


def _call(e: E, name: str):
    return e.call(_FN[name])


def _decline(e: E, condition):
    e.if_(condition, lambda: e.st(CTRL + C_STATUS, DECLINE))


def _ctrl(e: E, field: int):
    return e.ld(CTRL + field)


def _set_ctrl(e: E, field: int, value):
    e.st(CTRL + field, value)


# -- the object table (``object_table``): kind, references, CID, payload ---------------------------------------------

def _at(e: E, o):
    return e.ld(e.add(OBJAT, o))


def _kind(e: E, o):
    return e.rd(_at(e, o))


def _nrefs(e: E, o):
    return e.rd(e.add(_at(e, o), 1))


def _ref(e: E, o, k):
    return e.rd(e.add(e.add(_at(e, o), 2), k))


def _cid_word(e: E, o, k):
    return e.rd(e.add(e.add(e.add(_at(e, o), 2), _nrefs(e, o)), k))


def _payload(e: E, o):
    """The payload's first word (its length) for any object; for a graph it is the stream's length."""
    return e.add(e.add(_at(e, o), 6), _nrefs(e, o))


def _body(e: E, o):
    """``(length, first byte word)`` of a non-graph object's body."""
    at = _payload(e, o)
    return e.rd(at), e.add(at, 1)


def _stream(e: E, o):
    """The first stream word of graph object ``o``."""
    return e.add(_payload(e, o), 1)


def _index_objects(tables):
    """Record each object's table position in ``OBJAT``; ``C_OBJECTS`` = their count."""
    def build(e: E):
        p = e.p
        e.var("n", e.rd(0))
        _set_ctrl(e, C_OBJECTS, p["n"])
        _decline(e, e.lt(MAX_OBJECTS, p["n"]))
        e.var("at", 2)

        def each():
            e.st(e.add(OBJAT, p["o"]), p["at"])
            kind, refs = e.rd(p["at"]), e.rd(e.add(p["at"], 1))
            e.var("pay", e.add(e.add(p["at"], 6), refs))

            def graph():
                stream = e.rd(p["pay"])
                body_at = e.add(e.add(p["pay"], 1), stream)
                e.set("at", e.add(e.add(e.add(body_at, 1), e.rd(body_at)), 1))

            e.if_(e.eq(kind, GRAPH_), graph, lambda: e.set("at", e.add(e.add(p["pay"], 1), e.rd(p["pay"]))))

        e.for_("o", 0, e.sel(e.lt(MAX_OBJECTS, p["n"]), 0, p["n"]), each)
        e.give(p["n"])
    return _function((), build, tables)


# -- ``type_index`` (``marshal``): entries in depth-first first-visit order ------------------------------------------

def _mode(e: E, o):
    """``type_info_from``'s reading of object ``o``: full, kind only, or (unresolvable) NONE."""
    kind = _kind(e, o)
    length = e.sel(e.eq(kind, GRAPH_), 0, e.rd(_payload(e, o)))
    limit = e.sel(e.eq(kind, TARGET_), NATIVE_TARGET_LIMIT, TARGET_BODY_LIMIT)
    first = e.both(e.either(*(e.eq(kind, k) for k in (TARGET_, GROUP_, CONTRACT_, TYPE_))), e.le(length, limit))
    kind_only = e.either(e.lt(BODY_LIMIT, length), e.not_(e.either(*(e.eq(kind, k) for k in (TYPE_, CONSTANT_, FUNCTION_)))))
    return e.sel(first, MODE_FULL, e.sel(kind_only, MODE_KIND, MODE_FULL))


def _type_index(tables):
    """``type_index`` of object ``C_TOP`` (NONE: an unresolvable reference)."""
    def build(e: E):
        p = e.p
        e.var("o", _ctrl(e, C_TOP))
        e.if_(e.eq(p["o"], NONE), lambda: e.give(NONE))
        e.if_(e.ne(e.ld(e.add(MEMO, p["o"])), NONE), lambda: e.give(e.ld(e.add(MEMO, p["o"]))))
        e.var("sp", 0)

        def visit(o):
            index = _ctrl(e, C_ENTRIES)
            e.var("vi", index)
            full = e.lt(p["vi"], MAX_ENTRIES)
            _decline(e, e.not_(full))

            def enter():
                at = e.add(ENT, e.mul(p["vi"], ENTRY_WORDS))
                e.st(at, o)
                e.st(e.add(at, 1), _mode(e, o))
                e.st(e.add(MEMO, o), p["vi"])
                _set_ctrl(e, C_ENTRIES, e.add(p["vi"], 1))
                e.st(e.add(STACK, e.mul(p["sp"], 2)), o)
                e.st(e.add(STACK, e.add(e.mul(p["sp"], 2), 1)), 0)
                e.set("sp", e.add(p["sp"], 1))

            e.if_(e.both(full, e.lt(p["sp"], MAX_ENTRIES)), enter, lambda: e.set("sp", 0))

        visit(p["o"])

        def step():
            top = e.add(STACK, e.mul(e.sub(p["sp"], 1), 2))
            e.var("t", e.ld(top))
            e.var("k", e.ld(e.add(top, 1)))
            entry = e.add(ENT, e.mul(e.ld(e.add(MEMO, p["t"])), ENTRY_WORDS))
            e.var("entry", entry)
            e.var("count", e.mul(e.flag(e.eq(e.ld(e.add(p["entry"], 1)), MODE_FULL)), _nrefs(e, p["t"])))

            def child():
                e.st(e.add(top, 1), e.add(p["k"], 1))
                e.var("c", _ref(e, p["t"], p["k"]))
                e.if_(e.both(e.ne(p["c"], NONE), e.eq(e.ld(e.add(MEMO, e.sel(e.eq(p["c"], NONE), 0, p["c"]))), NONE)), lambda: visit(p["c"]))

            def finish():
                e.var("refs_at", _ctrl(e, C_ARENA))
                e.var("bad", 0)

                def each():
                    r = _ref(e, p["t"], p["q"])
                    e.var("r", r)
                    e.if_(e.eq(p["r"], NONE), lambda: e.set("bad", 1),
                          lambda: e.st(e.add(ARENA, e.add(p["refs_at"], p["q"])), e.ld(e.add(MEMO, p["r"]))))

                e.for_("q", 0, p["count"], each)
                _decline(e, e.lt(1 << 20, e.add(p["refs_at"], p["count"])))
                e.st(e.add(p["entry"], 2), p["refs_at"])
                e.if_(e.ne(p["bad"], 0), lambda: (e.st(e.add(p["entry"], 1), MODE_OTHER), e.st(e.add(p["entry"], 3), 0)),
                      lambda: (e.st(e.add(p["entry"], 3), p["count"]), _set_ctrl(e, C_ARENA, e.add(p["refs_at"], p["count"]))))
                e.set("sp", e.sub(p["sp"], 1))

            e.if_(e.lt(p["k"], p["count"]), child, finish)

        e.while_(lambda: e.ne(p["sp"], 0), step)
        e.give(e.ld(e.add(MEMO, p["o"])))
    return _function((), build, tables)


def _tidx(e: E, o):
    _set_ctrl(e, C_TOP, o)
    return _call(e, "type_index")


def _reset_types(e: E):
    p = e.p
    e.for_("rq", 0, _ctrl(e, C_OBJECTS), lambda: e.st(e.add(MEMO, p["rq"]), NONE))
    _set_ctrl(e, C_ENTRIES, 0)
    _set_ctrl(e, C_ARENA, 0)


def _emit(e: E, cursor: str, value, limit_end: int):
    p = e.p
    e.if_(e.lt(p[cursor], limit_end), lambda: e.st(p[cursor], value), lambda: e.st(CTRL + C_STATUS, DECLINE))
    e.set(cursor, e.add(p[cursor], 1))


def _serialize_entries(e: E, cursor: str):
    """``[count, per entry: kind, references, body length, body bytes, reference indices]``."""
    p = e.p
    end = MARSHAL_AT + MARSHAL_LIMIT
    _emit(e, cursor, _ctrl(e, C_ENTRIES), end)

    def each():
        at = e.add(ENT, e.mul(p["sq"], ENTRY_WORDS))
        e.var("so", e.ld(at))
        e.var("smode", e.ld(e.add(at, 1)))
        e.var("srefs_at", e.ld(e.add(at, 2)))
        e.var("srefs", e.mul(e.flag(e.eq(p["smode"], MODE_FULL)), e.ld(e.add(at, 3))))
        e.var("sblen", 0)
        e.var("sbat", 0)
        e.if_(e.eq(p["smode"], MODE_FULL), lambda: (e.set("sblen", e.rd(_payload(e, p["so"]))), e.set("sbat", e.add(_payload(e, p["so"]), 1))))
        _emit(e, cursor, e.mul(e.flag(e.ne(p["smode"], MODE_OTHER)), _kind(e, p["so"])), end)
        _emit(e, cursor, p["srefs"], end)
        _emit(e, cursor, p["sblen"], end)
        e.for_("sb", 0, p["sblen"], lambda: _emit(e, cursor, e.rd(e.add(p["sbat"], p["sb"])), end))
        e.for_("sr", 0, p["srefs"], lambda: _emit(e, cursor, e.ld(e.add(ARENA, e.add(p["srefs_at"], p["sr"]))), end))

    e.for_("sq", 0, _ctrl(e, C_ENTRIES), each)


def _objects_marshal(tables):
    """``marshal([], ..., objects=pending)``: every type and constant, in store order; ``LISTED`` holds each object's
    entry index (NONE for other kinds)."""
    def build(e: E):
        p = e.p
        _reset_types(e)

        def each():
            e.st(e.add(LISTED, p["o"]), NONE)
            kind = _kind(e, p["o"])
            e.if_(e.either(e.eq(kind, TYPE_), e.eq(kind, CONSTANT_)), lambda: e.st(e.add(LISTED, p["o"]), _tidx(e, p["o"])))

        e.for_("o", 0, _ctrl(e, C_OBJECTS), each)
        e.var("cur", MARSHAL_AT)
        _serialize_entries(e, "cur")
        for _word in range(3 + PADDING):  # no nodes, no blocks, no facts section, the padding
            _emit(e, "cur", 0, MARSHAL_AT + MARSHAL_LIMIT)
        _set_ctrl(e, C_LENGTH, e.sub(p["cur"], MARSHAL_AT))
        e.give(1)
    return _function((), build, tables)


# -- one graph: its stream parsed into blocks, nodes, and value types -------------------------------------------------

def _blk(e: E, b, field: int):
    return e.ld(e.add(BLK, e.add(e.mul(b, BLOCK_WORDS), field)))


def _node(e: E, n, field: int):
    return e.ld(e.add(NODE, e.add(e.mul(n, NODE_WORDS), field)))


# ``B_TRAP``: S15b.3c (ADR-295), the block trimmed at an invalid use (its first ``B_COUNT`` nodes, then a trap).
B_PARAMS, B_TYPES, B_FIRST, B_COUNT, B_TERM, B_BASE, B_TRAP = range(7)
N_OP, N_ENTITY, N_OPS, N_NOPS, N_NRES, N_RES, N_ATTRS, N_NATTRS, N_BASE, N_BLOCK = range(10)


def _skip_value(e: E, name: str):
    p = e.p
    e.set(name, e.add(e.add(p[name], 3), e.flag(e.eq(e.rd(p[name]), 1))))


def _parse_graph(tables):
    """Graph ``C_GRAPH``'s stream into ``BLK``, ``NODE``, and ``VT`` (each value's type object)."""
    def build(e: E):
        p = e.p
        e.var("g", _ctrl(e, C_GRAPH))
        e.var("at", _stream(e, p["g"]))
        e.var("B", e.rd(p["at"]))
        _set_ctrl(e, C_BLOCKS, p["B"])
        _set_ctrl(e, C_ENTRY, e.rd(e.add(p["at"], 1)))
        _decline(e, e.lt(MAX_BLOCKS, p["B"]))
        e.set("at", e.add(p["at"], 2))
        e.var("nodes", 0)
        e.var("values", 0)

        def put(base, index, field: int, value):
            e.st(e.add(base, e.add(e.mul(index, BLOCK_WORDS if base == BLK else NODE_WORDS), field)), value)

        def block():
            e.var("pc", e.rd(p["at"]))
            put(BLK, p["b"], B_PARAMS, p["pc"])
            put(BLK, p["b"], B_TYPES, e.add(p["at"], 1))
            put(BLK, p["b"], B_BASE, p["values"])
            e.for_("q", 0, p["pc"], lambda: e.if_(e.lt(e.add(p["values"], p["q"]), MAX_VALUES), lambda: e.st(
                e.add(VT, e.add(p["values"], p["q"])), _ref(e, p["g"], e.rd(e.add(e.add(p["at"], 1), p["q"]))))))
            e.set("values", e.add(p["values"], p["pc"]))
            e.set("at", e.add(e.add(p["at"], 1), p["pc"]))
            e.var("nc", e.rd(p["at"]))
            e.set("at", e.add(p["at"], 1))
            put(BLK, p["b"], B_FIRST, p["nodes"])
            put(BLK, p["b"], B_COUNT, p["nc"])

            def node():
                e.var("n", p["nodes"])
                _decline(e, e.le(MAX_NODES, p["n"]))
                e.var("opc", e.rd(p["at"]))
                e.set("at", e.add(p["at"], 1))
                e.if_(e.eq(p["opc"], int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("at", e.add(p["at"], 3)))
                e.var("entity", NONE)
                e.if_(e.either(*(e.eq(p["opc"], code) for code in ENTITY_CODES)), lambda: (
                    e.set("entity", _ref(e, p["g"], e.rd(p["at"]))), e.set("at", e.add(p["at"], 1))))
                put(NODE, p["n"], N_OP, p["opc"])
                put(NODE, p["n"], N_ENTITY, p["entity"])
                put(NODE, p["n"], N_BLOCK, p["b"])
                put(NODE, p["n"], N_NOPS, e.rd(p["at"]))
                e.set("at", e.add(p["at"], 1))
                put(NODE, p["n"], N_OPS, p["at"])
                e.for_("q", 0, _node(e, p["n"], N_NOPS), lambda: _skip_value(e, "at"))
                e.var("nr", e.rd(p["at"]))
                put(NODE, p["n"], N_NRES, p["nr"])
                put(NODE, p["n"], N_RES, e.add(p["at"], 1))
                put(NODE, p["n"], N_BASE, p["values"])
                e.for_("q", 0, p["nr"], lambda: e.if_(e.lt(e.add(p["values"], p["q"]), MAX_VALUES), lambda: e.st(
                    e.add(VT, e.add(p["values"], p["q"])), _ref(e, p["g"], e.rd(e.add(e.add(p["at"], 1), p["q"]))))))
                e.set("values", e.add(p["values"], p["nr"]))
                e.set("at", e.add(e.add(p["at"], 1), p["nr"]))
                put(NODE, p["n"], N_NATTRS, 0)
                put(NODE, p["n"], N_ATTRS, p["at"])

                def attributes():
                    put(NODE, p["n"], N_NATTRS, e.rd(p["at"]))
                    put(NODE, p["n"], N_ATTRS, e.add(p["at"], 1))
                    e.set("at", e.add(e.add(p["at"], 1), e.rd(p["at"])))

                e.if_(e.either(*(e.eq(p["opc"], code) for code in ATTRIBUTE_CODES)), attributes)
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, p["nc"], node)
            put(BLK, p["b"], B_TERM, p["at"])
            put(BLK, p["b"], B_TRAP, 0)
            e.st(e.add(CUT, p["b"]), NONE)
            e.var("kind", e.rd(p["at"]))
            e.set("at", e.add(p["at"], 1))

            def edge():
                e.set("at", e.add(p["at"], 1))
                e.var("ec", e.rd(p["at"]))
                e.set("at", e.add(p["at"], 1))
                e.for_("q", 0, p["ec"], lambda: _skip_value(e, "at"))

            def values_list():
                e.var("vc", e.rd(p["at"]))
                e.set("at", e.add(p["at"], 1))
                e.for_("q", 0, p["vc"], lambda: _skip_value(e, "at"))

            e.if_(e.eq(p["kind"], 1), edge, lambda: e.if_(e.eq(p["kind"], 2), lambda: (_skip_value(e, "at"), edge(), edge()), lambda: e.if_(
                e.eq(p["kind"], 3), values_list, lambda: e.set("at", e.add(p["at"], 2)))))

        e.for_("b", 0, e.sel(e.lt(MAX_BLOCKS, p["B"]), 0, p["B"]), block)
        _decline(e, e.lt(MAX_VALUES, p["values"]))
        _set_ctrl(e, C_NODES, p["nodes"])
        _set_ctrl(e, C_VALUES, p["values"])
        e.give(1)
    return _function((), build, tables)


def _value_id(e: E, at):
    """The value at stream word ``at``: parameter ``(block, index)`` or result ``(block, node, result)``."""
    tag, block, index = e.rd(at), e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
    parameter = e.add(_blk(e, block, B_BASE), index)
    result = e.add(_node(e, e.add(_blk(e, block, B_FIRST), index), N_BASE), e.rd(e.add(at, 3)))
    return e.sel(e.eq(tag, 0), parameter, result)


def _value_size(e: E, at):
    return e.add(3, e.flag(e.eq(e.rd(at), 1)))


def _vt(e: E, value):
    return e.ld(e.add(VT, e.sel(e.lt(value, MAX_VALUES), value, 0)))


# -- the CFG input (``_cfg_tables``, ``_cfg_uses``, ``analyze``) -----------------------------------------------------------

def _terminator_parts(e: E, b, on_value, on_edge):
    """Walk block ``b``'s terminator: ``on_value(stream at)`` for each terminator value (a condition or returned
    value), ``on_edge(target, argument count, first argument at)`` for each edge, in stream order."""
    p = e.p
    e.var("tp", _blk(e, b, B_TERM))
    e.var("tk", e.sel(e.ne(_blk(e, b, B_TRAP), 0), int(TerminatorKind.TRAP), e.rd(p["tp"])))  # a trimmed block ends in a trap
    e.set("tp", e.add(p["tp"], 1))

    def edge():
        target, count = e.rd(p["tp"]), e.rd(e.add(p["tp"], 1))
        e.var("te_target", target)
        e.var("te_count", count)
        e.set("tp", e.add(p["tp"], 2))
        on_edge(p["te_target"], p["te_count"], p["tp"])
        e.for_("teq", 0, p["te_count"], lambda: e.set("tp", e.add(p["tp"], _value_size(e, p["tp"]))))

    def conditional():
        on_value(p["tp"])
        e.set("tp", e.add(p["tp"], _value_size(e, p["tp"])))
        edge()
        edge()

    def returned():
        e.var("trc", e.rd(p["tp"]))
        e.set("tp", e.add(p["tp"], 1))

        def each():
            on_value(p["tp"])
            e.set("tp", e.add(p["tp"], _value_size(e, p["tp"])))

        e.for_("trq", 0, p["trc"], each)

    e.if_(e.eq(p["tk"], 1), edge, lambda: e.if_(e.eq(p["tk"], 2), conditional, lambda: e.if_(e.eq(p["tk"], 3), returned)))
    return p["tk"]


def _cfg_input(tables):
    def build(e: E):
        p = e.p
        e.var("cur", CFG_AT)
        end = CFG_AT + CFG_LIMIT
        B = _ctrl(e, C_BLOCKS)
        e.var("B", B)
        _emit(e, "cur", p["B"], end)
        _emit(e, "cur", _ctrl(e, C_ENTRY), end)

        def targets():
            e.var("ct_count_at", p["cur"])
            _emit(e, "cur", 0, end)
            e.var("ct_n", 0)

            def on_edge(target, _count, _at):
                _emit(e, "cur", target, end)
                e.set("ct_n", e.add(p["ct_n"], 1))

            _terminator_parts(e, p["b"], lambda _at: None, on_edge)
            e.if_(e.lt(p["ct_count_at"], end), lambda: e.st(p["ct_count_at"], p["ct_n"]))

        e.for_("b", 0, p["B"], targets)

        def table():
            _emit(e, "cur", _blk(e, p["b"], B_PARAMS), end)
            _emit(e, "cur", _blk(e, p["b"], B_COUNT), end)
            e.for_("m", 0, _blk(e, p["b"], B_COUNT), lambda: _emit(e, "cur", _node(e, e.add(_blk(e, p["b"], B_FIRST), p["m"]), N_NRES), end))

        e.for_("b", 0, p["B"], table)
        e.var("uses_at", p["cur"])
        _emit(e, "cur", 0, end)
        e.var("uses", 0)

        def use(b, n, at):
            tag = e.rd(at)
            e.var("u_tag", tag)
            for word in (b, n, p["u_tag"], e.rd(e.add(at, 1)), e.rd(e.add(at, 2)), e.mul(e.flag(e.eq(p["u_tag"], 1)), e.rd(e.add(at, 3)))):
                _emit(e, "cur", word, end)
            e.set("uses", e.add(p["uses"], 1))

        def uses():
            def node():
                e.var("un", e.add(_blk(e, p["b"], B_FIRST), p["m"]))
                e.var("ua", _node(e, p["un"], N_OPS))
                e.for_("q", 0, _node(e, p["un"], N_NOPS), lambda: (use(p["b"], p["m"], p["ua"]), e.set("ua", e.add(p["ua"], _value_size(e, p["ua"])))))

            e.for_("m", 0, _blk(e, p["b"], B_COUNT), node)
            count = _blk(e, p["b"], B_COUNT)
            e.var("uend", count)
            # ``[*term.values, *edge arguments]``: values first, then each edge's arguments.
            _terminator_parts(e, p["b"], lambda at: use(p["b"], p["uend"], at), lambda _t, _c, _a: None)

            def edge_arguments(_target, count, at):
                e.var("ea", at)
                e.for_("eaq", 0, count, lambda: (use(p["b"], p["uend"], p["ea"]), e.set("ea", e.add(p["ea"], _value_size(e, p["ea"])))))

            _terminator_parts(e, p["b"], lambda _at: None, edge_arguments)

        e.for_("b", 0, p["B"], uses)
        e.if_(e.lt(p["uses_at"], end), lambda: e.st(p["uses_at"], p["uses"]))
        _set_ctrl(e, C_USES, e.sub(p["uses_at"], CFG_AT))
        _set_ctrl(e, C_CFG_LENGTH, e.sub(p["cur"], CFG_AT))
        e.give(1)
    return _function((), build, tables)


# -- one graph's typing-and-facts stream (``marshal`` with ``facts``) -------------------------------------------------

def _skip_node(e: E, name: str):
    """Advance stream word ``p[name]`` past one node record; the operation stays in ``sk_op``."""
    p = e.p
    e.var("sk_op", e.rd(p[name]))
    e.set(name, e.add(p[name], 1))
    e.if_(e.eq(p["sk_op"], int(Operation.CALL_GROUP_MEMBER)), lambda: e.set(name, e.add(p[name], 3)))
    e.if_(e.either(*(e.eq(p["sk_op"], code) for code in ENTITY_CODES)), lambda: e.set(name, e.add(p[name], 1)))
    e.var("sk_n", e.rd(p[name]))
    e.set(name, e.add(p[name], 1))
    e.for_("skq", 0, p["sk_n"], lambda: e.set(name, e.add(p[name], _value_size(e, p[name]))))
    e.set(name, e.add(e.add(p[name], 1), e.rd(p[name])))
    e.if_(e.either(*(e.eq(p["sk_op"], code) for code in ATTRIBUTE_CODES)), lambda: e.set(name, e.add(e.add(p[name], 1), e.rd(p[name]))))


def _skip_terminator(e: E, name: str):
    p = e.p
    e.var("st_kind", e.rd(p[name]))
    e.set(name, e.add(p[name], 1))

    def edge():
        e.set(name, e.add(p[name], 1))
        e.var("st_n", e.rd(p[name]))
        e.set(name, e.add(p[name], 1))
        e.for_("stq", 0, p["st_n"], lambda: e.set(name, e.add(p[name], _value_size(e, p[name]))))

    def returned():
        e.var("st_n", e.rd(p[name]))
        e.set(name, e.add(p[name], 1))
        e.for_("stq", 0, p["st_n"], lambda: e.set(name, e.add(p[name], _value_size(e, p[name]))))

    e.if_(e.eq(p["st_kind"], 1), edge, lambda: e.if_(e.eq(p["st_kind"], 2), lambda: (
        e.set(name, e.add(p[name], _value_size(e, p[name]))), edge(), edge()), lambda: e.if_(
        e.eq(p["st_kind"], 3), returned, lambda: e.set(name, e.add(p[name], 2)))))


SCRATCH_SIZE = 1 << 14
LINKS_SIZE = 1 << 12


def _callee_aux(e: E, cursor: str, end: int):
    """``_callee_summary`` and ``_callee_links`` of the direct call node ``p["fn"]``, as the facts section's
    auxiliary words: ``[0]`` when neither applies, else ``[length, blocks, operation count, operations, link count,
    (view, target) pairs]``."""
    from xax_selfhost_facts import _uleb

    p = e.p
    e.var("cf", _node(e, p["fn"], N_ENTITY))
    e.var("cs_blocks", NONE)  # NONE: no summary
    e.var("cs_ops", 0)
    e.var("cl_count", NONE)   # NONE: links unreadable or not a function; else the pairs in LINKS

    def function():
        e.var("cb_at", e.add(_payload(e, p["cf"]), 1))
        value, size, ok = _uleb(e, p["cb_at"])
        e.var("cg", e.sel(e.lt(value, _nrefs(e, p["cf"])), _ref(e, p["cf"], value), NONE))
        e.var("cg_kind", e.sel(e.eq(p["cg"], NONE), 0, _kind(e, e.sel(e.eq(p["cg"], NONE), 0, p["cg"]))))
        e.set("cb_at", e.add(p["cb_at"], size))
        e.var("c_holder", p["cf"])  # the object whose references the interface's type indices name
        e.var("c_ok", e.flag(e.both(ok, e.eq(p["cg_kind"], GRAPH_))))

        def member():
            """S12e.2 (ADR-276): a group member function's interface is the member's (``_decode_function_interface``):
            its graph and types are indices into the group's references; a member index out of range has none."""
            index, index_size, index_ok = _uleb(e, p["cb_at"])
            e.var("cm", index)
            e.var("cm_ok", e.flag(index_ok))
            e.set("cb_at", e.add(_payload(e, p["cg"]), 1))
            count, count_size, count_ok = _uleb(e, p["cb_at"])
            e.var("cm_n", count)
            e.set("cb_at", e.add(p["cb_at"], count_size))
            e.set("cm_ok", e.and_(p["cm_ok"], e.flag(e.both(count_ok, e.lt(p["cm"], p["cm_n"])))))

            def skip_uleb():
                _value, step, _ok = _uleb(e, p["cb_at"])
                e.set("cb_at", e.add(p["cb_at"], step))

            def skip_list():
                n, step, _ok = _uleb(e, p["cb_at"])
                e.var("cm_list", n)
                e.set("cb_at", e.add(p["cb_at"], step))
                e.for_("cml", 0, p["cm_list"], skip_uleb)

            def skip_member():
                skip_uleb()  # the graph position
                skip_list()  # the parameters
                skip_list()  # the returns

            e.for_("cmq", 0, e.sel(e.ne(p["cm_ok"], 0), p["cm"], 0), skip_member)

            def found():
                position, position_size, position_ok = _uleb(e, p["cb_at"])
                e.var("cm_pos", position)
                e.var("cm_pos_ok", e.flag(position_ok))
                e.set("cb_at", e.add(p["cb_at"], position_size))
                e.set("c_holder", p["cg"])
                e.set("cg", e.sel(e.lt(p["cm_pos"], _nrefs(e, p["c_holder"])), _ref(e, p["c_holder"], e.sel(
                    e.lt(p["cm_pos"], _nrefs(e, p["c_holder"])), p["cm_pos"], 0)), NONE))
                e.set("c_ok", e.flag(e.both(e.ne(p["cm_pos_ok"], 0), e.ne(p["cg"], NONE),
                                            e.eq(_kind(e, e.sel(e.eq(p["cg"], NONE), 0, p["cg"])), GRAPH_))))

            e.if_(e.ne(p["cm_ok"], 0), found)

        e.if_(e.eq(p["cg_kind"], GROUP_), member)

        def decoded():
            e.var("c_owner", 0)

            def types():
                count, size_, _ok = _uleb(e, p["cb_at"])
                e.var("ct_n", count)
                e.set("cb_at", e.add(p["cb_at"], size_))

                def each():
                    index, size2, _ok2 = _uleb(e, p["cb_at"])
                    e.set("cb_at", e.add(p["cb_at"], size2))
                    e.var("ct_t", e.sel(e.lt(index, _nrefs(e, p["c_holder"])), _ref(e, p["c_holder"], index), NONE))

                    def owner():
                        length, at = _body(e, p["ct_t"])
                        same = e.both(e.eq(_kind(e, p["ct_t"]), TYPE_), e.eq(_nrefs(e, p["ct_t"]), 0), e.eq(length, 3),
                                      *(e.eq(e.rd(e.add(at, k)), byte) for k, byte in enumerate(STACK_OWNER_BODY)))
                        e.if_(same, lambda: e.set("c_owner", 1))

                    e.if_(e.ne(p["ct_t"], NONE), owner)

                e.for_("ctq", 0, p["ct_n"], each)

            types()
            types()
            e.var("ca", _stream(e, p["cg"]))
            e.var("cB", e.rd(p["ca"]))
            e.var("cE", e.rd(e.add(p["ca"], 1)))
            e.set("ca", e.add(p["ca"], 2))

            def summary():
                e.set("cs_blocks", p["cB"])
                e.set("cs_ops", 0)

                def single():
                    e.var("sa", e.add(e.add(p["ca"], 1), e.rd(p["ca"])))  # past the parameters
                    e.var("sn", e.rd(p["sa"]))
                    e.set("sa", e.add(p["sa"], 1))
                    _decline(e, e.lt(SCRATCH_SIZE, p["sn"]))

                    def node():
                        _skip_node(e, "sa")
                        e.st(e.add(SCRATCH, p["cs_ops"]), p["sk_op"])
                        e.set("cs_ops", e.add(p["cs_ops"], 1))

                    e.for_("snq", 0, e.sel(e.lt(SCRATCH_SIZE, p["sn"]), 0, p["sn"]), node)

                e.if_(e.eq(p["cB"], 1), single)

            e.if_(e.ne(p["c_owner"], 0), summary)

            # ``_declared_link_targets``: the entry block's ``link_target`` nodes whose two operands are parameters.
            e.set("cl_count", 0)
            e.var("la", p["ca"])

            def block():
                e.set("la", e.add(e.add(p["la"], 1), e.rd(p["la"])))
                e.var("ln", e.rd(p["la"]))
                e.set("la", e.add(p["la"], 1))

                def node():
                    e.var("ln_at", p["la"])
                    _skip_node(e, "la")
                    e.var("lv", e.add(p["ln_at"], 2))  # operation, operand count, then the operands
                    pair = e.both(e.eq(p["lb"], p["cE"]), e.eq(p["sk_op"], int(Operation.LINK_TARGET)), e.eq(e.rd(e.add(p["ln_at"], 1)), 2),
                                  e.eq(e.rd(p["lv"]), 0), e.eq(e.rd(e.add(p["lv"], 3)), 0))

                    def record():
                        e.var("lk", e.rd(e.add(p["lv"], 2)))
                        e.var("lval", e.rd(e.add(p["lv"], 5)))
                        e.var("lfound", NONE)
                        e.for_("lq", 0, p["cl_count"], lambda: e.if_(e.eq(e.ld(e.add(LINKS, e.mul(p["lq"], 2))), p["lk"]), lambda: e.set("lfound", p["lq"])))
                        e.if_(e.ne(p["lfound"], NONE), lambda: e.st(e.add(LINKS, e.add(e.mul(p["lfound"], 2), 1)), p["lval"]), lambda: e.if_(
                            e.lt(p["cl_count"], LINKS_SIZE // 2), lambda: (e.st(e.add(LINKS, e.mul(p["cl_count"], 2)), p["lk"]),
                                                                          e.st(e.add(LINKS, e.add(e.mul(p["cl_count"], 2), 1)), p["lval"]),
                                                                          e.set("cl_count", e.add(p["cl_count"], 1))), lambda: e.st(CTRL + C_STATUS, DECLINE)))

                    e.if_(pair, record)

                e.for_("lnq", 0, p["ln"], node)
                e.if_(e.lt(p["lb"], p["cE"]), lambda: _skip_terminator(e, "la"))

            e.for_("lb", 0, e.add(e.sel(e.lt(p["cE"], p["cB"]), p["cE"], 0), 1), block)

        e.if_(e.ne(p["c_ok"], 0), decoded)

    e.if_(e.eq(_kind(e, p["cf"]), FUNCTION_), function)
    nothing = e.both(e.eq(p["cs_blocks"], NONE), e.either(e.eq(p["cl_count"], NONE), e.eq(p["cl_count"], 0)))

    def aux():
        length = e.add(e.add(2, p["cs_ops"]), e.add(1, e.mul(p["cl_count"], 2)))
        _emit(e, cursor, length, end)
        e.if_(e.eq(p["cs_blocks"], NONE), lambda: (_emit(e, cursor, 0, end), _emit(e, cursor, 0, end)), lambda: (
            _emit(e, cursor, p["cs_blocks"], end), _emit(e, cursor, p["cs_ops"], end),
            e.for_("axq", 0, p["cs_ops"], lambda: _emit(e, cursor, e.ld(e.add(SCRATCH, p["axq"])), end))))
        _emit(e, cursor, p["cl_count"], end)
        # The pairs in key order (``sorted(links.items())``): a selection over the few declarations.
        e.var("ax_last", NONE)
        e.var("ax_taken", 0)

        def pick():
            e.var("ax_best", NONE)
            e.var("ax_best_key", NONE)

            def scan():
                key = e.ld(e.add(LINKS, e.mul(p["axk"], 2)))
                after = e.either(e.eq(p["ax_last"], NONE), e.lt(p["ax_last"], key))
                e.if_(e.both(after, e.either(e.eq(p["ax_best"], NONE), e.lt(key, p["ax_best_key"]))),
                      lambda: (e.set("ax_best", p["axk"]), e.set("ax_best_key", key)))

            e.for_("axk", 0, p["cl_count"], scan)
            _emit(e, cursor, p["ax_best_key"], end)
            _emit(e, cursor, e.ld(e.add(LINKS, e.add(e.mul(p["ax_best"], 2), 1))), end)
            e.set("ax_last", p["ax_best_key"])
            e.set("ax_taken", e.add(p["ax_taken"], 1))

        e.while_(lambda: e.lt(p["ax_taken"], p["cl_count"]), pick)

    e.if_(nothing, lambda: _emit(e, cursor, 0, end), aux)


COVERED_CODES = tuple(sorted(int(op) for op in COVERED))
SITE_SINGLE = (int(Operation.STACK_ALLOC), int(Operation.HEAP_VIEW), int(Operation.CALL_FOREIGN))
SITE_RESULTS = (int(Operation.CALL_DIRECT), int(Operation.CALL_GROUP_MEMBER))


def _byteswap(e: E, word):
    """A big-endian CID word as the little-endian word of the same eight bytes (``xax_selfhost_typing._cid_words``)."""
    result = e.c(0)
    for k in range(8):
        byte = e.and_(e.udiv(word, 1 << (8 * k)) if k else word, 255)
        result = e.add(result, e.mul(byte, 1 << (8 * (7 - k))))
    return result


def _graph_marshal(tables):
    """``marshal(blocks, ..., facts=(entry, order, summaries, links), cids=...)`` of graph ``C_GRAPH`` (parsed by
    ``parse_graph``; its block order in ``ORDER``) at ``MARSHAL_AT``; ``KEYIDX`` holds each node's key."""
    def build(e: E):
        p = e.p
        _reset_types(e)
        e.var("B", _ctrl(e, C_BLOCKS))
        e.var("N", _ctrl(e, C_NODES))
        e.var("V", _ctrl(e, C_VALUES))
        e.for_("q", 0, p["V"], lambda: e.st(e.add(VNUM, p["q"]), NONE))
        e.var("vcount", 0)
        e.var("keys", 0)

        # Pass 1 (``marshal``'s node loop): the covered nodes' words.
        e.var("nc", NODES_TMP)
        nodes_end = NODES_TMP + NODES_LIMIT

        def node():
            e.var("n", e.add(_blk(e, p["b"], B_FIRST), p["m"]))
            e.st(e.add(KEYIDX, p["n"]), NONE)
            e.var("opc", _node(e, p["n"], N_OP))

            def covered():
                e.var("nops", _node(e, p["n"], N_NOPS))
                e.var("nres", _node(e, p["n"], N_NRES))
                e.var("sc", 0)
                e.var("missing", 0)
                e.var("va", _node(e, p["n"], N_OPS))

                def index(value):
                    e.var("ix", value)
                    e.if_(e.eq(p["ix"], NONE), lambda: e.set("missing", 1))
                    e.if_(e.lt(p["sc"], SCRATCH_SIZE), lambda: e.st(e.add(SCRATCH, p["sc"]), p["ix"]))
                    e.set("sc", e.add(p["sc"], 1))

                e.for_("oq", 0, p["nops"], lambda: (index(_tidx(e, _vt(e, _value_id(e, p["va"])))), e.set("va", e.add(p["va"], _value_size(e, p["va"])))))
                e.for_("rq", 0, p["nres"], lambda: index(_tidx(e, _vt(e, e.add(_node(e, p["n"], N_BASE), p["rq"])))))
                _decline(e, e.lt(SCRATCH_SIZE, p["sc"]))
                e.var("extra_n", 0)
                e.var("extra", 0)

                def effect_step():
                    e.set("extra_n", p["nops"])
                    e.set("va", _node(e, p["n"], N_OPS))

                    def number():
                        e.var("vid", _value_id(e, p["va"]))
                        e.if_(e.eq(e.ld(e.add(VNUM, p["vid"])), NONE), lambda: (e.st(e.add(VNUM, p["vid"]), p["vcount"]), e.set("vcount", e.add(p["vcount"], 1))))
                        e.if_(e.lt(e.add(p["sc"], p["eq"]), SCRATCH_SIZE), lambda: e.st(e.add(SCRATCH, e.add(p["sc"], p["eq"])), e.ld(e.add(VNUM, p["vid"]))))
                        e.set("va", e.add(p["va"], _value_size(e, p["va"])))

                    e.for_("eq", 0, p["nops"], number)

                def entity():
                    e.var("ent", _tidx(e, _node(e, p["n"], N_ENTITY)))
                    e.if_(e.eq(p["ent"], NONE), lambda: e.set("missing", 1), lambda: (e.set("extra_n", 1), e.st(e.add(SCRATCH, p["sc"]), p["ent"])))

                def keep():
                    e.if_(e.eq(p["opc"], int(Operation.EFFECT_STEP)), effect_step, lambda: e.if_(
                        e.either(e.eq(p["opc"], int(Operation.CONSTANT)), e.eq(p["opc"], int(Operation.CALL_DIRECT))), entity))

                    def emit():
                        e.st(e.add(KEYIDX, p["n"]), p["keys"])
                        e.set("keys", e.add(p["keys"], 1))
                        nattrs = _node(e, p["n"], N_NATTRS)
                        e.var("na", nattrs)
                        attribute = e.mul(e.flag(e.ne(p["na"], 0)), e.rd(_node(e, p["n"], N_ATTRS)))
                        for word in (p["opc"], p["nops"], p["nres"], p["na"], e.sel(e.lt(attribute, ATTRIBUTE_LIMIT), attribute, ATTRIBUTE_LIMIT), p["extra_n"]):
                            _emit(e, "nc", word, nodes_end)
                        e.for_("wq", 0, e.add(p["sc"], p["extra_n"]), lambda: _emit(e, "nc", e.ld(e.add(SCRATCH, p["wq"])), nodes_end))

                    e.if_(e.eq(p["missing"], 0), emit)

                e.if_(e.eq(p["missing"], 0), keep)

            e.if_(e.either(*(e.eq(p["opc"], code) for code in COVERED_CODES)), covered)

        e.for_("b", 0, p["B"], lambda: e.for_("m", 0, _blk(e, p["b"], B_COUNT), node))

        # Pass 2 (the block section): parameters, the condition, each edge's argument types.
        e.var("scur", SECTION_TMP)
        section_end = SECTION_TMP + SECTION_LIMIT

        def section():
            e.var("sc", 0)
            e.var("known", 1)

            def keep_index(value):
                e.var("ix", value)
                e.if_(e.eq(p["ix"], NONE), lambda: (e.set("known", 0), e.set("ix", 0)))
                e.if_(e.lt(p["sc"], SCRATCH_SIZE), lambda: e.st(e.add(SCRATCH, p["sc"]), p["ix"]))
                e.set("sc", e.add(p["sc"], 1))

            e.for_("pq", 0, _blk(e, p["b"], B_PARAMS), lambda: keep_index(_tidx(e, _vt(e, e.add(_blk(e, p["b"], B_BASE), p["pq"])))))
            e.var("params", p["sc"])
            e.var("condition", 0)

            def condition(at):
                def typed():
                    e.set("condition", _tidx(e, _vt(e, _value_id(e, at))))
                    e.if_(e.eq(p["condition"], NONE), lambda: (e.set("known", 0), e.set("condition", 0)))

                e.if_(e.eq(p["tk"], 2), typed)  # a conditional branch's condition (returned values have no section words)

            kind = _terminator_parts(e, p["b"], condition, lambda _t, _c, _a: None)
            e.var("skind", kind)
            e.var("edges", 0)

            def edge(target, count, at):
                e.if_(e.lt(e.add(p["sc"], 1), SCRATCH_SIZE), lambda: (e.st(e.add(SCRATCH, p["sc"]), target), e.st(e.add(SCRATCH, e.add(p["sc"], 1)), count)))
                e.set("sc", e.add(p["sc"], 2))
                e.var("ea", at)
                e.for_("eq", 0, count, lambda: (keep_index(_tidx(e, _vt(e, _value_id(e, p["ea"])))), e.set("ea", e.add(p["ea"], _value_size(e, p["ea"])))))
                e.set("edges", e.add(p["edges"], 1))

            _terminator_parts(e, p["b"], lambda _at: None, edge)
            _decline(e, e.lt(SCRATCH_SIZE, p["sc"]))
            for word in (p["known"], p["params"]):
                _emit(e, "scur", word, section_end)
            e.for_("wq", 0, p["params"], lambda: _emit(e, "scur", e.ld(e.add(SCRATCH, p["wq"])), section_end))
            for word in (p["skind"], p["condition"], p["edges"]):
                _emit(e, "scur", word, section_end)
            e.for_("wq", p["params"], p["sc"], lambda: _emit(e, "scur", e.ld(e.add(SCRATCH, p["wq"])), section_end))

        e.for_("b", 0, p["B"], section)

        # Pass 3 (``_facts_section``).
        entry = _ctrl(e, C_ENTRY)
        e.var("entry", entry)
        e.var("kinds", e.add(1, _blk(e, p["entry"], B_PARAMS)))

        def site():
            op = _node(e, p["n"], N_OP)
            e.var("sop", op)
            e.st(e.add(SITE, p["n"]), NONE)
            e.if_(e.either(*(e.eq(p["sop"], code) for code in SITE_SINGLE)), lambda: (e.st(e.add(SITE, p["n"]), p["kinds"]), e.set("kinds", e.add(p["kinds"], 1))),
                  lambda: e.if_(e.either(*(e.eq(p["sop"], code) for code in SITE_RESULTS)), lambda: (
                      e.st(e.add(SITE, p["n"]), p["kinds"]), e.set("kinds", e.add(p["kinds"], _node(e, p["n"], N_NRES))))))

        e.for_("n", 0, p["N"], site)
        e.var("E", 0)
        e.for_("b", 0, p["B"], lambda: e.st(e.add(INCCOUNT, p["b"]), 0))

        def count_edges():
            e.st(e.add(EDGEBASE, p["b"]), p["E"])

            def edge(target, _count, _at):
                e.set("E", e.add(p["E"], 1))
                e.st(e.add(INCCOUNT, target), e.add(e.ld(e.add(INCCOUNT, target)), 1))

            _terminator_parts(e, p["b"], lambda _at: None, edge)

        e.for_("b", 0, p["B"], count_edges)
        e.var("incat", 0)
        e.for_("b", 0, p["B"], lambda: (e.st(e.add(INCAT, p["b"]), p["incat"]), e.set("incat", e.add(p["incat"], e.ld(e.add(INCCOUNT, p["b"])))),
                                        e.st(e.add(INCCOUNT, p["b"]), 0)))
        _decline(e, e.lt(1 << 18, p["incat"]))
        e.var("eid", 0)

        def fill_incoming():
            def edge(target, _count, _at):
                slot = e.add(e.ld(e.add(INCAT, target)), e.ld(e.add(INCCOUNT, target)))
                e.if_(e.lt(slot, 1 << 18), lambda: e.st(e.add(INCLIST, slot), p["eid"]))
                e.st(e.add(INCCOUNT, target), e.add(e.ld(e.add(INCCOUNT, target)), 1))
                e.set("eid", e.add(p["eid"], 1))

            _terminator_parts(e, p["b"], lambda _at: None, edge)

        e.for_("b", 0, p["B"], fill_incoming)

        e.var("fc", FACTS_TMP)
        facts_end = FACTS_TMP + FACTS_LIMIT
        for word in (1, p["V"], p["kinds"], p["E"], p["B"], p["entry"]):
            _emit(e, "fc", word, facts_end)
        e.for_("b", 0, p["B"], lambda: _emit(e, "fc", e.ld(e.add(ORDER, p["b"])), facts_end))
        _emit(e, "fc", 0, facts_end)
        e.for_("q", 0, _blk(e, p["entry"], B_PARAMS), lambda: _emit(e, "fc", 1, facts_end))

        def kinds_of():
            op = _node(e, p["n"], N_OP)
            e.var("kop", op)
            e.if_(e.either(*(e.eq(p["kop"], code) for code in SITE_SINGLE)), lambda: _emit(e, "fc", 2, facts_end),
                  lambda: e.if_(e.either(*(e.eq(p["kop"], code) for code in SITE_RESULTS)), lambda: e.for_(
                      "kq", 0, _node(e, p["n"], N_NRES), lambda: _emit(e, "fc", 3, facts_end))))

        e.for_("n", 0, p["N"], kinds_of)

        def fact_index(value):
            e.var("fx", value)
            _emit(e, "fc", p["fx"], facts_end)

        def body():
            e.var("pc", _blk(e, p["b"], B_PARAMS))
            e.var("vb", _blk(e, p["b"], B_BASE))
            _emit(e, "fc", e.mul(e.flag(e.ne(p["pc"], 0)), p["vb"]), facts_end)
            _emit(e, "fc", p["pc"], facts_end)
            e.for_("q", 0, p["pc"], lambda: fact_index(_tidx(e, _vt(e, e.add(p["vb"], p["q"])))))
            _emit(e, "fc", _blk(e, p["b"], B_COUNT), facts_end)

            def node():
                e.var("fn", e.add(_blk(e, p["b"], B_FIRST), p["m"]))
                e.var("fop", _node(e, p["fn"], N_OP))
                e.var("fna", _node(e, p["fn"], N_NATTRS))
                e.var("fnr", _node(e, p["fn"], N_NRES))
                e.var("fnops", _node(e, p["fn"], N_NOPS))
                e.var("fent", _node(e, p["fn"], N_ENTITY))
                e.var("fentity", NONE)
                e.if_(e.either(*(e.eq(p["fop"], code) for code in ENTITY_CODES)), lambda: e.set("fentity", _tidx(e, p["fent"])))
                for word in (p["fop"], e.ld(e.add(KEYIDX, p["fn"])), p["fentity"], e.ld(e.add(SITE, p["fn"])),
                             e.mul(e.flag(e.ne(p["fnr"], 0)), _node(e, p["fn"], N_BASE)), p["fna"]):
                    _emit(e, "fc", word, facts_end)
                e.for_("aq", 0, p["fna"], lambda: _emit(e, "fc", e.rd(e.add(_node(e, p["fn"], N_ATTRS), p["aq"])), facts_end))
                _emit(e, "fc", p["fnops"], facts_end)
                e.var("fa", _node(e, p["fn"], N_OPS))
                e.for_("oq", 0, p["fnops"], lambda: (_emit(e, "fc", _value_id(e, p["fa"]), facts_end), e.set("fa", e.add(p["fa"], _value_size(e, p["fa"])))))
                e.set("fa", _node(e, p["fn"], N_OPS))
                e.for_("oq", 0, p["fnops"], lambda: (fact_index(_tidx(e, _vt(e, _value_id(e, p["fa"])))), e.set("fa", e.add(p["fa"], _value_size(e, p["fa"])))))
                _emit(e, "fc", p["fnr"], facts_end)
                e.for_("rq", 0, p["fnr"], lambda: fact_index(_tidx(e, _vt(e, e.add(_node(e, p["fn"], N_BASE), p["rq"])))))
                e.if_(e.eq(p["fop"], int(Operation.CALL_DIRECT)), lambda: _callee_aux(e, "fc", facts_end), lambda: _emit(e, "fc", 0, facts_end))

            e.for_("m", 0, _blk(e, p["b"], B_COUNT), node)
            # The terminator: kind, values (ids, then types), edges (target, edge id, argument ids), incoming edges.
            e.var("tvc", 0)
            e.var("tv_at", 0)

            def count_value(at):
                e.if_(e.eq(p["tvc"], 0), lambda: e.set("tv_at", at))
                e.set("tvc", e.add(p["tvc"], 1))

            kind = _terminator_parts(e, p["b"], count_value, lambda _t, _c, _a: None)
            e.var("fkind", kind)
            _emit(e, "fc", p["fkind"], facts_end)
            _emit(e, "fc", p["tvc"], facts_end)
            e.var("tva", p["tv_at"])
            e.for_("tq", 0, p["tvc"], lambda: (_emit(e, "fc", _value_id(e, p["tva"]), facts_end), e.set("tva", e.add(p["tva"], _value_size(e, p["tva"])))))
            e.set("tva", p["tv_at"])
            e.for_("tq", 0, p["tvc"], lambda: (fact_index(_tidx(e, _vt(e, _value_id(e, p["tva"])))), e.set("tva", e.add(p["tva"], _value_size(e, p["tva"])))))
            e.var("fe", 0)

            def count_edge(_t, _c, _a):
                e.set("fe", e.add(p["fe"], 1))

            _terminator_parts(e, p["b"], lambda _at: None, count_edge)
            _emit(e, "fc", p["fe"], facts_end)
            e.var("fei", e.ld(e.add(EDGEBASE, p["b"])))

            def edge(target, count, at):
                _emit(e, "fc", target, facts_end)
                _emit(e, "fc", p["fei"], facts_end)
                e.set("fei", e.add(p["fei"], 1))
                _emit(e, "fc", count, facts_end)
                e.var("fea", at)
                e.for_("feq", 0, count, lambda: (_emit(e, "fc", _value_id(e, p["fea"]), facts_end), e.set("fea", e.add(p["fea"], _value_size(e, p["fea"])))))

            _terminator_parts(e, p["b"], lambda _at: None, edge)
            _emit(e, "fc", e.ld(e.add(INCCOUNT, p["b"])), facts_end)
            e.for_("iq", 0, e.ld(e.add(INCCOUNT, p["b"])), lambda: _emit(e, "fc", e.ld(e.add(INCLIST, e.add(e.ld(e.add(INCAT, p["b"])), p["iq"]))), facts_end))

        e.for_("b", 0, p["B"], body)

        # The words: entries, the node section, the block section, the facts section, each type's CID, padding.
        e.var("cur", MARSHAL_AT)
        end = MARSHAL_AT + MARSHAL_LIMIT
        _serialize_entries(e, "cur")
        _emit(e, "cur", p["keys"], end)
        e.for_("wq", NODES_TMP, p["nc"], lambda: _emit(e, "cur", e.ld(p["wq"]), end))
        _emit(e, "cur", p["B"], end)
        e.for_("wq", SECTION_TMP, p["scur"], lambda: _emit(e, "cur", e.ld(p["wq"]), end))
        e.for_("wq", FACTS_TMP, p["fc"], lambda: _emit(e, "cur", e.ld(p["wq"]), end))

        def cid():
            o = e.ld(e.add(ENT, e.mul(p["cq"], ENTRY_WORDS)))
            e.var("co", o)
            for word in range(4):
                _emit(e, "cur", _byteswap(e, _cid_word(e, p["co"], word)), end)

        e.for_("cq", 0, _ctrl(e, C_ENTRIES), cid)
        for _word in range(PADDING):
            _emit(e, "cur", 0, end)
        _set_ctrl(e, C_LENGTH, e.sub(p["cur"], MARSHAL_AT))
        _set_ctrl(e, C_KEYS, p["keys"])
        e.give(1)
    return _function((), build, tables)


def _trim(tables):
    """S15b.3c (ADR-295): ``_parse_graph``'s graph trimmed at its invalid uses.  ``CUT[b]`` (NONE: none) keeps block
    ``b``'s first nodes and ends it in a trap; the values are renumbered densely in block, node, and result order
    (``_facts_section``'s ``refs`` of the trimmed blocks), their types moved with them."""
    def build(e: E):
        p = e.p
        e.var("B", _ctrl(e, C_BLOCKS))
        e.var("tv", 0)

        def put(base, index, field: int, value):
            e.st(e.add(base, e.add(e.mul(index, BLOCK_WORDS if base == BLK else NODE_WORDS), field)), value)

        def move(old):
            """Value ``old`` becomes value ``tv`` (never above it: the copy runs forward)."""
            e.if_(e.lt(old, MAX_VALUES), lambda: e.st(e.add(VT, p["tv"]), e.ld(e.add(VT, old))))
            e.set("tv", e.add(p["tv"], 1))

        def block():
            e.var("tc", e.ld(e.add(CUT, p["b"])))
            e.if_(e.both(e.ne(p["tc"], NONE), e.lt(p["tc"], _blk(e, p["b"], B_COUNT))), lambda: put(BLK, p["b"], B_COUNT, p["tc"]))
            e.if_(e.ne(p["tc"], NONE), lambda: put(BLK, p["b"], B_TRAP, 1))
            e.var("tb", _blk(e, p["b"], B_BASE))
            put(BLK, p["b"], B_BASE, p["tv"])
            e.for_("tq", 0, _blk(e, p["b"], B_PARAMS), lambda: move(e.add(p["tb"], p["tq"])))

            def node():
                e.var("tn", e.add(_blk(e, p["b"], B_FIRST), p["tm"]))
                e.var("tnb", _node(e, p["tn"], N_BASE))
                put(NODE, p["tn"], N_BASE, p["tv"])
                e.for_("tr", 0, _node(e, p["tn"], N_NRES), lambda: move(e.add(p["tnb"], p["tr"])))

            e.for_("tm", 0, _blk(e, p["b"], B_COUNT), node)
            e.st(e.add(CUT, p["b"]), NONE)

        e.for_("b", 0, p["B"], block)
        _set_ctrl(e, C_VALUES, p["tv"])
        e.give(1)
    return _function((), build, tables)


def build_functions():
    """``{name: function}`` and the objects they need; ``type_index`` first (the marshals call it)."""
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("type_index", _type_index(None))
    for name, builder in (("index_objects", _index_objects), ("objects_marshal", _objects_marshal), ("parse_graph", _parse_graph),
                          ("cfg_input", _cfg_input), ("graph_marshal", _graph_marshal), ("trim", _trim)):
        add(name, builder(None))
    return dict(_FN), tuple(objects)
