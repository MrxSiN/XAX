"""Self-hosting step S15e.7b (ADR-321): SPIR-V compute modules decided and written by the general program.

``xax_build.build`` makes the module of a ``spirv-vulkan-compute-v1`` target (architecture 7) with
``xax_spirv.compile_spirv_kernel``: the entry contract (``SPIRV-KERNEL-ENTRY-CONTRACT``: the invocation index, then
view triples returned whole), the target's operation and terminator lists, then ``_Lowering``: every value a
``bits<1..32>``, a binding pointer or a proof (``SPIRV-VALUE``); every pointer a static binding and offset
(``SPIRV-POINTER-STATIC``, ``SPIRV-POINTER-ALIGNED``); the race rule (``SPIRV-KERNEL-OWN-ELEMENT``); 4-byte accesses
(``SPIRV-ACCESS-WIDTH``); the operations it lowers (``SPIRV-OP-LOWERED``).  The module is the bootstrap's word for word:
the same result ids in the same order (types, constants on first use, variables, labels, the cases' code), the
sections in order, and one structured dispatch loop over the cases.

The general x86-64 program takes this path for such a target (``xax_selfhost_request.PATH_SPIRV``): ``spirv`` writes
the module as the image record's container bytes.  A trap terminator (its payload's reason is not in the program's
stream) and capacities past the program's tables decline.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Kind, Operation, Permission, TerminatorKind
from xax_spirv import _BINARY, _COMPARE, _DONE, _SIGNED, LOCAL_SIZE, OP, STATUS_BOUNDS, STATUS_TRAP, _string
import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import (
    GLOBALS, G_NI, G_PAY, G_REC, NI_ATTRIBUTES, NI_ENTITY, NI_OP, NI_OPERANDS, NI_RESULTS, _at, _call, _cid_words, _g, _kind, _ok,
    _payload_uleb, _reference,
)

SP = GLOBALS + 96
(S_F, S_G, S_STREAM, S_B, S_ENTRY, S_NB, S_BIND, S_BLK, S_NODE, S_NN, S_V, S_VAL, S_NEXT, S_CONSTS, S_NCONSTS, S_TRAPS, S_NTRAPS,
 S_NCASES, S_UINT, S_BOOL, S_ELEMPTR, S_BUFS, S_STATE, S_ACC, S_NACC, S_STACK, S_EDGES, S_NEDGES, S_PB, S_PO, S_CASES, S_INV,
 S_FIX, S_ONPATH, S_SP, S_VIS, S_RES, S_CASELAB, S_NEXTCASE, S_CUR, S_LABELS, S_BODY, S_BLOCKCASES, S_EXTENT) = (SP + k for k in range(44))
SEC_AT, SEC_LEN = SP + 48, SP + 56  # section buffers: caps, entry, modes, decorations, globals, code, then the case bodies
SECTIONS = ("caps", "entry", "modes", "decorations", "globals", "code", "bodies")
SEC = {name: index for index, name in enumerate(SECTIONS)}
SEC_CAP = 1 << 20
BLK_W = 10
(B_PARAMS_AT, B_NPARAMS, B_PBASE, B_NODES_AT, B_NNODES, B_NODEBASE, B_TERM_AT, B_EDGE0, B_NEDGE, B_SEGBASE) = range(BLK_W)
NODE_W = 8
(N_AT, N_RBASE, N_NRES, N_OP, N_OPERANDS, N_ATTRS, N_ENTITY, N_BLOCK) = range(NODE_W)
VAL_W = 10
# V_KNOWN: the static pointer's binding + 1 (its offset in the ``S_PO`` table); V_ORIGIN: a parameter's block, or
# ``NODE_ORIGIN`` + a node result's node; V_INDEX: the parameter's index or the result's.
(V_TYPE, V_WIDTH, V_CONST, V_VALUE, V_VAR, V_KNOWN, V_RAW, V_ORIGIN, V_INDEX, V_SPARE) = range(VAL_W)
NODE_ORIGIN = 1 << 40
EDGE_W = 3  # target, first argument's position, argument count
INCOMING = 64
# A pointer frame: value, state (0 start, 1 a parameter's incoming edges, 2 a node's base), edge cursor, whether a
# parameter was on the path when it started, waiting on a child, distinct incoming pairs, then the pairs.
(F_V, F_STATE, F_EDGE, F_VIS, F_WAIT, F_N) = range(6)
F_PAIRS = 6
FRAME_W = F_PAIRS + 2 * INCOMING
ENTRY_EXPECTED = "fn(b32, (ptr<b32>, heap_view<E>, memory)...) -> ((ptr, view, memory)...)"
HEAP_VIEW_KIND = 0x101
CYCLE = NONE - 1


def _s(e: E, word):
    return e.ld(word)


def _rec(e: E, table_slot, index, width, field):
    return e.ld(e.add(e.add(e.ld(table_slot), e.mul(index, width)), field))


def _set_rec(e: E, table_slot, index, width, field, value):
    e.st(e.add(e.add(e.ld(table_slot), e.mul(index, width)), field), value)


def _blk(e: E, b, field):
    return _rec(e, S_BLK, b, BLK_W, field)


def _node(e: E, k, field):
    return _rec(e, S_NODE, k, NODE_W, field)


def _val(e: E, v, field):
    return _rec(e, S_VAL, v, VAL_W, field)


def _set_val(e: E, v, field, value):
    _set_rec(e, S_VAL, v, VAL_W, field, value)


def _vid(e: E, at):
    """The value id of the value reference at stream position ``at`` (tag, block, index[, result])."""
    tag, block, index = e.rd(at), e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
    param = e.add(_blk(e, block, B_PBASE), index)
    result = e.add(_node(e, e.add(_blk(e, block, B_NODEBASE), index), N_RBASE), e.rd(e.add(at, 3)))
    return e.sel(e.eq(tag, 0), param, result)


def _value_size(e: E, at):
    return e.add(3, e.flag(e.eq(e.rd(at), 1)))


def _body_bytes(e: E, obj):
    """``(position, length)`` of a listed object's body bytes."""
    pay = _at(e, G_PAY, obj)
    return pay, e.rd(e.sub(pay, 1))


# -- the module's words ---------------------------------------------------------------------------------------------

def _word(e: E, section, value):
    """Append a word to section ``section`` (an index, or a value naming one)."""
    p = e.p
    e.var("wd_s", section)
    e.var("wd_v", value)
    e.var("wd_n", e.ld(e.add(SEC_LEN, p["wd_s"])))
    _ok(e, e.lt(p["wd_n"], SEC_CAP))
    e.st(e.add(e.ld(e.add(SEC_AT, p["wd_s"])), p["wd_n"]), p["wd_v"])
    e.st(e.add(SEC_LEN, p["wd_s"]), e.add(p["wd_n"], 1))


def _emit(e: E, section, opcode: str, *operands):
    """``_Module.emit``: ``section`` a name, or ``None`` for the current one (``S_CUR``: a case body or the code)."""
    p = e.p
    e.var("em_s", e.ld(S_CUR) if section is None else SEC[section])
    for k, operand in enumerate(operands):  # values cross ``_word``'s branches only as variables
        e.var(f"em_{k}", operand)
    _word(e, p["em_s"], ((len(operands) + 1) << 16) | OP[opcode])
    for k in range(len(operands)):
        _word(e, p["em_s"], p[f"em_{k}"])


def _new_id(e: E, name: str):
    e.var(name, e.ld(S_NEXT))
    e.st(S_NEXT, e.add(e.p[name], 1))
    return e.p[name]


def _ins(e: E, name: str, opcode: str, result_type, *operands):
    """``_Lowering.ins``: a fresh result id (``name``), allocated after its operands, into the current section."""
    for k, operand in enumerate((result_type, *operands)):
        e.var(f"{name}_o{k}", operand)
    result = _new_id(e, name)
    _emit(e, None, opcode, *(e.p[f"{name}_o{k}"] for k in range(1)), result, *(e.p[f"{name}_o{k}"] for k in range(1, len(operands) + 1)))
    return result


def _raw(e: E, opcode: str, *operands):
    _emit(e, None, opcode, *operands)


def _const(e: E, value, name: str):
    """``_Module.constant``: the id of the 32-bit constant ``value`` (created in ``globals`` on first use)."""
    e.var(name, _call(e, "sp_const", e.and_(value, 0xFFFFFFFF)))
    return e.p[name]


def _value(e: E, v, name: str):
    e.var(name, _call(e, "sp_value", v))
    return e.p[name]


def _sp_const(tables):
    def build(e: E):
        p = e.p
        e.var("cf", NONE)
        e.for_("ck", 0, e.ld(S_NCONSTS), lambda: e.if_(e.eq(e.ld(e.add(e.ld(S_CONSTS), e.mul(p["ck"], 2))), p["cv"]),
                                                       lambda: e.set("cf", e.ld(e.add(e.ld(S_CONSTS), e.add(e.mul(p["ck"], 2), 1))))))

        def create():
            _ok(e, e.lt(e.ld(S_NCONSTS), 1 << 16))
            e.var("cid", e.ld(S_NEXT))
            e.st(S_NEXT, e.add(p["cid"], 1))
            e.st(e.add(e.ld(S_CONSTS), e.mul(e.ld(S_NCONSTS), 2)), p["cv"])
            e.st(e.add(e.ld(S_CONSTS), e.add(e.mul(e.ld(S_NCONSTS), 2), 1)), p["cid"])
            e.st(S_NCONSTS, e.add(e.ld(S_NCONSTS), 1))
            _emit(e, "globals", "Constant", e.ld(S_UINT), p["cid"], p["cv"])
            e.set("cf", p["cid"])

        e.if_(e.eq(p["cf"], NONE), create)
        e.give(p["cf"])
    return _function(("cv",), build, tables)


def _sp_value(tables):
    """``_Lowering.value``: a constant's id, else a load of the value's variable."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_val(e, p["vv"], V_CONST), 0), lambda: e.give(_const(e, _val(e, p["vv"], V_VALUE), "vc")))
        _ok(e, e.ne(_val(e, p["vv"], V_VAR), NONE))
        e.give(_ins(e, "vl", "Load", e.ld(S_UINT), _val(e, p["vv"], V_VAR)))
    return _function(("vv",), build, tables)


# -- the entry contract and the graph's tables -----------------------------------------------------------------------

def _resource_view(e: E, obj, name: str):
    """``name``: the heap view's extent when ``obj`` is a ``heap_view`` resource type (``_heap_view_info``), else 0."""
    p = e.p
    e.var(name, 0)
    at, length = _body_bytes(e, obj)
    e.var(f"{name}_at", at)
    e.var(f"{name}_len", length)

    def resource():
        e.var(f"{name}_c", e.add(p[f"{name}_at"], 1))
        kind = _payload_uleb(e, f"{name}_c")
        e.var(f"{name}_k", kind)
        e.var(f"{name}_st", _payload_uleb(e, f"{name}_c"))
        e.if_(e.both(e.eq(p[f"{name}_k"], HEAP_VIEW_KIND), e.either(e.eq(p[f"{name}_st"], 1), e.eq(p[f"{name}_st"], 2)),
                     e.lt(e.sub(p[f"{name}_c"], p[f"{name}_at"]), p[f"{name}_len"])), lambda: (
            _payload_uleb(e, f"{name}_c"),  # flags
            e.set(name, _payload_uleb(e, f"{name}_c"))))

    e.if_(e.both(e.eq(_kind(e, obj), int(Kind.TYPE)), e.lt(1, length), e.eq(e.rd(at), 4)), resource)


def _form(e: E, obj):
    at, length = _body_bytes(e, obj)
    return e.sel(e.both(e.eq(_kind(e, obj), int(Kind.TYPE)), e.ne(length, 0)), e.rd(at), 0)


def _bits(e: E, obj, name: str):
    """``name``: the width of ``bits<N>`` type ``obj`` (body form 1), else 0."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_at", e.add(_at(e, G_PAY, obj), 1))
    e.if_(e.eq(_form(e, obj), 1), lambda: e.set(name, _payload_uleb(e, f"{name}_at")))


def _sp_entry(tables):
    """``_kernel_interface`` of function ``ef``: the bindings (``S_BIND``: extent, writable per triple)."""
    def build(e: E):
        p = e.p
        f = p["ef"]
        e.var("ei", _call(e, "interface", f))
        e.var("enp", e.ld(e.add(p["ei"], 1)))
        e.var("ert", e.add(e.add(p["ei"], 2), p["enp"]))
        e.var("enr", e.ld(p["ert"]))
        param = lambda k: e.ld(e.add(e.add(p["ei"], 2), k))  # noqa: E731
        result = lambda k: e.ld(e.add(e.add(p["ert"], 1), k))  # noqa: E731

        def reject(write_detail):
            def write():
                D.text(e, "XAX.SPIRV.ENTRY")
                D.cid(e, _cid_words(e, f))
                D.text(e, "SPIRV-KERNEL-ENTRY-CONTRACT")
                D.text(e, ENTRY_EXPECTED)
                write_detail()
            D.reject_unless(e, e.eq(1, 0), write)

        e.var("ew0", 0)
        e.if_(e.ne(p["enp"], 0), lambda: (_bits(e, param(0), "eb0"), e.set("ew0", p["eb0"])))
        e.if_(e.ne(p["ew0"], 32), lambda: reject(lambda: D.text(e, "first parameter must be the b32 invocation index")))
        e.var("etn", e.sub(p["enp"], 1))
        e.var("esame", e.flag(e.both(e.eq(e.urem(p["etn"], 3), 0), e.eq(p["enr"], p["etn"]), e.ne(p["etn"], 0))))
        e.if_(e.ne(p["esame"], 0), lambda: e.for_("eq", 0, p["etn"], lambda: e.if_(e.ne(param(e.add(p["eq"], 1)), result(p["eq"])),
                                                                                 lambda: e.set("esame", 0))))
        e.if_(e.eq(p["esame"], 0), lambda: reject(lambda: D.text(e, "parameters after the invocation must be view triples, returned whole in order")))
        e.st(S_NB, e.udiv(p["etn"], 3))
        e.var("ebind", e.alloc(e.mul(e.add(e.ld(S_NB), 1), 2)))
        _ok(e, e.ne(p["ebind"], NONE))
        e.st(S_BIND, p["ebind"])

        def triple():
            e.var("ept", param(e.add(1, e.mul(p["ek"], 3))))
            e.var("evw", param(e.add(2, e.mul(p["ek"], 3))))
            e.var("eef", param(e.add(3, e.mul(p["ek"], 3))))
            _resource_view(e, p["evw"], "ext")
            proof = e.either(e.eq(_form(e, p["eef"]), 3), e.eq(_form(e, p["eef"]), 4))

            def not_triple():
                D.put(e, D.T_FORMAT)
                D.text(e, "binding {} is not a (pointer, heap view, memory) triple")
                D.put(e, 1)
                D.integer(e, p["ek"])

            e.if_(e.either(e.eq(p["ext"], 0), e.not_(proof)), lambda: reject(not_triple))
            # ``_decode_pointer_type`` (a verified pointer type: form 2, space, element, permission, alignment).
            _ok(e, e.eq(_form(e, p["ept"]), 2))
            e.var("epa", e.add(_at(e, G_PAY, p["ept"]), 1))
            _payload_uleb(e, "epa")  # space
            e.var("eel", _reference(e, p["ept"], _payload_uleb(e, "epa")))
            _ok(e, e.ne(p["eel"], NONE))
            e.var("eperm", _payload_uleb(e, "epa"))
            _bits(e, p["eel"], "eew")

            def not_words():
                D.put(e, D.T_FORMAT)
                D.text(e, "binding {} must view a nonempty array of b32")
                D.put(e, 1)
                D.integer(e, p["ek"])

            e.if_(e.either(e.ne(p["eew"], 32), e.ne(e.urem(p["ext"], 4), 0)), lambda: reject(not_words))
            e.st(e.add(p["ebind"], e.mul(p["ek"], 2)), p["ext"])
            e.st(e.add(p["ebind"], e.add(e.mul(p["ek"], 2), 1)), e.flag(e.eq(p["eperm"], int(Permission.READ_WRITE))))

        e.for_("ek", 0, e.ld(S_NB), triple)
        e.st(S_G, e.ld(p["ei"]))
        e.give(1)
    return _function(("ef",), build, tables)


def _sp_index(tables):
    """The graph's blocks, nodes, values and edges (``S_BLK``, ``S_NODE``, ``S_VAL``, ``S_EDGES``), and the target's
    operation and terminator lists over every block (``compile_spirv_kernel``'s loop)."""
    from xax_selfhost_views_backend import G_SUP, G_SUP_AT, G_SUPT, G_SUPT_AT, _target_list

    def build(e: E):
        p = e.p
        g = e.ld(S_G)
        e.var("is", _at(e, G_PAY, g))
        e.st(S_STREAM, p["is"])
        e.var("iB", e.rd(p["is"]))
        e.st(S_B, p["iB"])
        e.st(S_ENTRY, e.rd(e.add(p["is"], 1)))
        _ok(e, e.lt(p["iB"], 1 << 14))
        e.var("ib", e.alloc(e.add(e.mul(p["iB"], BLK_W), 1)))
        _ok(e, e.ne(p["ib"], NONE))
        e.st(S_BLK, p["ib"])
        # First pass: block extents, node and value counts.
        e.var("iat", e.add(p["is"], 2))
        e.var("inn", 0)
        e.var("inv", 0)
        e.var("ine", 0)

        def count_block():
            e.var("icb", e.add(p["ib"], e.mul(p["ibk"], BLK_W)))
            e.st(e.add(p["icb"], B_PARAMS_AT), p["iat"])
            e.st(e.add(p["icb"], B_NPARAMS), e.rd(p["iat"]))
            e.st(e.add(p["icb"], B_PBASE), p["inv"])
            e.set("inv", e.add(p["inv"], e.rd(p["iat"])))
            e.set("iat", e.add(e.add(p["iat"], 1), e.rd(p["iat"])))
            e.st(e.add(p["icb"], B_NNODES), e.rd(p["iat"]))
            e.st(e.add(p["icb"], B_NODEBASE), p["inn"])
            e.var("icn", e.rd(p["iat"]))
            e.set("iat", e.add(p["iat"], 1))
            e.st(e.add(p["icb"], B_NODES_AT), p["iat"])

            def count_node():
                e.set("iat", _call(e, "node_info", p["iat"]))
                e.set("inv", e.add(p["inv"], e.rd(e.ld(e.add(_g(e, G_NI), NI_RESULTS)))))

            e.for_("icq", 0, p["icn"], count_node)
            e.set("inn", e.add(p["inn"], p["icn"]))
            e.st(e.add(p["icb"], B_TERM_AT), p["iat"])
            kind = e.rd(p["iat"])
            e.st(e.add(p["icb"], B_EDGE0), p["ine"])
            e.st(e.add(p["icb"], B_NEDGE), e.sel(e.eq(kind, 1), 1, e.sel(e.eq(kind, 2), 2, 0)))
            e.set("ine", e.add(p["ine"], e.sel(e.eq(kind, 1), 1, e.sel(e.eq(kind, 2), 2, 0))))
            e.set("iat", _call(e, "term_end", p["iat"]))

        e.for_("ibk", 0, p["iB"], count_block)
        _ok(e, e.both(e.lt(p["inn"], 1 << 18), e.lt(p["inv"], 1 << 19)))
        e.st(S_NN, p["inn"])
        e.st(S_V, p["inv"])
        for slot, words in ((S_NODE, e.mul(e.add(p["inn"], 1), NODE_W)), (S_VAL, e.mul(e.add(p["inv"], 1), VAL_W)),
                            (S_EDGES, e.mul(e.add(p["ine"], 1), EDGE_W)), (S_PO, e.add(p["inv"], 1)), (S_ONPATH, e.add(p["inv"], 1))):
            e.var("ialloc", e.alloc(words))
            _ok(e, e.ne(p["ialloc"], NONE))
            e.st(slot, p["ialloc"])
        e.st(S_NEDGES, p["ine"])
        # Second pass: node records, value types, edges.

        def block():
            e.var("ipat", _blk(e, p["ibk"], B_PARAMS_AT))
            e.var("ipb", _blk(e, p["ibk"], B_PBASE))
            e.for_("ipq", 0, e.rd(p["ipat"]), lambda: (
                _set_val(e, e.add(p["ipb"], p["ipq"]), V_TYPE, _reference(e, g, e.rd(e.add(e.add(p["ipat"], 1), p["ipq"])))),
                _set_val(e, e.add(p["ipb"], p["ipq"]), V_CONST, 0),
                _set_val(e, e.add(p["ipb"], p["ipq"]), V_ORIGIN, p["ibk"]),
                _set_val(e, e.add(p["ipb"], p["ipq"]), V_INDEX, p["ipq"])))
            e.var("inat", _blk(e, p["ibk"], B_NODES_AT))
            e.var("ink", _blk(e, p["ibk"], B_NODEBASE))
            e.var("irb", e.add(p["ipb"], e.rd(p["ipat"])))

            def node():
                e.var("inr", e.add(e.ld(S_NODE), e.mul(p["ink"], NODE_W)))
                e.st(e.add(p["inr"], N_AT), p["inat"])
                e.set("inat", _call(e, "node_info", p["inat"]))
                ni = _g(e, G_NI)
                e.st(e.add(p["inr"], N_OP), e.ld(e.add(ni, NI_OP)))
                e.st(e.add(p["inr"], N_OPERANDS), e.ld(e.add(ni, NI_OPERANDS)))
                e.st(e.add(p["inr"], N_ATTRS), e.ld(e.add(ni, NI_ATTRIBUTES)))
                e.var("ient", e.ld(e.add(ni, NI_ENTITY)))
                e.st(e.add(p["inr"], N_ENTITY), e.sel(e.eq(p["ient"], NONE), NONE, _reference(e, g, e.sel(e.eq(p["ient"], NONE), 0, p["ient"]))))
                e.st(e.add(p["inr"], N_BLOCK), p["ibk"])
                e.st(e.add(p["inr"], N_RBASE), p["irb"])
                e.var("ires", e.ld(e.add(ni, NI_RESULTS)))
                e.st(e.add(p["inr"], N_NRES), e.rd(p["ires"]))
                e.for_("irq", 0, e.rd(p["ires"]), lambda: (
                    _set_val(e, e.add(p["irb"], p["irq"]), V_TYPE, _reference(e, g, e.rd(e.add(e.add(p["ires"], 1), p["irq"])))),
                    _set_val(e, e.add(p["irb"], p["irq"]), V_CONST, 0),
                    _set_val(e, e.add(p["irb"], p["irq"]), V_ORIGIN, e.add(NODE_ORIGIN, p["ink"])),
                    _set_val(e, e.add(p["irb"], p["irq"]), V_INDEX, p["irq"])))
                e.set("irb", e.add(p["irb"], e.rd(p["ires"])))
                e.set("ink", e.add(p["ink"], 1))

            e.for_("inq", 0, _blk(e, p["ibk"], B_NNODES), node)
            # The edges: target, arguments.
            e.var("ita", _blk(e, p["ibk"], B_TERM_AT))
            e.var("ikind", e.rd(p["ita"]))
            e.var("ie", _blk(e, p["ibk"], B_EDGE0))

            def edge(at_name: str):
                er = e.add(e.ld(S_EDGES), e.mul(p["ie"], EDGE_W))
                e.var("ier", er)
                e.st(p["ier"], e.rd(p[at_name]))
                e.st(e.add(p["ier"], 1), e.add(p[at_name], 2))
                e.st(e.add(p["ier"], 2), e.rd(e.add(p[at_name], 1)))
                e.set("ie", e.add(p["ie"], 1))
                e.var("iea", e.add(p[at_name], 2))
                e.for_("ieq", 0, e.rd(e.add(p[at_name], 1)), lambda: e.set("iea", e.add(p["iea"], _value_size(e, p["iea"]))))
                e.set(at_name, p["iea"])

            def branch():
                e.var("ieb", e.add(p["ita"], 1))
                edge("ieb")

            def conditional():
                e.var("iec", e.add(p["ita"], 1))
                e.set("iec", e.add(p["iec"], _value_size(e, p["iec"])))
                edge("iec")
                edge("iec")

            e.if_(e.eq(p["ikind"], 1), branch, lambda: e.if_(e.eq(p["ikind"], 2), conditional))

        e.for_("ibk", 0, p["iB"], block)

        # ``target.supported_operations`` and ``supported_terminators``, per block.
        def checks():
            e.var("ick", _blk(e, p["ibk"], B_NODEBASE))

            def op():
                e.var("icop", _node(e, e.add(p["ick"], p["icq"]), N_OP))
                supported = e.both(e.lt(p["icop"], 256), e.ne(_at(e, G_SUP, e.sel(e.lt(p["icop"], 256), p["icop"], 0)), 0))

                def write():
                    D.text(e, "XAX.SPIRV.OPERATION")
                    D.cid(e, _cid_words(e, g))
                    D.text(e, "SPIRV-OP-TARGET-SUPPORTED")
                    _target_list(e, G_SUP_AT)
                    D.integer(e, p["icop"])

                D.reject_unless(e, supported, write)

            e.for_("icq", 0, _blk(e, p["ibk"], B_NNODES), op)
            e.var("ictk", e.rd(_blk(e, p["ibk"], B_TERM_AT)))
            supported = e.both(e.lt(p["ictk"], 8), e.ne(_at(e, G_SUPT, e.sel(e.lt(p["ictk"], 8), p["ictk"], 0)), 0))

            def write_term():
                D.text(e, "XAX.SPIRV.TERMINATOR")
                D.cid(e, _cid_words(e, g))
                D.text(e, "SPIRV-TERMINATOR-TARGET-SUPPORTED")
                _target_list(e, G_SUPT_AT)
                D.tagged(e, D.T_TERMINATOR, p["ictk"])

            D.reject_unless(e, supported, write_term)

        e.for_("ibk", 0, p["iB"], checks)
        e.give(1)
    return _function((), build, tables)


def _reject_lowering(e: E, rule: str, expected, actual):
    """``_Lowering.reject``: ``XAX.SPIRV.LOWERING`` on the graph."""
    def write():
        D.text(e, "XAX.SPIRV.LOWERING")
        D.cid(e, _cid_words(e, e.ld(S_G)))
        D.text(e, rule)
        expected()
        actual()
    D.reject_unless(e, e.eq(1, 0), write)


def _sp_classify(tables):
    """``_Lowering.lower``'s first loop: every value classified (``SPIRV-VALUE``), constants' values masked."""
    def build(e: E):
        p = e.p

        def value():
            v = p["cv"]
            e.var("ct", _val(e, v, V_TYPE))
            _ok(e, e.ne(p["ct"], NONE))
            e.var("cform", _form(e, p["ct"]))
            _set_val(e, v, V_WIDTH, 0)
            _set_val(e, v, V_VAR, NONE)
            _set_val(e, v, V_KNOWN, 0)
            e.st(e.add(e.ld(S_ONPATH), v), 0)

            def machine():
                _bits(e, p["ct"], "cw")

                def bad():
                    _reject_lowering(e, "SPIRV-VALUE", lambda: D.text(e, "bits<1..32>, binding pointer, or proof"), lambda: D.cid(e, _cid_words(e, p["ct"])))

                e.if_(e.either(e.ne(p["cform"], 1), e.lt(32, p["cw"])), bad)
                _set_val(e, v, V_WIDTH, p["cw"])

            e.if_(e.not_(e.either(e.eq(p["cform"], 3), e.eq(p["cform"], 4), e.eq(p["cform"], 2))), machine)

        # Per block: the parameters, then each node's results (and a constant's value).
        def block():
            e.var("cpb", _blk(e, p["cb"], B_PBASE))
            e.for_("cq", 0, _blk(e, p["cb"], B_NPARAMS), lambda: (e.var("cv", e.add(p["cpb"], p["cq"])), value()))
            e.var("ckb", _blk(e, p["cb"], B_NODEBASE))

            def node():
                e.var("ck", e.add(p["ckb"], p["cn"]))
                e.for_("cq", 0, _node(e, p["ck"], N_NRES), lambda: (e.var("cv", e.add(_node(e, p["ck"], N_RBASE), p["cq"])), value()))

                def constant():
                    e.var("cr", _node(e, p["ck"], N_RBASE))
                    e.var("cent", _node(e, p["ck"], N_ENTITY))
                    _ok(e, e.ne(p["cent"], NONE))
                    e.var("cca", _at(e, G_PAY, p["cent"]))
                    _payload_uleb(e, "cca")  # the type reference
                    e.var("ccn", _payload_uleb(e, "cca"))
                    _ok(e, e.le(p["ccn"], 4))
                    e.var("ccv", 0)
                    e.var("ccwt", 1)
                    e.for_("ccq", 0, p["ccn"], lambda: (e.set("ccv", e.add(p["ccv"], e.mul(e.rd(e.add(p["cca"], p["ccq"])), p["ccwt"]))),
                                                        e.set("ccwt", e.mul(p["ccwt"], 256))))
                    _set_val(e, p["cr"], V_RAW, p["ccv"])
                    e.var("ccw", _val(e, p["cr"], V_WIDTH))
                    _ok(e, e.ne(p["ccw"], 0))
                    _set_val(e, p["cr"], V_CONST, 1)
                    e.var("ccm", 1)
                    e.for_("ccs", 0, p["ccw"], lambda: e.set("ccm", e.mul(p["ccm"], 2)))
                    _set_val(e, p["cr"], V_VALUE, e.and_(p["ccv"], e.sub(p["ccm"], 1)))

                e.if_(e.eq(_node(e, p["ck"], N_OP), int(Operation.CONSTANT)), constant)

            e.for_("cn", 0, _blk(e, p["cb"], B_NNODES), node)

        e.for_("cb", 0, e.ld(S_B), block)
        e.give(1)
    return _function((), build, tables)




# -- static pointers (``_Lowering.pointer``) as an explicit stack ----------------------------------------------------

def _frame(e: E, k):
    return e.add(e.ld(S_STACK), e.mul(k, FRAME_W))


def _push(e: E, v):
    p = e.p
    e.var("pu_sp", e.ld(S_SP))
    _ok(e, e.lt(p["pu_sp"], e.add(e.ld(S_V), 2)))
    e.var("pu_f", _frame(e, p["pu_sp"]))
    for field, value in ((F_V, v), (F_STATE, 0), (F_EDGE, 0), (F_VIS, e.flag(e.ne(e.ld(S_VIS), 0))), (F_WAIT, 0), (F_N, 0)):
        e.st(e.add(p["pu_f"], field), value)
    e.st(S_SP, e.add(p["pu_sp"], 1))


def _ret(e: E, kind: int):
    e.st(S_RES, kind)
    e.st(S_SP, e.sub(e.ld(S_SP), 1))


def _finish(e: E, frame, binding, offset):
    """The frame's pointer is found: ``SPIRV-POINTER-ALIGNED``, then memoized and returned."""
    p = e.p
    e.var("fi_b", binding)
    e.var("fi_o", offset)
    e.if_(e.ne(e.and_(p["fi_o"], 3), 0), lambda: _reject_lowering(e, "SPIRV-POINTER-ALIGNED", lambda: D.text(e, "4-byte multiple"),
                                                                 lambda: D.integer(e, p["fi_o"])))
    e.var("fi_v", e.ld(e.add(frame, F_V)))
    _set_val(e, p["fi_v"], V_KNOWN, e.add(p["fi_b"], 1))
    e.st(e.add(e.ld(S_PO), p["fi_v"]), p["fi_o"])
    e.st(S_PB, p["fi_b"])
    e.st(S_FIX, p["fi_o"])
    _ret(e, 1)


def _sp_step(tables):
    """One step of the pointer machine on the top frame."""
    def build(e: E):
        p = e.p
        e.var("sf", _frame(e, e.sub(e.ld(S_SP), 1)))
        e.var("sv", e.ld(e.add(p["sf"], F_V)))
        e.var("sstate", e.ld(e.add(p["sf"], F_STATE)))
        e.var("sorig", _val(e, p["sv"], V_ORIGIN))
        e.var("sidx", _val(e, p["sv"], V_INDEX))
        e.var("snode", e.flag(e.le(NODE_ORIGIN, p["sorig"])))

        def start():
            e.var("sknown", _val(e, p["sv"], V_KNOWN))

            def known():
                e.st(S_PB, e.sub(p["sknown"], 1))
                e.st(S_FIX, e.ld(e.add(e.ld(S_PO), p["sv"])))
                _ret(e, 1)

            def param():
                def entry():
                    _ok(e, e.le(1, p["sidx"]))  # the invocation index is no pointer
                    _finish(e, p["sf"], e.udiv(e.sub(p["sidx"], 1), 3), 0)

                def other():
                    e.st(e.add(e.ld(S_ONPATH), p["sv"]), 1)
                    e.st(S_VIS, e.add(e.ld(S_VIS), 1))
                    e.st(e.add(p["sf"], F_STATE), 1)

                e.if_(e.eq(p["sorig"], e.ld(S_ENTRY)), entry, other)

            def node():
                e.var("snk", e.sub(p["sorig"], NODE_ORIGIN))
                e.var("sop", _node(e, p["snk"], N_OP))
                base = e.either(e.eq(p["sop"], int(Operation.ADDRESS_OFFSET)), e.eq(p["sop"], int(Operation.POINTER_CAST)))

                def static():
                    _reject_lowering(e, "SPIRV-POINTER-STATIC", lambda: D.text(e, "binding pointer, address_offset, or pointer_cast"),
                                     lambda: D.integer(e, p["sop"]))

                e.if_(e.not_(base), static)
                e.var("sopnd", _node(e, p["snk"], N_OPERANDS))
                _ok(e, e.ne(e.rd(p["sopnd"]), 0))
                e.st(e.add(p["sf"], F_STATE), 2)
                _push(e, _vid(e, e.add(p["sopnd"], 1)))

            fresh = lambda: e.if_(e.ne(e.ld(e.add(e.ld(S_ONPATH), p["sv"])), 0), lambda: _ret(e, 2),  # noqa: E731
                                  lambda: e.if_(e.ne(p["snode"], 0), node, param))
            e.if_(e.ne(p["sknown"], 0), known, fresh)

        def edges():
            """The parameter's incoming edges, in block then edge order; a child's pair joins the distinct set."""
            def collect():
                e.st(e.add(p["sf"], F_WAIT), 0)

                def add():
                    e.var("sn", e.ld(e.add(p["sf"], F_N)))
                    e.var("sdup", 0)
                    e.for_("sq", 0, p["sn"], lambda: e.if_(e.both(
                        e.eq(e.ld(e.add(p["sf"], e.add(F_PAIRS, e.mul(p["sq"], 2)))), e.ld(S_PB)),
                        e.eq(e.ld(e.add(p["sf"], e.add(F_PAIRS + 1, e.mul(p["sq"], 2)))), e.ld(S_FIX))), lambda: e.set("sdup", 1)))

                    def insert():
                        _ok(e, e.lt(p["sn"], INCOMING))
                        e.st(e.add(p["sf"], e.add(F_PAIRS, e.mul(p["sn"], 2))), e.ld(S_PB))
                        e.st(e.add(p["sf"], e.add(F_PAIRS + 1, e.mul(p["sn"], 2))), e.ld(S_FIX))
                        e.st(e.add(p["sf"], F_N), e.add(p["sn"], 1))

                    e.if_(e.eq(p["sdup"], 0), insert)

                e.if_(e.eq(e.ld(S_RES), 1), add)

            e.if_(e.ne(e.ld(e.add(p["sf"], F_WAIT)), 0), collect)
            e.var("se", e.ld(e.add(p["sf"], F_EDGE)))
            e.var("sfound", NONE)
            e.while_(lambda: e.both(e.eq(p["sfound"], NONE), e.lt(p["se"], e.ld(S_NEDGES))), lambda: (
                e.if_(e.eq(e.ld(e.add(e.ld(S_EDGES), e.mul(p["se"], EDGE_W))), p["sorig"]), lambda: e.set("sfound", p["se"])),
                e.set("se", e.add(p["se"], 1))))

            def child():
                e.st(e.add(p["sf"], F_EDGE), p["se"])
                e.var("sea", e.ld(e.add(e.add(e.ld(S_EDGES), e.mul(p["sfound"], EDGE_W)), 1)))
                _ok(e, e.lt(p["sidx"], e.ld(e.add(e.add(e.ld(S_EDGES), e.mul(p["sfound"], EDGE_W)), 2))))
                e.for_("sq", 0, p["sidx"], lambda: e.set("sea", e.add(p["sea"], _value_size(e, p["sea"]))))
                e.st(e.add(p["sf"], F_WAIT), 1)
                _push(e, _vid(e, p["sea"]))

            def done():
                e.st(e.add(e.ld(S_ONPATH), p["sv"]), 0)
                e.st(S_VIS, e.sub(e.ld(S_VIS), 1))
                e.var("sn", e.ld(e.add(p["sf"], F_N)))

                def cycle():
                    _ret(e, 2)

                def decided():
                    def several():
                        def actual():
                            # ``sorted(incoming)``: the pairs by binding, then offset (a selection sort of the few).
                            D.put(e, D.T_LIST)
                            D.put(e, p["sn"])
                            e.var("slast_b", NONE)
                            e.var("slast_o", NONE)

                            def pick():
                                e.var("sbest", NONE)

                                def candidate():
                                    pb = e.ld(e.add(p["sf"], e.add(F_PAIRS, e.mul(p["sq"], 2))))
                                    po = e.ld(e.add(p["sf"], e.add(F_PAIRS + 1, e.mul(p["sq"], 2))))
                                    e.var("scb", pb)
                                    e.var("sco", po)
                                    after = e.either(e.eq(p["slast_b"], NONE), e.lt(p["slast_b"], p["scb"]),
                                                     e.both(e.eq(p["slast_b"], p["scb"]), e.lt(p["slast_o"], p["sco"])))
                                    e.var("sbb", e.sel(e.eq(p["sbest"], NONE), 0, e.ld(e.add(p["sf"], e.add(F_PAIRS, e.mul(e.sel(e.eq(p["sbest"], NONE), 0, p["sbest"]), 2))))))
                                    e.var("sbo", e.sel(e.eq(p["sbest"], NONE), 0, e.ld(e.add(p["sf"], e.add(F_PAIRS + 1, e.mul(e.sel(e.eq(p["sbest"], NONE), 0, p["sbest"]), 2))))))
                                    better = e.either(e.eq(p["sbest"], NONE), e.lt(p["scb"], p["sbb"]), e.both(e.eq(p["scb"], p["sbb"]), e.lt(p["sco"], p["sbo"])))
                                    e.if_(e.both(after, better), lambda: e.set("sbest", p["sq"]))

                                e.for_("sq", 0, p["sn"], candidate)
                                e.set("slast_b", e.ld(e.add(p["sf"], e.add(F_PAIRS, e.mul(p["sbest"], 2)))))
                                e.set("slast_o", e.ld(e.add(p["sf"], e.add(F_PAIRS + 1, e.mul(p["sbest"], 2)))))
                                D.put(e, D.T_TUPLE)
                                D.put(e, 2)
                                D.integer(e, p["slast_b"])
                                D.integer(e, p["slast_o"])

                            e.for_("sk", 0, p["sn"], pick)

                        _reject_lowering(e, "SPIRV-POINTER-STATIC", lambda: D.text(e, "one static binding and offset"), actual)

                    e.if_(e.ne(p["sn"], 1), several)
                    _finish(e, p["sf"], e.ld(e.add(p["sf"], F_PAIRS)), e.ld(e.add(p["sf"], F_PAIRS + 1)))

                e.if_(e.both(e.eq(p["sn"], 0), e.ne(e.ld(e.add(p["sf"], F_VIS)), 0)), cycle, decided)

            e.if_(e.ne(p["sfound"], NONE), child, done)

        def base():
            def found():
                e.var("sbk", e.sub(p["sorig"], NODE_ORIGIN))
                e.var("sadd", 0)
                e.if_(e.eq(_node(e, p["sbk"], N_OP), int(Operation.ADDRESS_OFFSET)), lambda: (
                    _ok(e, e.ne(_node(e, p["sbk"], N_ATTRS), NONE)), e.set("sadd", e.rd(e.add(_node(e, p["sbk"], N_ATTRS), 1)))))
                _finish(e, p["sf"], e.ld(S_PB), e.add(e.ld(S_FIX), p["sadd"]))

            e.if_(e.eq(e.ld(S_RES), 2), lambda: _ret(e, 2), found)

        e.if_(e.eq(p["sstate"], 0), start, lambda: e.if_(e.eq(p["sstate"], 1), edges, base))
        e.give(1)
    return _function((), build, tables)


def _sp_pointer(tables):
    """``pointer(ref)`` for value ``pv``: 1 with the binding and offset in ``S_PB``/``S_FIX``, ``CYCLE`` for the
    bootstrap's None (only open cycles), NONE when rejected or declined."""
    def build(e: E):
        p = e.p
        e.st(S_SP, 0)
        e.st(S_VIS, 0)
        _push(e, p["pv"])
        e.while_(lambda: e.ne(e.ld(S_SP), 0), lambda: _call(e, "sp_step"))
        e.give(e.sel(e.eq(e.ld(S_RES), 1), 1, CYCLE))
    return _function(("pv",), build, tables)


def _sp_races(tables):
    """``check_races``: the checked accesses' bindings; a stored-to binding's accesses at ``invocation * 4`` only."""
    def build(e: E):
        p = e.p
        e.var("racc", e.alloc(e.add(e.mul(e.ld(S_NN), 4), 1)))
        _ok(e, e.ne(p["racc"], NONE))
        e.var("rn", 0)
        e.var("rwritten", e.alloc(e.add(e.ld(S_NB), 2)))
        _ok(e, e.ne(p["rwritten"], NONE))
        e.for_("rq", 0, e.add(e.ld(S_NB), 2), lambda: e.st(e.add(p["rwritten"], p["rq"]), 0))

        def node():
            e.var("rop", _node(e, p["rk"], N_OP))
            access = e.either(e.eq(p["rop"], int(Operation.CHECKED_LOAD_BITS_LE)), e.eq(p["rop"], int(Operation.CHECKED_STORE_BITS_LE)))

            def record():
                e.var("ropnd", _node(e, p["rk"], N_OPERANDS))
                _ok(e, e.le(2, e.rd(p["ropnd"])))
                e.var("rp", _call(e, "sp_pointer", _vid(e, e.add(p["ropnd"], 1))))
                _ok(e, e.eq(p["rp"], 1))  # None: the bootstrap unpacks it and fails without a diagnostic
                e.var("rstore", e.flag(e.eq(p["rop"], int(Operation.CHECKED_STORE_BITS_LE))))
                e.var("rsecond", e.add(e.add(p["ropnd"], 1), _value_size(e, e.add(p["ropnd"], 1))))
                for field, value in enumerate((p["rstore"], e.ld(S_PB), e.ld(S_FIX), _vid(e, p["rsecond"]))):
                    e.st(e.add(p["racc"], e.add(e.mul(p["rn"], 4), field)), value)
                e.set("rn", e.add(p["rn"], 1))
                _ok(e, e.lt(e.ld(S_PB), e.add(e.ld(S_NB), 1)))
                e.if_(e.ne(p["rstore"], 0), lambda: e.st(e.add(p["rwritten"], e.ld(S_PB)), 1))

            e.if_(access, record)

        e.for_("rk", 0, e.ld(S_NN), node)
        invocation = _blk(e, e.ld(S_ENTRY), B_PBASE)
        e.var("rinv", invocation)

        def check():
            at = e.add(p["racc"], e.mul(p["rq"], 4))
            e.var("ra_store", e.ld(at))
            e.var("ra_b", e.ld(e.add(at, 1)))
            e.var("ra_o", e.ld(e.add(at, 2)))
            e.var("ra_i", e.ld(e.add(at, 3)))
            # ``own_element``: the index is ``mul.wrap(invocation, constant 4)`` (either operand order).
            e.var("ra_own", 0)
            e.var("ra_orig", _val(e, p["ra_i"], V_ORIGIN))

            def node_index():
                e.var("ra_k", e.sub(p["ra_orig"], NODE_ORIGIN))
                e.var("ra_ops", _node(e, p["ra_k"], N_OPERANDS))

                def product():
                    e.var("ra_x", _vid(e, e.add(p["ra_ops"], 1)))
                    e.var("ra_y", _vid(e, e.add(e.add(p["ra_ops"], 1), _value_size(e, e.add(p["ra_ops"], 1)))))
                    e.var("ra_c", NONE)
                    e.if_(e.both(e.eq(p["ra_x"], p["rinv"]), e.ne(p["ra_y"], p["rinv"])), lambda: e.set("ra_c", p["ra_y"]))
                    e.if_(e.both(e.eq(p["ra_y"], p["rinv"]), e.ne(p["ra_x"], p["rinv"])), lambda: e.set("ra_c", p["ra_x"]))

                    def constant():
                        e.var("ra_co", _val(e, p["ra_c"], V_ORIGIN))
                        e.if_(e.le(NODE_ORIGIN, p["ra_co"]), lambda: e.if_(
                            e.both(e.eq(_node(e, e.sub(p["ra_co"], NODE_ORIGIN), N_OP), int(Operation.CONSTANT)), e.eq(_val(e, p["ra_c"], V_RAW), 4)),
                            lambda: e.set("ra_own", 1)))

                    e.if_(e.ne(p["ra_c"], NONE), constant)

                e.if_(e.both(e.eq(_node(e, p["ra_k"], N_OP), int(Operation.MUL_WRAP)), e.eq(e.rd(p["ra_ops"]), 2)), product)

            e.if_(e.le(NODE_ORIGIN, p["ra_orig"]), node_index)

            def race():
                def actual():
                    D.put(e, D.T_LIST)
                    D.put(e, 3)
                    D.integer(e, p["ra_b"])
                    D.integer(e, p["ra_o"])
                    e.if_(e.ne(p["ra_store"], 0), lambda: D.text(e, "store"), lambda: D.text(e, "load"))

                _reject_lowering(e, "SPIRV-KERNEL-OWN-ELEMENT", lambda: D.text(e, "stores and loads of stored-to bindings at invocation * 4"), actual)

            e.if_(e.both(e.ne(e.ld(e.add(p["rwritten"], p["ra_b"])), 0), e.either(e.ne(p["ra_o"], 0), e.eq(p["ra_own"], 0))), race)

        e.for_("rq", 0, p["rn"], check)
        e.give(1)
    return _function((), build, tables)


# -- lowering (``_Lowering.lower_node``, ``lower_check``, ``lower_terminator``) ------------------------------------

def _second(e: E, operands_at):
    """The position of a node's second operand."""
    return e.add(e.add(operands_at, 1), _value_size(e, e.add(operands_at, 1)))


def _may_trap(e: E, k, name: str):
    """``may_trap``: a checked access, or a division whose divisor is no nonzero constant."""
    p = e.p
    e.var(f"{name}_op", _node(e, k, N_OP))
    e.var(name, e.flag(e.either(e.eq(p[f"{name}_op"], int(Operation.CHECKED_LOAD_BITS_LE)), e.eq(p[f"{name}_op"], int(Operation.CHECKED_STORE_BITS_LE)))))

    def division():
        e.var(f"{name}_d", _vid(e, _second(e, _node(e, k, N_OPERANDS))))
        e.set(name, e.flag(e.either(e.eq(_val(e, p[f"{name}_d"], V_CONST), 0), e.eq(_val(e, p[f"{name}_d"], V_VALUE), 0))))

    e.if_(e.either(e.eq(p[f"{name}_op"], int(Operation.UDIV)), e.eq(p[f"{name}_op"], int(Operation.UREM))), division)


def _store_state(e: E, value):
    _raw(e, "Store", e.ld(S_STATE), value)


def _trap_case(e: E, code, name: str):
    """``trap_case``: the case of trap ``code`` (a new one after every block case and earlier trap)."""
    e.var(name, _call(e, "sp_trap_case", code))
    return e.p[name]


def _sp_trap_case(tables):
    def build(e: E):
        p = e.p
        e.var("tf", NONE)
        e.for_("tq", 0, e.ld(S_NTRAPS), lambda: e.if_(e.eq(e.ld(e.add(e.ld(S_TRAPS), e.mul(p["tq"], 2))), p["tcode"]),
                                                      lambda: e.set("tf", e.ld(e.add(e.ld(S_TRAPS), e.add(e.mul(p["tq"], 2), 1))))))

        def create():
            _ok(e, e.lt(e.ld(S_NTRAPS), 64))
            e.var("tc", e.add(e.ld(S_BLOCKCASES), e.ld(S_NTRAPS)))
            e.st(e.add(e.ld(S_TRAPS), e.mul(e.ld(S_NTRAPS), 2)), p["tcode"])
            e.st(e.add(e.ld(S_TRAPS), e.add(e.mul(e.ld(S_NTRAPS), 2), 1)), p["tc"])
            e.st(S_NTRAPS, e.add(e.ld(S_NTRAPS), 1))
            e.set("tf", p["tc"])

        e.if_(e.eq(p["tf"], NONE), create)
        e.give(p["tf"])
    return _function(("tcode",), build, tables)


def _element(e: E, k, name: str):
    """``element``: the access's binding and offset (``SPIRV-ACCESS-WIDTH``), whether its limit is negative, the limit,
    and the dynamic offset's id (loaded now)."""
    p = e.p
    e.var(f"{name}_ops", _node(e, k, N_OPERANDS))
    e.var(f"{name}_r", _call(e, "sp_pointer", _vid(e, e.add(p[f"{name}_ops"], 1))))
    _ok(e, e.eq(p[f"{name}_r"], 1))
    e.var(f"{name}_b", e.ld(S_PB))
    e.var(f"{name}_o", e.ld(S_FIX))
    _ok(e, e.lt(p[f"{name}_b"], e.ld(S_NB)))
    e.var(f"{name}_at", _node(e, k, N_ATTRS))
    _ok(e, e.both(e.ne(p[f"{name}_at"], NONE), e.le(1, e.rd(p[f"{name}_at"]))))
    e.var(f"{name}_size", e.rd(e.add(p[f"{name}_at"], 1)))
    e.if_(e.ne(p[f"{name}_size"], 4), lambda: _reject_lowering(e, "SPIRV-ACCESS-WIDTH", lambda: D.integer(e, 4), lambda: D.integer(e, p[f"{name}_size"])))
    e.var(f"{name}_ext", e.ld(e.add(e.ld(S_BIND), e.mul(p[f"{name}_b"], 2))))
    e.var(f"{name}_neg", e.flag(e.lt(p[f"{name}_ext"], e.add(p[f"{name}_o"], 4))))
    e.var(f"{name}_limit", e.sub(e.sub(p[f"{name}_ext"], p[f"{name}_o"]), 4))
    _value(e, _vid(e, _second(e, p[f"{name}_ops"])), f"{name}_dyn")


def _sp_check(tables):
    """``lower_check`` of node ``ck``: the trap condition, then the state: its trap case or ``next`` case."""
    def build(e: E):
        p = e.p
        k = p["ck"]
        e.var("kop", _node(e, k, N_OP))
        e.var("kbad", 0)
        e.var("kcode", 0)
        uint, boolean = e.ld(S_UINT), e.ld(S_BOOL)

        def division():
            e.var("kdv", _value(e, _vid(e, _second(e, _node(e, k, N_OPERANDS))), "kdvv"))
            e.set("kbad", _ins(e, "kb1", "IEqual", boolean, p["kdv"], _const(e, 0, "kz")))
            e.set("kcode", STATUS_TRAP | 2)

        def access():
            _element(e, k, "kel")

            def negative():
                e.var("kz0", _const(e, 0, "kz1"))
                e.set("kbad", _ins(e, "kb2", "IEqual", boolean, p["kz0"], _const(e, 0, "kz2")))

            def bounded():
                e.var("kout", _ins(e, "kb3", "UGreaterThan", boolean, p["kel_dyn"], _const(e, p["kel_limit"], "kl")))
                e.var("kand", _ins(e, "kb4", "BitwiseAnd", uint, p["kel_dyn"], _const(e, 3, "k3")))
                e.var("kmis", _ins(e, "kb5", "INotEqual", boolean, p["kand"], _const(e, 0, "k0")))
                e.set("kbad", _ins(e, "kb6", "LogicalOr", boolean, p["kout"], p["kmis"]))

            e.if_(e.ne(p["kel_neg"], 0), negative, bounded)
            e.set("kcode", STATUS_BOUNDS)

        e.if_(e.either(e.eq(p["kop"], int(Operation.UDIV)), e.eq(p["kop"], int(Operation.UREM))), division, access)
        e.var("ktrap", _const(e, _trap_case(e, p["kcode"], "ktc"), "ktk"))
        e.var("knext", _const(e, p["cnext"], "knx"))
        _store_state(e, _ins(e, "ks", "Select", uint, p["kbad"], p["ktrap"], p["knext"]))
        e.give(1)
    return _function(("ck", "cnext"), build, tables)


def _sp_node(tables):
    """``lower_node`` of node ``nk``."""
    def build(e: E):
        p = e.p
        k = p["nk"]
        uint, boolean = e.ld(S_UINT), e.ld(S_BOOL)
        e.var("nop", _node(e, k, N_OP))
        e.var("nres", _node(e, k, N_RBASE))
        e.var("nops", _node(e, k, N_OPERANDS))
        skip = e.either(*(e.eq(p["nop"], int(op)) for op in (Operation.CONSTANT, Operation.ADDRESS_OFFSET, Operation.POINTER_CAST)))
        e.if_(skip, lambda: e.give(1))

        def access(store: bool):
            _element(e, k, "nel")
            e.var("nadd", _ins(e, "na1", "IAdd", uint, p["nel_dyn"], _const(e, p["nel_o"], "nc1")))
            e.var("nidx", _ins(e, "na2", "ShiftRightLogical", uint, p["nadd"], _const(e, 2, "nc2")))
            e.var("nbuf", e.ld(e.add(e.ld(S_BUFS), p["nel_b"])))
            e.var("nchain", _ins(e, "na3", "AccessChain", e.ld(S_ELEMPTR), p["nbuf"], _const(e, 0, "nc3"), p["nidx"]))
            if store:
                e.var("nthird", e.add(_second(e, p["nops"]), _value_size(e, _second(e, p["nops"]))))
                _raw(e, "Store", p["nchain"], _value(e, _vid(e, p["nthird"]), "nsv"))
            else:
                e.var("nloaded", _ins(e, "na4", "Load", uint, p["nchain"]))
                _ok(e, e.ne(_val(e, p["nres"], V_VAR), NONE))
                _raw(e, "Store", _val(e, p["nres"], V_VAR), p["nloaded"])
            e.give(1)

        e.if_(e.eq(p["nop"], int(Operation.CHECKED_LOAD_BITS_LE)), lambda: access(False))
        e.if_(e.eq(p["nop"], int(Operation.CHECKED_STORE_BITS_LE)), lambda: access(True))
        e.var("nw", _val(e, p["nres"], V_WIDTH))
        _ok(e, e.ne(p["nw"], 0))  # ``self.widths[result]``: a value of no machine width fails without a diagnostic
        e.var("nval", NONE)

        def mask(value):
            e.var("nmv", value)
            e.if_(e.ne(p["nw"], 32), lambda: (
                e.var("nmk", 1), e.for_("nms", 0, p["nw"], lambda: e.set("nmk", e.mul(p["nmk"], 2))),
                e.set("nmv", _ins(e, "nm", "BitwiseAnd", uint, p["nmv"], _const(e, e.sub(p["nmk"], 1), "nmc")))))
            return p["nmv"]

        def binary(opcode):
            def lower():
                e.var("nx", _value(e, _vid(e, e.add(p["nops"], 1)), "nxv"))
                e.var("ny", _value(e, _vid(e, _second(e, p["nops"])), "nyv"))
                e.set("nval", mask(_ins(e, "nb", opcode, uint, p["nx"], p["ny"])))
            return lower

        for operation, opcode in _BINARY.items():
            e.if_(e.eq(p["nop"], int(operation)), binary(opcode))

        def compare():
            e.var("ncmp", e.rd(e.add(_node(e, k, N_ATTRS), 1)))
            e.var("nl", _value(e, _vid(e, e.add(p["nops"], 1)), "nlv"))
            e.var("nr", _value(e, _vid(e, _second(e, p["nops"])), "nrv"))
            e.var("nl_w", _val(e, _vid(e, e.add(p["nops"], 1)), V_WIDTH))
            e.var("nl_w", e.sel(e.eq(p["nl_w"], 0), 32, p["nl_w"]))
            signed = e.either(*(e.eq(p["ncmp"], int(kind)) for kind in _SIGNED))

            def extend():
                e.var("nsh", _const(e, e.sub(32, p["nl_w"]), "nshc"))
                e.set("nl", _ins(e, "nsr1", "ShiftRightArithmetic", uint, _ins(e, "nsl1", "ShiftLeftLogical", uint, p["nl"], p["nsh"]), p["nsh"]))
                e.set("nr", _ins(e, "nsr2", "ShiftRightArithmetic", uint, _ins(e, "nsl2", "ShiftLeftLogical", uint, p["nr"], p["nsh"]), p["nsh"]))

            e.if_(e.both(signed, e.lt(p["nl_w"], 32)), extend)
            e.var("ncond", NONE)
            for kind, opcode in _COMPARE.items():
                e.if_(e.eq(p["ncmp"], int(kind)), lambda opcode=opcode: e.set("ncond", _ins(e, "nci", opcode, boolean, p["nl"], p["nr"])))
            _ok(e, e.ne(p["ncond"], NONE))
            e.var("none_", _const(e, 1, "nc_1"))
            e.set("nval", _ins(e, "ncs", "Select", uint, p["ncond"], p["none_"], _const(e, 0, "nc_0")))

        e.if_(e.eq(p["nop"], int(Operation.INT_COMPARE)), compare)
        e.if_(e.either(e.eq(p["nop"], int(Operation.INT_TRUNCATE)), e.eq(p["nop"], int(Operation.INT_ZERO_EXTEND))),
              lambda: e.set("nval", mask(_value(e, _vid(e, e.add(p["nops"], 1)), "ntv"))))

        def rotate():
            e.var("namt", e.rd(e.add(_node(e, k, N_ATTRS), 1)))
            e.set("nval", _value(e, _vid(e, e.add(p["nops"], 1)), "nrot"))

            def rotated():
                e.var("nright", _ins(e, "nr1", "ShiftRightLogical", uint, p["nval"], _const(e, p["namt"], "nra")))
                e.var("nleft", _ins(e, "nr2", "ShiftLeftLogical", uint, p["nval"], _const(e, e.sub(p["nw"], p["namt"]), "nrb")))
                e.set("nval", mask(_ins(e, "nr3", "BitwiseOr", uint, p["nright"], p["nleft"])))

            e.if_(e.ne(p["namt"], 0), rotated)

        e.if_(e.eq(p["nop"], int(Operation.ROTATE_RIGHT)), rotate)

        def unlowered():
            _reject_lowering(e, "SPIRV-OP-LOWERED", lambda: D.text(e, "supported operation"), lambda: D.integer(e, p["nop"]))

        e.if_(e.eq(p["nval"], NONE), unlowered)
        _ok(e, e.ne(_val(e, p["nres"], V_VAR), NONE))
        _raw(e, "Store", _val(e, p["nres"], V_VAR), p["nval"])
        e.give(1)
    return _function(("nk",), build, tables)


def _sp_term(tables):
    """``lower_terminator`` of block ``tb``."""
    def build(e: E):
        p = e.p
        uint, boolean = e.ld(S_UINT), e.ld(S_BOOL)
        e.var("tat", _blk(e, p["tb"], B_TERM_AT))
        e.var("tkind", e.rd(p["tat"]))
        e.if_(e.eq(p["tkind"], int(TerminatorKind.RETURN)), lambda: (_store_state(e, _const(e, _DONE, "td")), e.give(1)))
        _ok(e, e.ne(p["tkind"], int(TerminatorKind.TRAP)))  # its payload's reason is not in the program's stream: declined
        e.var("te", _blk(e, p["tb"], B_EDGE0))

        def machine(edge: int, name: str):
            """``machine(target, arguments)``: per argument whose target parameter has a variable, the variable and the
            argument's id (loaded now), into a list of pairs (``name``, ``name_n`` of them)."""
            er = e.add(e.ld(S_EDGES), e.mul(e.add(p["te"], edge), EDGE_W))
            e.var(f"{name}_r", er)
            e.var(f"{name}_t", e.ld(p[f"{name}_r"]))
            e.var(f"{name}_a", e.ld(e.add(p[f"{name}_r"], 1)))
            e.var(f"{name}_c", e.ld(e.add(p[f"{name}_r"], 2)))
            e.var(name, e.alloc(e.add(e.mul(p[f"{name}_c"], 2), 1)))
            _ok(e, e.ne(p[name], NONE))
            e.var(f"{name}_n", 0)
            e.var(f"{name}_pb", _blk(e, p[f"{name}_t"], B_PBASE))

            def argument():
                e.var(f"{name}_var", _val(e, e.add(p[f"{name}_pb"], p[f"{name}_q"]), V_VAR))

                def has():
                    e.var(f"{name}_val", _value(e, _vid(e, p[f"{name}_a"]), f"{name}_vv"))
                    e.st(e.add(p[name], e.mul(p[f"{name}_n"], 2)), p[f"{name}_var"])
                    e.st(e.add(p[name], e.add(e.mul(p[f"{name}_n"], 2), 1)), p[f"{name}_val"])
                    e.set(f"{name}_n", e.add(p[f"{name}_n"], 1))

                e.if_(e.ne(p[f"{name}_var"], NONE), has)
                e.set(f"{name}_a", e.add(p[f"{name}_a"], _value_size(e, p[f"{name}_a"])))

            e.for_(f"{name}_q", 0, p[f"{name}_c"], argument)

        def case_const(target_block, name: str):
            return _const(e, _blk(e, target_block, B_SEGBASE), name)

        def branch():
            machine(0, "tm")
            e.for_("tq", 0, p["tm_n"], lambda: _raw(e, "Store", e.ld(e.add(p["tm"], e.mul(p["tq"], 2))), e.ld(e.add(p["tm"], e.add(e.mul(p["tq"], 2), 1)))))
            _store_state(e, case_const(p["tm_t"], "tbc"))

        def conditional():
            e.var("tcv", _value(e, _vid(e, e.add(p["tat"], 1)), "tcvv"))
            e.var("tcond", _ins(e, "tc", "INotEqual", boolean, p["tcv"], _const(e, 0, "tc0")))
            machine(0, "tt")
            machine(1, "tf")
            e.var("tstores", e.alloc(e.add(e.mul(e.add(p["tt_n"], p["tf_n"]), 2), 1)))
            _ok(e, e.ne(p["tstores"], NONE))
            e.var("tsn", 0)

            def store(variable, value):
                e.st(e.add(p["tstores"], e.mul(p["tsn"], 2)), variable)
                e.st(e.add(p["tstores"], e.add(e.mul(p["tsn"], 2), 1)), value)
                e.set("tsn", e.add(p["tsn"], 1))

            pair = lambda table, q, field: e.ld(e.add(p[table], e.add(e.mul(q, 2), field)))  # noqa: E731

            def same():
                _ok(e, e.eq(p["tt_n"], p["tf_n"]))
                e.for_("tq", 0, p["tt_n"], lambda: store(pair("tt", p["tq"], 0), _ins(e, "ts1", "Select", uint, p["tcond"], pair("tt", p["tq"], 1),
                                                                                         pair("tf", p["tq"], 1))))

            def apart():
                def taken():
                    e.var("tld", _ins(e, "tl1", "Load", uint, pair("tt", p["tq"], 0)))
                    store(pair("tt", p["tq"], 0), _ins(e, "ts2", "Select", uint, p["tcond"], pair("tt", p["tq"], 1), p["tld"]))

                def other():
                    e.var("tld", _ins(e, "tl2", "Load", uint, pair("tf", p["tq"], 0)))
                    store(pair("tf", p["tq"], 0), _ins(e, "ts3", "Select", uint, p["tcond"], p["tld"], pair("tf", p["tq"], 1)))

                e.for_("tq", 0, p["tt_n"], taken)
                e.for_("tq", 0, p["tf_n"], other)

            e.if_(e.eq(p["tt_t"], p["tf_t"]), same, apart)
            e.for_("tq", 0, p["tsn"], lambda: _raw(e, "Store", e.ld(e.add(p["tstores"], e.mul(p["tq"], 2))), e.ld(e.add(p["tstores"], e.add(e.mul(p["tq"], 2), 1)))))
            e.var("tcase_t", case_const(p["tt_t"], "tct"))
            e.var("tcase_f", case_const(p["tf_t"], "tcf"))
            _store_state(e, _ins(e, "tsel", "Select", uint, p["tcond"], p["tcase_t"], p["tcase_f"]))

        e.if_(e.eq(p["tkind"], int(TerminatorKind.BRANCH)), branch, conditional)
        e.give(1)
    return _function(("tb",), build, tables)


def _sp_module(tables):
    """``_Lowering.lower``'s module: the declarations, the cases' bodies, the dispatch loop; the words in ``S_BODY``'s
    place: the header, then the sections in order (``SEC_AT``/``SEC_LEN``)."""
    from xax_spirv import _FUNCTION, _INPUT, _PUSH_CONSTANT, _STORAGE_BUFFER

    def build(e: E):
        p = e.p
        e.st(S_NEXT, 1)
        uint = _new_id(e, "muint")
        e.st(S_UINT, uint)
        _emit(e, "globals", "TypeInt", uint, 32, 0)
        boolean = _new_id(e, "mbool")
        e.st(S_BOOL, boolean)
        _emit(e, "globals", "TypeBool", boolean)
        _emit(e, "caps", "Capability", 1)
        _emit(e, "caps", "MemoryModel", 0, 1)
        void = _new_id(e, "mvoid")
        _emit(e, "globals", "TypeVoid", void)
        uvec3 = _new_id(e, "muvec3")
        _emit(e, "globals", "TypeVector", uvec3, uint, 3)
        input_uvec3 = _new_id(e, "minput")
        _emit(e, "globals", "TypePointer", input_uvec3, _INPUT, uvec3)
        gid = _new_id(e, "mgid")
        _emit(e, "globals", "Variable", input_uvec3, gid, _INPUT)
        _emit(e, "decorations", "Decorate", gid, 11, 28)
        array = _new_id(e, "marray")
        _emit(e, "globals", "TypeRuntimeArray", array, uint)
        _emit(e, "decorations", "Decorate", array, 6, 4)
        buffer_struct = _new_id(e, "mstruct")
        _emit(e, "globals", "TypeStruct", buffer_struct, array)
        _emit(e, "decorations", "MemberDecorate", buffer_struct, 0, 35, 0)
        _emit(e, "decorations", "Decorate", buffer_struct, 2)
        buffer_pointer = _new_id(e, "mbufptr")
        _emit(e, "globals", "TypePointer", buffer_pointer, _STORAGE_BUFFER, buffer_struct)
        element_pointer = _new_id(e, "melem")
        e.st(S_ELEMPTR, element_pointer)
        _emit(e, "globals", "TypePointer", element_pointer, _STORAGE_BUFFER, uint)
        e.var("mbufs", e.alloc(e.add(e.ld(S_NB), 2)))
        _ok(e, e.ne(p["mbufs"], NONE))
        e.st(S_BUFS, p["mbufs"])

        def buffer():
            e.var("mvar", _new_id(e, "mv"))
            _emit(e, "globals", "Variable", buffer_pointer, p["mvar"], _STORAGE_BUFFER)
            _emit(e, "decorations", "Decorate", p["mvar"], 34, 0)
            _emit(e, "decorations", "Decorate", p["mvar"], 33, p["mk"])
            e.var("mwritable", e.sel(e.lt(p["mk"], e.ld(S_NB)), e.ld(e.add(e.ld(S_BIND), e.add(e.mul(p["mk"], 2), 1))), 1))
            e.if_(e.eq(p["mwritable"], 0), lambda: _emit(e, "decorations", "Decorate", p["mvar"], 24))
            e.st(e.add(p["mbufs"], p["mk"]), p["mvar"])

        e.for_("mk", 0, e.add(e.ld(S_NB), 1), buffer)
        count_struct = _new_id(e, "mcount")
        _emit(e, "globals", "TypeStruct", count_struct, uint)
        _emit(e, "decorations", "MemberDecorate", count_struct, 0, 35, 0)
        _emit(e, "decorations", "Decorate", count_struct, 2)
        count_pointer = _new_id(e, "mcptr")
        _emit(e, "globals", "TypePointer", count_pointer, _PUSH_CONSTANT, count_struct)
        count_member = _new_id(e, "mcmem")
        _emit(e, "globals", "TypePointer", count_member, _PUSH_CONSTANT, uint)
        count_variable = _new_id(e, "mcvar")
        _emit(e, "globals", "Variable", count_pointer, count_variable, _PUSH_CONSTANT)
        function_uint = _new_id(e, "mfu")
        _emit(e, "globals", "TypePointer", function_uint, _FUNCTION, uint)
        function_type = _new_id(e, "mft")
        _emit(e, "globals", "TypeFunction", function_type, void)
        main = _new_id(e, "mmain")
        _emit(e, "entry", "EntryPoint", 5, main, *_string("main"), gid)
        _emit(e, "modes", "ExecutionMode", main, 17, LOCAL_SIZE, 1, 1)

        # Cases: one per block segment (a segment ends before each trap-capable node), then the traps'.
        e.var("mcase", 0)

        def segments():
            _set_rec(e, S_BLK, p["mb"], BLK_W, B_SEGBASE, p["mcase"])
            e.set("mcase", e.add(p["mcase"], 1))
            e.for_("mn", 0, _blk(e, p["mb"], B_NNODES), lambda: (
                _may_trap(e, e.add(_blk(e, p["mb"], B_NODEBASE), p["mn"]), "mt"), e.set("mcase", e.add(p["mcase"], p["mt"]))))

        e.for_("mb", 0, e.ld(S_B), segments)
        e.st(S_BLOCKCASES, p["mcase"])
        e.st(S_NTRAPS, 0)
        state = _new_id(e, "mstate")
        e.st(S_STATE, state)
        e.for_("mv", 0, e.ld(S_V), lambda: e.if_(e.both(e.ne(_val(e, p["mv"], V_WIDTH), 0), e.eq(_val(e, p["mv"], V_CONST), 0)),
                                                 lambda: _set_val(e, p["mv"], V_VAR, _new_id(e, "mvar2"))))
        e.var("mlabels", e.alloc(8))
        _ok(e, e.ne(p["mlabels"], NONE))
        e.st(S_LABELS, p["mlabels"])
        e.for_("ml", 0, 7, lambda: e.st(e.add(p["mlabels"], p["ml"]), _new_id(e, "mlab")))
        e.var("mcases", e.alloc(e.mul(e.add(p["mcase"], 65), 3)))  # per case: label, body start, body length
        _ok(e, e.ne(p["mcases"], NONE))
        e.st(S_CASES, p["mcases"])
        e.for_("mc", 0, p["mcase"], lambda: e.st(e.add(p["mcases"], e.mul(p["mc"], 3)), _new_id(e, "mcl")))
        # The bodies, in case order, into the bodies section.
        e.st(S_CUR, SEC["bodies"])

        def body_start(case):
            e.st(e.add(e.add(p["mcases"], e.mul(case, 3)), 1), e.ld(SEC_LEN + SEC["bodies"]))

        def body_end(case):
            at = e.add(p["mcases"], e.mul(case, 3))
            e.st(e.add(at, 2), e.sub(e.ld(SEC_LEN + SEC["bodies"]), e.ld(e.add(at, 1))))

        def block():
            e.var("mseg", _blk(e, p["mb"], B_SEGBASE))
            e.var("mkb", _blk(e, p["mb"], B_NODEBASE))
            body_start(p["mseg"])

            def node():
                e.var("mnk", e.add(p["mkb"], p["mn"]))
                _may_trap(e, p["mnk"], "mt2")

                def split():
                    _call(e, "sp_check", p["mnk"], e.add(p["mseg"], 1))
                    body_end(p["mseg"])
                    e.set("mseg", e.add(p["mseg"], 1))
                    body_start(p["mseg"])

                e.if_(e.ne(p["mt2"], 0), split)
                _call(e, "sp_node", p["mnk"])

            e.for_("mn", 0, _blk(e, p["mb"], B_NNODES), node)
            _call(e, "sp_term", p["mb"])
            body_end(p["mseg"])

        e.for_("mb", 0, e.ld(S_B), block)

        def trap():
            e.var("mtc", e.ld(e.add(e.ld(S_TRAPS), e.add(e.mul(p["mq"], 2), 1))))
            e.var("mtcode", e.ld(e.add(e.ld(S_TRAPS), e.mul(p["mq"], 2))))
            body_start(p["mtc"])
            e.var("mz", _const(e, 0, "mz0"))
            e.var("mchain", _ins(e, "mac", "AccessChain", element_pointer, e.ld(e.add(p["mbufs"], e.ld(S_NB))), p["mz"], _const(e, 0, "mz1")))
            e.var("mone", _const(e, 1, "m1"))
            e.var("mz2", _const(e, 0, "mz2c"))
            e.var("mcodec", _const(e, p["mtcode"], "mcc"))
            _ins(e, "mmax", "AtomicUMax", uint, p["mchain"], p["mone"], p["mz2"], p["mcodec"])
            _store_state(e, _const(e, _DONE, "md"))
            body_end(p["mtc"])
            e.st(e.add(p["mcases"], e.mul(p["mtc"], 3)), _new_id(e, "mtl"))

        e.for_("mq", 0, e.ld(S_NTRAPS), trap)
        e.var("mtotal", e.add(p["mcase"], e.ld(S_NTRAPS)))
        # The function, in the code section.
        e.st(S_CUR, SEC["code"])
        label = lambda k: e.ld(e.add(p["mlabels"], k))  # noqa: E731  (entry, header, body, selection, continue, merge, default)
        _emit(e, "code", "Function", void, main, 0, function_type)
        _emit(e, "code", "Label", label(0))
        _emit(e, "code", "Variable", function_uint, state, _FUNCTION)
        e.for_("mv", 0, e.ld(S_V), lambda: e.if_(e.both(e.ne(_val(e, p["mv"], V_WIDTH), 0), e.eq(_val(e, p["mv"], V_CONST), 0)),
                                                 lambda: _emit(e, "code", "Variable", function_uint, _val(e, p["mv"], V_VAR), _FUNCTION)))
        e.var("mvec", _ins(e, "me1", "Load", uvec3, gid))
        e.var("minv", _ins(e, "me2", "CompositeExtract", uint, p["mvec"], 0))
        e.var("mcc0", _const(e, 0, "me3"))
        e.var("mcch", _ins(e, "me4", "AccessChain", count_member, count_variable, p["mcc0"]))
        e.var("mcnt", _ins(e, "me5", "Load", uint, p["mcch"]))
        e.var("mlive", _ins(e, "me6", "ULessThan", boolean, p["minv"], p["mcnt"]))
        e.var("mentry", _const(e, _blk(e, e.ld(S_ENTRY), B_SEGBASE), "me7"))
        e.var("mdone", _const(e, _DONE, "me8"))
        _store_state(e, _ins(e, "me9", "Select", uint, p["mlive"], p["mentry"], p["mdone"]))
        e.var("minvvar", _val(e, _blk(e, e.ld(S_ENTRY), B_PBASE), V_VAR))
        _ok(e, e.ne(p["minvvar"], NONE))
        _raw(e, "Store", p["minvvar"], p["minv"])
        _emit(e, "code", "Branch", label(1))
        _emit(e, "code", "Label", label(1))
        _emit(e, "code", "LoopMerge", label(5), label(4), 0)
        _emit(e, "code", "Branch", label(2))
        _emit(e, "code", "Label", label(2))
        e.var("mcur", _new_id(e, "mcu"))
        _emit(e, "code", "Load", uint, p["mcur"], state)
        _emit(e, "code", "SelectionMerge", label(3), 0)
        _word(e, SEC["code"], e.add(e.mul(e.add(3, e.mul(p["mtotal"], 2)), 1 << 16), OP["Switch"]))
        _word(e, SEC["code"], p["mcur"])
        _word(e, SEC["code"], label(6))
        e.for_("mc", 0, p["mtotal"], lambda: (_word(e, SEC["code"], p["mc"]), _word(e, SEC["code"], e.ld(e.add(p["mcases"], e.mul(p["mc"], 3))))))

        def case():
            at = e.add(p["mcases"], e.mul(p["mc"], 3))
            e.var("mca", at)
            _emit(e, "code", "Label", e.ld(p["mca"]))
            e.var("mbs", e.add(e.ld(SEC_AT + SEC["bodies"]), e.ld(e.add(p["mca"], 1))))
            e.for_("mw", 0, e.ld(e.add(p["mca"], 2)), lambda: _word(e, SEC["code"], e.ld(e.add(p["mbs"], p["mw"]))))
            _emit(e, "code", "Branch", label(3))

        e.for_("mc", 0, p["mtotal"], case)
        _emit(e, "code", "Label", label(6))
        _store_state(e, _const(e, _DONE, "mdd"))
        _emit(e, "code", "Branch", label(3))
        _emit(e, "code", "Label", label(3))
        _emit(e, "code", "Branch", label(4))
        _emit(e, "code", "Label", label(4))
        e.var("magain", _new_id(e, "mag"))
        e.var("mgoing", _new_id(e, "mgo"))
        _emit(e, "code", "Load", uint, p["magain"], state)
        _emit(e, "code", "INotEqual", boolean, p["mgoing"], p["magain"], _const(e, _DONE, "mdn"))
        _emit(e, "code", "BranchConditional", p["mgoing"], label(1), label(5))
        _emit(e, "code", "Label", label(5))
        _emit(e, "code", "Return")
        _emit(e, "code", "FunctionEnd")
        e.give(1)
    return _function((), build, tables)


def _spirv(tables):
    """``compile_spirv_kernel`` for function ``sf`` (the target was checked by the front end): 1 with the module in the
    image record, NONE when rejected or declined."""
    from xax_selfhost_general_image import IMAGE_AT

    def build(e: E):
        p = e.p
        e.st(S_F, p["sf"])
        _ok(e, e.eq(_kind(e, p["sf"]), int(Kind.FUNCTION)))  # a build entry is a function
        _call(e, "sp_entry", p["sf"])
        _call(e, "sp_index")
        _call(e, "sp_classify")
        e.var("pstack", e.alloc(e.mul(e.add(e.ld(S_V), 2), FRAME_W)))
        _ok(e, e.ne(p["pstack"], NONE))
        e.st(S_STACK, p["pstack"])
        _call(e, "sp_races")
        for slot, words in ((S_CONSTS, 2 << 16), (S_TRAPS, 2 * 64)):
            e.var("palloc", e.alloc(words))
            _ok(e, e.ne(p["palloc"], NONE))
            e.st(slot, p["palloc"])
        e.st(S_NCONSTS, 0)
        for section in range(len(SECTIONS)):
            e.var("psec", e.alloc(SEC_CAP))
            _ok(e, e.ne(p["psec"], NONE))
            e.st(SEC_AT + section, p["psec"])
            e.st(SEC_LEN + section, 0)
        _call(e, "sp_module")
        # The image record: the header and the sections, little-endian words, as the container bytes.
        e.var("pwords", 5)
        for name in SECTIONS[:-1]:
            e.set("pwords", e.add(p["pwords"], e.ld(SEC_LEN + SEC[name])))
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(IMAGE_AT + 2, e.mul(p["pwords"], 4))
        e.var("pout", IMAGE_AT + 3)
        e.var("phalf", 0)
        e.var("pheld", 0)  # a low half is held (a module word may be any 32-bit value)

        def put(word):
            e.var("pw", word)
            e.if_(e.eq(p["pheld"], 0), lambda: (e.set("phalf", p["pw"]), e.set("pheld", 1)), lambda: (
                e.st(p["pout"], e.add(p["phalf"], e.mul(p["pw"], 1 << 32))), e.set("pout", e.add(p["pout"], 1)), e.set("pheld", 0)))

        for word in (0x07230203, 0x00010300, 0):
            put(word)
        put(e.ld(S_NEXT))
        put(0)
        for name in SECTIONS[:-1]:
            section = SEC[name]
            e.for_("pq", 0, e.ld(SEC_LEN + section), lambda section=section: put(e.ld(e.add(e.ld(SEC_AT + section), p["pq"]))))
        e.if_(e.ne(p["pheld"], 0), lambda: (e.st(p["pout"], p["phalf"]), e.set("pout", e.add(p["pout"], 1))))
        for k in range(5):  # out, entry, members, imports, needed: none
            e.st(e.add(p["pout"], k), 0)
        e.give(1)
    return _function(("sf",), build, tables)


def add_spirv_functions(add, tables):
    for name, builder in (("sp_const", _sp_const), ("sp_value", _sp_value), ("sp_trap_case", _sp_trap_case), ("sp_entry", _sp_entry),
                          ("sp_index", _sp_index), ("sp_classify", _sp_classify), ("sp_step", _sp_step), ("sp_pointer", _sp_pointer),
                          ("sp_races", _sp_races), ("sp_check", _sp_check), ("sp_node", _sp_node), ("sp_term", _sp_term),
                          ("sp_module", _sp_module), ("spirv", _spirv)):
        add(name, builder(tables))


def spirv_with_xax(reader, function_cid: bytes, target_object, required: bool = False) -> bytes | None:
    """The module the general program writes for a verified store (``xax_selfhost_general_accel.accelerator_with_xax``'s
    shape)."""
    from xax_selfhost_general_accel import accelerator_with_xax

    return accelerator_with_xax(reader, function_cid, target_object, required)


def spirv_module(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s SPIR-V module: S15e.7b (ADR-321) decided by the XAX general program where it runs and decides
    (``"auto"``; ``"xax"`` requires it), else ``xax_spirv.compile_spirv_kernel``.  With ``XAX_GENERAL_FRONTEND_DIFF=1``
    the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_spirv import compile_spirv_kernel

    def reference() -> bytes:
        return compile_spirv_kernel(reader, function_cid, target_object.cid).artifact_bytes

    if frontend == "python":
        return reference()
    module = spirv_with_xax(reader, function_cid, target_object, required=frontend == "xax")
    if module is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15e.7b: the bootstrap rejects ({error.diagnostic.rule}) a module the XAX program wrote") from error
        if module != expected:
            raise AssertionError("S15e.7b SPIR-V modules disagree")
    return module
