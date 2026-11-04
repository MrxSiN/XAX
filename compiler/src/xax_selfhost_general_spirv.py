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

from xax_compiler import Kind
from xax_spirv import OP
import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import GLOBALS, G_PAY, _at, _call, _cid_words, _kind, _ok, _payload_uleb

SP = GLOBALS + 96
(S_F, S_G, S_STREAM, S_B, S_ENTRY, S_NB, S_BIND, S_BLK, S_NODE, S_NN, S_V, S_VAL, S_NEXT, S_CONSTS, S_NCONSTS, S_TRAPS, S_NTRAPS,
 S_NCASES, S_UINT, S_BOOL, S_ELEMPTR, S_BUFS, S_STATE, S_ACC, S_NACC, S_STACK, S_EDGES, S_NEDGES, S_PB, S_PO, S_CASES, S_INV,
 S_FIX, S_ONPATH, S_SP, S_VIS, S_RES, S_CASELAB, S_NEXTCASE, S_CUR, S_LABELS, S_BODY, S_BLOCKCASES, S_EXTENT) = (SP + k for k in range(44))
SEC_AT, SEC_LEN = SP + 48, SP + 56  # section buffers: caps, entry, modes, decorations, globals, code, then the case bodies
SECTIONS = ("caps", "entry", "modes", "decorations", "globals", "code", "bodies")
SEC = {name: index for index, name in enumerate(SECTIONS)}
SEC_CAP = 1 << 20
NODE_W = 8
VAL_W = 10
# V_KNOWN: the static pointer's binding + 1 (its offset in the ``S_PO`` table); V_ORIGIN: a parameter's block, or
# ``NODE_ORIGIN`` + a node result's node; V_INDEX: the parameter's index or the result's.
(V_TYPE, V_WIDTH, V_CONST, V_VALUE, V_VAR, V_KNOWN, V_RAW, V_ORIGIN, V_INDEX, V_SPARE) = range(VAL_W)
INCOMING = 64
# A pointer frame: value, state (0 start, 1 a parameter's incoming edges, 2 a node's base), edge cursor, whether a
# parameter was on the path when it started, waiting on a child, distinct incoming pairs, then the pairs.
(F_V, F_STATE, F_EDGE, F_VIS, F_WAIT, F_N) = range(6)
F_PAIRS = 6
FRAME_W = F_PAIRS + 2 * INCOMING


def _s(e: E, word):
    return e.ld(word)


def _rec(e: E, table_slot, index, width, field):
    return e.ld(e.add(e.add(e.ld(table_slot), e.mul(index, width)), field))


def _set_rec(e: E, table_slot, index, width, field, value):
    e.st(e.add(e.add(e.ld(table_slot), e.mul(index, width)), field), value)


def _node(e: E, k, field):
    return _rec(e, S_NODE, k, NODE_W, field)


def _set_val(e: E, v, field, value):
    _set_rec(e, S_VAL, v, VAL_W, field, value)


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


def _raw(e: E, opcode: str, *operands):
    _emit(e, None, opcode, *operands)


def _value(e: E, v, name: str):
    e.var(name, _call(e, "sp_value", v))
    return e.p[name]


# -- the entry contract and the graph's tables -----------------------------------------------------------------------


def _form(e: E, obj):
    at, length = _body_bytes(e, obj)
    return e.sel(e.both(e.eq(_kind(e, obj), int(Kind.TYPE)), e.ne(length, 0)), e.rd(at), 0)


def _bits(e: E, obj, name: str):
    """``name``: the width of ``bits<N>`` type ``obj`` (body form 1), else 0."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_at", e.add(_at(e, G_PAY, obj), 1))
    e.if_(e.eq(_form(e, obj), 1), lambda: e.set(name, _payload_uleb(e, f"{name}_at")))


def _reject_lowering(e: E, rule: str, expected, actual):
    """``_Lowering.reject``: ``XAX.SPIRV.LOWERING`` on the graph."""
    def write():
        D.text(e, "XAX.SPIRV.LOWERING")
        D.cid(e, _cid_words(e, e.ld(S_G)))
        D.text(e, rule)
        expected()
        actual()
    D.reject_unless(e, e.eq(1, 0), write)


# -- static pointers (``_Lowering.pointer``) as an explicit stack ----------------------------------------------------

def _frame(e: E, k):
    return e.add(e.ld(S_STACK), e.mul(k, FRAME_W))


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


# -- lowering (``_Lowering.lower_node``, ``lower_check``, ``lower_terminator``) ------------------------------------


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
