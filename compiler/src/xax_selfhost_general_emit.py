"""S12d (ADR-272): the general x86-64 backend's register-resident emission as XAX functions.

``xax_x86_64_regalloc.compile_register_resident`` after its analyses (S12c.2): per function a dry run of every block
(spill count and used callee-saved registers), the frame and epilogue, then the real run, the edge stubs, the shared
trap stubs and the lookup tables, and the branch fixups.  The functions are linked into ``xax_x86_64_general.xax``
(``add_emit_functions``); ``_emit`` runs after a function's analyses and writes its record to the view output: the
code bytes, the call fixups (offset and callee CID, or the SysV entry adapter's label), and the semantic ranges.

The bootstrap's state maps become tables: ``register_for`` is ``T_REG`` (value -> register) with its inverse in the
sixteen ``E_REGV`` words; ``spill_offset``, ``spill_id``, the block's use lists, edge use counts and edge hints are
per-value tables valid while their ``T_ESTAMP`` equals the invocation's stamp.  Labels are numbers: block ``k`` is
label ``k``; stubs, traps, tables and startup loops take fresh numbers.  The bootstrap lowers a rotated loop header
by recursion (``continue_to``); XAX functions cannot call themselves, so the copy is a second instance of the block
function built with ``copy=True`` (a copy never copies again).

Where the bootstrap fails (``fail``) the program declines the function (the record says "not decided" and the
bootstrap lowers it and raises); where the bootstrap returns None (another path lowers the function) the record says
so.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_ranges import G2_RNONE, G2_MARKS, G2_NMARKS, MARK_WORDS, _attribute, _block_at, _g2, _is_param, _node_at, _pos_block, _pos_index
from xax_selfhost_general_regalloc import (
    CALLEE_SAVED, CALLS, COMMUTATIVE, COPY, DIRECT_CALL, MEMORY, PINNABLE, PURE_BINARY, R_ALLOC, R_DYN_BASE, R_EDGE_SPILL_BASE, R_FUSED,
    R_BTAB, R_HAS_CALL, R_HOISTED, R_LOOPHDR, R_MEMB, R_NALLOC, R_NHOISTED, R_OWN_ELIDED, T_ALIAS, T_CL, T_ERASED, T_EUSE,
    T_ESTAMP, T_RW, T_FOLD_BASE, T_FOLD_DISP, T_HINT, T_HOME, T_MV_LOW, T_MV_MASK, T_MV_SUBJECT, T_NONZERO, T_PIN, T_PSLOT,
    T_REG, T_RMW, T_RMW_ERASED, T_SCALE, T_SCALE_BASE, T_SINK_AMOUNT, T_SINK_OPERAND, T_SPID, T_SPOFF, T_STACK, T_ULEN, T_ULIST,
    T_VT_SUBJECT, T_VT_TABLE, U_COUNT, U_LENGTHS, U_LISTS, U_VALUES, _callee_object, _constant, _cval, _eop, _in, _key, _ra, _rotatable,
    _rt, _set_ra, _set_rt, _width,
)
from xax_selfhost_general_view import (
    B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_POS, B_TERM, B_VALUES, BRANCH, CONDITIONAL, EDGE, G_BCOUNT,
    G_BENTRY, G_VCOUNT, G_VTYPE, N_GRAPH, N_NOPS, N_NRES, N_OPSAT, RETURN, _f, _operand, _output, _vf,
)
from xax_selfhost_views_backend import _FN, G_PAY, _at, _call, _cid_words, _g, _ok, _reference

RAX, RCX, RDX, RSP, RSI, RDI = 0, 1, 2, 4, 6, 7
SCRATCH = 11
ARGUMENT_REGISTERS = (1, 2, 8, 9)
SYSV_REGISTERS = (7, 6, 2, 1, 8, 9)
SYSCALL_REGISTERS = (7, 6, 2, 10, 8, 9)
LOOP_ALIGNMENT = 16
FAR = 1 << 30
DYNAMIC_FORMAT = 6


def reject_at(e: E, write):
    """S12f.2 (ADR-278): the bootstrap fails here.  When every earlier function's code is the program's (``I_OK``), the
    bootstrap reached this point too: write its diagnostic (``write()`` emits the code, entity, rule, expected, and
    actual) and mark the program rejected (``E_FAIL``); otherwise an earlier function may have failed first, and the
    program declines.  Gives NONE either way."""
    import xax_selfhost_diagnostics as D
    from xax_selfhost_general_image import I_OK

    def record():
        D.begin(e)
        write()
        _se(e, E_FAIL, 1)
        e.st(0, D.REJECT)  # the status now, so a caller's decline (NONE) cannot leave it undecided

    e.if_(e.both(e.ne(_ra(e, I_OK), 0), e.eq(_e(e, E_FAIL), 0)), record)
    e.give(NONE)


def graph_cid_words(e: E, f):
    """The CID words of function ``f``'s graph (``_decode_function_interface``: a group member's own graph)."""
    return _cid_words(e, e.ld(_call(e, "interface", f)))


def write_dynamic_profile(e: E):
    """``require_sysv_profile``'s diagnostic for the current function (the target is a Linux ELF profile)."""
    import xax_selfhost_diagnostics as D
    from xax_selfhost_x86_64_general import G_TFMT, LINUX_ABI

    D.text(e, "XAX.NATIVE.FOREIGN_ABI")
    D.cid(e, graph_cid_words(e, _e(e, E_F)))
    D.text(e, "SYSV-C-REQUIRES-DYNAMIC-PROFILE")
    for second in (DYNAMIC_FORMAT, _g(e, G_TFMT)):
        D.put(e, D.T_LIST)
        D.put(e, 2)
        D.integer(e, LINUX_ABI)
        D.integer(e, second)
NOPS = (
    b"\x90", b"\x66\x90", b"\x0f\x1f\x00", b"\x0f\x1f\x40\x00", b"\x0f\x1f\x44\x00\x00",
    b"\x66\x0f\x1f\x44\x00\x00", b"\x0f\x1f\x80\x00\x00\x00\x00",
    b"\x0f\x1f\x84\x00\x00\x00\x00\x00", b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
)
GROUP1 = {Operation.ADD_WRAP: 0, Operation.BIT_OR: 1, Operation.BIT_AND: 4, Operation.SUB_WRAP: 5, Operation.BIT_XOR: 6}
ARITHMETIC = {Operation.ADD_WRAP: 0x01, Operation.SUB_WRAP: 0x29, Operation.BIT_XOR: 0x31, Operation.BIT_AND: 0x21, Operation.BIT_OR: 0x09}
SETCC = {IntCompare.EQ: 0x94, IntCompare.NE: 0x95, IntCompare.ULT: 0x92, IntCompare.ULE: 0x96, IntCompare.UGT: 0x97, IntCompare.UGE: 0x93,
         IntCompare.SLT: 0x9C, IntCompare.SLE: 0x9E, IntCompare.SGT: 0x9F, IntCompare.SGE: 0x9D}
JUMP_IF_FALSE = {IntCompare.EQ: 0x85, IntCompare.NE: 0x84, IntCompare.ULT: 0x83, IntCompare.ULE: 0x87, IntCompare.UGT: 0x86,
                 IntCompare.UGE: 0x82, IntCompare.SLT: 0x8D, IntCompare.SLE: 0x8F, IntCompare.SGT: 0x8E, IntCompare.SGE: 0x8C}
INTEGER_DIVIDE_BY_ZERO = 2
NULL_ON_ERROR = b"\x48\x3d\x01\xf0\xff\xff\x72\x02\x31\xc0"  # cmp rax, -4095; jb +2; xor eax, eax
STARTUP_NAMES = (b"argc", b"arg_length", b"arg_copy", b"envc", b"env_length", b"env_copy", b"auxv_value")
STARTUP_ABI = b"linux-x86_64-startup-v1"
SYSCALL_HEADER = 3

# Emission state (``_ra`` slots from E_BASE on).
E_BASE = 100
(E_CODE, E_CLEN, E_CAP_ON, E_CAPBUF, E_CAPLEN, E_REAL, E_LABELS, E_NLABELS, E_BRANCHES, E_NBRANCHES, E_CALLS, E_NCALLS, E_RANGES,
 E_NRANGES, E_STUBS, E_NSTUBS, E_TRAPS, E_NTRAPS, E_TABLES, E_NTABLES, E_CLOSED, E_USED, E_STAMP, E_FREE, E_NFREE, E_NEXT, E_MAX,
 E_CHECKED, E_NCHECKED, E_CALLPOS, E_NCALLPOS, E_HINT, E_BI, E_FOLLOW, E_EPI, E_EPILEN, E_FRAME, E_LOCK, E_LOCW, E_MOVES, E_NMOVES,
 E_ARGS, E_REGS, E_NARGS, E_PROCESS, E_LIVE, E_RECORD, E_DELAYED, E_NDELAYED, E_PAIRS, E_NPAIRS, E_F, E_FAIL, E_TRAPSEC) = range(E_BASE, E_BASE + 54)
E_REGV = 192  # sixteen words: the value in each register, NONE when free
assert E_REGV + 16 <= 256 and E_FAIL < E_REGV
LOC_REG, LOC_CONST, LOC_STACK, LOC_SPILL = range(4)
# Capacities (words).
CODE_CAP = 1 << 20
CAPTURE_CAP = 1 << 14
LABEL_CAP = 1 << 16
BRANCH_CAP = 1 << 16
CALL_CAP = 1 << 14
RANGE_CAP = 1 << 16
STUB_CAP = 1 << 14
TRAP_CAP = 64
TABLE_CAP = 1 << 10
CHECK_CAP = 1 << 14
MOVE_CAP = 64
INELIGIBLE = NONE - 2  # the bootstrap's ``return -1`` (the function is lowered by another path)


def _e(e: E, slot):
    return _ra(e, slot)


def _se(e: E, slot, value):
    _set_ra(e, slot, value)


def _regv(e: E, register):
    return _ra(e, e.add(E_REGV, register))


def _set_regv(e: E, register, value):
    _set_ra(e, e.add(E_REGV, register), value)


def _sget(e: E, table: int, value, default):
    """A stamped per-value field: its word while the value's stamp is the invocation's, else ``default``."""
    return e.sel(e.eq(_rt(e, T_ESTAMP, value), _e(e, E_STAMP)), _rt(e, table, value), default)


def _touch(e: E, value):
    """Make ``value``'s stamped fields current (absent when they were stale)."""
    p = e.p
    e.var("to_v", value)

    def fresh():
        _set_rt(e, T_ESTAMP, p["to_v"], _e(e, E_STAMP))
        for table, default in ((T_SPOFF, NONE), (T_SPID, NONE), (T_ULEN, 0), (T_ULIST, 0), (T_HINT, NONE), (T_EUSE, 0)):
            _set_rt(e, table, p["to_v"], default)

    e.if_(e.ne(_rt(e, T_ESTAMP, p["to_v"]), _e(e, E_STAMP)), fresh)


def _sset(e: E, table: int, value, word):
    _touch(e, value)
    _set_rt(e, table, e.p["to_v"], word)


# -- bytes -------------------------------------------------------------------------------------------------------

def _store_bytes(e: E, at, word, n):
    p = e.p
    e.var("sb_at", at)
    e.var("sb_w", word)
    e.for_("sb_k", 0, n, lambda: (e.st(e.add(p["sb_at"], p["sb_k"]), e.and_(p["sb_w"], 255)), e.set("sb_w", e.udiv(p["sb_w"], 256))))


def _bytes_fn(tables, direct: bool):
    """``emit`` (``direct`` False: into the capture while one is open, else the code in the real run) or the
    assembler's own ``emit`` (``direct``: the code in the real run only) of the ``n`` low bytes of ``w``."""
    def build(e: E):
        p = e.p

        def capture():
            e.var("by_len", _e(e, E_CAPLEN))
            _ok(e, e.le(e.add(p["by_len"], p["n"]), CAPTURE_CAP))
            _store_bytes(e, e.add(_e(e, E_CAPBUF), p["by_len"]), p["w"], p["n"])
            _se(e, E_CAPLEN, e.add(p["by_len"], p["n"]))

        def code():
            e.var("by_len", _e(e, E_CLEN))
            _ok(e, e.le(e.add(p["by_len"], p["n"]), CODE_CAP))
            _store_bytes(e, e.add(_e(e, E_CODE), p["by_len"]), p["w"], p["n"])
            _se(e, E_CLEN, e.add(p["by_len"], p["n"]))

        if direct:
            e.if_(e.ne(_e(e, E_REAL), 0), code)
        else:
            e.if_(e.ne(_e(e, E_CAP_ON), 0), capture, lambda: e.if_(e.ne(_e(e, E_REAL), 0), code))
        e.give(1)
    return _function(("w", "n"), build, tables)


def _b(e: E, data: bytes, direct: bool = False):
    """Emit literal bytes."""
    for start in range(0, len(data), 8):
        chunk = data[start:start + 8]
        _call(e, "ab" if direct else "eb", int.from_bytes(chunk, "little"), len(chunk))


def _bx(e: E, word, n, direct: bool = False):
    _call(e, "ab" if direct else "eb", word, n)


def _hi(e: E, register):
    """1 when the register needs a REX extension bit."""
    return e.flag(e.le(8, register))


def _low3(e: E, register):
    return e.and_(register, 7)


# -- encoders (``xax_x86_64`` and ``xax_x86_64_regalloc``) ------------------------------------------------------

def _rex_fn(tables):
    """``_rex``: REX with W, R, X, B from ``w`` and the registers; omitted when it is 0x40 unless ``force``."""
    def build(e: E):
        p = e.p
        value = e.add(e.add(e.add(e.add(0x40, e.mul(e.flag(e.ne(p["w"], 0)), 8)), e.mul(_hi(e, p["r"]), 4)), e.mul(_hi(e, p["x"]), 2)), _hi(e, p["b"]))
        e.var("rx_v", value)
        e.if_(e.either(e.ne(p["rx_v"], 0x40), e.ne(p["force"], 0)), lambda: _bx(e, p["rx_v"], 1))
        e.give(1)
    return _function(("w", "r", "x", "b", "force"), build, tables)


def _rex(e: E, w, r, x, b, force=0):
    _call(e, "rex", w, r, x, b, force)


def _small(e: E, offset):
    """-128 <= offset < 128 (two's complement words)."""
    return e.lt(e.add(offset, 128), 256)


def _modrm_base_fn(tables):
    """``_modrm_base``: mod 01 (disp8) or 10 (disp32), an SIB for an rsp/r12 base."""
    def build(e: E):
        p = e.p
        e.var("mb_small", e.flag(_small(e, p["off"])))
        head = e.sel(e.ne(p["mb_small"], 0), 0x40, 0x80)
        _bx(e, e.add(e.add(head, e.mul(_low3(e, p["reg"]), 8)), _low3(e, p["base"])), 1)
        e.if_(e.eq(_low3(e, p["base"]), 4), lambda: _bx(e, 0x24, 1))
        e.if_(e.ne(p["mb_small"], 0), lambda: _bx(e, e.and_(p["off"], 0xFF), 1), lambda: _bx(e, e.and_(p["off"], 0xFFFFFFFF), 4))
        e.give(1)
    return _function(("reg", "base", "off"), build, tables)


def _modrm(e: E, reg, base, offset):
    _call(e, "modrm_base", reg, base, offset)


def _mov_fn(tables):
    """``_move_register(dst, src, width)``: 64-bit for width 64, else 32-bit (which zero-extends)."""
    def build(e: E):
        p = e.p
        _ok(e, e.both(e.ne(p["width"], 0), e.le(p["width"], 64)))
        _rex(e, e.flag(e.eq(p["width"], 64)), p["src"], 0, p["dst"])
        _bx(e, e.add(0x89, e.mul(e.add(e.add(0xC0, e.mul(_low3(e, p["src"]), 8)), _low3(e, p["dst"])), 256)), 2)
        e.give(1)
    return _function(("dst", "src", "width"), build, tables)


def _mov(e: E, dst, src, width=64):
    _call(e, "mov", dst, src, width)


def _movabs(e: E, register, value):
    """``_immediate``: ``mov r64, imm64``."""
    _bx(e, e.add(e.add(0x48, _hi(e, register)), e.mul(e.add(0xB8, _low3(e, register)), 256)), 2)
    _bx(e, value, 8)


def _zero32(e: E, register):
    _rex(e, 0, register, 0, register)
    _bx(e, e.add(0x31, e.mul(e.add(e.add(0xC0, e.mul(_low3(e, register), 8)), _low3(e, register)), 256)), 2)


def _lea(e: E, register, base, offset):
    _rex(e, 1, register, 0, base)
    _bx(e, 0x8D, 1)
    _modrm(e, register, base, offset)


def _load_exact_fn(tables):
    def build(e: E):
        p = e.p
        _rex(e, e.flag(e.eq(p["size"], 8)), p["reg"], 0, p["base"])
        e.if_(e.lt(p["size"], 4), lambda: _bx(e, e.sel(e.eq(p["size"], 1), 0xB60F, 0xB70F), 2), lambda: _bx(e, 0x8B, 1))
        _modrm(e, p["reg"], p["base"], p["off"])
        e.give(1)
    return _function(("reg", "base", "off", "size"), build, tables)


def _store_exact_fn(tables):
    def build(e: E):
        p = e.p

        def byte():
            _rex(e, 0, p["reg"], 0, p["base"], e.flag(e.both(e.le(4, p["reg"]), e.lt(p["reg"], 8))))
            _bx(e, 0x88, 1)

        def wider():
            e.if_(e.eq(p["size"], 2), lambda: _bx(e, 0x66, 1))
            _rex(e, e.flag(e.eq(p["size"], 8)), p["reg"], 0, p["base"])
            _bx(e, 0x89, 1)

        e.if_(e.eq(p["size"], 1), byte, wider)
        _modrm(e, p["reg"], p["base"], p["off"])
        e.give(1)
    return _function(("reg", "base", "off", "size"), build, tables)


def _frame_access_fn(tables):
    """``_load``/``_store`` (``opcode`` 0x8B/0x89) of a frame slot ``[rsp + off]``: 1/2-byte accesses as the exact
    forms, 4/8-byte ones as ``_memory_instruction`` (declined outside 0..2^31-1)."""
    def build(e: E):
        p = e.p

        def exact():
            e.if_(e.eq(p["opcode"], 0x8B), lambda: _call(e, "load_exact", p["reg"], RSP, p["off"], p["width"]),
                  lambda: _call(e, "store_exact", p["reg"], RSP, p["off"], p["width"]))

        def memory():
            _ok(e, e.both(e.either(e.eq(p["width"], 4), e.eq(p["width"], 8)), e.lt(p["off"], 1 << 31)))
            e.var("fa_rex", e.add(e.add(0x40, e.mul(e.flag(e.eq(p["width"], 8)), 8)), e.mul(_hi(e, p["reg"]), 4)))
            e.if_(e.ne(p["fa_rex"], 0x40), lambda: _bx(e, p["fa_rex"], 1))
            e.if_(e.lt(p["off"], 128), lambda: (
                _bx(e, e.add(e.add(p["opcode"], e.mul(e.add(0x44, e.mul(_low3(e, p["reg"]), 8)), 256)), e.add(0x240000, e.mul(p["off"], 1 << 24))), 4)),
                lambda: (_bx(e, e.add(e.add(p["opcode"], e.mul(e.add(0x84, e.mul(_low3(e, p["reg"]), 8)), 256)), 0x240000), 3),
                         _bx(e, p["off"], 4)))

        e.if_(e.lt(p["width"], 4), exact, memory)
        e.give(1)
    return _function(("opcode", "reg", "off", "width"), build, tables)


def _load(e: E, register, offset, width):
    _call(e, "frame_access", 0x8B, register, offset, width)


def _store(e: E, register, offset, width):
    _call(e, "frame_access", 0x89, register, offset, width)


def _and_imm(e: E, register, value, wide):
    """``_and_immediate`` (declined above 32 bits, where the bootstrap fails: NATIVE-AND-IMM32)."""
    _ok(e, e.lt(value, 1 << 32))
    e.var("ai_rex", e.add(e.add(0x40, e.mul(wide, 8)), _hi(e, register)))
    e.if_(e.ne(e.p["ai_rex"], 0x40), lambda: _bx(e, e.p["ai_rex"], 1))
    _bx(e, e.add(0x81, e.mul(e.add(0xE0, _low3(e, register)), 256)), 2)
    _bx(e, value, 4)


def _arith_fn(tables):
    """``_register_arithmetic(op, dst, src, width)`` (width 32 or 64)."""
    def build(e: E):
        p = e.p
        wide = e.flag(e.eq(p["width"], 64))
        e.var("ar_w", wide)

        def mul():
            e.var("ar_rex", e.add(e.add(e.add(0x40, e.mul(p["ar_w"], 8)), e.mul(_hi(e, p["dst"]), 4)), _hi(e, p["src"])))
            e.if_(e.ne(p["ar_rex"], 0x40), lambda: _bx(e, p["ar_rex"], 1))
            _bx(e, e.add(0xAF0F, e.mul(e.add(e.add(0xC0, e.mul(_low3(e, p["dst"]), 8)), _low3(e, p["src"])), 1 << 16)), 3)

        def other():
            opcode = e.c(0)
            for operation, code in ARITHMETIC.items():
                opcode = e.add(opcode, e.mul(e.flag(e.eq(p["aop"], int(operation))), code))
            e.var("ar_op", opcode)
            _ok(e, e.ne(p["ar_op"], 0))
            e.var("ar_rex", e.add(e.add(e.add(0x40, e.mul(p["ar_w"], 8)), e.mul(_hi(e, p["src"]), 4)), _hi(e, p["dst"])))
            e.if_(e.ne(p["ar_rex"], 0x40), lambda: _bx(e, p["ar_rex"], 1))
            _bx(e, e.add(p["ar_op"], e.mul(e.add(e.add(0xC0, e.mul(_low3(e, p["src"]), 8)), _low3(e, p["dst"])), 256)), 2)

        e.if_(e.eq(p["aop"], int(Operation.MUL_WRAP)), mul, other)
        e.give(1)
    return _function(("aop", "dst", "src", "width"), build, tables)


def _test(e: E, register, width):
    """``_test_register``."""
    e.var("tr_rex", e.add(e.add(e.add(0x40, e.mul(e.flag(e.eq(width, 64)), 8)), e.mul(_hi(e, register), 4)), _hi(e, register)))
    e.if_(e.ne(e.p["tr_rex"], 0x40), lambda: _bx(e, e.p["tr_rex"], 1))
    _bx(e, e.add(0x85, e.mul(e.add(e.add(0xC0, e.mul(_low3(e, register), 8)), _low3(e, register)), 256)), 2)


def _cmp_rr(e: E, left, right, width):
    """``_cmp_registers``."""
    e.var("cr_rex", e.add(e.add(e.add(0x40, e.mul(e.flag(e.eq(width, 64)), 8)), e.mul(_hi(e, right), 4)), _hi(e, left)))
    e.if_(e.ne(e.p["cr_rex"], 0x40), lambda: _bx(e, e.p["cr_rex"], 1))
    _bx(e, e.add(0x39, e.mul(e.add(e.add(0xC0, e.mul(_low3(e, right), 8)), _low3(e, left)), 256)), 2)


def _setcc_fn(tables):
    """``_setcc_register(kind, reg)``; with ``full`` 0 only its setcc part (the bootstrap slices the movzx off)."""
    def build(e: E):
        p = e.p
        code = e.c(0)
        for kind, opcode in SETCC.items():
            code = e.add(code, e.mul(e.flag(e.eq(p["kind"], int(kind))), opcode))
        e.var("sc_op", code)
        _ok(e, e.ne(p["sc_op"], 0))
        e.var("sc_high", e.flag(e.le(4, p["reg"])))
        e.if_(e.ne(p["sc_high"], 0), lambda: _bx(e, e.add(0x40, _hi(e, p["reg"])), 1))
        _bx(e, e.add(e.add(0x0F, e.mul(p["sc_op"], 256)), e.mul(e.add(0xC0, _low3(e, p["reg"])), 1 << 16)), 3)

        def extend():
            e.if_(e.ne(p["sc_high"], 0), lambda: _bx(e, e.add(e.add(0x40, e.mul(_hi(e, p["reg"]), 4)), _hi(e, p["reg"])), 1))
            _bx(e, e.add(0xB60F, e.mul(e.add(e.add(0xC0, e.mul(_low3(e, p["reg"]), 8)), _low3(e, p["reg"])), 1 << 16)), 3)

        e.if_(e.ne(p["full"], 0), extend)
        e.give(1)
    return _function(("kind", "reg", "full"), build, tables)


def _load_constant_fn(tables):
    """``_load_constant``: xor for 0, ``mov r32, imm32`` below 2^32, else ``mov r64, imm64``."""
    def build(e: E):
        p = e.p

        def imm32():
            _rex(e, 0, 0, 0, p["reg"])
            _bx(e, e.add(0xB8, _low3(e, p["reg"])), 1)
            _bx(e, p["value"], 4)

        e.if_(e.eq(p["value"], 0), lambda: _zero32(e, p["reg"]), lambda: e.if_(e.lt(p["value"], 1 << 32), imm32, lambda: _movabs(e, p["reg"], p["value"])))
        e.give(1)
    return _function(("reg", "value"), build, tables)


def _load_constant(e: E, register, value):
    _call(e, "load_constant", register, value)


def _group1_fn(tables):
    """``_group1_immediate``: ``digit`` 0 add, 1 or, 4 and, 5 sub, 6 xor, 7 cmp; imm8 for 0..127."""
    def build(e: E):
        p = e.p
        _rex(e, e.flag(e.lt(32, p["width"])), 0, 0, p["reg"])
        modrm = e.add(e.add(0xC0, e.mul(p["digit"], 8)), _low3(e, p["reg"]))
        e.var("g1_m", modrm)
        e.if_(e.lt(p["value"], 128), lambda: _bx(e, e.add(e.add(0x83, e.mul(p["g1_m"], 256)), e.mul(p["value"], 1 << 16)), 3),
              lambda: (_bx(e, e.add(0x81, e.mul(p["g1_m"], 256)), 2), _bx(e, e.and_(p["value"], 0xFFFFFFFF), 4)))
        e.give(1)
    return _function(("digit", "reg", "value", "width"), build, tables)


def _group1(e: E, digit, register, value, width):
    _call(e, "group1", digit, register, value, width)


def _compare_immediate(e: E, register, value):
    """``_compare_immediate`` (64-bit cmp; declined outside 0..2^31-1)."""
    _ok(e, e.lt(value, 1 << 31))
    _group1(e, 7, register, value, 64)


def _scaled_fn(tables):
    """``_scaled_access(opcode (``on`` bytes of ``oc``), reg, base, index, scale, width, force_rex)``."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(p["width"], 2), lambda: _bx(e, 0x66, 1))
        rex = e.add(e.add(e.add(e.add(0x40, e.mul(e.flag(e.eq(p["width"], 8)), 8)), e.mul(_hi(e, p["reg"]), 4)), e.mul(_hi(e, p["index"]), 2)), _hi(e, p["base"]))
        e.var("sa_rex", rex)
        e.if_(e.either(e.ne(p["sa_rex"], 0x40), e.ne(p["force"], 0)), lambda: _bx(e, p["sa_rex"], 1))
        _bx(e, p["oc"], p["on"])
        log = e.add(e.add(e.flag(e.le(2, p["scale"])), e.flag(e.le(4, p["scale"]))), e.flag(e.le(8, p["scale"])))
        sib = e.add(e.add(e.mul(log, 64), e.mul(_low3(e, p["index"]), 8)), _low3(e, p["base"]))
        e.var("sa_sib", sib)
        reg8 = e.mul(_low3(e, p["reg"]), 8)
        e.var("sa_r", reg8)
        e.if_(e.eq(_low3(e, p["base"]), 5), lambda: _bx(e, e.add(e.add(0x44, p["sa_r"]), e.mul(p["sa_sib"], 256)), 3),
              lambda: _bx(e, e.add(e.add(0x04, p["sa_r"]), e.mul(p["sa_sib"], 256)), 2))
        e.give(1)
    return _function(("oc", "on", "reg", "base", "index", "scale", "width", "force"), build, tables)


def _scaled(e: E, opcode: int, opcode_length: int, register, base, index, scale, width, force=0):
    _call(e, "scaled", opcode, opcode_length, register, base, index, scale, width, force)


def _scaled_load(e: E, register, base, index, scale, size):
    """``_scaled_load`` (zero-extending)."""
    e.if_(e.lt(size, 4), lambda: _call(e, "scaled", e.sel(e.eq(size, 1), 0xB60F, 0xB70F), 2, register, base, index, scale, 4, 0),
          lambda: _scaled(e, 0x8B, 1, register, base, index, scale, size))


def _scaled_store(e: E, register, base, index, scale, size):
    e.if_(e.eq(size, 1), lambda: _scaled(e, 0x88, 1, register, base, index, scale, 1, e.flag(e.both(e.le(4, register), e.lt(register, 8)))),
          lambda: _scaled(e, 0x89, 1, register, base, index, scale, size))


def _memop_fn(tables):
    """``_memory_operand_instruction(opcode, reg, base, index (NONE: none), scale, disp, wide)``."""
    def build(e: E):
        p = e.p
        e.var("mo_hasx", e.flag(e.ne(p["index"], NONE)))
        index = e.sel(e.ne(p["mo_hasx"], 0), p["index"], 0)
        e.var("mo_x", index)
        rex = e.add(e.add(e.add(e.add(0x40, e.mul(p["wide"], 8)), e.mul(_hi(e, p["reg"]), 4)), e.mul(_hi(e, p["mo_x"]), 2)), _hi(e, p["base"]))
        e.var("mo_rex", rex)
        e.if_(e.ne(p["mo_rex"], 0x40), lambda: _bx(e, p["mo_rex"], 1))
        _bx(e, p["oc"], 1)
        e.var("mo_mod", 0x80)
        e.var("mo_tail", 4)
        e.if_(e.both(e.eq(p["disp"], 0), e.ne(_low3(e, p["base"]), 5)), lambda: (e.set("mo_mod", 0), e.set("mo_tail", 0)),
              lambda: e.if_(_small(e, p["disp"]), lambda: (e.set("mo_mod", 0x40), e.set("mo_tail", 1))))
        reg8 = e.mul(_low3(e, p["reg"]), 8)
        e.var("mo_r", reg8)

        def plain():
            _bx(e, e.add(e.add(p["mo_mod"], p["mo_r"]), _low3(e, p["base"])), 1)

        def with_sib():
            log = e.add(e.add(e.flag(e.le(2, p["scale"])), e.flag(e.le(4, p["scale"]))), e.flag(e.le(8, p["scale"])))
            sib = e.sel(e.ne(p["mo_hasx"], 0), e.add(e.add(e.mul(log, 64), e.mul(_low3(e, p["mo_x"]), 8)), _low3(e, p["base"])), 0x24)
            e.var("mo_sib", sib)
            _bx(e, e.add(e.add(e.add(p["mo_mod"], p["mo_r"]), 4), e.mul(p["mo_sib"], 256)), 2)

        e.if_(e.both(e.eq(p["mo_hasx"], 0), e.ne(_low3(e, p["base"]), 4)), plain, with_sib)
        e.if_(e.eq(p["mo_tail"], 1), lambda: _bx(e, e.and_(p["disp"], 0xFF), 1),
              lambda: e.if_(e.eq(p["mo_tail"], 4), lambda: _bx(e, e.and_(p["disp"], 0xFFFFFFFF), 4)))
        e.give(1)
    return _function(("oc", "reg", "base", "index", "scale", "disp", "wide"), build, tables)


def _member_bit_test(e: E, register, low, mask, temporary):
    """``_member_bit_test`` (value form: the clamp to bit 63 included)."""
    _lea_r11d(e, register, low)
    _b(e, b"\x41\x83\xfb\x3f")  # cmp r11d, 63
    _rex(e, 0, 0, 0, temporary)
    _bx(e, e.add(0xB8, _low3(e, temporary)), 1)
    _bx(e, 63, 4)
    _bx(e, e.add(e.add(e.add(0x44, _hi(e, temporary)), 0x470F00), e.mul(e.add(0xD8, _low3(e, temporary)), 1 << 24)), 4)  # cmova r11d, tmp
    _load_constant(e, temporary, mask)
    _bt(e, temporary)


def _lea_r11d(e: E, register, low):
    """``lea r11d, [x - low]``."""
    _bx(e, e.add(e.add(e.add(0x44, _hi(e, register)), 0x8D00), e.mul(e.add(0x98, _low3(e, register)), 1 << 16)), 3)
    e.if_(e.eq(_low3(e, register), 4), lambda: _bx(e, 0x24, 1))
    _bx(e, e.and_(e.sub(0, low), 0xFFFFFFFF), 4)


def _bt(e: E, temporary):
    """``bt tmp, r11``."""
    _bx(e, e.add(e.add(e.add(0x4C, _hi(e, temporary)), 0xA30F00), e.mul(e.add(0xD8, _low3(e, temporary)), 1 << 24)), 4)


def _shift_imm(e: E, left: int, register, amount, width):
    """``_shift_immediate``."""
    _rex(e, e.flag(e.lt(32, width)), 0, 0, register)
    _bx(e, e.add(e.add(0xC1, e.mul(e.add(0xC0 | ((4 if left else 5) << 3), _low3(e, register)), 256)), e.mul(amount, 1 << 16)), 3)


def _imul_imm(e: E, destination, source, value, width):
    """``_imul_immediate``."""
    _rex(e, e.flag(e.lt(32, width)), destination, 0, source)
    modrm = e.add(e.add(0xC0, e.mul(_low3(e, destination), 8)), _low3(e, source))
    e.var("im_m", modrm)
    e.if_(e.lt(value, 128), lambda: _bx(e, e.add(e.add(0x6B, e.mul(e.p["im_m"], 256)), e.mul(value, 1 << 16)), 3),
          lambda: (_bx(e, e.add(0x69, e.mul(e.p["im_m"], 256)), 2), _bx(e, value, 4)))


def _push(e: E, register, direct=True):
    e.if_(e.le(8, register), lambda: _bx(e, 0x41, 1, direct))
    _bx(e, e.add(0x50, _low3(e, register)), 1, direct)


def _pop(e: E, register):
    e.if_(e.le(8, register), lambda: _bx(e, 0x41, 1, True))
    _bx(e, e.add(0x58, _low3(e, register)), 1, True)


# -- allocation state (``lower_block``'s closures) --------------------------------------------------------------

def _bit(e: E, register):
    """``1 << register`` for a register 0..15."""
    return _ra(e, e.add(E_POW, register))


E_POW = E_REGV - 16  # sixteen words: the powers of two


def _excluded(e: E, mask, register):
    return e.ne(e.and_(mask, _bit(e, register)), 0)


def _wbytes(e: E, value):
    """``width_bytes``: 8 above 32 bits, else 4."""
    return e.sel(e.lt(32, _width(e, value)), 8, 4)


def _pinned(e: E, value):
    return _rt(e, T_PIN, value)


def _last_use(e: E, value):
    """The value's last use in the block, NONE when it has none."""
    length = _sget(e, T_ULEN, value, 0)
    e.var("lu_n", length)
    e.var("lu_out", NONE)
    e.if_(e.ne(e.p["lu_n"], 0), lambda: e.set("lu_out", e.ld(e.add(_rt(e, T_ULIST, value), e.sub(e.p["lu_n"], 1)))))
    return e.p["lu_out"]


def _next_use_fn(tables):
    """``next_use(value, position)``: its first use after ``position``, else 2^30."""
    def build(e: E):
        p = e.p
        e.var("nu_n", _sget(e, T_ULEN, p["v"], 0))
        e.var("nu_list", _rt(e, T_ULIST, p["v"]))
        e.var("nu_out", FAR)
        e.var("nu_k", 0)

        def step():
            e.var("nu_x", e.ld(e.add(p["nu_list"], p["nu_k"])))
            # ``pos`` 2^64-1 is -1 (``next_use(value, node_index - 1)`` at node 0).
            e.if_(e.either(e.eq(p["pos"], (1 << 64) - 1), e.lt(p["pos"], p["nu_x"])), lambda: (e.set("nu_out", p["nu_x"]), e.set("nu_k", p["nu_n"])), lambda: e.set("nu_k", e.add(p["nu_k"], 1)))

        e.while_(lambda: e.lt(p["nu_k"], p["nu_n"]), step)
        e.give(p["nu_out"])
    return _function(("v", "pos"), build, tables)


def _bind_fn(tables):
    def build(e: E):
        p = e.p
        e.var("bd_old", _regv(e, p["r"]))
        e.if_(e.both(e.ne(p["bd_old"], NONE), e.ne(p["bd_old"], p["v"])), lambda: _set_rt(e, T_REG, p["bd_old"], NONE))
        e.var("bd_oldr", _rt(e, T_REG, p["v"]))
        e.if_(e.both(e.ne(p["bd_oldr"], NONE), e.ne(p["bd_oldr"], p["r"])), lambda: _set_regv(e, p["bd_oldr"], NONE))
        _set_rt(e, T_REG, p["v"], p["r"])
        _set_regv(e, p["r"], p["v"])
        e.var("bd_used", _e(e, E_USED))
        e.if_(e.eq(e.and_(p["bd_used"], _bit(e, p["r"])), 0), lambda: _se(e, E_USED, e.add(p["bd_used"], _bit(e, p["r"]))))
        e.give(1)
    return _function(("v", "r"), build, tables)


def _unbind_fn(tables):
    def build(e: E):
        p = e.p
        e.var("ub_r", _rt(e, T_REG, p["v"]))

        def bound():
            _set_rt(e, T_REG, p["v"], NONE)
            e.if_(e.eq(_regv(e, p["ub_r"]), p["v"]), lambda: _set_regv(e, p["ub_r"], NONE))

        e.if_(e.ne(p["ub_r"], NONE), bound)
        e.give(1)
    return _function(("v",), build, tables)


def _release_fn(tables):
    """``release``: unbind; a dynamic spill slot returns to the free list."""
    def build(e: E):
        p = e.p
        _call(e, "unbind", p["v"])
        e.var("rl_slot", _sget(e, T_SPID, p["v"], NONE))

        def free():
            _sset(e, T_SPID, p["v"], NONE)
            _set_rt(e, T_SPOFF, p["v"], NONE)
            e.var("rl_n", _e(e, E_NFREE))
            e.st(e.add(_e(e, E_FREE), p["rl_n"]), p["rl_slot"])
            _se(e, E_NFREE, e.add(p["rl_n"], 1))

        e.if_(e.ne(p["rl_slot"], NONE), free)
        e.give(1)
    return _function(("v",), build, tables)


def _remat(e: E, value):
    """Rematerialized on demand, never stored: a constant, a pinned value, or a stack address."""
    return e.either(_constant(e, value), e.ne(_pinned(e, value), NONE), e.ne(_rt(e, T_STACK, value), NONE))


def _spill_fn(tables):
    def build(e: E):
        p = e.p
        e.var("sp_r", _rt(e, T_REG, p["v"]))
        e.if_(_remat(e, p["v"]), lambda: (e.if_(e.eq(p["keep"], 0), lambda: _call(e, "unbind", p["v"])), e.give(1)))

        def allocate():
            e.var("sp_n", _e(e, E_NFREE))

            def reuse():
                e.var("sp_best", 0)
                e.for_("sp_k", 1, p["sp_n"], lambda: e.if_(e.lt(e.ld(e.add(_e(e, E_FREE), p["sp_k"])), e.ld(e.add(_e(e, E_FREE), p["sp_best"]))),
                                                            lambda: e.set("sp_best", p["sp_k"])))
                e.var("sp_slot", e.ld(e.add(_e(e, E_FREE), p["sp_best"])))
                e.st(e.add(_e(e, E_FREE), p["sp_best"]), e.ld(e.add(_e(e, E_FREE), e.sub(p["sp_n"], 1))))
                _se(e, E_NFREE, e.sub(p["sp_n"], 1))

            def fresh():
                e.var("sp_slot", _e(e, E_NEXT))
                _se(e, E_NEXT, e.add(p["sp_slot"], 1))
                e.if_(e.lt(_e(e, E_MAX), _e(e, E_NEXT)), lambda: _se(e, E_MAX, _e(e, E_NEXT)))

            e.var("sp_slot", 0)
            e.if_(e.ne(p["sp_n"], 0), reuse, fresh)
            _sset(e, T_SPID, p["v"], p["sp_slot"])
            e.var("sp_off", e.add(_ra(e, R_DYN_BASE), e.mul(p["sp_slot"], 8)))
            _set_rt(e, T_SPOFF, p["v"], p["sp_off"])
            _store(e, p["sp_r"], p["sp_off"], _wbytes(e, p["v"]))

        e.if_(e.eq(_sget(e, T_SPOFF, p["v"], NONE), NONE), allocate)
        e.if_(e.eq(p["keep"], 0), lambda: _call(e, "unbind", p["v"]))
        e.give(1)
    return _function(("v", "keep"), build, tables)


def _protected(e: E, value, names):
    return e.either(*(e.eq(value, e.p[name]) for name in names))


def _acquire_fn(tables):
    """``acquire(position, protected (up to four values, NONE for none), excluded registers mask)``."""
    def build(e: E):
        p = e.p
        e.var("aq_hint", _e(e, E_HINT))

        def hinted():
            e.var("aq_pref", _sget(e, T_HINT, p["aq_hint"], NONE))
            ok = e.both(e.ne(p["aq_pref"], NONE), e.eq(_regv(e, e.sel(e.ne(p["aq_pref"], NONE), p["aq_pref"], 0)), NONE),
                        e.not_(_excluded(e, p["excl"], e.sel(e.ne(p["aq_pref"], NONE), p["aq_pref"], 0))))
            e.if_(ok, lambda: e.give(p["aq_pref"]))
            # Live across a call: a callee-saved register keeps it without a spill.
            e.var("aq_last", _last_use(e, p["aq_hint"]))
            e.var("aq_across", 0)
            e.if_(e.ne(p["aq_last"], NONE), lambda: e.for_("aq_k", 0, _e(e, E_NCALLPOS), lambda: (
                e.var("aq_c", e.ld(e.add(_e(e, E_CALLPOS), p["aq_k"]))),
                e.if_(e.both(e.lt(p["pos"], p["aq_c"]), e.lt(p["aq_c"], p["aq_last"])), lambda: e.set("aq_across", 1)))))

            def callee_saved():
                def each():
                    e.var("aq_r", e.ld(e.add(_ra(e, R_ALLOC), p["aq_k"])))
                    good = e.both(_in(e, p["aq_r"], PINNABLE), e.eq(_regv(e, p["aq_r"]), NONE), e.not_(_excluded(e, p["excl"], p["aq_r"])))
                    e.if_(good, lambda: e.give(p["aq_r"]))

                e.for_("aq_k", 0, _ra(e, R_NALLOC), each)

            e.if_(e.ne(p["aq_across"], 0), callee_saved)

        e.if_(e.ne(p["aq_hint"], NONE), hinted)

        def free():
            e.var("aq_r", e.ld(e.add(_ra(e, R_ALLOC), p["aq_k"])))
            e.if_(e.both(e.eq(_regv(e, p["aq_r"]), NONE), e.not_(_excluded(e, p["excl"], p["aq_r"]))), lambda: e.give(p["aq_r"]))

        e.for_("aq_k", 0, _ra(e, R_NALLOC), free)
        # Spill the live value used furthest away (ties: the highest register).
        e.var("aq_victim", NONE)
        e.var("aq_best", 0)

        def candidate():
            e.var("aq_v", _regv(e, p["aq_k"]))
            eligible = e.both(e.ne(p["aq_v"], NONE), e.not_(_protected(e, p["aq_v"], ("p1", "p2", "p3", "p4"))),
                              e.eq(_pinned(e, e.sel(e.ne(p["aq_v"], NONE), p["aq_v"], 0)), NONE), e.not_(_excluded(e, p["excl"], p["aq_k"])))

            def consider():
                e.var("aq_nu", _call(e, "next_use", p["aq_v"], p["pos"]))
                e.if_(e.either(e.eq(p["aq_victim"], NONE), e.le(p["aq_best"], p["aq_nu"])),
                      lambda: (e.set("aq_victim", p["aq_k"]), e.set("aq_best", p["aq_nu"])))

            e.if_(eligible, consider)

        e.for_("aq_k", 0, 16, candidate)
        _ok(e, e.ne(p["aq_victim"], NONE))  # the bootstrap fails (NATIVE-SPILLABLE-REGISTER)
        e.var("aq_reg", p["aq_victim"])
        _call(e, "spill", _regv(e, p["aq_reg"]), 0)
        e.give(p["aq_reg"])
    return _function(("pos", "p1", "p2", "p3", "p4", "excl"), build, tables)


def _acquire(e: E, position, protected=(), excluded=0):
    values = list(protected) + [NONE] * (4 - len(protected))
    return _call(e, "acquire", position, *values, excluded)


def _ensure_fn(tables):
    """``ensure(value, position, protected (up to three), excluded mask)`` -> its register."""
    def build(e: E):
        p = e.p
        v = p["v"]
        e.var("en_pin", _pinned(e, v))
        e.if_(e.both(e.ne(p["en_pin"], NONE), e.not_(_excluded(e, p["excl"], e.sel(e.ne(p["en_pin"], NONE), p["en_pin"], 0)))),
              lambda: (_call(e, "bind", v, p["en_pin"]), e.give(p["en_pin"])))
        e.var("en_r", _rt(e, T_REG, v))

        def bound():
            e.if_(e.not_(_excluded(e, p["excl"], p["en_r"])), lambda: e.give(p["en_r"]))
            e.var("en_new", _call(e, "acquire", p["pos"], p["p1"], p["p2"], p["p3"], v, p["excl"]))
            _mov(e, p["en_new"], p["en_r"])
            _call(e, "unbind", v)
            _call(e, "bind", v, p["en_new"])
            e.give(p["en_new"])

        e.if_(e.ne(p["en_r"], NONE), bound)
        e.var("en_new", _call(e, "acquire", p["pos"], p["p1"], p["p2"], p["p3"], NONE, p["excl"]))

        def done():
            _call(e, "bind", v, p["en_new"])
            e.give(p["en_new"])

        e.if_(_constant(e, v), lambda: (_load_constant(e, p["en_new"], _cval(e, v)), done()))
        e.var("en_stack", _rt(e, T_STACK, v))
        e.if_(e.ne(p["en_stack"], NONE), lambda: (_lea(e, p["en_new"], RSP, p["en_stack"]), done()))
        e.var("en_off", _sget(e, T_SPOFF, v, NONE))
        _ok(e, e.ne(p["en_off"], NONE))  # the bootstrap fails (NATIVE-VALUE-LOCATION)
        _load(e, p["en_new"], p["en_off"], _wbytes(e, v))
        done()
    return _function(("v", "pos", "p1", "p2", "p3", "excl"), build, tables)


def _ensure(e: E, value, position, protected=(), excluded=0):
    values = list(protected) + [NONE] * (3 - len(protected))
    return _call(e, "ensure", value, position, *values, excluded)


def _local_result(e: E, value):
    """A node result of the block being lowered."""
    return e.both(e.not_(_is_param(e, value)), e.eq(_pos_block(e, value), _e(e, E_BI)))


def _define_fn(tables):
    def build(e: E):
        p = e.p
        e.var("df_r", p["r"])
        e.var("df_pin", _pinned(e, p["v"]))
        e.if_(e.both(e.ne(p["df_pin"], NONE), e.ne(p["df_pin"], p["df_r"])), lambda: (_mov(e, p["df_pin"], p["df_r"]), e.set("df_r", p["df_pin"])))
        _call(e, "bind", p["v"], p["df_r"])
        e.var("df_home", _rt(e, T_HOME, p["v"]))

        def home():
            _store(e, p["df_r"], p["df_home"], _wbytes(e, p["v"]))
            _sset(e, T_SPOFF, p["v"], p["df_home"])

        e.if_(e.both(e.ne(p["df_home"], NONE), _local_result(e, p["v"])), home)
        e.if_(e.eq(_last_use(e, p["v"]), NONE), lambda: _call(e, "release", p["v"]))
        e.give(1)
    return _function(("v", "r"), build, tables)


def _retire(e: E, position, *operands):
    """``retire``: release each operand whose last use is here."""
    for operand in operands:
        e.var("rt_o", operand)
        e.if_(e.eq(_last_use(e, e.p["rt_o"]), position), lambda: _call(e, "release", e.p["rt_o"]))


def _consumable(e: E, value, position):
    return e.both(e.eq(_last_use(e, value), position), e.eq(_pinned(e, value), NONE))


def _destination_fn(tables):
    """``destination_for(position, source, protected (up to two))``."""
    def build(e: E):
        p = e.p
        e.var("ds_r", _rt(e, T_REG, p["src"]))
        _ok(e, e.ne(p["ds_r"], NONE))
        e.if_(_consumable(e, p["src"], p["pos"]), lambda: (_call(e, "unbind", p["src"]), e.give(p["ds_r"])))
        e.var("ds_new", _call(e, "acquire", p["pos"], p["p1"], p["p2"], p["src"], NONE, 0))
        _mov(e, p["ds_new"], p["ds_r"])
        e.give(p["ds_new"])
    return _function(("pos", "src", "p1", "p2"), build, tables)


def _destination_for(e: E, position, source, protected=()):
    values = list(protected) + [NONE] * (2 - len(protected))
    return _call(e, "destination_for", position, source, *values)


def _parallel_moves_fn(tables):
    """``parallel_moves`` over ``E_MOVES`` (``E_NMOVES`` entries ``(dst, src, width, offset)``)."""
    def build(e: E):
        p = e.p
        moves = _e(e, E_MOVES)
        e.var("pm_at", moves)
        at = lambda k, f: e.add(p["pm_at"], e.add(e.mul(k, 4), f))  # noqa: E731
        # Drop the moves that change nothing.
        e.var("pm_n", 0)

        def keep():
            useful = e.either(e.ne(e.ld(at(p["pm_k"], 0)), e.ld(at(p["pm_k"], 1))), e.ne(e.ld(at(p["pm_k"], 3)), 0))
            e.if_(useful, lambda: (e.for_("pm_f", 0, 4, lambda: e.st(at(p["pm_n"], p["pm_f"]), e.ld(at(p["pm_k"], p["pm_f"])))),
                                   e.set("pm_n", e.add(p["pm_n"], 1))))

        e.for_("pm_k", 0, _e(e, E_NMOVES), keep)

        def step():
            e.var("pm_safe", NONE)

            def check():
                e.var("pm_d", e.ld(at(p["pm_k"], 0)))
                e.var("pm_is_src", 0)
                e.var("pm_count", 0)
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.eq(e.ld(at(p["pm_j"], 1)), p["pm_d"]),
                                                           lambda: (e.set("pm_is_src", 1), e.set("pm_count", e.add(p["pm_count"], 1)))))
                self_offset = e.both(e.eq(p["pm_d"], e.ld(at(p["pm_k"], 1))), e.ne(e.ld(at(p["pm_k"], 3)), 0), e.eq(p["pm_count"], 1))
                e.if_(e.either(e.eq(p["pm_is_src"], 0), self_offset), lambda: (e.set("pm_safe", p["pm_k"]), e.set("pm_k", p["pm_n"])))

            e.var("pm_k", 0)
            e.while_(lambda: e.lt(p["pm_k"], p["pm_n"]), lambda: (check(), e.if_(e.eq(p["pm_safe"], NONE), lambda: e.set("pm_k", e.add(p["pm_k"], 1)))))

            def emit_safe():
                s = p["pm_safe"]
                e.var("pm_dst", e.ld(at(s, 0)))
                e.var("pm_src", e.ld(at(s, 1)))
                e.var("pm_w", e.ld(at(s, 2)))
                e.var("pm_off", e.ld(at(s, 3)))
                e.if_(e.ne(p["pm_off"], 0), lambda: (_rex(e, e.flag(e.eq(p["pm_w"], 64)), p["pm_dst"], 0, p["pm_src"]), _bx(e, 0x8D, 1),
                                                     _modrm(e, p["pm_dst"], p["pm_src"], p["pm_off"])),
                      lambda: _mov(e, p["pm_dst"], p["pm_src"]))
                # pop(safe): shift the later entries down
                e.for_("pm_j", s, e.sub(p["pm_n"], 1), lambda: e.for_("pm_f", 0, 4, lambda: e.st(at(p["pm_j"], p["pm_f"]), e.ld(at(e.add(p["pm_j"], 1), p["pm_f"])))))
                e.set("pm_n", e.sub(p["pm_n"], 1))

            def break_cycle():
                e.var("pm_src", e.ld(at(0, 1)))
                _mov(e, SCRATCH, p["pm_src"])
                e.for_("pm_j", 0, p["pm_n"], lambda: e.if_(e.eq(e.ld(at(p["pm_j"], 1)), p["pm_src"]), lambda: e.st(at(p["pm_j"], 1), SCRATCH)))

            e.if_(e.ne(p["pm_safe"], NONE), emit_safe, break_cycle)

        e.while_(lambda: e.ne(p["pm_n"], 0), step)
        _se(e, E_NMOVES, 0)
        e.give(1)
    return _function((), build, tables)


def _add_move(e: E, dst, src, width, offset=0):
    e.var("am_n", _e(e, E_NMOVES))
    _ok(e, e.lt(e.p["am_n"], MOVE_CAP))
    e.var("am_at", e.add(_e(e, E_MOVES), e.mul(e.p["am_n"], 4)))
    for field, value in enumerate((dst, src, width, offset)):
        e.st(e.add(e.p["am_at"], field), value)
    _se(e, E_NMOVES, e.add(e.p["am_n"], 1))


def _location_fn(tables):
    """``location(value)`` into ``E_LOCK`` (kind) and ``E_LOCW`` (register, constant, or offset)."""
    def build(e: E):
        p = e.p
        v = p["v"]

        def put(kind, where):
            _se(e, E_LOCK, kind)
            _se(e, E_LOCW, where)
            e.give(1)

        e.var("lo_pin", _pinned(e, v))
        e.if_(e.ne(p["lo_pin"], NONE), lambda: put(LOC_REG, p["lo_pin"]))
        e.var("lo_r", _rt(e, T_REG, v))
        e.if_(e.ne(p["lo_r"], NONE), lambda: put(LOC_REG, p["lo_r"]))
        e.if_(_constant(e, v), lambda: put(LOC_CONST, _cval(e, v)))
        e.var("lo_s", _rt(e, T_STACK, v))
        e.if_(e.ne(p["lo_s"], NONE), lambda: put(LOC_STACK, p["lo_s"]))
        e.var("lo_o", _sget(e, T_SPOFF, v, NONE))
        _ok(e, e.ne(p["lo_o"], NONE))  # the bootstrap fails (NATIVE-VALUE-LOCATION)
        put(LOC_SPILL, p["lo_o"])
    return _function(("v",), build, tables)


def _location(e: E, value, kind_name: str, where_name: str):
    _call(e, "location", value)
    e.var(kind_name, _e(e, E_LOCK))
    e.var(where_name, _e(e, E_LOCW))


def _materialize(e: E, register, kind, where, width_bytes):
    """Load a non-register location into ``register`` (``_load_constant``, ``lea``, or ``_load``)."""
    e.if_(e.eq(kind, LOC_CONST), lambda: _load_constant(e, register, where),
          lambda: e.if_(e.eq(kind, LOC_STACK), lambda: _lea(e, register, RSP, where), lambda: _load(e, register, where, width_bytes)))


def _place_arguments_fn(tables):
    """``place_arguments(position)`` of ``E_ARGS`` into ``E_REGS`` (``E_NARGS`` each): spill the volatile live values in
    key order, move the register operands in parallel, then load the rest."""
    def build(e: E):
        p = e.p
        # Live after the call in a volatile register, by (tag, block, index, result).
        e.var("pa_live", _e(e, E_LIVE))
        e.var("pa_n", 0)

        def gather():
            e.var("pa_v", _regv(e, p["pa_r"]))
            e.var("pa_last", e.sel(e.ne(p["pa_v"], NONE), _last_use(e, e.sel(e.ne(p["pa_v"], NONE), p["pa_v"], 0)), NONE))
            live = e.both(e.ne(p["pa_v"], NONE), e.ne(p["pa_last"], NONE), e.lt(p["pos"], p["pa_last"]), e.not_(_in(e, p["pa_r"], PINNABLE)))
            e.if_(live, lambda: (e.st(e.add(p["pa_live"], p["pa_n"]), p["pa_v"]), e.set("pa_n", e.add(p["pa_n"], 1))))

        e.for_("pa_r", 0, 16, gather)

        def insert():
            e.var("pa_item", e.ld(e.add(p["pa_live"], p["pa_s"])))
            e.var("pa_j", p["pa_s"])
            before = lambda: e.both(e.lt(0, p["pa_j"]), e.lt(_key(e, p["pa_item"]), _key(e, e.ld(e.add(p["pa_live"], e.sub(p["pa_j"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["pa_live"], p["pa_j"]), e.ld(e.add(p["pa_live"], e.sub(p["pa_j"], 1)))), e.set("pa_j", e.sub(p["pa_j"], 1))))
            e.st(e.add(p["pa_live"], p["pa_j"]), p["pa_item"])

        e.for_("pa_s", 1, p["pa_n"], insert)
        e.for_("pa_s", 0, p["pa_n"], lambda: _call(e, "spill", e.ld(e.add(p["pa_live"], p["pa_s"])), 1))
        args, regs = _e(e, E_ARGS), _e(e, E_REGS)
        e.var("pa_args", args)
        e.var("pa_regs", regs)

        def move():
            e.var("pa_o", e.ld(e.add(p["pa_args"], p["pa_k"])))
            _location(e, p["pa_o"], "pa_kind", "pa_where")
            e.if_(e.eq(p["pa_kind"], LOC_REG), lambda: _add_move(e, e.ld(e.add(p["pa_regs"], p["pa_k"])), p["pa_where"], _width(e, p["pa_o"])))

        e.for_("pa_k", 0, _e(e, E_NARGS), move)
        _call(e, "parallel_moves")

        def load():
            e.var("pa_o", e.ld(e.add(p["pa_args"], p["pa_k"])))
            _location(e, p["pa_o"], "pa_kind", "pa_where")
            e.if_(e.ne(p["pa_kind"], LOC_REG), lambda: _materialize(e, e.ld(e.add(p["pa_regs"], p["pa_k"])), p["pa_kind"], p["pa_where"], _wbytes(e, p["pa_o"])))

        e.for_("pa_k", 0, _e(e, E_NARGS), load)
        e.give(1)
    return _function(("pos",), build, tables)


def _set_arguments(e: E, operands, registers):
    """Fill ``E_ARGS``/``E_REGS`` from Python lists of expressions."""
    for k, (operand, register) in enumerate(zip(operands, registers)):
        e.st(e.add(_e(e, E_ARGS), k), operand)
        e.st(e.add(_e(e, E_REGS), k), register)
    _se(e, E_NARGS, len(operands))


def _after_call_fn(tables):
    """``after_call``: forget every volatile, unpinned register; the caller retires the operands."""
    def build(e: E):
        p = e.p

        def each():
            e.var("ac_v", _regv(e, p["ac_r"]))
            e.if_(e.both(e.ne(p["ac_v"], NONE), e.not_(_in(e, p["ac_r"], PINNABLE))),
                  lambda: e.if_(e.eq(_pinned(e, p["ac_v"]), NONE), lambda: _call(e, "unbind", p["ac_v"])))

        e.for_("ac_r", 0, 16, each)
        e.give(1)
    return _function(("pos",), build, tables)


# -- labels, jumps, calls, tables, traps ------------------------------------------------------------------------

def _new_label(e: E):
    """A fresh label number (blocks are labels 0..n-1)."""
    e.var("nl_id", _e(e, E_NLABELS))
    _ok(e, e.lt(e.p["nl_id"], LABEL_CAP))
    e.st(e.add(_e(e, E_LABELS), e.p["nl_id"]), NONE)
    _se(e, E_NLABELS, e.add(e.p["nl_id"], 1))
    return e.p["nl_id"]


def _label(e: E, label):
    e.if_(e.ne(_e(e, E_REAL), 0), lambda: e.st(e.add(_e(e, E_LABELS), label), _e(e, E_CLEN)))


def _jump_fn(tables):
    """``jump(opcode, label)``: the opcode (``on`` bytes), a fixup, four zero bytes; ``jmp`` closes the code."""
    def build(e: E):
        p = e.p

        def real():
            _bx(e, p["oc"], p["on"], True)
            _record_branch(e, p["label"])
            _bx(e, 0, 4, True)
            e.if_(e.both(e.eq(p["on"], 1), e.eq(p["oc"], 0xE9)), lambda: _se(e, E_CLOSED, _e(e, E_CLEN)))

        e.if_(e.ne(_e(e, E_REAL), 0), real)
        e.give(1)
    return _function(("oc", "on", "label"), build, tables)


def _record_branch(e: E, label):
    e.var("rb_n", _e(e, E_NBRANCHES))
    _ok(e, e.lt(e.p["rb_n"], BRANCH_CAP))
    e.var("rb_at", e.add(_e(e, E_BRANCHES), e.mul(e.p["rb_n"], 2)))
    e.st(e.p["rb_at"], _e(e, E_CLEN))
    e.st(e.add(e.p["rb_at"], 1), label)
    _se(e, E_NBRANCHES, e.add(e.p["rb_n"], 1))


def _jump(e: E, opcode: int, opcode_length: int, label):
    _call(e, "em_jump", opcode, opcode_length, label)


def _relative(e: E, opcode: int, label):
    """``assembler.relative`` (no closing mark): the prologue's and the stubs' jumps."""
    def real():
        _bx(e, opcode, 1, True)
        _record_branch(e, label)
        _bx(e, 0, 4, True)

    e.if_(e.ne(_e(e, E_REAL), 0), real)


def _jcc(e: E, condition, label):
    """``jump(b"\\x0f" + condition)``."""
    _call(e, "em_jump", e.add(0x0F, e.mul(condition, 256)), 2, label)


def _record_call(e: E, obj, prefixed):
    """``assembler.calls`` entry: the fixup position, the target object, and whether it is the SysV entry label."""
    e.var("rc_n", _e(e, E_NCALLS))
    _ok(e, e.lt(e.p["rc_n"], CALL_CAP))
    e.var("rc_at", e.add(_e(e, E_CALLS), e.mul(e.p["rc_n"], 3)))
    for field, value in enumerate((_e(e, E_CLEN), obj, prefixed)):
        e.st(e.add(e.p["rc_at"], field), value)
    _se(e, E_NCALLS, e.add(e.p["rc_n"], 1))


def _trap_label_fn(tables):
    """``traps.setdefault(trap, f"trap-{len(traps)}")``: ``key`` NONE is ``ud2``, else ``mov rax, key; ud2``."""
    def build(e: E):
        p = e.p
        e.for_("tl_k", 0, _e(e, E_NTRAPS), lambda: e.if_(e.eq(e.ld(e.add(_e(e, E_TRAPS), e.mul(p["tl_k"], 2))), p["key"]),
                                                       lambda: e.give(e.ld(e.add(_e(e, E_TRAPS), e.add(e.mul(p["tl_k"], 2), 1))))))
        e.var("tl_n", _e(e, E_NTRAPS))
        _ok(e, e.lt(p["tl_n"], TRAP_CAP))
        e.var("tl_label", _new_label(e))
        e.st(e.add(_e(e, E_TRAPS), e.mul(p["tl_n"], 2)), p["key"])
        e.st(e.add(_e(e, E_TRAPS), e.add(e.mul(p["tl_n"], 2), 1)), p["tl_label"])
        _se(e, E_NTRAPS, e.add(p["tl_n"], 1))
        e.give(p["tl_label"])
    return _function(("key",), build, tables)


def _trap_if(e: E, condition: int, key=NONE):
    e.var("ti_label", _call(e, "trap_label", key))
    _jcc(e, condition, e.p["ti_label"])


def _table_address_fn(tables):
    """``table_address(table)`` of the ``count`` byte words at ``entries``: ``lea r11, [rip + table]``."""
    def build(e: E):
        p = e.p
        e.var("ta_label", NONE)

        def same():
            e.var("ta_rec", e.add(_e(e, E_TABLES), e.mul(p["ta_k"], 3)))
            e.var("ta_eq", e.flag(e.eq(e.ld(e.add(p["ta_rec"], 1)), p["count"])))
            e.if_(e.ne(p["ta_eq"], 0), lambda: e.for_("ta_j", 0, p["count"], lambda: e.if_(
                e.ne(e.ld(e.add(e.ld(p["ta_rec"]), p["ta_j"])), e.ld(e.add(p["entries"], p["ta_j"]))), lambda: e.set("ta_eq", 0))))
            e.if_(e.both(e.ne(p["ta_eq"], 0), e.eq(p["ta_label"], NONE)), lambda: e.set("ta_label", e.ld(e.add(p["ta_rec"], 2))))

        e.for_("ta_k", 0, _e(e, E_NTABLES), same)

        def add():
            e.var("ta_n", _e(e, E_NTABLES))
            _ok(e, e.lt(p["ta_n"], TABLE_CAP))
            e.set("ta_label", _new_label(e))
            e.var("ta_rec", e.add(_e(e, E_TABLES), e.mul(p["ta_n"], 3)))
            for field, value in enumerate((p["entries"], p["count"], p["ta_label"])):
                e.st(e.add(p["ta_rec"], field), value)
            _se(e, E_NTABLES, e.add(p["ta_n"], 1))

        e.if_(e.eq(p["ta_label"], NONE), add)
        _ok(e, e.eq(_e(e, E_CAP_ON), 0))  # the bootstrap fails (NATIVE-TABLE-NOT-IN-EDGE-COPY)

        def real():
            _bx(e, 0x1D8D4C, 3, True)
            _record_branch(e, p["ta_label"])
            _bx(e, 0, 4, True)

        e.if_(e.ne(_e(e, E_REAL), 0), real)
        e.give(1)
    return _function(("entries", "count"), build, tables)


def _add_stub(e: E, label, code, target):
    e.var("as_n", _e(e, E_NSTUBS))
    _ok(e, e.lt(e.p["as_n"], STUB_CAP))
    e.var("as_at", e.add(_e(e, E_STUBS), e.mul(e.p["as_n"], 3)))
    for field, value in enumerate((label, code, target)):
        e.st(e.add(e.p["as_at"], field), value)
    _se(e, E_NSTUBS, e.add(e.p["as_n"], 1))


def _emit_record(e: E, record):
    """Emit a captured byte record ``[length, bytes...]`` (capture-aware)."""
    e.var("er_r", record)
    e.for_("er_k", 0, e.ld(e.p["er_r"]), lambda: _bx(e, e.ld(e.add(e.add(e.p["er_r"], 1), e.p["er_k"])), 1))


# -- edges --------------------------------------------------------------------------------------------------------

def _machine_index(e: E, block, index, name: str):
    """The position of parameter ``index`` among ``block``'s machine parameters."""
    p = e.p
    e.var(name, 0)
    e.for_(f"{name}_k", 0, index, lambda: e.if_(e.ne(_width(e, e.ld(e.add(_f(e, block, B_INPUTS), p[f"{name}_k"]))), 0),
                                                lambda: e.set(name, e.add(p[name], 1))))


def _copy_edge_fn(tables):
    """``copy_edge(target block record, arguments, count)``."""
    from xax_selfhost_general_regalloc import _uses_in

    def build(e: E):
        p = e.p
        tb = p["tb"]
        e.var("ce_tbi", _f(e, tb, B_POS))
        e.var("ce_pairs", _e(e, E_PAIRS))
        e.var("ce_n", 0)
        at = lambda k, f: e.add(p["ce_pairs"], e.add(e.mul(k, 5), f))  # noqa: E731  (source, index, destination, sunk, amount)

        def pair():
            e.var("ce_arg", e.ld(e.add(p["args"], p["ce_k"])))
            e.var("ce_dst", e.ld(e.add(_f(e, tb, B_INPUTS), p["ce_k"])))
            _uses_in(e, p["ce_tbi"], p["ce_dst"], "ce_use")
            dead = e.both(e.eq(p["ce_use"], NONE), e.eq(_rt(e, T_HOME, p["ce_dst"]), NONE), e.eq(_pinned(e, p["ce_dst"]), NONE))

            def add():
                _machine_index(e, tb, p["ce_k"], "ce_mi")
                e.var("ce_src", p["ce_arg"])
                e.var("ce_sunk", 0)
                e.var("ce_amount", 0)
                e.var("ce_so", _rt(e, T_SINK_OPERAND, p["ce_arg"]))
                e.if_(e.ne(p["ce_so"], NONE), lambda: (e.set("ce_src", p["ce_so"]), e.set("ce_sunk", 1), e.set("ce_amount", _rt(e, T_SINK_AMOUNT, p["ce_arg"]))))
                for field, value in enumerate((p["ce_src"], p["ce_mi"], p["ce_dst"], p["ce_sunk"], p["ce_amount"])):
                    e.st(at(p["ce_n"], field), value)
                e.set("ce_n", e.add(p["ce_n"], 1))

            e.if_(e.both(e.ne(_width(e, p["ce_arg"]), 0), e.ne(_width(e, p["ce_dst"]), 0), e.not_(dead)), add)

        e.for_("ce_k", 0, p["count"], pair)
        e.var("ce_nalloc", _ra(e, R_NALLOC))

        def to_stack():
            e.var("ce_s", e.ld(at(p["ce_q"], 0)))
            e.var("ce_i", e.ld(at(p["ce_q"], 1)))
            e.var("ce_d", e.ld(at(p["ce_q"], 2)))
            e.var("ce_off", NONE)
            e.var("ce_ps", _rt(e, T_PSLOT, p["ce_d"]))
            e.if_(e.ne(p["ce_ps"], NONE), lambda: e.set("ce_off", p["ce_ps"]), lambda: e.if_(
                e.both(e.le(p["ce_nalloc"], p["ce_i"]), e.eq(_pinned(e, p["ce_d"]), NONE)),
                lambda: e.set("ce_off", e.add(_ra(e, R_EDGE_SPILL_BASE), e.mul(e.sub(p["ce_i"], p["ce_nalloc"]), 8)))))

            def store():
                _location(e, p["ce_s"], "ce_kind", "ce_where")

                def sunk():
                    e.if_(e.eq(p["ce_kind"], LOC_REG), lambda: _mov(e, SCRATCH, p["ce_where"]), lambda: _load(e, SCRATCH, p["ce_where"], _wbytes(e, p["ce_s"])))
                    _rex(e, e.flag(e.eq(_width(e, p["ce_d"]), 64)), SCRATCH, 0, SCRATCH)
                    _bx(e, 0x8D, 1)
                    _modrm(e, SCRATCH, SCRATCH, e.ld(at(p["ce_q"], 4)))
                    _store(e, SCRATCH, p["ce_off"], 8)

                def plain():
                    e.if_(e.eq(p["ce_kind"], LOC_REG), lambda: _store(e, p["ce_where"], p["ce_off"], 8), lambda: e.if_(
                        e.ne(p["ce_kind"], LOC_SPILL), lambda: (_materialize(e, SCRATCH, p["ce_kind"], p["ce_where"], 8), _store(e, SCRATCH, p["ce_off"], 8)),
                        lambda: e.if_(e.ne(p["ce_where"], p["ce_off"]), lambda: (_load(e, SCRATCH, p["ce_where"], _wbytes(e, p["ce_s"])), _store(e, SCRATCH, p["ce_off"], 8)))))

                e.if_(e.ne(e.ld(at(p["ce_q"], 3)), 0), sunk, plain)

            e.if_(e.ne(p["ce_off"], NONE), store)

        e.for_("ce_q", 0, p["ce_n"], to_stack)
        # Registers: register sources in parallel, the others after.
        e.var("ce_delayed", _e(e, E_DELAYED))
        e.var("ce_nd", 0)

        def to_register():
            e.var("ce_s", e.ld(at(p["ce_q"], 0)))
            e.var("ce_i", e.ld(at(p["ce_q"], 1)))
            e.var("ce_d", e.ld(at(p["ce_q"], 2)))
            e.var("ce_reg", NONE)
            e.var("ce_pin", _pinned(e, p["ce_d"]))
            e.if_(e.eq(_rt(e, T_PSLOT, p["ce_d"]), NONE), lambda: e.if_(e.ne(p["ce_pin"], NONE), lambda: e.set("ce_reg", p["ce_pin"]), lambda: e.if_(
                e.lt(p["ce_i"], p["ce_nalloc"]), lambda: e.set("ce_reg", e.ld(e.add(_ra(e, R_ALLOC), p["ce_i"]))))))

            def place():
                _location(e, p["ce_s"], "ce_kind", "ce_where")
                e.var("ce_amt", e.mul(e.ld(at(p["ce_q"], 3)), e.ld(at(p["ce_q"], 4))))

                def delay():
                    e.var("ce_dat", e.add(p["ce_delayed"], e.mul(p["ce_nd"], 6)))
                    for field, value in enumerate((p["ce_reg"], p["ce_kind"], p["ce_where"], _wbytes(e, p["ce_s"]), p["ce_amt"], _width(e, p["ce_d"]))):
                        e.st(e.add(p["ce_dat"], field), value)
                    e.set("ce_nd", e.add(p["ce_nd"], 1))

                e.if_(e.eq(p["ce_kind"], LOC_REG), lambda: _add_move(e, p["ce_reg"], p["ce_where"], _width(e, p["ce_d"]), p["ce_amt"]), delay)

            e.if_(e.ne(p["ce_reg"], NONE), place)

        e.for_("ce_q", 0, p["ce_n"], to_register)
        _call(e, "parallel_moves")

        def delayed():
            e.var("ce_dat", e.add(p["ce_delayed"], e.mul(p["ce_q"], 6)))
            e.var("ce_reg", e.ld(p["ce_dat"]))
            _materialize(e, p["ce_reg"], e.ld(e.add(p["ce_dat"], 1)), e.ld(e.add(p["ce_dat"], 2)), e.ld(e.add(p["ce_dat"], 3)))
            e.var("ce_amt", e.ld(e.add(p["ce_dat"], 4)))
            e.if_(e.ne(p["ce_amt"], 0), lambda: (_rex(e, e.flag(e.eq(e.ld(e.add(p["ce_dat"], 5)), 64)), p["ce_reg"], 0, p["ce_reg"]), _bx(e, 0x8D, 1),
                                                 _modrm(e, p["ce_reg"], p["ce_reg"], p["ce_amt"])))

        e.for_("ce_q", 0, p["ce_nd"], delayed)
        e.give(1)
    return _function(("tb", "args", "count"), build, tables)


def _edge_code_fn(tables):
    """``edge_code(target, arguments)``: the copies captured as an arena record ``[length, bytes...]``."""
    def build(e: E):
        p = e.p
        _ok(e, e.eq(_e(e, E_CAP_ON), 0))
        _se(e, E_CAP_ON, 1)
        _se(e, E_CAPLEN, 0)
        _call(e, "copy_edge", p["tb"], p["args"], p["count"])
        _se(e, E_CAP_ON, 0)
        e.var("ec_n", _e(e, E_CAPLEN))
        e.var("ec_rec", e.alloc(e.add(p["ec_n"], 1)))
        _ok(e, e.ne(p["ec_rec"], NONE))
        e.st(p["ec_rec"], p["ec_n"])
        e.for_("ec_k", 0, p["ec_n"], lambda: e.st(e.add(e.add(p["ec_rec"], 1), p["ec_k"]), e.ld(e.add(_e(e, E_CAPBUF), p["ec_k"]))))
        e.give(p["ec_rec"])
    return _function(("tb", "args", "count"), build, tables)


def _edge(e: E, block, k: int):
    """Edge ``k`` of ``block``: (target block record, arguments, count)."""
    at = e.add(_f(e, block, B_EDGES), k * EDGE)
    return _f(e, at, 0), _f(e, at, 2), _f(e, at, 1)


# -- nodes ----------------------------------------------------------------------------------------------------------

def _op(operation) -> int:
    return int(operation)


def _immediate(e: E, value, width, name: str):
    """``immediate(value, width)``: ``name`` 1 when the value is a constant that fits an imm32 at ``width``, its value in
    ``name_v``."""
    p = e.p
    e.var(f"{name}_v", _cval(e, value))
    fits = e.sel(e.lt(32, width), e.flag(e.lt(p[f"{name}_v"], 1 << 31)), e.flag(e.lt(p[f"{name}_v"], 1 << 32)))
    e.var(name, e.mul(e.flag(_constant(e, value)), fits))


def _maximum(e: E, value, name: str):
    """``maximum(value)`` into ``name``; ``name_none`` 1 when there is no bound."""
    e.var(name, e.call(_FN["maximum0"], value))
    e.var(f"{name}_none", _g2(e, G2_RNONE))


def _rtg(e: E, table: int, value, default):
    """A per-value table entry, ``default`` for a missing value (NONE)."""
    return e.sel(e.ne(value, NONE), _rt(e, table, e.sel(e.ne(value, NONE), value, 0)), default)


def _power(e: E, value, name: str):
    """``_power_of_two(value)`` into ``name`` (NONE when the value is not a power of two)."""
    p = e.p
    e.var(name, NONE)
    e.var(f"{name}_x", value)
    e.if_(e.power_of_two(p[f"{name}_x"]), lambda: (e.set(name, 0), e.while_(lambda: e.lt(1, p[f"{name}_x"]), lambda: (
        e.set(f"{name}_x", e.udiv(p[f"{name}_x"], 2)), e.set(name, e.add(p[name], 1))))))


def _marks_of(e: E, value, name: str):
    """The prefetch mark of ``value``: ``name`` its (pointer, scale) list, ``name_n`` its length (0 when none)."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_n", 0)

    def mark():
        e.var(f"{name}_at", e.add(_g2(e, G2_MARKS), e.mul(p[f"{name}_q"], MARK_WORDS)))
        e.if_(e.eq(e.ld(p[f"{name}_at"]), value), lambda: (e.set(name, e.ld(e.add(p[f"{name}_at"], 1))), e.set(f"{name}_n", e.ld(e.add(p[f"{name}_at"], 2)))))

    e.for_(f"{name}_q", 0, _g2(e, G2_NMARKS), mark)


def _machine_operands(e: E, node, first: int = 0):
    """Fill ``E_ARGS`` with the node's machine operands from operand ``first``; their count in ``mo_n``."""
    p = e.p
    e.var("mo_n", 0)

    def each():
        e.var("mo_o", _operand(e, node, p["mo_k"]))
        e.if_(e.ne(_width(e, p["mo_o"]), 0), lambda: (e.st(e.add(_e(e, E_ARGS), p["mo_n"]), p["mo_o"]), e.set("mo_n", e.add(p["mo_n"], 1))))

    e.for_("mo_k", first, _f(e, node, N_NOPS), each)


def _retire_arguments(e: E, position, count):
    """``after_call``'s retirement of the machine operands saved in ``E_LIVE`` (``count``)."""
    p = e.p
    e.for_("ra_k", 0, count, lambda: _retire(e, position, e.ld(e.add(_e(e, E_LIVE), e.add(32, p["ra_k"])))))


def _save_operands(e: E, count):
    """Keep the machine operands (``E_ARGS``) for retirement after the call (place_arguments may reorder ``E_ARGS``)."""
    p = e.p
    e.for_("so_k", 0, count, lambda: e.st(e.add(_e(e, E_LIVE), e.add(32, p["so_k"])), e.ld(e.add(_e(e, E_ARGS), p["so_k"]))))


def _foreign_abi(e: E, obj, name: str):
    """``name``: 1 when ``obj`` declares the ``sysv-x86_64-c`` ABI."""
    from xax_selfhost_views_backend import _FOREIGN_PREFIX, _payload_uleb

    p = e.p
    abi = b"sysv-x86_64-c"
    e.var(name, 1)
    e.var(f"{name}_at", _at(e, G_PAY, obj))
    _payload_uleb(e, f"{name}_at")
    for k, value in enumerate(_FOREIGN_PREFIX):
        e.if_(e.ne(e.rd(e.add(p[f"{name}_at"], k)), value), lambda: e.set(name, 0))
    e.set(f"{name}_at", e.add(p[f"{name}_at"], len(_FOREIGN_PREFIX)))
    e.if_(e.ne(_payload_uleb(e, f"{name}_at"), len(abi)), lambda: e.set(name, 0))
    for k, value in enumerate(abi):
        e.if_(e.ne(e.rd(e.add(p[f"{name}_at"], k)), value), lambda: e.set(name, 0))


def _node_fn(tables, part: str):
    """One node of block ``bi`` (index ``m``): 1, or INELIGIBLE where the bootstrap returns -1.  ``part`` "dispatch" skips
    the nodes another instruction emits, then tries part "a" (tables, arithmetic, division; 0 when not its node) and
    part "b" (the rest); the parts keep each graph within what the XAX facts engine models."""
    def build(e: E):
        p = e.p
        e.var("nd_block", _block_at(e, p["bi"]))
        block = p["nd_block"]
        e.var("nd_node", _node_at(e, block, p["m"]))
        node = p["nd_node"]
        m = p["m"]
        e.var("nd_res", e.sel(e.ne(_f(e, node, N_NRES), 0), _output(e, node, 0), NONE))
        result = p["nd_res"]
        if part == "dispatch":
            # Emitted by the terminator (membership bit test, branch table), or by an access or compare that uses it.
            for slot in (R_MEMB, R_BTAB):
                e.var("nd_rec", e.ld(e.add(_ra(e, slot), p["bi"])))
                e.if_(e.ne(p["nd_rec"], NONE), lambda: e.if_(e.ne(e.ld(e.add(e.ld(e.add(p["nd_rec"], 3)), m)), 0), lambda: e.give(1)))
            skip = e.either(e.ne(_rtg(e, T_ERASED, result, 0), 0), e.ne(_rtg(e, T_RMW_ERASED, result, 0), 0), e.ne(_rtg(e, T_CL, result, NONE), NONE))
            e.if_(skip, lambda: e.give(1))
            e.var("nd_part", _call(e, "em_node_a", p["bi"], m))
            e.if_(e.ne(p["nd_part"], 0), lambda: e.give(p["nd_part"]))
            e.give(_call(e, "em_node_b", p["bi"], m))
            return
        e.var("nd_start", _e(e, E_CLEN))
        _se(e, E_HINT, result)
        e.var("nd_op", _eop(e, node))
        op = p["nd_op"]
        e.var("nd_w", _rtg(e, T_RW, result, 0))
        width = p["nd_w"]
        e.var("nd_a", e.sel(e.ne(_f(e, node, N_NOPS), 0), _operand(e, node, 0), NONE))
        e.var("nd_b", e.sel(e.lt(1, _f(e, node, N_NOPS)), _operand(e, node, e.sel(e.lt(1, _f(e, node, N_NOPS)), 1, 0)), NONE))

        def record_range():
            def add():
                e.var("nr_n", _e(e, E_NRANGES))
                _ok(e, e.lt(p["nr_n"], RANGE_CAP))
                e.var("nr_at", e.add(_e(e, E_RANGES), e.mul(p["nr_n"], 4)))
                for field, value in enumerate((p["bi"], m, p["nd_start"], _e(e, E_CLEN))):
                    e.st(e.add(p["nr_at"], field), value)
                _se(e, E_NRANGES, e.add(p["nr_n"], 1))

            e.if_(e.both(e.ne(_e(e, E_REAL), 0), e.ne(_e(e, E_RECORD), 0), e.lt(p["nd_start"], _e(e, E_CLEN))), add)

        def finish():
            record_range()
            e.give(1)

        if part == "a":
            # A value table (ADR-208): movzx destination, byte [r11 + subject].
            def value_table():
                e.var("nd_subject", _rt(e, T_VT_SUBJECT, result))
                e.var("nd_reg", _ensure(e, p["nd_subject"], m))
                _retire(e, m, p["nd_subject"])
                bound = e.ne(_rt(e, T_REG, p["nd_subject"]), NONE)
                e.var("nd_dst", _acquire(e, m, (e.sel(bound, p["nd_subject"], NONE),)))
                e.var("nd_tab", _rt(e, T_VT_TABLE, result))
                _call(e, "table_address", e.ld(e.add(p["nd_tab"], 1)), e.ld(e.add(p["nd_tab"], 2)))
                _scaled_load(e, p["nd_dst"], SCRATCH, p["nd_reg"], 1, 1)
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.ne(_rtg(e, T_VT_SUBJECT, result, NONE), NONE), value_table)

            def member_value():
                e.var("nd_subject", _rt(e, T_MV_SUBJECT, result))
                e.var("nd_reg", _ensure(e, p["nd_subject"], m))
                _retire(e, m, p["nd_subject"])
                bound = e.ne(_rt(e, T_REG, p["nd_subject"]), NONE)
                e.var("nd_dst", _acquire(e, m, (e.sel(bound, p["nd_subject"], NONE),)))
                _member_bit_test(e, p["nd_reg"], _rt(e, T_MV_LOW, result), _rt(e, T_MV_MASK, result), p["nd_dst"])
                _call(e, "setcc", int(IntCompare.ULT), p["nd_dst"], 1)
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.ne(_rtg(e, T_MV_SUBJECT, result, NONE), NONE), member_value)

            pure = _in(e, op, PURE_BINARY)
            e.var("nd_pure", e.flag(pure))

            def binary_forms():
                _immediate(e, p["nd_b"], width, "nd_ib")
                _immediate(e, p["nd_a"], width, "nd_ia")
                swap = e.both(e.eq(p["nd_ib"], 0), _in(e, op, COMMUTATIVE), e.ne(p["nd_ia"], 0))
                e.if_(swap, lambda: (e.var("nd_t", p["nd_a"]), e.set("nd_a", p["nd_b"]), e.set("nd_b", p["nd_t"]), _immediate(e, p["nd_b"], width, "nd_ib")))

                def with_immediate():
                    left, right = p["nd_a"], p["nd_b"]
                    e.var("nd_value", _cval(e, right))
                    _ensure(e, left, m)
                    e.var("nd_dst", _destination_for(e, m, left))
                    _power(e, p["nd_value"], "nd_shift")
                    e.var("nd_done", 0)

                    def multiply():
                        e.if_(e.ne(p["nd_shift"], NONE), lambda: _shift_imm(e, 1, p["nd_dst"], p["nd_shift"], width),
                              lambda: _imul_imm(e, p["nd_dst"], p["nd_dst"], p["nd_value"], width))
                        e.set("nd_done", 1)

                    e.if_(e.eq(op, _op(Operation.MUL_WRAP)), multiply)

                    def add32():
                        _maximum(e, left, "nd_max")
                        e.var("nd_lmax", e.mul(e.flag(e.eq(p["nd_max_none"], 0)), p["nd_max"]))
                        e.if_(e.lt(e.add(p["nd_lmax"], p["nd_value"]), 1 << 32), lambda: (_group1(e, 0, p["nd_dst"], p["nd_value"], 64), e.set("nd_done", 1)))

                    e.if_(e.both(e.eq(p["nd_done"], 0), e.eq(op, _op(Operation.ADD_WRAP)), e.eq(width, 32)), add32)

                    def group():
                        digit = e.c(0)
                        for operation, code in GROUP1.items():
                            digit = e.add(digit, e.mul(e.flag(e.eq(op, _op(operation))), code))
                        _group1(e, digit, p["nd_dst"], p["nd_value"], width)

                    e.if_(e.eq(p["nd_done"], 0), group)
                    e.if_(e.both(e.lt(width, 64), e.ne(width, 32)), lambda: _and_mask(e, p["nd_dst"], width))
                    _retire(e, m, left, right)
                    _call(e, "define", result, p["nd_dst"])
                    finish()

                e.if_(e.ne(p["nd_ib"], 0), with_immediate)
                # Register operands.
                left, right = _operand(e, node, 0), _operand(e, node, 1)
                e.var("nd_l", left)
                e.var("nd_r", right)
                e.var("nd_lr", _ensure(e, p["nd_l"], m))
                e.var("nd_rr", _ensure(e, p["nd_r"], m, (p["nd_l"],)))
                e.var("nd_dst", 0)
                e.var("nd_src", p["nd_rr"])
                distinct = e.ne(p["nd_l"], p["nd_r"])

                def into_right():
                    e.set("nd_dst", p["nd_rr"])
                    e.set("nd_src", p["nd_lr"])
                    _call(e, "unbind", p["nd_r"])

                def fresh():
                    e.set("nd_dst", _acquire(e, m, (p["nd_l"], p["nd_r"])))
                    _mov(e, p["nd_dst"], p["nd_lr"], width)

                e.if_(e.both(_consumable(e, p["nd_l"], m), distinct), lambda: (e.set("nd_dst", p["nd_lr"]), _call(e, "unbind", p["nd_l"])),
                      lambda: e.if_(e.both(_consumable(e, p["nd_r"], m), _in(e, op, COMMUTATIVE), distinct), into_right, fresh))
                _call(e, "arith", op, p["nd_dst"], p["nd_src"], e.sel(e.eq(width, 64), 64, 32))
                narrow_carry = e.both(e.lt(width, 32), e.not_(_in(e, op, (_op(Operation.BIT_AND), _op(Operation.BIT_OR), _op(Operation.BIT_XOR)))))
                e.if_(narrow_carry, lambda: _and_mask(e, p["nd_dst"], width))
                _retire(e, m, p["nd_l"], p["nd_r"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.ne(p["nd_pure"], 0), binary_forms)

            def division():
                e.var("nd_dividend", p["nd_a"])
                e.var("nd_divisor", p["nd_b"])
                e.var("nd_cd", e.sel(_constant(e, p["nd_divisor"]), _cval(e, p["nd_divisor"]), 0))
                _power(e, p["nd_cd"], "nd_shift")

                def by_power():
                    e.var("nd_mask", e.sub(p["nd_cd"], 1))
                    _ensure(e, p["nd_dividend"], m)
                    e.var("nd_dst", _destination_for(e, m, p["nd_dividend"]))

                    def quotient():
                        e.if_(e.ne(p["nd_shift"], 0), lambda: _shift_imm(e, 0, p["nd_dst"], p["nd_shift"], width))

                    def remainder():
                        e.if_(e.lt(p["nd_mask"], 1 << 31), lambda: _group1(e, 4, p["nd_dst"], p["nd_mask"], width), lambda: e.if_(
                            e.eq(p["nd_mask"], 0xFFFFFFFF), lambda: _mov(e, p["nd_dst"], p["nd_dst"], 32),
                            lambda: (_load_constant(e, SCRATCH, p["nd_mask"]), _call(e, "arith", _op(Operation.BIT_AND), p["nd_dst"], SCRATCH, width))))

                    e.if_(e.eq(op, _op(Operation.UDIV)), quotient, remainder)
                    _retire(e, m, p["nd_dividend"], p["nd_divisor"])
                    _call(e, "define", result, p["nd_dst"])
                    finish()

                e.if_(e.ne(p["nd_shift"], NONE), by_power)
                fixed = (1 << RAX) | (1 << RDX)
                e.var("nd_dr", _ensure(e, p["nd_divisor"], m, (p["nd_dividend"],), fixed))
                e.if_(e.eq(p["nd_cd"], 0), lambda: (_test(e, p["nd_dr"], width), _trap_if(e, 0x84, INTEGER_DIVIDE_BY_ZERO)))
                for register in (RDX, RAX):
                    def occupied(register=register):
                        e.var("nd_occ", _regv(e, register))
                        skip_it = e.either(e.eq(p["nd_occ"], NONE), e.both(e.eq(register, RAX), e.eq(p["nd_occ"], p["nd_dividend"])))

                        def evict():
                            def move_dividend():
                                e.var("nd_moved", _acquire(e, m, (p["nd_dividend"], p["nd_divisor"]), fixed))
                                _mov(e, p["nd_moved"], register)
                                _call(e, "unbind", p["nd_dividend"])
                                _call(e, "bind", p["nd_dividend"], p["nd_moved"])

                            e.if_(e.eq(p["nd_occ"], p["nd_dividend"]), move_dividend, lambda: e.if_(
                                e.lt(_call(e, "next_use", p["nd_occ"], e.sub(m, 1)), FAR), lambda: _call(e, "spill", p["nd_occ"], 0),
                                lambda: _call(e, "release", p["nd_occ"])))

                        e.if_(e.not_(skip_it), evict)

                    occupied()
                e.var("nd_xr", _ensure(e, p["nd_dividend"], m, (p["nd_divisor"],), 1 << RDX))
                e.if_(e.either(e.ne(_last_use(e, p["nd_dividend"]), m), e.ne(_rt(e, T_HOME, p["nd_dividend"]), NONE)), lambda: _call(e, "spill", p["nd_dividend"], 1))
                e.if_(e.ne(p["nd_xr"], RAX), lambda: _mov(e, RAX, p["nd_xr"]))
                _zero32(e, RDX)
                _rex(e, e.flag(e.eq(width, 64)), 0, 0, p["nd_dr"])
                _bx(e, e.add(0xF7, e.mul(e.add(0xF0, _low3(e, p["nd_dr"])), 256)), 2)
                for register in (RAX, RDX):
                    e.var("nd_occ", _regv(e, register))
                    e.if_(e.ne(p["nd_occ"], NONE), lambda: _call(e, "unbind", p["nd_occ"]))
                _retire(e, m, p["nd_dividend"], p["nd_divisor"])
                _call(e, "define", result, e.sel(e.eq(op, _op(Operation.UDIV)), RAX, RDX))
                finish()

            e.if_(_in(e, op, (_op(Operation.UDIV), _op(Operation.UREM))), division)
            e.if_(_in(e, op, tuple(_op(o) for o in (Operation.CONSTANT, Operation.STACK_ALLOC, Operation.STACK_END, Operation.LINK_TARGET))), finish)
            e.give(0)  # not a part "a" node

        if part == "b":
            def indirect():
                _machine_operands(e, node)
                e.var("nd_n", p["mo_n"])
                _save_operands(e, p["nd_n"])
                # (arguments..., callee) into (argument registers..., rax)
                e.var("nd_callee", e.ld(_e(e, E_ARGS)))
                e.for_("nd_k", 1, p["nd_n"], lambda: (e.st(e.add(_e(e, E_ARGS), e.sub(p["nd_k"], 1)), e.ld(e.add(_e(e, E_ARGS), p["nd_k"]))),
                                                       e.st(e.add(_e(e, E_REGS), e.sub(p["nd_k"], 1)), _select_register(e, e.sub(p["nd_k"], 1), ARGUMENT_REGISTERS))))
                e.st(e.add(_e(e, E_ARGS), e.sub(p["nd_n"], 1)), p["nd_callee"])
                e.st(e.add(_e(e, E_REGS), e.sub(p["nd_n"], 1)), RAX)
                _se(e, E_NARGS, p["nd_n"])
                _call(e, "place_arguments", m)
                _bx(e, 0xD0FF, 2)
                _call(e, "after_call", m)
                _retire_arguments(e, m, p["nd_n"])
                _define_first_result(e, node, RAX, aliases=False)
                finish()

            e.if_(e.eq(op, _op(Operation.CALL_INDIRECT)), indirect)
            e.if_(e.both(e.eq(op, _op(Operation.INT_COMPARE)), e.eq(e.ld(e.add(_ra(e, R_FUSED), p["bi"])), m)), finish)

            def compare():
                left, right = p["nd_a"], p["nd_b"]
                _ensure(e, left, m)
                _immediate(e, right, _width(e, left), "nd_ic")
                e.if_(e.eq(p["nd_ic"], 0), lambda: _ensure(e, right, m, (left,)))
                e.var("nd_dst", _acquire(e, m, (left, right)))
                _zero32(e, p["nd_dst"])
                _call(e, "em_compare", m, left, right)
                _retire(e, m, left, right)
                _call(e, "setcc", _attribute(e, node, 0), p["nd_dst"], 0)
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.INT_COMPARE)), compare)

            def rotate():
                _ensure(e, p["nd_a"], m)
                e.var("nd_dst", _destination_for(e, m, p["nd_a"]))
                e.var("nd_amount", _attribute(e, node, 0))
                e.if_(e.ne(p["nd_amount"], 0), lambda: (_rex(e, e.flag(e.lt(32, width)), 0, 0, p["nd_dst"]),
                                                        _bx(e, e.add(e.add(0xC1, e.mul(e.add(0xC8, _low3(e, p["nd_dst"])), 256)), e.mul(p["nd_amount"], 1 << 16)), 3)))
                _retire(e, m, p["nd_a"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.ROTATE_RIGHT)), rotate)

            def truncate():
                _ensure(e, p["nd_a"], m)
                e.var("nd_dst", _destination_for(e, m, p["nd_a"]))
                _maximum(e, p["nd_a"], "nd_max")
                fits = e.both(e.eq(p["nd_max_none"], 0), e.lt(width, 64), e.lt(p["nd_max"], _pow2(e, width)))
                e.if_(e.not_(fits), lambda: e.if_(e.eq(width, 32), lambda: _mov(e, p["nd_dst"], p["nd_dst"], 32), lambda: _and_mask(e, p["nd_dst"], width)))
                _retire(e, m, p["nd_a"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.INT_TRUNCATE)), truncate)

            def copy():
                e.var("nd_pin", _rt(e, T_PIN, result))
                shared = e.both(e.ne(p["nd_pin"], NONE), e.eq(p["nd_pin"], _pinned(e, p["nd_a"])))
                e.if_(shared, lambda: (_call(e, "bind", result, p["nd_pin"]), _retire(e, m, p["nd_a"]), finish()))
                _ensure(e, p["nd_a"], m)
                e.var("nd_dst", _destination_for(e, m, p["nd_a"]))
                _retire(e, m, p["nd_a"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(_in(e, op, COPY), copy)

            def offset():
                e.if_(e.ne(_rt(e, T_FOLD_BASE, result), NONE), lambda: (_retire(e, m, p["nd_a"]), finish()))
                _ensure(e, p["nd_a"], m)
                e.var("nd_dst", _destination_for(e, m, p["nd_a"]))
                e.var("nd_disp", _attribute(e, node, 0))
                e.if_(e.ne(p["nd_disp"], 0), lambda: _lea(e, p["nd_dst"], p["nd_dst"], p["nd_disp"]))
                _retire(e, m, p["nd_a"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.ADDRESS_OFFSET)), offset)

            def function_address():
                e.var("nd_dst", _acquire(e, m))
                e.var("nd_target", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
                _ok(e, e.ne(p["nd_target"], NONE))
                e.var("nd_abi", _call(e, "entry_abi", _vf(e, G_VTYPE, result)))
                from xax_selfhost_x86_64_general import EA_LEND, EA_SYSV

                def real():
                    _bx(e, e.add(e.add(0x48, e.mul(_hi(e, p["nd_dst"]), 4)), e.add(0x8D00, e.mul(e.add(0x05, e.mul(_low3(e, p["nd_dst"]), 8)), 1 << 16))), 3, True)
                    _record_call(e, p["nd_target"], e.flag(e.either(e.eq(p["nd_abi"], EA_SYSV), e.eq(p["nd_abi"], EA_LEND))))
                    _bx(e, 0, 4, True)

                e.if_(e.ne(_e(e, E_REAL), 0), real)
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.FUNCTION_ADDRESS)), function_address)

            def pointer_address():
                e.if_(e.ne(width, 64), lambda: e.give(INELIGIBLE))
                _ensure(e, p["nd_a"], m)
                e.var("nd_dst", _destination_for(e, m, p["nd_a"]))
                _retire(e, m, p["nd_a"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.POINTER_ADDRESS)), pointer_address)
            def rebase():
                # ADR-092: trap unless view <= address <= view + span and the distance is a multiple of the alignment.
                view, address = p["nd_a"], p["nd_b"]
                e.var("nd_extent", _call(e, "extent", view))
                e.var("nd_span", e.sub(p["nd_extent"], _attribute(e, node, 0)))
                e.var("nd_neg", e.flag(e.lt(p["nd_extent"], _attribute(e, node, 0))))
                e.var("nd_align", _pointer_alignment(e, _vf(e, G_VTYPE, result)))
                e.if_(e.either(e.ne(_width(e, address), 64), e.both(e.eq(p["nd_neg"], 0), e.le(1 << 31, p["nd_span"]))), lambda: e.give(INELIGIBLE))
                _proven_rebase(e, view, address, "nd_proven")

                def check():
                    e.var("nd_base", _ensure(e, view, m))
                    e.var("nd_ar", _ensure(e, address, m, (view,)))
                    _mov(e, SCRATCH, p["nd_ar"])
                    _call(e, "arith", _op(Operation.SUB_WRAP), SCRATCH, p["nd_base"], 64)
                    _power(e, p["nd_align"], "nd_shift")
                    e.if_(e.ne(p["nd_shift"], 0), lambda: _bx(e, e.add(0xCBC149, e.mul(p["nd_shift"], 1 << 24)), 4))  # ror r11, shift
                    _ok(e, e.eq(p["nd_neg"], 0))  # a negative span fails _compare_immediate
                    e.var("nd_q", p["nd_span"])
                    e.for_("nd_k", 0, p["nd_shift"], lambda: e.set("nd_q", e.udiv(p["nd_q"], 2)))
                    _compare_immediate(e, SCRATCH, p["nd_q"])
                    _trap_if(e, 0x87)

                e.if_(e.ne(p["nd_proven"], 0), lambda: _ensure(e, address, m), check)
                e.var("nd_dst", _destination_for(e, m, address, (view,)))
                _retire(e, m, view, address)
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.POINTER_REBASE)), rebase)

            def link_follow():
                e.var("nd_link", p["nd_b"])
                e.var("nd_lr", _ensure(e, p["nd_link"], m, (p["nd_a"],)))
                nonzero = e.both(e.ne(_rt(e, T_NONZERO, p["nd_link"]), 0), _is_param(e, p["nd_link"]), e.eq(_pos_block(e, p["nd_link"]), p["bi"]))
                e.if_(e.not_(nonzero), lambda: (_test(e, p["nd_lr"], 64), _trap_if(e, 0x84)))
                e.var("nd_dst", _destination_for(e, m, p["nd_link"]))
                _retire(e, m, p["nd_a"], p["nd_link"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.LINK_FOLLOW)), link_follow)

            def heap_view():
                e.var("nd_sr", _ensure(e, p["nd_a"], m))
                _test(e, p["nd_sr"], 64)
                _trap_if(e, 0x84)
                e.var("nd_dst", _destination_for(e, m, p["nd_a"]))
                _retire(e, m, p["nd_a"])
                _call(e, "define", result, p["nd_dst"])
                finish()

            e.if_(e.eq(op, _op(Operation.HEAP_VIEW)), heap_view)
            e.if_(_in(e, op, MEMORY), lambda: (_call(e, "em_memory", p["bi"], m), finish()))
            e.if_(e.eq(op, DIRECT_CALL), lambda: (e.var("nd_dc", _call(e, "direct_call", p["bi"], m)), e.if_(e.eq(p["nd_dc"], 2), lambda: e.give(1)), finish()))
            e.if_(e.eq(op, _op(Operation.CALL_FOREIGN)), lambda: (e.var("nd_f", _call(e, "foreign_call", p["bi"], m)),
                                                                   e.if_(e.eq(p["nd_f"], INELIGIBLE), lambda: e.give(INELIGIBLE)), finish()))
            e.if_(e.not_(_in(e, op, tuple(_op(o) for o in RESOURCE_EFFECT_OPERATIONS))), lambda: e.give(INELIGIBLE))
            finish()
    return _function(("bi", "m"), build, tables)


def _pointer_alignment(e: E, type_obj):
    """``_decode_pointer_type(type)[2]``: form, space, element, permission, alignment."""
    from xax_selfhost_views_backend import _payload_uleb

    e.var("pa_at", e.add(_at(e, G_PAY, type_obj), 1))
    for _field in range(3):
        _payload_uleb(e, "pa_at")
    e.var("pa_align", _payload_uleb(e, "pa_at"))
    return e.p["pa_align"]


def _multiple_of(e: E, value, factor, name: str):
    """``multiple_of(value, factor)``: a constant multiple, or a ``mul`` by a constant multiple (a non-constant
    multiplier counts as 1)."""
    from xax_selfhost_general_regalloc import _definition

    p = e.p
    e.var(name, 0)
    e.var(f"{name}_v", value)

    def constant():
        e.set(name, e.flag(e.eq(e.urem(_cval(e, p[f"{name}_v"]), factor), 0)))

    def product():
        _definition(e, p[f"{name}_v"], f"{name}_d")

        def mul():
            e.var(f"{name}_r", _operand(e, p[f"{name}_d"], 1))
            e.var(f"{name}_c", e.sel(_constant(e, p[f"{name}_r"]), _cval(e, p[f"{name}_r"]), 1))
            e.set(name, e.flag(e.eq(e.urem(p[f"{name}_c"], factor), 0)))

        e.if_(e.both(e.ne(p[f"{name}_d"], NONE), e.eq(_eop(e, e.sel(e.ne(p[f"{name}_d"], NONE), p[f"{name}_d"], 0)), _op(Operation.MUL_WRAP))), mul)

    e.if_(_constant(e, p[f"{name}_v"]), constant, product)


def _proven_rebase(e: E, view, address, name: str):
    """``proven_rebase(node)``: ``pointer_rebase(view, pointer_address(view) + offset)`` with the offset provably in
    range and aligned (the first operand order whose base is that pointer address decides)."""
    from xax_selfhost_general_regalloc import _definition

    p = e.p
    e.var(name, 0)
    e.var(f"{name}_view", view)
    _definition(e, address, f"{name}_add")

    def add():
        e.var(f"{name}_done", 0)
        for first in (0, 1):
            def attempt(first=first):
                e.var(f"{name}_base", _operand(e, p[f"{name}_add"], first))
                e.var(f"{name}_off", _operand(e, p[f"{name}_add"], 1 - first))
                _definition(e, p[f"{name}_base"], f"{name}_x")
                exposed = e.both(e.ne(p[f"{name}_x"], NONE), e.eq(_eop(e, e.sel(e.ne(p[f"{name}_x"], NONE), p[f"{name}_x"], 0)), _op(Operation.POINTER_ADDRESS)))

                def decide():
                    e.set(f"{name}_done", 1)
                    e.var(f"{name}_ext", _call(e, "extent", p[f"{name}_view"]))
                    e.var(f"{name}_span", e.sub(p[f"{name}_ext"], _attribute(e, p["nd_node"], 0)))
                    _maximum(e, p[f"{name}_off"], f"{name}_max")
                    _multiple_of(e, p[f"{name}_off"], p["nd_align"], f"{name}_mul")
                    fits = e.both(e.eq(p[f"{name}_max_none"], 0), e.le(_attribute(e, p["nd_node"], 0), p[f"{name}_ext"]),
                                  e.le(p[f"{name}_max"], p[f"{name}_span"]), e.ne(p[f"{name}_mul"], 0))
                    e.set(name, e.flag(fits))

                e.if_(e.both(e.eq(p[f"{name}_done"], 0), exposed), lambda: e.if_(e.eq(_operand(e, p[f"{name}_x"], 0), p[f"{name}_view"]), decide))

            attempt()

    e.if_(e.both(e.ne(p[f"{name}_add"], NONE), e.eq(_eop(e, e.sel(e.ne(p[f"{name}_add"], NONE), p[f"{name}_add"], 0)), _op(Operation.ADD_WRAP))), add)


def _pow2(e: E, width):
    """``1 << width`` for 1..63."""
    e.var("pw_x", 1)
    e.for_("pw_k", 0, width, lambda: e.set("pw_x", e.mul(e.p["pw_x"], 2)))
    return e.p["pw_x"]


def _and_mask(e: E, register, width):
    """``_and_immediate(register, (1 << width) - 1, width=32)``."""
    _and_imm(e, register, e.sub(_pow2(e, width), 1), 0)


def _select_register(e: E, index, registers):
    result = e.c(registers[-1])
    for position in range(len(registers) - 2, -1, -1):
        result = e.sel(e.eq(index, position), registers[position], result)
    return result


def _define_first_result(e: E, node, register, aliases: bool):
    """Define the node's first machine result (not a call alias when ``aliases``) in ``register``; ``dr_first`` keeps it."""
    p = e.p
    e.var("dr_first", NONE)

    def each():
        e.var("dr_v", _output(e, node, p["dr_k"]))
        machine = e.ne(_width(e, p["dr_v"]), 0)
        if aliases:
            machine = e.both(machine, e.eq(_rt(e, T_ALIAS, p["dr_v"]), NONE))
        e.if_(e.both(machine, e.eq(p["dr_first"], NONE)), lambda: e.set("dr_first", p["dr_v"]))

    e.for_("dr_k", 0, _f(e, node, N_NRES), each)
    e.if_(e.ne(p["dr_first"], NONE), lambda: _call(e, "define", p["dr_first"], register))


def _compare_fn(tables):
    """``emit_compare(position, left, right)``."""
    def build(e: E):
        p = e.p
        left, right = p["l"], p["r"]
        e.var("cm_cl", _rt(e, T_CL, left))
        e.var("cm_loaded", e.sel(e.ne(p["cm_cl"], NONE), left, e.sel(e.ne(_rt(e, T_CL, right), NONE), right, NONE)))

        def from_memory():
            e.var("cm_other", e.sel(e.eq(p["cm_loaded"], left), right, left))
            e.var("cm_rec", _rt(e, T_CL, p["cm_loaded"]))
            e.var("cm_bv", e.ld(p["cm_rec"]))
            e.var("cm_iv", e.ld(e.add(p["cm_rec"], 1)))
            e.var("cm_base", _ensure(e, p["cm_bv"], p["pos"]))
            e.var("cm_index", NONE)
            e.if_(e.ne(p["cm_iv"], NONE), lambda: e.set("cm_index", _ensure(e, p["cm_iv"], p["pos"], (p["cm_bv"],))))
            e.var("cm_or", _ensure(e, p["cm_other"], p["pos"], (p["cm_bv"], p["cm_iv"])))
            _call(e, "memop", e.sel(e.eq(p["cm_loaded"], left), 0x39, 0x3B), p["cm_or"], p["cm_base"], p["cm_index"], e.ld(e.add(p["cm_rec"], 2)),
                  e.ld(e.add(p["cm_rec"], 3)), e.flag(e.eq(_width(e, p["cm_loaded"]), 64)))
            e.give(1)

        e.if_(e.ne(p["cm_loaded"], NONE), from_memory)
        e.var("cm_w", _width(e, left))
        _immediate(e, right, p["cm_w"], "cm_imm")
        e.var("cm_lr", _ensure(e, left, p["pos"]))
        e.if_(e.ne(p["cm_imm"], 0), lambda: e.if_(e.eq(p["cm_imm_v"], 0), lambda: _test(e, p["cm_lr"], p["cm_w"]),
                                                  lambda: _group1(e, 7, p["cm_lr"], p["cm_imm_v"], p["cm_w"])),
              lambda: (e.var("cm_rr", _ensure(e, right, p["pos"], (left,))), _cmp_rr(e, p["cm_lr"], p["cm_rr"], p["cm_w"])))
        e.give(1)
    return _function(("pos", "l", "r"), build, tables)


def _memory_fn(tables):
    """The ``_MEMORY`` node ``m`` of block ``bi`` (loads, stores, checked accesses, read-modify-write, prefetches)."""
    def build(e: E):
        p = e.p
        m = p["m"]
        e.var("me_node", _node_at(e, _block_at(e, p["bi"]), m))
        node = p["me_node"]
        e.var("me_op", _eop(e, node))
        op = p["me_op"]
        e.var("me_res", e.sel(e.ne(_f(e, node, N_NRES), 0), _output(e, node, 0), NONE))
        result = p["me_res"]
        e.var("me_p0", _operand(e, node, 0))
        e.var("me_fb", _rt(e, T_FOLD_BASE, p["me_p0"]))
        e.var("me_ptr", e.sel(e.ne(p["me_fb"], NONE), p["me_fb"], p["me_p0"]))
        e.var("me_disp", e.sel(e.ne(p["me_fb"], NONE), _rt(e, T_FOLD_DISP, p["me_p0"]), 0))
        pointer = p["me_ptr"]
        e.var("me_base", _ensure(e, pointer, m))
        e.var("me_size", _attribute(e, node, 0))

        def hinted_ok(register):
            e.var("me_hint", _sget(e, T_HINT, result, NONE))
            return e.either(e.eq(p["me_hint"], NONE), e.eq(p["me_hint"], register), e.ne(_regv(e, e.sel(e.ne(p["me_hint"], NONE), p["me_hint"], 0)), NONE))

        def load():
            e.var("me_ok", e.flag(e.both(_consumable(e, pointer, m), hinted_ok(p["me_base"]))))
            e.var("me_reg", 0)
            e.if_(e.ne(p["me_ok"], 0), lambda: (e.set("me_reg", p["me_base"]), _call(e, "unbind", pointer)),
                  lambda: e.set("me_reg", _acquire(e, m, (pointer,))))
            _call(e, "load_exact", p["me_reg"], p["me_base"], p["me_disp"], p["me_size"])
            _retire(e, m, pointer)
            _call(e, "define", result, p["me_reg"])
            e.give(1)

        e.if_(_in(e, op, (_op(Operation.LOAD_BITS_LE), _op(Operation.RAW_LOAD_BITS_LE))), load)

        def store():
            e.var("me_value", _operand(e, node, 1))
            e.var("me_vr", _ensure(e, p["me_value"], m, (pointer,)))
            _call(e, "store_exact", p["me_vr"], p["me_base"], p["me_disp"], p["me_size"])
            _retire(e, m, pointer, p["me_value"])
            e.give(1)

        e.if_(e.eq(op, _op(Operation.STORE_BITS_LE)), store)
        # Checked accesses.
        e.var("me_i0", _operand(e, node, 1))
        e.var("me_sb", _rt(e, T_SCALE_BASE, p["me_i0"]))
        e.var("me_iv", e.sel(e.ne(p["me_sb"], NONE), p["me_sb"], p["me_i0"]))
        e.var("me_scale", e.sel(e.ne(p["me_sb"], NONE), _rt(e, T_SCALE, p["me_i0"]), 1))
        index_value = p["me_iv"]
        e.var("me_extent", _call(e, "extent", pointer))
        e.var("me_last", e.sub(p["me_extent"], p["me_size"]))
        e.var("me_index", _ensure(e, index_value, m, (pointer,)))

        def check():
            e.var("me_seen", 0)
            e.var("me_ck", _e(e, E_CHECKED))
            e.for_("me_k", 0, _e(e, E_NCHECKED), lambda: e.if_(e.both(
                e.eq(e.ld(e.add(p["me_ck"], e.mul(p["me_k"], 3))), pointer), e.eq(e.ld(e.add(p["me_ck"], e.add(e.mul(p["me_k"], 3), 1))), index_value),
                e.eq(e.ld(e.add(p["me_ck"], e.add(e.mul(p["me_k"], 3), 2))), p["me_last"])), lambda: e.set("me_seen", 1)))
            e.var("me_proven", _call(e, "access_proven", node))

            def emit_check():
                e.var("me_nc", _e(e, E_NCHECKED))
                _ok(e, e.lt(p["me_nc"], CHECK_CAP))
                for field, value in enumerate((pointer, index_value, p["me_last"])):
                    e.st(e.add(p["me_ck"], e.add(e.mul(p["me_nc"], 3), field)), value)
                _se(e, E_NCHECKED, e.add(p["me_nc"], 1))
                _compare_immediate(e, p["me_index"], p["me_last"])
                _trap_if(e, 0x87)

            e.if_(e.both(e.eq(p["me_proven"], 0), e.eq(p["me_seen"], 0)), emit_check)

        e.if_(e.lt(p["me_extent"], p["me_size"]), lambda: _b(e, b"\x0f\x0b"), check)
        e.var("me_rmw", _rtg(e, T_RMW, result, NONE))

        def rmw():
            e.var("me_val", p["me_rmw"])
            e.if_(e.lt(p["me_val"], 128), lambda: (_scaled(e, 0x83, 1, 0, p["me_base"], p["me_index"], p["me_scale"], p["me_size"]), _bx(e, p["me_val"], 1)),
                  lambda: (_scaled(e, 0x81, 1, 0, p["me_base"], p["me_index"], p["me_scale"], p["me_size"]), _bx(e, e.and_(p["me_val"], 0xFFFFFFFF), 4)))
            _retire(e, m, pointer, index_value)
            e.give(1)

        e.if_(e.ne(p["me_rmw"], NONE), rmw)

        def checked_load():
            ok = e.both(_consumable(e, index_value, m), e.ne(index_value, pointer), hinted_ok(p["me_index"]))
            e.var("me_ok", e.flag(ok))
            e.var("me_reg", 0)
            e.if_(e.ne(p["me_ok"], 0), lambda: (e.set("me_reg", p["me_index"]), _call(e, "unbind", index_value)),
                  lambda: e.set("me_reg", _acquire(e, m, (pointer, index_value))))
            _scaled_load(e, p["me_reg"], p["me_base"], p["me_index"], p["me_scale"], p["me_size"])
            _retire(e, m, pointer, index_value)
            _marks_of(e, result, "me_marks")

            def prefetch():
                _call(e, "bind", result, p["me_reg"])

                def each():
                    e.var("me_array", e.ld(e.add(p["me_marks"], e.mul(p["me_q"], 2))))
                    e.var("me_ar", _ensure(e, p["me_array"], m, (result,)))
                    _call(e, "scaled", 0x180F, 2, 1, p["me_ar"], p["me_reg"], e.ld(e.add(p["me_marks"], e.add(e.mul(p["me_q"], 2), 1))), 4, 0)
                    _retire(e, m, p["me_array"])

                e.for_("me_q", 0, p["me_marks_n"], each)
                _call(e, "unbind", result)

            e.if_(e.ne(p["me_marks_n"], 0), prefetch)
            _call(e, "define", result, p["me_reg"])
            e.give(1)

        e.if_(e.eq(op, _op(Operation.CHECKED_LOAD_BITS_LE)), checked_load)
        e.var("me_value", _operand(e, node, 2))
        e.var("me_vr", _ensure(e, p["me_value"], m, (pointer, index_value)))
        _scaled_store(e, p["me_vr"], p["me_base"], p["me_index"], p["me_scale"], p["me_size"])
        _retire(e, m, pointer, index_value, p["me_value"])
        e.give(1)
    return _function(("bi", "m"), build, tables)


def _direct_call_fn(tables):
    """``CALL_DIRECT`` node ``m``: 1 (lowered), 2 (an erased proof call: skipped, no range)."""
    def build(e: E):
        p = e.p
        m = p["m"]
        e.var("dc_node", _node_at(e, _block_at(e, p["bi"]), m))
        node = p["dc_node"]
        _callee_object(e, node, "dc_callee")
        _ok(e, e.ne(p["dc_callee"], NONE))
        e.if_(e.ne(_call(e, "erased", p["dc_callee"]), 0), lambda: e.give(2))
        _machine_operands(e, node)
        e.var("dc_n", p["mo_n"])
        _save_operands(e, p["dc_n"])
        e.for_("dc_k", 0, p["dc_n"], lambda: e.st(e.add(_e(e, E_REGS), p["dc_k"]), _select_register(e, p["dc_k"], ARGUMENT_REGISTERS)))
        _se(e, E_NARGS, p["dc_n"])
        _call(e, "place_arguments", m)

        def real():
            _bx(e, 0xE8, 1, True)
            _record_call(e, p["dc_callee"], 0)
            _bx(e, 0, 4, True)

        e.if_(e.ne(_e(e, E_REAL), 0), real)
        _call(e, "after_call", m)
        _retire_arguments(e, m, p["dc_n"])
        _define_first_result(e, node, RAX, aliases=True)
        e.var("dc_first", p["dr_first"])

        def alias():
            e.var("dc_a", _output(e, node, p["dc_k"]))
            e.var("dc_o", _rt(e, T_ALIAS, p["dc_a"]))

            def copy():
                e.var("dc_src", _ensure(e, p["dc_o"], e.add(m, 1), (p["dc_first"],)))
                e.var("dc_reg", _acquire(e, e.add(m, 1), (p["dc_o"], p["dc_first"])))
                _mov(e, p["dc_reg"], p["dc_src"])
                _call(e, "define", p["dc_a"], p["dc_reg"])

            e.if_(e.ne(p["dc_o"], NONE), copy)

        e.for_("dc_k", 0, _f(e, node, N_NRES), alias)
        e.give(1)
    return _function(("bi", "m"), build, tables)


def _startup_name(e: E, obj, name: str):
    """``name``: 1 + the index in ``STARTUP_NAMES`` of a ``linux-x86_64-startup-v1`` declaration's read, else 0."""
    from xax_selfhost_views_backend import _FOREIGN_PREFIX, _payload_uleb

    p = e.p
    e.var(name, 0)
    e.var(f"{name}_ok", 1)
    e.var(f"{name}_at", _at(e, G_PAY, obj))
    _payload_uleb(e, f"{name}_at")
    for k, value in enumerate(_FOREIGN_PREFIX):
        e.if_(e.ne(e.rd(e.add(p[f"{name}_at"], k)), value), lambda: e.set(f"{name}_ok", 0))
    e.set(f"{name}_at", e.add(p[f"{name}_at"], len(_FOREIGN_PREFIX)))
    e.if_(e.ne(_payload_uleb(e, f"{name}_at"), len(STARTUP_ABI)), lambda: e.set(f"{name}_ok", 0))
    for k, value in enumerate(STARTUP_ABI):
        e.if_(e.ne(e.rd(e.add(p[f"{name}_at"], k)), value), lambda: e.set(f"{name}_ok", 0))
    e.set(f"{name}_at", e.add(p[f"{name}_at"], len(STARTUP_ABI)))
    e.set(f"{name}_at", e.add(_payload_uleb(e, f"{name}_at"), p[f"{name}_at"]))  # the library
    e.var(f"{name}_n", _payload_uleb(e, f"{name}_at"))

    def match():
        for index, read in enumerate(STARTUP_NAMES, 1):
            e.var(f"{name}_m", e.flag(e.eq(p[f"{name}_n"], len(read))))
            for k, value in enumerate(read):
                e.if_(e.ne(e.rd(e.add(p[f"{name}_at"], k)), value), lambda: e.set(f"{name}_m", 0))
            e.if_(e.ne(p[f"{name}_m"], 0), lambda index=index: e.set(name, index))

    e.if_(e.ne(p[f"{name}_ok"], 0), match)


def _startup_read_fn(tables):
    """``emit_startup_read(name, extent)`` (``read`` is 1 + its ``STARTUP_NAMES`` index); declined for an unknown read,
    where the bootstrap fails (LINUX-STARTUP-NAME)."""
    def build(e: E):
        p = e.p
        read = p["read"]
        _lea(e, SCRATCH, RSP, _e(e, E_FRAME))  # r11 = &argc

        def loop_until_zero(test: bytes, step: bytes):
            e.var("sr_top", _new_label(e))
            e.var("sr_done", _new_label(e))
            _label(e, p["sr_top"])
            _b(e, test)
            _jcc(e, 0x84, p["sr_done"])
            _b(e, step)
            _jump(e, 0xE9, 1, p["sr_top"])
            _label(e, p["sr_done"])

        def environment_count():  # rsi = &envp[0]; rcx = envc
            _call(e, "load_exact", RAX, SCRATCH, 0, 8)
            _b(e, bytes.fromhex("498d74c310"))  # lea rsi, [r11 + rax*8 + 16]
            _b(e, bytes.fromhex("31c9"))
            loop_until_zero(bytes.fromhex("48833cce00"), bytes.fromhex("4883c101"))

        def string_length_and_copy():  # rsi = string; rax = length, or bytes copied to rdx when extent
            _b(e, bytes.fromhex("31c0"))
            loop_until_zero(bytes.fromhex("803c0600"), bytes.fromhex("4883c001"))

            def bounded():
                e.var("sr_fits", _new_label(e))
                _b(e, bytes.fromhex("4889c1"))  # mov rcx, rax
                _ok(e, e.lt(p["extent"], 1 << 31))  # _cmp_imm32 fails above
                _b(e, bytes.fromhex("4881f9"))
                _bx(e, p["extent"], 4)
                _jcc(e, 0x86, p["sr_fits"])
                _bx(e, 0xB9, 1)
                _bx(e, p["extent"], 4)
                _label(e, p["sr_fits"])
                _b(e, bytes.fromhex("4889c8"))  # mov rax, rcx: the copy returns the copied byte count
                _b(e, bytes.fromhex("4889d7f3a4"))  # mov rdi, rdx; rep movsb

            e.if_(e.ne(p["extent"], 0), bounded)

        def number(name: bytes):
            return STARTUP_NAMES.index(name) + 1

        def argc():
            _call(e, "load_exact", RAX, SCRATCH, 0, 8)

        def argument():
            _b(e, bytes.fromhex("493b3b"))  # cmp rdi, [r11]
            _trap_if(e, 0x83)
            _b(e, bytes.fromhex("498b74fb08"))  # mov rsi, [r11 + rdi*8 + 8]
            string_length_and_copy()

        def envc():
            environment_count()
            _b(e, bytes.fromhex("4889c8"))

        def environment():
            environment_count()
            _b(e, bytes.fromhex("4839cf"))  # cmp rdi, rcx
            _trap_if(e, 0x83)
            _b(e, bytes.fromhex("488b34fe"))  # mov rsi, [rsi + rdi*8]
            string_length_and_copy()

        def auxv():
            environment_count()
            _b(e, bytes.fromhex("488d74ce08"))  # lea rsi, [rsi + rcx*8 + 8]: the first auxv pair
            for label in ("sr_atop", "sr_absent", "sr_found", "sr_end"):
                e.var(label, _new_label(e))
            _label(e, p["sr_atop"])
            _b(e, bytes.fromhex("488b06"))
            _b(e, bytes.fromhex("4885c0"))
            _jcc(e, 0x84, p["sr_absent"])  # AT_NULL ends
            _b(e, bytes.fromhex("4839f8"))
            _jcc(e, 0x84, p["sr_found"])
            _b(e, bytes.fromhex("4883c610"))
            _jump(e, 0xE9, 1, p["sr_atop"])
            _label(e, p["sr_absent"])
            _b(e, bytes.fromhex("31c0"))
            _jump(e, 0xE9, 1, p["sr_end"])
            _label(e, p["sr_found"])
            _b(e, bytes.fromhex("488b4608"))  # mov rax, [rsi + 8]
            _label(e, p["sr_end"])

        e.if_(e.eq(read, number(b"argc")), argc)
        e.if_(e.either(e.eq(read, number(b"arg_length")), e.eq(read, number(b"arg_copy"))), argument)
        e.if_(e.eq(read, number(b"envc")), envc)
        e.if_(e.either(e.eq(read, number(b"env_length")), e.eq(read, number(b"env_copy"))), environment)
        e.if_(e.eq(read, number(b"auxv_value")), auxv)
        _ok(e, e.ne(read, 0))
        e.give(1)
    return _function(("read", "extent"), build, tables)


def _foreign_call_fn(tables):
    """``CALL_FOREIGN`` node ``m``: SysV imports, Linux syscalls, and the startup reads ``argc``/``arg_copy``; 1, or
    INELIGIBLE where the bootstrap returns -1.  Other declarations decline."""
    def build(e: E):
        p = e.p
        m = p["m"]
        e.var("fc_node", _node_at(e, _block_at(e, p["bi"]), m))
        node = p["fc_node"]
        e.var("fc_obj", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
        _ok(e, e.ne(p["fc_obj"], NONE))
        _machine_operands(e, node)
        e.var("fc_n", p["mo_n"])
        _save_operands(e, p["fc_n"])
        e.var("fc_saved", e.add(_e(e, E_LIVE), 32))
        e.var("fc_nres", 0)
        e.for_("fc_k", 0, _f(e, node, N_NRES), lambda: e.if_(e.ne(_width(e, _output(e, node, p["fc_k"])), 0), lambda: e.set("fc_nres", e.add(p["fc_nres"], 1))))
        e.var("fc_rec", _call(e, "syscall", p["fc_obj"], p["fc_n"]))
        e.var("fc_number", e.sel(e.ne(p["fc_rec"], 0), e.ld(e.sel(e.ne(p["fc_rec"], 0), p["fc_rec"], 0)), NONE))

        def sysv():
            _foreign_abi(e, p["fc_obj"], "fc_sysv")
            _ok(e, e.ne(p["fc_sysv"], 0))
            from xax_selfhost_x86_64_general import G_TFMT

            e.if_(e.ne(_g(e, G_TFMT), DYNAMIC_FORMAT), lambda: reject_at(e, lambda: write_dynamic_profile(e)))
            e.if_(e.either(e.lt(6, p["fc_n"]), e.lt(1, p["fc_nres"])), lambda: e.give(INELIGIBLE))
            e.for_("fc_k", 0, p["fc_n"], lambda: e.st(e.add(_e(e, E_REGS), p["fc_k"]), _select_register(e, p["fc_k"], SYSV_REGISTERS)))
            _se(e, E_NARGS, p["fc_n"])
            _call(e, "place_arguments", m)

            def real():
                _bx(e, 0x15FF, 2, True)
                _record_call(e, p["fc_obj"], 0)
                _bx(e, 0, 4, True)

            e.if_(e.ne(_e(e, E_REAL), 0), real)

        def syscall():
            e.var("fc_count", e.ld(e.add(p["fc_rec"], 1)))
            e.var("fc_j", 0)

            def item():
                e.var("fc_tag", e.ld(e.add(p["fc_rec"], e.add(SYSCALL_HEADER, e.mul(p["fc_i"], 2)))))
                e.var("fc_val", e.ld(e.add(p["fc_rec"], e.add(SYSCALL_HEADER + 1, e.mul(p["fc_i"], 2)))))
                e.if_(e.eq(p["fc_tag"], 0), lambda: (
                    e.st(e.add(_e(e, E_ARGS), p["fc_j"]), e.ld(e.add(p["fc_saved"], p["fc_val"]))),
                    e.st(e.add(_e(e, E_REGS), p["fc_j"]), _select_register(e, p["fc_i"], SYSCALL_REGISTERS)),
                    e.set("fc_j", e.add(p["fc_j"], 1))))

            e.for_("fc_i", 0, p["fc_count"], item)
            _se(e, E_NARGS, p["fc_j"])
            _call(e, "place_arguments", m)

            def literal():
                e.var("fc_tag", e.ld(e.add(p["fc_rec"], e.add(SYSCALL_HEADER, e.mul(p["fc_i"], 2)))))
                e.if_(e.ne(p["fc_tag"], 0), lambda: _load_constant(e, _select_register(e, p["fc_i"], SYSCALL_REGISTERS),
                                                                   e.ld(e.add(p["fc_rec"], e.add(SYSCALL_HEADER + 1, e.mul(p["fc_i"], 2))))))

            e.for_("fc_i", 0, p["fc_count"], literal)
            _bx(e, 0xB8, 1)
            _bx(e, p["fc_number"], 4)
            _bx(e, 0x050F, 2)
            e.if_(e.ne(e.ld(e.add(p["fc_rec"], 2)), 0), lambda: _b(e, NULL_ON_ERROR))

        def startup_read():
            """``emit_startup_read`` (ADR-094): the read named by the declaration, result in rax."""
            def write():
                import xax_selfhost_diagnostics as D

                D.text(e, "XAX.NATIVE.STARTUP")
                D.cid(e, graph_cid_words(e, _e(e, E_F)))
                D.text(e, "LINUX-STARTUP-PROCESS-ENTRY")
                D.text(e, "process entry function")
                D.text(e, "called function")

            e.if_(e.eq(_e(e, E_PROCESS), 0), lambda: reject_at(e, write))
            e.var("fc_copy", e.flag(e.either(e.eq(p["fc_start"], STARTUP_NAMES.index(b"arg_copy") + 1), e.eq(p["fc_start"], STARTUP_NAMES.index(b"env_copy") + 1))))
            e.var("fc_extent", 0)
            e.if_(e.ne(p["fc_copy"], 0), lambda: e.set("fc_extent", _call(e, "extent", e.ld(e.add(p["fc_saved"], 1)))))
            e.for_("fc_k", 0, p["fc_n"], lambda: e.st(e.add(_e(e, E_REGS), p["fc_k"]), _select_register(e, p["fc_k"], (RDI, RDX))))
            _se(e, E_NARGS, p["fc_n"])
            _call(e, "place_arguments", m)
            _call(e, "startup_read", p["fc_start"], p["fc_extent"])

        _startup_name(e, p["fc_obj"], "fc_start")
        e.if_(e.ne(p["fc_start"], 0), startup_read, lambda: e.if_(e.eq(p["fc_rec"], 0), sysv, syscall))
        _call(e, "after_call", m)
        _retire_arguments(e, m, p["fc_n"])

        def result():
            e.var("fc_rw", _width(e, p["dr_v"]))
            e.if_(e.lt(p["fc_rw"], 64), lambda: e.if_(e.eq(p["fc_rw"], 32), lambda: _mov(e, RAX, RAX, 32), lambda: _and_mask(e, RAX, p["fc_rw"])))

        # The first machine result: narrowed in rax, then defined there.
        e.var("dr_v", NONE)
        e.for_("fc_k", 0, _f(e, node, N_NRES), lambda: e.if_(e.both(e.eq(p["dr_v"], NONE), e.ne(_width(e, _output(e, node, p["fc_k"])), 0)),
                                                              lambda: e.set("dr_v", _output(e, node, p["fc_k"]))))
        e.if_(e.ne(p["dr_v"], NONE), lambda: (result(), _call(e, "define", p["dr_v"], RAX)))
        e.give(1)
    return _function(("bi", "m"), build, tables)


# -- blocks ---------------------------------------------------------------------------------------------------------

def _machine_params(e: E, block, visit):
    """``visit(machine index, value)`` for each parameter of ``block`` with a machine width."""
    p = e.p
    e.var("mp_i", 0)

    def each():
        e.var("mp_v", e.ld(e.add(_f(e, block, B_INPUTS), p["mp_k"])))
        e.if_(e.ne(_width(e, p["mp_v"]), 0), lambda: (visit(p["mp_i"], p["mp_v"]), e.set("mp_i", e.add(p["mp_i"], 1))))

    e.for_("mp_k", 0, _f(e, block, B_NP), each)


def _begin_fn(tables):
    """Start lowering block ``bi`` (``copy`` 1: an inline copy followed by ``follow``): fresh allocation state, the
    block's uses, edge hints, call positions, the label (padded at a loop header), and the parameters' locations."""
    from xax_selfhost_general_regalloc import _uses_record

    def build(e: E):
        p = e.p
        bi = p["bi"]
        _se(e, E_BI, bi)
        _se(e, E_FOLLOW, p["follow"])
        _se(e, E_RECORD, e.flag(e.eq(p["copy"], 0)))
        _se(e, E_STAMP, e.add(_e(e, E_STAMP), 1))

        def clear():
            e.var("bg_v", _regv(e, p["bg_r"]))
            e.if_(e.ne(p["bg_v"], NONE), lambda: (_set_rt(e, T_REG, p["bg_v"], NONE), _set_regv(e, p["bg_r"], NONE)))

        e.for_("bg_r", 0, 16, clear)
        for slot in (E_NFREE, E_NEXT, E_MAX, E_NCHECKED, E_CAP_ON, E_NMOVES):
            _se(e, slot, 0)
        _se(e, E_HINT, NONE)
        e.var("bg_block", _block_at(e, bi))
        block = p["bg_block"]
        e.var("bg_rec", _uses_record(e, bi))

        def use():
            e.var("bg_uv", e.ld(e.add(e.ld(e.add(p["bg_rec"], U_VALUES)), p["bg_k"])))
            _touch(e, p["bg_uv"])
            _set_rt(e, T_ULIST, p["bg_uv"], e.ld(e.add(e.ld(e.add(p["bg_rec"], U_LISTS)), p["bg_k"])))
            _set_rt(e, T_ULEN, p["bg_uv"], e.ld(e.add(e.ld(e.add(p["bg_rec"], U_LENGTHS)), p["bg_k"])))
            e.var("bg_home", _rt(e, T_HOME, p["bg_uv"]))
            e.if_(e.both(e.ne(_pos_block(e, p["bg_uv"]), bi), e.ne(p["bg_home"], NONE)), lambda: _set_rt(e, T_SPOFF, p["bg_uv"], p["bg_home"]))

        e.for_("bg_k", 0, e.ld(e.add(p["bg_rec"], U_COUNT)), use)
        # Edge use counts, then hints: a value of this block passed once prefers its parameter's register.
        def count_edge():
            tb, args, n = _edge(e, block, 0)
            e.var("bg_at", e.add(_f(e, block, B_EDGES), e.mul(p["bg_q"], EDGE)))
            e.var("bg_args", _f(e, p["bg_at"], 2))

            def each():
                e.var("bg_a", e.ld(e.add(p["bg_args"], p["bg_j"])))
                _touch(e, p["bg_a"])
                _set_rt(e, T_EUSE, p["bg_a"], e.add(_rt(e, T_EUSE, p["bg_a"]), 1))

            e.for_("bg_j", 0, _f(e, p["bg_at"], 1), each)
            del tb, args, n

        e.for_("bg_q", 0, _f(e, block, B_NEDGES), count_edge)

        def hint_edge():
            e.var("bg_at", e.add(_f(e, block, B_EDGES), e.mul(p["bg_q"], EDGE)))
            e.var("bg_tb", _f(e, p["bg_at"], 0))
            e.var("bg_args", _f(e, p["bg_at"], 2))

            def each(index, value):
                e.var("bg_a", e.ld(e.add(p["bg_args"], _pos_index(e, value))))
                good = e.both(_local_result(e, p["bg_a"]), e.eq(_sget(e, T_EUSE, p["bg_a"], 0), 1), e.eq(_pinned(e, value), NONE),
                              e.eq(_rt(e, T_PSLOT, value), NONE), e.lt(index, _ra(e, R_NALLOC)))
                e.if_(good, lambda: _sset(e, T_HINT, p["bg_a"], e.ld(e.add(_ra(e, R_ALLOC), index))))

            _machine_params(e, p["bg_tb"], each)

        e.for_("bg_q", 0, _f(e, block, B_NEDGES), hint_edge)
        # Call positions (erased proof calls excluded).
        e.var("bg_nc", 0)

        def call_position():
            e.var("bg_node", _node_at(e, block, p["bg_m"]))
            e.var("bg_op", _eop(e, p["bg_node"]))
            e.var("bg_is", e.flag(_in(e, p["bg_op"], CALLS)))

            def direct():
                _callee_object(e, p["bg_node"], "bg_callee")
                e.if_(e.both(e.ne(p["bg_callee"], NONE), e.ne(_call(e, "erased", e.sel(e.ne(p["bg_callee"], NONE), p["bg_callee"], 0)), 0)),
                      lambda: e.set("bg_is", 0))

            e.if_(e.eq(p["bg_op"], DIRECT_CALL), direct)
            e.if_(e.ne(p["bg_is"], 0), lambda: (e.st(e.add(_e(e, E_CALLPOS), p["bg_nc"]), p["bg_m"]), e.set("bg_nc", e.add(p["bg_nc"], 1))))

        e.for_("bg_m", 0, _f(e, block, B_NNODES), call_position)
        _se(e, E_NCALLPOS, p["bg_nc"])

        def label():
            def pad():
                e.var("bg_pad", e.and_(e.sub(0, _e(e, E_CLEN)), LOOP_ALIGNMENT - 1))
                e.while_(lambda: e.ne(p["bg_pad"], 0), lambda: (
                    e.var("bg_step", e.sel(e.lt(p["bg_pad"], len(NOPS)), p["bg_pad"], len(NOPS))),
                    _nop(e, p["bg_step"]), e.set("bg_pad", e.sub(p["bg_pad"], p["bg_step"]))))

            header = e.both(e.ne(_e(e, E_REAL), 0), e.ne(e.ld(e.add(_ra(e, R_LOOPHDR), bi)), 0))

            def at_header():
                e.var("bg_closed", e.flag(e.eq(_e(e, E_CLOSED), _e(e, E_CLEN))))
                e.if_(e.eq(p["bg_closed"], 0), lambda: e.if_(e.eq(_call(e, "reaches", bi, e.sub(bi, 1)), 0), lambda: e.set("bg_closed", 1)))
                e.if_(e.ne(p["bg_closed"], 0), pad)

            e.if_(header, at_header)
            _label(e, bi)

        e.if_(e.eq(p["copy"], 0), label)

        def place(index, value):
            e.var("bg_pin", _pinned(e, value))
            e.var("bg_ps", _rt(e, T_PSLOT, value))
            e.if_(e.ne(p["bg_pin"], NONE), lambda: _call(e, "bind", value, p["bg_pin"]), lambda: e.if_(
                e.ne(p["bg_ps"], NONE), lambda: _sset(e, T_SPOFF, value, p["bg_ps"]), lambda: e.if_(
                    e.lt(index, _ra(e, R_NALLOC)), lambda: _call(e, "bind", value, e.ld(e.add(_ra(e, R_ALLOC), index))),
                    lambda: _sset(e, T_SPOFF, value, e.add(_ra(e, R_EDGE_SPILL_BASE), e.mul(e.sub(index, _ra(e, R_NALLOC)), 8))))))

        _machine_params(e, block, place)

        def home(index, value):
            e.var("bg_hv", value)
            e.var("bg_ho", _rt(e, T_HOME, p["bg_hv"]))

            def store():
                _location(e, p["bg_hv"], "bg_kind", "bg_where")
                e.if_(e.eq(p["bg_kind"], LOC_REG), lambda: _store(e, p["bg_where"], p["bg_ho"], 8),
                      lambda: (_load(e, SCRATCH, p["bg_where"], 8), _store(e, SCRATCH, p["bg_ho"], 8)))

            e.if_(e.ne(p["bg_ho"], NONE), store)
            e.if_(e.eq(_last_use(e, p["bg_hv"]), NONE), lambda: _call(e, "release", p["bg_hv"]))

        _machine_params(e, block, home)
        e.give(1)
    return _function(("bi", "follow", "copy"), build, tables)


def _nop(e: E, length):
    """One ``_NOPS`` entry of ``length`` bytes (1..9), through the assembler."""
    for size, data in enumerate(NOPS, 1):
        e.if_(e.eq(length, size), lambda data=data: _b(e, data, True))


def _block_fn(tables, copy: bool):
    """``lower_block(bi)`` (``copy``: ``lower_block(bi, ..., copy_tag, follow)``): the spill high-water mark, or
    INELIGIBLE."""
    def build(e: E):
        p = e.p
        follow = p["follow"] if copy else e.add(p["bi"], 1)
        _call(e, "em_begin", p["bi"], follow, 1 if copy else 0)
        e.var("bl_block", _block_at(e, p["bi"]))

        def node():
            e.var("bl_r", _call(e, "em_node", p["bi"], p["bl_m"]))
            e.if_(e.eq(p["bl_r"], INELIGIBLE), lambda: e.give(INELIGIBLE))

        e.for_("bl_m", 0, _f(e, p["bl_block"], B_NNODES), node)
        e.give(_call(e, "em_term_copy" if copy else "em_term", p["bi"]))
    return _function(("bi", "follow") if copy else ("bi",), build, tables)


def _flip(e: E, condition):
    """``condition ^ 1``."""
    return e.sel(e.ne(e.and_(condition, 1), 0), e.sub(condition, 1), e.add(condition, 1))


def _term_fn(tables, copy: bool):
    """The terminator of block ``bi``; the block's spill high-water mark."""
    def build(e: E):
        p = e.p
        bi = p["bi"]
        e.var("tm_block", _block_at(e, bi))
        block = p["tm_block"]
        e.var("tm_pos", _f(e, block, B_NNODES))
        position = p["tm_pos"]
        e.var("tm_kind", _f(e, block, B_KIND))
        e.var("tm_follow", _e(e, E_FOLLOW))

        def close():
            e.if_(e.both(e.ne(_e(e, E_REAL), 0), e.eq(_e(e, E_CAP_ON), 0)), lambda: _se(e, E_CLOSED, _e(e, E_CLEN)))

        def goto(target):
            e.if_(e.ne(target, p["tm_follow"]), lambda: _jump(e, 0xE9, 1, target))

        def continue_to(target):
            e.var("tm_target", target)
            if copy:
                goto(p["tm_target"])
                return
            rotate = e.both(e.ne(p["tm_target"], p["tm_follow"]), e.ne(p["tm_target"], bi), _rotatable(e, _block_at(e, p["tm_target"])))

            def inline_copy():
                e.var("tm_saved", _e(e, E_MAX))
                e.var("tm_copy", _call(e, "em_block_copy", p["tm_target"], p["tm_follow"]))
                e.if_(e.both(e.ne(p["tm_copy"], INELIGIBLE), e.lt(p["tm_saved"], p["tm_copy"])), lambda: _se(e, E_MAX, p["tm_copy"]),
                      lambda: _se(e, E_MAX, p["tm_saved"]))

            e.if_(rotate, inline_copy, lambda: goto(p["tm_target"]))

        def returned():
            e.var("tm_first", NONE)
            e.for_("tm_k", 0, _f(e, block, B_NVALUES), lambda: (
                e.var("tm_v", e.ld(e.add(_f(e, block, B_VALUES), p["tm_k"]))),
                e.if_(e.both(e.eq(p["tm_first"], NONE), e.ne(_width(e, p["tm_v"]), 0), e.eq(e.ld(e.add(_ra(e, R_OWN_ELIDED), p["tm_k"])), NONE)),
                      lambda: e.set("tm_first", p["tm_v"]))))

            def value():
                _location(e, p["tm_first"], "tm_lk", "tm_lw")
                e.if_(e.eq(p["tm_lk"], LOC_REG), lambda: e.if_(e.ne(p["tm_lw"], RAX), lambda: _mov(e, RAX, p["tm_lw"])),
                      lambda: _materialize(e, RAX, p["tm_lk"], p["tm_lw"], _wbytes(e, p["tm_first"])))

            e.if_(e.ne(p["tm_first"], NONE), value, lambda: _bx(e, 0xC031, 2))
            _emit_record(e, _e(e, E_EPI))
            close()

        def branch():
            tb, args, n = _edge(e, block, 0)
            e.var("tm_rec", _call(e, "edge_code", tb, args, n))
            _emit_record(e, p["tm_rec"])
            continue_to(_f(e, _edge(e, block, 0)[0], B_POS))

        def conditional():
            e.var("tm_cond", e.ld(_f(e, block, B_VALUES)))
            e.var("tm_fused", e.ld(e.add(_ra(e, R_FUSED), bi)))
            e.var("tm_btab", e.ld(e.add(_ra(e, R_BTAB), bi)))
            e.var("tm_memb", e.ld(e.add(_ra(e, R_MEMB), bi)))
            e.var("tm_iff", 0x84)
            ttb, targs, tn = _edge(e, block, 0)
            ftb, fargs, fn = _edge(e, block, 1)
            e.var("tm_true", _f(e, ttb, B_POS))
            e.var("tm_false", _f(e, ftb, B_POS))

            def fused():
                e.var("tm_cmp", _node_at(e, block, p["tm_fused"]))
                _call(e, "em_compare", position, _operand(e, p["tm_cmp"], 0), _operand(e, p["tm_cmp"], 1))
                code = e.c(0)
                for kind, value in JUMP_IF_FALSE.items():
                    code = e.add(code, e.mul(e.flag(e.eq(_attribute(e, p["tm_cmp"], 0), int(kind))), value))
                e.set("tm_iff", code)

            def table():
                e.var("tm_subject", e.ld(p["tm_btab"]))
                e.var("tm_reg", _ensure(e, p["tm_subject"], position))
                _call(e, "table_address", e.ld(e.add(p["tm_btab"], 1)), e.ld(e.add(p["tm_btab"], 2)))
                _call(e, "scaled", 0x80, 1, 7, SCRATCH, p["tm_reg"], 1, 1, 0)
                _bx(e, 0, 1)
                e.set("tm_iff", 0x84)

            def membership():
                e.var("tm_subject", e.ld(p["tm_memb"]))
                e.var("tm_mask", e.ld(e.add(p["tm_memb"], 2)))
                e.var("tm_reg", _ensure(e, p["tm_subject"], position))
                e.var("tm_tmp", _acquire(e, position, (p["tm_subject"],)))
                e.var("tm_out", _new_label(e))
                e.var("tm_rec", _call(e, "edge_code", ftb, fargs, fn))
                _add_stub(e, p["tm_out"], p["tm_rec"], p["tm_false"])
                _lea_r11d(e, p["tm_reg"], e.ld(e.add(p["tm_memb"], 1)))
                e.var("tm_high", 0)
                e.var("tm_x", e.udiv(p["tm_mask"], 2))
                e.while_(lambda: e.ne(p["tm_x"], 0), lambda: (e.set("tm_high", e.add(p["tm_high"], 1)), e.set("tm_x", e.udiv(p["tm_x"], 2))))
                _bx(e, e.add(0xFB8341, e.mul(p["tm_high"], 1 << 24)), 4)  # cmp r11d, highest member offset
                _jcc(e, 0x87, p["tm_out"])
                _load_constant(e, p["tm_tmp"], p["tm_mask"])
                _bt(e, p["tm_tmp"])
                e.set("tm_iff", 0x83)

            def plain():
                e.var("tm_reg", _ensure(e, p["tm_cond"], position))
                _test(e, p["tm_reg"], _width(e, p["tm_cond"]))

            e.if_(e.ne(p["tm_fused"], NONE), fused, lambda: e.if_(e.ne(p["tm_btab"], NONE), table, lambda: e.if_(e.ne(p["tm_memb"], NONE), membership, plain)))
            e.var("tm_tc", _call(e, "edge_code", ttb, targs, tn))
            e.var("tm_fc", _call(e, "edge_code", ftb, fargs, fn))
            e.var("tm_tn", e.ld(p["tm_tc"]))
            e.var("tm_fn", e.ld(p["tm_fc"]))
            false_falls = e.both(e.eq(p["tm_false"], p["tm_follow"]), e.eq(p["tm_fn"], 0))
            true_falls = e.both(e.eq(p["tm_true"], p["tm_follow"]), e.eq(p["tm_tn"], 0))
            e.var("tm_ff", e.flag(false_falls))

            def fall_through():
                e.var("tm_taken", e.sel(e.ne(p["tm_ff"], 0), p["tm_true"], p["tm_false"]))
                e.var("tm_cc", e.sel(e.ne(p["tm_ff"], 0), _flip(e, p["tm_iff"]), p["tm_iff"]))
                e.var("tm_copies", e.sel(e.ne(p["tm_ff"], 0), p["tm_tc"], p["tm_fc"]))
                e.var("tm_dest", p["tm_taken"])

                def stub():
                    e.set("tm_dest", _new_label(e))
                    _add_stub(e, p["tm_dest"], p["tm_copies"], p["tm_taken"])

                e.if_(e.ne(e.ld(p["tm_copies"]), 0), stub)
                _jcc(e, p["tm_cc"], p["tm_dest"])

            def other():
                def both_copy():
                    def nearness(target):
                        """``nearness(target) + 1`` (so the bootstrap's -1 is 0)."""
                        return e.sel(e.eq(target, p["tm_follow"]), FAR + 1, e.sel(e.le(target, bi), e.add(target, 1), 0))

                    nf = nearness(p["tm_false"])
                    nt = nearness(p["tm_true"])
                    e.var("tm_inline_false", e.flag(e.lt(nt, nf)))
                    e.var("tm_inline", e.sel(e.ne(p["tm_inline_false"], 0), p["tm_false"], p["tm_true"]))

                    e.var("tm_icopies", e.sel(e.ne(p["tm_inline_false"], 0), p["tm_fc"], p["tm_tc"]))
                    e.var("tm_stubbed", e.sel(e.ne(p["tm_inline_false"], 0), p["tm_true"], p["tm_false"]))
                    e.var("tm_scopies", e.sel(e.ne(p["tm_inline_false"], 0), p["tm_tc"], p["tm_fc"]))
                    e.var("tm_cc", e.sel(e.ne(p["tm_inline_false"], 0), _flip(e, p["tm_iff"]), p["tm_iff"]))
                    e.var("tm_stub", _new_label(e))
                    _add_stub(e, p["tm_stub"], p["tm_scopies"], p["tm_stubbed"])
                    _jcc(e, p["tm_cc"], p["tm_stub"])
                    _emit_record(e, p["tm_icopies"])
                    continue_to(p["tm_inline"])

                def no_true_copies():
                    _jcc(e, _flip(e, p["tm_iff"]), p["tm_true"])
                    _emit_record(e, p["tm_fc"])
                    continue_to(p["tm_false"])

                def no_false_copies():
                    _jcc(e, p["tm_iff"], p["tm_false"])
                    _emit_record(e, p["tm_tc"])
                    continue_to(p["tm_true"])

                if copy:
                    def rotated():
                        _jcc(e, _flip(e, p["tm_iff"]), p["tm_true"])
                        _emit_record(e, p["tm_fc"])
                        goto(p["tm_false"])

                    e.if_(e.eq(p["tm_tn"], 0), rotated, lambda: e.if_(e.eq(p["tm_fn"], 0), no_false_copies, both_copy))
                else:
                    e.if_(e.eq(p["tm_fn"], 0), no_false_copies, lambda: e.if_(e.eq(p["tm_tn"], 0), no_true_copies, both_copy))

            e.if_(e.either(false_falls, true_falls), fall_through, other)

        def trap():
            e.var("tm_at", _f(e, block, B_TERM))
            e.var("tm_size", e.rd(e.add(p["tm_at"], 1)))
            e.var("tm_reason", 0)

            def decode():
                # ``decode_trap_payload``: the canonical ULEB (at most three bytes) heading the origin block's payload.
                from xax_selfhost_views_backend import G_ORDER, _payload_uleb
                from xax_selfhost_general_view import B_PB, B_PFN

                e.var("tm_fn_obj", e.ld(e.add(_g(e, G_ORDER), _f(e, block, B_PFN))))
                e.var("tm_graph", e.ld(_call(e, "interface", p["tm_fn_obj"])))
                e.var("tm_pa", _call(e, "trap_payload", p["tm_graph"], _f(e, block, B_PB)))
                e.set("tm_reason", _payload_uleb(e, "tm_pa"))

            e.if_(e.ne(p["tm_size"], 0), decode)
            _movabs(e, RAX, p["tm_reason"])
            _bx(e, 0x0B0F, 2)
            close()

        e.if_(e.eq(p["tm_kind"], RETURN), returned, lambda: e.if_(e.eq(p["tm_kind"], BRANCH), branch, lambda: e.if_(
            e.eq(p["tm_kind"], CONDITIONAL), conditional, trap)))
        e.give(_e(e, E_MAX))
    return _function(("bi",), build, tables)


# -- the function -----------------------------------------------------------------------------------------------

def _capture_begin(e: E):
    _se(e, E_CAP_ON, 1)
    _se(e, E_CAPLEN, 0)


def _capture_end(e: E, name: str):
    """Close the capture into an arena record ``[length, bytes...]`` in ``name``."""
    p = e.p
    _se(e, E_CAP_ON, 0)
    e.var(f"{name}_n", _e(e, E_CAPLEN))
    e.var(name, e.alloc(e.add(p[f"{name}_n"], 1)))
    _ok(e, e.ne(p[name], NONE))
    e.st(p[name], p[f"{name}_n"])
    e.for_(f"{name}_k", 0, p[f"{name}_n"], lambda: e.st(e.add(e.add(p[name], 1), p[f"{name}_k"]), e.ld(e.add(_e(e, E_CAPBUF), p[f"{name}_k"]))))


def _emit_function_fn(tables):
    """``compile_register_resident``'s emission of function ``f`` after its analyses: 1 emitted, 0 when the bootstrap
    returns None (a block is lowered by another path); NONE (declined) where the bootstrap fails."""
    from xax_selfhost_x86_64_general import G_ENTRY

    def build(e: E):
        p = e.p
        n, nb = _g(e, G_VCOUNT), _g(e, G_BCOUNT)
        e.var("ef_nb", nb)
        e.for_("ef_v", 0, n, lambda: (_set_rt(e, T_REG, p["ef_v"], NONE), _set_rt(e, T_ESTAMP, p["ef_v"], 0)))
        e.for_("ef_r", 0, 16, lambda: _set_regv(e, p["ef_r"], NONE))
        _se(e, E_STAMP, 0)
        _se(e, E_PROCESS, e.flag(e.eq(p["f"], _g(e, G_ENTRY))))
        _se(e, E_F, p["f"])
        for slot in (E_NTABLES, E_USED, E_REAL, E_NSTUBS, E_NTRAPS, E_FRAME, E_CLOSED, E_CLEN, E_NBRANCHES, E_NCALLS, E_NRANGES, E_CAP_ON):
            _se(e, slot, 0)
        _se(e, E_NLABELS, p["ef_nb"])
        # The dry run: the spill count and the used callee-saved registers; its code is discarded.
        _capture_begin(e)
        _capture_end(e, "ef_empty")
        _se(e, E_EPI, p["ef_empty"])
        e.var("ef_spills", 0)

        def plan():
            e.var("ef_r", _call(e, "em_block", p["ef_bi"]))
            e.if_(e.eq(p["ef_r"], INELIGIBLE), lambda: e.give(0))
            e.if_(e.lt(p["ef_spills"], p["ef_r"]), lambda: e.set("ef_spills", p["ef_r"]))

        e.for_("ef_bi", 0, p["ef_nb"], plan)
        # The frame: SysV preserves rbx, rbp, r12-r15; a process entry preserves nothing.
        e.var("ef_saved", e.alloc(9))
        _ok(e, e.ne(p["ef_saved"], NONE))
        e.var("ef_ns", 0)
        e.var("ef_used", _e(e, E_USED))
        for register in CALLEE_SAVED:
            if register in PINNABLE:
                e.if_(e.both(e.eq(_e(e, E_PROCESS), 0), e.ne(e.and_(p["ef_used"], 1 << register), 0)),
                      lambda register=register: (e.st(e.add(p["ef_saved"], p["ef_ns"]), register), e.set("ef_ns", e.add(p["ef_ns"], 1))))
        e.var("ef_payload", e.add(_ra(e, R_DYN_BASE), e.mul(p["ef_spills"], 8)))
        e.var("ef_pushed", e.add(e.sel(e.ne(_e(e, E_PROCESS), 0), 0, 8), e.mul(p["ef_ns"], 8)))
        e.var("ef_frame", 0)
        e.if_(e.either(e.ne(p["ef_payload"], 0), e.ne(_ra(e, R_HAS_CALL), 0)), lambda: e.set("ef_frame", e.sub(
            e.and_(e.add(e.add(p["ef_payload"], p["ef_pushed"]), 15), (1 << 64) - 16), p["ef_pushed"])))
        _ok(e, e.lt(p["ef_frame"], 1 << 31))
        _se(e, E_FRAME, p["ef_frame"])
        # The epilogue (captured): a process entry traps on return.
        _capture_begin(e)

        def returning():
            e.if_(e.ne(p["ef_frame"], 0), lambda: (_bx(e, 0xC48148, 3), _bx(e, p["ef_frame"], 4)))
            e.var("ef_k", p["ef_ns"])
            e.while_(lambda: e.ne(p["ef_k"], 0), lambda: (e.set("ef_k", e.sub(p["ef_k"], 1)), _pop_captured(e, e.ld(e.add(p["ef_saved"], p["ef_k"])))))
            _bx(e, 0xC3, 1)

        e.if_(e.ne(_e(e, E_PROCESS), 0), lambda: _bx(e, 0x0B0F, 2), returning)
        _capture_end(e, "ef_epi")
        _se(e, E_EPI, p["ef_epi"])
        # The real run.
        _se(e, E_REAL, 1)
        for slot in (E_NSTUBS, E_NTRAPS, E_CLOSED, E_CLEN, E_NBRANCHES, E_NCALLS, E_NRANGES):
            _se(e, slot, 0)
        e.for_("ef_l", 0, _e(e, E_NLABELS), lambda: e.st(e.add(_e(e, E_LABELS), p["ef_l"]), NONE))
        e.for_("ef_k", 0, p["ef_ns"], lambda: _push(e, e.ld(e.add(p["ef_saved"], p["ef_k"]))))
        e.if_(e.ne(p["ef_frame"], 0), lambda: (_bx(e, 0xEC8148, 3, True), _bx(e, p["ef_frame"], 4, True)))
        e.var("ef_entry", _block_at(e, _f(e, _g(e, G_BENTRY), B_POS)))
        _machine_params(e, p["ef_entry"], lambda index, value: e.if_(e.ne(_pinned(e, value), NONE), lambda: _mov(e, _pinned(e, value), e.ld(e.add(_ra(e, R_ALLOC), index)))))
        # Hoisted constants, by register.
        e.var("ef_hoisted", _ra(e, R_HOISTED))
        e.for_("ef_r", 0, 16, lambda: e.for_("ef_k", 0, _ra(e, R_NHOISTED), lambda: e.if_(
            e.eq(e.ld(e.add(p["ef_hoisted"], e.add(e.mul(p["ef_k"], 2), 1))), p["ef_r"]),
            lambda: _load_constant(e, p["ef_r"], e.ld(e.add(p["ef_hoisted"], e.mul(p["ef_k"], 2)))))))
        e.var("ef_ei", _f(e, _g(e, G_BENTRY), B_POS))
        e.if_(e.ne(p["ef_ei"], 0), lambda: _relative(e, 0xE9, p["ef_ei"]))

        def lower():
            e.var("ef_r", _call(e, "em_block", p["ef_bi"]))
            _ok(e, e.both(e.ne(p["ef_r"], INELIGIBLE), e.le(p["ef_r"], p["ef_spills"])))  # NATIVE-SPILL-PLAN-DETERMINISTIC

        e.for_("ef_bi", 0, p["ef_nb"], lower)

        def stub():
            e.var("ef_at", e.add(_e(e, E_STUBS), e.mul(p["ef_k"], 3)))
            _label(e, e.ld(p["ef_at"]))
            _emit_record(e, e.ld(e.add(p["ef_at"], 1)))
            _relative(e, 0xE9, e.ld(e.add(p["ef_at"], 2)))

        e.for_("ef_k", 0, _e(e, E_NSTUBS), stub)

        def trap():
            e.var("ef_at", e.add(_e(e, E_TRAPS), e.mul(p["ef_k"], 2)))
            _label(e, e.ld(e.add(p["ef_at"], 1)))
            e.var("ef_key", e.ld(p["ef_at"]))
            e.if_(e.ne(p["ef_key"], NONE), lambda: _movabs(e, RAX, p["ef_key"]))
            _bx(e, 0x0B0F, 2)

        e.for_("ef_k", 0, _e(e, E_NTRAPS), trap)

        def tables_after():
            e.var("ef_pad", e.and_(e.sub(0, _e(e, E_CLEN)), 15))
            e.for_("ef_k", 0, p["ef_pad"], lambda: _bx(e, 0xCC, 1))

            def table():
                e.var("ef_at", e.add(_e(e, E_TABLES), e.mul(p["ef_k"], 3)))
                _label(e, e.ld(e.add(p["ef_at"], 2)))
                e.var("ef_entries", e.ld(p["ef_at"]))
                e.for_("ef_j", 0, e.ld(e.add(p["ef_at"], 1)), lambda: _bx(e, e.ld(e.add(p["ef_entries"], p["ef_j"])), 1))

            e.for_("ef_k", 0, _e(e, E_NTABLES), table)

        e.if_(e.ne(_e(e, E_NTABLES), 0), tables_after)

        def fixup():
            e.var("ef_at", e.add(_e(e, E_BRANCHES), e.mul(p["ef_k"], 2)))
            e.var("ef_pos", e.ld(p["ef_at"]))
            e.var("ef_target", e.ld(e.add(_e(e, E_LABELS), e.ld(e.add(p["ef_at"], 1)))))
            _ok(e, e.ne(p["ef_target"], NONE))  # NATIVE-LABEL-RESOLVED
            _store_bytes(e, e.add(_e(e, E_CODE), p["ef_pos"]), e.sub(p["ef_target"], e.add(p["ef_pos"], 4)), 4)

        e.for_("ef_k", 0, _e(e, E_NBRANCHES), fixup)
        e.give(1)
    return _function(("f",), build, tables)


def _pop_captured(e: E, register):
    """``_pop`` into the capture (the epilogue)."""
    e.if_(e.le(8, register), lambda: _bx(e, 0x41, 1))
    _bx(e, e.add(0x58, _low3(e, register)), 1)


def write_emission(e: E, out, status):
    """The emission record after a function's view: 0 not decided, 1 the bootstrap returns None, 2 emitted, then the
    code length, the code packed eight bytes to a word (little endian), the call fixups (position, SysV entry label
    flag, four CID words), and the semantic ranges (block, node, start, end)."""
    p = e.p
    e.var("we_status", status)
    out(p["we_status"])

    def emitted():
        e.var("we_n", _e(e, E_CLEN))
        out(p["we_n"])
        e.var("we_code", _e(e, E_CODE))

        def word():
            e.var("we_w", 0)
            e.var("we_j", 8)
            e.while_(lambda: e.ne(p["we_j"], 0), lambda: (
                e.set("we_j", e.sub(p["we_j"], 1)),
                e.var("we_i", e.add(e.mul(p["we_k"], 8), p["we_j"])),
                e.set("we_w", e.add(e.mul(p["we_w"], 256), e.sel(e.lt(p["we_i"], p["we_n"]), e.ld(e.add(p["we_code"], e.sel(e.lt(p["we_i"], p["we_n"]), p["we_i"], 0))), 0)))))
            out(p["we_w"])

        e.for_("we_k", 0, e.udiv(e.add(p["we_n"], 7), 8), word)
        out(_e(e, E_NCALLS))

        def call():
            e.var("we_at", e.add(_e(e, E_CALLS), e.mul(p["we_k"], 3)))
            out(e.ld(p["we_at"]))
            out(e.ld(e.add(p["we_at"], 2)))
            for word in _cid_words(e, e.ld(e.add(p["we_at"], 1))):
                out(word)

        e.for_("we_k", 0, _e(e, E_NCALLS), call)
        out(_e(e, E_NRANGES))
        e.for_("we_k", 0, e.mul(_e(e, E_NRANGES), 4), lambda: out(e.ld(e.add(_e(e, E_RANGES), p["we_k"]))))

    e.if_(e.eq(p["we_status"], 2), emitted)


def set_trap_section(e: E, at):
    _set_ra(e, E_TRAPSEC, at)


def _trap_payload_fn(tables):
    """The input position of the payload head of graph ``g``'s trap block ``b`` (the trap section; declined when absent)."""
    def build(e: E):
        p = e.p
        e.var("tp_at", _e(e, E_TRAPSEC))
        e.var("tp_n", e.rd(p["tp_at"]))
        e.set("tp_at", e.add(p["tp_at"], 1))
        e.var("tp_cid", 0)
        cid = _cid_words(e, p["g"])
        e.var("tp_out", NONE)

        def graph():
            same = e.both(*(e.eq(e.rd(e.add(p["tp_at"], k)), word) for k, word in enumerate(cid)))
            e.var("tp_same", e.flag(same))
            e.var("tp_count", e.rd(e.add(p["tp_at"], 4)))
            e.set("tp_at", e.add(p["tp_at"], 5))

            def entry():
                e.if_(e.both(e.ne(p["tp_same"], 0), e.eq(e.rd(p["tp_at"]), p["b"])), lambda: e.set("tp_out", e.add(p["tp_at"], 2)))
                e.set("tp_at", e.add(e.add(p["tp_at"], 2), e.rd(e.add(p["tp_at"], 1))))

            e.for_("tp_k", 0, p["tp_count"], entry)

        e.for_("tp_q", 0, p["tp_n"], graph)
        _ok(e, e.ne(p["tp_out"], NONE))
        e.give(p["tp_out"])
    return _function(("g", "b"), build, tables)


def emit_prologue(e: E):
    """Allocate the emission buffers (once, after the register-allocation tables)."""
    for slot, words in ((E_CODE, CODE_CAP), (E_CAPBUF, CAPTURE_CAP), (E_LABELS, LABEL_CAP), (E_BRANCHES, 2 * BRANCH_CAP), (E_CALLS, 3 * CALL_CAP),
                        (E_RANGES, 4 * RANGE_CAP), (E_STUBS, 3 * STUB_CAP), (E_TRAPS, 2 * TRAP_CAP), (E_TABLES, 3 * TABLE_CAP),
                        (E_FREE, 1 << 16), (E_CHECKED, 3 * CHECK_CAP), (E_CALLPOS, 1 << 16), (E_MOVES, 4 * MOVE_CAP), (E_ARGS, 16), (E_REGS, 16),
                        (E_LIVE, 64), (E_DELAYED, 6 * MOVE_CAP), (E_PAIRS, 5 * MOVE_CAP)):
        at = e.alloc(words)
        _ok(e, e.ne(at, NONE))
        _se(e, slot, at)
    _se(e, E_FAIL, 0)  # S12f.2: no rejection yet (the arena is not re-zeroed between runs)
    e.var("ep_pow", 1)
    e.for_("ep_r", 0, 16, lambda: (_set_ra(e, e.add(E_POW, e.p["ep_r"]), e.p["ep_pow"]), e.set("ep_pow", e.mul(e.p["ep_pow"], 2))))


def add_emit_functions(add, tables):
    from xax_selfhost_views_backend import _syscall

    add("syscall", _syscall(tables))
    for name, direct in (("eb", False), ("ab", True)):
        add(name, _bytes_fn(tables, direct))
    add("rex", _rex_fn(tables))
    add("modrm_base", _modrm_base_fn(tables))
    add("mov", _mov_fn(tables))
    add("load_exact", _load_exact_fn(tables))
    add("store_exact", _store_exact_fn(tables))
    add("frame_access", _frame_access_fn(tables))
    add("arith", _arith_fn(tables))
    add("setcc", _setcc_fn(tables))
    add("load_constant", _load_constant_fn(tables))
    add("group1", _group1_fn(tables))
    add("scaled", _scaled_fn(tables))
    add("memop", _memop_fn(tables))
    add("next_use", _next_use_fn(tables))
    add("bind", _bind_fn(tables))
    add("unbind", _unbind_fn(tables))
    add("release", _release_fn(tables))
    add("spill", _spill_fn(tables))
    add("acquire", _acquire_fn(tables))
    add("ensure", _ensure_fn(tables))
    add("define", _define_fn(tables))
    add("destination_for", _destination_fn(tables))
    add("parallel_moves", _parallel_moves_fn(tables))
    add("location", _location_fn(tables))
    add("place_arguments", _place_arguments_fn(tables))
    add("after_call", _after_call_fn(tables))
    add("em_jump", _jump_fn(tables))
    add("trap_payload", _trap_payload_fn(tables))
    add("trap_label", _trap_label_fn(tables))
    add("table_address", _table_address_fn(tables))
    add("copy_edge", _copy_edge_fn(tables))
    add("edge_code", _edge_code_fn(tables))
    add("em_compare", _compare_fn(tables))
    add("em_memory", _memory_fn(tables))
    add("direct_call", _direct_call_fn(tables))
    add("startup_read", _startup_read_fn(tables))
    add("foreign_call", _foreign_call_fn(tables))
    add("em_node_a", _node_fn(tables, "a"))
    add("em_node_b", _node_fn(tables, "b"))
    add("em_node", _node_fn(tables, "dispatch"))
    add("em_begin", _begin_fn(tables))
    add("em_term_copy", _term_fn(tables, True))
    add("em_block_copy", _block_fn(tables, True))
    add("em_term", _term_fn(tables, False))
    add("em_block", _block_fn(tables, False))
    add("emit_function", _emit_function_fn(tables))
