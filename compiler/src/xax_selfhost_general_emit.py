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

from xax_compiler import Operation
from xax_selfhost_facts import E, NONE
from xax_selfhost_general_regalloc import _ra, _set_ra
from xax_selfhost_views_backend import _call, _cid_words, _ok

RAX, RCX, RDX, RSP, RSI, RDI = 0, 1, 2, 4, 6, 7
SCRATCH = 11


ARITHMETIC = {Operation.ADD_WRAP: 0x01, Operation.SUB_WRAP: 0x29, Operation.BIT_XOR: 0x31, Operation.BIT_AND: 0x21, Operation.BIT_OR: 0x09}
INTEGER_DIVIDE_BY_ZERO = 2

# Emission state (``_ra`` slots from E_BASE on).
E_BASE = 100
(E_CODE, E_CLEN, E_CAP_ON, E_CAPBUF, E_CAPLEN, E_REAL, E_LABELS, E_NLABELS, E_BRANCHES, E_NBRANCHES, E_CALLS, E_NCALLS, E_RANGES,
 E_NRANGES, E_STUBS, E_NSTUBS, E_TRAPS, E_NTRAPS, E_TABLES, E_NTABLES, E_CLOSED, E_USED, E_STAMP, E_FREE, E_NFREE, E_NEXT, E_MAX,
 E_CHECKED, E_NCHECKED, E_CALLPOS, E_NCALLPOS, E_HINT, E_BI, E_FOLLOW, E_EPI, E_EPILEN, E_FRAME, E_LOCK, E_LOCW, E_MOVES, E_NMOVES,
 E_ARGS, E_REGS, E_NARGS, E_PROCESS, E_LIVE, E_RECORD, E_DELAYED, E_NDELAYED, E_PAIRS, E_NPAIRS, E_F, E_FAIL, E_TRAPSEC,
 E_FWD_ON, E_FWD_END, E_FWD_REG, E_FWD_OFF) = range(E_BASE, E_BASE + 58)
E_REGV = 192  # sixteen words: the value in each register, NONE when free
assert E_REGV + 16 <= 256 and E_FAIL < E_REGV
LOC_REG, LOC_CONST, LOC_STACK, LOC_SPILL = range(4)
LABEL_CAP = 1 << 16
BRANCH_CAP = 1 << 16


def _e(e: E, slot):
    return _ra(e, slot)


def _se(e: E, slot, value):
    _set_ra(e, slot, value)


# -- bytes -------------------------------------------------------------------------------------------------------


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


def _rex(e: E, w, r, x, b, force=0):
    _call(e, "rex", w, r, x, b, force)


def _modrm(e: E, reg, base, offset):
    _call(e, "modrm_base", reg, base, offset)


def _movabs(e: E, register, value):
    """``_immediate``: ``mov r64, imm64``."""
    _bx(e, e.add(e.add(0x48, _hi(e, register)), e.mul(e.add(0xB8, _low3(e, register)), 256)), 2)
    _bx(e, value, 8)


def _lea(e: E, register, base, offset):
    _rex(e, 1, register, 0, base)
    _bx(e, 0x8D, 1)
    _modrm(e, register, base, offset)


def _load(e: E, register, offset, width):
    _call(e, "frame_access", 0x8B, register, offset, width)


def _store(e: E, register, offset, width):
    _call(e, "frame_access", 0x89, register, offset, width)


def _load_constant(e: E, register, value):
    _call(e, "load_constant", register, value)


def _scaled(e: E, opcode: int, opcode_length: int, register, base, index, scale, width, force=0):
    _call(e, "scaled", opcode, opcode_length, register, base, index, scale, width, force)


def _pop(e: E, register):
    e.if_(e.le(8, register), lambda: _bx(e, 0x41, 1, True))
    _bx(e, e.add(0x58, _low3(e, register)), 1, True)


# -- allocation state (``lower_block``'s closures) --------------------------------------------------------------


def _materialize(e: E, register, kind, where, width_bytes):
    """Load a non-register location into ``register`` (``_load_constant``, ``lea``, or ``_load``)."""
    e.if_(e.eq(kind, LOC_CONST), lambda: _load_constant(e, register, where),
          lambda: e.if_(e.eq(kind, LOC_STACK), lambda: _lea(e, register, RSP, where), lambda: _load(e, register, where, width_bytes)))


def _set_arguments(e: E, operands, registers):
    """Fill ``E_ARGS``/``E_REGS`` from Python lists of expressions."""
    for k, (operand, register) in enumerate(zip(operands, registers)):
        e.st(e.add(_e(e, E_ARGS), k), operand)
        e.st(e.add(_e(e, E_REGS), k), register)
    _se(e, E_NARGS, len(operands))


# -- labels, jumps, calls, tables, traps ------------------------------------------------------------------------

def _new_label(e: E):
    """A fresh label number (blocks are labels 0..n-1)."""
    e.var("nl_id", _e(e, E_NLABELS))
    _ok(e, e.lt(e.p["nl_id"], LABEL_CAP))
    e.st(e.add(_e(e, E_LABELS), e.p["nl_id"]), NONE)
    _se(e, E_NLABELS, e.add(e.p["nl_id"], 1))
    return e.p["nl_id"]


def _label(e: E, label):
    # A label ends a forwarding window (``forward_stores`` never rewrites a branch target).
    e.if_(e.ne(_e(e, E_REAL), 0), lambda: (e.st(e.add(_e(e, E_LABELS), label), _e(e, E_CLEN)), _se(e, E_FWD_END, NONE)))


def _record_branch(e: E, label):
    e.var("rb_n", _e(e, E_NBRANCHES))
    _ok(e, e.lt(e.p["rb_n"], BRANCH_CAP))
    e.var("rb_at", e.add(_e(e, E_BRANCHES), e.mul(e.p["rb_n"], 2)))
    e.st(e.p["rb_at"], _e(e, E_CLEN))
    e.st(e.add(e.p["rb_at"], 1), label)
    _se(e, E_NBRANCHES, e.add(e.p["rb_n"], 1))


# -- edges --------------------------------------------------------------------------------------------------------


# -- nodes ----------------------------------------------------------------------------------------------------------

def _op(operation) -> int:
    return int(operation)


# -- blocks ---------------------------------------------------------------------------------------------------------


# -- the function -----------------------------------------------------------------------------------------------


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


