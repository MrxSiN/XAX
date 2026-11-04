"""S12f.4 (ADR-280): the bootstrap's legacy register path for the Linux profiles, as XAX functions.

``xax_x86_64._compile_function`` tries ``_compile_register_resident_function`` on a function's own graph when the
register-resident lowering (S12d) returns None for its lowering view and the function is not the process entry.
The view inlines small leaf callees, so a function made only of ``add``/``sub``/``mul``, constants, and direct calls
reaches this path whenever an inlined callee keeps the view off the register-resident path (a float, say).  On a
Linux profile (not the hosted PE one) the path lowers exactly those operations, the resource operations (nothing),
and ``return``/``branch``/``conditional branch`` terminators:

* every bits value of at most 64 bits is a machine value; block parameters arrive in the allocatable registers
  (``rcx, rdx, r8, r9, r10, rax``) and then edge spill slots after the shadow space (when the function calls);
* a value used outside its defining block has a home slot, written at its definition;
* per block, values live in registers; one is spilled to a slot (the lowest free one) when no register is free,
  the victim being the value whose next use is furthest (then the register, then the value's position);
* a direct call spills every value live after it (keeping the copy), moves the operands to the argument registers
  (parallel moves through ``r11``), and kills every register; the result is in ``rax``;
* a dry run first sizes the dynamic spill area, then the real run emits.

The code, fixups, and ranges go to the emission record (S12d), so image assembly is unchanged.  Where the bootstrap
fails (NATIVE-BITS-SUPPORTED: arithmetic other than 32 or 64 bits wide) the program writes its diagnostic.

S15e.3b (ADR-326): on the hosted PE profile the path also lowers integer compares (``cmp``, ``setcc``), ``win64-c``
foreign calls (an import's ``call [rip + slot]`` or a COM method's ``mov rax, [rcx]; call [rax + 8k]``), code addresses
(``lea r, [rip + target]``), heap views (a ``test``/``jnz`` null trap), address offsets, pointer casts and addresses,
and plain and checked loads and stores through heap pointers (the bound check against the view's extent); pointers are
machine values.  A float, aggregate or sum value declines.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE
from xax_selfhost_general_emit import E_REAL, _bx, _label, _movabs, _new_label
from xax_selfhost_general_frame import _relative2
from xax_selfhost_general_regalloc import _ra
from xax_selfhost_general_view import N_GRAPH, N_OPSAT, _f
from xax_selfhost_views_backend import _call, _ok

SCRATCH = 11  # scratch_registers[1]
L_STATE = 242  # ``_ra`` slot: the legacy lowering's state record
# State words: per-value tables (each VCOUNT words), the register map, the spill slot flags, and scalars.
(S_WIDTH, S_HOME, S_REG, S_SPILL, S_SPID, S_LAST, S_UCOUNT, S_UAT, S_ULIST, S_VREG, S_FREE, S_NEXT, S_MAX, S_BI, S_DYN,
 S_EDGEB, S_P1, S_P2, S_NFREE, S_POSN, S_HOSTED, S_EXT) = range(22)


def _s(e: E, field: int):
    return e.ld(e.add(_ra(e, L_STATE), field))


def _set_s(e: E, field: int, value):
    e.st(e.add(_ra(e, L_STATE), field), value)


def _t(e: E, table: int, value):
    return e.ld(e.add(_s(e, table), value))


def _real(e: E, body):
    e.if_(e.ne(_ra(e, E_REAL), 0), body)


# -- the allocator -----------------------------------------------------------------------------------------------


def _protect(e: E, first=NONE, second=NONE):
    _set_s(e, S_P1, first)
    _set_s(e, S_P2, second)


def _acquire(e: E, position, first=NONE, second=NONE):
    _protect(e, first, second)
    return _call(e, "lg_acquire", position)


# -- moves, edges, calls -----------------------------------------------------------------------------------------


# -- one block ---------------------------------------------------------------------------------------------------


def _constant(e: E, node, result, m):
    """A bits constant (at most 64 bits; its little-endian value bytes) into a fresh register: ``mov r64, imm64``."""
    from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb, _reference

    p = e.p
    e.var("cs_obj", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
    _ok(e, e.ne(p["cs_obj"], NONE))
    e.var("cs_at", _at(e, G_PAY, p["cs_obj"]))
    _payload_uleb(e, "cs_at")  # the type
    e.var("cs_len", _payload_uleb(e, "cs_at"))
    _ok(e, e.le(p["cs_len"], 8))
    e.var("cs_value", 0)
    e.var("cs_weight", 1)
    e.for_("cs_k", 0, p["cs_len"], lambda: (e.set("cs_value", e.add(p["cs_value"], e.mul(e.rd(e.add(p["cs_at"], p["cs_k"])), p["cs_weight"]))),
                                            e.set("cs_weight", e.mul(p["cs_weight"], 256))))
    e.var("cs_reg", _acquire(e, m))
    _movabs(e, p["cs_reg"], p["cs_value"])
    _call(e, "lg_define", result, p["cs_reg"])


def _bound(e: E, pointer, index, size, access):
    """A checked access: ``ud2`` when the view is smaller than the access, else ``cmp index, extent - size``, ``jbe``
    over a ``ud2`` (NATIVE-CHECKED-BOUND-ENCODABLE past 2^31 - 1), then ``access``."""
    from xax_selfhost_general_emit import _hi, _low3
    from xax_selfhost_general_rejects import CHECKED_BOUND, encoding_reject

    p = e.p
    e.var("bd_ext", _t(e, S_EXT, pointer))
    _ok(e, e.ne(p["bd_ext"], NONE))  # the static checks: heap pointers only

    def fits():
        e.var("bd_max", e.sub(p["bd_ext"], size))
        e.if_(e.le(1 << 31, p["bd_max"]), lambda: encoding_reject(e, CHECKED_BOUND, p["bd_max"]))
        _bx(e, e.add(e.add(0x8148, _hi(e, index)), e.mul(e.add(0xF8, _low3(e, index)), 1 << 16)), 3)  # cmp r64, imm32
        _bx(e, p["bd_max"], 4)
        e.var("bd_ok", _new_label(e))
        _real(e, lambda: (_relative2(e, 0x860F, p["bd_ok"]), _bx(e, 0x0B0F, 2, True), _label(e, p["bd_ok"])))
        access()

    e.if_(e.lt(p["bd_ext"], size), lambda: _bx(e, 0x0B0F, 2), fits)


# -- the function ------------------------------------------------------------------------------------------------


