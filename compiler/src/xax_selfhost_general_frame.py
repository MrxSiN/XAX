"""S12f (ADR-275): the general x86-64 backend's frame lowering as XAX functions.

``xax_x86_64._compile_function``'s frame path, for the Linux profiles: every machine value of the function's own
graph (not the inlined view) owns a frame slot; each node loads its operands from their slots, computes in fixed
registers, and stores its result.  The bootstrap takes this path when the register-resident lowering rejects the
function (its eligibility, or a node it does not lower) and the legacy register path does not apply (always for a
process entry; otherwise the program declines where the legacy path's static checks would accept, so the bootstrap
decides).

Covered: integer arithmetic, division with its zero trap, width changes, rotation, constants (bits and floats),
compares, the SSE float operations under an IEEE MXCSR, float/integer conversions with their range traps, float
width conversion, products, sums, function addresses, stack storage (static accesses, escaping addresses),
first-class pointers and heap views (dynamic accesses), SysV C imports with INTEGER and SSE scalars, Linux syscalls,
direct and indirect calls, returns, branches, and traps; S12f.3 (ADR-279): atomics of stack storage with the
capability check, and aggregates passed by reference or returned through the hidden pointer.  Declined (the bootstrap
lowers or rejects): links and rebases (which the bootstrap rejects on this path), and the startup reads.

The code, fixups, and ranges go to the same emission record as the register-resident code (S12d), so image
assembly (S12e.1) is unchanged.
"""

from __future__ import annotations


from xax_compiler import IntCompare, Operation
from xax_selfhost_facts import E
from xax_selfhost_general_emit import _bx
from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb, _type_form

INTEGER_DIVIDE_BY_ZERO = 2
SETCC = {IntCompare.EQ: 0x94, IntCompare.NE: 0x95, IntCompare.ULT: 0x92, IntCompare.ULE: 0x96, IntCompare.UGT: 0x97, IntCompare.UGE: 0x93,
         IntCompare.SLT: 0x9C, IntCompare.SLE: 0x9E, IntCompare.SGT: 0x9F, IntCompare.SGE: 0x9D}
CALLS = tuple(int(op) for op in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT))


def _op(operation) -> int:
    return int(operation)


# -- types --------------------------------------------------------------------------------------------------------

def _form(e: E, type_obj):
    return _type_form(e, type_obj)


def _proof(e: E, type_obj):
    form = _form(e, type_obj)
    return e.either(e.eq(form, 3), e.eq(form, 4))


def _bits_width(e: E, type_obj, name: str):
    """``_bits_width``: the width of a bits type, 0 otherwise."""
    e.var(name, 0)

    def bits():
        e.var(f"{name}_at", e.add(_at(e, G_PAY, type_obj), 1))
        e.set(name, _payload_uleb(e, f"{name}_at"))

    e.if_(e.eq(_form(e, type_obj), 1), bits)


def _align_to(e: E, value, alignment):
    """``(value + alignment - 1) & -alignment``."""
    return e.and_(e.add(value, e.sub(alignment, 1)), e.sub(0, alignment))


# -- encoders (frame path) --------------------------------------------------------------------------------------


# -- the frame ----------------------------------------------------------------------------------------------------


# -- nodes ----------------------------------------------------------------------------------------------------------


def _relative2(e: E, opcode: int, label):
    """``assembler.relative`` with a two-byte opcode (``0f 8x``)."""
    from xax_selfhost_general_emit import _record_branch

    _bx(e, opcode, 2, True)
    _record_branch(e, label)
    _bx(e, 0, 4, True)


# -- calls ----------------------------------------------------------------------------------------------------------


SEQ_CST = 5


