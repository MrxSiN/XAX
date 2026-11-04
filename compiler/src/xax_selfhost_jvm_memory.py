"""S15e.5g (ADR-336): the memory profile in the XAX JVM program (``jvm-classfile-memory-v1``, ADR-156).

The memory operations' lowering (``_compile_method_pass``: heap views, address offsets, pointer casts, addresses and
rebases, little-endian loads and stores, the ``xax/jvm/Memory`` members, the constant byte runs), the members a class
then needs (``_memory_methods``: ``<clinit>``, ``xax$alloc``, the checked byte members, ``xax$ix``, the loads and
stores, ``free``/``read``/``write``) and its ``M``/``H`` fields.

The generated members are fixed bytecode around constant-pool entries.  Their templates are made at build time by
running ``xax_jvm._memory_methods`` itself against a recording pool: every pool call (in call order, each member's
own) and every code position that holds a pool index are kept, with the members' branch offsets, frames and frame
locals.  The XAX program makes the same pool entries in the same order and writes the template's bytes, so a member
cannot drift from the bootstrap's.  Two values vary per class: ``<clinit>``'s initial memory size and a checked byte
member's bound (its name and its ``Integer`` constant); the templates carry sentinels for them.
"""

from __future__ import annotations



# The needs a class records (``needs`` in the bootstrap), as bits; the checked byte members are a list.
(N_MEMORY, N_LD1, N_LD2, N_LD4, N_LD8, N_ST2, N_ST4, N_ST8, N_IX, N_ALLOC, N_FREE, N_READ, N_WRITE, N_STACK) = (1 << k for k in range(14))
MEMBER_NEEDS = {"alloc(J)I": N_ALLOC, "free(I)J": N_FREE, "read(IIJ)J": N_READ, "write(IIJ)J": N_WRITE}
MEMBER_NAMES = {"alloc(J)I": "xax$alloc", "free(I)J": "xax$free", "read(IIJ)J": "xax$read", "write(IIJ)J": "xax$write"}
# The member templates in the bootstrap's order, each with the need that asks for it.
ORDER = (("<clinit>", N_MEMORY), ("xax$alloc", N_ALLOC), ("xax$ld1", N_LD1), ("bl", 0), ("bs", 0), ("xax$ix", N_IX), ("xax$free", N_FREE),
         ("xax$read", N_READ), ("xax$write", N_WRITE), ("xax$ld2", N_LD2), ("xax$st2", N_ST2), ("xax$ld4", N_LD4), ("xax$st4", N_ST4),
         ("xax$ld8", N_LD8), ("xax$st8", N_ST8))


# == the XAX program ======================================================================================================

from xax_selfhost_facts import E  # noqa: E402


# -- the method's needs ---------------------------------------------------------------------------------------------------

def need(e: E, bits):
    from xax_selfhost_jvm_code import _m, _set_m
    from xax_selfhost_jvm_method import M_MNEEDS

    _set_m(e, M_MNEEDS, e.or_(_m(e, M_MNEEDS), bits))


# -- facts the lowering reads -----------------------------------------------------------------------------------------------


KEYS = ("alloc(J)I", "free(I)J", "read(IIJ)J", "write(IIJ)J")  # sorted, as ``JVM-MEMORY-MEMBER`` lists them


# -- the lowering -----------------------------------------------------------------------------------------------------------


# -- the class: the merged needs, the initial memory, the members ------------------------------------------------------------

STACK_BYTES = 1 << 20


# -- the general profile (S15e.5h) ----------------------------------------------------------------------------------------


# -- the threaded launcher (S15e.5i) ------------------------------------------------------------------------------------------


