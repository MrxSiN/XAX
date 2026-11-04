"""Self-hosting step S15e.2 (ADR-315): the AArch64 bundle and its Linux ELF64 container as XAX functions.

``xax_aarch64.compile_aarch64_bundle_bound_target`` and ``xax_linux_aarch64.emit_linux_aarch64_executable`` after the
per-function code (``xax_selfhost_aarch64_emit``): the text is a 16-byte entry stub (``bl`` to the entry, then
``brk #0x5841``), one thunk per distinct foreign symbol in call order (a ``linux-aarch64-syscall-v1`` template, or
three words an ``aapcs64-linux-c`` import binds to its GOT slot), each padded to 16 bytes with zeros, then the bundle:
every closure function in CID order at a 16-byte boundary (``nop`` padding), its direct calls bound, its foreign calls
branched to their thunks.  The container is the static ``ET_EXEC`` (one read/execute segment) or, for
``aarch64-linux-elf-dynexec-v1``, the dynamic one (``PT_INTERP``, ``DT_NEEDED``, a one-bucket hash, ``GLOB_DAT``
relocations, bind-now GOT slots).

Each function's code is staged as it is emitted (``a64_image_add``); the assembly runs once every closure function
is emitted.  Where the bootstrap fails (a call out of ``bl`` range, an import symbol in two libraries) or a capacity is
reached, the record says "not decided" and the host assembles.

The record is ``xax_selfhost_general_image``'s at ``IMAGE_AT`` (the driver reads its status, code and ELF the same
way): the status, the bundle code (before the foreign calls are bound), the ELF bytes, the bundle's file offset, the
entry's bundle offset, then per closure function (image order) its bundle offset, code length, and node ranges
(block, node, start, end), the foreign calls (bundle position, library, name), and the ``DT_NEEDED`` libraries.
"""

from __future__ import annotations

from xax_selfhost_facts import E
from xax_selfhost_general_regalloc import _ra

FUNCTIONS, CALLS, RANGES, THUNKS = 1 << 16, 1 << 18, 1 << 19, 1 << 12
FN_WORDS = 7  # per closure function: stage start, length, first call, calls, first range, ranges, bundle offset
# State (``_ra`` slots: the x86-64 image's, which this program does not otherwise use).
(J_FNS, J_STAGED, J_CALLS, J_NCALLS, J_RANGES, J_NRANGES, J_ORDER, J_THUNKS, J_NTHUNKS, J_BASE, J_NAMES, J_NNAMES, J_NEEDED,
 J_ENTRY) = range(240, 254)
R_AARCH64_GLOB_DAT = 1025


def _fn(e: E, fidx, field: int):
    return e.add(e.add(_ra(e, J_FNS), e.mul(fidx, FN_WORDS)), field)


# -- staging -----------------------------------------------------------------------------------------------------------


# -- thunks ------------------------------------------------------------------------------------------------------------


# -- the bundle and the text --------------------------------------------------------------------------------------------


# -- the container ---------------------------------------------------------------------------------------------------


# -- the record --------------------------------------------------------------------------------------------------


