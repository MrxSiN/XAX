"""S12e (ADR-273): the general x86-64 backend's image assembly and Linux ELF64 container as XAX functions.

``xax_x86_64._compile_native_with_target`` after the per-function code (S12d): each function placed at a 16-byte
boundary (``nop`` padding) in image order, the SysV entry adapters of the addressed functions after them (in label
order), every call and address fixup bound, and each foreign call recorded as an import; then ``xax_linux``'s
container: the static ``ET_EXEC`` (one read/execute segment) or, for ``x86_64-linux-elf-dynexec-v1``, the dynamic
one (``PT_INTERP``, ``DT_NEEDED``, a one-bucket hash, ``GLOB_DAT`` relocations, bind-now GOT slots).

The program assembles only when it emitted every function of the closure (S12d); otherwise the record says "not
decided" and the host assembles.  Where the bootstrap fails (an entry adapter's signature, an import symbol in two
libraries (S15b.4: its diagnostic), a static profile with imports) the program declines and the bootstrap reports the error.

The record is written at ``IMAGE_AT``: the status, the image code (before the container binds its imports), the ELF
bytes, the code's file offset, the entry offset, each function's offset, the imports (position, library, name), and
the ``DT_NEEDED`` libraries.
"""

from __future__ import annotations

from xax_selfhost_facts import E
from xax_selfhost_general_regalloc import _ra, _set_ra
from xax_selfhost_views_backend import _ok

IMAGE_AT, IMAGE_END = 232 << 20, 252 << 20  # S15f (ADR-323): above the arena in the 2 GiB view (was 6M-11M words)
# image bytes; S14a (ADR-284): the compiler's own image; S15b (ADR-291): 12 MiB; S15e.2 (ADR-315): 16 MiB; S15f (ADR-323):
# 32 MiB, one byte per word; ledger 0018 (ADR-381): 48 MiB, packed eight bytes to a word (the container buffer, one byte per
# word in the arena, holds IMAGE_CAP + 64 KiB)
IMAGE_CAP = 48 << 20
# S15d.0 (ADR-303): the code image's buffer sits at a fixed place the general program does not otherwise use (between
# the diagnostic record and the views backend's globals), so it no longer takes arena words and the views can grow.
IMAGE_BUFFER_AT = 200 << 20  # S15f (ADR-323): between the general arena and the image record
assert IMAGE_BUFFER_AT + IMAGE_CAP // 8 <= IMAGE_AT
# State (``_ra`` slots after the emission's register words).
(I_IMG, I_LEN, I_OK, I_COUNT, I_BASES, I_CALLS, I_NCALLS, I_ADAPT, I_NADAPT, I_IMPORTS, I_NIMPORTS, I_ENTRY, I_ELF, I_ELEN, I_OUT,
 I_NEEDED, I_NNEEDED, I_NAMES, I_NNAMES, I_SNAP, I_CURSOR, I_ADSTART) = range(210, 232)
BASE_ADDRESS, PAGE = 0x400000, 4096
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR, PT_GNU_STACK = 1, 2, 3, 6, 0x6474E551
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 0, 1, 4, 5, 6, 7, 8, 9, 10, 11


def _put(e: E, buffer_slot: int, length_slot: int, cap: int, word, n):
    """Append the ``n`` low bytes of ``word`` (little endian) to a byte buffer (one byte per word)."""
    p = e.p
    e.var("pu_len", _ra(e, length_slot))
    _ok(e, e.le(e.add(p["pu_len"], n), cap))
    e.var("pu_w", word)
    e.var("pu_at", e.add(_ra(e, buffer_slot), p["pu_len"]))
    e.for_("pu_k", 0, n, lambda: (e.st(e.add(p["pu_at"], p["pu_k"]), e.and_(p["pu_w"], 255)), e.set("pu_w", e.udiv(p["pu_w"], 256))))
    _set_ra(e, length_slot, e.add(p["pu_len"], n))


def _img(e: E, word, n):
    _put(e, I_IMG, I_LEN, IMAGE_CAP, word, n)


# -- the container ---------------------------------------------------------------------------------------------------

def _elf(e: E, word, n):
    _put(e, I_ELF, I_ELEN, IMAGE_CAP + (1 << 16), word, n)


def _align(e: E, value, alignment: int):
    return e.and_(e.add(value, alignment - 1), (1 << 64) - alignment)


# -- S15e.3 (ADR-317): the PE32+ container ---------------------------------------------------------------------------


# -- the record --------------------------------------------------------------------------------------------------

def _out(e: E, word):
    p = e.p
    e.var("io_at", _ra(e, I_CURSOR))
    _ok(e, e.lt(p["io_at"], IMAGE_END))
    e.st(p["io_at"], word)
    _set_ra(e, I_CURSOR, e.add(p["io_at"], 1))


