"""Self-hosting step S15b.4 (ADR-294): the general x86-64 program's code generation rejections on malformed or extreme
inputs, with the bootstrap's exact diagnostics.

ADR-280 left these rules declined: where the bootstrap fails, the program made no claim.  The functions here write the
bootstrap's diagnostic instead, through ``reject_at`` (only when every earlier function's code was the program's, so
the bootstrap reached the same point):

* encodability (``xax_x86_64``'s encoders): a frame access, an indexed or atomic access, or an ``xmm`` access past
  ``disp32`` (NATIVE-MEMORY-ENCODABLE, NATIVE-INDEXED-MEMORY-ENCODABLE, NATIVE-ATOMIC-ENCODABLE, NATIVE-XMM-MEMORY), a
  checked bound past ``imm32`` (NATIVE-CHECKED-BOUND-ENCODABLE), and an ``and`` mask past 32 bits (NATIVE-AND-IMM32);
* calls: more than one machine result on the frame path (NATIVE-CALL-ARITY), and on the register path a value that
  has no location (NATIVE-VALUE-LOCATION: a second machine result is never defined);
* foreign calls: a declaration of an ABI the path does not own (NATIVE-FOREIGN-ABI), a syscall with more than one
  machine result (SYSCALL-ONE-RESULT), a syscall name ``decode_syscall_name`` rejects (SYSCALL-TEMPLATE-CANONICAL,
  SYSCALL-TEMPLATE-OPERANDS), and a startup read of another name (LINUX-STARTUP-NAME);
* pointer widths on the frame path (NATIVE-POINTER-ELEMENT-WIDTH, NATIVE-ADDRESS-POINTER-WIDTH);
* the dynamic container: one symbol imported from two libraries (LINUX-IMPORT-SYMBOL-UNIQUE).

A text the bootstrap renders with ``decode("ascii", "replace")`` is written as its raw bytes, which the record's
``STR`` decoding renders the same way.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E

# Encodability rejections, by ``which``: (code, rule, expected, how many actual words; 1 is the bare value).
ENCODING_RULES = (
    ("XAX.NATIVE.MEMORY_ENCODING", "NATIVE-MEMORY-ENCODABLE", "4/8-byte access with disp32", 2),
    ("XAX.NATIVE.MEMORY_ENCODING", "NATIVE-INDEXED-MEMORY-ENCODABLE", "4/8-byte access with rsp+index+disp32", 2),
    ("XAX.NATIVE.MEMORY_ENCODING", "NATIVE-CHECKED-BOUND-ENCODABLE", "0..2^31-1", 1),
    ("XAX.NATIVE.ATOMIC_ENCODING", "NATIVE-ATOMIC-ENCODABLE", "aligned 4/8-byte access with disp32", 2),
    ("XAX.NATIVE.FLOAT_ENCODING", "NATIVE-XMM-MEMORY", "f32/f64 stack access", 3),
    ("XAX.NATIVE.IMMEDIATE", "NATIVE-AND-IMM32", "0..2^32-1", 1),
)
MEMORY, INDEXED, CHECKED_BOUND, ATOMIC, XMM, AND_IMM32 = range(len(ENCODING_RULES))
# Foreign declarations: their ABI classes, and what each path owns (``xax_x86_64_regalloc``: NATIVE-FOREIGN-ABI).
SYSV_C, SYSCALL, STARTUP, WIN64_C = b"sysv-x86_64-c", b"linux-x86_64-syscall-v1", b"linux-x86_64-startup-v1", b"win64-c"


def _signed(e: E, value):
    """An integer as Python holds it: a word with the top bit set is a negative number."""
    e.if_(e.le(1 << 63, value), lambda: (D.put(e, D.T_SINT), D.put(e, value)), lambda: D.integer(e, value))


def encoding_reject(e: E, which: int, *words):
    """Reject with ``ENCODING_RULES[which]``; gives NONE (the caller's ``_call`` then stops)."""
    from xax_selfhost_views_backend import _call

    _call(e, "encoding_reject", which, *(tuple(words) + (0, 0, 0))[:3])


