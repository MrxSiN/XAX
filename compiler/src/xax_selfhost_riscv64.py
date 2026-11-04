"""Self-hosting step S1 (ADR-116): the RISC-V instruction encoder as XAX semantics.

The RISC-V backend's instruction encoding (the R/I/S/B/J/U formats) and its
64-bit constant materialization planner (``li``) are one ordinary XAX function,
``encode(kind, a1, a2, a3, a4, a5, a6) -> bits<64>``:

====  =========================================  ===================================
kind  operands                                   result
====  =========================================  ===================================
0     funct7, rs2, rs1, funct3, rd, opcode       R-type word
1     imm, rs1, funct3, rd, opcode               I-type word (imm taken mod 2^12)
2     imm, rs2, rs1, funct3, opcode              S-type word
3     offset, rs2, rs1, funct3                   B-type word (opcode 0x63)
4     offset, rd                                 J-type word (opcode 0x6F)
5     imm20, rd, opcode                          U-type word
6     rd, value, index                           index-th word of ``li rd, value``,
                                                 or 0 past the end of the sequence
====  =========================================  ===================================

Every operand is a ``bits<64>`` holding the two's-complement value; fields
are masked to their width, so the function is total.  ``li`` uses only loops
over block parameters (no memory): one pass sizes the sequence, a second
finds the requested word, so a caller asks for words 0, 1, ... until 0.

The canonical store is committed at ``bootstrap/xax_riscv64_encoder.xax``.
The production RISC-V backend calls this function natively: it is lowered by
the XAX x86-64 backend and called in-process (``NativeEncoder``).  The Python
encoders in ``xax_riscv64`` remain the bootstrap reference and the fallback on
hosts that cannot execute the leaf.  The same graph also compiles to RISC-V and
to the JVM, so one compiler component runs on three targets.
"""

from __future__ import annotations

import ctypes
import mmap
from dataclasses import dataclass

from xax_compiler import Kind, SemanticObject, StoreReader, bits_type

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_riscv64_encoder.xax"
B1, B64 = bits_type(1), bits_type(64)
KIND_R, KIND_I, KIND_S, KIND_B, KIND_J, KIND_U, KIND_LI = range(7)
_MASK64 = (1 << 64) - 1


def load_encoder_program() -> tuple[StoreReader, SemanticObject]:
    """The committed canonical store, verified on load."""
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "riscv64-encoder")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    encode = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, encode


# ------------------------------------------------------------------ native leaf


@dataclass
class NativeEncoder:
    """The encoder lowered by the XAX x86-64 backend and called in-process.

    The code is mapped once; each call goes through the harness thunk that
    adapts the host's SysV ABI to the image's Win64-style internal convention
    (``xax_x86_64._SYSV_TO_WIN64_THUNK``).  No encoding logic lives outside
    the XAX image.
    """

    code_size: int
    _mapping: mmap.mmap
    _call: object
    _entry: int
    _slots: object
    _xmm: object

    @classmethod
    def load(cls) -> "NativeEncoder":
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = host_image(*load_encoder_program(), "riscv64-encoder")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + machine_code
        from xax_native import executable_mapping

        mapping, base = executable_mapping(code)
        call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        return cls(len(machine_code), mapping, call, base + len(thunk) + entry_offset, (ctypes.c_uint64 * 7)(), ctypes.c_uint64())

    def __call__(self, kind: int, *operands: int) -> int:
        slots = self._slots
        slots[0] = kind
        for position in range(6):
            slots[position + 1] = (operands[position] if position < len(operands) else 0) & _MASK64
        return self._call(self._entry, ctypes.addressof(slots), 7, ctypes.addressof(self._xmm))


_native: list[NativeEncoder | None] = []


def native_encoder() -> NativeEncoder | None:
    """The in-process XAX encoder, or ``None`` where it cannot run.

    It runs on Linux x86-64 hosts; ``XAX_RISCV64_PYTHON_ENCODER=1`` forces the
    bootstrap Python encoders.
    """
    if not _native:
        import xax_native

        usable = xax_native.usable("riscv64-encoder", STORE_PATH, "XAX_RISCV64_PYTHON_ENCODER")
        _native.append(NativeEncoder.load() if usable else None)
    return _native[0]
