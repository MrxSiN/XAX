"""ADR-129: a bare-metal XAX program calling statically linked freestanding C (QEMU virt).

``benchmarks/board_c/checksum.c`` is compiled by the cross gcc into an ELF
relocatable object and linked into the board image after the XAX code.  The
XAX reset entry takes 16 bytes from the C bump allocator (an explicit
allocator contract), stores ``123456789``, calls C ``board_crc32`` (imported
from ``checksum.h`` by the ADR-127 importer), prints the CRC in hex on the
UART, releases the block, and powers off.  The expected CRC-32 of
``123456789`` is ``cbf43926``.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from xax_board import DEVICE, POWER_OFF, UART_PUT, qemu_virt_board
from xax_compiler import (
    AAPCS64_STATIC_C_ABI,
    AtomicScope,
    IntCompare,
    ForeignAllocatorContract,
    ForeignDeallocatorContract,
    Kind,
    Operation,
    Permission,
    StoreReader,
    bits_type,
    foreign_function_symbol,
    heap_owner_type,
    heap_view_type,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    verify_store,
    write_store,
)
from xax_structured import B8, B32, B64, Proc

HERE = Path(__file__).resolve().parent
SOURCE, HEADER = HERE / "board_c" / "checksum.c", HERE / "board_c" / "checksum.h"
OBJECT_NAME = b"checksum.o"
CFLAGS = ("-O2", "-ffreestanding", "-fno-pic", "-fno-common", "-fno-stack-protector", "-mgeneral-regs-only", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables")
MESSAGE = b"123456789"
EXPECTED = b"crc cbf43926\r\n"
MEM = memory_effect_type()
BYTES = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
VIEW = heap_view_type(16, initialized=False)  # the C arena is not zeroed


def compile_object(directory: Path) -> Path:
    output = directory / OBJECT_NAME.decode()
    subprocess.run(["aarch64-linux-gnu-gcc", *CFLAGS, "-c", str(SOURCE), "-o", str(output)], check=True)
    return output


def _op(proc: Proc, board, operation: int, operand=None) -> None:
    operands = (() if operand is None else (operand,)) + (proc["dev"],)
    proc["dev"] = proc.op(Operation.TARGET_OP, operands, (DEVICE,), entity=board, attributes=(operation, int(AtomicScope.SYSTEM), 0, 0))[0]


def build(board=None):
    from xax_c_import import import_c_functions

    board = board or qemu_virt_board()
    crc = import_c_functions([HEADER], OBJECT_NAME, ["board_crc32"], abi=AAPCS64_STATIC_C_ABI, flags=["-ffreestanding"]).function("board_crc32")
    allocate = foreign_function_symbol(
        OBJECT_NAME, b"board_alloc", (B64, MEM), (BYTES, heap_owner_type(), MEM), abi=AAPCS64_STATIC_C_ABI,
        allocator=ForeignAllocatorContract((0,), 0, 1, 16, False),
    )
    release = foreign_function_symbol(OBJECT_NAME, b"board_release", (BYTES, VIEW, MEM), (MEM,), abi=AAPCS64_STATIC_C_ABI, deallocator=ForeignDeallocatorContract(0, 1))
    proc = Proc((("dev", DEVICE), ("mem", MEM)))
    raw, owner, memory = proc.op(Operation.CALL_FOREIGN, (proc.const(16, B64), proc.drop("mem")), (BYTES, heap_owner_type(), MEM), entity=allocate)
    pointer, view, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, memory), (BYTES, VIEW, MEM), attributes=(16, 1))
    for index, byte in enumerate(MESSAGE):
        memory = proc.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, proc.const(index), proc.const(byte, B8), memory), MEM, attributes=(1, 1))
    readable = proc.op1(Operation.POINTER_CAST, (pointer,), crc.inputs[1])
    value, memory = proc.op(Operation.CALL_FOREIGN, (proc.const(0), readable, proc.const(len(MESSAGE), B64), memory), crc.outputs, entity=crc.declaration)
    memory = proc.op1(Operation.CALL_FOREIGN, (pointer, view, memory), MEM, entity=release)
    proc.let("value", B32, value)
    for byte in b"crc ":
        _op(proc, board, UART_PUT, proc.const(byte, B8))
    for shift in range(28, -4, -4):
        nibble = proc.bin(Operation.BIT_AND, proc.bin(Operation.UDIV, proc["value"], 1 << shift), 0xF)
        letter = proc.bin(Operation.ADD_WRAP, nibble, proc.op1(Operation.MUL_WRAP, (proc.widen(proc.cmp(IntCompare.UGE, nibble, 10)), proc.const(0x61 - 0x30 - 10)), B32))
        _op(proc, board, UART_PUT, proc.op1(Operation.INT_TRUNCATE, (proc.bin(Operation.ADD_WRAP, letter, 0x30),), B8))
    for byte in b"\r\n":
        _op(proc, board, UART_PUT, proc.const(byte, B8))
    _op(proc, board, POWER_OFF)
    proc.ret(proc["dev"], memory)
    reset = proc.function((DEVICE, MEM))
    handler_proc = Proc((("dev", DEVICE),))
    handler_proc.ret(handler_proc["dev"])
    handler = handler_proc.function((DEVICE,))
    module = object_with_refs(Kind.MODULE, (reset, handler, board))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    available = {item.cid: item for item in (*proc.graph.objects.values(), *handler_proc.graph.objects.values(), reset, handler, board, module, root, *crc.inputs, *crc.outputs, *[item for item in __import__("xax_c_import")._ELEMENTS.get(crc.inputs[1].cid, ())], B64)}
    reachable, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    reader = StoreReader(write_store(root.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader, reset, handler, board


def evidence() -> dict:
    import hashlib

    from xax_board import compile_board_image, run_board_image

    with tempfile.TemporaryDirectory() as directory:
        obj = compile_object(Path(directory))
        object_bytes = obj.read_bytes()
        reader, reset, handler, board = build()
        image = compile_board_image(reader, reset.cid, handler.cid, board.cid, objects=[obj])
    completed = run_board_image(image)
    if (completed.returncode, completed.stdout) != (0, EXPECTED):
        raise AssertionError(completed)
    return {
        "format": "xax-board-linked-c-evidence-v1",
        "evidence_label": "EXECUTED (QEMU virt, emulated; not hardware)",
        "c_source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "c_compiler": subprocess.run(["aarch64-linux-gnu-gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
        "c_flags": list(CFLAGS),
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_bytes": len(image.data),
        "image_sha256": hashlib.sha256(image.data).hexdigest(),
        "uart_output": completed.stdout.decode(),
        "program_root": reader.root_cid.hex(),
    }


if __name__ == "__main__":
    import json
    import sys

    text = json.dumps(evidence(), indent=2, sort_keys=True) + "\n"
    if "--write" in sys.argv:
        (HERE / "board_linked_c_evidence.json").write_text(text)
    sys.stdout.write(text)
