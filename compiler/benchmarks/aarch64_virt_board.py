"""U1.6 bare-metal workload on QEMU ``virt``: UART output, GICv2, and a timer interrupt (ADR-128).

``reset`` prints ``boot``, enables the virtual timer interrupt in the GICv2
distributor and CPU interface, arms the timer for 10 ms, and then three times:
waits for an interrupt with IRQs masked (``wfi`` wakes on a pending IRQ),
unmasks so the handler runs, masks again, and prints ``tick``.  The IRQ
handler acknowledges the interrupt, prints ``irq``, re-arms the timer, and
signals end of interrupt.  ``reset`` then stops the timer, prints ``done``, and
powers off through PSCI.  Masking around the unmask point makes the output
order exact: ``boot irq tick irq tick irq tick done``.
"""

from __future__ import annotations

from xax_board import (
    CNTFRQ, CNTV_CTL, CNTV_TVAL, DEVICE, GICC_CTLR, GICC_EOIR, GICC_IAR, GICC_PMR, GICD_CTLR, GICD_ISENABLER0,
    IRQ_MASK, IRQ_UNMASK, POWER_OFF, UART_PUT, VIRTUAL_TIMER_IRQ, WAIT_FOR_INTERRUPT, qemu_virt_board,
)
from xax_compiler import AtomicScope, IntCompare, Operation, bits_type
from xax_graph_builder import program_store
from xax_structured import B8, B32, B64, Proc

EXPECTED = b"boot\r\nirq\r\ntick\r\nirq\r\ntick\r\nirq\r\ntick\r\ndone\r\n"
TICKS = 3


def _op(proc: Proc, board, operation: int, operand=None, result=None) -> object:
    operands = (() if operand is None else (operand,)) + (proc["dev"],)
    results = (() if result is None else (result,)) + (DEVICE,)
    values = proc.op(Operation.TARGET_OP, operands, results, entity=board, attributes=(operation, int(AtomicScope.SYSTEM), 0, 0))
    proc["dev"] = values[-1]
    return values[0] if result is not None else None


def _print(proc: Proc, board, text: bytes) -> None:
    for byte in text.replace(b"\n", b"\r\n"):
        _op(proc, board, UART_PUT, proc.const(byte, B8))


def _arm_timer(proc: Proc, board) -> None:
    frequency = _op(proc, board, CNTFRQ, result=B64)
    _op(proc, board, CNTV_TVAL, proc.bin(Operation.UDIV, frequency, 100, B64))
    _op(proc, board, CNTV_CTL, proc.const(1, B64))


def irq_handler(board):
    proc = Proc((("dev", DEVICE),))
    interrupt = _op(proc, board, GICC_IAR, result=B32)
    _print(proc, board, b"irq\n")
    _arm_timer(proc, board)
    _op(proc, board, GICC_EOIR, interrupt)
    proc.ret(proc["dev"])
    return proc.function((DEVICE,)), proc


def reset(board):
    proc = Proc((("dev", DEVICE),))
    _print(proc, board, b"boot\n")
    _op(proc, board, GICD_CTLR, proc.const(1))
    _op(proc, board, GICD_ISENABLER0, proc.const(1 << VIRTUAL_TIMER_IRQ))
    _op(proc, board, GICC_PMR, proc.const(0xFF))
    _op(proc, board, GICC_CTLR, proc.const(1))
    _arm_timer(proc, board)
    proc.let("count", B32, proc.const(0))

    def tick(p: Proc):
        _op(p, board, WAIT_FOR_INTERRUPT)
        _op(p, board, IRQ_UNMASK)
        _op(p, board, IRQ_MASK)
        _print(p, board, b"tick\n")
        p["count"] = p.bin(Operation.ADD_WRAP, p["count"], 1)

    proc.while_(lambda p: p.cmp(IntCompare.ULT, p["count"], TICKS), tick)
    _op(proc, board, CNTV_CTL, proc.const(0, B64))
    _print(proc, board, b"done\n")
    _op(proc, board, POWER_OFF)
    proc.ret(proc["dev"])
    return proc.function((DEVICE,)), proc


def build_board_program():
    board = qemu_virt_board()
    handler, handler_proc = irq_handler(board)
    entry, entry_proc = reset(board)
    objects = (*handler_proc.graph.objects.values(), *entry_proc.graph.objects.values(), handler, board, DEVICE, bits_type(64))
    from xax_compiler import Kind, object_with_refs, StoreReader, write_store, verify_store

    module = object_with_refs(Kind.MODULE, (entry, handler, board))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    available = {item.cid: item for item in (*objects, entry, module, root)}
    reachable, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    reader = StoreReader(write_store(root.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader, entry, handler, board


def evidence() -> dict:
    import hashlib
    import subprocess

    from xax_board import compile_board_image, run_board_image

    reader, entry, handler, board = build_board_program()
    image = compile_board_image(reader, entry.cid, handler.cid, board.cid)
    completed = run_board_image(image)
    if (completed.returncode, completed.stdout) != (0, EXPECTED):
        raise AssertionError(completed)
    return {
        "format": "xax-aarch64-virt-board-evidence-v1",
        "evidence_label": "EXECUTED (QEMU virt, emulated; not hardware)",
        "board": "QEMU virt, cortex-a57, 128 MiB, GICv2, PL011 UART, PSCI via HVC",
        "qemu": subprocess.run(["qemu-system-aarch64", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
        "program_root": reader.root_cid.hex(),
        "reset_entry": entry.cid.hex(),
        "irq_handler": handler.cid.hex(),
        "target": board.cid.hex(),
        "image_bytes": len(image.data),
        "loaded_bytes": len(image.code),
        "image_sha256": hashlib.sha256(image.data).hexdigest(),
        "uart_output": completed.stdout.decode(),
        "exit_status": completed.returncode,
        "generated_code": "reset stub (stack pointer, VBAR_EL1, bl reset, fault branch), fault stub (UART '!' then PSCI SYSTEM_OFF), 2 KiB vector table whose IRQ slot saves x0-x18/x30, calls the handler, restores, eret",
    }


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    text = json.dumps(evidence(), indent=2, sort_keys=True) + "\n"
    if "--write" in sys.argv:
        (Path(__file__).resolve().parent / "aarch64_virt_board_evidence.json").write_text(text)
    sys.stdout.write(text)
