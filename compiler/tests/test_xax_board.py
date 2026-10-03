"""ADR-128 (U1.6): a bare-metal XAX program on QEMU virt with MMIO, GICv2, and a timer interrupt."""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    AtomicScope,
    EffectDomain,
    Kind,
    Operation,
    StoreReader,
    TerminatorKind,
    XaxError,
    aarch64_linux_exec_target,
    bits_type,
    decode_native_target,
    effect_type,
    object_with_refs,
    trap_payload,
    verify_store,
    write_store,
)
from xax_board import DEVICE, IRQ_HANDLER, UART_PUT, compile_board_image, qemu_virt_board, run_board_image
from xax_structured import B8, B32, Proc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.aarch64_virt_board import EXPECTED, build_board_program, irq_handler  # noqa: E402

QEMU = shutil.which("qemu-system-aarch64")


def _store(*functions_and_objects):
    functions = [item for item in functions_and_objects if item.kind == Kind.FUNCTION]
    board = qemu_virt_board()
    module = object_with_refs(Kind.MODULE, (*functions, board))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    available = {item.cid: item for item in (*functions_and_objects, board, module, root, DEVICE)}
    reachable, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    reader = StoreReader(write_store(root.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader, board


def _reset(body, board, *, returns: bool = False):
    proc = Proc((("dev", DEVICE),))
    body(proc)
    if proc.block is not None:
        if not returns:
            values = proc.op(Operation.TARGET_OP, (proc["dev"],), (DEVICE,), entity=board, attributes=(14, int(AtomicScope.SYSTEM), 0, 0))
            proc["dev"] = values[0]
        proc.ret(proc["dev"])
    return proc.function((DEVICE,)), proc


def _put(proc: Proc, board, byte: int) -> None:
    proc["dev"] = proc.op(Operation.TARGET_OP, (proc.const(byte, B8), proc["dev"]), (DEVICE,), entity=board, attributes=(UART_PUT, int(AtomicScope.SYSTEM), 0, 0))[0]


class BoardPackageTests(unittest.TestCase):
    def test_board_package_decodes(self):
        description = decode_native_target(qemu_virt_board())
        self.assertEqual((description.architecture, description.abi, description.image_format), (3, 3, 8))
        self.assertEqual(description.handler_entries, (IRQ_HANDLER,))
        self.assertEqual(len(description.target_operations), 14)

    def test_image_is_deterministic(self):
        reader, entry, handler, board = build_board_program()
        first = compile_board_image(reader, entry.cid, handler.cid, board.cid)
        self.assertEqual(first.data, compile_board_image(reader, entry.cid, handler.cid, board.cid).data)
        self.assertEqual(first.data[:4], b"\x7fELF")

    def test_handler_contract_rejects_other_effects(self):
        board = qemu_virt_board()
        filesystem = effect_type(EffectDomain.FILESYSTEM, 0)
        proc = Proc((("dev", DEVICE), ("fs", filesystem)))
        proc.ret(proc["dev"], proc["fs"])
        handler = proc.function((DEVICE, filesystem))
        entry, entry_proc = _reset(lambda p: None, board)
        reader, board = _store(*proc.graph.objects.values(), *entry_proc.graph.objects.values(), handler, entry)
        with self.assertRaises(XaxError) as caught:
            compile_board_image(reader, entry.cid, handler.cid, board.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "HANDLER-ALLOWED-EFFECTS")

    def test_handler_with_machine_values_rejects(self):
        board = qemu_virt_board()
        proc = Proc((("dev", DEVICE), ("x", B32)))
        proc.ret(proc["dev"], proc["x"])
        handler = proc.function((DEVICE, B32))
        entry, entry_proc = _reset(lambda p: None, board)
        reader, board = _store(*proc.graph.objects.values(), *entry_proc.graph.objects.values(), handler, entry)
        with self.assertRaises(XaxError) as caught:
            compile_board_image(reader, entry.cid, handler.cid, board.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "HANDLER-PROOF-ONLY-INTERFACE")

    def test_board_operations_need_the_board_target(self):
        from xax_aarch64 import compile_aarch64_bundle_bound_target
        from xax_graph_builder import program_store

        board = qemu_virt_board()
        entry, proc = _reset(lambda p: _put(p, board, 0x41), board, returns=True)
        linux = aarch64_linux_exec_target()
        with self.assertRaises(XaxError) as caught:
            reader = program_store(entry, linux, (*proc.graph.objects.values(), board))
            compile_aarch64_bundle_bound_target(reader, (entry.cid,), linux)
        self.assertIn(caught.exception.diagnostic.rule, ("AARCH64-OP-TARGET-SUPPORTED", "AARCH64-TARGET-OP-PACKAGE"))


@unittest.skipUnless(QEMU, "requires qemu-system-aarch64")
class BoardExecutionTests(unittest.TestCase):
    def test_uart_gic_timer_interrupts_and_power_off(self):
        reader, entry, handler, board = build_board_program()
        completed = run_board_image(compile_board_image(reader, entry.cid, handler.cid, board.cid))
        self.assertEqual((completed.returncode, completed.stdout), (0, EXPECTED))

    def _run_reset(self, body, *, returns: bool = False):
        board = qemu_virt_board()
        handler, handler_proc = irq_handler(board)
        entry, proc = _reset(lambda p: body(p, board), board, returns=returns)
        reader, board = _store(*handler_proc.graph.objects.values(), *proc.graph.objects.values(), handler, entry, bits_type(64))
        return run_board_image(compile_board_image(reader, entry.cid, handler.cid, board.cid))

    def test_trap_reports_and_powers_off(self):
        def body(p: Proc, board):
            _put(p, board, 0x41)
            zero = p.bin(Operation.SUB_WRAP, 5, 5)
            _put(p, board, 0x42)
            p.op1(Operation.UDIV, (p.const(9), zero), B32)
            _put(p, board, 0x43)  # never reached

        completed = self._run_reset(body)
        self.assertEqual((completed.returncode, completed.stdout), (0, b"AB!"))

    def test_returning_reset_entry_is_a_trap(self):
        completed = self._run_reset(lambda p, board: _put(p, board, 0x52), returns=True)
        self.assertEqual((completed.returncode, completed.stdout), (0, b"R!"))


if __name__ == "__main__":
    unittest.main()
