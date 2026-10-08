"""ADR-223: every clause of ``linux-x86_64-process-v1`` (``xax_linux.process_contract``) against real executables."""
from __future__ import annotations

import platform
import signal
import sys
import unittest

from xax_build import build
from xax_compiler import XaxError
from xax_construct import construct
from xax_linux import LINUX_X86_64_PROCESS_CONTRACT, process_contract, run_linux_executable

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
TYPES = {"buf": {"view": 64}, "mem": "linux.memory_effect", "proc": "linux.process_effect", "fs": "linux.filesystem_effect"}
SIGNATURE = {"params": ["proc", "fs", "mem"], "returns": ["b32", "proc", "fs", "mem"]}


def _program(nodes: list, end: list) -> bytes:
    request = {"format": "xax-construct-v1", "platform": "linux-x86_64", "types": TYPES,
               "functions": [{"name": "main", **SIGNATURE, "blocks": [{"params": ["proc", "fs", "mem"], "nodes": nodes, "end": end}]}],
               "package": {"name": "contract", "entries": {"app": "main"}, "release": "app"}}
    constructed = construct(request)
    return build(constructed.reader, constructed.release_request.cid).artifact


def _exit_with(status: int) -> bytes:
    return _program([["call.foreign", [["b32", status], "p0"], ["proc"], {"entity": "linux.exit_group"}]],
                    ["ret", [["b32", 0], "n0", "p1", "p2"]])


def _view_nodes() -> list:
    return [["call.foreign", [["b64", 64], "p2"], ["linux.bytes_rw", "linux.heap_owner", "mem"], {"entity": "linux.mmap_anonymous"}],
            ["heap.view", ["n0", "n0.r1", "n0.r2"], ["linux.bytes_rw", "buf", "mem"], {"attrs": [64, 1]}]]


class ProcessContractTests(unittest.TestCase):
    def test_contract_is_versioned_data(self):
        contract = process_contract()
        self.assertEqual(contract["identity"], LINUX_X86_64_PROCESS_CONTRACT)
        self.assertEqual(LINUX_X86_64_PROCESS_CONTRACT, "linux-x86_64-process-v1")
        self.assertIn("x86_64-linux-elf-exec-v1", contract["target_profiles"])

    def test_entry_with_machine_parameters_is_rejected(self):
        request = {"format": "xax-construct-v1", "platform": "linux-x86_64", "types": TYPES,
                   "functions": [{"name": "main", "params": ["b64", "proc"], "returns": ["b32", "proc"], "blocks": [
                       {"params": ["b64", "proc"], "nodes": [["call.foreign", [["b32", 0], "p1"], ["proc"], {"entity": "linux.exit_group"}]],
                        "end": ["ret", [["b32", 0], "n0"]]}]}],
                   "package": {"name": "bad", "entries": {"app": "main"}, "release": "app"}}
        constructed = construct(request)
        with self.assertRaises(XaxError) as raised:
            build(constructed.reader, constructed.release_request.cid)
        self.assertEqual(raised.exception.diagnostic.rule, "LINUX-PROCESS-ENTRY-CONTRACT")

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_exit_status_is_the_exit_group_argument_modulo_256(self):
        for status in (0, 7, 255, 256 + 9):
            with self.subTest(status=status):
                self.assertEqual(run_linux_executable(_exit_with(status)).returncode, status % 256)

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_returning_from_the_entry_traps(self):
        artifact = _program([], ["ret", [["b32", 0], "p0", "p1", "p2"]])
        self.assertEqual(run_linux_executable(artifact).returncode, -signal.SIGILL)

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_failed_check_traps(self):
        # A checked load at a runtime offset past the 64-byte view: the offset is read from stdin.
        nodes = [*_view_nodes(),
                 ["call.foreign", [["b32", 0], "n1", ["b64", 1], "p1", "n1.r2"], ["b64", "fs", "mem"], {"entity": "linux.read"}],
                 ["checked.load.bits.le", ["n1", ["b32", 0], "n2.r2"], ["b8", "mem"], {"attrs": [1, 1]}],
                 ["int.zero.extend", ["n3"], ["b32"]],
                 ["checked.load.bits.le", ["n1", "n4", "n3.r1"], ["b8", "mem"], {"attrs": [1, 1]}],
                 ["call.foreign", ["n1", "n1.r1", "n5.r1"], ["b64", "mem"], {"entity": {"linux.munmap_view": ["linux.bytes_rw", 64]}}],
                 ["call.foreign", [["b32", 0], "p0"], ["proc"], {"entity": "linux.exit_group"}]]
        artifact = _program(nodes, ["ret", [["b32", 0], "n7", "n2.r1", "n6.r1"]])
        self.assertEqual(run_linux_executable(artifact, stdin=bytes([10])).returncode, 0)
        self.assertEqual(run_linux_executable(artifact, stdin=bytes([200])).returncode, -signal.SIGILL)

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_stdout_and_stderr_are_fds_1_and_2(self):
        def writer(fd: int) -> bytes:
            nodes = [*_view_nodes(),
                     ["checked.store.bits.le", ["n1", ["b32", 0], ["b8", 33], "n1.r2"], ["mem"], {"attrs": [1, 1]}],
                     ["pointer.cast", ["n1"], ["linux.bytes_read"]],
                     ["call.foreign", [["b32", fd], "n3", ["b64", 1], "p1", "n2"], ["b64", "fs", "mem"], {"entity": "linux.write"}],
                     ["call.foreign", ["n1", "n1.r1", "n4.r2"], ["b64", "mem"], {"entity": {"linux.munmap_view": ["linux.bytes_rw", 64]}}],
                     ["call.foreign", [["b32", 0], "p0"], ["proc"], {"entity": "linux.exit_group"}]]
            return _program(nodes, ["ret", [["b32", 0], "n6", "n4.r1", "n5.r1"]])

        out, err = run_linux_executable(writer(1)), run_linux_executable(writer(2))
        self.assertEqual((out.stdout, out.stderr, err.stdout, err.stderr), (b"!", b"", b"", b"!"))


if __name__ == "__main__":
    unittest.main()
