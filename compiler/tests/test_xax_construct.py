"""ADR-210: the xax-construct-v1 carrier, and the XAX-only xb64 application built from it."""
from __future__ import annotations

import copy
import json
import platform
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.bench_r6_xb64 import INCOMPLETE_EDIT, MAINTENANCE_EDIT, REQUEST, STORES, _builds  # noqa: E402
from xax_compiler import StoreReader  # noqa: E402
from xax_construct import construct  # noqa: E402
from xax_local_protocol import LocalMutationSession  # noqa: E402
from xax_workspace import Workspace  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
WINDOWS_X86_64 = sys.platform == "win32" and platform.machine().lower() in ("x86_64", "amd64")
XB64 = json.loads(REQUEST.read_text(encoding="utf-8"))


def _hello(text: bytes = b"hi\n") -> dict:
    stores = [["checked.store.bits.le", ["n1", ["b32", i], ["b8", byte], "n1.r2" if i == 0 else f"n{1 + i}"], ["mem"], {"attrs": [1, 1]}]
              for i, byte in enumerate(text)]
    last = 1 + len(text)
    return {
        "format": "xax-construct-v1", "platform": "linux-x86_64", "types": {"buf": {"view": 64}, "mem": "linux.memory_effect"},
        "functions": [{"name": "main", "params": ["linux.process_effect", "linux.filesystem_effect", "mem"],
                       "returns": ["b32", "linux.process_effect", "linux.filesystem_effect", "mem"],
                       "blocks": [{"params": ["linux.process_effect", "linux.filesystem_effect", "mem"], "nodes": [
                           ["call.foreign", [["b64", 64], "p2"], ["linux.bytes_rw", "linux.heap_owner", "mem"], {"entity": "linux.mmap_anonymous"}],
                           ["heap.view", ["n0", "n0.r1", "n0.r2"], ["linux.bytes_rw", "buf", "mem"], {"attrs": [64, 1]}],
                           *stores,
                           ["pointer.cast", ["n1"], ["linux.bytes_read"]],
                           ["call.foreign", [["b32", 1], f"n{last + 1}", ["b64", len(text)], "p1", f"n{last}"], ["b64", "linux.filesystem_effect", "mem"], {"entity": "linux.write"}],
                           ["call.foreign", ["n1", "n1.r1", f"n{last + 2}.r2"], ["b64", "mem"], {"entity": {"linux.munmap_view": ["linux.bytes_rw", 64]}}],
                           ["call.foreign", [["b32", 0], "p0"], ["linux.process_effect"], {"entity": "linux.exit_group"}]],
                        "end": ["ret", [["b32", 0], f"n{last + 4}", f"n{last + 2}.r1", f"n{last + 3}.r1"]]}]}],
        "package": {"name": "hello", "entries": {"app": "main"}, "release": "app"}}


def _echo_argument() -> dict:
    """ADR-223: write argv[1] (clamped to a 64-byte view) and exit with argc, through linux.startup.* entities."""
    return {
        "format": "xax-construct-v1", "platform": "linux-x86_64", "types": {"buf": {"view": 64}, "mem": "linux.memory_effect"},
        "functions": [{"name": "main", "params": ["linux.process_effect", "linux.filesystem_effect", "mem"],
                       "returns": ["b32", "linux.process_effect", "linux.filesystem_effect", "mem"],
                       "blocks": [{"params": ["linux.process_effect", "linux.filesystem_effect", "mem"], "nodes": [
                           ["call.foreign", [["b64", 64], "p2"], ["linux.bytes_rw", "linux.heap_owner", "mem"], {"entity": "linux.mmap_anonymous"}],
                           ["heap.view", ["n0", "n0.r1", "n0.r2"], ["linux.bytes_rw", "buf", "mem"], {"attrs": [64, 1]}],
                           ["call.foreign", [["b64", 1], "n1", "n1.r2"], ["b64", "mem"], {"entity": "linux.startup.arg_copy"}],
                           ["pointer.cast", ["n1"], ["linux.bytes_read"]],
                           ["call.foreign", [["b32", 1], "n3", "n2", "p1", "n2.r1"], ["b64", "linux.filesystem_effect", "mem"], {"entity": "linux.write"}],
                           ["call.foreign", ["n1", "n1.r1", "n4.r2"], ["b64", "mem"], {"entity": {"linux.munmap_view": ["linux.bytes_rw", 64]}}],
                           ["call.foreign", [], ["b64"], {"entity": "linux.startup.argc"}],
                           ["int.truncate", ["n6"], ["b32"]],
                           ["call.foreign", ["n7", "p0"], ["linux.process_effect"], {"entity": "linux.exit_group"}]],
                        "end": ["ret", ["n7", "n8", "n4.r1", "n5.r1"]]}]}],
        "package": {"name": "echo1", "entries": {"app": "main"}, "release": "app"}}


def _windows_echo() -> dict:
    """ADR-252: copy up to 4 KiB of stdin to stdout through the heap-view stdio contracts; exit with the byte count."""
    alloc = lambda effect: ["call.foreign", [["b64", 0], ["b64", 4096], ["b32", 0x3000], ["b32", 4], effect],  # noqa: E731
                            ["win32.heap_ptr_rw", "win32.heap_resource", "mem"], {"entity": "win32.virtual_alloc"}]
    free = lambda view, extent, ptr, effect: ["call.foreign", [view, ["b64", 0], ["b32", 0x8000], f"{view}.r1", effect],  # noqa: E731
                                              ["b32", "mem"], {"entity": {"win32.virtual_free_view": [ptr, extent]}}]
    return {
        "format": "xax-construct-v1", "platform": "windows-x86_64",
        "types": {"buf": {"view": 4096}, "cnt": {"view": 4}, "mem": "win32.memory_effect"},
        "functions": [{"name": "main", "params": ["win32.process_effect", "win32.filesystem_effect", "mem"],
                       "returns": ["b32", "win32.process_effect", "win32.filesystem_effect", "mem"],
                       "blocks": [{"params": ["win32.process_effect", "win32.filesystem_effect", "mem"], "nodes": [
                           ["call.foreign", [["b32", 0xFFFFFFF6], "p0"], ["b64", "win32.process_effect"], {"entity": "win32.get_std_handle"}],
                           ["call.foreign", [["b32", 0xFFFFFFF5], "n0.r1"], ["b64", "win32.process_effect"], {"entity": "win32.get_std_handle"}],
                           alloc("p2"),
                           ["heap.view", ["n2", "n2.r1", "n2.r2"], ["win32.bytes_rw", "buf", "mem"], {"attrs": [4096, 1]}],
                           alloc("n3.r2"),
                           ["heap.view", ["n4", "n4.r1", "n4.r2"], ["win32.u32_rw", "cnt", "mem"], {"attrs": [4, 4]}],
                           ["call.foreign", ["n0", "n3", ["b32", 4096], "n5", ["b64", 0], "p1", "n5.r2"],
                            ["b32", "win32.filesystem_effect", "mem"], {"entity": "win32.read_file"}],
                           ["checked.load.bits.le", ["n5", ["b32", 0], "n6.r2"], ["b32", "mem"], {"attrs": [4, 1]}],
                           ["pointer.cast", ["n3"], ["win32.bytes_read"]],
                           ["call.foreign", ["n1", "n8", "n7", "n5", ["b64", 0], "n6.r1", "n7.r1"],
                            ["b32", "win32.filesystem_effect", "mem"], {"entity": "win32.write_file"}],
                           free("n3", 4096, "win32.bytes_rw", "n9.r2"),
                           free("n5", 4, "win32.u32_rw", "n10.r1"),
                           ["call.foreign", ["n7", "n1.r1"], ["win32.process_effect"], {"entity": "win32.exit_process"}]],
                        "end": ["ret", ["n7", "n12", "n9.r1", "n11.r1"]]}]}],
        "package": {"name": "echo", "entries": {"app": "main"}, "release": "app"}}


class CarrierTests(unittest.TestCase):
    def test_construction_is_deterministic_and_verified(self):
        self.assertEqual(construct(_hello()).reader.canonical_bytes(), construct(_hello()).reader.canonical_bytes())

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_constructed_program_builds_and_runs(self):
        from xax_build import build
        from xax_linux import run_linux_executable

        constructed = construct(_hello(b"xax\n"))
        completed = run_linux_executable(build(constructed.reader, constructed.release_request.cid).artifact)
        self.assertEqual((completed.returncode, completed.stdout), (0, b"xax\n"))

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_startup_entities_read_arguments(self):
        from xax_build import build
        from xax_linux import run_linux_executable

        constructed = construct(_echo_argument())
        artifact = build(constructed.reader, constructed.release_request.cid).artifact
        completed = run_linux_executable(artifact, arguments=("meaning is source", "x"))
        self.assertEqual((completed.returncode, completed.stdout), (3, b"meaning is source"))
        clamped = run_linux_executable(artifact, arguments=("y" * 100,))
        self.assertEqual((clamped.returncode, clamped.stdout), (2, b"y" * 64))

    def test_startup_entities_are_entry_only_and_named_exactly(self):
        from xax_build import build
        from xax_compiler import XaxError

        request = _echo_argument()
        request["functions"][0]["blocks"][0]["nodes"][6][3]["entity"] = "linux.startup.fork"
        with self.assertRaises(ValueError):
            construct(request)
        helper = {"name": "count", "params": [], "returns": ["b64"], "blocks": [
            {"params": [], "nodes": [["call.foreign", [], ["b64"], {"entity": "linux.startup.argc"}]], "end": ["ret", ["n0"]]}]}
        request = _echo_argument()
        request["functions"].insert(0, helper)
        request["functions"][1]["blocks"][0]["nodes"][6] = ["call.direct", [], ["b64"], {"entity": {"fn": "count"}}]
        constructed = construct(request)
        with self.assertRaises(XaxError) as raised:
            build(constructed.reader, constructed.release_request.cid)
        self.assertEqual(raised.exception.diagnostic.code, "XAX.NATIVE.STARTUP")

    def test_malformed_requests_reject(self):
        def broken(edit):
            request = _hello()
            edit(request)
            return request

        node = lambda r: r["functions"][0]["blocks"][0]["nodes"]  # noqa: E731
        cases = {
            "format": broken(lambda r: r.update(format="text")),
            "unknown operation": broken(lambda r: node(r).__setitem__(2, ["shift.left", ["n1"], ["b8"]])),
            "unbound operand": broken(lambda r: node(r).__setitem__(2, ["int.truncate", ["n99"], ["b8"]])),
            "unknown type": broken(lambda r: r["types"].update(buf="float77")),
            "unknown entity": broken(lambda r: node(r)[0][3].update(entity="linux.fork")),
            "missing release": broken(lambda r: r["package"].update(release="lib")),
            "duplicate function": broken(lambda r: r["functions"].append(copy.deepcopy(r["functions"][0]))),
        }
        for name, request in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                construct(request)

    def test_windows_platform_builds_a_pe_from_stdio_contracts(self):
        from xax_build import build
        from xax_compiler import decode_native_target, x86_64_windows_pe_target

        constructed = construct(_windows_echo())
        self.assertEqual(constructed.reader.canonical_bytes(), construct(_windows_echo()).reader.canonical_bytes())
        self.assertEqual(constructed.target.cid, x86_64_windows_pe_target().cid)
        artifact = build(constructed.reader, constructed.release_request.cid).artifact
        self.assertEqual(artifact[:2], b"MZ")
        for name in (b"GetStdHandle", b"ReadFile", b"WriteFile", b"VirtualAlloc", b"VirtualFree", b"ExitProcess"):
            self.assertIn(name, artifact)
        self.assertEqual(decode_native_target(constructed.target).identity, b"x86_64-windows-pe-v1")

    def test_platform_names_do_not_cross_platforms(self):
        windows = _windows_echo()
        windows["functions"][0]["blocks"][0]["nodes"][12][3]["entity"] = "linux.exit_group"
        linux = _hello()
        linux["functions"][0]["blocks"][0]["nodes"][0][3]["entity"] = "win32.virtual_alloc"
        startup = _windows_echo()
        startup["functions"][0]["blocks"][0]["nodes"][0][3]["entity"] = "linux.startup.argc"
        for request in (windows, linux, startup):
            with self.subTest(platform=request["platform"]), self.assertRaises(ValueError):
                construct(request)

    @unittest.skipUnless(WINDOWS_X86_64, "requires a Windows x86-64 host")
    def test_windows_integer_completion_operations_run(self):
        """ADR-256: exit((n udiv 4) | ((n urem 5) & 3)) over the runtime byte count n, so nothing folds at build time."""
        import subprocess
        import tempfile

        from xax_build import build

        request = _windows_echo()
        block = request["functions"][0]["blocks"][0]
        block["nodes"][12:] = [
            ["int.zero.extend", ["n7"], ["b64"]],
            ["udiv", ["n12", ["b64", 4]], ["b64"]],
            ["urem", ["n12", ["b64", 5]], ["b64"]],
            ["bit.and", ["n14", ["b64", 3]], ["b64"]],
            ["bit.or", ["n13", "n15"], ["b64"]],
            ["int.truncate", ["n16"], ["b32"]],
            ["call.foreign", ["n17", "n1.r1"], ["win32.process_effect"], {"entity": "win32.exit_process"}]]
        block["end"] = ["ret", ["n17", "n18", "n9.r1", "n11.r1"]]
        constructed = construct(request)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "arith.exe")
            path.write_bytes(build(constructed.reader, constructed.release_request.cid).artifact)
            for data in (b"meaning is source\n", b"x" * 1001):
                with self.subTest(length=len(data)):
                    completed = subprocess.run([str(path)], input=data, capture_output=True, timeout=30)
                    self.assertEqual((completed.returncode, completed.stdout), ((len(data) // 4) | (len(data) % 5 & 3), data))

    @unittest.skipUnless(WINDOWS_X86_64, "requires a Windows x86-64 host")
    def test_windows_program_runs(self):
        import subprocess
        import tempfile

        from xax_build import build

        constructed = construct(_windows_echo())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "echo.exe")
            path.write_bytes(build(constructed.reader, constructed.release_request.cid).artifact)
            completed = subprocess.run([str(path)], input=b"meaning is source\n", capture_output=True, timeout=30)
        self.assertEqual((completed.returncode, completed.stdout), (18, b"meaning is source\n"))

    def test_verifier_rejects_semantic_errors(self):
        from xax_compiler import XaxError

        request = _hello()
        request["functions"][0]["blocks"][0]["end"][1][1] = "p0"  # returns the consumed process effect
        with self.assertRaises((XaxError, ValueError)):
            construct(request)


class Xb64Tests(unittest.TestCase):
    """The committed stores are the application; the request only reconstructs generation 0."""

    def test_request_reconstructs_generation_0(self):
        self.assertEqual(construct(XB64).reader.canonical_bytes(), STORES[0].read_bytes())

    def test_generation_1_is_the_maintenance_transaction(self):
        gen0 = StoreReader(STORES[0].read_bytes())
        constructed = construct(XB64)
        workspace = Workspace(gen0, constructed.target)
        for function in constructed.functions.values():
            workspace.function_nodes(function.cid, 1024)
        result = LocalMutationSession(workspace, expected_generation=workspace.generation).commit(MAINTENANCE_EDIT)
        self.assertTrue(result.committed)
        self.assertEqual(workspace.reader.canonical_bytes(), STORES[1].read_bytes())

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_xax_selftest_passes_on_both_releases_and_catches_an_incomplete_edit(self):
        from xax_linux import run_linux_executable

        for generation in (0, 1):
            builds = _builds(StoreReader(STORES[generation].read_bytes()))
            self.assertEqual(run_linux_executable(builds["test"]["artifact"]).returncode, 0)
            self.assertTrue(builds["app"]["reproducible"] and builds["test"]["reproducible"])
        constructed = construct(XB64)
        workspace = Workspace(StoreReader(STORES[0].read_bytes()), constructed.target)
        for function in constructed.functions.values():
            workspace.function_nodes(function.cid, 1024)
        LocalMutationSession(workspace, expected_generation=workspace.generation).commit(INCOMPLETE_EDIT)
        self.assertEqual(run_linux_executable(_builds(workspace.reader)["test"]["artifact"]).returncode, 8)

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_release_matches_rfc_4648_vectors(self):
        from xax_linux import run_linux_executable

        app = _builds(StoreReader(STORES[0].read_bytes()))["app"]["artifact"]
        for plain, encoded in ((b"", b""), (b"f", b"Zg==\n"), (b"fo", b"Zm8=\n"), (b"foo", b"Zm9v\n"), (b"foobar", b"Zm9vYmFy\n")):
            with self.subTest(plain=plain):
                completed = run_linux_executable(app, stdin=plain)
                self.assertEqual((completed.returncode, completed.stdout), (0, encoded))


if __name__ == "__main__":
    unittest.main()
