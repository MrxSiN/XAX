"""S12e.2 (ADR-276): the compiler driver lowers ordinary Linux programs with the general x86-64 backend program.

The general driver is the S10/S11 driver (``xax_selfhost_driver.build_driver_program(general=True)``) with the general
backend program (S12a-S12f.1) linked in.  For a target whose identity is a Linux ELF profile it builds the general
program's object table itself (the program store, the target, the verifier's pointer extents taken from the facts
engine during its own semantic verification, and the trap payload heads), calls the program, and writes the ELF
file the program assembled.  Every run below is a real process with no Python inside.  Differential: each output
equals ``compile_linux_executable`` (the executable bytes, or the exact ``Diagnostic``); where the general program
leaves a decision to the bootstrap, the driver declines (S12f.2: code generation rejections are the program's).  The
views profiles are lowered exactly as before.  S12e.3
(ADR-277): the general driver verifies its own store and rebuilds itself through three generations as processes.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_selfhost_diagnostics import decode_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _root_entry(reader):
    module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
    return next(cid for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class GeneralDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver, load_driver_program
        from xax_x86_64_views import compile_x86_64_views

        reader, function = load_driver_program(general=True)
        cls.image = compile_x86_64_views(reader, function.cid, X.x86_64_views_exec_target(), backend="xax")
        cls.driver = NativeGeneralDriver(cls.image)
        cls.directory = tempfile.mkdtemp()

    def run_driver(self, data: bytes, target):
        from xax_selfhost_driver import target_package

        store, package, output = (os.path.join(self.directory, name) for name in ("store.xax", "target.xax", "out.bin"))
        Path(store).write_bytes(data)
        Path(package).write_bytes(target_package(target))
        if os.path.exists(output):
            os.unlink(output)
        status = self.driver.run(store, package, output)
        produced = Path(output).read_bytes() if os.path.exists(output) else None
        if status == 0:
            return "image", produced
        if status == 1:
            return "rejected", decode_record([int.from_bytes(produced[k:k + 8], "little") for k in range(0, len(produced), 8)])
        return {2: "declined", 3: "failed"}[status], None

    def assertLinuxOutcome(self, reader, target):
        """The driver's outcome for the store's root entry equals ``compile_linux_executable``'s."""
        from xax_linux import compile_linux_executable

        entry = _root_entry(reader)
        try:
            expected = ("image", compile_linux_executable(reader, entry, target.cid).data)
        except X.XaxError as error:
            expected = ("rejected", error.diagnostic)
        outcome = self.run_driver(reader.data, target)
        self.assertEqual(outcome, expected)
        return outcome

    def test_executables(self):
        """Static (status, jsonmin, chains) and dynamic (a C import) executables: the bootstrap's bytes."""
        from benchmarks.jsonmin import build_jsonmin
        from benchmarks.linux_chains import build_chains_program
        from test_xax_linux import _crc_program, _status_program

        programs = []
        reader, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        programs.append(("status", reader, target))
        reader, _entry, target = _crc_program(X.x86_64_linux_dynamic_exec_target())
        programs.append(("crc", reader, target))
        jsonmin = build_jsonmin()
        programs.append(("jsonmin", jsonmin.reader, jsonmin.target))
        for links in ("index", "soa"):
            chains = build_chains_program(links=links)
            programs.append((f"chains-{links}", chains.reader, chains.target))
        for name, reader, target in programs:
            with self.subTest(name):
                self.assertEqual(self.assertLinuxOutcome(reader, target)[0], "image")

    def test_the_executable_runs(self):
        from test_xax_linux import _status_program
        from xax_linux import run_linux_executable

        reader, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        kind, data = self.run_driver(reader.data, target)
        self.assertEqual(kind, "image")
        self.assertEqual(run_linux_executable(data).returncode, 7)

    def test_rejections_are_the_general_programs(self):
        from test_xax_selfhost_general import B32, _call, _function, _process, _store

        target = X.x86_64_linux_exec_target()
        pair, items = _function((B32,), (B32, B32), lambda g, b: b.ret(b.params[0], b.params[0]))
        cases = {
            "NATIVE-ABI-ARITY": _store(_process([_call(pair, (B32,), (B32, B32))]), target, *items)[0],
            "LINUX-PROCESS-ENTRY-CONTRACT": _store(_function((B32,), (B32,), lambda g, b: b.ret(b.params[0])), target, X.bits_type(64))[0],
        }
        for rule, reader in cases.items():
            with self.subTest(rule):
                kind, diagnostic = self.assertLinuxOutcome(reader, target)
                self.assertEqual((kind, diagnostic.rule), ("rejected", rule))

    def test_a_code_generation_rejection_is_the_general_programs(self):
        """S12f.2 (ADR-278): a C import in the static profile is rejected during code generation with the bootstrap's
        diagnostic."""
        from test_xax_linux import _crc_program

        reader, _entry, target = _crc_program(X.x86_64_linux_exec_target())
        kind, diagnostic = self.assertLinuxOutcome(reader, target)
        self.assertEqual((kind, diagnostic.rule), ("rejected", "SYSV-C-REQUIRES-DYNAMIC-PROFILE"))

    def test_views_profiles_are_unchanged(self):
        from test_xax_selfhost_driver import BOOTSTRAP, _reference

        target = X.x86_64_views_target()
        data = (BOOTSTRAP / "xax_blake3_compress.xax").read_bytes()
        self.assertEqual(self.run_driver(data, target), _reference(data, target))


    def test_the_general_driver_rebuilds_itself_as_processes(self):
        """S12e.3: gen1 (the XAX views backend's executable) lowers the general driver's store to gen2, gen2 to gen3;
        gen1 = gen2 = gen3 = ``views_executable`` of the bootstrap generator's image."""
        import subprocess

        from xax_selfhost_driver import GENERAL_STORE_PATH, target_package
        from xax_x86_64_views import compile_x86_64_views, views_executable

        reader = X.StoreReader(GENERAL_STORE_PATH.read_bytes())
        entry = _root_entry(reader)
        self.assertEqual(self.image, compile_x86_64_views(reader, entry, X.x86_64_views_exec_target(), backend="python"))
        package = Path(self.directory) / "exec.xax"
        package.write_bytes(target_package(X.x86_64_views_exec_target()))
        generation = Path(self.driver.path)
        executables = [generation.read_bytes()]
        for name in ("gen2", "gen3"):
            output = Path(self.directory) / name
            status = subprocess.run([str(generation), "lower", str(GENERAL_STORE_PATH), str(package), str(output)], check=False).returncode
            self.assertEqual(status, 0, name)
            os.chmod(output, 0o755)
            executables.append(output.read_bytes())
            generation = output
        self.assertEqual(executables[0], views_executable(self.image))
        self.assertEqual(executables[1], executables[0])
        self.assertEqual(executables[2], executables[0])


if __name__ == "__main__":
    unittest.main()
