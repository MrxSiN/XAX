"""S14a (ADR-284): the general driver compiles itself with the general (optimizing) x86-64 backend, to a fixed point.

C0 is the general driver lowered by the XAX views backend (S12e.3's executable, the seed).  C0 lowers the general
driver's own store for ``x86_64-linux-elf-exec-v1`` with the general backend program: C1.  C1 lowers the same store to
C2, and C2 to C3.  Every step is a process with no Python inside, and C1 = C2 = C3 byte for byte.  C1 is a working
compiler: its ``lower`` output equals ``compile_linux_executable``'s.  (C1's equality with the bootstrap's own compile of
the store, about ten minutes of Python, is recorded by ``benchmarks/bench_selfhost_compiler.py``.)
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class CompilerFixedPointTests(unittest.TestCase):
    def test_the_compiler_rebuilds_itself_with_the_general_backend(self):
        from test_xax_linux import _status_program
        from xax_linux import compile_linux_executable, run_linux_executable
        from xax_selfhost_driver import GENERAL_STORE_PATH, NativeGeneralDriver, target_package

        directory = Path(tempfile.mkdtemp())
        seed = NativeGeneralDriver()
        target = directory / "linux.xax"
        target.write_bytes(target_package(X.x86_64_linux_exec_target()))
        generation, executables = Path(seed.path), []
        for name in ("C1", "C2", "C3"):
            output = directory / name
            status = subprocess.run([str(generation), "lower", str(GENERAL_STORE_PATH), str(target), str(output)], check=False, timeout=3000).returncode
            self.assertEqual(status, 0, name)
            os.chmod(output, 0o755)
            executables.append(output.read_bytes())
            generation = output
        self.assertEqual(executables[1], executables[0])
        self.assertEqual(executables[2], executables[0])
        self.assertNotEqual(executables[0], seed.executable)  # the optimizing backend's compiler, not the views backend's

        program, entry, program_target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        store, package, output = directory / "program.xax", directory / "target.xax", directory / "program.elf"
        store.write_bytes(program.data)
        package.write_bytes(target_package(program_target))
        self.assertEqual(subprocess.run([str(directory / "C1"), "lower", str(store), str(package), str(output)], check=False).returncode, 0)
        self.assertEqual(output.read_bytes(), compile_linux_executable(program, entry.cid, program_target.cid).data)
        self.assertEqual(run_linux_executable(output.read_bytes()).returncode, 7)


if __name__ == "__main__":
    unittest.main()
