"""OI-37 evidence workload: arena + index chained hash table on Linux x86-64."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import unittest
from pathlib import Path

from xax_linux import run_linux_executable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.linux_chains import EVIDENCE, compile_chains, reference_chains  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


class ChainsTests(unittest.TestCase):
    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_small_tables_match_reference(self):
        for nodes, buckets in ((1, 2), (4096, 64), (3000, 4096)):
            with self.subTest(nodes=nodes, buckets=buckets):
                _program, executable = compile_chains(nodes, buckets)
                completed = run_linux_executable(executable.data)
                self.assertEqual((completed.returncode, completed.stdout), (0, reference_chains(nodes, buckets)))

    def test_committed_artifact_identity_reproduces(self):
        program, executable = compile_chains()
        evidence = json.loads(EVIDENCE.read_text())
        self.assertEqual(evidence["xax"]["artifact_sha256"], hashlib.sha256(executable.data).hexdigest())
        self.assertEqual(evidence["xax"]["program_root"], program.reader.root_cid.hex())


if __name__ == "__main__":
    unittest.main()
