"""S15a (ADR-286): the Linux x86-64 production compiler's seed is a pinned XAX-built compiler; no Python builds it.

The seed is pinned; the request store is the committed driver store's canonical build request; the record of the
seed's Python-free self-build describes both; and, on Linux x86-64, ``selfbuild.sh`` runs with ``PATH`` holding only
its tools: no Python can run.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xax_selfhost import FULL_SELFHOST_EVIDENCE, SEED_EVIDENCE, seed_requires_python
from xax_selfhost_seed import REQUEST_PATH, SEED_PATH, SEED_SHA256, SEED_SIZE, SELFBUILD_PATH, SELFBUILD_TOOLS

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


class PythonFreeSeedTests(unittest.TestCase):
    def test_the_seed_is_pinned(self):
        data = SEED_PATH.read_bytes()
        self.assertEqual((hashlib.sha256(data).hexdigest(), len(data)), (SEED_SHA256, SEED_SIZE))
        self.assertTrue(os.access(SEED_PATH, os.X_OK))
        self.assertEqual(data[:4], b"\x7fELF")

    def test_the_request_store_is_the_committed_compilers(self):
        from xax_selfhost_compiler import compiler_request

        self.assertEqual(REQUEST_PATH.read_bytes(), compiler_request()[0].data, "regenerate it: python -m xax_selfhost_seed write-request")

    def test_the_record_decides_whether_the_seed_requires_python(self):
        full = json.loads(FULL_SELFHOST_EVIDENCE.read_text(encoding="utf-8"))
        seed = json.loads(SEED_EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(seed["request_store_sha256"], hashlib.sha256(REQUEST_PATH.read_bytes()).hexdigest())
        self.assertFalse(seed_requires_python(full, seed))
        self.assertTrue(seed_requires_python(full, None))
        for path, value in ((("environment", "python_on_path"), "/usr/bin/python3"), (("seed", "sha256"), "0" * 64), (("selfbuild_status",), 1)):
            broken = copy.deepcopy(seed)
            target = broken
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            self.assertTrue(seed_requires_python(full, broken), path)

    @unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the seed runs on Linux x86-64 only")
    def test_the_seed_rebuilds_the_compiler_without_python(self):
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory) / "tools"
            tools.mkdir()
            for tool in SELFBUILD_TOOLS:
                os.symlink(shutil.which(tool), tools / tool)
            environment = {"PATH": str(tools)}
            probe = subprocess.run(["/bin/sh", "-c", "command -v python3 || command -v python"], env=environment, capture_output=True, text=True)
            self.assertNotEqual(probe.returncode, 0)
            self.assertEqual(probe.stdout, "")  # no Python resolves
            output = Path(directory) / "out"
            self.assertEqual(subprocess.run([str(tools / "sh"), str(SELFBUILD_PATH), str(output)], env=environment, timeout=3000).returncode, 0)
            self.assertEqual((output / "xaxc1").read_bytes(), (output / "xaxc2").read_bytes())


if __name__ == "__main__":
    unittest.main()
