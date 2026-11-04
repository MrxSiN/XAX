"""Gates for the evidence-and-canonical-state integrity milestone (ADR-177).

Each test names the audit failure it keeps from recurring.  Store regeneration is in ``test_store_regeneration.py``,
derived B status in ``test_full_selfhost_status.py`` and ``test_python_free_seed.py``, the wheel in ``test_wheel_install.py``, evidence validation in
``test_replacement_matrix.py``, and generated status blocks in ``test_status_docs.py``.
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import xax_native

COMPILER = Path(__file__).resolve().parents[1]
BOOTSTRAP = COMPILER / "bootstrap"
BENCHMARKS = COMPILER / "benchmarks"


def _environment(src: Path) -> dict:
    return {**{k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "XAX_REQUIRE_NATIVE")}, "PYTHONPATH": str(src),
            "PYTHONDONTWRITEBYTECODE": "1"}


class SelfhostEvidenceCurrencyTests(unittest.TestCase):
    """CANONICAL_TYPING_EVIDENCE_CURRENT: every B1 entry names the committed store it describes."""

    def test_every_b1_entry_is_bound_to_the_committed_store(self):
        for name in ("selfhost_closure_evidence.json", "selfhost_x86_64_evidence.json"):
            evidence = json.loads((BENCHMARKS / name).read_text(encoding="utf-8"))
            for entry in evidence["b1_gen1_images"]:
                module = importlib.import_module(entry["program"])
                committed = hashlib.sha256(module.STORE_PATH.read_bytes()).hexdigest()
                self.assertEqual(entry["store_sha256"], committed, (name, entry["program"]))
                if entry.get("native_rerun_required"):
                    self.assertIsNone(entry["gen1_equals_bootstrap_reference"])  # never an execution this host did not do


class SeedTests(unittest.TestCase):
    def test_the_bootstrap_seed_is_native(self):
        """W3 (ADR-362): the M14 Python zipapp seed is retired; the only bootstrap seed is the pinned native compiler
        (``test_python_free_seed`` checks its pin and its Python-free self-build), and no Python seed or generator is
        left in ``bootstrap/``."""
        from xax_selfhost import bootstrap_status

        self.assertEqual(sorted(path.name for path in BOOTSTRAP.rglob("*.pyz")), [])
        self.assertFalse((BOOTSTRAP / "generate_m14.py").exists())
        self.assertFalse((BOOTSTRAP / "m14_selfhost_evidence.json").exists())
        seed = bootstrap_status()["bootstrap_seed"]
        self.assertEqual((seed["kind"], seed["path"], seed["requires_python"]), ("native-elf", "compiler/bootstrap/seed/xaxc-linux-x86_64", False))


class NativeAuthorityTests(unittest.TestCase):
    """NATIVE_AUTHORITY_OBSERVABLE and NO_SILENT_XAX_EVIDENCE_FALLBACK."""

    PROBE = (
        "import json, xax_compiler as X, xax_native\n"
        "X.verify_store(X.StoreReader(open(r'{store}', 'rb').read()))\n"
        "print(json.dumps(xax_native.AUTHORITY))\n"
    )

    def _run(self, **environment):
        env = {**_environment(COMPILER / "src"), **environment}
        probe = self.PROBE.format(store=BOOTSTRAP / "m11_compiler_subset.xax")
        return subprocess.run([sys.executable, "-c", probe], cwd=COMPILER, env=env, capture_output=True, text=True)

    def test_every_component_reports_its_actual_authority(self):
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        authority = json.loads(completed.stdout)
        for component in ("store-decoder", "store-verifier", "typing"):
            entry = authority[component]
            if xax_native.native_host() is None:
                self.assertEqual(entry["actual_authority"], "xax", entry)
                self.assertEqual(len(entry["native_artifact_digest"]), 64)
            else:
                self.assertEqual((entry["actual_authority"], entry["fallback_occurred"]), ("python", True), entry)
                self.assertIn("Linux x86-64", entry["fallback_reason"])

    def test_required_native_execution_cannot_fall_back_silently(self):
        completed = self._run(XAX_REQUIRE_NATIVE="1")
        if xax_native.native_host() is None:
            self.assertEqual(completed.returncode, 0, completed.stderr)
        else:
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("NativeFallback", completed.stderr)

    def test_an_explicit_python_request_is_not_a_fallback_error(self):
        opt_outs = {name: "1" for name in ("XAX_BLAKE3_PYTHON_HASH", "XAX_STORE_PYTHON_DECODER", "XAX_GRAPH_PYTHON_DECODER", "XAX_CFG_PYTHON",
                                           "XAX_TYPING_PYTHON", "XAX_VERIFY_PYTHON")}
        completed = self._run(**opt_outs, XAX_REQUIRE_NATIVE="1")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        authority = json.loads(completed.stdout)
        self.assertEqual(authority["store-verifier"]["requested_authority"], "python")
        self.assertFalse(authority["store-verifier"]["fallback_occurred"])


class NativeCacheTests(unittest.TestCase):
    """NATIVE_CACHE_AUTHENTICATED: a cache entry runs only when it is well formed, for this key, with its digest."""

    def test_only_an_exact_entry_is_accepted(self):
        key, other = hashlib.sha256(b"key").digest(), hashlib.sha256(b"other").digest()
        code = bytes(range(64))
        good = xax_native.cache_entry(key, code, 16)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "entry.bin"
            cases = {
                "good": (good, key, (code, 16)),
                "wrong key": (good, other, None),
                "truncated": (good[:-1], key, None),
                "flipped code": (good[:-1] + bytes((good[-1] ^ 1,)), key, None),
                "bad magic": (b"Y" + good[1:], key, None),
                "entry outside code": (xax_native.cache_entry(key, code, 64), key, None),
                "old format": (good[88:], key, None),
            }
            for name, (data, lookup, expected) in cases.items():
                path.write_bytes(data)
                self.assertEqual(xax_native.cache_read(path, lookup), expected, name)

    @unittest.skipUnless(hasattr(os, "getuid"), "UNAVAILABLE: POSIX ownership and permission bits")
    def test_a_shared_cache_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            shared = Path(directory) / "cache"
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            previous = os.environ.get("XAX_NATIVE_CACHE")
            os.environ["XAX_NATIVE_CACHE"] = str(shared)
            try:
                self.assertIsNone(xax_native.cache_dir())
                shared.chmod(0o700)
                self.assertEqual(xax_native.cache_dir(), shared)
            finally:
                if previous is None:
                    del os.environ["XAX_NATIVE_CACHE"]
                else:
                    os.environ["XAX_NATIVE_CACHE"] = previous


if __name__ == "__main__":
    unittest.main()
