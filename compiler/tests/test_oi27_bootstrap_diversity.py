from __future__ import annotations
import json
import shutil
from pathlib import Path
import tempfile
import unittest

from benchmarks.bench_oi27_bootstrap_diversity import (
    EVIDENCE, EXPECTED_M11_ROOT, EXPECTED_M14_ROOT, GO_SOURCE, M11, M14, TIMING,
    _malformed_but_canonical, _rehashed_inner_corruption, _valid_semantic_divergence,
    build_checker, checker, experiment,
)

@unittest.skipUnless(shutil.which("go"), "UNAVAILABLE: the Go toolchain is not installed, so the independent checker cannot be built")
class OI27BootstrapDiversityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="oi27-test-")
        cls.binary=Path(cls.tmp.name)/"checker"
        cls.build=build_checker(cls.binary)

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def _path(self,name,data):
        p=Path(self.tmp.name)/name;p.write_bytes(data);return p

    def test_independent_checker_is_go_and_dependency_free(self):
        src=GO_SOURCE.read_text()
        self.assertIn("package main",src)
        self.assertNotIn("xax_compiler",src)
        self.assertGreater(self.build["bytes"],0)

    def test_independent_blake3_known_vectors(self):
        e=self._path("empty",b"");a=self._path("abc",b"abc")
        self.assertEqual(checker(self.binary,"hash",e).stdout.strip(),"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        self.assertEqual(checker(self.binary,"hash",a).stdout.strip(),"6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")

    def test_m11_and_m14_verify_with_pinned_roots(self):
        self.assertEqual(checker(self.binary,"verify",M11,EXPECTED_M11_ROOT).returncode,0)
        self.assertEqual(checker(self.binary,"verify",M14,EXPECTED_M14_ROOT).returncode,0)

    def test_rewrite_is_byte_identical(self):
        out=Path(self.tmp.name)/"rewrite.xax"
        self.assertEqual(checker(self.binary,"rewrite",M14,output=out).returncode,0)
        self.assertEqual(out.read_bytes(),M14.read_bytes())

    def test_valid_semantic_divergence_requires_pinned_root(self):
        p=self._path("diverge.xax",_valid_semantic_divergence())
        self.assertEqual(checker(self.binary,"verify",p,"-").returncode,0)
        self.assertNotEqual(checker(self.binary,"verify",p,EXPECTED_M11_ROOT).returncode,0)

    def test_independent_semantics_catches_primary_verifier_omission(self):
        p=self._path("badsem.xax",_malformed_but_canonical())
        self.assertEqual(checker(self.binary,"container",p).returncode,0)
        self.assertNotEqual(checker(self.binary,"verify",p,"-").returncode,0)

    def test_hash_checker_catches_rehashed_inner_corruption(self):
        p=self._path("hashbug.xax",_rehashed_inner_corruption(M11.read_bytes()))
        self.assertNotEqual(checker(self.binary,"container",p).returncode,0)

    def test_runtime_corruption_rejects(self):
        data=bytearray(M14.read_bytes());data[len(data)//2]^=1
        p=self._path("runtime.xax",bytes(data))
        self.assertNotEqual(checker(self.binary,"container",p).returncode,0)

    def test_deterministic_experiment_without_timings(self):
        a,_=experiment(measure=False);b,_=experiment(measure=False)
        self.assertEqual(a,b)
        self.assertTrue(a["comparison"]["b2_b4_reconstruction_byte_identical"])
        self.assertTrue(all(v.get("detected",v.get("detected_by_pinned_release_root",v.get("detected_by_independent_semantics",False))) for v in a["fault_injection"].values()))

    def test_committed_evidence_shape(self):
        if not EVIDENCE.exists() or not TIMING.exists(): self.skipTest("evidence not generated")
        e=json.loads(EVIDENCE.read_text());t=json.loads(TIMING.read_text())
        self.assertEqual(e["status"],"closed")
        self.assertEqual(e["selected_threshold"],"release-only independent verifier+canonical-serializer/hash checker; no permanent second compiler")
        self.assertEqual(e["host_observations_nonsemantic"],t["host"])

if __name__=="__main__": unittest.main()
