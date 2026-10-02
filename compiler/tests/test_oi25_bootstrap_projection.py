from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from bench_oi25_bootstrap_projection import (  # noqa: E402
    BOOTSTRAP, EXPECTED_ENTRIES, PROGRAM, SEED, _entries, _semantic_mutation,
    _unknown_layout, attribute_differences, build_deterministic_seed, build_evidence,
    build_seed, project_seed_pyz_v1, projected_digest, run_seed,
)


class OI25BootstrapProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = SEED.read_bytes()
        cls.program = PROGRAM.read_bytes()
        cls.entries = _entries(cls.seed)

    def test_projection_normalizes_only_declared_timestamp_fields(self):
        a = build_seed(self.entries, 2024)
        b = build_seed(self.entries, 2025)
        self.assertNotEqual(a, b)
        self.assertEqual(project_seed_pyz_v1(a), project_seed_pyz_v1(b))
        attrs = attribute_differences(a, b)
        self.assertTrue(attrs)
        self.assertTrue(all("dos-time-date" in item["field"] for item in attrs))

    def test_projection_matches_deterministic_emitter(self):
        variable = build_seed(self.entries, 2026)
        deterministic = build_deterministic_seed(self.entries)
        self.assertEqual(project_seed_pyz_v1(variable), deterministic)
        with zipfile.ZipFile(io.BytesIO(deterministic), "r") as archive:
            self.assertEqual(tuple(i.filename for i in archive.infolist()), EXPECTED_ENTRIES)
            self.assertTrue(all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in archive.infolist()))

    def test_semantic_mutation_is_not_hidden(self):
        good = build_deterministic_seed(self.entries)
        bad = build_seed(_semantic_mutation(self.entries), 1980)
        self.assertNotEqual(projected_digest(good), projected_digest(bad))
        result = run_seed(bad, self.program)
        self.assertEqual(result["returncode"], 0)
        self.assertFalse(result["byte_identical_to_input"])

    def test_unknown_layout_rejects(self):
        with self.assertRaisesRegex(ValueError, "LAYOUT"):
            project_seed_pyz_v1(_unknown_layout(self.entries))

    def test_corrupt_payload_rejects(self):
        data = bytearray(build_deterministic_seed(self.entries))
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            info = archive.getinfo("__main__.py")
            # Compressed data starts after fixed header + filename; no extra is allowed by v1.
            data[info.header_offset + 30 + len(info.filename) + 2] ^= 1
        with self.assertRaises(Exception):
            project_seed_pyz_v1(bytes(data))

    def test_metadata_only_variants_execute_identically(self):
        for year in (2024, 2025, 2026):
            result = run_seed(build_seed(self.entries, year), self.program)
            self.assertEqual(result["returncode"], 0, result["stderr"])
            self.assertTrue(result["byte_identical_to_input"])

    def test_production_generator_normalizes_zip_timestamp(self):
        path = BOOTSTRAP / "generate_m14.py"
        spec = importlib.util.spec_from_file_location("xax_generate_m14_oi25", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="xax-oi25-generator-") as directory:
            target = Path(directory) / "seed.pyz"
            module._build_seed_archive(target)
            with zipfile.ZipFile(target, "r") as archive:
                self.assertTrue(all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in archive.infolist()))

    def test_evidence_closure_shape(self):
        evidence, _ = build_evidence(False)
        self.assertEqual(evidence["status"], "closed")
        self.assertTrue(evidence["canonical_target"]["b4"])
        self.assertTrue(evidence["variable_artifact"]["all_raw_distinct"])
        self.assertTrue(evidence["variable_artifact"]["all_projected_identical"])
        self.assertEqual(evidence["implementation"]["selected"], "deterministic-emitter-byte-identity")

    def test_committed_evidence_matches_deterministic_replay(self):
        evidence, _ = build_evidence(False)
        committed = json.loads((Path(__file__).resolve().parents[1] / "benchmarks" / "oi25_bootstrap_projection_evidence.json").read_text())
        self.assertEqual(committed, json.loads(json.dumps(evidence)))


if __name__ == "__main__":
    unittest.main()
