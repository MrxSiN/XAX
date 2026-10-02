"""The universal replacement matrix never records a level its evidence does not support."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from xax_replacement import MatrixError, achieved_level, load_matrix, validate_matrix

REPOSITORY = Path(__file__).resolve().parents[2]


class ReplacementMatrixTests(unittest.TestCase):
    def setUp(self):
        self.matrix = load_matrix(REPOSITORY)

    def _target(self, matrix, target_id):
        return next(item for item in matrix["targets"] if item["id"] == target_id)

    def _rejects(self, matrix, fragment):
        with self.assertRaises(MatrixError) as caught:
            validate_matrix(matrix, REPOSITORY)
        self.assertIn(fragment, str(caught.exception))

    def test_committed_matrix_is_consistent(self):
        validate_matrix(self.matrix, REPOSITORY)
        self.assertEqual(achieved_level(self._target(self.matrix, "linux-x86_64-elf")), "R2")

    def test_benchmark_scale_utility_is_not_r3(self):
        target = self._target(self.matrix, "linux-x86_64-elf")
        self.assertEqual(target["capabilities"]["practical_application"]["label"], "PROTOTYPE")
        self.assertNotIn(target["replacement_level"], ("R3", "R4", "R5", "R6"))

    def test_overclaimed_level_rejects(self):
        matrix = copy.deepcopy(self.matrix)
        self._target(matrix, "linux-x86_64-elf")["replacement_level"] = "R4"
        self._rejects(matrix, "differs from evidence-supported level R2")

    def test_uncompetitive_measurement_cannot_reach_r4(self):
        matrix = copy.deepcopy(self.matrix)
        target = self._target(matrix, "linux-x86_64-elf")
        for name in ("ffi", "platform_apis", "abi", "practical_application"):
            target["capabilities"][name]["label"] = "EXECUTED"
        self.assertEqual(achieved_level(target), "R3")
        target["capabilities"]["performance_evidence"]["competitive"] = True
        self.assertEqual(achieved_level(target), "R4")

    def test_execution_claim_requires_existing_evidence(self):
        matrix = copy.deepcopy(self.matrix)
        self._target(matrix, "linux-x86_64-elf")["capabilities"]["simd"] = {"label": "EXECUTED", "note": "claimed", "evidence": []}
        self._rejects(matrix, "requires an evidence path")
        self._target(matrix, "linux-x86_64-elf")["capabilities"]["simd"]["evidence"] = ["compiler/benchmarks/does_not_exist.json"]
        self._rejects(matrix, "evidence path does not exist")

    def test_unknown_label_and_xax_runtime_reject(self):
        matrix = copy.deepcopy(self.matrix)
        self._target(matrix, "wasm32-core")["capabilities"]["simd"]["label"] = "WORKS"
        self._rejects(matrix, "unknown label")
        matrix = copy.deepcopy(self.matrix)
        self._target(matrix, "wasm32-core")["runtime_requirement"]["xax_runtime"] = ["gc"]
        self._rejects(matrix, "FND-004")


if __name__ == "__main__":
    unittest.main()
