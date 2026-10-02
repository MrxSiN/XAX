from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from benchmarks.bench_oi16_target_granularity import (
    EVIDENCE,
    TIMING,
    OPAQUE_REQUIRED,
    PackageError,
    TARGETS,
    WIDTHS,
    decode_per_instruction,
    decode_shared_primitives,
    deterministic_evidence,
    encode_per_instruction,
    encode_shared_primitives,
    lower_one,
    normalized_contracts,
    opaque_fixtures,
    package_identity,
    validate_opaque_contract,
)


class OI16TargetGranularityTests(unittest.TestCase):
    def test_package_forms_normalize_exactly(self):
        for target in TARGETS:
            per = decode_per_instruction(encode_per_instruction(target))
            shared = decode_shared_primitives(encode_shared_primitives(target))
            self.assertEqual(normalized_contracts(per), normalized_contracts(shared))
            self.assertNotEqual(package_identity(encode_per_instruction(target)), package_identity(encode_shared_primitives(target)))

    def test_package_encoding_is_deterministic(self):
        for target in TARGETS:
            self.assertEqual(encode_per_instruction(target), encode_per_instruction(target))
            self.assertEqual(encode_shared_primitives(target), encode_shared_primitives(target))

    def test_digest_corruption_rejected(self):
        payload = bytearray(encode_per_instruction("x86_64_windows"))
        payload[-33] ^= 1
        with self.assertRaisesRegex(PackageError, "digest"):
            decode_per_instruction(bytes(payload))

    def test_wrong_form_rejected(self):
        with self.assertRaisesRegex(PackageError, "wrong package form"):
            decode_per_instruction(encode_shared_primitives("x86_64_windows"))

    def test_both_forms_emit_identical_artifacts(self):
        for target in TARGETS:
            for width in WIDTHS:
                first = lower_one(target, width, "per_instruction")[2].artifact_bytes
                second = lower_one(target, width, "shared_primitive")[2].artifact_bytes
                self.assertEqual(first, second)

    def test_wasm_execution_matches_reference_for_both_forms(self):
        from xax_compiler import execute
        from xax_wasm import run_wasm_isolated
        for width in WIDTHS:
            for form in ("per_instruction", "shared_primitive"):
                reader, entry, image, _, _ = lower_one("wasm32_core", width, form)
                self.assertEqual(run_wasm_isolated(image, (7, 3, 2)), execute(reader, entry.cid, (7, 3, 2)))

    def test_opaque_top_level_fields_are_mandatory(self):
        arithmetic, _ = opaque_fixtures()
        for field in OPAQUE_REQUIRED:
            damaged = copy.deepcopy(arithmetic)
            del damaged[field]
            with self.assertRaises(PackageError, msg=field):
                validate_opaque_contract(damaged)

    def test_opaque_nested_behavior_must_be_explicit(self):
        arithmetic, _ = opaque_fixtures()
        for container, field in (("control", "trap"), ("memory", "ordering"), ("legality", "privilege"), ("optimization", "barrier")):
            damaged = copy.deepcopy(arithmetic)
            del damaged[container][field]
            with self.assertRaises(PackageError, msg=f"{container}.{field}"):
                validate_opaque_contract(damaged)

    def test_accelerator_sync_requires_scope_and_spaces(self):
        _, accelerator = opaque_fixtures()
        self.assertEqual(validate_opaque_contract(accelerator, accelerator=True), "device-space-1")
        for container, field in (
            ("legality", "supported_scopes"),
            ("memory", "source_space"),
            ("memory", "destination_space"),
            ("memory", "visibility"),
        ):
            damaged = copy.deepcopy(accelerator)
            del damaged[container][field]
            with self.assertRaises(PackageError, msg=f"{container}.{field}"):
                validate_opaque_contract(damaged, accelerator=True)

    def test_deterministic_evidence_excludes_host_timing_values(self):
        first = deterministic_evidence()
        second = deterministic_evidence()
        self.assertEqual(first, second)
        self.assertNotIn("summary_ns", first["timing"])

    def test_committed_evidence_shape_if_present(self):
        if EVIDENCE.exists():
            data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], "xax.oi16.target-granularity.evidence.v1")
            self.assertEqual(set(data["targets"]), set(TARGETS))
            self.assertFalse(data["canonical_target_schema_changed"])
        if TIMING.exists():
            data = json.loads(TIMING.read_text(encoding="utf-8"))
            self.assertEqual(data["sample_count_per_target_form"], 20)


if __name__ == "__main__":
    unittest.main()
