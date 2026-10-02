from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from xax_compiler import XaxError

from benchmarks.bench_oi23_package_resolver import (
    CATALOG_VERSION,
    DEFAULT_LIMITS,
    ResolverLimits,
    Requirement,
    Version,
    VersionConstraint,
    add_dependency,
    adversarial_backtrack,
    ai_tasks,
    ambiguous_fixture,
    build_evidence,
    catalog_digest,
    corpus,
    decode_catalog,
    encode_catalog,
    make_catalog,
    realistic_diamond,
    realistic_major_coexistence,
    realistic_service,
    replace_dependency,
    resolve,
    selected_versions,
    unsatisfied_fixture,
)


class OI23PackageResolverTests(unittest.TestCase):
    def test_catalog_roundtrip_is_canonical_and_digest_checked(self):
        catalog, _ = realistic_diamond()
        encoded = encode_catalog(catalog)
        decoded = decode_catalog(encoded, catalog.objects)
        self.assertEqual(encoded, encode_catalog(decoded))
        self.assertEqual(catalog_digest(catalog), catalog_digest(decoded))

        damaged = bytearray(encoded)
        damaged[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            decode_catalog(bytes(damaged), catalog.objects)

        damaged = bytearray(encoded)
        # XRV1 is followed by one-byte version 1 in this experiment.
        self.assertEqual(damaged[4], CATALOG_VERSION)
        damaged[4] = CATALOG_VERSION + 1
        payload = bytes(damaged[:-32])
        from blake3 import blake3
        damaged[-32:] = blake3(payload).digest()
        with self.assertRaisesRegex(ValueError, "unsupported .* catalog version"):
            decode_catalog(bytes(damaged), catalog.objects)

    def test_diamond_uses_conjunctive_range_and_is_input_order_independent(self):
        catalog, root = realistic_diamond()
        first = resolve(root, catalog)
        reversed_catalog = type(catalog)(tuple(sorted(reversed(catalog.entries), key=lambda item: (item.logical_identity, item.version, item.package_root))), catalog.objects)
        second = resolve(root, reversed_catalog)
        self.assertEqual(first.snapshot_digest, second.snapshot_digest)
        self.assertEqual(selected_versions(first, catalog)["shared"], "6.0.0")
        self.assertEqual(first.selected_roots, second.selected_roots)

    def test_exact_root_is_authoritative_and_repairs_ambiguous_coordinate(self):
        catalog, root = ambiguous_fixture()
        with self.assertRaisesRegex(XaxError, "XAX.RESOLVE.AMBIGUOUS"):
            resolve(root, catalog)
        candidates = sorted((item for item in catalog.entries if item.logical_identity == b"lib"), key=lambda item: item.package_root)
        repaired = replace_dependency(catalog, root, 0, Requirement.exact(candidates[0].package_root))
        result = resolve(root, repaired)
        self.assertIn(candidates[0].package_root, result.selected_roots)
        self.assertNotIn(candidates[1].package_root, result.selected_roots)

    def test_unsatisfied_range_and_work_budget_are_compact_deterministic_failures(self):
        catalog, root = unsatisfied_fixture()
        with self.assertRaises(XaxError) as first:
            resolve(root, catalog)
        with self.assertRaises(XaxError) as second:
            resolve(root, catalog)
        self.assertEqual(first.exception.diagnostic, second.exception.diagnostic)
        self.assertEqual(first.exception.diagnostic.code, "XAX.RESOLVE.UNSAT")

        adversarial, adversarial_root = adversarial_backtrack(16, 8)
        with self.assertRaises(XaxError) as limited:
            resolve(adversarial_root, adversarial, ResolverLimits(3, DEFAULT_LIMITS.max_requirement_visits, DEFAULT_LIMITS.max_candidate_checks))
        self.assertEqual(limited.exception.diagnostic.code, "XAX.RESOLVE.BUDGET")
        self.assertEqual(limited.exception.diagnostic.rule, "RESOLVE-STATE-BOUND")

    def test_explicit_major_line_coexistence_uses_distinct_logical_identities(self):
        catalog, root = realistic_major_coexistence()
        result = resolve(root, catalog)
        versions = selected_versions(result, catalog)
        self.assertEqual(versions["codec/1"], "1.5.0")
        self.assertEqual(versions["codec/2"], "2.1.0")
        self.assertEqual(len(result.selected_roots), 3)

    def test_realistic_service_selects_one_exact_root_per_identity(self):
        catalog, root = realistic_service()
        result = resolve(root, catalog)
        identities = [catalog.by_root[cid].logical_identity for cid in result.selected_roots]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(len(result.selected_roots), 13)
        self.assertTrue(all(selected_versions(result, catalog)[f"lib{i}"] == "6.0.0" for i in range(4)))

    def test_adversarial_work_is_bounded_and_deterministic(self):
        small, small_root = adversarial_backtrack(8, 4)
        large, large_root = adversarial_backtrack(32, 8)
        first = resolve(small_root, small)
        repeat = resolve(small_root, small)
        bigger = resolve(large_root, large)
        self.assertEqual(first, repeat)
        self.assertEqual(first.stats.backtracks, 3)
        self.assertEqual(bigger.stats.backtracks, 7)
        self.assertGreater(bigger.stats.work_units, first.stats.work_units)
        self.assertLess(bigger.stats.work_units, DEFAULT_LIMITS.max_requirement_visits)

    def test_add_and_change_dependency_constraints_change_only_derived_snapshot(self):
        catalog = make_catalog(((b"lib", Version(1), ()), (b"app", Version(1), ())))
        root = next(item.package_root for item in catalog.entries if item.logical_identity == b"app")
        original_package_cid = root
        base = resolve(root, catalog)
        added = add_dependency(catalog, root, Requirement.logical(b"lib", VersionConstraint.range(Version(1), Version(2))))
        after_add = resolve(root, added)
        changed = replace_dependency(added, root, 0, Requirement.logical(b"lib", VersionConstraint.exact_version(Version(1))))
        after_change = resolve(root, changed)
        self.assertEqual(root, original_package_cid)
        self.assertNotEqual(base.snapshot_digest, after_add.snapshot_digest)
        self.assertNotEqual(after_add.catalog_digest, after_change.catalog_digest)
        self.assertEqual(after_add.selected_roots, after_change.selected_roots)

    def test_ai_tasks_have_exact_targets_but_do_not_claim_unavailable_model_tokens(self):
        tasks = ai_tasks()
        self.assertEqual([item["name"] for item in tasks], [
            "add_dependency_constraint",
            "change_dependency_range",
            "repair_unsatisfied_range",
            "repair_ambiguous_with_exact_root",
        ])
        self.assertTrue(all(item["view_bytes"] > 0 and item["mutation_bytes"] > 0 for item in tasks))
        self.assertTrue(all(len(item["target_snapshot"]) == 64 for item in tasks))

    def test_committed_evidence_matches_replay_from_raw_samples(self):
        root = Path(__file__).parents[1] / "benchmarks"
        raw = json.loads((root / "oi23_package_resolver_timing.json").read_text())
        expected = json.loads((root / "oi23_package_resolver_evidence.json").read_text())
        self.assertEqual(build_evidence(raw), expected)


if __name__ == "__main__":
    unittest.main()
