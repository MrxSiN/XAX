from __future__ import annotations

import json
import unittest

from benchmarks.bench_oi13_scope_normalization import (
    PORTABLE_LATTICE,
    PortableScope,
    ScopeMappingError,
    SyncSemanticError,
    SyncVector,
    _deployment_fixture,
    lower_sync_vector,
    portable_to_target,
    run,
    target_to_portable,
    validate_portable_lattice,
    validate_sync_semantics,
)
from xax_accelerator import (
    coherent_grid_accelerator_target,
    compile_accelerator,
    run_accelerator_deployment,
)
from xax_compiler import (
    AtomicOrder,
    AtomicScope,
    decode_native_target,
    simt32_accelerator_target,
    verify_store,
)


class OI13ScopeNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.simt = simt32_accelerator_target()
        self.coherent = coherent_grid_accelerator_target()

    def test_existing_m13_target_identity_is_unchanged(self):
        self.assertEqual(
            self.simt.cid.hex(),
            "202e9d0db81107e8380f27ef1f233327c34fe8a1f56431d38814ec4ee6feee04",
        )
        reader, entry = _deployment_fixture(self.simt)
        verify_store(reader)
        image = compile_accelerator(reader, entry.cid, self.simt.cid)
        self.assertEqual(len(image.deployment), 122)
        self.assertEqual(run_accelerator_deployment(image, (7, 9)), (16,))

    def test_second_target_has_materially_different_topology(self):
        first = decode_native_target(self.simt)
        second = decode_native_target(self.coherent)
        self.assertEqual(tuple(space.identity for space in first.memory_spaces), (1, 2, 3))
        self.assertEqual(tuple(space.identity for space in second.memory_spaces), (1, 2))
        self.assertFalse(first.memory_spaces[0].device_visible)
        self.assertTrue(second.memory_spaces[0].host_visible)
        self.assertTrue(second.memory_spaces[0].device_visible)
        self.assertNotIn(AtomicScope.SYSTEM, first.accelerator_scopes)
        self.assertIn(AtomicScope.SYSTEM, second.accelerator_scopes)

    def test_second_target_compiles_and_executes_existing_deployment_contract(self):
        reader, entry = _deployment_fixture(self.coherent)
        verify_store(reader)
        first = compile_accelerator(reader, entry.cid, self.coherent.cid)
        second = compile_accelerator(reader, entry.cid, self.coherent.cid)
        self.assertEqual(first.deployment, second.deployment)
        self.assertEqual(len(first.deployment), 120)
        self.assertEqual(run_accelerator_deployment(first, (0xFFFFFFFF, 2)), (1,))

    def test_portable_scope_lattice_maps_and_roundtrips_exactly(self):
        validate_portable_lattice((self.simt, self.coherent))
        self.assertEqual(PORTABLE_LATTICE, (PortableScope.WORKGROUP, PortableScope.DEVICE))
        for target in (self.simt, self.coherent):
            self.assertEqual(portable_to_target(target, PortableScope.WORKGROUP), AtomicScope.WORKGROUP)
            self.assertEqual(portable_to_target(target, PortableScope.DEVICE), AtomicScope.DEVICE)
            self.assertEqual(target_to_portable(target, AtomicScope.WORKGROUP), PortableScope.WORKGROUP)
            self.assertEqual(target_to_portable(target, AtomicScope.DEVICE), PortableScope.DEVICE)

    def test_target_only_system_scope_is_nonportable_not_approximated(self):
        self.assertIsNone(target_to_portable(self.coherent, AtomicScope.SYSTEM))
        with self.assertRaises(ScopeMappingError):
            target_to_portable(self.simt, AtomicScope.SYSTEM)

    def test_atomic_orders_are_checked_before_target_lowering(self):
        valid = SyncVector(
            "valid", "atomic_load", AtomicOrder.ACQUIRE, "local", "local",
            portable_scope=PortableScope.WORKGROUP,
        )
        validate_sync_semantics(valid)
        invalid = SyncVector(
            "invalid", "atomic_load", AtomicOrder.RELEASE, "local", "local",
            portable_scope=PortableScope.WORKGROUP,
        )
        with self.assertRaises(SyncSemanticError):
            validate_sync_semantics(invalid)

    def test_barrier_orders_are_checked_before_target_lowering(self):
        valid = SyncVector(
            "valid", "barrier", AtomicOrder.ACQ_REL, "global", "local",
            portable_scope=PortableScope.WORKGROUP,
        )
        validate_sync_semantics(valid)
        invalid = SyncVector(
            "invalid", "barrier", AtomicOrder.RELAXED, "global", "local",
            portable_scope=PortableScope.WORKGROUP,
        )
        with self.assertRaises(SyncSemanticError):
            validate_sync_semantics(invalid)

    def test_workgroup_cross_space_vector_is_legal_on_both_targets(self):
        vector = SyncVector(
            "wg", "barrier", AtomicOrder.ACQ_REL, "global", "local",
            portable_scope=PortableScope.WORKGROUP,
        )
        self.assertEqual(len(lower_sync_vector(self.simt, vector)), 41)
        self.assertEqual(len(lower_sync_vector(self.coherent, vector)), 41)

    def test_device_to_local_cross_space_rejects_on_both_targets(self):
        vector = SyncVector(
            "device-local", "barrier", AtomicOrder.SEQ_CST, "global", "local",
            portable_scope=PortableScope.DEVICE,
        )
        with self.assertRaisesRegex(ScopeMappingError, "not visible"):
            lower_sync_vector(self.simt, vector)
        with self.assertRaisesRegex(ScopeMappingError, "not visible"):
            lower_sync_vector(self.coherent, vector)

    def test_system_target_specific_vector_accepts_only_coherent_target(self):
        vector = SyncVector(
            "system", "barrier", AtomicOrder.SEQ_CST, "system", "system",
            target_scope=AtomicScope.SYSTEM,
        )
        self.assertEqual(len(lower_sync_vector(self.coherent, vector)), 41)
        with self.assertRaisesRegex(ScopeMappingError, "not supported"):
            lower_sync_vector(self.simt, vector)

    def test_evidence_is_deterministic_and_charges_unavailable_tokens_as_unknown(self):
        first = run()
        second = run()
        self.assertEqual(first, second)
        self.assertEqual(first["candidate_portable_lattice"], ["workgroup", "device"])
        self.assertIsNone(first["measurement"]["token_cost"]["portable_tokens"])
        self.assertIsNone(first["measurement"]["token_cost"]["target_specific_tokens"])
        self.assertEqual(first["measurement"]["production_core_semantic_lines_added"], 0)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
