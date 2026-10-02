import json
import unittest
from pathlib import Path

from compiler.benchmarks.bench_oi07_dma import collect_evidence, fixture
from xax_accelerator import compile_dma_flow, inspect_deployment, run_dma_deployment
from xax_compiler import (
    DmaAction,
    DmaResourceState,
    XaxError,
    decode_native_target,
    dma_resource_types,
    oi07_coherent_dma_target,
    oi07_noncoherent_dma_target,
    simt32_accelerator_target,
    verify_store,
)


class OI07DmaVocabularyTests(unittest.TestCase):
    def test_shared_state_vocabulary_is_small_and_deterministic(self):
        self.assertEqual(
            [(state.name, int(state)) for state in DmaResourceState],
            [
                ("HOST_UNMAPPED", 1),
                ("HOST_MAPPED", 2),
                ("HOST_DIRTY", 3),
                ("DEVICE_OWNED", 4),
                ("DEVICE_PENDING", 5),
                ("HOST_STALE", 6),
            ],
        )
        first = dma_resource_types()
        second = dma_resource_types()
        self.assertEqual([item.cid for item in first], [item.cid for item in second])

    def test_noncoherent_split_flow_verifies_compiles_and_executes(self):
        reader, entry, target = fixture(coherent=False)
        verify_store(reader)
        root = reader.root_cid
        first = compile_dma_flow(reader, entry.cid, target.cid)
        second = compile_dma_flow(reader, entry.cid, target.cid)
        self.assertEqual(first.deployment, second.deployment)
        self.assertEqual(reader.root_cid, root)
        sequence = [DmaAction(item.semantic_code) for item in inspect_deployment(first.deployment).instructions]
        self.assertIn(DmaAction.CACHE_CLEAN, sequence)
        self.assertIn(DmaAction.CACHE_INVALIDATE, sequence)
        self.assertEqual(run_dma_deployment(first, (7, 9)), (16,))
        spaces = decode_native_target(target).memory_spaces
        self.assertEqual([(s.host_visible, s.device_visible) for s in spaces], [(True, False), (False, True)])

    def test_coherent_shared_flow_verifies_compiles_and_executes_without_cache_ops(self):
        reader, entry, target = fixture(coherent=True)
        verify_store(reader)
        image = compile_dma_flow(reader, entry.cid, target.cid)
        sequence = [DmaAction(item.semantic_code) for item in inspect_deployment(image.deployment).instructions]
        self.assertNotIn(DmaAction.CACHE_CLEAN, sequence)
        self.assertNotIn(DmaAction.CACHE_INVALIDATE, sequence)
        self.assertIn(DmaAction.SYNCHRONIZE, sequence)
        self.assertEqual(run_dma_deployment(image, (0xFFFFFFFF, 2)), (1,))
        spaces = decode_native_target(target).memory_spaces
        self.assertEqual([(s.host_visible, s.device_visible) for s in spaces], [(True, True)])

    def test_noncoherent_cache_clean_is_required_by_resource_state(self):
        reader, _, _ = fixture(coherent=False, omit_clean=True)
        with self.assertRaises(XaxError) as caught:
            verify_store(reader)
        self.assertEqual(caught.exception.diagnostic.rule, "TARGET-OPERATION-TYPE")

    def test_synchronization_is_required_by_device_pending_state_on_both_models(self):
        for coherent in (False, True):
            with self.subTest(coherent=coherent):
                reader, _, _ = fixture(coherent=coherent, omit_sync=True)
                with self.assertRaises(XaxError) as caught:
                    verify_store(reader)
                self.assertEqual(caught.exception.diagnostic.rule, "TARGET-OPERATION-TYPE")

    def test_target_identity_is_deterministic_and_existing_m13_identity_is_unchanged(self):
        self.assertEqual(oi07_noncoherent_dma_target().cid, oi07_noncoherent_dma_target().cid)
        self.assertEqual(oi07_coherent_dma_target().cid, oi07_coherent_dma_target().cid)
        self.assertNotEqual(oi07_noncoherent_dma_target().cid, oi07_coherent_dma_target().cid)
        self.assertEqual(
            simt32_accelerator_target().cid.hex(),
            "202e9d0db81107e8380f27ef1f233327c34fe8a1f56431d38814ec4ee6feee04",
        )

    def test_committed_evidence_reproduces(self):
        committed = json.loads((Path(__file__).parents[1] / "benchmarks" / "oi07_dma_evidence.json").read_text())
        self.assertEqual(collect_evidence(), committed)


if __name__ == "__main__":
    unittest.main()
