from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from benchmarks import bench_oi21_dependency_index as bench
from xax_artifact import BOOTSTRAP_COMPILER_IDENTITY_V1
from xax_compiler import DEFAULT_VERIFIER_IDENTITY, StoreReader, verify_store


class OI21DependencyIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = bench.build_project("mixed_modules")
        cls.index = bench.build_index(cls.base.reader)
        cls.encoded = bench.encode_index(cls.index)

    def test_roundtrip_and_full_recompute_match(self):
        decoded = bench.decode_index(
            self.encoded,
            expected_root=self.base.root.cid,
            verifier_identity=DEFAULT_VERIFIER_IDENTITY,
            compiler_identity=BOOTSTRAP_COMPILER_IDENTITY_V1,
        )
        bench.validate_index(decoded, self.base.reader)
        self.assertEqual(bench.encode_index(decoded), self.encoded)

    def test_corrupt_digest_rejected_and_rebuilt(self):
        corrupt = bytearray(self.encoded)
        corrupt[50] ^= 1
        with self.assertRaisesRegex(bench.IndexRejected, "oi21.index.digest"):
            bench.decode_index(bytes(corrupt))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deps.xdi"
            path.write_bytes(corrupt)
            rebuilt, did_rebuild = bench.load_or_rebuild(path, self.base.reader)
            self.assertTrue(did_rebuild)
            bench.validate_index(rebuilt, self.base.reader)
            self.assertEqual(path.read_bytes(), bench.encode_index(rebuilt))

    def test_rehashed_reverse_edge_corruption_rejected(self):
        entries = list(self.index.entries)
        source_pos = next(i for i, entry in enumerate(entries) if entry.dependencies)
        dependency = entries[source_pos].dependencies[0]
        target_pos = next(i for i, entry in enumerate(entries) if entry.cid == dependency)
        target = entries[target_pos]
        entries[target_pos] = bench.IndexEntry(
            target.cid, target.dependency_fingerprint, target.dependencies,
            tuple(user for user in target.users if user != entries[source_pos].cid),
        )
        forged = bench.DependencyIndex(
            self.index.root_cid, self.index.verifier_identity, self.index.compiler_identity, tuple(entries)
        )
        with self.assertRaisesRegex(bench.IndexRejected, "oi21.index.reverse_edge"):
            bench.decode_index(bench.encode_index(forged))

    def test_stale_root_and_dependency_identities_rejected(self):
        edited = bench.build_project("mixed_modules", leaf_delta=1)
        with self.assertRaisesRegex(bench.IndexRejected, "oi21.index.stale_root"):
            bench.decode_index(self.encoded, expected_root=edited.root.cid)
        with self.assertRaisesRegex(bench.IndexRejected, "oi21.index.stale_verifier"):
            bench.decode_index(self.encoded, verifier_identity="other-verifier")
        with self.assertRaisesRegex(bench.IndexRejected, "oi21.index.stale_compiler"):
            bench.decode_index(self.encoded, compiler_identity=b"other-compiler")

    def test_atomic_replace_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deps.xdi"
            bench.save_index_atomic(path, self.index)
            self.assertEqual(path.read_bytes(), self.encoded)
            leftovers = tuple(path.parent.glob(f".{path.name}.*"))
            self.assertEqual(leftovers, ())

    def _assert_edit_exact(self, *, leaf_delta=0, leaf_arity=1, interface=False):
        edited = bench.build_project("mixed_modules", leaf_delta=leaf_delta, leaf_arity=leaf_arity)
        old = set(self.base.reader.object_cids)
        new = set(edited.reader.object_cids)
        removed = old - new
        seeds = (self.base.graphs[self.base.leaf].cid,)
        if interface:
            seeds += (self.base.functions[self.base.leaf].cid,)
        self.assertEqual(set(bench.invalidation_frontier(self.index, seeds)), removed)
        updated, stats = bench.update_index(self.index, edited.reader)
        rebuilt = bench.build_index(edited.reader)
        self.assertEqual(bench.encode_index(updated), bench.encode_index(rebuilt))
        self.assertEqual(stats["decoded_new_objects"], len(new - old))

    def test_leaf_edit_exact_invalidation_and_incremental_rebuild(self):
        self._assert_edit_exact(leaf_delta=1)

    def test_interface_edit_exact_invalidation_and_incremental_rebuild(self):
        self._assert_edit_exact(leaf_arity=2, interface=True)

    def test_all_project_shapes_have_no_under_invalidation(self):
        for name in ("shallow_fanout", "deep_chain", "mixed_modules", "service_generated"):
            with self.subTest(name=name):
                evidence = bench.deterministic_project_evidence(name)
                self.assertTrue(evidence["edits"]["leaf_body"]["invalidation_exact"])
                self.assertTrue(evidence["edits"]["leaf_interface"]["invalidation_exact"])

    def test_index_deletion_does_not_change_semantics(self):
        before_root = self.base.reader.root_cid
        verify_store(StoreReader(self.base.store_bytes))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deps.xdi"
            bench.save_index_atomic(path, self.index)
            path.unlink()
            rebuilt, did_rebuild = bench.load_or_rebuild(path, StoreReader(self.base.store_bytes))
            self.assertTrue(did_rebuild)
            self.assertEqual(rebuilt.root_cid, before_root)
            self.assertEqual(StoreReader(self.base.store_bytes).root_cid, before_root)

    def test_parallel_serial_outputs_identical(self):
        payloads = [bench._independent_compile_payload(16, salt) for salt in range(4)]
        one = bench.run_process_pool(payloads, 1)
        two = bench.run_process_pool(payloads, 2)
        self.assertEqual(one, two)
        self.assertEqual(
            hashlib.sha256(repr(one).encode()).digest(),
            hashlib.sha256(repr(two).encode()).digest(),
        )

    def test_parallel_diagnostics_identical(self):
        good = bench._independent_compile_payload(8, 0)
        bad = (good[0], b"\xff" * 32, good[2])
        serial = bench._compile_payload(bad)
        self.assertEqual(serial[1], "diagnostic")
        one = bench.run_process_pool([bad], 1)
        two = bench.run_process_pool([bad], 2)
        self.assertEqual(one, (serial,))
        self.assertEqual(two, (serial,))

    def test_index_snapshot_is_shared_read_only_across_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deps.xdi"
            bench.save_index_atomic(path, self.index)
            seed = self.base.graphs[self.base.leaf].cid
            results = bench.run_shared_index_queries(path, self.base.root.cid, seed, 2)
            self.assertEqual(len(set(results)), 1)
            self.assertEqual(path.read_bytes(), self.encoded)

    def test_deterministic_evidence_without_timing(self):
        first = bench.deterministic_evidence(None)
        second = bench.deterministic_evidence(None)
        self.assertEqual(first, second)

    def test_committed_evidence_replays_from_raw_samples(self):
        import json
        raw = json.loads(bench.RAW.read_text())
        committed = json.loads(bench.EVIDENCE.read_text())
        self.assertEqual(bench.deterministic_evidence(raw), committed)


if __name__ == "__main__":
    unittest.main()
