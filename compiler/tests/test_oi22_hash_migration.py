from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from blake3 import blake3
from benchmarks import bench_oi22_hash_migration as bench
from benchmarks.bench_oi21_dependency_index import build_project
from xax_compiler import Cursor


class OI22HashMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = build_project("service_generated")
        cls.reader = bench.build_migration_repository()
        cls.store = cls.reader.data
        cls.alias = bench.build_alias_index(cls.reader)
        cls.alias_bytes = bench.encode_alias_index(cls.alias)
        cls.full = bench.build_full_migration(cls.reader)
        cls.full_bytes = bench.encode_full_migration(cls.full)

    def test_suite1_is_byte_exact_and_untouched(self):
        before = self.store
        root = self.reader.root_cid
        bench.build_alias_index(self.reader)
        bench.build_full_migration(self.reader)
        self.assertEqual(self.reader.data, before)
        self.assertEqual(self.reader.root_cid, root)

    def test_alias_and_full_roundtrip_and_root_mapping(self):
        alias = bench.decode_alias_index(self.alias_bytes, expected_store=self.store)
        full = bench.decode_full_migration(self.full_bytes, source_reader=self.reader)
        self.assertEqual(bench.encode_alias_index(alias), self.alias_bytes)
        self.assertEqual(bench.encode_full_migration(full), self.full_bytes)
        self.assertEqual(alias.by_source()[self.reader.root_cid], alias.alias_root)
        self.assertEqual(full.by_source()[self.reader.root_cid].target_digest, full.target_root)

    def test_cross_suite_equivalence_uses_decoded_semantics(self):
        alias_repo = bench.DualRepository(self.reader, alias=self.alias)
        full_repo = bench.DualRepository(self.reader, full=self.full)
        s1 = bench.HashIdentity(1, self.reader.root_cid)
        a2 = bench.HashIdentity(2, self.alias.alias_root)
        f2 = bench.HashIdentity(2, self.full.target_root)
        self.assertTrue(bench.equivalent_semantics(alias_repo, s1, a2))
        self.assertTrue(bench.equivalent_semantics(full_repo, s1, f2))
        self.assertNotEqual((s1.suite_id, s1.digest), (a2.suite_id, a2.digest))

    def test_unknown_suite_and_wrong_declared_suite_reject(self):
        with self.assertRaisesRegex(bench.MigrationRejected, "unknown_suite"):
            bench.HashIdentity(99, b"x" * 32)
        forged = bytearray(self.alias_bytes)
        # Header: magic, version=1, source_suite=1, target_suite=2. Change target to 99.
        forged[6] = 99
        forged[-32:] = blake3(forged[:-32]).digest()
        with self.assertRaisesRegex(bench.MigrationRejected, "unknown_suite"):
            bench.decode_alias_index(bytes(forged))

    def test_corruption_and_stale_source_reject(self):
        corrupt = bytearray(self.alias_bytes)
        corrupt[80] ^= 1
        with self.assertRaisesRegex(bench.MigrationRejected, "integrity"):
            bench.decode_alias_index(bytes(corrupt))
        edited = build_project("service_generated", leaf_delta=1)
        with self.assertRaisesRegex(bench.MigrationRejected, "stale_source"):
            bench.decode_alias_index(self.alias_bytes, expected_store=edited.store_bytes)
        corrupt_full = bytearray(self.full_bytes)
        corrupt_full[120] ^= 1
        with self.assertRaisesRegex(bench.MigrationRejected, "integrity"):
            bench.decode_full_migration(bytes(corrupt_full), source_reader=self.reader)

    def test_forced_collision_rejected(self):
        fake = lambda payload: b"\x5a" * 32
        with self.assertRaisesRegex(bench.MigrationRejected, "collision"):
            bench.build_alias_index(self.reader, test_hash=fake)
        with self.assertRaisesRegex(bench.MigrationRejected, "collision"):
            bench.build_full_migration(self.reader, test_hash=fake)

    def test_dependency_resolution_all_suite2_children_resolve(self):
        by_target = self.full.by_target()
        self.assertGreater(sum(len(r.target_references) for r in self.full.records), 0)
        for record in self.full.records:
            for ref in record.target_references:
                self.assertIn(ref, by_target)
        bench.decode_full_migration(self.full_bytes, source_reader=self.reader)

    def test_proof_cache_alias_reuse_and_full_direct_loss(self):
        result = bench._proof_cache_reuse(self.reader, self.alias, self.full)
        self.assertEqual(result["alias_direct_reuse_entries"], result["suite1_cache_entries"])
        self.assertEqual(result["alias_direct_reuse_percent"], 100.0)
        self.assertEqual(result["full_direct_reuse_entries"], 0)

    def test_object_lookup_by_explicit_suite(self):
        repo = bench.DualRepository(self.reader, alias=self.alias)
        entry = self.alias.entries[len(self.alias.entries) // 2]
        one = repo.get_semantic(bench.HashIdentity(1, entry.source_cid))
        two = repo.get_semantic(bench.HashIdentity(2, entry.alias_digest))
        self.assertEqual(one, two)
        root = repo.get_semantic(bench.HashIdentity(2, self.alias.alias_root))
        self.assertEqual(root.kind.name, "PACKAGE")
        with self.assertRaisesRegex(bench.MigrationRejected, "object_missing"):
            repo.get_semantic(bench.HashIdentity(2, b"\xff" * 32))

    def test_atomic_interruption_restart_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "migration.xha"
            with self.assertRaises(InterruptedError):
                bench.save_atomic(path, self.alias_bytes, interrupt_before_replace=True)
            self.assertFalse(path.exists())
            self.assertEqual(self.reader.data, self.store)
            bench.save_atomic(path, self.alias_bytes)
            self.assertEqual(path.read_bytes(), self.alias_bytes)
            # Restart is deterministic and does not touch suite-1.
            bench.save_atomic(path, bench.encode_alias_index(bench.build_alias_index(self.reader)))
            self.assertEqual(path.read_bytes(), self.alias_bytes)
            bench.rollback(path)
            self.assertFalse(path.exists())
            self.assertEqual(self.reader.data, self.store)

    def test_full_container_detects_rehashed_semantic_corruption(self):
        # Mutate a record body, then recompute only the outer integrity digest.
        data = bytearray(self.full_bytes)
        cursor = Cursor(data[:-32], "test")
        cursor.take(4); cursor.uleb(); cursor.uleb(); cursor.uleb()
        cursor.take(32 * 3)
        count = cursor.uleb()
        self.assertGreater(count, 0)
        cursor.take(32 * 2); cursor.uleb(); cursor.uleb()
        for _ in range(cursor.uleb()): cursor.take(32)
        body_len = cursor.uleb()
        self.assertGreater(body_len, 0)
        data[cursor.pos] ^= 1
        data[-32:] = blake3(data[:-32]).digest()
        with self.assertRaisesRegex(bench.MigrationRejected, "cid_mismatch"):
            bench.decode_full_migration(bytes(data))

    def test_deterministic_evidence_and_committed_replay(self):
        first = bench.deterministic_evidence(None)
        second = bench.deterministic_evidence(None)
        self.assertEqual(first, second)
        if bench.RAW.exists() and bench.EVIDENCE.exists():
            raw = json.loads(bench.RAW.read_text())
            committed = json.loads(bench.EVIDENCE.read_text())
            self.assertEqual(bench.deterministic_evidence(raw), committed)


if __name__ == "__main__":
    unittest.main()
