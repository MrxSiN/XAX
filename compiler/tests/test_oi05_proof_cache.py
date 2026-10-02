import json
import tempfile
import unittest
from pathlib import Path

from blake3 import blake3

from xax_compiler import (
    DEFAULT_VERIFIER_IDENTITY,
    Block,
    Kind,
    Node,
    Operation,
    ProofCache,
    ProofCacheEntry,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    uleb,
    verify_store,
    write_store,
)
from xax_workspace import RootRef, SetConstant, Transaction, Workspace


def program_fixture(count: int = 8) -> tuple[StoreReader, tuple[object, ...]]:
    b32 = bits_type(32)
    functions = []
    objects = [b32]
    for index in range(count):
        value = constant(b32, index + 1)
        graph = graph_fragment(
            (
                Block(
                    (),
                    (Node(Operation.CONSTANT, (), (b32,), entity=value),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                ),
            )
        )
        entry = function(graph, (), (b32,))
        functions.append(entry)
        objects.extend((value, graph, entry))
    module = object_with_refs(Kind.MODULE, functions)
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects.extend((module, root))
    return StoreReader(write_store(root.cid, objects)), tuple(functions)


class OI05ProofCacheTests(unittest.TestCase):
    def test_cold_then_warm_verification_is_exact_and_nonsemantic(self):
        base, _ = program_fixture()
        canonical = base.canonical_bytes()
        cache = ProofCache()
        reader = StoreReader(canonical, proof_cache=cache)

        cold = verify_store(reader)
        warm = verify_store(reader)

        self.assertEqual(cold.objects, len(reader.object_cids))
        self.assertEqual(cold.cache_hits, 0)
        self.assertEqual(cold.cache_misses, cold.objects)
        self.assertEqual(cold.cache_entries_after, cold.objects)
        self.assertEqual(warm.cache_hits, warm.objects)
        self.assertEqual(warm.cache_misses, 0)
        self.assertEqual(reader.canonical_bytes(), canonical)
        self.assertEqual(reader.root_cid, base.root_cid)

    def test_cache_bytes_are_deterministic_and_round_trip(self):
        base, _ = program_fixture()
        cache = ProofCache()
        verify_store(StoreReader(base.data, proof_cache=cache))
        first = cache.canonical_bytes()
        second = ProofCache.from_bytes(first).canonical_bytes()

        self.assertEqual(first, second)
        self.assertEqual(ProofCache.from_bytes(first).entry_count, len(base.object_cids))

    def test_cache_corruption_is_rejected_explicitly(self):
        base, _ = program_fixture()
        cache = ProofCache()
        verify_store(StoreReader(base.data, proof_cache=cache))
        damaged = bytearray(cache.canonical_bytes())
        damaged[-3] ^= 1

        with self.assertRaises(XaxError) as raised:
            ProofCache.from_bytes(bytes(damaged), "damaged-cache")
        self.assertEqual(raised.exception.diagnostic.code, "XAX.CACHE.CORRUPT")

    def test_exact_dependency_tuple_and_verifier_identity_control_reuse(self):
        base, _ = program_fixture()
        exact = ProofCache()
        reader = StoreReader(base.data, proof_cache=exact)
        verify_store(reader)
        target = next(obj for obj in reader.objects() if obj.references)
        malformed = ProofCache(
            ProofCacheEntry(DEFAULT_VERIFIER_IDENTITY, obj.cid, obj.references)
            for obj in reader.objects()
            if obj.cid != target.cid
        )
        malformed.record(DEFAULT_VERIFIER_IDENTITY, SemanticObject(target.kind, target.schema_version, (), target.body, target.cid))
        wrong_reader = StoreReader(base.data, proof_cache=malformed)

        repaired = verify_store(wrong_reader)
        self.assertEqual(repaired.cache_hits, repaired.objects - 1)
        self.assertEqual(repaired.cache_misses, 1)
        self.assertEqual(repaired.cache_entries_invalidated, 1)
        self.assertEqual(repaired.cache_entries_written, 1)

        changed_verifier = verify_store(wrong_reader, verifier_identity="bootstrap-schema-test-v2")
        self.assertEqual(changed_verifier.cache_hits, 0)
        self.assertEqual(changed_verifier.cache_misses, changed_verifier.objects)
        self.assertEqual(changed_verifier.cache_entries_invalidated, changed_verifier.objects)
        self.assertEqual(changed_verifier.cache_entries_written, changed_verifier.objects)

    def test_workspace_commit_updates_only_new_frontier_and_sidecar_is_optional(self):
        base, functions = program_fixture()
        cache = ProofCache()
        cached_reader = StoreReader(base.data, proof_cache=cache)
        verify_store(cached_reader)
        workspace = Workspace(cached_reader)
        node = workspace.function_nodes(functions[0].cid, 1).entities[0]
        before_root = workspace.root
        before_cache = cache.canonical_bytes()

        result = workspace.commit(Transaction(RootRef(0), (SetConstant(node.handle, node.constant_value, 99),)))

        self.assertTrue(result.committed)
        self.assertNotEqual(result.root, before_root)
        self.assertEqual(workspace.accounting.proof_cache_entries_written, result.verified_objects)
        self.assertGreater(workspace.accounting.proof_cache_entries_invalidated, 0)
        self.assertGreater(workspace.accounting.proof_cache_dependency_cids_maintained, 0)
        warm = verify_store(workspace.reader)
        self.assertEqual(warm.cache_hits, warm.objects)
        self.assertEqual(warm.cache_misses, 0)
        self.assertNotEqual(cache.canonical_bytes(), before_cache)

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "program.xax"
            cache_path = Path(directory) / "program.xax.proof-cache"
            workspace.save(store_path, proof_cache_path=cache_path)
            self.assertEqual(store_path.read_bytes(), workspace.reader.canonical_bytes())
            loaded = Workspace.load(store_path, proof_cache_path=cache_path)
            replay = verify_store(loaded.reader)
            self.assertEqual(loaded.root, workspace.root)
            self.assertEqual(replay.cache_hits, replay.objects)
            self.assertEqual(replay.cache_misses, 0)

    def test_committed_evidence_inputs_and_cache_accounting_reproduce(self):
        base, _ = program_fixture(96)
        cache = ProofCache()
        reader = StoreReader(base.data, proof_cache=cache)
        cold = verify_store(reader)
        warm = verify_store(reader)
        evidence_path = Path(__file__).resolve().parents[1] / "benchmarks" / "oi05_proof_cache_evidence.json"
        evidence = json.loads(evidence_path.read_text())

        self.assertEqual(evidence["schema"], "xax-oi05-proof-cache-evidence-v1")
        self.assertEqual(evidence["inputs"]["program_root"], reader.root_cid.hex())
        self.assertEqual(evidence["inputs"]["program_store_bytes"], len(reader.data))
        self.assertEqual(evidence["inputs"]["program_object_count"], len(reader.object_cids))
        deterministic = evidence["verification"]["deterministic"]
        self.assertEqual(deterministic["cold"], cold.__dict__)
        self.assertEqual(deterministic["warm"], warm.__dict__)
        self.assertEqual(deterministic["cache_bytes"], len(cache.canonical_bytes()))
        self.assertEqual(deterministic["cache_digest"], blake3(cache.canonical_bytes()).hexdigest())

    def test_stale_cache_cannot_cover_changed_invalid_semantics(self):
        base, _ = program_fixture()
        cache = ProofCache()
        verify_store(StoreReader(base.data, proof_cache=cache))

        b7 = bits_type(7)
        invalid = SemanticObject.create(Kind.CONSTANT, uleb(0) + uleb(1) + b"\x80", (b7.cid,))
        module = object_with_refs(Kind.MODULE, (invalid, b7))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        invalid_reader = StoreReader(write_store(root.cid, (b7, invalid, module, root)), proof_cache=cache)

        with self.assertRaises(XaxError) as raised:
            verify_store(invalid_reader)
        self.assertEqual(raised.exception.diagnostic.code, "XAX.CONSTANT.WIDTH")


if __name__ == "__main__":
    unittest.main()
