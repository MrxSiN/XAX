from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from xax_artifact import BOOTSTRAP_COMPILER_IDENTITY_V1, WASM_LOWERING_IDENTITY_V1
from xax_bootstrap import (
    M11_BUILD_ENTRY,
    M11_BUNDLE_FILENAME,
    M11_CONFORMANCE_VECTORS,
    M11_EVIDENCE_FILENAME,
    M11_PACKAGE_ID,
    M11_PROGRAM_FILENAME,
    M11_RESOLVER_IDENTITY,
    build_m11_hosted_subset,
    compare_m11_vectors,
    create_m11_bootstrap_store,
    create_m11_program_store,
    load_m11_bundle,
    load_m11_bundle_from_directory,
)
from xax_build import BuildMode, build, decode_provenance
from xax_compiler import Kind, verify_store


BOOTSTRAP_DIR = Path(__file__).resolve().parents[1] / "bootstrap"


class M11BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which("node")
        if cls.node is None:
            raise unittest.SkipTest("Node.js is required for the fixed M11 WebAssembly bootstrap target")
        cls.bundle = load_m11_bundle_from_directory(BOOTSTRAP_DIR)

    def test_committed_artifacts_are_canonical_and_reproducible(self):
        program = create_m11_program_store()
        bootstrap = create_m11_bootstrap_store()
        self.assertEqual((BOOTSTRAP_DIR / M11_PROGRAM_FILENAME).read_bytes(), program.data)
        self.assertEqual((BOOTSTRAP_DIR / M11_BUNDLE_FILENAME).read_bytes(), bootstrap.data)
        verify_store(program)
        verify_store(bootstrap)

    def test_bundle_binds_authoritative_program_and_fixed_policy(self):
        bundle = self.bundle
        self.assertEqual(bundle.program_root.kind, Kind.PROGRAM_ROOT)
        self.assertEqual(bundle.package_view.logical_identity, M11_PACKAGE_ID)
        self.assertEqual(bundle.package_view.modules, (bundle.module.cid,))
        self.assertEqual(bundle.package_view.build_entries, ((M11_BUILD_ENTRY, bundle.entry.cid),))
        self.assertEqual(bundle.request_view.package_root, bundle.package.cid)
        self.assertEqual(bundle.request_view.target_root, bundle.target.cid)
        self.assertEqual(bundle.request_view.profile_root, bundle.profile.cid)
        self.assertEqual(bundle.snapshot_view.request_root, bundle.request.cid)
        self.assertEqual(bundle.snapshot_view.resolver_identity, M11_RESOLVER_IDENTITY)
        self.assertEqual(bundle.profile_view.mode, BuildMode.HERMETIC_REPRODUCIBLE)
        self.assertEqual(bundle.profile_view.optimization, 0)
        self.assertEqual(bundle.profile_view.verification, 1)
        self.assertEqual(bundle.profile_view.grants, ())

    def test_seed_build_is_deterministic_and_provenance_complete(self):
        first = build_m11_hosted_subset(self.bundle)
        second = build_m11_hosted_subset(self.bundle)
        self.assertEqual(first.result, second.result)
        self.assertEqual(first.image.artifact_bytes, first.result.artifact)
        self.assertEqual(first.provenance_view.snapshot_root, self.bundle.snapshot.cid)
        self.assertEqual(first.provenance_view.request_root, self.bundle.request.cid)
        self.assertEqual(first.provenance_view.target_root, self.bundle.target.cid)
        self.assertEqual(first.provenance_view.profile_root, self.bundle.profile.cid)
        self.assertEqual(first.provenance_view.compiler_identity, BOOTSTRAP_COMPILER_IDENTITY_V1)
        self.assertEqual(first.provenance_view.lowering_identity, WASM_LOWERING_IDENTITY_V1)

    def test_seed_and_xax_hosted_behavior_match_conformance_vectors(self):
        compiled = build_m11_hosted_subset(self.bundle)
        comparisons = compare_m11_vectors(self.bundle, compiled, node_executable=self.node)
        self.assertEqual(tuple(item.arguments for item in comparisons), M11_CONFORMANCE_VECTORS)
        self.assertTrue(all(item.matches for item in comparisons))
        expected = (
            (0,),
            (3,),
            (1,),
            (12,),
            (0xFFFFFFFE,),
            (0,),
        )
        self.assertEqual(tuple(item.hosted_result for item in comparisons), expected)

    def test_bundle_loader_rejects_non_authoritative_program(self):
        program = create_m11_program_store()
        bootstrap = create_m11_bootstrap_store()
        other_program = bytearray(program.data)
        other_program[-5] ^= 1
        with self.assertRaises(Exception):
            load_m11_bundle(bytes(other_program), bootstrap.data)

    def test_evidence_record_matches_current_roots_when_present(self):
        evidence_path = BOOTSTRAP_DIR / M11_EVIDENCE_FILENAME
        if not evidence_path.exists():
            self.skipTest("M11 evidence record is emitted by the milestone validation benchmark")
        record = json.loads(evidence_path.read_text())
        compiled = build_m11_hosted_subset(self.bundle)
        provenance = decode_provenance(compiled.result.provenance, self.bundle.build_store.get)
        self.assertEqual(record["program_root"], self.bundle.program_root.cid.hex())
        self.assertEqual(record["entry_function_root"], self.bundle.entry.cid.hex())
        self.assertEqual(record["package_root"], self.bundle.package.cid.hex())
        self.assertEqual(record["snapshot_root"], self.bundle.snapshot.cid.hex())
        self.assertEqual(record["request_root"], self.bundle.request.cid.hex())
        self.assertEqual(record["target_root"], self.bundle.target.cid.hex())
        self.assertEqual(record["build_profile_root"], self.bundle.profile.cid.hex())
        self.assertEqual(record["seed_compiler_identity"], provenance.compiler_identity.hex())
        self.assertEqual(record["lowering_identity"], provenance.lowering_identity.hex())
        self.assertEqual(record["provenance_root"], compiled.result.provenance.cid.hex())
        self.assertEqual(record["artifact_digest"], compiled.result.artifact_digest.hex())


if __name__ == "__main__":
    unittest.main()
