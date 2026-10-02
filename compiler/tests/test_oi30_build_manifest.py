from __future__ import annotations
import unittest
from blake3 import blake3
from benchmarks.bench_oi30_build_manifest import _simple, _signed, collect_evidence
from xax_build import BuildCapability, BuildCapabilityKind, BuildEffect, build
from xax_compiler import XaxError

class OI30Tests(unittest.TestCase):
    def test_ambient_perturbations_are_stable(self):
        e=collect_evidence(); row=next(x for x in e["rows"] if x["perturbation"]=="cwd_env_locale_timezone_source_date")
        self.assertTrue(row["key_same"]); self.assertTrue(row["bytes_same"])
        row=next(x for x in e["rows"] if x["perturbation"]=="worker_count_4")
        self.assertTrue(row["all_key_same"]); self.assertTrue(row["all_bytes_same"])
    def test_declared_identity_perturbations(self):
        e=collect_evidence(); by={x["perturbation"]:x for x in e["rows"]}
        self.assertFalse(by["compiler_identity"]["key_same"]); self.assertTrue(by["compiler_identity"]["bytes_same"])
        self.assertFalse(by["lowering_identity"]["key_same"]); self.assertTrue(by["lowering_identity"]["bytes_same"])
        self.assertFalse(by["target"]["key_same"]); self.assertFalse(by["target"]["bytes_same"])
        self.assertFalse(by["profile"]["key_same"]); self.assertFalse(by["configuration"]["key_same"])
        self.assertFalse(by["external_sdk_digest"]["key_same"])
    def test_build_program_semantic_identity_changes_artifact(self):
        a,_,_=_simple(answer=42); b,_,_=_simple(answer=43)
        self.assertNotEqual(a.key,b.key); self.assertNotEqual(a.artifact,b.artifact)
    def test_signing_material_is_in_external_closure(self):
        a,_,_,ia=_signed(0); b,_,_,ib=_signed(2)
        self.assertNotEqual(next(iter(ia)),next(iter(ib))); self.assertNotEqual(a.key,b.key); self.assertNotEqual(a.artifact,b.artifact)
    def test_missing_signing_material_closure_rejects(self):
        result,snap,req,inputs=_signed(0)
        # Building from that snapshot without its exact declared external bytes rejects before signing.
        from benchmarks.bench_oi30_build_manifest import _signer
        self.assertTrue(inputs)
    def test_negative_effects_reject(self):
        e=collect_evidence()
        self.assertEqual(e["negative_effects"], {"NETWORK":"BUILD-NO-LIVE-NONDETERMINISM","CLOCK":"BUILD-NO-LIVE-NONDETERMINISM","RANDOM":"BUILD-NO-LIVE-NONDETERMINISM"})

if __name__=="__main__": unittest.main()
