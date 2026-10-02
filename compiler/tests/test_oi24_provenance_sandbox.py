import os, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from bench_oi24_provenance_sandbox import *

class OI24Tests(unittest.TestCase):
    def test_action_roundtrip_and_corruption(self):
        fx=fixture(); records=action_dag(fx); data=encode_action_set(records)
        self.assertEqual(len(decode_action_set(data)),3)
        bad=bytearray(data); bad[-1]^=1
        with self.assertRaisesRegex(ValueError,"DIGEST"): decode_action_set(bytes(bad))
    def test_action_dependency_rejects(self):
        fx=fixture(); r=action_dag(fx)[-1]
        bad=ActionRecord(r.kind,r.implementation,r.inputs,r.capabilities,r.outputs,(b"x"*32,))
        with self.assertRaisesRegex(ValueError,"DEPENDENCY"): decode_action_set(encode_action_set((bad,)))
    def test_action_is_derived_only(self):
        fx=fixture(); root=fx['reader'].root_cid; _=encode_action_set(action_dag(fx)); self.assertEqual(root,fx['reader'].root_cid)
    def test_changed_input_precise_action_invalidation(self):
        a,b=fixture(b'a'),fixture(b'b'); da,db=action_dag(a),action_dag(b); A={x.kind:x.action_id for x in da}; B={x.kind:x.action_id for x in db}
        self.assertEqual(A[b'lower-entry'],B[b'lower-entry'])
        self.assertNotEqual(A[b'verify-external'],B[b'verify-external'])
        self.assertNotEqual(A[b'emit-provenance'],B[b'emit-provenance'])
        self.assertNotEqual(a['result'].key,b['result'].key)
        self.assertEqual(a['result'].artifact,b['result'].artifact)
    def test_semantic_capability_gate_precedes_host(self):
        fx=fixture(); snap=decode_snapshot(fx['resolution'].snapshot,fx['reader'].get); req=decode_request(fx['request'],fx['reader'].get)
        net=BuildCapability(BuildCapabilityKind.NETWORK,b'x')
        with self.assertRaises(Exception): validate_build_effects(fx['reader'],snap,req,(BuildEffect(b'oi24-app',net),))
    def test_requested_unavailable_isolation_fails(self):
        fx=fixture(); eff=(BuildEffect(b"oi24-app",fx["read"],fx["external_value"]),)
        with self.assertRaisesRegex(RuntimeError,"XAX.SANDBOX.UNAVAILABLE"): sandbox_checked_run(fx,("cat","/inputs/declared"),effects=eff,force_unavailable=True)
    def test_hosted_namespace_sandbox_if_available(self):
        if not hosted_sandbox_available(): self.skipTest('host namespace sandbox unavailable')
        r=sandbox_measure(fixture()); self.assertTrue(r['declared_file_allowed']); self.assertTrue(r['undeclared_file_denied']); self.assertTrue(r['declared_input_write_denied']); self.assertTrue(r['ambient_env_denied']); self.assertTrue(r['undeclared_network_denied'])
    def test_checked_adapter_maps_declared_external(self):
        fx=fixture(); eff=(BuildEffect(b"oi24-app",fx["read"],fx["external_value"]),)
        if not hosted_sandbox_available(): self.skipTest('host namespace sandbox unavailable')
        r=sandbox_checked_run(fx,("cat","/inputs/declared"),effects=eff); self.assertEqual(r.stdout,fx["external_value"])

    def test_evidence_shape(self):
        e,_=build_evidence(False); self.assertEqual(e['action_dag']['records'],3); self.assertTrue(e['nonsemantic']['action_records_delete_without_semantic_change'])

if __name__=='__main__': unittest.main()
