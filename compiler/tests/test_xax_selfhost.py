"""M14 self-hosting and closure-target tests.

The semantic-image target is intentionally narrow: it proves recursive XAX
compiler generations and XAX-hosted verification/encoding/finalization/build
orchestration without claiming closure for legacy native/wasm/accelerator
backends.  B6 remains false until immutable-seed independence is separately proven.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from xax_selfhost import (
    create_m14_program_store,
    current_m14_readiness,
    execute_m14_recursive_evidence,
    readiness_from_recursive_evidence,
    bootstrap_status,
)

from xax_compiler import (
    Block,
    CompileTimeEvaluator,
    Kind,
    MetaCapability,
    Node,
    OpaqueKind,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    function,
    graph_fragment,
    object_with_refs,
    opaque_type,
    verify_store,
    write_store,
)


def self_inspection_fixture():
    b32 = bits_type(32)
    function_ref = opaque_type(OpaqueKind.FUNCTION)
    graph_ref = opaque_type(OpaqueKind.GRAPH)

    target_graph = graph_fragment(
        [
            Block(
                (b32, b32),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    target_function = function(target_graph, (b32, b32), (b32,))

    inspector_nodes = (
        Node(Operation.META_FUNCTION_GRAPH, (ValueRef.parameter(0, 0),), (graph_ref,)),
        Node(Operation.META_GRAPH_BLOCK_COUNT, (ValueRef.node_result(0, 0),), (b32,)),
        Node(
            Operation.META_GRAPH_NODE_COUNT,
            (ValueRef.node_result(0, 0), ValueRef.parameter(0, 1)),
            (b32,),
        ),
        Node(
            Operation.META_GRAPH_NODE_OPERATION,
            (ValueRef.node_result(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
            (b32,),
        ),
    )
    inspector_graph = graph_fragment(
        [
            Block(
                (function_ref, b32, b32),
                inspector_nodes,
                Terminator.return_(
                    (
                        ValueRef.node_result(0, 1),
                        ValueRef.node_result(0, 2),
                        ValueRef.node_result(0, 3),
                    )
                ),
            )
        ]
    )
    inspector = function(inspector_graph, (function_ref, b32, b32), (b32, b32, b32))
    module = object_with_refs(Kind.MODULE, (target_function, inspector))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(
        write_store(
            root.cid,
            (
                b32,
                function_ref,
                graph_ref,
                target_graph,
                target_function,
                inspector_graph,
                inspector,
                module,
                root,
            ),
        )
    )
    return reader, target_function, inspector


class M14GraphIntrospectionTests(unittest.TestCase):
    def test_xax_compile_time_can_inspect_function_graph_shape_and_opcode(self):
        reader, target_function, inspector = self_inspection_fixture()
        verify_store(reader)
        result = CompileTimeEvaluator().evaluate(
            reader,
            inspector.cid,
            (target_function, 0, 0),
            capabilities=(MetaCapability.INSPECT_FUNCTION,),
        )
        self.assertEqual(result.values, (1, 1, Operation.ADD_WRAP))

    def test_graph_introspection_requires_explicit_capability(self):
        reader, target_function, inspector = self_inspection_fixture()
        with self.assertRaisesRegex(XaxError, "XAX.META.CAPABILITY"):
            CompileTimeEvaluator().evaluate(reader, inspector.cid, (target_function, 0, 0))

    def test_graph_introspection_rejects_out_of_range_indices_deterministically(self):
        reader, target_function, inspector = self_inspection_fixture()
        with self.assertRaises(XaxError) as caught:
            CompileTimeEvaluator().evaluate(
                reader,
                inspector.cid,
                (target_function, 1, 0),
                capabilities=(MetaCapability.INSPECT_FUNCTION,),
            )
        self.assertEqual(caught.exception.diagnostic.rule, "META-GRAPH-BLOCK-INDEX")


class M14RecursiveSelfHostTests(unittest.TestCase):
    def test_capability_presence_does_not_fabricate_executed_bootstrap_claims(self):
        readiness = current_m14_readiness()
        self.assertTrue(readiness.graph_introspection)
        self.assertTrue(readiness.canonical_byte_emission)
        self.assertFalse(readiness.b2)
        self.assertFalse(readiness.b3)
        self.assertFalse(readiness.b4)
        self.assertFalse(readiness.b5)
        self.assertFalse(readiness.b6)
        self.assertNotIn("compile-time XAX cannot emit arbitrary canonical store/object/artifact bytes", readiness.blockers)

    def test_recursive_semantic_image_build_reaches_b2_b4_but_not_b5_b6(self):
        reader = create_m14_program_store()
        evidence = execute_m14_recursive_evidence(reader)
        self.assertTrue(evidence.b2)
        self.assertTrue(evidence.b3)
        self.assertTrue(evidence.b4)
        # Verification, encoding, and materialization run as host (Python) META primitives: not toolchain closure.
        self.assertEqual(evidence.host_substrate_operations, ("META_CANONICAL_STORE", "META_MATERIALIZE_PROGRAM", "META_VERIFY_SEMANTICS"))
        self.assertFalse(evidence.b5)
        self.assertEqual(evidence.generation0_digest, evidence.generation1_digest)
        self.assertEqual(evidence.generation1_digest, evidence.generation2_digest)
        self.assertGreaterEqual(len(evidence.vectors), 4)
        self.assertTrue(all(item.matches for item in evidence.vectors))

        readiness = readiness_from_recursive_evidence(evidence)
        self.assertTrue(readiness.b2)
        self.assertTrue(readiness.b3)
        self.assertTrue(readiness.b4)
        self.assertFalse(readiness.b5)
        self.assertFalse(readiness.b6)
        self.assertEqual(
            readiness.blockers,
            (
                "semantic verifier remains a live host-language service",
                "target lowering/code generation remains a live host-language service",
                "package/build/repository operations remain live host-language services",
                "ordinary release/target evolution still requires maintained Python implementation code",
            ),
        )

    def test_committed_m14_artifacts_match_executed_evidence(self):
        bootstrap = Path(__file__).resolve().parents[1] / "bootstrap"
        program_path = bootstrap / "m14_selfhost_compiler.xax"
        evidence_path = bootstrap / "m14_selfhost_evidence.json"
        self.assertTrue(program_path.is_file())
        self.assertTrue(evidence_path.is_file())

        expected = create_m14_program_store().canonical_bytes()
        self.assertEqual(program_path.read_bytes(), expected)
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        executed = execute_m14_recursive_evidence(StoreReader(expected))
        self.assertEqual(evidence["compiler_root"], executed.compiler_root.hex())
        self.assertEqual(evidence["compiler_function"], executed.compiler_function.hex())
        self.assertEqual(evidence["generation_digests"], [
            executed.generation0_digest.hex(),
            executed.generation1_digest.hex(),
            executed.generation2_digest.hex(),
        ])
        # SELFHOST_EVIDENCE_DERIVED / NO_HAND_ASSERTED_B_STATUS: the committed B status is the derivation's output.
        self.assertEqual(evidence["bootstrap_status"], bootstrap_status(executed))
        self.assertFalse(any(key.startswith("b") and key[1:2].isdigit() for key in evidence))

    def test_committed_seed_runtime_reconstructs_without_repository_source_path(self):
        bootstrap = Path(__file__).resolve().parents[1] / "bootstrap"
        seed = bootstrap / "m14_seed_runtime.pyz"
        program = bootstrap / "m14_selfhost_compiler.xax"
        self.assertTrue(seed.is_file())
        self.assertTrue(program.is_file())
        with tempfile.TemporaryDirectory(prefix="xax-m14-seed-test-") as directory:
            output = Path(directory) / "rebuilt.xax"
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            completed = subprocess.run(
                [sys.executable, str(seed), "rebuild", str(program), str(output)],
                cwd=directory,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(output.read_bytes(), program.read_bytes())


if __name__ == "__main__":
    unittest.main()
