from __future__ import annotations

import hashlib
import unittest

from xax_accelerator import compile_accelerator, inspect_deployment, run_accelerator_deployment
from xax_build import (
    ArtifactKind,
    build,
    build_profile,
    build_request,
    package,
    resolve_packages,
    snapshot_store,
    trust_policy,
)
from xax_workspace import Workspace

from xax_compiler import (
    AtomicScope,
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    ResourceFlags,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    decode_native_target,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    resource_type,
    simt32_accelerator_target,
    verify_store,
    write_store,
)


def accelerator_fixture(*, launch_scope=AtomicScope.DEVICE, h2d_source_space=1):
    b32 = bits_type(32)
    device_effect = effect_type(EffectDomain.DEVICE, 1)
    host_buffer = resource_type(
        1001,
        1,
        flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE,
        transitions=(2,),
    )
    device_buffer = resource_type(1001, 2, flags=ResourceFlags.RELEASABLE, transitions=(1,))
    target = simt32_accelerator_target()
    nodes = (
        Node(
            Operation.TARGET_OP,
            (ValueRef.parameter(0, 2),),
            (host_buffer, device_effect),
            entity=target,
            attributes=(1, AtomicScope.DEVICE, 1, 1),
        ),
        Node(
            Operation.TARGET_OP,
            (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)),
            (device_buffer, device_effect),
            entity=target,
            attributes=(2, AtomicScope.DEVICE, h2d_source_space, 2),
        ),
        Node(
            Operation.TARGET_OP,
            (ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)),
            (device_buffer, device_effect),
            entity=target,
            attributes=(3, launch_scope, 2, 2),
        ),
        Node(
            Operation.TARGET_OP,
            (ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 1)),
            (device_buffer, device_effect),
            entity=target,
            attributes=(4, AtomicScope.DEVICE, 2, 2),
        ),
        Node(
            Operation.TARGET_OP,
            (ValueRef.node_result(0, 3, 0), ValueRef.node_result(0, 3, 1)),
            (b32, host_buffer, device_effect),
            entity=target,
            attributes=(5, AtomicScope.DEVICE, 2, 1),
        ),
        Node(
            Operation.TARGET_OP,
            (ValueRef.node_result(0, 4, 1), ValueRef.node_result(0, 4, 2)),
            (device_effect,),
            entity=target,
            attributes=(6, AtomicScope.DEVICE, 1, 1),
        ),
    )
    graph = graph_fragment(
        (
            Block(
                (b32, b32, device_effect),
                nodes,
                Terminator.return_((ValueRef.node_result(0, 4, 0), ValueRef.node_result(0, 5, 0))),
            ),
        )
    )
    entry = function(graph, (b32, b32, device_effect), (b32, device_effect))
    module = object_with_refs(Kind.MODULE, (b32, device_effect, host_buffer, device_buffer, entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b32, device_effect, host_buffer, device_buffer, target, graph, entry, module, root)
    reader = StoreReader(write_store(root.cid, objects))
    return reader, entry, target, objects


class AcceleratorTargetTests(unittest.TestCase):
    def test_target_package_describes_topology_spaces_and_operations(self):
        first = simt32_accelerator_target()
        second = simt32_accelerator_target()
        self.assertEqual(first, second)
        description = decode_native_target(first)
        self.assertEqual((description.architecture, description.image_format), (4, 3))
        self.assertEqual(description.accelerator_lane_width, 32)
        self.assertEqual(description.accelerator_scopes, (AtomicScope.DEVICE, AtomicScope.WORKGROUP))
        self.assertEqual(tuple(space.identity for space in description.memory_spaces), (1, 2, 3))
        self.assertEqual(tuple(contract.semantic_code for contract in description.target_operations), (1, 2, 3, 4, 5, 6))
        self.assertTrue(all(not contract.runtime_dependency for contract in description.target_operations))

    def test_compile_and_execute_deployment_is_deterministic(self):
        reader, entry, target, _ = accelerator_fixture()
        verify_store(reader)
        first = compile_accelerator(reader, entry.cid, target.cid)
        second = compile_accelerator(reader, entry.cid, target.cid)
        self.assertEqual(first.deployment, second.deployment)
        view = inspect_deployment(first.deployment)
        self.assertEqual(view.target_cid, target.cid)
        self.assertEqual(view.function_cid, entry.cid)
        self.assertEqual(view.memory_spaces, (1, 2, 3))
        self.assertEqual(tuple(item.semantic_code for item in view.instructions), (1, 2, 3, 4, 5, 6))
        self.assertEqual(tuple(item.encoding_opcode for item in view.instructions), (0x10, 0x11, 0x12, 0x13, 0x14, 0x15))
        self.assertEqual(first.runtime_dependencies, ())
        self.assertEqual(run_accelerator_deployment(first, (7, 9)), (16,))
        self.assertEqual(run_accelerator_deployment(first, (0xFFFFFFFF, 2)), (1,))
        self.assertEqual(len([item for item in first.semantic_ranges if item.block_index is not None]), 6)
        self.assertEqual(hashlib.sha256(first.deployment).digest(), hashlib.sha256(second.deployment).digest())

    def test_unsupported_execution_scope_rejects_deterministically(self):
        reader, _, _, _ = accelerator_fixture(launch_scope=AtomicScope.SYSTEM)
        with self.assertRaises(XaxError) as first:
            verify_store(reader)
        with self.assertRaises(XaxError) as second:
            verify_store(reader)
        self.assertEqual(first.exception.diagnostic.rule, "TARGET-OPERATION-SCOPE-SUPPORTED")
        self.assertEqual(first.exception.diagnostic, second.exception.diagnostic)

    def test_unsupported_memory_space_pair_rejects(self):
        reader, _, _, _ = accelerator_fixture(h2d_source_space=3)
        with self.assertRaises(XaxError) as error:
            verify_store(reader)
        self.assertEqual(error.exception.diagnostic.rule, "TARGET-OPERATION-MEMORY-SPACES")

    def test_resource_effect_chain_is_linear_and_sync_is_explicit(self):
        reader, entry, target, objects = accelerator_fixture()
        verify_store(reader)
        graph = next(item for item in objects if item.kind == Kind.GRAPH_FRAGMENT)
        target_bytes = target.cid
        self.assertIn(target_bytes, graph.references)
        image = compile_accelerator(reader, entry.cid, target.cid)
        view = inspect_deployment(image.deployment)
        sync = view.instructions[3]
        self.assertTrue(sync.synchronizes)
        self.assertTrue(sync.may_block)
        self.assertEqual((sync.scope, sync.source_space, sync.destination_space), (AtomicScope.DEVICE, 2, 2))


    def test_workspace_artifact_mapping_uses_target_neutral_interface(self):
        reader, entry, target, _ = accelerator_fixture()
        workspace = Workspace(reader, target)
        artifact = workspace.artifact(entry.cid)
        self.assertEqual(artifact.classification, "derived")
        self.assertEqual(artifact.format, "simt32-packet-accelerator-v1")
        self.assertIsNotNone(artifact.handle)
        self.assertIsNotNone(artifact.entry_handle)
        mapping = workspace.map_semantic(artifact.entry_handle, artifact.handle, 8)
        self.assertTrue(mapping.ranges)
        self.assertTrue(any(item.end > item.start for item in mapping.ranges))

    def test_package_build_emits_accelerator_artifact_and_provenance(self):
        reader, entry, target, objects = accelerator_fixture()
        module = next(item for item in objects if item.kind == Kind.MODULE)
        app = package(b"m13-accelerator-app", (module,), build_entries=((b"deployment", entry),))
        profile = build_profile()
        policy = trust_policy()
        request = build_request(
            app,
            b"deployment",
            target,
            profile,
            requested_artifacts=(ArtifactKind.ACCELERATOR_DEPLOYMENT,),
        )
        candidates = (*tuple(reader.objects()), app, profile, policy, request)
        resolution = resolve_packages(request, candidates, policy, b"m13-resolver-v1")
        snapshot_reader = snapshot_store(resolution, candidates)
        result = build(snapshot_reader, request.cid)
        direct = compile_accelerator(snapshot_reader, entry.cid, target.cid)
        self.assertEqual(result.artifact, direct.deployment)
        self.assertEqual(run_accelerator_deployment(result.artifact, (123, 456)), (579,))
        self.assertTrue(result.provenance.references)

        wrong_request = build_request(app, b"deployment", target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
        wrong_candidates = (*candidates, wrong_request)
        wrong_resolution = resolve_packages(wrong_request, wrong_candidates, policy, b"m13-resolver-v1")
        wrong_reader = snapshot_store(wrong_resolution, wrong_candidates)
        with self.assertRaisesRegex(XaxError, "XAX.BUILD.ARTIFACT"):
            build(wrong_reader, wrong_request.cid)


if __name__ == "__main__":
    unittest.main()
