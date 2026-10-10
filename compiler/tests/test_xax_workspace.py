import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xax_compiler import (
    AtomicOrder,
    AtomicScope,
    Block,
    Diagnostic,
    EffectDomain,
    Kind,
    Node,
    Operation,
    Permission,
    RecursionMember,
    ResourceFlags,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    aarch64_baremetal_target,
    bits_type,
    constant,
    execute,
    effect_type,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    RealtimeProfile,
    recursion_group,
    resource_type,
    stack_owner_type,
    verify_store,
    wasm32_target,
    write_store,
    x86_64_windows_target,
)
from xax_workspace import (
    ConnectEdgeArgument,
    DeleteNode,
    DisconnectEdgeArgument,
    InsertPureNode,
    MovePureNode,
    ReplaceUse,
    RootRef,
    SetConstant,
    SetFunctionSignature,
    SetOperation,
    SetResultType,
    SpecializationArgument,
    SpecializeFunction,
    Transaction,
    TransactionValueRef,
    Workspace,
    _query_size,
)


def workspace_fixture():
    b8 = bits_type(8)
    two, three = constant(b8, 2), constant(b8, 3)
    graph = graph_fragment(
        [
            Block(
                (),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=two),
                    Node(Operation.CONSTANT, (), (b8,), entity=three),
                    Node(
                        Operation.ADD_WRAP,
                        (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)),
                        (b8,),
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 2),)),
            )
        ]
    )
    entry = function(graph, (), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (entry, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (b8, two, three, graph, entry, unrelated, module, root))), entry


def resource_workspace_fixture():
    b8 = bits_type(8)
    filesystem = effect_type(EffectDomain.FILESYSTEM, 4)
    handle = resource_type(2, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE)
    graph = graph_fragment(
        [
            Block(
                (b8, filesystem),
                (
                    Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (handle, filesystem)),
                    Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (filesystem,)),
                ),
                Terminator.return_((ValueRef.parameter(0, 0), ValueRef.node_result(0, 1, 0))),
            )
        ]
    )
    entry = function(graph, (b8, filesystem), (b8, filesystem))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (b8, filesystem, handle, graph, entry, module, root))), entry


def atomic_workspace_fixture():
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    target_object = x86_64_windows_target()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.ATOMIC_STORE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(AtomicOrder.RELEASE, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_LOAD, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 0)), (b32, effect), attributes=(AtomicOrder.ACQUIRE, AtomicScope.SYSTEM, 4)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)), ()),
    )
    graph = graph_fragment([Block((b32,), nodes, Terminator.return_((ValueRef.node_result(0, 2, 0),)))])
    entry = function(graph, (b32,), (b32,))
    module = object_with_refs(Kind.MODULE, (entry, target_object))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b32, pointer, owner, effect, graph, entry, target_object, module, root)
    return StoreReader(write_store(root.cid, objects)), entry, target_object



def deletable_caller_fixture():
    b8 = bits_type(8)
    unused_literal = constant(b8, 9)
    callee_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=unused_literal),
                    Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),
                ),
                Terminator.return_((ValueRef.node_result(0, 1),)),
            )
        ]
    )
    callee = function(callee_graph, (b8, b8), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=callee),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (callee, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, unused_literal, callee_graph, callee, caller_graph, caller, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), callee, unrelated


def movable_caller_fixture():
    b8 = bits_type(8)
    two, three = constant(b8, 2), constant(b8, 3)
    callee_graph = graph_fragment(
        [
            Block(
                (),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=two),
                    Node(Operation.CONSTANT, (), (b8,), entity=three),
                    Node(
                        Operation.ADD_WRAP,
                        (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)),
                        (b8,),
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 2),)),
            )
        ]
    )
    callee = function(callee_graph, (), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (),
                (Node(Operation.CALL_DIRECT, (), (b8,), entity=callee),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (callee, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, two, three, callee_graph, callee, caller_graph, caller, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), callee, caller, unrelated


def branch_use_fixture():
    b1 = bits_type(1)
    one = constant(b1, 1)
    graph = graph_fragment(
        [
            Block((), (Node(Operation.CONSTANT, (), (b1,), entity=one),), Terminator.branch(1, (ValueRef.node_result(0, 0),))),
            Block((b1,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
        ]
    )
    entry = function(graph, (), (b1,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (b1, one, graph, entry, module, root))), entry


def edge_argument_caller_fixture():
    b8, b16 = bits_type(8), bits_type(16)
    one = constant(b8, 1)
    callee_graph = graph_fragment(
        [
            Block(
                (b8, b8, b16),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=one),
                    Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),
                ),
                Terminator.branch(1, (ValueRef.parameter(0, 0),)),
            ),
            Block((b8,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
        ]
    )
    callee = function(callee_graph, (b8, b8, b16), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8, b16),
                (
                    Node(
                        Operation.CALL_DIRECT,
                        (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
                        (b8,),
                        entity=callee,
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8, b16), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (callee, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, b16, one, callee_graph, callee, caller_graph, caller, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), callee, unrelated

def native_workspace_fixture():
    b32 = bits_type(32)
    two, three = constant(b32, 2), constant(b32, 3)
    graph = graph_fragment(
        [
            Block(
                (),
                (
                    Node(Operation.CONSTANT, (), (b32,), entity=two),
                    Node(Operation.CONSTANT, (), (b32,), entity=three),
                    Node(
                        Operation.ADD_WRAP,
                        (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)),
                        (b32,),
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 2),)),
            )
        ]
    )
    entry = function(graph, (), (b32,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (b32, two, three, graph, entry, module, root))), entry


def caller_fixture(recursive_user=False):
    b8 = bits_type(8)
    arithmetic_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    arithmetic = function(arithmetic_graph, (b8, b8), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (
                    Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=arithmetic),
                    Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 0)), (b8,)),
                ),
                Terminator.return_((ValueRef.node_result(0, 1),)),
            )
        ]
    )
    if recursive_user:
        # A recursion group must be a recursive SCC; the self-call is never executed by this fixture.
        caller_graph = graph_fragment(
            [
                Block(
                    (b8, b8),
                    (
                        Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=arithmetic),
                        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 0)), (b8,)),
                        Node(Operation.CALL_GROUP_MEMBER, (ValueRef.node_result(0, 1), ValueRef.parameter(0, 1)), (b8,), member=0),
                    ),
                    Terminator.return_((ValueRef.node_result(0, 2),)),
                )
            ]
        )
    caller = recursion_group((RecursionMember(caller_graph, (b8, b8), (b8,)),)) if recursive_user else function(caller_graph, (b8, b8), (b8,))
    callers = [caller]
    objects = [b8, arithmetic_graph, arithmetic, caller_graph, caller]
    if not recursive_user:
        outer_graph = graph_fragment(
            [
                Block(
                    (b8, b8),
                    (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=caller),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                )
            ]
        )
        outer = function(outer_graph, (b8, b8), (b8,))
        callers.append(outer)
        objects.extend((outer_graph, outer))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (arithmetic, *callers, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects.extend((unrelated, module, root))
    return StoreReader(write_store(root.cid, objects)), arithmetic


def disjoint_fixture():
    b8 = bits_type(8)
    functions = []
    objects = [b8]
    for value in (2, 3):
        literal = constant(b8, value)
        graph = graph_fragment(
            [Block((), (Node(Operation.CONSTANT, (), (b8,), entity=literal),), Terminator.return_((ValueRef.node_result(0, 0),)))]
        )
        item = function(graph, (), (b8,))
        functions.append(item)
        objects.extend((literal, graph, item))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (*functions, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects.extend((unrelated, module, root))
    return StoreReader(write_store(root.cid, objects)), tuple(functions)


def shared_caller_fixture():
    b8 = bits_type(8)
    functions = []
    objects = [b8]
    for operation in (Operation.ADD_WRAP, Operation.SUB_WRAP):
        graph = graph_fragment(
            [
                Block(
                    (b8, b8),
                    (Node(operation, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                )
            ]
        )
        item = function(graph, (b8, b8), (b8,))
        functions.append(item)
        objects.extend((graph, item))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (
                    Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=functions[0]),
                    Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=functions[1]),
                    Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b8,)),
                ),
                Terminator.return_((ValueRef.node_result(0, 2),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (*functions, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects.extend((caller_graph, caller, unrelated, module, root))
    return StoreReader(write_store(root.cid, objects)), tuple(functions)


def specialization_fixture():
    b8 = bits_type(8)
    source_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    source = function(source_graph, (b8, b8), (b8,))
    caller_literal = constant(b8, 1)
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (
                    Node(Operation.CONSTANT, (), (b8,), entity=caller_literal),
                    Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,), entity=source),
                ),
                Terminator.return_((ValueRef.node_result(0, 1),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8), (b8,))
    unrelated = constant(b8, 255)
    module = object_with_refs(Kind.MODULE, (source, caller, unrelated))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b8, source_graph, source, caller_literal, caller_graph, caller, unrelated, module, root)
    return StoreReader(write_store(root.cid, objects)), source, caller, unrelated


def type_fixture(extra_value=None):
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(
            Operation.STORE_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
            (effect,),
            attributes=(4, 4),
        ),
        Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1)),
            (b32, effect),
            attributes=(4, 4),
        ),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)), ()),
    )
    graph = graph_fragment([Block((b32,), nodes, Terminator.return_((ValueRef.node_result(0, 2),)))])
    entry = function(graph, (b32,), (b32,))
    extra = constant(b32, extra_value) if extra_value is not None else None
    module = object_with_refs(Kind.MODULE, (entry,) if extra is None else (entry, extra))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b32, pointer, owner, effect, graph, entry, module, root) if extra is None else (b32, pointer, owner, effect, graph, entry, extra, module, root)
    return StoreReader(write_store(root.cid, objects)), entry


class WorkspaceTests(unittest.TestCase):
    def test_result_type_and_function_signature_change_atomically(self):
        b8, b16 = bits_type(8), bits_type(16)
        c8, c16 = constant(b8, 7), constant(b16, 1)
        graph8 = graph_fragment([Block((), (Node(Operation.CONSTANT, (), (b8,), entity=c8),), Terminator.return_((ValueRef.node_result(0, 0),)))])
        graph16 = graph_fragment([Block((), (Node(Operation.CONSTANT, (), (b16,), entity=c16),), Terminator.return_((ValueRef.node_result(0, 0),)))])
        entry8, helper16 = function(graph8, (), (b8,)), function(graph16, (), (b16,))
        module = object_with_refs(Kind.MODULE, (entry8, helper16))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        reader = StoreReader(write_store(root.cid, (b8, b16, c8, c16, graph8, graph16, entry8, helper16, module, root)))
        workspace = Workspace(reader)
        node8 = workspace.function_nodes(entry8.cid, 1).entities[0]
        node16 = workspace.function_nodes(helper16.cid, 1).entities[0]
        type8 = next(item.type_handle for item in workspace.neighborhood(node8.handle, 4).entities if "result" in item.relations)
        type16 = next(item.type_handle for item in workspace.neighborhood(node16.handle, 4).entities if "result" in item.relations)
        function8 = node8.handle.split(".", 1)[0]
        transaction = Transaction(
            RootRef(0),
            (
                SetResultType(node8.handle, 0, type8, type16),
                SetFunctionSignature(function8, (), (), (type8,), (type16,)),
            ),
        )

        verified = workspace.verify(transaction)
        committed = workspace.commit(transaction)

        self.assertTrue(verified.verified)
        self.assertTrue(committed.committed)
        self.assertEqual(execute(workspace.reader, committed.changed_entity, ()), (7,))

    def test_x86_artifact_mapping_is_exact_bounded_and_classifies_unavailable(self):
        reader, entry = type_fixture()
        workspace = Workspace(reader, x86_64_windows_target())
        artifact = workspace.artifact(entry.cid)
        nodes = workspace.function_nodes(entry.cid, 8).entities

        self.assertEqual(
            (artifact.handle, artifact.entry_handle, artifact.format, artifact.size_bytes, artifact.entry_offset, artifact.classification),
            ("A0.0", "F0", "x86_64-windows-load-image-v2", 43, 0, "derived"),
        )
        artifact_entity = workspace.entity(artifact.handle)
        self.assertEqual(artifact_entity.kind, "artifact")
        artifact_facts = dict(artifact_entity.facts)
        self.assertEqual(artifact_facts["semantic_root"], "R0.0")
        self.assertEqual(artifact_facts["identity"], artifact.identity)
        self.assertEqual(artifact_facts["digest"], artifact.digest)
        self.assertEqual(artifact_facts["compiler_identity"], artifact.compiler_identity)
        self.assertEqual(artifact_facts["lowering_identity"], artifact.lowering_identity)
        self.assertGreater(artifact_facts["retained_ranges"], 0)
        self.assertEqual(len(artifact.identity), 64)
        self.assertEqual(len(artifact.digest), 64)
        self.assertEqual(artifact.semantic_root, "R0.0")
        self.assertEqual(len(artifact.compiler_identity), 64)
        self.assertEqual(len(artifact.lowering_identity), 64)
        function_map = workspace.map_semantic(artifact.entry_handle, artifact.handle, 1)
        self.assertEqual(function_map.artifact_identity, artifact.identity)
        self.assertEqual([(item.start, item.end, item.relation) for item in function_map.ranges], [(0, 43, "function")])
        self.assertEqual(function_map.classification, "derived")

        allocation_map = workspace.map_semantic(nodes[0].handle, artifact.handle, 1)
        store_map = workspace.map_semantic(nodes[1].handle, artifact.handle, 1)
        load_map = workspace.map_semantic(nodes[2].handle, artifact.handle, 1)
        lifetime_map = workspace.map_semantic(nodes[3].handle, artifact.handle, 1)
        self.assertEqual((allocation_map.classification, allocation_map.ranges), ("unavailable", ()))
        self.assertEqual([(item.start, item.end) for item in store_map.ranges], [(12, 21)])
        self.assertEqual([(item.start, item.end) for item in load_map.ranges], [(21, 30)])
        self.assertEqual((lifetime_map.classification, lifetime_map.ranges), ("unavailable", ()))

        first = workspace.map_artifact(artifact.handle, 12, 1, 1)
        second = workspace.map_artifact(artifact.handle, 12, 1, 1, first.continuation)
        self.assertEqual((first.artifact_identity, second.artifact_identity), (artifact.identity, artifact.identity))
        self.assertTrue(first.truncated)
        self.assertFalse(second.truncated)
        self.assertEqual(
            [(item.handle, item.kind, item.start, item.end) for item in (*first.entities, *second.entities)],
            [("F0", "function", 0, 43), (nodes[1].handle, "node", 12, 21)],
        )
        self.assertTrue(all(len(item.handle) < 64 for item in (*first.entities, *second.entities)))

        unavailable = Workspace(reader).artifact(entry.cid)
        self.assertEqual((unavailable.handle, unavailable.classification), (None, "unavailable"))
        self.assertEqual(
            (unavailable.identity, unavailable.digest, unavailable.semantic_root, unavailable.compiler_identity, unavailable.lowering_identity),
            (None, None, None, None, None),
        )

    def test_artifact_provenance_identity_commits_to_root_target_and_lowering(self):
        reader, entry = type_fixture()
        first = Workspace(reader, x86_64_windows_target()).artifact(entry.cid)
        second = Workspace(reader, x86_64_windows_target()).artifact(entry.cid)
        self.assertEqual((first.identity, first.digest), (second.identity, second.digest))

        changed_reader, changed_entry = type_fixture(extra_value=17)
        changed_root = Workspace(changed_reader, x86_64_windows_target()).artifact(changed_entry.cid)
        self.assertEqual(first.digest, changed_root.digest)
        self.assertNotEqual(first.identity, changed_root.identity)
        self.assertNotEqual(reader.root_cid, changed_reader.root_cid)

        aarch64 = Workspace(reader, aarch64_baremetal_target()).artifact(entry.cid)
        wasm = Workspace(reader, wasm32_target()).artifact(entry.cid)
        self.assertEqual(len({first.identity, aarch64.identity, wasm.identity}), 3)
        self.assertEqual(len({first.lowering_identity, aarch64.lowering_identity, wasm.lowering_identity}), 3)

        changed_lowering_workspace = Workspace(reader, x86_64_windows_target())
        changed_lowering_workspace._lowering_identity = bytes.fromhex("a5" * 32)
        changed_lowering = changed_lowering_workspace.artifact(entry.cid)
        self.assertEqual(first.digest, changed_lowering.digest)
        self.assertNotEqual(first.identity, changed_lowering.identity)

    def test_artifact_mapping_rejects_changed_toolchain_dependency_without_generation_change(self):
        for attribute in ("_compiler_identity", "_lowering_identity"):
            with self.subTest(attribute=attribute):
                reader, entry = type_fixture()
                workspace = Workspace(reader, x86_64_windows_target())
                artifact = workspace.artifact(entry.cid)
                nodes = workspace.function_nodes(entry.cid, 8).entities
                setattr(workspace, attribute, bytes.fromhex("5a" * 32))

                with self.assertRaises(XaxError) as caught:
                    workspace.map_semantic(nodes[1].handle, artifact.handle, 1)
                self.assertEqual((caught.exception.diagnostic.code, caught.exception.diagnostic.rule), ("XAX.WORKSPACE.ARTIFACT_STALE", "WORKSPACE-ARTIFACT-DEPENDENCIES"))

                with self.assertRaises(XaxError) as caught:
                    workspace.map_artifact(artifact.handle, 12, 1, 1)
                self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.ARTIFACT_STALE")

                rejected = workspace.commit(
                    Transaction(
                        RootRef(0),
                        (SetOperation(nodes[1].handle, nodes[1].operation, nodes[1].operation),),
                        (artifact.handle,),
                    )
                )
                self.assertFalse(rejected.committed)
                self.assertEqual((rejected.diagnostic.code, rejected.diagnostic.entity), ("XAX.WORKSPACE.READ_CONFLICT", artifact.handle))

    def test_aarch64_artifact_mapping_uses_same_target_neutral_api(self):
        reader, entry = type_fixture()
        workspace = Workspace(reader, aarch64_baremetal_target())
        artifact = workspace.artifact(entry.cid)
        nodes = workspace.function_nodes(entry.cid, 8).entities

        self.assertEqual(
            (artifact.handle, artifact.entry_handle, artifact.format, artifact.size_bytes, artifact.entry_offset, artifact.classification),
            ("A0.0", "F0", "aarch64-baremetal-load-image-v1", 20, 0, "derived"),
        )
        self.assertEqual(workspace.entity(artifact.handle).kind, "artifact")
        function_map = workspace.map_semantic(artifact.entry_handle, artifact.handle, 1)
        self.assertEqual([(item.start, item.end, item.relation) for item in function_map.ranges], [(0, 20, "function")])

        allocation_map = workspace.map_semantic(nodes[0].handle, artifact.handle, 1)
        store_map = workspace.map_semantic(nodes[1].handle, artifact.handle, 1)
        load_map = workspace.map_semantic(nodes[2].handle, artifact.handle, 1)
        lifetime_map = workspace.map_semantic(nodes[3].handle, artifact.handle, 1)
        self.assertEqual((allocation_map.classification, allocation_map.ranges), ("unavailable", ()))
        self.assertEqual([(item.start, item.end) for item in store_map.ranges], [(4, 8)])
        self.assertEqual([(item.start, item.end) for item in load_map.ranges], [(8, 12)])
        self.assertEqual((lifetime_map.classification, lifetime_map.ranges), ("unavailable", ()))

        first = workspace.map_artifact(artifact.handle, 4, 1, 1)
        second = workspace.map_artifact(artifact.handle, 4, 1, 1, first.continuation)
        self.assertTrue(first.truncated)
        self.assertFalse(second.truncated)
        self.assertEqual(
            [(item.handle, item.kind, item.start, item.end) for item in (*first.entities, *second.entities)],
            [("F0", "function", 0, 20), (nodes[1].handle, "node", 4, 8)],
        )

    def test_wasm_artifact_mapping_uses_same_target_neutral_api(self):
        reader, entry = type_fixture()
        workspace = Workspace(reader, wasm32_target())
        artifact = workspace.artifact(entry.cid)
        nodes = workspace.function_nodes(entry.cid, 8).entities

        self.assertEqual(
            (artifact.handle, artifact.entry_handle, artifact.format, artifact.size_bytes, artifact.entry_offset, artifact.classification),
            ("A0.0", "F0", "wasm32-core-module-v1", 78, 39, "derived"),
        )
        function_map = workspace.map_semantic(artifact.entry_handle, artifact.handle, 1)
        self.assertEqual([(item.start, item.end, item.relation) for item in function_map.ranges], [(39, 78, "function")])

        allocation_map = workspace.map_semantic(nodes[0].handle, artifact.handle, 1)
        store_map = workspace.map_semantic(nodes[1].handle, artifact.handle, 1)
        load_map = workspace.map_semantic(nodes[2].handle, artifact.handle, 1)
        lifetime_map = workspace.map_semantic(nodes[3].handle, artifact.handle, 1)
        self.assertEqual((allocation_map.classification, allocation_map.ranges), ("unavailable", ()))
        self.assertEqual([(item.start, item.end) for item in store_map.ranges], [(56, 63)])
        self.assertEqual([(item.start, item.end) for item in load_map.ranges], [(63, 70)])
        self.assertEqual((lifetime_map.classification, lifetime_map.ranges), ("unavailable", ()))

        header = workspace.map_artifact(artifact.handle, 0, 1, 1)
        self.assertEqual((header.classification, header.entities), ("unavailable", ()))
        first = workspace.map_artifact(artifact.handle, 56, 1, 1)
        second = workspace.map_artifact(artifact.handle, 56, 1, 1, first.continuation)
        self.assertTrue(first.truncated)
        self.assertFalse(second.truncated)
        self.assertEqual(
            [(item.handle, item.kind, item.start, item.end) for item in (*first.entities, *second.entities)],
            [("F0", "function", 39, 78), (nodes[1].handle, "node", 56, 63)],
        )

    def test_artifact_mapping_handles_are_generation_scoped_and_read_set_eligible(self):
        for target in (x86_64_windows_target(), aarch64_baremetal_target(), wasm32_target()):
            with self.subTest(target=target.cid.hex()):
                reader, entry = native_workspace_fixture()
                workspace = Workspace(reader, target)
                artifact = workspace.artifact(entry.cid)
                nodes = workspace.function_nodes(entry.cid, 3).entities
                add_map = workspace.map_semantic(nodes[2].handle, artifact.handle, 1)
                contributor = workspace.map_artifact(artifact.handle, add_map.ranges[0].start, 1, 2).entities[-1]
                first = workspace.commit(
                    Transaction(
                        RootRef(0),
                        (SetOperation(nodes[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
                        (artifact.handle, contributor.handle),
                    )
                )
                self.assertTrue(first.committed)
                self.assertEqual(workspace.generation, 1)
                with self.assertRaisesRegex(XaxError, "XAX.WORKSPACE.HANDLE"):
                    workspace.map_artifact(artifact.handle, 0, 1, 1)

                current = workspace.function_nodes(first.changed_entity, 3).entities[2]
                stale_read = workspace.commit(
                    Transaction(
                        RootRef(1),
                        (SetOperation(current.handle, Operation.MUL_WRAP, Operation.SUB_WRAP),),
                        (artifact.handle,),
                    )
                )
                self.assertFalse(stale_read.committed)
                self.assertEqual(stale_read.diagnostic.code, "XAX.WORKSPACE.READ_CONFLICT")
                self.assertEqual(stale_read.diagnostic.entity, artifact.handle)

    def test_generation_root_alias_commits_rejects_stale_and_rebases(self):
        reader, entry = workspace_fixture()
        byte_workspace = Workspace(reader)
        alias_workspace = Workspace(reader)
        byte_node = byte_workspace.function_nodes(entry.cid, 3).entities[2]
        alias_node = alias_workspace.function_nodes(entry.cid, 3).entities[2]

        byte_result = byte_workspace.commit(Transaction(reader.root_cid, (SetOperation(byte_node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))
        alias_result = alias_workspace.commit(Transaction(RootRef(0), (SetOperation(alias_node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))

        self.assertTrue(byte_result.committed)
        self.assertTrue(alias_result.committed)
        self.assertEqual(byte_result.root, alias_result.root)
        self.assertEqual(byte_result.transaction_bytes - alias_result.transaction_bytes, 30)
        self.assertEqual(RootRef(0).handle, "R0.0")
        stale = alias_workspace.commit(Transaction(RootRef(0), (SetOperation(alias_node.handle, Operation.ADD_WRAP, Operation.SUB_WRAP),)))
        self.assertFalse(stale.committed)
        self.assertEqual((stale.diagnostic.code, stale.diagnostic.expected, stale.diagnostic.actual), ("XAX.WORKSPACE.STALE_ROOT", "R0.0", "R0.1"))
        self.assertEqual(alias_workspace.root, alias_result.root)

        reader, functions = disjoint_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
        stale_transaction = Transaction(RootRef(0), (SetConstant(nodes[1].handle, nodes[1].constant_value, 5),))
        first = workspace.commit(Transaction(RootRef(0), (SetConstant(nodes[0].handle, nodes[0].constant_value, 4),)))
        rebased = workspace.rebase(stale_transaction)
        self.assertTrue(first.committed)
        self.assertTrue(rebased.committed)
        self.assertEqual({execute(workspace.reader, obj.cid, ()) for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION}, {(4,), (5,)})

    def test_generation_root_alias_rejects_aba_at_atomic_compare(self):
        import xax_workspace as workspace_module

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        transaction = Transaction(RootRef(0), (SetOperation(node.handle, Operation.ADD_WRAP, Operation.SUB_WRAP),))
        original_candidate = workspace_module._candidate
        injected = False

        def candidate_with_aba(candidate_reader, bindings, mutations, users):
            nonlocal injected
            if not injected:
                injected = True
                first = workspace.commit(Transaction(RootRef(0), (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))
                self.assertTrue(first.committed)
                current = workspace.function_nodes(first.changed_entity, 3).entities[2]
                second = workspace.commit(Transaction(RootRef(1), (SetOperation(current.handle, Operation.MUL_WRAP, Operation.ADD_WRAP),)))
                self.assertTrue(second.committed)
                self.assertEqual(second.root, reader.root_cid)
                self.assertEqual(workspace.generation, 2)
            return original_candidate(candidate_reader, bindings, mutations, users)

        with patch("xax_workspace._candidate", side_effect=candidate_with_aba):
            result = workspace.commit(transaction)

        self.assertFalse(result.committed)
        self.assertEqual(result.root, reader.root_cid)
        self.assertEqual(workspace.generation, 2)
        self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.WORKSPACE.STALE_ROOT", "WORKSPACE-ATOMIC-COMPARE"))
        self.assertEqual((result.diagnostic.expected, result.diagnostic.actual), ("R0.0", "R0.2"))

    def test_proof_query_reports_verified_status_without_artifact(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        before_proof = workspace.accounting.query_bytes
        proof = workspace.proof(node.handle)
        after_proof = workspace.accounting.query_bytes
        root_proof = workspace.proof("R0")

        self.assertEqual(proof.handle, node.handle)
        self.assertEqual(proof.dependency_handle, "P0.0")
        self.assertEqual(root_proof.dependency_handle, "P1.0")
        binding = workspace._proof_bindings[proof.dependency_handle]
        self.assertEqual(binding.observed_root, reader.root_cid)
        self.assertEqual((binding.subject_kind, binding.subject_cid, binding.block_index, binding.node_index), ("node", entry.cid, 0, 2))
        self.assertEqual(
            proof.facts,
            (
                ("root", "R0.0", "authoritative"),
                ("verified", True, "authoritative"),
                ("verifier", "bootstrap-schema-1", "authoritative"),
                ("freshness", "subject+verifier", "authoritative"),
                ("proof_dependency", "P0.0", "derived"),
                ("proof_artifact", None, "unavailable"),
            ),
        )
        self.assertEqual(dict((name, value) for name, value, _ in root_proof.facts)["freshness"], "root+verifier")
        self.assertEqual(after_proof - before_proof, _query_size(proof))
        self.assertEqual(workspace.accounting.query_bytes - after_proof, _query_size(root_proof))
        exposed = (proof.handle, proof.dependency_handle, root_proof.handle, root_proof.dependency_handle) + tuple(
            value for _, value, _ in (*proof.facts, *root_proof.facts) if isinstance(value, str)
        )
        self.assertFalse(any(len(value) == 64 for value in exposed))

        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.proof(node.handle)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")
        self.assertTrue(dict((name, value) for name, value, _ in workspace.proof("R0").facts)["verified"])

    def test_current_proof_dependency_can_guard_transaction_and_then_invalidates_if_subject_changes(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        proof = workspace.proof(node.handle)
        transaction = Transaction(
            RootRef(0),
            (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
            (proof.dependency_handle,),
        )

        committed = workspace.commit(transaction)
        self.assertTrue(committed.committed)
        self.assertEqual(execute(workspace.reader, committed.changed_entity, ()), (6,))

        current = workspace.function_nodes(committed.changed_entity, 3).entities[2]
        conflict = workspace.commit(
            Transaction(
                RootRef(1),
                (SetOperation(current.handle, Operation.MUL_WRAP, Operation.SUB_WRAP),),
                (proof.dependency_handle,),
            )
        )
        self.assertFalse(conflict.committed)
        self.assertEqual(
            (conflict.diagnostic.code, conflict.diagnostic.rule),
            ("XAX.WORKSPACE.PROOF_CONFLICT", "WORKSPACE-PROOF-DEPENDENCY"),
        )
        self.assertEqual(workspace.generation, 1)

    def test_proof_dependency_survives_only_independent_compatible_commit(self):
        reader, functions = disjoint_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
        proof = workspace.proof(nodes[0].handle)

        first = workspace.commit(
            Transaction(RootRef(0), (SetConstant(nodes[1].handle, nodes[1].constant_value, 5),))
        )
        self.assertTrue(first.committed)

        stale_root = workspace.commit(
            Transaction(
                RootRef(0),
                (SetConstant(nodes[0].handle, nodes[0].constant_value, 4),),
                (proof.dependency_handle,),
            )
        )
        self.assertFalse(stale_root.committed)
        self.assertEqual(stale_root.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")

        preserved_node = workspace.function_nodes(functions[0].cid, 1).entities[0]
        second = workspace.commit(
            Transaction(
                RootRef(1),
                (SetConstant(preserved_node.handle, preserved_node.constant_value, 4),),
                (proof.dependency_handle,),
            )
        )
        self.assertTrue(second.committed)
        self.assertEqual(
            {execute(workspace.reader, obj.cid, ()) for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION},
            {(4,), (5,)},
        )

    def test_root_and_verifier_proof_dependencies_have_distinct_conflicts(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        root_proof = workspace.proof("R0")
        node_proof = workspace.proof(nodes[0].handle)

        first = workspace.commit(
            Transaction(RootRef(0), (SetConstant(nodes[1].handle, nodes[1].constant_value, 7),))
        )
        self.assertTrue(first.committed)
        current_nodes = workspace.function_nodes(first.changed_entity, 3).entities
        root_conflict = workspace.commit(
            Transaction(
                RootRef(1),
                (SetConstant(current_nodes[1].handle, current_nodes[1].constant_value, 8),),
                (root_proof.dependency_handle,),
            )
        )
        self.assertFalse(root_conflict.committed)
        self.assertEqual(root_conflict.diagnostic.code, "XAX.WORKSPACE.PROOF_CONFLICT")

        # The subject of node_proof also changed because both constants are in the same function.
        node_conflict = workspace.commit(
            Transaction(
                RootRef(1),
                (SetConstant(current_nodes[1].handle, current_nodes[1].constant_value, 8),),
                (node_proof.dependency_handle,),
            )
        )
        self.assertFalse(node_conflict.committed)
        self.assertEqual(node_conflict.diagnostic.code, "XAX.WORKSPACE.PROOF_CONFLICT")

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[0]
        verifier_proof = workspace.proof(node.handle)
        workspace._verifier_identity = "bootstrap-schema-test-v2"
        verifier_conflict = workspace.commit(
            Transaction(
                RootRef(0),
                (SetConstant(node.handle, node.constant_value, 4),),
                (verifier_proof.dependency_handle,),
            )
        )
        self.assertFalse(verifier_conflict.committed)
        self.assertEqual(
            (verifier_conflict.diagnostic.code, verifier_conflict.diagnostic.rule),
            ("XAX.WORKSPACE.PROOF_CONFLICT", "WORKSPACE-PROOF-DEPENDENCY"),
        )
        self.assertEqual(workspace.root, reader.root_cid)

    def test_proof_dependency_rejects_raw_root_aba_at_final_atomic_compare(self):
        import xax_workspace as workspace_module

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        proof = workspace.proof(node.handle)
        transaction = Transaction(
            reader.root_cid,
            (SetOperation(node.handle, Operation.ADD_WRAP, Operation.SUB_WRAP),),
            (proof.dependency_handle,),
        )
        original_candidate = workspace_module._candidate
        injected = False

        def candidate_with_aba(candidate_reader, bindings, mutations, users):
            nonlocal injected
            if not injected:
                injected = True
                first = workspace.commit(
                    Transaction(RootRef(0), (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
                )
                self.assertTrue(first.committed)
                current = workspace.function_nodes(first.changed_entity, 3).entities[2]
                second = workspace.commit(
                    Transaction(RootRef(1), (SetOperation(current.handle, Operation.MUL_WRAP, Operation.ADD_WRAP),))
                )
                self.assertTrue(second.committed)
                self.assertEqual(second.root, reader.root_cid)
            return original_candidate(candidate_reader, bindings, mutations, users)

        with patch("xax_workspace._candidate", side_effect=candidate_with_aba):
            result = workspace.commit(transaction)

        self.assertFalse(result.committed)
        self.assertEqual(result.root, reader.root_cid)
        self.assertEqual(workspace.generation, 2)
        self.assertEqual(
            (result.diagnostic.code, result.diagnostic.rule),
            ("XAX.WORKSPACE.PROOF_CONFLICT", "WORKSPACE-PROOF-DEPENDENCY"),
        )
        self.assertEqual(execute(workspace.reader, entry.cid, ()), (5,))

    def test_proof_dependency_accounting_is_exact_and_deterministic(self):
        def run_once():
            reader, entry = workspace_fixture()
            workspace = Workspace(reader)
            node = workspace.function_nodes(entry.cid, 3).entities[2]
            before_query = workspace.accounting.query_bytes
            proof = workspace.proof(node.handle)
            proof_bytes = workspace.accounting.query_bytes - before_query
            transaction = Transaction(
                RootRef(0),
                (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
                (proof.dependency_handle,),
            )
            result = workspace.commit(transaction)
            return proof, proof_bytes, result.transaction_bytes, result

        first = run_once()
        second = run_once()
        self.assertEqual(first[:3], second[:3])
        self.assertEqual(first[1], _query_size(first[0]))
        self.assertTrue(first[3].committed)
        self.assertGreater(first[1], 0)
        self.assertGreater(first[2], 0)


    def test_cost_query_reports_support_without_inventing_numbers(self):
        reader, entry = workspace_fixture()
        target = x86_64_windows_target()
        workspace = Workspace(reader, target)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        before_cost = workspace.accounting.query_bytes
        cost = workspace.cost(node.handle)

        self.assertEqual(cost.target, target.cid.hex())
        self.assertEqual(workspace.accounting.query_bytes - before_cost, 293)
        self.assertEqual(
            cost.facts,
            (
                ("operation", "add_wrap", "authoritative"),
                ("supported", True, "authoritative"),
                ("instruction_cost", None, "unavailable"),
                ("latency", None, "unavailable"),
                ("code_bytes", None, "unavailable"),
            ),
        )

        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        before_cost = workspace.accounting.query_bytes
        self.assertEqual(workspace.cost(node.handle).facts[1], ("supported", None, "unavailable"))
        self.assertEqual(workspace.accounting.query_bytes - before_cost, 229)
        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.cost(node.handle)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_atomic_realtime_and_handler_queries_are_target_qualified(self):
        reader, entry, target = atomic_workspace_fixture()
        workspace = Workspace(reader, target)
        nodes = workspace.function_nodes(entry.cid, 4).entities
        capability = workspace.atomic_capability(nodes[1].handle)
        self.assertEqual(capability.target, target.cid.hex())
        self.assertEqual(dict((name, value) for name, value, _ in capability.facts)["support"], "native")
        realtime = workspace.realtime(nodes[1].handle, RealtimeProfile())
        facts = {name: value for name, value, _ in realtime.facts}
        self.assertEqual((facts["may_block"], facts["stack_upper_bound"], facts["progress"]), (False, 4, "wait_free"))
        self.assertEqual(facts["runtime_assists"], ())
        handler = workspace.handler_entry(1)
        handler_facts = {name: value for name, value, _ in handler.facts}
        self.assertEqual(handler_facts["allowed_effect_domains"], ("memory", "atomic"))
        self.assertEqual(handler_facts["stack_bound"], 4096)

        unbound = Workspace(reader)
        node = unbound.function_nodes(entry.cid, 2).entities[1]
        self.assertEqual(unbound.atomic_capability(node.handle).facts[0], ("support", None, "unavailable"))
        with self.assertRaisesRegex(XaxError, "XAX.WORKSPACE.HANDLER"):
            unbound.handler_entry(1)

    def test_layout_query_is_target_qualified_and_stale_checked(self):
        reader, entry = type_fixture()
        layouts = []
        for target, pointer_bytes in ((x86_64_windows_target(), 8), (wasm32_target(), 4)):
            workspace = Workspace(reader, target)
            allocation = workspace.function_nodes(entry.cid, 1).entities[0]
            pointer = workspace.neighborhood(allocation.handle, 1).entities[0]
            before_layout = workspace.accounting.query_bytes
            layout = workspace.layout(pointer.type_handle)

            self.assertEqual(layout.target, target.cid.hex())
            self.assertEqual(layout.classification, "derived")
            self.assertEqual(dict(layout.facts), {"size_bits": pointer_bytes * 8, "size_bytes": pointer_bytes, "alignment_bytes": pointer_bytes})
            self.assertEqual(workspace.accounting.query_bytes - before_layout, 189)
            self.assertEqual(workspace.root_query().contexts[0], ("target", target.cid.hex(), "authoritative"))
            layouts.append(layout)
        self.assertNotEqual(layouts[0].facts, layouts[1].facts)

        workspace = Workspace(reader)
        allocation = workspace.function_nodes(entry.cid, 1).entities[0]
        pointer = workspace.neighborhood(allocation.handle, 1).entities[0]
        before_layout = workspace.accounting.query_bytes
        self.assertEqual(workspace.layout(pointer.type_handle).classification, "unavailable")
        self.assertEqual(workspace.accounting.query_bytes - before_layout, 76)

        reader, entry = workspace_fixture()
        workspace = Workspace(reader, x86_64_windows_target())
        add = workspace.function_nodes(entry.cid, 3).entities[2]
        bits = workspace.operands(add.handle, 1).entities[0]
        self.assertEqual(dict(workspace.layout(bits.type_handle).facts), {"size_bits": 8, "size_bytes": 1, "alignment_bytes": 1})
        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(add.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.layout(bits.type_handle)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_root_query_tracks_generation_and_unavailable_context(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)

        first = workspace.root_query()
        first_bytes = workspace.accounting.query_bytes
        node = workspace.function_nodes(entry.cid, 1).entities[0]
        after_node_bytes = workspace.accounting.query_bytes
        result = workspace.commit(Transaction(reader.root_cid, (SetConstant(node.handle, 2, 9),)))
        second = workspace.root_query()

        self.assertTrue(result.committed)
        self.assertEqual((first.handle, first.root, first.generation), ("R0", reader.root_cid.hex(), 0))
        self.assertEqual((second.handle, second.root, second.generation), ("R0", result.root.hex(), 1))
        self.assertNotEqual(first.root, second.root)
        self.assertEqual(first.contexts, (("target", None, "unavailable"), ("platform", None, "unavailable"), ("configuration", None, "unavailable")))
        self.assertEqual(second.contexts, first.contexts)
        self.assertEqual(first_bytes, 249)
        self.assertEqual(workspace.accounting.query_bytes - after_node_bytes, 249)

    def test_query_is_bounded_and_exposes_literal(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)

        first = workspace.function_nodes(entry.cid, 1)
        second = workspace.function_nodes(entry.cid, 2, first.continuation)

        self.assertEqual((first.entities[0].handle, first.entities[0].constant_value), ("F0.B0.N0", 2))
        self.assertTrue(first.truncated)
        self.assertEqual([entity.operation for entity in second.entities], [Operation.CONSTANT, Operation.ADD_WRAP])
        self.assertFalse(second.truncated)
        self.assertEqual(workspace.accounting.queries, 2)
        self.assertEqual(workspace.accounting.entities_exposed, 3)
        self.assertEqual(workspace.accounting.query_bytes, 472)

    def test_response_byte_budget_exact_boundary_and_one_byte_over_rejection(self):
        reader, entry = workspace_fixture()
        baseline = Workspace(reader).function_nodes(entry.cid, 1)
        size = _query_size(baseline)

        exact = Workspace(reader)
        self.assertEqual(exact.function_nodes(entry.cid, 1, byte_budget=size), baseline)
        self.assertEqual((exact.accounting.queries, exact.accounting.entities_exposed, exact.accounting.query_bytes), (1, 1, size))

        rejected = Workspace(reader)
        for _ in range(2):
            with self.assertRaises(XaxError) as caught:
                rejected.function_nodes(entry.cid, 1, byte_budget=size - 1)
            self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.RESPONSE_BUDGET")
            self.assertEqual(caught.exception.diagnostic.rule, "WORKSPACE-RESPONSE-BYTES")
            self.assertEqual(caught.exception.diagnostic.expected, {"at_most": size - 1})
            self.assertEqual(caught.exception.diagnostic.actual, {"required": size})
        self.assertEqual((rejected.accounting.queries, rejected.accounting.entities_exposed, rejected.accounting.query_bytes), (0, 0, 0))
        with self.assertRaises(XaxError) as caught:
            rejected.entity("F0.B0.N0")
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_response_byte_budget_paginates_with_positive_progress_and_exact_accounting(self):
        reader, entry = workspace_fixture()
        single_size = max(_query_size(Workspace(reader).function_nodes(entry.cid, 1, continuation)) for continuation in range(3))
        workspace = Workspace(reader)
        pages = []
        continuation = 0
        first = workspace.function_nodes(entry.cid, 3, continuation, byte_budget=single_size)
        pages.append(first)
        with self.assertRaises(XaxError) as caught:
            workspace.entity("F0.B0.N1")
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")
        continuation = first.continuation
        while continuation is not None:
            page = workspace.function_nodes(entry.cid, 3, continuation, byte_budget=single_size)
            pages.append(page)
            continuation = page.continuation

        self.assertEqual([len(page.entities) for page in pages], [1, 1, 1])
        self.assertEqual([page.continuation for page in pages], [1, 2, None])
        self.assertEqual([entity.handle for page in pages for entity in page.entities], ["F0.B0.N0", "F0.B0.N1", "F0.B0.N2"])
        self.assertTrue(all(_query_size(page) <= single_size for page in pages))
        self.assertEqual(workspace.accounting.queries, 3)
        self.assertEqual(workspace.accounting.entities_exposed, 3)
        self.assertEqual(workspace.accounting.query_bytes, sum(_query_size(page) for page in pages))

    def test_response_byte_budget_nonpaged_boundary_and_default_behavior(self):
        reader, _ = workspace_fixture()
        unbounded = Workspace(reader)
        expected = unbounded.root_query()
        size = _query_size(expected)

        bounded = Workspace(reader)
        self.assertEqual(bounded.root_query(byte_budget=size), expected)
        self.assertEqual(bounded.accounting.query_bytes, size)

        rejected = Workspace(reader)
        with self.assertRaises(XaxError) as caught:
            rejected.root_query(byte_budget=size - 1)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.RESPONSE_BUDGET")
        self.assertEqual((rejected.accounting.queries, rejected.accounting.query_bytes), (0, 0))
        with self.assertRaises(ValueError):
            rejected.root_query(byte_budget=0)

    def test_users_query_is_bounded_and_deterministic(self):
        reader, entry = workspace_fixture()
        workspaces = (Workspace(reader), Workspace(reader))
        handles = []
        for workspace in workspaces:
            entry_users = workspace.users(entry.cid, 1)
            b8 = next(obj for obj in reader.objects() if obj.kind == Kind.TYPE)
            first = workspace.users(b8.cid, 2)
            second = workspace.users(b8.cid, 8, first.continuation)

            self.assertEqual([entity.kind for entity in entry_users.entities], [Kind.MODULE])
            self.assertTrue(first.truncated)
            self.assertFalse(second.truncated)
            self.assertGreater(len(first.entities) + len(second.entities), 2)
            handles.append(entry_users.entities[0].handle)
        self.assertEqual(handles[0], handles[1])

    def test_invalidate_query_is_transitive_bounded_and_stale_checked(self):
        reader, leaves = shared_caller_fixture()
        pages = []
        for workspace in (Workspace(reader), Workspace(reader)):
            caller = next(
                item
                for item in reader.objects()
                if item.kind == Kind.FUNCTION and len(workspace.function_nodes(item.cid, 10).entities) == 3
            )
            leaf_handle = workspace.callees(caller.cid, 1).entities[0].handle
            first = workspace.invalidate(leaf_handle, 2)
            second = workspace.invalidate(leaf_handle, 2, first.continuation)
            entities = (*first.entities, *second.entities)

            self.assertTrue(first.truncated)
            self.assertFalse(second.truncated)
            self.assertEqual({entity.kind for entity in entities}, {Kind.GRAPH_FRAGMENT, Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT})
            self.assertTrue(all(not hasattr(entity, "cid") for entity in entities))
            self.assertIsInstance(workspace.invalidate(entities[0].handle, 1), type(first))
            pages.append(entities)
        self.assertEqual(pages[0], pages[1])

        workspace = Workspace(reader)
        caller = next(
            item
            for item in reader.objects()
            if item.kind == Kind.FUNCTION and len(workspace.function_nodes(item.cid, 10).entities) == 3
        )
        leaf_handle = workspace.callees(caller.cid, 1).entities[0].handle
        node = workspace.function_nodes(leaves[0].cid, 1).entities[0]
        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, node.operation, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.invalidate(leaf_handle, 1)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_diff_query_is_bounded_deterministic_and_multi_generation(self):
        reader, entry = workspace_fixture()
        snapshots = []
        for workspace in (Workspace(reader), Workspace(reader)):
            node = workspace.function_nodes(entry.cid, 3).entities[2]
            result = workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))
            entities = []
            continuation = 0
            while continuation is not None:
                page = workspace.diff(0, 3, continuation)
                entities.extend(page.entities)
                continuation = page.continuation

            self.assertEqual([entity.change for entity in entities], ["removed"] * 4 + ["added"] * 4)
            self.assertEqual(
                {entity.kind for entity in entities},
                {Kind.GRAPH_FRAGMENT, Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT},
            )
            self.assertTrue(all(not hasattr(entity, "cid") for entity in entities))
            snapshots.append(tuple(entities))

            current = workspace.function_nodes(result.changed_entity, 3).entities[2]
            second = workspace.commit(Transaction(result.root, (SetOperation(current.handle, Operation.MUL_WRAP, Operation.SUB_WRAP),)))
            self.assertTrue(workspace.diff(0, 1).entities)
            self.assertTrue(workspace.diff(1, 1).entities)
            self.assertTrue(second.committed)
        self.assertEqual(snapshots[0], snapshots[1])

    def test_call_queries_are_bounded_local_and_deterministic(self):
        reader, leaves = shared_caller_fixture()
        handles = []
        for workspace in (Workspace(reader), Workspace(reader)):
            caller = next(
                item
                for item in reader.objects()
                if item.kind == Kind.FUNCTION and len(workspace.function_nodes(item.cid, 10).entities) == 3
            )
            first = workspace.callees(caller.cid, 1)
            second = workspace.callees(caller.cid, 1, first.continuation)
            leaf_caller = workspace.callers(leaves[0].cid, 1)

            self.assertTrue(first.truncated)
            self.assertFalse(second.truncated)
            self.assertEqual(len(leaf_caller.entities), 1)
            self.assertFalse(hasattr(first.entities[0], "cid"))
            handles.append(tuple(entity.handle for entity in (*first.entities, *second.entities)))
        self.assertEqual(handles[0], handles[1])

    def test_operands_query_uses_local_value_and_type_handles(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]

        first = workspace.operands(node.handle, 1)
        second = workspace.operands(node.handle, 1, first.continuation)

        self.assertTrue(first.truncated)
        self.assertFalse(second.truncated)
        self.assertEqual(first.entities[0].handle, "F0.B0.N0.R0")
        self.assertEqual(second.entities[0].handle, "F0.B0.N1.R0")
        self.assertEqual(first.entities[0].type_handle, second.entities[0].type_handle)
        self.assertFalse(hasattr(first.entities[0], "cid"))
        self.assertEqual(workspace.type(first.entities[0].type_handle).form, "bits")

        result = workspace.commit(
            Transaction(
                reader.root_cid,
                (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
                (node.handle, first.entities[0].handle, first.entities[0].type_handle),
            )
        )
        self.assertTrue(result.committed)
        with self.assertRaises(XaxError) as caught:
            workspace.operands(node.handle, 1)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")
        with self.assertRaises(XaxError) as caught:
            workspace.type(first.entities[0].type_handle)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_neighborhood_query_is_bounded_local_and_stale_checked(self):
        reader, entry = type_fixture()
        pages = []
        for workspace in (Workspace(reader), Workspace(reader)):
            store = workspace.function_nodes(entry.cid, 4).entities[1]
            first = workspace.neighborhood(store.handle, 3)
            second = workspace.neighborhood(store.handle, 3, first.continuation)
            entities = (*first.entities, *second.entities)

            self.assertTrue(first.truncated)
            self.assertFalse(second.truncated)
            self.assertEqual(
                [(entity.handle, entity.relations) for entity in entities],
                [
                    ("F0.B0.N0.R0", ("operand",)),
                    ("F0.B0.P0", ("operand",)),
                    ("F0.B0.N0.R2", ("operand", "effect_input")),
                    ("F0.B0.N1.R0", ("result", "effect_output")),
                ],
            )
            self.assertTrue(all(not hasattr(entity, "cid") for entity in entities))
            self.assertEqual(workspace.type(entities[-1].type_handle).form, "effect")
            pages.append(entities)
        self.assertEqual(pages[0], pages[1])

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.neighborhood(node.handle, 1)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_expand_query_finds_value_producer_and_users(self):
        reader, entry = workspace_fixture()
        handles = []
        for workspace in (Workspace(reader), Workspace(reader)):
            add = workspace.function_nodes(entry.cid, 3).entities[2]
            value = workspace.operands(add.handle, 1).entities[0]
            producer = workspace.expand(value.handle, "producer", 1)
            users = workspace.expand(value.handle, "users", 1)

            self.assertEqual([(node.handle, node.operation) for node in producer.entities], [("F0.B0.N0", Operation.CONSTANT)])
            self.assertEqual([(node.handle, node.operation) for node in users.entities], [("F0.B0.N2", Operation.ADD_WRAP)])
            self.assertFalse(producer.truncated)
            self.assertFalse(users.truncated)
            self.assertFalse(hasattr(producer.entities[0], "cid"))
            handles.append((producer.entities, users.entities))
        self.assertEqual(handles[0], handles[1])

        reader, entry = type_fixture()
        workspace = Workspace(reader)
        allocation = workspace.function_nodes(entry.cid, 1).entities[0]
        pointer = workspace.neighborhood(allocation.handle, 1).entities[0]
        first = workspace.expand(pointer.handle, "users", 1)
        second = workspace.expand(pointer.handle, "users", 1, first.continuation)
        self.assertTrue(first.truncated)
        self.assertFalse(second.truncated)
        self.assertEqual([first.entities[0].handle, second.entities[0].handle], ["F0.B0.N1", "F0.B0.N2"])

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        add = workspace.function_nodes(entry.cid, 3).entities[2]
        value = workspace.operands(add.handle, 1).entities[0]
        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(add.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.expand(value.handle, "users", 1)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_expand_query_is_depth_bounded_breadth_first(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        add = workspace.function_nodes(entry.cid, 3).entities[2]
        result = workspace.neighborhood(add.handle, 3).entities[2]

        first = workspace.expand(result.handle, "producer", 2, depth=3)
        second = workspace.expand(result.handle, "producer", 2, first.continuation, depth=3)
        third = workspace.expand(result.handle, "producer", 2, second.continuation, depth=3)
        entities = (*first.entities, *second.entities, *third.entities)

        self.assertEqual(
            [(entity.kind, entity.handle, entity.relation) for entity in entities],
            [
                ("node", "F0.B0.N2", "producer"),
                ("value", "F0.B0.N0.R0", "operand"),
                ("value", "F0.B0.N1.R0", "operand"),
                ("node", "F0.B0.N0", "producer"),
                ("node", "F0.B0.N1", "producer"),
            ],
        )
        self.assertTrue(first.truncated)
        self.assertTrue(second.truncated)
        self.assertFalse(third.truncated)
        self.assertEqual(workspace.type(entities[1].type_handle).form, "bits")
        self.assertTrue(all(not hasattr(entity, "cid") for entity in entities))
        with self.assertRaises(ValueError):
            workspace.expand(result.handle, "producer", 1, depth=0)

    def test_type_query_covers_implemented_forms(self):
        reader, entry = type_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 4).entities
        store_operands = workspace.operands(nodes[1].handle, 3).entities
        end_operands = workspace.operands(nodes[3].handle, 2).entities

        pointer = workspace.type(store_operands[0].type_handle)
        bits = workspace.type(store_operands[1].type_handle)
        effect = workspace.type(store_operands[2].type_handle)
        resource = workspace.type(end_operands[0].type_handle)

        self.assertEqual(dict(pointer.facts), {"space": "stack", "element": bits.handle, "permission": "read_write", "alignment": 4})
        self.assertEqual((bits.form, dict(bits.facts)), ("bits", {"width": 32}))
        self.assertEqual((effect.form, dict(effect.facts)), ("effect", {"domain": "memory", "instance": 0}))
        self.assertEqual(
            (resource.form, dict(resource.facts)),
            ("resource", {"kind": "stack-storage", "state": "live", "flags": 4, "instance": 0, "transitions": ()}),
        )
        self.assertFalse(hasattr(pointer, "cid"))

    def test_effects_query_exposes_memory_frontiers_and_pure_nodes(self):
        reader, entry = type_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 4).entities
        allocation, store, load, end = (workspace.effects(node.handle) for node in nodes)

        self.assertEqual((allocation.pure, allocation.domain, allocation.inputs), (False, "memory", ()))
        self.assertEqual([value.handle for value in allocation.outputs], ["F0.B0.N0.R2"])
        self.assertEqual([value.handle for value in store.inputs], ["F0.B0.N0.R2"])
        self.assertEqual([value.handle for value in store.outputs], ["F0.B0.N1.R0"])
        self.assertEqual([value.handle for value in load.inputs], ["F0.B0.N1.R0"])
        self.assertEqual([value.handle for value in load.outputs], ["F0.B0.N2.R1"])
        self.assertEqual([value.handle for value in end.inputs], ["F0.B0.N2.R1"])
        self.assertEqual(end.outputs, ())
        self.assertEqual(workspace.type(store.inputs[0].type_handle).form, "effect")
        rejected = workspace.commit(Transaction(reader.root_cid, (), (load.outputs[0].handle,)))
        self.assertEqual(rejected.diagnostic.code, "XAX.WORKSPACE.EMPTY_TRANSACTION")

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        pure = workspace.effects(node.handle)
        self.assertEqual((pure.pure, pure.domain, pure.inputs, pure.outputs), (True, None, (), ()))
        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.effects(node.handle)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_generic_resource_effect_queries_and_summary(self):
        reader, entry = resource_workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 2).entities
        acquire = workspace.effects(nodes[0].handle)
        operands = workspace.operands(nodes[1].handle, 2).entities
        resource = workspace.type(operands[0].type_handle)
        effect = workspace.type(operands[1].type_handle)
        summary = workspace.effect_summary(nodes[0].handle)

        self.assertEqual((acquire.pure, acquire.domain), (False, "filesystem"))
        self.assertEqual(dict(effect.facts), {"domain": "filesystem", "instance": 4})
        self.assertEqual(dict(resource.facts), {"kind": 2, "state": 1, "flags": 12, "instance": 0, "transitions": ()})
        self.assertEqual(summary.domains, (("filesystem", 4),))
        self.assertTrue(summary.may_return)
        self.assertFalse(summary.may_trap)

    def test_entity_query_covers_bound_handle_kinds_without_cids(self):
        reader, leaves = shared_caller_fixture()
        workspace = Workspace(reader)
        with self.assertRaises(XaxError) as caught:
            workspace.entity("F0")
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

        caller = next(item for item in reader.objects() if item.kind == Kind.FUNCTION and len(workspace.function_nodes(item.cid, 10).entities) == 3)
        function_handle = workspace.callers(leaves[0].cid, 1).entities[0].handle
        object_handle = workspace.users(caller.cid, 1).entities[0].handle
        nodes = workspace.function_nodes(caller.cid, 3).entities
        value = workspace.operands(nodes[2].handle, 1).entities[0]
        views = (
            workspace.entity(function_handle),
            workspace.entity(object_handle),
            workspace.entity(nodes[2].handle),
            workspace.entity(value.handle),
            workspace.entity(value.type_handle),
        )

        self.assertEqual([view.kind for view in views], ["function", "module", "node", "value", "type"])
        self.assertEqual(dict(views[0].facts), {"parameters": 2, "returns": 1})
        self.assertEqual(dict(views[2].facts), {"operation": "add_wrap", "operands": 2, "results": 1})
        self.assertEqual(dict(views[3].facts), {"type": value.type_handle})
        self.assertEqual(dict(views[4].facts), {"form": "bits"})
        self.assertTrue(all(not hasattr(view, "cid") for view in views))

        leaf_node = workspace.function_nodes(leaves[0].cid, 1).entities[0]
        self.assertTrue(workspace.commit(Transaction(reader.root_cid, (SetOperation(leaf_node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))).committed)
        with self.assertRaises(XaxError) as caught:
            workspace.entity(function_handle)
        self.assertEqual(caught.exception.diagnostic.code, "XAX.WORKSPACE.HANDLE")

    def test_insert_pure_constant_remaps_later_nodes_and_terminator_deterministically(self):
        reader, entry = workspace_fixture()
        results = []
        for workspace in (Workspace(reader), Workspace(reader)):
            nodes = workspace.function_nodes(entry.cid, 3).entities
            type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
            mutation = InsertPureNode(nodes[1].handle, 0, 1, 7, Operation.CONSTANT, (), type_handle, 9)

            result = workspace.commit(Transaction(RootRef(0), (mutation,)))

            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, ()), (5,))
            current = workspace.function_nodes(result.changed_entity, 4).entities
            self.assertEqual([node.operation for node in current], [Operation.CONSTANT, Operation.CONSTANT, Operation.CONSTANT, Operation.ADD_WRAP])
            self.assertEqual([node.constant_value for node in current[:3]], [2, 9, 3])
            operands = workspace.operands(current[3].handle, 2).entities
            self.assertEqual([value.handle for value in operands], ["F0.B0.N0.R0", "F0.B0.N2.R0"])
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)
        self.assertEqual(results[0].transaction_bytes, results[1].transaction_bytes)

    def test_inserted_compare_and_extension_with_a_new_bits_type(self):
        """ADR-255: a compare produces ``bits<1>``, which the store need not hold yet; its extension feeds the add."""
        from xax_compiler import IntCompare

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        value = lambda index: ValueRef.node_result(0, index)  # noqa: E731
        inserted = workspace.commit(Transaction(RootRef(0), (
            InsertPureNode(nodes[2].handle, 0, 2, 0, Operation.INT_COMPARE, (value(0), value(1)), "bits<1>", attributes=(int(IntCompare.ULT),)),
        )))
        self.assertTrue(inserted.committed, inserted.diagnostic)
        nodes = workspace.function_nodes(inserted.changed_entity, 4).entities
        self.assertEqual([node.operation for node in nodes], [Operation.CONSTANT, Operation.CONSTANT, Operation.INT_COMPARE, Operation.ADD_WRAP])
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle  # handles are per generation
        extended = workspace.commit(Transaction(RootRef(1), (
            InsertPureNode(nodes[3].handle, 0, 3, 0, Operation.INT_ZERO_EXTEND, (value(2),), type_handle),
        )))
        self.assertTrue(extended.committed, extended.diagnostic)
        nodes = workspace.function_nodes(extended.changed_entity, 5).entities
        replaced = workspace.commit(Transaction(RootRef(2), (ReplaceUse(nodes[4].handle, 1, value(1), value(3)),)))
        self.assertTrue(replaced.committed, replaced.diagnostic)
        self.assertEqual(execute(workspace.reader, replaced.changed_entity, ()), (3,))  # 2 + (2 < 3)
        first = workspace.function_nodes(replaced.changed_entity, 1).entities[0]
        type_handle = workspace.neighborhood(first.handle, 1).entities[0].type_handle
        rejected = workspace.commit(Transaction(RootRef(3), (
            InsertPureNode(first.handle, 0, 0, 0, Operation.UDIV, (value(0), value(1)), type_handle),
        )))
        self.assertFalse(rejected.committed)
        self.assertEqual(rejected.diagnostic.rule, "WORKSPACE-INSERT-PURE-NODE")

    def test_inserted_result_is_transaction_local_and_can_feed_later_mutation(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        transaction = Transaction(
            RootRef(0),
            (
                InsertPureNode(nodes[1].handle, 0, 1, 4, Operation.CONSTANT, (), type_handle, 9),
                ReplaceUse(nodes[2].handle, 0, ValueRef.node_result(0, 0), TransactionValueRef(4)),
            ),
        )

        result = workspace.commit(transaction)

        self.assertTrue(result.committed)
        self.assertEqual(execute(workspace.reader, result.changed_entity, ()), (12,))
        current = workspace.function_nodes(result.changed_entity, 4).entities
        operands = workspace.operands(current[3].handle, 2).entities
        self.assertEqual([value.handle for value in operands], ["F0.B0.N1.R0", "F0.B0.N2.R0"])
        self.assertFalse(any(handle.startswith("I4") for handle in workspace._value_bindings))

    def test_insert_position_conflict_and_verifier_rejection_are_atomic(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        original_root = workspace.root

        conflict = workspace.commit(
            Transaction(RootRef(0), (InsertPureNode(nodes[1].handle, 0, 0, 0, Operation.CONSTANT, (), type_handle, 9),))
        )
        invalid = workspace.commit(
            Transaction(
                RootRef(0),
                (
                    InsertPureNode(
                        nodes[1].handle,
                        0,
                        1,
                        1,
                        Operation.ADD_WRAP,
                        (ValueRef.node_result(0, 2), ValueRef.node_result(0, 0)),
                        type_handle,
                    ),
                ),
            )
        )

        self.assertFalse(conflict.committed)
        self.assertEqual((conflict.diagnostic.code, conflict.diagnostic.rule), ("XAX.WORKSPACE.CONTAINMENT_CONFLICT", "WORKSPACE-INSERT-POSITION"))
        self.assertFalse(invalid.committed)
        self.assertEqual((invalid.diagnostic.code, invalid.diagnostic.rule), ("XAX.STRUCT.SSA_DOMINANCE", "GRAPH-SSA-DOMINANCE"))
        self.assertEqual(workspace.root, original_root)

    def test_insert_rejects_stale_root_and_read_set_and_rebuilds_callers(self):
        reader, arithmetic = caller_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(arithmetic.cid, 1).entities[0]
        type_handle = workspace.neighborhood(node.handle, 3).entities[-1].type_handle
        stale_read = workspace.users(arithmetic.cid, 1).entities[0].handle
        mutation = InsertPureNode(node.handle, 0, 0, 2, Operation.CONSTANT, (), type_handle, 11)

        stale = workspace.commit(Transaction(bytes(32), (mutation,)))
        read_conflict = workspace.commit(Transaction(RootRef(0), (mutation,), ("E999",)))
        committed = workspace.commit(Transaction(RootRef(0), (mutation,), (stale_read,)))

        self.assertFalse(stale.committed)
        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertFalse(read_conflict.committed)
        self.assertEqual(read_conflict.diagnostic.code, "XAX.WORKSPACE.READ_CONFLICT")
        self.assertTrue(committed.committed)
        self.assertEqual(execute(workspace.reader, committed.changed_entity, (2, 3)), (5,))
        callers = workspace.callers(committed.changed_entity, 2).entities
        self.assertEqual(len(callers), 1)
        caller_cid = workspace._function_bindings[callers[0].handle][0]
        self.assertEqual(execute(workspace.reader, caller_cid, (2, 3)), (7,))
        self.assertGreater(committed.reused_objects, 0)

    def test_insert_transaction_accounting_is_exact_and_duplicate_local_ids_reject(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        mutation = InsertPureNode(nodes[1].handle, 0, 1, 3, Operation.CONSTANT, (), type_handle, 9)
        transaction = Transaction(RootRef(0), (mutation,))

        result = workspace.commit(transaction)

        self.assertTrue(result.committed)
        self.assertEqual(result.transaction_bytes, workspace.accounting.transaction_bytes)
        self.assertGreater(result.touched_objects, 0)
        self.assertGreater(result.verified_objects, 0)

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        duplicate = workspace.commit(
            Transaction(
                RootRef(0),
                (
                    InsertPureNode(nodes[0].handle, 0, 0, 5, Operation.CONSTANT, (), type_handle, 7),
                    InsertPureNode(nodes[1].handle, 0, 1, 5, Operation.CONSTANT, (), type_handle, 8),
                ),
            )
        )
        self.assertFalse(duplicate.committed)
        self.assertEqual((duplicate.diagnostic.code, duplicate.diagnostic.rule), ("XAX.WORKSPACE.DUPLICATE_MUTATION", "WORKSPACE-INSERT-LOCAL-ID-UNIQUE"))

    def test_edge_argument_disconnect_connect_commits_deterministically_and_rebuilds_callers(self):
        reader, callee, unrelated = edge_argument_caller_fixture()
        results = []
        for reverse in (False, True):
            workspace = Workspace(reader)
            nodes = workspace.function_nodes(callee.cid, 2).entities
            anchor = nodes[1].handle
            disconnect = DisconnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 0))
            connect = ConnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 1))
            mutations = (connect, disconnect) if reverse else (disconnect, connect)

            result = workspace.commit(Transaction(RootRef(0), mutations))

            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, (2, 3, 300)), (3,))
            callers = workspace.callers(result.changed_entity, 2).entities
            self.assertEqual(len(callers), 1)
            caller_cid = workspace._function_bindings[callers[0].handle][0]
            self.assertEqual(execute(workspace.reader, caller_cid, (2, 3, 300)), (3,))
            self.assertIn(unrelated.cid, {obj.cid for obj in workspace.reader.objects()})
            self.assertGreater(result.reused_objects, 0)
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)
        self.assertEqual(results[0].transaction_bytes, results[1].transaction_bytes)

    def test_edge_argument_reconnect_can_consume_transaction_local_inserted_result(self):
        reader, callee, _ = edge_argument_caller_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(callee.cid, 2).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        transaction = Transaction(
            RootRef(0),
            (
                InsertPureNode(nodes[0].handle, 0, 0, 9, Operation.CONSTANT, (), type_handle, 7),
                DisconnectEdgeArgument(nodes[1].handle, 0, 0, 0, ValueRef.parameter(0, 0)),
                ConnectEdgeArgument(nodes[1].handle, 0, 0, 0, TransactionValueRef(9)),
            ),
        )

        result = workspace.commit(transaction)

        self.assertTrue(result.committed)
        self.assertEqual(execute(workspace.reader, result.changed_entity, (2, 3, 300)), (7,))
        self.assertEqual(len(workspace.function_nodes(result.changed_entity, 3).entities), 3)
        self.assertFalse(any(handle.startswith("I9") for handle in workspace._value_bindings))

    def test_edge_argument_drift_and_disconnect_only_reject_atomically(self):
        reader, callee, _ = edge_argument_caller_fixture()
        cases = (
            (
                lambda anchor: DisconnectEdgeArgument(anchor, 0, 1, 0, ValueRef.parameter(0, 0)),
                ("XAX.WORKSPACE.CONTAINMENT_CONFLICT", "WORKSPACE-TERMINATOR-EDGE"),
            ),
            (
                lambda anchor: DisconnectEdgeArgument(anchor, 0, 0, 1, ValueRef.parameter(0, 0)),
                ("XAX.WORKSPACE.RELATION_CONFLICT", "WORKSPACE-EDGE-ARGUMENT-INDEX"),
            ),
            (
                lambda anchor: DisconnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 1)),
                ("XAX.WORKSPACE.RELATION_CONFLICT", "WORKSPACE-EDGE-ARGUMENT-PRECONDITION"),
            ),
        )
        for make_mutation, expected in cases:
            workspace = Workspace(reader)
            anchor = workspace.function_nodes(callee.cid, 2).entities[1].handle
            original_root = workspace.root
            result = workspace.commit(Transaction(RootRef(0), (make_mutation(anchor),)))
            self.assertFalse(result.committed)
            self.assertEqual((result.diagnostic.code, result.diagnostic.rule), expected)
            self.assertEqual(workspace.root, original_root)

        workspace = Workspace(reader)
        anchor = workspace.function_nodes(callee.cid, 2).entities[1].handle
        original_root = workspace.root
        result = workspace.commit(
            Transaction(RootRef(0), (DisconnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 0)),))
        )
        self.assertFalse(result.committed)
        self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.STRUCT.BRANCH_ARGUMENTS", "GRAPH-BLOCK-PARAMETERS"))
        self.assertEqual(workspace.root, original_root)

    def test_edge_argument_invalid_type_and_dominance_are_rejected_by_verifier(self):
        reader, callee, _ = edge_argument_caller_fixture()
        invalid_values = (
            (ValueRef.parameter(0, 2), ("XAX.STRUCT.BRANCH_ARGUMENTS", "GRAPH-BLOCK-PARAMETERS")),
            (ValueRef.parameter(1, 0), ("XAX.STRUCT.SSA_DOMINANCE", "GRAPH-SSA-DOMINANCE")),
        )
        for value, expected in invalid_values:
            workspace = Workspace(reader)
            anchor = workspace.function_nodes(callee.cid, 2).entities[1].handle
            original_root = workspace.root
            result = workspace.commit(
                Transaction(
                    RootRef(0),
                    (
                        DisconnectEdgeArgument(anchor, 0, 0, 0, ValueRef.parameter(0, 0)),
                        ConnectEdgeArgument(anchor, 0, 0, 0, value),
                    ),
                )
            )
            self.assertFalse(result.committed)
            self.assertEqual((result.diagnostic.code, result.diagnostic.rule), expected)
            self.assertEqual(workspace.root, original_root)

    def test_edge_argument_rejects_stale_root_and_read_set(self):
        reader, callee, _ = edge_argument_caller_fixture()
        workspace = Workspace(reader)
        old_nodes = workspace.function_nodes(callee.cid, 2).entities
        stale_read = workspace.callers(callee.cid, 1).entities[0].handle
        first = workspace.commit(
            Transaction(RootRef(0), (SetOperation(old_nodes[1].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
        )
        self.assertTrue(first.committed)
        current_anchor = workspace.function_nodes(first.changed_entity, 2).entities[1].handle

        stale = workspace.commit(
            Transaction(
                RootRef(0),
                (
                    DisconnectEdgeArgument(old_nodes[1].handle, 0, 0, 0, ValueRef.parameter(0, 0)),
                    ConnectEdgeArgument(old_nodes[1].handle, 0, 0, 0, ValueRef.parameter(0, 1)),
                ),
            )
        )
        read_conflict = workspace.commit(
            Transaction(
                RootRef(1),
                (
                    DisconnectEdgeArgument(current_anchor, 0, 0, 0, ValueRef.parameter(0, 0)),
                    ConnectEdgeArgument(current_anchor, 0, 0, 0, ValueRef.parameter(0, 1)),
                ),
                (stale_read,),
            )
        )

        self.assertFalse(stale.committed)
        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertFalse(read_conflict.committed)
        self.assertEqual((read_conflict.diagnostic.code, read_conflict.diagnostic.entity), ("XAX.WORKSPACE.READ_CONFLICT", stale_read))
        self.assertEqual(workspace.root, first.root)

    def test_candidate_verify_is_private_and_followup_commit_still_succeeds(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        transaction = Transaction(
            RootRef(0),
            (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
            (node.handle,),
        )
        original_root = workspace.root

        verified = workspace.verify(transaction)

        self.assertTrue(verified.verified)
        self.assertEqual(verified.candidate_handle, "C0.0")
        self.assertEqual(verified.root, original_root)
        self.assertEqual(workspace.root, original_root)
        self.assertEqual(workspace.generation, 0)
        self.assertEqual(execute(workspace.reader, entry.cid, ()), (5,))
        self.assertIn(verified.candidate_handle, workspace._candidate_bindings)
        self.assertFalse(hasattr(verified, "changed_entities"))

        committed = workspace.commit(transaction)
        self.assertTrue(committed.committed)
        self.assertEqual(execute(workspace.reader, committed.changed_entity, ()), (6,))
        self.assertEqual(workspace.generation, 1)
        self.assertEqual(workspace._candidate_bindings, {})

    def test_candidate_verify_rejects_verifier_invalid_graph_without_publication(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        original_root = workspace.root
        transaction = Transaction(
            RootRef(0),
            (
                InsertPureNode(
                    nodes[1].handle,
                    0,
                    1,
                    1,
                    Operation.ADD_WRAP,
                    (ValueRef.node_result(0, 2), ValueRef.node_result(0, 0)),
                    type_handle,
                ),
            ),
        )

        rejected = workspace.verify(transaction)

        self.assertFalse(rejected.verified)
        self.assertIsNone(rejected.candidate_handle)
        self.assertEqual((rejected.diagnostic.code, rejected.diagnostic.rule), ("XAX.STRUCT.SSA_DOMINANCE", "GRAPH-SSA-DOMINANCE"))
        self.assertEqual(workspace.root, original_root)
        self.assertEqual(workspace.generation, 0)
        self.assertEqual(workspace._candidate_bindings, {})

    def test_candidate_rollback_discards_private_state_only(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        transaction = Transaction(RootRef(0), (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
        original_root = workspace.root
        verified = workspace.verify(transaction)

        rolled_back = workspace.rollback(verified.candidate_handle)
        repeated = workspace.rollback(verified.candidate_handle)

        self.assertTrue(rolled_back.rolled_back)
        self.assertIsNone(rolled_back.diagnostic)
        self.assertFalse(repeated.rolled_back)
        self.assertEqual((repeated.diagnostic.code, repeated.diagnostic.rule), ("XAX.WORKSPACE.CANDIDATE_HANDLE", "WORKSPACE-CANDIDATE-CURRENT"))
        self.assertEqual(workspace.root, original_root)
        self.assertEqual(workspace.generation, 0)
        self.assertEqual(workspace._candidate_bindings, {})
        self.assertEqual(workspace.accounting.candidate_rollbacks, 1)

    def test_candidate_verify_resolves_transaction_local_insert_without_handle_leakage(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        type_handle = workspace.neighborhood(nodes[0].handle, 1).entities[0].type_handle
        transaction = Transaction(
            RootRef(0),
            (
                InsertPureNode(nodes[1].handle, 0, 1, 4, Operation.CONSTANT, (), type_handle, 9),
                ReplaceUse(nodes[2].handle, 0, ValueRef.node_result(0, 0), TransactionValueRef(4)),
            ),
        )

        verified = workspace.verify(transaction)

        self.assertTrue(verified.verified)
        self.assertEqual(workspace.root, reader.root_cid)
        self.assertEqual(execute(workspace.reader, entry.cid, ()), (5,))
        binding = workspace._candidate_bindings[verified.candidate_handle]
        candidate_outputs = {
            execute(binding.reader, obj.cid, ())
            for obj in binding.reader.objects()
            if obj.kind == Kind.FUNCTION
        }
        self.assertEqual(candidate_outputs, {(12,)})
        self.assertFalse(any(handle.startswith("I4") for handle in workspace._value_bindings))
        self.assertFalse(any(handle.startswith("I4") for handle in workspace._node_bindings))

    def test_candidate_verify_rejects_stale_root_read_proof_and_artifact_dependencies(self):
        reader, functions = disjoint_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
        stale_read = workspace.users(functions[0].cid, 1).entities[0].handle
        first = workspace.commit(Transaction(RootRef(0), (SetConstant(nodes[0].handle, nodes[0].constant_value, 4),)))
        current_other = workspace.function_nodes(functions[1].cid, 1).entities[0]

        stale_root = workspace.verify(Transaction(RootRef(0), (SetConstant(current_other.handle, current_other.constant_value, 5),)))
        read_conflict = workspace.verify(
            Transaction(RootRef(1), (SetConstant(current_other.handle, current_other.constant_value, 5),), (stale_read,))
        )
        self.assertFalse(stale_root.verified)
        self.assertEqual(stale_root.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertFalse(read_conflict.verified)
        self.assertEqual(read_conflict.diagnostic.code, "XAX.WORKSPACE.READ_CONFLICT")
        self.assertEqual(workspace.root, first.root)

        reader, functions = disjoint_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
        proof = workspace.proof(nodes[0].handle)
        first = workspace.commit(Transaction(RootRef(0), (SetConstant(nodes[0].handle, nodes[0].constant_value, 4),)))
        current_other = workspace.function_nodes(functions[1].cid, 1).entities[0]
        proof_conflict = workspace.verify(
            Transaction(RootRef(1), (SetConstant(current_other.handle, current_other.constant_value, 5),), (proof.dependency_handle,))
        )
        self.assertFalse(proof_conflict.verified)
        self.assertEqual((proof_conflict.diagnostic.code, proof_conflict.diagnostic.rule), ("XAX.WORKSPACE.PROOF_CONFLICT", "WORKSPACE-PROOF-DEPENDENCY"))
        self.assertEqual(workspace.root, first.root)

        reader, entry = type_fixture()
        workspace = Workspace(reader, x86_64_windows_target())
        artifact = workspace.artifact(entry.cid)
        nodes = workspace.function_nodes(entry.cid, 8).entities
        workspace._compiler_identity = bytes.fromhex("5a" * 32)
        artifact_conflict = workspace.verify(
            Transaction(
                RootRef(0),
                (SetOperation(nodes[1].handle, nodes[1].operation, nodes[1].operation),),
                (artifact.handle,),
            )
        )
        self.assertFalse(artifact_conflict.verified)
        self.assertEqual((artifact_conflict.diagnostic.code, artifact_conflict.diagnostic.entity), ("XAX.WORKSPACE.READ_CONFLICT", artifact.handle))
        self.assertEqual(workspace.root, reader.root_cid)

    def test_candidate_verify_rejects_raw_root_aba_when_proof_dependency_changes(self):
        import xax_workspace as workspace_module

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        proof = workspace.proof(node.handle)
        transaction = Transaction(
            reader.root_cid,
            (SetOperation(node.handle, Operation.ADD_WRAP, Operation.SUB_WRAP),),
            (proof.dependency_handle,),
        )
        original_candidate = workspace_module._candidate
        injected = False

        def candidate_with_aba(candidate_reader, bindings, mutations, users):
            nonlocal injected
            if not injected:
                injected = True
                first = workspace.commit(
                    Transaction(RootRef(0), (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
                )
                self.assertTrue(first.committed)
                current = workspace.function_nodes(first.changed_entity, 3).entities[2]
                second = workspace.commit(
                    Transaction(RootRef(1), (SetOperation(current.handle, Operation.MUL_WRAP, Operation.ADD_WRAP),))
                )
                self.assertTrue(second.committed)
                self.assertEqual(second.root, reader.root_cid)
            return original_candidate(candidate_reader, bindings, mutations, users)

        with patch("xax_workspace._candidate", side_effect=candidate_with_aba):
            result = workspace.verify(transaction)

        self.assertFalse(result.verified)
        self.assertIsNone(result.candidate_handle)
        self.assertEqual(workspace.root, reader.root_cid)
        self.assertEqual(workspace.generation, 2)
        self.assertEqual(
            (result.diagnostic.code, result.diagnostic.rule),
            ("XAX.WORKSPACE.PROOF_CONFLICT", "WORKSPACE-PROOF-DEPENDENCY"),
        )
        self.assertEqual(workspace._candidate_bindings, {})

    def test_candidate_verification_accounting_is_deterministic_and_separate_from_commit(self):
        records = []
        for _ in range(2):
            reader, entry = workspace_fixture()
            workspace = Workspace(reader)
            node = workspace.function_nodes(entry.cid, 3).entities[2]
            transaction = Transaction(RootRef(0), (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
            before_commit_bytes = workspace.accounting.transaction_bytes

            result = workspace.verify(transaction)

            self.assertTrue(result.verified)
            self.assertEqual(workspace.accounting.transaction_bytes, before_commit_bytes)
            self.assertEqual(workspace.accounting.candidate_verifications, 1)
            self.assertEqual(workspace.accounting.rejected_candidates, 0)
            self.assertEqual(workspace.accounting.candidate_transaction_bytes, result.transaction_bytes)
            self.assertEqual(workspace.accounting.candidate_verified_objects, result.verified_objects)
            records.append((result.transaction_bytes, result.touched_objects, result.reused_objects, result.verified_objects))
        self.assertEqual(records[0], records[1])

    def test_move_pure_node_commits_deterministically_and_rebuilds_callers(self):
        reader, callee, _, unrelated = movable_caller_fixture()
        records = []
        for workspace in (Workspace(reader), Workspace(reader)):
            nodes = workspace.function_nodes(callee.cid, 3).entities
            mutation = MovePureNode(nodes[1].handle, 0, 1, nodes[0].handle, 0, 0)

            result = workspace.commit(Transaction(RootRef(0), (mutation,)))

            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, ()), (5,))
            current = workspace.function_nodes(result.changed_entity, 3).entities
            self.assertEqual(
                [(node.operation, node.constant_value) for node in current],
                [(Operation.CONSTANT, 3), (Operation.CONSTANT, 2), (Operation.ADD_WRAP, None)],
            )
            operands = workspace.operands(current[2].handle, 2).entities
            self.assertEqual([value.handle.rsplit(".", 2)[-2:] for value in operands], [["N1", "R0"], ["N0", "R0"]])
            callers = workspace.callers(result.changed_entity, 2).entities
            self.assertEqual(len(callers), 1)
            caller_cid = workspace._function_bindings[callers[0].handle][0]
            self.assertEqual(execute(workspace.reader, caller_cid, ()), (5,))
            self.assertIn(unrelated.cid, {obj.cid for obj in workspace.reader.objects()})
            self.assertGreater(result.reused_objects, 0)
            records.append((result.root, result.transaction_bytes, result.touched_objects, result.reused_objects, result.verified_objects))
        self.assertEqual(records[0], records[1])

    def test_move_source_and_destination_containment_conflicts_are_exact(self):
        reader, entry = workspace_fixture()
        diagnostics = []
        for source_expected, destination_expected, expected_rule in (
            ((0, 0), (0, 0), "WORKSPACE-MOVE-SOURCE"),
            ((0, 1), (0, 2), "WORKSPACE-MOVE-DESTINATION"),
        ):
            workspace = Workspace(reader)
            nodes = workspace.function_nodes(entry.cid, 3).entities
            result = workspace.commit(
                Transaction(
                    RootRef(0),
                    (
                        MovePureNode(
                            nodes[1].handle,
                            source_expected[0],
                            source_expected[1],
                            nodes[0].handle,
                            destination_expected[0],
                            destination_expected[1],
                        ),
                    ),
                )
            )
            self.assertFalse(result.committed)
            self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.WORKSPACE.CONTAINMENT_CONFLICT", expected_rule))
            self.assertEqual(workspace.root, reader.root_cid)
            diagnostics.append(result.diagnostic)
        self.assertEqual(diagnostics[0].actual, (0, 1))
        self.assertEqual(diagnostics[1].actual, (0, 0))

    def test_move_that_breaks_ssa_dominance_is_rejected_atomically(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        original_root = workspace.root

        result = workspace.commit(
            Transaction(RootRef(0), (MovePureNode(nodes[2].handle, 0, 2, nodes[0].handle, 0, 0),))
        )

        self.assertFalse(result.committed)
        self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.STRUCT.SSA_DOMINANCE", "GRAPH-SSA-DOMINANCE"))
        self.assertEqual(workspace.root, original_root)
        self.assertEqual(execute(workspace.reader, entry.cid, ()), (5,))

    def test_move_rejects_stale_root_read_set_and_self_anchor(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        mutation = MovePureNode(nodes[1].handle, 0, 1, nodes[0].handle, 0, 0)

        stale = workspace.commit(Transaction(bytes(32), (mutation,)))
        read_conflict = workspace.commit(Transaction(RootRef(0), (mutation,), ("E999",)))
        self_anchor = workspace.commit(
            Transaction(RootRef(0), (MovePureNode(nodes[1].handle, 0, 1, nodes[1].handle, 0, 1),))
        )

        self.assertFalse(stale.committed)
        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertFalse(read_conflict.committed)
        self.assertEqual(read_conflict.diagnostic.code, "XAX.WORKSPACE.READ_CONFLICT")
        self.assertFalse(self_anchor.committed)
        self.assertEqual((self_anchor.diagnostic.code, self_anchor.diagnostic.rule), ("XAX.WORKSPACE.RELATION_CONFLICT", "WORKSPACE-MOVE-SELF-ANCHOR"))
        self.assertEqual(workspace.root, reader.root_cid)

    def test_move_batch_is_request_order_deterministic_with_nonstructural_edit(self):
        reader, entry = workspace_fixture()
        records = []
        for reverse in (False, True):
            workspace = Workspace(reader)
            nodes = workspace.function_nodes(entry.cid, 3).entities
            mutations = (
                MovePureNode(nodes[1].handle, 0, 1, nodes[0].handle, 0, 0),
                SetOperation(nodes[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),
            )

            result = workspace.commit(Transaction(RootRef(0), tuple(reversed(mutations)) if reverse else mutations))

            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, ()), (6,))
            records.append((result.root, result.transaction_bytes, result.touched_objects, result.reused_objects, result.verified_objects))
        self.assertEqual(records[0], records[1])

    def test_delete_unused_pure_node_commits_deterministically_and_rebuilds_callers(self):
        reader, callee, unrelated = deletable_caller_fixture()
        results = []
        for workspace in (Workspace(reader), Workspace(reader)):
            nodes = workspace.function_nodes(callee.cid, 2).entities
            mutation = DeleteNode(nodes[0].handle, 0, 0)
            result = workspace.commit(Transaction(RootRef(0), (mutation,)))

            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, (2, 3)), (5,))
            current_nodes = workspace.function_nodes(result.changed_entity, 2).entities
            self.assertEqual(len(current_nodes), 1)
            self.assertEqual(current_nodes[0].operation, Operation.ADD_WRAP)
            callers = workspace.callers(result.changed_entity, 2).entities
            self.assertEqual(len(callers), 1)
            caller_cid = workspace._function_bindings[callers[0].handle][0]
            self.assertEqual(execute(workspace.reader, caller_cid, (2, 3)), (5,))
            self.assertIn(unrelated.cid, {obj.cid for obj in workspace.reader.objects()})
            self.assertGreater(result.reused_objects, 0)
            self.assertEqual(workspace.accounting.transaction_bytes, result.transaction_bytes)
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)
        self.assertEqual(results[0].transaction_bytes, results[1].transaction_bytes)

    def test_delete_node_rejects_live_operand_use_atomically(self):
        reader, entry = workspace_fixture()
        diagnostics = []
        for workspace in (Workspace(reader), Workspace(reader)):
            nodes = workspace.function_nodes(entry.cid, 3).entities
            original_root = workspace.root
            result = workspace.commit(Transaction(RootRef(0), (DeleteNode(nodes[0].handle, 0, 0),)))

            self.assertFalse(result.committed)
            self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.WORKSPACE.DELETE_USE_CONFLICT", "WORKSPACE-DELETE-NODE-UNUSED"))
            self.assertEqual(workspace.root, original_root)
            self.assertEqual(execute(workspace.reader, entry.cid, ()), (5,))
            diagnostics.append(result.diagnostic)
        self.assertEqual(diagnostics[0], diagnostics[1])

    def test_delete_node_rejects_branch_argument_use(self):
        reader, entry = branch_use_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 1).entities[0]
        result = workspace.commit(Transaction(RootRef(0), (DeleteNode(node.handle, 0, 0),)))

        self.assertFalse(result.committed)
        self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.WORKSPACE.DELETE_USE_CONFLICT", "WORKSPACE-DELETE-NODE-UNUSED"))
        self.assertEqual(result.diagnostic.actual, (1, 0, 0, 0))
        self.assertEqual(workspace.root, reader.root_cid)

    def test_delete_node_wrong_containment_precondition_is_deterministic(self):
        reader, callee, _ = deletable_caller_fixture()
        diagnostics = []
        for workspace in (Workspace(reader), Workspace(reader)):
            node = workspace.function_nodes(callee.cid, 2).entities[0]
            result = workspace.commit(Transaction(RootRef(0), (DeleteNode(node.handle, 0, 1),)))
            self.assertFalse(result.committed)
            self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.WORKSPACE.CONTAINMENT_CONFLICT", "WORKSPACE-NODE-CONTAINMENT"))
            self.assertEqual((result.diagnostic.expected, result.diagnostic.actual), ((0, 1), (0, 0)))
            diagnostics.append(result.diagnostic)
        self.assertEqual(diagnostics[0], diagnostics[1])

    def test_delete_node_rejects_stale_generation_and_read_set(self):
        reader, callee, _ = deletable_caller_fixture()
        workspace = Workspace(reader)
        old_nodes = workspace.function_nodes(callee.cid, 2).entities
        stale_read = workspace.callers(callee.cid, 1).entities[0].handle
        first = workspace.commit(Transaction(RootRef(0), (SetOperation(old_nodes[1].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))
        self.assertTrue(first.committed)
        current_nodes = workspace.function_nodes(first.changed_entity, 2).entities

        stale = workspace.commit(Transaction(RootRef(0), (DeleteNode(old_nodes[0].handle, 0, 0),)))
        read_conflict = workspace.commit(Transaction(RootRef(1), (DeleteNode(current_nodes[0].handle, 0, 0),), (stale_read,)))

        self.assertFalse(stale.committed)
        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertFalse(read_conflict.committed)
        self.assertEqual((read_conflict.diagnostic.code, read_conflict.diagnostic.entity), ("XAX.WORKSPACE.READ_CONFLICT", stale_read))
        self.assertEqual(workspace.root, first.root)

    def test_delete_node_does_not_change_existing_mutation_behavior(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        literal = workspace.commit(Transaction(RootRef(0), (SetConstant(nodes[0].handle, 2, 4),)))
        self.assertTrue(literal.committed)
        current = workspace.function_nodes(literal.changed_entity, 3).entities
        relation = workspace.commit(
            Transaction(RootRef(1), (ReplaceUse(current[2].handle, 0, ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)),))
        )
        self.assertTrue(relation.committed)
        current = workspace.function_nodes(relation.changed_entity, 3).entities
        operation = workspace.commit(Transaction(RootRef(2), (SetOperation(current[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))
        self.assertTrue(operation.committed)
        self.assertEqual(execute(workspace.reader, operation.changed_entity, ()), (9,))

    def test_replace_use_commits_deterministically_and_rebuilds_callers(self):
        reader, arithmetic = caller_fixture()
        results = []
        for workspace in (Workspace(reader), Workspace(reader)):
            node = workspace.function_nodes(arithmetic.cid, 1).entities[0]
            mutation = ReplaceUse(
                node.handle,
                0,
                ValueRef.parameter(0, 0),
                ValueRef.parameter(0, 1),
            )
            result = workspace.commit(Transaction(RootRef(0), (mutation,)))

            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, (2, 3)), (6,))
            self.assertEqual(len(workspace.callers(result.changed_entity, 8).entities), 1)
            self.assertEqual(
                {execute(workspace.reader, obj.cid, (2, 3)) for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION},
                {(6,), (8,)},
            )
            self.assertEqual(workspace.accounting.transaction_bytes, result.transaction_bytes)
            self.assertGreater(result.transaction_bytes, 0)
            self.assertGreater(result.reused_objects, 0)
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)
        self.assertEqual(results[0].transaction_bytes, results[1].transaction_bytes)

    def test_replace_use_wrong_old_relation_is_deterministic_and_atomic(self):
        reader, arithmetic = caller_fixture()
        diagnostics = []
        for workspace in (Workspace(reader), Workspace(reader)):
            node = workspace.function_nodes(arithmetic.cid, 1).entities[0]
            original_root = workspace.root
            result = workspace.commit(
                Transaction(
                    RootRef(0),
                    (
                        ReplaceUse(
                            node.handle,
                            0,
                            ValueRef.parameter(0, 1),
                            ValueRef.parameter(0, 0),
                        ),
                    ),
                )
            )

            self.assertFalse(result.committed)
            self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.WORKSPACE.RELATION_CONFLICT", "WORKSPACE-OPERAND-PRECONDITION"))
            self.assertEqual(result.diagnostic.expected, (0, 0, 1, 0))
            self.assertEqual(result.diagnostic.actual, (0, 0, 0, 0))
            self.assertEqual(workspace.root, original_root)
            self.assertEqual(execute(workspace.reader, arithmetic.cid, (2, 3)), (5,))
            diagnostics.append(result.diagnostic)
        self.assertEqual(diagnostics[0], diagnostics[1])

    def test_replace_use_type_incompatible_value_is_rejected_by_verifier(self):
        b8, b16 = bits_type(8), bits_type(16)
        graph = graph_fragment(
            [
                Block(
                    (b8, b8, b16),
                    (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                )
            ]
        )
        entry = function(graph, (b8, b8, b16), (b8,))
        module = object_with_refs(Kind.MODULE, (entry,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        reader = StoreReader(write_store(root.cid, (b8, b16, graph, entry, module, root)))
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 1).entities[0]

        result = workspace.commit(
            Transaction(
                RootRef(0),
                (ReplaceUse(node.handle, 1, ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),),
            )
        )

        self.assertFalse(result.committed)
        self.assertEqual((result.diagnostic.code, result.diagnostic.rule), ("XAX.STRUCT.OP_TYPE", "GRAPH-OP-TYPE"))
        self.assertEqual(workspace.root, reader.root_cid)
        self.assertEqual(execute(workspace.reader, entry.cid, (2, 3, 300)), (5,))

    def test_replace_use_rejects_stale_generation_and_read_set(self):
        reader, arithmetic = caller_fixture()
        workspace = Workspace(reader)
        old_node = workspace.function_nodes(arithmetic.cid, 1).entities[0]
        stale_read = workspace.callers(arithmetic.cid, 1).entities[0].handle
        first = workspace.commit(
            Transaction(RootRef(0), (SetOperation(old_node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
        )
        self.assertTrue(first.committed)
        current = workspace.function_nodes(first.changed_entity, 1).entities[0]

        stale = workspace.commit(
            Transaction(
                RootRef(0),
                (ReplaceUse(old_node.handle, 0, ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)),),
            )
        )
        read_conflict = workspace.commit(
            Transaction(
                RootRef(1),
                (ReplaceUse(current.handle, 0, ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)),),
                (stale_read,),
            )
        )

        self.assertFalse(stale.committed)
        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertFalse(read_conflict.committed)
        self.assertEqual((read_conflict.diagnostic.code, read_conflict.diagnostic.entity), ("XAX.WORKSPACE.READ_CONFLICT", stale_read))
        self.assertEqual(workspace.root, first.root)

    def test_replace_use_does_not_change_set_operation_or_set_constant_behavior(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        literal = workspace.commit(Transaction(RootRef(0), (SetConstant(nodes[0].handle, 2, 4),)))
        self.assertTrue(literal.committed)
        current_nodes = workspace.function_nodes(literal.changed_entity, 3).entities
        operation = workspace.commit(
            Transaction(RootRef(1), (SetOperation(current_nodes[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
        )

        self.assertTrue(operation.committed)
        self.assertEqual(execute(workspace.reader, operation.changed_entity, ()), (12,))

    def test_operation_edit_commits_deterministically(self):
        reader, entry = workspace_fixture()
        workspaces = (Workspace(reader), Workspace(reader))
        results = []
        for workspace in workspaces:
            page = workspace.function_nodes(entry.cid, 3)
            user = workspace.users(entry.cid, 1).entities[0]
            result = workspace.commit(
                Transaction(
                    reader.root_cid,
                    (SetOperation(page.entities[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
                    (page.entities[2].handle, user.handle),
                )
            )
            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, ()), (6,))
            self.assertEqual(result.touched_objects, 4)
            self.assertEqual(result.verified_objects, result.touched_objects)
            self.assertGreater(result.reused_objects, 0)
            self.assertGreater(result.transaction_bytes, 0)
            self.assertEqual(workspace.accounting.transaction_bytes, result.transaction_bytes)
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)
        self.assertEqual(workspaces[0].accounting.verified_objects, 4)

    def test_frontier_verification_matches_oracle_and_rejects_atomically(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        result = workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))

        self.assertTrue(result.committed)
        self.assertEqual(result.verified_objects, result.touched_objects)
        verify_store(workspace.reader)

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 3).entities[2]
        diagnostic = Diagnostic("XAX.TEST.INVALID_CANDIDATE", node.handle, "TEST-FRONTIER", "valid", "invalid")
        with patch("xax_workspace.verify_object", side_effect=XaxError(diagnostic)):
            rejected = workspace.commit(Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))

        self.assertFalse(rejected.committed)
        self.assertEqual(rejected.diagnostic, diagnostic)
        self.assertEqual(rejected.verified_objects, 1)
        self.assertEqual(workspace.accounting.verified_objects, 1)
        self.assertEqual(workspace.root, reader.root_cid)

    def test_literal_edit_commits_without_rewriting_unrelated_objects(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 1).entities[0]

        result = workspace.commit(Transaction(reader.root_cid, (SetConstant(node.handle, node.constant_value, 9),)))

        self.assertTrue(result.committed)
        self.assertEqual(execute(workspace.reader, result.changed_entity, ()), (12,))
        self.assertEqual(result.touched_objects, 5)
        self.assertGreater(result.reused_objects, 0)

    def test_multi_mutation_rebuilds_once_and_is_order_independent(self):
        reader, entry = workspace_fixture()
        results = []
        for reverse in (False, True):
            workspace = Workspace(reader)
            nodes = workspace.function_nodes(entry.cid, 3).entities
            mutations = (
                SetConstant(nodes[0].handle, 2, 4),
                SetConstant(nodes[1].handle, 3, 5),
                SetOperation(nodes[2].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),
            )
            result = workspace.commit(Transaction(reader.root_cid, tuple(reversed(mutations)) if reverse else mutations))

            self.assertTrue(result.committed)
            self.assertEqual(execute(workspace.reader, result.changed_entity, ()), (20,))
            self.assertEqual(result.touched_objects, 6)
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)
        self.assertEqual(results[0].transaction_bytes, results[1].transaction_bytes)

    def test_failed_or_duplicate_batch_is_atomic(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        nodes = workspace.function_nodes(entry.cid, 3).entities
        original_root = workspace.root

        failed = workspace.commit(
            Transaction(
                original_root,
                (SetConstant(nodes[0].handle, 2, 4), SetConstant(nodes[1].handle, 99, 5)),
            )
        )
        duplicate = workspace.commit(
            Transaction(
                original_root,
                (SetConstant(nodes[0].handle, 2, 4), SetConstant(nodes[0].handle, 2, 6)),
            )
        )

        self.assertFalse(failed.committed)
        self.assertEqual(failed.diagnostic.code, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT")
        self.assertFalse(duplicate.committed)
        self.assertEqual(duplicate.diagnostic.code, "XAX.WORKSPACE.DUPLICATE_MUTATION")
        self.assertEqual(workspace.root, original_root)
        self.assertEqual(execute(workspace.reader, entry.cid, ()), (5,))

    def test_disjoint_function_batch_commits_deterministically(self):
        reader, functions = disjoint_fixture()
        results = []
        for reverse in (False, True):
            workspace = Workspace(reader)
            nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
            mutations = tuple(SetConstant(node.handle, node.constant_value, node.constant_value + 2) for node in nodes)
            result = workspace.commit(Transaction(reader.root_cid, tuple(reversed(mutations)) if reverse else mutations))

            self.assertTrue(result.committed)
            self.assertIsNone(result.changed_entity)
            self.assertEqual({execute(workspace.reader, cid, ()) for cid in result.changed_entities}, {(4,), (5,)})
            self.assertEqual(result.touched_objects, 8)
            self.assertGreaterEqual(result.reused_objects, 2)
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)

    def test_shared_caller_rebuilds_once_for_disjoint_edits(self):
        reader, leaves = shared_caller_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in leaves)

        result = workspace.commit(
            Transaction(
                reader.root_cid,
                tuple(
                    SetOperation(node.handle, node.operation, value)
                    for node, value in zip(nodes, (Operation.SUB_WRAP, Operation.MUL_WRAP))
                ),
            )
        )

        self.assertTrue(result.committed)
        self.assertEqual({execute(workspace.reader, cid, (2, 3)) for cid in result.changed_entities}, {(255,), (6,)})
        caller = next(obj for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION and obj.cid not in result.changed_entities)
        self.assertEqual(execute(workspace.reader, caller.cid, (2, 3)), (5,))
        self.assertEqual(result.touched_objects, 6)

    def test_caller_callee_batch_merges_deterministically(self):
        reader, arithmetic = caller_fixture()
        results = []
        for reverse in (False, True):
            workspace = Workspace(reader)
            arithmetic_node = workspace.function_nodes(arithmetic.cid, 1).entities[0]
            caller_nodes = next(
                workspace.function_nodes(item.cid, 10).entities
                for item in reader.objects()
                if item.kind == Kind.FUNCTION and item.cid != arithmetic.cid and len(workspace.function_nodes(item.cid, 10).entities) == 2
            )
            mutations = (
                SetOperation(arithmetic_node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),
                SetOperation(caller_nodes[1].handle, Operation.ADD_WRAP, Operation.MUL_WRAP),
            )

            result = workspace.commit(Transaction(reader.root_cid, tuple(reversed(mutations)) if reverse else mutations))

            self.assertTrue(result.committed)
            self.assertEqual({execute(workspace.reader, cid, (2, 3)) for cid in result.changed_entities}, {(6,), (12,)})
            self.assertEqual({execute(workspace.reader, obj.cid, (2, 3)) for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION}, {(6,), (12,)})
            results.append(result)
        self.assertEqual(results[0].root, results[1].root)

    def test_edit_rebuilds_direct_callers(self):
        reader, arithmetic = caller_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(arithmetic.cid, 1).entities[0]
        caller = workspace.callers(arithmetic.cid, 1).entities[0]

        result = workspace.commit(
            Transaction(
                reader.root_cid,
                (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),),
                (node.handle, caller.handle),
            )
        )

        self.assertTrue(result.committed)
        functions = tuple(obj for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION)
        self.assertEqual(len(functions), 3)
        self.assertEqual({execute(workspace.reader, obj.cid, (2, 3)) for obj in functions}, {(6,), (8,)})
        self.assertEqual(result.touched_objects, 8)
        self.assertGreater(result.reused_objects, 1)

    def test_recursion_group_caller_rejects_atomically(self):
        reader, arithmetic = caller_fixture(recursive_user=True)
        workspace = Workspace(reader)
        node = workspace.function_nodes(arithmetic.cid, 1).entities[0]

        result = workspace.commit(
            Transaction(reader.root_cid, (SetOperation(node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
        )

        self.assertFalse(result.committed)
        self.assertEqual(result.diagnostic.code, "XAX.WORKSPACE.TOPOLOGY")
        self.assertEqual(result.diagnostic.rule, "WORKSPACE-RECURSION-REBUILD")
        self.assertEqual(workspace.root, reader.root_cid)
        self.assertEqual(execute(workspace.reader, arithmetic.cid, (2, 3)), (5,))

    def test_stale_or_conflicting_transaction_is_atomic(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 1).entities[0]
        original_root = workspace.root

        conflict = workspace.commit(Transaction(original_root, (SetConstant(node.handle, 99, 9),)))
        read_conflict = workspace.commit(Transaction(original_root, (SetConstant(node.handle, 2, 9),), ("E999",)))
        stale = workspace.commit(Transaction(bytes(32), (SetConstant(node.handle, 2, 9),)))

        self.assertFalse(conflict.committed)
        self.assertEqual(conflict.diagnostic.code, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT")
        self.assertFalse(read_conflict.committed)
        self.assertEqual(read_conflict.diagnostic.code, "XAX.WORKSPACE.READ_CONFLICT")
        self.assertFalse(stale.committed)
        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertEqual(workspace.root, original_root)
        self.assertEqual(execute(workspace.reader, entry.cid, ()), (5,))
        self.assertEqual(workspace.accounting.rejected_transactions, 3)

    def test_repair_neighborhood_is_bounded_for_workspace_conflicts(self):
        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 1).entities[0]
        mutation = SetConstant(node.handle, 2, 9)

        attribute = workspace.commit(Transaction(reader.root_cid, (SetConstant(node.handle, 99, 9),)))
        read = workspace.commit(Transaction(reader.root_cid, (mutation,), ("E999",)))
        stale = workspace.commit(Transaction(bytes(32), (mutation,)))

        attribute_page = workspace.repair_neighborhood(attribute.diagnostic, 1)
        read_first = workspace.repair_neighborhood(read.diagnostic, 1)
        read_second = workspace.repair_neighborhood(read.diagnostic, 1, read_first.continuation)
        stale_page = workspace.repair_neighborhood(stale.diagnostic, 2)

        self.assertEqual(tuple(item.handle for item in attribute_page.entities), (node.handle,))
        self.assertEqual(tuple(item.handle for item in read_first.entities), ("E999",))
        self.assertTrue(read_first.truncated)
        self.assertEqual(read_first.continuation, 1)
        self.assertEqual(tuple(item.handle for item in read_second.entities), (node.handle,))
        self.assertEqual(tuple(item.handle for item in stale_page.entities), ("R0", node.handle))
        self.assertFalse(stale_page.truncated)
        self.assertFalse(any(len(item.handle) == 64 for item in (*attribute_page.entities, *read_first.entities, *read_second.entities, *stale_page.entities)))

    def test_one_generation_rebase_accepts_only_unchanged_entities(self):
        reader, functions = disjoint_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
        value = workspace.neighborhood(nodes[1].handle, 1).entities[0]
        stale = Transaction(
            reader.root_cid,
            (SetConstant(nodes[1].handle, nodes[1].constant_value, 5),),
            (nodes[1].handle, value.handle, value.type_handle),
        )

        first = workspace.commit(Transaction(reader.root_cid, (SetConstant(nodes[0].handle, nodes[0].constant_value, 4),)))
        rebased = workspace.rebase(stale)

        self.assertTrue(first.committed)
        self.assertTrue(rebased.committed)
        self.assertEqual({execute(workspace.reader, obj.cid, ()) for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION}, {(4,), (5,)})

        reader, entry = workspace_fixture()
        workspace = Workspace(reader)
        node = workspace.function_nodes(entry.cid, 1).entities[0]
        stale = Transaction(reader.root_cid, (SetConstant(node.handle, 2, 9),))
        first = workspace.commit(Transaction(reader.root_cid, (SetConstant(node.handle, 2, 4),)))
        conflict = workspace.rebase(stale)

        self.assertFalse(conflict.committed)
        self.assertEqual(conflict.diagnostic.code, "XAX.WORKSPACE.REBASE_CONFLICT")
        self.assertEqual(conflict.diagnostic.rule, "WORKSPACE-REBASE-TARGET-UNCHANGED")
        self.assertEqual(workspace.root, first.root)

        reader, arithmetic = caller_fixture()
        workspace = Workspace(reader)
        caller = next(item for item in reader.objects() if item.kind == Kind.FUNCTION and item.cid != arithmetic.cid and len(workspace.function_nodes(item.cid, 10).entities) == 2)
        caller_node = workspace.function_nodes(caller.cid, 2).entities[1]
        stale = Transaction(reader.root_cid, (SetOperation(caller_node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),))
        arithmetic_node = workspace.function_nodes(arithmetic.cid, 1).entities[0]
        first = workspace.commit(Transaction(reader.root_cid, (SetOperation(arithmetic_node.handle, Operation.ADD_WRAP, Operation.MUL_WRAP),)))
        conflict = workspace.rebase(stale)

        self.assertFalse(conflict.committed)
        self.assertEqual(conflict.diagnostic.rule, "WORKSPACE-REBASE-TARGET-UNCHANGED")
        self.assertEqual(workspace.root, first.root)

    def test_rebase_rejects_changed_reads_across_retained_bases(self):
        reader, functions = disjoint_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
        module = workspace.users(functions[1].cid, 1).entities[0]
        stale = Transaction(reader.root_cid, (SetConstant(nodes[1].handle, 3, 5),), (module.handle,))
        first = workspace.commit(Transaction(reader.root_cid, (SetConstant(nodes[0].handle, 2, 4),)))
        conflict = workspace.rebase(stale)

        self.assertFalse(conflict.committed)
        self.assertEqual(conflict.diagnostic.rule, "WORKSPACE-REBASE-READ-UNCHANGED")
        self.assertEqual(workspace.root, first.root)

        current_first = workspace.function_nodes(first.changed_entity, 1).entities[0]
        second = workspace.commit(Transaction(first.root, (SetConstant(current_first.handle, 4, 6),)))
        old_base = workspace.rebase(stale)

        self.assertTrue(second.committed)
        self.assertFalse(old_base.committed)
        self.assertEqual(old_base.diagnostic.rule, "WORKSPACE-REBASE-READ-UNCHANGED")
        self.assertEqual(workspace.root, second.root)

    def test_multi_generation_rebase_diff_and_durable_snapshot(self):
        reader, functions = disjoint_fixture()
        workspace = Workspace(reader)
        nodes = tuple(workspace.function_nodes(item.cid, 1).entities[0] for item in functions)
        stale = Transaction(RootRef(0), (SetConstant(nodes[1].handle, 3, 9),), (nodes[1].handle,))

        first = workspace.commit(Transaction(RootRef(0), (SetConstant(nodes[0].handle, 2, 4),)))
        current_first = workspace.function_nodes(first.changed_entity, 1).entities[0]
        second = workspace.commit(Transaction(RootRef(1), (SetConstant(current_first.handle, 4, 6),)))
        rebased = workspace.rebase(stale)

        self.assertTrue(first.committed)
        self.assertTrue(second.committed)
        self.assertTrue(rebased.committed)
        self.assertEqual({execute(workspace.reader, obj.cid, ()) for obj in workspace.reader.objects() if obj.kind == Kind.FUNCTION}, {(6,), (9,)})
        self.assertTrue(workspace.diff(0, 100).entities)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workspace.xax"
            workspace.save(path)
            loaded = Workspace.load(path)
            self.assertEqual(loaded.root, workspace.root)
            self.assertEqual(loaded.reader.canonical_bytes(), workspace.reader.canonical_bytes())

    def test_specialize_function_is_private_until_commit_and_preserves_source_callers(self):
        reader, source, caller, unrelated = specialization_fixture()
        workspace = Workspace(reader)
        source_view = workspace.callees(caller.cid, 1).entities[0]
        source_node = workspace.function_nodes(source.cid, 1).entities[0]
        type_handle = workspace.operands(source_node.handle, 2).entities[0].type_handle
        transaction = Transaction(
            RootRef(0),
            (SpecializeFunction(source_view.handle, (SpecializationArgument(0, type_handle, 5),)),),
        )

        verified = workspace.verify(transaction)

        self.assertTrue(verified.verified)
        self.assertIsNotNone(verified.candidate_handle)
        self.assertEqual(workspace.root, reader.root_cid)
        self.assertEqual(workspace.generation, 0)

        committed = workspace.commit(transaction)

        self.assertTrue(committed.committed)
        self.assertEqual(len(committed.changed_entities), 1)
        self.assertEqual(execute(workspace.reader, committed.changed_entity, (3,)), (8,))
        self.assertEqual(execute(workspace.reader, source.cid, (5, 3)), (8,))
        self.assertEqual(execute(workspace.reader, caller.cid, (5, 3)), (8,))
        self.assertEqual(workspace.reader.get(unrelated.cid), unrelated)
        self.assertFalse(workspace.rollback(verified.candidate_handle).rolled_back)

    def test_specialize_function_is_deterministic_and_accounted(self):
        results = []
        for _ in range(2):
            reader, source, caller, _ = specialization_fixture()
            workspace = Workspace(reader)
            source_view = workspace.callees(caller.cid, 1).entities[0]
            source_node = workspace.function_nodes(source.cid, 1).entities[0]
            type_handle = workspace.operands(source_node.handle, 2).entities[0].type_handle
            result = workspace.commit(
                Transaction(
                    RootRef(0),
                    (SpecializeFunction(source_view.handle, (SpecializationArgument(0, type_handle, 5),)),),
                )
            )
            self.assertTrue(result.committed)
            results.append(
                (
                    result.root,
                    result.changed_entity,
                    result.transaction_bytes,
                    result.touched_objects,
                    result.reused_objects,
                    result.verified_objects,
                )
            )

        self.assertEqual(results[0], results[1])

    def test_specialize_function_rebases_only_when_source_and_argument_types_are_unchanged(self):
        reader, source, caller, _ = specialization_fixture()
        workspace = Workspace(reader)
        source_view = workspace.callees(caller.cid, 1).entities[0]
        source_node = workspace.function_nodes(source.cid, 1).entities[0]
        type_handle = workspace.operands(source_node.handle, 2).entities[0].type_handle
        stale = Transaction(
            RootRef(0),
            (SpecializeFunction(source_view.handle, (SpecializationArgument(0, type_handle, 5),)),),
        )
        caller_literal = workspace.function_nodes(caller.cid, 2).entities[0]
        first = workspace.commit(Transaction(RootRef(0), (SetConstant(caller_literal.handle, 1, 2),)))

        rebased = workspace.rebase(stale)

        self.assertTrue(first.committed)
        self.assertTrue(rebased.committed)
        self.assertEqual(execute(workspace.reader, rebased.changed_entity, (3,)), (8,))

    def test_specialize_function_rejects_conflicts_and_broader_evaluation(self):
        reader, source, caller, _ = specialization_fixture()
        workspace = Workspace(reader)
        source_view = workspace.callees(caller.cid, 1).entities[0]
        caller_view = workspace.callers(source.cid, 1).entities[0]
        source_node = workspace.function_nodes(source.cid, 1).entities[0]
        type_handle = workspace.operands(source_node.handle, 2).entities[0].type_handle

        def transaction(function_handle, arguments, expected_root=RootRef(0), read_set=()):
            return Transaction(expected_root, (SpecializeFunction(function_handle, arguments),), read_set)

        argument = SpecializationArgument(0, type_handle, 5)
        stale = workspace.commit(transaction(source_view.handle, (argument,), bytes(32)))
        read_conflict = workspace.commit(transaction(source_view.handle, (argument,), read_set=("E999",)))
        duplicate = workspace.commit(transaction(source_view.handle, (argument, argument)))
        out_of_range = workspace.commit(
            transaction(source_view.handle, (SpecializationArgument(2, type_handle, 5),))
        )
        unsupported = workspace.commit(transaction(caller_view.handle, (argument,)))

        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")
        self.assertEqual(read_conflict.diagnostic.code, "XAX.WORKSPACE.READ_CONFLICT")
        self.assertEqual(duplicate.diagnostic.rule, "WORKSPACE-SPECIALIZE-PARAMETER-UNIQUE")
        self.assertEqual(out_of_range.diagnostic.rule, "WORKSPACE-SPECIALIZE-PARAMETER-INDEX")
        self.assertEqual(unsupported.diagnostic.rule, "WORKSPACE-SPECIALIZE-PURE-SUBSET")
        self.assertEqual(workspace.root, reader.root_cid)

    def test_edited_transitive_caller_calls_the_rebuilt_middle_function(self):
        # ADR-197: editing rate and c1 (c1 -> fee -> rate) in one batch left c1
        # calling the stale fee. The result must equal building the edit directly.
        from xax_compiler import IntCompare
        from xax_graph_builder import GraphBuilder
        from xax_local_protocol import LocalMutationSession

        def program(rate_value, expected):
            b32, b1 = bits_type(32), bits_type(1)
            rate, fee, check = GraphBuilder(), GraphBuilder(), GraphBuilder()
            block = rate.block()
            block.ret(block.const(b32, rate_value))
            rate_fn = rate.function((), (b32,))
            block = fee.block(b32)
            block.ret(block.op1(Operation.MUL_WRAP, (block.params[0], block.op1(Operation.CALL_DIRECT, (), b32, entity=rate_fn)), b32))
            fee_fn = fee.function((b32,), (b32,))
            block = check.block()
            called = block.op1(Operation.CALL_DIRECT, (block.const(b32, 4),), b32, entity=fee_fn)
            block.ret(block.op1(Operation.INT_COMPARE, (called, block.const(b32, expected)), b1, attributes=(IntCompare.EQ,)))
            check_fn = check.function((), (b1,))
            objects = {obj.cid: obj for graph in (rate, fee, check) for obj in graph.objects.values()}
            module = object_with_refs(Kind.MODULE, (rate_fn, fee_fn, check_fn))
            root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
            return StoreReader(write_store(root.cid, (*objects.values(), module, root))), rate_fn.cid, check_fn.cid

        reader, rate_cid, check_cid = program(5, 20)
        workspace = Workspace(reader)
        aliases = dict(LocalMutationSession.for_function(workspace, rate_cid).aliases)
        aliases.update({"A" + key[1:]: value for key, value in LocalMutationSession.for_function(workspace, check_cid).aliases.items()})
        result = LocalMutationSession(workspace, aliases).commit("const N0 7; const A2 28")
        self.assertTrue(result.committed)
        self.assertEqual(workspace.root, program(7, 28)[0].root_cid)


if __name__ == "__main__":
    unittest.main()
