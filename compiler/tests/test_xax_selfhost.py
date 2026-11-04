"""M14 graph introspection: compile-time META operations inspect a function's graph under an explicit capability.

W3 (ADR-362): the M14 semantic-image wrapper's Python recursive-generation tests and its Python zipapp seed are retired;
its store (``bootstrap/m14_selfhost_compiler.xax``) is a frozen corpus program checked by ``test_store_regeneration``.
"""

import unittest


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


if __name__ == "__main__":
    unittest.main()
