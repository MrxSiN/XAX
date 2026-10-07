import unittest
from unittest.mock import patch

from xax_compiler import Block, Kind, Node, Operation, StoreReader, Terminator, ValueRef, bits_type, constant, function, graph_fragment, object_with_refs, write_store
from xax_local_protocol import LocalMutationSession, construct_program
from xax_workspace import RootRef, SetConstant, Transaction, Workspace


def fixture():
    typ = bits_type(32)
    value = constant(typ, 3)
    graph = graph_fragment([Block((typ,), (
        Node(Operation.CONSTANT, (), (typ,), entity=value),
        Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (typ,)),
    ), Terminator.return_((ValueRef.node_result(0, 1),)))])
    fn = function(graph, (typ,), (typ,))
    module = object_with_refs(Kind.MODULE, (fn,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    workspace = Workspace(StoreReader(write_store(root.cid, [typ, value, graph, fn, module, root])))
    return workspace, fn.cid


class LocalProtocolTests(unittest.TestCase):
    def test_bound_fields_use_ordinary_transactions_and_preserve_freshness(self):
        for verb, node, fields in (("const", "N0", "23"), ("op", "N1", "mul.wrap"),
                                   ("operand", "N1", "1 P0"), ("move", "N1", "before N0")):
            for response in (fields, f"{verb} {node} {fields}"):
                workspace, cid = fixture()
                session = LocalMutationSession.for_function(workspace, cid)
                expected = session.transaction(f"{verb} {node} {fields}")
                session.bind(verb, node)
                with patch.object(workspace, "commit", wraps=workspace.commit) as commit:
                    session.commit_bound(response)
                self.assertEqual(commit.call_args.args[0], expected)
        workspace, cid = fixture()
        original = workspace.root
        session = LocalMutationSession.for_function(workspace, cid)
        session.bind("const", "N0")
        changed = session.commit_bound("9")
        fresh = LocalMutationSession.for_function(workspace, changed.changed_entity)
        self.assertTrue(fresh.commit("const N0 3").committed)
        self.assertEqual(workspace.root, original)
        stale = session.commit_bound("7")
        self.assertFalse(stale.committed)
        self.assertEqual(stale.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")

    def test_bound_fields_reject_extra_mutations_unbound_targets_and_alias_drift(self):
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        with self.assertRaisesRegex(ValueError, "no bound"):
            session.commit_bound("7")
        for verb, node in (("const", "N9"), ("delete", "N0")):
            with self.assertRaises(ValueError):
                session.bind(verb, node)
        session.bind("const", "N0")
        session.bind("const", "N0")  # Idempotent; an outstanding request cannot be retargeted.
        with self.assertRaisesRegex(ValueError, "binding already fixed"):
            session.bind("op", "N1")
        original = workspace.root
        for fields in ("7; delete N1", "const N1 7", "op N0 mul.wrap", "7 8", "", "not-an-integer"):
            with self.assertRaises(ValueError):
                session.commit_bound(fields)
            self.assertEqual(workspace.root, original)
        session.aliases["N0"] = session.aliases["N1"]
        with self.assertRaisesRegex(ValueError, "alias changed"):
            session.commit_bound("7")
        self.assertEqual(workspace.root, original)

    def test_bound_scalar_views_are_minimal_and_keep_the_queried_snapshot(self):
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        with self.assertRaisesRegex(ValueError, "no bound"):
            session.view(bound=True)
        session.bind("const", "N0")
        before = session.view(bound=True)
        self.assertEqual(before, "R0.0\nN0 constant 3 bits32")
        self.assertEqual(session.last_view_entities, 3)
        with self.assertRaises(ValueError):
            session.view(functions=(b'\0' * 32,), bound=True)
        self.assertTrue(session.commit_bound("19").committed)
        self.assertEqual(session.view(bound=True), before)
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        session.bind("operand", "N1")
        self.assertEqual(session.view(bound=True), session.view())

    def test_numeric_node_aliases_keep_parameters_distinct_and_preserve_snapshot(self):
        from xax_compiler import execute
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        result = session.commit("replace-operand 1 1 P0")
        self.assertTrue(result.committed)
        self.assertEqual(execute(workspace.reader, result.changed_entity, (3,)), (6,))
        stale = session.commit("set-constant 0 7")
        self.assertFalse(stale.committed)
        diagnostic = session.diagnostic_view(stale.diagnostic)
        self.assertEqual(diagnostic["code"], "XAX.WORKSPACE.STALE_ROOT")
        self.assertEqual(diagnostic["repair"], ["R0.0", "N0"])

    def test_dead_closure_preserves_shared_live_dependencies_and_requires_exposure(self):
        from xax_graph_builder import GraphBuilder
        typ = bits_type(32)
        graph = GraphBuilder()
        block = graph.block(typ)
        zero = block.const(typ, 0)
        block.op1(Operation.MUL_WRAP, (block.params[0], zero), typ)
        block.ret(block.op1(Operation.ADD_WRAP, (block.params[0], zero), typ))
        fn = graph.function((typ,), (typ,))
        module = object_with_refs(Kind.MODULE, (fn,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        reader = StoreReader(write_store(root.cid, (*graph.objects.values(), module, root)))
        workspace = Workspace(reader)
        session = LocalMutationSession.for_function(workspace, fn.cid)
        with self.assertRaises(ValueError):
            session.transaction("prune-dead N2")
        result = session.commit("prune-dead N1")
        self.assertTrue(result.committed)
        self.assertEqual(len(workspace.function_nodes(result.changed_entity, 4).entities), 2)
        # An unshared dependency outside the exposed node set cannot be deleted.
        graph = GraphBuilder()
        block = graph.block(typ)
        block.op1(Operation.MUL_WRAP, (block.params[0], block.const(typ, 0)), typ)
        block.ret(block.params[0])
        fn = graph.function((typ,), (typ,))
        module = object_with_refs(Kind.MODULE, (fn,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        workspace = Workspace(StoreReader(write_store(root.cid, (*graph.objects.values(), module, root))))
        page = workspace.function_nodes(fn.cid, 1, continuation=1)
        session = LocalMutationSession(workspace, {"N0": page.entities[0].handle})
        with self.assertRaisesRegex(ValueError, "exposed neighborhood"):
            session.transaction("prune-dead N0")
        self.assertEqual(workspace.root, root.cid)

    def test_construction_is_canonical_and_rejects_invalid_references(self):
        from xax_compiler import execute, XaxError
        request = {"parameters": [32], "returns": [32], "nodes": [["constant", 32, 19], ["mul.wrap", 32, "P0", "@0"]], "return": ["@1"]}
        reader = construct_program(request)
        cid = next(obj.cid for obj in reader.objects() if obj.kind == Kind.FUNCTION)
        self.assertEqual(execute(reader, cid, (3,)), (57,))
        self.assertEqual(reader.data, construct_program(request).data)
        with self.assertRaises(ValueError):
            construct_program(request, limit=1)
        with self.assertRaises(ValueError):
            construct_program(request | {"return": ["@3"]})
        with self.assertRaises(XaxError):
            construct_program(request | {"returns": [16]})

    def test_atomic_deletion_of_dead_dependency_chain_and_live_use_rejection(self):
        from xax_graph_builder import GraphBuilder
        typ = bits_type(32)
        graph = GraphBuilder()
        block = graph.block(typ)
        dead = block.op1(Operation.MUL_WRAP, (block.params[0], block.const(typ, 0)), typ)
        block.ret(block.params[0])
        fn = graph.function((typ,), (typ,))
        module = object_with_refs(Kind.MODULE, (fn,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        reader = StoreReader(write_store(root.cid, (*graph.objects.values(), module, root)))
        workspace = Workspace(reader)
        session = LocalMutationSession.for_function(workspace, fn.cid)
        original = workspace.root
        rejected = session.commit("delete N0")
        self.assertFalse(rejected.committed)
        self.assertEqual(workspace.root, original)
        committed = session.commit("delete N0; delete N1")
        self.assertTrue(committed.committed)
        from xax_compiler import execute
        self.assertEqual(execute(workspace.reader, committed.changed_entity, (123,)), (123,))
        live = GraphBuilder()
        block = live.block(typ)
        result = block.op1(Operation.MUL_WRAP, (block.params[0], block.const(typ, 0)), typ)
        block.ret(result)
        fn = live.function((typ,), (typ,))
        module = object_with_refs(Kind.MODULE, (fn,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        workspace = Workspace(StoreReader(write_store(root.cid, (*live.objects.values(), module, root))))
        session = LocalMutationSession.for_function(workspace, fn.cid)
        self.assertFalse(session.commit("delete N0; delete N1").committed)
        self.assertEqual(workspace.root, root.cid)

    def test_view_is_snapshot_bound_and_includes_control_and_types(self):
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        before = session.view()
        self.assertIn("N0 constant 3", before)
        self.assertIn("bits32", before)
        self.assertIn("return N1", before)
        self.assertTrue(session.commit("set-constant N0 9").committed)
        self.assertEqual(session.view(), before)

    def test_uniform_result_types_are_declared_once_and_mixed_types_stay_explicit(self):
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        view = session.view()
        self.assertEqual(view.count("node results=(T0)"), 1)
        self.assertIn("N1 add.wrap P0 N0\n", view)
        from xax_graph_builder import GraphBuilder
        graph = GraphBuilder()
        block = graph.block()
        first = block.const(bits_type(8), 7)
        block.const(bits_type(16), 9)
        block.ret(first)
        fn = graph.function((), (bits_type(8),))
        module = object_with_refs(Kind.MODULE, (fn,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        workspace = Workspace(StoreReader(write_store(root.cid, (*graph.objects.values(), module, root))))
        view = LocalMutationSession.for_function(workspace, fn.cid).view()
        self.assertNotIn("node results=", view)
        self.assertEqual(view.count(" -> ("), 2)
        self.assertIn("bits8", view)
        self.assertIn("bits16", view)
        helper = GraphBuilder()
        block = helper.block()
        block.ret(block.const(bits_type(32), 1), block.const(bits_type(32), 2))
        callee = helper.function((), (bits_type(32), bits_type(32)))
        graph = GraphBuilder()
        block = graph.block()
        values = block.op(Operation.CALL_DIRECT, (), (bits_type(32), bits_type(32)), entity=callee)
        block.ret(*values)
        fn = graph.function((), (bits_type(32), bits_type(32)))
        module = object_with_refs(Kind.MODULE, (fn, callee))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        workspace = Workspace(StoreReader(write_store(root.cid, (*(graph.objects | helper.objects).values(), module, root))))
        view = LocalMutationSession.for_function(workspace, fn.cid).view(functions=(fn.cid,))
        self.assertNotIn("node results=", view)
        self.assertIn(" -> (T0,T0)", view)
        self.assertIn("N0.R1", view)

    def test_batch_equals_exact_ordinary_transaction(self):
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        transaction = session.transaction("set-constant N0 7; set-op N1 mul.wrap")
        self.assertEqual(transaction.expected_root, RootRef(0))
        self.assertEqual(transaction.mutations[0].expected, 3)
        self.assertEqual(transaction.mutations[1].expected, Operation.ADD_WRAP)
        self.assertTrue(workspace.commit(transaction).committed)

    def test_old_session_never_refreshes_preconditions(self):
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        self.assertTrue(session.commit("set-constant N0 9").committed)
        # Parsing after the intervening commit still uses the old snapshot.
        transaction = session.transaction("set-constant N0 7")
        self.assertEqual(transaction.mutations[0].expected, 3)
        result = workspace.commit(transaction)
        self.assertFalse(result.committed)
        self.assertEqual(result.diagnostic.code, "XAX.WORKSPACE.STALE_ROOT")

    def test_restoring_root_does_not_revive_old_session(self):
        workspace, cid = fixture()
        original = workspace.root
        session = LocalMutationSession.for_function(workspace, cid)
        result = session.commit("set-constant N0 9")
        fresh = LocalMutationSession.for_function(workspace, result.changed_entity)
        self.assertTrue(fresh.commit("set-constant N0 3").committed)
        self.assertEqual(workspace.root, original)
        self.assertFalse(session.commit("set-op N1 mul.wrap").committed)

    def test_failed_batch_cannot_partially_publish(self):
        workspace, cid = fixture()
        session = LocalMutationSession.for_function(workspace, cid)
        root = workspace.root
        result = session.commit("set-constant N0 7; delete N0")
        self.assertFalse(result.committed)
        self.assertEqual(workspace.root, root)

    def test_unexposed_and_malformed_requests_reject(self):
        for command in ("", "set-constant N9 7", "set-op N1 made.up", "replace-operand N1 -1 P0",
                        "delete N0;", "signature F99 - - - -", "insert-constant N0 -1 7"):
            workspace, cid = fixture()
            session = LocalMutationSession.for_function(workspace, cid)
            root = workspace.root
            with self.assertRaises((ValueError, KeyError)):
                session.transaction(command)
            self.assertEqual(root, workspace.root)

    def test_query_budget_rejects_incomplete_function(self):
        workspace, cid = fixture()
        with self.assertRaisesRegex(ValueError, "budget"):
            LocalMutationSession.for_function(workspace, cid, limit=1)

    def test_generation_change_between_query_and_session_rejects(self):
        workspace, cid = fixture()
        LocalMutationSession.for_function(workspace, cid)
        with self.assertRaisesRegex(ValueError, "stale"):
            LocalMutationSession(workspace, expected_generation=1)

    def test_cross_function_value_cannot_be_reinterpreted_as_local(self):
        workspace, cid = fixture()
        local = LocalMutationSession.for_function(workspace, cid)
        # A value from a different function must not silently become a local
        # ValueRef with the same numeric block/node coordinates.
        handle = local.aliases["P0"]
        owner, value, generation = workspace._value_bindings[handle]
        workspace._value_bindings["Foreign"] = (b"x" * 32, value, generation)
        session = LocalMutationSession(workspace, local.aliases)
        with self.assertRaisesRegex(ValueError, "another function"):
            session.transaction("replace-operand N1 0 Foreign")


if __name__ == "__main__":
    unittest.main()
