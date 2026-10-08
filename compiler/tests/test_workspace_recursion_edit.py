"""ADR-209: semantic transactions edit recursion-group members; the group, its member identities, and their users
are rebuilt, and the member order is re-canonicalized when an edit moves it."""
from __future__ import annotations

import unittest

from test_xax_recursion import parity_group, program
from xax_compiler import Kind, decode_group_member_function, execute, store_resolver, target, verify_store
from xax_local_protocol import LocalMutationSession
from xax_workspace import Workspace


def _entry(workspace: Workspace):
    resolve = store_resolver(workspace.reader)
    module = resolve(resolve(workspace.root).references[0])
    return next(cid for cid in module.references if resolve(cid).kind == Kind.FUNCTION)


def _edit_base(value: int):
    """Set ``even``'s base result (block 1's constant) to ``value`` through a local mutation; return the workspace,
    the entry, and whether the group's member order moved."""
    parity, even, _odd = parity_group()
    reader, entry = program(parity, even, target(b"probe"))
    workspace = Workspace(reader)
    resolve = store_resolver(reader)
    callee = next(node for node in _calls(entry, resolve))
    session = LocalMutationSession.for_function(workspace, callee, limit=256)
    nodes = workspace.function_nodes(callee, 64).entities
    index = next(i for i, node in enumerate(nodes) if ".B1." in node.handle and node.operation.name == "CONSTANT")
    result = session.commit(f"const N{index} {value}")
    return workspace, result, even


def _calls(function_object, resolve):
    from xax_compiler import _decode_function_interface, _parse_graph

    graph, _parameters, _returns = _decode_function_interface(function_object, resolve)
    for block in _parse_graph(graph, resolve).blocks:
        for node in block.nodes:
            if node.entity is not None and node.entity.kind == Kind.FUNCTION:
                yield node.entity.cid


class RecursionMemberEditTests(unittest.TestCase):
    def test_member_edit_commits_and_executes(self):
        moved = []
        for value in range(2, 40):
            with self.subTest(value=value):
                workspace, result, even = _edit_base(value)
                self.assertTrue(result.committed, result.diagnostic)
                verify_store(workspace.reader)
                resolve = store_resolver(workspace.reader)
                entry = _entry(workspace)
                (callee,) = tuple(_calls(resolve(entry), resolve))
                group, member = decode_group_member_function(resolve(callee), resolve)
                moved.append(member != even)
                # even(n) returns the edited base for even n and odd's base 0 for odd n.
                self.assertEqual(execute(workspace.reader, entry, (10,)), (value,))
                self.assertEqual(execute(workspace.reader, entry, (7,)), (0,))
                self.assertEqual(group.kind, Kind.RECURSION_GROUP)
        # Some edits move the canonical member order; those exercised the renumbering path.
        self.assertTrue(any(moved) and not all(moved), moved)

    def test_r5_record_replays_to_its_committed_root(self):
        """The R5 evidence's transaction is reproducible: the pinned root and the agent's edit give the same root."""
        import json
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from benchmarks.bench_r5_maintenance import AGENT_MUTATION, EVIDENCE
        from benchmarks.jsonmin import MAX_DEPTH, build_jsonmin

        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        program = build_jsonmin("jvm")
        self.assertEqual(program.reader.root_cid.hex(), evidence["application"]["original_root"])
        workspace = Workspace(program.reader, program.target)
        holder = None
        pending, seen = [program.entry.cid], set()
        while pending:
            cid = pending.pop()
            if cid in seen:
                continue
            seen.add(cid)
            pending.extend(workspace._function_bindings[view.handle][0] for view in workspace.callees(cid, 64).entities)
            if any(node.constant_value == MAX_DEPTH for node in workspace.function_nodes(cid, 1024).entities):
                holder = cid
        result = LocalMutationSession.for_function(workspace, holder, limit=1024).commit(AGENT_MUTATION)
        self.assertTrue(result.committed)
        self.assertEqual(result.root.hex(), evidence["transaction"]["new_root"])
        self.assertTrue(evidence["tests"]["all_passed"])
        self.assertFalse(evidence["transaction"]["whole_source_regenerated"])


if __name__ == "__main__":
    unittest.main()
