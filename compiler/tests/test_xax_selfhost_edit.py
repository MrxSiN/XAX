"""S15d.1 (ADR-304): semantic transactions applied by the production compiler, equal to the Python workspace.

``xax_selfhost_edit`` applies an edit record (``SetOperation`` and ``SetConstant`` mutations, named by function CID,
block and node) to a verified store: the mutated graphs are re-encoded, every transitive user is rebuilt with its
references in CID order, unreachable objects are dropped, and the S9 writer writes the store.  Differential, on random
transactions of one to three mutations over three Linux test programs:

* ``apply_reference`` (Python, every host) equals ``Workspace.commit`` byte for byte when the workspace commits;
* the XAX helpers, run natively with Python in the driver's place, equal it too, and reject exactly where the
  workspace rejects (code and rule; the workspace names a session handle where the record names a CID);
* the general driver's ``edit`` command, a process, writes the same store, which its own ``verify`` accepts.
"""

from __future__ import annotations

import ctypes
import platform
import random
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_selfhost_edit import SET_CONSTANT, SET_OPERATION, apply_reference, edit_record
from xax_workspace import RootRef, SetConstant, SetOperation, Transaction, Workspace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _stores():
    from benchmarks.jsonmin import build_jsonmin
    from test_xax_linux import _crc_program, _status_program

    return [_status_program(lambda b: b.const(X.bits_type(32), 7))[0], _crc_program(X.x86_64_linux_dynamic_exec_target())[0],
            build_jsonmin().reader]


def _candidates(reader):
    """``(function, position in function_nodes order, block, node, node)`` for every arithmetic and constant node."""
    found = []
    for function_object in (item for item in reader.objects() if item.kind == X.Kind.FUNCTION):
        try:  # a graph that parses only in its recursion group's context is left out
            graph = X._parse_graph(reader.get(function_object.references[X.Cursor(function_object.body, "").uleb()]), reader.get)
        except X.XaxError:
            continue
        position = 0
        for b, block in enumerate(graph.blocks):
            for n, node in enumerate(block.nodes):
                if node.operation in (1, 2, 3, X.Operation.CONSTANT):
                    found.append((function_object, position, b, n, node))
                position += 1
    return found


def transactions(seed: int, count: int):
    """``(reader, workspace mutations builder, edit record)`` for random transactions, some failing a precondition."""
    rng = random.Random(seed)
    for reader in _stores():
        candidates = _candidates(reader)
        for _trial in range(count):
            picks = rng.sample(candidates, min(len(candidates), rng.choice((1, 1, 2, 3))))
            if len({(f.cid, b, n) for f, _i, b, n, _node in picks}) != len(picks):
                continue
            mutations, record = [], []
            for f, i, b, n, node in picks:
                if node.operation == X.Operation.CONSTANT:
                    width = X.decode_bits_width(reader.get(node.entity.references[0]))
                    old = int.from_bytes(node.entity.body[2:], "little")
                    value = (1 << width) if width < 64 and rng.random() < 0.1 else rng.randrange(1 << min(width, 64))
                    expected = old if rng.random() < 0.9 else old ^ 1
                    mutations.append((f.cid, i, lambda handle, e=expected, v=value: SetConstant(handle, e, v)))
                    record.append((SET_CONSTANT, f.cid, b, n, expected, value))
                else:
                    value = rng.choice([op for op in (1, 2, 3) if op != node.operation])
                    expected = int(node.operation) if rng.random() < 0.9 else (int(node.operation) % 3) + 1
                    mutations.append((f.cid, i, lambda handle, e=expected, v=value: SetOperation(handle, X.Operation(e), X.Operation(v))))
                    record.append((SET_OPERATION, f.cid, b, n, expected, value))
            yield reader, mutations, edit_record(record, reader.root_cid if rng.random() < 0.5 else bytes(32))


# -- S15d.4b (ADR-314): the workspace's structural mutations ---------------------------------------------------------

def _graphs(reader):
    found = []
    for function_object in (item for item in reader.objects() if item.kind == X.Kind.FUNCTION):
        try:
            graph = X._parse_graph(reader.get(function_object.references[X.Cursor(function_object.body, "").uleb()]), reader.get)
        except X.XaxError:
            continue
        if any(block.nodes for block in graph.blocks):
            found.append((function_object, graph))
    return found


def _available(graph, b, n):
    """``(value, type CID)`` usable before node ``n`` of block ``b``."""
    block = graph.blocks[b]
    values = [(X.ValueRef.parameter(b, i), t) for i, t in enumerate(block.parameters)]
    for j, node in enumerate(block.nodes[:n]):
        values += [(X.ValueRef.node_result(b, j, r), t) for r, t in enumerate(node.results)]
    return values


def structural_oracle(reader, mutations):
    """``Workspace.commit`` for a record's mutations: ``("store", bytes)``, ``("rejected", diagnostic)``, or None when the
    workspace has no handle for them."""
    from xax_selfhost_edit import workspace_mutations

    try:
        workspace, made = workspace_mutations(reader, mutations)
    except ValueError:
        return None
    result = workspace.commit(Transaction(RootRef(0), made))
    return ("store", workspace.reader.data) if result.committed else ("rejected", result.diagnostic)


def structural_transactions(seed: int, count: int):
    """``(case, reader, mutations)``: random insertions (a constant; a wrapping add, then used by the next node or an
    edge), uses replaced, deletions, result types set, edge arguments disconnected and connected, each also with its
    preconditions broken; and two-step cases (an insertion committed, then deleted or retyped)."""
    import xax_selfhost_edit as EDT
    from xax_workspace import TransactionValueRef as T

    V, rng = X.ValueRef, random.Random(seed)
    for reader in _stores():
        functions = _graphs(reader)
        for _trial in range(count):
            f, graph = rng.choice(functions)
            b = rng.choice([index for index, block in enumerate(graph.blocks) if block.nodes])
            block = graph.blocks[b]
            n = rng.randrange(len(block.nodes))
            node = block.nodes[n]
            bits = sorted({t for item in graph.blocks for other in item.nodes if other.operation == X.Operation.CONSTANT for t in other.results})
            if not bits:
                continue
            t = rng.choice(bits)
            case = rng.choice(("constant", "add", "add", "use", "delete", "type", "edge", "edge", "bad", "bad", "two-step"))
            if case == "constant":
                width = X.decode_bits_width(reader.get(t))
                yield case, reader, [(EDT.INSERT_NODE, f.cid, b, n, 0, X.Operation.CONSTANT, (), t, rng.randrange(1 << min(width, 16)), ())]
            elif case == "add":
                typed = {}
                for value, value_type in _available(graph, b, n):
                    if reader.get(value_type).body[:1] == b"\x01":
                        typed.setdefault(value_type, []).append(value)
                if not typed:
                    continue
                t = rng.choice(sorted(typed))
                mutations = [(EDT.INSERT_NODE, f.cid, b, n, 3, X.Operation.ADD_WRAP, (rng.choice(typed[t]), rng.choice(typed[t])), t, None, ())]
                if n + 1 < len(block.nodes) and block.nodes[n + 1].operands and rng.random() < 0.7:
                    after = block.nodes[n + 1]
                    k = rng.choice([k for k, o in enumerate(after.operands) if k < len(after.operand_types) and after.operand_types[k] == t]
                                   or list(range(len(after.operands))))
                    mutations.append((EDT.REPLACE_USE, f.cid, b, n + 1, k, after.operands[k], T(3, 0)))
                elif block.terminator.edges and block.terminator.edges[0][1]:
                    mutations += [(EDT.DISCONNECT_EDGE, f.cid, b, 0, 0, block.terminator.edges[0][1][0]), (EDT.CONNECT_EDGE, f.cid, b, 0, 0, T(3, 0))]
                yield case, reader, mutations
            elif case == "use" and node.operands:
                k = rng.randrange(len(node.operands)) if rng.random() < 0.9 else len(node.operands) + 1
                expected = node.operands[k] if k < len(node.operands) and rng.random() < 0.9 else V.node_result(b, 99, 0)
                choices = [value for value, _type in _available(graph, b, n)]
                if choices:
                    yield case, reader, [(EDT.REPLACE_USE, f.cid, b, n, k, expected, rng.choice(choices))]
            elif case == "delete":
                yield case, reader, [(EDT.DELETE_NODE, f.cid, b, n)]
            elif case == "type" and node.results:
                r = rng.randrange(len(node.results)) if rng.random() < 0.9 else len(node.results)
                expected = node.results[min(r, len(node.results) - 1)] if rng.random() < 0.9 else t
                yield case, reader, [(EDT.SET_RESULT_TYPE, f.cid, b, n, r, expected, t)]
            elif case == "edge" and block.terminator.edges:
                edge = rng.randrange(len(block.terminator.edges))
                arguments = block.terminator.edges[edge][1]
                choices = [value for value, _type in _available(graph, b, len(block.nodes))]
                if arguments and rng.random() < 0.6:
                    a = rng.randrange(len(arguments))
                    mutations = [(EDT.DISCONNECT_EDGE, f.cid, b, edge, a, arguments[a] if rng.random() < 0.9 else V.parameter(b, 9))]
                    if choices and rng.random() < 0.7:
                        mutations.append((EDT.CONNECT_EDGE, f.cid, b, edge, a, rng.choice(choices)))
                    yield case, reader, mutations
                elif choices:
                    yield case, reader, [(EDT.CONNECT_EDGE, f.cid, b, edge, rng.randrange(len(arguments) + 2), rng.choice(choices))]
            elif case == "two-step":
                made = structural_oracle(reader, [(EDT.INSERT_NODE, f.cid, b, n, 0, X.Operation.CONSTANT, (), t, 1, ())])
                if made is None or made[0] != "store":
                    continue
                after = X.StoreReader(made[1])
                g = next(item for item, parsed in _graphs(after) if len(parsed.blocks) == len(graph.blocks)
                         and len(parsed.blocks[b].nodes) == len(block.nodes) + 1 and parsed.blocks[b].nodes[n].operation == X.Operation.CONSTANT
                         and parsed.blocks[b].nodes[n].results == (t,))
                if rng.random() < 0.6:
                    yield "two-step delete", after, [(EDT.DELETE_NODE, g.cid, b, n)]
                else:
                    yield "two-step type", after, [(EDT.SET_RESULT_TYPE, g.cid, b, n, 0, t, rng.choice(bits))]
            elif case == "bad":
                later = n + 1 if n + 1 < len(block.nodes) else n
                broken = {
                    "local": [(EDT.REPLACE_USE, f.cid, b, n, 0, node.operands[0], T(5, 0))] if node.operands else None,
                    "duplicate local": [(EDT.INSERT_NODE, f.cid, b, n, 1, X.Operation.CONSTANT, (), t, 1, ()),
                                        (EDT.INSERT_NODE, f.cid, b, later, 1, X.Operation.CONSTANT, (), t, 2, ())],
                    "no value": [(EDT.INSERT_NODE, f.cid, b, n, 0, X.Operation.CONSTANT, (), t, None, ())],
                    "a value": [(EDT.INSERT_NODE, f.cid, b, n, 0, X.Operation.ADD_WRAP, (), t, 4, ())],
                    "edge": [(EDT.DISCONNECT_EDGE, f.cid, b, 5, 0, V.parameter(0, 0))],
                    "impure": [(EDT.INSERT_NODE, f.cid, b, n, 0, X.Operation.UDIV, (), t, None, ())],
                    "result": [(EDT.SET_RESULT_TYPE, f.cid, b, n, len(node.results), t, t)],
                    "range": [(EDT.INSERT_NODE, f.cid, b, n, 0, X.Operation.CONSTANT, (), t, (1 << 63) + 5, ())],
                    "local result": [(EDT.INSERT_NODE, f.cid, b, n, 2, X.Operation.CONSTANT, (), t, 1, ()),
                                     (EDT.INSERT_NODE, f.cid, b, later, 4, X.Operation.ADD_WRAP, (T(2, 1), T(2, 0)), t, None, ())],
                }
                name = rng.choice(sorted(broken))
                if broken[name]:
                    yield name, reader, broken[name]


# The workspace's own checks the engine reproduces exactly; any other rejection is the candidate's verification, which
# the engine leaves to ``verify`` (the driver runs it after ``edit``).
STRUCTURAL_RULES = {
    "WORKSPACE-OPERAND-INDEX", "WORKSPACE-OPERAND-PRECONDITION", "WORKSPACE-DELETE-PURE-NODE", "WORKSPACE-DELETE-NODE-UNUSED",
    "WORKSPACE-INSERT-PURE-NODE", "WORKSPACE-INSERT-CONSTANT-VALUE", "WORKSPACE-INSERT-CONSTANT-ABSENT", "WORKSPACE-INSERT-LOCAL-VALUE",
    "WORKSPACE-INSERT-LOCAL-RESULT", "WORKSPACE-INSERT-LOCAL-ID-UNIQUE", "WORKSPACE-RESULT-INDEX", "WORKSPACE-RESULT-TYPE-PRECONDITION",
    "WORKSPACE-CONSTANT-SINGLE-RESULT", "WORKSPACE-CONSTANT-RANGE", "WORKSPACE-TERMINATOR-EDGE", "WORKSPACE-EDGE-ARGUMENT-INDEX",
    "WORKSPACE-EDGE-ARGUMENT-PRECONDITION", "WORKSPACE-MUTATION-TARGET-UNIQUE", "WORKSPACE-RECURSION-REBUILD",
}


def write_batch(batch: bytes) -> bytes:
    """The store the S9 writer makes from ``batch`` (its layout: count, zero, end, root CID, then per object its kind,
    schema, reference count, body length, CID, references, body), by the bootstrap's writer: every object's CID is
    re-derived, as the S9 writer does."""
    word = lambda at: int.from_bytes(batch[at:at + 8], "little")  # noqa: E731
    count, end, root = word(0), word(16), batch[24:56]
    assert end == len(batch)
    at, objects = 56, []
    for _ in range(count):
        kind, schema, references, length = (word(at + 8 * k) for k in range(4))
        cid = batch[at + 32:at + 64]
        refs = [batch[at + 64 + 32 * k:at + 96 + 32 * k] for k in range(references)]
        body = batch[at + 64 + 32 * references:at + 64 + 32 * references + length]
        item = X.SemanticObject.create(X.Kind(kind), body, refs, schema)
        assert item.cid == cid, "a batch CID differs from its object's"
        objects.append(item)
        at += 64 + 32 * references + length
    assert at == end
    return X.write_store(root, objects)


def commit(reader, mutations):
    workspace = Workspace(reader)
    made = tuple(make(workspace.function_nodes(cid, 1 << 20).entities[i].handle) for cid, i, make in mutations)
    result = workspace.commit(Transaction(RootRef(0), made))
    return ("store", workspace.reader.data) if result.committed else ("rejected", result.diagnostic)


class ReferenceTests(unittest.TestCase):
    def test_reference_equals_the_workspace(self):
        committed = 0
        for reader, mutations, record in transactions(303, 10):
            expected = commit(reader, mutations)
            if expected[0] == "store":
                self.assertEqual(apply_reference(reader, record).data, expected[1])
                committed += 1
        self.assertGreater(committed, 5)


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the helper images run on Linux x86-64 only")
class XaxEditTests(unittest.TestCase):
    """The helpers alone, natively; Python hashes each preimage and assembles the store, as the driver does."""

    @classmethod
    def setUpClass(cls):
        import xax_selfhost_edit as EDT
        import xax_selfhost_semantic as SM
        from xax_graph_builder import program_store
        from xax_native import zeroed_array
        from xax_selfhost_typing import IN_WORDS, OUT_WORDS
        from xax_x86_64_views import NativeViewsImage, compile_x86_64_views

        building = X._TYPING_BUILDING
        X._TYPING_BUILDING = True
        try:
            functions, objects = EDT.build_functions()
            semantic, semantic_objects = SM.build_functions()
        finally:
            X._TYPING_BUILDING = building
        cls.EDT, cls.images = EDT, {}
        target = X.x86_64_views_target()
        helpers = {name: (functions, objects) for name in ("edit_begin", "edit_next", "edit_place", "edit_reach", "edit_batch")}
        for name, (table, items) in {**helpers, "index_objects": (semantic, semantic_objects)}.items():
            reader = program_store(table[name], X.x86_64_linux_exec_target(), items)
            cls.images[name] = NativeViewsImage(compile_x86_64_views(reader, table[name].cid, target, backend="python"))
        cls.input = zeroed_array(ctypes.c_uint64, IN_WORDS)
        cls.output = zeroed_array(ctypes.c_uint64, OUT_WORDS)

    def call(self, name: str) -> int:
        return self.images[name](ctypes.addressof(self.input), ctypes.addressof(self.output))

    def edit(self, reader, record: bytes):
        from blake3 import blake3
        import xax_selfhost_diagnostics as D
        from xax_selfhost_verify import object_table

        EDT, out = self.EDT, self.output
        listed = list(reader.objects())
        index = {item.cid: position for position, item in enumerate(listed)}
        words = object_table(listed, [index[reader.root_cid]])
        self.input[:len(words)] = words
        self.call("index_objects")
        for k, byte in enumerate(record):
            out[EDT.EIN + k] = byte
        out[EDT.EC + EDT.E_LENGTH] = len(record)

        def rejected():
            return "rejected", D.decode_record([out[k] for k in range(D.DIAG_AT + 1, out[D.DIAG_AT])])

        self.call("edit_begin")
        if out[EDT.EC + EDT.E_STATUS] == EDT.REJECT:
            return rejected()
        while self.call("edit_next") == EDT.MORE:
            at, length = out[EDT.EC + EDT.E_PRE_AT], out[EDT.EC + EDT.E_PRE_LENGTH]
            cid = blake3(X.SEMANTIC_DOMAIN + bytes(out[at + k] for k in range(length))).digest()
            slot = out[EDT.EC + EDT.E_SLOT]
            for k in range(4):
                out[slot + k] = int.from_bytes(cid[8 * k:8 * k + 8], "big")
            self.call("edit_place")
        if out[EDT.EC + EDT.E_STATUS] == EDT.REJECT:
            return rejected()
        self.call("edit_reach")
        self.call("edit_batch")
        if out[EDT.EC + EDT.E_STATUS] == EDT.REJECT:
            return rejected()
        return "store", write_batch(bytes(out[EDT.BATCH + k] for k in range(out[EDT.EC + EDT.E_BATCH_LENGTH])))

    def test_transactions_equal_the_workspace(self):
        outcomes = set()
        for reader, mutations, record in transactions(3031, 12):
            expected, actual = commit(reader, mutations), self.edit(reader, record)
            if expected[0] == "store":
                self.assertEqual(actual, expected)
            else:
                self.assertEqual((actual[0], actual[1].code, actual[1].rule), ("rejected", expected[1].code, expected[1].rule))
            outcomes.add(expected[0] if expected[0] == "store" else expected[1].rule)
        self.assertTrue({"store", "WORKSPACE-RECURSION-REBUILD", "WORKSPACE-CONSTANT-PRECONDITION"} <= outcomes, outcomes)

    def test_record_rejections(self):
        reader, (f, i, b, n, node) = next((reader, item) for reader in _stores() for item in _candidates(reader)
                                          if item[4].operation in (1, 2, 3) and commit(reader, [(item[0].cid, item[1], lambda handle, op=int(
                                              item[4].operation): SetOperation(handle, X.Operation(op), X.Operation(1 + op % 3)))])[0] == "store")
        good = edit_record([(SET_OPERATION, f.cid, b, n, int(node.operation), 1 + int(node.operation) % 3)])
        cases = {
            "WORKSPACE-EXPECTED-ROOT": edit_record([(SET_OPERATION, f.cid, b, n, int(node.operation), 1)], b"\x01" * 32),
            "EDIT-RECORD-MAGIC": b"XAXEDIT2" + good[8:],
            "EDIT-RECORD-ULEB": good[:-1],
            "EDIT-RECORD-END": good + b"\x00",
            "WORKSPACE-MUTATION-NONEMPTY": edit_record([]),
            "WORKSPACE-HANDLE-GENERATION": edit_record([(SET_OPERATION, bytes(32), 0, 0, 1, 2)]),
            "WORKSPACE-NODE-INDEX": edit_record([(SET_OPERATION, f.cid, b, 1 << 20, 1, 2)]),
            "WORKSPACE-MUTATION-TARGET-UNIQUE": edit_record([(SET_OPERATION, f.cid, b, n, 1, 2), (SET_OPERATION, f.cid, b, n, 1, 3)]),
            "EDIT-RECORD-KIND": good[:41] + b"\x0a" + good[42:],
            "WORKSPACE-OP-CONTRACT-PRESERVED": edit_record([(SET_OPERATION, f.cid, b, n, int(node.operation), int(X.Operation.UDIV))]),
            "WORKSPACE-OP-PRECONDITION": edit_record([(SET_OPERATION, f.cid, b, n, 1 + int(node.operation) % 3, 1)]),
        }
        for rule, record in cases.items():
            with self.subTest(rule):
                kind, diagnostic = self.edit(reader, record)
                self.assertEqual((kind, diagnostic.rule), ("rejected", rule))
        self.assertEqual(self.edit(reader, good), ("store", apply_reference(reader, good).data))

    def test_structural_transactions(self):
        """S15d.4b (ADR-314): every structural transaction the workspace commits gives the same store; every one it
        rejects with its own check rejects with the same code, rule, expected and actual."""
        from xax_selfhost_edit import edit_record

        outcomes = set()
        for case, reader, mutations in structural_transactions(8, 30):
            expected = structural_oracle(reader, mutations)
            if expected is None:
                continue
            actual = self.edit(reader, edit_record(mutations))
            with self.subTest(case=case, mutations=repr(mutations)[:300]):
                if expected[0] == "store":
                    self.assertEqual(actual, expected)
                    outcomes.add(f"{case}: store")
                elif expected[1].rule in STRUCTURAL_RULES:
                    self.assertEqual(actual[0], "rejected")
                    self.assertEqual((actual[1].code, actual[1].rule), (expected[1].code, expected[1].rule))
                    if expected[1].rule != "WORKSPACE-RECURSION-REBUILD":  # the topology check names the group by handle
                        self.assertEqual((actual[1].expected, actual[1].actual), (expected[1].expected, expected[1].actual))
                    outcomes.add(expected[1].rule)
        self.assertTrue({"constant: store", "add: store", "use: store", "type: store", "two-step delete: store", "two-step type: store",
                         "WORKSPACE-DELETE-NODE-UNUSED", "WORKSPACE-DELETE-PURE-NODE", "WORKSPACE-INSERT-LOCAL-ID-UNIQUE", "WORKSPACE-CONSTANT-RANGE",
                         "WORKSPACE-INSERT-PURE-NODE", "WORKSPACE-RESULT-INDEX", "WORKSPACE-TERMINATOR-EDGE"} <= outcomes, outcomes)


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class EditCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 900
        cls.directory = Path(tempfile.mkdtemp())

    def test_edit_then_verify(self):
        from xax_selfhost_diagnostics import decode_record

        store, record_path, output, verified = (self.directory / name for name in ("store.xax", "edit.bin", "out.xax", "verify.bin"))
        seen = set()
        for reader, mutations, record in transactions(30311, 3):
            store.write_bytes(reader.data)
            record_path.write_bytes(record)
            output.unlink(missing_ok=True)
            status = self.driver._process("edit", store, record_path, output)
            expected = commit(reader, mutations)
            if status == 2:  # the driver declines to verify the store (an S15b.3d decline): no claim, no output
                self.assertFalse(output.exists())
                seen.add("declined")
                continue
            if expected[0] == "store":
                self.assertEqual((status, output.read_bytes()), (0, expected[1]))
                # The workspace verified the candidate; the driver accepts it or declines (an S15b.3d decline), never rejects.
                verdict = self.driver.verify(output, verified)
                self.assertIn(verdict, (0, 2))
                seen.add(f"verify {verdict}")
            else:
                self.assertEqual(record_path.read_bytes(), record)  # the input record is never written
                data = output.read_bytes()
                diagnostic = decode_record([int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)])
                self.assertEqual((status, diagnostic.code, diagnostic.rule), (1, expected[1].code, expected[1].rule))
            seen.add(expected[0])
        self.assertTrue({"store", "verify 0"} <= seen, seen)

    def test_replace_reference(self):
        """S15d.4a (ADR-312): a reference replaced by an object the record supplies: the store equals the Python
        reference and the program built with the new object directly, and verifies; the rejections are the engine's."""
        import xax_compiler as X
        from test_xax_linux import _status_program
        from xax_selfhost_diagnostics import decode_record
        from xax_selfhost_edit import REPLACE_REFERENCE, apply_reference, edit_record

        def entry_of(reader):
            module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
            return module, next(reader.get(cid) for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)

        reader = _status_program(lambda b: b.const(X.bits_type(32), 7))[0]
        other = _status_program(lambda b: b.const(X.bits_type(32), 9))[0]
        module, old_function = entry_of(reader)
        _module, new_function = entry_of(other)
        graph_of = lambda store, f: store.get(f.references[X.Cursor(f.body, "").uleb()])  # noqa: E731
        old_graph, new_graph = graph_of(reader, old_function), graph_of(other, new_function)
        stored = {item.cid for item in reader.objects()}
        supplied = [item for item in other.objects() if item.cid not in stored and item.kind not in (X.Kind.MODULE, X.Kind.PROGRAM_ROOT)]
        store, record_path, output, verified = (self.directory / name for name in ("store.xax", "edit.bin", "out.xax", "verify.bin"))
        store.write_bytes(reader.data)

        def run(record):
            record_path.write_bytes(record)
            output.unlink(missing_ok=True)
            status = self.driver._process("edit", store, record_path, output)
            data = output.read_bytes() if output.exists() else None
            if status == 1:
                return status, decode_record([int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)]).rule
            return status, data

        for name, mutation in (("graph", (REPLACE_REFERENCE, old_function.cid, old_graph.cid, new_graph.cid)),
                               ("function", (REPLACE_REFERENCE, module.cid, old_function.cid, new_function.cid))):
            with self.subTest(name):
                record = edit_record([mutation], reader.root_cid, supplied + [X.constant(X.bits_type(32), 12345)])  # one unreached
                status, data = run(record)
                self.assertEqual((status, data), (0, apply_reference(reader, record).data))
                self.assertEqual(data, other.data)
                self.assertEqual(self.driver.verify(output, verified), 0)
        for name, mutation, objects, rule in (
                ("not a reference", (REPLACE_REFERENCE, old_function.cid, new_graph.cid, new_graph.cid), supplied, "EDIT-REFERENCE-PRECONDITION"),
                ("no owner", (REPLACE_REFERENCE, bytes(32), old_graph.cid, new_graph.cid), supplied, "WORKSPACE-HANDLE-GENERATION"),
                ("no new child", (REPLACE_REFERENCE, old_function.cid, old_graph.cid, new_graph.cid), [], "EDIT-REFERENCE-TARGET"),
                ("a supplied object naming nothing", (REPLACE_REFERENCE, old_function.cid, old_graph.cid, new_graph.cid),
                 [item for item in supplied if item.kind != X.Kind.CONSTANT], "EDIT-OBJECT-REFERENCE")):
            with self.subTest(name):
                self.assertEqual(run(edit_record([mutation], reader.root_cid, objects)), (1, rule))

    def test_structural_edit_then_verify(self):
        """S15d.4b: the driver's ``edit`` applies structural transactions as the workspace does, and verifies the result."""
        from xax_selfhost_diagnostics import decode_record
        from xax_selfhost_edit import edit_record

        store, record_path, output, verified = (self.directory / name for name in ("store.xax", "edit.bin", "out.xax", "verify.bin"))
        seen = set()
        for case, reader, mutations in structural_transactions(9, 6):
            expected = structural_oracle(reader, mutations)
            if expected is None or (expected[0] == "rejected" and expected[1].rule not in STRUCTURAL_RULES):
                continue
            store.write_bytes(reader.data)
            record_path.write_bytes(edit_record(mutations))
            output.unlink(missing_ok=True)
            status = self.driver._process("edit", store, record_path, output)
            if expected[0] == "store":
                self.assertEqual((status, output.read_bytes()), (0, expected[1]))
                verdict = self.driver.verify(output, verified)
                self.assertIn(verdict, (0, 2))
                seen.add(f"verify {verdict}")
            else:
                data = output.read_bytes()
                diagnostic = decode_record([int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)])
                self.assertEqual((status, diagnostic.code, diagnostic.rule), (1, expected[1].code, expected[1].rule))
                seen.add("rejected")
        self.assertTrue({"verify 0", "rejected"} <= seen, seen)


# -- S16a (ADR-360): the native workspace's ``view`` and ``apply`` ---------------------------------------------------
# ``ws_view``/``ws_listing``: the text ``view`` writes, computed in Python from the parsed graph (the reference the XAX
# helpers are compared with); ``ws_random_batch``: an ``apply`` batch and the same edits in ``LocalMutationSession``'s
# long verbs, whose commit is the reference for the store ``apply`` makes.
def _ws_name(op):
    try:
        return X.Operation(op).name.lower().replace("_", ".")
    except ValueError:
        return f"op{op}"

def _ws_type_text(obj):
    cur = X.Cursor(obj.body, "")
    form = cur.uleb()
    if form == 1:
        return f"bits{cur.uleb()}"
    return f"form{form} {obj.cid.hex()}"

def ws_functions(reader):
    return [o for o in reader.objects() if o.kind == X.Kind.FUNCTION]

def ws_listing(reader):
    lines = [f"R {reader.root_cid.hex()}"]
    for n, f in enumerate(ws_functions(reader)):
        graph = reader.get(f.references[X.Cursor(f.body, "").uleb()])
        lines.append(f"F{n} {f.cid.hex()}" + (" group-member" if graph.kind != X.Kind.GRAPH_FRAGMENT else ""))
    return "\n".join(lines) + "\n"

def ws_view(reader, n):
    fs = ws_functions(reader)
    f = fs[n]
    ford = {o.cid: k for k, o in enumerate(fs)}
    cur = X.Cursor(f.body, "")
    graph = reader.get(f.references[cur.uleb()])
    params = [f.references[cur.uleb()] for _ in range(cur.uleb())]
    returns = [f.references[cur.uleb()] for _ in range(cur.uleb())]
    parsed = X._parse_graph(graph, reader.get)
    types = {}
    def t(cid):
        return types.setdefault(cid, len(types))
    for c in params + returns: t(c)
    nstart, pstart, ni, pi = [], [], 0, 0
    for block in parsed.blocks:
        nstart.append(ni); pstart.append(pi)
        for c in block.parameters: t(c)
        for node in block.nodes:
            for c in node.results: t(c)
        ni += len(block.nodes); pi += len(block.parameters)
    def val(v):
        if v.tag == 0:
            return f"P{pstart[v.block] + v.index}"
        return f"N{nstart[v.block] + v.index}" + (f".R{v.result}" if v.result else "")
    lines = [f"R {reader.root_cid.hex()}", f"F{n} {f.cid.hex()}",
             "(" + ",".join(f"T{t(c)}" for c in params) + ")->(" + ",".join(f"T{t(c)}" for c in returns) + ")"]
    if parsed.entry:
        lines.append(f"entry B{parsed.entry}")
    ni, pi = 0, 0
    for b, block in enumerate(parsed.blocks):
        ps = []
        for c in block.parameters:
            ps.append(f"P{pi}:T{t(c)}"); pi += 1
        lines.append(f"B{b}(" + ",".join(ps) + ")")
        for node in block.nodes:
            line = f"N{ni} {_ws_name(node.operation)}"
            if node.entity is not None:
                if node.operation == X.Operation.CONSTANT:
                    body = X.Cursor(node.entity.body, ""); body.uleb(); value = body.byte_string()
                    line += f" {int.from_bytes(value, 'little')}" if len(value) <= 8 else " 0x" + value[::-1].hex()
                elif node.entity.cid in ford:
                    line += f" entity=F{ford[node.entity.cid]}"
                else:
                    line += f" entity={node.entity.cid.hex()}"
            if node.operation == X.Operation.CALL_GROUP_MEMBER:
                line += f" member={node.member}"
            for v in node.operands:
                line += " " + val(v)
            if node.results:
                line += " ->" + ",".join(f" T{t(c)}" if k == 0 else f"T{t(c)}" for k, c in enumerate(node.results))
            if node.attributes:
                line += " [" + ",".join(str(a) for a in node.attributes) + "]"
            lines.append(line); ni += 1
        term = block.terminator
        edge = lambda e: f"B{e[0]}(" + ",".join(val(v) for v in e[1]) + ")"
        if term.kind == X.TerminatorKind.BRANCH:
            lines.append("br " + edge(term.edges[0]))
        elif term.kind == X.TerminatorKind.CONDITIONAL_BRANCH:
            lines.append(f"cbr {val(term.values[0])} {edge(term.edges[0])} {edge(term.edges[1])}")
        elif term.kind == X.TerminatorKind.RETURN:
            lines.append("ret" + "".join(" " + val(v) for v in term.values))
        else:
            lines.append("trap")
    for cid, k in sorted(types.items(), key=lambda i: i[1]):
        lines.append(f"T{k} {_ws_type_text(reader.get(cid))}")
    return "\n".join(lines) + "\n"


def ws_random_batch(reader, n, rng):
    f = ws_functions(reader)[n]
    cur = X.Cursor(f.body, "")
    graph = reader.get(f.references[cur.uleb()])
    parsed = X._parse_graph(graph, reader.get)
    nodes = [(b, k, node) for b, block in enumerate(parsed.blocks) for k, node in enumerate(block.nodes)]
    nparams = sum(len(bl.parameters) for bl in parsed.blocks)
    if not nodes:
        return None
    def value():
        r = rng.random()
        if r < 0.3 and nparams:
            return f"P{rng.randrange(nparams)}"
        i = rng.randrange(len(nodes))
        return f"N{i}"
    native, python = [], []
    used = set()
    for _ in range(rng.choice((1, 1, 2, 3))):
        i = rng.randrange(len(nodes))
        if i in used:
            continue
        used.add(i)
        b, k, node = nodes[i]
        kind = rng.random()
        if node.operation == X.Operation.CONSTANT and kind < 0.4:
            width = X.decode_bits_width(reader.get(node.results[0])) if node.results else 8
            v = rng.randrange(1 << min(width, 63))
            native.append(f"const N{i} {v}"); python.append(f"set-constant N{i} {v}")
        elif node.operation in (1, 2, 3) and kind < 0.5:
            op = rng.choice(["add.wrap", "sub.wrap", "mul.wrap"])
            native.append(f"op N{i} {op}"); python.append(f"set-op N{i} {op}")
        elif node.operands and kind < 0.7:
            j = rng.randrange(len(node.operands)); v = value()
            native.append(f"operand N{i} {j} {v}"); python.append(f"replace-operand N{i} {j} {v}")
        elif kind < 0.8:
            native.append(f"delete N{i}"); python.append(f"delete N{i}")
        elif kind < 0.9 and len(node.results) == 1:
            v = rng.randrange(100)
            native.append(f"insert-constant N{i} 0 {v}"); python.append(f"insert-constant N{i} 0 {v}")
            used.add(-1)
        else:
            term = parsed.blocks[b].terminator
            if term.edges and any(args for _t, args in term.edges) and k == 0:
                e = rng.choice([q for q, (_t, args) in enumerate(term.edges) if args])
                a = rng.randrange(len(term.edges[e][1])); v = value()
                native.append(f"edge N{i} {e} {a} {v}"); python.append(f"set-edge N{i} {e} {a} {v}")
            else:
                native.append(f"delete N{i}"); python.append(f"delete N{i}")
    if not native:
        return None
    if len([x for x in native if x.startswith("insert")]) > 1:
        return None
    root = reader.root_cid.hex()
    return (f"R {root}\nF{n}\n" + "; ".join(native)).encode(), "; ".join(python)


def ws_python_commit(reader, n, command):
    """``LocalMutationSession``'s commit of ``command`` on function handle ``n``: the store, or the rejection."""
    from xax_local_protocol import LocalMutationSession

    workspace = Workspace(reader)
    session = LocalMutationSession.for_function(workspace, ws_functions(reader)[n].cid, limit=1 << 16)
    try:
        result = session.commit(command)
    except (ValueError, X.XaxError) as error:
        return "error", str(error)
    return ("store", workspace.reader.data) if result.committed else ("rejected", result.diagnostic)


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the helper images run on Linux x86-64 only")
class NativeWorkspaceTests(unittest.TestCase):
    """S16a (ADR-360): ``ws_view`` and ``ws_translate`` natively, with the edit engine applying the translated record."""

    call = XaxEditTests.call
    edit = XaxEditTests.edit

    @classmethod
    def setUpClass(cls):
        import xax_selfhost_edit as EDT
        import xax_selfhost_semantic as SM
        from xax_graph_builder import program_store
        from xax_native import zeroed_array
        from xax_selfhost_typing import IN_WORDS, OUT_WORDS
        from xax_x86_64_views import NativeViewsImage, compile_x86_64_views

        building = X._TYPING_BUILDING
        X._TYPING_BUILDING = True
        try:
            functions, objects = EDT.build_functions()
            semantic, semantic_objects = SM.build_functions()
        finally:
            X._TYPING_BUILDING = building
        cls.EDT, cls.images = EDT, {}
        target = X.x86_64_views_target()
        helpers = {name: (functions, objects) for name in ("edit_begin", "edit_next", "edit_place", "edit_reach", "edit_batch", "ws_view", "ws_translate",
                                                            "ws_explain", "ws_command")}
        for name, (table, items) in {**helpers, "index_objects": (semantic, semantic_objects)}.items():
            reader = program_store(table[name], X.x86_64_linux_exec_target(), items)
            cls.images[name] = NativeViewsImage(compile_x86_64_views(reader, table[name].cid, target, backend="python"))
        cls.input = zeroed_array(ctypes.c_uint64, IN_WORDS)
        cls.output = zeroed_array(ctypes.c_uint64, OUT_WORDS)

    def _text(self, reader, text: bytes, helper: str):
        from xax_selfhost_verify import object_table
        import xax_selfhost_diagnostics as D

        EDT, out = self.EDT, self.output
        listed = list(reader.objects())
        index = {item.cid: position for position, item in enumerate(listed)}
        words = object_table(listed, [index[reader.root_cid]])
        self.input[:len(words)] = words
        self.call("index_objects")
        for k, byte in enumerate(text):
            out[EDT.WS_IN + k] = byte
        out[EDT.WSC + EDT.W_LEN] = len(text)
        out[EDT.WSC + EDT.W_TEXT] = 0
        self.call(helper)
        if out[EDT.EC + EDT.E_STATUS] == EDT.REJECT:
            return "rejected", D.decode_record([out[k] for k in range(D.DIAG_AT + 1, out[D.DIAG_AT])])
        return "ok", None

    def view(self, reader, selector: bytes):
        status, diagnostic = self._text(reader, selector, "ws_view")
        if status == "rejected":
            return status, diagnostic
        return "view", bytes(self.output[self.EDT.BATCH + k] for k in range(self.output[self.EDT.WSC + self.EDT.W_OUT])).decode()

    def apply(self, reader, batch: bytes):
        status, diagnostic = self._text(reader, batch, "ws_translate")
        if status == "rejected":
            return status, diagnostic
        record = bytes(self.output[self.EDT.EIN + k] for k in range(self.output[self.EDT.EC + self.EDT.E_LENGTH]))
        return self.edit(reader, record)

    def test_view_equals_the_reference(self):
        viewed = 0
        for reader in _stores():
            self.assertEqual(self.view(reader, b""), ("view", ws_listing(reader)))
            for n in range(len(ws_functions(reader))):
                got = self.view(reader, f"F{n}".encode())
                try:
                    expected = ws_view(reader, n)
                except X.XaxError:  # a recursion group's member has no graph of its own
                    self.assertEqual((got[0], got[1].rule), ("rejected", "WORKSPACE-VIEW-GROUP-MEMBER"))
                    continue
                self.assertEqual(got, ("view", expected))
                viewed += 1
        self.assertGreater(viewed, 6)

    def test_view_selector_rejections(self):
        reader = _stores()[0]
        for selector, rule in ((b"G1", "WORKSPACE-VIEW-SELECTOR"), (b"F0 F1", "WORKSPACE-VIEW-SELECTOR"), (b"F99", "WORKSPACE-VIEW-FUNCTION")):
            status, diagnostic = self.view(reader, selector)
            self.assertEqual((status, diagnostic.rule), ("rejected", rule))

    def test_apply_equals_the_workspace(self):
        """Every batch makes the store the workspace commits, or both reject; where the workspace's verification rejects
        a well-formed batch, ``apply``'s store fails ``verify`` (``apply`` is ``edit``: the caller verifies)."""
        rng = random.Random(7)
        seen = set()
        for reader in _stores():
            functions = ws_functions(reader)
            for _trial in range(60):
                n = rng.randrange(len(functions))
                try:
                    ws_view(reader, n)
                except X.XaxError:
                    continue
                made = ws_random_batch(reader, n, rng)
                if not made:
                    continue
                batch, command = made
                native, python = self.apply(reader, batch), ws_python_commit(reader, n, command)
                if python[0] == "store":
                    self.assertEqual(native, python, batch)
                    seen.add("store")
                elif native[0] == "store":
                    with self.assertRaises(X.XaxError):
                        X.verify_store(X.StoreReader(native[1]))
                    seen.add("unverified")
                else:
                    seen.add("rejected")
        self.assertEqual(seen, {"store", "unverified", "rejected"})

    def test_batch_rejections(self):
        reader = _stores()[2]
        root = reader.root_cid.hex()
        cases = ((b"", "WORKSPACE-BATCH-ROOT"), (b"R abc F0", "WORKSPACE-BATCH-ROOT"), (f"R {root} F99".encode(), "WORKSPACE-BATCH-FUNCTION"),
                 (f"R {root} F0 frob N1".encode(), "WORKSPACE-BATCH-FORM"), (f"R {root} F0 const N9999 3".encode(), "WORKSPACE-BATCH-HANDLE"),
                 (f"R {root} F0 operand N1 0 Q3".encode(), "WORKSPACE-BATCH-VALUE"), (f"R {root} F0 type N1 T99".encode(), "WORKSPACE-BATCH-TYPE"),
                 (f"R {'0' * 63}1 F0 op N1 add.wrap".encode(), "WORKSPACE-EXPECTED-ROOT"), (f"R {root} F0".encode(), "WORKSPACE-MUTATION-NONEMPTY"))
        for batch, rule in cases:
            status, diagnostic = self.apply(reader, batch)
            self.assertEqual((status, diagnostic.rule), ("rejected", rule), batch)

    def explain(self, words):
        import xax_selfhost_diagnostics as D

        EDT, out = self.EDT, self.output
        for k, word in enumerate(words):
            out[EDT.XREC + k] = word
        out[EDT.WSC + EDT.W_LEN] = len(words)
        self.call("ws_explain")
        if out[EDT.EC + EDT.E_STATUS] == EDT.REJECT:
            return "rejected", D.decode_record([out[k] for k in range(D.DIAG_AT + 1, out[D.DIAG_AT])])
        return "text", bytes(out[EDT.BATCH + k] for k in range(out[EDT.WSC + EDT.W_OUT])).decode()

    def test_explain_renders_every_value(self):
        for words in _ws_records():
            self.assertEqual(self.explain(words), ("text", ws_explained(words)))
        status, diagnostic = self.explain([2, 99])  # a string longer than the record
        self.assertEqual((status, diagnostic.rule), ("rejected", "WORKSPACE-EXPLAIN-RECORD"))

    def command(self, reader, data: bytes):
        """``ws_command`` on ``edit``'s input ``data``: ``(mode, W_TEXT, text or None)``."""
        from xax_selfhost_verify import object_table

        EDT, out = self.EDT, self.output
        listed = list(reader.objects())
        index = {item.cid: position for position, item in enumerate(listed)}
        words = object_table(listed, [index[reader.root_cid]])
        self.input[:len(words)] = words
        self.call("index_objects")
        for k, byte in enumerate(data):
            out[EDT.EIN + k] = byte
        out[EDT.EC + EDT.E_LENGTH] = len(data)
        self.call("ws_command")
        mode, text = out[EDT.WSC + EDT.W_MODE], out[EDT.WSC + EDT.W_TEXT]
        packed = b"".join(out[EDT.BATCH + k].to_bytes(8, "little") for k in range((out[EDT.WSC + EDT.W_OUT] + 7) // 8))
        out[EDT.WSC + EDT.W_TEXT] = 0
        return mode, text, packed[:out[EDT.WSC + EDT.W_OUT]].decode() if text == 1 else None

    def test_edit_input_is_classified(self):
        """``edit``'s input: an edit record, a batch, a view selector, or a diagnostic record."""
        reader = _stores()[2]
        EDT = self.EDT
        self.assertEqual(self.command(reader, edit_record([]))[:2], (EDT.WS_EDIT, 0))
        self.assertEqual(self.command(reader, b"F0"), (EDT.WS_VIEW, 1, ws_view(reader, 0)))
        self.assertEqual(self.command(reader, b""), (EDT.WS_VIEW, 1, ws_listing(reader)))
        self.assertEqual(self.command(reader, f" R {reader.root_cid.hex()} F0 frob".encode())[:2], (EDT.WS_APPLY, 2))
        words = _ws_records()[1]
        data = b"".join(word.to_bytes(8, "little") for word in words)
        self.assertEqual(self.command(reader, data), (EDT.WS_EXPLAIN, 1, ws_explained(words)))

    def test_explain_renders_rejections(self):
        """The records ``apply`` and the edit engine write for real rejections."""
        import xax_selfhost_diagnostics as D

        reader = _stores()[2]
        root = reader.root_cid.hex()
        for batch in (b"", f"R {'0' * 63}1 F0 op N1 add.wrap".encode(), f"R {root} F0 type N1 T99".encode()):
            self.assertEqual(self.apply(reader, batch)[0], "rejected")
            words = [self.output[k] for k in range(D.DIAG_AT + 1, self.output[D.DIAG_AT])]
            self.assertEqual(self.explain(words), ("text", ws_explained(words)))


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the production compiler runs on Linux x86-64 only")
class WorkspaceCommandTests(unittest.TestCase):
    """S16a (ADR-360): ``xaxc view``, ``apply`` and ``explain`` as processes: the workspace with no Python."""

    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 900
        cls.directory = Path(tempfile.mkdtemp())

    def files(self, *names):
        return tuple(self.directory / name for name in names)

    def test_view_apply_verify_explain(self):
        store, selector, viewed, batch, edited, verified, explained = self.files(
            "store.xax", "selector", "view.txt", "batch", "edited.xax", "verify.bin", "explain.txt")
        reader = _stores()[0]  # no recursion group: every function's constants can be edited
        store.write_bytes(reader.data)
        selector.write_bytes(b"")
        self.assertEqual(self.driver.view(store, selector, viewed), 0)
        self.assertEqual(viewed.read_text(), ws_listing(reader))
        n = next(k for k in range(len(ws_functions(reader))) if "constant" in ws_view(reader, k))
        selector.write_bytes(f"F{n}".encode())
        self.assertEqual(self.driver.view(store, selector, viewed), 0)
        text = viewed.read_text()
        self.assertEqual(text, ws_view(reader, n))
        node = next(line.split()[0] for line in text.splitlines() if " constant " in line)
        batch.write_bytes(f"R {reader.root_cid.hex()}\nF{n}\nconst {node} 7\n".encode())
        self.assertEqual(self.driver.apply(store, batch, edited), 0)
        self.assertEqual(edited.read_bytes(), ws_python_commit(reader, n, f"set-constant {node} 7")[1])
        self.assertIn(self.driver.verify(edited, verified), (0, 2))
        # The same batch against the edited store is stale: the rejection, then its text.
        self.assertEqual(self.driver.apply(edited, batch, verified), 1)
        self.assertEqual(self.driver.explain(store, verified, explained), 0)
        data = verified.read_bytes()
        words = [int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)]
        self.assertEqual(explained.read_text(), ws_explained(words))
        self.assertIn("rule WORKSPACE-EXPECTED-ROOT", explained.read_text())


def ws_render(value) -> str:
    """A ``decode_record`` value as ``explain`` writes it (128-bit integers as 32 hexadecimal digits)."""
    import enum

    if isinstance(value, bool):
        return str(value)
    if isinstance(value, enum.Enum):
        return f"{type(value).__name__}.{value.name}"
    if isinstance(value, int):
        return str(value) if value < 1 << 64 else f"0x{value:032x}"
    if isinstance(value, str):
        return value
    if value is None:
        return "None"
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return "[" + ", ".join(ws_render(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "(" + ", ".join(ws_render(item) for item in value) + ")"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{ws_render(key)}: {ws_render(item)}" for key, item in value.items()) + "}"
    raise TypeError(type(value))


def ws_explained(words) -> str:
    """The text ``explain`` writes for a record's words."""
    import xax_selfhost_diagnostics as D

    diagnostic = D.decode_record(words)
    fields = ("code", "entity", "rule", "expected", "actual")
    lines = [f"{name} {ws_render(getattr(diagnostic, name))}" for name in fields]
    if _ws_five_values_end(words) != len(words):  # the dependencies and the repair neighborhood follow
        lines += [f"dependencies {ws_render(list(diagnostic.dependencies))}", f"repair {ws_render(list(diagnostic.repair_neighborhood))}"]
    return "\n".join(lines) + "\n"


def _ws_five_values_end(words) -> int:
    """The word after the record's first five values."""
    import xax_selfhost_diagnostics as D

    position = 0

    def skip():
        nonlocal position
        tag = words[position]
        position += 1
        if tag in (D.T_STR, D.T_HEX, D.T_BYTES):
            position += 1 + (words[position] + 7) // 8
        elif tag == D.T_CID:
            position += 4
        elif tag in (D.T_ENUM, D.T_NAME, D.T_WIDE):
            position += 2
        elif tag in (D.T_LIST, D.T_TUPLE):
            count = words[position]
            position += 1
            for _ in range(count):
                skip()
        elif tag == D.T_DICT:
            count = words[position]
            position += 1
            for _ in range(2 * count):
                skip()
        elif tag == D.T_OBJECT:
            count = words[position + 1]
            position += 2
            for _ in range(count):
                skip()
        elif tag == D.T_FORMAT:
            skip()
            count = words[position]
            position += 1
            for _ in range(count):
                skip()
        elif tag != D.T_NONE:
            position += 1

    for _ in range(5):
        skip()
    return position


def _ws_records():
    """Diagnostic records with every value tag ``explain`` renders."""
    import xax_selfhost_diagnostics as D

    def text(value: str):
        data = value.encode()
        return [D.T_STR, len(data)] + [int.from_bytes(data[k:k + 8].ljust(8, b"\0"), "little") for k in range(0, len(data), 8)]

    cid = [D.T_CID, 1, 2, 3, (1 << 64) - 1]
    return [
        text("XAX.EDIT.RECORD") + text("edit") + text("EDIT-RECORD-ULEB") + text("xax-edit-v1") + [D.T_INT, 42],
        text("X") + cid + text("R") + [D.T_TUPLE, 4, D.T_INT, 1, D.T_INT, 0, D.T_INT, 2, D.T_INT, 0] + [D.T_LIST, 2, D.T_NAME, 10, 1, D.T_ENUM, 0, 3],
        text("C") + [D.T_NONE] + text("R") + [D.T_FORMAT] + text("value fitting {} and {}") + [2, D.T_INT, 8, D.T_SINT, (1 << 64) - 5]
        + [D.T_DICT, 2] + text("a") + [D.T_BOOL, 1] + text("b") + [D.T_LIST, 0],
        text("C") + [D.T_KIND, 3] + text("R") + [D.T_TERMINATOR, 2] + [D.T_WIDE, 5, 1] + [D.T_LIST, 1, D.T_TUPLE, 1] + cid + [D.T_LIST, 0],
        text("C") + [D.T_HEX, 3, 0x030201] + text("R") + [D.T_BYTES, 2, 0xBBAA] + [D.T_FORMAT] + text("<{}>") + [1, D.T_LIST, 2, D.T_INT, 1, D.T_INT, 2],
    ]


if __name__ == "__main__":
    unittest.main()
