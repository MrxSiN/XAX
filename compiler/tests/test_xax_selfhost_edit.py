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


if __name__ == "__main__":
    unittest.main()
