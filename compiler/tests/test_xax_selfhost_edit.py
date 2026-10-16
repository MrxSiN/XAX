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
            "EDIT-RECORD-KIND": good[:41] + b"\x09" + good[42:],
            "WORKSPACE-OP-CONTRACT-PRESERVED": edit_record([(SET_OPERATION, f.cid, b, n, int(node.operation), int(X.Operation.UDIV))]),
            "WORKSPACE-OP-PRECONDITION": edit_record([(SET_OPERATION, f.cid, b, n, 1 + int(node.operation) % 3, 1)]),
        }
        for rule, record in cases.items():
            with self.subTest(rule):
                kind, diagnostic = self.edit(reader, record)
                self.assertEqual((kind, diagnostic.rule), ("rejected", rule))
        self.assertEqual(self.edit(reader, good), ("store", apply_reference(reader, good).data))


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


if __name__ == "__main__":
    unittest.main()
