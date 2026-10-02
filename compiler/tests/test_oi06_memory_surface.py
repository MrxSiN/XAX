import json
import unittest
from pathlib import Path

from xax_compiler import (
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    Permission,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    XaxTrap,
    bits_type,
    effect_type,
    execute,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    stack_owner_type,
    verify_store,
    write_store,
    oi06_x86_64_windows_target,
    oi06_wasm32_target,
)
from xax_x86_64 import compile_native_bound_target
from xax_wasm import compile_wasm_bound_target, run_wasm_isolated


def _reader_for(objects, entry):
    module = object_with_refs(Kind.MODULE, [entry])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return StoreReader(write_store(root.cid, [*objects, module, root])), entry


def checked_load_fixture():
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(8, 4)),
        Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(4, 4)),
        Node(Operation.ADDRESS_OFFSET, (ValueRef.node_result(0, 0, 0),), (pointer,), attributes=(4,)),
        Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 2, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0)), (effect,), attributes=(4, 4)),
        Node(Operation.CHECKED_LOAD_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 2), ValueRef.node_result(0, 3, 0)), (b32, effect), attributes=(4, 1)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 4, 1)), ()),
    )
    graph = graph_fragment([Block((b32, b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, 4, 0),)))])
    entry = function(graph, (b32, b32, b32), (b32,))
    return _reader_for([b32, pointer, owner, effect, graph, entry], entry)


def checked_store_fixture():
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.CHECKED_STORE_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(4, 1)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 0)), ()),
    )
    graph = graph_fragment([Block((b32, b32), nodes, Terminator.return_((ValueRef.parameter(0, 1),)))])
    entry = function(graph, (b32, b32), (b32,))
    return _reader_for([b32, pointer, owner, effect, graph, entry], entry)


def raw_load_fixture(*, waiver=2, unsafe=True):
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    unsafe_effect = effect_type(EffectDomain.UNSAFE if unsafe else EffectDomain.IO)
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.RAW_LOAD_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 2), ValueRef.parameter(0, 0)), (b32, effect, unsafe_effect), attributes=(4, 4, waiver)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 1)), ()),
    )
    graph = graph_fragment([Block((unsafe_effect,), nodes, Terminator.return_((ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 2))))])
    entry = function(graph, (unsafe_effect,), (b32, unsafe_effect))
    return _reader_for([b32, pointer, owner, effect, unsafe_effect, graph, entry], entry)


def two_alias_fixture(*, mismatch=False):
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    e0 = ValueRef.node_result(0, 0, 2)
    e1 = ValueRef.node_result(0, 1, 2)
    nodes = [
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), e1 if mismatch else e0), (effect,), attributes=(4, 4)),
    ]
    if mismatch:
        graph = graph_fragment([Block((b32, b32), tuple(nodes), Terminator.return_())])
        entry = function(graph, (b32, b32), ())
    else:
        nodes.extend([
            Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 1), e1), (effect,), attributes=(4, 4)),
            Node(Operation.LOAD_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 2, 0)), (b32, effect), attributes=(4, 4)),
            Node(Operation.LOAD_BITS_LE, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 3, 0)), (b32, effect), attributes=(4, 4)),
            Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 4, 1)), ()),
            Node(Operation.STACK_END, (ValueRef.node_result(0, 1, 1), ValueRef.node_result(0, 5, 1)), ()),
        ])
        graph = graph_fragment([Block((b32, b32), tuple(nodes), Terminator.return_((ValueRef.node_result(0, 4, 0),)))])
        entry = function(graph, (b32, b32), (b32,))
    return _reader_for([b32, pointer, owner, effect, graph, entry], entry)


class OI06MemorySurfaceTests(unittest.TestCase):
    def test_two_allocations_have_independent_provenance_and_execute(self):
        reader, entry = two_alias_fixture()
        verify_store(reader)
        self.assertEqual(execute(reader, entry.cid, (11, 22)), (11,))

    def test_cross_alias_effect_is_rejected(self):
        reader, _ = two_alias_fixture(mismatch=True)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PROVENANCE"):
            verify_store(reader)

    def test_checked_load_is_deterministic_and_traps_out_of_range(self):
        reader, entry = checked_load_fixture()
        verify_store(reader)
        encoded = reader.canonical_bytes()
        self.assertEqual(StoreReader(encoded).canonical_bytes(), encoded)
        self.assertEqual(execute(reader, entry.cid, (0x11223344, 0x55667788, 0)), (0x11223344,))
        self.assertEqual(execute(reader, entry.cid, (0x11223344, 0x55667788, 4)), (0x55667788,))
        with self.assertRaises(XaxTrap):
            execute(reader, entry.cid, (1, 2, 5))

    def test_checked_store_traps_out_of_range(self):
        reader, entry = checked_store_fixture()
        verify_store(reader)
        self.assertEqual(execute(reader, entry.cid, (0, 0xAABBCCDD)), (0xAABBCCDD,))
        with self.assertRaises(XaxTrap):
            execute(reader, entry.cid, (1, 0xAABBCCDD))

    def test_raw_load_requires_explicit_unsafe_effect_and_waiver(self):
        reader, _ = raw_load_fixture()
        verify_store(reader)
        bad_effect, _ = raw_load_fixture(unsafe=False)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.RAW_EFFECT"):
            verify_store(bad_effect)
        bad_waiver, _ = raw_load_fixture(waiver=0)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.RAW_WAIVER"):
            verify_store(bad_waiver)


    def test_committed_evidence_reproduces_deterministic_measurements(self):
        from compiler.benchmarks.bench_oi06_memory_surface import collect_evidence
        committed = json.loads((Path(__file__).parents[1] / "benchmarks" / "oi06_memory_surface_evidence.json").read_text())
        actual = collect_evidence()
        self.assertEqual(actual["schema"], committed["schema"])
        self.assertEqual(actual["token_metric"], committed["token_metric"])
        self.assertEqual(actual["alias_encoding_comparator"], committed["alias_encoding_comparator"])
        self.assertEqual(actual["checked_surface_comparator"], committed["checked_surface_comparator"])
        self.assertEqual(actual["raw_surface_comparator"], committed["raw_surface_comparator"])
        self.assertEqual(actual["target_models"], committed["target_models"])
        deterministic = ("root_cid", "graph_cid", "graph_body_bytes", "graph_envelope_bytes", "store_bytes", "token_atoms", "x86_64_code_bytes", "wasm_module_bytes")
        for name in committed["rows"]:
            self.assertEqual({k: actual["rows"][name][k] for k in deterministic}, {k: committed["rows"][name][k] for k in deterministic})

    def test_checked_and_raw_lower_on_native_stack_and_wasm_linear_memory(self):
        checked, entry = checked_load_fixture()
        native = compile_native_bound_target(checked, entry.cid, oi06_x86_64_windows_target())
        wasm = compile_wasm_bound_target(checked, entry.cid, oi06_wasm32_target())
        self.assertGreater(len(native.code), 0)
        self.assertGreater(len(wasm.module), 0)
        self.assertEqual(run_wasm_isolated(wasm, (7, 9, 4)), (9,))
        raw, raw_entry = raw_load_fixture()
        self.assertGreater(len(compile_native_bound_target(raw, raw_entry.cid, oi06_x86_64_windows_target()).code), 0)
        self.assertGreater(len(compile_wasm_bound_target(raw, raw_entry.cid, oi06_wasm32_target()).module), 0)


if __name__ == "__main__":
    unittest.main()
