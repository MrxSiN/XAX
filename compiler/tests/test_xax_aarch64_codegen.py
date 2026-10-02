import hashlib
import json
from pathlib import Path

from xax_aarch64 import compile_aarch64
from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    aarch64_baremetal_target,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    write_store,
)


def _reader(function_object, objects, *, extra_functions=()):
    target = aarch64_baremetal_target()
    module = object_with_refs(Kind.MODULE, [*extra_functions, function_object, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return StoreReader(write_store(root.cid, [*objects, *extra_functions, function_object, target, module, root])), target


def _function_code(image, function_cid):
    semantic_range = next(
        item
        for item in image.semantic_ranges
        if item.function_cid == function_cid and item.block_index is None
    )
    return image.code[semantic_range.start:semantic_range.end]


def _words(code):
    return tuple(int.from_bytes(code[index:index + 4], "little") for index in range(0, len(code), 4))


def _metrics(code):
    words = _words(code)
    loads = stores = sp_adjustments = x30_stack_ops = 0
    frame_bytes = 0
    for word in words:
        top = word & 0xFFC00000
        base_register = (word >> 5) & 31
        register = word & 31
        if base_register == 31 and top in (0xB9400000, 0xF9400000):
            loads += 1
        if base_register == 31 and top in (0xB9000000, 0xF9000000):
            stores += 1
        if base_register == 31 and register == 31 and (word & 0xFF000000) in (0xD1000000, 0x91000000):
            sp_adjustments += 1
            if (word & 0xFF000000) == 0xD1000000:
                frame_bytes = max(frame_bytes, (word >> 10) & 0xFFF)
        if base_register == 31 and register == 30 and top in (0xF9400000, 0xF9000000):
            x30_stack_ops += 1
    return {
        "instructions": len(words),
        "code_bytes": len(code),
        "stack_loads": loads,
        "stack_stores": stores,
        "stack_frame_bytes": frame_bytes,
        "sp_adjustments": sp_adjustments,
        "x30_stack_ops": x30_stack_ops,
    }


def _simple_add(width):
    bits = bits_type(width)
    graph = graph_fragment([
        Block(
            (bits, bits),
            (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (bits,)),),
            Terminator.return_((ValueRef.node_result(0, 0),)),
        )
    ])
    fn = function(graph, (bits, bits), (bits,))
    reader, target = _reader(fn, [bits, graph])
    return reader, target, fn


def _arithmetic_chain():
    bits = bits_type(32)
    nodes = (
        Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (bits,)),
        Node(Operation.MUL_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 2)), (bits,)),
        Node(Operation.SUB_WRAP, (ValueRef.node_result(0, 1), ValueRef.parameter(0, 1)), (bits,)),
    )
    graph = graph_fragment([Block((bits, bits, bits), nodes, Terminator.return_((ValueRef.node_result(0, 2),)))])
    fn = function(graph, (bits, bits, bits), (bits,))
    reader, target = _reader(fn, [bits, graph])
    return reader, target, fn


def _pressure_fixture():
    bits = bits_type(32)
    c11, c13 = constant(bits, 11), constant(bits, 13)
    nodes = [
        Node(Operation.CONSTANT, (), (bits,), entity=c11),
        Node(Operation.CONSTANT, (), (bits,), entity=c13),
    ]
    values = [ValueRef.parameter(0, index) for index in range(8)] + [
        ValueRef.node_result(0, 0),
        ValueRef.node_result(0, 1),
    ]
    accumulator = values[0]
    for value in values[1:]:
        node_index = len(nodes)
        nodes.append(Node(Operation.ADD_WRAP, (accumulator, value), (bits,)))
        accumulator = ValueRef.node_result(0, node_index)
    graph = graph_fragment([Block((bits,) * 8, tuple(nodes), Terminator.return_((accumulator,)))])
    fn = function(graph, (bits,) * 8, (bits,))
    reader, target = _reader(fn, [bits, c11, c13, graph])
    return reader, target, fn


def _call_fixture(*, swap_arguments=False, live_across=True):
    bits = bits_type(32)
    callee_graph = graph_fragment([
        Block(
            (bits, bits),
            (Node(Operation.SUB_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (bits,)),),
            Terminator.return_((ValueRef.node_result(0, 0),)),
        )
    ])
    callee = function(callee_graph, (bits, bits), (bits,))
    call_operands = (ValueRef.parameter(0, 1), ValueRef.parameter(0, 0)) if swap_arguments else (
        ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)
    )
    nodes = [Node(Operation.CALL_DIRECT, call_operands, (bits,), entity=callee)]
    if live_across:
        nodes.append(Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 2)), (bits,)))
        result = ValueRef.node_result(0, 1)
        parameters = (bits, bits, bits)
    else:
        result = ValueRef.node_result(0, 0)
        parameters = (bits, bits)
    caller_graph = graph_fragment([Block(parameters, tuple(nodes), Terminator.return_((result,)))])
    caller = function(caller_graph, parameters, (bits,))
    reader, target = _reader(caller, [bits, callee_graph, caller_graph], extra_functions=(callee,))
    return reader, target, caller, callee


def _unconditional_swap_fixture():
    bits = bits_type(32)
    graph = graph_fragment([
        Block((bits, bits), (), Terminator.branch(1, (ValueRef.parameter(0, 1), ValueRef.parameter(0, 0)))),
        Block(
            (bits, bits),
            (Node(Operation.SUB_WRAP, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)), (bits,)),),
            Terminator.return_((ValueRef.node_result(1, 0),)),
        ),
    ])
    fn = function(graph, (bits, bits), (bits,))
    reader, target = _reader(fn, [bits, graph])
    return reader, target, fn


def _conditional_swap_fixture():
    bits1, bits32 = bits_type(1), bits_type(32)
    graph = graph_fragment([
        Block(
            (bits32, bits32, bits1),
            (),
            Terminator.conditional_branch(
                ValueRef.parameter(0, 2),
                1,
                (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)),
                1,
                (ValueRef.parameter(0, 1), ValueRef.parameter(0, 0)),
            ),
        ),
        Block(
            (bits32, bits32),
            (Node(Operation.SUB_WRAP, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)), (bits32,)),),
            Terminator.return_((ValueRef.node_result(1, 0),)),
        ),
    ])
    fn = function(graph, (bits32, bits32, bits1), (bits32,))
    reader, target = _reader(fn, [bits1, bits32, graph])
    return reader, target, fn


def _explicit_stack_fixture():
    bits = bits_type(32)
    from xax_compiler import memory_effect_type, pointer_type, stack_owner_type

    pointer = pointer_type(bits, alignment=4)
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
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 0)),
            (bits, effect),
            attributes=(4, 4),
        ),
        Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)),
            (),
        ),
    )
    graph = graph_fragment([Block((bits,), nodes, Terminator.return_((ValueRef.node_result(0, 2, 0),)))])
    fn = function(graph, (bits,), (bits,))
    reader, target = _reader(fn, [bits, pointer, owner, effect, graph])
    return reader, target, fn


def test_trivial_leaf_add_32_is_add_ret_only():
    reader, target, fn = _simple_add(32)
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    assert _words(code) == (0x0B010000, 0xD65F03C0)
    assert _metrics(code) == {
        "instructions": 2,
        "code_bytes": 8,
        "stack_loads": 0,
        "stack_stores": 0,
        "stack_frame_bytes": 0,
        "sp_adjustments": 0,
        "x30_stack_ops": 0,
    }


def test_trivial_leaf_add_64_is_add_ret_only():
    reader, target, fn = _simple_add(64)
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    assert _words(code) == (0x8B010000, 0xD65F03C0)
    assert _metrics(code)["stack_loads"] == 0
    assert _metrics(code)["stack_stores"] == 0
    assert _metrics(code)["sp_adjustments"] == 0


def test_constant_return_leaf_has_no_frame():
    bits = bits_type(32)
    value = constant(bits, 42)
    graph = graph_fragment([Block((), (Node(Operation.CONSTANT, (), (bits,), entity=value),), Terminator.return_((ValueRef.node_result(0, 0),)))])
    fn = function(graph, (), (bits,))
    reader, target = _reader(fn, [bits, value, graph])
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    assert _words(code) == (0x52800540, 0xD65F03C0)


def test_arithmetic_chain_stays_register_resident():
    reader, target, fn = _arithmetic_chain()
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    metrics = _metrics(code)
    assert metrics["instructions"] == 4
    assert metrics["stack_loads"] == metrics["stack_stores"] == 0
    assert metrics["stack_frame_bytes"] == metrics["sp_adjustments"] == 0


def test_real_call_preserves_link_and_only_live_across_value_spills():
    reader, target, caller, callee = _call_fixture(live_across=True)
    image = compile_aarch64(reader, caller.cid, target.cid)
    caller_code = _function_code(image, caller.cid)
    callee_code = _function_code(image, callee.cid)
    caller_metrics = _metrics(caller_code)
    assert _metrics(callee_code)["x30_stack_ops"] == 0
    assert _metrics(callee_code)["sp_adjustments"] == 0
    assert caller_metrics["stack_stores"] == 2  # x30 + one live-across SSA value
    assert caller_metrics["stack_loads"] == 2   # one SSA reload + x30
    assert caller_metrics["x30_stack_ops"] == 2
    assert caller_metrics["stack_frame_bytes"] == 16


def test_call_argument_swap_uses_reserved_scratch_not_temporary_stack():
    reader, target, caller, _ = _call_fixture(swap_arguments=True, live_across=False)
    code = _function_code(compile_aarch64(reader, caller.cid, target.cid), caller.cid)
    words = _words(code)
    assert 0x2A0103EA in words  # mov w10, w1 breaks x0/x1 cycle
    metrics = _metrics(code)
    assert metrics["stack_stores"] == 1  # link register only
    assert metrics["stack_loads"] == 1
    assert metrics["stack_frame_bytes"] == 16


def test_register_pressure_spills_only_one_value_for_ten_live_values_and_nine_registers():
    reader, target, fn = _pressure_fixture()
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    metrics = _metrics(code)
    assert metrics["stack_stores"] == 1
    assert metrics["stack_loads"] == 1
    assert metrics["stack_frame_bytes"] == 16
    assert metrics["x30_stack_ops"] == 0


def test_unconditional_edge_swap_uses_register_parallel_copy():
    reader, target, fn = _unconditional_swap_fixture()
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    words = _words(code)
    assert 0x2A0103EA in words
    assert _metrics(code)["stack_loads"] == 0
    assert _metrics(code)["stack_stores"] == 0
    assert _metrics(code)["stack_frame_bytes"] == 0


def test_conditional_edge_swap_uses_register_parallel_copy():
    reader, target, fn = _conditional_swap_fixture()
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    assert 0x2A0103EA in _words(code)
    metrics = _metrics(code)
    assert metrics["stack_loads"] == metrics["stack_stores"] == 0
    assert metrics["stack_frame_bytes"] == 0


def test_explicit_stack_memory_remains_explicit_without_link_save():
    reader, target, fn = _explicit_stack_fixture()
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    metrics = _metrics(code)
    assert metrics == {
        "instructions": 5,
        "code_bytes": 20,
        "stack_loads": 1,
        "stack_stores": 1,
        "stack_frame_bytes": 16,
        "sp_adjustments": 2,
        "x30_stack_ops": 0,
    }


def test_codegen_is_deterministic():
    reader, target, fn = _pressure_fixture()
    first = compile_aarch64(reader, fn.cid, target.cid)
    second = compile_aarch64(reader, fn.cid, target.cid)
    assert first.code == second.code
    assert hashlib.sha256(first.code).digest() == hashlib.sha256(second.code).digest()


def test_committed_before_after_evidence_reproduces_optimized_metrics():
    evidence = json.loads(
        (Path(__file__).parents[1] / "benchmarks" / "aarch64_register_residency_evidence.json").read_text()
    )
    builders = {
        "simple_add32": lambda: _simple_add(32),
        "simple_add64": lambda: _simple_add(64),
        "arithmetic_chain": _arithmetic_chain,
        "register_pressure": _pressure_fixture,
        "explicit_stack": _explicit_stack_fixture,
    }
    for name, builder in builders.items():
        reader, target, fn = builder()
        code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
        assert _metrics(code) == evidence["fixtures"][name]["after"]
        assert [f"{word:08x}" for word in _words(code)] == evidence["fixtures"][name]["after_words"]

    reader, target, caller, _ = _call_fixture(live_across=True)
    code = _function_code(compile_aarch64(reader, caller.cid, target.cid), caller.cid)
    assert _metrics(code) == evidence["fixtures"]["direct_call"]["after"]
    assert [f"{word:08x}" for word in _words(code)] == evidence["fixtures"]["direct_call"]["after_words"]

    # The conditional evidence fixture uses the same non-cyclic representative
    # shape captured before the rewrite; cycle behavior is covered separately.
    bits1, bits32 = bits_type(1), bits_type(32)
    graph = graph_fragment([
        Block(
            (bits1, bits32, bits32),
            (),
            Terminator.conditional_branch(
                ValueRef.parameter(0, 0),
                1,
                (ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
                2,
                (ValueRef.parameter(0, 2), ValueRef.parameter(0, 1)),
            ),
        ),
        Block(
            (bits32, bits32),
            (Node(Operation.ADD_WRAP, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)), (bits32,)),),
            Terminator.return_((ValueRef.node_result(1, 0),)),
        ),
        Block(
            (bits32, bits32),
            (Node(Operation.SUB_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 1)), (bits32,)),),
            Terminator.return_((ValueRef.node_result(2, 0),)),
        ),
    ])
    fn = function(graph, (bits1, bits32, bits32), (bits32,))
    reader, target = _reader(fn, [bits1, bits32, graph])
    code = _function_code(compile_aarch64(reader, fn.cid, target.cid), fn.cid)
    assert _metrics(code) == evidence["fixtures"]["conditional_branch"]["after"]
    assert [f"{word:08x}" for word in _words(code)] == evidence["fixtures"]["conditional_branch"]["after_words"]
