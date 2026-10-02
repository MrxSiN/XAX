import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from xax_aarch64 import compile_aarch64_bound_target, compile_aarch64_bundle_bound_target
from xax_android import AndroidExport, compile_android_shared, inspect_android_elf
from xax_compiler import (
    Block, FloatCompare, FloatFormat, Kind, Node, Operation, StoreReader, Terminator, ValueRef,
    abi_layout, aarch64_baremetal_general_target, android_arm64_shared_general_target,
    array_type, bits_type, constant, float_type, function, graph_fragment, heap_view_type,
    object_with_refs, sum_type, tuple_type, verify_store, XaxError,
    wasm32_general_target, write_store, x86_64_windows_general_target,
)
from xax_platform import posix_android_api
from xax_strings import (
    BytearrayStringAllocator, append_owned_utf8, clone_owned_utf8, concat_owned_utf8,
    format_owned_utf8, format_utf8, owned_utf8, utf8_boundaries, utf8_codepoint_count,
    utf8_contains, utf8_find, utf8_rfind, validate_utf8,
)
from xax_wasm import compile_wasm_bound_target, run_wasm_isolated
from xax_x86_64 import compile_native


def reader_for(entry, objects, target):
    module = object_with_refs(Kind.MODULE, [entry, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    values = list(objects) + [target, module, root]
    return StoreReader(write_store(root.cid, values))


def test_abi_layout_supports_nested_large_products_and_sums():
    b8, b32, b64 = bits_type(8), bits_type(32), bits_type(64)
    inner = tuple_type((b8, b64, b32))
    array3 = array_type(b64, 3)
    large = tuple_type((b32, inner, array3))
    choice = sum_type((large, b64))
    objects = {obj.cid: obj for obj in (b8, b32, b64, inner, array3, large, choice)}
    resolve = objects.__getitem__
    inner_layout = abi_layout(inner, resolve)
    assert inner_layout.offsets == (0, 8, 16)
    assert (inner_layout.size, inner_layout.alignment) == (24, 8)
    large_layout = abi_layout(large, resolve)
    assert large_layout.offsets == (0, 8, 32)
    assert (large_layout.size, large_layout.alignment) == (56, 8)
    choice_layout = abi_layout(choice, resolve)
    assert choice_layout.payload_offset == 8
    assert (choice_layout.size, choice_layout.alignment) == (64, 8)


def _large_aggregate_program(target):
    b64 = bits_type(64)
    triple = tuple_type((b64, b64, b64))  # 24 bytes: by-reference on Win64/AAPCS64
    choice = sum_type((triple, b64))

    callee_graph = graph_fragment([
        Block((triple,), (), Terminator.return_((ValueRef.parameter(0, 0),)))
    ])
    callee = function(callee_graph, (triple,), (triple,))

    nodes = (
        Node(Operation.AGGREGATE_MAKE, tuple(ValueRef.parameter(0, i) for i in range(3)), (triple,)),
        Node(Operation.CALL_DIRECT, (ValueRef.node_result(0, 0),), (triple,), entity=callee),
        Node(Operation.SUM_MAKE, (ValueRef.node_result(0, 1),), (choice,), attributes=(0,)),
        Node(Operation.SUM_GET, (ValueRef.node_result(0, 2),), (triple,), attributes=(0,)),
        Node(Operation.AGGREGATE_GET, (ValueRef.node_result(0, 3),), (b64,), attributes=(2,)),
    )
    graph = graph_fragment([Block((b64, b64, b64), nodes, Terminator.return_((ValueRef.node_result(0, 4),)))])
    entry = function(graph, (b64, b64, b64), (b64,))
    reader = reader_for(entry, [b64, triple, choice, callee_graph, callee, graph, entry], target)
    return reader, entry


def test_large_aggregate_and_sum_lowering_parity_x86_aarch64_wasm():
    x86 = x86_64_windows_general_target()
    reader, entry = _large_aggregate_program(x86)
    assert compile_native(reader, entry.cid, x86.cid).code

    arm = aarch64_baremetal_general_target()
    reader, entry = _large_aggregate_program(arm)
    assert compile_aarch64_bound_target(reader, entry.cid, arm).code

    wasm = wasm32_general_target()
    reader, entry = _large_aggregate_program(wasm)
    image = compile_wasm_bound_target(reader, entry.cid, wasm)
    if not shutil.which("node"):
        pytest.skip("node is required for WASM runtime proof")
    assert run_wasm_isolated(image, (11, 22, 33)) == (33,)


def test_win64_stack_arguments_and_hidden_large_return_compile():
    b64 = bits_type(64)
    triple = tuple_type((b64, b64, b64))
    target = x86_64_windows_general_target()

    # The hidden result pointer consumes RCX.  The fourth and later explicit
    # parameters therefore use Win64 stack slots, while the 24-byte aggregate
    # itself is passed indirectly through a 16-byte-aligned caller copy.
    callee_params = (b64, b64, b64, b64, b64, triple)
    callee_graph = graph_fragment([
        Block(callee_params, (), Terminator.return_((ValueRef.parameter(0, 5),)))
    ])
    callee = function(callee_graph, callee_params, (triple,))

    caller_params = (b64, b64, b64, b64, b64, b64, b64, b64)
    caller_nodes = (
        Node(Operation.AGGREGATE_MAKE, tuple(ValueRef.parameter(0, i) for i in range(5, 8)), (triple,)),
        Node(
            Operation.CALL_DIRECT,
            tuple(ValueRef.parameter(0, i) for i in range(5)) + (ValueRef.node_result(0, 0),),
            (triple,),
            entity=callee,
        ),
        Node(Operation.AGGREGATE_GET, (ValueRef.node_result(0, 1),), (b64,), attributes=(2,)),
    )
    caller_graph = graph_fragment([
        Block(caller_params, caller_nodes, Terminator.return_((ValueRef.node_result(0, 2),)))
    ])
    caller = function(caller_graph, caller_params, (b64,))
    reader = reader_for(
        caller,
        [b64, triple, callee_graph, callee, caller_graph, caller],
        target,
    )
    assert compile_native(reader, caller.cid, target.cid).code


def test_aarch64_hfa_and_stack_argument_aggregate_abi_compile():
    b64 = bits_type(64)
    f64 = float_type(FloatFormat.BINARY64)
    hfa = tuple_type((f64, f64, f64))
    triple = tuple_type((b64, b64, b64))
    target = aarch64_baremetal_general_target()

    # Eight integer parameters exhaust x0..x7; the >16-byte aggregate then has
    # to be passed as a pointer in the AAPCS64 stack argument area.
    callee_params = (b64,) * 8 + (triple, hfa)
    callee_nodes = (
        Node(Operation.AGGREGATE_GET, (ValueRef.parameter(0, 8),), (b64,), attributes=(1,)),
        Node(Operation.AGGREGATE_GET, (ValueRef.parameter(0, 9),), (f64,), attributes=(2,)),
        Node(Operation.FLOAT_TO_UINT_TRUNC, (ValueRef.node_result(0, 1),), (b64,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 2)), (b64,)),
    )
    callee_graph = graph_fragment([Block(callee_params, callee_nodes, Terminator.return_((ValueRef.node_result(0, 3),)))])
    callee = function(callee_graph, callee_params, (b64,))

    caller_params = (b64,) * 11 + (f64, f64, f64)
    caller_nodes = (
        Node(Operation.AGGREGATE_MAKE, tuple(ValueRef.parameter(0, i) for i in range(8, 11)), (triple,)),
        Node(Operation.AGGREGATE_MAKE, tuple(ValueRef.parameter(0, i) for i in range(11, 14)), (hfa,)),
        Node(Operation.CALL_DIRECT, tuple(ValueRef.parameter(0, i) for i in range(8)) + (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b64,), entity=callee),
    )
    caller_graph = graph_fragment([Block(caller_params, caller_nodes, Terminator.return_((ValueRef.node_result(0, 2),)))])
    caller = function(caller_graph, caller_params, (b64,))
    reader = reader_for(caller, [b64, f64, hfa, triple, callee_graph, callee, caller_graph, caller], target)
    image = compile_aarch64_bound_target(reader, caller.cid, target)
    assert image.code

    # HFA values also use v0..vN for results rather than the large-composite
    # x8 indirect-result convention.
    hfa_identity_graph = graph_fragment([
        Block((hfa,), (), Terminator.return_((ValueRef.parameter(0, 0),)))
    ])
    hfa_identity = function(hfa_identity_graph, (hfa,), (hfa,))
    hfa_reader = reader_for(hfa_identity, [f64, hfa, hfa_identity_graph, hfa_identity], target)
    assert compile_aarch64_bound_target(hfa_reader, hfa_identity.cid, target).code


@pytest.mark.parametrize("float_format,left,right,expected", [
    (FloatFormat.BINARY32, 1.5, 2.25, 3.75),
    (FloatFormat.BINARY64, -10.0, 0.5, -9.5),
])
def test_wasm_float_arithmetic_and_compare_runtime(float_format, left, right, expected):
    if not shutil.which("node"):
        pytest.skip("node is required for WASM runtime proof")
    ftype = float_type(float_format)
    b1 = bits_type(1)
    target = wasm32_general_target()
    nodes = (
        Node(Operation.FLOAT_ADD, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (ftype,)),
        Node(Operation.FLOAT_COMPARE, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 1)), (b1,), attributes=(FloatCompare.NE,)),
    )
    # Return the arithmetic result; the compare is retained in the graph to
    # force lowering of both operation families.
    graph = graph_fragment([Block((ftype, ftype), nodes, Terminator.return_((ValueRef.node_result(0, 0),)))])
    entry = function(graph, (ftype, ftype), (ftype,))
    reader = reader_for(entry, [ftype, b1, graph, entry], target)
    image = compile_wasm_bound_target(reader, entry.cid, target)
    result = run_wasm_isolated(image, (left, right))
    assert result[0] == pytest.approx(expected)


def _conversion_program(operation, source_type, result_type, target):
    graph = graph_fragment([
        Block((source_type,), (Node(operation, (ValueRef.parameter(0, 0),), (result_type,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
    ])
    entry = function(graph, (source_type,), (result_type,))
    reader = reader_for(entry, [source_type, result_type, graph, entry], target)
    return reader, entry


def test_wasm_signed_and_64bit_integer_float_conversion_runtime():
    if not shutil.which("node"):
        pytest.skip("node is required for WASM runtime proof")
    import struct

    b64 = bits_type(64)
    target = wasm32_general_target()
    unsigned = (1 << 63) + 4096
    for float_format in (FloatFormat.BINARY32, FloatFormat.BINARY64):
        ftype = float_type(float_format)
        reader, entry = _conversion_program(Operation.SINT_TO_FLOAT, b64, ftype, target)
        image = compile_wasm_bound_target(reader, entry.cid, target)
        assert run_wasm_isolated(image, ((1 << 64) - 7,)) == (-7.0,)

        reader, entry = _conversion_program(Operation.UINT_TO_FLOAT, b64, ftype, target)
        image = compile_wasm_bound_target(reader, entry.cid, target)
        expected_unsigned = float(unsigned) if float_format == FloatFormat.BINARY64 else struct.unpack("<f", struct.pack("<f", float(unsigned)))[0]
        assert run_wasm_isolated(image, (unsigned,))[0] == pytest.approx(expected_unsigned)

        reader, entry = _conversion_program(Operation.FLOAT_TO_SINT_TRUNC, ftype, b64, target)
        image = compile_wasm_bound_target(reader, entry.cid, target)
        assert run_wasm_isolated(image, (-42.75,)) == (((1 << 64) - 42),)

        reader, entry = _conversion_program(Operation.FLOAT_TO_UINT_TRUNC, ftype, b64, target)
        image = compile_wasm_bound_target(reader, entry.cid, target)
        assert run_wasm_isolated(image, (123.75,)) == (123,)


def test_wasm_narrow_float_to_int_uses_exact_destination_range():
    if not shutil.which("node"):
        pytest.skip("node is required for WASM runtime proof")
    b8 = bits_type(8)
    f64 = float_type(FloatFormat.BINARY64)
    target = wasm32_general_target()
    reader, entry = _conversion_program(Operation.FLOAT_TO_UINT_TRUNC, f64, b8, target)
    image = compile_wasm_bound_target(reader, entry.cid, target)
    assert run_wasm_isolated(image, (255.9,)) == (255,)
    with pytest.raises(RuntimeError):
        run_wasm_isolated(image, (256.0,))


@pytest.mark.parametrize("target,compile_fn", [
    (aarch64_baremetal_general_target(), compile_aarch64_bound_target),
    (x86_64_windows_general_target(), lambda reader, cid, target: compile_native(reader, cid, target.cid)),
])
def test_native_signed_and_64bit_conversion_variants_compile(target, compile_fn):
    b64 = bits_type(64)
    f32 = float_type(FloatFormat.BINARY32)
    f64 = float_type(FloatFormat.BINARY64)
    for operation, source, result in (
        (Operation.SINT_TO_FLOAT, b64, f32),
        (Operation.SINT_TO_FLOAT, b64, f64),
        (Operation.UINT_TO_FLOAT, b64, f32),
        (Operation.UINT_TO_FLOAT, b64, f64),
        (Operation.FLOAT_TO_SINT_TRUNC, f32, b64),
        (Operation.FLOAT_TO_SINT_TRUNC, f64, b64),
        (Operation.FLOAT_TO_UINT_TRUNC, f32, b64),
        (Operation.FLOAT_TO_UINT_TRUNC, f64, b64),
    ):
        reader, entry = _conversion_program(operation, source, result, target)
        assert compile_fn(reader, entry.cid, target).code


def test_raw_foreign_malloc_pointer_is_not_direct_core_storage():
    api = posix_android_api()
    size = constant(api.b64, 4)
    nodes = (
        Node(Operation.CONSTANT, (), (api.b64,), entity=size),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 1)), (api.byte_ptr_rw, api.heap_resource, api.memory_effect), entity=api.malloc),
        Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 1, 2)), (api.memory_effect,), attributes=(1, 1)),
    )
    graph = graph_fragment([Block((api.b8, api.memory_effect), nodes, Terminator.return_((ValueRef.node_result(0, 2, 0),)))])
    entry = function(graph, (api.b8, api.memory_effect), (api.memory_effect,))
    target = android_arm64_shared_general_target()
    heap_types = [api.b8, api.b64, api.byte_ptr_rw, api.memory_effect, api.heap_resource]
    reader = reader_for(entry, [*heap_types, api.malloc, size, graph, entry], target)
    with pytest.raises(XaxError, match="XAX.MEMORY.PROVENANCE"):
        verify_store(reader)


def test_foreign_malloc_heap_view_proves_direct_core_memory_and_typed_free():
    api = posix_android_api()
    view = heap_view_type(4, initialized=False)
    free_view = api.free_heap_view(view)
    size = constant(api.b64, 4)
    nodes = (
        Node(Operation.CONSTANT, (), (api.b64,), entity=size),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 1)), (api.byte_ptr_rw, api.heap_resource, api.memory_effect), entity=api.malloc),
        Node(Operation.HEAP_VIEW, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1), ValueRef.node_result(0, 1, 2)), (api.byte_ptr_rw, view, api.memory_effect), attributes=(4, 1)),
        Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 2, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 2, 2)), (api.memory_effect,), attributes=(1, 1)),
        Node(Operation.LOAD_BITS_LE, (ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 3, 0)), (api.b8, api.memory_effect), attributes=(1, 1)),
        Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 1), ValueRef.node_result(0, 4, 1)), (api.memory_effect,), entity=free_view),
    )
    graph = graph_fragment([Block((api.b8, api.memory_effect), nodes, Terminator.return_((ValueRef.node_result(0, 4, 0), ValueRef.node_result(0, 5, 0))))])
    entry = function(graph, (api.b8, api.memory_effect), (api.b8, api.memory_effect))
    target = android_arm64_shared_general_target()
    heap_types = [api.b8, api.b64, api.byte_ptr_rw, api.memory_effect, api.heap_resource, view]
    objects = [*heap_types, api.malloc, free_view, size, graph, entry]
    reader = reader_for(entry, objects, target)
    verify_store(reader)
    bundle = compile_aarch64_bundle_bound_target(reader, (entry.cid,), target)
    assert tuple(name for _, _, name in bundle.foreign_calls) == (b"malloc", b"free")


def test_android_general_target_can_emit_shared_object_for_new_lowering():
    f64 = float_type(FloatFormat.BINARY64)
    graph = graph_fragment([
        Block((f64, f64), (Node(Operation.FLOAT_ADD, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (f64,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
    ])
    entry = function(graph, (f64, f64), (f64,))
    target = android_arm64_shared_general_target()
    reader = reader_for(entry, [f64, graph, entry], target)
    shared = compile_android_shared(reader, (AndroidExport(b"xax_float_add", entry.cid),), target_object=target)
    view = inspect_android_elf(shared.data)
    assert view.machine == 183


def test_utf8_validation_search_format_and_owned_strings():
    valid = "héllo 🌍".encode()
    status = validate_utf8(valid)
    assert status.valid and status.codepoints == 7 and status.error_offset is None
    for invalid in (b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82"):
        assert not validate_utf8(invalid).valid
    assert utf8_codepoint_count(valid) == 7
    assert utf8_boundaries("aé🌍") == (0, 1, 3, 7)
    assert utf8_find("zéro zéro", "éro") == 1
    assert utf8_rfind("zéro zéro", "zéro") == len("zéro ".encode())
    assert utf8_contains("abc🌍def", "🌍")
    assert format_utf8("{0} {1:x} {{ok}}", ("value", 255)) == b"value ff {ok}"
    with pytest.raises(TypeError):
        format_utf8("{}", (object(),))

    allocator = BytearrayStringAllocator()
    first = owned_utf8(allocator, "hé", capacity=4)
    assert first.text() == "hé"
    first = append_owned_utf8(first, "!")
    assert first.text() == "hé!"
    clone = clone_owned_utf8(first)
    joined = concat_owned_utf8(allocator, (clone, " + ", "世界"))
    formatted = format_owned_utf8(allocator, "{}:{}", ("n", 7))
    assert joined.text() == "hé! + 世界"
    assert formatted.bytes() == b"n:7"
    first.free(); clone.free(); joined.free(); formatted.free()
    assert allocator.live_allocations == 0
    with pytest.raises(RuntimeError):
        first.bytes()


def test_android_platform_runtime_probe_static_contracts():
    from benchmarks.bench_android_platform_runtime import build_probe, collect_evidence
    shared = build_probe()
    evidence = collect_evidence()
    imports = set(evidence["imports"])
    assert {"open", "write", "read", "close", "pthread_create", "pthread_join", "socket", "connect", "send", "recv"} <= imports
    assert evidence["target"] == "android-arm64-v8a-shared-v4"
    assert hashlib_sha256(shared) == evidence["artifact_sha256"]


def hashlib_sha256(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


@pytest.mark.skipif(os.environ.get("XAX_ANDROID_RUNTIME") != "1", reason="requires explicit connected arm64 Android runtime")
def test_android_platform_contracts_execute_on_real_runtime():
    script = Path(__file__).parents[1] / "integration" / "android" / "validate_platform_contracts.sh"
    completed = subprocess.run([str(script)], check=False, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    evidence_path = Path(__file__).parents[1] / "benchmarks" / "android_platform_runtime_probe_evidence.json"
    evidence = json.loads(evidence_path.read_text())
    assert evidence["runtime"]["executed"] is True
    assert all(evidence["runtime"][key] for key in ("file", "thread", "socket"))
