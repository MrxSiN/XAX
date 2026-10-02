"""Deterministic Android arm64-v8a structural/codegen evidence.

This benchmark deliberately measures generated artifacts only.  It does not
claim Android loader latency without an Android device/emulator.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from xax_aarch64 import compile_aarch64_bundle_bound_target
from xax_android import AndroidExport, compile_android_shared, inspect_android_elf
from xax_jni import (
    JNI_VERSION_1_6,
    java_vm_pointer_type,
    java_vm_table_load_node,
    jni_env_slot_pointer_type,
    jni_get_env_contract,
    jni_invoke_function_load_node,
    jni_memory_effect_type,
    jni_type_objects,
    jni_void_pointer_type,
)
from xax_compiler import (
    AtomicScope,
    Block,
    EffectDomain,
    Kind,
    Node,
    OpaqueKind,
    Operation,
    Permission,
    StoreReader,
    Terminator,
    ValueRef,
    android_arm64_shared_target,
    bits_type,
    call_contract,
    constant,
    effect_type,
    foreign_function_symbol,
    function,
    function_pointer_type,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    opaque_type,
    pointer_type,
    stack_owner_type,
    write_store,
)


def _reader(functions, objects, target):
    candidates = {obj.cid: obj for obj in (*objects, *functions, target)}
    reachable = {}
    pending = [obj.cid for obj in (*functions, target)]
    while pending:
        cid = pending.pop()
        if cid in reachable:
            continue
        obj = candidates[cid]
        reachable[cid] = obj
        pending.extend(ref for ref in obj.references if ref not in reachable)
    module = object_with_refs(Kind.MODULE, [*functions, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    all_objects = [*reachable.values(), module, root]
    unique = {obj.cid: obj for obj in all_objects}
    return StoreReader(write_store(root.cid, unique.values()))


def _abi_types():
    b32 = bits_type(32)
    b64 = bits_type(64)
    external_object = opaque_type(OpaqueKind.OBJECT)
    external_pointer = pointer_type(external_object, Permission.READ, 8)
    function_object = opaque_type(OpaqueKind.FUNCTION)
    function_pointer = function_pointer_type()
    external_memory = effect_type(EffectDomain.MEMORY, 1)
    return b32, b64, external_object, external_pointer, function_object, function_pointer, external_memory


def simple_add_fixture():
    target = android_arm64_shared_target()
    b32 = bits_type(32)
    graph = graph_fragment([
        Block((b32, b32), (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
    ])
    fn = function(graph, (b32, b32), (b32,))
    reader = _reader((fn,), (b32, graph), target)
    return reader, target, fn, (AndroidExport(b"add", fn.cid),)


def minimal_native_init_fixture():
    target = android_arm64_shared_target()
    b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem = _abi_types()
    callback_graph = graph_fragment([Block((ext_ptr, ext_ptr), (), Terminator.return_(()))])
    callback = function(callback_graph, (ext_ptr, ext_ptr), ())
    init_graph = graph_fragment([
        Block(
            (ext_ptr, ext_mem),
            (Node(Operation.FUNCTION_ADDRESS, (), (fn_ptr,), entity=callback),),
            Terminator.return_((ValueRef.node_result(0, 0), ValueRef.parameter(0, 1))),
        )
    ])
    init = function(init_graph, (ext_ptr, ext_mem), (fn_ptr, ext_mem))
    objects = (b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem, callback_graph, init_graph)
    reader = _reader((init, callback), objects, target)
    return reader, target, init, callback, (AndroidExport(b"native_init", init.cid),)


def libxposed_native_init_fixture():
    target = android_arm64_shared_target()
    b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem = _abi_types()
    callback_graph = graph_fragment([Block((ext_ptr, ext_ptr), (), Terminator.return_(()))])
    callback = function(callback_graph, (ext_ptr, ext_ptr), ())
    nodes = (
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32, ext_mem), entity=target, attributes=(1, AtomicScope.SYSTEM, 0, 0)),
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 1)), (fn_ptr, ext_mem), entity=target, attributes=(2, AtomicScope.SYSTEM, 0, 0)),
        Node(Operation.FUNCTION_ADDRESS, (), (fn_ptr,), entity=callback),
    )
    graph = graph_fragment([Block((ext_ptr, ext_mem), nodes, Terminator.return_((ValueRef.node_result(0, 2), ValueRef.node_result(0, 1, 1))))])
    init = function(graph, (ext_ptr, ext_mem), (fn_ptr, ext_mem))
    objects = (b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem, callback_graph, graph)
    reader = _reader((init, callback), objects, target)
    return reader, target, init, callback, (AndroidExport(b"native_init", init.cid),)


def libxposed_hook_call_fixture():
    target = android_arm64_shared_target()
    b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem = _abi_types()
    contract = call_contract((ext_ptr, ext_ptr, ext_ptr, ext_mem), (b32, ext_mem), may_return=True, may_trap=False)
    nodes = (
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 4)), (fn_ptr, ext_mem), entity=target, attributes=(2, AtomicScope.SYSTEM, 0, 0)),
        Node(
            Operation.CALL_INDIRECT,
            (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 2), ValueRef.parameter(0, 3), ValueRef.node_result(0, 0, 1)),
            (b32, ext_mem),
            entity=contract,
        ),
    )
    params = (ext_ptr, ext_ptr, ext_ptr, ext_ptr, ext_mem)
    graph = graph_fragment([Block(params, nodes, Terminator.return_((ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1))))])
    fn = function(graph, params, (b32, ext_mem))
    objects = (b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem, contract, graph)
    reader = _reader((fn,), objects, target)
    return reader, target, fn, (AndroidExport(b"hook_probe", fn.cid),)



def indirect_cycle_fixture():
    """Bounded indirect call whose ABI argument placement swaps x0/x1."""
    target = android_arm64_shared_target()
    b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem = _abi_types()
    contract = call_contract((ext_ptr, ext_ptr, ext_mem), (b32, ext_mem), may_return=True, may_trap=False)
    params = (ext_ptr, ext_ptr, fn_ptr, ext_mem)
    node = Node(
        Operation.CALL_INDIRECT,
        (ValueRef.parameter(0, 2), ValueRef.parameter(0, 1), ValueRef.parameter(0, 0), ValueRef.parameter(0, 3)),
        (b32, ext_mem),
        entity=contract,
    )
    graph = graph_fragment([Block(params, (node,), Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1))))])
    fn = function(graph, params, (b32, ext_mem))
    objects = (b32, b64, opaque, ext_ptr, fn_opaque, fn_ptr, ext_mem, contract, graph)
    reader = _reader((fn,), objects, target)
    return reader, target, fn, (AndroidExport(b"indirect_swap", fn.cid),)

def jni_onload_fixture():
    target = android_arm64_shared_target()
    b32 = bits_type(32)
    vm = java_vm_pointer_type()
    reserved = jni_void_pointer_type()
    ext_mem = jni_memory_effect_type()
    local_mem = memory_effect_type()
    owner = stack_owner_type()
    env_slot = jni_env_slot_pointer_type()
    version = constant(b32, JNI_VERSION_1_6)
    contract = jni_get_env_contract(env_slot, owner, local_mem)
    nodes = (
        java_vm_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
        jni_invoke_function_load_node(target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), "GetEnv"),
        Node(Operation.STACK_ALLOC, (), (env_slot, owner, local_mem), attributes=(8, 8)),
        Node(Operation.CONSTANT, (), (b32,), entity=version),
        Node(
            Operation.CALL_INDIRECT,
            (
                ValueRef.node_result(0, 1, 0),
                ValueRef.parameter(0, 0),
                ValueRef.node_result(0, 2, 0),
                ValueRef.node_result(0, 3),
                ValueRef.node_result(0, 1, 1),
                ValueRef.node_result(0, 2, 1),
                ValueRef.node_result(0, 2, 2),
            ),
            (b32, ext_mem, owner, local_mem),
            entity=contract,
        ),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 4, 2), ValueRef.node_result(0, 4, 3)), ()),
        Node(Operation.CONSTANT, (), (b32,), entity=version),
    )
    params = (vm, reserved, ext_mem)
    graph = graph_fragment([Block(params, nodes, Terminator.return_((ValueRef.node_result(0, 6), ValueRef.node_result(0, 4, 1))))])
    fn = function(graph, params, (b32, ext_mem))
    objects = {obj.cid: obj for obj in jni_type_objects()}
    for obj in (b32, local_mem, owner, version, contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects[cid] for cid in sorted(objects)), target)
    return reader, target, fn, (AndroidExport(b"JNI_OnLoad", fn.cid),)


def bionic_import_fixture():
    target = android_arm64_shared_target()
    b32 = bits_type(32)
    syscall = effect_type(EffectDomain.SYSCALL)
    foreign = foreign_function_symbol(b"libc.so", b"getpid", (syscall,), (b32, syscall))
    graph = graph_fragment([
        Block(
            (syscall,),
            (Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 0),), (b32, syscall), entity=foreign),),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1))),
        )
    ])
    fn = function(graph, (syscall,), (b32, syscall))
    reader = _reader((fn,), (b32, syscall, foreign, graph), target)
    return reader, target, fn, (AndroidExport(b"probe_getpid", fn.cid),)


def _function_code(shared, reader, target, function_cids, function_cid):
    bundle = compile_aarch64_bundle_bound_target(reader, function_cids, target)
    semantic = next(
        item for item in bundle.semantic_ranges
        if item.function_cid == function_cid and item.block_index is None
    )
    # Measure the final ELF text, after Android import-thunk/local-address fixups,
    # not the pre-emission bundle with unresolved foreign-call placeholders.
    start = shared.text_offset + semantic.start
    end = shared.text_offset + semantic.end
    return shared.data[start:end]


def _code_metrics(code):
    words = [int.from_bytes(code[i:i+4], "little") for i in range(0, len(code), 4)]
    loads = stores = sp_adjust = x30 = 0
    frame = 0
    for word in words:
        top = word & 0xFFC00000
        rn, rt = (word >> 5) & 31, word & 31
        if rn == 31 and top in (0xB9400000, 0xF9400000): loads += 1
        if rn == 31 and top in (0xB9000000, 0xF9000000): stores += 1
        if rn == 31 and rt == 31 and (word & 0xFF000000) in (0xD1000000, 0x91000000):
            sp_adjust += 1
            if (word & 0xFF000000) == 0xD1000000: frame = max(frame, (word >> 10) & 0xFFF)
        if rn == 31 and rt == 30 and top in (0xF9400000, 0xF9000000): x30 += 1
    return {"instructions": len(words), "bytes": len(code), "stack_loads": loads, "stack_stores": stores, "frame_bytes": frame, "sp_adjustments": sp_adjust, "x30_stack_ops": x30, "words_hex": [f"{w:08x}" for w in words]}


def _artifact_record(name, fixture):
    values = fixture()
    if name in ("minimal_native_init", "libxposed_native_init"):
        reader, target, fn, callback, exports = values
        function_cids = (fn.cid, callback.cid)
    else:
        reader, target, fn, exports = values
        function_cids = (fn.cid,)
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    code = _function_code(shared, reader, target, function_cids, fn.cid)
    return {
        "sha256": hashlib.sha256(shared.data).hexdigest(),
        "elf": {
            "file_bytes": shared.metrics.file_bytes,
            "text_bytes": shared.metrics.text_bytes,
            "rodata_bytes": shared.metrics.rodata_bytes,
            "data_bytes": shared.metrics.data_bytes,
            "bss_bytes": shared.metrics.bss_bytes,
            "pt_load": shared.metrics.load_segments,
            "load_alignments": list(view.load_alignments),
            "exports": [x.decode() for x in view.exports],
            "imports": [x.decode() for x in view.imports],
            "needed": [x.decode() for x in view.needed],
            "relocations": view.relocation_count,
            "constructors": shared.metrics.constructors,
            "tls": shared.metrics.tls_entries,
        },
        "entry_code": _code_metrics(code),
    }


def collect_evidence():
    return {
        "schema": "xax-android-arm64-evidence-v1",
        "environment_note": "structural/codegen measurements only; no Android device/emulator or Android NDK was available on the measurement host",
        "runtime_overhead_audit_minimal": {
            "xax_runtime_dependency": 0,
            "xax_heap_allocations_at_startup": 0,
            "tls_entries": 0,
            "constructors": 0,
            "destructors": 0,
            "exception_runtime": 0,
            "cpp_runtime": 0,
            "automatic_libc_dependency": 0,
            "automatic_libdl_dependency": 0,
            "dynamic_relocations": 0,
            "exported_symbols": 1
        },
        "ndk_c_reference": "source fixtures committed; optimized NDK comparison not measured because Android NDK is unavailable on this host",
        "fixtures": {
            "simple_add": _artifact_record("simple_add", simple_add_fixture),
            "minimal_native_init": _artifact_record("minimal_native_init", minimal_native_init_fixture),
            "libxposed_native_init": _artifact_record("libxposed_native_init", libxposed_native_init_fixture),
            "libxposed_hook_call": _artifact_record("libxposed_hook_call", libxposed_hook_call_fixture),
            "jni_onload": _artifact_record("jni_onload", jni_onload_fixture),
            "bionic_import": _artifact_record("bionic_import", bionic_import_fixture),
        },
    }


def main():
    evidence = collect_evidence()
    path = Path(__file__).with_name("android_arm64_evidence.json")
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
