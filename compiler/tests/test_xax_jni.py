import json
from pathlib import Path

import pytest

from benchmarks.bench_android_jni import (
    _objects_for,
    cached_post_delayed_fixture,
    cached_app_set_value_fixture,
    loader_relative_method_cache_fixture,
    release_method_cache_fixture,
    collect_evidence,
    get_version_fixture,
    global_ref_roundtrip_fixture,
    generated_listener_construction_fixture,
)
from xax_android import compile_android_shared, inspect_android_elf
from xax_compiler import (
    Block,
    Node,
    Operation,
    Terminator,
    ValueRef,
    XaxError,
    android_arm64_shared_target,
    decode_native_target,
    function,
    graph_fragment,
    opaque_identity_type,
    verify_store,
)
from xax_jni import (
    JNI_NATIVE_FUNCTION_NAMES,
    JNI_NATIVE_SLOT_BY_NAME,
    JniReferenceKind,
    jni_delete_global_ref_contract,
    jni_class_cache_owner_type,
    jni_get_method_id_contract,
    jni_new_object_zero_arg_contract,
    jni_delete_weak_global_ref_contract,
    jni_env_pointer_type,
    jni_env_table_load_node,
    jni_get_object_ref_type_contract,
    jni_memory_effect_type,
    jni_native_function_load_node,
    jni_new_global_ref_contract,
    jni_new_weak_global_ref_contract,
    jni_reference_owner_type,
    jni_reference_type,
    jni_short_native_symbol,
)


def _words(code):
    return tuple(int.from_bytes(code[index:index + 4], "little") for index in range(0, len(code), 4))


def _entry_code(shared, reader, target, fn):
    from xax_aarch64 import compile_aarch64_bundle_bound_target

    bundle = compile_aarch64_bundle_bound_target(reader, (fn.cid,), target)
    item = next(r for r in bundle.semantic_ranges if r.function_cid == fn.cid and r.block_index is None)
    return bundle.code[item.start:item.end]


def test_identity_qualified_opaque_abi_types_are_canonical_and_distinct():
    first = opaque_identity_type(b"android.jni.JNIEnv")
    again = opaque_identity_type(b"android.jni.JNIEnv")
    other = opaque_identity_type(b"android.jni.JavaVM")
    assert first.cid == again.cid
    assert first.body == again.body
    assert first.cid != other.cid
    assert first.references == ()


def test_android_jni_16_target_table_is_complete_and_exact():
    desc = decode_native_target(android_arm64_shared_target())
    assert desc.identity == b"android-arm64-v8a-shared-v3"
    assert len(desc.target_operations) == 242
    assert len(JNI_NATIVE_FUNCTION_NAMES) == 229
    assert JNI_NATIVE_FUNCTION_NAMES[0] == "GetVersion"
    assert JNI_NATIVE_FUNCTION_NAMES[-1] == "GetObjectRefType"
    expected_slots = {
        "GetVersion": 4,
        "FindClass": 6,
        "NewGlobalRef": 21,
        "GetMethodID": 33,
        "GetStaticMethodID": 113,
        "NewStringUTF": 167,
        "GetArrayLength": 171,
        "RegisterNatives": 215,
        "GetJavaVM": 219,
        "NewWeakGlobalRef": 226,
        "ExceptionCheck": 228,
        "NewDirectByteBuffer": 229,
        "GetObjectRefType": 232,
    }
    for name, slot in expected_slots.items():
        assert JNI_NATIVE_SLOT_BY_NAME[name] == slot
    by_id = {item.operation_id: item for item in desc.target_operations}
    assert by_id[1004].encoding_opcode == 4 * 8
    assert by_id[1021].encoding_opcode == 21 * 8
    assert by_id[1232].encoding_opcode == 232 * 8
    assert by_id[11].encoding_opcode == 0
    assert by_id[12].operands[-1].primary == 2001 and by_id[12].operands[-1].secondary == 2
    assert by_id[13].operands[-1].primary == 2001 and by_id[13].operands[-1].secondary == 3
    assert all(not item.runtime_dependency for item in desc.target_operations)


def test_get_version_direct_table_call_is_deterministic_and_wrapper_free():
    reader, target, fn, exports = get_version_fixture()
    first = compile_android_shared(reader, exports, target_object=target)
    second = compile_android_shared(reader, exports, target_object=target)
    assert first.data == second.data
    view = inspect_android_elf(first.data)
    assert view.imports == () and view.needed == () and view.relocation_count == 0
    words = _words(_entry_code(first, reader, target, fn))
    assert 0xF9400001 in words  # JNIEnv->functions @ 0
    assert 0xF9401021 in words  # GetVersion @ slot 4 => 32 bytes
    assert sum((word & 0xFFFFFC1F) == 0xD63F0000 for word in words) == 1


def test_global_reference_roundtrip_has_linear_release_and_no_lookup_helper():
    reader, target, fn, exports = global_ref_roundtrip_fixture()
    verify_store(reader)
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    assert view.imports == () and view.needed == () and view.relocation_count == 0
    words = _words(_entry_code(shared, reader, target, fn))
    assert 0xF9405443 in words  # NewGlobalRef @ 21*8
    assert 0xF9405821 in words  # DeleteGlobalRef @ 22*8
    assert sum((word & 0xFFFFFC1F) == 0xD63F0000 for word in words) == 2


def test_dropped_owned_global_reference_is_rejected():
    target = android_arm64_shared_target()
    env = jni_env_pointer_type()
    memory = jni_memory_effect_type()
    borrowed = jni_reference_type(JniReferenceKind.BORROWED, b"object")
    global_ref = jni_reference_type(JniReferenceKind.GLOBAL, b"object")
    global_owner = jni_reference_owner_type(JniReferenceKind.GLOBAL)
    new_contract = jni_new_global_ref_contract()
    nodes = (
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
        jni_native_function_load_node(target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), "NewGlobalRef"),
        Node(
            Operation.CALL_INDIRECT,
            (
                ValueRef.node_result(0, 1, 0),
                ValueRef.parameter(0, 0),
                ValueRef.parameter(0, 1),
                ValueRef.node_result(0, 1, 1),
            ),
            (global_ref, global_owner, memory),
            entity=new_contract,
        ),
    )
    graph = graph_fragment([
        Block(
            (env, borrowed, memory),
            nodes,
            Terminator.return_((ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 2))),
        )
    ])
    fn = function(graph, (env, borrowed, memory), (global_ref, memory))
    from benchmarks.bench_android_arm64 import _reader

    refs = ((JniReferenceKind.BORROWED, b"object"), (JniReferenceKind.GLOBAL, b"object"))
    reader = _reader((fn,), _objects_for(new_contract, graph, reference_specs=refs), target)
    with pytest.raises(XaxError) as error:
        verify_store(reader)
    assert error.value.diagnostic.code == "XAX.RESOURCE.DROP"


def test_local_and_global_reference_ownership_classes_are_distinct():
    local = jni_reference_owner_type(JniReferenceKind.LOCAL)
    global_ = jni_reference_owner_type(JniReferenceKind.GLOBAL)
    weak = jni_reference_owner_type(JniReferenceKind.WEAK_GLOBAL)
    assert len({local.cid, global_.cid, weak.cid}) == 3
    with pytest.raises(ValueError):
        jni_reference_owner_type(JniReferenceKind.BORROWED)
    assert jni_delete_global_ref_contract().cid != jni_new_global_ref_contract().cid


def test_owned_reference_use_contracts_thread_lifetime_proofs():
    global_owner = jni_reference_owner_type(JniReferenceKind.GLOBAL)
    owned_query = jni_get_object_ref_type_contract(JniReferenceKind.GLOBAL)
    borrowed_query = jni_get_object_ref_type_contract(JniReferenceKind.BORROWED)
    assert global_owner.cid in owned_query.references
    assert global_owner.cid not in borrowed_query.references

    weak_owner = jni_reference_owner_type(JniReferenceKind.WEAK_GLOBAL)
    acquire = jni_new_weak_global_ref_contract()
    release = jni_delete_weak_global_ref_contract()
    assert weak_owner.cid in acquire.references
    assert weak_owner.cid in release.references


def test_committed_jni_evidence_reproduces_exactly():
    evidence_path = Path(__file__).parents[1] / "benchmarks" / "android_jni_platform_evidence.json"
    expected = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert collect_evidence() == expected


def test_typed_method_ids_encode_owner_signature_and_staticness():
    from xax_jni import jni_typed_method_id_type, jni_get_method_id_contract, jni_get_static_method_id_contract

    instance = jni_typed_method_id_type("fixture/api/Example", "add", "(IJ)I")
    static = jni_typed_method_id_type("fixture/api/Example", "add", "(IJ)I", is_static=True)
    other_sig = jni_typed_method_id_type("fixture/api/Example", "add", "(I)I")
    assert len({instance.cid, static.cid, other_sig.cid}) == 3
    resolved = jni_get_method_id_contract(
        owner="fixture/api/Example", name="add", descriptor="(IJ)I"
    )
    resolved_static = jni_get_static_method_id_contract(
        owner="fixture/api/Example", name="add", descriptor="(IJ)I"
    )
    assert instance.cid in resolved.references
    assert static.cid in resolved_static.references


def test_descriptor_driven_method_plan_selects_exact_jni_A_variant_and_pack_size():
    from xax_jni import JNI_NATIVE_SLOT_BY_NAME, jni_method_call_plan

    plan = jni_method_call_plan(
        "fixture/api/Example",
        "mix",
        "(ILjava/lang/String;J)I",
        dispatch="virtual",
    )
    assert plan.function_name == "CallIntMethodA"
    assert plan.function_name in JNI_NATIVE_SLOT_BY_NAME
    assert plan.argument_pack_bytes == 24
    assert plan.argument_pack_alignment == 8
    assert len(plan.parameter_types) == 3
    assert len(plan.result_types) == 1
    assert plan.may_set_pending_exception is True

    static = jni_method_call_plan(
        "fixture/api/Example",
        "make",
        "()Ljava/lang/String;",
        dispatch="static",
    )
    assert static.function_name == "CallStaticObjectMethodA"
    assert len(static.result_types) == 2  # local jobject + linear local-reference owner
    assert static.argument_pack_bytes == 0

    nonvirtual = jni_method_call_plan(
        "fixture/api/Example",
        "run",
        "()V",
        dispatch="nonvirtual",
    )
    assert nonvirtual.function_name == "CallNonvirtualVoidMethodA"
    assert nonvirtual.result_types == ()


def test_descriptor_driven_field_plans_select_exact_get_set_variants():
    from xax_jni import JNI_NATIVE_SLOT_BY_NAME, jni_field_access_plan, jni_typed_field_id_type

    get_static = jni_field_access_plan(
        "fixture/api/Example", "FLAG", "I", is_static=True
    )
    assert get_static.function_name == "GetStaticIntField"
    assert get_static.function_name in JNI_NATIVE_SLOT_BY_NAME
    assert get_static.field_id_type.cid == jni_typed_field_id_type(
        "fixture/api/Example", "FLAG", "I", is_static=True
    ).cid

    set_object = jni_field_access_plan(
        "fixture/api/Example", "name", "Ljava/lang/String;", is_set=True
    )
    assert set_object.function_name == "SetObjectField"
    assert set_object.function_name in JNI_NATIVE_SLOT_BY_NAME

    get_object = jni_field_access_plan(
        "fixture/api/Example", "name", "Ljava/lang/String;"
    )
    assert get_object.function_name == "GetObjectField"
    # Object getters produce a local reference plus an owner token before memory.
    assert len(get_object.call_contract.references) >= 4


def test_float_jni_plan_rejects_until_exact_float_type_exists():
    from xax_jni import jni_method_call_plan, jni_field_access_plan

    with pytest.raises(ValueError, match="no implemented float carrier"):
        jni_method_call_plan("fixture/api/Example", "f", "(F)I")
    with pytest.raises(ValueError, match="no implemented float carrier"):
        jni_field_access_plan("fixture/api/Example", "d", "D")


def test_stack_jvalue_pack_initializes_full_jint_slot_and_rejects_unsupported_shapes():
    from xax_compiler import Operation
    from xax_jni import jni_argument_pack_nodes, jni_argument_pack_plan

    plan = jni_argument_pack_plan("(I)V")
    pack = jni_argument_pack_nodes(plan, (ValueRef.parameter(0, 0),))
    assert plan.total_bytes == 8
    assert plan.store_bytes == 4
    assert [node.operation for node in pack.nodes] == [
        Operation.STACK_ALLOC,
        Operation.CONSTANT,
        Operation.STORE_BITS_LE,
        Operation.ADDRESS_OFFSET,
        Operation.STORE_BITS_LE,
    ]
    assert pack.nodes[-1].attributes == (4, 4)
    narrow = jni_argument_pack_plan("(Z)V")
    narrow_pack = jni_argument_pack_nodes(narrow, (ValueRef.parameter(0, 0),))
    narrow_stores = [node for node in narrow_pack.nodes if node.operation == Operation.STORE_BITS_LE]
    assert narrow.store_bytes == 1
    assert len(narrow_stores) == 8
    assert all(node.attributes == (1, 1) for node in narrow_stores)
    short = jni_argument_pack_plan("(S)V")
    short_pack = jni_argument_pack_nodes(short, (ValueRef.parameter(0, 0),))
    short_stores = [node for node in short_pack.nodes if node.operation == Operation.STORE_BITS_LE]
    assert short.store_bytes == 2
    assert len(short_stores) == 4
    assert all(node.attributes == (2, 2) for node in short_stores)
    with pytest.raises(ValueError, match="homogeneous integer"):
        jni_argument_pack_plan("(ILjava/lang/String;)V")
    with pytest.raises(ValueError, match="homogeneous integer"):
        jni_argument_pack_plan("(F)V")


def test_mixed_reference_jvalue_pack_checks_type_loader_nullability_and_sdk_subtyping():
    from xax_android_sdk import import_android_classes, parse_classfile
    from xax_jni import (
        JniReferenceArgumentSpec,
        jni_argument_pack_plan,
        jni_reference_descriptor_assignable,
        jni_reference_type,
    )

    boot = b"android.boot"
    borrowed_nullable = jni_reference_type(
        JniReferenceKind.BORROWED, b"java.lang.Runnable", loader_domain=boot, nullable=True
    )
    borrowed_nonnull = jni_reference_type(
        JniReferenceKind.BORROWED, b"java.lang.Runnable", loader_domain=boot, nullable=False
    )
    legacy = jni_reference_type(JniReferenceKind.BORROWED, b"java.lang.Runnable", loader_domain=boot)
    assert len({borrowed_nullable.cid, borrowed_nonnull.cid, legacy.cid}) == 3

    runnable = JniReferenceArgumentSpec(
        "Ljava/lang/Runnable;", JniReferenceKind.BORROWED, boot, nullable=True
    )
    plan = jni_argument_pack_plan(
        "(Ljava/lang/Runnable;J)Z",
        reference_arguments=(runnable, None),
        expected_reference_loader_domains=(boot, None),
    )
    assert plan.mode == "mixed_word"
    assert plan.total_bytes == 16 and plan.store_bytes == 8
    assert plan.value_types[0].cid == borrowed_nullable.cid

    with pytest.raises(ValueError, match="loader domain"):
        jni_argument_pack_plan(
            "(Ljava/lang/Runnable;J)Z",
            reference_arguments=(runnable, None),
            expected_reference_loader_domains=(b"app:fixture", None),
        )
    with pytest.raises(ValueError, match="mixed jlong"):
        jni_argument_pack_plan(
            "(Ljava/lang/Runnable;I)Z",
            reference_arguments=(runnable, None),
            expected_reference_loader_domains=(boot, None),
        )
    with pytest.raises(ValueError, match="weak-global"):
        JniReferenceArgumentSpec(
            "Ljava/lang/Runnable;", JniReferenceKind.WEAK_GLOBAL, boot
        )

    fixture = Path(__file__).parent / "fixtures" / "android_sdk_example.class"
    sdk = import_android_classes((parse_classfile(fixture.read_bytes()),))
    assert not jni_reference_descriptor_assignable(
        "Lfixture/api/Example;", "Ljava/io/Serializable;"
    )
    assert jni_reference_descriptor_assignable(
        "Lfixture/api/Example;", "Ljava/io/Serializable;", sdk=sdk
    )
    subtype = JniReferenceArgumentSpec(
        "Lfixture/api/Example;", JniReferenceKind.BORROWED, b"app:fixture", nullable=False
    )
    subtype_plan = jni_argument_pack_plan(
        "(Ljava/io/Serializable;J)V",
        reference_arguments=(subtype, None),
        expected_reference_loader_domains=(b"app:fixture", None),
        sdk=sdk,
    )
    assert subtype_plan.mode == "mixed_word"


def test_owned_reference_projection_threads_linear_owner_and_rejects_missing_owner():
    from benchmarks.bench_android_arm64 import _reader
    from xax_compiler import (
        Kind,
        bits_type,
        object_with_refs,
        write_store,
        StoreReader,
    )
    from xax_jni import (
        JniReferenceArgumentSpec,
        jni_reference_word_node,
        jni_type_objects,
    )

    target = android_arm64_shared_target()
    boot = b"android.boot"
    spec = JniReferenceArgumentSpec(
        "Ljava/lang/String;", JniReferenceKind.LOCAL, boot, nullable=True
    )
    reference = jni_reference_type(
        JniReferenceKind.LOCAL, b"java.lang.String", loader_domain=boot, nullable=True
    )
    owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    with pytest.raises(ValueError, match="requires its linear owner"):
        jni_reference_word_node(target, ValueRef.parameter(0, 0), spec)

    projection = jni_reference_word_node(
        target,
        ValueRef.parameter(0, 0),
        spec,
        owner=ValueRef.parameter(0, 1),
    )
    graph = graph_fragment([Block(
        (reference, owner),
        (projection,),
        Terminator.return_((ValueRef.node_result(0, 0, 1),)),
    )])
    fn = function(graph, (reference, owner), (owner,))
    objects = {obj.cid: obj for obj in jni_type_objects(((JniReferenceKind.LOCAL, b"java.lang.String", boot, True),))}
    for obj in (bits_type(64), graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    verify_store(reader)

    bad_graph = graph_fragment([Block(
        (reference, owner),
        (projection,),
        Terminator.return_((ValueRef.parameter(0, 1),)),
    )])
    bad_fn = function(bad_graph, (reference, owner), (owner,))
    module = object_with_refs(Kind.MODULE, (bad_fn,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    bad_objects = dict(objects)
    for obj in (bad_graph, bad_fn, module, root, target):
        bad_objects[obj.cid] = obj
    with pytest.raises(XaxError, match="XAX.RESOURCE.DUPLICATE"):
        verify_store(StoreReader(write_store(root.cid, bad_objects.values())))


def test_cached_post_delayed_mixed_reference_pack_is_wrapper_free_and_deterministic():
    from benchmarks.bench_android_arm64 import _function_code, _code_metrics

    reader, target, fn, exports = cached_post_delayed_fixture()
    verify_store(reader)
    first = compile_android_shared(reader, exports, target_object=target)
    second = compile_android_shared(reader, exports, target_object=target)
    assert first.data == second.data
    view = inspect_android_elf(first.data)
    code = _function_code(first, reader, target, (fn.cid,), fn.cid)
    metrics = _code_metrics(code)
    assert metrics["bytes"] == 88
    assert metrics["instructions"] == 22
    # The borrowed Runnable reference is stored directly into jvalue[0].l;
    # the semantic reference->ABI-word projection emits no instruction here.
    assert metrics["words_hex"][4:7] == ["f90003e3", "f90007e4", "910003e3"]
    assert view.imports == () and view.needed == () and view.relocation_count == 0


def test_cached_set_visibility_stack_pack_verifies_and_compiles_without_helpers():
    from benchmarks.bench_android_jni import cached_set_visibility_fixture
    from benchmarks.bench_android_arm64 import _function_code, _code_metrics
    from xax_android import compile_android_shared, inspect_android_elf
    from xax_compiler import verify_store

    reader, target, fn, exports = cached_set_visibility_fixture()
    verify_store(reader)
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    code = _function_code(shared, reader, target, (fn.cid,), fn.cid)
    metrics = _code_metrics(code)
    assert metrics["bytes"] == 84
    assert metrics["instructions"] == 21
    assert view.imports == ()
    assert view.needed == ()
    assert view.relocation_count == 0



def test_cached_set_clickable_narrow_pack_compiles_to_exact_byte_stores():
    from benchmarks.bench_android_jni import cached_set_clickable_fixture
    from benchmarks.bench_android_arm64 import _function_code, _code_metrics
    from xax_android import compile_android_shared, inspect_android_elf
    from xax_compiler import verify_store

    reader, target, fn, exports = cached_set_clickable_fixture()
    verify_store(reader)
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    code = _function_code(shared, reader, target, (fn.cid,), fn.cid)
    metrics = _code_metrics(code)
    assert metrics["bytes"] == 108
    assert metrics["instructions"] == 27
    # STRB W3,[SP] then seven STRB W6 padding stores fill the 8-byte jvalue slot.
    assert metrics["words_hex"][5:13] == [
        "390003e3", "390007e6", "39000be6", "39000fe6",
        "390013e6", "390017e6", "39001be6", "39001fe6",
    ]
    assert view.imports == ()
    assert view.needed == ()
    assert view.relocation_count == 0

def test_pending_exception_state_is_linear_and_requires_explicit_policy_transition():
    from xax_compiler import ResourceFlags
    from xax_jni import (
        JniExceptionState,
        jni_exception_clear_state_contract,
        jni_exception_state_type,
        jni_stack_method_call_contract,
        jni_argument_pack_plan,
        jni_method_call_plan,
    )

    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    assert clean.cid != maybe.cid
    plan = jni_method_call_plan("android/view/View", "setVisibility", "(I)V")
    pack = jni_argument_pack_plan("(I)V")
    stateful = jni_stack_method_call_contract(plan, pack, track_exception_state=True)
    assert clean.cid in stateful.references
    assert maybe.cid in stateful.references
    clear = jni_exception_clear_state_contract()
    assert maybe.cid in clear.references
    assert clean.cid in clear.references


def test_cached_framework_probe_threads_and_clears_pending_exception_state():
    from benchmarks.bench_android_jni import cached_set_visibility_fixture
    from xax_compiler import verify_store

    reader, _target, _fn, _exports = cached_set_visibility_fixture()
    verify_store(reader)


def test_loader_domains_qualify_reference_member_and_plan_identity_without_changing_legacy_ids():
    from xax_jni import (
        jni_method_call_plan,
        jni_reference_type,
        jni_typed_field_id_type,
        jni_typed_method_id_type,
    )

    owner = "android/view/View"
    name = "setVisibility"
    descriptor = "(I)V"
    legacy = jni_typed_method_id_type(owner, name, descriptor)
    explicit_legacy = jni_typed_method_id_type(owner, name, descriptor, loader_domain=None)
    boot = jni_typed_method_id_type(owner, name, descriptor, loader_domain=b"android.boot")
    app = jni_typed_method_id_type(owner, name, descriptor, loader_domain=b"app:fixture")
    assert legacy.cid == explicit_legacy.cid
    assert len({legacy.cid, boot.cid, app.cid}) == 3

    boot_ref = jni_reference_type(
        JniReferenceKind.BORROWED, b"android.view.View", loader_domain=b"android.boot"
    )
    app_ref = jni_reference_type(
        JniReferenceKind.BORROWED, b"android.view.View", loader_domain=b"app:fixture"
    )
    assert boot_ref.cid != app_ref.cid

    plan = jni_method_call_plan(owner, name, descriptor, loader_domain=b"android.boot")
    assert plan.loader_domain == b"android.boot"
    assert plan.method_id_type.cid == boot.cid
    assert boot_ref.cid in plan.call_contract.references
    assert app_ref.cid not in plan.call_contract.references

    boot_field = jni_typed_field_id_type(
        owner, "mVisibilityFlags", "I", loader_domain=b"android.boot"
    )
    app_field = jni_typed_field_id_type(
        owner, "mVisibilityFlags", "I", loader_domain=b"app:fixture"
    )
    assert boot_field.cid != app_field.cid

    with pytest.raises(ValueError, match="loader domain"):
        jni_typed_method_id_type(owner, name, descriptor, loader_domain=b"")


def test_loader_domain_survives_local_global_weak_reference_lifetime_transitions():
    from xax_jni import (
        jni_delete_global_ref_contract,
    jni_class_cache_owner_type,
    jni_get_method_id_contract,
    jni_new_object_zero_arg_contract,
        jni_delete_local_ref_contract,
        jni_delete_weak_global_ref_contract,
        jni_get_object_class_contract,
        jni_new_global_ref_contract,
        jni_new_local_ref_contract,
        jni_new_weak_global_ref_contract,
    )

    family = b"android.view.View"
    boot = b"android.boot"
    app = b"app:fixture"
    for kind, builder, releaser in (
        (JniReferenceKind.GLOBAL, jni_new_global_ref_contract, jni_delete_global_ref_contract),
        (JniReferenceKind.LOCAL, jni_new_local_ref_contract, jni_delete_local_ref_contract),
        (JniReferenceKind.WEAK_GLOBAL, jni_new_weak_global_ref_contract, jni_delete_weak_global_ref_contract),
    ):
        boot_ref = jni_reference_type(kind, family, loader_domain=boot)
        app_ref = jni_reference_type(kind, family, loader_domain=app)
        acquire = builder(family=family, loader_domain=boot)
        release = releaser(family, loader_domain=boot)
        assert boot_ref.cid in acquire.references
        assert boot_ref.cid in release.references
        assert app_ref.cid not in acquire.references
        assert app_ref.cid not in release.references

    object_class = jni_get_object_class_contract(
        JniReferenceKind.BORROWED,
        family,
        owner="android/view/View",
        loader_domain=boot,
    )
    boot_class = jni_reference_type(JniReferenceKind.LOCAL, family, loader_domain=boot)
    app_class = jni_reference_type(JniReferenceKind.LOCAL, family, loader_domain=app)
    assert boot_class.cid in object_class.references
    assert app_class.cid not in object_class.references


def test_loader_mismatched_receiver_is_rejected_by_indirect_call_contract():
    from benchmarks.bench_android_arm64 import _reader
    from xax_compiler import (
        Block,
        Node,
        Operation,
        Terminator,
        ValueRef,
        android_arm64_shared_target,
        function,
        function_pointer_type,
        graph_fragment,
        verify_store,
    )
    from xax_jni import jni_method_call_plan, jni_type_objects, jni_value_array_pointer_type

    boot = b"android.boot"
    app = b"app:fixture"
    plan = jni_method_call_plan(
        "android/view/View", "setVisibility", "(I)V", loader_domain=boot
    )
    fptr = function_pointer_type()
    env = jni_env_pointer_type()
    wrong_receiver = jni_reference_type(
        JniReferenceKind.BORROWED, b"android.view.View", loader_domain=app
    )
    args = jni_value_array_pointer_type()
    memory = jni_memory_effect_type()
    graph = graph_fragment([Block(
        (fptr, env, wrong_receiver, plan.method_id_type, args, memory),
        (Node(
            Operation.CALL_INDIRECT,
            tuple(ValueRef.parameter(0, index) for index in range(6)),
            (memory,),
            entity=plan.call_contract,
        ),),
        Terminator.return_((ValueRef.node_result(0, 0, 0),)),
    )])
    fn = function(graph, (fptr, env, wrong_receiver, plan.method_id_type, args, memory), (memory,))
    refs = (
        (JniReferenceKind.BORROWED, b"android.view.View", boot),
        (JniReferenceKind.BORROWED, b"android.view.View", app),
    )
    methods = (("android/view/View", "setVisibility", "(I)V", False, boot),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs, method_specs=methods)}
    for obj in (fptr, args, plan.call_contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), android_arm64_shared_target())
    with pytest.raises(XaxError) as error:
        verify_store(reader)
    assert error.value.diagnostic.code == "XAX.CALL.INDIRECT"


def test_class_cache_owner_is_content_qualified_and_linear():
    from benchmarks.bench_android_arm64 import _reader

    boot = jni_class_cache_owner_type("fixture/Target", loader_domain=b"android.boot")
    boot_again = jni_class_cache_owner_type("fixture/Target", loader_domain=b"android.boot")
    app = jni_class_cache_owner_type("fixture/Target", loader_domain=b"app:fixture")
    other = jni_class_cache_owner_type("fixture/Other", loader_domain=b"app:fixture")
    assert boot.cid == boot_again.cid
    assert len({boot.cid, app.cid, other.cid}) == 3

    graph = graph_fragment([Block((app,), (), Terminator.return_(()))])
    fn = function(graph, (app,), ())
    reader = _reader((fn,), (app, graph), android_arm64_shared_target())
    with pytest.raises(XaxError, match="XAX.RESOURCE"):
        verify_store(reader)

    with pytest.raises(ValueError, match="typed global class"):
        jni_get_method_id_contract(
            JniReferenceKind.LOCAL,
            owner="fixture/Target",
            name="setValue",
            descriptor="(J)V",
            loader_domain=b"app:fixture",
            class_cache_owner=True,
        )


def test_loader_relative_method_cache_resolves_once_calls_twice_and_releases():
    from benchmarks.bench_android_arm64 import _function_code, _code_metrics

    reader, target, fn, exports = loader_relative_method_cache_fixture()
    verify_store(reader)
    first = compile_android_shared(reader, exports, target_object=target)
    second = compile_android_shared(reader, exports, target_object=target)
    assert first.data == second.data
    view = inspect_android_elf(first.data)
    metrics = _code_metrics(_function_code(first, reader, target, (fn.cid,), fn.cid))
    assert metrics["bytes"] == 364
    assert metrics["instructions"] == 91
    words = tuple(int(word, 16) for word in metrics["words_hex"])
    slot_masks = tuple(word & 0xFFFFFC00 for word in words)
    for name in ("GetObjectClass", "NewGlobalRef", "DeleteLocalRef", "GetMethodID", "CallVoidMethodA", "DeleteGlobalRef"):
        expected = 0xF9400000 | (JNI_NATIVE_SLOT_BY_NAME[name] << 10)
        assert slot_masks.count(expected) == 1, name
    exception_clear = 0xF9400000 | (JNI_NATIVE_SLOT_BY_NAME["ExceptionClear"] << 10)
    assert slot_masks.count(exception_clear) == 2
    assert sum((word & 0xFFFFFC1F) == 0xD63F0000 for word in words) == 9
    assert view.imports == () and view.needed == () and view.relocation_count == 0


def test_cached_loader_qualified_hot_call_has_no_lookup_or_runtime_cache_layer():
    from benchmarks.bench_android_arm64 import _function_code, _code_metrics

    reader, target, fn, exports = cached_app_set_value_fixture()
    verify_store(reader)
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    metrics = _code_metrics(_function_code(shared, reader, target, (fn.cid,), fn.cid))
    assert metrics["bytes"] == 76
    assert metrics["instructions"] == 19
    words = tuple(int(word, 16) for word in metrics["words_hex"])
    slot_masks = tuple(word & 0xFFFFFC00 for word in words)
    for name in ("FindClass", "GetObjectClass", "GetMethodID", "NewGlobalRef"):
        unexpected = 0xF9400000 | (JNI_NATIVE_SLOT_BY_NAME[name] << 10)
        assert unexpected not in slot_masks
    call_slot = 0xF9400000 | (JNI_NATIVE_SLOT_BY_NAME["CallVoidMethodA"] << 10)
    clear_slot = 0xF9400000 | (JNI_NATIVE_SLOT_BY_NAME["ExceptionClear"] << 10)
    assert slot_masks.count(call_slot) == 1
    assert slot_masks.count(clear_slot) == 1
    assert view.imports == () and view.needed == () and view.relocation_count == 0


def test_method_cache_teardown_is_explicit_delete_global_ref_only():
    from benchmarks.bench_android_arm64 import _function_code, _code_metrics

    reader, target, fn, exports = release_method_cache_fixture()
    verify_store(reader)
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    metrics = _code_metrics(_function_code(shared, reader, target, (fn.cid,), fn.cid))
    assert metrics["bytes"] == 36
    assert metrics["instructions"] == 9
    words = tuple(int(word, 16) for word in metrics["words_hex"])
    slot_masks = tuple(word & 0xFFFFFC00 for word in words)
    delete_slot = 0xF9400000 | (JNI_NATIVE_SLOT_BY_NAME["DeleteGlobalRef"] << 10)
    assert slot_masks.count(delete_slot) == 1
    assert sum((word & 0xFFFFFC1F) == 0xD63F0000 for word in words) == 1
    assert view.imports == () and view.needed == () and view.relocation_count == 0


def test_zero_arg_listener_construction_is_explicit_nullable_and_exception_tracked():
    from benchmarks.bench_android_arm64 import _function_code, _code_metrics

    reader, target, fn, exports = generated_listener_construction_fixture()
    verify_store(reader)
    first = compile_android_shared(reader, exports, target_object=target)
    second = compile_android_shared(reader, exports, target_object=target)
    assert first.data == second.data
    view = inspect_android_elf(first.data)
    metrics = _code_metrics(_function_code(first, reader, target, (fn.cid,), fn.cid))
    assert metrics["bytes"] == 36
    assert metrics["instructions"] == 9
    words = tuple(int(word, 16) for word in metrics["words_hex"])
    slot_masks = tuple(word & 0xFFFFFC00 for word in words)
    new_object = 0xF9400000 | (JNI_NATIVE_SLOT_BY_NAME["NewObject"] << 10)
    assert slot_masks.count(new_object) == 1
    assert sum((word & 0xFFFFFC1F) == 0xD63F0000 for word in words) == 1
    assert view.imports == () and view.needed == () and view.relocation_count == 0

    with pytest.raises(ValueError, match="global class reference"):
        jni_new_object_zero_arg_contract(
            owner="xax/generated/XaxOnClickListener",
            loader_domain=b"app:xax.generated",
            class_kind=JniReferenceKind.LOCAL,
            class_cache_owner=True,
        )
