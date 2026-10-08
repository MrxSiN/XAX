"""Exact JNI jfloat/jdouble carriers and typed-record jvalue packs (ADR-202)."""
from __future__ import annotations

import pytest

from benchmarks.bench_android_arm64 import _reader
from xax_android import AndroidExport, compile_android_shared
from xax_android_managed import AndroidManagedClass, AndroidManagedMethod, android_managed_class_semantics, check_export_signature, lower_android_managed_class
from xax_compiler import (
    Block,
    FloatFormat,
    Node,
    Operation,
    Terminator,
    ValueRef,
    XaxError,
    android_arm64_shared_general_target,
    bits_type,
    float_type,
    function,
    graph_fragment,
    memory_effect_type,
    stack_owner_type,
    verify_store,
)
from xax_dex import emit_dex039_bridge, inspect_dex
from xax_graph_builder import GraphBuilder
from xax_jni import (
    JniExceptionState,
    JniReferenceArgumentSpec,
    JniReferenceKind,
    jni_argument_pack_nodes,
    jni_argument_pack_plan,
    jni_env_pointer_type,
    jni_env_table_load_node,
    jni_exception_state_type,
    jni_field_access_plan,
    jni_memory_effect_type,
    jni_method_call_plan,
    jni_native_function_load_node,
    jni_reference_type,
    jni_stack_method_call_contract,
    jni_type_objects,
    jni_typed_method_id_type,
)

F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
BOOT = b"android.boot"


def test_float_plans_use_exact_ieee_carriers():
    get_x = jni_method_call_plan("android/view/MotionEvent", "getX", "(I)F", loader_domain=BOOT)
    assert get_x.function_name == "CallFloatMethodA"
    assert get_x.parameter_types == (bits_type(32),) and get_x.result_types == (F32,)
    scale = jni_method_call_plan("java/lang/Math", "scalb", "(DI)D", dispatch="static")
    assert scale.function_name == "CallStaticDoubleMethodA" and scale.result_types == (F64,)
    field = jni_field_access_plan("fixture/P", "ratio", "D", is_set=True)
    assert field.function_name == "SetDoubleField" and field.value_type == F64


def test_existing_pack_forms_keep_their_identity():
    # Pre-float shapes keep their pack mode and pointer type (and so every existing CID).
    assert jni_argument_pack_plan("(I)V").mode == "homogeneous_integer"
    assert jni_argument_pack_plan("(J)V").pointer_type == jni_argument_pack_plan("(JJ)V").pointer_type
    spec = JniReferenceArgumentSpec("Ljava/lang/Runnable;", loader_domain=BOOT)
    assert jni_argument_pack_plan("(Ljava/lang/Runnable;J)Z", reference_arguments=(spec, None)).mode == "mixed_word"


@pytest.mark.parametrize("descriptor,offsets", [
    ("(F)V", (0, 4)),
    ("(D)V", (0,)),
    ("(IIIJI)V", (0, 4, 8, 12, 16, 20, 24, 32, 36)),  # MediaCodec.queueInputBuffer
    ("(ZF)V", (0, 1, 2, 4, 8, 12)),
])
def test_typed_record_layout_is_exact_jvalue_slots(descriptor, offsets):
    plan = jni_argument_pack_plan(descriptor)
    assert plan.mode == "typed_record"
    assert plan.record_offsets == offsets
    assert plan.total_bytes == 8 * len(plan.parameter_descriptors)
    # Every 8-byte slot is fully covered: the value first, then zero padding.
    sizes = {F32.cid: 4, F64.cid: 8, **{bits_type(w).cid: w // 8 for w in (8, 16, 32, 64)}}
    covered = sum(sizes[field.cid] for field in plan.record_fields)
    assert covered == plan.total_bytes
    pack = jni_argument_pack_nodes(plan, tuple(ValueRef.parameter(0, i) for i in range(len(plan.parameter_descriptors))))
    stores = [node for node in pack.nodes if node.operation == Operation.STORE_BITS_LE]
    assert len(stores) == len(plan.record_fields)


def _stack_call_fixture(owner, name, descriptor, argument_types, *, references=()):
    """``(env, receiver, method_id, args..., clean, jni) -> (result?, maybe, jni)`` over a stack jvalue pack."""
    target = android_arm64_shared_general_target()
    env, jni_effect = jni_env_pointer_type(), jni_memory_effect_type()
    receiver = jni_reference_type(JniReferenceKind.BORROWED, owner.replace("/", ".").encode(), loader_domain=BOOT)
    method_id = jni_typed_method_id_type(owner, name, descriptor, loader_domain=BOOT)
    clean, maybe = jni_exception_state_type(JniExceptionState.CLEAN), jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    plan = jni_method_call_plan(owner, name, descriptor, loader_domain=BOOT)
    specs = tuple(references) or None
    pack_plan = jni_argument_pack_plan(descriptor, reference_arguments=specs)
    parameters = (env, receiver, method_id, *argument_types, clean, jni_effect)
    clean_index, jni_index = 3 + len(argument_types), 4 + len(argument_types)
    prefix = [
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, jni_index)),
        jni_native_function_load_node(target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), plan.function_name),
    ]
    values = tuple(ValueRef.parameter(0, 3 + index) for index in range(len(argument_types)))
    pack = jni_argument_pack_nodes(pack_plan, values, target=target, start_node_index=len(prefix))
    contract = jni_stack_method_call_contract(plan, pack_plan, track_exception_state=True)
    call_index = len(prefix) + len(pack.nodes)
    results = (*plan.result_types, maybe, stack_owner_type(), memory_effect_type(), jni_effect)
    call = Node(
        Operation.CALL_INDIRECT,
        (ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 2),
         pack.pointer, ValueRef.parameter(0, clean_index), pack.owner, pack.effect, ValueRef.node_result(0, 1, 1)),
        results,
        entity=contract,
    )
    r = len(plan.result_types)
    end = Node(Operation.STACK_END, (ValueRef.node_result(0, call_index, r + 1), ValueRef.node_result(0, call_index, r + 2)), ())
    returned = tuple(ValueRef.node_result(0, call_index, index) for index in (*range(r), r, r + 3))
    graph = graph_fragment([Block(parameters, (*prefix, *pack.nodes, call, end), Terminator.return_(returned))])
    fn = function(graph, parameters, (*plan.result_types, maybe, jni_effect))
    refs = [(JniReferenceKind.BORROWED, owner.replace("/", ".").encode(), BOOT)]
    refs += [(spec.kind, spec.descriptor[1:-1].replace("/", ".").encode(), spec.loader_domain) for spec in references if spec]
    objects = {obj.cid: obj for obj in jni_type_objects(tuple(refs), method_specs=((owner, name, descriptor, False, BOOT),))}
    for obj in (*pack.semantic_objects, contract, graph, *argument_types, *plan.result_types, clean, maybe, stack_owner_type(), memory_effect_type()):
        objects[obj.cid] = obj
    return _reader((fn,), tuple(objects.values()), target), target, fn


@pytest.mark.parametrize("owner,name,descriptor,arguments", [
    ("android/view/MotionEvent", "getX", "(I)F", (bits_type(32),)),
    ("android/view/View", "setAlpha", "(F)V", (F32,)),
    ("android/media/MediaCodec", "queueInputBuffer", "(IIIJI)V", (bits_type(32),) * 3 + (bits_type(64), bits_type(32))),
    ("android/view/MotionEvent", "getAxisValue", "(II)F", (bits_type(32), bits_type(32))),
])
def test_float_and_narrow_mixed_calls_verify_and_lower(owner, name, descriptor, arguments):
    reader, target, fn = _stack_call_fixture(owner, name, descriptor, arguments)
    verify_store(reader)
    first = compile_android_shared(reader, (AndroidExport(b"probe", fn.cid),), target_object=target)
    second = compile_android_shared(reader, (AndroidExport(b"probe", fn.cid),), target_object=target)
    assert first.data == second.data


def test_float_reference_mixed_pack_projects_reference_word():
    spec = JniReferenceArgumentSpec("Landroid/view/View;", loader_domain=BOOT)
    plan = jni_argument_pack_plan("(Landroid/view/View;F)V", reference_arguments=(spec, None))
    assert plan.mode == "typed_record" and plan.record_fields[0] == bits_type(64)
    with pytest.raises(ValueError, match="target ABI"):
        jni_argument_pack_nodes(plan, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)))


def test_float_value_in_integer_slot_is_rejected_by_the_verifier():
    # Passing a jint where the descriptor says jfloat is a type error, not a silent bit cast.
    reader, _target, _fn = _stack_call_fixture("android/view/View", "setAlpha", "(F)V", (bits_type(32),))
    with pytest.raises(XaxError):
        verify_store(reader)


def test_managed_float_callbacks_lower_and_check_exact_signatures():
    method = AndroidManagedMethod("onScale", "(FD)F")
    cls = AndroidManagedClass("Lxax/t/F;", "Ljava/lang/Object;", (), (method,))
    view = inspect_dex(emit_dex039_bridge(lower_android_managed_class(android_managed_class_semantics(cls))))
    assert "(FD)F" not in view.strings  # DEX stores shorty/proto, not the descriptor text
    assert "FFD" in view.strings  # shorty: float result, float and double arguments
    env = jni_env_pointer_type()
    this = jni_reference_type(JniReferenceKind.BORROWED, b"xax.t.F", loader_domain=b"app:xax.t")

    def export(parameters, results):
        graph = GraphBuilder()
        block = graph.block(*parameters)
        block.ret(*(block.params[3] for _ in results))
        fn = graph.function(parameters, results)
        objects = {**graph.objects, fn.cid: fn, **{item.cid: item for item in (*parameters, *results)}}
        for item in jni_type_objects(((JniReferenceKind.BORROWED, b"xax.t.F", b"app:xax.t"),)):
            objects[item.cid] = item
        return fn, objects.__getitem__

    assert check_export_signature(method, "Lxax/t/F;", *export((env, this, F32, F64), (F64,))) is not None  # float result expected
    good = GraphBuilder()
    block = good.block(env, this, F32, F64)
    block.ret(block.params[2])
    fn = good.function((env, this, F32, F64), (F32,))
    objects = {**good.objects, fn.cid: fn, **{item.cid: item for item in (env, this, F32, F64)}}
    for item in jni_type_objects(((JniReferenceKind.BORROWED, b"xax.t.F", b"app:xax.t"),)):
        objects[item.cid] = item
    assert check_export_signature(method, "Lxax/t/F;", fn, objects.__getitem__) is None
    assert check_export_signature(method, "Lxax/t/F;", *export((env, this, bits_type(32), F64), (F32,))) is not None
