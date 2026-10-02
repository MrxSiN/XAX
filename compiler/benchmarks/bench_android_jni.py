"""Deterministic JNI 1.6 platform-package/codegen evidence for Android arm64."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.bench_android_arm64 import _code_metrics, _function_code, _reader
from xax_android import AndroidExport, compile_android_shared, inspect_android_elf
from xax_compiler import (
    Block,
    Node,
    Operation,
    Terminator,
    ValueRef,
    android_arm64_shared_target,
    bits_type,
    memory_effect_type,
    stack_owner_type,
    decode_native_target,
    function,
    graph_fragment,
)
from xax_jni import (
    JNI_NATIVE_FUNCTION_NAMES,
    JNI_NATIVE_SLOT_BY_NAME,
    JniExceptionState,
    JniReferenceArgumentSpec,
    JniReferenceKind,
    jni_delete_global_ref_contract,
    jni_delete_global_class_cache_contract,
    jni_exception_clear_state_contract,
    jni_exception_state_type,
    jni_env_pointer_type,
    jni_env_table_load_node,
    jni_c_string_pointer_type,
    jni_class_cache_owner_type,
    jni_get_version_contract,
    jni_get_method_id_contract,
    jni_get_object_class_contract,
    jni_memory_effect_type,
    jni_method_call_plan,
    jni_field_access_plan,
    jni_argument_pack_plan,
    jni_argument_pack_nodes,
    jni_stack_method_call_contract,
    jni_typed_method_id_type,
    jni_native_function_load_node,
    jni_new_global_ref_contract,
    jni_new_object_zero_arg_contract,
    jni_new_global_class_cache_contract,
    jni_delete_local_ref_contract,
    jni_reference_owner_type,
    jni_reference_type,
    jni_type_objects,
)


def _objects_for(*extra, reference_specs=()):
    objects = {obj.cid: obj for obj in jni_type_objects(tuple(reference_specs))}
    for obj in extra:
        objects[obj.cid] = obj
    return tuple(objects[cid] for cid in sorted(objects))


def get_version_fixture():
    target = android_arm64_shared_target()
    env = jni_env_pointer_type()
    memory = jni_memory_effect_type()
    jint = bits_type(32)
    contract = jni_get_version_contract()
    nodes = (
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)),
        jni_native_function_load_node(target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), "GetVersion"),
        Node(
            Operation.CALL_INDIRECT,
            (ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 1, 1)),
            (jint, memory),
            entity=contract,
        ),
    )
    graph = graph_fragment([Block((env, memory), nodes, Terminator.return_((ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 1))))])
    fn = function(graph, (env, memory), (jint, memory))
    reader = _reader((fn,), _objects_for(contract, graph), target)
    return reader, target, fn, (AndroidExport(b"jni_get_version_probe", fn.cid),)


def global_ref_roundtrip_fixture():
    target = android_arm64_shared_target()
    env = jni_env_pointer_type()
    memory = jni_memory_effect_type()
    borrowed = jni_reference_type(JniReferenceKind.BORROWED, b"object")
    global_ref = jni_reference_type(JniReferenceKind.GLOBAL, b"object")
    global_owner = jni_reference_owner_type(JniReferenceKind.GLOBAL)
    new_contract = jni_new_global_ref_contract()
    delete_contract = jni_delete_global_ref_contract()
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
        jni_native_function_load_node(target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 2, 2), "DeleteGlobalRef"),
        Node(
            Operation.CALL_INDIRECT,
            (
                ValueRef.node_result(0, 3, 0),
                ValueRef.parameter(0, 0),
                ValueRef.node_result(0, 2, 0),
                ValueRef.node_result(0, 2, 1),
                ValueRef.node_result(0, 3, 1),
            ),
            (memory,),
            entity=delete_contract,
        ),
    )
    graph = graph_fragment([Block((env, borrowed, memory), nodes, Terminator.return_((ValueRef.node_result(0, 4, 0),)))])
    fn = function(graph, (env, borrowed, memory), (memory,))
    refs = ((JniReferenceKind.BORROWED, b"object"), (JniReferenceKind.GLOBAL, b"object"))
    reader = _reader((fn,), _objects_for(new_contract, delete_contract, graph, reference_specs=refs), target)
    return reader, target, fn, (AndroidExport(b"jni_global_ref_roundtrip", fn.cid),)


def cached_set_visibility_fixture():
    """Hot-path framework call with cached loader-qualified ID and explicit clear policy."""
    target = android_arm64_shared_target()
    loader_domain = b"android.boot"
    env = jni_env_pointer_type()
    receiver = jni_reference_type(
        JniReferenceKind.BORROWED, b"android.view.View", loader_domain=loader_domain
    )
    method_id = jni_typed_method_id_type(
        "android/view/View", "setVisibility", "(I)V", loader_domain=loader_domain
    )
    jint = bits_type(32)
    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    jni_effect = jni_memory_effect_type()
    plan = jni_method_call_plan(
        "android/view/View", "setVisibility", "(I)V", loader_domain=loader_domain
    )
    pack_plan = jni_argument_pack_plan("(I)V")

    prefix = [
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 5)),
        jni_native_function_load_node(target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), plan.function_name),
    ]
    pack = jni_argument_pack_nodes(pack_plan, (ValueRef.parameter(0, 3),), start_node_index=len(prefix))
    call_contract = jni_stack_method_call_contract(plan, pack_plan, track_exception_state=True)
    call_index = len(prefix) + len(pack.nodes)
    call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, 1, 0),
            ValueRef.parameter(0, 0),
            ValueRef.parameter(0, 1),
            ValueRef.parameter(0, 2),
            pack.pointer,
            ValueRef.parameter(0, 4),
            pack.owner,
            pack.effect,
            ValueRef.node_result(0, 1, 1),
        ),
        (maybe, stack_owner_type(), memory_effect_type(), jni_effect),
        entity=call_contract,
    )
    end_index = call_index + 1
    end = Node(
        Operation.STACK_END,
        (ValueRef.node_result(0, call_index, 1), ValueRef.node_result(0, call_index, 2)),
        (),
    )
    clear_load_index = end_index + 1
    clear_load = jni_native_function_load_node(
        target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, call_index, 3), "ExceptionClear"
    )
    clear_contract = jni_exception_clear_state_contract()
    clear_call_index = clear_load_index + 1
    clear_call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, clear_load_index, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, call_index, 0),
            ValueRef.node_result(0, clear_load_index, 1),
        ),
        (clean, jni_effect),
        entity=clear_contract,
    )
    graph = graph_fragment([Block(
        (env, receiver, method_id, jint, clean, jni_effect),
        tuple(prefix) + pack.nodes + (call, end, clear_load, clear_call),
        Terminator.return_((
            ValueRef.node_result(0, clear_call_index, 0),
            ValueRef.node_result(0, clear_call_index, 1),
        )),
    )])
    fn = function(graph, (env, receiver, method_id, jint, clean, jni_effect), (clean, jni_effect))
    refs = ((JniReferenceKind.BORROWED, b"android.view.View", loader_domain),)
    methods = (("android/view/View", "setVisibility", "(I)V", False, loader_domain),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs, method_specs=methods)}
    for obj in (*pack.semantic_objects, call_contract, clear_contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    return reader, target, fn, (AndroidExport(b"jni_set_visibility_cached", fn.cid),)


def cached_set_clickable_fixture():
    """Hot-path boolean framework call proving exact narrow jvalue slot stores."""
    target = android_arm64_shared_target()
    loader_domain = b"android.boot"
    env = jni_env_pointer_type()
    receiver = jni_reference_type(
        JniReferenceKind.BORROWED, b"android.view.View", loader_domain=loader_domain
    )
    method_id = jni_typed_method_id_type(
        "android/view/View", "setClickable", "(Z)V", loader_domain=loader_domain
    )
    jboolean = bits_type(8)
    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    jni_effect = jni_memory_effect_type()
    plan = jni_method_call_plan(
        "android/view/View", "setClickable", "(Z)V", loader_domain=loader_domain
    )
    pack_plan = jni_argument_pack_plan("(Z)V")

    prefix = [
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 5)),
        jni_native_function_load_node(target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), plan.function_name),
    ]
    pack = jni_argument_pack_nodes(pack_plan, (ValueRef.parameter(0, 3),), start_node_index=len(prefix))
    call_contract = jni_stack_method_call_contract(plan, pack_plan, track_exception_state=True)
    call_index = len(prefix) + len(pack.nodes)
    call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, 1, 0),
            ValueRef.parameter(0, 0),
            ValueRef.parameter(0, 1),
            ValueRef.parameter(0, 2),
            pack.pointer,
            ValueRef.parameter(0, 4),
            pack.owner,
            pack.effect,
            ValueRef.node_result(0, 1, 1),
        ),
        (maybe, stack_owner_type(), memory_effect_type(), jni_effect),
        entity=call_contract,
    )
    end_index = call_index + 1
    end = Node(
        Operation.STACK_END,
        (ValueRef.node_result(0, call_index, 1), ValueRef.node_result(0, call_index, 2)),
        (),
    )
    clear_load_index = end_index + 1
    clear_load = jni_native_function_load_node(
        target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, call_index, 3), "ExceptionClear"
    )
    clear_contract = jni_exception_clear_state_contract()
    clear_call_index = clear_load_index + 1
    clear_call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, clear_load_index, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, call_index, 0),
            ValueRef.node_result(0, clear_load_index, 1),
        ),
        (clean, jni_effect),
        entity=clear_contract,
    )
    graph = graph_fragment([Block(
        (env, receiver, method_id, jboolean, clean, jni_effect),
        tuple(prefix) + pack.nodes + (call, end, clear_load, clear_call),
        Terminator.return_((
            ValueRef.node_result(0, clear_call_index, 0),
            ValueRef.node_result(0, clear_call_index, 1),
        )),
    )])
    fn = function(graph, (env, receiver, method_id, jboolean, clean, jni_effect), (clean, jni_effect))
    refs = ((JniReferenceKind.BORROWED, b"android.view.View", loader_domain),)
    methods = (("android/view/View", "setClickable", "(Z)V", False, loader_domain),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs, method_specs=methods)}
    for obj in (*pack.semantic_objects, call_contract, clear_contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    return reader, target, fn, (AndroidExport(b"jni_set_clickable_cached", fn.cid),)


def cached_post_delayed_fixture():
    """Mixed reference+jlong framework call using explicit jvalue.l projection."""
    target = android_arm64_shared_target()
    loader_domain = b"android.boot"
    env = jni_env_pointer_type()
    receiver = jni_reference_type(
        JniReferenceKind.BORROWED, b"android.view.View", loader_domain=loader_domain
    )
    runnable = jni_reference_type(
        JniReferenceKind.BORROWED,
        b"java.lang.Runnable",
        loader_domain=loader_domain,
        nullable=True,
    )
    method_id = jni_typed_method_id_type(
        "android/view/View",
        "postDelayed",
        "(Ljava/lang/Runnable;J)Z",
        loader_domain=loader_domain,
    )
    jlong = bits_type(64)
    jboolean = bits_type(8)
    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    jni_effect = jni_memory_effect_type()
    plan = jni_method_call_plan(
        "android/view/View",
        "postDelayed",
        "(Ljava/lang/Runnable;J)Z",
        loader_domain=loader_domain,
    )
    runnable_spec = JniReferenceArgumentSpec(
        "Ljava/lang/Runnable;",
        JniReferenceKind.BORROWED,
        loader_domain,
    )
    pack_plan = jni_argument_pack_plan(
        "(Ljava/lang/Runnable;J)Z",
        reference_arguments=(runnable_spec, None),
        expected_reference_loader_domains=(loader_domain, None),
    )

    prefix = [
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 6)),
        jni_native_function_load_node(
            target,
            ValueRef.node_result(0, 0, 0),
            ValueRef.node_result(0, 0, 1),
            plan.function_name,
        ),
    ]
    pack = jni_argument_pack_nodes(
        pack_plan,
        (ValueRef.parameter(0, 3), ValueRef.parameter(0, 4)),
        target=target,
        start_node_index=len(prefix),
    )
    call_contract = jni_stack_method_call_contract(plan, pack_plan, track_exception_state=True)
    call_index = len(prefix) + len(pack.nodes)
    call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, 1, 0),
            ValueRef.parameter(0, 0),
            ValueRef.parameter(0, 1),
            ValueRef.parameter(0, 2),
            pack.pointer,
            ValueRef.parameter(0, 5),
            pack.owner,
            pack.effect,
            ValueRef.node_result(0, 1, 1),
        ),
        (jboolean, maybe, stack_owner_type(), memory_effect_type(), jni_effect),
        entity=call_contract,
    )
    end_index = call_index + 1
    end = Node(
        Operation.STACK_END,
        (ValueRef.node_result(0, call_index, 2), ValueRef.node_result(0, call_index, 3)),
        (),
    )
    clear_load_index = end_index + 1
    clear_load = jni_native_function_load_node(
        target,
        ValueRef.node_result(0, 0, 0),
        ValueRef.node_result(0, call_index, 4),
        "ExceptionClear",
    )
    clear_contract = jni_exception_clear_state_contract()
    clear_call_index = clear_load_index + 1
    clear_call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, clear_load_index, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, call_index, 1),
            ValueRef.node_result(0, clear_load_index, 1),
        ),
        (clean, jni_effect),
        entity=clear_contract,
    )
    graph = graph_fragment([Block(
        (env, receiver, method_id, runnable, jlong, clean, jni_effect),
        tuple(prefix) + pack.nodes + (call, end, clear_load, clear_call),
        Terminator.return_((
            ValueRef.node_result(0, call_index, 0),
            ValueRef.node_result(0, clear_call_index, 0),
            ValueRef.node_result(0, clear_call_index, 1),
        )),
    )])
    fn = function(
        graph,
        (env, receiver, method_id, runnable, jlong, clean, jni_effect),
        (jboolean, clean, jni_effect),
    )
    refs = (
        (JniReferenceKind.BORROWED, b"android.view.View", loader_domain),
        (JniReferenceKind.BORROWED, b"java.lang.Runnable", loader_domain, True),
    )
    methods = (("android/view/View", "postDelayed", "(Ljava/lang/Runnable;J)Z", False, loader_domain),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs, method_specs=methods)}
    for obj in (*pack.semantic_objects, call_contract, clear_contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    return reader, target, fn, (AndroidExport(b"jni_post_delayed_cached", fn.cid),)



def loader_relative_method_cache_fixture():
    """Resolve once from the target object's loader, call twice, then release the cache."""
    target = android_arm64_shared_target()
    loader_domain = b"app:fixture"
    owner = "fixture/Target"
    family = b"fixture.Target"
    method_name = "setValue"
    descriptor = "(J)V"
    env = jni_env_pointer_type()
    receiver = jni_reference_type(JniReferenceKind.BORROWED, family, loader_domain=loader_domain)
    name_ptr = jni_c_string_pointer_type()
    sig_ptr = jni_c_string_pointer_type()
    jlong = bits_type(64)
    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    jni_effect = jni_memory_effect_type()
    local_class = jni_reference_type(JniReferenceKind.LOCAL, family, loader_domain=loader_domain)
    global_class = jni_reference_type(JniReferenceKind.GLOBAL, family, loader_domain=loader_domain)
    local_owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    cache_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    method_id = jni_typed_method_id_type(owner, method_name, descriptor, loader_domain=loader_domain)

    object_class_contract = jni_get_object_class_contract(
        JniReferenceKind.BORROWED, family, owner=owner, loader_domain=loader_domain
    )
    promote_contract = jni_new_global_class_cache_contract(
        owner=owner, loader_domain=loader_domain, source_kind=JniReferenceKind.LOCAL
    )
    delete_local_contract = jni_delete_local_ref_contract(family, loader_domain=loader_domain)
    method_contract = jni_get_method_id_contract(
        JniReferenceKind.GLOBAL,
        owner=owner,
        name=method_name,
        descriptor=descriptor,
        loader_domain=loader_domain,
        class_cache_owner=True,
    )
    delete_cache_contract = jni_delete_global_class_cache_contract(
        owner=owner, loader_domain=loader_domain
    )
    plan = jni_method_call_plan(owner, method_name, descriptor, loader_domain=loader_domain)
    pack_plan = jni_argument_pack_plan(descriptor)
    hot_contract = jni_stack_method_call_contract(
        plan, pack_plan, track_exception_state=True, require_class_cache_owner=True
    )
    clear_contract = jni_exception_clear_state_contract()

    nodes: list[Node] = []
    def add(node: Node) -> int:
        index = len(nodes)
        nodes.append(node)
        return index

    table_i = add(jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 6)))
    object_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, table_i, 1), "GetObjectClass"
    ))
    object_call_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, object_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.parameter(0, 1),
            ValueRef.node_result(0, object_load_i, 1),
        ),
        (local_class, local_owner, jni_effect),
        entity=object_class_contract,
    ))
    promote_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, object_call_i, 2), "NewGlobalRef"
    ))
    promote_call_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, promote_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, object_call_i, 0),
            ValueRef.node_result(0, object_call_i, 1),
            ValueRef.node_result(0, promote_load_i, 1),
        ),
        (global_class, cache_owner, local_owner, jni_effect),
        entity=promote_contract,
    ))
    local_delete_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, promote_call_i, 3), "DeleteLocalRef"
    ))
    local_delete_call_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, local_delete_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, object_call_i, 0),
            ValueRef.node_result(0, promote_call_i, 2),
            ValueRef.node_result(0, local_delete_load_i, 1),
        ),
        (jni_effect,),
        entity=delete_local_contract,
    ))
    method_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, local_delete_call_i, 0), "GetMethodID"
    ))
    method_call_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, method_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, promote_call_i, 0),
            ValueRef.node_result(0, promote_call_i, 1),
            ValueRef.parameter(0, 2),
            ValueRef.parameter(0, 3),
            ValueRef.node_result(0, method_load_i, 1),
        ),
        (method_id, cache_owner, jni_effect),
        entity=method_contract,
    ))
    hot_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, method_call_i, 2), plan.function_name
    ))
    pack = jni_argument_pack_nodes(
        pack_plan, (ValueRef.parameter(0, 4),), start_node_index=len(nodes)
    )
    for node in pack.nodes:
        add(node)
    first_hot_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, hot_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.parameter(0, 1),
            ValueRef.node_result(0, method_call_i, 0),
            ValueRef.node_result(0, method_call_i, 1),
            pack.pointer,
            ValueRef.parameter(0, 5),
            pack.owner,
            pack.effect,
            ValueRef.node_result(0, hot_load_i, 1),
        ),
        (cache_owner, maybe, stack_owner_type(), memory_effect_type(), jni_effect),
        entity=hot_contract,
    ))
    clear1_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, first_hot_i, 4), "ExceptionClear"
    ))
    clear1_call_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, clear1_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, first_hot_i, 1),
            ValueRef.node_result(0, clear1_load_i, 1),
        ),
        (clean, jni_effect),
        entity=clear_contract,
    ))
    second_hot_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, hot_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.parameter(0, 1),
            ValueRef.node_result(0, method_call_i, 0),
            ValueRef.node_result(0, first_hot_i, 0),
            pack.pointer,
            ValueRef.node_result(0, clear1_call_i, 0),
            ValueRef.node_result(0, first_hot_i, 2),
            ValueRef.node_result(0, first_hot_i, 3),
            ValueRef.node_result(0, clear1_call_i, 1),
        ),
        (cache_owner, maybe, stack_owner_type(), memory_effect_type(), jni_effect),
        entity=hot_contract,
    ))
    clear2_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, second_hot_i, 4), "ExceptionClear"
    ))
    clear2_call_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, clear2_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, second_hot_i, 1),
            ValueRef.node_result(0, clear2_load_i, 1),
        ),
        (clean, jni_effect),
        entity=clear_contract,
    ))
    add(Node(
        Operation.STACK_END,
        (ValueRef.node_result(0, second_hot_i, 2), ValueRef.node_result(0, second_hot_i, 3)),
        (),
    ))
    delete_load_i = add(jni_native_function_load_node(
        target, ValueRef.node_result(0, table_i, 0), ValueRef.node_result(0, clear2_call_i, 1), "DeleteGlobalRef"
    ))
    delete_call_i = add(Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, delete_load_i, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, promote_call_i, 0),
            ValueRef.node_result(0, second_hot_i, 0),
            ValueRef.node_result(0, delete_load_i, 1),
        ),
        (jni_effect,),
        entity=delete_cache_contract,
    ))

    graph = graph_fragment([Block(
        (env, receiver, name_ptr, sig_ptr, jlong, clean, jni_effect),
        tuple(nodes),
        Terminator.return_((
            ValueRef.node_result(0, clear2_call_i, 0),
            ValueRef.node_result(0, delete_call_i, 0),
        )),
    )])
    fn = function(
        graph,
        (env, receiver, name_ptr, sig_ptr, jlong, clean, jni_effect),
        (clean, jni_effect),
    )
    refs = (
        (JniReferenceKind.BORROWED, family, loader_domain),
        (JniReferenceKind.LOCAL, family, loader_domain),
        (JniReferenceKind.GLOBAL, family, loader_domain),
    )
    methods = ((owner, method_name, descriptor, False, loader_domain),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs, method_specs=methods)}
    for obj in (
        cache_owner,
        object_class_contract,
        promote_contract,
        delete_local_contract,
        method_contract,
        delete_cache_contract,
        hot_contract,
        clear_contract,
        *pack.semantic_objects,
        graph,
    ):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    return reader, target, fn, (AndroidExport(b"jni_resolve_call_twice_release", fn.cid),)


def cached_app_set_value_fixture():
    """Hot cached target-app method call with an exact class/loader lifetime anchor."""
    target = android_arm64_shared_target()
    loader_domain = b"app:fixture"
    owner = "fixture/Target"
    family = b"fixture.Target"
    descriptor = "(J)V"
    env = jni_env_pointer_type()
    receiver = jni_reference_type(JniReferenceKind.BORROWED, family, loader_domain=loader_domain)
    method_id = jni_typed_method_id_type(owner, "setValue", descriptor, loader_domain=loader_domain)
    cache_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    jlong = bits_type(64)
    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    jni_effect = jni_memory_effect_type()
    plan = jni_method_call_plan(owner, "setValue", descriptor, loader_domain=loader_domain)
    pack_plan = jni_argument_pack_plan(descriptor)

    prefix = [
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 6)),
        jni_native_function_load_node(
            target,
            ValueRef.node_result(0, 0, 0),
            ValueRef.node_result(0, 0, 1),
            plan.function_name,
        ),
    ]
    pack = jni_argument_pack_nodes(
        pack_plan, (ValueRef.parameter(0, 4),), start_node_index=len(prefix)
    )
    call_contract = jni_stack_method_call_contract(
        plan,
        pack_plan,
        track_exception_state=True,
        require_class_cache_owner=True,
    )
    call_index = len(prefix) + len(pack.nodes)
    call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, 1, 0),
            ValueRef.parameter(0, 0),
            ValueRef.parameter(0, 1),
            ValueRef.parameter(0, 2),
            ValueRef.parameter(0, 3),
            pack.pointer,
            ValueRef.parameter(0, 5),
            pack.owner,
            pack.effect,
            ValueRef.node_result(0, 1, 1),
        ),
        (cache_owner, maybe, stack_owner_type(), memory_effect_type(), jni_effect),
        entity=call_contract,
    )
    end_index = call_index + 1
    end = Node(
        Operation.STACK_END,
        (ValueRef.node_result(0, call_index, 2), ValueRef.node_result(0, call_index, 3)),
        (),
    )
    clear_load_index = end_index + 1
    clear_load = jni_native_function_load_node(
        target,
        ValueRef.node_result(0, 0, 0),
        ValueRef.node_result(0, call_index, 4),
        "ExceptionClear",
    )
    clear_contract = jni_exception_clear_state_contract()
    clear_call_index = clear_load_index + 1
    clear_call = Node(
        Operation.CALL_INDIRECT,
        (
            ValueRef.node_result(0, clear_load_index, 0),
            ValueRef.parameter(0, 0),
            ValueRef.node_result(0, call_index, 1),
            ValueRef.node_result(0, clear_load_index, 1),
        ),
        (clean, jni_effect),
        entity=clear_contract,
    )
    graph = graph_fragment([Block(
        (env, receiver, method_id, cache_owner, jlong, clean, jni_effect),
        tuple(prefix) + pack.nodes + (call, end, clear_load, clear_call),
        Terminator.return_((
            ValueRef.node_result(0, call_index, 0),
            ValueRef.node_result(0, clear_call_index, 0),
            ValueRef.node_result(0, clear_call_index, 1),
        )),
    )])
    fn = function(
        graph,
        (env, receiver, method_id, cache_owner, jlong, clean, jni_effect),
        (cache_owner, clean, jni_effect),
    )
    refs = ((JniReferenceKind.BORROWED, family, loader_domain),)
    methods = ((owner, "setValue", descriptor, False, loader_domain),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs, method_specs=methods)}
    for obj in (cache_owner, *pack.semantic_objects, call_contract, clear_contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    return reader, target, fn, (AndroidExport(b"jni_set_value_cached", fn.cid),)


def release_method_cache_fixture():
    """Explicitly release the exact global class that anchors a resolved method cache."""
    target = android_arm64_shared_target()
    loader_domain = b"app:fixture"
    owner = "fixture/Target"
    family = b"fixture.Target"
    env = jni_env_pointer_type()
    global_class = jni_reference_type(JniReferenceKind.GLOBAL, family, loader_domain=loader_domain)
    cache_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    jni_effect = jni_memory_effect_type()
    delete_contract = jni_delete_global_class_cache_contract(owner=owner, loader_domain=loader_domain)
    nodes = (
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 3)),
        jni_native_function_load_node(
            target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), "DeleteGlobalRef"
        ),
        Node(
            Operation.CALL_INDIRECT,
            (
                ValueRef.node_result(0, 1, 0),
                ValueRef.parameter(0, 0),
                ValueRef.parameter(0, 1),
                ValueRef.parameter(0, 2),
                ValueRef.node_result(0, 1, 1),
            ),
            (jni_effect,),
            entity=delete_contract,
        ),
    )
    graph = graph_fragment([Block(
        (env, global_class, cache_owner, jni_effect),
        nodes,
        Terminator.return_((ValueRef.node_result(0, 2, 0),)),
    )])
    fn = function(graph, (env, global_class, cache_owner, jni_effect), (jni_effect,))
    refs = ((JniReferenceKind.GLOBAL, family, loader_domain),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs)}
    for obj in (cache_owner, delete_contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    return reader, target, fn, (AndroidExport(b"jni_release_target_method_cache", fn.cid),)



def generated_listener_construction_fixture():
    """Construct the generated click-listener class with explicit JNI allocation semantics."""
    target = android_arm64_shared_target()
    loader_domain = b"app:xax.generated"
    owner = "xax/generated/XaxOnClickListener"
    family = b"xax.generated.XaxOnClickListener"
    env = jni_env_pointer_type()
    clazz = jni_reference_type(JniReferenceKind.GLOBAL, family, loader_domain=loader_domain)
    cache_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    ctor = jni_typed_method_id_type(owner, "<init>", "()V", loader_domain=loader_domain)
    result = jni_reference_type(
        JniReferenceKind.LOCAL, family, loader_domain=loader_domain, nullable=True
    )
    result_owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    jni_effect = jni_memory_effect_type()
    contract = jni_new_object_zero_arg_contract(
        owner=owner,
        loader_domain=loader_domain,
        class_cache_owner=True,
        track_exception_state=True,
    )
    nodes = (
        jni_env_table_load_node(target, ValueRef.parameter(0, 0), ValueRef.parameter(0, 5)),
        jni_native_function_load_node(
            target, ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), "NewObject"
        ),
        Node(
            Operation.CALL_INDIRECT,
            (
                ValueRef.node_result(0, 1, 0),
                ValueRef.parameter(0, 0),
                ValueRef.parameter(0, 1),
                ValueRef.parameter(0, 2),
                ValueRef.parameter(0, 3),
                ValueRef.parameter(0, 4),
                ValueRef.node_result(0, 1, 1),
            ),
            (result, result_owner, cache_owner, maybe, jni_effect),
            entity=contract,
        ),
    )
    graph = graph_fragment([Block(
        (env, clazz, cache_owner, ctor, clean, jni_effect),
        nodes,
        Terminator.return_((
            ValueRef.node_result(0, 2, 0),
            ValueRef.node_result(0, 2, 1),
            ValueRef.node_result(0, 2, 2),
            ValueRef.node_result(0, 2, 3),
            ValueRef.node_result(0, 2, 4),
        )),
    )])
    fn = function(
        graph,
        (env, clazz, cache_owner, ctor, clean, jni_effect),
        (result, result_owner, cache_owner, maybe, jni_effect),
    )
    refs = (
        (JniReferenceKind.GLOBAL, family, loader_domain),
        (JniReferenceKind.LOCAL, family, loader_domain, True),
    )
    methods = ((owner, "<init>", "()V", False, loader_domain),)
    objects = {obj.cid: obj for obj in jni_type_objects(refs, method_specs=methods)}
    for obj in (cache_owner, contract, graph):
        objects[obj.cid] = obj
    reader = _reader((fn,), tuple(objects.values()), target)
    return reader, target, fn, (AndroidExport(b"jni_new_xax_click_listener", fn.cid),)


def _record(fixture):
    reader, target, fn, exports = fixture()
    shared = compile_android_shared(reader, exports, target_object=target)
    view = inspect_android_elf(shared.data)
    code = _function_code(shared, reader, target, (fn.cid,), fn.cid)
    return {
        "sha256": hashlib.sha256(shared.data).hexdigest(),
        "elf_bytes": shared.metrics.file_bytes,
        "text_bytes": shared.metrics.text_bytes,
        "imports": [item.decode() for item in view.imports],
        "needed": [item.decode() for item in view.needed],
        "relocations": view.relocation_count,
        "entry_code": _code_metrics(code),
    }



def _plan_record(plan):
    return {
        "owner": plan.owner,
        "name": plan.name,
        "descriptor": plan.descriptor,
        "dispatch": plan.dispatch,
        "jni_function": plan.function_name,
        "jni_slot": JNI_NATIVE_SLOT_BY_NAME[plan.function_name],
        "method_id_type_cid": plan.method_id_type.cid.hex(),
        "call_contract_cid": plan.call_contract.cid.hex(),
        "parameter_count": len(plan.parameter_types),
        "argument_pack_bytes": plan.argument_pack_bytes,
        "argument_pack_alignment": plan.argument_pack_alignment,
        "result_count": len(plan.result_types),
        "may_set_pending_exception": plan.may_set_pending_exception,
        "loader_domain": None if plan.loader_domain is None else plan.loader_domain.decode("utf-8"),
    }


def _field_plan_record(plan):
    return {
        "owner": plan.owner,
        "name": plan.name,
        "descriptor": plan.descriptor,
        "is_static": plan.is_static,
        "is_set": plan.is_set,
        "jni_function": plan.function_name,
        "jni_slot": JNI_NATIVE_SLOT_BY_NAME[plan.function_name],
        "field_id_type_cid": plan.field_id_type.cid.hex(),
        "call_contract_cid": plan.call_contract.cid.hex(),
        "may_set_pending_exception": plan.may_set_pending_exception,
        "loader_domain": None if plan.loader_domain is None else plan.loader_domain.decode("utf-8"),
    }

def collect_evidence():
    target = android_arm64_shared_target()
    description = decode_native_target(target)
    return {
        "schema": "xax-android-jni-platform-evidence-v1",
        "source_contract": "Android public JNI 1.6 JNINativeInterface/JNIInvokeInterface table layout",
        "source_reference": "AOSP platform/libnativehelper/include_jni/jni.h, public JNI 1.6 surface, verified 2026-10-01",
        "reference_lifetime_model": "borrowed carrier or owned local/global/weak-global carrier plus linear release proof",
        "pending_exception_model": "linear clean -> maybe_pending state; explicit ExceptionClear restores clean",
        "class_loader_model": "loader domain is part of reference/class/member-ID semantic identity; target-object GetObjectClass resolution can promote one exact loader-qualified jclass into a linear global cache anchor; cached method calls thread that proof and teardown consumes it; no runtime dispatch layer",
        "target_identity": description.identity.decode(),
        "target_operation_contracts": len(description.target_operations),
        "target_body_bytes": len(target.body),
        "jni_native_slot_first": 4,
        "jni_native_slot_last": 232,
        "jni_native_function_count": len(JNI_NATIVE_FUNCTION_NAMES),
        "jni_native_slot_samples": {
            name: JNI_NATIVE_SLOT_BY_NAME[name]
            for name in ("GetVersion", "FindClass", "NewGlobalRef", "GetMethodID", "GetStaticMethodID", "RegisterNatives", "GetJavaVM", "ExceptionCheck", "GetObjectRefType")
        },
        "runtime_dependencies_added": 0,
        "stack_jvalue_lowering": {
            "supported_bootstrap_shapes": [
                "homogeneous jboolean[]",
                "homogeneous jbyte[]",
                "homogeneous jchar[]",
                "homogeneous jshort[]",
                "homogeneous jint[]",
                "homogeneous jlong[]",
                "mixed jlong + strong JNI reference[] with explicit reference ABI projection",
            ],
            "slot_bytes": 8,
            "subword_high_padding": "explicit same-width zero stores",
            "reference_compatibility": "exact descriptor or imported superclass/interface proof plus optional exact defining-loader domain",
            "reference_abi_projection": "target-declared arm64 jobject handle -> 64-bit jvalue.l word; local/global owner tokens thread linearly; borrowed last-use projection emits zero instructions",
            "unsupported_mixed_shapes": "narrow mixed integers, weak-global references, float and double hard reject",
            "framework_probes": [
                "android.view.View.setVisibility(I)V",
                "android.view.View.setClickable(Z)V",
                "android.view.View.postDelayed(Ljava/lang/Runnable;J)Z",
            ],
            "framework_probe_exception_policy": "explicit ExceptionClear after maybe_pending",
        },
        "descriptor_driven_plans": {
            "virtual_method": _plan_record(jni_method_call_plan(
                "android/view/View", "setVisibility", "(I)V", dispatch="virtual"
            )),
            "static_method": _plan_record(jni_method_call_plan(
                "android/os/SystemClock", "uptimeMillis", "()J", dispatch="static"
            )),
            "object_field": _field_plan_record(jni_field_access_plan(
                "android/view/View", "mParent", "Landroid/view/ViewParent;"
            )),
        },
        "fixtures": {
            "get_version": _record(get_version_fixture),
            "global_ref_roundtrip": _record(global_ref_roundtrip_fixture),
            "cached_view_set_visibility": _record(cached_set_visibility_fixture),
            "cached_view_set_clickable": _record(cached_set_clickable_fixture),
            "cached_view_post_delayed": _record(cached_post_delayed_fixture),
            "loader_relative_method_cache": _record(loader_relative_method_cache_fixture),
            "cached_target_set_value": _record(cached_app_set_value_fixture),
            "release_target_method_cache": _record(release_method_cache_fixture),
            "generated_listener_zero_arg_construction": _record(generated_listener_construction_fixture),
        },
        "limitations": {
            "android_runtime_execution": "not run on this host",
            "jni_pending_exception_branch_refinement": "clean/maybe_pending is verifier-visible; conditional refinement to definitely-pending versus clean is not yet implemented",
            "nullable_reference_state": "mixed-pack input reference identities distinguish nullable/non-null; runtime null-check/refinement and explicit null construction are not yet implemented",
            "float_double_aapcs64": "not yet supported by the integer/pointer-only AArch64 bootstrap ABI lowerer",
            "thread_attachment_resource_state": "ABI table entries are exposed, but attach success/failure is not yet coupled to a verifier resource-state transition",
            "class_cache_runtime_validation": "loader-relative GetObjectClass/GetMethodID cache construction and global-ref teardown are compiler-verified but not executed on Android on this host",
            "listener_construction_success_refinement": "NewObject is explicit and verifier-visible, but nullable-result plus maybe-pending exception state cannot yet be refined to a proven successful construction branch",
        },
    }


def main():
    evidence = collect_evidence()
    path = Path(__file__).with_name("android_jni_platform_evidence.json")
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
