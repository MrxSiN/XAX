"""Android JNI 1.6 semantic platform helpers for XAX.

JNI remains platform-package data: this module constructs ordinary XAX types,
TARGET_OP table loads, and bounded CallContract objects.  It adds no JNI
operation to the XAX semantic kernel and emits no runtime wrapper.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType

from xax_compiler import (
    ANDROID_JNI_REFERENCE_RESOURCE_KIND,
    ANDROID_JNI_REFERENCE_WORD_BORROWED_OPERATION,
    ANDROID_JNI_REFERENCE_WORD_GLOBAL_OPERATION,
    ANDROID_JNI_REFERENCE_WORD_LOCAL_OPERATION,
    ANDROID_JNI_ENV_FUNCTIONS_OPERATION,
    AtomicScope,
    EffectDomain,
    Node,
    Operation,
    OpaqueKind,
    Permission,
    ResourceFlags,
    SemanticObject,
    ValueRef,
    android_jni_invoke_operation,
    android_jni_native_operation,
    bits_type,
    call_contract,
    constant,
    effect_type,
    memory_effect_type,
    function_pointer_type,
    opaque_type,
    opaque_identity_type,
    pointer_type,
    resource_type,
    stack_owner_type,
    uleb,
)

from xax_android_sdk import AndroidSdkImport, parse_jvm_field_descriptor, parse_jvm_method_descriptor

JNI_VERSION_1_1 = 0x00010001
JNI_VERSION_1_2 = 0x00010002
JNI_VERSION_1_4 = 0x00010004
JNI_VERSION_1_6 = 0x00010006
JNI_OK = 0
JNI_ERR = -1
JNI_EDETACHED = -2
JNI_EVERSION = -3
JNI_ENOMEM = -4
JNI_EEXIST = -5
JNI_EINVAL = -6
JNI_COMMIT = 1
JNI_ABORT = 2

JNI_INVOKE_SLOT_BY_NAME = MappingProxyType({
    "DestroyJavaVM": 3,
    "AttachCurrentThread": 4,
    "DetachCurrentThread": 5,
    "GetEnv": 6,
    "AttachCurrentThreadAsDaemon": 7,
})

# Exact Android public JNI 1.6 table order from JNINativeInterface.  Slots
# 0..3 are reserved; the callable surface is 4..232 inclusive.
JNI_NATIVE_FUNCTION_NAMES = (
    'GetVersion', 'DefineClass', 'FindClass', 'FromReflectedMethod', 'FromReflectedField', 'ToReflectedMethod',
    'GetSuperclass', 'IsAssignableFrom', 'ToReflectedField', 'Throw', 'ThrowNew', 'ExceptionOccurred',
    'ExceptionDescribe', 'ExceptionClear', 'FatalError', 'PushLocalFrame', 'PopLocalFrame', 'NewGlobalRef',
    'DeleteGlobalRef', 'DeleteLocalRef', 'IsSameObject', 'NewLocalRef', 'EnsureLocalCapacity', 'AllocObject',
    'NewObject', 'NewObjectV', 'NewObjectA', 'GetObjectClass', 'IsInstanceOf', 'GetMethodID',
    'CallObjectMethod', 'CallObjectMethodV', 'CallObjectMethodA', 'CallBooleanMethod', 'CallBooleanMethodV', 'CallBooleanMethodA',
    'CallByteMethod', 'CallByteMethodV', 'CallByteMethodA', 'CallCharMethod', 'CallCharMethodV', 'CallCharMethodA',
    'CallShortMethod', 'CallShortMethodV', 'CallShortMethodA', 'CallIntMethod', 'CallIntMethodV', 'CallIntMethodA',
    'CallLongMethod', 'CallLongMethodV', 'CallLongMethodA', 'CallFloatMethod', 'CallFloatMethodV', 'CallFloatMethodA',
    'CallDoubleMethod', 'CallDoubleMethodV', 'CallDoubleMethodA', 'CallVoidMethod', 'CallVoidMethodV', 'CallVoidMethodA',
    'CallNonvirtualObjectMethod', 'CallNonvirtualObjectMethodV', 'CallNonvirtualObjectMethodA', 'CallNonvirtualBooleanMethod', 'CallNonvirtualBooleanMethodV', 'CallNonvirtualBooleanMethodA',
    'CallNonvirtualByteMethod', 'CallNonvirtualByteMethodV', 'CallNonvirtualByteMethodA', 'CallNonvirtualCharMethod', 'CallNonvirtualCharMethodV', 'CallNonvirtualCharMethodA',
    'CallNonvirtualShortMethod', 'CallNonvirtualShortMethodV', 'CallNonvirtualShortMethodA', 'CallNonvirtualIntMethod', 'CallNonvirtualIntMethodV', 'CallNonvirtualIntMethodA',
    'CallNonvirtualLongMethod', 'CallNonvirtualLongMethodV', 'CallNonvirtualLongMethodA', 'CallNonvirtualFloatMethod', 'CallNonvirtualFloatMethodV', 'CallNonvirtualFloatMethodA',
    'CallNonvirtualDoubleMethod', 'CallNonvirtualDoubleMethodV', 'CallNonvirtualDoubleMethodA', 'CallNonvirtualVoidMethod', 'CallNonvirtualVoidMethodV', 'CallNonvirtualVoidMethodA',
    'GetFieldID', 'GetObjectField', 'GetBooleanField', 'GetByteField', 'GetCharField', 'GetShortField',
    'GetIntField', 'GetLongField', 'GetFloatField', 'GetDoubleField', 'SetObjectField', 'SetBooleanField',
    'SetByteField', 'SetCharField', 'SetShortField', 'SetIntField', 'SetLongField', 'SetFloatField',
    'SetDoubleField', 'GetStaticMethodID', 'CallStaticObjectMethod', 'CallStaticObjectMethodV', 'CallStaticObjectMethodA', 'CallStaticBooleanMethod',
    'CallStaticBooleanMethodV', 'CallStaticBooleanMethodA', 'CallStaticByteMethod', 'CallStaticByteMethodV', 'CallStaticByteMethodA', 'CallStaticCharMethod',
    'CallStaticCharMethodV', 'CallStaticCharMethodA', 'CallStaticShortMethod', 'CallStaticShortMethodV', 'CallStaticShortMethodA', 'CallStaticIntMethod',
    'CallStaticIntMethodV', 'CallStaticIntMethodA', 'CallStaticLongMethod', 'CallStaticLongMethodV', 'CallStaticLongMethodA', 'CallStaticFloatMethod',
    'CallStaticFloatMethodV', 'CallStaticFloatMethodA', 'CallStaticDoubleMethod', 'CallStaticDoubleMethodV', 'CallStaticDoubleMethodA', 'CallStaticVoidMethod',
    'CallStaticVoidMethodV', 'CallStaticVoidMethodA', 'GetStaticFieldID', 'GetStaticObjectField', 'GetStaticBooleanField', 'GetStaticByteField',
    'GetStaticCharField', 'GetStaticShortField', 'GetStaticIntField', 'GetStaticLongField', 'GetStaticFloatField', 'GetStaticDoubleField',
    'SetStaticObjectField', 'SetStaticBooleanField', 'SetStaticByteField', 'SetStaticCharField', 'SetStaticShortField', 'SetStaticIntField',
    'SetStaticLongField', 'SetStaticFloatField', 'SetStaticDoubleField', 'NewString', 'GetStringLength', 'GetStringChars',
    'ReleaseStringChars', 'NewStringUTF', 'GetStringUTFLength', 'GetStringUTFChars', 'ReleaseStringUTFChars', 'GetArrayLength',
    'NewObjectArray', 'GetObjectArrayElement', 'SetObjectArrayElement', 'NewBooleanArray', 'NewByteArray', 'NewCharArray',
    'NewShortArray', 'NewIntArray', 'NewLongArray', 'NewFloatArray', 'NewDoubleArray', 'GetBooleanArrayElements',
    'GetByteArrayElements', 'GetCharArrayElements', 'GetShortArrayElements', 'GetIntArrayElements', 'GetLongArrayElements', 'GetFloatArrayElements',
    'GetDoubleArrayElements', 'ReleaseBooleanArrayElements', 'ReleaseByteArrayElements', 'ReleaseCharArrayElements', 'ReleaseShortArrayElements', 'ReleaseIntArrayElements',
    'ReleaseLongArrayElements', 'ReleaseFloatArrayElements', 'ReleaseDoubleArrayElements', 'GetBooleanArrayRegion', 'GetByteArrayRegion', 'GetCharArrayRegion',
    'GetShortArrayRegion', 'GetIntArrayRegion', 'GetLongArrayRegion', 'GetFloatArrayRegion', 'GetDoubleArrayRegion', 'SetBooleanArrayRegion',
    'SetByteArrayRegion', 'SetCharArrayRegion', 'SetShortArrayRegion', 'SetIntArrayRegion', 'SetLongArrayRegion', 'SetFloatArrayRegion',
    'SetDoubleArrayRegion', 'RegisterNatives', 'UnregisterNatives', 'MonitorEnter', 'MonitorExit', 'GetJavaVM',
    'GetStringRegion', 'GetStringUTFRegion', 'GetPrimitiveArrayCritical', 'ReleasePrimitiveArrayCritical', 'GetStringCritical', 'ReleaseStringCritical',
    'NewWeakGlobalRef', 'DeleteWeakGlobalRef', 'ExceptionCheck', 'NewDirectByteBuffer', 'GetDirectBufferAddress', 'GetDirectBufferCapacity',
    'GetObjectRefType',
)
JNI_NATIVE_SLOT_BY_NAME = MappingProxyType({name: slot for slot, name in enumerate(JNI_NATIVE_FUNCTION_NAMES, 4)})


class JniExceptionState(IntEnum):
    CLEAN = 1
    MAYBE_PENDING = 2


class JniReferenceKind(IntEnum):
    BORROWED = 1
    LOCAL = 2
    GLOBAL = 3
    WEAK_GLOBAL = 4


JNI_REFERENCE_RESOURCE_KIND = ANDROID_JNI_REFERENCE_RESOURCE_KIND
JNI_EXCEPTION_RESOURCE_KIND = 2002


def _identity_pointer(identity: bytes, permission: Permission = Permission.READ) -> SemanticObject:
    return pointer_type(opaque_identity_type(identity), permission, 8)


def java_vm_pointer_type() -> SemanticObject:
    return _identity_pointer(b"android.jni.JavaVM", Permission.READ)


def jni_env_pointer_type() -> SemanticObject:
    return _identity_pointer(b"android.jni.JNIEnv", Permission.READ)


def jni_invoke_table_pointer_type() -> SemanticObject:
    return _identity_pointer(b"android.jni.JNIInvokeInterface", Permission.READ)


def jni_native_table_pointer_type() -> SemanticObject:
    return _identity_pointer(b"android.jni.JNINativeInterface", Permission.READ)


def jni_method_id_type() -> SemanticObject:
    return _identity_pointer(b"android.jni.jmethodID", Permission.READ)


def jni_field_id_type() -> SemanticObject:
    return _identity_pointer(b"android.jni.jfieldID", Permission.READ)


def _typed_member_identity(
    prefix: bytes,
    owner: str,
    name: str,
    descriptor: str,
    is_static: bool,
    loader_domain: bytes | None = None,
) -> bytes:
    if not owner or not name or "\x00" in owner or "\x00" in name:
        raise ValueError("typed JNI member identity requires nonempty owner/name")
    loader_domain = _loader_domain(loader_domain)
    body = bytearray(prefix if loader_domain is None else prefix.replace(b"/v1/", b"/v2/"))
    body.extend(bytes((1 if is_static else 0,)))
    for value in (owner, name, descriptor):
        raw = value.encode("utf-8")
        body.extend(uleb(len(raw)) + raw)
    if loader_domain is not None:
        body.extend(uleb(len(loader_domain)) + loader_domain)
    return bytes(body)


def jni_typed_method_id_type(
    owner: str,
    name: str,
    descriptor: str,
    *,
    is_static: bool = False,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    parse_jvm_method_descriptor(descriptor)
    return _identity_pointer(
        _typed_member_identity(
            b"android.jni.jmethodID/v1/", owner, name, descriptor, is_static, loader_domain
        ),
        Permission.READ,
    )


def jni_typed_field_id_type(
    owner: str,
    name: str,
    descriptor: str,
    *,
    is_static: bool = False,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    parse_jvm_field_descriptor(descriptor)
    return _identity_pointer(
        _typed_member_identity(
            b"android.jni.jfieldID/v1/", owner, name, descriptor, is_static, loader_domain
        ),
        Permission.READ,
    )


@dataclass(frozen=True)
class JniMethodCallPlan:
    owner: str
    name: str
    descriptor: str
    dispatch: str
    function_name: str
    method_id_type: SemanticObject
    parameter_types: tuple[SemanticObject, ...]
    result_types: tuple[SemanticObject, ...]
    call_contract: SemanticObject
    argument_pack_bytes: int
    argument_pack_alignment: int = 8
    may_set_pending_exception: bool = True
    loader_domain: bytes | None = None


@dataclass(frozen=True)
class JniFieldAccessPlan:
    owner: str
    name: str
    descriptor: str
    is_static: bool
    is_set: bool
    function_name: str
    field_id_type: SemanticObject
    value_type: SemanticObject
    call_contract: SemanticObject
    may_set_pending_exception: bool = True
    loader_domain: bytes | None = None


@dataclass(frozen=True)
class JniArgumentPackPlan:
    descriptor: str
    parameter_descriptors: tuple[str, ...]
    pointer_type: SemanticObject
    value_types: tuple[SemanticObject, ...]
    slot_bytes: int
    total_bytes: int
    store_bytes: int
    fully_initialized: bool = True
    mode: str = "homogeneous_integer"
    reference_arguments: tuple["JniReferenceArgumentSpec | None", ...] = ()


@dataclass(frozen=True)
class JniArgumentPackNodes:
    nodes: tuple[Node, ...]
    pointer: ValueRef
    owner: ValueRef
    effect: ValueRef
    semantic_objects: tuple[SemanticObject, ...]
    reference_owners: tuple[ValueRef | None, ...] = ()


@dataclass(frozen=True)
class JniReferenceArgumentSpec:
    """Exact semantic identity for one JNI reference argument.

    ``descriptor`` is the actual Java reference type represented by the SSA
    value. ``loader_domain`` identifies that type's defining loader.  Strong
    local/global references may carry a linear owner token; borrowed values do
    not. Weak globals are intentionally excluded from the bounded jvalue pack
    path because their liveness can change asynchronously.
    """

    descriptor: str
    kind: JniReferenceKind = JniReferenceKind.BORROWED
    loader_domain: bytes | None = None
    nullable: bool = True

    def __post_init__(self) -> None:
        parse_jvm_field_descriptor(self.descriptor)
        if not self.descriptor.startswith(("L", "[")):
            raise ValueError("JNI reference argument descriptor must be a JVM reference type")
        JniReferenceKind(self.kind)
        _loader_domain(self.loader_domain)
        if self.kind == JniReferenceKind.WEAK_GLOBAL:
            raise ValueError("weak-global JNI references require explicit liveness/null refinement before jvalue packing")


def jni_void_pointer_type(permission: Permission = Permission.READ_WRITE) -> SemanticObject:
    return _identity_pointer(b"android.jni.void", permission)


def jni_c_string_pointer_type(permission: Permission = Permission.READ) -> SemanticObject:
    return pointer_type(bits_type(8), permission, 1)


def jni_value_array_pointer_type(permission: Permission = Permission.READ) -> SemanticObject:
    return _identity_pointer(b"android.jni.jvalue[]", permission)


def jni_native_method_array_pointer_type(permission: Permission = Permission.READ) -> SemanticObject:
    return _identity_pointer(b"android.jni.JNINativeMethod[]", permission)


def _loader_domain(loader_domain: bytes | None) -> bytes | None:
    if loader_domain is None:
        return None
    loader_domain = bytes(loader_domain)
    if not loader_domain or b"\x00" in loader_domain:
        raise ValueError("JNI loader domain must be nonempty and NUL-free")
    return loader_domain


def _jni_reference_identity(
    kind: JniReferenceKind,
    family: bytes,
    loader_domain: bytes | None = None,
    nullable: bool | None = None,
) -> bytes:
    loader_domain = _loader_domain(loader_domain)
    if nullable is not None:
        body = bytearray(b"android.jni.ref/v3/")
        body.extend(bytes((int(kind), 1 if nullable else 0)))
        body.extend(uleb(len(family)) + family)
        encoded_loader = b"" if loader_domain is None else loader_domain
        body.extend(uleb(len(encoded_loader)) + encoded_loader)
        return bytes(body)
    if loader_domain is None:
        # Preserve the original v1 identity exactly for existing semantic graphs.
        return b"android.jni.ref/" + kind.name.lower().encode("ascii") + b"/" + family
    body = bytearray(b"android.jni.ref/v2/")
    body.extend(bytes((int(kind),)))
    for value in (family, loader_domain):
        body.extend(uleb(len(value)) + value)
    return bytes(body)


def jni_reference_type(
    kind: JniReferenceKind | int,
    family: bytes = b"object",
    *,
    loader_domain: bytes | None = None,
    nullable: bool | None = None,
) -> SemanticObject:
    try:
        kind = JniReferenceKind(kind)
    except ValueError as error:
        raise ValueError("invalid JNI reference kind") from error
    family = bytes(family)
    if not family or b"/" in family:
        raise ValueError("JNI reference family must be nonempty and slash-free")
    if nullable is not None and not isinstance(nullable, bool):
        raise ValueError("JNI reference nullability must be bool or unspecified")
    return _identity_pointer(_jni_reference_identity(kind, family, loader_domain, nullable), Permission.READ)


def jni_class_reference_type(
    kind: JniReferenceKind | int = JniReferenceKind.LOCAL,
    *,
    owner: str | None = None,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    """Return a class reference whose identity includes the defining loader when known."""
    family = b"class" if owner is None else owner.replace("/", ".").encode("utf-8")
    return jni_reference_type(kind, family, loader_domain=loader_domain)


def jni_reference_owner_type(kind: JniReferenceKind | int) -> SemanticObject:
    """Linear lifetime token for an owned JNI reference class.

    Borrowed references deliberately have no owner token: their lifetime is
    supplied by the enclosing callback/call contract.  Local/global/weak-global
    references acquired by JNI return an explicit linear proof value that must
    be consumed by the matching release path or returned to the caller.
    """
    try:
        kind = JniReferenceKind(kind)
    except ValueError as error:
        raise ValueError("invalid JNI reference kind") from error
    if kind == JniReferenceKind.BORROWED:
        raise ValueError("borrowed JNI references do not own a release token")
    return resource_type(
        JNI_REFERENCE_RESOURCE_KIND,
        int(kind),
        flags=ResourceFlags.RELEASABLE,
    )


def jni_class_cache_owner_type(owner: str, *, loader_domain: bytes | None) -> SemanticObject:
    """Linear lifetime proof for a cached loader-qualified ``jclass``.

    The resource instance is the full content identity of the corresponding
    global class-reference type.  This makes the proof specific to Java class
    identity plus defining loader while remaining a compile-time-only value in
    native code generation.
    """
    if not owner:
        raise ValueError("JNI cached class owner requires a nonempty class owner")
    loader_domain = _loader_domain(loader_domain)
    clazz = jni_class_reference_type(
        JniReferenceKind.GLOBAL, owner=owner, loader_domain=loader_domain
    )
    # Resource fields are canonical unsigned integers capped at 64 bits by the
    # core encoding.  Use three independent 63-bit chunks of the class CID so
    # cache capability types remain content-derived without truncating to one
    # weak local handle.  As with XAX content addressing itself, identity is
    # cryptographic; this retains 189 bits of collision resistance.
    chunks = [int.from_bytes(clazz.cid[index:index + 8], "little") & ((1 << 63) - 1) for index in (0, 8, 16)]
    chunks = [value or 1 for value in chunks]
    return resource_type(
        chunks[0],
        chunks[1],
        flags=ResourceFlags.RELEASABLE,
        instance=chunks[2],
    )


def _owned_reference_owner(kind: JniReferenceKind | int) -> SemanticObject | None:
    kind = JniReferenceKind(kind)
    return None if kind == JniReferenceKind.BORROWED else jni_reference_owner_type(kind)


def jni_exception_state_type(state: JniExceptionState | int) -> SemanticObject:
    """Linear verifier-visible JNI pending-exception state.

    ``MAYBE_PENDING`` deliberately means the call may or may not have created a
    Java exception.  It cannot be silently treated as ``CLEAN``; an explicit
    exception-policy operation must restore a clean state or the token must be
    propagated to the caller.
    """
    state = JniExceptionState(state)
    transitions = (
        (JniExceptionState.MAYBE_PENDING,)
        if state == JniExceptionState.CLEAN
        else (JniExceptionState.CLEAN,)
    )
    return resource_type(
        JNI_EXCEPTION_RESOURCE_KIND,
        int(state),
        flags=ResourceFlags.LINEAR,
        transitions=tuple(int(item) for item in transitions),
    )


def jni_memory_effect_type() -> SemanticObject:
    # Instance 1 is the Android external/platform-memory frontier declared by
    # android-arm64-v8a-shared-v3 target-operation contracts.
    return effect_type(EffectDomain.MEMORY, 1)


def jni_env_slot_pointer_type() -> SemanticObject:
    return pointer_type(jni_env_pointer_type(), Permission.READ_WRITE, 8)


def jni_type_objects(
    reference_specs: tuple[tuple[object, ...], ...] = (),
    method_specs: tuple[tuple[object, ...], ...] = (),
    field_specs: tuple[tuple[object, ...], ...] = (),
) -> tuple[SemanticObject, ...]:
    """Return the exact semantic type-object closure used by JNI helpers.

    Pointer types are content-addressed references to their element types, so a
    standalone store must include those element objects as well as the pointer
    carriers.  This function exposes that closure explicitly instead of hiding
    compiler-time dependencies behind a runtime/library abstraction.
    """

    identities = (
        b"android.jni.JavaVM",
        b"android.jni.JNIEnv",
        b"android.jni.JNIInvokeInterface",
        b"android.jni.JNINativeInterface",
        b"android.jni.jmethodID",
        b"android.jni.jfieldID",
        b"android.jni.void",
        b"android.jni.jvalue[]",
        b"android.jni.JNINativeMethod[]",
    )
    objects: dict[bytes, SemanticObject] = {}
    for identity in identities:
        element = opaque_identity_type(identity)
        objects[element.cid] = element
    for obj in (
        bits_type(8),
        bits_type(16),
        bits_type(32),
        bits_type(64),
        java_vm_pointer_type(),
        jni_env_pointer_type(),
        jni_invoke_table_pointer_type(),
        jni_native_table_pointer_type(),
        jni_method_id_type(),
        jni_field_id_type(),
        jni_void_pointer_type(),
        jni_c_string_pointer_type(),
        jni_value_array_pointer_type(),
        jni_native_method_array_pointer_type(),
        jni_memory_effect_type(),
        jni_env_slot_pointer_type(),
        opaque_type(OpaqueKind.FUNCTION),
        function_pointer_type(),
        jni_reference_owner_type(JniReferenceKind.LOCAL),
        jni_reference_owner_type(JniReferenceKind.GLOBAL),
        jni_reference_owner_type(JniReferenceKind.WEAK_GLOBAL),
        jni_exception_state_type(JniExceptionState.CLEAN),
        jni_exception_state_type(JniExceptionState.MAYBE_PENDING),
    ):
        objects[obj.cid] = obj
    for spec in reference_specs:
        if len(spec) not in {2, 3, 4}:
            raise ValueError("JNI reference type spec must be (kind, family[, loader_domain[, nullable]])")
        kind = JniReferenceKind(spec[0])
        family = bytes(spec[1])
        loader_domain = None if len(spec) == 2 else bytes(spec[2])
        nullable = None if len(spec) < 4 else bool(spec[3])
        identity = _jni_reference_identity(kind, family, loader_domain, nullable)
        element = opaque_identity_type(identity)
        pointer = jni_reference_type(kind, family, loader_domain=loader_domain, nullable=nullable)
        objects[element.cid] = element
        objects[pointer.cid] = pointer
    for spec in method_specs:
        if len(spec) not in {4, 5}:
            raise ValueError("JNI method type spec must be (owner, name, descriptor, is_static[, loader_domain])")
        owner, name, descriptor, is_static = spec[:4]
        loader_domain = None if len(spec) == 4 else bytes(spec[4])
        identity = _typed_member_identity(
            b"android.jni.jmethodID/v1/", str(owner), str(name), str(descriptor), bool(is_static), loader_domain
        )
        element = opaque_identity_type(identity)
        pointer = jni_typed_method_id_type(
            str(owner), str(name), str(descriptor), is_static=bool(is_static), loader_domain=loader_domain
        )
        objects[element.cid] = element
        objects[pointer.cid] = pointer
    for spec in field_specs:
        if len(spec) not in {4, 5}:
            raise ValueError("JNI field type spec must be (owner, name, descriptor, is_static[, loader_domain])")
        owner, name, descriptor, is_static = spec[:4]
        loader_domain = None if len(spec) == 4 else bytes(spec[4])
        identity = _typed_member_identity(
            b"android.jni.jfieldID/v1/", str(owner), str(name), str(descriptor), bool(is_static), loader_domain
        )
        element = opaque_identity_type(identity)
        pointer = jni_typed_field_id_type(
            str(owner), str(name), str(descriptor), is_static=bool(is_static), loader_domain=loader_domain
        )
        objects[element.cid] = element
        objects[pointer.cid] = pointer
    return tuple(objects[cid] for cid in sorted(objects))


def jni_invoke_slot(name: str) -> int:
    try:
        return JNI_INVOKE_SLOT_BY_NAME[name]
    except KeyError as error:
        raise ValueError(f"unknown JNI invocation function: {name}") from error


def jni_native_slot(name: str) -> int:
    try:
        return JNI_NATIVE_SLOT_BY_NAME[name]
    except KeyError as error:
        raise ValueError(f"unknown Android JNI 1.6 function: {name}") from error


def jni_invoke_operation(name: str) -> int:
    return android_jni_invoke_operation(jni_invoke_slot(name))


def jni_native_operation(name: str) -> int:
    return android_jni_native_operation(jni_native_slot(name))


def _table_load_node(
    target: SemanticObject,
    base: ValueRef,
    memory: ValueRef,
    result_type: SemanticObject,
    operation_id: int,
) -> Node:
    effect = jni_memory_effect_type()
    return Node(
        Operation.TARGET_OP,
        (base, memory),
        (result_type, effect),
        entity=target,
        attributes=(operation_id, AtomicScope.SYSTEM, 0, 0),
    )


def java_vm_table_load_node(target: SemanticObject, vm: ValueRef, memory: ValueRef) -> Node:
    return _table_load_node(target, vm, memory, jni_invoke_table_pointer_type(), 4)


def jni_invoke_function_load_node(target: SemanticObject, table: ValueRef, memory: ValueRef, name: str) -> Node:
    return _table_load_node(target, table, memory, function_pointer_type(), jni_invoke_operation(name))


def jni_env_table_load_node(target: SemanticObject, env: ValueRef, memory: ValueRef) -> Node:
    return _table_load_node(target, env, memory, jni_native_table_pointer_type(), ANDROID_JNI_ENV_FUNCTIONS_OPERATION)


def jni_native_function_load_node(target: SemanticObject, table: ValueRef, memory: ValueRef, name: str) -> Node:
    return _table_load_node(target, table, memory, function_pointer_type(), jni_native_operation(name))


def jni_get_version_contract() -> SemanticObject:
    env, jint, memory = jni_env_pointer_type(), bits_type(32), jni_memory_effect_type()
    return call_contract((env, memory), (jint, memory), may_return=True, may_trap=False)


def jni_find_class_contract() -> SemanticObject:
    env, name, memory = jni_env_pointer_type(), jni_c_string_pointer_type(), jni_memory_effect_type()
    clazz = jni_reference_type(JniReferenceKind.LOCAL, b"class")
    owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    return call_contract((env, name, memory), (clazz, owner, memory), may_return=True, may_trap=False)


def jni_get_object_class_contract(
    reference_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    family: bytes = b"object",
    *,
    owner: str | None = None,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    source = jni_reference_type(reference_kind, family, loader_domain=loader_domain)
    source_owner = _owned_reference_owner(reference_kind)
    clazz = jni_class_reference_type(JniReferenceKind.LOCAL, owner=owner, loader_domain=loader_domain)
    clazz_owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    inputs = (env, source, memory) if source_owner is None else (env, source, source_owner, memory)
    outputs = (clazz, clazz_owner, memory) if source_owner is None else (clazz, clazz_owner, source_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def _resolved_method_id_type(
    owner: str | None,
    name: str | None,
    descriptor: str | None,
    *,
    is_static: bool,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    supplied = (owner is not None, name is not None, descriptor is not None)
    if any(supplied) and not all(supplied):
        raise ValueError("typed JNI method resolution requires owner, name and descriptor together")
    if all(supplied):
        return jni_typed_method_id_type(
            owner or "", name or "", descriptor or "",
            is_static=is_static, loader_domain=loader_domain,
        )
    return jni_method_id_type()


def _resolved_field_id_type(
    owner: str | None,
    name: str | None,
    descriptor: str | None,
    *,
    is_static: bool,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    supplied = (owner is not None, name is not None, descriptor is not None)
    if any(supplied) and not all(supplied):
        raise ValueError("typed JNI field resolution requires owner, name and descriptor together")
    if all(supplied):
        return jni_typed_field_id_type(
            owner or "", name or "", descriptor or "",
            is_static=is_static, loader_domain=loader_domain,
        )
    return jni_field_id_type()


def jni_get_method_id_contract(
    class_kind: JniReferenceKind = JniReferenceKind.LOCAL,
    *,
    owner: str | None = None,
    name: str | None = None,
    descriptor: str | None = None,
    loader_domain: bytes | None = None,
    class_cache_owner: bool = False,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    loader_domain = _loader_domain(loader_domain)
    clazz = jni_class_reference_type(class_kind, owner=owner, loader_domain=loader_domain)
    if class_cache_owner:
        if class_kind != JniReferenceKind.GLOBAL or owner is None:
            raise ValueError("cached method resolution requires a typed global class")
        class_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    else:
        class_owner = _owned_reference_owner(class_kind)
    string = jni_c_string_pointer_type()
    method_id = _resolved_method_id_type(
        owner, name, descriptor, is_static=False, loader_domain=loader_domain
    )
    inputs = (env, clazz, string, string, memory) if class_owner is None else (env, clazz, class_owner, string, string, memory)
    outputs = (method_id, memory) if class_owner is None else (method_id, class_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_get_static_method_id_contract(
    class_kind: JniReferenceKind = JniReferenceKind.LOCAL,
    *,
    owner: str | None = None,
    name: str | None = None,
    descriptor: str | None = None,
    loader_domain: bytes | None = None,
    class_cache_owner: bool = False,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    loader_domain = _loader_domain(loader_domain)
    clazz = jni_class_reference_type(class_kind, owner=owner, loader_domain=loader_domain)
    if class_cache_owner:
        if class_kind != JniReferenceKind.GLOBAL or owner is None:
            raise ValueError("cached static method resolution requires a typed global class")
        class_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    else:
        class_owner = _owned_reference_owner(class_kind)
    string = jni_c_string_pointer_type()
    method_id = _resolved_method_id_type(
        owner, name, descriptor, is_static=True, loader_domain=loader_domain
    )
    inputs = (env, clazz, string, string, memory) if class_owner is None else (env, clazz, class_owner, string, string, memory)
    outputs = (method_id, memory) if class_owner is None else (method_id, class_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_get_field_id_contract(
    class_kind: JniReferenceKind = JniReferenceKind.LOCAL,
    *,
    owner: str | None = None,
    name: str | None = None,
    descriptor: str | None = None,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    loader_domain = _loader_domain(loader_domain)
    clazz = jni_class_reference_type(class_kind, owner=owner, loader_domain=loader_domain)
    class_owner = _owned_reference_owner(class_kind)
    string = jni_c_string_pointer_type()
    field_id = _resolved_field_id_type(
        owner, name, descriptor, is_static=False, loader_domain=loader_domain
    )
    inputs = (env, clazz, string, string, memory) if class_owner is None else (env, clazz, class_owner, string, string, memory)
    outputs = (field_id, memory) if class_owner is None else (field_id, class_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_get_static_field_id_contract(
    class_kind: JniReferenceKind = JniReferenceKind.LOCAL,
    *,
    owner: str | None = None,
    name: str | None = None,
    descriptor: str | None = None,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    loader_domain = _loader_domain(loader_domain)
    clazz = jni_class_reference_type(class_kind, owner=owner, loader_domain=loader_domain)
    class_owner = _owned_reference_owner(class_kind)
    string = jni_c_string_pointer_type()
    field_id = _resolved_field_id_type(
        owner, name, descriptor, is_static=True, loader_domain=loader_domain
    )
    inputs = (env, clazz, string, string, memory) if class_owner is None else (env, clazz, class_owner, string, string, memory)
    outputs = (field_id, memory) if class_owner is None else (field_id, class_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def _jni_reference_family(descriptor: str) -> bytes:
    if descriptor.startswith("L"):
        return descriptor[1:-1].replace("/", ".").encode("utf-8")
    if descriptor.startswith("["):
        return descriptor.replace("/", ".").encode("utf-8")
    raise ValueError("descriptor is not a JVM reference type")


def _descriptor_internal_name(descriptor: str) -> str | None:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1]
    return None


def jni_reference_descriptor_assignable(
    actual_descriptor: str,
    expected_descriptor: str,
    *,
    sdk: AndroidSdkImport | None = None,
) -> bool:
    """Return whether one non-null JVM reference can flow to another.

    The bounded proof deliberately accepts only cases that can be established
    from exact descriptors or imported class metadata.  Array covariance and
    primitive-array special cases are not guessed: arrays are exact-match only
    except for the universally valid ``java/lang/Object`` supertype.
    """
    parse_jvm_field_descriptor(actual_descriptor)
    parse_jvm_field_descriptor(expected_descriptor)
    if not actual_descriptor.startswith(("L", "[")) or not expected_descriptor.startswith(("L", "[")):
        raise ValueError("JNI reference assignability requires reference descriptors")
    if actual_descriptor == expected_descriptor:
        return True
    if expected_descriptor == "Ljava/lang/Object;":
        return True
    if actual_descriptor.startswith("[") or expected_descriptor.startswith("["):
        return False
    if sdk is None:
        return False
    actual_name = _descriptor_internal_name(actual_descriptor)
    expected_name = _descriptor_internal_name(expected_descriptor)
    if actual_name is None or expected_name is None:
        return False
    frontier = [actual_name]
    seen: set[str] = set()
    while frontier:
        name = frontier.pop()
        if name in seen:
            continue
        seen.add(name)
        if name == expected_name:
            return True
        imported = sdk.query_class(name)
        if imported is None:
            continue
        metadata = imported.metadata
        if metadata.superclass is not None:
            frontier.append(metadata.superclass)
        frontier.extend(metadata.interfaces)
    return False


def _reference_argument_type(spec: JniReferenceArgumentSpec) -> SemanticObject:
    return jni_reference_type(
        spec.kind,
        _jni_reference_family(spec.descriptor),
        loader_domain=spec.loader_domain,
        nullable=spec.nullable,
    )


def _reference_word_operation(kind: JniReferenceKind) -> int:
    if kind == JniReferenceKind.BORROWED:
        return ANDROID_JNI_REFERENCE_WORD_BORROWED_OPERATION
    if kind == JniReferenceKind.LOCAL:
        return ANDROID_JNI_REFERENCE_WORD_LOCAL_OPERATION
    if kind == JniReferenceKind.GLOBAL:
        return ANDROID_JNI_REFERENCE_WORD_GLOBAL_OPERATION
    raise ValueError("weak-global JNI references require explicit liveness/null refinement before jvalue packing")


def jni_reference_word_node(
    target: SemanticObject,
    reference: ValueRef,
    spec: JniReferenceArgumentSpec,
    *,
    owner: ValueRef | None = None,
) -> Node:
    """Project a strong JNI reference into its arm64 ``jvalue.l`` ABI word.

    The operation is target-declared and proof-visible. Borrowed references
    need no owner token. Local/global references must thread their linear owner
    through the projection unchanged, preventing the ABI word from being
    synthesized after the owned reference lifetime has ended.
    """
    reference_type = _reference_argument_type(spec)
    bits64 = bits_type(64)
    operation_id = _reference_word_operation(spec.kind)
    if spec.kind == JniReferenceKind.BORROWED:
        if owner is not None:
            raise ValueError("borrowed JNI reference ABI projection must not receive an owner token")
        operands = (reference,)
        results = (bits64,)
    else:
        if owner is None:
            raise ValueError("owned JNI reference ABI projection requires its linear owner token")
        owner_type = jni_reference_owner_type(spec.kind)
        operands = (reference, owner)
        results = (bits64, owner_type)
    return Node(
        Operation.TARGET_OP,
        operands,
        results,
        entity=target,
        attributes=(operation_id, AtomicScope.SYSTEM, 0, 0),
    )


def _jni_value_type(descriptor: str, *, reference_kind: JniReferenceKind = JniReferenceKind.BORROWED) -> SemanticObject:
    if descriptor == "Z" or descriptor == "B":
        return bits_type(8)
    if descriptor == "C" or descriptor == "S":
        return bits_type(16)
    if descriptor == "I":
        return bits_type(32)
    if descriptor == "J":
        return bits_type(64)
    if descriptor in {"F", "D"}:
        raise ValueError("prototype XAX type system has no implemented float carrier for exact JNI F/D semantics")
    if descriptor.startswith(("L", "[")):
        return jni_reference_type(reference_kind, _jni_reference_family(descriptor))
    raise ValueError(f"unsupported JNI JVM descriptor: {descriptor!r}")


def _jni_call_suffix(descriptor: str) -> str:
    return {
        "V": "Void",
        "Z": "Boolean",
        "B": "Byte",
        "C": "Char",
        "S": "Short",
        "I": "Int",
        "J": "Long",
        "F": "Float",
        "D": "Double",
    }.get(descriptor, "Object" if descriptor.startswith(("L", "[")) else "")


def _owned_use(
    kind: JniReferenceKind,
    family: bytes,
    loader_domain: bytes | None = None,
) -> tuple[SemanticObject, SemanticObject | None]:
    return jni_reference_type(kind, family, loader_domain=loader_domain), _owned_reference_owner(kind)


def jni_argument_pack_plan(
    descriptor: str,
    *,
    reference_arguments: tuple[JniReferenceArgumentSpec | None, ...] | None = None,
    expected_reference_loader_domains: tuple[bytes | None, ...] | None = None,
    sdk: AndroidSdkImport | None = None,
) -> JniArgumentPackPlan:
    """Plan a verifier-visible stack ``jvalue[]`` pack for the bounded bootstrap subset.

    The legacy bounded path supports nonempty homogeneous integer JNI argument
    lists (Z/B/C/S/I/J) using exact-width stores and deterministic zero padding.

    A second bounded path supports mixed ``jlong``/strong-reference argument
    lists. Every slot is represented as one 64-bit word. Reference words are
    produced only by the explicit Android target ABI projection above; actual
    Java reference descriptors are checked against the expected method
    descriptor, optional imported SDK hierarchy, and optional defining-loader
    identity. Narrow mixed integers and F/D remain hard rejection.
    """
    parameters, _result = parse_jvm_method_descriptor(descriptor)
    if not parameters:
        raise ValueError("zero-argument JNI A calls do not require a stack jvalue pack")
    integer_widths = {"Z": 8, "B": 8, "C": 16, "S": 16, "I": 32, "J": 64}
    if reference_arguments is None and len(set(parameters)) == 1 and parameters[0] in integer_widths:
        width = integer_widths[parameters[0]]
        value = bits_type(width)
        pointer = pointer_type(value, Permission.READ_WRITE, 8)
        return JniArgumentPackPlan(
            descriptor,
            parameters,
            pointer,
            tuple(value for _ in parameters),
            8,
            8 * len(parameters),
            width // 8,
        )

    refs = tuple(reference_arguments or (None for _ in parameters))
    if len(refs) != len(parameters):
        raise ValueError("JNI reference-argument specification count must match method parameters")
    expected_loaders = tuple(expected_reference_loader_domains or (None for _ in parameters))
    if len(expected_loaders) != len(parameters):
        raise ValueError("JNI expected loader-domain count must match method parameters")
    value_types: list[SemanticObject] = []
    normalized_refs: list[JniReferenceArgumentSpec | None] = []
    for index, (expected, spec, expected_loader) in enumerate(zip(parameters, refs, expected_loaders)):
        if expected.startswith(("L", "[")):
            if spec is None:
                raise ValueError(f"JNI reference parameter {index} requires an explicit reference argument specification")
            if not jni_reference_descriptor_assignable(spec.descriptor, expected, sdk=sdk):
                raise ValueError(
                    f"JNI reference argument {index} type {spec.descriptor} is not provably assignable to {expected}"
                )
            expected_loader = _loader_domain(expected_loader)
            if expected_loader is not None and spec.loader_domain != expected_loader:
                raise ValueError(f"JNI reference argument {index} loader domain does not match the expected defining loader")
            value_types.append(_reference_argument_type(spec))
            normalized_refs.append(spec)
        else:
            if spec is not None:
                raise ValueError(f"JNI primitive parameter {index} cannot carry a reference argument specification")
            if expected != "J":
                raise ValueError(
                    "current JNI stack jvalue pack supports homogeneous integer Z/B/C/S/I/J "
                    "or mixed jlong plus strong references only"
                )
            value_types.append(bits_type(64))
            normalized_refs.append(None)
    word = bits_type(64)
    return JniArgumentPackPlan(
        descriptor,
        parameters,
        pointer_type(word, Permission.READ_WRITE, 8),
        tuple(value_types),
        8,
        8 * len(parameters),
        8,
        mode="mixed_word",
        reference_arguments=tuple(normalized_refs),
    )


def jni_argument_pack_nodes(
    plan: JniArgumentPackPlan,
    values: tuple[ValueRef, ...],
    *,
    target: SemanticObject | None = None,
    reference_owners: tuple[ValueRef | None, ...] | None = None,
    block_index: int = 0,
    start_node_index: int = 0,
) -> JniArgumentPackNodes:
    """Construct exact stack-memory nodes for a bounded ``jvalue[]`` pack.

    Each JNI union slot is fully initialized. The low element-width bytes hold
    the argument and all remaining bytes are explicitly zeroed using stores of
    the same semantic element type. This avoids hidden casts and never exposes
    uninitialized union padding to the opaque JNI implementation.
    """
    if len(values) != len(plan.value_types):
        raise ValueError("JNI jvalue pack value count does not match descriptor")
    owner_inputs = tuple(reference_owners or (None for _ in values))
    if len(owner_inputs) != len(values):
        raise ValueError("JNI jvalue reference-owner count does not match descriptor")
    if plan.mode == "mixed_word" and target is None:
        raise ValueError("mixed/reference JNI jvalue packing requires the explicit target ABI package")
    nodes: list[Node] = []
    semantic_objects: dict[bytes, SemanticObject] = {}
    pointer = plan.pointer_type
    store_element_type = bits_type(64) if plan.mode == "mixed_word" else plan.value_types[0]
    owner_type = stack_owner_type()
    effect_type_obj = memory_effect_type()
    for obj in (pointer, *plan.value_types, owner_type, effect_type_obj, bits_type(64)):
        semantic_objects[obj.cid] = obj
    alloc_index = start_node_index
    nodes.append(Node(Operation.STACK_ALLOC, (), (pointer, owner_type, effect_type_obj), attributes=(plan.total_bytes, 8)))
    base = ValueRef.node_result(block_index, alloc_index, 0)
    owner = ValueRef.node_result(block_index, alloc_index, 1)
    effect = ValueRef.node_result(block_index, alloc_index, 2)
    next_index = alloc_index + 1
    zero_ref = None
    if plan.mode == "homogeneous_integer" and plan.store_bytes < 8:
        zero_type = store_element_type
        zero = constant(zero_type, 0)
        semantic_objects[zero.cid] = zero
        nodes.append(Node(Operation.CONSTANT, (), (zero_type,), entity=zero))
        zero_ref = ValueRef.node_result(block_index, next_index, 0)
        next_index += 1

    def at_offset(offset: int, alignment: int = 8) -> ValueRef:
        nonlocal next_index
        if offset == 0 and alignment == 8:
            return base
        derived = pointer if alignment == 8 else pointer_type(store_element_type, Permission.READ_WRITE, alignment)
        semantic_objects[derived.cid] = derived
        nodes.append(Node(Operation.ADDRESS_OFFSET, (base,), (derived,), attributes=(offset,)))
        result = ValueRef.node_result(block_index, next_index, 0)
        next_index += 1
        return result

    continued_reference_owners: list[ValueRef | None] = []
    for slot, value in enumerate(values):
        low = at_offset(slot * 8)
        store_value = value
        spec = plan.reference_arguments[slot] if plan.reference_arguments else None
        if spec is not None:
            assert target is not None
            identity = opaque_identity_type(
                _jni_reference_identity(
                    spec.kind,
                    _jni_reference_family(spec.descriptor),
                    spec.loader_domain,
                    spec.nullable,
                )
            )
            semantic_objects[identity.cid] = identity
            projection = jni_reference_word_node(target, value, spec, owner=owner_inputs[slot])
            nodes.append(projection)
            store_value = ValueRef.node_result(block_index, next_index, 0)
            if spec.kind == JniReferenceKind.BORROWED:
                continued_reference_owners.append(None)
            else:
                continued_reference_owners.append(ValueRef.node_result(block_index, next_index, 1))
                semantic_objects[jni_reference_owner_type(spec.kind).cid] = jni_reference_owner_type(spec.kind)
            next_index += 1
        else:
            if owner_inputs[slot] is not None:
                raise ValueError("JNI primitive jvalue slot must not receive a reference owner token")
            continued_reference_owners.append(None)
        nodes.append(Node(Operation.STORE_BITS_LE, (low, store_value, effect), (effect_type_obj,), attributes=(plan.store_bytes, plan.store_bytes)))
        effect = ValueRef.node_result(block_index, next_index, 0)
        next_index += 1
        if plan.mode == "homogeneous_integer" and plan.store_bytes < 8:
            assert zero_ref is not None
            for padding_offset in range(plan.store_bytes, 8, plan.store_bytes):
                high = at_offset(slot * 8 + padding_offset, plan.store_bytes)
                nodes.append(Node(
                    Operation.STORE_BITS_LE,
                    (high, zero_ref, effect),
                    (effect_type_obj,),
                    attributes=(plan.store_bytes, plan.store_bytes),
                ))
                effect = ValueRef.node_result(block_index, next_index, 0)
                next_index += 1
    return JniArgumentPackNodes(
        tuple(nodes),
        base,
        owner,
        effect,
        tuple(semantic_objects[cid] for cid in sorted(semantic_objects)),
        tuple(continued_reference_owners),
    )


def jni_stack_method_call_contract(
    plan: JniMethodCallPlan,
    pack: JniArgumentPackPlan,
    *,
    receiver_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    class_kind: JniReferenceKind = JniReferenceKind.LOCAL,
    track_exception_state: bool = False,
    require_class_cache_owner: bool = False,
) -> SemanticObject:
    """Return the exact indirect-call contract for a stack-backed ``jvalue[]``.

    Local pack ownership/effect and the external JNI memory frontier are both
    explicit proof operands/results.  Machine lowering erases only those proof
    values; the runtime ABI still receives exactly env/receiver-or-class/member
    ID/argument-pointer.
    """
    if plan.descriptor != pack.descriptor:
        raise ValueError("JNI method plan and stack argument pack disagree")
    if pack.mode == "homogeneous_integer" and tuple(plan.parameter_types) != tuple(pack.value_types):
        raise ValueError("JNI method plan and stack argument pack disagree")
    if pack.mode == "mixed_word" and len(plan.parameter_types) != len(pack.value_types):
        raise ValueError("JNI method plan and stack argument pack disagree")
    env = jni_env_pointer_type()
    threaded: list[SemanticObject] = []
    if plan.dispatch == "virtual":
        receiver, receiver_owner = _owned_use(
            receiver_kind, plan.owner.replace("/", ".").encode("utf-8"), plan.loader_domain
        )
        inputs = [env, receiver]
        if receiver_owner is not None:
            inputs.append(receiver_owner); threaded.append(receiver_owner)
    elif plan.dispatch == "static":
        class_family = plan.owner.replace("/", ".").encode("utf-8") if plan.loader_domain is not None else b"class"
        clazz, clazz_owner = _owned_use(class_kind, class_family, plan.loader_domain)
        inputs = [env, clazz]
        if clazz_owner is not None:
            inputs.append(clazz_owner); threaded.append(clazz_owner)
    elif plan.dispatch == "nonvirtual":
        receiver, receiver_owner = _owned_use(
            receiver_kind, plan.owner.replace("/", ".").encode("utf-8"), plan.loader_domain
        )
        class_family = plan.owner.replace("/", ".").encode("utf-8") if plan.loader_domain is not None else b"class"
        clazz, clazz_owner = _owned_use(class_kind, class_family, plan.loader_domain)
        inputs = [env, receiver]
        if receiver_owner is not None:
            inputs.append(receiver_owner); threaded.append(receiver_owner)
        inputs.append(clazz)
        if clazz_owner is not None:
            inputs.append(clazz_owner); threaded.append(clazz_owner)
    else:
        raise ValueError("JNI method dispatch must be virtual, static or nonvirtual")
    stack_owner = stack_owner_type()
    stack_effect = memory_effect_type()
    jni_effect = jni_memory_effect_type()
    inputs.append(plan.method_id_type)
    if require_class_cache_owner:
        cache_owner = jni_class_cache_owner_type(plan.owner, loader_domain=plan.loader_domain)
        inputs.append(cache_owner)
        threaded.append(cache_owner)
    inputs.append(pack.pointer_type)
    for spec in pack.reference_arguments:
        if spec is not None and spec.kind != JniReferenceKind.BORROWED:
            ref_owner = jni_reference_owner_type(spec.kind)
            inputs.append(ref_owner)
            threaded.append(ref_owner)
    outputs = [*plan.result_types, *threaded]
    if track_exception_state:
        inputs.append(jni_exception_state_type(JniExceptionState.CLEAN))
        outputs.append(jni_exception_state_type(JniExceptionState.MAYBE_PENDING))
    inputs.extend((stack_owner, stack_effect, jni_effect))
    outputs.extend((stack_owner, stack_effect, jni_effect))
    return call_contract(tuple(inputs), tuple(outputs), may_return=True, may_trap=False)


def jni_method_call_plan(
    owner: str,
    name: str,
    descriptor: str,
    *,
    dispatch: str = "virtual",
    receiver_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    class_kind: JniReferenceKind = JniReferenceKind.LOCAL,
    loader_domain: bytes | None = None,
) -> JniMethodCallPlan:
    """Build a typed JNI ``Call*MethodA`` plan from one exact JVM descriptor.

    The ``A`` family is selected deliberately: arguments are represented by an
    explicit fixed-size ``jvalue[]`` pack, avoiding hidden C varargs behavior.
    The plan records the source parameter types and exact pack size; allocation
    of that pack remains explicit in the caller.
    """
    parameters, result = parse_jvm_method_descriptor(descriptor)
    suffix = _jni_call_suffix(result)
    if not suffix:
        raise ValueError("unsupported JNI result descriptor")
    # F/D are named by JNI but exact XAX float carriers are not implemented yet.
    parameter_types = tuple(_jni_value_type(item) for item in parameters)
    if result in {"F", "D"}:
        _jni_value_type(result)  # raises exact unsupported diagnostic

    loader_domain = _loader_domain(loader_domain)
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    method_id = jni_typed_method_id_type(
        owner, name, descriptor, is_static=(dispatch == "static"), loader_domain=loader_domain
    )
    args_pointer = jni_value_array_pointer_type()
    threaded: list[SemanticObject] = []

    if dispatch == "virtual":
        receiver, receiver_owner = _owned_use(
            receiver_kind, owner.replace("/", ".").encode("utf-8"), loader_domain
        )
        inputs = [env, receiver]
        if receiver_owner is not None:
            inputs.append(receiver_owner); threaded.append(receiver_owner)
        inputs.extend((method_id, args_pointer, memory))
        function_name = f"Call{suffix}MethodA"
    elif dispatch == "static":
        class_family = owner.replace("/", ".").encode("utf-8") if loader_domain is not None else b"class"
        clazz, clazz_owner = _owned_use(class_kind, class_family, loader_domain)
        inputs = [env, clazz]
        if clazz_owner is not None:
            inputs.append(clazz_owner); threaded.append(clazz_owner)
        inputs.extend((method_id, args_pointer, memory))
        function_name = f"CallStatic{suffix}MethodA"
    elif dispatch == "nonvirtual":
        receiver, receiver_owner = _owned_use(
            receiver_kind, owner.replace("/", ".").encode("utf-8"), loader_domain
        )
        class_family = owner.replace("/", ".").encode("utf-8") if loader_domain is not None else b"class"
        clazz, clazz_owner = _owned_use(class_kind, class_family, loader_domain)
        inputs = [env, receiver]
        if receiver_owner is not None:
            inputs.append(receiver_owner); threaded.append(receiver_owner)
        inputs.append(clazz)
        if clazz_owner is not None:
            inputs.append(clazz_owner); threaded.append(clazz_owner)
        inputs.extend((method_id, args_pointer, memory))
        function_name = f"CallNonvirtual{suffix}MethodA"
    else:
        raise ValueError("JNI method dispatch must be virtual, static or nonvirtual")

    outputs: list[SemanticObject] = []
    result_types: tuple[SemanticObject, ...]
    if result == "V":
        result_types = ()
    elif result.startswith(("L", "[")):
        value = _jni_value_type(result, reference_kind=JniReferenceKind.LOCAL)
        owner_token = jni_reference_owner_type(JniReferenceKind.LOCAL)
        result_types = (value, owner_token)
        outputs.extend(result_types)
    else:
        value = _jni_value_type(result)
        result_types = (value,)
        outputs.append(value)
    outputs.extend(threaded)
    outputs.append(memory)
    contract = call_contract(tuple(inputs), tuple(outputs), may_return=True, may_trap=False)
    return JniMethodCallPlan(
        owner,
        name,
        descriptor,
        dispatch,
        function_name,
        method_id,
        parameter_types,
        result_types,
        contract,
        8 * len(parameters),
        loader_domain=loader_domain,
    )


def jni_field_access_plan(
    owner: str,
    name: str,
    descriptor: str,
    *,
    is_static: bool = False,
    is_set: bool = False,
    receiver_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    class_kind: JniReferenceKind = JniReferenceKind.LOCAL,
    loader_domain: bytes | None = None,
) -> JniFieldAccessPlan:
    """Build an exact typed JNI field get/set plan."""
    descriptor = parse_jvm_field_descriptor(descriptor)
    suffix = _jni_call_suffix(descriptor)
    if not suffix or suffix == "Void":
        raise ValueError("unsupported JNI field descriptor")
    value_type = _jni_value_type(descriptor)
    loader_domain = _loader_domain(loader_domain)
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    field_id = jni_typed_field_id_type(
        owner, name, descriptor, is_static=is_static, loader_domain=loader_domain
    )
    threaded: list[SemanticObject] = []
    if is_static:
        class_family = owner.replace("/", ".").encode("utf-8") if loader_domain is not None else b"class"
        receiver, receiver_owner = _owned_use(class_kind, class_family, loader_domain)
        stem = "Static"
    else:
        receiver, receiver_owner = _owned_use(
            receiver_kind, owner.replace("/", ".").encode("utf-8"), loader_domain
        )
        stem = ""
    inputs: list[SemanticObject] = [env, receiver]
    if receiver_owner is not None:
        inputs.append(receiver_owner); threaded.append(receiver_owner)
    inputs.append(field_id)
    if is_set:
        inputs.append(value_type)
    inputs.append(memory)

    outputs: list[SemanticObject] = []
    if not is_set:
        if descriptor.startswith(("L", "[")):
            local_value = _jni_value_type(descriptor, reference_kind=JniReferenceKind.LOCAL)
            local_owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
            outputs.extend((local_value, local_owner))
            exposed_value = local_value
        else:
            outputs.append(value_type)
            exposed_value = value_type
    else:
        exposed_value = value_type
    outputs.extend(threaded)
    outputs.append(memory)
    function_name = f"{'Set' if is_set else 'Get'}{stem}{suffix}Field"
    contract = call_contract(tuple(inputs), tuple(outputs), may_return=True, may_trap=False)
    return JniFieldAccessPlan(
        owner, name, descriptor, is_static, is_set, function_name,
        field_id, exposed_value, contract, loader_domain=loader_domain
    )


def jni_new_object_zero_arg_contract(
    *,
    owner: str,
    loader_domain: bytes | None,
    class_kind: JniReferenceKind = JniReferenceKind.GLOBAL,
    class_cache_owner: bool = False,
    track_exception_state: bool = True,
) -> SemanticObject:
    """Exact JNI ``NewObject`` contract for a zero-argument ``<init>()V``.

    No argument pack or varargs payload exists for this bounded case.  The
    constructed object is nullable because JNI may return NULL, and its local
    reference lifetime is explicit.  When exception tracking is requested, a
    clean state is consumed and a maybe-pending state is produced.
    """
    if not owner:
        raise ValueError("JNI object construction requires a nonempty class owner")
    loader_domain = _loader_domain(loader_domain)
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    clazz = jni_class_reference_type(class_kind, owner=owner, loader_domain=loader_domain)
    if class_cache_owner:
        if class_kind != JniReferenceKind.GLOBAL:
            raise ValueError("cached object construction requires a global class reference")
        class_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    else:
        class_owner = _owned_reference_owner(class_kind)
    ctor = jni_typed_method_id_type(owner, "<init>", "()V", loader_domain=loader_domain)
    family = owner.replace("/", ".").encode("utf-8")
    result = jni_reference_type(
        JniReferenceKind.LOCAL, family, loader_domain=loader_domain, nullable=True
    )
    result_owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    inputs: list[SemanticObject] = [env, clazz]
    threaded: list[SemanticObject] = []
    if class_owner is not None:
        inputs.append(class_owner)
        threaded.append(class_owner)
    inputs.append(ctor)
    outputs: list[SemanticObject] = [result, result_owner, *threaded]
    if track_exception_state:
        inputs.append(jni_exception_state_type(JniExceptionState.CLEAN))
        outputs.append(jni_exception_state_type(JniExceptionState.MAYBE_PENDING))
    inputs.append(memory)
    outputs.append(memory)
    return call_contract(tuple(inputs), tuple(outputs), may_return=True, may_trap=False)


def jni_new_global_ref_contract(
    source_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    family: bytes = b"object",
    *,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    source = jni_reference_type(source_kind, family, loader_domain=loader_domain)
    source_owner = _owned_reference_owner(source_kind)
    result = jni_reference_type(JniReferenceKind.GLOBAL, family, loader_domain=loader_domain)
    owner = jni_reference_owner_type(JniReferenceKind.GLOBAL)
    inputs = (env, source, memory) if source_owner is None else (env, source, source_owner, memory)
    outputs = (result, owner, memory) if source_owner is None else (result, owner, source_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_delete_global_ref_contract(family: bytes = b"object", *, loader_domain: bytes | None = None) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    reference = jni_reference_type(JniReferenceKind.GLOBAL, family, loader_domain=loader_domain)
    owner = jni_reference_owner_type(JniReferenceKind.GLOBAL)
    return call_contract((env, reference, owner, memory), (memory,), may_return=True, may_trap=False)


def jni_new_global_class_cache_contract(
    *,
    owner: str,
    loader_domain: bytes | None,
    source_kind: JniReferenceKind = JniReferenceKind.LOCAL,
) -> SemanticObject:
    """Promote a typed class reference into an explicit method-cache anchor.

    The runtime ABI is exactly ``NewGlobalRef``.  The returned cache-owner
    token is proof-only and is specific to the Java class and defining loader.
    """
    if source_kind not in (JniReferenceKind.BORROWED, JniReferenceKind.LOCAL, JniReferenceKind.GLOBAL):
        raise ValueError("cached class promotion requires a strong JNI reference")
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    source = jni_class_reference_type(source_kind, owner=owner, loader_domain=loader_domain)
    source_owner = _owned_reference_owner(source_kind)
    result = jni_class_reference_type(JniReferenceKind.GLOBAL, owner=owner, loader_domain=loader_domain)
    cache_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    inputs = (env, source, memory) if source_owner is None else (env, source, source_owner, memory)
    outputs = (result, cache_owner, memory) if source_owner is None else (result, cache_owner, source_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_delete_global_class_cache_contract(*, owner: str, loader_domain: bytes | None) -> SemanticObject:
    """Release one exact cached global class and consume its cache anchor."""
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    reference = jni_class_reference_type(JniReferenceKind.GLOBAL, owner=owner, loader_domain=loader_domain)
    cache_owner = jni_class_cache_owner_type(owner, loader_domain=loader_domain)
    return call_contract((env, reference, cache_owner, memory), (memory,), may_return=True, may_trap=False)


def jni_new_weak_global_ref_contract(
    source_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    family: bytes = b"object",
    *,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    source = jni_reference_type(source_kind, family, loader_domain=loader_domain)
    source_owner = _owned_reference_owner(source_kind)
    result = jni_reference_type(JniReferenceKind.WEAK_GLOBAL, family, loader_domain=loader_domain)
    owner = jni_reference_owner_type(JniReferenceKind.WEAK_GLOBAL)
    inputs = (env, source, memory) if source_owner is None else (env, source, source_owner, memory)
    outputs = (result, owner, memory) if source_owner is None else (result, owner, source_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_delete_weak_global_ref_contract(family: bytes = b"object", *, loader_domain: bytes | None = None) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    reference = jni_reference_type(JniReferenceKind.WEAK_GLOBAL, family, loader_domain=loader_domain)
    owner = jni_reference_owner_type(JniReferenceKind.WEAK_GLOBAL)
    return call_contract((env, reference, owner, memory), (memory,), may_return=True, may_trap=False)


def jni_new_local_ref_contract(
    source_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    family: bytes = b"object",
    *,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    source = jni_reference_type(source_kind, family, loader_domain=loader_domain)
    source_owner = _owned_reference_owner(source_kind)
    result = jni_reference_type(JniReferenceKind.LOCAL, family, loader_domain=loader_domain)
    owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    inputs = (env, source, memory) if source_owner is None else (env, source, source_owner, memory)
    outputs = (result, owner, memory) if source_owner is None else (result, owner, source_owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_delete_local_ref_contract(family: bytes = b"object", *, loader_domain: bytes | None = None) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    reference = jni_reference_type(JniReferenceKind.LOCAL, family, loader_domain=loader_domain)
    owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    return call_contract((env, reference, owner, memory), (memory,), may_return=True, may_trap=False)


def jni_exception_check_contract() -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    return call_contract((env, memory), (bits_type(8), memory), may_return=True, may_trap=False)


def jni_exception_clear_contract() -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    return call_contract((env, memory), (memory,), may_return=True, may_trap=False)


def jni_exception_check_state_contract() -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    state = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    return call_contract((env, state, memory), (bits_type(8), state, memory), may_return=True, may_trap=False)


def jni_exception_clear_state_contract() -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    maybe = jni_exception_state_type(JniExceptionState.MAYBE_PENDING)
    clean = jni_exception_state_type(JniExceptionState.CLEAN)
    return call_contract((env, maybe, memory), (clean, memory), may_return=True, may_trap=False)


def jni_register_natives_contract(class_kind: JniReferenceKind = JniReferenceKind.LOCAL) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    clazz = jni_reference_type(class_kind, b"class")
    owner = _owned_reference_owner(class_kind)
    methods = jni_native_method_array_pointer_type()
    jint = bits_type(32)
    inputs = (env, clazz, methods, jint, memory) if owner is None else (env, clazz, owner, methods, jint, memory)
    outputs = (jint, memory) if owner is None else (jint, owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_unregister_natives_contract(class_kind: JniReferenceKind = JniReferenceKind.LOCAL) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    clazz = jni_reference_type(class_kind, b"class")
    owner = _owned_reference_owner(class_kind)
    jint = bits_type(32)
    inputs = (env, clazz, memory) if owner is None else (env, clazz, owner, memory)
    outputs = (jint, memory) if owner is None else (jint, owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_new_direct_byte_buffer_contract() -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    result = jni_reference_type(JniReferenceKind.LOCAL, b"object")
    owner = jni_reference_owner_type(JniReferenceKind.LOCAL)
    return call_contract((env, jni_void_pointer_type(), bits_type(64), memory), (result, owner, memory), may_return=True, may_trap=False)


def jni_get_direct_buffer_address_contract(reference_kind: JniReferenceKind = JniReferenceKind.BORROWED) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    buffer = jni_reference_type(reference_kind, b"object")
    owner = _owned_reference_owner(reference_kind)
    inputs = (env, buffer, memory) if owner is None else (env, buffer, owner, memory)
    outputs = (jni_void_pointer_type(), memory) if owner is None else (jni_void_pointer_type(), owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_get_direct_buffer_capacity_contract(reference_kind: JniReferenceKind = JniReferenceKind.BORROWED) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    buffer = jni_reference_type(reference_kind, b"object")
    owner = _owned_reference_owner(reference_kind)
    inputs = (env, buffer, memory) if owner is None else (env, buffer, owner, memory)
    outputs = (bits_type(64), memory) if owner is None else (bits_type(64), owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)


def jni_get_object_ref_type_contract(
    reference_kind: JniReferenceKind = JniReferenceKind.BORROWED,
    family: bytes = b"object",
    *,
    loader_domain: bytes | None = None,
) -> SemanticObject:
    env, memory = jni_env_pointer_type(), jni_memory_effect_type()
    reference = jni_reference_type(reference_kind, family, loader_domain=loader_domain)
    owner = _owned_reference_owner(reference_kind)
    inputs = (env, reference, memory) if owner is None else (env, reference, owner, memory)
    outputs = (bits_type(32), memory) if owner is None else (bits_type(32), owner, memory)
    return call_contract(inputs, outputs, may_return=True, may_trap=False)



def _jni_mangle_component(value: str) -> str:
    """JNI native short-name mangling over UTF-16 code units."""
    out: list[str] = []
    raw = value.encode("utf-16-be", "surrogatepass")
    for index in range(0, len(raw), 2):
        code = int.from_bytes(raw[index:index + 2], "big")
        char = chr(code)
        if ("A" <= char <= "Z") or ("a" <= char <= "z") or ("0" <= char <= "9"):
            out.append(char)
        elif char in ("/", "."):
            out.append("_")
        elif char == "_":
            out.append("_1")
        elif char == ";":
            out.append("_2")
        elif char == "[":
            out.append("_3")
        else:
            out.append(f"_0{code:04x}")
    return "".join(out)


def jni_short_native_symbol(class_descriptor: str, method_name: str) -> bytes:
    """Return the canonical JNI short symbol for one non-overloaded native method."""
    if not (class_descriptor.startswith("L") and class_descriptor.endswith(";")):
        raise ValueError("JNI class descriptor must be L...;")
    if not method_name or any(char in method_name for char in "./;[\x00"):
        raise ValueError("invalid JNI method name")
    binary = class_descriptor[1:-1]
    return ("Java_" + _jni_mangle_component(binary) + "_" + _jni_mangle_component(method_name)).encode("ascii")

def jni_get_env_contract(env_slot: SemanticObject, owner: SemanticObject, local_memory: SemanticObject) -> SemanticObject:
    vm, external_memory, jint = java_vm_pointer_type(), jni_memory_effect_type(), bits_type(32)
    return call_contract(
        (vm, env_slot, jint, external_memory, owner, local_memory),
        (jint, external_memory, owner, local_memory),
        may_return=True,
        may_trap=False,
    )


def jni_attach_current_thread_contract(
    env_slot: SemanticObject,
    owner: SemanticObject,
    local_memory: SemanticObject,
) -> SemanticObject:
    vm, external_memory, jint = java_vm_pointer_type(), jni_memory_effect_type(), bits_type(32)
    return call_contract(
        (vm, env_slot, jni_void_pointer_type(), external_memory, owner, local_memory),
        (jint, external_memory, owner, local_memory),
        may_return=True,
        may_trap=False,
    )


def jni_detach_current_thread_contract() -> SemanticObject:
    vm, external_memory, jint = java_vm_pointer_type(), jni_memory_effect_type(), bits_type(32)
    return call_contract((vm, external_memory), (jint, external_memory), may_return=True, may_trap=False)


def jni_destroy_java_vm_contract() -> SemanticObject:
    return jni_detach_current_thread_contract()


__all__ = [
    name
    for name in globals()
    if name.startswith("jni_")
    or name.startswith("JNI_")
    or name
    in {
        "JniReferenceKind",
        "JniExceptionState",
        "JniReferenceArgumentSpec",
        "JniArgumentPackPlan",
        "JniArgumentPackNodes",
        "JniMethodCallPlan",
        "JniFieldAccessPlan",
        "java_vm_pointer_type",
    }
]
