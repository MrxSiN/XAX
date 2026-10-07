"""General Android managed classes whose methods forward to XAX native exports (ADR-199).

One identity-only target carrier, ``android-managed-class-v1``, declares a DEX
class: its descriptor, superclass, interfaces, and the virtual methods the
platform calls (lifecycle overrides, listener/callback interface methods).  Each
method forwards its exact arguments to one private native method, bound by JNI
short name to an XAX ``android-aapcs64-c`` export, and returns that export's
result.  ``call_super`` (void methods only) first invokes the superclass method
with the same arguments.  The class gets a public no-argument constructor that
calls the superclass constructor, so the platform (manifest components) or XAX
code (``NewObject`` over JNI) can instantiate it.

This is the managed half of the Android ABI, not application logic: every
behaviour is the XAX export's.  It replaces per-API carriers: an Activity's
``onResume``, ``SurfaceHolder.Callback.surfaceCreated`` and
``View.OnTouchListener.onTouch`` are all instances of it.  The export's
non-proof parameters must be ``(JNIEnv*, this, arguments...)`` with exact JNI
widths, and its non-proof results must match the Java result
(``check_export_signature``).  ``float``/``double`` are rejected because the JNI
layer has no exact float carrier yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from xax_android_sdk import parse_jvm_method_descriptor
from xax_compiler import (
    Cursor,
    Kind,
    SemanticObject,
    _decode_function_interface,
    _decode_opaque_identity_type,
    _decode_pointer_type,
    _is_proof_type,
    fail,
    target,
    uleb,
)
from xax_dex import (
    ACC_PROTECTED,
    ACC_PUBLIC,
    ACC_PRIVATE,
    ACC_NATIVE,
    DexBridgeSpec,
    DexForwardingOverride,
    DexNativeMethod,
    DexProto,
)
from xax_jni import JniReferenceKind, _jni_reference_family, _jni_value_type, jni_env_pointer_type, jni_short_native_symbol

ANDROID_MANAGED_CLASS_PREFIX = b"android-managed-class-v1\0"
ACCESS = {"public": ACC_PUBLIC, "protected": ACC_PROTECTED}
_PRIMITIVES = frozenset("ZBCSIJ")


@dataclass(frozen=True, order=True)
class AndroidManagedMethod:
    name: str
    descriptor: str  # JVM method descriptor, e.g. "(Landroid/view/MotionEvent;)Z"
    access: str = "public"
    call_super: bool = False

    def __post_init__(self) -> None:
        if not self.name or not self.name.isidentifier() or self.name.startswith("<"):
            raise ValueError("managed method name must be a Java identifier")
        parameters, result = parse_jvm_method_descriptor(self.descriptor)
        for item in (*parameters, result):
            if item in ("F", "D"):
                raise ValueError("float/double callbacks need an exact JNI float carrier (unsupported)")
            if item != "V" and item not in _PRIMITIVES and not item.startswith(("L", "[")):
                raise ValueError(f"unsupported descriptor component {item!r}")
        if self.access not in ACCESS:
            raise ValueError("managed method access must be public or protected")
        if self.call_super and result != "V":
            raise ValueError("call_super requires a void method; call the superclass explicitly over JNI otherwise")

    @property
    def proto(self) -> DexProto:
        parameters, result = parse_jvm_method_descriptor(self.descriptor)
        return DexProto(result, parameters)

    @property
    def native_name(self) -> str:
        return f"xax{self.name[0].upper()}{self.name[1:]}"


@dataclass(frozen=True)
class AndroidManagedClass:
    class_descriptor: str
    superclass_descriptor: str = "Ljava/lang/Object;"
    interfaces: tuple[str, ...] = ()
    methods: tuple[AndroidManagedMethod, ...] = ()
    native_library: str = "xaxapp"

    def __post_init__(self) -> None:
        for descriptor in (self.class_descriptor, self.superclass_descriptor, *self.interfaces):
            if not (descriptor.startswith("L") and descriptor.endswith(";") and len(descriptor) > 2):
                raise ValueError(f"class descriptor expected, got {descriptor!r}")
        object.__setattr__(self, "interfaces", tuple(sorted(set(self.interfaces))))
        object.__setattr__(self, "methods", tuple(sorted(self.methods)))
        names = [method.name for method in self.methods]
        if not names or len(set(names)) != len(names):
            raise ValueError("a managed class needs one or more methods with distinct names (JNI short names)")
        if not self.native_library or "/" in self.native_library:
            raise ValueError("native library must be a bare name")

    @property
    def java_name(self) -> str:
        return self.class_descriptor[1:-1].replace("/", ".")

    def symbols(self) -> dict[bytes, AndroidManagedMethod]:
        return {jni_short_native_symbol(self.class_descriptor, method.native_name): method for method in self.methods}


def _text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return uleb(len(raw)) + raw


def android_managed_class_semantics(description: AndroidManagedClass) -> SemanticObject:
    identity = bytearray(ANDROID_MANAGED_CLASS_PREFIX)
    identity += _text(description.class_descriptor) + _text(description.superclass_descriptor) + _text(description.native_library)
    identity += uleb(len(description.interfaces)) + b"".join(_text(item) for item in description.interfaces)
    identity += uleb(len(description.methods))
    for method in description.methods:
        identity += _text(method.name) + _text(method.descriptor) + _text(method.access) + bytes((int(method.call_super),))
    return target(bytes(identity))


def decode_android_managed_class(obj: SemanticObject) -> AndroidManagedClass:
    where = obj.cid.hex()
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.MANAGED", where, "ANDROID-MANAGED-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, where)
    identity = outer.byte_string()
    outer.end("ANDROID-MANAGED-CARRIER")
    if not identity.startswith(ANDROID_MANAGED_CLASS_PREFIX):
        fail("XAX.ANDROID.MANAGED", where, "ANDROID-MANAGED-IDENTITY", ANDROID_MANAGED_CLASS_PREFIX.decode(), identity[:32].hex())
    cursor = Cursor(identity[len(ANDROID_MANAGED_CLASS_PREFIX):], where)
    try:
        text = lambda: cursor.byte_string().decode("utf-8")  # noqa: E731
        class_descriptor, superclass, library = text(), text(), text()
        interfaces = tuple(text() for _ in range(cursor.uleb()))
        methods = []
        for _ in range(cursor.uleb()):
            name, descriptor, access = text(), text(), text()
            methods.append(AndroidManagedMethod(name, descriptor, access, cursor.boolean()))
        cursor.end("ANDROID-MANAGED-IDENTITY")
        description = AndroidManagedClass(class_descriptor, superclass, interfaces, tuple(methods), library)
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.MANAGED", where, "ANDROID-MANAGED-FIELDS", "valid managed class", str(error))
    canonical = android_managed_class_semantics(description)
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.MANAGED", where, "ANDROID-MANAGED-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return description


def lower_android_managed_class(obj: SemanticObject) -> DexBridgeSpec:
    description = decode_android_managed_class(obj)
    return DexBridgeSpec(
        description.class_descriptor,
        description.superclass_descriptor,
        tuple(DexNativeMethod(method.native_name, method.proto, ACC_PRIVATE | ACC_NATIVE) for method in description.methods),
        tuple(
            DexForwardingOverride(method.name, method.proto, method.native_name, ACCESS[method.access], method.call_super)
            for method in description.methods
        ),
        description.interfaces,
        description.native_library,
    )


def _jni_reference(cid: bytes, resolve: Callable[[bytes], SemanticObject]) -> tuple[str, str] | None:
    """(kind, family) of a JNI reference type, or None.  Loader domain and nullability are not compared."""
    obj = resolve(cid)
    if obj.kind != Kind.TYPE:
        return None
    try:
        element, _permission, _alignment = _decode_pointer_type(obj, resolve)
        identity = _decode_opaque_identity_type(resolve(element))
    except Exception:  # noqa: BLE001 - any other type form is simply not a JNI reference
        return None
    if identity.startswith(b"android.jni.ref/v2/") or identity.startswith(b"android.jni.ref/v3/"):
        cursor = Cursor(identity[19:], "jni-ref")
        kind = JniReferenceKind(cursor.take(1)[0])
        if identity.startswith(b"android.jni.ref/v3/"):
            cursor.take(1)  # nullability
        return kind.name, cursor.byte_string().decode("utf-8")
    if identity.startswith(b"android.jni.ref/"):
        kind, _, family = identity[len(b"android.jni.ref/"):].partition(b"/")
        return kind.decode("ascii").upper(), family.decode("utf-8")
    return None


def check_export_signature(
    method: AndroidManagedMethod,
    class_descriptor: str,
    function: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
) -> str | None:
    """Why ``function`` cannot implement ``method`` as a JNI native, or None.  Proof parameters/results are erased."""
    _graph, parameters, results = _decode_function_interface(function, resolve)
    parameters = [cid for cid in parameters if not _is_proof_type(resolve(cid))]
    results = [cid for cid in results if not _is_proof_type(resolve(cid))]
    java_parameters, java_result = parse_jvm_method_descriptor(method.descriptor)
    if len(parameters) != 2 + len(java_parameters):
        return f"{len(parameters)} ABI parameters, expected JNIEnv*, this and {len(java_parameters)} argument(s)"
    if parameters[0] != jni_env_pointer_type().cid:
        return "first parameter is not JNIEnv*"
    expected = [class_descriptor, *java_parameters]
    for index, (cid, descriptor) in enumerate(zip(parameters[1:], expected), start=1):
        if descriptor in _PRIMITIVES:
            if cid != _jni_value_type(descriptor).cid:
                return f"parameter {index} is not the JNI width of {descriptor}"
        elif _jni_reference(cid, resolve) != ("BORROWED", _jni_reference_family(descriptor).decode("utf-8")):
            return f"parameter {index} is not a borrowed JNI reference to {descriptor}"
    if java_result == "V":
        return None if not results else "void method with a non-proof result"
    if len(results) != 1:
        return f"{len(results)} non-proof results for {java_result}"
    if java_result in _PRIMITIVES:
        return None if results[0] == _jni_value_type(java_result).cid else f"result is not the JNI width of {java_result}"
    reference = _jni_reference(results[0], resolve)
    if reference is None or reference[1] != _jni_reference_family(java_result).decode("utf-8") or reference[0] not in ("LOCAL", "BORROWED"):
        return f"result is not a local or borrowed JNI reference to {java_result}"
    return None
