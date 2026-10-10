"""Persistent-counter Android Activity: state, file I/O, and lifecycle owned by XAX (ADR-111).

Semantics (one content-addressed carrier plus two ordinary XAX functions):

* ``onCreate`` restores the count from a private state file and shows it;
* each click increments the count, persists it, and shows it;
* the count survives the process being killed and restarted.

The managed side does only what the platform requires: it obtains a file
descriptor for ``<files dir>/<state file>`` (``ParcelFileDescriptor.open`` plus
``detachFd``, so the descriptor is handed to XAX and nothing on the Java side
closes it), calls one native method, and sets the returned number as the
button's text.  The native XAX functions own every read, write, the
arithmetic, and the descriptor's lifetime (each one closes it).  Nothing here
adds an Android concept to the kernel.
"""

from __future__ import annotations

from dataclasses import dataclass

from xax_compiler import (
    Kind,
    Operation,
    Permission,
    SemanticObject,
    bits_type,
    fail,
    foreign_function_symbol,
    heap_view_type,
    pointer_type,
    target,
    uleb,
    Cursor,
    ForeignDeallocatorContract,
)
from xax_dex import (
    ACC_PRIVATE,
    ACC_NATIVE,
    ACC_PUBLIC,
    DexAssembledMethod,
    DexBridgeSpec,
    DexInstruction,
    DexMethodRef,
    DexNativeMethod,
    DexProto,
)
from xax_graph_builder import GraphBuilder
from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type, jni_type_objects
from xax_platform import PosixAndroidApi, PosixDescriptorApi, posix_android_api, posix_descriptor_api

COUNTER_PREFIX = b"android-counter-activity-v1"
# ParcelFileDescriptor.MODE_READ_WRITE | MODE_CREATE
_MODE_READ_WRITE_CREATE = 0x30000000 | 0x08000000
B32, B64 = bits_type(32), bits_type(64)


@dataclass(frozen=True)
class CounterActivityDescription:
    package_name: str
    activity_class: str  # binary name, e.g. "xax.generated.XaxActivity"
    listener_class: str
    state_file: str

    @property
    def activity_descriptor(self) -> str:
        return "L" + self.activity_class.replace(".", "/") + ";"

    @property
    def listener_descriptor(self) -> str:
        return "L" + self.listener_class.replace(".", "/") + ";"


def counter_activity_semantics(
    *,
    package_name: str = "xax.generated",
    activity_class: str = "xax.generated.XaxActivity",
    listener_class: str = "xax.generated.XaxOnClickListener",
    state_file: str = "xax.counter",
) -> SemanticObject:
    """Identity-only carrier naming the classes and the private state file."""
    values = (package_name, activity_class, listener_class, state_file)
    if any(not value or "\x00" in value for value in values) or "/" in state_file or state_file in (".", ".."):
        raise ValueError("counter Activity fields must be nonempty; the state file is one file name")
    identity = bytearray(COUNTER_PREFIX)
    for value in values:
        raw = value.encode("utf-8")
        identity.extend(uleb(len(raw)) + raw)
    return target(bytes(identity))


def decode_counter_activity(obj: SemanticObject) -> CounterActivityDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.COUNTER", obj.cid.hex(), "ANDROID-COUNTER-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-COUNTER-CARRIER")
    if not identity.startswith(COUNTER_PREFIX):
        fail("XAX.ANDROID.COUNTER", obj.cid.hex(), "ANDROID-COUNTER-IDENTITY", COUNTER_PREFIX.decode(), identity[:32].hex())
    cursor = Cursor(identity[len(COUNTER_PREFIX):], obj.cid.hex())
    values = tuple(cursor.byte_string().decode("utf-8") for _ in range(4))
    cursor.end("ANDROID-COUNTER-IDENTITY")
    try:
        canonical = counter_activity_semantics(**dict(zip(("package_name", "activity_class", "listener_class", "state_file"), values)))
    except ValueError as error:
        fail("XAX.ANDROID.COUNTER", obj.cid.hex(), "ANDROID-COUNTER-FIELDS", "valid counter Activity fields", str(error))
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.COUNTER", obj.cid.hex(), "ANDROID-COUNTER-CANONICAL", "canonical carrier", obj.cid.hex())
    return CounterActivityDescription(*values)


# ---------------------------------------------------------------- native XAX side


@dataclass(frozen=True)
class CounterNative:
    on_create: SemanticObject  # (env, activity, bundle, fd, descriptor, fs, memory) -> (count, fs, memory)
    on_click: SemanticObject  # (env, listener, view, fd, descriptor, fs, memory) -> (count, fs, memory)
    objects: tuple[SemanticObject, ...]


def _file_calls(api: PosixAndroidApi, cell: SemanticObject):
    """``pread64``/``pwrite64`` of one 8-byte cell at offset 0 (bionic)."""
    def call(name: bytes) -> SemanticObject:
        return foreign_function_symbol(b"libc.so", name, (B32, cell, B64, B64, api.filesystem_effect, api.memory_effect), (B64, api.filesystem_effect, api.memory_effect))
    return call(b"pread64"), call(b"pwrite64")


def counter_native(description: CounterActivityDescription, *, api: PosixAndroidApi | None = None, descriptors: PosixDescriptorApi | None = None) -> CounterNative:
    """Both JNI callbacks.  Each one owns the descriptor it is given (the ``descriptor``
    token, ADR-153) and must close it exactly once; a click makes its write durable
    with ``fdatasync`` before closing."""
    api = api or posix_android_api()
    descriptors = descriptors or posix_descriptor_api(api)
    env = jni_env_pointer_type()
    activity = jni_reference_type(JniReferenceKind.BORROWED, description.activity_class.encode(), loader_domain=f"app:{description.package_name}".encode())
    bundle = jni_reference_type(JniReferenceKind.BORROWED, b"android.os.Bundle", loader_domain=b"android.boot")
    listener = jni_reference_type(JniReferenceKind.BORROWED, description.listener_class.encode(), loader_domain=f"app:{description.package_name}".encode())
    view = jni_reference_type(JniReferenceKind.BORROWED, b"android.view.View", loader_domain=b"android.boot")
    view_type = heap_view_type(8, initialized=False)  # malloc does not zero; the explicit store does
    cell = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
    pread, pwrite = _file_calls(api, cell)
    # The heap view hands out the 8-byte cell directly; free takes that same pointer.
    free = foreign_function_symbol(b"libc.so", b"free", (cell, view_type, api.memory_effect), (api.memory_effect,), deallocator=ForeignDeallocatorContract(0, 1))

    def callback(receiver, argument, increment: bool):
        graph = GraphBuilder()
        block = graph.block(env, receiver, argument, B32, descriptors.descriptor, api.filesystem_effect, api.memory_effect)
        _env, _receiver, _argument, fd, owner_fd, fs, memory = block.params
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 8), memory), (api.byte_ptr_rw, api.heap_resource, api.memory_effect), entity=api.malloc)
        slot, owned, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (cell, view_type, api.memory_effect), attributes=(8, 8))
        memory = block.op1(Operation.STORE_BITS_LE, (slot, block.const(B64, 0), memory), api.memory_effect, attributes=(8, 8))
        offset = block.const(B64, 0)
        _read, fs, memory = block.op(Operation.CALL_FOREIGN, (fd, slot, block.const(B64, 8), offset, fs, memory), (B64, api.filesystem_effect, api.memory_effect), entity=pread)
        count, memory = block.op(Operation.LOAD_BITS_LE, (slot, memory), (B64, api.memory_effect), attributes=(8, 8))
        if increment:
            count = block.op1(Operation.ADD_WRAP, (count, block.const(B64, 1)), B64)
            memory = block.op1(Operation.STORE_BITS_LE, (slot, count, memory), api.memory_effect, attributes=(8, 8))
            _written, fs, memory = block.op(Operation.CALL_FOREIGN, (fd, slot, block.const(B64, 8), offset, fs, memory), (B64, api.filesystem_effect, api.memory_effect), entity=pwrite)
            _synced, fs = block.op(Operation.CALL_FOREIGN, (fd, fs), (B32, api.filesystem_effect), entity=descriptors.fdatasync)
        _closed, fs = block.op(Operation.CALL_FOREIGN, (fd, owner_fd, fs), (B32, api.filesystem_effect), entity=descriptors.close)
        memory = block.op1(Operation.CALL_FOREIGN, (slot, owned, memory), api.memory_effect, entity=free)
        block.ret(count, fs, memory)
        function = graph.function(block.parameter_types, (B64, api.filesystem_effect, api.memory_effect))
        return graph, function

    create_graph, on_create = callback(activity, bundle, False)
    click_graph, on_click = callback(listener, view, True)
    app = f"app:{description.package_name}".encode()
    references = jni_type_objects((
        (JniReferenceKind.BORROWED, description.activity_class.encode(), app),
        (JniReferenceKind.BORROWED, b"android.os.Bundle", b"android.boot"),
        (JniReferenceKind.BORROWED, description.listener_class.encode(), app),
        (JniReferenceKind.BORROWED, b"android.view.View", b"android.boot"),
    ))
    objects = (*api.types, *references, *create_graph.objects.values(), *click_graph.objects.values(), pread, pwrite, free, cell, view_type, *descriptors.objects)
    return CounterNative(on_create, on_click, objects)


# ---------------------------------------------------------------- managed (DEX) side

_FILE, _CONTEXT, _PFD = "Ljava/io/File;", "Landroid/content/Context;", "Landroid/os/ParcelFileDescriptor;"
_STRING, _VIEW, _BUNDLE = "Ljava/lang/String;", "Landroid/view/View;", "Landroid/os/Bundle;"
_GET_FILES_DIR = DexMethodRef(_CONTEXT, "getFilesDir", DexProto(_FILE, ()))
_NEW_FILE = DexMethodRef(_FILE, "<init>", DexProto("V", (_FILE, _STRING)))
_OPEN = DexMethodRef(_PFD, "open", DexProto(_PFD, (_FILE, "I")))
_DETACH = DexMethodRef(_PFD, "detachFd", DexProto("I", ()))
_TO_STRING = DexMethodRef("Ljava/lang/Long;", "toString", DexProto(_STRING, ("J",)))
_SET_TEXT = DexMethodRef("Landroid/widget/TextView;", "setText", DexProto("V", ("Ljava/lang/CharSequence;",)))


def _open_state(files_dir: int, scratch: int, name: str) -> tuple[DexInstruction, ...]:
    """``fd = ParcelFileDescriptor.open(new File(files_dir, name), RW|CREATE).detachFd()`` into ``scratch``.

    Uses ``scratch`` and ``scratch + 1``; ``files_dir`` holds the files directory.
    """
    file, text = scratch, scratch + 1
    return (
        DexInstruction("new-instance", (file,), _FILE),
        DexInstruction("const-string", (text,), name),
        DexInstruction("invoke-direct", (file, files_dir, text), _NEW_FILE),
        DexInstruction("const", (text,), literal=_MODE_READ_WRITE_CREATE),
        DexInstruction("invoke-static", (file, text), _OPEN),
        DexInstruction("move-result-object", (file,)),
        DexInstruction("invoke-virtual", (file,), _DETACH),
        DexInstruction("move-result", (file,)),
    )


def counter_dex_specs(description: CounterActivityDescription, native_library: str) -> tuple[DexBridgeSpec, DexBridgeSpec]:
    activity, listener = description.activity_descriptor, description.listener_descriptor
    create_native = DexNativeMethod("xaxOnCreate", DexProto("J", (_BUNDLE, "I")), ACC_PRIVATE | ACC_NATIVE)
    click_native = DexNativeMethod("xaxOnClick", DexProto("J", (_VIEW, "I")), ACC_PRIVATE | ACC_NATIVE)
    # onCreate(Bundle): registers v0..v5 locals, v6 = this, v7 = bundle.
    on_create = DexAssembledMethod("onCreate", DexProto("V", (_BUNDLE,)), 8, (
        DexInstruction("invoke-super", (6, 7), DexMethodRef("Landroid/app/Activity;", "onCreate", DexProto("V", (_BUNDLE,)))),
        DexInstruction("new-instance", (0,), "Landroid/widget/Button;"),
        DexInstruction("invoke-direct", (0, 6), DexMethodRef("Landroid/widget/Button;", "<init>", DexProto("V", (_CONTEXT,)))),
        DexInstruction("invoke-virtual", (6,), _GET_FILES_DIR),
        DexInstruction("move-result-object", (1,)),
        *_open_state(1, 2, description.state_file),                                      # v2 = fd
        DexInstruction("invoke-direct", (6, 7, 2), DexMethodRef(activity, create_native.name, create_native.proto)),
        DexInstruction("move-result-wide", (2,)),                                       # v2:v3 = count
        DexInstruction("invoke-static", (2, 3), _TO_STRING),
        DexInstruction("move-result-object", (2,)),
        DexInstruction("invoke-virtual", (0, 2), _SET_TEXT),
        DexInstruction("new-instance", (1,), listener),
        DexInstruction("invoke-direct", (1,), DexMethodRef(listener, "<init>", DexProto("V", ()))),
        DexInstruction("invoke-virtual", (0, 1), DexMethodRef(_VIEW, "setOnClickListener", DexProto("V", ("Landroid/view/View$OnClickListener;",)))),
        DexInstruction("invoke-virtual", (6, 0), DexMethodRef("Landroid/app/Activity;", "setContentView", DexProto("V", (_VIEW,)))),
        DexInstruction("return-void"),
    ), ACC_PUBLIC)
    # onClick(View): registers v0..v4 locals, v5 = this, v6 = view.
    on_click = DexAssembledMethod("onClick", DexProto("V", (_VIEW,)), 7, (
        DexInstruction("invoke-virtual", (6,), DexMethodRef(_VIEW, "getContext", DexProto(_CONTEXT, ()))),
        DexInstruction("move-result-object", (0,)),
        DexInstruction("invoke-virtual", (0,), _GET_FILES_DIR),
        DexInstruction("move-result-object", (0,)),
        *_open_state(0, 1, description.state_file),                                      # v1 = fd
        DexInstruction("invoke-direct", (5, 6, 1), DexMethodRef(listener, click_native.name, click_native.proto)),
        DexInstruction("move-result-wide", (2,)),                                       # v2:v3 = count
        DexInstruction("invoke-static", (2, 3), _TO_STRING),
        DexInstruction("move-result-object", (2,)),
        DexInstruction("check-cast", (6,), "Landroid/widget/TextView;"),
        DexInstruction("invoke-virtual", (6, 2), _SET_TEXT),
        DexInstruction("return-void"),
    ), ACC_PUBLIC)
    activity_spec = DexBridgeSpec(activity, "Landroid/app/Activity;", native_methods=(create_native,), native_library=native_library, assembled_methods=(on_create,))
    listener_spec = DexBridgeSpec(listener, "Ljava/lang/Object;", native_methods=(click_native,), interfaces=("Landroid/view/View$OnClickListener;",), assembled_methods=(on_click,))
    return activity_spec, listener_spec



def jni_symbols(description: CounterActivityDescription) -> tuple[bytes, bytes]:
    """JNI short names of ``xaxOnCreate`` and ``xaxOnClick``."""
    from xax_jni import jni_short_native_symbol

    return (
        jni_short_native_symbol(description.activity_descriptor, "xaxOnCreate"),
        jni_short_native_symbol(description.listener_descriptor, "xaxOnClick"),
    )


def counter_store(description: CounterActivityDescription, *, packed: bool = True):
    """``(reader, target object, onCreate cid, onClick cid)``: the verified canonical store of both JNI methods."""
    from xax_compiler import android_arm64_shared_integer_target, write_store, object_with_refs, StoreReader, verify_store

    native = counter_native(description)
    # The full-integer profile (ADR-255): the same code as v4 for these functions, and room for maintenance edits.
    target_object = android_arm64_shared_integer_target(packed=packed)
    functions = (native.on_create, native.on_click)
    available = {item.cid: item for item in (*native.objects, *functions, target_object)}
    module = object_with_refs(Kind.MODULE, [*functions, target_object])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    available.update({module.cid: module, root.cid: root})
    reachable, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    reader = StoreReader(write_store(root.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader, target_object, native.on_create.cid, native.on_click.cid


def compile_counter_library(reader, target_object: SemanticObject, on_create: bytes, on_click: bytes, description: CounterActivityDescription, *, soname: bytes = b"libxaxapp.so") -> bytes:
    """The native library exporting both JNI methods from a counter store (general target: heap views need it)."""
    from xax_android import AndroidExport, compile_android_shared

    create_symbol, click_symbol = jni_symbols(description)
    exports = (AndroidExport(create_symbol, on_create), AndroidExport(click_symbol, on_click))
    return compile_android_shared(reader, exports, target_object=target_object, soname=soname).data


def counter_library(description: CounterActivityDescription, *, packed: bool = True, soname: bytes = b"libxaxapp.so") -> bytes:
    """The native library exporting both JNI methods (general target: heap views need it)."""
    reader, target_object, on_create, on_click = counter_store(description, packed=packed)
    return compile_counter_library(reader, target_object, on_create, on_click, description, soname=soname)
