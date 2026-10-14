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


# ---------------------------------------------------------------- DEX-only side (ADR-259)
#
# The same app with no native library: both callbacks are XAX functions over the Android platform's managed
# members, compiled by the JVM class-file backend and lowered to DEX (``xax_dex_jvm``).  Each one owns what the
# JNI version owns (the state file's descriptor: open, pread/pwrite, fdatasync, close) and also what the generated
# DEX did around it: the button, its text, the listener, and the content view.  The only non-XAX code is the two
# platform-required class shells: ``onCreate`` calls ``super.onCreate`` and the XAX function; ``onClick`` calls the
# XAX function.  The file is opened ``O_RDWR | O_CREAT`` with mode 0600, as ``ParcelFileDescriptor`` opened it.

_O_RDWR, _O_CREAT, _MODE_0600 = 0o2, 0o100, 0o600  # Linux values (bionic)


@dataclass(frozen=True)
class CounterManaged:
    on_create: SemanticObject  # (activity, io) -> io
    on_click: SemanticObject  # (view, io) -> io
    objects: tuple[SemanticObject, ...]


def counter_managed(description: CounterActivityDescription) -> CounterManaged:
    from xax_compiler import EffectDomain, effect_type, opaque_identity_type
    from xax_jvm import REFERENCE_PREFIX, jvm_reference_type, jvm_static, jvm_virtual

    b8 = bits_type(8)
    io = effect_type(EffectDomain.IO, 0)
    types: list[SemanticObject] = [b8, B32, B64, io]

    def reference(descriptor: str) -> SemanticObject:
        types.append(opaque_identity_type(REFERENCE_PREFIX + descriptor.encode()))
        types.append(jvm_reference_type(descriptor.encode()))
        return types[-1]

    def internal(descriptor: str) -> bytes:
        return descriptor[1:-1].encode() if descriptor.startswith("L") else descriptor.encode()

    activity, listener = reference(description.activity_descriptor), reference(description.listener_descriptor)
    view, context, file, string = reference(_VIEW), reference(_CONTEXT), reference(_FILE), reference(_STRING)
    descriptor, cell_array = reference("Ljava/io/FileDescriptor;"), reference("[B")
    button, text_view, text = reference("Landroid/widget/Button;"), reference("Landroid/widget/TextView;"), reference("Ljava/lang/CharSequence;")
    on_click_listener, platform_activity = reference("Landroid/view/View$OnClickListener;"), reference("Landroid/app/Activity;")

    def special(abi: bytes, library: bytes, name: bytes, inputs, outputs) -> SemanticObject:
        return foreign_function_symbol(library, name, inputs, outputs, abi=abi)

    def cast(source: SemanticObject, result: SemanticObject, target_descriptor: str) -> SemanticObject:
        return special(b"jvm-checkcast", internal(target_descriptor), b"checkcast", (source,), (result,))

    os_class = b"android/system/Os"
    files_dir = jvm_virtual(b"android/content/Context", b"getFilesDir()Ljava/io/File;", (context, io), (file, io))
    path = jvm_virtual(b"java/io/File", b"getPath()Ljava/lang/String;", (file,), (string,))
    name = special(b"jvm-ldc", b"java/lang/String", b"/" + description.state_file.encode(), (), (string,))
    concat = jvm_virtual(b"java/lang/String", b"concat(Ljava/lang/String;)Ljava/lang/String;", (string, string), (string,))
    open_file = jvm_static(os_class, b"open(Ljava/lang/String;II)Ljava/io/FileDescriptor;", (string, B32, B32, io), (descriptor, io))
    new_cell = special(b"jvm-newarray", b"B", b"newarray", (B32,), (cell_array,))
    load = special(b"jvm-arrayload", b"[B", b"load", (cell_array, B32), (b8,))
    store = special(b"jvm-arraystore", b"[B", b"store", (cell_array, B32, b8), ())
    pread = jvm_static(os_class, b"pread(Ljava/io/FileDescriptor;[BIIJ)I", (descriptor, cell_array, B32, B32, B64, io), (B32, io))
    pwrite = jvm_static(os_class, b"pwrite(Ljava/io/FileDescriptor;[BIIJ)I", (descriptor, cell_array, B32, B32, B64, io), (B32, io))
    fdatasync = jvm_static(os_class, b"fdatasync(Ljava/io/FileDescriptor;)V", (descriptor, io), (io,))
    close = jvm_static(os_class, b"close(Ljava/io/FileDescriptor;)V", (descriptor, io), (io,))
    to_string = jvm_static(b"java/lang/Long", b"toString(J)Ljava/lang/String;", (B64,), (string,))
    set_text = jvm_virtual(b"android/widget/TextView", b"setText(Ljava/lang/CharSequence;)V", (text_view, text, io), (io,))
    new_button = special(b"jvm-new", b"android/widget/Button", b"<init>(Landroid/content/Context;)V", (context, io), (button, io))
    new_listener = special(b"jvm-new", internal(description.listener_descriptor), b"<init>()V", (io,), (listener, io))
    set_listener = jvm_virtual(b"android/view/View", b"setOnClickListener(Landroid/view/View$OnClickListener;)V", (view, on_click_listener, io), (io,))
    set_content = jvm_virtual(b"android/app/Activity", b"setContentView(Landroid/view/View;)V", (platform_activity, view, io), (io,))
    get_context = jvm_virtual(b"android/view/View", b"getContext()Landroid/content/Context;", (view, io), (context, io))
    casts = {
        "context": cast(activity, context, _CONTEXT), "activity": cast(activity, platform_activity, "Landroid/app/Activity;"),
        "button_view": cast(button, view, _VIEW), "button_text": cast(button, text_view, "Landroid/widget/TextView;"),
        "view_text": cast(view, text_view, "Landroid/widget/TextView;"), "chars": cast(string, text, "Ljava/lang/CharSequence;"),
        "listener": cast(listener, on_click_listener, "Landroid/view/View$OnClickListener;"),
    }
    declarations = (files_dir, path, name, concat, open_file, new_cell, load, store, pread, pwrite, fdatasync, close, to_string,
                    set_text, new_button, new_listener, set_listener, set_content, get_context, *casts.values())

    def call(block, entity, operands, results):
        return block.op(Operation.CALL_FOREIGN, operands, results, entity=entity)

    def call1(block, entity, operands, result):
        return block.op1(Operation.CALL_FOREIGN, operands, result, entity=entity)

    def read_count(block, source, effect):
        """Open the state file and read its 8-byte little-endian count (missing bytes read as zero)."""
        directory, effect = call(block, files_dir, (source, effect), (file, io))
        location = call1(block, concat, (call1(block, path, (directory,), string), call1(block, name, (), string)), string)
        fd, effect = call(block, open_file, (location, block.const(B32, _O_RDWR | _O_CREAT), block.const(B32, _MODE_0600), effect), (descriptor, io))
        cell = call1(block, new_cell, (block.const(B32, 8),), cell_array)
        _read, effect = call(block, pread, (fd, cell, block.const(B32, 0), block.const(B32, 8), block.const(B64, 0), effect), (B32, io))
        count = None
        for index in range(8):
            byte = block.op1(Operation.INT_ZERO_EXTEND, (call1(block, load, (cell, block.const(B32, index)), b8),), B64)
            if index:
                byte = block.op1(Operation.MUL_WRAP, (byte, block.const(B64, 1 << (8 * index))), B64)
            count = byte if count is None else block.op1(Operation.BIT_OR, (count, byte), B64)
        return fd, cell, count, effect

    def show(block, widget, count, effect):
        label = call1(block, casts["chars"], (call1(block, to_string, (count,), string),), text)
        return call1(block, set_text, (widget, label, effect), io)

    graph = GraphBuilder()
    block = graph.block(activity, io)
    owner, effect = block.params
    owner_context = call1(block, casts["context"], (owner,), context)
    fd, _cell, count, effect = read_count(block, owner_context, effect)
    effect = call1(block, close, (fd, effect), io)
    widget, effect = call(block, new_button, (owner_context, effect), (button, io))
    effect = show(block, call1(block, casts["button_text"], (widget,), text_view), count, effect)
    handler, effect = call(block, new_listener, (effect,), (listener, io))
    widget_view = call1(block, casts["button_view"], (widget,), view)
    effect = call1(block, set_listener, (widget_view, call1(block, casts["listener"], (handler,), on_click_listener), effect), io)
    effect = call1(block, set_content, (call1(block, casts["activity"], (owner,), platform_activity), widget_view, effect), io)
    block.ret(effect)
    on_create = graph.function((activity, io), (io,))

    click_graph = GraphBuilder()
    block = click_graph.block(view, io)
    clicked, effect = block.params
    clicked_context, effect = call(block, get_context, (clicked, effect), (context, io))
    fd, cell, count, effect = read_count(block, clicked_context, effect)
    count = block.op1(Operation.ADD_WRAP, (count, block.const(B64, 1)), B64)
    for index in range(8):
        part = block.op1(Operation.ROTATE_RIGHT, (count,), B64, attributes=(8 * index,)) if index else count
        block.op(Operation.CALL_FOREIGN, (cell, block.const(B32, index), block.op1(Operation.INT_TRUNCATE, (part,), b8)), (), entity=store)
    _written, effect = call(block, pwrite, (fd, cell, block.const(B32, 0), block.const(B32, 8), block.const(B64, 0), effect), (B32, io))
    effect = call1(block, fdatasync, (fd, effect), io)
    effect = call1(block, close, (fd, effect), io)
    effect = show(block, call1(block, casts["view_text"], (clicked,), text_view), count, effect)
    block.ret(effect)
    on_click = click_graph.function((view, io), (io,))
    return CounterManaged(on_create, on_click, (*types, *declarations, *graph.objects.values(), *click_graph.objects.values()))


def counter_dex_store(description: CounterActivityDescription):
    """``(reader, target object, onCreate cid, onClick cid)``: the verified canonical store of both managed callbacks."""
    from xax_compiler import StoreReader, jvm_classfile_target, object_with_refs, verify_store, write_store

    managed = counter_managed(description)
    target_object = jvm_classfile_target()
    functions = (managed.on_create, managed.on_click)
    available = {item.cid: item for item in (*managed.objects, *functions, target_object)}
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
    return reader, target_object, managed.on_create.cid, managed.on_click.cid


def _shell_classes(description: CounterActivityDescription):
    """The platform-required class shells: each forwards its callback to the XAX function and does nothing else."""
    from xax_dex import ACC_CONSTRUCTOR, ACC_FINAL
    from xax_dex_jvm import DexClassDef, DexCode, DexMethodDef

    activity, listener = description.activity_descriptor, description.listener_descriptor
    platform_activity, base = "Landroid/app/Activity;", "Ljava/lang/Object;"

    def method(owner: str, name: str, parameters: tuple[str, ...]):
        return ("method", (owner, name, "V", parameters))

    def constructor(superclass: str) -> DexMethodDef:  # invoke-direct {v0}, super.<init>; return-void
        return DexMethodDef("<init>", "V", (), ACC_PUBLIC | ACC_CONSTRUCTOR, DexCode(1, 1, 1, (0x1070, method(superclass, "<init>", ()), 0x0000, 0x000E)))

    on_create = DexMethodDef("onCreate", "V", (_BUNDLE,), ACC_PUBLIC, DexCode(2, 2, 2, (
        0x206F, method(platform_activity, "onCreate", (_BUNDLE,)), 0x0010,  # invoke-super {v0, v1}
        0x1071, method(activity, "entry", (activity,)), 0x0000,  # invoke-static {v0}
        0x000E,
    )))
    on_click = DexMethodDef("onClick", "V", (_VIEW,), ACC_PUBLIC, DexCode(2, 2, 1, (
        0x1071, method(listener, "entry", (_VIEW,)), 0x0001,  # invoke-static {v1}
        0x000E,
    )))
    return (
        DexClassDef(activity, ACC_PUBLIC | ACC_FINAL, platform_activity, (), (), (constructor(platform_activity), on_create)),
        DexClassDef(listener, ACC_PUBLIC | ACC_FINAL, base, ("Landroid/view/View$OnClickListener;",), (), (constructor(base), on_click)),
    )


def compile_counter_dex(reader, target_object: SemanticObject, on_create: bytes, on_click: bytes, description: CounterActivityDescription) -> bytes:
    """``classes.dex``: each XAX callback compiled to a JVM class, lowered to DEX, and merged into its class shell."""
    from xax_dex_jvm import merge_classes, translate_class, write_dex
    from xax_jvm import compile_jvm_bound_target

    merged = []
    for shell, function in zip(_shell_classes(description), (on_create, on_click)):
        image = compile_jvm_bound_target(reader, function, target_object)
        merged.append(merge_classes(shell, translate_class(image.class_bytes, {image.class_name: shell.descriptor[1:-1]})))
    return write_dex(merged)


def counter_dex(description: CounterActivityDescription) -> bytes:
    """The app's only code file (ADR-259)."""
    reader, target_object, on_create, on_click = counter_dex_store(description)
    return compile_counter_dex(reader, target_object, on_create, on_click, description)
