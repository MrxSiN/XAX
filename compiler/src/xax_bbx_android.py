"""Android BBX demonstration constructed as verified native and managed graphs.

The platform class shell only loads the library and forwards onCreate. The
managed graph reads Intent inputs and shows/hides a row using the native result.
No BF interpreter, foreign application source or generated Java is shipped.
"""
from dataclasses import dataclass

from xax_bbx import B8, B32, B64, MEM, READ, WRITE, construct_bbx
from xax_compiler import (
    EffectDomain, ForeignAllocatorContract, IntCompare,
    Operation, effect_type, foreign_function_symbol, heap_view_type,
    jvm_classfile_target, opaque_identity_type,
)
from xax_graph_builder import program_store
from xax_structured import Proc

PACKAGE = "org.bbc.bbxdecision"
ACTIVITY = PACKAGE + ".DecisionActivity"
DESCRIPTOR = "L" + ACTIVITY.replace(".", "/") + ";"
LIBRARY = "bbxdecision"
JNI_SYMBOL = b"Java_org_bbc_bbxdecision_DecisionActivity_evaluate"


def native_decision(record: bytes):
    """JNI (env, receiver, flag, capacity) -> 0 permit, 1 block, 2 error.

    Three independent allocation effects establish distinct initialized views.
    Returning paths release every allocation, including core errors.
    Allocation failure uses XAX's checked heap-view trap before memory access.
    """
    from xax_jni import JniReferenceKind, jni_env_pointer_type, jni_reference_type, jni_type_objects
    from xax_platform import posix_android_api

    core = construct_bbx(record, input_extent=16, output_extent=16)
    api = posix_android_api()
    domain = ("app:" + PACKAGE).encode()
    receiver = jni_reference_type(JniReferenceKind.BORROWED, ACTIVITY.encode(), loader_domain=domain)
    calloc = foreign_function_symbol(b"libc.so", b"calloc", (B64, B64, MEM),
        (api.byte_ptr_rw, api.heap_resource, MEM), allocator=ForeignAllocatorContract((0, 1), 0, 1, 16, True))
    p = Proc((("env", jni_env_pointer_type()), ("receiver", receiver), ("flag", B32), ("capacity", B32),
              ("a", MEM), ("b", MEM), ("c", MEM)))
    p.if_(p.any_of(p.cmp(IntCompare.UGT, p["flag"], 255), p.cmp(IntCompare.UGT, p["capacity"], 16)),
          lambda q: q.ret(q.const(2), q["a"], q["b"], q["c"]))
    views, free = {}, {}
    for name, memory, extent in (("i", "a", 16), ("o", "b", 16), ("t", "c", 65536)):
        view = heap_view_type(extent)
        raw, owner, effect = p.op(Operation.CALL_FOREIGN, (p.const(extent, B64), p.const(1, B64), p.drop(memory)),
                                (api.byte_ptr_rw, api.heap_resource, MEM), entity=calloc)
        # shortcut: OOM traps; add a recoverable path when XAX supports nullable view handoff.
        ptr, owner, effect = p.op(Operation.HEAP_VIEW, (raw, owner, effect),
                                  (WRITE, view, MEM), attributes=(extent, 1))
        views[name], free[name] = view, api.free_heap_view(view)
        for suffix, value, typ in (("p", ptr, WRITE), ("v", owner, view), ("m", effect, MEM)):
            p.let(name + suffix, typ, value)

    def release(q, result):
        effects = [q.op1(Operation.CALL_FOREIGN, (q[name + "p"], q[name + "v"], q[name + "m"]), MEM,
                         entity=free[name]) for name in views]
        q.ret(result, *effects)

    p["im"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["ip"], p.const(0), p.op1(Operation.INT_TRUNCATE, (p["flag"],), B8), p["im"]),
                     MEM, attributes=(1, 1))
    inp = p.op1(Operation.POINTER_CAST, (p["ip"],), READ)
    result, _ip, iv, im, _op, ov, om, _tp, tv, tm = p.op(Operation.CALL_DIRECT,
        (inp, p["iv"], p["im"], p["op"], p["ov"], p["om"], p["tp"], p["tv"], p["tm"], p.const(1), p["capacity"]),
        (B64, READ, views["i"], MEM, WRITE, views["o"], MEM, WRITE, views["t"], MEM), entity=core.function)
    for name, value in zip(("iv", "im", "ov", "om", "tv", "tm"), (iv, im, ov, om, tv, tm)):
        p[name] = value
    p.let("mode", B32, p.const(2))
    # Exactly one successful output byte is the sample module's application contract.
    def succeeded(q):
        byte, q["om"] = q.op(Operation.CHECKED_LOAD_BITS_LE, (q["op"], q.const(0), q["om"]), (B8, MEM), attributes=(1, 1))
        q.if_(q.cmp(IntCompare.EQ, byte, 1, B8), lambda r: r.__setitem__("mode", r.const(0)),
              lambda r: r.if_(r.cmp(IntCompare.EQ, byte, 0, B8), lambda s: s.__setitem__("mode", s.const(1))))
    p.if_(p.cmp(IntCompare.EQ, result, 1 << 32, B64), succeeded)
    release(p, p["mode"])
    function = p.function((B32, MEM, MEM, MEM))
    refs = jni_type_objects(((JniReferenceKind.BORROWED, ACTIVITY.encode(), domain),))
    reader = program_store(function, core.target, (*core.reader.objects(), *p.graph.objects.values(), *api.types, *refs, calloc, *free.values()))
    return reader, function, core.target


def managed_activity():
    """Canonical XAX UI behavior; platform callbacks are supplied by a tiny shell."""
    from xax_jvm import REFERENCE_PREFIX, jvm_reference_type, jvm_virtual

    types = []
    def ref(descriptor):
        raw = descriptor.encode()
        value = jvm_reference_type(raw)
        types.extend((opaque_identity_type(REFERENCE_PREFIX + raw), value))
        return value
    activity, platform, context, intent, layout, text, view, string, chars = map(ref, (
        DESCRIPTOR, "Landroid/app/Activity;", "Landroid/content/Context;", "Landroid/content/Intent;",
        "Landroid/widget/LinearLayout;", "Landroid/widget/TextView;", "Landroid/view/View;",
        "Ljava/lang/String;", "Ljava/lang/CharSequence;"))
    io = effect_type(EffectDomain.IO, 0)
    declarations = []
    def foreign(abi, owner, name, inputs, outputs):
        decl = foreign_function_symbol(owner, name, inputs, outputs, abi=abi)
        declarations.append(decl)
        return decl
    def virtual(owner, name, inputs, outputs):
        decl = jvm_virtual(owner, name, inputs, outputs)
        declarations.append(decl)
        return decl
    def cast(source, target, descriptor):
        return foreign(b"jvm-checkcast", descriptor[1:-1].encode(), b"checkcast", (source,), (target,))
    def literal(value):
        return foreign(b"jvm-ldc", b"java/lang/String", value.encode(), (), (string,))
    get_intent = virtual(b"android/app/Activity", b"getIntent()Landroid/content/Intent;", (platform, io), (intent, io))
    extra = virtual(b"android/content/Intent", b"getIntExtra(Ljava/lang/String;I)I", (intent, string, B32, io), (B32, io))
    evaluate = virtual(ACTIVITY.replace(".", "/").encode(), b"evaluate(II)I", (activity, B32, B32, io), (B32, io))
    new_layout = foreign(b"jvm-new", b"android/widget/LinearLayout", b"<init>(Landroid/content/Context;)V", (context, io), (layout, io))
    new_text = foreign(b"jvm-new", b"android/widget/TextView", b"<init>(Landroid/content/Context;)V", (context, io), (text, io))
    orientation = virtual(b"android/widget/LinearLayout", b"setOrientation(I)V", (layout, B32, io), (io,))
    gravity = virtual(b"android/widget/LinearLayout", b"setGravity(I)V", (layout, B32, io), (io,))
    padding = virtual(b"android/view/View", b"setPadding(IIII)V", (view, B32, B32, B32, B32, io), (io,))
    set_text = virtual(b"android/widget/TextView", b"setText(Ljava/lang/CharSequence;)V", (text, chars, io), (io,))
    visible = virtual(b"android/view/View", b"setVisibility(I)V", (view, B32, io), (io,))
    add = virtual(b"android/widget/LinearLayout", b"addView(Landroid/view/View;)V", (layout, view, io), (io,))
    content = virtual(b"android/app/Activity", b"setContentView(Landroid/view/View;)V", (platform, view, io), (io,))
    as_platform = cast(activity, platform, "Landroid/app/Activity;")
    as_context = cast(activity, context, "Landroid/content/Context;")
    layout_view = cast(layout, view, "Landroid/view/View;")
    text_view = cast(text, view, "Landroid/view/View;")
    as_chars = cast(string, chars, "Ljava/lang/CharSequence;")
    flag_key, capacity_key = literal("flag"), literal("capacity")
    permit, block, error, sample = map(literal, (
        "PERMIT: Brainfuck returned 01", "BLOCK: Brainfuck returned 00",
        "ERROR: decision rejected; row hidden", "Sample row: permitted by Brainfuck"))
    p = Proc((("owner", activity), ("io", io)))
    def call(decl, operands, outputs):
        return p.op(Operation.CALL_FOREIGN, operands, outputs, entity=decl)
    def one(decl, operands, typ):
        return p.op1(Operation.CALL_FOREIGN, operands, typ, entity=decl)
    p.let("platform", platform, one(as_platform, (p["owner"],), platform))
    p.let("context", context, one(as_context, (p["owner"],), context))
    got_intent, p["io"] = call(get_intent, (p["platform"], p["io"]), (intent, io))
    flag, p["io"] = call(extra, (got_intent, one(flag_key, (), string), p.const(0), p["io"]), (B32, io))
    capacity, p["io"] = call(extra, (got_intent, one(capacity_key, (), string), p.const(1), p["io"]), (B32, io))
    mode, p["io"] = call(evaluate, (p["owner"], flag, capacity, p["io"]), (B32, io))
    p.let("mode", B32, mode)
    panel, p["io"] = call(new_layout, (p["context"], p["io"]), (layout, io))
    p.let("panel", layout, panel)
    p["io"] = one(orientation, (panel, p.const(1), p["io"]), io)
    p["io"] = one(gravity, (panel, p.const(17), p["io"]), io)
    p["io"] = one(padding, (one(layout_view, (panel,), view), *(p.const(48) for _ in range(4)), p["io"]), io)
    label, p["io"] = call(new_text, (p["context"], p["io"]), (text, io))
    p.let("label", text, label)
    row, p["io"] = call(new_text, (p["context"], p["io"]), (text, io))
    p.let("row", text, row)
    def label_and_visibility(q, message, visibility):
        message = q.op1(Operation.CALL_FOREIGN, (), string, entity=message)
        message = q.op1(Operation.CALL_FOREIGN, (message,), chars, entity=as_chars)
        q["io"] = q.op1(Operation.CALL_FOREIGN, (q["label"], message, q["io"]), io, entity=set_text)
        row_view = q.op1(Operation.CALL_FOREIGN, (q["row"],), view, entity=text_view)
        q["io"] = q.op1(Operation.CALL_FOREIGN, (row_view, q.const(visibility), q["io"]), io, entity=visible)
    p.if_(p.cmp(IntCompare.EQ, p["mode"], 0), lambda q: label_and_visibility(q, permit, 0),
          lambda q: q.if_(q.cmp(IntCompare.EQ, q["mode"], 1), lambda r: label_and_visibility(r, block, 8),
                          lambda r: label_and_visibility(r, error, 8)))
    p["io"] = one(set_text, (p["row"], one(as_chars, (one(sample, (), string),), chars), p["io"]), io)
    for name in ("label", "row"):
        p["io"] = one(add, (p["panel"], one(text_view, (p[name],), view), p["io"]), io)
    p["io"] = one(content, (p["platform"], one(layout_view, (p["panel"],), view), p["io"]), io)
    p.ret(p["io"])
    function = p.function((io,))
    target = jvm_classfile_target()
    reader = program_store(function, target, (*p.graph.objects.values(), *types, *declarations))
    return reader, function, target


def activity_dex(reader, function, target):
    from xax_dex import ACC_CONSTRUCTOR, ACC_NATIVE, ACC_PUBLIC, ACC_STATIC
    from xax_dex_jvm import DexClassDef, DexCode, DexMethodDef, merge_classes, translate_class, write_dex
    from xax_jvm import compile_jvm_bound_target

    def method(owner, name, parameters):
        return ("method", (owner, name, "V", parameters))
    base = "Landroid/app/Activity;"
    shell = DexClassDef(DESCRIPTOR, ACC_PUBLIC, base, methods=(
        DexMethodDef("<init>", "V", (), ACC_PUBLIC | ACC_CONSTRUCTOR, DexCode(1, 1, 1,
            (0x1070, method(base, "<init>", ()), 0, 0x000e))),
        DexMethodDef("<clinit>", "V", (), ACC_STATIC | ACC_CONSTRUCTOR, DexCode(1, 0, 1,
            (0x001a, ("string", LIBRARY), 0x1071, method("Ljava/lang/System;", "loadLibrary", ("Ljava/lang/String;",)), 0, 0x000e))),
        DexMethodDef("onCreate", "V", ("Landroid/os/Bundle;",), ACC_PUBLIC, DexCode(2, 2, 2,
            (0x206f, method(base, "onCreate", ("Landroid/os/Bundle;",)), 0x0010,
             0x1071, method(DESCRIPTOR, "entry", (DESCRIPTOR,)), 0, 0x000e))),
        DexMethodDef("evaluate", "I", ("I", "I"), ACC_PUBLIC | ACC_NATIVE, None),
    ))
    image = compile_jvm_bound_target(reader, function.cid, target)
    translated = translate_class(image.class_bytes, {image.class_name: DESCRIPTOR[1:-1]})
    return write_dex((merge_classes(shell, translated),))


@dataclass(frozen=True)
class BBXAndroidApp:
    native_reader: object
    managed_reader: object
    library: bytes
    dex: bytes
    unsigned_apk: bytes


def build_bbx_app(record: bytes) -> BBXAndroidApp:
    from xax_android import AndroidExport, compile_android_shared
    from xax_apk import build_unsigned_apk
    from xax_manifest import AndroidManifestSpec, android_manifest_semantics, emit_binary_manifest_from_semantics

    reader, function, target = native_decision(record)
    library = compile_android_shared(reader, (AndroidExport(JNI_SYMBOL, function.cid),), target_object=target,
                                     soname=("lib" + LIBRARY + ".so").encode()).data
    managed, callback, managed_target = managed_activity()
    dex = activity_dex(managed, callback, managed_target)
    manifest = emit_binary_manifest_from_semantics(android_manifest_semantics(AndroidManifestSpec(
        package_name=PACKAGE, activity_class=ACTIVITY, min_sdk=28, target_sdk=35, version_code=1, launcher=True)))
    unsigned = build_unsigned_apk(manifest, dex, native_libraries={"lib" + LIBRARY + ".so": library})
    return BBXAndroidApp(reader, managed, library, dex, unsigned)
