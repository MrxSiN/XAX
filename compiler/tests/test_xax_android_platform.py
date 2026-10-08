"""Android platform declarations, NDK/POSIX ownership contracts and SDK capability rules (ADR-203, ADR-204)."""
from __future__ import annotations

import io
import zipfile

import pytest

from benchmarks.bench_android_managed import ACTIVITY, APP, BOOT, _export
from xax_android_managed import AndroidManagedClass, AndroidManagedMethod, android_managed_class_semantics
from xax_android_platform import (
    AAUDIO_INPUT,
    CALLBACK_ABSTRACT_METHODS,
    CAPABILITIES,
    aaudio_api,
    media_codec_api,
    native_window_api,
    platform_usage_violations,
)
from xax_android_sdk import parse_jvm_method_descriptor
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import (
    Kind,
    Operation,
    StoreReader,
    XaxError,
    android_arm64_shared_general_target,
    bits_type,
    object_with_refs,
    target,
    verify_store,
    write_store,
)
from xax_graph_builder import GraphBuilder
from xax_jni import JniReferenceKind, jni_type_objects, jni_typed_method_id_type
from xax_manifest import (
    AndroidDeclaredComponent,
    AndroidManifestSpec,
    AndroidPlatformDeclarations,
    AndroidUsesFeature,
    AndroidUsesPermission,
    android_manifest_semantics,
    android_platform_declarations_semantics,
    decode_android_platform_declarations,
    emit_binary_manifest,
    emit_binary_manifest_from_semantics,
    inspect_binary_manifest,
    platform_declaration_violations,
)
from xax_platform import posix_android_api, posix_async_api

P = "android.permission."
SPEC = AndroidManifestSpec("xax.managed", "xax.managed.MainActivity", min_sdk=28, target_sdk=35)


def _decl(*permissions, features=(), components=()):
    return AndroidPlatformDeclarations(tuple(AndroidUsesPermission(*item) if isinstance(item, tuple) else AndroidUsesPermission(item) for item in permissions),
                                       tuple(features), tuple(components))


# --- manifest declarations -------------------------------------------------------------------


def test_declarations_are_canonical_and_round_trip():
    decl = _decl(P + "INTERNET", (P + "BLUETOOTH", 30), (P + "BLUETOOTH_SCAN", 0, True),
                 features=(AndroidUsesFeature("android.hardware.bluetooth", False),),
                 components=(AndroidDeclaredComponent("receiver", "xax.managed.Boot", True, (), ("android.intent.action.BOOT_COMPLETED",)),))
    reordered = AndroidPlatformDeclarations(tuple(reversed(decl.permissions)), decl.features, decl.components)
    carrier = android_platform_declarations_semantics(decl)
    assert carrier.cid == android_platform_declarations_semantics(reordered).cid
    assert decode_android_platform_declarations(carrier) == decl
    for malformed in (target(b"wrong"), target(carrier.body[1:] + b"\x00")):
        with pytest.raises(XaxError):
            decode_android_platform_declarations(malformed)


@pytest.mark.parametrize("build", [
    lambda: AndroidUsesPermission("bad/name"),
    lambda: AndroidUsesPermission(P + "X", -1),
    lambda: AndroidDeclaredComponent("activity", "a.B"),
    lambda: AndroidDeclaredComponent("service", "a.B", foreground_types=("specialUse",)),
    lambda: AndroidDeclaredComponent("receiver", "a.B", foreground_types=("dataSync",)),
    lambda: _decl(P + "INTERNET", (P + "INTERNET", 30)),
])
def test_declaration_fields_reject(build):
    with pytest.raises(ValueError):
        build()


def test_manifest_without_declarations_keeps_its_bytes():
    manifest = android_manifest_semantics(SPEC)
    assert emit_binary_manifest_from_semantics(manifest) == emit_binary_manifest(SPEC)
    assert emit_binary_manifest(SPEC, declarations=AndroidPlatformDeclarations()) == emit_binary_manifest(SPEC)


def test_declarations_emit_exact_binary_xml():
    decl = _decl(P + "FOREGROUND_SERVICE", P + "FOREGROUND_SERVICE_CONNECTED_DEVICE", P + "BLUETOOTH_CONNECT",
                 (P + "BLUETOOTH_SCAN", 0, True), (P + "BLUETOOTH", 30),
                 features=(AndroidUsesFeature("android.hardware.bluetooth"),),
                 components=(AndroidDeclaredComponent("service", "xax.managed.Link", False, ("connectedDevice", "dataSync")),))
    view = inspect_binary_manifest(emit_binary_manifest(SPEC, declarations=decl))
    elements = {(item.name, next((a.value for a in item.attributes if a.name == "name"), None)): item for item in view.elements}
    assert 0x01010599 in view.resource_map and 0x01010644 in view.resource_map and 0x0101028E in view.resource_map
    service = elements[("service", "xax.managed.Link")]
    assert {a.name: a.value for a in service.attributes}["foregroundServiceType"] == 0x11
    assert {a.name: a.value for a in elements[("uses-permission", P + "BLUETOOTH_SCAN")].attributes}["usesPermissionFlags"] == 0x10000
    assert {a.name: a.value for a in elements[("uses-permission", P + "BLUETOOTH")].attributes}["maxSdkVersion"] == 30
    assert {a.name: a.value for a in elements[("uses-feature", "android.hardware.bluetooth")].attributes}["required"] is True
    assert service.depth == 2 and elements[("uses-permission", P + "BLUETOOTH_SCAN")].depth == 1
    # Resource-mapped attribute names occupy the first string slots in ID order.
    assert list(view.resource_map) == sorted(view.resource_map)


def test_foreground_service_rules():
    service = AndroidDeclaredComponent("service", "xax.managed.Rec", False, ("microphone",))
    missing = platform_declaration_violations(SPEC, _decl(components=(service,)))
    assert any("FOREGROUND_SERVICE" in item and "MICROPHONE" not in item for item in missing)
    assert any("FOREGROUND_SERVICE_MICROPHONE" in item for item in missing)
    assert any("RECORD_AUDIO" in item for item in missing)
    complete = _decl(P + "FOREGROUND_SERVICE", P + "FOREGROUND_SERVICE_MICROPHONE", P + "RECORD_AUDIO", components=(service,))
    assert platform_declaration_violations(SPEC, complete) == ()
    # Before targetSdk 34 the per-type permissions do not exist.
    old = AndroidManifestSpec("xax.managed", "xax.managed.MainActivity", min_sdk=28, target_sdk=33)
    assert platform_declaration_violations(old, _decl(P + "FOREGROUND_SERVICE", components=(service,))) == ()


def test_boot_receiver_needs_permission():
    boot = AndroidDeclaredComponent("receiver", "xax.managed.Boot", False, (), ("android.intent.action.BOOT_COMPLETED",))
    assert platform_declaration_violations(SPEC, _decl(components=(boot,)))
    assert platform_declaration_violations(SPEC, _decl(P + "RECEIVE_BOOT_COMPLETED", components=(boot,))) == ()


# --- NDK and POSIX ownership --------------------------------------------------------------------


def _store(parameters, body, results, extra=()):
    """Verify one function built by ``body(block) -> returned values``."""
    graph = GraphBuilder()
    block = graph.block(*parameters)
    block.ret(*body(block))
    function = graph.function(tuple(parameters), tuple(results))
    module = object_with_refs(Kind.MODULE, [function])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    from xax_android_platform import ndk_type_objects
    available = {item.cid: item for item in (*ndk_type_objects(), *graph.objects.values(), *extra, *parameters, *results, function, module, root)}
    reachable, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    return StoreReader(write_store(root.cid, tuple(reachable.values())))


def _call(block, symbol, operands, results):
    out = block.op(Operation.CALL_FOREIGN, operands, results, entity=symbol)
    return out if isinstance(out, tuple) else (out,)


def _codec_store(deletes: int):
    api = media_codec_api()
    from xax_compiler import effect_type, EffectDomain, Permission, pointer_type
    device = effect_type(EffectDomain.DEVICE, 0)
    mime = pointer_type(bits_type(8), Permission.READ, 1, space=2)

    def body(block):
        name, dev = block.params
        codec, token, dev = _call(block, api.create_decoder_by_type, (name, dev), (api.codec, api.codec_token, device))
        _status, token, dev = _call(block, api.start, (codec, token, dev), (bits_type(32), api.codec_token, device))
        for _ in range(deletes):
            _status, dev = _call(block, api.delete, (codec, token, dev), (bits_type(32), device))
        return (dev,)

    return _store((mime, device), body, (device,), (*api.symbols, api.codec, api.codec_token, api.format, api.format_token))


def test_codec_released_once_verifies():
    verify_store(_codec_store(1))


@pytest.mark.parametrize("deletes,code", [(0, "XAX.RESOURCE.DROP"), (2, "XAX.RESOURCE")])
def test_codec_leak_and_double_release_reject(deletes, code):
    with pytest.raises(XaxError) as caught:
        verify_store(_codec_store(deletes))
    assert caught.value.diagnostic.code.startswith(code)


def test_aaudio_direction_is_typed():
    output, capture = aaudio_api(), aaudio_api(AAUDIO_INPUT)
    assert output.stream_token.cid != capture.stream_token.cid
    assert output.transfer.cid != capture.transfer.cid
    assert output.close.cid != capture.close.cid
    # The input stream's token cannot satisfy the output write's contract.
    from xax_compiler import effect_type, EffectDomain, memory_effect_type, Permission, pointer_type
    device, memory = effect_type(EffectDomain.DEVICE, 0), memory_effect_type()
    buffer = pointer_type(bits_type(8), Permission.READ, 1, space=2)

    def body(block):
        stream, token, data, dev, mem = block.params
        _n, token, dev, mem = _call(block, output.transfer, (stream, data, block.const(bits_type(32), 1), block.const(bits_type(64), 0), token, dev, mem),
                                    (bits_type(32), output.stream_token, device, memory))
        _s, dev = _call(block, capture.close, (stream, token, dev), (bits_type(32), device))
        return (dev, mem)

    store = _store((capture.stream, capture.stream_token, buffer, device, memory), body, (device, memory),
                   (*output.symbols, *capture.symbols, output.stream_token))
    with pytest.raises(XaxError):
        verify_store(store)


def test_window_is_borrowed_by_geometry_and_released():
    api = native_window_api()
    from xax_compiler import effect_type, EffectDomain
    device = effect_type(EffectDomain.DEVICE, 0)

    def body(block):
        window, token, dev = block.params
        b32 = bits_type(32)
        _r, token, dev = _call(block, api.set_buffers_geometry, (window, block.const(b32, 640), block.const(b32, 480), block.const(b32, 1), token, dev), (b32, api.token, device))
        (dev,) = _call(block, api.release, (window, token, dev), (device,))
        return (dev,)

    verify_store(_store((api.window, api.token, device), body, (device,), api.symbols))


@pytest.mark.parametrize("closes", [0, 1])
def test_owned_socket_must_close_once(closes):
    base = posix_android_api()
    api = posix_async_api(base)

    def body(block):
        (net,) = block.params
        b32 = bits_type(32)
        fd, owner, net = _call(block, api.socket, (block.const(b32, 2), block.const(b32, 1 | 0o4000), block.const(b32, 0), net), (b32, api.descriptor, base.network_effect))
        for _ in range(closes):
            _r, net = _call(block, api.close_socket, (fd, owner, net), (b32, base.network_effect))
        return (net,)

    store = _store((base.network_effect,), body, (base.network_effect,), (*api.symbols, api.descriptor))
    if closes:
        verify_store(store)
    else:
        with pytest.raises(XaxError):
            verify_store(store)


def test_timerfd_deadline_and_close_verify():
    base = posix_android_api()
    api = posix_async_api(base)

    def body(block):
        time, fs = block.params
        b32 = bits_type(32)
        fd, owner, time = _call(block, api.timerfd_create, (block.const(b32, 1), block.const(b32, 0o4000), time), (b32, api.descriptor, base.time_effect))
        _r, fs = _call(block, api.close, (fd, owner, fs), (b32, base.filesystem_effect))
        return (time, fs)

    verify_store(_store((base.time_effect, base.filesystem_effect), body, (base.time_effect, base.filesystem_effect), (*api.symbols, api.descriptor)))


# --- SDK capability table -----------------------------------------------------------------------


def test_capability_members_are_exact_descriptors_and_unique():
    seen = set()
    for capability in CAPABILITIES:
        for member in capability.members:
            parse_jvm_method_descriptor(member.descriptor)
            key = (member.owner, member.name, member.descriptor)
            assert key not in seen, key
            seen.add(key)
        for acquire, release in capability.releases:
            assert acquire in capability.members
            parse_jvm_method_descriptor(release.descriptor)
    for callbacks in CALLBACK_ABSTRACT_METHODS.values():
        for _name, descriptor in callbacks:
            parse_jvm_method_descriptor(descriptor)


def _resolver(members):
    from xax_compiler import opaque_identity_type  # noqa: F401 - reachable identity objects
    objects = {}
    for owner, name, descriptor in members:
        pointer = jni_typed_method_id_type(owner, name, descriptor, loader_domain=BOOT)
        objects[pointer.cid] = pointer
        pending = list(pointer.references)
        while pending:
            cid = pending.pop()
            if cid in objects:
                continue
            for candidate in _identity_objects(owner, name, descriptor):
                if candidate.cid == cid:
                    objects[cid] = candidate
                    pending.extend(candidate.references)
    return objects.__getitem__


def _identity_objects(owner, name, descriptor):
    from xax_jni import _typed_member_identity
    from xax_compiler import opaque_identity_type
    return (opaque_identity_type(_typed_member_identity(b"android.jni.jmethodID/v1/", owner, name, descriptor, False, BOOT)),)


AUDIO_RECORD = ("android/media/AudioRecord", "<init>", "(IIIII)V")
AUDIO_RELEASE = ("android/media/AudioRecord", "release", "()V")


def _violations(members, declarations=None, classes=(ACTIVITY,), spec=SPEC):
    roots = tuple(jni_typed_method_id_type(*item, loader_domain=BOOT).cid for item in members)
    return platform_usage_violations(spec, declarations, {item.class_descriptor: item for item in classes}, roots, _resolver(members))


def test_reachable_member_requires_its_permission_and_release():
    assert any("RECORD_AUDIO" in item for item in _violations((AUDIO_RECORD, AUDIO_RELEASE)))
    assert _violations((AUDIO_RECORD, AUDIO_RELEASE), _decl(P + "RECORD_AUDIO")) == []
    assert any("never reachable" in item for item in _violations((AUDIO_RECORD,), _decl(P + "RECORD_AUDIO")))


def test_bluetooth_rules_follow_target_and_device_levels():
    bonded = ("android/bluetooth/BluetoothAdapter", "getBondedDevices", "()Ljava/util/Set;")
    problems = _violations((bonded,))
    assert any("BLUETOOTH_CONNECT" in item for item in problems) and any(item.endswith("needs android.permission.BLUETOOTH") for item in problems)
    assert _violations((bonded,), _decl(P + "BLUETOOTH_CONNECT", (P + "BLUETOOTH", 30))) == []
    # A legacy permission capped below the levels that still need it is reported.
    assert any("does not cover" in item for item in _violations((bonded,), _decl(P + "BLUETOOTH_CONNECT", (P + "BLUETOOTH", 29))))
    modern = AndroidManifestSpec("xax.managed", "xax.managed.MainActivity", min_sdk=31, target_sdk=35)
    assert _violations((bonded,), _decl(P + "BLUETOOTH_CONNECT"), spec=modern) == []


def test_min_api_gate():
    hotspot = ("android/net/wifi/WifiManager$LocalOnlyHotspotReservation", "close", "()V")
    assert any("needs API 30" in item for item in _violations((hotspot,), _decl(P + "CHANGE_WIFI_STATE", P + "NEARBY_WIFI_DEVICES", (P + "ACCESS_FINE_LOCATION", 32))))


def test_ndk_input_audio_requires_record_audio():
    capture = aaudio_api(AAUDIO_INPUT)
    objects = {item.cid: item for item in capture.symbols}

    def resolve(cid):
        return objects.get(cid) or _all_types(capture)[cid]

    roots = (capture.transfer.cid,)
    problems = platform_usage_violations(SPEC, None, {ACTIVITY.class_descriptor: ACTIVITY}, roots, resolve)
    assert any("RECORD_AUDIO" in item for item in problems)
    output = aaudio_api()
    out_objects = {item.cid: item for item in output.symbols}
    assert platform_usage_violations(SPEC, None, {ACTIVITY.class_descriptor: ACTIVITY}, (output.transfer.cid,),
                                     lambda cid: out_objects.get(cid) or _all_types(output)[cid]) == []


def _all_types(api):
    found, pending = {}, [ref for symbol in api.symbols for ref in symbol.references]
    candidates = {}
    from xax_compiler import EffectDomain, Permission, effect_type, memory_effect_type, opaque_identity_type, pointer_type
    for item in (api.builder, api.builder_token, api.stream, api.stream_token, bits_type(8), bits_type(32), bits_type(64),
                 effect_type(EffectDomain.DEVICE, 0), memory_effect_type(),
                 pointer_type(bits_type(8), Permission.READ, 1, space=2), pointer_type(bits_type(8), Permission.READ_WRITE, 1, space=2),
                 opaque_identity_type(b"android.ndk.AAudioStreamBuilder"), opaque_identity_type(b"android.ndk.AAudioStream")):
        candidates[item.cid] = item
    while pending:
        cid = pending.pop()
        if cid in found or cid not in candidates:
            continue
        found[cid] = candidates[cid]
        pending.extend(found[cid].references)
    return found


def test_callback_completeness_and_super_calls():
    partial = AndroidManagedClass("Lxax/t/S;", "Ljava/lang/Object;", ("Landroid/view/SurfaceHolder$Callback;",), (
        AndroidManagedMethod("surfaceCreated", "(Landroid/view/SurfaceHolder;)V"),
        AndroidManagedMethod("surfaceDestroyed", "(Landroid/view/SurfaceHolder;)V"),
    ))
    assert any("surfaceChanged" in item for item in _violations((), classes=(ACTIVITY, partial)))
    no_super = AndroidManagedClass("Lxax/t/A;", "Landroid/app/Activity;", (), (AndroidManagedMethod("onResume", "()V", "protected"),))
    assert any("must call super" in item for item in _violations((), classes=(no_super,)))
    assert _violations((), classes=(ACTIVITY,)) == []


# --- managed APK build -------------------------------------------------------------------------


RECEIVER = AndroidManagedClass("Lxax/managed/BootReceiver;", "Landroid/content/BroadcastReceiver;", (), (
    AndroidManagedMethod("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"),
))


def _managed_apk(declarations, classes=(ACTIVITY, RECEIVER)):
    target_object = android_arm64_shared_general_target()
    manifest = android_manifest_semantics(SPEC)
    carriers = tuple(android_managed_class_semantics(item) for item in classes)
    functions, exports, objects = [], [], []
    for owner in classes:
        for method in owner.methods:
            function, export, graph = _export(owner, method)
            functions.append(function)
            exports.append(export)
            objects.extend(graph.objects.values())
    extra = (android_platform_declarations_semantics(declarations),) if declarations is not None else ()
    module = object_with_refs(Kind.MODULE, (*functions, *carriers, manifest, *exports, *extra))
    app = package(b"android-platform-fixture", (module,), build_entries=((b"apk", functions[0]),))
    profile, policy = build_profile(), trust_policy()
    request = build_request(app, b"apk", target_object, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    references = jni_type_objects(tuple(
        (JniReferenceKind.BORROWED, name.encode(), APP if name.startswith("xax.") else BOOT)
        for name in ("xax.managed.MainActivity", "xax.managed.BootReceiver", "android.os.Bundle", "android.view.KeyEvent",
                     "android.content.Context", "android.content.Intent")
    ))
    everything = (*references, *objects, *functions, *exports, *carriers, manifest, *extra, module, app, target_object, profile, policy, request)
    resolution = resolve_packages(request, everything, policy, b"android-platform-resolver-v1")
    return build(snapshot_store(resolution, everything), request.cid).artifact


BOOT_DECL = _decl(P + "RECEIVE_BOOT_COMPLETED", components=(
    AndroidDeclaredComponent("receiver", "xax.managed.BootReceiver", True, (), ("android.intent.action.BOOT_COMPLETED",)),))


def test_managed_apk_registers_declared_receiver_deterministically():
    apk = _managed_apk(BOOT_DECL)
    assert apk == _managed_apk(BOOT_DECL)
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:
        view = inspect_binary_manifest(archive.read("AndroidManifest.xml"))
    names = [(item.name, next((a.value for a in item.attributes if a.name == "name"), None)) for item in view.elements]
    assert ("receiver", "xax.managed.BootReceiver") in names
    assert ("uses-permission", P + "RECEIVE_BOOT_COMPLETED") in names
    assert ("action", "android.intent.action.BOOT_COMPLETED") in names


@pytest.mark.parametrize("declarations", [
    _decl(components=(AndroidDeclaredComponent("receiver", "xax.managed.BootReceiver", True, (), ("android.intent.action.BOOT_COMPLETED",)),)),
    _decl(components=(AndroidDeclaredComponent("service", "xax.managed.BootReceiver"),)),  # not a Service subclass
    _decl(components=(AndroidDeclaredComponent("receiver", "xax.managed.Missing"),)),
])
def test_managed_apk_rejects_platform_rule_violations(declarations):
    with pytest.raises(XaxError) as caught:
        _managed_apk(declarations)
    assert caught.value.diagnostic.rule in ("ANDROID-PLATFORM-RULES", "ANDROID-DECLARATIONS-RULES")


def test_ndk_contracts_lower_to_exact_shared_library_imports():
    from benchmarks.bench_android_arm64 import _reader
    from xax_android import AndroidExport, compile_android_shared, inspect_android_elf

    store = _codec_store(1)
    objects = list(store.objects())
    function = next(item for item in objects if item.kind == Kind.FUNCTION)
    target_object = android_arm64_shared_general_target()
    reader = _reader((function,), objects, target_object)
    verify_store(reader)
    first = compile_android_shared(reader, (AndroidExport(b"codec_probe", function.cid),), target_object=target_object)
    assert first.data == compile_android_shared(reader, (AndroidExport(b"codec_probe", function.cid),), target_object=target_object).data
    view = inspect_android_elf(first.data)
    assert view.needed == (b"libmediandk.so",)
    assert set(view.imports) == {b"AMediaCodec_createDecoderByType", b"AMediaCodec_start", b"AMediaCodec_delete"}
