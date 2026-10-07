"""General declarative Surface Activity: canonical, fail-closed and reproducible."""
import io
import zipfile

import pytest

from xax_android_components import android_surface_activity_semantics, decode_android_surface_activity, lower_android_surface_activity
from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import Block, Kind, Terminator, XaxError, android_arm64_shared_target, function, graph_fragment, object_with_refs, target
from xax_dex import emit_dex039_bridge, inspect_dex
from xax_manifest import AndroidManifestSpec, android_manifest_semantics


def fixture(*, activity="fixture.surface.Main", min_sdk=28, extra=(), nonempty_selector=False):
    surface = android_surface_activity_semantics(class_descriptor="Lfixture/surface/Main;", content_description="Projection unavailable")
    manifest = android_manifest_semantics(AndroidManifestSpec("fixture.surface", activity, min_sdk=min_sdk))
    graph = graph_fragment((Block((), (), Terminator.trap(b"")),)) if nonempty_selector else graph_fragment((Block((), (), Terminator.return_(())),))
    selector = function(graph, (), ())
    module = object_with_refs(Kind.MODULE, (surface, manifest, selector, *extra))
    pkg = package(b"surface", (module,), build_entries=((b"apk", selector),))
    native_target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(pkg, b"apk", native_target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (surface, manifest, graph, selector, module, pkg, native_target, profile, policy, request, *extra)
    resolution = resolve_packages(request, objects, policy, b"surface-test-v1")
    return snapshot_store(resolution, objects), request


def test_surface_is_canonical_and_lowering_is_exact():
    kwargs = dict(class_descriptor="Lfixture/surface/Main;", content_description="Projection unavailable")
    left, right = android_surface_activity_semantics(**kwargs), android_surface_activity_semantics(**kwargs)
    assert left.cid == right.cid
    assert decode_android_surface_activity(left) == tuple(kwargs.values())
    spec = lower_android_surface_activity(left)
    assert not spec.native_methods and spec.native_library is None
    method, = spec.assembled_methods
    assert [i.mnemonic for i in method.instructions] == ["invoke-super", "new-instance", "invoke-direct", "const-string", "invoke-virtual", "invoke-virtual", "return-void"]
    assert sum(i.mnemonic == "new-instance" for i in method.instructions) == 1
    assert emit_dex039_bridge(spec) == emit_dex039_bridge(lower_android_surface_activity(right))
    view = inspect_dex(emit_dex039_bridge(spec))
    assert "Landroid/view/SurfaceView;" in view.strings
    assert "Projection unavailable" in view.strings


@pytest.mark.parametrize("descriptor,description", [("bad", "x"), ("[I", "x"), ("Lfoo.Bar;", "x"), ("Lfoo/Bar;", ""), ("Lfoo/Bar;", "a\x00b")])
def test_surface_invalid_fields_reject(descriptor, description):
    with pytest.raises(ValueError):
        android_surface_activity_semantics(class_descriptor=descriptor, content_description=description)


def test_surface_decoder_rejects_wrong_and_trailing_carriers():
    from xax_compiler import Cursor
    obj = android_surface_activity_semantics(class_descriptor="Lfixture/surface/Main;", content_description="x")
    identity = Cursor(obj.body, obj.cid.hex()).byte_string()
    for malformed in (target(b"wrong"), target(identity + b"\x00"), target(identity[:-1] + b"\xff")):
        with pytest.raises(XaxError):
            decode_android_surface_activity(malformed)


def test_surface_package_is_deterministic_and_has_no_native_or_extra_dex():
    reader, request = fixture()
    first, second = build(reader, request.cid), build(reader, request.cid)
    assert first.artifact == second.artifact
    assert first.provenance.cid == second.provenance.cid
    with zipfile.ZipFile(io.BytesIO(first.artifact)) as archive:
        assert sorted(archive.namelist()) == ["AndroidManifest.xml", "classes.dex"]
        assert inspect_dex(archive.read("classes.dex")).class_descriptor == "Lfixture/surface/Main;"


@pytest.mark.parametrize("kwargs", [dict(activity="fixture.surface.Other"), dict(min_sdk=27), dict(extra=(target(b"unsupported-executable-policy"),)), dict(nonempty_selector=True)])
def test_surface_build_rejects_mismatch_old_dex_profile_and_ignored_policy(kwargs):
    reader, request = fixture(**kwargs)
    with pytest.raises(XaxError):
        build(reader, request.cid)
