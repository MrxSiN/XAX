"""S15e.6f.2 (ADR-348): the managed-class Android profile's decisions by the XAX program equal the bootstrap's.

The managed fixture (an Activity and a boot receiver with their JNI exports and platform declarations) is mutated so
that each mutation fires one site: duplicate class descriptors, the DEX 039 floor, the manifest Activity, a missing
export, a mismatched export signature, the build entry, and platform problems (a component without its permission, a
component of the wrong superclass, a missing component class, a ``maxSdkVersion`` below ``minSdk``, a foreground
service without its permissions, a missing callback method, a lifecycle override without its super call).  Each build
runs with the XAX verdict (``XAX_GENERAL_FRONTEND_DIFF=1`` re-evaluates the bootstrap's conditions and texts) and with the
bootstrap alone (``XAX_ANDROID_RULES_PYTHON=1``); both give the same artifact or diagnostic, and the program decided it.
"""

from __future__ import annotations

import os
import platform
import sys
import unittest
from unittest import mock

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
P = "android.permission."


def _build(classes, declarations, *, min_sdk=28, activity="xax.managed.MainActivity", drop=None, swap=None, entry=0):
    from benchmarks.bench_android_managed import APP, BOOT, _export
    from xax_android_managed import android_managed_class_semantics
    from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
    from xax_compiler import Kind, android_arm64_shared_general_target, object_with_refs
    from xax_jni import JniReferenceKind, jni_type_objects
    from xax_manifest import AndroidManifestSpec, android_manifest_semantics, android_platform_declarations_semantics

    target_object = android_arm64_shared_general_target()
    manifest = android_manifest_semantics(AndroidManifestSpec("xax.managed", activity, min_sdk=min_sdk, target_sdk=34))
    carriers = tuple(android_managed_class_semantics(item) for item in classes)
    functions, exports, objects = [], [], []
    for owner in classes:
        for method in owner.methods:
            source = swap.get(method.name, method) if swap else method
            function, export, graph = _export(owner, source)
            if swap and method.name in swap:  # the export keeps the method's symbol, the function another method's signature
                from xax_compiler import android_export_symbol
                from xax_jni import jni_short_native_symbol

                export = android_export_symbol(function, jni_short_native_symbol(owner.class_descriptor, method.native_name))
            functions.append(function)
            if method.name != drop:
                exports.append(export)
            objects.extend(graph.objects.values())
    extra = (android_platform_declarations_semantics(declarations),) if declarations is not None else ()
    module = object_with_refs(Kind.MODULE, (*functions, *carriers, manifest, *exports, *extra))
    app = package(b"android-managed-rules", (module,), build_entries=((b"apk", functions[entry]),))
    profile, policy = build_profile(), trust_policy()
    request = build_request(app, b"apk", target_object, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    references = jni_type_objects(tuple(
        (JniReferenceKind.BORROWED, name.encode(), APP if name.startswith("xax.") else BOOT)
        for name in ("xax.managed.MainActivity", "xax.managed.BootReceiver", "xax.managed.Other", "xax.managed.Surface", "android.os.Bundle",
                     "android.view.KeyEvent", "android.content.Context", "android.content.Intent", "android.view.SurfaceHolder")
    ))
    everything = (*references, *objects, *functions, *exports, *carriers, manifest, *extra, module, app, target_object, profile, policy, request)
    resolution = resolve_packages(request, everything, policy, b"android-managed-rules-resolver-v1")
    return build(snapshot_store(resolution, everything), request.cid).artifact


def _outcome(*arguments, **knobs):
    from xax_compiler import XaxError

    try:
        return ("artifact", _build(*arguments, **knobs))
    except XaxError as error:
        return ("rule", error.diagnostic.rule, error.diagnostic.entity, repr(error.diagnostic.expected), repr(error.diagnostic.actual))


def _cases():
    from benchmarks.bench_android_managed import ACTIVITY
    from xax_android_managed import AndroidManagedClass, AndroidManagedMethod
    from xax_manifest import AndroidDeclaredComponent, AndroidPlatformDeclarations, AndroidUsesPermission

    receiver = AndroidManagedClass("Lxax/managed/BootReceiver;", "Landroid/content/BroadcastReceiver;", (), (
        AndroidManagedMethod("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"),))
    boot = AndroidDeclaredComponent("receiver", "xax.managed.BootReceiver", True, (), ("android.intent.action.BOOT_COMPLETED",))

    def declarations(*permissions, components=(boot,)):
        return AndroidPlatformDeclarations(tuple(AndroidUsesPermission(*item) if isinstance(item, tuple) else AndroidUsesPermission(item)
                                                 for item in permissions), (), components)

    accepted = declarations(P + "RECEIVE_BOOT_COMPLETED")
    twin = AndroidManagedClass("Lxax/managed/BootReceiver;", "Landroid/content/BroadcastReceiver;", (), (
        AndroidManagedMethod("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"), AndroidManagedMethod("other", "()V")))
    surface = AndroidManagedClass("Lxax/managed/Surface;", "Ljava/lang/Object;", ("Landroid/view/SurfaceHolder$Callback;",), (
        AndroidManagedMethod("surfaceCreated", "(Landroid/view/SurfaceHolder;)V"),))
    no_super = AndroidManagedClass("Lxax/managed/MainActivity;", "Landroid/app/Activity;", (), (AndroidManagedMethod("onResume", "()V", "protected"),))
    service = AndroidDeclaredComponent("service", "xax.managed.BootReceiver", False, ("camera",))
    onresume = next(item for item in ACTIVITY.methods if item.name == "onResume")
    return {
        "accepted": ((ACTIVITY, receiver), accepted, {}),
        "no declarations": ((ACTIVITY,), None, {}),
        "duplicate descriptor": ((ACTIVITY, receiver, twin), accepted, {}),
        "DEX 039 floor": ((ACTIVITY, receiver), accepted, {"min_sdk": 26}),
        "manifest Activity": ((ACTIVITY, receiver), accepted, {"activity": "xax.managed.Other"}),
        "missing export": ((ACTIVITY, receiver), accepted, {"drop": "onPause"}),
        "export signature": ((ACTIVITY, receiver), accepted, {"swap": {"onKeyDown": onresume}}),
        "build entry": ((ACTIVITY, receiver), accepted, {"entry": 4}),
        "boot permission": ((ACTIVITY, receiver), declarations(), {}),
        "component superclass": ((ACTIVITY, receiver), declarations(components=(AndroidDeclaredComponent("service", "xax.managed.BootReceiver"),)), {}),
        "missing component": ((ACTIVITY, receiver), declarations(components=(AndroidDeclaredComponent("receiver", "xax.managed.Missing"),)), {}),
        "maxSdkVersion": ((ACTIVITY, receiver), declarations(P + "RECEIVE_BOOT_COMPLETED", (P + "CAMERA", 21)), {}),
        "foreground service": ((ACTIVITY, receiver), declarations(components=(service,)), {}),
        "callback method": ((ACTIVITY, receiver, surface), accepted, {}),
        "super call": ((no_super, receiver), accepted, {}),
    }


@unittest.skipUnless(LINUX_X86_64, "the XAX Android managed rules program runs natively on Linux x86-64")
class SelfhostAndroidManagedRulesTests(unittest.TestCase):
    def test_mutated_packages(self):
        import xax_selfhost_android_managed_rules as R

        verdicts = []
        original = R.managed_rules_with_xax

        def recorded(*arguments):
            verdicts.append(original(*arguments))
            return verdicts[-1]

        sites = set()
        for name, (classes, declarations, knobs) in _cases().items():
            with self.subTest(case=name):
                verdicts.clear()
                with mock.patch.dict(os.environ, {"XAX_GENERAL_FRONTEND_DIFF": "1"}), mock.patch.object(R, "managed_rules_with_xax", recorded):
                    decided = _outcome(classes, declarations, **knobs)
                with mock.patch.dict(os.environ, {R.OPT_OUT: "1"}):
                    reference = _outcome(classes, declarations, **knobs)
                self.assertEqual(decided, reference)
                self.assertEqual(len(verdicts), 1)
                self.assertTrue(verdicts[0][0], "the XAX program decided")
                sites.add(verdicts[0][1])
        self.assertEqual(sites, {None, "M1", "M2", "M3", "M4", "M5", "M6", "M7"})


if __name__ == "__main__":
    unittest.main()
