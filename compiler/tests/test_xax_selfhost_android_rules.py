"""S15e.6f.1 (ADR-347): the unsigned Android carrier decisions decided by the XAX rules program equal the bootstrap's.

The libxposed hook fixture (an Activity UI, a manifest, libxposed metadata, a generated managed entry, a hooker and its
installation) is mutated carrier by carrier so that each mutation fires one rule site: the Activity identity and SDK
floor, the libxposed metadata, hook closures, the result, argument and combined mutation policies, deoptimization, API
levels, the hooker identity, the lifecycle, module services, remote preferences and files, hot reload, the Java and
native entries, and the JNI exports and build entry.  Each build runs twice: with the XAX verdict
(``XAX_GENERAL_FRONTEND_DIFF=1`` also re-evaluates the bootstrap's condition at every site up to it) and with the
bootstrap's checks alone (``XAX_ANDROID_RULES_PYTHON=1``); both give the same artifact or the same rule, and the XAX
program decided it.
"""

from __future__ import annotations

import os
import platform
import sys
import unittest
from unittest import mock

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _build(**knobs):
    from benchmarks.bench_android_libxposed_managed import _managed_callbacks
    from benchmarks.bench_android_managed_bridge import ui_activity_fixture
    import xax_libxposed as L
    from xax_build import ArtifactKind, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
    from xax_compiler import Kind, android_arm64_shared_target, object_with_refs
    from xax_manifest import AndroidManifestSpec, android_manifest_semantics

    ui = ui_activity_fixture()
    managed = _managed_callbacks()
    carriers = [android_manifest_semantics(AndroidManifestSpec("xax.generated", knobs.get("activity", "xax.generated.XaxActivity"),
                                                               min_sdk=knobs.get("min_sdk", 28), target_sdk=35))]
    if knobs.get("xposed", True):
        carriers.append(L.libxposed_module_semantics(L.LibxposedModuleDescription(
            min_api_version=knobs.get("min_api", 102), target_api_version=knobs.get("target_api", 102), static_scope=True,
            java_entries=knobs.get("java_entries", ("xax.generated.XaxModule",)), native_entries=knobs.get("native_entries", ()),
            scopes=("com.example.target",))))
    if knobs.get("managed", True):
        carriers.append(managed["managed"])
    if knobs.get("hooker", True):
        carriers.append(L.libxposed_hook_adapter_semantics(L.LibxposedHookAdapterDescription(
            java_class_name=knobs.get("hooker_name", "xax.generated.XaxHooker"), inspected_argument_index=knobs.get("inspected"))))
    if knobs.get("install", True):
        carriers.append(L.libxposed_hook_installation_semantics(L.LibxposedHookInstallationDescription(
            target_class_name="android.app.Activity", target_method_name="onResume", hooker_class_name=knobs.get("install_hooker", "xax.generated.XaxHooker"),
            parameter_type_names=knobs.get("params", ()), exception_mode="PROTECTIVE", failure_policy="propagate",
            lifetime_policy=knobs.get("lifetime", "process"), hook_id=knobs.get("hook_id"))))
    carriers.extend(knobs.get("extra", ()))
    exports = [ui["activity_export"], ui["listener_export"], *managed["exports"]]
    if knobs.get("drop_activity_export"):
        exports = exports[1:]
    module = object_with_refs(Kind.MODULE, (ui["activity_callback"], ui["listener_callback"], *managed["callbacks"], *exports, ui["ui_semantics"], *carriers))
    entry = managed["callbacks"][0] if knobs.get("wrong_entry") else ui["activity_callback"]
    app = package(b"android-rules", (module,), build_entries=((b"apk", entry),))
    target, profile, policy = android_arm64_shared_target(), build_profile(), trust_policy()
    request = build_request(app, b"apk", target, profile, requested_artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,))
    objects = (*tuple(ui["reader"].objects()), *managed["types"], *managed["graphs"], *managed["callbacks"], *exports, ui["ui_semantics"], *carriers,
               module, app, target, profile, policy, request)
    resolution = resolve_packages(request, objects, policy, b"android-rules-resolver-v1")
    return build(snapshot_store(resolution, objects), request.cid)


def _outcome(**knobs):
    from xax_compiler import XaxError

    try:
        return ("artifact", _build(**knobs).artifact)
    except XaxError as error:
        return ("rule", error.diagnostic.rule, error.diagnostic.entity, repr(error.diagnostic.expected), repr(error.diagnostic.actual))


def _cases():
    import xax_libxposed as L

    result = lambda **kw: L.libxposed_hook_result_semantics(L.LibxposedHookResultDescription(**kw))  # noqa: E731
    argument = lambda **kw: L.libxposed_hook_argument_semantics(L.LibxposedHookArgumentDescription(**kw))  # noqa: E731
    combined = lambda **kw: L.libxposed_hook_combined_semantics(L.LibxposedHookCombinedDescription(**kw))  # noqa: E731
    target = dict(target_class_name="android.app.Activity", target_method_name="onResume")
    return {
        "accepted": {},
        "activity identity": dict(activity="xax.generated.Other"),
        "multidex floor": dict(min_sdk=19),
        "managed metadata": dict(xposed=False, hooker=False, install=False),
        "hook managed entry": dict(managed=False),
        "hook closure": dict(install=False),
        "result and argument": dict(extra=(result(**target), argument(**target))),
        "result target": dict(extra=(result(),)),
        "result hooker": dict(extra=(result(hooker_class_name="xax.generated.Other", **target),)),
        "result zero argument": dict(inspected=0, extra=(result(**target),)),
        "result accepted": dict(extra=(result(**target),)),
        "argument signature": dict(inspected=0, extra=(argument(**target),)),
        "argument index": dict(inspected=1, params=("java.lang.String",), extra=(argument(**target),)),
        "argument accepted": dict(inspected=0, params=("java.lang.String",), extra=(argument(**target),)),
        "combined target": dict(inspected=0, params=("java.lang.String",), extra=(combined(),)),
        "deoptimization target": dict(extra=(L.libxposed_deoptimization_semantics(L.LibxposedDeoptimizationDescription(target_method_name="onPause")),)),
        "hook API": dict(target_api=101, min_api=101),
        "hook ID API": dict(hook_id="xax.primary", lifetime="retained-manual-unhook", min_api=101),
        "hooker identity": dict(install_hooker="xax.generated.Other"),
        "zero-argument hooker": dict(inspected=0),
        "hot reload ID": dict(hook_id="xax.other", lifetime="retained-manual-unhook",
                              extra=(L.libxposed_hot_reload_semantics(L.LibxposedHotReloadDescription(hook_id="xax.primary")),)),
        "java identity": dict(java_entries=("xax.generated.Other",)),
        "native entry": dict(native_entries=("libother.so",)),
        "native init": dict(native_entries=("libxaxapp.so",)),
        "JNI exports": dict(drop_activity_export=True),
        "build entry": dict(wrong_entry=True),
    }


@unittest.skipUnless(LINUX_X86_64, "the XAX Android rules program runs natively on Linux x86-64")
class SelfhostAndroidRulesTests(unittest.TestCase):
    def test_mutated_packages(self):
        import xax_selfhost_android_rules as R

        verdicts = []
        original = R.rules_with_xax

        def recorded(*arguments):
            verdicts.append(original(*arguments))
            return verdicts[-1]

        sites = set()
        for name, knobs in _cases().items():
            with self.subTest(case=name):
                verdicts.clear()
                with mock.patch.dict(os.environ, {"XAX_GENERAL_FRONTEND_DIFF": "1"}), mock.patch.object(R, "rules_with_xax", recorded):
                    decided = _outcome(**knobs)
                with mock.patch.dict(os.environ, {R.OPT_OUT: "1"}):
                    reference = _outcome(**knobs)
                self.assertEqual(decided, reference)
                self.assertEqual(len(verdicts), 1)
                self.assertTrue(verdicts[0][0], "the XAX program decided")
                sites.add(verdicts[0][1])
        self.assertGreaterEqual(len(sites), 20)


if __name__ == "__main__":
    unittest.main()
