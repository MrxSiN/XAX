"""Vector/libxposed API-102 contract of the Android target (ADR-178).

Layer 1 (structural/codegen) of the Android hook evidence hierarchy: the pinned
Vector revision, the pinned API-102 member table, Vector's loader rules applied
to every committed module fixture, the exact libxposed descriptors each one
emits, and isolation from legacy Xposed and framework implementation classes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
import zipfile

from xax_compiler import XaxError
from xax_dex import DexBridgeSpec, emit_dex039_bridge, inspect_dex, inspect_dex_references
from xax_vector import PIN_PATH, LibxposedApiTable, check_vector_module_apk, load_vector_pin

COMPILER = Path(__file__).resolve().parents[1]
BENCHMARKS = COMPILER / "benchmarks"
VECTOR_DIR = COMPILER / "integration" / "android" / "vector"
MODULE_FIXTURES = (
    "android_libxposed_argument_fixture.apk",
    "android_libxposed_combined_fixture.apk",
    "android_libxposed_deopt_fixture.apk",
    "android_libxposed_hook_fixture.apk",
    "android_libxposed_hot_reload_fixture.apk",
    "android_libxposed_managed_fixture.apk",
    "android_libxposed_native_fixture.apk",
    "android_libxposed_remote_files_fixture.apk",
    "android_libxposed_remote_preferences_fixture.apk",
    "android_libxposed_result_fixture.apk",
    "android_libxposed_runtime_module_signed.apk",
    "android_libxposed_services_fixture.apk",
    "android_libxposed_unhook_fixture.apk",
)
TARGET_FIXTURES = (
    "android_libxposed_argument_target_fixture.apk",
    "android_libxposed_runtime_target_signed.apk",
    "android_libxposed_target_fixture.apk",
)
API = "Lio/github/libxposed/api/"


def _member(kind, owner, name, descriptor, since=101):
    return (kind, API + owner, name, descriptor, since)


LIFECYCLE = {
    _member("method", "XposedModule;", "<init>", "()V"),
    _member("method", "XposedModuleInterface;", "onModuleLoaded", f"({API}XposedModuleInterface$ModuleLoadedParam;)V"),
    _member("method", "XposedModuleInterface;", "onPackageReady", f"({API}XposedModuleInterface$PackageReadyParam;)V"),
}
HOOK_INSTALL = {
    _member("field", "XposedInterface$ExceptionMode;", "PROTECTIVE", f"{API}XposedInterface$ExceptionMode;"),
    _member("method", "XposedInterface$HookBuilder;", "intercept", f"({API}XposedInterface$Hooker;){API}XposedInterface$HookHandle;"),
    _member("method", "XposedInterface$HookBuilder;", "setExceptionMode", f"({API}XposedInterface$ExceptionMode;){API}XposedInterface$HookBuilder;"),
    _member("method", "XposedInterfaceWrapper;", "hook", f"(Ljava/lang/reflect/Executable;){API}XposedInterface$HookBuilder;"),
    _member("method", "XposedModuleInterface$PackageReadyParam;", "getClassLoader", "()Ljava/lang/ClassLoader;"),
}
PROCEED = _member("method", "XposedInterface$Chain;", "proceed", "()Ljava/lang/Object;")
EXPECTED_MEMBERS = {
    "android_libxposed_native_fixture.apk": LIFECYCLE,
    "android_libxposed_managed_fixture.apk": LIFECYCLE,
    "android_libxposed_hook_fixture.apk": LIFECYCLE | HOOK_INSTALL | {PROCEED},
    "android_libxposed_deopt_fixture.apk": LIFECYCLE | HOOK_INSTALL | {
        PROCEED, _member("method", "XposedInterfaceWrapper;", "deoptimize", "(Ljava/lang/reflect/Executable;)Z"),
    },
    "android_libxposed_unhook_fixture.apk": LIFECYCLE | HOOK_INSTALL | {
        PROCEED, _member("method", "XposedInterface$HookHandle;", "unhook", "()V"),
    },
    "android_libxposed_runtime_module_signed.apk": LIFECYCLE | HOOK_INSTALL | {
        PROCEED,
        _member("method", "XposedInterface$Chain;", "getArg", "(I)Ljava/lang/Object;"),
        _member("method", "XposedInterface$Chain;", "proceed", "([Ljava/lang/Object;)Ljava/lang/Object;"),
    },
    "android_libxposed_hot_reload_fixture.apk": LIFECYCLE | HOOK_INSTALL | {
        PROCEED,
        _member("method", "XposedInterface$HookHandle;", "unhook", "()V"),
        _member("method", "XposedInterface$HookBuilder;", "setId", f"(Ljava/lang/String;){API}XposedInterface$HookBuilder;", 102),
        _member("method", "XposedInterface$HookHandle;", "getId", "()Ljava/lang/String;", 102),
        _member("method", "XposedInterface$HookHandle;", "replaceHook", f"({API}XposedInterface$Hooker;){API}XposedInterface$HookHandle;", 102),
        _member("method", "XposedModuleInterface$HotReloadedParam;", "getOldHookHandles", "()Ljava/util/List;", 102),
        _member("method", "XposedModuleInterface$HotReloadedParam;", "getSavedInstanceState", "()Ljava/lang/Object;", 102),
        _member("method", "XposedModuleInterface$HotReloadingParam;", "setSavedInstanceState", "(Ljava/lang/Object;)V", 102),
        _member("method", "XposedModuleInterface;", "onHotReloaded", f"({API}XposedModuleInterface$HotReloadedParam;)V", 102),
        _member("method", "XposedModuleInterface;", "onHotReloading", f"({API}XposedModuleInterface$HotReloadingParam;)Z", 102),
    },
    "android_libxposed_services_fixture.apk": LIFECYCLE | {
        _member("method", "XposedInterfaceWrapper;", "getFrameworkName", "()Ljava/lang/String;"),
        _member("method", "XposedInterfaceWrapper;", "getFrameworkVersion", "()Ljava/lang/String;"),
        _member("method", "XposedInterfaceWrapper;", "getRemotePreferences", "(Ljava/lang/String;)Landroid/content/SharedPreferences;"),
        _member("method", "XposedInterfaceWrapper;", "listRemoteFiles", "()[Ljava/lang/String;"),
        _member("method", "XposedInterfaceWrapper;", "openRemoteFile", "(Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;"),
    },
    "android_libxposed_remote_preferences_fixture.apk": LIFECYCLE | {
        _member("method", "XposedInterfaceWrapper;", "getFrameworkProperties", "()J"),
        _member("method", "XposedInterfaceWrapper;", "getRemotePreferences", "(Ljava/lang/String;)Landroid/content/SharedPreferences;"),
    },
    "android_libxposed_remote_files_fixture.apk": LIFECYCLE | {
        _member("method", "XposedInterfaceWrapper;", "getFrameworkProperties", "()J"),
        _member("method", "XposedInterfaceWrapper;", "listRemoteFiles", "()[Ljava/lang/String;"),
        _member("method", "XposedInterfaceWrapper;", "openRemoteFile", "(Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;"),
    },
}


def _table() -> LibxposedApiTable:
    return LibxposedApiTable(load_vector_pin())


def _repack(apk: bytes, *, replace: dict[str, bytes] | None = None, drop: tuple[str, ...] = ()) -> bytes:
    replace = replace or {}
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(apk)) as source, zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as target:
        for info in source.infolist():
            if info.filename in drop or info.filename in replace:
                continue
            target.writestr(info.filename, source.read(info.filename))
        for name, data in replace.items():
            target.writestr(name, data)
    return out.getvalue()


def _next_dex_name(apk: bytes) -> str:
    names = set(zipfile.ZipFile(io.BytesIO(apk)).namelist())
    index = 2
    while f"classes{index}.dex" in names:
        index += 1
    return f"classes{index}.dex"


def _load_pin_script():
    spec = importlib.util.spec_from_file_location("xax_pin_libxposed_api", VECTOR_DIR / "pin_libxposed_api.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VectorPinTests(unittest.TestCase):
    def test_pin_records_vector_v2_2_and_its_libxposed_submodules(self):
        pin = load_vector_pin()
        self.assertEqual(pin["schema"], "xax-vector-runtime-pin-v1")
        self.assertEqual(pin["vector"]["release"], "v2.2")
        self.assertEqual(pin["vector"]["commit"], "88f8e1faa8b4e7ce20aefabe9c295cd746ea038e")
        self.assertEqual(pin["vector"]["framework_name"], "Vector")
        self.assertEqual(pin["libxposed_api"]["commit"], "39cac0845771547c9c67a3e3ce255af110a54a0e")
        self.assertEqual(pin["libxposed_api"]["lib_api"], 102)
        self.assertEqual(pin["libxposed_service"]["commit"], "3318940876192e29cf6ab07637e899e22a87ebf0")
        self.assertEqual(pin["libxposed_service"]["framework_properties"]["PROP_CAP_REMOTE"], 2)

    def test_api_table_digest_detects_hand_edits(self):
        pin = load_vector_pin()
        script = _load_pin_script()
        self.assertEqual(script.table_digest(pin["api_classes"]), pin["api_table_sha256"])
        self.assertEqual(pin["vector"], script.VECTOR)
        self.assertEqual({k: v for k, v in pin["libxposed_api"].items() if k != "classes_jar_sha256"}, script.LIBXPOSED_API)
        self.assertEqual(pin["libxposed_service"], script.LIBXPOSED_SERVICE)

    def test_api_artifact_is_the_one_art_verification_uses(self):
        spec = importlib.util.spec_from_file_location("xax_make_android_root", COMPILER / "integration/android/make_android_root.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pin = load_vector_pin()
        self.assertEqual(module.LIBXPOSED_API, (pin["libxposed_api"]["aar_url"], pin["libxposed_api"]["aar_sha256"]))

    def test_api_table_reproduces_from_the_pinned_classes_jar_when_available(self):
        classes_jar = Path("/opt/android/libxposed/classes.jar")
        if not classes_jar.exists():
            self.skipTest("make_android_root.py has not fetched the pinned libxposed AAR")
        data = classes_jar.read_bytes()
        pin = load_vector_pin()
        self.assertEqual(hashlib.sha256(data).hexdigest(), pin["libxposed_api"]["classes_jar_sha256"])
        self.assertEqual(_load_pin_script().api_classes(data), pin["api_classes"])

    def test_api102_additions_are_exactly_the_since_api_members(self):
        pin = load_vector_pin()
        additions = sorted(
            (row["descriptor"].removeprefix(API), item["name"])
            for row in pin["api_classes"] for item in row["members"] if item["since"] == 102
        )
        self.assertEqual(additions, sorted([
            ("XposedInterface$HookBuilder;", "setId"),
            ("XposedInterface$HookHandle;", "getId"),
            ("XposedInterface$HookHandle;", "replaceHook"),
            ("XposedInterfaceWrapper;", "detach"),
            ("XposedModuleInterface$HotReloadedParam;", "getExtras"),
            ("XposedModuleInterface$HotReloadedParam;", "getOldHookHandles"),
            ("XposedModuleInterface$HotReloadedParam;", "getSavedInstanceState"),
            ("XposedModuleInterface$HotReloadingParam;", "getExtras"),
            ("XposedModuleInterface$HotReloadingParam;", "setSavedInstanceState"),
            ("XposedModuleInterface;", "onHotReloaded"),
            ("XposedModuleInterface;", "onHotReloading"),
        ]))
        internal = [item["name"] for row in pin["api_classes"] for item in row["members"] if item["internal"]]
        self.assertEqual(internal, ["attachFramework"])
        self.assertEqual(PIN_PATH, VECTOR_DIR / "vector_runtime_pin.json")


class VectorModuleAcceptanceTests(unittest.TestCase):
    def test_every_committed_module_fixture_is_accepted_by_vector_rules(self):
        table = _table()
        committed = sorted(
            path.name for path in BENCHMARKS.glob("android_libxposed_*.apk")
            if "META-INF/xposed/module.prop" in zipfile.ZipFile(path).namelist()
        )
        self.assertEqual(committed, sorted(MODULE_FIXTURES))
        for name in MODULE_FIXTURES:
            with self.subTest(name=name):
                report = check_vector_module_apk((BENCHMARKS / name).read_bytes(), table)
                self.assertEqual(report.violations, ())
                self.assertEqual(report.java_entries, ("xax.generated.XaxModule",))
                self.assertEqual(report.module_prop["targetApiVersion"], "102")
                self.assertEqual(report.scopes, ("com.example.target",))

    def test_controlled_targets_are_plain_apps(self):
        for name in TARGET_FIXTURES:
            with self.subTest(name=name):
                names = zipfile.ZipFile(BENCHMARKS / name).namelist()
                self.assertFalse([item for item in names if item.startswith("META-INF/xposed/")])

    def test_exact_libxposed_descriptors_per_fixture(self):
        table = _table()
        for name, expected in EXPECTED_MEMBERS.items():
            with self.subTest(name=name):
                report = check_vector_module_apk((BENCHMARKS / name).read_bytes(), table)
                self.assertEqual(set(report.api_members), expected)

    def test_api102_members_never_sit_behind_min_api_101(self):
        table = _table()
        for name in MODULE_FIXTURES:
            with self.subTest(name=name):
                report = check_vector_module_apk((BENCHMARKS / name).read_bytes(), table)
                self.assertEqual(int(report.module_prop["minApiVersion"]), report.required_api)
                self.assertEqual(bool(report.api102_members), name == "android_libxposed_hot_reload_fixture.apk")
                self.assertEqual(report.module_prop.get("autoHotReload") == "true", report.required_api == 102)

    def test_native_entry_rides_on_the_java_entry(self):
        report = check_vector_module_apk((BENCHMARKS / "android_libxposed_native_fixture.apk").read_bytes(), _table())
        self.assertEqual(report.native_entries, ("libxaxapp.so",))
        self.assertEqual(report.java_entries, ("xax.generated.XaxModule",))


class VectorModuleRejectionTests(unittest.TestCase):
    def setUp(self):
        self.table = _table()
        self.module = (BENCHMARKS / "android_libxposed_runtime_module_signed.apk").read_bytes()
        self.hot_reload = (BENCHMARKS / "android_libxposed_hot_reload_fixture.apk").read_bytes()

    def _rules(self, apk: bytes) -> set[str]:
        return {item.split(":", 1)[0] for item in check_vector_module_apk(apk, self.table).violations}

    def test_native_only_module_is_not_discoverable(self):
        native = (BENCHMARKS / "android_libxposed_native_fixture.apk").read_bytes()
        # The native library stays page-aligned only through the XAX packer, so
        # check the rule on a module without native entries.
        self.assertIn("VECTOR-JAVA-ENTRY", self._rules(_repack(self.module, drop=("META-INF/xposed/java_init.list",))))
        self.assertEqual(check_vector_module_apk(native, self.table).violations, ())

    def test_api102_member_with_min_api_101_is_rejected(self):
        prop = b"minApiVersion=101\ntargetApiVersion=102\nstaticScope=true\nautoHotReload=true\n"
        rules = self._rules(_repack(self.hot_reload, replace={"META-INF/xposed/module.prop": prop}))
        self.assertEqual(rules, {"VECTOR-MIN-API"})

    def test_auto_hot_reload_needs_the_api102_callbacks(self):
        prop = b"minApiVersion=102\ntargetApiVersion=102\nstaticScope=true\nautoHotReload=true\n"
        rules = self._rules(_repack(self.module, replace={"META-INF/xposed/module.prop": prop}))
        self.assertEqual(rules, {"VECTOR-HOT-RELOAD"})

    def test_wrong_target_api_and_empty_static_scope_are_rejected(self):
        prop = b"minApiVersion=100\ntargetApiVersion=100\nstaticScope=true\n"
        rules = self._rules(_repack(self.module, replace={"META-INF/xposed/module.prop": prop}, drop=("META-INF/xposed/scope.list",)))
        # minApiVersion=100 also undercuts the API-101 members the module uses.
        self.assertEqual(rules, {"VECTOR-TARGET-API", "VECTOR-STATIC-SCOPE", "VECTOR-MIN-API"})

    def test_legacy_xposed_entry_and_types_are_rejected(self):
        self.assertIn("VECTOR-LEGACY-API", self._rules(_repack(self.module, replace={"assets/xposed_init": b"x.Legacy\n"})))
        legacy = emit_dex039_bridge(DexBridgeSpec("Lprobe/Legacy;", "Lde/robv/android/xposed/XC_MethodHook;"))
        self.assertIn("VECTOR-LEGACY-API", self._rules(_repack(self.module, replace={_next_dex_name(self.module): legacy})))

    def test_framework_implementation_and_bundled_api_are_rejected(self):
        implementation = emit_dex039_bridge(DexBridgeSpec("Lprobe/Impl;", "Lorg/matrix/vector/impl/VectorContext;"))
        self.assertIn("VECTOR-IMPLEMENTATION-REF", self._rules(_repack(self.module, replace={_next_dex_name(self.module): implementation})))
        bundled = emit_dex039_bridge(DexBridgeSpec(API + "XposedModule;", "Ljava/lang/Object;"))
        self.assertIn("VECTOR-BUNDLED-API", self._rules(_repack(self.module, replace={_next_dex_name(self.module): bundled})))


class BuildApiFloorTests(unittest.TestCase):
    def test_stable_hook_id_requires_min_api_102(self):
        from benchmarks.bench_android_libxposed_hook import build_fixture

        with self.assertRaises(XaxError) as caught:
            build_fixture(lifetime_policy="retained-manual-unhook", hook_id="xax.primary", min_api_version=101)
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-APK-LIBXPOSED-HOOK-ID-API")
        result = build_fixture(lifetime_policy="retained-manual-unhook", hook_id="xax.primary")[-1]
        report = check_vector_module_apk(result.artifact, _table())
        self.assertEqual(report.violations, ())
        self.assertEqual(report.required_api, 102)


class LegacyIsolationTests(unittest.TestCase):
    def test_compiler_sources_name_no_legacy_or_framework_implementation_api(self):
        offenders = []
        for path in sorted((COMPILER / "src").glob("*.py")):
            if path.name == "xax_vector.py":  # the checker names them to reject them
                continue
            text = path.read_text(encoding="utf-8")
            for needle in ("de/robv/android/xposed", "de.robv.android.xposed", "XposedBridge", "XC_MethodHook",
                           "IXposedHookLoadPackage", "assets/xposed_init", "org/matrix/vector", "org.matrix.vector"):
                if needle in text:
                    offenders.append((path.name, needle))
        self.assertEqual(offenders, [])


class DexReferenceInspectionTests(unittest.TestCase):
    def test_reference_tables_agree_with_the_container_inspector(self):
        with zipfile.ZipFile(BENCHMARKS / "android_libxposed_hot_reload_fixture.apk") as archive:
            for name in ("classes.dex", "classes2.dex", "classes3.dex", "classes4.dex"):
                data = archive.read(name)
                container, references = inspect_dex(data), inspect_dex_references(data)
                self.assertEqual(references.strings, container.strings)
                self.assertEqual(len(references.method_refs), container.method_ids_size)
                self.assertEqual(references.classes[0].descriptor, container.class_descriptor)
                self.assertEqual(references.classes[0].superclass, container.superclass_descriptor)
                self.assertEqual(references.classes[0].interfaces, container.interfaces)


if __name__ == "__main__":
    unittest.main()
