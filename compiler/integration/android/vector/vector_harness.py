"""Real Vector runtime integration harness for XAX-generated libxposed modules (ADR-178).

Evidence hierarchy for the Android hook target:

    1. structural/codegen   tests/test_xax_vector_contract.py (pinned API, Vector loader rules)
    2. ART verification     benchmarks/bench_android_art_verify.py
    3. stand-in behaviour   benchmarks/bench_android_art_execute.py (recording framework)
    4. Vector runtime       this harness, on a rooted device running Vector

This layer is the only one that claims framework behaviour.  It drives a rooted
arm64 Android device (Magisk or KernelSU, a Zygisk implementation, Vector v2.2
or newer) over adb: installs the signed profiles from
``benchmarks/bench_android_vector_profiles.py``, enables and scopes each module
through Vector's own CLI, launches the controlled target, and observes

* the visible target text (uiautomator) and process survival (pidof);
* Vector's logcat lines and the target's /proc/<pid>/maps;
* the XAX-generated module inside the target process over JDWP (breakpoints,
  field reads, calls to the generated helpers; see jdwp.py).

Checks that need JDWP require ``ro.debuggable=1``.  A check that cannot be
observed is recorded ``INCONCLUSIVE`` or ``UNEXECUTED``, never ``PASS``.

    python integration/android/vector/vector_harness.py --plan     # no device: UNEXECUTED plan
    python integration/android/vector/vector_harness.py [--vector-zip Vector-v2.2.zip]
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
COMPILER = HERE.parents[2]
for path in (COMPILER / "src", COMPILER, HERE):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from jdwp import EVENT_BREAKPOINT, Jdwp, JdwpError, Value  # noqa: E402

EVIDENCE = COMPILER / "benchmarks" / "android_vector_runtime_evidence.json"
PIN = HERE / "vector_runtime_pin.json"
TARGET_PACKAGE = "com.example.target"
TARGET_COMPONENT = "com.example.target/com.example.target.XaxActivity"
TARGET_ACTIVITY = "Lcom/example/target/XaxActivity;"
MODULE_CLASS = "Lxax/generated/XaxModule;"
HOOKER_CLASS = "Lxax/generated/XaxHooker;"
WRAPPER_CLASS = "Lio/github/libxposed/api/XposedInterfaceWrapper;"
VECTOR_MODULE_DIR = "/data/adb/modules/zygisk_vector"
VECTOR_CLI = f"{VECTOR_MODULE_DIR}/cli"
REMOTE_FILE = "xax_probe.txt"
REMOTE_FILE_CONTENT = "XAX-VECTOR-PROBE\n"
CLEAR_TASK = "0x10008000"  # FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK: same process, new Activity
STATUSES = ("PASS", "FAIL", "INCONCLUSIVE", "UNEXECUTED")
# Thrown into the hooker for the PROTECTIVE check; any Throwable exercises the same path.
THROWABLES = ("Ljava/lang/IllegalStateException;", "Ljava/lang/RuntimeException;")


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    profile: str
    oracle: str


CHECKS: tuple[Check, ...] = (
    Check("discovery", "Vector discovers the generated module", "managed", "vector-cli modules ls lists the module package"),
    Check("module_prop", "META-INF/xposed/module.prop is accepted", "managed", "Vector logs 'Loaded module <pkg> successfully' in the target"),
    Check("java_init", "java_init.list is loaded", "managed", "JDWP: xax.generated.XaxModule is loaded in the target"),
    Check("native_init", "native_init.list is loaded", "native", "Vector logs 'Initialized native module' for libxaxapp.so; maps show it"),
    Check("scope", "scope configuration works", "managed", "vector-cli scope ls lists the target and the module loads there"),
    Check("instantiated", "the generated XposedModule is instantiated", "managed", "JDWP: one live XaxModule instance in the target"),
    Check("package_callbacks", "onPackageLoaded/onPackageReady are delivered", "managed", "JDWP from am start -D: XaxModule.onPackageReady hit once for the target; onPackageLoaded is the API default"),
    Check("class_loader", "the target ClassLoader is usable", "hook", "the hook installed through PackageReadyParam.getClassLoader() intercepts"),
    Check("hook_installed", "a generated hook is installed by Vector", "hook", "JDWP: XaxHooker.intercept is reached from Activity.onResume"),
    Check("intercepted", "the target method is intercepted", "hook", "JDWP breakpoint in XaxHooker.intercept hits on relaunch"),
    Check("pass_through", "pass-through reaches the original method", "hook", "Activity resumes (super.onResume ran), text OriginalArg, process alive"),
    Check("result_replacement", "result replacement works", "result", "visible text Hooked instead of Original"),
    Check("argument_replacement", "argument replacement works", "argument", "visible text HookedArg instead of OriginalArg"),
    Check("combined_replacement", "combined argument + result replacement works", "combined", "visible text HookedResult"),
    Check("deopt_order", "deoptimization is invoked before hooking", "deopt", "JDWP from am start -D: deoptimize() then hook() from XaxModule.onPackageReady"),
    Check("retained_handle", "the retained HookHandle works", "unhook", "JDWP: XaxModule.xaxHookHandle is a live HookHandle"),
    Check("manual_unhook", "manual unhook stops interception", "unhook", "JDWP: after xaxUnhook() the intercept breakpoint no longer hits"),
    Check("stable_hook_id", "stable hook IDs round-trip", "hot_reload", "JDWP: HookHandle.getId() is xax.primary before and after reload"),
    Check("module_services", "framework/module services work", "services", "JDWP: xaxFrameworkName() is Vector; xaxFrameworkVersion() is non-empty"),
    Check("remote_preferences", "remote preferences capability and reads work", "remote_preferences", "JDWP: preferences are non-null under PROP_CAP_REMOTE; absent keys return defaults"),
    Check("remote_files", "remote file capability/list/open works", "remote_files", "JDWP: a seeded file is listed and opens with its size"),
    Check("hot_reload_callbacks", "API-102 hot reload callbacks are delivered", "hot_reload", "a versionCode bump triggers Vector auto hot reload; new generation state is set"),
    Check("saved_state", "saved state is transferred", "hot_reload", "JDWP: new XaxModule.xaxReloadClassLoader is the target ClassLoader"),
    Check("stable_id_validation", "stable-ID validation skips a mismatched handle", "hot_reload_id_mismatch", "JDWP: new generation keeps no handle; the old hooker still intercepts"),
    Check("replace_hook", "replaceHook() swaps the hook atomically", "hot_reload", "JDWP: the new generation's XaxHooker intercepts and the old one does not"),
    Check("process_survives", "the target survives every successful profile", "*", "pidof is unchanged through each profile"),
    Check("protective", "PROTECTIVE exception handling", "protective", "JDWP throws inside intercept before proceed: original OriginalArg shown, process alive"),
)


def plan_evidence() -> dict[str, object]:
    """Evidence for a host without a prepared device: every check UNEXECUTED."""
    pin = json.loads(PIN.read_text(encoding="utf-8"))
    return {
        "schema": "xax-android-vector-runtime-evidence-v1",
        "label": "UNEXECUTED",
        "missing_requirement": (
            "a rooted arm64-v8a Android 8.1+ device or emulator reachable over adb, with Magisk (Zygisk enabled) "
            "or KernelSU plus a Zygisk implementation, Vector v2.2 or newer installed as zygisk_vector, and "
            "ro.debuggable=1 for the JDWP checks; none is available on the host that produced this file"
        ),
        "runtime_contract": "XAX -> libxposed API 102 module -> Vector -> ART",
        "pin": {
            "vector_release": pin["vector"]["release"],
            "vector_commit": pin["vector"]["commit"],
            "libxposed_api_commit": pin["libxposed_api"]["commit"],
            "libxposed_service_commit": pin["libxposed_service"]["commit"],
        },
        "environment": None,
        "profiles_evidence": "benchmarks/android_vector_profiles_evidence.json",
        "checks": [
            {"id": check.id, "title": check.title, "profile": check.profile, "oracle": check.oracle,
             "status": "UNEXECUTED", "detail": ""}
            for check in CHECKS
        ],
    }


class Device:
    """adb access to one device; ``ANDROID_SERIAL`` selects it."""

    def __init__(self, serial: str | None = None):
        self.adb = ["adb"] + (["-s", serial] if serial else [])

    def run(self, *arguments: str, check: bool = True, timeout: float = 120) -> str:
        completed = subprocess.run([*self.adb, *arguments], capture_output=True, text=True, timeout=timeout)
        if check and completed.returncode:
            raise RuntimeError(f"adb {' '.join(arguments)}: {completed.stderr.strip() or completed.stdout.strip()}")
        return completed.stdout

    def sh(self, command: str, check: bool = False) -> str:
        return self.run("shell", command, check=check).strip()

    def su(self, command: str, check: bool = False) -> str:
        return self.run("shell", f"su -c {shlex.quote(command)}", check=check).strip()

    def prop(self, name: str) -> str:
        return self.sh(f"getprop {name}")

    def install(self, apk: Path) -> None:
        self.run("install", "-r", "-t", str(apk), timeout=300)

    def uninstall(self, package: str) -> None:
        self.run("uninstall", package, check=False)

    def pid(self, package: str) -> int:
        out = self.sh(f"pidof {package}")
        return int(out.split()[0]) if out else 0

    def ui_texts(self) -> list[str]:
        self.sh("uiautomator dump /data/local/tmp/xax_window.xml")
        dump = self.sh("cat /data/local/tmp/xax_window.xml")
        return re.findall(r' text="([^"]*)"', dump)

    def wait_text(self, text: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text in self.ui_texts():
                return True
            time.sleep(1)
        return False

    def logcat(self) -> str:
        return self.run("logcat", "-d", "-v", "brief", check=False)

    def forward_jdwp(self, pid: int) -> int:
        return int(self.run("forward", "tcp:0", f"jdwp:{pid}").strip())


class VectorCli:
    def __init__(self, device: Device):
        self.device = device

    def __call__(self, *arguments: str) -> str:
        return self.device.su(" ".join([VECTOR_CLI, "--json", *map(shlex.quote, arguments)]))


def probe_environment(device: Device, vector_zip: Path | None) -> dict[str, object]:
    root = device.su("id")
    zygisk_impl = "unknown"
    magisk = device.su("magisk -v")
    if magisk:
        enabled = device.su("magisk --sqlite \"SELECT value FROM settings WHERE key='zygisk'\"")
        zygisk_impl = f"Magisk built-in Zygisk ({enabled or 'setting unreadable'})"
    for module in ("zygisksu", "zygisk_next", "rezygisk", "zygisk_noroot"):
        prop = device.su(f"cat /data/adb/modules/{module}/module.prop")
        if prop:
            zygisk_impl = f"{module}: " + next((line for line in prop.splitlines() if line.startswith("version=")), "version=?")
    vector_prop = device.su(f"cat {VECTOR_MODULE_DIR}/module.prop")
    return {
        "android_release": device.prop("ro.build.version.release"),
        "android_sdk": device.prop("ro.build.version.sdk"),
        "abi_list": device.prop("ro.product.cpu.abilist"),
        "fingerprint": device.prop("ro.build.fingerprint"),
        "model": device.prop("ro.product.model"),
        "emulator": device.prop("ro.kernel.qemu") == "1" or "emu" in device.prop("ro.hardware"),
        "debuggable": device.prop("ro.debuggable") == "1",
        "root_uid0": "uid=0" in root,
        "magisk": magisk or None,
        "kernelsu": device.su("ksud -V") or None,
        "zygisk": zygisk_impl,
        "vector_module_prop": vector_prop or None,
        "vector_cli_status": VectorCli(device)("status") if vector_prop else None,
        "vector_zip_sha256": hashlib.sha256(vector_zip.read_bytes()).hexdigest() if vector_zip else None,
    }


def vector_version_ok(module_prop: str | None, minimum: str) -> bool:
    found = re.search(r"^version=v(\d+)\.(\d+)", module_prop or "", re.MULTILINE)
    want = re.match(r"v(\d+)\.(\d+)", minimum)
    return bool(found and want) and tuple(map(int, found.groups())) >= tuple(map(int, want.groups()))


class Session:
    """A JDWP session on the target process, with the queries the checks share."""

    def __init__(self, device: Device, pid: int):
        self.device, self.pid = device, pid
        self.jdwp = Jdwp.connect(device.forward_jdwp(pid))

    def close(self) -> None:
        self.jdwp.close()

    def method(self, class_id: int, name: str, signature: str | None = None) -> int:
        for (found, found_signature), method in self.jdwp.methods(class_id).items():
            if found == name and (signature is None or found_signature == signature):
                return method
        raise LookupError(f"{name}{signature or ''} not found")

    def breakpoint(self, class_signature: str, name: str, signature: str | None = None) -> dict[int, int]:
        """Breakpoints on every loaded class with this signature: request id -> class id."""
        requests = {}
        for class_id in self.jdwp.classes_by_signature(class_signature):
            location = self.jdwp.method_entry(class_id, self.method(class_id, name, signature))
            requests[self.jdwp.set_breakpoint(location)] = class_id
        return requests

    def hit(self, requests: dict[int, int], trigger, timeout: float = 60):
        """Run ``trigger`` and return the breakpoint event (thread suspended) or None."""
        trigger()
        return self.jdwp.wait_event({EVENT_BREAKPOINT}, set(requests), timeout)

    def clear(self, requests: dict[int, int]) -> None:
        for request in requests:
            self.jdwp.clear_breakpoint(request)

    def modules(self) -> list[tuple[int, int]]:
        """Live XaxModule instances as (object, class) pairs, across module generations."""
        return [(obj, class_id) for class_id in self.jdwp.classes_by_signature(MODULE_CLASS)
                for obj in self.jdwp.instances(class_id)]

    def field(self, obj: int, class_id: int, name: str, signature: str) -> Value:
        return self.jdwp.get_field(obj, self.jdwp.fields(class_id)[(name, signature)])

    def call(self, obj: int, thread: int, name: str, signature: str, *arguments: Value) -> Value:
        class_id = self.jdwp.reference_type(obj)
        result, thrown = self.jdwp.invoke(obj, thread, class_id, self.method(class_id, name, signature), *arguments)
        if thrown:
            raise RuntimeError(f"{name} threw in the target")
        return result

    def text(self, value: Value) -> str | None:
        return None if value.is_null else self.jdwp.string_value(int(value.value))


class Harness:
    def __init__(self, device: Device, apks: Path, timeout: float):
        self.device, self.apks, self.timeout = device, apks, timeout
        self.cli = VectorCli(device)
        self.results: dict[str, tuple[str, str]] = {}
        self.survived: dict[str, bool] = {}
        self.jdwp_available = device.prop("ro.debuggable") == "1"

    # -- bookkeeping -------------------------------------------------------------------
    def record(self, check: str, ok: bool | None, detail: str) -> None:
        status = "INCONCLUSIVE" if ok is None else ("PASS" if ok else "FAIL")
        self.results[check] = (status, detail)

    def needs_jdwp(self, *checks: str) -> bool:
        if self.jdwp_available:
            return True
        for check in checks:
            self.results[check] = ("UNEXECUTED", "ro.debuggable is not 1; JDWP oracle unavailable")
        return False

    # -- device steps ------------------------------------------------------------------
    def prepare(self, profile: str, package: str, target: str) -> None:
        for name in ("xax.generated", "com.example.module", TARGET_PACKAGE):
            self.device.uninstall(name)
        self.device.install(self.apks / f"target-{target}.apk")
        self.device.install(self.apks / f"{profile}.apk")
        self.cli("modules", "enable", package)
        self.cli("scope", "set", package, f"{TARGET_PACKAGE}/0")
        self.device.sh(f"am force-stop {TARGET_PACKAGE}")
        self.device.run("logcat", "-c", check=False)

    def launch(self, debug: bool = False) -> int:
        self.device.sh(f"am start {'-D ' if debug else ''}-n {TARGET_COMPONENT}")
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if pid := self.device.pid(TARGET_PACKAGE):
                return pid
            time.sleep(0.5)
        return 0

    def relaunch(self) -> None:
        self.device.sh(f"am start -f {CLEAR_TASK} -n {TARGET_COMPONENT}")

    def survives(self, profile: str, pid: int) -> bool:
        alive = bool(pid) and self.device.pid(TARGET_PACKAGE) == pid
        self.survived[profile] = alive
        return alive

    def module_loaded_log(self, package: str) -> bool:
        return f"Loaded module {package} successfully" in self.device.logcat()

    def suspend_in_activity(self, session: Session):
        requests = session.breakpoint(TARGET_ACTIVITY, "onCreate", "(Landroid/os/Bundle;)V")
        event = session.hit(requests, self.relaunch, self.timeout)
        session.clear(requests)
        return event

    def intercept_hits(self, session: Session, class_ids: set[int] | None = None) -> set[int]:
        """Class ids of the XaxHooker generations whose intercept runs on one relaunch."""
        requests = session.breakpoint(HOOKER_CLASS, "intercept")
        if class_ids is not None:
            requests = {request: class_id for request, class_id in requests.items() if class_id in class_ids}
        hits = set()
        event = session.hit(requests, self.relaunch, self.timeout)
        while event is not None:
            hits.add(requests[event.request_id])
            session.jdwp.resume()
            event = session.jdwp.wait_event({EVENT_BREAKPOINT}, set(requests), 5)
        session.clear(requests)
        return hits

    # -- profiles ----------------------------------------------------------------------
    def run_managed(self) -> None:
        self.prepare("managed", "xax.generated", "string")
        listed = "xax.generated" in self.cli("modules", "ls")
        self.record("discovery", listed, "modules ls lists xax.generated" if listed else "module not listed")
        scope = self.cli("scope", "ls", "xax.generated")
        pid = self.launch(debug=self.jdwp_available)
        if self.jdwp_available and pid:
            session = Session(self.device, pid)
            try:
                requests = session.breakpoint(MODULE_CLASS, "onPackageReady")
                session.jdwp.resume()
                hits = 0
                while session.jdwp.wait_event({EVENT_BREAKPOINT}, set(requests), 10 if hits else self.timeout):
                    hits += 1
                    session.jdwp.resume()
                session.clear(requests)
                if hits == 1:
                    self.record("package_callbacks", True, "onPackageReady hit once; onPackageLoaded is not overridden (API default)")
                else:
                    self.record("package_callbacks", None if hits == 0 else False,
                                f"onPackageReady hits={hits} (0 means the callback ran before the debugger attached)")
                loaded = bool(session.jdwp.classes_by_signature(MODULE_CLASS))
                self.record("java_init", loaded, "XaxModule loaded in the target" if loaded else "XaxModule absent")
                instances = session.modules()
                self.record("instantiated", len(instances) == 1, f"{len(instances)} XaxModule instance(s)")
            finally:
                session.close()
        else:
            self.needs_jdwp("package_callbacks", "java_init", "instantiated")
        loaded = self.module_loaded_log("xax.generated")
        self.record("module_prop", loaded, "Vector: Loaded module xax.generated successfully" if loaded else "no load line")
        self.record("scope", TARGET_PACKAGE in scope and loaded, f"scope ls: {scope[:200]}")
        self.survives("managed", pid)

    def run_native(self) -> None:
        self.prepare("native", "xax.generated", "string")
        pid = self.launch()
        time.sleep(3)
        log = self.device.logcat()
        maps = self.device.su(f"cat /proc/{pid}/maps") if pid else ""
        initialized = "Initialized native module" in log and "libxaxapp.so" in log
        self.record("native_init", initialized and "libxaxapp.so" in maps,
                    f"native_init log={initialized}, mapped={'libxaxapp.so' in maps}")
        self.survives("native", pid)

    def run_hook(self) -> None:
        self.prepare("hook", "xax.generated", "string")
        pid = self.launch()
        text = self.device.wait_text("OriginalArg", self.timeout)
        if self.needs_jdwp("hook_installed", "intercepted", "class_loader"):
            session = Session(self.device, pid)
            try:
                hookers = session.jdwp.classes_by_signature(HOOKER_CLASS)
                hits = self.intercept_hits(session)
            finally:
                session.close()
            self.record("hook_installed", bool(hookers), f"{len(hookers)} XaxHooker class(es) loaded by Vector in the target")
            self.record("intercepted", bool(hits), "XaxHooker.intercept reached on relaunch")
            self.record("class_loader", bool(hits), "target class resolved through PackageReadyParam.getClassLoader()")
        resumed = TARGET_PACKAGE in self.device.sh("dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity'")
        alive = self.survives("hook", pid)
        self.record("pass_through", text and resumed and alive, f"text={text}, resumed={resumed}, alive={alive}")

    def run_text_profile(self, profile: str, check: str, target: str, expected: str) -> None:
        self.prepare(profile, "com.example.module", target)
        pid = self.launch()
        shown = self.device.wait_text(expected, self.timeout)
        alive = self.survives(profile, pid)
        self.record(check, shown and alive, f"text {expected!r} shown={shown}, alive={alive}")

    def run_deopt(self) -> None:
        self.prepare("deopt", "xax.generated", "string")
        pid = self.launch(debug=self.jdwp_available)
        if self.needs_jdwp("deopt_order") and pid:
            session = Session(self.device, pid)
            try:
                deopt = session.breakpoint(WRAPPER_CLASS, "deoptimize")
                hook = session.breakpoint(WRAPPER_CLASS, "hook")
                labels = {**{request: "deoptimize" for request in deopt}, **{request: "hook" for request in hook}}
                session.jdwp.resume()
                order = []
                while (event := session.jdwp.wait_event({EVENT_BREAKPOINT}, set(labels), 10 if order else self.timeout)) is not None:
                    order.append(labels[event.request_id])
                    session.jdwp.resume()
                session.clear({**deopt, **hook})
            finally:
                session.close()
            if not order:
                self.record("deopt_order", None, "no wrapper call observed (onPackageReady ran before the debugger attached)")
            else:
                self.record("deopt_order", order[:2] == ["deoptimize", "hook"], f"call order {order}")
        self.survives("deopt", pid)

    def run_unhook(self) -> None:
        self.prepare("unhook", "xax.generated", "string")
        pid = self.launch()
        self.device.wait_text("OriginalArg", self.timeout)
        if self.needs_jdwp("retained_handle", "manual_unhook"):
            session = Session(self.device, pid)
            try:
                before = self.intercept_hits(session)
                event = self.suspend_in_activity(session)
                (module, class_id), = session.modules()
                handle = session.field(module, class_id, "xaxHookHandle", "Lio/github/libxposed/api/XposedInterface$HookHandle;")
                self.record("retained_handle", not handle.is_null and bool(before), f"handle null={handle.is_null}, intercepted before={bool(before)}")
                session.call(module, event.thread, "xaxUnhook", "()V")
                session.jdwp.resume()
                after = self.intercept_hits(session)
            finally:
                session.close()
            self.record("manual_unhook", bool(before) and not after, f"intercept before={bool(before)}, after={bool(after)}")
        self.survives("unhook", pid)

    def run_services(self) -> None:
        self.seed_remote_file("xax.generated")
        self.prepare("services", "xax.generated", "string")
        pid = self.launch()
        self.device.wait_text("OriginalArg", self.timeout)
        if self.needs_jdwp("module_services"):
            session = Session(self.device, pid)
            try:
                event = self.suspend_in_activity(session)
                (module, _class_id), = session.modules()
                name = session.text(session.call(module, event.thread, "xaxFrameworkName", "()Ljava/lang/String;"))
                version = session.text(session.call(module, event.thread, "xaxFrameworkVersion", "()Ljava/lang/String;"))
                session.jdwp.resume()
            finally:
                session.close()
            self.record("module_services", name == "Vector" and bool(version), f"framework {name!r} version {version!r}")
        self.survives("services", pid)

    def run_remote_preferences(self) -> None:
        self.prepare("remote_preferences", "xax.generated", "string")
        pid = self.launch()
        self.device.wait_text("OriginalArg", self.timeout)
        if self.needs_jdwp("remote_preferences"):
            session = Session(self.device, pid)
            try:
                event = self.suspend_in_activity(session)
                (module, _class_id), = session.modules()
                group = session.jdwp.create_string("xax")
                prefs = session.call(module, event.thread, "xaxRemotePreferencesIfSupported",
                                     "(Ljava/lang/String;)Landroid/content/SharedPreferences;", group)
                detail, ok = "preferences null (PROP_CAP_REMOTE not advertised)", False
                if not prefs.is_null:
                    key, fallback = session.jdwp.create_string("xax.absent"), session.jdwp.create_string("fallback")
                    read = session.text(session.call(module, event.thread, "xaxPrefString",
                                                     "(Landroid/content/SharedPreferences;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                                                     prefs, key, fallback))
                    contains = session.call(module, event.thread, "xaxPrefContains",
                                            "(Landroid/content/SharedPreferences;Ljava/lang/String;)Z", prefs, key).value
                    number = session.call(module, event.thread, "xaxPrefInt",
                                          "(Landroid/content/SharedPreferences;Ljava/lang/String;I)I", prefs, key, Value(ord("I"), 7)).value
                    ok = read == "fallback" and contains is False and number == 7
                    detail = f"string default={read!r}, contains={contains}, int default={number}"
                session.jdwp.resume()
            finally:
                session.close()
            self.record("remote_preferences", ok, detail)
        self.survives("remote_preferences", pid)

    def seed_remote_file(self, package: str) -> None:
        directory = f"/data/adb/lspd/modules/0/{package}/files"
        self.device.su(f"mkdir -p {directory} && printf %s {shlex.quote(REMOTE_FILE_CONTENT)} > {directory}/{REMOTE_FILE}"
                       f" && chcon -R u:object_r:xposed_data:s0 {directory} && chmod 755 {directory} && chmod 644 {directory}/{REMOTE_FILE}")

    def run_remote_files(self) -> None:
        self.seed_remote_file("xax.generated")
        self.prepare("remote_files", "xax.generated", "string")
        pid = self.launch()
        self.device.wait_text("OriginalArg", self.timeout)
        if self.needs_jdwp("remote_files"):
            session = Session(self.device, pid)
            try:
                event = self.suspend_in_activity(session)
                (module, _class_id), = session.modules()
                listed = session.call(module, event.thread, "xaxListRemoteFilesIfSupported", "()[Ljava/lang/String;")
                names = [] if listed.is_null else [session.jdwp.string_value(int(item.value)) for item in session.jdwp.array_values(int(listed.value))]
                opened = session.call(module, event.thread, "xaxOpenRemoteFileIfSupported",
                                      "(Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;", session.jdwp.create_string(REMOTE_FILE))
                size = None if opened.is_null else session.call(int(opened.value), event.thread, "getStatSize", "()J").value
                session.jdwp.resume()
            finally:
                session.close()
            self.record("remote_files", REMOTE_FILE in names and size == len(REMOTE_FILE_CONTENT), f"listed={names}, opened size={size}")
        self.survives("remote_files", pid)

    def reload_state(self, session: Session, old_class: int):
        """Fields of the newest XaxModule generation after a hot reload."""
        event = self.suspend_in_activity(session)
        newer = [(obj, class_id) for obj, class_id in session.modules() if class_id != old_class]
        target_loader = session.jdwp.class_loader(session.jdwp.classes_by_signature(TARGET_ACTIVITY)[0])
        state = None
        if newer:
            module, class_id = newer[0]
            loader = session.field(module, class_id, "xaxReloadClassLoader", "Ljava/lang/ClassLoader;")
            handle = session.field(module, class_id, "xaxHookHandle", "Lio/github/libxposed/api/XposedInterface$HookHandle;")
            handle_id = None if handle.is_null else session.text(session.call(int(handle.value), event.thread, "getId", "()Ljava/lang/String;"))
            state = {"loader_is_target": loader.value == target_loader, "handle_null": handle.is_null, "handle_id": handle_id}
        session.jdwp.resume()
        return state

    def run_hot_reload(self, profile: str) -> None:
        self.prepare(profile, "xax.generated", "string")
        pid = self.launch()
        self.device.wait_text("OriginalArg", self.timeout)
        checks = ("stable_hook_id", "hot_reload_callbacks", "saved_state", "replace_hook") if profile == "hot_reload" else ("stable_id_validation",)
        if not self.needs_jdwp(*checks):
            self.survives(profile, pid)
            return
        session = Session(self.device, pid)
        try:
            (old_module, old_class), = session.modules()
            event = self.suspend_in_activity(session)
            handle = session.field(old_module, old_class, "xaxHookHandle", "Lio/github/libxposed/api/XposedInterface$HookHandle;")
            old_id = None if handle.is_null else session.text(session.call(int(handle.value), event.thread, "getId", "()Ljava/lang/String;"))
            session.jdwp.resume()
            old_hookers = set(session.jdwp.classes_by_signature(HOOKER_CLASS))
            self.device.install(self.apks / f"{profile}.reload.apk")  # versionCode 2: Vector auto hot reload
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline and "Hot reloaded xax.generated" not in self.device.logcat():
                time.sleep(1)
            reloaded_log = "Hot reloaded xax.generated" in self.device.logcat()
            state = self.reload_state(session, old_class)
            hits = self.intercept_hits(session)
        finally:
            session.close()
        new_hookers = hits - old_hookers
        if profile == "hot_reload":
            self.record("hot_reload_callbacks", reloaded_log and state is not None and state["loader_is_target"],
                        f"log={reloaded_log}, new generation state={state}")
            self.record("saved_state", bool(state and state["loader_is_target"]), f"state={state}")
            self.record("stable_hook_id", old_id == "xax.primary" and bool(state) and state["handle_id"] == "xax.primary",
                        f"before={old_id!r}, after={state and state['handle_id']!r}")
            self.record("replace_hook", bool(new_hookers) and not (hits & old_hookers),
                        f"new-generation hooker hits={len(new_hookers)}, old hooker hits={len(hits & old_hookers)}")
        else:
            self.record("stable_id_validation", bool(state) and state["handle_null"] and bool(hits & old_hookers) and not new_hookers,
                        f"state={state}, old hooker still intercepts={bool(hits & old_hookers)}")
        self.survives(profile, pid)

    def run_protective(self) -> None:
        self.prepare("protective", "com.example.module", "string")
        pid = self.launch()
        hooked = self.device.wait_text("HookedResult", self.timeout)
        if self.needs_jdwp("protective"):
            session = Session(self.device, pid)
            try:
                requests = session.breakpoint(HOOKER_CLASS, "intercept")
                event = session.hit(requests, self.relaunch, self.timeout)
                thrown = False
                if event is not None:
                    exception_class = session.jdwp.first_loaded_class(*THROWABLES)
                    exception = session.jdwp.new_instance(exception_class, event.thread, session.method(exception_class, "<init>", "()V"))
                    session.jdwp.stop_thread(event.thread, exception)  # thrown before Chain.proceed()
                    thrown = True
                session.clear(requests)
                session.jdwp.resume()
            finally:
                session.close()
            original = self.device.wait_text("OriginalArg", self.timeout)
            alive = self.device.pid(TARGET_PACKAGE) == pid
            self.relaunch()
            restored = self.device.wait_text("HookedResult", self.timeout)
            self.record("protective", hooked and thrown and original and alive and restored,
                        f"hooked={hooked}, fault injected={thrown}, original shown={original}, alive={alive}, hook still active={restored}")
        self.survives("protective", pid)

    def run_all(self) -> None:
        self.cli("config", "set", "verbose-log", "true")
        steps = (
            self.run_managed, self.run_native, self.run_hook, self.run_deopt, self.run_unhook,
            lambda: self.run_text_profile("result", "result_replacement", "zero", "Hooked"),
            lambda: self.run_text_profile("argument", "argument_replacement", "string", "HookedArg"),
            lambda: self.run_text_profile("combined", "combined_replacement", "string", "HookedResult"),
            self.run_services, self.run_remote_preferences, self.run_remote_files,
            lambda: self.run_hot_reload("hot_reload"), lambda: self.run_hot_reload("hot_reload_id_mismatch"),
            self.run_protective,
        )
        for step in steps:
            try:
                step()
            except (RuntimeError, LookupError, JdwpError, ConnectionError, OSError, ValueError, subprocess.SubprocessError) as error:
                print(f"step failed: {error}", file=sys.stderr)
        died = [name for name, alive in self.survived.items() if not alive]
        self.record("process_survives", bool(self.survived) and not died, f"profiles run={len(self.survived)}, died={died}")


def run(device: Device, apks: Path, vector_zip: Path | None, timeout: float) -> dict[str, object]:
    evidence = plan_evidence()
    environment = probe_environment(device, vector_zip)
    evidence["environment"] = environment
    pin = json.loads(PIN.read_text(encoding="utf-8"))
    blockers = []
    if "arm64-v8a" not in environment["abi_list"]:
        blockers.append("device does not advertise arm64-v8a")
    if not environment["root_uid0"]:
        blockers.append("su -c id is not uid 0")
    if not vector_version_ok(environment["vector_module_prop"], pin["vector"]["minimum_release"]):
        blockers.append(f"Vector {pin['vector']['minimum_release']} or newer is not installed as zygisk_vector")
    if blockers:
        evidence["missing_requirement"] = "; ".join(blockers)
        return evidence
    harness = Harness(device, apks, timeout)
    harness.run_all()
    for row in evidence["checks"]:
        status, detail = harness.results.get(row["id"], ("UNEXECUTED", "step did not reach this check"))
        row["status"], row["detail"] = status, detail
    evidence["label"] = "EXECUTED"
    evidence["missing_requirement"] = None
    evidence["jdwp_available"] = harness.jdwp_available
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", action="store_true", help="write the UNEXECUTED plan without a device")
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"))
    parser.add_argument("--apks", type=Path, help="signed profiles (default: build them now)")
    parser.add_argument("--vector-zip", type=Path, help="the installed Vector zip, to record its SHA-256")
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("XAX_VECTOR_TIMEOUT", "90")))
    parser.add_argument("--evidence", type=Path, default=EVIDENCE)
    arguments = parser.parse_args()
    if arguments.plan:
        evidence = plan_evidence()
    else:
        with tempfile.TemporaryDirectory() as directory:
            apks = arguments.apks
            if apks is None:
                from benchmarks.bench_android_vector_profiles import signed_apks
                apks = Path(directory)
                for name, data in signed_apks().items():
                    (apks / name).write_bytes(data)
            evidence = run(Device(arguments.serial), apks, arguments.vector_zip, arguments.timeout)
    arguments.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts = {status: sum(row["status"] == status for row in evidence["checks"]) for status in STATUSES}
    print(arguments.evidence)
    print(f"{evidence['label']}: " + ", ".join(f"{count} {status}" for status, count in counts.items()))
    return 0 if evidence["label"] == "UNEXECUTED" or counts["FAIL"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
