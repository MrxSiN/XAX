"""#48 (ADR-411 and its amendments): a libxposed JVM module whose v3 carrier names lifecycle entries.

The v3 carrier ``android-libxposed-jvm-module-v3`` keeps the v1/v2 record, makes ``branding`` optional and adds
``entries``: ``module_loaded`` and/or ``system_server_starting``, each a module function's CID. The XAX Android
program lowers each entry by its own JVM run, as class ``xax/P<16 hex>`` with method ``entry``, and the generated
``Module`` class forwards ``onModuleLoaded(ModuleLoadedParam)`` and ``onSystemServerStarting(SystemServerStartingParam)``
to them.

There is no Python reference for v3 (ADR-405): the oracle is execution.
- the XAX Android program builds the module and rejects the bad carriers (Linux x86-64, the native programs);
- ``dexdump -d`` (``XAX_DEXDUMP``) shows each ``Module`` method invoking its entry's ``xax/P…->entry``;
- ART (``XAX_ADB``, a connected device): ``dalvikvm64`` constructs ``Module`` against stub libxposed classes and calls
  each method; each entry prints its own line.

The store is built with ``xax_construct`` as a v1 module, then its carrier is replaced by a v3 one (test fixture code:
the module object is rebuilt over the new carrier, nothing is decoded in Python).
"""

from __future__ import annotations

import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
API = "Lio/github/libxposed/api/"
IFACE = "jvm:%sXposedInterface;" % API
PARAM = {"ready": "PackageReadyParam", "module_loaded": "ModuleLoadedParam", "system_server_starting": "SystemServerStartingParam"}
PREFIX_V3 = b"android-libxposed-jvm-module-v3\0"
MODULE = dict(package="org.example.lifecycle", module_class="org.example.Lifecycle", scopes=["system"], version_code=3)
PRINT = [["call.foreign", [], ["jvm:Ljava/io/PrintStream;"], {"entity": {"jvm": ["jvm-getstatic", "java/lang/System", "out:Ljava/io/PrintStream;"]}}]]


def _function(name, param, line=None):
    params = [IFACE, "jvm:%sXposedModuleInterface$%s;" % (API, PARAM[param])]
    nodes = []
    if line is not None:
        nodes = PRINT + [
            ["call.foreign", [], ["jvm:Ljava/lang/String;"], {"entity": {"jvm": ["jvm-ldc", "java/lang/String", line]}}],
            ["call.foreign", ["n0", "n1"], [], {"entity": {"jvm": ["jvm-invokevirtual", "java/io/PrintStream", "println(Ljava/lang/String;)V"]}}],
        ]
    return {"name": name, "params": params, "returns": [], "blocks": [{"params": params, "nodes": nodes, "end": ["ret", []]}]}


def _constructed(functions):
    from xax_construct import construct

    request = {"format": "xax-construct-v1", "platform": "android-libxposed", "functions": functions,
               "package": {"name": "lifecycle", "entries": {"app": "main"}, "release": "app", "android": dict(MODULE)}}
    return construct(request)


def v3_store(entries, functions=None, branding=None):
    """``(reader, package view, target, package entry CID, functions)``: the constructed module with a v3 carrier whose
    ``entries`` maps keys to function names (or raw values when not a function's name)."""
    from xax_android_libxposed_jvm import find_carriers
    from xax_build import decode_package, decode_request, decode_snapshot
    from xax_compiler import Cursor, Kind, StoreReader, object_with_refs, target

    functions = functions or [_function("main", "ready"), _function("ml", "module_loaded", "onModuleLoaded ran"),
                              _function("sss", "system_server_starting", "onSystemServerStarting ran")]
    built = _constructed(functions)
    reader = built.reader
    snapshot = decode_snapshot(reader.get(reader.root_cid), reader.get)
    request = decode_request(reader.get(snapshot.request_root), reader.get)
    package = decode_package(reader.get(request.package_root), reader.get)
    old, _ = find_carriers(reader, package)
    identity = Cursor(old.body, "carrier").byte_string()
    record = json.loads(identity[len(PREFIX_V3):])
    record["entries"] = {k: (built.functions[v].cid.hex() if v in built.functions else v) for k, v in entries.items()}
    if branding is not None:
        record["branding"] = branding
    carrier = target(PREFIX_V3 + json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
    (module_cid,) = package.modules
    module = reader.get(module_cid)
    members = [reader.get(c) for c in module.references if c != old.cid] + [carrier]
    new_module = object_with_refs(Kind.MODULE, members)
    root = object_with_refs(Kind.PROGRAM_ROOT, [new_module])
    keep = [o for o in reader.objects() if o.kind not in (Kind.MODULE, Kind.PROGRAM_ROOT, Kind.PACKAGE, Kind.BUILD) and o.cid != old.cid]
    store = StoreReader.from_objects(root.cid, [*keep, carrier, new_module, root])
    view = types.SimpleNamespace(modules=(new_module.cid,), logical_identity=package.logical_identity)
    entry = dict(package.build_entries)[request.build_entry]
    return store, view, reader.get(request.target_root), entry, built.functions


def build_v3(entries, **options):
    """The APK bytes, or the rejection's diagnostic, as the XAX Android program decides (never the bootstrap)."""
    from xax_compiler import XaxError
    from xax_selfhost_android import android_with_xax

    store, view, target_object, entry, functions = v3_store(entries, **options)
    try:
        return android_with_xax(store, view, target_object, entry, required=True, external_inputs={}), functions
    except XaxError as error:
        return error.diagnostic, functions


def _class(cid: bytes) -> str:
    return "Lxax/P%s;" % cid.hex()[:16]


STUBS = {
    "io/github/libxposed/api/XposedInterface.java": "package io.github.libxposed.api;\npublic interface XposedInterface {}\n",
    "io/github/libxposed/api/XposedModuleInterface.java": """package io.github.libxposed.api;
public interface XposedModuleInterface {
    interface ModuleLoadedParam {}
    interface PackageReadyParam {}
    interface SystemServerStartingParam {}
}
""",
    "io/github/libxposed/api/XposedModule.java": """package io.github.libxposed.api;
public abstract class XposedModule implements XposedInterface, XposedModuleInterface {
    public XposedModule() {}
}
""",
    "xaxtest/Harness.java": """package xaxtest;
import io.github.libxposed.api.XposedModuleInterface;
public final class Harness {
    public static void main(String[] args) throws Exception {
        Object module = Class.forName(args[0]).getDeclaredConstructor().newInstance();
        Class<?> c = module.getClass();
        c.getMethod("onModuleLoaded", XposedModuleInterface.ModuleLoadedParam.class).invoke(module, (Object) null);
        c.getMethod("onSystemServerStarting", XposedModuleInterface.SystemServerStartingParam.class).invoke(module, (Object) null);
        c.getMethod("onPackageReady", XposedModuleInterface.PackageReadyParam.class).invoke(module, (Object) null);
        System.out.println("harness done");
    }
}
""",
}


def _adb_device(adb: str) -> bool:
    try:
        listing = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=60).stdout
    except OSError:
        return False
    return any(line.endswith("\tdevice") for line in listing.splitlines()[1:])


def _host_path(path: str, tool: str) -> str:
    if tool.lower().endswith(".exe") and os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, check=True).stdout.strip()
    return path


@unittest.skipUnless(LINUX_X86_64, "the XAX Android program runs natively on Linux x86-64")
class LifecycleTests(unittest.TestCase):
    def test_module_and_forwarding(self):
        apk, functions = build_v3({"module_loaded": "ml", "system_server_starting": "sss"})
        self.assertIsInstance(apk, bytes, apk)
        with zipfile.ZipFile(io.BytesIO(apk)) as archive:
            names = set(archive.namelist())
            dexes = [archive.read(n) for n in sorted(archive.namelist()) if n.startswith("classes") and n.endswith(".dex")]
            self.assertEqual(archive.read("META-INF/xposed/java_init.list"), b"org.example.Lifecycle\n")
        self.assertTrue({"AndroidManifest.xml", "classes.dex", "classes2.dex"} <= names)
        (code,) = [d for d in dexes if b"Lxax/P" in d and b"onPackageReady" not in d]
        (module,) = [d for d in dexes if b"onPackageReady" in d]
        for name in ("main", "ml", "sss"):
            self.assertIn(_class(functions[name].cid)[1:-1].encode(), code)
        for method in (b"onModuleLoaded", b"onSystemServerStarting", b"onPackageReady"):
            self.assertIn(method, module)
        dexdump, adb = os.environ.get("XAX_DEXDUMP"), os.environ.get("XAX_ADB")
        with tempfile.TemporaryDirectory(prefix="xax-lifecycle-", dir=os.environ.get("XAX_JAVA_TMP")) as directory:
            paths = {}
            for name, data in (("classes.dex", code), ("classes2.dex", module)):
                paths[name] = os.path.join(directory, name)
                with open(paths[name], "wb") as handle:
                    handle.write(data)
            if dexdump:
                dumped = subprocess.run([dexdump, "-d", _host_path(paths["classes2.dex"], dexdump)], capture_output=True, text=True, timeout=120)
                self.assertEqual(dumped.returncode, 0, dumped.stderr[-2000:])
                for method, name in (("onModuleLoaded", "ml"), ("onSystemServerStarting", "sss"), ("onPackageReady", "main")):
                    at = dumped.stdout.index("name          : '%s'" % method)
                    code_at = dumped.stdout.index("invoke-static", at)
                    self.assertIn("%s.entry:" % _class(functions[name].cid), dumped.stdout[code_at:code_at + 300], method)
            if not (adb and _adb_device(adb)):
                return
            self._art(directory, paths, adb)

    def _art(self, directory, paths, adb):
        javac, d8 = shutil.which("javac"), os.environ.get("XAX_D8")
        if not (javac and d8):
            self.skipTest("the ART harness needs javac and XAX_D8")
        source = os.path.join(directory, "src")
        for name, text in STUBS.items():
            os.makedirs(os.path.dirname(os.path.join(source, name)), exist_ok=True)
            with open(os.path.join(source, name), "w") as handle:
                handle.write(text)
        classes = os.path.join(directory, "classes")
        subprocess.run([javac, "--release", "8", "-d", classes, *(os.path.join(source, name) for name in STUBS)], check=True, capture_output=True)
        out = os.path.join(directory, "harness")
        os.makedirs(out)
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(classes) for f in fs]
        subprocess.run([d8, "--min-api", "28", "--output", _host_path(out, d8), *(_host_path(f, d8) for f in files)], check=True, capture_output=True)
        remote = "/data/local/tmp/xax-lifecycle-%d" % os.getpid()
        subprocess.run([adb, "shell", "rm -rf %s && mkdir -p %s" % (remote, remote)], check=True, capture_output=True)
        for local, name in ((paths["classes.dex"], "code.dex"), (paths["classes2.dex"], "module.dex"), (os.path.join(out, "classes.dex"), "harness.dex")):
            subprocess.run([adb, "push", _host_path(local, adb), "%s/%s" % (remote, name)], check=True, capture_output=True)
        run = subprocess.run([adb, "shell", "cd %s && dalvikvm64 -cp harness.dex:module.dex:code.dex xaxtest.Harness org.example.Lifecycle; echo status=$?" % remote],
                             capture_output=True, text=True, timeout=300)
        subprocess.run([adb, "shell", "rm -rf " + remote], capture_output=True)
        lines = run.stdout.replace("\r\n", "\n").split("\n")
        self.assertEqual([l for l in lines if l], ["onModuleLoaded ran", "onSystemServerStarting ran", "harness done", "status=0"], run.stdout + run.stderr)

    def test_one_entry(self):
        apk, functions = build_v3({"system_server_starting": "sss"})
        self.assertIsInstance(apk, bytes, apk)
        with zipfile.ZipFile(io.BytesIO(apk)) as archive:
            (module,) = [archive.read(n) for n in archive.namelist() if n.endswith(".dex") and b"onPackageReady" in archive.read(n)]
        self.assertIn(b"onSystemServerStarting", module)
        self.assertNotIn(b"onModuleLoaded", module)

    def test_rejections(self):
        def rule(entries, **options):
            outcome, _ = build_v3(entries, **options)
            self.assertNotIsInstance(outcome, bytes, entries)
            return outcome.rule, outcome.actual

        self.assertEqual(rule({}), ("LIBXPOSED-JVM-ENTRIES", "no entry"))
        self.assertEqual(rule({"module_loaded": "main"}), ("LIBXPOSED-JVM-ENTRIES", "the package entry"))
        self.assertEqual(rule({"module_loaded": "ml", "on_boot": "ml"}), ("LIBXPOSED-JVM-ENTRIES", "an unknown key"))
        self.assertEqual(rule({"module_loaded": "ab" * 32}), ("LIBXPOSED-JVM-ENTRIES", "no such function"))
        self.assertEqual(rule({"module_loaded": "xyz"}), ("LIBXPOSED-JVM-ENTRIES", "not a function CID"))
        # An entry whose signature is not its callback's: its expected descriptor.
        outcome, functions = build_v3({"module_loaded": "sss"})
        self.assertEqual(outcome.rule, "LIBXPOSED-JVM-ENTRY")
        self.assertEqual(outcome.expected, "(%sXposedInterface;%sXposedModuleInterface$ModuleLoadedParam;)V" % (API, API))
        self.assertIn("SystemServerStartingParam", str(outcome.actual))


if __name__ == "__main__":
    unittest.main()
