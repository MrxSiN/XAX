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
SEED = Path(__file__).resolve().parents[1] / "bootstrap" / "seed" / "xaxc-linux-x86_64"
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

    def test_two_result_function_rejects_with_its_cid(self):
        """Issue #137: ``xaxc build`` of a module with a two-result function rejects with the reference's
        ``JVM-SINGLE-RESULT`` record (``xax_jvm._signature``), naming the function, instead of declining with none."""
        two = {"name": "two", "params": ["b32"], "returns": ["b32", "b32"], "blocks": [{"params": ["b32"], "nodes": [], "end": ["ret", ["p0", "p0"]]}]}
        main = _function("main", "ready")
        main["blocks"][0]["nodes"] = [["call.direct", [["b32", 7]], ["b32", "b32"], {"entity": {"fn": "two"}}]]
        built = _constructed([two, main])
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "module.xax").write_bytes(built.reader.data)
            status = subprocess.run([str(SEED), "build", "module.xax", "out", "provenance"], cwd=work, capture_output=True).returncode
            self.assertEqual(status, 1)  # a rejection: the output is the record
            subprocess.run([str(SEED), "edit", "module.xax", "out", "out.txt"], cwd=work, check=True, capture_output=True)
            lines = dict(line.split(" ", 1) for line in (work / "out.txt").read_text().splitlines())
        self.assertEqual((lines["code"], lines["rule"], lines["entity"]), ("XAX.JVM.ABI", "JVM-SINGLE-RESULT", built.functions["two"].cid.hex()))
        self.assertEqual((lines["expected"], lines["actual"]), ("at most one machine result", "2"))

    def test_module_prop_hot_reload_and_min_api(self):
        """Issue #133 (ADR-415): a v3 record's ``"auto_hot_reload": true`` adds ``autoHotReload=true`` to module.prop;
        false, absent or v1 add nothing; ``minApiVersion`` is the metadata carrier's ``min_api_version``. The carriers
        are swapped by one XAXEDIT1 record (a test fixture), and ``xaxc build`` makes the APK."""
        from xax_android_libxposed_jvm import find_carriers
        from xax_build import decode_package, decode_request, decode_snapshot
        from xax_compiler import Cursor
        from xax_libxposed import LibxposedModuleDescription, decode_libxposed_module, libxposed_module_semantics
        from xax_selfhost_edit import REPLACE_REFERENCE, edit_record
        from xax_compiler import target

        built = _constructed([_function("main", "ready"), _function("ml", "module_loaded", "loaded")])
        reader = built.reader
        snapshot = decode_snapshot(reader.get(reader.root_cid), reader.get)
        package = decode_package(reader.get(decode_request(reader.get(snapshot.request_root), reader.get).package_root), reader.get)
        (module,) = package.modules
        carrier, metadata = find_carriers(reader, package)
        record = json.loads(Cursor(carrier.body, "carrier").byte_string().split(b"\0", 1)[1])

        def module_prop(hot=None, v3=True, min_api=None) -> bytes:
            swaps = []
            if v3:
                fields = dict(record, entries={"module_loaded": built.functions["ml"].cid.hex()})
                if hot is not None:
                    fields["auto_hot_reload"] = hot
                swaps.append((carrier, target(PREFIX_V3 + json.dumps(fields, sort_keys=True, separators=(",", ":")).encode())))
            if min_api is not None:
                old = decode_libxposed_module(metadata)
                swaps.append((metadata, libxposed_module_semantics(LibxposedModuleDescription(
                    min_api, old.target_api_version, old.static_scope, old.java_entries, old.native_entries, old.scopes))))
            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                (work / "m.xax").write_bytes(reader.data)
                commands = [["build", "m.xax", "o.apk", "o.prov"]]
                if swaps:
                    (work / "e.edit").write_bytes(edit_record([(REPLACE_REFERENCE, module, a.cid, b.cid) for a, b in swaps], reader.root_cid, [b for _, b in swaps]))
                    commands = [["edit", "m.xax", "e.edit", "o.xax"], ["verify", "o.xax", "o.rec"], ["build", "o.xax", "o.apk", "o.prov"]]
                for command in commands:
                    subprocess.run([str(SEED), *command], cwd=work, check=True, capture_output=True)
                with zipfile.ZipFile(io.BytesIO((work / "o.apk").read_bytes())) as archive:
                    return archive.read("META-INF/xposed/module.prop")

        base = b"minApiVersion=102\ntargetApiVersion=102\nstaticScope=true\n"
        self.assertEqual(module_prop(hot=True), base + b"autoHotReload=true\n")
        for case in ({"hot": False}, {}, {"v3": False}):
            with self.subTest(**case):
                self.assertEqual(module_prop(**case), base)
        self.assertEqual(module_prop(min_api=101), base.replace(b"102\nt", b"101\nt"))


if __name__ == "__main__":
    unittest.main()
