"""Run XAX-emitted Android arm64 libraries under Android's own linker and libc.

No device or emulator is needed.  ``qemu-aarch64`` (user mode) runs AArch64
processes on the host; the root filesystem holds ``linker64`` and bionic
(``libc``/``libdl``/``libm``) extracted from an official Android system
image.  Loaders are built with the NDK.  What this executes:

* the platform-contract probe: file open/write/read/close, pthread
  create/join, and a loopback socket round trip through bionic imports;
* the libxposed native entry: ``native_init`` returns a callback, which runs;
* every JNI fixture export, against a ``JNIEnv`` whose 233 slots are
  recording stubs generated from the NDK's ``jni.h``.  Each export's calls are
  compared by *official slot name* (and arguments) with the intended sequence,
  so XAX's table offsets are checked against the platform header rather than
  against themselves.

This is AArch64 machine code under Android's dynamic linker and C library.
It is not ART, not a device kernel, and not a Java VM.

Environment: ``ANDROID_NDK_HOME`` (default ``/opt/android/android-ndk-r28c``),
``XAX_ANDROID_ROOT`` (default ``/opt/android/root``), and ``qemu-aarch64-static``
on ``PATH``.  Run from ``compiler/``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "android_bionic_qemu_evidence.json"
NDK = Path(os.environ.get("ANDROID_NDK_HOME", "/opt/android/android-ndk-r28c"))
ROOT = Path(os.environ.get("XAX_ANDROID_ROOT", "/opt/android/root"))
TOOLCHAIN = NDK / "toolchains/llvm/prebuilt/linux-x86_64"
JNI_H = TOOLCHAIN / "sysroot/usr/include/jni.h"
QEMU = shutil.which("qemu-aarch64-static") or shutil.which("qemu-aarch64")

# Sentinel handles the harness passes in; stub results are distinct sentinels.
OBJ, MID, CLS, RUNNABLE = 0x1111, 0x2222, 0x3333, 0x5555
RESULTS = {"GetVersion": 0x10006, "NewGlobalRef": 0x4444, "GetObjectClass": 0x6666, "GetMethodID": 0x7777, "NewObject": 0x8888, "CallBooleanMethodA": 1}


def jni_slots(tag: str = "struct JNINativeInterface {") -> list[str]:
    """Slot names in declaration order, from the NDK header."""
    source = JNI_H.read_text(encoding="utf-8")
    body = source[source.index(tag):]
    body = body[: body.index("};")]
    return [match.group(1).split()[-1] if match.group(1) else match.group(2) for match in re.finditer(r"(void\*\s+reserved\d)|\(\*(\w+)\)", body)]


def _jvalue_argument(name: str) -> int | None:
    """Register index of the ``const jvalue*`` argument of an ``...A`` slot, if any."""
    if not (name.endswith("MethodA") or name == "NewObjectA"):
        return None
    return 4 if name.startswith("CallNonvirtual") else 3


# (export, C prototype, C call expression, expected calls as (slot, arguments...), expected result, library source)
# Arguments: integers are compared exactly; "env"/"vm"/"pid" are the harness's JNIEnv*, JavaVM*, and
# process id; "*" accepts any value; "jv:a,b" compares the first 64-bit words of the jvalue array.
# The library source is a ``bench_android_jni``/``bench_android_arm64`` fixture name or ``apk:<APK>``.
CASES = (
    ("jni_get_version_probe", "uint32_t(void*)", "f(env)", (("GetVersion", "env"),), RESULTS["GetVersion"], "jni:get_version"),
    ("jni_global_ref_roundtrip", "void(void*,void*)", "f(env,(void*)0x1111)",
     (("NewGlobalRef", "env", OBJ), ("DeleteGlobalRef", "env", RESULTS["NewGlobalRef"])), None, "jni:global_ref_roundtrip"),
    ("jni_set_visibility_cached", "void(void*,void*,void*,uint32_t)", "f(env,(void*)0x1111,(void*)0x2222,8)",
     (("CallVoidMethodA", "env", OBJ, MID, "jv:8"), ("ExceptionClear", "env")), None, "jni:cached_set_visibility"),
    ("jni_set_clickable_cached", "void(void*,void*,void*,uint8_t)", "f(env,(void*)0x1111,(void*)0x2222,1)",
     (("CallVoidMethodA", "env", OBJ, MID, "jv:1"), ("ExceptionClear", "env")), None, "jni:cached_set_clickable"),
    ("jni_post_delayed_cached", "uint8_t(void*,void*,void*,void*,uint64_t)", "f(env,(void*)0x1111,(void*)0x2222,(void*)0x5555,250)",
     (("CallBooleanMethodA", "env", OBJ, MID, f"jv:{RUNNABLE},250"), ("ExceptionClear", "env")), 1, "jni:cached_post_delayed"),
    ("jni_resolve_call_twice_release", "void(void*,void*,const char*,const char*,uint64_t)", 'f(env,(void*)0x1111,NAME,SIG,42)',
     (("GetObjectClass", "env", OBJ), ("NewGlobalRef", "env", RESULTS["GetObjectClass"]), ("DeleteLocalRef", "env", RESULTS["GetObjectClass"]),
      ("GetMethodID", "env", RESULTS["NewGlobalRef"], "NAME", "SIG"),
      ("CallVoidMethodA", "env", OBJ, RESULTS["GetMethodID"], "jv:42"), ("ExceptionClear", "env"),
      ("CallVoidMethodA", "env", OBJ, RESULTS["GetMethodID"], "jv:42"), ("ExceptionClear", "env"),
      ("DeleteGlobalRef", "env", RESULTS["NewGlobalRef"])), None, "jni:loader_relative_method_cache"),
    ("jni_set_value_cached", "void(void*,void*,void*,uint64_t)", "f(env,(void*)0x1111,(void*)0x2222,77)",
     (("CallVoidMethodA", "env", OBJ, MID, "jv:77"), ("ExceptionClear", "env")), None, "jni:cached_app_set_value"),
    ("jni_release_target_method_cache", "void(void*,void*)", "f(env,(void*)0x3333)", (("DeleteGlobalRef", "env", CLS),), None, "jni:release_method_cache"),
    ("jni_new_xax_click_listener", "void*(void*,void*,void*)", "f(env,(void*)0x3333,(void*)0x2222)",
     (("NewObject", "env", CLS, MID),), RESULTS["NewObject"], "jni:generated_listener_construction"),  # zero-argument <init>()V: no varargs payload
    # JNI_OnLoad asks the JavaVM for a JNI 1.6 environment and returns JNI_VERSION_1_6.
    ("JNI_OnLoad", "uint32_t(void*,void*)", "f(vm,0)", (("GetEnv", "vm", "*", 0x10006),), 0x10006, "arm64:jni_onload"),
    # A bionic import: the result is this process's id.
    ("probe_getpid", "uint32_t(void)", "f()", (), "pid", "arm64:bionic_import"),
    # The two native callbacks inside the APK that ran on a Pixel 8 Pro, unchanged.
    ("Java_xax_generated_XaxActivity_xaxOnCreate", "void(void*,void*)", "f(env,(void*)0x1111)", (), None, "apk:android_minimal_activity.apk"),
    ("Java_xax_generated_XaxOnClickListener_xaxOnClick", "void(void*,void*)", "f(env,(void*)0x1111)", (), None, "apk:android_minimal_activity.apk"),
)


def _harness_source(slots: list[str], vm_first: int) -> str:
    """``slots`` is the JNIEnv table followed by the JavaVM table, which starts at ``vm_first``."""
    names = ",".join(f'"{name}"' for name in slots)
    jv = ",".join(str(-1 if _jvalue_argument(name) is None else _jvalue_argument(name)) for name in slots)
    results = "".join(f"  ret[{slots.index(name)}]={value};\n" for name, value in RESULTS.items() if name in slots)
    stubs = "".join(
        f"static u64 s{index}(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h){{u64 r[8]={{a,b,c,d,e,f,g,h}};rec({index},r);return ret[{index}];}}\n"
        for index in range(len(slots))
    )
    table = ",".join(f"(void*)s{index}" for index in range(len(slots)))
    calls = ""
    for export, prototype, call, _expected, _result, _source in CASES:
        result_type, arguments = prototype.split("(", 1)
        report = f"{call};puts(\"result none\");" if result_type == "void" else f"printf(\"result %llx\\n\",(u64)({call}));"
        calls += f'  if(!strcmp(argv[2],"{export}")){{{result_type}(*f)({arguments}=dlsym(h,"{export}");if(!f)return 66;{report}return 0;}}\n'
    return f"""/* Generated by benchmarks/bench_android_bionic.py.  Validation oracle only. */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
typedef unsigned long long u64;
static const char *NAMES[]={{{names}}};
static const int JV[]={{{jv}}};
static u64 ret[{len(slots)}];
enum {{ VM_FIRST = {vm_first} }};
static const char NAME[]="setValue", SIG[]="(J)V";
static void rec(int s,u64*r){{
  printf("call %s",NAMES[s]);
  for(int i=0;i<6;i++)printf(" %llx",r[i]);
  if(JV[s]>=0){{const u64*v=(const u64*)r[JV[s]];printf(" jv %llx %llx",v[0],v[1]);}}
  putchar('\\n');
}}
{stubs}static void *TABLE[]={{{table}}};
int main(int argc,char**argv){{
  if(argc!=3)return 64;
{results}  void*h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
  if(!h){{fprintf(stderr,"dlopen: %s\\n",dlerror());return 65;}}
  const void*table=TABLE; const void*const*env=&table;
  const void*vmtable=&TABLE[VM_FIRST]; const void*const*vm=&vmtable;
  printf("env %llx name %llx sig %llx vm %llx pid %llx\\n",(u64)env,(u64)NAME,(u64)SIG,(u64)vm,(u64)getpid());
{calls}  return 67;
}}
"""


def _clang(api: int) -> Path:
    return TOOLCHAIN / f"bin/aarch64-linux-android{api}-clang"


def _run(loader: Path, *arguments: str, cwd: Path) -> subprocess.CompletedProcess:
    completed = subprocess.run([QEMU, "-L", str(ROOT), str(loader), *arguments], capture_output=True, text=True, timeout=120, cwd=cwd, check=False)
    completed.stderr = "\n".join(line for line in completed.stderr.splitlines() if "linkerconfig" not in line)
    return completed


def _check_jni_log(output: str, expected_calls, expected_result) -> tuple[bool, list[str]]:
    lines = output.splitlines()
    header = lines[0].split()
    symbols = {key.upper() if key in ("name", "sig") else key: int(value, 16) for key, value in zip(header[::2], header[1::2])}
    calls = [line.split() for line in lines if line.startswith("call ")]
    problems = []
    if len(calls) != len(expected_calls):
        problems.append(f"expected {len(expected_calls)} calls, got {len(calls)}")
    for observed, expected in zip(calls, expected_calls):
        slot, *arguments = expected
        if observed[1] != slot:
            problems.append(f"slot {observed[1]} != {slot}")
            continue
        registers = [int(item, 16) for item in observed[2:8]]
        position = 0
        for argument in arguments:
            if isinstance(argument, str) and argument.startswith("jv:"):
                words = [int(item, 16) for item in observed[observed.index("jv") + 1:]]
                wanted = [int(item) for item in argument[3:].split(",") if item]
                if words[: len(wanted)] != wanted:
                    problems.append(f"{slot} jvalue {words} != {wanted}")
                continue
            value = symbols.get(argument, argument) if isinstance(argument, str) else argument
            if argument != "*" and registers[position] != value:
                problems.append(f"{slot} arg{position} {registers[position]:#x} != {value:#x}")
            position += 1
    result_line = lines[-1].split()
    expected_result = symbols.get(expected_result, expected_result)
    if expected_result is not None and int(result_line[1], 16) != expected_result:
        problems.append(f"result {result_line[1]} != {expected_result:#x}")
    return not problems, problems


# Every case runs in both ELF containers: format 4 and the packed format 5 (ADR-105).
CONTAINERS = ("", "@packed")


def _library(source: str, packed: bool = False) -> bytes:
    """Bytes of the shared object a case runs: an XAX fixture compiled now, or a library inside a committed APK."""
    import zipfile

    from benchmarks import bench_android_arm64, bench_android_jni
    from xax_android import ANDROID_GENERAL_TARGET_IDENTITY, compile_android_shared
    from xax_compiler import android_arm64_shared_general_target, android_arm64_shared_target, decode_native_target

    kind, name = source.split(":", 1)
    if kind == "apk":
        if packed:
            name = name.replace(".apk", "_packed.apk")
        with zipfile.ZipFile(HERE / name) as apk:
            return apk.read(next(item for item in apk.namelist() if item.startswith("lib/arm64-v8a/")))
    module = {"jni": bench_android_jni, "arm64": bench_android_arm64}[kind]
    reader, target, _function, exports = getattr(module, f"{name}_fixture")()
    if packed:
        general = decode_native_target(target).identity == ANDROID_GENERAL_TARGET_IDENTITY
        target = (android_arm64_shared_general_target if general else android_arm64_shared_target)(packed=True)
    return compile_android_shared(reader, exports, target_object=target).data


def _android_build(path: Path) -> str:
    props = dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line and not line.startswith("#"))
    return props.get("ro.system.build.fingerprint") or props.get("ro.build.fingerprint", "unknown")


def evidence() -> dict:
    from benchmarks import bench_android_platform_runtime

    native_slots = jni_slots()
    slots = native_slots + jni_slots("struct JNIInvokeInterface {")
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        rows: dict[str, dict] = {}

        # Platform-contract probe through real bionic imports.
        loader = work / "platform_loader"
        subprocess.run([_clang(24), "-O2", "-fPIE", "-pie", "-pthread", str(HERE.parent / "integration/android/platform_contract_runtime_loader.c"), "-ldl", "-o", str(loader)], check=True)
        Path("/data/local/tmp").mkdir(parents=True, exist_ok=True)  # qemu -L redirects only paths that exist under the root
        (ROOT / "data/local/tmp").mkdir(parents=True, exist_ok=True)
        for suffix in CONTAINERS:
            probe = work / "libxax_platform_probe.so"
            probe.write_bytes(bench_android_platform_runtime.build_probe(packed=bool(suffix)))
            completed = _run(loader, "./libxax_platform_probe.so", cwd=work)
            rows["platform_probe" + suffix] = {
                "library_bytes": probe.stat().st_size, "library_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
                "stdout": completed.stdout.strip(), "exit": completed.returncode,
                "passed": completed.returncode == 0 and completed.stdout.strip() == "XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1",
            }

        # bionic's pthread_create runs an XAX start routine (ADR-107), four threads at once.
        from benchmarks import android_thread_entry

        loader = work / "thread_loader"
        subprocess.run([_clang(24), "-O2", "-fPIE", "-pie", "-pthread", str(HERE.parent / "integration/android/thread_entry_loader.c"), "-ldl", "-o", str(loader)], check=True)
        for suffix in CONTAINERS:
            library = work / "libxax_threads.so"
            library.write_bytes(android_thread_entry.build_library(packed=bool(suffix)))
            completed = _run(loader, "./libxax_threads.so", cwd=work)
            rows["pthread_xax_start_routine" + suffix] = {
                "library_bytes": library.stat().st_size, "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
                "stdout": completed.stdout.strip(), "exit": completed.returncode,
                "passed": completed.returncode == 0 and completed.stdout.strip() == "XAX_THREAD_ENTRY_OK 4/4",
            }

        # libxposed native entry.
        module = HERE.parent / "integration/android/libxposed_fixture/app/src/main/jniLibs/arm64-v8a/libxaxmodule.so"
        loader = work / "device_loader"
        subprocess.run([_clang(26), "-O2", "-fPIE", "-pie", str(HERE.parent / "integration/android/device_loader.c"), "-ldl", "-o", str(loader)], check=True)
        shutil.copy(module, work / "libxaxmodule.so")
        completed = _run(loader, "./libxaxmodule.so", cwd=work)
        rows["libxposed_native_init"] = {"library_sha256": hashlib.sha256(module.read_bytes()).hexdigest(), "exit": completed.returncode, "passed": completed.returncode == 0}

        # JNI fixtures against a recording JNIEnv built from the NDK header.
        source = work / "jni_harness.c"
        source.write_text(_harness_source(slots, len(native_slots)), encoding="utf-8")
        harness = work / "jni_harness"
        subprocess.run([_clang(28), "-O1", "-fPIE", "-pie", str(source), "-ldl", "-o", str(harness)], check=True)
        for (export, _prototype, _call, expected_calls, expected_result, source_name), suffix in ((case, suffix) for case in CASES for suffix in CONTAINERS):
            data = _library(source_name, packed=bool(suffix))
            library = work / f"lib{export}.so"
            library.write_bytes(data)
            completed = _run(harness, f"./{library.name}", export, cwd=work)
            ok, problems = _check_jni_log(completed.stdout, expected_calls, expected_result) if completed.returncode == 0 else (False, [completed.stderr.strip() or f"exit {completed.returncode}"])
            rows[export + suffix] = {
                "library_bytes": len(data), "library_sha256": hashlib.sha256(data).hexdigest(), "source": source_name,
                "calls": [line.split()[1] for line in completed.stdout.splitlines() if line.startswith("call ")],
                "problems": problems, "passed": ok,
            }

    clang_version = subprocess.run([_clang(28), "--version"], capture_output=True, text=True, check=False).stdout.splitlines()[0]
    qemu_version = subprocess.run([QEMU, "--version"], capture_output=True, text=True, check=False).stdout.splitlines()[0]
    return {
        "format": "xax-android-bionic-qemu-evidence-v1",
        "label": "EXECUTED",
        "environment": {
            "kind": "qemu-aarch64 user mode with Android linker64 and bionic from an official system image; no device, kernel, or ART",
            "android_build": _android_build(ROOT.parent / "sysimg/arm64-v8a/build.prop") if (ROOT.parent / "sysimg/arm64-v8a/build.prop").exists() else "unknown",
            "qemu": qemu_version,
            "ndk": (NDK / "source.properties").read_text(encoding="utf-8").split("Pkg.Revision = ")[1].split()[0],
            "ndk_clang": clang_version,
        },
        "jni_header_slots": {"native": len(native_slots), "invoke": len(slots) - len(native_slots)},
        "runs": rows,
        "passed": sum(row["passed"] for row in rows.values()),
        "total": len(rows),
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, row in result["runs"].items():
        print(f"{'PASS' if row['passed'] else 'FAIL'} {name} {row.get('calls', '')} {row.get('problems', '')}")
    print(f"{result['passed']}/{result['total']}")
    return 0 if result["passed"] == result["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
