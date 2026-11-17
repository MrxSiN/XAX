"""#49 part 6 (ADR-406 (4)): a catching JVM call, lowered to DEX by the XAX programs, keeps its handler.

The programs are `test_jvm_catch_run`'s: one member called through a catching ABI, then the caught flag, the result
(its zero after a throw) and the throwable printed, and exit status 4, or 7 after a throw. The JAR comes from the XAX
JVM program. Its classes go through the XAX JVM-to-DEX program and the XAX DEX writer word for word, as the Android
program chains them, so the exception entry becomes a `try_item` and a catch-all handler that starts with
`move-exception`.

Checks, each where its tool exists:
- every program lowers and writes (Linux x86-64, the native programs);
- `dexdump -d` (`XAX_DEXDUMP`) accepts the file and shows one catch-all handler per catching call;
- ART (`XAX_ADB`, a connected device): `dalvikvm64` runs it with the JVM run's lines and exit status. Only the
  throwable's class is compared, because ART's messages differ from the JDK's.

There is no Python reference for these ABIs (ADR-405): the oracle is execution.
"""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
import zipfile

from test_jvm_catch_run import CASES, LINUX_X86_64, catching_program
from xax_compiler import jvm_classfile_target
from xax_graph_builder import program_store


def _lowered_words(data: bytes) -> list[int]:
    """The XAX JVM-to-DEX program's raw class record for one class file (no renames)."""
    from xax_selfhost_dex_jvm import _PROGRAM, OPT_OUT, OUT_AT

    words = [len(data), *(int.from_bytes(data[k:k + 8].ljust(8, b"\0"), "little") for k in range(0, len(data), 8)), 0]

    def collect(read):
        (status,) = read(0, 1)
        if status != 1:
            return None
        (count,) = read(OUT_AT, 1)
        return list(read(OUT_AT + 1, count))

    out = _PROGRAM.native(OPT_OUT).run(words, collect)
    if out is None:
        raise AssertionError("the JVM-to-DEX program declined")
    return out


def _dex(records: list[list[int]]) -> bytes:
    """The XAX DEX writer's file for raw class records."""
    from xax_selfhost_dex_writer import _PROGRAM, OPT_OUT, OUT
    from xax_selfhost_general_image import IMAGE_AT

    words = [len(records), *(w for record in records for w in record)]

    def collect(read):
        (status,) = read(0, 1)
        if status != 1:
            return None
        head = read(IMAGE_AT, 3)
        packed = read(OUT, (head[2] + 7) // 8)
        return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]]

    data = _PROGRAM.native(OPT_OUT).run(words, collect)
    if data is None:
        raise AssertionError("the DEX writer program declined")
    return data


def program_dex(jar: bytes) -> tuple[bytes, str]:
    """The JAR's classes (by name) as one DEX file, and its main class."""
    with zipfile.ZipFile(io.BytesIO(jar)) as archive:
        names = sorted(name for name in archive.namelist() if name.endswith(".class"))
        manifest = archive.read("META-INF/MANIFEST.MF").decode()
        records = [_lowered_words(archive.read(name)) for name in names]
    main = next(line.split(":", 1)[1].strip() for line in manifest.splitlines() if line.startswith("Main-Class:"))
    return _dex(records), main


def _host_path(path: str, tool: str) -> str:
    if tool.lower().endswith(".exe") and os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, check=True).stdout.strip()
    return path


def _adb_device(adb: str) -> bool:
    try:
        listing = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=60).stdout
    except OSError:
        return False
    return any(line.endswith("\tdevice") for line in listing.splitlines()[1:])


@unittest.skipUnless(LINUX_X86_64, "the XAX programs run natively on Linux x86-64")
class DexCatchTests(unittest.TestCase):
    def test_catching_calls_on_dex(self):
        from xax_selfhost_jvm import jvm_jar

        dexdump, adb = os.environ.get("XAX_DEXDUMP"), os.environ.get("XAX_ADB")
        device = bool(adb) and _adb_device(adb)
        for name, (abi, library, member, receiver, argument, result, lines, status) in CASES.items():
            with self.subTest(case=name):
                entry, objects = catching_program(abi, library, member, receiver, argument, result)
                target = jvm_classfile_target()
                jar = jvm_jar(program_store(entry, target, objects), entry.cid, target, process_entry=True, frontend="xax")
                data, main = program_dex(jar)
                self.assertEqual(data[:8], b"dex\n039\x00")
                with tempfile.TemporaryDirectory(prefix="xax-dexcatch-", dir=os.environ.get("XAX_JAVA_TMP")) as directory:
                    path = os.path.join(directory, "program.dex")
                    with open(path, "wb") as handle:
                        handle.write(data)
                    if dexdump:
                        dumped = subprocess.run([dexdump, "-d", _host_path(path, dexdump)], capture_output=True, timeout=120)
                        self.assertEqual(dumped.returncode, 0, dumped.stdout[-2000:] + dumped.stderr[-2000:])
                        self.assertEqual(dumped.stdout.count(b"<any> -> 0x"), 1, dumped.stdout[-3000:])
                    if not device:
                        continue
                    remote = "/data/local/tmp/xax-dexcatch-%d" % os.getpid()
                    subprocess.run([adb, "shell", "rm -rf %s && mkdir -p %s" % (remote, remote)], check=True, capture_output=True)
                    subprocess.run([adb, "push", _host_path(path, adb), remote + "/program.dex"], check=True, capture_output=True)
                    run = subprocess.run([adb, "shell", "cd %s && dalvikvm64 -cp program.dex %s; echo status=$?" % (remote, main)],
                                         capture_output=True, timeout=300)
                    subprocess.run([adb, "shell", "rm -rf " + remote], capture_output=True)
                printed = run.stdout.replace(b"\r\n", b"\n").split(b"\n")[:-1]
                self.assertEqual(printed[-1], b"status=%d" % status, run.stdout + run.stderr)
                printed = printed[:-1]
                self.assertEqual(len(printed), len(lines), printed)
                for line, expected in zip(printed[:-1], lines[:-1]):
                    self.assertTrue(line.startswith(expected), (printed, lines))
                self.assertEqual(printed[-1].split(b":")[0], lines[-1].split(b":")[0], (printed, lines))


if __name__ == "__main__":
    unittest.main()
