"""Issue #95: float code is authored by native transactions, not by the construct carrier.

`xax-construct-v1` is reference tooling that ADR-405 freezes (no new Python). Float types, float constants, float
operations and JVM calls with float descriptors are written with the production compiler's own `xaxc edit` batch
(docs/09 §16):
- `object 4 0x0701` supplies `float<binary32>`, and a type line names it as `form7 <CID>`;
- a float constant is `0x` and its IEEE bytes;
- a foreign declaration is supplied the same way, as an `object 6` line.

An integer program from `construct` is the starting store. Its helper `g` is redefined by a batch, then:
- the native verifier checks the store;
- the reference executor evaluates `g` (the arithmetic case: it runs no foreign calls);
- the XAX JVM program builds the JAR;
- a JVM runs it (`XAX_JAVA`, else `java`), with the exit status as the result.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import os
import platform
import shutil
import sys

from xax_compiler import FloatFormat, StoreReader, bits_type, execute, float_type, foreign_function_symbol, jvm_classfile_target
from xax_construct import construct

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
SEED = Path(__file__).resolve().parents[1] / "bootstrap" / "seed" / "xaxc-linux-x86_64"
F32 = float_type(FloatFormat.BINARY32)
ROUND = foreign_function_symbol(b"java/lang/Math", b"round(F)I", (F32,), (bits_type(32),), abi=b"jvm-invokestatic")
SKELETON = {
    "format": "xax-construct-v1", "platform": "jvm",
    "types": {"mem": "jvm.memory_effect", "proc": "jvm.process_effect", "fs": "jvm.filesystem_effect"},
    "functions": [
        {"name": "g", "params": ["b32"], "returns": ["b32"], "blocks": [{"params": ["b32"], "nodes": [], "end": ["ret", ["p0"]]}]},
        {"name": "main", "params": ["proc", "fs", "mem", "mem"], "returns": ["proc", "fs", "mem", "mem"],
         "blocks": [{"params": ["proc", "fs", "mem", "mem"], "nodes": [
             ["call.direct", [["b32", 7]], ["b32"], {"entity": {"fn": "g"}}],
             ["call.foreign", ["n0", "p0"], ["proc"], {"entity": "jvm.exit_group"}]],
             "end": ["ret", ["n1", "p1", "p2", "p3"]]}]}],
    "package": {"name": "floats", "entries": {"app": "main"}, "release": "app"}}
SUPPLIED = f"define @f32\nobject 4 0x{F32.body.hex()}\nend\ndefine @round\nobject 6 0x{ROUND.body.hex()}\nend\n"
# g(7) as IEEE binary32: (7 / 2.0) * 4.0 truncated is 14 (integer division would give 12); Math.round(7 / 2.0) is 4.
BODIES = {
    "arithmetic": (14, ["N0 sint.to.float P0 -> T1", "N1 constant 0x40000000 -> T1", "N2 float.div N0 N1 -> T1",
                        "N3 constant 0x40800000 -> T1", "N4 float.mul N2 N3 -> T1", "N5 float.to.sint.trunc N4 -> T0", "ret N5"]),
    "float call": (4, ["N0 sint.to.float P0 -> T1", "N1 constant 0x40000000 -> T1", "N2 float.div N0 N1 -> T1",
                       "N3 call.foreign entity=@round N2 -> T0", "ret N3"]),
}


def _exit_status(jar: bytes, java: str) -> int:
    """`java -jar`'s exit status; a Windows launcher from WSL gets the JAR's Windows path (`XAX_JAVA_TMP`)."""
    with tempfile.TemporaryDirectory(prefix="xax-floats-", dir=os.environ.get("XAX_JAVA_TMP")) as directory:
        path = os.path.join(directory, "program.jar")
        Path(path).write_bytes(jar)
        if java.lower().endswith(".exe") and shutil.which("wslpath"):
            path = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, check=True).stdout.strip()
        env = {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}
        return subprocess.run([java, "-jar", path], capture_output=True, timeout=120, env=env).returncode


def _edit(store: Path, batch: str, out: Path) -> None:
    source = store.with_suffix(".batch")
    source.write_text(batch)
    subprocess.run([str(SEED), "edit", str(store), str(source), str(out)], check=True, capture_output=True)
    subprocess.run([str(SEED), "verify", str(out), str(out.with_suffix(".rec"))], check=True, capture_output=True)


def _functions(store: Path) -> dict[str, tuple[str, bytes]]:
    """Each function's signature line, with its view name and CID (`xaxc edit` views)."""
    selector, listing, view = store.with_suffix(".sel"), store.with_suffix(".list"), store.with_suffix(".view")
    selector.write_text("")
    subprocess.run([str(SEED), "edit", str(store), str(selector), str(listing)], check=True)
    found = {}
    for line in listing.read_text().splitlines()[1:]:
        name, cid = line.split()[:2]
        selector.write_text(name)
        subprocess.run([str(SEED), "edit", str(store), str(selector), str(view)], check=True)
        found[view.read_text().splitlines()[2]] = (name, bytes.fromhex(cid))
    return found


@unittest.skipUnless(LINUX_X86_64, "the native edit and the XAX JVM program run on Linux x86-64")
class NativeFloatAuthoringTests(unittest.TestCase):
    def test_float_code_by_native_batch(self):
        from xax_selfhost_jvm import jvm_jar

        constructed = construct(SKELETON)
        java = os.environ.get("XAX_JAVA") or shutil.which("java")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            store = work / "s0.xax"
            store.write_bytes(constructed.reader.data)
            g, _ = _functions(store)["(T0)->(T0)"]
            for name, (status, lines) in BODIES.items():
                with self.subTest(case=name):
                    out = work / f"{name.replace(' ', '_')}.xax"
                    batch = "\n".join([f"R {constructed.reader.root_cid.hex()}", g, SUPPLIED + "define @g", "(T0)->(T0)", "B0(P0:T0)", *lines,
                                        "T0 bits32", f"T1 form7 {F32.cid.hex()}", "end", f"replace {g} @g", ""])
                    _edit(store, batch, out)
                    functions = _functions(out)
                    reader = StoreReader(out.read_bytes())
                    if name == "arithmetic":  # the reference executor runs no foreign calls
                        self.assertEqual(execute(reader, functions["(T0)->(T0)"][1], [7]), (status,))
                    (main,) = [cid for signature, (_, cid) in functions.items() if signature != "(T0)->(T0)"]
                    jar = jvm_jar(reader, main, jvm_classfile_target(), process_entry=True, frontend="xax")
                    if java:
                        self.assertEqual(_exit_status(jar, java), status)


if __name__ == "__main__":
    unittest.main()
