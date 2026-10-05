"""Native code plus a generated JVM bridge (ADR-165, the second OI-35 strategy).

``jsonmin`` is compiled for x86-64 Linux (syscalls only), packaged as a JNI
library, and run by HotSpot through a generated bridge class; every output must
equal the reference.  A kernel with parameters is called from Java code that
``javac`` compiles against the bridge JAR.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.jsonmin import benchmark_document, build_jsonmin, reference_jsonmin  # noqa: E402
from xax_compiler import Operation, XaxError, bits_type, x86_64_linux_exec_target  # noqa: E402
from xax_graph_builder import GraphBuilder, program_store  # noqa: E402
from xax_jvm_bridge import compile_jni_bridge, jni_mangle  # noqa: E402

B32, B64 = bits_type(32), bits_type(64)
JAVA = shutil.which("java") and shutil.which("javac") and platform.machine() == "x86_64" and sys.platform == "linux"
ENV = {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}


def _kernel(parameters=(B64, B64, B32, B32)):
    """``run(a, b) = a * b + (a ^ b)`` with the JNI ``env`` and ``class`` ignored."""
    graph = GraphBuilder()
    block = graph.block(*parameters)
    a, b = block.params[-2:]
    block.ret(block.op1(Operation.ADD_WRAP, (block.op1(Operation.MUL_WRAP, (a, b), B32), block.op1(Operation.BIT_XOR, (a, b), B32)), B32))
    entry = graph.function(parameters, (B32,))
    target = x86_64_linux_exec_target()
    return program_store(entry, target, (B32, B64, *graph.objects.values())), entry, target


class JniBridgeStructureTests(unittest.TestCase):
    def test_names_are_mangled_as_jni_short_names(self):
        self.assertEqual(jni_mangle("xax/Native_1"), "xax_Native_11")

    def test_the_library_exports_the_jni_symbol_and_needs_nothing(self):
        reader, entry, target = _kernel()
        bridge = compile_jni_bridge(reader, entry.cid, target.cid, class_name="xax/Kernel", method="run", library_name="xaxkernel")
        self.assertEqual((bridge.symbol, bridge.descriptor), ("Java_xax_Kernel_run", "(II)I"))
        self.assertEqual(bridge.library[16:18], (3).to_bytes(2, "little"))  # ET_DYN
        self.assertIn(b"Java_xax_Kernel_run\x00", bridge.library)
        self.assertIn(b"libxaxkernel.so\x00", bridge.library)
        self.assertNotIn(b"Main-Class", bridge.jar)
        again = compile_jni_bridge(reader, entry.cid, target.cid, class_name="xax/Kernel", method="run", library_name="xaxkernel")
        self.assertEqual((again.library, again.jar), (bridge.library, bridge.jar))

    def test_the_entry_takes_env_and_class_first(self):
        reader, entry, target = _kernel((B32, B32))
        with self.assertRaises(XaxError) as caught:
            compile_jni_bridge(reader, entry.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "JNI-ENTRY-SIGNATURE")


@unittest.skipUnless(JAVA, "requires java and javac on x86-64 Linux")
class JniBridgeExecutionTests(unittest.TestCase):
    def test_jsonmin_runs_as_native_code_behind_a_generated_bridge(self):
        program = build_jsonmin("jni")
        bridge = compile_jni_bridge(program.reader, program.entry.cid, program.target.cid, class_name="xax/Jsonmin", library_name="xaxjsonmin", process_entry=True)
        documents = (
            b'{"a": [1, 2.5e3, {"b": null}], "c": "x\\n\\u00e9", "d": true}', b"  [ ]  ", b"[1,", b'"\x01"',
            b"[" * 512 + b"]" * 512, b"[" * 513 + b"]" * 513, benchmark_document(1 << 16),
        )
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "libxaxjsonmin.so").write_bytes(bridge.library)
            Path(directory, "app.jar").write_bytes(bridge.jar)
            for document in documents:
                completed = subprocess.run(
                    ["java", f"-Djava.library.path={directory}", "-jar", str(Path(directory, "app.jar"))],
                    input=document, capture_output=True, env=ENV, timeout=120,
                )
                self.assertEqual((completed.returncode, completed.stdout, completed.stderr), reference_jsonmin(document), document[:40])

    def test_java_code_calls_a_native_xax_kernel(self):
        reader, entry, target = _kernel()
        bridge = compile_jni_bridge(reader, entry.cid, target.cid, class_name="xax/Kernel", method="run", library_name="xaxkernel")
        pairs = ((0, 0), (3, 4), (-7, 9), (65536, 65536), (2147483647, 2))
        caller = "public class Caller { public static void main(String[] a) { int[][] p = {%s}; for (int[] q : p) System.out.println(xax.Kernel.run(q[0], q[1])); } }" % ", ".join(f"{{{x}, {y}}}" for x, y in pairs)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "libxaxkernel.so").write_bytes(bridge.library)
            Path(directory, "bridge.jar").write_bytes(bridge.jar)
            Path(directory, "Caller.java").write_text(caller)
            subprocess.run(["javac", "-cp", "bridge.jar", "Caller.java"], cwd=directory, check=True, capture_output=True, env=ENV)
            completed = subprocess.run(
                ["java", f"-Djava.library.path={directory}", "-cp", f"bridge.jar{os.pathsep}.", "Caller"],
                cwd=directory, capture_output=True, text=True, check=True, env=ENV,
            )
        signed = lambda value: value - (1 << 32) if value & (1 << 31) else value  # noqa: E731
        expected = [signed(((x * y) + (x ^ y)) & 0xFFFFFFFF) for x, y in pairs]
        self.assertEqual([int(line) for line in completed.stdout.split()], expected)


if __name__ == "__main__":
    unittest.main()
