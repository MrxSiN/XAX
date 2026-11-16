"""#49 parts 2-3 (ADR-406 (2), (4)): a catching JVM call, lowered by the XAX JVM program, runs on a JVM.

Each program calls one member through a catching ABI, then prints whether a throwable was caught (``jvm-instanceof
java/lang/Throwable``), the call's result (its zero after a throw), and ``String.valueOf`` of the throwable (``null``
without one), and exits with 4, or 7 after a throw.  The cases: a member that returns, one that throws a checked
exception, one that throws an ``Error``, and one whose throw comes from a nested call, over the three catching ABIs.

There is no Python reference for these ABIs (ADR-405): the JAR comes from the XAX JVM program (Linux x86-64) and the
oracle is execution.  The run needs a ``java`` launcher (``XAX_JAVA``, else ``java`` on the path); a Windows launcher
from WSL gets the JAR's Windows path.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from xax_compiler import (
    JVM_CHECKCAST_ABI, JVM_INSTANCEOF_ABI, JVM_INVOKEVIRTUAL_ABI, JVM_LDC_ABI, Operation, bits_type, foreign_function_symbol,
    jvm_classfile_target, opaque_identity_type,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import REFERENCE_PREFIX, java_base_api, jvm_reference_type

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
TEXTS = (b"Ljava/lang/String;", b"Ljava/lang/Throwable;", b"Ljava/lang/Object;", b"Ljava/lang/Class;", b"Ljava/lang/CharSequence;")
STRING, THROWABLE, OBJECT, CLASS, SEQUENCE = (jvm_reference_type(text) for text in TEXTS)
ELEMENTS = tuple(opaque_identity_type(REFERENCE_PREFIX + text) for text in TEXTS)
B1, B16, B32, B64 = bits_type(1), bits_type(16), bits_type(32), bits_type(64)

# name: (abi, class, member, receiver text or None, argument (ldc text or an int), result type or None,
#        the printed lines (each a prefix: messages differ between JDKs), exit status)
CASES = {
    "returns": (b"jvm-invokestatic-catch", b"java/lang/Integer", b"parseInt(Ljava/lang/String;)I", None, b"42", B32,
                [b"0", b"42", b"null"], 4),
    "nested throw": (b"jvm-invokestatic-catch", b"java/lang/Integer", b"parseInt(Ljava/lang/String;)I", None, b"x", B32,
                     [b"1", b"0", b'java.lang.NumberFormatException: For input string: "x"'], 7),
    "checked": (b"jvm-invokestatic-catch", b"java/lang/Class", b"forName(Ljava/lang/String;)Ljava/lang/Class;", None, b"no.Such",
                CLASS, [b"1", b"null", b"java.lang.ClassNotFoundException: no.Such"], 7),
    "error": (b"jvm-invokestatic-catch", b"java/lang/System", b"loadLibrary(Ljava/lang/String;)V", None, b"xaxnosuchlib", None,
              [b"1", b"java.lang.UnsatisfiedLinkError: no xaxnosuchlib"], 7),
    "virtual": (b"jvm-invokevirtual-catch", b"java/lang/String", b"substring(I)Ljava/lang/String;", b"abc", 1, STRING,
                [b"0", b"bc", b"null"], 4),
    "virtual throw": (b"jvm-invokevirtual-catch", b"java/lang/String", b"substring(I)Ljava/lang/String;", b"abc", 9, STRING,
                      [b"1", b"null", b"java.lang.StringIndexOutOfBoundsException"], 7),
    "interface": (b"jvm-invokeinterface-catch", b"java/lang/CharSequence", b"charAt(I)C", b"abc", 2, B16, [b"0", b"99", b"null"], 4),
    "interface throw": (b"jvm-invokeinterface-catch", b"java/lang/CharSequence", b"charAt(I)C", b"abc", 7, B16,
                        [b"1", b"0", b"java.lang.StringIndexOutOfBoundsException"], 7),
}


def _member(abi, library, text, inputs, outputs):
    return foreign_function_symbol(library, text, inputs, outputs, abi=abi)


def catching_program(abi, library, member, receiver, argument, result):
    api = java_base_api()
    graph = GraphBuilder()
    block = graph.block(api.io_effect, api.process_effect)
    io, process = block.params

    def ldc(text):
        return block.op1(Operation.CALL_FOREIGN, (), STRING, entity=_member(JVM_LDC_ABI, b"java/lang/String", text, (), (STRING,)))

    stream, io = block.op(Operation.CALL_FOREIGN, (io,), (api.print_stream, api.io_effect), entity=api.system_out)
    inputs, types = [], []
    if receiver is not None:
        value = ldc(receiver)
        if library == b"java/lang/CharSequence":
            value = block.op1(Operation.CALL_FOREIGN, (value,), SEQUENCE,
                              entity=_member(JVM_CHECKCAST_ABI, b"java/lang/CharSequence", b"x", (STRING,), (SEQUENCE,)))
            types.append(SEQUENCE)
        else:
            types.append(STRING)
        inputs.append(value)
    if isinstance(argument, int):
        inputs.append(block.const(B32, argument))
        types.append(B32)
    else:
        inputs.append(ldc(argument))
        types.append(STRING)
    outputs = ((result,) if result is not None else ()) + (THROWABLE,)
    values = block.op(Operation.CALL_FOREIGN, tuple(inputs), outputs, entity=_member(abi, library, member, tuple(types), outputs))
    thrown = values[-1]
    flag = block.op1(Operation.CALL_FOREIGN, (thrown,), B1,
                     entity=_member(JVM_INSTANCEOF_ABI, b"java/lang/Throwable", b"x", (THROWABLE,), (B1,)))
    io = block.op1(Operation.CALL_FOREIGN, (stream, block.op1(Operation.INT_ZERO_EXTEND, (flag,), B64), io), api.io_effect,
                   entity=api.println_long)
    println_string = _member(JVM_INVOKEVIRTUAL_ABI, b"java/io/PrintStream", b"println(Ljava/lang/String;)V",
                             (api.print_stream, STRING, api.io_effect), (api.io_effect,))

    def show(value, kind, io):
        if kind in (B32, B16):
            return block.op1(Operation.CALL_FOREIGN, (stream, block.op1(Operation.INT_ZERO_EXTEND, (value,), B64), io), api.io_effect,
                             entity=api.println_long)
        anything = block.op1(Operation.CALL_FOREIGN, (value,), OBJECT,
                             entity=_member(JVM_CHECKCAST_ABI, b"java/lang/Object", b"x", (kind,), (OBJECT,)))
        text = block.op1(Operation.CALL_FOREIGN, (anything,), STRING, entity=_member(
            b"jvm-invokestatic", b"java/lang/String", b"valueOf(Ljava/lang/Object;)Ljava/lang/String;", (OBJECT,), (STRING,)))
        return block.op1(Operation.CALL_FOREIGN, (stream, text, io), api.io_effect, entity=println_string)

    if result is not None:
        io = show(values[0], result, io)
    io = show(thrown, THROWABLE, io)
    io = block.op1(Operation.CALL_FOREIGN, (stream, io), api.io_effect, entity=api.flush)
    status = block.op1(Operation.ADD_WRAP, (block.op1(Operation.MUL_WRAP, (block.op1(Operation.INT_ZERO_EXTEND, (flag,), B32),
                                                                         block.const(B32, 3)), B32), block.const(B32, 4)), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit)
    block.ret(io, process)
    entry = graph.function((api.io_effect, api.process_effect), (api.io_effect, api.process_effect))
    return entry, (*api.types, *ELEMENTS, STRING, THROWABLE, OBJECT, CLASS, SEQUENCE, B1, B16, B32, B64, *graph.objects.values())


def _java():
    return os.environ.get("XAX_JAVA") or shutil.which("java")


def run_jar(jar: bytes, java: str) -> subprocess.CompletedProcess:
    directory = tempfile.mkdtemp(prefix="xax-catch-", dir=os.environ.get("XAX_JAVA_TMP"))
    try:
        path = os.path.join(directory, "program.jar")
        with open(path, "wb") as handle:
            handle.write(jar)
        if java.lower().endswith(".exe") and shutil.which("wslpath"):
            path = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, check=True).stdout.strip()
        env = {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}
        return subprocess.run([java, "-jar", path], capture_output=True, timeout=120, check=False, env=env)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@unittest.skipUnless(LINUX_X86_64, "the XAX JVM program runs natively on Linux x86-64")
class CatchRunTests(unittest.TestCase):
    def test_catching_calls_run(self):
        from xax_selfhost_jvm import jvm_jar

        java = _java()
        for name, (abi, library, member, receiver, argument, result, lines, status) in CASES.items():
            with self.subTest(case=name):
                entry, objects = catching_program(abi, library, member, receiver, argument, result)
                target = jvm_classfile_target()
                jar = jvm_jar(program_store(entry, target, objects), entry.cid, target, process_entry=True, frontend="xax")
                if not java:
                    continue  # built only: no launcher on this host
                completed = run_jar(jar, java)
                self.assertEqual(completed.returncode, status, completed.stderr)
                printed = completed.stdout.replace(b"\r\n", b"\n").split(b"\n")[:-1]
                self.assertEqual(len(printed), len(lines), printed)
                for line, prefix in zip(printed, lines):
                    self.assertTrue(line.startswith(prefix), (printed, lines))


if __name__ == "__main__":
    unittest.main()
