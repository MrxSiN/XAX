"""A libxposed ``Hooker.intercept(Chain)Object`` written as an XAX ``jvm-interface:`` callback (ADR-161/162).

``FUNCTION_ADDRESS`` at the ``XposedInterface$Hooker`` entry type is an object of
that interface; a Java driver calls ``intercept`` with a ``Chain`` over the
arguments ``(a, b)`` whose original method returns ``a * b``.  The XAX callback
reads ``Chain.getArgs()``, calls ``Chain.proceed()`` once, and returns
``Integer.valueOf(proceed * 31 + args[0] - args[1] + args.size())``.

The libxposed API classes are stubbed with the API 102 member shapes and
compiled by ``javac``.  Callbacks are pure and cannot capture state: the
Hooker object carries only the callback's table index (ADR-161), so everything
the callback uses must come from its ``Chain``.  The ``Chain`` members are
therefore declared without effect tokens, which ADR-162 leaves to the program.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xax_compiler import Operation, bits_type, foreign_function_symbol, jvm_classfile_general_target, jvm_interface_entry_type, opaque_identity_type
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import compile_jvm_bound_target, jvm_interface, jvm_reference_type, jvm_static, jvm_virtual, run_jvm_calls

JAVA = shutil.which("java") and shutil.which("javac")
B32 = bits_type(32)
API = b"io/github/libxposed/api/XposedInterface"


def _reference(descriptor: bytes):
    return jvm_reference_type(descriptor), opaque_identity_type(b"jvm-ref:" + descriptor)


CHAIN, CHAIN_ELEMENT = _reference(b"L" + API + b"$Chain;")
OBJECT, OBJECT_ELEMENT = _reference(b"Ljava/lang/Object;")
INTEGER, INTEGER_ELEMENT = _reference(b"Ljava/lang/Integer;")
LIST, LIST_ELEMENT = _reference(b"Ljava/util/List;")
INTERCEPT = b"intercept(L" + API + b"$Chain;)Ljava/lang/Object;"
HOOKER = jvm_interface_entry_type(API + b"$Hooker", INTERCEPT)
HOOKER_ELEMENT = opaque_identity_type(b"code-entry:jvm-interface:" + API + b"$Hooker." + INTERCEPT)

GET_ARGS = jvm_interface(API + b"$Chain", b"getArgs()Ljava/util/List;", (CHAIN,), (LIST,))
PROCEED = jvm_interface(API + b"$Chain", b"proceed()Ljava/lang/Object;", (CHAIN,), (OBJECT,))
GET = jvm_interface(b"java/util/List", b"get(I)Ljava/lang/Object;", (LIST, B32), (OBJECT,))
SIZE = jvm_interface(b"java/util/List", b"size()I", (LIST,), (B32,))
AS_INTEGER = foreign_function_symbol(b"java/lang/Integer", b"checkcast", (OBJECT,), (INTEGER,), abi=b"jvm-checkcast")
AS_OBJECT = foreign_function_symbol(b"java/lang/Object", b"checkcast", (INTEGER,), (OBJECT,), abi=b"jvm-checkcast")
UNBOX = jvm_virtual(b"java/lang/Integer", b"intValue()I", (INTEGER,), (B32,))
BOX = jvm_static(b"java/lang/Integer", b"valueOf(I)Ljava/lang/Integer;", (B32,), (INTEGER,))
RUN = jvm_static(b"xaxtest/HookDriver", b"run(L" + API + b"$Hooker;II)I", (HOOKER, B32, B32), (B32,))

STUB_SOURCES = {
    "io/github/libxposed/api/XposedInterface.java": """package io.github.libxposed.api;
public interface XposedInterface {
    interface Chain { Object proceed() throws Throwable; java.util.List<Object> getArgs(); }
    interface Hooker { Object intercept(Chain chain) throws Throwable; }
}
""",
    "xaxtest/HookDriver.java": """package xaxtest;
import io.github.libxposed.api.XposedInterface;
public final class HookDriver {
    /** Runs the hooker over a chain whose original method is {@code a * b}; proceed calls go in bits 24 and up. */
    public static int run(XposedInterface.Hooker hooker, int a, int b) throws Throwable {
        int[] calls = {0};
        XposedInterface.Chain chain = new XposedInterface.Chain() {
            public Object proceed() { calls[0]++; return Integer.valueOf(a * b); }
            public java.util.List<Object> getArgs() { return java.util.List.of(Integer.valueOf(a), Integer.valueOf(b)); }
        };
        return ((Integer) hooker.intercept(chain)) ^ (calls[0] << 24);
    }
}
""",
}


def _classpath(directory: str) -> str:
    paths = []
    for name, source in STUB_SOURCES.items():
        path = Path(directory, "src", name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        paths.append(str(path))
    subprocess.run(["javac", "-d", directory, *paths], check=True, capture_output=True)
    return directory


def _program():
    hook = GraphBuilder()
    body = hook.block(CHAIN)
    (chain,) = body.params
    args = body.op1(Operation.CALL_FOREIGN, (chain,), LIST, entity=GET_ARGS)
    first, second = (
        body.op1(Operation.CALL_FOREIGN, (body.op1(Operation.CALL_FOREIGN, (body.op1(Operation.CALL_FOREIGN, (args, body.const(B32, index)), OBJECT, entity=GET),), INTEGER, entity=AS_INTEGER),), B32, entity=UNBOX)
        for index in (0, 1)
    )
    original = body.op1(Operation.CALL_FOREIGN, (body.op1(Operation.CALL_FOREIGN, (body.op1(Operation.CALL_FOREIGN, (chain,), OBJECT, entity=PROCEED),), INTEGER, entity=AS_INTEGER),), B32, entity=UNBOX)
    value = body.op1(Operation.MUL_WRAP, (original, body.const(B32, 31)), B32)
    value = body.op1(Operation.SUB_WRAP, (body.op1(Operation.ADD_WRAP, (value, first), B32), second), B32)
    value = body.op1(Operation.ADD_WRAP, (value, body.op1(Operation.CALL_FOREIGN, (args,), B32, entity=SIZE)), B32)
    body.ret(body.op1(Operation.CALL_FOREIGN, (body.op1(Operation.CALL_FOREIGN, (value,), INTEGER, entity=BOX),), OBJECT, entity=AS_OBJECT))
    intercept = hook.function((CHAIN,), (OBJECT,))

    graph = GraphBuilder()
    block = graph.block(B32, B32)
    a, b = block.params
    hooker = block.op1(Operation.FUNCTION_ADDRESS, (), HOOKER, entity=intercept)
    block.ret(block.op1(Operation.CALL_FOREIGN, (hooker, a, b), B32, entity=RUN))
    entry = graph.function((B32, B32), (B32,))
    objects = (
        B32, CHAIN, CHAIN_ELEMENT, OBJECT, OBJECT_ELEMENT, INTEGER, INTEGER_ELEMENT, LIST, LIST_ELEMENT, HOOKER, HOOKER_ELEMENT,
        GET_ARGS, PROCEED, GET, SIZE, AS_INTEGER, AS_OBJECT, UNBOX, BOX, RUN,
        *hook.objects.values(), intercept, *graph.objects.values(),
    )
    target = jvm_classfile_general_target()
    return compile_jvm_bound_target(program_store(entry, target, objects), entry.cid, target)


def _model(a: int, b: int) -> int:
    signed = lambda value: value - (1 << 32) if value >> 31 else value  # noqa: E731
    original = signed((a * b) & 0xFFFFFFFF)
    hooked = (original * 31 + a - b + 2) & 0xFFFFFFFF
    return hooked ^ (1 << 24)  # Chain.proceed() ran exactly once


@unittest.skipUnless(JAVA, "requires java and javac")
class LibxposedHookerCallbackTests(unittest.TestCase):
    def test_a_hooker_callback_reads_the_arguments_and_proceeds(self):
        image = _program()
        self.assertIn(API + b"$Hooker", image.class_bytes)
        calls = [(0, 0), (3, 4), (7, -2 & 0xFFFFFFFF), (65536, 65536), (0x7FFFFFFF, 3)]
        with tempfile.TemporaryDirectory() as directory:
            results = run_jvm_calls(image, calls, result_width=32, classpath=(_classpath(directory),))
        self.assertEqual(results, tuple(_model(a, b) for a, b in calls))


if __name__ == "__main__":
    unittest.main()
