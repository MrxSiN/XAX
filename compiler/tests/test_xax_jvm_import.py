"""JVM class-file importer (ADR-166, OI-32).

Declarations are imported from the JDK's own ``java.base`` and ``java.desktop``
modules.  A program built only from imported declarations runs on HotSpot
against a Python model.  The importer reproduces hand-built declarations byte
for byte when given the same curated facts (purity, effects), and refuses what
it cannot import with a reason.
"""

from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path

from xax_compiler import (
    EffectDomain,
    Operation,
    bits_type,
    effect_type,
    jvm_classfile_general_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import compile_jvm_bound_target, java_base_api, jvm_static, jvm_virtual, run_jvm_calls
from xax_jvm_import import JvmClassPath, class_requests, import_jvm_members

B32 = bits_type(32)
IO = effect_type(EffectDomain.IO, 0)


def _jmods() -> Path | None:
    javac = shutil.which("javac")
    if not javac:
        return None
    jmods = Path(os.path.realpath(javac)).parents[1] / "jmods"
    return jmods if (jmods / "java.base.jmod").is_file() and (jmods / "java.desktop.jmod").is_file() else None


JMODS = _jmods()
_CLASSPATH: JvmClassPath | None = None


def _classpath() -> JvmClassPath:
    global _CLASSPATH
    if _CLASSPATH is None:
        _CLASSPATH = JvmClassPath.of(JMODS / "java.base.jmod", JMODS / "java.desktop.jmod")
    return _CLASSPATH


SB = "java/lang/StringBuilder"
REQUESTS = {
    "new": f"{SB}.<init>()V",
    "append_int": f"{SB}.append(I){'L' + SB + ';'}",
    "append_string": f"{SB}.append(Ljava/lang/String;){'L' + SB + ';'}",
    "to_string": f"{SB}.toString()Ljava/lang/String;",
    "hex": "java/lang/Integer.toHexString(I)Ljava/lang/String;",
    "length": "java/lang/String.length()I",
    "hash": "java/lang/String.hashCode()I",
    "range": "java/util/stream/IntStream.rangeClosed(II)Ljava/util/stream/IntStream;",
    "map": "java/util/stream/IntStream.map(Ljava/util/function/IntUnaryOperator;)Ljava/util/stream/IntStream;",
    "sum": "java/util/stream/IntStream.sum()I",
    "point": "java/awt/Point.<init>(II)V",
    "x": "java/awt/Point.x:I",
    "y": "java/awt/Point.y:I",
    "set_y": "java/awt/Point.y:I=",
    "floor_mod": "java/lang/Math.floorMod(II)I",
}


def _program():
    """``f(n)`` over imported declarations only; the I/O effect orders every Java call."""
    imported = import_jvm_members(_classpath(), REQUESTS.values(), pure=(REQUESTS["floor_mod"],), callbacks=True)
    assert not imported.refused, imported.refused
    d = {key: imported.declarations[request] for key, request in REQUESTS.items()}
    square_graph = GraphBuilder()
    square_block = square_graph.block(B32)
    (x,) = square_block.params
    square_block.ret(square_block.op1(Operation.ADD_WRAP, (square_block.op1(Operation.MUL_WRAP, (x, x), B32), square_block.const(B32, 1)), B32))
    square = square_graph.function((B32,), (B32,))

    graph = GraphBuilder()
    block = graph.block(B32, IO)
    n, io = block.params

    def call(key, *operands):
        *values, effect = block.op(Operation.CALL_FOREIGN, (*operands, io), tuple(_outputs(d[key])), entity=d[key])
        return values, effect

    def _outputs(declaration):
        from xax_compiler import decode_foreign_function
        lookup = {item.cid: item for item in imported.objects}
        return [lookup[cid] for cid in decode_foreign_function(declaration).outputs]

    (builder,), io = call("new")
    (builder,), io = call("append_int", builder, n)
    (hex_string,), io = call("hex", n)
    (builder,), io = call("append_string", builder, hex_string)
    (text,), io = call("to_string", builder)
    (length,), io = call("length", text)
    (hashed,), io = call("hash", text)
    (stream,), io = call("range", block.const(B32, 1), n)
    unary = next(item for item in imported.objects if b"code-entry:jvm-interface:java/util/function/IntUnaryOperator" in item.body)
    entry_type = next(item for item in imported.objects if item.references == (unary.cid,))
    (stream,), io = call("map", stream, block.op1(Operation.FUNCTION_ADDRESS, (), entry_type, entity=square))
    (total,), io = call("sum", stream)
    (point,), io = call("point", n, block.const(B32, 3))
    (px,), io = call("x", point)
    (), io = call("set_y", point, block.op1(Operation.MUL_WRAP, (px, block.const(B32, 2)), B32))
    (py,), io = call("y", point)
    (remainder,) = block.op(Operation.CALL_FOREIGN, (n, block.const(B32, 7)), (B32,), entity=d["floor_mod"])
    terms = (
        block.op1(Operation.MUL_WRAP, (length, block.const(B32, 65599)), B32), hashed,
        block.op1(Operation.MUL_WRAP, (total, block.const(B32, 31)), B32), py,
        block.op1(Operation.MUL_WRAP, (remainder, block.const(B32, 1000003)), B32),
    )
    result = terms[0]
    for term in terms[1:]:
        result = block.op1(Operation.ADD_WRAP, (result, term), B32)
    block.ret(result, io)
    entry = graph.function((B32, IO), (B32, IO))
    target = jvm_classfile_general_target()
    reader = program_store(entry, target, (*imported.objects, *square_graph.objects.values(), square, *graph.objects.values()))
    return compile_jvm_bound_target(reader, entry.cid, target)


def _java_hash(text: str) -> int:
    value = 0
    for character in text:
        value = (31 * value + ord(character)) & 0xFFFFFFFF
    return value


def _model(n: int) -> int:
    text = f"{n}{n:x}"
    total = sum((x * x + 1) & 0xFFFFFFFF for x in range(1, n + 1)) & 0xFFFFFFFF
    return (len(text) * 65599 + _java_hash(text) + total * 31 + 2 * n + (n % 7) * 1000003) & 0xFFFFFFFF


@unittest.skipUnless(JMODS, "requires a JDK with jmods")
class JvmImportTests(unittest.TestCase):
    def test_java_base_exports_only_its_public_api(self):
        imported = import_jvm_members(_classpath(), (
            "jdk/internal/misc/Unsafe.getUnsafe()Ljdk/internal/misc/Unsafe;", "java/util/AbstractList.<init>()V",
            "java/lang/Object.missing()V", "java/lang/Integer.MAX_VALUE:I=", "java/awt/Point.x:I=",
            "java/util/List.of()Ljava/util/List;", "java/util/ArrayList.of()Ljava/util/List;",
        ))
        self.assertEqual(imported.refused, {
            "jdk/internal/misc/Unsafe.getUnsafe()Ljdk/internal/misc/Unsafe;": "owner not a public class in an exported package",
            "java/util/AbstractList.<init>()V": "member not public",
            "java/lang/Object.missing()V": "member not found",
            "java/lang/Integer.MAX_VALUE:I=": "final field",
            "java/util/ArrayList.of()Ljava/util/List;": "static interface methods are not inherited",
        })
        self.assertEqual(sorted(imported.declarations), ["java/awt/Point.x:I=", "java/util/List.of()Ljava/util/List;"])

    def test_hand_built_java_base_declarations_are_reproduced_byte_for_byte(self):
        api = java_base_api()
        hand_built = {
            "java/lang/System.out:Ljava/io/PrintStream;": api.system_out,
            "java/io/PrintStream.println(J)V": api.println_long,
            "java/io/PrintStream.println(D)V": api.println_double,
            "java/io/PrintStream.print(C)V": api.print_char,
            "java/io/PrintStream.flush()V": api.flush,
            "java/lang/System.exit(I)V": api.exit,
            "java/lang/Math.sqrt(D)D": api.sqrt,
            "java/lang/System.nanoTime()J": api.nano_time,
            "java/lang/Long.bitCount(J)I": api.bit_count,
        }
        imported = import_jvm_members(
            _classpath(), hand_built, pure=("java/lang/Math.sqrt(D)D", "java/lang/Long.bitCount(J)I"),
            effects={"java/lang/System.exit(I)V": api.process_effect, "java/lang/System.nanoTime()J": effect_type(EffectDomain.TIME, 0)},
        )
        self.assertEqual({key: item.cid for key, item in imported.declarations.items()}, {key: item.cid for key, item in hand_built.items()})

    def test_inherited_members_resolve_through_the_named_class(self):
        b32 = bits_type(32)
        builder = import_jvm_members(_classpath(), ("java/lang/StringBuilder.length()I", "java/lang/StringBuilder.charAt(I)C"), pure=(
            "java/lang/StringBuilder.length()I", "java/lang/StringBuilder.charAt(I)C"))
        from xax_jvm import jvm_reference_type
        reference = jvm_reference_type(b"Ljava/lang/StringBuilder;")
        self.assertEqual(builder.declarations["java/lang/StringBuilder.length()I"].cid, jvm_virtual(b"java/lang/StringBuilder", b"length()I", (reference,), (b32,)).cid)
        self.assertEqual(
            builder.declarations["java/lang/StringBuilder.charAt(I)C"].cid,
            jvm_virtual(b"java/lang/StringBuilder", b"charAt(I)C", (reference, b32), (bits_type(16),)).cid,
        )

    def test_whole_classes_import_with_reasons_for_the_rest(self):
        requests = class_requests(_classpath(), "java/lang/Math") + class_requests(_classpath(), "java/util/ArrayList")
        imported = import_jvm_members(_classpath(), requests)
        self.assertGreater(len(imported.declarations), 120)
        self.assertTrue(set(imported.refused.values()) <= {"member not public", "final field"})
        again = import_jvm_members(_classpath(), reversed(requests))
        self.assertEqual([item.cid for item in again.objects], [item.cid for item in imported.objects])
        self.assertIn(jvm_static(b"java/lang/Math", b"abs(I)I", (B32, IO), (B32, IO)).cid, {item.cid for item in imported.objects})

    def test_static_field_writes_import_as_putstatic(self):
        import tempfile
        import zipfile

        from tests.test_xax_jvm_objects import STATIC_DECLARATIONS, _statics_classpath

        with tempfile.TemporaryDirectory() as directory:
            _statics_classpath(directory)
            jar = Path(directory, "statics.jar")
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(Path(directory, "xaxtest", "Statics.class"), "xaxtest/Statics.class")
            classpath = JvmClassPath.of(jar, JMODS / "java.base.jmod")
        requests = [
            "xaxtest/Statics.count:I=", "xaxtest/Statics.count:I", "xaxtest/Statics.total:J=", "xaxtest/Statics.total:J",
            "xaxtest/Statics.small:B=", "xaxtest/Statics.small:B", "xaxtest/Statics.label:Ljava/lang/String;=",
            "xaxtest/Statics.label:Ljava/lang/String;", "xaxtest/Statics.bump()I",
        ]
        imported = import_jvm_members(classpath, requests)
        self.assertEqual(imported.refused, {})
        self.assertEqual([imported.declarations[key].cid for key in requests], [item.cid for item in STATIC_DECLARATIONS])
        self.assertEqual(set(class_requests(classpath, "xaxtest/Statics")) - set(requests), {"xaxtest/Statics.<init>()V"})

    @unittest.skipUnless(shutil.which("java"), "requires java")
    def test_a_program_over_imported_declarations_runs_on_hotspot(self):
        calls = [(1,), (2,), (10,), (255,), (1000,)]
        self.assertEqual(run_jvm_calls(_program(), calls, result_width=32), tuple(_model(n) for (n,) in calls))


if __name__ == "__main__":
    unittest.main()
