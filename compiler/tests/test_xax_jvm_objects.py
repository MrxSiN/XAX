"""JVM object construction and arrays (ADR-162).

Typed foreign declarations construct objects (``jvm-new``), create and access
arrays (``jvm-newarray``, ``jvm-arrayload``, ``jvm-arraystore``,
``jvm-arraylength``), load string constants (``jvm-ldc``), and cast
(``jvm-checkcast``).  Each program runs on HotSpot against a Python model,
including a comparator callback that takes objects (ADR-161) to sort an
``Integer[]``.
"""

from __future__ import annotations

import shutil
import unittest

from xax_compiler import (
    IntCompare,
    Operation,
    XaxError,
    bits_type,
    foreign_function_symbol,
    jvm_classfile_target,
    jvm_classfile_general_target,
    jvm_interface_entry_type,
    opaque_identity_type,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import compile_jvm_bound_target, jvm_reference_type, jvm_static, jvm_virtual, run_jvm_calls

B1, B32 = bits_type(1), bits_type(32)
JAVA = shutil.which("java") and shutil.which("javac")


def _reference(descriptor: bytes):
    """A JVM reference type and the opaque element type it names."""
    return jvm_reference_type(descriptor), opaque_identity_type(b"jvm-ref:" + descriptor)


INTS, INTS_ELEMENT = _reference(b"[I")
INTEGER, INTEGER_ELEMENT = _reference(b"Ljava/lang/Integer;")
INTEGERS, INTEGERS_ELEMENT = _reference(b"[Ljava/lang/Integer;")
OBJECT, OBJECT_ELEMENT = _reference(b"Ljava/lang/Object;")
OBJECTS, OBJECTS_ELEMENT = _reference(b"[Ljava/lang/Object;")
STRING, STRING_ELEMENT = _reference(b"Ljava/lang/String;")
BUILDER, BUILDER_ELEMENT = _reference(b"Ljava/lang/StringBuilder;")
COMPARATOR = jvm_interface_entry_type(b"java/util/Comparator", b"compare(Ljava/lang/Object;Ljava/lang/Object;)I")
COMPARATOR_ELEMENT = opaque_identity_type(b"code-entry:jvm-interface:java/util/Comparator.compare(Ljava/lang/Object;Ljava/lang/Object;)I")
TYPES = (
    B1, B32, INTS, INTS_ELEMENT, INTEGER, INTEGER_ELEMENT, INTEGERS, INTEGERS_ELEMENT, OBJECT, OBJECT_ELEMENT,
    OBJECTS, OBJECTS_ELEMENT, STRING, STRING_ELEMENT, BUILDER, BUILDER_ELEMENT, COMPARATOR, COMPARATOR_ELEMENT,
)


def _object(abi: bytes, library: bytes, name: bytes, inputs, outputs):
    return foreign_function_symbol(library, name, inputs, outputs, abi=abi)


NEW_INTS = _object(b"jvm-newarray", b"I", b"newarray", (B32,), (INTS,))
LOAD_INT = _object(b"jvm-arrayload", b"[I", b"load", (INTS, B32), (B32,))
STORE_INT = _object(b"jvm-arraystore", b"[I", b"store", (INTS, B32, B32), ())
LENGTH = _object(b"jvm-arraylength", b"[I", b"length", (INTS,), (B32,))
SORT_INTS = jvm_static(b"java/util/Arrays", b"sort([I)V", (INTS,), ())
NEW_BUILDER = _object(b"jvm-new", b"java/lang/StringBuilder", b"<init>()V", (), (BUILDER,))
PREFIX = _object(b"jvm-ldc", b"java/lang/String", b"value=", (), (STRING,))
APPEND_STRING = jvm_virtual(b"java/lang/StringBuilder", b"append(Ljava/lang/String;)Ljava/lang/StringBuilder;", (BUILDER, STRING), (BUILDER,))
APPEND_INT = jvm_virtual(b"java/lang/StringBuilder", b"append(I)Ljava/lang/StringBuilder;", (BUILDER, B32), (BUILDER,))
TO_STRING = jvm_virtual(b"java/lang/StringBuilder", b"toString()Ljava/lang/String;", (BUILDER,), (STRING,))
STRING_LENGTH = jvm_virtual(b"java/lang/String", b"length()I", (STRING,), (B32,))
HASH = jvm_virtual(b"java/lang/String", b"hashCode()I", (STRING,), (B32,))
NEW_INTEGERS = _object(b"jvm-newarray", b"Ljava/lang/Integer;", b"newarray", (B32,), (INTEGERS,))
BOX = jvm_static(b"java/lang/Integer", b"valueOf(I)Ljava/lang/Integer;", (B32,), (INTEGER,))
STORE_INTEGER = _object(b"jvm-arraystore", b"[Ljava/lang/Integer;", b"store", (INTEGERS, B32, INTEGER), ())
LOAD_INTEGER = _object(b"jvm-arrayload", b"[Ljava/lang/Integer;", b"load", (INTEGERS, B32), (INTEGER,))
AS_OBJECTS = _object(b"jvm-checkcast", b"[Ljava/lang/Object;", b"checkcast", (INTEGERS,), (OBJECTS,))
AS_INTEGER = _object(b"jvm-checkcast", b"java/lang/Integer", b"checkcast", (OBJECT,), (INTEGER,))
UNBOX = jvm_virtual(b"java/lang/Integer", b"intValue()I", (INTEGER,), (B32,))
COMPARE = jvm_static(b"java/lang/Integer", b"compare(II)I", (B32, B32), (B32,))
SORT_OBJECTS = jvm_static(b"java/util/Arrays", b"sort([Ljava/lang/Object;Ljava/util/Comparator;)V", (OBJECTS, COMPARATOR), ())
DECLARATIONS = (
    NEW_INTS, LOAD_INT, STORE_INT, LENGTH, SORT_INTS, NEW_BUILDER, PREFIX, APPEND_STRING, APPEND_INT, TO_STRING, STRING_LENGTH, HASH,
    NEW_INTEGERS, BOX, STORE_INTEGER, LOAD_INTEGER, AS_OBJECTS, AS_INTEGER, UNBOX, COMPARE, SORT_OBJECTS,
)


def _compile(graph: GraphBuilder, parameters, returns, extra=(), target=None):
    entry = graph.function(parameters, returns)
    target = target or jvm_classfile_target()
    reader = program_store(entry, target, (*TYPES, *DECLARATIONS, *extra, *graph.objects.values()))
    return compile_jvm_bound_target(reader, entry.cid, target)


def _counted_loop(graph: GraphBuilder, entry, count, carried, body):
    """``for i in range(count)``: ``body(block, i, *carried) -> carried``; returns the exit block and its values."""
    head = graph.block(B32, *(t for t, _v in carried))
    step = graph.block(B32, *(t for t, _v in carried))
    done = graph.block(*(t for t, _v in carried))
    entry.br(head, entry.const(B32, 0), *(v for _t, v in carried))
    index, *values = head.params
    head.cbr(head.op1(Operation.INT_COMPARE, (index, count), B1, attributes=(IntCompare.ULT,)), step, (index, *values), done, tuple(values))
    index, *values = step.params
    following = body(step, index, *values)
    step.br(head, step.op1(Operation.ADD_WRAP, (index, step.const(B32, 1)), B32), *following)
    return done, done.params


def _int_array_program():
    """``f(n, seed)``: fill ``int[n]``, sort it, and fold ``sum(a[i] * (i + 1))``."""
    graph = GraphBuilder()
    entry = graph.block(B32, B32)
    n, seed = entry.params
    array = entry.op1(Operation.CALL_FOREIGN, (n,), INTS, entity=NEW_INTS)

    def fill(block, index, array):
        value = block.op1(Operation.BIT_XOR, (block.op1(Operation.MUL_WRAP, (block.op1(Operation.ADD_WRAP, (index, seed), B32), block.const(B32, 2654435761)), B32), seed), B32)
        block.op(Operation.CALL_FOREIGN, (array, index, value), (), entity=STORE_INT)
        return (array,)

    filled, (array,) = _counted_loop(graph, entry, n, ((INTS, array),), fill)
    filled.op(Operation.CALL_FOREIGN, (array,), (), entity=SORT_INTS)
    length = filled.op1(Operation.CALL_FOREIGN, (array,), B32, entity=LENGTH)

    def fold(block, index, array, total):
        item = block.op1(Operation.CALL_FOREIGN, (array, index), B32, entity=LOAD_INT)
        weight = block.op1(Operation.ADD_WRAP, (index, block.const(B32, 1)), B32)
        return array, block.op1(Operation.ADD_WRAP, (total, block.op1(Operation.MUL_WRAP, (item, weight), B32)), B32)

    done, (_array, total) = _counted_loop(graph, filled, length, ((INTS, array), (B32, filled.const(B32, 0))), fold)
    done.ret(total)
    return _compile(graph, (B32, B32), (B32,))


def _int_array_model(n: int, seed: int) -> int:
    signed = lambda value: value - (1 << 32) if value >> 31 else value  # noqa: E731
    values = sorted(signed((((i + seed) * 2654435761) ^ seed) & 0xFFFFFFFF) for i in range(n))
    return sum(value * (i + 1) for i, value in enumerate(values)) & 0xFFFFFFFF


def _string_program():
    """``f(n)``: ``("value=" + n).length() * 65599 + hashCode()``."""
    graph = GraphBuilder()
    block = graph.block(B32)
    (n,) = block.params
    builder = block.op1(Operation.CALL_FOREIGN, (), BUILDER, entity=NEW_BUILDER)
    builder = block.op1(Operation.CALL_FOREIGN, (builder, block.op1(Operation.CALL_FOREIGN, (), STRING, entity=PREFIX)), BUILDER, entity=APPEND_STRING)
    builder = block.op1(Operation.CALL_FOREIGN, (builder, n), BUILDER, entity=APPEND_INT)
    text = block.op1(Operation.CALL_FOREIGN, (builder,), STRING, entity=TO_STRING)
    length = block.op1(Operation.CALL_FOREIGN, (text,), B32, entity=STRING_LENGTH)
    block.ret(block.op1(Operation.ADD_WRAP, (block.op1(Operation.MUL_WRAP, (length, block.const(B32, 65599)), B32), block.op1(Operation.CALL_FOREIGN, (text,), B32, entity=HASH)), B32))
    return _compile(graph, (B32,), (B32,))


def _string_model(n: int) -> int:
    text = "value=" + str(n - (1 << 32) if n >> 31 else n)
    digest = 0
    for character in text:
        digest = (digest * 31 + ord(character)) & 0xFFFFFFFF
    return (len(text) * 65599 + digest) & 0xFFFFFFFF


def _comparator_program():
    """``f(n, seed)``: an ``Integer[]`` sorted descending by an XAX ``Comparator``; folded as above."""
    comparator_graph = GraphBuilder()
    body = comparator_graph.block(OBJECT, OBJECT)
    left, right = (
        body.op1(Operation.CALL_FOREIGN, (body.op1(Operation.CALL_FOREIGN, (value,), INTEGER, entity=AS_INTEGER),), B32, entity=UNBOX)
        for value in body.params
    )
    body.ret(body.op1(Operation.CALL_FOREIGN, (right, left), B32, entity=COMPARE))  # descending
    comparator = comparator_graph.function((OBJECT, OBJECT), (B32,))

    graph = GraphBuilder()
    entry = graph.block(B32, B32)
    n, seed = entry.params
    array = entry.op1(Operation.CALL_FOREIGN, (n,), INTEGERS, entity=NEW_INTEGERS)

    def fill(block, index, array):
        value = block.op1(Operation.BIT_XOR, (block.op1(Operation.MUL_WRAP, (block.op1(Operation.ADD_WRAP, (index, seed), B32), block.const(B32, 40503)), B32), seed), B32)
        block.op(Operation.CALL_FOREIGN, (array, index, block.op1(Operation.CALL_FOREIGN, (value,), INTEGER, entity=BOX)), (), entity=STORE_INTEGER)
        return (array,)

    filled, (array,) = _counted_loop(graph, entry, n, ((INTEGERS, array),), fill)
    order = filled.op1(Operation.FUNCTION_ADDRESS, (), COMPARATOR, entity=comparator)
    filled.op(Operation.CALL_FOREIGN, (filled.op1(Operation.CALL_FOREIGN, (array,), OBJECTS, entity=AS_OBJECTS), order), (), entity=SORT_OBJECTS)

    def fold(block, index, array, total):
        item = block.op1(Operation.CALL_FOREIGN, (block.op1(Operation.CALL_FOREIGN, (array, index), INTEGER, entity=LOAD_INTEGER),), B32, entity=UNBOX)
        weight = block.op1(Operation.ADD_WRAP, (index, block.const(B32, 1)), B32)
        return array, block.op1(Operation.ADD_WRAP, (total, block.op1(Operation.MUL_WRAP, (item, weight), B32)), B32)

    done, (_array, total) = _counted_loop(graph, filled, n, ((INTEGERS, array), (B32, filled.const(B32, 0))), fold)
    done.ret(total)
    extra = (*comparator_graph.objects.values(), comparator)
    return _compile(graph, (B32, B32), (B32,), extra, jvm_classfile_general_target())


def _comparator_model(n: int, seed: int) -> int:
    signed = lambda value: value - (1 << 32) if value >> 31 else value  # noqa: E731
    values = sorted((signed((((i + seed) * 40503) ^ seed) & 0xFFFFFFFF) for i in range(n)), reverse=True)
    return sum(value * (i + 1) for i, value in enumerate(values)) & 0xFFFFFFFF


POINT, POINT_ELEMENT = _reference(b"Ljava/awt/Point;")
NEW_POINT = _object(b"jvm-new", b"java/awt/Point", b"<init>(II)V", (B32, B32), (POINT,))
GET_X = _object(b"jvm-getfield", b"java/awt/Point", b"x:I", (POINT,), (B32,))
GET_Y = _object(b"jvm-getfield", b"java/awt/Point", b"y:I", (POINT,), (B32,))
PUT_Y = _object(b"jvm-putfield", b"java/awt/Point", b"y:I", (POINT, B32), ())
TRANSLATE = jvm_virtual(b"java/awt/Point", b"translate(II)V", (POINT, B32, B32), ())
POINT_AS_OBJECT = _object(b"jvm-checkcast", b"java/lang/Object", b"checkcast", (POINT,), (OBJECT,))
IS_POINT2D = _object(b"jvm-instanceof", b"java/awt/geom/Point2D", b"instanceof", (OBJECT,), (B1,))
IS_STRING = _object(b"jvm-instanceof", b"java/lang/String", b"instanceof", (OBJECT,), (B1,))


def _field_program():
    """``f(a, b)``: a ``Point(a, b)``; ``y = x * 3``; ``translate(1, 2)``; then fields and type tests."""
    graph = GraphBuilder()
    block = graph.block(B32, B32)
    a, b = block.params
    point = block.op1(Operation.CALL_FOREIGN, (a, b), POINT, entity=NEW_POINT)
    x = block.op1(Operation.CALL_FOREIGN, (point,), B32, entity=GET_X)
    block.op(Operation.CALL_FOREIGN, (point, block.op1(Operation.MUL_WRAP, (x, block.const(B32, 3)), B32)), (), entity=PUT_Y)
    block.op(Operation.CALL_FOREIGN, (point, block.const(B32, 1), block.const(B32, 2)), (), entity=TRANSLATE)
    as_object = block.op1(Operation.CALL_FOREIGN, (point,), OBJECT, entity=POINT_AS_OBJECT)
    flags = block.op1(Operation.ADD_WRAP, (
        block.op1(Operation.MUL_WRAP, (block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.CALL_FOREIGN, (as_object,), B1, entity=IS_POINT2D),), B32), block.const(B32, 1 << 20)), B32),
        block.op1(Operation.MUL_WRAP, (block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.CALL_FOREIGN, (as_object,), B1, entity=IS_STRING),), B32), block.const(B32, 1 << 21)), B32),
    ), B32)
    fields = block.op1(Operation.ADD_WRAP, (block.op1(Operation.CALL_FOREIGN, (point,), B32, entity=GET_X), block.op1(Operation.MUL_WRAP, (block.op1(Operation.CALL_FOREIGN, (point,), B32, entity=GET_Y), block.const(B32, 1000)), B32)), B32)
    block.ret(block.op1(Operation.ADD_WRAP, (fields, flags), B32))
    extra = (POINT, POINT_ELEMENT, NEW_POINT, GET_X, GET_Y, PUT_Y, TRANSLATE, POINT_AS_OBJECT, IS_POINT2D, IS_STRING)
    return _compile(graph, (B32, B32), (B32,), extra)


def _field_model(a: int, b: int) -> int:
    x, y = (a + 1) & 0xFFFFFFFF, (a * 3 + 2) & 0xFFFFFFFF
    return (x + y * 1000 + (1 << 20)) & 0xFFFFFFFF


GRID, GRID_ELEMENT = _reference(b"[[I")
CUBE, CUBE_ELEMENT = _reference(b"[[[J")
NEW_GRID = _object(b"jvm-multianewarray", b"[[I", b"multianewarray", (B32, B32), (GRID,))
NEW_CUBE = _object(b"jvm-multianewarray", b"[[[J", b"multianewarray", (B32, B32), (CUBE,))
ROW = _object(b"jvm-arrayload", b"[[I", b"load", (GRID, B32), (INTS,))
GRID_LENGTH = _object(b"jvm-arraylength", b"[[I", b"length", (GRID,), (B32,))
CUBE_LENGTH = _object(b"jvm-arraylength", b"[[[J", b"length", (CUBE,), (B32,))
DEEP_HASH = jvm_static(b"java/util/Arrays", b"deepHashCode([Ljava/lang/Object;)I", (OBJECTS,), (B32,))
GRID_AS_OBJECTS = _object(b"jvm-checkcast", b"[Ljava/lang/Object;", b"checkcast", (GRID,), (OBJECTS,))


def _grid_program():
    """``f(a, b)``: ``g = new int[a][b]``; ``g[a-1][b-1] = 7``; lengths, the stored value, ``deepHashCode``, and a partial cube."""
    graph = GraphBuilder()
    block = graph.block(B32, B32)
    a, b = block.params
    grid = block.op1(Operation.CALL_FOREIGN, (a, b), GRID, entity=NEW_GRID)
    one = block.const(B32, 1)
    row = block.op1(Operation.CALL_FOREIGN, (grid, block.op1(Operation.SUB_WRAP, (a, one), B32)), INTS, entity=ROW)
    block.op(Operation.CALL_FOREIGN, (row, block.op1(Operation.SUB_WRAP, (b, one), B32), block.const(B32, 7)), (), entity=STORE_INT)
    lengths = block.op1(Operation.ADD_WRAP, (
        block.op1(Operation.MUL_WRAP, (block.op1(Operation.CALL_FOREIGN, (grid,), B32, entity=GRID_LENGTH), block.const(B32, 100)), B32),
        block.op1(Operation.CALL_FOREIGN, (row,), B32, entity=LENGTH),
    ), B32)
    stored = block.op1(Operation.CALL_FOREIGN, (row, block.op1(Operation.SUB_WRAP, (b, one), B32)), B32, entity=LOAD_INT)
    hashed = block.op1(Operation.CALL_FOREIGN, (block.op1(Operation.CALL_FOREIGN, (grid,), OBJECTS, entity=GRID_AS_OBJECTS),), B32, entity=DEEP_HASH)
    cube = block.op1(Operation.CALL_FOREIGN, (b, a), CUBE, entity=NEW_CUBE)  # new long[b][a][]: two of three dimensions
    total = block.op1(Operation.ADD_WRAP, (lengths, block.op1(Operation.MUL_WRAP, (stored, block.const(B32, 10000)), B32)), B32)
    total = block.op1(Operation.ADD_WRAP, (total, block.op1(Operation.MUL_WRAP, (block.op1(Operation.CALL_FOREIGN, (cube,), B32, entity=CUBE_LENGTH), block.const(B32, 1 << 20)), B32)), B32)
    block.ret(block.op1(Operation.BIT_XOR, (total, hashed), B32))
    extra = (GRID, GRID_ELEMENT, CUBE, CUBE_ELEMENT, NEW_GRID, NEW_CUBE, ROW, GRID_LENGTH, CUBE_LENGTH, DEEP_HASH, GRID_AS_OBJECTS)
    return _compile(graph, (B32, B32), (B32,), extra)


def _grid_model(a: int, b: int) -> int:
    rows = [[0] * b for _ in range(a)]
    rows[a - 1][b - 1] = 7

    def array_hash(values):  # java.util.Arrays.hashCode / deepHashCode
        result = 1
        for value in values:
            result = (31 * result + value) & 0xFFFFFFFF
        return result

    hashed = array_hash(array_hash(row) for row in rows)
    return ((a * 100 + b + 7 * 10000 + (b << 20)) ^ hashed) & 0xFFFFFFFF


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmObjectTests(unittest.TestCase):
    def test_multi_dimensional_arrays(self):
        calls = [(1, 1), (2, 3), (5, 4), (17, 9)]
        self.assertEqual(run_jvm_calls(_grid_program(), calls), tuple(_grid_model(a, b) for a, b in calls))

    def test_instance_fields_and_instanceof(self):
        calls = [(0, 0), (5, 9), (1000, 7), ((1 << 32) - 1, 3)]
        self.assertEqual(run_jvm_calls(_field_program(), calls), tuple(_field_model(*call) for call in calls))

    def test_int_arrays_are_created_filled_sorted_and_read(self):
        calls = [(0, 1), (1, 5), (17, 3), (1000, 0x9E3779B9)]
        self.assertEqual(run_jvm_calls(_int_array_program(), calls), tuple(_int_array_model(*call) for call in calls))

    def test_objects_and_string_constants(self):
        calls = [(0,), (42,), ((1 << 32) - 1,), (1 << 31,)]
        self.assertEqual(run_jvm_calls(_string_program(), calls), tuple(_string_model(*call) for call in calls))

    def test_a_comparator_callback_takes_objects(self):
        calls = [(0, 1), (2, 7), (50, 12345), (500, 0xDEADBEEF)]
        self.assertEqual(run_jvm_calls(_comparator_program(), calls), tuple(_comparator_model(*call) for call in calls))

    def test_an_index_outside_the_array_ends_the_program(self):
        graph = GraphBuilder()
        block = graph.block(B32)
        (n,) = block.params
        array = block.op1(Operation.CALL_FOREIGN, (block.const(B32, 4),), INTS, entity=NEW_INTS)
        block.ret(block.op1(Operation.CALL_FOREIGN, (array, n), B32, entity=LOAD_INT))
        self.assertEqual(run_jvm_calls(_compile(graph, (B32,), (B32,)), [(3,), (4,)]), (0, "trap java.lang.ArrayIndexOutOfBoundsException"))


class JvmMultiArrayRejectionTests(unittest.TestCase):
    def test_a_multi_dimensional_array_needs_rank_two_and_at_most_rank_lengths(self):
        for library, inputs, result in ((b"[I", (B32,), INTS), (b"[[I", (B32, B32, B32), GRID)):
            declaration = _object(b"jvm-multianewarray", library, b"multianewarray", inputs, (result,))
            graph = GraphBuilder()
            block = graph.block(B32)
            block.op1(Operation.CALL_FOREIGN, tuple(block.params) * len(inputs), result, entity=declaration)
            block.ret(*block.params)
            with self.assertRaises(XaxError) as caught:
                _compile(graph, (B32,), (B32,), (GRID, GRID_ELEMENT, declaration))
            self.assertEqual(caught.exception.diagnostic.rule, "JVM-MULTIANEWARRAY")


if __name__ == "__main__":
    unittest.main()
