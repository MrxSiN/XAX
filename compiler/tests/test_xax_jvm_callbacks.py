"""JVM callbacks (ADR-161): XAX functions passed to Java as functional-interface objects.

``FUNCTION_ADDRESS`` at a ``jvm-interface:`` entry type is an object of the
interface type; Java calls its method, which calls the XAX function.  The test
pipeline is driven entirely by the JDK: ``IntStream.rangeClosed(1, n)
.map(square).filter(isOdd).reduce(7, combine)``, through the new
``jvm-invokestatic-interface`` and ``jvm-invokeinterface`` foreign ABIs.
"""

from __future__ import annotations

import shutil
import unittest

from xax_compiler import (
    IntCompare,
    Operation,
    Permission,
    XaxError,
    bits_type,
    jvm_classfile_general_target,
    jvm_interface_entry_type,
    memory_effect_type,
    opaque_identity_type,
    pointer_type,
    stack_owner_type,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import compile_jvm_bound_target, jvm_interface, jvm_interface_static, jvm_reference_type, run_jvm_calls

B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
STREAM = jvm_reference_type(b"Ljava/util/stream/IntStream;")
UNARY = jvm_interface_entry_type(b"java/util/function/IntUnaryOperator", b"applyAsInt(I)I")
PREDICATE = jvm_interface_entry_type(b"java/util/function/IntPredicate", b"test(I)Z")
BINARY = jvm_interface_entry_type(b"java/util/function/IntBinaryOperator", b"applyAsInt(II)I")
INT_STREAM = b"java/util/stream/IntStream"
RANGE = jvm_interface_static(INT_STREAM, b"rangeClosed(II)Ljava/util/stream/IntStream;", (B32, B32), (STREAM,))
MAP = jvm_interface(INT_STREAM, b"map(Ljava/util/function/IntUnaryOperator;)Ljava/util/stream/IntStream;", (STREAM, UNARY), (STREAM,))
FILTER = jvm_interface(INT_STREAM, b"filter(Ljava/util/function/IntPredicate;)Ljava/util/stream/IntStream;", (STREAM, PREDICATE), (STREAM,))
REDUCE = jvm_interface(INT_STREAM, b"reduce(ILjava/util/function/IntBinaryOperator;)I", (STREAM, B32, BINARY), (B32,))
JAVA = shutil.which("java") and shutil.which("javac")
# The opaque element types the pointer types above name.
ELEMENTS = (
    opaque_identity_type(b"jvm-ref:Ljava/util/stream/IntStream;"),
    opaque_identity_type(b"code-entry:jvm-interface:java/util/function/IntUnaryOperator.applyAsInt(I)I"),
    opaque_identity_type(b"code-entry:jvm-interface:java/util/function/IntUnaryOperator.applyAsLong(I)J"),
    opaque_identity_type(b"code-entry:jvm-interface:java/util/function/IntPredicate.test(I)Z"),
    opaque_identity_type(b"code-entry:jvm-interface:java/util/function/IntBinaryOperator.applyAsInt(II)I"),
)


def _function(parameters, returns, body):
    graph = GraphBuilder()
    block = graph.block(*parameters)
    block.ret(*body(block, *block.params))
    return graph.function(parameters, returns), tuple(graph.objects.values())


def _callbacks(*, stack_in_square: bool = False):
    def square(block, x):
        if stack_in_square:  # the shadow stack belongs to the entry thread
            cell = pointer_type(B32, Permission.READ_WRITE, 4)
            pointer, owner, memory = block.op(Operation.STACK_ALLOC, (), (cell, stack_owner_type(), memory_effect_type()), attributes=(4, 4))
            from xax_compiler import Node
            memory = block.op1(Operation.STORE_BITS_LE, (pointer, x, memory), memory_effect_type(), attributes=(4, 4))
            block.nodes.append(Node(Operation.STACK_END, (owner, memory), ()))
        return (block.op1(Operation.ADD_WRAP, (block.op1(Operation.MUL_WRAP, (x, x), B32), block.const(B32, 1)), B32),)

    def odd(block, x):
        return (block.op1(Operation.INT_COMPARE, (block.op1(Operation.BIT_AND, (x, block.const(B32, 1)), B32), block.const(B32, 0)), B1, attributes=(IntCompare.NE,)),)

    def combine(block, a, b):
        return (block.op1(Operation.ADD_WRAP, (block.op1(Operation.MUL_WRAP, (a, block.const(B32, 31)), B32), b), B32),)

    return _function((B32,), (B32,), square), _function((B32,), (B1,), odd), _function((B32, B32), (B32,), combine)


def _program(*, stack_in_square: bool = False, square_type=UNARY):
    (square, square_objects), (odd, odd_objects), (combine, combine_objects) = _callbacks(stack_in_square=stack_in_square)
    graph = GraphBuilder()
    block = graph.block(B32)
    (n,) = block.params
    stream = block.op1(Operation.CALL_FOREIGN, (block.const(B32, 1), n), STREAM, entity=RANGE)
    stream = block.op1(Operation.CALL_FOREIGN, (stream, block.op1(Operation.FUNCTION_ADDRESS, (), square_type, entity=square)), STREAM, entity=MAP)
    stream = block.op1(Operation.CALL_FOREIGN, (stream, block.op1(Operation.FUNCTION_ADDRESS, (), PREDICATE, entity=odd)), STREAM, entity=FILTER)
    block.ret(block.op1(Operation.CALL_FOREIGN, (stream, block.const(B32, 7), block.op1(Operation.FUNCTION_ADDRESS, (), BINARY, entity=combine)), B32, entity=REDUCE))
    entry = graph.function((B32,), (B32,))
    objects = (
        *ELEMENTS, square_type, STREAM, UNARY, PREDICATE, BINARY, RANGE, MAP, FILTER, REDUCE, B1, B32,
        *square_objects, square, *odd_objects, odd, *combine_objects, combine, *graph.objects.values(),
    )
    target = jvm_classfile_general_target()
    return compile_jvm_bound_target(program_store(entry, target, objects), entry.cid, target)


def _expected(n: int) -> int:
    total = 7
    for x in range(1, n + 1):
        value = (x * x + 1) & 0xFFFFFFFF
        if value & 1:
            total = (total * 31 + value) & 0xFFFFFFFF
    return total


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmCallbackTests(unittest.TestCase):
    def test_a_jdk_stream_pipeline_calls_xax_functions(self):
        image = _program()
        self.assertIn(b"java/util/function/IntUnaryOperator", image.class_bytes)
        calls = [(0,), (1,), (2,), (10,), (1000,)]
        self.assertEqual(run_jvm_calls(image, calls), tuple(_expected(n) for (n,) in calls))


class JvmCallbackRejectionTests(unittest.TestCase):
    def test_a_callback_may_not_use_the_shadow_stack(self):
        with self.assertRaises(XaxError) as caught:
            _program(stack_in_square=True)
        self.assertEqual(caught.exception.diagnostic.rule, "JVM-ENTRY-SHADOW-STACK")

    def test_the_interface_method_must_match_the_function(self):
        wrong = jvm_interface_entry_type(b"java/util/function/IntUnaryOperator", b"applyAsLong(I)J")
        (square, square_objects), _odd, _combine = _callbacks()
        graph = GraphBuilder()
        block = graph.block(B32)
        block.op1(Operation.FUNCTION_ADDRESS, (), wrong, entity=square)  # b32 -> b32 is not (I)J
        block.ret(*block.params)
        entry = graph.function((B32,), (B32,))
        target = jvm_classfile_general_target()
        reader = program_store(entry, target, (*ELEMENTS, wrong, B32, *square_objects, square, *graph.objects.values()))
        with self.assertRaises(XaxError) as caught:
            compile_jvm_bound_target(reader, entry.cid, target)
        self.assertEqual(caught.exception.diagnostic.rule, "JVM-ENTRY-SIGNATURE")

    def test_an_effectful_callback_is_rejected_by_the_verifier(self):
        memory = memory_effect_type()
        callee_graph = GraphBuilder()
        callee_block = callee_graph.block(B32, memory)
        callee_block.ret(*callee_block.params)
        callee = callee_graph.function((B32, memory), (B32, memory))
        graph = GraphBuilder()
        block = graph.block(B32)
        block.op1(Operation.FUNCTION_ADDRESS, (), UNARY, entity=callee)
        block.ret(*block.params)
        entry = graph.function((B32,), (B32,))
        target = jvm_classfile_general_target()
        with self.assertRaises(XaxError) as caught:
            program_store(entry, target, (*ELEMENTS, UNARY, B32, memory, *callee_graph.objects.values(), callee, *graph.objects.values()))
        self.assertEqual(caught.exception.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")


if __name__ == "__main__":
    unittest.main()
