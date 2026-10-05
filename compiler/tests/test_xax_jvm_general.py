"""JVM general profile (``jvm-classfile-general-v1``, ADR-159).

Aggregates and sums are immutable flattened ``long[]`` values, stack
allocations live in a shadow stack in the linear memory, and indirect calls go
through a function table and a generated dispatcher per contract.  Every
program runs on HotSpot and is compared with the reference executor, including
recursion through aggregates and stack frames (which the wasm lowering's static
frames cannot express), the trap of a wrong sum variant, and the shadow stack's
overflow trap.
"""

from __future__ import annotations

import shutil
import unittest

from xax_compiler import (
    Block,
    FloatFormat,
    IntCompare,
    Node,
    OpaqueKind,
    Operation,
    Permission,
    RecursionMember,
    ValueRef,
    XaxError,
    XaxTrap,
    array_type,
    bits_type,
    call_contract,
    execute,
    float_type,
    graph_fragment,
    group_member_function,
    jvm_classfile_general_target,
    jvm_classfile_memory_target,
    memory_effect_type,
    opaque_type,
    pointer_type,
    recursion_group,
    stack_owner_type,
    sum_type,
    tuple_type,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_jvm import compile_jvm_bound_target, run_jvm_calls

B1, B8, B32, B64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)
F64 = float_type(FloatFormat.BINARY64)
JAVA = shutil.which("java") and shutil.which("javac")


def _compile(entry, objects, target=None):
    target = target or jvm_classfile_general_target()
    reader = program_store(entry, target, objects)
    return reader, compile_jvm_bound_target(reader, entry.cid, target)


def _reference(reader, cid, arguments):
    try:
        return execute(reader, cid, arguments)[0]
    except XaxTrap:
        return "trap java.lang.Error"


def _aggregate_program():
    """``f(a, b, x) -> b64`` over nested tuples and arrays passed through calls and block parameters."""
    pair = tuple_type((B32, F64))
    bytes3 = array_type(B8, 3)
    outer = tuple_type((pair, B64, bytes3))

    reader_graph = GraphBuilder()
    body = reader_graph.block(outer)
    (value,) = body.params
    inner = body.op1(Operation.AGGREGATE_GET, (value,), pair, attributes=(0,))
    first = body.op1(Operation.INT_ZERO_EXTEND, (body.op1(Operation.AGGREGATE_GET, (inner,), B32, attributes=(0,)),), B64)
    wide = body.op1(Operation.AGGREGATE_GET, (value,), B64, attributes=(1,))
    array = body.op1(Operation.AGGREGATE_GET, (value,), bytes3, attributes=(2,))
    middle = body.op1(Operation.INT_ZERO_EXTEND, (body.op1(Operation.AGGREGATE_GET, (array,), B8, attributes=(1,)),), B64)
    last = body.op1(Operation.INT_ZERO_EXTEND, (body.op1(Operation.AGGREGATE_GET, (array,), B8, attributes=(2,)),), B64)
    scaled = body.op1(Operation.FLOAT_TO_UINT_TRUNC, (body.op1(Operation.AGGREGATE_GET, (inner,), F64, attributes=(1,)),), B64)
    total = first
    for term, factor in ((wide, 3), (middle, 1 << 40), (last, 1 << 48), (scaled, 1 << 20)):
        total = body.op1(Operation.ADD_WRAP, (total, body.op1(Operation.MUL_WRAP, (term, body.const(B64, factor)), B64)), B64)
    body.ret(total)
    reader_function = reader_graph.function((outer,), (B64,))

    graph = GraphBuilder()
    entry = graph.block(B32, B64, F64)
    a, b, x = entry.params
    made_pair = entry.op1(Operation.AGGREGATE_MAKE, (a, x), pair)
    small = entry.op1(Operation.INT_TRUNCATE, (b,), B8)
    made_array = entry.op1(Operation.AGGREGATE_MAKE, (entry.op1(Operation.INT_TRUNCATE, (a,), B8), small, entry.const(B8, 7)), bytes3)
    made = entry.op1(Operation.AGGREGATE_MAKE, (made_pair, b, made_array), outer)
    # Through a block parameter on either side of a branch, then a call.
    join = graph.block(outer)
    swapped = graph.block(outer)
    entry.cbr(entry.op1(Operation.INT_COMPARE, (a, entry.const(B32, 100)), B1, attributes=(IntCompare.ULT,)), join, (made,), swapped, (made,))
    (other,) = swapped.params
    rebuilt = swapped.op1(
        Operation.AGGREGATE_MAKE,
        (swapped.op1(Operation.AGGREGATE_GET, (other,), pair, attributes=(0,)), swapped.const(B64, 5), swapped.op1(Operation.AGGREGATE_GET, (other,), bytes3, attributes=(2,))),
        outer,
    )
    swapped.br(join, rebuilt)
    (joined,) = join.params
    join.ret(join.op1(Operation.CALL_DIRECT, (joined,), B64, entity=reader_function))
    function = graph.function((B32, B64, F64), (B64,))
    return function, (pair, bytes3, outer, B8, B32, B64, F64, *reader_graph.objects.values(), reader_function, *graph.objects.values())


def _sum_program():
    """``f(selector, a, b) -> b32``: a sum made on three paths, then dispatched on its tag."""
    both = tuple_type((B32, B32))
    choice = sum_type((B32, both, B1))
    graph = GraphBuilder()
    entry = graph.block(B32, B32, B32)
    selector, a, b = entry.params
    first, rest = graph.block(), graph.block()
    second, third = graph.block(), graph.block()
    join = graph.block(choice)
    entry.cbr(entry.op1(Operation.INT_COMPARE, (selector, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)), first, (), rest, ())
    first.br(join, first.op1(Operation.SUM_MAKE, (a,), choice, attributes=(0,)))
    rest.cbr(rest.op1(Operation.INT_COMPARE, (selector, rest.const(B32, 1)), B1, attributes=(IntCompare.EQ,)), second, (), third, ())
    second.br(join, second.op1(Operation.SUM_MAKE, (second.op1(Operation.AGGREGATE_MAKE, (a, b), both),), choice, attributes=(1,)))
    flag = third.op1(Operation.INT_COMPARE, (a, b), B1, attributes=(IntCompare.ULT,))
    third.br(join, third.op1(Operation.SUM_MAKE, (flag,), choice, attributes=(2,)))
    (value,) = join.params
    tag = join.op1(Operation.SUM_TAG, (value,), B8)
    scalar, pair_case, flag_case = graph.block(), graph.block(), graph.block()
    other = graph.block()
    join.cbr(join.op1(Operation.INT_COMPARE, (tag, join.const(B8, 0)), B1, attributes=(IntCompare.EQ,)), scalar, (), other, ())
    other.cbr(other.op1(Operation.INT_COMPARE, (tag, other.const(B8, 1)), B1, attributes=(IntCompare.EQ,)), pair_case, (), flag_case, ())
    scalar.ret(scalar.op1(Operation.MUL_WRAP, (scalar.op1(Operation.SUM_GET, (value,), B32, attributes=(0,)), scalar.const(B32, 3)), B32))
    pair_value = pair_case.op1(Operation.SUM_GET, (value,), both, attributes=(1,))
    pair_case.ret(pair_case.op1(Operation.SUB_WRAP, (pair_case.op1(Operation.AGGREGATE_GET, (pair_value,), B32, attributes=(0,)), pair_case.op1(Operation.AGGREGATE_GET, (pair_value,), B32, attributes=(1,))), B32))
    flag_case.ret(flag_case.op1(Operation.INT_ZERO_EXTEND, (flag_case.op1(Operation.SUM_GET, (value,), B1, attributes=(2,)),), B32))
    function = graph.function((B32, B32, B32), (B32,))
    return function, (both, choice, B1, B8, B32, *graph.objects.values())


def _wrong_variant_program():
    choice = sum_type((B32, B64))
    graph = GraphBuilder()
    entry = graph.block(B32)
    (a,) = entry.params
    value = entry.op1(Operation.SUM_MAKE, (a,), choice, attributes=(0,))
    entry.ret(entry.op1(Operation.SUM_GET, (value,), B64, attributes=(1,)))
    return graph.function((B32,), (B64,)), (choice, B32, B64, *graph.objects.values())


def _indirect_program():
    """``f(selector, a, b)``: a function pointer chosen at run time, passed on, and called."""
    opaque_function = opaque_type(OpaqueKind.FUNCTION)
    function_pointer = pointer_type(opaque_function, Permission.READ, 8, space=2)
    contract = call_contract((B32, B32), (B32,), may_return=True, may_trap=False)

    def binary(operation):
        graph = GraphBuilder()
        block = graph.block(B32, B32)
        block.ret(block.op1(operation, block.params, B32))
        return graph.function((B32, B32), (B32,)), tuple(graph.objects.values())

    add, add_objects = binary(Operation.ADD_WRAP)
    multiply, multiply_objects = binary(Operation.MUL_WRAP)

    apply_graph = GraphBuilder()
    apply_block = apply_graph.block(function_pointer, B32, B32)
    pointer, x, y = apply_block.params
    once = apply_block.op1(Operation.CALL_INDIRECT, (pointer, x, y), B32, entity=contract)
    apply_block.ret(apply_block.op1(Operation.CALL_INDIRECT, (pointer, once, y), B32, entity=contract))
    apply = apply_graph.function((function_pointer, B32, B32), (B32,))

    graph = GraphBuilder()
    entry = graph.block(B32, B32, B32)
    selector, a, b = entry.params
    call = graph.block(function_pointer)
    entry.cbr(
        entry.op1(Operation.INT_COMPARE, (selector, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)),
        call, (entry.op1(Operation.FUNCTION_ADDRESS, (), function_pointer, entity=add),),
        call, (entry.op1(Operation.FUNCTION_ADDRESS, (), function_pointer, entity=multiply),),
    )
    (chosen,) = call.params
    call.ret(call.op1(Operation.CALL_DIRECT, (chosen, a, b), B32, entity=apply))
    function = graph.function((B32, B32, B32), (B32,))
    objects = (opaque_function, function_pointer, contract, B1, B32, *add_objects, add, *multiply_objects, multiply, *apply_graph.objects.values(), apply, *graph.objects.values())
    return function, objects


def _recursive_stack_program():
    """``sum(n)``: each activation keeps ``n`` in its own stack slot across the recursive call,
    and returns ``(total, depth)`` as an aggregate: ``n + (n - 1) + ... + 1``."""
    result = tuple_type((B32, B32))
    words = pointer_type(B32, Permission.READ_WRITE, 4)
    owner, effect = stack_owner_type(), memory_effect_type()
    graph = GraphBuilder()
    entry = graph.block(B32)
    (n,) = entry.params
    base, recurse = graph.block(), graph.block()
    entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)), base, (), recurse, ())
    base.ret(base.op1(Operation.AGGREGATE_MAKE, (base.const(B32, 0), base.const(B32, 0)), result))
    slot, slot_owner, memory = recurse.op(Operation.STACK_ALLOC, (), (words, owner, effect), attributes=(4, 4))
    memory = recurse.op1(Operation.STORE_BITS_LE, (slot, n, memory), effect, attributes=(4, 4))
    smaller = recurse.op1(Operation.SUB_WRAP, (n, recurse.const(B32, 1)), B32)
    recurse.nodes.append(Node(Operation.CALL_GROUP_MEMBER, (smaller,), (result,), member=0))
    inner = ValueRef.node_result(recurse.index, len(recurse.nodes) - 1)
    recurse.owner.track(result)
    kept, memory = recurse.op(Operation.LOAD_BITS_LE, (slot, memory), (B32, effect), attributes=(4, 4))
    recurse.nodes.append(Node(Operation.STACK_END, (slot_owner, memory), ()))
    total = recurse.op1(Operation.ADD_WRAP, (recurse.op1(Operation.AGGREGATE_GET, (inner,), B32, attributes=(0,)), kept), B32)
    depth = recurse.op1(Operation.ADD_WRAP, (recurse.op1(Operation.AGGREGATE_GET, (inner,), B32, attributes=(1,)), recurse.const(B32, 1)), B32)
    recurse.ret(recurse.op1(Operation.AGGREGATE_MAKE, (total, depth), result))
    fragment = graph_fragment([Block(block.parameter_types, tuple(block.nodes), block.terminator) for block in graph.blocks])
    group = recursion_group([RecursionMember(fragment, (B32,), (result,))])
    member = group_member_function(group, 0)

    outer = GraphBuilder()
    block = outer.block(B32)
    pair = block.op1(Operation.CALL_DIRECT, block.params, result, entity=member)
    block.ret(block.op1(Operation.ADD_WRAP, (
        block.op1(Operation.MUL_WRAP, (block.op1(Operation.AGGREGATE_GET, (pair,), B32, attributes=(1,)), block.const(B32, 1 << 20)), B32),
        block.op1(Operation.AGGREGATE_GET, (pair,), B32, attributes=(0,)),
    ), B32))
    function = outer.function((B32,), (B32,))
    return function, (result, words, owner, effect, B1, B32, *graph.objects.values(), fragment, group, member, *outer.objects.values())


@unittest.skipUnless(JAVA, "requires java and javac")
class JvmGeneralProfileTests(unittest.TestCase):
    def _check(self, program, calls, *, width=32):
        function, objects = program
        reader, image = _compile(function, objects)
        self.assertEqual(run_jvm_calls(image, calls, result_width=width), tuple(_reference(reader, function.cid, call) for call in calls))
        return image

    def test_nested_aggregates_through_calls_and_block_parameters(self):
        calls = [(a, b, x) for a in (0, 7, 99, 100, (1 << 32) - 1) for b in (0, 1, (1 << 64) - 1, 0x0123456789ABCDEF) for x in (0.0, 2.5, 1e6)]
        self._check(_aggregate_program(), calls, width=64)

    def test_sums_made_on_paths_and_dispatched_on_their_tag(self):
        calls = [(s, a, b) for s in (0, 1, 2, 7) for a in (0, 5, (1 << 32) - 1) for b in (0, 3, 9)]
        self._check(_sum_program(), calls)

    def test_a_wrong_sum_variant_traps(self):
        self.assertEqual(self._check(_wrong_variant_program(), [(1,), (0,)], width=64) and None, None)

    def test_indirect_calls_through_a_chosen_and_passed_pointer(self):
        calls = [(s, a, b) for s in (0, 1) for a in (0, 3, (1 << 32) - 1) for b in (0, 2, 1 << 31)]
        self._check(_indirect_program(), calls)

    def test_stack_frames_and_aggregates_in_recursion(self):
        image = self._check(_recursive_stack_program(), [(0,), (1,), (2,), (10,), (100,)])
        self.assertIn(b"fill", image.class_bytes)  # stack allocations are zero-filled
        # Deeper than the reference executor recurses (the harness thread's own JVM stack
        # bounds it; a process entry runs on the 256 MiB entry thread).
        n = 3_000
        self.assertEqual(run_jvm_calls(image, [(n,)], result_width=32), (((n << 20) + n * (n + 1) // 2) & 0xFFFFFFFF,))


    def test_the_shadow_stack_holds_deep_recursion_and_traps_beyond_it(self):
        from xax_jvm import STACK_BYTES, run_jvm_jar

        def process(depth: int):
            member_function, objects = _recursive_stack_program()
            member = next(item for item in objects if getattr(item, "kind", None) is not None and item.cid != member_function.cid and item.kind.name == "FUNCTION")
            graph = GraphBuilder()
            block = graph.block()
            block.op1(Operation.CALL_DIRECT, (block.const(B32, depth),), objects[0], entity=member)
            block.ret()
            entry = graph.function((), ())
            target = jvm_classfile_general_target()
            reader = program_store(entry, target, (*objects, *graph.objects.values()))
            return run_jvm_jar(compile_jvm_bound_target(reader, entry.cid, target, process_entry=True))

        frame = 16  # one 4-byte slot, frames 16-aligned
        fits = process(STACK_BYTES // frame // 2)
        self.assertEqual((fits.returncode, fits.stderr), (0, b""))
        overflow = process(STACK_BYTES // frame * 2)
        self.assertEqual(overflow.returncode, 1)
        self.assertIn(b"java.lang.Error", overflow.stderr)


class JvmGeneralProfileRejectionTests(unittest.TestCase):
    def test_the_memory_profile_rejects_aggregates_sums_and_indirect_calls(self):
        for program in (_aggregate_program(), _sum_program(), _indirect_program()):
            function, objects = program
            with self.subTest(function=function.cid.hex()[:8]):
                with self.assertRaises(XaxError) as caught:
                    _compile(function, objects, jvm_classfile_memory_target())
                self.assertEqual(caught.exception.diagnostic.rule, "JVM-OP-TARGET-SUPPORTED")


if __name__ == "__main__":
    unittest.main()
