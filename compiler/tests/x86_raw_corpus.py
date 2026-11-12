"""S15f.2 (ADR-324): Windows load images (``x86_64-windows-load-image-v2``, ``-oi06-v1``, ``-v5``) for the differential
tests of the XAX general program.

``x86_raw_case(rng)`` gives ``(reader, entry, target, name)``: random functions over the operations the drawn profile
lists (wrapping arithmetic at 8 to 64 bits, constants, direct calls to random helpers, stack storage with plain and,
where listed, checked accesses; on v5 also compares and loops, xor and rotations, binary32/binary64 arithmetic,
compares and conversions, tuples and sums), and functions the profile rejects (an operation it does not list).
"""

from __future__ import annotations

import random

from xax_compiler import (
    FloatCompare, FloatFormat, IntCompare, Operation, Permission, XaxError, bits_type, decode_native_target, float_constant, float_type,
    memory_effect_type, oi06_x86_64_windows_target, pointer_type, stack_owner_type, sum_type, tuple_type, x86_64_windows_general_target,
    x86_64_windows_target,
)
from xax_graph_builder import GraphBuilder, program_store

B1, B8, B16, B32, B64 = (bits_type(w) for w in (1, 8, 16, 32, 64))
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
INTS = (B8, B16, B32, B64)
WIDTH = {B8: 8, B16: 16, B32: 32, B64: 64}
TARGETS = (x86_64_windows_target, oi06_x86_64_windows_target, x86_64_windows_general_target)


class _Pools:
    def __init__(self, rng):
        self.rng, self.values = rng, {}

    def add(self, kind, value):
        self.values.setdefault(kind, []).append(value)

    def pick(self, block, kind):
        items = self.values.get(kind)
        if items and self.rng.random() < 0.8:
            return self.rng.choice(items)
        if kind in (F32, F64):
            value = block.op1(Operation.CONSTANT, (), kind, entity=float_constant(kind, self.rng.choice((0.5, -2.25, 1e10, 3.0))))
        else:
            value = block.const(kind, self.rng.randrange(1 << WIDTH[kind]))
        self.add(kind, value)
        return value


def _function(rng, ops, objects: list, fault: str | None, depth: int = 0):
    """A random function over ``ops`` (the profile's operation numbers); one ``bits`` result."""
    floats = Operation.FLOAT_ADD in ops
    kinds = INTS + ((F32, F64) if floats else ())
    params = tuple(rng.choice(INTS) for _ in range(rng.randrange(0, 4)))
    graph = GraphBuilder()
    block = graph.block(*params)
    pools = _Pools(rng)
    for t, value in zip(params, block.params):
        pools.add(t, value)
    arithmetic = [Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP] + ([Operation.BIT_XOR] if Operation.BIT_XOR in ops else [])
    for _ in range(rng.randrange(2, 9)):
        kind = rng.randrange(6)
        t = rng.choice(INTS)
        if kind < 3 or not floats:
            pools.add(t, block.op1(rng.choice(arithmetic), (pools.pick(block, t), pools.pick(block, t)), t))
        elif kind == 3:
            f = rng.choice((F32, F64))
            pools.add(f, block.op1(rng.choice((Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV)),
                                   (pools.pick(block, f), pools.pick(block, f)), f))
        elif kind == 4:
            f = rng.choice((F32, F64))
            if rng.random() < 0.5:
                pools.add(f, block.op1(rng.choice((Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT)), (pools.pick(block, t),), f))
            else:
                pools.add(t, block.op1(rng.choice((Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC)), (pools.pick(block, f),), t))
        else:
            flag = block.op1(Operation.INT_COMPARE, (pools.pick(block, t), pools.pick(block, t)), B1, attributes=(rng.choice(list(IntCompare)),))
            pools.add(B1, flag)
        if Operation.ROTATE_RIGHT in ops and rng.random() < 0.2:
            t = rng.choice((B32, B64))
            pools.add(t, block.op1(Operation.ROTATE_RIGHT, (pools.pick(block, t),), t, attributes=(rng.randrange(WIDTH[t]),)))
    if fault == "unsupported":
        pools.add(B32, block.op1(Operation.BIT_AND, (pools.pick(block, B32), pools.pick(block, B32)), B32))
    if rng.random() < 0.5:
        # Stack storage: plain stores initialize every element, then plain and (where listed) checked loads.
        element = rng.choice(INTS)
        size, count = WIDTH[element] // 8, rng.choice((1, 2, 4))
        owner_type, memory_type = stack_owner_type(), memory_effect_type()
        pointer = pointer_type(element, Permission.READ_WRITE, size)
        objects += [owner_type, memory_type, pointer]
        base, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, owner_type, memory_type), attributes=(size * count, size))
        for k in range(count):
            at = block.op1(Operation.ADDRESS_OFFSET, (base,), pointer, attributes=(k * size,)) if k else base
            memory = block.op1(Operation.STORE_BITS_LE, (at, pools.pick(block, element), memory), memory_type, attributes=(size, 1))
        loaded, memory = block.op(Operation.LOAD_BITS_LE, (base, memory), (element, memory_type), attributes=(size, 1))
        pools.add(element, loaded)
        if Operation.CHECKED_LOAD_BITS_LE in ops:
            index = block.const(B32, rng.randrange(count) * size)
            loaded, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (base, index, memory), (element, memory_type), attributes=(size, 1))
            pools.add(element, loaded)
        block.op(Operation.STACK_END, (owner, memory), ())
    if floats and rng.random() < 0.3:
        pair = tuple_type((B32, F64))
        objects.append(pair)
        made = block.op1(Operation.AGGREGATE_MAKE, (pools.pick(block, B32), pools.pick(block, F64)), pair)
        pools.add(B32, block.op1(Operation.AGGREGATE_GET, (made,), B32, attributes=(0,)))
        choice = sum_type((B64, F32))
        objects.append(choice)
        tag = rng.randrange(2)
        made_sum = block.op1(Operation.SUM_MAKE, (pools.pick(block, (B64, F32)[tag]),), choice, attributes=(tag,))
        pools.add(B32, block.op1(Operation.SUM_TAG, (made_sum,), B32))
    if depth < 2 and rng.random() < 0.4:
        callee, callee_params = _function(rng, ops, objects, None, depth + 1)
        result_type = B32
        pools.add(result_type, block.op1(Operation.CALL_DIRECT, tuple(pools.pick(block, t) for t in callee_params), result_type, entity=callee))
    result = pools.pick(block, B32)
    if Operation.INT_COMPARE in ops and rng.random() < 0.3:
        loop, done = graph.block(B32, B32), graph.block(B32)
        block.br(loop, result, block.const(B32, rng.randrange(1, 4)))
        value, count = loop.params
        more = loop.op1(Operation.INT_COMPARE, (count, loop.const(B32, 0)), B1, attributes=(IntCompare.NE,))
        loop.cbr(more, loop, (loop.op1(Operation.MUL_WRAP, (value, loop.const(B32, 3)), B32), loop.op1(Operation.SUB_WRAP, (count, loop.const(B32, 1)), B32)),
                 done, (value,))
        done.ret(done.params[0])
    else:
        block.ret(result)
    function = graph.function(params, (B32,))
    objects += [*graph.objects.values(), B1, *INTS, F32, F64]
    return function, params


def x86_raw_case(rng: random.Random):
    """``(reader, entry, target, name)``; a program the verifier rejects is drawn again."""
    while True:
        target = rng.choice(TARGETS)()
        name = rng.choice(("random", "random", "random", "unsupported"))
        ops = set(decode_native_target(target).supported_operations)
        objects: list = []
        try:
            entry, _params = _function(rng, ops, objects, None if name == "random" else name)
            return program_store(entry, target, tuple(objects)), entry, target, f"{decode_native_target(target).identity.decode()} {name}"
        except (XaxError, ValueError, KeyError, AttributeError, TypeError):
            continue
