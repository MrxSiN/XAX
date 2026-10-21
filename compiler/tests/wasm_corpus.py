"""S15e.4 (ADR-322): browser pages for the differential tests of the XAX general program.

``wasm_case(rng)`` gives ``(reader, entry, target, name)``: the benchmark page (``benchmarks.browser_fib``), pages that
render through the web bindings, and ``_start`` pages calling random helpers over every lowered operation (wrapping and
bitwise integer arithmetic at 8 to 64 bits, compares, resizes, binary32/binary64 arithmetic, compares and conversions
both ways, stack storage with checked and plain accesses, tuples, arrays and sums, nested calls, loops carrying values
through block parameters), and pages each rule rejects: an entry with machine values, a helper with two results, an
operation the target does not list, an internal function address, too much static memory, a checked
access through a pointer of unknown extent, a 64-bit pointer address, an undeclared or non-``wasm32-import`` binding.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

from xax_compiler import (
    FloatCompare, FloatFormat, IntCompare, Operation, Permission, XaxError, array_type, bits_type, float_constant, float_type,
    foreign_function_symbol, function_pointer_type, opaque_type, OpaqueKind, pointer_type, stack_owner_type, sum_type, tuple_type,
    wasm32_browser_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_web import web_api

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.browser_fib import fib_page_program  # noqa: E402

B1, B8, B16, B32, B64 = (bits_type(w) for w in (1, 8, 16, 32, 64))
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
INTS = (B8, B16, B32, B64)
FLOATS = (F32, F64)
WIDTH = {B8: 8, B16: 16, B32: 32, B64: 64}
ARITHMETIC = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR,
              Operation.UDIV, Operation.UREM)
FLOAT_ARITHMETIC = (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV)
FAULTS = ("entry_machine", "two_returns", "unsupported", "internal_address", "memory", "extent", "address_width",
          "forged_import", "foreign_abi")


def _constant(block, kind, rng):
    if kind in FLOATS:
        value = rng.choice((0.0, -0.0, 1.5, -3.25, 1e30, 255.75, 65536.0, float("inf")))
        return block.op1(Operation.CONSTANT, (), kind, entity=float_constant(kind, value))
    return block.const(kind, rng.randrange(1 << WIDTH[kind]) if rng.random() < 0.7 else rng.choice((0, 1, 3, (1 << WIDTH[kind]) - 1)))


class _Pools:
    def __init__(self, rng):
        self.rng = rng
        self.values = {}

    def add(self, kind, value):
        self.values.setdefault(kind, []).append(value)

    def pick(self, block, kind):
        items = self.values.get(kind)
        if items and self.rng.random() < 0.8:
            return self.rng.choice(items)
        value = _constant(block, kind, self.rng)
        self.add(kind, value)
        return value


def _straight(block, pools: _Pools, rng, steps: int, objects: list):
    """Random value-computing nodes in ``block``."""
    for _ in range(steps):
        kind = rng.randrange(10)
        if kind < 3:
            t = rng.choice(INTS)
            pools.add(t, block.op1(rng.choice(ARITHMETIC), (pools.pick(block, t), pools.pick(block, t)), t))
        elif kind == 3:
            t = rng.choice(INTS)
            flag = block.op1(Operation.INT_COMPARE, (pools.pick(block, t), pools.pick(block, t)), B1, attributes=(rng.choice(list(IntCompare)),))
            target = rng.choice(INTS)
            pools.add(target, block.op1(Operation.INT_ZERO_EXTEND, (flag,), target))
        elif kind == 4:
            source, target = rng.sample(INTS, 2)
            operation = Operation.INT_TRUNCATE if WIDTH[target] < WIDTH[source] else Operation.INT_ZERO_EXTEND
            pools.add(target, block.op1(operation, (pools.pick(block, source),), target))
        elif kind == 5:
            t = rng.choice(FLOATS)
            pools.add(t, block.op1(rng.choice(FLOAT_ARITHMETIC), (pools.pick(block, t), pools.pick(block, t)), t))
        elif kind == 6:
            t = rng.choice(FLOATS)
            flag = block.op1(Operation.FLOAT_COMPARE, (pools.pick(block, t), pools.pick(block, t)), B1, attributes=(rng.choice(list(FloatCompare)),))
            pools.add(B32, block.op1(Operation.INT_ZERO_EXTEND, (flag,), B32))
        elif kind == 7:
            source, target = rng.choice(FLOATS), rng.choice(INTS)
            operation = rng.choice((Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC))
            pools.add(target, block.op1(operation, (pools.pick(block, source),), target))
        elif kind == 8:
            source, target = rng.choice(INTS), rng.choice(FLOATS)
            operation = rng.choice((Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT))
            pools.add(target, block.op1(operation, (pools.pick(block, source),), target))
        else:
            source, target = rng.choice(FLOATS), rng.choice(FLOATS)
            pools.add(target, block.op1(Operation.FLOAT_CONVERT, (pools.pick(block, source),), target))


def _memory(block, pools: _Pools, rng, objects: list, fault: str | None):
    """Stack storage, every element written by checked stores, then checked and plain accesses."""
    owner_type = stack_owner_type()
    memory_type = web_api().memory_effect
    element = rng.choice(INTS)
    size = WIDTH[element] // 8
    count = rng.choice((1, 2, 4))
    extent = 70000 if fault == "memory" else size * count
    alignment = rng.choice([a for a in (1, 2, 4, 8) if a <= size])
    pointer = pointer_type(element, Permission.READ_WRITE, alignment)
    objects += [owner_type, pointer, memory_type]
    base, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, owner_type, memory_type), attributes=(extent, alignment))
    if fault != "memory":
        for k in range(count):  # plain stores at static offsets initialize the view (checked stores cannot)
            at = block.op1(Operation.ADDRESS_OFFSET, (base,), pointer, attributes=(k * size,)) if k else base
            memory = block.op1(Operation.STORE_BITS_LE, (at, pools.pick(block, element), memory), memory_type, attributes=(size, 1))
        memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (base, block.const(B32, rng.randrange(count) * size), pools.pick(block, element), memory),
                           memory_type, attributes=(size, 1))
        for _ in range(rng.randrange(1, 3)):
            index = block.const(B32, rng.randrange(count) * size)
            loaded, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (base, index, memory), (element, memory_type), attributes=(size, 1))
            pools.add(element, loaded)
        if rng.random() < 0.5:
            index = block.const(B32, rng.choice((extent, extent + size, 1 << 20)))  # out of range: the access traps
            loaded, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (base, index, memory), (element, memory_type), attributes=(size, 1))
            pools.add(element, loaded)
        if rng.random() < 0.5:
            memory = block.op1(Operation.STORE_BITS_LE, (base, pools.pick(block, element), memory), memory_type, attributes=(size, 1))
            plain, memory = block.op(Operation.LOAD_BITS_LE, (base, memory), (element, memory_type), attributes=(size, 1))
            pools.add(element, plain)
    if fault == "address_width":
        pools.add(B64, block.op1(Operation.POINTER_ADDRESS, (base,), B64, attributes=(1,)))
    elif rng.random() < 0.3:
        pools.add(B32, block.op1(Operation.POINTER_ADDRESS, (base,), B32, attributes=(1,)))
    block.op(Operation.STACK_END, (owner, memory), ())


def _aggregates(block, pools: _Pools, rng, objects: list):
    """A tuple or array made and read back, and a sum made, tagged and read."""
    items = [rng.choice((*INTS, *FLOATS)) for _ in range(rng.randrange(1, 4))]
    if rng.random() < 0.5:
        aggregate = tuple_type(items)
        operands = [pools.pick(block, t) for t in items]
    else:
        aggregate = array_type(items[0], len(items))
        operands = [pools.pick(block, items[0]) for _ in items]
        items = [items[0]] * len(items)
    objects.append(aggregate)
    made = block.op1(Operation.AGGREGATE_MAKE, tuple(operands), aggregate)
    k = rng.randrange(len(items))
    pools.add(items[k], block.op1(Operation.AGGREGATE_GET, (made,), items[k], attributes=(k,)))
    variants = (aggregate, rng.choice(INTS))
    choice = sum_type(variants)
    objects.append(choice)
    tag = rng.randrange(2)
    made_sum = block.op1(Operation.SUM_MAKE, (made if tag == 0 else pools.pick(block, variants[1]),), choice, attributes=(tag,))
    pools.add(B32, block.op1(Operation.SUM_TAG, (made_sum,), B32))
    read = block.op1(Operation.SUM_GET, (made_sum,), variants[tag], attributes=(tag,))
    if tag == 0:
        pools.add(items[0], block.op1(Operation.AGGREGATE_GET, (read,), items[0], attributes=(0,)))
    else:
        pools.add(variants[1], read)
    return aggregate, made


def _helper(rng, objects: list, fault: str | None, depth: int = 0):
    """A random function: parameters, nodes, maybe memory, aggregates, a callee and a loop; one result (two for
    ``two_returns``)."""
    params = tuple(rng.choice((*INTS, *FLOATS)) for _ in range(rng.randrange(0, 4)))
    graph = GraphBuilder()
    block = graph.block(*params)
    pools = _Pools(rng)
    for t, value in zip(params, block.params):
        pools.add(t, value)
    _straight(block, pools, rng, rng.randrange(2, 10), objects)
    if fault == "unsupported":
        pools.add(B32, block.op1(Operation.ROTATE_RIGHT, (pools.pick(block, B32),), B32, attributes=(3,)))
    if rng.random() < 0.4 or fault in ("memory", "address_width"):
        _memory(block, pools, rng, objects, fault)
    aggregate_result = None
    if rng.random() < 0.4:
        aggregate_result = _aggregates(block, pools, rng, objects)
    if depth < 2 and rng.random() < 0.4:
        callee, callee_params, callee_results = _helper(rng, objects, None, depth + 1)
        results = block.op(Operation.CALL_DIRECT, tuple(pools.pick(block, t) for t in callee_params), callee_results, entity=callee)
        for t, value in zip(callee_results, results if isinstance(results, tuple) else (results,)):
            pools.add(t, value)
    result_type = rng.choice((*INTS, *FLOATS))
    if aggregate_result is not None and rng.random() < 0.4:
        result_type, result = aggregate_result
    else:
        result = pools.pick(block, result_type)
    if fault == "extent" or rng.random() < 0.3:
        # A loop carrying the result (and, for ``extent``, a stack pointer whose extent the lowering cannot know).
        carried = [result_type, B32]
        if fault == "extent":
            owner_type, memory_type = stack_owner_type(), web_api().memory_effect
            pointer = pointer_type(B32, Permission.READ_WRITE, 1)
            objects += [owner_type, pointer, memory_type]
            base, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, owner_type, memory_type), attributes=(4, 1))
            memory = block.op1(Operation.STORE_BITS_LE, (base, block.const(B32, 7), memory), memory_type, attributes=(4, 1))
            carried += [pointer, memory_type, owner_type]
        loop = graph.block(*carried)
        done = graph.block(*carried)
        start = [result, block.const(B32, rng.randrange(1, 4))]
        if fault == "extent":
            start += [base, memory, owner]
        block.br(loop, *start)
        value, count, *rest = loop.params
        more = loop.op1(Operation.INT_COMPARE, (count, loop.const(B32, 0)), B1, attributes=(IntCompare.NE,))
        step = loop.op1(Operation.SUB_WRAP, (count, loop.const(B32, 1)), B32)
        loop.cbr(more, loop, (value, step, *rest), done, (value, count, *rest))
        result, _count, *rest = done.params
        if fault == "extent":
            loaded, memory = done.op(Operation.CHECKED_LOAD_BITS_LE, (rest[0], done.const(B32, 0), rest[1]), (B32, web_api().memory_effect), attributes=(4, 1))
            done.op(Operation.STACK_END, (rest[2], memory), ())
        block = done
    results = (result_type, result_type) if fault == "two_returns" else (result_type,)
    if fault == "two_returns":
        block.ret(result, result)
    else:
        block.ret(result)
    function = graph.function(params, results)
    objects += list(graph.objects.values())
    return function, params, results


def _start(rng, fault: str | None):
    api = web_api()
    objects = [*api.types, *api.symbols, B1, *INTS, *FLOATS]
    entry_params = (api.page_effect, B32) if fault == "entry_machine" else (api.page_effect,)
    graph = GraphBuilder()
    block = graph.block(*entry_params)
    page = block.params[0]
    helper_fault = fault if fault in ("two_returns", "unsupported", "memory", "extent", "address_width") else None
    for _ in range(rng.randrange(1, 3)):
        helper, params, results = _helper(rng, objects, helper_fault)
        block.op(Operation.CALL_DIRECT, tuple(_constant(block, t, rng) for t in params), results, entity=helper)
    if fault == "internal_address" or rng.random() < 0.3:
        handler_graph = GraphBuilder()
        handler_block = handler_graph.block(api.page_effect)
        handler_block.ret(*handler_block.params)
        handler = handler_graph.function((api.page_effect,), (api.page_effect,))
        objects += [opaque_type(OpaqueKind.FUNCTION), *handler_graph.objects.values()]
        address_type = function_pointer_type() if fault == "internal_address" else api.event_entry
        objects.append(address_type)
        address = block.op1(Operation.FUNCTION_ADDRESS, (), address_type, entity=handler)
        if fault != "internal_address":
            page = block.op1(Operation.CALL_FOREIGN, (address, page), api.page_effect, entity=api.body_on_click)
    if fault in ("forged_import", "foreign_abi") or rng.random() < 0.4:
        owner_type = stack_owner_type()
        objects.append(owner_type)
        buffer, owner, memory = block.op(Operation.STACK_ALLOC, (), (api.bytes_rw, owner_type, api.memory_effect), attributes=(4, 1))
        memory = block.op1(Operation.STORE_BITS_LE, (buffer, block.const(api.b8, 65), memory), api.memory_effect, attributes=(1, 1))
        readable = block.op1(Operation.POINTER_CAST, (buffer,), api.bytes_read)
        binding = api.set_body_text
        if fault == "forged_import":
            binding = foreign_function_symbol(b"xax-web-v1", b"eval", (api.bytes_read, B32, api.page_effect, api.memory_effect),
                                              (api.page_effect, api.memory_effect), abi=b"wasm32-import")
        elif fault == "foreign_abi":
            binding = foreign_function_symbol(b"xax-web-v1", b"set_body_text", (api.bytes_read, B32, api.page_effect, api.memory_effect),
                                              (api.page_effect, api.memory_effect), abi=b"sysv-x86_64-c")
        objects.append(binding)
        page, memory = block.op(Operation.CALL_FOREIGN, (readable, block.const(B32, 1), page, memory), (api.page_effect, api.memory_effect), entity=binding)
        if rng.random() < 0.5:
            length, page, memory = block.op(Operation.CALL_FOREIGN, (buffer, block.const(B32, 4), page, memory), (B32, api.page_effect, api.memory_effect),
                                            entity=rng.choice((api.query_copy, api.body_text_copy)))
        block.op(Operation.STACK_END, (owner, memory), ())
    block.ret(page)
    start = graph.function(entry_params, (api.page_effect,))
    objects += list(graph.objects.values())
    target = wasm32_browser_target()
    return program_store(start, target, tuple(objects)), start, target


def wasm_case(rng: random.Random):
    """``(reader, entry, target, name)``; a program the verifier rejects is drawn again."""
    while True:
        name = rng.choice(("fib", "random", "random", "random", "random", *FAULTS))
        try:
            if name == "fib":
                return (*fib_page_program(), name)
            fault = None if name == "random" else name
            return (*_start(rng, fault), name)
        except (XaxError, ValueError, KeyError, AttributeError, TypeError):
            continue
