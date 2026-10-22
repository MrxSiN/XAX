"""S15e.3b (ADR-326): Windows PE32+ programs whose functions the bootstrap lowers on the hosted legacy register path, for
the differential tests of the XAX general program.

``pe_legacy_case(rng)`` gives ``(reader, entry, target, name)``: a process entry that calls a random function ``f``.
``f`` calls a small float leaf the lowering view inlines (so the register-resident lowering of the view declines and
the bootstrap tries ``_compile_register_resident_function`` on ``f``'s own graph); its body draws 32/64-bit wrapping
arithmetic over many live values, constants, integer compares, direct calls, ``win64-c`` imports (``VirtualAlloc``,
``VirtualFree`` consuming a heap view, an import taking a code address), heap views with plain and checked loads and
stores through address offsets and pointer casts, a conditional diamond joined by up to eight parameters (edge spill
slots), entry values used across blocks (homes), and counted loops.  ``fault`` adds a COM method call (``com``), a
foreign call of another ABI (``abi``: NATIVE-FOREIGN-ABI), a malformed COM method (``malformed``: WIN64-COM-METHOD), or
a checked access of a view past 2^31 bytes (``bound``: NATIVE-CHECKED-BOUND-ENCODABLE).
"""

from __future__ import annotations

import random

from xax_compiler import (
    COM_LIBRARY_PREFIX, FloatFormat, IntCompare, Operation, XaxError, bits_type, float_type, foreign_function_symbol, function_pointer_type,
    heap_view_type, pointer_type, win64_com_method, x86_64_windows_pe_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_platform import win32_kernel32_api

B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
F64 = float_type(FloatFormat.BINARY64)
WIDE = (B32, B64)
WIDTH = {B32: 32, B64: 64}


def _leaf(width):
    """``f(a, b) = trunc(float(a)) + b``: a float leaf the view inlines."""
    graph = GraphBuilder()
    graph.track(F64)
    block = graph.block(width, width)
    floating = block.op1(Operation.UINT_TO_FLOAT, (block.params[0],), F64)
    block.ret(block.op1(Operation.ADD_WRAP, (block.op1(Operation.FLOAT_TO_UINT_TRUNC, (floating,), width), block.params[1]), width))
    return graph.function((width, width), (width,)), graph


def _outer(width, leaf):
    graph = GraphBuilder()
    block = graph.block(width, width)
    called = block.op1(Operation.CALL_DIRECT, (block.params[0], block.params[1]), width, entity=leaf)
    block.ret(block.op1(Operation.SUB_WRAP, (called, block.params[0]), width))
    return graph.function((width, width), (width,)), graph


def pe_legacy_case(rng: random.Random, fault: str | None = None):
    """``(reader, entry, target, name)``; a program the verifier rejects is drawn again."""
    while True:
        try:
            return _case(rng, fault)
        except (XaxError, ValueError, KeyError, AttributeError, TypeError):
            continue


def _case(rng, fault):
    api = win32_kernel32_api()
    mem = api.memory_effect
    value = rng.choice(WIDE)
    leaf, leaf_graph = _leaf(value)
    outer, outer_graph = _outer(value, leaf)
    graphs = [leaf_graph, outer_graph]
    extras = [F64, B1, B32, B64, leaf, outer]
    graph = GraphBuilder()
    count = rng.randint(0, 3)
    entry = graph.block(*(value,) * count, mem)
    *inputs, memory = entry.params
    pool = list(inputs) or [entry.const(value, rng.getrandbits(WIDTH[value]))]
    flags = []
    name = []

    def operations(block, pool, n, flags):
        for _ in range(n):
            roll = rng.random()
            if roll < 0.12:
                pool.append(block.const(value, rng.choice((0, 1, 7, 255, rng.getrandbits(WIDTH[value])))))
            elif roll < 0.22:
                pool.append(block.op1(Operation.CALL_DIRECT, (rng.choice(pool), rng.choice(pool)), value, entity=rng.choice((leaf, outer))))
            elif roll < 0.32:
                flags.append(block.op1(Operation.INT_COMPARE, (rng.choice(pool), rng.choice(pool)), B1, attributes=(rng.choice(list(IntCompare)),)))
            else:
                pool.append(block.op1(rng.choice((Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP)), (rng.choice(pool), rng.choice(pool)), value))

    pool.append(entry.op1(Operation.CALL_DIRECT, (pool[0], pool[-1]), value, entity=leaf))  # inlined: keeps the view off
    operations(entry, pool, rng.randint(2, 18), flags)
    if rng.random() < 0.6:
        # A heap view: VirtualAlloc, plain and checked accesses through offsets and casts, VirtualFree.
        name.append("heap")
        element = rng.choice(WIDE)
        size = WIDTH[element] // 8
        extent = (1 << 31) + 8 * size if fault == "bound" else size * rng.choice((1, 2, 4, 8))
        elem_ptr = pointer_type(element, 3, size, space=2)
        byte_ptr = pointer_type(bits_type(8), 3, 1, space=2)
        view = heap_view_type(extent)
        free = api.virtual_free_view(view, elem_ptr)
        extras += [elem_ptr, byte_ptr, view, free, element]
        raw, owner, memory = entry.op(Operation.CALL_FOREIGN, (entry.const(B64, 0), entry.const(B64, extent), entry.const(B32, 0x3000),
                                                              entry.const(B32, 4), memory), (api.heap_ptr_rw, api.heap_resource, mem),
                                      entity=api.virtual_alloc)
        base, token, memory = entry.op(Operation.HEAP_VIEW, (raw, owner, memory), (elem_ptr, view, mem), attributes=(extent, size))
        def element_value():
            if element == value:
                return rng.choice(pool)
            return entry.const(element, rng.getrandbits(WIDTH[element]))

        loaded = []
        for trial in range(rng.randint(1, 5)):
            roll = 0.4 if fault == "bound" and trial == 0 else rng.random()
            if roll < 0.3:
                at = entry.op1(Operation.ADDRESS_OFFSET, (base,), elem_ptr, attributes=(size * rng.randrange(extent // size),)) if extent > size else base
                memory = entry.op1(Operation.STORE_BITS_LE, (at, element_value(), memory), mem, attributes=(size, size))
            elif roll < 0.55:
                index = entry.const(B32, size * rng.randrange(extent // size + 1))
                memory = entry.op1(Operation.CHECKED_STORE_BITS_LE, (base, index, element_value(), memory), mem, attributes=(size, 1))
            elif roll < 0.8:
                index = rng.choice([p for p in pool if p in inputs] or [entry.const(B32, 0)]) if value == B32 else entry.const(B32, size)
                got, memory = entry.op(Operation.CHECKED_LOAD_BITS_LE, (base, index, memory), (element, mem), attributes=(size, 1))
                loaded.append(got)
            else:
                cast = entry.op1(Operation.POINTER_CAST, (base,), elem_ptr)
                got, memory = entry.op(Operation.LOAD_BITS_LE, (cast, memory), (element, mem), attributes=(size, size))
                loaded.append(got)
        if element == value:
            pool.extend(loaded)
        status, memory = entry.op(Operation.CALL_FOREIGN, (base, entry.const(B64, 0), entry.const(B32, 0x8000), token, memory), (B32, mem),
                                  entity=free)
        if value == B32:
            pool.append(status)
    if rng.random() < 0.3:
        name.append("address")
        takes = foreign_function_symbol(b"kernel32.dll", b"FlsAlloc", (function_pointer_type(),), (B32,), abi=b"win64-c")
        extras += [takes, function_pointer_type()]
        code = entry.op1(Operation.FUNCTION_ADDRESS, (), function_pointer_type(), entity=leaf)
        result = entry.op1(Operation.CALL_FOREIGN, (code,), B32, entity=takes)
        if value == B32:
            pool.append(result)
    if fault in ("com", "abi", "malformed"):
        name.append(fault)
        handle = rng.choice(pool) if value == B64 else entry.const(B64, rng.getrandbits(64))
        if fault == "com":
            method = win64_com_method(b"IUnknown", rng.randrange(3, 40), (B64, value), (value,))
        elif fault == "abi":
            method = foreign_function_symbol(b"libc.so.6", b"labs", (B64, value), (value,), abi=b"sysv-x86_64-c")
        else:
            method = foreign_function_symbol(COM_LIBRARY_PREFIX + b"IUnknown", b"vtable:7", (value, B64), (value,), abi=b"win64-c")
        extras.append(method)
        arguments = (handle, rng.choice(pool)) if fault != "malformed" else (rng.choice(pool), handle)
        pool.append(entry.op1(Operation.CALL_FOREIGN, arguments, value, entity=method))
    operations(entry, pool, rng.randint(0, 8), flags)
    shape = rng.choice(("return", "branch", "conditional", "loop"))
    name.append(shape)
    if shape == "return":
        entry.ret(rng.choice(pool), memory)
    elif shape == "loop":
        loop, done = graph.block(value, B32, mem), graph.block(value, mem)
        entry.br(loop, rng.choice(pool), entry.const(B32, rng.randint(1, 4)), memory)
        current, counter, loop_memory = loop.params
        more = loop.op1(Operation.INT_COMPARE, (counter, loop.const(B32, 0)), B1, attributes=(IntCompare.NE,))
        step = loop.op1(Operation.ADD_WRAP, (loop.op1(Operation.MUL_WRAP, (current, loop.const(value, 3)), value), rng.choice(pool)), value)
        loop.cbr(more, loop, (step, loop.op1(Operation.SUB_WRAP, (counter, loop.const(B32, 1)), B32), loop_memory), done, (current, loop_memory))
        done.ret(*done.params)
    else:
        k = rng.randint(1, 8)  # beyond six machine parameters: edge spill slots
        join = graph.block(*(value,) * k, mem)
        if shape == "branch":
            entry.br(join, *(rng.choice(pool) for _ in range(k)), memory)
        else:
            left, right = graph.block(mem), graph.block(mem)
            condition = rng.choice(flags) if flags and rng.random() < 0.8 else entry.const(B1, rng.randint(0, 1))
            entry.cbr(condition, left, (memory,), right, (memory,))
            for side in (left, right):
                reachable = pool[:]
                operations(side, reachable, rng.randint(0, 8), [])
                side.br(join, *(rng.choice(reachable) for _ in range(k)), side.params[0])
        *joined, join_memory = join.params
        joined = list(joined)
        operations(join, joined, rng.randint(1, 10), [])
        crossing = joined + [rng.choice(pool)]  # an entry value used in the join: a home slot
        join.ret(join.op1(Operation.ADD_WRAP, (rng.choice(crossing), rng.choice(crossing)), value), join_memory)
    function = graph.function((*(value,) * count, mem), (value, mem))
    # The process entry: f of constants, the status to ExitProcess.
    process = GraphBuilder()
    block = process.block(api.process_effect, mem)
    effect, memory = block.params
    result, memory = block.op(Operation.CALL_DIRECT, (*(block.const(value, rng.randint(0, 99)) for _ in range(count)), memory), (value, mem),
                              entity=function)
    status = block.op1(Operation.ADD_WRAP, (block.const(value, 0), result), value) if value == B32 else block.const(B32, 3)
    effect, = block.op(Operation.CALL_FOREIGN, (status, effect), (api.process_effect,), entity=api.exit_process)
    block.ret(status, effect, memory)
    process_entry = process.function((api.process_effect, mem), (B32, api.process_effect, mem))
    target = x86_64_windows_pe_target()
    objects = (*api.types, *api.symbols, *extras, *(item for g in graphs for item in g.objects.values()), *graph.objects.values(),
               *process.objects.values(), function)
    return program_store(process_entry, target, objects), process_entry, target, " ".join(name)
