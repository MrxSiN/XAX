"""Differential validation of the Linux register-resident lowering (U1.2b, ADR-089).

Seeded random integer programs (straight-line DAGs plus a counted loop with
block parameters, and a second corpus whose loops call earlier programs while
pinned values are live, ADR-091) are executed by the reference executor and natively after
lowering through ``xax_x86_64_regalloc``.  Every 64-bit result must match.
This is translation validation by execution over a fixed corpus, not a proof.
"""

from __future__ import annotations

import platform
import random
import struct
import sys
import unittest

from xax_compiler import (
    IntCompare,
    Operation,
    Permission,
    bits_type,
    execute,
    heap_view_type,
    pointer_type,
    store_resolver,
    _decode_function_interface,
    _parse_graph,
    decode_native_target,
    x86_64_linux_exec_target,
)
from xax_graph_builder import BlockBuilder, GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, run_linux_executable
from xax_x86_64_regalloc import compile_register_resident

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
MASK64 = (1 << 64) - 1
INTERESTING = (0, 1, 2, 3, 7, 8, 10, 255, 256, 1 << 31, (1 << 31) - 1, (1 << 32) - 1, 1 << 32, 1 << 40, 1 << 63, MASK64, 0x9E3779B97F4A7C15)
BINARY = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR, Operation.UDIV, Operation.UREM)
COMPARES = tuple(IntCompare)


def _random_constant(rng: random.Random) -> int:
    return rng.choice(INTERESTING) if rng.random() < 0.6 else rng.getrandbits(rng.choice((8, 31, 32, 33, 64)))


def _value(rng: random.Random, block: BlockBuilder, pool: list) -> object:
    return rng.choice(pool) if pool and rng.random() < 0.8 else block.const(B64, _random_constant(rng))


def _step(rng: random.Random, block: BlockBuilder, pool: list) -> object:
    choice = rng.random()
    if choice < 0.65:
        operation = rng.choice(BINARY)
        left, right = _value(rng, block, pool), _value(rng, block, pool)
        if operation in (Operation.UDIV, Operation.UREM):
            # Keep divisors nonzero so traps are not part of this corpus.
            right = block.op1(Operation.BIT_OR, (right, block.const(B64, 1 << rng.randrange(0, 64))), B64)
        return block.op1(operation, (left, right), B64)
    if choice < 0.8:
        flag = block.op1(Operation.INT_COMPARE, (_value(rng, block, pool), _value(rng, block, pool)), B1, attributes=(rng.choice(COMPARES),))
        return block.op1(Operation.INT_ZERO_EXTEND, (flag,), B64)
    narrow = block.op1(Operation.INT_TRUNCATE, (_value(rng, block, pool),), rng.choice((B32, bits_type(8), bits_type(16))))
    return block.op1(Operation.INT_ZERO_EXTEND, (narrow,), B64)


def _random_function(rng: random.Random, callees: tuple = ()):
    graph = GraphBuilder()
    entry = graph.block(B64, B64, B64, B64)
    pool = list(entry.params)
    for _ in range(rng.randrange(4, 24)):
        pool.append(_step(rng, entry, pool))
    loop = graph.block(B32, B64, B64)
    exit_block = graph.block(B64, B64)
    entry.br(loop, entry.const(B32, 0), pool[-1], pool[-2])
    counter, a, b = loop.params
    local = [a, b, *rng.sample(pool, min(3, len(pool)))]
    for _ in range(rng.randrange(2, 12)):
        local.append(_step(rng, loop, local))
    if callees:
        # Values from the entry block stay pinned across this call.
        arguments = tuple(_value(rng, loop, [*local, *pool]) for _ in range(4))
        local.append(loop.op1(Operation.CALL_DIRECT, arguments, B64, entity=rng.choice(callees)))
        local.append(loop.op1(rng.choice(BINARY[:6]), (local[-1], rng.choice(pool)), B64))
    following = loop.op1(Operation.ADD_WRAP, (counter, loop.const(B32, 1)), B32)
    condition = loop.op1(Operation.INT_COMPARE, (following, loop.const(B32, rng.randrange(1, 6))), B1, attributes=(IntCompare.ULT,))
    loop.cbr(condition, loop, (following, local[-1], local[-2]), exit_block, (local[-1], local[-3]))
    x, y = exit_block.params
    exit_block.ret(exit_block.op1(rng.choice(BINARY[:6]), (x, y), B64))
    return graph.function((B64,) * 4, (B64,)), graph


class RegisterAllocatorDifferentialTests(unittest.TestCase):
    SEED = 20261002
    PROGRAMS = 120
    CALLING_SEED = 20261003
    CALLING_PROGRAMS = 40

    def _corpus(self):
        rng = random.Random(self.SEED)
        functions, objects = [], []
        for _ in range(self.PROGRAMS):
            function, graph = _random_function(rng)
            functions.append((function, tuple(_random_constant(rng) for _ in range(4))))
            objects.extend(graph.objects.values())
        rng = random.Random(self.CALLING_SEED)
        leaves = tuple(function for function, _arguments in functions[:8])
        for _ in range(self.CALLING_PROGRAMS):
            function, graph = _random_function(rng, leaves)
            functions.append((function, tuple(_random_constant(rng) for _ in range(4))))
            objects.extend(graph.objects.values())
        return functions, objects

    def test_corpus_uses_register_resident_lowering(self):
        functions, objects = self._corpus()
        target = x86_64_linux_exec_target()
        for function, _arguments in (*functions[:20], *functions[-20:]):
            reader = program_store(function, target, objects)
            resolve = store_resolver(reader)
            graph_object, parameters, returns = _decode_function_interface(function, resolve)
            graph = _parse_graph(graph_object, resolve)
            self.assertIsNotNone(compile_register_resident(function, graph_object, graph, parameters, returns, resolve, decode_native_target(target)))

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_native_results_match_reference_executor(self):
        functions, objects = self._corpus()
        api = linux_api()
        words = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
        extent = 8 * len(functions)
        driver = GraphBuilder()
        block = driver.block(api.process_effect, api.filesystem_effect, api.memory_effect)
        process, fs, memory = block.params
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
        results, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (words, heap_view_type(4096), api.memory_effect), attributes=(4096, 8))
        for index, (function, arguments) in enumerate(functions):
            value = block.op1(Operation.CALL_DIRECT, tuple(block.const(B64, item) for item in arguments), B64, entity=function)
            slot = results if index == 0 else block.op1(Operation.ADDRESS_OFFSET, (results,), words, attributes=(8 * index,))
            memory = block.op1(Operation.STORE_BITS_LE, (slot, value, memory), api.memory_effect, attributes=(8, 8))
        readable = block.op1(Operation.POINTER_CAST, (raw,), api.bytes_read)
        _written, fs, memory = block.op(Operation.CALL_FOREIGN, (block.const(B32, 1), readable, block.const(B64, extent), fs, memory), (B64, api.filesystem_effect, api.memory_effect), entity=api.write)
        _unmapped, memory = block.op(Operation.CALL_FOREIGN, (results, view, memory), (B64, api.memory_effect), entity=api.munmap_view(words, 4096))
        zero = block.const(B32, 0)
        process = block.op1(Operation.CALL_FOREIGN, (zero, process), api.process_effect, entity=api.exit_group)
        block.ret(zero, process, fs, memory)
        entry = driver.function((api.process_effect, api.filesystem_effect, api.memory_effect), (B32, api.process_effect, api.filesystem_effect, api.memory_effect))
        target = x86_64_linux_exec_target()
        reader = program_store(entry, target, (*objects, *api.types, words, *driver.objects.values()))
        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        native = struct.unpack(f"<{len(functions)}Q", completed.stdout)
        for index, (function, arguments) in enumerate(functions):
            with self.subTest(program=index):
                self.assertEqual(native[index], execute(reader, function.cid, arguments)[0])


if __name__ == "__main__":
    unittest.main()
