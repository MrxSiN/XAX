"""S4d.2 (ADR-137): the XAX facts engine agrees with the bootstrap memory-fact passes.

Random stack-memory programs (allocations, field offsets, stores, loads,
casts, ends; straight-line and looping, with pointers, owners, and frontiers
carried through block parameters) and their mutations (use after end,
double end, leaks, a forked frontier, out-of-bounds and misaligned accesses,
uninitialized loads, permission and type errors) must verify or reject with
the same exact diagnostic, and with the same pointer extents, whether the
engine runs or not.  The engine must accept a substantial share of the
valid programs.
"""

from __future__ import annotations

import contextlib
import platform
import random
import sys
import unittest

from xax_compiler import (
    IntCompare, Operation, Permission, XaxError, bits_type, memory_effect_type, pointer_type, resource_type, x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32, B64 = (bits_type(width) for width in (1, 8, 32, 64))
MEM = memory_effect_type()
OWNER = resource_type(1, 1)
ELEMENTS = {B8: 1, B32: 4, B64: 8}


@contextlib.contextmanager
def _engine(native):
    import xax_compiler

    saved = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED)
    xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = native, True
    xax_compiler._PARSED_GRAPHS.clear()
    try:
        yield
    finally:
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = saved
        xax_compiler._PARSED_GRAPHS.clear()


def _program(rng: random.Random, mutation: str | None):
    """A random stack-memory function ``(bits<32>) -> bits<32>`` and the objects it needs."""
    element = rng.choice(tuple(ELEMENTS))
    size = ELEMENTS[element]
    count = rng.randrange(1, 5)
    extent = size * count
    alignment = size if mutation != "under_aligned_alloc" else max(1, size // 2)
    permission = Permission.READ_WRITE
    pointer = pointer_type(element, permission, size)
    graph = GraphBuilder()
    graph.track(pointer, OWNER, MEM, element, B32, B1)
    entry = graph.block(B32)
    (seed,) = entry.params
    p, owner, memory = entry.op(Operation.STACK_ALLOC, (), (pointer, OWNER, MEM), attributes=(extent, alignment))
    value = entry.const(element, 7)
    slots = list(range(count))
    rng.shuffle(slots)
    written = slots[: rng.randrange(1, count + 1)]
    for slot in written:
        at = p if slot == 0 else entry.op1(Operation.ADDRESS_OFFSET, (p,), pointer, attributes=(slot * size,))
        if mutation == "forked_frontier" and slot == written[-1]:
            entry.op1(Operation.STORE_BITS_LE, (at, value, memory), MEM, attributes=(size, size))
        memory = entry.op1(Operation.STORE_BITS_LE, (at, value, memory), MEM, attributes=(size, size))
    read_slot = written[0] if mutation != "uninitialized" else next((slot for slot in range(count) if slot not in written), count)
    if mutation == "out_of_bounds":
        read_slot = count
    looping = rng.random() < 0.5
    if looping:
        # A loop carries the pointer, owner, frontier, and a counter; the body rewrites one slot.
        header = graph.block(pointer, OWNER, MEM, B32)
        body = graph.block(pointer, OWNER, MEM, B32)
        exit_ = graph.block(pointer, OWNER, MEM, B32)
        entry.br(header, p, owner, memory, entry.const(B32, 0))
        hp, ho, hm, hi = header.params
        header.cbr(header.op1(Operation.INT_COMPARE, (hi, header.const(B32, 3)), B1, attributes=(IntCompare.ULT,)), body, (hp, ho, hm, hi), exit_, (hp, ho, hm, hi))
        bp, bo, bm, bi = body.params
        target = written[-1]
        at = bp if target == 0 else body.op1(Operation.ADDRESS_OFFSET, (bp,), pointer, attributes=(target * size,))
        bm = body.op1(Operation.STORE_BITS_LE, (at, body.const(element, 9), bm), MEM, attributes=(size, size))
        if mutation == "end_in_loop":
            body.op(Operation.STACK_END, (bo, bm), ())
        body.br(header, bp, bo, bm, body.op1(Operation.ADD_WRAP, (bi, body.const(B32, 1)), B32))
        block, p, owner, memory = exit_, *exit_.params[:3]
    else:
        block = entry
    at = p if read_slot == 0 else block.op1(Operation.ADDRESS_OFFSET, (p,), pointer, attributes=(read_slot * size,))
    access = size if mutation != "wrong_size" else size * 2
    align = size if mutation != "misaligned" else size * 2
    if mutation == "cast_read_only":
        at = block.op1(Operation.POINTER_CAST, (at,), pointer_type(element, Permission.READ, size))
    loaded, memory = block.op(Operation.LOAD_BITS_LE, (at, memory), (element, MEM), attributes=(access, align))
    if mutation == "cast_read_only":
        block.op1(Operation.STORE_BITS_LE, (at, value, memory), MEM, attributes=(size, size))
    if mutation == "use_after_end":
        block.op(Operation.STACK_END, (owner, memory), ())
        block.op(Operation.LOAD_BITS_LE, (at, memory), (element, MEM), attributes=(size, size))
    elif mutation == "double_end":
        block.op(Operation.STACK_END, (owner, memory), ())
        block.op(Operation.STACK_END, (owner, memory), ())
    elif mutation != "leak":
        block.op(Operation.STACK_END, (owner, memory), ())
    result = loaded if element == B32 else (block.op1(Operation.INT_ZERO_EXTEND, (loaded,), B32) if element == B8 else block.op1(Operation.INT_TRUNCATE, (loaded,), B32))
    block.ret(block.op1(Operation.ADD_WRAP, (result, seed), B32))
    function = graph.function((B32,), (B32,))
    return function, tuple(graph.objects.values())


MUTATIONS = (None, None, None, None, "use_after_end", "double_end", "leak", "forked_frontier", "out_of_bounds", "misaligned",
             "uninitialized", "wrong_size", "cast_read_only", "end_in_loop", "under_aligned_alloc")


def _outcome(native, function, objects):
    from xax_compiler import _decode_function_interface, _parse_graph, store_resolver

    with _engine(native):
        try:
            reader = program_store(function, x86_64_linux_exec_target(), objects)
        except XaxError as error:
            d = error.diagnostic
            return ("reject", d.code, d.rule, d.entity, repr(d.expected), repr(d.actual))
        resolve = store_resolver(reader)
        parsed = _parse_graph(_decode_function_interface(function, resolve)[0], resolve)
        return ("accept", parsed.pointer_extents, parsed.returns)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostFactsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_typing import NativeTyping

        cls.native = NativeTyping()

    def test_stack_programs_agree_with_the_bootstrap(self):
        import xax_selfhost_typing as typing_module

        accepted = []
        original = typing_module.NativeTyping.facts

        def counting(self_, values):
            result = original(self_, values)
            accepted.append(result[0])
            return result

        # S8c.8 (ADR-221): rejections the engine decided itself (the bootstrap check was not run).
        decided = []
        original_rejection = typing_module.NativeTyping.memory_rejection

        def deciding(self_, *arguments):
            result = original_rejection(self_, *arguments)
            decided.append(result is not None)
            return result

        rng = random.Random(137)
        outcomes = {"accept": 0, "reject": 0}
        typing_module.NativeTyping.facts = counting
        typing_module.NativeTyping.memory_rejection = deciding
        xax_decided = 0
        try:
            for _ in range(300):
                mutation = rng.choice(MUTATIONS)
                function, objects = _program(rng, mutation)
                baseline = _outcome(None, function, objects)
                decided.clear()
                with_engine = _outcome(self.native, function, objects)
                self.assertEqual(with_engine, baseline, mutation)  # full diagnostic: code, rule, entity, expected, actual
                outcomes[baseline[0]] += 1
                xax_decided += baseline[0] == "reject" and any(decided)
        finally:
            typing_module.NativeTyping.facts = original
            typing_module.NativeTyping.memory_rejection = original_rejection
        self.assertGreater(xax_decided, outcomes["reject"] * 9 // 10)
        self.assertGreater(outcomes["accept"], 60)
        self.assertGreater(outcomes["reject"], 60)
        # The engine itself accepted many graphs (not only fallbacks to the bootstrap).
        self.assertGreater(sum(accepted), 60)


if __name__ == "__main__":
    unittest.main()


# -- S4d.2c: borrowed heap views, checked accesses, rebase windows, view-passing calls --------------------

from xax_compiler import heap_view_type  # noqa: E402

EXTENT = 64
VIEW_POINTER = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
READ_POINTER = pointer_type(B8, Permission.READ, 1, space=2)


def _view_callee(initialized: bool):
    """``(bits<32>, ptr, view, mem) -> (bits<32>, ptr, view, mem)``: reads byte 3 of the view (when initialized)."""
    view = heap_view_type(EXTENT, initialized=initialized)
    graph = GraphBuilder()
    block = graph.block(B32, VIEW_POINTER, view, MEM)
    seed, pointer, token, memory = block.params
    if initialized:
        value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, block.const(B32, 3), memory), (B8, MEM), attributes=(1, 1))
        seed = block.op1(Operation.ADD_WRAP, (seed, block.op1(Operation.INT_ZERO_EXTEND, (value,), B32)), B32)
    block.ret(seed, pointer, token, memory)
    return graph.function((B32, VIEW_POINTER, view, MEM), (B32, VIEW_POINTER, view, MEM)), tuple(graph.objects.values())


VIEW_MUTATIONS = (None, None, None, "fork", "uninitialized_read", "rebase_too_wide", "read_only_store", "stale_effect", "return_offset", "window_uninitialized")


def _view_program(rng: random.Random, mutation: str | None):
    initialized = mutation != "uninitialized_read" and (rng.random() < 0.7 or mutation is None and rng.random() < 0.5)
    if mutation == "window_uninitialized":
        initialized = False
    view = heap_view_type(EXTENT, initialized=initialized)
    callee, callee_objects = _view_callee(initialized)
    graph = GraphBuilder()
    graph.track(view, VIEW_POINTER, READ_POINTER, B64)
    entry = graph.block(B32, VIEW_POINTER, view, MEM)
    seed, pointer, token, memory = entry.params
    offset = entry.const(B32, rng.randrange(0, EXTENT))
    stored = memory
    memory = entry.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, offset, entry.const(B8, 5), memory), MEM, attributes=(1, 1))
    if mutation == "fork":
        entry.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, offset, entry.const(B8, 6), stored), MEM, attributes=(1, 1))
    if initialized or mutation == "uninitialized_read":
        value, memory = entry.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, offset, memory), (B8, MEM), attributes=(1, 1))
        seed = entry.op1(Operation.ADD_WRAP, (seed, entry.op1(Operation.INT_ZERO_EXTEND, (value,), B32)), B32)
    if rng.random() < 0.6 or mutation in ("rebase_too_wide", "window_uninitialized"):
        width = rng.choice((1, 4, 16, EXTENT)) if mutation != "rebase_too_wide" else EXTENT + 1
        address = entry.op1(Operation.POINTER_ADDRESS, (pointer,), B64, attributes=(1,))
        window = entry.op1(Operation.POINTER_REBASE, (pointer, address), VIEW_POINTER, attributes=(width,))
        if initialized or mutation == "window_uninitialized":
            value, memory = entry.op(Operation.LOAD_BITS_LE, (window, memory), (B8, MEM), attributes=(1, 1))
        else:
            memory = entry.op1(Operation.STORE_BITS_LE, (window, entry.const(B8, 1), memory), MEM, attributes=(1, 1))
    if mutation == "read_only_store":
        readable = entry.op1(Operation.POINTER_CAST, (pointer,), READ_POINTER)
        memory = entry.op1(Operation.CHECKED_STORE_BITS_LE, (readable, offset, entry.const(B8, 2), memory), MEM, attributes=(1, 1))
    before_call = memory
    looping = rng.random() < 0.4
    if rng.random() < 0.7:
        seed, pointer, token, memory = entry.op(Operation.CALL_DIRECT, (seed, pointer, token, memory), (B32, VIEW_POINTER, view, MEM), entity=callee)
    if mutation == "stale_effect":
        memory = entry.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, offset, entry.const(B8, 3), before_call), MEM, attributes=(1, 1))
    if looping:
        header = graph.block(B32, VIEW_POINTER, view, MEM, B32)
        body = graph.block(B32, VIEW_POINTER, view, MEM, B32)
        done = graph.block(B32, VIEW_POINTER, view, MEM, B32)
        entry.br(header, seed, pointer, token, memory, entry.const(B32, 0))
        hs, hp, ht, hm, hi = header.params
        header.cbr(header.op1(Operation.INT_COMPARE, (hi, header.const(B32, 2)), B1, attributes=(IntCompare.ULT,)), body, (hs, hp, ht, hm, hi), done, (hs, hp, ht, hm, hi))
        bs, bp, bt, bm, bi = body.params
        bm = body.op1(Operation.CHECKED_STORE_BITS_LE, (bp, bi, body.const(B8, 4), bm), MEM, attributes=(1, 1))
        body.br(header, bs, bp, bt, bm, body.op1(Operation.ADD_WRAP, (bi, body.const(B32, 1)), B32))
        block = done
        seed, pointer, token, memory = done.params[:4]
    else:
        block = entry
    if mutation == "return_offset":
        pointer = block.op1(Operation.ADDRESS_OFFSET, (pointer,), VIEW_POINTER, attributes=(1,))
    block.ret(seed, pointer, token, memory)
    function = graph.function((B32, VIEW_POINTER, view, MEM), (B32, VIEW_POINTER, view, MEM))
    return function, (*graph.objects.values(), *callee_objects)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostHeapViewFactsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_typing import NativeTyping

        cls.native = NativeTyping()

    def test_view_programs_agree_with_the_bootstrap(self):
        import xax_selfhost_typing as typing_module

        engine = []
        original = typing_module.NativeTyping.facts

        def counting(self_, values):
            result = original(self_, values)
            engine.append(result[0])
            return result

        rng = random.Random(1372)
        outcomes = {"accept": 0, "reject": 0}
        typing_module.NativeTyping.facts = counting
        try:
            for _ in range(300):
                mutation = rng.choice(VIEW_MUTATIONS)
                function, objects = _view_program(rng, mutation)
                baseline = _outcome(None, function, objects)
                engine.clear()
                with_engine = _outcome(self.native, function, objects)
                self.assertEqual(with_engine, baseline, mutation)
                outcomes[baseline[0]] += 1
                if baseline[0] == "accept":
                    self.assertTrue(engine and engine[-1], f"the engine declined a valid program ({mutation})")
        finally:
            typing_module.NativeTyping.facts = original
        self.assertGreater(outcomes["accept"], 60)
        self.assertGreater(outcomes["reject"], 60)


# -- S8c.9 (ADR-226): the type and continuation checks of plain and checked accesses -----------------------------

def _typed_program(variant: str):
    """A one-block program whose single fault is ``variant`` (each a different bootstrap memory rule)."""
    graph = GraphBuilder()
    if variant.startswith("checked"):
        view = heap_view_type(EXTENT, initialized=True)
        graph.track(view, VIEW_POINTER, B64, B8, B32)
        entry = graph.block(B32, VIEW_POINTER, view, MEM)
        seed, pointer, token, memory = entry.params
        offset = entry.const(B64 if variant == "checked_offset" else B32, 1)
        alignment = 2 if variant == "checked_alignment" else 1
        if variant == "checked_store_type":
            memory = entry.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, offset, entry.const(B32, 5), memory), MEM, attributes=(1, 1))
        elif variant == "checked_effect_type":
            memory = entry.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, offset, entry.const(B8, 5), memory), B8, attributes=(1, 1))
        else:
            result = B32 if variant == "checked_load_type" else B8
            value, memory = entry.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, offset, memory), (result, MEM), attributes=(1, alignment))
        entry.ret(seed, pointer, token, memory)
        function = graph.function((B32, VIEW_POINTER, view, MEM), (B32, VIEW_POINTER, view, MEM))
        return function, tuple(graph.objects.values())
    pointer = pointer_type(B32, Permission.READ_WRITE, 4)
    graph.track(pointer, OWNER, MEM, B32, B8)
    entry = graph.block(B32)
    (seed,) = entry.params
    p, owner, memory = entry.op(Operation.STACK_ALLOC, (), (pointer, OWNER, MEM), attributes=(4, 4))
    stored = entry.const(B8 if variant == "store_type" else B32, 7)
    memory = entry.op1(Operation.STORE_BITS_LE, (p, stored, memory), B32 if variant == "store_effect_type" else MEM, attributes=(4, 4))
    loaded, memory = entry.op(Operation.LOAD_BITS_LE, (p, memory), (B8 if variant == "load_type" else B32, MEM), attributes=(4, 4))
    entry.op(Operation.STACK_END, (owner, memory), ())
    entry.ret(seed)
    return graph.function((B32,), (B32,)), tuple(graph.objects.values())


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostTypedAccessTests(unittest.TestCase):
    def test_access_type_rejections_are_decided_by_the_engine(self):
        import xax_selfhost_typing as typing_module

        native = typing_module.NativeTyping()
        decided = []
        original = typing_module.NativeTyping.memory_rejection

        def deciding(self_, *arguments):
            result = original(self_, *arguments)
            decided.append(result is not None)
            return result

        typing_module.NativeTyping.memory_rejection = deciding
        rules = {}
        try:
            for variant in ("load_type", "store_type", "store_effect_type", "checked_alignment", "checked_offset", "checked_load_type",
                            "checked_store_type", "checked_effect_type"):
                function, objects = _typed_program(variant)
                baseline = _outcome(None, function, objects)
                decided.clear()
                self.assertEqual(_outcome(native, function, objects), baseline, variant)
                self.assertEqual(baseline[0], "reject", variant)
                rules[variant] = (baseline[2], any(decided))
        finally:
            typing_module.NativeTyping.memory_rejection = original
        self.assertTrue(all(decided_ for _rule, decided_ in rules.values()), rules)
