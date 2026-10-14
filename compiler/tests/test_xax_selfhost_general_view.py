"""S12b, S12c.1, and S12c.2 (ADR-269 to ADR-271): the general x86-64 backend's lowering view, value ranges, prefetch
selection, and register-resident analyses decided by an XAX program.

``general_with_xax(required=True)`` fails rather than fall back; the views it returns are rebuilt from the program's
words (origins and operands), so equality with ``xax_inline.inline_leaf_calls`` -- every block, node, operand,
terminator, entry, and pointer extent -- proves the XAX program made every inlining, simplification, and layout
decision.  Where the program selected the prefetch, the view and marks equal ``prefetch_next_iteration``'s; with
``audit=True`` the program also writes every value's range bound, which must equal ``xax_ranges.upper_bounds``, and every function's register-resident analyses (eligibility, widths, folding,
uses, pressure, pins, frame, loop slots), which must equal ``xax_x86_64_regalloc``'s (``check_analyses``).
The suites that build Linux programs check all of it with ``XAX_GENERAL_FRONTEND_DIFF=1``.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Operation,
    bits_type,
    parse_function_graph,
    store_resolver,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_inline import inline_leaf_calls
from xax_linux import check_analyses, check_bounds, compile_linux_executable, linux_api, reference_view

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32, B64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)


def _process(calls):
    """A process entry that makes ``calls`` (``(callee, operand constants, result types)``) and exits with status 0."""
    api = linux_api()
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    for callee, constants, results in calls:
        block.op(Operation.CALL_DIRECT, tuple(block.const(type_, value) for type_, value in constants), results, entity=callee)
    status = block.const(B32, 0)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    parameters = (api.process_effect, api.filesystem_effect)
    return graph.function(parameters, (B32, *parameters)), (*graph.objects.values(), *api.types)


def _function(parameters, returns, body):
    graph = GraphBuilder()
    body(graph, graph.block(*parameters))
    return graph.function(parameters, returns), tuple(graph.objects.values())


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: native XAX helper images run on Linux x86-64 only")
class GeneralViewTests(unittest.TestCase):
    target = x86_64_linux_exec_target()

    def assertViews(self, reader, entry):
        from xax_selfhost_x86_64_general import general_with_xax

        resolve = store_resolver(reader)
        closure, views, prefetches, bounds, analyses = general_with_xax(reader, entry.cid, self.target, required=True, audit=True)
        check_bounds(views, bounds, closure, resolve)  # S12c.1: every value's range bound
        check_analyses(views, prefetches, analyses, closure, resolve, self.target)  # S12c.2: the register-resident analyses
        changed = 0
        for function in closure:
            graph = parse_function_graph(function, resolve)
            decided = function.cid in prefetches
            reference, marks = reference_view(function, resolve, decided)
            self.assertEqual(views[function.cid], reference, function.cid.hex())
            if decided:
                self.assertEqual(prefetches[function.cid], marks)
            changed += reference.blocks != graph.blocks
        return changed

    def store(self, calls, *objects):
        entry, items = _process(calls)
        return program_store(entry, self.target, (*items, *objects)), entry

    def test_inline_branching_leaf_into_a_loop(self):
        """A leaf with two returns inlined into a loop body: splice, continuation, merges, threading, layout."""
        def leaf(g, b):
            low, high = g.block(), g.block()
            b.cbr(b.op1(Operation.INT_COMPARE, (b.params[0], b.const(B64, 10)), B1, attributes=(IntCompare.ULT,)), low, (), high, ())
            low.ret(low.op1(Operation.ADD_WRAP, (b.params[0], low.const(B64, 1)), B64))
            high.ret(high.op1(Operation.SUB_WRAP, (b.params[0], high.const(B64, 3)), B64))

        callee, a = _function((B64,), (B64,), leaf)

        def looping(g, b):
            loop, done = g.block(B64, B64), g.block(B64)
            b.br(loop, b.params[0], b.const(B64, 0))
            value, count = loop.params
            stepped = loop.op1(Operation.CALL_DIRECT, (value,), B64, entity=callee)
            following = loop.op1(Operation.ADD_WRAP, (count, loop.const(B64, 1)), B64)
            loop.cbr(loop.op1(Operation.INT_COMPARE, (following, loop.const(B64, 5)), B1, attributes=(IntCompare.ULT,)), loop, (stepped, following), done, (stepped,))
            done.ret(done.params[0])

        caller, c = _function((B64,), (B64,), looping)
        reader, entry = self.store([(caller, ((B64, 3),), (B64,))], *a, *c)
        self.assertGreaterEqual(self.assertViews(reader, entry), 1)

    def test_packed_halves_fold(self):
        """``trunc32(zext(lo) | ror(zext(hi), 32))`` (and the same rotated by 32) read back the halves."""
        def pack(g, b):
            low = b.op1(Operation.INT_ZERO_EXTEND, (b.params[0],), B64)
            high = b.op1(Operation.ROTATE_RIGHT, (b.op1(Operation.INT_ZERO_EXTEND, (b.params[1],), B64),), B64, attributes=(32,))
            b.ret(b.op1(Operation.BIT_OR, (low, high), B64))

        packer, a = _function((B32, B32), (B64,), pack)

        def use(g, b):
            packed = b.op1(Operation.CALL_DIRECT, (b.params[0], b.params[1]), B64, entity=packer)
            low = b.op1(Operation.INT_TRUNCATE, (packed,), B32)
            high = b.op1(Operation.INT_TRUNCATE, (b.op1(Operation.ROTATE_RIGHT, (packed,), B64, attributes=(32,)),), B32)
            b.ret(b.op1(Operation.ADD_WRAP, (low, high), B32))

        caller, c = _function((B32, B32), (B32,), use)
        reader, entry = self.store([(caller, ((B32, 5), (B32, 9)), (B32,))], *a, *c)
        self.assertGreaterEqual(self.assertViews(reader, entry), 1)

    def test_forwarding_blocks_and_dead_code(self):
        def body(g, b):
            hop1, hop2, join = g.block(B64), g.block(B64), g.block(B64)
            b.op1(Operation.MUL_WRAP, (b.params[0], b.const(B64, 7)), B64)  # dead
            b.cbr(b.op1(Operation.INT_COMPARE, (b.params[0], b.const(B64, 0)), B1, attributes=(IntCompare.EQ,)), hop1, (b.params[0],), join, (b.params[0],))
            hop1.br(hop2, hop1.params[0])
            hop2.br(join, hop2.params[0])
            join.ret(join.op1(Operation.ADD_WRAP, (join.params[0], join.const(B64, 1)), B64))

        callee, a = _function((B64,), (B64,), body)
        # Called twice with a call in between, so it is not a leaf candidate's caller only: it is itself not inlined.
        api_free, c = _function((B64,), (B64,), lambda g, b: b.ret(b.op1(Operation.CALL_DIRECT, (b.op1(
            Operation.CALL_DIRECT, (b.params[0],), B64, entity=callee),), B64, entity=callee)))
        reader, entry = self.store([(api_free, ((B64, 4),), (B64,))], *a, *c)
        self.assertGreaterEqual(self.assertViews(reader, entry), 1)

    def test_random_programs(self):
        """Random loop programs over random widths, each calling the previous ones (leaf candidates and not)."""
        from test_xax_jvm import _random_function

        rng = random.Random(269)
        checked = changed = 0
        for trial in range(40):
            width = rng.choice((8, 16, 32, 47, 64))
            callees, objects = [], []
            for _ in range(rng.randrange(1, 5)):
                function, graph = _random_function(rng, width, tuple(callees))
                callees.append(function)
                objects.extend(graph.objects.values())
            bw = bits_type(width)
            reader, entry = self.store([(callees[-1], ((bw, 1), (bw, 2), (bw, 3)), (bw,))], *objects)
            with self.subTest(trial=trial):
                changed += self.assertViews(reader, entry)
                checked += 1
        self.assertEqual(checked, 40)
        self.assertGreater(changed, 20)

    def test_chains_prefetch(self):
        """S12c.1: the chains benchmark's lookup gets the next iteration's head load and its prefetches from the XAX
        program (soa: two arrays, scales 4 and 8); the other layouts get none.  Executables are byte-identical."""
        from benchmarks.linux_chains import build_chains_program
        from xax_selfhost_x86_64_general import general_with_xax

        for links in ("index", "pointer", "link", "soa"):
            with self.subTest(links=links):
                program = build_chains_program(links=links)
                resolve = store_resolver(program.reader)
                closure, views, prefetches, bounds, analyses = general_with_xax(program.reader, program.entry.cid, program.target, required=True, audit=True)
                check_bounds(views, bounds, closure, resolve)
                check_analyses(views, prefetches, analyses, closure, resolve, program.target)
                marks = {}
                for function in closure:
                    self.assertIn(function.cid, prefetches)
                    reference, expected = reference_view(function, resolve, True)
                    self.assertEqual(views[function.cid], reference)
                    self.assertEqual(prefetches[function.cid], expected)
                    marks.update(expected)
                self.assertEqual(len(marks), 1 if links == "soa" else 0)
                if links == "soa":
                    self.assertEqual(sorted(scale for _pointer, scale in next(iter(marks.values()))), [4, 8])
                xax = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="xax")
                python = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="python")
                self.assertEqual(xax.data, python.data)

    def test_jsonmin(self):
        from benchmarks.jsonmin import build_jsonmin

        program = build_jsonmin()
        closure, views, prefetches, bounds, analyses = __import__("xax_selfhost_x86_64_general").general_with_xax(
            program.reader, program.entry.cid, program.target, required=True, audit=True)
        resolve = store_resolver(program.reader)
        check_bounds(views, bounds, closure, resolve)
        check_analyses(views, prefetches, analyses, closure, resolve, program.target)
        for function in closure:
            reference, marks = reference_view(function, resolve, function.cid in prefetches)
            self.assertEqual(views[function.cid], reference)
            self.assertEqual(prefetches.get(function.cid, marks), marks)
        xax = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="xax")
        python = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="python")
        self.assertEqual(xax.data, python.data)

    def test_register_resident_analyses(self):
        """S12c.2: the register-allocator differential corpus (straight-line DAGs, counted loops, calls with pinned
        values live across them) gets every analysis from the XAX program, and the driver that calls all 160 of them
        from one block stays within the arena (per-root scratch is released)."""
        import xax_linux
        from test_xax_regalloc_differential import RegisterAllocatorDifferentialTests

        functions, objects = RegisterAllocatorDifferentialTests()._corpus()
        xax_linux.ANALYSIS_COUNTS.clear()
        calls = [(function, tuple((B64, item) for item in arguments), (B64,)) for function, arguments in functions]
        reader, entry = self.store(calls, *objects)
        self.assertViews(reader, entry)
        for kind in ("widths", "uses", "homes", "pinned", "loop_headers"):
            self.assertGreater(xax_linux.ANALYSIS_COUNTS.get(kind, 0), 0, kind)


if __name__ == "__main__":
    unittest.main()
