"""S12b to S12d (ADR-269 to ADR-272): the general x86-64 backend's lowering view, value ranges, prefetch selection,
register-resident analyses, and register-resident code decided by an XAX program.

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
from xax_linux import check_analyses, check_bounds, check_emission, compile_linux_executable, linux_api, reference_view

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
        closure, views, prefetches, code, bounds, analyses = general_with_xax(reader, entry.cid, self.target, required=True, audit=True)
        check_bounds(views, bounds, closure, resolve)  # S12c.1: every value's range bound
        check_analyses(views, prefetches, analyses, closure, resolve, self.target)  # S12c.2: the register-resident analyses
        check_emission(views, prefetches, code, closure, resolve, self.target, entry.cid)  # S12d: the code, byte for byte
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
                closure, views, prefetches, code, bounds, analyses = general_with_xax(program.reader, program.entry.cid, program.target, required=True, audit=True)
                check_bounds(views, bounds, closure, resolve)
                check_analyses(views, prefetches, analyses, closure, resolve, program.target)
                check_emission(views, prefetches, code, closure, resolve, program.target, program.entry.cid)
                self.assertEqual({type(item) for item in code.values()}, {tuple})  # every function's code is XAX's
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
        closure, views, prefetches, code, bounds, analyses = __import__("xax_selfhost_x86_64_general").general_with_xax(
            program.reader, program.entry.cid, program.target, required=True, audit=True)
        resolve = store_resolver(program.reader)
        check_bounds(views, bounds, closure, resolve)
        check_analyses(views, prefetches, analyses, closure, resolve, program.target)
        check_emission(views, prefetches, code, closure, resolve, program.target, program.entry.cid)
        self.assertGreaterEqual(sum(isinstance(item, tuple) for item in code.values()), 7)  # all but the entry's helper
        for function in closure:
            reference, marks = reference_view(function, resolve, function.cid in prefetches)
            self.assertEqual(views[function.cid], reference)
            self.assertEqual(prefetches.get(function.cid, marks), marks)
        xax = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="xax")
        python = compile_linux_executable(program.reader, program.entry.cid, program.target.cid, frontend="python")
        self.assertEqual(xax.data, python.data)

    def test_executables_assembled_in_xax(self):
        """S12e: the XAX program places the code, binds every fixup and import, and writes the ELF container; static
        (status, chains, jsonmin) and dynamic (a C import) executables equal the bootstrap's, image and ranges included."""
        import xax_linux
        from benchmarks.jsonmin import build_jsonmin
        from benchmarks.linux_chains import build_chains_program
        from test_xax_linux import _crc_program, _status_program
        from xax_compiler import x86_64_linux_dynamic_exec_target

        programs = []
        reader, entry, target, _ = _status_program(lambda b: b.const(bits_type(32), 7))
        programs.append((reader, entry.cid, target))
        reader, entry, target = _crc_program(x86_64_linux_dynamic_exec_target())
        programs.append((reader, entry.cid, target))
        jsonmin = build_jsonmin()
        programs.append((jsonmin.reader, jsonmin.entry.cid, jsonmin.target))
        for links in ("index", "soa"):
            chains = build_chains_program(links=links)
            programs.append((chains.reader, chains.entry.cid, chains.target))
        for reader, entry_cid, target in programs:
            with self.subTest(target=target.cid.hex()[:8], entry=entry_cid.hex()[:8]):
                xax_linux.ASSEMBLY_COUNTS.clear()
                xax = compile_linux_executable(reader, entry_cid, target.cid, frontend="xax")
                self.assertEqual(xax_linux.ASSEMBLY_COUNTS, {"xax": 1})
                self.assertEqual(xax, compile_linux_executable(reader, entry_cid, target.cid, frontend="python"))

    def test_code_generation_rejections(self):
        """S12f.2 (ADR-278): the bootstrap's rejections during code generation (a startup read outside the process
        entry, a C import in the static profile, C scalars beyond the register subset, a foreign entry signature beyond
        the adapter) are the XAX program's, with the exact diagnostic."""
        from test_xax_c_interop import _address_program, _pure
        from test_xax_linux import _crc_program
        from xax_compiler import XaxError, x86_64_linux_dynamic_exec_target, x86_64_linux_exec_target
        from xax_linux import c_function, linux_startup_api
        from xax_selfhost_x86_64_general import general_with_xax

        api, startup = linux_api(), linux_startup_api()
        cases = {}
        helper_graph = GraphBuilder()
        block = helper_graph.block()
        block.ret(block.op1(Operation.CALL_FOREIGN, (), B64, entity=startup.argc))
        helper = helper_graph.function((), (B64,))
        graph = GraphBuilder()
        graph.track(*api.types)
        entry = graph.block(api.process_effect)
        status = entry.op1(Operation.INT_TRUNCATE, (entry.op1(Operation.CALL_DIRECT, (), B64, entity=helper),), B32)
        entry.ret(status, entry.op1(Operation.CALL_FOREIGN, (status, entry.params[0]), api.process_effect, entity=api.exit_group))
        function = graph.function((api.process_effect,), (B32, api.process_effect))
        target = x86_64_linux_exec_target()
        cases["LINUX-STARTUP-PROCESS-ENTRY"] = (program_store(function, target, (*graph.objects.values(), *helper_graph.objects.values(), helper,
                                                                                   *startup.symbols)), function, target)
        reader, entry_function, target = _crc_program(x86_64_linux_exec_target())
        cases["SYSV-C-REQUIRES-DYNAMIC-PROFILE"] = (reader, entry_function, target)
        seven = c_function(b"libc.so.6", b"seven", (B64,) * 7, (B64,))
        graph = GraphBuilder()
        block = graph.block(api.filesystem_effect)
        value = block.op1(Operation.CALL_FOREIGN, tuple(block.const(B64, index) for index in range(7)), B64, entity=seven)
        block.ret(block.op1(Operation.INT_TRUNCATE, (value,), B32), block.params[0])
        function = graph.function((api.filesystem_effect,), (B32, api.filesystem_effect))
        target = x86_64_linux_dynamic_exec_target()
        cases["SYSV-C-SCALAR-CLASS"] = (program_store(function, target, tuple(graph.objects.values())), function, target)
        callee_graph, callee = _pure((B64,) * 5)
        cases["SYSV-ENTRY-SIGNATURE"] = _address_program(callee_graph, callee, api.c_callback, extra=api.types)
        for rule, (reader, function, target) in cases.items():
            with self.subTest(rule):
                with self.assertRaises(XaxError) as xax:
                    general_with_xax(reader, function.cid, target, required=True)
                with self.assertRaises(XaxError) as reference:
                    compile_linux_executable(reader, function.cid, target.cid, frontend="python")
                self.assertEqual(reference.exception.diagnostic.rule, rule)
                self.assertEqual(xax.exception.diagnostic, reference.exception.diagnostic)

    def test_frame_lowering(self):
        """S12f: functions the register-resident path rejects (floats, products, sums) are lowered by the XAX frame
        path, byte for byte the bootstrap's ``_compile_function``; whole programs are assembled in XAX."""
        import xax_linux
        from xax_compiler import (
            Block, FloatCompare, FloatFormat, Node, Terminator, ValueRef, array_type, constant, float_constant, float_type, function,
            graph_fragment, sum_type, tuple_type,
        )

        f32, f64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
        P, R = ValueRef.parameter, ValueRef.node_result
        half = float_constant(f64, 1.5)
        floats = graph_fragment([Block((B32, B32), (
            Node(Operation.UINT_TO_FLOAT, (P(0, 0),), (f64,)),
            Node(Operation.SINT_TO_FLOAT, (P(0, 1),), (f64,)),
            Node(Operation.CONSTANT, (), (f64,), entity=half),
            Node(Operation.FLOAT_ADD, (R(0, 0), R(0, 2)), (f64,)),
            Node(Operation.FLOAT_MUL, (R(0, 3), R(0, 1)), (f64,)),
            Node(Operation.FLOAT_SUB, (R(0, 4), R(0, 0)), (f64,)),
            Node(Operation.FLOAT_DIV, (R(0, 5), R(0, 2)), (f64,)),
            Node(Operation.FLOAT_CONVERT, (R(0, 6),), (f32,)),
            Node(Operation.FLOAT_CONVERT, (R(0, 7),), (f64,)),
            Node(Operation.FLOAT_COMPARE, (R(0, 8), R(0, 6)), (B1,), attributes=(FloatCompare.LE,)),
            Node(Operation.FLOAT_TO_SINT_TRUNC, (R(0, 8),), (B32,)),
            Node(Operation.FLOAT_TO_UINT_TRUNC, (R(0, 2),), (B64,)),
            Node(Operation.INT_ZERO_EXTEND, (R(0, 9),), (B32,)),
            Node(Operation.ADD_WRAP, (R(0, 10), R(0, 12)), (B32,)),
        ), Terminator.return_((R(0, 13),)))])
        floating = function(floats, (B32, B32), (B32,))
        pair, array = tuple_type((B32, B64)), array_type(B32, 2)
        choice = sum_type((B32, B1))
        zero = constant(B1, 0)
        products = graph_fragment([
            Block((B32, B32), (
                Node(Operation.INT_ZERO_EXTEND, (P(0, 1),), (B64,)),
                Node(Operation.AGGREGATE_MAKE, (P(0, 0), R(0, 0)), (pair,)),
                Node(Operation.AGGREGATE_GET, (R(0, 1),), (B32,), attributes=(0,)),
                Node(Operation.AGGREGATE_MAKE, (R(0, 2), P(0, 1)), (array,)),
                Node(Operation.AGGREGATE_GET, (R(0, 3),), (B32,), attributes=(1,)),
                Node(Operation.SUM_MAKE, (R(0, 4),), (choice,), attributes=(0,)),
                Node(Operation.SUM_TAG, (R(0, 5),), (B1,)),
                Node(Operation.CONSTANT, (), (B1,), entity=zero),
                Node(Operation.INT_COMPARE, (R(0, 6), R(0, 7)), (B1,), attributes=(IntCompare.EQ,)),
            ), Terminator.conditional_branch(R(0, 8), 1, (R(0, 5),), 2, ())),
            Block((choice,), (Node(Operation.SUM_GET, (P(1, 0),), (B32,), attributes=(0,)),), Terminator.return_((R(1, 0),))),
            Block((), (), Terminator.trap()),
        ])
        aggregate = function(products, (B32, B32), (B32,))
        from xax_compiler import Permission, memory_effect_type, pointer_type, stack_owner_type

        rw, ro = pointer_type(f32, Permission.READ_WRITE, 4), pointer_type(f32, Permission.READ, 4)
        owner, effect = stack_owner_type(), memory_effect_type()
        storage = graph_fragment([Block((B32,), (
            Node(Operation.UINT_TO_FLOAT, (P(0, 0),), (f32,)),
            Node(Operation.STACK_ALLOC, (), (rw, owner, effect), attributes=(4, 4)),
            Node(Operation.STORE_BITS_LE, (R(0, 1, 0), R(0, 0), R(0, 1, 2)), (effect,), attributes=(4, 4)),
            Node(Operation.POINTER_CAST, (R(0, 1, 0),), (ro,)),
            Node(Operation.LOAD_BITS_LE, (R(0, 3), R(0, 2)), (f32, effect), attributes=(4, 4)),
            Node(Operation.STACK_END, (R(0, 1, 1), R(0, 4, 1)), ()),
            Node(Operation.FLOAT_TO_UINT_TRUNC, (R(0, 4, 0),), (B32,)),
        ), Terminator.return_((R(0, 6),)))])
        stored = function(storage, (B32,), (B32,))
        objects = (B1, B32, B64, f32, f64, half, floats, floating, pair, array, choice, zero, products, aggregate, rw, ro, owner, effect, storage, stored)
        for callee, arguments in ((floating, (7, 3)), (aggregate, (5, 9)), (stored, (11,))):
            with self.subTest(callee=callee.cid.hex()[:8]):
                reader, entry = self.store([(callee, tuple((B32, value) for value in arguments), (B32,))], *objects)
                xax_linux.EMISSION_COUNTS.clear()
                self.assertViews(reader, entry)
                self.assertGreaterEqual(xax_linux.EMISSION_COUNTS.get("frame", 0), 1)
                xax_linux.ASSEMBLY_COUNTS.clear()
                xax = compile_linux_executable(reader, entry.cid, self.target.cid, frontend="xax")
                self.assertEqual(xax_linux.ASSEMBLY_COUNTS, {"xax": 1})
                self.assertEqual(xax, compile_linux_executable(reader, entry.cid, self.target.cid, frontend="python"))

    def test_trap_reasons(self):
        """S12d: a trap terminator's reason (the head of its payload, carried in the object table's trap section) is
        loaded into rax before ``ud2``, in the callee and where it is inlined into its caller."""
        from xax_compiler import trap_payload

        for reason in (0, 1, 2, 300, 0xFFFF):
            def body(g, b, reason=reason):
                ok, bad = g.block(), g.block()
                b.cbr(b.op1(Operation.INT_COMPARE, (b.params[0], b.const(B64, 5)), B1, attributes=(IntCompare.ULT,)), ok, (), bad, ())
                ok.ret(ok.const(B64, 1))
                bad.trap(trap_payload(reason) if reason else b"")

            callee, objects = _function((B64,), (B64,), body)
            reader, entry = self.store([(callee, ((B64, 3),), (B64,))], *objects)
            with self.subTest(reason=reason):
                self.assertViews(reader, entry)
                image = compile_linux_executable(reader, entry.cid, self.target.cid, frontend="xax")
                self.assertIn(b"\x48\xb8" + reason.to_bytes(8, "little") + b"\x0f\x0b", image.data)

    def test_register_resident_analyses(self):
        """S12c.2: the register-allocator differential corpus (straight-line DAGs, counted loops, calls with pinned
        values live across them) gets every analysis from the XAX program, and the driver that calls all 160 of them
        from one block stays within the arena (per-root scratch is released)."""
        import xax_linux
        from test_xax_regalloc_differential import RegisterAllocatorDifferentialTests

        functions, objects = RegisterAllocatorDifferentialTests()._corpus()
        xax_linux.ANALYSIS_COUNTS.clear()
        xax_linux.EMISSION_COUNTS.clear()
        calls = [(function, tuple((B64, item) for item in arguments), (B64,)) for function, arguments in functions]
        reader, entry = self.store(calls, *objects)
        self.assertViews(reader, entry)
        for kind in ("widths", "uses", "homes", "pinned", "loop_headers"):
            self.assertGreater(xax_linux.ANALYSIS_COUNTS.get(kind, 0), 0, kind)
        # S12d: the corpus's code is emitted by the XAX program, byte for byte the bootstrap's (checked above).
        self.assertGreaterEqual(xax_linux.EMISSION_COUNTS.get("emitted", 0), 160)


if __name__ == "__main__":
    unittest.main()
