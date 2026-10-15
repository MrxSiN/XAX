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

        from xax_compiler import XaxError

        rng = random.Random(269)
        checked = changed = rejected = 0
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
                try:
                    changed += self.assertViews(reader, entry)
                except XaxError as error:
                    # S12f.4 (ADR-280): code generation rejects (an operation of another width than 32 or 64 bits on
                    # the frame path), as the bootstrap's whole compile does.
                    with self.assertRaises(XaxError) as reference:
                        compile_linux_executable(reader, entry.cid, self.target.cid, frontend="python")
                    self.assertEqual(error.diagnostic, reference.exception.diagnostic)
                    rejected += 1
                checked += 1
        self.assertEqual(checked, 40)
        self.assertGreater(changed, 20)
        self.assertGreater(rejected, 0)

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

    def test_atomics_on_the_frame_path(self):
        """S12f.3 (ADR-279): atomic loads, stores, read-modify-writes, compare-exchanges, and fences of stack storage are
        lowered by the XAX frame path, byte for byte; an unsupported width (NATIVE-ATOMIC-CAPABILITY) and a heap view
        (NATIVE-ATOMIC-STACK-STORAGE) are the program's rejections."""
        import xax_linux
        from xax_compiler import (
            AtomicOrder, AtomicRmwKind, AtomicScope, CompareExchangeStrength, Permission, XaxError, heap_view_type, pointer_type,
            stack_owner_type, x86_64_linux_exec_target,
        )
        from xax_selfhost_x86_64_general import general_with_xax

        api, system = linux_api(), AtomicScope.SYSTEM
        owner_type, memory_type = stack_owner_type(), api.memory_effect

        def program(width, store_order, load_order, rmw_kind, fence_order):
            value = bits_type(width)
            size = width // 8
            pointer = pointer_type(value, Permission.READ_WRITE, max(1, size))
            graph = GraphBuilder()
            graph.track(pointer, owner_type, memory_type, value, B1)
            block = graph.block(value)
            (seed,) = block.params
            p, owner, memory = block.op(Operation.STACK_ALLOC, (), (pointer, owner_type, memory_type), attributes=(size, max(1, size)))
            memory = block.op1(Operation.ATOMIC_STORE, (p, seed, memory), memory_type, attributes=(store_order, system, size))
            loaded, memory = block.op(Operation.ATOMIC_LOAD, (p, memory), (value, memory_type), attributes=(load_order, system, size))
            _old, memory = block.op(Operation.ATOMIC_RMW, (p, loaded, memory), (value, memory_type), attributes=(rmw_kind, AtomicOrder.ACQ_REL, system, size))
            memory = block.op1(Operation.ATOMIC_FENCE, (memory,), memory_type, attributes=(fence_order, system))
            seen, _flag, memory = block.op(Operation.ATOMIC_CMPXCHG, (p, seed, loaded, memory), (value, B1, memory_type),
                                           attributes=(AtomicOrder.SEQ_CST, AtomicOrder.ACQUIRE, system, size, CompareExchangeStrength.STRONG))
            block.op(Operation.STACK_END, (owner, memory), ())
            block.ret(seen)
            callee = graph.function((value,), (value,))
            entry, items = _process([(callee, ((value, 41),), (value,))])
            target = x86_64_linux_exec_target()
            return program_store(entry, target, (*items, *graph.objects.values())), entry, target

        cases = []
        for width in (32, 64):
            for store_order in (AtomicOrder.RELAXED, AtomicOrder.RELEASE, AtomicOrder.SEQ_CST):
                cases.append((width, store_order, AtomicOrder.ACQUIRE, AtomicRmwKind.ADD_WRAP, AtomicOrder.SEQ_CST))
            for load_order in (AtomicOrder.RELAXED, AtomicOrder.SEQ_CST):
                cases.append((width, AtomicOrder.RELEASE, load_order, AtomicRmwKind.EXCHANGE, AtomicOrder.ACQUIRE))
            for fence_order in (AtomicOrder.RELEASE, AtomicOrder.ACQ_REL):
                cases.append((width, AtomicOrder.RELEASE, AtomicOrder.ACQUIRE, AtomicRmwKind.EXCHANGE, fence_order))
        for case in cases:
            with self.subTest(case=case):
                reader, entry, target = program(*case)
                xax_linux.ASSEMBLY_COUNTS.clear()
                xax = compile_linux_executable(reader, entry.cid, target.cid, frontend="xax")
                self.assertEqual(xax_linux.ASSEMBLY_COUNTS, {"xax": 1})
                self.assertEqual(xax, compile_linux_executable(reader, entry.cid, target.cid, frontend="python"))

        def rejection(reader, entry, target, rule):
            with self.assertRaises(XaxError) as xax:
                general_with_xax(reader, entry.cid, target, required=True)
            with self.assertRaises(XaxError) as reference:
                compile_linux_executable(reader, entry.cid, target.cid, frontend="python")
            self.assertEqual(reference.exception.diagnostic.rule, rule)
            self.assertEqual(xax.exception.diagnostic, reference.exception.diagnostic)

        with self.subTest("NATIVE-ATOMIC-CAPABILITY"):
            rejection(*program(16, AtomicOrder.RELEASE, AtomicOrder.ACQUIRE, AtomicRmwKind.ADD_WRAP, AtomicOrder.SEQ_CST), "NATIVE-ATOMIC-CAPABILITY")
        with self.subTest("NATIVE-ATOMIC-STACK-STORAGE"):
            words = pointer_type(B32, Permission.READ_WRITE, 4, space=api.bytes_rw.body[1])
            graph = GraphBuilder()
            graph.track(words)
            block = graph.block(api.process_effect, api.memory_effect)
            process, memory = block.params
            raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (api.bytes_rw, api.heap_owner, memory_type),
                                          entity=api.mmap_anonymous)
            pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (words, heap_view_type(4096), memory_type), attributes=(4096, 4))
            loaded, memory = block.op(Operation.ATOMIC_LOAD, (pointer, memory), (B32, memory_type), attributes=(AtomicOrder.ACQUIRE, system, 4))
            _result, memory = block.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, memory_type), entity=api.munmap_view(words, 4096))
            process = block.op1(Operation.CALL_FOREIGN, (loaded, process), api.process_effect, entity=api.exit_group)
            block.ret(loaded, process, memory)
            entry = graph.function((api.process_effect, memory_type), (B32, api.process_effect, memory_type))
            target = x86_64_linux_exec_target()
            rejection(program_store(entry, target, (*api.types, *graph.objects.values())), entry, target, "NATIVE-ATOMIC-STACK-STORAGE")

    def test_aggregates_by_reference(self):
        """S12f.3 (ADR-279): aggregates of other sizes than 1, 2, 4, and 8 bytes pass by reference (the caller's 16-byte
        aligned copy) and return through a hidden first argument, in registers and on the stack, through direct and
        indirect calls; the frame path's code is the bootstrap's."""
        import xax_linux
        from xax_compiler import OpaqueKind, call_contract, function_pointer_type, opaque_type, tuple_type, x86_64_linux_exec_target

        cases = []
        for name, fields, extra in (("pair16", (B64, B64), 0), ("pair12", (B32, B64), 0), ("triple24", (B64, B64, B64), 0),
                                    ("stacked", (B64, B64), 3), ("hidden-stacked", (B64, B64), 4)):
            aggregate = tuple_type(fields)
            graph = GraphBuilder()
            graph.track(aggregate, *fields)
            # (b64 x extra, aggregate) -> aggregate: the aggregate's fields swapped when they share a type.
            block = graph.block(*((B64,) * extra), aggregate)
            whole = block.params[-1]
            items = [block.op1(Operation.AGGREGATE_GET, (whole,), t, attributes=(k,)) for k, t in enumerate(fields)]
            if fields[0] == fields[1]:
                items[0], items[1] = items[1], items[0]
            block.ret(block.op1(Operation.AGGREGATE_MAKE, tuple(items), aggregate))
            callee = graph.function((*((B64,) * extra), aggregate), (aggregate,))
            for indirect in (False, True):
                user_graph = GraphBuilder()
                user_graph.track(aggregate, *fields)
                user = user_graph.block(fields[0])
                made = user.op1(Operation.AGGREGATE_MAKE, tuple(user.params[0] if t == fields[0] else user.const(t, 9) for t in fields), aggregate)
                arguments = (*(user.const(B64, k) for k in range(extra)), made)
                if indirect:
                    pointer = user.op1(Operation.FUNCTION_ADDRESS, (), function_pointer_type(), entity=callee)
                    contract = call_contract((*((B64,) * extra), aggregate), (aggregate,), may_return=True, may_trap=False)
                    user_graph.track(contract, function_pointer_type(), opaque_type(OpaqueKind.FUNCTION))
                    out = user.op1(Operation.CALL_INDIRECT, (pointer, *arguments), aggregate, entity=contract)
                else:
                    out = user.op1(Operation.CALL_DIRECT, arguments, aggregate, entity=callee)
                user.ret(user.op1(Operation.AGGREGATE_GET, (out,), fields[0], attributes=(0,)))
                caller = user_graph.function((fields[0],), (fields[0],))
                entry, process_items = _process([(caller, ((fields[0], 5),), (fields[0],))])
                target = x86_64_linux_exec_target()
                reader = program_store(entry, target, (*process_items, *graph.objects.values(), *user_graph.objects.values(), callee))
                cases.append((f"{name}{'-indirect' if indirect else ''}", reader, entry, target))
        for name, reader, entry, target in cases:
            with self.subTest(name):
                xax_linux.ASSEMBLY_COUNTS.clear()
                xax = compile_linux_executable(reader, entry.cid, target.cid, frontend="xax")
                self.assertEqual(xax_linux.ASSEMBLY_COUNTS, {"xax": 1})
                self.assertEqual(xax, compile_linux_executable(reader, entry.cid, target.cid, frontend="python"))

    def _same_outcome(self, reader, entry, target, xax_assembles=True):
        """``compile_linux_executable``'s outcome equals the bootstrap's, decided entirely by the XAX program."""
        import xax_linux
        from xax_compiler import XaxError
        from xax_selfhost_x86_64_general import general_with_xax

        try:
            reference = ("image", compile_linux_executable(reader, entry.cid, target.cid, frontend="python"))
        except XaxError as error:
            reference = ("rejected", error.diagnostic)
        if reference[0] == "rejected":
            with self.assertRaises(XaxError) as xax:
                general_with_xax(reader, entry.cid, target, required=True)
            self.assertEqual(xax.exception.diagnostic, reference[1])
            return reference
        xax_linux.ASSEMBLY_COUNTS.clear()
        self.assertEqual(compile_linux_executable(reader, entry.cid, target.cid, frontend="xax"), reference[1])
        if xax_assembles:
            self.assertEqual(xax_linux.ASSEMBLY_COUNTS, {"xax": 1})
        return reference

    def test_values_wider_than_64_bits(self):
        """S12f.4 (ADR-280): values wider than 64 bits are no constants for the ranges (the simplifier folds none): a
        dead one leaves the function on the register-resident path; a live one, or a wide block parameter, is the frame
        path's rejection (NATIVE-VALUE-MACHINE, NATIVE-BLOCK-PARAMETER-VALUE), the XAX program's."""
        from xax_compiler import x86_64_linux_exec_target

        B128 = bits_type(128)

        def program(build):
            graph = GraphBuilder()
            graph.track(B128)
            block = graph.block(B32, B32)
            build(graph, block)
            callee = graph.function((B32, B32), (B32,))
            entry, items = _process([(callee, ((B32, 1), (B32, 2)), (B32,))])
            target = x86_64_linux_exec_target()
            return program_store(entry, target, (*items, *graph.objects.values())), entry, target

        def dead(graph, block):
            block.op1(Operation.ADD_WRAP, (block.const(B128, 5), block.const(B128, 7)), B128)
            block.ret(block.op1(Operation.ADD_WRAP, (block.params[0], block.params[1]), B32))

        def live(graph, block):
            wide = block.op1(Operation.INT_ZERO_EXTEND, (block.params[0],), B128)
            block.ret(block.op1(Operation.INT_TRUNCATE, (block.op1(Operation.ADD_WRAP, (wide, wide), B128),), B32))

        def parameter(graph, block):
            join = graph.block(B128)
            block.br(join, block.op1(Operation.INT_ZERO_EXTEND, (block.params[0],), B128))
            join.ret(join.op1(Operation.INT_TRUNCATE, (join.params[0],), B32))

        for name, build, outcome in (("dead", dead, "image"), ("live", live, "NATIVE-VALUE-MACHINE"), ("parameter", parameter, "NATIVE-BLOCK-PARAMETER-VALUE")):
            with self.subTest(name):
                kind, value = self._same_outcome(*program(build))
                self.assertEqual(kind if kind == "image" else value.rule, outcome)

    def test_links_and_rebases_on_the_frame_path(self):
        """S12f.4 (ADR-280): a function the register-resident path cannot take (a float) with a link or a dynamic
        rebase is the frame path's rejection (NATIVE-LINK-REGISTER-PATH, NATIVE-REBASE-REGISTER-PATH)."""
        from test_xax_links import ARENA, LINK, NEXT, RECORD, RECORDS
        from xax_compiler import FloatFormat, Permission, float_type, heap_view_type, pointer_type, x86_64_linux_exec_target

        api = linux_api()
        memory_type, f64 = api.memory_effect, float_type(FloatFormat.BINARY64)
        words = pointer_type(B64, Permission.READ_WRITE, 8, space=2)

        def program(view_type, extent, alignment, middle):
            graph = GraphBuilder()
            graph.track(*api.types, LINK, RECORD, RECORDS, NEXT, words, f64, B1)
            block = graph.block(api.process_effect, api.filesystem_effect, memory_type)
            process, fs, memory = block.params
            raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, extent), memory), (api.bytes_rw, api.heap_owner, memory_type),
                                          entity=api.mmap_anonymous)
            view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (view_type, heap_view_type(extent), memory_type), attributes=(extent, alignment))
            memory = middle(block, view, memory)
            floating = block.op1(Operation.UINT_TO_FLOAT, (block.const(B64, 3),), f64)
            value = block.op1(Operation.FLOAT_TO_UINT_TRUNC, (floating,), B64)
            _result, memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, memory_type), entity=api.munmap_view(view_type, extent))
            status = block.op1(Operation.INT_TRUNCATE, (value,), B32)
            process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
            block.ret(status, process, fs, memory)
            function = graph.function((api.process_effect, api.filesystem_effect, memory_type), (B32, api.process_effect, api.filesystem_effect, memory_type))
            target = x86_64_linux_exec_target()
            return program_store(function, target, tuple(graph.objects.values())), function, target

        def link(block, arena, memory):
            field = block.op1(Operation.ADDRESS_OFFSET, (arena,), NEXT, attributes=(8,))
            return block.op1(Operation.STORE_BITS_LE, (field, block.op1(Operation.LINK_MAKE, (arena,), LINK), memory), memory_type, attributes=(8, 8))

        def rebase(block, view, memory):
            address = block.op1(Operation.POINTER_ADDRESS, (view,), B64, attributes=(1,))
            node = block.op1(Operation.POINTER_REBASE, (view, address), words, attributes=(16,))
            _value, memory = block.op(Operation.LOAD_BITS_LE, (node, memory), (B64, memory_type), attributes=(8, 8))
            return memory

        for rule, case in (("NATIVE-LINK-REGISTER-PATH", (RECORDS, ARENA, 16, link)), ("NATIVE-REBASE-REGISTER-PATH", (words, 64, 8, rebase))):
            with self.subTest(rule):
                kind, diagnostic = self._same_outcome(*program(*case))
                self.assertEqual((kind, diagnostic.rule), ("rejected", rule))

    def test_width_rejections_on_the_frame_path(self):
        """S12f.4 (ADR-280): a division or a rotation of another width than 32 or 64 bits on the frame path is the
        bootstrap's rejection (NATIVE-BITS-SUPPORTED naming the graph; NATIVE-ROTATE-RIGHT), the XAX program's."""
        from xax_compiler import FloatFormat, float_type, x86_64_linux_exec_target

        f64, b16 = float_type(FloatFormat.BINARY64), bits_type(16)

        def program(operation, attributes=()):
            graph = GraphBuilder()
            graph.track(f64, b16)
            block = graph.block(B32, B32)
            narrow = block.op1(Operation.INT_TRUNCATE, (block.params[0],), b16)
            operands = (narrow, block.op1(Operation.INT_TRUNCATE, (block.params[1],), b16)) if operation == Operation.UDIV else (narrow,)
            result = block.op1(operation, operands, b16, attributes=attributes)
            floating = block.op1(Operation.UINT_TO_FLOAT, (block.op1(Operation.INT_ZERO_EXTEND, (result,), B64),), f64)  # the frame path
            block.ret(block.op1(Operation.INT_TRUNCATE, (block.op1(Operation.FLOAT_TO_UINT_TRUNC, (floating,), B64),), B32))
            callee = graph.function((B32, B32), (B32,))
            entry, items = _process([(callee, ((B32, 9), (B32, 2)), (B32,))])
            target = x86_64_linux_exec_target()
            return program_store(entry, target, (*items, *graph.objects.values())), entry, target

        for rule, case in (("NATIVE-BITS-SUPPORTED", (Operation.UDIV,)), ("NATIVE-ROTATE-RIGHT", (Operation.ROTATE_RIGHT, (3,)))):
            with self.subTest(rule):
                kind, diagnostic = self._same_outcome(*program(*case))
                self.assertEqual((kind, diagnostic.rule), ("rejected", rule))

    def test_legacy_register_path(self):
        """S12f.4 (ADR-280): a function of ``add``/``sub``/``mul``, constants, and direct calls whose lowering view the
        register-resident path cannot take (an inlined float leaf) is lowered by the bootstrap's legacy register path;
        the XAX program's code is the bootstrap's (registers, spills, homes, edge copies, calls), and arithmetic of
        another width than 32 or 64 bits is its rejection (NATIVE-BITS-SUPPORTED)."""
        import random

        import xax_x86_64
        from xax_compiler import FloatFormat, float_type, x86_64_linux_exec_target

        f64 = float_type(FloatFormat.BINARY64)
        arithmetic = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP)

        def program(rng, width):
            value = bits_type(width)
            leaf_graph = GraphBuilder()
            leaf_graph.track(f64)
            block = leaf_graph.block(value, value)
            floating = block.op1(Operation.UINT_TO_FLOAT, (block.params[0],), f64)
            block.ret(block.op1(Operation.ADD_WRAP, (block.op1(Operation.FLOAT_TO_UINT_TRUNC, (floating,), value), block.params[1]), value))
            leaf = leaf_graph.function((value, value), (value,))
            outer_graph = GraphBuilder()
            block = outer_graph.block(value, value)
            called = block.op1(Operation.CALL_DIRECT, (block.params[0], block.params[1]), value, entity=leaf)
            block.ret(block.op1(Operation.SUB_WRAP, (called, block.params[0]), value))
            outer = outer_graph.function((value, value), (value,))
            graph = GraphBuilder()
            count = rng.randint(1, 4)
            entry = graph.block(*(value,) * count)
            pool = list(entry.params)

            def operations(block, pool, n):
                for _ in range(n):
                    roll = rng.random()
                    if roll < 0.15:
                        pool.append(block.const(value, rng.choice((0, 1, 7, 255, rng.getrandbits(width)))))
                    elif roll < 0.25:
                        pool.append(block.op1(Operation.CALL_DIRECT, (rng.choice(pool), rng.choice(pool)), value, entity=rng.choice((leaf, outer))))
                    else:
                        pool.append(block.op1(rng.choice(arithmetic), (rng.choice(pool), rng.choice(pool)), value))

            pool.append(entry.op1(Operation.CALL_DIRECT, (pool[0], pool[-1]), value, entity=leaf))  # inlined: keeps the view off
            operations(entry, pool, rng.randint(2, 18))
            shape = rng.choice(("return", "branch", "conditional"))
            if shape == "return":
                entry.ret(rng.choice(pool))
            else:
                k = rng.randint(1, 8)  # beyond six machine parameters: edge spill slots
                join = graph.block(*(value,) * k)
                if shape == "branch":
                    entry.br(join, *(rng.choice(pool) for _ in range(k)))
                else:
                    left, right = graph.block(), graph.block()
                    entry.cbr(entry.const(B1, rng.randint(0, 1)), left, (), right, ())
                    for side in (left, right):
                        reachable = pool[:]
                        operations(side, reachable, rng.randint(0, 8))
                        side.br(join, *(rng.choice(reachable) for _ in range(k)))
                joined = list(join.params)
                operations(join, joined, rng.randint(1, 10))
                crossing = joined + [rng.choice(pool)]  # an entry value used in the join: a home slot
                join.ret(join.op1(Operation.ADD_WRAP, (rng.choice(crossing), rng.choice(crossing)), value))
            function = graph.function((value,) * count, (value,))
            entry_function, items = _process([(function, tuple((value, rng.randint(0, 99)) for _ in range(count)), (value,))])
            target = x86_64_linux_exec_target()
            objects = (*items, *leaf_graph.objects.values(), *outer_graph.objects.values(), *graph.objects.values(), leaf, outer)
            return program_store(entry_function, target, objects), entry_function, target

        taken = []
        original = xax_x86_64._compile_register_resident_function

        def recording(*arguments, **keywords):
            result = original(*arguments, **keywords)
            taken.append(result is not None)
            return result

        xax_x86_64._compile_register_resident_function = recording
        try:
            rng = random.Random(280)
            for trial in range(24):
                width = rng.choice((32, 64))
                with self.subTest(trial=trial, width=width):
                    taken.clear()
                    reader, entry, target = program(rng, width)
                    self.assertEqual(self._same_outcome(reader, entry, target)[0], "image")
                    self.assertIn(True, taken)  # the bootstrap took the legacy path
            with self.subTest("NATIVE-BITS-SUPPORTED"):
                kind, diagnostic = self._same_outcome(*program(random.Random(7), 16))
                self.assertEqual((kind, diagnostic.rule), ("rejected", "NATIVE-BITS-SUPPORTED"))
        finally:
            xax_x86_64._compile_register_resident_function = original

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
