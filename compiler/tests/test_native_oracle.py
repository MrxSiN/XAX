"""ADR-405, slice 1 (docs/proposals/native-oracle.md): the native reference executor against the Python one.

On Linux x86-64 and on Windows x86-64, built by the pinned seed of the host (``xax_oracle_windows.xax`` on Windows): both executors
give the same results on the whole x86-64 register-lowering corpus (``test_xax_regalloc_differential``), and they
agree on traps, signed comparisons, rotations, several results and declined operations. ``native_execute`` is what
the area's comparison tests call instead of ``execute``.
"""

from __future__ import annotations

import functools
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
ORACLE = BOOTSTRAP / "oracle"
SEED = BOOTSTRAP / "seed" / "xaxc-linux-x86_64"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
WINDOWS_X86_64 = sys.platform == "win32" and platform.machine().lower() in ("x86_64", "amd64")
NATIVE = LINUX_X86_64 or WINDOWS_X86_64  # the hosts the native oracle runs on
BATCHES = ("oracle.batch", "driver.batch", "slice4-types.batch", "slice4-aggregates.batch")  # xax_oracle.xax, in order


@functools.lru_cache(maxsize=1)
def _program() -> Path:
    if WINDOWS_X86_64:
        seed, store, program = BOOTSTRAP / "windows" / "xaxc-windows-x86_64.exe", "xax_oracle_windows.xax", "xax_oracle.exe"
    else:
        seed, store, program = SEED, "xax_oracle.xax", "xax_oracle"
    work = Path(tempfile.mkdtemp(prefix="xax-oracle-"))
    subprocess.run([str(seed), "resolve", str(ORACLE / store), str(work / "oracle.xax")], check=True)
    subprocess.run([str(seed), "build", str(work / "oracle.xax"), str(work / program), str(work / "provenance")], check=True)
    (work / program).chmod(0o755)
    return work / program


def native_run(store: bytes, function_cid: bytes, arguments) -> tuple[int, str]:
    """The native oracle's exit status and output for one call (README.md)."""
    with tempfile.TemporaryDirectory() as directory:  # a closed file: Windows cannot open one that is still open
        file = Path(directory) / "store.xax"
        file.write_bytes(store)
        done = subprocess.run([str(_program()), "run", str(file), function_cid.hex(), *map(str, arguments)], capture_output=True, timeout=60)
    # On Windows the host layer writes through msvcrt _write, whose text-mode standard output ends lines with CR LF.
    return done.returncode, done.stdout.decode().replace("\r\n", "\n")


def native_execute(reader, function_cid: bytes, arguments) -> tuple[int, ...]:
    """``execute``'s results from the native oracle; anything but results fails the caller's test."""
    status, text = native_run(reader.data, function_cid, arguments)
    if status != 0:
        raise AssertionError(f"native oracle exit {status}: {text.strip()}")
    return tuple(int(line) for line in text.splitlines())


def oracle_execute(reader, function_cid: bytes, arguments) -> tuple[int, ...]:
    """The area's oracle: the native one where it runs (Linux and Windows x86-64), else the Python executor (ADR-405 (3))."""
    if NATIVE:
        return native_execute(reader, function_cid, arguments)
    from xax_compiler import execute

    return execute(reader, function_cid, arguments)


def _reference(reader, function_cid, arguments) -> tuple[int, str]:
    from xax_compiler import XaxError, XaxTrap, execute

    try:
        return 0, "".join(f"{value}\n" for value in execute(reader, function_cid, arguments))
    except XaxTrap as trap:
        return 1, f"trap {bytes(trap.payload).hex()}\n"
    except XaxError as error:
        return 3, error.diagnostic.rule


@unittest.skipUnless(NATIVE, "the native oracle runs on Linux and Windows x86-64")
class NativeOracleTests(unittest.TestCase):
    @unittest.skipUnless(LINUX_X86_64, "the pinned Linux seed")
    def test_the_store_is_its_batches(self):
        """oracle.batch on the ledger seed, then driver.batch (2026-11-28: the general driver's entry, so that
        ``windows/generator/generate.sh`` hosts it as ``xax_oracle_windows.xax``; test_windows_generator checks that),
        then slice 4's batches in order (README.md)."""
        with tempfile.TemporaryDirectory() as directory:
            store = BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"
            for k, batch in enumerate(BATCHES):
                out = Path(directory) / f"{k}.xax"
                subprocess.run([str(SEED), "edit", str(store), str(ORACLE / batch), str(out)], check=True)
                store = out
            self.assertEqual(store.read_bytes(), (ORACLE / "xax_oracle.xax").read_bytes())

    def test_arguments(self):
        """driver.batch's argument handling: too few arguments, and an argument of 4 KiB or more, exit 3."""
        done = subprocess.run([str(_program()), "run"], capture_output=True)
        self.assertEqual((done.returncode, done.stdout.replace(b"\r\n", b"\n")), (3, b"error\n"))
        with tempfile.TemporaryDirectory() as directory:
            long = "x" * 4096
            done = subprocess.run([str(_program()), "run", str(Path(directory) / "missing.xax"), long], capture_output=True)
            self.assertEqual((done.returncode, done.stdout.replace(b"\r\n", b"\n")), (3, b"error\n"))

    def test_both_oracles_agree_on_stack_memory(self):
        """Slice 3: stack allocations, offsets, plain and checked loads and stores, memory-check traps."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_xax_byte_view_widening import EXTENT, _stack_callee
        from xax_compiler import CHECKED_BYTE_VIEW_WIDTHS, x86_64_linux_exec_target
        from xax_graph_builder import program_store

        for size in CHECKED_BYTE_VIEW_WIDTHS:
            for store in (False, True):
                function, objects = _stack_callee(size, store=store)
                reader = program_store(function, x86_64_linux_exec_target(), objects)
                for offset in (0, 1, EXTENT - size, EXTENT - size + 1, EXTENT + 1):
                    for k in (0, size - 1) if store else (0,):
                        arguments = (offset, k) if store else (offset,)
                        with self.subTest(size=size, store=store, arguments=arguments):
                            self.assertEqual(native_run(reader.data, function.cid, arguments), _reference(reader, function.cid, arguments))

    def test_a_64_bit_offset_bound_does_not_wrap(self):
        """ADR-412 (4): ``offset + size <= extent`` holds without a 64-bit wrap, so offsets near 2^64 trap.

        A ``bits<64>`` offset is R2's, so the store is not verified, and the expected values are the area's own
        (``_expected``, unbounded integers), as the Python verifier still rejects the width."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_xax_byte_view_widening import B64, EXTENT, _expected, _stack_callee
        from xax_compiler import x86_64_linux_exec_target
        from xax_graph_builder import program_store

        top = 1 << 64
        for size in (1, 8):
            for store in (False, True):
                function, objects = _stack_callee(size, store=store, offset_type=B64)
                with mock.patch("xax_graph_builder.verify_store", lambda reader: None):
                    reader = program_store(function, x86_64_linux_exec_target(), objects)
                for offset in (0, EXTENT - size, EXTENT - size + 1, 1 << 32, top - size, top - 1, top - EXTENT):
                    value = _expected(size, offset, store=store)
                    expected = (1, "trap 6d656d6f72792d636865636b\n") if value is None else (0, f"{value}\n")
                    with self.subTest(size=size, store=store, offset=offset):
                        self.assertEqual(native_run(reader.data, function.cid, (offset, 0) if store else (offset,)), expected)

    def test_both_oracles_agree_on_the_register_lowering_corpus(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_xax_regalloc_differential import RegisterAllocatorDifferentialTests
        from xax_compiler import x86_64_linux_exec_target
        from xax_graph_builder import program_store

        functions, objects = RegisterAllocatorDifferentialTests()._corpus()
        target = x86_64_linux_exec_target()
        for index, (function, arguments) in enumerate(functions):
            with self.subTest(program=index):
                reader = program_store(function, target, objects)
                self.assertEqual(native_run(reader.data, function.cid, arguments), _reference(reader, function.cid, arguments))

    def test_both_oracles_agree_on_the_narrow_compare_corpus(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_x86_64_narrow_signed_compare import WIDTHS, _compare_program, _values
        from xax_compiler import IntCompare

        for width in WIDTHS:
            for kind in IntCompare:
                reader, entry, _target = _compare_program(width, kind)
                for left in _values(width):
                    for right in _values(width):
                        with self.subTest(width=width, kind=kind.name, left=left, right=right):
                            self.assertEqual(native_run(reader.data, entry.cid, (left, right)), _reference(reader, entry.cid, (left, right)))

    def test_both_oracles_agree_on_the_branch_fusion_corpus(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_native_branch_fusion import BRANCH_ONLY, INPUTS, REUSED
        from xax_construct import construct

        effects = ["linux.process_effect", "linux.filesystem_effect"]
        main = {"name": "main", "params": effects, "returns": ["b32", *effects], "blocks": [{"params": effects, "nodes": [
            ["call.direct", [["b32", 1], ["b32", 2]], ["b32"], {"entity": {"fn": "f"}}],
            ["call.foreign", ["n0", "p0"], [effects[0]], {"entity": "linux.exit_group"}]], "end": ["ret", ["n0", "n1", "p1"]]}]}
        for function in (REUSED, BRANCH_ONLY):
            built = construct({"format": "xax-construct-v1", "platform": "linux-x86_64", "functions": [function, main],
                               "package": {"name": "oi50", "entries": {"app": "main"}, "release": "app"}})
            cid = built.functions["f"].cid
            for arguments in INPUTS:
                with self.subTest(blocks=len(function["blocks"]), arguments=arguments):
                    data = built.reader.canonical_bytes()
                    self.assertEqual(native_run(data, cid, arguments), _reference(built.reader, cid, arguments))

    def test_both_oracles_agree_on_recursion_groups(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_xax_recursion as recursion
        from xax_compiler import x86_64_linux_exec_target

        target = x86_64_linux_exec_target()
        parity, even, odd = recursion.parity_group()
        cases = [(recursion.factorial_group(), 0, n) for n in (0, 1, 5, 10, 12)]
        cases += [(parity, member, value) for member, value in ((even, 10), (even, 7), (odd, 7), (odd, 0), (even, 200))]
        for group, member, value in cases:
            with self.subTest(member=member, value=value):
                reader, entry = recursion.program(group, member, target)
                self.assertEqual(native_run(reader.data, entry.cid, (value,)), _reference(reader, entry.cid, (value,)))

    def test_both_oracles_agree_on_aggregates_and_sums(self):
        """Slice 4 (docs/proposals/native-oracle.md §4): tuples, arrays and sums, test_xax_general_language's programs
        and more: nested aggregates, an aggregate returned by a callee, and the sum-variant trap."""
        from test_xax_general_language import reader_for
        from xax_compiler import (Block, IntCompare, Node, Operation, Terminator, ValueRef, array_type, bits_type, constant,
                                  function, graph_fragment, sum_type, tuple_type, x86_64_windows_general_target)

        P, R = ValueRef.parameter, ValueRef.node_result
        b1, b32, b64 = bits_type(1), bits_type(32), bits_type(64)
        pair, array, target = tuple_type((b32, b32)), array_type(b32, 2), x86_64_windows_general_target()
        cases = []

        def make(blocks, parameters, results):
            graph = graph_fragment(blocks)
            return function(graph, parameters, results), graph

        # test_xax_general_language: a tuple and an array
        entry, graph = make([Block((b32, b32), (
            Node(Operation.AGGREGATE_MAKE, (P(0, 0), P(0, 1)), (pair,)),
            Node(Operation.AGGREGATE_GET, (R(0, 0),), (b32,), attributes=(1,)),
            Node(Operation.AGGREGATE_MAKE, (P(0, 0), R(0, 1)), (array,)),
            Node(Operation.AGGREGATE_GET, (R(0, 2),), (b32,), attributes=(0,)),
            Node(Operation.ADD_WRAP, (R(0, 1), R(0, 3)), (b32,)),
        ), Terminator.return_((R(0, 4),)))], (b32, b32), (b32,))
        reader = reader_for(entry, [b32, pair, array, graph, entry], target)
        cases += [(reader, entry.cid, arguments) for arguments in ((7, 11), (0, 0), ((1 << 32) - 1, 5))]

        # test_xax_general_language: a sum across a block edge
        choice, zero = sum_type((b32, b1)), constant(b1, 0)
        entry, graph = make([
            Block((b32,), (Node(Operation.SUM_MAKE, (P(0, 0),), (choice,), attributes=(0,)),
                           Node(Operation.SUM_TAG, (R(0, 0),), (b1,)),
                           Node(Operation.CONSTANT, (), (b1,), entity=zero),
                           Node(Operation.INT_COMPARE, (R(0, 1), R(0, 2)), (b1,), attributes=(IntCompare.EQ,))),
                  Terminator.conditional_branch(R(0, 3), 1, (R(0, 0),), 2, ())),
            Block((choice,), (Node(Operation.SUM_GET, (P(1, 0),), (b32,), attributes=(0,)),), Terminator.return_((R(1, 0),))),
            Block((), (), Terminator.trap()),
        ], (b32,), (b32,))
        reader = reader_for(entry, [b1, b32, choice, zero, graph, entry], target)
        cases += [(reader, entry.cid, (value,)) for value in (99, 0, (1 << 32) - 1)]

        # the wrong variant traps (sum-variant); the tag of the right one
        wide = sum_type((b32, b64))
        entry, graph = make([Block((b64,), (Node(Operation.SUM_MAKE, (P(0, 0),), (wide,), attributes=(1,)),
                                            Node(Operation.SUM_TAG, (R(0, 0),), (b1,)),
                                            Node(Operation.SUM_GET, (R(0, 0),), (b32,), attributes=(0,))),
                                  Terminator.return_((R(0, 2),)))], (b64,), (b32,))
        reader = reader_for(entry, [b1, b32, b64, wide, graph, entry], target)
        cases.append((reader, entry.cid, (5,)))
        entry, graph = make([Block((b64,), (Node(Operation.SUM_MAKE, (P(0, 0),), (wide,), attributes=(1,)),
                                            Node(Operation.SUM_TAG, (R(0, 0),), (b1,)),
                                            Node(Operation.SUM_GET, (R(0, 0),), (b64,), attributes=(1,))),
                                  Terminator.return_((R(0, 1), R(0, 2))))], (b64,), (b1, b64))
        reader = reader_for(entry, [b1, b64, b32, wide, graph, entry], target)
        cases.append((reader, entry.cid, ((1 << 64) - 1,)))

        # nested aggregates, and an aggregate a callee returns (it outlives the callee's frame)
        outer = tuple_type((pair, b32))
        callee, callee_graph = make([Block((b32, b32), (Node(Operation.AGGREGATE_MAKE, (P(0, 1), P(0, 0)), (pair,)),),
                                           Terminator.return_((R(0, 0),)))], (b32, b32), (pair,))
        entry, graph = make([Block((b32, b32), (
            Node(Operation.CALL_DIRECT, (P(0, 0), P(0, 1)), (pair,), entity=callee),
            Node(Operation.AGGREGATE_MAKE, (R(0, 0), P(0, 0)), (outer,)),
            Node(Operation.AGGREGATE_GET, (R(0, 1),), (pair,), attributes=(0,)),
            Node(Operation.AGGREGATE_GET, (R(0, 2),), (b32,), attributes=(0,)),
            Node(Operation.AGGREGATE_GET, (R(0, 1),), (b32,), attributes=(1,)),
            Node(Operation.SUB_WRAP, (R(0, 3), R(0, 4)), (b32,)),
        ), Terminator.return_((R(0, 5),)))], (b32, b32), (b32,))
        reader = reader_for(entry, [b32, pair, outer, callee_graph, callee, graph, entry], target)
        cases += [(reader, entry.cid, arguments) for arguments in ((3, 10), (10, 3))]

        for reader, cid, arguments in cases:
            with self.subTest(function=cid.hex()[:8], arguments=arguments):
                self.assertEqual(native_run(reader.data, cid, arguments), _reference(reader, cid, arguments))

    def test_traps_compares_rotations_results_and_declines(self):
        from xax_compiler import FloatFormat, IntCompare, Operation, TrapReason, bits_type, float_type, trap_payload, x86_64_linux_exec_target
        from xax_graph_builder import GraphBuilder, program_store

        b1, b8, b32, b64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)
        target = x86_64_linux_exec_target()

        def check(build, parameters, results, *calls):
            graph = GraphBuilder()
            build(graph)
            function = graph.function(parameters, results)
            reader = program_store(function, target, tuple(graph.objects.values()))
            return [(reader, function, arguments) for arguments in calls]

        def udiv(graph):
            block = graph.block(b64, b64)
            block.ret(block.op1(Operation.UDIV, block.params, b64))

        def explicit(graph):
            graph.block(b32).trap(trap_payload(TrapReason.EXPLICIT, b"\x07\x08"))

        def signed(graph):
            block = graph.block(b8, b8)
            block.ret(block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, block.params, b1, attributes=(IntCompare.SLT,)),), b32))

        def rotate(graph):
            block = graph.block(b32)
            block.ret(block.op1(Operation.ROTATE_RIGHT, block.params, b32, attributes=(7,)))

        def pair(graph):
            block = graph.block(b64, b64)
            block.ret(block.op1(Operation.ADD_WRAP, block.params, b64), block.op1(Operation.MUL_WRAP, block.params, b64))

        cases = [*check(udiv, (b64, b64), (b64,), (17, 5), (5, 0)), *check(explicit, (b32,), (b32,), (1,)),
                 *check(signed, (b8, b8), (b32,), (200, 5), (5, 200)), *check(rotate, (b32,), (b32,), (0x12345679,)),
                 *check(pair, (b64, b64), (b64, b64), (1 << 63, 3))]
        for reader, function, arguments in cases:
            with self.subTest(function=function.cid.hex()[:8], arguments=arguments):
                self.assertEqual(native_run(reader.data, function.cid, arguments), _reference(reader, function.cid, arguments))

        graph = GraphBuilder()
        f64 = float_type(FloatFormat.BINARY64)
        block = graph.block(f64, f64)
        block.ret(block.op1(Operation.FLOAT_ADD, block.params, f64))
        function = graph.function((f64, f64), (f64,))
        reader = program_store(function, target, tuple(graph.objects.values()))
        self.assertEqual(native_run(reader.data, function.cid, (0, 0)), (2, f"decline {int(Operation.FLOAT_ADD)}\n"))


if __name__ == "__main__":
    unittest.main()
