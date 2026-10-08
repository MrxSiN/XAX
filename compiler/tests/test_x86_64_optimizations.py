"""Soundness of the x86-64 register-path optimizations (OI-38, ADR-147).

Each optimization is exercised at the edge of what it may assume: a check is
only removed when value ranges prove it, so the off-by-one program must still
trap; the lowering view (inlining, layout, folding) must not change results.
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import IntCompare, Operation, Permission, bits_type, heap_view_type, memory_effect_type, pointer_type, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_inline import inline_leaf_calls
from xax_linux import compile_linux_executable, linux_api, run_linux_executable
from xax_structured import B8, B32, B64, Proc

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
MEM = memory_effect_type()
BYTES = pointer_type(B8, Permission.READ_WRITE, 1, space=2)
EXTENT = 64


def _program(body):
    """A process entry mapping one zeroed ``EXTENT``-byte view; ``body(proc)`` returns the exit status."""
    api = linux_api()
    proc = Proc((("proc", api.process_effect), ("fs", api.filesystem_effect), ("m", MEM)))
    raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(EXTENT, B64), proc.drop("m")), (api.bytes_rw, api.heap_owner, MEM), entity=api.mmap_anonymous)
    pointer, view, memory = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (BYTES, heap_view_type(EXTENT), MEM), attributes=(EXTENT, 1))
    proc.let("p", BYTES, pointer)
    proc.let("v", heap_view_type(EXTENT), view)
    proc.let("m", MEM, memory)
    status = body(proc)
    _r, proc["m"] = proc.op(Operation.CALL_FOREIGN, (proc["p"], proc["v"], proc["m"]), (B64, MEM), entity=api.munmap_view(BYTES, EXTENT))
    process = proc.op1(Operation.CALL_FOREIGN, (status, proc["proc"]), api.process_effect, entity=api.exit_group)
    proc.ret(status, process, proc["fs"], proc["m"])
    entry = proc.function((B32, api.process_effect, api.filesystem_effect, MEM))
    target = x86_64_linux_exec_target()
    return program_store(entry, target, (*api.types, *proc.graph.objects.values())), entry, target


def _fill(limit: int):
    """Store 1 at every index ``i < limit``; the loop bound alone decides whether the store check can go."""
    def body(proc: Proc):
        proc.let("i", B32, proc.const(0))

        def step(p: Proc):
            p["m"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["p"], p["i"], p.const(1, B8), p["m"]), MEM, attributes=(1, 1))
            p["i"] = p.bin(Operation.ADD_WRAP, p["i"], 1)

        proc.while_(lambda p: p.cmp(IntCompare.ULT, p["i"], limit), step)
        last, proc["m"] = proc.op(Operation.CHECKED_LOAD_BITS_LE, (proc["p"], proc.const(EXTENT - 1), proc["m"]), (B8, MEM), attributes=(1, 1))
        return proc.bin(Operation.ADD_WRAP, proc.widen(last), 40)
    return _program(body)


def _classify():
    """Count and sum the bytes 0..255 that are JSON whitespace: an OR of equalities (one bit test)."""
    def body(proc: Proc):
        proc.let("b", B32, proc.const(0))
        proc.let("count", B32, proc.const(0))
        proc.let("sum", B32, proc.const(0))

        def step(p: Proc):
            b = p["b"]
            flag = p.widen(p.any_of(*(p.cmp(IntCompare.EQ, b, value) for value in (0x20, 0x09, 0x0A, 0x0D))))
            p["count"] = p.bin(Operation.ADD_WRAP, p["count"], flag)
            p["sum"] = p.bin(Operation.ADD_WRAP, p["sum"], p.bin(Operation.MUL_WRAP, flag, b))
            p["b"] = p.bin(Operation.ADD_WRAP, b, 1)

        proc.while_(lambda p: p.cmp(IntCompare.ULT, p["b"], 256), step)
        return proc.bin(Operation.ADD_WRAP, proc.bin(Operation.MUL_WRAP, proc["count"], 100), proc["sum"])
    return _program(body)


# Predicates over one byte (ADR-208): each is (name, builder, reference).  Builders get the Proc and the byte.
def _in_range(p: Proc, value, low: int, high: int):
    return p.cmp(IntCompare.ULE, p.bin(Operation.SUB_WRAP, value, low), high - low)


PREDICATES = (
    ("hex digit", lambda p, b: p.any_of(_in_range(p, b, 0x30, 0x39), _in_range(p, b, 0x41, 0x46), _in_range(p, b, 0x61, 0x66)),
     lambda b: chr(b) in "0123456789ABCDEFabcdef"),
    ("signed and masked", lambda p, b: p.all_of(
        p.cmp(IntCompare.SLT, p.bin(Operation.SUB_WRAP, b, 0x40), 0x10), p.cmp(IntCompare.NE, p.bin(Operation.BIT_AND, b, 3), 1)),
     lambda b: ((b - 0x40) & 0xFFFFFFFF) - ((b - 0x40) & 0x80000000) * 2 < 0x10 and b & 3 != 1),
    ("wrapping product", lambda p, b: p.any_of(
        p.cmp(IntCompare.UGT, p.bin(Operation.MUL_WRAP, b, 0x01010101), 0x7F000000), p.cmp(IntCompare.EQ, p.bin(Operation.BIT_XOR, b, 0x5A), 0)),
     lambda b: (b * 0x01010101) & 0xFFFFFFFF > 0x7F000000 or b == 0x5A),
)


def _predicate_program(predicate, branch: bool, result: str):
    """Loop over the bytes 0..255; ``result`` 'count' returns how many satisfy ``predicate``, 'xor' their XOR.
    ``branch`` uses the predicate as a branch condition, otherwise as a value."""
    def body(proc: Proc):
        proc.let("b", B32, proc.const(0))
        proc.let("acc", B32, proc.const(0))

        def step(p: Proc):
            b = p["b"]
            flag = predicate(p, b)
            if branch:
                def hit(q: Proc):
                    q["acc"] = q.bin(Operation.ADD_WRAP, q["acc"], 1) if result == "count" else q.bin(Operation.BIT_XOR, q["acc"], q["b"])
                p.if_(flag, hit)
            else:
                wide = p.widen(flag)
                p["acc"] = p.bin(Operation.ADD_WRAP, p["acc"], wide) if result == "count" else p.bin(
                    Operation.BIT_XOR, p["acc"], p.bin(Operation.MUL_WRAP, wide, b))
            p["b"] = p.bin(Operation.ADD_WRAP, p["b"], 1)

        proc.while_(lambda p: p.cmp(IntCompare.ULT, p["b"], 256), step)
        return proc.bin(Operation.BIT_AND, proc["acc"], 0xFF)
    return _program(body)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class RangeEliminationTests(unittest.TestCase):
    def test_proven_loop_index_runs(self):
        reader, entry, target = _fill(EXTENT)
        self.assertEqual(run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data).returncode, 41)

    def test_off_by_one_loop_index_still_traps(self):
        reader, entry, target = _fill(EXTENT + 1)
        self.assertEqual(run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data).returncode, -4)

    def test_membership_value_matches_every_byte(self):
        reader, entry, target = _classify()
        expected = (4 * 100 + 0x20 + 0x09 + 0x0A + 0x0D) % 256
        self.assertEqual(run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data).returncode, expected)


class PredicateTableTests(unittest.TestCase):
    """ADR-208: a boolean of one byte-ranged value read from a table equals the expression for every byte."""

    def test_tables_are_emitted_for_value_and_branch_forms(self):
        for name, predicate, reference in PREDICATES:
            for branch in (False, True):
                with self.subTest(name=name, branch=branch):
                    reader, entry, target = _predicate_program(predicate, branch, "count")
                    code = compile_linux_executable(reader, entry.cid, target.cid).data
                    self.assertIn(bytes(int(reference(b)) for b in range(256)), code)
                    self.assertIn(b"\x4c\x8d\x1d", code)  # lea r11, [rip + table]

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_tables_execute_exactly(self):
        for name, predicate, reference in PREDICATES:
            members = [b for b in range(256) if reference(b)]
            xor = 0
            for b in members:
                xor ^= b
            for branch in (False, True):
                for result, expected in (("count", len(members) & 0xFF), ("xor", xor)):
                    with self.subTest(name=name, branch=branch, result=result):
                        reader, entry, target = _predicate_program(predicate, branch, result)
                        completed = run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data)
                        self.assertEqual(completed.returncode, expected)


def _exit_edge_sum(start: int, width):
    """``x`` counts up from ``start`` until a wrapping ``+1`` reaches 0; ``found + 0xFF`` is computed in the loop
    block but only its exit edge passes it (an ADR-211 sink).  Exit status: ``(found + 0xFF + x) & 0xFF``."""
    from xax_graph_builder import GraphBuilder

    api = linux_api()
    graph = GraphBuilder()
    effects = (api.process_effect, api.filesystem_effect, MEM)
    entry, loop, done = graph.block(*effects), graph.block(*effects, width, width), graph.block(*effects, width, width)
    entry.br(loop, *entry.params, entry.const(width, start), entry.const(width, 0))
    process, fs, memory, x, found = loop.params
    following = loop.op1(Operation.ADD_WRAP, (x, loop.const(width, 1)), width)
    exit_found = loop.op1(Operation.ADD_WRAP, (found, loop.const(width, 0xFF)), width)
    at_zero = loop.op1(Operation.INT_COMPARE, (following, loop.const(width, 0)), bits_type(1), attributes=(IntCompare.EQ,))
    loop.cbr(at_zero, done, (process, fs, memory, following, exit_found), loop, (process, fs, memory, following, found))
    process, fs, memory, x, found = done.params
    low = lambda value: value if width is B32 else done.op1(Operation.INT_TRUNCATE, (value,), B32)  # noqa: E731
    total = done.op1(Operation.ADD_WRAP, (low(found), low(x)), B32)
    status = done.op1(Operation.BIT_AND, (total, done.const(B32, 0xFF)), B32)
    process = done.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    done.ret(status, process, fs, memory)
    function = graph.function(effects, (B32, *effects))
    target = x86_64_linux_exec_target()
    return program_store(function, target, (*api.types, *graph.objects.values())), function, target


class EdgeSinkAndPrefetchTests(unittest.TestCase):
    """ADR-211: exit-only arithmetic moves onto its edge; next-iteration prefetches never change results."""

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_sunk_edge_arithmetic_wraps_exactly(self):
        for width, start in ((B32, 0xFFFFFFF0), (B64, 0xFFFFFFFFFFFFFFF0)):
            with self.subTest(width=width):
                reader, entry, target = _exit_edge_sum(start, width)
                self.assertEqual(run_linux_executable(compile_linux_executable(reader, entry.cid, target.cid).data).returncode, 0xFF)

    def test_chains_lookup_gets_a_proven_prefetch_and_others_do_not(self):
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from benchmarks.linux_chains import build_chains_program
        from xax_compiler import parse_function_graph
        from xax_prefetch import prefetch_next_iteration

        program = build_chains_program(links="soa")
        view, marks = prefetch_next_iteration(inline_leaf_calls(parse_function_graph(program.entry, program.reader.get), program.reader.get), program.reader.get)
        self.assertEqual(len(marks), 1)
        (hints,) = marks.values()
        self.assertEqual(sorted(scale for _pointer, scale in hints), [4, 8])
        reader, entry, _target = _fill(EXTENT)
        plain = inline_leaf_calls(parse_function_graph(entry, reader.get), reader.get)
        self.assertEqual(prefetch_next_iteration(plain, reader.get)[1], {})

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_chains_with_prefetch_keeps_its_output(self):
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from benchmarks.linux_chains import compile_chains

        _program_, executable = compile_chains(nodes=1 << 12, buckets=1 << 8, links="soa")
        self.assertIn(b"\x0f\x18", executable.data)  # prefetcht0
        completed = run_linux_executable(executable.data)
        self.assertEqual(completed.returncode, 0)
        x, keys, heads, nxt = 0x9E3779B97F4A7C15, [0] * ((1 << 12) + 1), [0] * (1 << 8), [0] * ((1 << 12) + 1)
        mask = (1 << 64) - 1
        def step(v):
            v ^= (v << 13) & mask
            v ^= v >> 7
            return v ^ ((v << 17) & mask)
        for i in range(1 << 12):
            x = step(x)
            b = x >> 56
            keys[i + 1], nxt[i + 1], heads[b] = x, heads[b], i + 1
        x, found, steps = 0x9E3779B97F4A7C15, 0, 0
        for _ in range(1 << 12):
            x = step(x)
            cur = heads[x >> 56]
            while cur and cur <= 1 << 12:
                steps += 1
                if keys[cur] == x:
                    found += 1
                    break
                cur = nxt[cur]
        self.assertEqual(completed.stdout, f"{found} {steps}\n".encode())


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class LoweringViewTests(unittest.TestCase):
    def test_jsonmin_inlines_leaf_helpers_and_keeps_results(self):
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from benchmarks import jsonmin

        from xax_compiler import parse_function_graph

        program = jsonmin.build_jsonmin()
        resolve = program.reader.get
        view = inline_leaf_calls(parse_function_graph(program.entry, resolve), resolve)
        calls = [node for block in view.blocks for node in block.nodes if node.operation == Operation.CALL_DIRECT]
        helpers = jsonmin.helpers()
        self.assertFalse(any(node.entity.cid == helpers.whitespace.cid for node in calls))
        binary = compile_linux_executable(program.reader, program.entry.cid, program.target.cid).data
        for text in (b'{"a": [1, -2.5e+3, true, null], "b\\u00e9": "x\\n"}', b"[1, 2", b'"\x01"', b"[" * 600 + b"]" * 600, b" \t\r\n{}\v"):
            with self.subTest(text=text):
                completed = run_linux_executable(binary, stdin=text)
                self.assertEqual((completed.returncode, completed.stdout, completed.stderr), jsonmin.reference_jsonmin(text))


if __name__ == "__main__":
    unittest.main()
