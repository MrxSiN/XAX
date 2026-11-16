"""ADR-405, slice 1 (docs/proposals/native-oracle.md): the native reference executor against the Python one.

On Linux x86-64 with the pinned seed: the committed program is the seed's ``xaxc edit`` of its batch, both executors
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
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
ORACLE = BOOTSTRAP / "oracle"
SEED = BOOTSTRAP / "seed" / "xaxc-linux-x86_64"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


@functools.lru_cache(maxsize=1)
def _program() -> Path:
    work = Path(tempfile.mkdtemp(prefix="xax-oracle-"))
    subprocess.run([str(SEED), "resolve", str(ORACLE / "xax_oracle.xax"), str(work / "oracle.xax")], check=True)
    subprocess.run([str(SEED), "build", str(work / "oracle.xax"), str(work / "xax_oracle"), str(work / "provenance")], check=True)
    (work / "xax_oracle").chmod(0o755)
    return work / "xax_oracle"


def native_run(store: bytes, function_cid: bytes, arguments) -> tuple[int, str]:
    """The native oracle's exit status and output for one call (README.md)."""
    with tempfile.NamedTemporaryFile(suffix=".xax") as file:
        file.write(store)
        file.flush()
        done = subprocess.run([str(_program()), "run", file.name, function_cid.hex(), *map(str, arguments)], capture_output=True, timeout=60)
    return done.returncode, done.stdout.decode()


def native_execute(reader, function_cid: bytes, arguments) -> tuple[int, ...]:
    """``execute``'s results from the native oracle; anything but results fails the caller's test."""
    status, text = native_run(reader.data, function_cid, arguments)
    if status != 0:
        raise AssertionError(f"native oracle exit {status}: {text.strip()}")
    return tuple(int(line) for line in text.splitlines())


def oracle_execute(reader, function_cid: bytes, arguments) -> tuple[int, ...]:
    """The area's oracle: the native one where it runs (Linux x86-64), else the Python executor (ADR-405 (3))."""
    if LINUX_X86_64:
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


@unittest.skipUnless(LINUX_X86_64, "the pinned seed runs on Linux x86-64")
class NativeOracleTests(unittest.TestCase):
    def test_the_store_is_its_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "oracle.xax"
            subprocess.run([str(SEED), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"), str(ORACLE / "oracle.batch"), str(out)], check=True)
            self.assertEqual(out.read_bytes(), (ORACLE / "xax_oracle.xax").read_bytes())

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
