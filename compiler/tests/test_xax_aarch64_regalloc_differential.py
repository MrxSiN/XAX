"""Differential validation of the AArch64 register-resident path on general targets (ADR-110).

Seeded random integer programs, in a 64-bit and a 32-bit family, are compiled
into one Android arm64 library for the general (v4) target and executed under
Android's own ``linker64`` and bionic via ``qemu-aarch64``.  Each program has
straight-line arithmetic, a counted loop whose body uses entry-block values by
dominance (exercising value homes) and may call earlier programs, and a
compare-driven diamond using every ``IntCompare`` predicate.  Every result must
equal the reference executor's.  This is translation validation by execution
over a fixed corpus, not a proof.
"""

from __future__ import annotations

import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xax_android import AndroidExport, compile_android_shared
from xax_compiler import IntCompare, Operation, android_arm64_shared_general_target, bits_type, execute, store_resolver, _decode_function_interface, _parse_graph
from xax_graph_builder import GraphBuilder
from xax_aarch64 import _register_path_eligible

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import bench_android_bionic as bionic  # noqa: E402
from benchmarks.bench_android_arm64 import _reader  # noqa: E402

B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
SEED, COUNT = 20261002, 48
ARITHMETIC = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP)
EDGES = {64: (0, 1, 2, 7, 255, 1 << 31, (1 << 32) - 1, 1 << 63, (1 << 64) - 1, 0x9E3779B97F4A7C15),
         32: (0, 1, 2, 7, 255, 1 << 15, (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 0x9E3779B9)}


def _program(rng: random.Random, width: int, callees: list):
    """``f(a, b) -> bits<width>``: arithmetic, a counted loop using entry values, and a diamond."""
    kind = bits_type(width)
    graph = GraphBuilder()
    entry = graph.block(kind, kind)
    loop, body, after, then, otherwise, join = (
        graph.block(kind, kind), graph.block(kind, kind), graph.block(kind),
        graph.block(kind), graph.block(kind), graph.block(kind),
    )

    def constant(block):
        return block.const(kind, rng.choice(EDGES[width]) if rng.random() < 0.5 else rng.getrandbits(width))

    def step(block, pool):
        left = rng.choice(pool) if rng.random() < 0.8 else constant(block)
        right = rng.choice(pool) if rng.random() < 0.8 else constant(block)
        return block.op1(rng.choice(ARITHMETIC), (left, right), kind)

    pool = list(entry.params)
    for _ in range(rng.randrange(2, 7)):
        pool.append(step(entry, pool))
    entry.br(loop, entry.const(kind, 0), pool[-1])

    counter, accumulator = loop.params
    limit = loop.const(kind, rng.randrange(0, 5))
    loop.cbr(loop.op1(Operation.INT_COMPARE, (counter, limit), B1, attributes=(IntCompare.ULT,)), body, (counter, accumulator), after, (accumulator,))

    counter, accumulator = body.params
    inner = [counter, accumulator, *rng.sample(pool, min(3, len(pool)))]  # entry values used by dominance
    for _ in range(rng.randrange(1, 4)):
        inner.append(step(body, inner))
    if callees and rng.random() < 0.5:
        callee = rng.choice(callees)
        inner.append(body.op1(Operation.CALL_DIRECT, (rng.choice(inner), rng.choice(inner)), kind, entity=callee))
    body.br(loop, body.op1(Operation.ADD_WRAP, (counter, body.const(kind, 1)), kind), inner[-1])

    (value,) = after.params
    test = after.op1(Operation.INT_COMPARE, (value, rng.choice(pool)), B1, attributes=(rng.choice(tuple(IntCompare)),))
    after.cbr(test, then, (value,), otherwise, (value,))
    then.br(join, then.op1(Operation.ADD_WRAP, (then.params[0], rng.choice(pool)), kind))
    otherwise.br(join, otherwise.op1(Operation.MUL_WRAP, (otherwise.params[0], constant(otherwise)), kind))
    join.ret(join.params[0])
    return graph, graph.function((kind, kind), (kind,))


def corpus():
    rng = random.Random(SEED)
    target = android_arm64_shared_general_target(packed=True)
    functions, objects, widths = [], [], []
    for width in (64, 32):
        family = []
        for _ in range(COUNT // 2):
            graph, function = _program(rng, width, family)
            family.append(function)
            functions.append(function)
            objects.extend(graph.objects.values())
            widths.append(width)
    reader = _reader(tuple(functions), tuple(objects), target)
    return reader, target, functions, widths


def _arguments(rng: random.Random, width: int) -> list[tuple[int, int]]:
    edges = EDGES[width]
    return [(rng.choice(edges), rng.choice(edges)) for _ in range(3)] + [(rng.getrandbits(width), rng.getrandbits(width)) for _ in range(3)]


class AArch64RegisterPathDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader, cls.target, cls.functions, cls.widths = corpus()

    def test_corpus_takes_the_register_path(self):
        resolve = store_resolver(self.reader)
        for function in self.functions:
            graph_object, parameters, returns = _decode_function_interface(function, resolve)
            self.assertTrue(_register_path_eligible(_parse_graph(graph_object, resolve), parameters, returns, resolve))

    @unittest.skipUnless(bionic.QEMU and (bionic.ROOT / "system/bin/linker64").exists() and bionic.JNI_H.exists(), "requires the NDK, qemu-aarch64, and an Android bionic root")
    def test_results_match_the_reference_executor(self):
        exports = tuple(AndroidExport(f"f{index}".encode(), function.cid) for index, function in enumerate(self.functions))
        library = compile_android_shared(self.reader, exports, target_object=self.target).data
        rng = random.Random(SEED + 1)
        cases = [(index, a, b) for index, width in enumerate(self.widths) for a, b in _arguments(rng, width)]
        lines = ["#include <dlfcn.h>", "#include <stdint.h>", "#include <stdio.h>", "int main(int argc, char **argv) {",
                 "  void *h = dlopen(argv[1], RTLD_NOW); if (!h) return 65;"]
        for index, a, b in cases:
            c_type = "uint64_t" if self.widths[index] == 64 else "uint32_t"
            lines.append(f'  {{ {c_type} (*f)({c_type}, {c_type}) = dlsym(h, "f{index}"); if (!f) return 66; '
                         f'printf("%d %llu\\n", {index}, (unsigned long long) f(({c_type}){a}ULL, ({c_type}){b}ULL)); }}')
        lines += ["  return 0;", "}"]
        expected = [f"{index} {execute(self.reader, self.functions[index].cid, (a, b))[0]}" for index, a, b in cases]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "libcorpus.so").write_bytes(library)
            (work / "harness.c").write_text("\n".join(lines) + "\n", encoding="utf-8")
            subprocess.run([bionic._clang(28), "-O1", "-fPIE", "-pie", str(work / "harness.c"), "-ldl", "-o", str(work / "harness")], check=True, capture_output=True)
            completed = bionic._run(work / "harness", "./libcorpus.so", cwd=work)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), expected)


if __name__ == "__main__":
    unittest.main()
