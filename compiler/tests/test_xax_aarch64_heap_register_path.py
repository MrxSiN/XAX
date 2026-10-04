"""Differential validation of heap memory on the AArch64 register path (ADR-154).

Seeded random programs ``f(a, b) -> bits<width>`` run one to three phases.  Each
phase allocates a heap cell with bionic ``malloc``, makes it a heap view
(null-checked), stores and loads it in a random order mixed with arithmetic and
``getpid`` calls (so the pointer and values live across calls), and frees it;
values carry from phase to phase, and the last loaded value is returned.  They are compiled into one Android
arm64 library for the general (v4) target and executed under Android's own
``linker64`` and bionic via ``qemu-aarch64``.  Expected results come from a
mirror of the generated operations, computed while the program is built.  This
is translation validation by execution over a fixed corpus, not a proof.
"""

from __future__ import annotations

import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xax_android import AndroidExport, compile_android_shared
from xax_compiler import (
    ForeignDeallocatorContract, Operation, Permission, android_arm64_shared_general_target, bits_type,
    foreign_function_symbol, heap_view_type, pointer_type, store_resolver, _decode_function_interface, _parse_graph,
)
from xax_graph_builder import GraphBuilder
from xax_aarch64 import _register_path_eligible
from xax_platform import posix_android_api

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import bench_android_bionic as bionic  # noqa: E402
from benchmarks.bench_android_arm64 import _reader  # noqa: E402

SEED, COUNT = 20261004, 40
ARITHMETIC = {Operation.ADD_WRAP: lambda a, b: a + b, Operation.SUB_WRAP: lambda a, b: a - b, Operation.MUL_WRAP: lambda a, b: a * b}
API = posix_android_api()


class _Cells:
    """Typed declarations for ``width``-bit heap cells."""

    def __init__(self, width: int):
        size = width // 8
        self.kind = bits_type(width)
        self.size = size
        self.view = heap_view_type(size, initialized=False)
        self.pointer = pointer_type(self.kind, Permission.READ_WRITE, size, space=2)
        self.free = foreign_function_symbol(b"libc.so", b"free", (self.pointer, self.view, API.memory_effect), (API.memory_effect,), deallocator=ForeignDeallocatorContract(0, 1))
        self.objects = (self.kind, self.view, self.pointer, self.free)


def _program(rng: random.Random, cells: _Cells, width: int):
    """One program and the result it must return for each argument pair."""
    mask = (1 << width) - 1
    graph = GraphBuilder()
    block = graph.block(cells.kind, cells.kind, API.process_effect, API.memory_effect)
    a, b, process, memory = block.params
    script = []  # mirror: ("store", source) / ("load",) / ("op", operation, left, right)
    values = [a, b]
    # Each phase allocates one cell, uses it, and frees it; values carry over.  (A
    # heap view's memory effect carries its storage, so one effect chain serves one
    # live view at a time.)
    for _phase in range(rng.randrange(1, 4)):
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(API.b64, cells.size), memory), (API.byte_ptr_rw, API.heap_resource, API.memory_effect), entity=API.malloc)
        pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (cells.pointer, cells.view, API.memory_effect), attributes=(cells.size, cells.size))
        source = rng.randrange(len(values))
        memory = block.op1(Operation.STORE_BITS_LE, (pointer, values[source], memory), API.memory_effect, attributes=(cells.size, cells.size))
        script.append(("store", source))
        for _ in range(rng.randrange(2, 9)):
            choice = rng.random()
            if choice < 0.35:
                loaded, memory = block.op(Operation.LOAD_BITS_LE, (pointer, memory), (cells.kind, API.memory_effect), attributes=(cells.size, cells.size))
                script.append(("load",))
                values.append(loaded)
            elif choice < 0.55:
                source = rng.randrange(len(values))
                memory = block.op1(Operation.STORE_BITS_LE, (pointer, values[source], memory), API.memory_effect, attributes=(cells.size, cells.size))
                script.append(("store", source))
            elif choice < 0.7:
                # A foreign call with the pointer and values still live: they cross caller-saved registers.
                _pid, process = block.op(Operation.CALL_FOREIGN, (process,), (API.b32, API.process_effect), entity=API.getpid)
            else:
                operation = rng.choice(tuple(ARITHMETIC))
                left, right = rng.randrange(len(values)), rng.randrange(len(values))
                values.append(block.op1(operation, (values[left], values[right]), cells.kind))
                script.append(("op", operation, left, right))
        loaded, memory = block.op(Operation.LOAD_BITS_LE, (pointer, memory), (cells.kind, API.memory_effect), attributes=(cells.size, cells.size))
        script.append(("load",))
        values.append(loaded)
        memory = block.op1(Operation.CALL_FOREIGN, (pointer, view, memory), API.memory_effect, entity=cells.free)
    block.ret(values[-1], process, memory)

    def expected(x: int, y: int) -> int:
        mirror, cell = [x & mask, y & mask], None
        for step in script:
            if step[0] == "store":
                cell = mirror[step[1]]
            elif step[0] == "load":
                mirror.append(cell)
            else:
                mirror.append(ARITHMETIC[step[1]](mirror[step[2]], mirror[step[3]]) & mask)
        return mirror[-1]

    return graph, graph.function(block.parameter_types, (cells.kind, API.process_effect, API.memory_effect)), expected


def corpus():
    rng = random.Random(SEED)
    target = android_arm64_shared_general_target(packed=True)
    functions, objects, oracles, widths = [], list(API.types) + [API.malloc, API.getpid], [], []
    for width in (64, 32):
        cells = _Cells(width)
        objects.extend(cells.objects)
        for _ in range(COUNT // 2):
            graph, function, expected = _program(rng, cells, width)
            functions.append(function)
            objects.extend(graph.objects.values())
            oracles.append(expected)
            widths.append(width)
    reader = _reader(tuple(functions), tuple(objects), target)
    return reader, target, functions, oracles, widths


class AArch64HeapRegisterPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader, cls.target, cls.functions, cls.oracles, cls.widths = corpus()

    def test_corpus_takes_the_register_path(self):
        resolve = store_resolver(self.reader)
        for function in self.functions:
            graph_object, parameters, returns = _decode_function_interface(function, resolve)
            self.assertTrue(_register_path_eligible(_parse_graph(graph_object, resolve), parameters, returns, resolve))

    @unittest.skipUnless(bionic.QEMU and (bionic.ROOT / "system/bin/linker64").exists() and bionic.JNI_H.exists(), "requires the NDK, qemu-aarch64, and an Android bionic root")
    def test_results_match_the_mirror(self):
        exports = tuple(AndroidExport(f"f{index}".encode(), function.cid) for index, function in enumerate(self.functions))
        library = compile_android_shared(self.reader, exports, target_object=self.target).data
        rng = random.Random(SEED + 1)
        cases = [(index, rng.getrandbits(width), rng.getrandbits(width)) for index, width in enumerate(self.widths) for _ in range(4)]
        lines = ["#include <dlfcn.h>", "#include <stdint.h>", "#include <stdio.h>", "int main(int argc, char **argv) {",
                 "  void *h = dlopen(argv[1], RTLD_NOW); if (!h) return 65;"]
        for index, a, b in cases:
            c_type = "uint64_t" if self.widths[index] == 64 else "uint32_t"
            lines.append(f'  {{ {c_type} (*f)({c_type}, {c_type}) = dlsym(h, "f{index}"); if (!f) return 66; '
                         f'printf("%d %llu\\n", {index}, (unsigned long long) f(({c_type}){a}ULL, ({c_type}){b}ULL)); }}')
        lines += ["  return 0;", "}"]
        expected = [f"{index} {self.oracles[index](a, b)}" for index, a, b in cases]
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
