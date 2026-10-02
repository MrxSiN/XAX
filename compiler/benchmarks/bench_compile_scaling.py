"""Compiler-latency scaling smoke: one straight-line function of N wrapping adds.

Measures canonical store write, store parse, verification, and x86-64/AArch64
lowering separately.  Prints median/min milliseconds over repeats.
Usage: python -m benchmarks.bench_compile_scaling [N ...]
"""

from __future__ import annotations

import statistics
import sys
import time

import xax_compiler

from xax_compiler import (
    Block, Kind, Node, Operation, StoreReader, Terminator, ValueRef,
    aarch64_baremetal_target, bits_type, function, graph_fragment,
    object_with_refs, verify_store, write_store, x86_64_windows_general_target,
)
from xax_aarch64 import compile_aarch64
from xax_x86_64 import compile_native


def program(n: int, target):
    b32 = bits_type(32)
    nodes = [Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,))]
    for i in range(1, n):
        op = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP)[i % 3]
        nodes.append(Node(op, (ValueRef.node_result(0, i - 1), ValueRef.parameter(0, i & 1)), (b32,)))
    graph = graph_fragment([Block((b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, n - 1),)))])
    fn = function(graph, (b32, b32), (b32,))
    module = object_with_refs(Kind.MODULE, [fn, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return fn, root, [b32, graph, fn, target, module, root]


def timed(fn, repeats):
    samples = []
    for _ in range(repeats):
        getattr(xax_compiler, "_PARSED_GRAPHS", {}).clear()  # cold: no cross-sample graph reuse
        start = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - start) * 1e3)
    return result, samples


def main(argv):
    sizes = [int(arg) for arg in argv] or [10, 100, 1000]
    for n in sizes:
        repeats = 7 if n <= 1000 else 3
        for name, target, lower in (
            ("x86_64", x86_64_windows_general_target(), compile_native),
            ("aarch64", aarch64_baremetal_target(), compile_aarch64),
        ):
            fn, root, objects = program(n, target)
            data, w = timed(lambda: write_store(root.cid, objects), repeats)
            reader, r = timed(lambda: StoreReader(data), repeats)
            _, v = timed(lambda: verify_store(StoreReader(data)), repeats)
            image, l = timed(lambda: lower(StoreReader(data), fn.cid, target.cid), repeats)
            code = getattr(image, "code", b"")
            print(
                f"n={n:6d} {name:7s} write={statistics.median(w):8.2f} parse={statistics.median(r):8.2f} "
                f"verify={statistics.median(v):8.2f} lower(total)={statistics.median(l):8.2f} ms  code={len(code)}B"
            )


if __name__ == "__main__":
    main(sys.argv[1:])
