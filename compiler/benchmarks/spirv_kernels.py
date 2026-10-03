"""ADR-124 kernels: ordinary XAX functions under the ``spirv-compute-v1`` entry contract.

Python here is only the construction tool (:mod:`xax_graph_builder`).  Each
builder returns ``(reader, kernel, target)`` for a verified program rooted at
the kernel and the ``spirv-vulkan-compute-v1`` target package.

Run ``python -m benchmarks.spirv_kernels --write`` to regenerate
``spirv_compute_evidence.json``: every kernel validated by ``spirv-val``,
executed on the first Vulkan device, and compared with the reference
executor; Collatz also against an equivalent GLSL kernel compiled by
glslang.  The device here is llvmpipe (a CPU implementation), so times are
not GPU performance evidence (conformance §23.17).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Operation,
    Permission,
    bits_type,
    heap_view_type,
    memory_effect_type,
    pointer_type,
    spirv_vulkan_compute_target,
)
from xax_graph_builder import GraphBuilder, program_store

B1, B8, B32 = bits_type(1), bits_type(8), bits_type(32)
MEM = memory_effect_type()
HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "spirv_compute_evidence.json"


def binding(elements: int, writable: bool = True):
    return (pointer_type(B32, Permission.READ_WRITE if writable else Permission.READ, 4, space=2), heap_view_type(4 * elements), MEM)


def _finish(graph: GraphBuilder, triples):
    flat = tuple(item for triple in triples for item in triple)
    kernel = graph.function((B32, *flat), flat)
    target = spirv_vulkan_compute_target()
    return program_store(kernel, target, tuple(graph.objects.values())), kernel, target


def collatz_kernel(elements: int):
    """``data[i] = steps(data[i])``: the number of Collatz steps to reach 1."""
    triple = binding(elements)
    graph = GraphBuilder()
    entry = graph.block(B32, *triple)
    invocation, pointer, view, memory = entry.params
    own = entry.op1(Operation.MUL_WRAP, (invocation, entry.const(B32, 4)), B32)
    value, memory = entry.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, own, memory), (B32, MEM), attributes=(4, 1))
    loop = graph.block(B32, B32, *triple)
    body = graph.block(B32, B32, *triple)
    done = graph.block(B32, *triple)
    entry.br(loop, value, entry.const(B32, 0), pointer, view, memory)
    x, steps, lp, lv, lm = loop.params
    loop.cbr(loop.op1(Operation.INT_COMPARE, (x, loop.const(B32, 1)), B1, attributes=(IntCompare.UGT,)), body, (x, steps, lp, lv, lm), done, (steps, lp, lv, lm))
    x, steps, bp, bv, bm = body.params
    odd = body.op1(Operation.INT_ZERO_EXTEND, (body.op1(Operation.INT_COMPARE, (body.op1(Operation.BIT_AND, (x, body.const(B32, 1)), B32), body.const(B32, 0)), B1, attributes=(IntCompare.NE,)),), B32)
    half = body.op1(Operation.UDIV, (x, body.const(B32, 2)), B32)
    triple_plus_one = body.op1(Operation.ADD_WRAP, (body.op1(Operation.MUL_WRAP, (x, body.const(B32, 3)), B32), body.const(B32, 1)), B32)
    following = body.op1(Operation.ADD_WRAP, (half, body.op1(Operation.MUL_WRAP, (odd, body.op1(Operation.SUB_WRAP, (triple_plus_one, half), B32)), B32)), B32)
    body.br(loop, following, body.op1(Operation.ADD_WRAP, (steps, body.const(B32, 1)), B32), bp, bv, bm)
    steps, dp, dv, dm = done.params
    dm = done.op1(Operation.CHECKED_STORE_BITS_LE, (dp, own, steps, dm), MEM, attributes=(4, 1))
    done.ret(dp, dv, dm)
    return _finish(graph, (triple,))


def mix_kernel(elements: int, *, divide: bool = True, extra_offset: int = 0):
    """``out[i] = f(src[i], src[(7i) mod n])`` over every lowered operation and compare kind.

    ``divide`` adds ``a / b`` (traps for invocations whose ``b`` is zero);
    ``extra_offset`` shifts the second read so high invocations read past the
    source view (a bounds-check trap).
    """
    source, out = binding(elements, writable=False), binding(elements)
    graph = GraphBuilder()
    block = graph.block(B32, *source, *out)
    invocation, sp, sv, sm, op_, ov, om = block.params
    c = lambda value, type_=B32: block.const(type_, value)
    own = block.op1(Operation.MUL_WRAP, (invocation, c(4)), B32)
    a, sm = block.op(Operation.CHECKED_LOAD_BITS_LE, (sp, own, sm), (B32, MEM), attributes=(4, 1))
    other = block.op1(Operation.UREM, (block.op1(Operation.MUL_WRAP, (invocation, c(7)), B32), c(elements)), B32)
    other = block.op1(Operation.ADD_WRAP, (block.op1(Operation.MUL_WRAP, (other, c(4)), B32), c(extra_offset)), B32)
    b, sm = block.op(Operation.CHECKED_LOAD_BITS_LE, (sp, other, sm), (B32, MEM), attributes=(4, 1))
    terms = [
        block.op1(Operation.ADD_WRAP, (a, b), B32), block.op1(Operation.SUB_WRAP, (a, b), B32), block.op1(Operation.MUL_WRAP, (a, b), B32),
        block.op1(Operation.BIT_AND, (a, b), B32), block.op1(Operation.BIT_OR, (a, b), B32), block.op1(Operation.BIT_XOR, (a, b), B32),
        block.op1(Operation.ROTATE_RIGHT, (a,), B32, attributes=(7,)), block.op1(Operation.UREM, (a, c(1000)), B32),
    ]
    if divide:
        terms.append(block.op1(Operation.UDIV, (a, b), B32))
    for kind in IntCompare:
        terms.append(block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, (a, b), B1, attributes=(kind,)),), B32))
    narrow_a, narrow_b = (block.op1(Operation.INT_TRUNCATE, (value,), B8) for value in (a, b))
    for kind in (IntCompare.SLT, IntCompare.UGT):
        terms.append(block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, (narrow_a, narrow_b), B1, attributes=(kind,)),), B32))
    terms.append(block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.MUL_WRAP, (narrow_a, narrow_b), B8),), B32))
    terms.append(block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.ROTATE_RIGHT, (narrow_a,), B8, attributes=(3,)),), B32))
    accumulator = c(0x9E3779B9)
    for term in terms:
        accumulator = block.op1(Operation.ADD_WRAP, (block.op1(Operation.ROTATE_RIGHT, (accumulator,), B32, attributes=(5,)), term), B32)
    om = block.op1(Operation.CHECKED_STORE_BITS_LE, (op_, own, accumulator, om), MEM, attributes=(4, 1))
    block.ret(sp, sv, sm, op_, ov, om)
    return _finish(graph, (source, out))


def trap_kernel(elements: int, poison: int = 13):
    """``data[i] = 1000000 / (data[i] - poison)``: invocations holding ``poison`` trap.

    An explicit ``trap`` terminator cannot end a path that still holds the
    borrowed view (a linear resource), so the trap here is the node-level
    divide-by-zero check.
    """
    triple = binding(elements)
    graph = GraphBuilder()
    block = graph.block(B32, *triple)
    invocation, pointer, view, memory = block.params
    own = block.op1(Operation.MUL_WRAP, (invocation, block.const(B32, 4)), B32)
    value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, own, memory), (B32, MEM), attributes=(4, 1))
    divisor = block.op1(Operation.SUB_WRAP, (value, block.const(B32, poison)), B32)
    quotient = block.op1(Operation.UDIV, (block.const(B32, 1_000_000), divisor), B32)
    memory = block.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, own, quotient, memory), MEM, attributes=(4, 1))
    block.ret(pointer, view, memory)
    return _finish(graph, (triple,))


def words(values) -> bytes:
    return struct.pack(f"<{len(values)}I", *values)


GLSL_COLLATZ = """#version 450
layout(local_size_x = 64) in;
layout(std430, binding = 0) buffer Data { uint data[]; };
layout(push_constant) uniform Launch { uint count; };
void main() {
    uint i = gl_GlobalInvocationID.x;
    if (i >= count) return;
    uint x = data[i], steps = 0u;
    while (x > 1u) { x = (x & 1u) != 0u ? 3u * x + 1u : x / 2u; steps++; }
    data[i] = steps;
}
"""


def run_evidence(elements: int, repetitions: int) -> dict:
    from xax_spirv import compile_spirv_kernel, reference_dispatch, run_spirv_kernel

    rng = random.Random(124)
    results = {}
    cases = {
        "collatz": (collatz_kernel(256), [words([rng.randrange(1, 100_000) for _ in range(256)])], 256),
        "mix": (mix_kernel(256), [words([rng.randrange(0, 4) if index % 9 == 0 else rng.getrandbits(32) for index in range(256)]), bytes(1024)], 256),
        "mix_bounds": (mix_kernel(64, divide=False, extra_offset=128), [words([rng.getrandbits(32) for _ in range(64)]), bytes(256)], 64),
        "trap": (trap_kernel(64), [words([13 if index in (5, 40) else index for index in range(64)])], 64),
    }
    for name, ((reader, kernel, target), buffers, count) in cases.items():
        compiled = compile_spirv_kernel(reader, kernel.cid, target.cid)
        with tempfile.NamedTemporaryFile(suffix=".spv") as handle:
            handle.write(compiled.module)
            handle.flush()
            validation = subprocess.run(["spirv-val", "--target-env", "vulkan1.1", handle.name], capture_output=True, text=True)
        launch = run_spirv_kernel(compiled, buffers, count)
        expected = reference_dispatch(reader, kernel.cid, buffers, count)
        results[name] = {
            "module_bytes": len(compiled.module),
            "module_sha256": hashlib.sha256(compiled.module).hexdigest(),
            "kernel": kernel.cid.hex(),
            "spirv_val": "pass" if validation.returncode == 0 else validation.stdout + validation.stderr,
            "invocations": count,
            "status": hex(launch.status),
            "matches_reference_executor": (launch.buffers, launch.status) == expected,
            "output_sha256": [hashlib.sha256(item).hexdigest() for item in launch.buffers],
        }
    # Collatz at scale against an equivalent GLSL kernel on the same device.
    reader, kernel, target = collatz_kernel(elements)
    xax = compile_spirv_kernel(reader, kernel.cid, target.cid)
    data = words([rng.randrange(1, 1_000_000) for _ in range(elements)])
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory, "collatz.comp")
        source.write_text(GLSL_COLLATZ)
        spirv = Path(directory, "collatz.spv")
        subprocess.run(["glslangValidator", "-V", "--target-env", "vulkan1.1", str(source), "-o", str(spirv)], check=True, capture_output=True)
        glsl_module = spirv.read_bytes()
        glslang = subprocess.run(["glslangValidator", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    from xax_spirv import SpirvKernel

    glsl = SpirvKernel(glsl_module, xax.bindings, xax.local_size, b"", b"")
    timings = {}
    outputs = {}
    for arm, compiled in (("xax", xax), ("glslang", glsl)):
        samples = []
        for _ in range(repetitions):
            launch = run_spirv_kernel(compiled, [data], elements)
            samples.append(launch.seconds)
            outputs[arm] = launch.buffers[0]
        timings[arm] = {"module_bytes": len(compiled.module), "dispatch_seconds_median": round(statistics.median(samples), 6)}
    if outputs["xax"] != outputs["glslang"]:
        raise AssertionError("XAX and GLSL Collatz outputs differ")
    return {
        "format": "xax-spirv-compute-evidence-v1",
        "evidence_label": "EXECUTED (outputs equal the reference executor); MEASURED-SOFTWARE-DEVICE (times)",
        "device": launch.device,
        "driver_version": launch.driver,
        "kernels": results,
        "collatz_twin": {
            "elements": elements,
            "repetitions": repetitions,
            "outputs_equal": True,
            "arms": timings,
            "ratio_xax_over_glslang": {
                "module_bytes": round(timings["xax"]["module_bytes"] / timings["glslang"]["module_bytes"], 3),
                "dispatch_seconds_median": round(timings["xax"]["dispatch_seconds_median"] / timings["glslang"]["dispatch_seconds_median"], 3),
            },
            "glslang": glslang,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elements", type=int, default=1 << 18)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)
    if not shutil.which("spirv-val") or not shutil.which("glslangValidator"):
        raise SystemExit("needs spirv-val and glslangValidator")
    text = json.dumps(run_evidence(arguments.elements, arguments.repetitions), indent=2, sort_keys=True) + "\n"
    if arguments.write:
        EVIDENCE.write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
