"""S15e.7b (ADR-321): SPIR-V compute kernels for the differential tests of the XAX general program.

``spirv_case(rng)`` gives ``(reader, kernel, target, name)``: the benchmark kernels with random parameters, random
straight-line and branching kernels over every lowered operation (narrow widths, compares, rotations, divisions,
loops that carry the binding pointers through block parameters), and kernels each lowering rule rejects: a wide value
(``SPIRV-VALUE``), a 2-byte access (``SPIRV-ACCESS-WIDTH``), a pointer joined from two bindings
(``SPIRV-POINTER-STATIC``), a misaligned offset (``SPIRV-POINTER-ALIGNED``), a race (``SPIRV-KERNEL-OWN-ELEMENT``), an
operation the target does not list, and entry contracts it does not meet.
"""

from __future__ import annotations

import random

from xax_compiler import FloatFormat, IntCompare, Operation, bits_type, float_constant, float_type, spirv_vulkan_compute_target
from xax_graph_builder import GraphBuilder, program_store

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.spirv_kernels import B1, B8, B32, MEM, binding, collatz_kernel, mix_kernel, trap_kernel  # noqa: E402

B16, B64 = bits_type(16), bits_type(64)
BINARY = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR, Operation.BIT_XOR)


def _finish(graph, triples, parameters=None):
    flat = tuple(item for triple in triples for item in triple)
    kernel = graph.function(parameters or (B32, *flat), flat)
    spirv = spirv_vulkan_compute_target()
    return program_store(kernel, spirv, tuple(graph.objects.values())), kernel, spirv


def _random_kernel(rng: random.Random, fault: str | None):
    """``out[i] = f(src[i], src[j])`` with random operations, maybe a loop, maybe a fault."""
    source, out = binding(16, writable=fault == "join" or rng.random() < 0.7), binding(16)
    graph = GraphBuilder()
    entry = graph.block(B32, *source, *out)
    invocation, sp, sv, sm, op_, ov, om = entry.params
    own = entry.op1(Operation.MUL_WRAP, (invocation, entry.const(B32, 4)) if rng.random() < 0.8 else (entry.const(B32, 4), invocation), B32)
    if fault == "width":
        narrow, sm = entry.op(Operation.CHECKED_LOAD_BITS_LE, (sp, own, sm), (B16, MEM), attributes=(2, 1))
        a = entry.op1(Operation.INT_ZERO_EXTEND, (narrow,), B32)
    else:
        a, sm = entry.op(Operation.CHECKED_LOAD_BITS_LE, (sp, own, sm), (B32, MEM), attributes=(4, 1))
    values = [a, invocation]
    for _ in range(rng.randrange(2, 9)):
        kind = rng.randrange(8)
        x, y = rng.choice(values), rng.choice(values)
        if kind < 3:
            values.append(entry.op1(rng.choice(BINARY), (x, y), B32))
        elif kind == 3:
            values.append(entry.op1(Operation.INT_ZERO_EXTEND, (entry.op1(Operation.INT_COMPARE, (x, y), B1, attributes=(rng.choice(list(IntCompare)),)),), B32))
        elif kind == 4:
            narrow = rng.choice((B8, B16))
            nx, ny = (entry.op1(Operation.INT_TRUNCATE, (value,), narrow) for value in (x, y))
            nz = entry.op1(rng.choice((*BINARY, Operation.UDIV, Operation.UREM)), (nx, ny), narrow) if rng.random() < 0.5 else entry.op1(
                Operation.INT_ZERO_EXTEND, (entry.op1(Operation.INT_COMPARE, (nx, ny), B1, attributes=(rng.choice(list(IntCompare)),)),), narrow)
            values.append(entry.op1(Operation.INT_ZERO_EXTEND, (nz,), B32))
        elif kind == 5:
            values.append(entry.op1(Operation.ROTATE_RIGHT, (x,), B32, attributes=(rng.randrange(32),)))
        elif kind == 6:
            divisor = entry.const(B32, rng.choice((0, 1, 3, 7))) if rng.random() < 0.5 else y
            values.append(entry.op1(rng.choice((Operation.UDIV, Operation.UREM)), (x, divisor), B32))
        else:
            values.append(entry.const(B32, rng.randrange(1 << 32)))
    result = values[-1]
    if fault == "wide":
        entry.op1(Operation.INT_ZERO_EXTEND, (result,), B64)
    if rng.random() < 0.4 or fault in ("join", "misaligned"):
        # A loop carrying the pointers: ``count`` rounds of ``r = r * 3 + 1``.
        loop = graph.block(B32, B32, *source, *out)
        done = graph.block(B32, *source, *out)
        entry.br(loop, result, entry.const(B32, rng.randrange(1, 4)), sp, sv, sm, op_, ov, om)
        r, n, lsp, lsv, lsm, lop, lov, lom = loop.params
        more = loop.op1(Operation.INT_COMPARE, (n, loop.const(B32, 0)), B1, attributes=(IntCompare.NE,))
        following = loop.op1(Operation.ADD_WRAP, (loop.op1(Operation.MUL_WRAP, (r, loop.const(B32, 3)), B32), loop.const(B32, 1)), B32)
        step = loop.op1(Operation.SUB_WRAP, (n, loop.const(B32, 1)), B32)
        # Each side keeps the binding pointers whole; a ``join`` sends the source pointer where the output's goes.
        target_pointer = lsp if fault == "join" else lop
        loop.cbr(more, loop, (following, step, lsp, lsv, lsm, lop, lov, lom), done, (r, lsp, lsv, lsm, target_pointer, lov, lom))
        result, sp, sv, sm, op_, ov, om = done.params
        block = done
    else:
        block = entry
    pointer = op_
    if fault == "misaligned":
        pointer = block.op1(Operation.ADDRESS_OFFSET, (op_,), out_pointer(), attributes=(rng.choice((2, 6)),))
    index = own if fault != "race" else block.const(B32, 0)
    om = block.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, index, result, om), MEM, attributes=(4, 1))
    block.ret(sp, sv, sm, op_, ov, om)
    return _finish(graph, (source, out))


def out_pointer():
    return binding(16)[0]


def _contract(rng: random.Random):
    """An entry contract ``_kernel_interface`` rejects."""
    triple = binding(16)
    graph = GraphBuilder()
    graph.track(B32)
    choice = rng.randrange(3)
    if choice == 0:  # no invocation index
        block = graph.block(*triple)
        block.ret(*block.params)
        return _finish(graph, (triple,), parameters=triple)
    if choice == 1:  # a wide invocation index
        block = graph.block(B64, *triple)
        block.ret(*block.params[1:])
        return _finish(graph, (triple,), parameters=(B64, *triple))
    block = graph.block(B32, *triple, B32)  # a parameter after the triples
    block.ret(*block.params[1:4])
    kernel = graph.function((B32, *triple, B32), triple)
    spirv = spirv_vulkan_compute_target()
    return program_store(kernel, spirv, tuple(graph.objects.values())), kernel, spirv


def _float(rng: random.Random):
    f32 = float_type(FloatFormat.BINARY32)
    triple = binding(16)
    graph = GraphBuilder()
    block = graph.block(B32, *triple)
    constant = block.op1(Operation.CONSTANT, (), f32, entity=float_constant(f32, 1.5))
    block.op1(Operation.FLOAT_ADD, (constant, constant), f32)
    block.ret(*block.params[1:])
    return _finish(graph, (triple,))


def spirv_case(rng: random.Random):
    """``(reader, kernel, target, name)``."""
    from xax_compiler import XaxError

    while True:
        name = rng.choice(("collatz", "mix", "trap", "random", "random", "random", "wide", "width", "join", "misaligned", "race",
                           "contract", "float"))
        try:
            if name == "collatz":
                built = collatz_kernel(rng.choice((4, 16, 64)))
            elif name == "mix":
                built = mix_kernel(rng.choice((8, 64)), divide=rng.random() < 0.5, extra_offset=rng.choice((0, 4, 256)))
            elif name == "trap":
                built = trap_kernel(rng.choice((8, 64)), poison=rng.randrange(100))
            elif name == "contract":
                built = _contract(rng)
            elif name == "float":
                built = _float(rng)
            else:
                built = _random_kernel(rng, None if name == "random" else name)
        except (XaxError, ValueError, KeyError, AttributeError):
            continue
        return (*built, name)
