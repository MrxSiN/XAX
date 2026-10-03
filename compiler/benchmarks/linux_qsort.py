"""OI-42 closure workload: glibc ``qsort_r`` sorts an XAX-owned array with an XAX comparator (ADR-115).

The program maps one anonymous 128-byte view (16 u64 elements), fills it,
and calls ``qsort_r(base, 16, 8, compare, arg)`` with ``arg`` = the same view.
``compare`` is a *lend entry*: C calls it with two element addresses and the
context, the compiler-generated SysV adapter maps them, and the comparator
rebases each address into the lent view (``pointer_rebase``: out-of-view or
misaligned addresses trap), loads both elements, and returns -1/0/1.  The
view, its token, and the memory effect come from the ``qsort_r`` call itself,
so the borrow ends when ``qsort_r`` returns.  Afterwards XAX reads the array
back and exits with ``sum((i + 1) * a[i]) mod 256``, which depends on the
order.

Run ``python -m benchmarks.linux_qsort`` from ``compiler/`` to regenerate
``linux_qsort_evidence.json``.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path

from xax_compiler import (
    IntCompare,
    Operation,
    Permission,
    bits_type,
    heap_view_type,
    lend_entry_code_type,
    lend_entry_pointer_type,
    pointer_type,
    x86_64_linux_dynamic_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import c_function, compile_linux_executable, linux_api, run_linux_executable

EVIDENCE = Path(__file__).resolve().parent / "linux_qsort_evidence.json"
B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
VALUES = (907, 12, 455, 3, 3000, 77, 512, 1, 64, 999, 250, 18, 7, 2048, 33, 600)
COUNT = len(VALUES)
EXTENT = 8 * COUNT
ELEMENTS_RW = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
ELEMENTS_READ = pointer_type(B64, Permission.READ, 8, space=2)
VIEW = heap_view_type(EXTENT)
STATUS = sum((index + 1) * value for index, value in enumerate(sorted(VALUES))) % 256


def compare_entry(*, permission_view=ELEMENTS_READ, store: bool = False, descending: bool = False):
    """``compare(a, b, view...) -> ((*a > *b) - (*a < *b), view...)`` reading the lent view."""
    mem = linux_api().memory_effect
    graph = GraphBuilder()
    block = graph.block(B64, B64, permission_view, VIEW, mem)
    a, b, view, token, memory = block.params
    left_pointer = block.op1(Operation.POINTER_REBASE, (view, a), ELEMENTS_READ if permission_view is ELEMENTS_READ else permission_view, attributes=(8,))
    right_pointer = block.op1(Operation.POINTER_REBASE, (view, b), ELEMENTS_READ if permission_view is ELEMENTS_READ else permission_view, attributes=(8,))
    if store:
        memory = block.op1(Operation.STORE_BITS_LE, (left_pointer, block.const(B64, 0), memory), mem, attributes=(8, 8))
    left, memory = block.op(Operation.LOAD_BITS_LE, (left_pointer, memory), (B64, mem), attributes=(8, 8))
    right, memory = block.op(Operation.LOAD_BITS_LE, (right_pointer, memory), (B64, mem), attributes=(8, 8))
    first, second = (right, left) if descending else (left, right)
    greater = block.op1(Operation.INT_COMPARE, (first, second), B1, attributes=(IntCompare.UGT,))
    less = block.op1(Operation.INT_COMPARE, (first, second), B1, attributes=(IntCompare.ULT,))
    widen = lambda flag: block.op1(Operation.INT_ZERO_EXTEND, (flag,), B32)
    block.ret(block.op1(Operation.SUB_WRAP, (widen(greater), widen(less)), B32), view, token, memory)
    triple = (permission_view, VIEW, mem)
    return graph.function((B64, B64, *triple), (B32, *triple)), graph


def qsort_r_declaration(entry_type):
    api = linux_api()
    return c_function(b"libc.so.6", b"qsort_r", (ELEMENTS_RW, B64, B64, entry_type, ELEMENTS_RW, api.memory_effect), (api.memory_effect,))


def sort_program(*, comparator=None, entry_type=None, declaration=None, pass_memory=True, extra=()):
    api = linux_api()
    mem = api.memory_effect
    entry_type = entry_type or lend_entry_pointer_type(ELEMENTS_READ, VIEW)
    if comparator is None:
        comparator, comparator_graph = compare_entry()
        comparator_objects = tuple(comparator_graph.objects.values())
    else:
        comparator, comparator_objects = comparator
    declaration = declaration or qsort_r_declaration(entry_type)
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, EXTENT), memory), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
    base, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (ELEMENTS_RW, VIEW, mem), attributes=(EXTENT, 8))
    elements = [base] + [block.op1(Operation.ADDRESS_OFFSET, (base,), ELEMENTS_RW, attributes=(8 * index,)) for index in range(1, COUNT)]
    for element, value in zip(elements, VALUES):
        memory = block.op1(Operation.STORE_BITS_LE, (element, block.const(B64, value), memory), mem, attributes=(8, 8))
    entry = block.op1(Operation.FUNCTION_ADDRESS, (), entry_type, entity=comparator)
    if pass_memory:
        (memory,) = block.op(Operation.CALL_FOREIGN, (base, block.const(B64, COUNT), block.const(B64, 8), entry, base, memory), (mem,), entity=declaration)
    else:
        block.op(Operation.CALL_FOREIGN, (base, block.const(B64, COUNT), block.const(B64, 8), entry), (), entity=declaration)
    total = block.const(B64, 0)
    for index, element in enumerate(elements):
        value, memory = block.op(Operation.LOAD_BITS_LE, (element, memory), (B64, mem), attributes=(8, 8))
        total = block.op1(Operation.ADD_WRAP, (total, block.op1(Operation.MUL_WRAP, (value, block.const(B64, index + 1)), B64)), B64)
    status = block.op1(Operation.INT_TRUNCATE, (block.op1(Operation.BIT_AND, (total, block.const(B64, 255)), B64),), B32)
    _unmapped, memory = block.op(Operation.CALL_FOREIGN, (base, token, memory), (B64, mem), entity=api.munmap_view(ELEMENTS_RW, EXTENT))
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (B32, api.process_effect, api.filesystem_effect, mem))
    target = x86_64_linux_dynamic_exec_target()
    code = lend_entry_code_type(ELEMENTS_READ, VIEW)
    reader = program_store(function, target, (*api.types, *extra, ELEMENTS_RW, ELEMENTS_READ, VIEW, entry_type, code, *comparator_objects, comparator, declaration, *graph.objects.values()))
    return reader, function, target


def evidence() -> dict:
    reader, function, target = sort_program()
    executable = compile_linux_executable(reader, function.cid, target.cid)
    completed = run_linux_executable(executable.data)
    if completed.returncode != STATUS:
        raise AssertionError(f"exit {completed.returncode}, expected {STATUS}: {completed.stderr!r}")
    return {
        "format": "xax-linux-qsort-evidence-v1",
        "label": "EXECUTED",
        "host": {"system": platform.system(), "machine": platform.machine(), "libc": " ".join(platform.libc_ver())},
        "program_root": reader.root_cid.hex(),
        "executable_bytes": len(executable.data),
        "executable_sha256": hashlib.sha256(executable.data).hexdigest(),
        "needed": [item.decode() for item in executable.needed],
        "input": list(VALUES),
        "expected_status": STATUS,
        "exit_status": completed.returncode,
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
