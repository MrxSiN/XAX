"""OI-40 closure workload: C callbacks into XAX and SSE-class C arguments (ADR-102).

Two ordinary XAX programs for the ``x86_64-linux-elf-dynexec-v1`` profile:

* ``callback``: inserts the keys 7, 3, 9, 3, 12 into a libc binary search tree
  with ``tsearch`` and probes 1..12 with ``tfind``.  Both calls receive the
  address of an XAX comparator through a ``sysv-x86_64-c`` entry type, so libc
  calls back into XAX through the compiler-generated adapter.  Keys are passed
  as pointer-sized integers (the comparator never dereferences them).  The
  status is the sum of the found keys: 3 + 7 + 9 + 12 = 31.  A comparator that
  received wrong arguments or results would build a different tree.
* ``float``: ``ldexp(3.0, 3)`` (SSE + INTEGER arguments), ``pow(x, 2.0)``
  (two SSE arguments, SSE result), and ``sqrtf(16.0f)`` (binary32), all from
  the system ``libm.so.6``; status ``576 + 4 - 512 = 68``.

The foreign declarations are explicit contracts.  ``tsearch``/``tfind`` read
and write the tree root through the passed heap pointer (memory effect); libc
allocates its own tree nodes with its own allocator.  The libm calls are
declared pure for these finite, in-range inputs.

Run ``python -m benchmarks.linux_c_interop`` from ``compiler/`` to regenerate
``linux_c_interop_evidence.json``.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path

from xax_compiler import FloatFormat, IntCompare, Operation, bits_type, float_type, heap_view_type, x86_64_linux_dynamic_exec_target
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import LinuxExecutable, c_function, compile_linux_executable, linux_api, run_linux_executable

EVIDENCE = Path(__file__).resolve().parent / "linux_c_interop_evidence.json"
B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
INSERTED = (7, 3, 9, 3, 12)
PROBED = range(1, 13)
CALLBACK_STATUS = sum(set(INSERTED))
FLOAT_STATUS = 576 + 4 - 512


def comparator(graph: GraphBuilder):
    """``(a, b) -> (a > b) - (a < b)`` as a 32-bit C ``int``; pure, so C can call it."""
    block = graph.block(B64, B64)
    greater = block.op1(Operation.INT_COMPARE, block.params, B1, attributes=(IntCompare.UGT,))
    less = block.op1(Operation.INT_COMPARE, block.params, B1, attributes=(IntCompare.ULT,))
    widen = lambda flag: block.op1(Operation.INT_ZERO_EXTEND, (flag,), B32)
    block.ret(block.op1(Operation.SUB_WRAP, (widen(greater), widen(less)), B32))
    return graph.function((B64, B64), (B32,))


def callback_program():
    api = linux_api()
    callback = api.c_callback
    tsearch = c_function(b"libc.so.6", b"tsearch", (B64, api.bytes_rw, callback, api.memory_effect), (B64, api.memory_effect))
    tfind = c_function(b"libc.so.6", b"tfind", (B64, api.bytes_rw, callback, api.memory_effect), (B64, api.memory_effect))
    compare = GraphBuilder()
    compare_function = comparator(compare)
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
    process, fs, memory = block.params
    # The tree root is one zero-initialized pointer in an anonymous mapping.
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
    root, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(4096), api.memory_effect), attributes=(4096, 1))
    entry = block.op1(Operation.FUNCTION_ADDRESS, (), callback, entity=compare_function)
    for key in INSERTED:
        _node, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, key), root, entry, memory), (B64, api.memory_effect), entity=tsearch)
    status = block.const(B32, 0)
    for key in PROBED:
        node, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, key), root, entry, memory), (B64, api.memory_effect), entity=tfind)
        found = block.op1(Operation.INT_ZERO_EXTEND, (block.op1(Operation.INT_COMPARE, (node, block.const(B64, 0)), B1, attributes=(IntCompare.NE,)),), B32)
        status = block.op1(Operation.ADD_WRAP, (status, block.op1(Operation.MUL_WRAP, (found, block.const(B32, key)), B32)), B32)
    _unmapped, memory = block.op(Operation.CALL_FOREIGN, (root, view, memory), (B64, api.memory_effect), entity=api.munmap_view(api.bytes_rw, 4096))
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, api.memory_effect), (B32, api.process_effect, api.filesystem_effect, api.memory_effect))
    target = x86_64_linux_dynamic_exec_target()
    reader = program_store(function, target, (*api.types, *compare.objects.values(), *graph.objects.values()))
    return reader, function, target, compare_function


def float_program():
    api = linux_api()
    ldexp = c_function(b"libm.so.6", b"ldexp", (F64, B32), (F64,))
    pow_ = c_function(b"libm.so.6", b"pow", (F64, F64), (F64,))
    sqrtf = c_function(b"libm.so.6", b"sqrtf", (F32,), (F32,))
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    as_float = lambda value, type_: block.op1(Operation.UINT_TO_FLOAT, (block.const(B32, value),), type_)
    scaled = block.op1(Operation.CALL_FOREIGN, (as_float(3, F64), block.const(B32, 3)), F64, entity=ldexp)
    squared = block.op1(Operation.CALL_FOREIGN, (scaled, as_float(2, F64)), F64, entity=pow_)
    root = block.op1(Operation.CALL_FOREIGN, (as_float(16, F32),), F32, entity=sqrtf)
    total = block.op1(Operation.ADD_WRAP, (
        block.op1(Operation.FLOAT_TO_UINT_TRUNC, (squared,), B32),
        block.op1(Operation.FLOAT_TO_UINT_TRUNC, (root,), B32),
    ), B32)
    status = block.op1(Operation.SUB_WRAP, (total, block.const(B32, 512)), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    function = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
    target = x86_64_linux_dynamic_exec_target()
    return program_store(function, target, (*api.types, *graph.objects.values())), function, target


def compile_programs() -> dict[str, LinuxExecutable]:
    callback_reader, callback_entry, callback_target, _compare = callback_program()
    float_reader, float_entry, float_target = float_program()
    return {
        "callback": compile_linux_executable(callback_reader, callback_entry.cid, callback_target.cid),
        "float": compile_linux_executable(float_reader, float_entry.cid, float_target.cid),
    }


def evidence() -> dict:
    executables = compile_programs()
    expected = {"callback": CALLBACK_STATUS, "float": FLOAT_STATUS}
    rows = {}
    for name, executable in executables.items():
        completed = run_linux_executable(executable.data)
        rows[name] = {
            "artifact_bytes": len(executable.data),
            "artifact_sha256": hashlib.sha256(executable.data).hexdigest(),
            "code_bytes": len(executable.image.code),
            "needed": [item.decode() for item in executable.needed],
            "expected_status": expected[name],
            "observed_status": completed.returncode,
            "passed": completed.returncode == expected[name],
        }
    return {
        "format": "xax-linux-c-interop-evidence-v1",
        "label": "EXECUTED",
        "decision": "ADR-102",
        "host": {"system": platform.system(), "machine": platform.machine(), "libc": " ".join(platform.libc_ver())},
        "programs": rows,
    }


def main() -> int:
    result = evidence()
    EVIDENCE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["programs"], indent=2, sort_keys=True))
    return 0 if all(row["passed"] for row in result["programs"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
