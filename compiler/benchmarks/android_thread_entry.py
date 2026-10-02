"""ADR-107 workload: bionic's pthread_create runs an XAX function on a new thread.

``xax_spawn_fib(pthread_t *thread, uint64_t n)`` passes the address of the XAX
function ``worker`` to ``pthread_create`` through the ``android-aapcs64-c``
entry type.  ``worker(n)`` computes ``fib(n)`` modulo 2**64 with a loop and
returns it as the thread result.  The address is the function itself: no
adapter code is emitted.  ``integration/android/thread_entry_loader.c``
spawns four such threads and joins them.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Operation, bits_type, android_arm64_shared_general_target
from xax_graph_builder import GraphBuilder, program_store
from xax_android import AndroidExport, compile_android_shared
from xax_platform import android_c_entry_api, posix_android_api

B1, B32, B64 = bits_type(1), bits_type(32), bits_type(64)


def worker(graph: GraphBuilder):
    """``fib(n)`` modulo 2**64; pure, so C may call it."""
    entry, test, step, done = graph.block(B64), graph.block(B64, B64, B64), graph.block(B64, B64, B64), graph.block(B64)
    n = entry.params[0]
    entry.br(test, entry.const(B64, 0), entry.const(B64, 0), entry.const(B64, 1))
    k, a, b = test.params
    test.cbr(test.op1(Operation.INT_COMPARE, (k, n), B1, attributes=(IntCompare.ULT,)), step, (k, a, b), done, (a,))
    k, a, b = step.params
    step.br(test, step.op1(Operation.ADD_WRAP, (k, step.const(B64, 1)), B64), b, step.op1(Operation.ADD_WRAP, (a, b), B64))
    done.ret(done.params[0])
    return graph.function((B64,), (B64,))


def program(*, packed: bool = True):
    api = posix_android_api()
    entries = android_c_entry_api(api)
    worker_graph = GraphBuilder()
    worker_function = worker(worker_graph)
    graph = GraphBuilder()
    block = graph.block(api.byte_ptr_rw, B64, api.thread_effect, api.memory_effect)
    slot, n, thread, memory = block.params
    start = block.op1(Operation.FUNCTION_ADDRESS, (), entries.c_entry, entity=worker_function)
    status, thread, memory = block.op(Operation.CALL_FOREIGN, (slot, block.const(B64, 0), start, n, thread, memory), (B32, api.thread_effect, api.memory_effect), entity=entries.pthread_create)
    block.ret(status, thread, memory)
    spawn = graph.function(block.parameter_types, (B32, api.thread_effect, api.memory_effect))
    target = android_arm64_shared_general_target(packed=packed)
    reader = program_store(spawn, target, (*api.types, *entries.types, *worker_graph.objects.values(), *graph.objects.values()))
    return reader, target, spawn, worker_function


def build_library(*, packed: bool = True) -> bytes:
    reader, target, spawn, _worker = program(packed=packed)
    return compile_android_shared(reader, (AndroidExport(b"xax_spawn_fib", spawn.cid),), target_object=target, soname=b"libxax_threads.so").data
