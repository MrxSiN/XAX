"""Lend entries (ADR-115, OI-42): C calls back into XAX code that reads memory C was lent.

``qsort_r`` sorts an XAX-owned heap array with an XAX comparator that rebases
the element addresses C passes into the lent view.  The negative vectors are
the OI-42 closing set: a callback kept past the call (``atexit``), a call that
lends no view, a write through the lent view, a writable lent view, and a view
of the wrong extent.
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import (
    Operation,
    XaxError,
    bits_type,
    heap_view_type,
    lend_entry_code_type,
    lend_entry_pointer_type,
    pointer_type,
    Permission,
)
from xax_graph_builder import GraphBuilder
from xax_linux import c_function, compile_linux_executable, linux_api, run_linux_executable
from benchmarks.linux_qsort import (
    ELEMENTS_READ,
    ELEMENTS_RW,
    STATUS,
    VALUES,
    VIEW,
    compare_entry,
    qsort_r_declaration,
    sort_program,
)

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B64 = bits_type(64)


def _rejection(**kwargs) -> XaxError:
    try:
        sort_program(**kwargs)
    except XaxError as error:
        return error
    raise AssertionError("program verified")


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host with glibc")
class LendEntryExecutionTests(unittest.TestCase):
    def test_qsort_r_sorts_an_xax_array_with_an_xax_comparator(self):
        reader, function, target = sort_program()
        completed = run_linux_executable(compile_linux_executable(reader, function.cid, target.cid).data)
        self.assertEqual(completed.returncode, STATUS, completed.stderr)

    def test_comparator_result_decides_the_order(self):
        comparator, graph = compare_entry(descending=True)
        reader, function, target = sort_program(comparator=(comparator, tuple(graph.objects.values())))
        completed = run_linux_executable(compile_linux_executable(reader, function.cid, target.cid).data)
        descending = sum((index + 1) * value for index, value in enumerate(sorted(VALUES, reverse=True))) % 256
        self.assertNotEqual(descending, STATUS)
        self.assertEqual(completed.returncode, descending, completed.stderr)


class LendEntryRejectionTests(unittest.TestCase):
    def test_entry_kept_past_the_call_rejects(self):
        api = linux_api()
        entry_type = lend_entry_pointer_type(ELEMENTS_READ, VIEW)
        atexit = c_function(b"libc.so.6", b"atexit", (entry_type,), (bits_type(32),))
        comparator, graph = compare_entry()
        main = GraphBuilder()
        block = main.block(api.memory_effect)
        entry = block.op1(Operation.FUNCTION_ADDRESS, (), entry_type, entity=comparator)
        block.op1(Operation.CALL_FOREIGN, (entry,), bits_type(32), entity=atexit)
        block.ret(*block.params)
        function = main.function((api.memory_effect,), (api.memory_effect,))
        from xax_compiler import lend_entry_code_type, x86_64_linux_dynamic_exec_target
        from xax_graph_builder import program_store

        with self.assertRaises(XaxError) as raised:
            program_store(function, x86_64_linux_dynamic_exec_target(), (*api.types, ELEMENTS_READ, VIEW, entry_type, lend_entry_code_type(ELEMENTS_READ, VIEW), *graph.objects.values(), comparator, atexit, *main.objects.values()))
        self.assertEqual(raised.exception.diagnostic.rule, "LEND-ENTRY-VIEW-LENT")

    def test_call_that_lends_no_view_rejects(self):
        entry_type = lend_entry_pointer_type(ELEMENTS_READ, VIEW)
        declaration = c_function(b"libc.so.6", b"qsort_r", (ELEMENTS_RW, B64, B64, entry_type), ())
        error = _rejection(declaration=declaration, pass_memory=False)
        self.assertEqual(error.diagnostic.rule, "LEND-ENTRY-VIEW-LENT")

    def test_write_through_the_lent_view_rejects(self):
        comparator, graph = compare_entry(store=True)
        error = _rejection(comparator=(comparator, tuple(graph.objects.values())))
        self.assertEqual(error.diagnostic.rule, "MEMORY-WRITE-PERMISSION")

    def test_writable_lent_view_rejects(self):
        comparator, graph = compare_entry(permission_view=ELEMENTS_RW)
        error = _rejection(comparator=(comparator, tuple(graph.objects.values())), entry_type=lend_entry_pointer_type(ELEMENTS_RW, VIEW), extra=(lend_entry_code_type(ELEMENTS_RW, VIEW),))
        self.assertEqual(error.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")

    def test_callback_cannot_return_a_pointer_into_the_view(self):
        """A pointer result would let the borrow outlive the call."""
        mem = linux_api().memory_effect
        graph = GraphBuilder()
        block = graph.block(B64, B64, ELEMENTS_READ, VIEW, mem)
        a, _b, view, token, memory = block.params
        escaped = block.op1(Operation.POINTER_REBASE, (view, a), ELEMENTS_READ, attributes=(8,))
        block.ret(escaped, view, token, memory)
        comparator = graph.function((B64, B64, ELEMENTS_READ, VIEW, mem), (ELEMENTS_READ, ELEMENTS_READ, VIEW, mem))
        error = _rejection(comparator=(comparator, tuple(graph.objects.values())))
        self.assertEqual(error.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")

    def test_view_of_another_extent_rejects(self):
        small = heap_view_type(64)
        entry_type = lend_entry_pointer_type(ELEMENTS_READ, small)
        mem = linux_api().memory_effect
        graph = GraphBuilder()
        block = graph.block(B64, B64, ELEMENTS_READ, small, mem)
        _a, _b, view, token, memory = block.params
        block.ret(block.const(bits_type(32), 0), view, token, memory)
        comparator = graph.function((B64, B64, ELEMENTS_READ, small, mem), (bits_type(32), ELEMENTS_READ, small, mem))
        error = _rejection(comparator=(comparator, (small, *graph.objects.values())), entry_type=entry_type, extra=(lend_entry_code_type(ELEMENTS_READ, small),))
        self.assertEqual(error.diagnostic.rule, "LEND-ENTRY-VIEW-LENT")

    def test_pure_entry_type_still_rejects_proof_parameters(self):
        error = _rejection(entry_type=linux_api().c_callback)
        self.assertEqual(error.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")


if __name__ == "__main__":
    unittest.main()
