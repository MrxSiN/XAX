"""ADR-103: wasm32 browser pages with compiler-generated host bindings."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from xax_compiler import (
    Operation,
    XaxError,
    bits_type,
    foreign_function_symbol,
    function_pointer_type,
    opaque_type,
    OpaqueKind,
    stack_owner_type,
    wasm32_browser_target,
    wasm32_general_target,
    x86_64_linux_dynamic_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_wasm import compile_wasm, compile_wasm_bound_target
from xax_web import emit_browser_page, playwright_available, run_browser_page, web_api

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.browser_fib import CASES, CLICKS, EVIDENCE, compile_page, expected_texts  # noqa: E402

B32 = bits_type(32)


def _render_only(binding=None):
    """``_start`` that renders an empty body text through one binding."""
    api = web_api()
    owner_type = stack_owner_type()
    graph = GraphBuilder()
    block = graph.block(api.page_effect)
    buffer, owner, memory = block.op(Operation.STACK_ALLOC, (), (api.bytes_rw, owner_type, api.memory_effect), attributes=(1, 1))
    memory = block.op1(Operation.STORE_BITS_LE, (buffer, block.const(api.b8, 65), memory), api.memory_effect, attributes=(1, 1))
    readable = block.op1(Operation.POINTER_CAST, (buffer,), api.bytes_read)
    page, memory = block.op(Operation.CALL_FOREIGN, (readable, block.const(B32, 1), block.params[0], memory), (api.page_effect, api.memory_effect), entity=binding or api.set_body_text)
    block.op(Operation.STACK_END, (owner, memory), ())
    block.ret(page)
    function = graph.function((api.page_effect,), (api.page_effect,))
    target = wasm32_browser_target()
    reader = program_store(function, target, (*api.types, owner_type, *graph.objects.values()))
    return compile_wasm(reader, function.cid, target.cid)


class BrowserPageTests(unittest.TestCase):
    def test_page_is_deterministic(self):
        self.assertEqual(compile_page(), compile_page())

    def test_only_imported_bindings_are_emitted(self):
        page = emit_browser_page(_render_only())
        self.assertIn(b"set_body_text", page)
        self.assertNotIn(b"query_copy", page)

    def test_undeclared_import_rejects(self):
        api = web_api()
        forged = foreign_function_symbol(b"xax-web-v1", b"eval", (api.bytes_read, B32, api.page_effect, api.memory_effect), (api.page_effect, api.memory_effect), abi=b"wasm32-import")
        with self.assertRaises(XaxError) as caught:
            emit_browser_page(_render_only(forged))
        self.assertEqual(caught.exception.diagnostic.rule, "WEB-IMPORT-DECLARED")

    def test_integer_completion_is_gated_by_the_target(self):
        graph = GraphBuilder()
        block = graph.block(B32, B32)
        block.ret(block.op1(Operation.UDIV, block.params, B32))
        function = graph.function((B32, B32), (B32,))
        target = wasm32_general_target()
        reader = program_store(function, target, tuple(graph.objects.values()))
        with self.assertRaises(XaxError) as caught:
            compile_wasm_bound_target(reader, function.cid, target)
        self.assertEqual(caught.exception.diagnostic.rule, "WASM-OP-TARGET-SUPPORTED")

    def test_reference_texts(self):
        self.assertEqual(expected_texts("30"), ["30 832040", "31 1346269", "32 2178309"])
        self.assertEqual(expected_texts("7x9")[0], "7 13")

    def test_click_entry_is_exported_and_registered(self):
        module, page = compile_page()
        self.assertIn(b"entry_0", module)
        self.assertIn(b"body_on_click", page)


def _entry_program(handler_parameters, handler_returns, address_type=None, target=None):
    """``_start`` that takes the address of a handler with the given interface."""
    api = web_api()
    handler_graph = GraphBuilder()
    block = handler_graph.block(*handler_parameters)
    block.ret(*block.params)
    handler = handler_graph.function(handler_parameters, handler_returns)
    graph = GraphBuilder()
    start = graph.block(api.page_effect)
    start.op1(Operation.FUNCTION_ADDRESS, (), address_type or api.event_entry, entity=handler)
    start.ret(start.params[0])
    function = graph.function((api.page_effect,), (api.page_effect,))
    target = target or wasm32_browser_target()
    objects = (*api.types, opaque_type(OpaqueKind.FUNCTION), *handler_graph.objects.values(), *graph.objects.values())
    return program_store(function, target, objects), function, target


class EventEntryTests(unittest.TestCase):
    def test_entry_with_machine_parameters_rejects(self):
        api = web_api()
        with self.assertRaises(XaxError) as caught:
            _entry_program((api.page_effect, B32), (api.page_effect, B32))
        self.assertEqual(caught.exception.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")

    def test_entry_cannot_claim_a_memory_effect(self):
        api = web_api()
        with self.assertRaises(XaxError) as caught:
            _entry_program((api.page_effect, api.memory_effect), (api.page_effect, api.memory_effect))
        self.assertEqual(caught.exception.diagnostic.rule, "GRAPH-FUNCTION-ADDRESS-FOREIGN-ENTRY")

    def test_internal_address_rejects_on_wasm(self):
        api = web_api()
        reader, function, target = _entry_program((api.page_effect,), (api.page_effect,), address_type=function_pointer_type())
        with self.assertRaises(XaxError) as caught:
            compile_wasm(reader, function.cid, target.cid)
        self.assertEqual(caught.exception.diagnostic.rule, "WASM-FUNCTION-ADDRESS-EVENT-ENTRY")

    def test_event_entry_rejects_on_x86_64(self):
        from xax_x86_64 import compile_native_bound_target

        api = web_api()
        reader, function, _target = _entry_program((api.page_effect,), (api.page_effect,))
        with self.assertRaises(XaxError) as caught:
            compile_native_bound_target(reader, function.cid, x86_64_linux_dynamic_exec_target())
        self.assertEqual(caught.exception.diagnostic.rule, "SYSV-ENTRY-TARGET")

    def test_committed_evidence_matches_the_compiled_page(self):
        committed = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        module, page = compile_page()
        self.assertEqual(committed["module_sha256"], hashlib.sha256(module).hexdigest())
        self.assertEqual(committed["page_sha256"], hashlib.sha256(page).hexdigest())
        self.assertTrue(all(run["passed"] for run in committed["runs"]))


@unittest.skipUnless(playwright_available(), "requires Node.js with Playwright and Chromium")
class BrowserExecutionTests(unittest.TestCase):
    def test_page_reads_the_url_renders_and_handles_clicks(self):
        _module, page = compile_page()
        for query in CASES:
            with self.subTest(query=query):
                observed = run_browser_page(page, query, clicks=CLICKS)
                self.assertEqual((observed["texts"], observed["errors"]), (expected_texts(query), []))


if __name__ == "__main__":
    unittest.main()
