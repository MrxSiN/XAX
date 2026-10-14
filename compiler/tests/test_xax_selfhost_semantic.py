"""S10e (ADR-266): the semantic-verification inputs, built by XAX, are the words ``verify_store`` marshals in Python.

Each ``xax_selfhost_semantic`` function is lowered alone and run natively over the store verifier's object table
(``object_table``): the object index, the type and constant verdict stream (``marshal(objects=...)``), and, for every
graph fragment, the CFG program's input (``_cfg_tables``, ``_cfg_uses``) and the typing-and-facts stream (``marshal``
with the facts section and callee summaries and links) must be word-identical on committed stores.
"""

from __future__ import annotations

import ctypes
import platform
import sys
import unittest
from pathlib import Path

import xax_compiler as X

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
STORES = ("xax_cfg_analysis.xax", "xax_store_writer.xax", "xax_blake3_hash.xax", "xax_riscv64_encoder.xax")


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the helper images run on Linux x86-64 only")
class SemanticMarshalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import xax_selfhost_semantic as S
        from xax_graph_builder import program_store
        from xax_native import zeroed_array
        from xax_selfhost_typing import IN_WORDS, OUT_WORDS
        from xax_x86_64_views import NativeViewsImage, compile_x86_64_views

        building = X._TYPING_BUILDING
        X._TYPING_BUILDING = True
        try:
            functions, objects = S.build_functions()
        finally:
            X._TYPING_BUILDING = building
        target = X.x86_64_views_target()
        cls.images = {}
        for name in ("index_objects", "objects_marshal", "parse_graph", "cfg_input", "graph_marshal"):
            reader = program_store(functions[name], X.x86_64_linux_exec_target(), objects)
            cls.images[name] = NativeViewsImage(compile_x86_64_views(reader, functions[name].cid, target, backend="python"))
        cls.S = S
        cls.input = zeroed_array(ctypes.c_uint64, IN_WORDS)
        cls.output = zeroed_array(ctypes.c_uint64, OUT_WORDS)

    def run_helper(self, name: str):
        self.images[name](ctypes.addressof(self.input), ctypes.addressof(self.output))

    def ctrl(self, field: int) -> int:
        return self.output[self.S.CTRL + field]

    def test_marshals_equal_the_bootstraps(self):
        from xax_selfhost_typing import marshal, type_info_from
        from xax_selfhost_verify import object_table

        S, out = self.S, self.output
        for store in STORES:
            reader = X.StoreReader((BOOTSTRAP / store).read_bytes())
            listed = list(reader.objects())
            index = {item.cid: position for position, item in enumerate(listed)}
            objects = {item.cid: item for item in listed}
            resolve = objects.__getitem__
            words = object_table(listed, [index[reader.root_cid]])
            self.input[:len(words)] = words
            self.run_helper("index_objects")
            self.assertEqual((self.ctrl(S.C_STATUS), self.ctrl(S.C_OBJECTS)), (S.OK, len(listed)), store)

            pending = [item.cid for item in listed if item.kind in (X.Kind.TYPE, X.Kind.CONSTANT)]
            expected, expected_listed = marshal([], lambda *_args: None, type_info_from(resolve), objects=pending)
            self.run_helper("objects_marshal")
            self.assertEqual(self.ctrl(S.C_STATUS), S.OK, store)
            self.assertEqual(list(out[S.MARSHAL_AT:S.MARSHAL_AT + self.ctrl(S.C_LENGTH)]), expected, store)
            self.assertTrue(all(out[S.LISTED + index[cid]] == value for cid, value in expected_listed.items()), store)

            decoder, analysis = X._native_graph_decoder(), X._native_cfg()
            for graph in (item for item in listed if item.kind == X.Kind.GRAPH_FRAGMENT):
                with self.subTest(store=store, graph=graph.cid.hex()[:16]):
                    _status, stream, _diagnostic = decoder.decode_with_diagnostic(graph.body, len(graph.references), graph.cid)
                    entry, blocks, _used, _spans = X._graph_syntax_from_stream(graph, resolve, stream)
                    successors = [[target for target, _ in block.terminator.edges] for block in blocks]
                    tables, uses = X._cfg_tables(blocks), X._cfg_uses(blocks)
                    cfg = [len(successors), entry]
                    for targets in successors:
                        cfg += [len(targets), *targets]
                    for parameters, references in tables:
                        cfg += [parameters, len(references), *references]
                    cfg.append(len(uses))
                    for use in uses:
                        cfg.extend(use)
                    out[S.CTRL + S.C_GRAPH] = index[graph.cid]
                    self.run_helper("parse_graph")
                    self.run_helper("cfg_input")
                    self.assertEqual(list(out[S.CFG_AT:S.CFG_AT + self.ctrl(S.C_CFG_LENGTH)]), cfg)

                    _cfg_status, order, _dominators, _valid = analysis.analyze(entry, successors, (tables, uses))

                    def value_type(value):
                        block = blocks[value.block]
                        return block.parameters[value.index] if value.tag == 0 else block.nodes[value.index].results[value.result]

                    facts = (entry, order, lambda node: X._callee_summary(node, resolve), lambda node: X._callee_links(node, resolve))
                    expected, _keys, _refs = marshal(blocks, lambda b, n: tuple(value_type(v) for v in blocks[b].nodes[n].operands),
                                                     type_info_from(resolve), lambda _b, v: value_type(v), facts=facts, cids=[])
                    out[S.ORDER:S.ORDER + len(order)] = order
                    self.run_helper("graph_marshal")
                    self.assertEqual(self.ctrl(S.C_STATUS), S.OK)
                    self.assertEqual(list(out[S.MARSHAL_AT:S.MARSHAL_AT + self.ctrl(S.C_LENGTH)]), expected)


if __name__ == "__main__":
    unittest.main()
