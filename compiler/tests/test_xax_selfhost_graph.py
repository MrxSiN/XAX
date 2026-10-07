"""Self-hosting steps S3c (ADR-120) and S8b.2 (ADR-185): graph-body syntax is decoded by XAX on the production path,
rejections included.

The parse built from the XAX decoder's stream must equal the bootstrap
parser's on real graphs (committed stores and generated programs), and every
mutated body must give the same parse or the same diagnostic.  A constructed
body per syntax rule is rejected by the XAX decoder itself (never deferred)
with the bootstrap's exact diagnostic, and resolution that precedes the
rejection in body order still comes first.
"""

from __future__ import annotations

import glob
import platform
import random
import sys
import unittest
from pathlib import Path

import xax_compiler as compiler
from xax_compiler import Kind, SemanticObject, StoreReader, XaxError, store_resolver, uleb
from xax_graph_builder import program_store
from xax_selfhost_graph import REJECT, STORE_PATH, build_graph_decoder_program
from test_xax_jvm import _random_function

NATIVE = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"


def _parse(graph, resolve, native: bool):
    building = compiler._GRAPH_DECODER_BUILDING
    compiler._GRAPH_DECODER_BUILDING = not native
    try:
        parsed = compiler._parse_graph_uncached(graph, resolve)
        blocks = [
            (block.parameters, [(n.operation, n.member, n.entity.cid if n.entity else None, n.operands, n.results, n.attributes) for n in block.nodes], block.terminator)
            for block in parsed.blocks
        ]
        return ("parse", parsed.entry, blocks, parsed.member_spans)
    except XaxError as error:
        return ("diagnostic", error.diagnostic)
    finally:
        compiler._GRAPH_DECODER_BUILDING = building


def _graphs():
    graphs = []
    for path in sorted(glob.glob(str(BOOTSTRAP / "*.xax"))):
        reader = StoreReader(Path(path).read_bytes())
        resolve = store_resolver(reader)
        graphs += [(item, resolve) for item in reader.objects() if item.kind == Kind.GRAPH_FRAGMENT]
    rng = random.Random(4)
    from xax_compiler import x86_64_linux_exec_target

    for width in (8, 32, 64):
        callees = []
        for _ in range(4):
            entry, builder = _random_function(rng, width, tuple(callees))
            reader = program_store(entry, x86_64_linux_exec_target(), (*builder.objects.values(), *[o for c in callees for o in (c,)], *[item for c in callees for item in _OBJECTS[c.cid]]))
            _OBJECTS[entry.cid] = (*builder.objects.values(), *[item for c in callees for item in _OBJECTS[c.cid]], *callees)
            resolve = store_resolver(reader)
            graphs += [(item, resolve) for item in reader.objects() if item.kind == Kind.GRAPH_FRAGMENT]
            callees.append(entry)
    return graphs


_OBJECTS: dict[bytes, tuple] = {}


class GraphDecoderStoreTests(unittest.TestCase):
    def test_committed_store_regenerates(self):
        building = compiler._GRAPH_DECODER_BUILDING
        compiler._GRAPH_DECODER_BUILDING = True
        try:
            reader, _function = build_graph_decoder_program()
        finally:
            compiler._GRAPH_DECODER_BUILDING = building
        self.assertEqual(reader.data, STORE_PATH.read_bytes())


@unittest.skipUnless(NATIVE, "the native leaf runs on Linux x86-64")
class GraphDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graphs = _graphs()
        assert compiler._native_graph_decoder() is not None

    def test_real_graphs_parse_identically(self):
        for graph, resolve in self.graphs:
            native = _parse(graph, resolve, True)
            self.assertEqual(native[0], "parse")
            self.assertEqual(native, _parse(graph, resolve, False))

    def test_mutated_bodies_give_the_same_parse_or_diagnostic(self):
        rng = random.Random(20261003)
        parsed = 0
        for trial in range(1500):
            graph, resolve = rng.choice(self.graphs)
            body = bytearray(graph.body)
            choice = rng.random()
            if choice < 0.6:
                for _ in range(rng.randint(1, 2)):
                    index = rng.randrange(len(body))
                    body[index] = rng.randrange(256) if rng.random() < 0.5 else body[index] ^ (1 << rng.randrange(8))
            elif choice < 0.8:
                body = body[: rng.randrange(len(body))]
            else:
                index = rng.randrange(len(body) + 1)
                body[index:index] = bytes([rng.randrange(256)])
            mutated = SemanticObject.create(Kind.GRAPH_FRAGMENT, bytes(body), graph.references)
            native = _parse(mutated, resolve, True)
            with self.subTest(trial=trial):
                self.assertEqual(native, _parse(mutated, resolve, False))
            parsed += native[0] == "parse"
        self.assertGreater(parsed, 10)


    def test_every_syntax_rule_is_decided_by_the_xax_decoder(self):
        graph, resolve = next((g, r) for g, r in self.graphs if len(g.references) >= 2)
        references = graph.references
        wide = bytes([0xFF] * 9 + [0x7F])
        ret = uleb(3) + uleb(0)
        bodies = {
            "no-blocks": uleb(0) + uleb(0),
            "entry-out-of-range": uleb(1) + uleb(1) + uleb(0) + uleb(0) + ret,
            "entry-70-bit": uleb(2) + wide,
            "ref-index": uleb(1) + uleb(0) + uleb(1) + uleb(len(references) + 5),
            "ref-index-70-bit": uleb(1) + uleb(0) + uleb(1) + wide,
            "value-tag": uleb(1) + uleb(0) + uleb(0) + uleb(0) + uleb(3) + uleb(1) + uleb(2),
            "value-tag-70-bit": uleb(1) + uleb(0) + uleb(0) + uleb(0) + uleb(3) + uleb(1) + wide,
            "terminator-0": uleb(1) + uleb(0) + uleb(0) + uleb(0) + uleb(0),
            "terminator-5": uleb(1) + uleb(0) + uleb(0) + uleb(0) + uleb(5),
            "terminator-70-bit": uleb(1) + uleb(0) + uleb(0) + uleb(0) + wide,
            "trailing": uleb(1) + uleb(0) + uleb(0) + uleb(0) + ret + b"\0",
            "uleb-non-minimal": uleb(1) + uleb(0) + bytes([0x80, 0x00]),
            "uleb-unterminated": uleb(1) + uleb(0) + bytes([0x80]),
            "uleb-overflow": uleb(1) + uleb(0) + bytes([0x80] * 11),
            "trap-truncated": uleb(1) + uleb(0) + uleb(0) + uleb(0) + uleb(4) + uleb(10) + b"ab",
            "trap-70-bit": uleb(1) + uleb(0) + uleb(0) + uleb(0) + uleb(4) + wide,
            "huge-block-count": uleb(1 << 40) + uleb(0) + uleb(0) + uleb(0) + ret,
            "huge-node-count": uleb(1) + uleb(0) + uleb(0) + uleb(1 << 50) + uleb(1),
        }
        decoder = compiler._native_graph_decoder()
        rules = set()
        for name, body in bodies.items():
            mutated = SemanticObject.create(Kind.GRAPH_FRAGMENT, body, references)
            status, _words, diagnostic = decoder.decode_with_diagnostic(mutated.body, len(references), mutated.cid)
            bootstrap = _parse(mutated, resolve, False)
            with self.subTest(case=name):
                self.assertEqual(bootstrap[0], "diagnostic")
                self.assertEqual(status, REJECT)
                self.assertEqual(diagnostic, bootstrap[1])
                self.assertEqual(repr(diagnostic), repr(bootstrap[1]))
                self.assertEqual(_parse(mutated, resolve, True), bootstrap)
            rules.add(bootstrap[1].rule)
        self.assertTrue({"GRAPH-ENTRY", "GRAPH-REF-INDEX", "GRAPH-VALUE-TAG", "GRAPH-TERMINATOR-KIND", "GRAPH-BODY", "SER-ULEB-MINIMAL",
                         "SER-ULEB-TERMINATED", "SER-ULEB-BOUNDED", "SER-BOUNDS"} <= rules, rules)

    def test_resolution_before_a_syntax_rejection_comes_first(self):
        """A missing type (resolution) precedes a bad terminator (syntax) in body order: the bootstrap's diagnostic."""
        graph, resolve = self.graphs[0]
        missing = bytes(31) + b"\x01"
        body = uleb(1) + uleb(0) + uleb(1) + uleb(0) + uleb(0) + uleb(9)
        mutated = SemanticObject.create(Kind.GRAPH_FRAGMENT, body, (missing,))
        native, bootstrap = _parse(mutated, resolve, True), _parse(mutated, resolve, False)
        self.assertEqual(bootstrap[0], "diagnostic")
        self.assertNotEqual(bootstrap[1].rule, "GRAPH-TERMINATOR-KIND")
        self.assertEqual(native, bootstrap)


if __name__ == "__main__":
    unittest.main()
