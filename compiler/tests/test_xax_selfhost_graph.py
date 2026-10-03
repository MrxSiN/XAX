"""Self-hosting step S3c (ADR-120): graph-body syntax is decoded by XAX on the production path.

The parse built from the XAX decoder's stream must equal the bootstrap
parser's on real graphs (committed stores and generated programs), and every
mutated body must give the same parse or the same diagnostic.
"""

from __future__ import annotations

import glob
import platform
import random
import sys
import unittest
from pathlib import Path

import xax_compiler as compiler
from xax_compiler import Kind, SemanticObject, StoreReader, XaxError, store_resolver
from xax_graph_builder import program_store
from xax_selfhost_graph import STORE_PATH, build_graph_decoder_program
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


if __name__ == "__main__":
    unittest.main()
