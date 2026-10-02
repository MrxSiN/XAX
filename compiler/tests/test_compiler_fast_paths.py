"""Equivalence checks for compiler fast paths: ULEB decode, object/graph memoization, BLAKE3."""

import itertools
import unittest

import xax_compiler
from blake3 import blake3
from xax_compiler import (
    Block, Cursor, Kind, Node, Operation, StoreReader, Terminator, ValueRef, XaxError,
    bits_type, function, graph_fragment, object_with_refs, uleb, verify_store, write_store,
)


def program():
    b32 = bits_type(32)
    graph = graph_fragment([Block((b32, b32), (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),), Terminator.return_((ValueRef.node_result(0, 0),)))])
    fn = function(graph, (b32, b32), (b32,))
    root = object_with_refs(Kind.PROGRAM_ROOT, [object_with_refs(Kind.MODULE, [fn])])
    return b32, graph, fn, root


class FastPathTests(unittest.TestCase):
    def test_uleb_minimality_matches_reencoding(self):
        for length in range(1, 4):
            for raw in itertools.product((0x00, 0x01, 0x7F, 0x80, 0x81, 0xFF), repeat=length):
                data = bytes(raw)
                try:
                    value = Cursor(data).uleb()
                except XaxError as error:
                    code = error.diagnostic.code
                    if code == "XAX.CANON.ULEB_NON_MINIMAL":
                        end = next(i for i, b in enumerate(data) if not b & 0x80) + 1
                        self.assertNotEqual(data[:end], uleb(sum((b & 0x7F) << 7 * i for i, b in enumerate(data[:end]))))
                    else:
                        self.assertEqual(code, "XAX.CANON.ULEB_UNTERMINATED")
                    continue
                end = next(i for i, b in enumerate(data) if not b & 0x80) + 1
                self.assertEqual(data[:end], uleb(value))

    def test_cached_graph_still_rejects_store_missing_dependency(self):
        b32, graph, fn, root = program()
        module = object_with_refs(Kind.MODULE, [fn])
        verify_store(StoreReader(write_store(root.cid, (b32, graph, fn, module, root))))
        self.assertIn(graph.cid, xax_compiler._PARSED_GRAPHS)
        objects = {obj.cid: obj for obj in (b32, graph, fn, module, root)}

        def missing_type(cid):
            if cid == b32.cid:
                raise KeyError(cid)
            return objects[cid]

        with self.assertRaises(KeyError):
            xax_compiler._parse_graph(graph, missing_type)

    def test_reader_returns_same_verified_object(self):
        b32, graph, fn, root = program()
        module = object_with_refs(Kind.MODULE, [fn])
        reader = StoreReader(write_store(root.cid, (b32, graph, fn, module, root)))
        self.assertIs(reader.get(graph.cid), reader.get(graph.cid))
        self.assertEqual(reader.get(graph.cid), graph)

    def test_object_backed_reader_matches_byte_reader(self):
        b32, graph, fn, root = program()
        objects = (b32, graph, fn, object_with_refs(Kind.MODULE, [fn]), root)
        lazy = StoreReader.from_objects(root.cid, reversed(objects))
        self.assertIsNone(lazy._data)
        self.assertEqual(lazy.data, write_store(root.cid, objects))
        self.assertEqual(StoreReader(lazy.data).canonical_bytes(), lazy.data)
        with self.assertRaisesRegex(XaxError, "XAX.IDENTITY.OBJECT_MISSING"):
            lazy.get(bytes(32))
        forged = xax_compiler.SemanticObject(b32.kind, 1, (), b32.body + b"\0", b32.cid)
        with self.assertRaisesRegex(ValueError, "not canonical"):
            StoreReader.from_objects(root.cid, objects[1:] + (forged,))

    def test_blake3_reference_vectors(self):
        # Official BLAKE3 test_vectors.json: input[i] = i % 251.
        vectors = {
            0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        }
        for length, expected in vectors.items():
            self.assertEqual(blake3(bytes(i % 251 for i in range(length))).hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
