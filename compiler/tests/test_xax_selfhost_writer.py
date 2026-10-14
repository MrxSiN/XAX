"""Self-hosting step S9 (ADR-262): canonical store writing is XAX semantics on the production path, rejections
included.

Differential against the bootstrap writer (``_bootstrap_store_contents`` and ``_bootstrap_emit_store``): every
committed store, its objects in any order, with and without non-semantic records; random stores; every rejection
the bootstrap makes, with its precedence (input order, then the root, then the records); and the inputs the batch
cannot carry, which decline to the bootstrap.  The writer writes its own store byte for byte (a component fixed
point), and production writes record ``actual_authority: xax``.
"""

from __future__ import annotations

import dataclasses
import glob
import os
import platform
import random
import sys
import unittest
from pathlib import Path

import xax_compiler
import xax_native
from xax_compiler import Kind, NonsemanticRecord, SemanticObject, StoreReader, write_store

NATIVE = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"


def _bootstrap_write(root, objects, records=()):
    ordered, metadata = xax_compiler._bootstrap_store_contents(root, objects, records)
    return xax_compiler._bootstrap_emit_store(root, ordered.values(), metadata)


def _outcome(write, *arguments):
    try:
        return "bytes", write(*arguments)
    except ValueError as error:
        return "ValueError", str(error)


def _random_objects(rng: random.Random, count: int) -> list[SemanticObject]:
    objects: list[SemanticObject] = []
    for _ in range(count):
        references = [item.cid for item in rng.sample(objects, min(len(objects), rng.randrange(4)))]
        body = rng.randbytes(rng.choice((0, 1, 7, 8, 9, 63, 64, 65, 200, 1500)))
        objects.append(SemanticObject.create(Kind(rng.randrange(1, 12)), body, references))
    return objects


def _random_records(rng: random.Random, count: int) -> list[NonsemanticRecord]:
    return [NonsemanticRecord(rng.choice((0, 1, 127, 128, 300, 1 << 40)), rng.randbytes(rng.choice((0, 1, 5, 130)))) for _ in range(count)]


def _unchecked(obj: SemanticObject, **changes) -> SemanticObject:
    return dataclasses.replace(obj, **changes)  # replace() yields an object whose CID was never checked


@unittest.skipUnless(NATIVE, "UNAVAILABLE: native XAX helper images run on Linux x86-64 only")
class StoreWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("XAX_STORE_PYTHON_WRITER") == "1":
            raise unittest.SkipTest("XAX_STORE_PYTHON_WRITER=1 requests the bootstrap writer")
        cls.writer = xax_compiler._native_store_writer()
        if cls.writer is None:
            raise unittest.SkipTest(f"UNAVAILABLE: {xax_native.AUTHORITY.get('store-writer')}")

    def assertSameOutcome(self, root, objects, records=()):
        objects, records = tuple(objects), tuple(records)
        expected = _outcome(_bootstrap_write, root, objects, records)
        self.assertEqual(_outcome(write_store, root, objects, records), expected)
        status, *_rest = self.writer.run(root, objects, records)
        self.assertNotEqual(status, 2, "the XAX writer declined; the bootstrap decided")
        return expected

    def test_committed_stores_byte_identical_in_any_order(self):
        rng = random.Random(262)
        for path in sorted(glob.glob(str(BOOTSTRAP / "*.xax"))):
            with self.subTest(store=Path(path).name):
                data = Path(path).read_bytes()
                reader = StoreReader(data)
                objects = list(reader.objects())
                rng.shuffle(objects)
                self.assertEqual(write_store(reader.root_cid, objects, reader.nonsemantic_records), data)
                records = list(dict.fromkeys(_random_records(rng, 3)))
                self.assertEqual(self.assertSameOutcome(reader.root_cid, objects, records)[0], "bytes")

    def test_component_fixed_point_writes_its_own_store(self):
        from xax_selfhost_writer import STORE_PATH

        data = STORE_PATH.read_bytes()
        reader = StoreReader(data)
        status, _reason, _index, written = self.writer.run(reader.root_cid, tuple(reader.objects())[::-1], ())
        self.assertEqual((status, written), (0, data))

    def test_random_stores(self):
        rng = random.Random(9)
        for trial in range(150):
            with self.subTest(trial=trial):
                objects = list({obj.cid: obj for obj in _random_objects(rng, rng.randrange(1, 40))}.values())
                root = rng.choice(objects).cid
                rng.shuffle(objects)
                records = list(dict.fromkeys(_random_records(rng, rng.randrange(4))))
                self.assertEqual(self.assertSameOutcome(root, objects, records)[0], "bytes")

    def test_every_rejection_and_its_precedence(self):
        rng = random.Random(41)
        base = _random_objects(rng, 6)
        root = base[-1].cid
        version = SemanticObject.create(Kind.TYPE, b"v", (), schema_version=2)
        forged = _unchecked(base[1], cid=bytes(32))
        body_changed = _unchecked(base[2], body=base[2].body + b"!")
        unsorted = _unchecked(base[3], references=tuple(reversed(sorted({base[0].cid, base[1].cid}))))
        duplicate = SemanticObject.create(base[4].kind, base[4].body, base[4].references)
        record = NonsemanticRecord(5, b"meta")
        cases = {
            "schema version": [*base, version],
            "checked object with another schema": [version, *base],
            "forged CID": [*base, forged],
            "changed body": [body_changed, *base],
            "unsorted references": [*base, unsorted],
            "duplicate CID": [*base, duplicate],
            "duplicate before a later non-canonical object": [*base, duplicate, forged],
            "non-canonical before a later duplicate": [*base[:2], forged, *base[2:], duplicate],
            "duplicate of the first object, twice": [base[0], base[0], base[0]],
            "missing root": base[:-1],
            "missing root and a duplicate record": (base[:-1], [record, record]),
            "duplicate record": (base, [record, NonsemanticRecord(5, b"other"), record]),
            "empty store": [],
        }
        reasons = set()
        for name, case in cases.items():
            objects, records = case if isinstance(case, tuple) else (case, [])
            with self.subTest(case=name):
                kind, value = self.assertSameOutcome(root, objects, records)
                self.assertEqual(kind, "ValueError", name)
                reasons.add(value)
        from xax_selfhost_writer import REASONS

        self.assertEqual(reasons, set(REASONS.values()))

    def test_random_rejections(self):
        rng = random.Random(77)
        kinds = set()
        for trial in range(200):
            objects = _random_objects(rng, rng.randrange(1, 12))
            root = rng.choice(objects).cid
            for _ in range(rng.randrange(1, 3)):
                victim = rng.randrange(len(objects))
                change = rng.randrange(6)
                if change == 0:
                    objects.insert(rng.randrange(len(objects) + 1), objects[victim])
                elif change == 1:
                    objects[victim] = _unchecked(objects[victim], body=objects[victim].body + b"x")
                elif change == 2:
                    objects[victim] = _unchecked(objects[victim], schema_version=rng.choice((0, 2, 1 << 40)))
                elif change == 3:
                    root = bytes(32)
                elif change == 4 and len(objects[victim].references) > 1:
                    objects[victim] = _unchecked(objects[victim], references=objects[victim].references[::-1])
                else:
                    objects[victim] = _unchecked(objects[victim], cid=bytes(reversed(objects[victim].cid)))
            records = _random_records(rng, rng.randrange(3))
            if rng.randrange(4) == 0 and records:
                records.append(records[0])
            with self.subTest(trial=trial):
                kind, value = self.assertSameOutcome(root, objects, records)
                kinds.add(kind if kind == "bytes" else value)
        self.assertGreaterEqual(len(kinds), 5)

    def test_from_objects_decides_with_the_writer(self):
        rng = random.Random(5)
        objects = _random_objects(rng, 5)
        with self.assertRaisesRegex(ValueError, "^duplicate semantic object CID$"):
            StoreReader.from_objects(objects[0].cid, [*objects, objects[2]])
        with self.assertRaisesRegex(ValueError, "^root CID missing from store$"):
            StoreReader.from_objects(bytes(32), objects)
        reader = StoreReader.from_objects(objects[0].cid, objects, [NonsemanticRecord(1, b"x")])
        self.assertEqual(reader.data, _bootstrap_write(objects[0].cid, objects, [NonsemanticRecord(1, b"x")]))

    def test_unrepresentable_inputs_decline_to_the_bootstrap(self):
        rng = random.Random(3)
        objects = _random_objects(rng, 3)
        short = _unchecked(objects[0], cid=b"\x01" * 31)
        negative = _unchecked(objects[1], schema_version=-1)
        for name, case in {"short CID": [short, *objects[1:]], "negative version": [objects[0], negative, objects[2]]}.items():
            with self.subTest(case=name):
                status, *_rest = self.writer.run(objects[0].cid, case, ())
                self.assertEqual(status, 2)
                self.assertEqual(_outcome(write_store, objects[0].cid, case), _outcome(_bootstrap_write, objects[0].cid, case))

    def test_production_write_records_xax_authority(self):
        write_store(*(lambda obj: (obj.cid, [obj]))(SemanticObject.create(Kind.TYPE, b"\x01\x08", ())))
        entry = xax_native.AUTHORITY["store-writer"]
        self.assertEqual(entry["actual_authority"], "xax")
        self.assertEqual(entry["semantic_root"], self.writer.semantic_root.hex())


if __name__ == "__main__":
    unittest.main()
