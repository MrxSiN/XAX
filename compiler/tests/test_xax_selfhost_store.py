"""Self-hosting steps S3 (ADR-118) and S8a (ADR-183): the store container decoder is XAX semantics on the
production path, rejections included.

Differential: on committed stores, stores with non-semantic records, thousands
of mutations, and a constructed case for every container rule, the XAX decoder
accepts exactly what the bootstrap parser accepts, with an identical index, and
rejects with the bootstrap parser's exact diagnostic (every field and repr),
the digest comparison included (the digest itself is the XAX hash).
"""

from __future__ import annotations

import glob
import platform
import random
import sys
import unittest
from pathlib import Path

import xax_compiler
from blake3 import blake3
from xax_compiler import CONTAINER_MAJOR, HASH_SUITE, MAGIC, TRAILER_MAGIC, NonsemanticRecord, StoreReader, XaxError, uleb, write_store
from xax_selfhost_store import ACCEPT, DEFER, REJECT, STORE_PATH, NativeDecoder, build_decoder_program

NATIVE = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"


def _seeds() -> list[bytes]:
    seeds = [Path(path).read_bytes() for path in sorted(glob.glob(str(BOOTSTRAP / "*.xax")))]
    reader = StoreReader(seeds[0])
    records = (NonsemanticRecord(3, b"abc"), NonsemanticRecord(3, b"abd"), NonsemanticRecord(200, b""), NonsemanticRecord(1 << 20, b"x" * 300))
    seeds.append(write_store(reader.root_cid, tuple(reader.objects()), records))
    return seeds


def _bootstrap(data: bytes, verify_digest: bool = True):
    building = xax_compiler._DECODER_BUILDING
    xax_compiler._DECODER_BUILDING = True  # force the bootstrap parser
    try:
        reader = StoreReader(data, verify_digest=verify_digest)
        return True, {cid: reader._index[cid] for cid in reader._index}, reader
    except XaxError as error:
        return False, error.diagnostic, None
    finally:
        xax_compiler._DECODER_BUILDING = building


def _mutate(rng: random.Random, data: bytes) -> bytes:
    data = bytearray(data)
    choice = rng.random()
    if choice < 0.5:
        for _ in range(rng.randint(1, 3)):
            index = rng.randrange(len(data))
            data[index] = rng.randrange(256) if rng.random() < 0.5 else data[index] ^ (1 << rng.randrange(8))
    elif choice < 0.65:
        data = data[: rng.randrange(len(data))]
    elif choice < 0.75:
        data += bytes(rng.randrange(256) for _ in range(rng.randint(1, 4)))
    elif choice < 0.85:
        index = rng.randrange(len(data))
        data[index:index] = bytes([rng.randrange(256)])
    return bytes(data)


def _container(parts: dict) -> bytes:
    """A store from its parts (header fields, records, metadata, index, digest, trailer); a missing digest is the
    correct one, so a case breaks exactly the field it names."""
    head = (parts.get("magic", MAGIC) + parts.get("major", uleb(CONTAINER_MAJOR)) + parts.get("minor", uleb(0)) + parts.get("suite", uleb(HASH_SUITE))
            + parts["root"] + parts.get("objects", uleb(len(parts["records"]))) + parts.get("metadata_count", uleb(len(parts["metadata"])))
            + parts.get("flags", uleb(0)))
    body = head + b"".join(parts["records"]) + b"".join(parts["metadata"])
    index = parts.get("index_bytes")
    if index is None:
        offsets, at = [], len(head)
        for record in parts["records"]:
            cursor = xax_compiler.Cursor(record)
            length = cursor.uleb()
            offsets.append((record[cursor.pos:cursor.pos + 32], at, length))
            at += len(record)
        index = b"".join(cid + uleb(offset) + uleb(length) for cid, offset, length in offsets)
    body += parts.get("index_length", uleb(len(index))) + index
    return body + parts.get("digest", blake3(body).digest()) + parts.get("trailer", TRAILER_MAGIC) + parts.get("tail", b"")


def _rule_cases(seed: bytes) -> dict[str, bytes]:
    """One store per container rule (and the 70-bit ULEB paths), built from ``seed``'s objects."""
    reader = StoreReader(seed)
    objects = sorted(reader.objects(), key=lambda obj: obj.cid)[:6]
    records = [obj.envelope() for obj in objects]
    metadata = sorted([NonsemanticRecord(3, b"abc").envelope(), NonsemanticRecord(4, b"").envelope()])  # canonical byte order
    base = {"root": objects[0].cid, "records": records, "metadata": metadata}
    wide = bytes([0xFF] * 9 + [0x7F])  # 70 bits, all set
    cases = {
        "short": MAGIC[:3],
        "magic": b"XAY\0" + _container(base)[4:],
        "major": _container({**base, "major": uleb(2)}),
        "major-70-bit": _container({**base, "major": wide}),
        "uleb-overflow": _container({**base, "major": bytes([0x81] * 11)}),
        "uleb-unterminated": MAGIC + bytes([0x81, 0x81]),
        "uleb-non-minimal": _container({**base, "major": bytes([0x81, 0x00])}),
        "uleb-non-minimal-9": _container({**base, "suite": bytes([0xFF] * 8 + [0x80, 0x00])}),
        "suite": _container({**base, "suite": uleb(7)}),
        "root-truncated": MAGIC + uleb(1) + uleb(0) + uleb(1) + b"\1" * 10,
        "flags": _container({**base, "flags": uleb(1 << 40)}),
        "record-truncated": _container({**base, "records": [*records[:2], uleb(1 << 62) + b"x"]}),
        "record-70-bit": _container({**base, "records": [wide]}),
        "record-short": _container({**base, "records": [uleb(3) + b"abc"]}),
        "record-order": _container({**base, "records": [records[1], records[0], *records[2:]]}),
        "metadata-truncated": _container({**base, "metadata": [uleb(1 << 50)]}),
        "metadata-body": _container({**base, "metadata": [uleb(3) + uleb(1) + uleb(9) + b"x"]}),
        "metadata-trailing": _container({**base, "metadata": [uleb(4) + uleb(1) + uleb(1) + b"xy"]}),
        "metadata-uleb": _container({**base, "metadata": [uleb(2) + bytes([0x80, 0x00])]}),
        "metadata-order": _container({**base, "metadata": [metadata[1], metadata[0]]}),
        "index-length": _container({**base, "index_length": uleb(1 << 33)})[:-36],
        "digest-truncated": _container(base)[:-30],
        "trailer": _container({**base, "trailer": b"XAXF"}),
        "trailing": _container({**base, "tail": b"\0\0"}),
        "digest": _container({**base, "digest": bytes(32)}),
        "index-entry": _container({**base, "index_bytes": records[0][1:20]}),
        "index-uleb": _container({**base, "index_bytes": objects[0].cid + bytes([0x80])}),
        "index-count": _container({**base, "index_bytes": b"".join(obj.cid + uleb(1) + uleb(2) for obj in objects) + b"\0"}),
        "index-mismatch": _container({**base, "index_bytes": b"".join(obj.cid + uleb(1) + uleb(2) for obj in objects)}),
        "index-70-bit": _container({**base, "index_bytes": objects[0].cid + wide + uleb(2) + b"".join(obj.cid + uleb(1) + uleb(2) for obj in objects[1:])}),
        "root-missing": _container({**base, "root": bytes(32)}),
    }
    return cases


def _object_cases() -> dict[str, tuple[bytes, bytes]]:
    """``(store, CID)`` per ``decode_object`` rule: a valid container whose one record is the malformed object."""
    cid = bytes(range(1, 33))
    low, high = bytes(32), bytes([0xFF] * 32)
    wide = bytes([0xFF] * 9 + [0x7F])

    def store(payload: bytes) -> bytes:
        record = uleb(len(payload)) + payload
        return _container({"root": payload[:32], "records": [record], "metadata": []})

    def envelope(kind=uleb(3), version=uleb(1), references=uleb(0), body=uleb(0)):
        return cid + kind + version + references + body

    payloads = {
        "kind-0": envelope(kind=uleb(0)),
        "kind-12": envelope(kind=uleb(12)),
        "kind-70-bit": envelope(kind=wide),
        "kind-unterminated": cid + bytes([0x83]),
        "version": envelope(version=uleb(2)),
        "version-70-bit": envelope(version=wide),
        "references-truncated": envelope(references=uleb(1 << 40) + low),
        "references-unsorted": envelope(references=uleb(2) + high + low),
        "references-duplicate": envelope(references=uleb(3) + low + high + high),
        "body-truncated": envelope(body=uleb(1 << 33) + b"xy"),
        "body-non-minimal": envelope(body=bytes([0x82, 0x00]) + b"xy"),
        "trailing": envelope(body=uleb(1) + b"xy"),
        "cid": envelope(),
    }
    return {name: (store(payload), payload[:32]) for name, payload in payloads.items()}


class DecoderStoreTests(unittest.TestCase):
    def test_committed_store_regenerates_and_verifies(self):
        building = xax_compiler._DECODER_BUILDING
        xax_compiler._DECODER_BUILDING = True
        try:
            reader, _function = build_decoder_program()
        finally:
            xax_compiler._DECODER_BUILDING = building
        self.assertEqual(reader.data, STORE_PATH.read_bytes())


@unittest.skipUnless(NATIVE, "the native leaf runs on Linux x86-64")
class NativeDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.decoder = NativeDecoder()
        cls.seeds = _seeds()

    def test_accepts_exactly_what_the_bootstrap_accepts(self):
        rng = random.Random(20261003)
        accepted = 0
        for trial in range(2000):
            data = _mutate(rng, rng.choice(self.seeds)) if trial >= len(self.seeds) else self.seeds[trial]
            status, _header, records, _diagnostic = self.decoder.decode(data, verify_digest=False)
            ok, index, _reader = _bootstrap(data, verify_digest=False)
            if status == DEFER:
                continue
            with self.subTest(trial=trial):
                self.assertEqual(status == ACCEPT, ok)
                if ok:
                    accepted += 1
                    self.assertEqual({data[c:c + 32]: (o, n) for o, n, c, *_rest in records}, index)
        self.assertGreater(accepted, 300)

    def test_production_reader_matches_the_bootstrap_reader(self):
        for data in self.seeds:
            reader = StoreReader(data)
            _ok, index, bootstrap = _bootstrap(data)
            self.assertEqual((reader.root_cid, reader.minor, reader._index, reader.nonsemantic_records), (bootstrap.root_cid, bootstrap.minor, index, bootstrap.nonsemantic_records))
        self.assertIsNotNone(xax_compiler._native_store_decoder())

    def test_rejections_keep_the_bootstrap_diagnostic(self):
        rng = random.Random(9)
        for _ in range(200):
            data = _mutate(rng, rng.choice(self.seeds))
            ok, expected, _reader = _bootstrap(data)
            if ok:
                continue
            with self.assertRaises(XaxError) as raised:
                StoreReader(data)
            self.assertEqual(raised.exception.diagnostic, expected)

    def test_objects_match_the_bootstrap_decoder(self):
        """S3b: every object (or its exact diagnostic) equals the bootstrap decoder's."""
        rng = random.Random(77)
        parsed_objects = 0
        for trial in range(600):
            data = self.seeds[trial] if trial < len(self.seeds) else _mutate(rng, rng.choice(self.seeds))
            ok, _index, bootstrap = _bootstrap(data, verify_digest=False)
            if not ok:
                continue
            reader = StoreReader(data, verify_digest=False)
            if not hasattr(reader, "_parsed"):
                continue  # deferred to the bootstrap parser
            parsed_objects += len(reader._parsed)
            for cid in reader.object_cids:
                outcomes = []
                for source in (reader, bootstrap):
                    try:
                        obj = source.get(cid)
                        outcomes.append((obj.kind, obj.references, obj.body, obj.cid))
                    except XaxError as error:
                        outcomes.append(error.diagnostic)
                with self.subTest(trial=trial, cid=cid.hex()[:12]):
                    self.assertEqual(outcomes[0], outcomes[1])
        self.assertGreater(parsed_objects, 1000)

    def _xax(self, data: bytes, verify_digest: bool = True):
        status, _header, _records, diagnostic = self.decoder.decode(data, verify_digest, lambda prefix: blake3(prefix).digest())
        return status, diagnostic

    def assertSameDecision(self, data: bytes, verify_digest: bool = True):
        """The XAX decoder accepts what the bootstrap accepts and rejects with its exact diagnostic; returns the
        bootstrap's diagnostic (None on accept), or "defer"."""
        ok, expected, _reader = _bootstrap(data, verify_digest)
        status, diagnostic = self._xax(data, verify_digest)
        if status == DEFER:
            return "defer"
        self.assertEqual(status, ACCEPT if ok else REJECT)
        if not ok:
            self.assertEqual(diagnostic, expected)
            self.assertEqual(repr(diagnostic), repr(expected))
            return expected
        return None

    def test_every_mutation_is_decided_with_the_bootstrap_diagnostic(self):
        rng = random.Random(183)
        rules, defers = set(), 0
        for trial in range(1200):
            data = _mutate(rng, rng.choice(self.seeds))
            with self.subTest(trial=trial):
                outcome = self.assertSameDecision(data, verify_digest=trial % 4 != 0)
            if outcome == "defer":
                defers += 1
            elif outcome is not None:
                rules.add(outcome.rule)
        self.assertLess(defers, 12)
        self.assertGreaterEqual(len(rules), 10)

    def test_every_container_rule_is_decided_by_xax(self):
        cases = _rule_cases(self.seeds[-1])
        seen = set()
        for name, data in cases.items():
            with self.subTest(case=name):
                outcome = self.assertSameDecision(data)
                self.assertNotIn(outcome, (None, "defer"))
                seen.add(outcome.code)
        self.assertEqual(seen, {
            "XAX.CANON.TRUNCATED", "XAX.CONTAINER.MAGIC", "XAX.CONTAINER.MAJOR", "XAX.CONTAINER.HASH_SUITE", "XAX.CONTAINER.FEATURE",
            "XAX.CANON.ULEB_OVERFLOW", "XAX.CANON.ULEB_UNTERMINATED", "XAX.CANON.ULEB_NON_MINIMAL", "XAX.CANON.RECORD_SHORT",
            "XAX.CANON.RECORD_ORDER", "XAX.CANON.TRAILING_BYTES", "XAX.CANON.NONSEMANTIC_ORDER", "XAX.CONTAINER.TRAILER",
            "XAX.INTEGRITY.STORE_DIGEST", "XAX.CANON.INDEX", "XAX.IDENTITY.ROOT_MISSING"})

    def test_every_object_envelope_rule_is_decided_by_xax(self):
        """S8b.1: a valid container holding one malformed object; ``get`` raises the bootstrap's exact diagnostic."""
        seen = set()
        for name, (data, cid) in _object_cases().items():
            ok, _index, bootstrap = _bootstrap(data)
            self.assertTrue(ok, name)
            reader = StoreReader(data)
            outcomes = []
            for source in (reader, bootstrap):
                try:
                    source.get(cid)
                    outcomes.append(None)
                except XaxError as error:
                    outcomes.append(error.diagnostic)
            with self.subTest(case=name):
                self.assertIsNotNone(outcomes[1])
                self.assertEqual(outcomes[0], outcomes[1])
                self.assertEqual(repr(outcomes[0]), repr(outcomes[1]))
            seen.add(outcomes[1].rule)
        self.assertTrue({"SER-KIND-SUPPORTED", "SER-SCHEMA-SUPPORTED", "SER-REFS-SORTED-UNIQUE", "SER-OBJECT-BODY-LENGTH", "ID-CID-INTEGRITY",
                         "SER-BOUNDS", "SER-ULEB-MINIMAL", "SER-ULEB-TERMINATED"} <= seen, seen)

    def test_production_reader_raises_the_xax_diagnostic(self):
        import xax_native

        data = _rule_cases(self.seeds[-1])["digest"]
        _ok, expected, _reader = _bootstrap(data)
        with self.assertRaises(XaxError) as raised:
            StoreReader(data)
        self.assertEqual(raised.exception.diagnostic, expected)
        self.assertEqual(xax_native.AUTHORITY["store-decoder"]["actual_authority"], "xax")

    def test_huge_minor_defers_to_the_bootstrap_parser(self):
        reader = StoreReader(self.seeds[1])
        data = reader.data
        prefix = MAGIC + uleb(CONTAINER_MAJOR) + uleb(0)
        self.assertTrue(data.startswith(prefix))
        huge = MAGIC + uleb(CONTAINER_MAJOR) + uleb(1 << 60) + data[len(prefix):]
        self.assertEqual(self._xax(huge, verify_digest=False)[0], DEFER)
        self.assertEqual(self._xax(data)[0], ACCEPT)
        self.assertEqual(HASH_SUITE, 1)


if __name__ == "__main__":
    unittest.main()
