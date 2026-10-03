"""Self-hosting step S3 (ADR-118): the store container decoder is XAX semantics on the production path.

Differential: on committed stores, stores with non-semantic records, and
thousands of mutations, the XAX decoder accepts exactly what the bootstrap
parser accepts (digest aside, which is checked with the XAX hash), with an
identical index; rejected stores raise the bootstrap parser's exact diagnostic.
"""

from __future__ import annotations

import glob
import platform
import random
import sys
import unittest
from pathlib import Path

import xax_compiler
from xax_compiler import CONTAINER_MAJOR, HASH_SUITE, MAGIC, NonsemanticRecord, StoreReader, XaxError, uleb, write_store
from xax_selfhost_store import ACCEPT, DEFER, STORE_PATH, NativeDecoder, build_decoder_program

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
            status, _header, records = self.decoder.decode(data)
            ok, index, _reader = _bootstrap(data, verify_digest=False)
            if status == DEFER:
                continue
            with self.subTest(trial=trial):
                self.assertEqual(status == ACCEPT, ok)
                if ok:
                    accepted += 1
                    self.assertEqual({data[c:c + 32]: (o, n) for o, n, c in records}, index)
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

    def test_huge_minor_defers_to_the_bootstrap_parser(self):
        reader = StoreReader(self.seeds[1])
        data = reader.data
        prefix = MAGIC + uleb(CONTAINER_MAJOR) + uleb(0)
        self.assertTrue(data.startswith(prefix))
        huge = MAGIC + uleb(CONTAINER_MAJOR) + uleb(1 << 60) + data[len(prefix):]
        self.assertEqual(self.decoder.decode(huge)[0], DEFER)
        self.assertEqual(self.decoder.decode(data)[0], ACCEPT)
        self.assertEqual(HASH_SUITE, 1)


if __name__ == "__main__":
    unittest.main()
