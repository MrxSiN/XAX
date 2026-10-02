import json
import unittest

from benchmarks import bench_oi04_type_vocabulary as bench
from xax_compiler import (
    CID_SIZE, Cursor, FloatFormat, Kind, SemanticObject, StoreReader, XaxError,
    bits_type, blake3, float_type, uleb, verify_store,
)


class TypeVocabularyEvidenceTests(unittest.TestCase):
    def test_committed_evidence_reproduces(self):
        self.assertEqual(json.loads(bench.OUTPUT.read_text()), json.loads(json.dumps(bench.run(), sort_keys=True)))

    def test_every_alias_store_expands_to_identical_canonical_bytes(self):
        for name, data in bench.workloads().items():
            reader = StoreReader(data)
            for catalog in bench.CATALOGS.values():
                alias = bench.write_alias_store(reader.root_cid, reader.objects(), catalog)
                self.assertEqual(bench.read_alias_store(alias, catalog), data, name)
                self.assertEqual(alias, bench.write_alias_store(reader.root_cid, reader.objects(), catalog))


    def test_every_dictionary_store_expands_to_identical_canonical_bytes(self):
        for name, data in bench.workloads().items():
            reader = StoreReader(data)
            encoded = bench.write_dictionary_store(reader.root_cid, reader.objects())
            self.assertEqual(bench.read_dictionary_store(encoded), data, name)
            self.assertEqual(encoded, bench.write_dictionary_store(reader.root_cid, reader.objects()))

    def test_dictionary_is_exact_repeated_reference_set(self):
        data, _ = bench.reverse_store(bench.MIXES["bits64_only"])
        objects = list(StoreReader(data).objects())
        counts = {}
        for obj in objects:
            for cid in obj.references:
                counts[cid] = counts.get(cid, 0) + 1
        expected = tuple(sorted(cid for cid, count in counts.items() if count >= 2))
        self.assertEqual(bench.reference_dictionary(objects), expected)
        self.assertTrue(expected)

    def test_dictionary_decoder_rejections(self):
        data, _ = bench.reverse_store(bench.MIXES["bits64_only"])
        objects = list(StoreReader(data).objects())
        dictionary = bench.reference_dictionary(objects)
        ids = {cid: i for i, cid in enumerate(dictionary)}
        fn = next(obj for obj in objects if obj.kind == Kind.FUNCTION and any(cid in ids for cid in obj.references))
        record = bench.dictionary_envelope(fn, ids)
        outer = Cursor(record)
        payload = outer.take(outer.uleb())
        cursor = Cursor(payload)
        cid = cursor.take(CID_SIZE)
        kind = cursor.uleb()
        schema = cursor.uleb()
        head = cid + uleb(kind) + uleb(schema)
        count = cursor.uleb()
        indices = [cursor.uleb() for _ in range(count)]
        explicit_count = cursor.uleb()
        explicit = [cursor.take(CID_SIZE) for _ in range(explicit_count)]
        body = cursor.take(cursor.uleb())
        # unknown dictionary index
        bad = head + uleb(1) + uleb(len(dictionary)) + uleb(len(explicit)) + b"".join(explicit) + uleb(len(body)) + body
        with self.assertRaisesRegex(XaxError, "XAX.OI04.DICTIONARY_INDEX"):
            bench.decode_dictionary_envelope(bad, dictionary, ids)
        # dictionary member encoded explicitly is a second encoding
        dual_explicit = sorted([*explicit, dictionary[indices[0]]])
        dual = head + uleb(0) + uleb(len(dual_explicit)) + b"".join(dual_explicit) + uleb(len(body)) + body
        with self.assertRaisesRegex(XaxError, "XAX.OI04.DICTIONARY_EXPLICIT"):
            bench.decode_dictionary_envelope(dual, dictionary, ids)
        # wrong dictionary expansion changes semantic identity
        wrong_dictionary = list(dictionary)
        wrong_dictionary[indices[0]] = b"\x00" * CID_SIZE if dictionary[indices[0]] != b"\x00" * CID_SIZE else b"\xff" * CID_SIZE
        original_payload = record[len(record) - len(payload):]
        with self.assertRaisesRegex(XaxError, "XAX.OI04.DICTIONARY_CID"):
            bench.decode_dictionary_envelope(original_payload, tuple(wrong_dictionary), ids)

    def test_catalog_body_form_would_split_identity(self):
        # A canonical "pre-interned" body (hypothetical form 7 + index) is a second CID for bits<32>.
        interned = SemanticObject.create(Kind.TYPE, uleb(7) + uleb(bench.CATALOGS["bits5"].index(bench.BITS[32])))
        self.assertNotEqual(interned.cid, bits_type(32).cid)

    def test_float_descriptors_are_distinct_and_exact(self):
        cids = {obj.cid for obj in bench.FLOATS.values()}
        self.assertEqual(len(cids), len(bench.FLOATS))  # binary16/bfloat16 and ftz/non-ftz never collide
        for catalog in bench.CATALOGS.values():
            self.assertNotIn(bench.FLOATS["binary32_ftz"], catalog)
            self.assertNotIn(bench.FLOATS["e4m3fn"], catalog)
        with self.assertRaises(ValueError):
            bench.experimental_float_type(2, 24, 127, 5, 32, bench.IEEE)

    def test_float_descriptor_is_not_accepted_semantics(self):
        data, _ = bench.reverse_store(bench.MIXES["float_ieee"])
        # OI-04's measurement-only descriptor deliberately uses a noncanonical
        # historical form.  Form 6 is now a real identity-qualified opaque type,
        # so only rejection is stable; the exact decoder diagnostic is not.
        with self.assertRaises(XaxError):
            verify_store(StoreReader(data))

    def test_alias_decoder_rejections(self):
        catalog = bench.CATALOGS["bits5"]
        ids = {obj.cid: i for i, obj in enumerate(catalog)}
        data, _ = bench.reverse_store(bench.MIXES["bits64_only"])
        fn = next(obj for obj in StoreReader(data).objects() if obj.kind == Kind.FUNCTION)
        payload = bench.alias_envelope(fn, ids)
        body = payload[1:] if payload[0] < 0x80 else payload[2:]
        head = bench.CID_SIZE + 2  # cid, kind, schema
        # unknown catalog index
        bad = body[:head] + uleb(1) + uleb(len(catalog)) + body[head + 2:]
        with self.assertRaisesRegex(XaxError, "XAX.OI04.CATALOG_INDEX"):
            bench.decode_alias_envelope(bad, catalog, ids)
        # a catalog type written as an explicit CID is a second encoding
        explicit = [cid for cid in fn.references if cid not in ids]
        dual = body[:head] + uleb(0) + uleb(2) + b"".join(sorted([*explicit, catalog[4].cid])) + uleb(len(fn.body)) + fn.body
        with self.assertRaisesRegex(XaxError, "XAX.OI04.CATALOG_EXPLICIT"):
            bench.decode_alias_envelope(dual, catalog, ids)
        # wrong expansion changes the re-derived CID
        swapped = body[:head] + uleb(1) + uleb(3) + body[head + 2:]
        with self.assertRaisesRegex(XaxError, "XAX.OI04.CID"):
            bench.decode_alias_envelope(swapped, catalog, ids)

    def test_alias_store_rejects_other_catalog(self):
        data, _ = bench.reverse_store(bench.MIXES["bits_mixed"])
        reader = StoreReader(data)
        alias = bench.write_alias_store(reader.root_cid, reader.objects(), bench.CATALOGS["bits5"])
        with self.assertRaisesRegex(XaxError, "XAX.OI04.CATALOG"):
            bench.read_alias_store(alias, bench.CATALOGS["common"])

    def test_supported_float_catalog_entries_are_exact_canonical_types(self):
        self.assertEqual(bench.FLOATS["binary32"].cid, float_type(FloatFormat.BINARY32).cid)
        self.assertEqual(bench.FLOATS["binary64"].cid, float_type(FloatFormat.BINARY64).cid)
        self.assertEqual(bench.FLOATS["binary32"].body, float_type(FloatFormat.BINARY32).body)
        self.assertEqual(bench.FLOATS["binary64"].body, float_type(FloatFormat.BINARY64).body)

    def test_representative_corpus_is_exact_and_supported_core_verifies(self):
        corpus, composition = bench.representative_numeric_corpus()
        self.assertEqual(len(corpus["numeric_service_verified"]), 6231)
        self.assertEqual(StoreReader(corpus["numeric_service_verified"]).root_cid.hex(), "25fdca5fb6874ff1118816eec702bdb35f5f99ed0b96a30990b3c06f127f2341")
        self.assertEqual(len(corpus["numeric_abi_extended"]), 11762)
        self.assertEqual(StoreReader(corpus["numeric_abi_extended"]).root_cid.hex(), "94eb3ad9aeb82886be9d65d1471018cbc02d7baf58b43ebf03c75fe760419860")
        verify_store(StoreReader(corpus["numeric_service_verified"]))
        self.assertEqual(composition["numeric_abi_extended"]["float_formats_used"], ["binary16", "bfloat16", "binary32", "binary64"])
        with self.assertRaises(XaxError):
            verify_store(StoreReader(corpus["numeric_abi_extended"]))

    def test_representative_storage_result_is_exact_and_dictionary_wins(self):
        result = bench.run()
        expected = {
            "numeric_service_verified": (6231, 78, -537, -537, -812, -996),
            "numeric_abi_extended": (11762, 119, -713, -1183, -1458, -1905),
        }
        for name, values in expected.items():
            row = result["workloads"][name]
            actual = (row["structural_bytes"], row["bits5"]["delta"], row["bits5_float2"]["delta"], row["bits5_float4"]["delta"], row["common"]["delta"], row["cid_dictionary"]["delta"])
            self.assertEqual(actual, values)
            self.assertLess(row["cid_dictionary"]["bytes"], row["common"]["bytes"])
        self.assertEqual(result["representative_aggregate"]["structural_bytes"], 17993)
        self.assertEqual(result["representative_aggregate"]["common"]["delta"], -2270)
        self.assertEqual(result["representative_aggregate"]["cid_dictionary"]["delta"], -2901)

    def test_catalog_hit_counts_charge_zero_hit_workload(self):
        result = bench.run()
        zero = result["workloads"]["reverse_float_zero_catalog"]
        for name in bench.CATALOGS:
            self.assertEqual(zero[name]["entries_hit"], 0)
            self.assertEqual(zero[name]["header_digest_bytes"], CID_SIZE)
            self.assertEqual(zero[name]["delta"], 45)
        extended = result["workloads"]["numeric_abi_extended"]["bits5_float4"]
        hits = {item["name"]: item["references"] for item in extended["entry_hits"]}
        self.assertEqual({name: hits[name] for name in ("binary16", "bfloat16", "binary32", "binary64")}, {"binary16": 5, "bfloat16": 5, "binary32": 12, "binary64": 10})

    def test_alias_store_rejects_digest_and_index_corruption(self):
        data, _ = bench.reverse_store(bench.MIXES["bits64_only"])
        reader = StoreReader(data)
        alias = bench.write_alias_store(reader.root_cid, reader.objects(), bench.CATALOGS["bits5"])

        corrupt_digest = bytearray(alias)
        corrupt_digest[-36] ^= 1
        with self.assertRaisesRegex(XaxError, "XAX.OI04.DIGEST"):
            bench.read_alias_store(bytes(corrupt_digest), bench.CATALOGS["bits5"])

        cursor = Cursor(alias)
        cursor.take(4)
        cursor.uleb(); cursor.uleb(); cursor.uleb()
        cursor.take(CID_SIZE)
        cursor.take(CID_SIZE)
        count = cursor.uleb(); cursor.uleb(); cursor.uleb()
        for _ in range(count):
            cursor.take(cursor.uleb())
        index_length = cursor.uleb()
        index_start = cursor.pos
        cursor.take(index_length)
        digest_start = cursor.pos
        corrupt_index = bytearray(alias)
        corrupt_index[index_start] ^= 1
        corrupt_index[digest_start:digest_start + CID_SIZE] = blake3(corrupt_index[:digest_start]).digest()
        with self.assertRaisesRegex(XaxError, "XAX.OI04.INDEX_TABLE"):
            bench.read_alias_store(bytes(corrupt_index), bench.CATALOGS["bits5"])

    def test_mutation_tasks_have_same_semantic_target_and_strict_packets(self):
        rows = bench.mutation_task_rows()
        self.assertEqual(len(rows), 8)
        for row in rows:
            expected = bytes.fromhex(row["target_cid"])
            for arm in ("structural", "alias"):
                self.assertEqual(bench.check_mutation_response(row["task_id"], arm, row["arms"][arm]["target_response"]), expected)
                with self.assertRaisesRegex(ValueError, "invalid OI-04 type mutation packet"):
                    bench.check_mutation_response(row["task_id"], arm, row["arms"][arm]["target_response"].rstrip())
        self.assertTrue(any(row["task_id"] == "invalid-repair" for row in rows))

    def test_model_measurement_is_explicitly_unavailable_not_substituted(self):
        result = bench.run()
        self.assertEqual(result["model_token_status"], "not_run")
        self.assertEqual(result["tokenizer_measurements"], {"status": "unavailable", "raw": []})
        self.assertEqual(result["raw_model_trials"]["trials"], [])
        self.assertIsNone(result["model_trial_summary"]["alias"]["tokens_per_success"])


if __name__ == "__main__":
    unittest.main()
