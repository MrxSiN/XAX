"""ADR-111: persistent-counter Activity (state, file I/O, lifecycle in XAX) and assembled DEX methods."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from xax_android_counter import counter_activity_semantics, decode_counter_activity
from xax_compiler import XaxError, target
from xax_dex import DexAssembledMethod, DexInstruction, DexMethodRef, DexProto, _assemble

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import android_counter_app as app  # noqa: E402
from benchmarks import bench_android_art_verify as art  # noqa: E402
from benchmarks import bench_android_bionic as bionic  # noqa: E402


class CounterSemanticsTests(unittest.TestCase):
    def test_carrier_round_trips(self):
        description = decode_counter_activity(counter_activity_semantics(**app.SEMANTICS))
        self.assertEqual((description.activity_descriptor, description.state_file), ("Lxax/counter/CounterActivity;", "xax.counter"))

    def test_state_file_must_be_one_file_name(self):
        for name in ("../escape", "dir/file", "", ".."):
            with self.assertRaises(ValueError):
                counter_activity_semantics(state_file=name)

    def test_carrier_with_invalid_fields_rejects(self):
        fields = (b"xax.counter", b"xax.counter.A", b"xax.counter.B", b"a/b")
        identity = b"android-counter-activity-v1" + b"".join(bytes((len(item),)) + item for item in fields)
        with self.assertRaises(XaxError) as caught:
            decode_counter_activity(target(identity))
        self.assertEqual(caught.exception.diagnostic.rule, "ANDROID-COUNTER-FIELDS")


class AssembledDexTests(unittest.TestCase):
    def test_encodings(self):
        proto = DexProto("V", ("J",))
        reference = DexMethodRef("Ljava/lang/Long;", "f", proto)
        method = DexAssembledMethod("m", DexProto("V", ()), 6, (
            DexInstruction("const", (3,), literal=0x38000000),
            DexInstruction("invoke-static", (2, 3), reference),
            DexInstruction("invoke-virtual", (1, 2, 3, 4, 5), reference),
            DexInstruction("move-result-wide", (2,)),
            DexInstruction("return-void"),
        ))
        units = _assemble(method, {}, {}, {("Ljava/lang/Long;", "f", proto): 7})
        self.assertEqual(units, (0x0314, 0x0000, 0x3800, 0x2071, 7, 0x0032, 0x556E, 7, 0x4321, 0x020B, 0x000E))

    def test_invalid_instructions_reject(self):
        reference = DexMethodRef("Ljava/lang/Long;", "f", DexProto("V", ()))
        for build in (
            lambda: DexInstruction("invoke-static", (0, 1, 2, 3, 4, 5), reference),
            lambda: DexInstruction("goto", ()),
            lambda: DexInstruction("const", (0,)),
            lambda: DexInstruction("new-instance", (0,), "not-a-type"),
        ):
            with self.assertRaises(ValueError):
                build()


class CounterApkTests(unittest.TestCase):
    def test_apk_is_deterministic_and_committed(self):
        self.assertEqual(app.build()["signed"], app.APK.read_bytes())

    def test_committed_evidence_matches_the_apk(self):
        committed = json.loads(app.EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(committed["apk_sha256"], hashlib.sha256(app.APK.read_bytes()).hexdigest())
        self.assertTrue(all(committed[key]["passed"] for key in ("official_tools", "art_verify", "native_under_bionic")))
        self.assertEqual(committed["device"]["label"], "UNEXECUTED")

    @unittest.skipUnless(bionic.QEMU and (bionic.ROOT / "system/bin/linker64").exists() and bionic.JNI_H.exists(), "requires the NDK, qemu-aarch64, and an Android bionic root")
    def test_native_state_survives_restart_under_bionic(self):
        self.assertEqual(app.run_native(app.APK), app.EXPECTED_NATIVE)

    @unittest.skipUnless(art.available(), "requires qemu-aarch64 and the Android root from make_android_root.py")
    def test_art_verifies_both_classes(self):
        import shutil

        art.WORK.mkdir(parents=True, exist_ok=True)
        copy = art.WORK / app.APK.name
        shutil.copy(app.APK, copy)
        self.assertEqual(set(art.verify(copy).values()), {"Verified"})


if __name__ == "__main__":
    unittest.main()
