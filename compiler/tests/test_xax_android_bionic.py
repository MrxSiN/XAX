"""Android arm64 libraries under Android's own linker and bionic, via qemu-user (no device, no ART)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks import bench_android_bionic as bionic  # noqa: E402
from xax_jni import JNI_INVOKE_SLOT_BY_NAME, JNI_NATIVE_SLOT_BY_NAME  # noqa: E402

HAVE_NDK = bionic.JNI_H.exists()
HAVE_RUNTIME = HAVE_NDK and bionic.QEMU is not None and (bionic.ROOT / "system/bin/linker64").exists()


class CheckerTests(unittest.TestCase):
    LOG = "env 10 name 20 sig 30 vm 40 pid 50\ncall NewGlobalRef 10 1111 0 0 0 0\ncall DeleteGlobalRef 10 4444 0 0 0 0\nresult none\n"

    def test_matching_log_passes(self):
        expected = (("NewGlobalRef", "env", bionic.OBJ), ("DeleteGlobalRef", "env", 0x4444))
        self.assertEqual(bionic._check_jni_log(self.LOG, expected, None), (True, []))

    def test_wrong_slot_wrong_argument_and_missing_call_are_reported(self):
        self.assertFalse(bionic._check_jni_log(self.LOG, (("NewLocalRef", "env", bionic.OBJ), ("DeleteGlobalRef", "env", 0x4444)), None)[0])
        self.assertFalse(bionic._check_jni_log(self.LOG, (("NewGlobalRef", "env", 0x9999), ("DeleteGlobalRef", "env", 0x4444)), None)[0])
        self.assertFalse(bionic._check_jni_log(self.LOG, (("NewGlobalRef", "env", bionic.OBJ),), None)[0])


@unittest.skipUnless(HAVE_NDK, "requires the Android NDK")
class HeaderTests(unittest.TestCase):
    def test_xax_jni_tables_match_the_ndk_header(self):
        native = bionic.jni_slots()
        invoke = bionic.jni_slots("struct JNIInvokeInterface {")
        self.assertEqual({name: index for index, name in enumerate(native) if not re.match(r"reserved\d", name)}, JNI_NATIVE_SLOT_BY_NAME)
        self.assertEqual({name: index for index, name in enumerate(invoke) if not re.match(r"reserved\d", name)}, JNI_INVOKE_SLOT_BY_NAME)

    def test_committed_evidence_matches_current_libraries(self):
        committed = json.loads(bionic.EVIDENCE.read_text(encoding="utf-8"))
        for (export, *_rest, source), suffix in ((case, suffix) for case in bionic.CASES for suffix in bionic.CONTAINERS):
            self.assertEqual(committed["runs"][export + suffix]["library_sha256"], hashlib.sha256(bionic._library(source, packed=bool(suffix))).hexdigest())
        self.assertEqual(committed["passed"], committed["total"])


@unittest.skipUnless(HAVE_RUNTIME, "requires the NDK, qemu-aarch64, and an Android bionic root")
class BionicExecutionTests(unittest.TestCase):
    def test_every_case_executes(self):
        result = bionic.evidence()
        failed = {name: row for name, row in result["runs"].items() if not row["passed"]}
        self.assertEqual(failed, {})


if __name__ == "__main__":
    unittest.main()
