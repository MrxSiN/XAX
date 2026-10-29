"""S15e.6h.1 (ADR-354): an Android shared object's AArch64 bundle built by the XAX AArch64 program equals the bootstrap's.

``compile_android_shared`` compiles its exports' functions with ``compile_aarch64_bundle_bound_target``.  The XAX program
(``xax_selfhost_aarch64_general.android_bundle_with_xax``) builds the same bundle (code, function offsets, foreign calls,
semantic ranges) on every Android profile path: the legacy register path of ``android-arm64-v8a-shared-v3`` with JNI
foreign and indirect calls, code addresses and target operations (the ``bench_android_jni`` fixtures); code addresses on
v4, whose functions the register allocator declines (C entries, with the exact ``AARCH64-ENTRY-SIGNATURE`` and
``AARCH64-FOREIGN-ENTRY-TARGET`` rejections); and the frame path and the function-wide register allocator of v4/v5,
recorded from the AAudio and BBC builds.
"""

from __future__ import annotations

import os
import platform
import sys
import unittest
from pathlib import Path

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
TESTS = Path(__file__).resolve().parent


def _original():
    """The XAX entry point as the module defines it (the recorder below wraps the module attribute)."""
    import xax_selfhost_aarch64_general as G

    return getattr(G, "_unrecorded_android_bundle_with_xax", G.android_bundle_with_xax)


def _decisions(reader, function_cids, target):
    """``(XAX outcome, bootstrap outcome)``: a bundle or the rejection's diagnostic each."""
    from xax_aarch64 import compile_aarch64_bundle_bound_target
    from xax_compiler import XaxError

    android_bundle_with_xax = _original()

    def run(build):
        try:
            return "bundle", build()
        except XaxError as error:
            return "rejected", error.diagnostic

    return (run(lambda: android_bundle_with_xax(reader, function_cids, target, required=True)),
            run(lambda: compile_aarch64_bundle_bound_target(reader, tuple(dict.fromkeys(function_cids)), target)))


class _Recorder:
    """A pytest plugin: every ``android_bundle_with_xax`` call's outcome next to the bootstrap's."""

    def __init__(self):
        self.outcomes = []

    def pytest_configure(self, config):
        import xax_selfhost_aarch64_general as G

        original = _original()
        G._unrecorded_android_bundle_with_xax = original

        def recorded(reader, function_cids, target, required=False):
            mine, reference = _decisions(reader, function_cids, target)
            self.outcomes.append((mine, reference))
            return original(reader, function_cids, target, required)

        G.android_bundle_with_xax = recorded

    def pytest_unconfigure(self, config):
        import xax_selfhost_aarch64_general as G

        G.android_bundle_with_xax = G.__dict__.pop("_unrecorded_android_bundle_with_xax")


@unittest.skipUnless(LINUX_X86_64, "the XAX AArch64 program runs natively on Linux x86-64")
class SelfhostAndroidBundleTests(unittest.TestCase):
    def test_jni_fixtures_on_the_legacy_register_path(self):
        sys.path.insert(0, str(TESTS.parent))
        from benchmarks import bench_android_jni as J

        fixtures = [getattr(J, name) for name in dir(J) if name.endswith("_fixture")]
        self.assertGreaterEqual(len(fixtures), 8)
        for fixture in fixtures:
            with self.subTest(fixture=fixture.__name__):
                reader, target, _function, exports = fixture()
                mine, reference = _decisions(reader, tuple(item.function_cid for item in exports), target)
                self.assertEqual(mine[0], "bundle")
                self.assertEqual(mine, reference)

    def test_code_addresses_and_their_rejections(self):
        sys.path.insert(0, str(TESTS))
        from test_xax_android_c_entry import B32, B64, _address_of
        from xax_compiler import SYSV_X86_64_C_ABI, foreign_entry_code_type, foreign_entry_pointer_type
        from xax_platform import android_c_entry_api, posix_android_api

        entries = android_c_entry_api(posix_android_api())
        sysv = foreign_entry_pointer_type(SYSV_X86_64_C_ABI)
        cases = {
            "entry": (((B64,), (B64,), entries.c_entry), {"extra_types": entries.types}, "bundle"),
            "narrow parameter": (((B32,), (B32,), entries.c_entry), {"extra_types": entries.types}, "AARCH64-ENTRY-SIGNATURE"),
            "sysv entry": (((B64,), (B64,), sysv), {"extra_types": (sysv, foreign_entry_code_type(SYSV_X86_64_C_ABI))}, "AARCH64-FOREIGN-ENTRY-TARGET"),
        }
        for name, (arguments, knobs, expected) in cases.items():
            with self.subTest(case=name):
                reader, function, target = _address_of(*arguments, **knobs)
                mine, reference = _decisions(reader, (function.cid,), target)
                self.assertEqual(mine, reference)
                self.assertEqual(mine[0] if expected == "bundle" else mine[1].rule, expected)

    def test_frame_path_and_register_allocator_builds(self):
        import pytest

        recorder = _Recorder()
        status = pytest.main(["-q", "-p", "no:cacheprovider", "-p", "no:xdist",
                              str(TESTS / "test_xax_android_platform_emulated.py") + "::test_aaudio_output_stream_builds_writes_and_closes",
                              str(TESTS / "test_xax_android_bfc.py") + "::SharedHost::test_bbc_bind_record_binds_and_builds"],
                             plugins=[recorder])
        self.assertEqual(status, 0)
        self.assertGreaterEqual(len(recorder.outcomes), 2)
        for mine, reference in recorder.outcomes:
            self.assertEqual(mine[0], "bundle")
            self.assertEqual(mine, reference)


if __name__ == "__main__":
    unittest.main()
