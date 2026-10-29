"""S15e.6h.2 (ADR-355): unsigned APKs built by the XAX Android program equal the bootstrap's.

``xax_build._build_android_unsigned_apk`` asks the XAX Android program (``xax_selfhost_android.android_with_xax``)
first.  The program decodes the package's carriers from the general object table, decides the profile's rule sites
(the rules programs on the facts it derives), lowers the bridges and chains the AArch64, ELF, manifest, DEX,
resource-table and APK programs.  Every unsigned build of ``test_xax_build`` runs under
``XAX_GENERAL_FRONTEND_DIFF=1``, which rebuilds each APK the program decided with the bootstrap and requires the same
bytes, and each rejection the program decided with the same diagnostic: the plain, method, argument-method and resource
Activity UIs, the application, receiver and service components, and the libxposed module profiles (metadata, the
generated managed entry, hook adapters and installations, the result, argument and combined mutation policies,
deoptimization, module services, remote preferences), the managed-class profile and the declarative surface Activity.
None is declined.
"""

from __future__ import annotations

import os
import platform
import sys
import unittest
from pathlib import Path
from unittest import mock

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
TESTS = Path(__file__).resolve().parent


class _Recorder:
    """A pytest plugin: every ``android_with_xax`` call (an APK, a rejection or a decline) with the package's carrier
    classes."""

    def __init__(self):
        self.calls = []

    def pytest_configure(self, config):
        import xax_selfhost_android as A

        original = getattr(A, "_unrecorded_android_with_xax", A.android_with_xax)
        A._unrecorded_android_with_xax = original

        def recorded(reader, package_view, target_object, entry, required=False):
            from xax_compiler import Cursor, Kind

            classes = set()
            for module in package_view.modules:
                for cid in reader.get(module).references:
                    child = reader.get(cid)
                    if child.kind == Kind.TARGET and not child.references:
                        identity = Cursor(child.body, child.cid.hex()).byte_string()
                        classes.update(name for name, prefix in A.CLASSES if identity.startswith(prefix))
            from xax_compiler import XaxError

            try:
                built = original(reader, package_view, target_object, entry, required=required)
            except XaxError:
                self.calls.append(("rejected", frozenset(classes)))
                raise
            self.calls.append(("apk" if built is not None else "declined", frozenset(classes)))
            return built

        A.android_with_xax = recorded

    def pytest_unconfigure(self, config):
        import xax_selfhost_android as A

        A.android_with_xax = A.__dict__.pop("_unrecorded_android_with_xax")


@unittest.skipUnless(LINUX_X86_64, "the XAX Android program runs natively on Linux x86-64")
class SelfhostAndroidTests(unittest.TestCase):
    def test_unsigned_profiles_equal_the_bootstrap(self):
        import pytest

        recorder = _Recorder()
        with mock.patch.dict(os.environ, {"XAX_GENERAL_FRONTEND_DIFF": "1"}):
            status = pytest.main(["-q", "-p", "no:cacheprovider", "-p", "no:xdist", str(TESTS / "test_xax_build.py"), "-k", "android or apk"],
                                 plugins=[recorder])
        self.assertEqual(status, 0)
        outcomes = [outcome for outcome, _classes in recorder.calls]
        self.assertNotIn("declined", outcomes)
        self.assertGreaterEqual(outcomes.count("rejected"), 4)
        decided = [classes for outcome, classes in recorder.calls if outcome == "apk"]
        self.assertGreaterEqual(len(decided), 20)
        for profile in ({"ui_plain"}, {"ui_method"}, {"ui_resource", "resources"}, {"application"}, {"receiver"}, {"service"},
                        {"libxposed", "managed_entry", "adapter", "install", "result"}, {"argument"}, {"combined"}, {"deopt"},
                        {"services", "preferences"}):
            with self.subTest(profile=sorted(profile)):
                self.assertTrue(any(profile <= classes for classes in decided))

    def test_managed_class_and_surface_profiles(self):
        """S15e.6h.2c: the managed-class profile (classes, platform declarations, the JNI signatures and the platform rules
        the managed rules program decides) and the declarative surface Activity, with their rejections."""
        import pytest

        recorder = _Recorder()
        files = ("test_xax_android_managed.py", "test_xax_selfhost_android_managed_rules.py", "test_xax_android_surface.py")
        with mock.patch.dict(os.environ, {"XAX_GENERAL_FRONTEND_DIFF": "1"}):
            status = pytest.main(["-q", "-p", "no:cacheprovider", "-p", "no:xdist", *(str(TESTS / name) for name in files)], plugins=[recorder])
        self.assertEqual(status, 0)
        outcomes = [outcome for outcome, _classes in recorder.calls]
        self.assertNotIn("declined", outcomes)
        for profile in ({"managed"}, {"managed", "declarations"}, {"surface"}):
            with self.subTest(profile=sorted(profile)):
                self.assertTrue(any(outcome == "apk" and profile <= classes for outcome, classes in recorder.calls))
                self.assertTrue(any(outcome == "rejected" and profile <= classes for outcome, classes in recorder.calls))


if __name__ == "__main__":
    unittest.main()
