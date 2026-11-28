"""The suite's scheduling conftest: the driver-sized group names real files, and a finished class loses its state."""

import unittest
from pathlib import Path
from types import SimpleNamespace

import conftest


class SchedulingTests(unittest.TestCase):
    def test_driver_sized_files_exist(self):
        here = Path(__file__).parent
        self.assertEqual([name for name in sorted(conftest.DRIVER_SIZED) if not (here / name).exists()], [])
        self.assertTrue(conftest.driver_sized(here / "test_xax_selfhost_android_bundle.py"))
        self.assertFalse(conftest.driver_sized(here / "test_suite_scheduling.py"))

    def test_class_state_dropped_after_last_test(self):
        class Probe:
            kept = 1

        first, second = SimpleNamespace(cls=Probe), SimpleNamespace(cls=Probe)
        conftest.pytest_runtest_setup(first)
        Probe.reader = object()  # what setUpClass leaves behind
        conftest.pytest_runtest_teardown(first, second)
        self.assertTrue(hasattr(Probe, "reader"), "kept while the class still has tests")
        conftest.pytest_runtest_teardown(second, None)
        self.assertFalse(hasattr(Probe, "reader"))
        self.assertEqual(Probe.kept, 1)


if __name__ == "__main__":
    unittest.main()
