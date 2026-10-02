from __future__ import annotations

import json
from pathlib import Path
import unittest

from benchmarks.bench_android_resources import EVIDENCE_PATH, TABLE_PATH, collect_evidence, fixture
from xax_resources import inspect_resources_arsc


class AndroidResourcesEvidenceTests(unittest.TestCase):
    def test_committed_resource_evidence_matches_reproduction(self) -> None:
        expected = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(collect_evidence(), expected)
        _spec, _carrier, table = fixture()
        self.assertEqual(TABLE_PATH.read_bytes(), table)
        view = inspect_resources_arsc(table)
        self.assertEqual(view.package_name, "xax.generated")
        self.assertEqual(tuple(item.name for item in view.entries), ("app_name", "clicked", "greeting"))


if __name__ == "__main__":
    unittest.main()
