"""ADR-180: the Python-authority inventory covers every compiler module and every A/B component is described."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

COMPILER = Path(__file__).resolve().parents[1]
INVENTORY = COMPILER / "migration" / "python_authority_inventory.json"
FIELDS = {"python_authority", "xax_hosted", "target_dependency", "prerequisite", "differential_oracle", "fixed_point_relevance",
          "runtime_relevance", "recommended_step"}


class PythonAuthorityInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

    def test_every_source_module_is_classified_once(self):
        modules = {path.name for path in (COMPILER / "src").glob("*.py")}
        self.assertEqual(set(self.inventory["modules"]), modules)
        for name, entry in self.inventory["modules"].items():
            with self.subTest(module=name):
                self.assertIn(entry["class"], self.inventory["classes"])

    def test_authoritative_modules_name_described_components(self):
        components = self.inventory["components"]
        for name, entry in self.inventory["modules"].items():
            with self.subTest(module=name):
                if entry["class"] in ("A", "B"):
                    self.assertTrue(entry.get("components"), "an A/B module names its components")
                for component in entry.get("components", ()):
                    self.assertIn(component, components)
        for name, component in components.items():
            with self.subTest(component=name):
                self.assertEqual(set(component), FIELDS)

    def test_no_component_is_orphaned(self):
        named = {component for entry in self.inventory["modules"].values() for component in entry.get("components", ())}
        self.assertEqual(named, set(self.inventory["components"]))


if __name__ == "__main__":
    unittest.main()
