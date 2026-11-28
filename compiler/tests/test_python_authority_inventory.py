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
        modules = {path.name for directory in ("src", "reference") for path in (COMPILER / directory).glob("*.py")}
        self.assertEqual(set(self.inventory["modules"]), modules)
        for name, entry in self.inventory["modules"].items():
            with self.subTest(module=name):
                self.assertIn(entry["class"], self.inventory["classes"])

    def test_every_python_file_outside_reference_is_listed(self):
        """The retirement inventory: each Python file outside ``reference/`` and ``src/`` (tests aside) names who runs it
        and whether the release needs it; each ``src/`` module says whether the release needs it."""
        found = {path.relative_to(COMPILER).as_posix() for path in COMPILER.rglob("*.py")
                 if path.relative_to(COMPILER).parts[0] not in ("src", "reference", "build")
                 and "__pycache__" not in path.parts and not path.name.startswith("test_") and path.name != "conftest.py"}
        self.assertEqual(set(self.inventory["files"]), found)
        for name, entry in self.inventory["files"].items():
            with self.subTest(file=name):
                self.assertIn(entry["class"], self.inventory["classes"])
                self.assertTrue(entry["run_by"])
                self.assertIsInstance(entry["release"], bool)
        for name in (path.name for path in (COMPILER / "src").glob("*.py")):
            with self.subTest(module=name):
                self.assertIsInstance(self.inventory["modules"][name]["release"], bool)

    def test_the_python_compiler_is_in_reference(self):
        """W4 (ADR-363): the Python compiler (classes A, B and C, and the M11 Python seed) is in ``reference/``; ``src/``
        holds the native compiler's runners, generated-store modules and tooling (classes D, E, G, and the native seed's)."""
        for name, entry in self.inventory["modules"].items():
            with self.subTest(module=name):
                reference = entry["class"] in ("A", "B", "C") or name == "xax_bootstrap.py"
                self.assertTrue((COMPILER / ("reference" if reference else "src") / name).is_file())

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
