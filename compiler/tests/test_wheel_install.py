"""WHEEL_IMPORT_CLOSURE and WHEEL_REQUIRED_STORES_PRESENT: the installed package is the source checkout.

Builds the wheel, installs only it into a fresh virtual environment, imports every compiler module there, checks the
packaged canonical stores byte for byte, runs ``xaxc``, and reports which implementation authority executed.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
MODULES = sorted(path.stem for path in (PROJECT / "src").glob("*.py"))
STORES = sorted(path.name for path in (PROJECT / "bootstrap").glob("*.xax"))

PROBE = """
import importlib, json, sys
import xax_native
modules = json.loads(sys.argv[1])
for name in modules:
    importlib.import_module(name)
import xax_compiler as X
directory = xax_native.bootstrap_dir()
stores = {path.name: path.read_bytes().hex() for path in sorted(directory.glob("*.xax"))}
X.verify_store(X.StoreReader(bytes.fromhex(stores["m11_compiler_subset.xax"])))
print(json.dumps({"bootstrap_dir": str(directory), "stores": stores, "authority": xax_native.AUTHORITY}))
"""


@unittest.skipUnless(importlib.util.find_spec("setuptools"), "setuptools is unavailable: the wheel cannot be built")
class WheelInstallTests(unittest.TestCase):
    def test_clean_install_has_every_module_and_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            subprocess.run([sys.executable, "-m", "pip", "wheel", str(PROJECT), "--no-deps", "--no-build-isolation", "--wheel-dir",
                            str(temporary / "dist")], check=True, capture_output=True)
            wheel = next((temporary / "dist").glob("*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                names = set(archive.namelist())
            self.assertEqual([m for m in MODULES if f"{m}.py" not in names], [], "modules missing from the wheel")
            data = "xax_compiler-0.1.0.data/data/share/xax/bootstrap/"
            self.assertEqual([s for s in STORES if data + s not in names], [], "canonical stores missing from the wheel")

            subprocess.run([sys.executable, "-m", "venv", str(temporary / "env")], check=True, capture_output=True)
            bindir = temporary / "env" / ("Scripts" if os.name == "nt" else "bin")
            python = bindir / ("python.exe" if os.name == "nt" else "python")
            # No PYTHONPATH: the source checkout on it would make pip treat the package as installed already.
            environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
            subprocess.run([str(python), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)], env=environment,
                           check=True, capture_output=True)
            probe = subprocess.run([str(python), "-c", PROBE, json.dumps(MODULES)], cwd=temporary, env=environment,
                                   capture_output=True, text=True)
            self.assertEqual(probe.returncode, 0, probe.stderr)
            report = json.loads(probe.stdout)
            self.assertTrue(report["bootstrap_dir"].startswith(str(temporary / "env")), report["bootstrap_dir"])
            for name in STORES:
                self.assertEqual(bytes.fromhex(report["stores"][name]), (PROJECT / "bootstrap" / name).read_bytes(), name)
            # Which implementation ran is recorded for every component touched, whichever host this is.
            self.assertIn("store-verifier", report["authority"])
            self.assertTrue(all("actual_authority" in entry for entry in report["authority"].values()))

            store = PROJECT / "bootstrap" / "m11_compiler_subset.xax"
            verified = subprocess.run([str(bindir / ("xaxc.exe" if os.name == "nt" else "xaxc")), "verify", str(store)],
                                      cwd=temporary, env=environment, capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)


if __name__ == "__main__":
    unittest.main()
