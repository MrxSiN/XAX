"""Whether this host can build a wheel at all.

The wheel tests build the project with the host's setuptools (``--no-build-isolation``).  Some distribution builds of
setuptools cannot build any package on the interpreter they run under (Debian's setuptools 68 on a Python without
Debian's distutils patch fails in ``install_lib`` with ``AttributeError: install_layout``).  That is a property of the
host, not of the project, so the wheel tests skip there; a trivial package decides it.
"""

from __future__ import annotations

import functools
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path


@functools.lru_cache(maxsize=1)
def host_builds_wheels() -> bool:
    if importlib.util.find_spec("setuptools") is None:
        return False
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "probe").mkdir()
        (root / "probe" / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n\n'
            '[project]\nname = "xax-wheel-probe"\nversion = "0"\n\n[tool.setuptools]\npy-modules = ["probe_module"]\n')
        (root / "probe" / "probe_module.py").write_text("")
        completed = subprocess.run([sys.executable, "-m", "pip", "wheel", str(root / "probe"), "--no-deps", "--no-build-isolation",
                                    "--wheel-dir", str(root / "out")], capture_output=True, timeout=600)
        return completed.returncode == 0


SKIP_REASON = "UNAVAILABLE: this host's setuptools cannot build any wheel (checked with a trivial package)"
