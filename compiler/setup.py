"""W4 (ADR-363): the wheel's top-level modules come from two directories.

``src/`` holds the native compiler's runners and tooling; ``reference/`` holds the Python reference compiler.  Both are
top-level modules of the installed package.  The module list is every ``*.py`` in the two directories (a hand-kept list
drifted), and setuptools maps every top-level module to one directory, so ``build_py`` here finds each module in
``src/`` or ``reference/``.  Everything else is configured in ``pyproject.toml``.
"""

from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOTS = ("src", "reference")


class TwoRootBuildPy(build_py):
    def find_modules(self):
        found = []
        for module in self.py_modules:
            paths = [Path(root) / f"{module}.py" for root in ROOTS if (Path(root) / f"{module}.py").is_file()]
            if len(paths) != 1:
                raise SystemExit(f"module {module}: found in {[str(path) for path in paths] or 'neither src/ nor reference/'}")
            found.append(("", module, str(paths[0])))
        return found


HERE = Path(__file__).resolve().parent
MODULES = sorted(path.stem for root in ROOTS for path in (HERE / root).glob("*.py"))
setup(py_modules=MODULES, cmdclass={"build_py": TwoRootBuildPy})
