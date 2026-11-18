"""Self-hosting step S15a (ADR-286): the Linux x86-64 production compiler's seed is an XAX-built compiler, not Python.

``bootstrap/seed/`` holds:

* ``xaxc-linux-x86_64``: the production compiler (the general driver) as its own build made it, a static ELF64
  executable with no interpreter.
* ``xax_compiler_request.xax``: the compiler's canonical build request store, derived from the driver store
  (``evolution/request-tool``), the input the seed resolves and builds.
* ``selfbuild.sh``: the seed resolves and builds the request into the next compiler, and that compiler does it again;
  only ``sh``, ``dirname``, ``mkdir``, ``chmod``, and ``cmp`` run besides the compilers.

ADR-410: the seeds' pins are the release record ``bootstrap/RELEASES``, read by the native release tool
(``seed/rotate-tool``, ``pin``), and a seed is replaced only by ``seed/rotate.sh`` (``build``, ``confirm``,
``validate``).  The B levels are the native ``xax_evidence levels`` of the latest validated release's V2 record.
Both tools run on Linux x86-64; nothing here builds a compiler or derives a level in Python.
"""

from __future__ import annotations

import atexit
import functools
import shutil
import subprocess
import tempfile
from pathlib import Path

from xax_native import bootstrap_dir

BOOTSTRAP = bootstrap_dir()
SEED_DIRECTORY = BOOTSTRAP / "seed"
SEED_PATH = SEED_DIRECTORY / "xaxc-linux-x86_64"
REQUEST_PATH = SEED_DIRECTORY / "xax_compiler_request.xax"
SELFBUILD_PATH = SEED_DIRECTORY / "selfbuild.sh"
SELFBUILD_TOOLS = ("sh", "dirname", "mkdir", "chmod", "cmp")
LINUX_TARGET, WINDOWS_TARGET = "x86_64-linux-elf-exec-v1", "x86_64-windows-pe-v1"
ROTATE_STORE = SEED_DIRECTORY / "rotate-tool" / "xax_rotate.xax"
EVIDENCE = BOOTSTRAP / "evidence"


@functools.cache
def native_tool(store: Path) -> Path:
    """The XAX tool program ``store`` as the seed builds it (once per process, as ``rotate.sh`` does)."""
    directory = Path(tempfile.mkdtemp(prefix="xax-tool-"))
    atexit.register(shutil.rmtree, directory, True)
    for arguments in (("resolve", store, directory / "tool.xax"), ("build", directory / "tool.xax", directory / "tool", directory / "provenance")):
        subprocess.run([str(SEED_PATH), *map(str, arguments)], check=True, capture_output=True)
    (directory / "tool").chmod(0o755)
    return directory / "tool"


def run_tool(store: Path, *arguments) -> str:
    return subprocess.run([str(native_tool(store)), *map(str, arguments)], check=True, capture_output=True).stdout.decode()


def identity(path: Path) -> tuple[str, int]:
    """A file's SHA-256 and size as the release tool computes them (``id``)."""
    sha, size = run_tool(ROTATE_STORE, "id", path).strip().split(":")
    return sha, int(size)


def pin(target: str = LINUX_TARGET) -> tuple[str, int]:
    """The pinned seed of ``target``: its SHA-256 and size in the released (latest validated) release of RELEASES."""
    sha, size = run_tool(ROTATE_STORE, "pin", BOOTSTRAP, target).strip().split(":")
    return sha, int(size)


def released() -> str:
    """The latest validated release's name (``rotate.sh state``)."""
    return next(line.split()[1] for line in run_tool(ROTATE_STORE, "state", BOOTSTRAP).splitlines() if line.startswith("validated "))


def bootstrap_status() -> dict:
    """The one derivation of B0-B6 (XAX_SPEC.md 16.2, RFC section 4): the native ``levels`` of the latest validated
    release's V2 record; the generated status blocks consume it and nothing else asserts a B level.  S-step component
    fixed points are not B milestones (16.5)."""
    release = released()
    record = EVIDENCE / "records" / f"{release}.record"
    levels = dict(line.split() for line in run_tool(EVIDENCE / "xax_evidence.xax", "levels", record, EVIDENCE / "CORPUS",
                                                    EVIDENCE / "SNAPSHOTS", SEED_PATH).splitlines())
    held = {f"B{n}": levels[f"B{n}"] == "1" for n in range(7)}
    missing = [level for level, holds in held.items() if not holds]
    interpreter = next(line.split()[2] for line in record.read_text(encoding="ascii").splitlines() if line.startswith("seed "))
    sha, size = pin()
    return {
        "derivation_source": "xax_selfhost_seed.bootstrap_status",
        "records": [f"compiler/bootstrap/evidence/records/{release}.record"],
        "full_production_compiler": {**held, "blocker": f"release {release}'s V2 record, by `xax_evidence levels`"
                                     + (f"; {', '.join(missing)} do not hold" if missing else "")},
        "bootstrap_seed": {"kind": "native-elf" if interpreter == "0" else "elf-with-interpreter", "path": "compiler/bootstrap/seed/xaxc-linux-x86_64",
                           "bytes": size, "sha256": sha, "requires_python": levels["python"] == "1"},
    }
