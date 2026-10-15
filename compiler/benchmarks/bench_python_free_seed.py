"""S15a (ADR-286): the compiler rebuilds itself from the pinned XAX-built seed with no Python reachable.

``bootstrap/seed/selfbuild.sh`` runs under ``env -i`` with ``PATH`` set to a directory holding only links to
``SELFBUILD_TOOLS`` (no ``python``, no ``python3``, no ``PYTHONPATH``).  Recorded, raw: the seed's and request store's
digests, whether the seed has an ELF interpreter, the tools, whether a Python resolves on that ``PATH``, the script's
exit status, and the digests of the two compilers it builds.  ``xax_selfhost.bootstrap_status`` decides from this
record whether the Linux x86-64 seed requires Python.  Run: ``PYTHONPATH=src python benchmarks/bench_python_free_seed.py
[--write]``.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parent / "python_free_seed_evidence.json"


def sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def has_interpreter(data: bytes) -> bool:
    count, size, offset = int.from_bytes(data[56:58], "little"), int.from_bytes(data[54:56], "little"), int.from_bytes(data[32:40], "little")
    return any(int.from_bytes(data[offset + k * size:offset + k * size + 4], "little") == 3 for k in range(count))


def measure() -> dict:
    from xax_selfhost_seed import REQUEST_PATH, SEED_PATH, SELFBUILD_PATH, SELFBUILD_TOOLS

    directory = Path(tempfile.mkdtemp(prefix="xax-seed-"))
    tools = directory / "tools"
    tools.mkdir()
    for tool in SELFBUILD_TOOLS:
        os.symlink(shutil.which(tool), tools / tool)
    environment = {"PATH": str(tools)}
    probe = subprocess.run(["/bin/sh", "-c", "command -v python3 || command -v python || true"], env=environment, capture_output=True, text=True)
    output = directory / "out"
    start = time.perf_counter()
    status = subprocess.run([str(tools / "sh"), str(SELFBUILD_PATH), str(output)], env=environment, check=False).returncode
    seconds = time.perf_counter() - start
    return {
        "format": "xax-python-free-seed-evidence-v1",
        "label": "EXECUTED",
        "adr": "ADR-286",
        "host_nonsemantic": f"{platform.system()} {platform.machine()}",
        "seed": {"path": "compiler/bootstrap/seed/xaxc-linux-x86_64", "sha256": sha(SEED_PATH), "bytes": SEED_PATH.stat().st_size,
                 "has_interpreter": has_interpreter(SEED_PATH.read_bytes())},
        "request_store_sha256": sha(REQUEST_PATH),
        "environment": {"variables": sorted(environment), "tools": list(SELFBUILD_TOOLS), "python_on_path": probe.stdout.strip() or None},
        "selfbuild_status": status,
        "generations": [{"name": f"xaxc{n}", "sha256": sha(output / f"xaxc{n}"), "snapshot_sha256": sha(output / f"snapshot{n}.xax"),
                         "provenance_sha256": sha(output / f"provenance{n}")} for n in (1, 2)],
        "host_s_nonsemantic": round(seconds, 1),
    }


if __name__ == "__main__":
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
