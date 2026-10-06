"""Generate the committed M14 compiler store and its evidence; check (never rewrite) the immutable seed.

``python bootstrap/generate_m14.py`` regenerates ``m14_selfhost_compiler.xax`` and ``m14_selfhost_evidence.json``.
It reads the committed seed, refuses to run if the seed is not the pinned one, and never writes it.  B levels in the
evidence come from ``xax_selfhost.bootstrap_status``; nothing here asserts one.

``python bootstrap/generate_m14.py rotate-seed`` is the only way to make a new seed: it packs the current
``SEED_SOURCE_FILES`` deterministically and writes the seed.  The tests then fail until a reviewer pins the printed
digest and size in ``SEED_SHA256``/``SEED_SIZE`` (a seed rotation is a reviewed change, ``README.md`` here).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from blake3 import blake3

from xax_selfhost import (
    M14_CLOSURE_TARGET,
    M14_EVIDENCE_FILENAME,
    M14_PROGRAM_FILENAME,
    bootstrap_status,
    create_m14_program_store,
    execute_m14_recursive_evidence,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT / "src"
SEED_FILENAME = "m14_seed_runtime.pyz"
SEED_SOURCE_FILES = ("blake3.py", "xax_compiler.py", "xax_selfhost.py")
# The pinned immutable seed.  Change only through ``rotate-seed`` plus review.
SEED_SHA256 = "4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52"
SEED_SIZE = 46_255
SEED_KIND = "python-zipapp"
SHEBANG = b"#!/usr/bin/env python3\n"
ROTATION_TIME = (1980, 1, 1, 0, 0, 0)


def pack_seed(entries: list[tuple[str, tuple[int, int, int, int, int, int], bytes]]) -> bytes:
    """A zipapp whose bytes depend only on ``entries`` (name, zip date_time, content) in the given order: fixed
    shebang, deflate, Unix mode 0644, no extra fields.  Host clock, umask, file order, and OS never reach it."""
    buffer = io.BytesIO()
    buffer.write(SHEBANG)
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, date_time, content in entries:
            info = zipfile.ZipInfo(name, date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, content)
    return buffer.getvalue()


def seed_entries(data: bytes) -> list[tuple[str, tuple[int, int, int, int, int, int], bytes]]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return [(info.filename, info.date_time, archive.read(info.filename)) for info in archive.infolist()]


def seed_manifest(data: bytes) -> list[dict]:
    return [{"name": name, "zip_date_time": list(date_time), "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, date_time, content in seed_entries(data)]


def committed_seed() -> bytes:
    """The committed seed, or SystemExit when it is not the pinned one."""
    data = (HERE / SEED_FILENAME).read_bytes()
    if hashlib.sha256(data).hexdigest() != SEED_SHA256 or len(data) != SEED_SIZE:
        raise SystemExit(f"{SEED_FILENAME} is not the pinned seed (sha256 {SEED_SHA256}, {SEED_SIZE} bytes)")
    return data


def rotation_seed() -> bytes:
    """The seed a rotation would install: the current seed sources, packed with fixed metadata."""
    entries = [("__main__.py", ROTATION_TIME, (HERE / "m14_seed_main.py").read_bytes())]
    entries += [(name, ROTATION_TIME, (SRC / name).read_bytes()) for name in SEED_SOURCE_FILES]
    return pack_seed(entries)


def rotate_seed() -> int:
    data = rotation_seed()
    (HERE / SEED_FILENAME).write_bytes(data)
    print(json.dumps({"seed": SEED_FILENAME, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                      "next": "review the new seed, then pin SEED_SHA256/SEED_SIZE in generate_m14.py"}, indent=2))
    return 0


def _hex(value: bytes) -> str:
    return value.hex()


def main() -> int:
    seed_bytes = committed_seed()
    program_reader = create_m14_program_store()
    program_bytes = program_reader.canonical_bytes()
    program_path = HERE / M14_PROGRAM_FILENAME
    program_path.write_bytes(program_bytes)

    recursive = execute_m14_recursive_evidence(program_reader)
    status = bootstrap_status(recursive)
    if not (recursive.b2 and recursive.b3 and recursive.b4):
        raise SystemExit("M14 recursive evidence did not satisfy B2-B4 for the semantic-image wrapper")

    with tempfile.TemporaryDirectory(prefix="xax-m14-repository-independent-") as directory:
        rebuilt_path = Path(directory) / M14_PROGRAM_FILENAME
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [sys.executable, str(HERE / SEED_FILENAME), "rebuild", str(program_path), str(rebuilt_path)],
            cwd=directory,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        rebuilt = rebuilt_path.read_bytes() if rebuilt_path.exists() else b""
    reconstruction = completed.returncode == 0 and rebuilt == program_bytes
    if not reconstruction:
        raise SystemExit(completed.stderr.strip() or "immutable M14 seed failed repository-source-independent reconstruction")

    evidence = {
        "milestone": "M14",
        "closure_target": M14_CLOSURE_TARGET.decode("ascii"),
        "compiler_root": _hex(recursive.compiler_root),
        "compiler_function": _hex(recursive.compiler_function),
        "generation_digests": [
            _hex(recursive.generation0_digest),
            _hex(recursive.generation1_digest),
            _hex(recursive.generation2_digest),
        ],
        "generation_roots": [_hex(recursive.compiler_root), _hex(recursive.generation1_root), _hex(recursive.generation2_root)],
        "equivalence_vectors": [
            {
                "input_cid": _hex(item.input_cid),
                "generation0_digest": _hex(item.generation0_digest),
                "generation1_digest": _hex(item.generation1_digest),
                "matches": item.matches,
            }
            for item in recursive.vectors
        ],
        "bootstrap_status": status,
        "seed_runtime": {
            "filename": SEED_FILENAME,
            "seed_kind": SEED_KIND,
            "requires_python": True,
            "sha256": hashlib.sha256(seed_bytes).hexdigest(),
            "size": len(seed_bytes),
            "blake3_256": blake3(seed_bytes).hexdigest(),
            "contents_manifest": seed_manifest(seed_bytes),
            "packing_reproduces_seed": pack_seed(seed_entries(seed_bytes)) == seed_bytes,
            "seed_builder_revision": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "python_runtime_nonsemantic": sys.version.split()[0],
            "repository_pythonpath_removed": True,
            "repository_source_independent_reconstruction": reconstruction,
            "stdout": completed.stdout.strip(),
        },
        "scope": status["m14_semantic_image_wrapper"]["scope"],
    }
    (HERE / M14_EVIDENCE_FILENAME).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(rotate_seed() if sys.argv[1:] == ["rotate-seed"] else main())
