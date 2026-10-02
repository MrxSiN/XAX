"""Generate the committed M14 compiler, immutable seed runner, and evidence.

Run only at the M14 completion/validation gate.  Generated evidence records only
checks actually executed by this process.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipapp

from blake3 import blake3

from xax_selfhost import (
    M14_CLOSURE_TARGET,
    M14_EVIDENCE_FILENAME,
    M14_PROGRAM_FILENAME,
    create_m14_program_store,
    execute_m14_recursive_evidence,
    readiness_from_recursive_evidence,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT / "src"
SEED_FILENAME = "m14_seed_runtime.pyz"
SEED_SOURCE_FILES = ("blake3.py", "xax_compiler.py", "xax_selfhost.py")
SEED_ZIP_LOCAL_TIME = (1980, 1, 1, 0, 0, 0, 0, 1, -1)


def _hex(value: bytes) -> str:
    return value.hex()


def _build_seed_archive(target: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="xax-m14-seed-") as directory:
        stage = Path(directory)
        zip_epoch = time.mktime(SEED_ZIP_LOCAL_TIME)
        for filename in SEED_SOURCE_FILES:
            shutil.copy2(SRC / filename, stage / filename)
            os.utime(stage / filename, (zip_epoch, zip_epoch))
        shutil.copy2(HERE / "m14_seed_main.py", stage / "__main__.py")
        os.utime(stage / "__main__.py", (zip_epoch, zip_epoch))
        zipapp.create_archive(stage, target=target, interpreter="/usr/bin/env python3", compressed=True)


def main() -> int:
    program_reader = create_m14_program_store()
    program_bytes = program_reader.canonical_bytes()
    program_path = HERE / M14_PROGRAM_FILENAME
    program_path.write_bytes(program_bytes)

    recursive = execute_m14_recursive_evidence(program_reader)
    readiness = readiness_from_recursive_evidence(recursive)
    if not (recursive.b2 and recursive.b3 and recursive.b4 and recursive.b5 and readiness.b5):
        raise SystemExit("M14 recursive/closure evidence did not satisfy B2-B5")

    seed_path = HERE / SEED_FILENAME
    _build_seed_archive(seed_path)
    with tempfile.TemporaryDirectory(prefix="xax-m14-repository-independent-") as directory:
        rebuilt_path = Path(directory) / M14_PROGRAM_FILENAME
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [sys.executable, str(seed_path), "rebuild", str(program_path), str(rebuilt_path)],
            cwd=directory,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        rebuilt = rebuilt_path.read_bytes() if rebuilt_path.exists() else b""
    repository_source_independent_reconstruction = completed.returncode == 0 and rebuilt == program_bytes
    if not repository_source_independent_reconstruction:
        raise SystemExit(completed.stderr.strip() or "immutable M14 seed failed repository-source-independent reconstruction")

    seed_bytes = seed_path.read_bytes()
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
        "b2_recursive_compilation": recursive.b2,
        "b3_semantic_equivalence": recursive.b3,
        "b4_deterministic_fixed_point": recursive.b4,
        "b5_semantic_image_toolchain_closure": recursive.b5,
        "seed_runtime": {
            "filename": SEED_FILENAME,
            "sha256": hashlib.sha256(seed_bytes).hexdigest(),
            "blake3_256": blake3(seed_bytes).hexdigest(),
            "python_runtime": sys.version.split()[0],
            "source_files_bundled": list(SEED_SOURCE_FILES),
            "repository_pythonpath_removed": True,
            "repository_source_independent_reconstruction": repository_source_independent_reconstruction,
            "immutable_seed_boundary": True,
            "stdout": completed.stdout.strip(),
        },
        "b6_bootstrap_independence": repository_source_independent_reconstruction,
        "scope": (
            "B5/B6 apply only to xax-semantic-image-v1. Legacy x86-64, AArch64, "
            "WebAssembly, and accelerator lowerers remain bootstrap/reference implementations "
            "and are not included in this closure claim."
        ),
    }
    (HERE / M14_EVIDENCE_FILENAME).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
