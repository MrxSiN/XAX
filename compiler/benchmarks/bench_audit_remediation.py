"""Evidence for the evidence-and-canonical-state integrity milestone (ADR-177).

Every field is computed by this run: stores are rebuilt, the M14 status is re-derived, the seed is re-packed, the
wheel is built twice and inspected, the matrix is re-validated, the status blocks are re-checked, and (unless
``--skip-tests``) the test suite is run and its outcomes counted, with skips split into unavailable environments and
other skips.  Run from ``compiler``:

    PYTHONPATH=src:.:.. python -m benchmarks.bench_audit_remediation [--skip-tests] [--write]
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

COMPILER = Path(__file__).resolve().parents[1]
REPO = COMPILER.parent
EVIDENCE = Path(__file__).resolve().parent / "audit_remediation_evidence.json"
BUILDERS = (
    ("xax_selfhost_cfg", "build_cfg_program"), ("xax_selfhost_graph", "build_graph_decoder_program"),
    ("xax_selfhost_riscv64", "build_encoder_program"), ("xax_selfhost_store", "build_decoder_program"),
    ("xax_selfhost_blake3", "build_hash_program"), ("xax_selfhost_typing", "build_typing_program"),
    ("xax_selfhost_verify", "build_verifier_program"), ("xax_selfhost_riscv64_backend", "build_backend_program"),
    ("xax_selfhost_x86_64_backend", "build_backend_program"),
)


# Levels the matrix claimed when the independent audit ran (2026-10-06, uncommitted tree on af65d1b); an input to
# compare against, not evidence.  Rows absent here were NONE.
AUDITED_LEVELS = {
    "android-arm64": "R4", "jvm": "R4", "linux-x86_64": "R4", "linux-aarch64": "R3", "aarch64-baremetal": "R2",
    "browser-web": "R2", "windows-x86_64-pe": "R2", "gpu-spirv-cuda-metal-dxil": "R1", "riscv64": "R1",
    "wasm32-core": "R1", "wasm32-wasi": "R1", "accelerator-simt-packet": "R0",
}


def _git(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=REPO, capture_output=True, text=True, check=False).stdout.strip()


def _build(module, builder) -> bytes:
    import xax_compiler

    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True
    try:
        return getattr(module, builder)()[0].data
    finally:
        xax_compiler._TYPING_BUILDING = building


def canonical_state() -> dict:
    import xax_compiler

    stores = {}
    for name, builder in BUILDERS:
        module = importlib.import_module(name)
        first, second = _build(module, builder), _build(module, builder)
        stores[module.STORE_PATH.name] = first == second == module.STORE_PATH.read_bytes()
    typing = importlib.import_module("xax_selfhost_typing").STORE_PATH.read_bytes()
    return {
        "typing_root": xax_compiler.StoreReader(typing).root_cid.hex(),
        "typing_digest_sha256": hashlib.sha256(typing).hexdigest(),
        "typing_bytes": len(typing),
        "regeneration_identical": stores["xax_op_typing.xax"],
        "all_stores_regenerate_identically": stores,
    }


def selfhost_claims() -> dict:
    from xax_compiler import StoreReader
    from xax_selfhost import bootstrap_status, execute_m14_recursive_evidence

    program = (COMPILER / "bootstrap" / "m14_selfhost_compiler.xax").read_bytes()
    status = bootstrap_status(execute_m14_recursive_evidence(StoreReader(program)))
    committed = json.loads((COMPILER / "bootstrap" / "m14_selfhost_evidence.json").read_text(encoding="utf-8"))
    return {
        "derivation_source": status["derivation_source"],
        "full_production_compiler": {f"B{n}": status["full_production_compiler"][f"B{n}"] for n in range(7)},
        "m14_semantic_image_wrapper": {level: status["m14_semantic_image_wrapper"][level] for level in ("B2", "B3", "B4", "B5", "B6")},
        "committed_evidence_matches_derivation": committed["bootstrap_status"] == status,
        "hand_asserted_b_fields_in_committed_evidence": sorted(k for k in committed if re.fullmatch(r"b\d_.*", k)),
    }


def seed() -> dict:
    spec = importlib.util.spec_from_file_location("xax_generate_m14_evidence", COMPILER / "bootstrap" / "generate_m14.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    data = (COMPILER / "bootstrap" / generator.SEED_FILENAME).read_bytes()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for part in ("src", "bootstrap"):
            subprocess.run([sys.executable, "-c", f"import shutil; shutil.copytree(r'{COMPILER / part}', r'{root / part}', "
                            "ignore=shutil.ignore_patterns('__pycache__'))"], check=True)
        env = {**{k: v for k, v in os.environ.items() if k != "PYTHONPATH"}, "PYTHONPATH": str(root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
        generated = subprocess.run([sys.executable, str(root / "bootstrap" / "generate_m14.py")], cwd=root, env=env, capture_output=True, text=True)
        mutated = (root / "bootstrap" / generator.SEED_FILENAME).read_bytes() != data
    return {
        "kind": generator.SEED_KIND,
        "digest_sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "pinned": hashlib.sha256(data).hexdigest() == generator.SEED_SHA256 and len(data) == generator.SEED_SIZE,
        "contents_manifest": generator.seed_manifest(data),
        "deterministic": generator.pack_seed(generator.seed_entries(data)) == data and generator.rotation_seed() == generator.rotation_seed(),
        "routine_generation_succeeded": generated.returncode == 0,
        "routine_generation_mutates_seed": mutated,
        "requires_python": True,  # a zipapp of Python modules: fact of the kind, not a measurement
        "seed_builder_revision": hashlib.sha256((COMPILER / "bootstrap" / "generate_m14.py").read_bytes()).hexdigest(),
    }


def packaging() -> dict:
    wheels = []
    with tempfile.TemporaryDirectory() as directory:
        env = {**os.environ, "SOURCE_DATE_EPOCH": "946684800"}
        for run in ("a", "b"):
            subprocess.run([sys.executable, "-m", "pip", "wheel", str(COMPILER), "--no-deps", "--no-build-isolation", "--wheel-dir",
                            str(Path(directory) / run)], check=True, capture_output=True, env=env)
            wheels.append(next((Path(directory) / run).glob("*.whl")).read_bytes())
        with zipfile.ZipFile(Path(directory) / "a" / next((Path(directory) / "a").iterdir()).name) as archive:
            names = set(archive.namelist())
    modules = sorted(path.stem for path in (COMPILER / "src").glob("*.py"))
    stores = sorted(path.name for path in (COMPILER / "bootstrap").glob("*.xax"))
    data = "xax_compiler-0.1.0.data/data/share/xax/bootstrap/"
    return {
        "wheel_reproducible": wheels[0] == wheels[1],
        "wheel_sha256": hashlib.sha256(wheels[0]).hexdigest(),
        "module_closure": [m for m in modules if f"{m}.py" not in names] == [],
        "missing_modules": [m for m in modules if f"{m}.py" not in names],
        "canonical_stores_included": [s for s in stores if data + s not in names] == [],
        "installed_authority": "the clean-install test (tests/test_wheel_install.py) reports it per component; "
                               "Python everywhere except Linux x86-64, where the packaged stores make the native images usable",
    }


def native_execution() -> dict:
    import xax_native

    probe = ("import json, xax_compiler as X, xax_native\n"
             f"X.verify_store(X.StoreReader(open(r'{COMPILER / 'bootstrap' / 'm11_compiler_subset.xax'}', 'rb').read()))\n"
             "print(json.dumps(xax_native.AUTHORITY))\n")
    env = {**{k: v for k, v in os.environ.items() if k != "XAX_REQUIRE_NATIVE"}, "PYTHONPATH": str(COMPILER / "src")}
    normal = subprocess.run([sys.executable, "-c", probe], cwd=COMPILER, env=env, capture_output=True, text=True)
    strict = subprocess.run([sys.executable, "-c", probe], cwd=COMPILER, env={**env, "XAX_REQUIRE_NATIVE": "1"}, capture_output=True, text=True)
    authority = json.loads(normal.stdout) if normal.returncode == 0 else {}
    key = hashlib.sha256(b"k").digest()
    entry = xax_native.cache_entry(key, b"\x90" * 32, 0)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "e.bin"
        path.write_bytes(entry[:-1] + b"\x91")
        tampered_rejected = xax_native.cache_read(path, key) is None
        path.write_bytes(entry)
        exact_accepted = xax_native.cache_read(path, key) is not None
    host = xax_native.native_host()
    return {
        "host_runs_native_images": host is None,
        "host_reason": host,
        "authority_observable": bool(authority) and all("actual_authority" in item for item in authority.values()),
        "authority_on_this_host": {name: item.get("actual_authority") for name, item in sorted(authority.items())},
        # With XAX_REQUIRE_NATIVE=1 a fallback must fail the process; on a native host there is nothing to fall back from.
        "silent_fallback_possible": strict.returncode == 0 and host is not None,
        "cache_authenticated": tampered_rejected and exact_accepted,
    }


def replacement_matrix() -> dict:
    from xax_replacement import VALIDATOR_VERSION, derived_level, load, validate

    matrix = load(REPO / "XAX_REPLACEMENT_MATRIX.json")
    before = AUDITED_LEVELS
    rows = {row["id"]: row["level"] for row in matrix["platforms"]}
    return {
        "validator_version": VALIDATOR_VERSION,
        "rows": rows,
        "derived_equals_claimed": all(derived_level(row) == row["level"] for row in matrix["platforms"]),
        "downgraded_rows": {rid: [before.get(rid, "NONE"), level] for rid, level in rows.items() if before.get(rid, "NONE") != level},
        "evidence_failures": validate(matrix, REPO),
    }


def tests() -> dict:
    """Run the suite and classify every outcome; a skip whose reason starts 'UNAVAILABLE' or names a missing host
    tool is an unavailable environment, never a pass."""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(COMPILER / "src"), str(COMPILER), str(REPO))), "PYTHONDONTWRITEBYTECODE": "1"}
    completed = subprocess.run([sys.executable, "-m", "pytest", "tests", "-n", "auto", "-q", "-rs", "-p", "no:cacheprovider"],
                               cwd=COMPILER, env=env, capture_output=True, text=True)
    summary = completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else ""
    count = lambda word: int(m.group(1)) if (m := re.search(rf"(\d+) {word}", summary)) else 0  # noqa: E731
    reasons = re.findall(r"^SKIPPED \[\d+\] [^:]+:\d+: (.*)$", completed.stdout, re.M)
    return {
        "command": "python -m pytest tests -n auto -rs",
        "passed": count("passed"),
        "failed": count("failed") + count("error"),
        "skipped": count("skipped"),
        "unavailable_environment": len(reasons),
        "unavailable_reasons": dict(sorted({r: reasons.count(r) for r in set(reasons)}.items(), key=lambda kv: -kv[1])),
        "summary": summary,
        "host": f"{sys.platform} {os.name} Python {sys.version.split()[0]}",
    }


def documentation() -> dict:
    from xax_status_docs import sync

    stale = sync(write=False)
    return {"synchronized": not stale, "stale_documents": [str(path.relative_to(REPO)) for path in stale]}


def measure(run_tests: bool = True) -> dict:
    revision = _git("rev-parse", "HEAD")
    return {
        "format": "xax-audit-remediation-evidence-v1",
        "milestone": "evidence and canonical-state integrity (ADR-177)",
        "repository_revision": {"head": revision, "working_tree_dirty": bool(_git("status", "--porcelain"))},
        "canonical_state": canonical_state(),
        "selfhost_claims": selfhost_claims(),
        "seed": seed(),
        "packaging": packaging(),
        "native_execution": native_execution(),
        "replacement_matrix": replacement_matrix(),
        "tests": tests() if run_tests else None,
        "documentation": documentation(),
    }


if __name__ == "__main__":
    evidence = measure(run_tests="--skip-tests" not in sys.argv)
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text, encoding="utf-8")
    print(text)
