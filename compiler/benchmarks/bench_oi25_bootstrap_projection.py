"""OI-25 measurement-only fixed-point projection experiment.

The canonical semantic-image target remains byte-identical.  This benchmark
uses the committed M14 Python zipapp seed as an existing bootstrap artifact
whose ZIP DOS timestamps are non-runtime metadata, compares a strict versioned
projection against eliminating that variability at emission, and never treats
projection bytes as XAX program semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

from blake3 import blake3
from xax_compiler import StoreReader
from xax_selfhost import execute_m14_recursive_evidence

PROJECTION_ID = b"xax-m14-seed-pyz-projection-v1"
SHEBANG = b"#!/usr/bin/env python3\n"
EXPECTED_ENTRIES = ("__main__.py", "blake3.py", "xax_compiler.py", "xax_selfhost.py")
ZIP_LOCAL = b"PK\x03\x04"
ZIP_CENTRAL = b"PK\x01\x02"
ZIP_EOCD = b"PK\x05\x06"
DOS_TIME_ZERO = 0
DOS_DATE_1980_01_01 = 0x0021
HERE = Path(__file__).resolve().parent
COMPILER = HERE.parent
BOOTSTRAP = COMPILER / "bootstrap"
SEED = BOOTSTRAP / "m14_seed_runtime.pyz"
PROGRAM = BOOTSTRAP / "m14_selfhost_compiler.xax"


def _strict_layout(data: bytes) -> tuple[tuple[zipfile.ZipInfo, ...], tuple[tuple[int, int, str], ...]]:
    if not data.startswith(SHEBANG):
        raise ValueError("XAX.OI25.PROJECTION.LAYOUT shebang")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data), "r")
    except Exception as exc:
        raise ValueError("XAX.OI25.PROJECTION.LAYOUT zip") from exc
    with archive:
        if archive.comment:
            raise ValueError("XAX.OI25.PROJECTION.LAYOUT comment")
        infos = tuple(archive.infolist())
        if tuple(info.filename for info in infos) != EXPECTED_ENTRIES:
            raise ValueError("XAX.OI25.PROJECTION.LAYOUT entries")
        timestamp_fields: list[tuple[int, int, str]] = []
        for info in infos:
            if (
                info.compress_type != zipfile.ZIP_DEFLATED
                or info.flag_bits != 0
                or info.extra
                or info.comment
                or (info.external_attr >> 16) != 0o100644
            ):
                raise ValueError("XAX.OI25.PROJECTION.LAYOUT entry-metadata")
            # Reading validates compressed data and CRC before any metadata is ignored.
            archive.read(info.filename)
            off = info.header_offset
            if data[off : off + 4] != ZIP_LOCAL:
                raise ValueError("XAX.OI25.PROJECTION.LAYOUT local-header")
            values = struct.unpack_from("<IHHHHHIIIHH", data, off)
            name_len, extra_len = values[-2], values[-1]
            name = data[off + 30 : off + 30 + name_len].decode("utf-8")
            if name != info.filename or extra_len != 0:
                raise ValueError("XAX.OI25.PROJECTION.LAYOUT local-name")
            timestamp_fields.append((off + 10, off + 14, f"local:{info.filename}:dos-time-date"))

        pos = archive.start_dir
        for info in infos:
            if data[pos : pos + 4] != ZIP_CENTRAL:
                raise ValueError("XAX.OI25.PROJECTION.LAYOUT central-header")
            values = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, pos)
            name_len, extra_len, comment_len = values[10], values[11], values[12]
            local_relative = values[16]
            name = data[pos + 46 : pos + 46 + name_len].decode("utf-8")
            if (
                name != info.filename
                or extra_len != 0
                or comment_len != 0
                or local_relative != info.header_offset
            ):
                raise ValueError("XAX.OI25.PROJECTION.LAYOUT central-entry")
            timestamp_fields.append((pos + 12, pos + 16, f"central:{info.filename}:dos-time-date"))
            pos += 46 + name_len + extra_len + comment_len
        if data[pos : pos + 4] != ZIP_EOCD or pos + 22 != len(data):
            raise ValueError("XAX.OI25.PROJECTION.LAYOUT eocd")
        eocd = struct.unpack_from("<IHHHHIIH", data, pos)
        if eocd[1:3] != (0, 0) or eocd[3] != len(infos) or eocd[4] != len(infos) or eocd[7] != 0:
            raise ValueError("XAX.OI25.PROJECTION.LAYOUT eocd-fields")
        return infos, tuple(timestamp_fields)


def project_seed_pyz_v1(data: bytes) -> bytes:
    """Normalize only predeclared ZIP DOS timestamp fields for the M14 seed."""
    _infos, fields = _strict_layout(data)
    out = bytearray(data)
    replacement = struct.pack("<HH", DOS_TIME_ZERO, DOS_DATE_1980_01_01)
    for start, end, _label in fields:
        if end - start != 4:
            raise AssertionError("timestamp field width")
        out[start:end] = replacement
    projected = bytes(out)
    _strict_layout(projected)
    return projected


def projected_digest(data: bytes) -> bytes:
    return blake3(PROJECTION_ID + project_seed_pyz_v1(data)).digest()


def _entries(seed_data: bytes) -> dict[str, tuple[bytes, int]]:
    _strict_layout(seed_data)
    with zipfile.ZipFile(io.BytesIO(seed_data), "r") as archive:
        return {info.filename: (archive.read(info.filename), info.external_attr >> 16) for info in archive.infolist()}


def _local_epoch(year: int) -> float:
    return time.mktime((year, 1, 1, 0, 0, 0, 0, 1, -1))


def build_seed(entries: dict[str, tuple[bytes, int]], year: int) -> bytes:
    if tuple(entries) != EXPECTED_ENTRIES:
        raise ValueError("XAX.OI25.EMIT.ENTRIES")
    with tempfile.TemporaryDirectory(prefix="xax-oi25-seed-") as directory:
        stage = Path(directory) / "stage"
        stage.mkdir()
        epoch = _local_epoch(year)
        for name in EXPECTED_ENTRIES:
            payload, mode = entries[name]
            path = stage / name
            path.write_bytes(payload)
            os.chmod(path, mode & 0o7777)
            os.utime(path, (epoch, epoch))
        return _create_archive(stage, EXPECTED_ENTRIES)


def _create_archive(stage: Path, names: tuple[str, ...]) -> bytes:
    """``zipapp.create_archive`` output with entries in the declared order.

    ``zipapp`` walks the directory with an unsorted ``rglob``, so its entry
    order follows the host filesystem; this writes the same bytes
    (shebang, deflated entries, file mtime and mode) in a fixed order.
    """
    out = io.BytesIO()
    out.write(SHEBANG)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.write(stage / name, name)
    return out.getvalue()


def build_deterministic_seed(entries: dict[str, tuple[bytes, int]]) -> bytes:
    return build_seed(entries, 1980)


def _diff_ranges(a: bytes, b: bytes) -> tuple[tuple[int, int], ...]:
    if len(a) != len(b):
        raise ValueError("XAX.OI25.DIFF.LENGTH")
    result: list[tuple[int, int]] = []
    start = None
    for index, (left, right) in enumerate(zip(a, b)):
        if left != right and start is None:
            start = index
        elif left == right and start is not None:
            result.append((start, index))
            start = None
    if start is not None:
        result.append((start, len(a)))
    return tuple(result)


def attribute_differences(a: bytes, b: bytes) -> tuple[dict, ...]:
    _infos, fields = _strict_layout(a)
    _strict_layout(b)
    attributed: list[dict] = []
    for start, end in _diff_ranges(a, b):
        owners = [label for fs, fe, label in fields if fs <= start and end <= fe]
        if len(owners) != 1:
            raise ValueError("XAX.OI25.DIFF.UNDECLARED")
        attributed.append({"start": start, "end": end, "bytes": end - start, "field": owners[0]})
    return tuple(attributed)


def run_seed(seed_data: bytes, program_data: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="xax-oi25-run-") as directory:
        root = Path(directory)
        seed = root / "seed.pyz"
        source = root / "compiler.xax"
        output = root / "rebuilt.xax"
        seed.write_bytes(seed_data)
        source.write_bytes(program_data)
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [sys.executable, str(seed), "rebuild", str(source), str(output)],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        rebuilt = output.read_bytes() if output.exists() else b""
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "output_bytes": len(rebuilt),
            "output_blake3": blake3(rebuilt).hexdigest() if rebuilt else None,
            "byte_identical_to_input": rebuilt == program_data,
        }


def _semantic_mutation(entries: dict[str, tuple[bytes, int]]) -> dict[str, tuple[bytes, int]]:
    mutated = dict(entries)
    body, mode = mutated["__main__.py"]
    old = b"Path(args.output).write_bytes(output)"
    new = b"Path(args.output).write_bytes(output + b\"\\x00\")"
    if body.count(old) != 1:
        raise AssertionError("seed semantic mutation anchor changed")
    mutated["__main__.py"] = (body.replace(old, new), mode)
    return mutated


def _unknown_layout(entries: dict[str, tuple[bytes, int]]) -> bytes:
    expanded = dict(entries)
    expanded["extra.py"] = (b"x = 1\n", 0o100644)
    with tempfile.TemporaryDirectory(prefix="xax-oi25-extra-") as directory:
        stage = Path(directory) / "stage"
        stage.mkdir()
        epoch = _local_epoch(1980)
        for name, (payload, mode) in expanded.items():
            path = stage / name
            path.write_bytes(payload)
            os.chmod(path, mode & 0o7777)
            os.utime(path, (epoch, epoch))
        return _create_archive(stage, tuple(expanded))


def _stat(samples: list[int]) -> dict:
    ordered = sorted(samples)
    return {
        "median_ns": int(statistics.median(ordered)),
        "min_ns": ordered[0],
        "max_ns": ordered[-1],
        "samples_ns": ordered,
    }


def build_evidence(measure: bool = True) -> tuple[dict, dict]:
    committed = SEED.read_bytes()
    program = PROGRAM.read_bytes()
    entries = _entries(committed)
    years = (2024, 2025, 2026)
    generations = tuple(build_seed(entries, year) for year in years)
    projections = tuple(project_seed_pyz_v1(item) for item in generations)
    deterministic = build_deterministic_seed(entries)
    if any(projected != deterministic for projected in projections):
        raise AssertionError("projection and deterministic emission disagree")

    runs = tuple(run_seed(item, program) for item in generations)
    if not all(item["returncode"] == 0 and item["byte_identical_to_input"] for item in runs):
        raise AssertionError("metadata-only generations changed bootstrap behavior")

    semantic_mutant = build_seed(_semantic_mutation(entries), 1980)
    semantic_run = run_seed(semantic_mutant, program)
    if semantic_run["byte_identical_to_input"]:
        raise AssertionError("semantic mutation did not alter runtime output")
    if projected_digest(semantic_mutant) == projected_digest(deterministic):
        raise AssertionError("projection hid semantic mutation")

    recursive = execute_m14_recursive_evidence(StoreReader(program))
    if not recursive.b4 or len({recursive.generation0_digest, recursive.generation1_digest, recursive.generation2_digest}) != 1:
        raise AssertionError("semantic-image byte identity regressed")

    unknown_reject = False
    try:
        project_seed_pyz_v1(_unknown_layout(entries))
    except ValueError as exc:
        unknown_reject = "LAYOUT" in str(exc)
    if not unknown_reject:
        raise AssertionError("unknown projection layout was accepted")

    corruption_reject = False
    corrupt = bytearray(deterministic)
    with zipfile.ZipFile(io.BytesIO(deterministic), "r") as archive:
        info = archive.getinfo("__main__.py")
        local = struct.unpack_from("<IHHHHHIIIHH", deterministic, info.header_offset)
        payload_offset = info.header_offset + 30 + local[-2] + local[-1]
    corrupt[payload_offset + 3] ^= 1
    try:
        project_seed_pyz_v1(bytes(corrupt))
    except ValueError:
        corruption_reject = True
    except Exception:
        corruption_reject = True
    if not corruption_reject:
        raise AssertionError("corrupt compressed payload was accepted")

    generation_rows = []
    for label, year, raw, projected, run in zip(("B2", "B3", "B4"), years, generations, projections, runs):
        generation_rows.append({
            "generation": label,
            "source_metadata_year": year,
            "raw_bytes": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_blake3": blake3(raw).hexdigest(),
            "projected_bytes": len(projected),
            "projected_digest": projected_digest(raw).hex(),
            "runtime": run,
        })

    timing: dict = {"samples": 0}
    if measure:
        projection_samples = []
        variable_emit_samples = []
        deterministic_emit_samples = []
        for _ in range(31):
            t0 = time.perf_counter_ns(); project_seed_pyz_v1(generations[0]); projection_samples.append(time.perf_counter_ns() - t0)
        for _ in range(11):
            t0 = time.perf_counter_ns(); build_seed(entries, 2025); variable_emit_samples.append(time.perf_counter_ns() - t0)
            t0 = time.perf_counter_ns(); build_deterministic_seed(entries); deterministic_emit_samples.append(time.perf_counter_ns() - t0)
        timing = {
            "environment": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
            "samples": {"projection": 31, "emitter_each": 11},
            "projection": _stat(projection_samples),
            "variable_emitter": _stat(variable_emit_samples),
            "deterministic_emitter": _stat(deterministic_emit_samples),
        }

    projector_lines = sum(
        1 for line in inspect.getsource(project_seed_pyz_v1).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ) + sum(
        1 for line in inspect.getsource(_strict_layout).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )

    evidence = {
        "issue": "OI-25",
        "status": "closed",
        "decision": "require raw byte identity whenever emitter-controlled nonsemantic variability can be normalized; projection is reserved for target/profile-declared variability that cannot be eliminated",
        "canonical_target": {
            "target": "xax-semantic-image-v1",
            "comparison": "raw-byte-identity",
            "root": recursive.compiler_root.hex(),
            "generation_digests": [recursive.generation0_digest.hex(), recursive.generation1_digest.hex(), recursive.generation2_digest.hex()],
            "b2": recursive.b2,
            "b3": recursive.b3,
            "b4": recursive.b4,
        },
        "variable_artifact": {
            "artifact": "m14-seed-pyz-v1",
            "projection_id": PROJECTION_ID.decode(),
            "declared_nonsemantic_fields": ["ZIP local DOS modification time/date", "ZIP central-directory DOS modification time/date"],
            "entry_names": list(EXPECTED_ENTRIES),
            "generations": generation_rows,
            "all_raw_distinct": len({row["raw_sha256"] for row in generation_rows}) == 3,
            "all_projected_identical": len({row["projected_digest"] for row in generation_rows}) == 1,
            "difference_attribution_b2_b3": attribute_differences(generations[0], generations[1]),
            "difference_attribution_b3_b4": attribute_differences(generations[1], generations[2]),
            "deterministic_emitter_sha256": hashlib.sha256(deterministic).hexdigest(),
            "projection_equals_deterministic_emission": projections[0] == deterministic,
        },
        "negative_controls": {
            "semantic_mutation_entry": "__main__.py output write",
            "semantic_mutation_projected_digest_changed": projected_digest(semantic_mutant) != projected_digest(deterministic),
            "semantic_mutation_runtime_byte_identity": semantic_run["byte_identical_to_input"],
            "unknown_layout_rejected": unknown_reject,
            "corrupt_payload_rejected": corruption_reject,
        },
        "implementation": {
            "projection_checker_source_lines": projector_lines,
            "production_emitter_normalization_added_lines": 5,
            "projection_runtime_required": False,
            "selected": "deterministic-emitter-byte-identity",
        },
        "host_observation": {
            "semantic": False,
            "timing_artifact": "oi25_bootstrap_projection_timing.json" if measure else None,
        },
    }
    return evidence, timing


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-timing", action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--timing", type=Path)
    args = parser.parse_args()
    evidence, timing = build_evidence(not args.no_timing)
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.evidence:
        args.evidence.write_text(text)
    if args.timing:
        args.timing.write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
