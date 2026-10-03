"""Universal Replacement Matrix validator (tooling; not XAX semantics).

`XAX_REPLACEMENT_MATRIX.json` records per-platform evidence. A row's
replacement level is *derived* from its evidence; a claimed level that the
evidence does not support is rejected, so the matrix cannot overclaim.

Field value: ``"UNIMPLEMENTED"`` / ``"NOT_APPLICABLE"`` (no evidence), or
``[LABEL, evidence_path, ...]`` where every path must exist in the repository.
Missing fields mean UNIMPLEMENTED.
"""
from __future__ import annotations

import json
from pathlib import Path

LABELS = ("PROVEN", "EXECUTED", "MEASURED", "STRUCTURAL", "PROTOTYPE", "UNIMPLEMENTED")
FIELDS = (
    "semantic_expressibility", "code_generation", "abi", "artifact_format", "platform_apis", "ffi",
    "concurrency", "atomics", "simd", "dynamic_linking", "debugging", "optimization",
    "real_execution", "practical_application", "performance", "memory", "code_size",
    "ai_tokens", "autonomous_maintenance",
)
LEVELS = ("NONE", "R0", "R1", "R2", "R3", "R4", "R5", "R6")
_RUN = {"PROVEN", "EXECUTED"}
# Each level needs its own fields at one of the listed labels plus every lower level.
REQUIREMENTS: tuple[tuple[str, tuple[str, ...], frozenset[str]], ...] = (
    ("R0", ("semantic_expressibility",), frozenset({"PROVEN", "EXECUTED", "STRUCTURAL"})),
    ("R1", ("code_generation", "artifact_format", "real_execution"), frozenset(_RUN)),
    ("R2", ("abi", "platform_apis", "ffi", "dynamic_linking"), frozenset(_RUN)),
    ("R3", ("practical_application",), frozenset(_RUN)),
    ("R4", ("performance", "memory", "code_size"), frozenset({"MEASURED", "PROVEN"})),
    ("R5", ("ai_tokens",), frozenset({"MEASURED", "PROVEN"})),
    ("R6", ("autonomous_maintenance",), frozenset(_RUN)),
)


def label(row: dict, field: str) -> str:
    value = row.get("fields", {}).get(field, "UNIMPLEMENTED")
    return value if isinstance(value, str) else value[0]


def competitive(row: dict) -> bool:
    """R4 needs a measured *and* competitive result (XAX_SPEC.md §21.2).

    A MEASURED label only says a comparison exists; the row's ``competitive``
    verdict, which must cite evidence, says it favours XAX or is at parity.
    """
    verdict = row.get("competitive")
    return isinstance(verdict, list) and len(verdict) >= 2 and verdict[0] is True


def derived_level(row: dict) -> str:
    level = "NONE"
    for name, fields, accepted in REQUIREMENTS:
        if not all(label(row, field) in accepted for field in fields):
            break
        if name == "R4" and not competitive(row):
            break
        level = name
    return level


def validate(matrix: dict, repo_root: Path) -> list[str]:
    """Return deterministic error strings; empty means valid."""
    errors = []
    ids = [row.get("id") for row in matrix.get("platforms", ())]
    if len(ids) != len(set(ids)):
        errors.append("duplicate platform id")
    for row in matrix.get("platforms", ()):
        rid = row.get("id")
        for field, value in row.get("fields", {}).items():
            if field not in FIELDS:
                errors.append(f"{rid}.{field}: unknown field")
            elif isinstance(value, str):
                if value not in ("UNIMPLEMENTED", "NOT_APPLICABLE"):
                    errors.append(f"{rid}.{field}: bare label {value} needs evidence")
            elif not value or value[0] not in LABELS or len(value) < 2:
                errors.append(f"{rid}.{field}: expected [LABEL, evidence...]")
            else:
                errors.extend(f"{rid}.{field}: missing evidence {path}" for path in value[1:] if not (repo_root / path).exists())
        # Conformance §23.17: an emulator-only row cannot cite performance.
        if any("not hardware" in blocker for blocker in row.get("blockers", ())) and label(row, "performance") in ("MEASURED", "PROVEN"):
            errors.append(f"{rid}.performance: emulator-only row cannot claim performance evidence")
        verdict = row.get("competitive")
        if verdict is not None:
            if not isinstance(verdict, list) or len(verdict) < 2 or not isinstance(verdict[0], bool):
                errors.append(f"{rid}.competitive: expected [bool, evidence...]")
            else:
                errors.extend(f"{rid}.competitive: missing evidence {path}" for path in verdict[1:] if not (repo_root / path).exists())
        if row.get("level") not in LEVELS:
            errors.append(f"{rid}: unknown level {row.get('level')}")
        elif row["level"] != derived_level(row):
            errors.append(f"{rid}: claimed {row['level']} but evidence supports {derived_level(row)}")
    return errors


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
