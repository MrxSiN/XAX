"""Validator for the universal replacement evidence matrix (docs/18 §14).

The matrix is data; this module only checks that recorded replacement levels
never exceed the recorded evidence.  It is tooling, not XAX semantics.

Run ``python -m xax_replacement`` from ``compiler/src`` to print a summary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable

LABELS = ("PROVEN", "EXECUTED", "MEASURED", "STRUCTURAL", "PROTOTYPE", "UNIMPLEMENTED")
# Labels backed by running the artifact; MEASURED and PROVEN are at least as strong.
RAN = frozenset({"EXECUTED", "MEASURED", "PROVEN"})
CAPABILITIES = (
    "semantic_expressibility",
    "code_generation",
    "abi",
    "artifact_format",
    "platform_apis",
    "ffi",
    "concurrency",
    "atomics",
    "simd",
    "dynamic_linking",
    "debugging",
    "optimization_maturity",
    "real_execution",
    "practical_application",
    "performance_evidence",
    "memory_evidence",
    "code_size_evidence",
    "ai_token_evidence",
    "autonomous_maintenance",
)
LEVELS = ("R0", "R1", "R2", "R3", "R4", "R5", "R6")

# docs/18 §3: capabilities that must have run for each cumulative level.
_LEVEL_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "R0": ("semantic_expressibility",),
    "R1": ("code_generation", "artifact_format", "real_execution"),
    "R2": ("abi", "platform_apis", "ffi"),
    "R3": ("practical_application",),
    "R4": ("performance_evidence", "memory_evidence", "code_size_evidence"),
    "R5": ("ai_token_evidence",),
    "R6": ("autonomous_maintenance",),
}


class MatrixError(ValueError):
    pass


def achieved_level(target: dict) -> str | None:
    """Highest level whose cumulative obligations are met by the recorded labels."""
    capabilities = target["capabilities"]
    achieved = None
    for level in LEVELS:
        required = _LEVEL_REQUIREMENTS[level]
        if any(capabilities[name]["label"] not in RAN for name in required):
            break
        if level == "R4" and not capabilities["performance_evidence"].get("competitive", False):
            break
        if level == "R5" and not capabilities["ai_token_evidence"].get("improves", False):
            break
        if level == "R4" and any(capabilities[name]["label"] != "MEASURED" for name in required):
            break
        achieved = level
    return achieved


def _errors(matrix: dict, repository: Path) -> Iterable[str]:
    if matrix.get("format") != "xax-universal-replacement-matrix-v1":
        yield "unknown matrix format"
    names = set()
    for target in matrix.get("targets", ()):
        name = target.get("id", "<missing id>")
        if name in names:
            yield f"{name}: duplicate target id"
        names.add(name)
        for field in ("id", "platform", "workload_class", "capabilities", "runtime_requirement", "known_blockers", "replacement_level"):
            if field not in target:
                yield f"{name}: missing field {field}"
        if "capabilities" not in target:
            continue
        missing = set(CAPABILITIES) - set(target["capabilities"])
        extra = set(target["capabilities"]) - set(CAPABILITIES)
        if missing or extra:
            yield f"{name}: capability set mismatch missing={sorted(missing)} extra={sorted(extra)}"
            continue
        for capability, entry in target["capabilities"].items():
            label = entry.get("label")
            if label not in LABELS:
                yield f"{name}.{capability}: unknown label {label!r}"
            if not entry.get("note"):
                yield f"{name}.{capability}: missing note"
            evidence = entry.get("evidence", [])
            if label in RAN | {"STRUCTURAL"} and not evidence:
                yield f"{name}.{capability}: {label} requires an evidence path"
            for path in evidence:
                if not (repository / path).exists():
                    yield f"{name}.{capability}: evidence path does not exist: {path}"
        runtime = target.get("runtime_requirement", {})
        if runtime.get("xax_runtime"):
            yield f"{name}: a XAX-added runtime violates FND-004: {runtime['xax_runtime']}"
        recorded = target.get("replacement_level")
        if recorded is not None and recorded not in LEVELS:
            yield f"{name}: unknown replacement level {recorded!r}"
        elif recorded != achieved_level(target):
            yield f"{name}: recorded level {recorded} differs from evidence-supported level {achieved_level(target)}"
        if recorded != "R6" and not target.get("known_blockers"):
            yield f"{name}: a target below R6 must list its blockers"


def validate_matrix(matrix: dict, repository: Path) -> None:
    errors = list(_errors(matrix, repository))
    if errors:
        raise MatrixError("\n".join(errors))


def load_matrix(repository: Path) -> dict:
    return json.loads((repository / "docs" / "universal_replacement_matrix.json").read_text())


def main(argv: list[str] | None = None) -> int:
    repository = Path(__file__).resolve().parents[2]
    matrix = load_matrix(repository)
    validate_matrix(matrix, repository)
    for target in matrix["targets"]:
        level = target["replacement_level"] or "-"
        print(f"{level:>3}  {target['id']:<32} {target['workload_class']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
