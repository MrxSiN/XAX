"""Universal Replacement Matrix validator (tooling; not XAX semantics).

`XAX_REPLACEMENT_MATRIX.json` records per-platform evidence. A row's
replacement level is *derived* from its evidence; a claimed level that the
evidence does not support is rejected, so the matrix cannot overclaim.

Field value: ``"UNIMPLEMENTED"`` / ``"NOT_APPLICABLE"`` (no evidence), or
``[LABEL, evidence_path, ...]`` where every path must exist in the repository.
Missing fields mean UNIMPLEMENTED.

Labels are checked against what the cited files can show (v2, ADR-177): a
Markdown page, source file, script, or picture alone never shows that something
EXECUTED, MEASURED, or was PROVEN; MEASURED needs a recorded .json/.csv result;
MEASURED performance needs raw samples; and an R4 runtime verdict is recomputed
from raw samples under the baseline policy instead of trusting stored ratios or
``performance_class``.

v3 (ADR-207): R4 is performance leadership -- the XAX median is at most
R4_TARGET (0.9999x) of the fastest valid non-XAX median, and a one-sided
Mann-Whitney test says the advantage is not noise.  R5 is autonomous
maintenance (formerly R6) and R6 is a proven 100% XAX-developed application.
``ai_tokens`` is historical/future-milestone evidence and gates no level.
"""
from __future__ import annotations

import json
import math
import statistics
from pathlib import Path

VALIDATOR_VERSION = "xax-replacement-validator-v3"
REPO_ROOT = Path(__file__).resolve().parents[2]
LABELS = ("PROVEN", "EXECUTED", "MEASURED", "STRUCTURAL", "PROTOTYPE", "UNIMPLEMENTED")
FIELDS = (
    "semantic_expressibility", "code_generation", "abi", "artifact_format", "platform_apis", "ffi",
    "concurrency", "atomics", "simd", "dynamic_linking", "debugging", "optimization",
    "real_execution", "practical_application", "performance", "memory", "code_size",
    "ai_tokens", "autonomous_maintenance", "xax_only_application",
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
    ("R5", ("autonomous_maintenance",), frozenset(_RUN)),
    ("R6", ("xax_only_application",), frozenset(_RUN)),
)

# Fields a platform may genuinely lack, satisfied by NOT_APPLICABLE only with a
# written justification in the row's ``not_applicable`` map (ADR-129): a
# platform without a loader has nothing to load.
NOT_APPLICABLE_SATISFIES = frozenset({"dynamic_linking"})

# Files that can document or reproduce evidence but cannot by themselves show that something ran or was measured.
SUPPORTING_SUFFIXES = frozenset({".md", ".png", ".jpg", ".svg", ".sh"})
SUPPORTING_PREFIXES = ("compiler/src/", "compiler/integration/", "compiler/benchmarks/bench_", "XAX_")
RECORDED_SUFFIXES = frozenset({".json", ".csv"})
MIN_SAMPLES = 5
# R4 (ADR-207): XAX median / fastest non-XAX median, compared without rounding.
R4_TARGET = 0.9999
# One-sided Mann-Whitney U (normal approximation) significance for "XAX is faster than the competitor".
R4_ALPHA = 0.05
C_FAMILY = ("gcc", "clang", "msvc", "c-", "cpp", "c++")


def label(row: dict, field: str) -> str:
    value = row.get("fields", {}).get(field, "UNIMPLEMENTED")
    return value if isinstance(value, str) else value[0]


def _satisfied(row: dict, field: str, accepted: frozenset[str]) -> bool:
    value = label(row, field)
    if value == "NOT_APPLICABLE" and field in NOT_APPLICABLE_SATISFIES:
        return bool(str(row.get("not_applicable", {}).get(field, "")).strip())
    return value in accepted


def _supporting(path: str) -> bool:
    return Path(path).suffix in SUPPORTING_SUFFIXES or path.startswith(SUPPORTING_PREFIXES)


def _json(path: str, repo_root: Path):
    try:
        return json.loads((repo_root / path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _numbers(value) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in value)


def _sample_lists(value) -> list[list]:
    """Every list of numbers stored under a key naming samples, anywhere in a JSON value."""
    found: list[list] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if "samples" in key and _numbers(item):
                found.append(item)
            elif "samples" in key and isinstance(item, dict):
                found.extend(v for v in item.values() if _numbers(v))
            else:
                found.extend(_sample_lists(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_sample_lists(item))
    return found


def _emulated(row: dict) -> bool:
    return any("not hardware" in blocker for blocker in row.get("blockers", ()))


def _decimals(value: float) -> int:
    text = repr(float(value))
    return len(text.split(".")[1]) if "." in text and "e" not in text else 6


def _published_matches(published, exact: float) -> bool:
    """A stored ratio agrees with the recomputation to the precision it was stored with (never coarser than 1e-3)."""
    if not isinstance(published, (int, float)) or isinstance(published, bool):
        return False
    places = max(_decimals(published), 3)
    return abs(published - exact) <= 0.5 * 10 ** -places + 1e-12


def faster_p_value(xax: list[float], competitor: list[float]) -> float:
    """One-sided Mann-Whitney U p-value for 'XAX samples are smaller', normal approximation with tie correction."""
    n, m = len(xax), len(competitor)
    u = sum(1.0 if a < b else 0.5 if a == b else 0.0 for a in xax for b in competitor)
    pooled = sorted(xax + competitor)
    ties = 0
    i = 0
    while i < len(pooled):
        j = i
        while j < len(pooled) and pooled[j] == pooled[i]:
            j += 1
        t = j - i
        ties += t ** 3 - t
        i = j
    total = n + m
    variance = n * m / 12.0 * ((total + 1) - ties / (total * (total - 1)))
    if variance <= 0:
        return 1.0
    z = (u - n * m / 2.0 - 0.5) / math.sqrt(variance)  # continuity correction toward the null
    return 1.0 - statistics.NormalDist().cdf(z)


def recompute_runtime_verdict(paths, repo_root: Path = REPO_ROOT, emulated: bool = False) -> list[str]:
    """Reasons the cited evidence does not establish an R4 runtime verdict (empty: it does).

    XAX_BENCHMARKS.md 15.0/15.0a, recomputed from raw samples.  Every cited JSON must name its host and hold per-arm
    ``wall_seconds_samples`` (MIN_SAMPLES or more each) for an XAX arm and at least two baselines; the baselines follow
    the policy (``javac`` and ``kotlinc`` on the JVM, otherwise a C/C++ arm and an arm outside C/C++).  The ratio is the
    best XAX median over the fastest *non-XAX* median; it must be at most R4_TARGET and the advantage over that
    competitor must be significant (``faster_p_value`` < R4_ALPHA).  A published ratio must match the recomputation;
    ``performance_class`` is never read."""
    if emulated:
        return ["emulated execution is never performance evidence"]
    reasons = []
    for path in paths:
        data = _json(path, repo_root)
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, dict):
            reasons.append(f"{path}: no per-arm results")
            continue
        if not isinstance(data.get("host"), dict):
            reasons.append(f"{path}: no host/hardware identity")
            continue
        samples = {arm: item.get("wall_seconds_samples") for arm, item in results.items() if isinstance(item, dict)}
        if not all(_numbers(v) and len(v) >= MIN_SAMPLES for v in samples.values()):
            reasons.append(f"{path}: an arm lacks {MIN_SAMPLES}+ raw wall_seconds_samples")
            continue
        medians = {arm: statistics.median(values) for arm, values in samples.items()}
        xax = [arm for arm in medians if arm.startswith("xax")]
        baselines = [arm for arm in medians if not arm.startswith("xax")]
        if not xax or len(baselines) < 2:
            reasons.append(f"{path}: needs an XAX arm and at least two baseline arms")
            continue
        if any(arm.startswith("javac") for arm in baselines):
            policy = any(arm.startswith("kotlinc") for arm in baselines)
        else:
            c_family = [arm for arm in baselines if arm.lower().startswith(C_FAMILY)]
            policy = bool(c_family) and len(c_family) < len(baselines)
        if not policy:
            reasons.append(f"{path}: baselines do not meet the 15.0/15.0a policy")
            continue
        fastest = min(medians.values())
        competitor = min(baselines, key=lambda arm: (medians[arm], arm))
        for arm in xax:
            item = results[arm]
            legacy = item.get("time_ratio_vs_fastest")
            if legacy is not None and not _published_matches(legacy, medians[arm] / fastest):
                reasons.append(f"{path}: {arm} publishes ratio {legacy}, raw samples give {medians[arm] / fastest:.6f}")
            published = item.get("time_ratio_vs_fastest_competitor")
            if published is not None and not _published_matches(published, medians[arm] / medians[competitor]):
                reasons.append(f"{path}: {arm} publishes competitor ratio {published}, raw samples give {medians[arm] / medians[competitor]:.6f}")
        best = min(xax, key=lambda arm: (medians[arm], arm))
        ratio = medians[best] / medians[competitor]
        if ratio > R4_TARGET:
            reasons.append(f"{path}: XAX median is {ratio:.6f}x the fastest non-XAX arm ({competitor}); R4 needs <= {R4_TARGET}x")
            continue
        p_value = faster_p_value(samples[best], samples[competitor])
        if p_value >= R4_ALPHA:
            reasons.append(f"{path}: XAX advantage over {competitor} ({ratio:.6f}x) is within noise (one-sided Mann-Whitney p={p_value:.4f})")
    return reasons


def competitive(row: dict, repo_root: Path = REPO_ROOT) -> bool:
    """R4 needs a measured *and* leading result (XAX_SPEC.md §21.2), recomputed from the cited raw samples.

    The row's ``competitive`` entry names the evidence; its boolean must equal this recomputation (``validate``)."""
    verdict = row.get("competitive")
    if not (isinstance(verdict, list) and len(verdict) >= 2):
        return False
    return not recompute_runtime_verdict(verdict[1:], repo_root, _emulated(row))


def label_errors(row: dict, fields=FIELDS, repo_root: Path = REPO_ROOT) -> list[str]:
    """Evidence too weak for its label (see the module docstring)."""
    errors = []
    for field in fields:
        value = row.get("fields", {}).get(field)
        if not isinstance(value, list) or not value or value[0] not in ("EXECUTED", "MEASURED", "PROVEN"):
            continue
        paths = value[1:]
        if all(_supporting(path) for path in paths):
            errors.append(f"{row.get('id')}.{field}: {value[0]} cites only supporting files (documents, sources, scripts, images)")
        if value[0] == "MEASURED":
            recorded = [path for path in paths if Path(path).suffix in RECORDED_SUFFIXES]
            if not recorded:
                errors.append(f"{row.get('id')}.{field}: MEASURED needs a recorded .json/.csv result")
            elif field == "performance" and not any(
                any(len(samples) >= MIN_SAMPLES for samples in _sample_lists(_json(path, repo_root))) for path in recorded
            ):
                errors.append(f"{row.get('id')}.{field}: MEASURED performance needs {MIN_SAMPLES}+ raw samples to recompute from")
    return errors


def derived_level(row: dict, repo_root: Path = REPO_ROOT) -> str:
    level = "NONE"
    for name, fields, accepted in REQUIREMENTS:
        if not all(_satisfied(row, field, accepted) for field in fields) or label_errors(row, fields, repo_root):
            break
        if name == "R4" and not competitive(row, repo_root):
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
        errors.extend(f"{rid}: missing {key}" for key in ("name", "summary") if not str(row.get(key, "")).strip())
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
        if _emulated(row) and label(row, "performance") in ("MEASURED", "PROVEN"):
            errors.append(f"{rid}.performance: emulator-only row cannot claim performance evidence")
        for field, value in row.get("fields", {}).items():
            if value == "NOT_APPLICABLE" and not str(row.get("not_applicable", {}).get(field, "")).strip():
                errors.append(f"{rid}.{field}: NOT_APPLICABLE needs a justification in not_applicable")
        errors.extend(label_errors(row, FIELDS, repo_root))
        verdict = row.get("competitive")
        if verdict is not None:
            if not isinstance(verdict, list) or len(verdict) < 2 or not isinstance(verdict[0], bool):
                errors.append(f"{rid}.competitive: expected [bool, evidence...]")
            else:
                errors.extend(f"{rid}.competitive: missing evidence {path}" for path in verdict[1:] if not (repo_root / path).exists())
                reasons = recompute_runtime_verdict(verdict[1:], repo_root, _emulated(row))
                if verdict[0] != (not reasons):
                    detail = f" ({'; '.join(reasons)})" if reasons else ""
                    errors.append(f"{rid}.competitive: verdict {verdict[0]} but recomputation from raw samples gives {not reasons}{detail}")
        if row.get("level") not in LEVELS:
            errors.append(f"{rid}: unknown level {row.get('level')}")
        elif row["level"] != derived_level(row, repo_root):
            errors.append(f"{rid}: claimed {row['level']} but evidence supports {derived_level(row, repo_root)}")
    return errors


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
