"""Independently audit retained host-response trials without model requests."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def audit(results: Path, runs: Path, repetitions: int = 3, *, check_live: bool = True):
    root = Path(__file__).resolve().parents[2]
    manifest_bytes = (runs / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    errors, commands, live_drift = [], set(), []
    for name, expected in manifest["sources"].items():
        for label, path in (("live", root / name), ("snapshot", runs / "source-snapshot" / name)):
            if not path.exists() or sha(path.read_bytes()) != expected:
                if label == "live":
                    live_drift.append(name)
                if label == "snapshot" or check_live:
                    errors.append(f"{label} source mismatch: {name}")
    with results.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    cells, successes, contexts, profiles = defaultdict(int), set(), set(), set()
    attempts = set()
    for row in rows:
        cell = row["task_id"], row["arm"], int(row["trial"])
        attempts.add((*cell, int(row["attempt"])))
        folder = runs / f"{cell[0]}-{cell[1].lower()}-{cell[2]}-{row['attempt']}"
        record = json.loads((folder / "result.json").read_text(encoding="utf-8"))
        if {key: str(value) for key, value in record.items()} != row:
            errors.append(f"CSV/result mismatch: {folder.name}")
        traces = [folder / f"model-events-{i}.jsonl" for i in range(1, int(row["response_count"]) + 1)]
        if sha(b"".join(path.read_bytes() for path in traces)) != row["trace_sha256"]:
            errors.append(f"trace digest mismatch: {folder.name}")
        usage = defaultdict(int)
        turns = 0
        for index, trace in enumerate(traces, 1):
            for line in trace.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                if event.get("type") == "turn.completed":
                    turns += 1
                    for key, value in event["usage"].items():
                        usage[key] += value
                if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "command_execution":
                    commands.add((cell[1], event["item"]["command"]))
            context = json.loads((folder / f"model-context-{index}.json").read_text(encoding="utf-8"))
            context_hash = sha(json.dumps(context, sort_keys=True).encode())
            contexts.add(context_hash)
            if context_hash != json.loads(row["instruction_context_sha256"])[index - 1]:
                errors.append(f"instruction digest mismatch: {folder.name}/{index}")
        expected_usage = {"input_tokens": usage["input_tokens"], "output_tokens": usage["output_tokens"],
                          "cached_input_tokens": usage["cached_input_tokens"],
                          "total_tokens": usage["input_tokens"] + usage["output_tokens"], "turns": turns}
        if any(int(row[key]) != value for key, value in expected_usage.items()):
            errors.append(f"raw usage mismatch: {folder.name}")
        if row["accounting_complete"] != "TRUE":
            errors.append(f"incomplete accounting: {folder.name}")
        profiles.add(row["profile_sha256"])
        cells[cell] += expected_usage["total_tokens"]
        if row["pass"] == "TRUE":
            if cell in successes:
                errors.append(f"repeated successful cell: {cell}")
            successes.add(cell)
            check = json.loads((folder / f"host-check-{len(traces)}.json").read_text(encoding="utf-8"))
            if not check["pass"]:
                errors.append(f"missing successful host check: {folder.name}")
    if len(attempts) != len(rows):
        errors.append("duplicate attempt rows")
    for marker in runs.glob("jvm-*/attempt.json"):
        data = json.loads(marker.read_text(encoding="utf-8"))
        identity = data["task_id"], data["arm"], int(data["trial"]), int(data["attempt"])
        if identity not in attempts:
            errors.append(f"unrecorded attempt: {marker.parent.name}")
    if len(profiles) != 1 or len(contexts) != 1:
        errors.append("mixed or missing profiles/common instructions")
    if profiles != {sha(manifest_bytes)}:
        errors.append("row profile does not match manifest")
    expected = {(f"jvm-{task:02}", arm, trial) for task in range(1, 16)
                for arm in ("JAVA", "KOTLIN", "XAX") for trial in range(1, repetitions + 1)}
    medians = {arm: statistics.median([cost for cell, cost in cells.items() if cell in successes and cell[1] == arm])
               for arm in ("JAVA", "KOTLIN", "XAX") if any(cell[1] == arm for cell in successes)}
    ratio = medians["XAX"] / min(medians["JAVA"], medians["KOTLIN"]) if len(medians) == 3 else None
    complete = successes == expected
    totals = {arm: sum(int(row["total_tokens"]) for row in rows if row["arm"] == arm)
              for arm in ("JAVA", "KOTLIN", "XAX")}
    repairs = {arm: sum(int(row["repair_count"]) for row in rows if row["arm"] == arm)
               for arm in ("JAVA", "KOTLIN", "XAX")}
    families = {}
    for task_id in sorted({cell[0] for cell in cells}):
        family_medians = {}
        counts = {}
        for arm in ("JAVA", "KOTLIN", "XAX"):
            samples = [cost for cell, cost in cells.items() if cell in successes and cell[:2] == (task_id, arm)]
            counts[arm] = len(samples)
            if samples:
                family_medians[arm] = statistics.median(samples)
        families[task_id] = {"successful_trials": counts, "medians_including_attempt_costs": family_medians}
    return {"format": "xax-jvm-response-independent-audit-v1", "source_csv": results.name,
            "source_sha256": sha(results.read_bytes()), "manifest_sha256": sha(manifest_bytes),
            "attempts": len(rows), "successful_cells": len(successes), "required_cells": len(expected),
            "complete": complete, "errors": errors, "medians_including_all_attempt_costs": medians,
            "live_sources_checked": check_live, "live_source_drift": live_drift,
            "ratio_vs_lowest_textual_median": ratio,
            "total_recorded_tokens_by_arm": totals, "repair_responses_by_arm": repairs,
            "failed_attempts": sum(row["pass"] != "TRUE" for row in rows),
            "per_task_diagnostics_not_the_gate_aggregation": families,
            "numeric_gate": bool(complete and not errors and ratio is not None and ratio <= 0.5),
            # ADR-195: 0.50 is the target; the owner accepts up to 0.55.
            "acceptance_gate": bool(complete and not errors and ratio is not None and ratio <= 0.55),
            "instruction_context_sha256": sorted(contexts), "profile_sha256": sorted(profiles),
            "commands_requiring_context_review": [{"arm": arm, "command": command} for arm, command in sorted(commands)],
            "scope": "Raw usage/digests/completeness audit; task equivalence and context commands require human review. No matrix promotion."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("runs", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--archived", action="store_true", help="audit frozen snapshots after intentional live-source changes")
    args = parser.parse_args()
    report = audit(args.results, args.runs, args.repetitions, check_live=not args.archived)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return int(bool(report["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
