"""Fixed-profile JVM R5 multi-file comparison (ADR-197): XAX vs four textual workflows.

Same minimal client, model, calibration and accounting as response-v12
(`run_jvm_r5_response`). Every arm gets its whole context inline, in one
request per response, and no tools.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
from pathlib import Path

from benchmarks import run_jvm_r5_response as base
from benchmarks.jvm_r5_multifile import ARMS, TEXTUAL, XaxTrial, apply_multi_patch, check_textual, sources, task, tasks, textual_context
from benchmarks.jvm_r5_response import unwrap_response

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "ai_native/jvm-r5-multifile-v5-results.csv"
RUNS = HERE / "ai_native/runs-jvm-r5-multifile-v5"
SOURCES = (*base.SOURCES, "compiler/benchmarks/jvm_r5_multifile.py", "compiler/benchmarks/run_jvm_r5_multifile.py")
FIELDS = base.FIELDS


def manifest():
    current = base.manifest()
    current.update(format="xax-jvm-r5-multifile-v5", required_cells=len(tasks()) * len(ARMS) * 3,
                   sources={name: base.digest((base.REPO / name).read_bytes()) for name in SOURCES},
                   method=("Multi-file projects generated from one spec per task. XAX receives the target and its transitive callers "
                           "from the workspace callers query. Textual workflows per language: whole files containing that call hierarchy, "
                           "or an IDE-style excerpt of exactly its methods. All context is inline, one request per response, no tools. "
                           "The gate compares XAX with the lowest textual median after removing the calibrated client floor."))
    current["limits"] = current["limits"] + ["Generated projects: helper chains are synthetic; three task families."]
    return current


def pin_profile(runs):
    return base.pin_profile(runs, manifest(), SOURCES)


def schedule(repetitions=3):
    rotations = [ARMS[i:] + ARMS[:i] for i in range(len(ARMS))]
    return [(item.task_id, arm, trial) for trial in range(1, repetitions + 1)
            for index, item in enumerate(tasks()) for arm in rotations[(index + trial - 1) % len(rotations)]]


def _rows(results):
    return base._rows(results)


def _source_prompt(item, arm, workspace, repair=""):
    files = {path.name: path.read_text(encoding="utf-8") for path in sorted(workspace.iterdir())
             if path.suffix in {".java", ".kt"}}
    return (item.prompt + "\nReturn only an apply_patch update: *** Begin Patch, one *** Update File: NAME section per changed file "
            "with @@ context hunks, *** End Patch. Use exact old context; no line counts are needed.\n"
            + textual_context(item, arm, files)
            + "\nThe host applies your response and runs the compiler and exact-target/behavior checks. No tools." + repair)


def run_cell(results, runs, profile, settings, task_id, arm, trial, max_responses=3):
    previous = [r for r in _rows(results) if (r["task_id"], r["arm"], int(r["trial"])) == (task_id, arm, trial)]
    attempt = len(previous) + 1
    workspace = runs / f"{task_id}-{arm.lower()}-{trial}-{attempt}"
    if workspace.exists():
        raise ValueError(f"unrecorded attempt present: {workspace}; recover its traces before continuing")
    item = task(task_id)
    workspace.mkdir(parents=True)
    semantic = XaxTrial(item) if arm == "XAX" else None
    if semantic:
        prompt = semantic.prompt()
    else:
        for name, text in sources(item.initial, arm.startswith("KOTLIN")).items():
            (workspace / name).write_text(text, encoding="utf-8", newline="\n")
        prompt = _source_prompt(item, arm, workspace)
    (workspace / "TASK.md").write_text(prompt, encoding="utf-8")
    attempt_data = {"task_id": task_id, "arm": arm, "trial": trial, "attempt": attempt, "profile_sha256": profile, "started_unix": time.time()}
    (workspace / "attempt.json").write_text(json.dumps(attempt_data, indent=2), encoding="utf-8")
    started = time.perf_counter()
    events, traces, failures, transmitted, contexts = [], [], [], 0, []
    passed, complete, reason = False, True, ""
    for round_index in range(1, max_responses + 1):
        code, new_events, response, trace, count, context = base._model(workspace, prompt, round_index)
        contexts.append(context)
        events.extend(new_events)
        traces.append(trace)
        transmitted += count
        response = unwrap_response(response)
        (workspace / f"response-{round_index}.txt").write_text(response, encoding="utf-8")
        if code or not base.accounting.aggregate_usage(new_events):
            complete = bool(base.accounting.aggregate_usage(new_events)) and code != 124
            reason = "model client failure or incomplete usage; inspect retained trace"
            break
        wrong_target = False
        try:
            if semantic:
                generation = semantic.workspace.generation
                passed, reason = semantic.apply(response)
                if passed:
                    passed, reason = semantic.check_jvm()
                    if passed:
                        (workspace / "program.xax").write_bytes(semantic.reader.data)
                # A verified wrong target was published: a fresh attempt follows.
                wrong_target = not passed and semantic.workspace.generation != generation
                prompt = "Previous response rejected: " + reason + ". Correct the request.\n" + semantic.prompt()
            else:
                apply_multi_patch(workspace, response)
                passed, reason = check_textual(item, arm, workspace)
                prompt = _source_prompt(item, arm, workspace, repair="\nPrevious response failed: " + reason)
        except (ValueError, KeyError, OSError, RuntimeError) as error:
            reason = str(error)
            prompt = ("Previous response rejected: " + reason + ". Correct the request.\n" + semantic.prompt() if semantic
                      else _source_prompt(item, arm, workspace, repair="\nPrevious response failed: " + reason))
        (workspace / f"host-check-{round_index}.json").write_text(json.dumps({"pass": passed, "diagnostic": reason}), encoding="utf-8")
        if passed:
            break
        failures.append(reason)
        if wrong_target:
            break
    usage = base.accounting.aggregate_usage(events)
    commands = [e["item"] for e in events if e.get("type") == "item.completed" and e.get("item", {}).get("type") == "command_execution"]
    row = dict.fromkeys(FIELDS, "")
    row.update({k: v for k, v in attempt_data.items() if k != "started_unix"})
    row.update(task_family=item.family, model=base.MODEL, reasoning=base.REASONING, **{"pass": str(passed).upper()},
               input_tokens=usage.get("input_tokens", ""), output_tokens=usage.get("output_tokens", ""),
               total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0) if usage else "",
               cached_input_tokens=usage.get("cached_input_tokens", ""), turns=sum(e.get("type") == "turn.completed" for e in events),
               elapsed_seconds=f"{time.perf_counter() - started:.3f}", failed_checks=len(failures), repair_count=max(0, len(traces) - 1),
               context_bytes=len((workspace / "TASK.md").read_bytes()), semantic_entities=semantic.entities if semantic else "",
               session_id=";".join(e["thread_id"] for e in events if e.get("type") == "thread.started"),
               notes=reason if not passed else "", trace_sha256=base.digest(b"".join(t.read_bytes() for t in traces)),
               client=settings["client"], transmitted_bytes=transmitted, verifier_failures=semantic.verifier_failures if semantic else "",
               stale_transaction_failures=semantic.stale_failures if semantic else 0, response_count=len(traces),
               accounting_complete=str(complete and bool(usage)).upper(), host_failures=json.dumps(failures),
               instruction_context_sha256=json.dumps(contexts), context_reads=len(commands),
               unexpected_context_commands=json.dumps([c["command"] for c in commands]))
    exists = results.exists() and results.stat().st_size
    with results.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)
        file.flush()
        os.fsync(file.fileno())
    (workspace / "result.json").write_text(json.dumps(row, indent=2), encoding="utf-8")
    print(f"{task_id} {arm} trial={trial} attempt={attempt}: {row['pass']} {row['total_tokens']} tokens repairs={len(failures)}", flush=True)
    return row


def summarize(results, runs, repetitions=3):
    rows = _rows(results)
    calibration = json.loads((runs / "calibration.json").read_text(encoding="utf-8"))
    floor = calibration["client_floor_input_tokens"]
    cells = {}
    for row in rows:
        cells.setdefault((row["task_id"], row["arm"], int(row["trial"])), []).append(row)
    expected = set(schedule(repetitions))
    successes = {key for key, group in cells.items() if any(r["pass"] == "TRUE" for r in group)}
    raw, adjusted = ({arm: [] for arm in ARMS} for _ in range(2))
    for key in successes:
        group = cells[key]
        raw[key[1]].append(sum(int(r["total_tokens"] or 0) for r in group))
        adjusted[key[1]].append(sum(int(r["total_tokens"] or 0) - floor * int(r["response_count"] or 0) for r in group))
    medians = {arm: statistics.median(v) if v else None for arm, v in adjusted.items()}
    raw_medians = {arm: statistics.median(v) if v else None for arm, v in raw.items()}
    textual = {arm: medians[arm] for arm in TEXTUAL if medians[arm]}
    lowest = min(textual, key=textual.get) if textual else None
    ratio = medians["XAX"] / textual[lowest] if lowest and medians["XAX"] else None
    raw_ratio = raw_medians["XAX"] / min(raw_medians[a] for a in TEXTUAL if raw_medians[a]) if lowest and raw_medians["XAX"] else None
    complete = expected <= successes
    accounting = bool(rows) and all(r["accounting_complete"] == "TRUE" for r in rows) and not [
        p for p in runs.glob("mf-*/attempt.json") if not (p.parent / "result.json").exists()]
    profiles = {r["profile_sha256"] for r in rows}
    valid = complete and accounting and len(profiles) == 1 and ratio is not None
    status = ("TARGET_MET" if valid and ratio <= base.R5_TARGET else
              "ACCEPTED_WITHIN_TOLERANCE" if valid and ratio <= base.R5_ACCEPTANCE else "NOT_R5")
    return {"format": "xax-jvm-r5-multifile-evidence-v1", "status": status, "model": base.MODEL, "reasoning": base.REASONING,
            "attempts": len(rows), "successful_cells": len(successes & expected), "required_cells": len(expected),
            "complete": complete, "accounting_complete": accounting, "profile_sha256": sorted(profiles),
            "client_floor_input_tokens": floor,
            "task_token_medians_excluding_client_floor": medians, "successful_task_medians_including_retries": raw_medians,
            "lowest_textual_arm": lowest, "xax_ratio_vs_lowest_textual_median": ratio, "raw_xax_ratio_vs_lowest_textual_median": raw_ratio,
            "r5_threshold": base.R5_TARGET, "r5_acceptance_threshold": base.R5_ACCEPTANCE,
            "total_recorded_tokens_by_arm": {arm: sum(int(r["total_tokens"] or 0) for r in rows if r["arm"] == arm) for arm in ARMS},
            "failed_attempts_by_arm": {arm: sum(r["pass"] != "TRUE" for r in rows if r["arm"] == arm) for arm in ARMS},
            "source_csv": results.name, "source_sha256": base.digest(results.read_bytes()) if results.exists() else None,
            "limits": manifest()["limits"]}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=RESULTS)
    parser.add_argument("--runs", type=Path, default=RUNS)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--summarize-only", action="store_true")
    args = parser.parse_args(argv)
    results, runs = args.results.resolve(), args.runs.resolve()
    if args.summarize_only:
        print(json.dumps(summarize(results, runs, args.repetitions), indent=2))
        return 0
    profile, settings = pin_profile(runs)
    base.calibrate(runs)
    completed = {(r["task_id"], r["arm"], int(r["trial"])) for r in _rows(results) if r["pass"] == "TRUE"}
    for cell in schedule(args.repetitions):
        if cell in completed:
            continue
        if (runs / "STOP").exists():
            return 2
        row = run_cell(results, runs, profile, settings, *cell)
        results.with_suffix(".evidence.json").write_text(json.dumps(summarize(results, runs, args.repetitions), indent=2) + "\n", encoding="utf-8")
        if row["accounting_complete"] != "TRUE":
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
