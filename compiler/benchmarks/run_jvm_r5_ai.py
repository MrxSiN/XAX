"""Run the fixed-profile JVM R5 corpus and retain exact Codex usage."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from benchmarks.ai_native import check as check_base
from benchmarks.jvm_r5_ai import RUNS, check_source, check_xax, prepare_source, prepare_xax_task, task, tasks

RESULTS = RUNS.parent / "jvm-r5-bound-results.csv"
WORKSPACES = RUNS.parent / "runs-jvm-r5-bound"
FIELDS = (
    "task_id", "task_family", "arm", "trial", "model", "reasoning", "pass", "input_tokens", "output_tokens",
    "total_tokens", "cached_input_tokens", "turns", "elapsed_seconds", "failed_checks", "repair_count",
    "context_bytes", "semantic_entities", "session_id", "notes", "attempt", "trace_sha256", "client",
    "transmitted_bytes", "verifier_failures", "stale_transaction_failures",
)
MODEL = "gpt-5.6-luna"
REASONING = "low"
DEVELOPER = (
    "Controlled benchmark trial. Work only in the current directory. Follow the user protocol exactly. "
    "Inspect only the user-named editable context, execute the minimum commands needed, and stop after PASS."
)
LOCK = threading.Lock()


def _prompt(workspace: Path) -> str:
    return "\n".join(line.removeprefix("> ").removeprefix(">") for line in (workspace / "TASK.md").read_text(encoding="utf-8").splitlines() if line.startswith(">"))


def _workspace(task_id: str, arm: str, trial: int, attempt: int) -> Path:
    return WORKSPACES / f"{task_id}-{arm.lower()}-{trial}-{attempt}"


def _check(task_id: str, arm: str, workspace: Path) -> tuple[bool, str]:
    item = task(task_id)
    if arm in {"JAVA", "KOTLIN"}:
        return check_source(task_id, arm, workspace)
    if item.custom_xax:
        return check_xax(task_id, workspace)
    base_arm = "XAX-TYPED-LINE" if task_id == "jvm-10" else "XAX-DIRECT"
    return check_base(item.xax_task, base_arm, workspace)


def _context_bytes(task_id: str, arm: str, workspace: Path) -> int:
    item = task(task_id)
    if arm == "JAVA":
        path = workspace / "Program.java"
    elif arm == "KOTLIN":
        path = workspace / "Program.kt"
    else:
        return len(_prompt(workspace).encode())
    return path.stat().st_size if path.exists() else 0


def _events(stdout: str) -> list[dict]:
    events = []
    for line in stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events


def run_cell(task_id: str, arm: str, trial: int = 1) -> dict[str, object]:
    previous = [row for row in read_rows() if (row["task_id"], row["arm"], int(row["trial"])) == (task_id, arm, trial)]
    attempt = len(previous) + 1
    workspace = _workspace(task_id, arm, trial, attempt)
    if arm == "XAX":
        prepare_xax_task(task_id, workspace)
    else:
        prepare_source(task_id, arm, workspace)
    command = [
        shutil.which("codex") or "codex", "exec", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox", "-m", MODEL, "-c", f'model_reasoning_effort="{REASONING}"',
        "-c", f'developer_instructions={json.dumps(DEVELOPER)}', "-C", str(workspace), "--json", _prompt(workspace),
    ]
    started = time.perf_counter()
    environment = dict(os.environ)
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
    try:
        process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, env=environment)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        process = subprocess.CompletedProcess(command, 124, output, "model client timed out; token accounting may be incomplete")
    elapsed = time.perf_counter() - started
    events = _events(process.stdout)
    thread = next((event["thread_id"] for event in events if event.get("type") == "thread.started"), "")
    completions = [event for event in events if event.get("type") == "turn.completed"]
    usage = aggregate_usage(events)
    trace = workspace / "model-events.jsonl"
    trace.write_text(process.stdout, encoding="utf-8", newline="\n")
    (workspace / "model-stderr.txt").write_text(process.stderr, encoding="utf-8")
    commands = [event["item"] for event in events if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "command_execution"]
    failed_checks = sum(item.get("exit_code") not in (None, 0) for item in commands)
    passed, reason = _check(task_id, arm, workspace)
    if process.returncode or not usage:
        errors = [str(e.get("message", e.get("error", ""))) for e in events if e.get("type") in {"error", "turn.failed"}]
        reason = "; ".join(errors) or process.stderr.strip() or reason or f"codex exit {process.returncode}"
        passed = False
    row = {
        "task_id": task_id,
        "task_family": task(task_id).family,
        "arm": arm,
        "trial": trial,
        "model": MODEL,
        "reasoning": REASONING,
        "pass": str(passed).upper(),
        "input_tokens": usage.get("input_tokens", ""),
        "output_tokens": usage.get("output_tokens", ""),
        "total_tokens": (usage.get("input_tokens", 0) + usage.get("output_tokens", 0)) if usage else "",
        "cached_input_tokens": usage.get("cached_input_tokens", ""),
        "turns": len(completions),
        "elapsed_seconds": f"{elapsed:.3f}",
        "failed_checks": failed_checks,
        "repair_count": failed_checks,
        "context_bytes": _context_bytes(task_id, arm, workspace),
        "semantic_entities": "" if arm != "XAX" else 2 if task_id == "jvm-12" else 4 if task_id == "jvm-14" else load_entities(task_id),
        "session_id": thread,
        "notes": reason if not passed else "",
        "attempt": attempt,
        "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
        "client": subprocess.run([shutil.which("codex") or "codex", "--version"], capture_output=True, text=True).stdout.strip(),
        "transmitted_bytes": len((_prompt(workspace) + process.stdout).encode("utf-8")),
        "verifier_failures": sum("XAX." in item.get("aggregated_output", "") and item.get("exit_code") not in (None, 0) for item in commands),
        "stale_transaction_failures": sum("XAX.WORKSPACE.STALE_ROOT" in item.get("aggregated_output", "") for item in commands),
    }
    with LOCK:
        exists = RESULTS.exists() and RESULTS.stat().st_size
        with RESULTS.open("a", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDS)
            if not exists:
                writer.writeheader()
            writer.writerow(row)
        print(f"{task_id} {arm}: {row['pass']} {row['total_tokens']} tokens", flush=True)
    return row


def aggregate_usage(events: list[dict]) -> dict:
    usages = [event["usage"] for event in events if event.get("type") == "turn.completed" and event.get("usage")]
    if not usages:
        return {}
    return {field: sum(int(usage.get(field, 0)) for usage in usages)
            for field in ("input_tokens", "output_tokens", "cached_input_tokens")}


def load_entities(task_id: str) -> int:
    item = task(task_id)
    from benchmarks.ai_native import load_task
    return load_task(item.xax_task).semantic_entities or len(load_task(item.xax_task).initial) + 1


def read_rows() -> list[dict]:
    if not RESULTS.exists():
        return []
    with RESULTS.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def _completed() -> set[tuple[str, str, int]]:
    return {(row["task_id"], row["arm"], int(row["trial"])) for row in read_rows() if row["pass"] == "TRUE"}


def schedule(repetitions: int = 3) -> list[tuple[str, str, int]]:
    orders = (("JAVA", "KOTLIN", "XAX"), ("KOTLIN", "XAX", "JAVA"), ("XAX", "JAVA", "KOTLIN"))
    return [(item.task_id, arm, trial) for trial in range(1, repetitions + 1)
            for index, item in enumerate(tasks()) for arm in orders[(index + trial - 1) % len(orders)]]


def summarize(repetitions: int) -> dict:
    rows = read_rows()
    expected = set(schedule(repetitions))
    cells = {}
    for row in rows:
        key = row["task_id"], row["arm"], int(row["trial"])
        cells.setdefault(key, []).append(row)
    complete = set(cells) == expected and all(any(r["pass"] == "TRUE" for r in group) for group in cells.values())
    costs = {arm: [] for arm in ("JAVA", "KOTLIN", "XAX")}
    for key, group in cells.items():
        if any(row["pass"] == "TRUE" for row in group):
            # Fresh retries retain every failed attempt's model cost.
            costs[key[1]].append(sum(int(row["total_tokens"] or 0) for row in group))
    medians = {arm: statistics.median(values) if values else None for arm, values in costs.items()}
    ratio = medians["XAX"] / min(medians["JAVA"], medians["KOTLIN"]) if all(medians.values()) else None
    profiles = {(r["model"], r["reasoning"], r["client"]) for r in rows}
    accounting_complete = bool(rows) and all(r["total_tokens"] != "" for r in rows)
    gate = bool(complete and accounting_complete and repetitions >= 3 and len(profiles) == 1 and ratio is not None and ratio <= 0.5)
    return {
        "format": 2, "status": "GATE_MET_CORPUS_REVIEW_REQUIRED" if gate else "NOT_R5",
        "model": MODEL, "reasoning": REASONING, "profiles": sorted(profiles),
        "task_count": len(tasks()), "repetitions": repetitions, "attempts": len(rows),
        "successful_cells": len(_completed()), "required_cells": len(expected), "complete": complete,
        "accounting_complete": accounting_complete,
        "successful_task_medians_including_retries": medians,
        "partial_xax_ratio_vs_lowest_textual_median": ratio, "r5_threshold": 0.5,
        "meets_token_gate": gate,
        "source_csv": RESULTS.name, "source_sha256": hashlib.sha256(RESULTS.read_bytes()).hexdigest() if RESULTS.exists() else None,
        "limits": ["No automatic matrix promotion: semantic equivalence and corpus representativeness require review.",
                   "Creation retains the existing XAX scaffold; Java/Kotlin begin with an empty file.",
                   "Historical ADR-176 rows are not combined with this client/protocol run."],
    }


def main(argv: list[str] | None = None) -> int:
    global RESULTS, WORKSPACES
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--results", type=Path, default=RESULTS)
    parser.add_argument("--runs", type=Path, default=WORKSPACES)
    parser.add_argument("--summarize-only", action="store_true")
    parser.add_argument("--tasks", nargs="+", choices=[item.task_id for item in tasks()])
    parser.add_argument("--arms", nargs="+", choices=["JAVA", "KOTLIN", "XAX"])
    parser.add_argument("--stop-file", type=Path, help="stop between cells when this file exists")
    args = parser.parse_args(argv)
    if args.workers < 1 or args.repetitions < 1:
        parser.error("workers and repetitions must be positive")
    RESULTS, WORKSPACES = args.results.resolve(), args.runs.resolve()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    if args.summarize_only:
        print(json.dumps(summarize(args.repetitions), indent=2))
        return 0
    pending = [cell for cell in schedule(args.repetitions) if cell not in _completed()
               and (not args.tasks or cell[0] in args.tasks) and (not args.arms or cell[1] in args.arms)]
    # Sequential by default: stop at account/tooling blockage without burning
    # another model request for every remaining cell.
    if args.workers == 1:
        for cell in pending:
            if args.stop_file and args.stop_file.exists():
                return 2
            row = run_cell(*cell)
            RESULTS.with_suffix(".evidence.json").write_text(json.dumps(summarize(args.repetitions), indent=2) + "\n", encoding="utf-8")
            if not row["turns"]:
                return 2
        return 0
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(run_cell, *cell): cell for cell in pending}
        for future in as_completed(futures):
            future.result()
    RESULTS.with_suffix(".evidence.json").write_text(json.dumps(summarize(args.repetitions), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
