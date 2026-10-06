"""Run the fixed-profile JVM R5 corpus and retain exact Codex usage."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from benchmarks.ai_native import check as check_base
from benchmarks.jvm_r5_ai import RUNS, check_source, check_xax, task, tasks

RESULTS = RUNS.parent / "jvm-r5-full-results.csv"
FIELDS = (
    "task_id", "task_family", "arm", "trial", "model", "reasoning", "pass", "input_tokens", "output_tokens",
    "total_tokens", "cached_input_tokens", "turns", "elapsed_seconds", "failed_checks", "repair_count",
    "context_bytes", "semantic_entities", "session_id", "notes",
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


def _workspace(task_id: str, arm: str) -> Path:
    return RUNS / f"{task_id}-{arm.lower()}"


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


def run_cell(task_id: str, arm: str) -> dict[str, object]:
    workspace = _workspace(task_id, arm)
    command = [
        shutil.which("codex") or "codex", "exec", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox", "-m", MODEL, "-c", f'model_reasoning_effort="{REASONING}"',
        "-c", f'developer_instructions={json.dumps(DEVELOPER)}', "-C", str(workspace), "--json", _prompt(workspace),
    ]
    started = time.perf_counter()
    process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    elapsed = time.perf_counter() - started
    events = _events(process.stdout)
    thread = next((event["thread_id"] for event in events if event.get("type") == "thread.started"), "")
    completions = [event for event in events if event.get("type") == "turn.completed"]
    usage = completions[-1].get("usage", {}) if completions else {}
    commands = [event["item"] for event in events if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "command_execution"]
    failed_checks = sum(item.get("exit_code") not in (None, 0) for item in commands)
    passed, reason = _check(task_id, arm, workspace)
    if process.returncode or not usage:
        reason = reason or process.stderr.strip() or f"codex exit {process.returncode}"
        passed = False
    row = {
        "task_id": task_id,
        "task_family": task(task_id).family,
        "arm": arm,
        "trial": 1,
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
        "notes": reason,
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


def load_entities(task_id: str) -> int:
    item = task(task_id)
    from benchmarks.ai_native import load_task
    return load_task(item.xax_task).semantic_entities or len(load_task(item.xax_task).initial) + 1


def _completed() -> set[tuple[str, str]]:
    if not RESULTS.exists():
        return set()
    with RESULTS.open(newline="", encoding="utf-8") as file:
        return {(row["task_id"], row["arm"]) for row in csv.DictReader(file)}


def schedule() -> list[tuple[str, str]]:
    orders = (("JAVA", "KOTLIN", "XAX"), ("KOTLIN", "XAX", "JAVA"), ("XAX", "JAVA", "KOTLIN"))
    return [(item.task_id, arm) for index, item in enumerate(tasks()) for arm in orders[index % len(orders)]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args(argv)
    pending = [cell for cell in schedule() if cell not in _completed()]
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(run_cell, *cell): cell for cell in pending}
        for future in as_completed(futures):
            future.result()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
