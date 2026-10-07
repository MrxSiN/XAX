"""Durable fixed-profile Java/Kotlin/XAX host-applied-response comparison.

Response-v10 (ADR-195) supplies every arm its context inline in one request:
no arm reads files or receives an out-of-band edit kind/target.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from benchmarks import run_jvm_r5_ai as accounting
from benchmarks.jvm_r5_ai import prepare_source, tasks, check_source, _compiler
from benchmarks.jvm_r5_response import SemanticTrial, unwrap_response, apply_patch_response, response_task

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RESULTS = HERE / "ai_native/jvm-r5-response-v12-results.csv"
RUNS = HERE / "ai_native/runs-jvm-r5-response-v12"
FIELDS = (*accounting.FIELDS, "profile_sha256", "response_count", "accounting_complete", "host_failures", "instruction_context_sha256",
          "context_reads", "unexpected_context_commands")
# ADR-196 minimal client: every optional tool, skill and instruction block the
# pinned client lets configuration remove is removed, identically for all arms.
_DISABLED = ("plugins", "remote_plugin", "apps", "skill_search", "shell_tool", "unified_exec", "image_generation",
             "view_image", "sleep_tool", "browser_use", "browser_use_external", "computer_use", "multi_agent",
             "multi_agent_v2", "tool_suggest", "goals", "in_app_browser", "code_mode_host", "tool_call_mcp_elicitation",
             "workspace_dependencies", "hooks", "shell_snapshot", "memories")
_EXCLUDED = ("include_skills_usage_instructions", "include_permissions_instructions", "include_apps_instructions",
             "include_environment_context", "include_collaboration_mode_instructions")
CLIENT_FLAGS = (*(flag for name in _DISABLED for flag in ("--disable", name)),
                *(flag for name in _EXCLUDED for flag in ("-c", f"{name}=false")),
                "-c", "skills.bundled.enabled=false", "-c", 'web_search="disabled"')
MODEL, REASONING = "gpt-6-luna", "low"
BASE = "Return only the requested final response. No tools."
CALIBRATION_PROMPT = "."
SOURCES = ("compiler/src/xax_compiler.py", "compiler/src/xax_workspace.py", "compiler/src/xax_local_protocol.py",
           "compiler/src/xax_graph_builder.py", "compiler/src/xax_jvm.py", "compiler/benchmarks/ai_native/__init__.py",
           "compiler/benchmarks/jvm_r5_ai.py", "compiler/benchmarks/jvm_r5_response.py",
           "compiler/benchmarks/run_jvm_r5_ai.py", "compiler/benchmarks/run_jvm_r5_response.py", "docs/09_AI_PROTOCOL.md")
# ADR-195: 0.50 is the R5 target; the owner accepts up to 0.55.
R5_TARGET, R5_ACCEPTANCE = 0.50, 0.55
DEVELOPER = ("Controlled benchmark. Work only in the current directory. Follow the user response contract exactly. "
             "The host applies and checks your final response. All context is in the request; do not use tools, edit files, "
             "run checks, or acknowledge success. Return only the requested final response.")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest():
    return {"format": "xax-jvm-r5-response-v12", "model": MODEL, "reasoning": REASONING,
            "client": subprocess.run([shutil.which("codex") or "codex", "--version"], capture_output=True, text=True).stdout.strip(),
            "developer": DEVELOPER, "base_instructions": BASE, "client_flags": list(CLIENT_FLAGS), "sources": {name: digest((REPO / name).read_bytes()) for name in SOURCES},
            "repetitions": 3, "required_cells": 135,
            "method": "Same-prefill comparison (ADR-195): every arm receives its complete context inline and returns one final request with no tool use; host applies/verifies. Textual arms get their named program inline (jvm-15: the lines naming the target, the same named-symbol query the XAX view answers) and return a standard context patch; creation starts empty in all arms. XAX receives its ordinary semantic view and role names, with no out-of-band mutation kind or target. Textual results pass on exact normalized source or equal compiled JVM instructions that differ from the initial program; XAX results pass on the exact semantic root.",
            "limits": ["Exact semantic-root XAX targets and compiled-instruction textual checks remain more restrictive than behavioral equivalence.",
                       "Source-only textual targets (move, unused constant) still require the exact normalized source, as XAX requires the exact root.",
                       "jvm-09 XAX resource effects are proof values erased by the JVM lowering; textual arms execute a runtime resource tracker.",
                       "The client's fixed base instructions and tool schemas are common to every arm and counted in every total.",
                       "One JVM host and one requested model identifier; no separate provider weights digest.",
                       "Prior interrupted/exploratory profiles remain separately reported; no unknown-cost profile can satisfy the gate.",
                       "semantic_entities counts supplied root/function/block/parameter/node/type definitions and valid construction entities, per submitted response round, not canonical store objects.",
                       "transmitted_bytes counts submitted prompts plus streamed JSON event bytes; provider framing is unavailable.",
                       "unexpected_context_commands flags commands whose named files need manual context review."]}


def calibrate(runs, samples=3):
    """Measure the fixed per-request client floor F: the input tokens of a
    request whose user prompt is a single character, under the same flags,
    model and instructions. Every sample must agree; the result is pinned."""
    path = runs / "calibration.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    values, traces = [], []
    for index in range(samples):
        workspace = runs / "calibration" / str(index)
        workspace.mkdir(parents=True)
        code, events, _response, trace, _count, _context = _model(workspace, CALIBRATION_PROMPT, 1)
        usage = accounting.aggregate_usage(events)
        if code or not usage:
            raise ValueError("calibration request failed; inspect " + str(trace))
        values.append(usage["input_tokens"])
        traces.append(digest(trace.read_bytes()))
    if len(set(values)) != 1:
        raise ValueError(f"client floor is not stable: {values}")
    result = {"client_floor_input_tokens": values[0], "samples": values, "trace_sha256": traces,
              "prompt": CALIBRATION_PROMPT, "model": MODEL, "reasoning": REASONING}
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def pin_profile(runs, current=None, sources=SOURCES):
    current = current or manifest()
    # Fail before requesting inference if the host cannot check all three arms.
    current["toolchain"] = {"python": sys.version}
    for name, executable in (("java", shutil.which("java")), ("javap", shutil.which("javap")),
                             ("javac", _compiler("JAVA")), ("kotlinc", _compiler("KOTLIN"))):
        if not executable:
            raise ValueError(f"{name} unavailable")
        version = subprocess.run([executable, "-version"], capture_output=True, text=True, timeout=30)
        if version.returncode:
            raise ValueError(f"{name} failed: {version.stderr.strip()}")
        current["toolchain"][name] = (version.stdout + version.stderr).strip()
    path = runs / "manifest.json"
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != current:
            raise ValueError("profile changed; use a new results/runs pair rather than mixing source versions")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(current, indent=2) + '\n', encoding="utf-8")
        for name in sources:
            destination = runs / "source-snapshot" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((REPO / name).read_bytes())
    return digest(path.read_bytes()), current


def _source_prompt(item, arm, path, *, repair=""):
    creation = item.family == "creation"
    contract = (f"The program is empty; no existing file needs inspection. Return the complete contents of {path.name}." if creation else
                f"Return only an apply_patch update: *** Begin Patch, *** Update File: {path.name}, @@ context hunks, *** End Patch. Use exact old context; no line counts are needed.")
    race = " A concurrent update may invalidate this snapshot; the host returns fresh context on conflict." if item.task_id == "jvm-10" else ""
    view = "" if creation else f"\n{path.name}{' (lines naming target)' if item.family == 'large-application' else ''}:\n" + _context(item, path)
    return item.prompt + '\n' + contract + race + view + "\nThe host applies your response and runs the compiler and exact-target/behavior checks. No tools." + repair


def _context(item, path):
    """The inline textual view: the named file, or for the large application the
    lines naming its target, the textual counterpart of XAX's named-role view."""
    text = path.read_text(encoding="utf-8")
    if item.family == "large-application":
        text = "".join(line for line in text.splitlines(keepends=True) if "target" in line)
    return text


def _model(workspace, prompt, round_index):
    trace = workspace / f"model-events-{round_index}.jsonl"
    stderr = workspace / f"model-stderr-{round_index}.txt"
    command = [shutil.which("codex") or "codex", "exec", *CLIENT_FLAGS, "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
               "--dangerously-bypass-approvals-and-sandbox", "-m", MODEL,
               "-c", f'model_reasoning_effort="{REASONING}"',
               "-c", f'developer_instructions={json.dumps(DEVELOPER)}',
               "-c", f'model_instructions_file={json.dumps((workspace / "base-instructions.txt").as_posix())}',
               "-C", str(workspace), "--json", prompt]
    (workspace / "base-instructions.txt").write_text(BASE, encoding="utf-8")
    environment = dict(os.environ)
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
    (workspace / f"request-{round_index}.json").write_text(json.dumps({"prompt": prompt, "model": MODEL,
        "reasoning": REASONING, "started_unix": time.time()}, indent=2), encoding="utf-8")
    with trace.open("w", encoding="utf-8") as output, stderr.open("w", encoding="utf-8") as errors:
        process = subprocess.Popen(command, stdout=output, stderr=errors, env=environment)
        try:
            code = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            code = 124
    raw = trace.read_text(encoding="utf-8", errors="replace")
    events = accounting._events(raw)
    messages = [event["item"]["text"] for event in events if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "agent_message"]
    context = instruction_context(events)
    if context:
        (workspace / f"model-context-{round_index}.json").write_text(json.dumps(context, sort_keys=True, indent=2), encoding="utf-8")
    context_hash = digest(json.dumps(context, sort_keys=True).encode()) if context else ""
    return code, events, messages[-1] if messages else "", trace, len((prompt + raw).encode("utf-8")), context_hash


def instruction_context(events):
    """Capture common instructions from this controlled client's own rollout.

    Tool schemas are fixed by the pinned client/flags; provider framing is not
    exposed. Never inspect unrelated conversations or copy account metadata.
    """
    thread = next((event["thread_id"] for event in events if event.get("type") == "thread.started"), None)
    if not thread:
        return None
    home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    matches = list((home / "sessions").glob(f"**/*{thread}.jsonl"))
    if len(matches) != 1:
        return None
    base, developer = None, None
    for line in matches[0].read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        payload = event.get("payload", {})
        if event.get("type") == "session_meta":
            base = payload.get("base_instructions")
        if event.get("type") == "response_item" and payload.get("type") == "message" and payload.get("role") == "developer":
            developer = payload.get("content")
            break
    return {"base_instructions": base, "developer": developer} if base and developer else None


def _rows(results):
    if not results.exists():
        return []
    with results.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def summarize(results, runs, repetitions):
    accounting.RESULTS = results
    evidence = accounting.summarize(repetitions)
    rows = _rows(results)
    unknown = [str(path.relative_to(runs)) for path in runs.glob("jvm-*/attempt.json")
               if not (path.parent / "result.json").exists()]
    evidence["unrecorded_attempts"] = unknown
    evidence["accounting_complete"] = evidence["accounting_complete"] and not unknown and all(row["accounting_complete"] == "TRUE" for row in rows)
    profiles = {row["profile_sha256"] for row in rows}
    contexts = {context for row in rows for context in json.loads(row.get("instruction_context_sha256") or '[]')}
    context_complete = bool(rows) and all(json.loads(row.get("instruction_context_sha256") or '[]') and
        all(json.loads(row["instruction_context_sha256"])) for row in rows)
    evidence["profile_sha256"] = sorted(profiles)
    evidence["instruction_context_sha256"] = sorted(contexts)
    evidence["instruction_context_complete"] = context_complete
    evidence["raw_xax_ratio_vs_lowest_textual_median"] = evidence["partial_xax_ratio_vs_lowest_textual_median"]
    calibration = runs / "calibration.json"
    floor = json.loads(calibration.read_text(encoding="utf-8"))["client_floor_input_tokens"] if calibration.exists() else None
    ratio = None
    if floor is not None:
        evidence["client_floor_input_tokens"] = floor
        adjusted = adjusted_medians(rows, floor)
        evidence["task_token_medians_excluding_client_floor"] = adjusted
        if all(adjusted.values()):
            ratio = adjusted["XAX"] / min(adjusted["JAVA"], adjusted["KOTLIN"])
    evidence["partial_xax_ratio_vs_lowest_textual_median"] = ratio
    valid = bool(evidence["complete"] and repetitions >= 3 and evidence["accounting_complete"] and len(profiles) == 1
                 and context_complete and len(contexts) == 1 and ratio is not None)
    evidence["r5_threshold"], evidence["r5_acceptance_threshold"] = R5_TARGET, R5_ACCEPTANCE
    evidence["meets_token_gate"] = valid and ratio <= R5_ACCEPTANCE
    evidence["meets_token_target"] = valid and ratio <= R5_TARGET
    evidence["status"] = ("TARGET_MET" if evidence["meets_token_target"] else
                          "ACCEPTED_WITHIN_TOLERANCE" if evidence["meets_token_gate"] else "NOT_R5")
    evidence["limits"] = manifest()["limits"]
    evidence["host_applied_responses"] = True
    evidence["creation_empty_for_all_arms"] = True
    evidence["large_application_helpers_per_arm"] = 160
    return evidence


def adjusted_medians(rows, floor):
    """Successful-cell medians after removing F once per client request; every
    failed attempt's remaining cost still counts (ADR-196)."""
    import statistics
    cells = {}
    for row in rows:
        cells.setdefault((row["task_id"], row["arm"], int(row["trial"])), []).append(row)
    costs = {arm: [] for arm in ("JAVA", "KOTLIN", "XAX")}
    for (task_id, arm, trial), group in cells.items():
        if any(row["pass"] == "TRUE" for row in group):
            costs[arm].append(sum(int(row["total_tokens"] or 0) - floor * int(row["response_count"] or 0) for row in group))
    return {arm: statistics.median(values) if values else None for arm, values in costs.items()}


def run_cell(results, runs, profile, settings, task_id, arm, trial, max_responses=3):
    previous = [r for r in _rows(results) if (r["task_id"], r["arm"], int(r["trial"])) == (task_id, arm, trial)]
    attempt = len(previous) + 1
    workspace = runs / f"{task_id}-{arm.lower()}-{trial}-{attempt}"
    if workspace.exists():
        raise ValueError(f"unrecorded attempt present: {workspace}; recover its traces before continuing")
    item = response_task(task_id)
    semantic = SemanticTrial(task_id) if arm == "XAX" else None
    if semantic:
        workspace.mkdir(parents=True)
        prompt = semantic.prompt()
    else:
        prepare_source(task_id, arm, workspace, item=item)
        source = workspace / ("Program.java" if arm == "JAVA" else "Program.kt")
        prompt = _source_prompt(item, arm, source)
    (workspace / "TASK.md").write_text(prompt, encoding="utf-8")
    attempt_data = {"task_id": task_id, "arm": arm, "trial": trial, "attempt": attempt, "profile_sha256": profile,
                    "started_unix": time.time()}
    (workspace / "attempt.json").write_text(json.dumps(attempt_data, indent=2), encoding="utf-8")
    started = time.perf_counter()
    events, traces, failures, transmitted, contexts = [], [], [], 0, []
    passed, complete, reason = False, True, ""
    for round_index in range(1, max_responses + 1):
        original = source.read_text(encoding="utf-8") if not semantic and source.exists() else ""
        if semantic:
            semantic.entities += semantic.prompt_entities
        code, new_events, response, trace, count, context = _model(workspace, prompt, round_index)
        contexts.append(context)
        events.extend(new_events)
        traces.append(trace)
        transmitted += count
        response = unwrap_response(response)
        (workspace / f"response-{round_index}.txt").write_text(response, encoding="utf-8")
        if code or not accounting.aggregate_usage(new_events):
            complete = bool(accounting.aggregate_usage(new_events)) and code != 124
            reason = "model client failure or incomplete usage; inspect retained trace"
            break
        try:
            if semantic:
                passed, reason = semantic.apply(response)
                if passed:
                    passed, reason = semantic.check_jvm()
                if passed:
                    (workspace / "program.xax").write_bytes(semantic.reader.data)
                elif semantic.workspace is not None and semantic.workspace.generation != semantic.session.generation and task_id != "jvm-10":
                    # A semantically valid wrong target was published. Start a
                    # fresh attempt instead of silently restoring canonical state.
                    failures.append(reason)
                    break
                else:
                    prompt = semantic.repair_prompt(reason)
            else:
                current = source.read_text(encoding="utf-8") if source.exists() else ""
                if current != original:
                    raise ValueError("model changed the source outside the final-response contract")
                if task_id == "jvm-10" and round_index == 1:
                    source.write_text(original.replace("concurrent = 9", "concurrent = 10"), encoding="utf-8")
                    raise ValueError("STALE_SNAPSHOT: concurrent changed from 9 to 10; inspect the current file and preserve it")
                if item.family == "creation":
                    source.write_text(response, encoding="utf-8", newline="\n")
                else:
                    apply_patch_response(source, response, original)
                passed, reason = check_source(task_id, arm, workspace, item=item, compiled_equivalence=True)
                prompt = _source_prompt(item, arm, source, repair="\nPrevious response failed: " + reason)
        except (ValueError, KeyError, OSError, RuntimeError) as error:
            reason = str(error)
            if semantic:
                prompt = semantic.repair_prompt(reason)
            else:
                prompt = _source_prompt(item, arm, source, repair="\nPrevious response failed: " + reason)
        (workspace / f"host-check-{round_index}.json").write_text(json.dumps({"pass": passed, "diagnostic": reason}), encoding="utf-8")
        if passed:
            break
        failures.append(reason)
    usage = accounting.aggregate_usage(events)
    commands = [e["item"] for e in events if e.get("type") == "item.completed" and e.get("item", {}).get("type") == "command_execution"]
    failed_commands = sum(item.get("exit_code") not in (None, 0) for item in commands)
    import re
    allowed_name = "Program.java" if arm == "JAVA" else "Program.kt"
    unexpected = [command["command"] for command in commands if semantic or
                  set(re.findall(r"[\w.-]+\.(?:java|kt|py|md|txt|json|csv|toml)\b", command["command"])) != {allowed_name}]
    row = dict.fromkeys(FIELDS, "")
    row.update(attempt_data)
    row.pop("started_unix")
    row.update(task_family=item.family, model=MODEL, reasoning=REASONING, **{"pass": str(passed).upper()},
               input_tokens=usage.get("input_tokens", ""), output_tokens=usage.get("output_tokens", ""),
               total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0) if usage else "",
               cached_input_tokens=usage.get("cached_input_tokens", ""), turns=sum(e.get("type") == "turn.completed" for e in events),
               elapsed_seconds=f"{time.perf_counter()-started:.3f}", failed_checks=failed_commands + len(failures), repair_count=max(0, len(traces)-1),
               context_bytes=len((workspace / "TASK.md").read_bytes()), semantic_entities=semantic.entities if semantic else "",
               session_id=";".join(e["thread_id"] for e in events if e.get("type") == "thread.started"),
               notes=reason if not passed else "", trace_sha256=digest(b''.join(trace.read_bytes() for trace in traces)),
               client=settings["client"], transmitted_bytes=transmitted, verifier_failures=semantic.verifier_failures if semantic else "",
               stale_transaction_failures=semantic.stale_failures if semantic else sum("STALE_SNAPSHOT" in failure for failure in failures),
               response_count=len(traces), accounting_complete=str(complete and bool(usage)).upper(), host_failures=json.dumps(failures), instruction_context_sha256=json.dumps(contexts),
               context_reads=len(commands), unexpected_context_commands=json.dumps(unexpected))
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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=RESULTS)
    parser.add_argument("--runs", type=Path, default=RUNS)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--tasks", nargs="+", choices=[item.task_id for item in tasks()])
    parser.add_argument("--arms", nargs="+", choices=["JAVA", "KOTLIN", "XAX"])
    parser.add_argument("--summarize-only", action="store_true")
    parser.add_argument("--stop-file", type=Path)
    args = parser.parse_args(argv)
    if args.repetitions < 1:
        parser.error("positive repetitions required")
    results, runs = args.results.resolve(), args.runs.resolve()
    results.parent.mkdir(parents=True, exist_ok=True)
    if args.summarize_only:
        print(json.dumps(summarize(results, runs, args.repetitions), indent=2))
        return 0
    profile, settings = pin_profile(runs)
    calibrate(runs)
    completed = {(r["task_id"],r["arm"],int(r["trial"])) for r in _rows(results) if r["pass"] == "TRUE"}
    for cell in accounting.schedule(args.repetitions):
        if cell in completed or args.tasks and cell[0] not in args.tasks or args.arms and cell[1] not in args.arms:
            continue
        if (args.stop_file or runs / "STOP").exists():
            return 2
        row = run_cell(results, runs, profile, settings, *cell)
        evidence = summarize(results, runs, args.repetitions)
        results.with_suffix(".evidence.json").write_text(json.dumps(evidence, indent=2) + '\n', encoding="utf-8")
        if not row["turns"] or row["accounting_complete"] != "TRUE":
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
