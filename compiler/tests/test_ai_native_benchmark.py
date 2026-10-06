import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from benchmarks.ai_native import (
    FRAMINGS, HANDLES, REFERENCE_EDITS, _build, _expected_root, _variant, _workspace, check, corpus_report, decode_packet,
    encode_packet, load_task, oi01_tasks, prepare, record, record_session, summarize, summarize_oi01, summarize_transport,
    tasks, transport_report, trial_main,
)


class TransportCandidateTests(unittest.TestCase):
    def test_every_candidate_decodes_to_one_canonical_transaction_and_target(self):
        for task in oi01_tasks():
            expected_root = _expected_root(task)
            decoded = set()
            for handles in HANDLES:
                for framing in FRAMINGS:
                    packet = encode_packet(framing, handles, REFERENCE_EDITS[task.task_id], root=task.reference_root, task=task)
                    self.assertEqual(packet, encode_packet(framing, handles, REFERENCE_EDITS[task.task_id], root=task.reference_root, task=task))
                    transaction = decode_packet(task, framing, handles, packet)
                    decoded.add(transaction)
                    result = _workspace(task)[0].commit(transaction)
                    self.assertEqual(expected_root, result.root, (task.task_id, handles, framing))
            self.assertEqual(1, len(decoded), task.task_id)

    def test_whitespace_is_not_significant(self):
        task = load_task("task-02")
        canonical = decode_packet(task, "pipe", "typed", "X1|R0.0;O|N1|mul.wrap")
        self.assertEqual(canonical, decode_packet(task, "pipe", "typed", " X1 | R0.0 ;\n O |N1| mul.wrap ;"))
        self.assertEqual(canonical, decode_packet(task, "line", "typed", "X1   R0.0\n\n  set-op\tN1 mul.wrap"))
        self.assertEqual(canonical, decode_packet(task, "json", "typed", '[ "X1", "R0.0",\n ["O", "N1", "mul.wrap"] ]'))

    def test_malformed_and_cross_namespace_packets_reject(self):
        task = load_task("task-01")
        bad = [
            ("pipe", "typed", "X2|R0.0;C|N0|7"),           # unknown version
            ("pipe", "typed", "X1|R0.0"),                  # no mutation
            ("pipe", "typed", "X1|F0;C|N0|7"),             # root is not an alias
            ("pipe", "typed", "X1|R0.0;Z|N0|7"),           # unknown verb
            ("pipe", "typed", "X1|R0.0;C|N0|7|9"),         # unknown extra field
            ("pipe", "typed", "X1|R0.0;C|1|7"),            # unified handle in typed packet
            ("pipe", "unified", "X1|R0.0;C|N0|7"),         # typed handle in unified packet
            ("pipe", "unified", "X1|R0.0;C|01|7"),         # non-canonical integer handle
            ("pipe", "typed", "X1|R0.0;C|N0|+7"),          # non-canonical literal
            ("pipe", "typed", "X1|R0.0;C|N1|7"),           # not a constant node
            ("line", "typed", "X1 R0.0\nC N0 7"),          # short verb in long-verb framing
            ("line", "typed", "X1 R0.0\nmove N1 N0"),
            ("json", "typed", '["X1","R0.0",["C","N0","7"]]'),   # literal must be a JSON integer
            ("json", "unified", '["X1","R0.0",["C","1",7]]'),    # unified handle must be a JSON integer
            ("json", "typed", '["X1","R0.0",[["C"],"N0",7]]'),
            ("json", "typed", '{"v":"X1"}'),
            ("json", "typed", '["X1","R0.0",['),
        ]
        for framing, handles, packet in bad:
            with self.assertRaises(ValueError, msg=packet):
                decode_packet(task, framing, handles, packet)

        extended = load_task("task-07")
        bad_extended = [
            ("pipe", "typed", "X1|R0.01;X|N0|0|0|P0"),
            ("pipe", "typed", "X1|R0.0;X|N0|00|0|P0"),
            ("pipe", "unified", "X1|R0.0;Y|3|0|0|P1"),
            ("json", "unified", '["X1","R0.0",["Y",3,0,0,"1"]]'),
            ("line", "typed", "X1 R0.0\ndisconnect-edge N0 0 0 @0"),
        ]
        for framing, handles, packet in bad_extended:
            with self.assertRaises(ValueError, msg=packet):
                decode_packet(extended, framing, handles, packet)
        creation = load_task("task-06")
        with self.assertRaises(ValueError):
            decode_packet(creation, "pipe", "typed", "X1|R0.0;I|N1|0|7;U|N2|1|@00")

    def test_stale_root_alias_is_rejected_by_workspace(self):
        task = load_task("task-01")
        result = _workspace(task)[0].commit(decode_packet(task, "pipe", "unified", "X1|R0.1;C|1|7"))
        self.assertFalse(result.committed)

    def test_variant_trial_uses_its_namespace_and_framing(self):
        with tempfile.TemporaryDirectory() as directory:
            trial = prepare("task-01", "XAX-unified-pipe", Path(directory) / "task")
            self.assertIn("`C|H|VALUE`", (trial / "TASK.md").read_text())
            self.assertEqual("X1|R0.0", (trial / "packet.txt").read_text())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, trial_main("task-01", trial, ["inspect"], "XAX-UNIFIED-PIPE"))
                self.assertEqual(1, trial_main("task-01", trial, ["mutate", "set-constant", "1", "7"], "XAX-UNIFIED-PIPE"))
            self.assertTrue(output.getvalue().startswith(
                "R0 f(0:u32)->u32\n1 const 3\n2 add.wrap 0 1\n3 mul.wrap 2 1\nreturn 3\n"))
            (trial / "packet.txt").write_text("X1|R0.0;C|1|99|7")
            self.assertFalse(check("task-01", "XAX-UNIFIED-PIPE", trial)[0])
            (trial / "packet.txt").write_text("X1|R0.0;C|1|7")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, trial_main("task-01", trial, ["test"], "XAX-UNIFIED-PIPE"))
            self.assertEqual((True, ""), check("task-01", "XAX-UNIFIED-PIPE", trial))
        with self.assertRaisesRegex(ValueError, "arm must be"):
            prepare("task-01", "XAX-numeric-pipe", Path(directory) / "other")

    def test_transport_report_is_deterministic_and_complete(self):
        try:
            import tiktoken  # noqa: F401
            first, second = transport_report(), transport_report()
        except Exception as error:  # optional measurement dependency or offline encoding cache
            self.skipTest(f"tokenizer unavailable: {error}")
        self.assertEqual(first, second)
        self.assertEqual(len(tasks()) * len(HANDLES) * len(FRAMINGS), len(first["rows"]))
        self.assertTrue(all(row["reaches_target"] for row in first["rows"]))
        self.assertIsNone(first["model_run"])
        self.assertEqual(7, len(summarize_transport(first).splitlines()))

    def test_corpus_report_is_deterministic_without_tokenizer(self):
        first, second = corpus_report(), corpus_report()
        self.assertEqual(first, second)
        self.assertIsNone(first["model_run"])
        self.assertEqual(len(oi01_tasks()) * len(HANDLES) * len(FRAMINGS), len(first["rows"]))
        self.assertTrue(all(len(row["target_root"]) == 64 for row in first["rows"]))

    def test_missing_oi01_families_are_exact_and_prefilled_repairs_reject(self):
        extended = oi01_tasks()[5:]
        self.assertEqual(
            ["creation", "control-flow", "type-repair", "resource-effect-repair", "stale-root", "optimization"],
            [task.family for task in extended],
        )
        expected_failures = {
            "task-08": "XAX.STRUCT.OP_TYPE",
            "task-09": "XAX.RESOURCE.DROP",
            "task-10": "XAX.WORKSPACE.STALE_ROOT",
        }
        for task in extended:
            self.assertEqual(32, len(_expected_root(task)))
            if task.prefill:
                for handles in HANDLES:
                    for framing in FRAMINGS:
                        packet = encode_packet(framing, handles, task.prefill, root=task.prefill_root, task=task)
                        result = _workspace(task)[0].verify(decode_packet(task, framing, handles, packet))
                        self.assertFalse(result.verified)
                        self.assertEqual(expected_failures[task.task_id], result.diagnostic.code)
            with tempfile.TemporaryDirectory() as directory:
                trial = prepare(task.task_id, "XAX-TYPED-LINE", Path(directory) / task.task_id)
                if task.prefill:
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(1, trial_main(task.task_id, trial, ["test"], "XAX-TYPED-LINE"))
                (trial / "packet.txt").write_text(
                    encode_packet("line", "typed", REFERENCE_EDITS[task.task_id], root=task.reference_root, task=task)
                )
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(0, trial_main(task.task_id, trial, ["test"], "XAX-TYPED-LINE"))
                self.assertEqual((True, ""), check(task.task_id, "XAX-TYPED-LINE", trial))


class TinyAINativeBenchmarkTests(unittest.TestCase):
    def test_five_tasks_have_valid_distinct_xax_states(self):
        self.assertEqual(5, len(tasks()))
        self.assertEqual(5, len({task.task_id for task in tasks()}))
        for task in tasks():
            initial, _ = _build(task.initial, task.result)
            target, _ = _build(task.target, task.result)
            self.assertNotEqual(initial.root_cid, target.root_cid, task.task_id)

    def test_prepare_exposes_both_arms_and_exact_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for task in tasks():
                for arm in ("C", "XAX"):
                    trial = prepare(task.task_id, arm, root / f"{task.task_id}-{arm}")
                    instructions = (trial / "TASK.md").read_text()
                    self.assertIn(task.prompt, instructions)
                    self.assertTrue((trial / ("program.c" if arm == "C" else "transaction.txt")).is_file())
                    if arm == "C":
                        self.assertIn("python c.py", instructions)
                        self.assertTrue((trial / "c.py").is_file())
                    else:
                        self.assertIn("python xax.py inspect", instructions)
                        self.assertTrue((trial / "xax.py").is_file())

    def test_c_checker_rejects_initial_and_accepts_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for task in tasks():
                trial = prepare(task.task_id, "C", root / task.task_id)
                self.assertFalse(check(task.task_id, "C", trial)[0])
                (trial / "program.c").write_text(task.c_target)
                self.assertTrue(check(task.task_id, "C", trial)[0])

    def test_xax_checker_accepts_each_native_transaction(self):
        commands = {
            "task-01": ["mutate", "set-constant", "N0", "7"],
            "task-02": ["mutate", "set-op", "N1", "mul.wrap"],
            "task-03": ["mutate", "replace-operand", "N2", "1", "N1"],
            "task-04": ["mutate", "delete", "1"],
            "task-05": ["mutate", "move", "N1", "before", "N0"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for task in tasks():
                trial = prepare(task.task_id, "XAX", root / task.task_id)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(0, trial_main(task.task_id, trial, commands[task.task_id]))
                    self.assertEqual(0, trial_main(task.task_id, trial, ["verify"]))
                    self.assertEqual(0, trial_main(task.task_id, trial, ["test"]))
                passed, reason = check(task.task_id, "XAX", trial)
                self.assertTrue(passed, (task.task_id, reason))

    def test_direct_xax_arm_applies_and_checks_in_one_command(self):
        with tempfile.TemporaryDirectory() as directory:
            trial = prepare("task-01", "XAX-DIRECT", Path(directory) / "task")
            instructions = (trial / "TASK.md").read_text()
            self.assertIn("N0 const 3", instructions)
            self.assertIn("python xax.py apply", instructions)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(0, trial_main("task-01", trial, ["apply", "set-constant", "N0", "7"], "XAX-DIRECT"))
            self.assertEqual("PASS\n", output.getvalue())
            self.assertEqual((True, ""), check("task-01", "XAX-DIRECT", trial))

            (trial / "transaction.txt").write_text("TX R0.0\n# Add one mutation.\n")
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(0, trial_main("task-01", trial, ["apply", "set-constant N0 7"], "XAX-DIRECT"))
            self.assertEqual("PASS\n", output.getvalue())

    def test_direct_xax_arm_covers_extended_task_families(self):
        with tempfile.TemporaryDirectory() as directory:
            for task in oi01_tasks()[5:]:
                trial = prepare(task.task_id, "XAX-DIRECT", Path(directory) / task.task_id)
                command = "; ".join(" ".join(parts) for parts in REFERENCE_EDITS[task.task_id])
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(0, trial_main(task.task_id, trial, ["apply", command], "XAX-DIRECT"))
                self.assertEqual("PASS\n", output.getvalue(), task.task_id)
                self.assertEqual((True, ""), check(task.task_id, "XAX-DIRECT", trial), task.task_id)

    def test_xax_inspect_is_local_and_failures_are_compact(self):
        with tempfile.TemporaryDirectory() as directory:
            trial = prepare("task-01", "XAX", Path(directory) / "task")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, trial_main("task-01", trial, ["inspect"]))
            self.assertEqual(
                "R0 f(P0:u32)->u32\nN0 const 3\nN1 add.wrap P0 N0\nN2 mul.wrap N1 N0\nreturn N2\n",
                output.getvalue(),
            )

            (trial / "transaction.txt").write_text("TX R0.0\nC F0.B0.N0 99 7\n")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(1, trial_main("task-01", trial, ["verify"]))
            diagnostic = json.loads(output.getvalue())
            self.assertEqual("XAX.WORKSPACE.ATTRIBUTE_CONFLICT", diagnostic[0])
            self.assertEqual("N0", diagnostic[1])
            self.assertEqual(99, diagnostic[2])
            self.assertEqual(3, diagnostic[3])
            self.assertEqual(["N0"], diagnostic[4])

            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, trial_main("task-01", trial, ["mutate", "set-constant", "N0", "6"]))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(1, trial_main("task-01", trial, ["test"]))
            diagnostic = json.loads(output.getvalue())
            self.assertEqual(["XAX.TEST.TARGET", "R0"], diagnostic[:2])
            self.assertEqual(64, len(diagnostic[2]))
            self.assertEqual(64, len(diagnostic[3]))
            self.assertEqual(["R0"], diagnostic[4])

    def test_xax_checker_rejects_empty_and_wrong_transactions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trial = prepare("task-01", "XAX", root / "empty")
            self.assertFalse(check("task-01", "XAX", trial)[0])
            (trial / "transaction.txt").write_text("TX R0.0\nC F0.B0.N0 3 6\n")
            self.assertFalse(check("task-01", "XAX", trial)[0])

    def test_results_are_flat_summarized_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.csv"
            record("task-01", "C", True, input_tokens=10, output_tokens=2, turns=1, results_path=path)
            record("task-01", "XAX", False, total_tokens=8, turns=2, notes="retry failed", results_path=path)
            with self.assertRaisesRegex(ValueError, "already recorded"):
                record("task-01", "C", False, results_path=path)
            record("task-01", "C", True, input_tokens=11, output_tokens=2, turns=1, trial=2, results_path=path)
            record("task-01", "xax-unified-pipe", True, total_tokens=7, turns=1, results_path=path)
            with self.assertRaisesRegex(ValueError, "arm must be"):
                record("task-02", "XAX-unified-cbor", True, results_path=path)
            report = summarize(path)
            self.assertIn("XAX-UNIFIED-PIPE", report)
            self.assertIn("1/1", report)
            self.assertIn("0/1", report)
            self.assertIn("13", report)

    def test_variant_session_records_trace_and_transport_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trial = prepare("task-10", "XAX-UNIFIED-PIPE", root / "trial")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(1, trial_main("task-10", trial, ["test"], "XAX-UNIFIED-PIPE"))
                self.assertEqual(0, trial_main("task-10", trial, ["inspect"], "XAX-UNIFIED-PIPE"))
            task = load_task("task-10")
            (trial / "packet.txt").write_text(
                encode_packet("pipe", "unified", REFERENCE_EDITS["task-10"], root=task.reference_root, task=task)
            )
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, trial_main("task-10", trial, ["test"], "XAX-UNIFIED-PIPE"))
            sessions = root / "sessions"
            sessions.mkdir()
            log = sessions / "trial.jsonl"
            log.write_text("\n".join([
                json.dumps({"type": "session_meta", "payload": {"cwd": str(trial.resolve())}}),
                json.dumps({"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 100, "output_tokens": 5, "total_tokens": 105}}}}),
            ]) + "\n")
            results = root / "results.csv"
            record_session("task-10", "XAX-UNIFIED-PIPE", True, trial, trial=3, model="gpt-test", reasoning="fixed",
                           sessions_path=sessions, results_path=results)
            with results.open(newline="", encoding="utf-8") as file:
                row = next(csv.DictReader(file))
            self.assertEqual("stale-root", row["task_family"])
            self.assertEqual("3", row["trial"])
            self.assertEqual("1", row["failed_checks"])
            self.assertEqual("1", row["repair_count"])
            self.assertGreater(int(row["view_bytes"]), 0)
            self.assertGreater(int(row["packet_bytes"]), 0)
            self.assertEqual(64, len(row["final_root"]))
            self.assertIn("stale-root", summarize_oi01(results))

    def test_desktop_session_usage_is_recorded_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "trial"
            workspace.mkdir()
            sessions = root / "sessions"
            sessions.mkdir()
            log = sessions / "trial.jsonl"
            events = [
                {"type": "session_meta", "payload": {"cwd": str(workspace)}},
                {"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 40, "output_tokens": 2, "total_tokens": 42}}}},
            ]
            log.write_text("\n".join(json.dumps(event) for event in events) + "\n")
            results = root / "results.csv"
            self.assertEqual(log, record_session("task-01", "C", True, workspace, sessions_path=sessions, results_path=results))
            self.assertIn(",40,2,42,", results.read_text())


if __name__ == "__main__":
    unittest.main()
