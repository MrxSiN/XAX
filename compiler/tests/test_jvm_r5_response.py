import csv
from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from benchmarks.jvm_r5_response import SemanticTrial, CREATION, response_task, apply_patch_response
from benchmarks.jvm_r5_ai import tasks, prepare_source, check_source
from benchmarks import run_jvm_r5_response as runner


class JvmResponseTests(unittest.TestCase):
    def test_bound_requests_preserve_targets_and_report_conflicts_before_rebinding(self):
        fields = {"jvm-01": "7", "jvm-02": "mul.wrap", "jvm-03": "1 N1",
                  "jvm-07": "0 0 P2", "jvm-08": "1 P3",
                  "jvm-10": "mul.wrap", "jvm-13": "7"}
        for key, response in fields.items():
            trial = SemanticTrial(key, bound=True)
            self.assertIn("Bound ", trial.prompt())
            self.assertNotIn("insert-constant ANCHOR", trial.prompt())
            passed, why = trial.apply(response)
            if key == "jvm-10":
                self.assertFalse(passed)
                self.assertIn("STALE_ROOT", why)
                self.assertIn("Return only the edits", trial.repair_prompt(why))
                passed, why = trial.apply(trial.reference_command)
            self.assertTrue(passed, (key, why))
            self.assertEqual(trial.reader.root_cid, SemanticTrial(key).expected)

    def test_bound_rejection_falls_back_to_ordinary_batch_and_movement_stays_a_batch(self):
        trial = SemanticTrial("jvm-01", bound=True)
        with self.assertRaises(ValueError):
            trial.apply("a malformed full graph response")
        self.assertIn("Return only the edits", trial.repair_prompt("invalid fields"))
        self.assertEqual(trial.apply("const N0 7"), (True, ""))
        move = SemanticTrial("jvm-05", bound=True)
        self.assertIn("Return only the edits", move.prompt())
        self.assertEqual(move.apply("move N1 before N0"), (True, ""))

    def test_compact_verbs_preserve_exact_transactions_and_targets(self):
        aliases = {"set-constant": "const", "set-op": "op", "replace-operand": "operand",
                   "set-edge": "edge", "set-type": "type", "set-signature": "sig", "prune-dead": "prune"}
        for item in tasks():
            if item.task_id == "jvm-06":
                continue
            trial = SemanticTrial(item.task_id)
            command = trial.reference_command
            compact = '; '.join(aliases.get(verb, verb) + (' ' + args if args else '')
                                for verb, _, args in (record.strip().partition(' ') for record in command.split(';')))
            self.assertEqual(trial.session.transaction(command), trial.session.transaction(compact))
            passed, why = trial.apply(compact)
            if item.task_id == "jvm-10":
                trial.repair_prompt(why)
                passed, why = trial.apply(compact)
            self.assertTrue(passed, (item.task_id, why))
        for key, command in (("jvm-07", "edge N0 0 0 P2"), ("jvm-11", "prune N2"),
                             ("jvm-12", "type N0 T16; sig F0 - T16"),
                             ("jvm-14", "type N0 T16; type N1 T16; sig F0 - T16; sig F1 T16 T16")):
            self.assertEqual(SemanticTrial(key).apply(command), (True, ""))

    @unittest.skipUnless(shutil.which("javap") and shutil.which("kotlinc"), "JDK/Kotlin unavailable")
    def test_redundant_literal_coercion_requires_equal_compiled_instructions(self):
        item = response_task("jvm-14")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "Program.kt"
            source.write_text(item.kotlin_target.replace("inc(7)", "inc(7.toShort())"))
            self.assertTrue(check_source(item.task_id, "KOTLIN", workspace, item=item)[0])
            source.write_text(item.kotlin_target.replace("inc(7)", "inc(8.toShort())"))
            self.assertFalse(check_source(item.task_id, "KOTLIN", workspace, item=item)[0])
            target = ("object Program { fun pick(x: Short): Int = 7; fun pick(x: Int): Int = 8; "
                      "fun f(): Int = pick(7.toShort()); @JvmStatic fun main(a: Array<String>) { check(f() == 7) } }")
            overloaded = replace(item, kotlin_target=target)
            source.write_text(target.replace("pick(7.toShort())", "pick(7.toInt())"))
            passed, why = check_source(item.task_id, "KOTLIN", workspace, item=overloaded)
            self.assertFalse(passed)
            self.assertIn("compiled semantic target", why)

    @unittest.skipUnless(shutil.which("java") and shutil.which("javac"), "JVM unavailable")
    def test_all_semantic_targets_verify_and_execute_on_jvm(self):
        for item in tasks():
            trial = SemanticTrial(item.task_id)
            response = json.dumps(CREATION) if item.task_id == "jvm-06" else trial.reference_command
            passed, why = trial.apply(response)
            if item.task_id == "jvm-10":
                self.assertFalse(passed)
                self.assertEqual(json.loads(why)["code"], "XAX.WORKSPACE.STALE_ROOT")
                trial.repair_prompt(why)
                passed, why = trial.apply(response)
                self.assertEqual(trial.stale_failures, 1)
            self.assertTrue(passed, (item.task_id, why))
            self.assertTrue(trial.check_jvm()[0], item.task_id)

    def test_corpus_contains_real_application_and_rejected_candidates(self):
        large = SemanticTrial("jvm-15")
        self.assertEqual(len(large.workspace._function_handles), 162)
        self.assertIn("A2 constant 11", large.prompt())
        self.assertEqual(len(SemanticTrial("jvm-06").prompt().split("program is empty")), 2)
        for key in ("jvm-08", "jvm-09"):
            self.assertIn("diagnostic=XAX.", SemanticTrial(key).prompt())

    def test_selected_function_projection_cannot_mislabel_an_alias_collision(self):
        trial = SemanticTrial("jvm-14")
        with self.assertRaisesRegex(ValueError, "aliases collide"):
            trial.session.view()
        view = trial.session.view(functions=tuple(trial.selected))
        self.assertEqual(view.count("F1("), 1)
        self.assertIn("entity=F1", view)
        with self.assertRaisesRegex(ValueError, "unexposed function"):
            trial.session.view(functions=(b'\0'*32,))

    def test_typed_integer_aliases_have_unambiguous_function_type_and_node_fields(self):
        trial = SemanticTrial("jvm-14")
        response = "result-type 0 0 8 16; result-type 1 0 8 16; signature 0 - - 8 16; signature 1 8 16 8 16"
        self.assertEqual(trial.apply(response), (True, ""))

    def test_snapshot_setters_expand_to_the_exact_ordinary_target(self):
        for key, response in (
            ("jvm-07", "set-edge 0 edge0 arg0 P2"),
            ("jvm-11", "prune-dead 2"),
            ("jvm-12", "set-type 0 16; set-signature 0 - 16"),
            ("jvm-14", "set-type 0 16; set-type 1 16; set-signature 0 - 16; set-signature 1 16 16"),
        ):
            trial = SemanticTrial(key)
            self.assertEqual(trial.apply(response), (True, ""), key)
        resource = SemanticTrial("jvm-09").prompt()
        self.assertIn("effect filesystem", resource)
        self.assertIn("resource kind=2", resource)


    @unittest.skipUnless(shutil.which("javac") and shutil.which("kotlinc"), "textual compilers unavailable")
    def test_changed_textual_targets_compile_and_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            for key in ("jvm-08", "jvm-09", "jvm-10", "jvm-12", "jvm-14", "jvm-15"):
                item = response_task(key)
                for arm, name, target in (("JAVA", "Program.java", item.java_target), ("KOTLIN", "Program.kt", item.kotlin_target)):
                    root = prepare_source(key, arm, Path(directory) / f"{key}-{arm}", item=item)
                    (root / name).write_text(target, encoding="utf-8")
                    self.assertTrue(check_source(key, arm, root, item=item)[0], (key, arm))

    def test_unified_patch_is_atomic_bounded_and_checks_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Program.java"
            original = "one\ntwo\nthree\n"
            path.write_text(original)
            diff = "--- a/Program.java\n+++ b/Program.java\n@@ -1,3 +1,3 @@\n one\n-two\n+new\n three\n"
            apply_patch_response(path, diff, original)
            self.assertEqual(path.read_text(), "one\nnew\nthree\n")
            for invalid in (diff.replace("two", "wrong"), diff.replace("-1,3", "-1,2"), diff.replace("a/Program.java", "a/check.py")):
                with self.assertRaises(ValueError):
                    apply_patch_response(path, invalid, original)
                self.assertEqual(path.read_text(), "one\nnew\nthree\n")

    def test_native_context_patch_rejects_ambiguity_and_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Program.kt"
            original = "object Program {\n    fun f() = 3\n}\n"
            change = "*** Begin Patch\n*** Update File: Program.kt\n@@\n-    fun f() = 3\n+    fun f() = 7\n*** End Patch"
            apply_patch_response(path, change, original)
            self.assertEqual(path.read_text(), original.replace("= 3", "= 7"))
            apply_patch_response(path, change.replace("\n*** End Patch", "\n@@\n*** End Patch"), original)
            self.assertEqual(path.read_text(), original.replace("= 3", "= 7"))
            for bad, old in ((change.replace("Program.kt", "check.py"), original), (change, original + original)):
                with self.assertRaises(ValueError):
                    apply_patch_response(path, bad, old)
                self.assertEqual(path.read_text(), original.replace("= 3", "= 7"))

    def test_instruction_capture_uses_only_the_controlled_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sessions/2026/10/07"
            root.mkdir(parents=True)
            records = [{"type":"session_meta","payload":{"base_instructions":{"text":"fixed"},"account_id":"private"}},
                       {"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"fixed tools"}]}}]
            (root / "rollout-test-controlled.jsonl").write_text('\n'.join(json.dumps(item) for item in records))
            with patch.dict("os.environ", {"CODEX_HOME": directory}):
                result = runner.instruction_context([{"type":"thread.started","thread_id":"controlled"}])
            self.assertNotIn("private", json.dumps(result))
            self.assertEqual(result["developer"][0]["text"], "fixed tools")

    def test_interrupted_attempt_and_profile_mixing_block_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs = root / "runs"
            cell = runs / "jvm-01-java-1-1"
            cell.mkdir(parents=True)
            (cell / "attempt.json").write_text("{}")
            path = root / "results.csv"
            with path.open("w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=runner.FIELDS)
                writer.writeheader()
                for key, arm, trial in runner.accounting.schedule():
                    row = dict.fromkeys(runner.FIELDS, "")
                    row.update(task_id=key, arm=arm, trial=trial, model="fixed", reasoning="low", client="fixed", total_tokens=20 if arm == "XAX" else 100,
                               profile_sha256="same", accounting_complete="TRUE", **{"pass": "TRUE"})
                    writer.writerow(row)
            with patch.object(runner, "manifest", return_value={"limits": []}):
                evidence = runner.summarize(path, runs, 3)
            self.assertFalse(evidence["accounting_complete"])
            self.assertFalse(evidence["meets_token_gate"])
            self.assertEqual(len(evidence["unrecorded_attempts"]), 1)

    @unittest.skipUnless(shutil.which("javap") and shutil.which("javac"), "JDK unavailable")
    def test_v10_compiled_equivalence_admits_equal_java_and_rejects_unchanged_programs(self):
        def check(task_id, source):
            item = response_task(task_id)
            with tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "Program.java").write_text(source)
                return check_source(task_id, "JAVA", Path(directory), item=item, compiled_equivalence=True)[0]
        item = response_task("jvm-02")
        self.assertTrue(check("jvm-02", item.java_target.replace("x * k", "x * 5")))
        self.assertFalse(check("jvm-02", item.java_target.replace("x * k", "k * x")))
        # A move compiles like its initial program, so only the exact source passes.
        move = response_task("jvm-05")
        self.assertFalse(check("jvm-05", move.java_initial))
        self.assertTrue(check("jvm-05", move.java_target))

    def test_v10_textual_context_is_inline_and_xax_is_unbound(self):
        with tempfile.TemporaryDirectory() as directory:
            for task_id in ("jvm-01", "jvm-15"):
                item = response_task(task_id)
                source = prepare_source(task_id, "JAVA", Path(directory) / task_id, item=item) / "Program.java"
                prompt = runner._source_prompt(item, "JAVA", source)
                self.assertIn("static int target" if task_id == "jvm-15" else "final int k = 3", prompt)
                self.assertNotIn("Inspect", prompt)
            self.assertNotIn("helper7", prompt)
        self.assertNotIn("bound request", SemanticTrial("jvm-01").prompt())

    def test_cross_function_views_alias_every_parameter(self):
        # ADR-196: an unaliased callee parameter leaked as a raw handle.
        import re
        for task_id in ("jvm-12", "jvm-14"):
            self.assertIsNone(re.search(r"\.B\d+\.P\d+", SemanticTrial(task_id).prompt()), task_id)

    def test_v10_status_separates_target_and_owner_tolerance(self):
        def status(xax):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "results.csv"
                with path.open("w", newline="") as file:
                    writer = csv.DictWriter(file, fieldnames=runner.FIELDS)
                    writer.writeheader()
                    for key, arm, trial in runner.accounting.schedule():
                        row = dict.fromkeys(runner.FIELDS, "")
                        row.update(task_id=key, arm=arm, trial=trial, model="m", reasoning="low", client="c",
                                   total_tokens=xax if arm == "XAX" else 100, profile_sha256="p", accounting_complete="TRUE",
                                   instruction_context_sha256='["h"]', response_count=1, **{"pass": "TRUE"})
                        writer.writerow(row)
                runs = Path(directory) / "runs"
                runs.mkdir()
                # The calibrated floor (10 per request) is removed from every arm.
                (runs / "calibration.json").write_text('{"client_floor_input_tokens": 10}')
                with patch.object(runner, "manifest", return_value={"limits": []}):
                    return runner.summarize(path, runs, 3)
        self.assertEqual([status(x)["status"] for x in (55, 59, 60)], ["TARGET_MET", "ACCEPTED_WITHIN_TOLERANCE", "NOT_R5"])
        evidence = status(55)
        self.assertEqual(evidence["raw_xax_ratio_vs_lowest_textual_median"], 0.55)
        self.assertEqual(evidence["partial_xax_ratio_vs_lowest_textual_median"], 0.5)

    def test_profile_pins_checker_toolchain_and_rejects_version_drift_before_inference(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            runs = Path(directory)
            with patch.object(runner, "manifest", return_value={"sources": {}}), \
                 patch.object(runner, "_compiler", return_value="compiler"), \
                 patch.object(runner.shutil, "which", return_value="tool"), \
                 patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="v1", stderr="")) as version:
                _, profile = runner.pin_profile(runs)
                self.assertEqual(profile["toolchain"]["kotlinc"], "v1")
                version.return_value.stdout = "v2"
                with self.assertRaisesRegex(ValueError, "profile changed"):
                    runner.pin_profile(runs)
                version.return_value.returncode = 1
                with self.assertRaisesRegex(ValueError, "java failed"):
                    runner.pin_profile(runs)


if __name__ == "__main__":
    unittest.main()
