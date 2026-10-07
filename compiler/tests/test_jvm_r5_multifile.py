import shutil
import tempfile
import unittest
from pathlib import Path

from benchmarks.jvm_r5_multifile import (PREFIXES, XaxTrial, apply_multi_patch, build_store, check_textual,
                                         hierarchy, sources, task, tasks, textual_context)


def _alias(trial, key, index):
    cid = build_store(trial.item.initial)[1][key]
    return PREFIXES[trial.selected.index(cid)] + str(index)


def _handle(trial, key):
    cid = build_store(trial.item.initial)[1][key]
    return trial.workspace._function_handles[cid]


def _reference(trial):
    t, a, h = trial.item.task_id, lambda k, i: _alias(trial, k, i), lambda k: _handle(trial, k)
    if t == "mf-01":
        edits = [f"sig {h('Units.scale')} b16 b16"]
        for key in ("Orders.qty", "Billing.fee", "Report.code"):
            edits += [f"type {a(key, 0)} b16", f"type {a(key, 1)} b16", f"sig {h(key)} - b16"]
        return "; ".join(edits)
    if t == "mf-02":
        return f"op {a('Orders.discount', 3)} sub.wrap; const {a('Main.c1', 2)} 11"
    return f"const {a('Billing.rate', 0)} 7; const {a('Main.c1', 2)} 28; const {a('Main.c2', 2)} 15"


class MultiFileCorpusTests(unittest.TestCase):
    def test_xax_reference_edits_reach_the_spec_target_and_execute(self):
        for item in tasks():
            trial = XaxTrial(item)
            self.assertNotRegex(trial.prompt(), r"\.B\d+\.P\d+")
            self.assertEqual(trial.apply(_reference(trial)), (True, ""), item.task_id)
            if shutil.which("java"):
                self.assertTrue(trial.check_jvm()[0], item.task_id)

    def test_type_retype_expands_exactly_within_shown_functions(self):
        trial = XaxTrial(task("mf-01"))
        # bits32 is used only by functions outside the view: nothing to retype.
        with self.assertRaisesRegex(ValueError, "not used in the shown functions"):
            trial.session.transaction("type b32 b16")
        self.assertEqual(len(trial.session.transaction("type b8 b16").mutations), 10)
        self.assertEqual(trial.apply("type b8 b16"), (True, ""))

    def test_function_scoped_retype_and_kind_diagnostics(self):
        trial = XaxTrial(task("mf-01"))
        trial.prompt()
        self.assertEqual(len(trial.session.transaction("type Units.scale b8 b16").mutations), 1)
        with self.assertRaisesRegex(ValueError, "Units.scale is a function; use sig"):
            trial.session.transaction("type Units.scale b16")
        names = ("Units.scale", "Orders.qty", "Billing.fee", "Report.code")
        self.assertEqual(trial.apply("; ".join(f"type {name} b8 b16" for name in names)), (True, ""))

    def test_implied_edits_merge_and_conflicts_still_reject(self):
        # A model response that restates what the retype implies.
        redundant = "sig Units.scale b16 b16; type N0 b16; type N1 b16; type A0 b16; type A1 b16; type P0 b16; type b8 b16"
        trial = XaxTrial(task("mf-01"))
        trial.prompt()
        self.assertEqual(len(trial.session.transaction(redundant).mutations), 10)
        self.assertEqual(trial.apply(redundant), (True, ""))
        trial = XaxTrial(task("mf-01"))
        trial.prompt()
        passed, why = trial.apply("sig Units.scale b16 b16; type P0 b32")
        self.assertFalse(passed)
        self.assertIn("DUPLICATE_MUTATION", why)

    def test_wrong_xax_edit_is_rejected_as_wrong_target(self):
        trial = XaxTrial(task("mf-02"))
        self.assertEqual(trial.apply(f"op {_alias(trial, 'Orders.discount', 3)} sub.wrap"), (False, "XAX.TEST.TARGET"))

    def test_context_is_the_same_call_hierarchy_for_every_arm(self):
        item = task("mf-03")
        keys = [fn.key for fn in hierarchy(item.initial, item.target)]
        self.assertEqual(keys, ["Billing.rate", "Billing.fee", "Report.summary", "Main.c1", "Main.c2"])
        excerpt = textual_context(item, "JAVA-EXCERPT", sources(item.initial, False))
        self.assertEqual(sum(line.startswith("    static") for line in excerpt.splitlines()), 5)
        whole = textual_context(item, "JAVA", sources(item.initial, False))
        self.assertIn("h23", whole)
        self.assertNotIn("Units.java", whole)
        self.assertEqual(len(XaxTrial(item).selected), 5)

    def test_multi_file_patch_is_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("a\nb\n")
            (root / "B.java").write_text("c\n")
            with self.assertRaises(ValueError):
                apply_multi_patch(root, "*** Begin Patch\n*** Update File: A.java\n@@\n-a\n+x\n*** Update File: B.java\n@@\n-missing\n+y\n*** End Patch")
            self.assertEqual((root / "A.java").read_text(), "a\nb\n")
            apply_multi_patch(root, "*** Begin Patch\n*** Update File: A.java\n@@\n-a\n+x\n*** Update File: B.java\n@@\n-c\n+y\n*** End Patch")
            self.assertEqual(((root / "A.java").read_text(), (root / "B.java").read_text()), ("x\nb\n", "y\n"))

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap") and shutil.which("kotlinc"), "JDK/Kotlin unavailable")
    def test_textual_targets_pass_and_initial_or_wrong_programs_fail(self):
        for item in tasks():
            for arm, kotlin in (("JAVA", False), ("KOTLIN", True)):
                for fns, expected in ((item.final, True), (item.initial, False)):
                    with tempfile.TemporaryDirectory() as directory:
                        for name, text in sources(fns, kotlin).items():
                            (Path(directory) / name).write_text(text)
                        self.assertEqual(check_textual(item, arm, Path(directory))[0], expected, (item.task_id, arm, expected))
        # An equivalent Java form passes through compiled instructions.
        item = task("mf-03")
        with tempfile.TemporaryDirectory() as directory:
            for name, text in sources(item.final, False).items():
                (Path(directory) / name).write_text(text.replace("== 28", "== 4 * 7"))
            self.assertTrue(check_textual(item, "JAVA", Path(directory))[0])


class MultiFileSummaryTests(unittest.TestCase):
    def test_gate_uses_lowest_of_four_textual_arms_after_the_floor(self):
        import csv
        from benchmarks import run_jvm_r5_multifile as runner
        costs = {"JAVA": 300, "JAVA-EXCERPT": 120, "KOTLIN": 310, "KOTLIN-EXCERPT": 130, "XAX": 65}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "calibration.json").write_text('{"client_floor_input_tokens": 10}')
            path = root / "results.csv"
            with path.open("w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=runner.FIELDS)
                writer.writeheader()
                for task_id, arm, trial in runner.schedule():
                    row = dict.fromkeys(runner.FIELDS, "")
                    row.update(task_id=task_id, arm=arm, trial=trial, total_tokens=costs[arm], response_count=1,
                               accounting_complete="TRUE", profile_sha256="p", **{"pass": "TRUE"})
                    writer.writerow(row)
            evidence = runner.summarize(path, root)
        self.assertEqual(evidence["lowest_textual_arm"], "JAVA-EXCERPT")
        self.assertEqual(evidence["xax_ratio_vs_lowest_textual_median"], 0.5)
        self.assertEqual(evidence["status"], "TARGET_MET")


if __name__ == "__main__":
    unittest.main()
