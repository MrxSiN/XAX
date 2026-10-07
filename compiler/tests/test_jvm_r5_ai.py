import shutil
import tempfile
import unittest
from pathlib import Path

from benchmarks.ai_native import REFERENCE_EDITS, check as check_xax_base, encode_packet, load_task
from benchmarks.jvm_r5_ai import check_source, check_xax, prepare_source, prepare_xax_task, task, tasks, xax_main


class JvmR5AITests(unittest.TestCase):
    def test_direct_views_bind_intent_names_and_explain_inserted_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            move = prepare_xax_task("jvm-05", root / "move")
            self.assertIn("a=N0, b=N1", (move / "TASK.md").read_text())
            creation = prepare_xax_task("jvm-06", root / "creation")
            text = (creation / "TASK.md").read_text()
            self.assertIn("@ID", text)
            self.assertIn("pre-batch snapshot", text)
            self.assertIn("placeholder=N0", text)

    @unittest.skipUnless(shutil.which("javac"), "UNAVAILABLE: javac")
    def test_creation_oracle_rejects_a_single_point_impostor(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = prepare_source("jvm-06", "JAVA", Path(directory) / "java")
            (workspace / "Program.java").write_text("public final class Program { static int f(int x) { return 12; } }\n")
            passed, _reason = check_source("jvm-06", "JAVA", workspace)
            self.assertFalse(passed)
    def test_corpus_covers_every_required_family(self):
        families = {item.family for item in tasks()}
        self.assertTrue({
            "creation", "literal-edit", "operation-substitution", "control-flow", "type-change", "type-repair",
            "resource-effect-repair", "optimization", "stale-root", "context-scaling", "cross-function-api",
            "large-application",
        } <= families)

    @unittest.skipUnless(shutil.which("javac") and shutil.which("kotlinc"), "UNAVAILABLE: javac and kotlinc are needed to check the textual arms")
    def test_all_textual_targets_compile_and_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for item in tasks():
                for arm, name, target in (("JAVA", "Program.java", item.java_target), ("KOTLIN", "Program.kt", item.kotlin_target)):
                    workspace = prepare_source(item.task_id, arm, root / f"{item.task_id}-{arm.lower()}")
                    (workspace / name).write_text(target, encoding="utf-8")
                    passed, reason = check_source(item.task_id, arm, workspace)
                    self.assertTrue(passed, (item.task_id, arm, reason))

    def test_custom_type_and_api_transactions_reach_exact_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for task_id in ("jvm-12", "jvm-14"):
                workspace = prepare_xax_task(task_id, root / task_id)
                self.assertEqual(0, xax_main(task_id, workspace, ["apply", task(task_id).xax_command]))
                self.assertEqual((True, "wrong semantic target"), check_xax(task_id, workspace))

    def test_base_xax_tasks_reach_exact_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for item in tasks():
                if item.custom_xax:
                    continue
                workspace = prepare_xax_task(item.task_id, root / item.task_id)
                if item.task_id == "jvm-10":
                    base = load_task(item.xax_task)
                    (workspace / "packet.txt").write_text(
                        encode_packet("line", "typed", REFERENCE_EDITS[item.xax_task], root=base.reference_root, task=base),
                        encoding="utf-8",
                    )
                    arm = "XAX-TYPED-LINE"
                else:
                    (workspace / "direct.txt" if load_task(item.xax_task).fixture != "linear" else workspace / "transaction.txt").write_text(
                        item.xax_command if load_task(item.xax_task).fixture != "linear" else _linear_transaction(item.xax_task, item.xax_command),
                        encoding="utf-8",
                    )
                    arm = "XAX-DIRECT"
                passed, reason = check_xax_base(item.xax_task, arm, workspace)
                self.assertTrue(passed, (item.task_id, reason))


def _linear_transaction(task_id: str, command: str) -> str:
    task_map = {
        "task-01": "C F0.B0.N0 3 7",
        "task-02": "O F0.B0.N1 add.wrap mul.wrap",
        "task-03": "U F0.B0.N2 1 F0.B0.N0.R0 F0.B0.N1.R0",
        "task-04": "D F0.B0.N1",
        "task-05": "M F0.B0.N1 BEFORE F0.B0.N0",
    }
    return f"TX R0.0\n{task_map[task_id]}\n"


if __name__ == "__main__":
    unittest.main()
