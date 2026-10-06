"""Vector runtime harness: plan, profiles, and the JDWP client (ADR-178).

The harness itself needs a rooted device running Vector; these tests cover what
a host can check: the committed UNEXECUTED plan, the signed profile inputs, the
harness's refusal to claim PASS without its oracle, and the JDWP client
exercised end to end against a host JVM.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

COMPILER = Path(__file__).resolve().parents[1]
VECTOR_DIR = COMPILER / "integration" / "android" / "vector"
BENCHMARKS = COMPILER / "benchmarks"
sys.path.insert(0, str(VECTOR_DIR))

import jdwp  # noqa: E402

spec = importlib.util.spec_from_file_location("xax_vector_harness", VECTOR_DIR / "vector_harness.py")
harness = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = harness  # dataclasses resolve annotations through sys.modules
spec.loader.exec_module(harness)


class PlanTests(unittest.TestCase):
    def test_committed_runtime_evidence_is_the_unexecuted_plan(self):
        committed = json.loads((BENCHMARKS / "android_vector_runtime_evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(committed, harness.plan_evidence())
        self.assertEqual(committed["label"], "UNEXECUTED")
        self.assertIsNone(committed["environment"])
        self.assertTrue(all(row["status"] == "UNEXECUTED" for row in committed["checks"]))

    def test_checks_cover_the_runtime_contract_once_each(self):
        from benchmarks.bench_android_vector_profiles import PROFILES

        ids = [check.id for check in harness.CHECKS]
        self.assertEqual(len(ids), 27)
        self.assertEqual(len(set(ids)), 27)
        names = {profile.name for profile in PROFILES}
        for check in harness.CHECKS:
            self.assertIn(check.profile, names | {"*"})

    def test_vector_version_floor(self):
        self.assertTrue(harness.vector_version_ok("id=zygisk_vector\nversion=v2.2 (3120-abc)\n", "v2.2"))
        self.assertTrue(harness.vector_version_ok("version=v2.10 (1)\n", "v2.2"))
        self.assertFalse(harness.vector_version_ok("version=v2.1 (1)\n", "v2.2"))
        self.assertFalse(harness.vector_version_ok("version=v1.11.0\n", "v2.2"))
        self.assertFalse(harness.vector_version_ok(None, "v2.2"))

    def test_no_pass_without_the_jdwp_oracle(self):
        class NoDebugDevice:
            def prop(self, name):
                return "0"

        run = harness.Harness(NoDebugDevice(), Path("."), 1)
        self.assertFalse(run.needs_jdwp("module_services", "saved_state"))
        self.assertEqual(run.results["module_services"][0], "UNEXECUTED")
        self.assertEqual(run.results["saved_state"][0], "UNEXECUTED")
        run.record("discovery", None, "x")
        self.assertEqual(run.results["discovery"][0], "INCONCLUSIVE")


class ProfileTests(unittest.TestCase):
    def test_committed_profile_evidence_reproduces_exactly(self):
        from benchmarks.bench_android_vector_profiles import collect_evidence

        committed = json.loads((BENCHMARKS / "android_vector_profiles_evidence.json").read_text(encoding="utf-8"))
        evidence = collect_evidence()
        self.assertEqual(evidence, committed)
        for name, row in evidence["profiles"].items():
            with self.subTest(profile=name):
                self.assertTrue(row["module"]["vector_accepted"])
                if "reload" in row:
                    self.assertTrue(row["reload"]["vector_accepted"])
                    self.assertNotEqual(row["reload"]["sha256"], row["module"]["sha256"])
                    self.assertEqual(row["reload"]["module_prop"]["autoHotReload"], "true")

    def test_combined_profile_is_the_committed_runtime_pair(self):
        profiles = json.loads((BENCHMARKS / "android_vector_profiles_evidence.json").read_text(encoding="utf-8"))
        pair = json.loads((BENCHMARKS / "android_libxposed_runtime_pair_evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(profiles["profiles"]["combined"]["module"]["sha256"], pair["module"]["sha256"])
        self.assertEqual(profiles["targets"]["string"]["sha256"], pair["target"]["sha256"])


PROBE = r"""
public class Probe {
    String name = "Vector";
    String[] files = {"xax_probe.txt"};
    static volatile String caught = "";
    String hello(String who) { return "hi " + who; }
    int twice(int value) { return value * 2; }
    static void tick() {}
    static void guarded() { try { tick(); } catch (RuntimeException e) { caught = "caught"; } }
    public static void main(String[] args) throws Exception {
        Probe keep = new Probe();
        System.out.println("ready");
        while (true) {
            guarded();
            if (!caught.isEmpty()) { System.out.println(caught); caught = ""; }
            Thread.sleep(50);
        }
    }
}
"""


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "a host JDK is needed")
class JdwpClientTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        work = Path(self.directory.name)
        (work / "Probe.java").write_text(PROBE, encoding="utf-8")
        quiet = {**os.environ, "JAVA_TOOL_OPTIONS": ""}
        subprocess.run(["javac", "Probe.java"], cwd=work, check=True, env=quiet, capture_output=True)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.process = subprocess.Popen(
            ["java", f"-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:{port}", "-cp", str(work), "Probe"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=quiet,
        )
        self.assertIn("Listening", "Listening" if self.process.stdout.readline() else "")
        while self.process.stdout.readline().strip() != "ready":
            pass
        deadline = time.monotonic() + 20
        while True:
            try:
                self.client = jdwp.Jdwp.connect(port, timeout=20)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)

    def tearDown(self):
        self.client.close()
        self.process.kill()
        self.process.wait()
        self.process.stdout.close()
        self.directory.cleanup()

    def _suspend_in_tick(self):
        (probe_class,) = self.client.classes_by_signature("LProbe;")
        methods = self.client.methods(probe_class)
        request = self.client.set_breakpoint(self.client.method_entry(probe_class, methods[("tick", "()V")]))
        event = self.client.wait_event({jdwp.EVENT_BREAKPOINT}, {request}, 20)
        self.assertIsNotNone(event)
        self.client.clear_breakpoint(request)
        return probe_class, methods, event

    def test_breakpoint_instances_fields_and_invocation(self):
        probe_class, methods, event = self._suspend_in_tick()
        self.assertEqual(self.client.signature(event.location.class_id), "LProbe;")
        (instance,) = self.client.instances(probe_class)
        fields = self.client.fields(probe_class)
        name = self.client.get_field(instance, fields[("name", "Ljava/lang/String;")])
        self.assertEqual(self.client.string_value(name.value), "Vector")
        files = self.client.get_field(instance, fields[("files", "[Ljava/lang/String;")])
        self.assertEqual([self.client.string_value(item.value) for item in self.client.array_values(files.value)], ["xax_probe.txt"])
        result, thrown = self.client.invoke(instance, event.thread, probe_class, methods[("hello", "(Ljava/lang/String;)Ljava/lang/String;")],
                                            self.client.create_string("Vector"))
        self.assertEqual((self.client.string_value(result.value), thrown), ("hi Vector", 0))
        number, _ = self.client.invoke(instance, event.thread, probe_class, methods[("twice", "(I)I")], jdwp.Value(ord("I"), 21))
        self.assertEqual(number.value, 42)
        self.client.resume()

    def test_stop_thread_throws_inside_the_suspended_frame(self):
        _probe_class, _methods, event = self._suspend_in_tick()
        exception_class = self.client.first_loaded_class(*harness.THROWABLES)
        constructor = self.client.methods(exception_class)[("<init>", "()V")]
        exception = self.client.new_instance(exception_class, event.thread, constructor)
        self.client.stop_thread(event.thread, exception)
        self.client.resume()
        deadline = time.monotonic() + 20
        line = ""
        while time.monotonic() < deadline and line != "caught":
            line = self.process.stdout.readline().strip()
        self.assertEqual(line, "caught")


if __name__ == "__main__":
    unittest.main()
