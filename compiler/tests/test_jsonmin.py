"""The jsonmin application (R3 workload): differential, cross-checked, and limit tests."""

from __future__ import annotations

import json
import platform
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.jsonmin import CAPACITY, EXIT_INVALID, EXIT_OK, EXIT_TOO_LARGE, MAX_DEPTH, benchmark_document, build_jsonmin, reference_jsonmin  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
CASES = [
    b'{"a": [1, 2.5e3, -0, true, null, "x\\u00e9\\n"], "b": {}}', b"[]", b"{}", b"0", b"-0.0e-0", b'"\\"\\\\\\/\\b\\f\\n\\r\\t"',
    b" \t\r\n[ 1 , [ ] , { } ] \n", b"", b" ", b"[1,", b"[1,]", b"{,}", b'{"a" 1}', b'{"a":1,}', b"[01]", b"1.", b"1e", b"-",
    b"tru", b"nulL", b"[true false]", b'"\x01"', b'"\\x"', b'"\\u12g4"', b'"abc', b"[] x", b"\xff", b'"\xc3\xa9"',
    b"[" * MAX_DEPTH + b"]" * MAX_DEPTH, b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1),
]


def _python_accepts(data: bytes) -> bool | None:
    """Python's own parser as an independent oracle (None: outside its comparable domain)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None

    def reject(_constant):
        raise ValueError("non-RFC constant")

    try:
        json.loads(text, parse_constant=reject)
    except (ValueError, RecursionError):
        return False
    return True


def _mutations(rng: random.Random, document: bytes, count: int):
    alphabet = b'{}[],:" \\-+.eE0123456789tfnulr\x01'
    for _ in range(count):
        data = bytearray(document)
        kind = rng.randrange(4)
        if kind == 0 and data:
            data[rng.randrange(len(data))] = rng.choice(alphabet)
        elif kind == 1 and data:
            del data[rng.randrange(len(data)):]
        elif kind == 2:
            data.insert(rng.randrange(len(data) + 1), rng.choice(alphabet))
        elif data:
            del data[rng.randrange(len(data))]
        yield bytes(data)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class JsonminTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_linux import compile_linux_executable

        program = build_jsonmin()
        cls.artifact = compile_linux_executable(program.reader, program.entry.cid, program.target.cid).data
        cls.program = program

    def _run(self, data: bytes):
        from xax_linux import run_linux_executable

        completed = run_linux_executable(self.artifact, stdin=data)
        return completed.returncode, completed.stdout, completed.stderr

    def test_artifact_is_deterministic_and_static(self):
        from xax_linux import compile_linux_executable

        program = build_jsonmin()
        self.assertEqual(program.reader.root_cid, self.program.reader.root_cid)
        self.assertEqual(compile_linux_executable(program.reader, program.entry.cid, program.target.cid).data, self.artifact)
        self.assertNotIn(b"ld-linux", self.artifact)

    def test_cases_match_the_reference(self):
        for data in CASES:
            with self.subTest(data=data[:40]):
                self.assertEqual(self._run(data), reference_jsonmin(data))

    def test_generated_documents_and_mutations_match_the_reference(self):
        rng = random.Random(7)
        corpus = [benchmark_document(rng.randrange(50, 3000), seed=seed) for seed in range(12)]
        inputs = corpus + [mutation for document in corpus for mutation in _mutations(rng, document, 12)]
        accepted = rejected = 0
        for data in inputs:
            expected = reference_jsonmin(data)
            self.assertEqual(self._run(data), expected, data[:80])
            accepted += expected[0] == EXIT_OK
            rejected += expected[0] == EXIT_INVALID
        self.assertGreater(accepted, 12)
        self.assertGreater(rejected, 50)

    def test_validity_agrees_with_pythons_parser(self):
        rng = random.Random(11)
        corpus = [benchmark_document(rng.randrange(50, 2000), seed=100 + seed) for seed in range(8)] + CASES[:-2]
        checked = 0
        for data in corpus + [mutation for document in corpus[:8] for mutation in _mutations(rng, document, 10)]:
            oracle = _python_accepts(data)
            if oracle is None:
                continue
            status, stdout, _stderr = self._run(data)
            self.assertEqual(status == EXIT_OK, oracle, data[:80])
            if oracle:
                self.assertEqual(json.loads(stdout), json.loads(data))
            checked += 1
        self.assertGreater(checked, 80)

    def test_input_over_capacity_exits_2(self):
        status, stdout, stderr = self._run(b" " * (CAPACITY + 1))
        self.assertEqual((status, stdout, stderr), (EXIT_TOO_LARGE, b"", b""))
        self.assertEqual(self._run(b" " * (CAPACITY - 1) + b"0")[0], EXIT_OK)


class JsonminAarch64Tests(unittest.TestCase):
    def test_same_program_on_linux_aarch64(self):
        from xax_linux_aarch64 import aarch64_runner, compile_linux_aarch64_executable, run_linux_aarch64_executable

        if aarch64_runner() is None:
            self.skipTest("requires an AArch64 Linux host or qemu-aarch64")
        program = build_jsonmin("aarch64")
        artifact = compile_linux_aarch64_executable(program.reader, program.entry.cid, program.target.cid).data
        for data in (CASES[0], CASES[9], benchmark_document(4000, seed=3), CASES[-1]):
            completed = run_linux_aarch64_executable(artifact, stdin=data)
            self.assertEqual((completed.returncode, completed.stdout, completed.stderr), reference_jsonmin(data))


@unittest.skipUnless(__import__("shutil").which("java"), "requires a JVM")
class JsonminJvmTests(unittest.TestCase):
    """The same program on the JVM's linear memory (ADR-156): the JVM row's R3 application."""

    @classmethod
    def setUpClass(cls):
        from xax_jvm import compile_jvm_bound_target

        cls.program = build_jsonmin("jvm")
        cls.image = compile_jvm_bound_target(cls.program.reader, cls.program.entry.cid, cls.program.target, process_entry=True)

    def _run(self, data: bytes):
        from xax_jvm import run_jvm_jar

        completed = run_jvm_jar(self.image, stdin=data)
        return completed.returncode, completed.stdout, completed.stderr

    def test_jar_is_deterministic_and_uses_only_java_base(self):
        from xax_jvm import compile_jvm_bound_target

        program = build_jsonmin("jvm")
        self.assertEqual(compile_jvm_bound_target(program.reader, program.entry.cid, program.target, process_entry=True).jar, self.image.jar)
        self.assertNotIn(b"xax/jvm/Memory", self.image.class_bytes)  # the package is generated into the class

    def test_cases_match_the_reference(self):
        for data in CASES:
            with self.subTest(data=data[:40]):
                self.assertEqual(self._run(data), reference_jsonmin(data))

    def test_generated_documents_and_mutations_match_the_reference(self):
        rng = random.Random(7)
        corpus = [benchmark_document(rng.randrange(50, 3000), seed=seed) for seed in range(6)]
        inputs = corpus + [mutation for document in corpus for mutation in _mutations(rng, document, 8)]
        for data in inputs:
            self.assertEqual(self._run(data), reference_jsonmin(data), data[:80])

    def test_input_over_capacity_exits_2(self):
        self.assertEqual(self._run(b" " * (CAPACITY + 1)), (EXIT_TOO_LARGE, b"", b""))
        self.assertEqual(self._run(b" " * (CAPACITY - 1) + b"0")[0], EXIT_OK)


if __name__ == "__main__":
    unittest.main()
