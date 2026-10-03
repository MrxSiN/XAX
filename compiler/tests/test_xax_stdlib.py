"""ADR-130 (OI-36): standard semantic library packages and the uniqcount application."""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import Kind, Operation, XaxError, heap_view_type, verify_object, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_stdlib import MEM, WORDS, hashset_package, hashset_table_extent, text_package
from xax_structured import B32, B64, Proc

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


class StandardLibraryTests(unittest.TestCase):
    def test_packages_are_canonical_deterministic_and_instantiated(self):
        first, second = text_package(64), text_package(64)
        self.assertEqual(first.manifest(), second.manifest())
        self.assertNotEqual(first["format_u64"].cid, text_package(128)["format_u64"].cid)
        self.assertEqual(sorted(first.functions), ["find_digits", "format_u64", "parse_u64", "skip_spaces"])
        sets = hashset_package(8)
        objects = {item.cid: item for item in sets.objects}
        self.assertEqual(sets.package.kind, Kind.PACKAGE)
        for item in sets.objects:
            verify_object(item, objects.__getitem__)
        for bad in (0, 6, 1 << 29):
            with self.assertRaises(ValueError):
                hashset_package(bad)
        with self.assertRaises(ValueError):
            text_package(1 << 32)

    def test_call_with_another_instance_view_rejects(self):
        """An instance's view type is part of its interface: capacity 8 is not capacity 16."""
        small, large = hashset_package(8), hashset_package(16)
        view = heap_view_type(hashset_table_extent(16))
        proc = Proc((("key", B64), ("p", WORDS), ("v", view), ("m", MEM)))
        result, *views = proc.op(Operation.CALL_DIRECT, (proc["key"], proc["p"], proc["v"], proc["m"]), (B32, WORDS, view, MEM), entity=small["insert"])
        proc.ret(result, *views)
        entry = proc.function((B32, WORDS, view, MEM))
        with self.assertRaises(XaxError) as raised:
            program_store(entry, x86_64_linux_exec_target(), (*proc.graph.objects.values(), *small.objects, *large.objects))
        self.assertEqual(raised.exception.diagnostic.rule, "GRAPH-CALL-CONTRACT")

    def test_unused_exports_are_absent_from_the_application_store(self):
        from benchmarks.uniqcount import build_uniqcount

        program = build_uniqcount()
        stored = {item.cid for item in program.reader.objects()}
        text_in, text_out, sets = program.libraries
        self.assertNotIn(sets["contains"].cid, stored)
        self.assertNotIn(text_in["skip_spaces"].cid, stored)
        self.assertNotIn(text_out["parse_u64"].cid, stored)
        self.assertTrue(all(library.package.cid not in stored for library in program.libraries))
        self.assertTrue({sets["insert"].cid, text_in["find_digits"].cid, text_in["parse_u64"].cid, text_out["format_u64"].cid} <= stored)

    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_uniqcount_executes_against_reference(self):
        from benchmarks.uniqcount import CAPACITY, TABLE, build_uniqcount, reference_uniqcount
        from xax_linux import compile_linux_executable, run_linux_executable

        program = build_uniqcount()
        executable = compile_linux_executable(program.reader, program.entry.cid, program.target.cid)
        cases = (b"", b"1 2 3 2 1\n", b"a0b0c18446744073709551616 x 5,5;007 7", b"9" * 30, b"1" * (CAPACITY + 1), b" ".join(b"%d" % index for index in range(1, TABLE + 2)))
        for data in cases:
            completed = run_linux_executable(executable.data, stdin=data)
            self.assertEqual((completed.returncode, completed.stdout), reference_uniqcount(data), data[:40])


if __name__ == "__main__":
    unittest.main()
