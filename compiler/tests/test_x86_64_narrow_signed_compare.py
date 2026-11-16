"""The x86-64 lowering of ``int.compare`` against the reference executor at every operand width.

The frame path used to compare zero-extended ``bits<8>``/``bits<16>`` slots as 32-bit values, so the four signed
predicates ignored the narrow sign bit (docs/audits/2026-11-11-independent-audit.md, finding 1).  The oracle here is
``execute``, not another backend's bytes.  ``SeedNarrowCompareTests`` runs the same cases through the pinned Windows
seed (OI-55's PE half; the Linux half closed with ADR-393).
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import IntCompare, Operation, bits_type, x86_64_windows_pe_target
from xax_graph_builder import GraphBuilder, program_store
from xax_x86_64 import compile_native, run_native

sys.path.insert(0, __import__("os").path.dirname(__file__))
# ADR-405 (4): the native oracle where it runs (benchmarks/oracle_x86_64_compare_evidence.json), else the Python executor.
from test_native_oracle import oracle_execute as execute  # noqa: E402

X86_64_HOST = platform.machine().lower() in ("amd64", "x86_64") and (sys.platform == "win32" or sys.platform.startswith("linux"))
B1, B64 = bits_type(1), bits_type(64)


def _compare_program(width: int, kind: IntCompare):
    """fn(bits64, bits64) -> bits64: zero-extend(compare(truncate(x), truncate(y))), so the operands are run-time values."""
    graph = GraphBuilder()
    block = graph.block(B64, B64)
    narrow = bits_type(width)
    left, right = block.params if width == 64 else (block.op1(Operation.INT_TRUNCATE, (value,), narrow) for value in block.params)
    flag = block.op1(Operation.INT_COMPARE, (left, right), B1, attributes=(kind,))
    block.ret(block.op1(Operation.INT_ZERO_EXTEND, (flag,), B64))
    entry = graph.function((B64, B64), (B64,))
    target = x86_64_windows_pe_target()
    return program_store(entry, target, tuple(graph.objects.values())), entry, target


@unittest.skipUnless(X86_64_HOST, "requires an x86-64 Windows or Linux host")
class NarrowCompareTests(unittest.TestCase):
    def test_every_predicate_matches_the_executor_at_every_width(self):
        for width in (5, 8, 16, 24, 32, 64):
            top = 1 << (width - 1)
            # Both signs, the extremes, and dirt above the operand width that truncation must discard.
            values = (0, 1, 3, top - 1, top, top + 1, (1 << width) - 1, 0xF1 | (0xABCD << width) & ((1 << 64) - 1))
            for kind in IntCompare:
                reader, entry, target = _compare_program(width, kind)
                image = compile_native(reader, entry.cid, target.cid)
                for left in values:
                    for right in values:
                        with self.subTest(width=width, kind=kind.name, left=hex(left), right=hex(right)):
                            self.assertEqual(run_native(image, (left, right)), execute(reader, entry.cid, (left, right)))


WIDTHS = (5, 8, 16, 24, 32, 64)


def _values(width):
    top = 1 << (width - 1)
    # Both signs, the extremes, and dirt above the operand width that truncation must discard.
    return (0, 1, 3, top - 1, top, top + 1, (1 << width) - 1, 0xF1 | (0xABCD << width) & ((1 << 64) - 1))


def _construct_function(width, kind):
    """``f_<kind>(b64, b64) -> b32``: zext(compare(truncate(x), truncate(y))), as ``xax-construct-v1``."""
    nodes = [] if width == 64 else [["int.truncate", ["p0"], [f"b{width}"]], ["int.truncate", ["p1"], [f"b{width}"]]]
    left, right = ("p0", "p1") if width == 64 else ("n0", "n1")
    nodes += [["int.compare", [left, right], ["b1"], {"attrs": [kind.name.lower()]}], ["int.zero_extend", [f"n{len(nodes)}"], ["b32"]]]
    return {"name": f"f_{kind.name.lower()}", "params": ["b64", "b64"], "returns": ["b32"],
            "blocks": [{"params": ["b64", "b64"], "nodes": nodes, "end": ["ret", [f"n{len(nodes) - 1}"]]}]}


@unittest.skipUnless(platform.system() == "Windows" and platform.machine() in ("AMD64", "x86_64"), "requires Windows x86-64")
class SeedNarrowCompareTests(unittest.TestCase):
    """OI-55, PE half: each width's 640 cases in one program built by the pinned Windows seed.

    Main calls every ``f_<kind>`` on every value pair, XORs each result with ``execute``'s, and exits with the number
    of mismatches, so the exit status is 0 exactly when every case equals the executor.
    """

    def test_every_predicate_matches_the_executor_at_every_width(self):
        import subprocess
        import tempfile
        from pathlib import Path

        from test_native_branch_fusion import _seed_command
        from xax_construct import construct

        _, prefix, exit_call, seed = _seed_command()
        effects = [prefix + "process_effect", prefix + "filesystem_effect"]
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for width in WIDTHS:
                with self.subTest(width=width):
                    functions = [_construct_function(width, kind) for kind in IntCompare]
                    probe = construct({"format": "xax-construct-v1", "platform": "windows-x86_64", "functions": functions,
                                       "package": {"name": "oi55", "entries": {"app": functions[0]["name"]}, "release": "app"}})
                    nodes, total = [], ["b32", 0]
                    for kind in IntCompare:
                        cid = probe.functions[f"f_{kind.name.lower()}"].cid
                        for left in _values(width):
                            for right in _values(width):
                                (expected,) = execute(probe.reader, cid, (left, right))
                                nodes += [["call.direct", [["b64", left], ["b64", right]], ["b32"], {"entity": {"fn": f"f_{kind.name.lower()}"}}],
                                          ["bit.xor", [f"n{len(nodes)}", ["b32", expected]], ["b32"]],
                                          ["add.wrap", [total, f"n{len(nodes) + 1}"], ["b32"]]]
                                total = f"n{len(nodes) - 1}"
                    nodes.append(["call.foreign", [total, "p0"], [effects[0]], {"entity": prefix + exit_call}])
                    main = {"name": "main", "params": effects, "returns": ["b32", *effects],
                            "blocks": [{"params": effects, "nodes": nodes, "end": ["ret", [total, f"n{len(nodes) - 1}", "p1"]]}]}
                    built = construct({"format": "xax-construct-v1", "platform": "windows-x86_64", "functions": [*functions, main],
                                       "package": {"name": "oi55", "entries": {"app": "main"}, "release": "app"}})
                    snapshot, artifact = directory / f"snapshot{width}.xax", directory / f"program{width}.exe"
                    snapshot.write_bytes(built.reader.canonical_bytes())
                    status = subprocess.run([str(seed.path), "build", str(snapshot), str(artifact), str(directory / "provenance")], check=False, timeout=600)
                    self.assertEqual(status.returncode, 0)
                    self.assertEqual(subprocess.run([str(artifact)], check=False, timeout=60).returncode, 0, "mismatches with the executor")


if __name__ == "__main__":
    unittest.main()
