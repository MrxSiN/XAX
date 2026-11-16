"""ADR-376 (ledger 0013): a compare that drives its block's branch and is read again in later blocks (OI-50, OI-53).

The callee computes ``c = x < y``, branches on it, and in the join block returns ``10 * zext(c) + marker``.  Before
ledger 0013 the x86-64 general backend fused the compare into the branch without materializing it, so the join block
read a stale register (x < y returned 1, not 11).  The AArch64 backend lowers it correctly too.
"""

from __future__ import annotations

import platform
import unittest

from xax_compiler import IntCompare, Operation, aarch64_linux_exec_target, bits_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store

B1, B32 = bits_type(1), bits_type(32)
CASES = ((1, 2, 11), (3, 2, 2))


def program(api, a, b):
    graph = GraphBuilder()
    graph.track(*api.types, B1, B32)
    callee = graph.block(B32, B32)
    x, y = callee.params
    flag = callee.op1(Operation.INT_COMPARE, (x, y), B1, attributes=(int(IntCompare.ULT),))
    true, false, join = graph.block(), graph.block(), graph.block(B32)
    callee.cbr(flag, true, (), false, ())
    true.br(join, true.const(B32, 1))
    false.br(join, false.const(B32, 2))
    widened = join.op1(Operation.INT_ZERO_EXTEND, (flag,), B32)
    tens = join.op1(Operation.MUL_WRAP, (widened, join.const(B32, 10)), B32)
    join.ret(join.op1(Operation.ADD_WRAP, (tens, join.params[0]), B32))
    function = graph.function((B32, B32), (B32,))
    objects = tuple(graph.objects.values())
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    value = block.op1(Operation.CALL_DIRECT, (block.const(B32, a), block.const(B32, b)), B32, entity=function)
    process = block.op1(Operation.CALL_FOREIGN, (value, process), api.process_effect, entity=api.exit_group)
    block.ret(value, process, fs)
    entry = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
    return entry, (*objects, *graph.objects.values(), *api.types)


class BranchFusionTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "requires Linux x86-64")
    def test_x86_64(self):
        from xax_linux import compile_linux_executable, linux_api, run_linux_executable

        target = x86_64_linux_exec_target()
        for a, b, expected in CASES:
            with self.subTest(a=a, b=b):
                entry, objects = program(linux_api(), a, b)
                data = compile_linux_executable(program_store(entry, target, objects), entry.cid, target.cid, frontend="xax").data
                self.assertEqual(run_linux_executable(data).returncode, expected)

    def test_aarch64(self):
        from xax_linux_aarch64 import aarch64_runner, compile_linux_aarch64_executable, linux_aarch64_api, run_linux_aarch64_executable

        if aarch64_runner() is None:
            self.skipTest("requires an AArch64 Linux host or qemu-aarch64")
        target = aarch64_linux_exec_target()
        for a, b, expected in CASES:
            with self.subTest(a=a, b=b):
                entry, objects = program(linux_aarch64_api(), a, b)
                data = compile_linux_aarch64_executable(program_store(entry, target, objects), entry.cid, target.cid, frontend="xax").data
                self.assertEqual(run_linux_aarch64_executable(data).returncode, expected)


def _zext(value):
    return ["int.zero_extend", [value], ["b32"]]


def _reader(scale, addend):
    """``scale * zext(c) + addend``, ``c`` the entry block's compare."""
    return [_zext("B0.n0"), ["mul.wrap", ["n0", ["b32", scale]], ["b32"]], ["add.wrap", ["n1", addend], ["b32"]]]


# OI-50 (closed by ADR-376): ``c = x < y`` drives the branch and is read again in both arms and in the join.
REUSED = {"name": "f", "params": ["b32", "b32"], "returns": ["b32"], "blocks": [
    {"params": ["b32", "b32"], "nodes": [["int.compare", ["p0", "p1"], ["b1"], {"attrs": ["ult"]}]], "end": ["cbr", "n0", 1, [], 2, []]},
    {"params": [], "nodes": _reader(10, ["b32", 1]), "end": ["br", 3, ["n2"]]},
    {"params": [], "nodes": _reader(20, ["b32", 2]), "end": ["br", 3, ["n2"]]},
    {"params": ["b32"], "nodes": _reader(40, "p0"), "end": ["ret", ["n2"]]}]}
# A compare whose only use is its branch: still fused (ADR-376 left that path's code unchanged).
BRANCH_ONLY = {"name": "f", "params": ["b32", "b32"], "returns": ["b32"], "blocks": [
    {"params": ["b32", "b32"], "nodes": [["int.compare", ["p0", "p1"], ["b1"], {"attrs": ["ult"]}]], "end": ["cbr", "n0", 1, [], 2, []]},
    {"params": [], "nodes": [], "end": ["ret", [["b32", 7]]]},
    {"params": [], "nodes": [], "end": ["ret", [["b32", 9]]]}]}
# (x, y): taken, not taken, equal.  Results stay below 256, a Linux exit status.  Before ledger 0013 the native
# compiler returned 1 for (1, 2), not 51.
INPUTS = ((1, 2), (3, 2), (2, 2))


def _seed_command():
    """The pinned native compiler of this host (an object with its ``path``, kept alive while it runs), or None."""
    import hashlib
    import json

    from xax_native import bootstrap_dir

    if platform.system() == "Windows" and platform.machine() in ("AMD64", "x86_64"):
        directory = bootstrap_dir() / "windows"
        seed = directory / "xaxc-windows-x86_64.exe"
        pin = json.loads((directory / "seed.json").read_text())["sha256"]
        if hashlib.sha256(seed.read_bytes()).hexdigest() != pin:
            raise RuntimeError(f"{seed} is not the pinned seed {pin}")
        from types import SimpleNamespace

        return "windows-x86_64", "win32.", "exit_process", SimpleNamespace(path=seed)
    if platform.system() == "Linux" and platform.machine() == "x86_64":
        from xax_selfhost_driver import NativeGeneralDriver

        return "linux-x86_64", "linux.", "exit_group", NativeGeneralDriver()
    return None


class SeedBranchFusionTests(unittest.TestCase):
    """OI-50 through the pinned native compiler (``build``), each result checked against ``xax_compiler.execute``."""

    def _check(self, function):
        import subprocess
        import tempfile
        from pathlib import Path

        import sys

        from xax_construct import construct

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        # ADR-405 (4): the native oracle where it runs (benchmarks/oracle_x86_64_compare_evidence.json), else the Python executor.
        from test_native_oracle import oracle_execute as execute

        command = _seed_command()
        if command is None:
            self.skipTest("requires a Windows or Linux x86-64 host")
        name, prefix, exit_call, seed = command
        effects = [prefix + "process_effect", prefix + "filesystem_effect"]
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for x, y in INPUTS:
                with self.subTest(x=x, y=y):
                    main = {"name": "main", "params": effects, "returns": ["b32", *effects], "blocks": [{"params": effects, "nodes": [
                        ["call.direct", [["b32", x], ["b32", y]], ["b32"], {"entity": {"fn": "f"}}],
                        ["call.foreign", ["n0", "p0"], [effects[0]], {"entity": prefix + exit_call}]], "end": ["ret", ["n0", "n1", "p1"]]}]}
                    built = construct({"format": "xax-construct-v1", "platform": name, "functions": [function, main],
                                       "package": {"name": "oi50", "entries": {"app": "main"}, "release": "app"}})
                    (expected,) = execute(built.reader, built.functions["f"].cid, (x, y))
                    snapshot, artifact = directory / "snapshot.xax", directory / "program"
                    snapshot.write_bytes(built.reader.canonical_bytes())
                    status = subprocess.run([str(seed.path), "build", str(snapshot), str(artifact), str(directory / "provenance")], check=False, timeout=600)
                    self.assertEqual(status.returncode, 0)
                    artifact.chmod(0o755)
                    self.assertEqual(subprocess.run([str(artifact)], check=False, timeout=60).returncode, expected)

    def test_compare_reused_in_later_blocks(self):
        self._check(REUSED)

    def test_branch_only_compare(self):
        self._check(BRANCH_ONLY)


if __name__ == "__main__":
    unittest.main()
