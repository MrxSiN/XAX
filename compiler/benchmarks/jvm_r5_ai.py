"""JVM R5 real-model corpus: Java, Kotlin, and bounded XAX semantic edits."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from benchmarks.ai_native import REFERENCE_EDITS, load_task, prepare as prepare_xax
from xax_compiler import Block, Kind, Node, Operation, StoreReader, Terminator, ValueRef, bits_type, constant, execute, function, graph_fragment, object_with_refs, verify_store, write_store
from xax_workspace import RootRef, SetFunctionSignature, SetResultType, Transaction, Workspace

HERE = Path(__file__).resolve().parent
RUNS = HERE / "ai_native" / "runs-jvm-r5-full"
KOTLIN = Path(tempfile.gettempdir()) / "kotlin-compiler-2.1.0" / "kotlinc" / "bin" / "kotlinc.bat"


@dataclass(frozen=True)
class JvmTask:
    task_id: str
    family: str
    prompt: str
    java_initial: str
    java_target: str
    kotlin_initial: str
    kotlin_target: str
    xax_task: str | None
    xax_command: str
    custom_xax: bool = False
    unrelated_files: int = 0


def _java(methods: str, assertion: str) -> str:
    return f"public final class Program {{\n{methods}\n    public static void main(String[] args) {{ if (!({assertion})) throw new AssertionError(); }}\n}}\n"


def _kotlin(methods: str, assertion: str) -> str:
    return f"object Program {{\n{methods}\n    @JvmStatic fun main(args: Array<String>) {{ check({assertion}) }}\n}}\n"


def tasks() -> tuple[JvmTask, ...]:
    java_large_initial = _java("\n".join(f"    static int helper{i}(int x) {{ return x + {i}; }}" for i in range(160)) + "\n    static int target(int x) { return x + 5; }", "target(6) == 30")
    java_large_target = java_large_initial.replace("target(int x) { return x + 5; }", "target(int x) { return x * 5; }").replace("target(6) == 11", "target(6) == 30")
    kotlin_large_initial = _kotlin("\n".join(f"    fun helper{i}(x: Int) = x + {i}" for i in range(160)) + "\n    fun target(x: Int) = x + 5", "target(6) == 30")
    kotlin_large_target = kotlin_large_initial.replace("fun target(x: Int) = x + 5", "fun target(x: Int) = x * 5").replace("target(6) == 11", "target(6) == 30")
    return (
        JvmTask("jvm-01", "literal-edit", "Change the shared constant k from 3 to 7; both uses must change. Change nothing else.",
                _java("    static int f(int x) { final int k = 3; return (x + k) * k; }", "f(2) == 63"),
                _java("    static int f(int x) { final int k = 7; return (x + k) * k; }", "f(2) == 63"),
                _kotlin("    fun f(x: Int): Int { val k = 3; return (x + k) * k }", "f(2) == 63"),
                _kotlin("    fun f(x: Int): Int { val k = 7; return (x + k) * k }", "f(2) == 63"), "task-01", "set-constant N0 7"),
        JvmTask("jvm-02", "operation-substitution", "Change f from wrapping addition to wrapping multiplication. Keep its operands and change nothing else.",
                _java("    static int f(int x) { final int k = 5; return x + k; }", "f(6) == 30"),
                _java("    static int f(int x) { final int k = 5; return x * k; }", "f(6) == 30"),
                _kotlin("    fun f(x: Int): Int { val k = 5; return x + k }", "f(6) == 30"),
                _kotlin("    fun f(x: Int): Int { val k = 5; return x * k }", "f(6) == 30"), "task-02", "set-op N1 mul.wrap"),
        JvmTask("jvm-03", "operand-edit", "Change only r's second operand from a to b.",
                _java("    static int f(int x) { final int a = 2, b = 9; return x * a; }", "f(3) == 27"),
                _java("    static int f(int x) { final int a = 2, b = 9; return x * b; }", "f(3) == 27"),
                _kotlin("    fun f(x: Int): Int { val a = 2; val b = 9; return x * a }", "f(3) == 27"),
                _kotlin("    fun f(x: Int): Int { val a = 2; val b = 9; return x * b }", "f(3) == 27"), "task-03", "replace-operand N2 1 N1"),
        JvmTask("jvm-04", "delete", "Delete the unused constant dead. Change nothing else.",
                _java("    static int f(int x) { final int k = 4, dead = 21; return x + k; }", "f(3) == 7"),
                _java("    static int f(int x) { final int k = 4; return x + k; }", "f(3) == 7"),
                _kotlin("    fun f(x: Int): Int { val k = 4; val dead = 21; return x + k }", "f(3) == 7"),
                _kotlin("    fun f(x: Int): Int { val k = 4; return x + k }", "f(3) == 7"), "task-04", "delete N1"),
        JvmTask("jvm-05", "move", "Move b immediately before a. Change nothing else.",
                _java("    static int f(int x) { final int a = 2; final int b = 9; return x + a + b; }", "f(1) == 12"),
                _java("    static int f(int x) { final int b = 9; final int a = 2; return x + a + b; }", "f(1) == 12"),
                _kotlin("    fun f(x: Int): Int { val a = 2; val b = 9; return x + a + b }", "f(1) == 12"),
                _kotlin("    fun f(x: Int): Int { val b = 9; val a = 2; return x + a + b }", "f(1) == 12"), "task-05", "move N1 before N0"),
        JvmTask("jvm-06", "creation", "Create Program with a callable f(i32)->i32 such that f(x) = x + 7.",
                "", _java("    static int f(int x) { return x + 7; }", "f(5) == 12"),
                "", _kotlin("    fun f(x: Int) = x + 7", "f(5) == 12"), "task-06", "insert-constant N1 0 7; replace-operand N2 1 @0"),
        JvmTask("jvm-07", "control-flow", "Change only the selected branch result from x to y.",
                _java("    static int f(boolean take, int x, int y) { return take ? x : 1; }", "f(true, 4, 9) == 9"),
                _java("    static int f(boolean take, int x, int y) { return take ? y : 1; }", "f(true, 4, 9) == 9"),
                _kotlin("    fun f(take: Boolean, x: Int, y: Int) = if (take) x else 1", "f(true, 4, 9) == 9"),
                _kotlin("    fun f(take: Boolean, x: Int, y: Int) = if (take) y else 1", "f(true, 4, 9) == 9"), "task-07", "disconnect-edge N0 0 0 P0; connect-edge N0 0 0 P1"),
        JvmTask("jvm-08", "type-repair", "Repair the verifier/compiler-detectable operand type error so f adds the u8-compatible value y.",
                _java("    static byte f(byte x, short bad, byte y) { return x + bad; }", "f((byte)2, (short)7, (byte)3) == 5"),
                _java("    static byte f(byte x, short bad, byte y) { return (byte)(x + y); }", "f((byte)2, (short)7, (byte)3) == 5"),
                _kotlin("    fun f(x: Byte, bad: Short, y: Byte): Byte = x + bad", "f(2, 7, 3) == 5.toByte()"),
                _kotlin("    fun f(x: Byte, bad: Short, y: Byte): Byte = (x + y).toByte()", "f(2, 7, 3) == 5.toByte()"), "task-08", "replace-operand N0 1 P3"),
        JvmTask("jvm-09", "resource-effect-repair", "Repair the resource flow so resources are closed in reverse acquisition order.",
                _java("    static int f() { java.util.ArrayDeque<Integer> r = new java.util.ArrayDeque<>(); r.push(1); r.push(2); r.removeLast(); r.removeLast(); return 7; }", "f() == 7"),
                _java("    static int f() { java.util.ArrayDeque<Integer> r = new java.util.ArrayDeque<>(); r.push(1); r.push(2); r.pop(); r.pop(); return 7; }", "f() == 7"),
                _kotlin("    fun f(): Int { val r = java.util.ArrayDeque<Int>(); r.push(1); r.push(2); r.removeLast(); r.removeLast(); return 7 }", "f() == 7"),
                _kotlin("    fun f(): Int { val r = java.util.ArrayDeque<Int>(); r.push(1); r.push(2); r.pop(); r.pop(); return 7 }", "f() == 7"), "task-09", "replace-operand N2 0 N1; replace-operand N3 0 N0"),
        JvmTask("jvm-10", "stale-root", "Recover from the stale edit base and change the current addition to multiplication without reverting the concurrent constant update.",
                _java("    static int f(int x) { final int k = 5; final int concurrent = 10; return x + k + concurrent; }", "f(2) == 20"),
                _java("    static int f(int x) { final int k = 5; final int concurrent = 10; return x * k + concurrent; }", "f(2) == 20"),
                _kotlin("    fun f(x: Int): Int { val k = 5; val concurrent = 10; return x + k + concurrent }", "f(2) == 20"),
                _kotlin("    fun f(x: Int): Int { val k = 5; val concurrent = 10; return x * k + concurrent }", "f(2) == 20"), "task-10", "set-op N2 mul.wrap"),
        JvmTask("jvm-11", "optimization", "Remove the dead local while preserving behavior.",
                _java("    static int f(int x) { final int k = 4; final int dead = x * 0; return x + k; }", "f(3) == 7"),
                _java("    static int f(int x) { final int k = 4; return x + k; }", "f(3) == 7"),
                _kotlin("    fun f(x: Int): Int { val k = 4; val dead = x * 0; return x + k }", "f(3) == 7"),
                _kotlin("    fun f(x: Int): Int { val k = 4; return x + k }", "f(3) == 7"), "task-11", "delete N1"),
        JvmTask("jvm-12", "type-change", "Change f's result and constant from u8 to u16 without changing the value.",
                _java("    static byte f() { return (byte)7; }", "f() == 7"), _java("    static short f() { return (short)7; }", "f() == 7"),
                _kotlin("    fun f(): Byte = 7", "f() == 7.toByte()"), _kotlin("    fun f(): Short = 7", "f() == 7.toShort()"), None,
                "result-type N0 0 T8 T16; signature F0 - - T8 T16", True),
        JvmTask("jvm-13", "context-scaling", "Change the shared constant k from 3 to 7; ignore unrelated project files.",
                _java("    static int f(int x) { final int k = 3; return (x + k) * k; }", "f(2) == 63"),
                _java("    static int f(int x) { final int k = 7; return (x + k) * k; }", "f(2) == 63"),
                _kotlin("    fun f(x: Int): Int { val k = 3; return (x + k) * k }", "f(2) == 63"),
                _kotlin("    fun f(x: Int): Int { val k = 7; return (x + k) * k }", "f(2) == 63"), "task-01", "set-constant N0 7", unrelated_files=256),
        JvmTask("jvm-14", "cross-function-api", "Change inc and its caller from the u8 API to u16, preserving the returned value.",
                _java("    static byte inc(byte x) { return x; }\n    static byte call() { return inc((byte)7); }", "call() == 7"),
                _java("    static short inc(short x) { return x; }\n    static short call() { return inc((short)7); }", "call() == 7"),
                _kotlin("    fun inc(x: Byte): Byte = x\n    fun call(): Byte = inc(7)", "call() == 7.toByte()"),
                _kotlin("    fun inc(x: Short): Short = x\n    fun call(): Short = inc(7)", "call() == 7.toShort()"), None,
                "result-type N0 0 T8 T16; result-type N1 0 T8 T16; signature F0 - - T8 T16; signature F1 T8 T16 T8 T16", True),
        JvmTask("jvm-15", "large-application", "Inside this large application, change only target from addition by 5 to multiplication by 5 and update its assertion.",
                java_large_initial, java_large_target, kotlin_large_initial, kotlin_large_target, "task-02", "set-op N1 mul.wrap", unrelated_files=64),
    )


def task(task_id: str) -> JvmTask:
    return next(item for item in tasks() if item.task_id == task_id)


def _normalize(source: str) -> str:
    return re.sub(r"\s+", "", re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S))


def _compiler(arm: str) -> Path:
    if arm == "JAVA":
        found = shutil.which("javac")
    else:
        found = shutil.which("kotlinc") or (str(KOTLIN) if KOTLIN.is_file() else None)
    if not found:
        raise ValueError(f"{arm.lower()} compiler unavailable")
    return Path(found)


def check_source(task_id: str, arm: str, workspace: Path) -> tuple[bool, str]:
    item, arm = task(task_id), arm.upper()
    name, expected = ("Program.java", item.java_target) if arm == "JAVA" else ("Program.kt", item.kotlin_target)
    path = workspace / name
    if not path.is_file():
        return False, f"{name} is missing"
    if item.family != "creation" and _normalize(path.read_text(encoding="utf-8")) != _normalize(expected):
        return False, f"{name} does not match the requested semantic target"
    with tempfile.TemporaryDirectory() as directory:
        build = Path(directory)
        if arm == "JAVA":
            sources = [path]
            entry = "Program"
            if item.family == "creation":
                probe = build / "Probe.java"
                probe.write_text("public final class Probe { public static void main(String[] a) { if (Program.f(5) != 12) throw new AssertionError(); } }\n")
                sources.append(probe)
                entry = "Probe"
            compiled = subprocess.run([_compiler(arm), "-d", build, *sources], capture_output=True, text=True)
            if compiled.returncode:
                return False, compiled.stderr.strip()
            ran = subprocess.run([shutil.which("java") or "java", "-cp", build, entry], capture_output=True, text=True)
        else:
            jar = build / "program.jar"
            sources = [path]
            if item.family == "creation":
                probe = build / "Probe.kt"
                probe.write_text("fun main() { check(Program.f(5) == 12) }\n")
                sources.append(probe)
            compiled = subprocess.run([_compiler(arm), *sources, "-include-runtime", "-d", jar], capture_output=True, text=True)
            if compiled.returncode and item.family == "creation":
                probe.write_text("fun main() { check(f(5) == 12) }\n")
                compiled = subprocess.run([_compiler(arm), *sources, "-include-runtime", "-d", jar], capture_output=True, text=True)
            if compiled.returncode:
                return False, compiled.stderr.strip()
            entry = "ProbeKt" if item.family == "creation" else None
            ran = subprocess.run(
                ([shutil.which("java") or "java", "-cp", jar, entry] if entry else [shutil.which("java") or "java", "-jar", jar]),
                capture_output=True,
                text=True,
            )
        return ran.returncode == 0, ran.stderr.strip() or ran.stdout.strip()


def _checker_script(task_id: str, arm: str) -> str:
    compiler = HERE.parent
    return (
        "import sys\nfrom pathlib import Path\n"
        f"sys.path[:0] = [{str(compiler / 'src')!r}, {str(compiler)!r}]\n"
        "from benchmarks.jvm_r5_ai import check_source\n"
        f"ok, why = check_source({task_id!r}, {arm!r}, Path(__file__).parent)\n"
        "print('PASS' if ok else f'FAIL {why}')\nraise SystemExit(0 if ok else 1)\n"
    )


def _unrelated(output: Path, count: int) -> None:
    if not count:
        return
    root = output / "unrelated"
    root.mkdir()
    for index in range(count):
        (root / f"part-{index:04}.txt").write_text((f"unrelated-{index}\n" * 8), encoding="utf-8")


def prepare_source(task_id: str, arm: str, output: Path) -> Path:
    item, arm = task(task_id), arm.upper()
    output.mkdir(parents=True, exist_ok=False)
    name, initial = ("Program.java", item.java_initial) if arm == "JAVA" else ("Program.kt", item.kotlin_initial)
    if initial:
        (output / name).write_text(initial, encoding="utf-8")
    (output / "check.py").write_text(_checker_script(task_id, arm), encoding="utf-8")
    (output / "TASK.md").write_text(
        f"# {task_id} / {arm}\n\n> {item.prompt}\n>\n> Inspect and edit only `{name}`, then run `python check.py`. Stop after `PASS`.\n",
        encoding="utf-8",
    )
    _unrelated(output, item.unrelated_files)
    return output


def _custom_workspace(task_id: str):
    b8, b16 = bits_type(8), bits_type(16)
    objects = [b8, b16]
    if task_id == "jvm-12":
        value, helper_value = constant(b8, 7), constant(b16, 1)
        graph = graph_fragment([Block((), (Node(Operation.CONSTANT, (), (b8,), entity=value),), Terminator.return_((ValueRef.node_result(0, 0),)))])
        helper_graph = graph_fragment([Block((), (Node(Operation.CONSTANT, (), (b16,), entity=helper_value),), Terminator.return_((ValueRef.node_result(0, 0),)))])
        main, helper = function(graph, (), (b8,)), function(helper_graph, (), (b16,))
        objects += [value, helper_value, graph, helper_graph, main, helper]
        functions = {"F0": main}
        nodes = {"N0": (main, 0)}
        view = "R0 F0()->T8; N0 const 7:T8; T8 u8; T16 u16"
    elif task_id == "jvm-14":
        value, helper_value = constant(b8, 7), constant(b16, 1)
        callee_graph = graph_fragment([Block((b8,), (), Terminator.return_((ValueRef.parameter(0, 0),)))])
        callee = function(callee_graph, (b8,), (b8,))
        caller_graph = graph_fragment([Block((), (
            Node(Operation.CONSTANT, (), (b8,), entity=value),
            Node(Operation.CALL_DIRECT, (ValueRef.node_result(0, 0),), (b8,), entity=callee),
        ), Terminator.return_((ValueRef.node_result(0, 1),)))])
        caller = function(caller_graph, (), (b8,))
        helper_graph = graph_fragment([Block((), (Node(Operation.CONSTANT, (), (b16,), entity=helper_value),), Terminator.return_((ValueRef.node_result(0, 0),)))])
        helper = function(helper_graph, (), (b16,))
        objects += [value, helper_value, callee_graph, caller_graph, helper_graph, callee, caller, helper]
        functions = {"F0": caller, "F1": callee}
        nodes = {"N0": (caller, 0), "N1": (caller, 1)}
        view = "R0 F0()->T8 {N0 const 7:T8; N1 call F1(N0)->T8; return N1}; F1(T8)->T8; T8 u8; T16 u16"
    else:
        raise ValueError(task_id)
    module = object_with_refs(Kind.MODULE, tuple(functions.values()) + (helper,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects += [module, root]
    reader = StoreReader(write_store(root.cid, objects))
    verify_store(reader)
    workspace = Workspace(reader)
    function_handles = {}
    node_handles = {}
    for alias, fn in functions.items():
        page = workspace.function_nodes(fn.cid, 16)
        function_handles[alias] = workspace._function_handles[fn.cid]
        for node_alias, (owner, index) in nodes.items():
            if owner.cid == fn.cid:
                node_handles[node_alias] = page.entities[index].handle
                workspace.neighborhood(page.entities[index].handle, 16)
    helper_nodes = workspace.function_nodes(helper.cid, 1).entities
    if helper_nodes:
        workspace.neighborhood(helper_nodes[0].handle, 4)
    types = {"T8": workspace._type_handles[b8.cid], "T16": workspace._type_handles[b16.cid]}
    return workspace, view, function_handles, node_handles, types


def _type_list(field: str, aliases: dict[str, str]) -> tuple[str, ...]:
    return () if field == "-" else tuple(aliases[item] for item in field.split(","))


def _custom_transaction(task_id: str, command: str) -> tuple[Workspace, Transaction]:
    workspace, _view, functions, nodes, types = _custom_workspace(task_id)
    mutations = []
    for record in command.split(";"):
        parts = record.split()
        if not parts:
            continue
        if parts[0] == "result-type" and len(parts) == 5:
            mutations.append(SetResultType(nodes[parts[1]], int(parts[2]), types[parts[3]], types[parts[4]]))
        elif parts[0] == "signature" and len(parts) == 6:
            mutations.append(SetFunctionSignature(functions[parts[1]], *(_type_list(field, types) for field in parts[2:])))
        else:
            raise ValueError("result-type N I OLD NEW | signature F OLD_PARAMS NEW_PARAMS OLD_RETURNS NEW_RETURNS")
    if not mutations:
        raise ValueError("empty transaction")
    return workspace, Transaction(RootRef(0), tuple(mutations))


def check_xax(task_id: str, workspace_path: Path) -> tuple[bool, str]:
    try:
        command = (workspace_path / "direct.txt").read_text(encoding="utf-8")
        workspace, transaction = _custom_transaction(task_id, command)
        result = workspace.commit(transaction)
        reference_workspace, reference = _custom_transaction(task_id, task(task_id).xax_command)
        expected = reference_workspace.commit(reference)
        return bool(result.committed and expected.committed and result.root == expected.root), "wrong semantic target"
    except (OSError, ValueError) as error:
        return False, str(error)


def xax_main(task_id: str, workspace_path: Path, argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "apply":
        print("FAIL apply CMD")
        return 1
    command = argv[1]
    try:
        workspace, transaction = _custom_transaction(task_id, command)
        verified = workspace.verify(transaction)
        if not verified.verified:
            print(f"FAIL {verified.diagnostic.code}")
            return 1
        (workspace_path / "direct.txt").write_text(command, encoding="utf-8")
        passed, reason = check_xax(task_id, workspace_path)
        print("PASS" if passed else f"FAIL {reason}")
        return 0 if passed else 1
    except (OSError, ValueError) as error:
        print(f"FAIL {error}")
        return 1


def _custom_script(task_id: str) -> str:
    compiler = HERE.parent
    return (
        "import sys\nfrom pathlib import Path\n"
        f"sys.path[:0] = [{str(compiler / 'src')!r}, {str(compiler)!r}]\n"
        "from benchmarks.jvm_r5_ai import xax_main\n"
        f"raise SystemExit(xax_main({task_id!r}, Path(__file__).parent, sys.argv[1:]))\n"
    )


def prepare_xax_task(task_id: str, output: Path) -> Path:
    item = task(task_id)
    if item.custom_xax:
        output.mkdir(parents=True, exist_ok=False)
        _workspace, view, _functions, _nodes, _types = _custom_workspace(task_id)
        (output / "direct.txt").write_text("", encoding="utf-8")
        (output / "xax.py").write_text(_custom_script(task_id), encoding="utf-8")
        (output / "TASK.md").write_text(
            f"# {task_id} / XAX\n\n> {item.prompt}\n>\n> Complete local view: `{view}`.\n"
            "> Run one quoted `python xax.py apply CMD`; it atomically verifies, commits, and target-checks.\n"
            "> `CMD`: `result-type N I OLD NEW` | `signature F OLD_PARAMS NEW_PARAMS OLD_RETURNS NEW_RETURNS`; use `-` for an empty type list and `;` between mutations. Stop after `PASS`.\n",
            encoding="utf-8",
        )
    else:
        arm = "XAX-TYPED-LINE" if task_id == "jvm-10" else "XAX-DIRECT"
        prepare_xax(item.xax_task, arm, output)
        task_file = output / "TASK.md"
        task_file.write_text(task_file.read_text(encoding="utf-8").replace(load_task(item.xax_task).prompt, item.prompt), encoding="utf-8")
    _unrelated(output, item.unrelated_files)
    return output


def prepare_suite(output: Path = RUNS) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for item in tasks():
        prepare_source(item.task_id, "JAVA", output / f"{item.task_id}-java")
        prepare_source(item.task_id, "KOTLIN", output / f"{item.task_id}-kotlin")
        prepare_xax_task(item.task_id, output / f"{item.task_id}-xax")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare"); prep.add_argument("output", nargs="?", type=Path, default=RUNS)
    check = sub.add_parser("check-source"); check.add_argument("task_id"); check.add_argument("arm"); check.add_argument("workspace", type=Path)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        prepare_suite(args.output)
        return 0
    passed, reason = check_source(args.task_id, args.arm, args.workspace)
    print("PASS" if passed else f"FAIL {reason}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
