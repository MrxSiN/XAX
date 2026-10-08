"""JVM R5 multi-file corpus (ADR-197, OI-46 option b).

One spec per task generates the Java and Kotlin projects and the XAX store, so
every arm edits the same program. The edit touches a target function and its
transitive callers in other classes. XAX receives that call hierarchy through
the workspace `callers` query. Each textual language has two workflows: the
whole files containing the hierarchy, as an agent reads them, and an IDE-style
excerpt of just the hierarchy's methods. The gate compares XAX against the
lowest of the four textual medians.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from benchmarks.jvm_r5_ai import _compiler, _normalize
from benchmarks.jvm_r5_response import _apply_context_patch, unwrap_response
from xax_compiler import (IntCompare, Kind, Operation, StoreReader, bits_type, jvm_classfile_target,
                          object_with_refs, verify_store, write_store)
from xax_graph_builder import GraphBuilder
from xax_local_protocol import LocalMutationSession, edit_grammar_id
from xax_workspace import Workspace

ARMS = ("JAVA", "JAVA-EXCERPT", "KOTLIN", "KOTLIN-EXCERPT", "XAX")
TEXTUAL = ARMS[:4]
CLASSES = ("Units", "Orders", "Billing", "Report", "Main")
OPS = {"add": "+", "sub": "-", "mul": "*"}
XAX_OPS = {"add": Operation.ADD_WRAP, "sub": Operation.SUB_WRAP, "mul": Operation.MUL_WRAP}


@dataclass(frozen=True)
class Fn:
    cls: str
    name: str
    params: tuple[int, ...]
    ret: int
    body: tuple  # ("p", i) | ("c", v, width) | (op, a, b) | ("call", "Cls.name", *args) | ("eq", a, b)

    @property
    def key(self):
        return f"{self.cls}.{self.name}"


@dataclass(frozen=True)
class Task:
    task_id: str
    family: str
    prompt: str
    target: str            # Cls.name whose transitive callers form the edit's hierarchy
    initial: tuple[Fn, ...]
    final: tuple[Fn, ...]
    entry: str             # function executed after the edit
    expected: int          # its result
    width: int


def _helpers(cls_index: int, cls: str, count: int) -> list[Fn]:
    """A call chain per class with constants unique across the project, so no
    two functions share content (content addressing would merge them)."""
    out = []
    for i in range(count):
        a, b = 3 + (cls_index * 5 + i) % 7, 100 * (cls_index + 1) + i
        inner = ("p", 0) if i == 0 else ("call", f"{cls}.h{i - 1}", ("p", 0))
        out.append(Fn(cls, f"h{i}", (32,), 32, ("add", ("mul", inner, ("c", a, 32)), ("c", b, 32))))
    return out


def _project(specific: list[Fn], helpers: dict[str, int]) -> tuple[Fn, ...]:
    fns = [fn for index, cls in enumerate(CLASSES) for fn in _helpers(index, cls, helpers.get(cls, 0))]
    # A 16-bit function exists in the project, as wider types do in real code.
    return tuple(fns + [Fn("Units", "unit", (), 16, ("c", 1, 16))] + specific)


def _swap(fns, key, **changes):
    return tuple(replace(fn, **changes) if fn.key == key else fn for fn in fns)


def tasks() -> tuple[Task, ...]:
    sizes = {"Units": 12, "Orders": 40, "Billing": 24, "Report": 24, "Main": 0}
    # mf-01: cross-file 8-bit to 16-bit API change of a callee and its callers.
    api = [Fn("Units", "scale", (8,), 8, ("p", 0)),
           Fn("Orders", "qty", (), 8, ("call", "Units.scale", ("c", 7, 8))),
           Fn("Billing", "fee", (), 8, ("call", "Units.scale", ("c", 3, 8))),
           Fn("Report", "code", (), 8, ("call", "Units.scale", ("c", 5, 8)))]
    api_final = [Fn("Units", "scale", (16,), 16, ("p", 0))] + [
        replace(fn, ret=16, body=("call", "Units.scale", ("c", fn.body[2][1], 16))) for fn in api[1:]]
    # mf-02: operation change in a large class and its dependent assertion.
    disc = [Fn("Orders", "discount", (32,), 32, ("add", ("mul", ("p", 0), ("c", 3, 32)), ("c", 4, 32))),
            Fn("Main", "c1", (), 1, ("eq", ("call", "Orders.discount", ("c", 5, 32)), ("c", 19, 32)))]
    disc_final = [replace(disc[0], body=("sub", disc[0].body[1], ("c", 4, 32))),
                  replace(disc[1], body=("eq", disc[1].body[1], ("c", 11, 32)))]
    # mf-03: constant change whose effect reaches assertions through a call chain.
    rate = [Fn("Billing", "rate", (), 32, ("c", 5, 32)),
            Fn("Billing", "fee", (32,), 32, ("mul", ("p", 0), ("call", "Billing.rate"))),
            Fn("Report", "summary", (32,), 32, ("add", ("call", "Billing.fee", ("p", 0)), ("c", 1, 32))),
            Fn("Main", "c1", (), 1, ("eq", ("call", "Billing.fee", ("c", 4, 32)), ("c", 20, 32))),
            Fn("Main", "c2", (), 1, ("eq", ("call", "Report.summary", ("c", 2, 32)), ("c", 11, 32)))]
    rate_final = [replace(rate[0], body=("c", 7, 32)), rate[1], rate[2],
                  replace(rate[3], body=("eq", rate[3].body[1], ("c", 28, 32))),
                  replace(rate[4], body=("eq", rate[4].body[1], ("c", 15, 32)))]
    return (
        Task("mf-01", "cross-file-api", "Change Units.scale and all of its callers from an 8-bit to a 16-bit integer API, preserving every returned value.",
             "Units.scale", _project(api, sizes), _project(api_final, sizes), "Orders.qty", 7, 16),
        Task("mf-02", "large-class-dependent-assertion", "Change Orders.discount from adding 4 to subtracting 4, and update every assertion that depends on it.",
             "Orders.discount", _project(disc, sizes), _project(disc_final, sizes), "Main.c1", 1, 1),
        Task("mf-03", "transitive-constant", "Change Billing.rate from 5 to 7, and update every assertion that depends on it.",
             "Billing.rate", _project(rate, sizes), _project(rate_final, sizes), "Main.c2", 1, 1),
    )


def task(task_id):
    return next(item for item in tasks() if item.task_id == task_id)


def hierarchy(fns, target):
    """The target and its transitive callers, in program order."""
    def callees(expr):
        if expr[0] == "call":
            yield expr[1]
        for part in expr[1:]:
            if isinstance(part, tuple):
                yield from callees(part)
    keys = {target}
    changed = True
    while changed:
        changed = False
        for fn in fns:
            if fn.key not in keys and keys & set(callees(fn.body)):
                keys.add(fn.key)
                changed = True
    return [fn for fn in fns if fn.key in keys]


# Textual projects --------------------------------------------------------------

JAVA_TYPES = {1: "boolean", 8: "byte", 16: "short", 32: "int"}
KOTLIN_TYPES = {1: "Boolean", 8: "Byte", 16: "Short", 32: "Int"}


def _expr(expr, cls, kotlin):
    kind = expr[0]
    if kind == "p":
        return "xyz"[expr[1]]
    if kind == "c":
        return str(expr[1]) if kotlin or expr[2] == 32 else f"({JAVA_TYPES[expr[2]]}){expr[1]}"
    if kind == "call":
        owner, name = expr[1].split(".")
        callee = name if owner == cls else expr[1]
        return f"{callee}({', '.join(_expr(arg, cls, kotlin) for arg in expr[2:])})"
    if kind == "eq":
        return f"{_expr(expr[1], cls, kotlin)} == {_expr(expr[2], cls, kotlin)}"
    left, right = (_expr(part, cls, kotlin) for part in expr[1:])
    left = f"({left})" if expr[1][0] in OPS and kind == "mul" and expr[1][0] != "mul" else left
    return f"{left} {OPS[kind]} {right}"


def _method(fn, kotlin):
    params = ", ".join(f"{'xyz'[i]}: {KOTLIN_TYPES[w]}" if kotlin else f"{JAVA_TYPES[w]} {'xyz'[i]}" for i, w in enumerate(fn.params))
    body = _expr(fn.body, fn.cls, kotlin)
    if kotlin:
        return f"    fun {fn.name}({params}): {KOTLIN_TYPES[fn.ret]} = {body}"
    return f"    static {JAVA_TYPES[fn.ret]} {fn.name}({params}) {{ return {body}; }}"


def sources(fns, kotlin):
    """One file per class; every method is one line. Main also carries the
    harness entry that runs its assertions."""
    files = {}
    for cls in CLASSES:
        methods = [_method(fn, kotlin) for fn in fns if fn.cls == cls]
        checks = [fn.name for fn in fns if fn.cls == cls and fn.ret == 1]
        if cls == "Main":
            condition = " && ".join(f"{name}()" for name in checks) or "true"
            methods.append(f"    @JvmStatic fun main(args: Array<String>) {{ check({condition}) }}" if kotlin else
                           f"    public static void main(String[] args) {{ if (!({condition})) throw new AssertionError(); }}")
        head = f"object {cls} {{" if kotlin else (f"public final class {cls} {{" if cls == "Main" else f"final class {cls} {{")
        files[f"{cls}.{'kt' if kotlin else 'java'}"] = "\n".join([head, *methods, "}"]) + "\n"
    return files


def textual_context(item, arm, files):
    """Whole files containing the hierarchy, or only the hierarchy's current
    method lines (matched by name, so a repair shows the edited text)."""
    wanted = {}
    for fn in hierarchy(item.initial, item.target):
        wanted.setdefault(fn.cls, set()).add(fn.name)
    parts = []
    for name, text in files.items():
        names = wanted.get(name.rsplit(".", 1)[0])
        if not names:
            continue
        if arm.endswith("EXCERPT"):
            lines = [line for line in text.splitlines()
                     if (match := re.match(r"\s+(?:fun|static \w+) (\w+)\(", line)) and match[1] in names]
            parts.append(f"{name} (excerpt):\n" + "".join(line + "\n" for line in lines))
        else:
            parts.append(f"{name}:\n{text}")
    return "\n".join(parts)


def apply_multi_patch(directory: Path, response: str):
    """Apply one bounded apply_patch response with one Update File section per file."""
    lines = response.strip().splitlines()
    if len(lines) < 4 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("expected one bounded apply_patch update")
    sections, current = [], None
    for line in lines[1:-1]:
        if line.startswith("*** Update File: "):
            current = [line]
            sections.append(current)
        elif current is None:
            raise ValueError("patch content before *** Update File")
        else:
            current.append(line)
    if not sections:
        raise ValueError("empty patch")
    names = [section[0][len("*** Update File: "):].strip() for section in sections]
    if len(set(names)) != len(names):
        raise ValueError("one section per file")
    originals = {}
    for name in names:
        path = directory / name
        if "/" in name or "\\" in name or not path.is_file():
            raise ValueError(f"patch must target an existing project file: {name}")
        originals[name] = path.read_text(encoding="utf-8")
    try:
        for name, section in zip(names, sections):
            patch = "\n".join(["*** Begin Patch", f"*** Update File: {name}", *section[1:], "*** End Patch"])
            _apply_context_patch(directory / name, patch, originals[name])
    except Exception:
        for name, text in originals.items():
            (directory / name).write_text(text, encoding="utf-8", newline="\n")
        raise


def _stdlib():
    kotlinc = shutil.which("kotlinc")
    if not kotlinc:
        raise ValueError("kotlinc unavailable")
    return Path(kotlinc).resolve().parent.parent / "lib" / "kotlin-stdlib.jar"


def _build(files: dict[str, str], output: Path, kotlin: bool):
    output.mkdir(parents=True)
    src = output / "src"
    src.mkdir()
    for name, text in files.items():
        (src / name).write_text(text, encoding="utf-8", newline="\n")
    classes = output / "classes"
    paths = sorted(src.iterdir())
    command = ([_compiler("KOTLIN"), *paths, "-d", classes] if kotlin else [_compiler("JAVA"), "-d", classes, *paths])
    compiled = subprocess.run(command, capture_output=True, text=True)
    if compiled.returncode:
        return None, compiled.stderr.strip()
    return classes, ""


def _instructions(classes: Path):
    names = sorted(path.stem for path in classes.glob("*.class"))
    javap = shutil.which("javap")
    result = subprocess.run([javap, "-classpath", str(classes), "-c", "-p", "-s", "-constants", *names], capture_output=True, text=True)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return "\n".join(re.sub(r"#\d+", "#", line) for line in result.stdout.splitlines() if not line.startswith("Compiled from "))


def check_textual(item, arm, directory: Path):
    """Exact normalized sources, or equal compiled instructions that differ from
    the initial program; then the project's assertions must run."""
    kotlin = arm.startswith("KOTLIN")
    target, initial = sources(item.final, kotlin), sources(item.initial, kotlin)
    actual = {name: (directory / name).read_text(encoding="utf-8") for name in target}
    exact = all(_normalize(actual[name]) == _normalize(text) for name, text in target.items())
    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        classes, error = _build(actual, scratch / "actual", kotlin)
        if classes is None:
            return False, error
        if not exact:
            reference, _ = _build(target, scratch / "target", kotlin)
            start, _ = _build(initial, scratch / "initial", kotlin)
            code = _instructions(classes)
            if code != _instructions(reference) or code == _instructions(start):
                return False, "project does not match the requested semantic target"
        classpath = str(classes) + (";" if "\\" in str(classes) else ":") + str(_stdlib()) if kotlin else str(classes)
        ran = subprocess.run([shutil.which("java") or "java", "-cp", classpath, "Main"], capture_output=True, text=True)
        return ran.returncode == 0, (ran.stderr.strip() or ran.stdout.strip())[:400]


# XAX ---------------------------------------------------------------------------

def build_store(fns):
    """Canonical XAX program for a spec; returns (reader, {key: function cid})."""
    built, graphs = {}, []
    types = {w: bits_type(w) for w in (1, 8, 16, 32)}
    for fn in fns:
        graph = GraphBuilder()
        block = graph.block(*(types[w] for w in fn.params))

        def emit(expr, width):
            kind = expr[0]
            if kind == "p":
                return block.params[expr[1]]
            if kind == "c":
                return block.const(types[expr[2]], expr[1])
            if kind == "call":
                callee = next(f for f in fns if f.key == expr[1])
                args = tuple(emit(arg, callee.params[i]) for i, arg in enumerate(expr[2:]))
                return block.op1(Operation.CALL_DIRECT, args, types[callee.ret], entity=built[expr[1]])
            if kind == "eq":
                left, right = emit(expr[1], 32), emit(expr[2], 32)
                return block.op1(Operation.INT_COMPARE, (left, right), types[1], attributes=(IntCompare.EQ,))
            left, right = emit(expr[1], width), emit(expr[2], width)
            return block.op1(XAX_OPS[kind], (left, right), types[width])
        block.ret(emit(fn.body, fn.ret))
        built[fn.key] = graph.function(tuple(types[w] for w in fn.params), (types[fn.ret],))
        graphs.append(graph)
    objects = {obj.cid: obj for graph in graphs for obj in graph.objects.values()}
    module = object_with_refs(Kind.MODULE, tuple(built[fn.key] for fn in fns))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*objects.values(), module, root)))
    verify_store(reader)
    return reader, {key: obj.cid for key, obj in built.items()}


# Never B/F/P/R/T, which label blocks, functions, parameters, roots and types.
PREFIXES = "NACDEGHJKLM"


class XaxTrial:
    """The ordinary snapshot session over the target and its callers query."""

    def __init__(self, item: Task):
        self.item = item
        reader, cids = build_store(item.initial)
        self.workspace = Workspace(reader)
        selected, frontier = [cids[item.target]], [cids[item.target]]
        while frontier:
            cid = frontier.pop()
            for view in self.workspace.callers(cid, 64).entities:
                caller = self.workspace._function_bindings[view.handle][0]
                if caller not in selected:
                    selected.append(caller)
                    frontier.append(caller)
        # Shown functions are aliased by the names the task uses; the view lists
        # them by alias, and node prefixes follow that order.
        names = {cid: key for key, cid in cids.items()}
        self.selected = sorted(selected, key=names.get)
        aliases, parameter = {}, 0
        for index, cid in enumerate(self.selected):
            bound = LocalMutationSession.for_function(self.workspace, cid)
            for alias, handle in bound.aliases.items():
                if alias.startswith("P"):
                    aliases[f"P{parameter}"] = handle
                    parameter += 1
                else:
                    aliases[PREFIXES[index] + alias[1:]] = handle
        # Expose every integer type the program already has (a types query),
        # binding one function that uses it; only the view's functions get aliases.
        widths = {w for fn in item.initial if cids[fn.key] in self.selected for w in (*fn.params, fn.ret)}
        for fn in item.initial:
            if not {*fn.params, fn.ret} <= widths:
                LocalMutationSession.for_function(self.workspace, cids[fn.key])
                widths |= {*fn.params, fn.ret}
        aliases.update({names[cid]: self.workspace._function_handles[cid] for cid in self.selected})
        # Integer types get shape-named aliases (b8, b16, ...), derived from the
        # type alone: numbered T handles were confused across widths (ADR-197).
        from xax_compiler import XaxError, decode_bits_width
        for handle, binding in self.workspace._type_bindings.items():
            try:
                aliases[f"b{decode_bits_width(self.workspace.reader.get(binding[0]))}"] = handle
            except XaxError:
                pass  # not an integer type: keeps its T handle
        self.session = LocalMutationSession(self.workspace, aliases)
        self.target_reader, self.target_cids = build_store(item.final)
        self.reader = None
        self.entities = 0
        self.verifier_failures = 0
        self.stale_failures = 0

    def prompt(self):
        view = self.session.view(functions=tuple(self.selected))
        self.entities += self.session.last_view_entities
        return (self.item.prompt + "\nSnapshot:\n" + view +
                "\nReturn only the edits, in the shared edit grammar. No tools." + self.session.instructions(shared=edit_grammar_id()))

    def apply(self, response):
        result = self.session.commit(unwrap_response(response))
        if not result.committed:
            self.verifier_failures += 1
            self.stale_failures += int(result.diagnostic.code == "XAX.WORKSPACE.STALE_ROOT")
            return False, json.dumps(self.session.diagnostic_view(result.diagnostic), separators=(",", ":"))
        self.reader = self.workspace.reader
        if self.reader.root_cid != self.target_reader.root_cid:
            return False, "XAX.TEST.TARGET"
        return True, ""

    def check_jvm(self):
        """Equal roots mean equal stores; execute the entry of that program."""
        from xax_jvm import compile_jvm_bound_target, run_jvm_calls
        image = compile_jvm_bound_target(self.target_reader, self.target_cids[self.item.entry], jvm_classfile_target())
        actual = run_jvm_calls(image, ((),), result_width=self.item.width)
        return actual == (self.item.expected,), "" if actual == (self.item.expected,) else "JVM behavior differs"
