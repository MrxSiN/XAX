"""JVM token trials with host-applied final responses and real semantic fixtures.

The host adapters use ordinary compiler constructors and snapshot sessions.
Reference edits belong only to the checker, never the model-facing context.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from benchmarks.ai_native import _workspace_state, load_task
from benchmarks.jvm_r5_ai import _custom_workspace, task
from xax_compiler import (Kind, Operation, StoreReader, bits_type, constant, function,
    graph_fragment, object_with_refs, verify_store, write_store, IntCompare,
    jvm_classfile_target)
from xax_graph_builder import GraphBuilder
from xax_local_protocol import BATCH_HELP, LocalMutationSession, construct_program
from xax_workspace import Workspace


CREATION = {"parameters": [32], "returns": [32],
            "nodes": [["constant", 32, 7], ["add.wrap", 32, "P0", "@0"]], "return": ["@1"]}


def response_task(task_id):
    """Strengthen the new corpus without rewriting historical task definitions."""
    # These select only the named mutation kind/target, never its new fields.
    bindings = {"jvm-01": ("const", "N0"), "jvm-02": ("op", "N1"),
                "jvm-03": ("operand", "N2"),
                "jvm-07": ("edge", "N0"), "jvm-08": ("operand", "N0"),
                "jvm-10": ("op", "N2"), "jvm-13": ("const", "N0")}
    item = replace(task(task_id), xax_binding=bindings.get(task_id))
    if task_id == "jvm-06":
        return replace(item, prompt="Create Program with a callable f(i32)->i32 such that f(x) = x + 7. The program starts empty.")
    if task_id == "jvm-08":
        fields = {}
        for name in ("java_initial", "java_target"):
            fields[name] = getattr(item, name).replace("byte x, short bad, byte y", "byte x, byte old, short bad, byte y").replace("f((byte)2, (short)7, (byte)3)", "f((byte)2, (byte)9, (short)7, (byte)3)")
        for name in ("kotlin_initial", "kotlin_target"):
            fields[name] = getattr(item, name).replace("x: Byte, bad: Short, y: Byte", "x: Byte, old: Byte, bad: Short, y: Byte").replace("f(2, 7, 3)", "f(2, 9, 7, 3)")
        return replace(item, **fields)
    if task_id == "jvm-09":
        from benchmarks.jvm_r5_ai import _java, _kotlin
        java = ("    static final class Resources { int next=0, trace=0; boolean[] closed=new boolean[3]; "
                "int acquire() { return ++next; } void close(int id) { if (closed[id]) throw new IllegalStateException(); closed[id]=true; trace=trace*10+id; } }\n"
                "    static int f() { Resources r=new Resources(); int a=r.acquire(), b=r.acquire(); r.close(b); r.close(b); return r.trace; }")
        kotlin = ("    class Resources { var next=0; var trace=0; val closed=BooleanArray(3); fun acquire(): Int = ++next; "
                  "fun close(id: Int) { check(!closed[id]); closed[id]=true; trace=trace*10+id } }\n"
                  "    fun f(): Int { val r=Resources(); val a=r.acquire(); val b=r.acquire(); r.close(b); r.close(b); return r.trace }")
        return replace(item, java_initial=_java(java, "f() == 21"), java_target=_java(java.replace("r.close(b); r.close(b)", "r.close(b); r.close(a)"), "f() == 21"),
                       kotlin_initial=_kotlin(kotlin, "f() == 21"), kotlin_target=_kotlin(kotlin.replace("r.close(b); r.close(b)", "r.close(b); r.close(a)"), "f() == 21"))
    if task_id == "jvm-10":
        return replace(item, prompt="Change only the x + k subexpression to wrapping multiplication. Preserve the final addition of concurrent and its current constant; on a stale conflict refresh and retry without reverting concurrent updates.",
                       java_initial=item.java_initial.replace("concurrent = 10", "concurrent = 9"),
                       kotlin_initial=item.kotlin_initial.replace("concurrent = 10", "concurrent = 9"))
    if task_id == "jvm-11":
        return replace(item, prompt="Remove the unused dead computation and any constants used only by it, preserving all other behavior.")
    if task_id in {"jvm-12", "jvm-14"}:
        # ADR-197: "u8/u16" invited Kotlin UShort; the target is the signless
        # 8-bit to 16-bit integer change (Java/Kotlin byte to short).
        fields = {"prompt": item.prompt.replace("from u8 to u16", "from the 8-bit to the 16-bit integer type")
                                       .replace("from the u8 API to u16", "from an 8-bit to a 16-bit integer API")}
        for name in ("java_initial", "java_target"):
            fields[name] = getattr(item, name).replace("public final class Program {", "public final class Program {\n    static short helper() { return (short)1; }")
        for name in ("kotlin_initial", "kotlin_target"):
            fields[name] = getattr(item, name).replace("object Program {", "object Program {\n    fun helper(): Short = 1")
        return replace(item, **fields)
    if task_id == "jvm-15":
        return replace(item, java_initial=item.java_initial.replace("target(6) == 30", "target(6) == 11"),
                       kotlin_initial=item.kotlin_initial.replace("target(6) == 30", "target(6) == 11"))
    return item


def _store(graphs, functions):
    objects = {obj.cid: obj for graph in graphs for obj in graph.objects.values()}
    module = object_with_refs(Kind.MODULE, tuple(functions))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*objects.values(), module, root)))
    verify_store(reader)
    return Workspace(reader)


def _special(task_id):
    b1, b32 = bits_type(1), bits_type(32)
    graph = GraphBuilder()
    if task_id == "jvm-07":
        block = graph.block(b1, b32, b32)
        join = graph.block(b32)
        one = block.const(b32, 1)
        block.cbr(block.params[0], join, (block.params[1],), join, (one,))
        join.ret(join.params[0])
        entry = graph.function((b1, b32, b32), (b32,))
    elif task_id == "jvm-10":
        block = graph.block(b32)
        k, concurrent = block.const(b32, 5), block.const(b32, 9)
        first = block.op1(Operation.ADD_WRAP, (block.params[0], k), b32)
        block.ret(block.op1(Operation.ADD_WRAP, (first, concurrent), b32))
        entry = graph.function((b32,), (b32,))
    elif task_id == "jvm-11":
        block = graph.block(b32)
        k, zero = block.const(b32, 4), block.const(b32, 0)
        block.op1(Operation.MUL_WRAP, (block.params[0], zero), b32)
        block.ret(block.op1(Operation.ADD_WRAP, (block.params[0], k), b32))
        entry = graph.function((b32,), (b32,))
    elif task_id == "jvm-15":
        graphs, helpers = [], []
        for index in range(160):
            helper = GraphBuilder()
            block = helper.block(b32)
            block.ret(block.op1(Operation.ADD_WRAP, (block.params[0], block.const(b32, index)), b32))
            helpers.append(helper.function((b32,), (b32,)))
            graphs.append(helper)
        block = graph.block(b32)
        # Distinguish target's graph from helper5 despite equal behavior, so
        # content-addressed sharing cannot make a target edit change a helper.
        block.ret(block.op1(Operation.ADD_WRAP, (block.const(b32, 5), block.params[0]), b32))
        entry = graph.function((b32,), (b32,))
        app = GraphBuilder()
        block = app.block()
        argument = block.const(b32, 6)
        result = block.op1(Operation.CALL_DIRECT, (argument,), b32, entity=entry)
        expected = block.const(b32, 11)
        block.ret(block.op1(Operation.INT_COMPARE, (result, expected), b1, attributes=(IntCompare.EQ,)))
        assertion = app.function((), (b1,))
        return _store((*graphs, graph, app), (*helpers, entry, assertion)), entry.cid, assertion.cid
    else:
        raise ValueError(task_id)
    return _store((graph,), (entry,)), entry.cid, entry.cid


class SemanticTrial:
    def __init__(self, task_id: str, *, bound: bool = False):
        self.task_id = task_id
        self.binding = response_task(task_id).xax_binding if bound else None
        self.workspace = None
        self.session = None
        self.roles = ""
        self.candidate = ""
        self.concurrent_applied = False
        self.verifier_failures = 0
        self.stale_failures = 0
        self.mutations = 0
        self.entities = 0
        self.prompt_entities = 0
        if task_id == "jvm-06":
            self.expected = construct_program(CREATION).root_cid
            return
        if task_id in {"jvm-12", "jvm-14"}:
            self.workspace, _, functions, nodes, types = _custom_workspace(task_id)
            self.entry = next(cid for cid, name in self.workspace._function_handles.items() if name == functions["F0"])
            self.selected = [cid for cid, raw in self.workspace._function_handles.items() if raw in functions.values()]
            # Bind unused function parameters as well as nodes, and alias them:
            # an unaliased parameter showed as a raw handle (F2.B0.P0) beside the
            # F1 alias of its own function (ADR-196).
            parameters = {}
            for alias, raw in functions.items():
                cid = next(cid for cid, name in self.workspace._function_handles.items() if name == raw)
                bound = LocalMutationSession.for_function(self.workspace, cid)
                for handle in (h for a, h in bound.aliases.items() if a.startswith("P")):
                    parameters[f"P{len(parameters)}"] = handle
            self.session = LocalMutationSession(self.workspace, functions | nodes | types | parameters)
            self.roles = "f=F0" if task_id == "jvm-12" else "call=F0, inc=F1"
        else:
            if task_id in {"jvm-07", "jvm-10", "jvm-11", "jvm-15"}:
                self.workspace, selected, self.entry = _special(task_id)
            else:
                self.workspace, _, selected = _workspace_state(load_task(task(task_id).xax_task))
                self.entry = selected
            self.selected = [selected]
            self.session = LocalMutationSession.for_function(self.workspace, selected)
            if task_id == "jvm-15":
                target_aliases = dict(self.session.aliases)
                application = LocalMutationSession.for_function(self.workspace, self.entry)
                target_aliases.update({"A" + alias[1:]: raw for alias, raw in application.aliases.items()})
                self.session = LocalMutationSession(self.workspace, target_aliases)
                self.selected.append(self.entry)
                self.roles = "target=" + self.workspace._function_handles[selected] + ", assertion=" + self.workspace._function_handles[self.entry]
            elif task_id == "jvm-07":
                self.roles = "take=P0, x=P1, y=P2, selected=P3"
            elif task_id == "jvm-10":
                self.roles = "x=P0, k=N0, concurrent=N1, first=N2, result=N3"
            elif task_id == "jvm-11":
                self.roles = "x=P0, k=N0, zero=N1, dead=N2, result=N3"
            else:
                item = load_task(task(task_id).xax_task)
                roles = item.role_bindings or tuple((spec[0], f"N{i}") for i, spec in enumerate(item.initial))
                self.roles = ', '.join(f"{name}={handle}" for name, handle in roles)
                if item.fixture == "linear":
                    self.roles = "x=P0, " + self.roles
        if task_id in {"jvm-08", "jvm-09"}:
            self.candidate = "replace-operand N0 1 P2" if task_id == "jvm-08" else "replace-operand N2 0 N1"
            verification = self.workspace.verify(self.session.transaction(self.candidate))
            if verification.verified:
                raise AssertionError("repair candidate unexpectedly valid")
            self.candidate += "; diagnostic=" + verification.diagnostic.code
        # Exact target computed independently, through the same public verifier.
        reference = self._reference()
        self.expected = reference.root
        if self.binding:
            self.session.bind(*self.binding)

    def _reference(self):
        # Avoid recursively constructing a trial just to compute its target.
        if self.task_id == "jvm-10":
            ws, selected, _ = _special(self.task_id)
            session = LocalMutationSession.for_function(ws, selected)
            changed = session.commit("set-constant N1 10")
            if not changed.committed:
                raise AssertionError(changed.diagnostic)
            session = LocalMutationSession.for_function(ws, changed.changed_entity)
        else:
            ws = Workspace(self.workspace.reader)
            # Queries and aliases refer to the identical pre-edit store.
            for cid in self.workspace._function_handles:
                if (any(binding[0] == cid for binding in self.session.snapshot.node_bindings.values())
                        or any(binding[0] == cid for binding in self.session.snapshot.function_bindings.values()) or cid in self.selected):
                    LocalMutationSession.for_function(ws, cid)
            aliases = self.session.aliases
            session = LocalMutationSession(ws, aliases)
        result = session.commit(self.reference_command)
        if not result.committed:
            raise AssertionError(result.diagnostic)
        return result

    @property
    def reference_command(self):
        return {"jvm-07": "disconnect-edge N0 0 0 P1; connect-edge N0 0 0 P2",
                "jvm-10": "set-op N2 mul.wrap",
                "jvm-11": "delete N1; delete N2",
                "jvm-15": "set-op N1 mul.wrap; set-constant A2 30"}.get(self.task_id, task(self.task_id).xax_command)

    def prompt(self):
        intent = response_task(self.task_id).prompt
        if self.task_id == "jvm-06":
            self.prompt_entities = 1
            return (intent + "\nThe program is empty. Return only a JSON construction-tool request with keys parameters, returns, nodes, return. "
                    "parameters/returns are lists of integer bit widths. Each nodes record is [operation, result_width, operand...]; "
                    "constant records are [\"constant\", width, integer]. Operations use names such as add.wrap or mul.wrap. "
                    "P0.. index parameters, @0.. index prior node results; return is a list of value aliases. "
                    "The ordinary construct_program adapter builds and verifies canonical XAX state, and the host checks the result. No tools are needed.")
        instructions = self.session.bind(*self.binding) if self.binding else self.session.instructions()
        view = self.session.view(functions=tuple(self.selected), bound=bool(self.binding))
        self.prompt_entities = self.session.last_view_entities
        candidate = "\nRejected (not applied): " + self.candidate if self.candidate else ""
        race = "\nA concurrent update may invalidate the supplied snapshot; repair only after the host returns a fresh view." if self.task_id == "jvm-10" else ""
        scalar = self.binding and self.binding[0] in {"const", "op"}
        names = "\nNames: " + self.roles if self.roles and not scalar else ""
        response = "bound request" if self.binding else "edits"
        return (intent + "\nSnapshot:\n" + view + names + candidate + race +
                f"\nReturn only the {response}. No tools.\n" + instructions)

    def apply(self, response: str):
        self.mutations += 1
        if self.task_id == "jvm-06":
            request = json.loads(response)
            self.reader = construct_program(request)
            widths = set(request["parameters"] + request["returns"] + [node[1] for node in request["nodes"]])
            self.entities += 3 + len(widths) + len(request["parameters"]) + len(request["nodes"])
            self.entry = next(obj.cid for obj in self.reader.objects() if obj.kind == Kind.FUNCTION)
            return self.reader.root_cid == self.expected, "XAX.TEST.TARGET" if self.reader.root_cid != self.expected else ""
        if self.task_id == "jvm-10" and not self.concurrent_applied:
            result = self.session.commit("set-constant N1 10")
            if not result.committed:
                raise AssertionError(result.diagnostic)
            self.concurrent_applied = True
        result = self.session.commit_bound(response) if self.binding else self.session.commit(response)
        if not result.committed:
            self.verifier_failures += 1
            self.stale_failures += int(result.diagnostic.code == "XAX.WORKSPACE.STALE_ROOT")
            return False, json.dumps(self.session.diagnostic_view(result.diagnostic), separators=(',', ':'))
        self.reader = self.workspace.reader
        if self.reader.root_cid != self.expected:
            return False, "XAX.TEST.TARGET"
        # Locate the post-edit entry by its old handle only through the exact
        # target's changed graph: no source names enter the canonical store.
        if self.task_id in {"jvm-12", "jvm-14", "jvm-15"}:
            from xax_compiler import _decode_function_interface, store_resolver
            resolve = store_resolver(self.reader)
            if self.task_id == "jvm-15":
                self.entry = next(obj.cid for obj in self.reader.objects() if obj.kind == Kind.FUNCTION and
                    _decode_function_interface(obj, resolve)[1:] == ((), (bits_type(1).cid,)))
            elif self.task_id == "jvm-12":
                self.entry = next(obj.cid for obj in self.reader.objects() if obj.kind == Kind.FUNCTION and
                    _decode_function_interface(obj, resolve)[1:] == ((), (bits_type(16).cid,)) and obj.cid != self._helper_cid())
            else:
                self.entry = next(obj.cid for obj in self.reader.objects() if obj.kind == Kind.FUNCTION and
                    _decode_function_interface(obj, resolve)[1:] == ((), (bits_type(16).cid,)) and obj.cid != self._helper_cid())
        else:
            self.entry = result.changed_entity
        return True, ""

    def _helper_cid(self):
        graph = GraphBuilder()
        block = graph.block()
        block.ret(block.const(bits_type(16), 1))
        return graph.function((), (bits_type(16),)).cid

    def repair_prompt(self, diagnostic):
        # Prefer the established batch carrier after a rejected compact request.
        self.binding = None
        if self.task_id == "jvm-10":
            self.selected = [next(obj.cid for obj in self.workspace.reader.objects() if obj.kind == Kind.FUNCTION)]
        if self.workspace is not None:
            aliases = {}
            for index, cid in enumerate(self.selected):
                bound = LocalMutationSession.for_function(self.workspace, cid)
                aliases.update(bound.aliases if index == 0 else {"A" + key[1:]: raw for key, raw in bound.aliases.items()})
            # Preserve explicit cross-function/type roles when the root is unchanged.
            if self.workspace.generation == self.session.generation:
                aliases = self.session.aliases
            self.session = LocalMutationSession(self.workspace, aliases)
        return "Previous response rejected: " + diagnostic + ". Correct the request.\n" + self.prompt()

    def check_jvm(self):
        if self.task_id == "jvm-09":
            return True, "resource contract verified by exact semantic target"
        from xax_jvm import compile_jvm_bound_target, run_jvm_calls
        cases = {"jvm-01": (((2,), (-1,)), (63, 42), 32),
                 "jvm-02": (((6,),), (30,), 32), "jvm-03": (((3,),), (27,), 32),
                 "jvm-04": (((3,),), (7,), 32), "jvm-05": (((1,),), (12,), 32),
                 "jvm-06": (tuple((x,) for x in (0,1,-1,5,127,-128,2147483647,-2147483648,123456789)),
                            tuple((x+7) & 0xffffffff for x in (0,1,-1,5,127,-128,2147483647,-2147483648,123456789)), 32),
                 "jvm-07": (((1,4,9),(0,4,9)), (9,1), 32), "jvm-08": (((2,9,7,3),), (5,), 8),
                 "jvm-10": (((2,),), (20,), 32), "jvm-11": (((3,),), (7,), 32),
                 "jvm-12": (((),), (7,), 16), "jvm-13": (((2,),), (63,), 32),
                 "jvm-14": (((),), (7,), 16), "jvm-15": (((),), (1,), 1)}
        calls, expected, width = cases[self.task_id]
        calls = tuple(tuple(value & 0xffffffff if value < 0 else value for value in call) for call in calls)
        image = compile_jvm_bound_target(self.reader, self.entry, jvm_classfile_target())
        actual = run_jvm_calls(image, calls, result_width=width)
        return actual == expected, "JVM behavior differs" if actual != expected else ""


def unwrap_response(response):
    text = response.strip()
    if text.startswith("```") and text.endswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return text


def apply_patch_response(path: Path, response: str, original: str):
    """Apply a standard one-file unified diff, guarded by exact old lines.

    Supports ordinary diff output; no executable model text is evaluated.
    A missing/changed context line rejects the whole response.
    """
    if response.startswith("*** Begin Patch"):
        return _apply_context_patch(path, response, original)
    import re
    lines = response.splitlines(keepends=True)
    old = original.splitlines(keepends=True)
    result, cursor, index, hunks = [], 0, 0, 0
    while index < len(lines):
        line = lines[index]
        if line.startswith(("--- ", "+++ ")):
            name = line[4:].strip().split('\t')[0]
            if name not in {path.name, "a/" + path.name, "b/" + path.name}:
                raise ValueError("patch must target only the supplied program")
            index += 1
            continue
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?", line)
        if not match:
            raise ValueError("expected a one-file unified diff")
        start = int(match[1]) - 1
        if start < cursor or start > len(old):
            raise ValueError("invalid or overlapping patch range")
        result.extend(old[cursor:start])
        cursor = start
        before = after = 0
        index += 1
        while index < len(lines) and not lines[index].startswith("@@ "):
            change = lines[index]
            if change.startswith("\\ No newline at end of file"):
                index += 1
                continue
            if not change or change[0] not in " +-":
                raise ValueError("invalid patch line")
            content = change[1:]
            if change[0] in " -":
                if cursor >= len(old) or old[cursor].rstrip('\r\n') != content.rstrip('\r\n'):
                    raise ValueError("patch context differs from snapshot")
                cursor += 1
                before += 1
            if change[0] in " +":
                result.append(content if content.endswith('\n') else content + '\n')
                after += 1
            index += 1
        if before != int(match[2] or 1) or after != int(match[4] or 1):
            raise ValueError("patch hunk counts differ")
        hunks += 1
    if not hunks:
        raise ValueError("empty patch")
    result.extend(old[cursor:])
    path.write_text(''.join(result), encoding="utf-8", newline="\n")


def _apply_context_patch(path, response, original):
    """The ordinary apply_patch context format, without fragile line counts."""
    lines = response.splitlines()
    if len(lines) < 5 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch" or lines[1] != f"*** Update File: {path.name}":
        raise ValueError("expected one bounded apply_patch update")
    old = original.splitlines()
    result, cursor, index, hunks = [], 0, 2, 0
    while index < len(lines)-1:
        header = lines[index]
        if not header.startswith("@@"):
            raise ValueError("expected patch context hunk")
        if header == "@@" and index == len(lines)-2 and hunks:
            # A trailing section delimiter carries no mutation or precondition.
            index += 1
            break
        anchor = header[2:].strip()
        search_start = cursor
        if anchor:
            anchors = [i for i in range(cursor, len(old)) if old[i] == anchor]
            if len(anchors) != 1:
                raise ValueError("missing or ambiguous patch anchor")
            search_start = anchors[0] + 1
        index += 1
        before, after = [], []
        end_of_file = False
        while index < len(lines)-1 and not lines[index].startswith("@@"):
            line = lines[index]
            if line == "*** End of File":
                end_of_file = True
                index += 1
                break
            if not line or line[0] not in " +-":
                raise ValueError("invalid context-patch line")
            if line[0] in " -":
                before.append(line[1:])
            if line[0] in " +":
                after.append(line[1:])
            index += 1
        if not before:
            raise ValueError("patch requires existing context")
        matches = [i for i in range(search_start, len(old)-len(before)+1) if old[i:i+len(before)] == before and (not end_of_file or i+len(before) == len(old))]
        if len(matches) != 1:
            raise ValueError("missing or ambiguous patch context")
        start = matches[0]
        result.extend(old[cursor:start])
        result.extend(after)
        cursor = start + len(before)
        hunks += 1
    if not hunks:
        raise ValueError("empty patch")
    result.extend(old[cursor:])
    path.write_text('\n'.join(result) + '\n', encoding="utf-8", newline="\n")
