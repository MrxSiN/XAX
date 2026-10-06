"""Tiny manual C-vs-XAX benchmark for Codex Desktop."""

from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from statistics import median

from xax_compiler import (
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    ResourceFlags,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    constant,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    resource_type,
    verify_store,
    write_store,
)
from xax_workspace import (
    ConnectEdgeArgument,
    DeleteNode,
    DisconnectEdgeArgument,
    InsertPureNode,
    MovePureNode,
    ReplaceUse,
    RootRef,
    SetConstant,
    SetOperation,
    Transaction,
    TransactionValueRef,
    Workspace,
)

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"
RESULTS = HERE / "results.csv"
SESSIONS = Path.home() / ".codex" / "sessions"
FIELDS = (
    "task_id", "task_family", "arm", "trial", "model", "reasoning", "pass",
    "input_tokens", "output_tokens", "total_tokens", "turns", "elapsed_seconds",
    "failed_checks", "repair_count", "view_bytes", "packet_bytes", "semantic_entities", "final_root", "notes",
)
LEGACY_FIELDS = ("task_id", "arm", "pass", "input_tokens", "output_tokens", "total_tokens", "turns", "elapsed_seconds", "notes")
OPS = {"add.wrap": Operation.ADD_WRAP, "sub.wrap": Operation.SUB_WRAP, "mul.wrap": Operation.MUL_WRAP}
TRANSPORT = HERE / "transport-oi01.json"
CORPUS = HERE / "corpus-oi01.json"
# OI-01 fallback-transport candidates: handle namespace x packet framing. Non-source, non-canonical tooling.
TRANSPORT_VERSION = "X1"
HANDLES = ("typed", "unified")
FRAMINGS = ("line", "pipe", "json")
# long verb -> (short verb, field kinds: h=entity handle, v=value handle/temp, i=integer, o=operation)
SIGNATURES = {
    "set-constant": ("C", "hi"),
    "set-op": ("O", "ho"),
    "replace-operand": ("U", "hiv"),
    "delete": ("D", "h"),
    "move": ("M", "hh"),
    "insert-constant": ("I", "hii"),
    "disconnect-edge": ("X", "hiiv"),
    "connect-edge": ("Y", "hiiv"),
}
SHORT_VERBS = {short: long for long, (short, _kinds) in SIGNATURES.items()}
REFERENCE_EDITS = {
    "task-01": (("set-constant", "N0", "7"),),
    "task-02": (("set-op", "N1", "mul.wrap"),),
    "task-03": (("replace-operand", "N2", "1", "N1"),),
    "task-04": (("delete", "N1"),),
    "task-05": (("move", "N1", "before", "N0"),),
    "task-06": (("insert-constant", "N1", "0", "7"), ("replace-operand", "N2", "1", "@0")),
    "task-07": (("disconnect-edge", "N0", "0", "0", "P0"), ("connect-edge", "N0", "0", "0", "P1")),
    "task-08": (("replace-operand", "N0", "1", "P3"),),
    "task-09": (("replace-operand", "N2", "0", "N1"), ("replace-operand", "N3", "0", "N0")),
    "task-10": (("set-op", "N2", "mul.wrap"),),
    "task-11": (("delete", "N1"),),
}
GRAMMAR = {
    "line": "Edit `packet.txt`: keep the `X1 R0.<generation>` header, then write one mutation per line: `set-constant H VALUE`, "
            "`set-op H OP`, `replace-operand H INDEX V`, `delete H`, `move H before H`, `insert-constant H ID VALUE`, "
            "`disconnect-edge H EDGE ARG V`, `connect-edge H EDGE ARG V`.",
    "pipe": "Edit `packet.txt`: keep `X1|R0.<generation>`, then append `;`-separated mutations: `C|H|VALUE`, `O|H|OP`, "
            "`U|H|INDEX|V`, `D|H`, `M|H|H`, `I|H|ID|VALUE`, `X|H|EDGE|ARG|V`, `Y|H|EDGE|ARG|V`.",
    "json": "Edit `packet.txt`: keep `[\"X1\",\"R0.<generation>\"]` and append mutation arrays: `[\"C\",H,VALUE]`, "
            "`[\"O\",H,OP]`, `[\"U\",H,INDEX,V]`, `[\"D\",H]`, `[\"M\",H,H]`, `[\"I\",H,ID,VALUE]`, "
            "`[\"X\",H,EDGE,ARG,V]`, `[\"Y\",H,EDGE,ARG,V]`; integer fields are JSON integers.",
}
HANDLE_NOTES = {
    "typed": "`H`/`V` is a handle exactly as printed by `inspect` (a JSON string in JSON packets); `@ID` is a transaction-local inserted value.",
    "unified": "`H`/`V` is an integer handle exactly as printed by `inspect` (a JSON integer in JSON packets); `@ID` is a transaction-local inserted value.",
}


@dataclass(frozen=True)
class Task:
    task_id: str
    prompt: str
    c_initial: str
    c_target: str
    initial: tuple[tuple[str, str, tuple[str, ...], int | None], ...]
    target: tuple[tuple[str, str, tuple[str, ...], int | None], ...]
    result: str
    family: str = "local-edit"
    fixture: str = "linear"
    semantic_entities: int | None = None
    prefill: tuple[tuple[str, ...], ...] = ()
    prefill_root: str = "R0.0"
    reference_root: str = "R0.0"


def _c(body: str) -> str:
    return f"#include <stdint.h>\n\nuint32_t f(uint32_t x) {{\n{body}}}\n"


def tasks() -> tuple[Task, ...]:
    const = lambda name, value: (name, "const", (), value)
    op = lambda name, operation, *args: (name, operation, args, None)
    return (
        Task(
            "task-01",
            "In f, change the shared constant k from 3 to 7; both uses must change. Change nothing else.",
            _c("    const uint32_t k = 3;\n    return (x + k) * k;\n"),
            _c("    const uint32_t k = 7;\n    return (x + k) * k;\n"),
            (const("k", 3), op("a", "add.wrap", "x", "k"), op("r", "mul.wrap", "a", "k")),
            (const("k", 7), op("a", "add.wrap", "x", "k"), op("r", "mul.wrap", "a", "k")),
            "r",
        ),
        Task(
            "task-02",
            "In f, change the operation from wrapping addition to wrapping multiplication. Keep its operands and change nothing else.",
            _c("    const uint32_t k = 5;\n    return x + k;\n"),
            _c("    const uint32_t k = 5;\n    return x * k;\n"),
            (const("k", 5), op("r", "add.wrap", "x", "k")),
            (const("k", 5), op("r", "mul.wrap", "x", "k")),
            "r",
        ),
        Task(
            "task-03",
            "In f, change only r's second operand from a to b. Change nothing else.",
            _c("    const uint32_t a = 2;\n    const uint32_t b = 9;\n    const uint32_t r = x * a;\n    return r;\n"),
            _c("    const uint32_t a = 2;\n    const uint32_t b = 9;\n    const uint32_t r = x * b;\n    return r;\n"),
            (const("a", 2), const("b", 9), op("r", "mul.wrap", "x", "a")),
            (const("a", 2), const("b", 9), op("r", "mul.wrap", "x", "b")),
            "r",
        ),
        Task(
            "task-04",
            "In f, delete the unused constant dead. Change nothing else.",
            _c("    const uint32_t k = 4;\n    const uint32_t dead = 21;\n    return x + k;\n"),
            _c("    const uint32_t k = 4;\n    return x + k;\n"),
            (const("k", 4), const("dead", 21), op("r", "add.wrap", "x", "k")),
            (const("k", 4), op("r", "add.wrap", "x", "k")),
            "r",
        ),
        Task(
            "task-05",
            "In f, move the constant b immediately before a. Change nothing else.",
            _c("    const uint32_t a = 2;\n    const uint32_t b = 9;\n    return x + a + b;\n"),
            _c("    const uint32_t b = 9;\n    const uint32_t a = 2;\n    return x + a + b;\n"),
            (const("a", 2), const("b", 9), op("s", "add.wrap", "x", "a"), op("r", "add.wrap", "s", "b")),
            (const("b", 9), const("a", 2), op("s", "add.wrap", "x", "a"), op("r", "add.wrap", "s", "b")),
            "r",
        ),
    )


def oi01_tasks() -> tuple[Task, ...]:
    """OI-01 corpus: the five baseline edits plus only the missing task families."""
    empty_specs: tuple[tuple[str, str, tuple[str, ...], int | None], ...] = ()
    return tasks() + (
        Task(
            "task-06",
            "Complete the supplied semantic scaffold so f uses a newly created constant 7 as the second operand of its add. Keep the placeholder and anchor nodes unchanged.",
            "", "", empty_specs, empty_specs, "",
            family="creation", fixture="creation", semantic_entities=4,
        ),
        Task(
            "task-07",
            "Change only B0's branch argument from P0 to P1. Preserve the branch target, block parameter, and all other semantics.",
            "", "", empty_specs, empty_specs, "",
            family="control-flow", fixture="control", semantic_entities=4,
        ),
        Task(
            "task-08",
            "The supplied candidate tries to change N0's second operand but fails type verification. Repair it so the second operand becomes P3 and change nothing else.",
            "", "", empty_specs, empty_specs, "",
            family="type-repair", fixture="type-repair", semantic_entities=5,
            prefill=(("replace-operand", "N0", "1", "P2"),),
        ),
        Task(
            "task-09",
            "Swap the two resource values consumed by N2 and N3. The supplied candidate performs only the first half and violates linear resource use; repair it without changing the effect chain.",
            "", "", empty_specs, empty_specs, "",
            family="resource-effect-repair", fixture="resource-repair", semantic_entities=5,
            prefill=(("replace-operand", "N2", "0", "N1"),),
        ),
        Task(
            "task-10",
            "The packet targets a stale root. Refresh the local semantic view and retry the same requested change: change N2 from wrapping addition to wrapping multiplication while preserving the concurrent constant update.",
            "", "", empty_specs, empty_specs, "",
            family="stale-root", fixture="stale-root", semantic_entities=4,
            prefill=(("set-op", "N2", "mul.wrap"),), prefill_root="R0.0", reference_root="R0.1",
        ),
        Task(
            "task-11",
            "Optimize f for the fewest semantic nodes without changing its result. N1 is dead; remove it and change nothing else.",
            "", "", empty_specs, empty_specs, "",
            family="optimization", fixture="optimization", semantic_entities=4,
        ),
    )


def load_task(task_id: str) -> Task:
    try:
        return next(task for task in oi01_tasks() if task.task_id == task_id)
    except StopIteration:
        raise ValueError(f"unknown task: {task_id}") from None


def _build(specs, result: str) -> tuple[StoreReader, bytes]:
    u32 = bits_type(32)
    values = {"x": ValueRef.parameter(0, 0)}
    nodes, objects = [], {u32.cid: u32}
    for index, (name, op, operands, value) in enumerate(specs):
        entity = None
        if op == "const":
            entity = constant(u32, value)
            objects[entity.cid] = entity
            operation = Operation.CONSTANT
        else:
            operation = OPS[op]
        nodes.append(Node(operation, tuple(values[item] for item in operands), (u32,), entity=entity))
        values[name] = ValueRef.node_result(0, index, 0)
    graph = graph_fragment((Block((u32,), tuple(nodes), Terminator.return_((values[result],))),))
    fn = function(graph, (u32,), (u32,))
    module = object_with_refs(Kind.MODULE, (fn,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects.update((obj.cid, obj) for obj in (graph, fn, module, root))
    reader = StoreReader(write_store(root.cid, objects.values()))
    verify_store(reader)
    return reader, fn.cid


def _build_fixture(task: Task) -> tuple[StoreReader, bytes]:
    if task.fixture == "linear":
        return _build(task.initial, task.result)
    if task.fixture == "creation":
        u32 = bits_type(32)
        zero, anchor = constant(u32, 0), constant(u32, 1)
        graph = graph_fragment((Block(
            (u32,),
            (
                Node(Operation.CONSTANT, (), (u32,), entity=zero),
                Node(Operation.CONSTANT, (), (u32,), entity=anchor),
                Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (u32,)),
            ),
            Terminator.return_((ValueRef.node_result(0, 2),)),
        ),))
        objects = (u32, zero, anchor, graph)
    elif task.fixture == "control":
        b8 = bits_type(8)
        one = constant(b8, 1)
        graph = graph_fragment((
            Block((b8, b8), (Node(Operation.CONSTANT, (), (b8,), entity=one),), Terminator.branch(1, (ValueRef.parameter(0, 0),))),
            Block((b8,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
        ))
        objects = (b8, one, graph)
    elif task.fixture == "type-repair":
        b8, b16 = bits_type(8), bits_type(16)
        graph = graph_fragment((Block(
            (b8, b8, b16, b8),
            (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
            Terminator.return_((ValueRef.node_result(0, 0),)),
        ),))
        objects = (b8, b16, graph)
    elif task.fixture == "resource-repair":
        effect = effect_type(EffectDomain.FILESYSTEM, 4)
        resource = resource_type(2, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE)
        graph = graph_fragment((Block(
            (effect,),
            (
                Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 0),), (resource, effect)),
                Node(Operation.RESOURCE_ACQUIRE, (ValueRef.node_result(0, 0, 1),), (resource, effect)),
                Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 1)), (effect,)),
                Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 2, 0)), (effect,)),
            ),
            Terminator.return_((ValueRef.node_result(0, 3, 0),)),
        ),))
        objects = (effect, resource, graph)
    elif task.fixture in {"stale-root", "optimization"}:
        u32 = bits_type(32)
        first_value, dead_value = ((5, 9) if task.fixture == "stale-root" else (4, 21))
        first, dead = constant(u32, first_value), constant(u32, dead_value)
        graph = graph_fragment((Block(
            (u32,),
            (
                Node(Operation.CONSTANT, (), (u32,), entity=first),
                Node(Operation.CONSTANT, (), (u32,), entity=dead),
                Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (u32,)),
            ),
            Terminator.return_((ValueRef.node_result(0, 2),)),
        ),))
        objects = (u32, first, dead, graph)
    else:
        raise ValueError(f"unknown task fixture: {task.fixture}")
    if task.fixture == "control":
        parameters, returns = (objects[0], objects[0]), (objects[0],)
    elif task.fixture == "type-repair":
        parameters, returns = (objects[0], objects[0], objects[1], objects[0]), (objects[0],)
    elif task.fixture == "resource-repair":
        parameters, returns = (objects[0],), (objects[0],)
    else:
        parameters, returns = (objects[0],), (objects[0],)
    fn = function(graph, parameters, returns)
    module = object_with_refs(Kind.MODULE, (fn,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    all_objects = (*objects, fn, module, root)
    reader = StoreReader(write_store(root.cid, all_objects))
    verify_store(reader)
    return reader, fn.cid


def _short_handle(handle: str) -> str:
    return re.sub(r"^F\d+\.B\d+\.", "", handle).removesuffix(".R0")


def _workspace_state(task: Task) -> tuple[Workspace, str, bytes]:
    reader, function_cid = _build_fixture(task)
    workspace = Workspace(reader)
    generation = 0
    if task.fixture == "stale-root":
        nodes = workspace.function_nodes(function_cid, 8).entities
        concurrent = workspace.commit(Transaction(RootRef(0), (SetConstant(nodes[1].handle, 9, 10),)))
        if not concurrent.committed:
            raise AssertionError(concurrent.diagnostic)
        function_cid = concurrent.changed_entity
        generation = 1
    if task.fixture != "linear":
        for node in workspace.function_nodes(function_cid, 64).entities:
            workspace.neighborhood(node.handle, 64)
        return workspace, _custom_view(task, generation), function_cid
    lines = ["R0 f(P0:u32)->u32"]
    for node in workspace.function_nodes(function_cid, 32).entities:
        related = workspace.neighborhood(node.handle, 32).entities
        inputs = [_short_handle(item.handle) for item in related if "operand" in item.relations]
        op = node.operation.name.lower().replace("_", ".")
        if op == "constant":
            op = f"const {node.constant_value}"
        lines.append(f"{_short_handle(node.handle)} {op} {' '.join(inputs)}".rstrip())
    result = next(index for index, spec in enumerate(task.initial) if spec[0] == task.result)
    lines.append(f"return N{result}")
    return workspace, "\n".join(lines) + "\n", function_cid


def _workspace(task: Task) -> tuple[Workspace, str]:
    workspace, view, _function_cid = _workspace_state(task)
    return workspace, view


def _custom_view(task: Task, generation: int) -> str:
    root = f"R0.{generation}"
    if task.fixture == "creation":
        return f"{root} f(P0:u32)->u32\nN0 const 0\nN1 const 1\nN2 add.wrap P0 N0\nreturn N2\n"
    if task.fixture == "control":
        return f"{root} f(P0:u8,P1:u8)->u8\nB0 N0 const 1\nB0 branch B1(P0)\nB1(P2:u8) return P2\n"
    if task.fixture == "type-repair":
        return f"{root} f(P0:u8,P1:u8,P2:u16,P3:u8)->u8\nN0 add.wrap P0 P1\nreturn N0\n"
    if task.fixture == "resource-repair":
        return (
            f"{root} f(P0:effect.filesystem)->effect.filesystem\n"
            "N0 acquire P0 -> resource+effect\nN1 acquire effect(N0) -> resource+effect\n"
            "N2 release N0 effect(N1) -> effect\nN3 release N1 effect(N2) -> effect\nreturn effect(N3)\n"
        )
    if task.fixture == "stale-root":
        return f"{root} f(P0:u32)->u32\nN0 const 5\nN1 const 10\nN2 add.wrap P0 N0\nreturn N2\n"
    if task.fixture == "optimization":
        return f"{root} f(P0:u32)->u32\nN0 const 4\nN1 const 21\nN2 add.wrap P0 N0\nreturn N2\n"
    raise ValueError(f"unknown task fixture: {task.fixture}")


def _variant(arm: str) -> tuple[str, str] | None:
    match = re.fullmatch(r"XAX-(TYPED|UNIFIED)-(LINE|PIPE|JSON)", arm.upper())
    return (match.group(1).lower(), match.group(2).lower()) if match else None


def _arm(arm: str) -> str:
    arm = arm.upper()
    if arm in {"C", "XAX", "XAX-DIRECT"} or _variant(arm):
        return arm
    raise ValueError("arm must be C, XAX, XAX-DIRECT, or XAX-<TYPED|UNIFIED>-<LINE|PIPE|JSON>")


def _handle_order(task: Task | None) -> tuple[str, ...]:
    if task is None or task.fixture == "linear":
        count = 1 if task is None else len(task.initial)
        return ("P0", *(f"N{index}" for index in range(count)))
    return {
        "creation": ("P0", "N0", "N1", "N2"),
        "control": ("P0", "P1", "P2", "N0"),
        "type-repair": ("P0", "P1", "P2", "P3", "N0"),
        "resource-repair": ("P0", "N0", "N1", "N2", "N3"),
        "stale-root": ("P0", "N0", "N1", "N2"),
        "optimization": ("P0", "N0", "N1", "N2"),
    }[task.fixture]


def _to_model(handle: str, handles: str, task: Task | None = None) -> str:
    if handles == "typed":
        if handle not in _handle_order(task):
            raise ValueError(f"bad typed handle: {handle}")
        return handle
    try:
        return str(_handle_order(task).index(handle))
    except ValueError:
        raise ValueError(f"bad unified handle: {handle}") from None


def _from_model(field: str, handles: str, task: Task) -> str:
    order = _handle_order(task)
    if handles == "typed" and field in order:
        return field
    if handles == "unified" and re.fullmatch(r"0|[1-9]\d*", field):
        index = int(field)
        if index < len(order):
            return order[index]
    raise ValueError(f"bad {handles} handle: {field}")


def _rename(text: str, handles: str, task: Task | None = None) -> str:
    if handles == "typed":
        return text
    mapping = {handle: str(index) for index, handle in enumerate(_handle_order(task))}
    pattern = r"(?<![A-Za-z0-9_.])(?:" + "|".join(map(re.escape, sorted(mapping, key=len, reverse=True))) + r")(?![A-Za-z0-9_.])"
    return re.sub(pattern, lambda match: mapping[match.group(0)], text)


def encode_packet(framing: str, handles: str, edits, root: str = "R0.0", *, task: Task | None = None) -> str:
    records = []
    for long, *fields in edits:
        if long == "move":
            fields = [fields[0], fields[2]]
        short, kinds = SIGNATURES[long]
        values = []
        for kind, field in zip(kinds, fields):
            if kind == "h" or (kind == "v" and not field.startswith("@")):
                field = _to_model(field, handles, task)
            values.append(field)
        if framing == "line":
            records.append(" ".join([long, values[0], "before", values[1]] if long == "move" else [long, *values]))
        elif framing == "pipe":
            records.append("|".join([short, *values]))
        else:
            encoded = []
            for kind, value in zip(kinds, values):
                if kind == "i" or (handles == "unified" and kind in {"h", "v"} and not value.startswith("@")):
                    value = int(value)
                encoded.append(value)
            records.append([short, *encoded])
    if framing == "line":
        return f"{TRANSPORT_VERSION} {root}\n" + "".join(record + "\n" for record in records)
    if framing == "pipe":
        return ";".join([f"{TRANSPORT_VERSION}|{root}", *records])
    return json.dumps([TRANSPORT_VERSION, root, *records], separators=(",", ":"))


def decode_packet(task: Task, framing: str, handles: str, text: str) -> Transaction:
    if framing == "line":
        records = [line.split() for line in text.splitlines() if line.strip()]
    elif framing == "pipe":
        records = [[field.strip() for field in record.split("|")] for record in text.split(";") if record.strip()]
    elif framing == "json":
        data = json.loads(text)
        if not isinstance(data, list) or len(data) < 2 or not all(isinstance(item, list) and item for item in data[2:]):
            raise ValueError("packet must be [version, root, [mutation]...]")
        records = [data[:2], *data[2:]]
    else:
        raise ValueError(f"unknown framing: {framing}")
    header = records[0] if records else []
    if len(header) != 2 or header[0] != TRANSPORT_VERSION or not isinstance(header[1], str) or not re.fullmatch(r"R0\.(?:0|[1-9]\d*)", header[1]):
        raise ValueError(f"header must be {TRANSPORT_VERSION} R0.<generation>")
    if len(records) < 2:
        raise ValueError("packet has no mutation")
    mutations = []
    for verb, *fields in records[1:]:
        if framing == "line":
            long = verb if verb in SIGNATURES else None
            if long == "move":
                if len(fields) != 3 or fields[1] != "before":
                    raise ValueError("move H before H")
                fields = [fields[0], fields[2]]
        else:
            long = SHORT_VERBS.get(verb) if isinstance(verb, str) else None
        if long is None or len(fields) != len(SIGNATURES[long][1]):
            raise ValueError(f"bad mutation: {[verb, *fields]}")
        parts = [long]
        for kind, field in zip(SIGNATURES[long][1], fields):
            if framing == "json":
                integer_handle = handles == "unified" and kind in {"h", "v"} and not (isinstance(field, str) and field.startswith("@"))
                expected = int if kind == "i" or integer_handle else str
                if type(field) is not expected:
                    raise ValueError(f"bad field: {field!r}")
                field = str(field)
            if kind == "h" or (kind == "v" and not field.startswith("@")):
                field = _from_model(field, handles, task)
            elif kind == "v" and not re.fullmatch(r"@(?:0|[1-9]\d*)", field):
                raise ValueError(f"bad value: {field}")
            elif kind == "i" and not re.fullmatch(r"0|-?[1-9]\d*", field):
                raise ValueError(f"bad integer: {field}")
            parts.append(field)
        if long == "move":
            parts.insert(2, "before")
        mutations.append(_transport_mutation(task, parts))
    return Transaction(RootRef(int(header[1].rsplit(".", 1)[1])), tuple(mutations))


def _load_transaction(task: Task, arm: str, workspace_path: Path) -> Transaction:
    variant = _variant(arm)
    if variant is None:
        if arm == "XAX-DIRECT" and task.fixture != "linear":
            return _direct_transaction(task, (workspace_path / "direct.txt").read_text(encoding="utf-8"))
        return _transaction((workspace_path / "transaction.txt").read_text(encoding="utf-8"))
    return decode_packet(task, variant[1], variant[0], (workspace_path / "packet.txt").read_text(encoding="utf-8"))


def _direct_transaction(task: Task, text: str) -> Transaction:
    commands = [shlex.split(command.strip()) for command in text.split(";") if command.strip()]
    if not commands:
        raise ValueError("one or more semicolon-separated mutations required")
    generation = int(task.reference_root.rsplit(".", 1)[1])
    return Transaction(RootRef(generation), tuple(_transport_mutation(task, command) for command in commands))


def _trial_script(task_id: str, arm: str) -> str:
    compiler = HERE.parents[1]
    return (
        "import sys\nfrom pathlib import Path\n"
        f"sys.path[:0] = [{str(compiler / 'src')!r}, {str(compiler)!r}]\n"
        "from benchmarks.ai_native import trial_main\n"
        f"raise SystemExit(trial_main({task_id!r}, Path(__file__).parent, sys.argv[1:], {arm!r}))\n"
    )


def _c_trial_script(task_id: str) -> str:
    compiler = HERE.parents[1]
    return (
        "import sys\nfrom pathlib import Path\n"
        f"sys.path[:0] = [{str(compiler / 'src')!r}, {str(compiler)!r}]\n"
        "from benchmarks.ai_native import check\n"
        f"passed, reason = check({task_id!r}, 'C', Path(__file__).parent)\n"
        "print('PASS' if passed else f'FAIL {reason}')\n"
        "raise SystemExit(0 if passed else 1)\n"
    )


def prepare(task_id: str, arm: str, output: Path | None = None) -> Path:
    task, arm = load_task(task_id), _arm(arm)
    variant = _variant(arm)
    if task.fixture != "linear" and variant is None and arm != "XAX-DIRECT":
        raise ValueError("OI-01 extension tasks are transport-candidate trials only")
    output = output or RUNS / f"{task_id}-{arm.lower()}"
    output.mkdir(parents=True, exist_ok=False)
    editable = "program.c" if arm == "C" else "packet.txt" if variant else "transaction.txt"
    (output / "TASK.md").write_text(
        f"# {task_id} / {arm}\n\nPaste this exact prompt into Codex Desktop:\n\n> {task.prompt}\n\n"
        f"Codex should edit `{editable}`. Afterward, run from `compiler/`:\n\n"
        f"`$env:PYTHONPATH='src'; python -m benchmarks.ai_native check {task_id} {arm} {output}`\n",
        encoding="utf-8",
    )
    if arm == "C":
        (output / "program.c").write_text(task.c_initial, encoding="utf-8")
        (output / "c.py").write_text(_c_trial_script(task_id), encoding="utf-8")
        (output / "TASK.md").write_text(
            f"# {task_id} / C\n\nPaste this exact prompt into Codex Desktop:\n\n> {task.prompt}\n>\n"
            "> Inspect and edit only `program.c`, then run `python c.py`. Stop when it prints `PASS`.\n",
            encoding="utf-8",
        )
    elif variant:
        handles, framing = variant
        (output / "xax.py").write_text(_trial_script(task_id, arm), encoding="utf-8")
        (output / "packet.txt").write_text(
            encode_packet(framing, handles, task.prefill, root=task.prefill_root, task=task), encoding="utf-8"
        )
        (output / "TASK.md").write_text(
            f"# {task_id} / {arm}\n\nPaste this exact prompt into Codex Desktop:\n\n> {task.prompt}\n>\n"
            f"> Use `python xax.py inspect`, edit `packet.txt`, then `python xax.py test`. {GRAMMAR[framing]} {HANDLE_NOTES[handles]}\n",
            encoding="utf-8",
        )
    else:
        (output / "xax.py").write_text(_trial_script(task_id, arm), encoding="utf-8")
        (output / "transaction.txt").write_text("TX R0.0\n# Add one mutation.\n", encoding="utf-8")
        direct = arm == "XAX-DIRECT"
        if direct and task.fixture != "linear":
            (output / "direct.txt").write_text("", encoding="utf-8")
        workflow = (
            "> Complete local view: `"
            + _workspace(task)[1].strip().replace("\n", "; ")
            + "`.\n> Run one `python xax.py apply CMD` command (no function argument); it verifies and tests.\n"
            if direct else
            "> Use `python xax.py inspect`, one `python xax.py mutate ...`, then `python xax.py test`.\n"
        )
        commands = (
            "`set-constant N V` | `set-op N OP` | `replace-operand N I V` | `delete N` | `move N before N`"
            if task.fixture == "linear" else
            "`insert-constant N ID V` | `replace-operand N I V` | `disconnect-edge N EDGE ARG V` | "
            "`connect-edge N EDGE ARG V` | `set-op N OP` | `delete N`; N is a node anchor in the containing block, "
            "EDGE and ARG are zero-based indices; separate multiple mutations with `;`"
        )
        (output / "TASK.md").write_text(
            f"# {task_id} / {arm}\n\nPaste this exact prompt into Codex Desktop:\n\n> {task.prompt}\n>\n"
            + workflow
            + f"> `CMD`: {commands}. Quote a multi-mutation `CMD` as one shell argument. Stop after `PASS`.\n",
            encoding="utf-8",
        )
    return output


def _node_index(text: str, count: int) -> int:
    match = re.fullmatch(r"N?(\d+)", text)
    if not match or int(match.group(1)) >= count:
        raise ValueError(f"node 0..{count - 1}")
    return int(match.group(1))


def _short_value(text: str, count: int) -> str:
    # ponytail: benchmark corpus has one parameter/result; extend only when the corpus does.
    if text == "P0":
        return "F0.B0.P0"
    return f"F0.B0.N{_node_index(text, count)}.R0"


def _transport_node(task: Task, short: str):
    if not re.fullmatch(r"N\d+", short):
        raise ValueError(f"node handle required: {short}")
    workspace, _view, function_cid = _workspace_state(task)
    nodes = workspace.function_nodes(function_cid, 64).entities
    index = int(short[1:])
    if index >= len(nodes):
        raise ValueError(f"node 0..{len(nodes) - 1}")
    return workspace, nodes[index]


def _transport_value(task: Task, short: str) -> ValueRef | TransactionValueRef:
    if re.fullmatch(r"@(?:0|[1-9]\d*)", short):
        return TransactionValueRef(int(short[1:]))
    if re.fullmatch(r"P\d+", short):
        index = int(short[1:])
        if task.fixture == "control" and index == 2:
            return ValueRef.parameter(1, 0)
        entry_parameter_counts = {
            "linear": 1, "creation": 1, "control": 2, "type-repair": 4,
            "resource-repair": 1, "stale-root": 1, "optimization": 1,
        }
        count = entry_parameter_counts[task.fixture]
        if index >= count:
            raise ValueError(f"parameter 0..{count - 1}")
        return ValueRef.parameter(0, index)
    workspace, node = _transport_node(task, short)
    block, index = _position(node.handle)
    return ValueRef.node_result(block, index, 0)


def _transport_mutation(task: Task, parts: list[str]):
    command = parts[0]
    if command == "set-constant" and len(parts) == 3:
        _workspace_, node = _transport_node(task, parts[1])
        if node.operation != Operation.CONSTANT:
            raise ValueError("constant node")
        return SetConstant(node.handle, node.constant_value, int(parts[2]))
    if command == "set-op" and len(parts) == 3:
        _workspace_, node = _transport_node(task, parts[1])
        if node.operation not in OPS.values() or parts[2] not in OPS:
            raise ValueError("arithmetic node and supported op")
        return SetOperation(node.handle, node.operation, OPS[parts[2]])
    if command == "replace-operand" and len(parts) == 4:
        workspace, node = _transport_node(task, parts[1])
        operand = int(parts[2])
        operands = workspace.operands(node.handle, 64).entities
        if operand < 0 or operand >= len(operands):
            raise ValueError(f"operand 0..{len(operands) - 1}")
        return ReplaceUse(node.handle, operand, _value(operands[operand].handle), _transport_value(task, parts[3]))
    if command == "delete" and len(parts) == 2:
        _workspace_, node = _transport_node(task, parts[1])
        block, index = _position(node.handle)
        return DeleteNode(node.handle, block, index)
    if command == "move" and len(parts) == 4 and parts[2] == "before":
        _workspace_, node = _transport_node(task, parts[1])
        _workspace_, destination = _transport_node(task, parts[3])
        block, index = _position(node.handle)
        destination_block, destination_index = _position(destination.handle)
        return MovePureNode(node.handle, block, index, destination.handle, destination_block, destination_index)
    if command == "insert-constant" and len(parts) == 4:
        workspace, anchor = _transport_node(task, parts[1])
        block, index = _position(anchor.handle)
        local_id = int(parts[2])
        if local_id < 0:
            raise ValueError("local id must be nonnegative")
        type_handle = next(item.type_handle for item in workspace.neighborhood(anchor.handle, 8).entities if "result" in item.relations)
        return InsertPureNode(anchor.handle, block, index, local_id, Operation.CONSTANT, (), type_handle, int(parts[3]))
    if command in {"disconnect-edge", "connect-edge"} and len(parts) == 5:
        _workspace_, anchor = _transport_node(task, parts[1])
        block, _index = _position(anchor.handle)
        edge, argument = int(parts[2]), int(parts[3])
        if edge < 0 or argument < 0:
            raise ValueError("edge and argument indices must be nonnegative")
        value = _transport_value(task, parts[4])
        if isinstance(value, TransactionValueRef) and command == "disconnect-edge":
            raise ValueError("disconnect expected value cannot be transaction-local")
        if command == "disconnect-edge":
            return DisconnectEdgeArgument(anchor.handle, block, edge, argument, value)
        return ConnectEdgeArgument(anchor.handle, block, edge, argument, value)
    raise ValueError("unsupported transport mutation")


def _mutation_line(task: Task, parts: list[str]) -> str:
    specs = task.initial
    names = {name: f"F0.B0.N{index}.R0" for index, (name, *_rest) in enumerate(specs)}
    names["x"] = "F0.B0.P0"
    if len(parts) == 3 and parts[0] == "set-constant":
        index = _node_index(parts[1], len(specs))
        if specs[index][1] != "const":
            raise ValueError("constant node")
        return f"C F0.B0.N{index} {specs[index][3]} {int(parts[2])}"
    if len(parts) == 3 and parts[0] == "set-op":
        index = _node_index(parts[1], len(specs))
        if specs[index][1] not in OPS or parts[2] not in OPS:
            raise ValueError("arithmetic node and supported op")
        return f"O F0.B0.N{index} {specs[index][1]} {parts[2]}"
    if len(parts) == 4 and parts[0] == "replace-operand":
        index = _node_index(parts[1], len(specs))
        operand = int(parts[2])
        operands = specs[index][2]
        if operand < 0 or operand >= len(operands):
            raise ValueError(f"operand 0..{len(operands) - 1}")
        return f"U F0.B0.N{index} {operand} {names[operands[operand]]} {_short_value(parts[3], len(specs))}"
    if len(parts) == 2 and parts[0] == "delete":
        index = _node_index(parts[1], len(specs))
        return f"D F0.B0.N{index}"
    if len(parts) == 4 and parts[0] == "move" and parts[2] == "before":
        source = _node_index(parts[1], len(specs))
        destination = _node_index(parts[3], len(specs))
        return f"M F0.B0.N{source} BEFORE F0.B0.N{destination}"
    raise ValueError("set-constant|set-op|replace-operand|delete|move")


def _local_diagnostic_value(task: Task, value):
    if task.fixture == "linear":
        return value
    type_names = {}
    if task.fixture == "type-repair":
        type_names = {bits_type(8).cid.hex(): "u8", bits_type(16).cid.hex(): "u16"}
    if isinstance(value, str):
        if value in type_names:
            return type_names[value]
        if re.fullmatch(r"[0-9a-f]{64}", value):
            return "local-cid"
        return value
    if isinstance(value, (list, tuple)):
        return [_local_diagnostic_value(task, item) for item in value]
    return value


def _print_diagnostic(diagnostic, handles: str = "typed", task: Task | None = None) -> None:
    task = task or load_task("task-01")
    entity = _short_handle(diagnostic.entity)
    if task.fixture != "linear" and re.fullmatch(r"[0-9a-f]{64}", entity):
        entity = "f"
    print(json.dumps([
        diagnostic.code,
        _rename(entity, handles, task),
        _local_diagnostic_value(task, diagnostic.expected),
        _local_diagnostic_value(task, diagnostic.actual),
        [_rename(_short_handle(item), handles, task) for item in diagnostic.repair_neighborhood],
    ], separators=(",", ":")))


def trial_main(task_id: str, workspace_path: Path, argv: list[str] | None = None, arm: str = "XAX") -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    code = _trial(task_id, workspace_path, argv, arm)
    if _variant(arm):
        # Objective per-invocation trace for invalid-packet and repair-round counts.
        packet = workspace_path / "packet.txt"
        entry = {"argv": argv, "exit": code, "packet": packet.read_text(encoding="utf-8") if packet.exists() else None}
        with (workspace_path / "trace.jsonl").open("a", encoding="utf-8") as file:
            file.write(json.dumps(entry, separators=(",", ":")) + "\n")
    return code


def _expected_root(task: Task) -> bytes:
    if task.fixture == "linear":
        return _build(task.target, task.result)[0].root_cid
    workspace, _view, _function_cid = _workspace_state(task)
    packet = encode_packet("line", "typed", REFERENCE_EDITS[task.task_id], root=task.reference_root, task=task)
    result = workspace.commit(decode_packet(task, "line", "typed", packet))
    if not result.committed:
        raise AssertionError((task.task_id, result.diagnostic))
    return result.root


def _trial(task_id: str, workspace_path: Path, argv: list[str], arm: str) -> int:
    task, args = load_task(task_id), list(argv)
    command = args.pop(0) if args else ""
    variant = _variant(arm)
    handles = variant[0] if variant else "typed"
    try:
        if command in {"query", "inspect"} and (not args or args == ["f"]):
            print(_rename(_workspace(task)[1], handles, task), end="")
            return 0
        if command in {"mutate", "apply"} and not variant:
            if command == "apply" and len(args) == 1:
                if task.fixture != "linear":
                    (workspace_path / "direct.txt").write_text(args[0], encoding="utf-8")
                    args = []
                else:
                    args = shlex.split(args[0])
            if task.fixture == "linear":
                line = _mutation_line(task, args)
                (workspace_path / "transaction.txt").write_text(f"TX R0.0\n{line}\n", encoding="utf-8")
            elif command != "apply" or args:
                raise ValueError("apply one semicolon-separated command string")
            if command == "mutate":
                print("OK")
                return 0
            command, args = "test", []
        if command in {"verify", "test"} and not args:
            workspace, _ = _workspace(task)
            transaction = _load_transaction(task, arm, workspace_path)
            result = workspace.verify(transaction)
            if not result.verified:
                _print_diagnostic(result.diagnostic, handles, task)
                return 1
            if command == "verify":
                print("OK")
                return 0
            committed = workspace.commit(transaction)
            expected_root = _expected_root(task)
            if committed.committed and committed.root == expected_root:
                print("PASS")
                return 0
            print(json.dumps(["XAX.TEST.TARGET", "R0", expected_root.hex(), committed.root.hex(), ["R0"]], separators=(",", ":")))
            return 1
        raise ValueError("query|inspect|verify|test" if variant else "query|inspect|mutate|apply|verify|test")
    except (OSError, ValueError) as error:
        print(json.dumps(["XAX.CLI.INPUT", command or "-", "valid command", str(error), []], separators=(",", ":")))
        return 1


def _normalize_c(source: str) -> str:
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    return re.sub(r"\s+", "", source)


def _value(text: str) -> ValueRef:
    match = re.fullmatch(r"F\d+\.B(\d+)\.(?:P(\d+)|N(\d+)\.R(\d+))", text)
    if not match:
        raise ValueError(f"bad value handle: {text}")
    block, parameter, node, result = match.groups()
    return ValueRef.parameter(int(block), int(parameter)) if parameter is not None else ValueRef.node_result(int(block), int(node), int(result))


def _position(handle: str) -> tuple[int, int]:
    match = re.fullmatch(r"F\d+\.B(\d+)\.N(\d+)", handle)
    if not match:
        raise ValueError(f"bad node handle: {handle}")
    return tuple(map(int, match.groups()))


def _transaction(text: str) -> Transaction:
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines or not re.fullmatch(r"TX R0\.\d+", lines[0]):
        raise ValueError("first line must be TX R0.<generation>")
    generation = int(lines.pop(0).rsplit(".", 1)[1])
    mutations = []
    for line in lines:
        parts = line.split()
        if len(parts) == 4 and parts[0] == "C":
            mutations.append(SetConstant(parts[1], int(parts[2]), int(parts[3])))
        elif len(parts) == 4 and parts[0] == "O" and parts[2] in OPS and parts[3] in OPS:
            mutations.append(SetOperation(parts[1], OPS[parts[2]], OPS[parts[3]]))
        elif len(parts) == 5 and parts[0] == "U":
            mutations.append(ReplaceUse(parts[1], int(parts[2]), _value(parts[3]), _value(parts[4])))
        elif len(parts) == 2 and parts[0] == "D":
            mutations.append(DeleteNode(parts[1], *_position(parts[1])))
        elif len(parts) == 4 and parts[0] == "M" and parts[2] == "BEFORE":
            mutations.append(MovePureNode(parts[1], *_position(parts[1]), parts[3], *_position(parts[3])))
        else:
            raise ValueError(f"bad mutation: {line}")
    return Transaction(RootRef(generation), tuple(mutations))


def check(task_id: str, arm: str, workspace_path: Path) -> tuple[bool, str]:
    task, arm = load_task(task_id), _arm(arm)
    try:
        if arm == "C":
            passed = _normalize_c((workspace_path / "program.c").read_text(encoding="utf-8")) == _normalize_c(task.c_target)
            return passed, "" if passed else "program.c does not match the requested structure"
        workspace, _ = _workspace(task)
        result = workspace.commit(_load_transaction(task, arm, workspace_path))
        if not result.committed:
            diagnostic = result.diagnostic
            return False, diagnostic.code if diagnostic else "transaction rejected"
        passed = result.root == _expected_root(task)
        return passed, "" if passed else "transaction is valid but reaches the wrong program"
    except (OSError, ValueError) as error:
        return False, str(error)


def _upgrade_results_schema(path: Path) -> None:
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        fieldnames = tuple(reader.fieldnames or ())
        rows = list(reader)
    if fieldnames == FIELDS:
        return
    if fieldnames != LEGACY_FIELDS:
        raise ValueError(f"unsupported results schema: {path}")
    upgraded = []
    for row in rows:
        task = load_task(row["task_id"])
        upgraded.append({
            "task_id": row["task_id"], "task_family": task.family, "arm": row["arm"], "trial": "1",
            "model": "", "reasoning": "", "pass": row["pass"], "input_tokens": row["input_tokens"],
            "output_tokens": row["output_tokens"], "total_tokens": row["total_tokens"], "turns": row["turns"],
            "elapsed_seconds": row["elapsed_seconds"], "failed_checks": "", "repair_count": "", "view_bytes": "",
            "packet_bytes": "", "semantic_entities": "", "final_root": "", "notes": row["notes"],
        })
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(upgraded)
    temporary.replace(path)


def record(task_id: str, arm: str, passed: bool, *, input_tokens: int | None = None, output_tokens: int | None = None,
           total_tokens: int | None = None, turns: int = 1, elapsed_seconds: float | None = None,
           failed_checks: int | None = None, repair_count: int | None = None, view_bytes: int | None = None,
           packet_bytes: int | None = None, semantic_entities: int | None = None, final_root: str = "", trial: int = 1,
           model: str = "", reasoning: str = "", notes: str = "",
           results_path: Path = RESULTS) -> None:
    task = load_task(task_id)
    arm = _arm(arm)
    nonnegative = (input_tokens, output_tokens, total_tokens, failed_checks, repair_count, view_bytes, packet_bytes, semantic_entities)
    if turns < 1 or trial < 1 or any(value is not None and value < 0 for value in nonnegative):
        raise ValueError("invalid result")
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    _upgrade_results_schema(results_path)
    rows = _rows(results_path)
    if any(row["task_id"] == task_id and row["arm"] == arm and int(row.get("trial") or 1) == trial for row in rows):
        raise ValueError(f"result already recorded: {task_id} {arm} trial {trial}")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        if results_path.stat().st_size == 0:
            writer.writeheader()
        writer.writerow(dict(zip(FIELDS, (
            task_id, task.family, arm, trial, model, reasoning, str(passed).upper(), input_tokens, output_tokens,
            total_tokens, turns, elapsed_seconds, failed_checks, repair_count, view_bytes, packet_bytes,
            semantic_entities, final_root, notes,
        ))))


def _trace_counts(workspace_path: Path) -> tuple[int, int]:
    trace = workspace_path / "trace.jsonl"
    if not trace.exists():
        return 0, 0
    events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines() if line.strip()]
    failed_checks = 0
    repairs = 0
    failed_since_change = False
    previous_packet = events[0].get("packet") if events else None
    for event in events:
        packet = event.get("packet")
        if packet != previous_packet:
            if failed_since_change:
                repairs += 1
            failed_since_change = False
            previous_packet = packet
        argv = event.get("argv") or []
        if argv and argv[0] in {"verify", "test"} and event.get("exit"):
            failed_checks += 1
            failed_since_change = True
    return failed_checks, repairs


def _trial_evidence(task: Task, arm: str, workspace_path: Path) -> dict[str, int | str]:
    variant = _variant(arm)
    if variant is None:
        return {}
    handles, _framing = variant
    view = _rename(_workspace(task)[1], handles, task)
    packet_path = workspace_path / "packet.txt"
    packet = packet_path.read_text(encoding="utf-8") if packet_path.exists() else ""
    failed_checks, repairs = _trace_counts(workspace_path)
    workspace, _ = _workspace(task)
    final_root = workspace.root
    try:
        result = workspace.commit(_load_transaction(task, arm, workspace_path))
        final_root = result.root
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return {
        "failed_checks": failed_checks,
        "repair_count": repairs,
        "view_bytes": len(view.encode()),
        "packet_bytes": len(packet.encode()),
        "semantic_entities": task.semantic_entities or len(task.initial) + 1,
        "final_root": final_root.hex(),
    }


def record_session(task_id: str, arm: str, passed: bool, workspace_path: Path, *, turns: int = 1, notes: str = "",
                   trial: int = 1, model: str = "", reasoning: str = "", sessions_path: Path = SESSIONS,
                   results_path: Path = RESULTS) -> Path:
    task, arm = load_task(task_id), _arm(arm)
    workspace = workspace_path.resolve()
    matches = []
    for path in sessions_path.rglob("*.jsonl"):
        try:
            with path.open(encoding="utf-8") as file:
                metadata = json.loads(file.readline())
            if metadata.get("type") == "session_meta" and Path(metadata["payload"]["cwd"]).resolve() == workspace:
                matches.append(path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            continue
    if not matches:
        raise ValueError(f"no Codex Desktop session found for {workspace}")
    session = max(matches, key=lambda path: path.stat().st_mtime_ns)
    usage = None
    with session.open(encoding="utf-8") as file:
        for line in file:
            event = json.loads(line)
            if event.get("type") == "event_msg" and event.get("payload", {}).get("type") == "token_count":
                usage = event["payload"].get("info", {}).get("total_token_usage")
    if not usage:
        raise ValueError(f"session has no token usage: {session}")
    evidence = _trial_evidence(task, arm, workspace_path)
    record(task_id, arm, passed, input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"],
           total_tokens=usage["total_tokens"], turns=turns, trial=trial, model=model, reasoning=reasoning,
           notes=notes, results_path=results_path, **evidence)
    return session


def summarize(results_path: Path = RESULTS) -> str:
    rows = _rows(results_path)
    by_key = {(row["task_id"], row["arm"]): row for row in rows}
    arms = ["C", "XAX", *sorted({row["arm"] for row in rows} - {"C", "XAX"})]
    lines = ["task      " + " ".join(f"{arm} pass/tokens/turns".ljust(max(22, len(arm) + 18)) for arm in arms).rstrip()]
    for task in oi01_tasks():
        cells = []
        for arm in arms:
            row = by_key.get((task.task_id, arm))
            cells.append(("-" if not row else f"{row['pass']} / {row['total_tokens'] or '-'} / {row['turns']}").ljust(max(22, len(arm) + 18)))
        lines.append(f"{task.task_id}  {' '.join(cells).rstrip()}")
    lines.append("")
    lines.append("metric        " + " ".join(arm.ljust(10) for arm in arms).rstrip())
    for metric in ("passes", "tokens", "median/task", "turns"):
        values = []
        for arm in arms:
            arm_rows = [row for row in rows if row["arm"] == arm]
            tokens = [int(row["total_tokens"]) for row in arm_rows if row["total_tokens"]]
            if metric == "passes": value = f"{sum(row['pass'] == 'TRUE' for row in arm_rows)}/{len(arm_rows)}"
            elif metric == "tokens": value = str(sum(tokens)) if arm_rows and len(tokens) == len(arm_rows) else "-"
            elif metric == "median/task": value = str(median(tokens)) if tokens and len(tokens) == len(arm_rows) else "-"
            else: value = str(sum(int(row["turns"]) for row in arm_rows))
            values.append(value)
        lines.append(f"{metric:<13} " + " ".join(value.ljust(10) for value in values).rstrip())
    return "\n".join(lines)


def summarize_oi01(results_path: Path = RESULTS) -> str:
    rows = [row for row in _rows(results_path) if _variant(row["arm"])]
    def metrics(group):
        passed = sum(row["pass"] == "TRUE" for row in group)
        failed = sum(int(row.get("failed_checks") or 0) for row in group)
        repairs = sum(int(row.get("repair_count") or 0) for row in group)
        tokens = [int(row["total_tokens"]) for row in group if row.get("total_tokens")]
        token_cost = sum(tokens) / passed if passed and len(tokens) == len(group) else None
        byte_cells = [
            int(row.get("view_bytes") or 0) + int(row.get("packet_bytes") or 0)
            for row in group if row.get("view_bytes") and row.get("packet_bytes")
        ]
        byte_cost = sum(byte_cells) if len(byte_cells) == len(group) else None
        return passed, len(group), failed, repairs, token_cost, byte_cost

    lines = ["family                    arm                 pass  failed  repairs  tokens/success  bytes(view+packet)"]
    groups = {}
    for row in rows:
        task = load_task(row["task_id"])
        groups.setdefault((task.family, row["arm"]), []).append(row)
    for (family, arm), group in sorted(groups.items()):
        passed, count, failed, repairs, token_cost, byte_cost = metrics(group)
        token_text = "-" if token_cost is None else f"{token_cost:.1f}"
        byte_text = "-" if byte_cost is None else str(byte_cost)
        lines.append(f"{family:<25} {arm:<19} {passed}/{count:<3} {failed:<7} {repairs:<8} {token_text:<15} {byte_text}")
    if not groups:
        lines.append("(no model trial rows)")
        return "\n".join(lines)

    def ranked(title: str, key):
        aggregate = {}
        for row in rows:
            aggregate.setdefault(key(row), []).append(row)
        scored = []
        for name, group in aggregate.items():
            passed, count, failed, repairs, token_cost, byte_cost = metrics(group)
            score = (-passed / count, failed, repairs, float("inf") if token_cost is None else token_cost,
                     float("inf") if byte_cost is None else byte_cost, name)
            scored.append((score, name, passed, count, failed, repairs, token_cost, byte_cost))
        lines.extend(("", title, "name                 pass  failed  repairs  tokens/success  bytes(view+packet)"))
        for _score, name, passed, count, failed, repairs, token_cost, byte_cost in sorted(scored):
            token_text = "-" if token_cost is None else f"{token_cost:.1f}"
            byte_text = "-" if byte_cost is None else str(byte_cost)
            lines.append(f"{name:<20} {passed}/{count:<3} {failed:<7} {repairs:<8} {token_text:<15} {byte_text}")

    ranked("arm ranking (reliability -> tokens -> bytes)", lambda row: row["arm"])
    ranked("handle namespace", lambda row: _variant(row["arm"])[0])
    ranked("framing", lambda row: _variant(row["arm"])[1])
    return "\n".join(lines)


def corpus_report() -> dict:
    rows = []
    for task in oi01_tasks():
        target_root = _expected_root(task).hex()
        for handles in HANDLES:
            view = _rename(_workspace(task)[1], handles, task)
            for framing in FRAMINGS:
                prefill = encode_packet(framing, handles, task.prefill, root=task.prefill_root, task=task)
                packet = encode_packet(framing, handles, REFERENCE_EDITS[task.task_id], root=task.reference_root, task=task)
                rows.append({
                    "task_id": task.task_id,
                    "task_family": task.family,
                    "handles": handles,
                    "framing": framing,
                    "semantic_entities": task.semantic_entities or len(task.initial) + 1,
                    "view": view,
                    "view_bytes": len(view.encode()),
                    "prefill_packet": prefill,
                    "prefill_packet_bytes": len(prefill.encode()),
                    "target_packet": packet,
                    "target_packet_bytes": len(packet.encode()),
                    "target_root": target_root,
                })
    return {"transport_version": TRANSPORT_VERSION, "model_run": None, "rows": rows}


def transport_report(encodings: tuple[str, ...] = ("cl100k_base", "o200k_base")) -> dict:
    """Offline tokenizer/byte accounting of each handle x framing candidate on the reference edits. No model run."""
    import tiktoken

    tokenizers = {name: tiktoken.get_encoding(name) for name in encodings}
    count = lambda text: {name: len(tokenizer.encode(text)) for name, tokenizer in tokenizers.items()}
    rows = []
    for task in tasks():
        expected, _ = _build(task.target, task.result)
        for handles in HANDLES:
            view = _rename(_workspace(task)[1], handles, task)
            for framing in FRAMINGS:
                packet = encode_packet(framing, handles, REFERENCE_EDITS[task.task_id], task=task)
                result = _workspace(task)[0].commit(decode_packet(task, framing, handles, packet))
                rows.append({
                    "task_id": task.task_id, "handles": handles, "framing": framing,
                    "semantic_entities": len(task.initial) + 1,
                    "view": view, "view_bytes": len(view.encode()), "view_tokens": count(view),
                    "packet": packet, "packet_bytes": len(packet.encode()), "packet_tokens": count(packet),
                    "reaches_target": bool(result.committed and result.root == expected.root_cid),
                })
    return {"transport_version": TRANSPORT_VERSION, "tokenizer": f"tiktoken {tiktoken.__version__}", "encodings": list(encodings),
            "model_run": None, "rows": rows}


def summarize_transport(report: dict) -> str:
    lines = ["handles  framing  " + "  ".join(f"{name} view+packet=total" for name in report["encodings"]) + "  bytes  targets"]
    for handles in HANDLES:
        for framing in FRAMINGS:
            rows = [row for row in report["rows"] if row["handles"] == handles and row["framing"] == framing]
            cells = []
            for name in report["encodings"]:
                view, packet = (sum(row[f"{part}_tokens"][name] for row in rows) for part in ("view", "packet"))
                cells.append(f"{view}+{packet}={view + packet}".ljust(len(name) + 18))
            size = sum(row["view_bytes"] + row["packet_bytes"] for row in rows)
            lines.append(f"{handles:<8} {framing:<8} {'  '.join(cells)} {size:<6} {sum(row['reaches_target'] for row in rows)}/{len(rows)}")
    return "\n".join(lines)


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("prepare"); make.add_argument("task_id"); make.add_argument("arm"); make.add_argument("output", nargs="?", type=Path)
    verify = commands.add_parser("check"); verify.add_argument("task_id"); verify.add_argument("arm"); verify.add_argument("workspace", type=Path)
    save = commands.add_parser("record"); save.add_argument("task_id"); save.add_argument("arm"); save.add_argument("outcome", choices=("PASS", "FAIL"))
    save.add_argument("--input-tokens", type=int); save.add_argument("--output-tokens", type=int); save.add_argument("--total-tokens", type=int)
    save.add_argument("--turns", type=int, default=1); save.add_argument("--elapsed-seconds", type=float)
    save.add_argument("--failed-checks", type=int); save.add_argument("--repair-count", type=int); save.add_argument("--view-bytes", type=int)
    save.add_argument("--packet-bytes", type=int); save.add_argument("--semantic-entities", type=int); save.add_argument("--final-root", default="")
    save.add_argument("--trial", type=int, default=1); save.add_argument("--model", default=""); save.add_argument("--reasoning", default="")
    save.add_argument("--notes", default=""); save.add_argument("--results", type=Path, default=RESULTS)
    session = commands.add_parser("record-session"); session.add_argument("task_id"); session.add_argument("arm"); session.add_argument("outcome", choices=("PASS", "FAIL")); session.add_argument("workspace", type=Path)
    session.add_argument("--turns", type=int, default=1); session.add_argument("--trial", type=int, default=1)
    session.add_argument("--model", default=""); session.add_argument("--reasoning", default="")
    session.add_argument("--notes", default=""); session.add_argument("--results", type=Path, default=RESULTS)
    report = commands.add_parser("summary"); report.add_argument("--results", type=Path, default=RESULTS)
    oi01 = commands.add_parser("oi01-summary"); oi01.add_argument("--results", type=Path, default=RESULTS)
    transport = commands.add_parser("transport"); transport.add_argument("--output", type=Path, default=TRANSPORT)
    corpus = commands.add_parser("corpus"); corpus.add_argument("--output", type=Path, default=CORPUS)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare": print(prepare(args.task_id, args.arm, args.output))
        elif args.command == "check":
            passed, reason = check(args.task_id, args.arm, args.workspace)
            print("PASS" if passed else f"FAIL: {reason}")
            return 0 if passed else 1
        elif args.command == "record":
            record(args.task_id, args.arm, args.outcome == "PASS", input_tokens=args.input_tokens, output_tokens=args.output_tokens,
                   total_tokens=args.total_tokens, turns=args.turns, elapsed_seconds=args.elapsed_seconds, failed_checks=args.failed_checks,
                   repair_count=args.repair_count, view_bytes=args.view_bytes, packet_bytes=args.packet_bytes,
                   semantic_entities=args.semantic_entities, final_root=args.final_root, trial=args.trial, model=args.model,
                   reasoning=args.reasoning, notes=args.notes, results_path=args.results)
        elif args.command == "record-session":
            print(record_session(args.task_id, args.arm, args.outcome == "PASS", args.workspace, turns=args.turns, trial=args.trial,
                                 model=args.model, reasoning=args.reasoning, notes=args.notes, results_path=args.results))
        elif args.command == "transport":
            data = transport_report()
            args.output.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
            print(summarize_transport(data))
        elif args.command == "corpus":
            data = corpus_report()
            args.output.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
            print(f"{len(data['rows'])} rows")
        elif args.command == "oi01-summary": print(summarize_oi01(args.results))
        else: print(summarize(args.results))
        return 0
    except ValueError as error:
        parser.error(str(error))


__all__ = ("Task", "tasks", "oi01_tasks", "load_task", "prepare", "trial_main", "check", "record", "record_session", "summarize",
           "summarize_oi01", "encode_packet", "decode_packet", "corpus_report", "transport_report", "summarize_transport", "main")
