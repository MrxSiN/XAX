"""M12 optimizer prototype with bounded validated search.

The canonical XAX semantic graph remains authoritative.  This module is a
bootstrap compiler service: optimization policy, profile observations, cost
reports, and search bookkeeping are derived tooling state and are not XAX
source.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from itertools import product
from typing import Callable, Iterable, Sequence

from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _parse_graph,
    bits_type,
    constant,
    decode_bits_width,
    decode_native_target,
    fail,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    write_store,
)
from xax_aarch64 import compile_aarch64_bound_target
from xax_build import OptimizationObjective, decode_optimization_policy
from xax_wasm import compile_wasm_bound_target
from xax_x86_64 import compile_native_bound_target


PURE_ARITHMETIC = frozenset((Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.CONSTANT))
M12_COST_MODEL_IDENTITY = b"xax-m12-lowering-size-v1"
M12_VALIDATOR_IDENTITY = b"xax-m12-wrap-poly-validator-v1"


class CostObjective(str, Enum):
    CODE_SIZE = "code_size"


@dataclass(frozen=True)
class OptimizationBudget:
    """Deterministic compiler-work and memory limits for M12.

    ``search_steps`` is a deterministic compile-work fuel budget rather than a
    wall-clock cutoff, so reproducible builds do not depend on host scheduling.
    """

    pass_iterations: int = 4
    search_steps: int = 384
    search_candidates: int = 192
    search_memory_bytes: int = 1 << 20
    polynomial_terms: int = 256
    inline_cold_nodes: int = 2
    inline_hot_nodes: int = 8
    hot_call_threshold: int = 10

    def __post_init__(self) -> None:
        for value in (
            self.pass_iterations,
            self.search_steps,
            self.search_candidates,
            self.search_memory_bytes,
            self.polynomial_terms,
            self.inline_cold_nodes,
            self.inline_hot_nodes,
            self.hot_call_threshold,
        ):
            if value < 0:
                raise ValueError("optimization budgets must be non-negative")


@dataclass(frozen=True)
class ProfileData:
    """Non-semantic profitability observations.

    The profile identity is supplied by the measurement/collection layer.  It
    is deliberately never serialized into canonical XAX objects.
    """

    identity: bytes
    call_weights: tuple[tuple[bytes, int], ...] = ()

    def __post_init__(self) -> None:
        if not self.identity:
            raise ValueError("profile identity must not be empty")
        ordered = tuple(sorted(self.call_weights, key=lambda item: item[0]))
        if ordered != self.call_weights or len({cid for cid, _ in ordered}) != len(ordered):
            raise ValueError("profile call weights must be CID-sorted and unique")
        if any(len(cid) != 32 or weight < 0 for cid, weight in ordered):
            raise ValueError("invalid profile call weight")

    def weight(self, callee: bytes) -> int:
        for cid, weight in self.call_weights:
            if cid == callee:
                return weight
        return 0

    @property
    def tooling_digest(self) -> bytes:
        payload = bytearray(b"XAX-M12-PROFILE-1" + self.identity)
        for cid, weight in self.call_weights:
            payload.extend(cid + weight.to_bytes(8, "little"))
        return sha256(payload).digest()


@dataclass(frozen=True)
class TargetCostReport:
    entity: bytes
    target: bytes
    objective: CostObjective
    value: int
    unit: str
    model_identity: bytes
    classification: str
    artifact_bytes: int
    assumptions: tuple[str, ...] = ()


@dataclass(frozen=True)
class OptimizationEvent:
    pass_name: str
    before_function: bytes
    candidate_function: bytes
    accepted: bool
    correctness: str
    reason: str
    cost_before: int | None = None
    cost_after: int | None = None


@dataclass(frozen=True)
class SearchReport:
    attempted: bool
    steps: int
    candidates: int
    equivalent_candidates: int
    rejected_validation: int
    peak_memory_bytes: int
    validator_identity: bytes
    selected_function: bytes | None


@dataclass(frozen=True)
class OptimizationResult:
    reader: StoreReader
    function: SemanticObject
    events: tuple[OptimizationEvent, ...]
    cost_reports: tuple[TargetCostReport, ...]
    search: SearchReport
    profile_identity: bytes | None
    policy_root: bytes | None


@dataclass(frozen=True)
class _Expr:
    kind: str
    value: int | None = None
    index: int | None = None
    left: "_Expr | None" = None
    right: "_Expr | None" = None

    @staticmethod
    def param(index: int) -> "_Expr":
        return _Expr("param", index=index)

    @staticmethod
    def const(value: int) -> "_Expr":
        return _Expr("const", value=value)

    @staticmethod
    def op(kind: str, left: "_Expr", right: "_Expr") -> "_Expr":
        return _Expr(kind, left=left, right=right)


Polynomial = dict[tuple[int, ...], int]


def _resolver(reader: StoreReader) -> tuple[dict[bytes, SemanticObject], Callable[[bytes], SemanticObject]]:
    objects = {obj.cid: obj for obj in reader.objects()}

    def resolve(cid: bytes) -> SemanticObject:
        try:
            return objects[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "stored object", "missing")

    return objects, resolve


def _public_graph(reader: StoreReader, function_object: SemanticObject) -> tuple[int, tuple[Block, ...], tuple[SemanticObject, ...], tuple[SemanticObject, ...]]:
    _, resolve = _resolver(reader)
    graph, parameter_cids, return_cids = _decode_function_interface(function_object, resolve)
    parsed = _parse_graph(graph, resolve)
    blocks = tuple(
        Block(
            tuple(resolve(cid) for cid in block.parameters),
            tuple(
                Node(
                    Operation(node.operation),
                    node.operands,
                    tuple(resolve(cid) for cid in node.results),
                    member=node.member,
                    entity=node.entity,
                    attributes=node.attributes,
                )
                for node in block.nodes
            ),
            block.terminator,
        )
        for block in parsed.blocks
    )
    return parsed.entry, blocks, tuple(resolve(cid) for cid in parameter_cids), tuple(resolve(cid) for cid in return_cids)


def _reachable_store(root: SemanticObject, objects: dict[bytes, SemanticObject], metadata=()) -> StoreReader:
    reachable: dict[bytes, SemanticObject] = {}

    def visit(cid: bytes) -> None:
        if cid in reachable:
            return
        try:
            obj = objects[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "optimized object", "missing")
        reachable[cid] = obj
        for child in obj.references:
            visit(child)

    visit(root.cid)
    result = StoreReader.from_objects(root.cid, reachable.values(), metadata)
    verify_store(result)
    return result


def _replace_function(
    reader: StoreReader,
    old_function: SemanticObject,
    entry: int,
    blocks: Sequence[Block],
    extra_objects: Iterable[SemanticObject] = (),
) -> tuple[StoreReader, SemanticObject]:
    objects, resolve = _resolver(reader)
    _, parameter_cids, return_cids = _decode_function_interface(old_function, resolve)
    graph = graph_fragment(tuple(blocks), entry)
    candidate = function(graph, tuple(resolve(cid) for cid in parameter_cids), tuple(resolve(cid) for cid in return_cids))
    objects[graph.cid] = graph
    objects[candidate.cid] = candidate
    for obj in extra_objects:
        objects[obj.cid] = obj

    root = resolve(reader.root_cid)
    if root.kind != Kind.PROGRAM_ROOT:
        fail("XAX.OPT.ROOT", root.cid.hex(), "OPT-PROGRAM-ROOT", Kind.PROGRAM_ROOT.name, root.kind.name)
    replaced = False
    root_children: list[SemanticObject] = []
    for child_cid in root.references:
        child = objects[child_cid]
        if child.kind == Kind.MODULE and old_function.cid in child.references:
            members = [objects[cid] for cid in child.references]
            members = [candidate if item.cid == old_function.cid else item for item in members]
            child = object_with_refs(Kind.MODULE, members)
            objects[child.cid] = child
            replaced = True
        root_children.append(child)
    if not replaced:
        fail("XAX.OPT.FUNCTION_SCOPE", old_function.cid.hex(), "OPT-MODULE-MEMBER", "direct module member", "absent")
    new_root = object_with_refs(Kind.PROGRAM_ROOT, root_children)
    objects[new_root.cid] = new_root
    return _reachable_store(new_root, objects, reader.nonsemantic_records), candidate


def _map_value(value: ValueRef, mapping: dict[ValueRef, ValueRef]) -> ValueRef:
    # Mapping keys are coordinates in the pre-transform graph while values are
    # coordinates in the candidate graph.  These namespaces can numerically
    # overlap after deletion/insertion, so following a mapped value as another
    # old key would conflate graph generations.
    return mapping.get(value, value)


def _map_terminator(term: Terminator, mapping: dict[ValueRef, ValueRef], block_map: dict[int, int] | None = None) -> Terminator:
    block_map = block_map or {}

    def val(value: ValueRef) -> ValueRef:
        value = _map_value(value, mapping)
        return ValueRef(value.tag, block_map.get(value.block, value.block), value.index, value.result)

    edges = tuple((block_map.get(target, target), tuple(val(arg) for arg in args)) for target, args in term.edges)
    return Terminator(term.kind, tuple(val(value) for value in term.values), edges, term.payload)


def _simplify_local(reader: StoreReader, function_object: SemanticObject) -> tuple[StoreReader, SemanticObject, bool]:
    entry, blocks, _, _ = _public_graph(reader, function_object)
    _, resolve = _resolver(reader)
    changed = False
    extras: dict[bytes, SemanticObject] = {}
    output: list[Block] = []
    for block_index, block in enumerate(blocks):
        mapping: dict[ValueRef, ValueRef] = {}
        constants: dict[ValueRef, int] = {}
        cse: dict[tuple, tuple[ValueRef, ...]] = {}
        new_nodes: list[Node] = []
        for old_index, node in enumerate(block.nodes):
            operands = tuple(_map_value(value, mapping) for value in node.operands)
            old_results = tuple(ValueRef.node_result(block_index, old_index, result) for result in range(len(node.result_types)))

            replacement: ValueRef | None = None
            folded: int | None = None
            if node.operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP) and len(node.result_types) == 1:
                left = constants.get(operands[0])
                right = constants.get(operands[1])
                width = decode_bits_width(node.result_types[0])
                mask = (1 << width) - 1
                if left is not None and right is not None:
                    folded = {
                        Operation.ADD_WRAP: (left + right) & mask,
                        Operation.SUB_WRAP: (left - right) & mask,
                        Operation.MUL_WRAP: (left * right) & mask,
                    }[node.operation]
                elif node.operation == Operation.ADD_WRAP:
                    if left == 0:
                        replacement = operands[1]
                    elif right == 0:
                        replacement = operands[0]
                elif node.operation == Operation.SUB_WRAP and right == 0:
                    replacement = operands[0]
                elif node.operation == Operation.MUL_WRAP:
                    if left == 1:
                        replacement = operands[1]
                    elif right == 1:
                        replacement = operands[0]
                    elif left == 0 or right == 0:
                        folded = 0

            if replacement is not None:
                mapping[old_results[0]] = replacement
                changed = True
                continue

            emitted = Node(node.operation, operands, node.result_types, member=node.member, entity=node.entity, attributes=node.attributes)
            if folded is not None:
                obj = constant(node.result_types[0], folded)
                extras[obj.cid] = obj
                emitted = Node(Operation.CONSTANT, (), node.result_types, entity=obj)
                changed = True

            key = None
            if emitted.operation in PURE_ARITHMETIC:
                key = (
                    emitted.operation,
                    emitted.operands,
                    tuple(item.cid for item in emitted.result_types),
                    None if emitted.entity is None else emitted.entity.cid,
                    emitted.attributes,
                )
                existing = cse.get(key)
                if existing is not None:
                    for old_ref, new_ref in zip(old_results, existing):
                        mapping[old_ref] = new_ref
                    changed = True
                    continue

            new_index = len(new_nodes)
            new_nodes.append(emitted)
            new_results = tuple(ValueRef.node_result(block_index, new_index, result) for result in range(len(emitted.result_types)))
            for old_ref, new_ref in zip(old_results, new_results):
                mapping[old_ref] = new_ref
            if key is not None:
                cse[key] = new_results
            if emitted.operation == Operation.CONSTANT and emitted.entity is not None and new_results:
                _, value = _decode_constant(emitted.entity, resolve)
                constants[new_results[0]] = value

        term = _map_terminator(block.terminator, mapping)
        if tuple(new_nodes) != block.nodes or term != block.terminator:
            changed = True
        output.append(Block(block.parameters, tuple(new_nodes), term))

    output, dce_changed = _dce(tuple(output))
    changed |= dce_changed
    if not changed:
        return reader, function_object, False
    new_reader, candidate = _replace_function(reader, function_object, entry, output, extras.values())
    return new_reader, candidate, True


def _dce(blocks: tuple[Block, ...]) -> tuple[tuple[Block, ...], bool]:
    live: set[ValueRef] = set()
    for block in blocks:
        live.update(value for value in block.terminator.values if value.tag == 1)
        for _, args in block.terminator.edges:
            live.update(value for value in args if value.tag == 1)
    changed_live = True
    while changed_live:
        changed_live = False
        for block_index in range(len(blocks) - 1, -1, -1):
            block = blocks[block_index]
            for node_index in range(len(block.nodes) - 1, -1, -1):
                node = block.nodes[node_index]
                results = tuple(ValueRef.node_result(block_index, node_index, result) for result in range(len(node.result_types)))
                keep = node.operation not in PURE_ARITHMETIC or any(result in live for result in results)
                if keep:
                    before = len(live)
                    live.update(value for value in node.operands if value.tag == 1)
                    changed_live |= len(live) != before

    index_maps: list[dict[int, int]] = []
    kept: list[list[tuple[int, Node]]] = []
    any_removed = False
    for block_index, block in enumerate(blocks):
        entries: list[tuple[int, Node]] = []
        mapping: dict[int, int] = {}
        for old_index, node in enumerate(block.nodes):
            results = tuple(ValueRef.node_result(block_index, old_index, result) for result in range(len(node.result_types)))
            if node.operation in PURE_ARITHMETIC and not any(result in live for result in results):
                any_removed = True
                continue
            mapping[old_index] = len(entries)
            entries.append((old_index, node))
        index_maps.append(mapping)
        kept.append(entries)
    if not any_removed:
        return blocks, False

    def remap(value: ValueRef) -> ValueRef:
        if value.tag == 0:
            return value
        return ValueRef.node_result(value.block, index_maps[value.block][value.index], value.result)

    out: list[Block] = []
    for block_index, block in enumerate(blocks):
        nodes = tuple(
            Node(node.operation, tuple(remap(value) for value in node.operands), node.result_types, member=node.member, entity=node.entity, attributes=node.attributes)
            for _, node in kept[block_index]
        )
        term = Terminator(
            block.terminator.kind,
            tuple(remap(value) for value in block.terminator.values),
            tuple((target, tuple(remap(value) for value in args)) for target, args in block.terminator.edges),
            block.terminator.payload,
        )
        out.append(Block(block.parameters, nodes, term))
    return tuple(out), True


def _simplify_cfg(reader: StoreReader, function_object: SemanticObject) -> tuple[StoreReader, SemanticObject, bool]:
    entry, blocks, _, _ = _public_graph(reader, function_object)
    _, resolve = _resolver(reader)
    rewritten: list[Block] = []
    changed = False
    for block_index, block in enumerate(blocks):
        term = block.terminator
        if term.kind == TerminatorKind.CONDITIONAL_BRANCH:
            condition = term.values[0]
            if condition.tag == 1 and condition.block == block_index and condition.index < len(block.nodes):
                node = block.nodes[condition.index]
                if node.operation == Operation.CONSTANT and node.entity is not None:
                    _, value = _decode_constant(node.entity, resolve)
                    chosen = term.edges[0 if value else 1]
                    term = Terminator.branch(chosen[0], chosen[1])
                    changed = True
        rewritten.append(Block(block.parameters, block.nodes, term))

    reachable: set[int] = set()
    pending = [entry]
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        reachable.add(index)
        pending.extend(target for target, _ in rewritten[index].terminator.edges)
    if len(reachable) != len(rewritten):
        changed = True
    if not changed:
        return reader, function_object, False

    kept_indices = tuple(index for index in range(len(rewritten)) if index in reachable)
    block_map = {old: new for new, old in enumerate(kept_indices)}

    def remap(value: ValueRef) -> ValueRef:
        return ValueRef(value.tag, block_map[value.block], value.index, value.result)

    out: list[Block] = []
    for old_index in kept_indices:
        block = rewritten[old_index]
        nodes = tuple(
            Node(node.operation, tuple(remap(value) for value in node.operands), node.result_types, member=node.member, entity=node.entity, attributes=node.attributes)
            for node in block.nodes
        )
        term = Terminator(
            block.terminator.kind,
            tuple(remap(value) for value in block.terminator.values),
            tuple((block_map[target], tuple(remap(value) for value in args)) for target, args in block.terminator.edges),
            block.terminator.payload,
        )
        out.append(Block(block.parameters, nodes, term))
    out_tuple, _ = _dce(tuple(out))
    new_reader, candidate = _replace_function(reader, function_object, block_map[entry], out_tuple)
    return new_reader, candidate, True


def _inline_direct_calls(
    reader: StoreReader,
    function_object: SemanticObject,
    budget: OptimizationBudget,
    profile: ProfileData | None,
) -> tuple[StoreReader, SemanticObject, bool, tuple[str, ...]]:
    entry, blocks, _, _ = _public_graph(reader, function_object)
    _, resolve = _resolver(reader)
    changed = False
    reasons: list[str] = []
    output: list[Block] = []
    for block_index, block in enumerate(blocks):
        value_map: dict[ValueRef, ValueRef] = {}
        new_nodes: list[Node] = []
        for old_index, node in enumerate(block.nodes):
            old_results = tuple(ValueRef.node_result(block_index, old_index, result) for result in range(len(node.result_types)))
            operands = tuple(_map_value(value, value_map) for value in node.operands)
            inline = False
            callee_block: Block | None = None
            callee_returns: tuple[ValueRef, ...] = ()
            if node.operation == Operation.CALL_DIRECT and node.entity is not None:
                try:
                    callee_entry, callee_blocks, _, _ = _public_graph(reader, node.entity)
                except Exception:
                    callee_blocks = ()
                    callee_entry = -1
                if len(callee_blocks) == 1 and callee_entry == 0 and callee_blocks[0].terminator.kind == TerminatorKind.RETURN:
                    candidate_block = callee_blocks[0]
                    legal = all(item.operation in PURE_ARITHMETIC for item in candidate_block.nodes)
                    if legal and len(candidate_block.parameters) == len(operands) and len(candidate_block.terminator.values) == len(node.result_types):
                        weight = 0 if profile is None else profile.weight(node.entity.cid)
                        limit = budget.inline_hot_nodes if weight >= budget.hot_call_threshold else budget.inline_cold_nodes
                        if len(candidate_block.nodes) <= limit:
                            inline = True
                            callee_block = candidate_block
                            callee_returns = candidate_block.terminator.values
                            reasons.append(f"inline:{node.entity.cid.hex()}:{len(candidate_block.nodes)}:{weight}")
            if inline and callee_block is not None:
                local_map: dict[ValueRef, ValueRef] = {
                    ValueRef.parameter(0, index): operand for index, operand in enumerate(operands)
                }
                for callee_index, callee_node in enumerate(callee_block.nodes):
                    mapped_operands = tuple(_map_value(value, local_map) for value in callee_node.operands)
                    emitted = Node(
                        callee_node.operation,
                        mapped_operands,
                        callee_node.result_types,
                        member=callee_node.member,
                        entity=callee_node.entity,
                        attributes=callee_node.attributes,
                    )
                    new_index = len(new_nodes)
                    new_nodes.append(emitted)
                    for result in range(len(emitted.result_types)):
                        local_map[ValueRef.node_result(0, callee_index, result)] = ValueRef.node_result(block_index, new_index, result)
                mapped_returns = tuple(_map_value(value, local_map) for value in callee_returns)
                for old_ref, new_ref in zip(old_results, mapped_returns):
                    value_map[old_ref] = new_ref
                changed = True
                continue

            emitted = Node(node.operation, operands, node.result_types, member=node.member, entity=node.entity, attributes=node.attributes)
            new_index = len(new_nodes)
            new_nodes.append(emitted)
            for result in range(len(emitted.result_types)):
                value_map[old_results[result]] = ValueRef.node_result(block_index, new_index, result)
        output.append(Block(block.parameters, tuple(new_nodes), _map_terminator(block.terminator, value_map)))

    if not changed:
        return reader, function_object, False, ()
    new_reader, candidate = _replace_function(reader, function_object, entry, output)
    return new_reader, candidate, True, tuple(reasons)


def target_cost(reader: StoreReader, function_object: SemanticObject, target: SemanticObject) -> TargetCostReport:
    description = decode_native_target(target)
    if description.architecture == 1:
        image = compile_native_bound_target(reader, function_object.cid, target)
    elif description.architecture == 2:
        image = compile_wasm_bound_target(reader, function_object.cid, target)
    elif description.architecture == 3:
        image = compile_aarch64_bound_target(reader, function_object.cid, target)
    else:
        raise ValueError("unsupported M12 cost target")
    function_range = next(
        (item for item in image.semantic_ranges if item.function_cid == function_object.cid and item.block_index is None),
        None,
    )
    value = len(image.artifact_bytes) if function_range is None else function_range.end - function_range.start
    return TargetCostReport(
        function_object.cid,
        target.cid,
        CostObjective.CODE_SIZE,
        value,
        "bytes",
        M12_COST_MODEL_IDENTITY,
        "lowering-derived estimate",
        len(image.artifact_bytes),
        (f"target-architecture={description.architecture}", "exact emitted function extent used as size oracle"),
    )


def _expr_from_function(reader: StoreReader, function_object: SemanticObject) -> tuple[_Expr, int, int] | None:
    entry, blocks, parameters, returns = _public_graph(reader, function_object)
    _, resolve = _resolver(reader)
    if entry != 0 or len(blocks) != 1 or len(returns) != 1 or not (1 <= len(parameters) <= 2):
        return None
    widths = tuple(decode_bits_width(item) for item in (*parameters, *returns))
    if len(set(widths)) != 1:
        return None
    width = widths[0]
    block = blocks[0]
    if block.terminator.kind != TerminatorKind.RETURN or len(block.terminator.values) != 1:
        return None
    if any(node.operation not in PURE_ARITHMETIC for node in block.nodes):
        return None
    memo: dict[ValueRef, _Expr] = {}

    def expr(value: ValueRef) -> _Expr:
        if value in memo:
            return memo[value]
        if value.tag == 0:
            if value.block != 0:
                raise ValueError("search subset requires entry-block parameters")
            result = _Expr.param(value.index)
        else:
            if value.block != 0:
                raise ValueError("search subset requires one block")
            node = block.nodes[value.index]
            if value.result != 0 or len(node.result_types) != 1:
                raise ValueError("search subset requires single-result arithmetic")
            if node.operation == Operation.CONSTANT:
                _, raw = _decode_constant(node.entity, resolve)
                result = _Expr.const(raw)
            else:
                names = {
                    Operation.ADD_WRAP: "add",
                    Operation.SUB_WRAP: "sub",
                    Operation.MUL_WRAP: "mul",
                }
                result = _Expr.op(names[node.operation], expr(node.operands[0]), expr(node.operands[1]))
        memo[value] = result
        return result

    try:
        return expr(block.terminator.values[0]), width, len(parameters)
    except (KeyError, ValueError):
        return None


def _poly(expr: _Expr, width: int, parameter_count: int, term_budget: int) -> Polynomial | None:
    modulus = 1 << width
    if expr.kind == "param":
        monomial = [0] * parameter_count
        monomial[expr.index or 0] = 1
        return {tuple(monomial): 1}
    if expr.kind == "const":
        value = (expr.value or 0) % modulus
        return {} if value == 0 else {(0,) * parameter_count: value}
    left = _poly(expr.left, width, parameter_count, term_budget) if expr.left is not None else None
    right = _poly(expr.right, width, parameter_count, term_budget) if expr.right is not None else None
    if left is None or right is None:
        return None
    out: Polynomial = {}
    if expr.kind in ("add", "sub"):
        out.update(left)
        sign = 1 if expr.kind == "add" else -1
        for monomial, coeff in right.items():
            value = (out.get(monomial, 0) + sign * coeff) % modulus
            if value:
                out[monomial] = value
            else:
                out.pop(monomial, None)
    elif expr.kind == "mul":
        for left_m, left_c in left.items():
            for right_m, right_c in right.items():
                monomial = tuple(a + b for a, b in zip(left_m, right_m))
                value = (out.get(monomial, 0) + left_c * right_c) % modulus
                if value:
                    out[monomial] = value
                else:
                    out.pop(monomial, None)
                if len(out) > term_budget:
                    return None
    else:
        return None
    return out if len(out) <= term_budget else None


def _expr_nodes(expr: _Expr) -> int:
    if expr.kind in ("param",):
        return 0
    if expr.kind == "const":
        return 1
    return 1 + _expr_nodes(expr.left) + _expr_nodes(expr.right)


def _build_expr_candidate(
    reader: StoreReader,
    function_object: SemanticObject,
    expr: _Expr,
    width: int,
) -> tuple[StoreReader, SemanticObject]:
    entry, _, parameters, returns = _public_graph(reader, function_object)
    if entry != 0:
        raise ValueError("search candidate requires entry block zero")
    type_object = returns[0]
    if decode_bits_width(type_object) != width:
        raise ValueError("search candidate width mismatch")
    nodes: list[Node] = []
    cache: dict[_Expr, ValueRef] = {}
    extras: dict[bytes, SemanticObject] = {}

    def emit(item: _Expr) -> ValueRef:
        if item in cache:
            return cache[item]
        if item.kind == "param":
            value = ValueRef.parameter(0, item.index or 0)
        elif item.kind == "const":
            obj = constant(type_object, (item.value or 0) & ((1 << width) - 1))
            extras[obj.cid] = obj
            value = ValueRef.node_result(0, len(nodes))
            nodes.append(Node(Operation.CONSTANT, (), (type_object,), entity=obj))
        else:
            operation = {"add": Operation.ADD_WRAP, "sub": Operation.SUB_WRAP, "mul": Operation.MUL_WRAP}[item.kind]
            left = emit(item.left)
            right = emit(item.right)
            value = ValueRef.node_result(0, len(nodes))
            nodes.append(Node(operation, (left, right), (type_object,)))
        cache[item] = value
        return value

    result = emit(expr)
    block = Block(parameters, tuple(nodes), Terminator.return_((result,)))
    return _replace_function(reader, function_object, 0, (block,), extras.values())


def _search(
    reader: StoreReader,
    function_object: SemanticObject,
    target: SemanticObject,
    budget: OptimizationBudget,
) -> tuple[StoreReader, SemanticObject, SearchReport, tuple[TargetCostReport, ...], tuple[OptimizationEvent, ...]]:
    extracted = _expr_from_function(reader, function_object)
    if extracted is None or budget.search_steps == 0 or budget.search_candidates == 0:
        return reader, function_object, SearchReport(False, 0, 0, 0, 0, 0, M12_VALIDATOR_IDENTITY, None), (), ()
    baseline_expr, width, parameter_count = extracted
    baseline_poly = _poly(baseline_expr, width, parameter_count, budget.polynomial_terms)
    if baseline_poly is None:
        return reader, function_object, SearchReport(False, 0, 0, 0, 0, 0, M12_VALIDATOR_IDENTITY, None), (), ()

    reports: list[TargetCostReport] = []
    baseline_cost = target_cost(reader, function_object, target)
    reports.append(baseline_cost)
    best_reader, best_function, best_cost = reader, function_object, baseline_cost
    best_score = (baseline_cost.value, baseline_cost.artifact_bytes, _expr_nodes(baseline_expr), function_object.cid)

    seed = [_Expr.param(index) for index in range(parameter_count)] + [_Expr.const(value) for value in (0, 1, 2)]
    pool: list[_Expr] = []
    seen: set[_Expr] = set()
    for item in seed:
        if item not in seen:
            seen.add(item)
            pool.append(item)

    steps = candidates = equivalents = rejected = 0
    peak_memory = len(pool) * 96
    events: list[OptimizationEvent] = []
    cursor = 0
    operations = ("add", "sub", "mul")
    while cursor < len(pool) and steps < budget.search_steps and candidates < budget.search_candidates:
        left = pool[cursor]
        snapshot = tuple(pool)
        for right in snapshot:
            for opname in operations:
                if steps >= budget.search_steps or candidates >= budget.search_candidates:
                    break
                steps += 1
                expr = _Expr.op(opname, left, right)
                if expr in seen:
                    continue
                seen.add(expr)
                candidates += 1
                poly = _poly(expr, width, parameter_count, budget.polynomial_terms)
                memory = len(seen) * 96 + (0 if poly is None else len(poly) * 32)
                peak_memory = max(peak_memory, memory)
                if memory > budget.search_memory_bytes:
                    break
                if poly != baseline_poly:
                    rejected += 1
                    if len(pool) < budget.search_candidates:
                        pool.append(expr)
                    continue
                equivalents += 1
                try:
                    candidate_reader, candidate_function = _build_expr_candidate(reader, function_object, expr, width)
                    verify_store(candidate_reader)
                    check = _expr_from_function(candidate_reader, candidate_function)
                    if check is None or _poly(check[0], width, parameter_count, budget.polynomial_terms) != baseline_poly:
                        rejected += 1
                        continue
                    cost = target_cost(candidate_reader, candidate_function, target)
                except Exception:
                    rejected += 1
                    continue
                reports.append(cost)
                score = (cost.value, cost.artifact_bytes, _expr_nodes(expr), candidate_function.cid)
                accepted = score < best_score
                events.append(
                    OptimizationEvent(
                        "bounded-superopt",
                        best_function.cid,
                        candidate_function.cid,
                        accepted,
                        "exact wrapping-polynomial equivalence + verifier",
                        "lower target code-size cost" if accepted else "valid but not lower cost",
                        best_cost.value,
                        cost.value,
                    )
                )
                if accepted:
                    best_reader, best_function, best_cost, best_score = candidate_reader, candidate_function, cost, score
                if len(pool) < budget.search_candidates:
                    pool.append(expr)
            if steps >= budget.search_steps or candidates >= budget.search_candidates or peak_memory > budget.search_memory_bytes:
                break
        cursor += 1
        if peak_memory > budget.search_memory_bytes:
            break

    report = SearchReport(
        True,
        steps,
        candidates,
        equivalents,
        rejected,
        peak_memory,
        M12_VALIDATOR_IDENTITY,
        best_function.cid if best_function.cid != function_object.cid else None,
    )
    return best_reader, best_function, report, tuple(reports), tuple(events)


def optimize_function(
    reader: StoreReader,
    function_cid: bytes,
    *,
    target: SemanticObject | None = None,
    profile: ProfileData | None = None,
    budget: OptimizationBudget = OptimizationBudget(),
    policy: SemanticObject | None = None,
    enable_search: bool = True,
) -> OptimizationResult:
    """Optimize one module-member function while preserving a verified fallback.

    Low-risk transforms use conservative legality and the ordinary verifier.
    The bounded search slice additionally requires exact polynomial equivalence
    for wrapping arithmetic before a candidate can become the accepted result.
    """

    verify_store(reader)
    if policy is not None:
        if policy.kind != Kind.BUILD:
            fail("XAX.OPT.POLICY", policy.cid.hex(), "OPT-POLICY-KIND", Kind.BUILD.name, policy.kind.name)
        view = decode_optimization_policy(policy)
        if view.objective != OptimizationObjective.CODE_SIZE:
            fail("XAX.OPT.OBJECTIVE", policy.cid.hex(), "OPT-OBJECTIVE-SUPPORTED", OptimizationObjective.CODE_SIZE.name, view.objective.name)
        budget = OptimizationBudget(
            pass_iterations=view.pass_iterations,
            search_steps=view.search_steps,
            search_candidates=view.search_candidates,
            search_memory_bytes=view.search_memory_bytes,
            polynomial_terms=view.polynomial_terms,
            inline_cold_nodes=view.inline_cold_nodes,
            inline_hot_nodes=view.inline_hot_nodes,
            hot_call_threshold=view.hot_call_threshold,
        )
    _, resolve = _resolver(reader)
    current = resolve(function_cid)
    if current.kind != Kind.FUNCTION:
        fail("XAX.OPT.FUNCTION", function_cid.hex(), "OPT-FUNCTION-KIND", Kind.FUNCTION.name, current.kind.name)
    current_reader = reader
    events: list[OptimizationEvent] = []
    costs: list[TargetCostReport] = []

    before = current
    next_reader, next_function, changed = _simplify_cfg(current_reader, current)
    if changed:
        events.append(OptimizationEvent("cfg-simplify", before.cid, next_function.cid, True, "verifier-checked conservative rewrite", "constant branch/unreachable block"))
        current_reader, current = next_reader, next_function

    before = current
    next_reader, next_function, changed, inline_reasons = _inline_direct_calls(current_reader, current, budget, profile)
    if changed:
        events.append(OptimizationEvent("inline", before.cid, next_function.cid, True, "verified pure single-block direct callee", ";".join(inline_reasons)))
        current_reader, current = next_reader, next_function

    for _ in range(budget.pass_iterations):
        before = current
        next_reader, next_function, changed = _simplify_local(current_reader, current)
        if not changed:
            break
        events.append(OptimizationEvent("fold-cse-dce", before.cid, next_function.cid, True, "verifier-checked exact wrapping rules", "local simplification"))
        current_reader, current = next_reader, next_function

    search_report = SearchReport(False, 0, 0, 0, 0, 0, M12_VALIDATOR_IDENTITY, None)
    if enable_search and target is not None:
        searched_reader, searched_function, search_report, search_costs, search_events = _search(current_reader, current, target, budget)
        costs.extend(search_costs)
        events.extend(search_events)
        current_reader, current = searched_reader, searched_function
    elif target is not None:
        costs.append(target_cost(current_reader, current, target))

    verify_store(current_reader)
    return OptimizationResult(
        current_reader,
        current,
        tuple(events),
        tuple(costs),
        search_report,
        None if profile is None else profile.identity,
        None if policy is None else policy.cid,
    )
