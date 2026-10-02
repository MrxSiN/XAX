"""OI-19 transformation-proof granularity experiment.

All proof/witness records are compiler sidecars.  They are not XAX semantics and
never participate in canonical program identity.  Host timing/memory samples
are observational only and are kept in a separate raw artifact.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import json
import platform
import statistics
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from xax_compiler import (
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    bits_type,
    constant,
    decode_bits_width,
    effect_type,
    execute,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    write_store,
)
from xax_optimizer import (
    OptimizationBudget,
    _Expr,
    _build_expr_candidate,
    _expr_from_function,
    _inline_direct_calls,
    _poly,
    _public_graph,
    _replace_function,
    _simplify_cfg,
    _simplify_local,
)

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "oi19_transform_proof_evidence.json"
RAW = HERE / "oi19_transform_proof_timing.json"
OPTIMIZER = HERE.parent / "src" / "xax_optimizer.py"
THIS_FILE = Path(__file__).resolve()

MAGIC = b"X19W"
WITNESS_VERSION = 1
RULE_ADD_ZERO = 1
RULE_CONST_FOLD = 2
RULE_CFG_CONST = 3
RULE_INLINE = 4
RULE_POLY = 5
RULE_NAMES = {
    RULE_ADD_ZERO: "add_zero",
    RULE_CONST_FOLD: "const_fold",
    RULE_CFG_CONST: "cfg_constant",
    RULE_INLINE: "inline_single_block",
    RULE_POLY: "wrapping_polynomial",
}


@dataclass(frozen=True)
class TransformCase:
    name: str
    transform_class: str
    source_reader: StoreReader
    source: SemanticObject
    candidate_reader: StoreReader
    candidate: SemanticObject
    witness: bytes
    pure: bool


@dataclass(frozen=True)
class FaultCase:
    name: str
    fault_class: str
    source_reader: StoreReader
    source: SemanticObject
    candidate_reader: StoreReader
    candidate: SemanticObject
    witness: bytes | None
    pure: bool
    witness_rule: int | None


def _store_for(functions, objects) -> StoreReader:
    module = object_with_refs(Kind.MODULE, tuple(functions))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (*objects, *functions, module, root)))


def _resolve(reader: StoreReader, cid: bytes) -> SemanticObject:
    for obj in reader.objects():
        if obj.cid == cid:
            return obj
    raise KeyError(cid.hex())


def _function_types(reader: StoreReader, fn: SemanticObject):
    _, _, parameters, returns = _public_graph(reader, fn)
    return parameters, returns


def _make_function_like(reader: StoreReader, source: SemanticObject, blocks, entry=0) -> SemanticObject:
    parameters, returns = _function_types(reader, source)
    graph = graph_fragment(tuple(blocks), entry)
    return function(graph, parameters, returns)


def _candidate_from_blocks(reader: StoreReader, source: SemanticObject, blocks, *, extras=(), entry=0):
    return _replace_function(reader, source, entry, tuple(blocks), extras)


def _map_value(value: ValueRef, node_map: dict[int, int], replacement: dict[ValueRef, ValueRef]) -> ValueRef:
    if value in replacement:
        return replacement[value]
    if value.tag == 0:
        return value
    if value.block != 0 or value.index not in node_map:
        raise ValueError("unsupported witness remap")
    return ValueRef.node_result(0, node_map[value.index], value.result)


def _expected_add_zero(reader: StoreReader, source: SemanticObject, block_index: int, node_index: int) -> tuple[bytes, tuple[bytes, ...]]:
    entry, blocks, _, _ = _public_graph(reader, source)
    if entry != 0 or len(blocks) != 1 or block_index != 0:
        raise ValueError("add-zero witness requires one entry block")
    block = blocks[0]
    if node_index >= len(block.nodes):
        raise ValueError("add-zero node out of range")
    node = block.nodes[node_index]
    if node.operation != Operation.ADD_WRAP or len(node.operands) != 2 or len(node.result_types) != 1:
        raise ValueError("add-zero witness opcode mismatch")

    zero_operand = None
    zero_node = None
    other = None
    dependencies: list[bytes] = []
    for operand_index, operand in enumerate(node.operands):
        if operand.tag != 1 or operand.block != 0 or operand.index >= len(block.nodes):
            continue
        producer = block.nodes[operand.index]
        if producer.operation != Operation.CONSTANT or producer.entity is None:
            continue
        type_cid, value = _decode_constant(producer.entity, lambda cid: _resolve(reader, cid))
        if value == 0 and type_cid == node.result_types[0].cid:
            zero_operand = operand_index
            zero_node = operand.index
            other = node.operands[1 - operand_index]
            dependencies.append(producer.entity.cid)
            break
    if zero_operand is None or zero_node is None or other is None:
        raise ValueError("add-zero witness has no exact zero operand")

    # The zero producer may not be used by anything except the rewritten add.
    zero_ref = ValueRef.node_result(0, zero_node)
    for index, item in enumerate(block.nodes):
        if index != node_index and zero_ref in item.operands:
            raise ValueError("zero producer has another use")
    if zero_ref in block.terminator.values or any(zero_ref in args for _, args in block.terminator.edges):
        raise ValueError("zero producer escapes rewrite")

    remove = {zero_node, node_index}
    node_map: dict[int, int] = {}
    new_nodes: list[Node] = []
    replacement: dict[ValueRef, ValueRef] = {}
    for old_index, item in enumerate(block.nodes):
        if old_index == zero_node:
            continue
        if old_index == node_index:
            replacement[ValueRef.node_result(0, old_index)] = _map_value(other, node_map, replacement)
            continue
        operands = tuple(_map_value(value, node_map, replacement) for value in item.operands)
        new_index = len(new_nodes)
        new_nodes.append(Node(item.operation, operands, item.result_types, member=item.member, entity=item.entity, attributes=item.attributes))
        node_map[old_index] = new_index
        for result in range(len(item.result_types)):
            replacement[ValueRef.node_result(0, old_index, result)] = ValueRef.node_result(0, new_index, result)

    term = block.terminator
    mapped_term = Terminator(
        term.kind,
        tuple(_map_value(value, node_map, replacement) for value in term.values),
        tuple((target, tuple(_map_value(value, node_map, replacement) for value in args)) for target, args in term.edges),
        term.payload,
    )
    expected = _make_function_like(reader, source, (Block(block.parameters, tuple(new_nodes), mapped_term),))
    return expected.cid, tuple(dependencies)


def _expected_const_fold(reader: StoreReader, source: SemanticObject, block_index: int, node_index: int) -> tuple[bytes, tuple[bytes, ...]]:
    entry, blocks, _, returns = _public_graph(reader, source)
    if entry != 0 or len(blocks) != 1 or block_index != 0 or len(returns) != 1:
        raise ValueError("constant-fold witness requires one block/result")
    block = blocks[0]
    if len(block.nodes) != 3 or node_index != 2:
        raise ValueError("constant-fold fixture shape mismatch")
    left_node, right_node, node = block.nodes
    if left_node.operation != Operation.CONSTANT or right_node.operation != Operation.CONSTANT:
        raise ValueError("constant-fold inputs are not constants")
    if node.operation not in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
        raise ValueError("constant-fold opcode unsupported")
    if node.operands != (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)):
        raise ValueError("constant-fold dependency mismatch")
    if block.terminator != Terminator.return_((ValueRef.node_result(0, 2),)):
        raise ValueError("constant-fold result is not direct return")
    resolve = lambda cid: _resolve(reader, cid)
    left_type_cid, left = _decode_constant(left_node.entity, resolve)
    right_type_cid, right = _decode_constant(right_node.entity, resolve)
    if left_type_cid != right_type_cid or left_type_cid != node.result_types[0].cid:
        raise ValueError("constant-fold type mismatch")
    left_type = resolve(left_type_cid)
    width = decode_bits_width(left_type)
    mask = (1 << width) - 1
    value = {
        Operation.ADD_WRAP: (left + right) & mask,
        Operation.SUB_WRAP: (left - right) & mask,
        Operation.MUL_WRAP: (left * right) & mask,
    }[node.operation]
    folded = constant(left_type, value)
    expected_graph = graph_fragment([Block(block.parameters, (Node(Operation.CONSTANT, (), (left_type,), entity=folded),), Terminator.return_((ValueRef.node_result(0, 0),)))])
    parameters, returns = _function_types(reader, source)
    expected = function(expected_graph, parameters, returns)
    return expected.cid, (left_node.entity.cid, right_node.entity.cid)


def _remap_block_value(value: ValueRef, old_block: int, new_block: int) -> ValueRef:
    return ValueRef(value.tag, new_block if value.block == old_block else value.block, value.index, value.result)


def _expected_cfg(reader: StoreReader, source: SemanticObject, block_index: int, node_index: int) -> tuple[bytes, tuple[bytes, ...]]:
    entry, blocks, _, _ = _public_graph(reader, source)
    if entry != 0 or block_index != 0 or len(blocks) != 3:
        raise ValueError("cfg witness requires three-block fixture")
    entry_block = blocks[0]
    term = entry_block.terminator
    if term.kind != TerminatorKind.CONDITIONAL_BRANCH or node_index >= len(entry_block.nodes):
        raise ValueError("cfg witness terminator mismatch")
    condition = term.values[0]
    if condition != ValueRef.node_result(0, node_index):
        raise ValueError("cfg witness condition mismatch")
    node = entry_block.nodes[node_index]
    if node.operation != Operation.CONSTANT or node.entity is None:
        raise ValueError("cfg condition is not constant")
    _, value = _decode_constant(node.entity, lambda cid: _resolve(reader, cid))
    chosen_target, chosen_args = term.edges[0 if value else 1]
    if chosen_target not in (1, 2):
        raise ValueError("cfg fixture target mismatch")
    chosen = blocks[chosen_target]

    def remap(value_ref: ValueRef) -> ValueRef:
        return _remap_block_value(value_ref, chosen_target, 1)

    new_chosen = Block(
        chosen.parameters,
        tuple(Node(item.operation, tuple(remap(v) for v in item.operands), item.result_types, member=item.member, entity=item.entity, attributes=item.attributes) for item in chosen.nodes),
        Terminator(
            chosen.terminator.kind,
            tuple(remap(v) for v in chosen.terminator.values),
            tuple((1 if target == chosen_target else target, tuple(remap(v) for v in args)) for target, args in chosen.terminator.edges),
            chosen.terminator.payload,
        ),
    )
    # The production CFG pass runs DCE after branch selection, so the condition constant disappears.
    new_entry = Block(entry_block.parameters, (), Terminator.branch(1, chosen_args))
    expected = _make_function_like(reader, source, (new_entry, new_chosen))
    return expected.cid, (node.entity.cid,)


def _expected_inline(reader: StoreReader, source: SemanticObject, block_index: int, node_index: int) -> tuple[bytes, tuple[bytes, ...]]:
    entry, blocks, _, _ = _public_graph(reader, source)
    if entry != 0 or len(blocks) != 1 or block_index != 0:
        raise ValueError("inline witness requires one caller block")
    block = blocks[0]
    if len(block.nodes) != 1 or node_index != 0:
        raise ValueError("inline fixture must contain one call")
    call = block.nodes[0]
    if call.operation != Operation.CALL_DIRECT or call.entity is None:
        raise ValueError("inline witness node is not direct call")
    callee = _resolve(reader, call.entity.cid)
    callee_entry, callee_blocks, _, _ = _public_graph(reader, callee)
    if callee_entry != 0 or len(callee_blocks) != 1:
        raise ValueError("inline callee must be one block")
    callee_block = callee_blocks[0]
    if any(item.operation not in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.CONSTANT) for item in callee_block.nodes):
        raise ValueError("inline callee is not pure arithmetic")
    mapping = {ValueRef.parameter(0, index): operand for index, operand in enumerate(call.operands)}
    nodes: list[Node] = []
    for old_index, item in enumerate(callee_block.nodes):
        operands = tuple(mapping.get(value, value) for value in item.operands)
        new_index = len(nodes)
        nodes.append(Node(item.operation, operands, item.result_types, member=item.member, entity=item.entity, attributes=item.attributes))
        for result in range(len(item.result_types)):
            mapping[ValueRef.node_result(0, old_index, result)] = ValueRef.node_result(0, new_index, result)
    returns = tuple(mapping.get(value, value) for value in callee_block.terminator.values)
    expected = _make_function_like(reader, source, (Block(block.parameters, tuple(nodes), Terminator.return_(returns)),))
    callee_graph, _, _, _ = _public_graph(reader, callee)
    # Function CID plus its graph CID are the exact external dependencies used by this proof.
    graph_obj = _resolve(reader, callee.references[0])
    return expected.cid, (callee.cid, graph_obj.cid)


def _poly_expected(reader: StoreReader, source: SemanticObject, candidate_reader: StoreReader, candidate: SemanticObject) -> tuple[bool, tuple[bytes, ...]]:
    left = _expr_from_function(reader, source)
    right = _expr_from_function(candidate_reader, candidate)
    if left is None or right is None:
        return False, ()
    left_expr, left_width, left_params = left
    right_expr, right_width, right_params = right
    if (left_width, left_params) != (right_width, right_params):
        return False, ()
    lhs = _poly(left_expr, left_width, left_params, 256)
    rhs = _poly(right_expr, right_width, right_params, 256)
    _, _, params, returns = _public_graph(reader, source)
    dependencies = tuple(item.cid for item in (*params, *returns))
    return lhs is not None and lhs == rhs, dependencies


def encode_witness(rule: int, source: bytes, candidate: bytes, block: int, node: int, dependencies: tuple[bytes, ...]) -> bytes:
    if rule not in RULE_NAMES or len(source) != 32 or len(candidate) != 32 or block < 0 or block > 65535 or node < 0 or node > 65535:
        raise ValueError("invalid witness")
    if len(dependencies) > 255 or any(len(cid) != 32 for cid in dependencies):
        raise ValueError("invalid witness dependencies")
    return b"".join(
        (
            MAGIC,
            bytes((WITNESS_VERSION, rule)),
            block.to_bytes(2, "little"),
            node.to_bytes(2, "little"),
            source,
            candidate,
            bytes((len(dependencies),)),
            b"".join(dependencies),
        )
    )


def decode_witness(data: bytes):
    if len(data) < 75 or data[:4] != MAGIC or data[4] != WITNESS_VERSION:
        raise ValueError("invalid transformation witness header")
    rule = data[5]
    if rule not in RULE_NAMES:
        raise ValueError("unknown transformation witness rule")
    block = int.from_bytes(data[6:8], "little")
    node = int.from_bytes(data[8:10], "little")
    subject = data[10:42]
    candidate = data[42:74]
    count = data[74]
    expected = 75 + 32 * count
    if len(data) != expected:
        raise ValueError("invalid transformation witness length")
    dependencies = tuple(data[75 + 32 * index : 107 + 32 * index] for index in range(count))
    return rule, block, node, subject, candidate, dependencies


def check_witness(source_reader: StoreReader, candidate_reader: StoreReader, witness: bytes) -> bool:
    rule, block, node, subject_cid, candidate_cid, dependencies = decode_witness(witness)
    source = _resolve(source_reader, subject_cid)
    candidate = _resolve(candidate_reader, candidate_cid)
    if source.kind != Kind.FUNCTION or candidate.kind != Kind.FUNCTION:
        return False
    verify_store(candidate_reader)
    if rule == RULE_ADD_ZERO:
        expected_cid, expected_dependencies = _expected_add_zero(source_reader, source, block, node)
        return candidate.cid == expected_cid and dependencies == expected_dependencies
    if rule == RULE_CONST_FOLD:
        expected_cid, expected_dependencies = _expected_const_fold(source_reader, source, block, node)
        return candidate.cid == expected_cid and dependencies == expected_dependencies
    if rule == RULE_CFG_CONST:
        expected_cid, expected_dependencies = _expected_cfg(source_reader, source, block, node)
        return candidate.cid == expected_cid and dependencies == expected_dependencies
    if rule == RULE_INLINE:
        expected_cid, expected_dependencies = _expected_inline(source_reader, source, block, node)
        return candidate.cid == expected_cid and dependencies == expected_dependencies
    if rule == RULE_POLY:
        equivalent, expected_dependencies = _poly_expected(source_reader, source, candidate_reader, candidate)
        return equivalent and dependencies == expected_dependencies
    return False


def exact_finite_translation_validation(source_reader: StoreReader, source: SemanticObject, candidate_reader: StoreReader, candidate: SemanticObject) -> bool:
    """Exact oracle for the concrete tiny-bitwidth pure corpus, not production semantics."""
    verify_store(source_reader)
    verify_store(candidate_reader)
    _, _, parameters, returns = _public_graph(source_reader, source)
    _, _, candidate_parameters, candidate_returns = _public_graph(candidate_reader, candidate)
    if tuple(item.cid for item in parameters) != tuple(item.cid for item in candidate_parameters):
        return False
    if tuple(item.cid for item in returns) != tuple(item.cid for item in candidate_returns):
        return False
    widths = tuple(decode_bits_width(item) for item in parameters)
    if any(width > 4 for width in widths):
        raise ValueError("finite oracle intentionally limited to <=4-bit parameters")
    domains = [range(1 << width) for width in widths]
    for arguments in itertools.product(*domains):
        if execute(source_reader, source.cid, arguments) != execute(candidate_reader, candidate.cid, arguments):
            return False
    return True


def _witness_for(rule: int, source_reader: StoreReader, source: SemanticObject, candidate_reader: StoreReader, candidate: SemanticObject, block: int, node: int) -> bytes:
    if rule == RULE_ADD_ZERO:
        _, dependencies = _expected_add_zero(source_reader, source, block, node)
    elif rule == RULE_CONST_FOLD:
        _, dependencies = _expected_const_fold(source_reader, source, block, node)
    elif rule == RULE_CFG_CONST:
        _, dependencies = _expected_cfg(source_reader, source, block, node)
    elif rule == RULE_INLINE:
        _, dependencies = _expected_inline(source_reader, source, block, node)
    elif rule == RULE_POLY:
        ok, dependencies = _poly_expected(source_reader, source, candidate_reader, candidate)
        if not ok:
            # Fault witnesses still carry exact type dependencies; semantic failure is checked later.
            _, _, params, returns = _public_graph(source_reader, source)
            dependencies = tuple(item.cid for item in (*params, *returns))
    else:
        raise ValueError("unknown rule")
    return encode_witness(rule, source.cid, candidate.cid, block, node, dependencies)


def _replace_with_graph_unverified(reader: StoreReader, source: SemanticObject, graph: SemanticObject) -> tuple[StoreReader, SemanticObject]:
    parameters, returns = _function_types(reader, source)
    candidate = function(graph, parameters, returns)
    objects = {obj.cid: obj for obj in reader.objects()}
    objects[graph.cid] = graph
    objects[candidate.cid] = candidate
    root = objects[reader.root_cid]
    new_root_children = []
    for child_cid in root.references:
        child = objects[child_cid]
        if child.kind == Kind.MODULE and source.cid in child.references:
            members = [objects[cid] for cid in child.references]
            members = [candidate if item.cid == source.cid else item for item in members]
            child = object_with_refs(Kind.MODULE, members)
            objects[child.cid] = child
        new_root_children.append(child)
    new_root = object_with_refs(Kind.PROGRAM_ROOT, new_root_children)
    objects[new_root.cid] = new_root
    reachable = {}
    pending = [new_root.cid]
    while pending:
        cid = pending.pop()
        if cid in reachable:
            continue
        obj = objects[cid]
        reachable[cid] = obj
        pending.extend(obj.references)
    return StoreReader(write_store(new_root.cid, reachable.values())), candidate


def build_corpus() -> tuple[tuple[TransformCase, ...], tuple[FaultCase, ...]]:
    b1 = bits_type(1)
    b3 = bits_type(3)
    io = effect_type(EffectDomain.IO)
    zero = constant(b3, 0)
    one = constant(b3, 1)
    two = constant(b3, 2)
    three = constant(b3, 3)
    six = constant(b3, 6)
    seven = constant(b3, 7)
    false_value = constant(b1, 0)

    cases: list[TransformCase] = []
    faults: list[FaultCase] = []

    # Local arithmetic rewrite while preserving an explicit effect step.
    local_graph = graph_fragment([
        Block(
            (b3, io),
            (
                Node(Operation.CONSTANT, (), (b3,), entity=zero),
                Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (b3,)),
                Node(Operation.EFFECT_STEP, (ValueRef.parameter(0, 1),), (io,)),
            ),
            Terminator.return_((ValueRef.node_result(0, 1), ValueRef.node_result(0, 2))),
        )
    ])
    local_fn = function(local_graph, (b3, io), (b3, io))
    local_reader = _store_for((local_fn,), (b3, io, zero, local_graph))
    local_candidate_reader, local_candidate, changed = _simplify_local(local_reader, local_fn)
    assert changed
    local_witness = _witness_for(RULE_ADD_ZERO, local_reader, local_fn, local_candidate_reader, local_candidate, 0, 1)
    cases.append(TransformCase("local_add_zero_effect_preserved", "local_rewrite", local_reader, local_fn, local_candidate_reader, local_candidate, local_witness, False))
    dropped_reader, dropped_fn = _candidate_from_blocks(
        local_reader,
        local_fn,
        (Block((b3, io), (), Terminator.return_((ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)))),),
    )
    faults.append(FaultCase("dropped_effect", "dropped_effect", local_reader, local_fn, dropped_reader, dropped_fn, _witness_for(RULE_ADD_ZERO, local_reader, local_fn, dropped_reader, dropped_fn, 0, 1), False, RULE_ADD_ZERO))

    # Ordinary constant fold.
    fold_graph = graph_fragment([
        Block(
            (),
            (
                Node(Operation.CONSTANT, (), (b3,), entity=two),
                Node(Operation.CONSTANT, (), (b3,), entity=three),
                Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b3,)),
            ),
            Terminator.return_((ValueRef.node_result(0, 2),)),
        )
    ])
    fold_fn = function(fold_graph, (), (b3,))
    fold_reader = _store_for((fold_fn,), (b3, two, three, fold_graph))
    fold_candidate_reader, fold_candidate, changed = _simplify_local(fold_reader, fold_fn)
    assert changed
    fold_witness = _witness_for(RULE_CONST_FOLD, fold_reader, fold_fn, fold_candidate_reader, fold_candidate, 0, 2)
    cases.append(TransformCase("local_const_fold", "local_rewrite", fold_reader, fold_fn, fold_candidate_reader, fold_candidate, fold_witness, True))
    wrong_graph = graph_fragment([Block((), (Node(Operation.CONSTANT, (), (b3,), entity=six),), Terminator.return_((ValueRef.node_result(0, 0),)))])
    wrong_reader, wrong_fn = _candidate_from_blocks(fold_reader, fold_fn, (Block((), (Node(Operation.CONSTANT, (), (b3,), entity=six),), Terminator.return_((ValueRef.node_result(0, 0),))),), extras=(six,))
    faults.append(FaultCase("wrong_constant", "wrong_constant", fold_reader, fold_fn, wrong_reader, wrong_fn, _witness_for(RULE_CONST_FOLD, fold_reader, fold_fn, wrong_reader, wrong_fn, 0, 2), True, RULE_CONST_FOLD))

    # Overflow-sensitive constant fold: 7 + 1 wraps to zero at b3.
    overflow_graph = graph_fragment([
        Block((), (Node(Operation.CONSTANT, (), (b3,), entity=seven), Node(Operation.CONSTANT, (), (b3,), entity=one), Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b3,))), Terminator.return_((ValueRef.node_result(0, 2),)))
    ])
    overflow_fn = function(overflow_graph, (), (b3,))
    overflow_reader = _store_for((overflow_fn,), (b3, seven, one, overflow_graph))
    overflow_candidate_reader, overflow_candidate, changed = _simplify_local(overflow_reader, overflow_fn)
    assert changed
    cases.append(TransformCase("local_wrap_overflow_fold", "local_rewrite", overflow_reader, overflow_fn, overflow_candidate_reader, overflow_candidate, _witness_for(RULE_CONST_FOLD, overflow_reader, overflow_fn, overflow_candidate_reader, overflow_candidate, 0, 2), True))
    saturation_reader, saturation_fn = _candidate_from_blocks(overflow_reader, overflow_fn, (Block((), (Node(Operation.CONSTANT, (), (b3,), entity=seven),), Terminator.return_((ValueRef.node_result(0, 0),))),))
    faults.append(FaultCase("overflow_assumption", "overflow_assumption", overflow_reader, overflow_fn, saturation_reader, saturation_fn, _witness_for(RULE_CONST_FOLD, overflow_reader, overflow_fn, saturation_reader, saturation_fn, 0, 2), True, RULE_CONST_FOLD))

    # CFG constant branch with observably different arms.
    cfg_graph = graph_fragment([
        Block((b3,), (Node(Operation.CONSTANT, (), (b1,), entity=false_value),), Terminator.conditional_branch(ValueRef.node_result(0, 0), 1, (ValueRef.parameter(0, 0),), 2, (ValueRef.parameter(0, 0),))),
        Block((b3,), (Node(Operation.CONSTANT, (), (b3,), entity=one), Node(Operation.ADD_WRAP, (ValueRef.parameter(1, 0), ValueRef.node_result(1, 0)), (b3,))), Terminator.return_((ValueRef.node_result(1, 1),))),
        Block((b3,), (Node(Operation.CONSTANT, (), (b3,), entity=two), Node(Operation.ADD_WRAP, (ValueRef.parameter(2, 0), ValueRef.node_result(2, 0)), (b3,))), Terminator.return_((ValueRef.node_result(2, 1),))),
    ])
    cfg_fn = function(cfg_graph, (b3,), (b3,))
    cfg_reader = _store_for((cfg_fn,), (b1, b3, false_value, one, two, cfg_graph))
    cfg_candidate_reader, cfg_candidate, changed = _simplify_cfg(cfg_reader, cfg_fn)
    assert changed
    cfg_witness = _witness_for(RULE_CFG_CONST, cfg_reader, cfg_fn, cfg_candidate_reader, cfg_candidate, 0, 0)
    cases.append(TransformCase("cfg_constant_branch", "cfg", cfg_reader, cfg_fn, cfg_candidate_reader, cfg_candidate, cfg_witness, True))
    # Wrong-arm candidate is otherwise structurally valid.
    wrong_entry = Block(cfg_graph and _public_graph(cfg_reader, cfg_fn)[1][0].parameters, _public_graph(cfg_reader, cfg_fn)[1][0].nodes, Terminator.branch(1, (ValueRef.parameter(0, 0),)))
    arm1 = _public_graph(cfg_reader, cfg_fn)[1][1]
    wrong_arm = Block(arm1.parameters, tuple(Node(n.operation, tuple(_remap_block_value(v, 1, 1) for v in n.operands), n.result_types, member=n.member, entity=n.entity, attributes=n.attributes) for n in arm1.nodes), arm1.terminator)
    wrong_cfg_reader, wrong_cfg_fn = _candidate_from_blocks(cfg_reader, cfg_fn, (wrong_entry, wrong_arm))
    faults.append(FaultCase("wrong_cfg_edge", "wrong_control", cfg_reader, cfg_fn, wrong_cfg_reader, wrong_cfg_fn, _witness_for(RULE_CFG_CONST, cfg_reader, cfg_fn, wrong_cfg_reader, wrong_cfg_fn, 0, 0), True, RULE_CFG_CONST))

    # Pure single-block direct-call inlining.
    callee_graph = graph_fragment([Block((b3, b3), (Node(Operation.SUB_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b3,)),), Terminator.return_((ValueRef.node_result(0, 0),)))])
    callee = function(callee_graph, (b3, b3), (b3,))
    caller_graph = graph_fragment([Block((b3, b3), (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b3,), entity=callee),), Terminator.return_((ValueRef.node_result(0, 0),)))])
    caller = function(caller_graph, (b3, b3), (b3,))
    inline_reader = _store_for((callee, caller), (b3, callee_graph, caller_graph))
    inline_candidate_reader, inline_candidate, changed, _ = _inline_direct_calls(inline_reader, caller, OptimizationBudget(inline_cold_nodes=4, search_steps=0), None)
    assert changed
    inline_witness = _witness_for(RULE_INLINE, inline_reader, caller, inline_candidate_reader, inline_candidate, 0, 0)
    cases.append(TransformCase("inline_pure_single_block", "inline", inline_reader, caller, inline_candidate_reader, inline_candidate, inline_witness, True))
    swapped = Block((b3, b3), (Node(Operation.SUB_WRAP, (ValueRef.parameter(0, 1), ValueRef.parameter(0, 0)), (b3,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
    swapped_reader, swapped_fn = _candidate_from_blocks(inline_reader, caller, (swapped,))
    faults.append(FaultCase("wrong_inline_argument", "dropped_dependency", inline_reader, caller, swapped_reader, swapped_fn, _witness_for(RULE_INLINE, inline_reader, caller, swapped_reader, swapped_fn, 0, 0), True, RULE_INLINE))

    # Search-generated arithmetic equivalence.
    search_graph = graph_fragment([Block((b3,), (Node(Operation.CONSTANT, (), (b3,), entity=two), Node(Operation.MUL_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0)), (b3,))), Terminator.return_((ValueRef.node_result(0, 1),)))])
    search_fn = function(search_graph, (b3,), (b3,))
    search_reader = _store_for((search_fn,), (b3, two, search_graph))
    search_candidate_reader, search_candidate = _build_expr_candidate(search_reader, search_fn, _Expr.op("add", _Expr.param(0), _Expr.param(0)), 3)
    search_witness = _witness_for(RULE_POLY, search_reader, search_fn, search_candidate_reader, search_candidate, 0, 0)
    cases.append(TransformCase("search_mul2_to_add", "search", search_reader, search_fn, search_candidate_reader, search_candidate, search_witness, True))
    dropped_dep_reader, dropped_dep_fn = _build_expr_candidate(search_reader, search_fn, _Expr.param(0), 3)
    faults.append(FaultCase("dropped_dependency", "dropped_dependency", search_reader, search_fn, dropped_dep_reader, dropped_dep_fn, _witness_for(RULE_POLY, search_reader, search_fn, dropped_dep_reader, dropped_dep_fn, 0, 0), True, RULE_POLY))

    # Structurally invalid dominance fault: node 0 reads future node 1.
    invalid_graph = graph_fragment([Block((b3,), (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 1)), (b3,)), Node(Operation.CONSTANT, (), (b3,), entity=two)), Terminator.return_((ValueRef.node_result(0, 0),)))])
    invalid_reader, invalid_fn = _replace_with_graph_unverified(search_reader, search_fn, invalid_graph)
    invalid_witness = encode_witness(RULE_POLY, search_fn.cid, invalid_fn.cid, 0, 0, (b3.cid, b3.cid))
    faults.append(FaultCase("dominance_error", "dominance_error", search_reader, search_fn, invalid_reader, invalid_fn, invalid_witness, True, RULE_POLY))

    for case in cases:
        verify_store(case.source_reader)
        verify_store(case.candidate_reader)
        assert check_witness(case.source_reader, case.candidate_reader, case.witness)
        if case.pure:
            assert exact_finite_translation_validation(case.source_reader, case.source, case.candidate_reader, case.candidate)
    return tuple(cases), tuple(faults)


def _verifier_accepts(reader: StoreReader) -> bool:
    try:
        verify_store(reader)
        return True
    except Exception:
        return False


def _witness_accepts(fault: FaultCase) -> bool:
    if fault.witness is None:
        return False
    try:
        return check_witness(fault.source_reader, fault.candidate_reader, fault.witness)
    except Exception:
        return False


def _translation_accepts(fault: FaultCase) -> bool | None:
    if not fault.pure:
        return None
    try:
        return exact_finite_translation_validation(fault.source_reader, fault.source, fault.candidate_reader, fault.candidate)
    except Exception:
        return False


def _source_spans(path: Path, names: tuple[str, ...]) -> int:
    tree = ast.parse(path.read_text())
    wanted = set(names)
    total = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in wanted:
            total += (node.end_lineno or node.lineno) - node.lineno + 1
    return total


def implementation_sizes() -> dict:
    return {
        "existing_trusted_local_cfg_inline_generator_lines": _source_spans(OPTIMIZER, ("_simplify_local", "_dce", "_simplify_cfg", "_inline_direct_calls")),
        "existing_exact_polynomial_validator_lines": _source_spans(OPTIMIZER, ("_expr_from_function", "_poly")),
        "benchmark_witness_codec_checker_lines": _source_spans(THIS_FILE, ("encode_witness", "decode_witness", "check_witness", "_expected_add_zero", "_expected_const_fold", "_expected_cfg", "_expected_inline")),
        "benchmark_finite_oracle_lines": _source_spans(THIS_FILE, ("exact_finite_translation_validation",)),
        "solver_dependency_lines": 0,
    }


def deterministic_result() -> dict:
    cases, faults = build_corpus()
    correct_records = []
    for case in cases:
        translation = exact_finite_translation_validation(case.source_reader, case.source, case.candidate_reader, case.candidate) if case.pure else None
        correct_records.append({
            "name": case.name,
            "class": case.transform_class,
            "source_cid": case.source.cid.hex(),
            "candidate_cid": case.candidate.cid.hex(),
            "candidate_store_bytes": len(case.candidate_reader.data),
            "witness_bytes": len(case.witness),
            "witness_sha256": hashlib.sha256(case.witness).hexdigest(),
            "verifier_accepts": _verifier_accepts(case.candidate_reader),
            "witness_accepts": check_witness(case.source_reader, case.candidate_reader, case.witness),
            "finite_translation_accepts": translation,
        })
    fault_records = []
    for fault in faults:
        verifier = _verifier_accepts(fault.candidate_reader)
        witness = _witness_accepts(fault)
        translation = _translation_accepts(fault)
        fault_records.append({
            "name": fault.name,
            "class": fault.fault_class,
            "candidate_cid": fault.candidate.cid.hex(),
            "verifier_accepts": verifier,
            "witness_accepts": witness,
            "finite_translation_accepts": translation,
            "detected_by_verifier": not verifier,
            "detected_by_witness": not witness,
            "detected_by_finite_translation": None if translation is None else not translation,
            "witness_rejection_preserves_source": (not witness),
        })
    return {
        "issue": "OI-19",
        "scope": "transformation correctness mechanism granularity",
        "semantic_identity_note": "witnesses and validation records are compiler artifacts only; no proof bytes enter canonical XAX identity",
        "corpus": correct_records,
        "faults": fault_records,
        "fault_detection": {
            "verifier": sum(item["detected_by_verifier"] for item in fault_records),
            "verifier_total": len(fault_records),
            "witness": sum(item["detected_by_witness"] for item in fault_records),
            "witness_total": len(fault_records),
            "finite_translation": sum(item["detected_by_finite_translation"] is True for item in fault_records),
            "finite_translation_applicable": sum(item["detected_by_finite_translation"] is not None for item in fault_records),
        },
        "false_rejection": {
            "verifier": sum(not item["verifier_accepts"] for item in correct_records),
            "witness": sum(not item["witness_accepts"] for item in correct_records),
            "finite_translation": sum(item["finite_translation_accepts"] is False for item in correct_records),
        },
        "implementation": implementation_sizes(),
        "decision": {
            "ordinary_verifier": "always required for graph/type/effect/dominance validity; it is not semantic equivalence evidence",
            "trusted_conventional_rules": "keep current conservative local/CFG/inlining rule premises plus ordinary verifier; the witness prototype is not adopted because it would add a second checker unless it fully replaces the trusted rule implementation",
            "witness_migration_threshold": "move a conventional rule family out of the trusted generator only when one independent witness checker covers the complete family, rejects all family fault fixtures, and its correctness-critical implementation is smaller than the trusted rule code it replaces; this prototype is 223 checker/codec lines versus 276 current local/CFG/inline generator lines but covers only the measured subset",
            "search_generated_wrapping_arithmetic": "use exact polynomial normal-form translation validation plus ordinary verifier; no proof object or solver is required",
            "effectful_or_resource_transform": "verifier alone is insufficient; any future untrusted transform that can alter effects/resources requires a checker that covers the observable effect/resource relation, otherwise reject",
            "solver": "not justified by this corpus; no dependency added",
            "finite_oracle": "test-only exact oracle for <=4-bit pure concrete fixtures; not production semantics",
        },
    }


def _measure_call(call: Callable[[], bool], repeats: int = 21):
    samples = []
    peaks = []
    for _ in range(repeats):
        tracemalloc.start()
        start = time.perf_counter_ns()
        accepted = call()
        elapsed = time.perf_counter_ns() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if not accepted:
            raise AssertionError("correct validation unexpectedly rejected")
        samples.append(elapsed)
        peaks.append(peak)
    return samples, peaks


def measure_raw() -> dict:
    cases, _ = build_corpus()
    records = []
    for case in cases:
        validators = {
            "verifier": lambda c=case: (_verifier_accepts(c.candidate_reader)),
            "witness": lambda c=case: check_witness(c.source_reader, c.candidate_reader, c.witness),
        }
        if case.pure:
            validators["finite_translation"] = lambda c=case: exact_finite_translation_validation(c.source_reader, c.source, c.candidate_reader, c.candidate)
        if case.transform_class == "search":
            validators["polynomial_translation"] = lambda c=case: _poly_expected(c.source_reader, c.source, c.candidate_reader, c.candidate)[0] and _verifier_accepts(c.candidate_reader)
        for mechanism, validator in validators.items():
            elapsed, peaks = _measure_call(validator)
            records.append({
                "case": case.name,
                "class": case.transform_class,
                "mechanism": mechanism,
                "elapsed_ns": elapsed,
                "peak_bytes": peaks,
            })
    return {
        "clock": "perf_counter_ns",
        "memory": "tracemalloc peak bytes; host-observed and non-semantic",
        "environment": {
            "machine": platform.machine(),
            "system": platform.system(),
            "python": platform.python_version(),
        },
        "samples_per_cell": 21,
        "records": records,
    }


def summarize_raw(raw: dict) -> list[dict]:
    out = []
    for record in raw["records"]:
        elapsed = record["elapsed_ns"]
        peaks = record["peak_bytes"]
        median = statistics.median(elapsed)
        out.append({
            "case": record["case"],
            "class": record["class"],
            "mechanism": record["mechanism"],
            "median_ns": median,
            "p10_ns": sorted(elapsed)[max(0, int(len(elapsed) * 0.10) - 1)],
            "p90_ns": sorted(elapsed)[min(len(elapsed) - 1, int(len(elapsed) * 0.90))],
            "median_peak_bytes": statistics.median(peaks),
            "candidates_per_second": 1_000_000_000.0 / median if median else None,
        })
    return out


def evidence_from_raw(raw: dict) -> dict:
    result = deterministic_result()
    result["host_observations"] = {
        "classification": "non-semantic compile-tooling measurements",
        "raw_sha256": hashlib.sha256((json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest(),
        "summary": summarize_raw(raw),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", action="store_true")
    args = parser.parse_args()
    if args.measure or not RAW.exists():
        raw = measure_raw()
        RAW.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    else:
        raw = json.loads(RAW.read_text())
    evidence = evidence_from_raw(raw)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
