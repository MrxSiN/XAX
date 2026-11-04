"""Lowering analysis shared by the views-profile code generators (ADR-145, ADR-151): RISC-V and x86-64.

Everything here is independent of the instruction set: the call closure checked against the target's operation
and terminator sets, machine widths, the aggregate plan (made values, call results, field aliases), borrowed-view
aliases, view extents, and the linear scan over block-liveness interval hulls.  ``isa`` names the diagnostic
family (``XAX.<isa>.*`` codes and ``<isa>-*`` rules), so each generator keeps its own exact diagnostics.
"""

from __future__ import annotations

from typing import Sequence

from xax_compiler import (
    RESOURCE_EFFECT_OPERATIONS,
    Kind,
    Operation,
    SemanticObject,
    TerminatorKind,
    ValueRef,
    _decode_array_type,
    _decode_function_interface,
    _decode_tuple_type,
    _heap_view_info,
    _is_erased_proof_function,
    _is_proof_type,
    borrowed_view_returns,
    decode_bits_width,
    fail,
    parse_function_graph,
)

MAX_FIELDS = 255  # an aggregate's fields are addressed with 12-bit (RISC-V) or 8-bit-scaled doubleword offsets
# Every operation both views generators lower; any other one in a closure rejects with ``<isa>-OP-LOWERED``.
LOWERED_OPERATIONS = tuple(sorted({int(op) for op in (
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_OR, Operation.BIT_AND, Operation.UDIV,
    Operation.UREM, Operation.ROTATE_RIGHT, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.CONSTANT, Operation.INT_COMPARE,
    Operation.CALL_DIRECT, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.AGGREGATE_GET, Operation.AGGREGATE_MAKE,
    *RESOURCE_EFFECT_OPERATIONS)}))


def function_closure(entry: SemanticObject, resolve, operations, terminators, isa: str) -> tuple[SemanticObject, ...]:
    functions: dict[bytes, SemanticObject] = {}
    pending = [entry]
    while pending:
        function = pending.pop()
        if function.cid in functions:
            continue
        functions[function.cid] = function
        graph_object, _parameters, _returns = _decode_function_interface(function, resolve)
        for block in parse_function_graph(function, resolve).blocks:
            for node in block.nodes:
                if node.operation not in operations:
                    fail(f"XAX.{isa}.UNSUPPORTED_OPERATION", graph_object.cid.hex(), f"{isa}-OP-TARGET-SUPPORTED", list(operations), node.operation)
                if node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve):
                    pending.append(node.entity)
            if block.terminator.kind not in terminators:
                fail(f"XAX.{isa}.UNSUPPORTED_TERMINATOR", graph_object.cid.hex(), f"{isa}-TERMINATOR-TARGET-SUPPORTED", list(terminators), block.terminator.kind)
    return tuple(functions[cid] for cid in sorted(functions))


def machine_width(resolve, cid: bytes, where: str, isa: str) -> int | None:
    obj = resolve(cid)
    if _is_proof_type(obj):
        return None
    if obj.kind == Kind.TYPE and obj.body[:1] == b"\x02":
        return 64  # a pointer (views profile, ADR-145): one 64-bit address
    if obj.kind == Kind.TYPE and obj.body[:1] == b"\x01":
        width = decode_bits_width(obj)
        if width <= 64:
            return width
    fail(f"XAX.{isa}.VALUE", where, f"{isa}-VALUE-BITS", "bits<N <= 64> or a proof value", cid.hex())


def aggregate_fields(resolve, cid: bytes) -> int | None:
    """Views profile (ADR-151): the field count of a tuple or array of ``bits<N <= 64>``; None for any other type."""
    obj = resolve(cid)
    if obj.kind != Kind.TYPE or obj.body[:1] not in (b"\x08", b"\x09"):
        return None
    if obj.body[:1] == b"\x08":
        fields = _decode_tuple_type(obj, resolve)
    else:
        element, count = _decode_array_type(obj, resolve)
        fields = (element,) * count
    scalar = lambda field: resolve(field).body[:1] == b"\x01" and decode_bits_width(resolve(field)) <= 64  # noqa: E731
    return len(fields) if 0 < len(fields) <= MAX_FIELDS and all(scalar(field) for field in fields) else None


def result_fields(function: SemanticObject, resolve, isa: str) -> int | None:
    """The field count when ``function`` returns an aggregate (its only non-proof result), else None."""
    _graph, _parameters, returns = _decode_function_interface(function, resolve)
    fields = [aggregate_fields(resolve, cid) for cid in returns]
    if not any(count is not None for count in fields):
        return None
    machine = [cid for cid, count in zip(returns, fields) if count is None and not _is_proof_type(resolve(cid))]
    if len(fields) - fields.count(None) != 1 or machine:
        fail(f"XAX.{isa}.ABI", function.cid.hex(), f"{isa}-AGGREGATE-RESULT", "one aggregate and proof values only", len(returns))
    return next(count for count in fields if count is not None)


def allocate_registers(graph, order: Sequence[int], machine: set[ValueRef], allocatable: Sequence[int]) -> dict[ValueRef, int]:
    """Linear scan over interval hulls from block-level liveness.

    A value's interval covers its definition, every use, and every block
    boundary where it is live; values that do not fit in ``allocatable``
    stay in frame slots.  Edge arguments are uses at their block's end.
    """
    position = 0
    block_start: dict[int, int] = {}
    block_end: dict[int, int] = {}
    points: dict[ValueRef, list[int]] = {}
    successors: dict[int, tuple[int, ...]] = {}
    uses: dict[int, set[ValueRef]] = {}
    definitions: dict[int, set[ValueRef]] = {}
    for block_index in order:
        block = graph.blocks[block_index]
        block_start[block_index] = position
        defined = {ValueRef.parameter(block_index, index) for index in range(len(block.parameters))}
        used: set[ValueRef] = set()
        for ref in defined:
            points.setdefault(ref, []).append(position)
        for node_index, node in enumerate(block.nodes):
            position += 1
            for operand in node.operands:
                points.setdefault(operand, []).append(position)
                if operand not in defined:
                    used.add(operand)
            for result_index in range(len(node.results)):
                ref = ValueRef.node_result(block_index, node_index, result_index)
                defined.add(ref)
                points.setdefault(ref, []).append(position)
        position += 1
        terminator = block.terminator
        for value in (*terminator.values, *(argument for _target, arguments in terminator.edges for argument in arguments)):
            points.setdefault(value, []).append(position)
            if value not in defined:
                used.add(value)
        block_end[block_index] = position
        position += 1
        successors[block_index] = tuple(target for target, _arguments in terminator.edges)
        uses[block_index], definitions[block_index] = used, defined
    live_in: dict[int, set[ValueRef]] = {index: set() for index in order}
    live_out: dict[int, set[ValueRef]] = {index: set() for index in order}
    changed = True
    while changed:
        changed = False
        for block_index in reversed(order):
            out = set()
            for target in successors[block_index]:
                out |= {ref for ref in live_in[target] if not (ref.tag == 0 and ref.block == target)}
            new_in = uses[block_index] | (out - definitions[block_index])
            if out != live_out[block_index] or new_in != live_in[block_index]:
                live_out[block_index], live_in[block_index], changed = out, new_in, True
    for block_index in order:
        for ref in live_in[block_index]:
            points.setdefault(ref, []).append(block_start[block_index])
        for ref in live_out[block_index]:
            points.setdefault(ref, []).append(block_end[block_index])
    key = lambda ref: (ref.tag, ref.block, ref.index, ref.result)
    intervals = sorted(((min(points[ref]), max(points[ref]), ref) for ref in machine if ref in points), key=lambda item: (item[0], item[1], key(item[2])))
    assignment: dict[ValueRef, int] = {}
    active: list[tuple[int, ValueRef]] = []  # (end, value)
    free = list(allocatable)
    for start, end, ref in intervals:
        for item in [item for item in active if item[0] < start]:
            active.remove(item)
            free.append(assignment[item[1]])
        if free:
            free.sort()
            assignment[ref] = free.pop(0)
            active.append((end, ref))
        else:
            furthest = max(active, key=lambda item: (item[0], key(item[1])))
            if furthest[0] > end:
                assignment[ref] = assignment.pop(furthest[1])
                active.remove(furthest)
                active.append((end, ref))
    return assignment


class Rewritten:
    """A parsed graph with borrowed-view call results replaced by the pointers passed in (views profile)."""

    def __init__(self, entry, blocks):
        self.entry, self.blocks = entry, blocks


def rewrite_borrowed_views(graph, resolve):
    """``(graph, elided results)``: each pointer a direct call gives back as a borrowed view (``borrowed_view_returns``)
    is the pointer passed in, so its uses read that operand instead (ADR-145)."""
    alias: dict[ValueRef, ValueRef] = {}
    for block_index, block in enumerate(graph.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation != Operation.CALL_DIRECT or _is_erased_proof_function(node.entity, resolve):
                continue
            _graph, callee_parameters, callee_returns = _decode_function_interface(node.entity, resolve)
            for result_index, parameter_index in borrowed_view_returns(callee_parameters, callee_returns, resolve).items():
                alias[ValueRef.node_result(block_index, node_index, result_index)] = node.operands[parameter_index]
    return apply_aliases(graph, alias), frozenset(alias)


def apply_aliases(graph, alias: dict, expand: dict | None = None):
    """``graph`` with every use of an aliased value replaced by its alias, and (``expand``) each returned value
    replaced by the values it expands to."""
    from dataclasses import replace

    if not alias and not expand:
        return graph

    def canon(ref: ValueRef) -> ValueRef:
        while ref in alias:
            ref = alias[ref]
        return ref

    blocks = []
    for block in graph.blocks:
        nodes = tuple(replace(node, operands=tuple(canon(ref) for ref in node.operands)) for node in block.nodes)
        term = block.terminator
        values = tuple(canon(ref) for ref in term.values)
        if expand and term.kind == TerminatorKind.RETURN:
            values = tuple(canon(item) for ref in values for item in expand.get(ref, (ref,)))
        terminator = replace(term, values=values, edges=tuple((target, tuple(canon(ref) for ref in arguments)) for target, arguments in term.edges))
        blocks.append(replace(block, nodes=nodes, terminator=terminator))
    return Rewritten(graph.entry, tuple(blocks))


class Aggregates:
    """Views profile (ADR-151): where each aggregate value lives.

    ``made``: an ``aggregate.make`` result -> its field operands; ``returned``: an aggregate call result -> its field
    count; ``alias``: an ``aggregate.get`` of a made aggregate -> that field; ``elided``: every aggregate value and every
    aliased get.  Any other use of an aggregate (a block parameter, an edge or call argument, a returned aggregate
    that was not made here) fails."""

    def __init__(self, graph, resolve, where: str, returned_fields: int | None, isa: str) -> None:
        self.made: dict[ValueRef, tuple[ValueRef, ...]] = {}
        self.returned: dict[ValueRef, int] = {}
        for block_index, block in enumerate(graph.blocks):
            for index, cid in enumerate(block.parameters):
                if aggregate_fields(resolve, cid) is not None:
                    fail(f"XAX.{isa}.UNSUPPORTED_OPERATION", where, f"{isa}-AGGREGATE-VALUE", "made or call-returned aggregate", "block parameter")
            for node_index, node in enumerate(block.nodes):
                for result_index, cid in enumerate(node.results):
                    if aggregate_fields(resolve, cid) is None:
                        continue
                    ref = ValueRef.node_result(block_index, node_index, result_index)
                    if node.operation == Operation.AGGREGATE_MAKE:
                        self.made[ref] = node.operands
                    elif node.operation == Operation.CALL_DIRECT and not _is_erased_proof_function(node.entity, resolve):
                        self.returned[ref] = result_fields(node.entity, resolve, isa)
                    else:
                        fail(f"XAX.{isa}.UNSUPPORTED_OPERATION", where, f"{isa}-AGGREGATE-VALUE", "made or call-returned aggregate", node.operation)
        self.alias: dict[ValueRef, ValueRef] = {}
        aggregates = set(self.made) | set(self.returned)
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                if node.operation == Operation.AGGREGATE_GET:
                    if node.operands[0] in self.made:
                        self.alias[ValueRef.node_result(block_index, node_index)] = self.made[node.operands[0]][node.attributes[0]]
                elif node.operation != Operation.AGGREGATE_MAKE and aggregates.intersection(node.operands):
                    fail(f"XAX.{isa}.UNSUPPORTED_OPERATION", where, f"{isa}-AGGREGATE-USE", "aggregate.get or a return", node.operation)
            term = block.terminator
            arguments = {ref for _target, refs in term.edges for ref in refs} | (set(term.values) if term.kind != TerminatorKind.RETURN else set())
            returned = set(term.values) if term.kind == TerminatorKind.RETURN else set()
            if aggregates & arguments or returned & set(self.returned) or (returned & set(self.made) and returned_fields is None):
                fail(f"XAX.{isa}.UNSUPPORTED_OPERATION", where, f"{isa}-AGGREGATE-USE", "aggregate.get or a return", term.kind)
        self.elided = frozenset(aggregates | set(self.alias))


def pointer_extents(graph, resolve) -> dict[ValueRef, int]:
    """A pointer's extent: the instance of the ``heap_view<N>`` type right after it (as in parameter and result triples)."""
    extents: dict[ValueRef, int] = {}

    def scan(types, ref_of):
        for index in range(len(types) - 1):
            info = _heap_view_info(resolve(types[index + 1]))
            if info is not None and resolve(types[index]).body[:1] == b"\x02":
                extents[ref_of(index)] = info[0]

    for block_index, block in enumerate(graph.blocks):
        scan(block.parameters, lambda index, b=block_index: ValueRef.parameter(b, index))
        for node_index, node in enumerate(block.nodes):
            scan(node.results, lambda index, b=block_index, n=node_index: ValueRef.node_result(b, n, index))
    return extents
