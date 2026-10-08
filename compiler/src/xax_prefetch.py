"""Next-iteration prefetch for pointer walks on the x86-64 register path (ADR-211).

Lowering-view transform; the canonical program is unchanged.  It targets the common lookup shape

    loop:  k = f(x); h = load P[g(k)]; walk an inner loop from h (loads Q_i[cur * s_i]); x = k; repeat

where the inner walk is a chain of dependent cache misses.  While the current walk runs, the next iteration's
first node can already be in flight.  In the loop body block the view appends a copy of the pure index expression
with ``x`` replaced by ``k`` (the guess for the next iteration's input), one more load ``h' = P[g(f(k))]``, and the
backend follows it with ``prefetcht0 [Q_i + h' * s_i]`` for each inner-loop array.

Why this is exact: the appended nodes are pure, the added load is a read of a region the block already reads,
proven in bounds by value ranges (so it cannot trap), and placed in that region's memory-token chain; its value
feeds only prefetch hints, which have no architectural effect and never fault.  A wrong guess only wastes a
prefetch.  Nothing is added when any condition fails.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable

from xax_compiler import Operation, SemanticObject, TerminatorKind, ValueRef, Terminator, _decode_constant, decode_bits_width, pointer_extent_from_graph
from xax_ranges import upper_bounds

_PURE = frozenset({
    Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR,
    Operation.UDIV, Operation.UREM, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT,
})
_SCALES = (1, 2, 4, 8)


def _widths_and_constants(graph, resolve: Callable[[bytes], SemanticObject]):
    widths, constants = {}, {}
    for block_index, block in enumerate(graph.blocks):
        for index, cid in enumerate(block.parameters):
            try:
                widths[ValueRef.parameter(block_index, index)] = decode_bits_width(resolve(cid))
            except Exception:  # noqa: BLE001 - only bits types carry widths
                pass
        for node_index, node in enumerate(block.nodes):
            for result, cid in enumerate(node.results):
                try:
                    widths[ValueRef.node_result(block_index, node_index, result)] = decode_bits_width(resolve(cid))
                except Exception:  # noqa: BLE001
                    pass
            if node.operation == Operation.CONSTANT:
                constants[ValueRef.node_result(block_index, node_index)] = _decode_constant(node.entity, resolve)[1]
    return widths, constants


def _cycle_blocks(graph, start: int, avoid: int) -> set[int]:
    """Blocks on a cycle through ``start`` that does not pass ``avoid``: reachable from it and reaching it."""
    successors = {index: {target for target, _ in block.terminator.edges if target != avoid}
                  for index, block in enumerate(graph.blocks) if index != avoid}
    forward, pending = set(), [start]
    while pending:
        block = pending.pop()
        for target in successors[block]:
            if target not in forward:
                forward.add(target)
                pending.append(target)
    backward, pending = {start}, [start]
    while pending:
        block = pending.pop()
        for source, targets in successors.items():
            if block in targets and source not in backward:
                backward.add(source)
                pending.append(source)
    return (forward & backward) | ({start} if start in forward else set())


def _scaled_index(graph, block_index: int, index: ValueRef):
    """``(v, s)`` for an index ``v * s`` (optionally truncated) with ``v`` a block parameter, else None."""
    definition = lambda value: graph.blocks[value.block].nodes[value.index] if value.tag == 1 and value.result == 0 else None  # noqa: E731
    node = definition(index)
    if node is not None and node.operation == Operation.INT_TRUNCATE:
        index = node.operands[0]
        node = definition(index)
    if node is None or node.operation != Operation.MUL_WRAP:
        return None
    base, scale = node.operands
    scale_node = definition(scale)
    if scale_node is None or scale_node.operation != Operation.CONSTANT or base.tag != 0:
        return None
    return base, scale


def prefetch_next_iteration(graph, resolve: Callable[[bytes], SemanticObject]):
    """``(view, marks)``: ``marks`` maps an appended load's result to ``((array pointer, scale), ...)`` prefetches."""
    widths, constants = _widths_and_constants(graph, resolve)
    marks: dict[ValueRef, tuple[tuple[ValueRef, int], ...]] = {}
    blocks = list(graph.blocks)
    for body_index, body in enumerate(graph.blocks):
        term = body.terminator
        if term.kind != TerminatorKind.BRANCH or len(term.edges) != 1:
            continue
        (walk, arguments), = term.edges
        inner = _cycle_blocks(graph, walk, body_index)
        if not inner:
            continue
        for load_index, load in enumerate(body.nodes):
            if load.operation != Operation.CHECKED_LOAD_BITS_LE:
                continue
            head, token = ValueRef.node_result(body_index, load_index), ValueRef.node_result(body_index, load_index, 1)
            if head not in arguments or token not in arguments or any(token in node.operands for node in body.nodes):
                continue
            # The pure index expression and the single block parameter it starts from.
            expression, inputs, pending = {}, set(), [load.operands[1]]
            while pending:
                value = pending.pop()
                if value in expression or value in constants:
                    continue
                if value.tag == 0 and value.block == body_index:
                    inputs.add(value)
                    continue
                node = body.nodes[value.index] if value.tag == 1 and value.block == body_index and value.result == 0 else None
                if node is None or node.operation not in _PURE or (
                    node.operation in (Operation.UDIV, Operation.UREM) and not constants.get(node.operands[1])
                ):  # division only by a nonzero constant: the copy must not trap
                    inputs.add(None)
                    break
                expression[value] = node
                pending.extend(node.operands)
            if len(inputs) != 1 or None in inputs:
                continue
            (seed,) = inputs
            # The guess for the next input: the value this body passes on in the seed's own parameter position.
            guess = arguments[seed.index] if seed.index < len(arguments) else None
            if guess is None or guess not in expression:
                continue
            # Inner-loop arrays read at block-parameter * scale, with pointers defined in the entry block.
            prefetches = []
            for block_index in sorted(inner):
                for node in graph.blocks[block_index].nodes:
                    if node.operation != Operation.CHECKED_LOAD_BITS_LE:
                        continue
                    scaled = _scaled_index(graph, block_index, node.operands[1])
                    pointer = node.operands[0]
                    if scaled is None or pointer.block != graph.entry or constants.get(scaled[1]) not in _SCALES:
                        continue
                    if (pointer, constants[scaled[1]]) not in prefetches:
                        prefetches.append((pointer, constants[scaled[1]]))
            if not prefetches:
                continue
            nodes = list(body.nodes)
            copied: dict[ValueRef, ValueRef] = {seed: guess}
            for value in sorted(expression, key=lambda ref: ref.index):
                node = expression[value]
                copied[value] = ValueRef.node_result(body_index, len(nodes))
                nodes.append(replace(node, operands=tuple(copied.get(operand, operand) for operand in node.operands)))
            index = copied[load.operands[1]]
            extra = replace(load, operands=(load.operands[0], index, token))
            nodes.append(extra)
            next_head = ValueRef.node_result(body_index, len(nodes) - 1)
            next_token = ValueRef.node_result(body_index, len(nodes) - 1, 1)
            candidate = list(blocks)
            candidate[body_index] = replace(body, nodes=tuple(nodes), terminator=Terminator(
                term.kind, term.values, ((walk, tuple(next_token if value == token else value for value in arguments)),), term.payload))
            view = replace(graph, blocks=tuple(candidate))
            # The added load must be provably in bounds: it may never trap.
            view_widths, view_constants = _widths_and_constants(view, resolve)
            bound = upper_bounds(view, view_widths, view_constants)(index)
            if bound is None or bound > pointer_extent_from_graph(view, load.operands[0], resolve) - load.attributes[0]:
                continue
            blocks, graph = candidate, view
            marks[next_head] = tuple(prefetches)
            break
    return graph, marks
