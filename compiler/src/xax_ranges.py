"""Upper bounds of integer SSA values (OI-38 range elimination), shared by the register backends.

``upper_bounds(graph, widths, constants)`` returns ``maximum(value)``: an
upper bound of an integer value, or ``None`` when it is not an integer.  It
follows constants, ``udiv`` by a constant, ``add``, ``and``, ``mul`` by a
constant, truncation and zero extension, and compares (0 or 1).  Block
parameters take the maximum over their incoming edges, refined by an unsigned
compare whose branch selects the edge, with widening then narrowing so loop
counters stay bounded by their loop test.  Moved unchanged from the x86-64
register path (ADR-148) so AArch64 proves the same accesses (ADR-168).
"""

from __future__ import annotations

from typing import Callable

from xax_compiler import IntCompare, Operation, TerminatorKind, ValueRef


def upper_bounds(graph, widths: dict, constants: dict, *, bitwise: bool = False) -> Callable[[ValueRef], int | None]:
    """``bitwise`` also bounds ``or``/``xor`` by the next all-ones value above their operands (ADR-168;
    the x86-64 path keeps it off so its committed artifacts stay byte-identical)."""
    definition = {ValueRef.node_result(b, i): node for b, block in enumerate(graph.blocks) for i, node in enumerate(block.nodes)}

    maximum_cache: dict[ValueRef, int | None] = {}

    def maximum(value: ValueRef, depth: int = 0) -> int | None:
        if depth == 0 and value in maximum_cache:
            return maximum_cache[value]
        result = _maximum(value, depth)
        if depth == 0:
            maximum_cache[value] = result
        return result

    def _maximum(value: ValueRef, depth: int = 0) -> int | None:
        if value in constants:
            return constants[value]
        if value not in widths:
            return None
        limit = (1 << widths[value]) - 1  # every bits<w> value lies in [0, 2^w)
        if value.tag == 0:
            return min(limit, parameter_bound.get(value, limit))
        node = definition.get(value) if value.result == 0 else None
        if node is None or depth > 8:
            return limit
        left = node.operands[0] if node.operands else None
        if node.operation == Operation.UDIV and constants.get(node.operands[1]):
            bound = maximum(left, depth + 1)
            return (limit if bound is None else bound) // constants[node.operands[1]]
        if node.operation == Operation.ADD_WRAP:
            bounds = [maximum(operand, depth + 1) for operand in node.operands]
            return limit if None in bounds or sum(bounds) > limit else sum(bounds)
        if node.operation == Operation.BIT_AND:
            bounds = [b for b in (maximum(left, depth + 1), maximum(node.operands[1], depth + 1)) if b is not None]
            return min(bounds) if bounds else limit
        if bitwise and node.operation in (Operation.BIT_OR, Operation.BIT_XOR):
            bounds = [maximum(operand, depth + 1) for operand in node.operands]
            return limit if None in bounds else min(limit, (1 << max(bounds).bit_length()) - 1)
        if node.operation == Operation.MUL_WRAP and constants.get(node.operands[1]) is not None:
            bound = maximum(left, depth + 1)
            return limit if bound is None or bound * constants[node.operands[1]] > limit else bound * constants[node.operands[1]]
        if node.operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
            bound = maximum(left, depth + 1)
            return limit if bound is None else min(bound, limit)
        if node.operation == Operation.INT_COMPARE:
            return 1
        return limit

    # Block-parameter upper bounds (OI-38 range elimination): the maximum over
    # incoming edges of the argument's bound, refined by an unsigned compare
    # whose branch selects the edge (``x < y`` on the taken edge bounds x by
    # max(y) - 1).  Parameters start at 0 and only grow, every transfer is
    # monotone, and an iteration cap falls back to the width limit.
    parameter_bound: dict[ValueRef, int] = {
        ValueRef.parameter(block_index, index): 0
        for block_index, block in enumerate(graph.blocks) for index in range(len(block.parameters))
        if block_index != graph.entry and ValueRef.parameter(block_index, index) in widths
    }
    _UPPER = {  # (kind, taken edge?) -> how the left operand relates to the right
        (IntCompare.ULT, True): "lt", (IntCompare.UGE, False): "lt",
        (IntCompare.ULE, True): "le", (IntCompare.UGT, False): "le",
        (IntCompare.UGT, True): "gt", (IntCompare.ULE, False): "gt",
        (IntCompare.UGE, True): "ge", (IntCompare.ULT, False): "ge",
        (IntCompare.EQ, True): "eq", (IntCompare.NE, False): "eq",
    }

    def edge_bound(source: int, edge_index: int, argument: ValueRef) -> int | None:
        bound = maximum(argument)
        if bound is None:
            return None
        terminator = graph.blocks[source].terminator
        if terminator.kind != TerminatorKind.CONDITIONAL_BRANCH:
            return bound
        condition = terminator.values[0]
        if condition.tag != 1 or condition.block != source or condition.result:
            return bound
        compare = graph.blocks[source].nodes[condition.index]
        if compare.operation != Operation.INT_COMPARE:
            return bound
        relation = _UPPER.get((IntCompare(compare.attributes[0]), edge_index == 0))
        left, right = compare.operands
        if relation is None or argument not in (left, right):
            return bound
        if argument == right:
            relation = {"lt": "gt", "le": "ge", "gt": "lt", "ge": "le", "eq": "eq"}[relation]
        other = maximum(right if argument == left else left)
        if other is None:
            return bound
        if relation == "lt":
            return min(bound, other - 1) if other > 0 else bound
        if relation in ("le", "eq"):
            return min(bound, other)
        return bound

    incoming_arguments = [
        (source, edge_index, ValueRef.parameter(target, index), argument)
        for source, block in enumerate(graph.blocks)
        for edge_index, (target, arguments) in enumerate(block.terminator.edges)
        for index, argument in enumerate(arguments)
        if ValueRef.parameter(target, index) in parameter_bound
    ]
    for round_index in range(4 * len(graph.blocks) + 16):
        maximum_cache.clear()
        changed = False
        for source, edge_index, parameter, argument in incoming_arguments:
            bound = edge_bound(source, edge_index, argument)
            bound = (1 << widths[parameter]) - 1 if bound is None else min(bound, (1 << widths[parameter]) - 1)
            if bound > parameter_bound[parameter]:
                # Widening: a bound still growing after a few rounds (a counter) jumps
                # to its width limit; branch refinement on edges bounds it again.
                parameter_bound[parameter] = bound if round_index < 3 else (1 << widths[parameter]) - 1
                changed = True
        if not changed:
            break
    else:
        parameter_bound.clear()
    # Narrowing: from a post-fixpoint, recomputing every parameter from its
    # incoming edges (never above its current bound) stays a post-fixpoint,
    # so it recovers precision that widening gave away.
    for _round in range(len(graph.blocks) + 4 if parameter_bound else 0):
        maximum_cache.clear()
        recomputed: dict[ValueRef, int] = {}
        for source, edge_index, parameter, argument in incoming_arguments:
            bound = edge_bound(source, edge_index, argument)
            bound = (1 << widths[parameter]) - 1 if bound is None else min(bound, (1 << widths[parameter]) - 1)
            recomputed[parameter] = max(recomputed.get(parameter, 0), bound)
        narrowed = False
        for parameter, bound in recomputed.items():
            if bound < parameter_bound[parameter]:
                parameter_bound[parameter] = bound
                narrowed = True
        if not narrowed:
            break
    maximum_cache.clear()

    return maximum


# Predicate tables (ADR-208; AArch64 since ADR-254): a boolean computed only from one value below
# TABLE_SUBJECT_LIMIT and constants, by at least TABLE_MIN_OPERATIONS compares/arithmetic nodes whose
# results have no other use, is read from a byte table: the expression evaluated exactly for every value.
TABLE_SUBJECT_LIMIT = 256
TABLE_OPERATIONS = frozenset({
    Operation.INT_COMPARE, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR,
    Operation.BIT_XOR, Operation.INT_ZERO_EXTEND, Operation.INT_TRUNCATE,
})
TABLE_MIN_OPERATIONS = 3


def evaluate_table_node(node, values: list[int], width: int, operand_width: int) -> int:
    """Exact value of one table-evaluable node (wrapping arithmetic at ``width``)."""
    mask = (1 << width) - 1
    operation = node.operation
    if operation == Operation.INT_COMPARE:
        left, right = values
        kind = IntCompare(node.attributes[0])
        if kind in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE):
            half = 1 << (operand_width - 1)
            left, right = (left ^ half) - half, (right ^ half) - half
        return int({
            IntCompare.EQ: left == right, IntCompare.NE: left != right, IntCompare.ULT: left < right, IntCompare.ULE: left <= right,
            IntCompare.UGT: left > right, IntCompare.UGE: left >= right, IntCompare.SLT: left < right, IntCompare.SLE: left <= right,
            IntCompare.SGT: left > right, IntCompare.SGE: left >= right,
        }[kind])
    if operation in (Operation.INT_ZERO_EXTEND, Operation.INT_TRUNCATE):
        return values[0] & mask
    left, right = values
    return {
        Operation.ADD_WRAP: left + right, Operation.SUB_WRAP: left - right, Operation.MUL_WRAP: left * right,
        Operation.BIT_AND: left & right, Operation.BIT_OR: left | right, Operation.BIT_XOR: left ^ right,
    }[operation] & mask


def predicate_table(graph, block_index: int, root: ValueRef, definition: dict, widths: dict, constants: dict,
                    maximum: Callable[[ValueRef], int | None], early_uses) -> tuple[ValueRef, bytes, frozenset[int]] | None:
    """``(subject, table, erased node indices)`` when ``root`` (in ``block_index``) is a table predicate, else ``None``.

    ``early_uses`` counts every operand, terminator, and edge use of each value in the graph."""
    def local(value: ValueRef):
        node = definition.get(value) if value.tag == 1 and value.block == block_index and value.result == 0 else None
        return node if node is not None and node.operation in TABLE_OPERATIONS and value in widths else None

    nodes: dict[ValueRef, object] = {}
    leaves: set[ValueRef] = set()

    def expand(start: ValueRef, shared: bool) -> None:
        pending = [start]
        while pending:
            value = pending.pop()
            if value in nodes or value in constants:
                continue
            node = local(value)
            if node is not None and (value == start or shared or early_uses[value] == 1):
                leaves.discard(value)
                nodes[value] = node
                pending.extend(node.operands)
            else:
                leaves.add(value)

    if local(root) is None:
        return None
    expand(root, False)
    # A test shared with other code (computed anyway) is walked through too; it is kept, not erased.
    while len(leaves) > 1:
        expandable = [value for value in leaves if local(value) is not None]
        if not expandable:
            return None
        expand(max(expandable, key=lambda value: value.index), False)
    if len(leaves) != 1 or sum(node.operation != Operation.INT_ZERO_EXTEND for node in nodes.values()) < TABLE_MIN_OPERATIONS:
        return None
    (subject,) = leaves
    bound = maximum(subject)
    if subject not in widths or bound is None or bound >= TABLE_SUBJECT_LIMIT:
        return None
    order = sorted(nodes, key=lambda value: value.index)  # operands precede their uses within a block
    entries = bytearray()
    for x in range(bound + 1):
        values = {subject: x}
        for value in order:
            node = nodes[value]
            operands = [values[operand] if operand in values else constants[operand] for operand in node.operands]
            operand_width = widths.get(node.operands[0], widths.get(node.operands[-1], 64))
            values[value] = evaluate_table_node(node, operands, widths[value], operand_width)
        if values[root] not in (0, 1):
            return None
        entries.append(values[root])
    # Erase exactly the nodes all of whose uses are erased nodes (the root's users read the table).
    erased = {root}
    for value in reversed(order):
        if value != root and sum(operand == value for user in erased for operand in nodes[user].operands) == early_uses[value]:
            erased.add(value)
    return subject, bytes(entries), frozenset(value.index for value in erased)
