"""Lowering-view inlining of small leaf functions for the x86-64 register path (OI-38).

The canonical program is unchanged: this rewrites the *parsed lowering view* a
backend compiles, the same way :func:`xax_compiler.parse_function_graph`
presents group-member calls as direct calls.  A ``call.direct`` of a function
whose graph contains no call of any kind (a leaf) and at most
``INLINE_NODE_LIMIT`` nodes is replaced by the callee's blocks:

* the caller block splits at the call; the part before the call branches to
  the callee's entry block with the call operands (resources, effects and
  views included, so linear flow is the call's own);
* every callee ``return`` becomes a branch to the continuation block, whose
  parameters are the call's results;
* then exact simplifications run to a fixed point: a block entered by one
  unconditional branch from a single predecessor merges into it (its
  parameters become the branch arguments); an edge into a block that only
  forwards its parameters goes straight on (jump threading); ``bits<32>``
  halves read back out of a ``bits<64>`` packed as ``zext(lo) | ror(zext(hi),
  32)`` become ``lo`` and ``hi``; a ``w``-bit store of ``trunc_w(x)`` stores
  ``x``; pure nodes without uses are deleted;
* finally the blocks are laid out for fall-through (loop bodies contiguous,
  loop exits and returns after them).  Functions with nothing to inline get
  the simplifications and the layout too.

Every rewrite preserves the observable behavior of the graph: the callee
runs the same operations on the same values in the same order, and traps
stay where they were.  Callee pointer extents (verified facts) move with
their values.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable

from xax_compiler import (
    Operation,
    SemanticObject,
    Terminator,
    TerminatorKind,
    ValueRef,
    _is_erased_proof_function,
    decode_bits_width,
    decode_group_member_function,
    parse_function_graph,
)

INLINE_NODE_LIMIT = 256
_CALLS = frozenset({Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT, Operation.CALL_GROUP_MEMBER})
_PURE = frozenset({
    Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND,
    Operation.BIT_OR, Operation.INT_COMPARE, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT,
    Operation.ADDRESS_OFFSET, Operation.POINTER_CAST, Operation.POINTER_ADDRESS,
})


class _Value:
    __slots__ = ("extent",)

    def __init__(self) -> None:
        self.extent: int | None = None


class _Node:
    __slots__ = ("node", "operands", "outputs")

    def __init__(self, node, operands: list[_Value]) -> None:
        self.node = node
        self.operands = operands
        self.outputs = [_Value() for _ in node.results]


class _Block:
    __slots__ = ("parameters", "inputs", "nodes", "kind", "values", "edges", "payload")

    def __init__(self, parameters: tuple[bytes, ...]) -> None:
        self.parameters = list(parameters)
        self.inputs = [_Value() for _ in parameters]
        self.nodes: list[_Node] = []
        self.kind = TerminatorKind.TRAP
        self.values: list[_Value] = []
        self.edges: list[tuple[_Block, list[_Value]]] = []
        self.payload = b""


def _lift(graph) -> tuple[list[_Block], _Block]:
    """Object form of a parsed graph: values are identities, not positions."""
    blocks = [_Block(block.parameters) for block in graph.blocks]
    extents = dict(getattr(graph, "pointer_extents", ()))

    def value(ref: ValueRef) -> _Value:
        if ref.tag == 0:
            return blocks[ref.block].inputs[ref.index]
        return lifted[ref.block][ref.index].outputs[ref.result]

    lifted: list[list[_Node]] = [[] for _ in graph.blocks]
    # Nodes may only use values that dominate them, so a reverse-postorder-free
    # two pass build (create every node first, then wire operands) suffices.
    for block_index, block in enumerate(graph.blocks):
        for node in block.nodes:
            lifted[block_index].append(_Node(node, []))
    for block_index, block in enumerate(graph.blocks):
        for item, node in zip(lifted[block_index], block.nodes):
            item.operands = [value(ref) for ref in node.operands]
        blocks[block_index].nodes = lifted[block_index]
        terminator = block.terminator
        blocks[block_index].kind = terminator.kind
        blocks[block_index].values = [value(ref) for ref in terminator.values]
        blocks[block_index].edges = [(blocks[target], [value(ref) for ref in arguments]) for target, arguments in terminator.edges]
        blocks[block_index].payload = terminator.payload
    for ref, extent in extents.items():
        value(ref).extent = extent
    return blocks, blocks[graph.entry]


def _lower(graph, blocks: list[_Block], entry: _Block):
    """Back to positional ValueRefs (blocks keep their list order)."""
    index = {id(block): position for position, block in enumerate(blocks)}
    where: dict[int, ValueRef] = {}
    for block_position, block in enumerate(blocks):
        for parameter, value in enumerate(block.inputs):
            where[id(value)] = ValueRef.parameter(block_position, parameter)
        for node_position, item in enumerate(block.nodes):
            for result, value in enumerate(item.outputs):
                where[id(value)] = ValueRef.node_result(block_position, node_position, result)
    parsed_blocks, extents = [], []
    for block in blocks:
        nodes = tuple(replace(item.node, operands=tuple(where[id(value)] for value in item.operands)) for item in block.nodes)
        terminator = Terminator(
            block.kind,
            tuple(where[id(value)] for value in block.values),
            tuple((index[id(target)], tuple(where[id(value)] for value in arguments)) for target, arguments in block.edges),
            block.payload,
        )
        parsed_blocks.append(type(graph.blocks[0])(tuple(block.parameters), nodes, terminator))
        for value in (*block.inputs, *(output for item in block.nodes for output in item.outputs)):
            if value.extent is not None:
                extents.append((where[id(value)], value.extent))
    return replace(graph, entry=index[id(entry)], blocks=tuple(parsed_blocks), member_spans=(), pointer_extents=tuple(extents))


def _replace_uses(blocks: list[_Block], mapping: dict[int, _Value]) -> None:
    def resolve(value: _Value) -> _Value:
        while id(value) in mapping:
            value = mapping[id(value)]
        return value

    for block in blocks:
        for item in block.nodes:
            item.operands = [resolve(value) for value in item.operands]
        block.values = [resolve(value) for value in block.values]
        block.edges = [(target, [resolve(value) for value in arguments]) for target, arguments in block.edges]


def _carry_extent(source: _Value, target: _Value) -> None:
    if target.extent is None and source.extent is not None:
        target.extent = source.extent


def _inline_candidate(node, resolve: Callable[[bytes], SemanticObject]):
    if node.operation != Operation.CALL_DIRECT or node.entity is None or _is_erased_proof_function(node.entity, resolve):
        return None
    if decode_group_member_function(node.entity, resolve) is not None:
        return None
    callee = parse_function_graph(node.entity, resolve)
    if sum(len(block.nodes) for block in callee.blocks) > INLINE_NODE_LIMIT:
        return None
    if any(item.operation in _CALLS for block in callee.blocks for item in block.nodes):
        return None
    if any(block.terminator.kind == TerminatorKind.RETURN and len(block.terminator.values) != len(node.results) for block in callee.blocks):
        return None
    return callee


def _splice(blocks: list[_Block], block: _Block, position: int, callee) -> None:
    item = block.nodes[position]
    inner, inner_entry = _lift(callee)
    if len(inner_entry.inputs) != len(item.operands):
        raise ValueError("call arity differs from the callee entry block")
    continuation = _Block(item.node.results)
    continuation.nodes = block.nodes[position + 1:]
    continuation.kind, continuation.values, continuation.edges, continuation.payload = block.kind, block.values, block.edges, block.payload
    for result, parameter in zip(item.outputs, continuation.inputs):
        _carry_extent(result, parameter)
    block.nodes = block.nodes[:position]
    block.kind, block.values, block.edges, block.payload = TerminatorKind.BRANCH, [], [(inner_entry, list(item.operands))], b""
    for callee_block in inner:
        if callee_block.kind == TerminatorKind.RETURN:
            callee_block.kind, callee_block.edges, callee_block.values = TerminatorKind.BRANCH, [(continuation, list(callee_block.values))], []
    at = blocks.index(block) + 1
    blocks[at:at] = [*inner, continuation]
    _replace_uses(blocks, {id(result): parameter for result, parameter in zip(item.outputs, continuation.inputs)})


def _merge_blocks(blocks: list[_Block], entry: _Block) -> bool:
    predecessors: dict[int, list[_Block]] = {}
    for block in blocks:
        for target, _arguments in block.edges:
            predecessors.setdefault(id(target), []).append(block)
    for block in blocks:
        if block.kind != TerminatorKind.BRANCH:
            continue
        target, arguments = block.edges[0]
        if target is entry or target is block or len(predecessors.get(id(target), ())) != 1:
            continue
        for parameter, argument in zip(target.inputs, arguments):
            _carry_extent(parameter, argument)
        mapping = {id(parameter): argument for parameter, argument in zip(target.inputs, arguments)}
        block.nodes = block.nodes + target.nodes
        block.kind, block.values, block.edges, block.payload = target.kind, target.values, target.edges, target.payload
        blocks.remove(target)
        _replace_uses(blocks, mapping)
        return True
    return False


def _thread_jumps(blocks: list[_Block], entry: _Block) -> bool:
    """An edge into a block that only forwards its parameters goes straight to that block's target."""
    changed = False
    # A forwarding block's parameters may be read elsewhere by dominance; then it must stay.
    readers: dict[int, set[int]] = {}  # value -> blocks reading it
    for block in blocks:
        for value in (*(operand for item in block.nodes for operand in item.operands), *block.values, *(value for _target, arguments in block.edges for value in arguments)):
            readers.setdefault(id(value), set()).add(id(block))
    read_elsewhere = {value for value, owners in readers.items() if len(owners) > 1}
    for block in blocks:
        for parameter in block.inputs:
            if readers.get(id(parameter), {id(block)}) != {id(block)}:
                read_elsewhere.add(id(parameter))
    for block in blocks:
        new_edges = []
        for target, arguments in block.edges:
            hops = 0
            while (
                target is not entry and not target.nodes and target.kind == TerminatorKind.BRANCH and target.edges[0][0] is not target and hops < 8
                and not any(id(parameter) in read_elsewhere for parameter in target.inputs)
            ):
                mapping = {id(parameter): argument for parameter, argument in zip(target.inputs, arguments)}
                following, forwarded = target.edges[0]
                arguments = [mapping.get(id(value), value) for value in forwarded]
                target = following
                hops += 1
                changed = True
            new_edges.append((target, arguments))
        block.edges = new_edges
    reachable, stack = {id(entry)}, [entry]
    while stack:
        for target, _arguments in stack.pop().edges:
            if id(target) not in reachable:
                reachable.add(id(target))
                stack.append(target)
    if len(reachable) != len(blocks):
        blocks[:] = [block for block in blocks if id(block) in reachable]
        changed = True
    return changed


def _bits32_width(node, resolve) -> bool:
    try:
        return decode_bits_width(resolve(node.results[0])) == 32
    except Exception:
        return False


def _fold_pack(blocks: list[_Block], resolve) -> bool:
    """``trunc32(zext(lo) | ror(zext(hi), 32))`` is ``lo``; the same through ``ror 32`` is ``hi``."""
    producer: dict[int, _Node] = {id(output): item for block in blocks for item in block.nodes for output in item.outputs}

    def unpack(value: _Value):
        item = producer.get(id(value))
        if item is None or item.node.operation != Operation.BIT_OR:
            return None
        low, high = (producer.get(id(operand)) for operand in item.operands)
        if low is None or high is None or low.node.operation != Operation.INT_ZERO_EXTEND:
            return None
        if high.node.operation != Operation.ROTATE_RIGHT or high.node.attributes != (32,):
            return None
        widened = producer.get(id(high.operands[0]))
        if widened is None or widened.node.operation != Operation.INT_ZERO_EXTEND:
            return None
        if not (_bits32_width_of(low.operands[0]) and _bits32_width_of(widened.operands[0])):
            return None
        return low.operands[0], widened.operands[0]

    def _bits32_width_of(value: _Value) -> bool:
        item = producer.get(id(value))
        if item is not None:
            return _bits32_width(item.node, resolve)
        for block in blocks:
            for parameter, type_cid in zip(block.inputs, block.parameters):
                if parameter is value:
                    try:
                        return decode_bits_width(resolve(type_cid)) == 32
                    except Exception:
                        return False
        return False

    used = {id(value) for block in blocks for item in block.nodes for value in item.operands}
    used.update(id(value) for block in blocks for value in block.values)
    used.update(id(value) for block in blocks for _target, arguments in block.edges for value in arguments)
    mapping: dict[int, _Value] = {}
    for block in blocks:
        for item in block.nodes:
            if item.node.operation != Operation.INT_TRUNCATE or id(item.outputs[0]) not in used or not _bits32_width(item.node, resolve):
                continue
            source = item.operands[0]
            rotated = producer.get(id(source))
            if rotated is not None and rotated.node.operation == Operation.ROTATE_RIGHT and rotated.node.attributes == (32,):
                halves = unpack(rotated.operands[0])
                if halves is not None:
                    mapping[id(item.outputs[0])] = halves[1]
                continue
            halves = unpack(source)
            if halves is not None:
                mapping[id(item.outputs[0])] = halves[0]
    if mapping:
        _replace_uses(blocks, mapping)
    return bool(mapping)


def _store_truncations(blocks: list[_Block], resolve) -> bool:
    """A store of ``trunc_w(x)`` with a ``w``-bit access stores the low ``w`` bits of ``x`` itself."""
    producer: dict[int, _Node] = {id(output): item for block in blocks for item in block.nodes for output in item.outputs}
    changed = False
    for block in blocks:
        for item in block.nodes:
            operation = item.node.operation
            position = 1 if operation == Operation.STORE_BITS_LE else 2 if operation == Operation.CHECKED_STORE_BITS_LE else None
            if position is None:
                continue
            truncation = producer.get(id(item.operands[position]))
            if truncation is None or truncation.node.operation != Operation.INT_TRUNCATE:
                continue
            try:
                width = decode_bits_width(resolve(truncation.node.results[0]))
            except Exception:
                continue
            if width == 8 * item.node.attributes[0]:
                item.operands[position] = truncation.operands[0]
                changed = True
    return changed


def _local_parameters(blocks: list[_Block], entry: _Block) -> bool:
    """In a block entered by exactly one edge from another block, a value that edge passes as an argument is read
    through the block's own parameter (the same value), so it is not also live across the edge (ADR-212)."""
    incoming: dict[int, list[tuple[_Block, list[_Value]]]] = {}
    for block in blocks:
        for target, arguments in block.edges:
            incoming.setdefault(id(target), []).append((block, arguments))
    changed = False
    for block in blocks:
        edges = incoming.get(id(block), [])
        if block is entry or len(edges) != 1 or edges[0][0] is block:
            continue
        mapping: dict[int, _Value] = {}
        for parameter, argument in zip(block.inputs, edges[0][1]):
            if argument is not parameter and id(argument) not in mapping:
                mapping[id(argument)] = parameter
        if not mapping:
            continue

        def local(values: list[_Value]) -> list[_Value]:
            return [mapping.get(id(value), value) for value in values]

        for item in block.nodes:
            rewritten = local(item.operands)
            if any(new is not old for new, old in zip(rewritten, item.operands)):
                item.operands, changed = rewritten, True
        values = local(block.values)
        if any(new is not old for new, old in zip(values, block.values)):
            block.values, changed = values, True
        new_edges = []
        for target, arguments in block.edges:
            rewritten = local(arguments)
            changed = changed or any(new is not old for new, old in zip(rewritten, arguments))
            new_edges.append((target, rewritten))
        block.edges = new_edges
        for parameter, argument in zip(block.inputs, edges[0][1]):
            _carry_extent(argument, parameter)  # the parameter now stands for the argument
    return changed


def _dead_code(blocks: list[_Block]) -> bool:
    used: set[int] = set()
    for block in blocks:
        for item in block.nodes:
            used.update(id(value) for value in item.operands)
        used.update(id(value) for value in block.values)
        used.update(id(value) for _target, arguments in block.edges for value in arguments)
    changed = False
    for block in blocks:
        kept = [item for item in block.nodes if item.node.operation not in _PURE or any(id(output) in used for output in item.outputs)]
        if len(kept) != len(block.nodes):
            block.nodes = kept
            changed = True
    return changed


def _layout(blocks: list[_Block], entry: _Block) -> list[_Block]:
    """Block order for fall-through: loop bodies stay contiguous, loop exits and returns go after.

    From each placed block the chain continues to an unplaced successor,
    preferring the one with the shortest way back to this block (the
    innermost loop goes on), then one that does not end the function, then a
    join over a one-way arm, then the earlier edge.
    Successors not chosen wait on a stack and start later chains.  Only the
    order changes; the entry stays first.
    """
    position = {id(block): index for index, block in enumerate(blocks)}
    successors = {id(block): [target for target, _arguments in block.edges] for block in blocks}

    def reach(start: _Block) -> set[int]:
        seen, stack = set(), list(successors[id(start)])
        while stack:
            block = stack.pop()
            if id(block) not in seen:
                seen.add(id(block))
                stack.extend(successors[id(block)])
        return seen

    reaches = {id(block): reach(block) for block in blocks}

    def distance(start: _Block, goal: _Block) -> int:
        """Edges from ``start`` back to ``goal`` (breadth first); unreachable ranks last."""
        if id(goal) not in reaches[id(start)] and start is not goal:
            return 1 << 30
        frontier, seen, steps = [start], {id(start)}, 0
        while frontier:
            if any(block is goal for block in frontier):
                return steps
            steps += 1
            following = []
            for block in frontier:
                for target in successors[id(block)]:
                    if id(target) not in seen:
                        seen.add(id(target))
                        following.append(target)
            frontier = following
        return 1 << 30
    incoming: dict[int, int] = {}
    for block in blocks:
        for target in successors[id(block)]:
            incoming[id(target)] = incoming.get(id(target), 0) + 1
    order, placed, pending = [], set(), [entry]
    while pending:
        block = pending.pop()
        while block is not None and id(block) not in placed:
            order.append(block)
            placed.add(id(block))
            options = [
                (
                    distance(target, block),  # the innermost loop first (shortest way back)
                    1 if target.kind in (TerminatorKind.RETURN, TerminatorKind.TRAP) else 0,
                    -incoming.get(id(target), 0),  # a join (if-then's fall-through) before a one-way arm
                    edge, target,
                )
                for edge, target in enumerate(successors[id(block)]) if id(target) not in placed
            ]
            options.sort(key=lambda item: item[:4])
            pending.extend(target for *_rank, target in reversed(options[1:]))
            block = options[0][4] if options else None
        if not pending:
            pending.extend(block for block in reversed(blocks) if id(block) not in placed)
    return order


def inline_leaf_calls(graph, resolve: Callable[[bytes], SemanticObject]):
    """The lowering view: small leaf callees inlined, then a fall-through block layout."""
    blocks, entry = _lift(graph)
    if not any(_inline_candidate(node, resolve) is not None for block in graph.blocks for node in block.nodes if node.operation == Operation.CALL_DIRECT):
        while _merge_blocks(blocks, entry) or _thread_jumps(blocks, entry) or _store_truncations(blocks, resolve) or _local_parameters(blocks, entry) or _dead_code(blocks):
            pass
        return _lower(graph, _layout(blocks, entry), entry)
    changed = True
    while changed:
        changed = False
        for block in list(blocks):
            for position, item in enumerate(block.nodes):
                callee = _inline_candidate(item.node, resolve)
                if callee is not None:
                    _splice(blocks, block, position, callee)
                    changed = True
                    break
            if changed:
                break
    while _merge_blocks(blocks, entry) or _thread_jumps(blocks, entry) or _fold_pack(blocks, resolve) or _store_truncations(blocks, resolve) or _local_parameters(blocks, entry) or _dead_code(blocks):
        pass
    return _lower(graph, _layout(blocks, entry), entry)
