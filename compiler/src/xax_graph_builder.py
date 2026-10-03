"""Programmatic construction helper for canonical XAX graphs.

This is construction tooling, not a source language: it only calls the public
semantic constructors and tracks the objects a store must contain.  It exists
so producers (tests, benchmarks, generators, AI tool adapters) do not hand-
compute ``ValueRef`` indices.
"""

from __future__ import annotations

from typing import Sequence

from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    write_store,
)


class BlockBuilder:
    def __init__(self, owner: "GraphBuilder", index: int, parameter_types: Sequence[SemanticObject]):
        self.owner = owner
        self.index = index
        self.parameter_types = tuple(parameter_types)
        self.nodes: list[Node] = []
        self.terminator: Terminator | None = None
        owner.track(*parameter_types)

    @property
    def params(self) -> tuple[ValueRef, ...]:
        return tuple(ValueRef.parameter(self.index, position) for position in range(len(self.parameter_types)))

    def op(
        self,
        operation: Operation,
        operands: Sequence[ValueRef],
        results: Sequence[SemanticObject],
        *,
        entity: SemanticObject | None = None,
        attributes: tuple[int, ...] = (),
    ) -> tuple[ValueRef, ...]:
        node_index = len(self.nodes)
        self.owner.track(*results, *(() if entity is None else (entity,)))
        self.nodes.append(Node(operation, tuple(operands), tuple(results), entity=entity, attributes=attributes))
        return tuple(ValueRef.node_result(self.index, node_index, result) for result in range(len(results)))

    def op1(self, operation: Operation, operands: Sequence[ValueRef], result: SemanticObject, **kwargs) -> ValueRef:
        return self.op(operation, operands, (result,), **kwargs)[0]

    def const(self, type_object: SemanticObject, value: int) -> ValueRef:
        return self.op1(Operation.CONSTANT, (), type_object, entity=constant(type_object, value))

    def br(self, target: "BlockBuilder", *arguments: ValueRef) -> None:
        self.terminator = Terminator.branch(target.index, arguments)

    def cbr(self, condition: ValueRef, true: "BlockBuilder", true_arguments: Sequence[ValueRef], false: "BlockBuilder", false_arguments: Sequence[ValueRef]) -> None:
        self.terminator = Terminator.conditional_branch(condition, true.index, tuple(true_arguments), false.index, tuple(false_arguments))

    def ret(self, *values: ValueRef) -> None:
        self.terminator = Terminator.return_(values)

    def trap(self, payload: bytes = b"") -> None:
        self.terminator = Terminator.trap(payload)


class GraphBuilder:
    def __init__(self) -> None:
        self.blocks: list[BlockBuilder] = []
        self.objects: dict[bytes, SemanticObject] = {}

    def track(self, *objects: SemanticObject) -> None:
        for item in objects:
            self.objects.setdefault(item.cid, item)

    def block(self, *parameter_types: SemanticObject) -> BlockBuilder:
        builder = BlockBuilder(self, len(self.blocks), parameter_types)
        self.blocks.append(builder)
        return builder

    def function(self, parameters: Sequence[SemanticObject], returns: Sequence[SemanticObject]) -> SemanticObject:
        missing = [block.index for block in self.blocks if block.terminator is None]
        if missing:
            raise ValueError(f"blocks without terminator: {missing}")
        graph = graph_fragment([Block(block.parameter_types, tuple(block.nodes), block.terminator) for block in self.blocks])
        entry = function(graph, tuple(parameters), tuple(returns))
        self.track(*parameters, *returns, graph, entry)
        return entry


def program_store(entry: SemanticObject, target: SemanticObject, objects: Sequence[SemanticObject]) -> StoreReader:
    """Verified single-module store rooted at ``entry`` and ``target``.

    ``objects`` may over-approximate; only objects reachable from the root are
    written, because canonical stores reject unreachable semantic objects.
    """
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    available = {item.cid: item for item in (*objects, entry, target, module, root)}
    reachable: dict[bytes, SemanticObject] = {}
    pending = [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reachable:
            reachable[cid] = available[cid]
            pending.extend(reachable[cid].references)
    reader = StoreReader(write_store(root.cid, tuple(reachable.values())))
    verify_store(reader)
    return reader
