"""Structured construction over :mod:`xax_graph_builder` (tooling, not a language).

``Proc`` keeps named variables, including linear tokens, and threads every
live name through explicit block parameters at each join, loop header, and
exit.  ``if_``/``while_`` take Python callables that emit nodes; a branch
that calls ``ret`` ends its path.  The output is an ordinary verified graph:
nothing here survives into the canonical program, and an equivalent graph
can be produced by any other producer.
"""

from __future__ import annotations

from typing import Callable, Sequence

from xax_compiler import IntCompare, Node, Operation, SemanticObject, ValueRef, bits_type
from xax_graph_builder import BlockBuilder, GraphBuilder

B1, B8, B32, B64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)


class Proc:
    def __init__(self, parameters: Sequence[tuple[str, SemanticObject]]):
        self.graph = GraphBuilder()
        self.types: dict[str, SemanticObject] = dict(parameters)
        self.order: list[str] = [name for name, _type in parameters]
        self.block: BlockBuilder | None = self.graph.block(*(type_ for _name, type_ in parameters))
        self.vars: dict[str, ValueRef] = dict(zip(self.order, self.block.params))
        self.parameter_types = tuple(type_ for _name, type_ in parameters)

    # -- variables -------------------------------------------------------------
    def __getitem__(self, name: str) -> ValueRef:
        return self.vars[name]

    def __setitem__(self, name: str, value: ValueRef) -> None:
        if name not in self.types:
            raise KeyError(f"declare {name!r} with let() first")
        self.vars[name] = value

    def let(self, name: str, type_: SemanticObject, value: ValueRef) -> None:
        if name in self.types:
            raise KeyError(f"{name!r} already declared")
        self.types[name] = type_
        self.order.append(name)
        self.vars[name] = value

    def drop(self, name: str) -> ValueRef:
        """Remove a name from scope (a linear token consumed by a node) and return its value."""
        value = self.vars.pop(name)
        del self.types[name]
        self.order.remove(name)
        return value

    # -- nodes -------------------------------------------------------------------
    def op(self, operation: Operation, operands, results, **kwargs):
        return self.block.op(operation, operands, results, **kwargs)

    def op1(self, operation: Operation, operands, result, **kwargs):
        return self.block.op1(operation, operands, result, **kwargs)

    def const(self, value: int, type_: SemanticObject = B32) -> ValueRef:
        return self.block.const(type_, value)

    def bin(self, operation: Operation, left, right, type_: SemanticObject = B32) -> ValueRef:
        return self.op1(operation, (self._value(left, type_), self._value(right, type_)), type_)

    def cmp(self, kind: IntCompare, left, right, type_: SemanticObject = B32) -> ValueRef:
        return self.op1(Operation.INT_COMPARE, (self._value(left, type_), self._value(right, type_)), B1, attributes=(kind,))

    def any_of(self, *flags: ValueRef) -> ValueRef:
        result = flags[0]
        for flag in flags[1:]:
            result = self.op1(Operation.BIT_OR, (result, flag), B1)
        return result

    def all_of(self, *flags: ValueRef) -> ValueRef:
        result = flags[0]
        for flag in flags[1:]:
            result = self.op1(Operation.BIT_AND, (result, flag), B1)
        return result

    def widen(self, value: ValueRef, type_: SemanticObject = B32) -> ValueRef:
        return self.op1(Operation.INT_ZERO_EXTEND, (value,), type_)

    def group_call(self, member: int, operands, results) -> tuple[ValueRef, ...]:
        """``call.group_member`` (only inside recursion-group member graphs)."""
        block = self.block
        block.nodes.append(Node(Operation.CALL_GROUP_MEMBER, tuple(operands), tuple(results), member=member))
        self.graph.track(*results)
        index = len(block.nodes) - 1
        return tuple(ValueRef.node_result(block.index, index, result) for result in range(len(results)))

    def _value(self, value, type_: SemanticObject) -> ValueRef:
        return value if isinstance(value, ValueRef) else self.const(value, type_)

    # -- control -----------------------------------------------------------------
    def _carry(self) -> tuple[list[str], tuple[SemanticObject, ...]]:
        names = list(self.order)
        return names, tuple(self.types[name] for name in names)

    def _enter(self, block: BlockBuilder, names: list[str]) -> None:
        self.block = block
        self.vars = dict(zip(names, block.params))

    def _args(self, names: list[str]) -> tuple[ValueRef, ...]:
        return tuple(self.vars[name] for name in names)

    def _branch_to(self, target: BlockBuilder, names: list[str]) -> None:
        self.block.br(target, *self._args(names))

    def if_(self, condition: ValueRef, then: Callable[["Proc"], None], otherwise: Callable[["Proc"], None] | None = None) -> None:
        names, types = self._carry()
        then_block, else_block = self.graph.block(*types), self.graph.block(*types)
        self.block.cbr(condition, then_block, self._args(names), else_block, self._args(names))
        ends = []
        for block, body in ((then_block, then), (else_block, otherwise)):
            self._enter(block, names)
            if body is not None:
                body(self)
            if self.block is not None:
                ends.append((self.block, dict(self.vars)))
            self._truncate(names)
        if not ends:
            self.block = None
            return
        join = self.graph.block(*types)
        for block, values in ends:
            block.br(join, *(values[name] for name in names))
        self._enter(join, names)

    def while_(self, condition: Callable[["Proc"], ValueRef], body: Callable[["Proc"], None]) -> None:
        names, types = self._carry()
        header = self.graph.block(*types)
        self._branch_to(header, names)
        self._enter(header, names)
        flag = condition(self)
        header_block, header_vars = self.block, dict(self.vars)
        body_block, exit_block = self.graph.block(*types), self.graph.block(*types)
        header_block.cbr(flag, body_block, tuple(header_vars[name] for name in names), exit_block, tuple(header_vars[name] for name in names))
        self._enter(body_block, names)
        body(self)
        if self.block is not None:
            self._branch_to(header, names)
        self._truncate(names)
        self._enter(exit_block, names)

    def _truncate(self, names: list[str]) -> None:
        """Names declared inside a construct do not outlive it."""
        for name in self.order[len(names):]:
            del self.types[name]
        del self.order[len(names):]

    def ret(self, *values: ValueRef) -> None:
        self.block.ret(*values)
        self.block = None

    def function(self, returns: Sequence[SemanticObject]) -> SemanticObject:
        return self.graph.function(self.parameter_types, tuple(returns))

    def fragment(self):
        from xax_compiler import Block, graph_fragment

        missing = [block.index for block in self.graph.blocks if block.terminator is None]
        if missing:
            raise ValueError(f"blocks without terminator: {missing}")
        return graph_fragment([Block(block.parameter_types, tuple(block.nodes), block.terminator) for block in self.graph.blocks])
