"""Shared construction helpers for the Linux workload graphs (tooling only).

``Flow`` threads named SSA state, including linear tokens, through explicit
block parameters; ``Kit`` wraps the few node shapes the workloads repeat; and
``emit_decimal_line`` appends blocks that format unsigned 64-bit fields as one
decimal text line into a byte heap view.  None of this is XAX source syntax.
"""

from __future__ import annotations

from xax_compiler import IntCompare, Operation, SemanticObject, bits_type
from xax_graph_builder import BlockBuilder, GraphBuilder


class Flow:
    """Carry named SSA state (including linear tokens) across explicit block parameters."""

    def __init__(self, graph: GraphBuilder, names: tuple[str, ...], types: dict[str, SemanticObject]):
        self.graph = graph
        self.names = names
        self.types = types

    def block(self, *extra: tuple[str, SemanticObject]) -> tuple[BlockBuilder, dict]:
        order = (*self.names, *(name for name, _type in extra))
        types = {**self.types, **dict(extra)}
        block = self.graph.block(*(types[name] for name in order))
        block.order = order  # type: ignore[attr-defined]
        return block, dict(zip(order, block.params))

    @staticmethod
    def args(target: BlockBuilder, state: dict) -> tuple:
        return tuple(state[name] for name in target.order)  # type: ignore[attr-defined]


class Kit:
    """Node shortcuts over fixed bits<1>/<8>/<32>/<64> types."""

    def __init__(self) -> None:
        self.b1, self.b8, self.b32, self.b64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)

    def const(self, block: BlockBuilder, value: int, type_=None):
        return block.const(type_ or self.b64, value)

    def compare(self, block: BlockBuilder, kind: IntCompare, left, right):
        return block.op1(Operation.INT_COMPARE, (left, right), self.b1, attributes=(kind,))

    def binary(self, block: BlockBuilder, operation: Operation, left, right, type_=None):
        return block.op1(operation, (left, right), type_ or self.b64)


def emit_decimal_line(kit: Kit, flow: Flow, current: BlockBuilder, state: dict, fields: tuple[str, ...], buffer, memory_type: SemanticObject, memory_key: str = "buf_mem"):
    """Write ``state[field]`` values as space-separated decimal plus ``\\n`` at offset 0 of ``buffer``.

    ``flow`` must already carry every name in ``fields`` and ``memory_key``.
    Returns ``(block, state)`` after the line; ``state["pos"]`` is its byte length.
    """
    b8, b32, b64 = kit.b8, kit.b32, kit.b64
    const, compare, binary = kit.const, kit.compare, kit.binary
    field_types = tuple((name, b64) for name in fields)
    state = {**state, "pos": const(current, 0, b32)}
    carry = (*field_types, ("pos", b32))
    for index, name in enumerate(fields):
        separator = 10 if index == len(fields) - 1 else 32
        digits_block, digits_state = flow.block(*carry, ("t", b64), ("d", b32))
        write_block, write_state = flow.block(*carry, ("v", b64), ("k", b32), ("d", b32))
        current.br(digits_block, *flow.args(digits_block, {**state, "t": state[name], "d": const(current, 1, b32)}))
        d, ds = digits_block, digits_state
        more_block, more_state = flow.block(*carry, ("t", b64), ("d", b32))
        d.cbr(
            compare(d, IntCompare.UGE, ds["t"], const(d, 10)),
            more_block, flow.args(more_block, ds),
            write_block, flow.args(write_block, {**ds, "v": ds[name], "k": ds["d"]}),
        )
        more_block.br(digits_block, *flow.args(digits_block, {
            **more_state, "t": binary(more_block, Operation.UDIV, more_state["t"], const(more_block, 10)),
            "d": binary(more_block, Operation.ADD_WRAP, more_state["d"], const(more_block, 1, b32), b32),
        }))
        digit_block, digit_state = flow.block(*carry, ("v", b64), ("k", b32), ("d", b32))
        done_block, done_state = flow.block(*carry, ("d", b32))
        write_block.cbr(
            compare(write_block, IntCompare.NE, write_state["k"], const(write_block, 0, b32)),
            digit_block, flow.args(digit_block, write_state),
            done_block, flow.args(done_block, write_state),
        )
        w, ws = digit_block, digit_state
        k = binary(w, Operation.SUB_WRAP, ws["k"], const(w, 1, b32), b32)
        ascii_digit = w.op1(Operation.INT_TRUNCATE, (binary(w, Operation.ADD_WRAP, binary(w, Operation.UREM, ws["v"], const(w, 10)), const(w, 48)),), b8)
        memory = w.op1(Operation.CHECKED_STORE_BITS_LE, (buffer, binary(w, Operation.ADD_WRAP, ws["pos"], k, b32), ascii_digit, ws[memory_key]), memory_type, attributes=(1, 1))
        w.br(write_block, *flow.args(write_block, {**ws, memory_key: memory, "k": k, "v": binary(w, Operation.UDIV, ws["v"], const(w, 10))}))
        f, fs = done_block, done_state
        end = binary(f, Operation.ADD_WRAP, fs["pos"], fs["d"], b32)
        memory = f.op1(Operation.CHECKED_STORE_BITS_LE, (buffer, end, const(f, separator, b8), fs[memory_key]), memory_type, attributes=(1, 1))
        current, state = f, {**fs, memory_key: memory, "pos": binary(f, Operation.ADD_WRAP, end, const(f, 1, b32), b32)}
    return current, state
