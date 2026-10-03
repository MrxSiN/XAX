"""Self-hosting step S4 (ADR-132): scalar operation typing rules as XAX semantics.

After S3e proves every value use defined and dominated, the verifier types
each node.  This XAX function decides the arity and operand/result type rules
of the scalar operation families, decoding the type objects itself:

* integer binary (``add/sub/mul.wrap``, ``bit.and/or/xor``, ``udiv``, ``urem``):
  two operands and one result of the same ``bits<N>``, no attributes;
* ``int.truncate`` / ``int.zero_extend``: one ``bits<M>`` operand, one
  ``bits<N>`` result, strictly narrower / wider;
* ``rotate_right``: operand type equals the ``bits<N>`` result, amount < N;
* float binary: two operands and one result of the same float type;
* ``float.compare``: equal float operands, ``bits<1>`` result, known kind;
* ``uint/sint_to_float``: ``bits<=64>`` operand, float result;
* ``float_to_uint/sint_trunc``: float operand, ``bits<=64>`` result;
* ``float.convert``: float operand and result;
* ``int.compare``: equal ``bits<N>`` operands (or link operands with ``eq``/``ne``
  only), ``bits<1>`` result, known kind.

Input words: the type count T, then per type its object kind, reference
count, body length L, and L body bytes (one per word); then the node count
N and per node its operation, operand count, result count, attribute count,
first attribute (clamped below 2^63), operand type indices, result type
indices.  Output: ``out[0]`` status (0 accept, 1 reject on a malformed
stream, 2 defer when the tables do not fit), ``out[1]`` the proven count,
then one verdict per node: 0 outside these families, 1 proven, 2 not proven.

Soundness is one-sided by construction: a node is proven only when every
condition the bootstrap checks holds, with type bodies decoded strictly
(single-byte form; a value of one byte, or two bytes with a nonzero final
byte; exact end).  Anything else, including a canonical encoding this
decoder does not accept, is "not proven", and the bootstrap checks the node
and raises the exact diagnostic.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import platform
import sys
import threading
from pathlib import Path

from xax_compiler import (
    FloatCompare,
    IntCompare,
    Kind,
    Operation,
    SemanticObject,
    StoreReader,
    verify_store,
    x86_64_linux_exec_target,
)
from xax_graph_builder import program_store
from xax_selfhost_cfg import B64, IN_POINTER, IN_VIEW, IN_WORDS, MEM, OUT_POINTER, OUT_VIEW, OUT_WORDS, _Builder

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_op_typing.xax"
ACCEPT, REJECT, DEFER = 0, 1, 2
NOT_COVERED, PROVEN, NOT_PROVEN = 0, 1, 2
TABLE = OUT_WORDS // 2  # per-type tables start here; verdicts live below
ATTRIBUTE_LIMIT = (1 << 63) - 1

BINARY_INTEGER = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR, Operation.UDIV, Operation.UREM)
FLOAT_BINARY = (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV)
TO_FLOAT = (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT)
FROM_FLOAT = (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC)
COVERED = frozenset(
    {*BINARY_INTEGER, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT, *FLOAT_BINARY,
     Operation.FLOAT_COMPARE, *TO_FLOAT, *FROM_FLOAT, Operation.FLOAT_CONVERT, Operation.INT_COMPARE}
)


def _kind_range(kinds) -> int:
    values = sorted(int(item) for item in kinds)
    if values != list(range(1, len(values) + 1)):
        raise AssertionError("comparison kinds must be 1..n")
    return len(values)


INT_COMPARE_KINDS, FLOAT_COMPARE_KINDS = _kind_range(IntCompare), _kind_range(FloatCompare)
LINK_COMPARE_KINDS = (int(IntCompare.EQ), int(IntCompare.NE))


class _Typing:
    """Branch-free predicates over the cfg builder: every flag is a ``bits<64>`` 0 or 1."""

    def __init__(self, b: _Builder):
        self.b = b

    def flag(self, condition):
        return self.b.cur.op1(Operation.INT_ZERO_EXTEND, (condition,), B64)

    def eq(self, x, y):
        return self.flag(self.b.cmp(IntCompare.EQ, x, y))

    def lt(self, x, y):
        return self.flag(self.b.cmp(IntCompare.ULT, x, y))

    def le(self, x, y):
        return self.flag(self.b.cmp(IntCompare.ULE, x, y))

    def all(self, *flags):
        result = flags[0]
        for item in flags[1:]:
            result = self.b.op(Operation.BIT_AND, result, item)
        return result

    def any(self, *flags):
        result = flags[0]
        for item in flags[1:]:
            result = self.b.op(Operation.BIT_OR, result, item)
        return result

    def one_of(self, value, codes):
        return self.any(*(self.eq(value, int(code)) for code in codes))

    def nonzero(self, value):
        return self.flag(self.b.cmp(IntCompare.NE, value, 0))


def build_typing_program() -> tuple[StoreReader, SemanticObject]:
    b = _Builder()
    t = _Typing(b)
    count = b.read(b.c(0))
    b.check(b.cmp(IntCompare.ULE, b.mul(count, 3), OUT_WORDS - TABLE), b.defer_block)
    nodes_at = b.for_range(b.c(0), count, lambda index, carried: _type_entry(b, t, index, carried, count), (b.c(1),))[0]
    nodes = b.read(nodes_at)
    b.check(b.cmp(IntCompare.ULE, b.add(nodes, 2), TABLE), b.defer_block)

    def lookup(table: int, value):
        valid = b.cmp(IntCompare.ULT, value, count)
        index = b.select(valid, value, b.c(0))
        return b.mul(t.flag(valid), b.get(b.add(b.add(b.c(TABLE), b.mul(count, table)), index)))

    _end, proven = b.for_range(b.c(0), nodes, lambda index, carried: _node_entry(b, t, index, carried, lookup), (b.add(nodes_at, 1), b.c(0)))
    b.put(b.c(1), proven)
    b.put(b.c(0), ACCEPT)
    in_view, in_mem, out_view, out_mem = b.state
    b.cur.ret(b.inp, in_view, in_mem, b.out, out_view, out_mem)
    for failure, status in ((b.reject_block, REJECT), (b.defer_block, DEFER)):
        b.enter(failure)
        b.put(b.c(0), status)
        in_view, in_mem, out_view, out_mem = b.state
        b.cur.ret(b.inp, in_view, in_mem, b.out, out_view, out_mem)
    triples = (IN_POINTER, IN_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    function = b.g.function(triples, triples)
    return program_store(function, x86_64_linux_exec_target(), tuple(b.g.objects.values())), function


def _type_entry(b: _Builder, t: _Typing, index, carried, count):
    """One type: its ``bits`` width, float format, and link flag (0 when not that form)."""
    (position,) = carried
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    # Look-ahead past a short body reads the next words of the stream (which ends
    # in three zero words); the length conditions below make them irrelevant.
    first, second, third = (b.read(b.add(base, k)) for k in range(3))
    plain = t.all(t.eq(kind, int(Kind.TYPE)), t.eq(references, 0), t.lt(first, 128))
    single = t.all(t.lt(second, 128), t.eq(length, 2))
    double = t.all(t.le(b.c(128), second), t.lt(second, 256), t.lt(third, 128), t.nonzero(third), t.eq(length, 3))
    value = b.select(b.cmp(IntCompare.ULT, second, 128), second, b.add(b.sub(second, 128), b.mul(third, 128)))
    bits_ok = t.all(plain, t.eq(first, 1), t.any(single, double), t.nonzero(value))
    float_ok = t.all(plain, t.eq(first, 7), single, t.any(t.eq(second, 1), t.eq(second, 2)))
    link_ok = t.all(plain, t.eq(length, 1), t.eq(first, 11))
    b.put(b.add(b.c(TABLE), index), b.mul(bits_ok, value))
    b.put(b.add(b.add(b.c(TABLE), count), index), b.mul(float_ok, second))
    b.put(b.add(b.add(b.c(TABLE), b.mul(count, 2)), index), link_ok)
    return (b.add(base, length),)


def _node_entry(b: _Builder, t: _Typing, index, carried, lookup):
    position, proven = carried
    operation, operands, results, attributes, attribute = (b.read(b.add(position, k)) for k in range(5))
    ids = b.add(position, 5)
    first, second, result = b.read(ids), b.read(b.add(ids, 1)), b.read(b.add(ids, operands))
    width, first_width = lookup(0, result), lookup(0, first)
    form, first_form = lookup(1, result), lookup(1, first)
    first_link = lookup(2, first)

    def shape(count_in: int, count_out: int, count_attributes: int):
        return t.all(t.eq(operands, count_in), t.eq(results, count_out), t.eq(attributes, count_attributes))

    is_bits, first_bits = t.nonzero(width), t.nonzero(first_width)
    is_float, first_float = t.nonzero(form), t.nonzero(first_form)
    same_first, same_second, same_operands = t.eq(first, result), t.eq(second, result), t.eq(second, first)
    kind_in = lambda limit: t.all(t.le(b.c(1), attribute), t.le(attribute, limit))  # noqa: E731
    families = (
        (t.one_of(operation, BINARY_INTEGER), t.all(shape(2, 1, 0), is_bits, same_first, same_second)),
        (t.eq(operation, int(Operation.INT_TRUNCATE)), t.all(shape(1, 1, 0), is_bits, first_bits, t.lt(width, first_width))),
        (t.eq(operation, int(Operation.INT_ZERO_EXTEND)), t.all(shape(1, 1, 0), is_bits, first_bits, t.lt(first_width, width))),
        (t.eq(operation, int(Operation.ROTATE_RIGHT)), t.all(shape(1, 1, 1), is_bits, same_first, t.lt(attribute, width))),
        (t.one_of(operation, FLOAT_BINARY), t.all(shape(2, 1, 0), is_float, same_first, same_second)),
        (t.eq(operation, int(Operation.FLOAT_COMPARE)), t.all(shape(2, 1, 1), same_operands, first_float, t.eq(width, 1), kind_in(FLOAT_COMPARE_KINDS))),
        (t.one_of(operation, TO_FLOAT), t.all(shape(1, 1, 0), first_bits, t.le(first_width, 64), is_float)),
        (t.one_of(operation, FROM_FLOAT), t.all(shape(1, 1, 0), first_float, is_bits, t.le(width, 64))),
        (t.eq(operation, int(Operation.FLOAT_CONVERT)), t.all(shape(1, 1, 0), first_float, is_float)),
        (
            t.eq(operation, int(Operation.INT_COMPARE)),
            t.all(
                shape(2, 1, 1), same_operands, t.eq(width, 1),
                t.any(t.all(first_link, t.one_of(attribute, LINK_COMPARE_KINDS)), t.all(first_bits, kind_in(INT_COMPARE_KINDS))),
            ),
        ),
    )
    covered = t.any(*(member for member, _ok in families))
    ok = t.any(*(t.all(member, condition) for member, condition in families))
    verdict = b.add(covered, b.sub(covered, ok))  # 0 outside, 1 proven, 2 not proven
    b.put(b.add(b.c(2), index), verdict)
    return b.add(ids, b.add(operands, results)), b.add(proven, ok)


def load_typing_program() -> tuple[StoreReader, SemanticObject]:
    if not STORE_PATH.exists():
        return build_typing_program()
    reader = StoreReader(STORE_PATH.read_bytes())
    verify_store(reader)
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_typing_store() -> bytes:
    import xax_compiler

    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True
    try:
        reader, _function = build_typing_program()
        STORE_PATH.write_bytes(reader.data)
    finally:
        xax_compiler._TYPING_BUILDING = building
    return reader.data


BODY_LIMIT = 16  # longer bodies are never bits/float/link types: passed as "other"


def type_info_from(resolve):
    """``type_info`` over a resolver: None when the CID does not resolve."""

    def info(cid: bytes):
        try:
            item = resolve(cid)
        except Exception:  # noqa: BLE001 - any resolution failure leaves the node to the bootstrap
            return None
        if len(item.body) > BODY_LIMIT:
            return 0, 0, b""
        return int(item.kind), len(item.references), item.body

    return info


def marshal(blocks, operand_types_of, type_info) -> tuple[list[int], list[tuple[int, int]]]:
    """Input words for the covered nodes of parsed ``blocks`` and their (block, node) keys.

    ``operand_types_of(block, node)`` gives a node's operand type CIDs (or None
    to leave it to the bootstrap); ``type_info(cid)`` returns ``(kind,
    reference count, body)`` or None when the type cannot be resolved.
    """
    types: dict[bytes, int] = {}
    entries: list[tuple[int, int, int, bytes]] = []
    nodes: list[int] = []
    keys: list[tuple[int, int]] = []

    def type_index(cid: bytes) -> int | None:
        if cid not in types:
            info = type_info(cid)
            if info is None:
                return None
            types[cid] = len(entries)
            entries.append((cid, *info))
        return types[cid]

    for block_index, block in enumerate(blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation not in COVERED:
                continue
            operand_types = operand_types_of(block_index, node_index)
            if operand_types is None:
                continue
            indices = [type_index(cid) for cid in (*operand_types, *node.results)]
            if any(item is None for item in indices):
                continue
            attribute = min(node.attributes[0], ATTRIBUTE_LIMIT) if node.attributes else 0
            nodes += [int(node.operation), len(node.operands), len(node.results), len(node.attributes), attribute, *indices]
            keys.append((block_index, node_index))
    words = [len(entries)]
    for _cid, kind, references, body in entries:
        words += [kind, references, len(body), *body]
    # Three zero words end the stream so the decoder's fixed look-ahead stays inside it.
    words += [len(keys), *nodes, 0, 0, 0]
    return words, keys


class NativeTyping:
    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK, compile_native

        reader, function = load_typing_program()
        target = next(item for item in reader.objects() if item.kind == Kind.TARGET)
        image = compile_native(reader, function.cid, target.cid)
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + image.code
        self._mapping = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self._mapping.write(code)
        base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + image.entry_offset
        self.code_size = len(image.code)
        self._in = (ctypes.c_uint64 * IN_WORDS)()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def check(self, words: list[int], count: int) -> tuple[int, list[int] | None]:
        """``(status, verdict per node)`` for one marshalled stream of ``count`` nodes."""
        if len(words) > IN_WORDS or any(word >= 1 << 64 for word in words):
            return DEFER, None
        with self._lock:
            self._in[: len(words)] = words
            slots = self._slots
            slots[0], slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            status = self._out[0]
            if status != ACCEPT:
                return status, None
            return status, list(self._out[2 : 2 + count])


def native_typing_usable() -> bool:
    return (
        sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
        and os.environ.get("XAX_TYPING_PYTHON") != "1" and STORE_PATH.exists()
    )
