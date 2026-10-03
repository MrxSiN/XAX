"""Self-hosting steps S4 and S4b (ADR-132, ADR-133): operation typing rules as XAX semantics.

After S3e proves every value use defined and dominated, the verifier types
each node.  This XAX function decides the arity and operand/result type rules
of the pure typing families, decoding the type objects itself:

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
  only), ``bits<1>`` result, known kind;
* S4c: the resource/effect operations (``effect.step`` with distinct effect
  operands and values; ``resource.acquire/transfer/transition/release/
  discard/split/join`` with their flag, state-transition, and continuation
  rules) and the meta operations (operand opaque kinds, result forms), with
  effect, resource, and opaque type bodies decoded canonically;
* S4b: ``aggregate.make`` (operands are the tuple's elements in order, or
  ``count`` copies of the array element), ``aggregate.get`` (index below the
  element count, result is that element), ``sum.make`` / ``sum.get`` (variant
  below the variant count, operand / result is that variant), ``sum.tag``
  (a ``bits<W>`` result with ``2^W`` at least the variant count).

Aggregate and sum types are proven only when every element or variant is a
scalar the decoder knows (``bits``, float, link), which are never proof types;
nested aggregates and other elements are left to the bootstrap.

Input words: the type count T, then per type its object kind, reference
count R, body length L, L body bytes (one per word), and the type indices of
its R references in table order; then the node count N and per node its
operation, operand count, result count, attribute count, first attribute
(clamped below 2^63), extra word count E, operand type indices, result type
indices, and E extra words (``effect.step``: its operand value identities);
then ``PADDING`` zero words.  Output: ``out[0]`` status (0 accept, 1 reject on a malformed
stream, 2 defer when the tables do not fit), ``out[1]`` the proven count,
then one verdict per node: 0 outside these families, 1 proven, 2 not proven.

Soundness is one-sided by construction: a node is proven only when every
condition the bootstrap checks holds, with type bodies decoded strictly
(single-byte forms; canonical values of at most three bytes; exact end).
Anything else, including a canonical encoding this decoder does not accept,
is "not proven", and the bootstrap checks the node and raises the exact
diagnostic.
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
    TerminatorKind,
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
from xax_compiler import heap_view_type
from xax_selfhost_cfg import B64, IN_POINTER, MEM, OUT_POINTER, _Builder

# The typing-and-facts program's own views: large graphs need room for their streams and fact tables.
IN_EXTENT, OUT_EXTENT = 16 << 20, 256 << 20
IN_WORDS, OUT_WORDS = IN_EXTENT // 8, OUT_EXTENT // 8
IN_VIEW, OUT_VIEW = heap_view_type(IN_EXTENT), heap_view_type(OUT_EXTENT)

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_op_typing.xax"
ACCEPT, REJECT, DEFER = 0, 1, 2
NOT_COVERED, PROVEN, NOT_PROVEN = 0, 1, 2
TABLE = OUT_WORDS // 2  # per-type tables start here; verdicts live below
ATTRIBUTE_LIMIT = (1 << 63) - 1
# Per-type tables, each T words from TABLE + k*T.
WIDTH, FORMAT, LINK, POSITION, AGGREGATE, COUNT, ITEMS = range(7)
EFFECT, RESOURCE, RKIND, RSTATE, RFLAGS, RINSTANCE, TSTART, TCOUNT, OPAQUE, EDOMAIN = range(7, 17)
# S4d.2b: pointer types (form 2) and the exact stack-owner and memory-effect forms.
PTR, PSPACE, PELEM, PPERM, PALIGN, STACKOWNER, MEMEFFECT = range(17, 24)
FORMB = 24  # S4d.2c: a type's raw first body byte (its form when single-byte), any type kind
OPID = 25  # S4d.2d: an opaque identity type (form 6): 1 when ``_decode_opaque_identity_type`` accepts it
EINST = 26  # S4d.2d: an effect type's instance (0 when absent)
OBJOK = 27  # S6b: 1 when the entry is a type ``_verify_type`` accepts or a constant ``_decode_constant`` accepts
TABLES = 28
# S4d.2a: types the memory-fact system tracks (besides pointers and other undecoded forms).
MEMORY_EFFECT_DOMAIN = 1
FACT_RESOURCE_KINDS = (1, 0x100, 0x101)  # stack storage, heap owner, heap view
PADDING = 24  # zero words ending the stream: the decoders' look-ahead stays inside it
AFFINE, PARTITIONABLE, RELEASABLE, ACQUIRABLE = 1, 2, 4, 8
EFFECT_DOMAINS, OPAQUE_KINDS = 11, 7
MARKS = 128  # scratch marks for reference use, after the tables; at most this many references
TUPLE, ARRAY, SUM = 8, 9, 10

BINARY_INTEGER = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR, Operation.UDIV, Operation.UREM)
FLOAT_BINARY = (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV)
TO_FLOAT = (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT)
FROM_FLOAT = (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC)
AGGREGATES = (Operation.AGGREGATE_MAKE, Operation.AGGREGATE_GET, Operation.SUM_MAKE, Operation.SUM_TAG, Operation.SUM_GET)
# S4c: resource/effect operations, (operands, results) per operation.
RESOURCE_COUNTS = {
    Operation.RESOURCE_ACQUIRE: (1, 2), Operation.RESOURCE_TRANSFER: (2, 2), Operation.RESOURCE_TRANSITION: (2, 2),
    Operation.RESOURCE_RELEASE: (2, 1), Operation.RESOURCE_DISCARD: (2, 1), Operation.RESOURCE_SPLIT: (2, 3), Operation.RESOURCE_JOIN: (3, 2),
}
# S4c: meta operations: operand kinds (an opaque kind, or None for bits), result count, attribute count,
# and the result rule (an opaque kind, "bit" for bits<1>, or "bits" for any bits<N>).
META_RULES = {
    Operation.META_TYPE_BITS_WIDTH: ((1,), 1, 0, "bits"),
    Operation.META_CONSTANT_VALUE: ((2,), 1, 0, "bits"),
    Operation.META_TARGET_SUPPORTS: ((4,), 1, 1, "bit"),
    Operation.META_DECLARED_INPUT: ((), 1, 1, "bits"),
    Operation.META_MATERIALIZE_CONSTANT_FUNCTION: ((1, None), 1, 0, 3),
    Operation.META_FUNCTION_GRAPH: ((3,), 1, 0, 5),
    Operation.META_GRAPH_BLOCK_COUNT: ((5,), 1, 0, "bits"),
    Operation.META_GRAPH_NODE_COUNT: ((5, None), 1, 0, "bits"),
    Operation.META_GRAPH_NODE_OPERATION: ((5, None, None), 1, 0, "bits"),
    Operation.META_CANONICAL_STORE: ((6,), 1, 0, 7),
    Operation.META_VERIFY_SEMANTICS: ((6,), 1, 0, "bit"),
    Operation.META_MATERIALIZE_PROGRAM: ((3,), 1, 0, 6),
    Operation.META_FUNCTION_PARAMETER_COUNT: ((3,), 1, 0, "bits"),
    Operation.META_FUNCTION_RETURN_COUNT: ((3,), 1, 0, "bits"),
}
COVERED = frozenset(
    {*BINARY_INTEGER, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT, *FLOAT_BINARY,
     Operation.FLOAT_COMPARE, *TO_FLOAT, *FROM_FLOAT, Operation.FLOAT_CONVERT, Operation.INT_COMPARE, *AGGREGATES,
     *RESOURCE_COUNTS, Operation.EFFECT_STEP, *META_RULES, Operation.CONSTANT, Operation.CALL_DIRECT}
)
CONDITIONAL_BRANCH = int(TerminatorKind.CONDITIONAL_BRANCH)
F32_QUIET_NAN, F64_QUIET_NAN = 0x7FC00000, 0x7FF8000000000000


def _kind_range(kinds) -> int:
    values = sorted(int(item) for item in kinds)
    if values != list(range(1, len(values) + 1)):
        raise AssertionError("comparison kinds must be 1..n")
    return len(values)


INT_COMPARE_KINDS, FLOAT_COMPARE_KINDS = _kind_range(IntCompare), _kind_range(FloatCompare)
LINK_COMPARE_KINDS = (int(IntCompare.EQ), int(IntCompare.NE))


ULEB_BYTES = 5  # values below 2^35: view extents and instances up to 32 GiB


def _uleb_bytes(t, data):
    """Branch-free canonical ULEB of at most ``len(data)`` bytes: length L is the first byte below 128,
    and a multi-byte encoding's last byte is nonzero.  ``t`` provides add/mul/flag predicates."""
    b = t.b
    value, size, ok = b.c(0), b.c(0), b.c(0)
    continuing = b.c(1)  # every earlier byte had its continuation bit
    for length in range(1, len(data) + 1):
        last = data[length - 1]
        ends = t.all(continuing, t.lt(last, 128), t.nonzero(last) if length > 1 else b.c(1))
        total = b.c(0)
        for index in range(length):
            low = data[index] if index == length - 1 else b.sub(data[index], 128)
            total = b.add(total, b.mul(low, 1 << (7 * index)))
        value = b.add(value, b.mul(ends, total))
        size = b.add(size, b.mul(ends, length))
        ok = b.op(Operation.BIT_OR, ok, ends)
        continuing = t.all(continuing, t.le(b.c(128), last), t.lt(last, 256))
    return value, size, ok


class _Typing:
    """Branch-free predicates over the cfg builder: every flag is a ``bits<64>`` 0 or 1."""

    def __init__(self, b: _Builder, count):
        self.b = b
        self.count = count

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

    def not_(self, flag):
        return self.b.op(Operation.BIT_XOR, flag, 1)

    def one_of(self, value, codes):
        return self.any(*(self.eq(value, int(code)) for code in codes))

    def nonzero(self, value):
        return self.flag(self.b.cmp(IntCompare.NE, value, 0))

    def pick(self, flag, if_true, if_false):
        return self.b.select(self.b.cmp(IntCompare.NE, flag, 0), if_true, if_false)

    def slot(self, table: int, index):
        return self.b.add(self.b.add(self.b.c(TABLE), self.b.mul(self.count, table)), index)

    def lookup(self, table: int, value):
        """Table entry for a type index; 0 for an index outside the table."""
        valid = self.b.cmp(IntCompare.ULT, value, self.count)
        index = self.b.select(valid, value, self.b.c(0))
        return self.b.mul(self.flag(valid), self.b.get(self.slot(table, index)))

    def scalar(self, value):
        return self.any(self.nonzero(self.lookup(WIDTH, value)), self.nonzero(self.lookup(FORMAT, value)), self.lookup(LINK, value))

    def uleb(self, at):
        """``(value, size, ok)`` for a canonical ULEB of at most five bytes at ``at``."""
        return _uleb_bytes(self, [self.b.read(self.b.add(at, k)) for k in range(ULEB_BYTES)])


_ENGINE: list = []


def build_typing_program() -> tuple[StoreReader, SemanticObject]:
    from xax_selfhost_facts import build_engine

    engine, engine_objects = build_engine()
    _ENGINE[:] = [engine, engine_objects]
    b = _Builder(IN_EXTENT, OUT_EXTENT)
    count = b.read(b.c(0))
    t = _Typing(b, count)
    b.check(b.cmp(IntCompare.ULE, b.add(b.add(b.mul(count, TABLES), MARKS), IN_WORDS), OUT_WORDS - TABLE), b.defer_block)
    nodes_at = b.for_range(b.c(0), count, lambda index, carried: _scalar_entry(b, t, index, carried), (b.c(1),))[0]
    items = b.add(t.slot(TABLES, b.c(0)), MARKS)
    # Aggregate items first (all elements unvalidated), so proof-type transition lists follow them.
    (after_items,) = b.for_range(b.c(0), count, lambda index, carried: _aggregate_entry(b, t, index, carried), (items,))
    b.for_range(b.c(0), count, lambda index, carried: _proof_entry(b, t, index, carried), (after_items,))
    # Pointers and aggregates validate each other's elements: two rounds reach depth two
    # (each aggregate round rewrites the same item slots: the layout does not depend on validity).
    for _depth in range(2):
        b.for_range(b.c(0), count, lambda index, carried: _pointer_entry(b, t, index) or (), ())
        b.for_range(b.c(0), count, lambda index, carried: _aggregate_entry(b, t, index, carried), (items,))
    b.for_range(b.c(0), count, lambda index, carried: _object_entry(b, t, index) or (), ())
    nodes = b.read(nodes_at)
    b.check(b.cmp(IntCompare.ULE, b.add(nodes, 2), TABLE), b.defer_block)
    blocks_at, proven = b.for_range(b.c(0), nodes, lambda index, carried: _node_entry(b, t, index, carried), (b.add(nodes_at, 1), b.c(0)))
    # S4d.1: terminator typing, one verdict per block after the node verdicts.
    blocks = b.read(blocks_at)
    places = b.add(b.add(t.slot(TABLES, b.c(0)), MARKS), IN_WORDS)  # block stream positions
    b.check(b.cmp(IntCompare.ULE, b.add(b.add(nodes, blocks), 3), TABLE), b.defer_block)
    b.check(b.cmp(IntCompare.ULE, b.add(places, blocks), OUT_WORDS), b.defer_block)
    (facts_at,) = b.for_range(b.c(0), blocks, lambda index, carried: _block_place(b, index, carried, places), (b.add(blocks_at, 1),))
    verdicts = b.add(b.c(2), nodes)
    b.for_range(b.c(0), blocks, lambda index, carried: _block_entry(b, t, index, carried, blocks, places, verdicts), ())
    # S4d.2a: the graph is memory-free when every type object is decoded and none is one the fact system tracks.
    (memory_free,) = b.for_range(b.c(0), count, lambda index, carried: (t.all(carried[0], _fact_free_type(b, t, index)),), (b.c(1),))
    b.put(b.add(verdicts, blocks), memory_free)
    # S4d.2b: the facts engine runs over the facts section (if any), reading these header words.
    from xax_selfhost_facts import H_COUNT, H_FACTS_AT, H_LIST, H_NODES, H_TABLE, HEADER, VIEW_TYPES

    for field, value in ((H_FACTS_AT, facts_at), (H_COUNT, count), (H_TABLE, b.c(TABLE)), (H_NODES, nodes), (H_LIST, b.add(b.add(places, blocks), 3))):
        b.put(b.c(HEADER + field), value)
    in_view, in_mem, out_view, out_mem = b.state
    # The original pointers stay valid (the views come back whole); the shared reject/defer blocks use them.
    _status, _inp, in_view, in_mem, _out, out_view, out_mem = b.cur.op(
        Operation.CALL_DIRECT, (b.inp, in_view, in_mem, b.out, out_view, out_mem), (B64, *VIEW_TYPES), entity=_ENGINE[0])
    b.state = (in_view, in_mem, out_view, out_mem)
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
    return program_store(function, x86_64_linux_exec_target(), (*b.g.objects.values(), *engine_objects)), function


def _value_element(t: _Typing, element):
    """A tuple, array, or sum element: a validated type that is not a proof type (effect or resource)."""
    return t.all(_known(t, element), t.not_(t.any(t.lookup(EFFECT, element), t.lookup(RESOURCE, element))))


def _scalar_entry(b: _Builder, t: _Typing, index, carried):
    """Pass 1, one type: its ``bits`` width, float format, link flag, and stream position."""
    (position,) = carried
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    # Look-ahead past a short body reads the next words of the stream (which ends
    # in PADDING zero words); the length conditions below make them irrelevant.
    first, second, third = (b.read(b.add(base, k)) for k in range(3))
    plain = t.all(t.eq(kind, int(Kind.TYPE)), t.eq(references, 0), t.lt(first, 128))
    single = t.all(t.lt(second, 128), t.eq(length, 2))
    double = t.all(t.le(b.c(128), second), t.lt(second, 256), t.lt(third, 128), t.nonzero(third), t.eq(length, 3))
    value = b.select(b.cmp(IntCompare.ULT, second, 128), second, b.add(b.sub(second, 128), b.mul(third, 128)))
    bits_ok = t.all(plain, t.eq(first, 1), t.any(single, double), t.nonzero(value))
    float_ok = t.all(plain, t.eq(first, 7), single, t.any(t.eq(second, 1), t.eq(second, 2)))
    link_ok = t.all(plain, t.eq(length, 1), t.eq(first, 11))
    b.put(t.slot(WIDTH, index), b.mul(bits_ok, value))
    b.put(t.slot(FORMAT, index), b.mul(float_ok, second))
    b.put(t.slot(LINK, index), link_ok)
    b.put(t.slot(POSITION, index), position)
    b.put(t.slot(FORMB, index), b.mul(t.all(t.eq(kind, int(Kind.TYPE)), t.nonzero(length)), first))
    return (b.add(b.add(base, length), references),)


def _aggregate_entry(b: _Builder, t: _Typing, index, carried):
    """Pass 2, one type: a tuple, array, or sum of known scalars, with its element type indices."""
    (cursor,) = carried
    position = b.get(t.slot(POSITION, index))
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    end = b.add(base, length)  # the reference indices follow the body
    form = b.read(base)
    plain = t.all(t.eq(kind, int(Kind.TYPE)), t.le(b.c(1), references), t.le(references, MARKS), t.le(b.c(2), length))
    listed = t.all(plain, t.any(t.eq(form, TUPLE), t.eq(form, SUM)))
    is_array = t.all(plain, t.eq(form, ARRAY))
    count, size, count_ok = t.uleb(b.add(base, 1))
    # Tuple or sum: ``count`` reference indices, each naming a scalar, every reference used.
    b.for_range(b.c(0), b.mul(listed, references), lambda k, c: (b.put(b.add(t.slot(TABLES, b.c(0)), k), 0),) and (), ())
    steps = t.pick(t.all(listed, count_ok, t.le(count, length)), count, b.c(0))

    def item(k, carried):
        at, ok = carried
        reference, width, reference_ok = t.uleb(at)
        inside = t.all(reference_ok, t.lt(reference, references), t.le(b.add(at, width), end))
        element = b.read(b.add(end, t.pick(inside, reference, b.c(0))))
        b.put(b.add(cursor, k), element)
        b.put(b.add(t.slot(TABLES, b.c(0)), t.pick(inside, reference, b.c(0))), 1)
        return b.add(at, width), t.all(ok, inside, _value_element(t, element))

    after, items_ok = b.for_range(b.c(0), steps, item, (b.add(b.add(base, 1), size), b.c(1)))
    (used,) = b.for_range(b.c(0), b.mul(listed, references), lambda k, c: (b.add(c[0], b.get(b.add(t.slot(TABLES, b.c(0)), k))),), (b.c(0),))
    listed_ok = t.all(listed, count_ok, t.nonzero(steps), items_ok, t.eq(after, end), t.eq(used, references))
    # Array: reference index 0 (its only reference), then the count, exact end.
    reference, width, reference_ok = t.uleb(b.add(base, 1))
    array_count, array_size, array_count_ok = t.uleb(b.add(b.add(base, 1), width))
    element = b.read(end)
    array_ok = t.all(is_array, reference_ok, t.eq(reference, 0), t.eq(references, 1), array_count_ok, t.eq(b.add(b.add(b.add(base, 1), width), array_size), end), _value_element(t, element))
    b.put(b.add(cursor, b.mul(listed, steps)), element)  # an array's one element (harmless after a list)
    ok = t.any(listed_ok, array_ok)
    b.put(t.slot(AGGREGATE, index), b.mul(ok, form))
    b.put(t.slot(COUNT, index), t.pick(array_ok, array_count, count))
    b.put(t.slot(ITEMS, index), cursor)
    return (b.add(b.add(cursor, b.mul(listed, steps)), 1),)


def _proof_entry(b: _Builder, t: _Typing, index, carried):
    """Pass 3, one type (S4c): effect, resource (with its transition list), and opaque forms."""
    (cursor,) = carried
    position = b.get(t.slot(POSITION, index))
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    end = b.add(base, length)
    form = b.read(base)
    plain = t.all(t.eq(kind, int(Kind.TYPE)), t.eq(references, 0), t.lt(form, 128))
    at = b.add(base, 1)
    fields = []  # (value, ok, next position) for up to five header values
    for _ in range(5):
        value, size, ok = t.uleb(at)
        at = b.add(at, size)
        fields.append((value, t.all(ok, t.le(at, end)), at))
    (v1, ok1, p2), (v2, ok2, p3), (v3, ok3, _p4), (v4, ok4, _p5), (tcount, ok5, p6) = fields
    in_range = lambda value, low, high: t.all(t.le(b.c(low), value), t.le(value, high))  # noqa: E731
    effect_ok = t.all(plain, t.eq(form, 3), ok1, in_range(v1, 1, EFFECT_DOMAINS), t.any(t.eq(p2, end), t.all(ok2, t.nonzero(v2), t.eq(p3, end))))
    opaque_ok = t.all(plain, t.eq(form, 5), ok1, t.eq(p2, end), in_range(v1, 1, OPAQUE_KINDS))
    resource = t.all(plain, t.eq(form, 4), ok1, ok2)
    owner = t.all(resource, t.eq(p3, end), t.eq(v1, 1), t.eq(v2, 1))
    header = t.all(resource, ok3, ok4, ok5, t.nonzero(v1), t.nonzero(v2), t.eq(b.op(Operation.BIT_AND, v3, ~0xF & (1 << 64) - 1), 0))
    steps = t.pick(t.all(header, t.le(tcount, length)), tcount, b.c(0))

    def transition(k, carried_):
        at_, ok, previous = carried_
        value, size, value_ok = t.uleb(at_)
        after = b.add(at_, size)
        b.put(b.add(cursor, k), value)
        good = t.all(value_ok, t.le(after, end), t.lt(previous, value), t.nonzero(b.op(Operation.BIT_XOR, value, v2)))
        return after, t.all(ok, good), value

    after, transitions_ok, _last = b.for_range(b.c(0), steps, transition, (p6, b.c(1), b.c(0)))
    owner_shape = t.all(t.eq(v1, 1), t.eq(v2, 1), t.eq(v3, RELEASABLE), t.eq(v4, 0), t.eq(tcount, 0))
    full = t.all(header, t.eq(steps, tcount), transitions_ok, t.eq(after, end), t.not_(owner_shape))
    resource_ok = t.any(owner, full)
    b.put(t.slot(EFFECT, index), effect_ok)
    b.put(t.slot(MEMEFFECT, index), t.all(effect_ok, t.eq(v1, MEMORY_EFFECT_DOMAIN), t.eq(p2, end)))
    b.put(t.slot(STACKOWNER, index), owner)
    b.put(t.slot(EDOMAIN, index), b.mul(effect_ok, v1))
    b.put(t.slot(EINST, index), b.mul(effect_ok, t.pick(t.eq(p2, end), b.c(0), v2)))
    b.put(t.slot(OPAQUE, index), b.mul(opaque_ok, v1))
    # form 6: a nonempty byte string identity, exactly to the end, no references.
    b.put(t.slot(OPID, index), t.all(plain, t.eq(form, 6), ok1, t.nonzero(v1), t.eq(b.add(p2, v1), end)))
    b.put(t.slot(RESOURCE, index), resource_ok)
    b.put(t.slot(RKIND, index), v1)
    b.put(t.slot(RSTATE, index), v2)
    b.put(t.slot(RFLAGS, index), t.pick(owner, b.c(RELEASABLE), v3))
    b.put(t.slot(RINSTANCE, index), t.pick(owner, b.c(0), v4))
    b.put(t.slot(TSTART, index), cursor)
    b.put(t.slot(TCOUNT, index), b.mul(full, tcount))
    return (b.add(cursor, steps),)


def _pointer_entry(b: _Builder, t: _Typing, index):
    """Pass 4, one type: ``ptr<space, element, permission, alignment>`` as ``_decode_pointer_type`` accepts it."""
    position = b.get(t.slot(POSITION, index))
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    end = b.add(base, length)
    form = b.read(base)
    at = b.add(base, 1)
    fields = []
    for _ in range(4):  # space, element reference, permission, alignment
        value, size, ok = t.uleb(at)
        at = b.add(at, size)
        fields.append((value, t.all(ok, t.le(at, end))))
    (space, space_ok), (reference, reference_ok), (permission, permission_ok), (alignment, alignment_ok) = fields
    element = b.read(end)
    element_ok = t.all(t.lt(element, t.count), _known(t, element), t.not_(t.any(t.lookup(EFFECT, element), t.lookup(RESOURCE, element))))
    power = t.all(t.nonzero(alignment), t.eq(b.op(Operation.BIT_AND, alignment, b.sub(alignment, 1)), 0))
    ok = t.all(
        t.eq(kind, int(Kind.TYPE)), t.eq(references, 1), t.eq(form, 2), space_ok, t.nonzero(space), reference_ok, t.eq(reference, 0),
        permission_ok, t.le(b.c(1), permission), t.le(permission, 3), alignment_ok, power, t.eq(at, end), element_ok,
    )
    for table, value in ((PTR, ok), (PSPACE, space), (PELEM, element), (PPERM, permission), (PALIGN, alignment)):
        b.put(t.slot(table, index), b.mul(ok, value) if table != PTR else ok)


def _resource_rules(b: _Builder, t: _Typing, operation, operands, results, attributes, attribute, ids, extra_at):
    """S4c families: ``(member, ok)`` pairs for the resource/effect and meta operations."""
    def operand(k):
        return b.read(b.add(ids, k))

    def result(k):
        return b.read(b.add(b.add(ids, operands), k))

    def flagged(value, bit):
        return t.nonzero(b.op(Operation.BIT_AND, t.lookup(RFLAGS, value), bit))

    is_resource = lambda value: t.lookup(RESOURCE, value)  # noqa: E731
    last_in = b.read(b.add(ids, b.sub(operands, 1)))
    last_out = b.read(b.add(b.add(ids, operands), b.sub(results, 1)))
    continuation = t.all(t.lookup(EFFECT, last_in), t.eq(last_in, last_out))
    source, target, second = operand(0), result(0), result(1)

    def shape(count_in: int, count_out: int):
        return t.all(t.eq(operands, count_in), t.eq(results, count_out), t.eq(attributes, 0), continuation)

    def contains(k, carried):
        (found,) = carried
        listed = b.get(b.add(t.lookup(TSTART, source), k))
        return (t.any(found, t.eq(listed, t.lookup(RSTATE, target))),)

    (reachable,) = b.for_range(b.c(0), t.lookup(TCOUNT, source), contains, (b.c(0),))
    rules = [
        (Operation.RESOURCE_ACQUIRE, t.all(shape(1, 2), is_resource(target), flagged(target, ACQUIRABLE))),
        (Operation.RESOURCE_TRANSFER, t.all(shape(2, 2), is_resource(source), t.eq(target, source))),
        (
            Operation.RESOURCE_TRANSITION,
            t.all(
                shape(2, 2), is_resource(source), is_resource(target), t.eq(t.lookup(RKIND, target), t.lookup(RKIND, source)),
                t.eq(flagged(target, AFFINE), flagged(source, AFFINE)), t.eq(t.lookup(RINSTANCE, target), t.lookup(RINSTANCE, source)), reachable,
            ),
        ),
        (Operation.RESOURCE_RELEASE, t.all(shape(2, 1), is_resource(source), flagged(source, RELEASABLE))),
        (Operation.RESOURCE_DISCARD, t.all(shape(2, 1), is_resource(source), flagged(source, AFFINE))),
        (Operation.RESOURCE_SPLIT, t.all(shape(2, 3), is_resource(source), t.eq(target, source), t.eq(second, source), flagged(source, PARTITIONABLE))),
        (Operation.RESOURCE_JOIN, t.all(shape(3, 2), is_resource(source), t.eq(operand(1), source), t.eq(target, source), flagged(source, PARTITIONABLE))),
    ]
    # effect.step: matching effect operands/results, distinct types, distinct operand values.
    stepping = t.all(t.eq(attributes, 0), t.nonzero(operands), t.eq(operands, results))

    def step(k, carried):
        (ok,) = carried
        here = operand(k)
        same = t.all(t.eq(here, result(k)), t.lookup(EFFECT, here))

        def distinct(j, carried_):
            (unique,) = carried_
            other = t.lt(j, k)
            clash = t.any(t.eq(operand(j), here), t.eq(b.read(b.add(extra_at, j)), b.read(b.add(extra_at, k))))
            return (t.all(unique, t.not_(t.all(other, clash))),)

        (unique,) = b.for_range(b.c(0), k, distinct, (b.c(1),))
        return (t.all(ok, same, unique),)

    (stepped,) = b.for_range(b.c(0), b.mul(stepping, operands), step, (stepping,))
    rules.append((Operation.EFFECT_STEP, stepped))
    for meta, (kinds, result_count, attribute_count, result_rule) in META_RULES.items():
        checks = [t.eq(operands, len(kinds)), t.eq(results, result_count), t.eq(attributes, attribute_count)]
        for position_, opaque in enumerate(kinds):
            value = operand(position_)
            checks.append(t.nonzero(t.lookup(WIDTH, value)) if opaque is None else t.eq(t.lookup(OPAQUE, value), opaque))
        if result_rule == "bits":
            checks.append(t.nonzero(t.lookup(WIDTH, target)))
        elif result_rule == "bit":
            checks.append(t.eq(t.lookup(WIDTH, target), 1))
        else:
            checks.append(t.eq(t.lookup(OPAQUE, target), result_rule))
        if meta == Operation.META_TARGET_SUPPORTS:
            checks.append(t.one_of(attribute, tuple(Operation)))
        rules.append((meta, t.all(*checks)))
    return rules


def _known(t: _Typing, value):
    """A type the decoders fully validated (what ``_verify_type`` accepts, restricted to decoded forms)."""
    return t.any(
        t.nonzero(t.lookup(WIDTH, value)), t.nonzero(t.lookup(FORMAT, value)), t.lookup(LINK, value), t.nonzero(t.lookup(AGGREGATE, value)),
        t.lookup(EFFECT, value), t.lookup(RESOURCE, value), t.nonzero(t.lookup(OPAQUE, value)), t.lookup(PTR, value), t.lookup(OPID, value),
    )


def _fact_free_type(b: _Builder, t: _Typing, index):
    """1 unless entry ``index`` is a type the fact system tracks, or a type the decoders did not validate."""
    kind = b.read(b.get(t.slot(POSITION, index)))
    tracked = t.any(
        t.lookup(LINK, index),
        t.lookup(PTR, index),
        t.all(t.lookup(EFFECT, index), t.eq(t.lookup(EDOMAIN, index), MEMORY_EFFECT_DOMAIN)),
        t.all(t.lookup(RESOURCE, index), t.one_of(t.lookup(RKIND, index), FACT_RESOURCE_KINDS)),
    )
    return t.any(t.not_(t.eq(kind, int(Kind.TYPE))), t.all(_known(t, index), t.not_(tracked)))


def _call_rule(b: _Builder, t: _Typing, operands, results, extra, extra_at, ids):
    """``call.direct``: a function object whose decoded interface equals the node's types.

    The function's graph is a graph fragment (its interface follows in the
    function body) or a recursion group (the body names a member, whose
    interface the group lists; ADR-125).  Group bodies are decoded whole, as
    ``_decode_recursion_group`` does: every member's graph is a fragment, every
    type is valid, the body ends exactly, and every reference is used.
    """
    entity = b.read(extra_at)
    valid = t.lt(entity, t.count)
    position = b.get(t.slot(POSITION, t.pick(valid, entity, b.c(0))))
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    end = b.add(base, length)
    graph, size, graph_ok = t.uleb(base)
    graph_inside = t.all(graph_ok, t.lt(graph, references))
    graph_entry = b.read(b.add(end, t.pick(graph_inside, graph, b.c(0))))

    def entry_kind(entry):
        ok = t.lt(entry, t.count)
        return b.mul(ok, b.read(b.get(t.slot(POSITION, t.pick(ok, entry, b.c(0))))))

    graph_kind = entry_kind(graph_entry)

    def interface(start, expected_count, expected_at, refs_at, ref_count, limit):
        count, count_size, count_ok = t.uleb(start)
        same = t.all(count_ok, t.eq(count, expected_count))

        def item(k, carried):
            at, ok = carried
            reference, width, reference_ok = t.uleb(at)
            inside = t.all(reference_ok, t.lt(reference, ref_count), t.le(b.add(at, width), limit))
            declared = b.read(b.add(refs_at, t.pick(inside, reference, b.c(0))))
            return b.add(at, width), t.all(ok, inside, _known(t, declared), t.eq(declared, b.read(b.add(expected_at, k))))

        return b.for_range(b.c(0), b.mul(same, count), item, (b.add(start, count_size), same))

    after_parameters, parameters_ok = interface(b.add(base, size), operands, ids, end, references, end)
    after_returns, returns_ok = interface(after_parameters, results, b.add(ids, operands), end, references, end)
    fragment_ok = t.all(t.eq(graph_kind, int(Kind.GRAPH_FRAGMENT)), parameters_ok, returns_ok, t.eq(after_returns, end))
    # A recursion-group member function: [graph, member], the group decoded whole.
    member, member_size, member_ok = t.uleb(b.add(base, size))
    group_ok = _group_member_interface(b, t, graph_entry, member, operands, results, ids, interface)
    group_ok = t.all(t.eq(graph_kind, int(Kind.RECURSION_GROUP)), member_ok, t.eq(b.add(b.add(base, size), member_size), end), group_ok)
    return t.all(t.eq(extra, 1), valid, t.eq(kind, int(Kind.FUNCTION)), graph_inside, t.any(fragment_ok, group_ok))


def _group_member_interface(b: _Builder, t: _Typing, group_entry, member, operands, results, ids, interface):
    """1 when the recursion group decodes and member ``member``'s interface equals the node's types."""
    valid = t.lt(group_entry, t.count)
    position = b.get(t.slot(POSITION, t.pick(valid, group_entry, b.c(0))))
    references, length = b.read(b.add(position, 1)), b.read(b.add(position, 2))
    base = b.add(position, 3)
    end = b.add(base, length)
    count, count_size, count_ok = t.uleb(base)
    marks = t.slot(TABLES, b.c(0))
    small = t.le(references, MARKS)
    b.for_range(b.c(0), b.mul(small, references), lambda k, c: (b.put(b.add(marks, k), 0),) and (), ())

    def reference(at, ok, need_graph):
        value, width, value_ok = t.uleb(at)
        inside = t.all(value_ok, t.lt(value, references), t.le(b.add(at, width), end))
        target = b.read(b.add(end, t.pick(inside, value, b.c(0))))
        b.put(b.add(marks, t.pick(inside, value, b.c(0))), 1)
        target_ok = t.lt(target, t.count)
        target_kind = b.mul(target_ok, b.read(b.get(t.slot(POSITION, t.pick(target_ok, target, b.c(0))))))
        good = t.eq(target_kind, int(Kind.GRAPH_FRAGMENT)) if need_graph else _known(t, target)
        return b.add(at, width), t.all(ok, inside, good)

    def types_list(at, ok):
        n, n_size, n_ok = t.uleb(at)
        steps = b.mul(t.all(n_ok, t.le(n, length)), n)
        return b.for_range(b.c(0), steps, lambda _k, c: reference(c[0], c[1], False), (b.add(at, n_size), t.all(ok, n_ok)))

    def each_member(k, carried):
        at, ok, target = carried
        at, ok = reference(at, ok, True)
        target = b.select(b.cmp(IntCompare.EQ, k, member), at, target)
        at, ok = types_list(at, ok)
        at, ok = types_list(at, ok)
        return at, ok, target

    members = b.mul(t.all(count_ok, t.nonzero(count), t.le(count, length)), count)
    walked, members_ok, target = b.for_range(b.c(0), members, each_member, (b.add(base, count_size), t.all(count_ok, t.nonzero(count)), b.c(0)))
    (used,) = b.for_range(b.c(0), b.mul(small, references), lambda k, c: (b.add(c[0], b.get(b.add(marks, k))),), (b.c(0),))
    after_parameters, parameters_ok = interface(target, operands, ids, end, references, end)
    _after_returns, returns_ok = interface(after_parameters, results, b.add(ids, operands), end, references, end)
    return t.all(
        valid, t.eq(b.read(position), int(Kind.RECURSION_GROUP)), small, members_ok, t.eq(walked, end), t.eq(used, references),
        t.lt(member, count), parameters_ok, returns_ok,
    )


def _block_place(b: _Builder, index, carried, places):
    """Record a block's stream position; skip its parameters and terminator."""
    (position,) = carried
    b.put(b.add(places, index), position)
    parameters = b.read(b.add(position, 1))
    at = b.add(b.add(position, 2), parameters)  # terminator kind, condition type, edge count
    edges = b.read(b.add(at, 2))

    def edge(_k, carried_):
        (cursor,) = carried_
        return (b.add(b.add(cursor, 2), b.read(b.add(cursor, 1))),)

    (end,) = b.for_range(b.c(0), edges, edge, (b.add(at, 3),))
    return (end,)


def _block_entry(b: _Builder, t: _Typing, index, _carried, blocks, places, verdicts):
    """A block's terminator: a ``bits<1>`` branch condition, and edge argument types equal to the target's parameters."""
    position = b.get(b.add(places, index))
    known = b.read(position)  # 0 when some value type was not marshalled
    parameters = b.read(b.add(position, 1))
    at = b.add(b.add(position, 2), parameters)
    kind, condition, edges = b.read(at), b.read(b.add(at, 1)), b.read(b.add(at, 2))
    condition_ok = t.any(t.not_(t.eq(kind, CONDITIONAL_BRANCH)), t.eq(t.lookup(WIDTH, condition), 1))

    def edge(_k, carried):
        cursor, ok = carried
        target, count = b.read(cursor), b.read(b.add(cursor, 1))
        inside = t.lt(target, blocks)
        target_at = b.get(b.add(places, t.pick(inside, target, b.c(0))))
        expected = b.read(b.add(target_at, 1))
        same_count = t.all(inside, t.eq(count, expected))

        def argument(j, carried_):
            (match,) = carried_
            return (t.all(match, t.eq(b.read(b.add(b.add(cursor, 2), j)), b.read(b.add(b.add(target_at, 2), j)))),)

        (match,) = b.for_range(b.c(0), b.mul(same_count, count), argument, (same_count,))
        return b.add(b.add(cursor, 2), count), t.all(ok, match)

    _end, edges_ok = b.for_range(b.c(0), edges, edge, (b.add(at, 3), b.c(1)))
    ok = t.all(t.nonzero(known), condition_ok, edges_ok)
    b.put(b.add(verdicts, index), b.sub(b.c(NOT_PROVEN), ok))
    return ()


def _constant_rule(b: _Builder, t: _Typing, operands, results, extra, extra_at, result):
    """``constant``: a canonical constant object of a scalar type, no operands, one result of that type."""
    entity = b.read(extra_at)
    ok, value_type = _constant_object(b, t, entity)
    return t.all(ok, t.eq(extra, 1), t.eq(operands, 0), t.eq(results, 1), t.eq(result, value_type))


def _constant_object(b: _Builder, t: _Typing, entity):
    """``(ok, value type)``: entry ``entity`` is a constant object ``_decode_constant`` accepts."""
    position = t.pick(t.lt(entity, t.count), b.get(t.slot(POSITION, t.pick(t.lt(entity, t.count), entity, b.c(0)))), b.c(0))
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    end = b.add(base, length)
    reference, size, reference_ok = t.uleb(base)
    count, count_size, count_ok = t.uleb(b.add(base, size))
    data = b.add(b.add(base, size), count_size)
    value_type = b.read(end)
    shape = t.all(
        t.lt(entity, t.count), t.eq(kind, int(Kind.CONSTANT)), t.eq(references, 1), reference_ok, t.eq(reference, 0),
        count_ok, t.eq(b.add(data, count), end),
    )
    width, form, link = t.lookup(WIDTH, value_type), t.lookup(FORMAT, value_type), t.lookup(LINK, value_type)
    # bits<W>: ceil(W/8) bytes, unused high bits of the last byte zero.
    spare = b.op(Operation.UREM, width, 8)
    limit = b.c(256)
    for bits_ in range(1, 8):
        limit = t.pick(t.eq(spare, bits_), b.c(1 << bits_), limit)
    last = b.read(b.add(data, t.pick(t.nonzero(count), b.sub(count, 1), b.c(0))))
    bits_ok = t.all(t.nonzero(width), t.eq(count, b.op(Operation.UDIV, b.add(width, 7), 8)), t.lt(last, limit))
    # float and link values: at most eight little-endian bytes.
    small = t.le(count, 8)

    def byte(k, carried):
        raw, scale, zero = carried
        value = b.read(b.add(data, k))
        return b.add(raw, b.mul(value, scale)), b.mul(scale, 256), t.all(zero, t.eq(value, 0))

    raw, _scale, zero = b.for_range(b.c(0), b.mul(small, count), byte, (b.c(0), b.c(1), b.c(1)))

    def nan(exponent_shift, exponent_mask, mantissa_mask):
        exponent = b.op(Operation.BIT_AND, b.op(Operation.UDIV, raw, 1 << exponent_shift), exponent_mask)
        return t.all(t.eq(exponent, exponent_mask), t.nonzero(b.op(Operation.BIT_AND, raw, mantissa_mask)))

    f32 = t.all(t.eq(form, 1), t.eq(count, 4), t.any(t.not_(nan(23, 0xFF, (1 << 23) - 1)), t.eq(raw, F32_QUIET_NAN)))
    f64 = t.all(t.eq(form, 2), t.eq(count, 8), t.any(t.not_(nan(52, 0x7FF, (1 << 52) - 1)), t.eq(raw, F64_QUIET_NAN)))
    link_ok = t.all(link, t.eq(count, 8), zero)
    return t.all(shape, t.any(bits_ok, f32, f64, link_ok)), value_type


def _object_entry(b: _Builder, t: _Typing, index):
    """S6b (ADR-143): the entry's object verdict: a valid type (``_known``) or a valid constant."""
    kind = b.read(b.get(t.slot(POSITION, index)))
    constant_ok, _value_type = _constant_object(b, t, index)
    verdict = t.any(t.all(t.eq(kind, int(Kind.TYPE)), _known(t, index)), t.all(t.eq(kind, int(Kind.CONSTANT)), constant_ok))
    b.put(t.slot(OBJOK, index), verdict)


def _node_entry(b: _Builder, t: _Typing, index, carried):
    position, proven = carried
    operation, operands, results, attributes, attribute, extra = (b.read(b.add(position, k)) for k in range(6))
    ids = b.add(position, 6)
    extra_at = b.add(ids, b.add(operands, results))
    first, second, result = b.read(ids), b.read(b.add(ids, 1)), b.read(b.add(ids, operands))
    width, first_width = t.lookup(WIDTH, result), t.lookup(WIDTH, first)
    form, first_form = t.lookup(FORMAT, result), t.lookup(FORMAT, first)
    first_link = t.lookup(LINK, first)

    def shape(count_in: int, count_out: int, count_attributes: int):
        return t.all(t.eq(operands, count_in), t.eq(results, count_out), t.eq(attributes, count_attributes))

    is_bits, first_bits = t.nonzero(width), t.nonzero(first_width)
    is_float, first_float = t.nonzero(form), t.nonzero(first_form)
    same_first, same_second, same_operands = t.eq(first, result), t.eq(second, result), t.eq(second, first)
    kind_in = lambda limit: t.all(t.le(b.c(1), attribute), t.le(attribute, limit))  # noqa: E731

    # S4b: aggregates and sums, by the result's (make) or first operand's (get, tag) type.
    def element(owner, position_):
        """Element ``position_`` of ``owner``'s list (an array's one element), or 0 outside it."""
        shape_ = t.lookup(AGGREGATE, owner)
        inside = t.lt(position_, t.lookup(COUNT, owner))
        offset = t.pick(t.eq(shape_, ARRAY), b.c(0), t.pick(inside, position_, b.c(0)))
        return b.mul(t.all(t.nonzero(shape_), inside), b.get(b.add(t.lookup(ITEMS, owner), offset))), t.all(t.nonzero(shape_), inside)

    result_shape, first_shape = t.lookup(AGGREGATE, result), t.lookup(AGGREGATE, first)
    make_listed = t.all(t.eq(attributes, 0), t.eq(results, 1), t.any(t.eq(result_shape, TUPLE), t.eq(result_shape, ARRAY)), t.eq(operands, t.lookup(COUNT, result)))

    def make_step(k, carried):
        (ok,) = carried
        expected, inside = element(result, k)
        return (t.all(ok, inside, t.eq(b.read(b.add(ids, k)), expected)),)

    (make_ok,) = b.for_range(b.c(0), b.mul(make_listed, operands), make_step, (make_listed,))
    get_element, get_inside = element(first, attribute)
    tuple_or_array = t.any(t.eq(first_shape, TUPLE), t.eq(first_shape, ARRAY))
    make_variant, make_inside = element(result, attribute)
    # Variant count c fits in bits<W> when the bit length of c - 1 is at most W.
    variants = t.lookup(COUNT, first)
    _rest, needed = b.loop((b.sub(variants, 1), b.c(0)), lambda v: b.cmp(IntCompare.NE, v[0], 0), lambda v: (b.op(Operation.UDIV, v[0], 2), b.add(v[1], 1)))
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
        (t.eq(operation, int(Operation.AGGREGATE_MAKE)), make_ok),
        (t.eq(operation, int(Operation.AGGREGATE_GET)), t.all(shape(1, 1, 1), tuple_or_array, get_inside, t.eq(result, get_element))),
        (t.eq(operation, int(Operation.SUM_MAKE)), t.all(shape(1, 1, 1), t.eq(result_shape, SUM), make_inside, t.eq(first, make_variant))),
        (t.eq(operation, int(Operation.SUM_TAG)), t.all(shape(1, 1, 0), t.eq(first_shape, SUM), is_bits, t.le(needed, width))),
        (t.eq(operation, int(Operation.SUM_GET)), t.all(shape(1, 1, 1), t.eq(first_shape, SUM), get_inside, t.eq(result, get_element))),
        *((t.eq(operation, int(member)), condition) for member, condition in _resource_rules(b, t, operation, operands, results, attributes, attribute, ids, extra_at)),
        (t.eq(operation, int(Operation.CONSTANT)), _constant_rule(b, t, operands, results, extra, extra_at, result)),
        (t.eq(operation, int(Operation.CALL_DIRECT)), _call_rule(b, t, operands, results, extra, extra_at, ids)),
    )
    covered = t.any(*(member for member, _ok in families))
    ok = t.any(*(t.all(member, condition) for member, condition in families))
    verdict = b.add(covered, b.sub(covered, ok))  # 0 outside, 1 proven, 2 not proven
    b.put(b.add(b.c(2), index), verdict)
    return b.add(extra_at, extra), b.add(proven, ok)


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


BODY_LIMIT = 64  # longer bodies are passed as "other" (never proven)
TARGET_BODY_LIMIT = 4096  # foreign-function carriers embed their interface CIDs


def type_info_from(resolve):
    """``type_info`` over a resolver: ``(kind, references, body)``, or None when the CID does not resolve."""

    def info(cid: bytes):
        try:
            item = resolve(cid)
        except Exception:  # noqa: BLE001 - any resolution failure leaves the node to the bootstrap
            return None
        if item.kind in (Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT, Kind.TYPE) and len(item.body) <= TARGET_BODY_LIMIT:
            # S4d.2c: foreign declarations, recursion groups; S4d.2d: identity types embedding CIDs (lend entries).
            return int(item.kind), tuple(item.references), item.body
        if len(item.body) > BODY_LIMIT or item.kind not in (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION):
            # Kind only: graph bodies (and their references) are never needed, and no rule accepts a longer body.
            return int(item.kind), (), b""
        return int(item.kind), tuple(item.references), item.body

    return info


def marshal(blocks, operand_types_of, type_info, value_type_of=None, facts=None, objects=()):
    """Input words for the covered nodes of parsed ``blocks`` and their (block, node) keys.

    ``operand_types_of(block, node)`` gives a node's operand type CIDs (or None
    to leave it to the bootstrap); ``type_info(cid)`` returns ``(kind,
    references, body)`` or None when the object cannot be resolved.  The
    objects an object references are listed too (transitively).  With
    ``value_type_of(block, value)``, every block's parameters and terminator
    follow (S4d.1); otherwise the block section is empty.
    """
    types: dict[bytes, int] = {}
    entries: list[list] = []
    nodes: list[int] = []
    keys: list[tuple[int, int]] = []
    values: dict = {}

    def type_index(cid: bytes) -> int | None:
        if cid in types:
            return types[cid]
        info = type_info(cid)
        if info is None:
            return None
        kind, references, body = info
        types[cid] = len(entries)
        entry = [kind, (), body]
        entries.append(entry)
        indices = [type_index(reference) for reference in references]
        # An unresolvable reference makes the type "other": nothing referencing it is proven.
        entry[0], entry[1] = (kind, tuple(indices)) if None not in indices else (0, ())
        return types[cid]

    listed = {cid: type_index(cid) for cid in objects}  # S6b: objects to give a verdict for
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
            # effect.step also lists its operand values (distinctness is part of its rule).
            if node.operation == Operation.EFFECT_STEP:
                extra = [values.setdefault(value, len(values)) for value in node.operands]
            elif node.operation in (Operation.CONSTANT, Operation.CALL_DIRECT):
                entity = None if node.entity is None else type_index(node.entity.cid)
                extra = [] if entity is None else [entity]
            else:
                extra = []
            nodes += [int(node.operation), len(node.operands), len(node.results), len(node.attributes), attribute, len(extra), *indices, *extra]
            keys.append((block_index, node_index))
    section: list[int] = []
    for block_index, block in enumerate(blocks if value_type_of is not None else ()):
        parameters = [type_index(cid) for cid in block.parameters]
        term = block.terminator
        condition = type_index(value_type_of(block_index, term.values[0])) if term.kind == TerminatorKind.CONDITIONAL_BRANCH else 0
        edges = [(target, [type_index(value_type_of(block_index, value)) for value in arguments]) for target, arguments in term.edges]
        known = None not in parameters and condition is not None and all(None not in argument_types for _target, argument_types in edges)
        clean = lambda items: [0 if item is None else item for item in items]  # noqa: E731
        section += [int(known), len(parameters), *clean(parameters), int(term.kind), condition or 0, len(edges)]
        for target, argument_types in edges:
            section += [target, len(argument_types), *clean(argument_types)]
    facts_section, refs = _facts_section(blocks, facts, keys, type_index, value_type_of) if facts is not None else ([0], None)
    if facts is not None:
        facts_section += _cid_words([cid for cid, _index in sorted(types.items(), key=lambda item: item[1])])
    # Serialized last: the block and facts sections can add types.
    words = [len(entries)]
    for kind, references, body in entries:
        words += [kind, len(references), len(body), *body, *references]
    words += [len(keys), *nodes]
    words += [len(blocks) if value_type_of is not None else 0, *section, *facts_section, *(0,) * PADDING]
    if objects:
        return words, listed
    return (words, keys) if facts is None else (words, keys, refs)


def _facts_section(blocks, facts, keys, type_index, value_type_of):
    """S4d.2b: the facts engine's input (see ``xax_selfhost_facts``); ``refs`` maps value ids to ValueRefs."""
    from xax_compiler import ValueRef
    from xax_selfhost_facts import NONE

    entry, order, callee_summary, *rest = facts
    callee_links = rest[0] if rest else None
    key_of = {key: index for index, key in enumerate(keys)}
    refs, ids = [], {}
    for block_index, block in enumerate(blocks):
        for index in range(len(block.parameters)):
            ids[ValueRef.parameter(block_index, index)] = len(refs)
            refs.append(ValueRef.parameter(block_index, index))
        for node_index, node in enumerate(block.nodes):
            for result in range(len(node.results)):
                ids[ValueRef.node_result(block_index, node_index, result)] = len(refs)
                refs.append(ValueRef.node_result(block_index, node_index, result))
    entry_parameters = len(blocks[entry].parameters)
    kinds = [0] + [1] * entry_parameters  # (-1, 0), then (-2, i)
    sites: dict[tuple[int, int], int] = {}
    for block_index, block in enumerate(blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation in (Operation.STACK_ALLOC, Operation.HEAP_VIEW, Operation.CALL_FOREIGN):
                sites[(block_index, node_index)] = len(kinds)
                kinds.append(2)
            elif node.operation in (Operation.CALL_DIRECT, Operation.CALL_GROUP_MEMBER):
                sites[(block_index, node_index)] = len(kinds)
                kinds.extend([3] * len(node.results))
    edges: dict[tuple[int, int], int] = {}
    incoming: dict[int, list[int]] = {index: [] for index in range(len(blocks))}
    for block_index, block in enumerate(blocks):
        for edge_index, (target, _arguments) in enumerate(block.terminator.edges):
            edges[(block_index, edge_index)] = len(edges)
            incoming[target].append(edges[(block_index, edge_index)])
    body: list[int] = []
    for block_index, block in enumerate(blocks):
        body += [ids[ValueRef.parameter(block_index, 0)] if block.parameters else 0, len(block.parameters), *(_index(type_index, cid) for cid in block.parameters), len(block.nodes)]
        for node_index, node in enumerate(block.nodes):
            ref = ValueRef.node_result(block_index, node_index, 0)
            operand_types = [value_type_of(block_index, value) for value in node.operands]
            supported = all(item < ATTRIBUTE_LIMIT for item in node.attributes)
            entity = NONE if node.entity is None else _index(type_index, node.entity.cid)
            body += [
                int(node.operation) if supported else 0, key_of.get((block_index, node_index), NONE), entity, sites.get((block_index, node_index), NONE),
                ids.get(ref, 0), len(node.attributes), *(min(item, ATTRIBUTE_LIMIT) for item in node.attributes),
                len(node.operands), *(ids[value] for value in node.operands), *(_index(type_index, cid) for cid in operand_types),
                len(node.results), *(_index(type_index, cid) for cid in node.results),
            ]
            # Auxiliary words: a direct call's callee summary ``[blocks, operation count, operations]``
            # when its interface carries a stack owner (resource call contracts), else none.
            summary = callee_summary(node) if node.operation == Operation.CALL_DIRECT and callee_summary is not None else None
            # S4d.2d: then the callee's entry ``link_target`` declarations ``[count, (view, target) pairs]``
            # (count NONE when they cannot be read).
            links = callee_links(node) if node.operation == Operation.CALL_DIRECT and callee_links is not None else {}
            if summary is None and not links:
                body += [0]
            else:
                aux = [summary[0], len(summary[1]), *summary[1]] if summary is not None else [0, 0]
                aux += [NONE] if links is None else [len(links), *(item for pair in sorted(links.items()) for item in pair)]
                body += [len(aux), *aux]
        term = block.terminator
        body += [
            int(term.kind), len(term.values), *(ids[value] for value in term.values),
            *(_index(type_index, value_type_of(block_index, value)) for value in term.values), len(term.edges),
        ]
        for edge_index, (target, arguments) in enumerate(term.edges):
            body += [target, edges[(block_index, edge_index)], len(arguments), *(ids[value] for value in arguments)]
        body += [len(incoming[block_index]), *incoming[block_index]]
    words = [1, len(refs), len(kinds), len(edges), len(blocks), entry, *order, *kinds, *body]
    return words, refs


def _cid_words(cids: list[bytes]) -> list[int]:
    """S4d.2c: each type entry's CID as four little-endian words (foreign declarations name types by CID)."""
    return [int.from_bytes(cid[offset:offset + 8], "little") for cid in cids for offset in range(0, 32, 8)]


def _index(type_index, cid: bytes) -> int:
    from xax_selfhost_facts import NONE

    index = type_index(cid)
    return NONE if index is None else index


def _native_image() -> tuple[bytes, int]:
    """``(machine code, entry offset)`` of the typing program, from the cache when present.

    The cache key covers the exact store bytes and the backend sources that
    lower them, so a changed store or compiler never reuses old code.  The
    cache is a build artifact (``XAX_NATIVE_CACHE``, default
    ``~/.cache/xax-native``); deleting it only costs a recompile.
    """
    import hashlib
    import tempfile

    from xax_x86_64 import compile_native

    sources = Path(__file__).resolve().parent
    digest = hashlib.sha256(STORE_PATH.read_bytes() if STORE_PATH.exists() else b"")
    for name in ("xax_compiler.py", "xax_x86_64.py", "xax_x86_64_regalloc.py"):
        digest.update((sources / name).read_bytes())
    cache = Path(os.environ.get("XAX_NATIVE_CACHE", Path.home() / ".cache" / "xax-native"))
    entry = cache / f"typing-{digest.hexdigest()}.bin"
    try:
        data = entry.read_bytes()
        return data[8:], int.from_bytes(data[:8], "little")
    except OSError:
        pass
    reader, function = load_typing_program()
    target = next(item for item in reader.objects() if item.kind == Kind.TARGET)
    image = compile_native(reader, function.cid, target.cid)
    try:
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as handle:
            handle.write(image.entry_offset.to_bytes(8, "little") + image.code)
        os.replace(handle.name, entry)
    except OSError:
        pass  # an unwritable cache only costs the next process a recompile
    return image.code, image.entry_offset


class NativeTyping:
    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = _native_image()

        class _Image:
            code = machine_code

        image = _Image()
        image.entry_offset = entry_offset
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

    def facts(self, values: int) -> tuple[bool, list[int]]:
        """After ``check``: whether the facts engine accepted, and per value its pointer extent + 1 (0: none)."""
        from xax_selfhost_facts import ACCEPTED, H_EXTENTS, H_STATUS, HEADER

        if self._out[HEADER + H_STATUS] != ACCEPTED:
            return False, []
        return True, self._extents(values)

    def object_verdicts(self, words: list[int], listed: dict) -> set[bytes]:
        """S6b (ADR-143): the CIDs among ``listed`` (CID -> entry index) that XAX proves valid types or constants."""
        status, _verdicts = self.check(words, 0)
        if status != ACCEPT:
            return set()
        count = words[0]
        base = TABLE + count * OBJOK
        return {cid for cid, index in listed.items() if index is not None and self._out[base + index] == 1}

    def linear_flow(self) -> bool:
        """After an accepted ``check``: S6a (ADR-142), whether XAX proved ``_verify_linear_flow``."""
        from xax_selfhost_facts import H_LINEAR, HEADER

        return self._out[HEADER + H_LINEAR] == 1

    def decline_reason(self) -> str:
        """The engine check that declined the last graph (diagnosis only)."""
        from xax_selfhost_facts import DECLINE_SITES, H_REASON, HEADER, build_engine

        if not DECLINE_SITES:
            build_engine()  # the codes are assigned in build order
        code = self._out[HEADER + H_REASON] - 1
        return DECLINE_SITES[code] if 0 <= code < len(DECLINE_SITES) else f"code {code}"

    def _extents(self, values: int) -> list[int]:
        from xax_selfhost_facts import H_EXTENTS, HEADER

        base = self._out[HEADER + H_EXTENTS]
        return list(self._out[base : base + values])

    def check(self, words: list[int], count: int) -> tuple[int, list[int] | None]:
        """``(status, verdicts)`` for one marshalled stream: ``count`` verdicts (nodes, then blocks)."""
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
