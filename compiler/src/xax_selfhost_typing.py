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
# Per-type tables, each T words from TABLE + k*T.
WIDTH, FORMAT, LINK, POSITION, AGGREGATE, COUNT, ITEMS = range(7)
EFFECT, RESOURCE, RKIND, RSTATE, RFLAGS, RINSTANCE, TSTART, TCOUNT, OPAQUE = range(7, 16)
TABLES = 16
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
     *RESOURCE_COUNTS, Operation.EFFECT_STEP, *META_RULES}
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
        """``(value, size, ok)`` for a canonical ULEB of at most three bytes at ``at``."""
        b = self.b
        x0, x1, x2 = (b.read(b.add(at, k)) for k in range(3))
        one = self.lt(x0, 128)
        two = self.all(self.not_(one), self.lt(x1, 128), self.nonzero(x1))
        three = self.all(self.not_(one), self.le(b.c(128), x1), self.lt(x1, 256), self.lt(x2, 128), self.nonzero(x2))
        low = b.sub(x0, 128)
        value = b.add(b.add(b.mul(one, x0), b.mul(two, b.add(low, b.mul(x1, 128)))), b.mul(three, b.add(b.add(low, b.mul(b.sub(x1, 128), 128)), b.mul(x2, 16384))))
        size = b.add(b.add(one, b.mul(two, 2)), b.mul(three, 3))
        return value, size, self.all(self.lt(x0, 256), self.any(one, two, three))


def build_typing_program() -> tuple[StoreReader, SemanticObject]:
    b = _Builder()
    count = b.read(b.c(0))
    t = _Typing(b, count)
    b.check(b.cmp(IntCompare.ULE, b.add(b.add(b.mul(count, TABLES), MARKS), IN_WORDS), OUT_WORDS - TABLE), b.defer_block)
    nodes_at = b.for_range(b.c(0), count, lambda index, carried: _scalar_entry(b, t, index, carried), (b.c(1),))[0]
    items = b.add(t.slot(TABLES, b.c(0)), MARKS)
    (items,) = b.for_range(b.c(0), count, lambda index, carried: _aggregate_entry(b, t, index, carried), (items,))
    b.for_range(b.c(0), count, lambda index, carried: _proof_entry(b, t, index, carried), (items,))
    nodes = b.read(nodes_at)
    b.check(b.cmp(IntCompare.ULE, b.add(nodes, 2), TABLE), b.defer_block)
    _end, proven = b.for_range(b.c(0), nodes, lambda index, carried: _node_entry(b, t, index, carried), (b.add(nodes_at, 1), b.c(0)))
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
        return b.add(at, width), t.all(ok, inside, t.scalar(element))

    after, items_ok = b.for_range(b.c(0), steps, item, (b.add(b.add(base, 1), size), b.c(1)))
    (used,) = b.for_range(b.c(0), b.mul(listed, references), lambda k, c: (b.add(c[0], b.get(b.add(t.slot(TABLES, b.c(0)), k))),), (b.c(0),))
    listed_ok = t.all(listed, count_ok, t.nonzero(steps), items_ok, t.eq(after, end), t.eq(used, references))
    # Array: reference index 0 (its only reference), then the count, exact end.
    reference, width, reference_ok = t.uleb(b.add(base, 1))
    array_count, array_size, array_count_ok = t.uleb(b.add(b.add(base, 1), width))
    element = b.read(end)
    array_ok = t.all(is_array, reference_ok, t.eq(reference, 0), t.eq(references, 1), array_count_ok, t.eq(b.add(b.add(b.add(base, 1), width), array_size), end), t.scalar(element))
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
    b.put(t.slot(OPAQUE, index), b.mul(opaque_ok, v1))
    b.put(t.slot(RESOURCE, index), resource_ok)
    b.put(t.slot(RKIND, index), v1)
    b.put(t.slot(RSTATE, index), v2)
    b.put(t.slot(RFLAGS, index), t.pick(owner, b.c(RELEASABLE), v3))
    b.put(t.slot(RINSTANCE, index), t.pick(owner, b.c(0), v4))
    b.put(t.slot(TSTART, index), cursor)
    b.put(t.slot(TCOUNT, index), b.mul(full, tcount))
    return (b.add(cursor, steps),)


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


def type_info_from(resolve):
    """``type_info`` over a resolver: ``(kind, references, body)``, or None when the CID does not resolve."""

    def info(cid: bytes):
        try:
            item = resolve(cid)
        except Exception:  # noqa: BLE001 - any resolution failure leaves the node to the bootstrap
            return None
        if len(item.body) > BODY_LIMIT:
            return 0, (), b""
        return int(item.kind), tuple(item.references), item.body

    return info


def marshal(blocks, operand_types_of, type_info) -> tuple[list[int], list[tuple[int, int]]]:
    """Input words for the covered nodes of parsed ``blocks`` and their (block, node) keys.

    ``operand_types_of(block, node)`` gives a node's operand type CIDs (or None
    to leave it to the bootstrap); ``type_info(cid)`` returns ``(kind,
    references, body)`` or None when the type cannot be resolved.  The types a
    type references are listed too (their own references transitively).
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
            extra = [values.setdefault(value, len(values)) for value in node.operands] if node.operation == Operation.EFFECT_STEP else []
            nodes += [int(node.operation), len(node.operands), len(node.results), len(node.attributes), attribute, len(extra), *indices, *extra]
            keys.append((block_index, node_index))
    words = [len(entries)]
    for kind, references, body in entries:
        words += [kind, len(references), len(body), *body, *references]
    words += [len(keys), *nodes, *(0,) * PADDING]
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
