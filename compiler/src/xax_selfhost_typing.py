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
import threading

from xax_compiler import (
    OpaqueKind, TerminatorKind, FloatCompare, IntCompare, Kind, Operation, SemanticObject, StoreReader)
from xax_compiler import heap_view_type
from xax_selfhost_cfg import B64, IN_POINTER, OUT_POINTER, _Builder

# The typing-and-facts program's own views: large graphs need room for their streams and fact tables.
IN_EXTENT, OUT_EXTENT = 1 << 30, 1 << 31  # S15e.4 (ADR-322): output 2 GiB; ADR-334: input 1 GiB. S6c; S10e (ADR-266): the driver store as one object table, its stream
# S12e.3 (ADR-277): both views grew 2x (input from 128 MiB, output from 512 MiB; the input stays at most a quarter of
# the output) so the general driver's own object table (28.3M words) fits.  ADR-287: the input view grew to 512 MiB
# for the verifier's object table of the growing driver store, and (ADR-334) to 1 GiB when the JVM program made it
# 71M words; the typing program's own input stays bounded by TYPING_WORDS, the quarter of the output its tables reserve
# for it.
IN_WORDS, OUT_WORDS = IN_EXTENT // 8, OUT_EXTENT // 8
TYPING_WORDS = (256 << 20) // 8
IN_VIEW, OUT_VIEW = heap_view_type(IN_EXTENT), heap_view_type(OUT_EXTENT)

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_op_typing.xax"
ACCEPT, REJECT, DEFER = 0, 1, 2
NOT_COVERED, PROVEN, NOT_PROVEN = 0, 1, 2
# S8c.1 (ADR-214): XAX rejects the node; its diagnostic record is the four words at DIAGNOSTICS + 4 * node.
REJECTED = 3
DIAGNOSTICS = OUT_WORDS // 4  # below TABLE, above every verdict
PASS_NODES_AT = DIAGNOSTICS - 1  # the node stream position, for the rejection pass (ADR-218)
PASS_SINK = DIAGNOSTICS - 2  # S8c.7: where list words go that do not fit below TABLE (never read)
TERMINATOR_RECORDS = PASS_SINK - 4  # S8 (ADR-251): block b's terminator record at TERMINATOR_RECORDS - 4 * b
# Rejection sites, in each family's bootstrap check order: (code, rule) and the record's payload meaning.
(SITE_NONE, SITE_OP_ARITY, SITE_OP_TYPE, SITE_INT_WIDTH_CONTRACT, SITE_INT_TRUNCATE_NARROWS, SITE_INT_ZERO_EXTEND_WIDENS,
 SITE_ROTATE_CONTRACT, SITE_ROTATE_TYPE, SITE_ROTATE_AMOUNT,
 # S8c.2 (ADR-215): float and integer-compare families.
 SITE_FLOAT_BINARY_CONTRACT, SITE_FLOAT_BINARY_TYPE, SITE_FLOAT_COMPARE_CONTRACT, SITE_FLOAT_COMPARE_OPERANDS, SITE_FLOAT_COMPARE_RESULT,
 SITE_FLOAT_COMPARE_KIND, SITE_UINT_TO_FLOAT_CONTRACT, SITE_SINT_TO_FLOAT_CONTRACT, SITE_UINT_TO_FLOAT_WIDTH, SITE_SINT_TO_FLOAT_WIDTH,
 SITE_FLOAT_TO_UINT_CONTRACT, SITE_FLOAT_TO_SINT_CONTRACT, SITE_FLOAT_TO_UINT_WIDTH, SITE_FLOAT_TO_SINT_WIDTH, SITE_FLOAT_CONVERT_CONTRACT,
 SITE_INT_COMPARE_CONTRACT, SITE_INT_COMPARE_LINK_EQUALITY, SITE_INT_COMPARE_TYPE, SITE_INT_COMPARE_KIND,
 # S8c.3 (ADR-216): aggregates and sums.
 SITE_AGGREGATE_MAKE_CONTRACT, SITE_AGGREGATE_MAKE_TYPE, SITE_AGGREGATE_MAKE_ELEMENTS, SITE_AGGREGATE_GET_CONTRACT, SITE_AGGREGATE_GET_TYPE,
 SITE_AGGREGATE_GET_INDEX, SITE_SUM_MAKE_CONTRACT, SITE_SUM_MAKE_VARIANT, SITE_SUM_TAG_CONTRACT, SITE_SUM_TAG_WIDTH, SITE_SUM_GET_CONTRACT,
 SITE_SUM_GET_VARIANT,
 # S8c.4 (ADR-217): meta operations; META-OP-ARITY has one site per operation (its expected counts), from SITE_META_ARITY.
 SITE_META_OPERAND_TYPE, SITE_META_RESULT_TYPE, SITE_META_VERIFY_RESULT, SITE_META_TARGET_SUPPORT_RESULT, SITE_META_TARGET_OPERATION,
 SITE_META_ARITY) = range(46)
# S8c.5 (ADR-218): resource and effect operations, after the per-operation META-OP-ARITY sites.
(SITE_RES_NO_ATTRIBUTES, SITE_RES_STEP_MATCH, SITE_RES_EXPECT_EFFECT, SITE_RES_EFFECT_UNIQUE, SITE_RES_COUNTS, SITE_RES_CONTINUATION,
 SITE_RES_EXPECT_RESOURCE, SITE_RES_ACQUIRE_ALLOWED, SITE_RES_RELEASE_ALLOWED, SITE_RES_DISCARD_ALLOWED, SITE_RES_JOIN_MATCH,
 SITE_RES_JOIN_PARTITIONABLE, SITE_RES_TRANSFER_SAME, SITE_RES_TRANSITION, SITE_RES_SPLIT) = range(SITE_META_ARITY + 14, SITE_META_ARITY + 29)
# S8c.6 (ADR-219): constant targets and contracts, direct-call targets.
(SITE_CONSTANT_TARGET_NONE, SITE_CONSTANT_TARGET_KIND, SITE_CONSTANT_CONTRACT, SITE_CALL_TARGET_NONE,
 SITE_CALL_TARGET_KIND) = range(SITE_META_ARITY + 29, SITE_META_ARITY + 34)
SITE_CALL_CONTRACT = SITE_META_ARITY + 34  # S8c.7 (ADR-220)
# S8 (ADR-251): a node's type decoded as ``bits`` or ``float`` that the decoder rejects (payload: the type); the
# diagnostic is the decoder's own, for the type (its per-type XSTAT/XA/XB outcome).
SITE_CROSS_BITS, SITE_CROSS_FLOAT = SITE_META_ARITY + 35, SITE_META_ARITY + 36
# S15b.3d (ADR-297): a sum operation's type of another (valid) form: ``_decode_sum_type``'s TYPE-SUM, for the type.
SITE_CROSS_SUM = SITE_META_ARITY + 37
TABLE = OUT_WORDS // 2  # per-type tables start here; verdicts live below
# The tables and the block positions after them hold a copy-sized region of the input (``places``): an input view
# more than half the space above TABLE defers every stream (ADR-266).
assert TYPING_WORDS <= (OUT_WORDS - TABLE) // 2
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
# S8c.24 (ADR-242): a well-formed constant ``_decode_constant`` rejects: its site, value offset in the body, value bytes,
# and the type's width (bits) or float width.
CREJ, COFF, CLEN, CWIDTH = 28, 29, 30, 31
C4, C5 = 32, 33  # S8c.26 (ADR-244): a resource type's flags and instance
# S8 (ADR-251): the type's body read as ``decode_bits_width``/``decode_float_format`` read it: XSTAT 0 (form and value
# read, nothing left: XA the form, XB the value), 1-3 a malformed ULEB (XA its body offset, XB its size), 4 deferred
# (a value over five bytes, or a type the stream does not resolve), 5 trailing bytes (XA how many), 6 not a type (XA
# its kind).
XSTAT, XA, XB = 34, 35, 36
C6 = 37  # S8: a resource type's transition-count body offset
# S8 (ADR-251): the type's body read as ``_decode_pointer_type`` reads it before its element: XP 0 (a pointer shape, or
# not decided), 1-3 a malformed ULEB (XPA its offset), 4 deferred, 5 trailing bytes (XPA), 6 element index out of range
# (XPA), 7 unknown permission (XPA), 8 not a pointer shape (XPA form, XPB space, XPC alignment).
XP, XPA, XPB, XPC = 38, 39, 40, 41
TABLES = 42
CONSTANT_SITES = ("BITS_WIDTH", "FLOAT_WIDTH", "FLOAT_NAN", "LINK_NULL", "SCALAR_TYPE",
                  # S8c.29 (ADR-247): malformed bodies (COFF: the index, CLEN: the value length, CWIDTH: bytes available or left).
                  "CONST_REF_INDEX", "CONST_TRUNCATED", "CONST_TRAILING")
# S8c.25 (ADR-243): ``_verify_type`` rejections of scalar and unknown forms, in the same tables (COFF: the form, CLEN:
# the second body value, CWIDTH: the bytes left after it).
TYPE_SITES = ("TYPE_TRAILING", "TYPE_BITS", "TYPE_FLOAT_FORMAT", "TYPE_FLOAT", "TYPE_LINK", "TYPE_FORM",
              # S8c.26 (ADR-244): opaque, effect, sum, and pointer forms, before any element type is verified (CWIDTH: the
              # quoted third value: bytes left, an index, a permission, or an alignment).
              "TYPE_OPAQUE_KIND", "TYPE_OPAQUE_CANONICAL", "TYPE_EFFECT_DOMAIN", "TYPE_EFFECT_CANONICAL", "TYPE_SUM_NONEMPTY",
              "TYPE_REF_INDEX", "TYPE_POINTER_PERMISSION", "TYPE_POINTER",
              # S8c.26 (ADR-244): resource and array forms.
              "TYPE_RESOURCE_STACK_OWNER", "TYPE_RESOURCE_CANONICAL", "TYPE_ARRAY_ELEMENT",
              # S8c.27 (ADR-245): tuple and sum items (C4: the used-reference bit mask).
              "TYPE_TUPLE_ELEMENT", "TYPE_SUM_VARIANT", "TYPE_LIST_UNUSED",
              # S8 (ADR-251): malformed ULEB fields (C4: the field's offset in the body).
              "TYPE_ULEB_UNTERMINATED", "TYPE_ULEB_MINIMAL", "TYPE_ULEB_BOUNDED",
              # S8c.28 (ADR-246): pointer elements and opaque identity types.
              "TYPE_POINTER_ELEMENT", "TYPE_POINTER_UNUSED", "TYPE_IDENTITY_TRUNCATED", "TYPE_IDENTITY_CANONICAL")
TYPE_SITE_BASE = 16
# S4d.2a: types the memory-fact system tracks (besides pointers and other undecoded forms).
MEMORY_EFFECT_DOMAIN = 1
PADDING = 24  # zero words ending the stream: the decoders' look-ahead stays inside it
AFFINE, PARTITIONABLE, RELEASABLE, ACQUIRABLE = 1, 2, 4, 8
EFFECT_DOMAINS, OPAQUE_KINDS = 11, 7
MARKS = 128  # scratch marks for reference use, after the tables; at most this many references
TUPLE, ARRAY, SUM = 8, 9, 10

BINARY_INTEGER = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_XOR, Operation.BIT_AND, Operation.BIT_OR, Operation.UDIV, Operation.UREM)
INTEGER_FAMILIES = frozenset({*BINARY_INTEGER, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT})  # S8c.1
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
# S8c.2: the families whose rejections XAX decides; the rest stay NOT_PROVEN for the bootstrap.
DECIDED_FAMILIES = frozenset({*INTEGER_FAMILIES, *FLOAT_BINARY, Operation.FLOAT_COMPARE, *TO_FLOAT, *FROM_FLOAT, Operation.FLOAT_CONVERT, Operation.INT_COMPARE,
                              Operation.AGGREGATE_MAKE, Operation.AGGREGATE_GET, Operation.SUM_MAKE, Operation.SUM_TAG, Operation.SUM_GET,
                              *META_RULES, *RESOURCE_COUNTS, Operation.EFFECT_STEP, Operation.CONSTANT, Operation.CALL_DIRECT})
COVERED = frozenset(
    {*BINARY_INTEGER, Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT, *FLOAT_BINARY,
     Operation.FLOAT_COMPARE, *TO_FLOAT, *FROM_FLOAT, Operation.FLOAT_CONVERT, Operation.INT_COMPARE, *AGGREGATES,
     *RESOURCE_COUNTS, Operation.EFFECT_STEP, *META_RULES, Operation.CONSTANT, Operation.CALL_DIRECT}
)
CONDITIONAL_BRANCH = int(TerminatorKind.CONDITIONAL_BRANCH)


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


def _known(t: _Typing, value):
    """A type the decoders fully validated (what ``_verify_type`` accepts, restricted to decoded forms)."""
    return t.any(
        t.nonzero(t.lookup(WIDTH, value)), t.nonzero(t.lookup(FORMAT, value)), t.lookup(LINK, value), t.nonzero(t.lookup(AGGREGATE, value)),
        t.lookup(EFFECT, value), t.lookup(RESOURCE, value), t.nonzero(t.lookup(OPAQUE, value)), t.lookup(PTR, value), t.lookup(OPID, value),
    )


def _rejection(b: _Builder, t: _Typing, operation, shape, counts, attribute, kind_in, result, first, second,
               width, first_width, is_bits, first_bits, is_float, first_float, first_link, ok, position, needed, ids, extra_at, constant, call):
    """S8c.1/S8c.2: the site and payload of the bootstrap's first failing typing check for a scalar-family node.

    Each family lists its checks in the bootstrap's order.  A step with site 0 leaves the node to the bootstrap:
    a type the program does not decode as the expected ``bits`` or ``float`` (the bootstrap raises its own decode
    diagnostic there) or a clamped attribute (the diagnostic would quote its exact value).  S8c.3: an aggregate or
    sum type is decided only when the program decoded it (its AGGREGATE table entry); a type whose single-byte
    form is neither tuple nor array is rejected by form.  ``ok`` is the node's rule: once a family's earlier
    steps pass, its last check fails exactly when ``ok`` does.
    """
    zero = b.c(0)
    none = (SITE_NONE, (zero,) * 3)
    is_ = lambda code: t.eq(operation, int(code))  # noqa: E731
    clamped = t.eq(attribute, ATTRIBUTE_LIMIT)
    fp_binary, compare_f, to_float, from_float = t.one_of(operation, FLOAT_BINARY), is_(Operation.FLOAT_COMPARE), t.one_of(operation, TO_FLOAT), t.one_of(operation, FROM_FLOAT)
    truncate, extend, rotate = is_(Operation.INT_TRUNCATE), is_(Operation.INT_ZERO_EXTEND), is_(Operation.ROTATE_RIGHT)
    unsigned_to, unsigned_from = is_(Operation.UINT_TO_FLOAT), is_(Operation.FLOAT_TO_UINT_TRUNC)
    same_first, same_second, same_operands = t.eq(first, result), t.eq(second, result), t.eq(second, first)
    code = lambda flag, if_true, if_false: t.pick(flag, b.c(if_true), b.c(if_false))  # noqa: E731
    payload = lambda *words: tuple((*words, zero, zero, zero)[:3])  # noqa: E731
    link_kind = t.one_of(attribute, LINK_COMPARE_KINDS)
    result_shape, first_shape = t.lookup(AGGREGATE, result), t.lookup(AGGREGATE, first)
    result_form, first_form = t.lookup(FORMB, result), t.lookup(FORMB, first)
    tuple_like = lambda shape_: t.any(t.eq(shape_, TUPLE), t.eq(shape_, ARRAY))  # noqa: E731

    cross = lambda type_, decoder: _cross(b, t, type_, decoder)  # noqa: E731
    # ``_decode_sum_type`` of a type the parse verified, of another form: TYPE-SUM (a form-10 body it did not decode defers).
    not_sum = lambda type_: (t.all(_known(t, type_), t.not_(t.eq(t.lookup(FORMB, type_), 10))), SITE_CROSS_SUM, (type_, b.c(0), b.c(0)))  # noqa: E731

    def other_form(form, site):
        """A type whose one-byte form is known and neither tuple nor array is rejected by form; else deferred."""
        known = t.all(t.nonzero(form), t.lt(form, 128), t.not_(t.one_of(form, (TUPLE, ARRAY))))
        return t.pick(known, b.c(site), b.c(SITE_NONE)), payload(form)
    families = (
        (t.one_of(operation, BINARY_INTEGER), (
            (t.not_(shape(2, 1, 0)), SITE_OP_ARITY, counts),
            (t.not_(is_bits), *cross(result, 1)),
            (t.not_(t.all(same_first, same_second)), SITE_OP_TYPE, (result, first, second)),
        )),
        (t.any(truncate, extend), (
            (t.not_(shape(1, 1, 0)), SITE_INT_WIDTH_CONTRACT, counts),
            (t.not_(first_bits), *cross(first, 1)),
            (t.not_(is_bits), *cross(result, 1)),
            (t.pick(truncate, t.le(first_width, width), t.le(width, first_width)),
             code(truncate, SITE_INT_TRUNCATE_NARROWS, SITE_INT_ZERO_EXTEND_WIDENS), payload(first_width, width)),
        )),
        (rotate, (
            (t.not_(shape(1, 1, 1)), SITE_ROTATE_CONTRACT, counts),
            (t.not_(is_bits), *cross(result, 1)),
            (t.not_(same_first), SITE_ROTATE_TYPE, payload(result, first)),
            (t.all(t.le(width, attribute), clamped), *none),
            (t.le(width, attribute), SITE_ROTATE_AMOUNT, payload(width, attribute)),
        )),
        (fp_binary, (
            (t.not_(shape(2, 1, 0)), SITE_FLOAT_BINARY_CONTRACT, counts),
            (t.not_(is_float), *cross(result, 7)),
            (t.not_(t.all(same_first, same_second)), SITE_FLOAT_BINARY_TYPE, (result, first, second)),
        )),
        (compare_f, (
            (t.not_(shape(2, 1, 1)), SITE_FLOAT_COMPARE_CONTRACT, counts),
            (t.not_(same_operands), SITE_FLOAT_COMPARE_OPERANDS, payload(first, second)),
            (t.not_(first_float), *cross(first, 7)),
            (t.not_(is_bits), *cross(result, 1)),
            (t.not_(t.eq(width, 1)), SITE_FLOAT_COMPARE_RESULT, payload(result)),
            (clamped, *none),
            (t.not_(kind_in(FLOAT_COMPARE_KINDS)), SITE_FLOAT_COMPARE_KIND, payload(attribute)),
        )),
        (to_float, (
            (t.not_(shape(1, 1, 0)), code(unsigned_to, SITE_UINT_TO_FLOAT_CONTRACT, SITE_SINT_TO_FLOAT_CONTRACT), counts),
            (t.not_(first_bits), *cross(first, 1)),
            (t.lt(b.c(64), first_width), code(unsigned_to, SITE_UINT_TO_FLOAT_WIDTH, SITE_SINT_TO_FLOAT_WIDTH), payload(first)),
            (t.not_(is_float), *cross(result, 7)),
        )),
        (from_float, (
            (t.not_(shape(1, 1, 0)), code(unsigned_from, SITE_FLOAT_TO_UINT_CONTRACT, SITE_FLOAT_TO_SINT_CONTRACT), counts),
            (t.not_(first_float), *cross(first, 7)),
            (t.not_(is_bits), *cross(result, 1)),
            (t.lt(b.c(64), width), code(unsigned_from, SITE_FLOAT_TO_UINT_WIDTH, SITE_FLOAT_TO_SINT_WIDTH), payload(result)),
        )),
        (is_(Operation.FLOAT_CONVERT), (
            (t.not_(shape(1, 1, 0)), SITE_FLOAT_CONVERT_CONTRACT, counts),
            (t.not_(first_float), *cross(first, 7)),
            (t.not_(is_float), *cross(result, 7)),
        )),
        (is_(Operation.AGGREGATE_MAKE), (
            (t.not_(t.all(t.eq(counts[2], 0), t.eq(counts[1], 1))), SITE_AGGREGATE_MAKE_CONTRACT, counts),
            (t.not_(tuple_like(result_shape)), *other_form(result_form, SITE_AGGREGATE_MAKE_TYPE)),
            (t.not_(ok), SITE_AGGREGATE_MAKE_ELEMENTS, payload(result, position)),
        )),
        (is_(Operation.AGGREGATE_GET), (
            (t.not_(shape(1, 1, 1)), SITE_AGGREGATE_GET_CONTRACT, counts),
            (t.not_(tuple_like(first_shape)), *other_form(first_form, SITE_AGGREGATE_GET_TYPE)),
            (clamped, *none),
            (t.not_(ok), SITE_AGGREGATE_GET_INDEX, (first, attribute, result)),
        )),
        (is_(Operation.SUM_MAKE), (
            (t.not_(shape(1, 1, 1)), SITE_SUM_MAKE_CONTRACT, counts),
            not_sum(result),
            (t.not_(t.eq(result_shape, SUM)), *none),
            (clamped, *none),
            (t.not_(ok), SITE_SUM_MAKE_VARIANT, (result, attribute, first)),
        )),
        (is_(Operation.SUM_TAG), (
            (t.not_(shape(1, 1, 0)), SITE_SUM_TAG_CONTRACT, counts),
            not_sum(first),
            (t.not_(t.eq(first_shape, SUM)), *none),
            (t.not_(is_bits), *cross(result, 1)),
            (t.not_(ok), SITE_SUM_TAG_WIDTH, payload(t.pick(t.nonzero(needed), needed, b.c(1)), width)),
        )),
        (is_(Operation.SUM_GET), (
            (t.not_(shape(1, 1, 1)), SITE_SUM_GET_CONTRACT, counts),
            not_sum(first),
            (t.not_(t.eq(first_shape, SUM)), *none),
            (clamped, *none),
            (t.not_(ok), SITE_SUM_GET_VARIANT, (first, attribute, result)),
        )),
        (is_(Operation.CONSTANT), _entity_steps(b, t, constant[0], extra_at, Kind.CONSTANT, SITE_CONSTANT_TARGET_NONE, none) + (
            (t.not_(constant[1]), *none),
            (t.not_(ok), SITE_CONSTANT_CONTRACT, (constant[2], position, zero)),
        )),
        (is_(Operation.CALL_DIRECT), _entity_steps(b, t, constant[0], extra_at, Kind.FUNCTION, SITE_CALL_TARGET_NONE, none) + (
            (t.not_(call[0]), *none),
            (t.not_(ok), SITE_CALL_CONTRACT, (call[1], position, zero)),
        )),
        *((is_(member), _resource_steps(b, t, member, counts, attribute, ids, position, ok, clamped, none)) for member in (*RESOURCE_COUNTS, Operation.EFFECT_STEP)),
        *((is_(meta), _meta_steps(b, t, index_, meta, counts, attribute, ids, result, width, is_bits, clamped, none))
          for index_, meta in enumerate(META_RULES)),
        (is_(Operation.INT_COMPARE), (
            (t.not_(shape(2, 1, 1)), SITE_INT_COMPARE_CONTRACT, counts),
            (t.all(first_link, t.not_(link_kind), clamped), *none),
            (t.all(first_link, t.not_(link_kind)), SITE_INT_COMPARE_LINK_EQUALITY, payload(attribute)),
            (t.all(t.not_(first_link), t.not_(first_bits)), *cross(first, 1)),
            (t.not_(same_operands), SITE_INT_COMPARE_TYPE, (first, second, result)),
            (t.not_(is_bits), *cross(result, 1)),
            (t.not_(t.eq(width, 1)), SITE_INT_COMPARE_TYPE, (first, second, result)),
            (clamped, *none),
            (t.not_(kind_in(INT_COMPARE_KINDS)), SITE_INT_COMPARE_KIND, payload(attribute)),
        )),
    )
    site, words = b.c(SITE_NONE), (zero,) * 3
    for member, steps in families:
        # The first applying step of this family, folded from the last.
        family_site, family_words = b.c(SITE_NONE), (zero,) * 3
        for applies, step_site, step_words in reversed(steps):
            family_site = t.pick(applies, b.c(step_site) if isinstance(step_site, int) else step_site, family_site)
            family_words = tuple(t.pick(applies, word, prior) for word, prior in zip(step_words, family_words))
        site = t.pick(member, family_site, site)
        words = tuple(t.pick(member, word, prior) for word, prior in zip(family_words, words))
    return site, words


def _cross(b: _Builder, t: _Typing, type_, decoder: int):
    """S8 (ADR-251): ``decode_bits_width`` (1) or ``decode_float_format`` (7) of ``type_`` fails: the decoder's diagnostic
    (site 0 when it would succeed, or the outcome is deferred)."""
    stat, xa, xb = t.lookup(XSTAT, type_), t.lookup(XA, type_), t.lookup(XB, type_)
    references = b.read(b.add(t.lookup(POSITION, type_), 1))
    plain = t.all(t.eq(stat, 0), t.eq(references, 0), t.eq(xa, decoder))
    decodes = t.all(plain, t.nonzero(xb)) if decoder == 1 else t.all(plain, t.one_of(xb, (1, 2)))
    site = t.pick(t.any(decodes, t.eq(stat, 4)), b.c(SITE_NONE), b.c(SITE_CROSS_BITS if decoder == 1 else SITE_CROSS_FLOAT))
    return site, (type_, b.c(0), b.c(0))


def _meta_steps(b: _Builder, t: _Typing, index, meta, counts, attribute, ids, result, width, is_bits, clamped, none):
    """S8c.4: ``_verify_meta_node``'s checks in order: arity, each operand's kind, the result rule, the target operation."""
    kinds, result_count, attribute_count, result_rule = META_RULES[meta]
    operands, results, attributes = counts

    def opaque(value, kind, site):
        # ``_is_opaque`` is False for a type whose body does not start with form 5 (a rejection); a form-5 type the
        # program did not decode as an opaque type makes the bootstrap raise its own decode diagnostic (deferred).
        undecoded = t.all(t.eq(t.lookup(FORMB, value), 5), t.eq(t.lookup(OPAQUE, value), 0))
        return [(undecoded, *none), (t.not_(t.eq(t.lookup(OPAQUE, value), kind)), site, (b.c(kind), value, b.c(0)))]

    steps = [(t.not_(t.all(t.eq(operands, len(kinds)), t.eq(results, result_count), t.eq(attributes, attribute_count))),
              SITE_META_ARITY + index, counts)]
    for position_, kind in enumerate(kinds):
        value = b.read(b.add(ids, position_))
        steps += [(t.not_(t.nonzero(t.lookup(WIDTH, value))), *_cross(b, t, value, 1))] if kind is None else opaque(value, kind, SITE_META_OPERAND_TYPE)
    if isinstance(result_rule, int):
        steps += opaque(result, result_rule, SITE_META_RESULT_TYPE)
    else:
        steps.append((t.not_(is_bits), *_cross(b, t, result, 1)))
        if result_rule == "bit":
            site = SITE_META_TARGET_SUPPORT_RESULT if meta == Operation.META_TARGET_SUPPORTS else SITE_META_VERIFY_RESULT
            steps.append((t.not_(t.eq(width, 1)), site, (width if site == SITE_META_TARGET_SUPPORT_RESULT else result, b.c(0), b.c(0))))
    if meta == Operation.META_TARGET_SUPPORTS:
        steps += [(clamped, *none), (t.not_(t.one_of(attribute, tuple(Operation))), SITE_META_TARGET_OPERATION, (attribute, b.c(0), b.c(0)))]
    return tuple(steps)


def _entity_steps(b: _Builder, t: _Typing, extra, extra_at, kind, site_none, none):
    """S8c.6: a constant's or direct call's entity check: absent, or of another kind (an entry whose references did not
    resolve has kind 0 in the stream and stays with the bootstrap).  ``site_none + 1`` is the wrong-kind site."""
    entity = b.read(extra_at)
    valid = t.lt(entity, t.count)
    entity_kind = b.mul(valid, b.read(b.get(t.slot(POSITION, t.pick(valid, entity, b.c(0))))))
    return (
        (t.eq(extra, 0), site_none, (b.c(0),) * 3),
        (t.eq(entity_kind, 0), *none),
        (t.not_(t.eq(entity_kind, int(kind))), site_none + 1, (entity_kind, b.c(0), b.c(0))),
    )


def _resource_steps(b: _Builder, t: _Typing, operation, counts, attribute, ids, position, ok, clamped, none):
    """S8c.5: ``_verify_resource_effect_node``'s checks in order.  ``effect(cid)`` and ``resource(cid)`` reject a type
    whose body does not start with form 3 or 4; a type of that form the program did not decode defers."""
    operands, results, attributes = counts
    zero = b.c(0)
    operand = lambda k: b.read(b.add(ids, k))  # noqa: E731
    result = lambda k: b.read(b.add(b.add(ids, operands), k))  # noqa: E731
    flagged = lambda value, bit: t.nonzero(b.op(Operation.BIT_AND, t.lookup(RFLAGS, value), bit))  # noqa: E731

    def proof(value, form, table, site):
        return [(t.not_(t.eq(t.lookup(FORMB, value), form)), site, (value, zero, zero)), (t.not_(t.nonzero(t.lookup(table, value))), *none)]

    effect = lambda value: proof(value, 3, EFFECT, SITE_RES_EXPECT_EFFECT)  # noqa: E731
    resource = lambda value: proof(value, 4, RESOURCE, SITE_RES_EXPECT_RESOURCE)  # noqa: E731
    # Attributes: the record quotes the whole tuple, so only a single unclamped attribute is decided.
    steps = [(t.all(t.nonzero(attributes), t.any(t.not_(t.eq(attributes, 1)), clamped)), *none),
             (t.nonzero(attributes), SITE_RES_NO_ATTRIBUTES, (attribute, zero, zero))]
    if operation == Operation.EFFECT_STEP:
        paired = t.all(t.nonzero(operands), t.eq(operands, results))
        (matching,) = b.for_range(zero, b.mul(paired, operands), lambda k, c: (t.all(c[0], t.eq(operand(k), result(k))),), (paired,))

        def first_bad(k, carried):
            found, form_bad, at = carried
            value = operand(k)
            bad = t.any(t.not_(t.eq(t.lookup(FORMB, value), 3)), t.not_(t.nonzero(t.lookup(EFFECT, value))))
            fresh = t.all(t.not_(found), bad)
            return (t.any(found, bad), t.pick(fresh, t.not_(t.eq(t.lookup(FORMB, value), 3)), form_bad), t.pick(fresh, value, at))

        found, form_bad, at = b.for_range(zero, operands, first_bad, (zero, zero, zero))
        return (*steps, (t.not_(matching), SITE_RES_STEP_MATCH, (position, zero, zero)),
                (t.all(found, t.not_(form_bad)), *none), (found, SITE_RES_EXPECT_EFFECT, (at, zero, zero)),
                (t.not_(ok), SITE_RES_EFFECT_UNIQUE, (position, zero, zero)))
    count_in, count_out = RESOURCE_COUNTS[operation]
    steps.append((t.not_(t.all(t.eq(operands, count_in), t.eq(results, count_out))), SITE_RES_COUNTS, (operands, results, b.c(int(operation)))))
    last_in, last_out = operand(count_in - 1), result(count_out - 1)
    steps += [*effect(last_in), (t.not_(t.eq(last_in, last_out)), SITE_RES_CONTINUATION, (last_in, last_out, zero))]
    if operation == Operation.RESOURCE_ACQUIRE:
        return (*steps, *resource(result(0)), (t.not_(flagged(result(0), ACQUIRABLE)), SITE_RES_ACQUIRE_ALLOWED, (zero,) * 3))
    source = operand(0)
    steps += resource(source)
    if operation == Operation.RESOURCE_RELEASE:
        steps.append((t.not_(flagged(source, RELEASABLE)), SITE_RES_RELEASE_ALLOWED, (source, zero, zero)))
    elif operation == Operation.RESOURCE_DISCARD:
        steps.append((t.not_(flagged(source, AFFINE)), SITE_RES_DISCARD_ALLOWED, (source, zero, zero)))
    elif operation == Operation.RESOURCE_JOIN:
        steps += [(t.not_(t.all(t.eq(operand(1), source), t.eq(result(0), source))), SITE_RES_JOIN_MATCH, (position, zero, zero)),
                  (t.not_(flagged(source, PARTITIONABLE)), SITE_RES_JOIN_PARTITIONABLE, (zero,) * 3)]
    elif operation == Operation.RESOURCE_TRANSFER:
        steps.append((t.not_(t.eq(result(0), source)), SITE_RES_TRANSFER_SAME, (source, result(0), zero)))
    elif operation == Operation.RESOURCE_TRANSITION:
        steps += [*resource(result(0)), (t.not_(ok), SITE_RES_TRANSITION, (source, result(0), zero))]
    else:  # split
        steps.append((t.not_(ok), SITE_RES_SPLIT, (source, result(0), result(1))))
    return tuple(steps)


def _render_sites():
    # Each renderer takes ``(r, x, y, z)``: ``r`` is the rendering context (``r.h`` a type index's CID hex, ``r.items``
    # a decoded aggregate or sum's element indices from the program's tables, ``r.operands`` a node's operand type
    # indices from the input stream), then the record's three payload words.
    contract = lambda code, rule, expected: (code, rule, lambda r, x, y, z: expected, lambda r, x, y, z: [x, y, z])  # noqa: E731
    listing = lambda r, owner: [len(r.items(owner)), [r.h(item) for item in r.items(owner)]]  # noqa: E731
    sites = {
        SITE_OP_ARITY: contract("XAX.STRUCT.OP_ARITY", "GRAPH-OP-ARITY", "2 inputs, 1 result, 0 attributes"),
        SITE_OP_TYPE: ("XAX.STRUCT.OP_TYPE", "GRAPH-OP-TYPE", lambda r, x, y, z: [r.h(x), r.h(x)], lambda r, x, y, z: [r.h(y), r.h(z)]),
        SITE_INT_WIDTH_CONTRACT: contract("XAX.INT.WIDTH", "INT-WIDTH-CONTRACT", [1, 1, 0]),
        SITE_INT_TRUNCATE_NARROWS: ("XAX.INT.WIDTH", "INT-TRUNCATE-NARROWS", lambda r, x, y, z: f"result < {x}", lambda r, x, y, z: y),
        SITE_INT_ZERO_EXTEND_WIDENS: ("XAX.INT.WIDTH", "INT-ZERO-EXTEND-WIDENS", lambda r, x, y, z: f"result > {x}", lambda r, x, y, z: y),
        SITE_ROTATE_CONTRACT: contract("XAX.INT.ROTATE", "INT-ROTATE-CONTRACT", [1, 1, 1]),
        SITE_ROTATE_TYPE: ("XAX.INT.ROTATE", "INT-ROTATE-TYPE", lambda r, x, y, z: r.h(x), lambda r, x, y, z: [r.h(y)]),
        SITE_ROTATE_AMOUNT: ("XAX.INT.ROTATE", "INT-ROTATE-AMOUNT", lambda r, x, y, z: f"0..{x - 1}", lambda r, x, y, z: y),
        SITE_FLOAT_BINARY_CONTRACT: contract("XAX.FLOAT.CONTRACT", "FLOAT-BINARY-CONTRACT", [2, 1, 0]),
        SITE_FLOAT_BINARY_TYPE: ("XAX.FLOAT.TYPE", "FLOAT-BINARY-TYPE", lambda r, x, y, z: [r.h(x), r.h(x)], lambda r, x, y, z: [r.h(y), r.h(z)]),
        SITE_FLOAT_COMPARE_CONTRACT: contract("XAX.FLOAT.CONTRACT", "FLOAT-COMPARE-CONTRACT", [2, 1, 1]),
        SITE_FLOAT_COMPARE_OPERANDS: ("XAX.FLOAT.TYPE", "FLOAT-COMPARE-OPERANDS", lambda r, x, y, z: "matching float types", lambda r, x, y, z: [r.h(x), r.h(y)]),
        SITE_FLOAT_COMPARE_RESULT: ("XAX.FLOAT.TYPE", "FLOAT-COMPARE-RESULT", lambda r, x, y, z: "bits<1>", lambda r, x, y, z: r.h(x)),
        SITE_FLOAT_COMPARE_KIND: ("XAX.FLOAT.COMPARE", "FLOAT-COMPARE-KIND", lambda r, x, y, z: [item.value for item in FloatCompare], lambda r, x, y, z: x),
        SITE_INT_COMPARE_CONTRACT: contract("XAX.INT.COMPARE", "INT-COMPARE-CONTRACT", [2, 1, 1]),
        SITE_INT_COMPARE_LINK_EQUALITY: ("XAX.INT.COMPARE", "INT-COMPARE-LINK-EQUALITY", lambda r, x, y, z: [IntCompare.EQ, IntCompare.NE], lambda r, x, y, z: x),
        SITE_INT_COMPARE_TYPE: ("XAX.INT.COMPARE", "INT-COMPARE-TYPE", lambda r, x, y, z: [r.h(x), "bits<1>"], lambda r, x, y, z: [[r.h(x), r.h(y)], r.h(z)]),
        SITE_INT_COMPARE_KIND: ("XAX.INT.COMPARE", "INT-COMPARE-KIND", lambda r, x, y, z: [item.value for item in IntCompare], lambda r, x, y, z: x),
        SITE_FLOAT_CONVERT_CONTRACT: contract("XAX.FLOAT.CONTRACT", "FLOAT-CONVERT-CONTRACT", [1, 1, 0]),
    }
    sites.update({
        SITE_AGGREGATE_MAKE_CONTRACT: ("XAX.AGGREGATE.CONTRACT", "AGGREGATE-MAKE-CONTRACT", lambda r, x, y, z: "operands -> one aggregate result",
                                       lambda r, x, y, z: [x, y, z]),
        SITE_AGGREGATE_MAKE_TYPE: ("XAX.AGGREGATE.TYPE", "AGGREGATE-MAKE-TYPE", lambda r, x, y, z: ["tuple", "array"], lambda r, x, y, z: x),
        SITE_AGGREGATE_MAKE_ELEMENTS: ("XAX.AGGREGATE.TYPE", "AGGREGATE-MAKE-ELEMENTS", lambda r, x, y, z: [r.h(item) for item in r.items(x)],
                                       lambda r, x, y, z: [r.h(item) for item in r.operands(y)]),
        SITE_AGGREGATE_GET_CONTRACT: contract("XAX.AGGREGATE.CONTRACT", "AGGREGATE-GET-CONTRACT", [1, 1, 1]),
        SITE_AGGREGATE_GET_TYPE: ("XAX.AGGREGATE.TYPE", "AGGREGATE-GET-TYPE", lambda r, x, y, z: ["tuple", "array"], lambda r, x, y, z: x),
        SITE_AGGREGATE_GET_INDEX: ("XAX.AGGREGATE.INDEX", "AGGREGATE-GET-INDEX", lambda r, x, y, z: listing(r, x), lambda r, x, y, z: [y, r.h(z)]),
        SITE_SUM_MAKE_CONTRACT: contract("XAX.SUM.CONTRACT", "SUM-MAKE-CONTRACT", [1, 1, 1]),
        SITE_SUM_MAKE_VARIANT: ("XAX.SUM.VARIANT", "SUM-MAKE-VARIANT", lambda r, x, y, z: listing(r, x), lambda r, x, y, z: [y, r.h(z)]),
        SITE_SUM_TAG_CONTRACT: contract("XAX.SUM.CONTRACT", "SUM-TAG-CONTRACT", [1, 1, 0]),
        SITE_SUM_TAG_WIDTH: ("XAX.SUM.TAG", "SUM-TAG-WIDTH", lambda r, x, y, z: f">= {x} bits", lambda r, x, y, z: y),
        SITE_SUM_GET_CONTRACT: contract("XAX.SUM.CONTRACT", "SUM-GET-CONTRACT", [1, 1, 1]),
        SITE_SUM_GET_VARIANT: ("XAX.SUM.VARIANT", "SUM-GET-VARIANT", lambda r, x, y, z: listing(r, x), lambda r, x, y, z: [y, r.h(z)]),
    })
    opaque_name = lambda kind: f"opaque<{OpaqueKind(kind).name.lower()}>"  # noqa: E731
    sites.update({
        SITE_META_OPERAND_TYPE: ("XAX.META.CONTRACT", "META-OPERAND-TYPE", lambda r, x, y, z: opaque_name(x), lambda r, x, y, z: r.h(y)),
        SITE_META_RESULT_TYPE: ("XAX.META.CONTRACT", "META-RESULT-TYPE", lambda r, x, y, z: opaque_name(x), lambda r, x, y, z: r.h(y)),
        SITE_META_VERIFY_RESULT: ("XAX.META.CONTRACT", "META-VERIFY-RESULT", lambda r, x, y, z: "bits<1>", lambda r, x, y, z: r.h(x)),
        SITE_META_TARGET_SUPPORT_RESULT: ("XAX.META.CONTRACT", "META-TARGET-SUPPORT-RESULT", lambda r, x, y, z: "bits<1>", lambda r, x, y, z: f"bits<{x}>"),
        SITE_META_TARGET_OPERATION: ("XAX.META.CONTRACT", "META-TARGET-OPERATION", lambda r, x, y, z: list(Operation), lambda r, x, y, z: x),
    })
    from xax_compiler import EffectDomain, _EffectType

    resource_contract = "XAX.RESOURCE.CONTRACT", "RESOURCE-EFFECT-OP-CONTRACT"
    sites.update({
        SITE_RES_NO_ATTRIBUTES: (*resource_contract, lambda r, x, y, z: "no attributes", lambda r, x, y, z: (x,)),
        SITE_RES_STEP_MATCH: (*resource_contract, lambda r, x, y, z: "one or more matching effect inputs/results",
                              lambda r, x, y, z: [tuple(r.cids[i] for i in r.operands(x)), tuple(r.cids[i] for i in r.results(x))]),
        SITE_RES_EXPECT_EFFECT: (*resource_contract, lambda r, x, y, z: "effect<D>", lambda r, x, y, z: r.h(x)),
        SITE_RES_EFFECT_UNIQUE: ("XAX.EFFECT.FORK", "EFFECT-DOMAIN-INSTANCE-UNIQUE", lambda r, x, y, z: "distinct domain instances",
                                 lambda r, x, y, z: tuple(_EffectType(EffectDomain(r.field(EDOMAIN, i)), r.field(EINST, i)) for i in r.operands(x))),
        SITE_RES_COUNTS: (*resource_contract, lambda r, x, y, z: RESOURCE_COUNTS[Operation(z)], lambda r, x, y, z: (x, y)),
        SITE_RES_CONTINUATION: (*resource_contract, lambda r, x, y, z: "matching effect continuation", lambda r, x, y, z: [r.h(x), r.h(y)]),
        SITE_RES_EXPECT_RESOURCE: (*resource_contract, lambda r, x, y, z: "resource<K,state>", lambda r, x, y, z: r.h(x)),
        SITE_RES_ACQUIRE_ALLOWED: ("XAX.RESOURCE.ACQUIRE_STATE", "RESOURCE-ACQUIRE-ALLOWED", lambda r, x, y, z: True, lambda r, x, y, z: False),
        SITE_RES_RELEASE_ALLOWED: ("XAX.RESOURCE.RELEASE_STATE", "RESOURCE-TERMINAL-ALLOWED", lambda r, x, y, z: "releasable",
                                   lambda r, x, y, z: r.field(RFLAGS, x)),
        SITE_RES_DISCARD_ALLOWED: ("XAX.RESOURCE.DISCARD_LINEAR", "RESOURCE-TERMINAL-ALLOWED", lambda r, x, y, z: "affine",
                                   lambda r, x, y, z: r.field(RFLAGS, x)),
        SITE_RES_JOIN_MATCH: (*resource_contract, lambda r, x, y, z: "two matching pieces and one matching joined resource",
                              lambda r, x, y, z: [tuple(r.cids[i] for i in r.operands(x)), tuple(r.cids[i] for i in r.results(x))]),
        SITE_RES_JOIN_PARTITIONABLE: ("XAX.RESOURCE.JOIN", "RESOURCE-PARTITIONABLE", lambda r, x, y, z: True, lambda r, x, y, z: False),
        SITE_RES_TRANSFER_SAME: (*resource_contract, lambda r, x, y, z: "same resource type", lambda r, x, y, z: [r.h(x), r.h(y)]),
        SITE_RES_TRANSITION: ("XAX.RESOURCE.INVALID_TRANSITION", "RESOURCE-STATE-TRANSITION",
                              lambda r, x, y, z: {"kind": r.field(RKIND, x), "from": r.field(RSTATE, x), "to": r.transitions(x)},
                              lambda r, x, y, z: {"kind": r.field(RKIND, y), "state": r.field(RSTATE, y)}),
        SITE_RES_SPLIT: ("XAX.RESOURCE.SPLIT", "RESOURCE-PARTITION-CONTRACT", lambda r, x, y, z: "partitionable resource -> two matching pieces",
                         lambda r, x, y, z: [r.field(RFLAGS, x), r.h(y), r.h(z)]),
    })
    hexes = lambda r, indices: [r.h(item) for item in indices]  # noqa: E731
    sites.update({
        SITE_CONSTANT_TARGET_NONE: ("XAX.STRUCT.CONSTANT_TARGET", "GRAPH-CONSTANT-TARGET", lambda r, x, y, z: Kind.CONSTANT.name, lambda r, x, y, z: None),
        SITE_CONSTANT_TARGET_KIND: ("XAX.STRUCT.CONSTANT_TARGET", "GRAPH-CONSTANT-TARGET", lambda r, x, y, z: Kind.CONSTANT.name,
                                    lambda r, x, y, z: Kind(x).name),
        SITE_CONSTANT_CONTRACT: ("XAX.STRUCT.CONSTANT_CONTRACT", "GRAPH-CONSTANT-CONTRACT", lambda r, x, y, z: [[], [r.h(x)]],
                                 lambda r, x, y, z: [hexes(r, r.operands(y)), hexes(r, r.results(y))]),
        SITE_CALL_TARGET_NONE: ("XAX.STRUCT.CALL_TARGET", "GRAPH-CALL-TARGET", lambda r, x, y, z: Kind.FUNCTION.name, lambda r, x, y, z: None),
        SITE_CALL_TARGET_KIND: ("XAX.STRUCT.CALL_TARGET", "GRAPH-CALL-TARGET", lambda r, x, y, z: Kind.FUNCTION.name, lambda r, x, y, z: Kind(x).name),
        SITE_CALL_CONTRACT: ("XAX.STRUCT.CALL_CONTRACT", "GRAPH-CALL-CONTRACT", lambda r, x, y, z: [hexes(r, items) for items in r.interface(x)],
                             lambda r, x, y, z: [hexes(r, r.operands(y)), hexes(r, r.results(y))]),
    })
    for index, (kinds, result_count, attribute_count, _rule) in enumerate(META_RULES.values()):
        expected = (len(kinds), result_count, attribute_count)
        sites[SITE_META_ARITY + index] = ("XAX.META.CONTRACT", "META-OP-ARITY", lambda r, x, y, z, e=expected: e, lambda r, x, y, z: (x, y, z))
    for name in ("UINT", "SINT"):
        sites[globals()[f"SITE_{name}_TO_FLOAT_CONTRACT"]] = contract("XAX.FLOAT.CONTRACT", f"{name}-TO-FLOAT-CONTRACT", [1, 1, 0])
        sites[globals()[f"SITE_{name}_TO_FLOAT_WIDTH"]] = ("XAX.FLOAT.CONVERT", f"{name}-TO-FLOAT-WIDTH", lambda r, x, y, z: "bits<=64", lambda r, x, y, z: r.h(x))
        sites[globals()[f"SITE_FLOAT_TO_{name}_CONTRACT"]] = contract("XAX.FLOAT.CONTRACT", f"FLOAT-TO-{name}-CONTRACT", [1, 1, 0])
        sites[globals()[f"SITE_FLOAT_TO_{name}_WIDTH"]] = ("XAX.FLOAT.CONVERT", f"FLOAT-TO-{name}-WIDTH", lambda r, x, y, z: "bits<=64", lambda r, x, y, z: r.h(x))
    return sites


class _Rendering:
    def __init__(self, cids, items=None, operands=None, results=None, field=None, transitions=None, interface=None):
        self.cids, self.items, self.operands, self.results, self.field, self.transitions = cids, items, operands, results, field, transitions
        self.interface = interface

    def h(self, index):
        return self.cids[index].hex()


# S8 (ADR-251): the decoders that check only the form before reading on: form -> (code, rule, expected).  Key 0 is
# ``_decode_pointer_space`` (form 2, then the space).
FORM_CHECKS = {
    3: ("XAX.TYPE.EFFECT", "TYPE-EFFECT", "effect type"),
    4: ("XAX.TYPE.RESOURCE", "TYPE-RESOURCE", "resource type"),
    5: ("XAX.TYPE.OPAQUE", "TYPE-OPAQUE", "opaque semantic type"),
    6: ("XAX.TYPE.OPAQUE_IDENTITY", "TYPE-OPAQUE-IDENTITY", "identity-qualified opaque ABI type"),
    8: ("XAX.TYPE.TUPLE", "TYPE-TUPLE", "tuple type"),
    9: ("XAX.TYPE.ARRAY", "TYPE-ARRAY", "array type"),
    10: ("XAX.TYPE.SUM", "TYPE-SUM", "sum type"),
}


def pointer_cross_diagnostic(stat: int, xa: int, xb: int, xc: int, obj):
    """S8 (ADR-251): ``_decode_pointer_type``'s diagnostic for a type by the program's reading (XP/XPA/XPB/XPC), as
    ``(code, rule, expected, actual, entity)``; None when it reads a pointer shape or the outcome is deferred."""
    from xax_compiler import Permission

    entity = obj.cid.hex()
    if stat == 1:
        return "XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED", "terminating byte", "end of input", entity
    if stat == 2:
        return ("XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL", *_non_minimal(obj.body, xa), entity)
    if stat == 3:
        return "XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED", "at most 10 bytes", "more than 10 bytes", entity
    if stat == 5:
        return "XAX.CANON.TRAILING_BYTES", "TYPE-BODY", 0, xa, entity
    if stat == 6:
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {len(obj.references)}", xa, entity
    if stat == 7:
        return "XAX.TYPE.POINTER_PERMISSION", "TYPE-POINTER-PERMISSION", list(Permission), xa, entity
    if stat == 8:
        return "XAX.TYPE.POINTER", "TYPE-POINTER", "form=2,positive address space,power-of-two alignment", [xa, xb, xc], entity
    return None


def cross_diagnostic(bits: bool, stat: int, xa: int, xb: int, cid: bytes, body: bytes):
    """S8 (ADR-251): ``decode_bits_width`` (``bits``) or ``decode_float_format`` of a type, by the program's outcome for
    it: ``(code, rule, expected, actual, entity)`` (the entity is the type).  ``body``: the type's body (for the
    malformed ULEB the outcome locates)."""
    from xax_compiler import uleb

    rule = "TYPE-BITS" if bits else "TYPE-FLOAT"
    entity = cid.hex()
    if stat == 6:
        return "XAX.TYPE.EXPECTED", rule, Kind.TYPE.name, Kind(xa).name, entity
    if stat == 1:
        return "XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED", "terminating byte", "end of input", entity
    if stat == 3:
        return "XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED", "at most 10 bytes", "more than 10 bytes", entity
    if stat == 2:
        encoded = bytes(body[xa:xa + xb])
        value = sum((byte & 0x7F) << (7 * k) for k, byte in enumerate(encoded))
        return "XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL", uleb(value).hex(), encoded.hex(), entity
    if stat == 5:
        return "XAX.CANON.TRAILING_BYTES", "TYPE-BODY", 0, xa, entity
    if bits:
        return "XAX.TYPE.BITS", "TYPE-BITS", "form=1,width>=1", [xa, xb], entity
    if xb not in (1, 2):
        return "XAX.TYPE.FLOAT", "TYPE-FLOAT-FORMAT", [1, 2], xb, entity
    return "XAX.TYPE.FLOAT", "TYPE-FLOAT", "form=7,known format", [xa, xb], entity


def rejection(record, cids, items=None, operands=None, results=None, field=None, transitions=None, interface=None, body=None):
    """The bootstrap diagnostic ``(code, rule, expected, actual)`` for an XAX rejection record ``[site, a, b, c]``.

    Rendering only: XAX decided the site and its values.  ``cids`` maps the stream's type indices to CIDs;
    ``items(type)`` reads a decoded aggregate's or sum's element indices from the program's tables and
    ``operands(position)``/``results(position)`` a node's operand/result type indices from the input stream;
    ``field(table, type)`` and ``transitions(type)`` read the program's per-type tables (``NativeTyping.rejection``)."""
    site, x, y, z = record
    if site in (SITE_CROSS_BITS, SITE_CROSS_FLOAT):
        return cross_diagnostic(site == SITE_CROSS_BITS, field(XSTAT, x), field(XA, x), field(XB, x), cids[x], body(x) if body else b"")
    if site == SITE_CROSS_SUM:
        return "XAX.TYPE.SUM", "TYPE-SUM", "sum type", "different type form", cids[x].hex()
    if site not in _SITES:
        raise ValueError(f"unknown typing rejection site {site}")
    code, rule, expected, actual = _SITES[site]
    context = _Rendering(cids, items, operands, results, field, transitions, interface)
    return code, rule, expected(context, x, y, z), actual(context, x, y, z)


_SITES = _render_sites()


def load_typing_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "typing")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


BODY_LIMIT = 64  # longer bodies are passed as "other" (never proven)
TARGET_BODY_LIMIT = 4096  # foreign-function carriers embed their interface CIDs
NATIVE_TARGET_LIMIT = 1 << 16  # S8 (ADR-251): a platform target lists hundreds of operation contracts


def type_info_from(resolve):
    """``type_info`` over a resolver: ``(kind, references, body)``, or None when the CID does not resolve."""

    def info(cid: bytes):
        try:
            item = resolve(cid)
        except Exception:  # noqa: BLE001 - any resolution failure leaves the node to the bootstrap
            return None
        limit = NATIVE_TARGET_LIMIT if item.kind == Kind.TARGET else TARGET_BODY_LIMIT
        if item.kind in (Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT, Kind.TYPE) and len(item.body) <= limit:
            # S4d.2c: foreign declarations, recursion groups; S4d.2d: identity types embedding CIDs (lend entries).
            return int(item.kind), tuple(item.references), item.body
        if len(item.body) > BODY_LIMIT or item.kind not in (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION):
            # Kind only: graph bodies (and their references) are never needed, and no rule accepts a longer body.
            return int(item.kind), (), b""
        return int(item.kind), tuple(item.references), item.body

    return info


def marshal(blocks, operand_types_of, type_info, value_type_of=None, facts=None, objects=(), cids=None):
    """Input words for the covered nodes of parsed ``blocks`` and their (block, node) keys.

    ``operand_types_of(block, node)`` gives a node's operand type CIDs (or None
    to leave it to the bootstrap); ``type_info(cid)`` returns ``(kind,
    references, body)`` or None when the object cannot be resolved.  The
    objects an object references are listed too (transitively).  With
    ``value_type_of(block, value)``, every block's parameters and terminator
    follow (S4d.1); otherwise the block section is empty.  A ``cids`` list receives
    the type CIDs in stream index order (S8c.1: rendering XAX rejection records).
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
                if node.entity is not None and entity is None:
                    continue  # S8c.6: no entity word must mean no entity
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
    if cids is not None:
        cids[:] = sorted(types, key=types.__getitem__)
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
    """``(machine code, entry offset)``, lowered for this host by the XAX x86-64 backend and cached (ADR-152)."""
    from xax_selfhost_x86_64_backend import host_image

    return host_image(*load_typing_program(), "typing")


def _non_minimal(body: bytes, start: int) -> tuple[str, str]:
    """``SER-ULEB-MINIMAL``'s expected and actual: the minimal and the given encoding of the ULEB at ``start``."""
    from xax_compiler import uleb

    value, shift, end = 0, 0, start
    while True:
        byte = body[end]
        value |= (byte & 0x7F) << shift
        end += 1
        shift += 7
        if not byte & 0x80:
            break
    return uleb(value).hex(), body[start:end].hex()


def _transitions(obj, at):
    """A resource type's transitions, read at body offset ``at`` (the count) where the program verified them."""
    from xax_compiler import Cursor

    cursor = Cursor(obj.body[at:], obj.cid.hex())
    return [cursor.uleb() for _ in range(cursor.uleb())]


def _type_diagnostic(obj, name, form, second, left, fourth=0, fifth=0, sixth=0):
    """S8c.25 (ADR-243): ``_verify_type``'s diagnostic ``(code, rule, expected, actual, dependencies, repair)``."""
    import xax_compiler as X

    if name == "TYPE_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "TYPE-BODY", 0, left, (), ()
    if name == "TYPE_OPAQUE_KIND":
        return "XAX.TYPE.OPAQUE", "TYPE-OPAQUE-KIND", list(X.OpaqueKind), second, (), ()
    if name == "TYPE_OPAQUE_CANONICAL":
        return "XAX.TYPE.OPAQUE", "TYPE-OPAQUE-CANONICAL", "no references", len(obj.references), (), ()
    if name == "TYPE_EFFECT_DOMAIN":
        return "XAX.TYPE.EFFECT", "TYPE-EFFECT-DOMAIN", list(X.EffectDomain), second, (), ()
    if name == "TYPE_EFFECT_CANONICAL":
        return "XAX.TYPE.EFFECT", "TYPE-EFFECT-CANONICAL", "domain plus optional positive instance", obj.body.hex(), (), ()
    if name == "TYPE_SUM_NONEMPTY":
        return "XAX.TYPE.SUM", "TYPE-SUM-NONEMPTY", ">= 1", 0, (), ()
    if name == "TYPE_ULEB_UNTERMINATED":
        return "XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED", "terminating byte", "end of input", (), ()
    if name == "TYPE_ULEB_BOUNDED":
        return "XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED", "at most 10 bytes", "more than 10 bytes", (), ()
    if name == "TYPE_ULEB_MINIMAL":
        return ("XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL") + _non_minimal(obj.body, fourth) + ((), ())
    if name == "TYPE_POINTER_ELEMENT":
        return "XAX.TYPE.POINTER", "TYPE-POINTER-VALUE-ELEMENT", "non-proof value type", obj.references[left].hex(), (), ()
    if name == "TYPE_POINTER_UNUSED":
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", [obj.references[left].hex()], [cid.hex() for cid in obj.references], (), ()
    if name == "TYPE_IDENTITY_TRUNCATED":
        return "XAX.CANON.TRUNCATED", "SER-BOUNDS", f"{second} available bytes", left, (), ()
    if name == "TYPE_IDENTITY_CANONICAL":
        identity = obj.body[len(obj.body) - second:] if second else b""
        return ("XAX.TYPE.OPAQUE_IDENTITY", "TYPE-OPAQUE-IDENTITY-CANONICAL", "nonempty identity and no references",
                [identity.hex(), len(obj.references)], (), ())
    if name in ("TYPE_TUPLE_ELEMENT", "TYPE_SUM_VARIANT"):
        if name == "TYPE_TUPLE_ELEMENT":
            return "XAX.TYPE.TUPLE", "TYPE-TUPLE-VALUE-ELEMENT", "non-proof value type", obj.references[left].hex(), (), ()
        return "XAX.TYPE.SUM", "TYPE-SUM-VALUE-VARIANT", "non-proof value type", obj.references[left].hex(), (), ()
    if name == "TYPE_LIST_UNUSED":
        used = sorted(cid.hex() for k, cid in enumerate(obj.references) if fourth >> k & 1)
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", used, sorted(cid.hex() for cid in obj.references), (), ()
    if name == "TYPE_RESOURCE_STACK_OWNER":
        return "XAX.TYPE.RESOURCE", "TYPE-RESOURCE-STACK-OWNER", "resource<stack-storage,live>", [second, left], (), ()
    if name == "TYPE_RESOURCE_CANONICAL":
        return ("XAX.TYPE.RESOURCE", "TYPE-RESOURCE-CANONICAL", "positive kind/state, canonical flags/instance/transitions",
                [second, left, fourth, fifth, _transitions(obj, sixth) if len(obj.body) > sixth else []], (), ())
    if name == "TYPE_ARRAY_ELEMENT":
        return ("XAX.TYPE.ARRAY", "TYPE-ARRAY-VALUE-ELEMENT", "one non-proof value element",
                [obj.references[second].hex(), [cid.hex() for cid in obj.references]], (), ())
    if name == "TYPE_REF_INDEX" and form == 9:
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {len(obj.references)}", second, (), ()
    if name == "TYPE_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {len(obj.references)}", left, (), ()
    if name == "TYPE_POINTER_PERMISSION":
        return "XAX.TYPE.POINTER_PERMISSION", "TYPE-POINTER-PERMISSION", list(X.Permission), left, (), ()
    if name == "TYPE_POINTER":
        return ("XAX.TYPE.POINTER", "TYPE-POINTER", "form=2,positive address space,power-of-two alignment", [form, second, left], (), ())
    if name == "TYPE_BITS":
        return "XAX.TYPE.BITS", "TYPE-BITS", "form=1,width>=1", [form, second], (), ()
    if name == "TYPE_FLOAT_FORMAT":
        return "XAX.TYPE.FLOAT", "TYPE-FLOAT-FORMAT", [1, 2], second, (), ()
    if name == "TYPE_FLOAT":
        return "XAX.TYPE.FLOAT", "TYPE-FLOAT", "form=7,known format", [form, second], (), ()
    if name == "TYPE_LINK":
        return "XAX.TYPE.LINK", "TYPE-LINK-CANONICAL", "empty link body", obj.body.hex(), (), ()
    return "XAX.TYPE.FORM", "TYPE-FORM-SUPPORTED", list(range(1, 12)), form, (), ()


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
        from xax_native import executable_mapping, zeroed_array

        self._mapping, base = executable_mapping(code)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + image.entry_offset
        self.code_size = len(image.code)
        self._in = zeroed_array(ctypes.c_uint64, IN_WORDS)
        self._out = zeroed_array(ctypes.c_uint64, OUT_WORDS)
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
        self._object_count = words[0] if status == ACCEPT else None
        if status != ACCEPT:
            return set()
        count = words[0]
        base = TABLE + count * OBJOK
        return {cid for cid, index in listed.items() if index is not None and self._out[base + index] == 1}

    def object_cross(self, listed: dict, objects: dict) -> dict:
        """After ``object_verdicts``: S8 (ADR-251), ``{cid: {form: diagnostic}}`` for the types whose body
        ``decode_bits_width`` (1), ``decode_float_format`` (7), or ``_decode_pointer_type`` (2) rejects, by the program's
        reading of each body (``cross_diagnostic``, ``pointer_cross_diagnostic``)."""
        count = getattr(self, "_object_count", None)
        if count is None:
            return {}
        table = lambda field, index: self._out[TABLE + count * field + index]  # noqa: E731
        crossed = {}
        for cid, index in listed.items():
            obj = objects.get(cid)
            if index is None or obj is None or obj.kind != Kind.TYPE:
                continue
            outcomes = {}
            stat, xa, xb = table(XSTAT, index), table(XA, index), table(XB, index)
            plain = stat == 0 and not obj.references
            if stat != 4 and not (plain and xa == 1 and xb >= 1):
                outcomes[1] = cross_diagnostic(True, stat, xa, xb, cid, obj.body)
            if stat != 4 and not (plain and xa == 7 and xb in (1, 2)):
                outcomes[7] = cross_diagnostic(False, stat, xa, xb, cid, obj.body)
            # The other decoders read the form first: a malformed form ULEB, or another form.
            formb = table(FORMB, index)
            form_fault = stat in (1, 2, 3) and xa == 0
            if formb:
                for form, (code, rule, expected) in FORM_CHECKS.items():
                    if form_fault:
                        outcomes[form] = cross_diagnostic(True, stat, xa, xb, cid, obj.body)
                    elif formb != form:
                        outcomes[form] = (code, rule, expected, "different type form", cid.hex())
            pointer = pointer_cross_diagnostic(table(XP, index), table(XPA, index), table(XPB, index), table(XPC, index), obj)
            if pointer is not None:
                outcomes[2] = pointer
            if outcomes:
                crossed[cid] = outcomes
        return crossed

    def object_rejections(self, listed: dict, objects: dict) -> dict:
        """After ``object_verdicts``: S8c.24 (ADR-242), ``{cid: (code, rule, expected, actual, dependencies, repair)}`` for
        the constants XAX rejects (``objects``: CID -> object, for quoting the value bytes)."""
        count = getattr(self, "_object_count", None)
        if count is None:
            return {}
        table = lambda field, index: self._out[TABLE + count * field + index]  # noqa: E731
        rejected = {}
        for cid, index in listed.items():
            if index is None:
                continue
            site = table(CREJ, index)
            if not site:
                continue
            obj = objects[cid]
            offset, length, width = table(COFF, index), table(CLEN, index), table(CWIDTH, index)
            if site > TYPE_SITE_BASE:
                # The form (S8, ADR-251): a type decoder of the same form raises this same diagnostic.
                rejected[cid] = (*_type_diagnostic(obj, TYPE_SITES[site - TYPE_SITE_BASE - 1], offset, length, width, table(C4, index), table(C5, index), table(C6, index)), offset)
                continue
            value = obj.body[offset:offset + length]
            name = CONSTANT_SITES[site - 1]
            if name == "CONST_REF_INDEX":
                rejected[cid] = ("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {len(obj.references)}", offset, (), ())
                continue
            if name == "CONST_TRUNCATED":
                rejected[cid] = ("XAX.CANON.TRUNCATED", "SER-BOUNDS", f"{length} available bytes", width, (), ())
                continue
            if name == "CONST_TRAILING":
                rejected[cid] = ("XAX.CANON.TRAILING_BYTES", "CONST-BODY", 0, width, (), ())
                continue
            type_hex = obj.references[0].hex()
            if name == "BITS_WIDTH":
                rejected[cid] = ("XAX.CONSTANT.WIDTH", "CONST-BITS-WIDTH", f"{width} canonical bits", value.hex(), [type_hex], [cid.hex(), type_hex])
            elif name == "FLOAT_WIDTH":
                rejected[cid] = ("XAX.CONSTANT.WIDTH", "CONST-FLOAT-WIDTH", width // 8, length, (), ())
            elif name == "FLOAT_NAN":
                rejected[cid] = ("XAX.CONSTANT.FLOAT_NAN", "CONST-FLOAT-CANONICAL-NAN", "canonical quiet NaN", value.hex(), (), ())
            elif name == "LINK_NULL":
                rejected[cid] = ("XAX.CONSTANT.LINK", "CONST-LINK-NULL-ONLY", bytes(8).hex(), value.hex(), (), ())
            else:
                rejected[cid] = ("XAX.CONSTANT.TYPE", "CONST-SCALAR-TYPE", ["bits<N>", "float<F>", "link (null)"], type_hex, (), ())
        return rejected

    def memory_rejection(self, refs, storages, operation_of, cids=(), resolve=None):
        """After ``facts`` declined: S8c.8 (ADR-221), the engine's exact memory rejection as ``(pass, block, node,
        (code, rule, expected, actual))``, or None when it declined without one."""
        from xax_selfhost_facts import ACCEPTED, H_REJECT, H_RBLOCK, H_RNODE, H_RPASS, H_RPAY, H_STATUS, HEADER, memory_diagnostic

        site = self._out[HEADER + H_REJECT]
        if self._out[HEADER + H_STATUS] == ACCEPTED or site == 0:
            return None
        where = tuple(self._out[HEADER + field] for field in (H_RPASS, H_RBLOCK, H_RNODE))
        payload = list(self._out[HEADER + H_RPAY : HEADER + H_RPAY + 6])
        operation = operation_of(where[1], where[2])
        try:
            return (*where, memory_diagnostic(site, payload, operation, refs, storages, lambda word: self._out[word], cids, resolve))
        except (IndexError, KeyError, ValueError, TypeError, AttributeError):  # a value the host cannot render (an unindexed type): the bootstrap decides
            return None

    def terminator_rejection(self, nodes: int, block: int) -> tuple[int, int, int]:
        """After an accepted ``check``: S8 (ADR-251), block ``block``'s terminator record ``(site, edge, condition type)``
        (site 0: none; 1: ``GRAPH-CBR-CONDITION``; 2: ``GRAPH-BLOCK-PARAMETERS`` at that edge)."""
        at = TERMINATOR_RECORDS - 4 * block
        return tuple(self._out[at : at + 3])

    def rejection_record(self, node: int) -> tuple[int, int, int, int]:
        """After an accepted ``check``: S8c.1, node ``node``'s rejection record ``(site, a, b, c)``."""
        return tuple(self._out[DIAGNOSTICS + 4 * node : DIAGNOSTICS + 4 * node + 4])

    def rejection(self, node: int, cids: list[bytes], words: list[int]):
        """After an accepted ``check`` of ``words``: node ``node``'s rejection as a bootstrap diagnostic tuple."""
        count = words[0]

        def items(owner):
            shape, length, at = (self._out[TABLE + count * table + owner] for table in (AGGREGATE, COUNT, ITEMS))
            return [self._out[at]] * length if shape == ARRAY else list(self._out[at : at + length])

        def operands(position):
            return words[position + 6 : position + 6 + words[position + 1]]

        def results(position):
            start = position + 6 + words[position + 1]
            return words[start : start + words[position + 2]]

        def field(table, owner):
            return self._out[TABLE + count * table + owner]

        def transitions(owner):
            start = field(TSTART, owner)
            return list(self._out[start : start + field(TCOUNT, owner)])

        def interface(at):
            parameters = list(self._out[at + 1 : at + 1 + self._out[at]])
            returns_at = at + 1 + len(parameters)
            return parameters, list(self._out[returns_at + 1 : returns_at + 1 + self._out[returns_at]])

        def body(owner):
            position = field(POSITION, owner)
            return bytes(words[position + 3 : position + 3 + words[position + 2]])

        return rejection(self.rejection_record(node), cids, items, operands, results, field, transitions, interface, body)

    def linear_rejection(self):
        """After an accepted ``check``: S8 (ADR-251), ``(code, a, b)`` for the linear-flow check XAX found failing
        (``LINEAR_SITES[code - 1]``), or None."""
        from xax_selfhost_facts import H_LA, H_LB, H_LREJ, HEADER

        code = self._out[HEADER + H_LREJ]
        return (code, self._out[HEADER + H_LA], self._out[HEADER + H_LB]) if code else None

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
        if len(words) > TYPING_WORDS or any(word >= 1 << 64 for word in words):
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
    import xax_native

    return xax_native.usable("typing", STORE_PATH, "XAX_TYPING_PYTHON")
