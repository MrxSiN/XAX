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
    OpaqueKind,
    TerminatorKind,
    FloatCompare,
    IntCompare,
    Kind,
    Operation,
    SemanticObject,
    StoreReader,
    x86_64_linux_exec_target,
)
from xax_graph_builder import program_store
from xax_compiler import heap_view_type
from xax_selfhost_cfg import B64, IN_POINTER, MEM, OUT_POINTER, _Builder

# The typing-and-facts program's own views: large graphs need room for their streams and fact tables.
IN_EXTENT, OUT_EXTENT = 64 << 20, 256 << 20  # S6c: the largest helper stores as one verifier object table
IN_WORDS, OUT_WORDS = IN_EXTENT // 8, OUT_EXTENT // 8
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
TERMINATOR_RECORDS = PASS_SINK - 4  # S8 (ADR-248): block b's terminator record at TERMINATOR_RECORDS - 4 * b
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
# S8 (ADR-248): a node's type decoded as ``bits`` or ``float`` that the decoder rejects (payload: the type); the
# diagnostic is the decoder's own, for the type (its per-type XSTAT/XA/XB outcome).
SITE_CROSS_BITS, SITE_CROSS_FLOAT = SITE_META_ARITY + 35, SITE_META_ARITY + 36
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
# S8c.24 (ADR-242): a well-formed constant ``_decode_constant`` rejects: its site, value offset in the body, value bytes,
# and the type's width (bits) or float width.
CREJ, COFF, CLEN, CWIDTH = 28, 29, 30, 31
C4, C5 = 32, 33  # S8c.26 (ADR-244): a resource type's flags and instance
# S8 (ADR-248): the type's body read as ``decode_bits_width``/``decode_float_format`` read it: XSTAT 0 (form and value
# read, nothing left: XA the form, XB the value), 1-3 a malformed ULEB (XA its body offset, XB its size), 4 deferred
# (a value over five bytes, or a type the stream does not resolve), 5 trailing bytes (XA how many), 6 not a type (XA
# its kind).
XSTAT, XA, XB = 34, 35, 36
C6 = 37  # S8: a resource type's transition-count body offset
# S8 (ADR-248): the type's body read as ``_decode_pointer_type`` reads it before its element: XP 0 (a pointer shape, or
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
              # S8 (ADR-248): malformed ULEB fields (C4: the field's offset in the body).
              "TYPE_ULEB_UNTERMINATED", "TYPE_ULEB_MINIMAL", "TYPE_ULEB_BOUNDED",
              # S8c.28 (ADR-246): pointer elements and opaque identity types.
              "TYPE_POINTER_ELEMENT", "TYPE_POINTER_UNUSED", "TYPE_IDENTITY_TRUNCATED", "TYPE_IDENTITY_CANONICAL")
TYPE_SITE_BASE = 16
# S4d.2a: types the memory-fact system tracks (besides pointers and other undecoded forms).
MEMORY_EFFECT_DOMAIN = 1
FACT_RESOURCE_KINDS = (1, 0x100, 0x101)  # stack storage, heap owner, heap view
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


def _uleb_status(t, at, end):
    """S8 (ADR-248): ``Cursor.uleb``'s outcome at ``at`` inside a body ending at ``end``: ``(status, size)`` with status
    0 (canonical, at most five bytes), 1 (unterminated: the body ends first), 2 (non-minimal), 3 (more than ten
    bytes), or 4 (canonical but longer than five bytes: a deferred value)."""
    b = t.b
    status, size, found, continuing = b.c(0), b.c(0), b.c(0), b.c(1)
    for k in range(10):
        position = b.add(at, k)
        inside = t.lt(position, end)
        byte = b.read(position)
        here = t.all(continuing, t.not_(found))
        ended = t.all(here, t.not_(inside))
        status = t.pick(ended, b.c(1), status)
        found = t.any(found, ended)
        terminates = t.all(here, inside, t.lt(byte, 128))
        code = t.pick(t.eq(byte, 0), b.c(2), b.c(4 if k >= 5 else 0)) if k else b.c(0)
        status = t.pick(terminates, code, status)
        size = t.pick(terminates, b.c(k + 1), size)
        found = t.any(found, terminates)
        continuing = t.all(continuing, inside, t.le(b.c(128), byte))
    return t.pick(found, status, b.c(3)), size


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
_PASS: list = []


def build_typing_program() -> tuple[StoreReader, SemanticObject]:
    from xax_selfhost_facts import build_engine

    engine, engine_objects = build_engine()
    _ENGINE[:] = [engine, engine_objects]
    _PASS[:] = build_rejection_pass()
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
    b.check(b.cmp(IntCompare.ULE, b.add(b.mul(nodes, 4), DIAGNOSTICS), TABLE), b.defer_block)
    blocks_at, proven = b.for_range(b.c(0), nodes, lambda index, carried: _node_entry(b, t, index, carried), (b.add(nodes_at, 1), b.c(0)))
    # S8c (ADR-218): the rejection pass, a separate function.
    b.put(b.c(PASS_NODES_AT), nodes_at)
    in_view, in_mem, out_view, out_mem = b.state
    triples = (IN_POINTER, IN_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    _status, _inp, in_view, in_mem, _out, out_view, out_mem = b.cur.op(
        Operation.CALL_DIRECT, (b.inp, in_view, in_mem, b.out, out_view, out_mem), (B64, *triples), entity=_PASS[0])
    b.state = (in_view, in_mem, out_view, out_mem)
    # S4d.1: terminator typing, one verdict per block after the node verdicts.
    blocks = b.read(blocks_at)
    places = b.add(b.add(t.slot(TABLES, b.c(0)), MARKS), IN_WORDS)  # block stream positions
    b.check(b.cmp(IntCompare.ULE, b.add(b.add(nodes, blocks), 5), DIAGNOSTICS), b.defer_block)
    b.check(b.cmp(IntCompare.ULE, b.add(places, blocks), OUT_WORDS), b.defer_block)
    (facts_at,) = b.for_range(b.c(0), blocks, lambda index, carried: _block_place(b, index, carried, places), (b.add(blocks_at, 1),))
    verdicts = b.add(b.c(2), nodes)
    # S8 (ADR-248): block terminator rejection records sit below PASS_SINK, one four-word record per block going down
    # (the node records and the rejection pass's lists sit above DIAGNOSTICS).
    b.check(b.cmp(IntCompare.ULE, b.add(b.add(nodes, b.mul(blocks, 5)), 8), DIAGNOSTICS), b.defer_block)
    records = b.c(TERMINATOR_RECORDS)
    b.for_range(b.c(0), blocks, lambda index, carried: _block_entry(b, t, index, carried, blocks, places, verdicts, records), ())
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
    return program_store(function, x86_64_linux_exec_target(), (*b.g.objects.values(), *engine_objects, *_PASS[1])), function


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
    # S8 (ADR-248): the cross-form read (two ULEBs, then the end) for nodes that decode this type as bits or float.
    end = b.add(base, length)
    form_status, form_size = _uleb_status(t, base, end)
    form_value, _size, _ok = t.uleb(base)
    value_at = b.add(base, form_size)
    value_status, value_size = _uleb_status(t, value_at, end)
    value_value, _size, _ok = t.uleb(value_at)
    left = b.sub(end, b.add(value_at, value_size))
    xstat = t.pick(t.nonzero(left), b.c(5), b.c(0))
    xa, xb = t.pick(t.nonzero(left), left, form_value), value_value
    xstat, xa, xb = (t.pick(t.eq(value_status, 0), xstat, value_status), t.pick(t.eq(value_status, 0), xa, form_size),
                     t.pick(t.eq(value_status, 0), xb, value_size))
    xstat, xa, xb = (t.pick(t.eq(form_status, 0), xstat, form_status), t.pick(t.eq(form_status, 0), xa, b.c(0)),
                     t.pick(t.eq(form_status, 0), xb, form_size))
    xstat, xa = t.pick(t.eq(kind, int(Kind.TYPE)), xstat, b.c(6)), t.pick(t.eq(kind, int(Kind.TYPE)), xa, kind)
    xstat = t.pick(t.eq(kind, 0), b.c(4), xstat)  # a type with an unresolved reference: the bootstrap decides
    b.put(t.slot(XSTAT, index), xstat)
    b.put(t.slot(XA, index), xa)
    b.put(t.slot(XB, index), xb)
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


def _block_entry(b: _Builder, t: _Typing, index, _carried, blocks, places, verdicts, records):
    """A block's terminator: a ``bits<1>`` branch condition, and edge argument types equal to the target's parameters.

    S8 (ADR-248): a terminator the bootstrap rejects gets a record ``[site, a, condition, 0]`` at ``records - 4 * index``:
    site 1 a bits condition of another width (``GRAPH-CBR-CONDITION``), site 2 edge ``a``'s argument types
    (``GRAPH-BLOCK-PARAMETERS``).  A non-bits condition (the bootstrap's width decoder rejects it) gives no record."""
    position = b.get(b.add(places, index))
    known = b.read(position)  # 0 when some value type was not marshalled
    parameters = b.read(b.add(position, 1))
    at = b.add(b.add(position, 2), parameters)
    kind, condition, edges = b.read(at), b.read(b.add(at, 1)), b.read(b.add(at, 2))
    condition_ok = t.any(t.not_(t.eq(kind, CONDITIONAL_BRANCH)), t.eq(t.lookup(WIDTH, condition), 1))

    def edge(k, carried):
        cursor, ok, first = carried
        target, count = b.read(cursor), b.read(b.add(cursor, 1))
        inside = t.lt(target, blocks)
        target_at = b.get(b.add(places, t.pick(inside, target, b.c(0))))
        expected = b.read(b.add(target_at, 1))
        same_count = t.all(inside, t.eq(count, expected))

        def argument(j, carried_):
            (match,) = carried_
            return (t.all(match, t.eq(b.read(b.add(b.add(cursor, 2), j)), b.read(b.add(b.add(target_at, 2), j)))),)

        (match,) = b.for_range(b.c(0), b.mul(same_count, count), argument, (same_count,))
        return b.add(b.add(cursor, 2), count), t.all(ok, match), t.pick(t.all(ok, t.not_(match)), k, first)

    _end, edges_ok, first_edge = b.for_range(b.c(0), edges, edge, (b.add(at, 3), b.c(1), b.c(0)))
    ok = t.all(t.nonzero(known), condition_ok, edges_ok)
    b.put(b.add(verdicts, index), b.sub(b.c(NOT_PROVEN), ok))
    width = t.lookup(WIDTH, condition)
    bad_condition = t.all(t.eq(kind, CONDITIONAL_BRANCH), t.nonzero(width), t.not_(t.eq(width, 1)))
    non_bits = t.all(t.eq(kind, CONDITIONAL_BRANCH), t.eq(width, 0))
    site = t.pick(t.not_(t.nonzero(known)), b.c(0), t.pick(bad_condition, b.c(1), t.pick(non_bits, b.c(0), t.pick(edges_ok, b.c(0), b.c(2)))))
    record = b.sub(records, b.mul(index, 4))
    b.put(record, site)
    b.put(b.add(record, 1), first_edge)
    b.put(b.add(record, 2), condition)
    return ()


def _constant_rule(b: _Builder, t: _Typing, operands, results, extra, extra_at, result):
    """``constant``: a canonical constant object of a scalar type, no operands, one result of that type."""
    entity = b.read(extra_at)
    ok, value_type = _constant_object(b, t, entity)
    return t.all(ok, t.eq(extra, 1), t.eq(operands, 0), t.eq(results, 1), t.eq(result, value_type))


def _constant_object(b: _Builder, t: _Typing, entity, parts: dict | None = None):
    """``(ok, value type)``: entry ``entity`` is a constant object ``_decode_constant`` accepts (``parts``: filled with
    the values a rejection quotes)."""
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
    last = b.read(b.add(data, t.pick(t.all(t.nonzero(count), t.le(count, length)), b.sub(count, 1), b.c(0))))  # clamped: any body
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
    if parts is not None:
        parts.update(shape=shape, base=base, data=data, count=count, width=width, form=form, raw=raw, zero=zero, small=small, nan=nan,
                     value_type=value_type, bits_ok=bits_ok, kind=kind, references=references, end=end, reference=reference,
                     reference_ok=reference_ok, count_ok=count_ok, reference_size=size)
    return t.all(shape, t.any(bits_ok, f32, f64, link_ok)), value_type


def _object_entry(b: _Builder, t: _Typing, index):
    """S6b (ADR-143): the entry's object verdict: a valid type (``_known``) or a valid constant."""
    kind = b.read(b.get(t.slot(POSITION, index)))
    parts: dict = {}
    constant_ok, _value_type = _constant_object(b, t, index, parts)
    verdict = t.any(t.all(t.eq(kind, int(Kind.TYPE)), _known(t, index)), t.all(t.eq(kind, int(Kind.CONSTANT)), constant_ok))
    b.put(t.slot(OBJOK, index), verdict)
    # S8c.24 (ADR-242): ``_decode_constant``'s value rejection for a well-formed constant (one reference, used once,
    # exact length), by the value type's form byte.  A bits type the tables cannot size, or a float format they do
    # not know, declines (the bootstrap's own type decoders decide).
    value_type, count, width, form, raw = parts["value_type"], parts["count"], parts["width"], parts["form"], parts["raw"]
    formb = t.lookup(FORMB, value_type)
    float_width = t.pick(t.eq(form, 1), b.c(32), t.pick(t.eq(form, 2), b.c(64), b.c(0)))
    nan = t.pick(t.eq(form, 1), parts["nan"](23, 0xFF, (1 << 23) - 1), parts["nan"](52, 0x7FF, (1 << 52) - 1))
    quiet = t.pick(t.eq(form, 1), b.c(F32_QUIET_NAN), b.c(F64_QUIET_NAN))
    bits_site = t.pick(t.all(t.nonzero(width), t.not_(parts["bits_ok"])), b.c(1), b.c(0))
    float_site = t.pick(t.eq(float_width, 0), b.c(0), t.pick(t.not_(t.eq(count, b.op(Operation.UDIV, float_width, 8))), b.c(2),
                                                         t.pick(t.all(nan, t.not_(t.eq(raw, quiet))), b.c(3), b.c(0))))
    link_site = t.pick(t.all(t.eq(count, 8), parts["zero"]), b.c(0), b.c(4))
    site = t.pick(t.eq(formb, 1), bits_site, t.pick(t.eq(formb, 7), float_site, t.pick(t.eq(formb, 11), link_site, b.c(5))))
    constant = t.all(t.eq(kind, int(Kind.CONSTANT)), parts["shape"], t.lt(value_type, t.count))
    # S8c.25 (ADR-243): ``_verify_type`` for bits (1), float (7), link (11), and unsupported forms.  The second value
    # (width or float format) must be a canonical ULEB inside the body, else the bootstrap's cursor decides.
    position = b.get(t.slot(POSITION, index))
    references, length = b.read(b.add(position, 1)), b.read(b.add(position, 2))
    base = b.add(position, 3)
    end = b.add(base, length)
    form, form_size, form_ok = t.uleb(base)
    second, second_size, second_ok = t.uleb(b.add(base, form_size))
    after = b.add(b.add(base, form_size), second_size)
    second_ok = t.all(second_ok, t.le(after, end), t.le(b.add(base, form_size), end))
    # S8 (ADR-248): each field's ``Cursor.uleb`` outcome, so a malformed field rejects as the bootstrap's cursor does.
    statuses, starts = [], []
    field_at = base
    for _field in range(6):
        status_, size_ = _uleb_status(t, field_at, end)
        statuses.append(status_)
        starts.append(field_at)
        field_at = b.add(field_at, size_)
    uleb_codes = {1: "TYPE_ULEB_UNTERMINATED", 2: "TYPE_ULEB_MINIMAL", 3: "TYPE_ULEB_BOUNDED"}

    def first_bad(upto: int):
        """The site of the first malformed field among fields 0..upto (0 when none is, or the first is deferred)."""
        site_ = b.c(0)
        for k in reversed(range(upto + 1)):
            bad_code = t.pick(t.eq(statuses[k], 1), b.c(TYPE_SITE_BASE + 1 + TYPE_SITES.index(uleb_codes[1])), t.pick(
                t.eq(statuses[k], 2), b.c(TYPE_SITE_BASE + 1 + TYPE_SITES.index(uleb_codes[2])), t.pick(
                    t.eq(statuses[k], 3), b.c(TYPE_SITE_BASE + 1 + TYPE_SITES.index(uleb_codes[3])), b.c(0))))
            site_ = t.pick(t.eq(statuses[k], 0), site_, bad_code)
        return site_

    def first_bad_at(upto: int):
        """The body offset and size of that field (for ``SER-ULEB-MINIMAL``)."""
        offset_, size_ = b.c(0), b.c(0)
        for k in reversed(range(upto + 1)):
            offset_ = t.pick(t.eq(statuses[k], 0), offset_, b.sub(starts[k], base))
        return offset_
    left = b.sub(end, after)
    scalar = t.one_of(form, (1, 7))
    trailing = t.all(scalar, second_ok, t.nonzero(left))
    bits = t.all(t.eq(form, 1), second_ok, t.any(t.nonzero(references), t.eq(second, 0)))
    float_format = t.all(t.eq(form, 7), second_ok, t.not_(t.one_of(second, (1, 2))))
    float_refs = t.all(t.eq(form, 7), second_ok, t.nonzero(references))
    link = t.all(t.eq(form, 11), t.any(t.nonzero(references), t.not_(t.eq(length, 1))))
    unknown = t.any(t.eq(form, 0), t.not_(t.le(form, 11)))
    type_site = t.pick(trailing, b.c(TYPE_SITE_BASE + 1), t.pick(bits, b.c(TYPE_SITE_BASE + 2), t.pick(float_format, b.c(TYPE_SITE_BASE + 3), t.pick(
        float_refs, b.c(TYPE_SITE_BASE + 4), t.pick(link, b.c(TYPE_SITE_BASE + 5), t.pick(unknown, b.c(TYPE_SITE_BASE + 6), b.c(0)))))))
    type_site = t.pick(t.all(scalar, t.not_(second_ok)), first_bad(1), type_site)
    code = lambda name: b.c(TYPE_SITE_BASE + 1 + TYPE_SITES.index(name))  # noqa: E731
    # Values after the second: a ULEB chain from ``after`` (each canonical and inside the body, else the chain stops).
    third, third_size, third_ok = t.uleb(after)
    third_ok = t.all(second_ok, third_ok, t.le(b.add(after, third_size), end))
    at4 = b.add(after, third_size)
    fourth, fourth_size, fourth_ok = t.uleb(at4)
    fourth_ok = t.all(third_ok, fourth_ok, t.le(b.add(at4, fourth_size), end))
    at5 = b.add(at4, fourth_size)
    fifth, fifth_size, fifth_ok = t.uleb(at5)
    fifth_ok = t.all(fourth_ok, fifth_ok, t.le(b.add(at5, fifth_size), end))
    after5 = b.add(at5, fifth_size)
    # opaque (5): trailing, kind, references.
    opaque_site = t.pick(t.not_(second_ok), first_bad(1), t.pick(t.nonzero(left), code("TYPE_TRAILING"), t.pick(
        t.not_(t.all(t.nonzero(second), t.le(second, 7))), code("TYPE_OPAQUE_KIND"), t.pick(t.nonzero(references), code("TYPE_OPAQUE_CANONICAL"), b.c(0)))))
    # effect (3): the domain, then an optional instance, trailing bytes, and the canonical body.
    has_instance = t.nonzero(left)
    effect_left = t.pick(has_instance, b.sub(end, at4), b.c(0))
    effect_canonical = t.any(t.nonzero(references), t.all(has_instance, t.eq(third, 0)))
    effect_site = t.pick(t.not_(second_ok), first_bad(1), t.pick(t.not_(t.all(t.nonzero(second), t.le(second, 11))), code("TYPE_EFFECT_DOMAIN"), t.pick(
        t.all(has_instance, t.not_(third_ok)), first_bad(2), t.pick(t.nonzero(effect_left), code("TYPE_TRAILING"), t.pick(
            effect_canonical, code("TYPE_EFFECT_CANONICAL"), b.c(0))))))
    # sum (10): at least one variant.
    sum_site = t.pick(t.all(second_ok, t.eq(second, 0)), code("TYPE_SUM_NONEMPTY"), t.pick(second_ok, b.c(0), first_bad(1)))
    # pointer (2): space, element index (in range), permission, alignment, end, permission value, shape.
    pointer_left = b.sub(end, after5)
    power = t.eq(b.op(Operation.BIT_AND, fifth, b.sub(fifth, 1)), 0)
    pointer_site = t.pick(t.not_(third_ok), first_bad(2), t.pick(t.le(references, third), code("TYPE_REF_INDEX"), t.pick(t.not_(fifth_ok), first_bad(4), t.pick(
        t.nonzero(pointer_left), code("TYPE_TRAILING"), t.pick(t.not_(t.all(t.nonzero(fourth), t.le(fourth, 3))), code("TYPE_POINTER_PERMISSION"), t.pick(
            t.any(t.eq(second, 0), t.eq(fifth, 0), t.not_(power)), code("TYPE_POINTER"), b.c(0)))))))
    pointer_third = t.pick(t.le(references, third), third, t.pick(t.nonzero(pointer_left), pointer_left, t.pick(
        t.not_(t.all(t.nonzero(fourth), t.le(fourth, 3))), fourth, fifth)))
    # S8c.28: a well-formed pointer's element, when the tables decoded it: not a proof type, the only reference.
    pointee = b.read(b.add(end, t.pick(t.lt(third, references), third, b.c(0))))
    pointee_proof = t.any(t.lookup(EFFECT, pointee), t.lookup(RESOURCE, pointee))
    pointer_site = t.pick(t.all(t.eq(pointer_site, 0), fifth_ok, t.lt(third, references), _known(t, pointee)), t.pick(
        pointee_proof, code("TYPE_POINTER_ELEMENT"), t.pick(t.eq(references, 1), b.c(0), code("TYPE_POINTER_UNUSED"))), pointer_site)
    pointer_third = t.pick(t.any(t.eq(pointer_site, code("TYPE_POINTER_ELEMENT")), t.eq(pointer_site, code("TYPE_POINTER_UNUSED"))), third, pointer_third)
    # opaque identity (6): a byte string (truncated, trailing, or empty / with references).
    identity_end = b.add(after, second)
    identity_site = t.pick(t.not_(second_ok), first_bad(1), t.pick(t.lt(end, identity_end), code("TYPE_IDENTITY_TRUNCATED"), t.pick(
        t.lt(identity_end, end), code("TYPE_TRAILING"), t.pick(t.any(t.eq(second, 0), t.nonzero(references)), code("TYPE_IDENTITY_CANONICAL"), b.c(0)))))
    identity_third = t.pick(t.lt(end, identity_end), left, b.sub(end, t.pick(t.lt(end, identity_end), end, identity_end)))
    # resource (4): the stack-owner short form, or the long form with no transitions.
    sixth, sixth_size, sixth_ok = t.uleb(after5)
    sixth_ok = t.all(fifth_ok, sixth_ok, t.le(b.add(after5, sixth_size), end))
    after6 = b.add(after5, sixth_size)
    short = t.all(third_ok, t.eq(b.add(after, third_size), end))
    owner_bad = t.any(t.nonzero(references), t.not_(t.eq(second, 1)), t.not_(t.eq(third, 1)))
    unknown_flags = t.nonzero(b.op(Operation.BIT_AND, fourth, ~15 & ((1 << 64) - 1)))
    plain_owner = t.all(t.eq(second, 1), t.eq(third, 1), t.eq(fourth, 4), t.eq(fifth, 0))
    long_bad = t.any(t.nonzero(references), t.eq(second, 0), t.eq(third, 0), unknown_flags, plain_owner)
    # S8 (ADR-248): the transitions, each a ULEB as the cursor reads it: strictly increasing, positive, not the state.
    steps = t.pick(t.all(sixth_ok, t.le(sixth, length)), sixth, t.pick(sixth_ok, length, b.c(0)))

    def transition(k, carried):
        at, fault, fault_at, bad, prev = carried
        status_, size_ = _uleb_status(t, at, end)
        value, _size, _ok = t.uleb(at)
        live = t.eq(fault, 0)
        faulted = t.all(live, t.not_(t.eq(status_, 0)))
        good = t.all(live, t.eq(status_, 0))
        wrong = t.any(t.eq(value, 0), t.eq(value, third), t.all(t.nonzero(prev), t.le(b.add(value, 1), prev)))
        return (t.pick(good, b.add(at, size_), at), t.pick(faulted, status_, fault), t.pick(faulted, b.sub(at, base), fault_at),
                t.pick(t.all(good, wrong), b.c(1), bad), t.pick(good, b.add(value, 1), prev))

    transitions_end, transition_fault, transition_fault_at, transitions_bad, _prev = b.for_range(
        b.c(0), steps, transition, (after6, b.c(0), b.c(0), b.c(0), b.c(0)))
    uleb_code = lambda status_: t.pick(t.eq(status_, 1), code("TYPE_ULEB_UNTERMINATED"), t.pick(  # noqa: E731
        t.eq(status_, 2), code("TYPE_ULEB_MINIMAL"), t.pick(t.eq(status_, 3), code("TYPE_ULEB_BOUNDED"), b.c(0))))
    resource_site = t.pick(t.not_(third_ok), first_bad(2), t.pick(short, t.pick(owner_bad, code("TYPE_RESOURCE_STACK_OWNER"), b.c(0)), t.pick(
        t.not_(sixth_ok), first_bad(5), t.pick(t.nonzero(transition_fault), uleb_code(transition_fault), t.pick(
            t.nonzero(b.sub(end, transitions_end)), code("TYPE_TRAILING"), t.pick(
                t.any(long_bad, t.nonzero(transitions_bad)), code("TYPE_RESOURCE_CANONICAL"), b.c(0)))))))
    transition_uleb = t.all(t.eq(form, 4), t.nonzero(transition_fault))
    # array (9): element index in range, count, end, then a decoded element that is a proof type or not the only reference.
    element = b.read(b.add(end, t.pick(t.lt(second, references), second, b.c(0))))
    proof = t.any(t.lookup(EFFECT, element), t.lookup(RESOURCE, element))
    array_left = b.sub(end, b.add(after, third_size))
    array_site = t.pick(t.not_(second_ok), first_bad(1), t.pick(t.le(references, second), code("TYPE_REF_INDEX"), t.pick(t.not_(third_ok), first_bad(2), t.pick(
        t.nonzero(array_left), code("TYPE_TRAILING"), t.pick(t.not_(_known(t, element)), b.c(0), t.pick(
            t.any(proof, t.not_(t.eq(references, 1))), code("TYPE_ARRAY_ELEMENT"), b.c(0)))))))
    array_third = t.pick(t.le(references, second), second, array_left)
    # tuple (8) and sum (10): every item index in order (the first out of range rejects), the end, then each item
    # (a decoded type, the first proof type rejects), then every reference used.
    listy = t.any(t.eq(form, 8), t.eq(form, 10))
    marks = t.slot(TABLES, b.c(0))
    listable = t.all(kind_is_type := t.eq(kind, int(Kind.TYPE)), listy, second_ok, t.le(references, MARKS), t.le(second, length))
    list_unreadable = t.all(listy, t.not_(second_ok))
    steps = t.pick(listable, second, b.c(0))
    b.for_range(b.c(0), t.pick(listable, references, b.c(0)), lambda k, c: (b.put(b.add(marks, k), 0),) and (), ())
    none_word = b.c((1 << 64) - 1)

    def read_item(k, carried):
        at, ok, bad = carried
        value, size, value_ok = t.uleb(at)
        good = t.all(ok, value_ok, t.le(b.add(at, size), end))
        first_bad = t.all(good, t.eq(bad, none_word), t.le(references, value))
        b.put(b.add(marks, t.pick(t.all(good, t.lt(value, references)), value, b.c(0))), t.pick(t.all(good, t.lt(value, references)), b.c(1), b.get(b.add(marks, b.c(0)))))
        return b.add(at, size), t.all(good, t.not_(first_bad)), t.pick(first_bad, value, bad)

    items_end, items_ok, bad = b.for_range(b.c(0), steps, read_item, (after, b.c(1), none_word))

    def check_item(k, carried):
        at, state, which = carried
        value, size, _ok = t.uleb(at)
        item = b.read(b.add(end, t.pick(t.lt(value, references), value, b.c(0))))
        searching = t.eq(state, 0)
        known, proof = _known(t, item), t.any(t.lookup(EFFECT, item), t.lookup(RESOURCE, item))
        state_ = t.pick(searching, t.pick(t.not_(known), b.c(2), t.pick(proof, b.c(1), b.c(0))), state)
        return b.add(at, size), state_, t.pick(t.all(searching, known, proof), value, which)

    _at, item_state, which = b.for_range(b.c(0), t.pick(items_ok, steps, b.c(0)), check_item, (after, b.c(0), b.c(0)))
    (used_mask, _power, used_count) = b.for_range(b.c(0), t.pick(listable, references, b.c(0)), lambda k, c: (
        b.add(c[0], b.mul(b.get(b.add(marks, k)), c[1])), b.mul(c[1], 2), b.add(c[2], b.get(b.add(marks, k)))), (b.c(0), b.c(1), b.c(0)))
    list_left = b.sub(end, items_end)
    list_site = t.pick(t.not_(listable), b.c(0), t.pick(t.all(t.eq(form, 10), t.eq(second, 0)), code("TYPE_SUM_NONEMPTY"), t.pick(
        t.not_(t.eq(bad, none_word)), code("TYPE_REF_INDEX"), t.pick(t.not_(items_ok), b.c(0), t.pick(t.nonzero(list_left), code("TYPE_TRAILING"), t.pick(
            t.eq(item_state, 2), b.c(0), t.pick(t.eq(item_state, 1), t.pick(t.eq(form, 8), code("TYPE_TUPLE_ELEMENT"), code("TYPE_SUM_VARIANT")), t.pick(
                t.eq(used_count, references), b.c(0), t.pick(t.le(references, 64), code("TYPE_LIST_UNUSED"), b.c(0))))))))))
    list_third = t.pick(t.not_(t.eq(bad, none_word)), bad, t.pick(t.nonzero(list_left), list_left, which))
    del kind_is_type
    type_site = t.pick(list_unreadable, first_bad(1), t.pick(listy, list_site, t.pick(t.eq(form, 6), identity_site, type_site)))
    type_site = t.pick(t.eq(form, 5), opaque_site, t.pick(t.eq(form, 3), effect_site, t.pick(t.eq(form, 2), pointer_site, t.pick(
        t.eq(form, 4), resource_site, t.pick(t.eq(form, 9), array_site, type_site)))))
    type_third = t.pick(listy, list_third, t.pick(t.eq(form, 6), identity_third, t.pick(t.eq(form, 5), left, t.pick(t.eq(form, 3), effect_left, t.pick(t.eq(form, 2), pointer_third, t.pick(
        t.eq(form, 4), t.pick(t.eq(resource_site, code("TYPE_TRAILING")), b.sub(end, transitions_end), third), t.pick(t.eq(form, 9), array_third, left)))))))
    b.put(t.slot(C5, index), fifth)
    a_type = t.eq(kind, int(Kind.TYPE))
    type_site = t.pick(t.eq(statuses[0], 0), type_site, first_bad(0))
    uleb_site = t.any(*(t.eq(type_site, b.c(TYPE_SITE_BASE + 1 + TYPE_SITES.index(name))) for name in uleb_codes.values()))
    b.put(t.slot(C4, index), t.pick(uleb_site, t.pick(transition_uleb, transition_fault_at, first_bad_at(5)), t.pick(listy, used_mask, fourth)))
    b.put(t.slot(C6, index), b.sub(after5, base))  # S8: a resource type's transition count offset (its canonical rejection quotes them)
    # S8 (ADR-248): ``_decode_pointer_type``'s reading of any type, up to its shape check.
    shape_bad = t.any(t.not_(t.eq(form, 2)), t.eq(second, 0), t.eq(fifth, 0), t.not_(power))
    xp, xpa = t.pick(shape_bad, b.c(8), b.c(0)), form
    xp, xpa = t.pick(t.one_of(fourth, (1, 2, 3)), xp, b.c(7)), t.pick(t.one_of(fourth, (1, 2, 3)), xpa, fourth)
    xp, xpa = t.pick(t.nonzero(pointer_left), b.c(5), xp), t.pick(t.nonzero(pointer_left), pointer_left, xpa)
    for k in (4, 3):
        xp, xpa = t.pick(t.eq(statuses[k], 0), xp, statuses[k]), t.pick(t.eq(statuses[k], 0), xpa, b.sub(starts[k], base))
    xp, xpa = t.pick(t.le(references, third), b.c(6), xp), t.pick(t.le(references, third), third, xpa)
    for k in (2, 1, 0):
        xp, xpa = t.pick(t.eq(statuses[k], 0), xp, statuses[k]), t.pick(t.eq(statuses[k], 0), xpa, b.sub(starts[k], base))
    xp = t.pick(t.eq(kind, int(Kind.TYPE)), xp, b.c(4))
    b.put(t.slot(XP, index), xp)
    b.put(t.slot(XPA, index), xpa)
    b.put(t.slot(XPB, index), second)
    b.put(t.slot(XPC, index), fifth)
    # S8c.29 (ADR-247): a malformed constant body, in ``_decode_constant``'s order: the type index, the value length,
    # trailing bytes (each ULEB canonical and inside the body, else the bootstrap's cursor decides).
    c_end, c_data, c_refs, c_index = parts["end"], parts["data"], parts["references"], parts["reference"]
    c_index_ok = t.all(t.eq(parts["kind"], int(Kind.CONSTANT)), parts["reference_ok"], t.le(b.add(parts["base"], parts["reference_size"]), c_end))
    c_count_ok = t.all(c_index_ok, parts["count_ok"], t.le(c_data, c_end))
    c_value_end = b.add(c_data, count)
    malformed_site = t.pick(t.not_(c_index_ok), b.c(0), t.pick(t.le(c_refs, c_index), b.c(6), t.pick(t.not_(c_count_ok), b.c(0), t.pick(
        t.lt(c_end, c_value_end), b.c(7), t.pick(t.lt(c_value_end, c_end), b.c(8), b.c(0))))))
    malformed_left = t.pick(t.lt(c_end, c_value_end), b.sub(c_end, c_data), b.sub(c_end, t.pick(t.lt(c_end, c_value_end), c_end, c_value_end)))
    malformed = t.nonzero(malformed_site)
    b.put(t.slot(CREJ, index), t.pick(constant, site, t.pick(malformed, malformed_site, t.pick(a_type, type_site, b.c(0)))))
    b.put(t.slot(COFF, index), t.pick(constant, b.sub(parts["data"], parts["base"]), t.pick(malformed, c_index, form)))
    b.put(t.slot(CLEN, index), t.pick(constant, count, t.pick(malformed, count, second)))
    b.put(t.slot(CWIDTH, index), t.pick(constant, t.pick(t.eq(formb, 7), float_width, width), t.pick(malformed, malformed_left, type_third)))


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
    verdict = b.add(covered, b.sub(covered, ok))  # 0 outside, 1 proven, 2 not proven (the rejection pass may make it 3)
    b.put(b.add(b.c(2), index), verdict)
    return b.add(extra_at, extra), b.add(proven, ok)


def build_rejection_pass():
    """S8c (ADR-218): the rejection pass, its own XAX function so the typing program's main function stays within the
    XAX backends' per-function arena.  After the node verdicts, it walks the node stream again and turns each
    NOT_PROVEN node whose first failing bootstrap check it identifies into REJECTED with its diagnostic record.
    It reads the node stream position from ``PASS_NODES_AT``."""
    b = _Builder(IN_EXTENT, OUT_EXTENT)
    t = _Typing(b, b.read(b.c(0)))
    nodes_at = b.get(b.c(PASS_NODES_AT))
    nodes = b.read(nodes_at)
    b.check(b.cmp(IntCompare.ULE, b.add(b.mul(nodes, 4), DIAGNOSTICS), TABLE), b.defer_block)  # main checked it too
    # S8c.7: decoded callee interfaces go to a list area after the records.
    lists = b.add(b.mul(nodes, 4), DIAGNOSTICS)
    b.for_range(b.c(0), nodes, lambda index, carried: _rejection_entry(b, t, index, carried), (b.add(nodes_at, 1), lists))
    for block in (None, b.reject_block, b.defer_block):  # neither failure happens here: main read the same words
        if block is not None:
            b.enter(block)
        in_view, in_mem, out_view, out_mem = b.state
        b.cur.ret(b.c(0), b.inp, in_view, in_mem, b.out, out_view, out_mem)
    # The facts engine's signature: a status word, then the views (the backends lower calls of this shape).
    triples = (IN_POINTER, IN_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    return b.g.function(triples, (B64, *triples)), tuple(b.g.objects.values())


def _rejection_entry(b: _Builder, t: _Typing, index, carried):
    """One node of the rejection pass: the same fields ``_node_entry`` reads, then ``_rejection``."""
    position, lists = carried
    operation, operands, results, attributes, attribute, extra = (b.read(b.add(position, k)) for k in range(6))
    ids = b.add(position, 6)
    extra_at = b.add(ids, b.add(operands, results))
    first, second, result = b.read(ids), b.read(b.add(ids, 1)), b.read(b.add(ids, operands))
    width, first_width = t.lookup(WIDTH, result), t.lookup(WIDTH, first)
    is_bits, first_bits = t.nonzero(width), t.nonzero(first_width)
    interface_decoded, next_lists = _call_interface(b, t, operation, extra, extra_at, lists)
    is_float, first_float = t.nonzero(t.lookup(FORMAT, result)), t.nonzero(t.lookup(FORMAT, first))

    def shape(count_in: int, count_out: int, count_attributes: int):
        return t.all(t.eq(operands, count_in), t.eq(results, count_out), t.eq(attributes, count_attributes))

    kind_in = lambda limit: t.all(t.le(b.c(1), attribute), t.le(attribute, limit))  # noqa: E731
    verdict_at = b.add(b.c(2), index)
    verdict = b.get(verdict_at)
    ok = t.eq(verdict, PROVEN)
    # sum.tag: the bit length of (variant count - 1), as ``_node_entry`` computes it.
    _rest, needed = b.loop((b.sub(t.lookup(COUNT, first), 1), b.c(0)), lambda v: b.cmp(IntCompare.NE, v[0], 0),
                           lambda v: (b.op(Operation.UDIV, v[0], 2), b.add(v[1], 1)))
    site, payload = _rejection(b, t, operation, shape, (operands, results, attributes), attribute, kind_in, result, first, second,
                               width, first_width, is_bits, first_bits, is_float, first_float, t.lookup(LINK, first), ok, position, needed,
                               ids, extra_at, (extra, *_constant_object(b, t, b.read(extra_at))), (interface_decoded, lists))
    rejected = t.all(t.eq(verdict, NOT_PROVEN), t.nonzero(site))
    b.put(verdict_at, b.add(verdict, rejected))
    record = b.add(b.c(DIAGNOSTICS), b.mul(index, 4))
    for k, word in enumerate((b.mul(rejected, site), *payload)):
        b.put(b.add(record, k), word)
    return b.add(extra_at, extra), next_lists


def _call_interface(b: _Builder, t: _Typing, operation, extra, extra_at, lists):
    """S8c.7: a direct call's callee interface as ``_decode_function_interface`` reads a graph-fragment function, written
    at ``lists`` as ``[n, parameter types..., m, return types...]``.  ``(decoded, next free word)``; decoded is 0 for a
    group member, a type the program did not decode, or a body the bootstrap would reject (it then decides)."""
    entity = b.read(extra_at)
    valid = t.all(t.eq(operation, int(Operation.CALL_DIRECT)), t.eq(extra, 1), t.lt(entity, t.count))
    position = b.get(t.slot(POSITION, t.pick(valid, entity, b.c(0))))
    kind, references, length = (b.read(b.add(position, k)) for k in range(3))
    base = b.add(position, 3)
    end = b.add(base, length)
    graph, size, graph_ok = t.uleb(base)
    graph_inside = t.all(graph_ok, t.lt(graph, references))
    graph_entry = b.read(b.add(end, t.pick(graph_inside, graph, b.c(0))))
    graph_valid = t.lt(graph_entry, t.count)
    graph_kind = b.mul(graph_valid, b.read(b.get(t.slot(POSITION, t.pick(graph_valid, graph_entry, b.c(0))))))
    fragment = t.all(valid, t.eq(kind, int(Kind.FUNCTION)), graph_inside, t.eq(graph_kind, int(Kind.GRAPH_FRAGMENT)))
    sink = b.c(PASS_SINK)

    def walk(start, slot, ok):
        count, count_size, count_ok = t.uleb(start)
        bounded = t.all(ok, count_ok, t.le(count, length))
        steps = t.pick(bounded, count, b.c(0))
        fits = t.le(b.add(b.add(slot, 1), steps), b.c(TABLE))
        b.put(t.pick(fits, slot, sink), steps)

        def item(k, carried):
            at, good = carried
            reference, width, reference_ok = t.uleb(at)
            inside = t.all(reference_ok, t.lt(reference, references), t.le(b.add(at, width), end))
            declared = b.read(b.add(end, t.pick(inside, reference, b.c(0))))
            b.put(t.pick(fits, b.add(b.add(slot, 1), k), sink), declared)
            return b.add(at, width), t.all(good, inside, _known(t, declared))

        after, good = b.for_range(b.c(0), steps, item, (b.add(start, count_size), t.all(bounded, fits)))
        return after, good, b.add(b.add(slot, 1), steps)

    after_parameters, parameters_ok, returns_slot = walk(b.add(base, size), lists, fragment)
    after_returns, returns_ok, after_slot = walk(after_parameters, returns_slot, parameters_ok)
    decoded = t.all(returns_ok, t.eq(after_returns, end))
    return decoded, t.pick(decoded, after_slot, lists)


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
            (t.not_(t.eq(result_shape, SUM)), *none),
            (clamped, *none),
            (t.not_(ok), SITE_SUM_MAKE_VARIANT, (result, attribute, first)),
        )),
        (is_(Operation.SUM_TAG), (
            (t.not_(shape(1, 1, 0)), SITE_SUM_TAG_CONTRACT, counts),
            (t.not_(t.eq(first_shape, SUM)), *none),
            (t.not_(is_bits), *cross(result, 1)),
            (t.not_(ok), SITE_SUM_TAG_WIDTH, payload(t.pick(t.nonzero(needed), needed, b.c(1)), width)),
        )),
        (is_(Operation.SUM_GET), (
            (t.not_(shape(1, 1, 1)), SITE_SUM_GET_CONTRACT, counts),
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
    """S8 (ADR-248): ``decode_bits_width`` (1) or ``decode_float_format`` (7) of ``type_`` fails: the decoder's diagnostic
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


# S8 (ADR-248): the decoders that check only the form before reading on: form -> (code, rule, expected).  Key 0 is
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
    """S8 (ADR-248): ``_decode_pointer_type``'s diagnostic for a type by the program's reading (XP/XPA/XPB/XPC), as
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
    """S8 (ADR-248): ``decode_bits_width`` (``bits``) or ``decode_float_format`` of a type, by the program's outcome for
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
    if site not in _SITES:
        raise ValueError(f"unknown typing rejection site {site}")
    code, rule, expected, actual = _SITES[site]
    context = _Rendering(cids, items, operands, results, field, transitions, interface)
    return code, rule, expected(context, x, y, z), actual(context, x, y, z)


_SITES = _render_sites()


def load_typing_program() -> tuple[StoreReader, SemanticObject]:
    if not STORE_PATH.exists():
        return build_typing_program()
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "typing")
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
        from xax_native import executable_mapping

        self._mapping, base = executable_mapping(code)
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
        self._object_count = words[0] if status == ACCEPT else None
        if status != ACCEPT:
            return set()
        count = words[0]
        base = TABLE + count * OBJOK
        return {cid for cid, index in listed.items() if index is not None and self._out[base + index] == 1}

    def object_cross(self, listed: dict, objects: dict) -> dict:
        """After ``object_verdicts``: S8 (ADR-248), ``{cid: {form: diagnostic}}`` for the types whose body
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
                # The form (S8, ADR-248): a type decoder of the same form raises this same diagnostic.
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

    def memory_rejection(self, refs, storages, operation_of, cids=()):
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
            return (*where, memory_diagnostic(site, payload, operation, refs, storages, lambda word: self._out[word], cids))
        except (IndexError, KeyError, ValueError):  # a value the host cannot render (an unindexed type): the bootstrap decides
            return None

    def terminator_rejection(self, nodes: int, block: int) -> tuple[int, int, int]:
        """After an accepted ``check``: S8 (ADR-248), block ``block``'s terminator record ``(site, edge, condition type)``
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
    import xax_native

    return xax_native.usable("typing", STORE_PATH, "XAX_TYPING_PYTHON")
