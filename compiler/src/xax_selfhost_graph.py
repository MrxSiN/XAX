"""Self-hosting step S3c (ADR-120): graph-body syntax as XAX semantics.

A ``GRAPH_FRAGMENT`` body is the largest typed body the verifier parses.  One
XAX function decodes its byte-level structure and emits a word stream:

    decode(body: ptr<b8,READ,space 2>, heap_view<BODY_EXTENT>, memory,
           out: ptr<b64,RW,space 2>, heap_view<OUT_EXTENT>, memory,
           length: bits<64>, reference_count: bits<64>) -> (the same view triples)

``out[0]`` is the status (0 accept, 1 reject, 2 defer) and ``out[1]`` the word
count; the stream from ``out[2]`` mirrors the body in order: block count and
entry; per block the parameter reference indices, then per node the
operation, a call-group member with its byte span, the entity reference
index (for entity operations), the operands, the result reference indices,
and the attributes (for attribute operations); then the terminator (edges,
values, or a trap payload's length and offset).

It checks everything the bootstrap parser checks *syntactically*: ULEB rules,
entry block in range, reference indices in range, value tags 0/1, terminator
kinds 1-4, trap payload bounds, and an exact end.  Values that could exceed
2^35 defer (the bootstrap reports them exactly).  ``_parse_graph`` then walks
the stream in body order, resolving and verifying each referenced type and
decoding trap payloads exactly where the bootstrap parser would, so a valid
body yields the identical parse and an invalid one the identical diagnostic.
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
    ATTRIBUTE_OPERATIONS,
    ENTITY_OPERATIONS,
    IntCompare,
    Kind,
    Operation,
    Permission,
    SemanticObject,
    StoreReader,
    bits_type,
    heap_view_type,
    pointer_type,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
import xax_selfhost_store as store

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_graph_decoder.xax"
BODY_EXTENT = 1 << 20
OUT_EXTENT = 1 << 24  # S6c: a stream word per body byte for the largest (1 MiB) bodies, with room to spare
OUT_WORDS = OUT_EXTENT // 8
ACCEPT, REJECT, DEFER = 0, 1, 2
# S8b.2 (ADR-185): the diagnostic record (64-bit words) after its cursor at DIAG_AT, below the stream's end; on reject
# out[1] is the stream prefix's end, so the caller can walk what precedes the rejection in body order.
DIAG_AT = OUT_WORDS - 4096
GRAPH_SITES = {
    **store.CURSOR_SITES,
    "ENTRY_BLOCK": ("XAX.STRUCT.ENTRY_BLOCK", "GRAPH-ENTRY", ("format", "block < {}", ("wide", 0, 1)), ("wide", 2, 3)),
    "REF_INDEX": ("XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", ("format", "< {}", ("int", 2)), ("wide", 0, 1)),
    "VALUE_TAG": ("XAX.STRUCT.VALUE_TAG", "GRAPH-VALUE-TAG", ("list", 0, 1), ("wide", 0, 1)),
    "TERMINATOR": ("XAX.STRUCT.TERMINATOR", "GRAPH-TERMINATOR-KIND", ("list", *(("terminator", kind) for kind in (1, 2, 3, 4))), ("wide", 0, 1)),
    "TRAILING": ("XAX.CANON.TRAILING_BYTES", "GRAPH-BODY", 0, ("int", 0)),
}

B1, B8, B64 = bits_type(1), bits_type(8), bits_type(64)
MEM = store.MEM
BODY_POINTER = pointer_type(B8, Permission.READ, 1, space=2)
OUT_POINTER = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
BODY_VIEW, OUT_VIEW = heap_view_type(BODY_EXTENT), heap_view_type(OUT_EXTENT)
STATE = (BODY_VIEW, MEM, OUT_VIEW, MEM)


class _GraphDecoder(store._SiteDiagnostics, store._Decoder):
    """The S3 construction helpers over a 64-bit output stream with a running cursor, and (S8b.2) the graph body's
    rejection sites: the graph's CID follows the body in the input, so the program renders its own entity."""

    SITES = GRAPH_SITES
    ENTITIES = (("graph", None, "hex"),)
    block_state = STATE

    def __init__(self) -> None:
        self.g = GraphBuilder()
        entry = self.g.block(BODY_POINTER, BODY_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM, B64, B64)
        self.data, data_view, data_mem, self.out, out_view, out_mem, self.length, self.references = entry.params
        self.cur = entry
        self.state = (data_view, data_mem, out_view, out_mem)
        self.defer_block = self.g.block(*STATE)
        self.diagnostic_block = self.g.block(*(B64,) * store.DIAGNOSTIC_ARGUMENTS, *STATE)

    def g_block(self, *types):
        return self.g.block(*types, *STATE)

    # The S3 helpers create blocks with the S3 state types; rebind them to this decoder's views.
    def check(self, condition, failure):
        following = self.g.block(*STATE)
        self.cur.cbr(condition, following, self.state, failure, self.state)
        self.cur, self.state = following, tuple(following.params)

    def loop_header(self, values):
        header = self.g.block(*(B64,) * len(values), *STATE)
        self.cur.br(header, *values, *self.state)
        self.cur, self.state = header, tuple(header.params[len(values):])
        return header, header.params[: len(values)]

    def branch_loop(self, header, condition):
        body, exit_block = self.g.block(*STATE), self.g.block(*STATE)
        self.cur.cbr(condition, body, self.state, exit_block, self.state)
        self.cur, self.state = body, tuple(body.params)
        return exit_block

    def store64(self, index, value):
        data_view, data_mem, out_view, out_mem = self.state
        offset = self.cur.op1(Operation.INT_TRUNCATE, (self.mul(index, 8),), bits_type(32))
        out_mem = self.cur.op1(Operation.CHECKED_STORE_BITS_LE, (self.out, offset, value, out_mem), MEM, attributes=(8, 1))
        self.state = (data_view, data_mem, out_view, out_mem)

    def load64(self, index):
        data_view, data_mem, out_view, out_mem = self.state
        offset = self.cur.op1(Operation.INT_TRUNCATE, (self.mul(index, 8),), bits_type(32))
        value, out_mem = self.cur.op(Operation.CHECKED_LOAD_BITS_LE, (self.out, offset, out_mem), (B64, MEM), attributes=(8, 1))
        self.state = (data_view, data_mem, out_view, out_mem)
        return value

    def ret(self):
        data_view, data_mem, out_view, out_mem = self.state
        self.cur.ret(self.data, data_view, data_mem, self.out, out_view, out_mem)
        self.cur = None

    # ``_SiteDiagnostics`` hooks: the record in 64-bit words after the cursor at DIAG_AT.
    def begin_record(self):
        self.store64(self.c(DIAG_AT), self.c(DIAG_AT + 1))

    def put(self, value):
        cursor = self.load64(self.c(DIAG_AT))
        self.store64(cursor, value if not isinstance(value, int) else self.c(value))
        self.store64(self.c(DIAG_AT), self.add(cursor, 1))

    def finish_reject(self, context):
        self.store64(self.c(1), context)
        self.store64(self.c(0), self.c(REJECT))
        self.ret()

    def emit(self, cursor, value):
        """out[cursor] = value; returns cursor + 1 (defers when the stream would overflow)."""
        self.check(self.cmp(IntCompare.ULT, cursor, DIAG_AT), self.defer_block)
        data_view, data_mem, out_view, out_mem = self.state
        offset = self.cur.op1(Operation.INT_TRUNCATE, (self.mul(cursor, 8),), bits_type(32))
        out_mem = self.cur.op1(Operation.CHECKED_STORE_BITS_LE, (self.out, offset, value, out_mem), MEM, attributes=(8, 1))
        self.state = (data_view, data_mem, out_view, out_mem)
        return self.add(cursor, 1)

    def read(self, position, cursor):
        """Decode one ULEB with its diagnostics (S8b.2): ``(low, high, big, position)``; nothing is emitted, so a
        check on the value comes before the value enters the stream."""
        return self.uleb_d(position, self.length, (0, self.length), cursor)

    def word(self, position, cursor):
        """Decode one ULEB, defer if it may exceed 2^35 (an accepted value too wide for the stream), emit it:
        (value, position, cursor)."""
        value, _high, big, position = self.read(position, cursor)
        self.check(self.cmp(IntCompare.EQ, big, 0), self.defer_block)
        return value, position, self.emit(cursor, value)

    def member_of(self, value, members) -> object:
        hit = self.c(0)
        for member in sorted(members):
            hit = self.op(Operation.BIT_OR, hit, self.flag(IntCompare.EQ, value, int(member)))
        return hit

    def counted(self, position, cursor, element):
        """A ULEB count followed by ``count`` elements; ``element(position, cursor)`` returns both.  A count too large
        for the body runs until an element fails, as the bootstrap's loop does."""
        count, _high, big, position = self.read(position, cursor)
        cursor = self.emit(cursor, count)
        header, (index, position, cursor) = self.loop_header((self.c(0), position, cursor))
        done = self.branch_loop(header, self.either(self.cmp(IntCompare.NE, big, 0), self.cmp(IntCompare.ULT, index, count)))
        next_position, next_cursor = element(position, cursor)
        self.back(header, (self.add(index, 1), next_position, next_cursor))
        self.enter(done)
        return position, cursor

    def reference(self, position, cursor):
        index, high, big, position = self.read(position, cursor)
        self.fail_unless(self.both(self.cmp(IntCompare.EQ, big, 0), self.cmp(IntCompare.ULT, index, self.references)), "REF_INDEX",
                         (0, self.length), (index, high, self.references), cursor)
        return position, self.emit(cursor, index)

    def value(self, position, cursor):
        tag, high, big, position = self.read(position, cursor)
        self.fail_unless(self.both(self.cmp(IntCompare.EQ, big, 0), self.cmp(IntCompare.ULE, tag, 1)), "VALUE_TAG", (0, self.length), (tag, high), cursor)
        cursor = self.emit(cursor, tag)
        _block, position, cursor = self.word(position, cursor)
        _index, position, cursor = self.word(position, cursor)
        node_value, plain = self.g.block(B64, B64, *STATE), self.g.block(B64, B64, *STATE)
        joined = self.g.block(B64, B64, *STATE)
        self.cur.cbr(self.cmp(IntCompare.EQ, tag, 1), node_value, (position, cursor, *self.state), plain, (position, cursor, *self.state))
        self.enter_with(node_value)
        position, cursor = node_value.params[:2]
        _result, position, cursor = self.word(position, cursor)
        self.cur.br(joined, position, cursor, *self.state)
        self.enter_with(plain)
        self.cur.br(joined, *plain.params[:2], *self.state)
        self.enter_with(joined)
        return joined.params[0], joined.params[1]

    def enter_with(self, block):
        self.cur, self.state = block, tuple(block.params[-4:])

    def guarded(self, condition, position, cursor, action):
        """``if condition: action(position, cursor)``; returns the joined (position, cursor)."""
        taken, skipped, joined = (self.g.block(B64, B64, *STATE) for _ in range(3))
        self.cur.cbr(condition, taken, (position, cursor, *self.state), skipped, (position, cursor, *self.state))
        self.enter_with(taken)
        new_position, new_cursor = action(*taken.params[:2])
        self.cur.br(joined, new_position, new_cursor, *self.state)
        self.enter_with(skipped)
        self.cur.br(joined, *skipped.params[:2], *self.state)
        self.enter_with(joined)
        return joined.params[0], joined.params[1]


def build_graph_decoder_program() -> tuple[StoreReader, SemanticObject]:
    d = _GraphDecoder()
    graph = (0, d.length)  # the CID follows the body
    position, cursor = d.c(0), d.c(2)
    block_count, count_high, count_big, position = d.read(position, cursor)
    entry, entry_high, _entry_big, position = d.read(position, cursor)
    nonzero = d.either(d.cmp(IntCompare.NE, block_count, 0), d.cmp(IntCompare.NE, count_high, 0))
    below = d.either(d.cmp(IntCompare.ULT, entry_high, count_high), d.both(d.cmp(IntCompare.EQ, entry_high, count_high), d.cmp(IntCompare.ULT, entry, block_count)))
    d.fail_unless(d.both(nonzero, below), "ENTRY_BLOCK", graph, (block_count, count_high, entry, entry_high), cursor)
    cursor = d.emit(d.emit(cursor, block_count), entry)

    def edge(position, cursor):
        _target, position, cursor = d.word(position, cursor)
        return d.counted(position, cursor, d.value)

    def node(position, cursor):
        operation, position, cursor = d.word(position, cursor)

        def member(position, cursor):
            start = position
            _value, position, cursor = d.word(position, cursor)
            cursor = d.emit(cursor, start)
            return position, d.emit(cursor, position)

        position, cursor = d.guarded(d.cmp(IntCompare.EQ, operation, int(Operation.CALL_GROUP_MEMBER)), position, cursor, member)
        position, cursor = d.guarded(d.cmp(IntCompare.NE, d.member_of(operation, ENTITY_OPERATIONS), 0), position, cursor, d.reference)
        position, cursor = d.counted(position, cursor, d.value)
        position, cursor = d.counted(position, cursor, d.reference)
        attribute = lambda position, cursor: d.word(position, cursor)[1:]
        attributes = lambda position, cursor: d.counted(position, cursor, attribute)
        return d.guarded(d.cmp(IntCompare.NE, d.member_of(operation, ATTRIBUTE_OPERATIONS), 0), position, cursor, attributes)

    def block(position, cursor):
        position, cursor = d.counted(position, cursor, d.reference)
        position, cursor = d.counted(position, cursor, node)
        kind, high, big, position = d.read(position, cursor)
        d.fail_unless(d.both(d.cmp(IntCompare.EQ, big, 0), d.cmp(IntCompare.UGE, kind, 1), d.cmp(IntCompare.ULE, kind, 4)), "TERMINATOR", graph,
                      (kind, high), cursor)
        cursor = d.emit(cursor, kind)
        position, cursor = d.guarded(d.cmp(IntCompare.EQ, kind, 1), position, cursor, edge)

        def conditional(position, cursor):
            position, cursor = d.value(position, cursor)
            position, cursor = edge(position, cursor)
            return edge(position, cursor)

        position, cursor = d.guarded(d.cmp(IntCompare.EQ, kind, 2), position, cursor, conditional)
        position, cursor = d.guarded(d.cmp(IntCompare.EQ, kind, 3), position, cursor, lambda p, c: d.counted(p, c, d.value))

        def trap(position, cursor):
            size, high, big, position = d.read(position, cursor)
            cursor = d.emit(cursor, size)
            end = d.take(position, (size, high, big), d.length, graph, context=cursor)  # the offset follows only in bounds
            return end, d.emit(cursor, position)

        return d.guarded(d.cmp(IntCompare.EQ, kind, 4), position, cursor, trap)

    header, (b, position, cursor) = d.loop_header((d.c(0), position, cursor))
    done = d.branch_loop(header, d.either(d.cmp(IntCompare.NE, count_big, 0), d.cmp(IntCompare.ULT, b, block_count)))
    next_position, next_cursor = block(position, cursor)
    d.back(header, (d.add(b, 1), next_position, next_cursor))
    d.enter(done)
    d.fail_unless(d.cmp(IntCompare.EQ, position, d.length), "TRAILING", graph, (d.op(Operation.SUB_WRAP, d.length, position),), cursor)
    d.emit(d.c(1), cursor)
    d.emit(d.c(0), d.c(ACCEPT))
    d.ret()
    d.write_diagnostics()
    d.enter(d.defer_block)
    d.store64(d.c(0), d.c(DEFER))
    d.ret()
    triples = (BODY_POINTER, BODY_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    function = d.g.function((*triples, B64, B64), triples)
    return program_store(function, x86_64_linux_exec_target(), tuple(d.g.objects.values())), function


def load_graph_decoder_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "graph-decoder")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_graph_decoder_store() -> bytes:
    """Regenerate with the bootstrap graph parser, never the decoder being replaced."""
    import xax_compiler

    building = xax_compiler._GRAPH_DECODER_BUILDING
    xax_compiler._GRAPH_DECODER_BUILDING = True
    try:
        reader, _function = build_graph_decoder_program()
        STORE_PATH.write_bytes(reader.data)
    finally:
        xax_compiler._GRAPH_DECODER_BUILDING = building
    return reader.data


class NativeGraphDecoder:
    def __init__(self) -> None:
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = host_image(*load_graph_decoder_program(), "graph-decoder")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + machine_code
        from xax_native import executable_mapping

        self._mapping, base = executable_mapping(code)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self.code_size = len(machine_code)
        self._body = (ctypes.c_uint64 * (BODY_EXTENT // 8))()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()
        self.capacity = BODY_EXTENT - 32  # the graph's CID follows the body

    def decode(self, body: bytes, reference_count: int):
        """``(status, words)``: the decoded stream on accept, else ``()``."""
        status, words, _diagnostic = self.decode_with_diagnostic(body, reference_count, bytes(32))
        return status, words if status == ACCEPT else ()

    def decode_with_diagnostic(self, body: bytes, reference_count: int, cid: bytes):
        """``(status, words, diagnostic)`` (S8b.2): on accept the stream; on reject the stream prefix that precedes the
        rejection in body order and the ``Diagnostic`` the program wrote on the graph ``cid``."""
        from xax_selfhost_diagnostics import decode_record

        with self._lock:
            ctypes.memmove(self._body, body, len(body))
            ctypes.memmove(ctypes.addressof(self._body) + len(body), cid, 32)
            slots = self._slots
            slots[0], slots[1], slots[2], slots[3] = ctypes.addressof(self._body), ctypes.addressof(self._out), len(body), reference_count
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            status = out[0]
            if status == ACCEPT:
                return status, out[2:out[1]], None
            if status == REJECT:
                return status, out[2:out[1]], decode_record(out[DIAG_AT + 1:out[DIAG_AT]])
            return status, (), None


def native_graph_decoder_usable() -> bool:
    import xax_native

    return xax_native.usable("graph-decoder", STORE_PATH, "XAX_GRAPH_PYTHON_DECODER")
