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
    verify_store,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
import xax_selfhost_store as store

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_graph_decoder.xax"
BODY_EXTENT = 1 << 20
OUT_EXTENT = 1 << 22
OUT_WORDS = OUT_EXTENT // 8
ACCEPT, REJECT, DEFER = 0, 1, 2

B1, B8, B64 = bits_type(1), bits_type(8), bits_type(64)
MEM = store.MEM
BODY_POINTER = pointer_type(B8, Permission.READ, 1, space=2)
OUT_POINTER = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
BODY_VIEW, OUT_VIEW = heap_view_type(BODY_EXTENT), heap_view_type(OUT_EXTENT)
STATE = (BODY_VIEW, MEM, OUT_VIEW, MEM)


class _GraphDecoder(store._Decoder):
    """The S3 construction helpers over a 64-bit output stream with a running cursor."""

    def __init__(self) -> None:
        self.g = GraphBuilder()
        entry = self.g.block(BODY_POINTER, BODY_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM, B64, B64)
        self.data, data_view, data_mem, self.out, out_view, out_mem, self.length, self.references = entry.params
        self.cur = entry
        self.state = (data_view, data_mem, out_view, out_mem)
        self.reject_block = self.g.block(*STATE)
        self.defer_block = self.g.block(*STATE)

    def g_block(self, *types):
        return self.g.block(*types, *STATE)

    # The S3 helpers create blocks with the S3 state types; rebind them to this decoder's views.
    def check(self, condition, failure=None):
        following = self.g.block(*STATE)
        self.cur.cbr(condition, following, self.state, failure or self.reject_block, self.state)
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

    def uleb(self, position, limit=None, failure=None):
        limit = limit if limit is not None else self.length
        header, (pos, value, group, big) = self.loop_header((position, self.c(0), self.c(0), self.c(0)))
        self.check(self.cmp(IntCompare.ULT, group, 10), failure)
        self.check(self.cmp(IntCompare.ULT, pos, limit), failure)
        byte = self.load8(pos)
        low = self.op(Operation.BIT_AND, byte, self.c(0x7F))
        scale = self.c(0)
        for index in range(5):
            scale = self.add(scale, self.mul(self.flag(IntCompare.EQ, group, index), 128 ** index))
        value = self.add(value, self.mul(low, scale))
        big = self.op(Operation.BIT_OR, big, self.mul(self.flag(IntCompare.NE, low, 0), self.flag(IntCompare.UGE, group, 5)))
        following = self.add(pos, 1)
        more = self.cmp(IntCompare.NE, self.op(Operation.BIT_AND, byte, self.c(0x80)), 0)
        again, done = self.g.block(*STATE), self.g.block(*STATE)
        self.cur.cbr(more, again, self.state, done, self.state)
        self.enter(again)
        self.back(header, (following, value, self.add(group, 1), big))
        self.enter(done)
        self.check(self.cmp(IntCompare.NE, self.op(Operation.BIT_OR, self.flag(IntCompare.NE, byte, 0), self.flag(IntCompare.EQ, group, 0)), 0), failure)
        return value, big, following

    def emit(self, cursor, value):
        """out[cursor] = value; returns cursor + 1 (defers when the stream would overflow)."""
        self.check(self.cmp(IntCompare.ULT, cursor, OUT_WORDS), self.defer_block)
        data_view, data_mem, out_view, out_mem = self.state
        offset = self.cur.op1(Operation.INT_TRUNCATE, (self.mul(cursor, 8),), bits_type(32))
        out_mem = self.cur.op1(Operation.CHECKED_STORE_BITS_LE, (self.out, offset, value, out_mem), MEM, attributes=(8, 1))
        self.state = (data_view, data_mem, out_view, out_mem)
        return self.add(cursor, 1)

    def word(self, position, cursor):
        """Decode one ULEB, defer if it may exceed 2^35, emit it: (value, position, cursor)."""
        value, big, position = self.uleb(position)
        self.check(self.cmp(IntCompare.EQ, big, 0), self.defer_block)
        return value, position, self.emit(cursor, value)

    def member_of(self, value, members) -> object:
        hit = self.c(0)
        for member in sorted(members):
            hit = self.op(Operation.BIT_OR, hit, self.flag(IntCompare.EQ, value, int(member)))
        return hit

    def counted(self, position, cursor, element):
        """A ULEB count followed by ``count`` elements; ``element(position, cursor)`` returns both."""
        count, position, cursor = self.word(position, cursor)
        header, (index, position, cursor) = self.loop_header((self.c(0), position, cursor))
        done = self.branch_loop(header, self.cmp(IntCompare.ULT, index, count))
        next_position, next_cursor = element(position, cursor)
        self.back(header, (self.add(index, 1), next_position, next_cursor))
        self.enter(done)
        return position, cursor

    def reference(self, position, cursor):
        index, position, cursor = self.word(position, cursor)
        self.check(self.cmp(IntCompare.ULT, index, self.references))
        return position, cursor

    def value(self, position, cursor):
        tag, position, cursor = self.word(position, cursor)
        self.check(self.cmp(IntCompare.ULE, tag, 1))
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
    position, cursor = d.c(0), d.c(2)
    block_count, position, cursor = d.word(position, cursor)
    entry, position, cursor = d.word(position, cursor)
    d.check(d.cmp(IntCompare.NE, block_count, 0))
    d.check(d.cmp(IntCompare.ULT, entry, block_count))

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
        kind, position, cursor = d.word(position, cursor)
        d.check(d.cmp(IntCompare.UGE, kind, 1))
        d.check(d.cmp(IntCompare.ULE, kind, 4))
        position, cursor = d.guarded(d.cmp(IntCompare.EQ, kind, 1), position, cursor, edge)

        def conditional(position, cursor):
            position, cursor = d.value(position, cursor)
            position, cursor = edge(position, cursor)
            return edge(position, cursor)

        position, cursor = d.guarded(d.cmp(IntCompare.EQ, kind, 2), position, cursor, conditional)
        position, cursor = d.guarded(d.cmp(IntCompare.EQ, kind, 3), position, cursor, lambda p, c: d.counted(p, c, d.value))

        def trap(position, cursor):
            size, position, cursor = d.word(position, cursor)
            cursor = d.emit(cursor, position)
            return d.need(position, size), cursor

        return d.guarded(d.cmp(IntCompare.EQ, kind, 4), position, cursor, trap)

    header, (b, position, cursor) = d.loop_header((d.c(0), position, cursor))
    done = d.branch_loop(header, d.cmp(IntCompare.ULT, b, block_count))
    next_position, next_cursor = block(position, cursor)
    d.back(header, (d.add(b, 1), next_position, next_cursor))
    d.enter(done)
    d.check(d.cmp(IntCompare.EQ, position, d.length))
    d.emit(d.c(1), cursor)
    d.emit(d.c(0), d.c(ACCEPT))
    view_b, mem_b, view_o, mem_o = d.state
    d.cur.ret(d.data, view_b, mem_b, d.out, view_o, mem_o)
    for failure, status in ((d.reject_block, REJECT), (d.defer_block, DEFER)):
        d.enter(failure)
        data_view, data_mem, out_view, out_mem = d.state
        out_mem = d.cur.op1(Operation.CHECKED_STORE_BITS_LE, (d.out, d.cur.const(bits_type(32), 0), d.c(status), out_mem), MEM, attributes=(8, 1))
        d.cur.ret(d.data, data_view, data_mem, d.out, out_view, out_mem)
    triples = (BODY_POINTER, BODY_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    function = d.g.function((*triples, B64, B64), triples)
    return program_store(function, x86_64_linux_exec_target(), tuple(d.g.objects.values())), function


def load_graph_decoder_program() -> tuple[StoreReader, SemanticObject]:
    reader = StoreReader(STORE_PATH.read_bytes())
    verify_store(reader)
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
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK, compile_native

        reader, function = load_graph_decoder_program()
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
        self._body = (ctypes.c_uint64 * (BODY_EXTENT // 8))()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()
        self.capacity = BODY_EXTENT

    def decode(self, body: bytes, reference_count: int):
        """``(status, words)``: the decoded stream on accept, else ``()``."""
        with self._lock:
            ctypes.memmove(self._body, body, len(body))
            slots = self._slots
            slots[0], slots[1], slots[2], slots[3] = ctypes.addressof(self._body), ctypes.addressof(self._out), len(body), reference_count
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            status = self._out[0]
            if status != ACCEPT:
                return status, ()
            return status, self._out[2:self._out[1]]


def native_graph_decoder_usable() -> bool:
    return (
        sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
        and os.environ.get("XAX_GRAPH_PYTHON_DECODER") != "1" and STORE_PATH.exists()
    )
