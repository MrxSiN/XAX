"""Self-hosting step S3 (ADR-118): the canonical store container decoder as XAX semantics.

``StoreReader`` validates the container before any object is decoded: header
(magic, major, hash suite, flags), record envelopes in strictly ascending CID
order, non-semantic records in strict canonical byte order, the index (which
must equal the records exactly), the trailer, and the root's presence.  S3
moves that accept/reject decision and the record index into one XAX function:

    decode(data: ptr<b8,READ,space 2>, heap_view<DATA_EXTENT>, memory,
           out: ptr<b32,RW,space 2>, heap_view<OUT_EXTENT>, memory,
           length: bits<64>) -> (the same two view triples)

It writes ``out[0]`` = status (0 accept, 1 reject, 2 defer).  On accept,
``out[1..7]`` = minor, object count, metadata count, metadata start, metadata
end, digest end, root CID offset, and ``out[8 + 3i ...]`` = (record offset, record length, CID
offset) for record *i*.  Every ULEB obeys the bootstrap rules exactly: at most
ten bytes, minimal, and terminated within its bound.  A value whose bits reach
2^35 can only be a length or count the data cannot satisfy, so it rejects;
the fields that may legally be that large (``minor`` and a metadata schema
id) defer to the bootstrap parser instead.

On reject or defer ``StoreReader`` runs the bootstrap parser, so diagnostics
stay byte-identical.  The container digest is checked with ``blake3()``,
which is itself the XAX hash (S2, ADR-117).
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
    CONTAINER_MAJOR,
    HASH_SUITE,
    MAGIC,
    TRAILER_MAGIC,
    IntCompare,
    Kind,
    Operation,
    Permission,
    SemanticObject,
    StoreReader,
    bits_type,
    heap_view_type,
    memory_effect_type,
    pointer_type,
    verify_store,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_store_decoder.xax"
DATA_EXTENT = 1 << 22
OUT_EXTENT = 1 << 21
# Per record: offset, length, CID offset, parsed flag, kind, reference count,
# references offset, body offset, body length.
HEADER_WORDS, RECORD_WORDS = 8, 9  # header: status + seven fields
MAX_RECORDS = (OUT_EXTENT // 4 - HEADER_WORDS) // RECORD_WORDS
ACCEPT, REJECT, DEFER = 0, 1, 2
CID_BYTES = 32
MAX_KIND = 11  # Kind.CALL_CONTRACT

B1, B8, B32, B64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)
MEM = memory_effect_type()
DATA_POINTER = pointer_type(B8, Permission.READ, 1, space=2)
OUT_POINTER = pointer_type(B32, Permission.READ_WRITE, 4, space=2)
DATA_VIEW, OUT_VIEW = heap_view_type(DATA_EXTENT), heap_view_type(OUT_EXTENT)
STATE = (DATA_VIEW, MEM, OUT_VIEW, MEM)


class _Decoder:
    """Structured construction: each step continues in ``cur``; the two views travel as
    (token, memory) pairs in ``state`` through every block (ADR-099)."""

    def __init__(self) -> None:
        self.g = GraphBuilder()
        entry = self.g.block(DATA_POINTER, DATA_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM, B64)
        self.data, data_view, data_mem, self.out, out_view, out_mem, self.length = entry.params
        self.cur = entry
        self.state = (data_view, data_mem, out_view, out_mem)
        self.reject_block = self.g.block(*STATE)
        self.defer_block = self.g.block(*STATE)

    # values in the current block
    def c(self, value: int):
        return self.cur.const(B64, value)

    def op(self, operation, x, y):
        return self.cur.op1(operation, (x, y), B64)

    def add(self, x, y):
        return self.op(Operation.ADD_WRAP, x, y if not isinstance(y, int) else self.c(y))

    def mul(self, x, y):
        return self.op(Operation.MUL_WRAP, x, y if not isinstance(y, int) else self.c(y))

    def cmp(self, kind, x, y):
        return self.cur.op1(Operation.INT_COMPARE, (x, y if not isinstance(y, int) else self.c(y)), B1, attributes=(kind,))

    def flag(self, kind, x, y):
        return self.cur.op1(Operation.INT_ZERO_EXTEND, (self.cmp(kind, x, y),), B64)

    def to32(self, x):
        return self.cur.op1(Operation.INT_TRUNCATE, (x,), B32)

    def load8(self, position):
        data_view, data_mem, out_view, out_mem = self.state
        byte, data_mem = self.cur.op(Operation.CHECKED_LOAD_BITS_LE, (self.data, self.to32(position), data_mem), (B8, MEM), attributes=(1, 1))
        self.state = (data_view, data_mem, out_view, out_mem)
        return self.cur.op1(Operation.INT_ZERO_EXTEND, (byte,), B64)

    def out_word(self, index):
        data_view, data_mem, out_view, out_mem = self.state
        word, out_mem = self.cur.op(Operation.CHECKED_LOAD_BITS_LE, (self.out, self.to32(self.mul(index, 4)), out_mem), (B32, MEM), attributes=(4, 1))
        self.state = (data_view, data_mem, out_view, out_mem)
        return self.cur.op1(Operation.INT_ZERO_EXTEND, (word,), B64)

    def set_out(self, index, value):
        data_view, data_mem, out_view, out_mem = self.state
        out_mem = self.cur.op1(Operation.CHECKED_STORE_BITS_LE, (self.out, self.to32(self.mul(index, 4)), self.to32(value), out_mem), MEM, attributes=(4, 1))
        self.state = (data_view, data_mem, out_view, out_mem)

    # control
    def check(self, condition, failure=None):
        """Continue when ``condition`` holds, else go to reject (or ``failure``)."""
        following = self.g.block(*STATE)
        self.cur.cbr(condition, following, self.state, failure or self.reject_block, self.state)
        self.cur, self.state = following, tuple(following.params)

    def need(self, position, count, limit=None, failure=None):
        """``position + count <= limit`` (the bootstrap ``take`` bound); returns the end."""
        end = self.add(position, count)
        self.check(self.cmp(IntCompare.ULE, end, limit if limit is not None else self.length), failure)
        return end

    def loop_header(self, values):
        header = self.g.block(*(B64,) * len(values), *STATE)
        self.cur.br(header, *values, *self.state)
        self.cur, self.state = header, tuple(header.params[len(values):])
        return header, header.params[: len(values)]

    def branch_loop(self, header, condition):
        """In ``header``: continue into a body block while ``condition``; returns the exit block."""
        body, exit_block = self.g.block(*STATE), self.g.block(*STATE)
        self.cur.cbr(condition, body, self.state, exit_block, self.state)
        self.cur, self.state = body, tuple(body.params)
        return exit_block

    def back(self, header, values):
        self.cur.br(header, *values, *self.state)

    def enter(self, block):
        self.cur, self.state = block, tuple(block.params)

    def uleb(self, position, limit=None, failure=None):
        """Bootstrap ULEB: returns (value, big, next).  Unterminated, longer than ten
        bytes, and non-minimal encodings go to ``failure`` (default reject); ``big``
        marks bits at or above 2^35."""
        limit = limit if limit is not None else self.length
        header, (pos, value, group, big) = self.loop_header((position, self.c(0), self.c(0), self.c(0)))
        self.check(self.cmp(IntCompare.ULT, group, 10), failure)
        self.check(self.cmp(IntCompare.ULT, pos, limit), failure)
        byte = self.load8(pos)
        low = self.op(Operation.BIT_AND, byte, self.c(0x7F))
        scale = self.c(0)
        for index in range(5):
            scale = self.add(scale, self.mul(self.flag(IntCompare.EQ, group, index), 128 ** index))
        value = self.add(value, self.mul(low, scale))  # scale is 0 from group 5 on
        upper = self.mul(self.flag(IntCompare.NE, low, 0), self.flag(IntCompare.UGE, group, 5))
        big = self.op(Operation.BIT_OR, big, upper)
        following = self.add(pos, 1)
        more = self.cmp(IntCompare.NE, self.op(Operation.BIT_AND, byte, self.c(0x80)), 0)
        again, done = self.g.block(*STATE), self.g.block(*STATE)
        self.cur.cbr(more, again, self.state, done, self.state)
        self.enter(again)
        self.back(header, (following, value, self.add(group, 1), big))
        self.enter(done)
        # A final zero group is allowed only as the single byte 00.
        self.check(self.cmp(IntCompare.NE, self.op(Operation.BIT_OR, self.flag(IntCompare.NE, byte, 0), self.flag(IntCompare.EQ, group, 0)), 0), failure)
        return value, big, following

    def small_uleb(self, position, limit=None, failure=None):
        value, big, following = self.uleb(position, limit, failure)
        self.check(self.cmp(IntCompare.EQ, big, 0), failure)
        return value, following

    def compare(self, a, a_length, b, b_length):
        """Lexicographic compare of data[a:a+a_length] and data[b:b+b_length]: (less, equal)."""
        shorter = self.flag(IntCompare.ULT, b_length, a_length)
        common = self.add(a_length, self.mul(shorter, self.op(Operation.SUB_WRAP, b_length, a_length)))
        header, (index,) = self.loop_header((self.c(0),))
        joined = self.g.block(B64, B64, *STATE)
        step, tail = self.g.block(*STATE), self.g.block(*STATE)
        self.cur.cbr(self.cmp(IntCompare.ULT, index, common), step, self.state, tail, self.state)
        self.enter(step)
        left, right = self.load8(self.add(a, index)), self.load8(self.add(b, index))
        same, differ = self.g.block(*STATE), self.g.block(*STATE)
        self.cur.cbr(self.cmp(IntCompare.EQ, left, right), same, self.state, differ, self.state)
        self.enter(same)
        self.back(header, (self.add(index, 1),))
        self.enter(differ)
        self.cur.br(joined, self.flag(IntCompare.ULT, left, right), self.c(0), *self.state)
        self.enter(tail)
        self.cur.br(joined, self.flag(IntCompare.ULT, a_length, b_length), self.flag(IntCompare.EQ, a_length, b_length), *self.state)
        self.cur, self.state = joined, tuple(joined.params[2:])
        return joined.params[0], joined.params[1]

    def expect_bytes(self, position, expected: bytes):
        self.need(position, len(expected))
        for index, byte in enumerate(expected):
            self.check(self.cmp(IntCompare.EQ, self.load8(self.add(position, index)), byte))
        return self.add(position, len(expected))


def build_decoder_program() -> tuple[StoreReader, SemanticObject]:
    d = _Decoder()
    pos = d.expect_bytes(d.c(0), MAGIC)
    major, pos = d.small_uleb(pos)
    d.check(d.cmp(IntCompare.EQ, major, CONTAINER_MAJOR))
    minor, minor_big, pos = d.uleb(pos)
    d.check(d.cmp(IntCompare.EQ, minor_big, 0), d.defer_block)
    d.check(d.cmp(IntCompare.ULT, minor, 1 << 32), d.defer_block)
    suite, pos = d.small_uleb(pos)
    d.check(d.cmp(IntCompare.EQ, suite, HASH_SUITE))
    root_at = pos
    pos = d.need(pos, CID_BYTES)
    objects, pos = d.small_uleb(pos)
    metadata_count, pos = d.small_uleb(pos)
    flags, pos = d.small_uleb(pos)
    d.check(d.cmp(IntCompare.EQ, flags, 0))
    d.check(d.cmp(IntCompare.ULE, objects, MAX_RECORDS), d.defer_block)

    # Records: strictly ascending CIDs; note whether the root is present.
    header, (i, pos, previous, root_found) = d.loop_header((d.c(0), pos, d.c(0), d.c(0)))
    records_done = d.branch_loop(header, d.cmp(IntCompare.ULT, i, objects))
    offset = pos
    length, payload = d.small_uleb(pos)
    end = d.need(payload, length)
    d.check(d.cmp(IntCompare.UGE, length, CID_BYTES))
    first = d.flag(IntCompare.EQ, i, 0)
    prior = d.add(d.mul(first, payload), d.mul(d.op(Operation.SUB_WRAP, d.c(1), first), previous))
    less, _equal = d.compare(prior, d.c(CID_BYTES), payload, d.c(CID_BYTES))
    d.check(d.cmp(IntCompare.NE, d.op(Operation.BIT_OR, first, less), 0))
    _less, is_root = d.compare(root_at, d.c(CID_BYTES), payload, d.c(CID_BYTES))
    slot = d.add(d.mul(i, RECORD_WORDS), HEADER_WORDS)
    d.set_out(slot, offset)
    d.set_out(d.add(slot, 1), length)
    d.set_out(d.add(slot, 2), payload)
    following = (d.add(i, 1), end, payload, d.op(Operation.BIT_OR, root_found, is_root))
    # S3b: parse the object envelope (kind, schema version, sorted references,
    # exact body).  A malformed object does not reject the store (objects decode
    # lazily); it is marked unparsed so ``get`` reports it with the bootstrap decoder.
    bad = d.g.block(*STATE)
    inner = d.add(payload, CID_BYTES)
    kind, inner = d.small_uleb(inner, end, bad)
    d.check(d.cmp(IntCompare.UGE, kind, 1), bad)
    d.check(d.cmp(IntCompare.ULE, kind, MAX_KIND), bad)
    version, inner = d.small_uleb(inner, end, bad)
    d.check(d.cmp(IntCompare.EQ, version, 1), bad)
    reference_count, references = d.small_uleb(inner, end, bad)
    references_end = d.need(references, d.mul(reference_count, CID_BYTES), end, bad)
    sorted_header, (r,) = d.loop_header((d.c(1),))
    sorted_done = d.branch_loop(sorted_header, d.cmp(IntCompare.ULT, r, reference_count))
    current = d.add(references, d.mul(r, CID_BYTES))
    less, _equal = d.compare(d.op(Operation.SUB_WRAP, current, d.c(CID_BYTES)), d.c(CID_BYTES), current, d.c(CID_BYTES))
    d.check(d.cmp(IntCompare.NE, less, 0), bad)
    d.back(sorted_header, (d.add(r, 1),))
    d.enter(sorted_done)
    body_length, body = d.small_uleb(references_end, end, bad)
    d.check(d.cmp(IntCompare.EQ, d.add(body, body_length), end), bad)
    for word, value in enumerate((d.c(1), kind, reference_count, references, body, body_length)):
        d.set_out(d.add(slot, 3 + word), value)
    d.back(header, following)
    d.enter(bad)
    d.set_out(d.add(slot, 3), d.c(0))
    d.back(header, following)
    d.enter(records_done)

    # Non-semantic records: (schema, byte string) exactly filling the envelope, in strict byte order.
    metadata_start = pos
    header, (j, mpos, previous_at, previous_length) = d.loop_header((d.c(0), pos, pos, d.c(0)))
    metadata_done = d.branch_loop(header, d.cmp(IntCompare.ULT, j, metadata_count))
    record_at = mpos
    content_length, content = d.small_uleb(mpos)
    content_end = d.need(content, content_length)
    _schema, schema_big, body = d.uleb(content, content_end)
    d.check(d.cmp(IntCompare.EQ, schema_big, 0), d.defer_block)
    body_length, body_start = d.small_uleb(body, content_end)
    d.check(d.cmp(IntCompare.EQ, d.add(body_start, body_length), content_end))
    envelope_length = d.op(Operation.SUB_WRAP, content_end, record_at)
    first = d.flag(IntCompare.EQ, j, 0)
    less, _equal = d.compare(previous_at, previous_length, record_at, envelope_length)
    d.check(d.cmp(IntCompare.NE, d.op(Operation.BIT_OR, first, less), 0))
    d.back(header, (d.add(j, 1), content_end, record_at, envelope_length))
    d.enter(metadata_done)
    metadata_end = mpos

    # Index: one (CID, offset, length) per record, equal to the records, filling it exactly.
    index_length, index_start = d.small_uleb(metadata_end)
    index_end = d.need(index_start, index_length)
    header, (k, ipos) = d.loop_header((d.c(0), index_start))
    index_done = d.branch_loop(header, d.cmp(IntCompare.ULT, k, objects))
    slot = d.add(d.mul(k, RECORD_WORDS), HEADER_WORDS)
    record_offset, record_length, record_cid = d.out_word(slot), d.out_word(d.add(slot, 1)), d.out_word(d.add(slot, 2))
    after_cid = d.need(ipos, CID_BYTES, index_end)
    _less, equal = d.compare(ipos, d.c(CID_BYTES), record_cid, d.c(CID_BYTES))
    d.check(d.cmp(IntCompare.NE, equal, 0))
    indexed_offset, after_offset = d.small_uleb(after_cid, index_end)
    indexed_length, after_length = d.small_uleb(after_offset, index_end)
    d.check(d.cmp(IntCompare.EQ, indexed_offset, record_offset))
    d.check(d.cmp(IntCompare.EQ, indexed_length, record_length))
    d.back(header, (d.add(k, 1), after_length))
    d.enter(index_done)
    d.check(d.cmp(IntCompare.EQ, ipos, index_end))

    # Digest (checked by the caller with the XAX hash), trailer, exact end, root present.
    trailer = d.need(index_end, CID_BYTES)
    d.expect_bytes(trailer, TRAILER_MAGIC)
    d.check(d.cmp(IntCompare.EQ, d.add(trailer, len(TRAILER_MAGIC)), d.length))
    d.check(d.cmp(IntCompare.NE, root_found, 0))
    for word, value in enumerate((d.c(ACCEPT), minor, objects, metadata_count, metadata_start, metadata_end, index_end, root_at)):
        d.set_out(d.c(word), value)
    data_view, data_mem, out_view, out_mem = d.state
    d.cur.ret(d.data, data_view, data_mem, d.out, out_view, out_mem)

    for block, status in ((d.reject_block, REJECT), (d.defer_block, DEFER)):
        d.enter(block)
        d.set_out(d.c(0), d.c(status))
        data_view, data_mem, out_view, out_mem = d.state
        d.cur.ret(d.data, data_view, data_mem, d.out, out_view, out_mem)

    triples = (DATA_POINTER, DATA_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    function = d.g.function((*triples, B64), triples)
    return program_store(function, x86_64_linux_exec_target(), tuple(d.g.objects.values())), function


def load_decoder_program() -> tuple[StoreReader, SemanticObject]:
    reader = StoreReader(STORE_PATH.read_bytes())
    verify_store(reader)
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_decoder_store() -> bytes:
    """Regenerate the committed store with the bootstrap parser, never the decoder being replaced."""
    import xax_compiler

    building = xax_compiler._DECODER_BUILDING
    xax_compiler._DECODER_BUILDING = True
    try:
        reader, _function = build_decoder_program()
    finally:
        xax_compiler._DECODER_BUILDING = building
    STORE_PATH.write_bytes(reader.data)
    return reader.data


class NativeDecoder:
    """The decoder lowered by the XAX x86-64 backend, called in-process with two lent buffers."""

    def __init__(self) -> None:
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = host_image(*load_decoder_program(), "store-decoder")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + machine_code
        self._mapping = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self._mapping.write(code)
        base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self.code_size = len(machine_code)
        self._data = (ctypes.c_uint32 * (DATA_EXTENT // 4))()
        self._out = (ctypes.c_uint32 * (OUT_EXTENT // 4))()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()
        self.capacity = DATA_EXTENT

    def decode(self, data: bytes):
        """``(status, header words, records)``; each record is the nine words described at RECORD_WORDS."""
        with self._lock:
            ctypes.memmove(self._data, data, len(data))
            slots = self._slots
            slots[0], slots[1], slots[2] = ctypes.addressof(self._data), ctypes.addressof(self._out), len(data)
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            status = out[0]
            if status != ACCEPT:
                return status, (), ()
            header = tuple(out[1:HEADER_WORDS])
            count = header[1]
            flat = out[HEADER_WORDS:HEADER_WORDS + RECORD_WORDS * count]
            return status, header, tuple(tuple(flat[index:index + RECORD_WORDS]) for index in range(0, len(flat), RECORD_WORDS))


def native_decoder_usable() -> bool:
    return (
        sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
        and os.environ.get("XAX_STORE_PYTHON_DECODER") != "1" and STORE_PATH.exists()
    )
