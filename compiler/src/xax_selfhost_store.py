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
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
import xax_selfhost_diagnostics as D

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_store_decoder.xax"
DATA_EXTENT = 1 << 22
OUT_EXTENT = 1 << 24
# Out words (32 bits): the header and record table, then the parsed index (S8a), then the diagnostic record.
# Per record: offset, length, CID offset, parsed flag, kind, reference count,
# references offset, body offset, body length.
HEADER_WORDS, RECORD_WORDS = 8, 9  # header: status + seven fields
INDEX_AT, INDEX_WORDS = 1 << 20, 10  # per index entry: CID offset, offset low/high, length low/high, as 64-bit pairs
DIAG_AT = 2 << 20  # the cursor, then the record: 64-bit words as (low, high) 32-bit pairs
MAX_RECORDS = (INDEX_AT - HEADER_WORDS) // RECORD_WORDS
ACCEPT, REJECT, DEFER, NEED_DIGEST = 0, 1, 2, 3
CID_BYTES = 32
MODE_NONE, MODE_HASH, MODE_VERIFY = 0, 1, 2  # no digest check; report the digest's end; the digest follows the data
# S8b.1 (ADR-184): the data is one record envelope; report the CID's hashed span, then decide with the CID after it.
MODE_OBJECT_HASH, MODE_OBJECT_VERIFY = 3, 4

# S8a (ADR-183): every container rejection of ``StoreReader``: code, rule, expected, actual (value forms: ``_SiteDiagnostics``).
MAX_KIND = 11  # Kind.CALL_CONTRACT
_AVAILABLE = ("format", "{} available bytes", ("wide", 0, 1))
# The sites every ``Cursor``-shaped decoder shares (ULEB rules and truncation).
CURSOR_SITES = {
    "ULEB_OVERFLOW": ("XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED", "at most 10 bytes", "more than 10 bytes"),
    "ULEB_UNTERMINATED": ("XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED", "terminating byte", "end of input"),
    "ULEB_NON_MINIMAL": ("XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL", ("minimal", 0), ("hex", 1, ("value", 2))),
    "TRUNCATED": ("XAX.CANON.TRUNCATED", "SER-BOUNDS", _AVAILABLE, ("int", 2)),
}
SITES = {
    **CURSOR_SITES,
    "TRUNCATED_RECORD": ("XAX.CANON.TRUNCATED", "SER-RECORD-LENGTH", _AVAILABLE, ("int", 2)),
    "TRUNCATED_INDEX": ("XAX.CANON.TRUNCATED", "SER-INDEX-LENGTH", _AVAILABLE, ("int", 2)),
    "MAGIC": ("XAX.CONTAINER.MAGIC", "SER-HEADER-MAGIC", MAGIC.hex(), ("hex", ("const", 0), len(MAGIC))),
    "MAJOR": ("XAX.CONTAINER.MAJOR", "SER-MAJOR-SUPPORTED", CONTAINER_MAJOR, ("wide", 0, 1)),
    "HASH_SUITE": ("XAX.CONTAINER.HASH_SUITE", "SER-HASH-SUPPORTED", HASH_SUITE, ("wide", 0, 1)),
    "FEATURE": ("XAX.CONTAINER.FEATURE", "SER-FEATURE-SUPPORTED", 0, ("wide", 0, 1)),
    "RECORD_SHORT": ("XAX.CANON.RECORD_SHORT", "SER-RECORD-ENVELOPE", CID_BYTES, ("int", 0)),
    "RECORD_ORDER": ("XAX.CANON.RECORD_ORDER", "SER-RECORDS-SORTED-UNIQUE", ("format", "> {}", ("hex", 0, CID_BYTES)), ("hex", 1, CID_BYTES)),
    "TRAILING_NONSEMANTIC": ("XAX.CANON.TRAILING_BYTES", "SER-NONSEMANTIC-LENGTH", 0, ("int", 0)),
    "TRAILING_STORE": ("XAX.CANON.TRAILING_BYTES", "SER-STORE-LENGTH", 0, ("int", 0)),
    "TRAILING_INDEX": ("XAX.CANON.TRAILING_BYTES", "SER-INDEX-COUNT", 0, ("int", 0)),
    "NONSEMANTIC_ORDER": ("XAX.CANON.NONSEMANTIC_ORDER", "SER-NONSEMANTIC-SORTED-UNIQUE", "strict canonical byte order", ("hex", 0, ("value", 1))),
    "TRAILER": ("XAX.CONTAINER.TRAILER", "SER-TRAILER-MAGIC", TRAILER_MAGIC.hex(), ("hex", 0, len(TRAILER_MAGIC))),
    "STORE_DIGEST": ("XAX.INTEGRITY.STORE_DIGEST", "SER-STORE-DIGEST", ("hex", 0, CID_BYTES), ("hex", 1, CID_BYTES)),
    "INDEX": ("XAX.CANON.INDEX", "SER-INDEX-MATCHES-RECORDS", ("index", "records"), ("index", "index")),
    "ROOT_MISSING": ("XAX.IDENTITY.ROOT_MISSING", "ID-ROOT-PRESENT", ("hex", 0, CID_BYTES), "missing"),
    # S8b.1: ``decode_object``.
    "KIND": ("XAX.SCHEMA.KIND", "SER-KIND-SUPPORTED", ("list", *(("kind", value) for value in range(1, MAX_KIND + 1))), ("wide", 0, 1)),
    "VERSION": ("XAX.SCHEMA.VERSION", "SER-SCHEMA-SUPPORTED", 1, ("wide", 0, 1)),
    "REFERENCE_TABLE": ("XAX.CANON.REFERENCE_TABLE", "SER-REFS-SORTED-UNIQUE", "strict unsigned lexicographic order", ("references",)),
    "TRAILING_OBJECT": ("XAX.CANON.TRAILING_BYTES", "SER-OBJECT-BODY-LENGTH", 0, ("int", 0)),
    "CID_MISMATCH": ("XAX.IDENTITY.CID_MISMATCH", "ID-CID-INTEGRITY", ("hex", 0, CID_BYTES), ("hex", 1, CID_BYTES)),
}
# (name, template, fill): fill None is the name itself, "int" the template over the number, "cid" the template over the
# 32 bytes at that offset as hex, "hex" those bytes as hex alone
ENTITIES = (("store", None, None), ("index", None, None), ("record", "record:{}", "int"), ("metadata", "metadata:{}", "int"),
            ("object", "object:{}", "cid"))
ENTITY_STORE, ENTITY_INDEX = (0, 0), (1, 0)
DIAGNOSTIC_ARGUMENTS = 8  # site, entity kind, entity number, v0..v3, context

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


class _SiteDiagnostics:
    """Rejection sites with exact diagnostics for a decoder program (S8a, S8b; ADR-183, ADR-184, ADR-185).

    A decoder supplies ``SITES`` (name -> code, rule, expected form, actual form), ``ENTITIES`` (kind -> name,
    template, fill), ``block_state`` (the types its views thread through every block), ``diagnostic_block`` (a block
    taking ``DIAGNOSTIC_ARGUMENTS`` words then ``block_state``), ``put(word)`` (append one 64-bit record word), and
    ``finish_reject(context)`` (set the status and return).  A failing check branches, with its values, to the one
    shared diagnostic block, which writes each site's text once.

    A value form is a text, an integer constant, or a tuple: ("int", i), ("wide", low, high), ("hex", start, length)
    with start a value index or ("const", n) and length a constant or ("value", i), ("format", template, *forms),
    ("list", *forms), ("terminator", n), ("kind", n), ("minimal", i) (the minimal ULEB of value i); anything else is
    passed to ``d_custom``.  Values are v0..v3 of the failing check."""

    # -- conditions --------------------------------------------------------------------------------
    def both(self, *conditions):
        result = self.cur.op1(Operation.INT_ZERO_EXTEND, (conditions[0],), B64)
        for condition in conditions[1:]:
            result = self.op(Operation.BIT_AND, result, self.cur.op1(Operation.INT_ZERO_EXTEND, (condition,), B64))
        return self.cmp(IntCompare.NE, result, 0)

    def either(self, *conditions):
        result = self.cur.op1(Operation.INT_ZERO_EXTEND, (conditions[0],), B64)
        for condition in conditions[1:]:
            result = self.op(Operation.BIT_OR, result, self.cur.op1(Operation.INT_ZERO_EXTEND, (condition,), B64))
        return self.cmp(IntCompare.NE, result, 0)

    def when(self, condition, body):
        """Run ``body`` (emitting into the current block) only when ``condition`` holds."""
        then, join = self.g.block(*self.block_state), self.g.block(*self.block_state)
        self.cur.cbr(condition, then, self.state, join, self.state)
        self.cur, self.state = then, tuple(then.params)
        body()
        if self.cur is not None:
            self.cur.br(join, *self.state)
        self.cur, self.state = join, tuple(join.params)

    # -- record values ---------------------------------------------------------------------------
    def d_text(self, value: str):
        data = value.encode("ascii")
        self.put(D.T_STR)
        self.put(len(data))
        for start in range(0, len(data), 8):
            self.put(int.from_bytes(data[start:start + 8], "little"))

    def d_int(self, value):
        self.put(D.T_INT)
        self.put(value)

    def d_wide(self, low, high):
        self.put(D.T_WIDE)
        self.put(low)
        self.put(high)

    def d_hex(self, start, length):
        """HEX of data[start : start + length], packed eight bytes per word."""
        self.put(D.T_HEX)
        self.put(length)
        words = self.op(Operation.UDIV, self.add(length, 7), self.c(8))
        header, (w,) = self.loop_header((self.c(0),))
        done = self.branch_loop(header, self.cmp(IntCompare.ULT, w, words))
        word = self.c(0)
        for byte in range(8):
            at = self.add(self.mul(w, 8), byte)
            inside = self.flag(IntCompare.ULT, at, length)
            word = self.add(word, self.mul(self.mul(inside, self.load8(self.add(start, self.mul(inside, at)))), 1 << (8 * byte)))
        self.put(word)
        self.back(header, (self.add(w, 1),))
        self.enter(done)

    def d_hex_uleb(self, value):
        """HEX of the minimal ULEB of ``value`` (< 2**63, so at most nine bytes)."""
        groups = self.c(1)
        for k in range(1, 9):
            groups = self.add(groups, self.flag(IntCompare.UGE, value, 1 << (7 * k)))
        words = [self.c(0), self.c(0)]
        for k in range(9):
            low = self.op(Operation.BIT_AND, self.op(Operation.UDIV, value, self.c(1 << (7 * k))), self.c(0x7F))
            more = self.flag(IntCompare.UGE, value, 1 << (7 * (k + 1))) if k < 8 else self.c(0)
            words[k // 8] = self.add(words[k // 8], self.mul(self.add(low, self.mul(more, 0x80)), 1 << (8 * (k % 8))))
        self.put(D.T_HEX)
        self.put(groups)
        self.put(words[0])
        self.when(self.cmp(IntCompare.UGT, groups, 8), lambda: self.put(words[1]))

    def d_value(self, form, values):
        if isinstance(form, str):
            self.d_text(form)
        elif isinstance(form, int):
            self.d_int(self.c(form))
        else:
            kind, *arguments = form
            if kind == "int":
                self.d_int(values[arguments[0]])
            elif kind == "wide":
                self.d_wide(values[arguments[0]], values[arguments[1]])
            elif kind == "hex":
                start, length = arguments
                self.d_hex(self.c(start[1]) if isinstance(start, tuple) else values[start],
                           values[length[1]] if isinstance(length, tuple) else self.c(length))
            elif kind == "format":
                template, *forms = arguments
                self.put(D.T_FORMAT)
                self.d_text(template)
                self.put(len(forms))
                for item in forms:
                    self.d_value(item, values)
            elif kind == "list":
                self.put(D.T_LIST)
                self.put(len(arguments))
                for item in arguments:
                    self.d_value(item, values)
            elif kind in ("terminator", "kind"):
                self.put(D.T_TERMINATOR if kind == "terminator" else D.T_KIND)
                self.put(arguments[0])
            elif kind == "minimal":
                self.d_hex_uleb(values[arguments[0]])
            else:
                self.d_custom(form, values)

    # -- sites -------------------------------------------------------------------------------------
    def fail_unless(self, condition, site: str, entity=(0, 0), values=(), context=0):
        """Continue when ``condition`` holds, else write ``site``'s diagnostic on ``entity`` (an ``ENTITIES`` kind and
        its number) with ``values`` (v0..v3); ``context`` is handed to ``finish_reject``."""
        kind, number = entity
        names = list(self.SITES)
        arguments = [self.c(names.index(site)), self.c(kind), number if not isinstance(number, int) else self.c(number)]
        arguments += [value if not isinstance(value, int) else self.c(value) for value in values]
        arguments += [self.c(0)] * (DIAGNOSTIC_ARGUMENTS - 1 - len(arguments))
        arguments.append(context if not isinstance(context, int) else self.c(context))
        following = self.g.block(*self.block_state)
        self.cur.cbr(condition, following, self.state, self.diagnostic_block, (*arguments, *self.state))
        self.cur, self.state = following, tuple(following.params)

    def write_diagnostics(self):
        """The shared reject block: ``SITES[site]`` on the entity with values v0..v3."""
        self.cur = self.diagnostic_block
        site, kind, number, *values, context = self.diagnostic_block.params[:DIAGNOSTIC_ARGUMENTS]
        self.state = tuple(self.diagnostic_block.params[DIAGNOSTIC_ARGUMENTS:])
        self.begin_record()
        for index, (code, _rule, _expected, _actual) in enumerate(self.SITES.values()):
            self.when(self.cmp(IntCompare.EQ, site, index), lambda code=code: self.d_text(code))
        for index, (name, template, fill) in enumerate(self.ENTITIES):
            def entity(name=name, template=template, fill=fill):
                if fill is None:
                    self.d_text(name)
                elif fill == "hex":
                    self.d_hex(number, self.c(CID_BYTES))
                else:
                    self.d_value(("format", template, ("int", 0) if fill == "int" else ("hex", 0, CID_BYTES)), [number])  # "cid"
            self.when(self.cmp(IntCompare.EQ, kind, index), entity)
        for index, (_code, rule, expected, actual) in enumerate(self.SITES.values()):
            self.when(self.cmp(IntCompare.EQ, site, index), lambda rule=rule, expected=expected, actual=actual: (
                self.d_text(rule), self.d_value(expected, values), self.d_value(actual, values)))
        self.finish_reject(context)

    # -- the bootstrap ``Cursor`` with its diagnostics -------------------------------------------
    def uleb_d(self, position, limit, entity, context=0):
        """``Cursor.uleb`` with its diagnostics: ``(low 64 bits, high bits, big, next)``; ``big`` marks a value at or
        above 2**35.  A ULEB carries at most 70 bits, so the value is ``high * 2**64 + low``."""
        header, (pos, value, high, group, big) = self.loop_header((position, self.c(0), self.c(0), self.c(0), self.c(0)))
        self.fail_unless(self.cmp(IntCompare.ULT, group, 10), "ULEB_OVERFLOW", entity, context=context)
        self.fail_unless(self.cmp(IntCompare.ULT, pos, limit), "ULEB_UNTERMINATED", entity, context=context)
        byte = self.load8(pos)
        low = self.op(Operation.BIT_AND, byte, self.c(0x7F))
        scale = self.c(0)
        for index in range(10):
            scale = self.add(scale, self.mul(self.flag(IntCompare.EQ, group, index), (128 ** index) % (1 << 64)))
        value = self.add(value, self.mul(low, scale))  # wraps: the low 64 bits
        high = self.add(high, self.mul(self.flag(IntCompare.EQ, group, 9), self.op(Operation.UDIV, low, self.c(2))))
        upper = self.mul(self.flag(IntCompare.NE, low, 0), self.flag(IntCompare.UGE, group, 5))
        big = self.op(Operation.BIT_OR, big, upper)
        following = self.add(pos, 1)
        more = self.cmp(IntCompare.NE, self.op(Operation.BIT_AND, byte, self.c(0x80)), 0)
        again, done = self.g.block(*self.block_state), self.g.block(*self.block_state)
        self.cur.cbr(more, again, self.state, done, self.state)
        self.cur, self.state = again, tuple(again.params)
        self.back(header, (following, value, high, self.add(group, 1), big))
        self.cur, self.state = done, tuple(done.params)
        self.fail_unless(self.either(self.cmp(IntCompare.NE, byte, 0), self.cmp(IntCompare.EQ, group, 0)), "ULEB_NON_MINIMAL", entity,
                         (value, position, self.op(Operation.SUB_WRAP, following, position)), context)
        return value, high, big, following

    def take(self, position, count, limit, entity, site="TRUNCATED", context=0):
        """``Cursor.take(count, rule)`` on a cursor ending at ``limit``: the end; ``count`` is a value or a ``uleb_d``
        ``(low, high, big)``; ``site`` names the rule."""
        low, high, big = count if isinstance(count, tuple) else (count, self.c(0), self.c(0))
        end = self.add(position, low)
        self.fail_unless(self.both(self.cmp(IntCompare.EQ, big, 0), self.cmp(IntCompare.ULE, end, limit)), site, entity,
                         (low, high, self.op(Operation.SUB_WRAP, limit, position)), context)
        return end


class _ContainerDecoder(_SiteDiagnostics, _Decoder):
    """S8a (ADR-183): the container decoder with its rejections.  It adds a digest mode parameter and one shared
    diagnostic block; every check names its failure (a ``SITES`` entry through ``fail_unless``, or the defer block)."""

    SITES = SITES
    ENTITIES = ENTITIES
    block_state = STATE

    def __init__(self) -> None:
        self.g = GraphBuilder()
        entry = self.g.block(DATA_POINTER, DATA_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM, B64, B64)
        self.data, data_view, data_mem, self.out, out_view, out_mem, self.length, self.mode = entry.params
        self.cur = entry
        self.state = (data_view, data_mem, out_view, out_mem)
        self.defer_block = self.g.block(*STATE)
        self.diagnostic_block = self.g.block(*(B64,) * DIAGNOSTIC_ARGUMENTS, *STATE)

    def check(self, condition, failure):
        """Continue when ``condition`` holds, else go to ``failure`` (there is no anonymous reject here)."""
        super().check(condition, failure)

    def set_out64(self, index, value):
        self.set_out(index, value)
        self.set_out(self.add(index, 1), self.op(Operation.UDIV, value, self.c(1 << 32)))

    def out64(self, index):
        return self.add(self.out_word(index), self.mul(self.out_word(self.add(index, 1)), 1 << 32))

    def ret(self):
        data_view, data_mem, out_view, out_mem = self.state
        self.cur.ret(self.data, data_view, data_mem, self.out, out_view, out_mem)
        self.cur = None

    # The record in (low, high) 32-bit pairs after the cursor at DIAG_AT.
    def begin_record(self):
        self.set_out(self.c(DIAG_AT), self.c(DIAG_AT + 1))

    def put(self, value):
        cursor = self.out_word(self.c(DIAG_AT))
        self.set_out64(cursor, value if not isinstance(value, int) else self.c(value))
        self.set_out(self.c(DIAG_AT), self.add(cursor, 2))

    def finish_reject(self, _context):
        self.set_out(self.c(0), self.c(REJECT))
        self.ret()

    def d_custom(self, form, values):
        kind, *arguments = form
        if kind == "references":
            self.put(D.T_LIST)
            self.put(values[1])
            header, (r,) = self.loop_header((self.c(0),))
            done = self.branch_loop(header, self.cmp(IntCompare.ULT, r, values[1]))
            self.d_hex(self.add(values[0], self.mul(r, CID_BYTES)), self.c(CID_BYTES))
            self.back(header, (self.add(r, 1),))
            self.enter(done)
        else:
            self.index_lists(values[0], arguments[0])

    def index_lists(self, objects, table: str):
        """``XAX.CANON.INDEX`` values: the records (or the parsed index) as a list of (CID hex, offset, length);
        declines when both lists cannot fit the diagnostic region."""
        if table == "records":
            self.check(self.cmp(IntCompare.ULE, self.mul(objects, 64), (OUT_EXTENT // 4) - DIAG_AT - 1024), self.defer_block)
        self.put(D.T_LIST)
        self.put(objects)
        header, (k,) = self.loop_header((self.c(0),))
        done = self.branch_loop(header, self.cmp(IntCompare.ULT, k, objects))
        self.put(D.T_TUPLE)
        self.put(3)
        if table == "records":
            slot = self.add(self.mul(k, RECORD_WORDS), HEADER_WORDS)
            self.d_hex(self.out_word(self.add(slot, 2)), self.c(CID_BYTES))
            self.d_int(self.out_word(slot))
            self.d_int(self.out_word(self.add(slot, 1)))
        else:
            entry = self.add(self.mul(k, INDEX_WORDS), INDEX_AT)
            self.d_hex(self.out64(entry), self.c(CID_BYTES))
            self.d_wide(self.out64(self.add(entry, 2)), self.out64(self.add(entry, 4)))
            self.d_wide(self.out64(self.add(entry, 6)), self.out64(self.add(entry, 8)))
        self.back(header, (self.add(k, 1),))
        self.enter(done)


def _decode_object(d: _ContainerDecoder):
    """S8b.1 (ADR-184): ``decode_object`` on one record envelope (the data), in its order: the stored CID, kind,
    schema version, references (each in bounds, then strictly ascending), body, exact end; then the CID, which the
    caller computes with the XAX hash over the span this reports (MODE_OBJECT_HASH) and passes after the data
    (MODE_OBJECT_VERIFY).  On accept, out[1..6] = CID offset, kind, reference count, references offset, body offset,
    body length."""
    L = d.length
    _length, _high, _big, payload = d.uleb_d(d.c(0), L, ENTITY_STORE)  # the container checked the envelope's length
    obj = (4, payload)  # "object:<CID hex>"
    after_cid = d.take(payload, d.c(CID_BYTES), L, obj)
    kind, kind_hi, kind_big, pos = d.uleb_d(after_cid, L, obj)
    d.fail_unless(d.both(d.cmp(IntCompare.EQ, kind_big, 0), d.cmp(IntCompare.UGE, kind, 1), d.cmp(IntCompare.ULE, kind, MAX_KIND)), "KIND", obj,
                  (kind, kind_hi))
    version, version_hi, _version_big, pos = d.uleb_d(pos, L, obj)
    d.fail_unless(d.both(d.cmp(IntCompare.EQ, version, 1), d.cmp(IntCompare.EQ, version_hi, 0)), "VERSION", obj, (version, version_hi))
    count, _count_hi, count_big, references = d.uleb_d(pos, L, obj)
    header, (r, rpos, ascending) = d.loop_header((d.c(0), references, d.c(1)))
    done = d.branch_loop(header, d.either(d.cmp(IntCompare.NE, count_big, 0), d.cmp(IntCompare.ULT, r, count)))
    following = d.take(rpos, d.c(CID_BYTES), L, obj)
    first = d.flag(IntCompare.EQ, r, 0)
    previous = d.op(Operation.SUB_WRAP, rpos, d.mul(d.op(Operation.SUB_WRAP, d.c(1), first), CID_BYTES))
    less, _equal = d.compare(previous, d.c(CID_BYTES), rpos, d.c(CID_BYTES))
    in_order = d.op(Operation.BIT_OR, first, less)
    d.back(header, (d.add(r, 1), following, d.op(Operation.BIT_AND, ascending, in_order)))
    d.enter(done)
    d.fail_unless(d.cmp(IntCompare.NE, ascending, 0), "REFERENCE_TABLE", obj, (references, count))
    body_length, body_hi, body_big, body = d.uleb_d(rpos, L, obj)
    body_end = d.take(body, (body_length, body_hi, body_big), L, obj)
    d.fail_unless(d.cmp(IntCompare.EQ, body_end, L), "TRAILING_OBJECT", obj, (d.op(Operation.SUB_WRAP, L, body_end),))
    verify, need = d.g.block(*STATE), d.g.block(*STATE)
    d.cur.cbr(d.cmp(IntCompare.EQ, d.mode, MODE_OBJECT_VERIFY), verify, d.state, need, d.state)
    d.enter(need)
    d.set_out(d.c(0), d.c(NEED_DIGEST))
    d.set_out(d.c(1), after_cid)
    d.set_out(d.c(2), L)
    d.ret()
    d.enter(verify)
    _less, equal = d.compare(payload, d.c(CID_BYTES), L, d.c(CID_BYTES))  # the stored CID, then the computed one
    d.fail_unless(d.cmp(IntCompare.NE, equal, 0), "CID_MISMATCH", obj, (payload, L))
    for word, value in enumerate((d.c(ACCEPT), payload, kind, count, references, body, body_length)):
        d.set_out(d.c(word), value)
    d.ret()


def build_decoder_program() -> tuple[StoreReader, SemanticObject]:
    """S3/S3b, S8a (ADR-183), and S8b.1 (ADR-184): every container check ``StoreReader`` makes, in its order, with
    its diagnostic; in the object modes, every ``decode_object`` check."""
    d = _ContainerDecoder()
    L = d.length
    store, index = ENTITY_STORE, ENTITY_INDEX
    objects_mode, container = d.g.block(*STATE), d.g.block(*STATE)
    d.cur.cbr(d.cmp(IntCompare.UGE, d.mode, MODE_OBJECT_HASH), objects_mode, d.state, container, d.state)
    d.enter(objects_mode)
    _decode_object(d)
    d.enter(container)

    # Header.
    magic_end = d.take(d.c(0), d.c(len(MAGIC)), L, store)
    for position, byte in enumerate(MAGIC):
        d.fail_unless(d.cmp(IntCompare.EQ, d.load8(d.c(position)), byte), "MAGIC")
    major, major_hi, major_big, pos = d.uleb_d(magic_end, L, store)
    d.fail_unless(d.both(d.cmp(IntCompare.EQ, major, CONTAINER_MAJOR), d.cmp(IntCompare.EQ, major_hi, 0)), "MAJOR", store, (major, major_hi))
    minor, _minor_hi, minor_big, pos = d.uleb_d(pos, L, store)
    d.check(d.cmp(IntCompare.EQ, minor_big, 0), d.defer_block)  # an accepted minor this wide: out words are 32 bits
    d.check(d.cmp(IntCompare.ULT, minor, 1 << 32), d.defer_block)
    suite, suite_hi, _suite_big, pos = d.uleb_d(pos, L, store)
    d.fail_unless(d.both(d.cmp(IntCompare.EQ, suite, HASH_SUITE), d.cmp(IntCompare.EQ, suite_hi, 0)), "HASH_SUITE", store, (suite, suite_hi))
    root_at = pos
    pos = d.take(pos, d.c(CID_BYTES), L, store)
    objects, _objects_hi, objects_big, pos = d.uleb_d(pos, L, store)
    metadata_count, _metadata_hi, metadata_big, pos = d.uleb_d(pos, L, store)
    flags, flags_hi, _flags_big, pos = d.uleb_d(pos, L, store)
    d.fail_unless(d.both(d.cmp(IntCompare.EQ, flags, 0), d.cmp(IntCompare.EQ, flags_hi, 0)), "FEATURE", store, (flags, flags_hi))

    # Records: strictly ascending CIDs; note whether the root is present.
    header, (i, pos, previous, root_found) = d.loop_header((d.c(0), pos, d.c(0), d.c(0)))
    records_done = d.branch_loop(header, d.either(d.cmp(IntCompare.NE, objects_big, 0), d.cmp(IntCompare.ULT, i, objects)))
    d.check(d.cmp(IntCompare.ULT, i, MAX_RECORDS), d.defer_block)  # the record table is full
    offset = pos
    length, length_hi, length_big, payload = d.uleb_d(pos, L, store)
    end = d.take(payload, (length, length_hi, length_big), L, store, "TRUNCATED_RECORD")
    record = (2, i)
    d.fail_unless(d.cmp(IntCompare.UGE, length, CID_BYTES), "RECORD_SHORT", record, (length,))
    first = d.flag(IntCompare.EQ, i, 0)
    prior = d.add(d.mul(first, payload), d.mul(d.op(Operation.SUB_WRAP, d.c(1), first), previous))
    less, _equal = d.compare(prior, d.c(CID_BYTES), payload, d.c(CID_BYTES))
    d.fail_unless(d.cmp(IntCompare.NE, d.op(Operation.BIT_OR, first, less), 0), "RECORD_ORDER", record, (previous, payload))
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
    metadata_done = d.branch_loop(header, d.either(d.cmp(IntCompare.NE, metadata_big, 0), d.cmp(IntCompare.ULT, j, metadata_count)))
    metadata = (3, j)
    record_at = mpos
    content_length, content_hi, content_big, content = d.uleb_d(mpos, L, store)
    content_end = d.take(content, (content_length, content_hi, content_big), L, store)
    _schema, _schema_hi, _schema_big, body = d.uleb_d(content, content_end, metadata)
    body_length, body_hi, body_big, body_start = d.uleb_d(body, content_end, metadata)
    body_end = d.take(body_start, (body_length, body_hi, body_big), content_end, metadata)
    d.fail_unless(d.cmp(IntCompare.EQ, body_end, content_end), "TRAILING_NONSEMANTIC", metadata, (d.op(Operation.SUB_WRAP, content_end, body_end),))
    envelope_length = d.op(Operation.SUB_WRAP, content_end, record_at)
    first = d.flag(IntCompare.EQ, j, 0)
    less, _equal = d.compare(previous_at, previous_length, record_at, envelope_length)
    d.fail_unless(d.cmp(IntCompare.NE, d.op(Operation.BIT_OR, first, less), 0), "NONSEMANTIC_ORDER", metadata, (record_at, envelope_length))
    d.back(header, (d.add(j, 1), content_end, record_at, envelope_length))
    d.enter(metadata_done)
    metadata_end = mpos

    # Index bytes, digest, trailer, exact end.
    index_length, index_hi, index_big, index_start = d.uleb_d(metadata_end, L, store)
    index_end = d.take(index_start, (index_length, index_hi, index_big), L, store, "TRUNCATED_INDEX")
    trailer = d.take(index_end, d.c(CID_BYTES), L, store)
    trailer_end = d.take(trailer, d.c(len(TRAILER_MAGIC)), L, store)
    last = d.op(Operation.SUB_WRAP, L, d.c(len(TRAILER_MAGIC)))
    for position, byte in enumerate(TRAILER_MAGIC):
        d.fail_unless(d.cmp(IntCompare.EQ, d.load8(d.add(trailer, position)), byte), "TRAILER", store, (last,))
    d.fail_unless(d.cmp(IntCompare.EQ, trailer_end, L), "TRAILING_STORE", store, (d.op(Operation.SUB_WRAP, L, trailer_end),))

    # The digest (the caller hashes data[:index_end] with the XAX hash and calls again with it after the data).
    def digest_pass():
        verify, other, need, done = (d.g.block(*STATE) for _ in range(4))
        d.cur.cbr(d.cmp(IntCompare.EQ, d.mode, MODE_VERIFY), verify, d.state, other, d.state)
        d.enter(other)
        d.cur.cbr(d.cmp(IntCompare.EQ, d.mode, MODE_HASH), need, d.state, done, d.state)
        d.enter(need)
        d.set_out(d.c(0), d.c(NEED_DIGEST))
        d.set_out(d.c(1), index_end)
        d.ret()
        d.enter(verify)
        _less, equal = d.compare(index_end, d.c(CID_BYTES), L, d.c(CID_BYTES))  # the stored digest, then the computed one
        d.fail_unless(d.cmp(IntCompare.NE, equal, 0), "STORE_DIGEST", store, (index_end, L))
        d.cur.br(done, *d.state)
        d.enter(done)

    digest_pass()

    # The index: every (CID, offset, length), then exactly its end, then equal to the records.
    header, (k, ipos) = d.loop_header((d.c(0), index_start))
    index_done = d.branch_loop(header, d.cmp(IntCompare.ULT, k, objects))
    after_cid = d.take(ipos, d.c(CID_BYTES), index_end, index)
    indexed_offset, offset_hi, _offset_big, after_offset = d.uleb_d(after_cid, index_end, index)
    indexed_length, length_hi, _length_big, after_length = d.uleb_d(after_offset, index_end, index)
    entry = d.add(d.mul(k, INDEX_WORDS), INDEX_AT)
    for word, value in enumerate((ipos, indexed_offset, offset_hi, indexed_length, length_hi)):
        d.set_out64(d.add(entry, 2 * word), value)
    d.back(header, (d.add(k, 1), after_length))
    d.enter(index_done)
    d.fail_unless(d.cmp(IntCompare.EQ, ipos, index_end), "TRAILING_INDEX", index, (d.op(Operation.SUB_WRAP, index_end, ipos),))
    header, (k,) = d.loop_header((d.c(0),))
    compared = d.branch_loop(header, d.cmp(IntCompare.ULT, k, objects))
    slot, entry = d.add(d.mul(k, RECORD_WORDS), HEADER_WORDS), d.add(d.mul(k, INDEX_WORDS), INDEX_AT)
    _less, same_cid = d.compare(d.out64(entry), d.c(CID_BYTES), d.out_word(d.add(slot, 2)), d.c(CID_BYTES))
    same = d.both(d.cmp(IntCompare.NE, same_cid, 0), d.cmp(IntCompare.EQ, d.out64(d.add(entry, 2)), d.out_word(slot)),
                  d.cmp(IntCompare.EQ, d.out64(d.add(entry, 4)), 0), d.cmp(IntCompare.EQ, d.out64(d.add(entry, 6)), d.out_word(d.add(slot, 1))),
                  d.cmp(IntCompare.EQ, d.out64(d.add(entry, 8)), 0))
    d.fail_unless(same, "INDEX", index, (objects,))
    d.back(header, (d.add(k, 1),))
    d.enter(compared)
    d.fail_unless(d.cmp(IntCompare.NE, root_found, 0), "ROOT_MISSING", store, (root_at,))

    for word, value in enumerate((d.c(ACCEPT), minor, objects, metadata_count, metadata_start, metadata_end, index_end, root_at)):
        d.set_out(d.c(word), value)
    d.ret()
    d.write_diagnostics()
    d.enter(d.defer_block)
    d.set_out(d.c(0), d.c(DEFER))
    d.ret()

    triples = (DATA_POINTER, DATA_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
    function = d.g.function((*triples, B64, B64), triples)
    return program_store(function, x86_64_linux_exec_target(), tuple(d.g.objects.values())), function


def load_decoder_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "store-decoder")
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
        from xax_native import executable_mapping, zeroed_array

        self._mapping, base = executable_mapping(code)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self.code_size = len(machine_code)
        self._data = zeroed_array(ctypes.c_uint32, DATA_EXTENT // 4)
        self._out = zeroed_array(ctypes.c_uint32, OUT_EXTENT // 4)
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()
        self.capacity = DATA_EXTENT - CID_BYTES  # the digest is passed after the data

    def _run(self, length: int, mode: int):
        slots = self._slots
        slots[0], slots[1], slots[2], slots[3] = ctypes.addressof(self._data), ctypes.addressof(self._out), length, mode
        self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
        return self._out[0]

    def decode(self, data: bytes, verify_digest: bool = True, digest=None):
        """``(status, header words, records, diagnostic)``; each record is the nine words described at RECORD_WORDS.

        S8a: a rejection carries the ``Diagnostic`` the program wrote.  With ``verify_digest`` the program first
        reports where the digest ends; ``digest(prefix)`` (the XAX hash) hashes that prefix, and the program runs
        again with the digest after the data and decides the comparison itself."""
        from xax_selfhost_diagnostics import decode_record

        with self._lock:
            ctypes.memmove(self._data, data, len(data))
            status = self._run(len(data), MODE_HASH if verify_digest else MODE_NONE)
            if status == NEED_DIGEST:
                prefix = bytes(data[:self._out[1]])
                ctypes.memmove(ctypes.addressof(self._data) + len(data), digest(prefix), CID_BYTES)
                status = self._run(len(data), MODE_VERIFY)
            out = self._out
            if status == REJECT:
                end = out[DIAG_AT]
                pairs = out[DIAG_AT + 1:end]
                return status, (), (), decode_record([pairs[k] | pairs[k + 1] << 32 for k in range(0, len(pairs), 2)])
            if status != ACCEPT:
                return status, (), (), None
            header = tuple(out[1:HEADER_WORDS])
            count = header[1]
            flat = out[HEADER_WORDS:HEADER_WORDS + RECORD_WORDS * count]
            return status, header, tuple(tuple(flat[index:index + RECORD_WORDS]) for index in range(0, len(flat), RECORD_WORDS)), None

    def decode_object(self, envelope: bytes, cid_of):
        """``(fields or None, diagnostic or None)`` for one record envelope (S8b.1): fields are (CID offset, kind,
        reference count, references offset, body offset, body length) within ``envelope``; ``cid_of(span)`` is the XAX
        hash of the domain and the span."""
        from xax_selfhost_diagnostics import decode_record

        with self._lock:
            ctypes.memmove(self._data, envelope, len(envelope))
            status = self._run(len(envelope), MODE_OBJECT_HASH)
            if status == NEED_DIGEST:
                start, end = self._out[1], self._out[2]
                ctypes.memmove(ctypes.addressof(self._data) + len(envelope), cid_of(bytes(envelope[start:end])), CID_BYTES)
                status = self._run(len(envelope), MODE_OBJECT_VERIFY)
            out = self._out
            if status == REJECT:
                pairs = out[DIAG_AT + 1:out[DIAG_AT]]
                return None, decode_record([pairs[k] | pairs[k + 1] << 32 for k in range(0, len(pairs), 2)])
            if status != ACCEPT:
                return None, None
            return tuple(out[1:7]), None


def native_decoder_usable() -> bool:
    import xax_native

    return xax_native.usable("store-decoder", STORE_PATH, "XAX_STORE_PYTHON_DECODER")
