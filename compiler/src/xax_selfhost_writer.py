"""Self-hosting step S9 (ADR-262): canonical store writing as XAX semantics.

``write_store`` decides which objects form a canonical store and lays out its bytes: every object's schema
version, reference order, and CID (re-derived from its content, whatever the producer claimed), duplicate CIDs,
the root's presence, the canonical order and uniqueness of non-semantic records, and the container itself
(header, record envelopes in CID order, metadata envelopes, index, digest, trailer).  S9 moves all of it into one
XAX function:

    write(batch: ptr<b8,READ,space 2>, heap_view<IN_EXTENT>, memory,
          buf: ptr<b8,RW,space 2>, heap_view<BUF_EXTENT>, memory,
          scratch: ptr<b32,RW,space 2>, heap_view<SCRATCH_EXTENT>, memory,
          mode: bits<64>) -> (the same three view triples)

The batch is the host's marshal of the unordered inputs (``marshal``; little-endian 64-bit fields):

    object count, metadata count, batch length, root CID (32 bytes)
    per object: kind, schema version, reference count r, body length b, claimed CID (32), r references (32 each), body
    per record: schema id, payload length p, payload

The program hashes with the committed S2 hash graph instantiated over its own byte view (``hash_function(...,
based=True)``): each object's preimage (``XAX-SEM-1`` and the record payload after the CID) and the container
prefix are hashed in place, so no CID or digest comes from outside the program.  Objects are ordered by a stable
merge sort over their CIDs; records by their envelope bytes.  The status words at ``STATUS_AT`` are (status,
reason, object index, store length): ACCEPT with the store in ``buf[0 : length]`` (``MODE_CHECK`` validates only),
REJECT with one of ``REASONS``, or DECLINE when the batch or the store exceeds the program's capacity, and the
bootstrap writer decides.  Rejections follow the bootstrap's order: per object in input order a schema version
other than 1, then unsorted references, then a CID mismatch; a duplicate CID wins when it comes first in input
order; then a missing root; then a duplicate record.
"""

from __future__ import annotations

import ctypes
import threading
from pathlib import Path

from xax_compiler import (
    CID_SIZE,
    CONTAINER_MAJOR,
    HASH_SUITE,
    MAGIC,
    SEMANTIC_DOMAIN,
    TRAILER_MAGIC,
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
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_blake3 import DIGEST_OFFSET, MEM, SCRATCH_EXTENT, SCRATCH_POINTER, SCRATCH_VIEW, hash_function
from xax_selfhost_facts import E
from xax_structured import B64, Proc

STORE_PATH = bootstrap_dir() / "xax_store_writer.xax"
IN_EXTENT = 1 << 26  # S14b (ADR-285): the compiler's own snapshot store (17.7 MB) fits; ADR-319: 64 MiB (33 MB)
BUF_EXTENT = 1 << 27
# ``buf`` regions (byte offsets).  The store is written from 0; while objects are checked, a preimage is staged there.
OUT_LIMIT = 1 << 26
MAX_OBJECTS, MAX_RECORDS = 1 << 16, 1 << 12
OBJECTS_AT = OUT_LIMIT + 4096  # per object: (batch offset, payload length after the CID), 64-bit words
OBJECT_SORT_A = OBJECTS_AT + 16 * MAX_OBJECTS
OBJECT_SORT_B = OBJECT_SORT_A + 8 * MAX_OBJECTS
OFFSETS_AT = OBJECT_SORT_B + 8 * MAX_OBJECTS  # each emitted record's store offset, in CID order (for the index)
RECORDS_AT = OFFSETS_AT + 8 * MAX_OBJECTS  # per record: (envelope offset, envelope length)
RECORD_SORT_A = RECORDS_AT + 16 * MAX_RECORDS
RECORD_SORT_B = RECORD_SORT_A + 8 * MAX_RECORDS
ENVELOPES_AT = RECORD_SORT_B + 8 * MAX_RECORDS  # the records' canonical envelopes, in batch order
STATUS_AT = BUF_EXTENT - 64
ENVELOPES_LIMIT = STATUS_AT - 64
BATCH_HEADER = 24 + CID_SIZE
OBJECT_HEADER = 32 + CID_SIZE
RECORD_HEADER = 16
HASH_SLACK = 64  # the hash reads whole 64-byte blocks past a span's end (masked)

MODE_WRITE, MODE_CHECK = 0, 1
ACCEPT, REJECT, DECLINE, RUNNING = 0, 1, 2, 3
# The bootstrap writer's messages (``xax_compiler._store_contents``, ``encode_references``), by reason code.
REASONS = {
    1: "semantic object is not canonical",
    2: "reference table must be sorted and deduplicated",
    3: "duplicate semantic object CID",
    4: "root CID missing from store",
    5: "duplicate non-semantic record",
}
NOT_CANONICAL, REFERENCES_UNSORTED, DUPLICATE_OBJECT, ROOT_MISSING, DUPLICATE_RECORD = REASONS
ORDER_EQUAL, ORDER_GREATER, ORDER_LESS = 0, 1, 2

BATCH_POINTER = pointer_type(bits_type(8), Permission.READ, 1, space=2)
BUF_POINTER = pointer_type(bits_type(8), Permission.READ_WRITE, 1, space=2)
BATCH_VIEW, BUF_VIEW = heap_view_type(IN_EXTENT), heap_view_type(BUF_EXTENT)
VIEWS = (("ip", BATCH_POINTER), ("iv", BATCH_VIEW), ("im", MEM), ("bp", BUF_POINTER), ("bv", BUF_VIEW), ("bm", MEM),
         ("sp", SCRATCH_POINTER), ("sv", SCRATCH_VIEW), ("sm", MEM))
BATCH, BUF, SCRATCH = ("ip", "im"), ("bp", "bm"), ("sp", "sm")


class _W(E):
    """Arithmetic and structured control from the facts engine's helper, over the writer's three views."""

    def __init__(self, proc: Proc, hash_at: SemanticObject):
        super().__init__(proc, None)
        self.hash_at = hash_at
        self._names = 0

    def let(self, stem: str, value=0) -> str:
        """A fresh variable holding ``value``; its name."""
        self._names += 1
        name = f"{stem}_{self._names}"
        self.var(name, value)
        return name

    def __getitem__(self, name: str):
        return self.p[name]

    # -- memory: byte offsets; byte views read and write 1, 4, or 8 bytes as one little-endian integer -----------
    def _at(self, offset):
        return self.p.op1(Operation.INT_TRUNCATE, (self.v(offset),), bits_type(32))

    def load(self, view, offset, size: int = 1):
        p = self.p
        pointer, memory = view
        value, p[memory] = p.op(Operation.CHECKED_LOAD_BITS_LE, (p[pointer], self._at(offset), p[memory]), (bits_type(8 * size), MEM),
                                attributes=(size, 1))
        return value if size == 8 else p.op1(Operation.INT_ZERO_EXTEND, (value,), B64)

    def store(self, view, offset, value, size: int = 1):
        p = self.p
        pointer, memory = view
        value = self.v(value)
        if size != 8:
            value = p.op1(Operation.INT_TRUNCATE, (value,), bits_type(8 * size))
        p[memory] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p[pointer], self._at(offset), value, p[memory]), MEM, attributes=(size, 1))

    def word(self, view, offset):
        return self.load(view, offset, 8)

    def set_word(self, offset, value):
        self.store(BUF, offset, value, 8)

    def views(self):
        return tuple(self.p[name] for name, _type in VIEWS)

    def take_views(self, values):
        for (name, _type), value in zip(VIEWS, values):
            self.p[name] = value

    # -- composite steps -----------------------------------------------------------------------------------------
    def uleb_size(self, value):
        size, rest = self.let("size", 1), self.let("rest", value)
        self.while_(lambda: self.le(128, self[rest]), lambda: (self.set(rest, self.udiv(self[rest], 128)), self.set(size, self.add(self[size], 1))))
        return self[size]

    def put_uleb(self, at: str, value):
        """Write ``value`` as a minimal ULEB at ``buf[at]``; advance ``at``."""
        rest, going = self.let("rest", value), self.let("going", 1)

        def byte():
            low, high = self.and_(self[rest], 127), self.udiv(self[rest], 128)
            more = self.ne(high, 0)
            self.store(BUF, self[at], self.or_(low, self.mul(self.flag(more), 128)))
            self.set(at, self.add(self[at], 1))
            self.set(rest, high)
            self.set(going, self.flag(more))
        self.while_(lambda: self.ne(self[going], 0), byte)

    def put_bytes(self, at: str, data: bytes):
        for index, value in enumerate(data):
            self.store(BUF, self.add(self[at], index), value)
        self.set(at, self.add(self[at], len(data)))

    def copy(self, source, source_at, at: str, count):
        """Copy ``count`` bytes from ``source`` at ``source_at`` to ``buf[at]``; advance ``at``."""
        offset, left = self.let("from", source_at), self.let("left", count)

        def chunk(size: int):
            def step():
                self.store(BUF, self[at], self.load(source, self[offset], size), size)
                for name in (at, offset):
                    self.set(name, self.add(self[name], size))
                self.set(left, self.sub(self[left], size))
            return step
        self.while_(lambda: self.le(8, self[left]), chunk(8))
        self.while_(lambda: self.ne(self[left], 0), chunk(1))

    def order(self, x_view, x_at, x_length, y_view, y_at, y_length) -> str:
        """Unsigned lexicographic order of two byte strings (a proper prefix is less): ORDER_EQUAL, _GREATER, _LESS."""
        x, y = self.let("x", x_at), self.let("y", y_at)
        common = self.let("common", self.sel(self.lt(x_length, y_length), x_length, y_length))
        result, k = self.let("order", ORDER_EQUAL), self.let("k", 0)

        def step():
            a, b = self.load(x_view, self.add(self[x], self[k])), self.load(y_view, self.add(self[y], self[k]))
            self.set(result, self.sel(self.lt(a, b), ORDER_LESS, self.sel(self.lt(b, a), ORDER_GREATER, ORDER_EQUAL)))
            self.set(k, self.add(self[k], 1))
        self.while_(lambda: self.both(self.lt(self[k], self[common]), self.eq(self[result], ORDER_EQUAL)), step)
        self.if_(self.eq(self[result], ORDER_EQUAL), lambda: self.set(result, self.sel(
            self.lt(x_length, y_length), ORDER_LESS, self.sel(self.lt(y_length, x_length), ORDER_GREATER, ORDER_EQUAL))))
        return result

    def merge_sort(self, count, first: int, second: int, greater) -> str:
        """Stable bottom-up merge sort of the indices ``0 .. count`` (written to ``first``) by ``greater(i, j)``, a
        variable name holding 1 when index ``i``'s key orders after ``j``'s; the name holding the sorted array."""
        source, target, width = self.let("source", first), self.let("target", second), self.let("width", 1)
        index, count = self.let("index", 0), self[self.let("count", count)]

        def initialize():
            self.set_word(self.add(first, self.mul(self[index], 8)), self[index])
            self.set(index, self.add(self[index], 1))
        self.while_(lambda: self.lt(self[index], count), initialize)

        def element(array, position):
            return self.word(BUF, self.add(self[array], self.mul(position, 8)))

        def run():
            low = self.let("low", 0)

            def merge():
                middle = self.let("middle", self.sel(self.lt(self.add(self[low], self[width]), count), self.add(self[low], self[width]), count))
                two = self.add(self[low], self.mul(self[width], 2))
                high = self.let("high", self.sel(self.lt(two, count), two, count))
                left, right, out = self.let("left", self[low]), self.let("right", self[middle]), self.let("out", self[low])

                def take():
                    from_left = self.let("from_left", self.flag(self.lt(self[left], self[middle])))
                    self.if_(self.both(self.ne(self[from_left], 0), self.lt(self[right], self[high])), lambda: self.set(
                        from_left, self.sub(1, self[greater(element(source, self[left]), element(source, self[right]))])))
                    chosen = self.let("chosen", 0)
                    self.if_(self.ne(self[from_left], 0),
                             lambda: (self.set(chosen, element(source, self[left])), self.set(left, self.add(self[left], 1))),
                             lambda: (self.set(chosen, element(source, self[right])), self.set(right, self.add(self[right], 1))))
                    self.set_word(self.add(self[target], self.mul(self[out], 8)), self[chosen])
                    self.set(out, self.add(self[out], 1))
                self.while_(lambda: self.lt(self[out], self[high]), take)
                self.set(low, self[high])
            self.while_(lambda: self.lt(self[low], count), merge)
            swap = self.let("swap", self[source])
            self.set(source, self[target])
            self.set(target, self[swap])
            self.set(width, self.mul(self[width], 2))
        self.while_(lambda: self.lt(self[width], count), run)
        return source

    def hash(self, base, length):
        """The S2 hash of ``buf[base : base + length]``; the digest is at ``scratch[DIGEST_OFFSET]``."""
        p = self.p
        results = p.op(Operation.CALL_DIRECT, (*self.views()[3:], self.v(base), self.v(length)),
                       tuple(type_ for _name, type_ in VIEWS[3:]), entity=self.hash_at)
        self.take_views((*self.views()[:3], *results))


def _object_field(w: _W, at, field: int):
    return w.word(BATCH, w.add(at, 8 * field))


def build_writer_program() -> tuple[StoreReader, SemanticObject]:
    hash_at, hash_objects = hash_function(BUF_POINTER, BUF_VIEW, based=True)
    proc = Proc((*VIEWS, ("mode", B64)))
    w = _W(proc, hash_at)
    mode = proc["mode"]
    status, reason, culprit, length = w.let("status", RUNNING), w.let("reason", 0), w.let("culprit", 0), w.let("length", 0)
    objects, records, batch_length = (w.let(name, w.word(BATCH, 8 * field)) for field, name in enumerate(("objects", "records", "batch")))

    def decline_unless(condition):
        w.if_(w.not_(condition), lambda: w.set(status, DECLINE))

    def running():
        return w.eq(w[status], RUNNING)

    def when_running(body):
        w.if_(running(), body)

    # Phase 0: the batch's structure (a host marshal; anything it cannot hold declines), each object's payload length,
    # and each record's canonical envelope.  ``bound`` over-approximates the store's length.
    decline_unless(w.both(w.le(w[objects], MAX_OBJECTS), w.le(w[records], MAX_RECORDS), w.le(BATCH_HEADER, w[batch_length]),
                          w.le(w[batch_length], IN_EXTENT)))
    at, bound = w.let("at", BATCH_HEADER), w.let("bound", 64)

    def scan_object():
        index = w.let("object", 0)

        def each():
            decline_unless(w.le(w.add(w[at], OBJECT_HEADER), w[batch_length]))

            def fits():
                refs, body = w.let("refs", _object_field(w, w[at], 2)), w.let("body", _object_field(w, w[at], 3))
                decline_unless(w.both(w.le(w[refs], IN_EXTENT // CID_SIZE), w.le(w[body], IN_EXTENT)))

                def sized():
                    size = w.let("size", w.add(w.add(OBJECT_HEADER, w.mul(w[refs], CID_SIZE)), w[body]))
                    decline_unless(w.le(w.add(w[at], w[size]), w[batch_length]))

                    def table():
                        tail = w.add(w.add(w.uleb_size(_object_field(w, w[at], 0)), w.uleb_size(_object_field(w, w[at], 1))),
                                     w.add(w.uleb_size(w[refs]), w.uleb_size(w[body])))
                        tail = w.let("tail", w.add(tail, w.sub(w[size], OBJECT_HEADER)))
                        entry = w.add(OBJECTS_AT, w.mul(w[index], 16))
                        w.set_word(entry, w[at])
                        w.set_word(w.add(entry, 8), w[tail])
                        w.set(bound, w.add(w[bound], w.add(w[tail], 10 + CID_SIZE + CID_SIZE + 20)))
                        w.set(at, w.add(w[at], w[size]))
                        w.set(index, w.add(w[index], 1))
                    when_running(table)
                when_running(sized)
            when_running(fits)
        w.while_(lambda: w.both(w.lt(w[index], w[objects]), running()), each)

    def scan_records():
        index, staged = w.let("record", 0), w.let("staged", ENVELOPES_AT)

        def each():
            decline_unless(w.le(w.add(w[at], RECORD_HEADER), w[batch_length]))

            def fits():
                schema, payload = w.let("schema", w.word(BATCH, w[at])), w.let("payload", w.word(BATCH, w.add(w[at], 8)))
                decline_unless(w.both(w.le(w[payload], IN_EXTENT), w.le(w.add(w.add(w[at], RECORD_HEADER), w[payload]), w[batch_length])))

                def sized():
                    content = w.let("content", w.add(w.add(w.uleb_size(w[schema]), w.uleb_size(w[payload])), w[payload]))
                    envelope = w.let("envelope", w.add(w.uleb_size(w[content]), w[content]))
                    decline_unless(w.le(w.add(w[staged], w[envelope]), ENVELOPES_LIMIT))

                    def stage():
                        entry = w.add(RECORDS_AT, w.mul(w[index], 16))
                        w.set_word(entry, w[staged])
                        w.set_word(w.add(entry, 8), w[envelope])
                        w.put_uleb(staged, w[content])
                        w.put_uleb(staged, w[schema])
                        w.put_uleb(staged, w[payload])
                        w.copy(BATCH, w.add(w[at], RECORD_HEADER), staged, w[payload])
                        w.set(bound, w.add(w[bound], w[envelope]))
                        w.set(at, w.add(w.add(w[at], RECORD_HEADER), w[payload]))
                        w.set(index, w.add(w[index], 1))
                    when_running(stage)
                when_running(sized)
            when_running(fits)
        w.while_(lambda: w.both(w.lt(w[index], w[records]), running()), each)

    when_running(scan_object)
    when_running(scan_records)
    when_running(lambda: decline_unless(w.both(w.eq(w[at], w[batch_length]), w.le(w.add(w[bound], 20 + CID_SIZE + 4 + HASH_SLACK), OUT_LIMIT))))

    def entry_word(table: int, index, field: int):
        return w.word(BUF, w.add(table, w.add(w.mul(index, 16), 8 * field)))

    def encode_payload(at_name: str, record):
        """The record payload after its CID: kind, schema version, reference table, body length, body."""
        for field in (0, 1, 2):
            w.put_uleb(at_name, _object_field(w, record, field))
        w.copy(BATCH, w.add(record, OBJECT_HEADER), at_name, w.mul(_object_field(w, record, 2), CID_SIZE))
        w.put_uleb(at_name, _object_field(w, record, 3))
        w.copy(BATCH, w.add(w.add(record, OBJECT_HEADER), w.mul(_object_field(w, record, 2), CID_SIZE)), at_name, _object_field(w, record, 3))

    # Phase 1: each object in input order until the first that is not canonical (``first``).
    first, index = w.let("first", 0), w.let("checked", 0)
    w.set(first, w[objects])

    def check_object():
        record = w.let("at_object", entry_word(OBJECTS_AT, w[index], 0))

        def references():
            sorted_, k = w.let("sorted", 1), w.let("k", 1)
            refs = _object_field(w, w[record], 2)

            def step():
                at_ref = w.add(w.add(w[record], OBJECT_HEADER), w.mul(w[k], CID_SIZE))
                ordered = w[w.order(BATCH, w.sub(at_ref, CID_SIZE), CID_SIZE, BATCH, at_ref, CID_SIZE)]
                w.set(sorted_, w.flag(w.eq(ordered, ORDER_LESS)))
                w.set(k, w.add(w[k], 1))
            w.while_(lambda: w.both(w.lt(w[k], refs), w.ne(w[sorted_], 0)), step)
            w.if_(w.eq(w[sorted_], 0), lambda: (w.set(first, w[index]), w.set(reason, REFERENCES_UNSORTED)), identity)

        def identity():
            staged = w.let("preimage", 0)
            w.put_bytes(staged, SEMANTIC_DOMAIN)
            encode_payload(staged, w[record])
            w.hash(0, w[staged])
            same = w.let("same", 1)
            for word in range(CID_SIZE // 4):
                claimed = w.load(BATCH, w.add(w[record], 32 + 4 * word), 4)
                w.set(same, w.and_(w[same], w.flag(w.eq(claimed, w.load(SCRATCH, DIGEST_OFFSET + 4 * word, 4)))))
            w.if_(w.eq(w[same], 0), lambda: (w.set(first, w[index]), w.set(reason, NOT_CANONICAL)))

        w.if_(w.ne(_object_field(w, w[record], 1), 1), lambda: (w.set(first, w[index]), w.set(reason, NOT_CANONICAL)), references)
        w.set(index, w.add(w[index], 1))

    def cid_at(position):
        return w.add(entry_word(OBJECTS_AT, position, 0), 32)

    def cid_greater(i, j):
        return w.let("greater", w.flag(w.eq(w[w.order(BATCH, cid_at(i), CID_SIZE, BATCH, cid_at(j), CID_SIZE)], ORDER_GREATER)))

    def record_greater(i, j):
        return w.let("greater", w.flag(w.eq(w[w.order(BUF, entry_word(RECORDS_AT, i, 0), entry_word(RECORDS_AT, i, 1),
                                                       BUF, entry_word(RECORDS_AT, j, 0), entry_word(RECORDS_AT, j, 1))], ORDER_GREATER)))

    sorted_objects = w.let("sorted_objects", OBJECT_SORT_A)

    def identities():
        w.while_(lambda: w.both(w.lt(w[index], w[objects]), w.eq(w[first], w[objects])), check_object)
        # Phase 2: a duplicate CID among the canonical prefix; the bootstrap meets the one at the smallest index first.
        w.set(sorted_objects, w[w.merge_sort(w[first], OBJECT_SORT_A, OBJECT_SORT_B, cid_greater)])
        duplicate, k = w.let("duplicate", w[objects]), w.let("pair", 1)

        def pair():
            earlier = w.word(BUF, w.add(w[sorted_objects], w.mul(w.sub(w[k], 1), 8)))
            later = w.let("later", w.word(BUF, w.add(w[sorted_objects], w.mul(w[k], 8))))
            same = w.eq(w[w.order(BATCH, cid_at(earlier), CID_SIZE, BATCH, cid_at(w[later]), CID_SIZE)], ORDER_EQUAL)
            w.if_(w.both(same, w.lt(w[later], w[duplicate])), lambda: w.set(duplicate, w[later]))
            w.set(k, w.add(w[k], 1))
        w.while_(lambda: w.lt(w[k], w[first]), pair)
        w.if_(w.lt(w[duplicate], w[objects]), lambda: (w.set(status, REJECT), w.set(reason, DUPLICATE_OBJECT), w.set(culprit, w[duplicate])),
              lambda: w.if_(w.lt(w[first], w[objects]), lambda: (w.set(status, REJECT), w.set(culprit, w[first]))))

    when_running(identities)

    def root():
        found, k = w.let("found", 0), w.let("candidate", 0)

        def step():
            w.if_(w.eq(w[w.order(BATCH, 24, CID_SIZE, BATCH, cid_at(w[k]), CID_SIZE)], ORDER_EQUAL), lambda: w.set(found, 1))
            w.set(k, w.add(w[k], 1))
        w.while_(lambda: w.both(w.lt(w[k], w[objects]), w.eq(w[found], 0)), step)
        w.if_(w.eq(w[found], 0), lambda: (w.set(status, REJECT), w.set(reason, ROOT_MISSING)))

    when_running(root)
    sorted_records = w.let("sorted_records", RECORD_SORT_A)

    def metadata():
        w.set(sorted_records, w[w.merge_sort(w[records], RECORD_SORT_A, RECORD_SORT_B, record_greater)])
        k = w.let("pair", 1)

        def pair():
            earlier = w.word(BUF, w.add(w[sorted_records], w.mul(w.sub(w[k], 1), 8)))
            later = w.word(BUF, w.add(w[sorted_records], w.mul(w[k], 8)))
            same = w.eq(w[w.order(BUF, entry_word(RECORDS_AT, earlier, 0), entry_word(RECORDS_AT, earlier, 1),
                                  BUF, entry_word(RECORDS_AT, later, 0), entry_word(RECORDS_AT, later, 1))], ORDER_EQUAL)
            w.if_(same, lambda: (w.set(status, REJECT), w.set(reason, DUPLICATE_RECORD)))
            w.set(k, w.add(w[k], 1))
        w.while_(lambda: w.both(w.lt(w[k], w[records]), running()), pair)

    when_running(metadata)

    def emit():
        out = w.let("out", 0)
        w.put_bytes(out, MAGIC)
        for value in (CONTAINER_MAJOR, 0, HASH_SUITE):
            w.put_uleb(out, value)
        w.copy(BATCH, 24, out, CID_SIZE)
        w.put_uleb(out, w[objects])
        w.put_uleb(out, w[records])
        w.put_uleb(out, 0)
        # Records in CID order; the index needs each record's offset.
        index_length, k = w.let("index_length", 0), w.let("emitted", 0)

        def record():
            position = w.word(BUF, w.add(w[sorted_objects], w.mul(w[k], 8)))
            at_record = w.let("at_record", entry_word(OBJECTS_AT, position, 0))
            payload = w.let("payload", w.add(entry_word(OBJECTS_AT, position, 1), CID_SIZE))
            w.set_word(w.add(OFFSETS_AT, w.mul(w[k], 8)), w[out])
            w.set(index_length, w.add(w[index_length], w.add(CID_SIZE, w.add(w.uleb_size(w[out]), w.uleb_size(w[payload])))))
            w.put_uleb(out, w[payload])
            w.copy(BATCH, w.add(w[at_record], 32), out, CID_SIZE)
            encode_payload(out, w[at_record])
            w.set(k, w.add(w[k], 1))
        w.while_(lambda: w.lt(w[k], w[objects]), record)
        w.set(k, 0)

        def envelope():
            position = w.word(BUF, w.add(w[sorted_records], w.mul(w[k], 8)))
            w.copy(BUF, entry_word(RECORDS_AT, position, 0), out, entry_word(RECORDS_AT, position, 1))
            w.set(k, w.add(w[k], 1))
        w.while_(lambda: w.lt(w[k], w[records]), envelope)
        w.put_uleb(out, w[index_length])
        w.set(k, 0)

        def index_entry():
            position = w.word(BUF, w.add(w[sorted_objects], w.mul(w[k], 8)))
            w.copy(BATCH, cid_at(position), out, CID_SIZE)
            w.put_uleb(out, w.word(BUF, w.add(OFFSETS_AT, w.mul(w[k], 8))))
            w.put_uleb(out, w.add(entry_word(OBJECTS_AT, position, 1), CID_SIZE))
            w.set(k, w.add(w[k], 1))
        w.while_(lambda: w.lt(w[k], w[objects]), index_entry)
        w.hash(0, w[out])
        for word in range(CID_SIZE // 4):
            w.store(BUF, w.add(w[out], 4 * word), w.load(SCRATCH, DIGEST_OFFSET + 4 * word, 4), 4)
        w.set(out, w.add(w[out], CID_SIZE))
        w.put_bytes(out, TRAILER_MAGIC)
        w.set(length, w[out])

    w.if_(w.both(running(), w.eq(mode, MODE_WRITE)), emit)
    w.if_(running(), lambda: w.set(status, ACCEPT))
    for field, name in enumerate((status, reason, culprit, length)):
        w.set_word(STATUS_AT + 8 * field, w[name])
    proc.ret(*w.views())
    function = proc.function(tuple(type_ for _name, type_ in VIEWS))
    objects_ = (*proc.graph.objects.values(), *hash_objects)
    return program_store(function, x86_64_linux_exec_target(), objects_), function


def load_writer_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "store-writer")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_writer_store() -> bytes:
    reader, _function = build_writer_program()
    STORE_PATH.write_bytes(reader.data)
    return reader.data


def marshal(root_cid: bytes, objects, records) -> bytes | None:
    """The batch for ``objects`` and non-semantic ``records``; None for inputs the batch cannot represent (a CID or
    reference that is not 32 bytes, a field outside 0 .. 2^64), which the bootstrap writer decides."""
    limit = 1 << 64
    parts = [b"", b"", b"", bytes(root_cid)]
    if len(root_cid) != CID_SIZE:
        return None
    for obj in objects:
        kind, version, references, body, cid = int(obj.kind), obj.schema_version, obj.references, obj.body, obj.cid
        if not (0 <= kind < limit and 0 <= version < limit) or len(cid) != CID_SIZE or any(len(item) != CID_SIZE for item in references):
            return None
        parts.append(b"".join((kind.to_bytes(8, "little"), version.to_bytes(8, "little"), len(references).to_bytes(8, "little"),
                               len(body).to_bytes(8, "little"), cid, *references, body)))
    count = len(parts) - 4
    for record in records:
        if not 0 <= record.schema_id < limit:
            return None
        parts.append(record.schema_id.to_bytes(8, "little") + len(record.payload).to_bytes(8, "little") + record.payload)
    total = sum(map(len, parts)) + 24
    parts[0], parts[1], parts[2] = count.to_bytes(8, "little"), (len(parts) - 4 - count).to_bytes(8, "little"), total.to_bytes(8, "little")
    return b"".join(parts)


class NativeWriter:
    """The writer lowered by the XAX x86-64 backend, called in-process with three lent buffers."""

    def __init__(self) -> None:
        from xax_native import executable_mapping, zeroed_array
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        reader, function = load_writer_program()
        machine_code, entry_offset = host_image(reader, function, "store-writer")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        self._mapping, base = executable_mapping(thunk + machine_code)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self.code_size = len(machine_code)
        self.semantic_root = reader.root_cid
        self._batch = zeroed_array(ctypes.c_uint8, IN_EXTENT)
        self._buf = zeroed_array(ctypes.c_uint8, BUF_EXTENT)
        self._scratch = (ctypes.c_uint32 * (SCRATCH_EXTENT // 4))()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def run(self, root_cid: bytes, objects, records, mode: int = MODE_WRITE) -> tuple[int, int, int, bytes | None]:
        """``(status, reason, object index, store bytes or None)``."""
        batch = marshal(root_cid, objects, records)
        if batch is None or len(batch) > IN_EXTENT:
            return DECLINE, 0, 0, None
        with self._lock:
            ctypes.memmove(self._batch, batch, len(batch))
            slots = self._slots
            slots[0], slots[1], slots[2], slots[3] = (ctypes.addressof(self._batch), ctypes.addressof(self._buf),
                                                      ctypes.addressof(self._scratch), mode)
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            status, reason, index, length = (int.from_bytes(ctypes.string_at(ctypes.addressof(self._buf) + STATUS_AT + 8 * field, 8), "little")
                                             for field in range(4))
            data = ctypes.string_at(ctypes.addressof(self._buf), length) if status == ACCEPT and mode == MODE_WRITE else None
        return status, reason, index, data


def native_writer_usable() -> bool:
    import xax_native

    return xax_native.usable("store-writer", STORE_PATH, "XAX_STORE_PYTHON_WRITER")
