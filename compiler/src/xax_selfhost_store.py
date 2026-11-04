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
import threading

from xax_compiler import Kind, SemanticObject, StoreReader, bits_type, heap_view_type, memory_effect_type

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_store_decoder.xax"
DATA_EXTENT = 1 << 26  # S10e (ADR-266): the driver reads its own store; S12f.4 (ADR-280): the general driver's (16.7 MB); ADR-319: 64 MiB
OUT_EXTENT = 1 << 24
# Out words (32 bits): the header and record table, then the parsed index (S8a), then the diagnostic record.
# Per record: offset, length, CID offset, parsed flag, kind, reference count,
# references offset, body offset, body length.
HEADER_WORDS, RECORD_WORDS = 8, 9  # header: status + seven fields
DIAG_AT = 2 << 20  # the cursor, then the record: 64-bit words as (low, high) 32-bit pairs
ACCEPT, REJECT, DEFER, NEED_DIGEST = 0, 1, 2, 3
CID_BYTES = 32
MODE_NONE, MODE_HASH, MODE_VERIFY = 0, 1, 2  # no digest check; report the digest's end; the digest follows the data
# S8b.1 (ADR-184): the data is one record envelope; report the CID's hashed span, then decide with the CID after it.
MODE_OBJECT_HASH, MODE_OBJECT_VERIFY = 3, 4


B1, B8, B32, B64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)
MEM = memory_effect_type()
DATA_VIEW, OUT_VIEW = heap_view_type(DATA_EXTENT), heap_view_type(OUT_EXTENT)
STATE = (DATA_VIEW, MEM, OUT_VIEW, MEM)


def load_decoder_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "store-decoder")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


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
