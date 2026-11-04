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
import threading

from xax_compiler import Kind, SemanticObject, StoreReader, bits_type, heap_view_type
import xax_selfhost_store as store

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_graph_decoder.xax"
BODY_EXTENT = 1 << 22  # S13b (ADR-282): 2 MiB, so the general driver's own function body (1 MB) can grow; S15e.6i.2a (ADR-358): 4 MiB
OUT_EXTENT = 1 << 26  # S6c: a stream word per body byte for the largest bodies, with room to spare (S15e.6i.2a: 64 MiB)
OUT_WORDS = OUT_EXTENT // 8
ACCEPT, REJECT, DEFER = 0, 1, 2
# S8b.2 (ADR-185): the diagnostic record (64-bit words) after its cursor at DIAG_AT, below the stream's end; on reject
# out[1] is the stream prefix's end, so the caller can walk what precedes the rejection in body order.
DIAG_AT = OUT_WORDS - 4096

B1, B8, B64 = bits_type(1), bits_type(8), bits_type(64)
MEM = store.MEM
BODY_VIEW, OUT_VIEW = heap_view_type(BODY_EXTENT), heap_view_type(OUT_EXTENT)
STATE = (BODY_VIEW, MEM, OUT_VIEW, MEM)


def load_graph_decoder_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "graph-decoder")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


class NativeGraphDecoder:
    def __init__(self) -> None:
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = host_image(*load_graph_decoder_program(), "graph-decoder")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + machine_code
        from xax_native import executable_mapping, zeroed_array

        self._mapping, base = executable_mapping(code)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self.code_size = len(machine_code)
        self._body = zeroed_array(ctypes.c_uint64, BODY_EXTENT // 8)
        self._out = zeroed_array(ctypes.c_uint64, OUT_WORDS)
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
