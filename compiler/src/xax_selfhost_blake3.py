"""Self-hosting step S2 (ADR-117): the whole BLAKE3-256 hash as XAX semantics over borrowed views.

S0 made the BLAKE3 *compression* an XAX leaf; the chunking, block padding, and
chaining-value tree stayed in Python, with one native call per 64-byte block.
S2 moves the whole hash into one XAX function, so every content identity
(CID) the compiler computes comes from XAX code in one call per object:

    hash(input: ptr<b32,READ,space 2>, heap_view<INPUT_EXTENT>, memory,
         scratch: ptr<b32,RW,space 2>, heap_view<SCRATCH_EXTENT>, memory,
         length: bits<64>) -> (the same two view triples)

The caller lends two views: the input bytes (``length <= INPUT_EXTENT``) and a
scratch area that holds the chaining-value stack (54 entries), a 64-byte
padding block, and the 32-byte digest at ``DIGEST_OFFSET``.  Every access is a
checked load or store into a borrowed view (ADR-099, U1.2a), so an
out-of-range offset traps rather than reading foreign memory.  The compression
itself is the committed S0 function, called directly.

This is the first migrated component that passes buffers across the leaf
boundary.  The Python driver in ``blake3.py`` remains the reference and the
fallback for inputs over ``INPUT_EXTENT`` and for hosts that cannot run the
leaf.
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
from xax_graph_builder import BlockBuilder, GraphBuilder, program_store

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_blake3_hash.xax"
INPUT_EXTENT = 1 << 20
STACK_OFFSET, STACK_ENTRIES = 0, 54
DIGEST_OFFSET = STACK_OFFSET + 32 * STACK_ENTRIES  # 1728
SCRATCH_EXTENT = 2048
IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8

B1, B8, B32, B64 = bits_type(1), bits_type(8), bits_type(32), bits_type(64)
MEM = memory_effect_type()
# Word views: checked accesses are element-sized (the caller lends 4-aligned buffers).
INPUT_POINTER = pointer_type(B32, Permission.READ, 4, space=2)
SCRATCH_POINTER = pointer_type(B32, Permission.READ_WRITE, 4, space=2)
INPUT_VIEW, SCRATCH_VIEW = heap_view_type(INPUT_EXTENT), heap_view_type(SCRATCH_EXTENT)


class _Ops:
    def __init__(self, block: BlockBuilder, ctx: dict):
        self.b, self.ctx = block, ctx

    def c64(self, value: int):
        return self.b.const(B64, value)

    def c32(self, value: int):
        return self.b.const(B32, value)

    def op(self, operation, x, y, result=B64):
        return self.b.op1(operation, (x, y), result)

    def add(self, x, y):
        return self.op(Operation.ADD_WRAP, x, y)

    def sub(self, x, y):
        return self.op(Operation.SUB_WRAP, x, y)

    def mul(self, x, y):
        return self.op(Operation.MUL_WRAP, x, y)

    def cmp(self, kind, x, y):
        return self.b.op1(Operation.INT_COMPARE, (x, y), B1, attributes=(kind,))

    def flag64(self, kind, x, y):
        return self.b.op1(Operation.INT_ZERO_EXTEND, (self.cmp(kind, x, y),), B64)

    def min(self, x, y):
        """Unsigned min without a branch: y + (x - y) * (x < y)."""
        return self.add(y, self.mul(self.sub(x, y), self.flag64(IntCompare.ULT, x, y)))

    def to32(self, x):
        return self.b.op1(Operation.INT_TRUNCATE, (x,), B32)

    def load32(self, pointer, offset, memory):
        value, memory = self.b.op(Operation.CHECKED_LOAD_BITS_LE, (pointer, self.to32(offset), memory), (B32, MEM), attributes=(4, 1))
        return value, memory

    def store32(self, pointer, offset, value, memory):
        return self.b.op1(Operation.CHECKED_STORE_BITS_LE, (pointer, self.to32(offset), value, memory), MEM, attributes=(4, 1))

    def compress(self, cv, words, counter, block_len32, flags32):
        counter_lo = self.to32(counter)
        counter_hi = self.to32(self.b.op1(Operation.UDIV, (counter, self.c64(1 << 32)), B64))
        out = self.b.op1(Operation.CALL_DIRECT, (*cv, *words, counter_lo, counter_hi, block_len32, flags32), self.ctx["tuple"], entity=self.ctx["compress"])
        return [self.b.op1(Operation.AGGREGATE_GET, (out,), B32, attributes=(index,)) for index in range(8)]

    def parent(self, left, right, root_flag32):
        iv = [self.c32(word) for word in IV]
        flags = self.b.op1(Operation.BIT_OR, (self.c32(PARENT), root_flag32), B32)
        return self.compress(iv, [*left, *right], self.c64(0), self.c32(64), flags)

    def load_cv(self, pointer, offset, memory):
        words = []
        for index in range(8):
            word, memory = self.load32(pointer, self.add(offset, self.c64(4 * index)), memory)
            words.append(word)
        return words, memory

    def store_words(self, pointer, offset, words, memory):
        for index, word in enumerate(words):
            memory = self.store32(pointer, self.add(offset, self.c64(4 * index)), word, memory)
        return memory


def build_hash_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native_blake3 import load_blake3_compress_program

    compress_program = load_blake3_compress_program()
    compress = compress_program.function
    resolve = compress_program.reader.get
    ctx = {"compress": compress, "tuple": next(resolve(cid) for cid in compress.references if resolve(cid).kind == Kind.TYPE and resolve(cid).body[:1] == b"\x08")}
    graph = GraphBuilder()
    entry = graph.block(INPUT_POINTER, INPUT_VIEW, MEM, SCRATCH_POINTER, SCRATCH_VIEW, MEM, B64)
    inp, in_view, mi, scr, scr_view, ms, length = entry.params
    # Both views travel as (token, memory) pairs through every block, so their
    # ownership and effect facts follow the control flow (ADR-099).
    views = (INPUT_VIEW, MEM, SCRATCH_VIEW, MEM)
    cv8 = (B32,) * 8
    chunk = graph.block(B64, B64, *views)                    # ci, stack length
    block = graph.block(B64, *cv8, *views)                   # bi, cv
    compress_block = graph.block(*(B32,) * 16, *views)
    chunk_done = graph.block(*cv8, *views)
    after_last = graph.block(*cv8, *views)
    push = graph.block(*cv8, B64, B64, *views)               # cv, total, stack length
    pop = graph.block(*cv8, B64, B64, *views)
    push_store = graph.block(*cv8, B64, *views)
    finalize = graph.block(*cv8, B64, *views)                # cv, entries left to merge
    digest = graph.block(*cv8, *views)

    # entry: chunks = max(1, ceil(length / 1024))
    ops = _Ops(entry, ctx)
    count = ops.op(Operation.UDIV, ops.add(length, ops.c64(1023)), ops.c64(1024))
    chunks = ops.add(count, ops.flag64(IntCompare.EQ, count, ops.c64(0)))
    entry.br(chunk, ops.c64(0), ops.c64(0), in_view, mi, scr_view, ms)

    # chunk(ci, sl): this chunk's start, length, and block count.
    ci, sl, *state = chunk.params
    ops = _Ops(chunk, ctx)
    chunk_start = ops.mul(ci, ops.c64(1024))
    chunk_len = ops.min(ops.sub(length, chunk_start), ops.c64(1024))
    raw_blocks = ops.op(Operation.UDIV, ops.add(chunk_len, ops.c64(63)), ops.c64(64))
    blocks = ops.add(raw_blocks, ops.flag64(IntCompare.EQ, raw_blocks, ops.c64(0)))
    last_chunk = ops.cmp(IntCompare.EQ, ops.add(ci, ops.c64(1)), chunks)
    chunk.br(block, ops.c64(0), *[ops.c32(word) for word in IV], *state)

    # block(bi, cv): load the block's 16 words.  Word k keeps only the bytes
    # before the block's length; bytes past it (inside the lent view) are masked
    # to zero, which is BLAKE3's padding.
    bi, *rest = block.params
    cv, (iv, mi, sv, ms) = rest[:8], rest[8:]
    ops = _Ops(block, ctx)
    block_offset = ops.add(chunk_start, ops.mul(bi, ops.c64(64)))
    block_len = ops.min(ops.sub(chunk_len, ops.mul(bi, ops.c64(64))), ops.c64(64))
    words = []
    for index in range(16):
        word, mi = ops.load32(inp, ops.add(block_offset, ops.c64(4 * index)), mi)
        mask = ops.c64(0)
        for byte in range(4):
            present = ops.flag64(IntCompare.UGT, block_len, ops.c64(4 * index + byte))
            mask = ops.add(mask, ops.mul(present, ops.c64(0xFF << (8 * byte))))
        words.append(ops.b.op1(Operation.BIT_AND, (word, ops.to32(mask)), B32))
    block.br(compress_block, *words, iv, mi, sv, ms)

    # compress: flags from the block's position; a single chunk's last block is the root.
    *words, iv, mi, sv, ms = compress_block.params
    ops = _Ops(compress_block, ctx)
    last_block = ops.cmp(IntCompare.EQ, ops.add(bi, ops.c64(1)), blocks)
    first = ops.flag64(IntCompare.EQ, bi, ops.c64(0))
    last = ops.b.op1(Operation.INT_ZERO_EXTEND, (last_block,), B64)
    single = ops.flag64(IntCompare.EQ, chunks, ops.c64(1))
    root = ops.mul(ops.mul(last, single), ops.c64(ROOT))
    flags = ops.add(ops.add(first, ops.mul(last, ops.c64(CHUNK_END))), root)
    out = ops.compress(cv, words, ci, ops.to32(block_len), ops.to32(flags))
    compress_block.cbr(last_block, chunk_done, (*out, iv, mi, sv, ms), block, (ops.add(bi, ops.c64(1)), *out, iv, mi, sv, ms))

    # A finished chunk: the last one merges down the stack (or is the root);
    # others push their chaining value, merging completed subtrees first.
    *out, iv, mi, sv, ms = chunk_done.params
    ops = _Ops(chunk_done, ctx)
    chunk_done.cbr(last_chunk, after_last, (*out, iv, mi, sv, ms), push, (*out, ops.add(ci, ops.c64(1)), sl, iv, mi, sv, ms))
    *out, iv, mi, sv, ms = after_last.params
    ops = _Ops(after_last, ctx)
    after_last.cbr(ops.cmp(IntCompare.EQ, sl, ops.c64(0)), digest, (*out, iv, mi, sv, ms), finalize, (*out, sl, iv, mi, sv, ms))

    # push(cv, total, stack length): while total is even, merge with the top entry.
    *cv_push, total, stack, iv, mi, sv, ms = push.params
    ops = _Ops(push, ctx)
    even = ops.cmp(IntCompare.EQ, ops.op(Operation.BIT_AND, total, ops.c64(1)), ops.c64(0))
    push.cbr(even, pop, (*cv_push, total, stack, iv, mi, sv, ms), push_store, (*cv_push, stack, iv, mi, sv, ms))
    *cv_pop, total, stack, iv, mi, sv, ms = pop.params
    ops = _Ops(pop, ctx)
    top = ops.sub(stack, ops.c64(1))
    left, ms = ops.load_cv(scr, ops.mul(top, ops.c64(32)), ms)
    merged = ops.parent(left, cv_pop, ops.c32(0))
    pop.br(push, *merged, ops.op(Operation.UDIV, total, ops.c64(2)), top, iv, mi, sv, ms)
    *cv_store, stack, iv, mi, sv, ms = push_store.params
    ops = _Ops(push_store, ctx)
    ms = ops.store_words(scr, ops.mul(stack, ops.c64(32)), cv_store, ms)
    push_store.br(chunk, ops.add(ci, ops.c64(1)), ops.add(stack, ops.c64(1)), iv, mi, sv, ms)

    # finalize(cv, n): merge with entry n - 1; the bottom merge is the root.
    *cv_final, remaining, iv, mi, sv, ms = finalize.params
    ops = _Ops(finalize, ctx)
    below = ops.sub(remaining, ops.c64(1))
    left, ms = ops.load_cv(scr, ops.mul(below, ops.c64(32)), ms)
    is_root = ops.cmp(IntCompare.EQ, below, ops.c64(0))
    root_flag = ops.to32(ops.mul(ops.b.op1(Operation.INT_ZERO_EXTEND, (is_root,), B64), ops.c64(ROOT)))
    merged = ops.parent(left, cv_final, root_flag)
    finalize.cbr(is_root, digest, (*merged, iv, mi, sv, ms), finalize, (*merged, below, iv, mi, sv, ms))

    *result, iv, mi, sv, ms = digest.params
    ops = _Ops(digest, ctx)
    ms = ops.store_words(scr, ops.c64(DIGEST_OFFSET), result, ms)
    digest.ret(inp, iv, mi, scr, sv, ms)

    triples = (INPUT_POINTER, INPUT_VIEW, MEM, SCRATCH_POINTER, SCRATCH_VIEW, MEM)
    function = graph.function((*triples, B64), triples)
    objects = (*graph.objects.values(), *compress_program.reader.objects())
    objects = tuple(item for item in objects if item.kind not in (Kind.MODULE, Kind.PROGRAM_ROOT, Kind.TARGET))
    return program_store(function, x86_64_linux_exec_target(), objects), function


def load_hash_program() -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "hash")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def write_hash_store() -> bytes:
    reader, _function = build_hash_program()
    STORE_PATH.write_bytes(reader.data)
    return reader.data


def riscv64_hash_image(backend: str = "auto"):
    """The hash function compiled for the RISC-V views profile (ADR-151: the compression's 16-word result returns
    through a caller-owned area)."""
    from xax_compiler import riscv64_views_target
    from xax_riscv64 import compile_riscv64_bound_target

    reader, function = load_hash_program()
    return compile_riscv64_bound_target(reader, function.cid, riscv64_views_target(), backend=backend)


def run_riscv64_hash(image, data: bytes) -> bytes:
    """Test harness: the digest the RV64 image computes for ``data`` in the Unicorn emulator."""
    from xax_riscv64 import run_riscv64_views

    padded = data + bytes(-len(data) % 8)
    words = [int.from_bytes(padded[k:k + 8], "little") for k in range(0, len(padded), 8)]
    collect = lambda read: b"".join(word.to_bytes(8, "little") for word in read(DIGEST_OFFSET // 8, 4))  # noqa: E731
    _status, digest = run_riscv64_views(image, words, INPUT_EXTENT, SCRATCH_EXTENT, collect, extra_arguments=(len(data),))
    return digest


class NativeHasher:
    """The XAX hash lowered by the XAX x86-64 backend, called in-process with two lent buffers."""

    def __init__(self) -> None:
        from xax_selfhost_x86_64_backend import host_image
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        machine_code, entry_offset = host_image(*load_hash_program(), "blake3-hash")
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        code = thunk + machine_code
        from xax_native import executable_mapping, zeroed_array

        self._mapping, base = executable_mapping(code)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self.code_size = len(machine_code)
        # Word arrays: the views are declared 4-aligned.
        self._input = zeroed_array(ctypes.c_uint32, INPUT_EXTENT // 4)
        self._scratch = (ctypes.c_uint32 * (SCRATCH_EXTENT // 4))()
        self._lock = threading.Lock()
        self.capacity = INPUT_EXTENT
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()

    def digest(self, data: bytes) -> bytes:
        if len(data) > INPUT_EXTENT:
            raise ValueError("input exceeds the lent view")
        with self._lock:
            ctypes.memmove(self._input, data, len(data))
            slots = self._slots
            slots[0], slots[1], slots[2] = ctypes.addressof(self._input), ctypes.addressof(self._scratch), len(data)
            self._call(self._entry, ctypes.addressof(slots), 4, ctypes.addressof(self._xmm))
            return ctypes.string_at(ctypes.addressof(self._scratch) + DIGEST_OFFSET, 32)


def native_hasher_usable() -> bool:
    import xax_native

    return xax_native.usable("blake3-hash", STORE_PATH, "XAX_BLAKE3_PYTHON_HASH")
