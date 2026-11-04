"""Small dependency-free BLAKE3-256 implementation used by the XAX bootstrap.

The public surface intentionally matches the subset of the third-party
``blake3`` package used by this repository: ``blake3(data)``, ``update()``,
``digest()``, and ``hexdigest()``.  XAX uses only the unkeyed hash mode.
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass


_MASK32 = 0xFFFFFFFF
_BLOCK_LEN = 64
_CHUNK_LEN = 1024
_OUT_LEN = 32

_CHUNK_START = 1 << 0
_CHUNK_END = 1 << 1
_PARENT = 1 << 2
_ROOT = 1 << 3

_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_WORDS = struct.Struct("<16I")


def _words_from_block(block: bytes) -> tuple[int, ...]:
    if len(block) != _BLOCK_LEN:
        raise ValueError("BLAKE3 compression block must be 64 bytes")
    return _WORDS.unpack(block)


def _words_to_bytes(words: tuple[int, ...] | list[int]) -> bytes:
    return b"".join((word & _MASK32).to_bytes(4, "little") for word in words)


def _compress_python(
    chaining_value: tuple[int, ...],
    block_words: tuple[int, ...],
    counter: int,
    block_len: int,
    flags: int,
) -> tuple[int, ...]:
    # Seven rounds; each is the eight BLAKE3 G mixes inlined over local words,
    # then the message permutation (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8).
    v0, v1, v2, v3, v4, v5, v6, v7 = chaining_value
    v8, v9, v10, v11 = 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
    v12 = counter & 0xFFFFFFFF
    v13 = (counter >> 32) & 0xFFFFFFFF
    v14 = block_len
    v15 = flags
    m = block_words
    for _ in range(7):
        m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15 = m
        v0 = (v0 + v4 + m0) & 0xFFFFFFFF; v12 ^= v0; v12 = ((v12 >> 16) | (v12 << 16)) & 0xFFFFFFFF
        v8 = (v8 + v12) & 0xFFFFFFFF; v4 ^= v8; v4 = ((v4 >> 12) | (v4 << 20)) & 0xFFFFFFFF
        v0 = (v0 + v4 + m1) & 0xFFFFFFFF; v12 ^= v0; v12 = ((v12 >> 8) | (v12 << 24)) & 0xFFFFFFFF
        v8 = (v8 + v12) & 0xFFFFFFFF; v4 ^= v8; v4 = ((v4 >> 7) | (v4 << 25)) & 0xFFFFFFFF
        v1 = (v1 + v5 + m2) & 0xFFFFFFFF; v13 ^= v1; v13 = ((v13 >> 16) | (v13 << 16)) & 0xFFFFFFFF
        v9 = (v9 + v13) & 0xFFFFFFFF; v5 ^= v9; v5 = ((v5 >> 12) | (v5 << 20)) & 0xFFFFFFFF
        v1 = (v1 + v5 + m3) & 0xFFFFFFFF; v13 ^= v1; v13 = ((v13 >> 8) | (v13 << 24)) & 0xFFFFFFFF
        v9 = (v9 + v13) & 0xFFFFFFFF; v5 ^= v9; v5 = ((v5 >> 7) | (v5 << 25)) & 0xFFFFFFFF
        v2 = (v2 + v6 + m4) & 0xFFFFFFFF; v14 ^= v2; v14 = ((v14 >> 16) | (v14 << 16)) & 0xFFFFFFFF
        v10 = (v10 + v14) & 0xFFFFFFFF; v6 ^= v10; v6 = ((v6 >> 12) | (v6 << 20)) & 0xFFFFFFFF
        v2 = (v2 + v6 + m5) & 0xFFFFFFFF; v14 ^= v2; v14 = ((v14 >> 8) | (v14 << 24)) & 0xFFFFFFFF
        v10 = (v10 + v14) & 0xFFFFFFFF; v6 ^= v10; v6 = ((v6 >> 7) | (v6 << 25)) & 0xFFFFFFFF
        v3 = (v3 + v7 + m6) & 0xFFFFFFFF; v15 ^= v3; v15 = ((v15 >> 16) | (v15 << 16)) & 0xFFFFFFFF
        v11 = (v11 + v15) & 0xFFFFFFFF; v7 ^= v11; v7 = ((v7 >> 12) | (v7 << 20)) & 0xFFFFFFFF
        v3 = (v3 + v7 + m7) & 0xFFFFFFFF; v15 ^= v3; v15 = ((v15 >> 8) | (v15 << 24)) & 0xFFFFFFFF
        v11 = (v11 + v15) & 0xFFFFFFFF; v7 ^= v11; v7 = ((v7 >> 7) | (v7 << 25)) & 0xFFFFFFFF
        v0 = (v0 + v5 + m8) & 0xFFFFFFFF; v15 ^= v0; v15 = ((v15 >> 16) | (v15 << 16)) & 0xFFFFFFFF
        v10 = (v10 + v15) & 0xFFFFFFFF; v5 ^= v10; v5 = ((v5 >> 12) | (v5 << 20)) & 0xFFFFFFFF
        v0 = (v0 + v5 + m9) & 0xFFFFFFFF; v15 ^= v0; v15 = ((v15 >> 8) | (v15 << 24)) & 0xFFFFFFFF
        v10 = (v10 + v15) & 0xFFFFFFFF; v5 ^= v10; v5 = ((v5 >> 7) | (v5 << 25)) & 0xFFFFFFFF
        v1 = (v1 + v6 + m10) & 0xFFFFFFFF; v12 ^= v1; v12 = ((v12 >> 16) | (v12 << 16)) & 0xFFFFFFFF
        v11 = (v11 + v12) & 0xFFFFFFFF; v6 ^= v11; v6 = ((v6 >> 12) | (v6 << 20)) & 0xFFFFFFFF
        v1 = (v1 + v6 + m11) & 0xFFFFFFFF; v12 ^= v1; v12 = ((v12 >> 8) | (v12 << 24)) & 0xFFFFFFFF
        v11 = (v11 + v12) & 0xFFFFFFFF; v6 ^= v11; v6 = ((v6 >> 7) | (v6 << 25)) & 0xFFFFFFFF
        v2 = (v2 + v7 + m12) & 0xFFFFFFFF; v13 ^= v2; v13 = ((v13 >> 16) | (v13 << 16)) & 0xFFFFFFFF
        v8 = (v8 + v13) & 0xFFFFFFFF; v7 ^= v8; v7 = ((v7 >> 12) | (v7 << 20)) & 0xFFFFFFFF
        v2 = (v2 + v7 + m13) & 0xFFFFFFFF; v13 ^= v2; v13 = ((v13 >> 8) | (v13 << 24)) & 0xFFFFFFFF
        v8 = (v8 + v13) & 0xFFFFFFFF; v7 ^= v8; v7 = ((v7 >> 7) | (v7 << 25)) & 0xFFFFFFFF
        v3 = (v3 + v4 + m14) & 0xFFFFFFFF; v14 ^= v3; v14 = ((v14 >> 16) | (v14 << 16)) & 0xFFFFFFFF
        v9 = (v9 + v14) & 0xFFFFFFFF; v4 ^= v9; v4 = ((v4 >> 12) | (v4 << 20)) & 0xFFFFFFFF
        v3 = (v3 + v4 + m15) & 0xFFFFFFFF; v14 ^= v3; v14 = ((v14 >> 8) | (v14 << 24)) & 0xFFFFFFFF
        v9 = (v9 + v14) & 0xFFFFFFFF; v4 ^= v9; v4 = ((v4 >> 7) | (v4 << 25)) & 0xFFFFFFFF
        m = (m2, m6, m3, m10, m7, m0, m4, m13, m1, m11, m12, m5, m9, m14, m15, m8)
    c0, c1, c2, c3, c4, c5, c6, c7 = chaining_value
    return (
        v0 ^ v8, v1 ^ v9, v2 ^ v10, v3 ^ v11, v4 ^ v12, v5 ^ v13, v6 ^ v14, v7 ^ v15,
        v8 ^ c0, v9 ^ c1, v10 ^ c2, v11 ^ c3, v12 ^ c4, v13 ^ c5, v14 ^ c6, v15 ^ c7,
    )


# The Python compressor is the immutable bootstrap path.  Once xax_compiler has
# finished importing on an x86-64 host, the first real compression lazily loads
# and verifies the committed XAX store, then lowers it through the normal native
# backend.  Loading/lowering hashes semantic objects, so the building guard
# deliberately forces those recursive hashes through the Python leaf.
_NATIVE_COMPRESSOR = None
_NATIVE_ATTEMPTED = False
_NATIVE_BUILDING = False


def _native_compressor():
    global _NATIVE_COMPRESSOR, _NATIVE_ATTEMPTED, _NATIVE_BUILDING
    if _NATIVE_BUILDING:
        return None
    if _NATIVE_ATTEMPTED:
        return _NATIVE_COMPRESSOR
    compiler = sys.modules.get("xax_compiler")
    if compiler is None or not hasattr(compiler, "Operation"):
        return None
    _NATIVE_ATTEMPTED = True
    _NATIVE_BUILDING = True
    try:
        import xax_native
        from xax_native_blake3 import load_blake3_compress_program, native_blake3_compressor
        _NATIVE_COMPRESSOR = native_blake3_compressor()
        xax_native.loaded("blake3-compress", load_blake3_compress_program().reader.root_cid, _NATIVE_COMPRESSOR.image.code)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        # Portability/bootstrap is never conditional on executable mappings or
        # this optional accelerator being available; the fallback is recorded.
        _NATIVE_COMPRESSOR = None
        import xax_native

        xax_native.fallback("blake3-compress", f"native leaf unavailable: {error!r}", "XAX_BLAKE3_PYTHON_HASH")
    finally:
        _NATIVE_BUILDING = False
    return _NATIVE_COMPRESSOR


def _compress(
    chaining_value: tuple[int, ...],
    block_words: tuple[int, ...],
    counter: int,
    block_len: int,
    flags: int,
) -> tuple[int, ...]:
    native = _native_compressor()
    if native is not None:
        return native.compress(chaining_value, block_words, counter, block_len, flags)
    return _compress_python(chaining_value, block_words, counter, block_len, flags)


@dataclass(frozen=True)
class _Output:
    input_chaining_value: tuple[int, ...]
    block_words: tuple[int, ...]
    counter: int
    block_len: int
    flags: int

    def chaining_value(self) -> tuple[int, ...]:
        return _compress(
            self.input_chaining_value,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )[:8]

    def root_output_bytes(self, length: int) -> bytes:
        output = bytearray()
        output_block_counter = 0
        while len(output) < length:
            words = _compress(
                self.input_chaining_value,
                self.block_words,
                output_block_counter,
                self.block_len,
                self.flags | _ROOT,
            )
            output.extend(_words_to_bytes(words))
            output_block_counter += 1
        return bytes(output[:length])


class _ChunkState:
    def __init__(self, key_words: tuple[int, ...], chunk_counter: int, flags: int):
        self.chaining_value = key_words
        self.chunk_counter = chunk_counter
        self.block = bytearray()
        self.blocks_compressed = 0
        self.flags = flags

    def __len__(self) -> int:
        return _BLOCK_LEN * self.blocks_compressed + len(self.block)

    def _start_flag(self) -> int:
        return _CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if len(self.block) == _BLOCK_LEN:
                block_words = _words_from_block(bytes(self.block))
                self.chaining_value = _compress(
                    self.chaining_value,
                    block_words,
                    self.chunk_counter,
                    _BLOCK_LEN,
                    self.flags | self._start_flag(),
                )[:8]
                self.blocks_compressed += 1
                self.block.clear()
            want = _BLOCK_LEN - len(self.block)
            take = min(want, len(view) - offset)
            self.block.extend(view[offset : offset + take])
            offset += take

    def output(self) -> _Output:
        padded = bytes(self.block) + bytes(_BLOCK_LEN - len(self.block))
        return _Output(
            self.chaining_value,
            _words_from_block(padded),
            self.chunk_counter,
            len(self.block),
            self.flags | self._start_flag() | _CHUNK_END,
        )


def _parent_output(
    left_child_cv: tuple[int, ...],
    right_child_cv: tuple[int, ...],
    key_words: tuple[int, ...],
    flags: int,
) -> _Output:
    return _Output(key_words, left_child_cv + right_child_cv, 0, _BLOCK_LEN, flags | _PARENT)


class _Blake3:
    def __init__(self, data: bytes = b""):
        self._key_words = _IV
        self._flags = 0
        self._chunk_state = _ChunkState(self._key_words, 0, self._flags)
        self._cv_stack: list[tuple[int, ...]] = []
        if data:
            self.update(data)

    def _push_chunk_cv(self, new_cv: tuple[int, ...], total_chunks: int) -> None:
        while total_chunks & 1 == 0:
            left = self._cv_stack.pop()
            new_cv = _parent_output(left, new_cv, self._key_words, self._flags).chaining_value()
            total_chunks >>= 1
        self._cv_stack.append(new_cv)

    def update(self, data: bytes) -> "_Blake3":
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("a bytes-like object is required")
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if len(self._chunk_state) == _CHUNK_LEN:
                chunk_cv = self._chunk_state.output().chaining_value()
                total_chunks = self._chunk_state.chunk_counter + 1
                self._push_chunk_cv(chunk_cv, total_chunks)
                self._chunk_state = _ChunkState(self._key_words, total_chunks, self._flags)
            want = _CHUNK_LEN - len(self._chunk_state)
            take = min(want, len(view) - offset)
            self._chunk_state.update(bytes(view[offset : offset + take]))
            offset += take
        return self

    def _final_output(self) -> _Output:
        output = self._chunk_state.output()
        for left_cv in reversed(self._cv_stack):
            output = _parent_output(left_cv, output.chaining_value(), self._key_words, self._flags)
        return output

    def digest(self, length: int = _OUT_LEN) -> bytes:
        if length < 0:
            raise ValueError("digest length must be nonnegative")
        return self._final_output().root_output_bytes(length)

    def hexdigest(self, length: int = _OUT_LEN) -> str:
        return self.digest(length).hex()

    def copy(self) -> "_Blake3":
        other = _Blake3()
        other._key_words = self._key_words
        other._flags = self._flags
        other._chunk_state = _ChunkState(self._key_words, self._chunk_state.chunk_counter, self._flags)
        other._chunk_state.chaining_value = self._chunk_state.chaining_value
        other._chunk_state.block = bytearray(self._chunk_state.block)
        other._chunk_state.blocks_compressed = self._chunk_state.blocks_compressed
        other._cv_stack = list(self._cv_stack)
        return other


# Self-hosting S2 (ADR-117): the whole hash is an XAX function lowered by the
# XAX x86-64 backend.  It is loaded on first use under the same guard as the
# compression leaf: building it hashes semantic objects through the Python
# driver.  Inputs over its lent view, other digest lengths, and hosts without
# the leaf use the Python driver below.
_NATIVE_HASHER = None
_HASHER_ATTEMPTED = False
_HASHER_BUILDING = False


def _native_hasher():
    global _NATIVE_HASHER, _HASHER_ATTEMPTED, _HASHER_BUILDING
    if _HASHER_BUILDING or _NATIVE_BUILDING:
        return None
    if _HASHER_ATTEMPTED:
        return _NATIVE_HASHER
    compiler = sys.modules.get("xax_compiler")
    if compiler is None or not hasattr(compiler, "Operation"):
        return None
    partial = sys.modules.get("xax_selfhost_blake3")
    if partial is not None and not hasattr(partial, "native_hasher_usable"):
        return None  # that module is still importing; try again on a later hash
    _HASHER_ATTEMPTED = True
    _HASHER_BUILDING = True
    try:
        from xax_selfhost_blake3 import NativeHasher, native_hasher_usable

        _NATIVE_HASHER = NativeHasher() if native_hasher_usable() else None
    except ImportError:
        # A module on the hasher's path is still importing (its constants hash semantic objects); try again later.
        _NATIVE_HASHER, _HASHER_ATTEMPTED = None, False
    except (OSError, RuntimeError, ValueError) as error:
        _NATIVE_HASHER = None
        import xax_native

        xax_native.fallback("blake3-hash", f"native image failed to load: {error!r}")
    finally:
        _HASHER_BUILDING = False
    return _NATIVE_HASHER


class _OneShot:
    """Buffers input and hashes it in one call to the XAX hash on ``digest``."""

    def __init__(self, hasher, data: bytes = b"") -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("a bytes-like object is required")
        self._hasher = hasher
        self._data = bytearray(data)

    def update(self, data: bytes) -> "_OneShot":
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("a bytes-like object is required")
        self._data += data
        return self

    def digest(self, length: int = _OUT_LEN) -> bytes:
        if length == _OUT_LEN and len(self._data) <= self._hasher.capacity:
            return self._hasher.digest(bytes(self._data))
        return _Blake3(bytes(self._data)).digest(length)

    def hexdigest(self, length: int = _OUT_LEN) -> str:
        return self.digest(length).hex()

    def copy(self) -> "_OneShot":
        return _OneShot(self._hasher, bytes(self._data))


def blake3(data: bytes = b""):
    hasher = _native_hasher()
    return _OneShot(hasher, data) if hasher is not None else _Blake3(data)


__all__ = ["blake3"]
