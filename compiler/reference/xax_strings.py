"""Library-level UTF-8 and explicitly-owned string facilities for XAX tooling.

Strings intentionally remain library values rather than a new core type.  All
indexes returned by this module are UTF-8 byte offsets, matching ``byte_slice``.
Owned strings require an explicit allocator and an explicit ``free`` operation;
there is no finalizer, implicit reallocation, locale, or hidden I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Protocol, Sequence


@dataclass(frozen=True)
class Utf8Validation:
    valid: bool
    error_offset: int | None
    codepoints: int


def _as_bytes(value: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


def validate_utf8(value: bytes | bytearray | memoryview | str) -> Utf8Validation:
    """Validate strict UTF-8 and report the first invalid byte offset.

    Overlong encodings, UTF-16 surrogate code points, truncated sequences, and
    code points above U+10FFFF are rejected.  No replacement decoding occurs.
    """
    data = _as_bytes(value)
    i = 0
    codepoints = 0
    size = len(data)
    while i < size:
        lead = data[i]
        if lead <= 0x7F:
            i += 1
            codepoints += 1
            continue
        if 0xC2 <= lead <= 0xDF:
            need = 1
            minimum_second, maximum_second = 0x80, 0xBF
        elif 0xE0 <= lead <= 0xEF:
            need = 2
            minimum_second = 0xA0 if lead == 0xE0 else 0x80
            maximum_second = 0x9F if lead == 0xED else 0xBF
        elif 0xF0 <= lead <= 0xF4:
            need = 3
            minimum_second = 0x90 if lead == 0xF0 else 0x80
            maximum_second = 0x8F if lead == 0xF4 else 0xBF
        else:
            return Utf8Validation(False, i, codepoints)
        if i + need >= size:
            return Utf8Validation(False, i, codepoints)
        second = data[i + 1]
        if not minimum_second <= second <= maximum_second:
            return Utf8Validation(False, i + 1, codepoints)
        for offset in range(2, need + 1):
            if not 0x80 <= data[i + offset] <= 0xBF:
                return Utf8Validation(False, i + offset, codepoints)
        i += need + 1
        codepoints += 1
    return Utf8Validation(True, None, codepoints)


def require_utf8(value: bytes | bytearray | memoryview | str) -> bytes:
    data = _as_bytes(value)
    status = validate_utf8(data)
    if not status.valid:
        raise UnicodeDecodeError("utf-8", data, status.error_offset or 0, (status.error_offset or 0) + 1, "invalid UTF-8")
    return data


def utf8_boundaries(value: bytes | bytearray | memoryview | str) -> tuple[int, ...]:
    data = require_utf8(value)
    boundaries = [0]
    for index, byte in enumerate(data):
        if index and byte & 0xC0 != 0x80:
            boundaries.append(index)
    if boundaries[-1] != len(data):
        boundaries.append(len(data))
    return tuple(boundaries)


def _require_boundary(data: bytes, offset: int) -> None:
    if offset < 0 or offset > len(data) or (offset < len(data) and data[offset] & 0xC0 == 0x80):
        raise ValueError("UTF-8 offset is not a code-point boundary")


def utf8_find(
    haystack: bytes | bytearray | memoryview | str,
    needle: bytes | bytearray | memoryview | str,
    start: int = 0,
) -> int:
    """Return a byte offset, or -1, while preserving UTF-8 boundaries."""
    source = require_utf8(haystack)
    target = require_utf8(needle)
    _require_boundary(source, start)
    if not target:
        return start
    position = source.find(target, start)
    return position


def utf8_rfind(
    haystack: bytes | bytearray | memoryview | str,
    needle: bytes | bytearray | memoryview | str,
    end: int | None = None,
) -> int:
    source = require_utf8(haystack)
    target = require_utf8(needle)
    stop = len(source) if end is None else end
    _require_boundary(source, stop)
    if not target:
        return stop
    return source.rfind(target, 0, stop)


def utf8_contains(haystack: bytes | bytearray | memoryview | str, needle: bytes | bytearray | memoryview | str) -> bool:
    return utf8_find(haystack, needle) >= 0


def utf8_codepoint_count(value: bytes | bytearray | memoryview | str) -> int:
    status = validate_utf8(value)
    if not status.valid:
        data = _as_bytes(value)
        raise UnicodeDecodeError("utf-8", data, status.error_offset or 0, (status.error_offset or 0) + 1, "invalid UTF-8")
    return status.codepoints


def _format_scalar(value: object, spec: str) -> str:
    if spec in ("", "s"):
        if isinstance(value, bytes):
            return require_utf8(value).decode("utf-8")
        if isinstance(value, (bytearray, memoryview)):
            return require_utf8(value).decode("utf-8")
        if isinstance(value, str):
            return value
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            return repr(value)
        # Do not fall back to arbitrary ``object.__str__``/``__repr__`` here:
        # those hooks may depend on locale, process state, or object addresses
        # and would violate the library's deterministic-formatting contract.
        raise TypeError("default UTF-8 formatting requires str/bytes/bool/int/float")
    if spec == "d":
        if not isinstance(value, int):
            raise TypeError("{...:d} requires an integer")
        return str(int(value))
    if spec in ("x", "X", "b", "o"):
        if not isinstance(value, int):
            raise TypeError(f"{{...:{spec}}} requires an integer")
        return format(value, spec)
    if spec in ("f", "e", "g"):
        if not isinstance(value, (int, float)):
            raise TypeError(f"{{...:{spec}}} requires a number")
        number = float(value)
        if not isfinite(number):
            return str(number).lower()
        return format(number, spec)
    raise ValueError(f"unsupported UTF-8 format specifier: {spec!r}")


def format_utf8(template: bytes | bytearray | memoryview | str, arguments: Sequence[object]) -> bytes:
    """Deterministic locale-independent UTF-8 formatting.

    Supports ``{}``, ``{N}``, optional ``:s/d/x/X/b/o/f/e/g``, and escaped
    braces ``{{``/``}}``.  Automatic and explicit numbering may not be mixed.
    """
    text = require_utf8(template).decode("utf-8")
    output: list[str] = []
    automatic = 0
    mode: str | None = None
    i = 0
    while i < len(text):
        char = text[i]
        if char == "{":
            if i + 1 < len(text) and text[i + 1] == "{":
                output.append("{")
                i += 2
                continue
            close = text.find("}", i + 1)
            if close < 0:
                raise ValueError("unclosed format field")
            field = text[i + 1:close]
            index_text, separator, spec = field.partition(":")
            if index_text == "":
                if mode == "explicit":
                    raise ValueError("cannot mix automatic and explicit field numbering")
                mode = "automatic"
                index = automatic
                automatic += 1
            else:
                if not index_text.isdecimal():
                    raise ValueError("format field index must be a non-negative decimal integer")
                if mode == "automatic":
                    raise ValueError("cannot mix automatic and explicit field numbering")
                mode = "explicit"
                index = int(index_text)
            if index >= len(arguments):
                raise IndexError("format argument index out of range")
            output.append(_format_scalar(arguments[index], spec if separator else ""))
            i = close + 1
            continue
        if char == "}":
            if i + 1 < len(text) and text[i + 1] == "}":
                output.append("}")
                i += 2
                continue
            raise ValueError("unmatched closing brace")
        output.append(char)
        i += 1
    return "".join(output).encode("utf-8")


class StringAllocator(Protocol):
    """Explicit allocator contract used by ``OwnedUtf8String``."""

    def allocate(self, capacity: int) -> object: ...
    def read(self, allocation: object, length: int) -> bytes: ...
    def write(self, allocation: object, data: bytes) -> None: ...
    def free(self, allocation: object) -> None: ...


class BytearrayStringAllocator:
    """Small deterministic allocator for library/interpreter use and tests.

    Allocation handles are opaque integers.  Double-free/use-after-free are
    rejected instead of being silently tolerated.
    """

    def __init__(self) -> None:
        self._next = 1
        self._blocks: dict[int, bytearray] = {}

    @property
    def live_allocations(self) -> int:
        return len(self._blocks)

    def allocate(self, capacity: int) -> object:
        if capacity < 0:
            raise ValueError("capacity must be non-negative")
        handle = self._next
        self._next += 1
        self._blocks[handle] = bytearray(capacity)
        return handle

    def _block(self, allocation: object) -> bytearray:
        if not isinstance(allocation, int) or allocation not in self._blocks:
            raise RuntimeError("string allocation is not live")
        return self._blocks[allocation]

    def read(self, allocation: object, length: int) -> bytes:
        block = self._block(allocation)
        if length < 0 or length > len(block):
            raise ValueError("length exceeds allocation")
        return bytes(block[:length])

    def write(self, allocation: object, data: bytes) -> None:
        block = self._block(allocation)
        if len(data) > len(block):
            raise ValueError("write exceeds allocation")
        block[:len(data)] = data

    def free(self, allocation: object) -> None:
        if not isinstance(allocation, int) or allocation not in self._blocks:
            raise RuntimeError("string allocation is not live")
        del self._blocks[allocation]


@dataclass
class OwnedUtf8String:
    allocator: StringAllocator
    allocation: object
    length: int
    capacity: int
    _live: bool = True

    def _require_live(self) -> None:
        if not self._live:
            raise RuntimeError("owned UTF-8 string has been freed")

    def __copy__(self):
        raise TypeError("owned UTF-8 strings cannot be copied; use clone_owned_utf8")

    def __deepcopy__(self, memo):
        raise TypeError("owned UTF-8 strings cannot be copied; use clone_owned_utf8")

    def bytes(self) -> bytes:
        self._require_live()
        return self.allocator.read(self.allocation, self.length)

    def text(self) -> str:
        return self.bytes().decode("utf-8")

    def free(self) -> None:
        self._require_live()
        self.allocator.free(self.allocation)
        self._live = False


def owned_utf8(allocator: StringAllocator, value: bytes | bytearray | memoryview | str, *, capacity: int | None = None) -> OwnedUtf8String:
    data = require_utf8(value)
    actual_capacity = len(data) if capacity is None else capacity
    if actual_capacity < len(data):
        raise ValueError("capacity is smaller than UTF-8 byte length")
    allocation = allocator.allocate(actual_capacity)
    try:
        allocator.write(allocation, data)
    except Exception:
        allocator.free(allocation)
        raise
    return OwnedUtf8String(allocator, allocation, len(data), actual_capacity)


def clone_owned_utf8(value: OwnedUtf8String, allocator: StringAllocator | None = None) -> OwnedUtf8String:
    target = allocator or value.allocator
    return owned_utf8(target, value.bytes())


def concat_owned_utf8(
    allocator: StringAllocator,
    values: Sequence[bytes | bytearray | memoryview | str | OwnedUtf8String],
) -> OwnedUtf8String:
    parts: list[bytes] = []
    for value in values:
        parts.append(value.bytes() if isinstance(value, OwnedUtf8String) else require_utf8(value))
    return owned_utf8(allocator, b"".join(parts))


def append_owned_utf8(value: OwnedUtf8String, suffix: bytes | bytearray | memoryview | str, *, capacity: int | None = None) -> OwnedUtf8String:
    """Append with explicit ownership transfer.

    The returned value owns the allocation.  If growth is required, this
    function explicitly allocates a replacement and frees the old allocation
    before returning; callers therefore cannot accidentally retain two owners.
    """
    original = value.bytes()
    extra = require_utf8(suffix)
    combined = original + extra
    if len(combined) <= value.capacity:
        value.allocator.write(value.allocation, combined)
        value.length = len(combined)
        return value
    new_capacity = max(len(combined), capacity if capacity is not None else max(1, value.capacity * 2))
    replacement = owned_utf8(value.allocator, combined, capacity=new_capacity)
    value.free()
    return replacement


def format_owned_utf8(allocator: StringAllocator, template: bytes | bytearray | memoryview | str, arguments: Sequence[object]) -> OwnedUtf8String:
    return owned_utf8(allocator, format_utf8(template, arguments))
