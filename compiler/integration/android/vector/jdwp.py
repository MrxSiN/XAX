"""Minimal JDWP client for the Vector runtime harness (validation tooling only).

The harness observes the XAX-generated module *inside* the Vector-hosted target
process: it suspends a thread at a breakpoint, finds the module instance, reads
its fields and calls its generated helpers.  Only the JDWP commands it needs
are implemented (JDWP spec, Java SE 17): no handwritten module code is loaded.
"""

from __future__ import annotations

from dataclasses import dataclass
import socket
import struct
import time

HANDSHAKE = b"JDWP-Handshake"
REPLY_FLAG = 0x80
EVENT_COMPOSITE = (64, 100)

# Event kinds and modifiers used here.
EVENT_BREAKPOINT, EVENT_CLASS_PREPARE, EVENT_VM_START, EVENT_VM_DEATH = 2, 8, 90, 99
SUSPEND_NONE, SUSPEND_EVENT_THREAD, SUSPEND_ALL = 0, 1, 2
MOD_CLASS_MATCH, MOD_LOCATION_ONLY = 5, 7
TYPE_CLASS = 1
INVOKE_SINGLE_THREADED = 0x01

# Value tags.
TAG_OBJECT_LIKE = frozenset(b"L[stglc")
TAG_SIZE = {ord("Z"): 1, ord("B"): 1, ord("C"): 2, ord("S"): 2, ord("I"): 4, ord("F"): 4, ord("J"): 8, ord("D"): 8, ord("V"): 0}


class JdwpError(RuntimeError):
    def __init__(self, command: tuple[int, int], code: int):
        super().__init__(f"JDWP command {command} failed with error {code}")
        self.code = code


@dataclass(frozen=True)
class Value:
    tag: int
    value: object

    @property
    def is_null(self) -> bool:
        return self.tag in TAG_OBJECT_LIKE and self.value == 0


@dataclass(frozen=True)
class Location:
    type_tag: int
    class_id: int
    method_id: int
    index: int


@dataclass(frozen=True)
class Event:
    kind: int
    request_id: int
    thread: int = 0
    location: Location | None = None
    signature: str = ""


class _Reader:
    def __init__(self, data: bytes, sizes: dict[str, int]):
        self.data, self.offset, self.sizes = data, 0, sizes

    def take(self, size: int) -> bytes:
        chunk = self.data[self.offset:self.offset + size]
        if len(chunk) != size:
            raise ValueError("truncated JDWP packet")
        self.offset += size
        return chunk

    def u1(self) -> int:
        return self.take(1)[0]

    def u4(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def i4(self) -> int:
        return struct.unpack(">i", self.take(4))[0]

    def u8(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def id(self, kind: str) -> int:
        return int.from_bytes(self.take(self.sizes[kind]), "big")

    def string(self) -> str:
        return self.take(self.u4()).decode("utf-8", "replace")

    def location(self) -> Location:
        return Location(self.u1(), self.id("reference"), self.id("method"), self.u8())

    def value(self, tag: int | None = None) -> Value:
        tag = self.u1() if tag is None else tag
        if tag in TAG_OBJECT_LIKE:
            return Value(tag, self.id("object"))
        raw = self.take(TAG_SIZE[tag])
        if tag == ord("F"):
            return Value(tag, struct.unpack(">f", raw)[0])
        if tag == ord("D"):
            return Value(tag, struct.unpack(">d", raw)[0])
        if tag == ord("Z"):
            return Value(tag, bool(raw[0]))
        return Value(tag, int.from_bytes(raw, "big", signed=True) if raw else None)


class Jdwp:
    """One debugger connection.  ``transport`` is any connected socket-like object."""

    def __init__(self, transport: socket.socket, timeout: float = 30.0):
        self.transport = transport
        self.timeout = timeout
        self.next_id = 1
        self.events: list[Event] = []
        self.sizes = {"field": 8, "method": 8, "object": 8, "reference": 8, "frame": 8}
        transport.settimeout(timeout)
        transport.sendall(HANDSHAKE)
        if self._recv_exact(len(HANDSHAKE)) != HANDSHAKE:
            raise ConnectionError("JDWP handshake rejected")
        reader = self._reader(self.command(1, 7))
        self.sizes = dict(zip(("field", "method", "object", "reference", "frame"), (reader.u4() for _ in range(5))))

    @classmethod
    def connect(cls, port: int, host: str = "127.0.0.1", timeout: float = 30.0) -> "Jdwp":
        return cls(socket.create_connection((host, port), timeout=timeout), timeout)

    # -- encoding --------------------------------------------------------------------
    def _reader(self, data: bytes) -> _Reader:
        return _Reader(data, self.sizes)

    def pack_id(self, kind: str, value: int) -> bytes:
        return value.to_bytes(self.sizes[kind], "big")

    @staticmethod
    def pack_string(value: str) -> bytes:
        raw = value.encode("utf-8")
        return struct.pack(">I", len(raw)) + raw

    def pack_value(self, value: Value) -> bytes:
        if value.tag in TAG_OBJECT_LIKE:
            return bytes((value.tag,)) + self.pack_id("object", int(value.value))
        if value.tag == ord("F"):
            return bytes((value.tag,)) + struct.pack(">f", value.value)
        if value.tag == ord("D"):
            return bytes((value.tag,)) + struct.pack(">d", value.value)
        if value.tag == ord("Z"):
            return bytes((value.tag, 1 if value.value else 0))
        return bytes((value.tag,)) + int(value.value).to_bytes(TAG_SIZE[value.tag], "big", signed=True)

    def pack_location(self, location: Location) -> bytes:
        return (bytes((location.type_tag,)) + self.pack_id("reference", location.class_id)
                + self.pack_id("method", location.method_id) + struct.pack(">Q", location.index))

    # -- transport -------------------------------------------------------------------
    def _recv_exact(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.transport.recv(size - len(data))
            if not chunk:
                raise ConnectionError("JDWP connection closed")
            data += chunk
        return data

    def _read_packet(self) -> tuple[int, int, bytes, bytes]:
        length, packet_id, flags = struct.unpack(">IIB", self._recv_exact(9))
        header = self._recv_exact(2)
        return packet_id, flags, header, self._recv_exact(length - 11)

    def _queue_event(self, data: bytes) -> None:
        reader = self._reader(data)
        reader.u1()  # suspend policy
        for _ in range(reader.u4()):
            kind, request = reader.u1(), reader.u4()
            if kind == EVENT_BREAKPOINT:
                self.events.append(Event(kind, request, reader.id("object"), reader.location()))
            elif kind == EVENT_CLASS_PREPARE:
                thread = reader.id("object")
                reader.u1()  # reference type tag
                reader.id("reference")
                self.events.append(Event(kind, request, thread, signature=reader.string()))
                reader.u4()
            elif kind == EVENT_VM_START:
                self.events.append(Event(kind, request, reader.id("object")))
            elif kind == EVENT_VM_DEATH:
                self.events.append(Event(kind, request))
            else:
                return  # an event kind this client never requests; drop the rest

    def command(self, command_set: int, command: int, data: bytes = b"") -> bytes:
        packet_id = self.next_id
        self.next_id += 1
        self.transport.sendall(struct.pack(">IIBBB", 11 + len(data), packet_id, 0, command_set, command) + data)
        while True:
            reply_id, flags, header, body = self._read_packet()
            if flags & REPLY_FLAG and reply_id == packet_id:
                code = struct.unpack(">H", header)[0]
                if code:
                    raise JdwpError((command_set, command), code)
                return body
            if not flags & REPLY_FLAG and tuple(header) == EVENT_COMPOSITE:
                self._queue_event(body)

    def wait_event(self, kinds: set[int], request_ids: set[int] | None = None, timeout: float | None = None) -> Event | None:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            for event in self.events:
                if event.kind in kinds and (request_ids is None or event.request_id in request_ids):
                    self.events.remove(event)
                    return event
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.transport.settimeout(remaining)
            try:
                _packet_id, flags, header, body = self._read_packet()
            except (socket.timeout, TimeoutError):
                return None
            finally:
                self.transport.settimeout(self.timeout)
            if not flags & REPLY_FLAG and tuple(header) == EVENT_COMPOSITE:
                self._queue_event(body)

    # -- commands --------------------------------------------------------------------
    def resume(self) -> None:
        self.command(1, 9)

    def classes_by_signature(self, signature: str) -> list[int]:
        reader = self._reader(self.command(1, 2, self.pack_string(signature)))
        out = []
        for _ in range(reader.u4()):
            reader.u1()
            out.append(reader.id("reference"))
            reader.u4()
        return out

    def first_loaded_class(self, *signatures: str) -> int:
        """The first of ``signatures`` the VM has loaded (JDWP sees loaded classes only)."""
        for signature in signatures:
            if found := self.classes_by_signature(signature):
                return found[0]
        raise LookupError(f"none of {signatures} is loaded")

    def create_string(self, value: str) -> Value:
        return Value(ord("s"), self._reader(self.command(1, 11, self.pack_string(value))).id("object"))

    def signature(self, reference: int) -> str:
        return self._reader(self.command(2, 1, self.pack_id("reference", reference))).string()

    def class_loader(self, reference: int) -> int:
        return self._reader(self.command(2, 2, self.pack_id("reference", reference))).id("object")

    def fields(self, reference: int) -> dict[tuple[str, str], int]:
        reader = self._reader(self.command(2, 4, self.pack_id("reference", reference)))
        out = {}
        for _ in range(reader.u4()):
            field = reader.id("field")
            name, signature = reader.string(), reader.string()
            reader.u4()
            out[(name, signature)] = field
        return out

    def methods(self, reference: int) -> dict[tuple[str, str], int]:
        reader = self._reader(self.command(2, 5, self.pack_id("reference", reference)))
        out = {}
        for _ in range(reader.u4()):
            method = reader.id("method")
            name, signature = reader.string(), reader.string()
            reader.u4()
            out[(name, signature)] = method
        return out

    def instances(self, reference: int, limit: int = 0) -> list[int]:
        reader = self._reader(self.command(2, 16, self.pack_id("reference", reference) + struct.pack(">i", limit)))
        return [reader.value().value for _ in range(reader.u4())]

    def reference_type(self, obj: int) -> int:
        reader = self._reader(self.command(9, 1, self.pack_id("object", obj)))
        reader.u1()
        return reader.id("reference")

    def get_field(self, obj: int, field: int) -> Value:
        reader = self._reader(self.command(9, 2, self.pack_id("object", obj) + struct.pack(">I", 1) + self.pack_id("field", field)))
        reader.u4()
        return reader.value()

    def invoke(self, obj: int, thread: int, reference: int, method: int, *arguments: Value) -> tuple[Value, int]:
        """Call an instance method; returns (result, thrown exception object or 0)."""
        data = (self.pack_id("object", obj) + self.pack_id("object", thread) + self.pack_id("reference", reference)
                + self.pack_id("method", method) + struct.pack(">I", len(arguments))
                + b"".join(self.pack_value(item) for item in arguments) + struct.pack(">I", INVOKE_SINGLE_THREADED))
        reader = self._reader(self.command(9, 6, data))
        result = reader.value()
        return result, reader.value().value

    def new_instance(self, reference: int, thread: int, constructor: int) -> int:
        data = (self.pack_id("reference", reference) + self.pack_id("object", thread) + self.pack_id("method", constructor)
                + struct.pack(">I", 0) + struct.pack(">I", INVOKE_SINGLE_THREADED))
        reader = self._reader(self.command(3, 4, data))
        created, thrown = reader.value(), reader.value()
        if thrown.value:
            raise RuntimeError("constructor threw in the target")
        return int(created.value)

    def string_value(self, obj: int) -> str:
        return self._reader(self.command(10, 1, self.pack_id("object", obj))).string()

    def array_values(self, array: int) -> list[Value]:
        length = self._reader(self.command(13, 1, self.pack_id("object", array))).i4()
        if not length:
            return []
        reader = self._reader(self.command(13, 2, self.pack_id("object", array) + struct.pack(">ii", 0, length)))
        tag, count = reader.u1(), reader.u4()
        return [reader.value(None if tag in TAG_OBJECT_LIKE else tag) for _ in range(count)]

    def stop_thread(self, thread: int, throwable: int) -> None:
        self.command(11, 10, self.pack_id("object", thread) + self.pack_id("object", throwable))

    def set_breakpoint(self, location: Location, suspend: int = SUSPEND_EVENT_THREAD) -> int:
        data = struct.pack(">BBI", EVENT_BREAKPOINT, suspend, 1) + bytes((MOD_LOCATION_ONLY,)) + self.pack_location(location)
        return self._reader(self.command(15, 1, data)).u4()

    def clear_breakpoint(self, request_id: int) -> None:
        self.command(15, 2, struct.pack(">BI", EVENT_BREAKPOINT, request_id))

    def method_entry(self, class_id: int, method_id: int) -> Location:
        return Location(TYPE_CLASS, class_id, method_id, 0)

    def close(self) -> None:
        try:
            self.transport.close()
        except OSError:
            pass


__all__ = ["Event", "Jdwp", "JdwpError", "Location", "Value"]
