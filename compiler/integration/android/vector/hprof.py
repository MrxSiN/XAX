"""Minimal HPROF reader for the Vector runtime harness (validation tooling only).

``am dumpheap`` writes the target's heap from inside the process, with no JVMTI
agent.  Attaching JDWP to a Vector-hosted process aborts ART on API 37 (see
README), so the harness reads loaded classes, live instances and field values
from a heap dump instead.  Only the records ART emits are handled.
"""

from __future__ import annotations

import struct

# Basic type sizes; 2 (object) is the id size.
_SIZE = {4: 1, 5: 2, 6: 4, 7: 8, 8: 1, 9: 2, 10: 4, 11: 8}
# Heap-dump root/info sub-records: tag -> ids, then extra u4 words.
_ROOTS = {0xFF: (1, 0), 0x01: (2, 0), 0x02: (1, 2), 0x03: (1, 2), 0x04: (1, 1), 0x05: (1, 0), 0x06: (1, 1),
          0x07: (1, 0), 0x08: (1, 2), 0x89: (1, 0), 0x8A: (1, 0), 0x8B: (1, 0), 0x8C: (1, 0), 0x8D: (1, 0),
          0x8E: (1, 2), 0x90: (1, 0), 0xFE: (1, 1)}


class Heap:
    def __init__(self, data: bytes):
        if not data.startswith(b"JAVA PROFILE 1.0."):
            raise ValueError("not an HPROF file")
        at = data.index(b"\0") + 1
        self.data, self.idsize = data, struct.unpack_from(">I", data, at)[0]
        self.strings: dict[int, str] = {}
        self.class_names: dict[int, str] = {}  # class id -> JVM signature, e.g. Lxax/generated/XaxModule;
        self.classes: dict[int, tuple[int, int, list[tuple[str, int]]]] = {}  # id -> (super, loader, fields)
        self.instances: dict[int, tuple[int, int, int]] = {}  # id -> (class, offset, length)
        self.arrays: dict[int, tuple[int, int, int]] = {}  # id -> (type, offset, count)
        at += 12
        while at < len(data):
            tag, length = data[at], struct.unpack_from(">I", data, at + 5)[0]
            body = at + 9
            if tag == 0x01:
                self.strings[self._id(body)] = data[body + self.idsize:body + length].decode("utf-8", "replace")
            elif tag == 0x02:
                self.class_names[self._id(body + 4)] = self._id(body + 8 + self.idsize)  # string id, resolved below
            elif tag in (0x0C, 0x1C):
                self._dump(body, body + length)
            at = body + length
        self.class_names = {cid: _signature(self.strings.get(sid, "")) for cid, sid in self.class_names.items()}

    def _id(self, at: int) -> int:
        return int.from_bytes(self.data[at:at + self.idsize], "big")

    def _dump(self, at: int, end: int) -> None:
        data, n = self.data, self.idsize
        while at < end:
            tag = data[at]
            at += 1
            if tag in _ROOTS:
                ids, words = _ROOTS[tag]
                at += ids * n + 4 * words
            elif tag == 0x20:
                cid, superclass, loader = self._id(at), self._id(at + n + 4), self._id(at + 2 * n + 4)
                at += 7 * n + 8  # through instance size
                count, at = struct.unpack_from(">H", data, at)[0], at + 2
                for _ in range(count):  # constant pool: u2 index, type, value
                    at += 3 + self._value_size(data[at + 2])
                count, at = struct.unpack_from(">H", data, at)[0], at + 2
                for _ in range(count):  # statics: name id, type, value
                    at += n + 1 + self._value_size(data[at + n])
                count, at = struct.unpack_from(">H", data, at)[0], at + 2
                fields = []
                for _ in range(count):  # instance fields: name id, type
                    fields.append((self.strings.get(self._id(at), ""), data[at + n]))
                    at += n + 1
                self.classes[cid] = (superclass, loader, fields)
            elif tag == 0x21:
                length = struct.unpack_from(">I", data, at + 2 * n + 4)[0]
                self.instances[self._id(at)] = (self._id(at + n + 4), at + 2 * n + 8, length)
                at += 2 * n + 8 + length
            elif tag == 0x22:
                count = struct.unpack_from(">I", data, at + n + 4)[0]
                at += 2 * n + 8 + count * n
            elif tag == 0x23:
                count, kind = struct.unpack_from(">IB", data, at + n + 4)
                self.arrays[self._id(at)] = (kind, at + n + 9, count)
                at += n + 9 + count * _SIZE[kind]
            elif tag == 0xC3:
                at += n + 9
            else:
                raise ValueError(f"unknown heap sub-record 0x{tag:02x}")

    def _value_size(self, kind: int) -> int:
        return self.idsize if kind == 2 else _SIZE[kind]

    # -- queries ------------------------------------------------------------------------
    def classes_by_signature(self, signature: str) -> list[int]:
        return [cid for cid, name in self.class_names.items() if name == signature]

    def loader(self, class_id: int) -> int:
        return self.classes[class_id][1]

    def instances_of(self, class_id: int) -> list[int]:
        return [obj for obj, (cid, _at, _length) in self.instances.items() if cid == class_id]

    def fields(self, obj: int) -> dict[str, int]:
        """Instance field values (object fields as ids) by name; subclass fields win."""
        cid, at, _length = self.instances[obj]
        values: dict[str, int] = {}
        while cid in self.classes:
            superclass, _loader, fields = self.classes[cid]
            for name, kind in fields:
                size = self._value_size(kind)
                values.setdefault(name, int.from_bytes(self.data[at:at + size], "big"))
                at += size
            cid = superclass
        return values

    def string(self, obj: int) -> str | None:
        if obj not in self.instances or self.class_names.get(self.instances[obj][0]) != "Ljava/lang/String;":
            return None
        array = self.arrays.get(self.fields(obj).get("value", 0))
        if array is None:
            return None
        kind, at, count = array
        raw = self.data[at:at + count * _SIZE[kind]]
        return raw.decode("utf-16-be") if kind == 5 else raw.decode("latin-1")

    def reachable(self, obj: int, depth: int = 2) -> list[int]:
        """Objects referenced by ``obj``'s instance fields, ``depth`` levels deep."""
        found = []
        for value in self.fields(obj).values():
            if value in self.instances:
                found.append(value)
                if depth > 1:
                    found.extend(self.reachable(value, depth - 1))
        return found

    def strings_in(self, obj: int, depth: int = 2) -> list[str]:
        """Strings held by ``obj``'s instance fields, following object fields ``depth`` levels
        (framework objects such as Vector's obfuscated HookHandle nest their data)."""
        found = []
        for value in self.fields(obj).values():
            if (text := self.string(value)) is not None:
                found.append(text)
            elif depth > 1 and value in self.instances:
                found.extend(self.strings_in(value, depth - 1))
        return found


def _signature(name: str) -> str:
    if name.startswith("["):
        return name.replace(".", "/")
    return "L" + name.replace(".", "/") + ";"
