"""Minimal XAX canonical store and structural verifier bootstrap.

Human-readable CLI output is diagnostic projection only. Canonical XAX input is
the binary store handled by ``StoreReader`` and ``write_store``.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
from dataclasses import asdict, dataclass, field
from enum import IntEnum, IntFlag
from math import gcd
from pathlib import Path
from typing import Callable, Iterable, Sequence

from blake3 import blake3


MAGIC = b"XAX\0"
TRAILER_MAGIC = b"XAXE"
SEMANTIC_DOMAIN = b"XAX-SEM-1"
CONTAINER_MAJOR = 1
HASH_SUITE = 1
CID_SIZE = 32
PROOF_CACHE_SCHEMA = "xax-proof-cache-v1"
PROOF_CACHE_MAGIC = b"XAXP"
PROOF_CACHE_TRAILER = b"PXAX"
PROOF_CACHE_VERSION = 1
DEFAULT_VERIFIER_IDENTITY = "bootstrap-schema-1"


@dataclass(frozen=True)
class Diagnostic:
    code: str
    entity: str
    rule: str
    expected: object
    actual: object
    dependencies: tuple[str, ...] = ()
    repair_neighborhood: tuple[str, ...] = ()


class XaxError(ValueError):
    def __init__(self, diagnostic: Diagnostic):
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


class XaxTrap(RuntimeError):
    def __init__(self, payload: bytes):
        self.payload = payload
        reason, target_data = decode_trap_payload(payload)
        self.reason = reason
        self.target_data = target_data
        super().__init__(payload.hex())


def fail(
    code: str,
    entity: str,
    rule: str,
    expected: object,
    actual: object,
    dependencies: Iterable[str] = (),
    repair_neighborhood: Iterable[str] = (),
) -> None:
    raise XaxError(
        Diagnostic(
            code,
            entity,
            rule,
            expected,
            actual,
            tuple(dependencies),
            tuple(repair_neighborhood),
        )
    )


def uleb(value: int) -> bytes:
    if value < 0:
        raise ValueError("ULEB128 value must be nonnegative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def zigzag(value: int) -> int:
    return value * 2 if value >= 0 else -value * 2 - 1


class Cursor:
    def __init__(self, data: bytes | memoryview, entity: str = "store"):
        self.data = memoryview(data)
        self.pos = 0
        self.entity = entity

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, size: int, rule: str = "SER-BOUNDS") -> bytes:
        if size < 0 or size > self.remaining:
            fail(
                "XAX.CANON.TRUNCATED",
                self.entity,
                rule,
                f"{size} available bytes",
                self.remaining,
            )
        start = self.pos
        self.pos += size
        return bytes(self.data[start : self.pos])

    def uleb(self) -> int:
        data = self.data
        start = pos = self.pos
        end = len(data)
        value = 0
        shift = 0
        for _ in range(10):
            if pos >= end:
                self.pos = pos
                fail(
                    "XAX.CANON.ULEB_UNTERMINATED",
                    self.entity,
                    "SER-ULEB-TERMINATED",
                    "terminating byte",
                    "end of input",
                )
            byte = data[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                self.pos = pos
                # Minimal ULEB128 never ends in a zero group, except the single byte 00.
                if not byte and pos - start > 1:
                    encoded = bytes(data[start:pos])
                    fail(
                        "XAX.CANON.ULEB_NON_MINIMAL",
                        self.entity,
                        "SER-ULEB-MINIMAL",
                        uleb(value).hex(),
                        encoded.hex(),
                    )
                return value
            shift += 7
        self.pos = pos
        fail(
            "XAX.CANON.ULEB_OVERFLOW",
            self.entity,
            "SER-ULEB-BOUNDED",
            "at most 10 bytes",
            "more than 10 bytes",
        )

    def boolean(self) -> bool:
        value = self.take(1)[0]
        if value > 1:
            fail(
                "XAX.CANON.BOOL",
                self.entity,
                "SER-BOOL-CANONICAL",
                "00 or 01",
                f"{value:02x}",
            )
        return bool(value)

    def zigzag(self) -> int:
        value = self.uleb()
        return -(value // 2) - 1 if value & 1 else value // 2

    def byte_string(self) -> bytes:
        return self.take(self.uleb())

    def end(self, rule: str = "SER-NO-TRAILING") -> None:
        if self.remaining:
            fail(
                "XAX.CANON.TRAILING_BYTES",
                self.entity,
                rule,
                0,
                self.remaining,
            )


class Kind(IntEnum):
    PROGRAM_ROOT = 1
    MODULE = 2
    FUNCTION = 3
    TYPE = 4
    CONSTANT = 5
    TARGET = 6
    GRAPH_FRAGMENT = 7
    RECURSION_GROUP = 8
    PACKAGE = 9
    BUILD = 10
    CALL_CONTRACT = 11


SUPPORTED_KINDS = frozenset(Kind)


def encode_references(references: Sequence[bytes]) -> bytes:
    refs = tuple(references)
    if any(len(cid) != CID_SIZE for cid in refs):
        raise ValueError("CID must be 32 bytes")
    if refs != tuple(sorted(set(refs))):
        raise ValueError("reference table must be sorted and deduplicated")
    return uleb(len(refs)) + b"".join(refs)


def semantic_cid(kind: int, schema_version: int, references: Sequence[bytes], body: bytes) -> bytes:
    content = (
        SEMANTIC_DOMAIN
        + uleb(kind)
        + uleb(schema_version)
        + encode_references(references)
        + uleb(len(body))
        + body
    )
    return blake3(content).digest()


@dataclass(frozen=True)
class SemanticObject:
    kind: Kind
    schema_version: int
    references: tuple[bytes, ...]
    body: bytes
    cid: bytes
    # True only when this instance's CID was computed or checked from its own
    # content (create/decode_object).  Not an init field, so direct construction
    # and dataclasses.replace() always yield an unchecked object.
    cid_checked: bool = field(default=False, init=False, compare=False, repr=False)

    @classmethod
    def create(
        cls,
        kind: Kind,
        body: bytes,
        references: Iterable[bytes] = (),
        schema_version: int = 1,
    ) -> "SemanticObject":
        refs = tuple(sorted(set(references)))
        obj = cls(kind, schema_version, refs, body, semantic_cid(kind, schema_version, refs, body))
        object.__setattr__(obj, "cid_checked", True)
        return obj

    def envelope(self) -> bytes:
        refs = encode_references(self.references)
        payload = (
            self.cid
            + uleb(self.kind)
            + uleb(self.schema_version)
            + refs
            + uleb(len(self.body))
            + self.body
        )
        return uleb(len(payload)) + payload


@dataclass(frozen=True, order=True)
class NonsemanticRecord:
    schema_id: int
    payload: bytes

    def envelope(self) -> bytes:
        content = uleb(self.schema_id) + uleb(len(self.payload)) + self.payload
        return uleb(len(content)) + content


@dataclass(frozen=True, order=True)
class ProofCacheEntry:
    verifier_identity: str
    subject_cid: bytes
    dependencies: tuple[bytes, ...]


@dataclass(frozen=True)
class VerificationStats:
    objects: int
    cache_hits: int
    cache_misses: int
    dependency_cids_checked: int
    cache_entries_before: int
    cache_entries_after: int
    cache_entries_invalidated: int
    cache_entries_written: int


class ProofCache:
    """Deterministic non-semantic cache of successful object verification facts."""

    def __init__(self, entries: Iterable[ProofCacheEntry] = ()):
        self._entries = set(entries)

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def contains(self, verifier_identity: str, obj: "SemanticObject") -> bool:
        return ProofCacheEntry(verifier_identity, obj.cid, obj.references) in self._entries

    def record(self, verifier_identity: str, obj: "SemanticObject") -> bool:
        entry = ProofCacheEntry(verifier_identity, obj.cid, obj.references)
        before = len(self._entries)
        self._entries.add(entry)
        return len(self._entries) != before

    def reconcile(self, verifier_identity: str, objects: Iterable["SemanticObject"]) -> tuple[int, int]:
        current = {ProofCacheEntry(verifier_identity, obj.cid, obj.references) for obj in objects}
        invalidated = len(self._entries - current)
        written = len(current - self._entries)
        self._entries = current
        return invalidated, written

    def prune(self, verifier_identity: str, subject_cids: Iterable[bytes]) -> int:
        current = set(subject_cids)
        retained = {
            entry
            for entry in self._entries
            if entry.verifier_identity == verifier_identity and entry.subject_cid in current
        }
        invalidated = len(self._entries) - len(retained)
        self._entries = retained
        return invalidated

    def canonical_bytes(self) -> bytes:
        out = bytearray(PROOF_CACHE_MAGIC + uleb(PROOF_CACHE_VERSION) + uleb(len(self._entries)))
        for entry in sorted(self._entries):
            try:
                verifier = entry.verifier_identity.encode("ascii")
            except UnicodeEncodeError as error:
                raise ValueError("verifier identity must be ASCII") from error
            if not verifier:
                raise ValueError("verifier identity must not be empty")
            out.extend(uleb(len(verifier)))
            out.extend(verifier)
            out.extend(entry.subject_cid)
            out.extend(uleb(len(entry.dependencies)))
            for cid in entry.dependencies:
                out.extend(cid)
        out.extend(blake3(out).digest())
        out.extend(PROOF_CACHE_TRAILER)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes, entity: str = "proof-cache") -> "ProofCache":
        cursor = Cursor(data, entity)
        if cursor.take(len(PROOF_CACHE_MAGIC), "CACHE-MAGIC") != PROOF_CACHE_MAGIC:
            fail("XAX.CACHE.CORRUPT", entity, "CACHE-MAGIC", PROOF_CACHE_MAGIC.hex(), data[:4].hex())
        version = cursor.uleb()
        if version != PROOF_CACHE_VERSION:
            fail("XAX.CACHE.CORRUPT", entity, "CACHE-VERSION", PROOF_CACHE_VERSION, version)
        entries = []
        previous = None
        for index in range(cursor.uleb()):
            try:
                verifier = cursor.take(cursor.uleb(), "CACHE-VERIFIER").decode("ascii")
            except UnicodeDecodeError as error:
                fail("XAX.CACHE.CORRUPT", f"{entity}:{index}", "CACHE-VERIFIER", "nonempty ASCII", str(error))
            if not verifier:
                fail("XAX.CACHE.CORRUPT", f"{entity}:{index}", "CACHE-VERIFIER", "nonempty ASCII", verifier)
            subject = cursor.take(CID_SIZE, "CACHE-SUBJECT")
            dependencies = tuple(cursor.take(CID_SIZE, "CACHE-DEPENDENCY") for _ in range(cursor.uleb()))
            if dependencies != tuple(sorted(set(dependencies))):
                fail(
                    "XAX.CACHE.CORRUPT",
                    f"{entity}:{index}",
                    "CACHE-DEPENDENCIES",
                    "sorted unique CIDs",
                    [cid.hex() for cid in dependencies],
                )
            entry = ProofCacheEntry(verifier, subject, dependencies)
            if previous is not None and entry <= previous:
                fail("XAX.CACHE.CORRUPT", f"{entity}:{index}", "CACHE-ENTRY-ORDER", "strict canonical order", entry.subject_cid.hex())
            previous = entry
            entries.append(entry)
        digest_end = cursor.pos
        stored_digest = cursor.take(CID_SIZE, "CACHE-DIGEST")
        if cursor.take(len(PROOF_CACHE_TRAILER), "CACHE-TRAILER") != PROOF_CACHE_TRAILER:
            fail("XAX.CACHE.CORRUPT", entity, "CACHE-TRAILER", PROOF_CACHE_TRAILER.hex(), data[-4:].hex())
        cursor.end("CACHE-LENGTH")
        actual_digest = blake3(data[:digest_end]).digest()
        if stored_digest != actual_digest:
            fail("XAX.CACHE.CORRUPT", entity, "CACHE-DIGEST", stored_digest.hex(), actual_digest.hex())
        return cls(entries)

    @classmethod
    def load(cls, path: str | Path) -> "ProofCache":
        source = Path(path)
        if not source.exists():
            return cls()
        return cls.from_bytes(source.read_bytes(), str(source))

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.canonical_bytes())


def decode_object(data: bytes, entity: str = "record") -> SemanticObject:
    outer = Cursor(data, entity)
    payload_length = outer.uleb()
    payload = Cursor(outer.take(payload_length), entity)
    outer.end("SER-RECORD-LENGTH")
    stored_cid = payload.take(CID_SIZE)
    kind_value = payload.uleb()
    try:
        kind = Kind(kind_value)
    except ValueError:
        fail("XAX.SCHEMA.KIND", entity, "SER-KIND-SUPPORTED", sorted(SUPPORTED_KINDS), kind_value)
    schema_version = payload.uleb()
    if schema_version != 1:
        fail("XAX.SCHEMA.VERSION", entity, "SER-SCHEMA-SUPPORTED", 1, schema_version)
    reference_count = payload.uleb()
    references = tuple(payload.take(CID_SIZE) for _ in range(reference_count))
    if references != tuple(sorted(set(references))):
        fail(
            "XAX.CANON.REFERENCE_TABLE",
            entity,
            "SER-REFS-SORTED-UNIQUE",
            "strict unsigned lexicographic order",
            [cid.hex() for cid in references],
        )
    body = payload.take(payload.uleb())
    payload.end("SER-OBJECT-BODY-LENGTH")
    actual_cid = semantic_cid(kind, schema_version, references, body)
    if stored_cid != actual_cid:
        fail(
            "XAX.IDENTITY.CID_MISMATCH",
            entity,
            "ID-CID-INTEGRITY",
            stored_cid.hex(),
            actual_cid.hex(),
        )
    obj = SemanticObject(kind, schema_version, references, body, stored_cid)
    object.__setattr__(obj, "cid_checked", True)
    return obj


def write_store(
    root_cid: bytes,
    objects: Iterable[SemanticObject],
    nonsemantic_records: Iterable[NonsemanticRecord] = (),
) -> bytes:
    ordered, metadata = _store_contents(root_cid, objects, nonsemantic_records)
    return _emit_store(root_cid, ordered.values(), metadata)


def _store_contents(
    root_cid: bytes,
    objects: Iterable[SemanticObject],
    nonsemantic_records: Iterable[NonsemanticRecord],
) -> tuple[dict[bytes, SemanticObject], tuple[NonsemanticRecord, ...]]:
    """Validate store contents; return objects in canonical CID order and sorted metadata."""
    by_cid: dict[bytes, SemanticObject] = {}
    for obj in objects:
        if obj.schema_version != 1 or (
            not obj.cid_checked and obj.cid != semantic_cid(obj.kind, obj.schema_version, obj.references, obj.body)
        ):
            raise ValueError("semantic object is not canonical")
        if obj.cid in by_cid:
            raise ValueError("duplicate semantic object CID")
        by_cid[obj.cid] = obj
    if root_cid not in by_cid:
        raise ValueError("root CID missing from store")

    metadata = tuple(sorted(nonsemantic_records, key=lambda record: record.envelope()))
    if len(metadata) != len(set(metadata)):
        raise ValueError("duplicate non-semantic record")
    return {cid: by_cid[cid] for cid in sorted(by_cid)}, metadata


def _emit_store(root_cid: bytes, ordered: Iterable[SemanticObject], metadata: tuple[NonsemanticRecord, ...]) -> bytes:
    ordered = tuple(ordered)
    out = bytearray(
        MAGIC
        + uleb(CONTAINER_MAJOR)
        + uleb(0)
        + uleb(HASH_SUITE)
        + root_cid
        + uleb(len(ordered))
        + uleb(len(metadata))
        + uleb(0)
    )
    index: list[tuple[bytes, int, int]] = []
    for obj in ordered:
        offset = len(out)
        record = obj.envelope()
        record_length = Cursor(record).uleb()
        out.extend(record)
        index.append((obj.cid, offset, record_length))

    for record in metadata:
        out.extend(record.envelope())

    index_bytes = b"".join(cid + uleb(offset) + uleb(length) for cid, offset, length in index)
    out.extend(uleb(len(index_bytes)))
    out.extend(index_bytes)
    out.extend(blake3(out).digest())
    out.extend(TRAILER_MAGIC)
    return bytes(out)


class StoreReader:
    """Indexed canonical store reader; object bodies decode only on ``get``."""

    def __init__(self, data: bytes, verify_digest: bool = True, proof_cache: ProofCache | None = None):
        self._data: bytes | None = data
        self.proof_cache = proof_cache
        cursor = Cursor(data)
        if cursor.take(4) != MAGIC:
            fail("XAX.CONTAINER.MAGIC", "store", "SER-HEADER-MAGIC", MAGIC.hex(), data[:4].hex())
        major = cursor.uleb()
        if major != CONTAINER_MAJOR:
            fail("XAX.CONTAINER.MAJOR", "store", "SER-MAJOR-SUPPORTED", CONTAINER_MAJOR, major)
        self.minor = cursor.uleb()
        suite = cursor.uleb()
        if suite != HASH_SUITE:
            fail("XAX.CONTAINER.HASH_SUITE", "store", "SER-HASH-SUPPORTED", HASH_SUITE, suite)
        self.root_cid = cursor.take(CID_SIZE)
        object_count = cursor.uleb()
        nonsemantic_count = cursor.uleb()
        flags = cursor.uleb()
        if flags:
            fail("XAX.CONTAINER.FEATURE", "store", "SER-FEATURE-SUPPORTED", 0, flags)
        records: list[tuple[bytes, int, int]] = []
        previous = b""
        for number in range(object_count):
            offset = cursor.pos
            length = cursor.uleb()
            payload = cursor.take(length, "SER-RECORD-LENGTH")
            if len(payload) < CID_SIZE:
                fail("XAX.CANON.RECORD_SHORT", f"record:{number}", "SER-RECORD-ENVELOPE", CID_SIZE, len(payload))
            cid = payload[:CID_SIZE]
            if previous and cid <= previous:
                fail(
                    "XAX.CANON.RECORD_ORDER",
                    f"record:{number}",
                    "SER-RECORDS-SORTED-UNIQUE",
                    f"> {previous.hex()}",
                    cid.hex(),
                )
            previous = cid
            records.append((cid, offset, length))

        metadata: list[NonsemanticRecord] = []
        previous_metadata = b""
        for number in range(nonsemantic_count):
            payload = Cursor(cursor.take(cursor.uleb()), f"metadata:{number}")
            schema_id = payload.uleb()
            body = payload.byte_string()
            payload.end("SER-NONSEMANTIC-LENGTH")
            record = NonsemanticRecord(schema_id, body)
            canonical = record.envelope()
            if previous_metadata and canonical <= previous_metadata:
                fail(
                    "XAX.CANON.NONSEMANTIC_ORDER",
                    f"metadata:{number}",
                    "SER-NONSEMANTIC-SORTED-UNIQUE",
                    "strict canonical byte order",
                    canonical.hex(),
                )
            previous_metadata = canonical
            metadata.append(record)

        index_length = cursor.uleb()
        index_bytes = cursor.take(index_length, "SER-INDEX-LENGTH")
        digest_end = cursor.pos
        stored_digest = cursor.take(CID_SIZE)
        if cursor.take(4) != TRAILER_MAGIC:
            fail("XAX.CONTAINER.TRAILER", "store", "SER-TRAILER-MAGIC", TRAILER_MAGIC.hex(), data[-4:].hex())
        cursor.end("SER-STORE-LENGTH")
        if verify_digest:
            actual_digest = blake3(data[:digest_end]).digest()
            if stored_digest != actual_digest:
                fail(
                    "XAX.INTEGRITY.STORE_DIGEST",
                    "store",
                    "SER-STORE-DIGEST",
                    stored_digest.hex(),
                    actual_digest.hex(),
                )

        index_cursor = Cursor(index_bytes, "index")
        indexed: list[tuple[bytes, int, int]] = []
        for _ in range(object_count):
            indexed.append((index_cursor.take(CID_SIZE), index_cursor.uleb(), index_cursor.uleb()))
        index_cursor.end("SER-INDEX-COUNT")
        if indexed != records:
            fail(
                "XAX.CANON.INDEX",
                "index",
                "SER-INDEX-MATCHES-RECORDS",
                [(c.hex(), o, n) for c, o, n in records],
                [(c.hex(), o, n) for c, o, n in indexed],
            )
        if self.root_cid not in {cid for cid, _, _ in records}:
            fail("XAX.IDENTITY.ROOT_MISSING", "store", "ID-ROOT-PRESENT", self.root_cid.hex(), "missing")
        self._index = {cid: (offset, length) for cid, offset, length in records}
        self._decoded: dict[bytes, SemanticObject] = {}
        self.nonsemantic_records = tuple(metadata)

    @classmethod
    def from_objects(
        cls,
        root_cid: bytes,
        objects: Iterable[SemanticObject],
        nonsemantic_records: Iterable[NonsemanticRecord] = (),
        proof_cache: ProofCache | None = None,
    ) -> "StoreReader":
        """Equivalent to ``StoreReader(write_store(...))`` without redundant hashing.

        Contents are validated exactly as ``write_store`` does.  When every object
        is CID-checked the reader is object-backed and serialized only on demand;
        otherwise it falls back to writing and fully reading the bytes.
        """
        ordered, metadata = _store_contents(root_cid, objects, nonsemantic_records)
        if not all(obj.cid_checked for obj in ordered.values()):
            return cls(_emit_store(root_cid, ordered.values(), metadata), proof_cache=proof_cache)
        # Every object is already CID-checked: canonical bytes and the container
        # digest are produced only if someone reads ``data``.
        reader = cls.__new__(cls)
        reader._data = None
        reader.proof_cache = proof_cache
        reader.minor = 0
        reader.root_cid = bytes(root_cid)
        reader._index = dict.fromkeys(ordered)
        reader._decoded = ordered
        reader.nonsemantic_records = metadata
        return reader

    @property
    def data(self) -> bytes:
        if self._data is None:
            self._data = _emit_store(self.root_cid, self.objects(), self.nonsemantic_records)
        return self._data

    def get(self, cid: bytes) -> SemanticObject:
        # The store bytes are immutable, so each record is decoded and CID-checked once.
        obj = self._decoded.get(cid)
        if obj is not None:
            return obj
        try:
            offset, length = self._index[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "stored object", "missing")
        cursor = Cursor(self.data[offset:], f"object:{cid.hex()}")
        actual_length = cursor.uleb()
        if actual_length != length:
            fail("XAX.CANON.INDEX_LENGTH", cid.hex(), "SER-INDEX-RECORD-LENGTH", length, actual_length)
        prefix_size = cursor.pos
        obj = decode_object(self.data[offset : offset + prefix_size + length], f"object:{cid.hex()}")
        self._decoded[cid] = obj
        return obj

    def objects(self) -> Iterable[SemanticObject]:
        for cid in sorted(self._index):
            yield self.get(cid)

    @property
    def object_cids(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._index))

    def canonical_bytes(self) -> bytes:
        return write_store(self.root_cid, self.objects(), self.nonsemantic_records)


def ref_body(indices: Sequence[int]) -> bytes:
    return uleb(len(indices)) + b"".join(uleb(index) for index in indices)


def object_with_refs(kind: Kind, referenced: Sequence[SemanticObject]) -> SemanticObject:
    if kind not in (Kind.PROGRAM_ROOT, Kind.MODULE):
        raise ValueError("reference-list body is only valid for program_root and module")
    refs = tuple(sorted({obj.cid for obj in referenced}))
    return SemanticObject.create(kind, ref_body(range(len(refs))), refs)


def target(identity: bytes) -> SemanticObject:
    if not identity:
        raise ValueError("target identity must not be empty")
    return SemanticObject.create(Kind.TARGET, uleb(len(identity)) + identity)


@dataclass(frozen=True)
class AtomicTargetCapability:
    support: "AtomicSupport"
    lock_free: "LockFree"
    retry_behavior: "RetryBehavior"
    required_alignment: int
    supported_orders: tuple["AtomicOrder", ...]
    supported_scopes: tuple["AtomicScope", ...]
    latency_bound: int | None = None
    max_inline_instructions: int | None = None
    runtime_helper: bytes = b""


@dataclass(frozen=True)
class AtomicLegalizationPolicy:
    """Build policy for target-declared non-native atomic implementations."""

    permit_bounded_inline: bool = True
    permit_runtime_assist: bool = False


class AtomicFamily(IntEnum):
    LOAD = 1
    STORE = 2
    RMW = 3
    CMPXCHG = 4
    FENCE = 5


class AtomicOrder(IntEnum):
    RELAXED = 1
    ACQUIRE = 2
    RELEASE = 3
    ACQ_REL = 4
    SEQ_CST = 5


class AtomicScope(IntEnum):
    SYSTEM = 1
    DEVICE = 2
    WORKGROUP = 3


class AtomicRmwKind(IntEnum):
    EXCHANGE = 1
    ADD_WRAP = 2


class CompareExchangeStrength(IntEnum):
    STRONG = 1
    WEAK = 2


class AtomicSupport(IntEnum):
    NATIVE = 1
    BOUNDED_SEQUENCE = 2
    RUNTIME_ASSIST = 3
    UNSUPPORTED = 4


class LockFree(IntEnum):
    ALWAYS = 1
    CONDITIONAL = 2
    NO = 3


class RetryBehavior(IntEnum):
    NONE = 1
    STATICALLY_BOUNDED = 2
    POTENTIALLY_UNBOUNDED = 3


@dataclass(frozen=True)
class HandlerEntryContract:
    event_kind: int
    entry_abi: int
    privilege: int
    priority: int
    nesting_policy: int
    reentrancy_policy: int
    saved_machine_state: int
    allowed_effect_domains: tuple["EffectDomain", ...]
    stack_bound: int
    return_contract: int


class TargetValueConstraintKind(IntEnum):
    BITS = 1
    RESOURCE = 2
    EFFECT = 3
    FUNCTION_POINTER = 4
    POINTER = 5


# OI-07 bounded DMA vocabulary.  These state IDs are semantic resource states,
# not target opcodes: both OI-07 target packages below use the same values.
DMA_RESOURCE_KIND = 1002


class DmaResourceState(IntEnum):
    HOST_UNMAPPED = 1
    HOST_MAPPED = 2
    HOST_DIRTY = 3
    DEVICE_OWNED = 4
    DEVICE_PENDING = 5
    HOST_STALE = 6


class DmaAction(IntEnum):
    ACQUIRE = 1
    MAP = 2
    HOST_WRITE = 3
    CACHE_CLEAN = 4
    DEVICE_ACQUIRE = 5
    DEVICE_WRITE = 6
    SYNCHRONIZE = 7
    HOST_ACQUIRE = 8
    CACHE_INVALIDATE = 9
    HOST_READ = 10
    UNMAP = 11
    RELEASE = 12


@dataclass(frozen=True)
class TargetValueConstraint:
    kind: TargetValueConstraintKind
    primary: int
    secondary: int = 0


@dataclass(frozen=True)
class AcceleratorMemorySpace:
    identity: int
    address_bits: int
    address_unit_bits: int
    minimum_alignment: int
    access_widths: tuple[int, ...]
    visibility_scopes: tuple["AtomicScope", ...]
    host_visible: bool
    device_visible: bool


@dataclass(frozen=True)
class TargetOperationContract:
    operation_id: int
    semantic_code: int
    encoding_opcode: int
    operands: tuple[TargetValueConstraint, ...]
    results: tuple[TargetValueConstraint, ...]
    supported_scopes: tuple["AtomicScope", ...]
    source_space: int
    destination_space: int
    synchronizes: bool
    may_block: bool
    runtime_dependency: bytes = b""


@dataclass(frozen=True)
class NativeTargetDescription:
    identity: bytes
    architecture: int
    abi: int
    image_format: int
    word_bits: int
    pointer_bits: int
    stack_alignment: int
    shadow_space: int
    argument_registers: tuple[int, ...]
    result_register: int | None
    scratch_registers: tuple[int, ...]
    supported_operations: tuple[int, ...]
    supported_terminators: tuple[int, ...]
    atomic_widths: tuple[int, ...] = ()
    atomic_scopes: tuple[AtomicScope, ...] = ()
    atomic_families: tuple[AtomicFamily, ...] = ()
    handler_entries: tuple[HandlerEntryContract, ...] = ()
    accelerator_lane_width: int = 0
    accelerator_max_groups: int = 0
    accelerator_scopes: tuple[AtomicScope, ...] = ()
    memory_spaces: tuple[AcceleratorMemorySpace, ...] = ()
    target_operations: tuple[TargetOperationContract, ...] = ()


def _x86_64_windows_target(
    identity: bytes,
    operations: tuple[int, ...],
    machine: tuple[int, ...] = (2, 1, 1, 1, 64, 64, 16, 32),
) -> SemanticObject:
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in machine:
        body.extend(uleb(value))
    body.extend(uleb(4) + bytes((1, 2, 8, 9)))
    body.extend(uleb(0))
    body.extend(uleb(2) + bytes((10, 11)))
    body.extend(uleb(len(operations)) + bytes(operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    body.extend(uleb(2) + uleb(32) + uleb(64))
    body.extend(uleb(1) + uleb(AtomicScope.SYSTEM))
    body.extend(uleb(5) + b"".join(uleb(family) for family in AtomicFamily))
    handler = HandlerEntryContract(
        1, 1, 0, 0, 1, 1, 1, (EffectDomain.MEMORY, EffectDomain.ATOMIC), 4096, 1
    )
    body.extend(uleb(1))
    for value in (
        handler.event_kind,
        handler.entry_abi,
        handler.privilege,
        handler.priority,
        handler.nesting_policy,
        handler.reentrancy_policy,
        handler.saved_machine_state,
    ):
        body.extend(uleb(value))
    body.extend(uleb(len(handler.allowed_effect_domains)))
    body.extend(b"".join(uleb(domain) for domain in handler.allowed_effect_domains))
    body.extend(uleb(handler.stack_bound) + uleb(handler.return_contract))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def x86_64_windows_target() -> SemanticObject:
    return _x86_64_windows_target(
        b"x86_64-windows-load-image-v2",
        (1, 2, 3, *range(5, 25)),
    )


# x86-64 Linux hosted executable: XAX-internal calls keep the x64 register
# convention of the general profile; the only external boundaries are the
# Linux process-entry contract and declared ``linux-x86_64-syscall-v1`` calls.
X86_64_LINUX_ABI = 5
X86_64_LINUX_ELF_EXEC_FORMAT = 5
# Same machine profile, plus an explicit dynamic-loader capability: ELF64
# ET_EXEC with PT_INTERP (/lib64/ld-linux-x86-64.so.2), DT_NEEDED derived only
# from declared ``sysv-x86_64-c`` imports, and bind-now GOT relocations.
X86_64_LINUX_ELF_DYNAMIC_FORMAT = 6
X86_64_LINUX_OPERATIONS = (
    1, 2, 3, *range(5, 25),
    38, 39, 40, 41, 42, 43, *range(44, 62), 62, 63, *range(66, 74),
)


def x86_64_linux_exec_target() -> SemanticObject:
    """Static ELF64 ET_EXEC for Linux x86-64 with no libc, loader, or runtime."""
    return _x86_64_windows_target(
        b"x86_64-linux-elf-exec-v1",
        tuple(sorted(set(X86_64_LINUX_OPERATIONS))),
        machine=(2, 1, X86_64_LINUX_ABI, X86_64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 32),
    )


def x86_64_linux_dynamic_exec_target() -> SemanticObject:
    """Linux x86-64 ELF64 executable that explicitly requests the system dynamic loader."""
    return _x86_64_windows_target(
        b"x86_64-linux-elf-dynexec-v1",
        tuple(sorted(set(X86_64_LINUX_OPERATIONS))),
        machine=(2, 1, X86_64_LINUX_ABI, X86_64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 32),
    )


def x86_64_windows_general_target() -> SemanticObject:
    return _x86_64_windows_target(
        b"x86_64-windows-load-image-v5",
        (
            1, 2, 3, *range(5, 25),
            Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE,
            Operation.FUNCTION_ADDRESS, Operation.CALL_INDIRECT, *range(44, 61),
            Operation.BIT_XOR, Operation.ROTATE_RIGHT,
        ),
    )


def x86_64_windows_pe_target() -> SemanticObject:
    """v5 plus explicit Win64 foreign calls; v5 stays byte-identical.

    Only the PE container binds foreign calls (import slots); raw load images reject them.
    """
    return _x86_64_windows_target(
        b"x86_64-windows-pe-v1",
        (
            1, 2, 3, *range(5, 25),
            Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE,
            Operation.FUNCTION_ADDRESS, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT, *range(44, 62),
            Operation.BIT_XOR, Operation.ROTATE_RIGHT, Operation.POINTER_ADDRESS,
        ),
    )


WASM32_WASI_IDENTITY = b"wasm32-wasi-v1"


def wasm32_wasi_target() -> SemanticObject:
    """wasm32 general profile plus explicit ``wasm32-import`` foreign calls.

    The container exports ``memory`` and ``_start`` (WASI command ABI); host
    functions are module imports named by their foreign declarations.
    """
    return wasm32_general_target(WASM32_WASI_IDENTITY, (Operation.CALL_FOREIGN, Operation.POINTER_ADDRESS, Operation.POINTER_REBASE))


def wasm32_general_target(identity: bytes = b"wasm32-core-module-v2", extra: tuple[int, ...] = ()) -> SemanticObject:
    """wasm32 core module with native f32/f64 plus memory-backed aggregates and sums."""
    operations = (
        1, 2, 3, *range(5, 20),
        Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE,
        *range(44, 61), *extra,
    )
    operations = tuple(sorted(operations))
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (1, 2, 2, 2, 64, 32):
        body.extend(uleb(value))
    body.extend(uleb(len(operations)) + bytes(int(value) for value in operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def wasm32_target() -> SemanticObject:
    identity = b"wasm32-core-module-v1"
    operations = (1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19)
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (1, 2, 2, 2, 64, 32):
        body.extend(uleb(value))
    body.extend(uleb(len(operations)) + bytes(operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def oi06_x86_64_windows_target() -> SemanticObject:
    """Measurement-only x86-64 target package advertising the OI-06 memory candidates."""
    identity = b"x86_64-windows-load-image-oi06-v1"
    operations = (1, 2, 3, *range(5, 25), Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE)
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (2, 1, 1, 1, 64, 64, 16, 32):
        body.extend(uleb(value))
    body.extend(uleb(4) + bytes((1, 2, 8, 9)))
    body.extend(uleb(0))
    body.extend(uleb(2) + bytes((10, 11)))
    body.extend(uleb(len(operations)) + bytes(int(value) for value in operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    body.extend(uleb(2) + uleb(32) + uleb(64))
    body.extend(uleb(1) + uleb(AtomicScope.SYSTEM))
    body.extend(uleb(5) + b"".join(uleb(family) for family in AtomicFamily))
    handler = HandlerEntryContract(1, 1, 0, 0, 1, 1, 1, (EffectDomain.MEMORY, EffectDomain.ATOMIC), 4096, 1)
    body.extend(uleb(1))
    for value in (handler.event_kind, handler.entry_abi, handler.privilege, handler.priority, handler.nesting_policy, handler.reentrancy_policy, handler.saved_machine_state):
        body.extend(uleb(value))
    body.extend(uleb(len(handler.allowed_effect_domains)))
    body.extend(b"".join(uleb(domain) for domain in handler.allowed_effect_domains))
    body.extend(uleb(handler.stack_bound) + uleb(handler.return_contract))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def oi06_wasm32_target() -> SemanticObject:
    """Measurement-only WebAssembly target package advertising the OI-06 memory candidates."""
    identity = b"wasm32-core-module-oi06-v1"
    operations = (1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE, Operation.RAW_LOAD_BITS_LE)
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (1, 2, 2, 2, 64, 32):
        body.extend(uleb(value))
    body.extend(uleb(len(operations)) + bytes(int(value) for value in operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def aarch64_baremetal_target() -> SemanticObject:
    identity = b"aarch64-baremetal-load-image-v1"
    operations = (1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19)
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (1, 3, 3, 1, 64, 64, 16, 0):
        body.extend(uleb(value))
    body.extend(uleb(8) + bytes(range(8)))
    body.extend(uleb(0))
    body.extend(uleb(2) + bytes((9, 10)))
    body.extend(uleb(len(operations)) + bytes(operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def aarch64_baremetal_atomic_target() -> SemanticObject:
    """AArch64 bare-metal profile with the OI-11 load/store atomic capability.

    The target remains an ordinary profile-2 target package.  The backend
    implements relaxed/acquire/release directly and seq-cst load/store through
    finite barrier/access sequences; no helper or retry loop is available.
    """
    identity = b"aarch64-baremetal-atomic-v1"
    operations = (
        1, 2, 3, *range(5, 22),
    )
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (2, 3, 3, 1, 64, 64, 16, 0):
        body.extend(uleb(value))
    body.extend(uleb(8) + bytes(range(8)))
    body.extend(uleb(0))
    body.extend(uleb(2) + bytes((9, 10)))
    body.extend(uleb(len(operations)) + bytes(int(value) for value in operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    body.extend(uleb(2) + uleb(32) + uleb(64))
    body.extend(uleb(1) + uleb(AtomicScope.SYSTEM))
    body.extend(uleb(2) + uleb(AtomicFamily.LOAD) + uleb(AtomicFamily.STORE))
    body.extend(uleb(0))  # no interrupt/handler contracts added by this profile
    return SemanticObject.create(Kind.TARGET, bytes(body))


# CHECKED_LOAD/STORE_BITS_LE, FUNCTION_ADDRESS, CALL_INDIRECT, FLOAT_ADD..FLOAT_TO_SINT_TRUNC;
# plain ints because Operation is defined later in this module.
AARCH64_GENERAL_OPERATIONS = (38, 39, 41, 43, *range(44, 61))


def aarch64_baremetal_general_target() -> SemanticObject:
    """AAPCS64 bare-metal image with float, aggregate, sum, and conversion parity."""
    identity = b"aarch64-baremetal-load-image-v2"
    operations = tuple(sorted({1, 2, 3, *range(5, 20), *(int(value) for value in AARCH64_GENERAL_OPERATIONS)}))
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (1, 3, 3, 1, 64, 64, 16, 0):
        body.extend(uleb(value))
    body.extend(uleb(8) + bytes(range(8)))
    body.extend(uleb(0))
    body.extend(uleb(2) + bytes((9, 10)))
    body.extend(uleb(len(operations)) + bytes(operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    return SemanticObject.create(Kind.TARGET, bytes(body))


ANDROID_JNI_ENV_FUNCTIONS_OPERATION = 10
ANDROID_JNI_REFERENCE_RESOURCE_KIND = 2001
ANDROID_JNI_REFERENCE_WORD_BORROWED_OPERATION = 11
ANDROID_JNI_REFERENCE_WORD_LOCAL_OPERATION = 12
ANDROID_JNI_REFERENCE_WORD_GLOBAL_OPERATION = 13
ANDROID_JNI_NATIVE_OPERATION_BASE = 1000
_ANDROID_JNI_INVOKE_OPERATION_BY_SLOT = {
    3: 6,  # DestroyJavaVM
    4: 7,  # AttachCurrentThread
    5: 8,  # DetachCurrentThread
    6: 5,  # GetEnv -- retained for v1 graph compatibility
    7: 9,  # AttachCurrentThreadAsDaemon
}


def android_jni_invoke_operation(slot: int) -> int:
    try:
        return _ANDROID_JNI_INVOKE_OPERATION_BY_SLOT[int(slot)]
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("JNI invocation slot must be one of 3..7") from error


def android_jni_native_operation(slot: int) -> int:
    slot = int(slot)
    if not 4 <= slot <= 232:
        raise ValueError("Android JNI 1.6 native-interface slot must be in 4..232")
    return ANDROID_JNI_NATIVE_OPERATION_BASE + slot


def android_arm64_shared_target() -> SemanticObject:
    """Android arm64-v8a ET_DYN target sharing the existing AAPCS64 backend.

    Profile 4 carries only bounded platform-ABI target operations; Android
    concepts stay in this target package rather than the fundamental language.
    """
    return _android_arm64_shared_target(
        b"android-arm64-v8a-shared-v3",
        (1, 2, 3, *range(5, 20), Operation.FUNCTION_ADDRESS, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT, Operation.TARGET_OP),
    )


def android_arm64_shared_general_target() -> SemanticObject:
    """v3 plus float/aggregate/sum/conversion parity and foreign-heap views.

    v3 stays byte-identical so existing Android artifacts keep their identity.
    """
    return _android_arm64_shared_target(
        b"android-arm64-v8a-shared-v4",
        (
            1, 2, 3, *range(5, 20), Operation.FUNCTION_ADDRESS, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT,
            Operation.TARGET_OP, *AARCH64_GENERAL_OPERATIONS, Operation.HEAP_VIEW,
        ),
    )


ANDROID_ARM64_SHARED_IDENTITIES = (
    b"android-arm64-v8a-shared-v1", b"android-arm64-v8a-shared-v2",
    b"android-arm64-v8a-shared-v3", b"android-arm64-v8a-shared-v4",
)


def _android_arm64_shared_target(identity: bytes, operations: Sequence[int]) -> SemanticObject:
    operations = tuple(sorted({int(value) for value in operations}))
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (4, 3, 4, 4, 64, 64, 16, 0):
        body.extend(uleb(value))
    body.extend(uleb(8) + bytes(range(8)))
    body.extend(uleb(0))
    body.extend(uleb(2) + bytes((9, 10)))
    body.extend(uleb(len(operations)) + b"".join(uleb(int(value)) for value in operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))

    bits32 = TargetValueConstraint(TargetValueConstraintKind.BITS, 32)
    bits64 = TargetValueConstraint(TargetValueConstraintKind.BITS, 64)
    pointer = TargetValueConstraint(TargetValueConstraintKind.POINTER, 0, 0)
    function_pointer = TargetValueConstraint(TargetValueConstraintKind.FUNCTION_POINTER, 0, 0)
    memory = TargetValueConstraint(TargetValueConstraintKind.EFFECT, EffectDomain.MEMORY, 1)
    # Fixed-offset ABI loads.  The operation IDs are package-local; the graph
    # still uses the universal TARGET_OP operation and explicit memory effect.
    contracts = [
        TargetOperationContract(1, 1, 0, (pointer, memory), (bits32, memory), (AtomicScope.SYSTEM,), 0, 0, False, False),  # NativeAPIEntries.version @ 0
        TargetOperationContract(2, 2, 8, (pointer, memory), (function_pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False),  # hook_func @ 8
        TargetOperationContract(3, 3, 16, (pointer, memory), (function_pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False), # unhook_func @ 16
        TargetOperationContract(4, 4, 0, (pointer, memory), (pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False),  # JavaVM.functions @ 0
        TargetOperationContract(5, 5, 48, (pointer, memory), (function_pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False), # JNIInvokeInterface.GetEnv @ 6*8 (v1 ID retained)
        TargetOperationContract(6, 6, 24, (pointer, memory), (function_pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False), # DestroyJavaVM @ 3*8
        TargetOperationContract(7, 7, 32, (pointer, memory), (function_pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False), # AttachCurrentThread @ 4*8
        TargetOperationContract(8, 8, 40, (pointer, memory), (function_pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False), # DetachCurrentThread @ 5*8
        TargetOperationContract(9, 9, 56, (pointer, memory), (function_pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False), # AttachCurrentThreadAsDaemon @ 7*8
        TargetOperationContract(ANDROID_JNI_ENV_FUNCTIONS_OPERATION, 10, 0, (pointer, memory), (pointer, memory), (AtomicScope.SYSTEM,), 0, 0, False, False), # JNIEnv.functions @ 0
        # JNI object references are opaque pointer-shaped ABI handles.  These
        # operations expose the exact 64-bit AAPCS64 word used by jvalue.l
        # without making pointer-to-integer conversion a kernel operation.
        # Owned reference forms thread the linear JNI lifetime token unchanged.
        TargetOperationContract(
            ANDROID_JNI_REFERENCE_WORD_BORROWED_OPERATION,
            11,
            0,
            (pointer,),
            (bits64,),
            (AtomicScope.SYSTEM,),
            0,
            0,
            False,
            False,
        ),
        TargetOperationContract(
            ANDROID_JNI_REFERENCE_WORD_LOCAL_OPERATION,
            12,
            0,
            (
                pointer,
                TargetValueConstraint(TargetValueConstraintKind.RESOURCE, ANDROID_JNI_REFERENCE_RESOURCE_KIND, 2),
            ),
            (
                bits64,
                TargetValueConstraint(TargetValueConstraintKind.RESOURCE, ANDROID_JNI_REFERENCE_RESOURCE_KIND, 2),
            ),
            (AtomicScope.SYSTEM,),
            0,
            0,
            False,
            False,
        ),
        TargetOperationContract(
            ANDROID_JNI_REFERENCE_WORD_GLOBAL_OPERATION,
            13,
            0,
            (
                pointer,
                TargetValueConstraint(TargetValueConstraintKind.RESOURCE, ANDROID_JNI_REFERENCE_RESOURCE_KIND, 3),
            ),
            (
                bits64,
                TargetValueConstraint(TargetValueConstraintKind.RESOURCE, ANDROID_JNI_REFERENCE_RESOURCE_KIND, 3),
            ),
            (AtomicScope.SYSTEM,),
            0,
            0,
            False,
            False,
        ),
    ]
    # Android's public jni.h is the JNI 1.6 table.  Slots 0..3 are reserved;
    # every callable slot 4..232 is exposed as a package-local fixed-offset
    # function-pointer load.  Signatures remain explicit CallContract objects;
    # the kernel gains no JNI-specific operation vocabulary.
    contracts.extend(
        TargetOperationContract(
            android_jni_native_operation(slot),
            android_jni_native_operation(slot),
            slot * 8,
            (pointer, memory),
            (function_pointer, memory),
            (AtomicScope.SYSTEM,),
            0,
            0,
            False,
            False,
        )
        for slot in range(4, 233)
    )
    contracts = tuple(sorted(contracts, key=lambda item: item.operation_id))
    body.extend(uleb(len(contracts)))
    for contract in contracts:
        body.extend(uleb(contract.operation_id) + uleb(contract.semantic_code) + uleb(contract.encoding_opcode))
        for constraints in (contract.operands, contract.results):
            body.extend(uleb(len(constraints)))
            for item in constraints:
                body.extend(uleb(item.kind) + uleb(item.primary) + uleb(item.secondary))
        body.extend(uleb(len(contract.supported_scopes)))
        body.extend(b"".join(uleb(scope) for scope in contract.supported_scopes))
        body.extend(uleb(contract.source_space) + uleb(contract.destination_space))
        body.extend(bytes((contract.synchronizes, contract.may_block)))
        body.extend(uleb(0))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def _oi07_dma_target(*, coherent: bool) -> SemanticObject:
    """Measurement target for OI-07 DMA state-vocabulary evidence.

    The two packages intentionally differ in their memory model while sharing
    DmaResourceState values.  They remain ordinary immutable target packages;
    no DMA behavior is hardcoded into the fundamental graph representation.
    """

    identity = b"oi07-coherent-shared-dma-v1" if coherent else b"oi07-noncoherent-split-dma-v1"
    operations = (Operation.TARGET_OP.value,)
    terminators = (TerminatorKind.RETURN.value, TerminatorKind.TRAP.value)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (3, 4, 4, 3, 32, 64):
        body.extend(uleb(value))
    body.extend(uleb(len(operations)) + b"".join(uleb(value) for value in operations))
    body.extend(uleb(len(terminators)) + b"".join(uleb(value) for value in terminators))

    body.extend(uleb(1) + uleb(65535))
    scopes = (AtomicScope.SYSTEM, AtomicScope.DEVICE)
    body.extend(uleb(len(scopes)) + b"".join(uleb(scope) for scope in scopes))

    if coherent:
        spaces = ((1, 64, 8, 4, (32,), scopes, True, True),)
    else:
        spaces = (
            (1, 64, 8, 4, (32,), (AtomicScope.SYSTEM,), True, False),
            (2, 64, 8, 4, (32,), (AtomicScope.DEVICE,), False, True),
        )
    body.extend(uleb(len(spaces)))
    for space_id, address_bits, unit_bits, alignment, widths, visible_scopes, host_visible, device_visible in spaces:
        body.extend(uleb(space_id) + uleb(address_bits) + uleb(unit_bits) + uleb(alignment))
        body.extend(uleb(len(widths)) + b"".join(uleb(width) for width in widths))
        body.extend(uleb(len(visible_scopes)) + b"".join(uleb(scope) for scope in visible_scopes))
        body.extend(bytes((host_visible, device_visible)))

    bits32 = TargetValueConstraint(TargetValueConstraintKind.BITS, 32)
    effect = TargetValueConstraint(TargetValueConstraintKind.EFFECT, EffectDomain.DEVICE, 7)
    state = lambda value: TargetValueConstraint(TargetValueConstraintKind.RESOURCE, DMA_RESOURCE_KIND, int(value))
    host_unmapped = state(DmaResourceState.HOST_UNMAPPED)
    host_mapped = state(DmaResourceState.HOST_MAPPED)
    host_dirty = state(DmaResourceState.HOST_DIRTY)
    device_owned = state(DmaResourceState.DEVICE_OWNED)
    device_pending = state(DmaResourceState.DEVICE_PENDING)
    host_stale = state(DmaResourceState.HOST_STALE)
    device_space = 1 if coherent else 2

    contracts = [
        TargetOperationContract(DmaAction.ACQUIRE, DmaAction.ACQUIRE, 0x40, (effect,), (host_unmapped, effect), (AtomicScope.SYSTEM,), 1, 1, False, False),
        TargetOperationContract(DmaAction.MAP, DmaAction.MAP, 0x41, (host_unmapped, effect), (host_mapped, effect), (AtomicScope.SYSTEM,), 1, 1, False, False),
        TargetOperationContract(DmaAction.HOST_WRITE, DmaAction.HOST_WRITE, 0x42, (bits32, host_mapped, effect), ((host_mapped if coherent else host_dirty), effect), (AtomicScope.SYSTEM,), 1, 1, False, False),
    ]
    if not coherent:
        contracts.append(TargetOperationContract(DmaAction.CACHE_CLEAN, DmaAction.CACHE_CLEAN, 0x43, (host_dirty, effect), (host_mapped, effect), (AtomicScope.SYSTEM,), 1, 1, False, False))
    contracts.extend((
        TargetOperationContract(DmaAction.DEVICE_ACQUIRE, DmaAction.DEVICE_ACQUIRE, 0x44, (host_mapped, effect), (device_owned, effect), (AtomicScope.DEVICE,), 1, device_space, False, False),
        TargetOperationContract(DmaAction.DEVICE_WRITE, DmaAction.DEVICE_WRITE, 0x45, (bits32, device_owned, effect), (device_pending, effect), (AtomicScope.DEVICE,), device_space, device_space, False, False),
        TargetOperationContract(DmaAction.SYNCHRONIZE, DmaAction.SYNCHRONIZE, 0x46, (device_pending, effect), (device_owned, effect), (AtomicScope.DEVICE,), device_space, device_space, True, True),
        TargetOperationContract(DmaAction.HOST_ACQUIRE, DmaAction.HOST_ACQUIRE, 0x47, (device_owned, effect), ((host_mapped if coherent else host_stale), effect), (AtomicScope.SYSTEM,), device_space, 1, False, False),
    ))
    if not coherent:
        contracts.append(TargetOperationContract(DmaAction.CACHE_INVALIDATE, DmaAction.CACHE_INVALIDATE, 0x48, (host_stale, effect), (host_mapped, effect), (AtomicScope.SYSTEM,), 1, 1, False, False))
    contracts.extend((
        TargetOperationContract(DmaAction.HOST_READ, DmaAction.HOST_READ, 0x49, (host_mapped, effect), (bits32, host_mapped, effect), (AtomicScope.SYSTEM,), 1, 1, False, False),
        TargetOperationContract(DmaAction.UNMAP, DmaAction.UNMAP, 0x4A, (host_mapped, effect), (host_unmapped, effect), (AtomicScope.SYSTEM,), 1, 1, False, False),
        TargetOperationContract(DmaAction.RELEASE, DmaAction.RELEASE, 0x4B, (host_unmapped, effect), (effect,), (AtomicScope.SYSTEM,), 1, 1, False, False),
    ))
    contracts = tuple(sorted(contracts, key=lambda item: item.operation_id))
    body.extend(uleb(len(contracts)))
    for contract in contracts:
        body.extend(uleb(contract.operation_id) + uleb(contract.semantic_code) + uleb(contract.encoding_opcode))
        for constraints in (contract.operands, contract.results):
            body.extend(uleb(len(constraints)))
            for item in constraints:
                body.extend(uleb(item.kind) + uleb(item.primary) + uleb(item.secondary))
        body.extend(uleb(len(contract.supported_scopes)))
        body.extend(b"".join(uleb(scope) for scope in contract.supported_scopes))
        body.extend(uleb(contract.source_space) + uleb(contract.destination_space))
        body.extend(bytes((contract.synchronizes, contract.may_block)))
        body.extend(uleb(len(contract.runtime_dependency)) + contract.runtime_dependency)
    return SemanticObject.create(Kind.TARGET, bytes(body))


def oi07_noncoherent_dma_target() -> SemanticObject:
    return _oi07_dma_target(coherent=False)


def oi07_coherent_dma_target() -> SemanticObject:
    return _oi07_dma_target(coherent=True)


def simt32_accelerator_target() -> SemanticObject:
    """Prototype non-CPU accelerator package for the M13 deployment path.

    The package is canonical semantic data.  The compiler core only interprets
    its generic topology, memory-space, signature, effect/resource, and
    encoding contracts; accelerator operation behavior remains target-defined.
    """

    identity = b"simt32-packet-accelerator-v1"
    operations = (Operation.TARGET_OP.value,)
    terminators = (TerminatorKind.RETURN.value, TerminatorKind.TRAP.value)
    body = bytearray(uleb(len(identity)) + identity)
    # profile, architecture, ABI, deployment format, word width, address width
    for value in (3, 4, 4, 3, 32, 64):
        body.extend(uleb(value))
    body.extend(uleb(len(operations)) + b"".join(uleb(value) for value in operations))
    body.extend(uleb(len(terminators)) + b"".join(uleb(value) for value in terminators))

    # Execution topology: 32 lanes/workgroup, bounded workgroup count, explicit
    # device/workgroup scopes.  No CPU/thread model is implied.
    body.extend(uleb(32) + uleb(65535))
    scopes = (AtomicScope.DEVICE, AtomicScope.WORKGROUP)
    body.extend(uleb(len(scopes)) + b"".join(uleb(scope) for scope in scopes))

    # id, address bits, address-unit bits, min alignment, widths, scopes, flags
    spaces = (
        (1, 64, 8, 4, (32,), (AtomicScope.SYSTEM,), True, False),
        (2, 64, 8, 4, (32,), (AtomicScope.DEVICE, AtomicScope.WORKGROUP), False, True),
        (3, 32, 8, 4, (32,), (AtomicScope.WORKGROUP,), False, True),
    )
    body.extend(uleb(len(spaces)))
    for space_id, address_bits, unit_bits, alignment, widths, visible_scopes, host_visible, device_visible in spaces:
        body.extend(uleb(space_id) + uleb(address_bits) + uleb(unit_bits) + uleb(alignment))
        body.extend(uleb(len(widths)) + b"".join(uleb(width) for width in widths))
        body.extend(uleb(len(visible_scopes)) + b"".join(uleb(scope) for scope in visible_scopes))
        body.extend(bytes((host_visible, device_visible)))

    bits32 = TargetValueConstraint(TargetValueConstraintKind.BITS, 32)
    host_buffer = TargetValueConstraint(TargetValueConstraintKind.RESOURCE, 1001, 1)
    device_buffer = TargetValueConstraint(TargetValueConstraintKind.RESOURCE, 1001, 2)
    device_effect = TargetValueConstraint(TargetValueConstraintKind.EFFECT, EffectDomain.DEVICE, 1)
    contracts = (
        # id, semantic code, packet opcode, inputs, outputs, scopes, src, dst, sync, block
        TargetOperationContract(1, 1, 0x10, (device_effect,), (host_buffer, device_effect), (AtomicScope.DEVICE,), 1, 1, False, False),
        TargetOperationContract(2, 2, 0x11, (bits32, host_buffer, device_effect), (device_buffer, device_effect), (AtomicScope.DEVICE,), 1, 2, False, False),
        TargetOperationContract(3, 3, 0x12, (bits32, device_buffer, device_effect), (device_buffer, device_effect), (AtomicScope.DEVICE,), 2, 2, False, False),
        TargetOperationContract(4, 4, 0x13, (device_buffer, device_effect), (device_buffer, device_effect), (AtomicScope.DEVICE,), 2, 2, True, True),
        TargetOperationContract(5, 5, 0x14, (device_buffer, device_effect), (bits32, host_buffer, device_effect), (AtomicScope.DEVICE,), 2, 1, False, False),
        TargetOperationContract(6, 6, 0x15, (host_buffer, device_effect), (device_effect,), (AtomicScope.DEVICE,), 1, 1, False, False),
    )
    body.extend(uleb(len(contracts)))
    for contract in contracts:
        body.extend(uleb(contract.operation_id) + uleb(contract.semantic_code) + uleb(contract.encoding_opcode))
        for constraints in (contract.operands, contract.results):
            body.extend(uleb(len(constraints)))
            for item in constraints:
                body.extend(uleb(item.kind) + uleb(item.primary) + uleb(item.secondary))
        body.extend(uleb(len(contract.supported_scopes)))
        body.extend(b"".join(uleb(scope) for scope in contract.supported_scopes))
        body.extend(uleb(contract.source_space) + uleb(contract.destination_space))
        body.extend(bytes((contract.synchronizes, contract.may_block)))
        body.extend(uleb(len(contract.runtime_dependency)) + contract.runtime_dependency)
    return SemanticObject.create(Kind.TARGET, bytes(body))


def decode_native_target(obj: SemanticObject, allow_carrier: bool = False) -> NativeTargetDescription | None:
    if obj.kind != Kind.TARGET:
        fail("XAX.TARGET.EXPECTED", obj.cid.hex(), "TARGET-KIND", Kind.TARGET.name, obj.kind.name)
    if obj.references:
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", [], [cid.hex() for cid in obj.references])
    cursor = Cursor(obj.body, obj.cid.hex())
    identity = cursor.byte_string()
    if not identity:
        fail("XAX.STRUCT.TARGET_IDENTITY", obj.cid.hex(), "TARGET-IDENTITY-NONEMPTY", ">= 1 byte", 0)
    if not cursor.remaining:
        if allow_carrier:
            return None
        fail("XAX.TARGET.PROFILE_REQUIRED", obj.cid.hex(), "TARGET-NATIVE-PROFILE", "native target fields", "identity-only carrier")
    profile = cursor.uleb()
    architecture = cursor.uleb()
    abi = cursor.uleb()
    image_format = cursor.uleb()
    word_bits = cursor.uleb()
    pointer_bits = cursor.uleb()
    if architecture in (1, 3):
        stack_alignment = cursor.uleb()
        shadow_space = cursor.uleb()
        argument_registers = tuple(cursor.uleb() for _ in range(cursor.uleb()))
        result_register: int | None = cursor.uleb()
        scratch_registers = tuple(cursor.uleb() for _ in range(cursor.uleb()))
    elif architecture in (2, 4):
        stack_alignment = 1
        shadow_space = 0
        argument_registers = ()
        result_register = None
        scratch_registers = ()
    else:
        fail("XAX.TARGET.ARCHITECTURE", obj.cid.hex(), "TARGET-ARCHITECTURE-SUPPORTED", [1, 2, 3, 4], architecture)
    operations = tuple(cursor.uleb() for _ in range(cursor.uleb()))
    terminators = tuple(cursor.uleb() for _ in range(cursor.uleb()))
    atomic_widths: tuple[int, ...] = ()
    atomic_scopes: tuple[AtomicScope, ...] = ()
    atomic_families: tuple[AtomicFamily, ...] = ()
    handler_entries: tuple[HandlerEntryContract, ...] = ()
    accelerator_lane_width = 0
    accelerator_max_groups = 0
    accelerator_scopes: tuple[AtomicScope, ...] = ()
    memory_spaces: tuple[AcceleratorMemorySpace, ...] = ()
    target_operations: tuple[TargetOperationContract, ...] = ()
    if profile == 2:
        atomic_widths = tuple(cursor.uleb() for _ in range(cursor.uleb()))
        try:
            atomic_scopes = tuple(AtomicScope(cursor.uleb()) for _ in range(cursor.uleb()))
            atomic_families = tuple(AtomicFamily(cursor.uleb()) for _ in range(cursor.uleb()))
            handlers = []
            for _ in range(cursor.uleb()):
                fields = tuple(cursor.uleb() for _ in range(7))
                domains = tuple(EffectDomain(cursor.uleb()) for _ in range(cursor.uleb()))
                handlers.append(HandlerEntryContract(*fields, domains, cursor.uleb(), cursor.uleb()))
            handler_entries = tuple(handlers)
        except ValueError as error:
            fail("XAX.TARGET.CONCURRENCY", obj.cid.hex(), "TARGET-CONCURRENCY-ENUM", "known atomic/handler values", str(error))
    elif profile == 3:
        accelerator_lane_width = cursor.uleb()
        accelerator_max_groups = cursor.uleb()
        try:
            accelerator_scopes = tuple(AtomicScope(cursor.uleb()) for _ in range(cursor.uleb()))
            spaces = []
            for _ in range(cursor.uleb()):
                space_id, address_bits, unit_bits, alignment = (cursor.uleb() for _ in range(4))
                widths = tuple(cursor.uleb() for _ in range(cursor.uleb()))
                visibility = tuple(AtomicScope(cursor.uleb()) for _ in range(cursor.uleb()))
                host_raw, device_raw = cursor.take(1)[0], cursor.take(1)[0]
                if host_raw not in (0, 1) or device_raw not in (0, 1):
                    fail("XAX.TARGET.ACCELERATOR", obj.cid.hex(), "TARGET-ACCELERATOR-BOOL", [0, 1], [host_raw, device_raw])
                spaces.append(AcceleratorMemorySpace(space_id, address_bits, unit_bits, alignment, widths, visibility, bool(host_raw), bool(device_raw)))
            memory_spaces = tuple(spaces)
            contracts = []
            for _ in range(cursor.uleb()):
                operation_id, semantic_code, encoding_opcode = cursor.uleb(), cursor.uleb(), cursor.uleb()
                signatures = []
                for _signature in range(2):
                    constraints = []
                    for _ in range(cursor.uleb()):
                        constraints.append(TargetValueConstraint(TargetValueConstraintKind(cursor.uleb()), cursor.uleb(), cursor.uleb()))
                    signatures.append(tuple(constraints))
                scopes = tuple(AtomicScope(cursor.uleb()) for _ in range(cursor.uleb()))
                source_space, destination_space = cursor.uleb(), cursor.uleb()
                synchronizes_raw, may_block_raw = cursor.take(1)[0], cursor.take(1)[0]
                if synchronizes_raw not in (0, 1) or may_block_raw not in (0, 1):
                    fail("XAX.TARGET.ACCELERATOR", obj.cid.hex(), "TARGET-ACCELERATOR-BOOL", [0, 1], [synchronizes_raw, may_block_raw])
                runtime_dependency = cursor.byte_string()
                contracts.append(TargetOperationContract(operation_id, semantic_code, encoding_opcode, signatures[0], signatures[1], scopes, source_space, destination_space, bool(synchronizes_raw), bool(may_block_raw), runtime_dependency))
            target_operations = tuple(contracts)
        except ValueError as error:
            fail("XAX.TARGET.ACCELERATOR", obj.cid.hex(), "TARGET-ACCELERATOR-ENUM", "known scope/value-constraint values", str(error))
    elif profile == 4:
        try:
            contracts = []
            for _ in range(cursor.uleb()):
                operation_id, semantic_code, encoding_opcode = cursor.uleb(), cursor.uleb(), cursor.uleb()
                signatures = []
                for _signature in range(2):
                    constraints = []
                    for _ in range(cursor.uleb()):
                        constraints.append(TargetValueConstraint(TargetValueConstraintKind(cursor.uleb()), cursor.uleb(), cursor.uleb()))
                    signatures.append(tuple(constraints))
                scopes = tuple(AtomicScope(cursor.uleb()) for _ in range(cursor.uleb()))
                source_space, destination_space = cursor.uleb(), cursor.uleb()
                synchronizes_raw, may_block_raw = cursor.take(1)[0], cursor.take(1)[0]
                if synchronizes_raw not in (0, 1) or may_block_raw not in (0, 1):
                    fail("XAX.TARGET.PLATFORM", obj.cid.hex(), "TARGET-PLATFORM-BOOL", [0, 1], [synchronizes_raw, may_block_raw])
                runtime_dependency = cursor.byte_string()
                contracts.append(TargetOperationContract(operation_id, semantic_code, encoding_opcode, signatures[0], signatures[1], scopes, source_space, destination_space, bool(synchronizes_raw), bool(may_block_raw), runtime_dependency))
            target_operations = tuple(contracts)
        except ValueError as error:
            fail("XAX.TARGET.PLATFORM", obj.cid.hex(), "TARGET-PLATFORM-ENUM", "known scope/value-constraint values", str(error))
    cursor.end("TARGET-NATIVE-BODY")
    if profile not in (1, 2, 3, 4):
        fail("XAX.TARGET.PROFILE", obj.cid.hex(), "TARGET-PROFILE-SUPPORTED", [1, 2, 3, 4], profile)
    if architecture == 1:
        machine = (abi, image_format, word_bits, pointer_bits, stack_alignment, shadow_space)
        allowed_machines = (
            (1, 1, 64, 64, 16, 32),
            (X86_64_LINUX_ABI, X86_64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 32),
            (X86_64_LINUX_ABI, X86_64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 32),
        )
        if machine not in allowed_machines:
            fail("XAX.TARGET.MACHINE", obj.cid.hex(), "TARGET-X86-64-PROFILE", [list(item) for item in allowed_machines], list(machine))
        registers = (*argument_registers, result_register, *scratch_registers)
        if argument_registers != (1, 2, 8, 9) or result_register != 0 or scratch_registers != (10, 11) or any(register is None or register >= 16 for register in registers):
            fail("XAX.TARGET.ABI", obj.cid.hex(), "TARGET-WINDOWS-X64-REGISTERS", [[1, 2, 8, 9], 0, [10, 11]], [list(argument_registers), result_register, list(scratch_registers)])
    elif architecture == 2 and (abi, image_format, word_bits, pointer_bits) != (2, 2, 64, 32):
        fail("XAX.TARGET.MACHINE", obj.cid.hex(), "TARGET-WASM32-CORE", [2, 2, 64, 32], [abi, image_format, word_bits, pointer_bits])
    elif architecture == 3:
        machine = (abi, image_format, word_bits, pointer_bits, stack_alignment, shadow_space)
        if machine not in ((3, 1, 64, 64, 16, 0), (4, 4, 64, 64, 16, 0)):
            fail("XAX.TARGET.MACHINE", obj.cid.hex(), "TARGET-AARCH64-PROFILE", [[3, 1, 64, 64, 16, 0], [4, 4, 64, 64, 16, 0]], list(machine))
        if abi == 4 and profile != 4:
            fail("XAX.TARGET.MACHINE", obj.cid.hex(), "TARGET-ANDROID-PROFILE", 4, profile)
        if abi == 3 and profile not in (1, 2):
            fail("XAX.TARGET.MACHINE", obj.cid.hex(), "TARGET-AARCH64-BAREMETAL-PROFILE", [1, 2], profile)
        registers = (*argument_registers, result_register, *scratch_registers)
        if argument_registers != tuple(range(8)) or result_register != 0 or scratch_registers != (9, 10) or any(register is None or register >= 31 for register in registers):
            fail("XAX.TARGET.ABI", obj.cid.hex(), "TARGET-AAPCS64-REGISTERS", [list(range(8)), 0, [9, 10]], [list(argument_registers), result_register, list(scratch_registers)])
    elif architecture == 4:
        if profile != 3 or (abi, image_format, word_bits, pointer_bits) != (4, 3, 32, 64):
            fail("XAX.TARGET.MACHINE", obj.cid.hex(), "TARGET-ACCELERATOR-PROFILE", [3, 4, 3, 32, 64], [profile, abi, image_format, word_bits, pointer_bits])
        if accelerator_lane_width < 1 or accelerator_max_groups < 1:
            fail("XAX.TARGET.ACCELERATOR", obj.cid.hex(), "TARGET-ACCELERATOR-TOPOLOGY", "positive lane width and max groups", [accelerator_lane_width, accelerator_max_groups])
        if accelerator_scopes != tuple(sorted(set(accelerator_scopes))) or not accelerator_scopes:
            fail("XAX.TARGET.ACCELERATOR", obj.cid.hex(), "TARGET-ACCELERATOR-SCOPES-CANONICAL", "sorted unique nonempty scopes", accelerator_scopes)
        space_ids = tuple(space.identity for space in memory_spaces)
        if space_ids != tuple(sorted(set(space_ids))) or not memory_spaces:
            fail("XAX.TARGET.MEMORY_SPACE", obj.cid.hex(), "TARGET-MEMORY-SPACES-CANONICAL", "sorted unique nonempty memory spaces", space_ids)
        for space in memory_spaces:
            if (space.address_bits < 1 or space.address_unit_bits < 1 or space.minimum_alignment < 1 or space.minimum_alignment & (space.minimum_alignment - 1)
                or space.access_widths != tuple(sorted(set(space.access_widths))) or any(width < 1 for width in space.access_widths)
                or space.visibility_scopes != tuple(sorted(set(space.visibility_scopes)))):
                fail("XAX.TARGET.MEMORY_SPACE", obj.cid.hex(), "TARGET-MEMORY-SPACE-CONTRACT", "positive widths, power-of-two alignment, canonical widths/scopes", space)
        operation_ids = tuple(contract.operation_id for contract in target_operations)
        if operation_ids != tuple(sorted(set(operation_ids))) or not target_operations:
            fail("XAX.TARGET.OPERATION", obj.cid.hex(), "TARGET-OPERATIONS-CONTRACT-CANONICAL", "sorted unique nonempty target operation IDs", operation_ids)
        memory_ids = set(space_ids)
        for contract in target_operations:
            if contract.semantic_code < 1 or not 0 <= contract.encoding_opcode <= 255:
                fail("XAX.TARGET.OPERATION", obj.cid.hex(), "TARGET-OPERATION-ENCODING", "positive semantic code and byte opcode", [contract.semantic_code, contract.encoding_opcode])
            if contract.supported_scopes != tuple(sorted(set(contract.supported_scopes))) or not contract.supported_scopes or not set(contract.supported_scopes) <= set(accelerator_scopes):
                fail("XAX.TARGET.OPERATION", obj.cid.hex(), "TARGET-OPERATION-SCOPES", accelerator_scopes, contract.supported_scopes)
            if contract.source_space not in memory_ids or contract.destination_space not in memory_ids:
                fail("XAX.TARGET.OPERATION", obj.cid.hex(), "TARGET-OPERATION-MEMORY-SPACES", sorted(memory_ids), [contract.source_space, contract.destination_space])
            for constraint in (*contract.operands, *contract.results):
                if constraint.kind == TargetValueConstraintKind.BITS:
                    valid_constraint = constraint.primary >= 1 and constraint.secondary == 0
                elif constraint.kind == TargetValueConstraintKind.RESOURCE:
                    valid_constraint = constraint.primary >= 1 and constraint.secondary >= 1
                elif constraint.kind == TargetValueConstraintKind.EFFECT:
                    valid_constraint = constraint.primary in EffectDomain._value2member_map_ and constraint.secondary >= 0
                else:
                    valid_constraint = constraint.kind in (TargetValueConstraintKind.FUNCTION_POINTER, TargetValueConstraintKind.POINTER) and constraint.primary == 0 and constraint.secondary == 0
                if not valid_constraint:
                    fail("XAX.TARGET.OPERATION", obj.cid.hex(), "TARGET-OPERATION-VALUE-CONSTRAINT", "canonical bits/resource/effect constraint", [constraint.kind.value, constraint.primary, constraint.secondary])
            if contract.runtime_dependency and len(contract.runtime_dependency) != 32:
                fail("XAX.TARGET.OPERATION", obj.cid.hex(), "TARGET-OPERATION-RUNTIME-DEPENDENCY", "empty or 32-byte identity", len(contract.runtime_dependency))
    if profile == 4:
        operation_ids = tuple(contract.operation_id for contract in target_operations)
        if operation_ids != tuple(sorted(set(operation_ids))) or not target_operations:
            fail("XAX.TARGET.PLATFORM", obj.cid.hex(), "TARGET-PLATFORM-OPERATIONS-CANONICAL", "sorted unique nonempty target operation IDs", operation_ids)
        for contract in target_operations:
            if contract.semantic_code < 1 or contract.supported_scopes != tuple(sorted(set(contract.supported_scopes))) or not contract.supported_scopes:
                fail("XAX.TARGET.PLATFORM", obj.cid.hex(), "TARGET-PLATFORM-OPERATION-CONTRACT", "positive semantic code and canonical scopes", contract.operation_id)
            for constraint in (*contract.operands, *contract.results):
                if constraint.kind == TargetValueConstraintKind.BITS:
                    valid_constraint = constraint.primary >= 1 and constraint.secondary == 0
                elif constraint.kind == TargetValueConstraintKind.RESOURCE:
                    valid_constraint = constraint.primary >= 1 and constraint.secondary >= 1
                elif constraint.kind == TargetValueConstraintKind.EFFECT:
                    valid_constraint = constraint.primary in EffectDomain._value2member_map_ and constraint.secondary >= 0
                else:
                    valid_constraint = constraint.kind in (TargetValueConstraintKind.FUNCTION_POINTER, TargetValueConstraintKind.POINTER) and constraint.primary == 0 and constraint.secondary == 0
                if not valid_constraint:
                    fail("XAX.TARGET.PLATFORM", obj.cid.hex(), "TARGET-PLATFORM-VALUE-CONSTRAINT", "canonical bits/resource/effect constraint", [constraint.kind.value, constraint.primary, constraint.secondary])
            if contract.runtime_dependency and len(contract.runtime_dependency) != 32:
                fail("XAX.TARGET.PLATFORM", obj.cid.hex(), "TARGET-PLATFORM-RUNTIME-DEPENDENCY", "empty or 32-byte identity", len(contract.runtime_dependency))

    if operations != tuple(sorted(set(operations))) or any(operation not in Operation._value2member_map_ for operation in operations):
        fail("XAX.TARGET.OPERATIONS", obj.cid.hex(), "TARGET-OPERATIONS-CANONICAL", "sorted supported operation IDs", operations)
    if terminators != tuple(sorted(set(terminators))) or any(terminator not in TerminatorKind._value2member_map_ for terminator in terminators):
        fail("XAX.TARGET.TERMINATORS", obj.cid.hex(), "TARGET-TERMINATORS-CANONICAL", "sorted supported terminator IDs", terminators)
    if atomic_widths != tuple(sorted(set(atomic_widths))) or any(width < 1 for width in atomic_widths):
        fail("XAX.TARGET.ATOMICS", obj.cid.hex(), "TARGET-ATOMIC-WIDTHS-CANONICAL", "sorted positive widths", atomic_widths)
    if atomic_scopes != tuple(sorted(set(atomic_scopes))) or atomic_families != tuple(sorted(set(atomic_families))):
        fail("XAX.TARGET.ATOMICS", obj.cid.hex(), "TARGET-ATOMIC-CAPABILITIES-CANONICAL", "sorted unique scopes/families", [atomic_scopes, atomic_families])
    if tuple(entry.event_kind for entry in handler_entries) != tuple(sorted({entry.event_kind for entry in handler_entries})):
        fail("XAX.TARGET.HANDLER", obj.cid.hex(), "TARGET-HANDLER-ENTRIES-CANONICAL", "sorted unique event kinds", [entry.event_kind for entry in handler_entries])
    for entry in handler_entries:
        if entry.allowed_effect_domains != tuple(sorted(set(entry.allowed_effect_domains))) or entry.stack_bound < 1:
            fail(
                "XAX.TARGET.HANDLER",
                obj.cid.hex(),
                "TARGET-HANDLER-CONTRACT",
                "sorted unique effect domains and positive stack bound",
                [entry.allowed_effect_domains, entry.stack_bound],
            )
    return NativeTargetDescription(
        identity,
        architecture,
        abi,
        image_format,
        word_bits,
        pointer_bits,
        stack_alignment,
        shadow_space,
        argument_registers,
        result_register,
        scratch_registers,
        operations,
        terminators,
        atomic_widths,
        atomic_scopes,
        atomic_families,
        handler_entries,
        accelerator_lane_width,
        accelerator_max_groups,
        accelerator_scopes,
        memory_spaces,
        target_operations,
    )


def bits_type(width: int) -> SemanticObject:
    if width < 1:
        raise ValueError("bits width must be positive")
    return SemanticObject.create(Kind.TYPE, uleb(1) + uleb(width))


class FloatFormat(IntEnum):
    BINARY32 = 1
    BINARY64 = 2


class FloatCompare(IntEnum):
    EQ = 1
    NE = 2
    LT = 3
    LE = 4
    GT = 5
    GE = 6


class IntCompare(IntEnum):
    EQ = 1
    NE = 2
    ULT = 3
    ULE = 4
    UGT = 5
    UGE = 6
    SLT = 7
    SLE = 8
    SGT = 9
    SGE = 10


def float_type(format: FloatFormat | int) -> SemanticObject:
    try:
        format = FloatFormat(format)
    except ValueError as error:
        raise ValueError("unsupported float format") from error
    return SemanticObject.create(Kind.TYPE, uleb(7) + uleb(format))


def tuple_type(elements: Sequence[SemanticObject]) -> SemanticObject:
    elements = tuple(elements)
    if any(item.kind != Kind.TYPE for item in elements):
        raise ValueError("tuple elements must be types")
    references = tuple(sorted({item.cid for item in elements}))
    positions = {cid: index for index, cid in enumerate(references)}
    body = bytearray(uleb(8) + uleb(len(elements)))
    body.extend(b"".join(uleb(positions[item.cid]) for item in elements))
    return SemanticObject.create(Kind.TYPE, bytes(body), references)


def struct_type(fields: Sequence[SemanticObject]) -> SemanticObject:
    # Field names are non-semantic in XAX. A struct is therefore the same exact
    # product value as a tuple; callers may retain names only in tooling metadata.
    return tuple_type(fields)


def array_type(element: SemanticObject, count: int) -> SemanticObject:
    if element.kind != Kind.TYPE or count < 0:
        raise ValueError("array requires a type element and nonnegative count")
    return SemanticObject.create(Kind.TYPE, uleb(9) + uleb(0) + uleb(count), [element.cid])


def sum_type(variants: Sequence[SemanticObject]) -> SemanticObject:
    variants = tuple(variants)
    if not variants or any(item.kind != Kind.TYPE for item in variants):
        raise ValueError("sum variants must be a nonempty sequence of types")
    references = tuple(sorted({item.cid for item in variants}))
    positions = {cid: index for index, cid in enumerate(references)}
    body = bytearray(uleb(10) + uleb(len(variants)))
    body.extend(b"".join(uleb(positions[item.cid]) for item in variants))
    return SemanticObject.create(Kind.TYPE, bytes(body), references)


def byte_slice_type(length_type: SemanticObject | None = None) -> SemanticObject:
    byte = bits_type(8)
    length = bits_type(64) if length_type is None else length_type
    return tuple_type((pointer_type(byte, Permission.READ, 1, space=2), length))


class Permission(IntEnum):
    READ = 1
    WRITE = 2
    READ_WRITE = 3


class EffectDomain(IntEnum):
    MEMORY = 1
    IO = 2
    SYSCALL = 3
    DEVICE = 4
    FILESYSTEM = 5
    NETWORK = 6
    TIME = 7
    RANDOM = 8
    PRIVILEGED = 9
    UNSAFE = 10
    ATOMIC = 11


class ResourceFlags(IntFlag):
    LINEAR = 0
    AFFINE = 1
    PARTITIONABLE = 2
    RELEASABLE = 4
    ACQUIRABLE = 8


class OpaqueKind(IntEnum):
    TYPE = 1
    CONSTANT = 2
    FUNCTION = 3
    TARGET = 4
    GRAPH = 5
    OBJECT = 6
    BYTES = 7


class MetaCapability(IntEnum):
    INSPECT_TYPE = 1
    INSPECT_CONSTANT = 2
    INSPECT_TARGET = 3
    READ_DECLARED_INPUT = 4
    CONSTRUCT_SEMANTICS = 5
    INSPECT_FUNCTION = 6
    SERIALIZE_SEMANTICS = 7
    VERIFY_SEMANTICS = 8
    INSPECT_FUNCTION_INTERFACE = 9


_ATOMIC_ORDERS = {
    AtomicFamily.LOAD: (AtomicOrder.RELAXED, AtomicOrder.ACQUIRE, AtomicOrder.SEQ_CST),
    AtomicFamily.STORE: (AtomicOrder.RELAXED, AtomicOrder.RELEASE, AtomicOrder.SEQ_CST),
    AtomicFamily.RMW: tuple(AtomicOrder),
    AtomicFamily.CMPXCHG: tuple(AtomicOrder),
    AtomicFamily.FENCE: (AtomicOrder.ACQUIRE, AtomicOrder.RELEASE, AtomicOrder.ACQ_REL, AtomicOrder.SEQ_CST),
}


def _atomic_order(family: AtomicFamily | int, order: AtomicOrder | int, failure: AtomicOrder | int | None = None) -> tuple[AtomicFamily, AtomicOrder, AtomicOrder | None]:
    try:
        family = AtomicFamily(family)
        order = AtomicOrder(order)
        failure = AtomicOrder(failure) if failure is not None else None
    except ValueError as error:
        fail("XAX.ATOMIC.ORDER", "atomic", "ATOMIC-ORDER-ENUM", "portable atomic family/order", str(error))
    if order not in _ATOMIC_ORDERS[family]:
        fail("XAX.ATOMIC.ORDER", family.name.lower(), "ATOMIC-ORDER-LEGAL", [item.name.lower() for item in _ATOMIC_ORDERS[family]], order.name.lower())
    if family == AtomicFamily.CMPXCHG:
        if failure is None or failure not in (AtomicOrder.RELAXED, AtomicOrder.ACQUIRE, AtomicOrder.SEQ_CST):
            fail("XAX.ATOMIC.ORDER", family.name.lower(), "ATOMIC-CMPXCHG-FAILURE-ORDER", ["relaxed", "acquire", "seq_cst"], None if failure is None else failure.name.lower())
        read_strength = {
            AtomicOrder.RELAXED: 0,
            AtomicOrder.RELEASE: 0,
            AtomicOrder.ACQUIRE: 1,
            AtomicOrder.ACQ_REL: 1,
            AtomicOrder.SEQ_CST: 2,
        }
        if read_strength[failure] > read_strength[order]:
            fail("XAX.ATOMIC.ORDER", family.name.lower(), "ATOMIC-CMPXCHG-FAILURE-NOT-STRONGER", order.name.lower(), failure.name.lower())
    elif failure is not None:
        fail("XAX.ATOMIC.ORDER", family.name.lower(), "ATOMIC-FAILURE-ORDER-ABSENT", None, failure.name.lower())
    return family, order, failure


def atomic_capability(
    target: NativeTargetDescription,
    address_space: int,
    width: int,
    alignment: int,
    family: AtomicFamily | int,
    order: AtomicOrder | int,
    scope: AtomicScope | int,
    failure_order: AtomicOrder | int | None = None,
) -> AtomicTargetCapability:
    family, order, _ = _atomic_order(family, order, failure_order)
    try:
        scope = AtomicScope(scope)
    except ValueError as error:
        fail("XAX.ATOMIC.SCOPE", target.identity.decode("ascii", "replace"), "ATOMIC-SCOPE-ENUM", "known scope", str(error))
    required_alignment = max(1, width // 8) if family != AtomicFamily.FENCE else 1
    directly_supported = (
        address_space in (0, 1)
        and (family == AtomicFamily.FENCE or width in target.atomic_widths)
        and family in target.atomic_families
        and scope in target.atomic_scopes
        and alignment >= required_alignment
    )
    # Seq-cst load/store implementations that require more than one target
    # instruction are represented honestly as bounded inline legalization.
    # x86-64 uses load+mfence for seq-cst load.  The AArch64 profile-2 backend
    # uses a finite address/barrier/access/barrier lowering for seq-cst
    # load/store; it never uses an LL/SC retry loop.
    bounded_inline = directly_supported and order == AtomicOrder.SEQ_CST and (
        (target.architecture == 1 and family == AtomicFamily.LOAD)
        or (target.architecture == 3 and family in (AtomicFamily.LOAD, AtomicFamily.STORE))
    )
    support = (
        AtomicSupport.BOUNDED_SEQUENCE
        if bounded_inline
        else AtomicSupport.NATIVE
        if directly_supported
        else AtomicSupport.UNSUPPORTED
    )
    max_inline_instructions = None
    if support == AtomicSupport.BOUNDED_SEQUENCE:
        # Count the atomic synchronization/memory sequence itself, excluding
        # ordinary compiler value-location moves. x86-64 is load+mfence;
        # AArch64 is DMB ISH + LDAR/STLR + DMB ISH.
        max_inline_instructions = 2 if target.architecture == 1 else 3
    return AtomicTargetCapability(
        support,
        LockFree.ALWAYS if directly_supported else LockFree.NO,
        RetryBehavior.NONE if directly_supported else RetryBehavior.POTENTIALLY_UNBOUNDED,
        required_alignment,
        _ATOMIC_ORDERS[family],
        target.atomic_scopes,
        None,
        max_inline_instructions,
        b"",
    )


def select_atomic_legalization(
    capability: AtomicTargetCapability,
    policy: AtomicLegalizationPolicy = AtomicLegalizationPolicy(),
) -> AtomicSupport:
    """Select an explicit legal atomic path without inventing runtime behavior."""

    if capability.support == AtomicSupport.NATIVE:
        return AtomicSupport.NATIVE
    if capability.support == AtomicSupport.BOUNDED_SEQUENCE:
        if policy.permit_bounded_inline:
            return AtomicSupport.BOUNDED_SEQUENCE
        fail(
            "XAX.ATOMIC.LEGALIZATION_POLICY",
            "atomic",
            "ATOMIC-BOUNDED-INLINE-PERMITTED",
            True,
            False,
        )
    if capability.support == AtomicSupport.RUNTIME_ASSIST:
        if not policy.permit_runtime_assist:
            fail(
                "XAX.ATOMIC.LEGALIZATION_POLICY",
                "atomic",
                "ATOMIC-RUNTIME-ASSIST-PERMITTED",
                True,
                False,
            )
        if len(capability.runtime_helper) != 32:
            fail(
                "XAX.ATOMIC.LEGALIZATION_POLICY",
                "atomic",
                "ATOMIC-RUNTIME-ASSIST-IDENTITY",
                "32-byte explicit helper identity",
                len(capability.runtime_helper),
            )
        return AtomicSupport.RUNTIME_ASSIST
    return AtomicSupport.UNSUPPORTED


def pointer_type(
    element_type: SemanticObject,
    permission: Permission = Permission.READ_WRITE,
    alignment: int = 1,
    *,
    space: int = 1,
) -> SemanticObject:
    if element_type.kind != Kind.TYPE:
        raise ValueError("pointer element must be a type")
    if alignment < 1 or alignment & (alignment - 1):
        raise ValueError("pointer alignment must be a positive power of two")
    if space < 1:
        raise ValueError("pointer address space must be positive")
    try:
        permission = Permission(permission)
    except ValueError as error:
        raise ValueError("invalid pointer permission") from error
    body = uleb(2) + uleb(space) + uleb(0) + uleb(permission) + uleb(alignment)
    return SemanticObject.create(Kind.TYPE, body, [element_type.cid])


def effect_type(domain: EffectDomain | int, instance: int = 0) -> SemanticObject:
    try:
        domain = EffectDomain(domain)
    except ValueError as error:
        raise ValueError("invalid effect domain") from error
    if instance < 0:
        raise ValueError("effect instance must be nonnegative")
    body = uleb(3) + uleb(domain)
    if instance:
        body += uleb(instance)
    return SemanticObject.create(Kind.TYPE, body)


def memory_effect_type() -> SemanticObject:
    return effect_type(EffectDomain.MEMORY)


def resource_type(
    kind: int,
    state: int,
    *,
    flags: ResourceFlags = ResourceFlags.RELEASABLE,
    instance: int = 0,
    transitions: Sequence[int] = (),
) -> SemanticObject:
    if kind < 1 or state < 1 or instance < 0:
        raise ValueError("resource kind/state must be positive and instance nonnegative")
    try:
        flags = ResourceFlags(flags)
    except ValueError as error:
        raise ValueError("invalid resource flags") from error
    if int(flags) & ~int(ResourceFlags.AFFINE | ResourceFlags.PARTITIONABLE | ResourceFlags.RELEASABLE | ResourceFlags.ACQUIRABLE):
        raise ValueError("invalid resource flags")
    transitions = tuple(sorted(set(transitions)))
    if any(target < 1 or target == state for target in transitions):
        raise ValueError("resource transitions must name distinct positive states")
    if (kind, state, flags, instance, transitions) == (1, 1, ResourceFlags.RELEASABLE, 0, ()):
        return SemanticObject.create(Kind.TYPE, uleb(4) + uleb(1) + uleb(1))
    body = bytearray(uleb(4) + uleb(kind) + uleb(state) + uleb(int(flags)) + uleb(instance))
    body.extend(uleb(len(transitions)))
    body.extend(b"".join(uleb(target) for target in transitions))
    return SemanticObject.create(Kind.TYPE, bytes(body))


def dma_resource_types() -> tuple[SemanticObject, ...]:
    """Return the canonical OI-07 shared DMA resource-state types in state order."""

    transitions = {
        DmaResourceState.HOST_UNMAPPED: (DmaResourceState.HOST_MAPPED,),
        DmaResourceState.HOST_MAPPED: (DmaResourceState.HOST_DIRTY, DmaResourceState.DEVICE_OWNED, DmaResourceState.HOST_UNMAPPED),
        DmaResourceState.HOST_DIRTY: (DmaResourceState.HOST_MAPPED,),
        DmaResourceState.DEVICE_OWNED: (DmaResourceState.DEVICE_PENDING, DmaResourceState.HOST_MAPPED, DmaResourceState.HOST_STALE),
        DmaResourceState.DEVICE_PENDING: (DmaResourceState.DEVICE_OWNED,),
        DmaResourceState.HOST_STALE: (DmaResourceState.HOST_MAPPED,),
    }
    return tuple(
        resource_type(DMA_RESOURCE_KIND, int(state), transitions=tuple(int(item) for item in transitions[state]))
        for state in DmaResourceState
    )


def opaque_type(kind: OpaqueKind | int) -> SemanticObject:
    try:
        kind = OpaqueKind(kind)
    except ValueError as error:
        raise ValueError("invalid opaque semantic kind") from error
    return SemanticObject.create(Kind.TYPE, uleb(5) + uleb(kind))


def opaque_identity_type(identity: bytes) -> SemanticObject:
    """Create a target-independent identity-qualified opaque ABI type.

    Unlike ``opaque_type`` (which names compiler semantic-object categories),
    this form is for externally defined values whose representation is opaque
    but whose ABI identity must remain distinct for verification.  The identity
    bytes are semantic and content-addressed; no runtime metadata is emitted.
    """

    identity = bytes(identity)
    if not identity:
        raise ValueError("opaque ABI type identity must be nonempty")
    return SemanticObject.create(Kind.TYPE, uleb(6) + uleb(len(identity)) + identity)


def stack_owner_type() -> SemanticObject:
    return resource_type(1, 1)


HEAP_RESOURCE_KIND = 0x100
HEAP_VIEW_RESOURCE_KIND = 0x101


def heap_owner_type() -> SemanticObject:
    """Linear ownership of one foreign heap block of statically unknown size."""
    return resource_type(HEAP_RESOURCE_KIND, 1, flags=ResourceFlags.RELEASABLE, instance=0)


def heap_view_type(extent: int, *, initialized: bool = True) -> SemanticObject:
    """Linear ownership of a whole non-null heap block proven to span ``extent`` bytes.

    State 1 additionally proves every byte initialized; state 2 proves nothing
    about contents.  The extent lives in the type so borrowed views keep exact
    bounds across function boundaries without a runtime length check.
    """
    if extent < 1:
        raise ValueError("heap view extent must be positive")
    return resource_type(HEAP_VIEW_RESOURCE_KIND, 1 if initialized else 2, flags=ResourceFlags.RELEASABLE, instance=extent)


def _heap_view_info(obj: SemanticObject) -> tuple[int, bool] | None:
    if not _is_resource(obj):
        return None
    description = _decode_resource_type(obj)
    if description.kind != HEAP_VIEW_RESOURCE_KIND or description.state not in (1, 2) or description.instance < 1:
        return None
    return description.instance, description.state == 1


def _is_heap_owner(obj: SemanticObject) -> bool:
    if not _is_resource(obj):
        return False
    description = _decode_resource_type(obj)
    return description.kind == HEAP_RESOURCE_KIND


def constant(type_object: SemanticObject, value: int) -> SemanticObject:
    width = decode_bits_width(type_object)
    if value < 0 or value >= 1 << width:
        raise ValueError("constant does not fit type")
    encoded = value.to_bytes((width + 7) // 8, "little")
    return SemanticObject.create(Kind.CONSTANT, uleb(0) + uleb(len(encoded)) + encoded, [type_object.cid])


def _round_float(value: float, width: int) -> float:
    value = float(value)
    if width == 32:
        try:
            return struct.unpack("<f", struct.pack("<f", value))[0]
        except OverflowError:
            return math.copysign(math.inf, value)
    if width == 64:
        return struct.unpack("<d", struct.pack("<d", value))[0]
    raise ValueError("float width must be 32 or 64")


def _int_to_float(value: int, width: int) -> float:
    """Round an exact integer once, to nearest-even, into binary32/binary64."""
    if width == 64 or abs(value) < 1 << 53:
        # CPython int->float is correctly rounded; below 2**53 it is exact, so
        # the binary32 narrowing below is the only rounding step.
        return _round_float(float(value), width)
    magnitude = abs(value)
    shift = magnitude.bit_length() - 24
    quotient, remainder = divmod(magnitude, 1 << shift)
    half = 1 << (shift - 1)
    if remainder > half or (remainder == half and quotient & 1):
        quotient += 1
    return math.copysign(math.ldexp(float(quotient), shift), value)


def _float_raw_bits(value: float, width: int) -> int:
    value = _round_float(value, width)
    if math.isnan(value):
        return 0x7FC00000 if width == 32 else 0x7FF8000000000000
    encoded = struct.pack("<f" if width == 32 else "<d", value)
    return int.from_bytes(encoded, "little")


def float_constant(type_object: SemanticObject, value: float) -> SemanticObject:
    width = decode_float_width(type_object)
    encoded = _float_raw_bits(value, width).to_bytes(width // 8, "little")
    return SemanticObject.create(Kind.CONSTANT, uleb(0) + uleb(len(encoded)) + encoded, [type_object.cid])


class Operation(IntEnum):
    ADD_WRAP = 1
    SUB_WRAP = 2
    MUL_WRAP = 3
    CALL_GROUP_MEMBER = 4
    CALL_DIRECT = 5
    CONSTANT = 6
    STACK_ALLOC = 7
    ADDRESS_OFFSET = 8
    STORE_BITS_LE = 9
    LOAD_BITS_LE = 10
    STACK_END = 11
    RESOURCE_ACQUIRE = 12
    RESOURCE_TRANSFER = 13
    RESOURCE_TRANSITION = 14
    RESOURCE_RELEASE = 15
    RESOURCE_DISCARD = 16
    RESOURCE_SPLIT = 17
    RESOURCE_JOIN = 18
    EFFECT_STEP = 19
    ATOMIC_LOAD = 20
    ATOMIC_STORE = 21
    ATOMIC_RMW = 22
    ATOMIC_CMPXCHG = 23
    ATOMIC_FENCE = 24
    META_TYPE_BITS_WIDTH = 25
    META_CONSTANT_VALUE = 26
    META_TARGET_SUPPORTS = 27
    META_DECLARED_INPUT = 28
    META_MATERIALIZE_CONSTANT_FUNCTION = 29
    TARGET_OP = 30
    META_FUNCTION_GRAPH = 31
    META_GRAPH_BLOCK_COUNT = 32
    META_GRAPH_NODE_COUNT = 33
    META_GRAPH_NODE_OPERATION = 34
    META_CANONICAL_STORE = 35
    META_VERIFY_SEMANTICS = 36
    META_MATERIALIZE_PROGRAM = 37
    CHECKED_LOAD_BITS_LE = 38
    CHECKED_STORE_BITS_LE = 39
    RAW_LOAD_BITS_LE = 40
    FUNCTION_ADDRESS = 41
    CALL_FOREIGN = 42
    CALL_INDIRECT = 43
    FLOAT_ADD = 44
    FLOAT_SUB = 45
    FLOAT_MUL = 46
    FLOAT_DIV = 47
    FLOAT_COMPARE = 48
    UINT_TO_FLOAT = 49
    FLOAT_TO_UINT_TRUNC = 50
    AGGREGATE_MAKE = 51
    AGGREGATE_GET = 52
    SUM_MAKE = 53
    SUM_TAG = 54
    SUM_GET = 55
    POINTER_CAST = 56
    INT_COMPARE = 57
    FLOAT_CONVERT = 58
    SINT_TO_FLOAT = 59
    FLOAT_TO_SINT_TRUNC = 60
    HEAP_VIEW = 61
    BIT_XOR = 62
    ROTATE_RIGHT = 63
    META_FUNCTION_PARAMETER_COUNT = 64
    META_FUNCTION_RETURN_COUNT = 65
    POINTER_ADDRESS = 66
    BIT_AND = 67
    BIT_OR = 68
    UDIV = 69
    UREM = 70
    INT_TRUNCATE = 71
    INT_ZERO_EXTEND = 72
    POINTER_REBASE = 73


# Same-width binary integer operations: two bits<N> operands, one bits<N> result.
BINARY_INTEGER_OPERATIONS = frozenset(
    {
        Operation.ADD_WRAP,
        Operation.SUB_WRAP,
        Operation.MUL_WRAP,
        Operation.BIT_XOR,
        Operation.BIT_AND,
        Operation.BIT_OR,
        Operation.UDIV,
        Operation.UREM,
    }
)
# Width-changing integer operations: one bits<M> operand, one bits<N> result.
INTEGER_WIDTH_OPERATIONS = frozenset({Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND})


RESOURCE_EFFECT_OPERATIONS = frozenset(
    {
        Operation.RESOURCE_ACQUIRE,
        Operation.RESOURCE_TRANSFER,
        Operation.RESOURCE_TRANSITION,
        Operation.RESOURCE_RELEASE,
        Operation.RESOURCE_DISCARD,
        Operation.RESOURCE_SPLIT,
        Operation.RESOURCE_JOIN,
        Operation.EFFECT_STEP,
    }
)


MEMORY_OPERATIONS = frozenset(
    {
        Operation.STACK_ALLOC,
        Operation.ADDRESS_OFFSET,
        Operation.STORE_BITS_LE,
        Operation.LOAD_BITS_LE,
        Operation.STACK_END,
        Operation.CHECKED_LOAD_BITS_LE,
        Operation.CHECKED_STORE_BITS_LE,
        Operation.RAW_LOAD_BITS_LE,
        Operation.POINTER_CAST,
        Operation.HEAP_VIEW,
        Operation.POINTER_ADDRESS,
        Operation.POINTER_REBASE,
    }
)


ATOMIC_OPERATIONS = frozenset(
    {
        Operation.ATOMIC_LOAD,
        Operation.ATOMIC_STORE,
        Operation.ATOMIC_RMW,
        Operation.ATOMIC_CMPXCHG,
        Operation.ATOMIC_FENCE,
    }
)


META_OPERATIONS = frozenset(
    {
        Operation.META_TYPE_BITS_WIDTH,
        Operation.META_CONSTANT_VALUE,
        Operation.META_TARGET_SUPPORTS,
        Operation.META_DECLARED_INPUT,
        Operation.META_MATERIALIZE_CONSTANT_FUNCTION,
        Operation.META_FUNCTION_GRAPH,
        Operation.META_GRAPH_BLOCK_COUNT,
        Operation.META_GRAPH_NODE_COUNT,
        Operation.META_GRAPH_NODE_OPERATION,
        Operation.META_CANONICAL_STORE,
        Operation.META_VERIFY_SEMANTICS,
        Operation.META_MATERIALIZE_PROGRAM,
        Operation.META_FUNCTION_PARAMETER_COUNT,
        Operation.META_FUNCTION_RETURN_COUNT,
    }
)

TARGET_OPERATIONS = frozenset({Operation.TARGET_OP})
ENTITY_OPERATIONS = frozenset({Operation.CALL_DIRECT, Operation.CONSTANT, Operation.TARGET_OP, Operation.FUNCTION_ADDRESS, Operation.CALL_FOREIGN, Operation.CALL_INDIRECT})
ATTRIBUTE_OPERATIONS = MEMORY_OPERATIONS | ATOMIC_OPERATIONS | META_OPERATIONS | TARGET_OPERATIONS | frozenset(
    {
        Operation.FLOAT_COMPARE,
        Operation.AGGREGATE_GET,
        Operation.SUM_MAKE,
        Operation.SUM_GET,
        Operation.INT_COMPARE,
        Operation.ROTATE_RIGHT,
    }
)


class TerminatorKind(IntEnum):
    BRANCH = 1
    CONDITIONAL_BRANCH = 2
    RETURN = 3
    TRAP = 4


class TrapReason(IntEnum):
    UNSPECIFIED = 0
    EXPLICIT = 1
    INTEGER_DIVIDE_BY_ZERO = 2


def trap_payload(reason: int | TrapReason = TrapReason.EXPLICIT, target_data: bytes = b"") -> bytes:
    reason_value = int(reason)
    if not 0 <= reason_value <= 0xFFFF:
        raise ValueError("portable trap reason must fit 16 bits")
    if reason_value == 0 and not target_data:
        return b""
    return uleb(reason_value) + bytes(target_data)


def decode_trap_payload(payload: bytes) -> tuple[int, bytes]:
    payload = bytes(payload)
    if not payload:
        return int(TrapReason.UNSPECIFIED), b""
    value = 0
    shift = 0
    for index, byte in enumerate(payload[:3]):
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            encoded = payload[: index + 1]
            if encoded != uleb(value):
                raise ValueError("non-canonical trap reason ULEB")
            if value > 0xFFFF:
                raise ValueError("portable trap reason exceeds 16 bits")
            if value == 0 and len(payload) == 1:
                raise ValueError("zero trap reason uses the empty canonical payload")
            return value, payload[index + 1 :]
        shift += 7
    raise ValueError("unterminated or oversized portable trap reason")


FOREIGN_FUNCTION_PREFIX = b"foreign-function-v1"
# Foreign boundary conventions with a defined verifier contract.  Each is
# owned by exactly one backend, which rejects the others.
ANDROID_AAPCS64_C_ABI = b"android-aapcs64-c"
LINUX_X86_64_SYSCALL_ABI = b"linux-x86_64-syscall-v1"
SYSV_X86_64_C_ABI = b"sysv-x86_64-c"
# Inline reads of the Linux initial process stack (argv, envp, auxv; ADR-094).
LINUX_X86_64_STARTUP_ABI = b"linux-x86_64-startup-v1"
FOREIGN_ABIS = (ANDROID_AAPCS64_C_ABI, b"win64-c", b"wasm32-import", LINUX_X86_64_SYSCALL_ABI, SYSV_X86_64_C_ABI, LINUX_X86_64_STARTUP_ABI)
ANDROID_EXPORT_PREFIX = b"android-export-v1"


@dataclass(frozen=True)
class AndroidExportDescription:
    abi: bytes
    visibility: bytes
    name: bytes
    function_cid: bytes


def android_export_symbol(
    function_object: SemanticObject,
    name: bytes,
    *,
    abi: bytes = b"android-aapcs64-c",
    visibility: bytes = b"default",
) -> SemanticObject:
    """Content-addressed Android C-ABI export declaration.

    This is an identity-only target/package carrier, not a language annotation.
    The exact function CID is part of the declaration identity, and the Android
    emitter uses it as a reachability root.
    """
    if function_object.kind != Kind.FUNCTION:
        raise ValueError("Android export target must be a function")
    if not name or b"\x00" in name or not abi or not visibility:
        raise ValueError("Android export ABI/visibility/name must be nonempty and NUL-free")
    if abi != b"android-aapcs64-c" or visibility != b"default":
        raise ValueError("prototype supports only android-aapcs64-c default-visibility exports")
    identity = bytearray(ANDROID_EXPORT_PREFIX)
    for blob in (abi, visibility, name):
        identity.extend(uleb(len(blob)) + blob)
    identity.extend(function_object.cid)
    return target(bytes(identity))


def decode_android_export(obj: SemanticObject) -> AndroidExportDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.EXPORT", obj.cid.hex(), "ANDROID-EXPORT-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-EXPORT-CARRIER")
    if not identity.startswith(ANDROID_EXPORT_PREFIX):
        fail("XAX.ANDROID.EXPORT", obj.cid.hex(), "ANDROID-EXPORT-IDENTITY", ANDROID_EXPORT_PREFIX.decode(), identity[:32].hex())
    cursor = Cursor(identity[len(ANDROID_EXPORT_PREFIX):], obj.cid.hex())
    abi = cursor.byte_string()
    visibility = cursor.byte_string()
    name = cursor.byte_string()
    function_cid = cursor.take(CID_SIZE)
    cursor.end("ANDROID-EXPORT-IDENTITY")
    if abi != b"android-aapcs64-c" or visibility != b"default" or not name or b"\x00" in name:
        fail("XAX.ANDROID.EXPORT", obj.cid.hex(), "ANDROID-EXPORT-ABI", ["android-aapcs64-c", "default", "nonempty name"], [abi, visibility, name])
    return AndroidExportDescription(abi, visibility, name, function_cid)


@dataclass(frozen=True)
class ForeignAllocatorContract:
    """The call returns either null or a fresh heap block of ``product(sizes)`` bytes."""

    size_inputs: tuple[int, ...]
    pointer_output: int
    token_output: int
    alignment: int
    zeroed: bool


@dataclass(frozen=True)
class ForeignDeallocatorContract:
    """The call releases the block named by ``pointer_input`` and its owner token."""

    pointer_input: int
    token_input: int


@dataclass(frozen=True)
class ForeignFunctionDescription:
    abi: bytes
    library: bytes
    name: bytes
    inputs: tuple[bytes, ...]
    outputs: tuple[bytes, ...]
    allocator: ForeignAllocatorContract | None = None
    deallocator: ForeignDeallocatorContract | None = None


_FOREIGN_ALLOCATOR_TAG = 1
_FOREIGN_DEALLOCATOR_TAG = 2


def foreign_function_symbol(
    library: bytes,
    name: bytes,
    inputs: Sequence[SemanticObject],
    outputs: Sequence[SemanticObject],
    *,
    abi: bytes = b"android-aapcs64-c",
    allocator: ForeignAllocatorContract | None = None,
    deallocator: ForeignDeallocatorContract | None = None,
) -> SemanticObject:
    """Create a bounded foreign-function declaration as an identity-only target carrier.

    The carrier embeds the exact typed call interface in its identity.  It is a
    declaration only: no library is inferred from the symbol name and no runtime
    helper or generic FFI is implied.  Optional heap contracts are appended
    only when present, so contract-free declarations keep their prior identity.
    """
    if not library or not name or not abi:
        raise ValueError("foreign function ABI, library, and name must be nonempty")
    if any(obj.kind != Kind.TYPE for obj in (*inputs, *outputs)):
        raise ValueError("foreign function inputs/outputs must be types")
    identity = bytearray(FOREIGN_FUNCTION_PREFIX)
    for blob in (abi, library, name):
        identity.extend(uleb(len(blob)) + blob)
    for types in (inputs, outputs):
        identity.extend(uleb(len(types)))
        identity.extend(b"".join(obj.cid for obj in types))
    if allocator is not None:
        if (
            not allocator.size_inputs
            or any(index >= len(inputs) for index in allocator.size_inputs)
            or max(allocator.pointer_output, allocator.token_output) >= len(outputs)
            or allocator.alignment < 1
            or allocator.alignment & (allocator.alignment - 1)
        ):
            raise ValueError("invalid foreign allocator contract")
        identity.extend(uleb(_FOREIGN_ALLOCATOR_TAG) + uleb(len(allocator.size_inputs)))
        identity.extend(b"".join(uleb(index) for index in allocator.size_inputs))
        identity.extend(uleb(allocator.pointer_output) + uleb(allocator.token_output))
        identity.extend(uleb(allocator.alignment) + uleb(int(allocator.zeroed)))
    if deallocator is not None:
        if max(deallocator.pointer_input, deallocator.token_input) >= len(inputs):
            raise ValueError("invalid foreign deallocator contract")
        identity.extend(uleb(_FOREIGN_DEALLOCATOR_TAG) + uleb(deallocator.pointer_input) + uleb(deallocator.token_input))
    return target(bytes(identity))


def decode_foreign_function(obj: SemanticObject) -> ForeignFunctionDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.FOREIGN.KIND", obj.cid.hex(), "FOREIGN-FUNCTION-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("FOREIGN-FUNCTION-CARRIER")
    if not identity.startswith(FOREIGN_FUNCTION_PREFIX):
        fail("XAX.FOREIGN.IDENTITY", obj.cid.hex(), "FOREIGN-FUNCTION-IDENTITY", FOREIGN_FUNCTION_PREFIX.decode(), identity[:32].hex())
    cursor = Cursor(identity[len(FOREIGN_FUNCTION_PREFIX):], obj.cid.hex())
    abi = cursor.byte_string()
    library = cursor.byte_string()
    name = cursor.byte_string()
    groups = []
    for _ in range(2):
        count = cursor.uleb()
        groups.append(tuple(cursor.take(CID_SIZE) for _ in range(count)))
    allocator = deallocator = None
    if cursor.pos < len(cursor.data) and cursor.data[cursor.pos] == _FOREIGN_ALLOCATOR_TAG:
        cursor.uleb()
        sizes = tuple(cursor.uleb() for _ in range(cursor.uleb()))
        pointer_output, token_output, alignment, zeroed = (cursor.uleb() for _ in range(4))
        allocator = ForeignAllocatorContract(sizes, pointer_output, token_output, alignment, bool(zeroed))
        if (
            not sizes or zeroed > 1 or any(index >= len(groups[0]) for index in sizes)
            or max(pointer_output, token_output) >= len(groups[1])
            or alignment < 1 or alignment & (alignment - 1)
        ):
            fail("XAX.FOREIGN.HEAP_CONTRACT", obj.cid.hex(), "FOREIGN-ALLOCATOR-CONTRACT", "in-range indices and power-of-two alignment", [sizes, pointer_output, token_output, alignment])
    if cursor.pos < len(cursor.data) and cursor.data[cursor.pos] == _FOREIGN_DEALLOCATOR_TAG:
        cursor.uleb()
        deallocator = ForeignDeallocatorContract(cursor.uleb(), cursor.uleb())
        if max(deallocator.pointer_input, deallocator.token_input) >= len(groups[0]):
            fail("XAX.FOREIGN.HEAP_CONTRACT", obj.cid.hex(), "FOREIGN-DEALLOCATOR-CONTRACT", "in-range indices", [deallocator.pointer_input, deallocator.token_input])
    cursor.end("FOREIGN-FUNCTION-IDENTITY")
    if not abi or not library or not name:
        fail("XAX.FOREIGN.IDENTITY", obj.cid.hex(), "FOREIGN-FUNCTION-NONEMPTY", "abi/library/name", [abi, library, name])
    return ForeignFunctionDescription(abi, library, name, groups[0], groups[1], allocator, deallocator)


def function_pointer_type() -> SemanticObject:
    """Canonical opaque function pointer used by bounded indirect-call ABIs."""
    return pointer_type(opaque_type(OpaqueKind.FUNCTION), Permission.READ, 8)


@dataclass(frozen=True)
class ValueRef:
    tag: int
    block: int
    index: int
    result: int = 0

    @classmethod
    def parameter(cls, block: int, index: int) -> "ValueRef":
        return cls(0, block, index)

    @classmethod
    def node_result(cls, block: int, node: int, result: int = 0) -> "ValueRef":
        return cls(1, block, node, result)


@dataclass(frozen=True)
class Node:
    operation: Operation
    operands: tuple[ValueRef, ...]
    result_types: tuple[SemanticObject, ...]
    member: int | None = None
    entity: SemanticObject | None = None
    attributes: tuple[int, ...] = ()


@dataclass(frozen=True)
class Terminator:
    kind: TerminatorKind
    values: tuple[ValueRef, ...] = ()
    edges: tuple[tuple[int, tuple[ValueRef, ...]], ...] = ()
    payload: bytes = b""

    @classmethod
    def branch(cls, target: int, arguments: Sequence[ValueRef] = ()) -> "Terminator":
        return cls(TerminatorKind.BRANCH, edges=((target, tuple(arguments)),))

    @classmethod
    def conditional_branch(
        cls,
        condition: ValueRef,
        true_target: int,
        true_arguments: Sequence[ValueRef],
        false_target: int,
        false_arguments: Sequence[ValueRef],
    ) -> "Terminator":
        return cls(
            TerminatorKind.CONDITIONAL_BRANCH,
            values=(condition,),
            edges=((true_target, tuple(true_arguments)), (false_target, tuple(false_arguments))),
        )

    @classmethod
    def return_(cls, values: Sequence[ValueRef] = ()) -> "Terminator":
        return cls(TerminatorKind.RETURN, values=tuple(values))

    @classmethod
    def trap(cls, payload: bytes = b"") -> "Terminator":
        return cls(TerminatorKind.TRAP, payload=payload)


@dataclass(frozen=True)
class Block:
    parameters: tuple[SemanticObject, ...]
    nodes: tuple[Node, ...]
    terminator: Terminator


def _encode_value(value: ValueRef) -> bytes:
    encoded = uleb(value.tag) + uleb(value.block) + uleb(value.index)
    return encoded + (uleb(value.result) if value.tag == 1 else b"")


def graph_fragment(blocks: Sequence[Block], entry_block: int = 0) -> SemanticObject:
    referenced = {
        object_.cid: object_
        for block in blocks
        for object_ in (
            *block.parameters,
            *(type_ for node in block.nodes for type_ in node.result_types),
            *(node.entity for node in block.nodes if node.entity is not None),
        )
    }
    references = tuple(sorted(referenced))
    positions = {cid: index for index, cid in enumerate(references)}
    body = bytearray(uleb(len(blocks)) + uleb(entry_block))
    for block in blocks:
        body.extend(uleb(len(block.parameters)))
        for type_object in block.parameters:
            body.extend(uleb(positions[type_object.cid]))
        body.extend(uleb(len(block.nodes)))
        for node in block.nodes:
            body.extend(uleb(node.operation))
            if node.operation == Operation.CALL_GROUP_MEMBER:
                if node.member is None:
                    raise ValueError("group call requires member index")
                body.extend(uleb(node.member))
            elif node.member is not None:
                raise ValueError("member index is only valid for group calls")
            if node.operation in ENTITY_OPERATIONS:
                if node.entity is None:
                    raise ValueError("operation requires entity reference")
                body.extend(uleb(positions[node.entity.cid]))
            elif node.entity is not None:
                raise ValueError("entity reference is not valid for operation")
            body.extend(uleb(len(node.operands)))
            for operand in node.operands:
                body.extend(_encode_value(operand))
            body.extend(uleb(len(node.result_types)))
            for type_object in node.result_types:
                body.extend(uleb(positions[type_object.cid]))
            if node.operation in ATTRIBUTE_OPERATIONS:
                body.extend(uleb(len(node.attributes)))
                for attribute in node.attributes:
                    if attribute < 0:
                        raise ValueError("operation attributes must be nonnegative")
                    body.extend(uleb(attribute))
            elif node.attributes:
                raise ValueError("attributes are not valid for operation")
        term = block.terminator
        body.extend(uleb(term.kind))
        if term.kind == TerminatorKind.BRANCH:
            _encode_edges(body, term.edges)
        elif term.kind == TerminatorKind.CONDITIONAL_BRANCH:
            body.extend(_encode_value(term.values[0]))
            _encode_edges(body, term.edges)
        elif term.kind == TerminatorKind.RETURN:
            body.extend(uleb(len(term.values)))
            for value in term.values:
                body.extend(_encode_value(value))
        elif term.kind == TerminatorKind.TRAP:
            decode_trap_payload(term.payload)
            body.extend(uleb(len(term.payload)) + term.payload)
        else:
            raise ValueError("unsupported terminator")
    return SemanticObject.create(Kind.GRAPH_FRAGMENT, bytes(body), references)


def _encode_edges(out: bytearray, edges: Sequence[tuple[int, tuple[ValueRef, ...]]]) -> None:
    for target, arguments in edges:
        out.extend(uleb(target) + uleb(len(arguments)))
        for argument in arguments:
            out.extend(_encode_value(argument))


def function(
    graph: SemanticObject,
    parameters: Sequence[SemanticObject],
    returns: Sequence[SemanticObject],
) -> SemanticObject:
    references = tuple(sorted({graph.cid, *(obj.cid for obj in parameters), *(obj.cid for obj in returns)}))
    positions = {cid: index for index, cid in enumerate(references)}
    body = bytearray(uleb(positions[graph.cid]) + uleb(len(parameters)))
    body.extend(b"".join(uleb(positions[obj.cid]) for obj in parameters))
    body.extend(uleb(len(returns)))
    body.extend(b"".join(uleb(positions[obj.cid]) for obj in returns))
    return SemanticObject.create(Kind.FUNCTION, bytes(body), references)


@dataclass(frozen=True)
class CallContractSummary:
    inputs: tuple[bytes, ...]
    outputs: tuple[bytes, ...]
    effects: tuple[tuple[EffectDomain, int], ...]
    may_return: bool
    may_trap: bool


def call_contract(
    inputs: Sequence[SemanticObject],
    outputs: Sequence[SemanticObject],
    *,
    may_return: bool,
    may_trap: bool,
) -> SemanticObject:
    """Create a bounded reusable CallContract object.

    Resource/capability-bearing values remain explicit exact input/output types.
    Effect domains are reconstructed from those exact effect-typed values, so the
    contract cannot encode an unbounded/unknown effect set.
    """

    if any(obj.kind != Kind.TYPE for obj in (*inputs, *outputs)):
        raise ValueError("CallContract inputs and outputs must be types")
    references = tuple(sorted({obj.cid for obj in (*inputs, *outputs)}))
    positions = {cid: index for index, cid in enumerate(references)}
    body = bytearray(uleb(len(inputs)))
    body.extend(b"".join(uleb(positions[obj.cid]) for obj in inputs))
    body.extend(uleb(len(outputs)))
    body.extend(b"".join(uleb(positions[obj.cid]) for obj in outputs))
    body.extend(bytes((int(bool(may_return)), int(bool(may_trap)))))
    return SemanticObject.create(Kind.CALL_CONTRACT, bytes(body), references)


def _decode_call_contract(
    obj: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
) -> CallContractSummary:
    if obj.kind != Kind.CALL_CONTRACT:
        fail("XAX.CALL.CONTRACT_KIND", obj.cid.hex(), "CALL-CONTRACT-KIND", Kind.CALL_CONTRACT.name, obj.kind.name)
    cursor = Cursor(obj.body, obj.cid.hex())
    inputs = tuple(_type_reference(obj, cursor, resolve) for _ in range(cursor.uleb()))
    outputs = tuple(_type_reference(obj, cursor, resolve) for _ in range(cursor.uleb()))
    may_return = cursor.boolean()
    may_trap = cursor.boolean()
    cursor.end("CALL-CONTRACT-BODY")
    used = set((*inputs, *outputs))
    if used != set(obj.references):
        fail(
            "XAX.CANON.UNUSED_REFERENCE",
            obj.cid.hex(),
            "SER-REFS-DIRECT-ONLY",
            sorted(cid.hex() for cid in obj.references),
            sorted(cid.hex() for cid in used),
        )
    effects = {
        (_decode_effect_type(resolve(type_cid)).domain, _decode_effect_type(resolve(type_cid)).instance)
        for type_cid in (*inputs, *outputs)
        if _is_effect(resolve(type_cid))
    }
    return CallContractSummary(inputs, outputs, tuple(sorted(effects)), may_return, may_trap)


def derive_call_contract(reader: "StoreReader", function_cid: bytes) -> SemanticObject:
    """Derive the smallest exact reusable contract from an already verified direct function."""

    resolve = _verified_resolver(reader)
    function_object = resolve(function_cid)
    _graph, parameters, returns = _decode_function_interface(function_object, resolve)
    summary = derive_effect_summary(reader, function_cid)
    return call_contract(
        tuple(resolve(cid) for cid in parameters),
        tuple(resolve(cid) for cid in returns),
        may_return=summary.may_return,
        may_trap=summary.may_trap,
    )


def verify_function_call_contract(
    reader: "StoreReader",
    function_cid: bytes,
    contract: SemanticObject | bytes,
) -> CallContractSummary:
    """Verify that a direct function is bounded by a reusable CallContract."""

    resolve = _verified_resolver(reader)
    function_object = resolve(function_cid)
    contract_object = resolve(contract) if isinstance(contract, bytes) else contract
    verified_contract = _decode_call_contract(contract_object, resolve)
    _graph, parameters, returns = _decode_function_interface(function_object, resolve)
    summary = derive_effect_summary(reader, function_cid)
    actual_effects = set(summary.domains)
    allowed_effects = set(verified_contract.effects)
    valid = (
        parameters == verified_contract.inputs
        and returns == verified_contract.outputs
        and actual_effects <= allowed_effects
        and (not summary.may_return or verified_contract.may_return)
        and (not summary.may_trap or verified_contract.may_trap)
    )
    if not valid:
        fail(
            "XAX.CALL.CONTRACT_MISMATCH",
            function_cid.hex(),
            "CALL-CONTRACT-BOUNDS-FUNCTION",
            {
                "inputs": [cid.hex() for cid in verified_contract.inputs],
                "outputs": [cid.hex() for cid in verified_contract.outputs],
                "effects": [(domain.name.lower(), instance) for domain, instance in verified_contract.effects],
                "may_return": verified_contract.may_return,
                "may_trap": verified_contract.may_trap,
            },
            {
                "inputs": [cid.hex() for cid in parameters],
                "outputs": [cid.hex() for cid in returns],
                "effects": [(domain.name.lower(), instance) for domain, instance in summary.domains],
                "may_return": summary.may_return,
                "may_trap": summary.may_trap,
            },
        )
    return verified_contract


@dataclass(frozen=True)
class RecursionMember:
    graph: SemanticObject
    parameters: tuple[SemanticObject, ...]
    returns: tuple[SemanticObject, ...]


def recursion_group(members: Sequence[RecursionMember]) -> SemanticObject:
    if not members:
        raise ValueError("recursion group must contain a member")
    references = tuple(
        sorted(
            {
                obj.cid
                for member in members
                for obj in (member.graph, *member.parameters, *member.returns)
            }
        )
    )
    positions = {cid: index for index, cid in enumerate(references)}
    body = bytearray(uleb(len(members)))
    for member in members:
        body.extend(uleb(positions[member.graph.cid]) + uleb(len(member.parameters)))
        body.extend(b"".join(uleb(positions[obj.cid]) for obj in member.parameters))
        body.extend(uleb(len(member.returns)))
        body.extend(b"".join(uleb(positions[obj.cid]) for obj in member.returns))
    return SemanticObject.create(Kind.RECURSION_GROUP, bytes(body), references)


def decode_bits_width(obj: SemanticObject) -> int:
    if obj.kind != Kind.TYPE:
        fail("XAX.TYPE.EXPECTED", obj.cid.hex(), "TYPE-BITS", Kind.TYPE.name, obj.kind.name)
    cursor = Cursor(obj.body, obj.cid.hex())
    form = cursor.uleb()
    width = cursor.uleb()
    cursor.end("TYPE-BODY")
    if obj.references or form != 1 or width < 1:
        fail("XAX.TYPE.BITS", obj.cid.hex(), "TYPE-BITS", "form=1,width>=1", [form, width])
    return width


def decode_float_format(obj: SemanticObject) -> FloatFormat:
    if obj.kind != Kind.TYPE:
        fail("XAX.TYPE.EXPECTED", obj.cid.hex(), "TYPE-FLOAT", Kind.TYPE.name, obj.kind.name)
    cursor = Cursor(obj.body, obj.cid.hex())
    form = cursor.uleb()
    value = cursor.uleb()
    cursor.end("TYPE-BODY")
    try:
        format = FloatFormat(value)
    except ValueError:
        fail("XAX.TYPE.FLOAT", obj.cid.hex(), "TYPE-FLOAT-FORMAT", [item.value for item in FloatFormat], value)
    if obj.references or form != 7:
        fail("XAX.TYPE.FLOAT", obj.cid.hex(), "TYPE-FLOAT", "form=7,known format", [form, value])
    return format


def decode_float_width(obj: SemanticObject) -> int:
    return 32 if decode_float_format(obj) == FloatFormat.BINARY32 else 64


def _decode_tuple_type(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> tuple[bytes, ...]:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 8:
        fail("XAX.TYPE.TUPLE", obj.cid.hex(), "TYPE-TUPLE", "tuple type", "different type form")
    items = tuple(_reference(obj, cursor, resolve).cid for _ in range(cursor.uleb()))
    cursor.end("TYPE-BODY")
    for cid in items:
        item = resolve(cid)
        _verify_type(item, resolve)
        if _is_proof_type(item):
            fail("XAX.TYPE.TUPLE", obj.cid.hex(), "TYPE-TUPLE-VALUE-ELEMENT", "non-proof value type", cid.hex())
    if set(items) != set(obj.references):
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in set(items)), sorted(cid.hex() for cid in obj.references))
    return items


def _decode_array_type(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> tuple[bytes, int]:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 9:
        fail("XAX.TYPE.ARRAY", obj.cid.hex(), "TYPE-ARRAY", "array type", "different type form")
    element = _reference(obj, cursor, resolve)
    count = cursor.uleb()
    cursor.end("TYPE-BODY")
    _verify_type(element, resolve)
    if _is_proof_type(element) or set(obj.references) != {element.cid}:
        fail("XAX.TYPE.ARRAY", obj.cid.hex(), "TYPE-ARRAY-VALUE-ELEMENT", "one non-proof value element", [element.cid.hex(), [cid.hex() for cid in obj.references]])
    return element.cid, count


def _decode_sum_type(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> tuple[bytes, ...]:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 10:
        fail("XAX.TYPE.SUM", obj.cid.hex(), "TYPE-SUM", "sum type", "different type form")
    count = cursor.uleb()
    if not count:
        fail("XAX.TYPE.SUM", obj.cid.hex(), "TYPE-SUM-NONEMPTY", ">= 1", 0)
    variants = tuple(_reference(obj, cursor, resolve).cid for _ in range(count))
    cursor.end("TYPE-BODY")
    for cid in variants:
        item = resolve(cid)
        _verify_type(item, resolve)
        if _is_proof_type(item):
            fail("XAX.TYPE.SUM", obj.cid.hex(), "TYPE-SUM-VALUE-VARIANT", "non-proof value type", cid.hex())
    if set(variants) != set(obj.references):
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in set(variants)), sorted(cid.hex() for cid in obj.references))
    return variants


def value_bit_width(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> int | None:
    """Portable scalar/compact-value width used only by bounded machine lowerings.

    Aggregate semantics do not mandate this layout.  Targets may choose a compact
    carrier when every component fits their register model.
    """
    if obj.kind != Kind.TYPE or not obj.body:
        return None
    form = Cursor(obj.body).uleb()
    if form == 1:
        return decode_bits_width(obj)
    if form == 2:
        return 64
    if form == 7:
        return decode_float_width(obj)
    if form == 8:
        widths = [value_bit_width(resolve(cid), resolve) for cid in _decode_tuple_type(obj, resolve)]
        return None if any(width is None for width in widths) else sum(widths)
    if form == 9:
        element, count = _decode_array_type(obj, resolve)
        width = value_bit_width(resolve(element), resolve)
        return None if width is None else width * count
    if form == 10:
        variants = _decode_sum_type(obj, resolve)
        widths = [value_bit_width(resolve(cid), resolve) for cid in variants]
        if any(width is None for width in widths):
            return None
        tag_width = max(1, (len(variants) - 1).bit_length())
        return tag_width + max(widths, default=0)
    return None


SUM_TAG_BYTES = 4


@dataclass(frozen=True)
class AbiLayout:
    """C-compatible physical placement of one value type on a target ABI.

    Products use natural C struct layout, arrays C array layout, and sums the
    ``repr(C)`` tagged-union shape ``struct { uint32_t tag; union { ... } }``.
    Padding bytes carry no semantic value; backends write them as zero.
    """

    size: int
    alignment: int
    offsets: tuple[int, ...] = ()
    payload_offset: int = 0


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def abi_layout(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject], pointer_bytes: int = 8) -> AbiLayout:
    if obj.kind != Kind.TYPE or not obj.body:
        fail("XAX.ABI.LAYOUT", obj.cid.hex(), "ABI-LAYOUT-VALUE-TYPE", "value type", obj.kind.name)
    form = Cursor(obj.body, obj.cid.hex()).uleb()
    if form == 1:
        width = decode_bits_width(obj)
        size = next((item for item in (1, 2, 4, 8) if width <= item * 8), 8 * ((width + 63) // 64))
        return AbiLayout(size, min(size, 8))
    if form == 2:
        return AbiLayout(pointer_bytes, pointer_bytes)
    if form == 7:
        size = decode_float_width(obj) // 8
        return AbiLayout(size, size)
    if form in (8, 9):
        if form == 8:
            components = _decode_tuple_type(obj, resolve)
        else:
            element, count = _decode_array_type(obj, resolve)
            components = (element,) * count
        cursor, alignment, offsets = 0, 1, []
        for cid in components:
            item = abi_layout(resolve(cid), resolve, pointer_bytes)
            cursor = _align_up(cursor, item.alignment)
            offsets.append(cursor)
            cursor += item.size
            alignment = max(alignment, item.alignment)
        return AbiLayout(_align_up(cursor, alignment), alignment, tuple(offsets))
    if form == 10:
        variants = tuple(abi_layout(resolve(cid), resolve, pointer_bytes) for cid in _decode_sum_type(obj, resolve))
        payload_alignment = max(item.alignment for item in variants)
        alignment = max(SUM_TAG_BYTES, payload_alignment)
        payload_offset = _align_up(SUM_TAG_BYTES, payload_alignment)
        size = _align_up(payload_offset + max(item.size for item in variants), alignment)
        return AbiLayout(size, alignment, (), payload_offset)
    fail("XAX.ABI.LAYOUT", obj.cid.hex(), "ABI-LAYOUT-VALUE-TYPE", "bits, pointer, float, tuple, array, or sum", form)


def abi_scalar_leaves(
    obj: SemanticObject, resolve: Callable[[bytes], SemanticObject], pointer_bytes: int = 8, base: int = 0
) -> tuple[tuple[int, int, bool], ...] | None:
    """Return ``(offset, size, is_float)`` scalar fields, or None for sums.

    Sum payload placement depends on the dynamic tag, so callers needing a
    static field list (homogeneous-float classification) treat sums as opaque.
    """
    form = Cursor(obj.body, obj.cid.hex()).uleb()
    if form in (1, 2, 7):
        return ((base, abi_layout(obj, resolve, pointer_bytes).size, form == 7),)
    if form in (8, 9):
        layout = abi_layout(obj, resolve, pointer_bytes)
        if form == 8:
            components = _decode_tuple_type(obj, resolve)
        else:
            element, count = _decode_array_type(obj, resolve)
            components = (element,) * count
        leaves: list[tuple[int, int, bool]] = []
        for offset, cid in zip(layout.offsets, components):
            inner = abi_scalar_leaves(resolve(cid), resolve, pointer_bytes, base + offset)
            if inner is None:
                return None
            leaves.extend(inner)
        return tuple(leaves)
    return None


def abi_homogeneous_float(
    obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]
) -> tuple[int, int] | None:
    """AAPCS64 homogeneous floating-point aggregate: ``(member bytes, count)``."""
    form = Cursor(obj.body, obj.cid.hex()).uleb()
    if form not in (8, 9):
        return None
    leaves = abi_scalar_leaves(obj, resolve)
    if not leaves or len(leaves) > 4 or not all(is_float for _, _, is_float in leaves):
        return None
    sizes = {size for _, size, _ in leaves}
    if len(sizes) != 1:
        return None
    member = sizes.pop()
    return (member, len(leaves)) if all(offset == index * member for index, (offset, _, _) in enumerate(leaves)) else None


def _decode_pointer_space(obj: SemanticObject) -> int:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 2:
        fail("XAX.TYPE.POINTER", obj.cid.hex(), "TYPE-POINTER", "pointer type", "different type form")
    return cursor.uleb()


def _decode_pointer_type(
    obj: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
) -> tuple[bytes, Permission, int]:
    if obj.kind != Kind.TYPE:
        fail("XAX.TYPE.EXPECTED", obj.cid.hex(), "TYPE-POINTER", Kind.TYPE.name, obj.kind.name)
    cursor = Cursor(obj.body, obj.cid.hex())
    form = cursor.uleb()
    space = cursor.uleb()
    element = _reference(obj, cursor, resolve)
    permission_value = cursor.uleb()
    alignment = cursor.uleb()
    cursor.end("TYPE-BODY")
    try:
        permission = Permission(permission_value)
    except ValueError:
        fail("XAX.TYPE.POINTER_PERMISSION", obj.cid.hex(), "TYPE-POINTER-PERMISSION", list(Permission), permission_value)
    if form != 2 or space < 1 or alignment < 1 or alignment & (alignment - 1):
        fail(
            "XAX.TYPE.POINTER",
            obj.cid.hex(),
            "TYPE-POINTER",
            "form=2,positive address space,power-of-two alignment",
            [form, space, alignment],
        )
    # Pointer element identity is semantic but does not manufacture provenance.
    # Proof/effect values are not addressable ordinary values; all other verified
    # value types may be pointed to, including floats and aggregates.
    _verify_type(element, resolve)
    if _is_proof_type(element):
        fail("XAX.TYPE.POINTER", obj.cid.hex(), "TYPE-POINTER-VALUE-ELEMENT", "non-proof value type", element.cid.hex())
    if set(obj.references) != {element.cid}:
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", [element.cid.hex()], [cid.hex() for cid in obj.references])
    return element.cid, permission, alignment


@dataclass(frozen=True)
class _EffectType:
    domain: EffectDomain
    instance: int


@dataclass(frozen=True)
class _ResourceType:
    kind: int
    state: int
    flags: ResourceFlags
    instance: int
    transitions: tuple[int, ...]


def _decode_effect_type(obj: SemanticObject) -> _EffectType:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 3:
        fail("XAX.TYPE.EFFECT", obj.cid.hex(), "TYPE-EFFECT", "effect type", "different type form")
    domain_value = cursor.uleb()
    try:
        domain = EffectDomain(domain_value)
    except ValueError:
        fail("XAX.TYPE.EFFECT", obj.cid.hex(), "TYPE-EFFECT-DOMAIN", list(EffectDomain), domain_value)
    instance = cursor.uleb() if cursor.remaining else 0
    cursor.end("TYPE-BODY")
    if obj.references or (instance == 0 and len(obj.body) != len(uleb(3) + uleb(domain))):
        fail("XAX.TYPE.EFFECT", obj.cid.hex(), "TYPE-EFFECT-CANONICAL", "domain plus optional positive instance", obj.body.hex())
    return _EffectType(domain, instance)


def _decode_resource_type(obj: SemanticObject) -> _ResourceType:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 4:
        fail("XAX.TYPE.RESOURCE", obj.cid.hex(), "TYPE-RESOURCE", "resource type", "different type form")
    kind, state = cursor.uleb(), cursor.uleb()
    if not cursor.remaining:
        if obj.references or (kind, state) != (1, 1):
            fail("XAX.TYPE.RESOURCE", obj.cid.hex(), "TYPE-RESOURCE-STACK-OWNER", "resource<stack-storage,live>", [kind, state])
        return _ResourceType(kind, state, ResourceFlags.RELEASABLE, 0, ())
    flags_value, instance = cursor.uleb(), cursor.uleb()
    transition_count = cursor.uleb()
    transitions = tuple(cursor.uleb() for _ in range(transition_count))
    cursor.end("TYPE-BODY")
    known_flags = int(ResourceFlags.AFFINE | ResourceFlags.PARTITIONABLE | ResourceFlags.RELEASABLE | ResourceFlags.ACQUIRABLE)
    if (
        obj.references
        or kind < 1
        or state < 1
        or flags_value & ~known_flags
        or transitions != tuple(sorted(set(transitions)))
        or any(target < 1 or target == state for target in transitions)
        or (kind, state, flags_value, instance, transitions) == (1, 1, int(ResourceFlags.RELEASABLE), 0, ())
    ):
        fail(
            "XAX.TYPE.RESOURCE",
            obj.cid.hex(),
            "TYPE-RESOURCE-CANONICAL",
            "positive kind/state, canonical flags/instance/transitions",
            [kind, state, flags_value, instance, list(transitions)],
        )
    return _ResourceType(kind, state, ResourceFlags(flags_value), instance, transitions)


def _decode_opaque_type(obj: SemanticObject) -> OpaqueKind:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 5:
        fail("XAX.TYPE.OPAQUE", obj.cid.hex(), "TYPE-OPAQUE", "opaque semantic type", "different type form")
    kind_value = cursor.uleb()
    cursor.end("TYPE-BODY")
    try:
        kind = OpaqueKind(kind_value)
    except ValueError:
        fail("XAX.TYPE.OPAQUE", obj.cid.hex(), "TYPE-OPAQUE-KIND", list(OpaqueKind), kind_value)
    if obj.references:
        fail("XAX.TYPE.OPAQUE", obj.cid.hex(), "TYPE-OPAQUE-CANONICAL", "no references", len(obj.references))
    return kind


def _decode_opaque_identity_type(obj: SemanticObject) -> bytes:
    cursor = Cursor(obj.body, obj.cid.hex())
    if cursor.uleb() != 6:
        fail("XAX.TYPE.OPAQUE_IDENTITY", obj.cid.hex(), "TYPE-OPAQUE-IDENTITY", "identity-qualified opaque ABI type", "different type form")
    identity = cursor.byte_string()
    cursor.end("TYPE-BODY")
    if not identity or obj.references:
        fail(
            "XAX.TYPE.OPAQUE_IDENTITY",
            obj.cid.hex(),
            "TYPE-OPAQUE-IDENTITY-CANONICAL",
            "nonempty identity and no references",
            [identity.hex(), len(obj.references)],
        )
    return identity


def _verify_type(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> None:
    cursor = Cursor(obj.body, obj.cid.hex())
    form = cursor.uleb()
    if form == 1:
        decode_bits_width(obj)
    elif form == 2:
        _decode_pointer_type(obj, resolve)
    elif form == 3:
        _decode_effect_type(obj)
    elif form == 4:
        _decode_resource_type(obj)
    elif form == 5:
        _decode_opaque_type(obj)
    elif form == 6:
        _decode_opaque_identity_type(obj)
    elif form == 7:
        decode_float_format(obj)
    elif form == 8:
        _decode_tuple_type(obj, resolve)
    elif form == 9:
        _decode_array_type(obj, resolve)
    elif form == 10:
        _decode_sum_type(obj, resolve)
    else:
        fail("XAX.TYPE.FORM", obj.cid.hex(), "TYPE-FORM-SUPPORTED", list(range(1, 11)), form)


def _is_memory_effect(obj: SemanticObject) -> bool:
    return obj.kind == Kind.TYPE and not obj.references and obj.body == uleb(3) + uleb(1)


def _is_stack_owner(obj: SemanticObject) -> bool:
    return obj.kind == Kind.TYPE and not obj.references and obj.body == uleb(4) + uleb(1) + uleb(1)


def _is_effect(obj: SemanticObject) -> bool:
    return obj.kind == Kind.TYPE and obj.body.startswith(uleb(3))


def _is_resource(obj: SemanticObject) -> bool:
    return obj.kind == Kind.TYPE and obj.body.startswith(uleb(4))


def _is_opaque(obj: SemanticObject, kind: OpaqueKind | None = None) -> bool:
    if obj.kind != Kind.TYPE or not obj.body.startswith(uleb(5)):
        return False
    return kind is None or _decode_opaque_type(obj) == kind


def _is_proof_type(obj: SemanticObject) -> bool:
    return _is_effect(obj) or _is_resource(obj)


def _is_stack_pointer(obj: SemanticObject) -> bool:
    # Type bodies are already canonically verified before this predicate is used.
    return obj.kind == Kind.TYPE and obj.body.startswith(uleb(2))


def _decode_constant(
    obj: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
) -> tuple[bytes, object]:
    cursor = Cursor(obj.body, obj.cid.hex())
    type_object = _reference(obj, cursor, resolve)
    value = cursor.byte_string()
    cursor.end("CONST-BODY")
    form = Cursor(type_object.body, type_object.cid.hex()).uleb()
    if form == 1:
        width = decode_bits_width(type_object)
        expected_size = (width + 7) // 8
        if len(value) != expected_size or (width % 8 and value[-1] >> (width % 8)):
            fail(
                "XAX.CONSTANT.WIDTH",
                obj.cid.hex(),
                "CONST-BITS-WIDTH",
                f"{width} canonical bits",
                value.hex(),
                [type_object.cid.hex()],
                [obj.cid.hex(), type_object.cid.hex()],
            )
        decoded: object = int.from_bytes(value, "little")
    elif form == 7:
        width = decode_float_width(type_object)
        if len(value) != width // 8:
            fail("XAX.CONSTANT.WIDTH", obj.cid.hex(), "CONST-FLOAT-WIDTH", width // 8, len(value))
        raw = int.from_bytes(value, "little")
        decoded = struct.unpack("<f" if width == 32 else "<d", value)[0]
        # Canonical NaNs use one quiet payload; ordinary finite/infinite bit
        # patterns and signed zero retain their exact bits.
        if math.isnan(decoded) and raw != (0x7FC00000 if width == 32 else 0x7FF8000000000000):
            fail("XAX.CONSTANT.FLOAT_NAN", obj.cid.hex(), "CONST-FLOAT-CANONICAL-NAN", "canonical quiet NaN", value.hex())
    else:
        fail("XAX.CONSTANT.TYPE", obj.cid.hex(), "CONST-SCALAR-TYPE", ["bits<N>", "float<F>"], type_object.cid.hex())
    if set(obj.references) != {type_object.cid}:
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", [type_object.cid.hex()], [cid.hex() for cid in obj.references])
    return type_object.cid, decoded


def _reference(obj: SemanticObject, cursor: Cursor, resolve: Callable[[bytes], SemanticObject]) -> SemanticObject:
    index = cursor.uleb()
    if index >= len(obj.references):
        fail("XAX.STRUCT.REF_INDEX", obj.cid.hex(), "GRAPH-REF-INDEX", f"< {len(obj.references)}", index)
    return resolve(obj.references[index])


def _read_value(cursor: Cursor) -> ValueRef:
    tag = cursor.uleb()
    if tag == 0:
        return ValueRef.parameter(cursor.uleb(), cursor.uleb())
    if tag == 1:
        return ValueRef.node_result(cursor.uleb(), cursor.uleb(), cursor.uleb())
    fail("XAX.STRUCT.VALUE_TAG", cursor.entity, "GRAPH-VALUE-TAG", [0, 1], tag)


@dataclass
class _ParsedNode:
    operation: int
    member: int | None
    entity: SemanticObject | None
    operands: tuple[ValueRef, ...]
    results: tuple[bytes, ...]
    attributes: tuple[int, ...]
    operand_types: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class _ParsedBlock:
    parameters: tuple[bytes, ...]
    nodes: tuple[_ParsedNode, ...]
    terminator: Terminator


@dataclass(frozen=True)
class _ParsedGraph:
    entry: int
    blocks: tuple[_ParsedBlock, ...]
    returns: tuple[tuple[bytes, ...], ...]
    member_spans: tuple[tuple[int, int], ...] = ()
    # Verified remaining byte extent of every pointer value with a storage
    # fact, for backends lowering checked accesses.
    pointer_extents: tuple[tuple[ValueRef, int], ...] = ()


class _ResourceCallBody(IntEnum):
    PASS_THROUGH = 0
    STORE_SEQUENCE = 1
    LOAD_SEQUENCE = 2
    MIXED_SEQUENCE = 3


MAX_RESOURCE_CALL_ACCESSES = 8


@dataclass(frozen=True)
class _ResourceCallContract:
    returns: tuple[bytes, ...]
    body_shape: _ResourceCallBody
    pointer_operand: int | None
    owner_operand: int
    effect_operand: int
    owner_result: int
    effect_result: int
    required_permission: Permission | None
    requires_initialized: bool
    initializes: bool
    returns_final_load: bool = False


def _resource_call_candidates(
    parameters: tuple[bytes, ...],
    resolve: Callable[[bytes], SemanticObject],
) -> tuple[_ResourceCallContract, ...]:
    if (
        len(parameters) == 2
        and _is_stack_owner(resolve(parameters[0]))
        and _is_memory_effect(resolve(parameters[1]))
    ):
        # Pass-through historically permits pure work in the single block.
        return (_ResourceCallContract(parameters, _ResourceCallBody.PASS_THROUGH, None, 0, 1, 0, 1, None, False, False),)
    if len(parameters) == 4 and _is_stack_pointer(resolve(parameters[0])):
        element = _decode_pointer_type(resolve(parameters[0]), resolve)[0]
        if (
            parameters[1] == element
            and _is_stack_owner(resolve(parameters[2]))
            and _is_memory_effect(resolve(parameters[3]))
        ):
            return (
                _ResourceCallContract(
                    (parameters[2], parameters[3]),
                    _ResourceCallBody.STORE_SEQUENCE,
                    0, 2, 3, 0, 1, Permission.WRITE, False, True,
                ),
                _ResourceCallContract(
                    (element, parameters[2], parameters[3]),
                    _ResourceCallBody.MIXED_SEQUENCE,
                    0, 2, 3, 1, 2, Permission.READ_WRITE, False, True, True,
                ),
            )
    if len(parameters) == 3 and _is_stack_pointer(resolve(parameters[0])):
        element = _decode_pointer_type(resolve(parameters[0]), resolve)[0]
        if _is_stack_owner(resolve(parameters[1])) and _is_memory_effect(resolve(parameters[2])):
            return (
                _ResourceCallContract(
                    (element, parameters[1], parameters[2]),
                    _ResourceCallBody.LOAD_SEQUENCE,
                    0, 1, 2, 1, 2, Permission.READ, True, False,
                ),
            )
    return ()


def _resource_call_contract(
    callee: SemanticObject,
    parameters: tuple[bytes, ...],
    returns: tuple[bytes, ...],
    resolve: Callable[[bytes], SemanticObject],
) -> _ResourceCallContract | None:
    matches = tuple(
        contract
        for contract in _resource_call_candidates(parameters, resolve)
        if contract.returns == returns
    )
    if not matches:
        return None
    graph, _, _ = _decode_function_interface(callee, resolve)
    parsed = _parse_graph(graph, resolve)
    if len(parsed.blocks) != 1:
        return None
    operations = tuple(Operation(node.operation) for node in parsed.blocks[0].nodes)
    body_matches = tuple(_summarize_resource_contract(contract, operations) for contract in matches)
    body_matches = tuple(contract for contract in body_matches if contract is not None)
    return body_matches[0] if len(body_matches) == 1 else None


def _resource_body_matches(contract: _ResourceCallContract, operations: tuple[Operation, ...]) -> bool:
    if contract.body_shape == _ResourceCallBody.PASS_THROUGH:
        return True
    if not 1 <= len(operations) <= MAX_RESOURCE_CALL_ACCESSES:
        return False
    if contract.body_shape == _ResourceCallBody.STORE_SEQUENCE:
        return all(operation == Operation.STORE_BITS_LE for operation in operations)
    if contract.body_shape == _ResourceCallBody.LOAD_SEQUENCE:
        return all(operation == Operation.LOAD_BITS_LE for operation in operations)
    if contract.body_shape == _ResourceCallBody.MIXED_SEQUENCE:
        return (
            len(operations) >= 2
            and operations[-1] == Operation.LOAD_BITS_LE
            and Operation.STORE_BITS_LE in operations
            and Operation.LOAD_BITS_LE in operations
            and all(operation in (Operation.STORE_BITS_LE, Operation.LOAD_BITS_LE) for operation in operations)
        )
    raise AssertionError(f"unknown resource-call body shape {contract.body_shape}")


def _summarize_resource_contract(
    contract: _ResourceCallContract,
    operations: tuple[Operation, ...],
) -> _ResourceCallContract | None:
    if not _resource_body_matches(contract, operations):
        return None
    if contract.body_shape == _ResourceCallBody.PASS_THROUGH:
        return contract
    requires_initialized = operations[0] == Operation.LOAD_BITS_LE
    initializes = Operation.STORE_BITS_LE in operations
    if all(operation == Operation.STORE_BITS_LE for operation in operations):
        required_permission = Permission.WRITE
    elif all(operation == Operation.LOAD_BITS_LE for operation in operations):
        required_permission = Permission.READ
    else:
        required_permission = Permission.READ_WRITE
    return _ResourceCallContract(
        contract.returns,
        contract.body_shape,
        contract.pointer_operand,
        contract.owner_operand,
        contract.effect_operand,
        contract.owner_result,
        contract.effect_result,
        required_permission,
        requires_initialized,
        initializes,
        contract.returns_final_load,
    )


def _resource_entry_contract(
    candidates: tuple[_ResourceCallContract, ...],
    operations: tuple[Operation, ...],
) -> _ResourceCallContract | None:
    matches = tuple(_summarize_resource_contract(contract, operations) for contract in candidates)
    matches = tuple(contract for contract in matches if contract is not None)
    return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True)
class _PointerFact:
    storage: tuple[int, int]
    element: bytes
    permission: Permission
    offset: int
    extent: int
    alignment: int
    alias_class: tuple[int, int]
    # Bytes the true offset may exceed ``offset`` by (``pointer_rebase``,
    # ADR-092): the pointer lies somewhere in [offset, offset + window] in
    # steps of ``alignment``.  Static facts hold for every position.
    window: int = 0


@dataclass(frozen=True)
class _OwnerFact:
    storage: tuple[int, int]


@dataclass(frozen=True)
class _EffectFact:
    storage: tuple[int, int]
    initialized: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class _HeapAllocationFact:
    storage: tuple[int, int]
    size: int | None
    zeroed: bool
    alignment: int


@dataclass(frozen=True)
class _BlockFacts:
    """Verifier facts carried by one control edge into a block's parameters."""

    pointers: dict[int, _PointerFact]
    owners: dict[int, _OwnerFact]
    effects: dict[int, _EffectFact]
    ended: frozenset
    live: frozenset


def _intersect_intervals(
    left: tuple[tuple[int, int], ...], right: tuple[tuple[int, int], ...]
) -> tuple[tuple[int, int], ...]:
    result: list[tuple[int, int]] = []
    for left_start, left_end in left:
        for right_start, right_end in right:
            start, end = max(left_start, right_start), min(left_end, right_end)
            if start < end:
                result.append((start, end))
    merged: tuple[tuple[int, int], ...] = ()
    for start, end in result:
        merged = _merge_interval(merged, start, end)
    return merged


def _merge_block_facts(incoming: Sequence[_BlockFacts], parameter_count: int) -> _BlockFacts:
    """Meet of edge facts: keep only what every incoming edge proves."""
    if not incoming:
        return _BlockFacts({}, {}, {}, frozenset(), frozenset())
    pointers: dict[int, _PointerFact] = {}
    owners: dict[int, _OwnerFact] = {}
    effects: dict[int, _EffectFact] = {}
    for index in range(parameter_count):
        candidates = [facts.pointers.get(index) for facts in incoming]
        if candidates[0] is not None and all(item == candidates[0] for item in candidates):
            pointers[index] = candidates[0]
        owner_candidates = [facts.owners.get(index) for facts in incoming]
        if owner_candidates[0] is not None and all(item == owner_candidates[0] for item in owner_candidates):
            owners[index] = owner_candidates[0]
        effect_candidates = [facts.effects.get(index) for facts in incoming]
        if effect_candidates[0] is not None and all(
            item is not None and item.storage == effect_candidates[0].storage for item in effect_candidates
        ):
            initialized = effect_candidates[0].initialized
            for item in effect_candidates[1:]:
                initialized = _intersect_intervals(initialized, item.initialized)
            effects[index] = _EffectFact(effect_candidates[0].storage, initialized)
    return _BlockFacts(
        pointers,
        owners,
        effects,
        frozenset().union(*(facts.ended for facts in incoming)),
        frozenset().union(*(facts.live for facts in incoming)),
    )


def _heap_view_triples(types: Sequence[bytes], resolve: Callable[[bytes], SemanticObject]) -> tuple[tuple[int, int, bool], ...]:
    """Positions ``(token index, extent, initialized)`` of ptr/view/effect triples."""
    triples: list[tuple[int, int, bool]] = []
    for index, cid in enumerate(types):
        info = _heap_view_info(resolve(cid))
        if info is None:
            continue
        if (
            index == 0
            or index + 1 >= len(types)
            or not _is_stack_pointer(resolve(types[index - 1]))
            or _decode_pointer_space(resolve(types[index - 1])) != 2
            or not _is_memory_effect(resolve(types[index + 1]))
        ):
            fail(
                "XAX.MEMORY.HEAP_VIEW",
                cid.hex(),
                "HEAP-VIEW-TRIPLE",
                "ptr<space 2,T,P,A>, heap-view<N>, effect<memory>",
                [item.hex() for item in types[max(0, index - 1):index + 2]],
            )
        triples.append((index, info[0], info[1]))
    return tuple(triples)


def _entry_heap_view_facts(
    parameters: tuple[bytes, ...], resolve: Callable[[bytes], SemanticObject]
) -> _BlockFacts:
    pointers: dict[int, _PointerFact] = {}
    owners: dict[int, _OwnerFact] = {}
    effects: dict[int, _EffectFact] = {}
    for index, extent, initialized in _heap_view_triples(parameters, resolve):
        storage = (-2, index)
        element, permission, alignment = _decode_pointer_type(resolve(parameters[index - 1]), resolve)
        pointers[index - 1] = _PointerFact(storage, element, permission, 0, extent, alignment, storage)
        owners[index] = _OwnerFact(storage)
        effects[index + 1] = _EffectFact(storage, ((0, extent),) if initialized else ())
    return _BlockFacts(pointers, owners, effects, frozenset(), frozenset())


def _end_heap_views(
    operands: tuple[ValueRef, ...],
    operand_types: tuple[bytes, ...],
    owners: dict[ValueRef, _OwnerFact],
    owner_consumers: set[ValueRef],
    ended: set[tuple[int, int]],
    resolve: Callable[[bytes], SemanticObject],
) -> None:
    """A view token consumed without a view-preserving contract ends its storage."""
    for ref, cid in zip(operands, operand_types):
        owner = owners.get(ref)
        if owner is not None and ref not in owner_consumers and _heap_view_info(resolve(cid)) is not None:
            owner_consumers.add(ref)
            ended.add(owner.storage)


def _constant_operand(blocks: Sequence["_ParsedBlock"], ref: ValueRef, resolve: Callable[[bytes], SemanticObject]) -> int | None:
    if ref.tag != 1:
        return None
    node = blocks[ref.block].nodes[ref.index]
    if node.operation != Operation.CONSTANT or node.entity is None:
        return None
    _type, value = _decode_constant(node.entity, resolve)
    return value if isinstance(value, int) else None


def pointer_extent_from_graph(graph, ref: ValueRef, resolve: Callable[[bytes], SemanticObject]) -> int:
    """Recover the statically verified extent for stack/heap-view pointer SSA."""
    if ref.tag == 0:
        parameters = graph.blocks[ref.block].parameters
        if ref.index + 1 < len(parameters):
            info = _heap_view_info(resolve(parameters[ref.index + 1]))
            if info is not None:
                return info[0]
        fail("XAX.NATIVE.POINTER", "native", "NATIVE-POINTER-EXTENT", "heap-view parameter or derived pointer", [ref.block, ref.index, ref.result])
    node = graph.blocks[ref.block].nodes[ref.index]
    if node.operation == Operation.STACK_ALLOC:
        return node.attributes[0]
    if node.operation == Operation.HEAP_VIEW:
        return node.attributes[0]
    if node.operation == Operation.ADDRESS_OFFSET:
        return pointer_extent_from_graph(graph, node.operands[0], resolve) - node.attributes[0]
    if node.operation == Operation.POINTER_CAST:
        return pointer_extent_from_graph(graph, node.operands[0], resolve)
    if node.operation == Operation.POINTER_REBASE:
        return node.attributes[0]
    fail("XAX.NATIVE.POINTER", "native", "NATIVE-POINTER-EXTENT", "stack allocation, heap view, or derived pointer", node.operation)


def _verify_foreign_heap_call(
    graph: SemanticObject,
    blocks: Sequence["_ParsedBlock"],
    block_index: int,
    node_index: int,
    node: "_ParsedNode",
    declaration: "ForeignFunctionDescription",
    resolve: Callable[[bytes], SemanticObject],
    pointers: dict[ValueRef, _PointerFact],
    owners: dict[ValueRef, _OwnerFact],
    effects: dict[ValueRef, _EffectFact],
    effect_consumers: dict[ValueRef, Operation],
    owner_consumers: set[ValueRef],
    ended: set[tuple[int, int]],
    heap_allocations: dict[ValueRef, _HeapAllocationFact],
) -> None:
    operand_types = node.operand_types
    for ref in node.operands:
        fact = pointers.get(ref)
        if fact is not None and fact.storage in ended:
            fail("XAX.MEMORY.USE_AFTER_LIFETIME", graph.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage", fact.storage)
    released: tuple[int, int] | None = None
    if declaration.deallocator is not None:
        contract = declaration.deallocator
        pointer_ref = node.operands[contract.pointer_input]
        token_ref = node.operands[contract.token_input]
        owner = owners.get(token_ref)
        if owner is None or token_ref in owner_consumers:
            fail("XAX.MEMORY.OWNER", graph.cid.hex(), "HEAP-DEALLOCATE-OWNER-PROVEN", "live heap owner or heap view", [token_ref.block, token_ref.index, token_ref.result])
        token_type = resolve(operand_types[contract.token_input])
        if _heap_view_info(token_type) is not None:
            fact = pointers.get(pointer_ref)
            if fact is None or fact.storage != owner.storage or fact.offset or fact.window:
                fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "HEAP-DEALLOCATE-VIEW-BASE", owner.storage, None if fact is None else [fact.storage, fact.offset])
            released = owner.storage
        elif _is_heap_owner(token_type):
            allocation = heap_allocations.get(pointer_ref)
            if allocation is None or allocation.storage != owner.storage:
                fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "HEAP-DEALLOCATE-ALLOCATION", owner.storage, None if allocation is None else allocation.storage)
        else:
            fail("XAX.MEMORY.OWNER", graph.cid.hex(), "HEAP-DEALLOCATE-OWNER-TYPE", "heap owner or heap view", token_type.cid.hex())
        owner_consumers.add(token_ref)
    _end_heap_views(node.operands, operand_types, owners, owner_consumers, ended, resolve)
    memory_outputs = [index for index, cid in enumerate(node.results) if _is_memory_effect(resolve(cid))]
    memory_inputs = [ref for ref, cid in zip(node.operands, operand_types) if _is_memory_effect(resolve(cid))]
    for position, ref in enumerate(memory_inputs):
        fact = effects.get(ref)
        if fact is None:
            continue
        if ref in effect_consumers:
            fail("XAX.MEMORY.EFFECT_FORK", graph.cid.hex(), "MEMORY-EFFECT-LINEAR", "one consumer", Operation.CALL_FOREIGN.name)
        effect_consumers[ref] = Operation.CALL_FOREIGN
        # Foreign code may rewrite bytes of storage it can reach, but cannot
        # make initialized bytes uninitialized or end storage it does not own.
        if position < len(memory_outputs) and fact.storage != released and fact.storage not in ended:
            effects[ValueRef.node_result(block_index, node_index, memory_outputs[position])] = fact
    if released is not None:
        ended.add(released)
    if declaration.allocator is not None:
        contract = declaration.allocator
        pointer_type_object = resolve(node.results[contract.pointer_output])
        if not _is_stack_pointer(pointer_type_object) or _decode_pointer_space(pointer_type_object) != 2:
            fail("XAX.FOREIGN.HEAP_CONTRACT", graph.cid.hex(), "FOREIGN-ALLOCATOR-POINTER", "ptr<space 2,...>", node.results[contract.pointer_output].hex())
        if not _is_heap_owner(resolve(node.results[contract.token_output])):
            fail("XAX.FOREIGN.HEAP_CONTRACT", graph.cid.hex(), "FOREIGN-ALLOCATOR-OWNER", "resource<heap>", node.results[contract.token_output].hex())
        size: int | None = 1
        for index in contract.size_inputs:
            value = _constant_operand(blocks, node.operands[index], resolve)
            size = None if value is None or size is None else size * value
        storage = (block_index, node_index)
        heap_allocations[ValueRef.node_result(block_index, node_index, contract.pointer_output)] = _HeapAllocationFact(
            storage, size, contract.zeroed, contract.alignment
        )
        owners[ValueRef.node_result(block_index, node_index, contract.token_output)] = _OwnerFact(storage)


def _verify_heap_view_call(
    graph: SemanticObject,
    block_index: int,
    node_index: int,
    node: "_ParsedNode",
    callee_parameters: tuple[bytes, ...],
    callee_returns: tuple[bytes, ...],
    resolve: Callable[[bytes], SemanticObject],
    pointers: dict[ValueRef, _PointerFact],
    owners: dict[ValueRef, _OwnerFact],
    effects: dict[ValueRef, _EffectFact],
    effect_consumers: dict[ValueRef, Operation],
    owner_consumers: set[ValueRef],
    ended: set[tuple[int, int]],
) -> None:
    """Borrow whole heap views across a direct call and re-establish returned ones."""
    inputs = _heap_view_triples(callee_parameters, resolve)
    outputs = _heap_view_triples(callee_returns, resolve)
    if not inputs and not outputs:
        return
    # Borrowed views come back in order per view type; unreturned ones were
    # released by the callee, so their storage ends here.
    passed: dict[bytes, list[tuple[int, int]]] = {}
    for index, extent, initialized in inputs:
        pointer_ref, token_ref, effect_ref = node.operands[index - 1:index + 2]
        owner = owners.get(token_ref)
        pointer_fact = pointers.get(pointer_ref)
        effect = effects.get(effect_ref)
        if owner is None or token_ref in owner_consumers:
            fail("XAX.MEMORY.OWNER", graph.cid.hex(), "HEAP-VIEW-CALL-OWNER", "live heap view", [token_ref.block, token_ref.index, token_ref.result])
        if pointer_fact is None or pointer_fact.storage != owner.storage or pointer_fact.offset or pointer_fact.window:
            fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "HEAP-VIEW-CALL-BASE", owner.storage, None if pointer_fact is None else [pointer_fact.storage, pointer_fact.offset])
        if effect is None or effect.storage != owner.storage:
            fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "MEMORY-EFFECT-PROVENANCE", owner.storage, None if effect is None else effect.storage)
        if owner.storage in ended:
            fail("XAX.MEMORY.USE_AFTER_LIFETIME", graph.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage", owner.storage)
        if effect_ref in effect_consumers:
            fail("XAX.MEMORY.EFFECT_FORK", graph.cid.hex(), "MEMORY-EFFECT-LINEAR", "one consumer", Operation.CALL_DIRECT.name)
        if initialized and not _range_initialized(effect.initialized, 0, extent):
            fail("XAX.MEMORY.UNINITIALIZED", graph.cid.hex(), "HEAP-VIEW-CALL-INITIALIZED", [0, extent], effect.initialized)
        owner_consumers.add(token_ref)
        effect_consumers[effect_ref] = Operation.CALL_DIRECT
        passed.setdefault(callee_parameters[index], []).append(owner.storage)
    for index, extent, initialized in outputs:
        pending = passed.get(callee_returns[index])
        storage = pending.pop(0) if pending else (block_index, node_index, index)
        element, permission, alignment = _decode_pointer_type(resolve(callee_returns[index - 1]), resolve)
        pointers[ValueRef.node_result(block_index, node_index, index - 1)] = _PointerFact(storage, element, permission, 0, extent, alignment, storage)
        owners[ValueRef.node_result(block_index, node_index, index)] = _OwnerFact(storage)
        effects[ValueRef.node_result(block_index, node_index, index + 1)] = _EffectFact(storage, ((0, extent),) if initialized else ())
    for remaining in passed.values():
        ended.update(remaining)


def _verify_heap_view_return(
    graph: SemanticObject,
    values: tuple[ValueRef, ...],
    value_types: tuple[bytes, ...],
    entry_parameters: tuple[bytes, ...],
    resolve: Callable[[bytes], SemanticObject],
    pointers: dict[ValueRef, _PointerFact],
    owners: dict[ValueRef, _OwnerFact],
    effects: dict[ValueRef, _EffectFact],
    owner_consumers: set[ValueRef],
    effect_consumers: dict[ValueRef, Operation],
    ended: set[tuple[int, int]],
) -> None:
    """Returned views must be whole, live, and match borrowed inputs in order."""
    outputs = _heap_view_triples(value_types, resolve)
    if not outputs:
        return
    borrowed: dict[bytes, list[tuple[int, int]]] = {}
    for index, _extent, _initialized in _heap_view_triples(entry_parameters, resolve):
        borrowed.setdefault(entry_parameters[index], []).append((-2, index))
    borrowed_storages = {storage for items in borrowed.values() for storage in items}
    for index, extent, initialized in outputs:
        pointer_ref, token_ref, effect_ref = values[index - 1:index + 2]
        owner = owners.get(token_ref)
        pointer_fact = pointers.get(pointer_ref)
        effect = effects.get(effect_ref)
        if (
            owner is None
            or token_ref in owner_consumers
            or owner.storage in ended
            or pointer_fact is None
            or pointer_fact.storage != owner.storage
            or pointer_fact.offset
            or pointer_fact.window
            or pointer_fact.extent != extent
            or effect is None
            or effect.storage != owner.storage
            or effect_ref in effect_consumers
        ):
            fail("XAX.MEMORY.HEAP_VIEW", graph.cid.hex(), "HEAP-VIEW-RETURN-WHOLE", "live base pointer, view, and matching effect", [token_ref.index, pointer_ref.index, effect_ref.index])
        if initialized and not _range_initialized(effect.initialized, 0, extent):
            fail("XAX.MEMORY.UNINITIALIZED", graph.cid.hex(), "HEAP-VIEW-RETURN-INITIALIZED", [0, extent], effect.initialized)
        pending = borrowed.get(value_types[index])
        expected = pending.pop(0) if pending else None
        if (expected is not None and owner.storage != expected) or (expected is None and owner.storage in borrowed_storages):
            fail("XAX.MEMORY.HEAP_VIEW", graph.cid.hex(), "HEAP-VIEW-RETURN-ORDER", expected, owner.storage)


def _merge_interval(
    intervals: tuple[tuple[int, int], ...],
    start: int,
    end: int,
) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for old_start, old_end in sorted((*intervals, (start, end))):
        if merged and old_start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], old_end))
        else:
            merged.append((old_start, old_end))
    return tuple(merged)


def _range_initialized(intervals: tuple[tuple[int, int], ...], start: int, end: int) -> bool:
    return any(old_start <= start and end <= old_end for old_start, old_end in intervals)


def _verify_memory_node(
    graph: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    block_index: int,
    node_index: int,
    node: _ParsedNode,
    pointers: dict[ValueRef, _PointerFact],
    owners: dict[ValueRef, _OwnerFact],
    effects: dict[ValueRef, _EffectFact],
    effect_consumers: dict[ValueRef, Operation],
    owner_consumers: set[ValueRef],
    allocations: set[tuple[int, int]],
    ended: set[tuple[int, int]],
    heap_allocations: dict[ValueRef, _HeapAllocationFact] | None = None,
) -> None:
    operation = Operation(node.operation)
    result_refs = tuple(ValueRef.node_result(block_index, node_index, index) for index in range(len(node.results)))

    def contract(inputs: int, results: int, attributes: int) -> None:
        actual = (len(node.operands), len(node.results), len(node.attributes))
        expected = (inputs, results, attributes)
        if actual != expected:
            fail("XAX.MEMORY.CONTRACT", graph.cid.hex(), "MEMORY-OP-CONTRACT", expected, actual)

    def pointer(value: ValueRef) -> _PointerFact:
        try:
            fact = pointers[value]
        except KeyError:
            fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "MEMORY-PROVENANCE-PROVEN", "local stack pointer", [value.block, value.index, value.result])
        if fact.storage in ended:
            fail("XAX.MEMORY.USE_AFTER_LIFETIME", graph.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage", fact.storage)
        return fact

    def consume_effect(value: ValueRef, storage: tuple[int, int]) -> _EffectFact:
        try:
            fact = effects[value]
        except KeyError:
            fail("XAX.MEMORY.EFFECT", graph.cid.hex(), "MEMORY-EFFECT-PROVEN", "local memory frontier", [value.block, value.index, value.result])
        if value in effect_consumers:
            code = "XAX.MEMORY.USE_AFTER_LIFETIME" if effect_consumers[value] == Operation.STACK_END else "XAX.MEMORY.EFFECT_FORK"
            fail(code, graph.cid.hex(), "MEMORY-EFFECT-LINEAR", "one consumer", operation.name)
        if fact.storage != storage:
            fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "MEMORY-EFFECT-PROVENANCE", storage, fact.storage)
        effect_consumers[value] = operation
        return fact

    def element_size(type_cid: bytes) -> int:
        type_object = resolve(type_cid)
        form = Cursor(type_object.body, type_object.cid.hex()).uleb()
        if form == 2:
            # Pointer elements (ADR-082) are one target pointer word; the
            # backend rejects an access size that differs from its pointer width.
            size = node.attributes[0]
            if size not in (4, 8):
                fail("XAX.MEMORY.ACCESS_SIZE", graph.cid.hex(), "MEMORY-POINTER-ELEMENT-SIZE", [4, 8], size)
            return size
        width = decode_bits_width(type_object) if form == 1 else decode_float_width(type_object) if form == 7 else None
        if width is None or width < 1 or width % 8:
            fail("XAX.MEMORY.VALUE_TYPE", graph.cid.hex(), "MEMORY-BYTE-ADDRESSABLE-VALUE", "bits or float scalar with whole-byte width", type_cid.hex())
        return width // 8

    def stored_pointer_provenance(value: ValueRef) -> None:
        # Only provenance-free pointers (function addresses, foreign/external
        # pointers) may be stored: a reloaded pointer carries no facts, so a
        # stored local-storage pointer could outlive its storage unseen (OI-37).
        if value in pointers:
            fact = pointers[value]
            fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "MEMORY-POINTER-STORE-LOCAL-PROVENANCE", "provenance-free pointer", [fact.storage[0], fact.storage[1]])

    def access(pointer_fact: _PointerFact, size: int, alignment: int) -> None:
        expected_size = element_size(pointer_fact.element)
        if size != expected_size:
            fail("XAX.MEMORY.ACCESS_SIZE", graph.cid.hex(), "MEMORY-ACCESS-SIZE", expected_size, size)
        if alignment < 1 or alignment & (alignment - 1) or pointer_fact.alignment < alignment or pointer_fact.offset % alignment:
            fail("XAX.MEMORY.ALIGNMENT", graph.cid.hex(), "MEMORY-ALIGNMENT", f"aligned to {alignment}", pointer_fact.offset)
        if size > pointer_fact.extent:
            fail("XAX.MEMORY.BOUNDS", graph.cid.hex(), "MEMORY-BOUNDS", f"at least {size} bytes", pointer_fact.extent)

    if operation == Operation.HEAP_VIEW:
        contract(3, 3, 2)
        extent, alignment = node.attributes
        raw_ref, token_ref, allocation_effect_ref = node.operands
        allocation = (heap_allocations or {}).get(raw_ref)
        if allocation is None:
            fail("XAX.MEMORY.PROVENANCE", graph.cid.hex(), "HEAP-VIEW-ALLOCATION-PROVEN", "foreign allocator pointer result", [raw_ref.block, raw_ref.index, raw_ref.result])
        owner = owners.get(token_ref)
        if owner is None or owner.storage != allocation.storage or token_ref in owner_consumers or not _is_heap_owner(resolve(node.operand_types[1])):
            fail("XAX.MEMORY.OWNER", graph.cid.hex(), "HEAP-VIEW-OWNER-PROVEN", allocation.storage, None if owner is None else owner.storage)
        if not _is_memory_effect(resolve(node.operand_types[2])):
            fail("XAX.MEMORY.EFFECT_TYPE", graph.cid.hex(), "HEAP-VIEW-ALLOCATOR-EFFECT", "effect<memory>", node.operand_types[2].hex())
        if (
            allocation_effect_ref.tag != 1
            or allocation_effect_ref.block != raw_ref.block
            or allocation_effect_ref.index != raw_ref.index
        ):
            fail(
                "XAX.MEMORY.PROVENANCE",
                graph.cid.hex(),
                "HEAP-VIEW-ALLOCATOR-EFFECT-PROVEN",
                [raw_ref.block, raw_ref.index],
                [allocation_effect_ref.block, allocation_effect_ref.index],
            )
        if allocation.size is None:
            fail("XAX.MEMORY.BOUNDS", graph.cid.hex(), "HEAP-VIEW-STATIC-SIZE", "constant allocator size", None)
        if extent < 1 or extent > allocation.size:
            fail("XAX.MEMORY.BOUNDS", graph.cid.hex(), "HEAP-VIEW-BOUNDS", f"1..{allocation.size}", extent)
        if alignment < 1 or alignment & (alignment - 1) or alignment > allocation.alignment:
            fail("XAX.MEMORY.ALIGNMENT", graph.cid.hex(), "HEAP-VIEW-ALIGNMENT", f"power of two <= {allocation.alignment}", alignment)
        result_type = resolve(node.results[0])
        if not _is_stack_pointer(result_type) or _decode_pointer_space(result_type) != 2:
            fail("XAX.MEMORY.HEAP_VIEW", graph.cid.hex(), "HEAP-VIEW-POINTER-TYPE", "ptr<space 2,T,P,A>", node.results[0].hex())
        element, permission, pointer_alignment = _decode_pointer_type(result_type, resolve)
        if pointer_alignment > alignment:
            fail("XAX.MEMORY.ALIGNMENT", graph.cid.hex(), "MEMORY-ALIGNMENT", f"<= {alignment}", pointer_alignment)
        if _heap_view_info(resolve(node.results[1])) != (extent, allocation.zeroed):
            fail("XAX.MEMORY.HEAP_VIEW", graph.cid.hex(), "HEAP-VIEW-TOKEN-TYPE", [extent, allocation.zeroed], node.results[1].hex())
        if not _is_memory_effect(resolve(node.results[2])):
            fail("XAX.MEMORY.EFFECT_TYPE", graph.cid.hex(), "MEMORY-EFFECT-TYPE", "effect<memory>", node.results[2].hex())
        storage = (block_index, node_index)
        ended.discard(storage)
        owner_consumers.add(token_ref)
        pointers[result_refs[0]] = _PointerFact(storage, element, permission, 0, extent, alignment, storage)
        owners[result_refs[1]] = _OwnerFact(storage)
        effects[result_refs[2]] = _EffectFact(storage, ((0, extent),) if allocation.zeroed else ())
        return

    if operation == Operation.STACK_ALLOC:
        contract(0, 3, 2)
        extent, alignment = node.attributes
        if extent < 1 or alignment < 1 or alignment & (alignment - 1):
            fail("XAX.MEMORY.ALLOCATION", graph.cid.hex(), "MEMORY-STACK-ALLOCATION", "positive extent and power-of-two alignment", node.attributes)
        pointer_element, permission, pointer_alignment = _decode_pointer_type(resolve(node.results[0]), resolve)
        if _decode_pointer_space(resolve(node.results[0])) != 1:
            fail("XAX.MEMORY.ALLOCATION", graph.cid.hex(), "MEMORY-STACK-ADDRESS-SPACE", 1, _decode_pointer_space(resolve(node.results[0])))
        if pointer_alignment > alignment:
            fail("XAX.MEMORY.ALIGNMENT", graph.cid.hex(), "MEMORY-ALIGNMENT", f"<= {alignment}", pointer_alignment)
        if not _is_stack_owner(resolve(node.results[1])):
            fail("XAX.MEMORY.OWNER_TYPE", graph.cid.hex(), "MEMORY-OWNER-TYPE", "resource<stack-storage,live>", node.results[1].hex())
        if not _is_memory_effect(resolve(node.results[2])):
            fail("XAX.MEMORY.EFFECT_TYPE", graph.cid.hex(), "MEMORY-EFFECT-TYPE", "effect<memory>", node.results[2].hex())
        storage = (block_index, node_index)
        if storage in allocations and storage not in ended:
            fail("XAX.MEMORY.LIFETIME_LEAK", graph.cid.hex(), "MEMORY-LIFETIME-EXPLICIT-END", "storage ended before re-allocation", storage)
        allocations.add(storage)
        ended.discard(storage)  # a loop re-entering this node starts a fresh lifetime
        pointers[result_refs[0]] = _PointerFact(storage, pointer_element, permission, 0, extent, alignment, storage)
        owners[result_refs[1]] = _OwnerFact(storage)
        effects[result_refs[2]] = _EffectFact(storage, ())
        return

    if operation == Operation.STACK_END:
        contract(2, 0, 0)
        owner_ref = node.operands[0]
        try:
            owner = owners[owner_ref]
        except KeyError:
            fail("XAX.MEMORY.OWNER", graph.cid.hex(), "MEMORY-OWNER-PROVEN", "local stack owner", [owner_ref.block, owner_ref.index, owner_ref.result])
        if owner_ref in owner_consumers or owner.storage in ended:
            fail("XAX.MEMORY.USE_AFTER_LIFETIME", graph.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage owner", owner.storage)
        if not _is_stack_owner(resolve(node.operand_types[0])) or not _is_memory_effect(resolve(node.operand_types[1])):
            fail("XAX.MEMORY.LIFETIME_TYPE", graph.cid.hex(), "MEMORY-LIFETIME-TYPES", ["resource<stack-storage,live>", "effect<memory>"], [cid.hex() for cid in node.operand_types])
        consume_effect(node.operands[1], owner.storage)
        owner_consumers.add(owner_ref)
        ended.add(owner.storage)
        return

    if operation == Operation.ATOMIC_FENCE:
        contract(1, 1, 2)
        order, scope = node.attributes
        _atomic_order(AtomicFamily.FENCE, order)
        try:
            AtomicScope(scope)
        except ValueError as error:
            fail("XAX.ATOMIC.SCOPE", graph.cid.hex(), "ATOMIC-SCOPE-ENUM", list(AtomicScope), str(error))
        if not _is_effect(resolve(node.operand_types[0])) or node.results != node.operand_types:
            fail("XAX.ATOMIC.CONTRACT", graph.cid.hex(), "ATOMIC-FENCE-EFFECT", "one matching effect frontier", [node.operand_types, node.results])
        if node.operands[0] in effects:
            memory_effect = effects[node.operands[0]]
            effects[result_refs[0]] = consume_effect(node.operands[0], memory_effect.storage)
        return

    if operation == Operation.POINTER_ADDRESS:
        # Exposes a pointer's address as bits<pointer width>.  The integer has
        # no provenance; only ``pointer_rebase`` can turn it back into a
        # pointer, and only inside a live view it names; the mandatory waiver attribute (1 =
        # provenance exposed) keeps the exposure machine-visible.  Foreign
        # code that dereferences the address must receive the storage's
        # memory effect so the lifetime ordering stays explicit.
        contract(1, 1, 1)
        if node.attributes[0] != 1:
            fail("XAX.MEMORY.ADDRESS_EXPOSE", graph.cid.hex(), "MEMORY-ADDRESS-EXPOSE-WAIVER", 1, node.attributes[0])
        _decode_pointer_type(resolve(node.operand_types[0]), resolve)
        width = decode_bits_width(resolve(node.results[0]))
        if width not in (32, 64):
            fail("XAX.MEMORY.ADDRESS_EXPOSE", graph.cid.hex(), "MEMORY-ADDRESS-WIDTH", [32, 64], width)
        pointer_fact = pointers.get(node.operands[0])
        if pointer_fact is not None and pointer_fact.storage in ended:
            fail("XAX.MEMORY.USE_AFTER_LIFETIME", graph.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage", pointer_fact.storage)
        return

    if operation == Operation.POINTER_REBASE:
        # Re-derives a pointer from an address integer *inside an existing
        # live view* (ADR-092).  Provenance is not manufactured: the result
        # carries the view's storage, lifetime, and alias class, an extent
        # narrowed to ``attributes[0]`` bytes, and a window covering every
        # position the runtime check admits.  At run time the address must lie
        # in [view, view + view extent - extent] and be aligned to the result
        # alignment relative to the view, or the program traps.
        contract(2, 1, 1)
        view = pointer(node.operands[0])
        extent = node.attributes[0]
        width = decode_bits_width(resolve(node.operand_types[1]))
        if width not in (32, 64):
            fail("XAX.MEMORY.REBASE", graph.cid.hex(), "MEMORY-REBASE-ADDRESS-WIDTH", [32, 64], width)
        view_type, result_type = resolve(node.operand_types[0]), resolve(node.results[0])
        element, permission, alignment = _decode_pointer_type(result_type, resolve)
        if _decode_pointer_space(view_type) != _decode_pointer_space(result_type) or element != view.element or permission & view.permission != permission:
            fail("XAX.MEMORY.REBASE", graph.cid.hex(), "MEMORY-REBASE-NO-AUTHORITY-GAIN", [view.element.hex(), int(view.permission)], [element.hex(), int(permission)])
        if extent < 1 or extent > view.extent:
            fail("XAX.MEMORY.BOUNDS", graph.cid.hex(), "MEMORY-REBASE-EXTENT", f"1..{view.extent}", extent)
        if alignment > view.alignment:
            fail("XAX.MEMORY.ALIGNMENT", graph.cid.hex(), "MEMORY-REBASE-ALIGNMENT", f"<= {view.alignment}", alignment)
        pointers[result_refs[0]] = _PointerFact(
            view.storage, element, permission, view.offset, extent, alignment, view.alias_class, view.window + view.extent - extent
        )
        return

    if operation == Operation.POINTER_CAST:
        contract(1, 1, 0)
        source_type = resolve(node.operand_types[0])
        result_type = resolve(node.results[0])
        source_element, source_permission, source_alignment = _decode_pointer_type(source_type, resolve)
        element, permission, alignment = _decode_pointer_type(result_type, resolve)
        if (
            _decode_pointer_space(source_type) != _decode_pointer_space(result_type)
            or element != source_element
            or permission & source_permission != permission
            or alignment > source_alignment
        ):
            fail(
                "XAX.MEMORY.POINTER_CAST",
                graph.cid.hex(),
                "MEMORY-POINTER-CAST-NO-AUTHORITY-GAIN",
                [_decode_pointer_space(source_type), source_element.hex(), int(source_permission), source_alignment],
                [_decode_pointer_space(result_type), element.hex(), int(permission), alignment],
            )
        # Casting never manufactures provenance.  If this value already carries
        # a local storage fact, propagate its bounds/lifetime under the narrower
        # type; external/opaque pointers remain external typed values.
        pointer_fact = pointers.get(node.operands[0])
        if pointer_fact is not None:
            if pointer_fact.storage in ended:
                fail("XAX.MEMORY.USE_AFTER_LIFETIME", graph.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage", pointer_fact.storage)
            pointers[result_refs[0]] = _PointerFact(
                pointer_fact.storage, element, permission, pointer_fact.offset, pointer_fact.extent,
                min(pointer_fact.alignment, alignment), pointer_fact.alias_class, pointer_fact.window
            )
        return

    pointer_fact = pointer(node.operands[0])
    if operation == Operation.ADDRESS_OFFSET:
        contract(1, 1, 1)
        offset = node.attributes[0]
        if offset > pointer_fact.extent:
            fail("XAX.MEMORY.BOUNDS", graph.cid.hex(), "MEMORY-ADDRESS-BOUNDS", f"<= {pointer_fact.extent}", offset)
        element, permission, alignment = _decode_pointer_type(resolve(node.results[0]), resolve)
        actual_alignment = pointer_fact.alignment if not offset else gcd(pointer_fact.alignment, offset)
        if element != pointer_fact.element or permission & pointer_fact.permission != permission:
            fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "MEMORY-ADDRESS-NO-AUTHORITY-GAIN", [pointer_fact.element.hex(), int(pointer_fact.permission)], [element.hex(), int(permission)])
        if alignment > actual_alignment:
            fail("XAX.MEMORY.ALIGNMENT", graph.cid.hex(), "MEMORY-ADDRESS-ALIGNMENT", f"<= {actual_alignment}", alignment)
        pointers[result_refs[0]] = _PointerFact(
            pointer_fact.storage,
            element,
            permission,
            pointer_fact.offset + offset,
            pointer_fact.extent - offset,
            actual_alignment,
            pointer_fact.alias_class,
            pointer_fact.window,
        )
        return

    if operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
        is_load = operation == Operation.CHECKED_LOAD_BITS_LE
        contract(3 if is_load else 4, 2 if is_load else 1, 2)
        size, alignment = node.attributes
        expected_size = element_size(pointer_fact.element)
        if size != expected_size:
            fail("XAX.MEMORY.ACCESS_SIZE", graph.cid.hex(), "MEMORY-ACCESS-SIZE", expected_size, size)
        if alignment != 1:
            fail("XAX.MEMORY.CHECKED_ALIGNMENT", graph.cid.hex(), "MEMORY-CHECKED-ALIGNMENT-BOOTSTRAP", 1, alignment)
        offset_type = node.operand_types[1]
        offset_width = decode_bits_width(resolve(offset_type))
        if offset_width != 32:
            fail("XAX.MEMORY.CHECKED_OFFSET", graph.cid.hex(), "MEMORY-CHECKED-OFFSET-BITS", 32, offset_width)
        if is_load:
            if not pointer_fact.permission & Permission.READ:
                fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "MEMORY-READ-PERMISSION", "read", int(pointer_fact.permission))
            effect_index = 2
            if node.results[0] != pointer_fact.element:
                fail("XAX.MEMORY.VALUE_TYPE", graph.cid.hex(), "MEMORY-CHECKED-LOAD-TYPE", pointer_fact.element.hex(), node.results[0].hex())
        else:
            if not pointer_fact.permission & Permission.WRITE:
                fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "MEMORY-WRITE-PERMISSION", "write", int(pointer_fact.permission))
            if node.operand_types[2] != pointer_fact.element:
                fail("XAX.MEMORY.VALUE_TYPE", graph.cid.hex(), "MEMORY-CHECKED-STORE-TYPE", pointer_fact.element.hex(), node.operand_types[2].hex())
            stored_pointer_provenance(node.operands[2])
            effect_index = 3
        effect = consume_effect(node.operands[effect_index], pointer_fact.storage)
        effect_type = node.operand_types[effect_index]
        if not _is_memory_effect(resolve(effect_type)) or node.results[-1] != effect_type:
            fail("XAX.MEMORY.EFFECT_TYPE", graph.cid.hex(), "MEMORY-EFFECT-TYPE", "matching effect<memory> continuation", [cid.hex() for cid in node.results])
        # The dynamic offset is range-checked at runtime.  A checked load can
        # prove initialization only when the entire candidate view is already
        # initialized; a checked store cannot add a statically known interval.
        view_end = pointer_fact.offset + pointer_fact.window + pointer_fact.extent
        if is_load and not _range_initialized(effect.initialized, pointer_fact.offset, view_end):
            fail("XAX.MEMORY.UNINITIALIZED", graph.cid.hex(), "MEMORY-CHECKED-LOAD-INITIALIZED-VIEW", [pointer_fact.offset, view_end], effect.initialized)
        effects[result_refs[-1]] = effect
        return

    if operation == Operation.RAW_LOAD_BITS_LE:
        contract(3, 3, 3)
        size, alignment, waivers = node.attributes
        if waivers < 1 or waivers & ~3:
            fail("XAX.MEMORY.RAW_WAIVER", graph.cid.hex(), "MEMORY-RAW-WAIVER", "nonzero subset of alignment|initialization", waivers)
        expected_size = element_size(pointer_fact.element)
        if size != expected_size or size > pointer_fact.extent:
            fail("XAX.MEMORY.BOUNDS", graph.cid.hex(), "MEMORY-RAW-BOUNDS-STILL-PROVEN", [expected_size, pointer_fact.extent], size)
        if not pointer_fact.permission & Permission.READ:
            fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "MEMORY-READ-PERMISSION", "read", int(pointer_fact.permission))
        if node.results[0] != pointer_fact.element:
            fail("XAX.MEMORY.VALUE_TYPE", graph.cid.hex(), "MEMORY-RAW-LOAD-TYPE", pointer_fact.element.hex(), node.results[0].hex())
        if not (waivers & 1):
            if alignment < 1 or alignment & (alignment - 1) or pointer_fact.alignment < alignment or pointer_fact.offset % alignment:
                fail("XAX.MEMORY.ALIGNMENT", graph.cid.hex(), "MEMORY-ALIGNMENT", f"aligned to {alignment}", pointer_fact.offset)
        effect = consume_effect(node.operands[1], pointer_fact.storage)
        effect_type = node.operand_types[1]
        unsafe_type = resolve(node.operand_types[2])
        unsafe = _decode_effect_type(unsafe_type) if _is_effect(unsafe_type) else None
        if not _is_memory_effect(resolve(effect_type)) or unsafe is None or unsafe.domain != EffectDomain.UNSAFE:
            fail("XAX.MEMORY.RAW_EFFECT", graph.cid.hex(), "MEMORY-RAW-UNSAFE-EFFECT", ["effect<memory>", "effect<unsafe>"], [cid.hex() for cid in node.operand_types[1:]])
        if node.results[1:] != (effect_type, node.operand_types[2]):
            fail("XAX.MEMORY.RAW_EFFECT", graph.cid.hex(), "MEMORY-RAW-EFFECT-CONTINUATION", [effect_type.hex(), node.operand_types[2].hex()], [cid.hex() for cid in node.results[1:]])
        if not (waivers & 2):
            start = pointer_fact.offset
            if not _range_initialized(effect.initialized, start, start + pointer_fact.window + size):
                fail("XAX.MEMORY.UNINITIALIZED", graph.cid.hex(), "MEMORY-INITIALIZED", [start, start + size], effect.initialized)
        effects[result_refs[1]] = effect
        return

    if operation == Operation.STORE_BITS_LE:
        contract(3, 1, 2)
        size, alignment = node.attributes
        access(pointer_fact, size, alignment)
        if not pointer_fact.permission & Permission.WRITE:
            fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "MEMORY-WRITE-PERMISSION", "write", int(pointer_fact.permission))
        if node.operand_types[1] != pointer_fact.element:
            fail("XAX.MEMORY.VALUE_TYPE", graph.cid.hex(), "MEMORY-STORE-TYPE", pointer_fact.element.hex(), node.operand_types[1].hex())
        stored_pointer_provenance(node.operands[1])
        effect = consume_effect(node.operands[2], pointer_fact.storage)
        if not _is_memory_effect(resolve(node.operand_types[2])) or node.results != (node.operand_types[2],):
            fail("XAX.MEMORY.EFFECT_TYPE", graph.cid.hex(), "MEMORY-EFFECT-TYPE", "one matching effect<memory> result", [cid.hex() for cid in node.results])
        start = pointer_fact.offset
        # A windowed store initializes an unknown position, so it proves nothing new.
        effects[result_refs[0]] = effect if pointer_fact.window else _EffectFact(effect.storage, _merge_interval(effect.initialized, start, start + size))
        return

    if operation == Operation.LOAD_BITS_LE:
        contract(2, 2, 2)
        size, alignment = node.attributes
        access(pointer_fact, size, alignment)
        if not pointer_fact.permission & Permission.READ:
            fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "MEMORY-READ-PERMISSION", "read", int(pointer_fact.permission))
        effect = consume_effect(node.operands[1], pointer_fact.storage)
        if node.results[0] != pointer_fact.element or not _is_memory_effect(resolve(node.operand_types[1])) or node.results[1] != node.operand_types[1]:
            fail("XAX.MEMORY.VALUE_TYPE", graph.cid.hex(), "MEMORY-LOAD-TYPE", [pointer_fact.element.hex(), node.operand_types[1].hex()], [cid.hex() for cid in node.results])
        start = pointer_fact.offset
        if not _range_initialized(effect.initialized, start, start + pointer_fact.window + size):
            fail("XAX.MEMORY.UNINITIALIZED", graph.cid.hex(), "MEMORY-INITIALIZED", [start, start + pointer_fact.window + size], effect.initialized)
        effects[result_refs[1]] = effect
        return

    if operation in (Operation.ATOMIC_LOAD, Operation.ATOMIC_STORE, Operation.ATOMIC_RMW, Operation.ATOMIC_CMPXCHG):
        family = {
            Operation.ATOMIC_LOAD: AtomicFamily.LOAD,
            Operation.ATOMIC_STORE: AtomicFamily.STORE,
            Operation.ATOMIC_RMW: AtomicFamily.RMW,
            Operation.ATOMIC_CMPXCHG: AtomicFamily.CMPXCHG,
        }[operation]
        expected = {
            Operation.ATOMIC_LOAD: (2, 2, 3),
            Operation.ATOMIC_STORE: (3, 1, 3),
            Operation.ATOMIC_RMW: (3, 2, 4),
            Operation.ATOMIC_CMPXCHG: (4, 3, 5),
        }[operation]
        contract(*expected)
        if operation == Operation.ATOMIC_RMW:
            update_kind, order, scope, alignment = node.attributes
            try:
                AtomicRmwKind(update_kind)
            except ValueError as error:
                fail("XAX.ATOMIC.RMW", graph.cid.hex(), "ATOMIC-RMW-KIND", list(AtomicRmwKind), str(error))
            _atomic_order(family, order)
        elif operation == Operation.ATOMIC_CMPXCHG:
            success_order, failure_order, scope, alignment, strength = node.attributes
            _atomic_order(family, success_order, failure_order)
            try:
                CompareExchangeStrength(strength)
            except ValueError as error:
                fail("XAX.ATOMIC.CMPXCHG", graph.cid.hex(), "ATOMIC-CMPXCHG-STRENGTH", list(CompareExchangeStrength), str(error))
        else:
            order, scope, alignment = node.attributes
            _atomic_order(family, order)
        try:
            AtomicScope(scope)
        except ValueError as error:
            fail("XAX.ATOMIC.SCOPE", graph.cid.hex(), "ATOMIC-SCOPE-ENUM", list(AtomicScope), str(error))
        size = (decode_bits_width(resolve(pointer_fact.element)) + 7) // 8
        access(pointer_fact, size, alignment)
        effect_index = {Operation.ATOMIC_LOAD: 1, Operation.ATOMIC_STORE: 2, Operation.ATOMIC_RMW: 2, Operation.ATOMIC_CMPXCHG: 3}[operation]
        effect = consume_effect(node.operands[effect_index], pointer_fact.storage)
        effect_type = node.operand_types[effect_index]
        if not _is_memory_effect(resolve(effect_type)) or node.results[-1] != effect_type:
            fail("XAX.ATOMIC.CONTRACT", graph.cid.hex(), "ATOMIC-MEMORY-EFFECT", "matching effect<memory> continuation", [effect_type.hex(), node.results[-1].hex()])
        if operation != Operation.ATOMIC_LOAD and not pointer_fact.permission & Permission.WRITE:
            fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "ATOMIC-WRITE-PERMISSION", "write", int(pointer_fact.permission))
        if operation != Operation.ATOMIC_STORE and not pointer_fact.permission & Permission.READ:
            fail("XAX.MEMORY.PERMISSION", graph.cid.hex(), "ATOMIC-READ-PERMISSION", "read", int(pointer_fact.permission))
        ordinary_inputs = node.operand_types[1:effect_index]
        if any(type_cid != pointer_fact.element for type_cid in ordinary_inputs):
            fail("XAX.ATOMIC.CONTRACT", graph.cid.hex(), "ATOMIC-VALUE-TYPE", pointer_fact.element.hex(), [cid.hex() for cid in ordinary_inputs])
        ordinary_results = node.results[:-1]
        if operation in (Operation.ATOMIC_LOAD, Operation.ATOMIC_RMW) and ordinary_results != (pointer_fact.element,):
            fail("XAX.ATOMIC.CONTRACT", graph.cid.hex(), "ATOMIC-RESULT-TYPE", pointer_fact.element.hex(), [cid.hex() for cid in ordinary_results])
        if operation == Operation.ATOMIC_STORE and ordinary_results:
            fail("XAX.ATOMIC.CONTRACT", graph.cid.hex(), "ATOMIC-STORE-RESULT", [], [cid.hex() for cid in ordinary_results])
        if operation == Operation.ATOMIC_CMPXCHG:
            if len(ordinary_results) != 2 or ordinary_results[0] != pointer_fact.element or decode_bits_width(resolve(ordinary_results[1])) != 1:
                fail("XAX.ATOMIC.CONTRACT", graph.cid.hex(), "ATOMIC-CMPXCHG-RESULT", [pointer_fact.element.hex(), "bits<1>"], [cid.hex() for cid in ordinary_results])
        if pointer_fact.window:
            fail("XAX.MEMORY.REBASE", graph.cid.hex(), "MEMORY-REBASE-STATIC-ONLY", "statically positioned pointer", pointer_fact.window)
        start = pointer_fact.offset
        initialized = _range_initialized(effect.initialized, start, start + size)
        if operation != Operation.ATOMIC_STORE and not initialized:
            fail("XAX.MEMORY.UNINITIALIZED", graph.cid.hex(), "ATOMIC-INITIALIZED", [start, start + size], effect.initialized)
        next_effect = _EffectFact(effect.storage, _merge_interval(effect.initialized, start, start + size))
        effects[result_refs[-1]] = next_effect
        return


def _verify_resource_effect_node(
    graph: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    node: _ParsedNode,
) -> None:
    operation = Operation(node.operation)

    def reject(expected: object, actual: object) -> None:
        fail("XAX.RESOURCE.CONTRACT", graph.cid.hex(), "RESOURCE-EFFECT-OP-CONTRACT", expected, actual)

    def resource(type_cid: bytes) -> _ResourceType:
        type_object = resolve(type_cid)
        if not _is_resource(type_object):
            reject("resource<K,state>", type_cid.hex())
        return _decode_resource_type(type_object)

    def effect(type_cid: bytes) -> _EffectType:
        type_object = resolve(type_cid)
        if not _is_effect(type_object):
            reject("effect<D>", type_cid.hex())
        return _decode_effect_type(type_object)

    if node.attributes:
        reject("no attributes", node.attributes)
    if operation == Operation.EFFECT_STEP:
        if not node.operands or len(node.operands) != len(node.results) or node.operand_types != node.results:
            reject("one or more matching effect inputs/results", [node.operand_types, node.results])
        domains = tuple(effect(type_cid) for type_cid in node.operand_types)
        if len(set(domains)) != len(domains) or len(set(node.operands)) != len(node.operands):
            fail("XAX.EFFECT.FORK", graph.cid.hex(), "EFFECT-DOMAIN-INSTANCE-UNIQUE", "distinct domain instances", domains)
        return

    expected_counts = {
        Operation.RESOURCE_ACQUIRE: (1, 2),
        Operation.RESOURCE_TRANSFER: (2, 2),
        Operation.RESOURCE_TRANSITION: (2, 2),
        Operation.RESOURCE_RELEASE: (2, 1),
        Operation.RESOURCE_DISCARD: (2, 1),
        Operation.RESOURCE_SPLIT: (2, 3),
        Operation.RESOURCE_JOIN: (3, 2),
    }[operation]
    if (len(node.operands), len(node.results)) != expected_counts:
        reject(expected_counts, (len(node.operands), len(node.results)))
    effect_input = node.operand_types[-1]
    effect_output = node.results[-1]
    effect(effect_input)
    if effect_input != effect_output:
        reject("matching effect continuation", [effect_input.hex(), effect_output.hex()])

    if operation == Operation.RESOURCE_ACQUIRE:
        acquired = resource(node.results[0])
        if not acquired.flags & ResourceFlags.ACQUIRABLE:
            fail("XAX.RESOURCE.ACQUIRE_STATE", graph.cid.hex(), "RESOURCE-ACQUIRE-ALLOWED", True, False)
        return

    source_cid = node.operand_types[0]
    source = resource(source_cid)
    if operation in (Operation.RESOURCE_RELEASE, Operation.RESOURCE_DISCARD):
        required = ResourceFlags.RELEASABLE if operation == Operation.RESOURCE_RELEASE else ResourceFlags.AFFINE
        if not source.flags & required:
            code = "XAX.RESOURCE.RELEASE_STATE" if operation == Operation.RESOURCE_RELEASE else "XAX.RESOURCE.DISCARD_LINEAR"
            fail(code, graph.cid.hex(), "RESOURCE-TERMINAL-ALLOWED", required.name.lower(), int(source.flags))
        return

    if operation == Operation.RESOURCE_JOIN:
        if node.operand_types[1] != source_cid or node.results[0] != source_cid:
            reject("two matching pieces and one matching joined resource", [node.operand_types, node.results])
        if not source.flags & ResourceFlags.PARTITIONABLE:
            fail("XAX.RESOURCE.JOIN", graph.cid.hex(), "RESOURCE-PARTITIONABLE", True, False)
        return

    target_cids = node.results[:-1]
    if operation == Operation.RESOURCE_TRANSFER:
        if target_cids != (source_cid,):
            reject("same resource type", [source_cid.hex(), *[cid.hex() for cid in target_cids]])
    elif operation == Operation.RESOURCE_TRANSITION:
        target = resource(target_cids[0])
        if (
            (target.kind, bool(target.flags & ResourceFlags.AFFINE), target.instance)
            != (source.kind, bool(source.flags & ResourceFlags.AFFINE), source.instance)
            or target.state not in source.transitions
        ):
            fail(
                "XAX.RESOURCE.INVALID_TRANSITION",
                graph.cid.hex(),
                "RESOURCE-STATE-TRANSITION",
                {"kind": source.kind, "from": source.state, "to": list(source.transitions)},
                {"kind": target.kind, "state": target.state},
            )
    else:
        if target_cids != (source_cid, source_cid) or not source.flags & ResourceFlags.PARTITIONABLE:
            fail(
                "XAX.RESOURCE.SPLIT",
                graph.cid.hex(),
                "RESOURCE-PARTITION-CONTRACT",
                "partitionable resource -> two matching pieces",
                [int(source.flags), *[cid.hex() for cid in target_cids]],
            )


def _target_constraint_matches(
    constraint: TargetValueConstraint,
    type_cid: bytes,
    resolve: Callable[[bytes], SemanticObject],
) -> bool:
    type_object = resolve(type_cid)
    if constraint.kind == TargetValueConstraintKind.BITS:
        try:
            return decode_bits_width(type_object) == constraint.primary and constraint.secondary == 0
        except XaxError:
            return False
    if constraint.kind == TargetValueConstraintKind.RESOURCE:
        if not _is_resource(type_object):
            return False
        resource = _decode_resource_type(type_object)
        return (resource.kind, resource.state) == (constraint.primary, constraint.secondary)
    if constraint.kind == TargetValueConstraintKind.EFFECT:
        if not _is_effect(type_object):
            return False
        effect = _decode_effect_type(type_object)
        return (effect.domain.value, effect.instance) == (constraint.primary, constraint.secondary)
    if constraint.kind == TargetValueConstraintKind.FUNCTION_POINTER:
        if (constraint.primary, constraint.secondary) != (0, 0):
            return False
        try:
            element, _permission, _alignment = _decode_pointer_type(type_object, resolve)
        except XaxError:
            return False
        return _is_opaque(resolve(element), OpaqueKind.FUNCTION)
    if constraint.kind == TargetValueConstraintKind.POINTER:
        if (constraint.primary, constraint.secondary) != (0, 0):
            return False
        try:
            _decode_pointer_type(type_object, resolve)
            return True
        except XaxError:
            return False
    return False


def _verify_target_node(
    graph: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    node: _ParsedNode,
) -> None:
    if node.entity is None or node.entity.kind != Kind.TARGET:
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-PACKAGE", Kind.TARGET.name, None if node.entity is None else node.entity.kind.name)
    target_description = decode_native_target(node.entity)
    if not target_description.target_operations:
        fail(
            "XAX.TARGET.OPERATION",
            graph.cid.hex(),
            "TARGET-OPERATION-CONTRACTS",
            "target package with declared operation contracts",
            target_description.identity.decode("ascii", "backslashreplace"),
        )
    if len(node.attributes) != 4:
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-ATTRIBUTES", 4, len(node.attributes))
    operation_id, scope_value, source_space, destination_space = node.attributes
    contract = next((item for item in target_description.target_operations if item.operation_id == operation_id), None)
    if contract is None:
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-DEFINED", [item.operation_id for item in target_description.target_operations], operation_id)
    try:
        scope = AtomicScope(scope_value)
    except ValueError:
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-SCOPE-ENUM", [item.value for item in AtomicScope], scope_value)
    if scope not in contract.supported_scopes:
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-SCOPE-SUPPORTED", [item.name.lower() for item in contract.supported_scopes], scope.name.lower())
    if (source_space, destination_space) != (contract.source_space, contract.destination_space):
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-MEMORY-SPACES", [contract.source_space, contract.destination_space], [source_space, destination_space])
    if len(node.operand_types) != len(contract.operands) or len(node.results) != len(contract.results):
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-ARITY", [len(contract.operands), len(contract.results)], [len(node.operand_types), len(node.results)])
    for label, actual, constraints in (("operand", node.operand_types, contract.operands), ("result", node.results, contract.results)):
        for index, (type_cid, constraint) in enumerate(zip(actual, constraints)):
            if not _target_constraint_matches(constraint, type_cid, resolve):
                fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-TYPE", [label, index, constraint.kind.name.lower(), constraint.primary, constraint.secondary], type_cid.hex())
    resource_inputs = [_decode_resource_type(resolve(cid)) for cid, constraint in zip(node.operand_types, contract.operands) if constraint.kind == TargetValueConstraintKind.RESOURCE]
    resource_outputs = [_decode_resource_type(resolve(cid)) for cid, constraint in zip(node.results, contract.results) if constraint.kind == TargetValueConstraintKind.RESOURCE]
    if resource_inputs and resource_outputs:
        for source in resource_inputs:
            for target_resource in resource_outputs:
                if source.kind == target_resource.kind and source.instance == target_resource.instance:
                    if source.state != target_resource.state and target_resource.state not in source.transitions:
                        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-RESOURCE-TRANSITION", [source.kind, source.state, list(source.transitions)], [target_resource.kind, target_resource.state])
    effect_inputs = [cid for cid, constraint in zip(node.operand_types, contract.operands) if constraint.kind == TargetValueConstraintKind.EFFECT]
    effect_outputs = [cid for cid, constraint in zip(node.results, contract.results) if constraint.kind == TargetValueConstraintKind.EFFECT]
    if effect_inputs != effect_outputs:
        fail("XAX.TARGET.OPERATION", graph.cid.hex(), "TARGET-OPERATION-EFFECT-CONTINUATION", [cid.hex() for cid in effect_inputs], [cid.hex() for cid in effect_outputs])


def _verify_meta_node(
    graph: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    node: _ParsedNode,
) -> None:
    operation = Operation(node.operation)
    operand_kinds, result_count, attribute_count = {
        Operation.META_TYPE_BITS_WIDTH: ((OpaqueKind.TYPE,), 1, 0),
        Operation.META_CONSTANT_VALUE: ((OpaqueKind.CONSTANT,), 1, 0),
        Operation.META_TARGET_SUPPORTS: ((OpaqueKind.TARGET,), 1, 1),
        Operation.META_DECLARED_INPUT: ((), 1, 1),
        Operation.META_MATERIALIZE_CONSTANT_FUNCTION: ((OpaqueKind.TYPE, None), 1, 0),
        Operation.META_FUNCTION_GRAPH: ((OpaqueKind.FUNCTION,), 1, 0),
        Operation.META_GRAPH_BLOCK_COUNT: ((OpaqueKind.GRAPH,), 1, 0),
        Operation.META_GRAPH_NODE_COUNT: ((OpaqueKind.GRAPH, None), 1, 0),
        Operation.META_GRAPH_NODE_OPERATION: ((OpaqueKind.GRAPH, None, None), 1, 0),
        Operation.META_CANONICAL_STORE: ((OpaqueKind.OBJECT,), 1, 0),
        Operation.META_VERIFY_SEMANTICS: ((OpaqueKind.OBJECT,), 1, 0),
        Operation.META_MATERIALIZE_PROGRAM: ((OpaqueKind.FUNCTION,), 1, 0),
        Operation.META_FUNCTION_PARAMETER_COUNT: ((OpaqueKind.FUNCTION,), 1, 0),
        Operation.META_FUNCTION_RETURN_COUNT: ((OpaqueKind.FUNCTION,), 1, 0),
    }[operation]
    actual = (len(node.operands), len(node.results), len(node.attributes))
    expected = (len(operand_kinds), result_count, attribute_count)
    if actual != expected:
        fail("XAX.META.CONTRACT", graph.cid.hex(), "META-OP-ARITY", expected, actual)
    for type_cid, kind in zip(node.operand_types, operand_kinds):
        type_object = resolve(type_cid)
        if kind is None:
            decode_bits_width(type_object)
        elif not _is_opaque(type_object, kind):
            fail("XAX.META.CONTRACT", graph.cid.hex(), "META-OPERAND-TYPE", f"opaque<{kind.name.lower()}>", type_cid.hex())
    if operation == Operation.META_MATERIALIZE_CONSTANT_FUNCTION:
        if not _is_opaque(resolve(node.results[0]), OpaqueKind.FUNCTION):
            fail("XAX.META.CONTRACT", graph.cid.hex(), "META-RESULT-TYPE", "opaque<function>", node.results[0].hex())
    elif operation == Operation.META_MATERIALIZE_PROGRAM:
        if not _is_opaque(resolve(node.results[0]), OpaqueKind.OBJECT):
            fail("XAX.META.CONTRACT", graph.cid.hex(), "META-RESULT-TYPE", "opaque<object>", node.results[0].hex())
    elif operation == Operation.META_FUNCTION_GRAPH:
        if not _is_opaque(resolve(node.results[0]), OpaqueKind.GRAPH):
            fail("XAX.META.CONTRACT", graph.cid.hex(), "META-RESULT-TYPE", "opaque<graph>", node.results[0].hex())
    elif operation == Operation.META_CANONICAL_STORE:
        if not _is_opaque(resolve(node.results[0]), OpaqueKind.BYTES):
            fail("XAX.META.CONTRACT", graph.cid.hex(), "META-RESULT-TYPE", "opaque<bytes>", node.results[0].hex())
    elif operation == Operation.META_VERIFY_SEMANTICS:
        if decode_bits_width(resolve(node.results[0])) != 1:
            fail("XAX.META.CONTRACT", graph.cid.hex(), "META-VERIFY-RESULT", "bits<1>", node.results[0].hex())
    else:
        width = decode_bits_width(resolve(node.results[0]))
        if operation == Operation.META_TARGET_SUPPORTS and width != 1:
            fail("XAX.META.CONTRACT", graph.cid.hex(), "META-TARGET-SUPPORT-RESULT", "bits<1>", f"bits<{width}>")
    if operation == Operation.META_TARGET_SUPPORTS and node.attributes[0] not in Operation._value2member_map_:
        fail("XAX.META.CONTRACT", graph.cid.hex(), "META-TARGET-OPERATION", list(Operation), node.attributes[0])


def _verify_linear_flow(
    graph: SemanticObject,
    parsed: _ParsedGraph,
    resolve: Callable[[bytes], SemanticObject],
) -> None:
    value_types: dict[ValueRef, bytes] = {}
    node_uses: dict[ValueRef, list[tuple[int, int]]] = {}
    term_uses: dict[ValueRef, list[tuple[int, int]]] = {}
    predecessors: dict[int, list[tuple[int, tuple[ValueRef, ...]]]] = {index: [] for index in range(len(parsed.blocks))}
    for block_index, block in enumerate(parsed.blocks):
        for index, type_cid in enumerate(block.parameters):
            value_types[ValueRef.parameter(block_index, index)] = type_cid
        for node_index, node in enumerate(block.nodes):
            for result_index, type_cid in enumerate(node.results):
                value_types[ValueRef.node_result(block_index, node_index, result_index)] = type_cid
            for operand in node.operands:
                node_uses.setdefault(operand, []).append((block_index, node_index))
        for edge_index, (target, arguments) in enumerate(block.terminator.edges):
            predecessors[target].append((block_index, arguments))
            for argument in arguments:
                term_uses.setdefault(argument, []).append((block_index, edge_index))
        for value in block.terminator.values:
            term_uses.setdefault(value, []).append((block_index, -1))

    for block_index, block in enumerate(parsed.blocks):
        if block_index == parsed.entry:
            continue
        for parameter_index, type_cid in enumerate(block.parameters):
            if not _is_proof_type(resolve(type_cid)):
                continue
            if not predecessors[block_index]:
                fail("XAX.RESOURCE.UNREACHABLE_PARAMETER", graph.cid.hex(), "RESOURCE-BLOCK-PREDECESSOR", "at least one", 0)
            for _, arguments in predecessors[block_index]:
                if parameter_index >= len(arguments):
                    fail("XAX.RESOURCE.BLOCK_FLOW", graph.cid.hex(), "RESOURCE-BLOCK-ARGUMENT", parameter_index, len(arguments))

    for value, type_cid in value_types.items():
        type_object = resolve(type_cid)
        if not _is_proof_type(type_object):
            continue
        uses = node_uses.get(value, [])
        terms = term_uses.get(value, [])
        if uses and terms:
            fail("XAX.RESOURCE.DUPLICATE", graph.cid.hex(), "RESOURCE-LINEAR-CONTINUATION", "one continuation", "node and terminator")
        if uses:
            if len(uses) != 1 or uses[0][0] != value.block:
                fail("XAX.RESOURCE.DUPLICATE", graph.cid.hex(), "RESOURCE-LINEAR-CONTINUATION", "one same-block consumer", uses)
            continue
        defining_term = parsed.blocks[value.block].terminator
        local_terms = [use for use in terms if use[0] == value.block]
        if len(local_terms) != len(terms):
            fail("XAX.RESOURCE.BLOCK_FLOW", graph.cid.hex(), "RESOURCE-EXPLICIT-BLOCK-PARAMETER", value.block, terms)
        if defining_term.kind == TerminatorKind.CONDITIONAL_BRANCH:
            edge_counts = [sum(use == (value.block, edge) for use in local_terms) for edge in range(2)]
            if edge_counts != [1, 1]:
                fail("XAX.RESOURCE.DROP", graph.cid.hex(), "RESOURCE-EACH-CONTROL-PATH", [1, 1], edge_counts)
        elif defining_term.kind == TerminatorKind.TRAP and _is_effect(type_object):
            if local_terms:
                fail("XAX.EFFECT.FORK", graph.cid.hex(), "EFFECT-TRAP-END", 0, len(local_terms))
        elif len(local_terms) != 1:
            code = "XAX.RESOURCE.DROP" if _is_resource(type_object) else "XAX.EFFECT.FORK"
            fail(code, graph.cid.hex(), "RESOURCE-LINEAR-CONTINUATION", 1, len(local_terms))

    def origin(value: ValueRef, active: set[ValueRef]) -> tuple[object, ...]:
        if value in active:
            return ("cycle", value.block, value.index)
        if value.tag == 0:
            if value.block == parsed.entry:
                return ("parameter", value.index)
            incoming = predecessors[value.block]
            origins = {origin(arguments[value.index], active | {value}) for _, arguments in incoming}
            return next(iter(origins)) if len(origins) == 1 else ("phi", value.block, value.index)
        node = parsed.blocks[value.block].nodes[value.index]
        operation = Operation(node.operation)
        if operation == Operation.RESOURCE_ACQUIRE:
            return ("acquire", value.block, value.index)
        if operation in (Operation.RESOURCE_TRANSFER, Operation.RESOURCE_TRANSITION):
            return origin(node.operands[0], active | {value})
        if operation == Operation.RESOURCE_SPLIT:
            return ("split", value.block, value.index, value.result, origin(node.operands[0], active | {value}))
        if operation == Operation.RESOURCE_JOIN:
            return ("join", value.block, value.index)
        return ("opaque", value.block, value.index, value.result)

    for block_index, block in enumerate(parsed.blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation != Operation.RESOURCE_JOIN:
                continue
            left, right = (origin(value, set()) for value in node.operands[:2])
            valid = (
                len(left) >= 5
                and len(right) >= 5
                and left[0] == right[0] == "split"
                and left[1:3] == right[1:3]
                and {left[3], right[3]} == {0, 1}
                and left[4] == right[4]
            )
            if not valid:
                fail("XAX.RESOURCE.JOIN", graph.cid.hex(), "RESOURCE-JOIN-SIBLINGS", "two pieces from one split", [left, right])


@dataclass(frozen=True)
class EffectSummary:
    domains: tuple[tuple[EffectDomain, int], ...]
    may_return: bool
    may_trap: bool


def derive_effect_summary(reader: StoreReader, function_cid: bytes) -> EffectSummary:
    resolve = _verified_resolver(reader)
    function_object = resolve(function_cid)
    graph_object, parameters, returns = _decode_function_interface(function_object, resolve)
    graph = _parse_graph(graph_object, resolve)
    domains = {
        (_decode_effect_type(resolve(type_cid)).domain, _decode_effect_type(resolve(type_cid)).instance)
        for type_cid in (*parameters, *returns)
        if _is_effect(resolve(type_cid))
    }
    return EffectSummary(
        tuple(sorted(domains)),
        bool(graph.returns),
        any(block.terminator.kind == TerminatorKind.TRAP for block in graph.blocks),
    )


@dataclass(frozen=True)
class MemoryEvent:
    agent: int
    storage: str
    start: int
    end: int
    write: bool
    atomic: bool
    ordered_after: tuple[int, ...] = ()


@dataclass(frozen=True)
class AtomicLitmusEvent:
    agent: int
    location: str
    family: AtomicFamily
    order: AtomicOrder
    reads_from: int | None = None
    failure_order: AtomicOrder | None = None
    strength: CompareExchangeStrength | None = None
    succeeded: bool | None = None
    spurious_failure: bool = False


@dataclass(frozen=True)
class AtomicLitmusResult:
    happens_before: tuple[tuple[int, int], ...]
    modification_order: tuple[tuple[str, tuple[int, ...]], ...]
    seq_cst_order: tuple[int, ...]


def _transitive_edges(count: int, edges: set[tuple[int, int]]) -> set[tuple[int, int]]:
    reachable = [set() for _ in range(count)]
    for source, target in edges:
        if source < 0 or target < 0 or source >= count or target >= count:
            fail("XAX.CONCURRENCY.EDGE", "concurrency", "CONCURRENCY-EVENT-EDGE", f"event < {count}", [source, target])
        reachable[source].add(target)
    changed = True
    while changed:
        changed = False
        for source in range(count):
            expanded = set().union(*(reachable[target] for target in tuple(reachable[source]))) if reachable[source] else set()
            if not expanded <= reachable[source]:
                reachable[source] |= expanded
                changed = True
    return {(source, target) for source, targets in enumerate(reachable) for target in targets}


def validate_memory_events(events: Sequence[MemoryEvent]) -> tuple[tuple[int, int], ...]:
    edges: set[tuple[int, int]] = set()
    previous: dict[int, int] = {}
    for index, event in enumerate(events):
        if event.start < 0 or event.end <= event.start:
            fail("XAX.CONCURRENCY.EVENT", str(index), "CONCURRENCY-EVENT-EXTENT", "0 <= start < end", [event.start, event.end])
        if event.agent in previous:
            edges.add((previous[event.agent], index))
        previous[event.agent] = index
        edges.update((source, index) for source in event.ordered_after)
    happens_before = _transitive_edges(len(events), edges)
    if any((index, index) in happens_before for index in range(len(events))):
        fail("XAX.CONCURRENCY.CYCLE", "concurrency", "CONCURRENCY-HAPPENS-BEFORE-ACYCLIC", "acyclic", tuple(sorted(happens_before)))
    for left_index, left in enumerate(events):
        for right_index in range(left_index + 1, len(events)):
            right = events[right_index]
            conflicts = left.storage == right.storage and left.start < right.end and right.start < left.end and (left.write or right.write)
            ordered = (left_index, right_index) in happens_before or (right_index, left_index) in happens_before
            if left.agent != right.agent and conflicts and not ordered and not (left.atomic and right.atomic):
                fail(
                    "XAX.CONCURRENCY.DATA_RACE",
                    left.storage,
                    "CONCURRENCY-CONFLICT-HAPPENS-BEFORE",
                    "ordered or wholly atomic conflicting accesses",
                    [left_index, right_index],
                )
    return tuple(sorted(happens_before))


def validate_atomic_litmus(events: Sequence[AtomicLitmusEvent]) -> AtomicLitmusResult:
    edges: set[tuple[int, int]] = set()
    previous: dict[int, int] = {}
    writes: dict[str, list[int]] = {}
    for index, event in enumerate(events):
        _atomic_order(event.family, event.order, event.failure_order)
        if event.family == AtomicFamily.CMPXCHG:
            if event.strength is None or event.succeeded is None:
                fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-CMPXCHG-OUTCOME", "explicit strength and outcome", [event.strength, event.succeeded])
            try:
                strength = CompareExchangeStrength(event.strength)
            except ValueError as error:
                fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-CMPXCHG-STRENGTH", [item.name.lower() for item in CompareExchangeStrength], str(error))
            if type(event.succeeded) is not bool:
                fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-CMPXCHG-OUTCOME", "boolean outcome", event.succeeded)
            if event.spurious_failure and (strength != CompareExchangeStrength.WEAK or event.succeeded):
                fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-SPURIOUS-FAILURE", "failed weak compare-exchange", [strength.name.lower(), event.succeeded])
        elif event.strength is not None or event.succeeded is not None or event.spurious_failure:
            fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-CMPXCHG-FIELDS", "compare-exchange only", event.family.name.lower())
        if event.agent in previous:
            edges.add((previous[event.agent], index))
        previous[event.agent] = index
        if event.family in (AtomicFamily.STORE, AtomicFamily.RMW) or (event.family == AtomicFamily.CMPXCHG and event.succeeded):
            writes.setdefault(event.location, []).append(index)
    for index, event in enumerate(events):
        if event.reads_from is not None:
            if event.family not in (AtomicFamily.LOAD, AtomicFamily.RMW, AtomicFamily.CMPXCHG):
                fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-READ-FAMILY", "load/rmw/cmpxchg", event.family.name.lower())
            if event.reads_from < 0 or event.reads_from >= index:
                fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-READS-FROM", f"event < {index}", event.reads_from)
            source = events[event.reads_from]
            if event.reads_from not in writes.get(event.location, ()):
                fail("XAX.ATOMIC.LITMUS", str(index), "ATOMIC-LITMUS-READS-FROM", "write to same location", event.reads_from)
            effective_read_order = (
                event.failure_order
                if event.family == AtomicFamily.CMPXCHG and event.succeeded is False
                else event.order
            )
            acquire_like = effective_read_order in (AtomicOrder.ACQUIRE, AtomicOrder.ACQ_REL, AtomicOrder.SEQ_CST)
            if acquire_like:
                modification_order = writes[event.location]
                source_position = modification_order.index(event.reads_from)
                release_head = event.reads_from
                release_orders = (AtomicOrder.RELEASE, AtomicOrder.ACQ_REL, AtomicOrder.SEQ_CST)
                while source_position and events[release_head].family in (AtomicFamily.RMW, AtomicFamily.CMPXCHG) and events[release_head].order not in release_orders:
                    source_position -= 1
                    release_head = modification_order[source_position]
                if events[release_head].order in release_orders:
                    edges.add((release_head, index))
    happens_before = _transitive_edges(len(events), edges)
    if any((index, index) in happens_before for index in range(len(events))):
        fail("XAX.ATOMIC.LITMUS", "litmus", "ATOMIC-HAPPENS-BEFORE-ACYCLIC", "acyclic", tuple(sorted(happens_before)))
    return AtomicLitmusResult(
        tuple(sorted(happens_before)),
        tuple((location, tuple(indices)) for location, indices in sorted(writes.items())),
        tuple(
            index
            for index, event in enumerate(events)
            if (
                event.failure_order
                if event.family == AtomicFamily.CMPXCHG and event.succeeded is False
                else event.order
            ) == AtomicOrder.SEQ_CST
        ),
    )


@dataclass(frozen=True)
class RealtimeProperties:
    may_block: bool | None
    allocation_bound: int | None
    stack_upper_bound: int | None
    recursion_bound: int | None
    control_bound: int | None
    retry_bound: int | None
    progress: str
    runtime_assists: tuple[str, ...]
    scheduler_interaction: tuple[str, ...]
    kernel_interaction: tuple[str, ...]
    dynamic_initialization: tuple[str, ...]
    interrupt_mask_bound: int | None
    target_timing_bound: int | None
    target_cost_estimate: int | None
    effect_domains: tuple[EffectDomain, ...]
    unsupported_operations: tuple[str, ...]


@dataclass(frozen=True)
class RealtimeProfile:
    forbid_blocking: bool = True
    forbid_unbounded_retry: bool = True
    forbid_dynamic_allocation: bool = True
    forbid_dynamic_initialization: bool = True
    forbid_runtime_assist: bool = True
    forbid_scheduler_interaction: bool = True
    forbid_kernel_interaction: bool = True
    require_bounded_stack: bool = True
    require_bounded_recursion: bool = True
    require_bounded_control: bool = True
    require_bounded_interrupt_mask: bool = False
    require_known_progress: bool = True
    require_target_timing_bound: bool = False
    accepted_effect_domains: tuple[EffectDomain, ...] = tuple(EffectDomain)


def _atomic_node_request(node: _ParsedNode, resolve: Callable[[bytes], SemanticObject]) -> tuple[int, int, int, AtomicFamily, AtomicOrder, AtomicScope, AtomicOrder | None]:
    operation = Operation(node.operation)
    family = {
        Operation.ATOMIC_LOAD: AtomicFamily.LOAD,
        Operation.ATOMIC_STORE: AtomicFamily.STORE,
        Operation.ATOMIC_RMW: AtomicFamily.RMW,
        Operation.ATOMIC_CMPXCHG: AtomicFamily.CMPXCHG,
        Operation.ATOMIC_FENCE: AtomicFamily.FENCE,
    }[operation]
    if operation == Operation.ATOMIC_FENCE:
        order, scope = node.attributes
        return 0, 0, 1, family, AtomicOrder(order), AtomicScope(scope), None
    element, _, _ = _decode_pointer_type(resolve(node.operand_types[0]), resolve)
    width = decode_bits_width(resolve(element))
    alignment = node.attributes[-2] if operation == Operation.ATOMIC_CMPXCHG else node.attributes[-1]
    if operation == Operation.ATOMIC_RMW:
        order, scope = node.attributes[1:3]
        failure = None
    elif operation == Operation.ATOMIC_CMPXCHG:
        order, failure, scope = node.attributes[:3]
    else:
        order, scope = node.attributes[:2]
        failure = None
    return 1, width, alignment, family, AtomicOrder(order), AtomicScope(scope), None if failure is None else AtomicOrder(failure)


def analyze_realtime(reader: StoreReader, function_cid: bytes, target: SemanticObject | None = None) -> RealtimeProperties:
    resolve = _verified_resolver(reader)
    target_description = decode_native_target(target) if target is not None else None
    active: set[bytes] = set()
    cache: dict[bytes, tuple[int | None, int | None, int | None, str, set[str], set[EffectDomain], set[str]]] = {}

    def analyze(cid: bytes) -> tuple[int | None, int | None, int | None, str, set[str], set[EffectDomain], set[str]]:
        if cid in active:
            return None, None, None, "unknown", set(), set(), {"recursive_call"}
        if cid in cache:
            stack, recursion, control, progress, assists, domains, unsupported = cache[cid]
            return stack, recursion, control, progress, set(assists), set(domains), set(unsupported)
        active.add(cid)
        function_object = resolve(cid)
        graph_object, parameters, returns = _decode_function_interface(function_object, resolve)
        graph = _parse_graph(graph_object, resolve)
        local_stack = sum(node.attributes[0] for block in graph.blocks for node in block.nodes if node.operation == Operation.STACK_ALLOC)
        stack: int | None = local_stack
        recursion: int | None = 0
        control: int | None = sum(len(block.nodes) + 1 for block in graph.blocks)
        progress = "wait_free"
        assists: set[str] = set()
        domains = {
            _decode_effect_type(resolve(type_cid)).domain
            for type_cid in (*parameters, *returns)
            if _is_effect(resolve(type_cid))
        }
        unsupported: set[str] = set()
        visiting: set[int] = set()
        visited: set[int] = set()

        def visit_block(index: int) -> bool:
            if index in visiting:
                return False
            if index in visited:
                return True
            visiting.add(index)
            for target_index, _ in graph.blocks[index].terminator.edges:
                if not visit_block(target_index):
                    return False
            visiting.remove(index)
            visited.add(index)
            return True

        if not visit_block(graph.entry):
            control = None
        max_callee_stack = 0
        for block in graph.blocks:
            for node in block.nodes:
                operation = Operation(node.operation)
                if operation == Operation.CALL_GROUP_MEMBER:
                    recursion = control = stack = None
                    progress = "unknown"
                    unsupported.add("recursive_group")
                elif operation == Operation.CALL_DIRECT:
                    child = analyze(node.entity.cid)
                    child_stack, child_recursion, child_control, child_progress, child_assists, child_domains, child_unsupported = child
                    if child_stack is None:
                        stack = None
                    elif stack is not None:
                        max_callee_stack = max(max_callee_stack, child_stack)
                    recursion = None if child_recursion is None else max(recursion or 0, child_recursion)
                    control = None if control is None or child_control is None else control + child_control
                    if child_progress == "unknown":
                        progress = "unknown"
                    elif child_progress == "lock_free" and progress == "wait_free":
                        progress = "lock_free"
                    assists |= child_assists
                    domains |= child_domains
                    unsupported |= child_unsupported
                elif operation in ATOMIC_OPERATIONS:
                    if target_description is None:
                        progress = "unknown"
                        unsupported.add("atomic_target_unknown")
                    else:
                        request = _atomic_node_request(node, resolve)
                        capability = atomic_capability(target_description, *request)
                        if capability.support == AtomicSupport.RUNTIME_ASSIST:
                            assists.add(operation.name.lower())
                        elif capability.support == AtomicSupport.UNSUPPORTED:
                            unsupported.add(operation.name.lower())
                        if capability.lock_free != LockFree.ALWAYS:
                            progress = "unknown"
                        elif operation in (Operation.ATOMIC_RMW, Operation.ATOMIC_CMPXCHG) and progress == "wait_free":
                            progress = "lock_free"
        if stack is not None:
            stack += max_callee_stack
        active.remove(cid)
        result = (stack, recursion, control, progress, assists, domains, unsupported)
        cache[cid] = (stack, recursion, control, progress, set(assists), set(domains), set(unsupported))
        return result

    stack, recursion, control, progress, assists, domains, unsupported = analyze(function_cid)
    retry = 0 if progress in ("wait_free", "lock_free") else None
    return RealtimeProperties(
        False,
        0,
        stack,
        recursion,
        control,
        retry,
        progress,
        tuple(sorted(assists)),
        (),
        (),
        (),
        None,
        None,
        None,
        tuple(sorted(domains)),
        tuple(sorted(unsupported)),
    )


def validate_realtime_profile(properties: RealtimeProperties, profile: RealtimeProfile = RealtimeProfile()) -> None:
    def reject(rule: str, expected: object, actual: object) -> None:
        fail("XAX.REALTIME.PROFILE", "realtime", rule, expected, actual)

    if profile.forbid_blocking and properties.may_block is not False:
        reject("REALTIME-NONBLOCKING", False, properties.may_block)
    if profile.forbid_dynamic_allocation and properties.allocation_bound is None:
        reject("REALTIME-ALLOCATION-BOUNDED", "known bound", None)
    if profile.forbid_dynamic_initialization and properties.dynamic_initialization:
        reject("REALTIME-NO-DYNAMIC-INITIALIZATION", (), properties.dynamic_initialization)
    if profile.forbid_runtime_assist and properties.runtime_assists:
        reject("REALTIME-NO-RUNTIME-ASSIST", (), properties.runtime_assists)
    if profile.forbid_scheduler_interaction and properties.scheduler_interaction:
        reject("REALTIME-NO-SCHEDULER", (), properties.scheduler_interaction)
    if profile.forbid_kernel_interaction and properties.kernel_interaction:
        reject("REALTIME-NO-KERNEL", (), properties.kernel_interaction)
    if profile.require_bounded_stack and properties.stack_upper_bound is None:
        reject("REALTIME-STACK-BOUNDED", "known bound", None)
    if profile.require_bounded_recursion and properties.recursion_bound is None:
        reject("REALTIME-RECURSION-BOUNDED", "known bound", None)
    if profile.require_bounded_control and properties.control_bound is None:
        reject("REALTIME-CONTROL-BOUNDED", "known bound", None)
    if profile.require_bounded_interrupt_mask and properties.interrupt_mask_bound is None:
        reject("REALTIME-INTERRUPT-MASK-BOUNDED", "known bound", None)
    if profile.forbid_unbounded_retry and properties.retry_bound is None:
        reject("REALTIME-RETRY-BOUNDED", "known bound", None)
    if profile.require_known_progress and properties.progress == "unknown":
        reject("REALTIME-PROGRESS-KNOWN", "known progress", "unknown")
    if profile.require_target_timing_bound and properties.target_timing_bound is None:
        reject("REALTIME-TARGET-TIMING-BOUND", "guaranteed bound", None)
    if properties.unsupported_operations:
        reject("REALTIME-TARGET-SUPPORTED", (), properties.unsupported_operations)
    rejected_domains = tuple(domain for domain in properties.effect_domains if domain not in profile.accepted_effect_domains)
    if rejected_domains:
        reject("REALTIME-EFFECT-DOMAINS", [domain.name.lower() for domain in profile.accepted_effect_domains], [domain.name.lower() for domain in rejected_domains])


def validate_handler_entry(
    reader: StoreReader,
    function_cid: bytes,
    target: SemanticObject,
    event_kind: int,
    profile: RealtimeProfile = RealtimeProfile(),
) -> HandlerEntryContract:
    description = decode_native_target(target)
    contract = next((entry for entry in description.handler_entries if entry.event_kind == event_kind), None)
    if contract is None:
        fail("XAX.HANDLER.ENTRY", target.cid.hex(), "HANDLER-EVENT-TARGET-SUPPORTED", [entry.event_kind for entry in description.handler_entries], event_kind)
    resolve = _verified_resolver(reader)
    function_object = resolve(function_cid)
    _, parameters, returns = _decode_function_interface(function_object, resolve)
    if any(not _is_proof_type(resolve(type_cid)) for type_cid in (*parameters, *returns)):
        fail("XAX.HANDLER.ABI", function_cid.hex(), "HANDLER-PROOF-ONLY-INTERFACE", "resource/effect-only interface", [cid.hex() for cid in (*parameters, *returns)])
    summary = derive_effect_summary(reader, function_cid)
    allowed = set(contract.allowed_effect_domains)
    used = {domain for domain, _ in summary.domains}
    if not used <= allowed:
        fail("XAX.HANDLER.EFFECT", function_cid.hex(), "HANDLER-ALLOWED-EFFECTS", [domain.name.lower() for domain in sorted(allowed)], [domain.name.lower() for domain in sorted(used - allowed)])
    properties = analyze_realtime(reader, function_cid, target)
    validate_realtime_profile(properties, profile)
    if properties.stack_upper_bound is None or properties.stack_upper_bound > contract.stack_bound:
        fail("XAX.HANDLER.STACK", function_cid.hex(), "HANDLER-STACK-BOUND", contract.stack_bound, properties.stack_upper_bound)
    return contract


def _is_erased_proof_function(
    function_object: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
) -> bool:
    graph_object, parameters, returns = _decode_function_interface(function_object, resolve)
    if any(not _is_proof_type(resolve(type_cid)) for type_cid in (*parameters, *returns)):
        return False
    graph = _parse_graph(graph_object, resolve)
    return (
        len(graph.blocks) == 1
        and graph.blocks[0].terminator.kind == TerminatorKind.RETURN
        and all(node.operation in RESOURCE_EFFECT_OPERATIONS for node in graph.blocks[0].nodes)
    )

def _read_edge(cursor: Cursor) -> tuple[int, tuple[ValueRef, ...]]:
    target = cursor.uleb()
    return target, tuple(_read_value(cursor) for _ in range(cursor.uleb()))


_PARSED_GRAPHS: dict[bytes, tuple[_ParsedGraph, tuple[bytes, ...]]] = {}
_PARSED_GRAPHS_LIMIT = 4096


def _parse_graph(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> _ParsedGraph:
    """Parse/verify a graph once per CID.

    The parse is a pure function of the graph CID and the objects it resolves,
    which are themselves content-addressed.  A cache hit replays every resolve;
    if any fails, the uncached parse runs so the exact diagnostic is raised.
    Callers must not mutate the result.
    """
    cached = _PARSED_GRAPHS.get(obj.cid)
    if cached is not None:
        graph, dependencies = cached
        try:
            for cid in dependencies:
                resolve(cid)
        except Exception:
            return _parse_graph_uncached(obj, resolve)
        return graph
    seen: dict[bytes, None] = {}

    def recording_resolve(cid: bytes) -> SemanticObject:
        result = resolve(cid)
        seen[cid] = None
        return result

    graph = _parse_graph_uncached(obj, recording_resolve)
    if len(_PARSED_GRAPHS) >= _PARSED_GRAPHS_LIMIT:
        _PARSED_GRAPHS.clear()  # ponytail: wholesale reset bounds memory; LRU if long sessions thrash it
    _PARSED_GRAPHS[obj.cid] = (graph, tuple(seen))
    return graph


def _parse_graph_uncached(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> _ParsedGraph:
    cursor = Cursor(obj.body, obj.cid.hex())
    block_count = cursor.uleb()
    entry = cursor.uleb()
    if not block_count or entry >= block_count:
        fail("XAX.STRUCT.ENTRY_BLOCK", obj.cid.hex(), "GRAPH-ENTRY", f"block < {block_count}", entry)
    blocks: list[_ParsedBlock] = []
    used_references: set[bytes] = set()
    member_spans: list[tuple[int, int]] = []
    for _ in range(block_count):
        parameters = []
        for _ in range(cursor.uleb()):
            type_object = _reference(obj, cursor, resolve)
            _verify_type(type_object, resolve)
            parameters.append(type_object.cid)
            used_references.add(type_object.cid)
        nodes = []
        for _ in range(cursor.uleb()):
            operation = cursor.uleb()
            member = None
            if operation == Operation.CALL_GROUP_MEMBER:
                start = cursor.pos
                member = cursor.uleb()
                member_spans.append((start, cursor.pos))
            entity = _reference(obj, cursor, resolve) if operation in ENTITY_OPERATIONS else None
            if entity is not None:
                used_references.add(entity.cid)
            operands = tuple(_read_value(cursor) for _ in range(cursor.uleb()))
            results = []
            for _ in range(cursor.uleb()):
                type_object = _reference(obj, cursor, resolve)
                _verify_type(type_object, resolve)
                results.append(type_object.cid)
                used_references.add(type_object.cid)
            attributes = tuple(cursor.uleb() for _ in range(cursor.uleb())) if operation in ATTRIBUTE_OPERATIONS else ()
            nodes.append(_ParsedNode(operation, member, entity, operands, tuple(results), attributes))
        kind_value = cursor.uleb()
        try:
            kind = TerminatorKind(kind_value)
        except ValueError:
            fail("XAX.STRUCT.TERMINATOR", obj.cid.hex(), "GRAPH-TERMINATOR-KIND", list(TerminatorKind), kind_value)
        if kind == TerminatorKind.BRANCH:
            term = Terminator(kind, edges=(_read_edge(cursor),))
        elif kind == TerminatorKind.CONDITIONAL_BRANCH:
            term = Terminator(kind, values=(_read_value(cursor),), edges=(_read_edge(cursor), _read_edge(cursor)))
        elif kind == TerminatorKind.RETURN:
            term = Terminator(kind, values=tuple(_read_value(cursor) for _ in range(cursor.uleb())))
        else:
            trap_bytes = cursor.byte_string()
            try:
                decode_trap_payload(trap_bytes)
            except ValueError as error:
                fail("XAX.CONTROL.TRAP_PAYLOAD", obj.cid.hex(), "TRAP-PAYLOAD-CANONICAL", "empty or canonical u16 ULEB reason with optional target bytes", str(error))
            term = Terminator(kind, payload=trap_bytes)
        blocks.append(_ParsedBlock(tuple(parameters), tuple(nodes), term))
    cursor.end("GRAPH-BODY")
    if used_references != set(obj.references):
        fail(
            "XAX.CANON.UNUSED_REFERENCE",
            obj.cid.hex(),
            "SER-REFS-DIRECT-ONLY",
            sorted(cid.hex() for cid in obj.references),
            sorted(cid.hex() for cid in used_references),
        )

    predecessors = [set() for _ in blocks]
    for block_index, block in enumerate(blocks):
        for target, _ in block.terminator.edges:
            if target >= len(blocks):
                fail("XAX.STRUCT.BRANCH_TARGET", obj.cid.hex(), "GRAPH-BRANCH-TARGET", f"< {len(blocks)}", target)
            predecessors[target].add(block_index)
    dominators = [set(range(len(blocks))) for _ in blocks]
    dominators[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for index in range(len(blocks)):
            if index == entry:
                continue
            new = {index}
            if predecessors[index]:
                new |= set.intersection(*(dominators[p] for p in predecessors[index]))
            if new != dominators[index]:
                dominators[index] = new
                changed = True

    def value_type(value: ValueRef, use_block: int, use_node: int) -> bytes:
        if value.block >= len(blocks):
            fail("XAX.STRUCT.VALUE_BLOCK", obj.cid.hex(), "GRAPH-VALUE-DEFINED", f"< {len(blocks)}", value.block)
        source = blocks[value.block]
        if value.tag == 0:
            if value.index >= len(source.parameters):
                fail("XAX.STRUCT.VALUE_INDEX", obj.cid.hex(), "GRAPH-VALUE-DEFINED", f"< {len(source.parameters)}", value.index)
            type_cid = source.parameters[value.index]
        else:
            if value.index >= len(source.nodes) or value.result >= len(source.nodes[value.index].results):
                fail("XAX.STRUCT.VALUE_INDEX", obj.cid.hex(), "GRAPH-VALUE-DEFINED", "existing node result", [value.index, value.result])
            type_cid = source.nodes[value.index].results[value.result]
            if value.block == use_block and value.index >= use_node:
                fail("XAX.STRUCT.SSA_DOMINANCE", obj.cid.hex(), "GRAPH-SSA-DOMINANCE", f"node < {use_node}", value.index)
        if value.block != use_block and value.block not in dominators[use_block]:
            fail("XAX.STRUCT.SSA_DOMINANCE", obj.cid.hex(), "GRAPH-SSA-DOMINANCE", sorted(dominators[use_block]), value.block)
        return type_cid

    # Memory facts flow only along explicit block parameters.  Blocks are
    # verified in reverse postorder; a back edge first contributes nothing
    # (optimistic), then passes repeat until the block-entry facts reach a
    # fixpoint.  Facts only shrink between passes, so a failure in any pass is
    # a real failure and the final pass is exact.  Graphs without back edges
    # converge in one pass.
    order: list[int] = []
    visited = {entry}
    walk: list[tuple[int, int]] = [(entry, 0)]
    while walk:
        current, edge_cursor = walk[-1]
        out_edges = blocks[current].terminator.edges
        if edge_cursor < len(out_edges):
            walk[-1] = (current, edge_cursor + 1)
            successor = out_edges[edge_cursor][0]
            if successor not in visited:
                visited.add(successor)
                walk.append((successor, 0))
        else:
            order.append(current)
            walk.pop()
    order.reverse()
    order.extend(index for index in range(len(blocks)) if index not in visited)
    incoming_edges: dict[int, list[tuple[int, int]]] = {index: [] for index in range(len(blocks))}
    for source_index, source in enumerate(blocks):
        for edge_index, (target, _arguments) in enumerate(source.terminator.edges):
            incoming_edges[target].append((source_index, edge_index))
    entry_facts = _entry_heap_view_facts(blocks[entry].parameters, resolve)
    exits: dict[int, dict[tuple[int, int], _BlockFacts]] = {}
    previous_seeds: dict[int, _BlockFacts] | None = None
    for _fact_pass in range(2 * len(blocks) + 2):
        returns_by_block: list[tuple[int, tuple[bytes, ...]]] = []
        global_pointers: dict[ValueRef, _PointerFact] = {}
        heap_allocations: dict[ValueRef, _HeapAllocationFact] = {}
        pass_seeds: dict[int, _BlockFacts] = {}
        pass_exits: dict[int, dict[tuple[int, int], _BlockFacts]] = {}
        stale = False
        for block_index in order:
            block = blocks[block_index]
            arriving: list[_BlockFacts] = [entry_facts] if block_index == entry else []
            for edge in incoming_edges[block_index]:
                if edge in pass_exits.get(block_index, {}):
                    arriving.append(pass_exits[block_index][edge])
                else:
                    stale = True
                    if edge in exits.get(block_index, {}):
                        arriving.append(exits[block_index][edge])
            seeds = _merge_block_facts(arriving, len(block.parameters))
            pass_seeds[block_index] = seeds
            pointers: dict[ValueRef, _PointerFact] = dict(global_pointers)
            owners: dict[ValueRef, _OwnerFact] = {}
            effects: dict[ValueRef, _EffectFact] = {}
            for parameter_index in range(len(block.parameters)):
                parameter_ref = ValueRef.parameter(block_index, parameter_index)
                pointers.pop(parameter_ref, None)
                if parameter_index in seeds.pointers:
                    pointers[parameter_ref] = seeds.pointers[parameter_index]
                if parameter_index in seeds.owners:
                    owners[parameter_ref] = seeds.owners[parameter_index]
                if parameter_index in seeds.effects:
                    effects[parameter_ref] = seeds.effects[parameter_index]
            effect_consumers: dict[ValueRef, Operation] = {}
            owner_consumers: set[ValueRef] = set()
            allocations: set[tuple[int, int]] = set(seeds.live)
            ended: set[tuple[int, int]] = set(seeds.ended)
            resource_candidates: tuple[_ResourceCallContract, ...] = ()
            if block_index == entry and any(_is_stack_owner(resolve(type_cid)) for type_cid in block.parameters):
                resource_candidates = _resource_call_candidates(block.parameters, resolve)
                if not resource_candidates:
                    fail(
                        "XAX.MEMORY.ENTRY_CONTRACT",
                        obj.cid.hex(),
                        "MEMORY-ENTRY-CONTRACT",
                        [
                            ["resource<stack-storage,live>", "effect<memory>"],
                            ["ptr<stack,T,P,A>", "T", "resource<stack-storage,live>", "effect<memory>"],
                            ["ptr<stack,T,P,A>", "resource<stack-storage,live>", "effect<memory>"],
                        ],
                        [type_cid.hex() for type_cid in block.parameters],
                    )
                if len(blocks) != 1:
                    fail("XAX.MEMORY.ENTRY_CONTRACT", obj.cid.hex(), "MEMORY-ENTRY-CONTRACT", "one block", len(blocks))
                body_operations = tuple(Operation(node.operation) for node in block.nodes)
                entry_contract = _resource_entry_contract(resource_candidates, body_operations)
                seed = entry_contract or resource_candidates[0]
                seed_shape = (seed.pointer_operand, seed.owner_operand, seed.effect_operand)
                if any(
                    (candidate.pointer_operand, candidate.owner_operand, candidate.effect_operand) != seed_shape
                    for candidate in resource_candidates[1:]
                ):
                    raise AssertionError("resource-call candidates disagree on entry proof shape")
                storage = (-1, 0)
                if seed.pointer_operand is None:
                    owners[ValueRef.parameter(block_index, seed.owner_operand)] = _OwnerFact(storage)
                    effects[ValueRef.parameter(block_index, seed.effect_operand)] = _EffectFact(storage, ())
                else:
                    pointer_element, permission, pointer_alignment = _decode_pointer_type(
                        resolve(block.parameters[seed.pointer_operand]), resolve
                    )
                    pointer_extent = (decode_bits_width(resolve(pointer_element)) + 7) // 8
                    pointers[ValueRef.parameter(block_index, seed.pointer_operand)] = _PointerFact(
                        storage, pointer_element, permission, 0, pointer_extent, pointer_alignment, storage
                    )
                    owners[ValueRef.parameter(block_index, seed.owner_operand)] = _OwnerFact(storage)
                    effects[ValueRef.parameter(block_index, seed.effect_operand)] = _EffectFact(
                        storage, ((0, pointer_extent),) if seed.requires_initialized else ()
                    )
            for node_index, node in enumerate(block.nodes):
                if node.operation not in Operation._value2member_map_:
                    fail("XAX.STRUCT.OPERATION", obj.cid.hex(), "GRAPH-OP-SUPPORTED", list(Operation), node.operation)
                operand_types = tuple(value_type(value, block_index, node_index) for value in node.operands)
                node.operand_types = operand_types
                if node.operation in BINARY_INTEGER_OPERATIONS:
                    if len(node.operands) != 2 or len(node.results) != 1 or node.attributes:
                        fail("XAX.STRUCT.OP_ARITY", obj.cid.hex(), "GRAPH-OP-ARITY", "2 inputs, 1 result, 0 attributes", [len(node.operands), len(node.results), len(node.attributes)])
                    decode_bits_width(resolve(node.results[0]))
                    if operand_types != (node.results[0], node.results[0]):
                        fail("XAX.STRUCT.OP_TYPE", obj.cid.hex(), "GRAPH-OP-TYPE", [node.results[0].hex()] * 2, [cid.hex() for cid in operand_types])
                elif node.operation in INTEGER_WIDTH_OPERATIONS:
                    if len(node.operands) != 1 or len(node.results) != 1 or node.attributes:
                        fail("XAX.INT.WIDTH", obj.cid.hex(), "INT-WIDTH-CONTRACT", [1, 1, 0], [len(node.operands), len(node.results), len(node.attributes)])
                    source_width = decode_bits_width(resolve(operand_types[0]))
                    result_width = decode_bits_width(resolve(node.results[0]))
                    # Strict narrowing/widening only: an identity width change is not a canonical node.
                    narrows = node.operation == Operation.INT_TRUNCATE
                    if (result_width >= source_width) if narrows else (result_width <= source_width):
                        fail("XAX.INT.WIDTH", obj.cid.hex(), "INT-TRUNCATE-NARROWS" if narrows else "INT-ZERO-EXTEND-WIDENS", f"result {'<' if narrows else '>'} {source_width}", result_width)
                elif node.operation == Operation.ROTATE_RIGHT:
                    if len(node.operands) != 1 or len(node.results) != 1 or len(node.attributes) != 1:
                        fail("XAX.INT.ROTATE", obj.cid.hex(), "INT-ROTATE-CONTRACT", [1, 1, 1], [len(node.operands), len(node.results), len(node.attributes)])
                    width = decode_bits_width(resolve(node.results[0]))
                    if operand_types != (node.results[0],):
                        fail("XAX.INT.ROTATE", obj.cid.hex(), "INT-ROTATE-TYPE", node.results[0].hex(), [cid.hex() for cid in operand_types])
                    if not 0 <= node.attributes[0] < width:
                        fail("XAX.INT.ROTATE", obj.cid.hex(), "INT-ROTATE-AMOUNT", f"0..{width - 1}", node.attributes[0])
                elif node.operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV):
                    if len(node.operands) != 2 or len(node.results) != 1 or node.attributes:
                        fail("XAX.FLOAT.CONTRACT", obj.cid.hex(), "FLOAT-BINARY-CONTRACT", [2, 1, 0], [len(node.operands), len(node.results), len(node.attributes)])
                    decode_float_format(resolve(node.results[0]))
                    if operand_types != (node.results[0], node.results[0]):
                        fail("XAX.FLOAT.TYPE", obj.cid.hex(), "FLOAT-BINARY-TYPE", [node.results[0].hex()] * 2, [cid.hex() for cid in operand_types])
                elif node.operation == Operation.FLOAT_COMPARE:
                    if len(node.operands) != 2 or len(node.results) != 1 or len(node.attributes) != 1:
                        fail("XAX.FLOAT.CONTRACT", obj.cid.hex(), "FLOAT-COMPARE-CONTRACT", [2, 1, 1], [len(node.operands), len(node.results), len(node.attributes)])
                    if operand_types[0] != operand_types[1]:
                        fail("XAX.FLOAT.TYPE", obj.cid.hex(), "FLOAT-COMPARE-OPERANDS", "matching float types", [cid.hex() for cid in operand_types])
                    decode_float_format(resolve(operand_types[0]))
                    if decode_bits_width(resolve(node.results[0])) != 1:
                        fail("XAX.FLOAT.TYPE", obj.cid.hex(), "FLOAT-COMPARE-RESULT", "bits<1>", node.results[0].hex())
                    try:
                        FloatCompare(node.attributes[0])
                    except ValueError:
                        fail("XAX.FLOAT.COMPARE", obj.cid.hex(), "FLOAT-COMPARE-KIND", [item.value for item in FloatCompare], node.attributes[0])
                elif node.operation in (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT):
                    name = "UINT" if node.operation == Operation.UINT_TO_FLOAT else "SINT"
                    if len(node.operands) != 1 or len(node.results) != 1 or node.attributes:
                        fail("XAX.FLOAT.CONTRACT", obj.cid.hex(), f"{name}-TO-FLOAT-CONTRACT", [1, 1, 0], [len(node.operands), len(node.results), len(node.attributes)])
                    if decode_bits_width(resolve(operand_types[0])) > 64:
                        fail("XAX.FLOAT.CONVERT", obj.cid.hex(), f"{name}-TO-FLOAT-WIDTH", "bits<=64", operand_types[0].hex())
                    decode_float_format(resolve(node.results[0]))
                elif node.operation in (Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC):
                    name = "UINT" if node.operation == Operation.FLOAT_TO_UINT_TRUNC else "SINT"
                    if len(node.operands) != 1 or len(node.results) != 1 or node.attributes:
                        fail("XAX.FLOAT.CONTRACT", obj.cid.hex(), f"FLOAT-TO-{name}-CONTRACT", [1, 1, 0], [len(node.operands), len(node.results), len(node.attributes)])
                    decode_float_format(resolve(operand_types[0]))
                    if decode_bits_width(resolve(node.results[0])) > 64:
                        fail("XAX.FLOAT.CONVERT", obj.cid.hex(), f"FLOAT-TO-{name}-WIDTH", "bits<=64", node.results[0].hex())
                elif node.operation == Operation.FLOAT_CONVERT:
                    if len(node.operands) != 1 or len(node.results) != 1 or node.attributes:
                        fail("XAX.FLOAT.CONTRACT", obj.cid.hex(), "FLOAT-CONVERT-CONTRACT", [1, 1, 0], [len(node.operands), len(node.results), len(node.attributes)])
                    decode_float_format(resolve(operand_types[0]))
                    decode_float_format(resolve(node.results[0]))
                elif node.operation == Operation.INT_COMPARE:
                    if len(node.operands) != 2 or len(node.results) != 1 or len(node.attributes) != 1:
                        fail("XAX.INT.COMPARE", obj.cid.hex(), "INT-COMPARE-CONTRACT", [2, 1, 1], [len(node.operands), len(node.results), len(node.attributes)])
                    width = decode_bits_width(resolve(operand_types[0]))
                    if operand_types[1] != operand_types[0] or decode_bits_width(resolve(node.results[0])) != 1:
                        fail("XAX.INT.COMPARE", obj.cid.hex(), "INT-COMPARE-TYPE", [operand_types[0].hex(), "bits<1>"], [[cid.hex() for cid in operand_types], node.results[0].hex()])
                    try:
                        IntCompare(node.attributes[0])
                    except ValueError:
                        fail("XAX.INT.COMPARE", obj.cid.hex(), "INT-COMPARE-KIND", [item.value for item in IntCompare], node.attributes[0])
                elif node.operation == Operation.AGGREGATE_MAKE:
                    if node.attributes or len(node.results) != 1:
                        fail("XAX.AGGREGATE.CONTRACT", obj.cid.hex(), "AGGREGATE-MAKE-CONTRACT", "operands -> one aggregate result", [len(node.operands), len(node.results), len(node.attributes)])
                    result_type = resolve(node.results[0])
                    form = Cursor(result_type.body, result_type.cid.hex()).uleb()
                    if form == 8:
                        expected = _decode_tuple_type(result_type, resolve)
                    elif form == 9:
                        element, count = _decode_array_type(result_type, resolve)
                        expected = (element,) * count
                    else:
                        fail("XAX.AGGREGATE.TYPE", obj.cid.hex(), "AGGREGATE-MAKE-TYPE", ["tuple", "array"], form)
                    if operand_types != expected:
                        fail("XAX.AGGREGATE.TYPE", obj.cid.hex(), "AGGREGATE-MAKE-ELEMENTS", [cid.hex() for cid in expected], [cid.hex() for cid in operand_types])
                elif node.operation == Operation.AGGREGATE_GET:
                    if len(node.operands) != 1 or len(node.results) != 1 or len(node.attributes) != 1:
                        fail("XAX.AGGREGATE.CONTRACT", obj.cid.hex(), "AGGREGATE-GET-CONTRACT", [1, 1, 1], [len(node.operands), len(node.results), len(node.attributes)])
                    aggregate = resolve(operand_types[0])
                    form = Cursor(aggregate.body, aggregate.cid.hex()).uleb()
                    if form == 8:
                        elements = _decode_tuple_type(aggregate, resolve)
                    elif form == 9:
                        element, count = _decode_array_type(aggregate, resolve)
                        elements = (element,) * count
                    else:
                        fail("XAX.AGGREGATE.TYPE", obj.cid.hex(), "AGGREGATE-GET-TYPE", ["tuple", "array"], form)
                    index = node.attributes[0]
                    if index >= len(elements) or node.results[0] != elements[index]:
                        fail("XAX.AGGREGATE.INDEX", obj.cid.hex(), "AGGREGATE-GET-INDEX", [len(elements), [cid.hex() for cid in elements]], [index, node.results[0].hex()])
                elif node.operation == Operation.SUM_MAKE:
                    if len(node.operands) != 1 or len(node.results) != 1 or len(node.attributes) != 1:
                        fail("XAX.SUM.CONTRACT", obj.cid.hex(), "SUM-MAKE-CONTRACT", [1, 1, 1], [len(node.operands), len(node.results), len(node.attributes)])
                    variants = _decode_sum_type(resolve(node.results[0]), resolve)
                    variant = node.attributes[0]
                    if variant >= len(variants) or operand_types[0] != variants[variant]:
                        fail("XAX.SUM.VARIANT", obj.cid.hex(), "SUM-MAKE-VARIANT", [len(variants), [cid.hex() for cid in variants]], [variant, operand_types[0].hex()])
                elif node.operation == Operation.SUM_TAG:
                    if len(node.operands) != 1 or len(node.results) != 1 or node.attributes:
                        fail("XAX.SUM.CONTRACT", obj.cid.hex(), "SUM-TAG-CONTRACT", [1, 1, 0], [len(node.operands), len(node.results), len(node.attributes)])
                    variants = _decode_sum_type(resolve(operand_types[0]), resolve)
                    width = decode_bits_width(resolve(node.results[0]))
                    if (1 << width) < len(variants):
                        fail("XAX.SUM.TAG", obj.cid.hex(), "SUM-TAG-WIDTH", f">= {max(1, (len(variants)-1).bit_length())} bits", width)
                elif node.operation == Operation.SUM_GET:
                    if len(node.operands) != 1 or len(node.results) != 1 or len(node.attributes) != 1:
                        fail("XAX.SUM.CONTRACT", obj.cid.hex(), "SUM-GET-CONTRACT", [1, 1, 1], [len(node.operands), len(node.results), len(node.attributes)])
                    variants = _decode_sum_type(resolve(operand_types[0]), resolve)
                    variant = node.attributes[0]
                    if variant >= len(variants) or node.results[0] != variants[variant]:
                        fail("XAX.SUM.VARIANT", obj.cid.hex(), "SUM-GET-VARIANT", [len(variants), [cid.hex() for cid in variants]], [variant, node.results[0].hex()])
                elif node.operation == Operation.CALL_DIRECT:
                    if node.entity is None or node.entity.kind != Kind.FUNCTION:
                        fail("XAX.STRUCT.CALL_TARGET", obj.cid.hex(), "GRAPH-CALL-TARGET", Kind.FUNCTION.name, None if node.entity is None else node.entity.kind.name)
                    _, callee_parameters, callee_returns = _decode_function_interface(node.entity, resolve)
                    if operand_types != callee_parameters or node.results != callee_returns:
                        fail(
                            "XAX.STRUCT.CALL_CONTRACT",
                            obj.cid.hex(),
                            "GRAPH-CALL-CONTRACT",
                            [[cid.hex() for cid in callee_parameters], [cid.hex() for cid in callee_returns]],
                            [[cid.hex() for cid in operand_types], [cid.hex() for cid in node.results]],
                        )
                    resource_contract = _resource_call_contract(node.entity, callee_parameters, callee_returns, resolve)
                    # Memory effects inside heap-view triples are governed by the
                    # whole-view borrowing contract, not the stack call contracts.
                    view_effects = {
                        (group, index + 1)
                        for group, types in ((0, callee_parameters), (1, callee_returns))
                        for index, _extent, _initialized in _heap_view_triples(types, resolve)
                    }
                    has_resource_interface = any(
                        _is_stack_owner(resolve(type_cid)) or (_is_memory_effect(resolve(type_cid)) and (group, index) not in view_effects)
                        for group, types in ((0, callee_parameters), (1, callee_returns))
                        for index, type_cid in enumerate(types)
                    )
                    # With no pointer or stack owner in the interface the callee
                    # cannot reach caller storage: memory effects are a pure
                    # ordering frontier.  The input is consumed linearly and the
                    # returned frontier carries no storage facts (conservative).
                    frontier_only = has_resource_interface and not any(
                        _is_stack_owner(resolve(type_cid)) or _is_stack_pointer(resolve(type_cid))
                        for type_cid in (*callee_parameters, *callee_returns)
                    )
                    if frontier_only:
                        for ref, type_cid in zip(node.operands, operand_types):
                            if _is_memory_effect(resolve(type_cid)) and ref in effects:
                                if ref in effect_consumers:
                                    fail("XAX.MEMORY.EFFECT_FORK", obj.cid.hex(), "MEMORY-EFFECT-LINEAR", "one consumer", Operation.CALL_DIRECT.name)
                                effect_consumers[ref] = Operation.CALL_DIRECT
                    elif has_resource_interface:
                        if resource_contract is None:
                            fail(
                                "XAX.MEMORY.CALL_CONTRACT",
                                obj.cid.hex(),
                                "MEMORY-CALL-PASS-THROUGH",
                                [
                                    [["resource<stack-storage,live>", "effect<memory>"], ["resource<stack-storage,live>", "effect<memory>"]],
                                    [["ptr<stack,T,P,A>", "T", "resource<stack-storage,live>", "effect<memory>"], ["resource<stack-storage,live>", "effect<memory>"]],
                                    [["ptr<stack,T,P,A>", "resource<stack-storage,live>", "effect<memory>"], ["T", "resource<stack-storage,live>", "effect<memory>"]],
                                    [["ptr<stack,T,P,A>", "T", "resource<stack-storage,live>", "effect<memory>"], ["T", "resource<stack-storage,live>", "effect<memory>"]],
                                ],
                                [[cid.hex() for cid in callee_parameters], [cid.hex() for cid in callee_returns]],
                            )
                        pointer_fact = None
                        required_size = None
                        if resource_contract.pointer_operand is not None:
                            pointer_ref = node.operands[resource_contract.pointer_operand]
                            pointer_fact = pointers.get(pointer_ref)
                            if pointer_fact is None:
                                fail("XAX.MEMORY.PROVENANCE", obj.cid.hex(), "MEMORY-PROVENANCE-PROVEN", "live local stack pointer", [pointer_ref.block, pointer_ref.index, pointer_ref.result])
                            if pointer_fact.storage in ended:
                                fail("XAX.MEMORY.USE_AFTER_LIFETIME", obj.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage", pointer_fact.storage)
                            if pointer_fact.window:
                                fail("XAX.MEMORY.REBASE", obj.cid.hex(), "MEMORY-REBASE-STATIC-ONLY", "statically positioned pointer", pointer_fact.window)
                            required_size = (decode_bits_width(resolve(pointer_fact.element)) + 7) // 8
                            if pointer_fact.extent < required_size:
                                fail("XAX.MEMORY.BOUNDS", obj.cid.hex(), "MEMORY-CALL-POINTER-BOUNDS", f"at least {required_size} bytes", pointer_fact.extent)
                            required_permission = resource_contract.required_permission
                            if required_permission is not None and pointer_fact.permission & required_permission != required_permission:
                                fail(
                                    "XAX.MEMORY.PERMISSION",
                                    obj.cid.hex(),
                                    "MEMORY-CALL-PERMISSION",
                                    int(required_permission),
                                    int(pointer_fact.permission),
                                )
                        owner_ref = node.operands[resource_contract.owner_operand]
                        effect_ref = node.operands[resource_contract.effect_operand]
                        try:
                            owner = owners[owner_ref]
                        except KeyError:
                            fail("XAX.MEMORY.OWNER", obj.cid.hex(), "MEMORY-OWNER-PROVEN", "live stack owner", [owner_ref.block, owner_ref.index, owner_ref.result])
                        if owner_ref in owner_consumers or owner.storage in ended:
                            fail("XAX.MEMORY.USE_AFTER_LIFETIME", obj.cid.hex(), "MEMORY-LIFETIME-LIVE", "live storage owner", owner.storage)
                        if pointer_fact is not None and pointer_fact.storage != owner.storage:
                            fail("XAX.MEMORY.PROVENANCE", obj.cid.hex(), "MEMORY-CALL-POINTER-PROVENANCE", owner.storage, pointer_fact.storage)
                        effect = effects.get(effect_ref)
                        if effect is None or effect.storage != owner.storage:
                            fail("XAX.MEMORY.PROVENANCE", obj.cid.hex(), "MEMORY-EFFECT-PROVENANCE", owner.storage, None if effect is None else effect.storage)
                        if resource_contract.requires_initialized:
                            start = pointer_fact.offset
                            if not _range_initialized(effect.initialized, start, start + required_size):
                                fail(
                                    "XAX.MEMORY.UNINITIALIZED",
                                    obj.cid.hex(),
                                    "MEMORY-CALL-INITIALIZED",
                                    [start, start + required_size],
                                    effect.initialized,
                                )
                        if effect_ref in effect_consumers:
                            fail("XAX.MEMORY.EFFECT_FORK", obj.cid.hex(), "MEMORY-EFFECT-LINEAR", "one consumer", Operation.CALL_DIRECT.name)
                        owner_consumers.add(owner_ref)
                        effect_consumers[effect_ref] = Operation.CALL_DIRECT
                        owners[ValueRef.node_result(block_index, node_index, resource_contract.owner_result)] = owner
                        if resource_contract.initializes:
                            start = pointer_fact.offset
                            successor_effect = _EffectFact(
                                effect.storage,
                                _merge_interval(effect.initialized, start, start + required_size),
                            )
                        else:
                            successor_effect = effect
                        effects[ValueRef.node_result(block_index, node_index, resource_contract.effect_result)] = successor_effect
                    _verify_heap_view_call(
                        obj, block_index, node_index, node, callee_parameters, callee_returns, resolve,
                        pointers, owners, effects, effect_consumers, owner_consumers, ended,
                    )
                elif node.operation == Operation.FUNCTION_ADDRESS:
                    if node.entity is None or node.entity.kind != Kind.FUNCTION:
                        fail("XAX.STRUCT.FUNCTION_ADDRESS", obj.cid.hex(), "GRAPH-FUNCTION-ADDRESS-TARGET", Kind.FUNCTION.name, None if node.entity is None else node.entity.kind.name)
                    if node.operands or len(node.results) != 1:
                        fail("XAX.STRUCT.FUNCTION_ADDRESS", obj.cid.hex(), "GRAPH-FUNCTION-ADDRESS-ARITY", [0, 1], [len(node.operands), len(node.results)])
                    result_type = resolve(node.results[0])
                    try:
                        element, _permission, _alignment = _decode_pointer_type(result_type, resolve)
                    except XaxError:
                        fail("XAX.STRUCT.FUNCTION_ADDRESS", obj.cid.hex(), "GRAPH-FUNCTION-ADDRESS-TYPE", "ptr<opaque<function>>", node.results[0].hex())
                    if not _is_opaque(resolve(element), OpaqueKind.FUNCTION):
                        fail("XAX.STRUCT.FUNCTION_ADDRESS", obj.cid.hex(), "GRAPH-FUNCTION-ADDRESS-TYPE", "ptr<opaque<function>>", node.results[0].hex())
                elif node.operation == Operation.CALL_FOREIGN:
                    if node.entity is None:
                        fail("XAX.FOREIGN.CALL", obj.cid.hex(), "FOREIGN-CALL-TARGET", "foreign function carrier", None)
                    declaration = decode_foreign_function(node.entity)
                    if declaration.abi not in FOREIGN_ABIS:
                        fail("XAX.FOREIGN.ABI", obj.cid.hex(), "FOREIGN-CALL-ABI", [abi.decode() for abi in FOREIGN_ABIS], declaration.abi.decode("ascii", "replace"))
                    if operand_types != declaration.inputs or node.results != declaration.outputs:
                        fail("XAX.FOREIGN.CALL", obj.cid.hex(), "FOREIGN-CALL-CONTRACT", [[cid.hex() for cid in declaration.inputs], [cid.hex() for cid in declaration.outputs]], [[cid.hex() for cid in operand_types], [cid.hex() for cid in node.results]])
                    _verify_foreign_heap_call(
                        obj, blocks, block_index, node_index, node, declaration, resolve,
                        pointers, owners, effects, effect_consumers, owner_consumers, ended, heap_allocations,
                    )
                elif node.operation == Operation.CALL_INDIRECT:
                    if node.entity is None or node.entity.kind != Kind.CALL_CONTRACT:
                        fail("XAX.CALL.INDIRECT", obj.cid.hex(), "INDIRECT-CALL-CONTRACT", Kind.CALL_CONTRACT.name, None if node.entity is None else node.entity.kind.name)
                    contract = _decode_call_contract(node.entity, resolve)
                    if not node.operands:
                        fail("XAX.CALL.INDIRECT", obj.cid.hex(), "INDIRECT-CALL-TARGET", "function pointer operand", 0)
                    pointer_type_cid = operand_types[0]
                    try:
                        element, _permission, _alignment = _decode_pointer_type(resolve(pointer_type_cid), resolve)
                    except XaxError:
                        fail("XAX.CALL.INDIRECT", obj.cid.hex(), "INDIRECT-CALL-TARGET-TYPE", "ptr<opaque<function>>", pointer_type_cid.hex())
                    if not _is_opaque(resolve(element), OpaqueKind.FUNCTION):
                        fail("XAX.CALL.INDIRECT", obj.cid.hex(), "INDIRECT-CALL-TARGET-TYPE", "ptr<opaque<function>>", pointer_type_cid.hex())
                    if operand_types[1:] != contract.inputs or node.results != contract.outputs:
                        fail("XAX.CALL.INDIRECT", obj.cid.hex(), "INDIRECT-CALL-BOUNDED-CONTRACT", [[cid.hex() for cid in contract.inputs], [cid.hex() for cid in contract.outputs]], [[cid.hex() for cid in operand_types[1:]], [cid.hex() for cid in node.results]])
                    # If a bounded indirect ABI call carries a local stack pointer,
                    # its exact owner/effect proof must travel through the contract.
                    # This preserves provenance/lifetime without inventing a generic
                    # foreign-memory escape hatch.  Initialization is conservative:
                    # an opaque call does not make bytes statically initialized.
                    # Pointer types do not imply local-stack provenance.  Only a
                    # pointer value carrying an actual verifier stack fact requires
                    # the owner/effect proof to cross the opaque ABI call.  External
                    # borrowed pointers are valid bounded ABI values without being
                    # fabricated into local-storage provenance.
                    stack_input_indices = [
                        index
                        for index, _cid in enumerate(contract.inputs)
                        if pointers.get(node.operands[1 + index]) is not None
                    ]
                    if stack_input_indices:
                        if len(stack_input_indices) != 1:
                            fail("XAX.CALL.INDIRECT", obj.cid.hex(), "INDIRECT-CALL-STACK-POINTERS", 1, len(stack_input_indices))
                        pointer_contract_index = stack_input_indices[0]
                        owner_indices = [index for index, cid in enumerate(contract.inputs) if _is_stack_owner(resolve(cid))]
                        owner_results = [index for index, cid in enumerate(contract.outputs) if _is_stack_owner(resolve(cid))]
                        if not (len(owner_indices) == len(owner_results) == 1):
                            fail(
                                "XAX.CALL.INDIRECT",
                                obj.cid.hex(),
                                "INDIRECT-CALL-STACK-PROOF",
                                "one stack owner input and matching output",
                                [owner_indices, owner_results],
                            )
                        pointer_ref = node.operands[1 + pointer_contract_index]
                        pointer_fact = pointers.get(pointer_ref)
                        if pointer_fact is None or pointer_fact.storage in ended:
                            fail("XAX.MEMORY.PROVENANCE", obj.cid.hex(), "MEMORY-PROVENANCE-PROVEN", "live local stack pointer", [pointer_ref.block, pointer_ref.index, pointer_ref.result])
                        owner_ref = node.operands[1 + owner_indices[0]]
                        owner = owners.get(owner_ref)
                        # A bounded ABI call may carry additional external memory
                        # effect frontiers (for example JNI/platform memory) beside
                        # the local stack-storage frontier.  Identify the unique
                        # effect value whose verifier provenance matches this exact
                        # stack object instead of rejecting every multi-effect call.
                        stack_effect_inputs = []
                        for index, cid in enumerate(contract.inputs):
                            if not _is_memory_effect(resolve(cid)):
                                continue
                            ref = node.operands[1 + index]
                            fact = effects.get(ref)
                            if fact is not None and fact.storage == pointer_fact.storage:
                                stack_effect_inputs.append((index, ref, fact))
                        if len(stack_effect_inputs) != 1:
                            fail(
                                "XAX.CALL.INDIRECT",
                                obj.cid.hex(),
                                "INDIRECT-CALL-STACK-PROOF",
                                "one provenance-matching stack effect input",
                                [item[0] for item in stack_effect_inputs],
                            )
                        stack_effect_index, effect_ref, effect = stack_effect_inputs[0]
                        stack_effect_type = contract.inputs[stack_effect_index]
                        effect_results = [
                            index
                            for index, cid in enumerate(contract.outputs)
                            if cid == stack_effect_type and _is_memory_effect(resolve(cid))
                        ]
                        if len(effect_results) != 1:
                            fail(
                                "XAX.CALL.INDIRECT",
                                obj.cid.hex(),
                                "INDIRECT-CALL-STACK-PROOF",
                                "one matching stack effect output",
                                effect_results,
                            )
                        if owner is None or owner.storage != pointer_fact.storage:
                            fail("XAX.MEMORY.PROVENANCE", obj.cid.hex(), "INDIRECT-CALL-STACK-PROVENANCE", pointer_fact.storage, None if owner is None else owner.storage)
                        if owner_ref in owner_consumers or effect_ref in effect_consumers:
                            fail("XAX.MEMORY.EFFECT_FORK", obj.cid.hex(), "MEMORY-EFFECT-LINEAR", "one consumer", Operation.CALL_INDIRECT.name)
                        owner_consumers.add(owner_ref)
                        effect_consumers[effect_ref] = Operation.CALL_INDIRECT
                        owners[ValueRef.node_result(block_index, node_index, owner_results[0])] = owner
                        effects[ValueRef.node_result(block_index, node_index, effect_results[0])] = effect
                elif node.operation == Operation.CONSTANT:
                    if node.entity is None or node.entity.kind != Kind.CONSTANT:
                        fail("XAX.STRUCT.CONSTANT_TARGET", obj.cid.hex(), "GRAPH-CONSTANT-TARGET", Kind.CONSTANT.name, None if node.entity is None else node.entity.kind.name)
                    constant_type, _ = _decode_constant(node.entity, resolve)
                    if node.operands or node.results != (constant_type,):
                        fail(
                            "XAX.STRUCT.CONSTANT_CONTRACT",
                            obj.cid.hex(),
                            "GRAPH-CONSTANT-CONTRACT",
                            [[], [constant_type.hex()]],
                            [[cid.hex() for cid in operand_types], [cid.hex() for cid in node.results]],
                        )
                elif node.operation in MEMORY_OPERATIONS or node.operation in ATOMIC_OPERATIONS:
                    _verify_memory_node(
                        obj,
                        resolve,
                        block_index,
                        node_index,
                        node,
                        pointers,
                        owners,
                        effects,
                        effect_consumers,
                        owner_consumers,
                        allocations,
                        ended,
                        heap_allocations,
                    )
                elif node.operation in RESOURCE_EFFECT_OPERATIONS:
                    _verify_resource_effect_node(obj, resolve, node)
                elif node.operation in META_OPERATIONS:
                    _verify_meta_node(obj, resolve, node)
                elif node.operation in TARGET_OPERATIONS:
                    _verify_target_node(obj, resolve, node)
                if node.operation not in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.HEAP_VIEW):
                    _end_heap_views(node.operands, operand_types, owners, owner_consumers, ended, resolve)
            resource_entry_contract = None
            if resource_candidates:
                body_operations = tuple(Operation(node.operation) for node in block.nodes)
                resource_entry_contract = _resource_entry_contract(resource_candidates, body_operations)
                if resource_entry_contract is None:
                    expected_bodies = []
                    for contract in resource_candidates:
                        if contract.body_shape == _ResourceCallBody.STORE_SEQUENCE:
                            expected_bodies.append(f"1..{MAX_RESOURCE_CALL_ACCESSES} store.bits.le nodes")
                        elif contract.body_shape == _ResourceCallBody.LOAD_SEQUENCE:
                            expected_bodies.append(f"1..{MAX_RESOURCE_CALL_ACCESSES} load.bits.le nodes")
                        elif contract.body_shape == _ResourceCallBody.MIXED_SEQUENCE:
                            expected_bodies.append(
                                f"2..{MAX_RESOURCE_CALL_ACCESSES} mixed store/load nodes with final load.bits.le"
                            )
                    if len(resource_candidates) == 2:
                        rule = "MEMORY-ENTRY-STORE-SLICE"
                        expected = expected_bodies
                    elif resource_candidates[0].body_shape == _ResourceCallBody.LOAD_SEQUENCE:
                        rule = "MEMORY-ENTRY-LOAD-SLICE"
                        expected = expected_bodies[0]
                    else:
                        rule = "MEMORY-ENTRY-CONTRACT"
                        expected = expected_bodies
                    fail(
                        "XAX.MEMORY.ENTRY_CONTRACT",
                        obj.cid.hex(),
                        rule,
                        expected,
                        [node.operation for node in block.nodes],
                    )
            live = allocations - ended
            if live and block.terminator.kind in (TerminatorKind.RETURN, TerminatorKind.TRAP):
                fail(
                    "XAX.MEMORY.LIFETIME_LEAK",
                    obj.cid.hex(),
                    "MEMORY-LIFETIME-EXPLICIT-END",
                    sorted(allocations),
                    sorted(ended),
                )
            term = block.terminator
            if resource_candidates and term.kind != TerminatorKind.RETURN:
                fail("XAX.MEMORY.RESOURCE_DROP", obj.cid.hex(), "MEMORY-RESOURCE-TRANSFER", "explicit owner/effect return", term.kind.name)
            if term.kind == TerminatorKind.CONDITIONAL_BRANCH:
                condition_type = resolve(value_type(term.values[0], block_index, len(block.nodes)))
                if decode_bits_width(condition_type) != 1:
                    fail("XAX.STRUCT.CONDITION_TYPE", obj.cid.hex(), "GRAPH-CBR-CONDITION", "bits<1>", condition_type.cid.hex())
            for target, arguments in term.edges:
                actual = tuple(value_type(value, block_index, len(block.nodes)) for value in arguments)
                expected = blocks[target].parameters
                if actual != expected:
                    fail(
                        "XAX.STRUCT.BRANCH_ARGUMENTS",
                        obj.cid.hex(),
                        "GRAPH-BLOCK-PARAMETERS",
                        [cid.hex() for cid in expected],
                        [cid.hex() for cid in actual],
                    )
            if term.kind == TerminatorKind.RETURN:
                if resource_entry_contract is not None:
                    expected_return_count = len(resource_entry_contract.returns)
                    if len(term.values) != expected_return_count:
                        fail(
                            "XAX.MEMORY.RESOURCE_DROP",
                            obj.cid.hex(),
                            "MEMORY-RESOURCE-TRANSFER",
                            "value, owner, and effect return" if expected_return_count == 3 else "owner and effect return",
                            len(term.values),
                        )
                    owner_ref = term.values[resource_entry_contract.owner_result]
                    effect_ref = term.values[resource_entry_contract.effect_result]
                    if resource_entry_contract.returns_final_load:
                        value_node, value_result = len(block.nodes) - 1, 0
                        if term.values[0] != ValueRef.node_result(block_index, value_node, value_result):
                            fail(
                                "XAX.MEMORY.ENTRY_CONTRACT",
                                obj.cid.hex(),
                                "MEMORY-ENTRY-STORE-LOAD-RESULT",
                                [value_node, value_result],
                                [term.values[0].index, term.values[0].result],
                            )
                    owner = owners.get(owner_ref)
                    effect = effects.get(effect_ref)
                    if (
                        owner is None
                        or effect is None
                        or owner.storage != (-1, 0)
                        or effect.storage != owner.storage
                        or owner_ref in owner_consumers
                        or effect_ref in effect_consumers
                    ):
                        fail("XAX.MEMORY.RESOURCE_DROP", obj.cid.hex(), "MEMORY-RESOURCE-TRANSFER", "one live owner/effect pair", "dropped, duplicated, or mismatched")
                return_types = tuple(value_type(value, block_index, len(block.nodes)) for value in term.values)
                _verify_heap_view_return(
                    obj, term.values, return_types, blocks[entry].parameters, resolve,
                    pointers, owners, effects, owner_consumers, effect_consumers, ended,
                )
                returns_by_block.append((block_index, return_types))
            for edge_index, (target, arguments) in enumerate(term.edges):
                pass_exits.setdefault(target, {})[(block_index, edge_index)] = _BlockFacts(
                    {index: pointers[value] for index, value in enumerate(arguments) if value in pointers},
                    {index: owners[value] for index, value in enumerate(arguments) if value in owners and value not in owner_consumers},
                    {index: effects[value] for index, value in enumerate(arguments) if value in effects and value not in effect_consumers},
                    frozenset(ended),
                    frozenset(live),
                )
            global_pointers.update(pointers)
        if not stale or pass_seeds == previous_seeds:
            break
        previous_seeds = pass_seeds
        exits = pass_exits
    else:
        fail("XAX.MEMORY.FACT_FIXPOINT", obj.cid.hex(), "MEMORY-FACT-FIXPOINT", 2 * len(blocks) + 2, "not converged")
    returns = [item for _block, item in sorted(returns_by_block, key=lambda pair: pair[0])]
    parsed = _ParsedGraph(
        entry, tuple(blocks), tuple(returns), tuple(member_spans),
        tuple(sorted(((ref, fact.extent) for ref, fact in global_pointers.items()), key=lambda item: (item[0].tag, item[0].block, item[0].index, item[0].result))),
    )
    _verify_linear_flow(obj, parsed, resolve)
    return parsed


def _decode_function_interface(
    obj: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
) -> tuple[SemanticObject, tuple[bytes, ...], tuple[bytes, ...]]:
    cursor = Cursor(obj.body, obj.cid.hex())
    graph = _reference(obj, cursor, resolve)
    if graph.kind != Kind.GRAPH_FRAGMENT:
        fail("XAX.STRUCT.FUNCTION_GRAPH", obj.cid.hex(), "GRAPH-FUNCTION-CARRIER", Kind.GRAPH_FRAGMENT.name, graph.kind.name)
    parameters = tuple(_type_reference(obj, cursor, resolve) for _ in range(cursor.uleb()))
    returns = tuple(_type_reference(obj, cursor, resolve) for _ in range(cursor.uleb()))
    cursor.end("FUNCTION-BODY")
    return graph, parameters, returns


def _verify_function(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> None:
    graph, parameters, returns = _decode_function_interface(obj, resolve)
    parsed = _parse_graph(graph, resolve)
    if any(node.operation == Operation.CALL_GROUP_MEMBER for block in parsed.blocks for node in block.nodes):
        fail(
            "XAX.STRUCT.GROUP_CALL_CONTEXT",
            obj.cid.hex(),
            "GRAPH-GROUP-CALL-CONTEXT",
            Kind.RECURSION_GROUP.name,
            Kind.FUNCTION.name,
        )
    _verify_graph_contract(obj, parsed, parameters, returns)
    used = {graph.cid, *parameters, *returns}
    if used != set(obj.references):
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", sorted(c.hex() for c in obj.references), sorted(c.hex() for c in used))


def _type_reference(
    obj: SemanticObject,
    cursor: Cursor,
    resolve: Callable[[bytes], SemanticObject],
) -> bytes:
    type_object = _reference(obj, cursor, resolve)
    _verify_type(type_object, resolve)
    return type_object.cid


def _verify_graph_contract(
    owner: SemanticObject,
    parsed: _ParsedGraph,
    parameters: tuple[bytes, ...],
    returns: tuple[bytes, ...],
) -> None:
    entry_parameters = parsed.blocks[parsed.entry].parameters
    if entry_parameters != parameters:
        fail(
            "XAX.STRUCT.ENTRY_CONTRACT",
            owner.cid.hex(),
            "GRAPH-ENTRY-CONTRACT",
            [cid.hex() for cid in parameters],
            [cid.hex() for cid in entry_parameters],
        )
    for actual in parsed.returns:
        if actual != returns:
            fail(
                "XAX.STRUCT.RETURN_CONTRACT",
                owner.cid.hex(),
                "GRAPH-RETURN-CONTRACT",
                [cid.hex() for cid in returns],
                [cid.hex() for cid in actual],
            )


def _decode_recursion_group(
    obj: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
) -> tuple[tuple[SemanticObject, tuple[bytes, ...], tuple[bytes, ...]], ...]:
    cursor = Cursor(obj.body, obj.cid.hex())
    member_count = cursor.uleb()
    if not member_count:
        fail("XAX.STRUCT.RECURSION_GROUP_EMPTY", obj.cid.hex(), "GRAPH-RECURSION-GROUP-NONEMPTY", ">= 1", 0)
    members: list[tuple[SemanticObject, tuple[bytes, ...], tuple[bytes, ...]]] = []
    used: set[bytes] = set()
    for _ in range(member_count):
        graph = _reference(obj, cursor, resolve)
        if graph.kind != Kind.GRAPH_FRAGMENT:
            fail("XAX.STRUCT.FUNCTION_GRAPH", obj.cid.hex(), "GRAPH-FUNCTION-CARRIER", Kind.GRAPH_FRAGMENT.name, graph.kind.name)
        parameters = tuple(_type_reference(obj, cursor, resolve) for _ in range(cursor.uleb()))
        returns = tuple(_type_reference(obj, cursor, resolve) for _ in range(cursor.uleb()))
        members.append((graph, parameters, returns))
        used.update((graph.cid, *parameters, *returns))
    cursor.end("RECURSION-GROUP-BODY")
    if used != set(obj.references):
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", sorted(c.hex() for c in obj.references), sorted(c.hex() for c in used))
    return tuple(members)


def _recursion_shape(graph: SemanticObject, parsed: _ParsedGraph, parameters: tuple[bytes, ...], returns: tuple[bytes, ...]) -> tuple[tuple, tuple[int, ...]]:
    """(member key with group-local indices erased, callee indices in node order)."""
    erased, last = bytearray(), 0
    for start, end in parsed.member_spans:
        erased += graph.body[last:start]
        last = end
    erased += graph.body[last:]
    calls = tuple(node.member for block in parsed.blocks for node in block.nodes if node.operation == Operation.CALL_GROUP_MEMBER)
    return (graph.references, bytes(erased), parameters, returns), calls


def _canonical_recursion_order(keys: Sequence[tuple], calls: Sequence[tuple[int, ...]]) -> tuple[tuple, tuple[int, ...]] | None:
    """Return (descriptor, order) of the canonical member order, or None when the members are not one recursive SCC.

    Each candidate order is the breadth-first discovery order from one start member following group calls in node
    order; the canonical order has the smallest descriptor (erased key, renumbered callees) per position.  Starts with
    equal descriptors encode byte-identical groups.
    """
    # ponytail: O(k^2) over member count, fine for realistic SCC sizes; partition-refinement if large SCCs appear.
    count = len(calls)
    if count == 1 and not calls[0]:
        return None
    best = None
    for start in range(count):
        order, position = [start], {start: 0}
        for member in order:
            for callee in calls[member]:
                if callee not in position:
                    position[callee] = len(order)
                    order.append(callee)
        if len(order) != count:
            return None
        descriptor = tuple((keys[member], tuple(position[callee] for callee in calls[member])) for member in order)
        if best is None or descriptor < best[0]:
            best = (descriptor, tuple(order))
    return best


def canonical_recursion_order(members: Sequence[RecursionMember], resolve: Callable[[bytes], SemanticObject]) -> tuple[int, ...]:
    """Canonical order for a recursive SCC: position p holds input member order[p].

    Producers rebuild member graphs with callee index ``order.index(old)`` in that order before ``recursion_group``.
    """
    shapes = [
        _recursion_shape(m.graph, _parse_graph(m.graph, resolve), tuple(o.cid for o in m.parameters), tuple(o.cid for o in m.returns))
        for m in members
    ]
    if any(callee >= len(members) for _, calls in shapes for callee in calls):
        raise ValueError("group member index out of range")
    canonical = _canonical_recursion_order([key for key, _ in shapes], [calls for _, calls in shapes])
    if canonical is None:
        raise ValueError("recursion group members are not one recursive strongly connected component")
    return canonical[1]


def _verify_recursion_group(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> None:
    members = _decode_recursion_group(obj, resolve)
    member_count = len(members)
    interfaces = tuple((parameters, returns) for _, parameters, returns in members)
    shapes = []
    for graph, parameters, returns in members:
        parsed = _parse_graph(graph, resolve)
        shapes.append(_recursion_shape(graph, parsed, parameters, returns))
        _verify_graph_contract(obj, parsed, parameters, returns)
        for block in parsed.blocks:
            for node in block.nodes:
                if node.operation != Operation.CALL_GROUP_MEMBER:
                    continue
                if node.member is None or node.member >= member_count:
                    fail(
                        "XAX.STRUCT.RECURSION_MEMBER",
                        obj.cid.hex(),
                        "GRAPH-RECURSION-MEMBER",
                        f"< {member_count}",
                        node.member,
                    )
                expected_parameters, expected_returns = interfaces[node.member]
                if node.operand_types != expected_parameters or node.results != expected_returns:
                    fail(
                        "XAX.STRUCT.CALL_CONTRACT",
                        obj.cid.hex(),
                        "GRAPH-CALL-CONTRACT",
                        [[cid.hex() for cid in expected_parameters], [cid.hex() for cid in expected_returns]],
                        [[cid.hex() for cid in node.operand_types], [cid.hex() for cid in node.results]],
                    )
    keys = [key for key, _ in shapes]
    calls = [member_calls for _, member_calls in shapes]
    canonical = _canonical_recursion_order(keys, calls)
    if canonical is None:
        fail("XAX.STRUCT.RECURSION_SCC", obj.cid.hex(), "GRAPH-RECURSION-SCC", "one recursive strongly connected component", [list(c) for c in calls])
    if canonical[0] != tuple(zip(keys, calls)):
        fail("XAX.CANON.RECURSION_ORDER", obj.cid.hex(), "GRAPH-RECURSION-ORDER", list(canonical[1]), list(range(member_count)))


def _verify_reference_list(
    obj: SemanticObject,
    resolve: Callable[[bytes], SemanticObject],
    allowed: frozenset[Kind],
) -> None:
    cursor = Cursor(obj.body, obj.cid.hex())
    indices = tuple(cursor.uleb() for _ in range(cursor.uleb()))
    cursor.end("SCHEMA-BODY")
    if any(index >= len(obj.references) for index in indices):
        fail("XAX.STRUCT.REF_INDEX", obj.cid.hex(), "GRAPH-REF-INDEX", f"< {len(obj.references)}", indices)
    expected = tuple(range(len(obj.references)))
    if indices != expected:
        fail("XAX.CANON.REFERENCE_BODY", obj.cid.hex(), "SER-REF-BODY-CANONICAL", expected, indices)
    for cid in obj.references:
        child = resolve(cid)
        if child.kind not in allowed:
            fail(
                "XAX.STRUCT.CHILD_KIND",
                obj.cid.hex(),
                "GRAPH-CHILD-KIND",
                sorted(kind.name for kind in allowed),
                child.kind.name,
            )


def verify_object(obj: SemanticObject, resolve: Callable[[bytes], SemanticObject]) -> None:
    expected = semantic_cid(obj.kind, obj.schema_version, obj.references, obj.body)
    if obj.cid != expected:
        fail("XAX.IDENTITY.CID_MISMATCH", obj.cid.hex(), "ID-CID-INTEGRITY", expected.hex(), obj.cid.hex())
    for cid in obj.references:
        resolve(cid)
    cursor = Cursor(obj.body, obj.cid.hex())
    if obj.kind == Kind.TYPE:
        _verify_type(obj, resolve)
        return
    if obj.kind == Kind.CONSTANT:
        _decode_constant(obj, resolve)
        return
    if obj.kind == Kind.GRAPH_FRAGMENT:
        _parse_graph(obj, resolve)
        return
    if obj.kind == Kind.FUNCTION:
        _verify_function(obj, resolve)
        return
    if obj.kind == Kind.CALL_CONTRACT:
        _decode_call_contract(obj, resolve)
        return
    if obj.kind == Kind.RECURSION_GROUP:
        _verify_recursion_group(obj, resolve)
        return
    if obj.kind == Kind.PROGRAM_ROOT:
        _verify_reference_list(obj, resolve, frozenset({Kind.MODULE}))
        return
    if obj.kind == Kind.MODULE:
        _verify_reference_list(
            obj,
            resolve,
            frozenset({Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT}),
        )
        return
    if obj.kind in (Kind.PACKAGE, Kind.BUILD):
        from xax_build import verify_build_object

        verify_build_object(obj, resolve)
        return
    if obj.kind == Kind.TARGET:
        decode_native_target(obj, allow_carrier=True)


def verify_store(
    reader: StoreReader,
    *,
    proof_cache: ProofCache | None = None,
    verifier_identity: str = DEFAULT_VERIFIER_IDENTITY,
) -> VerificationStats:
    if not verifier_identity:
        raise ValueError("verifier identity must not be empty")
    objects = {obj.cid: obj for obj in reader.objects()}
    cache = proof_cache if proof_cache is not None else reader.proof_cache
    entries_before = 0 if cache is None else cache.entry_count
    cache_hits = 0
    cache_misses = 0
    dependency_cids_checked = 0

    def resolve(cid: bytes) -> SemanticObject:
        try:
            return objects[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "stored object", "missing")

    for obj in objects.values():
        dependency_cids_checked += len(obj.references)
        if cache is not None and cache.contains(verifier_identity, obj):
            cache_hits += 1
            continue
        cache_misses += 1
        verify_object(obj, resolve)

    reachable: set[bytes] = set()
    active: set[bytes] = set()

    def visit(cid: bytes) -> None:
        if cid in active:
            fail("XAX.IDENTITY.CID_CYCLE", cid.hex(), "ID-MERKLE-ACYCLIC", "acyclic references", "cycle")
        if cid in reachable:
            return
        active.add(cid)
        for child in resolve(cid).references:
            visit(child)
        active.remove(cid)
        reachable.add(cid)

    visit(reader.root_cid)
    if reachable != set(objects):
        fail(
            "XAX.IDENTITY.UNREACHABLE_OBJECT",
            "store",
            "ID-ROOTED-STORE",
            sorted(cid.hex() for cid in objects),
            sorted(cid.hex() for cid in reachable),
        )

    invalidated = written = 0
    if cache is not None:
        invalidated, written = cache.reconcile(verifier_identity, objects.values())
    entries_after = 0 if cache is None else cache.entry_count
    return VerificationStats(
        len(objects),
        cache_hits,
        cache_misses,
        dependency_cids_checked,
        entries_before,
        entries_after,
        invalidated,
        written,
    )


@dataclass(frozen=True)
class CompileTimeInput:
    identity: bytes
    type_object: SemanticObject
    value: int
    reproducible: bool = True


@dataclass(frozen=True)
class CompileTimeBudget:
    steps: int = 100_000
    call_depth: int = 64
    memory_bytes: int = 1 << 20
    semantic_objects: int = 1_024
    graph_nodes: int = 10_000


@dataclass(frozen=True)
class CompileTimeResult:
    key: bytes
    values: tuple[object, ...]
    created_objects: tuple[SemanticObject, ...]
    steps: int
    peak_memory_bytes: int
    cache_hit: bool = False
    evaluated_blocks: int = 0
    evaluated_nodes: int = 0
    graph_nodes: int = 0
    max_call_depth: int = 0


@dataclass
class _CompileTimeContext:
    objects: dict[bytes, SemanticObject]
    capabilities: frozenset[MetaCapability]
    inputs: tuple[CompileTimeInput, ...]
    budget: CompileTimeBudget
    steps: int = 0
    evaluated_blocks: int = 0
    evaluated_nodes: int = 0
    depth: int = 0
    max_depth: int = 0
    memory: int = 0
    peak_memory: int = 0
    created: dict[bytes, SemanticObject] | None = None
    graph_nodes: int = 0

    def __post_init__(self) -> None:
        self.created = {}

    def resolve(self, cid: bytes) -> SemanticObject:
        try:
            return self.objects[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "compile-time object", "missing")

    def charge_step(self, owner: SemanticObject, *, block: bool = False) -> None:
        self.steps += 1
        if block:
            self.evaluated_blocks += 1
        else:
            self.evaluated_nodes += 1
        if self.steps > self.budget.steps:
            fail("XAX.META.BUDGET", owner.cid.hex(), "META-STEP-BUDGET", f"<= {self.budget.steps}", self.steps)

    def enter(self, owner: SemanticObject, arguments: tuple[object, ...], result_slots: int) -> int:
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        if self.depth > self.budget.call_depth:
            fail("XAX.META.BUDGET", owner.cid.hex(), "META-CALL-DEPTH", f"<= {self.budget.call_depth}", self.depth)
        size = 32 + sum(_compile_time_value_size(value) for value in arguments) + 16 * result_slots
        self.memory += size
        self.peak_memory = max(self.peak_memory, self.memory)
        if self.memory > self.budget.memory_bytes:
            fail("XAX.META.BUDGET", owner.cid.hex(), "META-MEMORY-BUDGET", f"<= {self.budget.memory_bytes}", self.memory)
        return size

    def leave(self, size: int) -> None:
        self.memory -= size
        self.depth -= 1

    def require(self, owner: SemanticObject, capability: MetaCapability) -> None:
        if capability not in self.capabilities:
            fail("XAX.META.CAPABILITY", owner.cid.hex(), "META-CAPABILITY-DECLARED", capability.name.lower(), "absent")

    def publish(self, owner: SemanticObject, candidates: Sequence[SemanticObject], graph_nodes: int = 0) -> None:
        new = tuple(candidate for candidate in candidates if candidate.cid not in self.objects)
        if len(self.created) + len(new) > self.budget.semantic_objects:
            fail("XAX.META.BUDGET", owner.cid.hex(), "META-OBJECT-BUDGET", f"<= {self.budget.semantic_objects}", len(self.created) + len(new))
        if self.graph_nodes + graph_nodes > self.budget.graph_nodes:
            fail("XAX.META.BUDGET", owner.cid.hex(), "META-GRAPH-NODE-BUDGET", f"<= {self.budget.graph_nodes}", self.graph_nodes + graph_nodes)
        self.graph_nodes += graph_nodes
        for candidate in new:
            self.objects[candidate.cid] = candidate
            self.created[candidate.cid] = candidate
            verify_object(candidate, self.resolve)


def _compile_time_value_size(value: object) -> int:
    if isinstance(value, SemanticObject):
        return CID_SIZE
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, int):
        return max(1, (value.bit_length() + 7) // 8)
    return 0


def _compile_time_value(
    owner: SemanticObject,
    value: object,
    type_cid: bytes,
    resolve: Callable[[bytes], SemanticObject],
) -> object:
    type_object = resolve(type_cid)
    if _is_opaque(type_object):
        opaque_kind = _decode_opaque_type(type_object)
        if opaque_kind == OpaqueKind.OBJECT:
            if not isinstance(value, SemanticObject):
                fail("XAX.META.VALUE", owner.cid.hex(), "META-SEMANTIC-VALUE-TYPE", "semantic object", type(value).__name__)
            return value
        if opaque_kind == OpaqueKind.BYTES:
            if not isinstance(value, bytes):
                fail("XAX.META.VALUE", owner.cid.hex(), "META-BYTES-VALUE", "bytes", type(value).__name__)
            return value
        semantic_kind = {
            OpaqueKind.TYPE: Kind.TYPE,
            OpaqueKind.CONSTANT: Kind.CONSTANT,
            OpaqueKind.FUNCTION: Kind.FUNCTION,
            OpaqueKind.TARGET: Kind.TARGET,
            OpaqueKind.GRAPH: Kind.GRAPH_FRAGMENT,
        }[opaque_kind]
        if not isinstance(value, SemanticObject) or value.kind != semantic_kind:
            fail("XAX.META.VALUE", owner.cid.hex(), "META-SEMANTIC-VALUE-TYPE", semantic_kind.name, type(value).__name__)
        return value
    if _is_proof_type(type_object) or _is_stack_pointer(type_object):
        fail("XAX.META.STAGE", owner.cid.hex(), "META-COMPILE-TIME-TYPE", "bits or opaque semantic value", type_cid.hex())
    width = decode_bits_width(type_object)
    if not isinstance(value, int) or value < 0 or value >= 1 << width:
        fail("XAX.META.VALUE", owner.cid.hex(), "META-BITS-VALUE", f"bits<{width}>", value)
    return value


class CompileTimeEvaluator:
    def __init__(self) -> None:
        self._cache: dict[bytes, CompileTimeResult] = {}

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def evaluate(
        self,
        reader: StoreReader,
        callable_cid: bytes,
        arguments: Sequence[object],
        *,
        capabilities: Iterable[MetaCapability | int] = (),
        inputs: Sequence[CompileTimeInput] = (),
        budget: CompileTimeBudget = CompileTimeBudget(),
        reproducible: bool = True,
        member_index: int | None = None,
        evaluator_identity: bytes = b"xax-meta-evaluator-v1",
        verifier_identity: bytes = b"xax-verifier-v1",
    ) -> CompileTimeResult:
        verify_store(reader)
        if any(value < 0 for value in (budget.steps, budget.call_depth, budget.memory_bytes, budget.semantic_objects, budget.graph_nodes)):
            raise ValueError("compile-time budgets must be nonnegative")
        try:
            capability_set = frozenset(MetaCapability(value) for value in capabilities)
        except ValueError as error:
            raise ValueError("invalid compile-time capability") from error
        inputs = tuple(inputs)
        if any(not item.identity for item in inputs) or len({item.identity for item in inputs}) != len(inputs):
            raise ValueError("compile-time input identities must be nonempty and unique")
        if reproducible and any(not item.reproducible for item in inputs):
            fail("XAX.META.INPUT", callable_cid.hex(), "META-REPRODUCIBLE-INPUT", True, False)

        objects = {obj.cid: obj for obj in reader.objects()}
        for argument in arguments:
            if isinstance(argument, SemanticObject):
                objects[argument.cid] = argument
        for item in inputs:
            objects[item.type_object.cid] = item.type_object

        def resolve(cid: bytes) -> SemanticObject:
            try:
                return objects[cid]
            except KeyError:
                fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "compile-time object", "missing")

        for obj in tuple(objects.values()):
            verify_object(obj, resolve)
        for item in inputs:
            width = decode_bits_width(item.type_object)
            if not isinstance(item.value, int) or item.value < 0 or item.value >= 1 << width:
                fail("XAX.META.INPUT", item.identity.hex(), "META-INPUT-VALUE", f"bits<{width}>", item.value)

        owner = resolve(callable_cid)
        if owner.kind == Kind.FUNCTION:
            if member_index is not None:
                fail("XAX.META.CALLABLE", owner.cid.hex(), "META-MEMBER-INDEX", None, member_index)
            _, parameter_types, _ = _decode_function_interface(owner, resolve)
        elif owner.kind == Kind.RECURSION_GROUP:
            members = _decode_recursion_group(owner, resolve)
            if member_index is None or member_index < 0 or member_index >= len(members):
                fail("XAX.META.CALLABLE", owner.cid.hex(), "META-MEMBER-INDEX", f"< {len(members)}", member_index)
            _, parameter_types, _ = members[member_index]
        else:
            fail("XAX.META.CALLABLE", owner.cid.hex(), "META-CALLABLE-KIND", [Kind.FUNCTION.name, Kind.RECURSION_GROUP.name], owner.kind.name)
        normalized = tuple(_compile_time_value(owner, value, type_cid, resolve) for value, type_cid in zip(arguments, parameter_types))
        if len(arguments) != len(parameter_types):
            fail("XAX.META.VALUE", owner.cid.hex(), "META-ARGUMENT-COUNT", len(parameter_types), len(arguments))

        key = _compile_time_key(
            callable_cid,
            member_index,
            normalized,
            capability_set,
            inputs,
            reproducible,
            evaluator_identity,
            verifier_identity,
        )
        cached = self._cache.get(key)
        if cached is not None:
            return CompileTimeResult(
                cached.key, cached.values, cached.created_objects, cached.steps, cached.peak_memory_bytes, True,
                cached.evaluated_blocks, cached.evaluated_nodes, cached.graph_nodes, cached.max_call_depth,
            )

        context = _CompileTimeContext(objects, capability_set, inputs, budget)
        if owner.kind == Kind.FUNCTION:
            values = _execute_compile_time_function(owner, normalized, context)
        else:
            values = _execute_compile_time_group_member(owner, members, member_index, normalized, context)
        result = CompileTimeResult(
            key, values, tuple(context.created[cid] for cid in sorted(context.created)), context.steps, context.peak_memory,
            False, context.evaluated_blocks, context.evaluated_nodes, context.graph_nodes, context.max_depth,
        )
        self._cache[key] = result
        return result


def _compile_time_key(
    callable_cid: bytes,
    member_index: int | None,
    arguments: tuple[object, ...],
    capabilities: frozenset[MetaCapability],
    inputs: tuple[CompileTimeInput, ...],
    reproducible: bool,
    evaluator_identity: bytes,
    verifier_identity: bytes,
) -> bytes:
    out = bytearray(b"XAX-CT-1" + callable_cid + uleb(0 if member_index is None else member_index + 1))

    def add_bytes(value: bytes) -> None:
        out.extend(uleb(len(value)) + value)

    out.extend(uleb(len(arguments)))
    for value in arguments:
        if isinstance(value, SemanticObject):
            out.extend(b"S" + value.cid)
        elif isinstance(value, bytes):
            out.extend(b"B")
            add_bytes(value)
        else:
            out.extend(b"I" + uleb(value))
    out.extend(uleb(len(capabilities)) + b"".join(uleb(value) for value in sorted(capabilities)))
    out.extend(uleb(len(inputs)))
    for item in inputs:
        add_bytes(item.identity)
        out.extend(item.type_object.cid + uleb(item.value) + bytes((item.reproducible,)))
    out.extend(bytes((reproducible,)))
    add_bytes(evaluator_identity)
    add_bytes(verifier_identity)
    return blake3(out).digest()


def _execute_compile_time_function(
    function_object: SemanticObject,
    arguments: tuple[object, ...],
    context: _CompileTimeContext,
) -> tuple[object, ...]:
    graph, parameters, returns = _decode_function_interface(function_object, context.resolve)
    return _execute_compile_time_graph(function_object, graph, parameters, returns, arguments, context)


def _execute_compile_time_group_member(
    group: SemanticObject,
    members: tuple[tuple[SemanticObject, tuple[bytes, ...], tuple[bytes, ...]], ...],
    member_index: int,
    arguments: tuple[object, ...],
    context: _CompileTimeContext,
) -> tuple[object, ...]:
    if member_index < 0 or member_index >= len(members):
        fail("XAX.META.CALLABLE", group.cid.hex(), "META-RECURSION-MEMBER", f"< {len(members)}", member_index)
    graph, parameters, returns = members[member_index]
    return _execute_compile_time_graph(group, graph, parameters, returns, arguments, context, members)


def _execute_compile_time_graph(
    owner: SemanticObject,
    graph_object: SemanticObject,
    parameter_types: tuple[bytes, ...],
    return_types: tuple[bytes, ...],
    arguments: tuple[object, ...],
    context: _CompileTimeContext,
    group_members: tuple[tuple[SemanticObject, tuple[bytes, ...], tuple[bytes, ...]], ...] | None = None,
) -> tuple[object, ...]:
    if len(arguments) != len(parameter_types):
        fail("XAX.META.VALUE", owner.cid.hex(), "META-ARGUMENT-COUNT", len(parameter_types), len(arguments))
    arguments = tuple(_compile_time_value(owner, value, type_cid, context.resolve) for value, type_cid in zip(arguments, parameter_types))
    graph = _parse_graph(graph_object, context.resolve)
    result_slots = sum(len(node.results) for block in graph.blocks for node in block.nodes)
    frame_size = context.enter(owner, arguments, result_slots)
    values: dict[tuple[int, int, int, int], object] = {}
    block_index = graph.entry
    block_arguments = arguments

    def read(value: ValueRef) -> object:
        key = (value.tag, value.block, value.index, value.result)
        try:
            return values[key]
        except KeyError:
            fail("XAX.META.VALUE", graph_object.cid.hex(), "META-VALUE-AVAILABLE", key, "missing")

    try:
        while True:
            context.charge_step(owner, block=True)
            block = graph.blocks[block_index]
            for index, value in enumerate(block_arguments):
                values[(0, block_index, index, 0)] = value
            for node_index, node in enumerate(block.nodes):
                context.charge_step(owner)
                operands = tuple(read(value) for value in node.operands)
                operation = Operation(node.operation)
                if operation in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                    width = decode_bits_width(context.resolve(node.results[0]))
                    mask = (1 << width) - 1
                    value = operands[0] + operands[1] if operation == Operation.ADD_WRAP else operands[0] - operands[1] if operation == Operation.SUB_WRAP else operands[0] * operands[1]
                    results = (value & mask,)
                elif operation == Operation.CONSTANT:
                    _, value = _decode_constant(node.entity, context.resolve)
                    results = (value,)
                elif operation == Operation.CALL_DIRECT:
                    results = _execute_compile_time_function(node.entity, operands, context)
                elif operation == Operation.CALL_GROUP_MEMBER and group_members is not None:
                    results = _execute_compile_time_group_member(owner, group_members, node.member, operands, context)
                elif operation == Operation.META_TYPE_BITS_WIDTH:
                    context.require(owner, MetaCapability.INSPECT_TYPE)
                    results = (decode_bits_width(operands[0]),)
                elif operation == Operation.META_CONSTANT_VALUE:
                    context.require(owner, MetaCapability.INSPECT_CONSTANT)
                    constant_type, value = _decode_constant(operands[0], context.resolve)
                    if constant_type != node.results[0]:
                        fail("XAX.META.VALUE", owner.cid.hex(), "META-CONSTANT-RESULT-TYPE", node.results[0].hex(), constant_type.hex())
                    results = (value,)
                elif operation == Operation.META_TARGET_SUPPORTS:
                    context.require(owner, MetaCapability.INSPECT_TARGET)
                    description = decode_native_target(operands[0])
                    results = (int(node.attributes[0] in description.supported_operations),)
                elif operation == Operation.META_DECLARED_INPUT:
                    context.require(owner, MetaCapability.READ_DECLARED_INPUT)
                    index = node.attributes[0]
                    if index >= len(context.inputs):
                        fail("XAX.META.INPUT", owner.cid.hex(), "META-INPUT-INDEX", f"< {len(context.inputs)}", index)
                    item = context.inputs[index]
                    if item.type_object.cid != node.results[0]:
                        fail("XAX.META.INPUT", owner.cid.hex(), "META-INPUT-TYPE", node.results[0].hex(), item.type_object.cid.hex())
                    results = (item.value,)
                elif operation == Operation.META_MATERIALIZE_CONSTANT_FUNCTION:
                    context.require(owner, MetaCapability.CONSTRUCT_SEMANTICS)
                    type_object, value = operands
                    if node.operand_types[1] != type_object.cid:
                        fail("XAX.META.VALUE", owner.cid.hex(), "META-CONSTRUCT-VALUE-TYPE", type_object.cid.hex(), node.operand_types[1].hex())
                    constant_object = constant(type_object, value)
                    candidate_graph = graph_fragment(
                        (Block((), (Node(Operation.CONSTANT, (), (type_object,), entity=constant_object),), Terminator.return_((ValueRef.node_result(0, 0),))),)
                    )
                    candidate_function = function(candidate_graph, (), (type_object,))
                    context.publish(owner, (constant_object, candidate_graph, candidate_function), 1)
                    results = (candidate_function,)
                elif operation == Operation.META_MATERIALIZE_PROGRAM:
                    context.require(owner, MetaCapability.CONSTRUCT_SEMANTICS)
                    candidate_function = operands[0]
                    candidate_module = object_with_refs(Kind.MODULE, (candidate_function,))
                    candidate_root = object_with_refs(Kind.PROGRAM_ROOT, (candidate_module,))
                    context.publish(owner, (candidate_module, candidate_root))
                    results = (candidate_root,)
                elif operation == Operation.META_FUNCTION_GRAPH:
                    context.require(owner, MetaCapability.INSPECT_FUNCTION)
                    graph_value, _, _ = _decode_function_interface(operands[0], context.resolve)
                    results = (graph_value,)
                elif operation == Operation.META_GRAPH_BLOCK_COUNT:
                    context.require(owner, MetaCapability.INSPECT_FUNCTION)
                    parsed = _parse_graph(operands[0], context.resolve)
                    results = (len(parsed.blocks),)
                elif operation == Operation.META_GRAPH_NODE_COUNT:
                    context.require(owner, MetaCapability.INSPECT_FUNCTION)
                    parsed = _parse_graph(operands[0], context.resolve)
                    block_index = operands[1]
                    if block_index >= len(parsed.blocks):
                        fail("XAX.META.INSPECT", owner.cid.hex(), "META-GRAPH-BLOCK-INDEX", f"< {len(parsed.blocks)}", block_index)
                    results = (len(parsed.blocks[block_index].nodes),)
                elif operation == Operation.META_GRAPH_NODE_OPERATION:
                    context.require(owner, MetaCapability.INSPECT_FUNCTION)
                    parsed = _parse_graph(operands[0], context.resolve)
                    query_block_index, query_node_index = operands[1], operands[2]
                    if query_block_index >= len(parsed.blocks):
                        fail("XAX.META.INSPECT", owner.cid.hex(), "META-GRAPH-BLOCK-INDEX", f"< {len(parsed.blocks)}", query_block_index)
                    if query_node_index >= len(parsed.blocks[query_block_index].nodes):
                        fail("XAX.META.INSPECT", owner.cid.hex(), "META-GRAPH-NODE-INDEX", f"< {len(parsed.blocks[query_block_index].nodes)}", query_node_index)
                    results = (parsed.blocks[query_block_index].nodes[query_node_index].operation,)
                elif operation == Operation.META_FUNCTION_PARAMETER_COUNT:
                    context.require(owner, MetaCapability.INSPECT_FUNCTION_INTERFACE)
                    _, interface_parameters, _ = _decode_function_interface(operands[0], context.resolve)
                    results = (len(interface_parameters),)
                elif operation == Operation.META_FUNCTION_RETURN_COUNT:
                    context.require(owner, MetaCapability.INSPECT_FUNCTION_INTERFACE)
                    _, _, interface_returns = _decode_function_interface(operands[0], context.resolve)
                    results = (len(interface_returns),)
                elif operation == Operation.META_CANONICAL_STORE:
                    context.require(owner, MetaCapability.SERIALIZE_SEMANTICS)
                    root = operands[0]
                    reachable: dict[bytes, SemanticObject] = {}
                    pending = [root.cid]
                    while pending:
                        cid = pending.pop()
                        if cid in reachable:
                            continue
                        candidate = context.resolve(cid)
                        reachable[cid] = candidate
                        pending.extend(candidate.references)
                    results = (write_store(root.cid, reachable.values()),)
                elif operation == Operation.META_VERIFY_SEMANTICS:
                    context.require(owner, MetaCapability.VERIFY_SEMANTICS)
                    root = operands[0]
                    reachable: dict[bytes, SemanticObject] = {}
                    pending = [root.cid]
                    while pending:
                        cid = pending.pop()
                        if cid in reachable:
                            continue
                        candidate = context.resolve(cid)
                        reachable[cid] = candidate
                        pending.extend(candidate.references)
                    for candidate in tuple(reachable.values()):
                        verify_object(candidate, context.resolve)
                    results = (1,)
                else:
                    fail("XAX.META.STAGE", graph_object.cid.hex(), "META-OP-COMPILE-TIME", sorted(META_OPERATIONS | {Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.CONSTANT, Operation.CALL_DIRECT, Operation.CALL_GROUP_MEMBER}), operation)
                for result_index, (result, type_cid) in enumerate(zip(results, node.results)):
                    values[(1, block_index, node_index, result_index)] = _compile_time_value(owner, result, type_cid, context.resolve)

            term = block.terminator
            if term.kind == TerminatorKind.RETURN:
                results = tuple(read(value) for value in term.values)
                if len(results) != len(return_types):
                    fail("XAX.META.VALUE", owner.cid.hex(), "META-RETURN-COUNT", len(return_types), len(results))
                return tuple(_compile_time_value(owner, value, type_cid, context.resolve) for value, type_cid in zip(results, return_types))
            if term.kind == TerminatorKind.TRAP:
                raise XaxTrap(term.payload)
            edge = term.edges[0]
            if term.kind == TerminatorKind.CONDITIONAL_BRANCH:
                edge = term.edges[0 if read(term.values[0]) else 1]
            block_index, edge_arguments = edge
            block_arguments = tuple(read(value) for value in edge_arguments)
    finally:
        context.leave(frame_size)


def materialize_compile_time(reader: StoreReader, result: CompileTimeResult) -> StoreReader:
    verify_store(reader)
    generated = tuple(value for value in result.values if isinstance(value, SemanticObject) and value.kind == Kind.FUNCTION)
    if not generated:
        fail("XAX.META.MATERIALIZE", reader.root_cid.hex(), "META-MATERIALIZE-RESULT", "at least one function", "none")
    objects = {obj.cid: obj for obj in reader.objects()}
    for obj in (*result.created_objects, *generated):
        objects[obj.cid] = obj

    root = objects[reader.root_cid]
    modules = tuple(objects[cid] for cid in root.references)
    if len(modules) != 1:
        fail("XAX.META.MATERIALIZE", root.cid.hex(), "META-MATERIALIZE-MODULE", "exactly one module", len(modules))
    old_module = modules[0]
    children = tuple(objects[cid] for cid in old_module.references)
    new_module = object_with_refs(Kind.MODULE, (*children, *generated))
    objects[new_module.cid] = new_module
    new_root = object_with_refs(Kind.PROGRAM_ROOT, (new_module,))
    objects[new_root.cid] = new_root

    reachable: dict[bytes, SemanticObject] = {}

    def visit(cid: bytes) -> None:
        if cid in reachable:
            return
        try:
            obj = objects[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "materialized object", "missing")
        reachable[cid] = obj
        for child in obj.references:
            visit(child)

    visit(new_root.cid)
    candidate = StoreReader.from_objects(new_root.cid, reachable.values(), reader.nonsemantic_records)
    verify_store(candidate)
    return candidate


@dataclass
class _RuntimeStorage:
    data: bytearray
    live: bool = True


@dataclass(frozen=True)
class _RuntimePointer:
    storage: _RuntimeStorage
    offset: int


@dataclass(frozen=True)
class _RuntimeFunctionPointer:
    function: SemanticObject


@dataclass(frozen=True)
class _RuntimeSum:
    tag: int
    value: object


@dataclass(frozen=True)
class _RuntimeOwner:
    storage: _RuntimeStorage


@dataclass(frozen=True)
class _RuntimeEffect:
    storage: _RuntimeStorage


@dataclass(frozen=True)
class _RuntimeDomainEffect:
    domain: EffectDomain
    instance: int
    generation: int = 0


@dataclass
class _RuntimeResource:
    kind: int
    state: int
    identity: object
    live: bool = True
    split_identity: object | None = None
    split_part: int | None = None
    parent_identity: object | None = None


def _runtime_scalar_bytes(value: object, type_object: SemanticObject) -> bytes:
    form = Cursor(type_object.body, type_object.cid.hex()).uleb()
    if form == 1:
        width = decode_bits_width(type_object)
        return int(value).to_bytes((width + 7) // 8, "little")
    if form == 7:
        width = decode_float_width(type_object)
        return _float_raw_bits(float(value), width).to_bytes(width // 8, "little")
    fail("XAX.EXEC.MEMORY_TYPE", type_object.cid.hex(), "EXEC-MEMORY-SCALAR", ["bits", "float"], form)


def _runtime_scalar_from_bytes(data: bytes, type_object: SemanticObject) -> object:
    form = Cursor(type_object.body, type_object.cid.hex()).uleb()
    if form == 1:
        return int.from_bytes(data, "little")
    if form == 7:
        width = decode_float_width(type_object)
        return struct.unpack("<f" if width == 32 else "<d", data)[0]
    fail("XAX.EXEC.MEMORY_TYPE", type_object.cid.hex(), "EXEC-MEMORY-SCALAR", ["bits", "float"], form)


def _normalize_runtime_value(
    owner: SemanticObject, value: object, type_cid: bytes, resolve: Callable[[bytes], SemanticObject]
) -> object:
    type_object = resolve(type_cid)
    form = Cursor(type_object.body, type_object.cid.hex()).uleb()
    if form == 1:
        width = decode_bits_width(type_object)
        if not isinstance(value, int) or value < 0 or value >= 1 << width:
            fail("XAX.EXEC.ARGUMENT_RANGE", owner.cid.hex(), "EXEC-ARGUMENT-RANGE", f"bits<{width}>", value)
        return value
    if form == 7:
        if not isinstance(value, (int, float)):
            fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-FLOAT", "float", type(value).__name__)
        return _round_float(float(value), decode_float_width(type_object))
    if form == 8:
        elements = _decode_tuple_type(type_object, resolve)
        if not isinstance(value, (tuple, list)) or len(value) != len(elements):
            fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-TUPLE", len(elements), type(value).__name__)
        return tuple(_normalize_runtime_value(owner, item, cid, resolve) for item, cid in zip(value, elements))
    if form == 9:
        element, count = _decode_array_type(type_object, resolve)
        if not isinstance(value, (tuple, list)) or len(value) != count:
            fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-ARRAY", count, type(value).__name__)
        return tuple(_normalize_runtime_value(owner, item, element, resolve) for item in value)
    if form == 10:
        variants = _decode_sum_type(type_object, resolve)
        if not isinstance(value, _RuntimeSum) or value.tag < 0 or value.tag >= len(variants):
            fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-SUM", f"tag < {len(variants)}", type(value).__name__)
        return _RuntimeSum(value.tag, _normalize_runtime_value(owner, value.value, variants[value.tag], resolve))
    return value


def execute(
    reader: StoreReader,
    function_cid: bytes,
    arguments: Sequence[object],
    fuel: int = 100_000,
) -> tuple[object, ...]:
    resolve = _verified_resolver(reader)
    function_object = resolve(function_cid)
    if function_object.kind != Kind.FUNCTION:
        fail("XAX.EXEC.FUNCTION", function_cid.hex(), "EXEC-FUNCTION-KIND", Kind.FUNCTION.name, function_object.kind.name)
    return _execute_function(function_object, tuple(arguments), resolve, [fuel])


def execute_group_member(
    reader: StoreReader,
    group_cid: bytes,
    member_index: int,
    arguments: Sequence[object],
    fuel: int = 100_000,
) -> tuple[object, ...]:
    resolve = _verified_resolver(reader)
    group = resolve(group_cid)
    if group.kind != Kind.RECURSION_GROUP:
        fail("XAX.EXEC.RECURSION_GROUP", group_cid.hex(), "EXEC-RECURSION-GROUP-KIND", Kind.RECURSION_GROUP.name, group.kind.name)
    members = _decode_recursion_group(group, resolve)
    return _execute_group_member(group, members, member_index, tuple(arguments), resolve, [fuel])


def store_resolver(reader: StoreReader) -> Callable[[bytes], SemanticObject]:
    """Decode/CID-check every stored object once (in canonical order), then resolve via the reader memo."""
    for _ in reader.objects():
        pass
    return reader.get


def _verified_resolver(reader: StoreReader) -> Callable[[bytes], SemanticObject]:
    verify_store(reader)
    return reader.get


def _binary_integer(operation: Operation, left: int, right: int, width: int) -> int:
    """Exact reference semantics for every same-width binary integer operation."""
    mask = (1 << width) - 1
    if operation in (Operation.UDIV, Operation.UREM):
        if right == 0:
            raise XaxTrap(trap_payload(TrapReason.INTEGER_DIVIDE_BY_ZERO))
        return (left // right if operation == Operation.UDIV else left % right) & mask
    return {
        Operation.ADD_WRAP: left + right,
        Operation.SUB_WRAP: left - right,
        Operation.MUL_WRAP: left * right,
        Operation.BIT_XOR: left ^ right,
        Operation.BIT_AND: left & right,
        Operation.BIT_OR: left | right,
    }[operation] & mask


def _execute_function(
    function_object: SemanticObject,
    arguments: tuple[object, ...],
    resolve: Callable[[bytes], SemanticObject],
    fuel: list[int],
) -> tuple[object, ...]:
    graph_object, parameter_types, return_types = _decode_function_interface(function_object, resolve)
    return _execute_graph(function_object, graph_object, parameter_types, return_types, arguments, resolve, fuel)


def _execute_group_member(
    group: SemanticObject,
    members: tuple[tuple[SemanticObject, tuple[bytes, ...], tuple[bytes, ...]], ...],
    member_index: int,
    arguments: tuple[int, ...],
    resolve: Callable[[bytes], SemanticObject],
    fuel: list[int],
) -> tuple[int, ...]:
    if member_index < 0 or member_index >= len(members):
        fail("XAX.EXEC.RECURSION_MEMBER", group.cid.hex(), "EXEC-RECURSION-MEMBER", f"< {len(members)}", member_index)
    graph, parameter_types, return_types = members[member_index]
    return _execute_graph(group, graph, parameter_types, return_types, arguments, resolve, fuel, members)


def _execute_graph(
    owner: SemanticObject,
    graph_object: SemanticObject,
    parameter_types: tuple[bytes, ...],
    return_types: tuple[bytes, ...],
    arguments: tuple[object, ...],
    resolve: Callable[[bytes], SemanticObject],
    fuel: list[int],
    group_members: tuple[tuple[SemanticObject, tuple[bytes, ...], tuple[bytes, ...]], ...] | None = None,
) -> tuple[object, ...]:
    if len(arguments) != len(parameter_types):
        fail("XAX.EXEC.ARGUMENT_COUNT", owner.cid.hex(), "EXEC-ARGUMENT-COUNT", len(parameter_types), len(arguments))
    runtime_owner: _RuntimeOwner | None = None
    runtime_effect: _RuntimeEffect | None = None
    runtime_pointers: list[_RuntimePointer] = []
    normalized_arguments: list[object] = []
    for argument, type_cid in zip(arguments, parameter_types):
        type_object = resolve(type_cid)
        if _is_stack_pointer(type_object):
            element, _permission, _alignment = _decode_pointer_type(type_object, resolve)
            if _is_opaque(resolve(element), OpaqueKind.FUNCTION):
                if not isinstance(argument, _RuntimeFunctionPointer):
                    fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-TYPE", "function pointer", type(argument).__name__)
            elif _decode_pointer_space(type_object) == 1:
                if not isinstance(argument, _RuntimePointer) or not argument.storage.live:
                    fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-TYPE", "live pointer", type(argument).__name__)
                runtime_pointers.append(argument)
            elif not isinstance(argument, int) or argument < 0:
                fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-TYPE", "nonnegative external pointer word", type(argument).__name__)
        elif _is_stack_owner(type_object):
            if not isinstance(argument, _RuntimeOwner) or not argument.storage.live:
                fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-TYPE", "live stack owner", type(argument).__name__)
            runtime_owner = argument
        elif _is_memory_effect(type_object):
            if not isinstance(argument, _RuntimeEffect):
                fail("XAX.EXEC.ARGUMENT_TYPE", owner.cid.hex(), "EXEC-ARGUMENT-TYPE", "memory effect", type(argument).__name__)
            runtime_effect = argument
        elif _is_resource(type_object):
            expected = _decode_resource_type(type_object)
            if (
                not isinstance(argument, _RuntimeResource)
                or not argument.live
                or (argument.kind, argument.state) != (expected.kind, expected.state)
            ):
                fail(
                    "XAX.EXEC.ARGUMENT_TYPE",
                    owner.cid.hex(),
                    "EXEC-ARGUMENT-RESOURCE",
                    [expected.kind, expected.state],
                    type(argument).__name__,
                )
        elif _is_effect(type_object):
            expected = _decode_effect_type(type_object)
            if argument is None:
                argument = _RuntimeDomainEffect(expected.domain, expected.instance)
            if not isinstance(argument, _RuntimeDomainEffect) or (argument.domain, argument.instance) != (expected.domain, expected.instance):
                fail(
                    "XAX.EXEC.ARGUMENT_TYPE",
                    owner.cid.hex(),
                    "EXEC-ARGUMENT-EFFECT",
                    [expected.domain.name.lower(), expected.instance],
                    type(argument).__name__,
                )
        else:
            argument = _normalize_runtime_value(owner, argument, type_cid, resolve)
        normalized_arguments.append(argument)
    arguments = tuple(normalized_arguments)
    if runtime_owner is not None and (runtime_effect is None or runtime_effect.storage is not runtime_owner.storage):
        fail("XAX.EXEC.ARGUMENT_PROVENANCE", owner.cid.hex(), "EXEC-ARGUMENT-PROVENANCE", "matching owner/effect storage", "mismatch")
    if runtime_owner is not None and any(pointer.storage is not runtime_owner.storage for pointer in runtime_pointers):
        fail("XAX.EXEC.ARGUMENT_PROVENANCE", owner.cid.hex(), "EXEC-ARGUMENT-PROVENANCE", "matching pointer/owner storage", "mismatch")

    graph = _parse_graph(graph_object, resolve)
    values: dict[tuple[int, int, int, int], object] = {}
    block_index = graph.entry
    block_arguments = arguments

    def read(value: ValueRef) -> object:
        key = (value.tag, value.block, value.index, value.result)
        try:
            return values[key]
        except KeyError:
            fail("XAX.EXEC.VALUE", graph_object.cid.hex(), "EXEC-VALUE-AVAILABLE", key, "missing")

    while True:
        fuel[0] -= 1
        if fuel[0] < 0:
            fail("XAX.EXEC.FUEL", owner.cid.hex(), "EXEC-FUEL", ">= 0", fuel[0])
        block = graph.blocks[block_index]
        for index, value in enumerate(block_arguments):
            values[(0, block_index, index, 0)] = value
        for node_index, node in enumerate(block.nodes):
            fuel[0] -= 1
            if fuel[0] < 0:
                fail("XAX.EXEC.FUEL", owner.cid.hex(), "EXEC-FUEL", ">= 0", fuel[0])
            operands = tuple(read(value) for value in node.operands)
            if node.operation in BINARY_INTEGER_OPERATIONS:
                width = decode_bits_width(resolve(node.results[0]))
                results = (_binary_integer(node.operation, operands[0], operands[1], width),)
            elif node.operation in INTEGER_WIDTH_OPERATIONS:
                results = (int(operands[0]) & ((1 << decode_bits_width(resolve(node.results[0]))) - 1),)
            elif node.operation == Operation.ROTATE_RIGHT:
                width = decode_bits_width(resolve(node.results[0]))
                amount = node.attributes[0]
                mask = (1 << width) - 1
                value = int(operands[0]) & mask
                results = (((value >> amount) | (value << (width - amount) if amount else 0)) & mask,) if amount else (value,)
            elif node.operation in (Operation.FLOAT_ADD, Operation.FLOAT_SUB, Operation.FLOAT_MUL, Operation.FLOAT_DIV):
                width = decode_float_width(resolve(node.results[0]))
                left, right = float(operands[0]), float(operands[1])
                if node.operation == Operation.FLOAT_ADD:
                    value = left + right
                elif node.operation == Operation.FLOAT_SUB:
                    value = left - right
                elif node.operation == Operation.FLOAT_MUL:
                    value = left * right
                elif right == 0.0:
                    if left == 0.0 or math.isnan(left):
                        value = math.nan
                    else:
                        value = math.copysign(math.inf, left * right if right != 0.0 else left * math.copysign(1.0, right))
                else:
                    value = left / right
                results = (_round_float(value, width),)
            elif node.operation == Operation.FLOAT_COMPARE:
                left, right = float(operands[0]), float(operands[1])
                kind = FloatCompare(node.attributes[0])
                value = {
                    FloatCompare.EQ: left == right,
                    FloatCompare.NE: left != right,
                    FloatCompare.LT: left < right,
                    FloatCompare.LE: left <= right,
                    FloatCompare.GT: left > right,
                    FloatCompare.GE: left >= right,
                }[kind]
                results = (int(value),)
            elif node.operation in (Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT):
                width = decode_float_width(resolve(node.results[0]))
                value = int(operands[0])
                if node.operation == Operation.SINT_TO_FLOAT:
                    source_width = decode_bits_width(resolve(node.operand_types[0]))
                    if value >> (source_width - 1):
                        value -= 1 << source_width
                results = (_int_to_float(value, width),)
            elif node.operation == Operation.FLOAT_TO_UINT_TRUNC:
                width = decode_bits_width(resolve(node.results[0]))
                value = float(operands[0])
                if not math.isfinite(value) or value < 0 or value >= float(1 << width):
                    raise XaxTrap(b"float-conversion")
                results = (int(value),)
            elif node.operation == Operation.FLOAT_TO_SINT_TRUNC:
                width = decode_bits_width(resolve(node.results[0]))
                value = float(operands[0])
                if not math.isfinite(value) or not -(1 << (width - 1)) <= math.trunc(value) < 1 << (width - 1):
                    raise XaxTrap(b"float-conversion")
                results = (math.trunc(value) & ((1 << width) - 1),)
            elif node.operation == Operation.FLOAT_CONVERT:
                width = decode_float_width(resolve(node.results[0]))
                results = (_round_float(float(operands[0]), width),)
            elif node.operation == Operation.INT_COMPARE:
                width = decode_bits_width(resolve(node.operand_types[0]))
                left, right = int(operands[0]), int(operands[1])
                signed_left = left - (1 << width) if left & (1 << (width - 1)) else left
                signed_right = right - (1 << width) if right & (1 << (width - 1)) else right
                kind = IntCompare(node.attributes[0])
                value = {
                    IntCompare.EQ: left == right, IntCompare.NE: left != right,
                    IntCompare.ULT: left < right, IntCompare.ULE: left <= right,
                    IntCompare.UGT: left > right, IntCompare.UGE: left >= right,
                    IntCompare.SLT: signed_left < signed_right, IntCompare.SLE: signed_left <= signed_right,
                    IntCompare.SGT: signed_left > signed_right, IntCompare.SGE: signed_left >= signed_right,
                }[kind]
                results = (int(value),)
            elif node.operation == Operation.AGGREGATE_MAKE:
                results = (tuple(operands),)
            elif node.operation == Operation.AGGREGATE_GET:
                results = (operands[0][node.attributes[0]],)
            elif node.operation == Operation.SUM_MAKE:
                results = (_RuntimeSum(node.attributes[0], operands[0]),)
            elif node.operation == Operation.SUM_TAG:
                results = (operands[0].tag,)
            elif node.operation == Operation.SUM_GET:
                expected = node.attributes[0]
                value = operands[0]
                if not isinstance(value, _RuntimeSum) or value.tag != expected:
                    raise XaxTrap(b"sum-variant")
                results = (value.value,)
            elif node.operation == Operation.CONSTANT:
                _, value = _decode_constant(node.entity, resolve)
                results = (value,)
            elif node.operation == Operation.FUNCTION_ADDRESS:
                results = (_RuntimeFunctionPointer(node.entity),)
            elif node.operation == Operation.CALL_INDIRECT:
                target = operands[0]
                if not isinstance(target, _RuntimeFunctionPointer):
                    fail("XAX.EXEC.INDIRECT", graph_object.cid.hex(), "EXEC-INDIRECT-TARGET", "function pointer", type(target).__name__)
                results = _execute_function(target.function, operands[1:], resolve, fuel)
            elif node.operation == Operation.CALL_DIRECT:
                results = _execute_function(node.entity, operands, resolve, fuel)
            elif node.operation == Operation.CALL_GROUP_MEMBER and group_members is not None:
                results = _execute_group_member(owner, group_members, node.member, operands, resolve, fuel)
            elif node.operation == Operation.STACK_ALLOC:
                storage = _RuntimeStorage(bytearray(node.attributes[0]))
                results = (_RuntimePointer(storage, 0), _RuntimeOwner(storage), _RuntimeEffect(storage))
            elif node.operation == Operation.ADDRESS_OFFSET:
                pointer = operands[0]
                results = (_RuntimePointer(pointer.storage, pointer.offset + node.attributes[0]),)
            elif node.operation == Operation.POINTER_CAST:
                results = (operands[0],)
            elif node.operation in (Operation.POINTER_ADDRESS, Operation.POINTER_REBASE):
                # The reference executor has no address space; addresses are target facts.
                fail("XAX.EXEC.UNSUPPORTED", "executor", f"EXEC-{node.operation.name.replace('_', '-')}-TARGET-ONLY", "compiled target", "reference executor")
            elif node.operation == Operation.CHECKED_LOAD_BITS_LE:
                pointer, dynamic_offset, effect = operands
                size, alignment = node.attributes
                absolute = pointer.offset + dynamic_offset
                if dynamic_offset < 0 or dynamic_offset + size > len(pointer.storage.data) - pointer.offset or absolute % alignment:
                    raise XaxTrap(b"memory-check")
                element, _permission, _alignment = _decode_pointer_type(resolve(node.operand_types[0]), resolve)
                value = _runtime_scalar_from_bytes(bytes(pointer.storage.data[absolute : absolute + size]), resolve(element))
                results = (value, _RuntimeEffect(effect.storage))
            elif node.operation == Operation.CHECKED_STORE_BITS_LE:
                pointer, dynamic_offset, value, effect = operands
                size, alignment = node.attributes
                absolute = pointer.offset + dynamic_offset
                if dynamic_offset < 0 or dynamic_offset + size > len(pointer.storage.data) - pointer.offset or absolute % alignment:
                    raise XaxTrap(b"memory-check")
                element, _permission, _alignment = _decode_pointer_type(resolve(node.operand_types[0]), resolve)
                pointer.storage.data[absolute : absolute + size] = _runtime_scalar_bytes(value, resolve(element))
                results = (_RuntimeEffect(effect.storage),)
            elif node.operation == Operation.RAW_LOAD_BITS_LE:
                pointer, effect, unsafe_effect = operands
                size = node.attributes[0]
                element, _permission, _alignment = _decode_pointer_type(resolve(node.operand_types[0]), resolve)
                value = _runtime_scalar_from_bytes(bytes(pointer.storage.data[pointer.offset : pointer.offset + size]), resolve(element))
                results = (value, _RuntimeEffect(effect.storage), _RuntimeDomainEffect(unsafe_effect.domain, unsafe_effect.instance, unsafe_effect.generation + 1))
            elif node.operation == Operation.STORE_BITS_LE:
                pointer, value, effect = operands
                size = node.attributes[0]
                element, _permission, _alignment = _decode_pointer_type(resolve(node.operand_types[0]), resolve)
                pointer.storage.data[pointer.offset : pointer.offset + size] = _runtime_scalar_bytes(value, resolve(element))
                results = (_RuntimeEffect(effect.storage),)
            elif node.operation == Operation.LOAD_BITS_LE:
                pointer, effect = operands
                size = node.attributes[0]
                element, _permission, _alignment = _decode_pointer_type(resolve(node.operand_types[0]), resolve)
                value = _runtime_scalar_from_bytes(bytes(pointer.storage.data[pointer.offset : pointer.offset + size]), resolve(element))
                results = (value, _RuntimeEffect(effect.storage))
            elif node.operation == Operation.ATOMIC_LOAD:
                pointer, effect = operands
                size = (decode_bits_width(resolve(node.results[0])) + 7) // 8
                value = int.from_bytes(pointer.storage.data[pointer.offset : pointer.offset + size], "little")
                results = (value, _RuntimeEffect(effect.storage))
            elif node.operation == Operation.ATOMIC_STORE:
                pointer, value, effect = operands
                size = (decode_bits_width(resolve(node.operand_types[1])) + 7) // 8
                pointer.storage.data[pointer.offset : pointer.offset + size] = value.to_bytes(size, "little")
                results = (_RuntimeEffect(effect.storage),)
            elif node.operation == Operation.ATOMIC_RMW:
                pointer, operand, effect = operands
                width = decode_bits_width(resolve(node.results[0]))
                size = (width + 7) // 8
                old = int.from_bytes(pointer.storage.data[pointer.offset : pointer.offset + size], "little")
                kind = AtomicRmwKind(node.attributes[0])
                new = operand if kind == AtomicRmwKind.EXCHANGE else (old + operand) & ((1 << width) - 1)
                pointer.storage.data[pointer.offset : pointer.offset + size] = new.to_bytes(size, "little")
                results = (old, _RuntimeEffect(effect.storage))
            elif node.operation == Operation.ATOMIC_CMPXCHG:
                pointer, expected, desired, effect = operands
                width = decode_bits_width(resolve(node.results[0]))
                size = (width + 7) // 8
                old = int.from_bytes(pointer.storage.data[pointer.offset : pointer.offset + size], "little")
                success = old == expected
                if success:
                    pointer.storage.data[pointer.offset : pointer.offset + size] = desired.to_bytes(size, "little")
                results = (old, int(success), _RuntimeEffect(effect.storage))
            elif node.operation == Operation.ATOMIC_FENCE:
                effect = operands[0]
                if isinstance(effect, _RuntimeEffect):
                    results = (_RuntimeEffect(effect.storage),)
                elif isinstance(effect, _RuntimeDomainEffect):
                    results = (_RuntimeDomainEffect(effect.domain, effect.instance, effect.generation + 1),)
                else:
                    fail("XAX.EXEC.EFFECT", graph_object.cid.hex(), "EXEC-ATOMIC-FENCE-EFFECT", "effect frontier", type(effect).__name__)
            elif node.operation == Operation.STACK_END:
                owner_value, _ = operands
                owner_value.storage.live = False
                results = ()
            elif node.operation == Operation.EFFECT_STEP:
                results = tuple(
                    _RuntimeDomainEffect(effect.domain, effect.instance, effect.generation + 1)
                    for effect in operands
                )
            elif node.operation in RESOURCE_EFFECT_OPERATIONS:
                effect = operands[-1]
                if not isinstance(effect, _RuntimeDomainEffect):
                    fail("XAX.EXEC.EFFECT", graph_object.cid.hex(), "EXEC-EFFECT-TOKEN", "domain effect", type(effect).__name__)
                next_effect = _RuntimeDomainEffect(effect.domain, effect.instance, effect.generation + 1)
                if node.operation == Operation.RESOURCE_ACQUIRE:
                    resource = _decode_resource_type(resolve(node.results[0]))
                    results = (_RuntimeResource(resource.kind, resource.state, object()), next_effect)
                else:
                    resource_value = operands[0]
                    if not isinstance(resource_value, _RuntimeResource) or not resource_value.live:
                        fail("XAX.EXEC.RESOURCE", graph_object.cid.hex(), "EXEC-RESOURCE-LIVE", "live resource", type(resource_value).__name__)
                    if node.operation == Operation.RESOURCE_TRANSFER:
                        resource_value.live = False
                        results = (
                            _RuntimeResource(
                                resource_value.kind,
                                resource_value.state,
                                resource_value.identity,
                                split_identity=resource_value.split_identity,
                                split_part=resource_value.split_part,
                                parent_identity=resource_value.parent_identity,
                            ),
                            next_effect,
                        )
                    elif node.operation == Operation.RESOURCE_TRANSITION:
                        target = _decode_resource_type(resolve(node.results[0]))
                        resource_value.live = False
                        results = (
                            _RuntimeResource(
                                target.kind,
                                target.state,
                                resource_value.identity,
                                split_identity=resource_value.split_identity,
                                split_part=resource_value.split_part,
                                parent_identity=resource_value.parent_identity,
                            ),
                            next_effect,
                        )
                    elif node.operation in (Operation.RESOURCE_RELEASE, Operation.RESOURCE_DISCARD):
                        resource_value.live = False
                        results = (next_effect,)
                    elif node.operation == Operation.RESOURCE_SPLIT:
                        resource_value.live = False
                        split_identity = object()
                        results = (
                            _RuntimeResource(resource_value.kind, resource_value.state, object(), split_identity=split_identity, split_part=0, parent_identity=resource_value.identity),
                            _RuntimeResource(resource_value.kind, resource_value.state, object(), split_identity=split_identity, split_part=1, parent_identity=resource_value.identity),
                            next_effect,
                        )
                    else:
                        right = operands[1]
                        if (
                            not isinstance(right, _RuntimeResource)
                            or not right.live
                            or resource_value.split_identity is None
                            or resource_value.split_identity is not right.split_identity
                            or {resource_value.split_part, right.split_part} != {0, 1}
                        ):
                            fail("XAX.EXEC.RESOURCE_JOIN", graph_object.cid.hex(), "EXEC-RESOURCE-JOIN-SIBLINGS", "matching split pieces", "mismatch")
                        resource_value.live = right.live = False
                        results = (
                            _RuntimeResource(resource_value.kind, resource_value.state, resource_value.parent_identity),
                            next_effect,
                        )
            else:
                fail(
                    "XAX.EXEC.UNSUPPORTED_OPERATION",
                    graph_object.cid.hex(),
                    "EXEC-OP-SUPPORTED",
                    [Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.CONSTANT, Operation.CALL_DIRECT, Operation.CALL_GROUP_MEMBER],
                    node.operation,
                )
            for result_index, result in enumerate(results):
                values[(1, block_index, node_index, result_index)] = result

        term = block.terminator
        if term.kind == TerminatorKind.RETURN:
            results = tuple(read(value) for value in term.values)
            if len(results) != len(return_types):
                fail("XAX.EXEC.RETURN_COUNT", owner.cid.hex(), "EXEC-RETURN-COUNT", len(return_types), len(results))
            return results
        if term.kind == TerminatorKind.TRAP:
            raise XaxTrap(term.payload)
        edge = term.edges[0]
        if term.kind == TerminatorKind.CONDITIONAL_BRANCH:
            edge = term.edges[0 if read(term.values[0]) else 1]
        block_index, edge_arguments = edge
        block_arguments = tuple(read(value) for value in edge_arguments)


def diagnostic_json(error: XaxError) -> str:
    return json.dumps(asdict(error.diagnostic), separators=(",", ":"), sort_keys=True)


def trap_diagnostic_json(trap: XaxTrap) -> str:
    return json.dumps(
        {"trap": {"payload": trap.payload.hex(), "reason": trap.reason, "target_data": trap.target_data.hex()}},
        separators=(",", ":"),
        sort_keys=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="xaxc")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "inspect"):
        command = subcommands.add_parser(name)
        command.add_argument("store", type=Path)
    run = subcommands.add_parser("run")
    run.add_argument("store", type=Path)
    run.add_argument("function_cid")
    run.add_argument("arguments", nargs="*", type=lambda value: int(value, 0))
    run.add_argument("--fuel", type=int, default=100_000)
    args = parser.parse_args(argv)
    try:
        reader = StoreReader(args.store.read_bytes())
        verify_store(reader)
        if args.command == "run":
            function_cid = bytes.fromhex(args.function_cid)
            if len(function_cid) != CID_SIZE:
                raise ValueError("function CID must be 32 bytes")
            print(json.dumps({"results": execute(reader, function_cid, args.arguments, args.fuel)}, separators=(",", ":")))
        elif args.command == "inspect":
            print(
                json.dumps(
                    {
                        "root_cid": reader.root_cid.hex(),
                        "objects": [
                            {
                                "cid": obj.cid.hex(),
                                "kind": obj.kind.name.lower(),
                                "references": [cid.hex() for cid in obj.references],
                            }
                            for obj in reader.objects()
                        ],
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        return 0
    except XaxTrap as trap:
        print(trap_diagnostic_json(trap))
        return 2
    except (OSError, XaxError, ValueError) as error:
        if isinstance(error, XaxError):
            print(diagnostic_json(error))
        else:
            print(json.dumps({"code": "XAX.INPUT", "actual": str(error)}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

