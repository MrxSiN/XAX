"""OI-22 hash-agility and migration experiment.

Suite 1 remains the authoritative XAX v0.1 BLAKE3-256 identity.  SHA-256 is
used only as a readily available 256-bit test suite.  The two migration forms
here are tooling-only and versioned independently from canonical store v1:

* XHA2: secondary suite-2 addresses for immutable suite-1 canonical objects.
* XHF2: full experimental re-addressing whose object and child identities use
  suite 2.  Source CIDs are retained only as migration provenance/rollback
  mapping; they are not child references.

No digest is interpreted without an explicit/derived suite identifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from blake3 import blake3
from xax_compiler import (
    CID_SIZE,
    SEMANTIC_DOMAIN,
    Cursor,
    Kind,
    ProofCache,
    SemanticObject,
    StoreReader,
    encode_references,
    uleb,
    verify_store,
    write_store,
)
from xax_build import package
from benchmarks.bench_oi21_dependency_index import build_project

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "oi22_hash_migration_evidence.json"
RAW = HERE / "oi22_hash_migration_timing.json"

SUITE_BLAKE3_256 = 1
SUITE_TEST_SHA256 = 2
SUPPORTED_SUITES = (SUITE_BLAKE3_256, SUITE_TEST_SHA256)
ALIAS_MAGIC = b"XHA2"
ALIAS_VERSION = 1
FULL_MAGIC = b"XHF2"
FULL_VERSION = 1
FILE_TRAILER_BYTES = 32
FULL_DOMAIN = b"XAX-OI22-FULL-1\0"


class MigrationRejected(ValueError):
    pass


@dataclass(frozen=True, order=True)
class HashIdentity:
    suite_id: int
    digest: bytes

    def __post_init__(self) -> None:
        if self.suite_id not in SUPPORTED_SUITES:
            raise MigrationRejected("oi22.identity.unknown_suite")
        if len(self.digest) != CID_SIZE:
            raise MigrationRejected("oi22.identity.digest_size")

    def encode(self) -> bytes:
        return uleb(self.suite_id) + self.digest


@dataclass(frozen=True)
class AliasEntry:
    source_cid: bytes
    alias_digest: bytes


@dataclass(frozen=True)
class AliasIndex:
    source_root: bytes
    alias_root: bytes
    source_store_fingerprint: bytes
    entries: tuple[AliasEntry, ...]

    def by_source(self) -> dict[bytes, bytes]:
        return {entry.source_cid: entry.alias_digest for entry in self.entries}

    def by_alias(self) -> dict[bytes, bytes]:
        return {entry.alias_digest: entry.source_cid for entry in self.entries}


@dataclass(frozen=True)
class FullRecord:
    source_cid: bytes
    target_digest: bytes
    kind: Kind
    schema_version: int
    target_references: tuple[bytes, ...]
    body: bytes


@dataclass(frozen=True)
class FullMigration:
    source_root: bytes
    target_root: bytes
    source_store_fingerprint: bytes
    records: tuple[FullRecord, ...]

    def by_source(self) -> dict[bytes, FullRecord]:
        return {record.source_cid: record for record in self.records}

    def by_target(self) -> dict[bytes, FullRecord]:
        return {record.target_digest: record for record in self.records}


HashFn = Callable[[bytes], bytes]


def _suite_hash(suite_id: int, payload: bytes) -> bytes:
    if suite_id == SUITE_BLAKE3_256:
        return blake3(payload).digest()
    if suite_id == SUITE_TEST_SHA256:
        return hashlib.sha256(payload).digest()
    raise MigrationRejected("oi22.identity.unknown_suite")


def _canonical_cid_input(obj: SemanticObject) -> bytes:
    return (
        SEMANTIC_DOMAIN
        + uleb(obj.kind)
        + uleb(obj.schema_version)
        + encode_references(obj.references)
        + uleb(len(obj.body))
        + obj.body
    )


def _full_cid_input(obj: SemanticObject, target_references: tuple[bytes, ...]) -> bytes:
    # Reference order intentionally preserves the source canonical reference
    # ordinal because semantic bodies contain those ordinals.  XHF2 is a
    # migration carrier, not canonical XAX store v1.
    return (
        FULL_DOMAIN
        + uleb(obj.kind)
        + uleb(obj.schema_version)
        + uleb(len(target_references))
        + b"".join(target_references)
        + uleb(len(obj.body))
        + obj.body
    )


def _default_test_hash(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def _store_fingerprint(store_bytes: bytes) -> bytes:
    return blake3(b"XAX-OI22-SOURCE\0" + store_bytes).digest()


def build_alias_index(reader: StoreReader, *, test_hash: HashFn = _default_test_hash) -> AliasIndex:
    entries: list[AliasEntry] = []
    aliases: dict[bytes, bytes] = {}
    for obj in reader.objects():
        alias = test_hash(_canonical_cid_input(obj))
        if len(alias) != CID_SIZE:
            raise MigrationRejected("oi22.alias.digest_size")
        previous = aliases.get(alias)
        if previous is not None and previous != obj.cid:
            raise MigrationRejected("oi22.alias.collision")
        aliases[alias] = obj.cid
        entries.append(AliasEntry(obj.cid, alias))
    entries.sort(key=lambda entry: entry.source_cid)
    by_source = {entry.source_cid: entry.alias_digest for entry in entries}
    if reader.root_cid not in by_source:
        raise MigrationRejected("oi22.alias.root_missing")
    return AliasIndex(
        reader.root_cid,
        by_source[reader.root_cid],
        _store_fingerprint(reader.data),
        tuple(entries),
    )


def encode_alias_index(index: AliasIndex) -> bytes:
    if len(index.source_root) != CID_SIZE or len(index.alias_root) != CID_SIZE:
        raise ValueError("root digest size")
    if len(index.source_store_fingerprint) != CID_SIZE:
        raise ValueError("store fingerprint size")
    out = bytearray(ALIAS_MAGIC + uleb(ALIAS_VERSION) + uleb(1) + uleb(2))
    out.extend(index.source_root + index.alias_root + index.source_store_fingerprint)
    out.extend(uleb(len(index.entries)))
    previous = b""
    aliases: set[bytes] = set()
    for entry in index.entries:
        if len(entry.source_cid) != CID_SIZE or len(entry.alias_digest) != CID_SIZE:
            raise ValueError("entry digest size")
        if previous and entry.source_cid <= previous:
            raise ValueError("source CIDs must be sorted unique")
        if entry.alias_digest in aliases:
            raise MigrationRejected("oi22.alias.collision")
        previous = entry.source_cid
        aliases.add(entry.alias_digest)
        out.extend(entry.source_cid + entry.alias_digest)
    if dict((e.source_cid, e.alias_digest) for e in index.entries).get(index.source_root) != index.alias_root:
        raise MigrationRejected("oi22.alias.root_mapping")
    out.extend(blake3(out).digest())
    return bytes(out)


def _take(cursor: Cursor, size: int, rule: str) -> bytes:
    try:
        return cursor.take(size, rule)
    except Exception as exc:
        raise MigrationRejected(rule) from exc


def _take_u(cursor: Cursor, rule: str) -> int:
    try:
        return cursor.uleb()
    except Exception as exc:
        raise MigrationRejected(rule) from exc


def decode_alias_index(data: bytes, *, expected_store: bytes | None = None) -> AliasIndex:
    if len(data) < 4 + FILE_TRAILER_BYTES:
        raise MigrationRejected("oi22.alias.short")
    payload, stored = data[:-32], data[-32:]
    if blake3(payload).digest() != stored:
        raise MigrationRejected("oi22.alias.integrity")
    cursor = Cursor(payload, "oi22-alias")
    if _take(cursor, 4, "oi22.alias.magic") != ALIAS_MAGIC:
        raise MigrationRejected("oi22.alias.magic")
    if _take_u(cursor, "oi22.alias.version") != ALIAS_VERSION:
        raise MigrationRejected("oi22.alias.version")
    source_suite = _take_u(cursor, "oi22.alias.source_suite")
    target_suite = _take_u(cursor, "oi22.alias.target_suite")
    if source_suite != 1 or target_suite != 2:
        if source_suite not in SUPPORTED_SUITES or target_suite not in SUPPORTED_SUITES:
            raise MigrationRejected("oi22.identity.unknown_suite")
        raise MigrationRejected("oi22.alias.suite_pair")
    source_root = _take(cursor, 32, "oi22.alias.source_root")
    alias_root = _take(cursor, 32, "oi22.alias.alias_root")
    fingerprint = _take(cursor, 32, "oi22.alias.source_fingerprint")
    count = _take_u(cursor, "oi22.alias.count")
    entries: list[AliasEntry] = []
    previous = b""
    aliases: set[bytes] = set()
    for _ in range(count):
        source = _take(cursor, 32, "oi22.alias.source")
        alias = _take(cursor, 32, "oi22.alias.target")
        if previous and source <= previous:
            raise MigrationRejected("oi22.alias.order")
        if alias in aliases:
            raise MigrationRejected("oi22.alias.collision")
        previous = source
        aliases.add(alias)
        entries.append(AliasEntry(source, alias))
    try:
        cursor.end("oi22.alias.trailing")
    except Exception as exc:
        raise MigrationRejected("oi22.alias.trailing") from exc
    index = AliasIndex(source_root, alias_root, fingerprint, tuple(entries))
    if index.by_source().get(source_root) != alias_root:
        raise MigrationRejected("oi22.alias.root_mapping")
    if expected_store is not None and fingerprint != _store_fingerprint(expected_store):
        raise MigrationRejected("oi22.alias.stale_source")
    return index


def build_full_migration(reader: StoreReader, *, test_hash: HashFn = _default_test_hash) -> FullMigration:
    memo: dict[bytes, FullRecord] = {}
    target_to_source: dict[bytes, bytes] = {}
    active: set[bytes] = set()

    def visit(source_cid: bytes) -> FullRecord:
        cached = memo.get(source_cid)
        if cached is not None:
            return cached
        if source_cid in active:
            raise MigrationRejected("oi22.full.source_cycle")
        active.add(source_cid)
        obj = reader.get(source_cid)
        target_refs = tuple(visit(ref).target_digest for ref in obj.references)
        digest = test_hash(_full_cid_input(obj, target_refs))
        if len(digest) != CID_SIZE:
            raise MigrationRejected("oi22.full.digest_size")
        prior = target_to_source.get(digest)
        if prior is not None and prior != source_cid:
            raise MigrationRejected("oi22.full.collision")
        target_to_source[digest] = source_cid
        record = FullRecord(source_cid, digest, obj.kind, obj.schema_version, target_refs, obj.body)
        memo[source_cid] = record
        active.remove(source_cid)
        return record

    root = visit(reader.root_cid)
    # A canonical verified XAX store is rooted, but visit all records explicitly
    # so the migration fails rather than silently dropping any unexpected object.
    for cid in reader.object_cids:
        visit(cid)
    records = tuple(sorted(memo.values(), key=lambda record: record.target_digest))
    return FullMigration(reader.root_cid, root.target_digest, _store_fingerprint(reader.data), records)


def encode_full_migration(migration: FullMigration) -> bytes:
    out = bytearray(FULL_MAGIC + uleb(FULL_VERSION) + uleb(1) + uleb(2))
    out.extend(migration.source_root + migration.target_root + migration.source_store_fingerprint)
    out.extend(uleb(len(migration.records)))
    previous = b""
    sources: set[bytes] = set()
    targets: set[bytes] = set()
    for record in migration.records:
        if previous and record.target_digest <= previous:
            raise ValueError("target digests must be sorted unique")
        previous = record.target_digest
        if record.source_cid in sources or record.target_digest in targets:
            raise MigrationRejected("oi22.full.duplicate_identity")
        sources.add(record.source_cid)
        targets.add(record.target_digest)
        out.extend(record.target_digest + record.source_cid)
        out.extend(uleb(record.kind) + uleb(record.schema_version))
        out.extend(uleb(len(record.target_references)) + b"".join(record.target_references))
        out.extend(uleb(len(record.body)) + record.body)
    by_source = migration.by_source()
    if by_source.get(migration.source_root) is None or by_source[migration.source_root].target_digest != migration.target_root:
        raise MigrationRejected("oi22.full.root_mapping")
    out.extend(blake3(out).digest())
    return bytes(out)


def decode_full_migration(
    data: bytes,
    *,
    source_reader: StoreReader | None = None,
) -> FullMigration:
    if len(data) < 4 + FILE_TRAILER_BYTES:
        raise MigrationRejected("oi22.full.short")
    payload, stored = data[:-32], data[-32:]
    if blake3(payload).digest() != stored:
        raise MigrationRejected("oi22.full.integrity")
    cursor = Cursor(payload, "oi22-full")
    if _take(cursor, 4, "oi22.full.magic") != FULL_MAGIC:
        raise MigrationRejected("oi22.full.magic")
    if _take_u(cursor, "oi22.full.version") != FULL_VERSION:
        raise MigrationRejected("oi22.full.version")
    source_suite = _take_u(cursor, "oi22.full.source_suite")
    target_suite = _take_u(cursor, "oi22.full.target_suite")
    if source_suite != 1 or target_suite != 2:
        if source_suite not in SUPPORTED_SUITES or target_suite not in SUPPORTED_SUITES:
            raise MigrationRejected("oi22.identity.unknown_suite")
        raise MigrationRejected("oi22.full.suite_pair")
    source_root = _take(cursor, 32, "oi22.full.source_root")
    target_root = _take(cursor, 32, "oi22.full.target_root")
    fingerprint = _take(cursor, 32, "oi22.full.source_fingerprint")
    count = _take_u(cursor, "oi22.full.count")
    records: list[FullRecord] = []
    previous = b""
    sources: set[bytes] = set()
    targets: set[bytes] = set()
    for _ in range(count):
        target = _take(cursor, 32, "oi22.full.target")
        source = _take(cursor, 32, "oi22.full.source")
        if previous and target <= previous:
            raise MigrationRejected("oi22.full.order")
        if target in targets or source in sources:
            raise MigrationRejected("oi22.full.duplicate_identity")
        previous = target
        targets.add(target)
        sources.add(source)
        kind_raw = _take_u(cursor, "oi22.full.kind")
        try:
            kind = Kind(kind_raw)
        except ValueError as exc:
            raise MigrationRejected("oi22.full.kind") from exc
        schema = _take_u(cursor, "oi22.full.schema")
        refs = tuple(_take(cursor, 32, "oi22.full.reference") for _ in range(_take_u(cursor, "oi22.full.ref_count")))
        body = _take(cursor, _take_u(cursor, "oi22.full.body_length"), "oi22.full.body")
        records.append(FullRecord(source, target, kind, schema, refs, body))
    try:
        cursor.end("oi22.full.trailing")
    except Exception as exc:
        raise MigrationRejected("oi22.full.trailing") from exc
    migration = FullMigration(source_root, target_root, fingerprint, tuple(records))
    by_source, by_target = migration.by_source(), migration.by_target()
    root = by_source.get(source_root)
    if root is None or root.target_digest != target_root:
        raise MigrationRejected("oi22.full.root_mapping")
    for record in records:
        expected = _default_test_hash(_full_cid_input(
            SemanticObject(record.kind, record.schema_version, (), record.body, b"\0" * 32),
            record.target_references,
        ))
        if expected != record.target_digest:
            raise MigrationRejected("oi22.full.cid_mismatch")
        if any(ref not in by_target for ref in record.target_references):
            raise MigrationRejected("oi22.full.missing_reference")
    if source_reader is not None:
        if fingerprint != _store_fingerprint(source_reader.data):
            raise MigrationRejected("oi22.full.stale_source")
        for record in records:
            source = source_reader.get(record.source_cid)
            if source.kind != record.kind or source.schema_version != record.schema_version or source.body != record.body:
                raise MigrationRejected("oi22.full.semantic_mismatch")
            if len(source.references) != len(record.target_references):
                raise MigrationRejected("oi22.full.semantic_mismatch")
            for source_ref, target_ref in zip(source.references, record.target_references):
                child = by_source.get(source_ref)
                if child is None or child.target_digest != target_ref:
                    raise MigrationRejected("oi22.full.semantic_mismatch")
    return migration


class DualRepository:
    """Transitional tooling view.  Persistent identities are always typed."""

    def __init__(self, source: StoreReader, *, alias: AliasIndex | None = None, full: FullMigration | None = None):
        self.source = source
        self.alias = alias
        self.full = full
        if alias is not None and alias.source_store_fingerprint != _store_fingerprint(source.data):
            raise MigrationRejected("oi22.repository.stale_alias")
        if full is not None and full.source_store_fingerprint != _store_fingerprint(source.data):
            raise MigrationRejected("oi22.repository.stale_full")
        # Derived lookup tables are built once when the repository view opens;
        # per-lookup O(N) map reconstruction would hide the actual identity cost.
        self._alias_to_source = {} if alias is None else alias.by_alias()
        self._target_to_record = {} if full is None else full.by_target()

    def source_cid(self, identity: HashIdentity) -> bytes:
        if identity.suite_id == 1:
            self.source.get(identity.digest)
            return identity.digest
        if identity.suite_id == 2:
            candidates: list[bytes] = []
            source = self._alias_to_source.get(identity.digest)
            if source is not None:
                candidates.append(source)
            record = self._target_to_record.get(identity.digest)
            if record is not None:
                candidates.append(record.source_cid)
            if not candidates:
                raise MigrationRejected("oi22.repository.object_missing")
            if len(set(candidates)) != 1:
                raise MigrationRejected("oi22.repository.ambiguous_secondary")
            return candidates[0]
        raise MigrationRejected("oi22.identity.unknown_suite")

    def get_semantic(self, identity: HashIdentity) -> SemanticObject:
        return self.source.get(self.source_cid(identity))


def equivalent_semantics(repo: DualRepository, left: HashIdentity, right: HashIdentity) -> bool:
    a, b = repo.get_semantic(left), repo.get_semantic(right)
    return (a.kind, a.schema_version, a.references, a.body) == (b.kind, b.schema_version, b.references, b.body)


def save_atomic(path: Path, data: bytes, *, interrupt_before_replace: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if interrupt_before_replace:
            raise InterruptedError("simulated migration interruption")
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def rollback(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _proof_cache_reuse(reader: StoreReader, alias: AliasIndex, full: FullMigration) -> dict:
    cache = ProofCache()
    stats = verify_store(StoreReader(reader.data), proof_cache=cache)
    alias_repo = DualRepository(reader, alias=alias)
    alias_hits = 0
    for entry in alias.entries:
        obj = alias_repo.get_semantic(HashIdentity(2, entry.alias_digest))
        alias_hits += int(cache.contains("bootstrap-schema-1", obj))
    suite1_subjects = set(reader.object_cids)
    full_direct_hits = sum(record.target_digest in suite1_subjects for record in full.records)
    return {
        "suite1_cache_entries": cache.entry_count,
        "suite1_verify_cache_misses": stats.cache_misses,
        "alias_direct_reuse_entries": alias_hits,
        "alias_direct_reuse_percent": 100.0 * alias_hits / max(1, cache.entry_count),
        "full_direct_reuse_entries": full_direct_hits,
        "full_direct_reuse_percent": 100.0 * full_direct_hits / max(1, cache.entry_count),
        "full_reuse_requires_explicit_equivalence_map": True,
    }


def _lookup_sample(reader: StoreReader) -> tuple[bytes, ...]:
    cids = reader.object_cids
    if len(cids) <= 64:
        return cids
    return tuple(cids[(i * (len(cids) - 1)) // 63] for i in range(64))


def build_migration_repository() -> StoreReader:
    """Nontrivial package-rooted repository built from the OI-21 service DAG."""
    project = build_project("service_generated")
    base_objects = tuple(obj for obj in project.reader.objects() if obj.kind != Kind.PROGRAM_ROOT)
    modules = tuple(obj for obj in base_objects if obj.kind == Kind.MODULE)
    package_obj = package(b"oi22-service-package", modules)
    data = write_store(package_obj.cid, (*base_objects, package_obj))
    reader = StoreReader(data)
    verify_store(reader)
    return reader


def deterministic_evidence(raw: dict | None) -> dict:
    reader = build_migration_repository()
    suite1_root_before = reader.root_cid
    store_before = reader.data
    alias = build_alias_index(reader)
    full = build_full_migration(reader)
    alias_bytes = encode_alias_index(alias)
    full_bytes = encode_full_migration(full)
    decode_alias_index(alias_bytes, expected_store=store_before)
    decode_full_migration(full_bytes, source_reader=reader)
    alias_repo = DualRepository(reader, alias=alias)
    full_repo = DualRepository(reader, full=full)
    root_s1 = HashIdentity(1, reader.root_cid)
    root_alias = HashIdentity(2, alias.alias_root)
    root_full = HashIdentity(2, full.target_root)
    if not equivalent_semantics(alias_repo, root_s1, root_alias):
        raise AssertionError("alias root semantics differ")
    if not equivalent_semantics(full_repo, root_s1, root_full):
        raise AssertionError("full root semantics differ")
    if reader.root_cid != suite1_root_before or reader.data != store_before:
        raise AssertionError("suite-1 store changed during migration")
    proof = _proof_cache_reuse(reader, alias, full)
    kinds: dict[str, int] = {}
    for obj in reader.objects():
        kinds[obj.kind.name.lower()] = kinds.get(obj.kind.name.lower(), 0) + 1
    aliases_by_source = alias.by_source()
    full_by_source = full.by_source()
    same_raw_cross_suite = sum(1 for cid, digest in aliases_by_source.items() if cid == digest)
    if same_raw_cross_suite:
        # Even if this ever occurs, equality is still suite-qualified.  Record it
        # rather than treating raw digest equality as semantic authority.
        raw_note = "raw digest collision across suite domains observed; suite tag still disambiguates"
    else:
        raw_note = "no equal raw digests observed; equality would still require suite + decoded semantics"
    result = {
        "schema": "xax-oi22-hash-migration-evidence-v1",
        "status": "closed",
        "suite_policy": {
            "suite_1": "BLAKE3-256 permanent for XAX v0.1",
            "suite_2_test_only": "SHA-256",
            "suite_2_recommended": False,
            "persistent_identity": "(suite_id,digest)",
            "suite_inference_from_digest": False,
            "cross_suite_equivalence": "equality of decoded canonical semantics",
            "raw_digest_note": raw_note,
            "collision_policy": "same suite digest for unequal source semantics rejects migration",
        },
        "project": {
            "name": "service_generated_package",
            "suite1_root": reader.root_cid.hex(),
            "store_bytes": len(store_before),
            "objects": len(reader.object_cids),
            "object_kinds": dict(sorted(kinds.items())),
        },
        "alias_strategy": {
            "format": "XHA2/v1",
            "suite2_root": alias.alias_root.hex(),
            "index_bytes": len(alias_bytes),
            "index_entries": len(alias.entries),
            "semantic_envelopes_rewritten": 0,
            "source_store_bytes_rewritten": 0,
            "repository_extra_bytes": len(alias_bytes),
            "suite1_root_unchanged": reader.root_cid == suite1_root_before,
            "root_semantics_equal": True,
            "lookup_accepts_suites": [1, 2],
        },
        "full_readdress_strategy": {
            "format": "XHF2/v1",
            "suite2_root": full.target_root.hex(),
            "container_bytes": len(full_bytes),
            "records": len(full.records),
            "semantic_envelopes_rewritten": len(full.records),
            "child_references_using_suite2": sum(len(record.target_references) for record in full.records),
            "repository_extra_bytes_while_rollback_retained": len(full_bytes),
            "suite1_root_unchanged_while_staged": reader.root_cid == suite1_root_before,
            "root_semantics_equal": True,
            "lookup_accepts_suites": [1, 2],
        },
        "cache_behavior": proof,
        "migration_rules": {
            "unknown_suite": "reject",
            "mixed_reference_in_XHF2": "not representable; header declares suite 2 for every child reference",
            "stale_source_fingerprint": "reject",
            "corrupt_integrity": "reject",
            "interruption": "atomic replace leaves authoritative suite-1 store unchanged; restart recomputes deterministic artifact",
            "rollback": "delete migration artifact; suite-1 repository remains authoritative",
        },
        "security_analysis": {
            "algorithm_transition_explicit": True,
            "suite1_reinterpretation_possible": False,
            "unknown_suite_rejected": True,
            "forced_collision_detection": True,
            "test_algorithm_is_not_recommendation": True,
            "cryptographic_strength_claim": "none beyond exercising a distinct 256-bit suite",
        },
        "raw_timing_present": raw is not None,
    }
    if raw is not None:
        result["measurements"] = summarize_raw(raw)
    return result


def _median_spread(samples: list[float]) -> dict:
    ordered = sorted(samples)
    return {
        "median": statistics.median(ordered),
        "min": ordered[0],
        "max": ordered[-1],
    }


def summarize_raw(raw: dict) -> dict:
    out = {
        "host": raw["host"],
        "samples_per_cell": raw["samples_per_cell"],
        "migration_ms": {name: _median_spread(values) for name, values in raw["migration_ms"].items()},
        "decode_ms": {name: _median_spread(values) for name, values in raw["decode_ms"].items()},
        "lookup_us_per_object": {name: _median_spread(values) for name, values in raw["lookup_us_per_object"].items()},
        "hash_mib_per_s": {name: _median_spread(values) for name, values in raw["hash_mib_per_s"].items()},
    }
    return out


def measure(repeats: int = 11) -> dict:
    reader = build_migration_repository()
    samples = _lookup_sample(reader)
    alias = build_alias_index(reader)
    full = build_full_migration(reader)
    alias_bytes = encode_alias_index(alias)
    full_bytes = encode_full_migration(full)
    alias_by_source = alias.by_source()
    full_by_source = full.by_source()
    migration = {"alias": [], "full_readdress": []}
    decode = {"alias": [], "full_readdress": []}
    lookup = {"suite1": [], "alias_suite2": [], "full_suite2": []}
    hashing = {"blake3_suite1": [], "sha256_test_suite2": []}
    payload = b"".join(_canonical_cid_input(reader.get(cid)) for cid in reader.object_cids)
    mib = len(payload) / (1024 * 1024)
    for _ in range(repeats):
        start = time.perf_counter_ns(); build_alias_index(reader); migration["alias"].append((time.perf_counter_ns() - start) / 1e6)
        start = time.perf_counter_ns(); build_full_migration(reader); migration["full_readdress"].append((time.perf_counter_ns() - start) / 1e6)
        start = time.perf_counter_ns(); decode_alias_index(alias_bytes, expected_store=reader.data); decode["alias"].append((time.perf_counter_ns() - start) / 1e6)
        start = time.perf_counter_ns(); decode_full_migration(full_bytes, source_reader=reader); decode["full_readdress"].append((time.perf_counter_ns() - start) / 1e6)
        start = time.perf_counter_ns()
        for cid in samples:
            reader.get(cid)
        lookup["suite1"].append((time.perf_counter_ns() - start) / 1e3 / len(samples))
        alias_repo = DualRepository(reader, alias=alias)
        start = time.perf_counter_ns()
        for cid in samples:
            alias_repo.get_semantic(HashIdentity(2, alias_by_source[cid]))
        lookup["alias_suite2"].append((time.perf_counter_ns() - start) / 1e3 / len(samples))
        full_repo = DualRepository(reader, full=full)
        start = time.perf_counter_ns()
        for cid in samples:
            full_repo.get_semantic(HashIdentity(2, full_by_source[cid].target_digest))
        lookup["full_suite2"].append((time.perf_counter_ns() - start) / 1e3 / len(samples))
        for name, fn in (("blake3_suite1", lambda: blake3(payload).digest()), ("sha256_test_suite2", lambda: hashlib.sha256(payload).digest())):
            start = time.perf_counter_ns(); fn(); seconds = (time.perf_counter_ns() - start) / 1e9
            hashing[name].append(mib / seconds if seconds else 0.0)
    return {
        "schema": "xax-oi22-hash-migration-raw-v1",
        "host": {
            "platform": os.uname().sysname + " " + os.uname().machine,
            "python": os.sys.version.split()[0],
        },
        "samples_per_cell": repeats,
        "hashed_payload_bytes": len(payload),
        "migration_ms": migration,
        "decode_ms": decode,
        "lookup_us_per_object": lookup,
        "hash_mib_per_s": hashing,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--repeats", type=int, default=11)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    raw = measure(args.repeats) if args.measure else (json.loads(RAW.read_text()) if RAW.exists() else None)
    evidence = deterministic_evidence(raw)
    if args.write:
        if raw is not None and args.measure:
            RAW.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
        EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
