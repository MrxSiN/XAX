"""OI-21 durable semantic-dependency index and process-pool experiment.

The index is tooling-only derived state.  It stores exact canonical object
references and their reverse edges under one semantic root plus explicit
verifier/compiler identities.  Deleting or rebuilding it cannot change XAX
semantic state.  The file format is append-free and written by atomic replace.

The process-pool experiment compiles independent verified XAX functions.  Pool
startup and argument serialization are included in the measured wall time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import statistics
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from xax_artifact import BOOTSTRAP_COMPILER_IDENTITY_V1
from xax_compiler import (
    DEFAULT_VERIFIER_IDENTITY,
    Block,
    Cursor,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    store_resolver,
    uleb,
    verify_store,
    write_store,
    x86_64_windows_general_target,
)
from xax_x86_64 import compile_native

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "oi21_dependency_index_evidence.json"
RAW = HERE / "oi21_dependency_index_timing.json"
INDEX_MAGIC = b"XDI1"
INDEX_VERSION = 1
DIGEST_SIZE = 32


class IndexRejected(ValueError):
    pass


@dataclass(frozen=True)
class IndexEntry:
    cid: bytes
    dependency_fingerprint: bytes
    dependencies: tuple[bytes, ...]
    users: tuple[bytes, ...]


@dataclass(frozen=True)
class DependencyIndex:
    root_cid: bytes
    verifier_identity: str
    compiler_identity: bytes
    entries: tuple[IndexEntry, ...]

    def by_cid(self) -> dict[bytes, IndexEntry]:
        return {entry.cid: entry for entry in self.entries}

    @property
    def edge_count(self) -> int:
        return sum(len(entry.dependencies) for entry in self.entries)


@dataclass(frozen=True)
class Project:
    name: str
    reader: StoreReader
    store_bytes: bytes
    root: SemanticObject
    objects: tuple[SemanticObject, ...]
    functions: dict[tuple[int, int], SemanticObject]
    graphs: dict[tuple[int, int], SemanticObject]
    leaf: tuple[int, int]
    leaf_arity: int


def _take_u(cursor: Cursor, rule: str) -> int:
    try:
        return cursor.uleb()
    except Exception as error:
        raise IndexRejected(rule) from error


def _take(cursor: Cursor, size: int, rule: str) -> bytes:
    try:
        return cursor.take(size)
    except Exception as error:
        raise IndexRejected(rule) from error


def _fingerprint(cid: bytes, dependencies: Iterable[bytes]) -> bytes:
    h = hashlib.sha256(b"XAX-OI21-DEPS-v1\0" + cid)
    for dependency in dependencies:
        h.update(dependency)
    return h.digest()


def build_index(
    reader: StoreReader,
    verifier_identity: str = DEFAULT_VERIFIER_IDENTITY,
    compiler_identity: bytes = BOOTSTRAP_COMPILER_IDENTITY_V1,
) -> DependencyIndex:
    if not verifier_identity or not compiler_identity:
        raise ValueError("dependency identities must be nonempty")
    objects = tuple(reader.objects())
    dependencies = {obj.cid: tuple(obj.references) for obj in objects}
    users: dict[bytes, list[bytes]] = {obj.cid: [] for obj in objects}
    for cid, refs in dependencies.items():
        for ref in refs:
            if ref not in users:
                raise IndexRejected("oi21.index.missing_dependency")
            users[ref].append(cid)
    entries = tuple(
        IndexEntry(cid, _fingerprint(cid, dependencies[cid]), dependencies[cid], tuple(sorted(users[cid])))
        for cid in sorted(dependencies)
    )
    return DependencyIndex(reader.root_cid, verifier_identity, compiler_identity, entries)


def encode_index(index: DependencyIndex) -> bytes:
    verifier = index.verifier_identity.encode("utf-8")
    payload = bytearray(INDEX_MAGIC + uleb(INDEX_VERSION) + index.root_cid)
    payload.extend(uleb(len(verifier)) + verifier)
    payload.extend(uleb(len(index.compiler_identity)) + index.compiler_identity)
    payload.extend(uleb(len(index.entries)))
    cid_to_index = {entry.cid: ordinal for ordinal, entry in enumerate(index.entries)}
    if len(cid_to_index) != len(index.entries):
        raise ValueError("duplicate index entry CID")
    previous = b""
    for entry in index.entries:
        if previous and entry.cid <= previous:
            raise ValueError("index entries must be sorted unique")
        previous = entry.cid
        if tuple(sorted(set(entry.dependencies))) != entry.dependencies:
            raise ValueError("dependencies must be sorted unique")
        if tuple(sorted(set(entry.users))) != entry.users:
            raise ValueError("users must be sorted unique")
        try:
            dep_ordinals = tuple(cid_to_index[cid] for cid in entry.dependencies)
            user_ordinals = tuple(cid_to_index[cid] for cid in entry.users)
        except KeyError as error:
            raise ValueError("index edge points outside index") from error
        payload.extend(entry.cid)
        payload.extend(entry.dependency_fingerprint)
        payload.extend(uleb(len(dep_ordinals)))
        payload.extend(b"".join(uleb(ordinal) for ordinal in dep_ordinals))
        payload.extend(uleb(len(user_ordinals)))
        payload.extend(b"".join(uleb(ordinal) for ordinal in user_ordinals))
    payload.extend(hashlib.sha256(payload).digest())
    return bytes(payload)


def decode_index(
    data: bytes,
    *,
    expected_root: bytes | None = None,
    verifier_identity: str | None = None,
    compiler_identity: bytes | None = None,
) -> DependencyIndex:
    if len(data) < len(INDEX_MAGIC) + DIGEST_SIZE or hashlib.sha256(data[:-DIGEST_SIZE]).digest() != data[-DIGEST_SIZE:]:
        raise IndexRejected("oi21.index.digest")
    cursor = Cursor(data[:-DIGEST_SIZE], "oi21-index")
    if _take(cursor, 4, "oi21.index.magic") != INDEX_MAGIC:
        raise IndexRejected("oi21.index.magic")
    if _take_u(cursor, "oi21.index.version") != INDEX_VERSION:
        raise IndexRejected("oi21.index.version")
    root = _take(cursor, 32, "oi21.index.root")
    verifier_len = _take_u(cursor, "oi21.index.verifier")
    try:
        verifier = _take(cursor, verifier_len, "oi21.index.verifier").decode("utf-8")
    except UnicodeDecodeError as error:
        raise IndexRejected("oi21.index.verifier") from error
    compiler_len = _take_u(cursor, "oi21.index.compiler")
    compiler = _take(cursor, compiler_len, "oi21.index.compiler")
    count = _take_u(cursor, "oi21.index.count")
    raw: list[tuple[bytes, bytes, tuple[int, ...], tuple[int, ...]]] = []
    previous = b""
    for _ in range(count):
        cid = _take(cursor, 32, "oi21.index.cid")
        if previous and cid <= previous:
            raise IndexRejected("oi21.index.order")
        previous = cid
        fingerprint = _take(cursor, 32, "oi21.index.fingerprint")
        dep_count = _take_u(cursor, "oi21.index.dependencies")
        deps = tuple(_take_u(cursor, "oi21.index.dependency") for _ in range(dep_count))
        user_count = _take_u(cursor, "oi21.index.users")
        users = tuple(_take_u(cursor, "oi21.index.user") for _ in range(user_count))
        if tuple(sorted(set(deps))) != deps or tuple(sorted(set(users))) != users:
            raise IndexRejected("oi21.index.edge_order")
        if any(ordinal >= count for ordinal in (*deps, *users)):
            raise IndexRejected("oi21.index.edge_range")
        raw.append((cid, fingerprint, deps, users))
    try:
        cursor.end("oi21.index.trailing")
    except Exception as error:
        raise IndexRejected("oi21.index.trailing") from error
    cids = tuple(item[0] for item in raw)
    entries = []
    for cid, fingerprint, dep_ordinals, user_ordinals in raw:
        deps = tuple(cids[ordinal] for ordinal in dep_ordinals)
        users = tuple(cids[ordinal] for ordinal in user_ordinals)
        if fingerprint != _fingerprint(cid, deps):
            raise IndexRejected("oi21.index.fingerprint")
        entries.append(IndexEntry(cid, fingerprint, deps, users))
    index = DependencyIndex(root, verifier, compiler, tuple(entries))
    if expected_root is not None and root != expected_root:
        raise IndexRejected("oi21.index.stale_root")
    if verifier_identity is not None and verifier != verifier_identity:
        raise IndexRejected("oi21.index.stale_verifier")
    if compiler_identity is not None and compiler != compiler_identity:
        raise IndexRejected("oi21.index.stale_compiler")
    by_cid = index.by_cid()
    for entry in index.entries:
        for dep in entry.dependencies:
            other = by_cid.get(dep)
            if other is None or entry.cid not in other.users:
                raise IndexRejected("oi21.index.reverse_edge")
        for user in entry.users:
            other = by_cid.get(user)
            if other is None or entry.cid not in other.dependencies:
                raise IndexRejected("oi21.index.reverse_edge")
    return index


def validate_index(index: DependencyIndex, reader: StoreReader) -> None:
    if index.root_cid != reader.root_cid:
        raise IndexRejected("oi21.index.stale_root")
    rebuilt = build_index(reader, index.verifier_identity, index.compiler_identity)
    if encode_index(index) != encode_index(rebuilt):
        raise IndexRejected("oi21.index.store_mismatch")


def save_index_atomic(path: Path, index: DependencyIndex) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = encode_index(index)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def load_or_rebuild(path: Path, reader: StoreReader) -> tuple[DependencyIndex, bool]:
    try:
        index = decode_index(
            path.read_bytes(),
            expected_root=reader.root_cid,
            verifier_identity=DEFAULT_VERIFIER_IDENTITY,
            compiler_identity=BOOTSTRAP_COMPILER_IDENTITY_V1,
        )
        return index, False
    except (OSError, IndexRejected):
        index = build_index(reader)
        save_index_atomic(path, index)
        return index, True


def update_index(index: DependencyIndex, reader: StoreReader) -> tuple[DependencyIndex, dict[str, int]]:
    if index.verifier_identity != DEFAULT_VERIFIER_IDENTITY or index.compiler_identity != BOOTSTRAP_COMPILER_IDENTITY_V1:
        raise IndexRejected("oi21.index.stale_dependency_identity")
    old = index.by_cid()
    new_cids = set(reader.object_cids)
    old_cids = set(old)
    retained = old_cids & new_cids
    removed = old_cids - new_cids
    added = new_cids - old_cids
    dependencies: dict[bytes, tuple[bytes, ...]] = {cid: old[cid].dependencies for cid in retained}
    decoded = 0
    for cid in sorted(added):
        obj = reader.get(cid)
        decoded += 1
        dependencies[cid] = tuple(obj.references)
    users: dict[bytes, list[bytes]] = {cid: [] for cid in new_cids}
    for cid, refs in dependencies.items():
        for ref in refs:
            if ref not in users:
                raise IndexRejected("oi21.index.update_missing_dependency")
            users[ref].append(cid)
    entries = tuple(
        IndexEntry(cid, _fingerprint(cid, dependencies[cid]), dependencies[cid], tuple(sorted(users[cid])))
        for cid in sorted(new_cids)
    )
    result = DependencyIndex(reader.root_cid, index.verifier_identity, index.compiler_identity, entries)
    return result, {
        "retained_objects": len(retained),
        "removed_objects": len(removed),
        "added_objects": len(added),
        "decoded_new_objects": decoded,
    }


def invalidation_frontier(index: DependencyIndex, seeds: Iterable[bytes]) -> tuple[bytes, ...]:
    by_cid = index.by_cid()
    pending = list(seeds)
    affected: set[bytes] = set()
    while pending:
        cid = pending.pop()
        if cid in affected:
            continue
        if cid not in by_cid:
            raise IndexRejected("oi21.index.unknown_seed")
        affected.add(cid)
        pending.extend(by_cid[cid].users)
    return tuple(sorted(affected))


def _project_topology(name: str) -> tuple[int, int, int]:
    return {
        "shallow_fanout": (8, 16, 1),
        "deep_chain": (1, 128, 1),
        "mixed_modules": (8, 16, 1),
        "service_generated": (6, 12, 3),
    }[name]


def _callee_for(name: str, m: int, f: int, functions_per_module: int) -> tuple[int, int] | None:
    if name == "shallow_fanout":
        return None if (m, f) == (0, 0) else (0, 0)
    if name == "deep_chain":
        return None if f == 0 else (0, f - 1)
    if name == "mixed_modules":
        if (m, f) == (0, 0):
            return None
        if f == 0:
            return (m - 1, functions_per_module - 1)
        if f & 1:
            return (m, f - 1)
        return (0, 0)
    if name == "service_generated":
        if m == 0:
            return None if f == 0 else (0, (f - 1) // 2)
        if f & 1:
            return (m, f - 1)
        return (m - 1, (f * 3 + m) % functions_per_module)
    raise ValueError(name)


def build_project(name: str, *, leaf_delta: int = 0, leaf_arity: int = 1) -> Project:
    modules_count, functions_per_module, blocks_count = _project_topology(name)
    b64 = bits_type(64)
    target = x86_64_windows_general_target()
    objects: dict[bytes, SemanticObject] = {b64.cid: b64, target.cid: target}
    functions: dict[tuple[int, int], SemanticObject] = {}
    graphs: dict[tuple[int, int], SemanticObject] = {}
    arities: dict[tuple[int, int], int] = {}

    def add(obj: SemanticObject) -> SemanticObject:
        objects[obj.cid] = obj
        return obj

    for m in range(modules_count):
        for f in range(functions_per_module):
            key = (m, f)
            callee_key = _callee_for(name, m, f, functions_per_module)
            arity = leaf_arity if key == (0, 0) else 1
            params = tuple(b64 for _ in range(arity))
            if callee_key is None:
                if arity == 1:
                    first = Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 0)), (b64,))
                else:
                    first = Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b64,))
            else:
                callee = functions[callee_key]
                callee_arity = arities[callee_key]
                operands = tuple(ValueRef.parameter(0, 0) for _ in range(callee_arity))
                first = Node(Operation.CALL_DIRECT, operands, (b64,), entity=callee)
            ordinal = m * functions_per_module + f
            k_value = 3 + ordinal
            c_value = 10_000 + ordinal
            k = add(constant(b64, k_value))
            c = add(constant(b64, c_value))
            body_op = Operation.SUB_WRAP if key == (0, 0) and leaf_delta else Operation.MUL_WRAP
            if blocks_count == 1:
                nodes = (
                    first,
                    Node(Operation.CONSTANT, (), (b64,), entity=k),
                    Node(body_op, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b64,)),
                    Node(Operation.CONSTANT, (), (b64,), entity=c),
                    Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 3)), (b64,)),
                )
                blocks = (Block(params, nodes, Terminator.return_((ValueRef.node_result(0, 4),))),)
            else:
                blocks = (
                    Block(params, (first,), Terminator.branch(1, (ValueRef.node_result(0, 0),))),
                    Block((b64,), (
                        Node(Operation.CONSTANT, (), (b64,), entity=k),
                        Node(body_op, (ValueRef.parameter(1, 0), ValueRef.node_result(1, 0)), (b64,)),
                    ), Terminator.branch(2, (ValueRef.node_result(1, 1),))),
                    Block((b64,), (
                        Node(Operation.CONSTANT, (), (b64,), entity=c),
                        Node(Operation.ADD_WRAP, (ValueRef.parameter(2, 0), ValueRef.node_result(2, 0)), (b64,)),
                    ), Terminator.return_((ValueRef.node_result(2, 1),))),
                )
            graph = add(graph_fragment(blocks))
            fn = add(function(graph, params, (b64,)))
            graphs[key] = graph
            functions[key] = fn
            arities[key] = arity

    modules = []
    for m in range(modules_count):
        members = [functions[(m, f)] for f in range(functions_per_module)]
        if m == 0:
            members.append(target)
        modules.append(add(object_with_refs(Kind.MODULE, members)))
    root = add(object_with_refs(Kind.PROGRAM_ROOT, modules))
    data = write_store(root.cid, objects.values())
    reader = StoreReader(data)
    verify_store(reader)
    return Project(name, reader, data, root, tuple(objects.values()), functions, graphs, (0, 0), leaf_arity)


def _object_bytes(reader: StoreReader, cids: Iterable[bytes]) -> int:
    return sum(len(reader.get(cid).envelope()) for cid in cids)


def deterministic_project_evidence(name: str) -> dict:
    base = build_project(name)
    index = build_index(base.reader)
    encoded = encode_index(index)
    rows = {}
    for edit_name, edited, seeds in (
        ("leaf_body", build_project(name, leaf_delta=1), (base.graphs[base.leaf].cid,)),
        ("leaf_interface", build_project(name, leaf_arity=2), (base.graphs[base.leaf].cid, base.functions[base.leaf].cid)),
    ):
        old_cids = set(base.reader.object_cids)
        new_cids = set(edited.reader.object_cids)
        removed = old_cids - new_cids
        added = new_cids - old_cids
        frontier = set(invalidation_frontier(index, seeds))
        if frontier != removed:
            raise AssertionError(f"under/over invalidation for {name}/{edit_name}: {len(frontier)} != {len(removed)}")
        updated, update_stats = update_index(index, edited.reader)
        rebuilt = build_index(edited.reader)
        if encode_index(updated) != encode_index(rebuilt):
            raise AssertionError("incremental index differs from full rebuild")
        rows[edit_name] = {
            "new_root": edited.root.cid.hex(),
            "removed_objects": len(removed),
            "added_objects": len(added),
            "invalidation_count": len(frontier),
            "invalidation_exact": True,
            "invalidated_old_bytes": _object_bytes(base.reader, frontier),
            "new_object_bytes": _object_bytes(edited.reader, added),
            "reused_objects": len(old_cids & new_cids),
            "reused_object_bytes": _object_bytes(base.reader, old_cids & new_cids),
            "update": update_stats,
            "updated_index_bytes": len(encode_index(updated)),
            "matches_full_rebuild": True,
        }
    return {
        "root": base.root.cid.hex(),
        "store_bytes": len(base.store_bytes),
        "objects": len(base.reader.object_cids),
        "index_bytes": len(encoded),
        "index_objects": len(index.entries),
        "index_edges": index.edge_count,
        "index_sha256": hashlib.sha256(encoded).hexdigest(),
        "edits": rows,
    }


def _independent_compile_payload(nodes: int, salt: int) -> tuple[bytes, bytes, bytes]:
    b64 = bits_type(64)
    target = x86_64_windows_general_target()
    sequence = [Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b64,))]
    for i in range(1, nodes):
        op = (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP)[(i + salt) % 3]
        sequence.append(Node(op, (ValueRef.node_result(0, i - 1), ValueRef.parameter(0, i & 1)), (b64,)))
    graph = graph_fragment((Block((b64, b64), tuple(sequence), Terminator.return_((ValueRef.node_result(0, nodes - 1),))),))
    fn = function(graph, (b64, b64), (b64,))
    module = object_with_refs(Kind.MODULE, (fn, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    data = write_store(root.cid, (b64, graph, fn, target, module, root))
    return data, fn.cid, target.cid


def _compile_payload(payload: tuple[bytes, bytes, bytes]) -> tuple[str, str, str]:
    data, function_cid, target_cid = payload
    try:
        image = compile_native(StoreReader(data), function_cid, target_cid)
        detail = f"{len(image.artifact_bytes)}:{hashlib.sha256(image.artifact_bytes).hexdigest()}"
        return function_cid.hex(), "ok", detail
    except XaxError as error:
        d = error.diagnostic
        detail = json.dumps(
            {"code": d.code, "entity": d.entity, "rule": d.rule, "expected": d.expected, "actual": d.actual},
            sort_keys=True, separators=(",", ":"), default=str,
        )
        return function_cid.hex(), "diagnostic", detail


def run_process_pool(payloads: list[tuple[bytes, bytes, bytes]], workers: int) -> tuple[tuple[str, str, str], ...]:
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork")) as pool:
        results = tuple(pool.map(_compile_payload, payloads))
    return tuple(sorted(results))


def _read_only_index_query(payload: tuple[str, bytes, bytes]) -> str:
    path, root_cid, seed = payload
    index = decode_index(
        Path(path).read_bytes(),
        expected_root=root_cid,
        verifier_identity=DEFAULT_VERIFIER_IDENTITY,
        compiler_identity=BOOTSTRAP_COMPILER_IDENTITY_V1,
    )
    frontier = invalidation_frontier(index, (seed,))
    return hashlib.sha256(b"".join(frontier)).hexdigest()


def run_shared_index_queries(path: Path, root_cid: bytes, seed: bytes, workers: int) -> tuple[str, ...]:
    payload = (str(path), root_cid, seed)
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork")) as pool:
        return tuple(pool.map(_read_only_index_query, (payload for _ in range(workers))))


def _measure_process_pool(
    payloads: list[tuple[bytes, bytes, bytes]], workers: int, batches: int = 3
) -> tuple[tuple[tuple[str, str, str], ...], float, list[float]]:
    """Measure one cold batch (including process startup) plus warm batches."""
    ctx = multiprocessing.get_context("fork")
    warm: list[float] = []
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        start = time.perf_counter_ns()
        result = tuple(sorted(pool.map(_compile_payload, payloads)))
        cold = (time.perf_counter_ns() - start) / 1e6
        for _ in range(max(0, batches - 1)):
            start = time.perf_counter_ns()
            again = tuple(sorted(pool.map(_compile_payload, payloads)))
            warm.append((time.perf_counter_ns() - start) / 1e6)
            if again != result:
                raise AssertionError("parallel output differs across scheduling batches")
    return result, cold, warm


def _timed(callable_, samples: int) -> tuple[object, list[float]]:
    values = []
    result = None
    for _ in range(samples):
        start = time.perf_counter_ns()
        result = callable_()
        values.append((time.perf_counter_ns() - start) / 1e6)
    return result, values


def measure() -> dict:
    raw: dict = {
        "schema": 1,
        "host": {
            "platform": os.uname().sysname if hasattr(os, "uname") else os.name,
            "machine": os.uname().machine if hasattr(os, "uname") else "unknown",
            "logical_cpus": os.cpu_count(),
            "process_start_method": "fork",
        },
        "projects": {},
        "parallel": {},
    }
    for name in ("shallow_fanout", "deep_chain", "mixed_modules", "service_generated"):
        base = build_project(name)
        index = build_index(base.reader)
        encoded = encode_index(index)
        leaf = build_project(name, leaf_delta=1)
        interface = build_project(name, leaf_arity=2)
        _, cold = _timed(lambda: build_index(StoreReader(base.store_bytes)), 7)
        _, warm = _timed(lambda: decode_index(encoded, expected_root=base.root.cid, verifier_identity=DEFAULT_VERIFIER_IDENTITY, compiler_identity=BOOTSTRAP_COMPILER_IDENTITY_V1), 7)
        _, query = _timed(lambda: invalidation_frontier(index, (base.graphs[base.leaf].cid,)), 15)
        _, leaf_update = _timed(lambda: update_index(index, leaf.reader), 7)
        _, interface_update = _timed(lambda: update_index(index, interface.reader), 7)
        raw["projects"][name] = {
            "cold_index_build_ms": cold,
            "warm_index_load_ms": warm,
            "leaf_invalidation_query_ms": query,
            "leaf_index_update_ms": leaf_update,
            "interface_index_update_ms": interface_update,
        }

    workers = tuple(dict.fromkeys((1, 2, min(4, os.cpu_count() or 1))))
    for nodes in (16, 256, 2048, 4096):
        payloads = [_independent_compile_payload(nodes, salt) for salt in range(4)]
        reference = tuple(sorted(_compile_payload(payload) for payload in payloads))
        row = {"task_count": len(payloads), "payload_bytes": sum(len(p[0]) for p in payloads), "workers": {}}
        for count in workers:
            cold_samples: list[float] = []
            warm_samples: list[float] = []
            for _ in range(3):
                result, cold, warm = _measure_process_pool(payloads, count, 2)
                if result != reference:
                    raise AssertionError("parallel output differs from serial reference")
                cold_samples.append(cold)
                warm_samples.extend(warm)
            row["workers"][str(count)] = {"cold_ms": cold_samples, "warm_ms": warm_samples}
        row["output_digest"] = hashlib.sha256(json.dumps(reference, separators=(",", ":")).encode()).hexdigest()
        raw["parallel"][str(nodes)] = row
    return raw


def deterministic_evidence(raw: dict | None) -> dict:
    projects = {name: deterministic_project_evidence(name) for name in ("shallow_fanout", "deep_chain", "mixed_modules", "service_generated")}
    parallel = {}
    threshold = None
    if raw is not None:
        for nodes_text, row in sorted(raw["parallel"].items(), key=lambda item: int(item[0])):
            cold = {worker: statistics.median(samples["cold_ms"]) for worker, samples in row["workers"].items()}
            warm = {worker: statistics.median(samples["warm_ms"]) for worker, samples in row["workers"].items()}
            cold_baseline = cold["1"]
            warm_baseline = warm["1"]
            best_cold_worker = min(cold, key=cold.get)
            best_warm_worker = min(warm, key=warm.get)
            cold_speedup = cold_baseline / cold[best_cold_worker]
            warm_speedup = warm_baseline / warm[best_warm_worker]
            if threshold is None and int(best_cold_worker) > 1 and int(best_warm_worker) > 1 and cold_speedup >= 1.20 and warm_speedup >= 1.20:
                threshold = int(nodes_text)
            parallel[nodes_text] = {
                "task_count": row["task_count"],
                "payload_bytes": row["payload_bytes"],
                "workers_tested": sorted(int(k) for k in row["workers"]),
                "cold_best_worker_count": int(best_cold_worker),
                "cold_one_worker_ms": cold_baseline,
                "cold_best_ms": cold[best_cold_worker],
                "cold_speedup_vs_one_worker": cold_speedup,
                "warm_best_worker_count": int(best_warm_worker),
                "warm_one_worker_median_ms": warm_baseline,
                "warm_best_median_ms": warm[best_warm_worker],
                "warm_speedup_vs_one_worker": warm_speedup,
                "output_digest": row["output_digest"],
                "outputs_schedule_independent": True,
            }
    diagnostic_payload = _independent_compile_payload(16, 0)
    bad_payload = (diagnostic_payload[0], b"\xff" * 32, diagnostic_payload[2])
    diagnostic_reference = _compile_payload(bad_payload)
    return {
        "schema": 1,
        "parallel_diagnostic_reference": list(diagnostic_reference),
        "format": {
            "magic": INDEX_MAGIC.decode(),
            "version": INDEX_VERSION,
            "write_policy": "atomic_replace",
            "semantic": False,
            "key": ["semantic_root_cid", "verifier_identity", "compiler_identity"],
            "record": ["object_cid", "dependency_fingerprint", "exact_direct_dependencies", "exact_reverse_users"],
            "corrupt_or_stale": "reject_or_rebuild",
        },
        "projects": projects,
        "parallel": parallel,
        "distribution_threshold_nodes": threshold,
        "threshold_rule": "lowest measured nodes/task where parallel workers improve both median cold-batch and warm-batch wall time by at least 20%; cold batches include process startup and payload serialization",
        "raw_timing_available": raw is not None,
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", action="store_true")
    args = parser.parse_args(argv)
    raw = measure() if args.measure else (json.loads(RAW.read_text()) if RAW.exists() else None)
    if args.measure:
        write_json(RAW, raw)
    evidence = deterministic_evidence(raw)
    write_json(EVIDENCE, evidence)
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
