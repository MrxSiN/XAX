"""OI-05 proof-cache timing/size evidence.

The fixture is deterministic; timing samples are raw host observations and are not
used as conformance thresholds.
"""

from __future__ import annotations

import json
import platform
import statistics
import time
from pathlib import Path

from blake3 import blake3
from xax_build import build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import (
    DEFAULT_VERIFIER_IDENTITY,
    Block,
    Kind,
    Node,
    Operation,
    ProofCache,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    write_store,
    x86_64_windows_target,
)
from xax_workspace import RootRef, SetConstant, Transaction, Workspace
from xax_x86_64 import compile_native_bound_target


FUNCTION_COUNT = 96
REPETITIONS = 7


def function_objects(count: int):
    b32 = bits_type(32)
    functions = []
    objects = [b32]
    for index in range(count):
        value = constant(b32, index + 1)
        graph = graph_fragment(
            (
                Block(
                    (),
                    (Node(Operation.CONSTANT, (), (b32,), entity=value),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                ),
            )
        )
        entry = function(graph, (), (b32,))
        functions.append(entry)
        objects.extend((value, graph, entry))
    return b32, tuple(functions), tuple(objects)


def program_fixture(count: int = FUNCTION_COUNT):
    _, functions, objects = function_objects(count)
    module = object_with_refs(Kind.MODULE, functions)
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*objects, module, root)))
    return reader, functions


def build_fixture(count: int = FUNCTION_COUNT):
    _, functions, objects = function_objects(count)
    module = object_with_refs(Kind.MODULE, functions)
    package_object = package(b"oi05-proof-cache", (module,), build_entries=((b"image", functions[0]),))
    target = x86_64_windows_target()
    profile, policy = build_profile(), trust_policy()
    request = build_request(package_object, b"image", target, profile)
    all_objects = (*objects, module, package_object, target, profile, policy, request)
    resolution = resolve_packages(request, all_objects, policy, b"bootstrap-resolver-v1")
    reader = snapshot_store(resolution, all_objects)
    return reader, request.cid, target, functions[0].cid


def timed(callable_):
    start = time.perf_counter_ns()
    value = callable_()
    return time.perf_counter_ns() - start, value


def summary(samples):
    ordered = sorted(samples)
    return {
        "raw_ns": samples,
        "min_ns": ordered[0],
        "median_ns": int(statistics.median(ordered)),
        "max_ns": ordered[-1],
    }


def measure_verify(data: bytes):
    cold, cold_load, warm, warm_load = [], [], [], []
    deterministic = None
    for _ in range(REPETITIONS):
        duration, _ = timed(lambda: verify_store(StoreReader(data)))
        cold_load.append(duration)
        cache = ProofCache()
        reader = StoreReader(data, proof_cache=cache)
        duration, cold_stats = timed(lambda: verify_store(reader))
        cold.append(duration)
        cache_bytes = cache.canonical_bytes()
        duration, warm_stats = timed(lambda: verify_store(reader))
        warm.append(duration)

        def load_and_verify():
            loaded_cache = ProofCache.from_bytes(cache_bytes)
            loaded_reader = StoreReader(data, proof_cache=loaded_cache)
            return verify_store(loaded_reader)

        duration, loaded_stats = timed(load_and_verify)
        warm_load.append(duration)
        current = {
            "cold": cold_stats.__dict__,
            "warm": warm_stats.__dict__,
            "warm_after_sidecar_decode": loaded_stats.__dict__,
            "cache_bytes": len(cache_bytes),
            "cache_digest": blake3(cache_bytes).hexdigest(),
        }
        if deterministic is None:
            deterministic = current
        elif deterministic != current:
            raise RuntimeError("deterministic verification/cache accounting changed between repetitions")
    return {
        "cold_verify": summary(cold),
        "cold_store_load_plus_verify": summary(cold_load),
        "warm_verify": summary(warm),
        "warm_sidecar_load_plus_verify": summary(warm_load),
        "deterministic": deterministic,
    }


def measure_compile(data: bytes, entry_cid: bytes, target):
    cold, cold_load, warm, warm_load = [], [], [], []
    artifact_digest = None
    artifact_bytes = None
    for _ in range(REPETITIONS):
        duration, cold_loaded_image = timed(
            lambda: compile_native_bound_target(StoreReader(data), entry_cid, target)
        )
        cold_load.append(duration)
        cold_cache = ProofCache()
        cold_reader = StoreReader(data, proof_cache=cold_cache)
        duration, cold_image = timed(lambda: compile_native_bound_target(cold_reader, entry_cid, target))
        cold.append(duration)

        warm_cache = ProofCache()
        warm_reader = StoreReader(data, proof_cache=warm_cache)
        verify_store(warm_reader)
        sidecar = warm_cache.canonical_bytes()
        duration, warm_image = timed(lambda: compile_native_bound_target(warm_reader, entry_cid, target))
        warm.append(duration)

        def load_and_compile():
            loaded_cache = ProofCache.from_bytes(sidecar)
            loaded_reader = StoreReader(data, proof_cache=loaded_cache)
            return compile_native_bound_target(loaded_reader, entry_cid, target)

        duration, warm_loaded_image = timed(load_and_compile)
        warm_load.append(duration)
        if not (cold_loaded_image.artifact_bytes == cold_image.artifact_bytes == warm_image.artifact_bytes == warm_loaded_image.artifact_bytes):
            raise RuntimeError("proof cache changed compiled artifact")
        current_digest = blake3(warm_image.artifact_bytes).hexdigest()
        if artifact_digest is None:
            artifact_digest = current_digest
            artifact_bytes = len(warm_image.artifact_bytes)
        elif artifact_digest != current_digest:
            raise RuntimeError("compiled artifact changed between repetitions")
    return {
        "cold_compile": summary(cold),
        "cold_store_load_plus_compile": summary(cold_load),
        "warm_compile": summary(warm),
        "warm_sidecar_load_plus_compile": summary(warm_load),
        "artifact_bytes": artifact_bytes,
        "artifact_digest": artifact_digest,
    }


def measure_incremental(data: bytes, entry_cid: bytes, target):
    commit_without_cache, commit_with_cache = [], []
    compile_without_cache, compile_with_cache = [], []
    deterministic = None
    for _ in range(REPETITIONS):
        plain_workspace = Workspace(StoreReader(data))
        plain_node = plain_workspace.function_nodes(entry_cid, 1).entities[0]
        duration, plain_result = timed(
            lambda: plain_workspace.commit(Transaction(RootRef(0), (SetConstant(plain_node.handle, plain_node.constant_value, 777),)))
        )
        commit_without_cache.append(duration)
        if not plain_result.committed or plain_result.changed_entity is None:
            raise RuntimeError(plain_result.diagnostic)
        duration, plain_image = timed(
            lambda: compile_native_bound_target(plain_workspace.reader, plain_result.changed_entity, target)
        )
        compile_without_cache.append(duration)

        cache = ProofCache()
        cached_reader = StoreReader(data, proof_cache=cache)
        verify_store(cached_reader)
        cached_workspace = Workspace(cached_reader)
        cached_node = cached_workspace.function_nodes(entry_cid, 1).entities[0]
        before_entries = cache.entry_count
        before_bytes = len(cache.canonical_bytes())
        duration, cached_result = timed(
            lambda: cached_workspace.commit(Transaction(RootRef(0), (SetConstant(cached_node.handle, cached_node.constant_value, 777),)))
        )
        commit_with_cache.append(duration)
        if not cached_result.committed or cached_result.changed_entity is None:
            raise RuntimeError(cached_result.diagnostic)
        after_entries = cache.entry_count
        after_bytes = len(cache.canonical_bytes())
        duration, cached_image = timed(
            lambda: compile_native_bound_target(cached_workspace.reader, cached_result.changed_entity, target)
        )
        compile_with_cache.append(duration)
        if plain_image.artifact_bytes != cached_image.artifact_bytes:
            raise RuntimeError("incremental cache changed compiled artifact")
        warm_stats = verify_store(cached_workspace.reader)
        current = {
            "base_cache_entries": before_entries,
            "base_cache_bytes": before_bytes,
            "post_edit_cache_entries": after_entries,
            "post_edit_cache_bytes": after_bytes,
            "post_edit_root": cached_result.root.hex(),
            "touched_objects": cached_result.touched_objects,
            "reused_objects": cached_result.reused_objects,
            "verified_objects": cached_result.verified_objects,
            "cache_entries_written": cached_workspace.accounting.proof_cache_entries_written,
            "cache_entries_invalidated": cached_workspace.accounting.proof_cache_entries_invalidated,
            "cache_dependency_cids_maintained": cached_workspace.accounting.proof_cache_dependency_cids_maintained,
            "post_edit_warm_verify": warm_stats.__dict__,
            "artifact_digest": blake3(cached_image.artifact_bytes).hexdigest(),
        }
        if deterministic is None:
            deterministic = current
        elif deterministic != current:
            raise RuntimeError("incremental cache accounting changed between repetitions")
    return {
        "commit_without_cache": summary(commit_without_cache),
        "commit_with_cache": summary(commit_with_cache),
        "post_edit_compile_without_cache": summary(compile_without_cache),
        "post_edit_compile_with_cache": summary(compile_with_cache),
        "deterministic": deterministic,
    }


def measure_build(data: bytes, request_cid: bytes):
    cold, cold_load, warm, warm_load = [], [], [], []
    deterministic = None
    for _ in range(REPETITIONS):
        duration, cold_loaded_result = timed(lambda: build(StoreReader(data), request_cid))
        cold_load.append(duration)
        cold_cache = ProofCache()
        cold_reader = StoreReader(data, proof_cache=cold_cache)
        duration, cold_result = timed(lambda: build(cold_reader, request_cid))
        cold.append(duration)

        warm_cache = ProofCache()
        warm_reader = StoreReader(data, proof_cache=warm_cache)
        verify_store(warm_reader)
        sidecar = warm_cache.canonical_bytes()
        loaded_cache = ProofCache.from_bytes(sidecar)
        loaded_reader = StoreReader(data, proof_cache=loaded_cache)
        duration, warm_result = timed(lambda: build(loaded_reader, request_cid))
        warm.append(duration)

        def load_and_build():
            cache = ProofCache.from_bytes(sidecar)
            return build(StoreReader(data, proof_cache=cache), request_cid)

        duration, warm_loaded_result = timed(load_and_build)
        warm_load.append(duration)
        if not (cold_loaded_result.artifact == cold_result.artifact == warm_result.artifact == warm_loaded_result.artifact):
            raise RuntimeError("proof cache changed build artifact")
        if not (cold_loaded_result.provenance == cold_result.provenance == warm_result.provenance == warm_loaded_result.provenance):
            raise RuntimeError("proof cache changed build provenance")
        current = {
            "artifact_bytes": len(warm_result.artifact),
            "artifact_digest": warm_result.artifact_digest.hex(),
            "build_key": warm_result.key.hex(),
            "provenance_cid": warm_result.provenance.cid.hex(),
            "cache_bytes": len(sidecar),
            "cache_entries": loaded_cache.entry_count,
        }
        if deterministic is None:
            deterministic = current
        elif deterministic != current:
            raise RuntimeError("build output changed between repetitions")
    return {
        "cold_build": summary(cold),
        "cold_store_load_plus_build": summary(cold_load),
        "warm_build": summary(warm),
        "warm_sidecar_load_plus_build": summary(warm_load),
        "deterministic": deterministic,
    }


def main() -> None:
    program_reader, functions = program_fixture()
    build_reader, request_cid, target, build_entry = build_fixture()
    verification = measure_verify(program_reader.data)
    compile_measurement = measure_compile(program_reader.data, functions[0].cid, target)
    incremental = measure_incremental(program_reader.data, functions[0].cid, target)
    build_measurement = measure_build(build_reader.data, request_cid)

    record = {
        "schema": "xax-oi05-proof-cache-evidence-v1",
        "timing": True,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "inputs": {
            "function_count": FUNCTION_COUNT,
            "repetitions": REPETITIONS,
            "verifier_identity": DEFAULT_VERIFIER_IDENTITY,
            "program_root": program_reader.root_cid.hex(),
            "program_store_bytes": len(program_reader.data),
            "program_object_count": len(program_reader.object_cids),
            "build_snapshot_root": build_reader.root_cid.hex(),
            "build_store_bytes": len(build_reader.data),
            "build_object_count": len(build_reader.object_cids),
            "build_request": request_cid.hex(),
            "build_entry": build_entry.hex(),
            "target": target.cid.hex(),
        },
        "verification": verification,
        "compile": compile_measurement,
        "incremental": incremental,
        "build": build_measurement,
    }
    output = Path(__file__).with_name("oi05_proof_cache_evidence.json")
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
