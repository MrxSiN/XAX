"""Deterministic M10 package/snapshot/build/cache record; deliberately non-timing."""

from __future__ import annotations

import json

from xax_build import BuildCache, build, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    Terminator,
    ValueRef,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    wasm32_target,
    x86_64_windows_target,
)


def build_for(target):
    b32 = bits_type(32)
    value = constant(b32, 42)
    graph = graph_fragment(
        (Block((), (Node(Operation.CONSTANT, (), (b32,), entity=value),), Terminator.return_((ValueRef.node_result(0, 0),))),)
    )
    entry = function(graph, (), (b32,))
    module = object_with_refs(Kind.MODULE, (b32, value, entry))
    package_object = package(b"m10-smoke", (module,), build_entries=((b"image", entry),))
    profile, policy = build_profile(), trust_policy()
    request = build_request(package_object, b"image", target, profile)
    objects = (b32, value, graph, entry, module, package_object, target, profile, policy, request)
    resolution = resolve_packages(request, objects, policy, b"bootstrap-resolver-v1")
    reader = snapshot_store(resolution, objects)
    first, second = build(reader, request.cid), build(reader, request.cid)
    cache = BuildCache()
    cache.put(first)
    return {
        "artifact_bytes": len(first.artifact),
        "artifact_digest": first.artifact_digest.hex(),
        "build_key": first.key.hex(),
        "cache_verified": cache.get(first.key, reader) == first.artifact,
        "package_root": package_object.cid.hex(),
        "provenance_root": first.provenance.cid.hex(),
        "repeat_byte_identical": first == second,
        "request_root": request.cid.hex(),
        "snapshot_root": resolution.snapshot.cid.hex(),
        "store_bytes": len(reader.data),
        "target_root": target.cid.hex(),
    }


def main() -> None:
    record = {"x86_64": build_for(x86_64_windows_target()), "wasm32": build_for(wasm32_target())}
    record["cross_target_cache_separated"] = record["x86_64"]["build_key"] != record["wasm32"]["build_key"]
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
