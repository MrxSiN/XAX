"""Deterministic M7 proof-erasure comparison; not a timing benchmark."""

from __future__ import annotations

import hashlib
import json

from xax_aarch64 import compile_aarch64
from xax_compiler import (
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    ResourceFlags,
    StoreReader,
    Terminator,
    ValueRef,
    aarch64_baremetal_target,
    bits_type,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    resource_type,
    wasm32_target,
    write_store,
    x86_64_windows_target,
)
from xax_wasm import compile_wasm
from xax_x86_64 import compile_native


def fixture(target, lifecycle: bool):
    b32 = bits_type(32)
    parameters = (b32,)
    returns = (b32,)
    nodes = ()
    values = (ValueRef.parameter(0, 0),)
    objects = [b32]
    if lifecycle:
        effect = effect_type(EffectDomain.FILESYSTEM, 1)
        resource = resource_type(2, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE)
        parameters = (b32, effect)
        returns = (b32, effect)
        nodes = (
            Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (resource, effect)),
            Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (effect,)),
        )
        values = (ValueRef.parameter(0, 0), ValueRef.node_result(0, 1, 0))
        objects.extend((effect, resource))
    graph = graph_fragment([Block(parameters, nodes, Terminator.return_(values))])
    entry = function(graph, parameters, returns)
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return StoreReader(write_store(root.cid, (*objects, graph, entry, target, module, root))), entry


def main() -> None:
    results = {}
    for name, target_factory, compiler, attribute in (
        ("x86_64", x86_64_windows_target, compile_native, "code"),
        ("aarch64", aarch64_baremetal_target, compile_aarch64, "code"),
        ("wasm32", wasm32_target, compile_wasm, "module"),
    ):
        target = target_factory()
        baseline_reader, baseline_entry = fixture(target, False)
        lifecycle_reader, lifecycle_entry = fixture(target, True)
        baseline = getattr(compiler(baseline_reader, baseline_entry.cid, target.cid), attribute)
        lifecycle = getattr(compiler(lifecycle_reader, lifecycle_entry.cid, target.cid), attribute)
        results[name] = {
            "baseline_bytes": len(baseline),
            "lifecycle_bytes": len(lifecycle),
            "byte_identical": baseline == lifecycle,
            "sha256": hashlib.sha256(lifecycle).hexdigest(),
        }
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
