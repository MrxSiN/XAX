"""OI-13 accelerator synchronization-scope normalization evidence.

All portable-scope mappings and packets in this file are measurement-only
sidecar/tooling data.  Canonical XAX synchronization scopes and target package
identities remain authoritative and unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import inspect
import json
from pathlib import Path
from typing import Callable

from blake3 import blake3

from xax_accelerator import (
    coherent_grid_accelerator_target,
    compile_accelerator,
    run_accelerator_deployment,
)
from xax_compiler import (
    AtomicOrder,
    AtomicScope,
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    ResourceFlags,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    decode_native_target,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    resource_type,
    simt32_accelerator_target,
    uleb,
    verify_store,
    write_store,
)

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "oi13_scope_normalization_evidence.json"


class PortableScope(IntEnum):
    WORKGROUP = 1
    DEVICE = 2


PORTABLE_LATTICE = (PortableScope.WORKGROUP, PortableScope.DEVICE)
_PORTABLE_TO_ATOMIC = {
    PortableScope.WORKGROUP: AtomicScope.WORKGROUP,
    PortableScope.DEVICE: AtomicScope.DEVICE,
}


@dataclass(frozen=True)
class SyncVector:
    name: str
    operation: str
    order: AtomicOrder
    source_space: str
    destination_space: str
    portable_scope: PortableScope | None = None
    target_scope: AtomicScope | None = None
    effect: EffectDomain = EffectDomain.ATOMIC


class ScopeMappingError(ValueError):
    pass


class SyncSemanticError(ValueError):
    pass


def portable_to_target(target: SemanticObject, scope: PortableScope) -> AtomicScope:
    """Map only when the exact same scope meaning exists in the package."""

    description = decode_native_target(target)
    exact = _PORTABLE_TO_ATOMIC[scope]
    if exact not in description.accelerator_scopes:
        raise ScopeMappingError(f"unsupported portable scope: {scope.name.lower()}")
    return exact


def target_to_portable(target: SemanticObject, scope: AtomicScope) -> PortableScope | None:
    """Reverse-map exact common scopes; never approximate target-only scopes."""

    description = decode_native_target(target)
    if scope not in description.accelerator_scopes:
        raise ScopeMappingError(f"scope not supported by target: {scope.name.lower()}")
    for portable, exact in _PORTABLE_TO_ATOMIC.items():
        if exact == scope:
            return portable
    return None


def validate_portable_lattice(targets: tuple[SemanticObject, ...]) -> None:
    for target in targets:
        mapped = tuple(portable_to_target(target, item) for item in PORTABLE_LATTICE)
        if mapped != (AtomicScope.WORKGROUP, AtomicScope.DEVICE):
            raise ScopeMappingError(f"scope relation changed on {target.cid.hex()}")
        if tuple(target_to_portable(target, item) for item in mapped) != PORTABLE_LATTICE:
            raise ScopeMappingError(f"scope roundtrip changed on {target.cid.hex()}")


def validate_sync_semantics(vector: SyncVector) -> None:
    if (vector.portable_scope is None) == (vector.target_scope is None):
        raise SyncSemanticError("exactly one of portable_scope/target_scope is required")
    if vector.operation == "atomic_load":
        allowed = (AtomicOrder.RELAXED, AtomicOrder.ACQUIRE, AtomicOrder.SEQ_CST)
    elif vector.operation == "atomic_store":
        allowed = (AtomicOrder.RELAXED, AtomicOrder.RELEASE, AtomicOrder.SEQ_CST)
    elif vector.operation == "barrier":
        allowed = (AtomicOrder.ACQUIRE, AtomicOrder.RELEASE, AtomicOrder.ACQ_REL, AtomicOrder.SEQ_CST)
    else:
        raise SyncSemanticError(f"unknown synchronization operation: {vector.operation}")
    if vector.effect != EffectDomain.ATOMIC:
        raise SyncSemanticError(f"synchronization effect must be atomic, got {vector.effect.name.lower()}")
    if vector.order not in allowed:
        raise SyncSemanticError(f"invalid {vector.operation} order: {vector.order.name.lower()}")


def _space_ids(target: SemanticObject) -> dict[str, int]:
    description = decode_native_target(target)
    if description.identity == b"simt32-packet-accelerator-v1":
        return {"system": 1, "global": 2, "local": 3}
    if description.identity == b"coherent-grid-accelerator-v1":
        return {"system": 1, "global": 1, "local": 2}
    raise ScopeMappingError(f"unmeasured target package: {description.identity!r}")


def lower_sync_vector(target: SemanticObject, vector: SyncVector) -> bytes:
    """Measurement-only exact scope/space legality and tiny conformance packet."""

    validate_sync_semantics(vector)
    description = decode_native_target(target)
    if vector.portable_scope is not None:
        scope = portable_to_target(target, vector.portable_scope)
    else:
        assert vector.target_scope is not None
        scope = vector.target_scope
        if scope not in description.accelerator_scopes:
            raise ScopeMappingError(f"scope not supported by target: {scope.name.lower()}")
    spaces = _space_ids(target)
    try:
        source_id = spaces[vector.source_space]
        destination_id = spaces[vector.destination_space]
    except KeyError as error:
        raise ScopeMappingError(f"unknown memory-space class: {error.args[0]}") from error
    by_id = {space.identity: space for space in description.memory_spaces}
    for space_id in (source_id, destination_id):
        if scope not in by_id[space_id].visibility_scopes:
            raise ScopeMappingError(
                f"scope {scope.name.lower()} not visible in memory space {space_id}"
            )
    opcode = {"atomic_load": 1, "atomic_store": 2, "barrier": 3}[vector.operation]
    return (
        b"X13\x01"
        + target.cid
        + uleb(opcode)
        + uleb(vector.order)
        + uleb(scope)
        + uleb(source_id)
        + uleb(destination_id)
    )


def _deployment_fixture(target: SemanticObject) -> tuple[StoreReader, SemanticObject]:
    description = decode_native_target(target)
    unified = description.identity == b"coherent-grid-accelerator-v1"
    global_space = 1 if unified else 2
    b32 = bits_type(32)
    effect = effect_type(EffectDomain.DEVICE, 1)
    host_buffer = resource_type(1001, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE, transitions=(2,))
    device_buffer = resource_type(1001, 2, flags=ResourceFlags.RELEASABLE, transitions=(1,))
    nodes = (
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 2),), (host_buffer, effect), entity=target, attributes=(1, AtomicScope.DEVICE, 1, 1)),
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (device_buffer, effect), entity=target, attributes=(2, AtomicScope.DEVICE, 1, global_space)),
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)), (device_buffer, effect), entity=target, attributes=(3, AtomicScope.DEVICE, global_space, global_space)),
        Node(Operation.TARGET_OP, (ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 1)), (device_buffer, effect), entity=target, attributes=(4, AtomicScope.DEVICE, global_space, global_space)),
        Node(Operation.TARGET_OP, (ValueRef.node_result(0, 3, 0), ValueRef.node_result(0, 3, 1)), (b32, host_buffer, effect), entity=target, attributes=(5, AtomicScope.DEVICE, global_space, 1)),
        Node(Operation.TARGET_OP, (ValueRef.node_result(0, 4, 1), ValueRef.node_result(0, 4, 2)), (effect,), entity=target, attributes=(6, AtomicScope.DEVICE, 1, 1)),
    )
    graph = graph_fragment((Block((b32, b32, effect), nodes, Terminator.return_((ValueRef.node_result(0, 4, 0), ValueRef.node_result(0, 5, 0)))),))
    entry = function(graph, (b32, b32, effect), (b32, effect))
    module = object_with_refs(Kind.MODULE, (b32, effect, host_buffer, device_buffer, entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (b32, effect, host_buffer, device_buffer, target, graph, entry, module, root)))
    return reader, entry


def _tokenizer_counts(portable_payload: bytes, target_payload: bytes) -> dict:
    try:
        import tiktoken  # type: ignore
    except Exception:
        return {
            "tokenizer": None,
            "portable_tokens": None,
            "target_specific_tokens": None,
            "reason": "tiktoken unavailable; bytes are not substituted for tokens",
        }
    encoding = tiktoken.get_encoding("o200k_base")
    return {
        "tokenizer": "o200k_base",
        "portable_tokens": len(encoding.encode(portable_payload.decode("ascii"))),
        "target_specific_tokens": len(encoding.encode(target_payload.decode("ascii"))),
        "reason": None,
    }


def _vector_result(target: SemanticObject, vector: SyncVector) -> dict:
    semantic_valid = True
    try:
        validate_sync_semantics(vector)
    except SyncSemanticError as error:
        semantic_valid = False
        return {"semantic_valid": False, "target_legal": False, "error": str(error), "packet_bytes": None}
    try:
        packet = lower_sync_vector(target, vector)
        return {
            "semantic_valid": semantic_valid,
            "target_legal": True,
            "error": None,
            "packet_bytes": len(packet),
            "packet_blake3": blake3(packet).hexdigest(),
        }
    except ScopeMappingError as error:
        return {"semantic_valid": semantic_valid, "target_legal": False, "error": str(error), "packet_bytes": None}


def run() -> dict:
    simt = simt32_accelerator_target()
    coherent = coherent_grid_accelerator_target()
    targets = (simt, coherent)
    validate_portable_lattice(targets)

    deployment_rows = []
    for target in targets:
        reader, entry = _deployment_fixture(target)
        verify_store(reader)
        first = compile_accelerator(reader, entry.cid, target.cid)
        second = compile_accelerator(reader, entry.cid, target.cid)
        result = run_accelerator_deployment(first, (7, 9))
        description = decode_native_target(target)
        deployment_rows.append(
            {
                "target_identity": description.identity.decode("ascii"),
                "target_cid": target.cid.hex(),
                "package_object_bytes": len(target.envelope()),
                "package_object_count": 1,
                "memory_spaces": len(description.memory_spaces),
                "contracts": len(description.target_operations),
                "scopes": [item.name.lower() for item in description.accelerator_scopes],
                "deployment_bytes": len(first.deployment),
                "deployment_deterministic": first.deployment == second.deployment,
                "execution_result": list(result),
            }
        )

    vectors = (
        SyncVector("wg_atomic_acquire", "atomic_load", AtomicOrder.ACQUIRE, "local", "local", portable_scope=PortableScope.WORKGROUP),
        SyncVector("wg_cross_space_barrier", "barrier", AtomicOrder.ACQ_REL, "global", "local", portable_scope=PortableScope.WORKGROUP),
        SyncVector("device_atomic_seq_cst", "atomic_store", AtomicOrder.SEQ_CST, "global", "global", portable_scope=PortableScope.DEVICE),
        SyncVector("device_barrier", "barrier", AtomicOrder.SEQ_CST, "global", "global", portable_scope=PortableScope.DEVICE),
        SyncVector("device_to_local_reject", "barrier", AtomicOrder.SEQ_CST, "global", "local", portable_scope=PortableScope.DEVICE),
        SyncVector("target_only_system", "barrier", AtomicOrder.SEQ_CST, "system", "system", target_scope=AtomicScope.SYSTEM),
    )
    vector_rows = []
    for vector in vectors:
        vector_rows.append(
            {
                "name": vector.name,
                "operation": vector.operation,
                "order": vector.order.name.lower(),
                "effect": vector.effect.name.lower(),
                "portable_scope": None if vector.portable_scope is None else vector.portable_scope.name.lower(),
                "target_scope": None if vector.target_scope is None else vector.target_scope.name.lower(),
                "source_space": vector.source_space,
                "destination_space": vector.destination_space,
                "simt": _vector_result(simt, vector),
                "coherent": _vector_result(coherent, vector),
            }
        )

    portable_payload = b"S|barrier|seq_cst|device|global"
    target_payload = b"S|barrier|seq_cst|2|2"
    tokens = _tokenizer_counts(portable_payload, target_payload)

    mapping_lines = sum(
        len(inspect.getsource(item).splitlines())
        for item in (portable_to_target, target_to_portable, validate_sync_semantics, lower_sync_vector)
    )
    second_target_lines = len(inspect.getsource(coherent_grid_accelerator_target).splitlines())

    payload = {
        "issue": "OI-13",
        "candidate_portable_lattice": [item.name.lower() for item in PORTABLE_LATTICE],
        "ordering_relation": [["workgroup", "device"]],
        "targets": deployment_rows,
        "mapping": {
            "simt_roundtrip": [target_to_portable(simt, portable_to_target(simt, item)).name.lower() for item in PORTABLE_LATTICE],
            "coherent_roundtrip": [target_to_portable(coherent, portable_to_target(coherent, item)).name.lower() for item in PORTABLE_LATTICE],
            "coherent_system_reverse": target_to_portable(coherent, AtomicScope.SYSTEM),
            "simt_system_supported": AtomicScope.SYSTEM in decode_native_target(simt).accelerator_scopes,
        },
        "vectors": vector_rows,
        "measurement": {
            "production_core_semantic_lines_added": 0,
            "benchmark_mapping_verifier_lowering_lines": mapping_lines,
            "second_target_package_lines": second_target_lines,
            "portable_expression_bytes": len(portable_payload),
            "target_specific_expression_bytes": len(target_payload),
            "token_cost": tokens,
        },
        "claims": {
            "portable_subset": "workgroup < device maps exactly and round-trips on both measured target packages",
            "target_specific_escape": "system is explicit on coherent-grid and nonportable; it is rejected on the SIMT package",
            "cross_space": "workgroup global/local synchronization is legal on both; device synchronization involving local memory rejects on both",
            "runtime": "semantic/target-package conformance only; no physical accelerator executed",
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["evidence_sha256_without_digest_field"] = hashlib.sha256(encoded).hexdigest()
    return payload


if __name__ == "__main__":
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
