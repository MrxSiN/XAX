"""Deterministic OI-07 shared DMA resource-state vocabulary evidence.

The experiment uses two materially different synthetic target packages:
non-coherent split host/device memory and cache-coherent shared memory.  Both
use the same DMA resource-state IDs and generic TARGET_OP verifier machinery.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from blake3 import blake3

from xax_accelerator import compile_dma_flow, inspect_deployment, run_dma_deployment
from xax_compiler import (
    AtomicScope,
    Block,
    DmaAction,
    DmaResourceState,
    EffectDomain,
    Kind,
    Node,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    decode_native_target,
    dma_resource_types,
    effect_type,
    function,
    graph_fragment,
    object_with_refs,
    oi07_coherent_dma_target,
    oi07_noncoherent_dma_target,
    verify_store,
    write_store,
)

OUTPUT = Path(__file__).with_name("oi07_dma_evidence.json")


def _state_map():
    return {state: obj for state, obj in zip(DmaResourceState, dma_resource_types())}


def fixture(*, coherent: bool, omit_clean: bool = False, omit_sync: bool = False):
    b32 = bits_type(32)
    effect = effect_type(EffectDomain.DEVICE, 7)
    states = _state_map()
    target = oi07_coherent_dma_target() if coherent else oi07_noncoherent_dma_target()
    device_space = 1 if coherent else 2
    nodes: list[Node] = []

    def add(action, operands, results, scope, src, dst):
        nodes.append(Node(Operation.TARGET_OP, tuple(operands), tuple(results), entity=target,
                          attributes=(int(action), int(scope), src, dst)))
        return len(nodes) - 1

    i = add(DmaAction.ACQUIRE, (ValueRef.parameter(0, 2),),
            (states[DmaResourceState.HOST_UNMAPPED], effect), AtomicScope.SYSTEM, 1, 1)
    i = add(DmaAction.MAP, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
            (states[DmaResourceState.HOST_MAPPED], effect), AtomicScope.SYSTEM, 1, 1)
    host_write_state = DmaResourceState.HOST_MAPPED if coherent else DmaResourceState.HOST_DIRTY
    i = add(DmaAction.HOST_WRITE, (ValueRef.parameter(0, 0), ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
            (states[host_write_state], effect), AtomicScope.SYSTEM, 1, 1)
    if not coherent and not omit_clean:
        i = add(DmaAction.CACHE_CLEAN, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
                (states[DmaResourceState.HOST_MAPPED], effect), AtomicScope.SYSTEM, 1, 1)
    i = add(DmaAction.DEVICE_ACQUIRE, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
            (states[DmaResourceState.DEVICE_OWNED], effect), AtomicScope.DEVICE, 1, device_space)
    i = add(DmaAction.DEVICE_WRITE, (ValueRef.parameter(0, 1), ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
            (states[DmaResourceState.DEVICE_PENDING], effect), AtomicScope.DEVICE, device_space, device_space)
    if not omit_sync:
        i = add(DmaAction.SYNCHRONIZE, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
                (states[DmaResourceState.DEVICE_OWNED], effect), AtomicScope.DEVICE, device_space, device_space)
    host_state = DmaResourceState.HOST_MAPPED if coherent else DmaResourceState.HOST_STALE
    i = add(DmaAction.HOST_ACQUIRE, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
            (states[host_state], effect), AtomicScope.SYSTEM, device_space, 1)
    if not coherent:
        i = add(DmaAction.CACHE_INVALIDATE, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
                (states[DmaResourceState.HOST_MAPPED], effect), AtomicScope.SYSTEM, 1, 1)
    read_i = add(DmaAction.HOST_READ, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
                 (b32, states[DmaResourceState.HOST_MAPPED], effect), AtomicScope.SYSTEM, 1, 1)
    i = add(DmaAction.UNMAP, (ValueRef.node_result(0, read_i, 1), ValueRef.node_result(0, read_i, 2)),
            (states[DmaResourceState.HOST_UNMAPPED], effect), AtomicScope.SYSTEM, 1, 1)
    release_i = add(DmaAction.RELEASE, (ValueRef.node_result(0, i, 0), ValueRef.node_result(0, i, 1)),
                    (effect,), AtomicScope.SYSTEM, 1, 1)

    graph = graph_fragment((Block((b32, b32, effect), tuple(nodes),
                                  Terminator.return_((ValueRef.node_result(0, read_i, 0), ValueRef.node_result(0, release_i, 0)))),))
    entry = function(graph, (b32, b32, effect), (b32, effect))
    objects = (b32, effect, *states.values(), target, graph, entry)
    module = object_with_refs(Kind.MODULE, (b32, effect, *states.values(), entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*objects, module, root)))
    return reader, entry, target


def _negative(*, coherent: bool, **kwargs):
    try:
        reader, _, _ = fixture(coherent=coherent, **kwargs)
        verify_store(reader)
    except XaxError as error:
        return {"code": error.diagnostic.code, "rule": error.diagnostic.rule}
    return {"code": None, "rule": None}


def _flow_evidence(coherent: bool):
    reader, entry, target = fixture(coherent=coherent)
    verify_store(reader)
    first = compile_dma_flow(reader, entry.cid, target.cid)
    second = compile_dma_flow(reader, entry.cid, target.cid)
    view = inspect_deployment(first.deployment)
    description = decode_native_target(target)
    vectors = ((0, 0), (7, 9), (0xFFFFFFFF, 2), (0x80000000, 0x80000000))
    execution = [
        {
            "input": list(args),
            "result": list(run_dma_deployment(first, args)),
            "expected": [((args[0] + args[1]) & 0xFFFFFFFF)],
        }
        for args in vectors
    ]
    return {
        "target_identity": description.identity.decode(),
        "target_cid": target.cid.hex(),
        "program_root": reader.root_cid.hex(),
        "entry_cid": entry.cid.hex(),
        "memory_spaces": [
            {"id": s.identity, "host_visible": s.host_visible, "device_visible": s.device_visible}
            for s in description.memory_spaces
        ],
        "action_sequence": [DmaAction(i.semantic_code).name.lower() for i in view.instructions],
        "state_ids_used_by_target": sorted({
            c.secondary for op in description.target_operations for c in (*op.operands, *op.results)
            if c.kind.name == "RESOURCE"
        }),
        "synchronizing_actions": [DmaAction(i.semantic_code).name.lower() for i in view.instructions if i.synchronizes],
        "deployment_bytes": len(first.deployment),
        "deployment_blake3": blake3(first.deployment).hexdigest(),
        "deployment_sha256": hashlib.sha256(first.deployment).hexdigest(),
        "deterministic": first.deployment == second.deployment,
        "execution": execution,
        "all_execution_match": all(v["result"] == v["expected"] for v in execution),
    }


def collect_evidence():
    noncoherent = _flow_evidence(False)
    coherent = _flow_evidence(True)
    return {
        "schema": "xax.oi07-dma-v1",
        "shared_resource_kind": 1002,
        "shared_state_vocabulary": {state.name.lower(): int(state) for state in DmaResourceState},
        "shared_action_vocabulary": {action.name.lower(): int(action) for action in DmaAction},
        "state_type_cids": {state.name.lower(): obj.cid.hex() for state, obj in zip(DmaResourceState, dma_resource_types())},
        "flows": {"noncoherent_split": noncoherent, "coherent_shared": coherent},
        "negative": {
            "noncoherent_without_cache_clean": _negative(coherent=False, omit_clean=True),
            "noncoherent_without_synchronize": _negative(coherent=False, omit_sync=True),
            "coherent_without_synchronize": _negative(coherent=True, omit_sync=True),
        },
        "claims": {
            "shared_states": "six state IDs cover mapping, host/device ownership, cache-dirty/stale state, and in-flight unsynchronized device work in both packages",
            "cache_maintenance": "clean/invalidate are explicit only on the non-coherent package; coherent shared memory omits them",
            "synchronization": "device write produces device_pending; synchronize is the only transition back to transferable device_owned",
            "framework": "no device framework or new object kind; both flows use resource<K,state>, effect<device,7>, and generic target-op contracts",
        },
    }


def main():
    evidence = collect_evidence()
    OUTPUT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
