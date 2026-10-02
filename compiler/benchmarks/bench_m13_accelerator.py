"""Deterministic M13 accelerator target/deployment evidence generator.

This is conformance/artifact evidence.  It does not claim hardware throughput,
latency, occupancy, or GPU performance because the declared target is a
prototype deterministic packet accelerator executed by a conformance harness.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from blake3 import blake3

from xax_accelerator import compile_accelerator, inspect_deployment, run_accelerator_deployment
from xax_compiler import (
    AtomicScope,
    Block,
    EffectDomain,
    Kind,
    Node,
    Operation,
    ResourceFlags,
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
    verify_store,
    write_store,
)


HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "m13_accelerator_evidence.json"


def fixture(*, launch_scope=AtomicScope.DEVICE, h2d_source_space=1):
    b32 = bits_type(32)
    effect = effect_type(EffectDomain.DEVICE, 1)
    host_buffer = resource_type(1001, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE, transitions=(2,))
    device_buffer = resource_type(1001, 2, flags=ResourceFlags.RELEASABLE, transitions=(1,))
    target = simt32_accelerator_target()
    nodes = (
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 2),), (host_buffer, effect), entity=target, attributes=(1, AtomicScope.DEVICE, 1, 1)),
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (device_buffer, effect), entity=target, attributes=(2, AtomicScope.DEVICE, h2d_source_space, 2)),
        Node(Operation.TARGET_OP, (ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)), (device_buffer, effect), entity=target, attributes=(3, launch_scope, 2, 2)),
        Node(Operation.TARGET_OP, (ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 1)), (device_buffer, effect), entity=target, attributes=(4, AtomicScope.DEVICE, 2, 2)),
        Node(Operation.TARGET_OP, (ValueRef.node_result(0, 3, 0), ValueRef.node_result(0, 3, 1)), (b32, host_buffer, effect), entity=target, attributes=(5, AtomicScope.DEVICE, 2, 1)),
        Node(Operation.TARGET_OP, (ValueRef.node_result(0, 4, 1), ValueRef.node_result(0, 4, 2)), (effect,), entity=target, attributes=(6, AtomicScope.DEVICE, 1, 1)),
    )
    graph = graph_fragment((Block((b32, b32, effect), nodes, Terminator.return_((ValueRef.node_result(0, 4, 0), ValueRef.node_result(0, 5, 0)))),))
    entry = function(graph, (b32, b32, effect), (b32, effect))
    module = object_with_refs(Kind.MODULE, (b32, effect, host_buffer, device_buffer, entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (b32, effect, host_buffer, device_buffer, target, graph, entry, module, root)))
    return reader, entry, target


def negative(rule: str, **kwargs) -> dict:
    reader, _, _ = fixture(**kwargs)
    try:
        verify_store(reader)
    except XaxError as error:
        return {
            "expected_rule": rule,
            "actual_rule": error.diagnostic.rule,
            "diagnostic_code": error.diagnostic.code,
            "matched": error.diagnostic.rule == rule,
        }
    return {"expected_rule": rule, "actual_rule": None, "diagnostic_code": None, "matched": False}


def run() -> dict:
    reader, entry, target = fixture()
    verify_store(reader)
    first = compile_accelerator(reader, entry.cid, target.cid)
    second = compile_accelerator(reader, entry.cid, target.cid)
    description = decode_native_target(target)
    view = inspect_deployment(first.deployment)
    vectors = ((0, 0), (1, 2), (7, 9), (0xFFFFFFFF, 1), (0xFFFFFFFE, 5), (0x80000000, 0x80000000))
    executions = [
        {
            "arguments": list(arguments),
            "result": list(run_accelerator_deployment(first, arguments)),
            "expected": [((arguments[0] + arguments[1]) & 0xFFFFFFFF)],
        }
        for arguments in vectors
    ]
    return {
        "milestone": "M13",
        "scope": "prototype non-CPU SIMT accelerator target package and deployment path",
        "program_root": reader.root_cid.hex(),
        "entry_function": entry.cid.hex(),
        "target_root": target.cid.hex(),
        "target": {
            "architecture_id": description.architecture,
            "deployment_format_id": description.image_format,
            "lane_width": description.accelerator_lane_width,
            "max_groups": description.accelerator_max_groups,
            "execution_scopes": [scope.name.lower() for scope in description.accelerator_scopes],
            "memory_spaces": [
                {
                    "id": space.identity,
                    "address_bits": space.address_bits,
                    "address_unit_bits": space.address_unit_bits,
                    "minimum_alignment": space.minimum_alignment,
                    "access_widths": list(space.access_widths),
                    "visibility_scopes": [scope.name.lower() for scope in space.visibility_scopes],
                    "host_visible": space.host_visible,
                    "device_visible": space.device_visible,
                }
                for space in description.memory_spaces
            ],
            "target_operations": [
                {
                    "id": contract.operation_id,
                    "semantic_code": contract.semantic_code,
                    "encoding_opcode": contract.encoding_opcode,
                    "scopes": [scope.name.lower() for scope in contract.supported_scopes],
                    "source_space": contract.source_space,
                    "destination_space": contract.destination_space,
                    "synchronizes": contract.synchronizes,
                    "may_block": contract.may_block,
                    "runtime_dependency": contract.runtime_dependency.hex(),
                }
                for contract in description.target_operations
            ],
        },
        "deployment": {
            "bytes": len(first.deployment),
            "blake3_256": blake3(first.deployment).hexdigest(),
            "sha256": hashlib.sha256(first.deployment).hexdigest(),
            "deterministic": first.deployment == second.deployment,
            "runtime_dependencies": [item.hex() for item in first.runtime_dependencies],
            "instruction_semantics": [item.semantic_code for item in view.instructions],
            "semantic_ranges": [
                {
                    "node": item.node_index,
                    "start": item.start,
                    "end": item.end,
                }
                for item in first.semantic_ranges
            ],
        },
        "execution": {
            "vectors": executions,
            "all_match": all(item["result"] == item["expected"] for item in executions),
        },
        "negative": {
            "unsupported_scope": negative("TARGET-OPERATION-SCOPE-SUPPORTED", launch_scope=AtomicScope.SYSTEM),
            "unsupported_memory_pair": negative("TARGET-OPERATION-MEMORY-SPACES", h2d_source_space=3),
        },
        "claims": {
            "fundamental_core": "generic target-op contract only; accelerator topology/space/opcode facts reside in target package",
            "host_device_semantics": "allocate, H2D transfer, launch, synchronize, D2H transfer, and free are explicit target operations threaded by one device effect and one linear buffer resource",
            "runtime_dependencies": "none for this target revision; any declared dependency would require explicit compiler permission",
            "performance": "not measured; no hardware throughput/latency claim",
        },
    }


if __name__ == "__main__":
    payload = run()
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
