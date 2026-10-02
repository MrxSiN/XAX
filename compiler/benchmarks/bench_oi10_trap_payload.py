"""Deterministic OI-10 evidence: portable trap core across two native targets."""
from __future__ import annotations

import json
from pathlib import Path

from xax_aarch64 import compile_aarch64
from xax_compiler import (
    Block, Kind, StoreReader, Terminator, TrapReason, XaxTrap,
    aarch64_baremetal_target, decode_trap_payload, function, graph_fragment,
    object_with_refs, trap_diagnostic_json, trap_payload, write_store,
    x86_64_windows_target,
)
from xax_x86_64 import compile_native

OUT = Path(__file__).with_name("oi10_trap_payload_evidence.json")
REASON = 0x1234


def fixture(target, detail: bytes):
    graph = graph_fragment([Block((), (), Terminator.trap(trap_payload(REASON, detail)))])
    fn = function(graph, (), ())
    module = object_with_refs(Kind.MODULE, [fn, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    reader = StoreReader(write_store(root.cid, [graph, fn, target, module, root]))
    return reader, graph, fn


def build():
    targets = []
    for name, target, compiler, detail in (
        ("x86_64-windows", x86_64_windows_target(), compile_native, b"windows-exception-detail"),
        ("aarch64-baremetal", aarch64_baremetal_target(), compile_aarch64, b"firmware-detail"),
    ):
        reader, graph, fn = fixture(target, detail)
        image = compiler(reader, fn.cid, target.cid)
        alt_reader, alt_graph, alt_fn = fixture(target, b"different-target-detail")
        alt_image = compiler(alt_reader, alt_fn.cid, target.cid)
        reason, suffix = decode_trap_payload(trap_payload(REASON, detail))
        trap = XaxTrap(trap_payload(REASON, detail))
        targets.append({
            "name": name,
            "target_cid": target.cid.hex(),
            "graph_cid": graph.cid.hex(),
            "alternate_detail_graph_cid": alt_graph.cid.hex(),
            "portable_reason": reason,
            "target_data_hex": suffix.hex(),
            "machine_code_hex": image.code.hex(),
            "machine_code_bytes": len(image.code),
            "alternate_detail_same_machine_code": image.code == alt_image.code,
            "diagnostic_json": trap_diagnostic_json(trap),
        })
    return {
        "schema": "xax-oi10-trap-payload-evidence-v1",
        "portable_core": {
            "encoding": "empty => reason 0; otherwise canonical ULEB u16 reason followed by opaque target/platform bytes",
            "reason_bits": 16,
            "reasons_standardized_in_prototype": {
                "0": TrapReason.UNSPECIFIED.name.lower(),
                "1": TrapReason.EXPLICIT.name.lower(),
            },
        },
        "targets": targets,
    }


if __name__ == "__main__":
    evidence = build()
    OUT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(OUT)
