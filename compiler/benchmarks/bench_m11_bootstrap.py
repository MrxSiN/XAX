"""Deterministic M11 B0/B1 bootstrap evidence; deliberately non-timing."""

from __future__ import annotations

import json
from pathlib import Path

from xax_bootstrap import (
    M11_CONFORMANCE_VECTORS,
    M11_EVIDENCE_FILENAME,
    build_m11_hosted_subset,
    compare_m11_vectors,
    load_m11_bundle_from_directory,
)


BOOTSTRAP_DIR = Path(__file__).resolve().parents[1] / "bootstrap"


def evidence_record() -> dict[str, object]:
    bundle = load_m11_bundle_from_directory(BOOTSTRAP_DIR)
    first = build_m11_hosted_subset(bundle)
    second = build_m11_hosted_subset(bundle)
    comparisons = compare_m11_vectors(bundle, first)
    return {
        "milestone": "M11",
        "bootstrap_labels": ["B0", "B1"],
        "declared_subset": "bits32 arithmetic constant folder: selector 0 add.wrap, selector 1 mul.wrap",
        "authoritative_program": "canonical .xax semantic store",
        "bootstrap_target": "wasm32",
        "program_root": bundle.program_root.cid.hex(),
        "module_root": bundle.module.cid.hex(),
        "entry_function_root": bundle.entry.cid.hex(),
        "package_root": bundle.package.cid.hex(),
        "snapshot_root": bundle.snapshot.cid.hex(),
        "request_root": bundle.request.cid.hex(),
        "target_root": bundle.target.cid.hex(),
        "build_profile_root": bundle.profile.cid.hex(),
        "trust_policy_root": bundle.policy.cid.hex(),
        "seed_compiler_identity": first.provenance_view.compiler_identity.hex(),
        "lowering_identity": first.provenance_view.lowering_identity.hex(),
        "provenance_root": first.result.provenance.cid.hex(),
        "program_store_bytes": len(bundle.program_store.data),
        "bootstrap_store_bytes": len(bundle.build_store.data),
        "artifact_bytes": len(first.result.artifact),
        "artifact_digest": first.result.artifact_digest.hex(),
        "repeat_build_identical": first.result == second.result,
        "conformance_vector_count": len(M11_CONFORMANCE_VECTORS),
        "seed_hosted_all_match": all(item.matches for item in comparisons),
        "vectors": [
            {
                "arguments": list(item.arguments),
                "seed": list(item.seed_result),
                "hosted": list(item.hosted_result),
                "match": item.matches,
            }
            for item in comparisons
        ],
        "claims_not_made": ["B2", "B3", "B4", "B5", "B6"],
    }


def main() -> None:
    record = evidence_record()
    destination = BOOTSTRAP_DIR / M11_EVIDENCE_FILENAME
    destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
