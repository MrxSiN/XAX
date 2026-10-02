# OI-27 bootstrap trust-diversity report

## Selected threshold

For trust-sensitive `xax-semantic-image-v1` releases, retain the ordinary OI-26 Python seed path and run the release-only Go checker in `oi27_independent_checker.go`. The checker independently validates suite-1 BLAKE3/CIDs, canonical store/index structure, and the bounded M11/M14 semantic subset, then re-emits canonical bytes. The compared root is pinned; the comparison projection is raw byte identity.

A second full compiler/seed is not a standing maintenance requirement. The independent checker intentionally omits a general META evaluator, target lowerers, package resolution, and other production compiler services.

## Threat boundary

| Threat | Release-only checker coverage |
|---|---|
| compromised/divergent seed or compiler output | detects divergence from the pinned authoritative semantic root |
| compromised Python runtime/output transport | different Go implementation detects corrupt/divergent output |
| primary verifier omission/common implementation bug | independent bounded semantic checks catch the injected malformed arithmetic graph |
| serializer/hash bug | independent BLAKE3, object CID, store digest, ordering, reference and index checks catch the injected corruption |
| malicious/incorrect pinned authoritative graph | residual; this checker validates the declared semantics/root, not human intent |
| shared specification/test misunderstanding | residual common-mode dependency |

The Go checker and primary Python seed still share host hardware/kernel, the normative XAX specification, release authorization, and the BLAKE3 algorithm specification. These are not claimed away by diversity.

## Release procedure

1. Identify the exact authoritative compiler root, selected seed hash, Python runtime identity, checker source hash, Go toolchain identity, closure target, policy identities, and raw-byte comparison rule.
2. Reconstruct B2 and B3 with the selected Python seed.
3. Require B2/B3 and the committed authoritative image to be byte-identical.
4. Independently verify each image with the Go checker against the pinned root.
5. Independently re-emit the canonical store and require raw byte identity.
6. Reject any checker failure; do not fall back to the primary implementation.

The exact 2026-10-02 experiment is recorded in `../benchmarks/oi27_bootstrap_diversity_evidence.json` and raw host timings in `../benchmarks/oi27_bootstrap_diversity_timing.json`.
