# OI-26 bootstrap seed minimization report

This report is measurement-only. The historical `m14_seed_runtime.pyz` remains unchanged. Candidate archives are deterministically derived from that frozen seed snapshot and accept only the union needed by the approved M11 arithmetic B0/B1 component and M14 semantic-image reconstruction.

## Reachable accepted subset

Machine-readable details are in `oi26_seed_reachability.json`.

- Object kinds: `TYPE`, `GRAPH_FRAGMENT`, `FUNCTION`, `MODULE`, `PROGRAM_ROOT`.
- Operations: `ADD_WRAP`, `MUL_WRAP`, `CALL_DIRECT`, `META_MATERIALIZE_PROGRAM`, `META_VERIFY_SEMANTICS`, `META_CANONICAL_STORE`.
- Control: `RETURN`, `CONDITIONAL_BRANCH`.
- Suite-1 hashing: bundled in-tree pure-Python `blake3.py`; no external BLAKE3 package.
- External runtime: Python interpreter/standard library, recorded separately and not counted in seed archive bytes.

Every accepted store is passed through the existing verifier before evaluation. Valid excluded BUILD/PACKAGE/TARGET snapshots reject as `XAX.SEED.UNSUPPORTED_KIND`; a valid `SUB_WRAP` graph rejects as `XAX.SEED.UNSUPPORTED_OP`; corrupt stores reject before output publication.

## Measured candidates

| Candidate | Seed bytes | Compiler source lines | New seed-specific evaluator | Result |
|---|---:|---:|---:|---|
| historical baseline | 46,255 | 4,330 | 0 | viable |
| entry-pruned | 42,324 | 4,330 | 0 | viable |
| reachable-pruned | **32,017** | **3,050** | **0** | **selected** |
| specialized-subset | 27,392 | 2,492 | 30 | viable but rejected as practical default |

All three smaller candidates reconstruct B2 and B3/B4-style subsequent M14 generations byte-identically and reproduce all six committed M11 arithmetic vectors. The specialized candidate saves another 4,625 bytes versus reachable pruning, but only by adding a new seed-specific semantic evaluator. That duplicates semantic execution logic and enlarges the correctness surface, so pruning stops at `reachable-pruned`.

## Retained-feature reasons

- Canonical store reader/writer: required to load and reproduce the authoritative semantic image.
- CID/reference/root integrity and type/graph/function verifier paths: required because accepted artifacts are verified rather than trusted by assumption.
- Generic compile-time evaluator: required to avoid a second seed-specific semantic execution implementation while supporting both M11 arithmetic/control and M14 direct-call/META orchestration.
- BLAKE3-256 implementation: required for permanent suite-1 CIDs and store integrity.
- Python interpreter: still an external transitional bootstrap dependency; its bytes are not counted as seed bytes.

The selected subset is therefore the smallest *practical* candidate among those measured, not a claim of mathematical minimum.
