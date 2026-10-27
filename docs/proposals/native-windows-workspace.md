# Native Windows construction and transactional workspace requirements

Date: 2026-10-27. Status: proposal; not a published or implemented contract.

This is a host-independent XAX requirement. It adds no MCP protocol, agent framework, adapter, dependency or
application implementation to the language/compiler repository. Canonical semantic stores remain authoritative;
all requests and mutation records below are transport.

## Observed native boundary

At XAX `main` `fdc7312d60e12b6e784d920217f09df535090d55`, the generic driver's file commands remain `lower`,
`build`, `verify`, `inspect`, `resolve`, `edit` and `resolve-trusted`. Native inspection returns a binary root
and object/reference table; it is not the complete bounded workspace query interface. The generic command
table does not dispatch `construct`. The separate constructor's implementation tooling exists in
`compiler/integration/construct`, but its verified canonical program store and reproducible native Windows
executable are not committed. Requiring its Python builder does not satisfy a Windows XAX-only workflow.

A recovered native Windows compiler, SHA-256 `ff0355c5bf148bc79cf463748a285c3f982b6c8e47faf8d2d25bd3571b2ad638`,
source root `2b8136a8e052ccefd88f31b5d906dc986a070f2ca6e370668b73b17783ed3d17`, successfully inspected, edited,
verified, resolved and built small canonical Windows programs. It declined `build` on the current committed
Windows driver store with exit 2. This is not a current compiler self-build or a pin-equivalence claim.
The host has no WSL, Linux VM or installed carrier decoder. No interpreter bootstrap was run to fill those gaps.

The native editor checks mutation preconditions but is not itself a verified atomic workspace commit. A record
inserting wrapping add over a bits32 node and an effect parameter produced a candidate that later native
`verify` rejected with `XAX.STRUCT.OP_TYPE / GRAPH-OP-TYPE`. The consumer must not publish such an editor output.

## Smallest upstream deliverables

1. Commit the constructor's actual canonical `.xax` state and its exact native Windows seed identity, with the
   existing bounded `construct <carrier> <candidate-store>` argument-vector interface. Reproduce it using
   verified native XAX tools. Reject unsupported carriers explicitly; never execute a source emitter or another
   language as a hidden fallback. Preserve existing `xax-construct-v1` semantics and reference byte identity.
2. Publish a Windows native compiler seed and exact source/build identities with a native-only reconstruction
   recipe. Document accepted target/operation subsets and native decline cases. Keep historical bootstrap
   provenance separate from current execution authority and do not promote whole-compiler B milestones.
3. Provide a general verified candidate operation: apply `XAXEDIT1` against an exact root, fully verify the
   candidate, return compact diagnostics on rejection/decline, and leave publication to a documented atomic
   workspace commit with a final root/read-set check. Existing `edit` semantics must not silently change;
   introduce an explicitly versioned operation or contract for the stronger guarantee.
4. Expose existing bounded entity/operand/use/type/effect/proof queries through a native host interface. Return
   exact root/generation, scoped local handles, deterministic bounds and explicit truncation/continuation.
   Do not create another graph store or semantic authority in a consumer.

Start with file/argv operations that extend the current driver. A long-running daemon or private transport is
not required to unblock construction and verified commit. A future native service can use the same semantics.

## Candidate and publication rule

The stronger operation must execute: check expected root/read set -> stage mutation -> verify every required
invariant -> recheck the publication base -> atomically publish. Until publication succeeds, the current root
and generation remain unchanged. Rejection, native decline, I/O error, cancellation or timeout retains the old
state and removes scratch output. A diagnostic file is never a canonical candidate. Verification success
does not grant permission to execute generated native code.

Required native regressions include stale roots, invalid operand/result types, valid novel arithmetic graph
construction, output-path errors, interrupted publication and byte-identical native reconstruction. Keep exact
compiler/target/policy/artifact provenance. An exit 2 remains a decline with no validity claim.

The application consumer's graph examples and security fixtures belong in its own repository. This proposal
does not move them into XAX or duplicate their implementation. Existing upstream application-specific MCP
copies are migration debt, not a new dependency of ordinary XAX compilation.
