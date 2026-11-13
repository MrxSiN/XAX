# Native edits rebuild resolved snapshots

The transaction changes two native editor functions: the affected-user topology
check and the reference-carrying object scanner. It permits build snapshots
(form 3) alongside build requests (form 2), retaining the existing graph/function,
module, program-root and package boundaries. Recursion-group users, signatures,
provenance and other build forms remain unsupported rebuilding targets.

The new scanner preserves function interfaces and request fields, and rebuilds
package and snapshot reference collections in the resulting CID order. It uses
full ULEB reference indices, including values above 127. Exact package
dependencies are reordered while logical dependency names retain their canonical
order. Replacements that collide within a canonical collection reject with
`WORKSPACE-REBUILD-DISTINCT`, matching the reference constructor's rejection
instead of silently removing entries.

Snapshot request/policy references are rebound; resolver identity and external
digest bytes are copied exactly. Package/signature lists retain their roles.
Changing a signed package still encounters the unsupported signature user;
editing is not re-signing or new provenance authority. Verification remains
mandatory before publication.

The reference flags occupy the first 65,536 words of the existing editor STACK
region, which is unused until the later reachability phase. Temporary counters
start at STACK + 65,600, below BODY. Every helper finishes before reachability
uses that region. Per-entry reference emission is rolled back before canonical
list emission; no complete temporary list buffer is required.

The batches are native view carriers on the immutable driver and matching request,
with exact roots. The canonical stores remain authoritative. External reference
comparisons and malformed/alias/metadata probes are test orchestration only.

The transaction follows upstream ledger 0027's edge-copy staging fix. Its existing
callee identities were rebound to the updated driver and request inventories;
there is no separate compiler backend or foreign implementation in this change.
