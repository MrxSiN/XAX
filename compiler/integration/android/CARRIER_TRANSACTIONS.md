# Platform carrier replacement v1

`Workspace.bind_object(cid, byte_budget=...)` binds one exact existing object
at the current generation. Use its handle in the read set and in
`ReplaceTarget(handle, expected_old_cid, new_identity_only_target)` under
`Transaction(RootRef(workspace.generation), ..., read_set=...)`.

The workspace constructs a private candidate using canonical constructors for
MODULE, PACKAGE, build request and snapshot ancestors. All new objects verify.
Affected unsigned/signed Android APK requests also lower privately before
publication; this does not sign or publish an artifact. Commit checks generation
again after verification. Candidate-only verify and rollback preserve the root.
Machine targets, signature/provenance reconstruction, stale carrier rebase,
duplicate handles and wrong old identities reject. A stale caller must requery.
Old capabilities, resolver identity, policy and external input digests survive;
package signatures must be renewed separately. No new kernel operation or
textual application language is introduced.

The bounded contract covers identity-only TARGET carriers and supported acyclic
ancestor kinds. It does not promise platform-specific validation for an arbitrary
TARGET outside an affected Android build request. Runtime callbacks, ownership,
permissions and projection are separate contracts.

Run `python -m pytest tests/test_xax_workspace_targets.py -q` with compiler/src
on PYTHONPATH. Tests include durable reopen/build, private rollback, rejection,
two coordinated carrier edits, provenance preservation and root-byte ABA races.
AutoHead separately retains its exact version 1 -> 2 transaction, signed build
and original-Pixel installation/SurfaceView/relaunch evidence.
