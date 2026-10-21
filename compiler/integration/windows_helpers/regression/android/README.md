# Android native build regressions

These two canonical snapshots exercise 512 nested loops. The zero-entry case
emits 01; the active case enters every loop, repeats the inner body three times
and emits 03 02 01 00. See [cases](cases.json) and
[evidence](../../native_android_lowering_evidence.json) for exact source,
artifact, provenance and device execution identities.

Run the native driver's verify and build commands with explicit diagnostic,
artifact and provenance paths. Deploy the resulting ELF to an Android ARM64
device and require exact output bytes and exit 0. Redirect binary output on the
device and pull the file; a terminal is not a byte-preserving transport.
These are Windows-hosted native cross-builds with actual Android execution.
They do not implement an Android-hosted compiler or a complete source command.
