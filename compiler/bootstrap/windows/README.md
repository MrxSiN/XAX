# Native Windows seed — xax-native-file-v1

`xaxc-windows-x86_64.exe` packages the existing XAX-built alias-index driver as a trusted Windows x86-64 seed:
11,876,864 bytes, SHA-256 `aa72234d6dd8a111efde62b47ced8449a482c4c5506d876714ff7fbe0968ab79`.
Its original canonical source is `compiler/integration/windows_helpers/driver.xax` at
`c97a11d0d1762c863ae9fc17ca311954d195aaba`, root
`ec66899fddc117eb0496bbd504e06742daf9931d0b8e64e9efde0725dae45ebd`, source SHA-256
`894820c6ec0b777232ac6817f454add9f00493f95c72d53071de8ed4c690eced`.
The recovered source blob was compared with that Git revision byte for byte. Exact identities are in `seed.json`.

Its historical bootstrap used the Python SDK. No interpreter bootstrap was executed to publish or test this seed.
The executable contains XAX machine code and Windows system imports; it starts no interpreter. Native build of
its own large compiler source still declines. This trusted seed does not establish a Windows self-build fixed
point, remove bootstrap trust or promote B/R levels.

## Versioned file contract

Invoke directly with an argument vector:

```text
xaxc-windows-x86_64.exe verify <store> <diagnostic>
xaxc-windows-x86_64.exe inspect <store> <inspection-record>
xaxc-windows-x86_64.exe edit <store> <XAXEDIT1-carrier> <candidate-store>
xaxc-windows-x86_64.exe resolve <request-store> <snapshot-store>
xaxc-windows-x86_64.exe build <snapshot-store> <artifact> <provenance>
```

Exit 0 is success, 1 is rejection with a native diagnostic, 2 is decline with no validity/build claim and 3 is
usage/I/O failure. Successful verification writes an empty diagnostic. `edit` constructs a candidate; callers
MUST run `verify` before accepting it. It does not provide atomic workspace publication. `inspect` retains the
existing binary root/object/reference record; `resolve` and `build` retain the canonical build formats.
Unsupported cases reject or decline. `construct` is not a seed command. Pin the seed digest rather than moving
`main`. This contract is not the proposed bounded workspace service or an arbitrary runtime-argument ABI.

## Native-only example

The unchanged generic BLAKE3 host now has a canonical build request independent of application repositories:

```text
compiler/bootstrap/windows/xaxc-windows-x86_64.exe verify compiler/integration/windows_helpers/hash_request.xax hash.diag
compiler/bootstrap/windows/xaxc-windows-x86_64.exe resolve compiler/integration/windows_helpers/hash_request.xax hash-snapshot.xax
compiler/bootstrap/windows/xaxc-windows-x86_64.exe build hash-snapshot.xax xax-hash.exe hash.prov
```

The `xax_hash_cli` package references the existing `hash_host.xax` function closure without changing semantic
objects. Its executable reads raw stdin and emits a 32-byte digest. Empty and `abc` official vectors were checked.
No MCP implementation, schema or dependency is included. See `native_seed_evidence.json` in the Windows helpers.
