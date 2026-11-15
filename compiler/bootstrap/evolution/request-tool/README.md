# The build request a driver store compiles to, as an XAX program

`xax_request.xax` is a Linux x86-64 process, an XAX build request store (RFC
`docs/proposals/build-bootstrap-rotation-rfc.md` §6, step 5 of §13.7).

```text
xax_request <driver> <target> <out>
```

It writes the build request store for the driver store `<driver>`: the same transformation as the reference
`xax_selfhost_compiler.compiler_request`. `<target>` is a target object as a file: kind, schema, references and body,
the bytes a CID hashes after the domain. `x86_64-linux-elf-exec-v1.target` is the Linux one.

- The driver's objects are kept byte for byte, except its program root.
- Three objects are added: the profile, the package `xax-compiler` (its module and, as build entry `xaxc`, the
  module's first function), and the build request. The target object is added too when the driver lacks it.
- Each new object's reference indices follow CID order, and each CID is the program's own BLAKE3 hash.
- The store is written: the header naming the request as root, the records in CID order, the index, and the
  whole-store digest.

`sh request.sh <driver> <target> <out>` builds the program with the pinned seed (`XAXC` names another compiler) and
runs it. Exit status 0 means the store was written; 1 means the driver has no program root, module or function
entry, or is not under 63 MiB, and nothing is written.

How it was made, without a generator of its logic:

- `request.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `../ledger-tool/seed.xax`, the ledger tool's
  one-function seed. Its result is `xax_request.xax`, and `xaxc verify` accepts it.
- The batch supplies its own pointer, view and declaration objects:
  - buffers are `ptr<bits32>` views, because the BLAKE3 entry takes that type, and a cast from `bits8` to `bits32`
    is declined;
  - so every access is 4 bytes wide, and a byte store is a read-modify-write of its word;
  - mmap, munmap, read and write declarations are supplied for those pointer and view types.
- `@b3` and `@b3c` are the views of `../../xax_blake3_hash.xax` (S2) as `xaxc edit` shows them. Their CIDs are
  unchanged.
- Change it by a further batch on `xax_request.xax` (`xaxc edit` lists and shows its functions), then `xaxc verify`.

Limits:

- The driver must be under 63 MiB (66,060,288 bytes). The index is staged above that in the 64 MiB output view, and
  the BLAKE3 entry reads at most 64 MiB. The ledger 0032 driver is 62,593,194 bytes. A larger driver needs larger
  views here and in the hash; the tool refuses before that point.
- A target file holds at most 191 bytes.
- The driver's metadata records are not copied. It has none, and the request has none.

Checked on Linux x86-64 (WSL 2, the pinned seed `0cd26742…`), EXECUTED:

- On the ledger 0032 driver with the Linux target, the output equals `seed/xax_compiler_request.xax` byte for byte
  (SHA-256 `8345f64d…`), which the reference `compiler_request` also gives.
- It took 3.3 s wall time and 123 MB peak RSS; a request-mirror ledger transaction takes about 41 s of `edit`.
- A missing driver file exits 1 and writes nothing.
