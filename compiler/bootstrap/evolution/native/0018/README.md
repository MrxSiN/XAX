# Ledger 0018: the x86-64 image buffer packed eight bytes to a word (ADR-381)

The general backend kept the code image one byte per workspace word, at `IMAGE_BUFFER_AT` (200M words) with
`IMAGE_CAP` = 2^25 bytes: the 32M words up to the image record at 232M. BBC's program (about 37 MB of code) filled
it after 954 of 1,060 functions. The buffer is now packed eight bytes to a word, little-endian, in place: 48 MiB take
6M words, so `IMAGE_CAP` is 48 MiB, and the container buffer (`I_ELF`, still one byte per word, in the arena) and its
cap follow at 48 MiB + 64 KiB.

The image buffer's readers and writers are ten functions, the same objects (by CID) in the driver, the request and
the x86-64 general program; `sites.txt` lists them with their accesses:

| function | accesses of the image buffer |
|---|---|
| `image_add` | the padding and the code copy (2 stores) |
| `image_adapter` | each entry adapter's bytes (12 stores) |
| `image_finish` | the call and address fixups (2 stores) and the raw Windows image's copy (1 load) |
| `elf_static`, `pe` | the code's copy into the container (1 load each) |
| `elf_dynamic` | the GOT bindings (1 store) and the copy (1 load) |
| `image_snapshot` | its copy of the image (1 load from the image, 1 store to the snapshot, packed too) |
| `image_record` | the record's image bytes from the image or the snapshot (1 load) |
| the program's main, `dll_edata` | only the container buffer's size or cap |

The sites were found by following, through `add.wrap` and block parameters, every value derived from a load of
`_ra(210)` (the image) or `_ra(229)` (the snapshot) to the workspace accesses whose byte address it is, and by the
generator source of these functions (`git show 4a5d4b8^:compiler/src/xax_selfhost_general_image.py`). They are node
handles of these views, which are the same in every store apart from callee handles. To regenerate a store's batches:

```text
xaxc edit <store> <empty file> <list>                     # F<n> <CID>
xaxc edit <store> <file with F<n>> <dir>/F<n>.view        # for each function of sites.txt
sh mkbatch.sh A <list> <dir> <batch A>                    # nine functions, main replaced
xaxc edit <store> <batch A> <A.xax>                       # (evolve.sh apply does this)
sh mkbatch.sh B <A's list> <A's views> <batch B>          # image_add, from A's own view
```

- `pack.awk` rewrites each access. The old byte address A comes from the access's clamp chain; the base R is the
  buffer's start, reloaded from its register-allocation slot (`_ra(210)`, the image) or a value of the block that
  holds it (the snapshot's and the record's base). The word is R + (A - R)/8 and the byte lane (A - R) mod 8, as a
  multiplier M = 256^lane (computed from the lane's three bits). A store becomes a read-modify-write of the word
  (clear the lane, add the byte times M); a load becomes the word load and (word / M) & 255, which every later use of
  the old value takes. Fresh nodes are renumbered by `../0015/renumber.awk`.
- `view.sh` applies `pack.awk`, then the caps: 33554432 (2^25) -> 50331648 in `image_add` and `image_adapter`'s
  checks, 33619968 -> 50397184 in every container check and in the main's allocation of the container buffer. The
  main's other 2^25 (a views-backend global, word 56) is not the image cap and stays.
- `mkbatch.sh` writes two batches per store. Batch A defines the nine functions other than `image_add`, callees
  first, each call to another of them as `@name`, and replaces only the main. Replacing a function whose every caller
  is redefined in the batch left an old object unreachable (`XAX.IDENTITY.UNREACHABLE_OBJECT`) or a reference to a
  dropped one (`XAX.IDENTITY.OBJECT_MISSING`), and so did replacing `image_add` with the main in one batch (its
  replacement cascades through the view function into the main). Batch B, on A's result and from that store's own
  view, redefines and replaces `image_add`.

The packed buffer keeps the record's format: `image_record` already wrote the image eight bytes to a word, so the
driver and the hosts read the record as before. The AArch64 program has its own text buffer and record and is not
changed.
