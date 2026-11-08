# Ledger 0021 (prepared, not applied): graph bodies up to 8 MiB

Withdrawn before it was committed: on its own it changes nothing a program can observe, because graphs are refused
earlier than the 4 MiB body view. Kept for the memory-layout redesign that hanoi -O0 needs (ADR-387).

What it does, tested on the driver after ledger 0020 (`xaxc edit` and `verify` accept the result; the seed builds the
new request to xaxc1 = xaxc2 = `3b0695f6…`, 31,543,818 bytes):
- supplies `heap_view<8 MiB>` (`e9ce063c…`) and two `munmap(ptr, 8388608)` declarations (`munmap4.hex`, the old ones
  with the length and the view CID swapped: `4df34c83…`, `7226b8ed…`);
- defines `@decode` (the graph decoder, `cb5dc08f…`) and `@main` (the driver's main, `2713dde0…`) from the store's own
  views through `body8.awk`: the body view type, the three body buffers' sizes and `heap.view` extents (4194304), the
  body-length bounds (4194304) and the body capacity (4194272) doubled, the munmap calls and `decode` call renamed;
- replaces main only. Replacing `decode` as well made the engine rebuild the old main beside the new one (both
  reachable, the old one's references dangling): `XAX.IDENTITY.OBJECT_MISSING`.
`mkbatch.sh <store> <batch>` makes the batch (6.4 MB) for the driver or the request from that store.

Applying it also needs BBC's port to map the two new munmap CIDs: in `integration/bfx/.../native/main_map.txt`
`4df34c83… @vf_af31b1f8_8m munmap` and `7226b8ed… @vf_099cffe0_8m munmap`, and in `windows_objects.batch` the two
`VirtualFree` declarations `@vf_af31b1f8` and `@vf_099cffe0` copied with the view CID `6dff1135…` → `e9ce063c…`.

Why it waits: O0 decisions of 1.1–2.7 MB verify, 3.1 MB and larger do not (exit 2, `verify`, `resolve` and the `edit`
listing alike), with or without this ledger. The limit near 3 M words matches the semantic index's graph-stream
region (`NODES_LIMIT = 3 << 20` words at word 20 M, below the section and facts regions at 23 M and 24 M); the edit
engine's `BODY_LIMIT` (4 MiB) and `VCAP` (ADR-386) come after it.
