# The BFX command budget: 65,536 to 524,288 (issue #55, 2026-11-18)

`compile_bfx` rejected any program with more than 65,536 commands before folding (status 3), and the record view
that it, the strict decoder, the importer and the hosts share was 65,546 bytes. The budget is now N = 524,288
(2^19), above the 296,307 commands of ThreadsHideAds' largest policy program (BBC issue #4).

| Batch | Store | Parent root |
|---|---|---|
| `0037-bfx-budget-compile.batch` | `../../compile.xax` | `e8c3e53a…` |
| `0037-bfx-budget-bbc.batch` | `../../bbc.xax` | `b7bfa0a3…` |
| `0037-bfx-budget-request.batch` | `../../bbc_request.xax` | `b14fecd1…` |

What changes, per function (handles of `bbc.xax`; `compile.xax` holds the two coordinators as F1 and F3):

- The record view type: 65,546 bytes becomes N + 10 = 524,298 (`@rec`, `3e380ee0…`). The decoder's scratch view:
  524,288 bytes becomes 8N = 4,194,304 (the store's `6dff1135…`).
- F466 `decode_bfx`: record length at most N + 10, body at most N, the bracket stack at scratch offset 4N.
- F601 `compile_bfx` (O0): the stream_chunks count at most N + 3. F827 (O1): the pre-optimization total at most N.
  The check order is unchanged, so a program over the budget still returns 3 even after an earlier bracket error.
- F633, F819, F905 (the hosts): the record and scratch allocations and their heap views; F819's BFX stdin cap for
  `info`. The VirtualFree declaration of a record view is supplied for the new type (`@free_rec`); the store already
  has the one for a 4,194,304-byte view.
- F297 `import_bfx`: only the two view types. Its 65,539 and 524,298 constants are words of the tables it writes.

Each batch defines the changed functions under new names, reaches them through `@` references, and replaces only
the top caller (F103 in BBC's stores, F1 in `compile.xax`), as ledger 0018 does: a batch may not redefine a
function and also its caller. Every other entity is a CID, so one batch serves `bbc.xax` and `bbc_request.xax`; only
the root line and the top handle differ. Apply one with `xaxc edit <store> <batch> <out>`, then `xaxc verify <out>`.

Not changed: the standalone stores (`bfx.xax`, `import_bfx.xax`, `pack.xax`, the Android and older Windows hosts)
keep the 65,536 budget. `bbc compile` of a program this large still meets OI-54 (a function view holds 2^18
values); `check`, `emit-bfx` and `info` need only this change.

## Step 2: 1,048,576, the source limit (2026-11-18)

The owner chose the largest budget the buffers allow: N = 1,048,576, the 1 MiB source limit (a command is one source
byte, and O0's instructions fit `output/work`'s 1,114,112 bytes). The record view is N + 10 = 1,048,586 bytes
(`5a76e8d9…`) and the decoder scratch 8N = 8,388,608 (`e9ce063c…`). Both types and both `VirtualFree` declarations
are supplied (`@rec`, `@scr`, `@free_rec`, `@free_scr`).

| Batch | Store | Parent root |
|---|---|---|
| `0037-bfx-budget-1m-compile.batch` | `../../compile.xax` | `2397a010…` (step 1's result) |
| `0037-bfx-budget-1m-bbc.batch` | `../../bbc.xax` | step 1's result |
| `0037-bfx-budget-1m-request.batch` | `../../bbc_request.xax` | step 1's result |

The changed nodes are step 1's, with step 1's values as the old ones; the handles are those of step 1's results
(`bbc.xax`: F625, F786, F838, F554, F130, F64, F741, top F195; `compile.xax`: F2 and the top, F3).

No source can now have more commands than the budget, but "too big beats a bracket error" still holds: a source over
1 MiB fails the frame's declared-capacity check (status 3), which comes before the bracket check. The overflow cases
are therefore 1,048,577-byte sources.
