# BFX 02: offset instructions and loop folding — 2026-10-29

BBC's [BFX specification](https://github.com/MrxSiN/BBC/blob/main/docs/02_BFX_CONTRACT.md)
moved to format id `02`: no count field (the body ends at a mandatory `FF` END byte),
and four offset instructions that BBC's new `fold.bf` pass emits:

| Bytes | Instruction |
|---|---|
| `01 d k` | ADD: cell `p+d` += `k` |
| `02 d k` | MUL: cell `p+d` += cell `p` × `k` |
| `03 d` | CHECK: `p+d` is on the tape |
| `04 n` | MOVE: `p` += `n` |

`d`/`n` are signed bytes, `k` unsigned. Each fails with status 1 when its address is off
the tape. The arithmetic power opcodes `01`–`1C` of id `01` are gone. Id `01` records reject
(status 2); there is no legacy decoder.

## Decoder (`bfx.xax`, shared by the importer)

- Id `02`; a success is at least 7 bytes and its last byte must be `FF` (status 1 otherwise).
- Body length = record length − 7. The 65,536-instruction cap on that length is unchanged.
- Valid opcodes: the eight primitives, `00`, `01`–`04`. The loop advances by each
  instruction's length (1, 3 for ADD/MUL, 2 for CHECK/MOVE) and rejects an operand that
  would run past the body (status 5). Operand bytes are never read as opcodes or brackets.

## Importer emitter (`import_bfx.xax`)

- **Constant pool.** Block 0 of every emitted decision gains 254 `add.wrap` nodes making
  the `bits<32>` constants 2…255 from constant 1 (nodes 13…266). Emitted instructions refer
  to them, so each instruction block has a fixed shape and no new constant objects: the
  emitted store keeps its fixed 18-object reference set.
- **Handlers.** ADD, MUL, CHECK and MOVE each emit one decision block. The address is
  `p ± |d|` (`add.wrap`/`sub.wrap` chosen from the operand's sign); the bounds test is
  `address >u E−1`, which also catches a negative address. Accesses use
  `address & (flag − 1)`, so a failing instruction touches cell 0, never memory outside the
  tape, and then branches to the status-1 block; the tape is not observable after a failure.
  Every access remains a checked load/store.
- **Operand skipping.** The pre-pass and the emission loop advance by instruction length;
  the instruction-to-block table is indexed by byte offset, so brackets, edges and the final
  block are unchanged.
- **Payload at offset 6** (was 10), and the decision's input/output length check uses the
  view bound (`E−1`) instead of 65,536, so a decision can read and write more than 64 KiB.
  Hosts still pass at most 65,536.
- Dispatch for opcodes 1…14 as arithmetic powers is disabled; the remaining power handlers
  are unreachable under the new decoder.

## Frontend (`compile.xax`)

- The source coordinator writes `42 46 58 00 02 00`, the body at offset 6 and `FF`;
  it returns body + 7.
- `compile_bfx` O1 no longer calls the packer or the 3,840-gated clear pass. It copies the
  validated body into the source/work view, appends a zero byte and calls the `fold.bf`
  decision once on the whole body, then copies the result back and appends `FF`. If the
  decision fails, or the body plus 7 does not fit the 65,546-byte record view, it returns
  the O0 record unchanged. The packer and old clear decision drop out of the store.
- The `fold.bf` decision was compiled from BBC's own O0 record of `fold.bf` by the new
  importer, then retyped from the importer's 2,147,246,080-byte views to the frontend's
  1,114,112-byte work views (types and the `E−1` bound constant only), as the earlier view
  widening transactions did for the BF cores.

## Hosts

`compile_windows.xax` and `bbc.xax` replace the importer, decoder and `compile_bfx`
references (one record each). Their interfaces, buffers and the host build requests are
unchanged.

## Transactions

Expected-root `REPLACE_REFERENCE` records in [transactions/v2/](transactions/v2/). Each was
fully verified with the reference verifier, saved, and rejected as stale when replayed on
its result.

| Record | Store | Change |
|---|---|---|
| `1_importer_emitter.edit` | `import_bfx.xax` | Constant pool, handlers, operand skipping, offset 6, I/O bound |
| `2_importer_decoder.edit` | result of 1 | Decoder id 02, END, operand lengths |
| `3_coordinator.edit` | `compile.xax` | Source coordinator v2 framing |
| `4_facade.edit` | result of 3 | O1 through `fold.bf`, O0 fallback |
| `5_compile_windows.edit` | `compile_windows.xax` | Importer, decoder, facade references |
| `6_bbc.edit` | `bbc.xax` | Importer, decoder, facade references |

Authoring transport: short external Python scripts using the generic `xax_compiler`
constructors and `xax_selfhost_edit.edit_record` (not committed), the same method as the
earlier BBC transactions. No generic SDK file and no BBC Brainfuck changed in XAX.
