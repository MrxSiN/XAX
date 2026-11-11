# The production driver hosted on Windows, natively (2026-11-06)

BBC's driver follows the production driver. This directory rebuilds the Windows-hosted production driver from the
current production store with native transactions: the seed's `xaxc edit` applies them and `xaxc verify` accepts the
result. It does not use the Python porter that wrote `../1_windows_host.edit` for ledger 0003, whose root no longer
exists.

| Step | Applies to | Result root |
|---|---|---|
| `1_windows_host.batch` | the production driver after ledger 0015, root `d1beeea0…3604` (blob `fc32dfd8`) | `ad201ea4…63f3` |
| `2_pe_target.edit` | that result | `b4273875…2827` |

1. **`1_windows_host.batch`** is a native batch.
   - It supplies 30 objects with `define`'s `object` form (ADR-375, ADR-378):
     - five types: `bits16`, a resource type, and stack `ptr<bits32>`, `ptr<bits64>`, `ptr<bits16>`;
     - the Win64 declarations: `VirtualAlloc`, `ExitProcess`, `VirtualFree` per (pointer, view) type pair, and the
       msvcrt and kernel32 functions the adapters call.
   - It defines BBC's six host adapters (`read`, `write`, `open`, `close`, `argc`, `argcopy`) from their views.
   - It redefines the entry from its own view, rewritten by `port_main.awk` with `main_map.txt`, and installs it with
     `replace`.
   - The objects and adapters are those of the ledger-0003 port, copied as they are. The two `VirtualFree`
     declarations for view types that ledger 0005 introduced (`45de6fb2`, `47768124`) are the `ed7f465b:dfec0616` one
     with the view type replaced.
2. **`2_pe_target.edit`** is an XAXEDIT1 record written by `replace_reference.sh`. It makes the module's target
   `x86_64-windows-pe-v1`, with the growable accesses (operations 77 and 78) in its list. The driver has used them
   since ledger 0009, and ADR-371 put them in the Linux lists only.

**`port_main.awk`** maps each Linux host call of the entry's view to its Windows form:
- `mmap` becomes `VirtualAlloc(0, n, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`;
- `munmap` becomes `VirtualFree(p, 0, MEM_RELEASE)`, its `bits32` result widened;
- `openat`, `read`, `write` and `arg_copy` become the adapters, which take and give back the view token of the memory
  they touch. Later uses of that token take the returned one, and the results are renumbered;
- `close`, `argc` and `exit_group` keep their operands.

On ledger 0003's entry it reproduces the old port's entry exactly (with type handles named by CID).
`vtypes.awk` lists each host call's operand types; it keys the `VirtualFree` map.

**Build and check.** A build request for the result (its module's entry, the PE target), the seed's `resolve` and
`build`: `xaxc.exe`, 33,202,176 bytes, SHA-256 `be6ea1d3…`. Under wine its `edit` listing and `verify` match the
Linux compiler's. Under wine it also resolves and builds the production compiler's request
(`bootstrap/seed/xax_compiler_request.xax`, ledger 0015) in 5 minutes. The result is byte for byte the Linux
x86-64 seed (`33046fc4…`), so the Windows-hosted driver compiles exactly as the Linux one does.

`tests/test_bbc_windows_host_port.py` replays the two steps with the seed. It starts from the production driver blob
`fc32dfd8` (from git) and checks the roots and `verify`.

## BBC's layer

BBC's own layer goes on top in native batches. It comes from the committed `../../../bbc.xax` (2026-11-07): the first
port took it from the ledger-0003 staged record `../2_bbc_layer.edit`, an older layer whose framing expected the host
request of 2026-10-21, so every compile's edit step was rejected (`WORKSPACE-EXPECTED-ROOT`).

- `layer.sh <bbc.xax> <W2 store> <work>` writes `layer_functions.batch`:
  - `layer.py` finds the layer: what BBC's entry reaches before the driver (functions W2 holds, and the entry's
    callees with 24 or more parameters: the driver entry and its four variants);
  - each function's view goes through `portable.awk` (a layer function becomes `@L_<cid8>`, any other callee its
    CID), callees before callers (`tsort`);
  - then four `@STUB` places for the variants, `helpers.batch` (the compile steps' argument helpers and argument
    counts), and BBC's entry, `entry.view`: the store's entry without the graph proof cache (its 64 MiB reservation,
    passed to the step entries, is not carried).
- **Batch 3a** supplies the layer's declarations and types (`layer_objects.batch`) and defines the layer, with four
  distinct stubs in place of the driver entry variants. Then `replace` makes BBC's entry (the batch's last
  definition) the module's.
- `variants.sh` then replaces each stub with its variant, one batch each (`variant.awk` on that store's own main view):
  - all four variants reserve 17 of the 22 allocation sites with `MEM_RESERVE`/`PAGE_NOACCESS`;
  - the three `compile` steps call their argument helper instead of `arg_copy`, their own argument count instead of
    `argc` (resolve 4, edit and build 5: the main reads `argc` once), and `SetLastError` instead of `ExitProcess`.
  - One batch for all of it would exceed the driver's 16 MiB file view (`DRIVER-FILE-CAPACITY`).
- **Result** on the production driver after ledger 0019: root `1a582526…`, 72.3 MB, verified; it is now
  `../../../bbc.xax`. The seed builds `bbc.exe` in under 4 minutes (35,956,736 bytes). On the way, `build` first
  rejected the port (`NATIVE-CALL-ARITY`, fixed by ledger 0016), ran for hours (ledger 0017), filled the image buffer
  (ledger 0018) and passed `VCAP` (ledger 0019).

## Rebuilding BBC's driver after a production transaction (2026-11-12)

`rebuild.sh <production driver store before> <batch> <BBC driver store> <out>` applies one production ledger
transaction to BBC's store: the transaction's own batch through `xaxc edit`, then `xaxc verify`. It rewrites only the
batch's store handles (the root line; a production handle `F<n>` becomes the function's CID as an entity, or BBC's
handle on the function line and in `replace`). The edit engine rebuilds every caller, so BBC's entry and its four
driver entries follow without being named. It runs sh, grep, cut, sed, sort and `xaxc`; no Python and no awk.

It replaces the from-scratch rebuild below, which needed `cids.py`, `port_main.awk`, `main_map.txt`, `variants.sh`
and `variant.awk` (removed; they are in git history). Check that it makes the same store: ledgers 0024 (two
transactions) and 0025 applied in order to the `bbc.xax` of ledger 0023 (blob `deca732e`) give the `bbc.xax` the old
rebuild made after ledger 0025, byte for byte (SHA-256 `d01ec218…`), in 3.5 minutes per transaction where the old
rebuild took 32.

`../../../bbc_request.xax` is BBC's build request (the module's entry and PE target, as `compiler_request` makes one).
Run `rebuild.sh` on it with the same batch, then `xaxc resolve bbc_request.xax <snapshot>` and `xaxc build <snapshot>
bbc.exe <provenance>`. It replaces `tools/request.py`: ledger 0026 applied to the request of the previous `bbc.xax`
equals the request made for the new one, byte for byte (SHA-256 `48099bcf…`).

Ceiling: a batch that names the production entry itself declines (exit 2): BBC's entry is that function's Windows
form. Such a transaction needs its own native batch for BBC's entry, written from BBC's view of it. The layer tools
(`layer.sh`, `layer.py`, `portable.awk`, `cnorm.awk`, `vtypes.awk`, `dump_objects.py`) are removed too: a change to
BBC's layer is a native batch on `bbc.xax`, written from `xaxc edit`'s view of the function. `tools/*.py` and the
`importer_split` awk files are still Python and awk; nothing in the rebuild runs them.

## Rebuilding BBC's driver from any production driver (superseded 2026-11-12)

`rebuild.sh <production driver store> <work directory>` ran every step with the seed and ended with `xaxc verify` of
`<work>/bbc.xax`:
1. the Windows-host batch, with the entry ported by `port_main.awk`;
2. the PE-target record;
3. batch 3a, BBC's layer with stubs;
4. the four variant batches (`variants.sh`).

Its inputs are portable: they name driver functions by CID, not by store handle, and the eager entry by `@MAIN`.
- `windows_objects.batch`: Win64 declarations and types;
- `adapters.batch`: the six host adapters;
- `layer_objects.batch`: BBC's declarations and types;
- `layer_functions.batch`: the 32 layer functions in call order, `@STUB` marking the variants' places, from
  `portable.awk` over the 0003 views;
- `main_map.txt`, `pe_target_growable.hex`.

`cids.py` only reads the CIDs a listing does not show: module, target, entry, and stubs.

**First run** on the production driver after ledger 0016: BBC's driver root `b032947f…`, 72.4 MB; `verify` accepts
it.
