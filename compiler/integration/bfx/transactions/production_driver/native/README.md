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
