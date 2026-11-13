# Ledger 0029: the portable host memory ABI `xax-host-v1` (ADR-400)

Applied with `../../evolve.sh apply` to four stores, one batch each, all written as native view text from
`xaxc edit <store> <selector>` and accepted by `xaxc verify`:

| Batch | Store | Functions |
|---|---|---|
| `0029-host-abi-typing.batch` | `xax_op_typing.xax` | F61 (`a4663710…`), F34 (`54c8849b…`) |
| `0029-host-abi-x86-64.batch` | `xax_x86_64_general.xax` | F204 (`dd6b555b…`), new helpers |
| `0029-host-abi.batch` | the driver | F644, F333, F890 (the same three functions) |
| `0029-host-abi-request.batch` | the request | the same as the driver |

**Verifier.** F61 is the foreign declaration's ABI check: after its chain of known-ABI matches (N9666) it also
matches the 11 bytes `xax-host-v1` at the ABI's position and ors the result in, before `abi_known`. F34 writes
`FOREIGN-CALL-ABI`'s expected list: the count 26 becomes 27 and `xax-host-v1` is written last.

**Backend.** New functions: `host_uleb` (a ULEB or the position after it), `host_text` (the input bytes against one
of nine texts), `host_record` (an xax-host-v1 declaration's syscall record: `commit`/`reserve` with an allocator
contract first are mmap with allocator flag 1 or 2, `free` with a deallocator only is munmap of the token's view
extent, found by bisecting the store's objects on the token type's CID; 0 otherwise), `syscall_or_host` (`syscall`'s
record, else `host_record`'s), `host_import` (the store's `kernel32.dll` VirtualAlloc or VirtualFree win64-c
declaration), `host_call` and `host_tail`. In F204, the register path's foreign call:
- its `syscall` call (N440) calls `syscall_or_host`;
- a declaration of no known ABI class that has a record is owned: on Linux it joins the owned classes (B632), on
  Windows it is not rejected (B631); on Linux it then takes the syscall path unchanged;
- in the Win64 import path the `ab(0x15FF, 2)` call (N8121) becomes `host_call(fc_obj, fc_rec)`: the same two bytes
  for an ordinary import; for a host call first the argument setup after the operand in rcx, and the declaration the
  fixup names becomes the kernel32 one (N8257 stores `host_call`'s result); NONE declines;
- the `ab(0, 4)` displacement (N8301) becomes `host_tail(fc_rec)`, which adds `test eax, eax; sete al; movzx eax, al`
  after a host free.

`syscall` (F87) is not changed: replacing it and its caller `foreign_call` in one batch left the caller's rebuilt
old form in the store, unreachable (`ID-ROOTED-STORE`). The frame path's own `syscall` call (F167) therefore lowers
no host call.

**Checks.** `tests/test_xax_host_abi.py`: on Linux the host program's image equals the mmap/munmap program's with the
reference and with the XAX general program, and runs; the PE image built by either is the same bytes and runs on
Windows 11 (exit 18). The Linux seed rotated twice reaches its fixed point; `write-request` leaves the request
unchanged; BBC's stores are rebuilt with `rebuild.sh`; the Windows seed cut from them reaches generation 2 = 3.
