# Ledger 0030: main allocates and releases through `xax-host-v1` (ADR-401)

Applied with `../../evolve.sh apply` to two stores, one batch each, written from `xaxc edit <store> F599`'s view of
main (`99a19fc7…`) and accepted by `xaxc verify`:

| Batch | Store |
|---|---|
| `0030-host-main.batch` | the driver |
| `0030-host-main-request.batch` | the request (its own `R` line; the rest is the same text) |

**Objects.** Fourteen `xax-host-v1` declarations (ADR-400), supplied with `define`'s `object` form: `commit` and
`reserve` (`(bits64, memory) -> (bytes_rw, heap owner, memory)`, the allocator contract of the mmap declaration they
replace) and one `free` per (pointer type, view type) pair of main's 13 munmap declarations (`(ptr, view, memory) ->
(bits64, memory)`, a deallocator only). Their bodies are the reference's `foreign_function_symbol` with
`XAX_HOST_ABI` and the library `host`, for exactly the types of the declaration each replaces.

**Main.** `define @xaxc_main` is main's view with only call entities changed, then `replace F599 @xaxc_main`:
- the 22 calls of the mmap declaration `d2ab6da2…`, in view order: sites 1–4, 6–9, 12–15 and 18–22 call `reserve`,
  sites 5, 10, 11, 16 and 17 (buffers the kernel reads or writes) call `commit`. That is the split BBC's Windows
  entry has made with `MEM_RESERVE`/`PAGE_NOACCESS` since its variants (ADR-400's memory contract);
- the 22 munmap calls (13 declarations) call the `free` of the same pointer and view types.

No other node, value or type changes. On Linux `xax-host-v1` lowers to exactly the syscall declarations' code, so
main's machine code is unchanged.
