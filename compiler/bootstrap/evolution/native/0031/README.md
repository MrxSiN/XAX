# Ledger 0031: main's file and exit calls go through host functions (ADR-402)

Applied with `../../evolve.sh apply` to the driver and the request, one batch each, written from `xaxc edit <store>
F226`'s view of main (`3a16ee9b…`, after ledger 0030) and accepted by `xaxc verify`:

| Batch | Store |
|---|---|
| `0031-host-functions.batch` | the driver |
| `0031-host-functions-request.batch` | the request (its own `R` line; the rest is the same text) |

**Host functions.** Five functions with exactly the signatures of the Windows hosting layer's adapters, each one call
of the Linux syscall declaration it wraps:
- `host_open (fd, path ptr, view, memory, flags, mode, fs) -> (ptr, view, memory, fs, result)`,
- `host_read`, `host_write (fd, buffer ptr, view, memory, length, fs) -> (ptr, view, memory, fs, result)`,
- `host_close (fd, fs) -> (result, fs)` and `host_exit (status, process) -> (process)`.

The view operand is the token of the memory the call touches: the Windows adapters borrow it, and on Linux it passes
through.

**Main.** `define @xaxc_main` is main's view with its 17 `openat`, 5 `read`, 13 `write`, 17 `close` and 1
`exit_group` calls made calls of those functions; a later use of a token an adapter took uses the token it gives back.
No other node changes.

**Not moved: `argc` and `arg_copy`.** They are startup reads, which only the process entry may make on Linux
(`LINUX-STARTUP-PROCESS-ENTRY`); a probe that moved them built a store the seed's `build` rejected with that rule. The
Windows hosting batch ports those three sites (`../../windows/README.md`).
