# Diagnostic and test tools for the native BBC build (tooling only, never compiler logic)

Run from `compiler/` with `PYTHONPATH=src:reference:.`. All run the XAX general program (Python-hosted native image of
`bootstrap/xax_x86_64_general.xax`) or the seed; none of them decides anything the compiler decides.

- `request.py <driver store> <request out>`: a PE build request for a store's module (its entry, its target), as
  `compiler_request` makes one. Then `xaxc resolve <request> <snapshot>` and `xaxc build <snapshot> <exe> <provenance>`.
- `audit.py <store with a module>`: per function, in closure (CID) order, the analysis status (analysed/ineligible) and
  the emission status (`code`, or `None` = the frame path declined). Works even when the whole run declines; the line
  after the last record is where the run stopped.
- `probe_state.py <store>`: the stop state: status words, `E_F` (the function last in emit/frame), `R_*`, and the image
  slots (index 1 of the printed list is `I_LEN`, the image bytes so far; `IMAGE_CAP` is 2^25).
- `probe_order.py <store>`: the CIDs at chosen closure positions and `G_VCOUNT`/`G_BCOUNT` at the stop (`VCAP` = 2^18).
- `call_one.py <CID prefix> <out store> [source store]`: a PE entry that calls one function of a store with constant
  bits arguments and freshly VirtualAlloc'd views for each pointer/view/memory triple, to reproduce a per-function
  failure in isolation (then `audit.py` on the output).
- `check.py <bbc.exe> <work dir> [--bbc <BBC checkout>] [case ...]`: BBC's checks outside BBC. For 93 programs (pilot
  programs, BBC's tests, both depth-512 programs, negative loops, 60 random programs, capacity cases) it runs
  `wine bbc.exe compile <target> <level> <out>` for windows-x86_64 and android-arm64 at -O0/-O1, runs the result
  (wine / qemu-aarch64) and compares output bytes and the exact exit status with an independent interpreter; then the
  five compile error paths (exit status, no leftover files). Output goes through files, not pipes: wine's server and
  services inherit a run's descriptors.
- `bench.py <bbc.exe> <work dir> <out.json> <trials> <baseline record> <program.b> ...`: build and run times per
  trial (shuffled), every output checked against the hash BBC's baseline benchmark record holds for that source.

Profiling a slow native run: `gdb -p <pid> -batch -ex "info registers rip"` a few times, find the mapping in
`/proc/<pid>/maps`, subtract the mapping base and the SysV→Win64 thunk (16-byte aligned), and map the offset with
`compile_x86_64_views(reader, entry, x86_64_views_target(), backend="xax").function_offsets` of the general store
(names: build `xax_selfhost_x86_64_general.build_general_program` at commit `4a5d4b8^` for `_FN`, or match by CID).
