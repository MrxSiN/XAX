# Continuation prompt: the remaining XAX and BBC work plan (2026-11-06)

Paste everything below the line into a new session that has the `MrxSiN/XAX` repository (and, for the last steps,
`MrxSiN/BBC`). It is self-contained.

---

You are continuing the native evolution of XAX, a compiler whose source of truth is canonical semantic graphs in
`.xax` stores (no textual source language). You also continue BBC, a Brainfuck compiler whose driver is XAX's production
driver hosted on Windows. Work autonomously through the plan below. Commit and push after every finished step whose
tests pass. Do not stop until the plan is done, or a decision only the user can make blocks you.

## 0. Read first (in this order)

1. `CLAUDE.md` (and `AGENT.md`) at the repo root: binding rules.
   - **Native evolution only:** compiler logic is authored as native XAX graphs through native transactions. Python
     may test or serve as a reference, never generate or implement production compiler logic.
   - **Frozen stores** change only by ledger transactions.
   - **The request store** must stay `compiler_request` of the driver store.
   - **Dated sections** in `XAX_STATE.md`/`XAX_HANDOFF.md`/`XAX_DECISIONS.md` are historical: add new sections and
     point old ones at them.
   - **No AI attribution** in commits; commits use the owner's git identity, never Claude. PR titles and
     descriptions are plain and human-readable (see `CLAUDE.md`, Git workflow).
2. `docs/09_AI_PROTOCOL.md` §16: the native workspace.
   - `xaxc edit <store> <selector|batch|record> <out>`: views, `define`/`replace`, the `object` form with references.
   - Rejection rendering: run `xaxc edit <store> <rejection record> <text>`.
3. `XAX_DECISIONS.md` ADR-367 … ADR-380, and `XAX_HANDOFF.md`, newest sections first:
   - "BBC's driver on the production driver: ledgers 0016, 0017" (including its update about the image buffer);
   - "Ledger 0015 and the self-hosting record";
   - "The production driver on Windows, natively";
   - "BBC's PE decline found and fixed".
4. `compiler/bootstrap/evolution/LEDGER`, `evolve.sh`, and `native/0010` … `native/0017` (each has a README). They
   show exactly how every native transaction was authored.
5. `compiler/integration/bfx/transactions/production_driver/native/README.md` and `tools/README.md`: the BBC port,
   `rebuild.sh` and the diagnostic tools.

## 1. How native transactions are made here (proven recipe)

- **Views.** Run `bootstrap/seed/xaxc-linux-x86_64 edit <store> <empty file> <list>` to list the functions
  (`F<n> <CID>`, store order). Then `… edit <store> <file containing F<n>> <view>` shows one function (about 60 s on
  the 62 MB driver).
  - Handles (`F<n>`) differ between stores and change whenever any CID changes: always re-list the store you edit.
  - Find a function by CID. The generator sources were deleted (ADR-361) but are in git: `git show
    4a5d4b8^:compiler/src/<module>.py`. Old names map to CIDs via the generator's `_FN`; match a current function by
    CID, or by its view modulo handles.
- **Editing a view.** Write a small awk script that rewrites the view text: see `native/0013/fuse.awk`,
  `native/0016/fr_call.awk`, `native/0017/prefetch.awk`.
  - New hand-written functions go in view form, with workspace loads and stores expanded by `native/0016/ws.awk`.
    `@LD` and `@ST` use the clamp pattern: a word address is clamped below 2^28 and multiplied by 8.
  - Handles must be sequential in order of definition. Use `native/0015/renumber.awk` for nodes and parameters.
    Shift block numbers yourself if you insert blocks (as `prefetch.awk` does).
- **The batch.** `R <root>` / `F<n>` / `define @x … end` / `replace F<n> @x`. A production-compiler change is one batch
  per store: `xax_compiler_driver_general.xax`, `seed/xax_compiler_request.xax`, plus `xax_x86_64_general.xax` (and
  `xax_aarch64_general.xax` if relevant) when the general backend changes. Each batch comes from that store's own
  view. Apply each with `sh compiler/bootstrap/evolution/evolve.sh apply <batch> <store path under bootstrap/>`.
  - Name the batches `NNNN-<slug>.batch` (driver), `-request`, `-x86-64`. Copy the authoring aids into
    `native/NNNN/` with a README.
- **Constraints the seed imposes.** The pinned seed builds the new compiler, so new or changed functions must be
  compilable by the *old* seed:
  - at most four machine parameters, so the register path takes them (ledger 0016's first attempt failed on this);
  - keep the driver's main within the general backend's limits (main is about 632 values below `VCAP`).
- **Self-build.** `sh compiler/bootstrap/seed/selfbuild.sh <dir>` takes about 11 minutes.
  - xaxc1 = xaxc2 means code generation is unchanged. If they differ (a codegen change), xaxc2 must rebuild itself to
    the same bytes.
  - Then rotate the seed: copy into `bootstrap/seed/xaxc-linux-x86_64`, update `SEED_SHA256`/`SEED_SIZE` in
    `compiler/src/xax_selfhost_seed.py`.
  - Re-record `PYTHONPATH=src:reference python3 benchmarks/bench_python_free_seed.py --write` (about 10 min), and
    regenerate the status blocks with `cd compiler/src && PYTHONPATH=.:../reference python3 -m xax_status_docs --write`.
  - Write an ADR and a dated handoff section; then commit and push.
- **Tests per backend ledger** (repo `compiler/`, plain `pytest`):
  - `test_native_pe_frame_heap_views.py`, `test_native_frame_borrowed_returns.py`, `test_native_branch_fusion.py`;
  - `test_xax_oi52_r1.py`, `test_xax_growable_views.py`, `test_native_object_references.py`,
    `test_native_object_form.py`;
  - `test_store_regeneration.py` (long), `test_status_docs.py`, `test_python_free_seed.py`;
  - `test_bbc_windows_host_port.py` (pinned to driver blob `fc32dfd8`; leave it as a record of that port, or re-pin
    when you re-port).
  - Two tests are known to fail for an older reason; see §4: `test_python_free_seed.py::test_the_record_decides_…`
    and `test_xax_selfhost_evolution.py::test_the_raised_input_bound`.
- **Testing a general-backend edit before applying it.** Copy `compiler/` into a scratch tree with `bootstrap/` as a
  real directory holding the edited `xax_x86_64_general.xax`, and run tests from that tree with `PYTHONPATH=src:…`
  via plain `unittest`. The repo's `pyproject.toml` makes `pytest` use the repo's own paths.
- **Environment gotchas:**
  - Do not run many `xaxc` processes in parallel (about 1.5–3 GB each; one OOM kill already cost a test run).
  - Foreground commands time out at 10 minutes and backgrounded ones at 30 minutes unless started with
    `run_in_background` and a longer `timeout` (up to 2 h).
  - "Text file busy" if you exec the seed while copying it.
  - wine and qemu-aarch64 are available.

## 2. Where things stand

- **Ledgers 0014–0018 are in** (the frame path on PE, `object` with references, borrowed views at frame-path calls, a
  prefetch block budget, the packed image buffer). The seed is xaxc of ledger 0018: SHA-256 `8f9eb1e3…a992`,
  33,161,530 bytes.
- **The Windows-hosted production driver builds natively.** Under wine, `xaxc.exe` builds the production compiler's
  request byte-identical to the Linux seed.
- **`rebuild.sh <production driver> <work>` rebuilds BBC's whole driver natively,** and `xaxc verify` accepts it.
  Last run on the post-0017 driver: root `661b785b…`, 72.4 MB, about 28 minutes.
- **The native `bbc.exe` build declined** (`xaxc build` exit 2 after about 6 min): the general program's image
  buffer was full (`I_LEN` = 33,529,728 against `IMAGE_CAP` = 2^25, after 954 of 1,060 functions). Ledger 0018
  (step A, ADR-381) packs the buffer and raises the cap to 48 MiB; the build has not been retried yet (step B).

## 3. Work plan (in order)

### Step A — image capacity (ledger 0018): done (2026-11-07, ADR-381)

The image buffer is packed eight bytes to a word and `IMAGE_CAP` is 48 MiB; the container buffer (one byte per word,
in the arena) and its cap follow at 48 MiB + 64 KiB. See `compiler/bootstrap/evolution/native/0018/README.md`, ADR-381
and `XAX_HANDOFF.md` ("The image buffer packed: ledger 0018"). `tests/test_native_large_image.py` builds about 36 MiB
of code with `frontend="xax"`. If a later build declines at the container buffer's allocation (the arena after the
views), pack the container buffer too: its accesses are the same `_put` pattern in `pe`, `elf_static`, `elf_dynamic`,
`dll_edata`, `image_finish` and the record, and `native/0018/pack.awk` already rewrites such accesses.

### Step B — build `bbc.exe` natively and fix the next walls: done (2026-11-07, ADR-383)

`rebuild.sh` on the current production driver, then `tools/request.py`, then the seed's `resolve` and `build`. Diagnose
any decline with `tools/audit.py` (the first function without `code`), `tools/probe_state.py`, `tools/probe_order.py`,
and `tools/call_one.py` + `audit.py` to isolate one function. Profile slow builds with gdb as `tools/README.md` explains.
Expected possible walls:
- **`VCAP` (2^18 values per function view)**, if any BBC function inlines past it. The old BBC driver's F163 did.
- **More cubic or quadratic passes** on huge views. The inliner restarts its scan after every splice (quadratic), and
  `_simplify`'s merge loop repeats until no change.
- **`DRIVER-FILE-CAPACITY`**: the driver reads `edit`'s input into a 16 MiB view. That is why `rebuild.sh` splits BBC's
  layer into batch 3a and four variant batches.

### Step C — BBC's checks and the switch-over: done (2026-11-07)

Run `tools/check.py <bbc.exe> <work>` (wine for windows-x86_64, qemu-aarch64 for android-arm64, -O0/-O1).
- Extend its cases toward the old campaign: 83 programs (pilot programs, BBC's tests, both depth-512 programs,
  negative loops, 60 random programs, capacity cases), and the error paths (exits 1, 4, 4, 3, 3, no leftover files).
  See `integration/bfx/single_process_evidence.json`.
- Every run must match the interpreter in output bytes and exit status.
- Android first: the required targets are Android ARM64, then Windows x86-64.
- Then:
  - replace `compiler/integration/bfx/bbc.xax` with the rebuilt store;
  - record new evidence JSON;
  - add a dated section to `integration/bfx/COMPILE.md`;
  - update `XAX_HANDOFF.md`;
  - in the BBC repo, update `docs/25_NATIVE_COMPILE.md` and `docs/05_STATUS.md`. The BBC repo holds only Brainfuck
    and docs: no scripts, no textual XAX.
- Re-run the hanoi and mandelbrot O0 cases that used to decline.
- Benchmark compile time and run time against the old `bbc.exe` (`docs/08_BENCHMARKS.md` in BBC). `MEASURED` claims
  need raw per-arm samples.

### Step D — the full self-hosting record (B levels honest again): done (2026-11-07, ADR-382)

The derived status reads "seed requires Python: yes" because `benchmarks/full_selfhost_evidence.json` predates ledger
0001. Its C0 is the driver lowered by the x86-64 *views* backend in a Python host (`NativeGeneralDriver`), which
rejects operation 77, `growable.load.bits.le` (`X86_64_VIEWS-OP-TARGET-SUPPORTED`). The driver has used it since
ledger 0009. Either:
- teach the views backend program (its store and the views target lists) operations 77 and 78, natively;
- or write an ADR that makes C0 the pinned seed, and change `bench_full_selfhost.py`.

Then re-record `full_selfhost_evidence.json` with `XAX_REQUIRE_NATIVE=1`, regenerate the status blocks, and fix the two
known failing tests.

Steps B–D are recorded in `XAX_HANDOFF.md` ("BBC's `bbc.exe` built natively; C0 is the seed: ledger 0019"): ledger
0019 (the inliner's value budget) and seed `a9995432…`; `bbc.xax` rebuilt from the production driver (the layer from
the committed store, each step's argument count); 370 of 372 checks, `deep512active` declining on android-arm64; B0–B6
derived with no Python. Open from them: that AArch64 decline, hanoi -O0, device runs, an A/B benchmark.

### Step E — the rest of the original plan

- **P1, redundant block-parameter elimination:** a native pass in the general view pipeline. Measure on the
  compiler's own build.
- **Packed bytes:** byte-per-word buffers elsewhere in the general program (step A may already set the pattern).
- **Dynamic limits (OI-52):**
  - raise `VCAP` (encoded in about a dozen functions per store as `VCAP`, `+1`, `+2`, `2*VCAP` and `v + VCAP`
    offsets; check each use);
  - raise the driver's 16 MiB file view (one view type, used by main and one helper);
  - the edit engine's supplied-object count;
  - replace fixed reservations with growable views (ADR-369/371).
- **Optional, from ADR-380:** a predecessor-list `cycle`, to lift the prefetch budget.

## 4. Known failures and open notes

- The full run of 2026-11-06 on Linux x86-64 is recorded in `XAX_STATE.md` ("Full test run on Linux x86-64 —
  2026-11-06"). Until step D, about 65 tests fail: every class built on `NativeGeneralDriver`
  (`XAX.X86_64_VIEWS.UNSUPPORTED_OPERATION` for operation 77), `test_the_raised_input_bound`, the six op-77 stores of
  `test_xax_selfhost_driver::test_every_committed_store`, and the three tests that read `full_selfhost_evidence.json`
  (among them `test_the_record_decides_whether_the_seed_requires_python`).
- Ledger 0007 changed the Linux targets' CIDs. The R6 stores and the OI-37 chains identity were rebuilt for it on
  2026-11-06 (`XAX_STATE.md`); for a later target change use `bench_r6_xcksum --rebind` and
  `linux_chains --bind-committed`, which keep recorded device runs and samples only for byte-identical executables.
- With 4 workers on a 15 GB host the full suite runs out of memory; run the slow self-hosting group with `-n 1` or `-n 2`.
- The edit engine drops supplied objects that end up unreachable. A batch must make everything it defines reachable,
  which is why `rebuild.sh` uses stubs.
- A reference to a supplied object must come after that object in the batch.
- `xaxc edit` does not verify. Always run `xaxc verify` on a result.
