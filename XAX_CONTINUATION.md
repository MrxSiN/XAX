# Continuation prompt: the remaining XAX and BBC work plan (2026-11-06)

Paste everything below the line into a new session that has the `MrxSiN/XAX` repository (and, for the last steps,
`MrxSiN/BBC`). It is self-contained.

---

## First: finish the full test run (left unfinished on 2026-11-06)

A full run of the compiler suite (1749 tests, `cd compiler && python -m pytest -v -n 6 --durations=15`, on Windows)
was stopped at 1613 of 1749. Finish it before the plan below:

1. Run the full suite with its log written to a file (with `-v`) so progress stays visible. Do not pipe it through `grep`:
   nothing is shown until the run ends, and a hung worker then looks the same as a slow one.
2. The 136 tests that had not finished are mostly the slow ones: `tests/test_store_regeneration.py` (72),
   `integration/mcp/tests/test_native_stdio.py` (47), and the Android tests (`test_xax_android_*`, about 50). An
   earlier run stalled in this group for over an hour with two idle workers (one with 2.5 GB resident and no CPU),
   so watch for a hang. Run a stalled file on its own (`-n 0 -v`) to find the test that hangs, and record it.
3. Of the 1613 that finished, 11 failed. Three of them also fail on the tree before the commit-ID remap below
   (checked); the store-hash failures are expected on a Windows checkout with `core.autocrlf=true`, where hashed
   files get CRLF line endings. Run all 11 on a Linux checkout (or with `core.autocrlf=false` and a fresh checkout)
   and fix whatever still fails there:
   - `test_audit_remediation.py::SelfhostEvidenceCurrencyTests::test_every_b1_entry_is_bound_to_the_committed_store`
   - `test_audit_remediation.py::SeedTests::test_the_bootstrap_seed_is_native`
   - `test_python_free_seed.py::PythonFreeSeedTests::test_the_record_decides_whether_the_seed_requires_python`
   - `test_full_selfhost_status.py::FullSelfhostStatusTests::test_the_record_describes_the_committed_compiler`
   - `test_oi19_transform_proofs.py::OI19TransformProofTests::test_committed_evidence_replays_from_raw_samples`
   - `test_oi19_transform_proofs.py::OI19TransformProofTests::test_implementation_accounting_rejects_solver_complexity`
   - `test_oi20_abi_platform.py::OI20AbiPlatformTests::test_committed_evidence_replays_from_raw_samples`
   - `test_oi20_abi_platform.py::OI20AbiPlatformTests::test_model_token_cost_is_not_fabricated`
   - `test_xax_chains.py::ChainsTests::test_committed_artifact_identity_reproduces`
   - `test_xax_construct.py::Xb64Tests::test_request_reconstructs_generation_0`
   - `test_xax_construct.py::XcksumTests::test_request_reconstructs_generation_0`
4. Context: on 2026-11-06 `main` was rewritten so that only benchmark-evidence-only commits keep Claude as author
   (backup tag `backup/main-before-author-rewrite`), and commit IDs quoted in 40 tracked files were remapped to the
   rewritten IDs. If a test compares a recorded commit ID, check it against the rewritten history.

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

- **Ledgers 0014–0017 are in** (the frame path on PE, `object` with references, borrowed views at frame-path calls, a
  prefetch block budget). The seed is xaxc of ledger 0017: SHA-256 `a809c730…326d`, 33,154,122 bytes.
- **The Windows-hosted production driver builds natively.** Under wine, `xaxc.exe` builds the production compiler's
  request byte-identical to the Linux seed.
- **`rebuild.sh <production driver> <work>` rebuilds BBC's whole driver natively,** and `xaxc verify` accepts it.
  Last run on the post-0017 driver: root `661b785b…`, 72.4 MB, about 28 minutes.
- **The native `bbc.exe` build declines** (`xaxc build` exit 2 after about 6 min). The general program's image
  buffer is full: `I_LEN` = 33,529,728 against `IMAGE_CAP` = 2^25, after 954 of 1,060 functions. Each function on
  its own compiles.

## 3. Work plan (in order)

### Step A — image capacity (ledger 0018): make the general backend emit images larger than 32 MiB

Inspect the image module's generator source at `4a5d4b8^`
(`compiler/src/xax_selfhost_general_image.py`; the constants are still in the kept copy in `compiler/src`):
- `IMAGE_CAP = 1 << 25` (one byte per word);
- `IMAGE_BUFFER_AT = 200 << 20` words, with `assert IMAGE_BUFFER_AT + IMAGE_CAP <= IMAGE_AT`;
- `IMAGE_AT, IMAGE_END = 232 << 20, 252 << 20` (the output image record);
- the container buffer `I_ELF`, filled through `_elf`/`_put` with capacity `IMAGE_CAP + (1 << 16)` and allocated in
  the arena;
- the general arena is `120 << 20` … `200 << 20` words. The arena already reached about 187M words on large builds
  (`G_BLIST` was seen at 187,478,160).

The workspace view is 2 GiB, which is 256M words. Choose and document one design (ADR):
1. **Pack the image and container buffers 8 bytes per word.** `_put` writes byte k of word `len/8`; readers
   (`_read_image` on the host, `image_add` relocation and patching, the PE/ELF container writers, the output record)
   follow. This frees about 28M words and allows a 256 MiB image. It is a broad change across every function that
   reads or writes these buffers: list them by CID from the generator source, and edit each from its native view.
2. **Grow the workspace to 4 GiB** and move the buffers up. Simpler per function, but every fixed address (clamps use
   2^28 words) changes. Probably larger.
3. **Minimal:** move `IMAGE_BUFFER_AT` down and raise `IMAGE_CAP` to about 48M, shrinking the arena. Only if
   measurements show the arena peak of a BBC build stays below the new boundary. Risky, because the arena already
   reached about 187M.

Then:
- Apply the change to the driver, the request and the x86-64 general store (and the AArch64 general store if it
  shares the image code; check by CID).
- Self-build, rotate, record the evidence, and add a regression test: a program whose image exceeds 32 MiB, built
  with `frontend="xax"`.
- Expect xaxc1 = xaxc2 unless the image bytes for the compiler change.

### Step B — build `bbc.exe` natively and fix the next walls

`rebuild.sh` on the current production driver, then `tools/request.py`, then the seed's `resolve` and `build`. Diagnose
any decline with `tools/audit.py` (the first function without `code`), `tools/probe_state.py`, `tools/probe_order.py`,
and `tools/call_one.py` + `audit.py` to isolate one function. Profile slow builds with gdb as `tools/README.md` explains.
Expected possible walls:
- **`VCAP` (2^18 values per function view)**, if any BBC function inlines past it. The old BBC driver's F163 did.
- **More cubic or quadratic passes** on huge views. The inliner restarts its scan after every splice (quadratic), and
  `_simplify`'s merge loop repeats until no change.
- **`DRIVER-FILE-CAPACITY`**: the driver reads `edit`'s input into a 16 MiB view. That is why `rebuild.sh` splits BBC's
  layer into batch 3a and four variant batches.

### Step C — BBC's checks and the switch-over

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

### Step D — the full self-hosting record (B levels honest again)

The derived status reads "seed requires Python: yes" because `benchmarks/full_selfhost_evidence.json` predates ledger
0001. Its C0 is the driver lowered by the x86-64 *views* backend in a Python host (`NativeGeneralDriver`), which
rejects operation 77, `growable.load.bits.le` (`X86_64_VIEWS-OP-TARGET-SUPPORTED`). The driver has used it since
ledger 0009. Either:
- teach the views backend program (its store and the views target lists) operations 77 and 78, natively;
- or write an ADR that makes C0 the pinned seed, and change `bench_full_selfhost.py`.

Then re-record `full_selfhost_evidence.json` with `XAX_REQUIRE_NATIVE=1`, regenerate the status blocks, and fix the two
known failing tests.

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

- `test_python_free_seed.py::test_the_record_decides_whether_the_seed_requires_python` and
  `test_xax_selfhost_evolution.py::test_the_raised_input_bound` fail until step D.
- The edit engine drops supplied objects that end up unreachable. A batch must make everything it defines reachable,
  which is why `rebuild.sh` uses stubs.
- A reference to a supplied object must come after that object in the batch.
- `xaxc edit` does not verify. Always run `xaxc verify` on a result.
