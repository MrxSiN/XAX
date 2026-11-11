# Continuation prompt: fix signed compares below 32 bits in the native x86-64 backend (OI-55)

Resume work in the XAX repository on a Linux x86-64 host (WSL 2 on the user's Windows machine is the intended one).
This file is a work plan, not a record of delivered work. Remove it when its steps are complete, as the previous
continuation note was.

## Read first

- `AGENT.md` (or `CLAUDE.md`; they are identical), in particular the native evolution, seed and BBC rules and the
  engineering-principles section.
- `XAX_OPEN_ISSUES.md`, OI-55, and `XAX_DECISIONS.md`, ADR-392.
- `docs/audits/2026-11-11-independent-audit.md`, finding 1 and section 9.
- `docs/09_AI_PROTOCOL.md` §16 for views and batch text.
- `compiler/bootstrap/evolution/native/0022/README.md` as the most recent example of a backend change written as
  native batches.

## What is known

- The x86-64 general backend keeps `bits<N>` values zero-extended and compares them with a 32-bit or 64-bit `cmp`.
  For N < 32, `int.compare` with `slt`, `sle`, `sgt` or `sge` therefore ignores the operand's sign bit. The reference
  executor defines the predicate at the operand's own width.
- The Python reference is fixed (ADR-392, commit `732fa43`): the frame path shifts both operands left by `32 - N`
  before the compare, and `xax_x86_64_regalloc._eligible` sends a function with such a compare to the frame path.
- The Windows seed `aa72234d…` reproduces the defect. The Linux production compiler (seed `a35fd59f…`, ledger 0023)
  has not been run against it. It was accepted on byte equality with the bootstrap, so it is expected to fail.
- No committed store holds a signed compare below 32 bits, so the compiler's own build does not depend on the
  defect. A fix should leave the self-built compiler's behaviour on its own source unchanged.
- `compiler/tests/test_xax_selfhost_general_build.py` skips x86-64 corpus cases that hold such a compare
  (`x86_raw_corpus.has_narrow_signed_compare`). That edit was made on Windows and the test has never run with it.

## Rules that bind this work

- Compiler logic is changed only as canonical XAX graphs through native transactions: batch text from
  `xaxc edit <store> <selector> <view>`, one batch per store, recorded with
  `sh compiler/bootstrap/evolution/evolve.sh apply <batch> <store>`. Python may test and may serve as the reference.
  It must not generate or implement the change.
- Every production change is a transaction on both `xax_compiler_driver_general.xax` and
  `seed/xax_compiler_request.xax`. Functions of the backend also live in `xax_x86_64_general.xax`; follow what
  ledger 0022 did for which stores a backend function must change in.
- Keep the driver's `main` within the general backend's limits (four machine parameters, four machine inputs per
  call, nothing that inlines into `main`).
- Do not rotate the seed, edit `SEED_SHA256`/`SEED_SIZE`, or push until the user has seen the transaction and the
  results of step 5. Seed rotation is a reviewed change.
- Evidence that claims XAX-hosted execution runs with `XAX_REQUIRE_NATIVE=1` and records `xax_native.AUTHORITY`.
- Dated sections in the state, handoff, benchmark and decision documents are historical. Add new sections.

## Steps

### 1. Prepare the host

Clone or open the repository inside the Linux filesystem (not under `/mnt`), check `git status` is clean and at or
after `30af34d`, create a virtual environment and install `pytest`, `pytest-xdist` and `unicorn`. Confirm the seed
runs and matches its pin:

```sh
sha256sum compiler/bootstrap/seed/xaxc-linux-x86_64
sh compiler/bootstrap/evolution/evolve.sh check
```

### 2. Establish the baseline

Run these before changing anything and keep the output:

```sh
cd compiler
python -m pytest -q tests/test_x86_64_narrow_signed_compare.py tests/test_xax_selfhost_general_build.py \
    tests/test_store_regeneration.py tests/test_status_docs.py
```

`test_xax_selfhost_general_build.py` is the test edited blind. If it fails for a reason other than OI-55, fix the
test edit first and record what was wrong.

### 3. Reproduce on the production compiler

Build programs that contain a signed compare below 32 bits with the production seed and run them. Two routes:

- A Linux executable: construct with `xax_construct.construct` (`"platform": "linux-x86_64"`), write the store, then
  `xaxc build <store> <elf> <prov>` with the seed, and compare the exit status with `xax_compiler.execute` or a
  hand-computed value. Operands must be run-time values (read from stdin or `linux.startup.argc`), or the constant
  folder of ledger 0022 removes the compare.
- The raw-image cases the general-build test skips: remove the skip locally and read which cases differ.

Cover widths 5, 8, 16 and 24, all four signed predicates, and operand pairs with different signs. Record the
failing cases. If the production compiler is already correct, stop: close OI-55 with that evidence, remove the skip
from the test, and do not write a transaction.

### 4. Write the native fix

Find the functions that lower `int.compare` in the general backend: the register-resident path, its compare and
branch fusion, the immediate and test-against-zero forms, and the frame path. Use function views
(`xaxc edit <store> F<n> <view>`); ledger 0013 (single-use compare fusion) and 0022 (constant folding) touched the
same area and name the functions.

Choose the smallest sound change and say which one was chosen and why:

- Preferred: where the backend selects a compare for a signed predicate at a width below 32, flip the sign bit of
  both operands (`xor` with `1 << (N - 1)`) and emit the corresponding unsigned predicate. This is an exact
  composition of operations the backend already lowers correctly at narrow widths, it keeps the function
  register-resident, and it applies to every path.
- Acceptable: mirror the reference (eligibility guard plus the frame-path shift). It is less code but sends such
  functions to the frame path, which rejects narrow `udiv`, `urem` and rotates.

If the preferred change is made natively, make the same change in the Python reference afterwards so the two agree
in bytes again, and remove the `ponytail:` note in `xax_x86_64_regalloc._eligible`.

Write the change as batch text, one batch per store, under `compiler/bootstrap/evolution/native/0024/` with a short
README in the style of 0022. Apply with `evolve.sh apply`; it runs `xaxc edit` and `xaxc verify` and appends the
ledger lines.

### 5. Verify before rotating

```sh
sh compiler/bootstrap/evolution/evolve.sh check
sh compiler/bootstrap/evolution/evolve.sh replay
sh compiler/bootstrap/seed/selfbuild.sh /tmp/xax-selfbuild
```

Then, with the self-built compiler (`XAXC=/tmp/xax-selfbuild/xaxc1`):

- the step 3 programs now equal the reference executor;
- programs without such a compare build to the same bytes as with the old seed (the general-build corpus, BBC's
  mandelbrot, life and factor);
- the request store is still `compiler_request` of the driver store
  (`python -m xax_selfhost_seed write-request` makes no change).

Stop here and show the user the batches, the ledger lines and these results.

### 6. Rotate and follow through

After the user agrees:

- `python -m xax_selfhost_seed rotate-seed`, then update `SEED_SHA256` and `SEED_SIZE` in `xax_selfhost_seed.py`.
- Remove the OI-55 skip from `tests/test_xax_selfhost_general_build.py` and
  `x86_raw_corpus.has_narrow_signed_compare` if nothing else uses it.
- Extend `tests/test_x86_64_narrow_signed_compare.py`, or add a Linux test beside it, so the same cases run through
  the native compiler and are compared with `execute`.
- Rebuild BBC's driver from the new production driver
  (`compiler/integration/bfx/transactions/production_driver/native/rebuild.sh`), rebuild `bbc.exe` and rerun BBC's
  checks. Never patch a separate driver copy.
- Re-record the self-hosting evidence (`benchmarks/bench_full_selfhost.py --write` and the Python-free seed record)
  under `XAX_REQUIRE_NATIVE=1`, then `python -m xax_status_docs --write` from `compiler/src`.
- Run the full test suite on Linux.

### 7. Record

- A new ADR for the native change, and OI-55 closed with its evidence.
- New dated sections in `XAX_STATE.md` and `XAX_HANDOFF.md`.
- Remove this file.
- Commit with the repository's git identity, no AI attribution, plain-language subjects, and push to `main`.

### 8. Windows seed (separate, afterwards)

XAX-MCP pins `compiler/bootstrap/windows/xaxc-windows-x86_64.exe`, which keeps the defect until a Windows seed is cut
from the fixed driver. That is its own task with its own evidence (`compiler/bootstrap/windows/README.md`,
`seed.json`), and the XAX-MCP pin moves only after it. Do not claim the Windows side fixed from Linux results.

## Done means

OI-55's closing evidence exists: the ledger transaction, the rotated Linux seed that rebuilds itself byte for byte,
BBC rebuilt from it, and the narrow signed-compare cases executed through the native compiler equal to the
reference executor. Anything not run is listed as not run.
