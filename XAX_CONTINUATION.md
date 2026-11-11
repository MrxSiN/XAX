# Continuation prompt: rotate the seed after the native signed-compare fix (OI-55, ledger 0024)

Resume work in the XAX repository on a Linux x86-64 host. On the user's Windows machine that is WSL 2, distribution
`Ubuntu-24.04` (user root): clone `/root/XAX`, virtual environment `/root/venv`, scratch files under `/root/work`.
This file is a work plan, not a record of delivered work. Remove it when its steps are complete.

## Read first

- `AGENT.md` (or `CLAUDE.md`; they are identical), in particular the native evolution, seed and BBC rules.
- `XAX_OPEN_ISSUES.md`, OI-55, and `XAX_DECISIONS.md`, ADR-392.
- `compiler/bootstrap/evolution/native/0024/README.md`: what ledger 0024 changed and why.

## What is done (2026-11-11, WSL host)

- The defect was reproduced on the production seed `a35fd59f…`: 128 of 240 probe programs
  (`compiler/bootstrap/evolution/native/0024/probe.py`) differ from the reference executor, every signed predicate
  at widths 5, 8, 16 and 24 in all eight forms.
- Ledger 0024 is applied to `xax_compiler_driver_general.xax`, `seed/xax_compiler_request.xax` and
  `xax_x86_64_general.xax` (six batches, `evolve.sh check` passes). The register path's `em_compare` and the frame
  path's integer node function shift both operands left by `32 - N` before the 32-bit compare.
- The Python reference emits the same bytes: the ADR-392 eligibility guard is removed and
  `xax_x86_64_regalloc`'s `emit_compare` has the same sequence. Mirroring the guard natively was tried and dropped:
  the frame path lowers only `win64-c` foreign calls, so a Linux process entry with such a compare was rejected.
- `selfbuild.sh` reaches a fixed point: `xaxc1` = `xaxc2`, SHA-256
  `1085c08a0138b342c801e7406c43d7ed853fddd8eecd96b882acff1e2214614c`, 31,907,019 bytes. The old seed and the new
  compiler build the compiler to the same bytes.
- With that compiler: 240 of 240 probe programs equal the reference executor; the raw-image corpus of
  `tests/test_xax_selfhost_general_build.py` at `XAX_RAW_TRIALS=80` (720 subtests, 13 x86 cases with a narrow signed
  compare, the OI-55 skip removed locally) equals the reference in bytes. The request store is `compiler_request` of
  the driver store.

## What is not done

The seed is **not rotated**: `compiler/bootstrap/seed/xaxc-linux-x86_64` is still `a35fd59f…`, the compiler before
ledger 0024. Until step 1, everything that runs the pinned seed (`NativeGeneralDriver`, `evolve.sh` by default) has
the defect, and `tests/test_xax_selfhost_general_build.py` keeps its OI-55 skip because the seed's bytes differ from
the reference for a narrow signed compare.

Not run or not finished on 2026-11-11, to be run in step 4:

- `evolve.sh replay` had replayed 89 of 118 transactions without a failure when this note was written; the six 0024
  transactions are the last ones. `tests/test_store_regeneration.py` passes.
- `tests/test_native_large_image.py`, `tests/test_xax_selfhost_general_driver.py` and
  `tests/test_xax_selfhost_x86_64_backend.py` did not finish within seven minutes each (two workers).
- BBC's mandelbrot, life and factor were not rebuilt or compared.
- The AArch64 backends were not examined for the same defect.

Found on the way, not caused by ledger 0024: `tests/test_xax_selfhost_general_view.py` fails at commit `6bcaf77`
(`test_jsonmin`, `test_executables_assembled_in_xax`, `test_random_programs`, `test_register_resident_analyses`:
"S12c.2 analyses disagree" in `erased`, `uses`, `pinned`, `allocatable`, `hoisted`). The native `basics` folds
constants since ledger 0022 and the reference's analysis audit does not. Record it as an open issue or fix the
reference's audit; do not fold it into the OI-55 change.

## Host notes

- WSL has about 19 GB of memory. `pytest -n 12` on the self-hosting tests gets workers killed by the OOM killer; use
  `-n 5` or fewer, and run `test_native_large_image.py` alone.
- `xaxc edit` and `verify` on the driver or request store take one to three minutes each, a self-build about four
  minutes per generation, a full `evolve.sh replay` about three hours. Never run two in the same directory.
- On Linux `xax_build.build` and `compile_linux_executable` use the native front end by default. Pass
  `frontend="python"` to exercise the Python reference itself (`probe.py reference` does).
- To run a test against a compiler other than the pinned seed, load a pytest plugin that sets
  `xax_selfhost_seed.SEED_PATH`, `SEED_SHA256` and `SEED_SIZE` before the tests import them (`-p <module>`).

## Steps

### 1. Rotate the seed (a reviewed change; the user asked to see it)

```sh
sh compiler/bootstrap/evolution/evolve.sh check
sh compiler/bootstrap/seed/selfbuild.sh /tmp/xax-selfbuild
sha256sum /tmp/xax-selfbuild/xaxc1        # expect 1085c08a…2214614c, 31,907,019 bytes
cd compiler/src && python -m xax_selfhost_seed rotate-seed
```

Then set `SEED_SHA256` and `SEED_SIZE` in `compiler/src/xax_selfhost_seed.py`, and confirm
`python -m xax_selfhost_seed write-request` changes nothing.

### 2. Tests that follow the seed

- Remove the OI-55 skip from `tests/test_xax_selfhost_general_build.py` and
  `x86_raw_corpus.has_narrow_signed_compare` (nothing else uses it).
- Add a Linux test beside `tests/test_x86_64_narrow_signed_compare.py` that builds programs with the native compiler
  and compares their output with `execute`. `native/0024/probe.py` has the program shapes; it builds one executable
  per width, kind and form (about two seconds each), so pack the kinds and forms of one width into one executable
  before making it a test.
- Run `python native/0024/probe.py <rotated seed>` once more and keep the count for the ADR.

### 3. BBC

Rebuild BBC's driver from the new production driver
(`compiler/integration/bfx/transactions/production_driver/native/rebuild.sh`), rebuild `bbc.exe`, rerun BBC's
checks, and compare mandelbrot, life and factor with their previous bytes. Never patch a separate driver copy.

### 4. Evidence and the full suite

- Re-record the self-hosting evidence (`benchmarks/bench_full_selfhost.py --write` and the Python-free seed record)
  under `XAX_REQUIRE_NATIVE=1`, then `python -m xax_status_docs --write` from `compiler/src`.
- `sh compiler/bootstrap/evolution/evolve.sh replay` to the end.
- The full test suite on Linux, including the three files listed above.

### 5. Record

- ADR-393 for the native change (`native/0024/README.md` already names it) and the reference change that replaced
  ADR-392's guard; OI-55 closed with its evidence, or left open for the Windows seed alone.
- New dated sections in `XAX_STATE.md` and `XAX_HANDOFF.md`; point ADR-392's "Limits" at ADR-393.
- An open issue for the `test_xax_selfhost_general_view.py` failures above.
- Remove this file. Commit with the repository's git identity, no AI attribution, and push to `main`.

### 6. Windows seed (separate, afterwards)

XAX-MCP pins `compiler/bootstrap/windows/xaxc-windows-x86_64.exe`, which keeps the defect until a Windows seed is cut
from the fixed driver (`compiler/bootstrap/windows/README.md`, `seed.json`). The XAX-MCP pin moves only after it. Do
not claim the Windows side fixed from Linux results.

## Done means

OI-55's closing evidence exists: the ledger transaction (done), the rotated Linux seed that rebuilds itself byte for
byte, BBC rebuilt from it, and the narrow signed-compare cases executed through the native compiler equal to the
reference executor. Anything not run is listed as not run.
