# RFC: build, evidence and seed rotation for an AI-operated XAX

Date: 2026-11-15. Status: proposal; nothing here is implemented. Base: ledger 0032 (`77cff24`).

XAX is developed, verified, rotated and released by AI agents. This RFC changes how that work is organized so that
agents repeat less of it, while keeping the trusted compiler chain intact. It adds no build system, cache, daemon or
store format.

## 0. Central requirement

**Every phase is a separate, backward-compatible change. After every commit on `main`, XAX can still bootstrap,
and the trusted compiler chain is never broken.**

The following invariants hold after every commit. Each phase's tests check all of them:

- **I1 (seed):** on `main`, `bootstrap/seed/selfbuild.sh` run with the pinned Linux seed rebuilds the pinned seed
  byte for byte, and the pinned Windows seed has native evidence for its exact SHA-256. On a release branch with
  unrotated driver transactions, the pins still hold for the last release. The candidate is shown only by its own
  fixed point (C(n) = C(n−1)) and is never reported as the pinned seed.
- **I2 (ledger):** `evolve.sh check` passes. Historical ledger lines, records and blob identities are never edited.
- **I3 (stores):** no frozen store changes except through a ledger transaction. A phase that claims "no semantic
  change" leaves every store, CID and seed byte-identical.
- **I4 (evidence):** an executed record names the exact binary, inputs and ledger head it ran on. A claim about one
  compiler is never shown as a claim about another.
- **I5 (oracles):** the independent checks that exist today are kept: the Python reference resolver, the reference
  executor, the Go checker (`oi27_*`), and the Linux-built PE matching the Windows-built PE.

Phases 1–7 change no compiler store, so none of them needs a seed rotation. Only the optional phase 8 does.

## 1. Current behaviour (verified at ledger 0032)

| Fact | Where |
|---|---|
| A seed rotation takes about 8 min on Linux (two generations) and 7–11 min on Windows | `python_free_seed_evidence.json` (478 s), `windows/README.md` |
| The full self-hosting record takes 3 h 4 min to 5 h 33 min | `XAX_STATE.md`, ledger 0031 and 0032 sections |
| It runs three generations and the 198-case corpus on C0–C3, which were byte-identical (`0cd26742…`) | `benchmarks/bench_full_selfhost.py` `measure()` |
| It replays all 142 ledger transactions (78 min of `edit`, about 40 s and 2.3 GB peak RSS per driver `edit`; a driver `verify` also takes about 40 s and 1.6 GB, phase 2 profile in `XAX_STATE.md`, 2026-11-15) | same, `evolution` |
| The test suite replays the ledger a second time | `tests/test_xax_selfhost_evolution.py::test_the_compiler_replays_the_ledger` |
| `replay` prints `skip` and exits 0 when git lacks a blob, so a shallow clone passes | `bootstrap/evolution/evolve.sh:78` |
| A test forces the full record to be re-run after every driver transaction | `tests/test_full_selfhost_status.py::test_the_record_describes_the_committed_compiler` |
| Another test does the same for component stores (closure re-run about 9,400 s) | `tests/test_audit_remediation.py::test_every_b1_entry_is_bound_to_the_committed_store` |
| The B evaluator requires exactly three generations and reads `outcomes["C1"]` | `src/xax_selfhost.py:56`, `:61`, `:63`, `:66` |
| The request store is the driver plus four objects (package, target, profile, request), re-rooted | `src/xax_selfhost_compiler.py:22` |
| 52 of the 142 transactions are request mirrors of driver transactions | `bootstrap/evolution/LEDGER` |
| One semantic change can take four transactions (ledger 0032: dex_writer, android, driver, request) | `evolution/native/0032/README.md` |
| The Windows hosting batch (6 MB, main's view copied) and the PE record are rewritten by hand each ledger | `windows/README.md`, 0032 README |
| The Linux seed already cross-builds the exact Windows seed bytes | `windows/seed.json` |
| Seed pins are split between `SEED_SHA256`/`SEED_SIZE` (Python) and `windows/seed.json` | `src/xax_selfhost_seed.py`, `windows/seed.json` |
| There is no CI. This host is Windows 11 plus WSL 2 (~19 GB) | `.github/` absent |

## 2. Decisions

- **D1.** Full self-hosting evidence is recorded once per release batch, not once per ledger. Status always shows
  two things separately: the last validated release, and the current development head. Validation is never
  inherited (I4).
- **D2.** Strict replay comes before any reuse of replay results.
- **D3.** Evidence V2: generations stop at the first fixed point; the corpus is keyed by binary identity plus its
  execution context; V1 records keep their current meaning.
- **D4.** One execution, many consumers. No general cache.
- **D5.** Compiler requests are derived natively, per target, from the driver store.
- **D6.** The Windows hosting layer is generated deterministically, and Windows host semantics stay as they are.
  Unifying `main` through the host ABI is optional and evaluated separately (phase 8).
- **D7.** Rotation is `rotate build` followed by `rotate confirm` on each host, with one machine-readable pin and
  release record.
- **D8.** New production tooling is native XAX, with a thin `sh` layer as in `evolve.sh`. The Python logic that
  serves as an independent oracle moves to `compiler/reference/`, which may keep Python, and must agree with the
  native result.
- **D9.** Every gate is a program with a mechanical result. No step relies on an agent's judgment of whether a
  check may be skipped.

## 3. Lifecycle and the release record

The new file `compiler/bootstrap/RELEASES` is append-only and line-based, like `LEDGER`, so a native program can
parse it. It is the single release authority:

```text
# xax-releases-v1
host x86_64-linux-elf-exec-v1 seed/xaxc-linux-x86_64
host x86_64-windows-pe-v1 windows/xaxc-windows-x86_64.exe
candidate <n> ledger=<last record> driver=<blob> policy=<sha256> <target>=<sha256>:<size> ...
confirmed <n> <target> <sha256> <evidence sha256>
validated <n> evidence=<full record sha256>
```

The three states:

- **Development:** LEDGER has transactions after the last `validated` line. Gates: `evolve.sh check`, the `apply`
  verify that already exists, and the tests mapped to the changed stores (section 9). The status docs say "full
  validation pending for ledger <head>".
- **Candidate:** a `candidate` line freezes the ledger head, the driver blob, the policy hash and every host
  seed's hash.
- **Validated:** every `host` has a `confirmed` line for the candidate's hash, and the full V2 record is bound to
  the candidate. Only after that is a `validated` line written. Pins are what the latest `validated` line names;
  `SEED_SHA256` and `windows/seed.json` are retired in phase 6.

A `host` line is the list of compiler hosts. Target objects stay unchanged; adding a host flag to them would change
every target CID and every artifact's provenance.

## 4. Evidence V2

The new `xax-full-selfhost-evidence-v2` record keeps V1's facts and adds:

- `executions`: one row per actual process run, with the binary SHA-256, command, input SHA-256s, an environment
  tag (`empty`), status, output SHA-256s and timings. Every other section refers to these rows by index. Nothing is
  marked executed unless it has a row.
- `generations`: only the generations actually executed. Execution stops at the first n ≥ 1 where C(n) = C(n−1),
  with at most 3 generations.
- `fixed_point`: `{"n": n, "witness": [<execution>, <execution>], "assumptions": ["static ELF, no interpreter",
  "empty environment", "host calls: open read write close exit commit reserve free argc arg_copy"]}`. The
  argument: build is f(binary, inputs). If C(n) = C(n−1), then C(n+1) = f(C(n), R) = f(C(n−1), R) = C(n). When
  C1 = C0, the equality itself shows that two independent executions agree.
- `corpus`: keyed by context = (binary SHA-256, corpus identity, execution host target, environment tag). Each
  context runs once. A generation maps to a context; it never gets a copy of the outcomes.
- `imported`: results taken from an earlier record, each with that record's SHA-256 and execution row. The
  evaluator never counts an imported row towards a level of a different binary.

The evaluator changes in `linux_x86_64_status`. V1 records are evaluated exactly as today:

- B2: at least one executed generation, chained from the seed, with every snapshot equal to the reference
  resolver's.
- B3: agreement across contexts, plus `exact` and `reproduced` on generation 1's context.
- B4: a fixed point exists. During development, a fixed point that differs from the seed is valid and its blocker
  reads "seed not yet rotated". For a `validated` line, the fixed point must equal the candidate's seed hash.
  This addresses the case where C1 differs from the seed but C1 = C2.

What is lost: running the same binary four times was an implicit flakiness probe. V2 replaces it with an explicit
one, a fixed sample of 10 cases run twice per context.

Tests to change: `test_full_selfhost_status.py` (`test_each_level_follows_its_facts` gets V2 variants plus a V1
case; `test_the_committed_levels`), `test_status_docs.py`, and `test_audit_remediation.py` (bound to the
`validated` release, not to the head).

## 5. The strict replay contract

`evolve.sh replay` becomes strict by default:

1. The transactions come from `xax_ledger transactions`. Every one of them is replayed or the run fails; there is
   no skip.
2. A missing `before` blob is fatal. A shallow clone fails with `shallow clone: replay needs full history`
   (`git rev-parse --is-shallow-repository`).
3. Each transaction's result blob must equal its `after` blob. Byte-equal results need no second `verify`: the
   bytes were verified when they were applied. A new compiler's `verify` of history belongs to the V2 record.
4. Any failure means a nonzero exit status.
5. The last line is `replayed <n> of <total> LEDGER=<blob> xaxc=<blob>` (git object ids, which the ledger tool
   already computes). The evidence run and the test read this line instead of replaying again.
6. `evolve.sh replay --store <s>` keeps its filter and reports `<k> of <k>` for that store.

`check` remains a structural check: the committed files are the chain ends. It is never reported as a replay.

## 6. Derived requests and the ledger migration

New native program `bootstrap/evolution/request-tool/xax_request.xax`, used as `request <driver> <target> <out>`.
It writes the driver's objects plus the package, target, profile and build-request objects, rooted at the
request, the same transformation as `compiler_request`. The seed builds it, as `evolve.sh` builds the ledger tool.

Migration, in three commits:

1. The ledger tool accepts a new line kind, `derived <store> <final blob> <tool root>`, and still accepts every
   old line unchanged. This must land before any LEDGER line uses the new kind (see C1 in section 11).
2. The request tool lands. Its Linux output must be byte-equal to the committed request (`8345f64d…`) and to
   `reference` `compiler_request`. That Python function moves to `compiler/reference/` as the oracle.
3. LEDGER gets `derived seed/xax_compiler_request.xax 3b123e3d… <tool root>`. From then on, `check` requires
   committed request = `request(driver, linux)`. `evolve.sh apply` refuses a derived store. The 52 historical
   request lines stay and are replayed as before.

The request stays committed (seed records pin its SHA-256, and `selfbuild.sh` stays two commands). Making it
ephemeral is deferred until git size is measured as a problem. `write-request` is retired.

## 7. The Windows hosting generator

Today's Windows request is `edit(edit(request, hosting.batch), pe_target.edit)`. The hand-written parts are the
root line, main's handle, the five host-function handles in `@w_main`, and the hosted root and module object in
`pe_target.edit`.

The generator is the request tool with a Windows target. It:

1. Takes the fixed Windows layer from a new frozen store, `windows/host_layer.xax`, ledgered like any other store.
   The layer holds the declarations, `@w_open`…`@w_exit`, `@w_argc`, `@w_argcopy` and `@w_handler`; their CIDs have
   not changed since BBC's port.
2. Rewrites main by CID: host-function calls become calls of the layer's functions, and the three startup reads
   become calls of the adapters. This is today's `@w_main` rule, applied by program, not by hand.
3. Adds the `@XAXC` entry and the PE target, profile and request objects, and roots the result.

Acceptance, with the hand-written files as oracle until they are deleted:

- The generated hosted store equals `hosted_sha256` `ff9dfa42…`.
- The generated request equals `result_sha256` `5bf65de6…`.
- The build of that request equals the pinned `e88877d1…`.
- Then `hosting.batch` and `pe_target.edit` are deleted, and BBC's `rebuild.sh` derives from the generated request.

## 8. Rotation: build, then confirm

`rotate.sh` lives in `bootstrap/seed/` and has two subcommands.

**`build`**, on either host:

1. Derive every host request.
2. The current seed builds C1, C1 builds C2, and C1 must equal C2 (C3 only if the two differ).
3. The fixed-point compiler, not the old seed, cross-builds every other host's seed.
4. Append a `candidate` line and commit the seeds plus that line on the rotation branch.

**`confirm <target>`**, on that target's host:

1. The candidate seed resolves and builds its own request.
2. `cmp` against the candidate, then build once more and `cmp` again.
3. Write the evidence, append a `confirmed` line, and commit.

**Running both hosts without switching machines.** On this machine, WSL 2 can start Windows executables through
interop as real Windows processes (not Wine), and Git Bash on Windows can reach WSL through `wsl.exe`. So one
`rotate.sh all` can run `build` in WSL and `confirm x86_64-windows-pe-v1` natively on Windows, with no manual step.
This is not yet verified: a probe in phase 6 has to run the Windows seed through interop with `wslpath -w` paths
and show the same bytes as a run from Git Bash. If a host is unreachable, the run records `confirm` as NOT RUN and
exits nonzero, and the candidate stays a candidate.

**Failures:** nothing outside the rotation branch changes. Rollback is dropping the branch or `git revert`.
A `candidate` without a `validated` line can never become the pins.

## 9. Autonomy: gates, risks and guards

The gates are programs: `rotate.sh gate <profile>` exits 0 or names the first unmet requirement. The profile is
computed, not chosen. The stores changed since the last `validated` line select their tests through a table in
`bootstrap/POLICY`, a line-based file; a release candidate requires everything.

Risks that come from agents running the whole lifecycle, and the guard for each:

| Risk | Guard |
|---|---|
| An agent relaxes a gate, the evaluator or the expected outcomes to make a failure pass | **Policy ratchet:** `POLICY`, the evaluators, the frozen corpus expectations and `RELEASES` are policy files. A commit that changes one changes nothing else. A release whose policy hash differs from the previous release's must pass under both the old and the new policy. |
| Circular validation: the native evaluator or runner is built by the compiler it judges | The `reference/` Python evaluator recomputes every level and re-hashes every output file; the two must agree (C3, C8 in section 11). |
| A "fix" regenerates expected outcomes until they match | Expected outcomes change only through the reference oracle's recorded command, in a policy commit. |
| Endless repair loops | At most 3 repair commits per failing gate per candidate. After that the candidate is recorded `blocked <n> <gate> <reason>` and work stops. |
| A repair edits evidence or pins | A repair commit may not touch policy files, evidence records, seeds or `RELEASES`, except through `rotate.sh`; the gate checks the diff. |
| Old evidence shown as current | I4 and the `validated` binding; status docs are derived from `RELEASES`. |
| History rewritten | Append-only `LEDGER` and `RELEASES`; GitHub branch protection (no force push, no deletion) with an agent token that has no admin scope. |

**What this guarantees, and what it does not.** These guards make it hard to bypass trust by accident. They do not
stop an agent that has write access and sets out to bypass them; that needs an authority the agent cannot write,
and branch protection is the only one proposed here. Separately, AGENTS.md says "the owner reviews and merges". This
RFC does not change that rule. Letting agents merge on a passing `gate` is a separate change to AGENTS.md, made by
the owner.

**AI-specific efficiency:**

- `rotate.sh state` prints the ledger head, the last validated release, pending confirmations, blocked items and
  the next required gate, all derived from `LEDGER`, `RELEASES` and the evidence. Agents read this instead of the
  8,461 lines in `XAX_STATE.md`, `XAX_HANDOFF.md` and `XAX_DECISIONS.md`.
- Generators remove the CID and handle remapping that agents now do by hand on every ledger.
- The gate selects tests, so agents stop running 1–2 h suites after small changes.

## 10. Phases

Each phase lands as its own PR, keeps I1–I5, and none of them changes a compiler store.

| # | Change | Modified | New | Retired | Rotation |
|---|---|---|---|---|---|
| 0 | ADR for D1 and D9 (evidence cadence, gates) | `XAX_DECISIONS.md`, AGENTS.md (cadence line) | — | — | no |
| 1 | Strict replay | `evolution/evolve.sh`, `test_xax_selfhost_evolution.py` | — | the lenient skip | no |
| 2 | Profile `edit`/`verify` (measurement only) | — | an evidence note | — | no |
| 3 | Native evidence runner, V2, oracle split, release-bound tests | `test_full_selfhost_status.py`, `test_audit_remediation.py`, `test_status_docs.py` | `bootstrap/evidence/` (runner program, `sh` wrapper, frozen corpus), `RELEASES`, `POLICY` | `bench_full_selfhost.py`, `bench_python_free_seed.py`, `src/xax_selfhost.py` (moved to `reference/`) | no |
| 4 | Derived request | ledger tool, `LEDGER` (`derived` line) | `evolution/request-tool/` | `write-request`, request transactions | no |
| 5 | Windows generator | request tool, `windows/README.md`, BBC `rebuild.sh` | `windows/host_layer.xax` | `hosting.batch`, `pe_target.edit` | no |
| 6 | `rotate.sh` build/confirm/state/gate | `selfbuild.sh` (calls into it) | `seed/rotate.sh` | `src/xax_selfhost_seed.py`, `windows/seed.json` | no (its first use is the next rotation) |
| 7 | Re-baseline the whole workflow | `XAX_STATE.md` (new section) | evidence | — | uses one |
| 8 | Optional: one `main` through the host ABI; shared object pool; multi-record `edit` | ledger | — | the Windows layer's main rewrite | yes, two-stage |

**Tests per phase, runnable on their own:**

- 1: a replay in a `--depth 1` clone fails; a replay in a full clone prints `replayed 142 of 142`.
- 2: no code. `strace -r -e trace=openat,read,write,mmap,munmap` plus `/usr/bin/time -v` on one driver `edit` and
  one `verify` separate decode, compute and write, and show peak RSS.
- 3: the V2 record on the current stores gives the same B levels as the 0032 V1 record; the native and reference
  evaluators agree on V1 and V2 records and on mutated copies of both.
- 4: request tool output equals the committed request and the reference; `check` fails if either is edited by hand.
- 5: the three byte equalities in section 7, then Windows generation 1 = generation 2 on Windows 11.
- 6: a dry rotation of the current ledger rebuilds the pinned seeds exactly; `gate` fails while any host is NOT RUN.

**Rollback:** each phase is one PR, so rollback is reverting that PR. The oracle files (`hosting.batch`,
`pe_target.edit`, the Python `compiler_request`) are deleted only in the PR that proves the replacement equal to
them.

## 11. Circular dependencies in the migration

- **C1.** LEDGER cannot use `derived` until the ledger tool parses it. The tool is rebuilt from source on every
  `evolve.sh` run, so a tool change needs no rotation. Order: tool first, line second.
- **C2.** The request tool is validated against the Python `compiler_request`, so that function moves to
  `reference/` and stays there.
- **C3.** The native B evaluator is built by the compiler it evaluates. The reference evaluator is a second,
  permanent oracle.
- **C4.** The Windows generator is validated against the hand-written files it replaces. They are deleted only
  after byte equality.
- **C5.** `confirm` tests the candidate by running the candidate. If it fails, the previous Windows seed building
  the candidate request is the diagnostic, not a pass.
- **C6.** In phase 8, the compiler must lower a new host-ABI name before main may use it: rotate once for the
  lowering, then once more for main, as ledgers 0029 and 0030 did.
- **C7.** Strict replay fails in shallow clones, so the WSL clone `/root/XAX` must have full history.
- **C8.** The native evidence runner is built by the compiler under test. The reference re-hashes the output files
  it reports.
- **C9.** Policy changes are judged by the gates they change. The ratchet in section 9 handles this.

## 12. Measurement

- **Baseline:** the committed figures above. The phase 2 profile adds per-phase `edit` and `verify` times and RSS.
- **Recorded on every release:** wall and CPU time per stage, peak RSS, the count of actual compiler executions,
  executions avoided (contexts × cases vs generations × cases), and agent-side counts (commits and gate runs per
  candidate).
- **Provisional targets, to be revised after phase 2:**
  - development gate under 30 min;
  - release candidate under 90 min, plus about 10 min per extra host for confirmation;
  - for both, the same B levels and the same artifact hashes as before.

## 13. Coordinated outstanding work, dependency batching and release validation

Inventory taken on 2026-11-15 from `main` `d9249ed` (LEDGER head: ledger 0032; no transaction is pending) and the
live GitHub issue list (#47, #48, #49, #51, #55 open; no open PR).

### 13.1 Inventory

Status classes: **I** needs implementation · **V** fixed, evidence missing · **L** needs a ledger transaction ·
**D** documentation stale · **T** needs only targeted tests or native runs · **A** long-term design question ·
**X** depends on another project.

| ID | Problem | Class | Where | Depends on | Closes with | Batch |
|---|---|---|---|---|---|---|
| OI-55 | Signed compares below 32 bits, PE half | T | Windows seed; `test_x86_64_narrow_signed_compare.py` | — | the cases built by the pinned Windows seed and run on Windows 11, equal to the executor | S |
| OI-57 | Reference S12c.2 audit compares a folded graph with an unfolded one | I (test side) | `reference/`, `tests/test_xax_selfhost_general_view.py` | — | the file passes under `XAX_REQUIRE_NATIVE=1` | S |
| OI-60 | Ledger and seed tools are Linux-only; no Windows-seed pin test; `/proc/cpuinfo`; two developer paths | I | `evolve.sh`, `selfbuild.sh`, the 0023 `all.sh`, `tools/check.py` | RFC phases 1 and 6 | the ledger tool and seed check run on the Windows seed; one test runs a Windows-seed command against its pin | R |
| OI-58 | Win64 `chains`: loop-slot rule, prefetch shape, layout, placement | L + measurement | `xax_x86_64_general.xax`, driver | OI-59 (fixed) | native slot-rule transaction, the workload without workarounds, a repeated lead over every arm | C-x86 |
| OI-56 note | Native backend emits no PE stack probes (a DLL runs on its host's thread stack) | L | `xax_x86_64_general.xax`, driver | — | probes in native PE prologues for frames over 4 KiB, executed in a DLL | C-x86 |
| OI-49 | ARM64 frame path: composite return over 16 bytes reuses x16 | L | `xax_aarch64_general.xax`, driver | — | distinct copy registers, leaf and non-leaf, several sizes, run on Pixel 8 Pro | C-a64 |
| OI-54 | Function views capped at 2^18 values (BBC hanoi -O0) | L (several steps) | driver: semantic index, edit engine, x86-64 arena, AArch64 liveness | — | hanoi -O0 builds for Windows and Android and matches the interpreter | C-cap |
| OI-52 R2/R3 | 64-bit checked offsets; growable views | L + ADR | typing, both backends, driver | R1 (done) | over-4-GiB tape runs on Windows and Android, then fails at the new edge | C-cap (R2), later (R3) |
| #49 | JVM: catch and recover Java exceptions | I + L + ADR | typing (new ABI), JVM backend in driver | — | a catching foreign-call ABI, executed on HotSpot and on Android | C-jvm |
| #48 | libxposed: forward `onModuleLoaded`, `onSystemServerStarting` | L | module-carrier writer in driver (reference: `xax_android_libxposed_jvm.py`) | #49 (system_server hooks must fail open) | both entries in the carrier, a module loaded on device | C-jvm |
| #55 | `compile_bfx` capped at 65,536 commands | I | `integration/bfx/` (BBC stores, not the production driver) | maybe OI-54 at -O0 (to measure) | the six ThreadsHideAds programs compile; e65537 folds at -O1 | B-bfx |
| #51 | `bfc_call_v1` shared host: dynamic tape, JNI export | I | `integration/bfx/shared_arm64.xax` | — | current `bbc` records bind; a `Java_…` export runs on device | B-bfx |
| #47 | `bfc_call_v1`: host calls mid-run, persistent tape prefix | I + maybe ADR | `integration/bfx/`, ARM64 foreign entries | #51; OI-42 (lend entries exist only for SysV) | the four needs in the issue, executed on device | B-bfx |
| OI-48 | VRAMBoost CR-005..008, CR-011 | X + I | PE target and Windows ABI | external register | each CR's own acceptance test on Windows | later |
| OI-33 | TLS, unwind and debug data on Linux | A + I | backends | — | as recorded | later |
| OI-34 | First production GPU target | D? | matrix says SPIR-V runs on an RTX 3060 | — | check whether a throughput comparison on hardware exists; if it does, close | S (check) |
| OI-38, OI-39, OI-40 | Allocator gap; shift selection watch; SysV breadth | A / I | backends | — | as recorded | later |
| OI-44 | Hardware vs emulated rows (RISC-V, bare-metal AArch64) | X | hardware | hardware | as recorded | later |
| OI-47 | Android object ownership | A + device | typing, Android packages | — | verifier options plus device runs | later |
| OI-51 | Windows driver prototype corpus and diagnostics | D? | `integration/windows_helpers/` | — | the production compiler now runs natively on Windows; decide whether the prototype's criteria still apply | S (check) |
| OI-15, 18, 19, 21–24 | Have closure evidence but no status line | D | `XAX_OPEN_ISSUES.md` | — | a dated `Status: CLOSED` pointing at the closure paragraph | S |
| OI-14, 16, 17, 20, 28 | Evidence recorded, criteria not met | A | — | — | as recorded | later |
| Handoff items | "tests for the Windows seed", "XAX-MCP pin", `tools/check.py` | T / X | `XAX_HANDOFF.md` 2026-11-12/13 | OI-60 | covered by OI-60 and XAX-MCP's own pin PR | R |

### 13.2 What the dependencies are

- **Production driver and request** (rotation needed): OI-58, the OI-56 note, OI-49, OI-54, OI-52 R2, #49, #48.
  Each one is also a transaction on its component store (`xax_x86_64_general`, `xax_aarch64_general`, typing, the
  JVM and Android stores).
- **x86-64 backend:** OI-58, the OI-56 note. **AArch64 backend:** OI-49, OI-54 item 3. **JVM and Android:** #49,
  #48. **Verifier rules:** #49 (a new ABI), OI-52 R2, maybe #47.
- **Windows host behaviour:** the OI-56 note, OI-58 measurement, OI-55 run, OI-60.
- **BBC stores only** (`integration/bfx`, no production rotation; `bbc.exe` is rebuilt): #55, #51, #47. They are
  rebuilt after the release because `bbc.xax` follows the production driver.
- **None of the driver changes is used by the compiler itself** (the driver holds no JVM catch, no ARM64 return
  over 16 bytes, no offset over 4 GiB). So no change needs the two-stage "teach the compiler, then use it" rotation
  of ledgers 0029 and 0030. Two exceptions need care:
  - OI-58 and the OI-56 note change x86-64 code generation, which is the compiler's own target. They need a third
    generation in the release, not a separate rotation.
  - OI-54 changes the driver's own capacities. Its steps are ordered, but they are transactions, not rotations.

### 13.3 Batches

The key fact: **a driver change is tested with the candidate compiler, C1, without rotating.** The seed builds
C1 from the candidate request in about 4 minutes, and the targeted tests run with `XAXC=C1`. Only the release
rotates the pin.

| Batch | Contents | Order inside | Seed-neutral? |
|---|---|---|---|
| R (infrastructure) | RFC phases 0–6 and OI-60 | 0, 1, 2, then 4, 5 (so the compiler batches pay no request mirror and no hosting remap), then 3 and 6 in parallel with C | yes |
| S (seed-neutral closures) | OI-55 PE run, OI-57, status lines (OI-15…24), checks of OI-34 and OI-51 | any time; each its own PR | yes |
| C (one release batch) | C-x86 (OI-58 slot rule, PE probes), C-a64 (OI-49), C-jvm (#49 then #48), C-cap (OI-54 steps, OI-52 R2) | each sub-batch is its own transactions and tests against C1; integrated in ledger order; one candidate | no: **one rotation, three generations** |
| B (BBC integration) | #51, #47, #55 | #51 then #47; #55 independent; `bbc.exe` rebuilt once after C | no production rotation |
| later | OI-33, 38–40, 44, 47, 48, the A-class OIs, OI-52 R3 | not in this campaign; each has an external or design blocker | — |

So the minimum number of bootstrap transitions is **one production seed rotation**, covering both hosts. It
becomes two only if C-cap's capacity change turns out to need its own fixed point before the other changes can be
measured (decided when OI-54 step 1 lands).

### 13.4 Executions shared between consumers

- **One candidate C1** per integrated ledger head serves every sub-batch's targeted tests.
- **One strict replay** (§5) per candidate serves `test_xax_selfhost_evolution`, the V2 record and the release.
- **One V2 record** per release covers B0–B6 for all of batch C.
- **One Windows confirm** per release covers OI-55, OI-58 and the OI-56 note runs, all with the same seed.
- **One `bbc.exe` rebuild** after the release serves #55, #51, #47 and BBC's checks.
- **One device session** (Pixel 8 Pro over `adb`) runs OI-49, #48, #49 (Android half), #51 and #47.

### 13.5 Release plan

1. Freeze the candidate (`RELEASES` `candidate`).
2. Run the strict replay.
3. Rotate: three generations on Linux, and the Windows seed cross-built by the fixed point.
4. Confirm natively on Windows 11.
5. Record the V2 evidence.
6. Run the targeted tests, then the full suite once.
7. Rebuild BBC and run its checks.
8. Run the device session; record HotSpot, Wasm and SPIR-V conformance for the changed targets.
9. Append `validated`.
10. Close each issue whose acceptance criteria are met, with its evidence linked; leave the rest open with the
    exact blocker.

### 13.6 Cost: per issue (A) vs batched (B)

Measured unit costs:

- Linux self-build: 8 min.
- Windows build and confirm: 7–11 min.
- Full record: 3 h 4 min to 5 h 33 min.
- Linux test runs: 1 h 14 min to 2 h 6 min.
- An `xaxc edit` or `verify` on the driver: 1–3 min in WSL.
- `bbc.exe` build: about 4 min.

Estimates are marked *est.*

- **A**, one rotation and one full evidence run per driver change, for the 7 driver items:
  - 7 × (8 + 10 + 184…333 + 74…126 + BBC ≈ 15) min ≈ **34–57 h** of machine time.
  - Plus 7 hand remaps of the Windows hosting files.
  - Plus 7 full ledger replays, each run twice (test and evidence).
- **B**:
  - 7 × (apply on two stores ≈ 4–12 min + C1 build 4 min + targeted tests ≈ 15–30 min *est.*) ≈ 3–5 h;
  - plus one release: 8 + 4 (third generation) + 10 + V2 record + one test pass (1–2 h) + BBC (15 min);
  - the V2 record still runs one strict replay with `verify`: 78 min of measured `edit` time plus the untimed
    `verify` calls, then the corpus once instead of 4 times. Corrected projection: ≈ 2–2.5 h *est.* (an earlier
    draft said 1–1.5 h);
  - ≈ **7–10 h** of machine time (*est.*), with one hand remap at most and one replay.
- **Memory:** both are bounded by about 2.3 GB peak RSS per compiler process (phase 2 profile; an earlier draft said 6 GB) in a 19 GB WSL. B runs at most two compiler
  processes at a time; A has the same limit but repeats the work.
- **Agent cost:** A means 7 cycles of reading state, remapping handles and re-running evidence. B means one
  release, plus one gate run per sub-batch.

### 13.7 Audit corrections (2026-11-15) and the execution order

Checked against `main` `d9249ed`, AGENTS.md, the tests and the live GitHub state. The corrections:

1. **Current rules require a rotation and a BBC rebuild after every driver change.** AGENTS.md says to change the
   production compiler by a transaction, "then rebuild with `selfbuild.sh` and rotate the seed", and to rebuild
   BBC "after any production driver change". It also says to open a PR "as soon as each task is finished". In
   addition, `test_the_record_describes_the_committed_compiler` and `seed_requires_python` fail on `main` as soon
   as a driver transaction lands without a rotation.
   **So driver transactions never land on `main` before their release.** They go on a release branch,
   `release/<first ledger>`, cut from `main`. Each sub-batch is a PR into that branch, opened when its own tests
   pass; one release PR merges the validated release into `main`. Phase 0 changes AGENTS.md to say this, in its
   own PR. PRs are merged by the owner (every merged PR so far is `MrxSiN`'s); agents never merge.
2. **The Python test question is settled by AGENTS.md itself.** The native-evolution rule says "Python or other
   languages may test or serve as references but must not generate or implement production compiler logic".
   This more specific rule permits tests that compare a native result with the reference. The OI-50 Windows-seed
   test is such a test, and OI-55's PE cases may be done the same way, inside the existing test file
   (`test_x86_64_narrow_signed_compare.py`, "add no new file"). OI-60's remark is narrower than AGENTS.md and is
   corrected when OI-60 closes. Evidence runners, rotation and ledger tools are tooling, not tests, and are native.
3. **The Windows generator's oracle exists only at ledger 0032.** Its acceptance (§7) compares it with today's
   `hosted.xax` and request. That comparison must run on the 0032 request, before any batch C transaction, or no
   oracle is left. The same applies to the request tool, against `compiler_request` and the committed request.
4. **Phase 5 saves only one remap in this campaign**, because Windows is built only at the release. It stays in the
   campaign for later releases, but only its oracle check is time-critical (item 3). The generator itself must be
   finished before the release.
5. **Corpus freezing (phase 3) needs a size check first.** `corpus()` builds its cases from Python test helpers and
   the reference (`bench_full_selfhost.py` around line 85). Measure the bytes of its input stores before deciding
   to commit them as data. If they are too large, the runner stays a reference-side Python evidence harness with an
   AGENTS.md justification, and only the V2 schema changes.
6. **The one-rotation claim holds, with conditions.** No batch C change is used by the compiler's own store, so no
   change needs the two-stage rotation. Conditions:
   - x86-64 code generation changes (OI-58, PE probes, OI-54 arena) are also tested with C2, because C1 is the old
     seed's code;
   - the driver's growth is checked against its limits after each sub-batch (main is 632 values below `VCAP`);
   - if OI-54 step 1 needs its own fixed point to measure the later steps, the campaign takes two rotations.
7. **WSL may restart the VM and kill long runs.** A full replay started on 2026-11-15 was lost when the VM
   restarted, and its log was overwritten. Long runs keep a `wsl.exe` client attached for their whole duration,
   write to a log named per run, and are recorded as unfinished in the handoff until their last line exists.
   The rerun (2026-11-15, WSL, full clone at e796f50, pinned Linux seed) EXECUTED: `replayed 142 of 142
   LEDGER=eefbb4f9f2b83fc3b23b1341b2af6c4d3afa2d83 xaxc=0ecdcd6bcc8180d3727881dbea7c2d1042d2a403`, no `FAIL`, exit 0,
   wall 1:14:40, peak RSS 2.4 GB (`/usr/bin/time -v`).
8. **Inventory additions:**
   - BBC#4 is blocked on #55. `bbc compile` of those programs at -O0 also needs OI-54, so #55 closes on
     `check`/`emit-bfx` and BBC#4 waits for batch C.
   - The XAX-MCP pin is another repository's PR.
   - Roadmap U2.2 and S8c and the matrix rows marked NONE are outside this campaign.
9. **Branch protection:** `main` is not protected (GitHub API 404). The guard in §9 relies on owner merges until the
   owner adds protection; the RFC cannot add it.

**Execution order** (supersedes §10's order where they differ; each step is one PR unless noted):

| Step | Work | Target branch | Needs | Runs on |
|---|---|---|---|---|
| 1 | Phase 1 strict replay, after the full replay prints `replayed 142 of 142` | `main` | — | WSL |
| 2 | Phase 0: ADR (cadence, release branch, gates) and the AGENTS.md amendment | `main` | — | docs |
| 3 | Phase 2 profile, using step 1's per-transaction timestamps plus one `strace`/`time -v` edit | `main` (evidence note) | 1 | WSL |
| 4 | Batch S PRs: OI-55 PE run, OI-57, the status lines, OI-34 and OI-51 checks | `main` | — | Windows, WSL |
| 5 | Request tool and Windows generator, with their oracle checks at ledger 0032 | `main` | 1 | WSL, Windows |
| 6 | Phase 4: the `derived` ledger line | `main` | 5 | WSL |
| 7 | Cut `release/0033`; batch C sub-batches in this order: C-x86, C-a64, C-jvm (#49, then #48), C-cap (OI-54 steps, OI-52 R2); each tested with C1 (and C2 for x86-64) | release branch | 6 | WSL, Windows, device |
| 8 | Phase 3 (V2 runner) and phase 6 (`rotate.sh`), in parallel with step 7 | `main` | 1 | WSL |
| 9 | Release (§13.5): rotate, confirm, V2 record, full suite, BBC rebuild, device session, `validated`; release PR | `main` | 7, 8 | all |
| 10 | Batch B (#51, #47, #55) on the new `bbc.exe`; BBC#4 follows | `main` | 9 for -O0 programs; #55 `check` can go earlier | Windows, device |

**Plan change (2026-11-16).** Release 0033 ships C-x86 (ledgers 0033, 0034) and C-a64 (ledger 0035) and nothing
else. C-jvm (#49 with ADR-406, then #48) and C-cap (OI-54 steps, OI-52 R2) move to the next release branch,
`release/<its first ledger>`. Reason: each needs native changes inside single functions of 41,000 to 46,000 view lines
(the JVM backend) or new arena, index and liveness layouts (OI-54), with no generator. That is several sessions of
work, and holding the finished fixes (OI-58 item 1, the PE probes, OI-49) for it would leave them unshipped. Step 8
(phases 3 and 6) follows the release, so release 0033 records V1 evidence with the existing tools
(`bench_full_selfhost`, `bench_python_free_seed`, `rotate-seed`), as the ledger 0027 release did.

## 14. Open questions

- Does `xaxc edit` re-root a store? If it does, the request tool could be a generated batch instead of a program.
- Is WSL interop enabled, and does a Windows run started from WSL give the same bytes (phase 6 probe)?
- Does phase 2 show decode and serialize dominate `edit`? Partly answered (2026-11-15): file I/O and writing are under 0.4 s of a 40 s driver `edit`; a one-node `edit` and a whole `verify` take the same time, which points at decoding, but only a symbol-level profile can confirm it. That decides whether a multi-record `edit` is worthwhile
  in phase 8.
- Does the owner accept agent merges gated by `rotate.sh gate`? That is an AGENTS.md change, outside this RFC.
