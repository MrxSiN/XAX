# XAX Compiler Handoff

**Start here.** The last `## ` section of this file is the current handoff: what landed, what runs, what is open and
the next step. Every earlier section is a dated historical record (AGENTS.md); a later section supersedes it. List the
sections with `grep -n '^## ' XAX_HANDOFF.md` and read only the last one, plus older ones it names. Open design
questions are in `XAX_OPEN_ISSUES.md`; current levels are the generated blocks below.

A "Next", "Remaining" or "Queued" item in an earlier section records what was planned then. It is not an active task: only the
last section's next steps apply now, and only after checking them against `git log` and the open issues.

## Contents

Topic sections are listed first, then every dated section in file order (oldest first). The list can lag a newly
appended section: the last `## ` heading of the file is the current handoff, whatever this list ends with.

- [Invariants that must not drift](#invariants-that-must-not-drift)
- [Current repository state](#current-repository-state)
- [Milestones M0-M14 (historical status)](#milestones-m0-m14-historical-status) (5 entries)
- [Self-hosting steps (S0-S15)](#self-hosting-steps-s0-s15) (110 entries)
- [JVM](#jvm) (5 entries)
- [Android](#android) (11 entries)
- [Windows](#windows) (3 entries)
- [Replacement levels and performance](#replacement-levels-and-performance) (16 entries)
- [Other targets](#other-targets) (2 entries)
- [Compiler engineering](#compiler-engineering) (9 entries)
- [Open issues](#open-issues) (1 entries)
- [Documentation and process](#documentation-and-process) (2 entries)

Dated sections (historical records; a later section supersedes an earlier one):

- [N0 native-evolution bootstrap — 2026-11-05 (ADR-367, ADR-368)](#n0-native-evolution-bootstrap--2026-11-05-adr-367-adr-368)
- [N0 native-evolution bootstrap: N0.3 landed — 2026-11-05 (ADR-370, ADR-371)](#n0-native-evolution-bootstrap-n03-landed--2026-11-05-adr-370-adr-371)
- [N0 complete: native evolution — 2026-11-05 (ADR-372)](#n0-complete-native-evolution--2026-11-05-adr-372)
- [After N0: R1, the object form, and BBC's state — 2026-11-05 (ADR-373..375)](#after-n0-r1-the-object-form-and-bbcs-state--2026-11-05-adr-373375)
- [BBC on the native compiler: where it stands — 2026-11-06 (ADR-376)](#bbc-on-the-native-compiler-where-it-stands--2026-11-06-adr-376)
- [BBC's PE decline found and fixed: frame-path heap views — 2026-11-06 (ADR-377)](#bbcs-pe-decline-found-and-fixed-frame-path-heap-views--2026-11-06-adr-377)
- [Ledger 0015 and the self-hosting record — 2026-11-06 (ADR-378)](#ledger-0015-and-the-self-hosting-record--2026-11-06-adr-378)
- [The production driver on Windows, natively — 2026-11-06](#the-production-driver-on-windows-natively--2026-11-06)
- [BBC's driver on the production driver: ledgers 0016, 0017 — 2026-11-06 (ADR-379, ADR-380)](#bbcs-driver-on-the-production-driver-ledgers-0016-0017--2026-11-06-adr-379-adr-380)
- [The image buffer packed: ledger 0018 — 2026-11-07 (ADR-381)](#the-image-buffer-packed-ledger-0018--2026-11-07-adr-381)
- [BBC's `bbc.exe` built natively; C0 is the seed: ledger 0019 — 2026-11-07 (ADR-382, ADR-383)](#bbcs-bbcexe-built-natively-c0-is-the-seed-ledger-0019--2026-11-07-adr-382-adr-383)
- [Deep nesting on AArch64, the old-vs-new benchmark and hanoi -O0's limits: ledger 0020 — 2026-11-07 (ADR-384)](#deep-nesting-on-aarch64-the-old-vs-new-benchmark-and-hanoi--o0s-limits-ledger-0020--2026-11-07-adr-384)
- [Ledger 0022: constant folding and hoisted registers on x86-64 (2026-11-08)](#ledger-0022-constant-folding-and-hoisted-registers-on-x86-64-2026-11-08)
- [BBC's importer bounds branch, the capacity word (ledger 0023) and the plan completed — 2026-11-08](#bbcs-importer-bounds-branch-the-capacity-word-ledger-0023-and-the-plan-completed--2026-11-08)
- [Independent audit: x86-64 signed compares below 32 bits (2026-11-11)](#independent-audit-x86-64-signed-compares-below-32-bits-2026-11-11)
- [Android R4 re-measured, ledger 0025 and the Windows stack probe — 2026-11-11 (ADR-394)](#android-r4-re-measured-ledger-0025-and-the-windows-stack-probe--2026-11-11-adr-394)
- [OI-56 fixed in the stores: PE images commit their stack reserve (ledger 0026) — 2026-11-12 (ADR-396)](#oi-56-fixed-in-the-stores-pe-images-commit-their-stack-reserve-ledger-0026--2026-11-12-adr-396)
- [The Windows seed is the production compiler and builds itself on Windows 11 — 2026-11-12 (ADR-397)](#the-windows-seed-is-the-production-compiler-and-builds-itself-on-windows-11--2026-11-12-adr-397)
- [Windows row at R3: the compiler is the practical application — 2026-11-12](#windows-row-at-r3-the-compiler-is-the-practical-application--2026-11-12)
- [Seed rotated after ledgers 0024 and 0025; OI-55 closed on Linux — 2026-11-12 (ADR-393)](#seed-rotated-after-ledgers-0024-and-0025-oi-55-closed-on-linux--2026-11-12-adr-393)
- [Windows R4 measured and withheld: chains is at parity with rustc — 2026-11-12](#windows-r4-measured-and-withheld-chains-is-at-parity-with-rustc--2026-11-12)
- [Linux seed rotated to ledger 0026 — 2026-11-12](#linux-seed-rotated-to-ledger-0026--2026-11-12)
- [Windows chains: improved batch, a faster C arm, R4 still withheld — 2026-11-12](#windows-chains-improved-batch-a-faster-c-arm-r4-still-withheld--2026-11-12)
- [Windows maintenance cycle recorded on xbench (R5 evidence; R6 not yet) — 2026-11-12](#windows-maintenance-cycle-recorded-on-xbench-r5-evidence-r6-not-yet--2026-11-12)
- [Ledger 0027 (loop-slot rule) tried and dropped; OI-59 found — 2026-11-13](#ledger-0027-loop-slot-rule-tried-and-dropped-oi-59-found--2026-11-13)
- [OI-59 diagnosed: edge copies overwrite shared edge spill slots; reference fixed — 2026-11-13](#oi-59-diagnosed-edge-copies-overwrite-shared-edge-spill-slots-reference-fixed--2026-11-13)
- [Windows evolution ledger paths coexist — 2026-11-13](#windows-evolution-ledger-paths-coexist--2026-11-13)
- [Ledger 0027 (edge-copy staging), both seeds, four rows at R3 — 2026-11-13](#ledger-0027-edge-copy-staging-both-seeds-four-rows-at-r3--2026-11-13)
- [Native resolved-snapshot mutation handoff — 2026-11-13](#native-resolved-snapshot-mutation-handoff--2026-11-13)
- [Build/rotation campaign, steps 2–4 — 2026-11-15](#buildrotation-campaign-steps-24--2026-11-15)
- [Build/rotation campaign: step 5 started (request tool) — 2026-11-15](#buildrotation-campaign-step-5-started-request-tool--2026-11-15)
- [Build/rotation campaign: step 5 done (Windows generator) — 2026-11-15](#buildrotation-campaign-step-5-done-windows-generator--2026-11-15)
- [Build/rotation campaign: step 6 done (derived request) — 2026-11-15](#buildrotation-campaign-step-6-done-derived-request--2026-11-15)
- [Build/rotation campaign: step 7 started (C-x86) — 2026-11-16](#buildrotation-campaign-step-7-started-c-x86--2026-11-16)
- [Build/rotation campaign: release 0033 done — 2026-11-16](#buildrotation-campaign-release-0033-done--2026-11-16)
- [Build/rotation campaign: after release 0033 — 2026-11-16](#buildrotation-campaign-after-release-0033--2026-11-16)
- [Build/rotation campaign: phase 3 done (evidence V2) — 2026-11-16](#buildrotation-campaign-phase-3-done-evidence-v2--2026-11-16)
- [Build/rotation campaign: phase 6 done (RELEASES, POLICY, rotate.sh) — 2026-11-16](#buildrotation-campaign-phase-6-done-releases-policy-rotatesh--2026-11-16)
- [Native oracle: design and slice 1 done — 2026-11-16](#native-oracle-design-and-slice-1-done--2026-11-16)
- [Native oracle: slice 1 widened, slice 2 done — 2026-11-16](#native-oracle-slice-1-widened-slice-2-done--2026-11-16)
- [Release 0036 started: #49 part 1, the verifier — 2026-11-16](#release-0036-started-49-part-1-the-verifier--2026-11-16)
- [#49 part 2: anchors in the JVM program's F38 — 2026-11-16](#49-part-2-anchors-in-the-jvm-programs-f38--2026-11-16)
- [#49 parts 2+3: the JVM program's call path mapped, the change set designed — 2026-11-16](#49-parts-23-the-jvm-programs-call-path-mapped-the-change-set-designed--2026-11-16)
- [#49 parts 2+3 done: the JVM program lowers catching calls — 2026-11-16](#49-parts-23-done-the-jvm-program-lowers-catching-calls--2026-11-16)
- [#49 part 6, issues #95 and #96, release 0036 done — 2026-11-18](#49-part-6-issues-95-and-96-release-0036-done--2026-11-18)
- [ADR-410 pin retirement, OI-61 and #55 on release 0037 — 2026-11-18](#adr-410-pin-retirement-oi-61-and-55-on-release-0037--2026-11-18)
- [#55 at 1,048,576 and the #48 design — 2026-11-18](#55-at-1048576-and-the-48-design--2026-11-18)
- [ADR-411 (#48) mapped in the native programs — 2026-11-18](#adr-411-48-mapped-in-the-native-programs--2026-11-18)
- [ADR-411 implementation: the entry-word question — 2026-11-18](#adr-411-implementation-the-entry-word-question--2026-11-18)
- [#48 libxposed lifecycle entries on release 0037 — 2026-11-18](#48-libxposed-lifecycle-entries-on-release-0037--2026-11-18)
- [Native oracle slice 3 done; C-cap moved to the next release — 2026-11-18](#native-oracle-slice-3-done-c-cap-moved-to-the-next-release--2026-11-18)
- [Release 0037 rotated — 2026-11-19](#release-0037-rotated--2026-11-19)
- [Release 0037 on `main`; #55 closed; C-cap designed — 2026-11-19](#release-0037-on-main-55-closed-c-cap-designed--2026-11-19)
- [C-cap: OI-52 R2 on `release/0038`, sub-batches a–c — 2026-11-19](#c-cap-oi-52-r2-on-release0038-sub-batches-ac--2026-11-19)
- [Release 0038 on `main`: 64-bit checked offsets — 2026-11-19](#release-0038-on-main-64-bit-checked-offsets--2026-11-19)
- [OI-52 R2 on an Android device — 2026-11-19](#oi-52-r2-on-an-android-device--2026-11-19)
- [Release 0039 on `main`: OI-54 step 1 — 2026-11-20](#release-0039-on-main-oi-54-step-1--2026-11-20)
- [Release 0040 on `main`: consumer issues #136, #137, #133 — 2026-11-21](#release-0040-on-main-consumer-issues-136-137-133--2026-11-21)
- [Release 0041 on `main`: `versionName` and uppercase CID digits — 2026-11-23](#release-0041-on-main-versionname-and-uppercase-cid-digits--2026-11-23)
- [Release 0042 on `main`: carrier replace by CID, Wasm offset check, container sizing — 2026-11-24](#release-0042-on-main-carrier-replace-by-cid-wasm-offset-check-container-sizing--2026-11-24)

## Invariants that must not drift

- Meaning is source: canonical XAX is the typed semantic graph/store, never diagnostic text, Python constructors, packet dumps, JSON, or CLI syntax.
- Bootstrap labels B0–B6 are evidence claims. Capability presence, plans, or host-language simulation do not satisfy them.
- B5/B6 claims are target-scoped. The M14 `xax-semantic-image-v1` result does not silently close the legacy native, WebAssembly, or accelerator backends.
- B levels come only from `xax_selfhost.bootstrap_status` (generated blocks below); S-step self-compilation is a component fixed point, never B1–B4 (ADR-177).
- Committed self-hosting stores are frozen and are their evolution ledger's chain ends (`tests/test_store_regeneration.py`, ADR-361); the M14 Python bootstrap is retired (ADR-362) and the native seed is the bootstrap seed; evidence that claims XAX-hosted execution runs with `XAX_REQUIRE_NATIVE=1`.
- No hidden allocation, synchronization, syscall, initialization, exception edge, ownership transfer, device runtime, or target runtime assistance.
- Tests/benchmarks count only when actually executed. Host-unavailable cases remain unavailable, not passed.

## Current repository state

<!-- xax-status:levels -->Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): R6: jvm, linux-aarch64, linux-x86_64; R3: aarch64-baremetal, android-arm64, browser-web, gpu-spirv-cuda-metal-dxil, wasm32-wasi, windows-x86_64-pe; R1: riscv64; no level yet: bsd-unix, dotnet-clr, macos-ios-apple, rtos-embedded-mcu.<!-- /xax-status:levels -->

<!-- xax-status:bootstrap -->Bootstrap status (derived by `xax_selfhost_seed.bootstrap_status` from `compiler/bootstrap/evidence/records/0042.record`): whole production compiler: B0, B1, B2, B3, B4, B5, B6 established (release 0042's V2 record, by `xax_evidence levels`); S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: native-elf `compiler/bootstrap/seed/xaxc-linux-x86_64`, 31,851,585 bytes, requires Python: no.<!-- /xax-status:bootstrap -->

Sections below are dated; a later section supersedes an earlier figure. The current full-suite result is in the latest release section of this file that reports one.

M1–M14 are complete for their explicitly declared prototype scopes. M14 adds function/graph introspection; generic semantic-object and byte META values; verifier-gated program materialization; canonical-store emission; semantic verification; recursive semantic-image compilation; and an immutable seed boundary.


OI-02 now has four measured objectization arms in `compiler/benchmarks/bench_oi02_granularity.py`: function, module, `call_indirect`, and block. The block arm splits multi-block graphs into a skeleton plus content-addressed block units and requires byte-identical canonical graph/function reassembly before verification/execution. It shows modest rewrite-byte reuse on shallow four-block edits, but higher store/query overhead and no protection from direct-call caller-CID cascades; `call_indirect` remains the strongest locality result. OI-02 is still open and the canonical format is unchanged.

OI-04 now includes the previously missing catalog-free comparator. `bench_oi04_type_vocabulary.py` carries a deterministic store-wide dictionary for every CID referenced by at least two objects, encodes those references as small indices, leaves one-use CIDs explicit, and requires byte-identical canonical reconstruction with CID/index/digest checks. Across the 26,703-byte integer corpus it saves 4,174 bytes (15.6%), compared with 4,991 bytes (18.7%) for `bits5` and 5,623 bytes (21.1%) for `common`. This shows that most byte savings are generic repeated-CID compression, though a fixed catalog retains an incremental advantage. OI-04 remains open for real floating-point workloads; no comparator is canonical.

The authoritative M14 closure target is `xax-semantic-image-v1`. Its XAX entry graph performs materialize → verifier-facing call → canonical semantic-image encode → finalization/build. Canonical graph verification and canonical store formation remain deliberate trusted META substrate operations consistent with the minimal trusted-core model. Legacy x86-64, AArch64, WebAssembly, and accelerator lowerers remain Python bootstrap/reference implementations and are not included in the M14 B5/B6 claim.

*(Corrected 2026-10-06, ADR-177: B5/B6 are withdrawn for this target; the evidence now records the derived status below. Historical wording kept.)* Executed evidence in `compiler/bootstrap/m14_selfhost_evidence.json` records B2–B6 for that target: compiler root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`; entry function `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`; generation 0/1/2 BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`; and 4/4 fixed-policy function vectors matching. The committed 46,255-byte seed runtime reconstructs the compiler byte-identically with repository `PYTHONPATH` removed. It is an immutable bootstrap artifact that internally contains Python modules; B6 does not claim interpreter elimination or diverse-trust proof.

## Milestones M0-M14 (historical status)

### Validation state at M14 (historical)

- Syntax/import compilation: passed.
- M14 narrow tests on final state: **7/7 passed**.
- Broad unfiltered regression before the final two artifact assertions: **237 tests**, exactly the same **8 environment-only errors** as M13: 6 Windows x86-64 native execution cases and 2 AArch64/QEMU cases.
- Exact final applicable regression: **231/231 passed** out of 239 current tests, excluding only those same 8 unavailable host-bound cases.
- M14 compiler image: **2,020 bytes**, SHA-256 `05eb15404836e9f77b2f2931489859c43c0f75dcb00c891504e9ddcdd427cd07`.
- M14 seed runtime: **46,255 bytes**, SHA-256 `4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52`, BLAKE3-256 `eb8157fd2a00fcca5666ea574b7641b4adcb43382f5fbb60f8addead5f04b7b6`.
- M14 evidence JSON: **3,240 bytes**, SHA-256 `36c2a9a57aea432250ff7a1595e19535ed1d37f2aa7588cd4edd1f01710c6dfa`.
- M14 artifact generation was repeated after the final evidence wording correction; all three committed artifact hashes were identical.
- Deterministic wheel: two `SOURCE_DATE_EPOCH=946684800` builds matched byte-for-byte at **117,715 bytes**, SHA-256 `fa4add6e966ca09fe5df6c02043e91d333f0726ec92f681a03bf7251e4a4a34e`.
- OI-04 CID-dictionary edit: the focused OI-04 tests pass natively. The attempted broad suite exceeded the current host execution window; no new broad-pass claim is made.

### Queued (deferred by the user, 2026-10-02)

- **Device run of the stateful app (ADR-111)**: on an arm64 device, run `compiler/integration/android/validate_counter_apk.sh`. It expects 0 → 1 → 2 → 3, then `force-stop` and relaunch → 3, then 4. Record the output in `compiler/benchmarks/android_counter_evidence.json` (`device`) and, if it passes, raise the Android `practical_application` matrix field from PROTOTYPE to EXECUTED. *(2026-10-04: done on an Android 12L x86_64 emulator through ARM translation, ADR-155; a run on arm64 hardware is still wanted.)*

### Exact next task

1. **After S6** (roadmap): S6 is EXECUTED for RV64 (ADR-150: every committed store decided by XAX; B1–B4 for the RISC-V backend and the store verifier; ADR-151: BLAKE3 through both RISC-V generators with aggregates, hidden result areas, and stack arguments). S7a is EXECUTED (ADR-152): the x86-64 views backend is an XAX program, byte-identical to `xax_x86_64_views.py`, closes over itself natively, and lowers every production helper (`host_image`). Next (S7b): the object table and image assembly, and exact rejection diagnostics, in XAX; then code quality for the x86-64 profile (fall-through layout, caller-saved registers), now 1.08–1.32× the optimizing backend's run time. B4 runs are opt-in (`XAX_FIXED_POINT=1`); regenerate evidence with `benchmarks/bench_selfhost_closure.py --write` and `bench_selfhost_fixed_point.py --write` after backend or helper-store changes.
2. **ADR-097 breadth**: done for wasm32/PE (ADR-098), calls, and padding (ADR-099). Cross-storage targets across calls done (ADR-101: `link_target`, x86-64 executed). Remaining: execute a cross-call program on wasm32 and PE.
3. **OI-38 remainder**: PE uses the converged allocator (ADR-095) and the ADR-148 optimizations; current PE evidence executes on Windows (ADR-170). Remaining: floats and aggregates in it, a cross-block allocator (shuffles and home reloads), and translation validation of the lowering view. All three Linux workloads are within 1.05× of the fastest of gcc/clang/rustc (ADR-147); keep it that way after every backend change (§15.0).
4. **U1.2b remainder**: stack-storage, float, aggregate, and indirect-call functions on the PE register path (ADR-083 covers compares, foreign calls, heap memory; `sum_to` 8.02x). Install a C toolchain to turn this into an R4 comparison.
5. **OI-33 (Linux)**: argv/env/auxv done (ADR-094); TLS and unwind/debug data remain. **OI-40**: register scalars, pure callbacks (ADR-102), and lend entries (ADR-115, OI-42 closed: `qsort_r`) done; aggregates, stack arguments, and variadics remain. Lend-entry follow-ups: writable lends, several views, and AArch64.
6. **Windows PE workload**: done under Wine (ADR-100: MinGW-w64 C twin; XAX file 20% smaller, code larger because gcc folds `sum_to`/dispatch). Still needed: a Windows host, and a run-time-bound PE workload.
7. **Stateful Android app (ADR-111)**: run `compiler/integration/android/validate_counter_apk.sh` on a device. It installs `android_counter_activity.apk` and checks 0 → 1 → 2 → 3, `force-stop` and relaunch → 3, then 4.
8. **Android (ADR-105/106)**: device-free evidence exists (`bench_android_bionic.py`, `bench_android_official_tools.py`, `bench_android_ndk_twin.py`; they need the host tooling listed in `XAX_STATE.md`). C → XAX callbacks run on bionic threads (ADR-107). ART verifies all 62 classes in all 20 APKs, libxposed included (ADR-108). All 12 libxposed module profiles execute on ART with a stand-in framework (ADR-109); what remains is LSPosed in a real target process. rebuild the environment with `integration/android/make_android_root.py`. Next: run the packed APK on a device, then make format 5 the default; AArch64 loops now use registers (ADR-110); next for code quality: pinning loop-invariant homes, and floats/memory on the register path. After that, a richer Activity (state, I/O, lifecycle: U1 workload 4) and libxposed runtime execution.
9. **Browser (ADR-103/104)**: click entries are done. Next: static storage, so state need not live in the DOM; a Web IDL-driven binding importer (OI-32 is closed by ADR-166 without Web IDL); and an Emscripten/Rust wasm size comparison for R4.
10. **JVM (ADR-112, ADR-156–167, OI-35)**: R4 is done. The next item is a CLI/IL container for OI-35's CLR half.
11. **RISC-V (ADR-113)**: compare/branch fusion and copy coalescing (Collatz 3.72× `clang -O2` instructions); F/D floats and memory; a Linux `ET_EXEC` profile through `xax_elf`; a QEMU-system or hardware run (OI-44).

### Reproduce M14 evidence

```text
cd compiler
export PYTHONPATH=src
python -m py_compile src/*.py tests/*.py benchmarks/*.py bootstrap/*.py
python -m unittest tests.test_xax_selfhost -v
python bootstrap/generate_m14.py
python -m unittest discover -s tests -v
SOURCE_DATE_EPOCH=946684800 python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

Since ADR-114 the eight formerly host-bound cases execute on Linux x86-64: raw Win64 images go through a harness call thunk, and AArch64 images run in Unicorn when QEMU is absent (`pip install unicorn`). PE executables still need Windows or Wine. The JVM tests need `java`/`javac`; the RISC-V tests need Unicorn (`llvm-mc` adds an independent decode).

### Relevant specification

`XAX_SPEC.md` §8 and §16; `XAX_CONFORMANCE.md` §15; roadmap M14; ADR-027, ADR-057 and ADR-058; OI-25/OI-26/OI-27.

## Self-hosting steps (S0-S15)

Step: [S1](#step-s1) · [S4](#step-s4) · [S5](#step-s5) · [S6](#step-s6) · [S7](#step-s7) · [S8](#step-s8) · [S9](#step-s9) · [S10](#step-s10) · [S11](#step-s11) · [S12](#step-s12) · [S13](#step-s13) · [S14](#step-s14) · [S15](#step-s15) · [other](#other-self-hosting-records)

### Step S1

#### Self-hosting S1 — 2026-10-03 (ADR-116)

- The RISC-V encoder is an XAX function on the production path (`xax_selfhost_riscv64.py`, `bootstrap/xax_riscv64_encoder.xax`). Regenerate with `PYTHONPATH=src python -c "import xax_selfhost_riscv64 as m; m.write_encoder_store()"`; `test_xax_selfhost_riscv64.py` fails if the store drifts.
- Next is S2: pass a borrowed output view into a native leaf so a whole function's word stream comes from XAX. Then S3, the store codec and full BLAKE3, so CIDs are computed by XAX (ladder in the roadmap).
- Commits on `main` carry no Claude attribution, per the user.
- S2 (ADR-117): the whole BLAKE3 hash is XAX (`xax_selfhost_blake3.py`, `bootstrap/xax_blake3_hash.xax`), and `blake3.blake3()` uses it by default on Linux x86-64 (`XAX_BLAKE3_PYTHON_HASH=1` forces the driver). Next is S3: the store codec (ULEB, object framing, index) into lent views.
- S3 (ADR-118): the store container decoder is XAX (`xax_selfhost_store.py`); `StoreReader._decode_native` is the production path, and `XAX_STORE_PYTHON_DECODER=1` forces the bootstrap parser. Regenerate with `write_decoder_store()`, which always uses the bootstrap parser. Next is S3b: object bodies.
- S3b (ADR-119): object envelopes are parsed by XAX and `get` uses them. Next is S3c: typed body decoding (graph and function bodies).
- S3c (ADR-120): graph-body syntax is XAX (`XAX_GRAPH_PYTHON_DECODER=1` forces the bootstrap parser; regenerate with `write_graph_decoder_store()`). Next is S3d: branch targets, value definitions, and dominance over the decoded stream.
- S3d (ADR-121): control-flow analysis is XAX (`XAX_CFG_PYTHON=1` forces the bootstrap; regenerate with `write_cfg_store()`). Next is S3e: value definitions and SSA dominance.
- S3e (ADR-122): value definitions and dominance are checked in the same XAX CFG function (out word 2). Next is S4: per-operation typing rules.

### Step S4

#### S4 — 2026-10-03 (ADR-132)

- Scalar operation typing is XAX (`XAX_TYPING_PYTHON=1` forces the bootstrap; regenerate with `xax_selfhost_typing.write_typing_store()`). Wiring: `_native_typing()` and the `proven_nodes` gate in `_parse_graph_uncached`. Next is S4b: aggregate/sum/call typing, then memory and resource facts, which are the bulk of the remaining verifier.

#### S4b — 2026-10-03 (ADR-133)

- Aggregate and sum typing joined the XAX typing function (two-pass type decoding: scalars, then tuple/array/sum of scalars). Regenerate the store with `xax_selfhost_typing.write_typing_store()` after any change; `test_committed_store_is_the_built_program` fails otherwise. Next is S4c: move call, constant, and memory typing together with `_end_heap_views` and the pointer/owner/effect facts, which is most of the remaining verifier.

#### S4c — 2026-10-03 (ADR-134)

- Resource/effect and meta typing joined the XAX typing function (third type pass; nodes carry an extra-word count, used by `effect.step` for operand identities). The agreement test compares exact outcomes (code, rule, entity) with the path on and off, because later passes (linear flow, resource-join siblings) can still reject a node whose typing is proven. Next is S4d, which is a larger step: the call/memory branches update pointer, owner, and effect facts, so the fact tables must move with them.

#### S4d.1 — 2026-10-03 (ADR-135)

- Constants and terminators joined the XAX typing function. Python skips their checks via `proven_constants` and `proven_terminators` in `_parse_graph_uncached`; a proven constant still records its link fact. `NativeTyping.check` returns node verdicts and then block verdicts. Next is S4d.2, which is a design step: represent the fact tables (pointer facts with storage, offset, extent, permission, and window; owner and effect facts with initialized intervals; ended and live sets; per-edge exits; the fixpoint) as XAX data, starting with stack storage.

#### S4d.2a — 2026-10-03 (ADR-136)

- `fact_free` in `_parse_graph_uncached` gates the fact loop (`range(0 if fact_free else ...)`; the for-else fixpoint failure is guarded). The XAX check's last output word is the memory-free flag. Proven `call.direct` nodes are not added to `proven_nodes`, because their branch also does view and resource borrowing. Next is S4d.2b: model stack storage facts in XAX (allocation, owner, effect with initialized intervals, lifetime end, leaks), so graphs whose only memory is stack storage also skip the Python passes.

#### S4d.2b — 2026-10-03 (ADR-137)

- The facts engine is built from `xax_structured.Proc` helpers (`E` in `xax_selfhost_facts.py`): every helper is an XAX function `f(a, b, views) -> (bits<64>, views)`, with more arguments passed in header words `H_ARG + i`. State lives in the output view (layout in `_engine`). Add an operation by writing a handler and registering it in `build_engine`'s `handlers`; graph-level declines live in `_engine`. Then regenerate the store with `xax_selfhost_typing.write_typing_store()` and run `test_xax_selfhost_facts.py`.
- Cost: the per-process native compile is about 1.8 s. Caching the compiled image by store hash would remove it.

#### S4d.2c — 2026-10-03 (ADR-138)

- To see why the engine declines a graph, patch `NativeTyping.facts` (as `test_xax_selfhost_facts.py` does) and call `native.decline_reason()`; header word `H_NODE` holds the node record being modelled. The native image cache lives in `~/.cache/xax-native` (override with `XAX_NATIVE_CACHE`).

#### S4d.2d — 2026-10-03 (ADR-139): S4 complete

- To find graphs the engine declines, wrap `_parse_graph_uncached` and `NativeTyping.facts` over the suite and count graphs that parse but whose facts call did not accept. The result should be only seed graphs, parsed while `_TYPING_BUILDING` is set or while `_native_cfg()` is still loading.
- `target.op` lives in `xax_selfhost_target.py` and is registered in `build_engine`. Record and link helpers are `_layout`, `_has_link_function`, `_dependents_function`, and `_window_function` in `xax_selfhost_facts.py`.
- A direct call's aux words are `[count, summary blocks, operation count, operations, declaration count, (view, target) pairs]`, or `[0]` when there is neither a summary nor a declaration.
- After changing any XAX helper, rebuild its committed store: `write_typing_store()`, or `write_cfg_store()` for the CFG views. The store-equality tests check that the committed store is the built one.

### Step S5

#### S5a — 2026-10-03 (ADR-140)

- `xax_riscv64._object_table` copies the store objects for the backend program (S5b; the S5a `_marshal` is gone), and `_compile_with_xax` turns its output into a `Riscv64Image`. Use `backend="python"` to compare, or `XAX_RISCV64_BACKEND_PYTHON=1` to disable the program.
- After editing `xax_selfhost_riscv64_backend.py`, run `write_backend_store()`. A test checks that the committed store is the built one.
- The program declines with `give(NONE)` (`_ok`) and records nothing about why. To debug, bisect with the differential in `test_xax_selfhost_riscv64_backend.py`.

#### S5b — 2026-10-03 (ADR-141): S5 complete

- The backend program's front end (`_frontend`, `_translate`, `_interface`, `_erased`, `_node_info`, `_term_end`) reads the graph-decoder stream format from `xax_selfhost_graph`. A change to that stream must change these readers too.
- The output words are: `out[1]` the code word count, `out[2]` the range count, `out[3]` the offsets, `out[4]` the function order (object indices), `out[5]` the entry widths `[P, widths, R, widths]`, and `out[STREAM_AT]` the function count.

### Step S6

#### S6a — 2026-10-03 (ADR-142)

- `_linear_flow` in `xax_selfhost_facts.py` sets `H_LINEAR`. The engine runs it right after laying out the graph, so it is set even when the fact passes later decline. `NativeTyping.linear_flow()` reads the flag, but only after a check that returned status 0; otherwise the header may be stale.

#### S6b.1 — 2026-10-03 (ADR-143)

- `xax_compiler._XAX_VALID_OBJECTS` holds the CIDs XAX proved. `_xax_prove_objects` fills it at the start of `verify_store`. To compare against the bootstrap, clear the set, as `test_xax_selfhost_objects._bootstrap_accepts` does.

#### S6b.2 — 2026-10-03 (ADR-144)

- The store verifier (`xax_selfhost_verify.py`) records the check behind its last 0 verdict in `out[2]`, as an index into `DECLINE_SITES`. Call `build_verifier_program()` in-process first so the codes are assigned.
- **Open: x86-64 register-resident lowering and aliased variables.** In `_function_ok`, `e.var("ne_results", p["ne_at"])` followed by `e.set("ne_at", ...)` and a branch produced a native value equal to the *new* `ne_at`. Storing the snapshot to memory, or binding `ne_at + 0`, was correct. Small `Proc` programs with the same shape compiled correctly, and the frame (spill-all) lowering could not run the program to compare. The `E.var` fresh-copy rule avoids the pattern in every E-DSL program. A root-cause fix belongs in `xax_x86_64_regalloc` (edge copies or home slots for block parameters bound to two names), with a regression test.
- Helper programs import each other at hash time (`xax_structured` hashes its types at import). `_xax_verify_store` therefore returns "not proven" on `ImportError` and while any helper is building. Otherwise a swallowed `ImportError` leaves the native hasher off for the whole process, which slows the suite about 3×.

#### S6b.3 — 2026-10-03 (ADR-146)

- In the verifier's object table, a graph fragment's payload is its decoder stream followed by `[body length, body bytes]`. `_program`'s record walk skips both. The store verifier is the only reader of that layout; the S5b RISC-V table is unchanged.
- `graph` (in `_graph_ok`) is shared by ordinary functions and group members. In a group it writes `[count, (member, span start, span end)...]` for each member graph; `_group_ok` uses that for the breadth-first orders and the erased graph bytes.
- `NativeStoreVerifier.verify(words, count, groups)` returns each proven group's member graph indices (read under the lock). `verify_object` parses them in member order.
- To decide a store directly with `_xax_verify_store`, run `verify_store` on it first. Type verdicts (ADR-143) come from that run, and without them no function is proven.

### Step S7

#### S7b.1 rejection diagnostics — 2026-10-07 (ADR-179, ADR-180)

- A views ISA opts in with `DIAGNOSTICS = "<family>"`, `LOWERED`, and `LOWERED_NAME` (`X86_64` does; `RISCV64` does not, so `_legal` emits exactly `_ok` there and its store is unchanged). Each check is `_legal(e, isa, condition, rule, entity, expected, actual)`. Rules and codes live only in `VIEWS_RULES`. The per-function checks are in `_legality`, which runs inside `_translate` before the stream is written and keeps the bootstrap's order. Do not add a rejection anywhere else.
- Record format and renderer: `xax_selfhost_diagnostics.py`. Differential: `tests/test_xax_selfhost_diagnostics.py` (`backend="xax"` must equal `backend="python"`). Add a case there for every new rule.
- Next: S7b.2 (object table and image record from XAX), S7b.3 (RISC-V family), then S8 (verifier rejections). `compiler/migration/python_authority_inventory.json` lists what remains; update it when a component moves.

#### S7b.2 object table and image record — 2026-10-07 (ADR-181)

- Input of both views programs: `[S, entry CID words]`, then S store records in store order and the bound target record: `[kind, reference count, reference CIDs..., own CID, payload length, payload...]`. `G_REFS` holds the resolved indices; use `_reference` and `_cid_at`/`_cid_words`, and never read reference indices from the input.
- Output: words 1–5 are code count, range count, offsets, image record (`CID_WORDS + 1` words per function: CID, end), and widths. Read it with `collect_program_output`.
- A pinned closure size in `test_xax_selfhost_fixed_point.py` counts the backend's functions; adding a program function changes it.

#### S7b.3 and S7b complete — 2026-10-07 (ADR-182)

- Both views families opt into diagnostics. `_legal(..., deferred=True)` exists for checks the bootstrap makes after layout. It records the first failure in `G_PENDING`, and `_program` rejects only after patching succeeds. Keep that order if a family gains layout-time rejections.
- Next is S8: verifier totality. Start with the store container (`xax_selfhost_store.py`): one reject site per bootstrap check, two record value types (FORMAT for templated text such as `"{} available bytes"` and `"record:{}"`, HEX for byte strings), and a two-pass digest protocol (the decoder finds `digest_end`, the XAX hash computes the digest, a second pass decides the comparison and the index and root checks that follow it in the bootstrap's order).

### Step S8

#### S8c.1 integer typing rejections — 2026-10-08 (ADR-214)

- `_node_entry` (`xax_selfhost_typing.py`) calls `_integer_rejection`, which returns the first failing bootstrap check as a site and three payload words. The verdict becomes `REJECTED` and the record lands at `DIAGNOSTICS + 4 * node`; `rejection(record, cids)` renders it. Site 0 means "leave it to the bootstrap".
- Next (S8c.2): the float, compare, aggregate/sum, resource, meta, constant, and call families, same pattern; keep deferring every case whose bootstrap check would first raise a decode diagnostic. Then facts declines and object verification.

#### S8c.2 float and compare typing rejections — 2026-10-08 (ADR-215)

- `_rejection` holds one step list per family, in the bootstrap's check order; `_SITES` renders. Add a family by adding its steps and its site renderers.
- Next (S8c.3): aggregate and sum families. Their diagnostics quote element lists: render them from the program's `ITEMS`/`COUNT` tables (pass the owner's type index), not from Python decoding.

#### S8c.3 aggregate and sum typing rejections — 2026-10-08 (ADR-216)

- Renderers take a context `r`: `r.h` (CID hex), `r.items(type)` (program tables), `r.operands(position)` (input stream). Lists in a diagnostic must come from these, not from Python decoding.
- A changed typing store invalidates `selfhost_x86_64_evidence.json` and `selfhost_closure_evidence.json` (`test_audit_remediation`); re-run both benches with `--write` on Linux x86-64.
- Next (S8c.4): resource/effect and meta families, then constants and calls.

#### S8c.4 meta typing rejections — 2026-10-08 (ADR-217)

- `_meta_steps` builds each meta operation's checks from `META_RULES`. Undecoded `bits` and form-5 types defer; other non-opaque types reject.
- Next (S8c.5): resource/effect (`_verify_resource_effect_node`). Its diagnostics quote raw CID tuples, `_EffectType` reprs, flags, and transition lists; render them from the input stream and the program's tables (`EDOMAIN`, `EINST`, `RKIND`, `RSTATE`, `RFLAGS`, `TSTART`/`TCOUNT`).

#### S8c.5 resource/effect typing rejections — 2026-10-08 (ADR-218)

- Rejection logic lives in `build_rejection_pass` / `_rejection_entry` (its own function). Keep new rejection code there, not in `_node_entry`.
- If the XAX backends decline a helper program (`X86_64_VIEWS-XAX-BACKEND`), check the views backend's arena first: the largest function needs about 5 x blocks x values / 64 words for liveness. The region layout is in `xax_selfhost_views_backend.py`.
- Next (S8c.6): constants and call targets, then call contracts (they need the callee interface lists decoded separately from the comparison).

#### S8c.6 constant and call-target rejections — 2026-10-08 (ADR-219)

- `_entity_steps` covers both entity checks. Next (S8c.7): `GRAPH-CALL-CONTRACT` needs the callee interface lists decoded apart from the comparison (`_call_rule` fuses them); then the facts engine's declines and object verification.

#### S8c.7 call-contract rejections — 2026-10-08 (ADR-220)

- `_call_interface` decodes a fragment callee's interface into the pass's list area (after the records; overflow goes to `PASS_SINK` and defers). `NativeTyping.rejection` reads it back through `r.interface`.
- Next: the facts engine's declines (`xax_selfhost_facts`, `DECLINE_SITES`), which are the memory-fact rejections in `_parse_graph_uncached`; then object verification (`verify_object`).

#### S8c.8 stack-memory rejections — 2026-10-08 (ADR-221)

- Use `_reject(e, condition, M[site], payload..., renderable=...)` only where the engine check is exactly the bootstrap's check in its order; add the renderer in `memory_diagnostic`. `_pointer`, `_consume_effect`, and `_access` take `exact=True` in the handlers already verified (load, store, address offset, stack end).
- Next: heap views and checked accesses (`_heap_view_node`, `_checked`), whose corpus mutations still fall back; then calls, atomics, links; then object verification.

#### S8c.9 checked-access rejections — 2026-10-08 (ADR-226)

- `_access_size` is shared by plain and checked accesses. Next: rebase windows (`_pointer_rebase`), heap-view construction (`_heap_view_node`), returned views (`_return_views`), then calls, atomics, and links; then object verification.

#### S8c.10 rebase-window rejections — 2026-10-08 (ADR-227)

- Next: returned views (`_return_views`, `HEAP-VIEW-RETURN-*`), heap-view construction (`_heap_view_node`), then calls, atomics, links; then object verification. Another session also commits to `main`: fetch before pushing and take the next free ADR number.

#### S8c.11 returned-view rejections — 2026-10-08 (ADR-228)

- The corpus is fully engine-decided; extend it before converting more handlers (heap-view construction, foreign and view calls, atomics, links), each with a constructed case per rule as in `SelfhostTypedAccessTests`.

#### S8c.12 heap-view construction rejections — 2026-10-08 (ADR-229)

- `_heap_program` (tests) builds mmap-then-view programs for constructed cases. Next: foreign calls (`_call_foreign`), view-passing calls (`_view_call`), atomics, links, then object verification.

#### S8c.13 foreign-call memory rejections — 2026-10-08 (ADR-230)

- Next: view-passing direct calls (`_view_call`, `_verify_heap_view_call`), indirect calls, atomics, links; then object verification (`verify_object`). Superseded by S8c.14 below.

#### S8c.14 view-passing call rejections — 2026-10-08 (ADR-232)

- Next: released-view link dependents (`MEMORY-LINK-TARGET-OUTLIVES` at calls), indirect calls, atomics, links; then object verification (`verify_object`). Superseded by S8c.15 below.

#### S8c.15 indirect-call stack-proof rejections — 2026-10-08 (ADR-233)

- Next: released-view link dependents (`MEMORY-LINK-TARGET-OUTLIVES` at calls), atomics, links; then object verification (`verify_object`). Superseded by S8c.16 below.

#### S8c.16 atomic memory rejections — 2026-10-08 (ADR-234)

- Next: released-view link dependents (`MEMORY-LINK-TARGET-OUTLIVES` at calls), links; then object verification (`verify_object`). Superseded by S8c.17 below.

#### S8c.17 link memory rejections — 2026-10-08 (ADR-235)

- Next: the remaining memory declines (record field offsets and strides, byte-addressable values, link dependents of ended storage, foreign writes to link-bearing storage, atomic enums); then object verification (`verify_object`). Superseded by S8c.18 below.

#### S8c.18 address, record, and link-lifetime rejections — 2026-10-08 (ADR-236)

- Next: the remaining declines (atomic enum diagnostics, invalid record fields, ambiguous link dependents); then object verification (`verify_object`). Superseded by S8c.19 below.

#### S8c.19 object rejections: reference lists and call contracts — 2026-10-08 (ADR-237)

- Next: object rejections for functions (`_verify_function`), recursion groups, types, constants, targets, packages, and builds; the remaining memory declines. Superseded by S8c.20 below.

#### S8c.20 function object rejections — 2026-10-08 (ADR-238)

- Next: object rejections for recursion groups, types, constants, targets, packages, and builds; the remaining memory declines. Superseded by S8c.21 below.

#### S8c.21 recursion-group member-list rejections — 2026-10-08 (ADR-239)

- Next: group rejections after member parses (contracts, member calls, SCC, order), types, constants, targets, packages, and builds; the remaining memory declines. Superseded by S8c.22 below.

#### S8c.22 recursion-group member-graph rejections — 2026-10-08 (ADR-240)

- Next: the canonical member order (`GRAPH-RECURSION-ORDER`), types, constants, targets, packages, and builds; the remaining memory declines. Superseded by S8c.23 below.

#### S8c.23 target object rejections — 2026-10-09 (ADR-241)

- Next: target register lists and profile sections, the canonical group order, types, constants, packages, and builds; the remaining memory declines. Superseded by S8c.24 below.

#### S8c.24 constant object rejections — 2026-10-09 (ADR-242)

- Next: malformed constant bodies, types, target register lists and profile sections, the canonical group order, packages, and builds; the remaining memory declines. Superseded by S8c.25 below.

#### S8c.25 scalar type rejections — 2026-10-09 (ADR-243)

- Next: compound types (pointer, effect, resource, opaque, tuple, array, sum), malformed constant bodies, target register lists and profile sections, the canonical group order, packages, and builds; the remaining memory declines. Superseded by S8c.26 below.

#### S8c.26 compound type rejections — 2026-10-09 (ADR-244)

- Next: tuple and sum element checks, pointer element checks, resource transitions, opaque identity types, malformed constant bodies, target register lists and profile sections, the canonical group order, packages, and builds; the remaining memory declines. Superseded by S8c.27 below.

#### S8c.27 tuple and sum item rejections — 2026-10-09 (ADR-245)

- Next: pointer element checks, resource transitions, opaque identity types, malformed constant bodies, target register lists and profile sections, the canonical group order, packages, and builds; the remaining memory declines. Superseded by S8c.28 below.

#### S8c.28 pointer element and opaque identity rejections — 2026-10-09 (ADR-246)

- Next: resource transitions, malformed constant bodies, target register lists and profile sections, the canonical group order, packages, and builds; the remaining memory declines. Superseded by S8c.29 below.

#### S8c.29 malformed constant body rejections — 2026-10-09 (ADR-247)

- Next: resource transitions, target register lists and profile sections, the canonical group order, packages, and builds; the remaining memory declines. Superseded by S8 below.

#### S8 verifier totality — 2026-10-09 (ADR-251)

- Done: every rejection the suite reaches on Linux x86-64 is XAX-decided (trace: 0 bootstrap sites; differential: 4,685 rejections, 0 differences). To re-check after a verifier change, from `compiler`: `S8_TRACE_OUT=/tmp/s8 PYTHONPATH=src:tests:migration:.:.. python -m pytest -s -n 3 -p s8_rejection_trace -p s8_differential tests`, then `python migration/s8_rejection_trace.py /tmp/s8` (expect an empty report) and grep `DIFF ` (expect none).
- New checks go into the XAX program first, as exact `_reject` records in the bootstrap's order; a `_require` only declines (Python then decides). Keep each XAX function inside the views backend's limits (5 MiB of code, the per-function arena): `test_xax_selfhost_x86_64_backend` fails otherwise, and `target.op`'s target parse was split into `_target_contract` for this reason.
- Graph decoder rejections keep their stream prefix in the store verifier's object table (a flag word follows the body bytes); graphs with an invalid use are typed over a trimmed copy. Both paths count a rejection only where the bootstrap would reach it first.
- The two wheel tests fail on this host for an environment reason (Debian setuptools: `AttributeError: install_layout` under `pip wheel --no-build-isolation`), not a code one.
- Next: S9 (canonical store writing in XAX).

#### S8a store-container rejections — 2026-10-07 (ADR-183)

- Add a container rule by adding a `SITES` entry (code, rule, value forms over v0–v3) and a `fail_unless(condition, site, entity, values)` at the bootstrap's point in `build_decoder_program`. Keep the bootstrap's order: trailer and end, then the digest, then the index, then the root.
- `NativeDecoder.decode(data, verify_digest, digest)` runs the two digest passes. `MODE_*`, `NEED_DIGEST`, and the out layout (`INDEX_AT`, `DIAG_AT`) are at the top of the module. The record is in (low, high) 32-bit pairs, read with `xax_selfhost_diagnostics.decode_record`.
- Next (S8b): object envelopes (`decode_object`, reached through `StoreReader.get`; the S3b parse marks bad envelopes unparsed today) and graph bodies (the S3c decoder rejects without a diagnostic). Use the same site-table pattern.

#### S8b.1 object envelopes — 2026-10-07 (ADR-184)

- `NativeDecoder.decode_object(envelope, cid_of)` runs the two object passes on one envelope. `StoreReader._decode_object_native` uses it for natively decoded stores and builds the object from the program's fields.
- Next (S8b.2): graph bodies. The S3c decoder (`xax_selfhost_graph.py`, its own `_GraphDecoder` over a 64-bit stream) rejects without a diagnostic, and `_parse_graph` then re-parses with the bootstrap. Give it the same site table and shared diagnostic block, and keep the bootstrap's order, including the deferred value checks that `_parse_graph` makes while it walks the stream.

#### S8b.2 graph-body rejections — 2026-10-07 (ADR-185)

- Decoder rejection sites share `_SiteDiagnostics` (`xax_selfhost_store.py`). A decoder supplies `SITES`, `ENTITIES`, `block_state`, `diagnostic_block`, `begin_record`/`put`/`finish_reject`, and optionally `d_custom`.
- In the graph decoder (`xax_selfhost_graph.py`), decide a value with `read` before you `emit` it: the stream prefix up to a rejection is walked by `_graph_syntax_from_stream(..., prefix=True)`, which must never see an undecided value.
- Next (S8c): what `_graph_syntax_from_stream` and the verifier still decide in Python: resolution, `_verify_type`, trap payloads, typing and facts declines, and object-level verification declines.


### Step S9

#### S9 canonical store writing — 2026-10-14 (ADR-262)

- Done: the XAX writer decides every store write on Linux x86-64 (`compiler/src/xax_selfhost_writer.py`; tests `tests/test_xax_selfhost_writer.py`). Opt out with `XAX_STORE_PYTHON_WRITER=1`; `_bootstrap_store_contents`/`_bootstrap_emit_store` are the oracle.
- After changing the writer builder or the hash builder, run `write_writer_store()` (and `write_hash_store()` if the hash graph changed); `tests/test_store_regeneration.py` covers both. Keep `hash_function()`'s defaults producing the committed hash graph.
- A writer rejection is a reason code mapped to the bootstrap's `ValueError` text (`REASONS`); add a new writer check to the XAX program first, in the bootstrap's order.
- The batch is a host marshal (fixed 64-bit fields), not a format. S10 should build objects and call the writer from XAX directly, the way the writer calls the hash (view-passing direct call).
- Next: S10 (the driver as a native Linux x86-64 XAX program: platform file I/O, target-package interpretation, verify → lower → assemble → write).

### Step S10

#### S10e semantic verification in the driver — 2026-10-14 (ADR-266)

- Done: `compiler/src/xax_selfhost_semantic.py` (seven marshal functions, workspace layout at the top) is linked into the driver store; tests `tests/test_xax_selfhost_semantic.py` (word equality) and `tests/test_xax_selfhost_driver.py` (semantic rejections).
- Capacities are shared: changing `xax_selfhost_typing.IN_EXTENT/OUT_EXTENT`, the store decoder's `DATA_EXTENT`, or the views stream region regenerates the typing, verifier, decoder, both backend, and driver stores. Keep `IN_WORDS <= (OUT_WORDS - TABLE) // 2` (asserted): otherwise the typing program defers every stream and Python silently decides.
- Debugging a driver decline: give `stop(DECLINED)` a distinct status per call site temporarily (status `2 + 16 * site`) and rebuild the driver in memory; nothing else reports where it declined.
- Next: S11 (process entry in the views profile, the ELF64 container written by the driver, a self-build loop of processes). S11: see above.

#### S10 the compiler driver as XAX — 2026-10-14 (ADR-265)

- Done: `compiler/src/xax_selfhost_driver.py` builds `xax_compiler_driver.xax`; `NativeDriver(image).run(store, target_package, output)` runs it in-process (statuses: 0 image, 1 rejected with a diagnostic record, 2 declined, 3 I/O failure). Tests: `tests/test_xax_selfhost_driver.py`; evidence: `benchmarks/bench_selfhost_driver.py --write`.
- The driver store contains the decoder, graph decoder, hash, and backend stores' objects. Rebuild it (`write_driver_store()`) after any of them changes; `tests/test_store_regeneration.py` fails otherwise.
- Lower the driver with `x86_64_views_syscall_target()` (v2). Helpers keep v1.
- Next: S10e (port `verify_store`'s orchestration: the typing marshal and fact sections, `verifier_input`, and the precedence logic) and S11 (wrap the driver image in an ELF64 executable with an explicit process entry, so no host process remains). S10e: see above.

#### S10a Linux syscalls in the views profile — 2026-10-14 (ADR-264)

- Done: `x86_64-linux-views-v2` (`x86_64_views_syscall_target`) lowers `call.foreign` of `linux-x86_64-syscall-v1` declarations in both views generators (`xax_x86_64_views._syscall`, the XAX backend's `foreign` case and `_syscall` parser); tests in `tests/test_xax_selfhost_syscalls.py`.
- ISA-only views rules go in the ISA class's `EXTRA_RULES`; gate ISA-only front-end work on a class flag (`SYSCALLS`) and keep the gated code from emitting nodes for other ISAs (argument expressions included), or the RISC-V backend store changes.
- After changing the backend builders: `write_backend_store()`, then `benchmarks/bench_selfhost_x86_64.py --write` (native, `XAX_REQUIRE_NATIVE=1`).
- Next: S10b, driver-owned memory (`mmap`/`munmap` heap contracts, `heap.view`, `pointer.cast`) in the views profile; then S10c (the `verify` driver) and S10d (the `lower` driver), per ADR-264.

### Step S11

#### S11 the driver as an ELF64 executable — 2026-10-14 (ADR-267)

- Done: `x86_64_views_exec_target()`, `xax_x86_64_views.views_executable(image)`; the driver store's entry is the process entry, and `NativeDriver(image).run(...)` runs the executable as a subprocess (the exit status is the driver status). Tests: `tests/test_xax_selfhost_process.py`, `tests/test_xax_selfhost_driver.py` (self-build loop).
- Lower the driver with the exec target only: under v1/v2 its startup reads reject. Helpers keep v1.
- Process-only backend work is gated on the ISA class's `PROCESS` (the identity; the front end distinguishes it by length, so keep `IDENTITIES` lengths distinct from it) and reads `G_PROCESS`; the RISC-V store must stay unchanged.
- A function cannot pass memory effects without views to a callee (`MEMORY-CALL-PASS-THROUGH`), so the process entry cannot wrap a separate driver function. The driver function is the entry.
- Next: S12 (the optimizing x86-64 backend's decisions for ordinary programs), then S13 and S14. S12a: see above.

### Step S12

#### S12 complete: S12f.4 — 2026-10-15 (ADR-280)

- Done:
  - `xax_selfhost_general_legacy.py`: `legacy_function`, run by `frame_function` where `_legacy_static` accepts. Its state record lives at `_ra` slot 242, and calls are recorded only in the real run, because `_record_call` and `_relative2` do not check `E_REAL`.
  - `_value_facts` no longer declines wide values or float constants.
  - Exact frame rejections: `value_reject`, `width_reject` (rotation amount in slot 243), and `fixed_reject` for links and rebases.
  - `xax_selfhost_store.DATA_EXTENT` is 32 MiB.
- Order matters for exactness: the bootstrap's `_arithmetic` and `_rotate_right_immediate` fail after the operand loads (a missing slot fails first), while division checks the width first.
- Next: S13. S14's negative equivalence should take up ADR-280's list of declined rules. S13a: see above.

#### S12f.3 atomics and by-reference aggregates — 2026-10-15 (ADR-279)

- Done in `xax_selfhost_general_frame.py`:
  - `atomic_check` (run by `_view` on the lifted graph, before the lowering view), `atomic_reject`, and `fr_atomic`;
  - `_hidden_result`, `_copy_at`, and the `F_RETPTR`, `F_COPIES`, `F_NCOPIES` slots (239..241).
- The front end keeps `G_TPROFILE`/`G_TATOMIC` (globals 61, 62).
- `reject_at` sets the REJECT status itself: `_call` turns NONE into a decline that would otherwise abort before the final status.
- Capacity: the general driver store is 16.19 MB against the store decoder's 16 MiB `DATA_EXTENT`. Enlarge it, and regenerate every store that embeds the decoder, before the general backend grows much more.
- Next: S12f.4:
  - Values wider than 64 bits. The simplifier must fold them exactly; the bootstrap uses Python integers.
  - The legacy register path.
  - Links and rebases on the frame path.
- S12f.4: see above.

#### S12f.2 code generation rejections — 2026-10-15 (ADR-278)

- Done: `xax_selfhost_general_emit.reject_at(e, write)`, which writes the diagnostic only while `I_OK` holds and sets `E_FAIL`. `E_F` names the function being lowered, and `graph_cid_words` names its graph, which is the bootstrap's `graph_object`.
- After a rejection, `_view` skips every later function and the front end's status is REJECT. `xax_linux` (differential) compares a code-generation rejection with the bootstrap's whole compile.
- Findings for S12f.3:
  - Atomics compile on Linux in the bootstrap (frame path). XAX declines them in `frame_layout`.
  - `_value_facts` declines any value wider than 64 bits, even dead ones the simplifier removes.
  - The legacy register path accepts only add/sub/mul/constant/direct-call integer graphs (Linux, not hosted); it was never taken in 400 random programs.

#### S12e.3 the general driver rebuilds itself — 2026-10-15 (ADR-277)

- Done: `xax_selfhost_typing.IN_EXTENT, OUT_EXTENT = 256 MiB, 1 GiB` (keep `IN_WORDS <= OUT_WORDS / 4`), and every dependent store regenerated. The RISC-V harness `_STACK_TOP = 0x10000000`, so the emulator maps the 1 GiB output view.
- The general driver self-build: `tests/test_xax_selfhost_general_driver.py::test_the_general_driver_rebuilds_itself_as_processes`, about 42 s per generation.
- Evidence after a view change: `bench_selfhost_closure.py --write`, `bench_selfhost_x86_64.py --write`, and `bench_selfhost_driver.py --write`, each natively.
- Next: S12f.2. S12f.2: see above.

#### S12e.2 the general driver — 2026-10-14 (ADR-276)

- Done:
  - `build_driver_program(general=True)` / `write_general_driver_store` (`xax_compiler_driver_general.xax`); with `general=False` the views driver is byte-identical, so keep every general-only `w.let` under `if general:` (the structured builder threads every live name).
  - During S10e graph verification, `collect` copies each graph's pointer extents (facts output `H_EXTENTS`, value ids in block parameter, then node result order) and trap heads (stream `[4, size, offset]`, body bytes) into side buffers.
  - `group_members` derives the missing `group_member_function` CIDs with the hash before the target store overwrites `data`.
  - `lower` calls the general program for the Linux identities, and the output is the ELF from the image record.
- The S10e marshal (`_callee_aux`) now resolves group member callees through the group's references (`c_holder`).
- Views backend layout (ADR-276): ranges 4M words, stream 12M..28M, arena from 28M; `GLOBALS` moved with the arena.
- Evidence: the regenerated backends need `bench_selfhost_x86_64.py --write` and `refresh_selfhost_store.py xax_selfhost_riscv64_backend --write` (the refresh script does not know the x86-64 backend).
- Next: S12e.3. Grow the typing/verifier input views (the general driver's verifier table is 28.3M words against 16.8M), so the general driver verifies and rebuilds itself and can replace the views driver. Then S12f.2. S12e.3: see above.

#### S12f.1 the frame lowering — 2026-10-14 (ADR-275)

- Done: `compiler/src/xax_selfhost_general_frame.py`:
  - `frame_layout`;
  - the node groups `fr_int`, `fr_float`, `fr_ftrunc`, `fr_data`, `fr_foreign`, `fr_memory`, `fr_call`, and `fr_tail`;
  - `fr_node`, `fr_term`, `frame_function`, `eligible_only`, and `frame_fallback`.
- The view calls `frame_fallback` before `write_emission`. The frame tables are `T_FSLOT`..`T_FESC` (48..54, `VALUE_TABLES` = 55).
- `_FN` names are global. The view's block `layout` shadows the front end's ABI `layout`, so the frame code registers it as `abi_layout`. Keep the `em_`/`fr_` prefixes.
- Keep each graph small. A ~300 KB graph (the whole float group) did not converge in the facts engine, so the S10 driver declined the store. Split such functions.
- Next: S12e.2 (the S11 driver runs the general backend) and S12f.2 (atomics, by-reference aggregate arguments and results, and the legacy register path). S12e.2: see above.

#### S12e.1 image assembly and the ELF container — 2026-10-14 (ADR-273)

- Done: `compiler/src/xax_selfhost_general_image.py` (`image_add` per emitted function, `image_adapter`, `image_finish`, `elf_static`, `elf_dynamic`, `image_record` at `IMAGE_AT`), run after the views; `general_with_xax(...).image` (`GeneralResult`), `xax_linux._executable_from_image`, `ASSEMBLY_COUNTS`.
- Prologue order matters: anything stored in the `_ra` table (`set_trap_section`) must follow `regalloc_prologue`, which allocates it.
- Call records are `(position, object, SysV entry label flag)` everywhere (emission, image, and the host's reader).
- Next: S12f, so every function is on an XAX path (the legacy register path `_compile_register_resident_function` and the frame lowering; the 14 host-assembled Linux test compiles name the functions), and S12e.2: link the general backend into the S11 driver so the driver lowers `x86_64-linux-elf-exec-v1` programs. S12f.1: see above.

#### S12d register-resident emission — 2026-10-14 (ADR-272)

- Done: `compiler/src/xax_selfhost_general_emit.py` (encoders, allocation state, `em_node`, `em_memory`, `direct_call`, `foreign_call`, `em_begin`, `em_block`/`em_block_copy`, `em_term`/`em_term_copy`, `emit_function`, `write_emission`), run by the view after the analyses. `general_with_xax` now returns `(closure, views, prefetches, code[, bounds, analyses])`; `compile_native(code=)` uses it; `xax_linux.check_emission`/`reference_emission` are the references.
- The builder's `NONE` is 2^32-1, not -1: encode the bootstrap's -1 explicitly (a biased comparison, or 2^64-1 from a subtraction).
- Graph objects reach the program as decoded streams: data that only the body holds (trap payloads) needs its own object-table section.
- Function names are global in `_FN`: the emission functions use `em_` where the front end already has the name (`node`, `layout`).
- Keep every function graph small enough for the XAX facts engine (the S10 driver verifies every committed store with it; `test_xax_selfhost_driver.py::test_every_committed_store` declines otherwise). A 422 KB graph did not converge; split large functions (as `em_node`/`em_node_a`/`em_node_b`).
- Debugging: `emdiff`-style per-range comparison (first range whose position or length differs) plus the `_ok` site recorder found every defect; disassemble with capstone for terminator differences.
- Next: S12e. Port `compile_native`'s image assembly (function placement, call and address fixups, the SysV entry adapters, the import table) and `emit_linux_elf_executable`, then let the S11 driver call the general backend. S12e.1: see above.

#### S12c.2 register-resident analyses — 2026-10-14 (ADR-271)

- Done: `compiler/src/xax_selfhost_general_regalloc.py` (`_analyse` and its 18 helpers, the `G_RA` table of per-value tables `T_*` and globals `R_*`), run by the view after `lower` where the values are bounded. `general_with_xax(..., audit=True)` returns `(closure, views, prefetches, bounds, analyses)`; `xax_x86_64_regalloc.ANALYSIS_AUDIT` (test-only) and `xax_linux.check_analyses`/`reference_analyses` are the references; `xax_selfhost_x86_64_general.analysis_form` normalizes the bootstrap's dict.
- The arena is only reset per view. A helper called per value or per block must release its scratch (`_release(e, mark, result)`) when its result does not escape, or a large function exhausts the arena and the whole program declines.
- Debugging a decline: the `_ok` recorder must also replace `_ok` in `xax_selfhost_general_ranges` and `xax_selfhost_general_regalloc` (they import it by name).
- Next: S12d. Port `compile_register_resident`'s emission (block lowering, the dry run, the assembler, stubs, traps, and tables) to read the program's analyses, and compare each function's bytes with the bootstrap's. S12d: see above.

#### S12c.1 value ranges and prefetch selection — 2026-10-14 (ADR-270)

- Done: `compiler/src/xax_selfhost_general_ranges.py` (value facts, `maximum0`-`maximum9`, `edge_bound`, `bounds`, `extent`, `cycle`, `prefetch_load`, `prefetch`; second globals table `G_MORE`/`_g2`), the view now runs `positions`, `value_facts`, and `prefetch` before `lower`, and writes marks (and, with the input's audit flag, every value's bound). `general_with_xax(..., audit=True)` returns `(closure, views, prefetches, bounds)`; `xax_linux.check_bounds` and `reference_view` are the references.
- Ranges take a width table (`G2_WIDTHS`): S12c.2 must point it at the register lowering's machine widths (`_eligible`), which include pointers, unlike the prefetch's bits widths.
- Stamps: every stamp word must be cleared when its value or block is created (`_clear_stamps`, `B_SCRATCH`), because rounds restart per run and the native runner reuses its output view.
- Next: S12c.2. Instrument `compile_register_resident` to export its analyses (a test-only hook), port them in the same order, and audit them value by value like the ranges. S12c.2: see above.

#### S12b the general backend's lowering view — 2026-10-14 (ADR-269)

- Done: `compiler/src/xax_selfhost_general_view.py` (17 functions, linked into `xax_x86_64_general.xax` by `add_view_functions`; `views_prologue` runs after the closure), `general_with_xax` → `(closure, views)`, `rebuild_views`, `_compile_function(view=)`. Tests: `tests/test_xax_selfhost_general_view.py`.
- Debugging a decline: build the program in memory with `_ok` replaced by a recorder of `inspect` sites that stores the first failing site in an output word, then lower it with `host_image(reader, function, None)` and run it with `_NativeRunner`. The two bugs found this way were helpers that returned NONE for "no" (use `NOT_CALL`, since `_call` treats NONE as a decline).
- Arena records: values are indices into `G_V*` tables (capacity `VCAP`); nodes and blocks are arena records (`N_*`, `B_*`). The arena is reset after each view (`views_prologue`), so everything a view needs from caches (interfaces, erased flags) must be filled during the closure.
- Next: S12c. Port `xax_ranges.upper_bounds` and the predicate tables, then `prefetch_next_iteration` (it rewrites the view, so add it after `_layout`/`_lower` or rebuild positions), then `compile_register_resident`'s analyses. S12c.1: see above.

#### S12a the general backend's front end — 2026-10-14 (ADR-268)

- Done: `compiler/src/xax_selfhost_x86_64_general.py` (store `xax_x86_64_general.xax`, `write_general_store`), `xax_linux.linux_closure` (the reference), `compile_linux_executable(frontend="auto"|"xax"|"python")`, `compile_native(closure=, verified=)`, `xax_riscv64.object_table_words`. Tests: `tests/test_xax_selfhost_general.py`; differential: run the Linux suites with `XAX_GENERAL_FRONTEND_DIFF=1`.
- The program grows into the whole general backend: add S12b-S12e as further functions of this store, as the views backend grew. Its globals extend the views front end's (`G_*` from slot 21) and reuse its readers (`_find`, `_node_info`, `_term_end`, `_erased`, `_borrowed`); `interface` is the group-aware `_group_interface`.
- Builder pitfalls hit here: never name a variable `ip`/`iv`/`im`/`op`/`ov`/`om` (the view triples), and read a ULEB before using the cursor it advances (`e.add(p["ta"], _payload_uleb(e, "ta"))` reads the old cursor).
- Next: S12b. Port `xax_inline.inline_leaf_calls` and `xax_prefetch.prefetch_next_iteration` as a rewrite of the graph stream. Check it word for word against a marshal of the Python view, then S12c/S12d (`xax_x86_64_regalloc`). S12b: see above (prefetch moved to S12c).

### Step S13

#### S13 complete: S13c package resolution — 2026-10-15 (ADR-283)

- Done: `xax_selfhost_resolve.py` (`select`, `snapshot`; control words `R_*` 48..58; workspace regions `SELECTED_AT`, `STACK_AT`, `SNAPSHOT_AT` at 40M..43M words). The driver's `resolve` command, a `batch` buffer (16 MiB, the S9 writer's batch; `object` is the writer's buffer), and the writer in the general driver store. `NativeGeneralDriver.resolve`.
- The input is a request store (root = the request). Oracle: `snapshot_store(resolve_packages(request, store objects + POLICY, POLICY, RESOLVER_IDENTITY), ...)`.
- Next: S14. S14a: see above. First, grow `xax_selfhost_writer`'s views (`IN_EXTENT`, `OUT_LIMIT`) beyond the general driver's own store (17.6 MB), regenerate the writer, the general driver, and their evidence. Then resolve and build the compiler's own package as C1 → C2 → C3, with identity records and ADR-280's declined rules in the negative equivalence.

#### S13b verify and inspect — 2026-10-15 (ADR-282)

- Done: `xax_selfhost_graph.BODY_EXTENT` is 2 MiB and `OUT_EXTENT` 32 MiB (decoder and both drivers regenerated). The general driver's commands are `COMMANDS` (name to file-argument count); `verify` and `inspect` stop after verification with the internal status `DONE`, which `done_out` turns into the output and exit status 0. `decode_inspection` renders `inspect`'s record; `NativeGeneralDriver.verify` and `.inspect`.
- The driver's function body is 1,100,353 bytes of 2 MiB.
- Next: S13c. Port `resolve_packages` (candidate selection by exact root and logical identity, the dependency closure, signatures) and `snapshot_store` (the reachable closure) as helper functions, and write the snapshot store with the S9 writer; a `resolve` command. Then S14. S13c: see above.

#### S13a build requests and provenance — 2026-10-15 (ADR-281)

- Done:
  - `xax_selfhost_request.py`: `build_request` and `provenance`, in the S10e helper convention (input: the verifier's object table, `OBJAT` from `index_objects`; output: the workspace). Arguments and results are in control words `B_*` (32..43); the provenance envelope is at `ENVELOPE_AT` (`_END`), one byte per word; rejection records are at the workspace's `DIAG_AT`, which `from_work` copies to the driver's record.
  - The general driver: argv[1] is `lower` or `build` (`NativeGeneralDriver.run` and `.build`). The views driver is untouched (keep every new `w.let` under `if general:`).
  - `XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1` in `xax_artifact`.
- Capacity: the driver function's graph body is 1,012,484 bytes; the graph decoder takes 1 MiB less 32. Logic added inline to the driver costs about 5 KB per `if`/`while`, because every construct carries all ~130 live values. Put new logic in helper functions; grow `xax_selfhost_graph.BODY_EXTENT` (and regenerate the decoder, both drivers, and their evidence) before S13b.
- Pitfall: Python evaluates `e.add(p["cur"], r.uleb())` left to right, so the cursor is read before the ULEB moves it. Bind the ULEB first.
- Next: S13b (`verify`, `inspect`), then S13c (resolution and snapshot formation with the S9 writer), then S14. S13b: see above.

### Step S14

#### S14 complete: S14b the production compiler's generations — 2026-10-15 (ADR-285)

- Done:
  - `xax_selfhost_compiler.compiler_request` (the compiler's request store).
  - `benchmarks/bench_full_selfhost.py` → `benchmarks/full_selfhost_evidence.json` (about 50 minutes; the bootstrap compile is 10 of them).
  - `xax_selfhost.linux_x86_64_status`, reported by `bootstrap_status` and the status blocks.
  - Writer views 32/64 MiB; the general driver's `written` buffer; the general program's views region 32M–56M words, arena from 56M.
- After a change to the general driver, the general program, or the writer: re-run `bench_full_selfhost.py --write`. `tests/test_full_selfhost_status.py` fails while the record describes another compiler store. Then `python bootstrap/generate_m14.py` and `python -m xax_status_docs --write`.
- Pitfall: changing `xax_selfhost_writer`'s constants breaks `write_store` (the native writer) until its store is regenerated; regenerate it with `XAX_STORE_PYTHON_WRITER=1`. Never run evidence against an uncommitted constant change: an earlier S14a evidence run did, and was discarded and re-run from a clean worktree.
- Next: S15. The remaining blockers are recorded in `full_selfhost_evidence.json`:
  - B1: exact verification rejections in the driver, and ADR-280's declined rules decided;
  - B5: signature verification, external inputs and effects, grants, and capacities;
  - B6: compiler evolution by semantic transactions instead of Python builders;
  - SH8: a seed that needs no Python (C1 itself can be the next seed);
  - the other targets.
- S15a: see above.

#### S14a the compiler compiles itself with its optimizing backend — 2026-10-15 (ADR-284)

- Done: the fixed point C0 → C1 → C2 → C3 through `lower` (`tests/test_xax_selfhost_compiler_fixed_point.py`); fixes in `xax_x86_64_regalloc` (value tables skip the fused branch compare) and the XAX general program (`uses`/`loop_slots` exact-size arrays, bounded `copy_edge`/`_machine_operands` writes, `MOVE_CAP` 4096, views region 32M–48M words, `GENERAL_ARENA_AT` 48M, `CODE_CAP`/`IMAGE_CAP` 8 MiB).
- Diagnosing a decline of the general program on a large input: `_ok` records nothing. Build an uncommitted variant whose `_ok` (swap `xax_selfhost_views_backend._ok.__code__`, so every module's binding changes) writes a ring of (site, `H_ARENA`) records near the end of the output view, lower it with `compile_x86_64_views(..., backend="xax")`, and run it on `general_object_table`'s words with `_NativeRunner`.
- Next: S14b (see above). First grow `xax_selfhost_writer`'s views beyond the compiler's own snapshot store (17.7 MB) so `resolve` can write it, then generations through `resolve` → `build` with provenance identity records, the positive/negative corpus run by C1, C2, and C3 (ADR-280's declined rules included), `benchmarks/full_selfhost_evidence.json`, and the B levels derived from it by `xax_selfhost.bootstrap_status`.

### Step S15

#### S15b.3d objects inside a graph's parse — 2026-10-15 (ADR-297)

- Done:
  - In `xax_selfhost_render`: `_prefix` (the stream's type references), the plan's `undecided` graph and `undecided_group`, and `group_types`.
  - In `xax_selfhost_verify`: `G_GROUP_REACHED`.
  - In `xax_selfhost_typing`: `SITE_CROSS_SUM`, and the list items' ULEB fault (`C4` holds its offset).
  - In the outcome: `G_OBJECT` for a constant node's unproven constant.
  - In the driver: `objected`, and `I_NODE` for a tie at the first invalid use's node.
- Diagnosing a decline: a copy of the driver with a unique exit code per `stop(DECLINED)`, and a copy of `render.py` whose `finish(P_DECLINE)` records its line; the plan's words are at `PLAN_AT`.
- Next: the pointer-decoder and declaration-decoding memory sites, stack-owner entries, the group-call-context function, nested build decoders.

#### S15b.3d nested decoders — 2026-10-15 (ADR-296)

- Done:
  - In `xax_selfhost_render._plan`: `member_types` and `snapshot`.
  - In `xax_selfhost_semantic`: `object_marshal`, with `C_OVERRIDE`/`C_OLEN` and the `OVERRIDE` region.
  - In the driver: `as_type`.
  - In `xax_selfhost_render_types`: `TYPE_SITE_NUMBER` and `BODY_QUOTING`.
- Reproducing a corpus row: generate it as `bench_full_selfhost` does, with `PYTHONHASHSEED=0`, then compare `NativeGeneralDriver.verify` with `verify_store`.
- Next: the declaration-decoding memory sites, stack-owner entries, and constants reached inside a graph's parse. The latter: see above.

#### S15b.3c exact invalid-use rejections — 2026-10-15 (ADR-295)

- Done:
  - In `xax_selfhost_semantic`: `trim`, with the `B_TRAP` and `CUT` regions; `C_USES`.
  - In the driver: `invalid_uses`; the trimmed verdict and `render_use`.
  - In the outcome: `O_POS` and `O_MODE`.
  - `tests/test_xax_selfhost_verify_exact.py::test_uses`.
- Workspace: `INV_AT` (36M words) holds the first use, the use block's dominators (at most 1024 words), the native order, and the positions.
- Next: S15b.3d.
  - The memory sites that quote decoded declarations (FOREIGN_*, LEND, TARGET_DEFINED/SCOPE_SUPPORTED/SPACES, INDIRECT_BOUNDED_CONTRACT).
  - Stack-owner entries.
  - Constants and types reached inside a graph's parse.

#### S15b.4 exact code generation rejections — 2026-10-15 (ADR-294)

- Done:
  - `xax_selfhost_general_rejects`: the reject functions, which are registered before the emission functions that call them.
  - The frame path's, register path's, legacy path's and image's `_ok` guards at the bootstrap's failures now reject.
  - The frame size limits are now 2^32.
  - `tests/test_xax_selfhost_general_rejects.py`.
- Finding reachable rules: build a verified program, then compare `compile_linux_executable(frontend="python")` with `general_with_xax`. Its `image` is None when a function's code was declined.
- Memory: a 2 GiB-frame program runs fine alone, but run probes under `ulimit -v` (an unbounded run once took the container down).
- Next: S15b.3c (invalid uses, declaration-decoding memory sites, constants inside a graph's parse). Then the evidence re-run. S15b.3c: see above.

#### S15b.3a-S15b.3b exact graph rejections — 2026-10-15 (ADR-292, ADR-293)

- Done:
  - `xax_selfhost_render_graph`: the typing program's final function. It computes `_parse_graph`'s outcome and writes the deciding record: typing sites, terminators, memory sites, linear codes, the unknown operation.
  - The driver reads the outcome (`OUTCOME_AT`) instead of verdicts and renders the CFG branch target.
  - Record tags `DICT`/`SINT`; enumerations `AtomicRmwKind` and `CompareExchangeStrength`.
  - Tests: `tests/test_xax_selfhost_verify_exact.py::test_graphs` and `::test_memory`, plus the differential plugin `migration/s15_graph.py`.
- Layout: the outcome sits in the typing output at `DIAGNOSTICS - 8M` words: status, cursor, entity mode, bad flag. Record words follow at +8 to +2M; the arrays the outcome reads from the facts section sit at +2M to +6M.
- Order the outcome follows:
  - With no facts, or with the engine accepted and every terminator proven, it goes straight to the linear stage.
  - Otherwise pass 1 runs over the CFG order:
    - the engine's operation-code rejection, then an unknown operation;
    - a memory rejection at the node;
    - typing proven/rejected/unproven;
    - the terminator (memory, then typing).
  - A later pass's memory rejection comes after pass 1, and linear flow comes last.
- Memory rendering:
  - `storage`, `ref` and `intervals` are helper functions; `storages` follows `facts_storages`' order.
  - Byte-view widening quotes the graph's own `bits<8*size>` entry.
  - Where the host's `memory_diagnostic` would raise (an index out of range, an invalid enumeration value, a carry), the outcome sets the bad flag and declines.
- Capacity:
  - The facts engine declines a function with tens of thousands of edge arguments (its arena, `each_exit`).
  - So the renderers are split: `NODE_PARTS` and `MEMORY_PARTS`.
  - The driver verifies its own store only when the engine accepts every graph in it. Check new builder functions with the uncached-parse loop: every graph's outcome must be `G_ACCEPT`.
- Next: S15b.3c.
  - Invalid uses: the trimmed re-typing.
  - The declaration-decoding memory sites.
  - Constants and types reached inside a graph's parse.

#### S15b room for the compiler's image — 2026-10-15 (ADR-291)

- Done:
  - `IMAGE_CAP` in `xax_selfhost_general_image.py` is now 12 MiB. At 16 MiB the arena left too little room, and the compiler could not rebuild itself.
  - The general program store, both drivers, and the request store are regenerated.
  - The seed is rotated; `SEED_SHA256` and `SEED_SIZE` are updated.
- Diagnosis, for the next capacity step:
  - The seed's `build` exit 2 came from the general program declining to assemble.
  - To find which check declines, use a debug copy of `xax_selfhost_views_backend._ok` that records its call site in output word 3.
  - Order matters: change the capacity alone, regenerate, check that the old seed still builds the request, then `rotate-seed`. Only after that land the work that grows the compiler.
- Next: S15b.3. S15b.3a-S15b.3b: see above.

#### S15b.1-S15b.2 exact object, type, and constant rejections — 2026-10-15 (ADR-288, ADR-289)

- Done:
  - `xax_selfhost_render` (the verifier's rendering phase: bank, `_plan`, `Writer`);
  - `xax_selfhost_render_types` (type/constant records, S10e helper);
  - the driver's `plan`/`verify_outcome`;
  - record tags `BYTES`/`ENUM`/`NAME`/`OBJECT`/`BOOL` and optional dependencies/repair;
  - `tests/test_xax_selfhost_render.py`, `tests/test_xax_selfhost_verify_exact.py`, `migration/s15_render.py`;
  - `bench_full_selfhost` records verification rejections with the bootstrap's diagnostic (`bootstrap_diagnostic`), and the B1/B3 derivation uses them.
- Layout: the bank is at verifier output words 7M–11M. The plan is at 11M. The driver keeps typing records, the plan, and the outcome's record at workspace words 32M–35M; type scratch is at 35M.
- Writing records in XAX: write through the `put`/`cid` functions (`R.Writer`), not inline stores. Inline writes made the verifier 4.7 MB and pushed the driver past its own verification capacity.
- Next: S15b.3 (image capacity: see above).
  - The typing program holds every graph decision and the type CIDs (the facts section). Give it a final function that computes `_parse_graph`'s outcome in its order and renders the deciding record, as the verifier's plan does for objects. That order is: pass 1 over `order` (memory reject at the node, typing proven/rejected/unproven), the terminator (memory reject at the terminator, typing terminator records), later passes, then linear flow.
  - In the driver: the CFG branch target needs only rendering (`GRAPH-BRANCH-TARGET`, `< blocks`, the target). Invalid uses must decline: Python re-types the graph trimmed at each invalid use.
  - Constants and types reached inside a graph's parse (a constant node naming a malformed constant) currently decline.
- S15b.3a-S15b.3b: see above.

#### S15b.0 room for the driver's own verification — 2026-10-15 (ADR-287)

- Done: `xax_selfhost_typing.IN_EXTENT` 512 MiB (the typing program's own input bounded by `TYPING_WORDS`, 32M words); every component on that view regenerated; the request store rewritten; the seed rotated and its pins updated.
- Why first: the pinned seed verifies only what fits its own views. A change that grows the driver store past them must follow a rotation to a seed that has room; the old seed cannot build it.
- Next: S15b.1 (the store verifier renders its own rejections; the driver follows `verify_store`'s order).
- S15b.1-S15b.2: see above.

#### S15a a Python-free seed — 2026-10-15 (ADR-286)

- Done: `compiler/bootstrap/seed/` (`xaxc-linux-x86_64`, `xax_compiler_request.xax`, `selfbuild.sh`), `xax_selfhost_seed` (pins, `write-request`, `rotate-seed`), `benchmarks/bench_python_free_seed.py` → `python_free_seed_evidence.json`, and `xax_selfhost.seed_requires_python`.
- After a driver-store change: `python -m xax_selfhost_seed write-request`, then `bench_full_selfhost.py --write`, then `bench_python_free_seed.py --write`. The seed itself need not change; rotate it only deliberately, with `rotate-seed` and a reviewed pin update.
- Next: S15b (B1), decomposed in the roadmap (S15b.1-S15b.4). The S8 components decide each rejection as a site code and raw values; Python renders the diagnostic (`xax_selfhost_verify.object_diagnostic`/`object_entity` and their `_build_rule_`, `_uleb_`, and `_target_*_diagnostic` helpers; `xax_selfhost_typing.object_rejections`; `xax_selfhost_facts.memory_diagnostic`; the linear and CFG renderers) and applies `verify_store`'s precedence (objects in store order through `verify_object`, early `OBJECT_MISSING`, `OTHER_OBJECT`, `AFTER_PARSE` sites, the store's rootedness last). The driver has neither: it checks types, then objects, then the store, then graphs, and writes `XAX.DRIVER.VERIFY`. Start with S15b.1: precedence plus the object sites, rendered with the `xax_selfhost_diagnostics` writers in a helper function (S10e convention) and checked against `verify_store` on the S8 mutation corpora (`migration/s8_differential.py`). S15c to S15e follow.
- S15b.0: see above.

#### S15c grants, inputs, signatures, capacities — 2026-10-16 (ADR-298 to ADR-302)

- `resolve <request> <snapshot> [input ...]` and `build <snapshot> <artifact> <provenance> [input ...]`: up to 64 input files, hashed by the driver. The bootstrap reference for `build` is now `build(..., signature_verifier=xax_ed25519.signature_verifier)`; tests and `bench_full_selfhost` use it.
- Ed25519 lives in `xax_selfhost_ed25519` (workspace words from `ED_AT`, 48 Mi words). `tests/test_xax_selfhost_ed25519.py` runs the helpers alone; `tests/test_xax_selfhost_s15c.py` runs the driver.
- The compiler image grew to 10.4 MB of the 12 MiB the general program can assemble (ADR-291). The general backend inlines the field multiplication at each call site; if a later change approaches the cap, rotate the seed with a larger `IMAGE_CAP` first (ADR-291's procedure).
- Run the heavy driver tests with at most two workers here: four parallel drivers exceed this container's memory.
- Next: S15d.1 (the `edit` command), then S15d.2-S15d.3; S15c.5 and the S15b.3d remainder after that (ADR-298).

#### S15d.0-S15d.1 views room, seed rotation, `edit` — 2026-10-16 (ADR-303, ADR-304)

- The seed was rotated (ADR-303): SHA-256 `7eb76449…`, 10,403,192 bytes. The general program's views region is 36M words; the compiler's own closure uses about 25.9M.
- `edit <store> <record> <output>`; records are made with `xax_selfhost_edit.edit_record`, `apply_reference` is the Python reference. Node positions are (block, node) within the function's graph.
- General-backend hazard (found here): do not use a `bits<1>` comparison value in a block other than the one that computed it; keep it as a 64-bit flag (`e.flag`) and compare again. The views backend hides this; only the self-built compiler shows it, so run new driver code through `selfbuild.sh` and test with the resulting compiler.
- Measuring the general program's memory: `GLOBALS + G_VIEW_OUT` is the views cursor after a run; a host harness can build a variant program in memory (`build_general_program` with changed module constants, then `host_image`).

#### S15d.2-S15d.3 ledger and the first compiler transaction — 2026-10-16 (ADR-305, ADR-306)

- The general driver's committed store = builder baseline + `compiler/bootstrap/evolution/LEDGER`. `write_general_driver_store` applies the ledger; `test_store_regeneration` checks it; `tests/test_xax_selfhost_evolution.py` checks the native `edit` makes the committed stores.
- To change the compiler: write a query in `xax_selfhost_evolution.QUERIES`, make the record (`edit_record`), apply it with the compiler (`xaxc edit` on the driver store and the request store, then `xaxc verify`), add the ledger line, run `selfbuild.sh`. If you change a builder, run `python -m xax_selfhost_evolution rebase` afterwards and review the records.
- The committed compiler's external-input bound is 100 (`xax_selfhost_evolution.INPUTS_LIMIT`); `xax_selfhost_request.INPUTS_LIMIT` (64) is the baseline's.
- Next: S15d.4 (InsertPureNode, DeleteNode, ReplaceUse, edge arguments, signatures in the XAX engine, then new functions) is what B6 needs; S15c.5 (signed resolution) is what B5 needs; the S15b.3d declines are what B1 needs.

#### S15e.0 code buffer and seed rotation — 2026-10-16 (ADR-307)

- `xax_selfhost_general_emit.CODE_CAP` is 2M words (largest compiler function: 466,416 bytes). The seed was rotated; the ledger record was rebased.
- Next: S15e.1, `build` for further targets by XAX backends in the driver.

#### S15e.1 RISC-V `build` — 2026-10-16 (ADR-308)

- `build` on a RISC-V raw target (architecture 6, format 1) calls `xax_riscv64_backend.xax` from the driver; `B_RISCV` is control word 45. Artifact = code words as 4-byte LE; lowering identity `RISCV64_LOWERING_IDENTITY_V1`.
- S15e.2-S15e.7 (other targets) are rows in the roadmap; each needs an XAX backend/container first.

#### S15c.5a ELF buffer after the views — 2026-10-16 (ADR-310)

- `xax_selfhost_general_image`: `I_ELF` is allocated in `image_after_views`. Seed rotated (11,191,528 bytes).

#### S15c.5 `resolve-trusted` — 2026-10-16 (ADR-309)

- `xaxc resolve-trusted <request> <snapshot> <trust file> [inputs]`; trust file = `xax_selfhost_resolve.trust_file(policy, signatures)`. `resolve` uses the same path with the driver's policy.
- Workspace: `TRUST_IN` (43M words), `TRUST_TABLE`/`EXTRA_AT` (44M); control words `R_TRUST` 20, `R_USED` 21.

#### S15b.3d remainder and S15d.4a — 2026-10-16 (ADR-311 to ADR-313)

- `verify` declines that remain: two different resource callees before a graph's decision (`rejection_exactness_gaps`). Fixtures: `compiler/tests/fixtures/declared_rejections` (36 stores, named by rule; `test_declared_rejections`).
- Header words of the typing output: 51/52 `H_TSTOP`, 53 `H_TCONTRACTS`, 54-56 the declared renderers' cursor (`render_graph.D_*`), 57-62 the first resource call (`H_RCALL_*`). `O_DEFER` (outcome word 6) names a resource callee whose graph the driver checks first (`xax_selfhost_semantic.rc_decide`, state at `SM.RC_AT` in the workspace).
- The driver's main function is at what the seed's facts engine decides (about 239k values): new driver logic goes in workspace helpers and workspace words, not `w.let` variables or new branches in the main function.
- The general x86-64 backend miscompiles a copy that stays live while its source advances (see the suggested task); `xax_selfhost_render._target_words` works around it.
- `edit` records: `REPLACE_REFERENCE` (kind 3) with supplied objects (`edit_record(mutations, root, objects)`); an empty supplied section is EDIT-RECORD-END. Next: S15d.4b (the workspace's fine-grained graph mutations in the engine) for B6.

#### S15d.4b structural `edit` and ledger entry 0002 — 2026-10-16 (ADR-314)

- `edit` record kinds 4-9 (`xax_selfhost_edit`: `REPLACE_USE`, `DELETE_NODE`, `INSERT_NODE`, `SET_RESULT_TYPE`, `DISCONNECT_EDGE`, `CONNECT_EDGE`); values are `ValueRef`s or `TransactionValueRef`s. Row fields 5 (payload record word), 6 (operand/result/argument/local id), 8 `M_EXTRA` (an edge's index, or a new constant), 9-11 what LOCATE found. `workspace_mutations` turns a record into the workspace transaction (the Python reference for structural records is `Workspace.commit`).
- Helper names must not shadow the facts engine's view variables (`ip`, `iv`, `im`, `op`, `ov`, `om`): a variable named `im` broke a call contract.
- The x86-64 views backend has its own region layout (`X86_*` in `xax_selfhost_x86_64_backend`): 44 MiB code, two-word jumps and ranges. The views-built seed driver is 42.2 MB.
- Ledger: `0002-dead-constants.edit` (`query_dead_constants`). `bench_full_selfhost` has C1 replay the ledger (`evolution`); `linux_x86_64_status` derives B6 from it.
- Next: S15e.2 (Linux AArch64 ELF in XAX: a port of `xax_aarch64`'s general lowering and register allocator, byte-equal to `build`), then S15e.3-S15e.7; B1's two-callee gap.

#### S15e.2 Linux AArch64 `build` — 2026-10-17 (ADR-315, ADR-316)

- Control word 45 is now `B_PATH` (`xax_selfhost_request.PATH_*`: 0 Linux x86-64, 1 RISC-V raw, 2 Linux AArch64); `HOSTED_PROFILES` lists the ELF profiles by identity. The driver's main function is at the seed's capacity: read `B_PATH` only where a program is called, put new logic in helpers.
- `xax_aarch64_general.xax` (`xax_selfhost_aarch64_general` and `_lower`, `_emit`, `_image`, `_frame`). The frame path's state is `_ra` slots from `FRAME_BASE` (100); `group_member_tables` is shared with the x86-64 front end.
- `IMAGE_CAP` is 16 MiB (S15e.2a); the seed was rotated (11,942,047 bytes). The x86-64 views backend keeps jumps/ranges below the header (`X86_ARENA_END`).
- Next: S15e.3 (Windows PE32+ in the general x86-64 program), then S15e.4-S15e.7; B1's two-callee gap.

#### S15e.3 Windows PE32+ `build` — 2026-10-17 (ADR-317)

- `G_WINDOWS` (general front-end word 63) selects the PE profile; `PATH_WINDOWS_PE` = 3 in `B_PATH` (any image format but 5/6). `xax_pe.compile_pe_executable` is `_hosted_container`'s PE path.
- Frame path on Windows: `E_FWD_*` emission words implement `_Assembler.forward_stores` in `frame_access` (cleared by `_label`); the hosted legacy register path declines (`_legacy_static` computes the hosted checks).
- PE container: `xax_selfhost_general_image._pe_fn`/`_pe_entry_fn`; `import_pairs` is shared with the dynamic ELF.
- x86-64 views backend layout: stream `X86_STREAM_AT` (1M, 21M words), jumps/ranges after it, code `X86_CODE_AT` below the header; the driver's `lower` reads `X86_CODE_AT`.
- Next: S15e.3b (DLLs), S15e.4-S15e.7; B1's two-callee gap.

#### S15b.3e every resource callee; B1 — 2026-10-21 (ADR-318)

- `xax_selfhost_semantic.ACC_AT` (workspace words after `RC_AT`): 1 per graph accepted in this `verify`, cleared by `index_objects`, set by `rc_decide`. `_callee_aux` marks a call to an accepted callee with a trailing aux word; `xax_selfhost_facts._known_callee` reads it. Typing header word 63 is `H_RCALL_STOP` (the engine's stop at a callee).
- A waiting graph is checked again after each accepted callee (`RC_FINAL` unused).
- The driver's main function is at the pinned seed's facts-engine arena: even one more helper call there makes the seed decline to verify the compiler (check with `xaxc-linux-x86_64 verify bootstrap/xax_compiler_driver_general.xax`). Put new logic in helpers already called.
- `__pycache__` files are tracked: run with `PYTHONDONTWRITEBYTECODE=1` or restore them before committing.
- Next: S15e.3b (DLLs), S15e.7 (accelerator, SPIR-V), S15e.4-S15e.6.

#### S15e.3c 64 MiB stores and seed rotation — 2026-10-21 (ADR-319)

- `DATA_EXTENT` and the writer's `IN_EXTENT`/`OUT_LIMIT` are 64 MiB. Regenerating the decoder or writer store after changing their constants needs `XAX_STORE_PYTHON_DECODER=1 XAX_STORE_PYTHON_WRITER=1` (the old native images disagree with the new Python buffers). Seed `66a3f91d…`, 14,372,181 bytes.

#### S15e.3b DLLs and S15e.7 accelerator/SPIR-V — 2026-10-21 (ADR-320, ADR-321)

- `xax_selfhost_general_dll` (state at `GLOBALS + 64`), `xax_selfhost_general_accel`, `xax_selfhost_general_spirv` (state at `GLOBALS + 96`) are functions of the general x86-64 program. A DLL request reaches it as the entry (`B_DLL`, control word 46); architectures 4 and 7 branch in the front end before the Linux target check and write the image record directly.
- `B_PATH`: 4 accelerator, 5 SPIR-V (a hosted profile). The driver's main function was not changed.
- Builder pitfalls met: a raw value used after a branch must travel in a variable (`_emit` binds operands); `NONE` (0xFFFFFFFF) is a valid data word, not a sentinel, in emitted code; reusing a variable name of the enclosing function (`pe_dll`) silently reassigns it.
- Corpora: `tests/dll_corpus.py`, `tests/accel_corpus.py`, `tests/spirv_corpus.py`.
- Next: S15e.4 (browser Wasm page), S15e.5 (JVM jars), S15e.6 (Android), the raw-image targets, and the Windows legacy register path.


#### S15e.4 browser pages — 2026-10-21 (ADR-322)

- `src/xax_selfhost_general_wasm.py`: `wasm` (front end, architecture 2) → `wa_closure` (explicit DFS, `wa_enter`), `wa_imports`, layout pass (`wa_index` + `wa_addr` per function), `wa_types` (signatures), the WASI-entry check, `wa_function` per function (`wa_slots`, the four `wa_node_*` parts, `wa_term`), `wa_sections`, `wa_page`. Byte buffers are triples at `BUF`; `W_CUR` selects the one `wa_b`/`wa_u`/`wa_s` write. State lives at `GLOBALS + 192` (`WA`).
- `abi_layout` with 4-byte pointers: `_layout(tables, wasm=True)` (only the general program's `abi_layout`, in `xax_selfhost_general_frame`) reads `W_ON`, which the front end clears and `wasm` sets. Call `abi_layout`, not `layout` (the views took that name).
- Routing: `xax_selfhost_request.PATH_WASM_PAGE` (a `HOSTED_PROFILES` entry); `xax_build._hosted_container` calls `browser_page` (Python fallback on decline, `XAX_GENERAL_FRONTEND_DIFF=1` compares).
- Pitfalls met: DSL variable names `ip/iv/im/op/ov/om` are the views (a variable named `op` or `iv` breaks the call contract); the compile pass must reset `W_CURSOR` before laying storage out again; packing a 64-bit raw float into an argument word overflows (thresholds go through `W_THR`).
- Capacity: the compiler's views filled `VIEW_END` (68M words); now 73M with under 1M spare, arena 73M-128M. The probe that found it reads `GLOBALS + G_VIEW_OUT` and the emitted count after a declined run. A seed that cannot build the next compiler is rotated in two stages (build a compiler with only the capacity change, rotate, then the full one).
- Corpus: `tests/wasm_corpus.py`; driver test `test_browser_pages`; bench cases "build: a browser page (...)".
- Next: S15e.5 (JVM jars), S15e.6 (Android), the raw-image targets, the Windows legacy register path. Before the next addition to the general program, make room in the views region.
- The components' output view is 2 GiB (`xax_selfhost_typing.OUT_EXTENT`): the views backend lowering the driver needed ~105M words. Regenerating after such a layout change needs every native opt-out set (`XAX_*_PYTHON*`), since the old native images read the old layout.

#### S15f.4 and S15e.3b — 2026-10-22 (ADR-325, ADR-326)

- `src/xax_selfhost_aarch64_legacy.py`: the AArch64 legacy register path (`a64l_*`; state at `_a` slot 130). It is registered inside `add_frame_functions` before `a64f_function`, because it calls `a64f_movimm`. The dry run emits too: the emission state (`X_LEN`, `X_NFIX`, `X_NCALLS`, `X_NRANGES`, `F_NEXT_LABEL`) is reset before the real run.
- Bare-metal routing:
  - `G_A64RAW` (GLOBALS slot 191) is set by the AArch64 front end for ABI 3 / format 1.
  - `a64_view` skips the Linux allocator.
  - `_layout_fn` does not share slots.
  - The image has no stub or thunks.
  - Request path: `PATH_A64_RAW` 9 (ABI 3 required).
  - Hook: `xax_selfhost_aarch64_general.aarch64_raw_image`.
- Hosted x86 legacy additions: `lg_hosted` in `xax_selfhost_general_legacy.py`. `lg_call` takes `(node, position, obj, com)`: `obj` NONE for a direct call, `com` NONE for an import.
- Corpora:
  - `tests/aarch64_raw_corpus.py` (kinds `legacy`, `eligible`, `general`, `random`).
  - `tests/pe_legacy_corpus.py` (faults `com`, `abi`, `malformed`, `bound`). An inlined float leaf makes the bootstrap try its legacy path.
- Tests:
  - `test_xax_selfhost_aarch64_raw.py`.
  - `test_xax_selfhost_pe_legacy.py`.
  - `test_raw_images` includes the AArch64 cases.
- Pitfall: do not edit a builder module while a regeneration chain runs. The rebase and the evolved build import it and would capture half-finished code.
- View tests:
  - The audit decoder now sorts `pointer_extents` by value reference, as the verifier does.
  - `test_legacy_register_path` no longer expects `NATIVE-BITS-SUPPORTED` (ADR-324 sends narrow arithmetic to the frame path).
- Next: S15e.5 (JVM jars; `xax_jvm._compile_method_pass` is a two-pass optimizer: aliases, folding, slot coloring, deferred stores, stack-kept values) and S15e.6 (Android).

#### S15e.5a JVM program — 2026-10-22 (ADR-327)

- Modules:
  - `xax_selfhost_jvm` (front end, methods, class file, JAR, host `jvm_with_xax`/`jvm_jar`).
  - `_jvm_class` (buffers, pool).
  - `_jvm_code` (code buffer; `jc_flush` emits a deferred store's bytes directly, because the DSL has no recursion).
  - `_jvm_method` (analyses).
  - `_jvm_lower` (task stack at `M_WORK + 2^20`, top in `M_ONE`).
  - `_jvm_emit`.
- Pitfalls:
  - A variable declared inside an `if_`/`for_` body is out of scope after it: declare it first.
  - `jk_emit_pass` gives, so call it through `_emit_pass_call`.
  - `M_NEEDS_PK` is reset after the counting pass. Pass 2 (all attempts) sets `J_PK`.
- Checks:
  - `tests/test_xax_selfhost_jvm.py`.
  - The JVM tests with `XAX_GENERAL_FRONTEND_DIFF=1`.
  - Recording every `compile_jvm_bound_target` call of a test module against `jvm_with_xax` finds the declines to port next.
- Next: floats and conversions (`test_conversions`, `test_arithmetic_and_compares`), platform calls, traps. After that, a driver request path for JARs (then rotate the seed), and S15e.6 (Android).

#### S15e.5b JVM floats — 2026-10-22 (ADR-328)

- `_float_nodes` in `xax_selfhost_jvm_lower.py`.
- `K_FCONST` is (raw bits, width).
- `_relation_of` maps both compare kinds. `_compare_to_int` sets `prefix` to the relation and `prefix_fl` for a float compare.
- The task stack runs the last pushed task first. When a lowering pushes a conditional tail and an unconditional head, push the tail first.
- `INTERNAL_LABELS` (in `_jvm_method`) feeds the interference `M_ACROSS` and the definite-assignment points.
- Next: `CALL_FOREIGN` (the platform calls of `java_base_api`, `jvm_static`/`jvm_virtual`), then their rejections (`test_descriptor_type_mismatch_rejects`, `test_foreign_abi_from_another_platform_rejects`, `test_static_arity_mismatch_rejects`).

#### S15e.5c JVM references and platform calls — 2026-10-22 (ADR-329)

- `xax_selfhost_jvm_foreign`:
  - `jk_intern` (codes `D_REF + k`; texts in the class store, `J_REFS`/`J_NREFS`).
  - `jk_vdesc` (every value type; `_jvm_desc` and `jm_types` call it).
  - `jk_matches`.
  - `jk_member` (an `MB_*` record whose texts are words).
- `kind(e, d)` maps a reference code to `D_A` for the opcode tables.
- Reference codes start at 16 so that they never collide with `ST_FREED`/`ST_TOP`.
- Store objects for a reference type need its opaque element: `opaque_identity_type(REFERENCE_PREFIX + text)`.
- Next:
  - The object kinds (`_object_member`: new, arrays, instance fields, `ldc`, `checkcast`, `instanceof`, `putstatic`).
  - Then the memory profile (`xax/jvm/Memory`, loads and stores through `xax$ld*`/`xax$st*`).
  - The general and object profiles.
  - The driver request path.

#### S15e.5d JVM object kinds — 2026-10-22 (ADR-330)

- `MB_KIND` (`OK_*`): `OK_CALL` is the call kinds.
- `K_FOREIGN` takes a phase: 1 is `new`'s head, 0 the instruction.
- The member record's `MB_FSIZE` is the field descriptor's size, which the Fieldref records for the depth scan.
- Next:
  - Callbacks: `_callbacks` and the `jvm-interface` code entries, which may add classes to the JAR.
  - Indirect calls: `_indirect_calls`, the `xax$i<k>` dispatchers.
  - Recursion groups.
  - The memory and general profiles.

#### S15e.5e JVM callbacks — 2026-10-22 (ADR-331)

- `xax_selfhost_jvm_callback`:
  - `jk_table` runs after the signatures: the table and the groups.
  - `jk_cb_signature`.
  - `jk_callbacks` runs inside `jk_class`, before `xax$pk`, whose record then moves ahead of the callback records.
- `jk_parse` (in `_jvm_foreign`) parses a descriptor without diagnostics.
- `jk_vdesc` gives a `jvm-interface` code entry's pointer the type `L<interface>;`.
- `scratchpad/jprobe.py`-style probing works: read `GLOBALS + J_STATE` and its fields after a native run to see how far a declined compile got. A zero state means a front-end decline.
- Next, the general profile's operations, in `xax_jvm`'s order:
  - aggregates and sums (flattened `long[]`);
  - links;
  - `STACK_ALLOC` and the shadow stack (`S`, `M`, the memory members);
  - atomics;
  - indirect calls (`xax$i<k>`).
- Then the memory profile's members, recursion groups, the threaded launcher, and the driver request path.

#### S15e.5g JVM memory profile — 2026-10-28 (ADR-336, ADR-337)

- ADR-336 drafts the rest of S15 (roadmap rows S15e.5g-S15e.5j, S15e.6a-S15e.6h, S15g).
- `xax_selfhost_jvm_memory`: the memory lowering (`memory_nodes`, `memory_call`, `run_head`), the runs analysis (`jm_runs`), the needs (`M_MNEEDS`, `M_MBYTES` per method, merged by `jm_merge` into `J_NEEDS`/`J_BYTES`), `initial_scan`, and `jk_members` from `memory_templates` (verify with `check_templates()`).
- Pitfall: a `_call` whose result is NONE is a decline; a helper that can legitimately answer "none" must return 0 (or use `_call_none`).
- The decline audit: a pytest plugin that wraps `xax_jvm.compile_jvm_bound_target` and also runs `jvm_with_xax`, logging equal/declined/different for successes and rejections (see ADR-336). Run it over `test_xax_jvm*.py` after each step.
- The general driver store and the seed are NOT regenerated yet (the driver merges the JVM program): do that once at S15e.5j (`xax_selfhost_evolution rebase` if needed, `write-request`, two-stage `rotate-seed`, `selfbuild.sh`).
- Next: S15e.5h (general profile: `STACK_ALLOC` frames and the shadow stack, links, raw loads, atomics), S15e.5i (recursion groups, the threaded launcher).

#### S15e.5h-S15e.5i JVM general profile and launcher — 2026-10-28 (ADR-338)

- Frames: `M_FSLOT`/`M_FSIZE`/`N_FOFF` (computed in `jm_slots` after the coloring); the prologue is in `_emit_pass`, the epilogue in `je_terminator`.
- `general_nodes` and `mem_access` (in `xax_selfhost_jvm_memory`) are the shared access lowering; `Fwd` writes tasks forwards.
- `jf_scan` (closure rejections in the bootstrap's order) and `jf_shadow` (JVM-ENTRY-SHADOW-STACK) walk the graph stream: each block is its parameter list, node count, nodes, terminator.
- Debugging a decline: run the native program and read `GLOBALS + J_STATE`/`M_STATE` (the task stack is at `M_WORK + 2^20`, five words a task, top `M_ONE`).
- Next: S15e.5j (regenerate the general driver store with the new JVM program: ledger rebase if the edit records no longer apply, `write-request`, two-stage seed rotation if the pinned seed cannot verify it, `selfbuild.sh`; then the driver's JVM test and the evidence).

#### S15e.6h unsigned APKs in the driver — 2026-10-29 (ADR-354, ADR-355, ADR-356)

- The Android program's frontend is twelve phase functions. Its variables live in memory words (`_Slotted`), so a new `yield` boundary can go anywhere at the generator's top level. Keep every phase graph well below 1.5 MB: the previous seed's general x86-64 program must emit each one, because the pinned seed builds the next.
- Debugging a declined seed build:
  - Build a HEAD driver with `XAX_DRIVER_DECLINE_SITES=1`, make its request store (`compiler_request(reader)`), and let the seed resolve and build it. The debug compiler's exit status minus 16 indexes `DECLINE_SITES`.
  - Read the general program's image state (`I_OK`, `I_COUNT`, `I_LEN` at `GLOBALS + G_RA`) to find a function without code. `general_with_xax(...)[3]` names it.
- Debugging the views backend (`compile_with_xax` "unavailable or declined"): read the header words `S_COUNT` (code bytes) and `S_FN` (the function reached), and `G_OUT`/`G_SEND` (the stream).
- Next: S15e.6i.
  - Signed APKs need a signing-effect input checked as `validate_build_effects` does, with the XAX signer chained.
  - libxposed JVM modules need the bytes of external inputs, with the JVM program, class translation and DEX writer chained.
  - Then S15g: derive the whole-compiler B levels.

#### S15e.6i.1 signed APKs in the driver — 2026-10-29 (ADR-357)

- The pinned seed verifies the next driver, so the driver's function must fit that seed's capacities.
  - The binding one is the CFG program's 2M input words: six per operand use, including every edge argument.
  - The graph decoder's 2 MiB comes second.
  - Measure with the main graph of `build_general_driver_program()` before a regeneration (count its blocks, edges, nodes and uses as `xax_selfhost_semantic._cfg_input` writes them). The function is at 2,078,110 words.
  - A seed that declines `resolve` of a new request store is the symptom. A decline-site debug build of HEAD (`XAX_DRIVER_DECLINE_SITES=1`, built and run by the seed) names the helper.
- Each `w.let` name at the function's level is a block argument of every later block, and so costs a use on every edge.
  - Keep new state in workspace words (`SIGN_AT`).
  - Put decisions in helper functions (`xax_selfhost_request`) or in the programs the driver calls. The APK signer writes `build`'s signing rejections itself.
  - Write copies as loops.
- Next: S15e.6i.2, libxposed JVM modules (roadmap row).
  - First raise the CFG and graph capacities in two rotations: a driver with larger capacities built by this seed, then the change built by it.
  - The driver must keep the external inputs' bytes.
  - A new libxposed JVM program chains the JVM program, class translation, the DEX writer and bridges, the manifest or branding, the metadata and the APK.
  - Branding archives in the tests are stored, not deflated.

#### S15e.6i.2 and S15g libxposed JVM modules; the whole compiler's B levels — 2026-10-30 (ADR-358)

- A capacity the pinned seed's verifier lacks needs two rotations: first a driver that only raises the capacity, built and verified by the current seed, then the change, built by that driver's seed. S15e.6i.2a raised the graph bodies (4 MiB) and the CFG input (8M words, at workspace word 160M).
- The Android program's libxposed JVM profile is four phases (J1-J4) after the managed-class profile's. `managed` is 2 for a JVM target, and every other phase skips.
  - Its layers are the JVM program (it reads this input, like the AArch64 program) and the class-translation and DEX-writer programs, built redirected.
  - The external inputs follow the package identity in the input: digest, length, packed bytes. The driver appends what it kept at `INPUT_BYTES_AT`.
- `bench_full_selfhost`'s scope has no `outside_scope`. `bootstrap_status` then takes the whole production compiler's levels from the Linux x86-64 compiler's derived ones. Keep its corpus covering every target and artifact `build` makes.

#### W4 reference layout — 2026-11-04 (ADR-363)

- Python compiler code (`xax_compiler`, backends, workspace, references) is in `compiler/reference/`. Native runners and tooling stay in `compiler/src/`. New compiler logic goes in `reference/`; `test_python_authority_inventory` checks the split by class.
- Run from `compiler` with `PYTHONPATH=src:reference:.`, or use plain `pytest`. A subprocess that sets `PYTHONPATH` must name both directories.
- The wheel tests skip on hosts whose setuptools cannot build without isolation. Check packaging with `pip wheel . --no-deps`, then install the wheel into a fresh venv.
- What remains for Python independence: in-process runners still lower and verify with `reference/`. The M11 bootstrap and the Python `xaxc` CLI are reference tooling.

#### W3 M14 bootstrap retired — 2026-11-04 (ADR-362)

- Regenerate the status blocks with `python -m xax_status_docs --write` from `compiler/src`. They call `xax_selfhost.bootstrap_status()`, which reads `full_selfhost_evidence.json` and `python_free_seed_evidence.json`; re-run those benches to change a level.
- Do not add a Python seed. `test_audit_remediation.SeedTests` fails on any `.pyz` in `bootstrap/`.
- OI-27's experiment no longer has a primary-seed arm; its committed evidence is the pre-W3 record. Regenerate it with `python -m benchmarks.bench_oi27_bootstrap_diversity --write` (needs Go) only for a new dated record.
- Next, W4: move the independent checks and Python references into `reference/`. *(Done: the W4 section above, ADR-363.)*

#### W2 frozen stores and the ledger — 2026-11-04 (ADR-361)

- There are no self-hosting builders. To change a component or the compiler, write an `XAXEDIT1` record (`xax_selfhost_edit.edit_record`, or translate a workspace batch with `xaxc edit` and record its effect) and run `python -m xax_selfhost_evolution apply <record> <store>...` on Linux x86-64. For the production compiler name both `xax_compiler_driver_general.xax` and `seed/xax_compiler_request.xax`, then `selfbuild.sh` and rotate the seed.
- An edit of the 62 MB driver store takes about a minute with the seed. Python's `apply_reference` takes about 30 s for a constant and several minutes for a structural record.
- `test_store_regeneration` reads earlier stores from git by blob id. Keep the history: a shallow clone skips those replays.
- B6 evidence: `bench_full_selfhost` writes `evolution` as `xax-evolution-replay-v2` (ledger replays plus the structural `probe_record` on the committed driver). `bootstrap_status` reads both v1 and v2.
- The S16a debugging aid (`XAX_DRIVER_DECLINE_SITES`) needed the driver builder and no longer exists. Instrument with a ledger transaction on a copy instead.

#### S16a native workspace — 2026-10-30 (ADR-360)

- The workspace helpers are `ws_*` in `xax_selfhost_edit.py`; `ws_command` classifies `edit`'s input. Helpers keep their state in workspace words (`WSC` control words, `EIN`/`WS_IN`/`BATCH` regions).
- E-DSL pitfalls met here: a helper argument or variable must not be named `ip`, `iv`, `im`, `op`, `ov` or `om` (the view triples); a graph over about 4,000 blocks declines in the XAX verifier; inline text output (`_out_text`, `D.text`) multiplies nodes, so tables of packed words and loops keep helpers small.
- The driver's main function has about 600 values left under `VCAP` (`xax_selfhost_general_view`). Count with the snippet in ADR-360's work (`values = sum(params + node results)` of the entry graph) before adding a driver stage; each `emit` call or new command adds dozens of blocks of about 95 parameters each.
- Debugging a seed decline: build the committed driver with `XAX_DRIVER_DECLINE_SITES=1`, let the seed build it, and run it (the exit status names the site). Inside the general backend, `_ok` records no reason; instrument it temporarily (`H_REASON`) to find the check. *(Superseded by the W2 section above, ADR-361: the driver builder no longer exists.)*

#### S15e.6i.3 records, compressed branding, large inputs — 2026-10-30 (ADR-359)

- The module record is decoded to code points (`an_jdecode`) and parsed with an explicit stack (`an_jparse`); value nodes are listed above `_jcp` in `xax_selfhost_android.py`. Python's rules over them are the `an_j*` helpers. A check belongs where the bootstrap fails: before `LIBXPOSED-JVM-INPUTS` only what fails before it (J1); the rest in J3/J4.
- Compressed entries go through `an_entry_bytes`: `an_inflate`, `an_bunzip` (libbz2 1.0.8) and `an_unlzma` (liblzma 5.4.5). Every stop on short input ends in `an_zfinish`, which keeps `file_size` bytes and checks the CRC.
- Large data lives in the image buffer once no AArch64 program can run again (`big_writer`, `an_bigalloc`): inputs from its start, records from its end.
- A decline must leave the status word 0: the frontend clears it. Debug declines with `XAX_ANDROID_WHY=1` after `build_android_program()` in the same process (it fills `DECLINE_SITES`). *(Superseded by W2, ADR-361: the Android builder is deleted.)*
- `test_xax_selfhost_android_records.agree` is the differential harness; seed its fuzz differently to search further.

### Other self-hosting records

#### B1–B4 (RISC-V backend) — 2026-10-03 (ADR-145)

- Rebuild `bootstrap/xax_riscv64_backend.xax` with `write_backend_store()` after any change to `xax_selfhost_riscv64_backend.py`. The views-profile front end (pass A2 in `_translate`) must mirror `_pointer_extents` and `_rewrite_borrowed_views` in `xax_riscv64.py`.
- B4 takes about 6 minutes under Unicorn: run `XAX_FIXED_POINT=1 python -m pytest tests/test_xax_selfhost_fixed_point.py`, or regenerate the evidence with `PYTHONPATH=src python benchmarks/bench_selfhost_fixed_point.py --write`.
- `run_riscv64_views` maps the input view at `0x20000000` and the output view at `0x40000000`, and passes them in `a0` and `a1`. Read the output with one bulk `mem_read`: reading word by word is quadratic for a 2 MB image.

#### ADR-320/ADR-321 evidence — 2026-10-21

- `benchmarks/full_selfhost_evidence.json` re-run on the compiler with DLL, accelerator and SPIR-V paths: C1 = C2 = C3 = `a8059c6d…` (15,451,493 bytes), 150 corpus cases with every generation agreeing, `rejection_exactness_gaps` empty. `python_free_seed_evidence.json`, `m14_selfhost_evidence.json` and the status blocks regenerated; B0-B6 still hold for the Linux x86-64 production compiler, and the whole-compiler blocker now lists only S15e.4-S15e.6, the raw images and the Windows legacy register path.

## JVM

### JVM and RISC-V targets — 2026-10-03 (ADR-112–ADR-114)

- Two architectures were added with zero kernel changes. Architecture 5, `jvm-classfile-v1`, lowers XAX directly to class-file bytecode in a deterministic JAR; it is EXECUTED on HotSpot 21 and the JVM row is at R2. Architecture 6, `riscv64-baremetal-raw-v1`, emits a raw RV64IM image; it is EXECUTED under Unicorn and the riscv64 row is at R1. Both pass the same differential corpus against the reference executor.
- MEASURED: JVM Collatz 1.04× `javac` kernel time, 1.51× class bytes. RISC-V Collatz 3.72× `clang -O2` emulated instructions, after a liveness-hull linear scan cut it from 15.9×.
- Repairs: OI-25/OI-26 evidence replays no longer depend on filesystem order or interpreter version; one stale code hash was re-pinned after execution; the wheel now packages `xax_web`, `xax_android_counter`, `xax_jvm`, and `xax_riscv64`.
- Regression here: 903 passed, 19 skipped, 1 failed (wheel needs Python ≥ 3.12).

### JVM R4 — 2026-10-04 (ADR-157)

- Re-measure with `PYTHONPATH=src:.:.. python -m benchmarks.bench_jvm_jsonmin --write` and `PYTHONPATH=src python benchmarks/bench_jvm_twin.py --write` from `compiler/`. They need `java`, `javac`, `jar`, and `kotlinc` on `PATH`; `kotlinc` 2.1.0 is the JetBrains release under `/opt/kotlinc` here.
- The jsonmin benchmark times each run through a small runner process. A child forked straight from the benchmark process inherits its ~1 GB Python heap in `ru_maxrss`.
- Backend invariants that the JVM tests guard:
  - every frame lists the same locals, and a slot is typed only if a value in it lives across a branch target;
  - a value left on the operand stack never feeds an edge or a copy, whose readers use its slot;
  - the generated `xax$ix`/`xax$cld1`/`xax$cst1` members throw the same `java.lang.Error` as the inline trap.

### JVM code size — 2026-10-05 (ADR-158)

- `_compile_method` runs a counting pass into a scratch pool, then the real pass. A `_KeepParameters` retry keeps a dead parameter's slot when reusing it would need a zero store before the parameter is read.
- Invariants that the JVM tests guard:
  - a value is evaluated at its reader only if it is pure, read once, in its own block, and not an edge argument or copy operand;
  - liveness charges such a tree's operands to its reader (`effective`);
  - aliases (`canon`) go through one-predecessor block parameters and repeated loads.
- `tests/test_xax_selfhost_riscv64.py::CrossTargetEncoderTests::test_encoder_lowered_to_the_jvm_agrees` is the largest JVM program in the suite. It caught both miscompiles found during ADR-157/158, so run it after any JVM backend change.


### JVM R6 — 2026-10-10 (ADR-257)

- `python -m benchmarks.bench_r6_xwc --write` needs `java` and GNU `wc` (Git Bash has coreutils 8.32); about 15 seconds. It rewrites both stores and the evidence; the tests in `test_xax_construct.py::XwcTests` fail if the request, the transaction, or the stores drift.
- Carrier on the JVM: the process entry returns only proof values (`proc`, `fs`, memory effects); exit through `jvm.exit_group`. Projection node numbers are function-wide, workspace handles count per block.
- XAX-MCP (`MrxSiN/XAX-MCP`, `compat.py`) should learn host contract minor 5 (Windows PE integer operations) and 6 (`jvm` construct platform).

### Handoff — 2026-10-22, JVM JARs in the driver (ADR-332, ADR-333, ADR-334)

- The driver dispatches `PATH_JVM` (10) to `jvm_program`.
  - `build_request` checks the JAR artifacts and sets `B_JVMEXE`.
  - The JVM image record uses the general layout `[1, 0, len, jar]` at `IMAGE_AT`.
- Capacity:
  - `xax_selfhost_typing.IN_EXTENT` is now `1 << 30`.
  - The x86-64 views backend's stream sits below the code, and the jumps and ranges share the code region.
  - A future growth of the driver may need these raised again. Rotate the seed in two stages when the pinned seed cannot verify the new store.
- Next:
  1. Re-run the evidence (`refresh_selfhost_store.py` per program, `bench_selfhost_x86_64.py --write`, `bench_full_selfhost --write`, `bench_python_free_seed --write`), then `generate_m14` and `xax_status_docs --write`.
  2. Re-run serially the tests that crashed under xdist.
  3. The JVM memory machinery, then S15e.6 Android packages.

## Android

### Android arm64-v8a direct shared object — 2026-10-01

- Production path: verified XAX -> existing register-resident AArch64 lowerer ->
  bounded direct Android ELF64 ET_DYN emitter. No LLVM, Clang, GCC, CMake,
  ndk-build, XAX runtime, or C/C++ runtime is in the production path.
- Target: `android-arm64-v8a-shared-v3`; ABI `android-aapcs64-c`; 16-KiB
  `PT_LOAD` alignment.
- Explicit exports only; explicit foreign imports only. No default `DT_NEEDED`.
- Current import implementation uses one GOT slot + `R_AARCH64_GLOB_DAT` per
  referenced foreign function and a local 3-instruction AArch64 thunk.
- libxposed native ABI fixture uses borrowed `NativeAPIEntries*` offsets 0/8/16
  and returns a local callback without allocation.
- JNI bootstrap fixture uses borrowed `JavaVM*`, loads `GetEnv` from the invoke table, and
  calls it directly with `BLR`; the local `JNIEnv*` output slot remains explicit
  semantic stack memory.
- JNI phase-1 platform package now exposes all Android public JNI 1.6 table slots
  (native slots 4..232 plus VM slots 3..7) through ordinary fixed-offset target
  operations. `JNIEnv*`, `JavaVM*`, IDs and reference classes use generic
  identity-qualified opaque ABI types; acquired local/global/weak-global refs
  carry linear owner proofs. Focused JNI evidence is
  `compiler/benchmarks/android_jni_platform_evidence.json`. Calls that may raise
  now thread a linear `clean` -> `maybe-pending` proof; ordinary safe JNI calls
  reject `maybe-pending`, and the supported explicit `ExceptionClear` policy
  restores `clean`. Nullable/non-null reference identities are distinct for the
  bounded mixed-pack path, but runtime null refinement/construction and successful
  thread-attach state are still open semantics.
- Structural evidence/tests are authoritative for this host. Android `dlopen`
  validation remains to be run on a real arm64 device/emulator using
  `compiler/integration/android/validate_on_device.sh`.

### Android direct managed-artifact progress — 2026-10-01

- A content-addressed Android UI target/platform carrier is now authoritative for
  the first Activity fixture: Activity/listener descriptors, initial `XAX` text,
  and click `Clicked` text are semantic identity, not compiler-only configuration.
  Lowering the same carrier is byte-deterministic. A click-text-only semantic edit
  changes only the listener DEX; the Activity DEX remains byte-identical.
- Direct DEX 039 now synthesizes a real bounded managed UI path. `onCreate(Bundle)`
  is 28 code units and performs `super`, one `Button` allocation, initial text, one
  listener allocation/registration, `setContentView`, one native lifecycle callback,
  and return. The Activity DEX is 1,236 bytes.
- The generated listener click path is 11 code units: `check-cast` clicked `View`,
  `setText("Clicked")`, one private native XAX callback, return. It emits zero
  click-time allocations and no reflection machinery; listener DEX is 764 bytes.
- One 17,352-byte AArch64 ELF exports both canonical JNI callbacks with zero imports,
  `DT_NEEDED`, or relocations.
- Direct binary manifest, deterministic aligned APK packaging, and direct APK v2
  RSA/SHA-256 signing remain implemented. Both unsigned and signed APKs are ordinary
  M10 build-request artifacts. Signed publication requires an explicit package/profile
  `SIGN` capability scoped to the certificate SHA-256 plus an ephemeral build effect
  carrying private RSA material; private material is absent from semantic stores,
  provenance, and build keys. Current signed structural fixture:
  `compiler/benchmarks/android_minimal_activity.apk` (**35,413 bytes**), containing
  `classes.dex`, `classes2.dex`, and the native library. `minSdk=28`, so the fixture
  requires no multidex support runtime on ART.
- Direct class/JAR/API-version import, JNI loader-domain identity, linear reference
  ownership, exception state, exact descriptor-driven member calls, narrow integer
  `jvalue[]` packs, and bounded `jlong`+strong-reference packs remain as previously
  documented.
- Real Android install/ART/lifecycle/render/click/JNI execution **EXECUTED and
  PASSED** on 2026-10-02 via `validate_activity_apk.sh` (3 cold runs, exit 0) on
  Pixel 8 Pro `google/husky/husky:17/CP3A.260905.009/16091614:user/release-keys`
  (SDK 37, arm64-v8a). Evidence: v2 signature accepted; ART dexopt
  `status=PERFORMED`, filter `verify`, no verifier rejections; nativeloader loaded
  `lib/arm64/libxaxapp.so` `: ok`; `am start -W` `Status: ok` (cold TotalTime
  394/275 ms); initial `XAX` text rendered; tap rendered `Clicked`; process alive
  after both JNI callbacks; no crash-buffer entries. gfxinfo: 122 frames, 2 janky.
  This covers only the minimal Activity fixture; libxposed runtime remains UNEXECUTED.
- Resource-table emission, optional Application/Service/BroadcastReceiver synthesis, current modern libxposed metadata, generated `XposedModule`, and bounded API-102 managed hook installation/mutation are implemented structurally. Separate canonical profiles cover pass-through, zero-argument result replacement, one-String argument replacement, and combined argument-then-result replacement. `compiler/benchmarks/android_libxposed_combined_evidence.json` records the most complete profile: a 34,347-byte deterministic module APK; one install-time `Class[1]` plus one Hooker allocation; and a 20-code-unit interceptor with one explicit `Object[1]` hot allocation, one `proceed(Object[])`, original-result capture, and constant result replacement. Runtime libxposed execution remains UNEXECUTED.
- Retained HookHandle/manual-unhook semantics are now implemented structurally as a separate `retained-manual-unhook` lifetime. The process profile remains field-free and its Hooker bytes are unchanged. `compiler/benchmarks/android_libxposed_unhook_evidence.json` records the retained field/store and 11-code-unit `xaxUnhook()` shape; actual framework unhook remains UNEXECUTED.
- Explicit libxposed deoptimization is now a separate canonical `best-effort` policy. It reuses the exact `Method` resolved for the companion hook, emits one API-102 `deoptimize(Executable)` before `hook`, adds zero allocation, and does not alter Hooker bytes. `compiler/benchmarks/android_libxposed_deopt_evidence.json` records a 1,956-byte module DEX and 43-code-unit package-ready path; actual ART deoptimization success remains UNEXECUTED.
- Explicit module-service semantics cover generated direct wrappers for framework name/version, remote preferences, remote file listing, and remote file open with `propagate` failure policy. `compiler/benchmarks/android_libxposed_services_evidence.json` records a 1,664-byte module DEX; every selected wrapper is five code units and emits no allocation.
- Remote resources now have separate capability-aware carriers. `libxposed-remote-preferences-v1` tests `PROP_CAP_REMOTE` before acquisition and exposes only direct boolean/int/long/float/String/contains reads; no Editor/write path is generated. `compiler/benchmarks/android_libxposed_remote_preferences_evidence.json` records a 34,289-byte APK and 2,144-byte managed DEX with a 16-code-unit acquisition gate plus six 5-code-unit read helpers. `libxposed-remote-files-v1` applies the same null-on-unsupported/propagate-on-supported-failure policy to list/open; `android_libxposed_remote_files_evidence.json` records a 34,289-byte APK and 1,428-byte managed DEX, with both helpers at 16 code units and zero emitted allocation. Runtime capability/service behavior remains UNEXECUTED.
- Bounded API-102 hot reload is implemented as `single-retained-hook-id-guarded-atomic-replace`, legal only for one Java entry and one `retained-manual-unhook` generated hook. Metadata adds `autoHotReload=true`; initial hook installation sets stable ID `xax.primary` and stores the target/app ClassLoader from `PackageReadyParam`. `onHotReloading` is an 11-code-unit path that rejects reload before target readiness or saves only that host-owned ClassLoader through `setSavedInstanceState`. `onHotReloaded` is a 51-code-unit path that restores the loader, checks for an empty old-handle list, validates `HookHandle.getId()` against the declared ID, skips absent/mismatched transfer state, then creates one new Hooker, performs one atomic `replaceHook`, and stores the returned handle. It emits no unhook/install gap, target reflection, array allocation, module-defined saved object, or hidden serialization runtime. `compiler/benchmarks/android_libxposed_hot_reload_evidence.json` records a 34,347-byte APK and 2,920-byte managed DEX; Hooker bytes are unchanged. Runtime saved-state and hot-reload behavior remain UNEXECUTED.
- *(2026-10-06, ADR-178: run `compiler/integration/android/vector/validate_vector_runtime.sh` on a rooted arm64 device with Zygisk and Vector v2.2+; it automates this and 26 further checks.)* Exact next implementation dependency: execute the paired controlled target/module on a compatible Android + current libxposed API-102 environment and record module discovery, package-ready delivery, argument/result mutation, retained-handle behavior, explicit unhook/idempotence, deoptimization return, PROTECTIVE exception behavior, capability-gated preferences/files, saved target-ClassLoader transfer/rejection behavior, stable hook-ID transfer/mismatch behavior, hot-reload callback delivery and replacement atomicity, process survival, latency, and ART/XAX-attributable allocations. If that environment remains unavailable, the next bounded compiler-side gap is multiple retained hooks keyed by unique API-102 IDs, followed by explicit package/process and external-resource cleanup/migration; preference writes/listeners and ParcelFileDescriptor consumption remain separate later contracts.

### Android counter upgrade and emulator notes — 2026-10-04 (ADR-153, ADR-154)

- Host setup for the full suite is in `README.md` (Getting started). The API 30 `google_apis` x86_64 emulator image with ARM translation is the only route to an `adb` target on a host without `/dev/kvm`; see `compiler/integration/android/README.md` for the watchdog, ANR, and attach-timeout problems and their workarounds.
- `python -m benchmarks.android_counter_app --device` records a device run of the committed counter APK (target identity, `hardware` flag). Only an EXECUTED run of the same APK hash is carried forward; rebuilding the APK resets it to UNEXECUTED.
- `python -m benchmarks.bench_android_counter_twin --device` is the R4 harness for the Android row: cold start and PSS of XAX against the Java + NDK twin. It counts only on arm64 hardware; the matrix must not cite an emulator run for performance or memory.
- Next for the Android row: the counter on a device (R3), the twin comparison on hardware (R4 sizes are already MEASURED), and write-then-rename persistence if torn writes matter. *(Later the same day the counter passed on an emulator, so the row is R3; see ADR-155.)*

### Android retained-hook identity — 2026-10-05 (ADR-171)

- Stable API-102 IDs now belong to hook-installation semantics. Hot reload requires its ID to match the retained installation; process-lifetime hooks cannot carry an ID. Legacy ID-free installation CIDs are preserved.
- `benchmarks.bench_android_libxposed_hot_reload` regenerates the structural fixture. APK and DEX bytes remain unchanged; semantic/build roots change because the previously implicit ID is now declared.
- Next compiler slice: admit multiple `(adapter, retained installation)` pairs, reject duplicate IDs in the build closure, and replace each transferred old handle by ID. Runtime execution still takes precedence when a compatible libxposed device is attached.

### Android arm64 hardware R4 — 2026-10-05 (ADR-172)

- Device: Pixel 8 Pro, Tensor G3, Android 17/API 37. The committed counter APK passes the lifecycle/persistence oracle natively; evidence is in `android_counter_evidence.json`.
- `bench_android_counter_twin.py --device`: 16 tracked cold starts per arm, XAX 227.0 ms vs Java + NDK 223.5 ms (`1.016×`); median PSS 112,862.0 vs 113,411.5 KiB. Android is now R4 for this workload.
- Windows reproduction uses NDK `28.2.13676358`, build-tools `37.0.0`, `android-37.0`, and the host-portable `_llvm`/`_sdk` lookup in `bench_android_ndk_twin.py`. libxposed requires a compatible framework installation.

### Android platform contracts on hardware — 2026-10-05 (ADR-173)

- `integration/android/validate_platform_contracts.sh` now runs from Git Bash with the Windows r28c NDK. It keeps Windows local paths for `clang.exe`/adb while preventing MSYS conversion of `/data/local/tmp`.
- Pixel 8 Pro printed `XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1`; `android_platform_runtime_probe_evidence.json` records native arm64 hardware execution.

### Android hardware follow-up (2026-10-07, ADR-197, ADR-198)

- Device setup: rooted Pixel 8 Pro over wireless adb (KernelSU 3.1.2, Zygisk Next, Vector v2.2). With more than one device attached, set `ANDROID_SERIAL`. Windows tools: SDK build-tools 36.0.0, NDK 28.2, `android-36`, Temurin 17. The libxposed AAR is `XAX_LIBXPOSED_AAR` (pinned SHA-256).
- Vector harness: `python integration/android/vector/vector_harness.py` from `compiler/` (heap oracle by default). Nine checks remain UNEXECUTED because JDWP attach aborts Vector-hosted ART on API 37. Re-test `--oracle jdwp` after a Vector or ART update.
- ART layers on hardware: `XAX_ART_DEVICE=1 python -m benchmarks.bench_android_art_verify` / `bench_android_art_execute`.
- R4: `python -m benchmarks.bench_android_counter_twin --device` (about 15 minutes; the phone must be on AC power with Battery Saver off). Next: more starts per pass to bound the drift, and a Kotlin arm if Android code size matters.
- The ART execute stand-in still never calls the hot-reload callbacks; only Vector exercises them.

### Android managed classes for AutoHead (2026-10-07, ADR-199)

- New Android callbacks: declare an `AndroidManagedClass` (`xax_android_managed.py`), export one function per method named by `jni_short_native_symbol(class, "xax<Name>")`, with ABI `(JNIEnv*, borrowed this, args...)`. Use `android_arm64_shared_general_target()` when the export needs comparisons or the other general operations. Fixture and device oracle: `benchmarks/bench_android_managed.py --device` (needs `ANDROID_SERIAL`; the phone must be unlocked; media volume is restored with VOLUME_DOWN because `volume --set` is ignored on this build).
- Next for AutoHead, in dependency order: (1) execute an XAX graph that calls SDK members over JNI on the device (construct `SurfaceView`, `getHolder().addCallback(new SurfaceCallback())`); (2) uses-permission/feature entries in the manifest carrier; (3) exact JNI `float` carriers (MotionEvent coordinates); (4) NDK imports for `AMediaCodec`/`ANativeWindow_fromSurface` and AAudio, which avoid JNI on media hot paths; (5) services and receivers in the managed-class profile.

### Android platform capability contracts (2026-10-08, ADR-202 to ADR-204)

JNI `F`/`D` are exact, the managed-class APK takes an `android-platform-declarations-v1` carrier, and `xax_android_platform` plus `xax_platform.posix_async_api` give ownership-typed NDK/POSIX contracts and an SDK capability table that the managed build enforces. Per-capability status: `docs/ANDROID_PLATFORM_CAPABILITIES.md`. Everything is STRUCTURAL. Next, on the authorized device: run a managed APK that forwards `onTouchEvent` and reads `getX`/`getY`, a SurfaceHolder callback that acquires and releases an `ANativeWindow`, an AMediaCodec decode loop, an AAudio output stream, and an RFCOMM connect/close; then close OI-47's gaps.

### Android cold start and AArch64 on hardware — 2026-10-10 (ADR-253, ADR-254)

- Android R4 is blocked by a framework-bound tie, not by XAX code: re-runs of `bench_android_counter_twin --device` need about 40 minutes and every arm stays within ±2.5%. Do not expect a code change in the app to move it; a workload whose own work is visible (as `jsonmin`) is where the backend shows.
- Device runs on Windows: put `adb` and a JDK on `PATH`, set `ANDROID_NDK_HOME`, `ANDROID_BUILD_TOOLS`, `ANDROID_JAR`, `KOTLIN_HOME`, and `RUSTC`, and `MSYS_NO_PATHCONV=1` in Git Bash. `XAX_AARCH64_ADB=1` runs the AArch64 Linux runtime tests on the device; `simpleperf stat -e instructions:u` and `simpleperf record --sort vaddr_in_file` work on it from `adb shell` (user-mode events only). The XAX image has no symbols: wrap it with `.inst` words to disassemble with the NDK's `llvm-objdump`.
- Next for Linux AArch64: a second hardware workload (`chains` has no AArch64 build yet; `filestat` needs zlib through glibc's loader, absent on Android, so a static zlib-free variant or a glibc host is needed), floats and aggregates on the register path, and an R5 maintenance record. Next for Android: keep the cold-start evidence current; R4 there needs a start-up path the app controls.
- With several devices on `adb`, set `ANDROID_SERIAL` for every harness. `android_jsonmin --output PATH` writes a run on another device or core beside the cited file. 32-bit ARM devices (`armeabi-v7a`, e.g. OnePlus One) cannot run any XAX artifact: there is no ARM32 target.

### Android R5 maintenance — 2026-10-10 (ADR-255)

- `python -m benchmarks.bench_r5_android_counter --write` (one device on `adb`, `ANDROID_NDK_HOME`): about 15 minutes. Android cannot derive R5 before R4; the record is in place for when it does.
- Structural edits: one insertion per anchor and one mutation per node, and a deletion sees its own generation's uses, so plan a structural change as several small transactions. A machine-target change is refused by the workspace on purpose.

## Windows

### 2026-10-27 — Native Windows seed distribution (ADR-335)

`compiler/bootstrap/windows` pins the existing XAX native alias-index compiler executable and its original
canonical source revision. `compiler/integration/windows_helpers/hash_request.xax` is a native-verified build
request for the unchanged BLAKE3 host. Its verify/resolve/build path runs with the native seed and no interpreter
bootstrap. Application source remains outside XAX. The seed's own source still declines native build; no B/R
promotion or self-build fixed point is claimed. See the seed contract and evidence for the exact limits.

### 2026-10-27 — Native Windows consumer requirements

The Windows checkout was fast-forwarded to remote `main` after preserving its earlier local state in the stash
`Preserve pre-sync Windows checkout 2026-10-27`; `feat/native-construct` remains intact. No compiler semantics,
canonical compiler state, replacement levels or bootstrap milestone claims were changed.

`docs/proposals/native-windows-workspace.md` records the native-only construction/seed gap and the smallest
host-independent verified-candidate/query requirements. The recovered Windows compiler can edit/verify/build
small new graphs but declines the current driver store. Native `edit` output must be verified before a consumer
publishes it: an invalid add candidate was accepted as an edit output and then rejected by native verification.
The proposal is not an implemented contract. No interpreter bootstrap or other-language replacement was added.

### Windows x86-64 R2 — 2026-10-05 (ADR-170)

- `xax_platform.win32_thread_api()` owns the bounded thread package: Win64 code-entry type, linear thread-handle resource, `CreateThread`, `WaitForSingleObject`, `GetExitCodeThread`, and `CloseHandle`.
- `win64-c` foreign entries are direct function addresses because the XAX Windows convention is already Win64. Keep them pure: proof parameters/results reject.
- Reproduce current evidence from `compiler/` with `PYTHONPATH=src:. python -m benchmarks.bench_windows_pe_hosted`; the thread artifact must exit 39 and the hosted fixture 1339.
- Next Windows work: file I/O plus a practical application for R3, then a Windows-host C + non-C runtime-bound comparison. PE exports, unwind/PDB/TLS, sockets, and float/aggregate allocator convergence remain open.

## Replacement levels and performance

### Replacement levels v3 — 2026-10-08 (ADR-207)

R4 = leadership (≤ 0.9999× the fastest non-XAX median, significant); R5 = autonomous maintenance; R6 = XAX-only application. JVM is R4, Android is R3. Next task is U2 (`XAX_IMPLEMENTATION_ROADMAP.md`): re-run the Linux workloads with raw samples (U2.1), then optimize toward ≤ 0.9999× (U2.2), then the Android re-run with a Kotlin arm (U2.3). Items in "Exact next task" that cite the 1.05× target are superseded by this section.

### Linux R4 progress — 2026-10-08 (ADR-208)

`filestat` and `jsonmin` lead clang (0.882x, 0.968x); `chains` ties rustc (0.984x, not significant), so Linux stays R3. Next for R4: `chains` (look at the walk loop: `found + 1` is recomputed every step, extra moves; memory latency dominates), then the Android re-run with a Kotlin arm (U2.3). Profile with `valgrind --tool=callgrind --dump-instr=yes` on the image; XAX images have no symbols, so group costs by address.

### R5 record — 2026-10-08 (ADR-209)

JVM is R5 for one cycle (`benchmarks.bench_r5_maintenance`). Next for R5 breadth: a structural edit (insert/delete nodes) and an interface change maintained the same way, and a second platform row (Linux x86-64 `jsonmin` after its R4). Next level: R6 (U2.5), a complete application whose logic, tests, and build definitions are all XAX.

### R6 groundwork — 2026-10-08 (ADR-210)

New applications are created with `xax_construct.construct` (one request) and then changed only through workspace transactions on the committed store. `xb64` is the first; rerun its record with `python -m benchmarks.bench_r6_xb64`. For an R6 row, the row also needs R4 and R5: Linux needs `chains` to lead; the JVM has R5 but no XAX-only application (the carrier has only the Linux platform surface).

### Linux R4 — 2026-10-08 (ADR-212)

Linux x86-64 is R4 (§15.33). Next for this row: an R5 maintenance record (`benchmarks.bench_r5_maintenance` is JVM-only; add a Linux variant with a before/after benchmark), after which `xb64` (R6 evidence, ADR-210) can lift it to R6. Keep `jsonmin`'s margin in view: re-run all three after any backend change and report the result whatever it is.

### Linux R6 — 2026-10-08 (ADR-213)

Linux x86-64 is R6 on the validator's rules. What would make it robust: R4 re-runs on another host (`jsonmin`'s margin is small), a maintenance cycle with a structural edit, and an XAX-only application larger than `xb64`, ideally built by an independent agent.

### Universal-replacement upgrade — 2026-10-02

- Normative: `XAX_SPEC.md` §21 (replacement definition, R0–R6, evidence labels, kernel admission rule, model lowerings, platform classes, containers, foreign import, libraries, observability) and explicit document precedence in §1. ADR-074–ADR-078; OI-32–OI-36; `XAX_CONFORMANCE.md` §22; `XAX_BENCHMARKS.md` §15; roadmap U1; architecture v0.2 (§35–§47).
- `XAX_REPLACEMENT_MATRIX.json` is machine-checked: `compiler/src/xax_replacement.py` derives each row's level from cited evidence; `tests/test_replacement_matrix.py` rejects overclaims. Update a row only with an existing evidence path.
- U1.2a EXECUTED: x86-64 heap views (checked dynamic heap array round trip; OOB traps). U1.4 WASI EXECUTED under Node (`wasi_command_evidence.json`). ADR-079 (pointer-free memory frontiers), ADR-080 (WASI), OI-37 (pointers in memory).
- U1.1 EXECUTED: direct PE32+ hosted executable with kernel32 imports (`xax_pe.py`, target `x86_64-windows-pe-v1`, `xax_platform.win32_kernel32_api`, evidence `compiler/benchmarks/windows_pe_hosted_evidence.json`). Process exit must be an explicit `ExitProcess` call.
- U1.3 EXECUTED/MEASURED on Linux x86-64 (ADR-084–ADR-089, OI-38–OI-40, conformance §22 item 11, benchmarks §15.1). It adds integer completion (operations 67–72), `linux-x86_64-syscall-v1`, `sysv-x86_64-c`, and static plus explicit-loader ELF64 executables (`xax_linux.py`, `xax_elf.py`) whose entry is the XAX entry function with an explicit `exit_group`. A separate Linux register allocator (`xax_x86_64_regalloc.py`) is differentially validated. The `filestat` workload (`compiler/benchmarks/linux_filestat.py`) runs at 0.95–1.14× `gcc -O2` and 1.41–1.82× `clang -O2`, with a 3,560-byte artifact; the Linux row is at R2.

### Multi-language performance rule and x86-64 optimization — 2026-10-03 (ADR-147, ADR-148)

- Rule (`XAX_BENCHMARKS.md` §15.0): every CPU/native runtime comparison includes optimized C/C++ and an implementation outside C/C++ (Rust twins in `compiler/benchmarks/rust_twins/`); XAX meets the target at ≤ 1.05× the fastest valid median. The Linux harness interleaves rounds with a rotating arm order and records `time_ratio_vs_fastest` / `performance_class`. The matrix validator rejects a competitive verdict whose results lack either.
- Result (§15.14): `filestat` 1.017× (clang fastest), `chains` XAX `soa` arm fastest, `jsonmin` 1.029× (clang fastest). Linux x86-64 row is R4 within that scope.
- Compiler: range facts with edge refinement, widening, and narrowing remove proven checks; SIB-scale and RMW folding; compare-with-memory; value and branch bit tests; loop pass-through slots; hoisted wide constants; callee-saved registers across calls (SysV saves rbx/rbp/r12–r15 only); lowering view `xax_inline.py` (leaf inlining, merging, jump threading, pack and store-truncation folding, DCE, innermost-loop-first layout).
- Environment for the full suite (this container): `pip install unicorn pytest pytest-xdist vulkan setuptools`; apt `qemu-user qemu-user-static qemu-system-arm gcc-aarch64-linux-gnu libc6-dev-arm64-cross spirv-tools glslang-tools mesa-vulkan-drivers libvulkan1 wine64 mingw-w64 busybox zlib1g-dev e2fsprogs unzip`; arm64 `libz.so.1` copied into `/usr/aarch64-linux-gnu/lib`; `python compiler/integration/android/make_android_root.py` for `/opt/android`; Rust via rustup. Run with `PYTHONPATH=src:.:..` from `compiler/`: 1,059 passed, 4 skipped (Windows host and physical Android device only). Debian's patched setuptools fails the wheel test; install `setuptools` with `pip install -U --ignore-installed setuptools wheel`.

### Universal-replacement continuation — 2026-10-02 (ADR-102, ADR-103)

- ADR-102: C can call pure XAX functions. The calling convention is part of the code-address type, and x86-64 generates a 20-byte SysV adapter for each such function. `sysv-x86_64-c` imports now take and return SSE-class scalars. EXECUTED with libc `tsearch`/`tfind` and libm. OI-40 remains open for aggregates, stack arguments, and variadics; OI-42 opened for effectful callbacks.
- ADR-103/104: the browser target with generated host pages and XAX click entries. EXECUTED in headless Chromium; the browser row is at R2. OI-43 opened and closed.
- Host: Linux x86-64 with gcc, clang, node 22, and Playwright Chromium. No Wine and no QEMU, so PE and AArch64 rows could not be re-executed here.
- Regression: identical failure set before and after (2 failures and 27 errors, all host or dependency bound: no pytest, Windows/Wine, or wheel build).

### Linux AArch64 — 2026-10-03 (ADR-123)

- `xax_linux_aarch64.py`: `aarch64-linux-elf-exec-v1`/`-dynexec-v1`, syscall and C-import thunks, `e_entry` stub. `benchmarks.linux_filestat.build_filestat_program("aarch64")` builds the same graph for it. Host setup: `apt-get install qemu-user gcc-aarch64-linux-gnu libc6-dev-arm64-cross`; for `filestat`, copy an arm64 `libz.so.1` (Ubuntu ports `zlib1g_*_arm64.deb`) into `/usr/aarch64-linux-gnu/lib/`.
- Fixed duplicate `_cset` in `xax_aarch64.py` (frame-path compares were wrong). Frame slots are liveness-shared only on the Linux identities; extending this to Android/bare metal changes committed artifacts and needs their evidence re-run.
- Next for this row: AArch64 register path for memory, logic, and division (the 6.6×), then a hardware run (OI-44).

### jsonmin — 2026-10-03 (ADR-126)

- `benchmarks/jsonmin.py` builds the program (`build_jsonmin(arch)`), states the contract (`reference_jsonmin`), and measures it (`python -m benchmarks.jsonmin --write`). `src/xax_structured.py` is the construction helper; call `drop()` on a linear token a node consumes, or it rides later edges twice (`RESOURCE-LINEAR-CONTINUATION`).
- To reach R4: keep parser state in registers instead of the context view (pass position and output length as scalars and return them packed), prune dead names at joins in `Proc`, and read straight into the input view (a `pointer_rebase` window instead of the chunk copy).

### C header import — 2026-10-03 (ADR-127)

- `import_c_functions(headers, soname, names, abi=..., overrides={...}, flags=[...])`; use `.function(name).inputs/.outputs` for node types and `.objects` for the store. POSIX names need `flags=["-D_GNU_SOURCE"]` (the importer parses as C11).
- Next: by-value struct ABI classification (OI-40) to import struct returns; typed argument packs for variadics; an executed program over the Android classfile importer (closes OI-32 together with the token comparison).

### Static linking — 2026-10-03 (ADR-129)

- `compile_board_image(..., objects=[...])`; compile C with `benchmarks.board_linked_c.CFLAGS` (`-fno-pic -fno-common -ffreestanding -fno-asynchronous-unwind-tables`).
- Next: archive member selection, x86-64 relocations so Linux static profiles can link C, and calls from linked C back into XAX (code-entry addresses through `externals`).

### Next steps: benchmarks below the 1.05× target — 2026-10-05

Every current result (superseded sections excluded) with XAX above 1.05× the fastest valid arm. Time misses come first, then size misses. Each item is a next step: profile, optimize, and rerun the full comparison (§15.0), without changing the workload or dropping a faster competitor.

**Run time (or its emulated proxy):**
1. **RISC-V RV64IM, `sum_to`** (§15.9, `riscv64_twin_evidence.json`): 1,216× clang `-O2` emulated instructions (17,030 vs 14). Clang turns the loop into a closed form; XAX runs it.
2. **AArch64 Linux `filestat`** (§15.10, `linux_aarch64_filestat_evidence.json`): 7.18× `aarch64-linux-gnu-gcc -O2` qemu wall time (0.513 vs 0.072 s). The frame path keeps every value in memory; the register path (ADR-110) does not cover this workload. *Done (ADR-168, §15.20): now the fastest arm, at 0.767× gcc and 0.924× clang.*
3. **SPIR-V Collatz** (§15.11, `spirv_compute_evidence.json`): 6.88× glslang dispatch time on llvmpipe (74.3 vs 10.8 ms). The dispatch-loop lowering blocks vectorization; structured lowering of reducible CFGs is next.
4. **RISC-V RV64IM, `collatz`** (§15.9): 3.72× clang `-O2` emulated instructions. No compare/branch fusion or copy coalescing yet.
5. **JVM direct emission vs the native-bridge arm** (§15.19, `jvm_strategies_evidence.json`): XAX's own native-plus-JNI arm runs `jsonmin` in 0.68× the direct class's process time, so the direct arm is 1.47× it. Direct emission still beats `javac` (0.90×) and `kotlinc`. The gap is the 256 MiB entry thread and HotSpot interpreting before JIT. This is an XAX-vs-XAX comparison, outside §15.0a's `javac`/`kotlinc` baselines.

Items 1–4 are emulated or software-device results. They are not hardware performance evidence (§23.17), but they are the gaps those backends must close before a hardware run.

**Code size:**
6. **RISC-V code bytes** (§15.9): `sum_to` 2.93×, `collatz` 3.23× clang `-O2`.
7. **Windows PE executable bytes** (§15.6, `windows_pe_c_wine_evidence.json`): 1.82× MinGW-w64 `-O2` (757 vs 416). gcc inlines and constant-folds `sum_to(10)` and the dispatch table; XAX does that work at run time. Wall time under Wine is 1.006×, but it is start-up bound.
8. **SPIR-V module bytes** (§15.11): 1.81× glslang (3,132 vs 1,732).
9. **JVM `jsonmin` program class** (§15.18): 1.49× `javac` (5,575 vs 3,730 bytes). It is 0.99× `kotlinc`. The rest of the gap is the program's shape: an inlined parser, packed results, and a checked view per access.
10. **Android native callbacks** (§15.15): `xaxOnCreate` 1.33× and `xaxOnClick` 1.27× the NDK twin (128/168 vs 96/132 bytes). *Done (ADR-169, §15.21): 96/128 vs 96/132 bytes.*
11. **Android DEX bytes**: counter app 1.19× (§15.15) and minimal Activity 1.17× (§15.7), from one DEX per class, an edit-locality choice.
12. **Linux x86-64 `jsonmin` artifact** (§15.14): 1.07× clang `-O2`'s stripped dynamic binary (15,631 vs 14,552 bytes). It is static, with no libc. Time meets the target (1.029×).

**Not yet measurable against a baseline** (unknown, not passing):
- WebAssembly, WASI, and the browser: no Emscripten/Rust/wasi-sdk run.
- Android start-up and memory: *done on Pixel 8 Pro (ADR-172, §15.23); XAX is 1.016× the Java + NDK twin's cold-start median with lower median PSS.*
- Windows: no run-time-bound comparison on a Windows host.
- .NET, Apple, RTOS/MCU, and BSD: no container yet.

**Within 1.05×, for reference:**
- Linux x86-64: `filestat` 1.017×, `chains` 1.000×, `jsonmin` 1.029× (§15.14).
- JVM: `jsonmin` 1.000× vs `javac`/`kotlinc` (§15.18) and Collatz 0.91× `javac`.
- Android arm64: counter cold start 1.016× Java + NDK, with 0.995× median PSS (§15.23).

`chains`' other XAX link representations are slower: record links 1.185×, `pointer_rebase` 1.639×, checked index 2.119×. They are alternative encodings; the struct-of-arrays arm is the one that meets the target.

### Shared edit grammar (2026-10-08, ADR-200)

The per-request edit-form help is now optional in the normal protocol. `edit_grammar()` is the complete, request-independent carrier grammar, and `edit_grammar_id()` is its identity. A client sends the grammar once as shared context, and `session.instructions(shared=ID)` then adds nothing per request. A stale ID rejects, and acceptance rules don't change. The protocol is specified in `docs/09_AI_PROTOCOL.md`.

The full grammar is about 1 KB, larger than the filtered help; it pays off when a client keeps one session for several requests or caches its context.

### Linux AArch64 R5 and R6 — 2026-10-10 (ADR-258)

- `python -m benchmarks.bench_r5_maintenance --row=linux-aarch64 --write` needs one AArch64 device on `adb` (`ANDROID_SERIAL` with several), `XAX_AARCH64_ADB=1`, and `ANDROID_NDK_HOME` (status helper and `runner.c`); about one minute. The default pin (`XAX_JSONMIN_CPU_MASK=100`) is a Pixel 8 Pro core.
- `python -m benchmarks.bench_r6_xcksum --write` deploys to every attached device whose `uname -m` is `aarch64` (or `XAX_R6_SERIALS`); about 25 seconds for two phones. The oracle is the device's toybox `cksum`.
- Put the SDK `platform-tools` directory on `PATH`; the harnesses call `adb` by name.
- XAX-MCP (`compat.py`) should learn host contract minor 7 (`linux-aarch64` construct platform).

## Other targets

### SPIR-V / Vulkan — 2026-10-03 (ADR-124)

- `xax_spirv.py` (compiler + `run_spirv_kernel` harness + `reference_dispatch`), kernels in `benchmarks/spirv_kernels.py`. Host setup: `apt-get install mesa-vulkan-drivers libvulkan1 spirv-tools glslang-tools` and `pip install vulkan`. Keep nested Vulkan create-info structs in named variables: inline temporaries in the bindings dangle (`VK_ERROR_UNKNOWN` at pipeline creation).
- Next: structured lowering for reducible CFGs (the 6.9×), floats, then an XAX host program that drives Vulkan through `sysv-x86_64-c` imports (R2), then a physical GPU (OI-34).

### Board packages — 2026-10-03 (ADR-128)

- `xax_board.py` (package, image, `run_board_image`), workload `benchmarks/aarch64_virt_board.py`. Host: `apt-get install qemu-system-arm`; QEMU needs `-net none` (no EFI ROMs installed).
- Next: static storage shared between handler and reset (a board RAM region as a declared heap view), linking foreign objects (R2), a second board (RISC-V `virt` needs RISC-V memory operations first), DMA with the OI-07 states.

## Compiler engineering

### Host integration contracts — 2026-10-08 (ADR-222 to ADR-225)

- `xax_native.verify_component_store` memoizes component-store verification in `XAX_NATIVE_CACHE`. Set `XAX_NATIVE_REVERIFY=1` when evidence must show the verifier running on component stores.
- `xax_construct` accepts `linux.startup.*`. `xax_linux.process_contract()` and `xax_contract` are the versioned host surface: when one of their names or clauses changes, bump `HOST_CONTRACT_MINOR` or the identity, and tell XAX-MCP (`MrxSiN/XAX-MCP`, `src/xax_mcp/compat.py`).
- Wide checked loads on byte views (proposal P4 from XAX-MCP) are not implemented: they would change the checked-access rule in the verifier, the XAX-hosted typing program, and every backend, which needs its own decision.

### Lazily zeroed component views — 2026-10-09 (ADR-248)

- Allocate any view of 1 MiB or more with `xax_native.zeroed_array(element, count)`, never `(element * count)()`; keep the returned array (it owns its mapping). Contents start zero and are never re-zeroed between calls, exactly as before.

### One-call BLAKE3 up to 16 MiB — 2026-10-09 (ADR-249)

- Regenerate the hash store with `XAX_BLAKE3_PYTHON_HASH=1 PYTHONPATH=src python -c "import xax_selfhost_blake3 as m; m.write_hash_store()"`: the running hash image was lowered for the old extent and traps on larger inputs, so build it on the Python driver.
- When only one helper store changes, `PYTHONPATH=src python benchmarks/refresh_selfhost_store.py <module> --write` re-executes that program's entries in both self-hosting evidence files.

### Fast first start: `xax_native.prepare` — 2026-10-09 (ADR-250)

- Hosts: call `xax_native.prepare(parallel=True)` once (install or start-up) before the first verification; it returns per-component status and timings and never raises on fallback. Sequential `prepare()` loads the components into the calling process instead.
- A new XAX-hosted component that verification loads goes into `PREPARE_COMPONENTS`, `_load_component`, `_STORE_NAMES`, and a stage in `_PREPARE_STAGES` (give it an opt-out in `_PREPARE_OPT_OUTS` if other components could load it while being lowered).
- Write cache files only with `xax_native.cache_write`.

### Compiler fast paths — 2026-10-02

- Fixed import-time `NameError` (`AARCH64_GENERAL_OPERATIONS` referenced `Operation` before definition) that broke every import of `xax_compiler`.
- Wheel `py-modules` now includes `xax_android_components`, `xax_libxposed`, `xax_resources` (previously lazily imported but not packaged).
- Store/verify/lower/workspace fast paths; generated code and M14 evidence unchanged. Numbers: `XAX_BENCHMARKS.md` "Compiler-latency fast paths".
- Five identical backend `_resolver` copies replaced by `xax_compiler.store_resolver`.
- Pre-existing failures, not caused by this change (both reproduce on pre-edit bytecode): `test_stack_memory_executes_natively` pins a stale code SHA-256 (43-byte code still executes correctly); `test_float_descriptor_is_not_accepted_semantics` now rejects with `XAX.CANON.TRAILING_BYTES` instead of `XAX.TYPE.FORM` since float types became form 7. Four test modules import `pytest`, which is not installed here.
- Self-hosting reality check: the M14 hosted compiler is four XAX nodes orchestrating Python META primitives (verify, canonical store); all verification, lowering, encoding, and emission still execute in Python. No compiler functionality migrated to XAX in this pass.

### Native XAX compiler leaf — 2026-10-02

BLAKE3 compression is now the first real compiler hot path implemented as an ordinary XAX graph and run through the normal x86-64 lowering path. The canonical store is `compiler/bootstrap/xax_blake3_compress.xax` and its regeneration/loader is `compiler/src/xax_native_blake3.py`; `compiler/src/blake3.py` keeps the pure-Python leaf for bootstrap/fallback and lazily switches to the verified native XAX compressor on compatible x86-64 hosts. The graph has CID `f1744e682b2f99c542100f0e987dced9a87f40dfa4b8f173596fb24b78faa216`; emitted x86-64 code is 19,744 bytes with 806 semantic ranges. Evidence and timings are in `compiler/benchmarks/xax_native_blake3_evidence.json`. The current Linux execution shim is only a SysV-to-Win64 ABI adapter around the ordinary emitted image; no BLAKE3 logic lives in the shim.

### Recursion — 2026-10-03 (ADR-125)

- `group_member_function(group, k)` is the callable member identity; `parse_function_graph(function, resolve)` is the lowering view every backend now uses instead of `_parse_graph` for function bodies. New backends must use it too, or they will see raw `call.group_member` nodes.
- Next: wasm shadow stack for recursive frames; a workspace mutation that creates member functions; a verified stack-depth bound where a real-time profile asks for one.

### Membership selection — 2026-10-03 (ADR-131)

- `membership` in `xax_x86_64_regalloc.compile_register_resident`: an analysis next to `fused`, plus `_member_bit_test`. Next: the same selection on the AArch64 frame and register paths, two-word masks for spans up to 127 (the JSON escape set), and a profile of the remaining `jsonmin` gap.

### Byte-view widening — 2026-10-08 (ADR-231)

- The rule is in `_verify_memory_node` (`BYTE_ELEMENT_CID`, `CHECKED_BYTE_VIEW_WIDTHS` in `xax_compiler.py`) and mirrored in the facts engine's `_checked`. A backend that cannot do unaligned wide access sets `BYTE_VIEW_WIDENING = False` on its ISA class (views backends) and rejects in its Python lowering with the same text (`BYTE_VIEW_WIDTH_EXPECTED`).
- In the XAX views backend, `value_id` advances the stream cursor: read an operand's id once and keep it.

## N0 native-evolution bootstrap — 2026-11-05 (ADR-367, ADR-368)

Superseded by "N0 native-evolution bootstrap: N0.3 landed" below.

**Rule (ADR-367).** After N0, compiler logic is authored only as canonical XAX graphs through native XAX transactions.
Until N0 completes, only N0's own infrastructure may be generated. The generator worktree used for N0 is the pre-W2
tree (commit `8f2c9f4`) with the ledger fixes ported in; it reproduces the committed driver byte for byte (generator
output, then the baseline queries `inputs_limit` and `dead_constants` of the pre-W2 `xax_selfhost_evolution`). Records
are authored by pairing old and new generator output by function name and replacing references at the changed
functions' owners outside the generated set, never at the old versions' own graphs.

**Done.**
- N0.1/N0.2 (ledger 0004, seed `1e5868c9…`): `define @name` (a function in view form, then `end`) and
  `replace F<n> @name` in `xaxc edit` batches; records may name their own supplied objects by index
  (`SUPPLIED_MARK`); the engine puts supplied graphs' and functions' references in canonical order; the reach fix for a
  rebuilt object equal to a supplied one; the view is lossless. A structural change was authored, applied, verified,
  lowered and run with the seed alone (exit 41).
- N0.3 reference half (ADR-369, superseding ADR-368): `growable.load/store.bits.le` (77, 78), checked accesses with a
  `bits<64>` limit operand, in `reference/xax_compiler.py` and `XAX_SPEC.md`;
  `tests/test_xax_growable_views.py` (reference passes only: it switches the native graph decoder and typing off).

**Next (N0.3 native half), in the generator worktree, then one ledger transaction and a seed rotation.**
1. Graph decoder (`xax_selfhost_graph`): the operation flag sets come from `xax_compiler`; regenerating it with the
   new operations differs from the committed store only by them (unmodified generation reproduces it exactly).
2. Typing and facts (`xax_selfhost_typing`, `xax_selfhost_facts`): 77 and 78 handled as the checked accesses with the
   `bits<64>` limit operand after the offset (`MEMORY-GROWABLE-LIMIT-BITS`), the value and memory operands one later.
   No type form is involved (ADR-369).
3. Backends: x86-64 general (`xax_selfhost_general_regalloc`/`_emit`) and AArch64 (`xax_selfhost_aarch64_lower`/
   `_emit`): the checked access's static compare, plus `offset + size <= limit` against the limit register. Other
   targets reject.
4. Regenerate the stores in the generator worktree, author one ledger transaction, self-build, rotate the seed, and run
   `tests/test_xax_growable_views.py` with the native programs on, then the program natively (lower and run).

**Then.** N0.4: recursion-group rebuilds in the edit engine; the ledger keyed by XAX hashes so native tools record and
replay it; the completion demo (a natively authored change adding a function, a block, a changed signature and a
growable view; a self-rebuild with identical artifacts). After N0: the dynamic limits (the 64 MiB store family, the
fixed tables), P1, packed bytes and OI-52 R1 through the native workflow only, then BBC.

## N0 native-evolution bootstrap: N0.3 landed — 2026-11-05 (ADR-370, ADR-371)

Superseded by "N0 complete" below.

**Done since the section above.**
- Ledger 0005 (ADR-370): the store family's views hold 256 MiB (decoder data view, S9 writer input and output; writer
  buffer 512 MiB), and the edit batch is about 130 MiB. Seed `a5a33e89…` (32,986,843 bytes).
- Ledger 0006 (ADR-371): growable accesses in the facts program, its rendering, the verifier's and the views backends'
  graph parsers, and the x86-64 and AArch64 general backends (register and frame paths). Seed `b37b6cb4…`
  (33,138,571 bytes).
- Ledger 0007 (ADR-371): the Linux x86-64 and AArch64 targets list operations 77 and 78. It is a separate
  transaction because a target may list only operations the applying seed's verifier knows
  (`TARGET-OPERATIONS-CANONICAL`). Its request self-builds to the same seed bytes, so the seed stays.
- `tests/test_xax_growable_views.py` runs the reference and the XAX front end, and lowers and runs natively on
  x86-64 and on AArch64 (qemu).

**How the N0 records are made.** Set up the worktree as `compiler/bootstrap/evolution/n0/README.md` describes, change
the generators, and regenerate the affected stores. The driver is generator output followed by the `inputs_limit` and
`dead_constants` queries; the request is `compiler_request(driver)`. Then run
`n0/diff_record.py <committed store> <regenerated store> <record>` and apply each record with
`python -m xax_selfhost_evolution apply`. Before a full apply, probe one store with the seed's `xaxc edit` then
`xaxc verify`. After the stores change, `selfbuild.sh` must give xaxc1 = xaxc2; copy xaxc1 as the seed and update the
pins.

**Next.** N0.4: recursion-group rebuilds in the edit engine; the ledger keyed by XAX hashes, so that native tools record
and replay it; the completion demo (a natively authored change adding a function, a block, a changed signature and a
growable view; a self-rebuild with identical artifacts). The Android shared-object targets do not list the growable
operations yet. After N0: dynamic limits through growable views (replacing ADR-370's fixed reservations), P1, packed
bytes and OI-52 R1, through the native workflow only, then BBC.

## N0 complete: native evolution — 2026-11-05 (ADR-372)

**Done.**
- Native ledger tool: `compiler/bootstrap/evolution/evolve.sh` (`apply`, `replay`, `check`; sh, the seed, git).
- Ledger 0008: the assembler takes every `bits<64>` decimal.
- **Ledger 0009, the completion change**, written only as batch text. It adds a new function and two new blocks,
  changes the decoder's signature and its call sites, and makes the decoder's 166 data reads growable loads bounded by
  the store's own length. It was applied with `evolve.sh`, and the edited request was self-built without Python, with
  identical results (xaxc1 = xaxc2). Seed `7302550b…` (33,141,194 bytes).

**How to change the compiler now.**
1. `xaxc edit <store> <empty file> <list>` lists the functions; `xaxc edit <store> <file with F<n>> <view>` shows
   one. Each takes about a minute on the driver.
2. Write the batch: `R <root>`, `F<n>`, then `define @name … end` (view form; handles in order) and
   `replace F<n> @name`. Mechanical edits of a large view (renumbering after an insertion) may be done with `awk`, as
   in `compiler/bootstrap/evolution/n0/0009/`.
3. Probe: `xaxc edit <store> <batch> <out>` then `xaxc verify <out> <report>`. Then try `selfbuild.sh` on copies,
   because a store that verifies can still fail to build.
4. Record: `sh compiler/bootstrap/evolution/evolve.sh apply <batch> <store>`, once per store (driver, then the
   request with its own `R` line). Then `selfbuild.sh`, copy xaxc1 to the seed, and update `SEED_SHA256` and
   `SEED_SIZE`.

**The general backend's limits for the driver.** These decide whether a change builds:
- the register path takes at most four machine parameters per function and four machine inputs per call; anything
  larger falls to the frame path, which cannot lower main's startup reads;
- main is 632 values below `VCAP` (262,144), and leaf calls are inlined into their callers, so add no call to main
  that would be inlined.

**Next.** Through the native workflow only: dynamic limits (growable views in place of ADR-370's fixed
reservations), P1, packed bytes, OI-52 R1. Then BBC: rebuild its driver from the production driver, build bbc.exe
natively, and run the Android-first checks. Still open in the native workspace: recursion-group rebuilds,
`set-signature`, `move`, `prune-dead`.

## After N0: R1, the object form, and BBC's state — 2026-11-05 (ADR-373..375)

**Done (all native batch records, `evolve.sh`, C1 = C2, seed rotated each time).**
- Ledgers 0010, 0011, OI-52 R1. x86-64 checked bounds of 2^31 or more are materialized on the register path
  (`em_memory`) and the frame path (`fr_memory`, `fr_tail`). The authoring scripts are in
  `compiler/bootstrap/evolution/native/0010`, `0011`.
- Ledger 0012, `define`'s `object <kind> 0x<body>` form. Native batches can supply reference-free objects (foreign
  declarations). `@a_object` and its wrappers were written by hand in view form (`native/0012`).

**BBC (still not on the current driver).**
- *Finding: the committed `integration/bfx/bbc.xax` does not pass the production compiler's own `xaxc verify`.* It fails
  with `MEMORY-CHECKED-STORE-TYPE` in graph `1cedb119…`: 8-byte checked stores of `bits64` values through a
  `ptr<bits8>` (byte-view widening, ADR-231).
  - The reference verifier accepts the graph.
  - The native facts program implements widening only when the pointer value's element fact (`PEL`) is `bits8`. So
    the gap is in how the native analysis derives `PEL` for these pointer values (a cast or block-parameter
    provenance), not in the widening rule.
  - The stores staged in `transactions/production_driver/` show the same failure.
  - Fix that natively first: a facts transaction, plus a regression test with a widened store through such a pointer.
- *Port plan* (native only; the Python `port_driver.py`/`port_bbc.py` may not author it any more):
  1. Windows declarations become `object` forms. The shims (`_read`, `_write`, `_open`, `_close`) are written by hand
     with `define`, and the old port's adapters are defined from their views in `bbc.xax`.
  2. Main's host calls are rewritten in its view: about 100 sites, with result remapping and the token rebinding of the
     view adapters.
  3. Then the BBC layer, again defined from views.
- *Risk:* main is 632 values below `VCAP`, and shims small enough to be inlined (256 nodes or fewer) add values at
  every call site. Make the shims non-inlinable (more than 256 nodes, or calls inside them), or raise `VCAP` first.

## BBC on the native compiler: where it stands — 2026-11-06 (ADR-376)

- Ledger 0013 (ADR-376) closed OI-53. The general backend no longer fuses a compare into its branch when a later block
  reads it, so the self-built compiler's verifier is correct. `integration/bfx/bbc.xax` passes the production
  `xaxc verify`.
- **The native build of BBC's driver declines.** With a PE build request for `bbc.xax` (its module's entry and
  `x86_64-windows-pe-v1`), the seed's `resolve` succeeds and `build` declines (exit 2). A probe of the general
  program's state at the decline found:
  - the closure is complete (557 functions);
  - lowering stops in function `51514b76a3f3…` (object 2230). It is one of the driver's word-workspace helpers,
    `(bits64, view, view) -> (bits64, view, view)`, which returns three machine values;
  - the register path takes at most one machine result, so the function goes to the frame path;
  - on the Windows (PE) host the frame path's hosted subset declines it. On Linux the same helpers lower.
- **So `bbc.exe` needs this backend feature first:** the hosted (Win64) frame path must return several machine values
  (pointers with borrowed views) the way the Linux frame path does. It has to be a native transaction on the general
  backend's frame path (`frame_function` and its hosted allow-lists). Only after it does the BBC port (Windows
  declarations through `define`'s `object` form, main's ~100 host-call sites, the BBC layer) become buildable.
- The probe scripts (scratch) read output words 0, 1 (status, closure count) and 16.. (the order), then `G_RA` at
  `GLOBALS + 60` and its `E_F`, `R_NPARAMS`, `R_NRETURNS` and `R_ELIGIBLE` slots.
- *Superseded in part:* the decline's diagnosis is corrected in "BBC's PE decline found and fixed: frame-path heap
  views — 2026-11-06 (ADR-377)" below.

## BBC's PE decline found and fixed: frame-path heap views — 2026-11-06 (ADR-377)

- **The diagnosis above was wrong.** F162 (`51514b76…`) is where the probe found the program stopped, not the
  function that failed. On its own (an entry calling it with its real 512 MiB and 1 GiB views) it compiles on the
  register path.
- **Method:** the per-function records the program writes in audit mode. `general_object_table(..., audit=True)` and
  `rebuild_views` read each function's analysis and emission record even when the run declines. Functions 97 (F97 of
  the bbc listing: eleven parameters, three views) and 151 (F151: two views, a call returning an aggregate) had no
  emission. They are ineligible for the register path, and the frame path declined them. The program goes on after
  such a function with `I_OK` cleared, so the last `E_F` said nothing about them.
- **Cause:** `frame_function` made heap-view pointers first-class (`F_DYN`) only off Windows. **Ledger 0014** sets it
  on every target. It is one compare attribute, in three batches written from each store's own view. The seed
  rotated (xaxc1 = xaxc2). `tests/test_native_pe_frame_heap_views.py` runs such a helper under wine: exact sums,
  and a `ud2` trap past the extent.
- **Next wall for the committed `bbc.xax`:** F163 (`51b36b76…`, 2,498 calls). Its inlined view passes `VCAP`
  (2^18 values): `G_VCOUNT` reaches 262,144 inside `_view`, so the run stops before F163's emission record. That
  driver is the old Windows copy. The port of the production driver (whose main is 632 values below `VCAP`) is still
  the way to `bbc.exe`. `VCAP` is encoded in about a dozen functions of each store (as `VCAP`, `VCAP + 1`,
  `VCAP + 2`, `2 * VCAP` and `v + VCAP` offsets, among other uses of the same numbers). Raising it is a careful,
  broad transaction.
- **Main's host calls**, for the port. Production main (F280 of the pre-0014 driver) has 100 foreign calls:
  - `mmap` 22, `munmap` about 25 (one declaration per extent), `openat` 17, `close` 17, `write` 13, `read` 5;
  - `exit_group`, and the startup `argc` and `arg_copy`.
- **Known failing tests, both failing at the commit before 0014 too:**
  - `test_python_free_seed.py::test_the_record_decides_whether_the_seed_requires_python`. The Python-free seed
    evidence names an older request store; it is re-recorded with `benchmarks/bench_python_free_seed.py --write`.
  - `test_xax_selfhost_evolution.py::test_the_raised_input_bound`. `NativeGeneralDriver` compiles the driver with the
    Python-hosted x86-64 views backend program, which rejects it with `X86_64_VIEWS.UNSUPPORTED_OPERATION`. The
    likely cause is ledger 0009's growable accesses in the driver.

## Ledger 0015 and the self-hosting record — 2026-11-06 (ADR-378)

- **Ledger 0015.** `define`'s `object` form takes references (`object <kind> 0x<body> <CID>...`). Native batches can
  now supply pointer types, which BBC's Windows adapters need. The view is hand-written (`native/0015`), the seed
  rotated (xaxc1 = xaxc2), and `tests/test_native_object_references.py` covers it.
- **The Python-free seed record is re-measured** (`benchmarks/python_free_seed_evidence.json`, seed `33046fc4…`).
- **The derived bootstrap status now reads "its seed requires Python: yes".** That is the honest derivation:
  `seed_requires_python` also needs `full_selfhost_evidence.json` to name the same request store and compiler. That
  record dates from before ledger 0001, and the committed status text was stale.
  - The full record cannot be re-measured yet. Its C0 is the driver lowered by the x86-64 *views* backend program in
    a Python host (`NativeGeneralDriver`), and that program does not lower operation 77 (`growable.load.bits.le`).
    The driver has used it since ledger 0009 (`X86_64_VIEWS-OP-TARGET-SUPPORTED`, actual 77). This is also why
    `test_xax_selfhost_evolution.py::test_the_raised_input_bound` fails.
  - Either the views backend learns operations 77/78 (a native transaction on its store and the views target lists),
    or `bench_full_selfhost` takes the pinned seed as C0. Changing C0 changes what the record means, so that needs
    an ADR first.

## The production driver on Windows, natively — 2026-11-06

- **Done:** `compiler/integration/bfx/transactions/production_driver/native/` rebuilds the Windows-hosted production
  driver from the current production store with native transactions only:
  - a batch: supplied objects (ADR-378), BBC's six host adapters defined from their views, and the entry redefined
    from its view by `port_main.awk`;
  - a one-mutation XAXEDIT1 record that sets the PE target, with operations 77 and 78.
  The seed's `verify` accepts the result. `resolve` and `build` make `xaxc.exe` (33,202,176 bytes).
- **Evidence:** under wine, `xaxc.exe resolve` and `build` of the production compiler's request make the Linux seed
  byte for byte, in 5 minutes. `tests/test_bbc_windows_host_port.py` replays the port.
- **Next:** BBC's layer on top of it, from the ledger-0003 staged record's 36 functions.
  - The 32 that are not variants of main call only driver helpers that are unchanged since 0003, so they can be
    defined from their views with handles remapped by CID. The entry's call of the old main becomes the new main.
  - The four main variants (lazy views; the three `compile` steps) are derived from the new main with each variant's
    differences from the old ported main.
  - BBC's own declarations and types are supplied with `object`.
  - Then build `bbc.exe` and run BBC's checks under wine.

## BBC's driver on the production driver: ledgers 0016, 0017 — 2026-11-06 (ADR-379, ADR-380)

- **BBC's layer is ported natively.** `integration/bfx/transactions/production_driver/native/rebuild.sh` rebuilds
  BBC's driver from any production driver store with native transactions only:
  - the Windows host;
  - the PE target;
  - BBC's layer: 32 functions from portable batches, plus four driver entry variants through stubs.
  The result verifies (72.4 MB).
- **`build` first rejected it.** BBC's frame-path functions call helpers that give back borrowed views, and the frame
  path counted them as machine results. **Ledger 0016** elides them at frame-path call sites, through a hand-written
  `@cl_borrow`.
  - The first version had five machine parameters, so the pre-0016 seed's own frame path rejected it while building
    the compiler. It now takes the two counts in one word.
- **The build then ran for more than an hour.** Sampling the running program with gdb, and mapping the program
  counter through the views image's function offsets, found `cycle` inside next-iteration prefetch: cubic in the
  view's block count, and F811 inlines 1,782 calls. **Ledger 0017** skips prefetch for views of more than 4096
  blocks (ADR-380).
- Both ledgers: xaxc1 = xaxc2, the seed rotated, and the Python-free seed record re-measured.
- **Next:**
  - build `bbc.exe` from the rebuilt driver with the new seed;
  - run BBC's checks under wine and qemu-aarch64: a scratch harness compiles Brainfuck programs for both targets and
    compares each run with an interpreter;
  - replace `integration/bfx/bbc.xax` and record the evidence.
- **Update (same day):** after 0017, the seed's `build` of the rebuilt BBC driver (root `661b785b…`, from the
  post-0017 production driver) *declines* after 6 minutes.
  - The audit records show functions 0–541 emitted. Function 542 (`85b25a0f…`, a production-driver function) has
    none, though alone it compiles on PE.
  - The image state at the decline gives the cause: `I_LEN` = 33,529,728 bytes against `IMAGE_CAP` = 2^25
    (33,554,432), with 954 of 1,060 functions placed.
  - **BBC's program does not fit the general program's 32 MiB image buffer.** The production compiler alone is
    33.15 MB, and BBC adds its layer and four copies of the entry.
- **Next:** a capacity transaction on the general program's layout. The image buffer (`IMAGE_BUFFER_AT` 200M words,
  one byte per word), the image record (232M–252M words) and the container buffer (`I_ELF`, `IMAGE_CAP` + 64 KiB, in
  the arena) all assume 32 MiB, and the arena already reaches about 187M words on large builds. Options:
  - pack eight bytes per word in the image and container buffers;
  - or give the views 4 GiB.
  Making BBC's four entry variants smaller would only postpone it. (Done: see "The image buffer packed: ledger 0018 —
  2026-11-07".)

## The image buffer packed: ledger 0018 — 2026-11-07 (ADR-381)

- **Ledger 0018** packs the general backend's x86-64 image buffer eight bytes to a word and raises `IMAGE_CAP` to
  48 MiB; the container buffer and its cap follow (48 MiB + 64 KiB, still one byte per word, in the arena).
  - Ten functions, the same objects in the driver, the request and the x86-64 general program, read or write the
    buffer or size the container: 25 accesses become word read-modify-writes or word loads with a byte extract
    (`native/0018/pack.awk`, `sites.txt`, `view.sh`, `mkbatch.sh`; the README tells how).
  - Two batches per store. Replacing a function whose every caller the batch redefines, or `image_add` together with
    the main, left an old object unreachable or missing; batch A replaces only the main and reaches the rest through
    `@` references, batch B replaces `image_add`.
- The seed rebuilt itself: xaxc1 = xaxc2 = `8f9eb1e3…` (33,161,530 bytes), now the pinned seed; the Python-free seed
  record was re-measured.
- **Checks:** `tests/test_native_large_image.py` (new, about 30 minutes): about 36 MiB of code built with
  `frontend="xax"` is assembled by the XAX program and runs. Every `GeneralBuildTests` case gives the reference
  build's artifact, provenance and diagnostic with the new compiler as the driver, as with the old seed (run through a
  scratch shim that puts an `xaxc` executable in `NativeGeneralDriver`'s place; that class's own setup needs step D).
- **Next:** step B, BBC's `bbc.exe` from the rebuilt driver. If a build declines at the container buffer's allocation
  (the arena after the views), pack the container buffer too (ADR-381, Limits). (Done: see "BBC's `bbc.exe` built natively; C0 is the seed:
  ledger 0019 — 2026-11-07".)

## BBC's `bbc.exe` built natively; C0 is the seed: ledger 0019 — 2026-11-07 (ADR-382, ADR-383)

- **Step B, `bbc.exe` from the production driver.** `rebuild.sh` on the post-0019 production driver gives
  `bbc.xax` root `1a582526…` (72.3 MB, verified), and the seed builds `bbc.exe` in under 4 minutes. Three walls:
  - **`VCAP`:** BBC's compile front (`51b36b76…`) inlined 2,434 leaf calls past 2^18 values. **Ledger 0019**
    (ADR-383) inlines only while a view has at most 2^17 values (`native/0019`). xaxc1 ≠ xaxc2 (the compiler's own
    largest functions keep some calls); xaxc2 = xaxc3 = `a9995432…` is the seed.
  - **A stale layer:** the port's layer came from an older `bbc.xax`, so every compile's edit step was rejected
    (`WORKSPACE-EXPECTED-ROOT`, the host request of 2026-10-21). `layer.sh` now takes the layer from the committed
    `bbc.xax`.
  - **The steps' argument counts:** resolve saw edit's `argc` (5 for 4). The step variants now call their own
    count, as the old store did.
  - Diagnosing: wine's relay log (`WINEDEBUG=+relay`, the bbc.exe thread's `ret=14…` calls) shows each step's
    file I/O; `bbc bind` gives the edit record, and the Linux seed replays edit, resolve and build on it.
- **Step C.** `integration/bfx/bbc.xax` is the rebuilt store; evidence
  `integration/bfx/production_driver_evidence.json`; `COMPILE.md` has a dated section.
  - `tools/check.py`: 93 programs, 370 of 372 compiles, 486 runs, no mismatch; error paths 1, 4, 4, 3, 3 with no
    leftovers. `deep512active` declines on android-arm64 in the AArch64 general program (the seed's own build
    declines too).
  - Mandelbrot -O0 and hanoi -O1 (declined on 2026-11-05) build and run; hanoi -O0 still declines.
  - `tools/bench.py` recorded build and run samples for six baseline programs. It is not an A/B run against the
    old `bbc.exe`, which was not rebuilt.
  - Capture wine output in files, not pipes: a wineserver a captured run starts inherits the pipe.
- **Step D (ADR-382).** C0 of `bench_full_selfhost` is the pinned seed: neither the views profile nor the Python
  reference lowers operation 77. `NativeGeneralDriver()` runs the seed, so the classes built on it run again.
  - The bench now reads native batch records, keeps the corpus rows apart from the replay rows, and chains a replay
    through a store git lacks (0018's two batches per store), as `evolve.sh replay` now does.
  - **Result:** `full_selfhost_evidence.json` re-recorded with `XAX_REQUIRE_NATIVE=1` (95 minutes): C1 = C2 = C3 =
    the seed, every snapshot the Python resolver's, 198 corpus cases agreeing, 66 ledger transactions replayed and
    verified by C1. The derived status: **B0–B6 hold and the seed requires no Python.**
  - Fixed with it: `test_the_record_decides_whether_the_seed_requires_python`, `test_the_raised_input_bound`, the
    capacity test (256 MiB views since ledger 0005), the fixed-point test (C1 now equals C0), and the status test's
    v1 replay checks.
- BBC's docs (`docs/25_NATIVE_COMPILE.md`, `docs/05_STATUS.md`, `docs/08_BENCHMARKS.md`) and a new evidence report
  follow on BBC's branch.
- **Next:** the AArch64 decline of `deep512active` and hanoi -O0; Windows-native and Pixel runs of the new
  artifacts; an A/B benchmark against the old `bbc.exe`; step E.
- *Followed by:* "Deep nesting on AArch64, the old-vs-new benchmark and hanoi -O0's limits: ledger 0020 —
  2026-11-07" below.

## Deep nesting on AArch64, the old-vs-new benchmark and hanoi -O0's limits: ledger 0020 — 2026-11-07 (ADR-384)

- **`deep512active` on Android ARM64.** Python-hosted, the native AArch64 program took 2,187 s on its snapshot and
  then declined. gdb sampling with the image's function offsets put all 40 samples in `_aliases` (`adc7c672…`): every
  round scanned every edge argument for every block parameter. Probing the stop state (arena cursor at `HEADER + 12`)
  showed the decline: `_intervals` (`0952bb79…`) asked for a blocks × values range pool, 228.7 M words, past the
  arena's end. **Ledger 0020** (`native/0020`, four stores: the driver, the request, `xax_aarch64_general.xax`,
  `xax_android.xax`) lists each parameter's incoming arguments once and sizes the pool from liveness
  (`@pool_bound`). The program builds the snapshot in 16 s. The request store equals `compiler_request` of the driver;
  the seed's build is xaxc1 = xaxc2 = `439ddb0d…` (31,543,498 bytes), the new seed. Both seed records re-recorded.
- **BBC rebuilt.** `rebuild.sh` from the new production driver (23 min 41 s; root `560978…`, 72.3 MB, verified),
  `bbc.exe` by the new seed (5 min 12 s, 35,964,416 bytes). `tools/check.py`: **372 of 372 compiles**, 488 runs, no
  mismatch, error paths 1, 4, 4, 3, 3; the campaign takes 4 min 50 s. `deep512active` builds on android-arm64 (3.5 s
  / 6.9 s), `deep512`'s Android compile falls from 122 s to 0.5–0.7 s. Evidence:
  `integration/bfx/production_driver_0020_evidence.json` (BBC: `evidence/production_driver_0020_2026-11-07.json`).
- **Old vs new `bbc.exe`.** The old one was rebuilt from `bbc.xax` at `6417125` with the documented generic-SDK
  recipes (16,007,680 bytes, not byte-identical to the baseline's `83404a20…`); `tools/bench.py` now takes several
  arms and interleaves them. Where both build, the executables are byte-identical; the new `bbc.exe` builds 1.0–1.8×
  slower; mandelbrot -O0 and hanoi -O1 build only with the new one (BBC: `evidence/old_new_benchmark_2026-11-07.json`,
  `docs/08_BENCHMARKS.md`).
- **hanoi -O0's limits.** Its decision graph is one 7.25 MB object (53,884 instructions; factor's O0 graph is 0.46 MB
  for 3,878). The seed's own `verify` and `edit` decline the request store (exit 2): the graph decoder's body view is
  4 MiB (`heap_view<4194304>` in `decode`'s signature and three `heap.view` buffers of the driver's main). Scaled from
  factor, the view would hold about 54,000 blocks and 620,000 values, past `VCAP` (2^18); on AArch64 its liveness bit
  sets alone (blocks × values / 64 words) would exceed the arena.
- **Device runs:** still BLOCKED; no computer is connected to this session.

## Open issues

### OI-45 self-hosting re-runs — 2026-10-07

- Done on Linux x86-64: `selfhost_closure_evidence.json` and `selfhost_x86_64_evidence.json` were regenerated under `XAX_REQUIRE_NATIVE=1`; no `native_rerun_required` entry is left. Native self-hosting tests pass: 97, plus 7 with `XAX_FIXED_POINT=1`.
- Still open in OI-45: the Linux and Android R4 re-measurements.
- Run evidence generators from a clean worktree at the revision you are recording. The closure generator takes about 22 minutes here.
- Cold-cache fix: with an empty `XAX_NATIVE_CACHE`, `XAX_REQUIRE_NATIVE=1` used to fail. Images made while the BLAKE3 hash, the store decoder, or the graph decoder is being built cannot be lowered by the XAX backend, because it reads graph-decoder streams. `host_image` now records them as Python lowering by design (`requested_authority: python`), like the backend's own image (`_bootstrap_order`). Earlier warm-cache evidence is unaffected: the cache key does not depend on which generator lowered an image, and gen1 equals the bootstrap reference byte for byte.

## Documentation and process

### Standard libraries — 2026-10-03 (ADR-130)

- `text_package(extent)` and `hashset_package(capacity)` return a `Library`: index it by export name for the function to call, and pass `.objects` to `program_store`. The application lives in `benchmarks/uniqcount.py`, and `python -m benchmarks.bench_oi36_stdlib` regenerates the evidence.
- Next: more families (arena allocator, growable vector over a caller-provided arena, UTF-8 validation), multi-value returns on native backends (removes span packing), and a versioning policy.

### Evidence and canonical-state integrity, EI — 2026-10-06 (ADR-177)

- Start S7b from this baseline. Summary in `XAX_STATE.md`; evidence `compiler/benchmarks/audit_remediation_evidence.json` (`python -m benchmarks.bench_audit_remediation --write` from `compiler`, about 6 minutes with the suite).
- First job on a Linux x86-64 host (OI-45): `PYTHONPATH=src python benchmarks/bench_selfhost_closure.py --write` and `benchmarks/bench_selfhost_x86_64.py --write` (they set `XAX_REQUIRE_NATIVE=1`), then the native self-hosting tests. Without Linux, `--bind-committed` refreshes only the host-independent fields and marks changed stores `native_rerun_required`.
- New modules and tests: `src/xax_native.py` (authority, W^X, cache, `bootstrap_dir`), `tests/test_store_regeneration.py`, `tests/test_audit_remediation.py`, `tests/test_wheel_install.py`, `tests/test_hosted_build_provenance.py`.
- Windows host: run tests with `PYTHONPATH=src;.;..` (semicolons). Skips are environment-only; none hides a failure.

## Ledger 0022: constant folding and hoisted registers on x86-64 (2026-11-08)

- The x86-64 register lowering's `basics` folds single-result `add.wrap`/`sub.wrap`/`mul.wrap`/`int.truncate`/
  `int.zero.extend` nodes over constants (widths 8/16/32/64) into constants and erases them; the emit function now
  saves the callee-saved register of every hoisted wide constant (a latent fault the fold exposed). ADR-388,
  `compiler/bootstrap/evolution/native/0022`.
- The first application of the fold alone (`d37ec08`) built a self-consistent but wrong compiler and was reverted
  (`bbeb04e`); the cause was found by bisection. With both changes, the previous code generator's build of the
  compiler and its own build agree byte for byte on `build`, `resolve` and `verify`.
- Seed `510a794a…` (31,887,691 bytes); B0–B6 re-recorded (`full_selfhost_evidence.json`,
  `python_free_seed_evidence.json`).
- BBC: `bbc.xax` rebuilt (root `4026acc5…`), `bbc.exe` 36,302,848 bytes, 372 of 372 compiles and 488 runs pass
  (`integration/bfx/production_driver_0022_evidence.json`). Under Wine, mandelbrot 1,147 ms (was 1,635 the day
  before; brainfry's Windows output 1,250 in the same run). No rulebook win (build time, no device runs).
- Open: hanoi -O0 (ADR-387, ledger 0021 prepared); the AArch64 backends have no fold yet.

## BBC's importer bounds branch, the capacity word (ledger 0023) and the plan completed — 2026-11-08

Supersedes the ledger-0022 section above for BBC's current driver.
- **BBC's importer** (ADR-389) writes each ADD/MUL as a bounds branch and an access block; an x86-64 ADD is 8
  instructions instead of 15. Under Wine: mandelbrot 1,198 → 1,092 ms, factor 63 → 60, life 50 → 46
  (`integration/bfx/importer_split_evidence.json`). The same constant fold for AArch64 measured no gain under qemu
  and stays a prototype (`native/0023-prototype`).
- **Fewer block parameters rejected** (ADR-390): the decision's pass-through views must travel with their effects
  (`HEAP-VIEW-RETURN-WHOLE`), so hanoi -O0 stays at about 620,000 values.
- **Ledger 0023** (ADR-391): the per-view value capacity is a workspace word (globals slot 170) set by the x86-64,
  AArch64 and JVM prologues to 262,144, read by the 18 functions that used `VCAP`. The compiler rebuilds itself and the
  previous seed's outputs byte for byte. Seed `a35fd59f…` (31,903,131 bytes); B0–B6 re-recorded.
- **BBC's driver** rebuilt after ledger 0023 (root `1e253130…`), 372 of 372 compiles, 488 runs, no mismatch
  (`integration/bfx/production_driver_0023_evidence.json`).
- **`XAX_CONTINUATION.md`** (the 2026-11-06 work plan, steps A–E) is complete and was removed; older sections that cite
  it refer to that plan.
- **Open:** OI-54 (hanoi -O0: the front-end regions, room for the tables, AArch64 liveness); device runs on Windows and
  a Pixel (BLOCKED: emulated hosts only).

## Independent audit: x86-64 signed compares below 32 bits (2026-11-11)

Does not supersede an earlier section. An independent audit of both repositories is recorded in
[`docs/audits/2026-11-11-independent-audit.md`](docs/audits/2026-11-11-independent-audit.md).

- **Defect found and fixed in the reference** (ADR-392): the Python x86-64 general backend compared `bits<N>`, N < 32,
  as 32-bit values, so the four signed predicates were wrong. The frame path now sign-corrects them and the register
  allocator leaves such functions to it. `tests/test_x86_64_narrow_signed_compare.py` checks every predicate at six
  widths against the reference executor (EXECUTED on Windows x86-64).
- **Native compilers unchanged** (OI-55, OPEN): the Windows seed reproduces the defect; the Linux production compiler
  was not run on the audit host and is expected to share it. No committed store contains such a compare.
- **Agent instructions**: `AGENT.md` and `CLAUDE.md` gained a shared engineering-principles section and are now
  byte-identical, checked by `tests/test_agent_instructions.py` (`AGENT.md` had lacked the seed-rotation rule).
- **Not run on the audit host** (Windows, no Linux): the ledger tools, self-hosting evidence and every
  `XAX_REQUIRE_NATIVE=1` test. No R level, B level or performance figure changed.

## Android R4 re-measured, ledger 0025 and the Windows stack probe — 2026-11-11 (ADR-394)

Built on ledger 0024 (the x86-64 signed-compare fix, commit `8d83f98`).

- **Android R4: FAIL, unchanged.** The counter was re-measured on the Pixel 8 Pro against the Java + NDK, Java and
  Kotlin twins (`XAX_BENCHMARKS.md` §15.37): medians 168 / 166 / 167 / 162 ms, no arm significantly faster. An
  `atrace` breakdown puts everything an arm's own code can touch inside about 7 ms of 150, the same on every arm. The
  benchmark is framework-bound; the row needs a workload whose time is generated code before a compiler change can
  show.
- **Ledger 0025** (ADR-394, `bootstrap/evolution/native/0025`): the AArch64 register lowering no longer runs the
  copies of an edge that leaves a loop before the test. BBC's mandelbrot on the Pixel: 0.928x the cycles, factor
  0.911x (§15.38); executables 8% to 12% larger. Four stores; `evolve.sh check` passes; the self-build is a fixed
  point (`fb31b03b…`, not rotated). `integration/bfx/bbc.xax` rebuilt (root `eabd31c1…`, 31 min 49 s), `bbc.exe`
  built by the self-built compiler (4 min 55 s, SHA-256 `462d2cc2…`).
- **First device runs of the native `bbc.exe`'s output**: 18 programs at -O0/-O1 for Android ARM64, 70 of 72 builds,
  all 70 runs correct on the Pixel, before and after.
- **OI-56 (new, OPEN):** the natively built `bbc.exe` does not start on Windows 11: a 78 KB frame with no stack
  probe. Wine hides it. The measurements used a copy with its header's stack commit raised.
- **Tests** (Linux x86-64, WSL 2, `XAX_REQUIRE_NATIVE=1`): the native AArch64 and Android self-hosting tests and
  the Android tests on the 0025 stores (158 passed, 867 subtests); on the committed tree,
  `test_xax_selfhost_general_build.py`, `test_store_regeneration.py`, `test_status_docs.py`,
  `test_replacement_matrix.py` and the two AArch64 allocator tests: 114 passed, 91 skipped, 215 subtests passed.
- **Not done:** seed rotation and the B-level records (a reviewed step, together with 0024); `tools/check.py` under
  Wine and qemu (neither is on the host); BBC's Windows outputs; the Linux AArch64 `jsonmin` re-measurement;
  the Windows seed.
- **Next:** rotate the seed for 0024 and 0025 after review; fix OI-56 natively; share stubs between edges with equal
  copies if size matters; the remaining measured AArch64 waste in BBC's loops is a zero extension after each byte
  load (1.4% of mandelbrot's cycles by the same `nop` experiment) and the clear loop's load-subtract-store.

## OI-56 fixed in the stores: PE images commit their stack reserve (ledger 0026) — 2026-11-12 (ADR-396)

- **Ledger 0026**: one constant of the native PE writer (`SizeOfStackCommit`, 4096 → 1048576, the reserve) in
  `xax_x86_64_general.xax`, `xax_compiler_driver_general.xax` and `seed/xax_compiler_request.xax`, applied with
  `evolve.sh apply` (the seed's `edit` and `verify`). `reference/xax_pe.py` has the same value so the reference stays
  byte-equal with the native compiler; `benchmarks/windows_pe_hosted_evidence.json` was re-executed on Windows 11
  for the new bytes.
- **Self-build**: `selfbuild.sh` on the new request store, generations 1 and 2 byte-identical (31,907,179 bytes,
  SHA-256 `7988e0d0…`).
- **BBC**: `bbc.xax` (SHA-256 `b57f9044…`) is the committed store with the same batch applied by the new
  `rebuild.sh`; the self-built compiler built `bbc.exe` from it (36,323,328 bytes, SHA-256 `a4717ac8…`). That file,
  with its header as built, runs on Windows 11 (build 26300): 18 corpus programs at -O0 and -O1 for windows-x86_64,
  36 of 36 builds and runs, every output equal to the expected bytes with exit 0 (standard input and output
  redirected). One earlier run of a built `hello.exe` with the console's own handles did not return and was not
  explained; the same program built again prints `Hello World!` with redirected handles.
- **BBC's rebuild has no Python or awk**: `rebuild.sh` now applies a production batch to BBC's store with
  `xaxc edit` and `verify`. Checked against the old rebuild: ledgers 0024 and 0025 applied to the ledger 0023
  `bbc.xax` give the committed ledger 0025 `bbc.xax` byte for byte. `bbc_request.xax` is BBC's build request, kept
  by the same batches (ledger 0026 applied to the request of the previous `bbc.xax` equals a request made for the new
  one, byte for byte). Removed: `cids.py`, `port_main.awk`, `main_map.txt`, `variants.sh`, `variant.awk`, the layer
  tools and `tools/request.py`.
- **Language rule** (`CLAUDE.md`, `AGENT.md`): the repository is XAX; another language only where XAX cannot do it;
  existing code in other languages is to be rewritten natively.
- **Not done:** the Linux seed rotation (ledgers 0024 to 0026, one reviewed step) and the B-level records; the
  Windows seed; BBC's Android outputs on a device with this `bbc.exe`; `tools/check.py`. `rebuild.sh` and
  `evolve.sh` are still shell around `xaxc`; BBC's `tools/*.py` and the `importer_split` awk files remain.
- **Next:** rotate the seed; cut a Windows seed from it and close OI-56; move the remaining tools to XAX.

## The Windows seed is the production compiler and builds itself on Windows 11 — 2026-11-12 (ADR-397)

- **Seed**: `compiler/bootstrap/windows/xaxc-windows-x86_64.exe` is now the production driver after ledger 0026 with
  the Windows hosting layer (31,959,040 bytes, SHA-256 `e2f68c00…`). It replaces the alias-index seed `aa72234d…`.
- **How it is made**: one native batch on `bbc.xax` (`bootstrap/windows/xaxc_entry.batch`): a four-node entry that
  registers the view-commit handler and calls the driver's command-line entry, installed with `replace`. The engine
  drops BBC's front. The same batch for `bbc_request.xax` gives the build request.
- **Fixed point on Windows**: the seed resolves and builds its own request to its own bytes (42 s and 2 min 45 s).
  The first copy was built on Linux by the self-built ledger 0026 compiler.
- **Same compiler as on Linux**: its `edit` of a native batch equals the Linux result byte for byte; it builds the
  Linux compiler's request to the Linux self-build's bytes (`7988e0d0…`); `bbc.exe` also rebuilds itself to its own
  bytes on Windows (`a4717ac8…`). Records: `compiler/benchmarks/windows_selfhost_evidence.json`.
- **Not a B level**: B levels are derived from the Linux records; this is a Windows fixed point recorded on its own.
- **Not done:** the Linux seed rotation (another session); a console-handle run; OI-55's cases through this seed;
  XAX-MCP's pin of the Windows seed (its own repository). The two entry batches must be rewritten when `bbc.xax`
  changes (three handles and the root).
- **Next:** the Windows row of the replacement matrix: R3 with this compiler as the workload, then R4 to R6.

## Windows row at R3: the compiler is the practical application — 2026-11-12

- `XAX_REPLACEMENT_MATRIX.json`: `windows-x86_64-pe` `practical_application` is EXECUTED on
  `compiler/benchmarks/windows_selfhost_evidence.json` (the production compiler on Windows 11: files, 3.5 GiB of
  lazily committed views, a byte-identical self-build). The validator derives R3; status blocks regenerated.
- `tests/test_replacement_matrix.py`: the over-claim case expected the Windows row at R2; it now expects R3 (one
  string in an existing Python test; the test is the validator's own and has no native form yet).
- **Not done:** R4 needs raw-sample measurements on this host against C and one non-C toolchain (gcc and rustc are
  installed); R5 and R6 need a maintenance cycle and an XAX-only application run on Windows.

## Seed rotated after ledgers 0024 and 0025; OI-55 closed on Linux — 2026-11-12 (ADR-393)

Everything below was built and run on commit `059a327` (ledger 0025) and is committed on top of `6490d4f` (ledger 0026 and the
Windows seed of ADR-397), which landed meanwhile. It settles the seed rotation for ledgers 0024 and 0025 that the sections before it leave open; the
rotation for ledger 0026 is the next step.

- **Seed:** `compiler/bootstrap/seed/xaxc-linux-x86_64` is now `fb31b03b…abb6b`, 31,907,179 bytes (was `a35fd59f…`,
  31,903,131). `selfbuild.sh` from the old seed: two generations byte-identical, equal to `rotate-seed`'s result;
  `write-request` changes nothing; `evolve.sh check` passes. The expected `1085c08a…` of the 2026-11-11 plan was the
  fixed point before ledger 0025 and is not a committed seed.
- **OI-55 on Linux:** `native/0024/probe.py` with the rotated seed: 240 of 240 programs equal the reference executor
  (128 of 240 differ with `a35fd59f…`). `native/0024/narrow_signed_compare.xax`, the same check as an XAX program:
  exit 0 built by the rotated seed, 1 by the old one. The OI-55 skip in `tests/test_xax_selfhost_general_build.py`
  and `x86_raw_corpus.has_narrow_signed_compare` are removed; with `XAX_RAW_TRIALS=80` the file passes. OI-55 stays
  open for Windows PE cases only.
- **Windows seed (ADR-397, `e2f68c00…`):** on Windows 11 it builds `narrow_signed_compare.xax` to the same ELF bytes
  as the rotated Linux seed (SHA-256 `39baf88c…`); that file exits 0 on Linux. No PE program with a narrow signed
  compare was built or run.
- **BBC:** `bbc.exe` built by the rotated seed from the committed `integration/bfx/bbc.xax` is `462d2cc2…`, the file
  ADR-394 measured. Mandelbrot, life and factor at `-O1` for Windows x86-64 are byte-identical to the outputs of the
  pre-0024 `bbc.exe` (`dd044715…`) and print the expected bytes on Windows 11 (run from a copy with the stack commit
  raised, OI-56). BBC's driver was not rebuilt here: `bbc.xax` already follows the ledger 0025 driver.
- **Evidence:** `benchmarks/full_selfhost_evidence.json` and `python_free_seed_evidence.json` re-recorded under
  `XAX_REQUIRE_NATIVE=1`; status blocks regenerated (B levels unchanged).
- **Tests** (Linux x86-64, WSL 2, `XAX_REQUIRE_NATIVE=1`, four workers): the whole suite without
  `test_native_large_image.py`: 1,516 passed, 243 skipped, 524,991 subtests passed, 15 failed;
  `test_native_large_image.py` alone: passed (33 min 32 s). The 15 failures are not from this change: seven need a
  Wasm host the machine lacks (`test_oi06_memory_surface.py` 2, `test_oi16_target_granularity.py` 2,
  `test_xax_compiler.py::WasmTests` 3), `test_xax_selfhost_jvm.py::test_callback_programs` needs a JDK (one subtest;
  it fails the same way on `059a327` with the old seed), and the rest are `test_xax_selfhost_general_view.py`
  (`test_jsonmin`, `test_random_programs` with three trials, `test_register_resident_analyses`,
  `test_executables_assembled_in_xax`), now OI-57.
- **Ledger replay:** `evolve.sh replay` with the rotated seed: 122 of 122 transactions (ledgers up to 0025) give
  their recorded stores (58 min).
- **Language rule (user, 2026-11-12):** this repository is XAX only; another language is allowed only where XAX
  cannot do the thing. The Linux check that the 2026-11-11 plan asked for as a Python test is therefore the XAX
  program above, and no Python was added. It is not in an automated run yet: the only test runner is pytest.
- **Not done:** OI-55's cases as PE programs through the Windows seed; the XAX-MCP pin;
  `tools/check.py` under Wine and qemu (neither is on the host); the AArch64 backends were not examined for the same
  defect; the seed is one transaction behind the request again: ledger 0026 changed the request
  after these runs, so `tests/test_python_free_seed.py` (the record names the request it was made from) fails until
  the seed is rotated to the ledger 0026 compiler (`7988e0d0…` by the previous section) and the two records are
  made again; no test was rerun on the ledger 0026 tree except those named in the commit.
- **Next:** rotate the seed to ledger 0026 and re-record; run OI-55's cases as PE programs and close it; OI-57; a native runner for
  `narrow_signed_compare.xax` and the other checks as the Python tests are replaced.

## Windows R4 measured and withheld: chains is at parity with rustc — 2026-11-12

- **Workload**: `compiler/benchmarks/windows_chains/`: the OI-37 chains program for Windows PE as a native batch,
  built by the Windows seed (2,560 bytes); C and Rust baseline twins (`gcc -O2`, `gcc -O3`, `rustc -O3`).
- **Harness**: `xbench`, an XAX program (native batch, six new kernel32 declarations supplied as objects):
  CreateProcessA, QueryPerformanceCounter, exit status, peak working set; 34 rotating rounds, 31 samples per arm.
- **Result** (`compiler/benchmarks/windows_chains_evidence.json`, Windows 11, Ryzen 9 5900HS, ordinary load): XAX
  median 0.1426 s, rustc 0.1399 s, gcc 0.223 s. XAX over rustc is 1.019 in the recorded run and 0.960, 1.028, 0.978
  in three repeats: parity within noise. The validator recomputes `competitive` false; the row stays R3.
- **R5 and R6 on Windows are not started.** The validator derives levels in order, so neither can be reached while
  R4 is withheld; their evidence fields could still be recorded.
- **To reach R4**: a real code-generation lead over rustc on this workload (the walk loop is memory-bound, so the
  lead has to come from the insert loop or start-up), a quieter host, or further workloads. No workload or
  competitor was dropped.
- The matrix test file is unchanged; `python -m xax_status_docs --write` regenerated the status blocks.

## Linux seed rotated to ledger 0026 — 2026-11-12

Built and run on commit `b2df99d`; committed on top of `745e801`, which changes no store, ledger line or seed. The seed is again the compiler of the committed request.

- **Seed:** `compiler/bootstrap/seed/xaxc-linux-x86_64` is now `7988e0d0…2fade9`, 31,907,179 bytes (was `fb31b03b…`,
  the same size). `selfbuild.sh` from `fb31b03b…`: two generations byte-identical, equal to `rotate-seed`'s result
  and to the hash the ledger 0026 record and the Windows seed's record name. `evolve.sh check` passes.
  `write-request` leaves the request store unchanged.
- **Correction to the section before this one:** its "`write-request` changes nothing" was not checked on the ledger
  0025 tree: the command had stopped on a missing module path and printed nothing that was read. It is checked here,
  on the ledger 0026 tree.
- **OI-55 cases:** `native/0024/probe.py`: 240 of 240 programs equal the reference executor.
  `native/0024/narrow_signed_compare.xax` builds to the same bytes as before (`39baf88c…`) and exits 0.
- **BBC:** the seed resolves `integration/bfx/bbc_request.xax` and builds `bbc.exe`: `a4717ac8…`, 36,323,328 bytes,
  the file the ledger 0026 section ran on Windows 11. Nothing of BBC was run again here.
- **Evidence:** `benchmarks/full_selfhost_evidence.json` and `python_free_seed_evidence.json` re-recorded under
  `XAX_REQUIRE_NATIVE=1`; status blocks regenerated.
- **Tests** (Linux x86-64, WSL 2, `XAX_REQUIRE_NATIVE=1`, four workers, `XAX_RAW_TRIALS=80`):
  `test_python_free_seed.py`, `test_store_regeneration.py`, `test_xax_selfhost_general_build.py`,
  `test_xax_selfhost_general_driver.py`, `test_xax_selfhost_x86_64_backend.py`,
  `test_x86_64_narrow_signed_compare.py`, `test_status_docs.py`, `test_agent_instructions.py` and
  `test_replacement_matrix.py`: 125 passed, 93 skipped, 4,845 subtests passed. The whole suite was not run again
  on this tree; its last run is the section before this one (ledger 0025).
- **Ledger replay:** `evolve.sh replay` with the new seed: 125 of 125 transactions give their recorded stores (58 min).
- **Not done:** OI-55's cases as PE programs through the Windows seed; the XAX-MCP pin; `tools/check.py`; OI-57;
  the AArch64 backends were not examined for OI-55's defect.

## Windows chains: improved batch, a faster C arm, R4 still withheld — 2026-11-12

Built and run on Windows 11 with the Windows seed (`e2f68c00…`), on commit `cdf7eb5`. No store, ledger line or seed changes.

- **Workload batch:** `compiler/benchmarks/windows_chains/chains.batch` is rewritten in the lookup walk (masked
  links over 2^21-slot views, raw bucket head kept for the prefetch, `steps` and `found` kept out of frame slots).
  `chains.exe` is `90e48100…`, 2,560 bytes, same output.
- **New arm:** `chains_soa.c`, C with the XAX arm's data layout. It is the fastest arm and is now in the comparison.
- **Measurement** (`compiler/benchmarks/windows_chains_soa_evidence.json`, four runs of six arms): XAX median 122
  to 132 ms; `rustc -O3` 135 to 152 ms (XAX 0.87x to 0.92x); `chains_soa.c` 97 to 112 ms (XAX 1.19x to 1.26x).
  The matrix row stays R3 with `competitive` false; it now points at this record.
- **Causes:** `XAX_OPEN_ISSUES.md` OI-58: the allocator's loop-slot rule puts `steps` in a frame slot on Win64, the
  prefetch pass matches one program shape, the walk closes on the link test, and code placement alone moves the
  result by up to 25%.
- **Supersedes** the result of "Windows R4 measured and withheld" above (parity with rustc): that record stays as
  the first batch's measurement.
- **Not done:** the backend changes OI-58 names (native transactions, then both seeds and BBC); R5 and R6 on
  Windows, which the matrix cannot derive while R4 is unmet; a second workload; a quiet host.
- **Tests:** `tests/test_replacement_matrix.py` and `tests/test_status_docs.py` pass (19) on Windows; nothing else
  was run.

## Windows maintenance cycle recorded on xbench (R5 evidence; R6 not yet) — 2026-11-12

Run on Windows 11 with the Windows seed (`e2f68c00…`) only, on commit `f114fb4`. No store, ledger line or seed changes.

- **Application:** `xbench`, the timing harness of `compiler/benchmarks/windows_chains` (4 functions, root `eb64f934…`).
- **Cycle** (`compiler/benchmarks/r5_windows_xbench_maintenance_evidence.json`, `compiler/benchmarks/windows_xbench`):
  request "50 rounds per arm instead of 34"; three views read through `xaxc edit` (11,357 bytes); one edit,
  `const N23 50` (an 83-byte batch); `verify` exit 0; new root `3b945072…`; rebuilt with `resolve` and `build`
  (3,584 bytes before and after). The same batch on the new store is rejected (`WORKSPACE-EXPECTED-ROOT`).
- **Tests:** one arm gives 34 lines before and 50 after; three arms 102 and 150; a child's exit status 7 is reported
  in every line; line format and rotation unchanged. The checks were shell commands.
- **Benchmark:** child time reported by each generation for the same program, three alternating runs: 0.109 s before,
  0.101 s after; run medians ranged 0.096 to 0.140 s, so no difference is shown, and none is expected.
- **Matrix:** `autonomous_maintenance` is EXECUTED with this record; `xax_only_application` is PROTOTYPE: the
  application's logic, compiler and both releases are XAX, its tests are not. The row stays R3: R5 and R6 are not
  derived while R4 is unmet.
- **Not done:** tests for `xbench` written in XAX; generation 1 adopted as the committed `xbench.batch`; the backend
  changes of OI-58.
- **Tests:** `tests/test_replacement_matrix.py` and `tests/test_status_docs.py` pass (19) on Windows.

## Ledger 0027 (loop-slot rule) tried and dropped; OI-59 found — 2026-11-13

Worked on top of `65bce1e`. Nothing of the attempt is committed: no store, ledger line, seed or BBC change.

- **Attempt:** a native batch per store (x86-64 backend, driver, request) that makes `loop_slots` reject a slot class
  written by a cyclic block holding no member (OI-58 item 1), with the same rule in the reference. The first form read
  a reachability matrix the function no longer has (ADR-365) and disagreed with the reference on `chains-soa`; the
  second used the per-block cycle flags and agreed with it.
- **What worked:** the Linux self-build reached a fixed point at the third generation (`ca87a63c…`, 31,511,387 bytes);
  the Windows seed cut from the rebuilt `bbc.xax` reached its fixed point on Windows 11 (`851776f3…`); the Windows
  `chains` walk kept `steps` in a register without the program's workaround; 125 seed-following tests passed.
- **Why it was dropped:** the new compiler rejects a correctly Ed25519-signed package (`TRUST-SIGNATURE-REQUIRED`) where
  the committed seed and the reference accept it: B3 is lost in `bench_full_selfhost`'s record. A scratch differential
  over nested loops then showed that the reference register path already miscompiles such functions, and that the
  change made the native compiler emit the reference's bytes for them (`XAX_OPEN_ISSUES.md` OI-59).
- **Windows chains** with the change: 1.17x to 1.41x the C twin (`chains_soa.c`), 0.77x to 0.94x rustc, the same as
  the committed batch with its workaround; R4 stays withheld (OI-58).
- **Host change:** WSL 2 (Ubuntu-24.04-D) now has clang 18.1.3 (apt) and rustc 1.97.0 (rustup), the versions of the
  host that recorded `oi37_chains_evidence.json`.
- **Repository on Windows:** `compiler/bootstrap/evolution/LEDGER` (file) and `compiler/bootstrap/evolution/ledger/`
  (directory) collide on a case-insensitive file system; a Windows checkout shows `LEDGER` deleted.
- **Next:** OI-59 (the reference fault, then the native compiler against the same family), then OI-58.

## OI-59 diagnosed: edge copies overwrite shared edge spill slots; reference fixed — 2026-11-13

- **Cause:** `copy_edge` stores frame-word destinations before later moves of the same edge read them; edge spill
  slots are shared across blocks. Traced on a five-block function with 8 allocatable registers. The native general
  backend has the same two phases, so the committed compiler carries the fault (`XAX_OPEN_ISSUES.md` OI-59, which
  also corrects its first version: those results came from the native backend through `compile_linux_executable`'s
  default mode).
- **Reference fix:** `compiler/reference/xax_x86_64_regalloc.py` stages every source in a word the edge writes into a
  free dynamic spill slot first. The family's programs now equal the executor (before: 1 to 9 of 40 wrong).
- **Tests** (Linux x86-64, WSL 2, `XAX_REQUIRE_NATIVE=1`): `test_xax_regalloc_differential.py`,
  `test_xax_x86_64_codegen.py`, `test_x86_64_optimizations.py`, `test_xax_chains.py`, `test_xax_linux.py` pass (43);
  `test_xax_selfhost_general.py`, `_general_build.py`, `_general_rejects.py` pass; `_general_view.py` has its 7 OI-57
  failures with and without the change.
- **Not done:** the native transaction (the edge-copy code of the native general backend), seeds, BBC.

## Windows evolution ledger paths coexist — 2026-11-13

The native ledger tool directory is now `compiler/bootstrap/evolution/ledger-tool/`,
so it coexists with the tracked `evolution/LEDGER` file on case-insensitive Windows
filesystems. The native stores and construction batches are unchanged. Only the
wrapper's program path and the copy-based evolution test's fixture path changed;
the wrapper is checked out with LF line endings for execution under WSL.

Validation: `sh compiler/bootstrap/evolution/evolve.sh check` reports every chain
at its committed store. With `XAX_REQUIRE_NATIVE=1`, the evolution copy/apply test
passes (1 test, 179.43 seconds). This resolves the Windows checkout collision
recorded above; native snapshot mutation work and OI-59 remain separate.

## Ledger 0027 (edge-copy staging), both seeds, four rows at R3 — 2026-11-13

Built on Linux x86-64 (WSL 2) and Windows 11 (build 26300), on top of `43054ce`.

- **Ledger 0027** (ADR-398, OI-59 fixed): the general backend's edge-copy function stages every source that sits in a
  frame word the same edge writes, as the reference does since `b137b66`; batches
  `0027-edge-copy-staging-x86-64.batch`, `0027-edge-copy-staging.batch`, `0027-edge-copy-staging-request.batch` on
  `xax_x86_64_general.xax`, the driver and the request store, applied with `evolve.sh apply`.
- **Linux seed:** `selfbuild.sh` gives generations that differ (the first is still the old compiler's code); the
  second rebuilds itself byte for byte (`59588633…`, 31,912,763 bytes, was 31,907,179). `rotate-seed` twice; the seed
  is that fixed point and the pins follow. `write-request` leaves the request unchanged.
- **BBC and the Windows seed:** `bbc.xax` and `bbc_request.xax` rebuilt with `rebuild.sh` from the 0027 batches. The
  Windows seed cut from them on Windows 11: the ledger 0026 seed built generation 1, generations 2 and 3 are equal
  (`91ce2a71…`, 31,964,672 bytes); new entry handles `F598`, `F988`, `F125`. The Windows `chains.exe` and `xbench.exe`
  built by it are byte-identical to the committed ones (`90e48100…`, `148fdd7a…`).
- **Correctness:** the OI-59 family (nested loops carrying 8 to 21 values) returns the executor's result for every
  program with the new backend (before: 1 to 9 of 40 wrong). The two Ed25519 trust cases of `bench_full_selfhost`'s
  corpus are images again (the first, dropped version of ledger 0027 had lost them).
- **Records:** `python_free_seed_evidence.json` and `full_selfhost_evidence.json` re-recorded with `XAX_REQUIRE_NATIVE=1`;
  B0 to B6 hold. The Linux `chains` artifacts are unchanged, so `oi37_chains_evidence.json` stands.
- **Tests** (Linux x86-64, WSL 2, `XAX_REQUIRE_NATIVE=1`, four workers, `XAX_RAW_TRIALS=80`): store regeneration,
  general build, driver, x86-64 backend, narrow signed compare, chains, x86-64 optimizations, register-allocator
  differential, evolution, Python-free seed, status docs, agent instructions, replacement matrix, general, general
  rejects, build and Linux: 205 passed, 96 skipped, 5,097 subtests passed (1 h 14 min). On Windows 11,
  `test_store_regeneration.py` now collects and runs: 65 passed, 93 skipped (the native replays need the Linux seed).
- **Host audit** (OI-60): the compiler is host-neutral; the ledger path collision is fixed (`ledger-tool/`, `43054ce`);
  `*.sh`, `*.batch` and `LEDGER` keep LF on every host; the reference names the PE identity once
  (`PE_HOSTED_IDENTITY`); OI-58 item 1's register-count explanation is corrected. Left open: OI-60.
- **Matrix** (ADR-399): `aarch64-baremetal` R2 to R3, `browser-web` R2 to R3, `wasm32-wasi` R1 to R3 and
  `gpu-spirv-cuda-metal-dxil` R1 to R3, each with a practical application (SHA-256 firmware under QEMU, Game of Life
  in Chrome, a `wc` counter under Node WASI, a fingerprint kernel on an RTX 3060 and an AMD iGPU through an XAX Vulkan
  host). `wasm32-core` and `accelerator-simt-packet` are removed. RISC-V is deferred.
- **Not done:** OI-60; RISC-V; R4 evidence for the four new R3 rows; tests for the Windows seed.
## Native resolved-snapshot mutation handoff — 2026-11-13

Ledger 0028 and `compiler/bootstrap/evolution/native/0028/README.md` describe
native snapshot ancestry rebuilding after the upstream ledger-0027 backend fix.
Both production stores, both rebuilt BBC stores and the Windows compiler entry
batches follow this transaction. Current seed identities are pinned in
`xax_selfhost_seed` and `compiler/bootstrap/windows/seed.json`; independent native
fixed points, JVM behavior, metadata/canonical-collection controls and BBC checks
are recorded in `compiler/benchmarks/snapshot_mutation_20261113_evidence.json`.

Run native `verify` before accepting any edited candidate. A result-type mutation
can pass edit staging and fail semantic verification. Signed-package changes,
signature/provenance rewriting and recursion-group users remain unsupported.
Keep the historical generator identities separate from their natively evolved
successors (`edit_begin` and `edit_next` now join the existing helper exclusions).
Full bootstrap levels come only from the executed benchmark records and their
ordinary status derivation.

## Build/rotation campaign, steps 2–4 — 2026-11-15

Base `main` = `897002e` (ledger 0032, 142 transactions, nothing pending). Execution order: RFC
`docs/proposals/build-bootstrap-rotation-rfc.md` §13.7. Every PR below waits for the owner's merge. Several append
to `XAX_STATE.md` or edit `XAX_OPEN_ISSUES.md`, so later merges may need a trivial rebase.

- **Step 2 (phase 0):** ADR-404 and the AGENTS.md amendment (rotation, full evidence and BBC's rebuild once per
  release; driver transactions on `release/<ledger>`). [PR #59](https://github.com/MrxSiN/XAX/pull/59). Steps 7 and
  9 wait for its merge.
- **Step 3 (phase 2):** profile of one driver `edit` and `verify` in WSL, and per-store replay times. File I/O is
  under 0.4 s of 40 s; peak RSS is 2.26 GB (edit) and 1.61 GB (verify); the RFC's 6.1 GB is corrected.
  [PR #62](https://github.com/MrxSiN/XAX/pull/62).
- **Step 4 (batch S):**
  - OI-55 closed: Windows-seed cases, 3,840 of 3,840 equal the executor. [PR #63](https://github.com/MrxSiN/XAX/pull/63)
  - OI-57 closed: the reference folds as ledger 0022 does. [PR #64](https://github.com/MrxSiN/XAX/pull/64)
  - Status lines: OI-21 to OI-24 closed; OI-15, 18 and 19 kept open, each missing one criterion.
    [PR #60](https://github.com/MrxSiN/XAX/pull/60)
  - OI-34 and OI-51 checked, both still open. [PR #61](https://github.com/MrxSiN/XAX/pull/61)
- **Tests run** (results in the `XAX_STATE.md` sections of 2026-11-15):
  - `test_x86_64_narrow_signed_compare.py` on Windows 11: 6 passed, 3,846 subtests.
  - `test_xax_selfhost_general_view.py` in WSL with `XAX_REQUIRE_NATIVE=1`: 17 passed.
  - 42 reference-x86-64 files in WSL: 413 passed, 6 environmental failures (no `node`, no JDK jmods; also on main).
  - 7 Windows reference files: 22 passed.
  - Not run: the full suite (by design); `test_xax_selfhost_compiler_fixed_point.py`; `test_the_compiler_replays_the_ledger`
    on its own.
- **Identities:**
  - Linux seed `0cd26742…` (31,942,651 bytes).
  - Windows seed `e88877d1…` (31,993,856 bytes).
  - Request `8345f64d…`; `hosted_sha256` `ff9dfa42…`; Windows `result_sha256` `5bf65de6…` (`windows/seed.json`).
- **Runs in progress:** none. WSL logs: `/root/work/profile/profile-20261115.log`, `/root/work/oi57-run1.log`,
  `/root/work/oi57-related.log`, `/root/work/oi57-related2.log`. `/root/work/campaign` is detached at `897002e`, and its
  `reference/xax_x86_64_regalloc.py` holds PR #64's version (restore it with `git checkout` before other work).
  `strace` is now installed in WSL.
- **WSL environment gaps:** no `node` and no JDK `jmods`, so Wasm and JVM-import tests fail there. One worker of the
  42-file run peaked at 11.6 GB RSS, so keep `-n 4` or fewer.
- **Blockers:** none new. Steps 7 and 9 need PR #59 merged.
- **Next step:** step 5. Write the native request tool `request <driver> <target> <out>` and the Windows hosting
  generator, then run their oracle checks at ledger 0032 before any driver change:
  - the Linux request equals the committed `8345f64d…` and the reference `compiler_request`;
  - the hosted store equals `ff9dfa42…`;
  - the Windows request equals `5bf65de6…`;
  - its build equals `e88877d1…`.
  Only then delete `hosting.batch` and `pe_target.edit`. Steps 6 and 8 follow; step 8 may start in parallel.

## Build/rotation campaign: step 5 started (request tool) — 2026-11-15

`main` = `6b47cea`. On the owner's instruction in chat, PRs #59–#65 were merged (phase 0 ADR-404, the phase 2
profile, OI-55, OI-57, the OI status lines, the OI-34/OI-51 checks, the previous handoff).

- **Done, open:** [PR #66](https://github.com/MrxSiN/XAX/pull/66), the native request tool
  (`compiler/bootstrap/evolution/request-tool/`). At ledger 0032 its output equals the committed request and the
  reference `compiler_request` byte for byte (`8345f64d…`), EXECUTED in WSL with the pinned Linux seed.
  `tests/test_request_tool.py`: 3 passed.
- **Identities:** Linux seed `0cd26742…`, Windows seed `e88877d1…`, LEDGER head ledger 0032 (142 transactions).
- **Runs in progress:** none. WSL scratch: `/root/work/rt/`. `/root/work/campaign` is detached at `d382e00` (the PR
  branch). `/tmp` in WSL does not survive between `wsl.exe` calls, so keep outputs under `/root/work`.
- **Verifier and backend rules learned while writing the tool** (native batch authoring; see its README):
  - an access through `ptr<bitsN>` must be N/8 bytes wide;
  - a cast from `ptr<bits8>` to `ptr<bits32>` is declined (verify exit 2, no record);
  - a function has at most one machine return value and at most four machine parameters, and a call at most four
    machine inputs;
  - every heap view needs its own memory-effect token (`MEMORY-EFFECT-PROVENANCE`), so an entry takes one memory
    parameter per view;
  - `heap.view`'s second attribute must equal the pointer's alignment;
  - the startup `arg_copy` does not NUL-terminate;
  - `xaxc edit` verifies its input store first, so an unverified candidate cannot be viewed.
- **Next step (rest of step 5):** the Windows hosting generator. It takes the request tool with a PE target and a
  frozen `windows/host_layer.xax` (RFC §7), rewrites main's host-function calls and startup reads by CID, and adds
  `@XAXC`. Its oracle checks use the ledger 0032 files, which git keeps after later ledgers too:
  - the hosted store equals `ff9dfa42…`;
  - the Windows request equals `5bf65de6…`;
  - its build equals `e88877d1…`.
  Then delete `hosting.batch` and `pe_target.edit`. After that, step 6 (`derived` line), with steps 7 and 8 as the
  RFC orders them.

## Build/rotation campaign: step 5 done (Windows generator) — 2026-11-15

`main` = `d47ba6d` (PR #66, the request tool, merged on the owner's instruction). This PR completes step 5.

- `compiler/bootstrap/windows/generator/` derives the Windows seed's request from the shared request.
- At ledger 0032 every oracle matched (batch, record, hosted store, request, the build `e88877d1…`), so
  `hosting.batch` and `pe_target.edit` are deleted (`XAX_STATE.md`, same date).
- After a future driver change, run `sh windows/generator/generate.sh` instead of rewriting handles.
- **Next step:** step 6. First the ledger tool accepts the `derived <store> <final blob> <tool root>` line, in its
  own commit, with every old line still accepted. Then LEDGER gets
  `derived seed/xax_compiler_request.xax <blob> <request-tool root>`, and `check` requires committed request =
  `request(driver)`. Steps 7 and 8 follow (step 2 / PR #59 is merged).
- Runs in progress: none. WSL scratch is `/root/work/win/`, holding the chain log and the cross-built
  `xaxc_win.exe`.

## Build/rotation campaign: step 6 done (derived request) — 2026-11-15

`main` = `2595e42` (PR #67 merged on the owner's instruction). This PR: the ledger tool reads `derived` lines, and
`LEDGER` marks the request as derived. From now on, a production driver change is one transaction on the driver
only, applied with `evolve.sh apply`, which rewrites the request. Windows requests come from
`windows/generator/generate.sh` (AGENTS.md updated).

- **Next step:** step 7. Cut `release/0033` from `main` and start batch C with C-x86: the OI-58 slot rule and native
  PE stack probes for frames over 4 KiB. Each sub-batch is a PR into the release branch, tested with C1 (and C2 for
  x86-64 code generation). Step 8 (V2 evidence runner, `rotate.sh`) can run in parallel on `main`.
- Runs in progress: none. WSL scratch: `/root/work/step6b` (a copy of `bootstrap/` with a test transaction; it can
  be deleted) and `/root/work/step6.log`.

## Build/rotation campaign: step 7 started (C-x86) — 2026-11-16

`main` = `660f9eb`, unchanged this session. `release/0033` is cut from it and pushed. Re-verified at the start:
no open PRs; issues #47, #48, #49, #51, #55 open; both seeds at their pins (`0cd26742…`, `e88877d1…`);
`evolve.sh check` passes.

- **Done (PRs open, owner to merge):**
  - [#69](https://github.com/MrxSiN/XAX/pull/69) into `release/0033` (`2220530`): ledger 0033, OI-58 item 1, the
    loop-slot rule, native and reference.
  - [#71](https://github.com/MrxSiN/XAX/pull/71), stacked on #69 (`0bc8e85`): ledger 0034, the OI-56 note, PE stack
    probes. Retarget it to `release/0033` after #69 merges.
- **Tests run:** listed in `XAX_STATE.md` (2026-11-16). Known failure on the release branch:
  `test_xax_chains.py::test_committed_artifact_identity_reproduces`. The `xax_link` chains executable has new bytes,
  `oi37_chains_evidence.json` is historical, and a new chains record is due at the release.
- **Compilers in use:** the pinned Linux seed. Candidates (WSL, not seeds): 0033 C1 `64fb4180…`, C2 = C3
  `daeeff12…` (`/root/work/sb0033a`); 0033+0034 C1 `738a89f5…`, C2 `e64a0291…` (`/root/work/sb0034`).
- **WSL working clone:** `/root/work/campaign` is on `c-x86-pe-probes` (equal to the pushed branch). A `main`
  worktree is at `/root/work/mainwt`. `/root/work/x86v` holds the 0033 views of `xax_x86_64_general.xax`.
- **Runs in progress:** none.
- **Blockers:** none. OI-58 stays open: the Windows `chains` measurement without its workaround, and the lead over
  every arm, need the release's Windows seed. The OI-56 note's DLL run also waits for the release's Windows confirm.
- **Learned:** the native edit engine rejects a batch that redefines both a function and a caller of it, in either
  `replace` order. Split such a change into two transactions. Driver functions are often not byte-twins of the
  backend store's (31 of 235 differ). Find a driver twin read-only with the reference reader, by walking up from a
  distinctive constant to its functions.
- **Next step:** C-a64 (OI-49), a branch from `release/0033` (stacked on #71 until #69 and #71 merge). After it,
  C-jvm (#49 with an ADR, then #48) and C-cap (OI-54 steps, OI-52 R2). In parallel on `main`, step 8's phase 3: the
  corpus input measurement is done (`XAX_STATE.md`). The external input files of the build cases still need
  counting, then the decision whether to freeze the corpus as data.

## Build/rotation campaign: release 0033 done — 2026-11-16

Merged by the agent on the owner's chat instruction ("merge it yourself with gh pr merge --merge" once a PR's
targeted tests pass). PRs: [#69](https://github.com/MrxSiN/XAX/pull/69), [#71](https://github.com/MrxSiN/XAX/pull/71)
(C-x86) and [#73](https://github.com/MrxSiN/XAX/pull/73) (C-a64) into `release/0033`;
[#70](https://github.com/MrxSiN/XAX/pull/70) (the owner's ADR-405), [#72](https://github.com/MrxSiN/XAX/pull/72) and
[#74](https://github.com/MrxSiN/XAX/pull/74) (ADR-406, the plan change) into `main`; then the rotation PR and the
release PR (this section's).

- **Seeds now**: Linux `36e2b756…` (31,549,147 bytes), Windows `ae43e32f…` (31,602,176 bytes), both at ledger 0035.
  Results are in `XAX_STATE.md` (2026-11-16, release 0033).
- **Calls made overnight** (recorded):
  1. C-jvm and C-cap were moved to the next release, because the JVM backend's emission is in single 41,000–46,000-line
     functions and OI-54 needs new layouts. ADR-406 designs #49.
  2. The chains and filestat evidence go into new files; the old records and the matrix's R4 citations stay.
  3. The graph-decoder fuzz test runs 3,000 trials, not 1,500.
  4. `qemu-user-static` is installed in WSL, with a `qemu-aarch64` link in `/usr/local/bin`.
  5. BBC's `check.py` ran in WSL with a scratch `wine` shim that executes Windows files natively through interop.
  6. BBC's local `build/bbc.exe` is the new one; the old one is `build/bbc.exe.0032`.
- **Runs in progress**: none. Logs: `/root/work/logs/{replay-0035,rotation-0033,full-0033,pfs-0033,suite-0033,bbc-check-0033b}.log`.
- **Open**: OI-58 (the Windows measurement), the OI-56 note's DLL run, OI-49 closes once the Android-target build is
  run (the fix is in the seed now), #47, #48, #49, #51, #55.
- **Next step**: step 8 on `main`. For phase 3, count the build cases' external input files (the corpus stores are
  about 411 KB generated), then write the V2 runner and evaluator; then phase 6 (`rotate.sh`, `RELEASES`, `POLICY`).
  After that, the next release branch with C-jvm (#49 per ADR-406, then #48) and C-cap.

## Build/rotation campaign: after release 0033 — 2026-11-16

`main` = `1f2fc4c` (release PR [#76](https://github.com/MrxSiN/XAX/pull/76)), equal to `release/0033`. No open PRs.
Seeds: Linux `36e2b756…`, Windows `ae43e32f…` (ledger 0035). `evolve.sh check` passes on `main`.

- **Phase 3 size check done** (RFC §13.7, the 2026-11-16 measurement): the generated corpus inputs are 474,826 bytes in
  132 files, so the corpus is frozen as data.
- **Runs in progress**: none.
- **Exact next step**: phase 3 in one PR on `main`. Write the native evidence runner (`bootstrap/evidence/`: a program
  like `ledger-tool/`, plus an `sh` wrapper). It reads a frozen corpus manifest (case, command, input paths or
  committed store paths, expected outcome), runs each case once per context, and writes the V2 record (§4). Freezing
  needs a one-time export of the 132 generated files and the reference outcomes: do it from `bench_full_selfhost.corpus()`
  with a scratch script that is not committed, and record that command in the PR as the oracle's. Then move the Python
  evaluator to `reference/` and make the native evaluator agree with it on the V1 record and on mutated copies. After
  phase 3: phase 6 (`rotate.sh`, `RELEASES`, `POLICY`), then the next release branch with C-jvm (ADR-406) and C-cap.

## Build/rotation campaign: phase 3 done (evidence V2) — 2026-11-16

`main` = `92ae7cd` ([#78](https://github.com/MrxSiN/XAX/pull/78), merged by the agent on the owner's standing
instruction). No compiler store, CID or seed byte changed. Seeds unchanged: Linux `36e2b756…`, Windows `ae43e32f…`
(ledger 0035). `evolve.sh check` passes on `92ae7cd` (WSL).

- **Done:** `compiler/bootstrap/evidence/`: the frozen corpus (`CORPUS`, `inputs/`, `SNAPSHOTS`), the native program
  `xax_evidence` (`sha`, `elf`, `diag`, `plan`, `levels`; SHA-256 written in XAX), and `run.sh`, which writes the V2
  line record. `src/xax_selfhost.py` moved to `reference/` as the oracle. ADR-407 records the calls; the RFC has a
  phase 3 note. The oracle's export command and scratch script are in #78's description.
- **Calls made** (ADR-407): the V2 record is line text, not JSON. The native evaluator reads only V2. Agreement on V1
  is shown in `tests/test_evidence_v2.py` by writing the V1 record and 15 mutated copies as V2 records. B6's probe
  now edits the status program, a frozen store. The corpus directory is `inputs/`, because `CORPUS` and `corpus/`
  collide on Windows. `RELEASES` and `POLICY` move to phase 6.
- **Tests:** `test_evidence_v2` passes (4 tests, 16 subtests). The WSL targeted run gave 24 passed and 1 failed; the
  failure is the baseline `test_every_b1_entry_is_bound_to_the_committed_store`. `run.sh quick` took 10 min 50 s
  and the record's levels are B0–B5 1, B6 0 (replay not run), rotated 1, python 0.
- **Runs in progress:** none. Logs: `/root/work/logs/ev-run1.log`, `/root/work/logs/ev-tests.log`; the quick record
  is at `/root/work/p3/run1/record` (WSL).
- **Not done yet:** `bootstrap_status` still reads the V1 JSON record. The next rotation records V2 with
  `sh compiler/bootstrap/evidence/run.sh <out>` (a full run, about 90 min including C1's ledger replay), commits the
  record, and points the status derivation at its native `levels`.
- **Exact next step:** phase 6 on `main`. Write `rotate.sh build|confirm|state|gate` in `bootstrap/seed/`, with
  `RELEASES` and `POLICY` (RFC §3, §8, §9). Put its logic in a native batch on `../evolution/ledger-tool/seed.xax`
  and reuse `evidence/evidence.batch`'s helpers (`@fend`, `@nextline`, `@fld`, `@dnum`, `@put`, `@s256`); see
  `bootstrap/evidence/README.md`. Probe running the Windows seed through WSL interop (§8). After that: the native
  oracle (ADR-405), then `release/0036` (C-jvm, C-cap).

## Build/rotation campaign: phase 6 done (RELEASES, POLICY, rotate.sh) — 2026-11-16

`main` = `552234a` ([#80](https://github.com/MrxSiN/XAX/pull/80)). No compiler store or seed changed. Seeds unchanged:
Linux `36e2b756…`, Windows `ae43e32f…` (ledger 0035). `rotate.sh gate` passes on the committed tree (profile released).

- **Done:** `compiler/bootstrap/RELEASES` (release 0033 restated from its committed evidence) and `POLICY`. The
  native `seed/rotate-tool/xax_rotate` provides `state`, `tests`, `pin`, `id` and `valid`, and `seed/rotate.sh` runs
  `build [--dry]`, `confirm`, `gate`, `state` and `validate`. Decisions are in ADR-408.
- **Executed:** the interop probe (the Windows seed from WSL gives the same bytes as from Git Bash and as the Linux
  seed); a dry rotation that rebuilt both pins byte for byte (9 min 42 s); and on a scratch copy, `confirm` for
  both hosts (Windows through interop, 9 min 35 s; Linux, 6 min 17 s), after which the state read
  `profile candidate`. `test_rotate_tool` passes (4 tests).
- **Calls made:**
  - `SEED_SHA256` and `windows/seed.json` stay until the first release made by `rotate.sh`; a test requires them
    to equal the pins.
  - The §9 repair-diff guard is not built.
  - `selfbuild.sh` is unchanged.
  - `confirm` runs an executable copy of the Windows seed, because a Linux checkout drops the `.exe`'s execute bit.
- **Runs in progress:** none. Logs: `/root/work/logs/rot-{dry,confirm-win,confirm-win2,confirm-linux}.log`; the scratch
  copy is `/root/work/p6/boot` (WSL).
- **Next release, with the new tools:** cut `release/0036`; land the C-jvm and C-cap sub-batches; run
  `rotate.sh build 0036`; run `confirm` for both hosts; run `sh evidence/run.sh <out>` (full, with the replay); run
  `validate <out>/record`. Then commit the V2 record, point `bootstrap_status` at the native levels, retire the older
  pins, and amend AGENTS.md's seed rule.
- **Exact next step:** step 3, the native oracle (ADR-405), a roadmap item. Begin with a design note for a native XAX
  reference executor that interprets canonical graphs (no code shared with the backends, nothing generated from the
  compiler's stores), scoped first to x86-64 register lowering's corpus. Alternatively, start step 4
  (`release/0036`, #49 per ADR-406) if the release is more urgent; neither depends on the other.

## Native oracle: design and slice 1 done — 2026-11-16

`main` = `d4379fa`. PRs: [#82](https://github.com/MrxSiN/XAX/pull/82) (design, `docs/proposals/native-oracle.md`) and
[#83](https://github.com/MrxSiN/XAX/pull/83) (slice 1). No compiler store, CID or seed changed. Seeds unchanged:
`36e2b756…` and `ae43e32f…`.

- **Done:** `compiler/bootstrap/oracle/xax_oracle` (native, hand-written batch on the ledger tool's seed; shares no
  compiler code). Slice 1 covers integer arithmetic, compares, truncation and extension, rotation, direct calls and
  the four terminators. The Python and native executors agree on all 160 programs of the x86-64 register-lowering
  corpus (`benchmarks/oracle_x86_64_regalloc_evidence.json`, EXECUTED). `test_xax_regalloc_differential` therefore
  now compares native code with the native oracle (ADR-405 (4)), and `test_native_oracle` keeps checking that both
  oracles agree.
- **Found and fixed during the work:** the decimal printer the tools share looped forever at 10^19 and above. The
  oracle's copy (`@wdec`) is fixed. The copies in `xax_evidence` (`@putd`) and `xax_rotate` (`@decc`) only print
  counts and sizes, far below that, and are left as they are; note it if one ever prints a 64-bit value.
- **Calls made:** the oracle does not verify, because the harness verifies first, as `execute` does. A non-`bits`
  type declines as `decline 0`. Fuel exhaustion is reported but never compared with Python's, because the units may
  differ.
- **Next:** in order of the design's §4,
  - slice 1 for `test_x86_64_narrow_signed_compare` and `test_native_branch_fusion` (they may need only the same
    operations: run the agreement first);
  - slice 2 (recursion groups);
  - slice 3 (views and memory);
  - or step 4, `release/0036` (C-jvm per ADR-406, then C-cap), which is the first release made with `rotate.sh`.

## Native oracle: slice 1 widened, slice 2 done — 2026-11-16

`main` = `c2bdb48`. PRs: [#85](https://github.com/MrxSiN/XAX/pull/85) (narrow compare and branch fusion) and
[#86](https://github.com/MrxSiN/XAX/pull/86) (slice 2, recursion groups). No compiler store or seed changed.

- **Areas checked against the native oracle on Linux x86-64 (ADR-405 (4)):**
  - x86-64 register lowering (160 programs);
  - narrow and signed compare (3,840 cases);
  - compare after branch (6 cases);
  - recursion groups (10 cases).
  Evidence: `benchmarks/oracle_x86_64_regalloc_evidence.json`, `oracle_x86_64_compare_evidence.json` and
  `oracle_recursion_evidence.json`.
- **Windows:** the oracle is a Linux program, so these tests use `oracle_execute` (`tests/test_native_oracle.py`).
  That is the native oracle on Linux x86-64 and the Python executor elsewhere (ADR-405 (3)). The Python executor
  cannot be retired for these areas until the oracle runs on Windows, by building it as a PE through the Windows
  hosting generator or a host layer.
- **Oracle store now:** `2f4ce48c…` (executable `2805816c…`, 18,178 bytes, built by the pinned seed).
- **Next:**
  - slice 3: heap views, checked and growable loads and stores, stack allocation, address offset and pointer
    rebase (`test_xax_x86_64_views`, `test_xax_byte_view_widening`, `test_xax_pointer_rebase`). It needs a memory
    model: an allocation table of base, extent and element per region, plus bounds and alignment traps exactly
    as `_execute_graph` raises them. Read that function's memory cases first.
  - or step 4, `release/0036`.

## Release 0036 started: #49 part 1, the verifier — 2026-11-16

`release/0036` was cut from `main` `991ef7a`. PR [#88](https://github.com/MrxSiN/XAX/pull/88) (`jvm-catch-abis`, commits
`5dfc89b` and `df29469`) goes into it. Merged by the agent on the owner's standing instruction once its tests passed.

- **Done:** the verifier accepts the three catching JVM ABIs of ADR-406. These are native transactions on
  `xax_op_typing.xax` and the driver, and the derived request follows:
  - ledger 0036: op-typing F61 (driver F716), the `FOREIGN-CALL-ABI` diagnostic's list;
  - ledger 0036 b: op-typing F9 (driver F90), the facts program's byte compares that decide acceptance.
  The reference `FOREIGN_ABIS` lists the same three names. The JVM backends still reject them with
  `JVM-FOREIGN-ABI`, which `tests/test_jvm_catch_abis.py` checks.
- **Tests (EXECUTED):**
  - WSL, `XAX_REQUIRE_NATIVE=1`: 94 passed, 0 failed (store regeneration, facts, typing, verify, verify-exact and
    catch ABIs). Windows: the new test passes.
  - C1 (`/root/work/c1-0036b/C1`): it verifies the three catching stores, which the seed rejects. The
    `bench_full_selfhost.corpus()` differential, seed against C1, found 0 of 198 cases different.
  - `evolve.sh check` passes.
- **Seeds:** unchanged (Linux `36e2b756…`, Windows `ae43e32f…`). The release is not rotated yet.
- **Logs:** `/root/work/logs/{c1-0036b,diff-0036a,slice1-tests,catch-tests}.log`.
- **How the patch batches were made:** each is a whole-function `define`/`replace`. A scratch script appended the
  table entries to the function's view and renumbered the nodes; it is not committed. Only the op-typing store and
  the driver hold these two functions (checked over all 29 bootstrap stores).
- **C-jvm plan for #49 (ADR-406), made from the native stores** (function numbers are `xax_jvm_general.xax`'s at its
  committed root `31f5aa52…`; the driver holds 94 of its 97 functions, `xax_android.xax` all 97, so each JVM slice is
  three batches like ledger 0035):
  1. **Verifier (done, ledger 0036 and 0036 b, this release).** Op-typing F61 is only the `FOREIGN-CALL-ABI`
     diagnostic's list; the acceptance is the facts program's byte-compare chain in op-typing F9. Both now hold the
     three names.
  2. **Classification (F38, 45,641 lines, 787 blocks).** F38 is `_foreign_member`: it compares the ABI bytes in
     branchy chains (the `jvm-invokestatic` 16-byte compare appears about 6 times, at view lines 2831, 10989, 15312,
     …) and builds the member record. The planned change is one insertion before the first chain: when the ABI is a
     catching one, compare against the base name (length minus 6), check the last output is
     `jvm-ref:Ljava/lang/Throwable;`, drop it from the outputs, and mark the member record. Every later chain then
     classifies the base ABI unchanged. The insertion point is F38's B87: its parameters P1064 and P1065 are the ABI's
     length and start (B84 has just checked that the ABI, library and name blobs are nonempty), and B87's edges thread
     them through every later block, so replacing P1064 by the adjusted length in B87's nodes and edges is enough. First find the member record's layout (where the opcode, the interface flag
     and the output count are stored) by following the stores after the `invokevirtual` chain.
  3. **Emission (F83 44,675 lines and F84 9,724 lines emit nodes; the invoke opcodes 182/184/185 appear there).** At a
     marked call: label before the invoke, label after it, store the result and `aconst_null` into the throwable's
     local, `goto` the join; the handler stores the throwable and the result's zero; the join is a branch target.
  4. **Frames and stack depth.** The handler is a branch target whose frame has one stack item (`Throwable`); the
     uniform frame elsewhere is unchanged. F95 (33,050 lines) is the next place to read: it calls the pool and frame
     helpers.
  5. **Code attribute (F12, 5,088 lines).** F12 writes `StackMapTable` and `LineNumberTable` (their bytes are at view
     lines 1448 and 2184); the exception table length is written as zero there today and becomes the entries
     `start, end, handler, catch_type` (`java/lang/Throwable` in the pool).
  6. **DEX (`xax_dex_jvm.xax`, 53 functions).** Replace the `DEX-EXCEPTION-TABLE` rejection with a `try_item` and an
     encoded catch handler whose code starts with `move-exception`.
  7. **Oracle: execution.** JVM (Android Studio JBR on Windows) and ART on the Pixel: a member that returns, throws a
     checked exception, throws an `Error`, and throws from a nested call, each with the expected result, throwable
     class and exit status. Then #48.
- Every emitter slice keeps the existing byte-for-byte differential (`tests/test_xax_selfhost_jvm.py`) for programs
  without a catching call; programs with one are checked only by execution (ADR-405: no Python reference).
- **Next step:** #49 part 2, the F38 classification, on a new branch from `release/0036`. Then the emitter, frames,
  the Code attribute and DEX, each a PR into the release. After those: C-cap, the rotation and the release PR.
  Native oracle slice 3 is independent and can go first if part 2 is blocked.

## #49 part 2: anchors in the JVM program's F38 — 2026-11-16

Found on `main` `4c45125` (the view of `xax_jvm_general.xax` at root `31f5aa52…`); no store changed. These
add to the C-jvm plan in the section above. F38's B87 parameters P1064 and P1065 are the ABI's length and start.

     - the member record is the arena record whose address is F38's P30, and field 0 is the invoke opcode, stored
  at B226 (184, static), around view line 15918 (182, virtual), 16512 (185, interface) and 16979 (184,
  interface static). A catching call can carry its mark there as `opcode + 256`, which every reader of field 0
  (the emitter in F83 and F84) must then mask;
- the outputs are counted by a loop over the declaration's non-proof outputs (B334 to B336,
  `N19032 = count + 1`). The method arity check at B723 tests `count == 1 - (result == 'V')` (P32273) and
  raises `JVM-FOREIGN-ARITY` at B724. A catching call takes one off that count after the loop, once its last
  output has been checked to be `jvm-ref:Ljava/lang/Throwable;`;
- parts 2 and 3 must land together. Classification without emission would compile the call as a plain invoke
  and leave the throwable result unset.

## #49 parts 2+3: the JVM program's call path mapped, the change set designed — 2026-11-16

Step 1a of the release 0036 plan. Read-only on `xax_jvm_general.xax` at root `31f5aa52…` (unchanged on `release/0036`
`e53833a`); no store changed and no PR into the release. It supersedes the "emission in F83/F84" guess in the C-jvm
plan two sections up: F83 and F84 emit no instructions.

- **Names for the anonymous functions.** The frozen store's high-level source is readable in git history:
  `git show f6d5b08:compiler/src/xax_selfhost_jvm_{foreign,lower,code,emit,method}.py` and
  `xax_selfhost_jvm.py` (the builders before ADR-361 froze the store). They are only a map for reading the lowered
  views. Nothing may be generated from them (AGENTS.md, ADR-367). Arguments go through the global words
  `268435424 + k`; the method state is the record at global word `29360338` (`GLOBALS + M_STATE`, GLOBALS = 29360128).
  Identified, with the old names:

  | F | Old name | Role |
  |---|---|---|
  | F38 | `jk_member` | `_foreign_member`: the member record (`MB_*`, 18 words) |
  | F53 | `jl_node` | node lowering: pushes tasks with F33; `_foreign_node` is its second F38 call (view line ~33,009) |
  | F33 | `jl_push` | pushes one task (kind, a, b, c) |
  | F54 | `jl_run` | the task loop; `K_FOREIGN` writes the opcode at N809 (`mb[0]`, through F92), then the pool entry, then for 185 the count (B168) |
  | F92 | `jc_op` | `code.op`: flush, append, set `ended` |
  | F94 | `jc_branch` | `code.branch` (the target flag, three bytes) |
  | F96 | `jc_depth` | the operand stack depth; it ignores a depth that wrapped below zero (`depth < 2^62`) |
  | F89 | `jk_method` | the per-method driver: state `alloc(100)`, zeroes words 0–97, pass 1, pass 2 with retries, finish, record |
  | F12 | `_serialize_method` | StackMapTable, LineNumberTable, the Code attribute |
  | F14 | the class entry | no callers |

- **Free words, so no masking is needed.** The member record is allocated as `MB_WORDS + 1` = 19 words, and word 18 is
  unused, so word 18 can hold the catching flag (written 0 or 1 in F38 for every member). This replaces the
  `opcode + 256` idea, which would have needed every reader of word 0 to mask. The method state is
  `alloc(STATE_WORDS + 2)` with `STATE_WORDS` = 98 (16 code fields, 20 value tables, 62 scalars), so words 98 and 99 are free
  for a per-method list of handler labels. They are not zeroed at allocation, so the emit pass must reset the count.
  Check that no ledger transaction since `f6d5b08` uses words 98–99 or 18 before relying on them.
- **The handler needs no change in the depth pass.** At the handler frame F96 restarts at 0 and the `astore` takes it to
  −1, which F96 ignores. The true depth there is at most 2, and `max_stack` is at least 8.
- **Planned change set** (each also a batch on `xax_android.xax` and the driver, mapped by CID):
  1. F38: at B87, a catching ABI (length > 6, ending `-catch`) continues with P1064 − 6, and `mb[18]` = 1, else 0.
     After the outputs loop, check that the last machine output is `jvm-ref:Ljava/lang/Throwable;` and take one off
     `fm_mout`.
  2. F53 `_foreign_node`: allow two machine results when `mb[18]`. Bump `C_READS` of both, so pass 2 never keeps
     them on the operand stack. Then push, in this order:
     `K_FOREIGN mb`, `K_BRANCH goto Lok`, `K_MARK H`, the throwable's store (or `pop` when unused), the result's zero
     and its store, `K_BRANCH goto Ljoin`, `K_MARK Lok`, the mask and the result's store, `aconst_null` and the
     throwable's store, `K_MARK Ljoin`. Labels come from `_fresh` (`2 NB + 1 + M_LABELN`), and the pair (H, invoke
     length 3 or 5) is appended to state words 98–99. The fixed layout `invoke; goto` puts the protected range at
     `[H − 3 − len, H − 3)`.
  3. The emit pass: reset the list count at its start, because pass 1 and every pass-2 retry re-emit.
  4. The record (`jk_record`): `_copy_words` allocates `nframes + 1`, so its last word is free. Store there a
     pointer to the entries `n, (start, end, handler)…`, resolved through `C_LABELS`, or NONE.
  5. F12: a frame whose offset is a handler becomes `same_locals_1_stack_item` (64 + delta, or 247 and u2 delta) with
     `Object java/lang/Throwable`, or a full frame with one stack item when it is the first. The exception table is the
     entries, with catch_type the Class `java/lang/Throwable` (`jp_ref1(pool, 7, jp_utf8(…))`, as F12 already does
     for `StackMapTable`), instead of u2 0.
  6. The two analyses that treat `INTERNAL_LABELS` nodes specially: definite assignment (the old `emit.py` `da_*`,
     "a label inside it") and interference (the old `method.py` `in_*`, unions into `M_ACROSS`). They must treat a
     catching call as such a node, or a typed local unassigned at H, Lok or Ljoin breaks the uniform frame. **Not
     found yet:** no view compares the operation against 23, 49, 59, 50 and 60 (`ATOMIC_CMPXCHG`,
     `UINT_TO_FLOAT`, `SINT_TO_FLOAT`, `FLOAT_TO_UINT_TRUNC`, `FLOAT_TO_SINT_TRUNC`) together, so the node operation
     there is probably not the `Operation` number. Next: find `_eop` (the node's operation field) in F53's
     dispatch and search for its codes. The candidates are F31, F34, F5 and F89 (F89 inlines `_analyses`). The check
     must call no rejecting function before lowering: a cheap ABI suffix test on the carrier, not F38.
- **Searches already done for item 6 (all negative):** no view holds the five operation constants within 200 lines
  of each other, and none holds their bit mask (`1731071106778923008`). F53's own dispatch does compare `Operation`
  numbers (42 at view line 174), so the analyses probably read a per-operation table instead of comparing. Counting
  `constant 57` (the old `M_ACROSS` word) finds operation numbers too, so trace the analyses F89 calls after it allocates
  `M_ACROSS`/`M_FRAMED` (view line ~8,771: F56, F10, F40, then the others) instead of grepping for constants.
- **Tests and oracle:** unchanged from the plan (`test_xax_selfhost_jvm.py` byte equality without catching calls; JBR
  execution for the four member behaviours; C1 and the 198-case differential).
- **Next step:** locate item 6, then write batch 1 (F38) and batch 2 (F53) on `jvm-catch-emit` from `release/0036`.
  Then items 3–6, the android and driver batches, and the tests. Land all of it as one PR into the release.

## #49 parts 2+3 done: the JVM program lowers catching calls — 2026-11-16

PR [#93](https://github.com/MrxSiN/XAX/pull/93) (`jvm-catch-emit`, commit `d33546d`) went into `release/0036`, which
is now `e5de5e5`. Merged by the agent on the owner's standing instruction once its tests passed. It completes the plan
of the two sections above, with these differences from that plan.

- **Ledger 0036 c to g:** five steps, each one transaction on `xax_jvm_general.xax` (`-jvm`), `xax_android.xax`
  (`-android`) and the driver (no suffix); 15 in all, and the request is re-derived.
  - c: a new function `jk_catching(c)`. It is F38's own payload parse (its first 87 blocks, which issue no
    diagnostics) followed by a `-catch` suffix test. F10 (interference) and F13 (definite assignment) call it, and
    only for operation 42, so they treat a catching call like an `INTERNAL_LABELS` node. The anchor search of the
    earlier section failed because bits64 is not `T0` in F10 and F13. Search views type-agnostically.
  - d: F38 (`jk_member`): at B87 the flag, the ABI length minus 6 for every later chain, and `mb[18]` = flag (the
    record's spare word). At B723 the arity compares outputs minus the flag.
  - e: F53 (`jl_node`). Two guarded regions are inserted before B1238 (the result's keep) and B1256 (the K_FOREIGN
    push), and the results loop runs over nres minus the flag. Run order: invoke; mark E; mask; store the result;
    aconst_null; store the throwable; goto J; mark H; store the throwable (or pop); the result's zero and its store;
    mark J. V_SINGLE is cleared for both outputs. Three fresh labels are taken; C_TARGET[H] = 2, plus 4 for a 5-byte
    invokeinterface.
  - f: F41 (`jc_mark`) ORs in its target bit. F52 (`jk_record`) scans the labels and stores `n, (E − 3 or 5, E,
    H)…` in the class store, and puts the pointer in the word after the copied frames (`_copy_words` allocates
    count + 1). F12 (`_serialize_method`) treats a frame whose first instruction pops (astore, astore_n, wide astore,
    pop) as a handler: every other frame has an empty stack. It writes it as a full frame with one stack item
    `java/lang/Throwable`, takes the record's entries in frame order, and declines on any mismatch. The exception
    table replaces u2 0.
  - g: F89 (`jk_method`; in the driver, its own copy) sizes the label table 2·blocks + 2 + 3·nodes.
- **Why the first layout failed:** a `goto` with the result still on the stack reaches a frame whose stack is empty.
  The result must be stored before any branch, so the range is marked by a label, not by an offset from H.
- **Function numbers change after every transaction.** Callers of a changed function get new CIDs. A function's CID
  is the same in every store that holds it (its body and its callees' CIDs are), so a CID found in one store finds the
  function in the others. The driver lacks F14, F89 and F9 and has its own versions; its F89 is F882 at root `004a7d07…`.
- **Tests (EXECUTED, WSL 2, `XAX_REQUIRE_NATIVE=1`; JVM runs on the Android Studio JBR through WSL interop, with
  `XAX_JAVA` and `XAX_JAVA_TMP` set):**
  - `test_jvm_catch_run`: 8 of 8 programs right (result, throwable text, exit status 4 or 7). They cover returns, a
    nested throw, a checked exception and an Error, plus invokevirtual and invokeinterface with and without a throw.
  - Store regeneration, `test_xax_selfhost_jvm` (byte equality), the catch tests, `test_xax_selfhost_android_jvm` and
    `test_xax_selfhost_general_build`: 110 passed, 137 skipped, 1 failed. The failure is the known
    `test_callback_programs` subtest (no JDK jmods in WSL), and it fails the same way on the release's stores.
  - C1 (`/root/work/c1-catch/C1`) verifies the three stores. The corpus differential, seed against C1: 0 of 198 differ.
    `evolve.sh check` passes.
- **Logs:** `/root/work/logs/{catch-targeted2,catch-apply,c1-catch,diff-catch,catch-run}.log`. The scratch generators
  are in `/root/work/catch` (`vt.py`, `em.py`, `chain.py`, `mk_*.py`, `build.py`) and are not committed.
- **Seeds:** unchanged (Linux `36e2b756…`, Windows `ae43e32f…`). The release is not rotated.
- **Open:**
  - F38 does not check that the throwable output is `jvm-ref:Ljava/lang/Throwable;`. A wrong type gives a JAR that
    fails to load with a VerifyError.
  - Part 6: DEX still rejects exception tables (`DEX-EXCEPTION-TABLE`), so Android builds of catching calls decline.
  - Part 7 on ART (Pixel) waits for part 6.
- **Next step:** part 6 on a new branch from `release/0036` (`xax_dex_jvm.xax`: a `try_item` and an encoded handler
  whose code starts with `move-exception`). Then ART on the Pixel, #48, C-cap, and the release.

## #49 part 6, issues #95 and #96, release 0036 done — 2026-11-18

`main` = `9720d90` (release PR [#101](https://github.com/MrxSiN/XAX/pull/101)). Merged by the agent under the owner's
standing merge authority once each PR's tests passed:
- [#97](https://github.com/MrxSiN/XAX/pull/97) (DEX lowering) into `release/0036`;
- [#98](https://github.com/MrxSiN/XAX/pull/98) and [#99](https://github.com/MrxSiN/XAX/pull/99) into `main`;
- [#100](https://github.com/MrxSiN/XAX/pull/100) (rotation) into `release/0036`;
- [#101](https://github.com/MrxSiN/XAX/pull/101) (the release) into `main`.

Issues #49, #95 and #96 are answered and closed. Still open: #47, #48, #51, #55.

- **#49 part 6 (#97, ADR-409, ledger 0036 dex-catch a–c).** Each step is a transaction on three stores: `-dexjvm` or
  `-dexwriter`, `-android`, and the driver (no suffix).
  - a: `dj_stack_map` accepts a full frame with one stack item. `dj_translate` makes each handler pc a target
    (`targets[h] = 2`); there it pushes the throwable, emits `move-exception`, and records `targets[h] = 4 + unit`.
  - b: `dj_method` parses the exception table into globals `STATE_AT + 48` (entries) and `+ 49` (count), accepting
    only a Class catch type named `java/lang/Throwable`. After the last pass it appends the tail units and emits
    code flag 2.
  - c: the writer entry keeps the flag at `us[2·nu]` and writes `tries_size`, `insns_size` and every unit but the
    last two. This is writer F15; it is Android F465 and driver F1012, all with CID `f8b84da3…`.
  - The record tail is in ADR-409. `an_entry_desc` walks it unchanged.
- **#96 (#98):** sign extension is the exact composition of docs/03 §4.2, tested on both executors. A dedicated
  operation stays a §21.5 admission.
- **#95 (#99):** floats are written with native `xaxc edit` batches: `object 4 0x0701`, `form7` type lines, IEEE
  constant bytes, and `object 6` declarations, as documented in docs/09 §16. `xax_construct.py` was not extended
  (AGENTS.md, ADR-405).
- **Release 0036 (#100):**
  - seeds: Linux `92375288…`, Windows `8f0d23e1…`;
  - `RELEASES` reads `validated 0036 evidence=88ae1a59…`; `rotate.sh state` reads `profile released`;
  - results in `XAX_STATE.md` (2026-11-18).
- **OI-61 (new):** the JVM program does not check a catching declaration's throwable output type. A wrong type gives
  a `VerifyError` at load, never a wrong value.
- **Calls made (recorded):**
  1. **#48 not started.** It needs a v3 carrier, native carrier decoding and Android-program and driver transactions.
     Its oracle is a `system_server` hook on the owner's Pixel and a reboot, which was not installed unattended.
  2. **C-cap (OI-54 steps, OI-52 R2) deferred.** It is multi-release layout work, so release 0036 shipped C-jvm only.
  3. **ADR-408's pin retirement deferred to a PR on `main`.** That covers `SEED_SHA256`, `windows/seed.json`, the
     AGENTS.md seed rule, and pointing `bootstrap_status` at the V2 levels. Eight Python consumers read the pins, so
     this release updated both pins and the V1 records as release 0033 did, and committed the V2 record beside them.
  4. **The DEX handler is catch-all with fixed-width LEB128** (ADR-409), checked by `dexdump` and ART.
  5. **V2 needs a `SNAPSHOTS` line for each release's request.** The first `validate` refused, with B1–B6 at 0, until
     the reference oracle's line for the 0036 request was added in its own commit. A diagnostic showed the record
     needed nothing else.
  6. **Intermediate driver blobs of #93 were never committed.** The BBC rebuild replayed the driver from the batches
     instead, and checked each blob against the LEDGER.
  7. **A WSL VM restart killed the first V1 full run.** The rerun used a log named per run
     (`rel0036-full-v1b.log`).
- **Unexplained:** the corpus differential counts 197 cases where earlier runs had 198. It was not investigated.
- **Runs in progress:** none.
- **Logs:** `/root/work/logs/rel0036-*.log`, `dex-*.log`, `c1-dex.log`, `diff-dex.log`. The scratch generators are in
  `/root/work/dex` (`mk_jv.py`, `mk_wr.py`, `build_dex.py`) and `/root/work/rel0036`; they are not committed.
- **Exact next step:** a PR on `main` for the ADR-408 retirement:
  - every Python reader of `SEED_SHA256`/`SEED_SIZE` and `windows/seed.json` reads the pin from the native rotate
    tool's `pin` (from `RELEASES`), then the two pins are deleted;
  - `bootstrap_status` derives B0–B6 from the native `levels` of the latest validated V2 record;
  - AGENTS.md's seed rule names `rotate.sh` and drops `rotate-seed`;
  - also fix the stale `xax_selfhost.py` entry in the Python authority inventory (it fails on `main` since 978bd60).

  After that: OI-61, #55 (command budget: `compile.xax` and `bbc.xax`), #48, C-cap, and native oracle slice 3.

## ADR-410 pin retirement, OI-61 and #55 on release 0037 — 2026-11-18

`main` = `d605a6b` (PR [#103](https://github.com/MrxSiN/XAX/pull/103)). `release/0037` = `47e5451`, cut from `main`
at `d605a6b`, with PRs [#104](https://github.com/MrxSiN/XAX/pull/104) (OI-61) and
[#105](https://github.com/MrxSiN/XAX/pull/105) (#55). Each was merged by the agent under the standing merge
authority once its tests passed. The seeds are unchanged (Linux `92375288…`, Windows `8f0d23e1…`); release 0037 is
not built, confirmed or rotated yet.

- **ADR-410 (#103, on `main`).**
  - `SEED_SHA256`/`SEED_SIZE` and `bootstrap/windows/seed.json` are deleted; `xax_selfhost_seed.pin()` reads the pin
    with the native rotate tool (built from the seed once per process, 0.04 s).
  - `bootstrap_status` is `xax_selfhost_seed.bootstrap_status`, from `xax_evidence levels` of
    `bootstrap/evidence/records/<latest validated>.record`.
  - `reference/xax_selfhost.py` is now only the V1 oracle (inventory class C), which fixes that inventory test's
    baseline failure.
  - AGENTS.md's seed rule names `rotate.sh build`, `confirm`, `run.sh` and `validate`; `rotate_seed` and
    `write-request` are gone.
  - The status blocks and every pin read need Linux x86-64.
- **OI-61 (#104, ledger 0037 `jvm-throwable`).**
  - It is three transactions: `-jvm`, `-android` and the driver.
  - `jk_member` is F68 in `xax_jvm_general.xax`, F325 in Android and F705 in the driver (CID `b1db2f96…` before;
    the OI-61 text's "F38" was wrong). A guarded region before B723 runs `jk_matches` (F71/F339/F736) on the last
    machine output against `Ljava/lang/Throwable;` and sets `mb[18]` = 2 on a mismatch, so B723's arity check
    rejects with `JVM-FOREIGN-ARITY`.
  - Generator: `/root/work/oi61/mk_oi61.py` (scratch, on `catch/chain.py`).
  - Checks:
    - the new `test_xax_jvm_program_rejects_another_throwable_type` fails 6 of 6 on the old stores and passes on the
      new ones;
    - `test_jvm_catch_run` still passes on the JBR;
    - store regeneration, `test_xax_selfhost_jvm`, `test_xax_selfhost_android_jvm` and `test_dex_catch_run`: 84
      passed, 1 failed (the known `test_callback_programs`);
    - C1 `e61543f9…` verifies the three stores, and the 198-case differential seed against C1 shows 0 differences.
- **#55 (#105, `integration/bfx/transactions/budget/`).**
  - The budget is N = 524,288. The record view is N + 10 (a new type, `3e380ee0…`) and the decoder scratch 8N (the
    existing type `6dff1135…`).
  - It is one batch each on `compile.xax`, `bbc.xax` and `bbc_request.xax`. Each defines the changed functions under
    new names and replaces only the top caller (F103; F1 in `compile.xax`). The README lists per function what
    changed.
  - Found on the way: the hosts' `VirtualFree` declarations embed the view type in their bodies (`object 6`), so the
    record one is supplied anew.
  - Generator: `/root/work/b55/mk55.py` (scratch).
  - Checks: `bbc.exe` `e1fb321b…` passes all six ThreadsHideAds programs and the N/N+1/bracket edge cases;
    `check.py` shows 372 of 372 compiles and 0 mismatches. `COMPILE.md` has the details.
- **Calls made (recorded):**
  1. #55's batches go on `release/0037`, not `main`, because the release rebuilds `bbc.xax` from the released
     driver, and a `main` change would conflict with that binary.
  2. N = 2^19, not the 1 MiB source limit. A smaller decoder scratch (4 MiB) keeps the capacity path reachable and
     testable.
  3. The standalone `bfx.xax`, `import_bfx.xax`, `pack.xax` and the Android hosts keep 65,536 (YAGNI). The issue
     names only `compile.xax` and BBC's stores.
  4. BBC's fixtures wait for release 0037 on `main`, because BBC pins exact XAX commits.
  5. #55 stays open (progress comment posted). OI-61 closes when release 0037 reaches `main`.
- **Open:** #47, #48, #51, #55, OI-61 (fixed on the release branch), C-cap, and native oracle slice 3.
- **Next step:**
  1. #48: write the v3 carrier design (an ADR). The carrier is `android-libxposed-jvm-module-v3` with optional
     `onModuleLoaded`/`onSystemServerStarting` entries; its native decoding goes in the Android program and the
     driver (a transaction on `release/0037`). Installing a `system_server` hook on the Pixel needs the owner: record
     it as BLOCKED.
  2. Then C-cap and native oracle slice 3.
  3. Then release 0037: `rotate.sh build 0037`, `confirm` both targets, `run.sh`, the SNAPSHOTS line,
     `validate`, rebuild BBC, `check.py`, the Pixel session, the full suite, and the release PR.
  4. After that, BBC's fixtures and pin.

## #55 at 1,048,576 and the #48 design — 2026-11-18

Supersedes the 524,288 budget in the section above. `release/0037` = `95c35fd`; `main` = `e674dd9`.

- **#55 (PR [#107](https://github.com/MrxSiN/XAX/pull/107), on the owner's request):**
  - The budget is now 1,048,576, the source limit. The record is 1,048,586 bytes and the scratch 8,388,608.
  - It is batch step 2 in `integration/bfx/transactions/budget/` (generator `/root/work/b55/mk55b.py`, scratch).
  - `bbc.exe` `31c90bae…`: 1,048,576 `+` passes; 1,048,577 exits 2. Overflow beats a bracket error through the
    frame's 1 MiB check. ThreadsHideAds is unchanged. `check.py` shows 372 of 372 compiles and 0 mismatches.
  - BBC's overflow fixtures become 1,048,577-byte sources once release 0037 is on `main`.
- **#48 (PR [#108](https://github.com/MrxSiN/XAX/pull/108), ADR-411, proposed):** the v3 carrier with `entries` by
  function CID, closure roots for every entry, and two more `Module` forwarding methods. The device check is
  BLOCKED on the owner.
- **Next step:**
  1. ADR-411's native steps on `release/0037`: the Android program's record parse and `Module` methods, then the
     JVM closure roots, then the driver copies. Check each with C1, `dexdump` and ART.
  2. Then C-cap and native oracle slice 3.
  3. Then the release 0037 run, then BBC's pin and fixtures.

## ADR-411 (#48) mapped in the native programs — 2026-11-18

Read-only; no store changed. Old builder sources, a map for reading views and never a generator: `git show
4a5d4b8^:compiler/src/xax_selfhost_android.py` (lines ~5560–5700) and `git show f6d5b08:compiler/src/xax_selfhost_jvm.py`.

- **Android program, JVM-module path (J2–J3).**
  - It lowers the entry through the JVM layer (class `xax/P<entry CID's first 16 hex>`).
  - It reads the `entry` method's descriptor back from the lowered class (`an_entry_desc`) and rejects
    `LIBXPOSED-JVM-ENTRY` on a mismatch.
  - Then it writes the `Module` bridge: one method `onPackageReady`, 2 registers, `invoke-static {v0, v1}` of
    `entry`, then `return-void`. A lifecycle entry adds the same block with its parameter type and method name, and
    the method count goes from 1 to 1 + entries.
  - The managed profile already knows `onModuleLoaded` (`CALLBACKS`, line 124), but that is another path.
- **JVM program.**
  - The closure is walked twice from one `entry`: `jf_scan` (the bootstrap's rejection order, a LIFO stack seeded
    with `entry`) and the depth-first frame walk (`_push(entry)`).
  - Methods are `entry` and `f<k>` in closure CID order.
  - Multiple roots: seed both walks with every root.
- **Open design point for ADR-411 (4).** The Android program must find each lifecycle entry's method. Either the JVM
  layer takes (root CID, method name) pairs and names extra roots `xaxOnModuleLoaded`/`xaxOnSystemServerStarting`,
  or it reports each root's `f<k>`. The first keeps `an_entry_desc`'s lookup by name and needs no new output, so
  prefer it. The layer's input words (where the entry CID is passed today) gain a root count and the pairs. Write
  this as an ADR-411 amendment before the first transaction.
- **Order:** the JVM program's roots (`xax_jvm_general.xax`, Android's and the driver's copies, mapped by CID), then
  the Android program's v3 parse and `Module` methods. Check each with C1, `dexdump` and ART. The device check
  stays BLOCKED.

## ADR-411 implementation: the entry-word question — 2026-11-18

Read-only; no store changed. ADR-411's amendment (#111) runs the JVM layer once per lifecycle entry. Before the first
transaction, settle how that run gets its entry:

- The JVM program finds its entry with `find(1)`, which reads the CID at word 1 of the program's input view
  (`rd`). The Android program never writes that view. In the old builder (`git show
  4a5d4b8^:compiler/src/xax_selfhost_android.py`, J2 around line 5500) the JVM layer is called directly, without
  `G_INBASE`.
- Option A: write the lifecycle CID's words into input words 1..4, run the layer, then restore them. This needs the
  input view's type to allow stores (it has the same `04 81 02 01 04` flags as the writable views; check it), and
  every later phase must see the restored table.
- Option B, preferred: a small JVM-program transaction. `find(1)` becomes `find(entry_at)`, with `entry_at` a
  global word (default 1 when it is 0) that the Android program sets to a memory copy of the CID. But `find` takes
  an input position, so it would first need a variant that matches a CID held in memory. Size that change first.
- Useful facts:
  - The Android program keeps its variables in memory slots (`SLOT_AT` = `CO_AT + 4096`, `CO_AT` = 252 MiB),
    so regions can read and write them without block parameters.
  - Texts are `K(value)` handles at `G_K + index` (`CO_AT + 64`), written once at the start. New texts (the v3
    prefix, `entries`, the two parameter types and method names) can be built inline, as OI-61 built its text.
  - `an_jparse`/`an_jin`/`an_jhex` parse the record.
- Dumping all 484 views of `xax_android.xax` takes over an hour. Find the J1–J3 phase functions with the reference
  reader instead (walk up from a distinctive constant, for example `0x71` beside `0x0E` in the Module bridge, or
  `CO_AT`-relative slot stores).

## #48 libxposed lifecycle entries on release 0037 — 2026-11-18

Supersedes "ADR-411 implementation: the entry-word question" above. `release/0037` = `f55ed07`; `main` = `3aa3f7a`.
Issue #48 is closed.

- **Decision (ADR-411 amendment 2, #115):** option A cannot verify (the input view's pointer type is read only). The
  JVM main's `find(1)` uses the input position in word `CO_AT + 24` when it is nonzero. The Android program gets
  J0b (before J1: a v3 carrier is shown to J1 under the v1 or v2 branding rule) and J2b (after J2: `entries`, then J2
  again per entry with its CID, descriptor and input position swapped in), and J3 writes 1 + entries `Module`
  methods. J1 and J2 are not edited.
- **Transactions:**
  - #113: `0037-lifecycle-a` on the JVM, Android and driver stores.
  - #114: `-b` and `-c` on Android and the driver, plus `tests/test_libxposed_lifecycle.py`. b and c share one PR,
    because b alone builds lifecycle classes with no forwarders.
- **Function map (pre-0037-lifecycle numbering):**
  - Android: main F116, J1 F70, J2 F403, J3 F234, JVM main F207.
  - Helpers: `put` F431, `text` F158, `an_dtext` F429 (raw in word 268435424), `an_jget` F412, `an_jhex` F101,
    `an_prefix` F371.
  - Driver: main F281, J2 F894, JVM main F649.
  - Slots: `entry` 10, `lid` 14, `kids` 26, `managed` 55, `lowered` 916, `jv_cdesc` 926, `jv_desc` 927. Slots
    0–1007 are used; the new phases use `SLOT_AT + 2000` on.
- **Evidence (EXECUTED):**
  - C1 verifies all changed stores; corpus differential seed vs C1: 197 cases, 0 differ.
  - The targeted suite passes but the baseline `test_callback_programs`.
  - `dexdump` and the ART harness on the Pixel pass.
  - LSPosed (Vector v2.2, Android 17) after a reboot: `org.xax.lifecycle: onModuleLoaded ran` and
    `onSystemServerStarting ran` from `system_server`, in `/data/adb/lspd/log/modules_*.log`.
- **Device notes:**
  - logcat's main buffer (256 KiB) rotates seconds after boot. Vector's persistent module log keeps only its own
    tags, so a test module logs through `XposedInterface.log` with tag `VectorModuleManager`.
  - The wireless adb port changes on each reboot: pick the serial from `adb devices` each time.
- **Next step:**
  1. C-cap and native oracle slice 3.
  2. Release 0037: build, confirm both targets, V2 evidence and the SNAPSHOTS line, validate, rebuild BBC,
     `check.py`, the Pixel session, the full suite, the release PR.
  3. Then the consumer (SyncthingLiveUpdate's `PromotionPolicyPatch`) on the released compiler.

## Native oracle slice 3 done; C-cap moved to the next release — 2026-11-18

`main` = `3ae5c16` (PR #117). `release/0037` is unchanged at `f55ed07`.

- **Slice 3 (stack memory):**
  - The native oracle runs `stack.alloc`, `address.offset`, `store`/`load.bits.le`, `stack.end` and
    `checked.load`/`store.bits.le`, with pointer, effect and resource values.
  - A checked access out of its allocation, or misaligned, traps `memory-check`.
  - Allocations take zeroed words from the frame stack (global 2) and are released when their frame returns. A
    pointer is (data address << 32) + offset, and the extent is the word before the data.
  - New functions `@mem` and `@opx` (scratch globals 900–939). `@exec`'s trap block takes the code: 2 is a
    division, 3 is `memory-check`, 4 is an error.
- **Evidence (EXECUTED):** 646 of 646 stack-memory cases agree (`benchmarks/oracle_memory_evidence.json`), and the
  earlier areas still agree (24 tests, 8,033 subtests). `test_xax_byte_view_widening` now uses the native oracle on
  Linux x86-64. NOT RUN: the Windows side, which keeps the Python executor.
- **The design's slice-3 test list was wrong in two places, now corrected:**
  - `test_xax_x86_64_views` needs slices 1 and 4.
  - `test_xax_pointer_rebase` runs executables (target addresses, `mmap`), so it never compares with `execute`.
- **Still declined:** `pointer.address` and `pointer.rebase` (target-only, also in Python), heap views and
  growable accesses. Their programs reach memory through foreign `mmap`.
- **C-cap (OI-54, OI-52 R2) moved to the next release**, on the owner's decision. It spans the semantic index, the
  edit engine, the x86-64 arena, AArch64 liveness, typing and both backends, and OI-52 R2 needs an ADR first.
- **Next step:**
  1. Release 0037 as it stands: build, confirm both targets, V2 evidence and the SNAPSHOTS line, validate,
     rebuild BBC, `check.py`, the Pixel session, the full suite, the release PR.
  2. Then the next release, starting with C-cap's ADR.
  3. Oracle slice 4 (aggregates, sums, floats) is independent and can go to `main` at any time.

## Release 0037 rotated — 2026-11-19

`release/0037` + PR #119 (`rotation-0037`). Owner's instruction for this run: work autonomously overnight, make
reasonable calls and record them here.

- **Rotation (EXECUTED, WSL 2):**
  - `rotate.sh build 0037`: Linux seed `8e0a4cf3…` (31,811,019 bytes), Windows `06ece4cf…` (31,864,320).
  - Confirmed on both targets.
  - `evidence/run.sh` full: the ledger replay passed 189 of 189.
  - `rotate.sh validate`: `validated 0037 evidence=82fccd30…`, with B0–B6 holding.
  - The SNAPSHOTS line `f4b649c8… d6fc3dc7…` is in its own commit. Status blocks were re-derived.
- **BBC:**
  - `bbc.xax` and `bbc_request.xax` follow the four 0037 driver transactions. The driver was replayed from
    `2cd6c8f…`, because the state between lifecycle b and c was never committed, and each blob was checked against
    the LEDGER.
  - `bbc.exe` `4b73ad61…` (36,109,312 bytes) was built by the new Windows seed.
  - `check.py`: 372 of 372 compiles, 488 runs, 0 mismatches, 5 of 5 error paths.
  - On the Pixel, BBC's Android outputs match qemu in 14 of 14 cases.
- **Full suite:** 33 failures in the full run (`-n 2`, 2 h 36 min). It overlapped validation and the status
  regeneration, so state tests saw a half-finished release. Rerun on the final tree: everything passes but the
  baseline (Wasm 3, OI-16 2, OI-06 2, the B1 binding, `test_callback_programs`) and the two V1 records, which
  describe the old seed until they are regenerated.
- **Calls made:**
  1. The first full suite at `-n 4` ran alongside the evidence replay and exhausted WSL's memory (0 GB available).
     I stopped it so the replay would survive and reran it at `-n 2`.
  2. The V1 records (`bench_python_free_seed`, `bench_full_selfhost`) are regenerated as in release 0036, because
     their tests still read them.
  3. `test_rotate_tool`'s fictional lifecycle moved to 0038 and 0039.
- **V1 records regenerated (EXECUTED):** `python_free_seed_evidence.json` (392 s) and `full_selfhost_evidence.json`
  (11,390 s); their tests and `test_status_docs` pass (11 of 11).
- **Next step:**
  1. merge #119 into `release/0037`;
  2. the release PR `release/0037` → `main` (#48's lifecycle entries reach `main`);
  3. BBC's pin and its 1,048,577-byte overflow fixtures (#55) once 0037 is on `main`;
  4. then C-cap's ADR for the next release.

## Release 0037 on `main`; #55 closed; C-cap designed — 2026-11-19

`main` = merge of #121 (release 0037) plus #120 (ADR-412). `rotate.sh state`: `validated 0037`, `profile released`.
Seeds: Linux `8e0a4cf3…`, Windows `06ece4cf…`. Open issues: #47, #51. The owner asked for an autonomous run; the
calls below were made without asking.

- **Release 0037 merged** (#119 into `release/0037`, then #121 into `main`).
  - `main` had gained #115–#118 and #120 meanwhile, so the release branch got a merge of `main` first. The only
    conflict was this file's appended sections, kept in date order.
  - The section I had appended from WSL had CRLF lines, but the repository stores this file LF (the Windows
    checkout converts it). A follow-up commit normalized it, so the diff is just the new text.
- **#55 closed** with the release evidence. BBC's capacity fixtures moved to the 1,048,576 edge (MrxSiN/BBC#6,
  merged), and its docs state the new budget.
  - EXECUTED: 1,048,577 commands exit 2, and 1,048,576 with an unmatched bracket exit 1, at `check`,
    `emit-bfx -O0` and `-O1` (BBC `evidence/instruction_cap_2026-11-19.json`, `bbc.exe` `4b73ad61…`).
  - NOT RUN: the ThreadsHideAds programs (no checkout on this host).
- **ADR-412 (proposed, #120):** C-cap for the next release.
  - OI-52 R2: checked and growable offsets may be `bits<64>` under the same bound. JVM, Wasm32, RISC-V and SPIR-V
    reject them.
  - OI-54's three limits, in the order a build meets them.
  - Before R2 lands, the native oracle's `@mem` must evaluate the bound without a 64-bit wrap.
- **Calls made:**
  1. BBC has no machine-readable XAX pin file. I did not invent one; BBC's evidence names the XAX commit (`bfddb32`)
     and the `bbc.exe` hash. Adding a real pin (one file, read by BBC's tools) is a small BBC change for later.
  2. The full suite ran once alongside the evidence replay, and state tests were rerun after validation (see the
     section above).
- **Next step (a new release branch from `main`, ADR-404):**
  1. Cut `release/0038`.
  2. Fix the oracle bound first, on `main` (ADR-412 (4)).
  3. OI-52 R2: verifier/facts and typing programs, then the x86-64 general backend (64-bit compare), then AArch64.
     Each is a ledger sub-batch with C1, plus C2 for x86-64.
  4. Then OI-54 step 1: the semantic index's graph-stream region, the edit engine's body limit and the decoder's
     body view.
  5. Oracle slice 4 (aggregates, sums, floats) is independent and can go to `main` at any time.

## C-cap: OI-52 R2 on `release/0038`, sub-batches a–c — 2026-11-19

`main` = merge of #123. `release/0038` was cut from it and holds #124–#126. The seed is still release 0037's
(`validated 0037`). The owner asked for an autonomous run, so the calls below were made without asking.

- **#123 (on `main`), ADR-412 (4):** the native oracle's `@mem` checks a checked access as
  `ptroff + size > extent` or `dyn > extent - (ptroff + size)`, so the bound never wraps.
  - New probes in `test_native_oracle` use a `bits<64>` offset near 2^64 on an unverified store. The old oracle
    fails 7 of them.
  - `_stack_callee` takes an `offset_type`.
- **#124, sub-batch a (ledger `0038-checked-offset64`, `-typing`): the verifier.**
  - The four facts functions of the checked forms (typing F25, F33, F61, F74, the same objects in the driver) accept
    width 32 or 64 as `((width - 32) & ~32) == 0`.
  - The renderer (typing F1) writes the expected value as `[32, 64]`.
  - The Python reference verifier and `src/xax_selfhost_facts.py`'s site table say the same. Python decodes
    host-side records with that table, so it had to change too; these are two literals, not new logic.
- **#125, sub-batch b (`0038-checked-offset64-frame-{a,b}`, `-x86-64`): the x86-64 frame path.**
  - The register path already compared a 64-bit index.
  - The frame path loaded the index with `mov r10d` (4 bytes). Its three `frame_access(0x8B, r10, slot, 4)` sites
    (`fr_memory` once, `fr_tail` twice) now load 8 bytes.
  - That is three `const` mutations. Values stay zero-extended in slots (ADR-393), so `bits<32>` reads the same.
  - The reference `xax_x86_64.py` has the same three sites and changed with them, because the general-build tests
    compare bytes.
- **#126 (test only): AArch64 needs no change.**
  - Under qemu-aarch64, 14 of 14 probes pass on both paths, built in-process and by C1/C2.
  - Under Unicorn, the Android ARM64 stack probes give 0 mismatches.
- **Gates (EXECUTED, WSL 2):**
  - C1 of a against the seed: 197 of 197 corpus cases identical.
  - b: C2 = C3 (fixed point). C2 passes 14 of 14 x86-64 probes, and the seed rejects them at verification.
  - C2 against the seed on the corpus: one Windows load image differed once while another test run was going. Three
    reruns on each compiler are identical.
  - The driver tests were rerun with C1/C2 installed as `NativeGeneralDriver`, using the scratch
    `/root/work/r2/withc1.py`; it works without `-n`, because xdist workers do not inherit the patch.
- **Expected until rotation:** with the pinned seed as the driver, `test_xax_selfhost_verify_exact` program 124
  expects `32` where the reference now says `[32, 64]`.
- **Not reproduced:** `test_object_sites` failed once in a `-n 2` run. It passes alone with the seed, a's C1 and C2.
- **Open in R2: sub-batch d, the rejections** (ADR-412 (2)). With C1:
  - JVM (`jvm_classfile_memory_target`), RISC-V views and Wasm32 (`oi06`) all build a `bits<64>` offset.
  - Wasm32 emits an invalid module (an `i64` parameter compared with `i32.gt_u`), not a silently wrong one.
  - Each needs its own `*-CHECKED-OFFSET-BITS` rejection, natively and in its Python reference.
  - The renderers that write each backend's `*-OP-TARGET-SUPPORTED` text are driver F10 (JVM), F589 (Wasm, one
    straight-line function of 10,322 lines), F610 (RISC-V), and F744/F1033 (SPIR-V), as of the driver after #125.
    The rejection itself is set where each backend checks a node's operation against its target.
  - Scratch probes: `/root/work/r2/tprobes2.py` (heap views: RISC-V views, JVM), `tprobes.py` (stack: Wasm).
- **Next:**
  1. Sub-batch d.
  2. Then the release: `selfbuild.sh`, rotation, V2 evidence, and the Windows x86-64 and Android ARM64 device runs
     of `test_xax_oi52_r2`'s program (OI-52's closing evidence).
  3. Then OI-54 step 1.

## Release 0038 on `main`: 64-bit checked offsets — 2026-11-19

`main` = merge of #130 (`c3fdaab`). `rotate.sh state`: `validated 0038`, `profile released`.
Seeds: Linux `15b6c6d9…` (31,811,995 bytes), Windows `1aa1f9dc…` (31,865,344).
BBC pins it (MrxSiN/BBC#8). Open issues: #47, #51. The owner asked for an autonomous run, so the calls below were made
without asking.

- **Sub-batch d (#128): no new rejections.** I measured instead of assuming ADR-412 (2):
  - RISC-V views (`bgeu` on the whole register), the JVM (`Long.compareUnsigned` before `l2i`) and general Wasm32
    (`i64.gt_u`, then `i32.wrap_i64`) already lower a `bits<64>` offset correctly. SPIR-V rejects it as
    `SPIRV-VALUE`.
  - Their evidence tests are in `test_xax_oi52_r2`, and ADR-412 is amended and accepted.
  - The only wrong target is the legacy Wasm32 profile (`oi06`). Its module fails Wasm validation, so it never runs.
    That is OI-62. The fix copies F112's width lookup into F784, which was not tractable in this run.
- **Rotation (#129, EXECUTED):**
  - `rotate.sh build 0038` took 16.5 min; `confirm` passed on both targets.
  - The first `evidence/run.sh` gave B3 0. The frozen corpus case 167, a random Windows load image with one
    frame-path checked access, still had the 0037 bytes: one byte, `0x44` → `0x4c`, the intended index load. The
    expectation moved in its own commit, and the rerun (97 min, replay 195 of 195) validated:
    `validated 0038 evidence=b0b0d849…`.
  - The SNAPSHOTS line (`a7a4a1a0…` → `7afa1b98…`) is in its own commit.
  - The V1 records were regenerated: python-free seed 7 min, full self-host 194 min.
- **BBC:**
  - The driver follows the three 0038 driver transactions.
  - `bbc.exe` `0ec701ee…` (36,110,336 bytes) was built by the new Windows seed.
  - `check.py`: 372 of 372 compiles, 488 runs, 0 mismatches.
  - The capacity fixtures and all six ThreadsHideAds programs match (the latter cloned read-only at cf28f66).
  - BBC's `XAX_PIN.json` moved to `c3fdaab`.
- **OI-52 closing evidence:**
  - Windows x86-64 EXECUTED: the release's Windows seed builds the 5 GiB-view probes (`WindowsTests`, both paths).
    10 of 10 give the expected result natively on Windows 11; interop keeps only the exit code's low byte.
  - Android ARM64 BLOCKED: no adb device on 2026-11-19, and nothing on mDNS. The Pixel's wireless debugging needs to
    be on.
  - Linux AArch64 under qemu: 14 of 14 (an emulator run).
  - OI-52 stays open for the device run and for R3/R4.
- **Full suite** (`-n 2`, 2 h 36 min, on the final tree): 1,657 passed, 11 failed.
  - Two are the baseline: the B1 binding and `test_callback_programs`.
  - One was `test_rotate_tool`'s pinned release, fixed in #129.
  - Seven JVM/JDWP failures came only from `/root/work/bin`'s Windows-`java` wrapper on PATH. Without it they pass or
    skip.
  - The Wasm, OI-16 and OI-06 baseline failures did not reproduce, because node was on PATH through a wrapper.
- **Calls made:**
  1. RISC-V and the JVM accept rather than reject: they are correct, and rejecting would remove a working
     capability. The ADR amendment says so.
  2. The first full suite ran next to `bench_full_selfhost`. A worker reached 9.5 GB and left 1 GB free, so I killed
     the suite by PID and reran it after the bench.
  3. The ThreadsHideAds checkout is a scratch clone, never committed.
- **Next step:**
  1. The Android ARM64 device run of `test_xax_oi52_r2.AArch64Tests` with `XAX_AARCH64_ADB=1`, once the Pixel is
     on adb. Update `/root/work/bin/adb`'s serial. It closes OI-52 R2's evidence.
  2. OI-54 step 1 on a new `release/0039`: the semantic index's graph-stream region, the edit engine's 4 MiB body
     limit, and the decoder's body view (prepared as ledger 0021).
  3. OI-62 (legacy Wasm32 rejection) and oracle slice 4 can go at any time.

## OI-52 R2 on an Android device — 2026-11-19

Supersedes step 1 of "Release 0038 on `main`" above: the Pixel 8 Pro came back on adb (`adb-38021FDJG00610-…`).

- **EXECUTED on the device** (`XAX_AARCH64_ADB=1`, `/root/work/bin/adb` pinned to that serial):
  - `test_xax_oi52_r2.AArch64Tests` passes 14 of 14: an 8 GiB view answers 42 at its last byte and past 2^32, and
    traps (`brk`, SIGTRAP) at the edge and near 2^64, for one and five parameters.
  - The same probes built by the release's Linux seed `15b6c6d9…`: 14 of 14.
- The adb runner needs `/data/local/tmp/xax-exec-status`. WSL has no Linux NDK, so I built it with the Windows NDK
  (28.2, `aarch64-linux-android28-clang`) from `integration/android/exec_status.c` and pushed it.
- R2's closing evidence is complete (`XAX_OPEN_ISSUES.md`). OI-52 stays open for R3 and R4.
- **Next:** OI-54 step 1 on `release/0039`, then OI-62 and oracle slice 4.
- Step 1 is done: see "Release 0039 on `main`: OI-54 step 1" below.

## Release 0039 on `main`: OI-54 step 1 — 2026-11-20

`main` = merge of #144 (`a134f24`). `rotate.sh state`: `validated 0039`, `profile released`.
Seeds: Linux `5657768e…` (31,812,331 bytes), Windows `d4a433db…` (31,865,856). BBC pins it (MrxSiN/BBC9).
The owner asked for an autonomous run, so the calls below were made without asking.

- **What landed** (ADR-413; eleven driver transactions in five PRs into `release/0039`, #138–#142):
  - `0039-cfg-view-1g`: the CFG program's output view is 1 GiB (was 128 MiB).
  - `0039-index-section-region`: the semantic index's block section is 3M words at 29M–32M (was 1M at 23M).
  - `0039-decoder-body-8m`: the graph decoder's body buffers are 8 MiB (ledger 0021 regenerated).
  - `0039-edit-body-8m-a`…`-h`: the edit engine's body region is 8M + 64K words.
- **Measurements** (they replaced OI-54's list as the order of work):
  - Every command declined an O0 function past 22,238 instructions, the same for a `+` chain and for the hanoi
    prefix: the CFG program keeps n·⌈n/64⌉ dominator words beside its other tables, and that ran out of the 128 MiB
    view first. Found with a ptrace snapshot of every workspace view at the first `munmap`.
  - hanoi -O0's estimated streams: 1.2M node words, 2.1M block words, 2.8M edge words. The index's 3M-word node
    stream (OI-54 step 1's first item) is not binding for hanoi.
- **The ledger-0006 regression.** The first rotation's replay failed on ledger 0006 with `DRIVER-EDIT-CAPACITY`:
  #141 had moved the 16M-word preimage region to make room for the larger body. #142 puts the preimages back and
  moves the new-object table and the batch up instead; the second rotation replayed 206 of 206.
- **Rotation (EXECUTED):** `rotate.sh build 0039`, `confirm` on both targets, `evidence/run.sh` (replay 206 of 206),
  `validated 0039 evidence=32a05f79…`. The SNAPSHOTS line (`0a4b9fab…` → `771c15d8…`) is its own commit. V1 records:
  python-free seed 393 s, full self-host 12,843 s, three generations to the same bytes.
- **BBC:**
  - The driver follows all eleven 0039 transactions (`3e2e71a`). `rebuild.sh` applied the index and the eight
    edit-engine transactions. The CFG-view and decoder transactions replace the production entry, which is past
    `rebuild.sh`'s ceiling, so BBC's five Windows copies of it (its driver entry and the four step variants) each took
    one batch written from that function's view: the CFG view's `VirtualAlloc` length, view and `VirtualFree`; the
    three body buffers' lengths, views, bounds and capacities; the new CFG function and decode, defined once with the
    production CIDs. `0039-edit-body-8m-e` moves the batch base in a production host function that BBC's Windows
    layer replaces, so the same two `const` mutations went into BBC's five copies. No old edit-engine region constant
    is left in either store. The generators were scratch (`mkbbc.py`, driven by `bbc0039-entry.sh`), never committed.
  - `bbc.exe` `a3a1c70c…` (36,111,872 bytes) was built by the 0039 Windows seed from the rotated `bbc_request.xax`.
  - `check.py`: 93 programs, 372 of 372 compiles, 488 runs, 0 mismatches, 5 of 5 error paths.
  - The capacity fixtures are unchanged from 0038, and all six ThreadsHideAds programs match at O0 and O1 (a
    read-only clone at cf28f66).
  - hanoi -O1 builds (23.5 s on Windows 11); hanoi -O0 now gets past the front end and declines in the backend
    (exit 5 after 4.6–8.1 s): OI-54 step 2.
  - The CFG view's 1 GiB is reserved, not committed: hanoi -O1 peaks at 499 MB of commit with the 0039 `bbc.exe`
    and 495 MB with 0038's.
- **Full suite** (`-n 2`, 2 h 53 min, on the final tree): 1,660 passed, 11 failed.
  - The B1 binding is the known baseline (`test_callback_programs` passed this time).
  - Eight JVM/JDWP tests fail only with `/root/work/bin`'s Windows-`java` wrapper on PATH (`ClassNotFoundException`);
    without it they skip.
  - The two kept-generator pins (`test_store_regeneration`, `xax_selfhost_edit` and `xax_selfhost_semantic`) failed
    because 0039 changed edit-engine and index helpers natively. The helpers joined `NATIVELY_EVOLVED` (#143), and
    the file passes.
- **Still open:** OI-54 steps 2 (x86-64 per-value tables and `VCAP`) and 3 (AArch64 liveness); the 21,000×37 chain
  that declines after the facts engine, not located; the edit engine's body region has no bound check of its own
  (today's bodies cannot reach it: the decoder caps them at 8M − 4,096 words).
- **Calls made:** the previous session's bench pipeline woke at 18:30 and committed and pushed the V1 records itself
  (`75322ce`); nothing else ran from it, so I continued from that commit.
- **Next:** release 0040 (consumer issues #133–#137) on `release/0040`; see the next section.

## Release 0040 on `main`: consumer issues #136, #137, #133 — 2026-11-21

`main` = merge of #150 (`151013c`). `rotate.sh state`: `validated 0040`, `profile released`.
Seeds: Linux `3b84d518…` (31,819,377 bytes), Windows `c326f7c5…` (31,873,024). BBC pins it (MrxSiN/BBC10).
Supersedes the "Next" of "Release 0039 on `main`" above. The owner asked for an autonomous overnight run, so the
calls below were made without asking.

- **What landed** (seven driver transactions, three sub-batch PRs into `release/0040`, #146–#148):
  - #136 (#146, five transactions `0040-hex-digits-*`): every `0x` digit test in the batch parser reads `c|32`.
    Before, an uppercase digit ended the scan: an odd prefix was rejected, an even one silently made a **shorter**
    constant or object body (`0x401921FB54442D18` became 3 bytes). One function per transaction: two `replace`s
    whose functions share a caller (F158 and F982 under F1005) fail `verify` with `ID-REFERENCE-RESOLVED`.
  - #137 (#147, `0040-jvm-single-result`, ADR-414): the JVM program's signature function writes the reference's
    `XAX.JVM.ABI` / `JVM-SINGLE-RESULT` record (function CID; actual = the count) where it declined, so `build` of a
    JVM or libxposed module with a two-result function exits 1 with the record instead of 2 with nothing.
  - #133 (#148, `0040-libxposed-auto-hot-reload`, ADR-415): a v3 record's `"auto_hot_reload": true` adds
    `autoHotReload=true` to `module.prop`. The minimum API version needed no new field: it is the libxposed metadata
    carrier's `min_api_version`, which the native program already writes (tested with 101).
  - ADR-416 (#135, design only): `replace <CID> @name` for identity-only TARGETs.
- **How the native edits were made** (scratch tools, never committed, in the session scratchpad and `/root/work`):
  views patched as text and relabelled (`orpatch.py`: insert `v|32` before named consumers; `autohex.py` finds the
  consumers), new helpers written node by node with the existing load/store pattern (`rej137.py`, `ahr133.py`),
  callers spliced by one `call.direct` first in a block whose six view/token parameters it rebinds. Sites were
  found with `fconst.py` (a function's constants), `callers.py`, `anc.py` and the deleted generators in
  `git show 4a5d4b8^:compiler/src/...`.
- **Rotation (EXECUTED, WSL 2):** `rotate.sh build 0040` 804 s; `confirm` Linux 391 s, Windows 617 s; SNAPSHOTS line
  `cf3a6849…` → `4bd6d00f…` (reference resolver, 227 s) in its own commit; `evidence/run.sh` 6,652 s, replay 213 of
  213; `validated 0040 evidence=f1e8dc7b…`. V1 records: python-free seed 394 s, full self-host 13,150 s, three
  generations to the same bytes. The full self-host bench refuses an unpinned seed, so it runs only after `validate`.
- **BBC:** `rebuild.sh` applied all seven transactions to `bbc.xax` and its request (none names the entry or a host
  function BBC's Windows layer replaces); none of the seven replaced 0039 CIDs is left. `bbc.exe` `6737decc…`
  (36,119,040 bytes, 253 s) by the 0040 Windows seed. `check.py`: 93 programs, 372 of 372, 488 runs, 0 mismatches,
  5 of 5 error paths. Capacity fixtures and all six ThreadsHideAds programs: identical to 0039 (a scratch runner
  that reproduces 0039's `pin2.json` exactly). hanoi -O1 builds (23.2 s); -O0 exits 5 in the backend.
- **Full suite** (`-n 2`, 2 h 57 min): 1,665 passed, 9 failed: the B1 binding (baseline) and the eight
  JVM/JDWP tests that fail only with the Windows-`java` wrapper on PATH, the same set as 0039.
- **Issues:** #136, #137 and #133 closed with their evidence; #134 and #135 commented with the plan and left open.
- **Calls made:**
  1. #137 rejects (the reference's diagnostic) instead of adding a generic "decline record" to the driver: a
     generic record could only name the entry, not the function.
  2. #133: only JSON `true` adds the line; other values add nothing and are not rejected.
  3. #134 and #135 were not in 0040: #134 is done for 0041 (below); #135 stays a design (ADR-416).
  4. The V1 benches were first started before `validate`; the full one refused, so both reran afterwards.
- **Prepared for release 0041** (branch `issue-134-version-name` in `/root/work/r41`, not pushed as a PR yet; every
  C1 gate passed: fixed point, corpus 197 of 197, the tests fail on the 0040 seed and pass on the candidate):
  - #134, `0041-manifest-version-name` (ADR-417): `android:versionName` on an unbranded module's manifest;
    `aapt2 dump xmltree` shows it. Device check BLOCKED: no adb device overnight.
  - #136 follow-up, `0041-hex-digits-type`, `-entity`, `-root`: the 64-digit CIDs of `entity=`, type and `R` lines
    still decoded lowercase only (rejected, not silent). An uppercase CID starting with `F` after `entity=` stays
    an `F<n>` handle; docs/09 says to write such a CID in lowercase.
  - BBC's stores for those batches must be rebuilt at release time (`rebuild.sh` per batch; the "before" driver
    blobs are in `/root/work/blobs/<blob>.xax`, since a chain in one commit has no git blobs).
- **Next:** release 0041 from `main` with the r41 commits (`644f5c3`, `e186334`); close #134 after it, then #135
  (the batch parser's `replace` lives inside `ws_translate`'s closure in the driver), OI-54 step 2, OI-62.

## Release 0041 on `main`: `versionName` and uppercase CID digits — 2026-11-23

`main` = merge of #155 (`45b39fb`). `rotate.sh state`: `validated 0041`, `profile released`.
Seeds: Linux `c5dfd5fb…` (31,822,689 bytes), Windows `ae6fe1f4…` (31,876,096). BBC pins it (MrxSiN/BBC11).
Supersedes the "Next" of "Release 0040 on `main`" above. The owner asked for the campaign to continue, so the
calls below were made without asking.

- **What landed** (four driver transactions, two sub-batch PRs into `release/0041`, #152 and #153):
  - #134 (#152, `0041-manifest-version-name`, ADR-417): `android:versionName` on an unbranded libxposed JVM
    module's `<manifest>` when `version_name` is non-empty; every other APK keeps its bytes.
  - #136 follow-up (#153, `0041-hex-digits-type`, `-entity`, `-root`): the 64-digit CIDs of `entity=`, type and
    `R` lines read hex digits in either case.
- **Rotation** (#154, EXECUTED, WSL 2): `rotate.sh build 0041`, `confirm` on both targets; SNAPSHOTS line
  `87861cd0…` → `c907535a…` (reference resolver); `validated 0041 evidence=02ae4269…`. V1 records with
  `XAX_REQUIRE_NATIVE=1`: python-free seed 412.6 s; full self-host 12,879 s, three generations to `c5dfd5fb…`,
  no fallback.
- **D: filled and stopped WSL.** The `Ubuntu-24.04-D` VHDX lives on D:; when D: ran out of space, WSL stopped
  mid-campaign. Freed by deleting scratch output only (`/root/work/c1-*`, `xaxc-c1-*`, `h1*`; the other listed
  paths were already gone). The VM also shuts down on its own when no `wsl.exe` client is attached: a bench
  started from an agent's background shell died with the agent process. Long runs now go in a Terminal panel
  tab (`wsl.exe ... bash /root/work/<script>.sh`), which survives it; the VM still stops once the run ends.
- **Full suite** (`-n 2`, 2 h 46 min): 1,666 passed, 9 failed: the B1 binding (baseline) and the eight JVM/JDWP
  tests that fail only with the Windows-`java` wrapper on PATH, the same set as 0040. Two subtest failures from
  the host, not the tree (both test files unchanged since 0040):
  - 336 `test_xax_x86_64_views` subtests: `os.fork()` ENOMEM while the other worker held memory; run alone the
    file passes (339 subtests).
  - `test_xax_selfhost_jvm.test_callback_programs`, module `test_xax_jvm_import`: `JMODS=None`, since the PATH
    `javac` is the Windows wrapper and has no `jmods`. The test should skip there like the module's own tests.
  - The system `python3` in WSL has no pytest: run the suite with `/root/venv/bin/python -m pytest`.
- **BBC:** `rebuild.sh` applied the four transactions to `bbc.xax` and its request. `bbc.exe` `f18ceda9…`
  (36,122,112 bytes) by the 0041 Windows seed. `check.py`: 93 programs, 372 of 372, 488 runs, 0 mismatches,
  5 of 5 error paths. Capacity fixtures and the six ThreadsHideAds programs: identical to 0039 and 0040 (the
  scratch runner's output equals `/root/work/rel0039/pin2.json`). hanoi -O1 builds (23.2 s); -O0 exits 5.
- **#134 on a device** (EXECUTED, Pixel 8 Pro, Android 17, wireless adb): the test module built by the 0041 seed
  reports `versionName=2.0.0-dev` in `dumpsys package`. The seed's APK is unsigned: `adb install` refused it
  until it was zipaligned and signed with the SDK debug key. #134 closed by the merge, evidence commented.
- **Next:** #135 (ADR-416, `replace <CID> @name`; the batch parser's `replace` lives inside `ws_translate`'s
  closure in the driver), OI-54 step 2 (hanoi -O0), OI-62. Small: make `test_callback_programs` skip without
  `jmods`.

## Release 0042 on `main`: carrier replace by CID, Wasm offset check, container sizing — 2026-11-24

`main` = merge of #171 (`d8c2c61`). `rotate.sh state`: `validated 0042`, `profile released`.
Seeds: Linux `8d7745ab…` (31,851,585 bytes), Windows `4d361a39…` (31,905,280). BBC pins it (MrxSiN/BBC#12).
Supersedes the "Next" of "Release 0041 on `main`" above. The owner asked for the campaign to continue, so the calls
below were made without asking.

- **What landed** (four driver transactions, three sub-batch PRs into `release/0042`):
  - #157 (#135, ADR-416, ADR-418): batch `replace <TARGET CID> @name` swaps a carrier natively.
  - #158 (OI-62): the legacy Wasm32 profile rejects a checked offset wider than 32 bits (`WASM-CHECKED-OFFSET-BITS`).
  - #161 (OI-54 step 2 part 1, ADR-419): the x86-64 container buffer is sized from the image.
- **Before the rotation** (Phase 1): `evolve.sh check` passed and `evolve.sh replay` replayed 221 of 221 (1 h 45 min).
  #47 and #51 were assessed and commented (not bounded for this release; XAX owns both; #47 waits on #51 and on an
  AArch64 callback ADR). OI-49, OI-56, OI-59 and OI-61 got CLOSED lines (#162). OI-54 part 2 moved to 0043 after a
  workspace census (#164): hanoi's per-value tables (56M words) do not fit the free spans above the arena.
- **Rotation** (#169, EXECUTED, WSL 2): build, `confirm` on both targets, SNAPSHOTS line, `evidence/run.sh` (replay
  221 of 221), `validated 0042 evidence=557aeaba…` on the first run. V1: python-free seed 390 s; full self-host
  13,537 s, three generations `8d7745ab…`. `main` was merged into the release branch twice (#163, #170); the native
  status tool reports every block current on the merged tree.
- **BBC:** `rebuild.sh` for the four transactions (every driver blob matched the ledger); `bbc.exe` `92b24c61…`
  (36,151,296 bytes); `check.py` 372 of 372, 488 runs, 0 mismatches, 5 of 5 error paths; capacity fixtures and
  ThreadsHideAds equal 0039-0041. hanoi on Windows 11: -O1 builds (24.2 s) and runs; -O0 exits 5 (OI-54). `bbc.exe`
  needs `bbc-windows-x86_64.xax` and `bbc-android-arm64.xax` beside it, or every command exits 3.
- **Device** (Pixel 8 Pro, wireless adb `192.168.50.88:44929`): `test_libxposed_lifecycle.py` 7 of 7 with the 0042
  seed, the v3 module run under `dalvikvm64`. The scratch `/root/work/bin/adb` wrapper lost its execute bit when edited
  through `\wsl.localhost` (`sed -i`); the ART step then returns silently. Check `adb devices` through the wrapper.
- **Full suite** (`-n 2`, 2 h 39 min): 1,666 passed, 11 failed. The expected nine (B1 binding, eight JVM/JDWP tests
  with the Windows-`java` wrapper); 336 `test_xax_x86_64_views` subtests from fork ENOMEM (the file alone passes).
  Two new, both pre-existing and found by hash-seed-dependent random corpora:
  - `test_xax_selfhost_verify_exact::test_object_sites`: a store with a missing object is rejected by the reference
    (`ID-REFERENCE-RESOLVED`) but declined by native `verify`, with the 0041 seed too; fails for `PYTHONHASHSEED` 0
    and 1, passes for 2-5.
  - `test_xax_selfhost_graph::test_mutated_bodies_give_the_same_parse_or_diagnostic`: the Python reference parser
    raises `IndexError` on one mutated body. Reproduces alone (16 min).
- **Also on `main` this session:** the agent entry point and task routes (#166, #167), deleted dead native dirs
  (#165), and the native status tool replacing `xax_status_docs.py` (#168; `status-tool/status.sh check|write`).
- **Next:**
  1. The status tool on Windows: make its main driver-shaped so `windows/generator/generate.sh` hosts it unchanged,
     and the PE target by batch `replace <target CID>` (needs the 0042 seed, now pinned); then
     `test_status_docs.py` runs its levels, targets and rewrite cases on Windows (bootstrap stays Linux-only, OI-60).
  2. The two new single-case failures above (a native verifier decline; a reference parser crash).
  3. OI-54 step 2 part 2 (choose packed tables, a second workspace view, or growable views), then step 3.
  4. `xax_replacement.py` and its test to native XAX (needs a JSON reader with exact binary64 conversion).

## Release 0043 open on `release/0043`: one driver sub-batch in — 2026-11-25

`main` = `39695c2`. `release/0043` = `75827cb` (cut from `5aadffa`), not rotated; the pinned seed is still 0042.
Continues "Release 0042 on `main`" above.

- **Release branch** (#175, ledger 0043 `snapshot-missing-reference`): native `verify` declined a snapshot whose
  package or signature reference is missing; the plan (F1012) now calls a new `@lmscan` and rejects with the
  reference's `ID-REFERENCE-RESOLVED`. C1 EXECUTED (3 min 27 s); with the candidate `test_xax_selfhost_verify_exact`
  8 of 8, `test_object_sites` under PYTHONHASHSEED 0 and 1 230 exact, 0 declined. The new fixture test fails with the
  0042 seed until rotation.
- **On `main`:** #176, the reference's memory-fact pass no longer raises `IndexError` on an operand-less node
  (`test_xax_selfhost_graph.py` 4 passed, 3,018 subtests, 21 min 53 s); #174, OI-60's two developer paths removed.
- **Not started:** OI-54 step 2 part 2 (a layout decision, then step 3), OI-58 item 1, so 1d stays closed by its own
  condition; the Windows status tool (2a), OI-60's ledger tool, OI-51, the measurement items, rotation, full suite.
- **Next:** OI-54 part 2 and OI-58 item 1 as further sub-batches into `release/0043`, then rotate once.
  Shell note: from Git Bash, run `wsl` with `MSYS_NO_PATHCONV=1`, or `/mnt/...` arguments are rewritten.
