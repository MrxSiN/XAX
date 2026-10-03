# XAX Compiler Handoff

## Invariants that must not drift

- Meaning is source: canonical XAX is the typed semantic graph/store, never diagnostic text, Python constructors, packet dumps, JSON, or CLI syntax.
- Bootstrap labels B0–B6 are evidence claims. Capability presence, plans, or host-language simulation do not satisfy them.
- B5/B6 claims are target-scoped. The M14 `xax-semantic-image-v1` result does not silently close the legacy native, WebAssembly, or accelerator backends.
- No hidden allocation, synchronization, syscall, initialization, exception edge, ownership transfer, device runtime, or target runtime assistance.
- Tests/benchmarks count only when actually executed. Host-unavailable cases remain unavailable, not passed.
- The AI-native premise remains unproven. Historical, non-qualifying Codex Desktop C-vs-XAX rows are negative for XAX (1.25× C's tokens), so OI-31 still needs a qualifying run. The one-edit tokenizer measurement is a microbenchmark, not proof.

## Current repository state

M1–M14 are complete for their explicitly declared prototype scopes. M14 adds function/graph introspection; generic semantic-object and byte META values; verifier-gated program materialization; canonical-store emission; semantic verification; recursive semantic-image compilation; and an immutable seed boundary.

The AI-native benchmark under `compiler/benchmarks/ai_native/` is now intentionally tiny: five paired structural edits, C and XAX only, manual Codex Desktop execution, native XAX verification, and one flat CSV. The concise README there is the complete runbook. Historical, non-qualifying C-vs-XAX Codex Desktop rows exist (negative for XAX; OI-31). A post-upgrade one-pair `haiku` smoke check measured XAX at 1.04× C. Separately, the OI-01 transport candidates (typed/unified handles × `line`/`pipe`/`json` framing) have one Claude Code run: 30 Claude Code trials (`claude-opus-5-5` subagents, 5 tasks × 6 arms, n=1) completed 30/30. Offline, unified handles save 15 view tokens across the five tasks and unified/pipe is the smallest measured fallback at 237 combined view+packet tokens under both tested encodings. In-model harness-token differences were below run-to-run noise; failed `verify`/`test` checks were `line` 0, `pipe` 2, `json` 14, with nine of ten JSON trials requiring repair. The tested flat-array JSON framing is therefore disfavored and line framing is the observed reliability leader on this corpus, but no transport or handle namespace is canonical and OI-01 remains open.

OI-02 now has four measured objectization arms in `compiler/benchmarks/bench_oi02_granularity.py`: function, module, `call_indirect`, and block. The block arm splits multi-block graphs into a skeleton plus content-addressed block units and requires byte-identical canonical graph/function reassembly before verification/execution. It shows modest rewrite-byte reuse on shallow four-block edits, but higher store/query overhead and no protection from direct-call caller-CID cascades; `call_indirect` remains the strongest locality result. OI-02 is still open and the canonical format is unchanged.

OI-04 now includes the previously missing catalog-free comparator. `bench_oi04_type_vocabulary.py` carries a deterministic store-wide dictionary for every CID referenced by at least two objects, encodes those references as small indices, leaves one-use CIDs explicit, and requires byte-identical canonical reconstruction with CID/index/digest checks. Across the 26,703-byte integer corpus it saves 4,174 bytes (15.6%), compared with 4,991 bytes (18.7%) for `bits5` and 5,623 bytes (21.1%) for `common`. This shows that most byte savings are generic repeated-CID compression, though a fixed catalog retains an incremental advantage. OI-04 remains open for real-model mutation reliability and real floating-point workloads; no comparator is canonical.

The authoritative M14 closure target is `xax-semantic-image-v1`. Its XAX entry graph performs materialize → verifier-facing call → canonical semantic-image encode → finalization/build. Canonical graph verification and canonical store formation remain deliberate trusted META substrate operations consistent with the minimal trusted-core model. Legacy x86-64, AArch64, WebAssembly, and accelerator lowerers remain Python bootstrap/reference implementations and are not included in the M14 B5/B6 claim.

Executed evidence in `compiler/bootstrap/m14_selfhost_evidence.json` records B2–B6 for that target: compiler root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`; entry function `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`; generation 0/1/2 BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`; and 4/4 fixed-policy function vectors matching. The committed 46,255-byte seed runtime reconstructs the compiler byte-identically with repository `PYTHONPATH` removed. It is an immutable bootstrap artifact that internally contains Python modules; B6 does not claim interpreter elimination or diverse-trust proof.

## Validation state

- Syntax/import compilation: passed.
- M14 narrow tests on final state: **7/7 passed**.
- Broad unfiltered regression before the final two artifact assertions: **237 tests**, exactly the same **8 environment-only errors** as M13: 6 Windows x86-64 native execution cases and 2 AArch64/QEMU cases.
- Exact final applicable regression: **231/231 passed** out of 239 current tests, excluding only those same 8 unavailable host-bound cases.
- M14 compiler image: **2,020 bytes**, SHA-256 `05eb15404836e9f77b2f2931489859c43c0f75dcb00c891504e9ddcdd427cd07`.
- M14 seed runtime: **46,255 bytes**, SHA-256 `4e0c64d6f360359cc263c39817ec8cbe4cc3069edf20823755755c4d2707fe52`, BLAKE3-256 `eb8157fd2a00fcca5666ea574b7641b4adcb43382f5fbb60f8addead5f04b7b6`.
- M14 evidence JSON: **3,240 bytes**, SHA-256 `36c2a9a57aea432250ff7a1595e19535ed1d37f2aa7588cd4edd1f01710c6dfa`.
- M14 artifact generation was repeated after the final evidence wording correction; all three committed artifact hashes were identical.
- Deterministic wheel: two `SOURCE_DATE_EPOCH=946684800` builds matched byte-for-byte at **117,715 bytes**, SHA-256 `fa4add6e966ca09fe5df6c02043e91d333f0726ec92f681a03bf7251e4a4a34e`.
- AI-native benchmark focused validation: **7/7 passed**; full compiler suite: **246/246 passed**.
- OI-04 CID-dictionary edit: **9/9** non-tokenizer focused tests pass natively; complete OI-04 **10/10** passes with the unchanged committed token counts replayed by a local shim. The attempted broad suite exceeded the current host execution window; no new broad-pass claim is made.
- The manual benchmark requires no API key, network, SDK, tokenizer, or desktop automation.

## Compiler fast paths — 2026-10-02

- Fixed import-time `NameError` (`AARCH64_GENERAL_OPERATIONS` referenced `Operation` before definition) that broke every import of `xax_compiler`.
- Wheel `py-modules` now includes `xax_android_components`, `xax_libxposed`, `xax_resources` (previously lazily imported but not packaged).
- Store/verify/lower/workspace fast paths; generated code and M14 evidence unchanged. Numbers: `XAX_BENCHMARKS.md` "Compiler-latency fast paths".
- Five identical backend `_resolver` copies replaced by `xax_compiler.store_resolver`.
- Pre-existing failures, not caused by this change (both reproduce on pre-edit bytecode): `test_stack_memory_executes_natively` pins a stale code SHA-256 (43-byte code still executes correctly); `test_float_descriptor_is_not_accepted_semantics` now rejects with `XAX.CANON.TRAILING_BYTES` instead of `XAX.TYPE.FORM` since float types became form 7. Four test modules import `pytest`, which is not installed here.
- Self-hosting reality check: the M14 hosted compiler is four XAX nodes orchestrating Python META primitives (verify, canonical store); all verification, lowering, encoding, and emission still execute in Python. No compiler functionality migrated to XAX in this pass.

## Universal-replacement upgrade — 2026-10-02

- Normative: `XAX_SPEC.md` §21 (replacement definition, R0–R6, evidence labels, kernel admission rule, model lowerings, platform classes, containers, foreign import, libraries, observability) and explicit document precedence in §1. ADR-074–ADR-078; OI-32–OI-36; `XAX_CONFORMANCE.md` §23; `XAX_BENCHMARKS.md` §15; roadmap U1; architecture v0.2 (§35–§47).
- `XAX_REPLACEMENT_MATRIX.json` is machine-checked: `compiler/src/xax_replacement.py` derives each row's level from cited evidence; `tests/test_replacement_matrix.py` rejects overclaims. Update a row only with an existing evidence path.
- U1.2a EXECUTED: x86-64 heap views (checked dynamic heap array round trip; OOB traps). U1.4 WASI EXECUTED under Node (`wasi_command_evidence.json`). ADR-079 (pointer-free memory frontiers), ADR-080 (WASI), OI-37 (pointers in memory).
- U1.1 EXECUTED: direct PE32+ hosted executable with kernel32 imports (`xax_pe.py`, target `x86_64-windows-pe-v1`, `xax_platform.win32_kernel32_api`, evidence `compiler/benchmarks/windows_pe_hosted_evidence.json`). Process exit must be an explicit `ExitProcess` call.
- U1.3 EXECUTED/MEASURED on Linux x86-64 (ADR-084–ADR-089, OI-38–OI-40, conformance §23 item 11, benchmarks §15.1). It adds integer completion (operations 67–72), `linux-x86_64-syscall-v1`, `sysv-x86_64-c`, and static plus explicit-loader ELF64 executables (`xax_linux.py`, `xax_elf.py`) whose entry is the XAX entry function with an explicit `exit_group`. A separate Linux register allocator (`xax_x86_64_regalloc.py`) is differentially validated. The `filestat` workload (`compiler/benchmarks/linux_filestat.py`) runs at 0.95–1.14× `gcc -O2` and 1.41–1.82× `clang -O2`, with a 3,560-byte artifact; the Linux row is at R2.
- AI token trials ran after the upgrade at the lowest cost: offline `tiktoken` replays plus one `haiku` C/XAX pair (XAX 1.04× C, both pass). See `XAX_STATE.md`.

## Queued (deferred by the user, 2026-10-02)

- **Device run of the stateful app (ADR-111)**: on an arm64 device, run `compiler/integration/android/validate_counter_apk.sh`. It expects 0 → 1 → 2 → 3, then `force-stop` and relaunch → 3, then 4. Record the output in `compiler/benchmarks/android_counter_evidence.json` (`device`) and, if it passes, raise the Android `practical_application` matrix field from PROTOTYPE to EXECUTED.

## Exact next task

1. **ADR-097 breadth**: done for wasm32/PE (ADR-098), calls, and padding (ADR-099). Cross-storage targets across calls done (ADR-101: `link_target`, x86-64 executed). Remaining: execute a cross-call program on wasm32 and PE.
2. **OI-38 remainder**: PE now uses the converged allocator (ADR-095, executed under Wine). Remaining: floats and aggregates in it, range-based check elimination, LICM, and a Windows-host re-run of the PE evidence. `filestat` is still 1.47× `clang -O2`.
3. **U1.2b remainder**: stack-storage, float, aggregate, and indirect-call functions on the PE register path (ADR-083 covers compares, foreign calls, heap memory; `sum_to` 8.02x). Install a C toolchain to turn this into an R4 comparison.
4. **OI-33 (Linux)**: argv/env/auxv done (ADR-094); TLS and unwind/debug data remain. **OI-40**: register scalars, pure callbacks (ADR-102), and lend entries (ADR-115, OI-42 closed: `qsort_r`) done; aggregates, stack arguments, and variadics remain. Lend-entry follow-ups: writable lends, several views, and AArch64.
5. Done under Wine (ADR-100: MinGW-w64 C twin; XAX file 20% smaller, code larger because gcc folds `sum_to`/dispatch). Still needed: a Windows host, and a run-time-bound PE workload.
5b. **Stateful Android app (ADR-111)**: run `compiler/integration/android/validate_counter_apk.sh` on a device. It installs `android_counter_activity.apk` and checks 0 → 1 → 2 → 3, `force-stop` and relaunch → 3, then 4.
5a. **Android (ADR-105/106)**: device-free evidence exists (`bench_android_bionic.py`, `bench_android_official_tools.py`, `bench_android_ndk_twin.py`; they need the host tooling listed in `XAX_STATE.md`). C → XAX callbacks run on bionic threads (ADR-107). ART verifies all 62 classes in all 20 APKs, libxposed included (ADR-108). All 12 libxposed module profiles execute on ART with a stand-in framework (ADR-109); what remains is LSPosed in a real target process. rebuild the environment with `integration/android/make_android_root.py`. Next: run the packed APK on a device, then make format 5 the default; AArch64 loops now use registers (ADR-110); next for code quality: pinning loop-invariant homes, and floats/memory on the register path. After that, a richer Activity (state, I/O, lifecycle: U1 workload 4) and libxposed runtime execution.
6. **Browser (ADR-103/104)**: click entries are done. Next: static storage, so state need not live in the DOM; a Web IDL-driven binding importer (OI-32); and an Emscripten/Rust wasm size comparison for R4.
7. OI-31 remains open (manual Codex Desktop C-vs-XAX pass with recorded fixed model/reasoning setting and balanced arm order).
8. **JVM (ADR-112, OI-35)**: JVM→XAX callbacks (generated adapter classes implementing a Java interface, following ADR-102's purity rule); explicit object/array/string construction contracts; block-parameter coalescing (class 1.51× `javac`); an R3 application; a native-plus-bridge arm to close OI-35.
9. **RISC-V (ADR-113)**: compare/branch fusion and copy coalescing (Collatz 3.72× `clang -O2` instructions); F/D floats and memory; a Linux `ET_EXEC` profile through `xax_elf`; a QEMU-system or hardware run (OI-44).

## Reproduce M14 evidence

```text
cd compiler
export PYTHONPATH=src
python -m py_compile src/*.py tests/*.py benchmarks/*.py bootstrap/*.py
python -m unittest tests.test_xax_selfhost -v
python bootstrap/generate_m14.py
python -m unittest discover -s tests -v
SOURCE_DATE_EPOCH=946684800 python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
PYTHONPATH=src:. python -m unittest tests.test_ai_native_benchmark -v
PYTHONPATH=src:. python -m benchmarks.ai_native prepare task-01 C
PYTHONPATH=src:. python -m benchmarks.ai_native prepare task-01 XAX
```

Since ADR-114 the eight formerly host-bound cases execute on Linux x86-64: raw Win64 images go through a harness call thunk, and AArch64 images run in Unicorn when QEMU is absent (`pip install unicorn`). PE executables still need Windows or Wine. The JVM tests need `java`/`javac`; the RISC-V tests need Unicorn (`llvm-mc` adds an independent decode).

## Relevant specification

`XAX_SPEC.md` §8 and §16; `XAX_CONFORMANCE.md` §15; roadmap M14; `XAX_CONFORMANCE.md` §21; ADR-027, ADR-057, ADR-058, and ADR-059; OI-25/OI-26/OI-27/OI-31.

## Android arm64-v8a direct shared object — 2026-10-01

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

## Android direct managed-artifact progress — 2026-10-01

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
- Exact next implementation dependency: execute the paired controlled target/module on a compatible Android + current libxposed API-102 environment and record module discovery, package-ready delivery, argument/result mutation, retained-handle behavior, explicit unhook/idempotence, deoptimization return, PROTECTIVE exception behavior, capability-gated preferences/files, saved target-ClassLoader transfer/rejection behavior, stable hook-ID transfer/mismatch behavior, hot-reload callback delivery and replacement atomicity, process survival, latency, and ART/XAX-attributable allocations. If that environment remains unavailable, the next bounded compiler-side gap is multiple retained hooks keyed by unique API-102 IDs, followed by explicit package/process and external-resource cleanup/migration; preference writes/listeners and ParcelFileDescriptor consumption remain separate later contracts.

## Universal-replacement continuation — 2026-10-02 (ADR-102, ADR-103)

- ADR-102: C can call pure XAX functions. The calling convention is part of the code-address type, and x86-64 generates a 20-byte SysV adapter for each such function. `sysv-x86_64-c` imports now take and return SSE-class scalars. EXECUTED with libc `tsearch`/`tfind` and libm. OI-40 remains open for aggregates, stack arguments, and variadics; OI-42 opened for effectful callbacks.
- ADR-103/104: the browser target with generated host pages and XAX click entries. EXECUTED in headless Chromium; the browser row is at R2. OI-43 opened and closed.
- Host: Linux x86-64 with gcc, clang, node 22, and Playwright Chromium. No Wine and no QEMU, so PE and AArch64 rows could not be re-executed here.
- Regression: identical failure set before and after (2 failures and 27 errors, all host or dependency bound: no pytest, Windows/Wine, tokenizer, or wheel build).

## Native XAX compiler leaf — 2026-10-02

BLAKE3 compression is now the first real compiler hot path implemented as an ordinary XAX graph and run through the normal x86-64 lowering path. The canonical store is `compiler/bootstrap/xax_blake3_compress.xax` and its regeneration/loader is `compiler/src/xax_native_blake3.py`; `compiler/src/blake3.py` keeps the pure-Python leaf for bootstrap/fallback and lazily switches to the verified native XAX compressor on compatible x86-64 hosts. The graph has CID `f1744e682b2f99c542100f0e987dced9a87f40dfa4b8f173596fb24b78faa216`; emitted x86-64 code is 19,744 bytes with 806 semantic ranges. Evidence and timings are in `compiler/benchmarks/xax_native_blake3_evidence.json`. The current Linux execution shim is only a SysV-to-Win64 ABI adapter around the ordinary emitted image; no BLAKE3 logic lives in the shim.

## JVM and RISC-V targets — 2026-10-03 (ADR-112–ADR-114)

- Two architectures were added with zero kernel changes. Architecture 5, `jvm-classfile-v1`, lowers XAX directly to class-file bytecode in a deterministic JAR; it is EXECUTED on HotSpot 21 and the JVM row is at R2. Architecture 6, `riscv64-baremetal-raw-v1`, emits a raw RV64IM image; it is EXECUTED under Unicorn and the riscv64 row is at R1. Both pass the same differential corpus against the reference executor.
- MEASURED: JVM Collatz 1.04× `javac` kernel time, 1.51× class bytes. RISC-V Collatz 3.72× `clang -O2` emulated instructions, after a liveness-hull linear scan cut it from 15.9×.
- Repairs: OI-25/OI-26 evidence replays no longer depend on filesystem order or interpreter version; one stale code hash was re-pinned after execution; the wheel now packages `xax_web`, `xax_android_counter`, `xax_jvm`, and `xax_riscv64`.
- Regression here: 903 passed, 19 skipped, 2 failed (`tiktoken` absent; wheel needs Python ≥ 3.12).
- Lowest-cost token test after this upgrade: offline replays 44/44; one `haiku` `task-01` pair, both PASS, XAX 1.065× C (40,021 vs 37,576 tokens; 10 vs 3 tool calls). Not R5 or OI-31 evidence.

## Self-hosting S1 — 2026-10-03 (ADR-116)

- The RISC-V encoder is an XAX function on the production path (`xax_selfhost_riscv64.py`, `bootstrap/xax_riscv64_encoder.xax`). Regenerate with `PYTHONPATH=src python -c "import xax_selfhost_riscv64 as m; m.write_encoder_store()"`; `test_xax_selfhost_riscv64.py` fails if the store drifts.
- Next is S2: pass a borrowed output view into a native leaf so a whole function's word stream comes from XAX. Then S3, the store codec and full BLAKE3, so CIDs are computed by XAX (ladder in the roadmap).
- Commits on `main` carry no Claude attribution, per the user.
- S2 (ADR-117): the whole BLAKE3 hash is XAX (`xax_selfhost_blake3.py`, `bootstrap/xax_blake3_hash.xax`), and `blake3.blake3()` uses it by default on Linux x86-64 (`XAX_BLAKE3_PYTHON_HASH=1` forces the driver). Next is S3: the store codec (ULEB, object framing, index) into lent views.
- S3 (ADR-118): the store container decoder is XAX (`xax_selfhost_store.py`); `StoreReader._decode_native` is the production path, and `XAX_STORE_PYTHON_DECODER=1` forces the bootstrap parser. Regenerate with `write_decoder_store()`, which always uses the bootstrap parser. Next is S3b: object bodies.
- S3b (ADR-119): object envelopes are parsed by XAX and `get` uses them. Next is S3c: typed body decoding (graph and function bodies).
- S3c (ADR-120): graph-body syntax is XAX (`XAX_GRAPH_PYTHON_DECODER=1` forces the bootstrap parser; regenerate with `write_graph_decoder_store()`). Next is S3d: branch targets, value definitions, and dominance over the decoded stream.
- S3d (ADR-121): control-flow analysis is XAX (`XAX_CFG_PYTHON=1` forces the bootstrap; regenerate with `write_cfg_store()`). Next is S3e: value definitions and SSA dominance.
- S3e (ADR-122): value definitions and dominance are checked in the same XAX CFG function (out word 2). Next is S4: per-operation typing rules.

## Linux AArch64 — 2026-10-03 (ADR-123)

- `xax_linux_aarch64.py`: `aarch64-linux-elf-exec-v1`/`-dynexec-v1`, syscall and C-import thunks, `e_entry` stub. `benchmarks.linux_filestat.build_filestat_program("aarch64")` builds the same graph for it. Host setup: `apt-get install qemu-user gcc-aarch64-linux-gnu libc6-dev-arm64-cross`; for `filestat`, copy an arm64 `libz.so.1` (Ubuntu ports `zlib1g_*_arm64.deb`) into `/usr/aarch64-linux-gnu/lib/`.
- Fixed duplicate `_cset` in `xax_aarch64.py` (frame-path compares were wrong). Frame slots are liveness-shared only on the Linux identities; extending this to Android/bare metal changes committed artifacts and needs their evidence re-run.
- Next for this row: AArch64 register path for memory, logic, and division (the 6.6×), then a hardware run (OI-44).

## SPIR-V / Vulkan — 2026-10-03 (ADR-124)

- `xax_spirv.py` (compiler + `run_spirv_kernel` harness + `reference_dispatch`), kernels in `benchmarks/spirv_kernels.py`. Host setup: `apt-get install mesa-vulkan-drivers libvulkan1 spirv-tools glslang-tools` and `pip install vulkan`. Keep nested Vulkan create-info structs in named variables: inline temporaries in the bindings dangle (`VK_ERROR_UNKNOWN` at pipeline creation).
- Next: structured lowering for reducible CFGs (the 6.9×), floats, then an XAX host program that drives Vulkan through `sysv-x86_64-c` imports (R2), then a physical GPU (OI-34).

