# XAX Compiler Handoff

## Invariants that must not drift

- Meaning is source: canonical XAX is the typed semantic graph/store, never diagnostic text, Python constructors, packet dumps, JSON, or CLI syntax.
- Bootstrap labels B0–B6 are evidence claims. Capability presence, plans, or host-language simulation do not satisfy them.
- B5/B6 claims are target-scoped. The M14 `xax-semantic-image-v1` result does not silently close the legacy native, WebAssembly, or accelerator backends.
- B levels come only from `xax_selfhost.bootstrap_status` (generated blocks below); S-step self-compilation is a component fixed point, never B1–B4 (ADR-177).
- Committed stores are what their builders make (`tests/test_store_regeneration.py`); the M14 seed is pinned and only `generate_m14.py rotate-seed` writes it; evidence that claims XAX-hosted execution runs with `XAX_REQUIRE_NATIVE=1`.
- No hidden allocation, synchronization, syscall, initialization, exception edge, ownership transfer, device runtime, or target runtime assistance.
- Tests/benchmarks count only when actually executed. Host-unavailable cases remain unavailable, not passed.
- AI-efficiency claims remain evidence-scoped. ADR-175's five-edit result is historical; ADR-176 missed 0.50 (0.7683×, 42/45). ADR-186/187 add ordinary snapshot-bound requests and host-applied final responses. ADR-195 rejected response-v9 as R5 evidence. ADR-196's minimal-client same-prefill response-v12 measures XAX at 0.995× the lowest textual median, and ADR-197's multi-file corpus measures 1.68× against IDE excerpts (0.35× against whole files). JVM remains R4, and R5 is unmet.

## Current repository state

<!-- xax-status:levels -->Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): R6: linux-x86_64; R5: jvm; R3: android-arm64, linux-aarch64; R2: aarch64-baremetal, browser-web, windows-x86_64-pe; R1: gpu-spirv-cuda-metal-dxil, riscv64, wasm32-core, wasm32-wasi; R0: accelerator-simt-packet; no level yet: bsd-unix, dotnet-clr, macos-ios-apple, rtos-embedded-mcu.<!-- /xax-status:levels -->

<!-- xax-status:bootstrap -->Bootstrap status (generated from `compiler/bootstrap/m14_selfhost_evidence.json`, derived by `xax_selfhost.bootstrap_status`): whole production compiler: none of B0-B6 is established (no canonical XAX store implements the whole compiler; S8 and later steps are open (ADR-180)); M14 semantic-image META wrapper: B2, B3, B4 hold, B5, B6 do not (host-executed META_CANONICAL_STORE, META_MATERIALIZE_PROGRAM, META_VERIFY_SEMANTICS). S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: python-zipapp, 46,255 bytes, requires Python: yes.<!-- /xax-status:bootstrap -->

Sections below are dated; a later section supersedes an earlier figure. The current full-suite result is under "Multi-language performance rule" and later entries in `XAX_STATE.md`.

M1–M14 are complete for their explicitly declared prototype scopes. M14 adds function/graph introspection; generic semantic-object and byte META values; verifier-gated program materialization; canonical-store emission; semantic verification; recursive semantic-image compilation; and an immutable seed boundary.

The AI-native benchmark under `compiler/benchmarks/ai_native/` is intentionally tiny: five paired structural edits, task-local exact-target checkers, and flat CSV evidence. Historical, non-qualifying Codex Desktop rows are negative for XAX. ADR-175's fixed controlled-profile run is positive: 10/10 cells pass in one turn, XAX-DIRECT 98,432 tokens versus C's 197,252 (0.4990×; 50.098% fewer), with no repairs (`jvm-r5-optimized-evidence.json`). Separately, the OI-01 transport candidates (typed/unified handles × `line`/`pipe`/`json` framing) have one Claude Code run: 30/30 completed; line framing had 0 failed checks, pipe 2, JSON 14. No transport or handle namespace is canonical and OI-01 remains open.

OI-02 now has four measured objectization arms in `compiler/benchmarks/bench_oi02_granularity.py`: function, module, `call_indirect`, and block. The block arm splits multi-block graphs into a skeleton plus content-addressed block units and requires byte-identical canonical graph/function reassembly before verification/execution. It shows modest rewrite-byte reuse on shallow four-block edits, but higher store/query overhead and no protection from direct-call caller-CID cascades; `call_indirect` remains the strongest locality result. OI-02 is still open and the canonical format is unchanged.

OI-04 now includes the previously missing catalog-free comparator. `bench_oi04_type_vocabulary.py` carries a deterministic store-wide dictionary for every CID referenced by at least two objects, encodes those references as small indices, leaves one-use CIDs explicit, and requires byte-identical canonical reconstruction with CID/index/digest checks. Across the 26,703-byte integer corpus it saves 4,174 bytes (15.6%), compared with 4,991 bytes (18.7%) for `bits5` and 5,623 bytes (21.1%) for `common`. This shows that most byte savings are generic repeated-CID compression, though a fixed catalog retains an incremental advantage. OI-04 remains open for real-model mutation reliability and real floating-point workloads; no comparator is canonical.

The authoritative M14 closure target is `xax-semantic-image-v1`. Its XAX entry graph performs materialize → verifier-facing call → canonical semantic-image encode → finalization/build. Canonical graph verification and canonical store formation remain deliberate trusted META substrate operations consistent with the minimal trusted-core model. Legacy x86-64, AArch64, WebAssembly, and accelerator lowerers remain Python bootstrap/reference implementations and are not included in the M14 B5/B6 claim.

*(Corrected 2026-10-06, ADR-177: B5/B6 are withdrawn for this target; the evidence now records the derived status below. Historical wording kept.)* Executed evidence in `compiler/bootstrap/m14_selfhost_evidence.json` records B2–B6 for that target: compiler root `097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d`; entry function `4300342f92f9ba32bcefbb45af4aad117a3bbf3699bd66266b25cefdc874b6fc`; generation 0/1/2 BLAKE3-256 `6340c903f5da3e8aaf4d8ae886694a0d858687fc5c5520662a018518693f4788`; and 4/4 fixed-policy function vectors matching. The committed 46,255-byte seed runtime reconstructs the compiler byte-identically with repository `PYTHONPATH` removed. It is an immutable bootstrap artifact that internally contains Python modules; B6 does not claim interpreter elimination or diverse-trust proof.

## Replacement levels v3 — 2026-10-08 (ADR-207)

R4 = leadership (≤ 0.9999× the fastest non-XAX median, significant); R5 = autonomous maintenance; R6 = XAX-only application. AI-token work is deferred: do not run token trials. JVM is R4, Android is R3. Next task is U2 (`XAX_IMPLEMENTATION_ROADMAP.md`): re-run the Linux workloads with raw samples (U2.1), then optimize toward ≤ 0.9999× (U2.2), then the Android re-run with a Kotlin arm (U2.3). Items in "Exact next task" that cite the 1.05× target or the token gate are superseded by this section.

## Linux R4 progress — 2026-10-08 (ADR-208)

`filestat` and `jsonmin` lead clang (0.882x, 0.968x); `chains` ties rustc (0.984x, not significant), so Linux stays R3. Next for R4: `chains` (look at the walk loop: `found + 1` is recomputed every step, extra moves; memory latency dominates), then the Android re-run with a Kotlin arm (U2.3). Profile with `valgrind --tool=callgrind --dump-instr=yes` on the image; XAX images have no symbols, so group costs by address.

## R5 record — 2026-10-08 (ADR-209)

JVM is R5 for one cycle (`benchmarks.bench_r5_maintenance`). Next for R5 breadth: a structural edit (insert/delete nodes) and an interface change maintained the same way, and a second platform row (Linux x86-64 `jsonmin` after its R4). Next level: R6 (U2.5), a complete application whose logic, tests, and build definitions are all XAX.

## R6 groundwork — 2026-10-08 (ADR-210)

New applications are created with `xax_construct.construct` (one request) and then changed only through workspace transactions on the committed store. `xb64` is the first; rerun its record with `python -m benchmarks.bench_r6_xb64`. For an R6 row, the row also needs R4 and R5: Linux needs `chains` to lead; the JVM has R5 but no XAX-only application (the carrier has only the Linux platform surface).

## Linux R4 — 2026-10-08 (ADR-212)

Linux x86-64 is R4 (§15.33). Next for this row: an R5 maintenance record (`benchmarks.bench_r5_maintenance` is JVM-only; add a Linux variant with a before/after benchmark), after which `xb64` (R6 evidence, ADR-210) can lift it to R6. Keep `jsonmin`'s margin in view: re-run all three after any backend change and report the result whatever it is.

## Linux R6 — 2026-10-08 (ADR-213)

Linux x86-64 is R6 on the validator's rules. What would make it robust: R4 re-runs on another host (`jsonmin`'s margin is small), a maintenance cycle with a structural edit, and an XAX-only application larger than `xb64`, ideally built by an independent agent.

## S8c.1 integer typing rejections — 2026-10-08 (ADR-214)

- `_node_entry` (`xax_selfhost_typing.py`) calls `_integer_rejection`, which returns the first failing bootstrap check as a site and three payload words. The verdict becomes `REJECTED` and the record lands at `DIAGNOSTICS + 4 * node`; `rejection(record, cids)` renders it. Site 0 means "leave it to the bootstrap".
- Next (S8c.2): the float, compare, aggregate/sum, resource, meta, constant, and call families, same pattern; keep deferring every case whose bootstrap check would first raise a decode diagnostic. Then facts declines and object verification.

## S8c.2 float and compare typing rejections — 2026-10-08 (ADR-215)

- `_rejection` holds one step list per family, in the bootstrap's check order; `_SITES` renders. Add a family by adding its steps and its site renderers.
- Next (S8c.3): aggregate and sum families. Their diagnostics quote element lists: render them from the program's `ITEMS`/`COUNT` tables (pass the owner's type index), not from Python decoding.

## S8c.3 aggregate and sum typing rejections — 2026-10-08 (ADR-216)

- Renderers take a context `r`: `r.h` (CID hex), `r.items(type)` (program tables), `r.operands(position)` (input stream). Lists in a diagnostic must come from these, not from Python decoding.
- A changed typing store invalidates `selfhost_x86_64_evidence.json` and `selfhost_closure_evidence.json` (`test_audit_remediation`); re-run both benches with `--write` on Linux x86-64.
- Next (S8c.4): resource/effect and meta families, then constants and calls.

## S8c.4 meta typing rejections — 2026-10-08 (ADR-217)

- `_meta_steps` builds each meta operation's checks from `META_RULES`. Undecoded `bits` and form-5 types defer; other non-opaque types reject.
- Next (S8c.5): resource/effect (`_verify_resource_effect_node`). Its diagnostics quote raw CID tuples, `_EffectType` reprs, flags, and transition lists; render them from the input stream and the program's tables (`EDOMAIN`, `EINST`, `RKIND`, `RSTATE`, `RFLAGS`, `TSTART`/`TCOUNT`).

## S8c.5 resource/effect typing rejections — 2026-10-08 (ADR-218)

- Rejection logic lives in `build_rejection_pass` / `_rejection_entry` (its own function). Keep new rejection code there, not in `_node_entry`.
- If the XAX backends decline a helper program (`X86_64_VIEWS-XAX-BACKEND`), check the views backend's arena first: the largest function needs about 5 x blocks x values / 64 words for liveness. The region layout is in `xax_selfhost_views_backend.py`.
- Next (S8c.6): constants and call targets, then call contracts (they need the callee interface lists decoded separately from the comparison).

## S8c.6 constant and call-target rejections — 2026-10-08 (ADR-219)

- `_entity_steps` covers both entity checks. Next (S8c.7): `GRAPH-CALL-CONTRACT` needs the callee interface lists decoded apart from the comparison (`_call_rule` fuses them); then the facts engine's declines and object verification.

## S8c.7 call-contract rejections — 2026-10-08 (ADR-220)

- `_call_interface` decodes a fragment callee's interface into the pass's list area (after the records; overflow goes to `PASS_SINK` and defers). `NativeTyping.rejection` reads it back through `r.interface`.
- Next: the facts engine's declines (`xax_selfhost_facts`, `DECLINE_SITES`), which are the memory-fact rejections in `_parse_graph_uncached`; then object verification (`verify_object`).

## S8c.8 stack-memory rejections — 2026-10-08 (ADR-221)

- Use `_reject(e, condition, M[site], payload..., renderable=...)` only where the engine check is exactly the bootstrap's check in its order; add the renderer in `memory_diagnostic`. `_pointer`, `_consume_effect`, and `_access` take `exact=True` in the handlers already verified (load, store, address offset, stack end).
- Next: heap views and checked accesses (`_heap_view_node`, `_checked`), whose corpus mutations still fall back; then calls, atomics, links; then object verification.

## Host integration contracts — 2026-10-08 (ADR-222 to ADR-225)

- `xax_native.verify_component_store` memoizes component-store verification in `XAX_NATIVE_CACHE`. Set `XAX_NATIVE_REVERIFY=1` when evidence must show the verifier running on component stores.
- `xax_construct` accepts `linux.startup.*`. `xax_linux.process_contract()` and `xax_contract` are the versioned host surface: when one of their names or clauses changes, bump `HOST_CONTRACT_MINOR` or the identity, and tell XAX-MCP (`MrxSiN/XAX-MCP`, `src/xax_mcp/compat.py`).
- Wide checked loads on byte views (proposal P4 from XAX-MCP) are not implemented: they would change the checked-access rule in the verifier, the XAX-hosted typing program, and every backend, which needs its own decision.

## S8c.9 checked-access rejections — 2026-10-08 (ADR-226)

- `_access_size` is shared by plain and checked accesses. Next: rebase windows (`_pointer_rebase`), heap-view construction (`_heap_view_node`), returned views (`_return_views`), then calls, atomics, and links; then object verification.

## S8c.10 rebase-window rejections — 2026-10-08 (ADR-227)

- Next: returned views (`_return_views`, `HEAP-VIEW-RETURN-*`), heap-view construction (`_heap_view_node`), then calls, atomics, links; then object verification. Another session also commits to `main`: fetch before pushing and take the next free ADR number.

## S8c.11 returned-view rejections — 2026-10-08 (ADR-228)

- The corpus is fully engine-decided; extend it before converting more handlers (heap-view construction, foreign and view calls, atomics, links), each with a constructed case per rule as in `SelfhostTypedAccessTests`.

## S8c.12 heap-view construction rejections — 2026-10-08 (ADR-229)

- `_heap_program` (tests) builds mmap-then-view programs for constructed cases. Next: foreign calls (`_call_foreign`), view-passing calls (`_view_call`), atomics, links, then object verification.

## S8c.13 foreign-call memory rejections — 2026-10-08 (ADR-230)

- Next: view-passing direct calls (`_view_call`, `_verify_heap_view_call`), indirect calls, atomics, links; then object verification (`verify_object`). Superseded by S8c.14 below.

## S8c.14 view-passing call rejections — 2026-10-08 (ADR-232)

- Next: released-view link dependents (`MEMORY-LINK-TARGET-OUTLIVES` at calls), indirect calls, atomics, links; then object verification (`verify_object`). Superseded by S8c.15 below.

## S8c.15 indirect-call stack-proof rejections — 2026-10-08 (ADR-233)

- Next: released-view link dependents (`MEMORY-LINK-TARGET-OUTLIVES` at calls), atomics, links; then object verification (`verify_object`). Superseded by S8c.16 below.

## S8c.16 atomic memory rejections — 2026-10-08 (ADR-234)

- Next: released-view link dependents (`MEMORY-LINK-TARGET-OUTLIVES` at calls), links; then object verification (`verify_object`). Superseded by S8c.17 below.

## S8c.17 link memory rejections — 2026-10-08 (ADR-235)

- Next: the remaining memory declines (record field offsets and strides, byte-addressable values, link dependents of ended storage, foreign writes to link-bearing storage, atomic enums); then object verification (`verify_object`). Superseded by S8c.18 below.

## S8c.18 address, record, and link-lifetime rejections — 2026-10-08 (ADR-236)

- Next: the remaining declines (atomic enum diagnostics, invalid record fields, ambiguous link dependents); then object verification (`verify_object`). Superseded by S8c.19 below.

## S8c.19 object rejections: reference lists and call contracts — 2026-10-08 (ADR-237)

- Next: object rejections for functions (`_verify_function`), recursion groups, types, constants, targets, packages, and builds; the remaining memory declines. Superseded by S8c.20 below.

## S8c.20 function object rejections — 2026-10-08 (ADR-238)

- Next: object rejections for recursion groups, types, constants, targets, packages, and builds; the remaining memory declines. Superseded by S8c.21 below.

## S8c.21 recursion-group member-list rejections — 2026-10-08 (ADR-239)

- Next: group rejections after member parses (contracts, member calls, SCC, order), types, constants, targets, packages, and builds; the remaining memory declines.

## Validation state at M14 (historical)

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

## Multi-language performance rule and x86-64 optimization — 2026-10-03 (ADR-147, ADR-148)

- Rule (`XAX_BENCHMARKS.md` §15.0): every CPU/native runtime comparison includes optimized C/C++ and an implementation outside C/C++ (Rust twins in `compiler/benchmarks/rust_twins/`); XAX meets the target at ≤ 1.05× the fastest valid median. The Linux harness interleaves rounds with a rotating arm order and records `time_ratio_vs_fastest` / `performance_class`. The matrix validator rejects a competitive verdict whose results lack either.
- Result (§15.14): `filestat` 1.017× (clang fastest), `chains` XAX `soa` arm fastest, `jsonmin` 1.029× (clang fastest). Linux x86-64 row is R4 within that scope.
- Compiler: range facts with edge refinement, widening, and narrowing remove proven checks; SIB-scale and RMW folding; compare-with-memory; value and branch bit tests; loop pass-through slots; hoisted wide constants; callee-saved registers across calls (SysV saves rbx/rbp/r12–r15 only); lowering view `xax_inline.py` (leaf inlining, merging, jump threading, pack and store-truncation folding, DCE, innermost-loop-first layout).
- Environment for the full suite (this container): `pip install unicorn pytest pytest-xdist tiktoken vulkan setuptools`; apt `qemu-user qemu-user-static qemu-system-arm gcc-aarch64-linux-gnu libc6-dev-arm64-cross spirv-tools glslang-tools mesa-vulkan-drivers libvulkan1 wine64 mingw-w64 busybox zlib1g-dev e2fsprogs unzip`; arm64 `libz.so.1` copied into `/usr/aarch64-linux-gnu/lib`; `python compiler/integration/android/make_android_root.py` for `/opt/android`; Rust via rustup. Run with `PYTHONPATH=src:.:..` from `compiler/`: 1,059 passed, 4 skipped (Windows host and physical Android device only). Debian's patched setuptools fails the wheel test; install `setuptools` with `pip install -U --ignore-installed setuptools wheel`.

## Queued (deferred by the user, 2026-10-02)

- **Device run of the stateful app (ADR-111)**: on an arm64 device, run `compiler/integration/android/validate_counter_apk.sh`. It expects 0 → 1 → 2 → 3, then `force-stop` and relaunch → 3, then 4. Record the output in `compiler/benchmarks/android_counter_evidence.json` (`device`) and, if it passes, raise the Android `practical_application` matrix field from PROTOTYPE to EXECUTED. *(2026-10-04: done on an Android 12L x86_64 emulator through ARM translation, ADR-155; a run on arm64 hardware is still wanted.)*

## Exact next task

1. **After S6** (roadmap): S6 is EXECUTED for RV64 (ADR-150: every committed store decided by XAX; B1–B4 for the RISC-V backend and the store verifier; ADR-151: BLAKE3 through both RISC-V generators with aggregates, hidden result areas, and stack arguments). S7a is EXECUTED (ADR-152): the x86-64 views backend is an XAX program, byte-identical to `xax_x86_64_views.py`, closes over itself natively, and lowers every production helper (`host_image`). Next (S7b): the object table and image assembly, and exact rejection diagnostics, in XAX; then code quality for the x86-64 profile (fall-through layout, caller-saved registers), now 1.08–1.32× the optimizing backend's run time. B4 runs are opt-in (`XAX_FIXED_POINT=1`); regenerate evidence with `benchmarks/bench_selfhost_closure.py --write` and `bench_selfhost_fixed_point.py --write` after backend or helper-store changes.
2. **ADR-097 breadth**: done for wasm32/PE (ADR-098), calls, and padding (ADR-099). Cross-storage targets across calls done (ADR-101: `link_target`, x86-64 executed). Remaining: execute a cross-call program on wasm32 and PE.
3. **OI-38 remainder**: PE uses the converged allocator (ADR-095) and the ADR-148 optimizations; current PE evidence executes on Windows (ADR-170). Remaining: floats and aggregates in it, a cross-block allocator (shuffles and home reloads), and translation validation of the lowering view. All three Linux workloads are within 1.05× of the fastest of gcc/clang/rustc (ADR-147); keep it that way after every backend change (§15.0).
4. **U1.2b remainder**: stack-storage, float, aggregate, and indirect-call functions on the PE register path (ADR-083 covers compares, foreign calls, heap memory; `sum_to` 8.02x). Install a C toolchain to turn this into an R4 comparison.
5. **OI-33 (Linux)**: argv/env/auxv done (ADR-094); TLS and unwind/debug data remain. **OI-40**: register scalars, pure callbacks (ADR-102), and lend entries (ADR-115, OI-42 closed: `qsort_r`) done; aggregates, stack arguments, and variadics remain. Lend-entry follow-ups: writable lends, several views, and AArch64.
6. **Windows PE workload**: done under Wine (ADR-100: MinGW-w64 C twin; XAX file 20% smaller, code larger because gcc folds `sum_to`/dispatch). Still needed: a Windows host, and a run-time-bound PE workload.
7. **Stateful Android app (ADR-111)**: run `compiler/integration/android/validate_counter_apk.sh` on a device. It installs `android_counter_activity.apk` and checks 0 → 1 → 2 → 3, `force-stop` and relaunch → 3, then 4.
8. **Android (ADR-105/106)**: device-free evidence exists (`bench_android_bionic.py`, `bench_android_official_tools.py`, `bench_android_ndk_twin.py`; they need the host tooling listed in `XAX_STATE.md`). C → XAX callbacks run on bionic threads (ADR-107). ART verifies all 62 classes in all 20 APKs, libxposed included (ADR-108). All 12 libxposed module profiles execute on ART with a stand-in framework (ADR-109); what remains is LSPosed in a real target process. rebuild the environment with `integration/android/make_android_root.py`. Next: run the packed APK on a device, then make format 5 the default; AArch64 loops now use registers (ADR-110); next for code quality: pinning loop-invariant homes, and floats/memory on the register path. After that, a richer Activity (state, I/O, lifecycle: U1 workload 4) and libxposed runtime execution.
9. **Browser (ADR-103/104)**: click entries are done. Next: static storage, so state need not live in the DOM; a Web IDL-driven binding importer (OI-32 is closed by ADR-166 without Web IDL); and an Emscripten/Rust wasm size comparison for R4.
10. **OI-31 is closed** (ADR-174/175): fixed `gpt-5.6-luna` low reasoning, fresh sessions, exact session usage, and 10/10 pass. The controlled direct workflow uses 50.098% fewer aggregate tokens than C-like text. Broader §6.2 task classes remain future evidence, not part of this closure.
11. **JVM (ADR-112, ADR-156–167, ADR-174–176/186/187, OI-35)**: R4 is done. The current 15-family Java/Kotlin/XAX comparison uses host-applied final responses, empty creation, actual helpers and conflicts, with three trials per cell and retained failed-response costs. Response-v9 meets the median 0.50 gate at 0.498423x with all 135 cells and every failed cost included (ADR-194). Review corpus/context equivalence before any R5 promotion; further token tuning is not the next task. The other next item is a CLI/IL container for OI-35's CLR half.
12. **RISC-V (ADR-113)**: compare/branch fusion and copy coalescing (Collatz 3.72× `clang -O2` instructions); F/D floats and memory; a Linux `ET_EXEC` profile through `xax_elf`; a QEMU-system or hardware run (OI-44).

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
- *(2026-10-06, ADR-178: run `compiler/integration/android/vector/validate_vector_runtime.sh` on a rooted arm64 device with Zygisk and Vector v2.2+; it automates this and 26 further checks.)* Exact next implementation dependency: execute the paired controlled target/module on a compatible Android + current libxposed API-102 environment and record module discovery, package-ready delivery, argument/result mutation, retained-handle behavior, explicit unhook/idempotence, deoptimization return, PROTECTIVE exception behavior, capability-gated preferences/files, saved target-ClassLoader transfer/rejection behavior, stable hook-ID transfer/mismatch behavior, hot-reload callback delivery and replacement atomicity, process survival, latency, and ART/XAX-attributable allocations. If that environment remains unavailable, the next bounded compiler-side gap is multiple retained hooks keyed by unique API-102 IDs, followed by explicit package/process and external-resource cleanup/migration; preference writes/listeners and ParcelFileDescriptor consumption remain separate later contracts.

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

## Recursion — 2026-10-03 (ADR-125)

- `group_member_function(group, k)` is the callable member identity; `parse_function_graph(function, resolve)` is the lowering view every backend now uses instead of `_parse_graph` for function bodies. New backends must use it too, or they will see raw `call.group_member` nodes.
- Next: wasm shadow stack for recursive frames; a workspace mutation that creates member functions; a verified stack-depth bound where a real-time profile asks for one.

## jsonmin — 2026-10-03 (ADR-126)

- `benchmarks/jsonmin.py` builds the program (`build_jsonmin(arch)`), states the contract (`reference_jsonmin`), and measures it (`python -m benchmarks.jsonmin --write`). `src/xax_structured.py` is the construction helper; call `drop()` on a linear token a node consumes, or it rides later edges twice (`RESOURCE-LINEAR-CONTINUATION`).
- To reach R4: keep parser state in registers instead of the context view (pass position and output length as scalars and return them packed), prune dead names at joins in `Proc`, and read straight into the input view (a `pointer_rebase` window instead of the chunk copy).

## C header import — 2026-10-03 (ADR-127)

- `import_c_functions(headers, soname, names, abi=..., overrides={...}, flags=[...])`; use `.function(name).inputs/.outputs` for node types and `.objects` for the store. POSIX names need `flags=["-D_GNU_SOURCE"]` (the importer parses as C11).
- Next: by-value struct ABI classification (OI-40) to import struct returns; typed argument packs for variadics; an executed program over the Android classfile importer (closes OI-32 together with the token comparison).

## Board packages — 2026-10-03 (ADR-128)

- `xax_board.py` (package, image, `run_board_image`), workload `benchmarks/aarch64_virt_board.py`. Host: `apt-get install qemu-system-arm`; QEMU needs `-net none` (no EFI ROMs installed).
- Next: static storage shared between handler and reset (a board RAM region as a declared heap view), linking foreign objects (R2), a second board (RISC-V `virt` needs RISC-V memory operations first), DMA with the OI-07 states.

## Static linking — 2026-10-03 (ADR-129)

- `compile_board_image(..., objects=[...])`; compile C with `benchmarks.board_linked_c.CFLAGS` (`-fno-pic -fno-common -ffreestanding -fno-asynchronous-unwind-tables`).
- Next: archive member selection, x86-64 relocations so Linux static profiles can link C, and calls from linked C back into XAX (code-entry addresses through `externals`).

## Standard libraries — 2026-10-03 (ADR-130)

- `text_package(extent)` and `hashset_package(capacity)` return a `Library`: index it by export name for the function to call, and pass `.objects` to `program_store`. The application lives in `benchmarks/uniqcount.py`, and `python -m benchmarks.bench_oi36_stdlib` regenerates the evidence.
- Next: more families (arena allocator, growable vector over a caller-provided arena, UTF-8 validation), multi-value returns on native backends (removes span packing), and a versioning policy.

## Membership selection — 2026-10-03 (ADR-131)

- `membership` in `xax_x86_64_regalloc.compile_register_resident`: an analysis next to `fused`, plus `_member_bit_test`. Next: the same selection on the AArch64 frame and register paths, two-word masks for spans up to 127 (the JSON escape set), and a profile of the remaining `jsonmin` gap.

## Token test — 2026-10-03 (after ADR-123–131)

- Offline replays 67/67, zero model tokens. The model pair was skipped because the protocol and harness are unchanged since the last pair. See `XAX_STATE.md`.

## S4 — 2026-10-03 (ADR-132)

- Scalar operation typing is XAX (`XAX_TYPING_PYTHON=1` forces the bootstrap; regenerate with `xax_selfhost_typing.write_typing_store()`). Wiring: `_native_typing()` and the `proven_nodes` gate in `_parse_graph_uncached`. Next is S4b: aggregate/sum/call typing, then memory and resource facts, which are the bulk of the remaining verifier.

## S4b — 2026-10-03 (ADR-133)

- Aggregate and sum typing joined the XAX typing function (two-pass type decoding: scalars, then tuple/array/sum of scalars). Regenerate the store with `xax_selfhost_typing.write_typing_store()` after any change; `test_committed_store_is_the_built_program` fails otherwise. Next is S4c: move call, constant, and memory typing together with `_end_heap_views` and the pointer/owner/effect facts, which is most of the remaining verifier.

## S4c — 2026-10-03 (ADR-134)

- Resource/effect and meta typing joined the XAX typing function (third type pass; nodes carry an extra-word count, used by `effect.step` for operand identities). The agreement test compares exact outcomes (code, rule, entity) with the path on and off, because later passes (linear flow, resource-join siblings) can still reject a node whose typing is proven. Next is S4d, which is a larger step: the call/memory branches update pointer, owner, and effect facts, so the fact tables must move with them.

## S4d.1 — 2026-10-03 (ADR-135)

- Constants and terminators joined the XAX typing function. Python skips their checks via `proven_constants` and `proven_terminators` in `_parse_graph_uncached`; a proven constant still records its link fact. `NativeTyping.check` returns node verdicts and then block verdicts. Next is S4d.2, which is a design step: represent the fact tables (pointer facts with storage, offset, extent, permission, and window; owner and effect facts with initialized intervals; ended and live sets; per-edge exits; the fixpoint) as XAX data, starting with stack storage.

## S4d.2a — 2026-10-03 (ADR-136)

- `fact_free` in `_parse_graph_uncached` gates the fact loop (`range(0 if fact_free else ...)`; the for-else fixpoint failure is guarded). The XAX check's last output word is the memory-free flag. Proven `call.direct` nodes are not added to `proven_nodes`, because their branch also does view and resource borrowing. Next is S4d.2b: model stack storage facts in XAX (allocation, owner, effect with initialized intervals, lifetime end, leaks), so graphs whose only memory is stack storage also skip the Python passes.

## S4d.2b — 2026-10-03 (ADR-137)

- The facts engine is built from `xax_structured.Proc` helpers (`E` in `xax_selfhost_facts.py`): every helper is an XAX function `f(a, b, views) -> (bits<64>, views)`, with more arguments passed in header words `H_ARG + i`. State lives in the output view (layout in `_engine`). Add an operation by writing a handler and registering it in `build_engine`'s `handlers`; graph-level declines live in `_engine`. Then regenerate the store with `xax_selfhost_typing.write_typing_store()` and run `test_xax_selfhost_facts.py`.
- Cost: the per-process native compile is about 1.8 s. Caching the compiled image by store hash would remove it.

## S4d.2c — 2026-10-03 (ADR-138)

- To see why the engine declines a graph, patch `NativeTyping.facts` (as `test_xax_selfhost_facts.py` does) and call `native.decline_reason()`; header word `H_NODE` holds the node record being modelled. The native image cache lives in `~/.cache/xax-native` (override with `XAX_NATIVE_CACHE`).

## S4d.2d — 2026-10-03 (ADR-139): S4 complete

- To find graphs the engine declines, wrap `_parse_graph_uncached` and `NativeTyping.facts` over the suite and count graphs that parse but whose facts call did not accept. The result should be only seed graphs, parsed while `_TYPING_BUILDING` is set or while `_native_cfg()` is still loading.
- `target.op` lives in `xax_selfhost_target.py` and is registered in `build_engine`. Record and link helpers are `_layout`, `_has_link_function`, `_dependents_function`, and `_window_function` in `xax_selfhost_facts.py`.
- A direct call's aux words are `[count, summary blocks, operation count, operations, declaration count, (view, target) pairs]`, or `[0]` when there is neither a summary nor a declaration.
- After changing any XAX helper, rebuild its committed store: `write_typing_store()`, or `write_cfg_store()` for the CFG views. The store-equality tests check that the committed store is the built one.

## S5a — 2026-10-03 (ADR-140)

- `xax_riscv64._object_table` copies the store objects for the backend program (S5b; the S5a `_marshal` is gone), and `_compile_with_xax` turns its output into a `Riscv64Image`. Use `backend="python"` to compare, or `XAX_RISCV64_BACKEND_PYTHON=1` to disable the program.
- After editing `xax_selfhost_riscv64_backend.py`, run `write_backend_store()`. A test checks that the committed store is the built one.
- The program declines with `give(NONE)` (`_ok`) and records nothing about why. To debug, bisect with the differential in `test_xax_selfhost_riscv64_backend.py`.

## S5b — 2026-10-03 (ADR-141): S5 complete

- The backend program's front end (`_frontend`, `_translate`, `_interface`, `_erased`, `_node_info`, `_term_end`) reads the graph-decoder stream format from `xax_selfhost_graph`. A change to that stream must change these readers too.
- The output words are: `out[1]` the code word count, `out[2]` the range count, `out[3]` the offsets, `out[4]` the function order (object indices), `out[5]` the entry widths `[P, widths, R, widths]`, and `out[STREAM_AT]` the function count.

## S6a — 2026-10-03 (ADR-142)

- `_linear_flow` in `xax_selfhost_facts.py` sets `H_LINEAR`. The engine runs it right after laying out the graph, so it is set even when the fact passes later decline. `NativeTyping.linear_flow()` reads the flag, but only after a check that returned status 0; otherwise the header may be stale.

## S6b.1 — 2026-10-03 (ADR-143)

- `xax_compiler._XAX_VALID_OBJECTS` holds the CIDs XAX proved. `_xax_prove_objects` fills it at the start of `verify_store`. To compare against the bootstrap, clear the set, as `test_xax_selfhost_objects._bootstrap_accepts` does.

## S6b.2 — 2026-10-03 (ADR-144)

- The store verifier (`xax_selfhost_verify.py`) records the check behind its last 0 verdict in `out[2]`, as an index into `DECLINE_SITES`. Call `build_verifier_program()` in-process first so the codes are assigned.
- **Open: x86-64 register-resident lowering and aliased variables.** In `_function_ok`, `e.var("ne_results", p["ne_at"])` followed by `e.set("ne_at", ...)` and a branch produced a native value equal to the *new* `ne_at`. Storing the snapshot to memory, or binding `ne_at + 0`, was correct. Small `Proc` programs with the same shape compiled correctly, and the frame (spill-all) lowering could not run the program to compare. The `E.var` fresh-copy rule avoids the pattern in every E-DSL program. A root-cause fix belongs in `xax_x86_64_regalloc` (edge copies or home slots for block parameters bound to two names), with a regression test.
- Helper programs import each other at hash time (`xax_structured` hashes its types at import). `_xax_verify_store` therefore returns "not proven" on `ImportError` and while any helper is building. Otherwise a swallowed `ImportError` leaves the native hasher off for the whole process, which slows the suite about 3×.

## B1–B4 (RISC-V backend) — 2026-10-03 (ADR-145)

- Rebuild `bootstrap/xax_riscv64_backend.xax` with `write_backend_store()` after any change to `xax_selfhost_riscv64_backend.py`. The views-profile front end (pass A2 in `_translate`) must mirror `_pointer_extents` and `_rewrite_borrowed_views` in `xax_riscv64.py`.
- B4 takes about 6 minutes under Unicorn: run `XAX_FIXED_POINT=1 python -m pytest tests/test_xax_selfhost_fixed_point.py`, or regenerate the evidence with `PYTHONPATH=src python benchmarks/bench_selfhost_fixed_point.py --write`.
- `run_riscv64_views` maps the input view at `0x20000000` and the output view at `0x40000000`, and passes them in `a0` and `a1`. Read the output with one bulk `mem_read`: reading word by word is quadratic for a 2 MB image.

## S6b.3 — 2026-10-03 (ADR-146)

- In the verifier's object table, a graph fragment's payload is its decoder stream followed by `[body length, body bytes]`. `_program`'s record walk skips both. The store verifier is the only reader of that layout; the S5b RISC-V table is unchanged.
- `graph` (in `_graph_ok`) is shared by ordinary functions and group members. In a group it writes `[count, (member, span start, span end)...]` for each member graph; `_group_ok` uses that for the breadth-first orders and the erased graph bytes.
- `NativeStoreVerifier.verify(words, count, groups)` returns each proven group's member graph indices (read under the lock). `verify_object` parses them in member order.
- To decide a store directly with `_xax_verify_store`, run `verify_store` on it first. Type verdicts (ADR-143) come from that run, and without them no function is proven.

## Android counter upgrade and emulator notes — 2026-10-04 (ADR-153, ADR-154)

- Host setup for the full suite is in `README.md` (Getting started). The API 30 `google_apis` x86_64 emulator image with ARM translation is the only route to an `adb` target on a host without `/dev/kvm`; see `compiler/integration/android/README.md` for the watchdog, ANR, and attach-timeout problems and their workarounds.
- `python -m benchmarks.android_counter_app --device` records a device run of the committed counter APK (target identity, `hardware` flag). Only an EXECUTED run of the same APK hash is carried forward; rebuilding the APK resets it to UNEXECUTED.
- `python -m benchmarks.bench_android_counter_twin --device` is the R4 harness for the Android row: cold start and PSS of XAX against the Java + NDK twin. It counts only on arm64 hardware; the matrix must not cite an emulator run for performance or memory.
- Next for the Android row: the counter on a device (R3), the twin comparison on hardware (R4 sizes are already MEASURED), and write-then-rename persistence if torn writes matter. *(Later the same day the counter passed on an emulator, so the row is R3; see ADR-155.)*

## JVM R4 — 2026-10-04 (ADR-157)

- Re-measure with `PYTHONPATH=src:.:.. python -m benchmarks.bench_jvm_jsonmin --write` and `PYTHONPATH=src python benchmarks/bench_jvm_twin.py --write` from `compiler/`. They need `java`, `javac`, `jar`, and `kotlinc` on `PATH`; `kotlinc` 2.1.0 is the JetBrains release under `/opt/kotlinc` here.
- The jsonmin benchmark times each run through a small runner process. A child forked straight from the benchmark process inherits its ~1 GB Python heap in `ru_maxrss`.
- Backend invariants that the JVM tests guard:
  - every frame lists the same locals, and a slot is typed only if a value in it lives across a branch target;
  - a value left on the operand stack never feeds an edge or a copy, whose readers use its slot;
  - the generated `xax$ix`/`xax$cld1`/`xax$cst1` members throw the same `java.lang.Error` as the inline trap.

## JVM code size — 2026-10-05 (ADR-158)

- `_compile_method` runs a counting pass into a scratch pool, then the real pass. A `_KeepParameters` retry keeps a dead parameter's slot when reusing it would need a zero store before the parameter is read.
- Invariants that the JVM tests guard:
  - a value is evaluated at its reader only if it is pure, read once, in its own block, and not an edge argument or copy operand;
  - liveness charges such a tree's operands to its reader (`effective`);
  - aliases (`canon`) go through one-predecessor block parameters and repeated loads.
- `tests/test_xax_selfhost_riscv64.py::CrossTargetEncoderTests::test_encoder_lowered_to_the_jvm_agrees` is the largest JVM program in the suite. It caught both miscompiles found during ADR-157/158, so run it after any JVM backend change.


## Next steps: benchmarks below the 1.05× target — 2026-10-05

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

## Windows x86-64 R2 — 2026-10-05 (ADR-170)

- `xax_platform.win32_thread_api()` owns the bounded thread package: Win64 code-entry type, linear thread-handle resource, `CreateThread`, `WaitForSingleObject`, `GetExitCodeThread`, and `CloseHandle`.
- `win64-c` foreign entries are direct function addresses because the XAX Windows convention is already Win64. Keep them pure: proof parameters/results reject.
- Reproduce current evidence from `compiler/` with `PYTHONPATH=src:. python -m benchmarks.bench_windows_pe_hosted`; the thread artifact must exit 39 and the hosted fixture 1339.
- Next Windows work: file I/O plus a practical application for R3, then a Windows-host C + non-C runtime-bound comparison. PE exports, unwind/PDB/TLS, sockets, and float/aggregate allocator convergence remain open.

## Android retained-hook identity — 2026-10-05 (ADR-171)

- Stable API-102 IDs now belong to hook-installation semantics. Hot reload requires its ID to match the retained installation; process-lifetime hooks cannot carry an ID. Legacy ID-free installation CIDs are preserved.
- `benchmarks.bench_android_libxposed_hot_reload` regenerates the structural fixture. APK and DEX bytes remain unchanged; semantic/build roots change because the previously implicit ID is now declared.
- Next compiler slice: admit multiple `(adapter, retained installation)` pairs, reject duplicate IDs in the build closure, and replace each transferred old handle by ID. Runtime execution still takes precedence when a compatible libxposed device is attached.

## Android arm64 hardware R4 — 2026-10-05 (ADR-172)

- Device: Pixel 8 Pro, Tensor G3, Android 17/API 37. The committed counter APK passes the lifecycle/persistence oracle natively; evidence is in `android_counter_evidence.json`.
- `bench_android_counter_twin.py --device`: 16 tracked cold starts per arm, XAX 227.0 ms vs Java + NDK 223.5 ms (`1.016×`); median PSS 112,862.0 vs 113,411.5 KiB. Android is now R4 for this workload.
- Windows reproduction uses NDK `28.2.13676358`, build-tools `37.0.0`, `android-37.0`, and the host-portable `_llvm`/`_sdk` lookup in `bench_android_ndk_twin.py`. libxposed requires a compatible framework installation.

## Android platform contracts on hardware — 2026-10-05 (ADR-173)

- `integration/android/validate_platform_contracts.sh` now runs from Git Bash with the Windows r28c NDK. It keeps Windows local paths for `clang.exe`/adb while preventing MSYS conversion of `/data/local/tmp`.
- Pixel 8 Pro printed `XAX_PLATFORM_RUNTIME_OK file=1 thread=1 socket=1`; `android_platform_runtime_probe_evidence.json` records native arm64 hardware execution.

## JVM R5 handoff — 2026-10-06 (ADR-176)

- The 15-family JVM corpus and Java/Kotlin/XAX harness are in `compiler/benchmarks/jvm_r5_ai.py` and `compiler/benchmarks/run_jvm_r5_ai.py`.
- Run record: `compiler/benchmarks/ai_native/jvm-r5-full-results.csv`; summary: `jvm-r5-full-evidence.json`.
- 42/45 cells passed. Three fresh retries were blocked by the Codex usage limit before inference. Completed-cell XAX median is 0.7683× the lowest textual median, so R5 is not demonstrated; leave the matrix at R4/PROTOTYPE.
- After the account window resets, rerun only the three missing cells with the same fixed profile, then recompute the 0.50 median gate before any matrix promotion.

## Evidence and canonical-state integrity, EI — 2026-10-06 (ADR-177)

- Start S7b from this baseline. Summary in `XAX_STATE.md`; evidence `compiler/benchmarks/audit_remediation_evidence.json` (`python -m benchmarks.bench_audit_remediation --write` from `compiler`, about 6 minutes with the suite).
- First job on a Linux x86-64 host (OI-45): `PYTHONPATH=src python benchmarks/bench_selfhost_closure.py --write` and `benchmarks/bench_selfhost_x86_64.py --write` (they set `XAX_REQUIRE_NATIVE=1`), then the native self-hosting tests. Without Linux, `--bind-committed` refreshes only the host-independent fields and marks changed stores `native_rerun_required`.
- New modules and tests: `src/xax_native.py` (authority, W^X, cache, `bootstrap_dir`), `tests/test_store_regeneration.py`, `tests/test_audit_remediation.py`, `tests/test_wheel_install.py`, `tests/test_hosted_build_provenance.py`.
- Windows host: run tests with `PYTHONPATH=src;.;..` (semicolons). Skips are environment-only; none hides a failure.

## OI-45 self-hosting re-runs — 2026-10-07

- Done on Linux x86-64: `selfhost_closure_evidence.json` and `selfhost_x86_64_evidence.json` were regenerated under `XAX_REQUIRE_NATIVE=1`; no `native_rerun_required` entry is left. Native self-hosting tests pass: 97, plus 7 with `XAX_FIXED_POINT=1`.
- Still open in OI-45: the Linux and Android R4 re-measurements.
- Run evidence generators from a clean worktree at the revision you are recording. The closure generator takes about 22 minutes here.
- Cold-cache fix: with an empty `XAX_NATIVE_CACHE`, `XAX_REQUIRE_NATIVE=1` used to fail. Images made while the BLAKE3 hash, the store decoder, or the graph decoder is being built cannot be lowered by the XAX backend, because it reads graph-decoder streams. `host_image` now records them as Python lowering by design (`requested_authority: python`), like the backend's own image (`_bootstrap_order`). Earlier warm-cache evidence is unaffected: the cache key does not depend on which generator lowered an image, and gen1 equals the bootstrap reference byte for byte.

## S7b.1 rejection diagnostics — 2026-10-07 (ADR-179, ADR-180)

- A views ISA opts in with `DIAGNOSTICS = "<family>"`, `LOWERED`, and `LOWERED_NAME` (`X86_64` does; `RISCV64` does not, so `_legal` emits exactly `_ok` there and its store is unchanged). Each check is `_legal(e, isa, condition, rule, entity, expected, actual)`. Rules and codes live only in `VIEWS_RULES`. The per-function checks are in `_legality`, which runs inside `_translate` before the stream is written and keeps the bootstrap's order. Do not add a rejection anywhere else.
- Record format and renderer: `xax_selfhost_diagnostics.py`. Differential: `tests/test_xax_selfhost_diagnostics.py` (`backend="xax"` must equal `backend="python"`). Add a case there for every new rule.
- Next: S7b.2 (object table and image record from XAX), S7b.3 (RISC-V family), then S8 (verifier rejections). `compiler/migration/python_authority_inventory.json` lists what remains; update it when a component moves.

## S7b.2 object table and image record — 2026-10-07 (ADR-181)

- Input of both views programs: `[S, entry CID words]`, then S store records in store order and the bound target record: `[kind, reference count, reference CIDs..., own CID, payload length, payload...]`. `G_REFS` holds the resolved indices; use `_reference` and `_cid_at`/`_cid_words`, and never read reference indices from the input.
- Output: words 1–5 are code count, range count, offsets, image record (`CID_WORDS + 1` words per function: CID, end), and widths. Read it with `collect_program_output`.
- A pinned closure size in `test_xax_selfhost_fixed_point.py` counts the backend's functions; adding a program function changes it.

## S7b.3 and S7b complete — 2026-10-07 (ADR-182)

- Both views families opt into diagnostics. `_legal(..., deferred=True)` exists for checks the bootstrap makes after layout. It records the first failure in `G_PENDING`, and `_program` rejects only after patching succeeds. Keep that order if a family gains layout-time rejections.
- Next is S8: verifier totality. Start with the store container (`xax_selfhost_store.py`): one reject site per bootstrap check, two record value types (FORMAT for templated text such as `"{} available bytes"` and `"record:{}"`, HEX for byte strings), and a two-pass digest protocol (the decoder finds `digest_end`, the XAX hash computes the digest, a second pass decides the comparison and the index and root checks that follow it in the bootstrap's order).

## S8a store-container rejections — 2026-10-07 (ADR-183)

- Add a container rule by adding a `SITES` entry (code, rule, value forms over v0–v3) and a `fail_unless(condition, site, entity, values)` at the bootstrap's point in `build_decoder_program`. Keep the bootstrap's order: trailer and end, then the digest, then the index, then the root.
- `NativeDecoder.decode(data, verify_digest, digest)` runs the two digest passes. `MODE_*`, `NEED_DIGEST`, and the out layout (`INDEX_AT`, `DIAG_AT`) are at the top of the module. The record is in (low, high) 32-bit pairs, read with `xax_selfhost_diagnostics.decode_record`.
- Next (S8b): object envelopes (`decode_object`, reached through `StoreReader.get`; the S3b parse marks bad envelopes unparsed today) and graph bodies (the S3c decoder rejects without a diagnostic). Use the same site-table pattern.

## S8b.1 object envelopes — 2026-10-07 (ADR-184)

- `NativeDecoder.decode_object(envelope, cid_of)` runs the two object passes on one envelope. `StoreReader._decode_object_native` uses it for natively decoded stores and builds the object from the program's fields.
- Next (S8b.2): graph bodies. The S3c decoder (`xax_selfhost_graph.py`, its own `_GraphDecoder` over a 64-bit stream) rejects without a diagnostic, and `_parse_graph` then re-parses with the bootstrap. Give it the same site table and shared diagnostic block, and keep the bootstrap's order, including the deferred value checks that `_parse_graph` makes while it walks the stream.

## S8b.2 graph-body rejections — 2026-10-07 (ADR-185)

- Decoder rejection sites share `_SiteDiagnostics` (`xax_selfhost_store.py`). A decoder supplies `SITES`, `ENTITIES`, `block_state`, `diagnostic_block`, `begin_record`/`put`/`finish_reject`, and optionally `d_custom`.
- In the graph decoder (`xax_selfhost_graph.py`), decide a value with `read` before you `emit` it: the stream prefix up to a rejection is walked by `_graph_syntax_from_stream(..., prefix=True)`, which must never see an undecided value.
- Next (S8c): what `_graph_syntax_from_stream` and the verifier still decide in Python: resolution, `_verify_type`, trap payloads, typing and facts declines, and object-level verification declines.


## JVM snapshot-bound follow-up (2026-10-07, ADR-186)

*Superseded workflow: use the ADR-187–189 host-response follow-up below for
current work; the bound-profile records and commands here are historical.*

The normal adapter is `compiler/src/xax_local_protocol.py`. Roles in the intent must be bound explicitly to exposed handles. A batch retains pre-batch handles; new results use `@ID`. Never reconstruct a stale session implicitly.

Use `compiler/benchmarks/ai_native/jvm-r5-bound-results.evidence.json` for the fresh repeated comparison and the bound manifest for source hashes. The local profile is exploratory history, preserved with all failures and its source snapshot. Resume with `python -m benchmarks.run_jvm_r5_ai --repetitions 3` from `compiler/` with `src` and `.` on `PYTHONPATH`, JDK tools and Kotlin available. Do not combine different profiles. Every failed attempt remains in successful-cell cost; incomplete/unknown-usage cells cannot pass the gate. Creation's scaffold and large-application equivalence still require review before matrix promotion. JVM remains R4.

## JVM host-response follow-up (2026-10-07, ADR-187–189)

Normal snapshot setters, dead-chain pruning, compact aliases and multi-result
help are implemented. A redundant Kotlin literal conversion is admitted only
with matching compiled instructions; an overload-changing conversion rejects.
Affected validation: 142 tests and 167 subtests passed on Windows/JDK 17.

Response-v4 remains separate incomplete negative evidence: 137 attempts,
134/135 successful cells, all costs known, partial ratio 0.501623. Its checker
falsely rejected an equivalent explicit Kotlin literal conversion. The source
snapshot and independent raw-usage audit are retained unchanged.

The current response-v5 comparison runs three trials for each of the 15
Java/Kotlin/XAX task families. Use its CSV, evidence JSON, manifest and streamed
traces under `compiler/benchmarks/ai_native`; do not import older cells. Source
bytes are frozen during inference. Resume with `benchmarks.run_jvm_r5_response`
only after ensuring no runner is active; never start a second CSV writer.
A `runs-jvm-r5-response-v5/STOP` file stops safely between cells. Every failed
response/attempt remains in successful-cell cost. Independently audit using
`benchmarks.audit_jvm_r5_response` before reporting a complete numeric result.

JVM stays R4/PROTOTYPE pending the complete result and corpus review. The graph
is host-projected while textual edits inspect a named file; the large fixture
is synthetic and resource effects are abstract verifier contracts. This work
makes no JVM backend-speed or native self-hosting claim.

## JVM continuation on the transferred host (2026-10-07, ADR-190)

Response-v5 stopped with 60/135 successful cells; the partial ratio is
0.5003204395. Its unrecorded jvm-06-java-2-1 attempt contains turn.started
without final usage. See jvm-r5-response-v5-interruption.json and the
continuation audit. The CSV, raw traces and source snapshot are preserved.
Unknown cost blocks the old profile permanently unless its original complete
trace is recovered; do not discard the attempt or import its successful rows.

The current runner defaults to response-v6, with lossless per-function result
type defaults and checker toolchain versions pinned before inference. Local
tools are under .venv/jvm-r5-tools (Temurin JDK 17 and Kotlin 2.1.0); use the
Codex 0.160.0 executable from the desktop app, not the older npm shim. Set
JAVA_HOME and prepend those bin directories to PATH, and set PYTHONPATH to
src;.;.. from compiler/. Run benchmarks.run_jvm_r5_response, with only one
runner active. Source bytes must remain frozen until inference finishes.
Independent audit and complete three-trial evidence are still required; the
synthetic/helper/resource/context limitations remain unchanged. JVM stays R4.

## JVM bound-field continuation (2026-10-07, ADR-191)

Response-v6 is complete: 135/135 cells, 142 attempts, all costs known, ratio
0.5002551375; its independent audit has zero errors. It misses 0.50 and is
archived unchanged. Current defaults are response-v7, using ordinary bound
kind/node requests for the eight applicable named scalar-edit task families.
The model still chooses every new semantic field; no expected target enters
the normal adapter. Compound and no-remaining-field edits keep full batches.
The same local toolchain/PATH setup applies. Keep sources frozen and one runner
active, retain failed costs, and independently audit before any gate claim.

## JVM immutable scalar binding (2026-10-07, ADR-192)

Current defaults are response-v8. Response-v7 stopped safely at 11 successful
cells with complete accounting and a clean audit before a binding-retargeting
guard was added. No old rows are imported. Bound constant/arithmetic views now
include only the selected node's old value/operation and width; other edit kinds
retain the candidates they need. Bindings are immutable and reject alias drift.
Validation: 145 tests and 167 subtests passed. Keep the v8 sources frozen, only
one runner active, and audit the complete three-trial corpus before a gate claim.

## JVM command compatibility continuation (2026-10-07, ADR-193)

Current defaults are response-v9. Response-v8 stopped safely at 71/135 successful cells in 74 attempts, with every cost known and zero independent audit errors. Its source snapshots and CSV are retained. Matching full commands are accepted only within the immutable bound kind/target; movement and rejected bound requests use ordinary full batches. Validation: 146 tests and 167 subtests passed. Run one writer, freeze sources during inference, retain every failed cost and audit the complete three-trial corpus before reporting the gate.

## JVM token gate complete; next is corpus review (2026-10-07, ADR-194)

*Superseded as R5 evidence by ADR-195 (2026-10-07): the corpus review found the comparison context-asymmetric; see the response-v10 section below.*

Response-v9: 135/135 successes, 142 attempts, ratio 0.4984232980894083. Independent audit and usage/source/digest checks pass with zero errors. All seven failures count; do not drop retries or mix profiles. The CSV SHA-256 is a2e678fb689910fac1cd9844ad5834f8ab7876d8eb72e54a0d290f056b0c93ce. Inference has finished and no runner is active. Preserve frozen source snapshots and traces.

Next: review equivalence of caller-selected semantic node versus named textual file, exact-root versus strict textual oracle, synthetic large-application helpers and abstract resource contracts. The agent command review found only named Java/Kotlin program reads, with no unexpected context commands. This does not replace corpus review. Keep JVM R4/PROTOTYPE until that review supports promotion. Numeric token optimization is complete; aggregate XAX/textual tokens are 0.747651x, distinct from the median gate.

## JVM corpus review; same-prefill v10; R5 blocked on OI-46 (2026-10-07, ADR-195)

*Superseded by ADR-196 (2026-10-07): option (a) measured; see the response-v12 section below.*

Response-v9 is not R5 evidence. In every textual edit cell the model read its file through a tool call, a second client request with about 10,000 tokens of fixed client context. XAX got its view inline, along with an out-of-band mutation kind and target. On creation, where nobody reads a file, XAX was 1.007× Java. Response-v9 rows, traces and audits are retained unchanged.

Response-v10 is same-prefill: every arm gets inline context and one request with no tools, and XAX is unbound. Textual checks admit equal compiled JVM instructions that differ from the initial program. The status distinguishes `TARGET_MET` (≤ 0.50), `ACCEPTED_WITHIN_TOLERANCE` (≤ 0.55, owner-approved) and `NOT_R5`. The pilot (jvm-01 and jvm-15, one trial, CSV SHA-256 f4839408a24567cd66a20a8014375fd334a9522d2322a90bb0f0a7f051f66c23) gives Java 10,753/10,723, Kotlin 10,738/10,747 and XAX 21,965 (one repair)/10,834. Even with one-line instructions the client still uses about 6,900 input tokens per request, so a fair ratio stays near 0.93× or above.

The full 135-cell v10 run has not been executed. Resolve OI-46's measurement design first. Validation: 29 JVM R5 tests pass on Windows with Temurin 17 and Kotlin 2.1.0. JVM stays R4.

Next step: the owner chooses an OI-46 measurement design, either a minimal client with no tool schemas for every arm or a real multi-file corpus. Then run the full v10 with `--repetitions 3` under the ADR-190 toolchain setup (Codex 0.160.0 desktop executable, `.venv/jvm-r5-tools`), keep only one writer active, and audit with `benchmarks.audit_jvm_r5_response`.

## JVM minimal-client run; R5 unmet (2026-10-07, ADR-196)

*Superseded by ADR-197 (2026-10-08): option (b) measured; see the multi-file section below.*

The run uses option (a) of OI-46. Every arm goes through the pinned Codex client with all configurable optional tools, skills and instruction blocks removed, one-line base instructions, and `gpt-6-luna` at low reasoning. The fixed per-request floor was calibrated at 3,501 input tokens, identical in three samples. The gate subtracts it once per request from every arm, and failed attempts still count.

Two adapter defects were fixed first, and each fix started a new profile. Edit forms are now listed one per line as labelled placeholders. Cross-function views now alias callee parameters instead of leaking `F2.B0.P0`. v10 (stopped) and v11 (stopped, 113/135 cells) are retained unchanged.

Response-v12 had 151 attempts and 123/135 successful cells after one refill pass. 28 attempts failed: XAX 16, Kotlin 10 and Java 2. Medians including failed costs were Java 3,710, Kotlin 3,702 and XAX 3,701. The raw ratio is 0.99973 and the floor-adjusted ratio is **0.99502**. Aggregate recorded tokens were Java 200,712, Kotlin 283,035 and XAX 322,843. The independent audit has zero errors and no source drift. CSV SHA-256: c39f72bedb1e7162938ab1d642669be7c0fe9846fd4bad4c794c332c94cc6bac.

R5 is unmet, with a target of 0.50 and acceptance at 0.55. On single-function edits the XAX view plus edit list costs about the same as the inline program plus a patch, and the model repairs XAX more often. 12 cells never passed: XAX jvm-07, jvm-09, jvm-14 and jvm-15, and Kotlin jvm-12 and jvm-14, where "u16" invites `UShort`. JVM stays R4. Validation: 47 JVM R5/local-protocol tests pass.

Next step: an owner decision on OI-46. Option (b) is a real multi-file corpus where the textual workflow needs more context than a named-symbol excerpt. Option (c) records R5 as unreachable for single small edits. Under (b), first fix the Kotlin u16 wording, then run a new profile with `--repetitions 3` using the ADR-190 toolchain setup. Keep only one writer active and audit with `benchmarks.audit_jvm_r5_response`.

## Android hardware follow-up (2026-10-07, ADR-197, ADR-198)

- Device setup: rooted Pixel 8 Pro over wireless adb (KernelSU 3.1.2, Zygisk Next, Vector v2.2). With more than one device attached, set `ANDROID_SERIAL`. Windows tools: SDK build-tools 36.0.0, NDK 28.2, `android-36`, Temurin 17 from `.venv/jvm-r5-tools`. The libxposed AAR is `XAX_LIBXPOSED_AAR` (pinned SHA-256).
- Vector harness: `python integration/android/vector/vector_harness.py` from `compiler/` (heap oracle by default). Nine checks remain UNEXECUTED because JDWP attach aborts Vector-hosted ART on API 37. Re-test `--oracle jdwp` after a Vector or ART update.
- ART layers on hardware: `XAX_ART_DEVICE=1 python -m benchmarks.bench_android_art_verify` / `bench_android_art_execute`.
- R4: `python -m benchmarks.bench_android_counter_twin --device` (about 15 minutes; the phone must be on AC power with Battery Saver off). Next: more starts per pass to bound the drift, and a Kotlin arm if Android code size matters.
- The ART execute stand-in still never calls the hot-reload callbacks; only Vector exercises them.

## Android managed classes for AutoHead (2026-10-07, ADR-199)

- New Android callbacks: declare an `AndroidManagedClass` (`xax_android_managed.py`), export one function per method named by `jni_short_native_symbol(class, "xax<Name>")`, with ABI `(JNIEnv*, borrowed this, args...)`. Use `android_arm64_shared_general_target()` when the export needs comparisons or the other general operations. Fixture and device oracle: `benchmarks/bench_android_managed.py --device` (needs `ANDROID_SERIAL`; the phone must be unlocked; media volume is restored with VOLUME_DOWN because `volume --set` is ignored on this build).
- Next for AutoHead, in dependency order: (1) execute an XAX graph that calls SDK members over JNI on the device (construct `SurfaceView`, `getHolder().addCallback(new SurfaceCallback())`); (2) uses-permission/feature entries in the manifest carrier; (3) exact JNI `float` carriers (MotionEvent coordinates); (4) NDK imports for `AMediaCodec`/`ANativeWindow_fromSurface` and AAudio, which avoid JNI on media hot paths; (5) services and receivers in the managed-class profile.

## JVM multi-file corpus; R5 unmet (2026-10-08, ADR-197)

`benchmarks.run_jvm_r5_multifile` compares XAX with four textual workflows on generated five-class projects. The textual workflows are Java and Kotlin, each with whole files or an IDE-style excerpt of the same call hierarchy. There are three families: a cross-file API change, a large-class operation change with its dependent assertion, and a transitive constant change. XAX gets the target and its transitive callers from the workspace `callers` query. Client, model (`gpt-6-luna`, low) and the calibrated 3,501-token floor are as in ADR-196.

Profile v5 had 48 attempts and 42/45 cells after one refill pass. Floor-adjusted medians:

| Arm | Median |
|---|---|
| Kotlin excerpt | 286 |
| Java excerpt | 306 |
| XAX | 481 |
| Kotlin files | 1,315 |
| Java files | 1,391 |

XAX is **1.68×** the lowest textual median (raw 1.05×) and 0.35× the whole-file workflows. XAX had 6 failed attempts and the textual arms none. Every XAX mf-02 attempt changed the operation but not the assertion constant. CSV SHA-256: 9414ad6a56deac5ef95939b6de419e0bdb033be60c535142360dd04a39f8c0aa. Profiles v1–v4 were stopped for protocol defects and are retained.

Normal-protocol work from this corpus:
- A workspace fix: an edited function no longer calls a stale, rebuilt callee.
- Exact `type OLD NEW` and `type F OLD NEW` retypes.
- Removal of edits the batch already implies.
- Kind-specific node diagnostics.

R5 is unmet and JVM stays R4. The remaining gap is the per-request edit-form help, which the textual arms don't pay because the model knows Java and Kotlin, and lower model reliability on XAX.

Next options, which are the owner's decision:
- Reduce or cache the per-request edit-form help as shared context: a protocol design question, and it must apply to normal use. *Implemented in ADR-200 (2026-10-08); see the shared edit grammar section below.*
- A stronger reasoning setting for all arms.
- Record R5 as unmet for this model class.

Rerun with `python -m benchmarks.run_jvm_r5_multifile` from `compiler/`, using the ADR-190 toolchain setup and a new profile name after any source change.

## Shared edit grammar (2026-10-08, ADR-200)

The per-request edit-form help is now optional in the normal protocol. `edit_grammar()` is the complete, request-independent carrier grammar, and `edit_grammar_id()` is its identity. A client sends the grammar once as shared context, and `session.instructions(shared=ID)` then adds nothing per request. A stale ID rejects, and acceptance rules don't change. The protocol is specified in `docs/09_AI_PROTOCOL.md`.

There is no model measurement yet. In the existing one-request-per-cell profiles the grammar would still be sent with every request, and the full grammar (about 1 KB) is larger than the filtered help. The saving needs multi-request sessions or prompt caching. A new R5 profile has to pin the grammar as shared context, count it, and leave its accounting against textual arms to the owner. R5 is still unmet and JVM stays R4.

## Multi-file profile v6 with the shared grammar (2026-10-08, ADR-201)

`python -m benchmarks.run_jvm_r5_multifile` from `compiler/` now runs profile v6. The XAX arm holds the shared edit grammar in its client base instructions and gets no per-request edit help. The runner calibrates the common floor and the XAX floor (`calibration-xax.json`); their difference is the grammar's cost per request. The gate counts that cost in every XAX request. The evidence JSON also reports informational ratios with the grammar counted once per attempt and excluded, for the owner's accounting decision. No inference has been run. Use the ADR-190 toolchain setup with one writer, `--repetitions 3`, and keep every failed attempt. R5 is still unmet and JVM stays R4.

## Android platform capability contracts (2026-10-08, ADR-202 to ADR-204)

JNI `F`/`D` are exact, the managed-class APK takes an `android-platform-declarations-v1` carrier, and `xax_android_platform` plus `xax_platform.posix_async_api` give ownership-typed NDK/POSIX contracts and an SDK capability table that the managed build enforces. Per-capability status: `docs/ANDROID_PLATFORM_CAPABILITIES.md`. Everything is STRUCTURAL. Next, on the authorized device: run a managed APK that forwards `onTouchEvent` and reads `getX`/`getY`, a SurfaceHolder callback that acquires and releases an `ANativeWindow`, an AMediaCodec decode loop, an AAudio output stream, and an RFCOMM connect/close; then close OI-47's gaps.

## Byte-view widening — 2026-10-08 (ADR-231)

- The rule is in `_verify_memory_node` (`BYTE_ELEMENT_CID`, `CHECKED_BYTE_VIEW_WIDTHS` in `xax_compiler.py`) and mirrored in the facts engine's `_checked`. A backend that cannot do unaligned wide access sets `BYTE_VIEW_WIDENING = False` on its ISA class (views backends) and rejects in its Python lowering with the same text (`BYTE_VIEW_WIDTH_EXPECTED`).
- In the XAX views backend, `value_id` advances the stream cursor: read an operand's id once and keep it.
