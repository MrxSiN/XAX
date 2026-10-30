# XAX Compiler Handoff

## Contents

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

## Invariants that must not drift

- Meaning is source: canonical XAX is the typed semantic graph/store, never diagnostic text, Python constructors, packet dumps, JSON, or CLI syntax.
- Bootstrap labels B0–B6 are evidence claims. Capability presence, plans, or host-language simulation do not satisfy them.
- B5/B6 claims are target-scoped. The M14 `xax-semantic-image-v1` result does not silently close the legacy native, WebAssembly, or accelerator backends.
- B levels come only from `xax_selfhost.bootstrap_status` (generated blocks below); S-step self-compilation is a component fixed point, never B1–B4 (ADR-177).
- Committed stores are what their builders make (`tests/test_store_regeneration.py`); the M14 seed is pinned and only `generate_m14.py rotate-seed` writes it; evidence that claims XAX-hosted execution runs with `XAX_REQUIRE_NATIVE=1`.
- No hidden allocation, synchronization, syscall, initialization, exception edge, ownership transfer, device runtime, or target runtime assistance.
- Tests/benchmarks count only when actually executed. Host-unavailable cases remain unavailable, not passed.

## Current repository state

<!-- xax-status:levels -->Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): R6: jvm, linux-aarch64, linux-x86_64; R3: android-arm64; R2: aarch64-baremetal, browser-web, windows-x86_64-pe; R1: gpu-spirv-cuda-metal-dxil, riscv64, wasm32-core, wasm32-wasi; R0: accelerator-simt-packet; no level yet: bsd-unix, dotnet-clr, macos-ios-apple, rtos-embedded-mcu.<!-- /xax-status:levels -->

<!-- xax-status:bootstrap -->Bootstrap status (generated from `compiler/bootstrap/m14_selfhost_evidence.json`, derived by `xax_selfhost.bootstrap_status`): whole production compiler: B0, B1, B2, B3, B4, B5, B6 established (derived from the Linux x86-64 production compiler, whose executed record covers every target and artifact `build` makes (S15g, ADR-358)); Linux x86-64 production compiler (`benchmarks/full_selfhost_evidence.json`): B0, B1, B2, B3, B4, B5, B6 hold, none do not; its seed requires Python: no; M14 semantic-image META wrapper: B2, B3, B4 hold, B5, B6 do not (host-executed META_CANONICAL_STORE, META_MATERIALIZE_PROGRAM, META_VERIFY_SEMANTICS). S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: python-zipapp, 46,255 bytes, requires Python: yes.<!-- /xax-status:bootstrap -->

Sections below are dated; a later section supersedes an earlier figure. The current full-suite result is under "Multi-language performance rule" and later entries in `XAX_STATE.md`.

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

#### S16a native workspace — 2026-10-30 (ADR-360)

- The workspace helpers are `ws_*` in `xax_selfhost_edit.py`; `ws_command` classifies `edit`'s input. Helpers keep their state in workspace words (`WSC` control words, `EIN`/`WS_IN`/`BATCH` regions).
- E-DSL pitfalls met here: a helper argument or variable must not be named `ip`, `iv`, `im`, `op`, `ov` or `om` (the view triples); a graph over about 4,000 blocks declines in the XAX verifier; inline text output (`_out_text`, `D.text`) multiplies nodes, so tables of packed words and loops keep helpers small.
- The driver's main function has about 600 values left under `VCAP` (`xax_selfhost_general_view`). Count with the snippet in ADR-360's work (`values = sum(params + node results)` of the entry graph) before adding a driver stage; each `emit` call or new command adds dozens of blocks of about 95 parameters each.
- Debugging a seed decline: build the committed driver with `XAX_DRIVER_DECLINE_SITES=1`, let the seed build it, and run it (the exit status names the site). Inside the general backend, `_ok` records no reason; instrument it temporarily (`H_REASON`) to find the check.

#### S15e.6i.3 records, compressed branding, large inputs — 2026-10-30 (ADR-359)

- The module record is decoded to code points (`an_jdecode`) and parsed with an explicit stack (`an_jparse`); value nodes are listed above `_jcp` in `xax_selfhost_android.py`. Python's rules over them are the `an_j*` helpers. A check belongs where the bootstrap fails: before `LIBXPOSED-JVM-INPUTS` only what fails before it (J1); the rest in J3/J4.
- Compressed entries go through `an_entry_bytes`: `an_inflate`, `an_bunzip` (libbz2 1.0.8) and `an_unlzma` (liblzma 5.4.5). Every stop on short input ends in `an_zfinish`, which keeps `file_size` bytes and checks the CRC.
- Large data lives in the image buffer once no AArch64 program can run again (`big_writer`, `an_bigalloc`): inputs from its start, records from its end.
- A decline must leave the status word 0: the frontend clears it. Debug declines with `XAX_ANDROID_WHY=1` after `build_android_program()` in the same process (it fills `DECLINE_SITES`).
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
