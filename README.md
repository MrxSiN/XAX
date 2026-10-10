# XAX

**An AI-native programming language. Meaning is the source.**

![Status](https://img.shields.io/badge/status-research%20prototype-orange)
![Python](https://img.shields.io/badge/bootstrap-Python%203.11%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

XAX has no text syntax. A program is a verified **semantic graph**. AI agents read the smallest part they need, send a small typed edit, and the compiler verifies it and builds machine code or a platform artifact directly.

The goal: one small language that can build what C, Rust, Java, Kotlin, Swift, JavaScript, Python and others build today — from firmware to apps to GPU kernels — with **zero hidden runtime cost** (no mandatory GC, allocator, VM, exceptions, or runtime library).

## How it works

```text
intent -> AI -> small semantic edit -> verified XAX graph -> optimize -> target artifact
```

- **Tiny kernel**: values, arithmetic, aggregates, control, calls, memory, resources, effects, atomics, target ops, compile-time meta.
- **Everything else is a library or package**: strings, collections, objects, async, GC — you pay only for what you use.
- **Platforms are packages**: ABI, OS, and target packages lower the same semantics to ELF, PE, DEX/APK, JVM class files, WebAssembly, SPIR-V, and raw images.

## Replacement levels

A platform gets a level only when evidence exists. Levels are cumulative. Full rules: [`XAX_SPEC.md`](XAX_SPEC.md) §21.2.

| Level | Meaning |
|---|---|
| R0 | The workload can be expressed exactly in XAX |
| R1 | XAX builds a target artifact that runs |
| R2 | Platform ABI, system APIs, and libraries work |
| R3 | A real application runs |
| R4 | **Faster**: median time ≤ 0.9999× the fastest non-XAX build, with a real (not noise) advantage |
| R5 | An AI maintains the app through semantic transactions |
| R6 | A complete app is built and maintained 100% in XAX |

AI token efficiency (≤ 0.50× textual languages) is a later milestone, not a level.

## Targets

Generated from [`XAX_REPLACEMENT_MATRIX.json`](XAX_REPLACEMENT_MATRIX.json). "—" means not started.

<!-- xax-status:targets -->
| Target | Matrix id | Level | Status |
|---|---|---|---|
| x86-64 Linux | `linux-x86_64` | R6 | Direct ELF64 executables via syscalls, optionally with declared shared-library imports; jsonmin executes as the R3 application. R4 (ADR-212 run): filestat 0.852x and jsonmin 0.959x clang -O2, chains 0.911x rustc -O3, all significant on one shared host; jsonmin's margin is small (an earlier binary measured 0.968x and 1.029x in two runs). R5: one jsonmin maintenance cycle through semantic transactions (ADR-213). R6: xb64, an application developed and maintained only in XAX (ADR-210). |
| AArch64 Linux | `linux-aarch64` | R6 | Static and dynamic ELF executables. The static jsonmin image runs on two phones' Android kernels: on Pixel 8 Pro (Tensor G3) 0.956x NDK clang -O2 -static, the fastest non-XAX arm, and on the original Pixel (Snapdragon 821) 0.898x, ahead of rustc -O3 on both, over 101 interleaved pinned rounds each (ADR-254). Dynamic images and the filestat application run only under qemu-aarch64 (Android has no glibc loader). R5 (ADR-258): one jsonmin maintenance cycle through a semantic transaction, rebuilt and tested on Pixel 8 Pro. R6 (ADR-258): xcksum, a POSIX cksum constructed in one xax-construct-v1 request for the new linux-aarch64 platform, tested by its own XAX selftest, and released twice (release 2, cksum -H, is one workspace transaction); both releases match toybox cksum on 26/26 inputs on both phones. |
| JVM | `jvm` | R6 | Direct class files in a deterministic JAR with typed JDK member calls; linear memory, aggregates, sums, stack allocations, indirect calls, links, atomics, callbacks, object/array construction, and fields; native-plus-JNI strategy and JDK metadata imports. R4 for one workload: jsonmin's median is 0.865x the fastest non-XAX arm (javac), significant over 15 interleaved fresh-JVM runs per arm (re-run after ADR-212). R5 for one maintenance cycle (ADR-209): an AI agent raised jsonmin's depth limit through one semantic transaction, then the JAR was rebuilt, tested, benchmarked, and the store committed. R6 (ADR-257): xwc, a GNU wc-compatible word counter, was constructed in one xax-construct-v1 request, tested by its own XAX selftest, built as JARs by the canonical build service, and released twice: release 2 (UTF-8 words) is one workspace transaction, and both releases match GNU wc on every test input. The former AI-token trials are historical (ADR-207). |
| Android (arm64-v8a) | `android-arm64` | R3 | Direct DEX, manifest, resources, signed APKs, JNI shared objects, and libxposed API-102 modules executed under Vector v2.2. On Pixel 8 Pro the stateful counter app's cold start ties its Java + NDK, Java, and Kotlin twins (all within 2.5%, ADR-253), and the AArch64 jsonmin image runs at 0.956x NDK clang -O2 -static (ADR-254); the cold-start tie keeps the row at R3. One maintenance cycle (cap the count at 9999: three semantic transactions, rebuilt APK tested on the device) is recorded for R5 (ADR-255), which the row derives once it holds R4. |
| x86-64 Windows | `windows-x86_64-pe` | R2 | Direct PE32+ executables executed on Windows 11; Win64 calls and callbacks, linear thread-handle lifecycle, and kernel32 loader imports. |
| AArch64 bare metal | `aarch64-baremetal` | R2 | AAPCS64 images with a QEMU `virt` board package (reset/fault stubs, vector table, one interrupt source); executed under QEMU only. |
| Browser (WebAssembly + generated glue) | `browser-web` | R2 | wasm32 page whose JavaScript glue is compiler-generated from imported `xax-web-v1` declarations; four DOM bindings executed. |
| WebAssembly (wasm32) | `wasm32-core` | R1 | Direct module emission with no imports; executed in a host WebAssembly engine. |
| WebAssembly + WASI | `wasm32-wasi` | R1 | wasm32 modules with three WASI imports (args, `fd_write`, exit); executed under Node.js `node:wasi`. |
| RISC-V (RV64IM) | `riscv64` | R1 | Raw position-independent images, LP64 integer calls; executed under the Unicorn emulator; the XAX-hosted RISC-V backend and store verifier reach component fixed points here (S-steps, not B milestones). |
| GPU (SPIR-V/Vulkan; PTX, Metal, DXIL planned) | `gpu-spirv-cuda-metal-dxil` | R1 | Direct SPIR-V compute modules executed on Mesa llvmpipe (a CPU Vulkan driver), not GPU hardware; integer words only. |
| SIMT accelerator packet | `accelerator-simt-packet` | R0 | Synthetic deployment-packet format checked by conformance tests only; no execution. |
| macOS / iOS / iPadOS / watchOS / tvOS / visionOS | `macos-ios-apple` | — | Not started: no Mach-O container, Apple ABI package, or Objective-C runtime contract. |
| .NET CLI/CLR | `dotnet-clr` | — | Not started: no CLI metadata/IL container. |
| RTOS / embedded MCU (Cortex-M, RISC-V MCU) | `rtos-embedded-mcu` | — | Not started: no MCU target, vector table, or linker-layout package. |
| BSD / other Unix | `bsd-unix` | — | Not started: no FreeBSD/OpenBSD/NetBSD syscall, ELF note, or libc ABI package. |
<!-- /xax-status:targets -->

## Quick start

Requires Python 3.11+. No third-party runtime dependencies.

```bash
cd compiler
pip install -e '.[test]'
xaxc --help
PYTHONPATH=src:.:.. python -m pytest -n auto tests
```

Tests that need a missing host tool (QEMU, Wine, JDK, Android tools, …) are skipped; skipped is not passed. Full host setup: [`XAX_BENCHMARKS.md`](XAX_BENCHMARKS.md#host-setup-for-the-full-test-and-benchmark-suite).

AI agents: read [`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md) and [`CLAUDE.md`](CLAUDE.md) first.

## Status

Research prototype. Part of the compiler (hashing, decoding, typing, the store verifier, and two code generators) is itself XAX; the rest is Python.

Recent results (one shared x86-64 host; details in [`XAX_BENCHMARKS.md`](XAX_BENCHMARKS.md)):

- **Linux x86-64 is R6**: faster than the fastest C/Rust build on `filestat` (0.85× clang), `jsonmin` (0.96× clang, a small margin) and `chains` (0.91× rustc); maintained through a semantic transaction; and `xb64` below is 100% XAX.
- **JVM is R5**: `jsonmin` runs 0.87× javac, and an AI changed it through one semantic transaction, then rebuilt, tested, and benchmarked it.
- **First XAX-only app**: `xb64`, a base64 tool whose code, tests, and build are all XAX, matches coreutils `base64` and shipped a second release through one transaction.
- **The verifier rejects in XAX**: on Linux x86-64, every rejection in the test suite is decided by XAX code, with the same message the Python verifier gives (S8).

<!-- xax-status:bootstrap -->Bootstrap status (generated from `compiler/bootstrap/m14_selfhost_evidence.json`, derived by `xax_selfhost.bootstrap_status`): whole production compiler: none of B0-B6 is established (no canonical XAX store implements the whole compiler; S9 and later steps are open (ADR-180, ADR-251)); M14 semantic-image META wrapper: B2, B3, B4 hold, B5, B6 do not (host-executed META_CANONICAL_STORE, META_MATERIALIZE_PROGRAM, META_VERIFY_SEMANTICS). S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: python-zipapp, 46,255 bytes, requires Python: yes.<!-- /xax-status:bootstrap -->

## Docs

- [Architecture](XAX_AI_Native_Programming_Language_Architecture.md) · [Specification](XAX_SPEC.md) · [Normative docs](docs/)
- [State](XAX_STATE.md) · [Roadmap](XAX_IMPLEMENTATION_ROADMAP.md) · [Handoff](XAX_HANDOFF.md)
- [Decisions](XAX_DECISIONS.md) · [Open issues](XAX_OPEN_ISSUES.md)
- [Conformance](XAX_CONFORMANCE.md) · [Benchmarks](XAX_BENCHMARKS.md)
