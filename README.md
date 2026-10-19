# XAX - Xenial Agent Xenogenesis

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
| x86-64 Linux | `linux-x86_64` | R6 | Native ELF executables. Faster than the fastest C/Rust build on three apps (ADR-212). An AI maintained one app through semantic transactions (ADR-213). `xb64` is 100% XAX (ADR-210). |
| AArch64 Linux | `linux-aarch64` | R6 | Native ELF executables. On two Pixel phones, jsonmin beats NDK clang and rustc (ADR-254). An AI maintained it on-device (ADR-258). `xcksum` is 100% XAX and matches toybox cksum (ADR-258). |
| JVM | `jvm` | R6 | Direct class files and JARs calling the JDK. jsonmin runs 0.87x javac (ADR-212). An AI maintained it through one transaction (ADR-209). `xwc` is 100% XAX and matches GNU wc (ADR-257). |
| Android (arm64-v8a) | `android-arm64` | R3 | Signed APKs with DEX, JNI and libxposed modules, run on Pixel 8 Pro. Cold start ties the Java and Kotlin versions, so the row stays at R3 (ADR-253). R5 maintenance is recorded (ADR-255). |
| x86-64 Windows | `windows-x86_64-pe` | R2 | Native PE32+ executables run on Windows 11, with Win64 calls, threads and DLL imports. |
| AArch64 bare metal | `aarch64-baremetal` | R2 | Bare-metal images with a QEMU board package; run under QEMU only. |
| Browser (WebAssembly + generated glue) | `browser-web` | R2 | WebAssembly page with generated JavaScript glue; four DOM bindings run. |
| WebAssembly (wasm32) | `wasm32-core` | R1 | Plain WebAssembly modules with no imports; run in a host engine. |
| WebAssembly + WASI | `wasm32-wasi` | R1 | WebAssembly modules with basic WASI imports; run under Node.js. |
| RISC-V (RV64IM) | `riscv64` | R1 | Raw RV64IM images; run under the Unicorn emulator. |
| GPU (SPIR-V/Vulkan; PTX, Metal, DXIL planned) | `gpu-spirv-cuda-metal-dxil` | R1 | SPIR-V compute modules run on a CPU Vulkan driver (llvmpipe), not GPU hardware; integers only. |
| SIMT accelerator packet | `accelerator-simt-packet` | R0 | Packet format checked by conformance tests only; nothing runs. |
| macOS / iOS / iPadOS / watchOS / tvOS / visionOS | `macos-ios-apple` | — | Not started. |
| .NET CLI/CLR | `dotnet-clr` | — | Not started. |
| RTOS / embedded MCU (Cortex-M, RISC-V MCU) | `rtos-embedded-mcu` | — | Not started. |
| BSD / other Unix | `bsd-unix` | — | Not started. |
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

Research prototype. Much of the compiler is now XAX: hashing, decoding, typing, the store verifier and writer, the driver, and the Linux code generators. The rest is Python.

Recent results (details in [`XAX_BENCHMARKS.md`](XAX_BENCHMARKS.md)):

- **Linux x86-64 is R6**: faster than the fastest C/Rust build on `filestat` (0.85× clang), `jsonmin` (0.96× clang, a small margin) and `chains` (0.91× rustc). `xb64` is 100% XAX.
- **Linux AArch64 is R6**: `jsonmin` beats NDK clang and rustc on two Pixel phones. `xcksum` is 100% XAX.
- **JVM is R6**: `jsonmin` runs 0.87× javac. `xwc` is 100% XAX.
- **XAX-only apps**: `xb64`, `xcksum` and `xwc` match the standard tools, and each shipped a second release through one transaction.
- **The compiler builds itself**: on Linux x86-64, the XAX compiler rebuilds itself byte for byte, and its seed needs no Python. Full bootstrap status: [`compiler/bootstrap/README.md`](compiler/bootstrap/README.md).

## Docs

- [Architecture](XAX_AI_Native_Programming_Language_Architecture.md) · [Specification](XAX_SPEC.md) · [Normative docs](docs/)
- [State](XAX_STATE.md) · [Roadmap](XAX_IMPLEMENTATION_ROADMAP.md) · [Handoff](XAX_HANDOFF.md)
- [Decisions](XAX_DECISIONS.md) · [Open issues](XAX_OPEN_ISSUES.md)
- [Conformance](XAX_CONFORMANCE.md) · [Benchmarks](XAX_BENCHMARKS.md)

## BFX integration

BBC emits BFX modules for the [canonical XAX decoder](docs/18_BFX_IMPORT.md),
which executes on Android ARM64 and Windows x86-64. The
[native BFX importer](compiler/integration/bfx/IMPORT.md) emits complete
canonical decision stores and executes on Android and Windows. Three frontend
generations on each platform produce identical artifacts. The
[canonical Android app](compiler/integration/bfx/ANDROID.md) passes eight
Activity cases. Native lowering uses the Windows build host.
