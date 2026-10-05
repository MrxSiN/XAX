<div align="center">

# XAX — eXact Autonomous eXecution

**From Intent to Execution.**

**A language built for AI agents**

![Status](https://img.shields.io/badge/status-research%20prototype-orange)
![Python](https://img.shields.io/badge/bootstrap-Python%203.11%2B-blue)
![Targets](https://img.shields.io/badge/targets-x86--64%20%7C%20AArch64%20%7C%20RISC--V%20%7C%20wasm32%20%7C%20Android%20%7C%20JVM-informational)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

</div>

---

XAX is an AI-native programming language designed to turn intent directly into executable software.

Instead of optimizing for human-written source code, XAX is designed around exact machine semantics, deterministic structure, and efficient AI interaction.

**Less source. Less context. Fewer tokens. More execution.**

XAX reduces the amount of code and contextual information an AI must read, generate, and reason about—helping autonomous systems build, modify, verify, and compile software more efficiently.

**Designed for machines. Directed by humans.**

---

## Why XAX is different

| Traditional languages | XAX |
|---|---|
| Text source files are the program | A **canonical semantic graph** is the program |
| Humans write, AI imitates | AI agents edit through **typed semantic mutations** |
| Whole files re-read and re-emitted | Agents query the **smallest semantic neighborhood** |
| Edits applied by text patching | Edits committed through a **verified transaction** |
| Formatting and naming noise | Content-addressed, **byte-exact** canonical form |

XAX has **no canonical human-written source syntax**. Human-readable views exist for tooling and diagnostics only; the authoritative program is the verified semantic store.

## Core ideas

- **Canonical semantic store** — content-addressed objects (BLAKE3-256, `XAX-SEM-1` domain separation) with a deterministic container format and whole-store digest.
- **Transactional AI workspace** — bounded queries, short workspace-local handles, minimal mutations, dependency-aware verification, diff/rebase, and structured repair diagnostics.
- **Exact semantics** — explicit types (`bits<N>`, pointers, tuples, arrays, sums, floats), SSA blocks with block parameters, explicit traps, no hidden runtime.
- **Effects and resources** — linear resources, typed `effect<domain,instance>` tracking, and proof values that erase completely from emitted code.
- **Memory facts** — provenance, extent, alignment, permission, initialization, and lifetime verified statically.
- **Concurrency** — portable atomics with explicit order/scope, target capability queries, and real-time rejection profiles.
- **Compile-time execution** — deterministic, capability-gated specialization and metaprogramming over ordinary XAX graphs.
- **Reproducible builds** — canonical package, trust, provenance, and signature objects with exact offline closure.
- **Self-hosting** — a semantic-image compiler path reaching byte-identical generation 0/1/2.

## Targets

Each platform's replacement level is derived from cited evidence in [`XAX_REPLACEMENT_MATRIX.json`](XAX_REPLACEMENT_MATRIX.json) by `compiler/src/xax_replacement.py`; the table below is generated from that file (`python -m xax_status_docs --write` from `compiler/src`). "—" means the platform has no level yet: the work has not started. Each row's open blockers are listed in the matrix.

<!-- xax-status:targets -->
| Target | Matrix id | Level | Status |
|---|---|---|---|
| x86-64 Linux | `linux-x86_64` | R4 | Direct ELF64 executables via syscalls, optionally with declared shared-library imports; executed and measured within 1.05× of the fastest of gcc, clang, and rustc on three workloads; the views profile is lowered by the XAX-hosted backend (native B1–B4). |
| JVM | `jvm` | R4 | Direct class files in a deterministic JAR with typed JDK member calls; the `jvm-classfile-memory-v1` profile adds linear memory and `jvm-classfile-general-v1` aggregates, sums, stack allocations, indirect calls, links, atomics, JDK-called callbacks, and object and array construction; `jsonmin` on HotSpot runs fastest of XAX, `javac`, and `kotlinc` builds with the lowest peak RSS and a program class 0.99× kotlinc's and 1.5× javac's. |
| Android (arm64-v8a) | `android-arm64` | R3 | Direct DEX, manifest, resources, signed APKs, JNI shared objects, and libxposed modules; minimal Activity executed on a device; the stateful counter app (state, file I/O, lifecycle) passed its UI oracle on an Android 12L x86_64 emulator through ARM translation, not yet on arm64 hardware. |
| AArch64 Linux | `linux-aarch64` | R3 | Static and dynamic ELF executables; a file-processing application executed under `qemu-aarch64` user mode only (no hardware, so no performance level). |
| AArch64 bare metal | `aarch64-baremetal` | R2 | AAPCS64 images with a QEMU `virt` board package (reset/fault stubs, vector table, one interrupt source); executed under QEMU only. |
| Browser (WebAssembly + generated glue) | `browser-web` | R2 | wasm32 page whose JavaScript glue is compiler-generated from imported `xax-web-v1` declarations; four DOM bindings executed. |
| x86-64 Windows | `windows-x86_64-pe` | R1 | Direct PE32+ executables, Win64 ABI, kernel32 imports; current bytes executed under Wine, not yet on a Windows host. |
| WebAssembly (wasm32) | `wasm32-core` | R1 | Direct module emission with no imports; executed in a host WebAssembly engine. |
| WebAssembly + WASI | `wasm32-wasi` | R1 | wasm32 modules with three WASI imports (args, `fd_write`, exit); executed under Node.js `node:wasi`. |
| RISC-V (RV64IM) | `riscv64` | R1 | Raw position-independent images, LP64 integer calls; executed under the Unicorn emulator; the self-hosted XAX backend and store verifier reach B1–B4 here. |
| GPU (SPIR-V/Vulkan; PTX, Metal, DXIL planned) | `gpu-spirv-cuda-metal-dxil` | R1 | Direct SPIR-V compute modules executed on Mesa llvmpipe (a CPU Vulkan driver), not GPU hardware; integer words only. |
| SIMT accelerator packet | `accelerator-simt-packet` | R0 | Synthetic deployment-packet format checked by conformance tests only; no execution. |
| macOS / iOS / iPadOS / watchOS / tvOS / visionOS | `macos-ios-apple` | — | Not started: no Mach-O container, Apple ABI package, or Objective-C runtime contract. |
| .NET CLI/CLR | `dotnet-clr` | — | Not started: no CLI metadata/IL container. |
| RTOS / embedded MCU (Cortex-M, RISC-V MCU) | `rtos-embedded-mcu` | — | Not started: no MCU target, vector table, or linker-layout package. |
| BSD / other Unix | `bsd-unix` | — | Not started: no FreeBSD/OpenBSD/NetBSD syscall, ELF note, or libc ABI package. |
<!-- /xax-status:targets -->

## Replacement levels (R0–R6)

XAX does not claim to "replace" a language or platform from design intent. A platform reaches a level only when evidence for it exists; the levels are cumulative, so a platform holds a level only when it also holds every lower one. The normative definitions are in [`XAX_SPEC.md`](XAX_SPEC.md) §21.2.

| Level | Name | What has to be shown |
|---|---|---|
| R0 | Semantic expressibility | The workload is represented exactly in verified XAX. |
| R1 | Executable lowering | XAX directly produces a valid executable artifact for the target, and it executed (on hardware, a device, or a named emulator/harness). |
| R2 | Platform interoperability | The platform's ABI, system APIs, foreign libraries, callbacks, dynamic loading, resources, and lifecycle executed. |
| R3 | Practical application | A nontrivial real application or workload executed successfully. |
| R4 | Performance competitiveness | Runtime, memory, and binary size were measured against the platform's established toolchains, and XAX is competitive (for native CPU code: within 1.05× of the fastest of an optimized C/C++ baseline and at least one non-C/C++ implementation; on the JVM: within 1.05× of the fastest of `javac` and `kotlinc` builds). |
| R5 | AI efficiency | Real model trials measured total tokens per successful change and repair rate, and XAX beats or materially improves on textual-source workflows. |
| R6 | Autonomous maintenance | An AI queried, modified, verified, benchmarked, rebuilt, and committed the application through semantic transactions without regenerating whole source. |

Evidence is labelled `PROVEN`, `EXECUTED`, `MEASURED`, `STRUCTURAL`, `PROTOTYPE`, or `UNIMPLEMENTED` ([`XAX_SPEC.md`](XAX_SPEC.md) §21.3). Emulated execution counts toward R1–R3 correctness only, never toward R4 performance. A platform counts as *replaced* for a workload class only at the level its evidence supports.

## Repository layout

```text
XAX/
├── docs/                    Normative specification (01–17)
│   └── 09_AI_PROTOCOL.md    How AI agents must interact with XAX
├── compiler/                Python 3.11+ bootstrap compiler (`xaxc`)
│   ├── src/                 Store, verifier, workspace, backends
│   └── benchmarks/          Evidence, fixtures, AI-native experiments
├── XAX_SPEC.md              Language specification overview
├── XAX_STATE.md             Current milestone status
├── XAX_IMPLEMENTATION_ROADMAP.md
├── XAX_DECISIONS.md         Design decision log
├── XAX_OPEN_ISSUES.md       Open research questions
└── XAX_BENCHMARKS.md        Benchmark methodology
```

## Getting started

Requires Python 3.11+. The compiler has no third-party runtime dependencies.

```bash
cd compiler
pip install -e .
xaxc --help
```

The test suite runs from `compiler/`:

```bash
pip install -e '.[test]'           # pytest, pytest-xdist, unicorn, tiktoken
PYTHONPATH=src:.:.. python -m pytest -n auto tests
```

`..` must be on `PYTHONPATH` because some tests import `compiler.benchmarks.*`.

Tests that need a host tool skip when it is absent; skipped is not passed. The complete host environment on Ubuntu 24.04 x86-64:

```bash
pip install -U --ignore-installed setuptools wheel   # Debian's patched setuptools fails the wheel test
pip install vulkan
# busybox must be the dynamic build, not busybox-static (the OI-24 sandbox test resolves its shared libraries)
sudo apt-get install qemu-user qemu-user-static qemu-system-arm gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross spirv-tools glslang-tools mesa-vulkan-drivers libvulkan1 \
    wine64 mingw-w64 busybox zlib1g-dev e2fsprogs unzip curl time \
    clang llvm lld default-jdk-headless nodejs
# arm64 zlib for the qemu-aarch64 sysroot (filestat's libz.so.1 crc32 import)
curl -sSfLO http://ports.ubuntu.com/ubuntu-ports/pool/main/z/zlib/zlib1g_1.3.dfsg-3.1ubuntu2_arm64.deb
dpkg-deb -x zlib1g_*_arm64.deb zlib-arm64 && sudo cp -a zlib-arm64/usr/lib/aarch64-linux-gnu/libz.so* /usr/aarch64-linux-gnu/lib/
# Android 14 system image, NDK r28c, build-tools, platform, libxposed API (pinned, ~1 GB) into /opt/android
sudo python compiler/integration/android/make_android_root.py
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y   # rustc twins for the multi-language benchmark rule
```

What still cannot run on such a host: the Windows-host PE execution test (Wine covers the rest). The Android device oracles in [`compiler/integration/android/`](compiler/integration/android/README.md) need `adb` and a target that runs arm64 code: a device, or an x86_64 Android emulator image with ARM translation (that README explains how to run one even without KVM). Emulator runs are correctness evidence only.

AI agents working in this repository should read [`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md) and [`CLAUDE.md`](CLAUDE.md) first.

## Project status

XAX is a **research prototype**. Milestones M1–M14 are complete for their declared prototype slices; the universal-replacement milestone U1 is in progress — see [`XAX_STATE.md`](XAX_STATE.md) for exact scope and limits, and [`XAX_OPEN_ISSUES.md`](XAX_OPEN_ISSUES.md) for what remains open. Replacement levels are derived from evidence in [`XAX_REPLACEMENT_MATRIX.json`](XAX_REPLACEMENT_MATRIX.json) (summary under [Targets](#targets)). On one shared Linux x86-64 host, XAX is within 1.05× of the fastest of gcc, clang, and rustc on `filestat` (1.017×), `chains` (fastest), and `jsonmin` (1.029×) ([`XAX_BENCHMARKS.md`](XAX_BENCHMARKS.md) §15.14); on the JVM, `jsonmin` runs fastest of XAX, `javac`, and `kotlinc` builds with a class 0.99× kotlinc's and 1.5× javac's (§15.18), and a Collatz kernel at 0.91× the `javac` twin's time. Part of the compiler is now XAX: hashing, store decoding, verification, and RISC-V and x86-64 code generation for the views profile run as XAX programs, reach B1–B4 on RV64 (emulated) and natively on x86-64, and every native helper is lowered by the XAX x86-64 backend (ADR-150–ADR-152). The program backends (Linux, Windows, Android, JVM, WebAssembly) and the driver are still Python.

Performance and AI-efficiency claims are made only where recorded evidence exists. See [`XAX_BENCHMARKS.md`](XAX_BENCHMARKS.md) for methodology; no result is fabricated.

## Documentation

- [Architecture](XAX_AI_Native_Programming_Language_Architecture.md)
- [Specification](XAX_SPEC.md) · [Prototype schema v1](XAX_PROTOTYPE_SCHEMA_V1.md)
- [Roadmap](XAX_IMPLEMENTATION_ROADMAP.md) · [Decisions](XAX_DECISIONS.md)
- [Conformance](XAX_CONFORMANCE.md) · [Benchmarks](XAX_BENCHMARKS.md)

---

<div align="center">

**XAX — From Intent to Execution.**

</div>
