<div align="center">

# XAX

### A programming language built for AI, not for typing

![Status](https://img.shields.io/badge/status-research%20prototype-orange)
![Python](https://img.shields.io/badge/bootstrap-Python%203.11%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

</div>

---

## What is XAX?

Most programming languages are text files that people type. XAX is different: **there is no text to type.**

An XAX program is stored as a map of meaning (a *semantic graph*). It records what each piece of the program does and how the pieces connect. An AI assistant changes the program by sending a small, exact edit ("change this limit from 64 to 128"). XAX checks that the edit is correct and then turns the program straight into a file that runs on your computer, phone, browser or GPU.

```text
  You describe what you want
            ↓
  AI sends a small, exact edit
            ↓
  XAX checks that the edit is correct
            ↓
  XAX builds a program that runs on the device
```

## Why build it?

- **One language for everything.** The long-term goal is to build what people use C, Rust, Java, Kotlin, Swift, JavaScript or Python for today, from tiny chips to phone apps to GPU code.
- **No hidden extras.** Programs carry nothing they don't use: no forced garbage collector, virtual machine or large runtime library. That keeps them small and fast.
- **Made for AI editing.** The AI reads only the part it needs and changes only what must change, so it doesn't rewrite whole files.
- **Checked before it runs.** Every change is verified first. Edits that would break the program are rejected with a clear reason.

## How it is organised

| Part | What it means |
|---|---|
| **Small core** | Just the basics: numbers, math, data, decisions, loops, function calls and memory. |
| **Everything else is optional** | Text, lists, objects, async code and garbage collection are add-on packages, used only when needed. |
| **Platforms are packages too** | The same program can be turned into a Linux or Windows app, an Android app, Java bytecode, WebAssembly for browsers, or GPU code. |

## How far along is it?

Each platform earns a level only when there is proof (tests and measurements). Each level includes all the ones below it.

| Level | In plain words |
|---|---|
| **R0** | The program can be described in XAX |
| **R1** | XAX makes a file that runs |
| **R2** | It can use the platform's normal system features and libraries |
| **R3** | A real, useful app runs |
| **R4** | It runs **faster** than the best C, Rust or Java version, by a margin bigger than measurement noise |
| **R5** | An AI can keep the app updated using XAX's exact edits |
| **R6** | A whole app is written and maintained 100% in XAX |

Full rules: [`XAX_SPEC.md`](XAX_SPEC.md) §21.2.

### Platform levels at a glance

| Platform | Level | Plain summary |
|---|---|---|
| Linux (Intel/AMD PCs) | R6 | Fastest of all tested builds on three test apps; a full app (`xb64`) written only in XAX |
| Linux (ARM, e.g. phones) | R6 | Runs on real Pixel phones, faster than the C and Rust versions; a full app (`xcksum`) written only in XAX |
| Java (JVM) | R6 | Builds Java files directly, faster than the Java version; a full app (`xwc`) written only in XAX |
| Android phones | R3 | Real signed apps run on a Pixel 8 Pro; start-up speed ties the Java and Kotlin versions |
| Windows | R2 | Real Windows programs run on Windows 11 |
| ARM devices with no OS | R2 | Tested in an emulator only |
| Web browser | R2 | Web pages with XAX code that update the page |
| WebAssembly / WASI | R1 | Runs in WebAssembly engines and Node.js |
| RISC-V | R1 | Tested in an emulator only |
| GPU (Vulkan) | R1 | Tested on a software GPU, not real GPU hardware yet |
| Apple, .NET, small chips (RTOS), BSD | — | Not started |

<!-- xax-status:levels -->Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): R6: jvm, linux-aarch64, linux-x86_64; R3: android-arm64; R2: aarch64-baremetal, browser-web, windows-x86_64-pe; R1: gpu-spirv-cuda-metal-dxil, riscv64, wasm32-core, wasm32-wasi; R0: accelerator-simt-packet; no level yet: bsd-unix, dotnet-clr, macos-ios-apple, rtos-embedded-mcu.<!-- /xax-status:levels -->

<details>
<summary><b>Full technical details per platform</b></summary>

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

</details>

## Highlights so far

- **Faster than C and Rust on Linux.** On three test apps, XAX beat the fastest C (clang) or Rust build, in one case by about 15%.
- **Faster on real phones.** On a Pixel 8 Pro and an original Pixel, XAX's test app ran faster than the C and Rust versions.
- **Apps written only in XAX.** Three small command-line tools (`xb64` for base64, `xcksum` for checksums, `xwc` for word counts) match the standard Linux tools, and each shipped a second version through one XAX edit.
- **An AI kept apps updated.** An AI changed real apps through exact XAX edits, then rebuilt, tested and measured them.
- **XAX can build itself.** On Linux (Intel/AMD), the XAX compiler compiles its own code and gets the same result every time, without needing Python.

## Try it

You need **Python 3.11 or newer**. Nothing else needs to be installed.

```bash
cd compiler
pip install -e '.[test]'
xaxc --help
PYTHONPATH=src:.:.. python -m pytest -n auto tests
```

Some tests need extra tools (QEMU, Wine, a JDK, Android tools and so on). Without them those tests are skipped, and skipped doesn't mean passed. Full setup guide: [`XAX_BENCHMARKS.md`](XAX_BENCHMARKS.md#host-setup-for-the-full-test-and-benchmark-suite).

**For AI agents:** read [`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md) and [`CLAUDE.md`](CLAUDE.md) first.

## Project status

This is a **research prototype**. Part of the compiler is already written in XAX itself; the rest is still Python.

<details>
<summary><b>Self-hosting details (technical)</b></summary>

"Self-hosting" means the compiler is written in its own language. On Linux (Intel/AMD), these parts of the compiler are XAX programs: checking stores, writing stores, the compiler driver, and the code generator for ordinary Linux programs. Each produces exactly the same bytes as the older Python version, and the driver rebuilds itself identically across three generations. Details: [`XAX_STATE.md`](XAX_STATE.md).

<!-- xax-status:bootstrap -->Bootstrap status (generated from `compiler/bootstrap/m14_selfhost_evidence.json`, derived by `xax_selfhost.bootstrap_status`): whole production compiler: none of B0-B6 is established (every target but Linux x86-64, Linux AArch64, Windows PE32+ executables and RISC-V raw images is compiled by Python backends (S15e.3-S15e.7); the Linux x86-64 production compiler is reported separately (ADR-180, ADR-285, ADR-308, ADR-315, ADR-317)); Linux x86-64 production compiler (`benchmarks/full_selfhost_evidence.json`): B0, B2, B3, B4, B5, B6 hold, B1 do not; its seed requires Python: no; M14 semantic-image META wrapper: B2, B3, B4 hold, B5, B6 do not (host-executed META_CANONICAL_STORE, META_MATERIALIZE_PROGRAM, META_VERIFY_SEMANTICS). S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). Bootstrap seed: python-zipapp, 46,255 bytes, requires Python: yes.<!-- /xax-status:bootstrap -->

</details>

## Learn more

| Topic | Documents |
|---|---|
| Big picture | [Architecture](XAX_AI_Native_Programming_Language_Architecture.md) · [Specification](XAX_SPEC.md) · [Normative docs](docs/) |
| Progress | [State](XAX_STATE.md) · [Roadmap](XAX_IMPLEMENTATION_ROADMAP.md) · [Handoff](XAX_HANDOFF.md) |
| Choices made | [Decisions](XAX_DECISIONS.md) · [Open issues](XAX_OPEN_ISSUES.md) |
| Proof | [Conformance](XAX_CONFORMANCE.md) · [Benchmarks](XAX_BENCHMARKS.md) |
