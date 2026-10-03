<div align="center">

# XAX — eXact Autonomous eXecution

### From Intent to Execution.

**A language built for AI agents**

![Status](https://img.shields.io/badge/status-research%20prototype-orange)
![Python](https://img.shields.io/badge/bootstrap-Python%203.12-blue)
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

| Target | Status |
|---|---|
| x86-64 Linux | Direct ELF64 executables via syscalls, optionally with explicit shared-library imports — executed and measured |
| x86-64 Windows | Direct native encoder, Win64 ABI; direct PE32+ executables with kernel32 imports |
| AArch64 | AAPCS64 bare-metal and Android shared objects |
| WebAssembly (wasm32) | Direct module emission |
| Android | DEX, manifest, resources, APK signing, JNI, libxposed modules |
| JVM | Direct class files in a deterministic JAR, typed JDK member calls — executed on HotSpot, measured against `javac` |
| RISC-V (RV64IM) | Raw position-independent images, LP64 calls — executed under an emulator |
| SIMT accelerator | Deployment-packet format (conformance only) |

Per-platform replacement levels (R0–R6) are derived from evidence in [`XAX_REPLACEMENT_MATRIX.json`](XAX_REPLACEMENT_MATRIX.json); see `XAX_SPEC.md` §21.

## Repository layout

```text
XAX/
├── docs/                    Normative specification (01–17)
│   └── 09_AI_PROTOCOL.md    How AI agents must interact with XAX
├── compiler/                Python 3.12 bootstrap compiler (`xaxc`)
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

Requires Python 3.12+. No third-party dependencies.

```bash
cd compiler
pip install -e .
xaxc --help
```

AI agents working in this repository should read [`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md) and [`CLAUDE.md`](CLAUDE.md) first.

## Project status

XAX is a **research prototype**. Milestones M1–M14 are complete for their declared prototype slices; the universal-replacement milestone U1 is in progress — see [`XAX_STATE.md`](XAX_STATE.md) for exact scope and limits, and [`XAX_OPEN_ISSUES.md`](XAX_OPEN_ISSUES.md) for what remains open. Replacement levels are derived from evidence in [`XAX_REPLACEMENT_MATRIX.json`](XAX_REPLACEMENT_MATRIX.json); no platform is above R2. On Linux `filestat`, XAX roughly matches `gcc -O2` but is 1.4–1.8× slower than `clang -O2`; on the JVM a Collatz kernel runs at 1.04× the `javac` twin's time.

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
