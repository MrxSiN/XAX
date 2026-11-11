# Independent architecture and soundness audit (2026-11-11)

This is a dated record. It covers `MrxSiN/XAX` at `ed1961b` and `MrxSiN/XAX-MCP` at `1e5cf66`, both with clean
working trees. It was written before any tracked file was changed. Later sections of this file record what was done
afterwards; they do not rewrite the findings.

Evidence labels used here:

| Label | Meaning |
|---|---|
| REPRODUCED | Executed on the audit host and observed |
| SOURCE-SUPPORTED | Read in the cited source; not executed |
| INFERRED | Follows from reproduced or source-supported facts; not observed directly |
| UNVERIFIED | Could not be checked on this host |

## 1. Host and limits

| Item | Value |
|---|---|
| Host | Windows 11 Pro 10.0.26300, x86-64, Python 3.12.10, pytest 9.1.1, unicorn 2.1.4 |
| Native compiler available | `compiler/bootstrap/windows/xaxc-windows-x86_64.exe`, SHA-256 `aa72234d…ab79` (the seed XAX-MCP pins) |
| Not available | WSL, Docker, a Linux host. The Linux seed (`compiler/bootstrap/seed/xaxc-linux-x86_64`) could not run |

Consequences. `evolve.sh`, `selfbuild.sh`, seed rotation and every `XAX_REQUIRE_NATIVE=1` component run on Linux
x86-64 only (`compiler/src/xax_native.py:41`), so nothing about the current production driver (ledger 0023) was
executed. The Windows seed accepts `XAXEDIT1` records only: an empty selector is rejected with `EDIT-RECORD-MAGIC`
(REPRODUCED), so the native view and batch forms of `docs/09_AI_PROTOCOL.md` §16 do not exist on Windows. No B level,
R level or performance number was measured or changed by this audit.

## 2. Architecture and dependency map

```text
canonical store (.xax)            docs/08, XAX_SPEC §9        reference/xax_compiler.py (StoreReader, write_store)
  objects: CID = BLAKE3(kind, schema, refs, body); records CID-sorted; store digest in the trailer
verification                      XAX_SPEC, docs/02-06        reference/xax_compiler.py (verify_store, _parse_graph_uncached,
                                                              _verify_memory_node, _verify_linear_flow)
                                                              bootstrap/xax_store_verifier.xax + decoders, CFG, typing (native)
reference execution               XAX_SPEC                    reference/xax_compiler.py (_execute_graph): the semantic oracle
workspace and transactions        docs/09 §5-§7, §15, §16     reference/xax_workspace.py, xax_local_protocol.py (Python)
                                                              edit engine inside xax_compiler_driver_general.xax (native)
lowering                          docs/10-13                  reference/xax_x86_64*.py, xax_aarch64*.py, xax_riscv64.py,
                                                              xax_wasm.py, xax_jvm.py, xax_dex.py, xax_spirv.py (Python)
                                                              bootstrap/xax_x86_64_general.xax and siblings (native)
build, packages, artifacts        docs/14                     reference/xax_build.py, xax_pe.py, xax_elf.py, xax_apk.py
production compiler               docs/15, ADR-361/367/372    bootstrap/xax_compiler_driver_general.xax + seed/xax_compiler_request.xax,
                                                              changed only through bootstrap/evolution/LEDGER (144 lines, 27 stores)
status and evidence               XAX_REPLACEMENT_MATRIX.json src/xax_replacement.py, xax_status_docs.py, benchmarks/*.json
XAX-MCP (separate repository)     its CLAUDE.md               native/xax-mcp-native-gen3.xax -> xax-mcp-native.exe, pinned to the
                                                              Windows seed through native/xax-dependency.json
```

Dependency direction is one way: `XAX-MCP -> XAX`. Inside XAX, the native programs were brought up against the Python
reference and are compared with it by tests; the reference executor is the only independent statement of run-time
meaning.

## 3. Semantic invariants and their status

| Invariant | Status | Evidence |
|---|---|---|
| CID integrity, sorted unique records, index equals records, store digest | Implemented in both decoders | SOURCE-SUPPORTED: `reference/xax_compiler.py:427-466`, `656-760` |
| Minimal ULEB128 | Implemented; width bound is loose in the reference decoder (finding 5) | SOURCE-SUPPORTED, REPRODUCED probe |
| SSA dominance, operand and result typing, linear effects and resources | Reference and native seed agree on every corrupted program tried | REPRODUCED: 0 disagreements in the first 150 corrupted programs; the completed run is in section 9 |
| Exact integer semantics in lowering | Violated for signed compares below 32 bits on the x86-64 frame path (finding 1) | REPRODUCED |
| Stale-root rejection | Enforced in-process (Python workspace) and by the edit engine's expected root | SOURCE-SUPPORTED; exercised by XAX-MCP session fixtures (not rerun here) |
| Verify before publish | `xaxc edit` writes a candidate only; `evolve.sh` and XAX-MCP run `verify` before replacing a store | SOURCE-SUPPORTED: `bootstrap/evolution/evolve.sh:66-80` |
| Atomic publication | Single file: atomic replace. Several stores plus the ledger: not atomic (finding 6) | SOURCE-SUPPORTED |
| No textual source | Holds. Views and batches are tooling output bound to a root CID | SOURCE-SUPPORTED: `docs/09_AI_PROTOCOL.md` §16 |
| No mandatory runtime | Holds for every artifact built here: the PE images import only the kernel32 functions the program names | REPRODUCED on 1,171 generated programs |

## 4. Findings

### Finding 1. Signed compares of `bits<8>` and `bits<16>` are miscompiled on the x86-64 frame path

- Severity: high (silent wrong result from a verified program). Confidence: high. Label: REPRODUCED.
- Location: `compiler/reference/xax_x86_64.py:1989-1994` with `_cmp_registers` at `:462`. The frame path loads four
  bytes of each zero-extended slot and emits a 32-bit `cmp` followed by a signed `setcc`. For operand widths below 32
  the narrow sign bit never reaches bit 31, so `slt`, `sle`, `sgt` and `sge` compare the values as non-negative.
- The register path refuses compares that are not 32 or 64 bits (`:1019`), which sends exactly these functions to the
  frame path.
- Sibling backends sign-extend first and are correct in source: `xax_x86_64_views.py:475-483`,
  `xax_riscv64.py:467-475`, `xax_aarch64.py:2133-2141`, `xax_wasm.py:503-507`.
- The reference executor is correct (`xax_compiler.py:9181-9193`), so the canonical meaning is not in question.
- Reproduction: a PE program that reads 32 bytes of stdin, truncates two words to `bits<8>`, compares them and exits
  with the zero-extended flag. With `x = 0xF1`, `y = 0x03`, `slt` must give 1; the reference backend and the native
  Windows seed both give 0. 40 of 441 single-operation probes fail, all of them the four signed predicates at widths
  8 and 16; every other operation and every 32-bit case passes. In a 1,500-seed random campaign, 1,171 programs built
  on both compilers and every mismatch that was inspected contained such a compare.
- Native compiler: the Windows seed `aa72234d…` has the same defect (REPRODUCED). The current Linux production driver
  was accepted on byte equality with the bootstrap's output for this path (`XAX_STATE.md:879`), so it very probably has
  it too (INFERRED, UNVERIFIED on this host).

### Finding 2. Byte equality with the bootstrap was the acceptance oracle for native lowering

- Severity: medium. Confidence: medium. Label: SOURCE-SUPPORTED, with finding 1 as the observed consequence.
- The native general backend was accepted when its images equalled the Python backend's (`XAX_DECISIONS.md` S12
  records; `XAX_STATE.md:879`). That proves the port, not the meaning. A defect in the reference becomes a defect in
  the production compiler with no test failing.
- The AArch64 Linux register path was tested against the reference executor with random 8/16/32/33/64-bit programs
  and that campaign found two bugs (`XAX_DECISIONS.md:1968`). No equivalent executor differential covers the x86-64
  frame path at narrow widths.

### Finding 3. The deployed MCP surface cannot inspect or mutate a program semantically

- Severity: medium for the "reliable AI evolution" objective. Confidence: high. Label: REPRODUCED and SOURCE-SUPPORTED.
- The default native server (0.10.0, gen3) takes `{}` for `xax_query` and returns root, byte count and the first
  function CID; mutations are hexadecimal `XAXEDIT1` records (`XAX-MCP/docs/TOOLS.md`, `schemas/tools-v2.json`).
  An agent cannot list functions, read a node, find callers or express a typed mutation through it. The repository
  says so (`native/release-status.json`, `blocking_findings`).
- The retired Python adapter did offer typed queries and mutations. The MCP server attached to this audit session is
  that adapter: `xax_capabilities` reports version 0.5.0, "Python (bootstrap adapter)", toolchain status `untested`,
  every native component `unavailable`. So the server a user actually has can differ from the repository default
  without any signal other than reading the capabilities result.
- The semantic checkpoint (`native/candidates/20261110/server-semantic-inspect.xax`) is archived, not installed, and
  the last capabilities candidate emits malformed JSON (`CONTINUE_NATIVE_EVOLUTION.md`). Not rerun here.

### Finding 4. The Windows seed is older than the protocol it is documented beside

- Severity: medium. Confidence: high. Label: REPRODUCED.
- `xaxc-windows-x86_64.exe edit <store> <empty selector> <out>` exits 1 with `EDIT-RECORD-MAGIC`. Views, batches and
  rejection rendering (`docs/09_AI_PROTOCOL.md` §16) are Linux-seed features. `bootstrap/windows/README.md` lists the
  five commands correctly, but `AGENT.md` and `CLAUDE.md` name `xaxc edit` views as "the native one" with no host
  qualifier.
- Consequence: on Windows no native authoring is possible, and XAX-MCP cannot build function views on its pinned
  compiler; it would need a newer Windows seed or an upstream inspection record.

### Finding 5. The reference ULEB128 reader accepts values wider than 64 bits

- Severity: low. Confidence: high. Label: SOURCE-SUPPORTED, probe REPRODUCED.
- `Cursor.uleb` (`compiler/reference/xax_compiler.py:139-176`) stops at ten bytes but does not bound the tenth, so it
  returns values up to 2^70 - 1. `docs/08_SERIALIZATION_IDENTITY.md:135` requires rejecting schema-width-exceeding
  encodings.
- Probe: a rotate amount encoded as 2^64 + 5. The reference rejects it later with `INT-ROTATE-AMOUNT` (a range rule,
  not a canonical-form rule); the native seed declines (exit 2). No store was found that one side accepts and the
  other rejects, but the two decoders classify the same bytes differently, and a field without a range check would
  let the reference accept a value no native word can hold.

### Finding 6. A ledger transaction over several stores is not atomic

- Severity: low. Confidence: high. Label: SOURCE-SUPPORTED.
- `evolve.sh apply` (`:71-80`) and `xax_selfhost_evolution.apply` (`:187-194`) copy the record, replace each store in
  turn and then append the ledger lines. An interruption in between leaves a store that is not its chain's end. There
  is no lock against two concurrent applies.
- It is detected (`evolve.sh check`, `tests/test_store_regeneration.py`) and repaired from git, so the last committed
  state is never lost. The code comment "Nothing is changed unless every store's edit and verification succeed" is
  true of rejection, not of interruption.

### Finding 7. Saving a Python workspace has no cross-process freshness check

- Severity: low. Confidence: high. Label: SOURCE-SUPPORTED.
- `Workspace.save` (`compiler/reference/xax_workspace.py:780-801`) writes a temporary file, fsyncs it and replaces the
  destination. Two processes that loaded the same store both succeed and the later one wins. Expected-root checks are
  in-process only. The parent directory is not fsynced, so durability after power loss is not established.
- The native MCP server avoids this with one exclusive OS lease per work directory.

### Finding 8. The MCP golden fixture does not pin byte framing

- Severity: low. Confidence: high. Label: REPRODUCED.
- `tests/protocol/readonly.responses.ndjson` is committed with CRLF line endings (`git ls-files --eol`: `i/crlf`); the
  server writes LF. The 15 response lines match after line splitting, and CI compares lines
  (`.github/workflows/ci.yml:90-93`), so a server that began to write CRLF, or dropped the final LF, would pass.

### Finding 9. `AGENT.md` and `CLAUDE.md` have drifted

- Severity: low. Confidence: high. Label: REPRODUCED (`diff AGENT.md CLAUDE.md`).
- `CLAUDE.md` has the seed-rotation rule; `AGENT.md` does not. Two hand-kept copies of the same policy is the cause.

### Finding 10. Replay can pass without replaying

- Severity: low. Confidence: medium. Label: SOURCE-SUPPORTED.
- `evolve.sh replay` prints `skip` and keeps exit status 0 when the repository does not hold a transaction's earlier
  store (`:95-98`), for example in a shallow clone. pytest reports the same case as a skip, which is visible; the
  shell command's exit status is not.

## 5. Design principles: what applies, with consequences

| Principle | Where it holds | Where it is broken, and the cost |
|---|---|---|
| SRP | Backends, regalloc, build, workspace are separate modules; native programs are one store each | `xax_compiler.py` is 9,487 lines: encoding, types, verifier, executor, target tables and the CLI. `_parse_graph_uncached` is about 960 lines. Cost: a verifier change is reviewed inside the same function body as unrelated rules. It is the frozen reference, so splitting it now would be churn without a defect to fix (rejected as a change) |
| OCP | Targets are data (`NativeTargetDescription`), platforms are packages; adding RISC-V or SPIR-V did not touch the kernel | The x86-64 backend has three lowering paths (register, legacy register, frame) with separately written operation cases. Cost: finding 1 exists in one path and not the others |
| LSP | The only real substitution contract is "native component equals bootstrap or declines". It is enforced by `AUTHORITY` and `XAX_REQUIRE_NATIVE` | The contract is on bytes, not on meaning (finding 2) |
| ISP | Windows seed: five narrow file commands. MCP: eight tools, rights granted by the host | Native `xax_query` is too narrow to be useful (finding 3). That is a missing interface, not a fat one |
| DIP | Canonical semantics do not depend on a backend or on MCP; XAX-MCP consumes a file contract | None found with a consequence |
| DRY | Levels, targets and B status are generated from the matrix and evidence records | Agent instructions are duplicated by hand (finding 9). The signed-compare lowering is written once per backend path (finding 1). Two independent verifiers are a legitimate second oracle, not a DRY violation |
| KISS | Four terminators, 78 operations, no shifts or signed division in the kernel | Ledger apply is simple but not atomic (finding 6); a simple failure model would say so |
| YAGNI | Kernel admissions are argued per ADR; unsupported cases decline | None found with a consequence |
| Law of Demeter | XAX-MCP reads the compiler's public inspection record, not store internals | Test tooling imports private names (`_parse_graph`, `_decode_constant`) from `xax_compiler`. Cost is confined to tooling |
| Boy Scout Rule | Dated records are superseded, not rewritten | `XAX_OPEN_ISSUES.md` OI-50 still cites `compiler/src/xax_x86_64_regalloc.py`; the file moved to `reference/`. Historical, left alone |
| Separation of Concerns | Semantics, verification, lowering, artifacts and evidence are separate layers and separate repositories | The reference executor, the only semantic oracle, sits in the verifier's module and is not the acceptance test for native lowering (finding 2) |

## 6. Strengths confirmed, and false positives rejected

- Native MCP JSON-RPC framing. 27 groups of malformed or hostile input (escapes, lone surrogates, invalid UTF-8, NUL,
  BOM, 5,000-deep nesting, a 4 MiB line, a 70,000-byte id, duplicate keys, batches, bad numbers) produced 0 invalid
  response lines; the server resynchronised and answered the next request every time. REPRODUCED on gen3.
- Verifier agreement. Corrupted graphs (wrong result type, operand of another width, non-dominating use, reused linear
  effect, bad branch arguments, wrong block parameter type) were classified the same way by the reference and the
  native seed. A native decline was never an accept. REPRODUCED.
- Oversized ULEB. Suspected native acceptance of a truncated 2^64 + k value: the native seed declines. Rejected.
- All non-signed integer operations at 8, 16 and 32 bits, and all ten predicates at 32 bits, match the model on both
  compilers. REPRODUCED (401 of 441 probes).
- Honest status. XAX-MCP's `release_ready` and `full_mission_complete` are false and its blocking list matches what
  was observed. The Windows seed README claims no self-build. No R or B claim was found to exceed its evidence in the
  files read; R4 is recomputed from raw samples by `xax_replacement.py`.

## 7. Improvement sequence

1. Fix finding 1 in the reference backend with a failing-first test that compares against the model, on this host.
2. Record the native side as an open issue with the reproduction, because the Linux seed cannot run here.
3. On a Linux host: reproduce on the production seed, fix `xax_x86_64_general.xax` by ledger transaction on the driver
   and request stores, rebuild, rotate the seed, rebuild BBC, then cut a Windows seed from it.
4. Add an executor differential for the x86-64 frame path (finding 2), run in CI on Linux and Windows.
5. Bound the tenth ULEB byte in the reference reader (finding 5), after checking no committed store depends on it.
6. XAX-MCP: finish the semantic inspection checkpoint on a Windows seed that has views (findings 3 and 4), and store
   the golden fixture with LF and compare bytes (finding 8).

## 8. Tests that could not be run

- Anything requiring the Linux seed: `evolve.sh check` and `replay`, `selfbuild.sh`, the S-step and full self-hosting
  evidence, every `XAX_REQUIRE_NATIVE=1` test.
- XAX-MCP compiler-backed session fixtures (46 exchanges), the executor probes and the sandbox checks were not rerun;
  only the read-only golden fixture and the framing cases were.
- No benchmark was run. No performance claim is made or changed.

## 9. Actions taken after the audit (2026-11-11)

Recorded after sections 1 to 8 were written; those sections are unchanged.

- Verifier differential, completed: 625 corrupted programs that could be built were classified by both verifiers.
  The reference rejected 527 (the native seed rejected 508 of them and declined 19) and both accepted the other 98,
  which the corruption had left valid. No disagreement.
- Agent instructions: `AGENT.md` and `CLAUDE.md` have the shared section "Engineering principles for compiler and
  semantic-graph changes" and are byte-identical; `compiler/tests/test_agent_instructions.py` keeps them so
  (finding 9).
- Finding 1, reference backend: fixed (ADR-392). The defect was on both x86-64 paths, not only the frame path as
  section 4 says: the register allocator also compared zero-extended registers. Any width below 32 was affected
  (5 and 24 were confirmed as well as 8 and 16).
  - Regression test `compiler/tests/test_x86_64_narrow_signed_compare.py`: 496 of 3,840 cases failed before, 0 after;
    either half of the fix alone still fails.
  - Single-operation probes: 441 of 441 match on the reference backend (401 before).
  - Random campaign, seeds 1000 to 2499: 20 mismatching seeds before, 0 after. 965 programs build after the change;
    166 that contain such a compare together with an operation the frame path rejects now end in a diagnostic.
  - Old and new reference output were compared over the fixed-seed corpora that Linux tests use against the native
    compiler. Six raw x86-64 cases change, all containing such a compare; the PE corpus does not change.
    `tests/test_xax_selfhost_general_build.py` now leaves those cases out of its byte comparison until OI-55 closes.
    That test runs on Linux only and was not executed here.
- Finding 1, native compilers: not fixed. OI-55 records the reproduction on the Windows seed and what closes it.
  No committed store contains a signed compare below 32 bits (scan of the frozen stores, the production driver, the
  MCP programs, the Windows helpers and the BFX programs: 0 nodes).
- Findings 2 to 8 and 10: recorded only.
- Test runs on the audit host (Windows, Python 3.12.10):
  - Full suite, started before any change (`pytest -q -n 8`): 1,194 passed, 609 skipped, 2 failed, in 53 minutes.
    `tests/test_wheel_install.py::WheelInstallTests::test_clean_install_has_every_module_and_store` passes when run
    alone and failed only while files were being edited under it.
    `tests/test_verified_component_store.py::VerifiedComponentStoreTests::test_reverify_switch_and_unusable_cache_always_verify`
    fails with `0 != 1` on the unchanged commit `ed1961b` as well, so it is a host difference that predates this work;
    its cause was not investigated (the test expects an unusable cache to force verification, and on this host
    verification did not run).
  - After the change, 15 files covering the x86-64 backends, PE, construct, the compiler core, status documents and
    store regeneration: 245 passed, 129 skipped (Linux-only), 0 failed.
