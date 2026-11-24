# XAX AI Instructions

XAX is an AI-native programming language: a program is a verified, content-addressed semantic graph stored as
canonical `.xax` objects, edited by small typed transactions and compiled directly to machine code or platform
artifacts. XAX has no canonical human-written source syntax. Do not invent or emit textual XAX programs as
authoritative source; protocol examples and diagnostic notation are tooling views, not XAX source.

## Start here

1. Read this file (always loaded; `CLAUDE.md` imports it).
2. Read the scoped rules that apply to the files you change (mandatory, not optional):

   | You change or run | Mandatory rules |
   |---|---|
   | anything under `compiler/` (stores, seeds, ledger, evidence, benchmarks, tests, BBC integration) | [`compiler/AGENTS.md`](compiler/AGENTS.md) |
   | an XAX program (query, edit, verify, commit) | [`docs/09_AI_PROTOCOL.md`](docs/09_AI_PROTOCOL.md) |
   | Markdown or status data | "Documents and status" below |

3. Find your task in [`docs/README.md` → Task routes](docs/README.md#task-routes) and read only what its row names.
4. To continue earlier work, read the last `## ` section of [`XAX_HANDOFF.md`](XAX_HANDOFF.md) (see its top).

## Authority

Document precedence is [`XAX_SPEC.md` §1](XAX_SPEC.md#1-normative-language-and-precedence): the specification is
normative, `docs/NN_*.md` are subordinate detail, conformance and benchmark documents define obligations,
`XAX_DECISIONS.md` records adopted rationale, and state, handoff and the replacement matrix record evidence, never
requirements. For a program, the canonical semantic graph and current workspace state are authoritative.
Implementation behavior is evidence of what the compiler does, not authority to change the specification: when they
disagree, report the discrepancy; do not rewrite the specification to match the code.

## XAX programming

1. Read `docs/09_AI_PROTOCOL.md` and follow its normative requirements.
2. Treat the canonical semantic graph and current workspace state as authoritative.
3. Query only the smallest semantic neighborhood required for the task.
4. Use short workspace-local handles instead of persistent identities when available.
5. Emit only the minimum exact semantic mutation and do not repeat facts uniquely reconstructible from shared workspace or protocol state.
6. Do not regenerate unchanged program state or the canonical `.xax` artifact for a local edit.
7. Use structured diagnostics and the supplied repair neighborhood for rejected mutations; do not request unrelated context.
8. Verify required invariants and commit only through the XAX transaction/workspace interface.

If the XAX workspace/compiler interface is available, use it instead of producing a source-like textual substitute. The native one is `xaxc edit <store> <input> <output>` (views, batches and rejection text; `docs/09_AI_PROTOCOL.md` §16).

## Repository rules

- Language rule (2026-11-12): this repository is written in XAX. Any other language (Python, shell, awk, C, Go and the rest) is prohibited unless the thing cannot be written in XAX, for example a benchmark's baseline arm that must be in a specific language. Add no new file or logic in another language; where one is truly unavoidable, say why in the change. Existing code in other languages is to be rewritten as native XAX: when a change touches such a tool, replace it natively instead of extending it, and delete it once nothing runs it. BBC (`compiler/integration/bfx` and BBC's own repository) is Brainfuck and XAX only.
- Evidence follows the ecosystem rule below. A skipped test, a successful compilation, existing code or a plan is not evidence of a capability. Native-execution and performance evidence rules are in `compiler/AGENTS.md`.

## Documents and status

- `XAX_REPLACEMENT_MATRIX.json` is the source of current replacement levels and of the README Targets table (each row's `name` and `summary`). After changing it, run `python -m xax_status_docs --write` from `compiler/src` to regenerate every `<!-- xax-status:levels -->` and `<!-- xax-status:targets -->` block; `tests/test_status_docs.py` fails while a block is stale.
- Never write a `<!-- xax-status:... -->` block by hand. B levels are derived from the latest validated release record (`compiler/AGENTS.md`, "Seeds, releases and bootstrap levels").
- Dated sections in `XAX_STATE.md`, `XAX_HANDOFF.md`, `XAX_BENCHMARKS.md`, and `XAX_DECISIONS.md` are historical records; record a new result in a new section and point the superseded one at it instead of rewriting it.
- Keep one authoritative owner per fact: link to it instead of restating it. When a change affects a rule, capability, interface, level or decision, update its owner (route "Documentation maintenance" in `docs/README.md`), regenerate generated blocks, and leave unrelated documents alone. Add no session summaries or audit reports beyond the dated sections above.

## Git workflow

- Do not add AI attribution to commits or pull requests: no `Co-Authored-By` trailers naming an AI assistant, no session links, no "Generated with" footers.
- Commits are authored and committed by the repository's git identity (`git config user.name` / `user.email`), never by Claude or `noreply@anthropic.com`; check `git log -1 --format='%an <%ae> / %cn <%ce>'` before pushing. Claude never appears as a GitHub contributor (the only exceptions are past benchmark-evidence-only commits).
- Pull request titles say what the change does in plain words, under about 70 characters ("General backend: limit prefetch to small views"). Never use the branch name (`Ccr 9a7d54f8 ss6wxl`, `Claude/...`), a "WIP" prefix, or a title cut off mid-word; spell out internal IDs (ADR, ledger, step numbers) only as a parenthetical after the plain description.
- Pull request descriptions start with one or two sentences a newcomer can follow: what changed and why. Then a `## Changes` list with one plain line per commit or logical change, and an optional `## Details` section for technical depth. Never leave the description empty.
- Open a pull request as soon as each task is finished and its tests pass; do not hold finished work until a larger set is complete.

<!-- ecosystem-policy v1 (2026-11-13): identical in every MrxSiN first-party repository. Change it everywhere in one coordinated set of PRs, never in one repository alone. -->
## Ecosystem rules (v1)

Shared by MrxSiN's first-party repositories. Any other rule in this file that is stricter or more specific to this repository wins.

- **Who owns what.** XAX owns the semantic graph, verifier, compiler, ABIs, backends, targets and artifacts. BBC owns the Brainfuck frontend, BFX and Brainfuck-specific optimization. XAX-MCP owns MCP transport, tool schemas, sandbox and permissions. Dependencies point one way: consumers -> XAX-MCP / BBC -> XAX.
- **New production logic** is XAX, or Brainfuck + XAX, wherever the toolchains reach the target; this repository's own language rules say where that is. Existing code in other languages is tracked migration debt, not permission to add more. Declarative config, assets, fixtures and licenses are not code to convert.
- **Upstream first.** When a toolchain lacks something this repository needs: reproduce it on the toolchain's latest `main`, search its issues and PRs, then fix a small bounded gap with a PR in the owning repository, or open (or link) an issue for a large one and mark only the affected work blocked-upstream. No consumer-side shims, private toolchain forks or local toolchain patches.
- **Pins.** Build against exact toolchain commits, recorded in one machine-readable place. Check the toolchains' latest commits before nontrivial work; move a pin by reviewed PR once checks pass, and write down why when an older pin stays.
- **No hardcoding** of secrets, personal or machine paths, toolchain locations, obfuscated host names or version-specific offsets. Machine-local paths belong in your own `~/.claude/CLAUDE.md` or `CLAUDE.local.md`, never in the repository. Specification constants (opcodes, ABI layouts, protocol markers, security limits) are fine when named and documented.
- **Design.** SOLID, DRY, KISS, YAGNI, Law of Demeter, Boy Scout Rule and Separation of Concerns, applied with judgment. They never override correctness, safety, verified state or evidence quality.
- **Evidence.** Report only what actually ran: EXECUTED, MEASURED, NOT RUN or BLOCKED, with the reason. Emulator, Wine or qemu runs are not device runs. Never rewrite old evidence; add new.
- **Git.** Work on a branch from the default branch and land it by pull request; the owner reviews and merges. No force-push to the default branch, no history rewrites. No AI attribution in commits, PRs or comments; commits use the repository's git identity. PR titles say what changed in plain words.
- **Security.** Report vulnerabilities privately, never in a public issue. Never print or commit tokens.
<!-- /ecosystem-policy v1 -->
