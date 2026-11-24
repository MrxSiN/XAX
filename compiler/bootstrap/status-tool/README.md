# The generated status blocks as an XAX program

Documents that repeat a current level carry a marked block that is rewritten from its one source, so no level is
written by hand (AGENTS.md, "Documents and status"):

| Opening tag (closed by the same tag with `/` before `xax-status`) | Content |
|---|---|
| `<!-- xax-status:levels -->` | replacement levels, one line (`XAX_REPLACEMENT_MATRIX.json`) |
| `<!-- xax-status:targets -->` | the per-platform table (each row's name, id, level, summary) |
| `<!-- xax-status:bootstrap -->` | B0-B6 from the latest validated release's V2 record |

`sh status.sh check` lists stale documents (exit 1 when there is one); `sh status.sh write` rewrites them. It builds
`xax_status.xax`, `../evidence/xax_evidence.xax` and `../seed/rotate-tool/xax_rotate.xax` with the pinned seed, so it
runs on Linux x86-64.

## The program

`xax_status.xax` is a Linux x86-64 process, an XAX build request store:

```text
xax_status l <matrix>                        the levels line: ids grouped by level, R6 first, ids sorted bytewise
xax_status t <matrix>                        the targets table, highest level first, then matrix order
xax_status b <release> <levels> <record> <seed>
                                             the bootstrap line from `xax_evidence levels` output, the record's
                                             `seed` line (its interpreter digit) and the seed file's size
xax_status s <md> <levels> <targets> <bootstrap>
                                             the document with every block's content replaced by the given text
```

Exit status: 0; 2 for an unknown command; 3 when a file cannot be read or exceeds its limit, a matrix string holds a
backslash (the reader does not decode JSON escapes; the matrix has none), or the levels or record are not in the form
the tools write.

- The matrix reader keeps, for each object of the top-level `platforms` array, the string values of its own `id`,
  `name`, `level` and `summary` keys (nested objects and arrays are skipped by depth).
- `s` replaces like a non-greedy regular expression: from an opening tag, the content runs to the first closing tag
  of the same kind; an opening tag with none after it is copied unchanged.
- Limits: a matrix, levels output or record under 8 MiB, a document under 64 MiB, a generated text under 1 MiB, a
  seed under 96 MiB, output under 64 MiB, at most 16,320 platform rows.

How it was made, without a generator of its logic:

- `status.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `../evolution/ledger-tool/seed.xax`. Its result is
  `xax_status.xax`, and `xaxc verify` accepts it. It copies the rotate tool's `@put` and `@putw`.
- Change it by a further batch on `xax_status.xax`, then `xaxc verify`.

Checked on Linux x86-64 (WSL 2, the release 0041 seed), EXECUTED: on the release 0042 tree its levels line, targets
table and bootstrap line equal the retired Python `xax_status_docs` byte for byte (299, 2,212 and 427 bytes), and
`s` gives Python's result for all 115 Markdown files of the repository and five fixtures (a stale block, an empty
block, an opening tag without a closing tag, two blocks on one line, an empty file).
