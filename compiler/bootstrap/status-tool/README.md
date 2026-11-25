# The generated status blocks as an XAX program

Documents that repeat a current level carry a marked block that is rewritten from its one source, so no level is
written by hand (AGENTS.md, "Documents and status"):

| Opening tag (closed by the same tag with `/` before `xax-status`) | Content |
|---|---|
| `<!-- xax-status:levels -->` | replacement levels, one line (`XAX_REPLACEMENT_MATRIX.json`) |
| `<!-- xax-status:targets -->` | the per-platform table (each row's name, id, level, summary) |
| `<!-- xax-status:bootstrap -->` | B0-B6 from the latest validated release's V2 record |

`sh status.sh check` lists stale documents (exit 1 when there is one); `sh status.sh write` rewrites them. On Linux
x86-64 it builds `xax_status.xax`, `../evidence/xax_evidence.xax` and `../seed/rotate-tool/xax_rotate.xax` with the
pinned Linux seed. On Windows (Git for Windows' `sh`) it builds `xax_status_windows.xax` with the pinned Windows seed
and rewrites levels and targets blocks only: the bootstrap line needs the two Linux-only tools, so a document with a
bootstrap block is refused there (exit 3).

## The program

`xax_status.xax` is an XAX build request store with the general driver's entry (`main` takes and returns the file
system, the process and 22 memory tokens). It reaches files only through the driver's host functions (`host_open`,
`host_read`, `host_write`, `host_close`, `host_exit`, copied from the driver so their CIDs are the same), its
arguments through `argc` and one `arg_copy` site, and its views through the driver's `xax-host-v1` reserve, commit and
free declarations. So `../windows/generator/generate.sh` hosts it as it hosts the compiler: `xax_status_windows.xax` is
`sh ../windows/generator/generate.sh xax_status.xax xax_status_windows.xax`.

```text
xax_status l <matrix> <out>                  the levels line: ids grouped by level, R6 first, ids sorted bytewise
xax_status t <matrix> <out>                  the targets table, highest level first, then matrix order
xax_status b <release> <levels> <record> <seed> <out>
                                             the bootstrap line from `xax_evidence levels` output, the record's
                                             `seed` line (its interpreter digit) and the seed file's size
xax_status s <md> <levels> <targets> <bootstrap> <out>
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
  seed under 96 MiB, output under 64 MiB, at most 16,320 platform rows, each argument under 4 KiB. Every file is read
  in 64 KiB chunks.

How it was made, without a generator of its logic:

- `status.batch` is a native batch (docs/09_AI_PROTOCOL.md §16) on `../evolution/ledger-tool/seed.xax`. Its result is
  `xax_status.xax`, and `xaxc verify` accepts it. It copies the rotate tool's `@put` and `@putw` and the driver's five
  host functions, and supplies the driver's declarations and its 8 MiB and 4 KiB view types that the seed lacks.
- Change it by a further batch on `xax_status.xax`, then `xaxc verify`.

Checked on Linux x86-64 (WSL 2, the release 0041 seed), EXECUTED: on the release 0042 tree its levels line, targets
table and bootstrap line equal the retired Python `xax_status_docs` byte for byte (299, 2,212 and 427 bytes), and
`s` gives Python's result for all 115 Markdown files of the repository and five fixtures (a stale block, an empty
block, an opening tag without a closing tag, two blocks on one line, an empty file).

Driver-shaped main (2026-11-25), EXECUTED in WSL 2 with the release 0042 seed: the levels line, targets table and
bootstrap line (299, 2,220 and 428 bytes) and `s` on all 117 Markdown files of the repository and the five fixtures
equal the previous `xax_status.xax`'s output byte for byte, as do the exit statuses for an unknown command (2) and a
missing file (3). On Windows 11 the Windows seed builds `xax_status_windows.xax` (26,624 bytes), and its levels and
targets output and its `s` output for the 112 tracked Markdown files equal the Linux build's.
