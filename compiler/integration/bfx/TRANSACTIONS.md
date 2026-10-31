# BFX migration transactions

Current canonical stores are authoritative; expected-root transactions are the
reviewable migration changes. Every accepted candidate was fully verified and
saved through Workspace; replay against the resulting root rejects as stale.

| Record in `transactions/` | Expected parent |
|---|---|
| `canonical_importer.edit` | Original `wide/import_bfx.xax` at commit 6c9ed73474307d4b3f6130dd09a16431b0f8046d |
| `source.edit` | Original `wide/source.xax` at that commit |
| `initial-pack.edit` | Original `wide/pack.xax` at that commit |
| `pack_core.edit` | Result of initial-pack.edit; replaces the private BF packer with the checked BF source |
| `runs_views.edit` | Current stream_runs BF bootstrap decision store; widens borrowed work views |
| `runs_fixed.edit` | Result of runs_views.edit; specializes the private packet's fixed logical extents |

The importer transaction introduces the single strict decoder, replaces the
old decoder reference, adjusts payload offset and record extent, and prunes
unreachable old objects. `bfx.xax` is the exact decoder dependency closure from
that verified importer; its function has the same CID. The old BUILD/package
wrapper's reference edit was declined by the unchanged generic edit service
with XAX.CANON.ULEB_UNTERMINATED in package module sorting. It was retired;
the portable closure was verified and saved without a second implementation.

Source/packing entrypoints are newly constructed canonical functions bound by
minimum expected-root reference edits. Existing BF chunk filtering stays exact.
The corrected stream_runs BF is compiled using native canonical source/packing/
import components, then its view/interface specialization is replayed before
binding the private core. All transaction objects are canonical graph data;
no foreign-language BFX parser or BF compiler is a production dependency.

Generic replay uses `xax_selfhost_edit.apply_reference(reader, record_bytes)`,
`xax_compiler.verify_store(result)` and `xax_workspace.Workspace(result).save(path)`.
Read the exact parent from Git history or the preceding transaction, never
refresh a stale root implicitly. Current evidence pins transaction digests,
roots, native images, source hashes, target execution and external test tools.
Historical sources remain in Git; no old wire decoder remains in the maintained
compilation path. Generic SDK files under compiler/src were not changed.

## Unified public compilation

[COMPILE.md](COMPILE.md) records the new closed facade/host stores and exact-root
edits under transactions/unified. The existing source coordinator now binds
the reproducible native BF chunk core and defers sticky bracket errors until
instruction capacity has been checked across all chunks. The strict decoder,
importer, packer and BFX wire identity are unchanged.

## Later migrations

- [transactions/v2/](transactions/v2/): BFX id `02` and `fold.bf` ([BFX_V2.md](BFX_V2.md)).
- [transactions/dynamic_tape/](transactions/dynamic_tape/): the 2 GiB lazily committed tape ([DYNAMIC_TAPE.md](DYNAMIC_TAPE.md)).
- [transactions/packed/](transactions/packed/): packed decision lengths ([PACKED_LENGTHS.md](PACKED_LENGTHS.md)).
