# N0 authoring worktree (ADR-367)

N0's own infrastructure is authored once with the pre-W2 generators: commit `b3e22b0`, plus this patch, plus the
current `compiler/reference/xax_compiler.py` and `compiler/src/xax_selfhost_edit.py` copied over the worktree's
`src/` copies. With nothing else changed the worktree regenerates the committed general driver byte for byte
(generator output, then the pre-W2 ledger queries `inputs_limit` and `dead_constants`).

`generator.patch` holds the worktree's N0 changes to generators that have no copy in this repository:

- ledger 0002's fixes (`xax_selfhost_general_regalloc.py` `_loop_slots`, `xax_selfhost_general_view.py` `_distance`);
- ADR-370 (ledger 0005): the store decoder's and the S9 writer's views (`xax_selfhost_store.py`,
  `xax_selfhost_writer.py`; the runners here carry the same constants);
- N0.3 (ADR-369, ADR-371, ledger 0006): the facts program's growable accesses (`xax_selfhost_facts.py` `_checked`,
  `MEMORY_SITES` `GROWABLE_LIMIT_BITS`) and their native rendering (`xax_selfhost_render_graph.py`); the graph
  parsers' attribute-operation lists (`xax_selfhost_views_backend.py`, `xax_selfhost_verify.py`); the x86-64 general
  backend's register and frame paths (`xax_selfhost_general_regalloc.py`, `_emit.py`, `_frame.py`) and the AArch64
  ones (`xax_selfhost_aarch64_lower.py`, `_emit.py`, `_frame.py`).

Records authored from the worktree pair old and new generator output by function name and replace references at the
changed functions' owners outside the generated set (ledger 0003, 0004), or pair the committed store with the
worktree's regenerated one from the root down (`diff_record.py`, ledger 0005 on). After N0, no generator authors compiler logic.
