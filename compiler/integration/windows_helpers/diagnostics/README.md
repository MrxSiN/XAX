# Private native decline diagnostics

These canonical transactions instrument diagnostic builds. Their exit values
are private state captures, **not the production CLI protocol or validity
results**. They do not change the committed production `driver.xax`.
[Resource diagnosis](../resource_diagnosis.json) records sources, bootstrap
configuration, artifact hashes, native authority and observed values.

| Record | Expected root | Purpose |
|---|---|---|
| [decline_sites.edit](decline_sites.edit) | `59b52b732f54086588c34ba4098d54cea0d33dd1a102aeab5749b933cdc54d71` | Assign private codes 16..156 to the original entry's 141 decline leaves. Exit 63 identifies block 757, node 0: resource-callee action 2. |
| [resource_state_binding.edit](resource_state_binding.edit) | `2b8136a8e052ccefd88f31b5d906dc986a070f2ca6e370668b73b17783ed3d17` | Bind a canonical wrapper around `rc_decide`, returning packed graph/defer state after the unchanged decision. |
| [resource_state_status.edit](resource_state_status.edit) | `743923d00aa8e18be5ec6d48130dbf7c0c7ac71128659628f731fc105b12ff5a` | At the original decline leaf only, forward that wrapper's scalar result as the private exit value. |

Use the unchanged reference expected-root edit service, fully verify each
candidate and save through `Workspace.save` before the documented bootstrap
lowering. Native edit of the driver source currently declines; no native replay
success is claimed for these records. The first record's baseline is available
at XAX revision `85abd4640439c748374dce79cb54bfecb406cedf`. The last two records
apply in order to the current production source, yielding private root
`a4cfa166b469d70a3f95439c54698f7b844b28caf6b4d7d554563e94df6eb6c8`.

The state probe returns `(RC_O + 1) * 65536 + RC_DEFER` at that decline leaf.
For the tested stores, both fields fit sixteen bits. `RC_O` indexes the input
store's ordered object table. `RC_DEFER` is a typing-entry token plus one;
it is not an object ordinal. Only decode private exits in that documented
range/configuration. No private exit may be treated as a normal success.

The corrected production self-store returns private value 201,981,952:
graph ordinal 3,081 and defer token zero. This selects its entry graph
`85a20ba4e71d38112f4a59ec76ede95cab3810090495a8580b11acc98205aaa6`,
with 2,149 blocks, 37,533 nodes and 112 direct calls to 37 distinct targets.
The small two-callee fixture returns 655,360, selecting its caller graph and
zero defer token. Sharing this decision stage does not establish the same
underlying graph/facts failure.
