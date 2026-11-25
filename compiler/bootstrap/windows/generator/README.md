# The Windows seed's build request, generated

`sh generate.sh <request> <out>` writes the Windows seed's build request from the shared compiler request
(`../../seed/xax_compiler_request.xax`). Build it as `../README.md` describes:

```text
xaxc resolve <out> snapshot.xax
xaxc build snapshot.xax xaxc.exe xaxc.provenance
```

It replaces the hand-written `hosting.batch` and `pe_target.edit`, which had to be rewritten for each ledger (RFC
`docs/proposals/build-bootstrap-rotation-rfc.md` §7, step 5 of §13.7).

`xax_hosting.xax` is a Linux x86-64 process, an XAX build request store, with three commands:

```text
xax_hosting e <request> <listing> - <out>    main's handle ("F<n>"): the request's package's build entry, found in
                                              the listing (`xaxc edit <request> <empty file>`)
xax_hosting b <view> <listing> <layer> <out> the hosting batch for main's view (`xaxc edit <request> F<n>`)
xax_hosting r <hosted> <template> - <out>    the ledger 0032 PE target record for the hosted store (no longer used)
```

`-` stands for any file; `generate.sh` passes `/dev/null`.

**The hosting batch** consists of:

1. the view's root line and main's handle;
2. the fixed layer: the head of `../host_layer.txt`, its Windows declarations, and the bodies `@w_open`…`@w_exit`,
   `@w_argc`, `@w_argcopy` and `@w_handler`;
3. `@w_main`: main's view, with three rewrites —
   - a call of a host function (`host_open`, `host_read`, `host_write`, `host_close`, `host_exit`, found by CID
     in the listing) calls its Windows body instead;
   - the startup read `argc` becomes a call of `@w_argc`;
   - the startup read `arg_copy` becomes a call of `@w_argcopy`, which also takes and returns the argument view.
     In every later line its value becomes `.R3`, its memory `.R2`, and the view parameter `.R1`;
4. the layer's tail, `@XAXC`, the process entry;
5. `replace F<main> @XAXC`.

**The target** is replaced by a batch (2026-11-25): `generate.sh` writes the hosted store's root line and `F0` before
`pe_target.batch`, which supplies the `x86_64-windows-pe-v1` target (`define @pe` / `object 6 0x…`) and replaces the
shared request's target `28f1deec…` with it (`replace <CID> @pe`, ledger 0042). For the compiler request it makes the
same bytes as the earlier record template (`pe_target.template`, deleted), and it works for any store whose request
names that target, such as the status tool's.

How it was made, without a generator of its logic:

- It is a native batch, `generator.batch`, on `../../evolution/ledger-tool/seed.xax`. Its result is
  `xax_hosting.xax`, and `xaxc verify` accepts it.
- It reuses the request tool's declarations and byte helpers (`../../evolution/request-tool/README.md` gives
  their rules).
- Change it by a further batch on `xax_hosting.xax`, then `xaxc verify`.
- `entry.batch` (2026-11-25) is that: `e` read the package entry's reference index at body byte 22, the compiler
  package's layout, and so missed the ledger program's entry. It now reads it after the package identity and the entry
  name (one module, no dependencies, one entry, as every hosted request has). `xax_hosting.xax` is `generator.batch`
  then `entry.batch` on the ledger seed.

**Limits:**

- Main must have at most two `arg_copy` reads, and each must take its view as the parameter right after its pointer
  (the shape main has had since ledger 0031).
- Every file must be under 63 MiB.
- The program runs on Linux x86-64 only, like the ledger and request tools.
- A new host function or startup read needs a new layer and a new rewrite rule.
