# Ledger 0015: `object` with references (ADR-378)

`a_object_refs.view` is ledger 0012's `a_object.view` (`@a_object`) with references. After the body's hex digits it
counts the space-separated 64-digit CIDs that follow (B6). It writes the reference count (B7) and each reference's 32
bytes (B8 to B10, two hex digits a byte, as the body loop decodes them). Only then does it write the body's length
(B11) and its bytes (B3 and B4, unchanged). With no CIDs it writes the record that ledger 0012 wrote.

The view was written with free node and parameter numbers (`a_object_refs.src`); `renumber.awk` numbers them in
order of definition. The batch for each store (`../../0015-object-references*.batch`) defines `@a_object` from the
view, with `@ABLANK`, `@ANUMBER`, `@AOBJULEB` and `@AOBJBYTE` replaced by that store's handles. It then redefines
`a_object` (F376 in the driver and the request) with `replace`.

A reference names an object the store holds, or one the same batch supplied earlier: the engine resolves a CID
against the store, then against the objects already supplied. List the objects so that each comes after those it
refers to. List each object's references in its canonical order.
