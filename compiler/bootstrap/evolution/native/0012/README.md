# Ledger 0012: `define`'s `object` form (ADR-375)

The batches `../../0012-define-object*.batch` (the driver and the request store) add three functions, written by hand
in view form:

- `a_object.view`, `@a_object`: reads `object <kind> 0x<body>` at the definition's start. It takes the kind with
  `a_number` and scans the hex digits, then writes the supplied object (the kind, no references, the body length and
  the bytes) with `a_obj_uleb` and `a_obj_byte`. It returns the object's supplied index.
- `scan.view`, `@scan2`, and `emit.view`, `@emit2`: wrappers with `a_scan`'s and `a_emit`'s signature. When the
  definition starts with `o` they skip the scan or call `@a_object`; otherwise they call the original function.

`ws_tr_define` is redefined from its native view with its `a_scan` and `a_emit` calls retargeted to the wrappers
(`replace F535 @define2`). In the views, `@ABLANK`, `@ANUMBER`, `@AOBJULEB`, `@AOBJBYTE` and `@ORIGINAL` stand for
the helpers' `F<n>` handles in the store being edited. Workspace words are read at constant offsets: word address times 8.
