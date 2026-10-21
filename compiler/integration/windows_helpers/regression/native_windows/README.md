# Windows native lowering fixtures

Forty-five canonical XAX snapshots cover pointer widths and bounds, Win64 stack
frames, six unchanged unsupported operations and counted byte arithmetic.
cases.json defines exact build/program statuses and artifact/diagnostic hashes.
Four pointer programs intentionally terminate with illegal-instruction status.
The twelve counted grids each require 65536 executed iterations; six callees
exceed the 256-node leaf-inline limit. These are compiler backend tests, with
no new BBC algorithm or BFX format. External authoring/replay transports are
archived by native_lowering_evidence.json, outside the implementation repository.
