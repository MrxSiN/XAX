# Native frame bitwise regression snapshots

These canonical XAX snapshots require mandatory semantic verification and
exercise five-argument Win64 function graphs. Cases cover
all four Boolean inputs for bits1 AND/OR/XOR, 32-bit unchanged-image controls,
nonzero fifth arguments and retained bits1 arithmetic rejections.
cases.json records current expected build/process statuses and exact output hashes.
These are native backend tests; they introduce no BFX format or BBC parser.
The initial graph construction and native replay transport are archived outside BBC.

The current driver additionally supports byte arithmetic. The four width8
AND expectations now succeed; the immutable driver_bits1.json preserves the
original rejection run. See ../native_windows for the broader byte tests.
