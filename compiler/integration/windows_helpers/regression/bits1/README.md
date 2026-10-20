# Native frame bitwise regression snapshots

These canonical XAX snapshots require mandatory semantic verification and
exercise five-argument Win64 callees, forcing the frame fallback. Cases cover
all four Boolean inputs for bits1 AND/OR/XOR, 32-bit unchanged-image controls,
nonzero fifth stack arguments, and unchanged bits1 arithmetic/bits8 rejection
records. cases.json records expected build/process statuses and exact output hashes.
These are native backend tests; they introduce no BFX format or BBC parser.
The initial graph construction and native replay transport are archived outside BBC.
