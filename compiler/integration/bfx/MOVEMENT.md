# Movement packing

Current production uses one [BFX specification](https://github.com/MrxSiN/BBC/blob/main/docs/02_BFX_CONTRACT.md) and one shared
canonical decoder. See [import/build contracts](IMPORT.md) and
[migration transactions](TRANSACTIONS.md). Optimized instructions are members
of the shared opcode set, not separate wire formats. Previous format-specific
transactions are retired from current paths and preserved in Git history.
The adjacent optimization evidence JSON remains immutable historical evidence.
