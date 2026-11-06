# Historical streaming-profile evidence

This directory retains immutable evidence from the pre-migration streaming
implementation. Its former source, packer and importer entrypoints and legacy
transactions are retired from the maintained tree. Git commit
e40f77ddb9b671e750f055fcf84324f114d47b8f preserves their exact bytes.

Current [canonical sources](../README.md) live directly in the parent directory
and use the single BFX format for every source size. See [IMPORT.md](../IMPORT.md)
and [TRANSACTIONS.md](../TRANSACTIONS.md). Old report identities do not describe
the migrated implementations. No new performance claim follows from migration.
