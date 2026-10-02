# XAX Serialization and Identity

## 1. Purpose and scope

This document defines the authoritative semantic-level rules for the canonical `.xax` artifact: a compact binary semantic store of immutable, content-addressed XAX objects arranged as a Merkle DAG.

The format exists to preserve exact program meaning, permit local reads and mutations, support deterministic verification, and avoid retransmitting unchanged semantic material. It is not a human source format. A human-readable dump may exist for diagnostics, but it is never authoritative and editing it does not modify a XAX program.

This stage specifies:

- canonical binary framing;
- semantic object identity and object kinds;
- canonical integer, length, collection, and field encoding;
- reference interning and local indices;
- content hashes and non-semantic lineage identities;
- Merkle program/module/function structure;
- immutable local mutation;
- integrity validation;
- schema and container version evolution;
- forward/backward compatibility;
- deterministic corruption handling;
- separation of semantic and non-semantic data;
- streaming and bounded random access.

It does not define human programming syntax, optimizer behavior, target semantics, or semantic fields owned by other XAX stages.

---

## 2. Normative definitions

The terms **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

**Canonical encoding** — the unique valid byte encoding of a supported semantic object under one schema version and hash suite.

**Semantic object** — an immutable serialized object whose contents contribute to program meaning or immutable structure determining program meaning.

**CID** — content identity: the cryptographic hash of one canonical semantic object envelope.

**LID** — logical lineage identity: a stable non-semantic identifier used by workspaces and transactions to track one logical entity across immutable versions.

**Semantic root** — CID of the root semantic object of a complete artifact.

**Store** — a `.xax` binary container holding a semantic root, reachable objects, optional non-semantic records, an index, and integrity data.

**Reachable object** — an object reachable by following semantic references from the semantic root.

**Schema version** — the exact interpretation and canonical encoding for one semantic object kind.

---

## 3. Core invariants

| Invariant | Requirement |
|---|---|
| Meaning is source | The semantic graph represented by canonical objects is authoritative, not text or a dump. |
| Unique encoding | One semantic object under one supported schema has one canonical byte encoding. |
| Immutable objects | A CID-addressed semantic object is never modified in place. |
| Hash identity | Changing any hashed semantic fact changes the enclosing object's CID. |
| Merkle propagation | A changed child CID changes semantic ancestors up to the root. |
| Local stability | Unchanged objects keep their CIDs and need not be rewritten or retransmitted. |
| Metadata exclusion | Non-semantic metadata never changes semantic CIDs or the semantic root. |
| Deterministic failure | Invalid, corrupt, ambiguous, or unsupported semantic data is rejected. |
| No heuristic repair | Readers never guess missing or damaged semantics. |
| Machine locality | A known object can be read without deserializing the whole program. |

---

## 4. Canonical store model

A canonical `.xax` store has four ordered regions:

1. container header;
2. semantic object records;
3. optional non-semantic records;
4. canonical index and integrity trailer.

The semantic object set is closed over the semantic root. Every reachable CID MUST be present unless the enclosing package/store policy explicitly permits external content-addressed dependencies. A standalone artifact MUST contain every reachable object.

### 4.1 Header

The header fields, in canonical order, are:

| Field | Encoding | Meaning |
|---|---|---|
| magic | 4 bytes | `58 41 58 00` (`XAX\0`) |
| container_major | ULEB128 | incompatible framing generation |
| container_minor | ULEB128 | backward-compatible container revision |
| hash_suite | ULEB128 enum | CID/integrity hash algorithm |
| root_cid | fixed digest | semantic root |
| semantic_object_count | ULEB128 | semantic record count |
| nonsemantic_record_count | ULEB128 | optional tooling record count |
| feature_flags | ULEB128 bitset | required container features |

Initial canonical values are:

- `container_major = 1`;
- `hash_suite = 1`;
- hash suite `1` = **BLAKE3-256**;
- CIDs are 32 bytes.

Unsupported major versions, required feature bits, or hash suites MUST be rejected. Hash substitution is forbidden.

---

## 5. Canonical primitive encodings

### 5.1 Integers

Unsigned integers use **minimal ULEB128**. A decoder MUST reject overlong, redundant, unterminated, or schema-width-exceeding encodings.

Signed schema integers use ZigZag mapping followed by minimal ULEB128.

### 5.2 Lengths, counts, and byte strings

Lengths and element counts use minimal ULEB128.

A byte string is:

`byte_length || raw_bytes`

No text interpretation is implied unless the owning schema explicitly defines one.

A decoder MUST validate lengths and counts before allocation or traversal. A length extending beyond its enclosing record is corruption.

### 5.3 Booleans, enums, and collections

False is byte `00`; true is byte `01`. Other boolean values are invalid.

Enums use minimal ULEB128 and reject unknown values unless the schema defines an extension range.

Ordered lists encode `count` followed by canonical elements.

Unordered semantic sets MUST use the exact canonical order specified by the owning schema. Canonical ordering MUST NOT depend on insertion history, host pointer values, locale, map iteration, or platform behavior.

---

## 6. Semantic object envelope

Each semantic record contains:

| Field | Encoding |
|---|---|
| record_length | ULEB128 |
| cid | 32 bytes |
| kind_id | ULEB128 |
| schema_version | ULEB128 |
| reference_table | canonical direct-reference table |
| body_length | ULEB128 |
| semantic_body | schema-defined bytes |

`record_length` covers all bytes after itself through the record end.

The bytes hashed for CID are:

`domain_tag || kind_id || schema_version || reference_table || body_length || semantic_body`

The fixed domain tag is the eight ASCII bytes `XAX-SEM-1`.

Excluded from CID computation are the stored CID itself, outer record length, file offset, container version, index, non-semantic metadata, and integrity trailer.

A decoder MUST recompute each CID and reject a mismatch.

---

## 7. Core object kinds

Initial core kind IDs are:

| ID | Kind | Role |
|---:|---|---|
| 1 | program_root | root of one complete program semantic graph |
| 2 | module | module-level semantic ownership and references |
| 3 | function | signature, capabilities, and function semantic structure |
| 4 | type | canonical type object |
| 5 | constant | canonical constant object |
| 6 | target | target semantic package/object |
| 7 | graph_fragment | independently addressable immutable graph region |
| 8 | recursion_group | one recursive function SCC with group-local member identity |
| 9 | package | immutable package/dependency/build-interface semantics |
| 10 | build | build profile/request/snapshot/trust/provenance/signature/policy semantics |
| 11 | call_contract | reusable bounded indirect-call interface/effect/resource/control contract |

The serialization layer assigns IDs but does not redefine semantic fields owned by other stages. Kind 11 is separately content-addressed so implementation-function CID changes do not change package-facing contract identity when the bounded contract itself is unchanged.

Unassigned kind IDs are invalid unless a later registry defines them. A reader encountering an unknown reachable kind MAY preserve its bytes if framing is understood, but MUST NOT claim it can verify, compile, optimize, or mutate that artifact.

---

## 8. Deterministic fields and schemas

Fields are encoded in schema order. Ordinary fixed-schema fields do not carry field tags.

For every `(kind_id, schema_version)`, the schema MUST define:

- all fields;
- exact field order;
- field encoding;
- required/optional status;
- canonical collection ordering;
- reference category.

Inserting, deleting, reordering, reinterpreting, or changing the encoding of a semantic field requires a new `schema_version`.

A semantic body MUST be consumed exactly. Unknown trailing bytes are invalid.

---

## 9. Interning and reference tables

Persistent references use CIDs, but repeated 32-byte hashes inside an object are wasteful. Each object therefore contains one canonical direct-reference table. Precise object-backed pointer provenance/alias class is not serialized as a second local identity when it can be derived exactly from the referenced/creating storage object; OI-06 measured redundant local class IDs and rejected that duplication. Conservative raw/target alias classes may still require explicit semantic data when no precise object identity exists.

Construction is mandatory:

1. collect all directly referenced external semantic CIDs;
2. remove duplicates;
3. sort CIDs in unsigned lexicographic byte order;
4. assign indices `0..n-1`;
5. encode `count || cid_0 || ... || cid_n`.

Body references then use minimal ULEB128 indices into this table.

Encounter-order tables are non-canonical.

References to entities defined inside the same semantic body use schema-defined local indices assigned by canonical definition order. Equivalent semantics MUST NOT receive different numbering because of construction history.

Identical immutable semantic objects necessarily share one CID. A canonical store MUST NOT contain duplicate semantic records for the same CID, whether identical or conflicting.

---

### 9.1 Effect-edge compression selected by OI-08

Effect ordering is semantic, but canonical store v1 does not introduce a second effect-edge object or derive dependencies from record order. OI-08 benchmark evidence selects a future-schema compression policy if effect frontiers are persisted separately from ordinary graph references: group explicit operation handles by exact effect domain instance, encode a semantic topological run for that instance, use a compact previous-member form on ordinary linear runs, and encode explicit predecessor deltas at roots, forks, joins, or other non-run frontiers.

The semantic run order in such a section is part of the effect representation. It is not the order of graph nodes, semantic records, CIDs, file offsets, traversal, or construction. A decoder MUST reconstruct the exact predecessor frontier and partial order and reject any mismatch. A conservative unpartitioned instance remains required when independence is not proven. The OI-08 comparator is measurement tooling only; adopting this form requires a future schema version and does not alter current CIDs or store bytes.

---

## 10. Content identity versus logical identity

### 10.1 CID

CID is the authoritative immutable identity of serialized semantic content.

Equal canonical envelopes produce equal CIDs. Any hashed semantic change produces a different CID.

CID equality means equality of canonical serialized semantic objects under the same schema/hash suite. It does not claim observational equivalence between independently structured programs.

### 10.2 LID

A workspace MAY assign a 128-bit opaque LID to an editable entity so agents and transaction systems can refer to the same logical function, module, or other entity across immutable revisions.

LIDs:

- are not derived from content;
- are excluded from semantic hashes;
- do not affect program meaning;
- are not required for compilation;
- MAY map to different CIDs over time;
- never replace CID integrity.

An optional non-semantic lineage table may record:

`LID -> current CID`

Removing or changing this table MUST NOT change the semantic root.

Package logical identity used for dependency upgrade continuity is a separate package-system concept and MUST NOT be conflated with workspace LIDs.

---

## 11. Merkle DAG structure

The semantic root heads a Merkle DAG. Conceptually:

```text
program_root CID
  -> module CID
       -> function CID
            -> graph_fragment CID
            -> type CID
            -> constant CID
       -> type CID
       -> constant CID
  -> target CID
```

Exact ownership edges are defined by the relevant semantic schemas.

Shared immutable objects are stored once and referenced many times.

Direct cycles between independently content-addressed objects are prohibited because each CID depends on referenced CIDs. Recursive language semantics MUST use a schema-defined indirection that avoids cyclic CID computation, such as local references inside one enclosing object or an acyclic declaration/definition partition.

---

## 12. Local mutation and version creation

Semantic mutation is copy-on-write at object granularity.

For one local edit:

1. construct a replacement for the lowest semantic object containing the changed fact;
2. canonicalize and hash it;
3. rebuild each ancestor whose child CID changed;
4. continue until a new root CID is produced;
5. retain every unchanged object and CID.

No immutable object is edited in place.

A graph-fragment-local change SHOULD leave unrelated functions, modules, types, constants, and targets byte-identical.

Fragment granularity is permitted to vary by implementation policy, but the resulting semantic object must still have one canonical encoding once boundaries are chosen by its governing semantic schema.

---

## 13. Non-semantic metadata

Debug names, display labels, source-origin descriptions, visualization hints, profiling observations, timestamps, comments, UI layout, temporary local handles, and diagnostic caches are non-semantic unless another XAX stage explicitly defines them as semantic.

Non-semantic data MUST remain outside semantic object envelopes.

A non-semantic record is framed as:

`record_kind || record_length || payload`

Such a record MAY refer to a CID or LID. Deleting or changing it MUST NOT alter any semantic CID or root.

Measured profile data therefore remains separate from program semantics even when compilation policy uses it.

Verifier proof caches MAY also be persisted beside a canonical store as implementation-owned non-semantic sidecars. Such sidecars are not semantic records, do not participate in the semantic root or canonical `.xax` bytes, and MUST key every reusable fact by its complete meaning-affecting dependency closure plus verifier identity. Missing/stale entries cause recomputation; corrupt sidecars MUST cause recomputation or explicit failure, never semantic acceptance. The current OI-05 prototype uses exact subject/direct-reference CIDs and verifier identity for object-verification facts; broader proof facts require broader keys.

---

## 14. Streaming and random access

A canonical store MUST permit sequential scanning and bounded random access.

### 14.1 Record order

Semantic records are sorted by CID in ascending unsigned lexicographic byte order.

Non-semantic records follow them and use ordering defined by their tooling schemas.

This order is independent of graph traversal and construction history.

### 14.2 Index

The canonical index contains one entry per semantic object:

`cid || file_offset || record_length`

Entries are sorted by CID. Offsets and lengths use minimal ULEB128.

The index is non-semantic but is part of canonical container bytes and is covered by store integrity validation.

A random-access reader SHOULD be able to read the header and trailer, locate the index, binary-search a CID, read only that record, and validate its CID independently.

A streaming reader MAY process records sequentially and consume the index last.

Reading one known function or graph fragment MUST NOT require deserializing all other functions.

---

## 15. Integrity trailer

The store ends with:

| Field | Encoding |
|---|---|
| index_length | ULEB128 |
| index_bytes | canonical index |
| store_digest | 32 bytes |
| trailer_magic | 4 bytes |

`trailer_magic` is `58 41 58 45` (`XAXE`).

`store_digest` is BLAKE3-256 over every byte from file start through the final byte of `index_bytes`, excluding the digest and trailer magic.

The store digest detects truncation, reordering, index corruption, and damage to non-semantic records. Object CIDs remain the authoritative integrity mechanism for semantic records.

A bounded reader MAY validate one object without validating the complete store digest. It MUST validate the store digest before claiming whole-store integrity.

---

## 16. Version evolution

Serialization has three independent version dimensions.

### 16.1 Container version

`container_major.container_minor` governs framing and container-level features.

A major version may break framing compatibility.

A minor version MUST preserve the ability of older readers of the same major version to locate records and deterministically reject unsupported required features.

### 16.2 Object schema version

Every semantic object carries its own `schema_version`. Object kinds evolve independently.

Semantic reinterpretation or canonical encoding changes require a new schema version.

### 16.3 Hash suite

The hash suite is explicit in the header.

Changing suites changes CIDs even when semantic bodies are unchanged. Hash-suite migration is therefore an explicit store-wide identity migration. CIDs from different suites MUST NOT be silently treated as interchangeable.

---

## 17. Compatibility policy

### 17.1 Backward compatibility

A newer implementation SHOULD read older supported container and object schema versions when their exact semantics remain implemented.

A newer writer MAY emit an older schema only when meaning is preserved exactly, without hidden defaults or loss.

### 17.2 Forward compatibility

An older implementation MAY preserve newer records as opaque bytes when framing permits exact preservation.

It MUST reject verification, optimization, compilation, or mutation if any reachable kind, schema version, required feature, or hash suite is unsupported.

Unknown reachable semantic fields are never silently ignored.

### 17.3 Canonical migration

Schema migration:

1. decodes the old object under the exact old schema;
2. constructs the corresponding new semantic object;
3. serializes it under the new schema;
4. produces new CIDs where envelopes change;
5. rebuilds affected Merkle ancestors;
6. produces a new semantic root.

Migration is an explicit transformation, not in-place reinterpretation.

---

## 18. Corruption behavior

A reader MUST fail deterministically on:

- invalid header/trailer magic;
- unsupported required version, feature, schema, or hash suite;
- non-minimal integer encoding;
- invalid boolean or enum value;
- length/count overflow;
- record-boundary violation;
- missing or trailing semantic-body bytes;
- non-canonical or duplicate reference-table entries;
- invalid local reference index;
- duplicate semantic-record CID;
- CID mismatch;
- illegal CID cycle;
- missing reachable object;
- non-canonical semantic record order;
- inconsistent index;
- store-digest mismatch when full validation is performed.

Canonical readers MUST NOT repair corrupted semantics heuristically.

A separate recovery tool MAY copy intact objects into a new store, but guessed bytes or reconstructed meaning MUST NOT be represented as the original artifact.

---

## 19. Human-readable dumps

A tool MAY render XAX objects or neighborhoods as text.

Such a dump:

- is not `.xax` source;
- has no normative grammar;
- need not round-trip;
- may omit redundant details;
- may use human-friendly names;
- may change between tool versions;
- MUST be identified as non-authoritative diagnostic output.

Importing an edited dump as authoritative program state is not part of XAX. Program changes occur through structured semantic construction or transactional mutation.

---

## 20. Interfaces with other subsystems

| Subsystem | Dependency |
|---|---|
| Canonical semantic graph | Defines object semantics, canonical definition order, and legal local references. |
| Type/value system | Defines type/constant bodies and scalar payload rules. |
| Effects, control, memory, resources | Define function/fragment semantic fields. |
| Target model | Defines target semantic contents; this stage supplies immutable identity. |
| Compile-time execution | Produces semantic objects that are canonicalized and hashed here. |
| Transactions | Use root CIDs for base checks and MAY use LIDs for workspace addressing. |
| Diagnostics | May reference CIDs, LIDs, and local indices without changing meaning. |
| Package system | Uses content-addressed module graphs and separate logical package identities. |
| Compiler cache | May key derived results by CIDs plus explicit compilation inputs. |
| AI workspace protocol | May expose short temporary handles mapped to CIDs/LIDs; handles are never persistent semantic identities. |

No subsystem may derive semantic meaning from file offsets, insertion history, timestamps, UI metadata, or host-specific ordering.

---

## 21. Rejected alternatives

| Alternative | Why rejected |
|---|---|
| JSON/YAML/TOML/text as authority | Adds representational variance and human syntax without semantic value. |
| Parser-generated source AST as authority | Contradicts the semantic graph as source. |
| Mutable content IDs | Breaks immutable caching and Merkle verification. |
| Whole-file program hash only | Makes metadata/layout changes alter identity and destroys local reuse. |
| Hashing debug/UI metadata | Invalidates semantic caches for non-semantic changes. |
| Encounter-order reference tables | Makes construction history affect bytes. |
| Arbitrary map ordering | Produces non-deterministic serialization. |
| Silently ignoring unknown semantics | Risks incorrect verification or compilation. |
| Heuristic reader repair | Replaces exact meaning with guesses. |
| Cyclic CID dependencies | Makes hash computation recursively undefined. |
| Repeating full hashes at every reference | Wastes space versus canonical local reference indices. |
| In-place semantic mutation | Violates content addressing and transactional base checking. |
| Canonical per-record compression in v1 | Adds compressor determinism and complexity without semantic benefit; transport compression can remain external. |
| Required dump round-trip | Risks creating a second human programming language. |

---

## 22. Open issues requiring implementation evidence

### 22.1 Graph-fragment granularity

Small fragments improve edit locality and reuse but increase hash, object, index, and traversal overhead. Large fragments reduce overhead but amplify invalidation.

The semantic model does not depend on one fixed default. Prototype measurements should determine practical fragmentation policies.

### 22.2 Index acceleration

The mandatory sorted CID index is sufficient for deterministic lookup. An additional canonical acceleration structure should be added only if large-store measurements show a material benefit greater than its byte and implementation cost. Any such structure remains non-semantic.

---

## 23. Falsification criteria

This design must be reconsidered if implementation or benchmarking demonstrates any of the following:

1. independent conforming serializers produce different bytes or CIDs for the same semantic object;
2. common one-operation edits invalidate or retransmit large unrelated semantic regions;
3. reference-table overhead materially exceeds viable alternatives across representative programs;
4. retrieving one function or graph neighborhood requires reading a substantial fraction of a large store;
5. BLAKE3-256 hashing materially limits edit, verification, compilation, or package throughput;
6. the mandatory index has disproportionate space cost at realistic object counts;
7. independent object-schema versioning creates excessive migration complexity or root churn;
8. real compiler workflows require supposedly non-semantic data to alter program meaning;
9. no measured fragmentation policy provides both local editability and acceptable store overhead;
10. AI editing still requires retransmitting large semantic regions despite stable CIDs, LIDs, and bounded object access.

A failed benchmark may justify changing serialization structure. It does not justify hidden semantics, heuristic repair, textual authority, or non-deterministic encoding.
