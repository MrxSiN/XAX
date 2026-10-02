# XAX Package, Build, Security, Reproducibility, and Supply-Chain Model

## 1. Purpose and scope

This document defines the canonical XAX model for package identity, dependency resolution, build description, reproducibility, trust, and supply-chain integrity.

The design follows the foundational rule that **meaning is source**. Packages and builds are therefore expressed as XAX semantic objects and XAX programs, not as text files interpreted by a second configuration language. A project must not require TOML, YAML, JSON, shell scripts, makefiles, package-manager DSLs, or other permanently maintained human-oriented languages to define its build or dependency semantics.

This stage specifies:

- package and module identity;
- content addressing and dependency graphs;
- deterministic dependency resolution;
- logical version continuity;
- package metadata as semantic data;
- build descriptions and build-time computation as XAX;
- target, profile, feature, and configuration selection;
- reproducible input closure;
- hermetic and sandboxed build modes;
- capability and privilege boundaries;
- artifact integrity, signatures, provenance, and trust metadata;
- cache validation;
- lock/snapshot semantics;
- workspace composition;
- multi-target builds;
- network-access policy.

This stage depends on, but does not redefine, canonical serialization, compiler query, target, ABI, or optimizer semantics.

Package/build support is not a runtime requirement. A bare-metal XAX program still requires only a program graph and target package.

---

## 2. Normative terminology

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

| Term | Definition |
|---|---|
| **package** | A content-addressed XAX module graph plus canonical package metadata. |
| **module** | A semantic namespace/composition unit containing or referencing XAX semantic objects. |
| **logical package identity** | A stable semantic identity used to express upgrade continuity across different immutable package instances. |
| **package instance** | One immutable content-addressed package object. |
| **package root** | The persistent content identity of the canonical package object. |
| **dependency edge** | A semantic requirement from one package instance or build root to another package identity or instance. |
| **resolution** | Deterministic selection of exact immutable package instances satisfying declared dependency requirements. |
| **snapshot** | A canonical semantic object fixing the complete resolved dependency closure and relevant build inputs. |
| **build description** | XAX semantic data identifying requested outputs and the semantic computation required to produce them. |
| **build action** | A deterministic or explicitly nondeterministic XAX build-time computation over declared inputs and capabilities. |
| **build input closure** | The transitive set of semantic objects, target/platform objects, tools, environment facts, and external byte artifacts that may influence an output. |
| **profile** | A semantic selection of compilation/build policies such as optimization objective, verification level, diagnostics, instrumentation, or reproducibility mode. |
| **feature** | A package-defined semantic option that changes the selected graph, capabilities, or build computation. |
| **capability** | Explicit authority permitting an effectful operation during build execution. |
| **hermetic build** | A build whose observable inputs are restricted to its declared build input closure and granted capabilities. |
| **reproducible build** | A build for which identical canonical inputs and declared deterministic policies produce identical canonical outputs. |
| **artifact** | A produced immutable object such as a `.xax` package, object file, executable, firmware image, debug artifact, or metadata object. |
| **provenance record** | Canonical semantic data relating an output artifact to declared inputs, build computation, policies, and producing toolchain identities. |
| **trust policy** | Semantic rules specifying which identities, signatures, provenance claims, capabilities, or dependency sources are accepted. |

Logical identity and version labels do not prove content; the package root is authoritative.

---

## 3. Canonical package model

A package is an immutable semantic object whose identity is derived from its canonical content.

Conceptually:

```text
Package {
    logical_identity
    modules[]
    exports
    dependency_requirements[]
    build_entries[]
    feature_schema
    capability_declarations
    metadata
}
```

The canonical serialization stage defines field layout; this schema defines semantic obligations.

### 3.1 Package identity

Each immutable package instance MUST have a persistent content identity derived from the canonical serialization of all identity-relevant package content.

A package identity relation is:

```text
package_root = H(canonical_package_object)
```

where `H` is the content-addressing hash selected by the canonical identity rules.

Changing identity-relevant content creates a new root; mutable content MUST NOT remain reachable under an unchanged root.

Logical package identity MAY remain stable across package instances in order to express upgrade continuity:

```text
logical_identity P
    -> package_root R1
    -> package_root R2
    -> package_root R3
```

Logical identity MUST NOT substitute for integrity verification.

### 3.2 Modules and exports

A package MAY contain multiple modules.

Exports MUST be semantic object references rather than textual file-path conventions.

Module relationships MUST NOT depend on host filesystem order, locale, or case rules unless explicitly modeled by the target/platform semantics.

### 3.3 Package metadata

Package metadata MUST be XAX semantic data.

Metadata MAY include logical identity, compatibility/version labels, authorship, licensing, target predicates, feature declarations, capability expectations, provenance/signature references, and deprecation status.

Metadata MAY be excluded from package identity only when it cannot affect resolution, target selection, build behavior, verification, trust, or produced bytes.

No package requires a manifest written in an external data language.

---

## 4. Dependency graph and deterministic resolution

Dependencies form a directed semantic graph.

A dependency requirement conceptually contains:

```text
DependencyRequirement {
    logical_identity
    constraint
    required_features
    target_predicate
    trust_requirement
}
```

A requirement MAY directly name an exact package root. That is the strongest and simplest form.

Where upgrade continuity is required, a requirement MAY name a logical identity plus a semantic constraint.

### 4.1 Deterministic resolution rule

Given identical:

- root package/build request;
- dependency requirements;
- available candidate package set;
- trust policy;
- target/profile/configuration inputs;
- resolver algorithm identity;

resolution MUST select the same package roots or fail with the same semantic conflict.

Resolution MUST NOT depend on:

- package discovery order;
- network response timing;
- filesystem enumeration order;
- current wall-clock time;
- unspecified locale behavior;
- mutable registry state not captured as an input;
- "latest" as an implicit dynamic selector.

Remaining ties MUST use a canonical tie-break rule or be rejected as ambiguous.

### 4.2 Candidate set

The candidate package set is an input. Network discovery MAY populate it before snapshot finalization, but mutable registry state MUST NOT remain an undeclared build input. A reproducible snapshot fixes exact roots independently of later registry changes.

### 4.3 Conflict handling

The resolver MUST reject dependency sets that cannot satisfy required constraints simultaneously unless the package model explicitly permits multiple coexisting package instances.

Coexisting versions MUST remain distinct by immutable package identity.

---

## 5. Versioning policy

XAX uses immutable content identity as the correctness mechanism. Human-style version numbers are not the authority for package integrity.

A package MAY publish a version label or compatibility coordinate:

```text
VersionInfo {
    logical_identity
    release_label
    compatibility_class
    predecessor_roots[]
}
```

XAX does not require one universal human-oriented version grammar. Resolution constraints MUST have exact semantic meaning and MUST NOT rely on implementation-specific textual range parsing. Compatibility declarations are claims, not automatic proof.

An exact package root always denotes one immutable instance regardless of its version label.

---

## 6. Snapshot and lock model

The deterministic lock mechanism is a canonical semantic object, called a **snapshot**.

Conceptually:

```text
Snapshot {
    root_request
    resolver_identity
    resolved_packages[]
    package_roots[]
    target_roots[]
    profile_root
    feature_selection
    external_input_digests[]
    trust_policy_root
}
```

A snapshot MUST be serializable canonically and content-addressed.

A reproducible build SHOULD consume a snapshot, which MUST fix every dependency choice affecting build semantics.

External byte artifacts MUST be fixed by cryptographic digest plus required interpretation metadata.

The snapshot replaces conventional lockfiles; any human-readable rendering is non-authoritative.

---

## 7. Build descriptions as XAX semantics

A build description is XAX semantic data naming build roots and XAX build-time computations.

Conceptually:

```text
BuildRequest {
    package_root
    build_entry
    target
    profile
    features
    configuration
    requested_artifacts
    capability_policy
}
```

A package MAY export build entries that select modules, specialize computation, construct semantic objects, invoke verification/lowering, compose/link outputs, generate auxiliary data, and emit artifacts.

Build-time algorithms MUST be XAX programs; permanent shell, macro, template, or second build DSLs are rejected.

### 7.1 Build-time execution

Build-time XAX execution SHOULD be deterministic, bounded, and sandboxable.

A build action MUST declare or receive the capabilities needed for effects.

Absent network or filesystem capability, an action cannot perform those effects.

Wall-clock time, randomness, ambient environment state, host process state, and network responses are prohibited in reproducible mode unless promoted to explicit declared inputs.

---

## 8. Target, profile, feature, and configuration model

Target selection references semantic target/platform packages rather than compiler-internal target names alone.

A target selection MAY contain:

```text
TargetSelection {
    machine_target_root
    platform_root?
    abi_root?
    device_constraints?
}
```

A **profile** selects build policy. Examples include:

- optimization objective;
- compile-time resource bounds;
- verification strictness;
- debug information policy;
- instrumentation;
- link/dead-strip policy;
- deterministic-latency policy;
- reproducibility requirements.

A **feature** is package-defined and MUST have a declared semantic domain. Configuration values MUST be typed semantic values, and any output-affecting difference MUST change build identity.

---

## 9. Reproducible build input closure

For an output artifact `A`, the build system MUST be able to identify the inputs allowed to influence `A`.

The closure may include package and snapshot roots, target/platform and toolchain roots, build-program roots, profile/configuration values, external digests, capability policy, and explicit environment facts.

Reproducible mode MUST reject undeclared observable inputs.

Host properties MUST NOT influence output unless promoted to explicit semantic inputs.

Examples:

```text
host_cpu_feature_set
requested_source_date
sdk_digest
signing_policy
device_memory_limit
```

Semantic inputs MUST be distinguishable from diagnostics-only observations.

---

## 10. Hermetic and sandboxed build modes

XAX defines at least these build execution classes:

| Mode | Rule |
|---|---|
| **hermetic-reproducible** | Only declared inputs and deterministic operations are available. Undeclared effects are rejected. |
| **hermetic-nondeterministic** | Input/effect boundaries remain sandboxed, but explicitly granted nondeterministic capabilities may be used. |
| **ambient** | Host effects may be granted explicitly for development or integration tasks; reproducibility is not implied. |

Hermetic mode SHOULD be the default for release artifact production.

Sandbox mechanism is implementation-defined, but failure to enforce requested isolation is a build failure.

---

## 11. Capability and security boundaries

Build execution follows the same XAX principle as runtime semantics: effects are explicit.

Build capabilities MAY include narrowly scoped authority such as:

```text
read_object(root)
read_external(digest)
write_artifact(namespace)
network(endpoint_policy)
clock(mode)
random(mode)
sign(key_capability)
invoke_tool(tool_root)
publish(destination_policy)
```

Capabilities SHOULD be narrow and composable; package possession does not grant ambient host authority.

Dependency build logic MUST execute under the capabilities granted to that dependency context, not under unrestricted authority inherited from the invoking user.

Privilege escalation through undeclared build behavior MUST be rejected.

Trusting package content and authorizing package execution are separate decisions.

---

## 12. Artifact integrity, signatures, provenance, and trust

Content addressing verifies immutable content once an expected root is known; it does not identify or trust the producer. XAX therefore permits optional signatures and provenance records.

### 12.1 Signatures

A signature object SHOULD identify:

- signed object root;
- signature algorithm identity;
- signer identity/key reference;
- signature bytes;
- optional policy context.

Signature verification MUST be separate from content hashing.

The core package format MUST NOT require every package to be signed.

Trust policy determines whether signatures are required for a particular build or publication path.

### 12.2 Provenance

A provenance record MAY bind:

```text
output_root
input_snapshot_root
build_program_root
toolchain_roots
target_roots
profile_root
capability_policy_root
producer_identity
```

Provenance is evidence; trust policy determines which producers or attestations are accepted.

### 12.3 Trust metadata

Trust metadata MUST NOT silently change program semantics.

If trust policy affects whether a dependency or tool is accepted, the policy identity MUST be included in the resolution/build decision and SHOULD be recorded in the snapshot or provenance closure.

---

## 13. Dependency integrity and cache verification

Every fetched immutable XAX object MUST be validated against its expected content identity before use.

A cache entry MUST NOT be trusted merely because it exists under a filename or local key.

At minimum:

```text
expected_root == H(canonical_object)
```

must hold before the object is accepted.

For external byte artifacts:

```text
expected_digest == H(bytes)
```

must hold.

Build caches SHOULD key results by the complete semantic build identity, including all output-affecting inputs.

A cached artifact MUST be rejected if:

- its content identity fails verification;
- required provenance is absent under the active trust policy;
- its recorded input identity differs from the requested build identity;
- its toolchain/target/profile closure differs where those values affect output.

Cache corruption is an integrity failure, not a signal to weaken verification.

---

## 14. Workspace composition and multi-target builds

A workspace is a semantic composition object referencing packages and build requests.

Conceptually:

```text
Workspace {
    members[]
    shared_policy
    snapshots[]
    build_requests[]
}
```

Workspace membership MUST be independent of host directory layout unless paths are explicit inputs. Members MAY share snapshots when their semantic requirements are identical.

Multi-target builds are represented as multiple build requests sharing appropriate package inputs:

```text
build(P, target=T1, profile=R)
build(P, target=T2, profile=R)
build(P, target=T3, profile=S)
```

Target-specific dependencies MUST be selected by semantic predicates, not by hidden conditionals based on the build machine.

An output for one target MUST NOT contaminate the cache identity of another target unless the artifact is proven target-independent.

---

## 15. Network policy

Network access is not mandatory for XAX builds.

A fully resolved build MUST be executable without network access when all objects in its declared closure are locally available.

Discovery, publication, remote caching, and acquisition MAY use explicitly authorized network access, but release reproducibility MUST NOT depend on mutable remote responses.

A build step that needs live network content must either:

1. operate outside reproducible mode; or
2. transform the acquired content into an immutable declared input before the reproducible build begins.

"No network capability" MUST be enforceable as a build policy.

---

## 16. Invariants

The following invariants are normative:

1. **Immutable identity** — an immutable package or artifact root never denotes different content.
2. **Meaning over filenames** — package/build semantics do not depend on human-oriented file conventions unless explicitly modeled.
3. **No external mandatory DSL** — package metadata, build configuration, and build algorithms are XAX semantic objects/programs.
4. **Deterministic resolution** — identical declared resolver inputs produce identical exact package selections or the same rejection.
5. **Exact dependency integrity** — resolved immutable dependencies are verified by content identity before use.
6. **Explicit build effects** — network, filesystem, clock, random, signing, publication, and similar effects require declared authority.
7. **No ambient authority by default** — dependency build logic does not inherit unrestricted host privilege.
8. **Snapshot completeness** — a reproducible snapshot fixes every dependency choice capable of affecting outputs.
9. **Declared input closure** — reproducible outputs cannot depend on undeclared host or network state.
10. **Target explicitness** — target/platform assumptions are semantic inputs, not hidden compiler globals.
11. **Runtime independence** — package/build support does not add mandatory runtime services to produced programs.
12. **Trust separation** — content integrity, producer identity, provenance, and authorization are distinct mechanisms.
13. **Cache verification** — cached objects are verified against semantic identities before acceptance.
14. **No mandatory build network** — builds can run offline once their declared closure is present.
15. **Transactional consistency** — snapshots, package roots, and build requests refer to immutable semantic objects and cannot be partially mutated in place.

---

## 17. Rejected alternatives

| Alternative | Rejection reason |
|---|---|
| TOML/YAML/JSON package manifests | Creates an external human-oriented package language and duplicates semantics outside XAX. |
| Shell scripts as the authoritative build system | Introduces ambient effects, weak semantic visibility, poor portability, and an additional language. |
| Mutable package names as dependency identity | Names do not prove content and allow silent substitution. |
| Version numbers as integrity identity | A label can be republished or mis-associated; immutable content roots are authoritative. |
| Implicit "latest" dependency selection | Makes resolution depend on mutable external time/state and destroys reproducibility. |
| Undeclared environment-variable configuration | Creates hidden semantic inputs. |
| Mandatory online dependency resolution on every build | Violates offline and hermetic deployment requirements. |
| Trusting local caches without hash verification | Allows stale or corrupted objects to masquerade as expected inputs. |
| Automatically executing dependency build code with full user privilege | Violates explicit capability and least-authority semantics. |
| Mandatory signatures for every package | Integrity already follows from content identity; required signer trust is policy-specific and would overconstrain bare-metal/private uses. |
| Treating signatures as proof of correctness | A valid signature proves only a cryptographic statement from a key, not semantic correctness. |
| Host-dependent target auto-detection in reproducible releases | Creates hidden input dependence on the build machine. |
| One global feature-string namespace | Loses type ownership and creates ambiguous package interactions. |
| Package-manager-specific source graph separate from the XAX graph | Duplicates authoritative identity and composition semantics. |

---

## 18. Interfaces with other XAX subsystems

| Subsystem | Required interface |
|---|---|
| Canonical serialization / Merkle DAG | Defines stable canonical bytes, object roots, structural sharing, and persistent identities for packages, snapshots, provenance, and build objects. |
| Semantic graph / type system | Supplies typed package metadata, build configuration values, feature schemas, and build programs. |
| Effects / capabilities | Supplies machine-visible authority and proof obligations for build-time I/O, network, signing, time, randomness, and external tools. |
| Compile-time execution | Executes build-time XAX computation under determinism, resource, and sandbox constraints. |
| Target/platform model | Supplies target identities, ABI/platform semantics, legalizations, encoders, and target predicates. |
| Compiler/verifier | Validates package graphs, build requests, capability constraints, and input closure. |
| Workspace/query protocol | Lets AI agents inspect dependency neighborhoods, create transactions, request resolutions, and compare snapshots without regenerating repositories. |
| Optimizer/lowering/code generation | Consumes the selected package graph, target, profile, and configuration to produce artifacts. |
| ABI/foreign interoperability | Defines identity and integrity requirements for external libraries, SDK objects, and foreign binary inputs. |
| Diagnostic protocol | Reports resolution conflicts, capability violations, integrity failures, and irreproducible inputs as structured machine data. |

No subsystem may silently reinterpret package identity, dependency selection, target selection, or build capabilities outside these semantic interfaces.

---

## 19. Open issues

The following points require implementation evidence.

### 19.1 Hash agility

The canonical identity stage must determine how hash-algorithm evolution is represented without ambiguous identities or unnecessary graph churn.

The requirement is fixed: identity comparisons must remain unambiguous and verifiable across algorithm transitions.

### 19.2 Resolver complexity bounds

The semantic requirement for deterministic resolution is fixed, but the acceptable expressiveness of compatibility constraints depends on measured resolver cost and AI mutation efficiency.

Constraint forms that create pathological resolution behavior may need to be restricted.

### 19.3 Provenance granularity

It remains to be measured whether provenance should normally record only a snapshot/toolchain closure or a finer action-level build DAG.

The design must balance verifiability, cache utility, metadata size, and AI token cost.

### 19.4 Sandbox enforcement portability

The semantic capability model is fixed. The implementation mechanism for enforcing it on hosted platforms and bare-metal build environments remains target/platform-specific.

---

## 20. Falsification criteria

This design should be reconsidered if later implementation evidence establishes any of the following:

1. Canonical semantic package/build data requires materially more AI tokens or repair turns than a simpler external representation for equivalent reliable mutations.
2. Content-addressed package graphs cause unacceptable storage, lookup, or incremental-update cost that cannot be mitigated by interning, structural sharing, and local references.
3. Deterministic semantic dependency resolution proves impractical for realistic dependency graphs without reintroducing hidden mutable state.
4. Snapshot construction fails to capture output-affecting inputs reliably enough to support reproducible builds.
5. Hermetic execution cannot be enforced with acceptable overhead on the intended deployment classes.
6. Capability declarations are too coarse to prevent meaningful build-time privilege escalation or too fine to be practical for AI generation and verification.
7. Cache-key closure becomes so large or expensive to compute that verified caching loses its practical benefit.
8. Target/profile/configuration identities cannot be made sufficiently canonical to prevent accidental cache aliasing.
9. Provenance metadata costs more in storage, build time, or token use than the security/reproducibility value it provides for policies that require it.
10. Offline builds from complete snapshots cannot be achieved without hidden registry or network dependencies.
11. A second build/package DSL proves necessary for capabilities that cannot be expressed efficiently and verifiably in XAX itself.
12. Multi-target workspace composition requires target knowledge to leak into fundamental package semantics rather than remaining in explicit target/platform inputs.

The decisive criterion is whether XAX can maintain immutable package identity, explicit dependency/build semantics, deterministic snapshots, verifiable input closure, and capability-bounded execution without hidden human-oriented configuration languages.
