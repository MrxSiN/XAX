"""Canonical M10 package/build objects and deterministic bootstrap build service."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Iterable, Mapping, Sequence

from blake3 import blake3

from xax_artifact import (
    ANDROID_SIGNED_APK_LOWERING_IDENTITY_V1,
    ANDROID_UNSIGNED_APK_LOWERING_IDENTITY_V1,
    BOOTSTRAP_COMPILER_IDENTITY_V1,
    lowering_identity,
)
from xax_compiler import (
    Cursor,
    Kind,
    SemanticObject,
    StoreReader,
    decode_native_target,
    decode_object,
    fail,
    uleb,
    verify_object,
    verify_store,
    write_store,
)


BUILD_DOMAIN = b"XAX-BUILD-1"


class BuildForm(IntEnum):
    PROFILE = 1
    REQUEST = 2
    SNAPSHOT = 3
    TRUST_POLICY = 4
    PROVENANCE = 5
    SIGNATURE = 6
    OPTIMIZATION_POLICY = 7


class BuildMode(IntEnum):
    HERMETIC_REPRODUCIBLE = 1
    HERMETIC_NONDETERMINISTIC = 2
    AMBIENT = 3


class BuildCapabilityKind(IntEnum):
    READ_OBJECT = 1
    READ_EXTERNAL = 2
    WRITE_ARTIFACT = 3
    NETWORK = 4
    CLOCK = 5
    RANDOM = 6
    SIGN = 7
    INVOKE_TOOL = 8
    PUBLISH = 9


class ArtifactKind(IntEnum):
    NATIVE_IMAGE = 1
    ACCELERATOR_DEPLOYMENT = 2
    ANDROID_UNSIGNED_APK = 3
    ANDROID_SIGNED_APK = 4


class OptimizationObjective(IntEnum):
    CODE_SIZE = 1


@dataclass(frozen=True, order=True)
class BuildCapability:
    kind: BuildCapabilityKind
    scope: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", BuildCapabilityKind(self.kind))
        if not isinstance(self.scope, bytes):
            raise TypeError("capability scope must be bytes")


@dataclass(frozen=True, order=True)
class CapabilityGrant:
    logical_identity: bytes
    capability: BuildCapability

    def __post_init__(self) -> None:
        if not self.logical_identity:
            raise ValueError("grant logical identity must not be empty")


@dataclass(frozen=True, order=True)
class DependencyRequirement:
    exact_root: bytes | None = None
    logical_identity: bytes | None = None

    def __post_init__(self) -> None:
        if (self.exact_root is None) == (self.logical_identity is None):
            raise ValueError("dependency must name exactly one exact root or logical identity")
        if self.exact_root is not None and len(self.exact_root) != 32:
            raise ValueError("exact dependency root must be 32 bytes")
        if self.logical_identity is not None and not self.logical_identity:
            raise ValueError("logical dependency identity must not be empty")

    @classmethod
    def exact(cls, package_or_root: SemanticObject | bytes) -> "DependencyRequirement":
        return cls(exact_root=package_or_root.cid if isinstance(package_or_root, SemanticObject) else package_or_root)

    @classmethod
    def logical(cls, identity: bytes) -> "DependencyRequirement":
        return cls(logical_identity=identity)


@dataclass(frozen=True)
class TypedBinding:
    name: bytes
    value: SemanticObject

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("binding name must not be empty")
        if self.value.kind != Kind.CONSTANT:
            raise ValueError("typed binding value must be a constant")


@dataclass(frozen=True)
class PackageView:
    logical_identity: bytes
    modules: tuple[bytes, ...]
    dependencies: tuple[DependencyRequirement, ...]
    build_entries: tuple[tuple[bytes, bytes], ...]
    feature_types: tuple[tuple[bytes, bytes], ...]
    configuration_types: tuple[tuple[bytes, bytes], ...]
    capabilities: tuple[BuildCapability, ...]


@dataclass(frozen=True)
class ProfileView:
    mode: BuildMode
    optimization: int
    verification: int
    grants: tuple[CapabilityGrant, ...]


@dataclass(frozen=True)
class RequestView:
    package_root: bytes
    build_entry: bytes
    target_root: bytes
    profile_root: bytes
    features: tuple[tuple[bytes, bytes], ...]
    configuration: tuple[tuple[bytes, bytes], ...]
    requested_artifacts: tuple[ArtifactKind, ...]


@dataclass(frozen=True)
class TrustPolicyView:
    require_package_signatures: bool
    require_provenance_signature: bool
    accepted_algorithms: tuple[bytes, ...]
    accepted_signers: tuple[bytes, ...]


@dataclass(frozen=True)
class SignatureView:
    signed_root: bytes
    algorithm: bytes
    signer: bytes
    signature: bytes


@dataclass(frozen=True)
class ProvenanceView:
    snapshot_root: bytes
    request_root: bytes
    target_root: bytes
    profile_root: bytes
    artifact_digest: bytes
    compiler_identity: bytes
    lowering_identity: bytes
    producer_identity: bytes


@dataclass(frozen=True)
class SnapshotView:
    request_root: bytes
    resolver_identity: bytes
    trust_policy_root: bytes
    package_roots: tuple[bytes, ...]
    signature_roots: tuple[bytes, ...]
    external_digests: tuple[bytes, ...]


@dataclass(frozen=True)
class OptimizationPolicyView:
    objective: OptimizationObjective
    pass_iterations: int
    search_steps: int
    search_candidates: int
    search_memory_bytes: int
    polynomial_terms: int
    inline_cold_nodes: int
    inline_hot_nodes: int
    hot_call_threshold: int
    deterministic: bool


@dataclass(frozen=True)
class Resolution:
    packages: tuple[SemanticObject, ...]
    signatures: tuple[SemanticObject, ...]
    snapshot: SemanticObject


@dataclass(frozen=True)
class BuildEffect:
    logical_identity: bytes
    capability: BuildCapability
    value: bytes = b""


@dataclass(frozen=True)
class BuildResult:
    key: bytes
    artifact: bytes
    artifact_digest: bytes
    provenance: SemanticObject


@dataclass(frozen=True)
class BuildCacheEntry:
    artifact: bytes
    provenance: SemanticObject
    signatures: tuple[SemanticObject, ...] = ()


SignatureVerifier = Callable[[bytes, bytes, bytes, bytes], bool]
Resolver = Callable[[bytes], SemanticObject]


def _bytes(value: bytes) -> bytes:
    return uleb(len(value)) + value


def _canonical(items: Iterable[object], key: Callable[[object], object] | None = None) -> tuple:
    ordered = tuple(sorted(items, key=key))
    keys = tuple((key or (lambda item: item))(item) for item in ordered)
    if len(keys) != len(set(keys)):
        raise ValueError("canonical collection contains duplicates")
    return ordered


def _refs(items: Iterable[SemanticObject | bytes]) -> tuple[bytes, ...]:
    return tuple(sorted({item.cid if isinstance(item, SemanticObject) else item for item in items}))


def _ref_index(references: Sequence[bytes], cid: bytes) -> int:
    return references.index(cid)


def _dependency_key(item: DependencyRequirement) -> bytes:
    return b"\x01" + item.exact_root if item.exact_root is not None else b"\x02" + _bytes(item.logical_identity or b"")


def _capability_bytes(capability: BuildCapability) -> bytes:
    return uleb(capability.kind) + _bytes(capability.scope)


def _binding_key(binding: TypedBinding) -> bytes:
    return binding.name


def package(
    logical_identity: bytes,
    modules: Sequence[SemanticObject],
    *,
    dependencies: Iterable[DependencyRequirement] = (),
    build_entries: Iterable[tuple[bytes, SemanticObject]] = (),
    feature_types: Iterable[tuple[bytes, SemanticObject]] = (),
    configuration_types: Iterable[tuple[bytes, SemanticObject]] = (),
    capabilities: Iterable[BuildCapability] = (),
) -> SemanticObject:
    if not logical_identity:
        raise ValueError("package logical identity must not be empty")
    modules = _canonical(modules, key=lambda item: item.cid)
    if not modules or any(item.kind != Kind.MODULE for item in modules):
        raise ValueError("package requires one or more modules")
    dependencies = _canonical(dependencies, key=_dependency_key)
    entries = _canonical(build_entries, key=lambda item: item[0])
    features = _canonical(feature_types, key=lambda item: item[0])
    configuration = _canonical(configuration_types, key=lambda item: item[0])
    capabilities = _canonical(capabilities)
    if any(not name or value.kind != Kind.FUNCTION for name, value in entries):
        raise ValueError("build entries require nonempty names and functions")
    if any(not name or value.kind != Kind.TYPE for name, value in (*features, *configuration)):
        raise ValueError("feature/configuration schemas require nonempty names and types")
    references = _refs(
        (*modules, *(value for _, value in entries), *(value for _, value in features), *(value for _, value in configuration), *(item.exact_root for item in dependencies if item.exact_root is not None))
    )
    body = bytearray(_bytes(logical_identity))
    body.extend(uleb(len(modules)))
    body.extend(b"".join(uleb(_ref_index(references, item.cid)) for item in modules))
    body.extend(uleb(len(dependencies)))
    for item in dependencies:
        if item.exact_root is not None:
            body.extend(uleb(1) + uleb(_ref_index(references, item.exact_root)))
        else:
            body.extend(uleb(2) + _bytes(item.logical_identity or b""))
    for collection in (entries, features, configuration):
        body.extend(uleb(len(collection)))
        for name, value in collection:
            body.extend(_bytes(name) + uleb(_ref_index(references, value.cid)))
    body.extend(uleb(len(capabilities)))
    body.extend(b"".join(_capability_bytes(item) for item in capabilities))
    return SemanticObject.create(Kind.PACKAGE, bytes(body), references)


def build_profile(
    mode: BuildMode = BuildMode.HERMETIC_REPRODUCIBLE,
    *,
    optimization: int = 0,
    verification: int = 1,
    grants: Iterable[CapabilityGrant] = (),
) -> SemanticObject:
    mode = BuildMode(mode)
    if optimization < 0 or verification < 0:
        raise ValueError("profile levels must be non-negative")
    grants = _canonical(grants, key=lambda item: (item.logical_identity, item.capability.kind, item.capability.scope))
    body = bytearray(uleb(BuildForm.PROFILE) + uleb(mode) + uleb(optimization) + uleb(verification) + uleb(len(grants)))
    for grant in grants:
        body.extend(_bytes(grant.logical_identity) + _capability_bytes(grant.capability))
    return SemanticObject.create(Kind.BUILD, bytes(body))


def optimization_policy(
    *,
    objective: OptimizationObjective = OptimizationObjective.CODE_SIZE,
    pass_iterations: int = 4,
    search_steps: int = 384,
    search_candidates: int = 192,
    search_memory_bytes: int = 1 << 20,
    polynomial_terms: int = 256,
    inline_cold_nodes: int = 2,
    inline_hot_nodes: int = 8,
    hot_call_threshold: int = 10,
    deterministic: bool = True,
) -> SemanticObject:
    objective = OptimizationObjective(objective)
    values = (
        pass_iterations,
        search_steps,
        search_candidates,
        search_memory_bytes,
        polynomial_terms,
        inline_cold_nodes,
        inline_hot_nodes,
        hot_call_threshold,
    )
    if any(value < 0 for value in values):
        raise ValueError("optimization policy budgets must be non-negative")
    body = bytearray(uleb(BuildForm.OPTIMIZATION_POLICY) + uleb(objective))
    body.extend(b"".join(uleb(value) for value in values))
    body.extend(bytes((bool(deterministic),)))
    return SemanticObject.create(Kind.BUILD, bytes(body))


def trust_policy(
    *,
    require_package_signatures: bool = False,
    require_provenance_signature: bool = False,
    accepted_algorithms: Iterable[bytes] = (),
    accepted_signers: Iterable[bytes] = (),
) -> SemanticObject:
    algorithms = _canonical(accepted_algorithms)
    signers = _canonical(accepted_signers)
    body = bytearray(
        uleb(BuildForm.TRUST_POLICY)
        + bytes((require_package_signatures, require_provenance_signature))
        + uleb(len(algorithms))
    )
    body.extend(b"".join(_bytes(item) for item in algorithms))
    body.extend(uleb(len(signers)) + b"".join(_bytes(item) for item in signers))
    return SemanticObject.create(Kind.BUILD, bytes(body))


def signature(signed: SemanticObject, algorithm: bytes, signer: bytes, signature_bytes: bytes) -> SemanticObject:
    if not algorithm or not signer or not signature_bytes:
        raise ValueError("signature algorithm, signer, and bytes must not be empty")
    return SemanticObject.create(
        Kind.BUILD,
        uleb(BuildForm.SIGNATURE) + uleb(0) + _bytes(algorithm) + _bytes(signer) + _bytes(signature_bytes),
        (signed.cid,),
    )


def build_request(
    package_object: SemanticObject,
    build_entry: bytes,
    target_object: SemanticObject,
    profile_object: SemanticObject,
    *,
    features: Iterable[TypedBinding] = (),
    configuration: Iterable[TypedBinding] = (),
    requested_artifacts: Iterable[ArtifactKind] = (ArtifactKind.NATIVE_IMAGE,),
) -> SemanticObject:
    if package_object.kind != Kind.PACKAGE or target_object.kind != Kind.TARGET or profile_object.kind != Kind.BUILD:
        raise ValueError("build request requires package, target, and profile objects")
    if not build_entry:
        raise ValueError("build entry must not be empty")
    features = _canonical(features, key=_binding_key)
    configuration = _canonical(configuration, key=_binding_key)
    artifacts = _canonical((ArtifactKind(item) for item in requested_artifacts))
    if not artifacts:
        raise ValueError("build request requires an artifact")
    references = _refs((package_object, target_object, profile_object, *(item.value for item in features), *(item.value for item in configuration)))
    body = bytearray(uleb(BuildForm.REQUEST))
    body.extend(uleb(_ref_index(references, package_object.cid)) + _bytes(build_entry))
    body.extend(uleb(_ref_index(references, target_object.cid)) + uleb(_ref_index(references, profile_object.cid)))
    for bindings in (features, configuration):
        body.extend(uleb(len(bindings)))
        for item in bindings:
            body.extend(_bytes(item.name) + uleb(_ref_index(references, item.value.cid)))
    body.extend(uleb(len(artifacts)) + b"".join(uleb(item) for item in artifacts))
    return SemanticObject.create(Kind.BUILD, bytes(body), references)


def snapshot(
    request: SemanticObject,
    resolver_identity: bytes,
    policy: SemanticObject,
    packages: Iterable[SemanticObject],
    *,
    signatures: Iterable[SemanticObject] = (),
    external_digests: Iterable[bytes] = (),
) -> SemanticObject:
    if not resolver_identity:
        raise ValueError("resolver identity must not be empty")
    packages = _canonical(packages, key=lambda item: item.cid)
    signatures = _canonical(signatures, key=lambda item: item.cid)
    digests = _canonical(external_digests)
    if any(item.kind != Kind.PACKAGE for item in packages) or any(item.kind != Kind.BUILD for item in signatures):
        raise ValueError("snapshot packages/signatures have wrong kind")
    if any(len(item) != 32 for item in digests):
        raise ValueError("external digest must be 32 bytes")
    references = _refs((request, policy, *packages, *signatures))
    body = bytearray(uleb(BuildForm.SNAPSHOT) + uleb(_ref_index(references, request.cid)) + _bytes(resolver_identity))
    body.extend(uleb(_ref_index(references, policy.cid)) + uleb(len(packages)))
    body.extend(b"".join(uleb(_ref_index(references, item.cid)) for item in packages))
    body.extend(uleb(len(signatures)) + b"".join(uleb(_ref_index(references, item.cid)) for item in signatures))
    body.extend(uleb(len(digests)) + b"".join(digests))
    return SemanticObject.create(Kind.BUILD, bytes(body), references)


def provenance(
    snapshot_object: SemanticObject,
    request: SemanticObject,
    target_object: SemanticObject,
    profile_object: SemanticObject,
    artifact_digest: bytes,
    compiler_identity: bytes,
    lowering: bytes,
    producer_identity: bytes = b"",
) -> SemanticObject:
    for name, value in (("artifact digest", artifact_digest), ("compiler identity", compiler_identity), ("lowering identity", lowering)):
        if len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes")
    references = _refs((snapshot_object, request, target_object, profile_object))
    body = bytearray(uleb(BuildForm.PROVENANCE))
    for item in (snapshot_object, request, target_object, profile_object):
        body.extend(uleb(_ref_index(references, item.cid)))
    body.extend(artifact_digest + compiler_identity + lowering + _bytes(producer_identity))
    return SemanticObject.create(Kind.BUILD, bytes(body), references)


def _enum(enum: type[IntEnum], value: int, obj: SemanticObject, rule: str) -> IntEnum:
    try:
        return enum(value)
    except ValueError:
        fail("XAX.BUILD.ENUM", obj.cid.hex(), rule, sorted(item.value for item in enum), value)


def _reference(obj: SemanticObject, cursor: Cursor, resolve: Resolver, used: set[int]) -> SemanticObject:
    index = cursor.uleb()
    if index >= len(obj.references):
        fail("XAX.STRUCT.REF_INDEX", obj.cid.hex(), "BUILD-REF-INDEX", f"< {len(obj.references)}", index)
    used.add(index)
    return resolve(obj.references[index])


def _finish(obj: SemanticObject, cursor: Cursor, used: set[int]) -> None:
    cursor.end("BUILD-BODY")
    expected = tuple(range(len(obj.references)))
    actual = tuple(sorted(used))
    if actual != expected:
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "BUILD-REFS-EXACT", expected, actual)


def _read_capability(cursor: Cursor, obj: SemanticObject) -> BuildCapability:
    return BuildCapability(_enum(BuildCapabilityKind, cursor.uleb(), obj, "BUILD-CAPABILITY-KIND"), cursor.byte_string())


def _check_canonical(obj: SemanticObject, rule: str, items: Sequence, key: Callable[[object], object] | None = None) -> None:
    keys = tuple((key or (lambda item: item))(item) for item in items)
    if keys != tuple(sorted(set(keys))):
        fail("XAX.BUILD.CANONICAL", obj.cid.hex(), rule, "sorted unique values", keys)


def _build_form(obj: SemanticObject) -> BuildForm:
    if obj.kind != Kind.BUILD:
        fail("XAX.BUILD.KIND", obj.cid.hex(), "BUILD-KIND", Kind.BUILD.name, obj.kind.name)
    cursor = Cursor(obj.body, obj.cid.hex())
    return _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM")


def decode_package(obj: SemanticObject, resolve: Resolver) -> PackageView:
    if obj.kind != Kind.PACKAGE:
        fail("XAX.PACKAGE.KIND", obj.cid.hex(), "PACKAGE-KIND", Kind.PACKAGE.name, obj.kind.name)
    cursor, used = Cursor(obj.body, obj.cid.hex()), set()
    logical_identity = cursor.byte_string()
    if not logical_identity:
        fail("XAX.PACKAGE.IDENTITY", obj.cid.hex(), "PACKAGE-LOGICAL-IDENTITY", "nonempty bytes", "empty")
    modules = tuple(_reference(obj, cursor, resolve, used).cid for _ in range(cursor.uleb()))
    if not modules:
        fail("XAX.PACKAGE.MODULE", obj.cid.hex(), "PACKAGE-MODULES", ">= 1", 0)
    for cid in modules:
        if resolve(cid).kind != Kind.MODULE:
            fail("XAX.PACKAGE.MODULE", obj.cid.hex(), "PACKAGE-MODULE-KIND", Kind.MODULE.name, resolve(cid).kind.name)
    _check_canonical(obj, "PACKAGE-MODULES-CANONICAL", modules)

    dependencies: list[DependencyRequirement] = []
    for _ in range(cursor.uleb()):
        form = cursor.uleb()
        if form == 1:
            dependency = _reference(obj, cursor, resolve, used)
            if dependency.kind != Kind.PACKAGE:
                fail("XAX.PACKAGE.DEPENDENCY", obj.cid.hex(), "PACKAGE-EXACT-KIND", Kind.PACKAGE.name, dependency.kind.name)
            dependencies.append(DependencyRequirement.exact(dependency))
        elif form == 2:
            dependencies.append(DependencyRequirement.logical(cursor.byte_string()))
        else:
            fail("XAX.PACKAGE.DEPENDENCY", obj.cid.hex(), "PACKAGE-DEPENDENCY-FORM", [1, 2], form)
    _check_canonical(obj, "PACKAGE-DEPENDENCIES-CANONICAL", dependencies, _dependency_key)

    collections: list[tuple[tuple[bytes, bytes], ...]] = []
    expected_kinds = (Kind.FUNCTION, Kind.TYPE, Kind.TYPE)
    for expected_kind in expected_kinds:
        items = []
        for _ in range(cursor.uleb()):
            name = cursor.byte_string()
            child = _reference(obj, cursor, resolve, used)
            if not name or child.kind != expected_kind:
                fail("XAX.PACKAGE.SCHEMA", obj.cid.hex(), "PACKAGE-NAMED-REFERENCE", ["nonempty", expected_kind.name], [name.hex(), child.kind.name])
            items.append((name, child.cid))
        _check_canonical(obj, "PACKAGE-NAMES-CANONICAL", items, lambda item: item[0])
        collections.append(tuple(items))

    capabilities = tuple(_read_capability(cursor, obj) for _ in range(cursor.uleb()))
    _check_canonical(obj, "PACKAGE-CAPABILITIES-CANONICAL", capabilities)
    _finish(obj, cursor, used)
    return PackageView(
        logical_identity,
        modules,
        tuple(dependencies),
        collections[0],
        collections[1],
        collections[2],
        capabilities,
    )


def decode_profile(obj: SemanticObject) -> ProfileView:
    cursor, used = Cursor(obj.body, obj.cid.hex()), set()
    if _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM") != BuildForm.PROFILE:
        fail("XAX.BUILD.FORM", obj.cid.hex(), "BUILD-PROFILE-FORM", BuildForm.PROFILE.value, "other")
    mode = _enum(BuildMode, cursor.uleb(), obj, "BUILD-MODE")
    optimization, verification = cursor.uleb(), cursor.uleb()
    grants = tuple(CapabilityGrant(cursor.byte_string(), _read_capability(cursor, obj)) for _ in range(cursor.uleb()))
    _check_canonical(obj, "BUILD-GRANTS-CANONICAL", grants, lambda item: (item.logical_identity, item.capability.kind, item.capability.scope))
    _finish(obj, cursor, used)
    return ProfileView(mode, optimization, verification, grants)


def decode_trust_policy(obj: SemanticObject) -> TrustPolicyView:
    cursor, used = Cursor(obj.body, obj.cid.hex()), set()
    if _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM") != BuildForm.TRUST_POLICY:
        fail("XAX.BUILD.FORM", obj.cid.hex(), "BUILD-TRUST-FORM", BuildForm.TRUST_POLICY.value, "other")
    require_packages, require_provenance = cursor.boolean(), cursor.boolean()
    algorithms = tuple(cursor.byte_string() for _ in range(cursor.uleb()))
    signers = tuple(cursor.byte_string() for _ in range(cursor.uleb()))
    _check_canonical(obj, "TRUST-ALGORITHMS-CANONICAL", algorithms)
    _check_canonical(obj, "TRUST-SIGNERS-CANONICAL", signers)
    if any(not item for item in (*algorithms, *signers)):
        fail("XAX.TRUST.EMPTY", obj.cid.hex(), "TRUST-IDENTITY-NONEMPTY", "nonempty identities", "empty")
    if (require_packages or require_provenance) and (not algorithms or not signers):
        fail("XAX.TRUST.EMPTY", obj.cid.hex(), "TRUST-REQUIRED-SETS", "accepted algorithms and signers", [algorithms, signers])
    _finish(obj, cursor, used)
    return TrustPolicyView(require_packages, require_provenance, algorithms, signers)


def decode_signature(obj: SemanticObject, resolve: Resolver) -> SignatureView:
    cursor, used = Cursor(obj.body, obj.cid.hex()), set()
    if _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM") != BuildForm.SIGNATURE:
        fail("XAX.BUILD.FORM", obj.cid.hex(), "BUILD-SIGNATURE-FORM", BuildForm.SIGNATURE.value, "other")
    signed = _reference(obj, cursor, resolve, used)
    algorithm, signer, value = cursor.byte_string(), cursor.byte_string(), cursor.byte_string()
    if not algorithm or not signer or not value:
        fail("XAX.TRUST.SIGNATURE", obj.cid.hex(), "TRUST-SIGNATURE-NONEMPTY", "nonempty fields", [algorithm.hex(), signer.hex(), value.hex()])
    _finish(obj, cursor, used)
    return SignatureView(signed.cid, algorithm, signer, value)


def _constant_type(obj: SemanticObject, resolve: Resolver) -> bytes:
    if obj.kind != Kind.CONSTANT:
        fail("XAX.BUILD.VALUE", obj.cid.hex(), "BUILD-TYPED-VALUE", Kind.CONSTANT.name, obj.kind.name)
    cursor = Cursor(obj.body, obj.cid.hex())
    index = cursor.uleb()
    if index >= len(obj.references):
        fail("XAX.STRUCT.REF_INDEX", obj.cid.hex(), "BUILD-CONSTANT-TYPE", f"< {len(obj.references)}", index)
    return resolve(obj.references[index]).cid


def decode_request(obj: SemanticObject, resolve: Resolver) -> RequestView:
    cursor, used = Cursor(obj.body, obj.cid.hex()), set()
    if _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM") != BuildForm.REQUEST:
        fail("XAX.BUILD.FORM", obj.cid.hex(), "BUILD-REQUEST-FORM", BuildForm.REQUEST.value, "other")
    package_object = _reference(obj, cursor, resolve, used)
    build_entry = cursor.byte_string()
    target_object = _reference(obj, cursor, resolve, used)
    profile_object = _reference(obj, cursor, resolve, used)
    if package_object.kind != Kind.PACKAGE or target_object.kind != Kind.TARGET or _build_form(profile_object) != BuildForm.PROFILE:
        fail("XAX.BUILD.REQUEST", obj.cid.hex(), "BUILD-REQUEST-REFERENCE-KINDS", [Kind.PACKAGE.name, Kind.TARGET.name, BuildForm.PROFILE.name], [package_object.kind.name, target_object.kind.name, _build_form(profile_object).name])
    package_view = decode_package(package_object, resolve)
    if build_entry not in dict(package_view.build_entries):
        fail("XAX.BUILD.ENTRY", obj.cid.hex(), "BUILD-ENTRY-DECLARED", [name.hex() for name, _ in package_view.build_entries], build_entry.hex())

    decoded_bindings = []
    for schema in (package_view.feature_types, package_view.configuration_types):
        items = []
        for _ in range(cursor.uleb()):
            name = cursor.byte_string()
            value = _reference(obj, cursor, resolve, used)
            items.append((name, value.cid))
        _check_canonical(obj, "BUILD-BINDINGS-CANONICAL", items, lambda item: item[0])
        expected = dict(schema)
        if set(name for name, _ in items) != set(expected):
            fail("XAX.BUILD.INPUT_CLOSURE", obj.cid.hex(), "BUILD-BINDINGS-COMPLETE", sorted(name.hex() for name in expected), sorted(name.hex() for name, _ in items))
        for name, cid in items:
            actual_type = _constant_type(resolve(cid), resolve)
            if actual_type != expected[name]:
                fail("XAX.BUILD.VALUE_TYPE", obj.cid.hex(), "BUILD-BINDING-TYPE", expected[name].hex(), actual_type.hex())
        decoded_bindings.append(tuple(items))
    artifacts = tuple(_enum(ArtifactKind, cursor.uleb(), obj, "BUILD-ARTIFACT-KIND") for _ in range(cursor.uleb()))
    _check_canonical(obj, "BUILD-ARTIFACTS-CANONICAL", artifacts)
    if not artifacts:
        fail("XAX.BUILD.ARTIFACT", obj.cid.hex(), "BUILD-ARTIFACT-REQUIRED", ">= 1", 0)
    _finish(obj, cursor, used)
    return RequestView(package_object.cid, build_entry, target_object.cid, profile_object.cid, decoded_bindings[0], decoded_bindings[1], artifacts)


def decode_optimization_policy(obj: SemanticObject) -> OptimizationPolicyView:
    cursor = Cursor(obj.body, obj.cid.hex())
    if _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM") != BuildForm.OPTIMIZATION_POLICY:
        fail("XAX.BUILD.FORM", obj.cid.hex(), "BUILD-OPTIMIZATION-POLICY-FORM", BuildForm.OPTIMIZATION_POLICY.value, "other")
    objective = _enum(OptimizationObjective, cursor.uleb(), obj, "OPT-OBJECTIVE")
    values = tuple(cursor.uleb() for _ in range(8))
    deterministic = cursor.boolean()
    cursor.end("BUILD-OPTIMIZATION-POLICY-BODY")
    if obj.references:
        fail("XAX.CANON.UNUSED_REFERENCE", obj.cid.hex(), "SER-REFS-DIRECT-ONLY", [], [cid.hex() for cid in obj.references])
    return OptimizationPolicyView(objective, *values, deterministic)


def decode_provenance(obj: SemanticObject, resolve: Resolver) -> ProvenanceView:
    cursor, used = Cursor(obj.body, obj.cid.hex()), set()
    if _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM") != BuildForm.PROVENANCE:
        fail("XAX.BUILD.FORM", obj.cid.hex(), "BUILD-PROVENANCE-FORM", BuildForm.PROVENANCE.value, "other")
    snapshot_object, request, target, profile = (_reference(obj, cursor, resolve, used) for _ in range(4))
    if _build_form(snapshot_object) != BuildForm.SNAPSHOT or _build_form(request) != BuildForm.REQUEST or target.kind != Kind.TARGET or _build_form(profile) != BuildForm.PROFILE:
        fail("XAX.PROVENANCE.REFERENCE", obj.cid.hex(), "PROVENANCE-REFERENCE-KINDS", "snapshot/request/target/profile", [snapshot_object.kind.name, request.kind.name, target.kind.name, profile.kind.name])
    artifact_digest, compiler, lowering = cursor.take(32), cursor.take(32), cursor.take(32)
    producer = cursor.byte_string()
    _finish(obj, cursor, used)
    snapshot_view = decode_snapshot(snapshot_object, resolve)
    request_view = decode_request(request, resolve)
    if snapshot_view.request_root != request.cid or request_view.target_root != target.cid or request_view.profile_root != profile.cid:
        fail(
            "XAX.PROVENANCE.CLOSURE",
            obj.cid.hex(),
            "PROVENANCE-EXACT-CLOSURE",
            [snapshot_view.request_root.hex(), request_view.target_root.hex(), request_view.profile_root.hex()],
            [request.cid.hex(), target.cid.hex(), profile.cid.hex()],
        )
    return ProvenanceView(snapshot_object.cid, request.cid, target.cid, profile.cid, artifact_digest, compiler, lowering, producer)


def _resolved_dependency(
    owner: SemanticObject,
    requirement: DependencyRequirement,
    packages: Mapping[bytes, tuple[SemanticObject, PackageView]],
) -> bytes:
    if requirement.exact_root is not None:
        if requirement.exact_root not in packages:
            fail("XAX.RESOLVE.MISSING", owner.cid.hex(), "RESOLVE-EXACT-ROOT", requirement.exact_root.hex(), "missing")
        return requirement.exact_root
    matches = tuple(cid for cid, (_, view) in packages.items() if view.logical_identity == requirement.logical_identity)
    if len(matches) != 1:
        fail(
            "XAX.RESOLVE.AMBIGUOUS" if matches else "XAX.RESOLVE.MISSING",
            owner.cid.hex(),
            "RESOLVE-LOGICAL-IDENTITY",
            "exactly one candidate",
            [cid.hex() for cid in sorted(matches)],
        )
    return matches[0]


def decode_snapshot(obj: SemanticObject, resolve: Resolver) -> SnapshotView:
    cursor, used = Cursor(obj.body, obj.cid.hex()), set()
    if _enum(BuildForm, cursor.uleb(), obj, "BUILD-FORM") != BuildForm.SNAPSHOT:
        fail("XAX.BUILD.FORM", obj.cid.hex(), "BUILD-SNAPSHOT-FORM", BuildForm.SNAPSHOT.value, "other")
    request = _reference(obj, cursor, resolve, used)
    resolver_identity = cursor.byte_string()
    policy = _reference(obj, cursor, resolve, used)
    if not resolver_identity or _build_form(request) != BuildForm.REQUEST or _build_form(policy) != BuildForm.TRUST_POLICY:
        fail("XAX.SNAPSHOT.HEADER", obj.cid.hex(), "SNAPSHOT-HEADER", "request, resolver identity, trust policy", [request.kind.name, resolver_identity.hex(), policy.kind.name])
    package_objects = tuple(_reference(obj, cursor, resolve, used) for _ in range(cursor.uleb()))
    signature_objects = tuple(_reference(obj, cursor, resolve, used) for _ in range(cursor.uleb()))
    digests = tuple(cursor.take(32) for _ in range(cursor.uleb()))
    if any(item.kind != Kind.PACKAGE for item in package_objects):
        fail("XAX.SNAPSHOT.PACKAGE", obj.cid.hex(), "SNAPSHOT-PACKAGE-KIND", Kind.PACKAGE.name, [item.kind.name for item in package_objects])
    if any(_build_form(item) != BuildForm.SIGNATURE for item in signature_objects):
        fail("XAX.SNAPSHOT.SIGNATURE", obj.cid.hex(), "SNAPSHOT-SIGNATURE-KIND", BuildForm.SIGNATURE.name, [_build_form(item).name for item in signature_objects])
    package_roots = tuple(item.cid for item in package_objects)
    signature_roots = tuple(item.cid for item in signature_objects)
    _check_canonical(obj, "SNAPSHOT-PACKAGES-CANONICAL", package_roots)
    _check_canonical(obj, "SNAPSHOT-SIGNATURES-CANONICAL", signature_roots)
    _check_canonical(obj, "SNAPSHOT-EXTERNAL-CANONICAL", digests)
    _finish(obj, cursor, used)

    request_view = decode_request(request, resolve)
    packages = {item.cid: (item, decode_package(item, resolve)) for item in package_objects}
    if request_view.package_root not in packages:
        fail("XAX.SNAPSHOT.ROOT", obj.cid.hex(), "SNAPSHOT-ROOT-PACKAGE", request_view.package_root.hex(), "missing")
    reachable, pending = set(), [request_view.package_root]
    while pending:
        root = pending.pop()
        if root in reachable:
            continue
        reachable.add(root)
        package_object, view = packages[root]
        pending.extend(_resolved_dependency(package_object, item, packages) for item in view.dependencies)
    if reachable != set(packages):
        fail("XAX.SNAPSHOT.CLOSURE", obj.cid.hex(), "SNAPSHOT-EXACT-CLOSURE", sorted(cid.hex() for cid in reachable), sorted(cid.hex() for cid in packages))

    profile = decode_profile(resolve(request_view.profile_root))
    policy_view = decode_trust_policy(policy)
    by_identity: dict[bytes, list[PackageView]] = {}
    for _, view in packages.values():
        by_identity.setdefault(view.logical_identity, []).append(view)
    for grant in profile.grants:
        views = by_identity.get(grant.logical_identity, ())
        if not views or any(grant.capability not in view.capabilities for view in views):
            fail("XAX.BUILD.CAPABILITY", obj.cid.hex(), "BUILD-GRANT-DECLARED", [item.hex() for item in by_identity], [grant.logical_identity.hex(), grant.capability])
    decoded_signatures = tuple(decode_signature(item, resolve) for item in signature_objects)
    signed_roots = tuple(item.signed_root for item in decoded_signatures)
    if any(root not in packages for root in signed_roots):
        fail("XAX.TRUST.SNAPSHOT", obj.cid.hex(), "TRUST-SIGNATURE-PACKAGE", [cid.hex() for cid in packages], [cid.hex() for cid in signed_roots])
    if policy_view.require_package_signatures and any(root not in signed_roots for root in packages):
        fail("XAX.TRUST.REQUIRED", obj.cid.hex(), "TRUST-SNAPSHOT-COVERAGE", [cid.hex() for cid in packages], [cid.hex() for cid in signed_roots])
    return SnapshotView(request.cid, resolver_identity, policy.cid, package_roots, signature_roots, digests)


def verify_build_object(obj: SemanticObject, resolve: Resolver) -> None:
    if obj.kind == Kind.PACKAGE:
        decode_package(obj, resolve)
        return
    form = _build_form(obj)
    if form == BuildForm.PROFILE:
        decode_profile(obj)
    elif form == BuildForm.REQUEST:
        decode_request(obj, resolve)
    elif form == BuildForm.SNAPSHOT:
        decode_snapshot(obj, resolve)
    elif form == BuildForm.TRUST_POLICY:
        decode_trust_policy(obj)
    elif form == BuildForm.PROVENANCE:
        decode_provenance(obj, resolve)
    elif form == BuildForm.SIGNATURE:
        decode_signature(obj, resolve)
    elif form == BuildForm.OPTIMIZATION_POLICY:
        decode_optimization_policy(obj)


def verify_fetched_object(expected_root: bytes, envelope: bytes) -> SemanticObject:
    obj = decode_object(envelope, "fetched-object")
    if obj.cid != expected_root:
        fail("XAX.INTEGRITY.FETCH", obj.cid.hex(), "FETCH-EXPECTED-ROOT", expected_root.hex(), obj.cid.hex())
    return obj


def verify_external_bytes(expected_digest: bytes, value: bytes) -> None:
    actual = blake3(value).digest()
    if actual != expected_digest:
        fail("XAX.INTEGRITY.EXTERNAL", expected_digest.hex(), "EXTERNAL-DIGEST", expected_digest.hex(), actual.hex())


def _signature_is_trusted(
    view: SignatureView,
    policy: TrustPolicyView,
    verifier: SignatureVerifier | None,
) -> bool:
    return (
        verifier is not None
        and view.algorithm in policy.accepted_algorithms
        and view.signer in policy.accepted_signers
        and verifier(view.algorithm, view.signer, view.signed_root, view.signature)
    )


def _trusted_signatures(
    roots: Iterable[bytes],
    signatures: Iterable[SemanticObject],
    policy: TrustPolicyView,
    resolve: Resolver,
    verifier: SignatureVerifier | None,
) -> tuple[SemanticObject, ...]:
    decoded = tuple((item, decode_signature(item, resolve)) for item in sorted(signatures, key=lambda item: item.cid))
    accepted = []
    for root in sorted(roots):
        matches = tuple(item for item, view in decoded if view.signed_root == root and _signature_is_trusted(view, policy, verifier))
        if not matches:
            fail("XAX.TRUST.REQUIRED", root.hex(), "TRUST-SIGNATURE-REQUIRED", "accepted valid signature", "missing")
        accepted.extend(matches)
    return tuple(_canonical(accepted, key=lambda item: item.cid))


def resolve_packages(
    request: SemanticObject,
    objects: Iterable[SemanticObject],
    policy: SemanticObject,
    resolver_identity: bytes,
    *,
    signatures: Iterable[SemanticObject] = (),
    signature_verifier: SignatureVerifier | None = None,
    external_inputs: Mapping[bytes, bytes] | None = None,
) -> Resolution:
    signatures = tuple(signatures)
    all_objects = {item.cid: item for item in (*tuple(objects), request, policy, *signatures)}

    def resolve(cid: bytes) -> SemanticObject:
        try:
            return all_objects[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "ID-REFERENCE-RESOLVED", "candidate object", "missing")

    for item in all_objects.values():
        verify_object(item, resolve)
    request_view = decode_request(request, resolve)
    policy_view = decode_trust_policy(policy)
    candidates = {cid: item for cid, item in all_objects.items() if item.kind == Kind.PACKAGE}
    candidate_views = {cid: (item, decode_package(item, resolve)) for cid, item in candidates.items()}
    selected, pending = set(), [request_view.package_root]
    while pending:
        root = pending.pop()
        if root in selected:
            continue
        if root not in candidate_views:
            fail("XAX.RESOLVE.MISSING", request.cid.hex(), "RESOLVE-ROOT-PACKAGE", root.hex(), "missing")
        selected.add(root)
        owner, view = candidate_views[root]
        pending.extend(_resolved_dependency(owner, item, candidate_views) for item in view.dependencies)
    package_objects = tuple(candidates[cid] for cid in sorted(selected))
    used_signatures = ()
    if policy_view.require_package_signatures:
        used_signatures = _trusted_signatures(selected, signatures, policy_view, resolve, signature_verifier)
    digests = tuple(sorted((external_inputs or {}).keys()))
    for digest, value in (external_inputs or {}).items():
        verify_external_bytes(digest, value)
    snapshot_object = snapshot(
        request,
        resolver_identity,
        policy,
        package_objects,
        signatures=used_signatures,
        external_digests=digests,
    )
    all_objects[snapshot_object.cid] = snapshot_object
    verify_build_object(snapshot_object, resolve)
    return Resolution(package_objects, used_signatures, snapshot_object)


def snapshot_store(resolution: Resolution, objects: Iterable[SemanticObject]) -> StoreReader:
    by_cid = {item.cid: item for item in (*tuple(objects), *resolution.packages, *resolution.signatures, resolution.snapshot)}
    reachable: set[bytes] = set()

    def visit(cid: bytes) -> None:
        if cid in reachable:
            return
        try:
            item = by_cid[cid]
        except KeyError:
            fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "SNAPSHOT-LOCAL-CLOSURE", "local object", "missing")
        reachable.add(cid)
        for child in item.references:
            visit(child)

    visit(resolution.snapshot.cid)
    reader = StoreReader.from_objects(resolution.snapshot.cid, (by_cid[cid] for cid in reachable))
    verify_store(reader)
    return reader


def _build_identity(snapshot_root: bytes, request_root: bytes, compiler: bytes, lowering: bytes) -> bytes:
    return blake3(BUILD_DOMAIN + snapshot_root + request_root + compiler + lowering).digest()


def _snapshot_context(reader: StoreReader, request_root: bytes) -> tuple[SemanticObject, SnapshotView, SemanticObject, RequestView, TrustPolicyView]:
    if reader.root_cid == request_root:
        fail("XAX.BUILD.SNAPSHOT", request_root.hex(), "BUILD-SNAPSHOT-ROOT", "snapshot root", "request root")
    snapshot_object = reader.get(reader.root_cid)
    if _build_form(snapshot_object) != BuildForm.SNAPSHOT:
        fail("XAX.BUILD.SNAPSHOT", snapshot_object.cid.hex(), "BUILD-SNAPSHOT-ROOT", BuildForm.SNAPSHOT.name, _build_form(snapshot_object).name)
    snapshot_view = decode_snapshot(snapshot_object, reader.get)
    if snapshot_view.request_root != request_root:
        fail("XAX.BUILD.REQUEST", snapshot_object.cid.hex(), "BUILD-SNAPSHOT-REQUEST", snapshot_view.request_root.hex(), request_root.hex())
    request = reader.get(request_root)
    request_view = decode_request(request, reader.get)
    policy = decode_trust_policy(reader.get(snapshot_view.trust_policy_root))
    return snapshot_object, snapshot_view, request, request_view, policy


def _validate_external_inputs(snapshot_view: SnapshotView, external_inputs: Mapping[bytes, bytes]) -> None:
    actual = tuple(sorted(external_inputs))
    if actual != snapshot_view.external_digests:
        fail("XAX.BUILD.INPUT_CLOSURE", "external-inputs", "BUILD-EXTERNAL-COMPLETE", [item.hex() for item in snapshot_view.external_digests], [item.hex() for item in actual])
    for digest, value in external_inputs.items():
        verify_external_bytes(digest, value)


def _validate_trust(
    reader: StoreReader,
    snapshot_view: SnapshotView,
    policy: TrustPolicyView,
    verifier: SignatureVerifier | None,
) -> None:
    if not policy.require_package_signatures:
        return
    signatures = tuple(reader.get(cid) for cid in snapshot_view.signature_roots)
    accepted = _trusted_signatures(snapshot_view.package_roots, signatures, policy, reader.get, verifier)
    if tuple(item.cid for item in accepted) != snapshot_view.signature_roots:
        fail("XAX.TRUST.SNAPSHOT", "snapshot", "TRUST-SNAPSHOT-SIGNATURES", [item.hex() for item in snapshot_view.signature_roots], [item.cid.hex() for item in accepted])


def validate_build_effects(reader: StoreReader, snapshot_view: SnapshotView, request_view: RequestView, effects: Iterable[BuildEffect]) -> None:
    packages = tuple((reader.get(cid), decode_package(reader.get(cid), reader.get)) for cid in snapshot_view.package_roots)
    by_identity: dict[bytes, list[PackageView]] = {}
    for _, view in packages:
        by_identity.setdefault(view.logical_identity, []).append(view)
    profile = decode_profile(reader.get(request_view.profile_root))
    grants = set(profile.grants)
    nondeterministic = {BuildCapabilityKind.NETWORK, BuildCapabilityKind.CLOCK, BuildCapabilityKind.RANDOM}
    for effect in effects:
        views = by_identity.get(effect.logical_identity, ())
        grant = CapabilityGrant(effect.logical_identity, effect.capability)
        if not views or grant not in grants or any(effect.capability not in view.capabilities for view in views):
            fail("XAX.BUILD.CAPABILITY", effect.logical_identity.hex(), "BUILD-CAPABILITY-ISOLATED", "declared package-local grant", [effect.capability.kind.name, effect.capability.scope.hex()])
        if profile.mode == BuildMode.HERMETIC_REPRODUCIBLE and effect.capability.kind in nondeterministic:
            fail("XAX.BUILD.REPRODUCIBLE_INPUT", effect.logical_identity.hex(), "BUILD-NO-LIVE-NONDETERMINISM", "declared immutable input", effect.capability.kind.name)
        if effect.capability.kind == BuildCapabilityKind.READ_EXTERNAL:
            digest = effect.capability.scope
            if digest not in snapshot_view.external_digests:
                fail("XAX.BUILD.INPUT_CLOSURE", effect.logical_identity.hex(), "BUILD-EXTERNAL-DECLARED", [item.hex() for item in snapshot_view.external_digests], digest.hex())
            verify_external_bytes(digest, effect.value)
        elif profile.mode == BuildMode.HERMETIC_REPRODUCIBLE and effect.capability.kind == BuildCapabilityKind.SIGN:
            # Signing material affects emitted bytes.  Keep the secret transport
            # out of semantic objects, but require its digest in the declared
            # external closure so the snapshot/build key commits to it.
            digest = blake3(effect.value).digest()
            if digest not in snapshot_view.external_digests:
                fail(
                    "XAX.BUILD.INPUT_CLOSURE",
                    effect.logical_identity.hex(),
                    "BUILD-SIGNING-MATERIAL-DECLARED",
                    [item.hex() for item in snapshot_view.external_digests],
                    digest.hex(),
                )


def _build_android_unsigned_apk(
    reader: StoreReader,
    package_view: PackageView,
    target_object: SemanticObject,
    build_entry_function: bytes,
) -> bytes:
    """Lower the bounded semantic Android application slice to one unsigned APK."""

    from xax_android import (
        ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX,
        ANDROID_ACTIVITY_METHOD_UI_PREFIX,
        ANDROID_ACTIVITY_RESOURCE_UI_PREFIX,
        ANDROID_ACTIVITY_UI_PREFIX,
        ANDROID_TARGET_IDENTITY,
        compile_android_shared,
        decode_android_activity_argument_method_ui,
        decode_android_activity_method_ui,
        decode_android_activity_resource_ui,
        decode_android_activity_ui,
        lower_android_activity_argument_method_ui,
        lower_android_activity_method_ui,
        lower_android_activity_resource_ui,
        lower_android_activity_ui,
    )
    from xax_apk import build_unsigned_apk
    from xax_android_components import (
        ANDROID_APPLICATION_PREFIX,
        ANDROID_BROADCAST_RECEIVER_PREFIX,
        ANDROID_SERVICE_PREFIX,
        decode_android_application,
        decode_android_broadcast_receiver,
        decode_android_service,
        lower_android_application,
        lower_android_broadcast_receiver,
        lower_android_service,
    )
    from xax_dex import emit_dex039_bridge
    from xax_jni import jni_short_native_symbol
    from xax_libxposed import (
        LIBXPOSED_HOOK_ADAPTER_PREFIX,
        LIBXPOSED_HOOK_ARGUMENT_PREFIX,
        LIBXPOSED_HOOK_COMBINED_PREFIX,
        LIBXPOSED_DEOPTIMIZE_PREFIX,
        LIBXPOSED_MODULE_SERVICES_PREFIX,
        LIBXPOSED_REMOTE_PREFERENCES_PREFIX,
        LIBXPOSED_REMOTE_FILES_PREFIX,
        LIBXPOSED_HOT_RELOAD_PREFIX,
        LIBXPOSED_HOOK_INSTALL_PREFIX,
        LIBXPOSED_HOOK_RESULT_PREFIX,
        LIBXPOSED_MANAGED_ENTRY_PREFIX,
        LIBXPOSED_MODULE_PREFIX,
        decode_libxposed_hook_adapter,
        decode_libxposed_hook_argument,
        decode_libxposed_hook_combined,
        decode_libxposed_deoptimization,
        decode_libxposed_module_services,
        decode_libxposed_remote_preferences,
        decode_libxposed_remote_files,
        decode_libxposed_hot_reload,
        decode_libxposed_hook_installation,
        decode_libxposed_hook_result,
        decode_libxposed_managed_entry,
        decode_libxposed_module,
        emit_libxposed_metadata,
        lower_libxposed_hook_adapter,
        lower_libxposed_managed_entry,
    )
    from xax_manifest import (
        ANDROID_MANIFEST_PREFIX,
        AndroidManifestApplication,
        AndroidManifestReceiver,
        AndroidManifestService,
        decode_android_manifest_semantics,
        emit_binary_manifest_with_components_from_semantics,
    )
    from xax_resources import ANDROID_RESOURCES_PREFIX, decode_android_resources_semantics, emit_resources_arsc_from_semantics
    from xax_compiler import ANDROID_EXPORT_PREFIX, decode_android_export

    description = decode_native_target(target_object)
    if description.identity != ANDROID_TARGET_IDENTITY:
        fail("XAX.BUILD.ANDROID", target_object.cid.hex(), "ANDROID-APK-TARGET", ANDROID_TARGET_IDENTITY.decode(), description.identity.decode("ascii", "replace"))

    ui_carriers: list[SemanticObject] = []
    manifest_carriers: list[SemanticObject] = []
    resource_carriers: list[SemanticObject] = []
    application_carriers: list[SemanticObject] = []
    receiver_carriers: list[SemanticObject] = []
    service_carriers: list[SemanticObject] = []
    libxposed_carriers: list[SemanticObject] = []
    libxposed_managed_entry_carriers: list[SemanticObject] = []
    libxposed_hook_adapter_carriers: list[SemanticObject] = []
    libxposed_hook_install_carriers: list[SemanticObject] = []
    libxposed_hook_result_carriers: list[SemanticObject] = []
    libxposed_hook_argument_carriers: list[SemanticObject] = []
    libxposed_hook_combined_carriers: list[SemanticObject] = []
    libxposed_deoptimization_carriers: list[SemanticObject] = []
    libxposed_module_services_carriers: list[SemanticObject] = []
    libxposed_remote_preferences_carriers: list[SemanticObject] = []
    libxposed_remote_files_carriers: list[SemanticObject] = []
    libxposed_hot_reload_carriers: list[SemanticObject] = []
    export_carriers: list[SemanticObject] = []
    for module_cid in package_view.modules:
        module = reader.get(module_cid)
        for cid in module.references:
            child = reader.get(cid)
            if child.kind != Kind.TARGET or child.references:
                continue
            cursor = Cursor(child.body, child.cid.hex())
            identity = cursor.byte_string()
            if identity.startswith((
                ANDROID_ACTIVITY_UI_PREFIX,
                ANDROID_ACTIVITY_RESOURCE_UI_PREFIX,
                ANDROID_ACTIVITY_METHOD_UI_PREFIX,
                ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX,
            )):
                ui_carriers.append(child)
            elif identity.startswith(ANDROID_MANIFEST_PREFIX):
                manifest_carriers.append(child)
            elif identity.startswith(ANDROID_RESOURCES_PREFIX):
                resource_carriers.append(child)
            elif identity.startswith(ANDROID_APPLICATION_PREFIX):
                application_carriers.append(child)
            elif identity.startswith(ANDROID_BROADCAST_RECEIVER_PREFIX):
                receiver_carriers.append(child)
            elif identity.startswith(ANDROID_SERVICE_PREFIX):
                service_carriers.append(child)
            elif identity.startswith(LIBXPOSED_MODULE_PREFIX):
                libxposed_carriers.append(child)
            elif identity.startswith(LIBXPOSED_MANAGED_ENTRY_PREFIX):
                libxposed_managed_entry_carriers.append(child)
            elif identity.startswith(LIBXPOSED_HOOK_ADAPTER_PREFIX):
                libxposed_hook_adapter_carriers.append(child)
            elif identity.startswith(LIBXPOSED_HOOK_INSTALL_PREFIX):
                libxposed_hook_install_carriers.append(child)
            elif identity.startswith(LIBXPOSED_HOOK_RESULT_PREFIX):
                libxposed_hook_result_carriers.append(child)
            elif identity.startswith(LIBXPOSED_HOOK_ARGUMENT_PREFIX):
                libxposed_hook_argument_carriers.append(child)
            elif identity.startswith(LIBXPOSED_HOOK_COMBINED_PREFIX):
                libxposed_hook_combined_carriers.append(child)
            elif identity.startswith(LIBXPOSED_DEOPTIMIZE_PREFIX):
                libxposed_deoptimization_carriers.append(child)
            elif identity.startswith(LIBXPOSED_MODULE_SERVICES_PREFIX):
                libxposed_module_services_carriers.append(child)
            elif identity.startswith(LIBXPOSED_REMOTE_PREFERENCES_PREFIX):
                libxposed_remote_preferences_carriers.append(child)
            elif identity.startswith(LIBXPOSED_REMOTE_FILES_PREFIX):
                libxposed_remote_files_carriers.append(child)
            elif identity.startswith(LIBXPOSED_HOT_RELOAD_PREFIX):
                libxposed_hot_reload_carriers.append(child)
            elif identity.startswith(ANDROID_EXPORT_PREFIX):
                export_carriers.append(child)

    if (
        len(ui_carriers) != 1
        or len(manifest_carriers) != 1
        or len(resource_carriers) > 1
        or len(application_carriers) > 1
        or len(receiver_carriers) > 1
        or len(service_carriers) > 1
        or len(libxposed_carriers) > 1
        or len(libxposed_managed_entry_carriers) > 1
        or len(libxposed_hook_adapter_carriers) > 1
        or len(libxposed_hook_install_carriers) > 1
        or len(libxposed_hook_result_carriers) > 1
        or len(libxposed_hook_argument_carriers) > 1
        or len(libxposed_hook_combined_carriers) > 1
        or len(libxposed_deoptimization_carriers) > 1
        or len(libxposed_module_services_carriers) > 1
        or len(libxposed_remote_preferences_carriers) > 1
        or len(libxposed_remote_files_carriers) > 1
        or len(libxposed_hot_reload_carriers) > 1
    ):
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-SEMANTIC-CARRIERS",
            {"ui": 1, "manifest": 1, "resources": "0..1", "application": "0..1", "receiver": "0..1", "service": "0..1", "libxposed": "0..1", "libxposed_managed_entry": "0..1", "libxposed_hook_adapter": "0..1", "libxposed_hook_install": "0..1", "libxposed_hook_result": "0..1", "libxposed_hook_argument": "0..1", "libxposed_hook_combined": "0..1", "libxposed_deoptimization": "0..1", "libxposed_module_services": "0..1", "libxposed_remote_preferences": "0..1", "libxposed_remote_files": "0..1", "libxposed_hot_reload": "0..1"},
            {
                "ui": len(ui_carriers),
                "manifest": len(manifest_carriers),
                "resources": len(resource_carriers),
                "application": len(application_carriers),
                "receiver": len(receiver_carriers),
                "service": len(service_carriers),
                "libxposed": len(libxposed_carriers),
                "libxposed_managed_entry": len(libxposed_managed_entry_carriers),
                "libxposed_hook_adapter": len(libxposed_hook_adapter_carriers),
                "libxposed_hook_install": len(libxposed_hook_install_carriers),
                "libxposed_hook_result": len(libxposed_hook_result_carriers),
                "libxposed_hook_argument": len(libxposed_hook_argument_carriers),
                "libxposed_hook_combined": len(libxposed_hook_combined_carriers),
                "libxposed_deoptimization": len(libxposed_deoptimization_carriers),
                "libxposed_module_services": len(libxposed_module_services_carriers),
                "libxposed_remote_preferences": len(libxposed_remote_preferences_carriers),
                "libxposed_remote_files": len(libxposed_remote_files_carriers),
                "libxposed_hot_reload": len(libxposed_hot_reload_carriers),
            },
        )

    ui_identity_cursor = Cursor(ui_carriers[0].body, ui_carriers[0].cid.hex())
    ui_identity = ui_identity_cursor.byte_string()
    if ui_identity.startswith(ANDROID_ACTIVITY_RESOURCE_UI_PREFIX):
        ui_view = decode_android_activity_resource_ui(ui_carriers[0])
        if len(resource_carriers) != 1:
            fail(
                "XAX.BUILD.ANDROID",
                ui_carriers[0].cid.hex(),
                "ANDROID-RESOURCE-UI-REQUIRES-TABLE",
                1,
                len(resource_carriers),
            )
    elif ui_identity.startswith(ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX):
        ui_view = decode_android_activity_argument_method_ui(ui_carriers[0])
    elif ui_identity.startswith(ANDROID_ACTIVITY_METHOD_UI_PREFIX):
        ui_view = decode_android_activity_method_ui(ui_carriers[0])
    else:
        ui_view = decode_android_activity_ui(ui_carriers[0])
    manifest_view = decode_android_manifest_semantics(manifest_carriers[0])
    resource_view = decode_android_resources_semantics(resource_carriers[0]) if resource_carriers else None
    application_view = decode_android_application(application_carriers[0]) if application_carriers else None
    receiver_view = decode_android_broadcast_receiver(receiver_carriers[0]) if receiver_carriers else None
    service_view = decode_android_service(service_carriers[0]) if service_carriers else None
    libxposed_view = decode_libxposed_module(libxposed_carriers[0]) if libxposed_carriers else None
    libxposed_managed_entry_view = (
        decode_libxposed_managed_entry(libxposed_managed_entry_carriers[0])
        if libxposed_managed_entry_carriers else None
    )
    libxposed_hook_adapter_view = (
        decode_libxposed_hook_adapter(libxposed_hook_adapter_carriers[0])
        if libxposed_hook_adapter_carriers else None
    )
    libxposed_hook_install_view = (
        decode_libxposed_hook_installation(libxposed_hook_install_carriers[0])
        if libxposed_hook_install_carriers else None
    )
    libxposed_hook_result_view = (
        decode_libxposed_hook_result(libxposed_hook_result_carriers[0])
        if libxposed_hook_result_carriers else None
    )
    libxposed_hook_argument_view = (
        decode_libxposed_hook_argument(libxposed_hook_argument_carriers[0])
        if libxposed_hook_argument_carriers else None
    )
    libxposed_hook_combined_view = (
        decode_libxposed_hook_combined(libxposed_hook_combined_carriers[0])
        if libxposed_hook_combined_carriers else None
    )
    libxposed_deoptimization_view = (
        decode_libxposed_deoptimization(libxposed_deoptimization_carriers[0])
        if libxposed_deoptimization_carriers else None
    )
    libxposed_module_services_view = (
        decode_libxposed_module_services(libxposed_module_services_carriers[0])
        if libxposed_module_services_carriers else None
    )
    libxposed_remote_preferences_view = (
        decode_libxposed_remote_preferences(libxposed_remote_preferences_carriers[0])
        if libxposed_remote_preferences_carriers else None
    )
    libxposed_remote_files_view = (
        decode_libxposed_remote_files(libxposed_remote_files_carriers[0])
        if libxposed_remote_files_carriers else None
    )
    libxposed_hot_reload_view = (
        decode_libxposed_hot_reload(libxposed_hot_reload_carriers[0])
        if libxposed_hot_reload_carriers else None
    )
    expected_activity_name = ui_view.activity_class_descriptor[1:-1].replace("/", ".")
    if manifest_view.activity_class != expected_activity_name:
        fail("XAX.BUILD.ANDROID", manifest_carriers[0].cid.hex(), "ANDROID-APK-ACTIVITY-IDENTITY", expected_activity_name, manifest_view.activity_class)
    if manifest_view.min_sdk < 21:
        fail("XAX.BUILD.ANDROID", manifest_carriers[0].cid.hex(), "ANDROID-APK-MULTIDEX-MINSDK", ">= 21", manifest_view.min_sdk)
    if resource_view is not None and resource_view.package_name != manifest_view.package_name:
        fail(
            "XAX.BUILD.ANDROID",
            resource_carriers[0].cid.hex(),
            "ANDROID-APK-RESOURCE-PACKAGE",
            manifest_view.package_name,
            resource_view.package_name,
        )
    if libxposed_managed_entry_view is not None and libxposed_view is None:
        fail(
            "XAX.BUILD.ANDROID",
            libxposed_managed_entry_carriers[0].cid.hex(),
            "ANDROID-APK-LIBXPOSED-MANAGED-METADATA",
            "matching libxposed module metadata carrier",
            "missing",
        )
    if (
        libxposed_hook_adapter_view is not None
        or libxposed_hook_install_view is not None
        or libxposed_hook_result_view is not None
        or libxposed_hook_argument_view is not None
        or libxposed_hook_combined_view is not None
        or libxposed_hot_reload_view is not None
    ) and (
        libxposed_view is None or libxposed_managed_entry_view is None
    ):
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-LIBXPOSED-HOOK-MANAGED-ENTRY",
            "libxposed metadata plus generated managed entry",
            "missing",
        )
    if (libxposed_hook_adapter_view is None) != (libxposed_hook_install_view is None):
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-LIBXPOSED-HOOK-CLOSURE",
            "one hook adapter plus one hook installation",
            {
                "adapter": libxposed_hook_adapter_view is not None,
                "installation": libxposed_hook_install_view is not None,
            },
        )
    if libxposed_hook_result_view is not None:
        if libxposed_hook_argument_view is not None or libxposed_hook_combined_view is not None:
            fail(
                "XAX.BUILD.ANDROID", package_view.logical_identity.hex(),
                "ANDROID-APK-LIBXPOSED-HOOK-POLICY",
                "one mutation policy carrier", [name for name, present in (("result", True), ("argument", libxposed_hook_argument_view is not None), ("combined", libxposed_hook_combined_view is not None)) if present],
            )
        if libxposed_hook_adapter_view is None or libxposed_hook_install_view is None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_hook_result_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-RESULT-CLOSURE",
                "hook adapter plus hook installation",
                {"adapter": libxposed_hook_adapter_view is not None, "installation": libxposed_hook_install_view is not None},
            )
        if libxposed_hook_result_view.hooker_class_name != libxposed_hook_adapter_view.java_class_name:
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_result_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-RESULT-HOOKER", libxposed_hook_adapter_view.java_class_name,
                libxposed_hook_result_view.hooker_class_name,
            )
        if (
            libxposed_hook_result_view.target_class_name != libxposed_hook_install_view.target_class_name
            or libxposed_hook_result_view.target_method_name != libxposed_hook_install_view.target_method_name
        ):
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_result_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-RESULT-TARGET",
                [libxposed_hook_install_view.target_class_name, libxposed_hook_install_view.target_method_name],
                [libxposed_hook_result_view.target_class_name, libxposed_hook_result_view.target_method_name],
            )
        if libxposed_hook_adapter_view.inspected_argument_index is not None:
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_result_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-RESULT-ZERO-ARG", None, libxposed_hook_adapter_view.inspected_argument_index,
            )
    if libxposed_hook_argument_view is not None:
        if libxposed_hook_combined_view is not None:
            fail(
                "XAX.BUILD.ANDROID", package_view.logical_identity.hex(),
                "ANDROID-APK-LIBXPOSED-HOOK-POLICY",
                "one mutation policy carrier", ["argument", "combined"],
            )
        if libxposed_hook_adapter_view is None or libxposed_hook_install_view is None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_hook_argument_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-ARGUMENT-CLOSURE",
                "hook adapter plus hook installation",
                {"adapter": libxposed_hook_adapter_view is not None, "installation": libxposed_hook_install_view is not None},
            )
        if libxposed_hook_argument_view.hooker_class_name != libxposed_hook_adapter_view.java_class_name:
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_argument_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-ARGUMENT-HOOKER", libxposed_hook_adapter_view.java_class_name,
                libxposed_hook_argument_view.hooker_class_name,
            )
        if (
            libxposed_hook_argument_view.target_class_name != libxposed_hook_install_view.target_class_name
            or libxposed_hook_argument_view.target_method_name != libxposed_hook_install_view.target_method_name
        ):
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_argument_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-ARGUMENT-TARGET",
                [libxposed_hook_install_view.target_class_name, libxposed_hook_install_view.target_method_name],
                [libxposed_hook_argument_view.target_class_name, libxposed_hook_argument_view.target_method_name],
            )
        if libxposed_hook_adapter_view.inspected_argument_index != libxposed_hook_argument_view.argument_index:
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_argument_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-ARGUMENT-INDEX", libxposed_hook_argument_view.argument_index,
                libxposed_hook_adapter_view.inspected_argument_index,
            )
        if libxposed_hook_install_view.parameter_type_names != ("java.lang.String",):
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_install_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-ARGUMENT-SIGNATURE", ["java.lang.String"],
                list(libxposed_hook_install_view.parameter_type_names),
            )
    if libxposed_hook_combined_view is not None:
        if libxposed_hook_adapter_view is None or libxposed_hook_install_view is None:
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_combined_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-COMBINED-CLOSURE",
                "hook adapter plus hook installation",
                {"adapter": libxposed_hook_adapter_view is not None, "installation": libxposed_hook_install_view is not None},
            )
        if libxposed_hook_combined_view.hooker_class_name != libxposed_hook_adapter_view.java_class_name:
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_combined_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-COMBINED-HOOKER", libxposed_hook_adapter_view.java_class_name,
                libxposed_hook_combined_view.hooker_class_name,
            )
        if (
            libxposed_hook_combined_view.target_class_name != libxposed_hook_install_view.target_class_name
            or libxposed_hook_combined_view.target_method_name != libxposed_hook_install_view.target_method_name
        ):
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_combined_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-COMBINED-TARGET",
                [libxposed_hook_install_view.target_class_name, libxposed_hook_install_view.target_method_name],
                [libxposed_hook_combined_view.target_class_name, libxposed_hook_combined_view.target_method_name],
            )
        if libxposed_hook_adapter_view.inspected_argument_index != libxposed_hook_combined_view.argument_index:
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_combined_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-COMBINED-INDEX", libxposed_hook_combined_view.argument_index,
                libxposed_hook_adapter_view.inspected_argument_index,
            )
        if libxposed_hook_install_view.parameter_type_names != ("java.lang.String",):
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_install_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-COMBINED-SIGNATURE", ["java.lang.String"],
                list(libxposed_hook_install_view.parameter_type_names),
            )
    if libxposed_deoptimization_view is not None:
        if libxposed_hook_install_view is None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_deoptimization_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-DEOPT-CLOSURE",
                "companion hook installation",
                None,
            )
        if (
            libxposed_deoptimization_view.target_class_name != libxposed_hook_install_view.target_class_name
            or libxposed_deoptimization_view.target_method_name != libxposed_hook_install_view.target_method_name
            or libxposed_deoptimization_view.parameter_type_names != libxposed_hook_install_view.parameter_type_names
        ):
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_deoptimization_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-DEOPT-TARGET",
                {
                    "class": libxposed_hook_install_view.target_class_name,
                    "method": libxposed_hook_install_view.target_method_name,
                    "parameters": list(libxposed_hook_install_view.parameter_type_names),
                },
                {
                    "class": libxposed_deoptimization_view.target_class_name,
                    "method": libxposed_deoptimization_view.target_method_name,
                    "parameters": list(libxposed_deoptimization_view.parameter_type_names),
                },
            )
    if libxposed_hook_install_view is not None:
        if libxposed_view.target_api_version != 102:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-HOOK-API",
                102,
                libxposed_view.target_api_version,
            )
        if libxposed_hook_install_view.hooker_class_name != libxposed_hook_adapter_view.java_class_name:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_hook_install_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-HOOKER-IDENTITY",
                libxposed_hook_adapter_view.java_class_name,
                libxposed_hook_install_view.hooker_class_name,
            )
        if "onPackageReady" not in libxposed_managed_entry_view.callbacks:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_managed_entry_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-HOOK-LIFECYCLE",
                "onPackageReady",
                list(libxposed_managed_entry_view.callbacks),
            )
        if libxposed_hook_argument_view is None and libxposed_hook_combined_view is None and libxposed_hook_adapter_view.inspected_argument_index is not None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_hook_adapter_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-ZERO-ARG-HOOKER",
                "pure Chain.proceed() with no argument inspection",
                libxposed_hook_adapter_view.inspected_argument_index,
            )
    if libxposed_module_services_view is not None:
        if libxposed_view is None or libxposed_managed_entry_view is None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_module_services_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-SERVICES-CLOSURE",
                "libxposed metadata plus generated managed entry",
                {
                    "metadata": libxposed_view is not None,
                    "managed_entry": libxposed_managed_entry_view is not None,
                },
            )
        if libxposed_view.target_api_version != 102:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-SERVICES-API",
                102,
                libxposed_view.target_api_version,
            )
    if libxposed_remote_preferences_view is not None:
        if libxposed_view is None or libxposed_managed_entry_view is None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_remote_preferences_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-REMOTE-PREFS-CLOSURE",
                "libxposed metadata plus generated managed entry",
                {
                    "metadata": libxposed_view is not None,
                    "managed_entry": libxposed_managed_entry_view is not None,
                },
            )
        if libxposed_view.target_api_version != 102:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-REMOTE-PREFS-API",
                102,
                libxposed_view.target_api_version,
            )
    if libxposed_remote_files_view is not None:
        if libxposed_view is None or libxposed_managed_entry_view is None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_remote_files_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-REMOTE-FILES-CLOSURE",
                "libxposed metadata plus generated managed entry",
                {"metadata": libxposed_view is not None, "managed_entry": libxposed_managed_entry_view is not None},
            )
        if libxposed_view.target_api_version != 102:
            fail(
                "XAX.BUILD.ANDROID", libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-REMOTE-FILES-API", 102, libxposed_view.target_api_version,
            )
    if libxposed_hot_reload_view is not None:
        if libxposed_view is None or libxposed_managed_entry_view is None or libxposed_hook_install_view is None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_hot_reload_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-HOT-RELOAD-CLOSURE",
                "API-102 metadata, one managed entry, and one retained hook installation",
                {
                    "metadata": libxposed_view is not None,
                    "managed_entry": libxposed_managed_entry_view is not None,
                    "hook_install": libxposed_hook_install_view is not None,
                },
            )
        if libxposed_view.min_api_version != 102 or libxposed_view.target_api_version != 102:
            fail(
                "XAX.BUILD.ANDROID", libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-HOT-RELOAD-API",
                {"min": 102, "target": 102},
                {"min": libxposed_view.min_api_version, "target": libxposed_view.target_api_version},
            )
        if len(libxposed_view.java_entries) != 1:
            fail(
                "XAX.BUILD.ANDROID", libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-HOT-RELOAD-ENTRY", 1, len(libxposed_view.java_entries),
            )
        if libxposed_hook_install_view.lifetime_policy != "retained-manual-unhook":
            fail(
                "XAX.BUILD.ANDROID", libxposed_hook_install_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-HOT-RELOAD-LIFETIME",
                "retained-manual-unhook", libxposed_hook_install_view.lifetime_policy,
            )

    if libxposed_view is not None:
        if libxposed_view.java_entries:
            if libxposed_managed_entry_view is None:
                fail(
                    "XAX.BUILD.ANDROID",
                    libxposed_carriers[0].cid.hex(),
                    "ANDROID-APK-LIBXPOSED-JAVA-ENTRY",
                    "one generated XposedModule managed entry carrier",
                    list(libxposed_view.java_entries),
                )
            if libxposed_view.java_entries != (libxposed_managed_entry_view.java_class_name,):
                fail(
                    "XAX.BUILD.ANDROID",
                    libxposed_carriers[0].cid.hex(),
                    "ANDROID-APK-LIBXPOSED-JAVA-IDENTITY",
                    [libxposed_managed_entry_view.java_class_name],
                    list(libxposed_view.java_entries),
                )
        elif libxposed_managed_entry_view is not None:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-JAVA-ENTRY",
                [libxposed_managed_entry_view.java_class_name],
                [],
            )
        unsupported_native = tuple(name for name in libxposed_view.native_entries if name != "libxaxapp.so")
        if unsupported_native:
            fail(
                "XAX.BUILD.ANDROID",
                libxposed_carriers[0].cid.hex(),
                "ANDROID-APK-LIBXPOSED-NATIVE-ENTRY",
                ["libxaxapp.so"],
                list(libxposed_view.native_entries),
            )

    if ui_identity.startswith(ANDROID_ACTIVITY_RESOURCE_UI_PREFIX):
        activity_spec, listener_spec = lower_android_activity_resource_ui(ui_carriers[0], resource_carriers[0])
    elif ui_identity.startswith(ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX):
        activity_spec, listener_spec = lower_android_activity_argument_method_ui(ui_carriers[0])
    elif ui_identity.startswith(ANDROID_ACTIVITY_METHOD_UI_PREFIX):
        activity_spec, listener_spec = lower_android_activity_method_ui(ui_carriers[0])
    else:
        activity_spec, listener_spec = lower_android_activity_ui(ui_carriers[0])
    application_spec = lower_android_application(application_carriers[0]) if application_carriers else None
    receiver_spec = lower_android_broadcast_receiver(receiver_carriers[0]) if receiver_carriers else None
    service_spec = lower_android_service(service_carriers[0]) if service_carriers else None
    libxposed_managed_spec = (
        lower_libxposed_managed_entry(
            libxposed_managed_entry_carriers[0],
            libxposed_hook_install_carriers[0] if libxposed_hook_install_carriers else None,
            libxposed_deoptimization_carriers[0] if libxposed_deoptimization_carriers else None,
            libxposed_module_services_carriers[0] if libxposed_module_services_carriers else None,
            libxposed_remote_preferences_carriers[0] if libxposed_remote_preferences_carriers else None,
            libxposed_hot_reload_carriers[0] if libxposed_hot_reload_carriers else None,
            libxposed_remote_files_carriers[0] if libxposed_remote_files_carriers else None,
        )
        if libxposed_managed_entry_carriers else None
    )
    libxposed_hook_adapter_spec = (
        lower_libxposed_hook_adapter(
            libxposed_hook_adapter_carriers[0],
            libxposed_hook_result_carriers[0] if libxposed_hook_result_carriers else None,
            libxposed_hook_argument_carriers[0] if libxposed_hook_argument_carriers else None,
            libxposed_hook_combined_carriers[0] if libxposed_hook_combined_carriers else None,
        )
        if libxposed_hook_adapter_carriers else None
    )
    activity_symbol = jni_short_native_symbol(activity_spec.class_descriptor, activity_spec.native_methods[0].name)
    listener_symbol = jni_short_native_symbol(listener_spec.class_descriptor, listener_spec.native_methods[0].name)
    receiver_symbol = (
        jni_short_native_symbol(receiver_spec.class_descriptor, receiver_spec.native_methods[0].name)
        if receiver_spec is not None
        else None
    )
    application_symbol = (
        jni_short_native_symbol(application_spec.class_descriptor, application_spec.native_methods[0].name)
        if application_spec is not None
        else None
    )
    service_symbols = (
        tuple(jni_short_native_symbol(service_spec.class_descriptor, item.name) for item in service_spec.native_methods)
        if service_spec is not None
        else ()
    )
    libxposed_managed_symbols = (
        tuple(jni_short_native_symbol(libxposed_managed_spec.class_descriptor, item.name) for item in libxposed_managed_spec.native_methods)
        if libxposed_managed_spec is not None
        else ()
    )
    decoded_exports = tuple((carrier, decode_android_export(carrier)) for carrier in export_carriers)
    by_name = {view.name: (carrier, view) for carrier, view in decoded_exports}
    if activity_symbol not in by_name or listener_symbol not in by_name:
        fail("XAX.BUILD.ANDROID", package_view.logical_identity.hex(), "ANDROID-APK-JNI-EXPORTS", [activity_symbol.decode(), listener_symbol.decode()], sorted(name.decode("ascii", "replace") for name in by_name))
    if application_symbol is not None and application_symbol not in by_name:
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-APPLICATION-EXPORT",
            application_symbol.decode(),
            sorted(name.decode("ascii", "replace") for name in by_name),
        )
    if receiver_symbol is not None and receiver_symbol not in by_name:
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-RECEIVER-EXPORT",
            receiver_symbol.decode(),
            sorted(name.decode("ascii", "replace") for name in by_name),
        )
    missing_service_symbols = tuple(symbol for symbol in service_symbols if symbol not in by_name)
    if missing_service_symbols:
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-SERVICE-EXPORT",
            [symbol.decode() for symbol in service_symbols],
            sorted(name.decode("ascii", "replace") for name in by_name),
        )
    missing_libxposed_managed_symbols = tuple(symbol for symbol in libxposed_managed_symbols if symbol not in by_name)
    if missing_libxposed_managed_symbols:
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-LIBXPOSED-MANAGED-EXPORT",
            [symbol.decode() for symbol in libxposed_managed_symbols],
            sorted(name.decode("ascii", "replace") for name in by_name),
        )
    if libxposed_view is not None and libxposed_view.native_entries and b"native_init" not in by_name:
        fail(
            "XAX.BUILD.ANDROID",
            package_view.logical_identity.hex(),
            "ANDROID-APK-LIBXPOSED-NATIVE-INIT",
            "exported native_init in libxaxapp.so",
            sorted(name.decode("ascii", "replace") for name in by_name),
        )
    if by_name[activity_symbol][1].function_cid != build_entry_function:
        fail("XAX.BUILD.ANDROID", package_view.logical_identity.hex(), "ANDROID-APK-BUILD-ENTRY", build_entry_function.hex(), by_name[activity_symbol][1].function_cid.hex())

    shared = compile_android_shared(
        reader,
        tuple(carrier for carrier, _ in decoded_exports),
        target_object=target_object,
        soname=b"libxaxapp.so",
    )
    manifest_receivers = (
        (AndroidManifestReceiver(receiver_view.java_class_name, receiver_view.exported, receiver_view.action),)
        if receiver_view is not None
        else ()
    )
    manifest_services = (
        (AndroidManifestService(service_view.java_class_name, service_view.exported),)
        if service_view is not None
        else ()
    )
    manifest_application = (
        AndroidManifestApplication(application_view.java_class_name)
        if application_view is not None
        else None
    )
    manifest = emit_binary_manifest_with_components_from_semantics(
        manifest_carriers[0], manifest_receivers, manifest_services, manifest_application
    )
    activity_dex = emit_dex039_bridge(activity_spec)
    listener_dex = emit_dex039_bridge(listener_spec)
    extra_entries = {"classes2.dex": listener_dex}
    next_dex = 3
    if receiver_spec is not None:
        extra_entries[f"classes{next_dex}.dex"] = emit_dex039_bridge(receiver_spec)
        next_dex += 1
    if service_spec is not None:
        extra_entries[f"classes{next_dex}.dex"] = emit_dex039_bridge(service_spec)
        next_dex += 1
    if application_spec is not None:
        extra_entries[f"classes{next_dex}.dex"] = emit_dex039_bridge(application_spec)
        next_dex += 1
    if libxposed_managed_spec is not None:
        extra_entries[f"classes{next_dex}.dex"] = emit_dex039_bridge(libxposed_managed_spec)
        next_dex += 1
    if libxposed_hook_adapter_spec is not None:
        extra_entries[f"classes{next_dex}.dex"] = emit_dex039_bridge(libxposed_hook_adapter_spec)
        next_dex += 1
    if libxposed_carriers:
        for name, data in emit_libxposed_metadata(
            libxposed_carriers[0],
            libxposed_hot_reload_carriers[0] if libxposed_hot_reload_carriers else None,
        ).items():
            extra_entries[name] = data
    if resource_carriers:
        extra_entries["resources.arsc"] = emit_resources_arsc_from_semantics(resource_carriers[0])
    return build_unsigned_apk(
        manifest,
        activity_dex,
        native_libraries={"libxaxapp.so": shared.data},
        extra_entries=extra_entries,
    )


def build(
    reader: StoreReader,
    request_root: bytes,
    *,
    external_inputs: Mapping[bytes, bytes] | None = None,
    effects: Iterable[BuildEffect] = (),
    signature_verifier: SignatureVerifier | None = None,
    compiler_identity: bytes = BOOTSTRAP_COMPILER_IDENTITY_V1,
    producer_identity: bytes = b"",
) -> BuildResult:
    verify_store(reader)
    if len(compiler_identity) != 32:
        raise ValueError("compiler identity must be 32 bytes")
    snapshot_object, snapshot_view, request, request_view, policy = _snapshot_context(reader, request_root)
    _validate_external_inputs(snapshot_view, external_inputs or {})
    _validate_trust(reader, snapshot_view, policy, signature_verifier)
    effects = tuple(effects)
    validate_build_effects(reader, snapshot_view, request_view, effects)
    package_view = decode_package(reader.get(request_view.package_root), reader.get)
    function_root = dict(package_view.build_entries)[request_view.build_entry]
    target_object = reader.get(request_view.target_root)
    description = decode_native_target(target_object)
    if request_view.requested_artifacts in (
        (ArtifactKind.ANDROID_UNSIGNED_APK,),
        (ArtifactKind.ANDROID_SIGNED_APK,),
    ):
        artifact = _build_android_unsigned_apk(reader, package_view, target_object, function_root)
        if request_view.requested_artifacts == (ArtifactKind.ANDROID_UNSIGNED_APK,):
            lowering = ANDROID_UNSIGNED_APK_LOWERING_IDENTITY_V1
        else:
            from xax_apk_signing import decode_private_signing_capability, sign_apk_v2

            signing_effects = tuple(
                effect
                for effect in effects
                if effect.logical_identity == package_view.logical_identity
                and effect.capability.kind == BuildCapabilityKind.SIGN
            )
            if len(signing_effects) != 1:
                fail(
                    "XAX.BUILD.ANDROID",
                    package_view.logical_identity.hex(),
                    "ANDROID-APK-SIGNING-CAPABILITY",
                    "exactly one explicit package SIGN effect",
                    len(signing_effects),
                )
            signing_effect = signing_effects[0]
            if len(signing_effect.capability.scope) != 32:
                fail(
                    "XAX.BUILD.ANDROID",
                    package_view.logical_identity.hex(),
                    "ANDROID-APK-SIGNER-IDENTITY",
                    "32-byte certificate SHA-256",
                    signing_effect.capability.scope.hex(),
                )
            try:
                signing_capability = decode_private_signing_capability(signing_effect.value)
            except (TypeError, ValueError):
                fail(
                    "XAX.BUILD.ANDROID",
                    package_view.logical_identity.hex(),
                    "ANDROID-APK-SIGNING-CAPABILITY",
                    "valid private signing capability transport",
                    "invalid",
                )
            actual_signer = bytes.fromhex(signing_capability.identity_sha256)
            if signing_effect.capability.scope != actual_signer:
                fail(
                    "XAX.BUILD.ANDROID",
                    package_view.logical_identity.hex(),
                    "ANDROID-APK-SIGNER-IDENTITY",
                    signing_effect.capability.scope.hex(),
                    actual_signer.hex(),
                )
            artifact = sign_apk_v2(artifact, signing_capability)
            lowering = ANDROID_SIGNED_APK_LOWERING_IDENTITY_V1
    else:
        expected_artifact = ArtifactKind.ACCELERATOR_DEPLOYMENT if description.architecture == 4 else ArtifactKind.NATIVE_IMAGE
        if request_view.requested_artifacts != (expected_artifact,):
            fail(
                "XAX.BUILD.ARTIFACT",
                request.cid.hex(),
                "BUILD-ARTIFACT-SUPPORTED",
                [expected_artifact.name, ArtifactKind.ANDROID_UNSIGNED_APK.name, ArtifactKind.ANDROID_SIGNED_APK.name],
                [item.name for item in request_view.requested_artifacts],
            )
        if description.architecture == 1:
            from xax_x86_64 import compile_native_bound_target

            image = compile_native_bound_target(reader, function_root, target_object)
        elif description.architecture == 2:
            from xax_wasm import compile_wasm_bound_target

            image = compile_wasm_bound_target(reader, function_root, target_object)
        elif description.architecture == 3:
            from xax_aarch64 import compile_aarch64_bound_target

            image = compile_aarch64_bound_target(reader, function_root, target_object)
        elif description.architecture == 4:
            from xax_accelerator import compile_accelerator_bound_target

            image = compile_accelerator_bound_target(reader, function_root, target_object)
        else:
            fail("XAX.BUILD.TARGET", target_object.cid.hex(), "BUILD-TARGET-SUPPORTED", [1, 2, 3, 4], description.architecture)
        artifact = image.artifact_bytes
        lowering = lowering_identity(description.architecture, description.image_format)
    artifact_digest = blake3(artifact).digest()
    record = provenance(
        snapshot_object,
        request,
        target_object,
        reader.get(request_view.profile_root),
        artifact_digest,
        compiler_identity,
        lowering,
        producer_identity,
    )
    key = _build_identity(snapshot_object.cid, request.cid, compiler_identity, lowering)
    return BuildResult(key, artifact, artifact_digest, record)


class BuildCache:
    def __init__(self, entries: Mapping[bytes, BuildCacheEntry] | None = None):
        self._entries = dict(entries or {})

    def put(self, result: BuildResult, signatures: Iterable[SemanticObject] = ()) -> None:
        self._entries[result.key] = BuildCacheEntry(result.artifact, result.provenance, tuple(signatures))

    def get(
        self,
        key: bytes,
        reader: StoreReader,
        *,
        policy: SemanticObject | None = None,
        signature_verifier: SignatureVerifier | None = None,
    ) -> bytes:
        try:
            entry = self._entries[key]
        except KeyError:
            fail("XAX.CACHE.MISS", key.hex(), "CACHE-KEY-PRESENT", "cached artifact", "missing")
        actual_digest = blake3(entry.artifact).digest()
        resolve_map = {item.cid: item for item in (*tuple(reader.objects()), entry.provenance, *entry.signatures)}

        def resolve(cid: bytes) -> SemanticObject:
            try:
                return resolve_map[cid]
            except KeyError:
                fail("XAX.IDENTITY.OBJECT_MISSING", cid.hex(), "CACHE-PROVENANCE-CLOSURE", "available object", "missing")

        verify_build_object(entry.provenance, resolve)
        view = decode_provenance(entry.provenance, resolve)
        if actual_digest != view.artifact_digest:
            fail("XAX.CACHE.INTEGRITY", key.hex(), "CACHE-ARTIFACT-DIGEST", view.artifact_digest.hex(), actual_digest.hex())
        expected_key = _build_identity(view.snapshot_root, view.request_root, view.compiler_identity, view.lowering_identity)
        if key != expected_key:
            fail("XAX.CACHE.IDENTITY", key.hex(), "CACHE-BUILD-IDENTITY", expected_key.hex(), key.hex())
        if policy is not None:
            policy_view = decode_trust_policy(policy)
            if policy_view.require_provenance_signature:
                accepted = _trusted_signatures((entry.provenance.cid,), entry.signatures, policy_view, resolve, signature_verifier)
                if not accepted:
                    fail("XAX.TRUST.REQUIRED", entry.provenance.cid.hex(), "TRUST-PROVENANCE-SIGNATURE", "accepted valid signature", "missing")
        return entry.artifact
