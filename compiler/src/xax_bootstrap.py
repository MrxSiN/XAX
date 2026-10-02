"""M11 bootstrap evidence for the first XAX-hosted compiler subset.

The authoritative implementation is the committed canonical ``.xax`` program
artifact.  The Python constructors in this module are transitional seed
material used only to reproduce and validate that artifact; they are not XAX
source and do not define language semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from xax_artifact import BOOTSTRAP_COMPILER_IDENTITY_V1, WASM_LOWERING_IDENTITY_V1
from xax_build import (
    BuildMode,
    BuildResult,
    PackageView,
    ProfileView,
    ProvenanceView,
    RequestView,
    SnapshotView,
    TrustPolicyView,
    build,
    build_profile,
    build_request,
    decode_package,
    decode_profile,
    decode_provenance,
    decode_request,
    decode_snapshot,
    decode_trust_policy,
    package,
    resolve_packages,
    snapshot_store,
    trust_policy,
)
from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    decode_native_target,
    execute,
    function,
    graph_fragment,
    object_with_refs,
    verify_store,
    wasm32_target,
    write_store,
)
from xax_wasm import WasmImage, compile_wasm_bound_target, run_wasm_isolated


M11_PACKAGE_ID = b"xax.m11.arithmetic-folder.v1"
M11_BUILD_ENTRY = b"compiler"
M11_RESOLVER_IDENTITY = b"xax-bootstrap-resolver-v1"
M11_PROGRAM_FILENAME = "m11_compiler_subset.xax"
M11_BUNDLE_FILENAME = "m11_bootstrap_bundle.xax"
M11_EVIDENCE_FILENAME = "m11_bootstrap_evidence.json"

# selector=0 -> add.wrap, selector=1 -> mul.wrap.  These are conformance inputs,
# not a textual XAX language.
M11_CONFORMANCE_VECTORS: tuple[tuple[int, int, int], ...] = (
    (0, 0, 0),
    (0, 1, 2),
    (0, 0xFFFFFFFF, 2),
    (1, 3, 4),
    (1, 0xFFFFFFFF, 2),
    (1, 0x80000000, 2),
)


@dataclass(frozen=True)
class M11Definition:
    b1: SemanticObject
    b32: SemanticObject
    graph: SemanticObject
    entry: SemanticObject
    module: SemanticObject
    program_root: SemanticObject

    @property
    def program_objects(self) -> tuple[SemanticObject, ...]:
        return (self.b1, self.b32, self.graph, self.entry, self.module, self.program_root)


@dataclass(frozen=True)
class M11BootstrapBundle:
    program_store: StoreReader
    build_store: StoreReader
    program_root: SemanticObject
    module: SemanticObject
    entry: SemanticObject
    package: SemanticObject
    package_view: PackageView
    target: SemanticObject
    profile: SemanticObject
    profile_view: ProfileView
    policy: SemanticObject
    policy_view: TrustPolicyView
    request: SemanticObject
    request_view: RequestView
    snapshot: SemanticObject
    snapshot_view: SnapshotView


@dataclass(frozen=True)
class M11BootstrapBuild:
    result: BuildResult
    image: WasmImage
    provenance_view: ProvenanceView


@dataclass(frozen=True)
class M11Comparison:
    arguments: tuple[int, int, int]
    seed_result: tuple[int, ...]
    hosted_result: tuple[int, ...]

    @property
    def matches(self) -> bool:
        return self.seed_result == self.hosted_result


def m11_definition() -> M11Definition:
    """Construct the exact transitional seed representation of the M11 graph."""

    b1 = bits_type(1)
    b32 = bits_type(32)
    graph = graph_fragment(
        (
            Block(
                (b1, b32, b32),
                (),
                Terminator.conditional_branch(
                    ValueRef.parameter(0, 0),
                    1,
                    (ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
                    2,
                    (ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)),
                ),
            ),
            Block(
                (b32, b32),
                (Node(Operation.MUL_WRAP, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(1, 0),)),
            ),
            Block(
                (b32, b32),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(2, 0),)),
            ),
        )
    )
    entry = function(graph, (b1, b32, b32), (b32,))
    module = object_with_refs(Kind.MODULE, (entry,))
    program_root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return M11Definition(b1, b32, graph, entry, module, program_root)


def create_m11_program_store() -> StoreReader:
    definition = m11_definition()
    reader = StoreReader.from_objects(definition.program_root.cid, definition.program_objects)
    verify_store(reader)
    return reader


def create_m11_bootstrap_store() -> StoreReader:
    """Create the exact fixed-policy seed build snapshot for the hosted subset."""

    definition = m11_definition()
    target = wasm32_target()
    profile = build_profile(mode=BuildMode.HERMETIC_REPRODUCIBLE, optimization=0, verification=1)
    policy = trust_policy()
    package_object = package(
        M11_PACKAGE_ID,
        (definition.module,),
        build_entries=((M11_BUILD_ENTRY, definition.entry),),
    )
    request = build_request(package_object, M11_BUILD_ENTRY, target, profile)
    candidates = (
        definition.b1,
        definition.b32,
        definition.graph,
        definition.entry,
        definition.module,
        package_object,
        target,
        profile,
        policy,
        request,
    )
    resolution = resolve_packages(request, candidates, policy, M11_RESOLVER_IDENTITY)
    return snapshot_store(resolution, candidates)


def write_m11_artifacts(directory: str | Path) -> tuple[Path, Path]:
    """Write byte-canonical program and bootstrap stores for repository retention."""

    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    program = create_m11_program_store()
    bundle = create_m11_bootstrap_store()
    program_path = destination / M11_PROGRAM_FILENAME
    bundle_path = destination / M11_BUNDLE_FILENAME
    program_path.write_bytes(program.data)
    bundle_path.write_bytes(bundle.data)
    return program_path, bundle_path


def _single_reference(reader: StoreReader, obj: SemanticObject, kind: Kind, rule: str) -> SemanticObject:
    matches = tuple(reader.get(cid) for cid in obj.references if reader.get(cid).kind == kind)
    if len(matches) != 1:
        raise ValueError(f"{rule}: expected one {kind.name}, got {len(matches)}")
    return matches[0]


def load_m11_bundle(program_bytes: bytes, build_bytes: bytes) -> M11BootstrapBundle:
    """Load and verify the committed authoritative program plus fixed seed snapshot."""

    program_store = StoreReader(program_bytes)
    build_store = StoreReader(build_bytes)
    verify_store(program_store)
    verify_store(build_store)

    program_root = program_store.get(program_store.root_cid)
    if program_root.kind != Kind.PROGRAM_ROOT:
        raise ValueError("M11 program store root must be PROGRAM_ROOT")
    module = _single_reference(program_store, program_root, Kind.MODULE, "M11-PROGRAM-MODULE")

    snapshot = build_store.get(build_store.root_cid)
    snapshot_view = decode_snapshot(snapshot, build_store.get)
    request = build_store.get(snapshot_view.request_root)
    request_view = decode_request(request, build_store.get)
    package_object = build_store.get(request_view.package_root)
    package_view = decode_package(package_object, build_store.get)
    target = build_store.get(request_view.target_root)
    profile = build_store.get(request_view.profile_root)
    profile_view = decode_profile(profile)
    policy = build_store.get(snapshot_view.trust_policy_root)
    policy_view = decode_trust_policy(policy)

    if package_view.logical_identity != M11_PACKAGE_ID:
        raise ValueError("M11 bootstrap package logical identity mismatch")
    entries = dict(package_view.build_entries)
    if tuple(entries) != (M11_BUILD_ENTRY,):
        raise ValueError("M11 bootstrap bundle must expose exactly the compiler build entry")
    entry = build_store.get(entries[M11_BUILD_ENTRY])
    if entry.kind != Kind.FUNCTION:
        raise ValueError("M11 compiler entry must be a FUNCTION")
    if tuple(package_view.modules) != (module.cid,):
        raise ValueError("M11 bootstrap bundle module must match the authoritative program module")
    if program_store.get(entry.cid) != entry:
        raise ValueError("M11 build entry must be byte-identical to the authoritative program function")
    target_view = decode_native_target(target)
    if (target_view.architecture, target_view.image_format) != (2, 2):
        raise ValueError("M11 bootstrap target must be the fixed WebAssembly target")
    if profile_view.mode != BuildMode.HERMETIC_REPRODUCIBLE or profile_view.optimization != 0 or profile_view.verification != 1:
        raise ValueError("M11 bootstrap build profile mismatch")
    if profile_view.grants:
        raise ValueError("M11 bootstrap profile must grant no ambient capabilities")
    if policy_view.require_package_signatures or policy_view.require_provenance_signature:
        raise ValueError("M11 prototype trust policy must not claim unavailable signatures")
    if snapshot_view.resolver_identity != M11_RESOLVER_IDENTITY:
        raise ValueError("M11 bootstrap resolver identity mismatch")

    return M11BootstrapBundle(
        program_store,
        build_store,
        program_root,
        module,
        entry,
        package_object,
        package_view,
        target,
        profile,
        profile_view,
        policy,
        policy_view,
        request,
        request_view,
        snapshot,
        snapshot_view,
    )


def load_m11_bundle_from_directory(directory: str | Path) -> M11BootstrapBundle:
    directory = Path(directory)
    return load_m11_bundle(
        (directory / M11_PROGRAM_FILENAME).read_bytes(),
        (directory / M11_BUNDLE_FILENAME).read_bytes(),
    )


def build_m11_hosted_subset(bundle: M11BootstrapBundle) -> M11BootstrapBuild:
    """Use the transitional seed compiler to produce the runnable XAX-hosted subset."""

    result = build(
        bundle.build_store,
        bundle.request.cid,
        compiler_identity=BOOTSTRAP_COMPILER_IDENTITY_V1,
    )
    image = compile_wasm_bound_target(bundle.build_store, bundle.entry.cid, bundle.target)
    if image.artifact_bytes != result.artifact:
        raise ValueError("M11 seed build artifact differs from direct fixed-target lowering")
    provenance_view = decode_provenance(result.provenance, bundle.build_store.get)
    if provenance_view.snapshot_root != bundle.snapshot.cid:
        raise ValueError("M11 provenance snapshot root mismatch")
    if provenance_view.request_root != bundle.request.cid:
        raise ValueError("M11 provenance request root mismatch")
    if provenance_view.target_root != bundle.target.cid:
        raise ValueError("M11 provenance target root mismatch")
    if provenance_view.profile_root != bundle.profile.cid:
        raise ValueError("M11 provenance profile root mismatch")
    if provenance_view.compiler_identity != BOOTSTRAP_COMPILER_IDENTITY_V1:
        raise ValueError("M11 provenance seed compiler identity mismatch")
    if provenance_view.lowering_identity != WASM_LOWERING_IDENTITY_V1:
        raise ValueError("M11 provenance lowering identity mismatch")
    return M11BootstrapBuild(result, image, provenance_view)


def seed_execute(bundle: M11BootstrapBundle, arguments: Sequence[int]) -> tuple[int, ...]:
    """Reference seed execution of the authoritative XAX compiler component."""

    return execute(bundle.program_store, bundle.entry.cid, arguments)


def hosted_execute(build_result: M11BootstrapBuild, arguments: Sequence[int], node_executable: str | None = None) -> tuple[int, ...]:
    """Execute the seed-built XAX-hosted compiler component."""

    return run_wasm_isolated(build_result.image, arguments, node_executable)


def compare_m11_vectors(
    bundle: M11BootstrapBundle,
    build_result: M11BootstrapBuild,
    vectors: Iterable[Sequence[int]] = M11_CONFORMANCE_VECTORS,
    *,
    node_executable: str | None = None,
) -> tuple[M11Comparison, ...]:
    comparisons = []
    for vector in vectors:
        arguments = tuple(int(value) for value in vector)
        if len(arguments) != 3:
            raise ValueError("M11 conformance vector must contain selector, lhs, rhs")
        comparisons.append(
            M11Comparison(
                arguments,
                seed_execute(bundle, arguments),
                hosted_execute(build_result, arguments, node_executable),
            )
        )
    return tuple(comparisons)
