"""M14 self-hosting closure implementation and evidence helpers.

Bootstrap labels are evidence claims.  This module provides the canonical M14
hosted semantic-image compiler, recursive-generation execution, and conservative
closure accounting.  Presence of code is never converted into B2-B6 evidence;
callers must execute the evidence path and record the exact generation roots.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from blake3 import blake3

from xax_compiler import (
    Block,
    CompileTimeBudget,
    CompileTimeEvaluator,
    Kind,
    MetaCapability,
    Node,
    OpaqueKind,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    _decode_function_interface,
    _parse_graph,
    function,
    graph_fragment,
    object_with_refs,
    opaque_type,
    verify_store,
    write_store,
)


M14_PROGRAM_FILENAME = "m14_selfhost_compiler.xax"
M14_EVIDENCE_FILENAME = "m14_selfhost_evidence.json"
M14_COMPILER_IDENTITY = b"xax-m14-semantic-image-compiler-v1"
M14_EVALUATOR_IDENTITY = b"xax-m14-meta-evaluator-v1"
M14_VERIFIER_IDENTITY = b"xax-verifier-v1"
M14_CLOSURE_TARGET = b"xax-semantic-image-v1"

M14_REQUIRED_HOSTED_SERVICES = (
    "canonical serializer/store writer",
    "semantic verifier-facing service",
    "target interpretation/code generation",
    "object/image writer and linker",
    "package/build/repository operation",
)


@dataclass(frozen=True)
class M14Definition:
    b1: SemanticObject
    function_ref: SemanticObject
    object_ref: SemanticObject
    bytes_ref: SemanticObject
    verify_graph: SemanticObject
    verify_function: SemanticObject
    encode_graph: SemanticObject
    encode_function: SemanticObject
    link_graph: SemanticObject
    link_function: SemanticObject
    build_graph: SemanticObject
    entry: SemanticObject
    module: SemanticObject
    program_root: SemanticObject

    @property
    def program_objects(self) -> tuple[SemanticObject, ...]:
        return (
            self.b1,
            self.function_ref,
            self.object_ref,
            self.bytes_ref,
            self.verify_graph,
            self.verify_function,
            self.encode_graph,
            self.encode_function,
            self.link_graph,
            self.link_function,
            self.build_graph,
            self.entry,
            self.module,
            self.program_root,
        )


@dataclass(frozen=True)
class M14GenerationVector:
    input_cid: bytes
    generation0_digest: bytes
    generation1_digest: bytes

    @property
    def matches(self) -> bool:
        return self.generation0_digest == self.generation1_digest


@dataclass(frozen=True)
class M14RecursiveEvidence:
    closure_target: bytes
    compiler_root: bytes
    compiler_function: bytes
    generation0_digest: bytes
    generation1_digest: bytes
    generation2_digest: bytes
    generation1_root: bytes
    generation2_root: bytes
    vectors: tuple[M14GenerationVector, ...]
    recursive_self_build_executed: bool
    semantic_generation_equivalence_executed: bool
    deterministic_fixed_point_executed: bool
    hosted_service_closure_executed: bool
    # META operations on the compiler path that the host substrate (Python) executes, by operation name.  Each one is
    # compiler work that is not XAX-hosted, so B5/B6 cannot hold while any remains.
    host_substrate_operations: tuple[str, ...] = ()

    @property
    def b2(self) -> bool:
        return self.recursive_self_build_executed

    @property
    def b3(self) -> bool:
        return self.b2 and self.semantic_generation_equivalence_executed and all(item.matches for item in self.vectors)

    @property
    def b4(self) -> bool:
        return self.b3 and self.deterministic_fixed_point_executed

    @property
    def b5(self) -> bool:
        return self.b4 and self.hosted_service_closure_executed and not self.host_substrate_operations


@dataclass(frozen=True)
class M14ClosureReadiness:
    graph_introspection: bool
    canonical_byte_emission: bool
    verifier_hosted: bool
    target_codegen_hosted: bool
    object_link_hosted: bool
    package_build_hosted: bool
    recursive_self_build_executed: bool
    semantic_generation_equivalence_executed: bool
    deterministic_fixed_point_executed: bool
    bootstrap_independence_proven: bool

    @property
    def b2(self) -> bool:
        return self.recursive_self_build_executed

    @property
    def b3(self) -> bool:
        return self.b2 and self.semantic_generation_equivalence_executed

    @property
    def b4(self) -> bool:
        return self.b3 and self.deterministic_fixed_point_executed

    @property
    def b5(self) -> bool:
        return (
            self.b4
            and self.canonical_byte_emission
            and self.verifier_hosted
            and self.target_codegen_hosted
            and self.object_link_hosted
            and self.package_build_hosted
        )

    @property
    def b6(self) -> bool:
        return self.b5 and self.bootstrap_independence_proven

    @property
    def blockers(self) -> tuple[str, ...]:
        blockers: list[str] = []
        if not self.graph_introspection:
            blockers.append("authoritative function/graph structure is not inspectable by compile-time XAX")
        if not self.canonical_byte_emission:
            blockers.append("compile-time XAX cannot emit arbitrary canonical store/object/artifact bytes")
        if not self.verifier_hosted:
            blockers.append("semantic verifier remains a live host-language service")
        if not self.target_codegen_hosted:
            blockers.append("target lowering/code generation remains a live host-language service")
        if not self.object_link_hosted:
            blockers.append("object/image writing and linking remain live host-language services")
        if not self.package_build_hosted:
            blockers.append("package/build/repository operations remain live host-language services")
        if not self.recursive_self_build_executed:
            blockers.append("no XAX-hosted compiler has executed a recursive build of its authoritative graph")
        if not self.semantic_generation_equivalence_executed:
            blockers.append("no fixed-policy generation equivalence comparison has executed")
        if not self.deterministic_fixed_point_executed:
            blockers.append("no byte-identity or declared canonical-projection fixed point has executed")
        if not self.bootstrap_independence_proven:
            blockers.append("ordinary release/target evolution still requires maintained Python implementation code")
        return tuple(blockers)


def m14_definition() -> M14Definition:
    """Construct the transitional seed projection of the authoritative M14 compiler.

    The committed canonical ``.xax`` artifact is authoritative after generation;
    this constructor is bootstrap material only, matching the M11 seed discipline.
    The declared closure target is a canonical semantic image: verification,
    encoding, finalization, and build orchestration are ordinary XAX functions,
    while graph verification and canonical store encoding remain minimal trusted
    META substrate operations.
    """

    from xax_compiler import bits_type

    b1 = bits_type(1)
    function_ref = opaque_type(OpaqueKind.FUNCTION)
    object_ref = opaque_type(OpaqueKind.OBJECT)
    bytes_ref = opaque_type(OpaqueKind.BYTES)

    verify_graph = graph_fragment(
        (
            Block(
                (object_ref,),
                (
                    Node(
                        Operation.META_VERIFY_SEMANTICS,
                        (ValueRef.parameter(0, 0),),
                        (b1,),
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            ),
        )
    )
    verify_function = function(verify_graph, (object_ref,), (b1,))

    encode_graph = graph_fragment(
        (
            Block(
                (object_ref,),
                (
                    Node(
                        Operation.META_CANONICAL_STORE,
                        (ValueRef.parameter(0, 0),),
                        (bytes_ref,),
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            ),
        )
    )
    encode_function = function(encode_graph, (object_ref,), (bytes_ref,))

    link_graph = graph_fragment(
        (
            Block(
                (bytes_ref,),
                (),
                Terminator.return_((ValueRef.parameter(0, 0),)),
            ),
        )
    )
    link_function = function(link_graph, (bytes_ref,), (bytes_ref,))

    build_graph = graph_fragment(
        (
            Block(
                (function_ref,),
                (
                    Node(
                        Operation.META_MATERIALIZE_PROGRAM,
                        (ValueRef.parameter(0, 0),),
                        (object_ref,),
                    ),
                    Node(
                        Operation.CALL_DIRECT,
                        (ValueRef.node_result(0, 0),),
                        (b1,),
                        entity=verify_function,
                    ),
                    Node(
                        Operation.CALL_DIRECT,
                        (ValueRef.node_result(0, 0),),
                        (bytes_ref,),
                        entity=encode_function,
                    ),
                    Node(
                        Operation.CALL_DIRECT,
                        (ValueRef.node_result(0, 2),),
                        (bytes_ref,),
                        entity=link_function,
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 3),)),
            ),
        )
    )
    entry = function(build_graph, (function_ref,), (bytes_ref,))
    module = object_with_refs(Kind.MODULE, (entry,))
    program_root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return M14Definition(
        b1,
        function_ref,
        object_ref,
        bytes_ref,
        verify_graph,
        verify_function,
        encode_graph,
        encode_function,
        link_graph,
        link_function,
        build_graph,
        entry,
        module,
        program_root,
    )


def create_m14_program_store() -> StoreReader:
    definition = m14_definition()
    reader = StoreReader.from_objects(definition.program_root.cid, definition.program_objects)
    verify_store(reader)
    return reader


def write_m14_program(path: str | Path) -> bytes:
    reader = create_m14_program_store()
    data = reader.canonical_bytes()
    Path(path).write_bytes(data)
    return data


def load_m14_program(data: bytes) -> StoreReader:
    reader = StoreReader(data)
    verify_store(reader)
    _locate_m14_entry(reader)
    return reader


def _locate_m14_entry(reader: StoreReader) -> SemanticObject:
    """Locate the hosted compiler from canonical structure, not a Python graph projection."""

    root = reader.get(reader.root_cid)
    if root.kind != Kind.PROGRAM_ROOT:
        raise ValueError("M14 compiler store root must be a program_root")
    modules = tuple(reader.get(cid) for cid in root.references if reader.get(cid).kind == Kind.MODULE)
    if len(modules) != 1:
        raise ValueError("M14 compiler root must reference exactly one module")
    functions = tuple(reader.get(cid) for cid in modules[0].references if reader.get(cid).kind == Kind.FUNCTION)
    if len(functions) != 1:
        raise ValueError("M14 compiler module must reference exactly one function")
    return functions[0]


def _semantic_image_compile(
    reader: StoreReader,
    root: SemanticObject,
    *,
    evaluator: CompileTimeEvaluator | None = None,
) -> bytes:
    """Execute the authoritative XAX compiler against one semantic root."""

    entry = _locate_m14_entry(reader)
    evaluator = evaluator or CompileTimeEvaluator()
    result = evaluator.evaluate(
        reader,
        entry.cid,
        (root,),
        capabilities=(
            MetaCapability.CONSTRUCT_SEMANTICS,
            MetaCapability.SERIALIZE_SEMANTICS,
            MetaCapability.VERIFY_SEMANTICS,
        ),
        budget=CompileTimeBudget(
            steps=1 << 20,
            call_depth=64,
            memory_bytes=64 << 20,
            semantic_objects=1 << 16,
            graph_nodes=1 << 20,
        ),
        evaluator_identity=M14_EVALUATOR_IDENTITY,
        verifier_identity=M14_VERIFIER_IDENTITY,
    )
    if len(result.values) != 1 or not isinstance(result.values[0], bytes):
        raise ValueError("M14 hosted compiler must return one canonical byte image")
    return result.values[0]


def _hosted_service_closure(reader: StoreReader) -> bool:
    """Check that the live semantic-image path is XAX graph orchestration.

    The entry must call, in order, a verifier-facing service, canonical image
    encoder, and link/finalization service.  Verification and canonical byte
    formation themselves are deliberately trusted META substrate primitives;
    no Python build/codegen/package dispatcher is on this declared target path.
    """

    entry = _locate_m14_entry(reader)
    build_graph_object, _, _ = _decode_function_interface(entry, reader.get)
    build_graph = _parse_graph(build_graph_object, reader.get)
    if len(build_graph.blocks) != 1 or len(build_graph.blocks[0].nodes) != 4:
        return False
    build_nodes = build_graph.blocks[0].nodes
    if build_nodes[0].operation != Operation.META_MATERIALIZE_PROGRAM:
        return False
    call_nodes = build_nodes[1:]
    if any(node.operation != Operation.CALL_DIRECT or node.entity is None for node in call_nodes):
        return False
    verify_function, encode_function, link_function = (node.entity for node in call_nodes)

    verify_graph_object, _, _ = _decode_function_interface(verify_function, reader.get)
    encode_graph_object, _, _ = _decode_function_interface(encode_function, reader.get)
    link_graph_object, _, _ = _decode_function_interface(link_function, reader.get)
    verify_graph = _parse_graph(verify_graph_object, reader.get)
    encode_graph = _parse_graph(encode_graph_object, reader.get)
    link_graph = _parse_graph(link_graph_object, reader.get)
    return (
        len(verify_graph.blocks) == 1
        and tuple(node.operation for node in verify_graph.blocks[0].nodes) == (Operation.META_VERIFY_SEMANTICS,)
        and len(encode_graph.blocks) == 1
        and tuple(node.operation for node in encode_graph.blocks[0].nodes) == (Operation.META_CANONICAL_STORE,)
        and len(link_graph.blocks) == 1
        and not link_graph.blocks[0].nodes
    )


HOST_SUBSTRATE_OPERATIONS = (Operation.META_MATERIALIZE_PROGRAM, Operation.META_VERIFY_SEMANTICS, Operation.META_CANONICAL_STORE)


def _host_substrate_operations(reader: StoreReader) -> tuple[str, ...]:
    """Names of the host-executed META operations in any graph of the compiler store (sorted, deduplicated)."""

    found = set()
    for obj in reader.objects():
        if obj.kind == Kind.GRAPH_FRAGMENT:
            graph = _parse_graph(obj, reader.get)
            found.update(Operation(node.operation).name for block in graph.blocks for node in block.nodes if node.operation in HOST_SUBSTRATE_OPERATIONS)
    return tuple(sorted(found))


def m14_compile_own_generation(reader: StoreReader) -> bytes:
    return _semantic_image_compile(reader, _locate_m14_entry(reader))


def execute_m14_recursive_evidence(
    generation0: StoreReader,
    *,
    vector_cids: Iterable[bytes] | None = None,
) -> M14RecursiveEvidence:
    """Execute B2-B4 evidence for the semantic-image closure target.

    Generation 0 executes the authoritative XAX compiler graph and emits a
    canonical generation-1 store.  Generation 1 is loaded and verified, then
    executes the same authoritative service to emit generation 2.  Equivalence
    vectors are evaluated independently through both generations.
    """

    verify_store(generation0)
    compiler0 = _locate_m14_entry(generation0)
    generation1_bytes = m14_compile_own_generation(generation0)
    generation1 = load_m14_program(generation1_bytes)
    compiler1 = _locate_m14_entry(generation1)
    generation2_bytes = m14_compile_own_generation(generation1)
    generation2 = load_m14_program(generation2_bytes)

    if vector_cids is None:
        vector_cids = tuple(obj.cid for obj in generation0.objects() if obj.kind == Kind.FUNCTION)

    vectors: list[M14GenerationVector] = []
    for cid in vector_cids:
        input0 = generation0.get(cid)
        input1 = generation1.get(cid)
        output0 = _semantic_image_compile(generation0, input0)
        output1 = _semantic_image_compile(generation1, input1)
        vectors.append(M14GenerationVector(cid, blake3(output0).digest(), blake3(output1).digest()))

    recursive = (
        generation1.root_cid == generation0.root_cid
        and compiler1.cid == compiler0.cid
        and generation1_bytes == generation1.canonical_bytes()
    )
    equivalent = bool(vectors) and all(item.matches for item in vectors)
    fixed_point = generation1_bytes == generation2_bytes and generation1.root_cid == generation2.root_cid
    return M14RecursiveEvidence(
        closure_target=M14_CLOSURE_TARGET,
        compiler_root=generation0.root_cid,
        compiler_function=compiler0.cid,
        generation0_digest=blake3(generation0.canonical_bytes()).digest(),
        generation1_digest=blake3(generation1_bytes).digest(),
        generation2_digest=blake3(generation2_bytes).digest(),
        generation1_root=generation1.root_cid,
        generation2_root=generation2.root_cid,
        vectors=tuple(vectors),
        recursive_self_build_executed=recursive,
        semantic_generation_equivalence_executed=equivalent,
        deterministic_fixed_point_executed=fixed_point,
        hosted_service_closure_executed=_hosted_service_closure(generation0) and _hosted_service_closure(generation1),
        host_substrate_operations=_host_substrate_operations(generation0),
    )


def readiness_from_recursive_evidence(evidence: M14RecursiveEvidence) -> M14ClosureReadiness:
    """Combine executed B2-B4 evidence with the currently hosted service surface."""

    base = current_m14_readiness()
    closure, host = evidence.hosted_service_closure_executed, set(evidence.host_substrate_operations)
    return M14ClosureReadiness(
        graph_introspection=base.graph_introspection,
        canonical_byte_emission=base.canonical_byte_emission,
        # Each service is hosted only when the XAX path performs it rather than handing it to a host META primitive.
        verifier_hosted=closure and Operation.META_VERIFY_SEMANTICS.name not in host,
        target_codegen_hosted=closure and Operation.META_CANONICAL_STORE.name not in host,  # semantic-image codegen is encoding
        object_link_hosted=closure,  # the link/finalize step is an XAX graph with no host operation
        package_build_hosted=closure and Operation.META_MATERIALIZE_PROGRAM.name not in host,
        recursive_self_build_executed=evidence.b2,
        semantic_generation_equivalence_executed=evidence.b3,
        deterministic_fixed_point_executed=evidence.b4,
        # B6: no maintained second implementation; every host operation above is maintained Python code.
        bootstrap_independence_proven=closure and not host,
    )


def current_m14_readiness() -> M14ClosureReadiness:
    """Return capability readiness without fabricating unexecuted bootstrap evidence."""

    graph_introspection = (
        OpaqueKind.GRAPH in OpaqueKind
        and MetaCapability.INSPECT_FUNCTION in MetaCapability
        and all(
            operation in Operation
            for operation in (
                Operation.META_FUNCTION_GRAPH,
                Operation.META_GRAPH_BLOCK_COUNT,
                Operation.META_GRAPH_NODE_COUNT,
                Operation.META_GRAPH_NODE_OPERATION,
            )
        )
    )
    canonical_byte_emission = (
        OpaqueKind.OBJECT in OpaqueKind
        and OpaqueKind.BYTES in OpaqueKind
        and MetaCapability.SERIALIZE_SEMANTICS in MetaCapability
        and Operation.META_CANONICAL_STORE in Operation
    )
    return M14ClosureReadiness(
        graph_introspection=graph_introspection,
        canonical_byte_emission=canonical_byte_emission,
        verifier_hosted=False,
        target_codegen_hosted=False,
        object_link_hosted=False,
        package_build_hosted=False,
        recursive_self_build_executed=False,
        semantic_generation_equivalence_executed=False,
        deterministic_fixed_point_executed=False,
        bootstrap_independence_proven=False,
    )


# The canonical XAX store implementing the whole production compiler, once one exists.  None today: the driver, the
# verifier's rejections, store writing, program backends, and build orchestration are Python (S8-S15, ADR-180).
FULL_COMPILER_STORE: Path | None = None

M14_SCOPE = (
    "xax-semantic-image-v1 META wrapper: an XAX graph that materializes, verifies, and canonically encodes a program "
    "through host-executed META primitives; a scoped wrapper fixed point, not whole-compiler self-hosting"
)


def bootstrap_status(evidence: M14RecursiveEvidence) -> dict:
    """The one derivation of B0-B6 (XAX_SPEC.md 16.2) for every declared scope.

    ``m14_selfhost_evidence.json`` and the generated status blocks consume this; nothing else asserts a B level.
    S-step component fixed points are not B milestones (16.5) and are not reported here."""

    if FULL_COMPILER_STORE is not None:
        raise NotImplementedError("derive whole-compiler B levels from executed evidence for FULL_COMPILER_STORE")
    readiness = readiness_from_recursive_evidence(evidence)
    return {
        "derivation_source": "xax_selfhost.bootstrap_status",
        "full_production_compiler": {
            **{f"B{level}": False for level in range(7)},
            "blocker": "no canonical XAX store implements the whole compiler; S9 and later steps are open (ADR-180, ADR-251)",
        },
        "m14_semantic_image_wrapper": {
            "scope": M14_SCOPE,
            "B2": readiness.b2, "B3": readiness.b3, "B4": readiness.b4, "B5": readiness.b5, "B6": readiness.b6,
            "host_substrate_operations": list(evidence.host_substrate_operations),
            "blockers": list(readiness.blockers),
        },
    }
