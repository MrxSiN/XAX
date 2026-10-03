"""Bounded queries and atomic expected-root transactions for the XAX prototype."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from threading import Lock
from typing import Callable

from xax_compiler import (
    store_resolver,
    ATOMIC_OPERATIONS,
    DEFAULT_VERIFIER_IDENTITY,
    AtomicSupport,
    Block,
    Cursor,
    Diagnostic,
    Kind,
    Node,
    Operation,
    Permission,
    ProofCache,
    RealtimeProfile,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    _decode_constant,
    _decode_function_interface,
    _decode_effect_type,
    _decode_opaque_identity_type,
    _decode_opaque_type,
    _decode_pointer_type,
    _decode_resource_type,
    _is_effect,
    _is_memory_effect,
    _is_resource,
    _parse_graph,
    _atomic_node_request,
    analyze_realtime,
    atomic_capability,
    constant,
    decode_native_target,
    decode_bits_width,
    derive_effect_summary,
    fail,
    function,
    graph_fragment,
    object_with_refs,
    uleb,
    verify_object,
    verify_store,
    validate_realtime_profile,
    write_store,
    zigzag,
)
from xax_artifact import (
    BOOTSTRAP_COMPILER_IDENTITY_V1,
    ArtifactProvenanceBinding,
    ArtifactSemanticRange,
    MappableArtifact,
    lowering_identity,
)
from xax_aarch64 import compile_aarch64_bound_target
from xax_accelerator import compile_accelerator_bound_target
from xax_wasm import compile_wasm_bound_target
from xax_x86_64 import compile_native_bound_target


@dataclass(frozen=True)
class NodeView:
    handle: str
    operation: Operation
    operand_count: int
    result_count: int
    constant_value: int | None = None
    classification: str = "authoritative"


@dataclass(frozen=True)
class QueryPage:
    entities: tuple[NodeView, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class ObjectView:
    handle: str
    kind: Kind
    classification: str = "authoritative"


@dataclass(frozen=True)
class ObjectQueryPage:
    entities: tuple[ObjectView, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class FunctionView:
    handle: str
    classification: str = "authoritative"


@dataclass(frozen=True)
class FunctionQueryPage:
    entities: tuple[FunctionView, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class ValueView:
    handle: str
    type_handle: str
    classification: str = "authoritative"


@dataclass(frozen=True)
class ValueQueryPage:
    entities: tuple[ValueView, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class NeighborhoodValue:
    handle: str
    type_handle: str
    relations: tuple[str, ...]
    classification: str = "authoritative"


@dataclass(frozen=True)
class NeighborhoodPage:
    entities: tuple[NeighborhoodValue, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class ExpansionView:
    handle: str
    kind: str
    relation: str
    operation: Operation | None = None
    operand_count: int | None = None
    result_count: int | None = None
    constant_value: int | None = None
    type_handle: str | None = None
    classification: str = "authoritative"


@dataclass(frozen=True)
class ExpansionPage:
    entities: tuple[ExpansionView, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class DiffView:
    handle: str
    change: str
    kind: Kind
    classification: str = "authoritative"


@dataclass(frozen=True)
class DiffPage:
    entities: tuple[DiffView, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class RepairView:
    handle: str
    classification: str = "authoritative"


@dataclass(frozen=True)
class RepairPage:
    entities: tuple[RepairView, ...]
    truncated: bool
    continuation: int | None


@dataclass(frozen=True)
class RootView:
    handle: str
    root: str
    generation: int
    contexts: tuple[tuple[str, object, str], ...]
    classification: str = "authoritative"


@dataclass(frozen=True)
class LayoutView:
    type_handle: str
    target: str | None
    facts: tuple[tuple[str, object], ...]
    classification: str


@dataclass(frozen=True)
class CostView:
    node_handle: str
    target: str | None
    facts: tuple[tuple[str, object, str], ...]


@dataclass(frozen=True)
class AtomicCapabilityView:
    node_handle: str
    target: str | None
    facts: tuple[tuple[str, object, str], ...]


@dataclass(frozen=True)
class RealtimeView:
    function_handle: str
    target: str | None
    facts: tuple[tuple[str, object, str], ...]


@dataclass(frozen=True)
class HandlerEntryView:
    event_kind: int
    target: str
    facts: tuple[tuple[str, object, str], ...]


@dataclass(frozen=True)
class ProofView:
    handle: str
    dependency_handle: str
    facts: tuple[tuple[str, object, str], ...]


@dataclass(frozen=True)
class ProofDependencyBinding:
    subject_kind: str
    subject_cid: bytes
    observed_root: bytes
    verifier_identity: str
    origin_generation: int
    block_index: int | None = None
    node_index: int | None = None
    value: ValueRef | None = None
    valid: bool = True


@dataclass(frozen=True)
class TypeView:
    handle: str
    form: str
    facts: tuple[tuple[str, object], ...]
    classification: str = "authoritative"


@dataclass(frozen=True)
class EffectView:
    node_handle: str
    pure: bool
    domain: str | None
    inputs: tuple[ValueView, ...]
    outputs: tuple[ValueView, ...]
    classification: str = "authoritative"


@dataclass(frozen=True)
class EffectSummaryView:
    function_handle: str
    domains: tuple[tuple[str, int], ...]
    may_return: bool
    may_trap: bool
    classification: str = "derived"


@dataclass(frozen=True)
class EntityView:
    handle: str
    kind: str
    facts: tuple[tuple[str, object], ...] = ()
    classification: str = "authoritative"


@dataclass(frozen=True)
class ArtifactView:
    handle: str | None
    entry_handle: str | None
    format: str | None
    size_bytes: int | None
    entry_offset: int | None
    target: str | None
    identity: str | None
    digest: str | None
    semantic_root: str | None
    compiler_identity: str | None
    lowering_identity: str | None
    classification: str


@dataclass(frozen=True)
class ArtifactRangeView:
    start: int
    end: int
    relation: str
    classification: str = "derived"


@dataclass(frozen=True)
class SemanticMapPage:
    semantic_handle: str
    artifact_handle: str
    artifact_identity: str
    ranges: tuple[ArtifactRangeView, ...]
    truncated: bool
    continuation: int | None
    classification: str


@dataclass(frozen=True)
class ArtifactContributorView:
    handle: str
    kind: str
    start: int
    end: int
    classification: str = "derived"


@dataclass(frozen=True)
class ArtifactMapPage:
    artifact_handle: str
    artifact_identity: str
    offset: int
    length: int
    entities: tuple[ArtifactContributorView, ...]
    truncated: bool
    continuation: int | None
    classification: str


@dataclass(frozen=True)
class SetOperation:
    node: str
    expected: Operation
    value: Operation


@dataclass(frozen=True)
class SetConstant:
    node: str
    expected: int
    value: int


@dataclass(frozen=True)
class ReplaceUse:
    node: str
    operand_index: int
    expected: ValueRef
    value: ValueRef | "TransactionValueRef"

    def __post_init__(self) -> None:
        if self.operand_index < 0:
            raise ValueError("operand index must be nonnegative")


@dataclass(frozen=True)
class DeleteNode:
    node: str
    expected_block: int
    expected_index: int

    def __post_init__(self) -> None:
        if self.expected_block < 0 or self.expected_index < 0:
            raise ValueError("expected containment indices must be nonnegative")


@dataclass(frozen=True)
class TransactionValueRef:
    """Transaction-local reference to one result of an inserted node."""

    insertion: int
    result: int = 0

    def __post_init__(self) -> None:
        if self.insertion < 0 or self.result < 0:
            raise ValueError("transaction-local value indices must be nonnegative")


@dataclass(frozen=True)
class InsertPureNode:
    """Insert one verifier-safe pure node immediately before an existing anchor."""

    node: str
    expected_block: int
    expected_index: int
    local_id: int
    operation: Operation
    operands: tuple[ValueRef | TransactionValueRef, ...]
    result_type: str
    constant_value: int | None = None

    def __post_init__(self) -> None:
        if self.expected_block < 0 or self.expected_index < 0 or self.local_id < 0:
            raise ValueError("insertion indices must be nonnegative")


@dataclass(frozen=True)
class DisconnectEdgeArgument:
    """Remove one existing block-terminator edge argument under exact preconditions."""

    node: str
    expected_block: int
    edge_index: int
    argument_index: int
    expected: ValueRef

    def __post_init__(self) -> None:
        if self.expected_block < 0 or self.edge_index < 0 or self.argument_index < 0:
            raise ValueError("edge-argument indices must be nonnegative")


@dataclass(frozen=True)
class ConnectEdgeArgument:
    """Insert one block-terminator edge argument at an exact position."""

    node: str
    expected_block: int
    edge_index: int
    argument_index: int
    value: ValueRef | TransactionValueRef

    def __post_init__(self) -> None:
        if self.expected_block < 0 or self.edge_index < 0 or self.argument_index < 0:
            raise ValueError("edge-argument indices must be nonnegative")


@dataclass(frozen=True)
class MovePureNode:
    """Move one existing pure node immediately before an exact same-block anchor."""

    node: str
    expected_block: int
    expected_index: int
    destination: str
    expected_destination_block: int
    expected_destination_index: int

    def __post_init__(self) -> None:
        if min(
            self.expected_block,
            self.expected_index,
            self.expected_destination_block,
            self.expected_destination_index,
        ) < 0:
            raise ValueError("move containment indices must be nonnegative")


@dataclass(frozen=True)
class SpecializationArgument:
    parameter: int
    expected_type: str
    value: int

    def __post_init__(self) -> None:
        if self.parameter < 0:
            raise ValueError("specialization parameter index must be nonnegative")


@dataclass(frozen=True)
class SpecializeFunction:
    """Clone one pure standalone function under exact constant arguments."""

    function: str
    arguments: tuple[SpecializationArgument, ...]

    @property
    def node(self) -> str:
        return self.function


@dataclass(frozen=True)
class _ResolvedInsertPureNode:
    node: str
    expected_block: int
    expected_index: int
    local_id: int
    operation: Operation
    operands: tuple[ValueRef | TransactionValueRef, ...]
    result_type_cid: bytes
    constant_value: int | None = None


@dataclass(frozen=True)
class _ResolvedSpecializationArgument:
    parameter: int
    expected_type_cid: bytes
    value: int


@dataclass(frozen=True)
class _ResolvedSpecializeFunction:
    function: str
    arguments: tuple[_ResolvedSpecializationArgument, ...]

    @property
    def node(self) -> str:
        return self.function


Mutation = (
    SetOperation
    | SetConstant
    | ReplaceUse
    | DeleteNode
    | InsertPureNode
    | DisconnectEdgeArgument
    | ConnectEdgeArgument
    | MovePureNode
    | SpecializeFunction
)


@dataclass(frozen=True)
class RootRef:
    generation: int

    def __post_init__(self) -> None:
        if self.generation < 0:
            raise ValueError("root generation must be nonnegative")

    @property
    def handle(self) -> str:
        return f"R0.{self.generation}"


@dataclass(frozen=True)
class Transaction:
    expected_root: bytes | RootRef
    mutations: tuple[Mutation, ...]
    read_set: tuple[str, ...] = ()


@dataclass(frozen=True)
class TransactionResult:
    committed: bool
    root: bytes
    changed_entities: tuple[bytes, ...]
    diagnostic: Diagnostic | None
    transaction_bytes: int
    touched_objects: int
    reused_objects: int
    verified_objects: int

    @property
    def changed_entity(self) -> bytes | None:
        return self.changed_entities[0] if len(self.changed_entities) == 1 else None


@dataclass(frozen=True)
class CandidateVerification:
    verified: bool
    candidate_handle: str | None
    root: bytes
    diagnostic: Diagnostic | None
    transaction_bytes: int
    touched_objects: int
    reused_objects: int
    verified_objects: int


@dataclass(frozen=True)
class CandidateRollback:
    rolled_back: bool
    candidate_handle: str
    root: bytes
    diagnostic: Diagnostic | None


@dataclass(frozen=True)
class _CandidateBinding:
    reader: StoreReader
    base_root: bytes
    generation: int
    verifier_identity: str
    transaction_bytes: int
    touched_objects: int
    reused_objects: int
    verified_objects: int


@dataclass(frozen=True)
class _GenerationSnapshot:
    reader: StoreReader
    root: bytes
    node_bindings: dict[str, tuple[bytes, int, int, int]]
    object_bindings: dict[str, tuple[bytes, int]]
    function_bindings: dict[str, tuple[bytes, int]]
    value_bindings: dict[str, tuple[bytes, ValueRef, int]]
    type_bindings: dict[str, tuple[bytes, int]]


@dataclass
class WorkspaceAccounting:
    queries: int = 0
    entities_exposed: int = 0
    query_bytes: int = 0
    mutations: int = 0
    rejected_transactions: int = 0
    committed_changes: int = 0
    transaction_bytes: int = 0
    verified_objects: int = 0
    candidate_verifications: int = 0
    rejected_candidates: int = 0
    candidate_rollbacks: int = 0
    candidate_transaction_bytes: int = 0
    candidate_verified_objects: int = 0
    proof_cache_entries_written: int = 0
    proof_cache_entries_invalidated: int = 0
    proof_cache_dependency_cids_maintained: int = 0


BOOTSTRAP_VERIFIER_IDENTITY_V1 = DEFAULT_VERIFIER_IDENTITY


class Workspace:
    def __init__(self, reader: StoreReader, target: SemanticObject | None = None):
        verify_store(reader)
        target_description = decode_native_target(target) if target is not None else None
        self._reader = reader
        self._target = target
        self._target_description = target_description
        self._compiler_identity = BOOTSTRAP_COMPILER_IDENTITY_V1
        self._lowering_identity = (
            lowering_identity(target_description.architecture, target_description.image_format)
            if target_description is not None and (target_description.architecture, target_description.image_format) in ((1, 1), (2, 2), (3, 1), (4, 3), (5, 1), (6, 1))
            else None
        )
        self._lock = Lock()
        self.generation = 0
        self.accounting = WorkspaceAccounting()
        self._previous_reader: StoreReader | None = None
        self._previous_root: bytes | None = None
        self._previous_generation = -1
        self._previous_node_bindings: dict[str, tuple[bytes, int, int, int]] = {}
        self._previous_object_bindings: dict[str, tuple[bytes, int]] = {}
        self._previous_function_bindings: dict[str, tuple[bytes, int]] = {}
        self._previous_value_bindings: dict[str, tuple[bytes, ValueRef, int]] = {}
        self._previous_type_bindings: dict[str, tuple[bytes, int]] = {}
        self._verifier_identity = BOOTSTRAP_VERIFIER_IDENTITY_V1
        self._proof_bindings: dict[str, ProofDependencyBinding] = {}
        self._next_proof_handle = 0
        self._candidate_bindings: dict[str, _CandidateBinding] = {}
        self._next_candidate_handle = 0
        self._bind_handles()
        self._history: dict[int, _GenerationSnapshot] = {0: self._snapshot()}

    @property
    def root(self) -> bytes:
        with self._lock:
            return self._reader.root_cid

    @property
    def reader(self) -> StoreReader:
        with self._lock:
            return self._reader

    def _snapshot(self) -> _GenerationSnapshot:
        return _GenerationSnapshot(
            self._reader,
            self._reader.root_cid,
            dict(self._node_bindings),
            dict(self._object_bindings),
            dict(self._function_bindings),
            dict(self._value_bindings),
            dict(self._type_bindings),
        )

    def save(
        self,
        path: str | os.PathLike[str],
        *,
        proof_cache_path: str | os.PathLike[str] | None = None,
    ) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = self._reader.canonical_bytes()
            proof_cache = self._reader.proof_cache
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=f".{destination.name}.", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        if proof_cache_path is not None and proof_cache is not None:
            proof_cache.save(proof_cache_path)

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str],
        target: SemanticObject | None = None,
        *,
        proof_cache_path: str | os.PathLike[str] | None = None,
    ) -> "Workspace":
        proof_cache = None if proof_cache_path is None else ProofCache.load(proof_cache_path)
        return cls(StoreReader(Path(path).read_bytes(), proof_cache=proof_cache), target)

    def _bind_handles(self) -> None:
        objects = tuple(self._reader.objects())
        functions = sorted((obj.cid for obj in objects if obj.kind == Kind.FUNCTION))
        types = sorted((obj.cid for obj in objects if obj.kind == Kind.TYPE))
        self._function_handles = {cid: f"F{index}" for index, cid in enumerate(functions)}
        self._type_handles = {cid: f"T{index}" for index, cid in enumerate(types)}
        self._object_handles = {obj.cid: f"E{index}" for index, obj in enumerate(sorted(objects, key=lambda obj: obj.cid))}
        # ponytail: rebuild per committed root; maintain incrementally only if profiling justifies it.
        users: dict[bytes, list[bytes]] = {obj.cid: [] for obj in objects}
        for obj in objects:
            for reference in obj.references:
                users[reference].append(obj.cid)
        self._users = {cid: tuple(sorted(cids)) for cid, cids in users.items()}
        resolve = store_resolver(self._reader)
        callees = {}
        callers: dict[bytes, list[bytes]] = {cid: [] for cid in functions}
        for function_cid in functions:
            graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
            graph = _parse_graph(graph_object, resolve)
            direct = tuple(
                sorted(
                    {
                        node.entity.cid
                        for block in graph.blocks
                        for node in block.nodes
                        if node.operation == Operation.CALL_DIRECT
                    }
                )
            )
            callees[function_cid] = direct
            for callee in direct:
                callers[callee].append(function_cid)
        self._callees = callees
        self._callers = {cid: tuple(sorted(cids)) for cid, cids in callers.items()}
        self._node_bindings: dict[str, tuple[bytes, int, int, int]] = {}
        self._object_bindings: dict[str, tuple[bytes, int]] = {}
        self._function_bindings: dict[str, tuple[bytes, int]] = {}
        self._value_bindings: dict[str, tuple[bytes, ValueRef, int]] = {}
        self._type_bindings: dict[str, tuple[bytes, int]] = {}
        self._artifact_bindings: dict[str, tuple[MappableArtifact, bytes, int, ArtifactProvenanceBinding]] = {}

    def _artifact_binding_current(
        self, binding: tuple[MappableArtifact, bytes, int, ArtifactProvenanceBinding]
    ) -> bool:
        image, _, generation, provenance = binding
        target = self._target
        return (
            generation == self.generation
            and target is not None
            and self._lowering_identity is not None
            and provenance.matches(
                self._reader.root_cid,
                target.cid,
                self._compiler_identity,
                self._lowering_identity,
                image.artifact_bytes,
                image.semantic_ranges,
            )
        )

    @staticmethod
    def _proof_subject_present(reader: StoreReader, binding: ProofDependencyBinding) -> bool:
        if not binding.valid:
            return False
        if binding.subject_kind == "root":
            return reader.root_cid == binding.subject_cid
        return any(obj.cid == binding.subject_cid for obj in reader.objects())

    def _proof_binding_current(self, binding: ProofDependencyBinding) -> bool:
        return (
            binding.valid
            and binding.verifier_identity == self._verifier_identity
            and self._proof_subject_present(self._reader, binding)
        )

    def _invalidate_changed_proofs(self, candidate: StoreReader) -> None:
        for handle, binding in tuple(self._proof_bindings.items()):
            if binding.valid and (
                binding.verifier_identity != self._verifier_identity
                or not self._proof_subject_present(candidate, binding)
            ):
                self._proof_bindings[handle] = replace(binding, valid=False)

    def _require_artifact_binding(
        self, artifact_handle: str
    ) -> tuple[MappableArtifact, bytes, int, ArtifactProvenanceBinding]:
        binding = self._artifact_bindings.get(artifact_handle)
        if binding is None or binding[2] != self.generation:
            fail("XAX.WORKSPACE.HANDLE", artifact_handle, "WORKSPACE-HANDLE-GENERATION", self.generation, "unbound or stale")
        if not self._artifact_binding_current(binding):
            fail(
                "XAX.WORKSPACE.ARTIFACT_STALE",
                artifact_handle,
                "WORKSPACE-ARTIFACT-DEPENDENCIES",
                binding[3].identity.hex(),
                "dependency changed",
            )
        return binding

    def _account_query(self, response: object, entities: int) -> None:
        self.accounting.queries += 1
        self.accounting.entities_exposed += entities
        self.accounting.query_bytes += _query_size(response)

    @staticmethod
    def _validate_byte_budget(byte_budget: int | None) -> None:
        if byte_budget is not None and byte_budget < 1:
            raise ValueError("response byte budget must be positive")

    @staticmethod
    def _reject_response_budget(query: str, byte_budget: int, required_bytes: int) -> None:
        fail(
            "XAX.WORKSPACE.RESPONSE_BUDGET",
            query,
            "WORKSPACE-RESPONSE-BYTES",
            {"at_most": byte_budget},
            {"required": required_bytes},
        )

    def _enforce_response_budget(self, query: str, response: object, byte_budget: int | None) -> object:
        self._validate_byte_budget(byte_budget)
        if byte_budget is None:
            return response
        size = _query_size(response)
        if size > byte_budget:
            self._reject_response_budget(query, byte_budget, size)
        return response

    def _fit_page_budget(
        self,
        query: str,
        response: object,
        field: str,
        start: int,
        byte_budget: int | None,
    ) -> object:
        self._validate_byte_budget(byte_budget)
        if byte_budget is None:
            return response
        if _query_size(response) <= byte_budget:
            return response
        items = tuple(getattr(response, field))
        if not items or len(items) == 1:
            self._reject_response_budget(query, byte_budget, _query_size(response))
        # Keep the largest prefix that both fits and makes positive pagination progress.
        for count in range(len(items) - 1, 0, -1):
            candidate = replace(
                response,
                **{field: items[:count], "truncated": True, "continuation": start + count},
            )
            if _query_size(candidate) <= byte_budget:
                return candidate
        minimum = replace(
            response,
            **{field: items[:1], "truncated": True, "continuation": start + 1},
        )
        self._reject_response_budget(query, byte_budget, _query_size(minimum))

    def function_nodes(self, function_cid: bytes, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> QueryPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            reader = self._reader
            generation = self.generation
        resolve = store_resolver(reader)
        function_object = resolve(function_cid)
        if function_object.kind != Kind.FUNCTION:
            fail("XAX.WORKSPACE.ENTITY", function_cid.hex(), "WORKSPACE-FUNCTION", Kind.FUNCTION.name, function_object.kind.name)
        graph_object, _, _ = _decode_function_interface(function_object, resolve)
        graph = _parse_graph(graph_object, resolve)
        handle = self._function_handles[function_cid]
        all_nodes = []
        for block_index, block in enumerate(graph.blocks):
            for node_index, node in enumerate(block.nodes):
                value = _decode_constant(node.entity, resolve)[1] if node.operation == Operation.CONSTANT else None
                all_nodes.append(
                    NodeView(
                        f"{handle}.B{block_index}.N{node_index}",
                        Operation(node.operation),
                        len(node.operands),
                        len(node.results),
                        value,
                    )
                )
        page = tuple(all_nodes[continuation:continuation + limit])
        end = continuation + len(page)
        response = QueryPage(page, end < len(all_nodes), end if end < len(all_nodes) else None)
        response = self._fit_page_budget("function_nodes", response, "entities", continuation, byte_budget)
        page = response.entities
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", handle, "WORKSPACE-GENERATION", generation, self.generation)
            for entity in page:
                parts = entity.handle.split(".")
                self._node_bindings[entity.handle] = (function_cid, int(parts[1][1:]), int(parts[2][1:]), generation)
            self._account_query(response, len(page))
        return response

    def users(self, entity_cid: bytes, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> ObjectQueryPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            generation = self.generation
            if entity_cid not in self._users:
                fail("XAX.WORKSPACE.ENTITY", entity_cid.hex(), "WORKSPACE-ENTITY-EXISTS", "stored object", "missing")
            user_cids = self._users[entity_cid]
            page_cids = user_cids[continuation:continuation + limit]
            page = tuple(ObjectView(self._object_handles[cid], self._reader.get(cid).kind) for cid in page_cids)
            end = continuation + len(page)
            response = ObjectQueryPage(page, end < len(user_cids), end if end < len(user_cids) else None)
            response = self._fit_page_budget("users", response, "entities", continuation, byte_budget)
            page = response.entities
            page_cids = page_cids[:len(page)]
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", entity_cid.hex(), "WORKSPACE-GENERATION", generation, self.generation)
            for cid, entity in zip(page_cids, page):
                self._object_bindings[entity.handle] = (cid, generation)
            self._account_query(response, len(page))
        return response

    def invalidate(self, handle: str, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> ObjectQueryPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            generation = self.generation
            function_binding = self._function_bindings.get(handle)
            object_binding = self._object_bindings.get(handle)
            if function_binding is not None and function_binding[1] == generation:
                entity_cid = function_binding[0]
            elif object_binding is not None and object_binding[1] == generation:
                entity_cid = object_binding[0]
            else:
                fail("XAX.WORKSPACE.HANDLE", handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
            reader = self._reader
            users = self._users
            object_handles = self._object_handles
        affected = set()
        pending = list(users[entity_cid])
        while pending:
            cid = pending.pop()
            if cid in affected:
                continue
            affected.add(cid)
            pending.extend(users[cid])
        ordered = tuple(sorted(affected))
        page_cids = ordered[continuation:continuation + limit]
        page = tuple(ObjectView(object_handles[cid], reader.get(cid).kind) for cid in page_cids)
        end = continuation + len(page)
        response = ObjectQueryPage(page, end < len(ordered), end if end < len(ordered) else None)
        response = self._fit_page_budget("invalidate", response, "entities", continuation, byte_budget)
        page = response.entities
        page_cids = page_cids[:len(page)]
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", handle, "WORKSPACE-GENERATION", generation, self.generation)
            for cid, entity in zip(page_cids, page):
                self._object_bindings[entity.handle] = (cid, generation)
            self._account_query(response, len(page))
        return response

    def diff(self, from_generation: int, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> DiffPage:
        if limit < 1 or continuation < 0 or from_generation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            generation = self.generation
            snapshot = self._history.get(from_generation)
            current = self._reader
            if snapshot is None or from_generation >= generation:
                fail("XAX.WORKSPACE.DIFF_BASE", "R0", "WORKSPACE-DIFF-GENERATION", f"0..{generation - 1}", from_generation)
            previous = snapshot.reader
        previous_objects = {obj.cid: obj for obj in previous.objects()}
        current_objects = {obj.cid: obj for obj in current.objects()}
        changes = tuple(("removed", cid, previous_objects[cid].kind) for cid in sorted(previous_objects.keys() - current_objects.keys())) + tuple(
            ("added", cid, current_objects[cid].kind) for cid in sorted(current_objects.keys() - previous_objects.keys())
        )
        page_items = changes[continuation:continuation + limit]
        page = tuple(DiffView(f"D{generation}.{continuation + index}", change, kind) for index, (change, _, kind) in enumerate(page_items))
        end = continuation + len(page)
        response = DiffPage(page, end < len(changes), end if end < len(changes) else None)
        response = self._fit_page_budget("diff", response, "entities", continuation, byte_budget)
        page = response.entities
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", "R0", "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(response, len(page))
        return response

    def repair_neighborhood(self, diagnostic: Diagnostic, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> RepairPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        handles = tuple(dict.fromkeys(diagnostic.repair_neighborhood))
        page = tuple(RepairView(handle) for handle in handles[continuation:continuation + limit])
        end = continuation + len(page)
        response = RepairPage(page, end < len(handles), end if end < len(handles) else None)
        response = self._fit_page_budget("repair_neighborhood", response, "entities", continuation, byte_budget)
        page = response.entities
        with self._lock:
            self._account_query(response, len(page))
        return response

    def root_query(self, *, byte_budget: int | None = None) -> RootView:
        with self._lock:
            target = self._target.cid.hex() if self._target is not None else None
            response = RootView(
                "R0",
                self._reader.root_cid.hex(),
                self.generation,
                (("target", target, "authoritative" if target else "unavailable"), ("platform", None, "unavailable"), ("configuration", None, "unavailable")),
            )
            response = self._enforce_response_budget("root_query", response, byte_budget)
            self._account_query(response, 1)
            return response

    def layout(self, type_handle: str, *, byte_budget: int | None = None) -> LayoutView:
        with self._lock:
            binding = self._type_bindings.get(type_handle)
            generation = self.generation
            reader = self._reader
            target = self._target
            description = self._target_description
            if binding is None or binding[1] != generation:
                fail("XAX.WORKSPACE.HANDLE", type_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
        facts: tuple[tuple[str, object], ...] = ()
        classification = "unavailable"
        if description is not None:
            type_object = reader.get(binding[0])
            form = Cursor(type_object.body, type_object.cid.hex()).uleb()
            if form == 1:
                width = decode_bits_width(type_object)
                if width in (8, 16, 32, 64):
                    size = width // 8
                    facts = (("size_bits", width), ("size_bytes", size), ("alignment_bytes", min(size, description.word_bits // 8)))
                    classification = "derived"
            elif form == 2:
                # ponytail: current native profiles use natural pointer alignment; package the rule before adding arbitrary targets.
                size = description.pointer_bits // 8
                facts = (("size_bits", description.pointer_bits), ("size_bytes", size), ("alignment_bytes", size))
                classification = "derived"
        response = LayoutView(type_handle, target.cid.hex() if target is not None else None, facts, classification)
        response = self._enforce_response_budget("layout", response, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", type_handle, "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(response, 1)
        return response

    def artifact(self, function_cid: bytes, *, byte_budget: int | None = None) -> ArtifactView:
        with self._lock:
            reader = self._reader
            target = self._target
            description = self._target_description
            generation = self.generation
            function_handle = self._function_handles.get(function_cid)
        if function_handle is None:
            fail("XAX.WORKSPACE.ENTITY", function_cid.hex(), "WORKSPACE-FUNCTION", Kind.FUNCTION.name, "missing")
        if target is None or description is None or (description.architecture, description.image_format) not in ((1, 1), (2, 2), (3, 1), (4, 3), (5, 1), (6, 1)):
            response = ArtifactView(
                None,
                function_handle,
                None,
                None,
                None,
                target.cid.hex() if target is not None else None,
                None,
                None,
                None,
                None,
                None,
                "unavailable",
            )
            response = self._enforce_response_budget("artifact", response, byte_budget)
            with self._lock:
                if generation != self.generation:
                    fail("XAX.WORKSPACE.STALE_QUERY", function_handle, "WORKSPACE-GENERATION", generation, self.generation)
                self._function_bindings[function_handle] = (function_cid, generation)
                self._account_query(response, 0)
            return response
        if description.architecture == 1:
            image: MappableArtifact = compile_native_bound_target(reader, function_cid, target)
        elif description.architecture == 2:
            image = compile_wasm_bound_target(reader, function_cid, target)
        elif description.architecture == 3:
            image = compile_aarch64_bound_target(reader, function_cid, target)
        elif description.architecture == 6:
            from xax_riscv64 import compile_riscv64_bound_target

            image = compile_riscv64_bound_target(reader, function_cid, target)
        elif description.architecture == 5:
            from xax_jvm import compile_jvm_bound_target

            image = compile_jvm_bound_target(reader, function_cid, target)
        else:
            image = compile_accelerator_bound_target(reader, function_cid, target)
        if self._lowering_identity is None:
            fail("XAX.WORKSPACE.ARTIFACT", function_handle, "WORKSPACE-LOWERING-IDENTITY", "versioned lowering identity", "unavailable")
        provenance = ArtifactProvenanceBinding.bind(
            reader.root_cid,
            target.cid,
            self._compiler_identity,
            self._lowering_identity,
            image.artifact_bytes,
            image.semantic_ranges,
        )
        artifact_handle = f"A{generation}.{function_handle[1:]}"
        response = ArtifactView(
            artifact_handle,
            function_handle,
            description.identity.decode("ascii", "backslashreplace"),
            len(image.artifact_bytes),
            image.entry_offset,
            target.cid.hex(),
            provenance.identity.hex(),
            provenance.artifact_digest.hex(),
            f"R0.{generation}",
            provenance.compiler_identity.hex(),
            provenance.lowering_identity.hex(),
            "derived",
        )
        response = self._enforce_response_budget("artifact", response, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", artifact_handle, "WORKSPACE-GENERATION", generation, self.generation)
            if reader.root_cid != self._reader.root_cid or not provenance.matches(
                self._reader.root_cid,
                target.cid,
                self._compiler_identity,
                self._lowering_identity,
                image.artifact_bytes,
                image.semantic_ranges,
            ):
                fail("XAX.WORKSPACE.ARTIFACT_STALE", artifact_handle, "WORKSPACE-ARTIFACT-DEPENDENCIES", provenance.identity.hex(), "dependency changed")
            self._artifact_bindings[artifact_handle] = (image, function_cid, generation, provenance)
            self._function_bindings[function_handle] = (function_cid, generation)
            self._account_query(response, 1)
        return response

    def map_semantic(self, semantic_handle: str, artifact_handle: str, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> SemanticMapPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            generation = self.generation
            artifact_binding = self._require_artifact_binding(artifact_handle)
            image = artifact_binding[0]
            provenance = artifact_binding[3]
            node_binding = self._node_bindings.get(semantic_handle)
            function_binding = self._function_bindings.get(semantic_handle)
            object_binding = self._object_bindings.get(semantic_handle)
            value_binding = self._value_bindings.get(semantic_handle)
            type_binding = self._type_bindings.get(semantic_handle)
            if semantic_handle == "R0":
                semantic_key: tuple[str, bytes | None, int | None, int | None] | None = None
                bound = True
            elif node_binding is not None and node_binding[3] == generation:
                semantic_key = ("node", node_binding[0], node_binding[1], node_binding[2])
                bound = True
            elif function_binding is not None and function_binding[1] == generation:
                semantic_key = ("function", function_binding[0], None, None)
                bound = True
            elif object_binding is not None and object_binding[1] == generation:
                object_cid = object_binding[0]
                if self._reader.get(object_cid).kind == Kind.FUNCTION:
                    semantic_key = ("function", object_cid, None, None)
                else:
                    semantic_key = None
                bound = True
            elif value_binding is not None and value_binding[2] == generation:
                semantic_key = None
                bound = True
            elif type_binding is not None and type_binding[1] == generation:
                semantic_key = None
                bound = True
            else:
                semantic_key = None
                bound = False
            if not bound:
                fail("XAX.WORKSPACE.HANDLE", semantic_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
        ranges: tuple[ArtifactSemanticRange, ...]
        relation = "unavailable"
        if semantic_key is None:
            ranges = ()
        elif semantic_key[0] == "function":
            ranges = tuple(
                item for item in image.semantic_ranges
                if item.function_cid == semantic_key[1] and item.block_index is None and item.node_index is None
            )
            relation = "function"
        else:
            ranges = tuple(
                item for item in image.semantic_ranges
                if item.function_cid == semantic_key[1] and item.block_index == semantic_key[2] and item.node_index == semantic_key[3]
            )
            relation = "node"
        page_ranges = ranges[continuation:continuation + limit]
        page = tuple(ArtifactRangeView(item.start, item.end, relation) for item in page_ranges)
        end = continuation + len(page)
        classification = "derived" if ranges else "unavailable"
        response = SemanticMapPage(
            semantic_handle,
            artifact_handle,
            provenance.identity.hex(),
            page,
            end < len(ranges),
            end if end < len(ranges) else None,
            classification,
        )
        response = self._fit_page_budget("map_semantic", response, "ranges", continuation, byte_budget)
        page = response.ranges
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", artifact_handle, "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(response, len(page))
        return response

    def map_artifact(self, artifact_handle: str, offset: int, length: int, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> ArtifactMapPage:
        if offset < 0 or length < 1 or limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            generation = self.generation
            artifact_binding = self._require_artifact_binding(artifact_handle)
            image = artifact_binding[0]
            provenance = artifact_binding[3]
            if offset + length > len(image.artifact_bytes):
                fail("XAX.WORKSPACE.ARTIFACT_RANGE", artifact_handle, "WORKSPACE-ARTIFACT-RANGE", [0, len(image.artifact_bytes)], [offset, offset + length])
            function_handles = self._function_handles
        query_end = offset + length
        overlapping = tuple(
            item for item in image.semantic_ranges
            if item.start < query_end and offset < item.end
        )
        contributors: list[tuple[ArtifactSemanticRange, ArtifactContributorView]] = []
        for item in overlapping:
            function_handle = function_handles[item.function_cid]
            if item.block_index is None:
                handle = function_handle
                kind = "function"
            else:
                handle = f"{function_handle}.B{item.block_index}.N{item.node_index}"
                kind = "node"
            contributors.append((item, ArtifactContributorView(handle, kind, item.start, item.end)))
        contributors.sort(key=lambda pair: (pair[0].start, pair[0].end, pair[1].kind, pair[1].handle))
        page_pairs = tuple(contributors[continuation:continuation + limit])
        page = tuple(view for _, view in page_pairs)
        end = continuation + len(page)
        response = ArtifactMapPage(
            artifact_handle,
            provenance.identity.hex(),
            offset,
            length,
            page,
            end < len(contributors),
            end if end < len(contributors) else None,
            "derived" if contributors else "unavailable",
        )
        response = self._fit_page_budget("map_artifact", response, "entities", continuation, byte_budget)
        page = response.entities
        page_pairs = page_pairs[:len(page)]
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", artifact_handle, "WORKSPACE-GENERATION", generation, self.generation)
            for item, view in page_pairs:
                if view.kind == "function":
                    self._function_bindings[view.handle] = (item.function_cid, generation)
                else:
                    self._node_bindings[view.handle] = (item.function_cid, item.block_index, item.node_index, generation)
            self._account_query(response, len(page))
        return response

    def cost(self, node_handle: str, *, byte_budget: int | None = None) -> CostView:
        with self._lock:
            binding = self._node_bindings.get(node_handle)
            generation = self.generation
            reader = self._reader
            target = self._target
            description = self._target_description
            if binding is None or binding[3] != generation:
                fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
        function_cid, block_index, node_index, _ = binding
        resolve = store_resolver(reader)
        graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        try:
            operation = Operation(graph.blocks[block_index].nodes[node_index].operation)
        except IndexError:
            fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-NODE-EXISTS", "bound node", "missing")
        supported = int(operation) in description.supported_operations if description is not None else None
        support_classification = "authoritative" if description is not None else "unavailable"
        response = CostView(
            node_handle,
            target.cid.hex() if target is not None else None,
            (
                ("operation", operation.name.lower(), "authoritative"),
                ("supported", supported, support_classification),
                ("instruction_cost", None, "unavailable"),
                ("latency", None, "unavailable"),
                ("code_bytes", None, "unavailable"),
            ),
        )
        response = self._enforce_response_budget("cost", response, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", node_handle, "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(response, 1)
        return response

    def atomic_capability(self, node_handle: str, *, byte_budget: int | None = None) -> AtomicCapabilityView:
        with self._lock:
            binding = self._node_bindings.get(node_handle)
            generation = self.generation
            reader = self._reader
            target = self._target
            description = self._target_description
            if binding is None or binding[3] != generation:
                fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
        function_cid, block_index, node_index, _ = binding
        resolve = store_resolver(reader)
        graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        try:
            node = graph.blocks[block_index].nodes[node_index]
        except IndexError:
            fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-NODE-EXISTS", "bound node", "missing")
        if node.operation not in ATOMIC_OPERATIONS:
            fail("XAX.WORKSPACE.ATOMIC", node_handle, "WORKSPACE-ATOMIC-NODE", "atomic operation", Operation(node.operation).name.lower())
        if description is None:
            facts = (
                ("support", None, "unavailable"),
                ("lock_free", None, "unavailable"),
                ("retry_behavior", None, "unavailable"),
                ("required_alignment", None, "unavailable"),
                ("latency_bound", None, "unavailable"),
            )
        else:
            capability = atomic_capability(description, *_atomic_node_request(node, resolve))
            facts = (
                ("support", capability.support.name.lower(), "authoritative"),
                ("lock_free", capability.lock_free.name.lower(), "authoritative"),
                ("retry_behavior", capability.retry_behavior.name.lower(), "authoritative"),
                ("required_alignment", capability.required_alignment, "authoritative"),
                ("latency_bound", capability.latency_bound, "unavailable" if capability.latency_bound is None else "authoritative"),
            )
        response = AtomicCapabilityView(node_handle, None if target is None else target.cid.hex(), facts)
        response = self._enforce_response_budget("atomic_capability", response, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", node_handle, "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(response, 1)
        return response

    def realtime(
        self,
        function_handle: str,
        profile: RealtimeProfile | None = None,
        *,
        byte_budget: int | None = None,
    ) -> RealtimeView:
        with self._lock:
            binding = self._function_bindings.get(function_handle)
            node_binding = self._node_bindings.get(function_handle)
            generation = self.generation
            reader = self._reader
            target = self._target
            if binding is None and node_binding is not None and node_binding[3] == generation:
                binding = (node_binding[0], generation)
            if binding is None or binding[1] != generation:
                fail("XAX.WORKSPACE.HANDLE", function_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
        properties = analyze_realtime(reader, binding[0], target)
        if profile is not None:
            validate_realtime_profile(properties, profile)
        facts = (
            ("may_block", properties.may_block, "derived"),
            ("allocation_bound", properties.allocation_bound, "derived" if properties.allocation_bound is not None else "unknown"),
            ("stack_upper_bound", properties.stack_upper_bound, "derived" if properties.stack_upper_bound is not None else "unknown"),
            ("recursion_bound", properties.recursion_bound, "derived" if properties.recursion_bound is not None else "unknown"),
            ("control_bound", properties.control_bound, "derived" if properties.control_bound is not None else "unknown"),
            ("retry_bound", properties.retry_bound, "derived" if properties.retry_bound is not None else "unknown"),
            ("progress", properties.progress, "derived" if properties.progress != "unknown" else "unknown"),
            ("runtime_assists", properties.runtime_assists, "derived"),
            ("scheduler_interaction", properties.scheduler_interaction, "derived"),
            ("kernel_interaction", properties.kernel_interaction, "derived"),
            ("dynamic_initialization", properties.dynamic_initialization, "derived"),
            ("interrupt_mask_bound", properties.interrupt_mask_bound, "unknown"),
            ("target_timing_bound", properties.target_timing_bound, "unknown"),
            ("target_cost_estimate", properties.target_cost_estimate, "unavailable"),
            ("effect_domains", tuple(domain.name.lower() for domain in properties.effect_domains), "derived"),
            ("unsupported_operations", properties.unsupported_operations, "derived"),
        )
        response = RealtimeView(function_handle, None if target is None else target.cid.hex(), facts)
        response = self._enforce_response_budget("realtime", response, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", function_handle, "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(response, 1)
        return response

    def handler_entry(self, event_kind: int, *, byte_budget: int | None = None) -> HandlerEntryView:
        with self._lock:
            generation = self.generation
            target = self._target
            description = self._target_description
            if target is None or description is None:
                fail("XAX.WORKSPACE.HANDLER", "handler", "WORKSPACE-TARGET-BOUND", "target package", "unavailable")
        contract = next((entry for entry in description.handler_entries if entry.event_kind == event_kind), None)
        if contract is None:
            fail("XAX.WORKSPACE.HANDLER", target.cid.hex(), "WORKSPACE-HANDLER-EVENT", [entry.event_kind for entry in description.handler_entries], event_kind)
        response = HandlerEntryView(
            event_kind,
            target.cid.hex(),
            (
                ("entry_abi", contract.entry_abi, "authoritative"),
                ("privilege", contract.privilege, "authoritative"),
                ("priority", contract.priority, "authoritative"),
                ("nesting_policy", contract.nesting_policy, "authoritative"),
                ("reentrancy_policy", contract.reentrancy_policy, "authoritative"),
                ("saved_machine_state", contract.saved_machine_state, "authoritative"),
                ("allowed_effect_domains", tuple(domain.name.lower() for domain in contract.allowed_effect_domains), "authoritative"),
                ("stack_bound", contract.stack_bound, "authoritative"),
                ("return_contract", contract.return_contract, "authoritative"),
            ),
        )
        response = self._enforce_response_budget("handler_entry", response, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", "handler", "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(response, 1)
        return response

    def proof(self, handle: str, *, byte_budget: int | None = None) -> ProofView:
        with self._lock:
            generation = self.generation
            root = self._reader.root_cid
            node = self._node_bindings.get(handle)
            entity = self._object_bindings.get(handle)
            function = self._function_bindings.get(handle)
            value = self._value_bindings.get(handle)
            type_ = self._type_bindings.get(handle)
            if handle == "R0":
                subject_kind = "root"
                subject_cid = root
                block_index = node_index = None
                value_ref = None
                freshness = "root+verifier"
            elif node is not None and node[3] == generation:
                subject_kind = "node"
                subject_cid, block_index, node_index, _ = node
                value_ref = None
                freshness = "subject+verifier"
            elif function is not None and function[1] == generation:
                subject_kind = "function"
                subject_cid = function[0]
                block_index = node_index = None
                value_ref = None
                freshness = "subject+verifier"
            elif entity is not None and entity[1] == generation:
                subject_kind = "object"
                subject_cid = entity[0]
                block_index = node_index = None
                value_ref = None
                freshness = "subject+verifier"
            elif value is not None and value[2] == generation:
                subject_kind = "value"
                subject_cid, value_ref, _ = value
                block_index = value_ref.block
                node_index = value_ref.index if value_ref.tag == 1 else None
                freshness = "subject+verifier"
            elif type_ is not None and type_[1] == generation:
                subject_kind = "type"
                subject_cid = type_[0]
                block_index = node_index = None
                value_ref = None
                freshness = "subject+verifier"
            else:
                fail("XAX.WORKSPACE.HANDLE", handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")

            dependency_handle = f"P{self._next_proof_handle}.{generation}"
            binding = ProofDependencyBinding(
                subject_kind,
                subject_cid,
                root,
                self._verifier_identity,
                generation,
                block_index,
                node_index,
                value_ref,
            )
            response = ProofView(
                handle,
                dependency_handle,
                (
                    ("root", f"R0.{generation}", "authoritative"),
                    ("verified", True, "authoritative"),
                    ("verifier", self._verifier_identity, "authoritative"),
                    ("freshness", freshness, "authoritative"),
                    ("proof_dependency", dependency_handle, "derived"),
                    ("proof_artifact", None, "unavailable"),
                ),
            )
            response = self._enforce_response_budget("proof", response, byte_budget)
            self._proof_bindings[dependency_handle] = binding
            self._next_proof_handle += 1
            self._account_query(response, 1)
            return response

    def callers(self, function_cid: bytes, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> FunctionQueryPage:
        return self._function_page(function_cid, self._callers, limit, continuation, byte_budget=byte_budget)

    def callees(self, function_cid: bytes, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> FunctionQueryPage:
        return self._function_page(function_cid, self._callees, limit, continuation, byte_budget=byte_budget)

    def operands(self, node_handle: str, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> ValueQueryPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            binding = self._node_bindings.get(node_handle)
            generation = self.generation
            reader = self._reader
            if binding is None or binding[3] != generation:
                fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
            function_handle = self._function_handles[binding[0]]
            type_handles = self._type_handles
        function_cid, block_index, node_index, _ = binding
        resolve = store_resolver(reader)
        graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        try:
            node = graph.blocks[block_index].nodes[node_index]
        except IndexError:
            fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-NODE-EXISTS", "bound node", "missing")
        all_operands = tuple(
            ValueView(_value_handle(function_handle, operand), type_handles[type_cid])
            for operand, type_cid in zip(node.operands, node.operand_types)
        )
        page = all_operands[continuation:continuation + limit]
        end = continuation + len(page)
        response = ValueQueryPage(page, end < len(all_operands), end if end < len(all_operands) else None)
        response = self._fit_page_budget("operands", response, "entities", continuation, byte_budget)
        page = response.entities
        end = continuation + len(page)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", node_handle, "WORKSPACE-GENERATION", generation, self.generation)
            for offset, (operand, entity) in enumerate(zip(node.operands[continuation:end], page)):
                self._value_bindings[entity.handle] = (function_cid, operand, generation)
                type_cid = node.operand_types[continuation + offset]
                self._type_bindings[entity.type_handle] = (type_cid, generation)
            self._account_query(response, len(page))
        return response

    def neighborhood(self, node_handle: str, limit: int, continuation: int = 0, *, byte_budget: int | None = None) -> NeighborhoodPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            binding = self._node_bindings.get(node_handle)
            generation = self.generation
            reader = self._reader
            if binding is None or binding[3] != generation:
                fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
            function_handle = self._function_handles[binding[0]]
            type_handles = self._type_handles
        function_cid, block_index, node_index, _ = binding
        resolve = store_resolver(reader)
        graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        try:
            node = graph.blocks[block_index].nodes[node_index]
        except IndexError:
            fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-NODE-EXISTS", "bound node", "missing")
        related = tuple(
            (
                operand,
                type_cid,
                ("operand", "effect_input") if _is_memory_effect(resolve(type_cid)) else ("operand",),
            )
            for operand, type_cid in zip(node.operands, node.operand_types)
        ) + tuple(
            (
                ValueRef.node_result(block_index, node_index, index),
                type_cid,
                ("result", "effect_output") if _is_memory_effect(resolve(type_cid)) else ("result",),
            )
            for index, type_cid in enumerate(node.results)
        )
        page_items = related[continuation:continuation + limit]
        page = tuple(
            NeighborhoodValue(_value_handle(function_handle, value), type_handles[type_cid], relations)
            for value, type_cid, relations in page_items
        )
        end = continuation + len(page)
        response = NeighborhoodPage(page, end < len(related), end if end < len(related) else None)
        response = self._fit_page_budget("neighborhood", response, "entities", continuation, byte_budget)
        page = response.entities
        page_items = page_items[:len(page)]
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", node_handle, "WORKSPACE-GENERATION", generation, self.generation)
            for (value, type_cid, _), entity in zip(page_items, page):
                self._value_bindings[entity.handle] = (function_cid, value, generation)
                self._type_bindings[entity.type_handle] = (type_cid, generation)
            self._account_query(response, len(page))
        return response

    def expand(self, value_handle: str, relation: str, limit: int, continuation: int = 0, depth: int = 1, *, byte_budget: int | None = None) -> ExpansionPage:
        if relation not in ("producer", "users"):
            raise ValueError("relation must be producer or users")
        if limit < 1 or continuation < 0 or depth < 1:
            raise ValueError("query bounds must be positive")
        with self._lock:
            binding = self._value_bindings.get(value_handle)
            generation = self.generation
            reader = self._reader
            if binding is None or binding[2] != generation:
                fail("XAX.WORKSPACE.HANDLE", value_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
            function_handle = self._function_handles[binding[0]]
            type_handles = self._type_handles
        function_cid, value, _ = binding
        resolve = store_resolver(reader)
        graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        frontier = (("value", value, None, None),)
        seen = {("value", value)}
        expanded = []
        for _ in range(depth):
            next_frontier = []
            for kind, entity, _, _ in frontier:
                if kind == "value":
                    # ponytail: scan one graph per value; index uses only if query profiling demands it.
                    locations = (
                        ((entity.block, entity.index),)
                        if relation == "producer" and entity.tag == 1
                        else tuple(
                            (block_index, node_index)
                            for block_index, block in enumerate(graph.blocks)
                            for node_index, node in enumerate(block.nodes)
                            if relation == "users" and entity in node.operands
                        )
                    )
                    for location in locations:
                        key = ("node", location)
                        if key not in seen:
                            seen.add(key)
                            next_frontier.append(("node", location, None, "producer" if relation == "producer" else "user"))
                else:
                    block_index, node_index = entity
                    node = graph.blocks[block_index].nodes[node_index]
                    values = (
                        tuple(zip(node.operands, node.operand_types))
                        if relation == "producer"
                        else tuple((ValueRef.node_result(block_index, node_index, index), type_cid) for index, type_cid in enumerate(node.results))
                    )
                    for related, type_cid in values:
                        key = ("value", related)
                        if key not in seen:
                            seen.add(key)
                            next_frontier.append(("value", related, type_cid, "operand" if relation == "producer" else "result"))
            expanded.extend(next_frontier)
            frontier = tuple(next_frontier)
            if not frontier:
                break
        page_items = expanded[continuation:continuation + limit]
        page = tuple(
            ExpansionView(
                f"{function_handle}.B{entity[0]}.N{entity[1]}",
                "node",
                relation_name,
                Operation(graph.blocks[entity[0]].nodes[entity[1]].operation),
                len(graph.blocks[entity[0]].nodes[entity[1]].operands),
                len(graph.blocks[entity[0]].nodes[entity[1]].results),
                _decode_constant(graph.blocks[entity[0]].nodes[entity[1]].entity, resolve)[1]
                if graph.blocks[entity[0]].nodes[entity[1]].operation == Operation.CONSTANT
                else None,
            )
            if kind == "node"
            else ExpansionView(_value_handle(function_handle, entity), "value", relation_name, type_handle=type_handles[type_cid])
            for kind, entity, type_cid, relation_name in page_items
        )
        end = continuation + len(page)
        response = ExpansionPage(page, end < len(expanded), end if end < len(expanded) else None)
        response = self._fit_page_budget("expand", response, "entities", continuation, byte_budget)
        page = response.entities
        page_items = page_items[:len(page)]
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", value_handle, "WORKSPACE-GENERATION", generation, self.generation)
            for (kind, entity, type_cid, _), view in zip(page_items, page):
                if kind == "node":
                    self._node_bindings[view.handle] = (function_cid, entity[0], entity[1], generation)
                else:
                    self._value_bindings[view.handle] = (function_cid, entity, generation)
                    self._type_bindings[view.type_handle] = (type_cid, generation)
            self._account_query(response, len(page))
        return response

    def type(self, type_handle: str, *, byte_budget: int | None = None) -> TypeView:
        with self._lock:
            binding = self._type_bindings.get(type_handle)
            generation = self.generation
            reader = self._reader
            type_handles = self._type_handles
            if binding is None or binding[1] != generation:
                fail("XAX.WORKSPACE.HANDLE", type_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
        type_cid = binding[0]
        resolve = store_resolver(reader)
        type_object = resolve(type_cid)
        cursor = Cursor(type_object.body, type_object.cid.hex())
        form = cursor.uleb()
        element = None
        if form == 1:
            view = TypeView(type_handle, "bits", (("width", decode_bits_width(type_object)),))
        elif form == 2:
            element, permission, alignment = _decode_pointer_type(type_object, resolve)
            view = TypeView(
                type_handle,
                "pointer",
                (
                    ("space", "stack"),
                    ("element", type_handles[element]),
                    ("permission", Permission(permission).name.lower()),
                    ("alignment", alignment),
                ),
            )
        elif form == 3:
            effect = _decode_effect_type(type_object)
            view = TypeView(
                type_handle,
                "effect",
                (("domain", effect.domain.name.lower()), ("instance", effect.instance)),
            )
        elif form == 4:
            resource = _decode_resource_type(type_object)
            view = TypeView(
                type_handle,
                "resource",
                (
                    ("kind", "stack-storage" if resource.kind == 1 else resource.kind),
                    ("state", "live" if (resource.kind, resource.state) == (1, 1) else resource.state),
                    ("flags", int(resource.flags)),
                    ("instance", resource.instance),
                    ("transitions", resource.transitions),
                ),
            )
        elif form == 5:
            view = TypeView(type_handle, "opaque", (("kind", _decode_opaque_type(type_object).name.lower()),))
        elif form == 6:
            view = TypeView(type_handle, "opaque-identity", (("identity", _decode_opaque_identity_type(type_object).hex()),))
        else:
            fail("XAX.TYPE.FORM", type_object.cid.hex(), "TYPE-FORM-SUPPORTED", [1, 2, 3, 4, 5, 6], form)
        view = self._enforce_response_budget("type", view, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", type_handle, "WORKSPACE-GENERATION", generation, self.generation)
            if element is not None:
                self._type_bindings[type_handles[element]] = (element, generation)
            self._account_query(view, 1)
        return view

    def effects(self, node_handle: str, *, byte_budget: int | None = None) -> EffectView:
        with self._lock:
            binding = self._node_bindings.get(node_handle)
            generation = self.generation
            reader = self._reader
            if binding is None or binding[3] != generation:
                fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
            function_handle = self._function_handles[binding[0]]
            type_handles = self._type_handles
        function_cid, block_index, node_index, _ = binding
        resolve = store_resolver(reader)
        graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        try:
            node = graph.blocks[block_index].nodes[node_index]
        except IndexError:
            fail("XAX.WORKSPACE.HANDLE", node_handle, "WORKSPACE-NODE-EXISTS", "bound node", "missing")
        input_pairs = tuple(
            (operand, type_cid)
            for operand, type_cid in zip(node.operands, node.operand_types)
            if _is_effect(resolve(type_cid))
        )
        output_pairs = tuple(
            (ValueRef.node_result(block_index, node_index, index), type_cid)
            for index, type_cid in enumerate(node.results)
            if _is_effect(resolve(type_cid))
        )
        inputs = tuple(ValueView(_value_handle(function_handle, value), type_handles[type_cid]) for value, type_cid in input_pairs)
        outputs = tuple(ValueView(_value_handle(function_handle, value), type_handles[type_cid]) for value, type_cid in output_pairs)
        domains = tuple(
            sorted(
                {
                    _decode_effect_type(resolve(type_cid)).domain.name.lower()
                    for _, type_cid in (*input_pairs, *output_pairs)
                }
            )
        )
        view = EffectView(node_handle, not inputs and not outputs, ",".join(domains) if domains else None, inputs, outputs)
        view = self._enforce_response_budget("effects", view, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", node_handle, "WORKSPACE-GENERATION", generation, self.generation)
            for (value, type_cid), entity in zip((*input_pairs, *output_pairs), (*inputs, *outputs)):
                self._value_bindings[entity.handle] = (function_cid, value, generation)
                self._type_bindings[entity.type_handle] = (type_cid, generation)
            self._account_query(view, 1)
        return view

    def effect_summary(self, function_handle: str, *, byte_budget: int | None = None) -> EffectSummaryView:
        with self._lock:
            binding = self._function_bindings.get(function_handle)
            node_binding = self._node_bindings.get(function_handle)
            generation = self.generation
            reader = self._reader
            if binding is None and node_binding is not None and node_binding[3] == generation:
                binding = (node_binding[0], generation)
            if binding is None or binding[1] != generation:
                fail("XAX.WORKSPACE.HANDLE", function_handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
        summary = derive_effect_summary(reader, binding[0])
        view = EffectSummaryView(
            function_handle,
            tuple((domain.name.lower(), instance) for domain, instance in summary.domains),
            summary.may_return,
            summary.may_trap,
        )
        view = self._enforce_response_budget("effect_summary", view, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", function_handle, "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(view, 1)
        return view

    def entity(self, handle: str, *, byte_budget: int | None = None) -> EntityView:
        with self._lock:
            generation = self.generation
            reader = self._reader
            node_binding = self._node_bindings.get(handle)
            object_binding = self._object_bindings.get(handle)
            function_binding = self._function_bindings.get(handle)
            value_binding = self._value_bindings.get(handle)
            type_binding = self._type_bindings.get(handle)
            artifact_binding = self._artifact_bindings.get(handle)
            artifact_current = artifact_binding is not None and artifact_binding[2] == generation and self._artifact_binding_current(artifact_binding)
            if artifact_binding is not None and artifact_binding[2] == generation and not artifact_current:
                fail(
                    "XAX.WORKSPACE.ARTIFACT_STALE",
                    handle,
                    "WORKSPACE-ARTIFACT-DEPENDENCIES",
                    artifact_binding[3].identity.hex(),
                    "dependency changed",
                )
            current = (
                (node_binding is not None and node_binding[3] == generation)
                or (object_binding is not None and object_binding[1] == generation)
                or (function_binding is not None and function_binding[1] == generation)
                or (value_binding is not None and value_binding[2] == generation)
                or (type_binding is not None and type_binding[1] == generation)
                or artifact_current
            )
            if not current:
                fail("XAX.WORKSPACE.HANDLE", handle, "WORKSPACE-HANDLE-GENERATION", generation, "unbound or stale")
            type_handles = self._type_handles
        resolve = store_resolver(reader)
        if artifact_binding is not None:
            image, function_cid, artifact_generation, provenance = artifact_binding
            view = EntityView(
                handle,
                "artifact",
                (
                    ("entry", self._function_handles[function_cid]),
                    ("semantic_root", f"R0.{artifact_generation}"),
                    ("size_bytes", len(image.artifact_bytes)),
                    ("target", provenance.target_configuration_cid.hex()),
                    ("identity", provenance.identity.hex()),
                    ("digest", provenance.artifact_digest.hex()),
                    ("compiler_identity", provenance.compiler_identity.hex()),
                    ("lowering_identity", provenance.lowering_identity.hex()),
                    ("retained_ranges", len(provenance.semantic_ranges)),
                ),
                "derived",
            )
        elif node_binding is not None:
            function_cid, block_index, node_index, _ = node_binding
            graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
            node = _parse_graph(graph_object, resolve).blocks[block_index].nodes[node_index]
            facts = (("operation", Operation(node.operation).name.lower()), ("operands", len(node.operands)), ("results", len(node.results)))
            if node.operation == Operation.CONSTANT:
                facts += (("constant", _decode_constant(node.entity, resolve)[1]),)
            view = EntityView(handle, "node", facts)
        elif value_binding is not None:
            function_cid, value, _ = value_binding
            graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
            graph = _parse_graph(graph_object, resolve)
            type_cid = graph.blocks[value.block].parameters[value.index] if value.tag == 0 else graph.blocks[value.block].nodes[value.index].results[value.result]
            view = EntityView(handle, "value", (("type", type_handles[type_cid]),))
        elif function_binding is not None:
            _, parameters, returns = _decode_function_interface(resolve(function_binding[0]), resolve)
            view = EntityView(handle, "function", (("parameters", len(parameters)), ("returns", len(returns))))
        elif object_binding is not None:
            view = EntityView(handle, reader.get(object_binding[0]).kind.name.lower())
        else:
            type_object = resolve(type_binding[0])
            form = Cursor(type_object.body, type_object.cid.hex()).uleb()
            view = EntityView(handle, "type", (("form", ("bits", "pointer", "effect", "resource")[form - 1]),))
        view = self._enforce_response_budget("entity", view, byte_budget)
        with self._lock:
            if generation != self.generation:
                fail("XAX.WORKSPACE.STALE_QUERY", handle, "WORKSPACE-GENERATION", generation, self.generation)
            self._account_query(view, 1)
        return view

    def _function_page(
        self,
        function_cid: bytes,
        relation: dict[bytes, tuple[bytes, ...]],
        limit: int,
        continuation: int,
        *,
        byte_budget: int | None = None,
    ) -> FunctionQueryPage:
        if limit < 1 or continuation < 0:
            raise ValueError("query bounds must be positive")
        with self._lock:
            if function_cid not in relation:
                fail("XAX.WORKSPACE.ENTITY", function_cid.hex(), "WORKSPACE-FUNCTION", Kind.FUNCTION.name, "missing")
            generation = self.generation
            related = relation[function_cid]
            page_cids = related[continuation:continuation + limit]
            page = tuple(FunctionView(self._function_handles[cid]) for cid in page_cids)
            end = continuation + len(page)
            response = FunctionQueryPage(page, end < len(related), end if end < len(related) else None)
            response = self._fit_page_budget("function_relation", response, "entities", continuation, byte_budget)
            page = response.entities
            page_cids = page_cids[:len(page)]
            for cid, entity in zip(page_cids, page):
                self._function_bindings[entity.handle] = (cid, generation)
            self._account_query(response, len(page))
        return response

    def _read_dependency_diagnostic(self, handle: str, mutations: tuple[Mutation, ...]) -> Diagnostic | None:
        proof = self._proof_bindings.get(handle)
        if proof is not None:
            if not self._proof_binding_current(proof):
                repair = (handle, *(mutation.node for mutation in mutations if mutation.node != handle))
                return _diagnostic(
                    "XAX.WORKSPACE.PROOF_CONFLICT",
                    handle,
                    "WORKSPACE-PROOF-DEPENDENCY",
                    {"subject": proof.subject_kind, "verifier": proof.verifier_identity, "freshness": "preserved"},
                    {"verifier": self._verifier_identity, "freshness": "changed or stale"},
                    repair,
                )
            return None
        node = self._node_bindings.get(handle)
        entity = self._object_bindings.get(handle)
        function = self._function_bindings.get(handle)
        value = self._value_bindings.get(handle)
        type_ = self._type_bindings.get(handle)
        artifact = self._artifact_bindings.get(handle)
        if not (
            (node is not None and node[3] == self.generation)
            or (entity is not None and entity[1] == self.generation)
            or (function is not None and function[1] == self.generation)
            or (value is not None and value[2] == self.generation)
            or (type_ is not None and type_[1] == self.generation)
            or (artifact is not None and self._artifact_binding_current(artifact))
        ):
            repair = (handle, *(mutation.node for mutation in mutations if mutation.node != handle))
            return _diagnostic(
                "XAX.WORKSPACE.READ_CONFLICT",
                handle,
                "WORKSPACE-READ-SET",
                "bound entity at current root",
                "unbound or stale",
                repair,
            )
        return None

    def _candidate_rejected(self, size: int, diagnostic: Diagnostic, verified: int = 0) -> CandidateVerification:
        self.accounting.rejected_candidates += 1
        self.accounting.candidate_verified_objects += verified
        return CandidateVerification(
            False,
            None,
            self._reader.root_cid,
            diagnostic,
            size,
            0,
            len(tuple(self._reader.objects())),
            verified,
        )

    def verify(self, transaction: Transaction) -> CandidateVerification:
        """Build and verify a private candidate without publishing semantic state."""
        size = _transaction_size(transaction)
        mutations = tuple(sorted(transaction.mutations, key=_mutation_sort_key))
        with self._lock:
            reader = self._reader
            current_root = reader.root_cid
            users = self._users
            base_generation = self.generation
            self.accounting.candidate_verifications += 1
            self.accounting.candidate_transaction_bytes += size
            expected = transaction.expected_root
            if isinstance(expected, RootRef):
                if expected.generation != self.generation:
                    repair = (expected.handle, *(mutation.node for mutation in mutations))
                    return self._candidate_rejected(
                        size,
                        _diagnostic(
                            "XAX.WORKSPACE.STALE_ROOT",
                            "R0",
                            "WORKSPACE-EXPECTED-ROOT",
                            expected.handle,
                            f"R0.{self.generation}",
                            repair,
                        ),
                    )
                expected_root = current_root
            else:
                expected_root = expected
                if expected_root != current_root:
                    repair = ("R0", *(mutation.node for mutation in mutations))
                    return self._candidate_rejected(
                        size,
                        _diagnostic(
                            "XAX.WORKSPACE.STALE_ROOT",
                            "R0",
                            "WORKSPACE-EXPECTED-ROOT",
                            expected_root.hex(),
                            current_root.hex(),
                            repair,
                        ),
                    )
            for handle in sorted(set(transaction.read_set)):
                diagnostic = self._read_dependency_diagnostic(handle, mutations)
                if diagnostic is not None:
                    return self._candidate_rejected(size, diagnostic)
            if not mutations:
                return self._candidate_rejected(
                    size,
                    _diagnostic(
                        "XAX.WORKSPACE.EMPTY_TRANSACTION",
                        "R0",
                        "WORKSPACE-MUTATION-NONEMPTY",
                        ">= 1 mutation",
                        0,
                        ("R0",),
                    ),
                )
            mutations_by_node: dict[str, list[Mutation]] = {}
            for mutation in mutations:
                mutations_by_node.setdefault(mutation.node, []).append(mutation)
            duplicate = None
            for handle, group in mutations_by_node.items():
                if len(group) == 1:
                    continue
                edge_pair = (
                    len(group) == 2
                    and {type(mutation) for mutation in group} == {DisconnectEdgeArgument, ConnectEdgeArgument}
                    and len({(mutation.expected_block, mutation.edge_index, mutation.argument_index) for mutation in group}) == 1
                )
                if not edge_pair:
                    duplicate = handle
                    break
            if duplicate is not None:
                return self._candidate_rejected(
                    size,
                    _diagnostic(
                        "XAX.WORKSPACE.DUPLICATE_MUTATION",
                        duplicate,
                        "WORKSPACE-MUTATION-TARGET-UNIQUE",
                        "one mutation per node, except one matching disconnect/connect edge-argument pair",
                        "duplicate",
                        (duplicate,),
                    ),
                )
            insertion_ids = sorted(mutation.local_id for mutation in mutations if isinstance(mutation, InsertPureNode))
            duplicate_insertion = next((left for left, right in zip(insertion_ids, insertion_ids[1:]) if left == right), None)
            if duplicate_insertion is not None:
                return self._candidate_rejected(
                    size,
                    _diagnostic(
                        "XAX.WORKSPACE.DUPLICATE_MUTATION",
                        f"I{duplicate_insertion}",
                        "WORKSPACE-INSERT-LOCAL-ID-UNIQUE",
                        "one inserted node per transaction-local id",
                        "duplicate",
                        (f"I{duplicate_insertion}",),
                    ),
                )
            bindings = []
            candidate_mutations: list[Mutation | _ResolvedInsertPureNode | _ResolvedSpecializeFunction] = []
            for mutation in mutations:
                if isinstance(mutation, SpecializeFunction):
                    function_binding = self._function_bindings.get(mutation.function)
                    if function_binding is None or function_binding[1] != self.generation:
                        return self._candidate_rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.HANDLE",
                                mutation.function,
                                "WORKSPACE-HANDLE-GENERATION",
                                self.generation,
                                "unbound or stale",
                                ("R0",),
                            ),
                        )
                    resolved_arguments = []
                    for argument in mutation.arguments:
                        type_binding = self._type_bindings.get(argument.expected_type)
                        if type_binding is None or type_binding[1] != self.generation:
                            return self._candidate_rejected(
                                size,
                                _diagnostic(
                                    "XAX.WORKSPACE.HANDLE",
                                    argument.expected_type,
                                    "WORKSPACE-HANDLE-GENERATION",
                                    self.generation,
                                    "unbound or stale",
                                    (mutation.function,),
                                ),
                            )
                        resolved_arguments.append(
                            _ResolvedSpecializationArgument(argument.parameter, type_binding[0], argument.value)
                        )
                    candidate_mutations.append(
                        _ResolvedSpecializeFunction(mutation.function, tuple(resolved_arguments))
                    )
                    bindings.append((function_binding[0], 0, 0))
                    continue
                binding = self._node_bindings.get(mutation.node)
                if binding is None or binding[3] != self.generation:
                    return self._candidate_rejected(
                        size,
                        _diagnostic(
                            "XAX.WORKSPACE.HANDLE",
                            mutation.node,
                            "WORKSPACE-HANDLE-GENERATION",
                            self.generation,
                            "unbound or stale",
                            ("R0",),
                        ),
                    )
                if isinstance(mutation, MovePureNode):
                    destination_binding = self._node_bindings.get(mutation.destination)
                    if destination_binding is None or destination_binding[3] != self.generation:
                        return self._candidate_rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.HANDLE",
                                mutation.destination,
                                "WORKSPACE-HANDLE-GENERATION",
                                self.generation,
                                "unbound or stale",
                                (mutation.node,),
                            ),
                        )
                    if destination_binding[0] != binding[0] or destination_binding[1] != binding[1]:
                        return self._candidate_rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                                mutation.node,
                                "WORKSPACE-MOVE-SAME-BLOCK",
                                {"function": binding[0].hex(), "block": binding[1]},
                                {"function": destination_binding[0].hex(), "block": destination_binding[1]},
                                (mutation.node, mutation.destination),
                            ),
                        )
                    actual_destination = (destination_binding[1], destination_binding[2])
                    expected_destination = (
                        mutation.expected_destination_block,
                        mutation.expected_destination_index,
                    )
                    if actual_destination != expected_destination:
                        return self._candidate_rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                                mutation.destination,
                                "WORKSPACE-MOVE-DESTINATION",
                                expected_destination,
                                actual_destination,
                                (mutation.node, mutation.destination),
                            ),
                        )
                if isinstance(mutation, InsertPureNode):
                    type_binding = self._type_bindings.get(mutation.result_type)
                    if type_binding is None or type_binding[1] != self.generation:
                        return self._candidate_rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.HANDLE",
                                mutation.result_type,
                                "WORKSPACE-HANDLE-GENERATION",
                                self.generation,
                                "unbound or stale",
                                (mutation.node,),
                            ),
                        )
                    candidate_mutations.append(
                        _ResolvedInsertPureNode(
                            mutation.node,
                            mutation.expected_block,
                            mutation.expected_index,
                            mutation.local_id,
                            mutation.operation,
                            mutation.operands,
                            type_binding[0],
                            mutation.constant_value,
                        )
                    )
                else:
                    candidate_mutations.append(mutation)
                bindings.append(binding[:3])
        verified = 0
        try:
            candidate, _, touched, reused, frontier = _candidate(
                reader, tuple(bindings), tuple(candidate_mutations), users
            )
            resolve = store_resolver(candidate)
            for cid in frontier:
                verified += 1
                verify_object(candidate.get(cid), resolve)
        except XaxError as error:
            with self._lock:
                return self._candidate_rejected(size, error.diagnostic, verified)
        with self._lock:
            root_changed = self._reader.root_cid != expected_root
            generation_changed = isinstance(expected, RootRef) and self.generation != expected.generation
            if root_changed or generation_changed:
                expected_label = expected.handle if isinstance(expected, RootRef) else expected_root.hex()
                actual_label = f"R0.{self.generation}" if isinstance(expected, RootRef) else self._reader.root_cid.hex()
                return self._candidate_rejected(
                    size,
                    _diagnostic(
                        "XAX.WORKSPACE.STALE_ROOT",
                        "R0",
                        "WORKSPACE-CANDIDATE-ATOMIC-COMPARE",
                        expected_label,
                        actual_label,
                        ("R0",),
                    ),
                    verified,
                )
            for handle in sorted(set(transaction.read_set)):
                diagnostic = self._read_dependency_diagnostic(handle, mutations)
                if diagnostic is not None:
                    return self._candidate_rejected(size, diagnostic, verified)
            handle = f"C{self._next_candidate_handle}.{base_generation}"
            self._next_candidate_handle += 1
            self._candidate_bindings[handle] = _CandidateBinding(
                candidate,
                current_root,
                base_generation,
                self._verifier_identity,
                size,
                touched,
                reused,
                verified,
            )
            self.accounting.candidate_verified_objects += verified
            return CandidateVerification(
                True,
                handle,
                self._reader.root_cid,
                None,
                size,
                touched,
                reused,
                verified,
            )

    def rollback(self, candidate_handle: str) -> CandidateRollback:
        """Discard a private verified candidate without changing the canonical root."""
        with self._lock:
            binding = self._candidate_bindings.pop(candidate_handle, None)
            if binding is None:
                diagnostic = _diagnostic(
                    "XAX.WORKSPACE.CANDIDATE_HANDLE",
                    candidate_handle,
                    "WORKSPACE-CANDIDATE-CURRENT",
                    "live private candidate handle",
                    "missing, stale, or already discarded",
                    (candidate_handle,),
                )
                return CandidateRollback(False, candidate_handle, self._reader.root_cid, diagnostic)
            self.accounting.candidate_rollbacks += 1
            return CandidateRollback(True, candidate_handle, self._reader.root_cid, None)

    def commit(self, transaction: Transaction) -> TransactionResult:
        size = _transaction_size(transaction)
        mutations = tuple(sorted(transaction.mutations, key=_mutation_sort_key))
        with self._lock:
            reader = self._reader
            current_root = reader.root_cid
            users = self._users
            self.accounting.mutations += 1
            self.accounting.transaction_bytes += size
            expected = transaction.expected_root
            if isinstance(expected, RootRef):
                if expected.generation != self.generation:
                    repair = (expected.handle, *(mutation.node for mutation in mutations))
                    return self._rejected(size, _diagnostic("XAX.WORKSPACE.STALE_ROOT", "R0", "WORKSPACE-EXPECTED-ROOT", expected.handle, f"R0.{self.generation}", repair))
                expected_root = current_root
            else:
                expected_root = expected
                if expected_root != current_root:
                    repair = ("R0", *(mutation.node for mutation in mutations))
                    return self._rejected(size, _diagnostic("XAX.WORKSPACE.STALE_ROOT", "R0", "WORKSPACE-EXPECTED-ROOT", expected_root.hex(), current_root.hex(), repair))
            for handle in sorted(set(transaction.read_set)):
                proof = self._proof_bindings.get(handle)
                if proof is not None:
                    if not self._proof_binding_current(proof):
                        repair = (handle, *(mutation.node for mutation in mutations if mutation.node != handle))
                        return self._rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.PROOF_CONFLICT",
                                handle,
                                "WORKSPACE-PROOF-DEPENDENCY",
                                {"subject": proof.subject_kind, "verifier": proof.verifier_identity, "freshness": "preserved"},
                                {"verifier": self._verifier_identity, "freshness": "changed or stale"},
                                repair,
                            ),
                        )
                    continue
                node = self._node_bindings.get(handle)
                entity = self._object_bindings.get(handle)
                function = self._function_bindings.get(handle)
                value = self._value_bindings.get(handle)
                type_ = self._type_bindings.get(handle)
                artifact = self._artifact_bindings.get(handle)
                if not (
                    (node is not None and node[3] == self.generation)
                    or (entity is not None and entity[1] == self.generation)
                    or (function is not None and function[1] == self.generation)
                    or (value is not None and value[2] == self.generation)
                    or (type_ is not None and type_[1] == self.generation)
                    or (artifact is not None and self._artifact_binding_current(artifact))
                ):
                    repair = (handle, *(mutation.node for mutation in mutations if mutation.node != handle))
                    return self._rejected(size, _diagnostic("XAX.WORKSPACE.READ_CONFLICT", handle, "WORKSPACE-READ-SET", "bound entity at current root", "unbound or stale", repair))
            if not mutations:
                return self._rejected(size, _diagnostic("XAX.WORKSPACE.EMPTY_TRANSACTION", "R0", "WORKSPACE-MUTATION-NONEMPTY", ">= 1 mutation", 0, ("R0",)))
            mutations_by_node: dict[str, list[Mutation]] = {}
            for mutation in mutations:
                mutations_by_node.setdefault(mutation.node, []).append(mutation)
            duplicate = None
            for handle, group in mutations_by_node.items():
                if len(group) == 1:
                    continue
                edge_pair = (
                    len(group) == 2
                    and {type(mutation) for mutation in group} == {DisconnectEdgeArgument, ConnectEdgeArgument}
                    and len({(mutation.expected_block, mutation.edge_index, mutation.argument_index) for mutation in group}) == 1
                )
                if not edge_pair:
                    duplicate = handle
                    break
            if duplicate is not None:
                return self._rejected(size, _diagnostic("XAX.WORKSPACE.DUPLICATE_MUTATION", duplicate, "WORKSPACE-MUTATION-TARGET-UNIQUE", "one mutation per node, except one matching disconnect/connect edge-argument pair", "duplicate", (duplicate,)))
            insertion_ids = sorted(mutation.local_id for mutation in mutations if isinstance(mutation, InsertPureNode))
            duplicate_insertion = next((left for left, right in zip(insertion_ids, insertion_ids[1:]) if left == right), None)
            if duplicate_insertion is not None:
                return self._rejected(
                    size,
                    _diagnostic(
                        "XAX.WORKSPACE.DUPLICATE_MUTATION",
                        f"I{duplicate_insertion}",
                        "WORKSPACE-INSERT-LOCAL-ID-UNIQUE",
                        "one inserted node per transaction-local id",
                        "duplicate",
                        (f"I{duplicate_insertion}",),
                    ),
                )
            bindings = []
            candidate_mutations: list[Mutation | _ResolvedInsertPureNode | _ResolvedSpecializeFunction] = []
            for mutation in mutations:
                if isinstance(mutation, SpecializeFunction):
                    function_binding = self._function_bindings.get(mutation.function)
                    if function_binding is None or function_binding[1] != self.generation:
                        return self._rejected(size, _diagnostic("XAX.WORKSPACE.HANDLE", mutation.function, "WORKSPACE-HANDLE-GENERATION", self.generation, "unbound or stale", ("R0",)))
                    resolved_arguments = []
                    for argument in mutation.arguments:
                        type_binding = self._type_bindings.get(argument.expected_type)
                        if type_binding is None or type_binding[1] != self.generation:
                            return self._rejected(
                                size,
                                _diagnostic(
                                    "XAX.WORKSPACE.HANDLE",
                                    argument.expected_type,
                                    "WORKSPACE-HANDLE-GENERATION",
                                    self.generation,
                                    "unbound or stale",
                                    (mutation.function,),
                                ),
                            )
                        resolved_arguments.append(
                            _ResolvedSpecializationArgument(argument.parameter, type_binding[0], argument.value)
                        )
                    candidate_mutations.append(
                        _ResolvedSpecializeFunction(mutation.function, tuple(resolved_arguments))
                    )
                    bindings.append((function_binding[0], 0, 0))
                    continue
                binding = self._node_bindings.get(mutation.node)
                if binding is None or binding[3] != self.generation:
                    return self._rejected(size, _diagnostic("XAX.WORKSPACE.HANDLE", mutation.node, "WORKSPACE-HANDLE-GENERATION", self.generation, "unbound or stale", ("R0",)))
                if isinstance(mutation, MovePureNode):
                    destination_binding = self._node_bindings.get(mutation.destination)
                    if destination_binding is None or destination_binding[3] != self.generation:
                        return self._rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.HANDLE",
                                mutation.destination,
                                "WORKSPACE-HANDLE-GENERATION",
                                self.generation,
                                "unbound or stale",
                                (mutation.node,),
                            ),
                        )
                    if destination_binding[0] != binding[0] or destination_binding[1] != binding[1]:
                        return self._rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                                mutation.node,
                                "WORKSPACE-MOVE-SAME-BLOCK",
                                {"function": binding[0].hex(), "block": binding[1]},
                                {"function": destination_binding[0].hex(), "block": destination_binding[1]},
                                (mutation.node, mutation.destination),
                            ),
                        )
                    actual_destination = (destination_binding[1], destination_binding[2])
                    expected_destination = (
                        mutation.expected_destination_block,
                        mutation.expected_destination_index,
                    )
                    if actual_destination != expected_destination:
                        return self._rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                                mutation.destination,
                                "WORKSPACE-MOVE-DESTINATION",
                                expected_destination,
                                actual_destination,
                                (mutation.node, mutation.destination),
                            ),
                        )
                if isinstance(mutation, InsertPureNode):
                    type_binding = self._type_bindings.get(mutation.result_type)
                    if type_binding is None or type_binding[1] != self.generation:
                        return self._rejected(
                            size,
                            _diagnostic(
                                "XAX.WORKSPACE.HANDLE",
                                mutation.result_type,
                                "WORKSPACE-HANDLE-GENERATION",
                                self.generation,
                                "unbound or stale",
                                (mutation.node,),
                            ),
                        )
                    candidate_mutations.append(
                        _ResolvedInsertPureNode(
                            mutation.node,
                            mutation.expected_block,
                            mutation.expected_index,
                            mutation.local_id,
                            mutation.operation,
                            mutation.operands,
                            type_binding[0],
                            mutation.constant_value,
                        )
                    )
                else:
                    candidate_mutations.append(mutation)
                bindings.append(binding[:3])
        verified = 0
        try:
            candidate, changed, touched, reused, frontier = _candidate(reader, tuple(bindings), tuple(candidate_mutations), users)
            resolve = store_resolver(candidate)
            for cid in frontier:
                verified += 1
                verify_object(candidate.get(cid), resolve)
        except XaxError as error:
            with self._lock:
                return self._rejected(size, error.diagnostic, verified)
        with self._lock:
            root_changed = self._reader.root_cid != expected_root
            generation_changed = isinstance(expected, RootRef) and self.generation != expected.generation
            if root_changed or generation_changed:
                expected_label = expected.handle if isinstance(expected, RootRef) else expected_root.hex()
                actual_label = f"R0.{self.generation}" if isinstance(expected, RootRef) else self._reader.root_cid.hex()
                return self._rejected(size, _diagnostic("XAX.WORKSPACE.STALE_ROOT", "R0", "WORKSPACE-ATOMIC-COMPARE", expected_label, actual_label, ("R0",)), verified)
            # Proof dependencies are invalidated monotonically when a commit changes their
            # required subject/verifier dependency. Re-check at publication so a raw-root
            # ABA cannot revive a proof handle that was valid only at transaction start.
            for handle in sorted(set(transaction.read_set)):
                proof = self._proof_bindings.get(handle)
                if proof is not None and not self._proof_binding_current(proof):
                    repair = (handle, *(mutation.node for mutation in mutations if mutation.node != handle))
                    return self._rejected(
                        size,
                        _diagnostic(
                            "XAX.WORKSPACE.PROOF_CONFLICT",
                            handle,
                            "WORKSPACE-PROOF-DEPENDENCY",
                            {"subject": proof.subject_kind, "verifier": proof.verifier_identity, "freshness": "preserved"},
                            {"verifier": self._verifier_identity, "freshness": "changed or stale"},
                            repair,
                        ),
                        verified,
                    )
            self._previous_reader = self._reader
            self._previous_root = current_root
            self._previous_generation = self.generation
            self._previous_node_bindings = dict(self._node_bindings)
            self._previous_object_bindings = dict(self._object_bindings)
            self._previous_function_bindings = dict(self._function_bindings)
            self._previous_value_bindings = dict(self._value_bindings)
            self._previous_type_bindings = dict(self._type_bindings)
            self._history[self.generation] = self._snapshot()
            self._invalidate_changed_proofs(candidate)
            if candidate.proof_cache is not None:
                cache_writes = 0
                dependency_cids = 0
                for cid in frontier:
                    obj = candidate.get(cid)
                    dependency_cids += len(obj.references)
                    cache_writes += int(candidate.proof_cache.record(self._verifier_identity, obj))
                cache_invalidated = candidate.proof_cache.prune(self._verifier_identity, candidate.object_cids)
                self.accounting.proof_cache_entries_written += cache_writes
                self.accounting.proof_cache_entries_invalidated += cache_invalidated
                self.accounting.proof_cache_dependency_cids_maintained += dependency_cids
            # Verified private candidates are generation-scoped tooling state. A published
            # commit invalidates all of them rather than rebasing or reviving them.
            self._candidate_bindings.clear()
            self._reader = candidate
            self.generation += 1
            self._bind_handles()
            self._history[self.generation] = self._snapshot()
            self.accounting.committed_changes += 1
            self.accounting.verified_objects += verified
            return TransactionResult(True, candidate.root_cid, changed, None, size, touched, reused, verified)

    def rebase(self, transaction: Transaction) -> TransactionResult:
        with self._lock:
            current_root = self._reader.root_cid
            generation = self.generation
        expected = transaction.expected_root
        if (isinstance(expected, RootRef) and expected.generation == generation) or expected == current_root:
            return self.commit(transaction)

        size = _transaction_size(transaction)
        with self._lock:
            def reject(entity: str, rule: str, expected: object, actual: object) -> TransactionResult:
                self.accounting.mutations += 1
                self.accounting.transaction_bytes += size
                return self._rejected(size, _diagnostic("XAX.WORKSPACE.REBASE_CONFLICT", entity, rule, expected, actual, (entity,)))

            if isinstance(expected, RootRef):
                snapshot = self._history.get(expected.generation)
                if snapshot is None or expected.generation >= self.generation:
                    return reject("R0", "WORKSPACE-REBASE-BASE", f"retained generation < {self.generation}", expected.handle)
                expected_root = snapshot.root
                expected_label = expected.handle
            else:
                matches = tuple(
                    (old_generation, old_snapshot)
                    for old_generation, old_snapshot in self._history.items()
                    if old_generation < self.generation and old_snapshot.root == expected
                )
                if not matches:
                    return reject("R0", "WORKSPACE-REBASE-BASE", "retained historical root", expected.hex())
                _, snapshot = max(matches, key=lambda item: item[0])
                expected_root = snapshot.root
                expected_label = expected.hex()
            generation = self.generation
            current_cids = set(self._object_handles)
            bindings_to_publish = []

            def translate(handle: str) -> str | None:
                binding = snapshot.node_bindings.get(handle)
                if binding is not None and binding[0] in current_cids:
                    translated = f"{self._function_handles[binding[0]]}.B{binding[1]}.N{binding[2]}"
                    bindings_to_publish.append(("node", translated, (*binding[:3], generation)))
                    return translated
                object_binding = snapshot.object_bindings.get(handle)
                if object_binding is not None and object_binding[0] in current_cids:
                    translated = self._object_handles[object_binding[0]]
                    bindings_to_publish.append(("object", translated, (object_binding[0], generation)))
                    return translated
                function_binding = snapshot.function_bindings.get(handle)
                if function_binding is not None and function_binding[0] in current_cids:
                    translated = self._function_handles[function_binding[0]]
                    bindings_to_publish.append(("function", translated, (function_binding[0], generation)))
                    return translated
                value_binding = snapshot.value_bindings.get(handle)
                if value_binding is not None and value_binding[0] in current_cids:
                    translated = _value_handle(self._function_handles[value_binding[0]], value_binding[1])
                    bindings_to_publish.append(("value", translated, (value_binding[0], value_binding[1], generation)))
                    return translated
                type_binding = snapshot.type_bindings.get(handle)
                if type_binding is not None and type_binding[0] in current_cids:
                    translated = self._type_handles[type_binding[0]]
                    bindings_to_publish.append(("type", translated, (type_binding[0], generation)))
                    return translated
                return None

            translated_mutations = []
            for mutation in transaction.mutations:
                handle = translate(mutation.node)
                if handle is None:
                    return reject(mutation.node, "WORKSPACE-REBASE-TARGET-UNCHANGED", "unchanged target at current root", "changed, missing, or unbound")
                if isinstance(mutation, SetOperation):
                    translated_mutations.append(SetOperation(handle, mutation.expected, mutation.value))
                elif isinstance(mutation, SetConstant):
                    translated_mutations.append(SetConstant(handle, mutation.expected, mutation.value))
                elif isinstance(mutation, ReplaceUse):
                    translated_mutations.append(
                        ReplaceUse(handle, mutation.operand_index, mutation.expected, mutation.value)
                    )
                elif isinstance(mutation, DeleteNode):
                    translated_mutations.append(DeleteNode(handle, mutation.expected_block, mutation.expected_index))
                elif isinstance(mutation, DisconnectEdgeArgument):
                    translated_mutations.append(
                        DisconnectEdgeArgument(
                            handle,
                            mutation.expected_block,
                            mutation.edge_index,
                            mutation.argument_index,
                            mutation.expected,
                        )
                    )
                elif isinstance(mutation, ConnectEdgeArgument):
                    translated_mutations.append(
                        ConnectEdgeArgument(
                            handle,
                            mutation.expected_block,
                            mutation.edge_index,
                            mutation.argument_index,
                            mutation.value,
                        )
                    )
                elif isinstance(mutation, MovePureNode):
                    destination = translate(mutation.destination)
                    if destination is None:
                        return reject(
                            mutation.destination,
                            "WORKSPACE-REBASE-READ-UNCHANGED",
                            "unchanged move destination at current root",
                            "changed, missing, or unbound",
                        )
                    translated_mutations.append(
                        MovePureNode(
                            handle,
                            mutation.expected_block,
                            mutation.expected_index,
                            destination,
                            mutation.expected_destination_block,
                            mutation.expected_destination_index,
                        )
                    )
                elif isinstance(mutation, SpecializeFunction):
                    arguments = []
                    for argument in mutation.arguments:
                        expected_type = translate(argument.expected_type)
                        if expected_type is None:
                            return reject(
                                argument.expected_type,
                                "WORKSPACE-REBASE-READ-UNCHANGED",
                                "unchanged specialization parameter type at current root",
                                "changed, missing, or unbound",
                            )
                        arguments.append(
                            SpecializationArgument(argument.parameter, expected_type, argument.value)
                        )
                    translated_mutations.append(SpecializeFunction(handle, tuple(arguments)))
                else:
                    result_type = translate(mutation.result_type)
                    if result_type is None:
                        return reject(
                            mutation.result_type,
                            "WORKSPACE-REBASE-READ-UNCHANGED",
                            "unchanged insertion result type at current root",
                            "changed, missing, or unbound",
                        )
                    translated_mutations.append(
                        InsertPureNode(
                            handle,
                            mutation.expected_block,
                            mutation.expected_index,
                            mutation.local_id,
                            mutation.operation,
                            mutation.operands,
                            result_type,
                            mutation.constant_value,
                        )
                    )
            translated_reads = []
            for handle in transaction.read_set:
                translated = translate(handle)
                if translated is None:
                    return reject(handle, "WORKSPACE-REBASE-READ-UNCHANGED", "unchanged read entity at current root", "changed, missing, or unbound")
                translated_reads.append(translated)
            binding_maps = {
                "node": self._node_bindings,
                "object": self._object_bindings,
                "function": self._function_bindings,
                "value": self._value_bindings,
                "type": self._type_bindings,
            }
            for kind, handle, binding in bindings_to_publish:
                binding_maps[kind][handle] = binding
            rebased = Transaction(current_root, tuple(translated_mutations), tuple(translated_reads))
        result = self.commit(rebased)
        with self._lock:
            self.accounting.transaction_bytes += size - result.transaction_bytes
        return replace(result, transaction_bytes=size)

    def _rejected(self, size: int, diagnostic: Diagnostic, verified: int = 0) -> TransactionResult:
        self.accounting.rejected_transactions += 1
        self.accounting.verified_objects += verified
        return TransactionResult(False, self._reader.root_cid, (), diagnostic, size, 0, len(tuple(self._reader.objects())), verified)


def _diagnostic(code: str, entity: str, rule: str, expected: object, actual: object, repair: tuple[str, ...]) -> Diagnostic:
    return Diagnostic(code, entity, rule, expected, actual, (), repair)


def _query_size(response: object) -> int:
    # ponytail: JSON is removable measurement framing, never authoritative XAX source.
    return len(json.dumps(asdict(response), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def _value_handle(function_handle: str, value: ValueRef) -> str:
    if value.tag == 0:
        return f"{function_handle}.B{value.block}.P{value.index}"
    return f"{function_handle}.B{value.block}.N{value.index}.R{value.result}"


def _value_relation(value: ValueRef) -> tuple[int, int, int, int]:
    return value.tag, value.block, value.index, value.result


def _mutation_sort_key(mutation: Mutation) -> tuple[object, ...]:
    # ponytail: deterministic bootstrap ordering only; never authoritative XAX syntax.
    if isinstance(mutation, DisconnectEdgeArgument):
        return (mutation.node, 0, mutation.expected_block, mutation.edge_index, mutation.argument_index)
    if isinstance(mutation, ConnectEdgeArgument):
        return (mutation.node, 1, mutation.expected_block, mutation.edge_index, mutation.argument_index)
    if isinstance(mutation, MovePureNode):
        return (
            mutation.node,
            3,
            mutation.expected_block,
            mutation.expected_index,
            mutation.destination,
            mutation.expected_destination_block,
            mutation.expected_destination_index,
        )
    if isinstance(mutation, SpecializeFunction):
        return (
            mutation.function,
            4,
            tuple((argument.parameter, argument.expected_type, argument.value) for argument in sorted(mutation.arguments, key=lambda item: item.parameter)),
        )
    return (mutation.node, 2, type(mutation).__name__)


def _transaction_size(transaction: Transaction) -> int:
    def value_size(value: ValueRef | TransactionValueRef) -> int:
        if isinstance(value, TransactionValueRef):
            return 1 + len(uleb(value.insertion)) + len(uleb(value.result))
        return sum(len(uleb(part)) for part in (value.tag, value.block, value.index, value.result))

    read_handles = tuple(handle.encode() for handle in sorted(set(transaction.read_set)))
    mutations = tuple(sorted(transaction.mutations, key=_mutation_sort_key))
    root_size = 1 + len(uleb(transaction.expected_root.generation)) if isinstance(transaction.expected_root, RootRef) else 32
    size = 1 + root_size + len(uleb(len(read_handles)))
    size += sum(len(uleb(len(read_handle))) + len(read_handle) for read_handle in read_handles)
    size += len(uleb(len(mutations)))
    for mutation in mutations:
        handle = mutation.node.encode()
        size += 1 + len(uleb(len(handle))) + len(handle)
        if isinstance(mutation, ReplaceUse):
            size += len(uleb(mutation.operand_index))
            size += value_size(mutation.expected) + value_size(mutation.value)
        elif isinstance(mutation, DeleteNode):
            size += len(uleb(mutation.expected_block)) + len(uleb(mutation.expected_index))
        elif isinstance(mutation, DisconnectEdgeArgument):
            size += sum(len(uleb(value)) for value in (mutation.expected_block, mutation.edge_index, mutation.argument_index))
            size += value_size(mutation.expected)
        elif isinstance(mutation, ConnectEdgeArgument):
            size += sum(len(uleb(value)) for value in (mutation.expected_block, mutation.edge_index, mutation.argument_index))
            size += value_size(mutation.value)
        elif isinstance(mutation, MovePureNode):
            destination = mutation.destination.encode()
            size += len(uleb(mutation.expected_block)) + len(uleb(mutation.expected_index))
            size += len(uleb(len(destination))) + len(destination)
            size += len(uleb(mutation.expected_destination_block)) + len(uleb(mutation.expected_destination_index))
        elif isinstance(mutation, InsertPureNode):
            type_handle = mutation.result_type.encode()
            size += sum(len(uleb(value)) for value in (mutation.expected_block, mutation.expected_index, mutation.local_id, int(mutation.operation)))
            size += len(uleb(len(type_handle))) + len(type_handle)
            size += len(uleb(len(mutation.operands))) + sum(value_size(value) for value in mutation.operands)
            size += 1
            if mutation.constant_value is not None:
                size += len(uleb(zigzag(mutation.constant_value)))
        elif isinstance(mutation, SpecializeFunction):
            arguments = tuple(sorted(mutation.arguments, key=lambda argument: argument.parameter))
            size += len(uleb(len(arguments)))
            for argument in arguments:
                type_handle = argument.expected_type.encode()
                size += len(uleb(argument.parameter))
                size += len(uleb(len(type_handle))) + len(type_handle)
                size += len(uleb(zigzag(argument.value)))
        else:
            values = (int(mutation.expected), int(mutation.value))
            if isinstance(mutation, SetConstant):
                values = tuple(zigzag(value) for value in values)
            size += sum(len(uleb(value)) for value in values)
    return size


def _candidate(
    reader: StoreReader,
    bindings: tuple[tuple[bytes, int, int], ...],
    mutations: tuple[Mutation | _ResolvedInsertPureNode | _ResolvedSpecializeFunction, ...],
    users: dict[bytes, tuple[bytes, ...]],
) -> tuple[StoreReader, tuple[bytes, ...], int, int, tuple[bytes, ...]]:
    specializations = tuple(mutation for mutation in mutations if isinstance(mutation, _ResolvedSpecializeFunction))
    if specializations:
        if len(mutations) != 1:
            fail(
                "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                specializations[0].function,
                "WORKSPACE-SPECIALIZE-SINGLE-MUTATION",
                1,
                len(mutations),
                repair_neighborhood=(specializations[0].function,),
            )
        return _specialization_candidate(reader, bindings[0][0], specializations[0], users)
    objects = {obj.cid: obj for obj in reader.objects()}
    resolve = store_resolver(reader)
    grouped: dict[bytes, list[tuple[tuple[bytes, int, int], Mutation | _ResolvedInsertPureNode]]] = {}
    for binding, mutation in zip(bindings, mutations):
        grouped.setdefault(binding[0], []).append((binding, mutation))
    seeds = frozenset(grouped)
    affected = _affected_users(seeds, users, resolve, mutations[0].node)
    replacements = {}
    seed_dependencies = {}
    for function_cid in seeds:
        graph_object, _, _ = _decode_function_interface(resolve(function_cid), resolve)
        graph = _parse_graph(graph_object, resolve)
        seed_dependencies[function_cid] = {
            node.entity.cid
            for block in graph.blocks
            for node in block.nodes
            if node.operation == Operation.CALL_DIRECT and node.entity.cid in seeds
        }
    remaining_seeds = set(seeds)
    while remaining_seeds:
        ready = sorted(cid for cid in remaining_seeds if seed_dependencies[cid] <= replacements.keys())
        if not ready:
            fail("XAX.WORKSPACE.TOPOLOGY", mutations[0].node, "WORKSPACE-EDITED-FUNCTION-DAG", "acyclic edited functions", "cycle", repair_neighborhood=(mutations[0].node,))
        for function_cid in ready:
            replacement = _mutate_function(resolve(function_cid), tuple(grouped[function_cid]), objects, resolve, replacements)
            replacements[function_cid] = replacement
            objects[replacement.cid] = replacement
            remaining_seeds.remove(function_cid)

    remaining = affected - seeds
    while remaining:
        ready = sorted(
            cid
            for cid in remaining
            if all(reference not in affected or reference in replacements for reference in resolve(cid).references)
        )
        if not ready:
            fail("XAX.WORKSPACE.TOPOLOGY", mutations[0].node, "WORKSPACE-AFFECTED-DAG", "acyclic affected users", "cycle", repair_neighborhood=(mutations[0].node,))
        for user_cid in ready:
            replacement = _rebuild_user(resolve(user_cid), replacements, resolve, mutations[0].node)
            replacements[user_cid] = replacement
            objects[replacement.cid] = replacement
            remaining.remove(user_cid)
    try:
        new_root = replacements[reader.root_cid]
    except KeyError:
        fail("XAX.WORKSPACE.TOPOLOGY", mutations[0].node, "WORKSPACE-ROOT-REBUILT", "changed function reachable from root", "no rebuilt root", repair_neighborhood=(mutations[0].node,))

    reachable: dict[bytes, SemanticObject] = {}
    pending = [new_root.cid]
    while pending:
        cid = pending.pop()
        if cid in reachable:
            continue
        obj = objects[cid]
        reachable[cid] = obj
        pending.extend(obj.references)
    candidate = StoreReader.from_objects(new_root.cid, reachable.values(), reader.nonsemantic_records, proof_cache=reader.proof_cache)
    old_cids = {obj.cid for obj in reader.objects()}
    frontier = tuple(sorted(set(reachable) - old_cids))
    touched = len(frontier)
    reused = len(set(reachable) & old_cids)
    changed = tuple(replacements[cid].cid for cid in sorted(seeds))
    return candidate, changed, touched, reused, frontier


def _specialization_candidate(
    reader: StoreReader,
    function_cid: bytes,
    mutation: _ResolvedSpecializeFunction,
    users: dict[bytes, tuple[bytes, ...]],
) -> tuple[StoreReader, tuple[bytes, ...], int, int, tuple[bytes, ...]]:
    objects = {obj.cid: obj for obj in reader.objects()}
    resolve = store_resolver(reader)
    specialized = _specialize_function(resolve(function_cid), mutation, objects, resolve)
    module_cids = tuple(
        sorted(cid for cid in users.get(function_cid, ()) if resolve(cid).kind == Kind.MODULE)
    )
    if not module_cids:
        fail(
            "XAX.WORKSPACE.TOPOLOGY",
            mutation.function,
            "WORKSPACE-SPECIALIZE-STANDALONE-MODULE",
            "standalone function referenced by a module",
            "missing module reference",
            repair_neighborhood=(mutation.function,),
        )

    replacements: dict[bytes, SemanticObject] = {}
    for module_cid in module_cids:
        module = resolve(module_cid)
        if specialized.cid in module.references:
            fail(
                "XAX.WORKSPACE.RELATION_CONFLICT",
                mutation.function,
                "WORKSPACE-SPECIALIZATION-ABSENT",
                "new specialized function",
                specialized.cid.hex(),
                repair_neighborhood=(mutation.function,),
            )
        replacement = object_with_refs(
            Kind.MODULE,
            (*tuple(resolve(cid) for cid in module.references), specialized),
        )
        replacements[module_cid] = replacement
        objects[replacement.cid] = replacement

    seeds = frozenset(module_cids)
    affected = _affected_users(seeds, users, resolve, mutation.function)
    remaining = affected - seeds
    while remaining:
        ready = sorted(
            cid
            for cid in remaining
            if all(reference not in affected or reference in replacements for reference in resolve(cid).references)
        )
        if not ready:
            fail(
                "XAX.WORKSPACE.TOPOLOGY",
                mutation.function,
                "WORKSPACE-SPECIALIZE-AFFECTED-DAG",
                "acyclic module users",
                "cycle",
                repair_neighborhood=(mutation.function,),
            )
        for user_cid in ready:
            replacement = _rebuild_user(resolve(user_cid), replacements, resolve, mutation.function)
            replacements[user_cid] = replacement
            objects[replacement.cid] = replacement
            remaining.remove(user_cid)

    try:
        new_root = replacements[reader.root_cid]
    except KeyError:
        fail(
            "XAX.WORKSPACE.TOPOLOGY",
            mutation.function,
            "WORKSPACE-ROOT-REBUILT",
            "containing module reachable from root",
            "no rebuilt root",
            repair_neighborhood=(mutation.function,),
        )

    reachable: dict[bytes, SemanticObject] = {}
    pending = [new_root.cid]
    while pending:
        cid = pending.pop()
        if cid in reachable:
            continue
        obj = objects[cid]
        reachable[cid] = obj
        pending.extend(obj.references)
    candidate = StoreReader.from_objects(new_root.cid, reachable.values(), reader.nonsemantic_records, proof_cache=reader.proof_cache)
    old_cids = {obj.cid for obj in reader.objects()}
    frontier = tuple(sorted(set(reachable) - old_cids))
    return candidate, (specialized.cid,), len(frontier), len(set(reachable) & old_cids), frontier


def _specialize_function(
    function_object: SemanticObject,
    mutation: _ResolvedSpecializeFunction,
    objects: dict[bytes, SemanticObject],
    resolve: Callable[[bytes], SemanticObject],
) -> SemanticObject:
    graph_object, parameter_cids, return_cids = _decode_function_interface(function_object, resolve)
    graph = _parse_graph(graph_object, resolve)
    if len(graph.blocks) != 1 or graph.entry != 0:
        fail(
            "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
            mutation.function,
            "WORKSPACE-SPECIALIZE-SINGLE-BLOCK",
            "one entry block",
            len(graph.blocks),
            repair_neighborhood=(mutation.function,),
        )
    if not mutation.arguments:
        fail(
            "XAX.WORKSPACE.INVALID_VALUE",
            mutation.function,
            "WORKSPACE-SPECIALIZE-ARGUMENT-NONEMPTY",
            ">= 1 constant argument",
            0,
            repair_neighborhood=(mutation.function,),
        )
    allowed = {Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP}
    block = graph.blocks[0]
    if block.terminator.edges:
        fail(
            "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
            mutation.function,
            "WORKSPACE-SPECIALIZE-STRAIGHT-LINE",
            "return or trap terminator",
            block.terminator.kind.name,
            repair_neighborhood=(mutation.function,),
        )
    unsupported = next((Operation(node.operation) for node in block.nodes if Operation(node.operation) not in allowed), None)
    if unsupported is not None:
        fail(
            "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
            mutation.function,
            "WORKSPACE-SPECIALIZE-PURE-SUBSET",
            sorted(operation.name for operation in allowed),
            unsupported.name,
            repair_neighborhood=(mutation.function,),
        )

    arguments = tuple(sorted(mutation.arguments, key=lambda argument: argument.parameter))
    indices = tuple(argument.parameter for argument in arguments)
    if len(set(indices)) != len(indices):
        fail(
            "XAX.WORKSPACE.DUPLICATE_MUTATION",
            mutation.function,
            "WORKSPACE-SPECIALIZE-PARAMETER-UNIQUE",
            "one constant per parameter",
            indices,
            repair_neighborhood=(mutation.function,),
        )

    specialized_parameters: dict[int, int] = {}
    constant_nodes = []
    for node_index, argument in enumerate(arguments):
        if argument.parameter >= len(parameter_cids):
            fail(
                "XAX.WORKSPACE.RELATION_CONFLICT",
                mutation.function,
                "WORKSPACE-SPECIALIZE-PARAMETER-INDEX",
                f"0..{len(parameter_cids) - 1}",
                argument.parameter,
                repair_neighborhood=(mutation.function,),
            )
        actual_type_cid = parameter_cids[argument.parameter]
        if actual_type_cid != argument.expected_type_cid:
            fail(
                "XAX.WORKSPACE.ATTRIBUTE_CONFLICT",
                mutation.function,
                "WORKSPACE-SPECIALIZE-PARAMETER-TYPE",
                argument.expected_type_cid.hex(),
                actual_type_cid.hex(),
                repair_neighborhood=(mutation.function,),
            )
        type_object = resolve(actual_type_cid)
        try:
            value = constant(type_object, argument.value)
        except ValueError:
            fail(
                "XAX.WORKSPACE.INVALID_VALUE",
                mutation.function,
                "WORKSPACE-SPECIALIZE-CONSTANT-RANGE",
                f"value fitting {actual_type_cid.hex()}",
                argument.value,
                repair_neighborhood=(mutation.function,),
            )
        objects[value.cid] = value
        specialized_parameters[argument.parameter] = node_index
        constant_nodes.append(Node(Operation.CONSTANT, (), (type_object,), entity=value))

    remaining_indices = tuple(index for index in range(len(parameter_cids)) if index not in specialized_parameters)
    remaining_parameter_index = {old: new for new, old in enumerate(remaining_indices)}
    inserted_count = len(constant_nodes)

    def remap(value: ValueRef) -> ValueRef:
        if value.tag == 0:
            if value.index in specialized_parameters:
                return ValueRef.node_result(0, specialized_parameters[value.index], value.result)
            return ValueRef.parameter(0, remaining_parameter_index[value.index])
        return ValueRef.node_result(0, value.index + inserted_count, value.result)

    nodes = tuple(constant_nodes) + tuple(
        Node(
            Operation(node.operation),
            tuple(remap(value) for value in node.operands),
            tuple(resolve(cid) for cid in node.results),
            node.member,
            node.entity,
            node.attributes,
        )
        for node in block.nodes
    )
    terminator = Terminator(
        block.terminator.kind,
        tuple(remap(value) for value in block.terminator.values),
        tuple(
            (target, tuple(remap(value) for value in arguments))
            for target, arguments in block.terminator.edges
        ),
        block.terminator.payload,
    )
    specialized_graph = graph_fragment(
        [Block(tuple(resolve(parameter_cids[index]) for index in remaining_indices), nodes, terminator)]
    )
    specialized = function(
        specialized_graph,
        tuple(resolve(parameter_cids[index]) for index in remaining_indices),
        tuple(resolve(cid) for cid in return_cids),
    )
    objects[specialized_graph.cid] = specialized_graph
    objects[specialized.cid] = specialized
    return specialized


def _mutate_function(
    function_object: SemanticObject,
    edits: tuple[tuple[tuple[bytes, int, int], Mutation | _ResolvedInsertPureNode], ...],
    objects: dict[bytes, SemanticObject],
    resolve: Callable[[bytes], SemanticObject],
    external_replacements: dict[bytes, SemanticObject] | None = None,
) -> SemanticObject:
    external_replacements = external_replacements or {}
    graph_object, parameter_cids, return_cids = _decode_function_interface(function_object, resolve)
    graph = _parse_graph(graph_object, resolve)
    replacements_by_node = {}
    deletions: set[tuple[int, int]] = set()
    insertions: dict[tuple[int, int], _ResolvedInsertPureNode] = {}
    insertion_by_local: dict[int, tuple[int, int]] = {}
    edge_disconnects: dict[tuple[int, int, int], DisconnectEdgeArgument] = {}
    edge_connects: dict[tuple[int, int, int], ConnectEdgeArgument] = {}
    moves: dict[tuple[int, int], MovePureNode] = {}
    move_index_maps: dict[int, dict[int, int]] = {}

    def uses_deleted(value: ValueRef, target_block: int, target_node: int) -> bool:
        return value.tag == 1 and value.block == target_block and value.index == target_node

    def remap_value(value: ValueRef) -> ValueRef:
        if value.tag != 1:
            return value
        move_map = move_index_maps.get(value.block)
        if move_map is not None:
            return ValueRef.node_result(value.block, move_map[value.index], value.result)
        deleted_before = sum(1 for block_index, node_index in deletions if block_index == value.block and node_index < value.index)
        inserted_before_or_at = sum(1 for block_index, node_index in insertions if block_index == value.block and node_index <= value.index)
        shift = inserted_before_or_at - deleted_before
        return ValueRef.node_result(value.block, value.index + shift, value.result) if shift else value

    def inserted_value(value: TransactionValueRef, entity: str) -> ValueRef:
        location = insertion_by_local.get(value.insertion)
        if location is None:
            fail(
                "XAX.WORKSPACE.RELATION_CONFLICT",
                entity,
                "WORKSPACE-INSERT-LOCAL-VALUE",
                "transaction-local inserted result in the same function",
                f"I{value.insertion}.R{value.result}",
                repair_neighborhood=(entity,),
            )
        if value.result != 0:
            fail(
                "XAX.WORKSPACE.RELATION_CONFLICT",
                entity,
                "WORKSPACE-INSERT-LOCAL-RESULT",
                0,
                value.result,
                repair_neighborhood=(entity,),
            )
        block_index, node_index = location
        deleted_before = sum(1 for b, n in deletions if b == block_index and n < node_index)
        inserted_before = sum(1 for b, n in insertions if b == block_index and n < node_index)
        return ValueRef.node_result(block_index, node_index - deleted_before + inserted_before, 0)

    def remap_mutation_value(value: ValueRef | TransactionValueRef, entity: str) -> ValueRef:
        return inserted_value(value, entity) if isinstance(value, TransactionValueRef) else remap_value(value)

    for (_, target_block, target_node), mutation in edits:
        try:
            selected = graph.blocks[target_block].nodes[target_node]
        except IndexError:
            fail("XAX.WORKSPACE.HANDLE", mutation.node, "WORKSPACE-NODE-EXISTS", "bound node", "missing", repair_neighborhood=(mutation.node,))
        if isinstance(mutation, (DisconnectEdgeArgument, ConnectEdgeArgument)):
            if target_block != mutation.expected_block:
                fail(
                    "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                    mutation.node,
                    "WORKSPACE-EDGE-CONTAINMENT",
                    mutation.expected_block,
                    target_block,
                    repair_neighborhood=(mutation.node,),
                )
            term = graph.blocks[target_block].terminator
            if mutation.edge_index >= len(term.edges):
                fail(
                    "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                    mutation.node,
                    "WORKSPACE-TERMINATOR-EDGE",
                    f"< {len(term.edges)}",
                    mutation.edge_index,
                    repair_neighborhood=(mutation.node,),
                )
            arguments = term.edges[mutation.edge_index][1]
            key = (target_block, mutation.edge_index, mutation.argument_index)
            if isinstance(mutation, DisconnectEdgeArgument):
                if mutation.argument_index >= len(arguments):
                    fail(
                        "XAX.WORKSPACE.RELATION_CONFLICT",
                        mutation.node,
                        "WORKSPACE-EDGE-ARGUMENT-INDEX",
                        f"< {len(arguments)}",
                        mutation.argument_index,
                        repair_neighborhood=(mutation.node,),
                    )
                actual = arguments[mutation.argument_index]
                if actual != mutation.expected:
                    fail(
                        "XAX.WORKSPACE.RELATION_CONFLICT",
                        mutation.node,
                        "WORKSPACE-EDGE-ARGUMENT-PRECONDITION",
                        _value_relation(mutation.expected),
                        _value_relation(actual),
                        repair_neighborhood=(mutation.node,),
                    )
                if key in edge_disconnects:
                    fail(
                        "XAX.WORKSPACE.DUPLICATE_MUTATION",
                        mutation.node,
                        "WORKSPACE-EDGE-ARGUMENT-DISCONNECT-UNIQUE",
                        "one disconnect per edge-argument slot",
                        "duplicate",
                        repair_neighborhood=(mutation.node,),
                    )
                edge_disconnects[key] = mutation
            else:
                if mutation.argument_index > len(arguments):
                    fail(
                        "XAX.WORKSPACE.RELATION_CONFLICT",
                        mutation.node,
                        "WORKSPACE-EDGE-ARGUMENT-INDEX",
                        f"<= {len(arguments)}",
                        mutation.argument_index,
                        repair_neighborhood=(mutation.node,),
                    )
                if key in edge_connects:
                    fail(
                        "XAX.WORKSPACE.DUPLICATE_MUTATION",
                        mutation.node,
                        "WORKSPACE-EDGE-ARGUMENT-CONNECT-UNIQUE",
                        "one connect per edge-argument slot",
                        "duplicate",
                        repair_neighborhood=(mutation.node,),
                    )
                edge_connects[key] = mutation
            continue
        if isinstance(mutation, MovePureNode):
            actual_containment = (target_block, target_node)
            expected_containment = (mutation.expected_block, mutation.expected_index)
            if actual_containment != expected_containment:
                fail(
                    "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                    mutation.node,
                    "WORKSPACE-MOVE-SOURCE",
                    expected_containment,
                    actual_containment,
                    repair_neighborhood=(mutation.node, mutation.destination),
                )
            if mutation.expected_destination_block != target_block:
                fail(
                    "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                    mutation.node,
                    "WORKSPACE-MOVE-SAME-BLOCK",
                    target_block,
                    mutation.expected_destination_block,
                    repair_neighborhood=(mutation.node, mutation.destination),
                )
            if mutation.expected_destination_index >= len(graph.blocks[target_block].nodes):
                fail(
                    "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                    mutation.destination,
                    "WORKSPACE-MOVE-DESTINATION",
                    f"< {len(graph.blocks[target_block].nodes)}",
                    mutation.expected_destination_index,
                    repair_neighborhood=(mutation.node, mutation.destination),
                )
            if mutation.expected_destination_index == target_node:
                fail(
                    "XAX.WORKSPACE.RELATION_CONFLICT",
                    mutation.node,
                    "WORKSPACE-MOVE-SELF-ANCHOR",
                    "distinct destination anchor",
                    mutation.destination,
                    repair_neighborhood=(mutation.node, mutation.destination),
                )
            if Operation(selected.operation) not in (
                Operation.CONSTANT,
                Operation.ADD_WRAP,
                Operation.SUB_WRAP,
                Operation.MUL_WRAP,
            ):
                fail(
                    "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                    mutation.node,
                    "WORKSPACE-MOVE-PURE-NODE",
                    [Operation.CONSTANT.name, Operation.ADD_WRAP.name, Operation.SUB_WRAP.name, Operation.MUL_WRAP.name],
                    Operation(selected.operation).name,
                    repair_neighborhood=(mutation.node,),
                )
            if moves:
                fail(
                    "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                    mutation.node,
                    "WORKSPACE-MOVE-SINGLE-PER-FUNCTION",
                    1,
                    len(moves) + 1,
                    repair_neighborhood=(mutation.node,),
                )
            moves[(target_block, target_node)] = mutation
            continue
        if isinstance(mutation, _ResolvedInsertPureNode):
            actual_containment = (target_block, target_node)
            expected_containment = (mutation.expected_block, mutation.expected_index)
            if actual_containment != expected_containment:
                fail(
                    "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                    mutation.node,
                    "WORKSPACE-INSERT-POSITION",
                    expected_containment,
                    actual_containment,
                    repair_neighborhood=(mutation.node,),
                )
            if mutation.operation not in (Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                fail(
                    "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                    mutation.node,
                    "WORKSPACE-INSERT-PURE-NODE",
                    [Operation.CONSTANT.name, Operation.ADD_WRAP.name, Operation.SUB_WRAP.name, Operation.MUL_WRAP.name],
                    mutation.operation.name,
                    repair_neighborhood=(mutation.node,),
                )
            if mutation.local_id in insertion_by_local:
                fail(
                    "XAX.WORKSPACE.DUPLICATE_MUTATION",
                    f"I{mutation.local_id}",
                    "WORKSPACE-INSERT-LOCAL-ID-UNIQUE",
                    "one inserted node per transaction-local id",
                    "duplicate",
                    repair_neighborhood=(mutation.node,),
                )
            insertions[(target_block, target_node)] = mutation
            insertion_by_local[mutation.local_id] = (target_block, target_node)
            continue
        if isinstance(mutation, DeleteNode):
            actual_containment = (target_block, target_node)
            expected_containment = (mutation.expected_block, mutation.expected_index)
            if actual_containment != expected_containment:
                fail(
                    "XAX.WORKSPACE.CONTAINMENT_CONFLICT",
                    mutation.node,
                    "WORKSPACE-NODE-CONTAINMENT",
                    expected_containment,
                    actual_containment,
                    repair_neighborhood=(mutation.node,),
                )
            if Operation(selected.operation) not in (Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                fail(
                    "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
                    mutation.node,
                    "WORKSPACE-DELETE-PURE-NODE",
                    [Operation.CONSTANT.name, Operation.ADD_WRAP.name, Operation.SUB_WRAP.name, Operation.MUL_WRAP.name],
                    Operation(selected.operation).name,
                    repair_neighborhood=(mutation.node,),
                )
            for block in graph.blocks:
                for node in block.nodes:
                    for operand in node.operands:
                        if uses_deleted(operand, target_block, target_node):
                            fail(
                                "XAX.WORKSPACE.DELETE_USE_CONFLICT",
                                mutation.node,
                                "WORKSPACE-DELETE-NODE-UNUSED",
                                "zero semantic uses",
                                _value_relation(operand),
                                repair_neighborhood=(mutation.node,),
                            )
                for value in block.terminator.values:
                    if uses_deleted(value, target_block, target_node):
                        fail(
                            "XAX.WORKSPACE.DELETE_USE_CONFLICT",
                            mutation.node,
                            "WORKSPACE-DELETE-NODE-UNUSED",
                            "zero semantic uses",
                            _value_relation(value),
                            repair_neighborhood=(mutation.node,),
                        )
                for _, arguments in block.terminator.edges:
                    for value in arguments:
                        if uses_deleted(value, target_block, target_node):
                            fail(
                                "XAX.WORKSPACE.DELETE_USE_CONFLICT",
                                mutation.node,
                                "WORKSPACE-DELETE-NODE-UNUSED",
                                "zero semantic uses",
                                _value_relation(value),
                                repair_neighborhood=(mutation.node,),
                            )
            deletions.add((target_block, target_node))
            continue

        replacement_entity = selected.entity
        replacement_operation = Operation(selected.operation)
        replacement_operands = selected.operands
        if isinstance(mutation, SetOperation):
            if replacement_operation != mutation.expected:
                fail("XAX.WORKSPACE.ATTRIBUTE_CONFLICT", mutation.node, "WORKSPACE-OP-PRECONDITION", mutation.expected.name, replacement_operation.name, repair_neighborhood=(mutation.node,))
            if mutation.value not in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP) or replacement_operation not in (Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP):
                fail("XAX.WORKSPACE.UNSUPPORTED_MUTATION", mutation.node, "WORKSPACE-OP-CONTRACT-PRESERVED", "wrapping arithmetic replacement", mutation.value.name, repair_neighborhood=(mutation.node,))
            replacement_operation = mutation.value
        elif isinstance(mutation, SetConstant):
            if replacement_operation != Operation.CONSTANT:
                fail("XAX.WORKSPACE.ATTRIBUTE_CONFLICT", mutation.node, "WORKSPACE-CONSTANT-NODE", Operation.CONSTANT.name, replacement_operation.name, repair_neighborhood=(mutation.node,))
            type_cid, value = _decode_constant(selected.entity, resolve)
            if value != mutation.expected:
                fail("XAX.WORKSPACE.ATTRIBUTE_CONFLICT", mutation.node, "WORKSPACE-CONSTANT-PRECONDITION", mutation.expected, value, repair_neighborhood=(mutation.node,))
            try:
                replacement_entity = constant(resolve(type_cid), mutation.value)
            except ValueError:
                fail("XAX.WORKSPACE.INVALID_VALUE", mutation.node, "WORKSPACE-CONSTANT-RANGE", f"value fitting {type_cid.hex()}", mutation.value, repair_neighborhood=(mutation.node,))
            objects[replacement_entity.cid] = replacement_entity
        elif isinstance(mutation, ReplaceUse):
            if mutation.operand_index >= len(selected.operands):
                fail(
                    "XAX.WORKSPACE.RELATION_CONFLICT",
                    mutation.node,
                    "WORKSPACE-OPERAND-INDEX",
                    f"< {len(selected.operands)}",
                    mutation.operand_index,
                    repair_neighborhood=(mutation.node,),
                )
            actual = selected.operands[mutation.operand_index]
            if actual != mutation.expected:
                fail(
                    "XAX.WORKSPACE.RELATION_CONFLICT",
                    mutation.node,
                    "WORKSPACE-OPERAND-PRECONDITION",
                    _value_relation(mutation.expected),
                    _value_relation(actual),
                    repair_neighborhood=(mutation.node,),
                )
            operands = list(selected.operands)
            operands[mutation.operand_index] = mutation.value
            replacement_operands = tuple(operands)
        else:
            raise AssertionError(f"unhandled mutation {type(mutation)!r}")
        replacements_by_node[(target_block, target_node)] = (replacement_operation, replacement_entity, replacement_operands)

    if moves and (insertions or deletions):
        move = next(iter(moves.values()))
        fail(
            "XAX.WORKSPACE.UNSUPPORTED_MUTATION",
            move.node,
            "WORKSPACE-MOVE-STRUCTURAL-COMBINATION",
            "move without insert/delete in the same function",
            {"insertions": len(insertions), "deletions": len(deletions)},
            repair_neighborhood=(move.node,),
        )
    for (block_index, source_index), move in moves.items():
        order = [index for index in range(len(graph.blocks[block_index].nodes)) if index != source_index]
        try:
            anchor_position = order.index(move.expected_destination_index)
        except ValueError:
            fail(
                "XAX.WORKSPACE.RELATION_CONFLICT",
                move.node,
                "WORKSPACE-MOVE-DESTINATION",
                "existing destination anchor distinct from source",
                move.expected_destination_index,
                repair_neighborhood=(move.node, move.destination),
            )
        order.insert(anchor_position, source_index)
        move_index_maps[block_index] = {old_index: new_index for new_index, old_index in enumerate(order)}

    blocks: list[Block] = []
    for block_index, block in enumerate(graph.blocks):
        nodes: list[Node] = []
        node_indices = list(range(len(block.nodes)))
        move_map = move_index_maps.get(block_index)
        if move_map is not None:
            node_indices.sort(key=move_map.__getitem__)
        for node_index in node_indices:
            node = block.nodes[node_index]
            insertion = insertions.get((block_index, node_index))
            if insertion is not None:
                result_type_cid = insertion.result_type_cid
                result_type = resolve(result_type_cid)
                entity = None
                if insertion.operation == Operation.CONSTANT:
                    if insertion.constant_value is None:
                        fail(
                            "XAX.WORKSPACE.INVALID_VALUE",
                            insertion.node,
                            "WORKSPACE-INSERT-CONSTANT-VALUE",
                            "integer constant value",
                            None,
                            repair_neighborhood=(insertion.node,),
                        )
                    try:
                        entity = constant(result_type, insertion.constant_value)
                    except ValueError:
                        fail(
                            "XAX.WORKSPACE.INVALID_VALUE",
                            insertion.node,
                            "WORKSPACE-CONSTANT-RANGE",
                            f"value fitting {result_type_cid.hex()}",
                            insertion.constant_value,
                            repair_neighborhood=(insertion.node,),
                        )
                    objects[entity.cid] = entity
                elif insertion.constant_value is not None:
                    fail(
                        "XAX.WORKSPACE.INVALID_VALUE",
                        insertion.node,
                        "WORKSPACE-INSERT-CONSTANT-ABSENT",
                        None,
                        insertion.constant_value,
                        repair_neighborhood=(insertion.node,),
                    )
                nodes.append(
                    Node(
                        insertion.operation,
                        tuple(remap_mutation_value(value, insertion.node) for value in insertion.operands),
                        (result_type,),
                        entity=entity,
                    )
                )
            if (block_index, node_index) in deletions:
                continue
            operation, entity, operands = replacements_by_node.get(
                (block_index, node_index),
                (Operation(node.operation), node.entity, node.operands),
            )
            if entity is not None:
                entity = external_replacements.get(entity.cid, entity)
            nodes.append(
                Node(
                    operation,
                    tuple(remap_mutation_value(value, f"B{block_index}.N{node_index}") for value in operands),
                    tuple(resolve(cid) for cid in node.results),
                    node.member,
                    entity,
                    node.attributes,
                )
            )
        term = block.terminator
        remapped_edges = []
        for edge_index, (target, arguments) in enumerate(term.edges):
            remapped_arguments = []
            for argument_index in range(len(arguments) + 1):
                key = (block_index, edge_index, argument_index)
                connection = edge_connects.get(key)
                if connection is not None:
                    remapped_arguments.append(remap_mutation_value(connection.value, connection.node))
                if argument_index < len(arguments) and key not in edge_disconnects:
                    remapped_arguments.append(remap_value(arguments[argument_index]))
            remapped_edges.append((target, tuple(remapped_arguments)))
        remapped_term = Terminator(
            term.kind,
            tuple(remap_value(value) for value in term.values),
            tuple(remapped_edges),
            term.payload,
        )
        blocks.append(Block(tuple(resolve(cid) for cid in block.parameters), tuple(nodes), remapped_term))
    new_graph = graph_fragment(blocks, graph.entry)
    new_function = function(new_graph, tuple(resolve(cid) for cid in parameter_cids), tuple(resolve(cid) for cid in return_cids))
    objects[new_graph.cid] = new_graph
    return new_function


def _affected_users(
    seeds: frozenset[bytes],
    users: dict[bytes, tuple[bytes, ...]],
    resolve: Callable[[bytes], SemanticObject],
    entity: str,
) -> set[bytes]:
    affected = set(seeds)
    for seed in sorted(seeds):
        pending = [seed]
        seen = {seed}
        while pending:
            child = pending.pop()
            for user_cid in users.get(child, ()):
                user = resolve(user_cid)
                if user.kind == Kind.RECURSION_GROUP:
                    fail("XAX.WORKSPACE.TOPOLOGY", entity, "WORKSPACE-RECURSION-REBUILD", "non-recursive direct-call users", Kind.RECURSION_GROUP.name, repair_neighborhood=(entity,))
                if user.kind not in (Kind.GRAPH_FRAGMENT, Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT):
                    fail("XAX.WORKSPACE.TOPOLOGY", entity, "WORKSPACE-SUPPORTED-USER", [Kind.GRAPH_FRAGMENT.name, Kind.FUNCTION.name, Kind.MODULE.name, Kind.PROGRAM_ROOT.name], user.kind.name, repair_neighborhood=(entity,))
                affected.add(user_cid)
                if user_cid not in seen:
                    seen.add(user_cid)
                    pending.append(user_cid)
    return affected


def _rebuild_user(
    user: SemanticObject,
    replacements: dict[bytes, SemanticObject],
    resolve: Callable[[bytes], SemanticObject],
    entity: str,
) -> SemanticObject:
    def replacement(cid: bytes) -> SemanticObject:
        return replacements[cid] if cid in replacements else resolve(cid)

    if user.kind == Kind.GRAPH_FRAGMENT:
        graph = _parse_graph(user, resolve)
        blocks = []
        for block in graph.blocks:
            nodes = tuple(
                Node(
                    Operation(node.operation),
                    node.operands,
                    tuple(replacement(cid) for cid in node.results),
                    node.member,
                    replacement(node.entity.cid) if node.entity is not None else None,
                    node.attributes,
                )
                for node in block.nodes
            )
            blocks.append(Block(tuple(replacement(cid) for cid in block.parameters), nodes, block.terminator))
        return graph_fragment(blocks, graph.entry)
    if user.kind == Kind.FUNCTION:
        graph, parameters, returns = _decode_function_interface(user, resolve)
        return function(replacement(graph.cid), tuple(replacement(cid) for cid in parameters), tuple(replacement(cid) for cid in returns))
    if user.kind in (Kind.MODULE, Kind.PROGRAM_ROOT):
        return object_with_refs(user.kind, tuple(replacement(cid) for cid in user.references))
    if user.kind == Kind.RECURSION_GROUP:
        fail("XAX.WORKSPACE.TOPOLOGY", entity, "WORKSPACE-RECURSION-REBUILD", "non-recursive direct-call users", Kind.RECURSION_GROUP.name, repair_neighborhood=(entity,))
    fail("XAX.WORKSPACE.TOPOLOGY", entity, "WORKSPACE-SUPPORTED-USER", [Kind.GRAPH_FRAGMENT.name, Kind.FUNCTION.name, Kind.MODULE.name, Kind.PROGRAM_ROOT.name], user.kind.name, repair_neighborhood=(entity,))
