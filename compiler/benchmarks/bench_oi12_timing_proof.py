"""OI-12 timing-proof sidecar experiment.

The proof carrier is benchmark-only and non-semantic.  It is keyed by exact
semantic/target/profile/model dependencies and can be deleted without changing
any XAX CID or executable meaning.  Timing samples are host observations of the
proof tooling, never target execution guarantees.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
import platform
import statistics
import time
from pathlib import Path
from typing import Iterable

from blake3 import blake3
from xax_compiler import (
    CID_SIZE,
    Block,
    Kind,
    Node,
    Operation,
    Permission,
    RealtimeProfile,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    _decode_function_interface,
    _parse_graph,
    _verified_resolver,
    analyze_realtime,
    aarch64_baremetal_general_target,
    bits_type,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    stack_owner_type,
    uleb,
    verify_store,
    write_store,
    x86_64_windows_target,
)


MAGIC = b"XTPF"
TRAILER = b"TP12"
VERSION = 1
TIMING_REPETITIONS = 31
MEMORY_OPERATIONS = frozenset((Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE))


class TimingProofError(ValueError):
    pass


def _take(data: bytes, pos: int, count: int, rule: str) -> tuple[bytes, int]:
    end = pos + count
    if count < 0 or end > len(data):
        raise TimingProofError(rule)
    return data[pos:end], end


def _read_uleb(data: bytes, pos: int, rule: str) -> tuple[int, int]:
    value = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data) or shift > 63:
            raise TimingProofError(rule)
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            if data[start:pos] != uleb(value):
                raise TimingProofError(f"{rule}:noncanonical")
            return value, pos
        shift += 7


def _encode_ascii(value: str) -> bytes:
    raw = value.encode("ascii")
    if not raw:
        raise ValueError("empty ASCII field")
    return uleb(len(raw)) + raw


def _read_ascii(data: bytes, pos: int, rule: str) -> tuple[str, int]:
    length, pos = _read_uleb(data, pos, rule)
    raw, pos = _take(data, pos, length, rule)
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise TimingProofError(rule) from error
    if not value:
        raise TimingProofError(rule)
    return value, pos


def _encode_optional(value: int | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + uleb(value)


def _read_optional(data: bytes, pos: int, rule: str) -> tuple[int | None, int]:
    flag, pos = _take(data, pos, 1, rule)
    if flag == b"\x00":
        return None, pos
    if flag != b"\x01":
        raise TimingProofError(rule)
    return _read_uleb(data, pos, rule)


@dataclass(frozen=True)
class TimingModel:
    identity: str
    version: int
    operation_cycles: tuple[tuple[int, int], ...]
    memory_extra_cycles: int | None
    max_interrupts: int | None
    interrupt_service_cycles: int | None
    interrupt_mask_bound_cycles: int | None
    require_memory_bound: bool
    require_interrupt_bound: bool

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("timing model version must be positive")
        if self.operation_cycles != tuple(sorted(set(self.operation_cycles))):
            raise ValueError("operation timing table must be sorted and unique")
        if any(op < 0 or cycles < 0 for op, cycles in self.operation_cycles):
            raise ValueError("operation timing entries must be nonnegative")

    def canonical_bytes(self) -> bytes:
        out = bytearray(_encode_ascii(self.identity) + uleb(self.version) + uleb(len(self.operation_cycles)))
        for operation, cycles in self.operation_cycles:
            out.extend(uleb(operation))
            out.extend(uleb(cycles))
        for value in (
            self.memory_extra_cycles,
            self.max_interrupts,
            self.interrupt_service_cycles,
            self.interrupt_mask_bound_cycles,
        ):
            out.extend(_encode_optional(value))
        out.extend(bytes((int(self.require_memory_bound), int(self.require_interrupt_bound))))
        return bytes(out)

    @property
    def assumption_fingerprint(self) -> bytes:
        return blake3(self.canonical_bytes()).digest()

    def operation_bound(self, operation: int) -> int:
        table = dict(self.operation_cycles)
        if operation not in table:
            raise TimingProofError(f"unknown-operation-timing:{operation}")
        return table[operation]

    def validate_assumptions(self) -> None:
        if self.require_memory_bound and self.memory_extra_cycles is None:
            raise TimingProofError("unknown-memory-bound")
        if self.require_interrupt_bound and (
            self.max_interrupts is None
            or self.interrupt_service_cycles is None
            or self.interrupt_mask_bound_cycles is None
        ):
            raise TimingProofError("unknown-interrupt-bound")


# Operation 0 is the terminator timing assumption.  CALL_DIRECT is dispatch
# overhead; the callee path is added separately.
_USED_OPERATIONS = (
    0,
    int(Operation.ADD_WRAP),
    int(Operation.SUB_WRAP),
    int(Operation.CALL_DIRECT),
    int(Operation.STACK_ALLOC),
    int(Operation.STORE_BITS_LE),
    int(Operation.LOAD_BITS_LE),
    int(Operation.STACK_END),
)

FIXED_IN_ORDER = TimingModel(
    "fixed-inorder",
    1,
    tuple(sorted({
        0: 1,
        int(Operation.ADD_WRAP): 1,
        int(Operation.SUB_WRAP): 1,
        int(Operation.CALL_DIRECT): 1,
        int(Operation.STACK_ALLOC): 2,
        int(Operation.STORE_BITS_LE): 4,
        int(Operation.LOAD_BITS_LE): 4,
        int(Operation.STACK_END): 1,
    }.items())),
    0,
    0,
    0,
    0,
    False,
    True,
)

BOUNDED_MEMORY_INTERRUPT = TimingModel(
    "bounded-memory-interrupt",
    1,
    tuple((operation, 1) for operation in _USED_OPERATIONS),
    6,
    2,
    11,
    7,
    True,
    True,
)


@dataclass(frozen=True)
class PathFacts:
    path_control_bound: int
    timed_path_steps: int
    timed_path_memory_ops: int
    timed_path_cycles_before_interrupts: int
    reachable_operations: tuple[int, ...]
    uses_memory_bound: bool
    dependencies: tuple[bytes, ...]


@dataclass(frozen=True)
class TimingProof:
    subject_cid: bytes
    target_cid: bytes
    profile_identity: bytes
    model_identity: str
    model_version: int
    dependencies: tuple[bytes, ...]
    path_control_bound: int
    recursion_bound: int
    retry_bound: int
    progress: str
    timed_path_steps: int
    timed_path_memory_ops: int
    operation_cycles: tuple[tuple[int, int], ...]
    memory_extra_cycles: int | None
    max_interrupts: int | None
    interrupt_service_cycles: int | None
    interrupt_mask_bound_cycles: int | None
    guarantee_cycles: int
    dependency_fingerprint: bytes

    def canonical_bytes(self) -> bytes:
        if len(self.subject_cid) != CID_SIZE or len(self.target_cid) != CID_SIZE or len(self.profile_identity) != CID_SIZE:
            raise ValueError("invalid proof identity width")
        if self.dependencies != tuple(sorted(set(self.dependencies))):
            raise ValueError("proof dependencies must be sorted and unique")
        out = bytearray(MAGIC + uleb(VERSION))
        out.extend(self.subject_cid)
        out.extend(self.target_cid)
        out.extend(self.profile_identity)
        out.extend(_encode_ascii(self.model_identity))
        out.extend(uleb(self.model_version))
        out.extend(uleb(len(self.dependencies)))
        for dependency in self.dependencies:
            if len(dependency) != CID_SIZE:
                raise ValueError("invalid proof dependency width")
            out.extend(dependency)
        for value in (
            self.path_control_bound,
            self.recursion_bound,
            self.retry_bound,
            self.timed_path_steps,
            self.timed_path_memory_ops,
            self.guarantee_cycles,
        ):
            out.extend(uleb(value))
        out.extend(_encode_ascii(self.progress))
        out.extend(uleb(len(self.operation_cycles)))
        for operation, cycles in self.operation_cycles:
            out.extend(uleb(operation))
            out.extend(uleb(cycles))
        for value in (
            self.memory_extra_cycles,
            self.max_interrupts,
            self.interrupt_service_cycles,
            self.interrupt_mask_bound_cycles,
        ):
            out.extend(_encode_optional(value))
        out.extend(self.dependency_fingerprint)
        out.extend(blake3(out).digest())
        out.extend(TRAILER)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> "TimingProof":
        pos = 0
        magic, pos = _take(data, pos, len(MAGIC), "proof-magic")
        if magic != MAGIC:
            raise TimingProofError("proof-magic")
        version, pos = _read_uleb(data, pos, "proof-version")
        if version != VERSION:
            raise TimingProofError("proof-version")
        subject, pos = _take(data, pos, CID_SIZE, "proof-subject")
        target, pos = _take(data, pos, CID_SIZE, "proof-target")
        profile, pos = _take(data, pos, CID_SIZE, "proof-profile")
        model_identity, pos = _read_ascii(data, pos, "proof-model")
        model_version, pos = _read_uleb(data, pos, "proof-model-version")
        dependency_count, pos = _read_uleb(data, pos, "proof-dependency-count")
        dependencies = []
        for _ in range(dependency_count):
            dependency, pos = _take(data, pos, CID_SIZE, "proof-dependency")
            dependencies.append(dependency)
        dependencies = tuple(dependencies)
        if dependencies != tuple(sorted(set(dependencies))):
            raise TimingProofError("proof-dependencies")
        path_control_bound, pos = _read_uleb(data, pos, "proof-path-control")
        recursion_bound, pos = _read_uleb(data, pos, "proof-recursion")
        retry_bound, pos = _read_uleb(data, pos, "proof-retry")
        timed_path_steps, pos = _read_uleb(data, pos, "proof-path-steps")
        timed_path_memory_ops, pos = _read_uleb(data, pos, "proof-memory-ops")
        guarantee_cycles, pos = _read_uleb(data, pos, "proof-guarantee")
        progress, pos = _read_ascii(data, pos, "proof-progress")
        operation_count, pos = _read_uleb(data, pos, "proof-operation-count")
        operation_cycles = []
        for _ in range(operation_count):
            operation, pos = _read_uleb(data, pos, "proof-operation")
            cycles, pos = _read_uleb(data, pos, "proof-operation-cycles")
            operation_cycles.append((operation, cycles))
        operation_cycles = tuple(operation_cycles)
        if operation_cycles != tuple(sorted(set(operation_cycles))):
            raise TimingProofError("proof-operation-table")
        optionals = []
        for rule in ("proof-memory-bound", "proof-interrupt-count", "proof-interrupt-service", "proof-interrupt-mask"):
            value, pos = _read_optional(data, pos, rule)
            optionals.append(value)
        fingerprint, pos = _take(data, pos, CID_SIZE, "proof-fingerprint")
        digest_start = pos
        digest, pos = _take(data, pos, CID_SIZE, "proof-digest")
        trailer, pos = _take(data, pos, len(TRAILER), "proof-trailer")
        if trailer != TRAILER:
            raise TimingProofError("proof-trailer")
        if pos != len(data):
            raise TimingProofError("proof-length")
        if digest != blake3(data[:digest_start]).digest():
            raise TimingProofError("proof-digest")
        return cls(
            subject,
            target,
            profile,
            model_identity,
            model_version,
            dependencies,
            path_control_bound,
            recursion_bound,
            retry_bound,
            progress,
            timed_path_steps,
            timed_path_memory_ops,
            operation_cycles,
            optionals[0],
            optionals[1],
            optionals[2],
            optionals[3],
            guarantee_cycles,
            fingerprint,
        )


@dataclass(frozen=True)
class Fixture:
    reader: StoreReader
    target: SemanticObject
    functions: dict[str, SemanticObject]
    root_cid: bytes


def profile_identity(profile: RealtimeProfile) -> bytes:
    out = bytearray(b"OI12-PROFILE-1")
    for field in fields(profile):
        value = getattr(profile, field.name)
        if isinstance(value, bool):
            out.extend(bytes((int(value),)))
        elif isinstance(value, tuple):
            out.extend(uleb(len(value)))
            for item in value:
                out.extend(uleb(int(item)))
        else:
            raise TypeError(field.name)
    return blake3(out).digest()


def _dependency_fingerprint(
    subject_cid: bytes,
    target_cid: bytes,
    profile_cid: bytes,
    model: TimingModel,
    dependencies: Iterable[bytes],
    operation_cycles: tuple[tuple[int, int], ...],
    *,
    uses_memory_bound: bool,
) -> bytes:
    out = bytearray(b"OI12-DEPS-2" + subject_cid + target_cid + profile_cid)
    out.extend(_encode_ascii(model.identity))
    out.extend(uleb(model.version))
    out.extend(uleb(len(operation_cycles)))
    for operation, cycles in operation_cycles:
        out.extend(uleb(operation))
        out.extend(uleb(cycles))
    out.extend(bytes((int(model.require_memory_bound), int(model.require_interrupt_bound), int(uses_memory_bound))))
    if uses_memory_bound:
        out.extend(_encode_optional(model.memory_extra_cycles))
    if model.require_interrupt_bound:
        out.extend(_encode_optional(model.max_interrupts))
        out.extend(_encode_optional(model.interrupt_service_cycles))
        out.extend(_encode_optional(model.interrupt_mask_bound_cycles))
    deps = tuple(sorted(set(dependencies)))
    out.extend(uleb(len(deps)))
    for dependency in deps:
        out.extend(dependency)
    return blake3(out).digest()


def _path_facts(reader: StoreReader, function_cid: bytes, model: TimingModel) -> PathFacts:
    if model.require_interrupt_bound and (
        model.max_interrupts is None
        or model.interrupt_service_cycles is None
        or model.interrupt_mask_bound_cycles is None
    ):
        raise TimingProofError("unknown-interrupt-bound")
    resolve = _verified_resolver(reader)
    active: set[bytes] = set()
    cache: dict[bytes, tuple[int, int, int, int, set[int], bool, set[bytes]]] = {}

    def function_summary(cid: bytes) -> tuple[int, int, int, int, set[int], bool, set[bytes]]:
        if cid in active:
            raise TimingProofError("recursive-timing-path")
        if cid in cache:
            steps, timed_steps, memory_ops, cycles, operations, uses_memory, dependencies = cache[cid]
            return steps, timed_steps, memory_ops, cycles, set(operations), uses_memory, set(dependencies)
        active.add(cid)
        function_object = resolve(cid)
        graph_object, _, _ = _decode_function_interface(function_object, resolve)
        graph = _parse_graph(graph_object, resolve)
        dependencies = {function_object.cid, graph_object.cid}
        visiting: set[int] = set()
        block_cache: dict[int, tuple[int, int, int, int, set[int], bool, set[bytes]]] = {}

        def block_summary(index: int) -> tuple[int, int, int, int, set[int], bool, set[bytes]]:
            if index in visiting:
                raise TimingProofError("unbounded-control-path")
            if index in block_cache:
                steps, timed_steps, memory_ops, cycles, operations, uses_memory, deps = block_cache[index]
                return steps, timed_steps, memory_ops, cycles, set(operations), uses_memory, set(deps)
            visiting.add(index)
            block = graph.blocks[index]
            local_steps = 1  # terminator
            local_timed_steps = 1
            local_memory = 0
            local_cycles = model.operation_bound(0)
            local_operations: set[int] = {0}
            local_uses_memory = False
            local_dependencies: set[bytes] = set()
            for node in block.nodes:
                operation = Operation(node.operation)
                local_steps += 1
                local_timed_steps += 1
                local_operations.add(int(operation))
                local_cycles += model.operation_bound(int(operation))
                if operation in MEMORY_OPERATIONS:
                    local_memory += 1
                    local_uses_memory = local_uses_memory or model.require_memory_bound
                    if model.require_memory_bound:
                        if model.memory_extra_cycles is None:
                            raise TimingProofError("unknown-memory-bound")
                        local_cycles += model.memory_extra_cycles
                if operation == Operation.CALL_DIRECT:
                    if node.entity is None:
                        raise TimingProofError("call-without-entity")
                    child_steps, child_timed_steps, child_memory, child_cycles, child_operations, child_uses_memory, child_dependencies = function_summary(node.entity.cid)
                    local_steps += child_steps
                    local_timed_steps += child_timed_steps
                    local_memory += child_memory
                    local_cycles += child_cycles
                    local_operations |= child_operations
                    local_uses_memory = local_uses_memory or child_uses_memory
                    local_dependencies |= child_dependencies
            successors = []
            for target, _ in block.terminator.edges:
                successors.append(block_summary(target))
            visiting.remove(index)
            if successors:
                # Control bound is independent of the timing model; timed path is
                # chosen by the model's guaranteed cycle upper bound.
                max_steps = max(item[0] for item in successors)
                timed = max(successors, key=lambda item: (item[3], item[1], item[2], item[0]))
                all_operations = set(local_operations)
                uses_memory = local_uses_memory
                all_dependencies = set(local_dependencies)
                for successor in successors:
                    all_operations |= successor[4]
                    uses_memory = uses_memory or successor[5]
                    all_dependencies |= successor[6]
                result = (
                    local_steps + max_steps,
                    local_timed_steps + timed[1],
                    local_memory + timed[2],
                    local_cycles + timed[3],
                    all_operations,
                    uses_memory,
                    all_dependencies,
                )
            else:
                result = (local_steps, local_timed_steps, local_memory, local_cycles, local_operations, local_uses_memory, local_dependencies)
            block_cache[index] = (result[0], result[1], result[2], result[3], set(result[4]), result[5], set(result[6]))
            return result

        steps, timed_steps, memory_ops, cycles, operations, uses_memory, child_dependencies = block_summary(graph.entry)
        dependencies |= child_dependencies
        active.remove(cid)
        result = (steps, timed_steps, memory_ops, cycles, operations, uses_memory, dependencies)
        cache[cid] = (steps, timed_steps, memory_ops, cycles, set(operations), uses_memory, set(dependencies))
        return result

    path_control, timed_steps, memory_ops, cycles, operations, uses_memory, dependencies = function_summary(function_cid)
    return PathFacts(path_control, timed_steps, memory_ops, cycles, tuple(sorted(operations)), uses_memory, tuple(sorted(dependencies)))


def build_timing_proof(
    reader: StoreReader,
    function_cid: bytes,
    target: SemanticObject,
    profile: RealtimeProfile,
    model: TimingModel,
) -> TimingProof:
    verify_store(reader)
    properties = analyze_realtime(reader, function_cid, target)
    if properties.recursion_bound is None:
        raise TimingProofError("unknown-recursion-bound")
    if properties.retry_bound is None:
        raise TimingProofError("unknown-retry-bound")
    if properties.progress == "unknown":
        raise TimingProofError("unknown-progress")
    facts = _path_facts(reader, function_cid, model)
    if profile.require_bounded_interrupt_mask and model.interrupt_mask_bound_cycles is None:
        raise TimingProofError("unknown-interrupt-mask-bound")
    interrupt_cycles = 0
    if model.max_interrupts is not None and model.interrupt_service_cycles is not None:
        interrupt_cycles = model.max_interrupts * model.interrupt_service_cycles
    guarantee = facts.timed_path_cycles_before_interrupts + interrupt_cycles
    profile_cid = profile_identity(profile)
    operation_cycles = tuple((operation, model.operation_bound(operation)) for operation in facts.reachable_operations)
    fingerprint = _dependency_fingerprint(
        function_cid, target.cid, profile_cid, model, facts.dependencies, operation_cycles, uses_memory_bound=facts.uses_memory_bound
    )
    return TimingProof(
        function_cid,
        target.cid,
        profile_cid,
        model.identity,
        model.version,
        facts.dependencies,
        facts.path_control_bound,
        properties.recursion_bound,
        properties.retry_bound,
        properties.progress,
        facts.timed_path_steps,
        facts.timed_path_memory_ops,
        operation_cycles,
        model.memory_extra_cycles if facts.uses_memory_bound else None,
        model.max_interrupts,
        model.interrupt_service_cycles,
        model.interrupt_mask_bound_cycles,
        guarantee,
        fingerprint,
    )


def check_timing_proof(
    proof: TimingProof,
    reader: StoreReader,
    function_cid: bytes,
    target: SemanticObject,
    profile: RealtimeProfile,
    model: TimingModel,
    *,
    deep: bool = False,
) -> int:
    if proof.subject_cid != function_cid:
        raise TimingProofError("stale-subject")
    if proof.target_cid != target.cid:
        raise TimingProofError("stale-target")
    current_profile = profile_identity(profile)
    if proof.profile_identity != current_profile:
        raise TimingProofError("stale-profile")
    if (proof.model_identity, proof.model_version) != (model.identity, model.version):
        raise TimingProofError("stale-model")
    current_operation_cycles = tuple((operation, model.operation_bound(operation)) for operation, _ in proof.operation_cycles)
    expected_fingerprint = _dependency_fingerprint(
        function_cid,
        target.cid,
        current_profile,
        model,
        proof.dependencies,
        current_operation_cycles,
        uses_memory_bound=proof.memory_extra_cycles is not None,
    )
    if proof.dependency_fingerprint != expected_fingerprint:
        raise TimingProofError("stale-assumption")
    for dependency in proof.dependencies:
        try:
            reader.get(dependency)
        except Exception as error:
            raise TimingProofError("stale-dependency") from error
    if deep:
        expected = build_timing_proof(reader, function_cid, target, profile, model)
        if expected != proof:
            raise TimingProofError("proof-mismatch")
    return proof.guarantee_cycles


def timing_query_payload(subject_handle: int = 0, model_handle: int = 0) -> bytes:
    return f"1|tg|F{subject_handle}|M{model_handle}".encode("ascii")


def timing_query_response(bound: int) -> bytes:
    return f"1|tg|{bound}|cycles".encode("ascii")


def tokenizer_counts(payloads: tuple[bytes, ...]) -> dict[str, object]:
    try:
        import tiktoken
    except ImportError:
        return {"available": False, "tokenizer": None, "tokens": None}
    encoding = tiktoken.get_encoding("o200k_base")
    return {
        "available": True,
        "tokenizer": f"tiktoken {tiktoken.__version__} o200k_base",
        "tokens": [len(encoding.encode(payload.decode("ascii"))) for payload in payloads],
    }


def program_fixture(*, leaf_extra: bool = False, unrelated_variant: bool = False, target: SemanticObject | None = None) -> Fixture:
    target = target or x86_64_windows_target()
    b1, b32 = bits_type(1), bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()

    leaf_nodes = [
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(
            Operation.STORE_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
            (effect,),
            attributes=(4, 4),
        ),
        Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1)),
            (b32, effect),
            attributes=(4, 4),
        ),
    ]
    return_value = ValueRef.node_result(0, 2)
    if leaf_extra:
        leaf_nodes.append(Node(Operation.ADD_WRAP, (return_value, ValueRef.parameter(0, 0)), (b32,)))
        return_value = ValueRef.node_result(0, 3)
        effect_ref = ValueRef.node_result(0, 2, 1)
        owner_ref = ValueRef.node_result(0, 0, 1)
        leaf_nodes.append(Node(Operation.STACK_END, (owner_ref, effect_ref), ()))
    else:
        leaf_nodes.append(Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)), ()))
    leaf_graph = graph_fragment((Block((b32,), tuple(leaf_nodes), Terminator.return_((return_value,))),))
    leaf = function(leaf_graph, (b32,), (b32,))

    caller_graph = graph_fragment(
        (
            Block(
                (b1, b32),
                (),
                Terminator.conditional_branch(
                    ValueRef.parameter(0, 0),
                    1,
                    (ValueRef.parameter(0, 1),),
                    2,
                    (ValueRef.parameter(0, 1),),
                ),
            ),
            Block(
                (b32,),
                (Node(Operation.CALL_DIRECT, (ValueRef.parameter(1, 0),), (b32,), entity=leaf),),
                Terminator.return_((ValueRef.node_result(1, 0),)),
            ),
            Block(
                (b32,),
                (Node(Operation.SUB_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 0)), (b32,)),),
                Terminator.return_((ValueRef.node_result(2, 0),)),
            ),
        )
    )
    caller = function(caller_graph, (b1, b32), (b32,))

    unrelated_op = Operation.SUB_WRAP if unrelated_variant else Operation.ADD_WRAP
    unrelated_graph = graph_fragment(
        (
            Block(
                (b32, b32),
                (Node(unrelated_op, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            ),
        )
    )
    unrelated = function(unrelated_graph, (b32, b32), (b32,))

    module = object_with_refs(Kind.MODULE, (leaf, caller, unrelated, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (
        b1,
        b32,
        pointer,
        owner,
        effect,
        leaf_graph,
        leaf,
        caller_graph,
        caller,
        unrelated_graph,
        unrelated,
        target,
        module,
        root,
    )
    reader = StoreReader(write_store(root.cid, objects))
    verify_store(reader)
    return Fixture(reader, target, {"leaf": leaf, "caller": caller, "unrelated": unrelated}, root.cid)


def _proof_set(fixture: Fixture, profile: RealtimeProfile, model: TimingModel) -> dict[str, TimingProof]:
    return {
        name: build_timing_proof(fixture.reader, function.cid, fixture.target, profile, model)
        for name, function in fixture.functions.items()
    }


def _reused_roles(
    old: dict[str, TimingProof],
    new_fixture: Fixture,
    profile: RealtimeProfile,
    model: TimingModel,
) -> tuple[str, ...]:
    reused = []
    for role, proof in old.items():
        try:
            check_timing_proof(
                proof,
                new_fixture.reader,
                new_fixture.functions[role].cid,
                new_fixture.target,
                profile,
                model,
            )
        except TimingProofError:
            continue
        reused.append(role)
    return tuple(sorted(reused))


def _summary(samples: list[int]) -> dict[str, object]:
    ordered = sorted(samples)
    return {
        "raw_ns": samples,
        "min_ns": ordered[0],
        "median_ns": int(statistics.median(ordered)),
        "p10_ns": ordered[max(0, int(len(ordered) * 0.10) - 1)],
        "p90_ns": ordered[min(len(ordered) - 1, int(len(ordered) * 0.90))],
        "max_ns": ordered[-1],
    }


def _time(callable_) -> int:
    start = time.perf_counter_ns()
    callable_()
    return time.perf_counter_ns() - start


def collect_timing(fixture: Fixture, profile: RealtimeProfile, models: tuple[TimingModel, ...]) -> dict[str, object]:
    result: dict[str, object] = {
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "repetitions": TIMING_REPETITIONS,
        "models": {},
    }
    for model in models:
        proof = build_timing_proof(fixture.reader, fixture.functions["caller"].cid, fixture.target, profile, model)
        encoded = proof.canonical_bytes()
        decoded = TimingProof.from_bytes(encoded)
        measurements = {"build": [], "encode": [], "decode": [], "deep_check": [], "cold_query": [], "warm_query": []}
        for _ in range(TIMING_REPETITIONS):
            measurements["build"].append(_time(lambda: build_timing_proof(fixture.reader, fixture.functions["caller"].cid, fixture.target, profile, model)))
            measurements["encode"].append(_time(proof.canonical_bytes))
            measurements["decode"].append(_time(lambda: TimingProof.from_bytes(encoded)))
            measurements["deep_check"].append(_time(lambda: check_timing_proof(decoded, fixture.reader, fixture.functions["caller"].cid, fixture.target, profile, model, deep=True)))
            measurements["cold_query"].append(_time(lambda: check_timing_proof(TimingProof.from_bytes(encoded), fixture.reader, fixture.functions["caller"].cid, fixture.target, profile, model)))
            measurements["warm_query"].append(_time(lambda: check_timing_proof(decoded, fixture.reader, fixture.functions["caller"].cid, fixture.target, profile, model)))
        result["models"][model.identity] = {name: _summary(samples) for name, samples in measurements.items()}
    return result


def collect_evidence() -> dict[str, object]:
    fixture = program_fixture()
    profile = RealtimeProfile(require_bounded_interrupt_mask=True)
    models = (FIXED_IN_ORDER, BOUNDED_MEMORY_INTERRUPT)
    model_evidence = {}
    for model in models:
        proofs = _proof_set(fixture, profile, model)
        caller = proofs["caller"]
        encoded = caller.canonical_bytes()
        query = timing_query_payload()
        response = timing_query_response(caller.guarantee_cycles)
        token_measurement = tokenizer_counts((query, response))
        model_evidence[model.identity] = {
            "model_version": model.version,
            "caller_proof_bytes": len(encoded),
            "proof_set_bytes": sum(len(proof.canonical_bytes()) for proof in proofs.values()),
            "proof_set_entries": len(proofs),
            "path_control_bound": caller.path_control_bound,
            "timed_path_steps": caller.timed_path_steps,
            "timed_path_memory_ops": caller.timed_path_memory_ops,
            "recursion_bound": caller.recursion_bound,
            "retry_bound": caller.retry_bound,
            "progress": caller.progress,
            "memory_extra_cycles": caller.memory_extra_cycles,
            "max_interrupts": caller.max_interrupts,
            "interrupt_service_cycles": caller.interrupt_service_cycles,
            "interrupt_mask_bound_cycles": caller.interrupt_mask_bound_cycles,
            "guarantee_cycles": caller.guarantee_cycles,
            "dependencies": len(caller.dependencies),
            "dependency_fingerprint": caller.dependency_fingerprint.hex(),
            "query_request_bytes": len(query),
            "query_response_bytes": len(response),
            "query_tokens": token_measurement,
            "cost_estimate": {
                "kind": "separate-nonproof-estimate",
                "available": False,
                "value_cycles": None,
                "used_by_proof": False,
            },
        }

    base_proofs = _proof_set(fixture, profile, BOUNDED_MEMORY_INTERRUPT)
    leaf_edit = program_fixture(leaf_extra=True)
    unrelated_edit = program_fixture(unrelated_variant=True)
    changed_target = program_fixture(target=aarch64_baremetal_general_target())
    changed_profile = RealtimeProfile(require_bounded_interrupt_mask=False)
    changed_assumption = TimingModel(
        BOUNDED_MEMORY_INTERRUPT.identity,
        BOUNDED_MEMORY_INTERRUPT.version,
        BOUNDED_MEMORY_INTERRUPT.operation_cycles,
        7,
        BOUNDED_MEMORY_INTERRUPT.max_interrupts,
        BOUNDED_MEMORY_INTERRUPT.interrupt_service_cycles,
        BOUNDED_MEMORY_INTERRUPT.interrupt_mask_bound_cycles,
        True,
        True,
    )
    changed_operation = TimingModel(
        BOUNDED_MEMORY_INTERRUPT.identity,
        BOUNDED_MEMORY_INTERRUPT.version,
        tuple((operation, 2 if operation == int(Operation.SUB_WRAP) else cycles) for operation, cycles in BOUNDED_MEMORY_INTERRUPT.operation_cycles),
        BOUNDED_MEMORY_INTERRUPT.memory_extra_cycles,
        BOUNDED_MEMORY_INTERRUPT.max_interrupts,
        BOUNDED_MEMORY_INTERRUPT.interrupt_service_cycles,
        BOUNDED_MEMORY_INTERRUPT.interrupt_mask_bound_cycles,
        True,
        True,
    )
    invalidation = {}
    cases = (
        ("unrelated_function_edit", unrelated_edit, profile, BOUNDED_MEMORY_INTERRUPT),
        ("callee_body_edit", leaf_edit, profile, BOUNDED_MEMORY_INTERRUPT),
        ("target_change", changed_target, profile, BOUNDED_MEMORY_INTERRUPT),
        ("profile_change", fixture, changed_profile, BOUNDED_MEMORY_INTERRUPT),
        ("memory_assumption_change", fixture, profile, changed_assumption),
        ("sub_operation_assumption_change", fixture, profile, changed_operation),
    )
    for name, changed_fixture, changed_case_profile, changed_model in cases:
        reused = _reused_roles(base_proofs, changed_fixture, changed_case_profile, changed_model)
        invalidation[name] = {
            "reused_roles": list(reused),
            "reused": len(reused),
            "invalidated": len(base_proofs) - len(reused),
        }
    # Cost estimates are deliberately not proof dependencies.
    invalidation["cost_estimate_only_change"] = {
        "reused_roles": sorted(base_proofs),
        "reused": len(base_proofs),
        "invalidated": 0,
    }

    unknown_memory = TimingModel(
        "unknown-memory",
        1,
        BOUNDED_MEMORY_INTERRUPT.operation_cycles,
        None,
        0,
        0,
        0,
        True,
        False,
    )
    unknown_interrupt = TimingModel(
        "unknown-interrupt",
        1,
        BOUNDED_MEMORY_INTERRUPT.operation_cycles,
        6,
        None,
        None,
        None,
        True,
        True,
    )
    fail_closed = {}
    for name, model in (("unknown_memory", unknown_memory), ("unknown_interrupt", unknown_interrupt)):
        try:
            build_timing_proof(fixture.reader, fixture.functions["caller"].cid, fixture.target, profile, model)
        except TimingProofError as error:
            fail_closed[name] = str(error)
        else:
            raise RuntimeError(f"{name} unexpectedly produced a timing proof")

    return {
        "version": 1,
        "status": "measurement-only-nonsemantic-sidecar",
        "fixture": {
            "root_cid": fixture.root_cid.hex(),
            "target_cid": fixture.target.cid.hex(),
            "function_cids": {name: function.cid.hex() for name, function in sorted(fixture.functions.items())},
            "store_bytes": len(fixture.reader.data),
        },
        "profile_identity": profile_identity(profile).hex(),
        "models": model_evidence,
        "invalidation": invalidation,
        "fail_closed": fail_closed,
        "deletion_semantics": {
            "proof_sidecar_is_store_input": False,
            "root_cid_without_sidecar": fixture.root_cid.hex(),
            "root_cid_after_sidecar_delete": fixture.root_cid.hex(),
        },
        "tokenizer_note": "actual tokenizer tokens are null when tiktoken is unavailable; bytes are not substituted for tokens",
    }


def main() -> None:
    fixture = program_fixture()
    profile = RealtimeProfile(require_bounded_interrupt_mask=True)
    evidence = collect_evidence()
    timing = collect_timing(fixture, profile, (FIXED_IN_ORDER, BOUNDED_MEMORY_INTERRUPT))
    here = Path(__file__).resolve().parent
    evidence_path = here / "oi12_timing_proof_evidence.json"
    timing_path = here / "oi12_timing_proof_timing.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    timing_path.write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "evidence": str(evidence_path),
        "evidence_digest": blake3(evidence_path.read_bytes()).hexdigest(),
        "timing": str(timing_path),
        "timing_digest": blake3(timing_path.read_bytes()).hexdigest(),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
