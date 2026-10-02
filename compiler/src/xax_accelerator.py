"""M13 prototype non-CPU accelerator deployment backend.

The deployment format is intentionally tiny and deterministic.  Fundamental
XAX semantics remain target-neutral: the graph uses generic ``target`` nodes
whose exact contract is supplied by the selected target package.  This module
is the target-specific bootstrap emitter/execution harness for the prototype
SIMT packet accelerator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from xax_artifact import ArtifactSemanticRange
from xax_compiler import (
    store_resolver,
    AtomicScope,
    Cursor,
    DmaAction,
    DmaResourceState,
    EffectDomain,
    Kind,
    Operation,
    SemanticObject,
    StoreReader,
    TargetOperationContract,
    TargetValueConstraint,
    TargetValueConstraintKind,
    TerminatorKind,
    _decode_effect_type,
    _decode_function_interface,
    _parse_graph,
    decode_bits_width,
    decode_native_target,
    fail,
    uleb,
    verify_store,
)


MAGIC = b"XAXA\x01"
M13_DEPLOYMENT_FORMAT = 1


def coherent_grid_accelerator_target() -> SemanticObject:
    """Second prototype accelerator package for OI-13 scope experiments.

    Unlike the M13 split host/global/workgroup topology, this package exposes
    one coherent host+device-visible unified space plus workgroup-local memory.
    It also supports system scope.  The package uses the existing accelerator
    target encoding and six-operation deployment contract; no core semantic
    scope or runtime mechanism is added.
    """

    identity = b"coherent-grid-accelerator-v1"
    operations = (Operation.TARGET_OP.value,)
    terminators = (TerminatorKind.RETURN.value, TerminatorKind.TRAP.value)
    body = bytearray(uleb(len(identity)) + identity)
    for value in (3, 4, 4, 3, 32, 64):
        body.extend(uleb(value))
    body.extend(uleb(len(operations)) + b"".join(uleb(value) for value in operations))
    body.extend(uleb(len(terminators)) + b"".join(uleb(value) for value in terminators))

    body.extend(uleb(8) + uleb(4096))
    scopes = (AtomicScope.SYSTEM, AtomicScope.DEVICE, AtomicScope.WORKGROUP)
    body.extend(uleb(len(scopes)) + b"".join(uleb(scope) for scope in scopes))

    spaces = (
        (1, 64, 8, 4, (32,), scopes, True, True),
        (2, 32, 8, 4, (32,), (AtomicScope.WORKGROUP,), False, True),
    )
    body.extend(uleb(len(spaces)))
    for space_id, address_bits, unit_bits, alignment, widths, visible_scopes, host_visible, device_visible in spaces:
        body.extend(uleb(space_id) + uleb(address_bits) + uleb(unit_bits) + uleb(alignment))
        body.extend(uleb(len(widths)) + b"".join(uleb(width) for width in widths))
        body.extend(uleb(len(visible_scopes)) + b"".join(uleb(scope) for scope in visible_scopes))
        body.extend(bytes((host_visible, device_visible)))

    bits32 = TargetValueConstraint(TargetValueConstraintKind.BITS, 32)
    host_buffer = TargetValueConstraint(TargetValueConstraintKind.RESOURCE, 1001, 1)
    device_buffer = TargetValueConstraint(TargetValueConstraintKind.RESOURCE, 1001, 2)
    device_effect = TargetValueConstraint(TargetValueConstraintKind.EFFECT, EffectDomain.DEVICE, 1)
    contracts = (
        TargetOperationContract(1, 1, 0x20, (device_effect,), (host_buffer, device_effect), (AtomicScope.DEVICE,), 1, 1, False, False),
        TargetOperationContract(2, 2, 0x21, (bits32, host_buffer, device_effect), (device_buffer, device_effect), (AtomicScope.DEVICE,), 1, 1, False, False),
        TargetOperationContract(3, 3, 0x22, (bits32, device_buffer, device_effect), (device_buffer, device_effect), (AtomicScope.DEVICE,), 1, 1, False, False),
        TargetOperationContract(4, 4, 0x23, (device_buffer, device_effect), (device_buffer, device_effect), scopes, 1, 1, True, True),
        TargetOperationContract(5, 5, 0x24, (device_buffer, device_effect), (bits32, host_buffer, device_effect), (AtomicScope.DEVICE,), 1, 1, False, False),
        TargetOperationContract(6, 6, 0x25, (host_buffer, device_effect), (device_effect,), (AtomicScope.DEVICE,), 1, 1, False, False),
    )
    body.extend(uleb(len(contracts)))
    for contract in contracts:
        body.extend(uleb(contract.operation_id) + uleb(contract.semantic_code) + uleb(contract.encoding_opcode))
        for constraints in (contract.operands, contract.results):
            body.extend(uleb(len(constraints)))
            for item in constraints:
                body.extend(uleb(item.kind) + uleb(item.primary) + uleb(item.secondary))
        body.extend(uleb(len(contract.supported_scopes)))
        body.extend(b"".join(uleb(scope) for scope in contract.supported_scopes))
        body.extend(uleb(contract.source_space) + uleb(contract.destination_space))
        body.extend(bytes((contract.synchronizes, contract.may_block)))
        body.extend(uleb(len(contract.runtime_dependency)) + contract.runtime_dependency)
    return SemanticObject.create(Kind.TARGET, bytes(body))


@dataclass(frozen=True)
class AcceleratorInstruction:
    semantic_code: int
    encoding_opcode: int
    scope: AtomicScope
    source_space: int
    destination_space: int
    synchronizes: bool
    may_block: bool


@dataclass(frozen=True)
class AcceleratorImage:
    deployment: bytes
    target_cid: bytes
    function_cid: bytes
    lane_width: int
    max_groups: int
    runtime_dependencies: tuple[bytes, ...]
    semantic_ranges: tuple[ArtifactSemanticRange, ...] = ()
    entry_offset: int = 0
    parameter_widths: tuple[int, ...] = (32, 32, 0)
    return_widths: tuple[int, ...] = (32, 0)

    @property
    def artifact_bytes(self) -> bytes:
        return self.deployment


@dataclass(frozen=True)
class AcceleratorDeploymentView:
    target_cid: bytes
    function_cid: bytes
    lane_width: int
    max_groups: int
    memory_spaces: tuple[int, ...]
    instructions: tuple[AcceleratorInstruction, ...]
    runtime_dependencies: tuple[bytes, ...]


def _effect_is_device_instance(resolve: Callable[[bytes], SemanticObject], cid: bytes, instance: int) -> bool:
    obj = resolve(cid)
    if obj.kind != Kind.TYPE:
        return False
    try:
        effect = _decode_effect_type(obj)
    except Exception:
        return False
    return effect.domain == EffectDomain.DEVICE and effect.instance == instance


def _effect_is_device_one(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> bool:
    return _effect_is_device_instance(resolve, cid, 1)


def _bits32(resolve: Callable[[bytes], SemanticObject], cid: bytes) -> bool:
    try:
        return decode_bits_width(resolve(cid)) == 32
    except Exception:
        return False


def compile_accelerator(
    reader: StoreReader,
    function_cid: bytes,
    target_cid: bytes,
    *,
    allowed_runtime_dependencies: Sequence[bytes] = (),
) -> AcceleratorImage:
    """Compile a verified accelerator orchestration graph into a deployment packet.

    Runtime assistance is never inferred.  Any target-operation dependency must
    be named by the caller in ``allowed_runtime_dependencies``; the M13
    prototype target intentionally declares none.
    """

    verify_store(reader)
    resolve = store_resolver(reader)
    function_object = resolve(function_cid)
    target_object = resolve(target_cid)
    description = decode_native_target(target_object)
    if description.architecture != 4 or not description.target_operations:
        fail("XAX.ACCELERATOR.TARGET", target_cid.hex(), "ACCELERATOR-TARGET-PROFILE", 4, description.architecture)

    graph_object, parameters, returns = _decode_function_interface(function_object, resolve)
    graph = _parse_graph(graph_object, resolve)
    if len(graph.blocks) != 1 or graph.entry != 0:
        fail("XAX.ACCELERATOR.CFG", function_cid.hex(), "ACCELERATOR-SINGLE-BLOCK", [1, 0], [len(graph.blocks), graph.entry])
    block = graph.blocks[0]
    if block.terminator.kind != TerminatorKind.RETURN:
        fail("XAX.ACCELERATOR.CFG", function_cid.hex(), "ACCELERATOR-RETURN", TerminatorKind.RETURN.name, block.terminator.kind.name)
    if len(parameters) != 3 or len(returns) != 2 or not all(_bits32(resolve, cid) for cid in parameters[:2]) or not _effect_is_device_one(resolve, parameters[2]) or not _bits32(resolve, returns[0]) or returns[1] != parameters[2]:
        fail(
            "XAX.ACCELERATOR.ABI",
            function_cid.hex(),
            "ACCELERATOR-HOST-INTERFACE",
            ["bits<32>", "bits<32>", "effect<device,1>", "->", "bits<32>", "effect<device,1>"],
            [cid.hex() for cid in (*parameters, *returns)],
        )

    contract_by_id = {item.operation_id: item for item in description.target_operations}
    expected_semantic_sequence = (1, 2, 3, 4, 5, 6)
    seen_semantics: list[int] = []
    dependencies: set[bytes] = set()
    emitted = bytearray()
    ranges: list[ArtifactSemanticRange] = []
    encoded_nodes: list[tuple[int, int, int, int, int, bool, bool]] = []
    for node_index, node in enumerate(block.nodes):
        if node.operation != Operation.TARGET_OP or node.entity is None or node.entity.cid != target_cid:
            fail("XAX.ACCELERATOR.OPERATION", graph_object.cid.hex(), "ACCELERATOR-TARGET-OPS-ONLY", Operation.TARGET_OP.name, node.operation)
        operation_id, scope_value, source_space, destination_space = node.attributes
        contract = contract_by_id[operation_id]
        seen_semantics.append(contract.semantic_code)
        if contract.runtime_dependency:
            dependencies.add(contract.runtime_dependency)
        encoded_nodes.append(
            (
                contract.semantic_code,
                contract.encoding_opcode,
                scope_value,
                source_space,
                destination_space,
                contract.synchronizes,
                contract.may_block,
            )
        )
    if tuple(seen_semantics) != expected_semantic_sequence:
        fail("XAX.ACCELERATOR.SEQUENCE", graph_object.cid.hex(), "ACCELERATOR-DEPLOY-SEQUENCE", expected_semantic_sequence, tuple(seen_semantics))
    requested_dependencies = tuple(sorted(set(allowed_runtime_dependencies)))
    required_dependencies = tuple(sorted(dependencies))
    if requested_dependencies != required_dependencies:
        fail(
            "XAX.ACCELERATOR.RUNTIME",
            target_cid.hex(),
            "ACCELERATOR-RUNTIME-DEPENDENCIES-EXPLICIT",
            [item.hex() for item in required_dependencies],
            [item.hex() for item in requested_dependencies],
        )

    emitted.extend(MAGIC)
    emitted.extend(uleb(M13_DEPLOYMENT_FORMAT))
    emitted.extend(target_cid + function_cid)
    emitted.extend(uleb(description.accelerator_lane_width) + uleb(description.accelerator_max_groups))
    emitted.extend(uleb(len(description.memory_spaces)))
    for space in description.memory_spaces:
        emitted.extend(uleb(space.identity))
    emitted.extend(uleb(len(required_dependencies)))
    emitted.extend(b"".join(required_dependencies))
    emitted.extend(uleb(len(encoded_nodes)))
    for node_index, (semantic_code, opcode, scope, source_space, destination_space, synchronizes, may_block) in enumerate(encoded_nodes):
        start = len(emitted)
        emitted.extend(bytes((opcode,)))
        emitted.extend(uleb(semantic_code) + uleb(scope) + uleb(source_space) + uleb(destination_space))
        emitted.extend(bytes((synchronizes, may_block)))
        end = len(emitted)
        ranges.append(ArtifactSemanticRange(function_cid, 0, node_index, start, end))

    ranges.insert(0, ArtifactSemanticRange(function_cid, None, None, 0, len(emitted)))
    return AcceleratorImage(
        bytes(emitted),
        target_cid,
        function_cid,
        description.accelerator_lane_width,
        description.accelerator_max_groups,
        required_dependencies,
        tuple(ranges),
    )


def compile_dma_flow(
    reader: StoreReader,
    function_cid: bytes,
    target_cid: bytes,
) -> AcceleratorImage:
    """Compile the bounded OI-07 DMA-flow experiment to the packet carrier.

    This is deliberately not a general device framework.  It accepts only the
    two OI-07 target-package identities and their exact measured action traces.
    """

    verify_store(reader)
    resolve = store_resolver(reader)
    function_object = resolve(function_cid)
    target_object = resolve(target_cid)
    description = decode_native_target(target_object)
    expected_by_identity = {
        b"oi07-noncoherent-split-dma-v1": tuple(int(item) for item in DmaAction),
        b"oi07-coherent-shared-dma-v1": (
            int(DmaAction.ACQUIRE),
            int(DmaAction.MAP),
            int(DmaAction.HOST_WRITE),
            int(DmaAction.DEVICE_ACQUIRE),
            int(DmaAction.DEVICE_WRITE),
            int(DmaAction.SYNCHRONIZE),
            int(DmaAction.HOST_ACQUIRE),
            int(DmaAction.HOST_READ),
            int(DmaAction.UNMAP),
            int(DmaAction.RELEASE),
        ),
    }
    expected_semantics = expected_by_identity.get(description.identity)
    if expected_semantics is None:
        fail("XAX.DMA.TARGET", target_cid.hex(), "DMA-OI07-TARGET", sorted(item.decode() for item in expected_by_identity), description.identity.decode("ascii", "replace"))

    graph_object, parameters, returns = _decode_function_interface(function_object, resolve)
    graph = _parse_graph(graph_object, resolve)
    if len(graph.blocks) != 1 or graph.entry != 0 or graph.blocks[0].terminator.kind != TerminatorKind.RETURN:
        fail("XAX.DMA.CFG", function_cid.hex(), "DMA-SINGLE-BLOCK-RETURN", [1, 0, TerminatorKind.RETURN.name], [len(graph.blocks), graph.entry, graph.blocks[0].terminator.kind.name if graph.blocks else None])
    if (
        len(parameters) != 3
        or len(returns) != 2
        or not all(_bits32(resolve, cid) for cid in parameters[:2])
        or not _effect_is_device_instance(resolve, parameters[2], 7)
        or not _bits32(resolve, returns[0])
        or returns[1] != parameters[2]
    ):
        fail("XAX.DMA.ABI", function_cid.hex(), "DMA-OI07-HOST-INTERFACE", ["bits<32>", "bits<32>", "effect<device,7>", "->", "bits<32>", "effect<device,7>"], [cid.hex() for cid in (*parameters, *returns)])

    contract_by_id = {item.operation_id: item for item in description.target_operations}
    seen_semantics: list[int] = []
    encoded_nodes: list[tuple[int, int, int, int, int, bool, bool]] = []
    for node in graph.blocks[0].nodes:
        if node.operation != Operation.TARGET_OP or node.entity is None or node.entity.cid != target_cid:
            fail("XAX.DMA.OPERATION", graph_object.cid.hex(), "DMA-TARGET-OPS-ONLY", Operation.TARGET_OP.name, node.operation)
        operation_id, scope_value, source_space, destination_space = node.attributes
        contract = contract_by_id[operation_id]
        seen_semantics.append(contract.semantic_code)
        encoded_nodes.append((contract.semantic_code, contract.encoding_opcode, scope_value, source_space, destination_space, contract.synchronizes, contract.may_block))
    if tuple(seen_semantics) != expected_semantics:
        fail("XAX.DMA.SEQUENCE", graph_object.cid.hex(), "DMA-OI07-ACTION-SEQUENCE", expected_semantics, tuple(seen_semantics))

    emitted = bytearray(MAGIC)
    emitted.extend(uleb(M13_DEPLOYMENT_FORMAT))
    emitted.extend(target_cid + function_cid)
    emitted.extend(uleb(description.accelerator_lane_width) + uleb(description.accelerator_max_groups))
    emitted.extend(uleb(len(description.memory_spaces)))
    for space in description.memory_spaces:
        emitted.extend(uleb(space.identity))
    emitted.extend(uleb(0))
    emitted.extend(uleb(len(encoded_nodes)))
    ranges: list[ArtifactSemanticRange] = []
    for node_index, (semantic_code, opcode, scope, source_space, destination_space, synchronizes, may_block) in enumerate(encoded_nodes):
        start = len(emitted)
        emitted.extend(bytes((opcode,)))
        emitted.extend(uleb(semantic_code) + uleb(scope) + uleb(source_space) + uleb(destination_space))
        emitted.extend(bytes((synchronizes, may_block)))
        ranges.append(ArtifactSemanticRange(function_cid, 0, node_index, start, len(emitted)))
    ranges.insert(0, ArtifactSemanticRange(function_cid, None, None, 0, len(emitted)))
    return AcceleratorImage(bytes(emitted), target_cid, function_cid, description.accelerator_lane_width, description.accelerator_max_groups, (), tuple(ranges))


def run_dma_deployment(image: AcceleratorImage | bytes, arguments: Sequence[int]) -> tuple[int, ...]:
    """Execute the bounded OI-07 DMA packet in the deterministic conformance harness."""

    data = image.deployment if isinstance(image, AcceleratorImage) else image
    view = inspect_deployment(data)
    if len(arguments) != 2 or any(value < 0 or value >= 1 << 32 for value in arguments):
        fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-ARGUMENTS", "two bits<32> values", list(arguments))
    semantics = tuple(item.semantic_code for item in view.instructions)
    noncoherent = tuple(int(item) for item in DmaAction)
    coherent = tuple(item for item in noncoherent if item not in (int(DmaAction.CACHE_CLEAN), int(DmaAction.CACHE_INVALIDATE)))
    if semantics == noncoherent:
        cache_coherent = False
    elif semantics == coherent:
        cache_coherent = True
    else:
        fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-OI07-ACTION-SEQUENCE", [noncoherent, coherent], semantics)

    initial, delta = (int(value) for value in arguments)
    state: DmaResourceState | None = None
    value: int | None = None
    synchronized = False
    result: int | None = None
    for instruction in view.instructions:
        action = DmaAction(instruction.semantic_code)
        if action == DmaAction.ACQUIRE:
            if state is not None:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-ACQUIRE-STATE", None, state.name)
            state = DmaResourceState.HOST_UNMAPPED
        elif action == DmaAction.MAP:
            if state != DmaResourceState.HOST_UNMAPPED:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-MAP-STATE", DmaResourceState.HOST_UNMAPPED.name, None if state is None else state.name)
            state = DmaResourceState.HOST_MAPPED
        elif action == DmaAction.HOST_WRITE:
            if state != DmaResourceState.HOST_MAPPED:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-HOST-WRITE-STATE", DmaResourceState.HOST_MAPPED.name, None if state is None else state.name)
            value = initial
            state = DmaResourceState.HOST_MAPPED if cache_coherent else DmaResourceState.HOST_DIRTY
        elif action == DmaAction.CACHE_CLEAN:
            if cache_coherent or state != DmaResourceState.HOST_DIRTY:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-CACHE-CLEAN-STATE", DmaResourceState.HOST_DIRTY.name, None if state is None else state.name)
            state = DmaResourceState.HOST_MAPPED
        elif action == DmaAction.DEVICE_ACQUIRE:
            if state != DmaResourceState.HOST_MAPPED:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-DEVICE-ACQUIRE-STATE", DmaResourceState.HOST_MAPPED.name, None if state is None else state.name)
            state = DmaResourceState.DEVICE_OWNED
            synchronized = False
        elif action == DmaAction.DEVICE_WRITE:
            if state != DmaResourceState.DEVICE_OWNED or value is None:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-DEVICE-WRITE-STATE", DmaResourceState.DEVICE_OWNED.name, None if state is None else state.name)
            value = (value + delta) & 0xFFFFFFFF
            state = DmaResourceState.DEVICE_PENDING
            synchronized = False
        elif action == DmaAction.SYNCHRONIZE:
            if state != DmaResourceState.DEVICE_PENDING or not instruction.synchronizes:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-SYNCHRONIZE", [DmaResourceState.DEVICE_PENDING.name, True], [None if state is None else state.name, instruction.synchronizes])
            state = DmaResourceState.DEVICE_OWNED
            synchronized = True
        elif action == DmaAction.HOST_ACQUIRE:
            if state != DmaResourceState.DEVICE_OWNED or not synchronized:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-HOST-ACQUIRE-STATE", [DmaResourceState.DEVICE_OWNED.name, True], [None if state is None else state.name, synchronized])
            state = DmaResourceState.HOST_MAPPED if cache_coherent else DmaResourceState.HOST_STALE
        elif action == DmaAction.CACHE_INVALIDATE:
            if cache_coherent or state != DmaResourceState.HOST_STALE:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-CACHE-INVALIDATE-STATE", DmaResourceState.HOST_STALE.name, None if state is None else state.name)
            state = DmaResourceState.HOST_MAPPED
        elif action == DmaAction.HOST_READ:
            if state != DmaResourceState.HOST_MAPPED or value is None:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-HOST-READ-STATE", DmaResourceState.HOST_MAPPED.name, None if state is None else state.name)
            result = value
        elif action == DmaAction.UNMAP:
            if state != DmaResourceState.HOST_MAPPED:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-UNMAP-STATE", DmaResourceState.HOST_MAPPED.name, None if state is None else state.name)
            state = DmaResourceState.HOST_UNMAPPED
        elif action == DmaAction.RELEASE:
            if state != DmaResourceState.HOST_UNMAPPED:
                fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-RELEASE-STATE", DmaResourceState.HOST_UNMAPPED.name, None if state is None else state.name)
            state = None
    if state is not None or result is None:
        fail("XAX.DMA.EXEC", view.function_cid.hex(), "DMA-FINAL-STATE", [None, "result"], [None if state is None else state.name, result])
    return (result,)


def compile_accelerator_bound_target(
    reader: StoreReader,
    function_cid: bytes,
    target_object: SemanticObject,
    *,
    allowed_runtime_dependencies: Sequence[bytes] = (),
) -> AcceleratorImage:
    if target_object.kind != Kind.TARGET:
        raise ValueError("bound accelerator target must be a TARGET object")
    # Build snapshots retain the exact target object in the semantic closure, so
    # the ordinary CID path remains authoritative and avoids an alternate target
    # carrier format.
    return compile_accelerator(
        reader,
        function_cid,
        target_object.cid,
        allowed_runtime_dependencies=allowed_runtime_dependencies,
    )


def inspect_deployment(data: bytes) -> AcceleratorDeploymentView:
    cursor = Cursor(data, "accelerator-deployment")
    if cursor.take(len(MAGIC)) != MAGIC:
        fail("XAX.ACCELERATOR.ARTIFACT", "accelerator-deployment", "ACCELERATOR-MAGIC", MAGIC.hex(), data[: len(MAGIC)].hex())
    version = cursor.uleb()
    if version != M13_DEPLOYMENT_FORMAT:
        fail("XAX.ACCELERATOR.ARTIFACT", "accelerator-deployment", "ACCELERATOR-FORMAT", M13_DEPLOYMENT_FORMAT, version)
    target_cid, function_cid = cursor.take(32), cursor.take(32)
    lane_width, max_groups = cursor.uleb(), cursor.uleb()
    spaces = tuple(cursor.uleb() for _ in range(cursor.uleb()))
    dependencies = tuple(cursor.take(32) for _ in range(cursor.uleb()))
    instructions = []
    for _ in range(cursor.uleb()):
        opcode = cursor.take(1)[0]
        semantic_code, scope_value, source_space, destination_space = (cursor.uleb() for _ in range(4))
        synchronizes, may_block = bool(cursor.take(1)[0]), bool(cursor.take(1)[0])
        try:
            scope = AtomicScope(scope_value)
        except ValueError:
            fail("XAX.ACCELERATOR.ARTIFACT", "accelerator-deployment", "ACCELERATOR-SCOPE", [item.value for item in AtomicScope], scope_value)
        instructions.append(AcceleratorInstruction(semantic_code, opcode, scope, source_space, destination_space, synchronizes, may_block))
    cursor.end("ACCELERATOR-ARTIFACT-LENGTH")
    return AcceleratorDeploymentView(target_cid, function_cid, lane_width, max_groups, spaces, tuple(instructions), dependencies)


def run_accelerator_deployment(image: AcceleratorImage | bytes, arguments: Sequence[int]) -> tuple[int, ...]:
    """Execute the prototype deployment packet in the deterministic M13 harness.

    This is a conformance harness for the declared packet target, not a hidden
    runtime linked into emitted artifacts.
    """

    data = image.deployment if isinstance(image, AcceleratorImage) else image
    view = inspect_deployment(data)
    if len(arguments) != 2 or any(value < 0 or value >= 1 << 32 for value in arguments):
        fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-ARGUMENTS", "two bits<32> values", list(arguments))
    host_value, delta = (int(value) for value in arguments)
    buffer_exists = False
    buffer_space = 0
    device_value: int | None = None
    synchronized = False
    result: int | None = None

    for instruction in view.instructions:
        code = instruction.semantic_code
        if code == 1:  # explicit buffer acquisition in host-visible staging space
            if buffer_exists:
                fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-ALLOCATE-ONCE", False, True)
            buffer_exists, buffer_space = True, instruction.destination_space
        elif code == 2:  # host -> device transfer
            if not buffer_exists or buffer_space != instruction.source_space:
                fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-H2D-STATE", instruction.source_space, buffer_space)
            buffer_space, device_value, synchronized = instruction.destination_space, host_value, False
        elif code == 3:  # target-defined device launch: wrapping add kernel
            if not buffer_exists or buffer_space != instruction.source_space or device_value is None:
                fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-LAUNCH-STATE", instruction.source_space, buffer_space)
            device_value = (device_value + delta) & 0xFFFFFFFF
            synchronized = False
        elif code == 4:  # explicit host-visible synchronization point
            if not buffer_exists or buffer_space != instruction.source_space:
                fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-SYNC-STATE", instruction.source_space, buffer_space)
            synchronized = True
        elif code == 5:  # device -> host transfer requires the explicit synchronization
            if not buffer_exists or buffer_space != instruction.source_space or device_value is None or not synchronized:
                fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-D2H-SYNCHRONIZED", True, synchronized)
            result = device_value
            buffer_space = instruction.destination_space
        elif code == 6:  # explicit buffer release
            if not buffer_exists or buffer_space != instruction.source_space:
                fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-FREE-STATE", instruction.source_space, buffer_space)
            buffer_exists = False
        else:
            fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-SEMANTIC-CODE", [1, 2, 3, 4, 5, 6], code)

    if buffer_exists or result is None:
        fail("XAX.ACCELERATOR.EXEC", view.function_cid.hex(), "ACCELERATOR-TERMINAL-STATE", [False, "result"], [buffer_exists, result])
    return (result,)
