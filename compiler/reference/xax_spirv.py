"""SPIR-V compute target for Vulkan (ADR-124).

A kernel is an ordinary verified XAX function under the target-owned
``spirv-compute-v1`` entry contract:

* parameters: ``(b32 invocation, (ptr<b32>, heap_view<E>, memory)...)``;
* results: the same view triples, returned whole (borrowed storage buffers).

Lowering adds no runtime.  The compiler generates, explicitly:

* an entry adapter: invocation = ``GlobalInvocationId.x``; invocations at or
  past the launch count (push constant 0) return at once, so the profile's
  fixed workgroup size never changes semantics;
* storage-buffer bindings ``0..k-1`` for the view triples, in order, plus one
  status binding ``k`` where a trap records ``atomicMax(status, code)`` and
  ends the invocation (``0x10000 | portable reason`` for ``trap`` and divide
  by zero; ``0x20000`` for a failed bounds check);
* any XAX CFG as one structured dispatch loop: each block, split after every
  trap-capable node, is one ``OpSwitch`` case; values live in Function
  variables (the driver's SSA construction removes them).

Invocations run concurrently, so the target requires them to be race-free
and checks a sufficient rule (``SPIRV-KERNEL-OWN-ELEMENT``): every store, and
every load from a stored-to binding, addresses exactly the invocation's own
32-bit element, ``invocation * 4``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Sequence

from xax_compiler import (
    IntCompare,
    Kind,
    Operation,
    Permission,
    SPIRV_ARCHITECTURE,
    SemanticObject,
    StoreReader,
    TerminatorKind,
    ValueRef,
    _decode_constant,
    _decode_function_interface,
    _decode_pointer_type,
    _heap_view_info,
    _is_proof_type,
    _parse_graph,
    decode_bits_width,
    decode_native_target,
    decode_trap_payload,
    fail,
    store_resolver,
    verify_store,
)

LOCAL_SIZE = 64
STATUS_TRAP = 0x10000  # | portable reason
STATUS_BOUNDS = 0x20000
_DONE = 0xFFFFFFFF

# Opcodes (SPIR-V 1.3 unified specification).
OP = dict(
    Capability=17, MemoryModel=14, EntryPoint=15, ExecutionMode=16, Decorate=71, MemberDecorate=72,
    TypeVoid=19, TypeBool=20, TypeInt=21, TypeVector=23, TypeRuntimeArray=29, TypeStruct=30, TypePointer=32, TypeFunction=33,
    Constant=43, Variable=59, Load=61, Store=62, AccessChain=65, CompositeExtract=81,
    Function=54, FunctionEnd=56, Label=248, Branch=249, BranchConditional=250, Switch=251, Return=253,
    LoopMerge=246, SelectionMerge=247, Select=169,
    IAdd=128, ISub=130, IMul=132, UDiv=134, UMod=137,
    ShiftRightLogical=194, ShiftRightArithmetic=195, ShiftLeftLogical=196, BitwiseOr=197, BitwiseXor=198, BitwiseAnd=199,
    LogicalOr=166, IEqual=170, INotEqual=171, UGreaterThan=172, SGreaterThan=173, UGreaterThanEqual=174, SGreaterThanEqual=175,
    ULessThan=176, SLessThan=177, ULessThanEqual=178, SLessThanEqual=179, AtomicUMax=239,
)
_INPUT, _UNIFORM, _FUNCTION, _PUSH_CONSTANT, _STORAGE_BUFFER = 1, 2, 7, 9, 12
_COMPARE = {
    IntCompare.EQ: "IEqual", IntCompare.NE: "INotEqual", IntCompare.ULT: "ULessThan", IntCompare.ULE: "ULessThanEqual",
    IntCompare.UGT: "UGreaterThan", IntCompare.UGE: "UGreaterThanEqual", IntCompare.SLT: "SLessThan", IntCompare.SLE: "SLessThanEqual",
    IntCompare.SGT: "SGreaterThan", IntCompare.SGE: "SGreaterThanEqual",
}
_SIGNED = {IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE}
_BINARY = {
    Operation.ADD_WRAP: "IAdd", Operation.SUB_WRAP: "ISub", Operation.MUL_WRAP: "IMul", Operation.UDIV: "UDiv", Operation.UREM: "UMod",
    Operation.BIT_AND: "BitwiseAnd", Operation.BIT_OR: "BitwiseOr", Operation.BIT_XOR: "BitwiseXor",
}


@dataclass(frozen=True)
class SpirvBinding:
    extent: int  # bytes
    writable: bool


@dataclass(frozen=True)
class SpirvKernel:
    module: bytes
    bindings: tuple[SpirvBinding, ...]  # status binding excluded; it is binding len(bindings)
    local_size: int
    target_cid: bytes
    kernel_cid: bytes

    @property
    def artifact_bytes(self) -> bytes:
        return self.module


def _string(text: str) -> list[int]:
    data = text.encode() + b"\0"
    data += bytes(-len(data) % 4)
    return list(struct.unpack(f"<{len(data) // 4}I", data))


class _Module:
    def __init__(self) -> None:
        self.next_id = 1
        self.sections: dict[str, list[int]] = {name: [] for name in ("caps", "entry", "modes", "decorations", "globals", "code")}
        self.types: dict[tuple, int] = {}
        self.constants: dict[int, int] = {}

    def id(self) -> int:
        value = self.next_id
        self.next_id += 1
        return value

    def emit(self, section: str, opcode: str, *operands: int) -> None:
        self.sections[section].extend(((len(operands) + 1) << 16 | OP[opcode], *operands))

    def type(self, opcode: str, *operands: int) -> int:
        key = (opcode, *operands)
        if key not in self.types:
            self.types[key] = self.id()
            self.emit("globals", opcode, self.types[key], *operands)
        return self.types[key]

    def uint(self) -> int:
        return self.type("TypeInt", 32, 0)

    def constant(self, value: int) -> int:
        value &= 0xFFFFFFFF
        if value not in self.constants:
            self.constants[value] = self.id()
            self.emit("globals", "Constant", self.uint(), self.constants[value], value)
        return self.constants[value]

    def words(self) -> bytes:
        body = [word for name in ("caps", "entry", "modes", "decorations", "globals", "code") for word in self.sections[name]]
        header = (0x07230203, 0x00010300, 0, self.next_id, 0)
        return struct.pack(f"<{len(header) + len(body)}I", *header, *body)


def _kernel_interface(function: SemanticObject, resolve) -> tuple[list[tuple[bytes, int, bool]], object]:
    """Validate ``spirv-compute-v1`` and return ``[(pointer cid, extent, writable)]`` per binding."""
    graph_object, parameters, returns = _decode_function_interface(function, resolve)

    def reject(detail) -> None:
        fail("XAX.SPIRV.ENTRY", function.cid.hex(), "SPIRV-KERNEL-ENTRY-CONTRACT", "fn(b32, (ptr<b32>, heap_view<E>, memory)...) -> ((ptr, view, memory)...)", detail)

    if not parameters or resolve(parameters[0]).body[:1] != b"\x01" or decode_bits_width(resolve(parameters[0])) != 32:
        reject("first parameter must be the b32 invocation index")
    triples = parameters[1:]
    if len(triples) % 3 or tuple(returns) != tuple(triples) or not triples:
        reject("parameters after the invocation must be view triples, returned whole in order")
    bindings = []
    for index in range(0, len(triples), 3):
        pointer, view, effect = triples[index : index + 3]
        info = _heap_view_info(resolve(view))
        if info is None or not _is_proof_type(resolve(effect)):
            reject(f"binding {index // 3} is not a (pointer, heap view, memory) triple")
        element, permission, _alignment = _decode_pointer_type(resolve(pointer), resolve)
        extent = info[0]
        if resolve(element).body[:1] != b"\x01" or decode_bits_width(resolve(element)) != 32 or extent % 4 or not extent:
            reject(f"binding {index // 3} must view a nonempty array of b32")
        bindings.append((pointer, extent, permission == Permission.READ_WRITE))
    return bindings, graph_object


def compile_spirv_kernel(reader: StoreReader, kernel_cid: bytes, target_cid: bytes) -> SpirvKernel:
    verify_store(reader)
    resolve = store_resolver(reader)
    target = decode_native_target(resolve(target_cid))
    if target.architecture != SPIRV_ARCHITECTURE:
        fail("XAX.SPIRV.TARGET", target_cid.hex(), "SPIRV-TARGET", SPIRV_ARCHITECTURE, target.architecture)
    function = resolve(kernel_cid)
    if function.kind != Kind.FUNCTION:
        fail("XAX.SPIRV.ENTRY", kernel_cid.hex(), "SPIRV-KERNEL-FUNCTION", Kind.FUNCTION.name, function.kind.name)
    bindings, graph_object = _kernel_interface(function, resolve)
    graph = _parse_graph(graph_object, resolve)
    for block in graph.blocks:
        for node in block.nodes:
            if node.operation not in target.supported_operations:
                fail("XAX.SPIRV.OPERATION", graph_object.cid.hex(), "SPIRV-OP-TARGET-SUPPORTED", list(target.supported_operations), node.operation)
        if block.terminator.kind not in target.supported_terminators:
            fail("XAX.SPIRV.TERMINATOR", graph_object.cid.hex(), "SPIRV-TERMINATOR-TARGET-SUPPORTED", list(target.supported_terminators), block.terminator.kind)
    module = _Lowering(graph, graph_object, resolve, bindings).lower()
    return SpirvKernel(module, tuple(SpirvBinding(extent, writable) for _cid, extent, writable in bindings), LOCAL_SIZE, target_cid, kernel_cid)


class _Lowering:
    def __init__(self, graph, graph_object: SemanticObject, resolve: Callable[[bytes], SemanticObject], bindings) -> None:
        self.graph = graph
        self.graph_object = graph_object
        self.resolve = resolve
        self.bindings = bindings
        self.m = _Module()
        self.pointers: dict[ValueRef, tuple[int, int]] = {}
        self.constants: dict[ValueRef, int] = {}
        self.variables: dict[ValueRef, int] = {}
        self.widths: dict[ValueRef, int] = {}

    # -- facts -----------------------------------------------------------------
    def value_type(self, ref: ValueRef) -> bytes:
        block = self.graph.blocks[ref.block]
        return block.parameters[ref.index] if ref.tag == 0 else block.nodes[ref.index].results[ref.result]

    def reject(self, rule: str, expected, actual) -> None:
        fail("XAX.SPIRV.LOWERING", self.graph_object.cid.hex(), rule, expected, actual)

    def pointer(self, ref: ValueRef, visiting: frozenset = frozenset()) -> tuple[int, int] | None:
        """Static ``(binding, byte offset)`` of a pointer value, or None while a cycle is open."""
        if ref in self.pointers:
            return self.pointers[ref]
        if ref in visiting:
            return None
        if ref.tag == 0:
            if ref.block == self.graph.entry:
                found = (ref.index - 1) // 3, 0
            else:
                incoming = set()
                for block in self.graph.blocks:
                    for target, arguments in block.terminator.edges:
                        if target == ref.block:
                            resolved = self.pointer(arguments[ref.index], visiting | {ref})
                            if resolved is not None:
                                incoming.add(resolved)
                if not incoming and visiting:
                    return None  # only reached through the open cycle so far
                if len(incoming) != 1:
                    self.reject("SPIRV-POINTER-STATIC", "one static binding and offset", sorted(incoming))
                found = incoming.pop()
        else:
            node = self.graph.blocks[ref.block].nodes[ref.index]
            base = self.pointer(node.operands[0], visiting) if node.operation in (Operation.ADDRESS_OFFSET, Operation.POINTER_CAST) else None
            if base is None:
                if node.operation in (Operation.ADDRESS_OFFSET, Operation.POINTER_CAST):
                    return None
                self.reject("SPIRV-POINTER-STATIC", "binding pointer, address_offset, or pointer_cast", node.operation)
            found = (base[0], base[1] + (node.attributes[0] if node.operation == Operation.ADDRESS_OFFSET else 0))
        if found[1] % 4:
            self.reject("SPIRV-POINTER-ALIGNED", "4-byte multiple", found[1])
        self.pointers[ref] = found
        return found

    def own_element(self, ref: ValueRef) -> bool:
        if ref.tag == 0:
            return False
        node = self.graph.blocks[ref.block].nodes[ref.index]
        if node.operation != Operation.MUL_WRAP:
            return False
        invocation = ValueRef.parameter(self.graph.entry, 0)
        constant = [operand for operand in node.operands if operand != invocation]
        if len(constant) != 1 or invocation not in node.operands:
            return False
        source = self.graph.blocks[constant[0].block].nodes[constant[0].index] if constant[0].tag else None
        return source is not None and source.operation == Operation.CONSTANT and _decode_constant(source.entity, self.resolve)[1] == 4

    def check_races(self) -> None:
        accesses = []
        for block in self.graph.blocks:
            for node in block.nodes:
                if node.operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
                    binding, offset = self.pointer(node.operands[0])
                    accesses.append((node.operation == Operation.CHECKED_STORE_BITS_LE, binding, offset, node.operands[1]))
        written = {binding for store, binding, _offset, _index in accesses if store}
        for store, binding, offset, index in accesses:
            if binding in written and (offset or not self.own_element(index)):
                self.reject("SPIRV-KERNEL-OWN-ELEMENT", "stores and loads of stored-to bindings at invocation * 4", [binding, offset, "store" if store else "load"])

    # -- module ----------------------------------------------------------------
    def lower(self) -> bytes:
        m, graph = self.m, self.graph
        for block_index, block in enumerate(graph.blocks):
            for index, cid in enumerate(block.parameters):
                self.classify(ValueRef.parameter(block_index, index), cid)
            for node_index, node in enumerate(block.nodes):
                for result, cid in enumerate(node.results):
                    self.classify(ValueRef.node_result(block_index, node_index, result), cid)
                if node.operation == Operation.CONSTANT:
                    type_cid, value = _decode_constant(node.entity, self.resolve)
                    self.constants[ValueRef.node_result(block_index, node_index, 0)] = value & ((1 << decode_bits_width(self.resolve(type_cid))) - 1)
        self.check_races()

        uint, boolean = m.uint(), m.type("TypeBool")
        m.emit("caps", "Capability", 1)  # Shader
        m.emit("caps", "MemoryModel", 0, 1)  # Logical GLSL450
        void = m.type("TypeVoid")
        uvec3 = m.type("TypeVector", uint, 3)
        input_uvec3 = m.type("TypePointer", _INPUT, uvec3)
        gid = m.id()
        m.emit("globals", "Variable", input_uvec3, gid, _INPUT)
        m.emit("decorations", "Decorate", gid, 11, 28)  # BuiltIn GlobalInvocationId
        array = m.type("TypeRuntimeArray", uint)
        m.emit("decorations", "Decorate", array, 6, 4)  # ArrayStride 4
        buffer_struct = m.type("TypeStruct", array)
        m.emit("decorations", "MemberDecorate", buffer_struct, 0, 35, 0)  # Offset 0
        m.emit("decorations", "Decorate", buffer_struct, 2)  # Block
        buffer_pointer = m.type("TypePointer", _STORAGE_BUFFER, buffer_struct)
        self.element_pointer = m.type("TypePointer", _STORAGE_BUFFER, uint)
        self.buffers = []
        for binding, (_cid, _extent, writable) in enumerate((*self.bindings, (None, 4, True))):
            variable = m.id()
            m.emit("globals", "Variable", buffer_pointer, variable, _STORAGE_BUFFER)
            m.emit("decorations", "Decorate", variable, 34, 0)  # DescriptorSet 0
            m.emit("decorations", "Decorate", variable, 33, binding)  # Binding
            if not writable:
                m.emit("decorations", "Decorate", variable, 24)  # NonWritable
            self.buffers.append(variable)
        count_struct = m.id()
        m.emit("globals", "TypeStruct", count_struct, uint)
        m.emit("decorations", "MemberDecorate", count_struct, 0, 35, 0)
        m.emit("decorations", "Decorate", count_struct, 2)
        count_pointer = m.type("TypePointer", _PUSH_CONSTANT, count_struct)
        count_member = m.type("TypePointer", _PUSH_CONSTANT, uint)
        count_variable = m.id()
        m.emit("globals", "Variable", count_pointer, count_variable, _PUSH_CONSTANT)
        function_uint = m.type("TypePointer", _FUNCTION, uint)
        function_type = m.type("TypeFunction", void)
        main = m.id()
        m.emit("entry", "EntryPoint", 5, main, *_string("main"), gid)  # GLCompute
        m.emit("modes", "ExecutionMode", main, 17, LOCAL_SIZE, 1, 1)  # LocalSize

        # Case numbering: one case per block segment, then one per trap code.
        segments = [self.segments(block) for block in graph.blocks]
        self.case_of: dict[tuple[int, int], int] = {}
        for block_index, items in enumerate(segments):
            for segment_index in range(len(items)):
                self.case_of[(block_index, segment_index)] = len(self.case_of)
        self.trap_cases: dict[int, int] = {}
        self.code: list[int] = []
        self.uint, self.bool = uint, boolean

        state = self.state = m.id()
        variables = [state]
        for ref in self.widths:
            if ref not in self.constants:
                self.variables[ref] = m.id()
                variables.append(self.variables[ref])
        labels = {name: m.id() for name in ("entry", "header", "body", "selection", "continue", "merge", "default")}
        case_labels = {case: m.id() for case in self.case_of.values()}

        bodies: dict[int, list[int]] = {}
        for block_index, items in enumerate(segments):
            for segment_index, (nodes, ends_with) in enumerate(items):
                self.code = []
                for node_index in nodes:
                    self.lower_node(block_index, node_index)
                if ends_with is None:
                    self.lower_terminator(block_index)
                else:
                    self.lower_check(block_index, ends_with, self.case_of[(block_index, segment_index + 1)])
                bodies[self.case_of[(block_index, segment_index)]] = self.code
        trap_bodies = {}
        for code, case in sorted(self.trap_cases.items(), key=lambda item: item[1]):
            self.code = []
            chain = self.ins("AccessChain", self.element_pointer, self.buffers[-1], m.constant(0), m.constant(0))
            self.ins("AtomicUMax", uint, chain, m.constant(1), m.constant(0), m.constant(code))
            self.store_state(m.constant(_DONE))
            trap_bodies[case] = self.code
            case_labels[case] = m.id()
        bodies.update(trap_bodies)

        code = m.sections["code"]
        put = lambda opcode, *operands: code.extend(((len(operands) + 1) << 16 | OP[opcode], *operands))
        put("Function", void, main, 0, function_type)
        put("Label", labels["entry"])
        put("Variable", function_uint, state, _FUNCTION)
        for variable in variables[1:]:
            put("Variable", function_uint, variable, _FUNCTION)
        self.code = []
        vector = self.ins("Load", uvec3, gid)
        invocation = self.ins("CompositeExtract", uint, vector, 0)
        count = self.ins("Load", uint, self.ins("AccessChain", count_member, count_variable, m.constant(0)))
        live = self.ins("ULessThan", boolean, invocation, count)
        entry_case = m.constant(self.case_of[(graph.entry, 0)])
        self.store_state(self.ins("Select", uint, live, entry_case, m.constant(_DONE)))
        self.raw("Store", self.variables[ValueRef.parameter(graph.entry, 0)], invocation)
        code.extend(self.code)
        put("Branch", labels["header"])
        put("Label", labels["header"])
        put("LoopMerge", labels["merge"], labels["continue"], 0)
        put("Branch", labels["body"])
        put("Label", labels["body"])
        current = m.id()
        put("Load", uint, current, state)
        put("SelectionMerge", labels["selection"], 0)
        targets = [word for case in sorted(case_labels) for word in (case, case_labels[case])]
        put("Switch", current, labels["default"], *targets)
        for case in sorted(case_labels):
            put("Label", case_labels[case])
            code.extend(bodies[case])
            put("Branch", labels["selection"])
        put("Label", labels["default"])
        self.code = []
        self.store_state(m.constant(_DONE))
        code.extend(self.code)
        put("Branch", labels["selection"])
        put("Label", labels["selection"])
        put("Branch", labels["continue"])
        put("Label", labels["continue"])
        again, going = m.id(), m.id()
        put("Load", uint, again, state)
        put("INotEqual", boolean, going, again, m.constant(_DONE))
        put("BranchConditional", going, labels["header"], labels["merge"])
        put("Label", labels["merge"])
        put("Return")
        put("FunctionEnd")
        return m.words()

    def classify(self, ref: ValueRef, cid: bytes) -> None:
        obj = self.resolve(cid)
        if _is_proof_type(obj):
            return
        if obj.body[:1] == b"\x02":  # pointer: static binding facts, no storage
            return
        if obj.body[:1] != b"\x01" or decode_bits_width(obj) > 32:
            self.reject("SPIRV-VALUE", "bits<1..32>, binding pointer, or proof", cid.hex())
        self.widths[ref] = decode_bits_width(obj)

    def segments(self, block) -> list[tuple[list[int], int | None]]:
        """Nodes per case; a trap-capable node starts a new case after its check."""
        items, current = [], []
        for node_index, node in enumerate(block.nodes):
            if self.may_trap(node):
                items.append((current, node_index))
                current = []
            current.append(node_index)
        items.append((current, None))
        return items

    def may_trap(self, node) -> bool:
        if node.operation in (Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE):
            return True
        return node.operation in (Operation.UDIV, Operation.UREM) and not self.constants.get(node.operands[1])

    # -- instructions -------------------------------------------------------------
    def raw(self, opcode: str, *operands: int) -> None:
        self.code.extend(((len(operands) + 1) << 16 | OP[opcode], *operands))

    def ins(self, opcode: str, result_type: int, *operands: int) -> int:
        result = self.m.id()
        self.raw(opcode, result_type, result, *operands)
        return result

    def store_state(self, value: int) -> None:
        self.raw("Store", self.state, value)

    def value(self, ref: ValueRef) -> int:
        if ref in self.constants:
            return self.m.constant(self.constants[ref])
        return self.ins("Load", self.uint, self.variables[ref])

    def mask(self, value: int, width: int) -> int:
        return value if width == 32 else self.ins("BitwiseAnd", self.uint, value, self.m.constant((1 << width) - 1))

    def flag(self, ref: ValueRef) -> int:
        return self.ins("INotEqual", self.bool, self.value(ref), self.m.constant(0))

    def element(self, node) -> tuple[int, int]:
        """Access chain and bounds-check condition (true = out of bounds) for a checked word access."""
        binding, offset = self.pointer(node.operands[0])
        size = node.attributes[0]
        if size != 4:
            self.reject("SPIRV-ACCESS-WIDTH", 4, size)
        limit = self.bindings[binding][1] - offset - size
        dynamic = self.value(node.operands[1])
        return binding, offset, dynamic, limit

    def lower_check(self, block_index: int, node_index: int, next_case: int) -> None:
        node = self.graph.blocks[block_index].nodes[node_index]
        if node.operation in (Operation.UDIV, Operation.UREM):
            bad = self.ins("IEqual", self.bool, self.value(node.operands[1]), self.m.constant(0))
            code = STATUS_TRAP | 2
        else:
            _binding, _offset, dynamic, limit = self.element(node)
            if limit < 0:
                bad = self.ins("IEqual", self.bool, self.m.constant(0), self.m.constant(0))
            else:
                outside = self.ins("UGreaterThan", self.bool, dynamic, self.m.constant(limit))
                misaligned = self.ins("INotEqual", self.bool, self.ins("BitwiseAnd", self.uint, dynamic, self.m.constant(3)), self.m.constant(0))
                bad = self.ins("LogicalOr", self.bool, outside, misaligned)
            code = STATUS_BOUNDS
        self.store_state(self.ins("Select", self.uint, bad, self.m.constant(self.trap_case(code)), self.m.constant(next_case)))

    def trap_case(self, code: int) -> int:
        if code not in self.trap_cases:
            self.trap_cases[code] = len(self.case_of) + len(self.trap_cases)
        return self.trap_cases[code]

    def lower_node(self, block_index: int, node_index: int) -> None:
        node = self.graph.blocks[block_index].nodes[node_index]
        result = ValueRef.node_result(block_index, node_index, 0)
        operation = node.operation
        if operation in (Operation.CONSTANT, Operation.ADDRESS_OFFSET, Operation.POINTER_CAST):
            return
        if operation == Operation.CHECKED_LOAD_BITS_LE:
            binding, offset, dynamic, _limit = self.element(node)
            index = self.ins("ShiftRightLogical", self.uint, self.ins("IAdd", self.uint, dynamic, self.m.constant(offset)), self.m.constant(2))
            chain = self.ins("AccessChain", self.element_pointer, self.buffers[binding], self.m.constant(0), index)
            self.raw("Store", self.variables[result], self.ins("Load", self.uint, chain))
            return
        if operation == Operation.CHECKED_STORE_BITS_LE:
            binding, offset, dynamic, _limit = self.element(node)
            index = self.ins("ShiftRightLogical", self.uint, self.ins("IAdd", self.uint, dynamic, self.m.constant(offset)), self.m.constant(2))
            chain = self.ins("AccessChain", self.element_pointer, self.buffers[binding], self.m.constant(0), index)
            self.raw("Store", chain, self.value(node.operands[2]))
            return
        width = self.widths[result]
        if operation in _BINARY:
            value = self.ins(_BINARY[operation], self.uint, self.value(node.operands[0]), self.value(node.operands[1]))
            value = self.mask(value, width)
        elif operation == Operation.INT_COMPARE:
            kind = IntCompare(node.attributes[0])
            left, right = self.value(node.operands[0]), self.value(node.operands[1])
            operand_width = self.widths[node.operands[0]] if node.operands[0] in self.widths else 32
            if kind in _SIGNED and operand_width < 32:
                shift = self.m.constant(32 - operand_width)
                left = self.ins("ShiftRightArithmetic", self.uint, self.ins("ShiftLeftLogical", self.uint, left, shift), shift)
                right = self.ins("ShiftRightArithmetic", self.uint, self.ins("ShiftLeftLogical", self.uint, right, shift), shift)
            condition = self.ins(_COMPARE[kind], self.bool, left, right)
            value = self.ins("Select", self.uint, condition, self.m.constant(1), self.m.constant(0))
        elif operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND):
            value = self.mask(self.value(node.operands[0]), width)
        elif operation == Operation.ROTATE_RIGHT:
            amount = node.attributes[0]
            value = self.value(node.operands[0])
            if amount:
                right = self.ins("ShiftRightLogical", self.uint, value, self.m.constant(amount))
                left = self.ins("ShiftLeftLogical", self.uint, value, self.m.constant(width - amount))
                value = self.mask(self.ins("BitwiseOr", self.uint, right, left), width)
        else:
            self.reject("SPIRV-OP-LOWERED", "supported operation", operation)
        self.raw("Store", self.variables[result], value)

    def lower_terminator(self, block_index: int) -> None:
        terminator = self.graph.blocks[block_index].terminator
        if terminator.kind == TerminatorKind.RETURN:
            self.store_state(self.m.constant(_DONE))
            return
        if terminator.kind == TerminatorKind.TRAP:
            reason, _target_data = decode_trap_payload(terminator.payload)
            self.store_state(self.m.constant(self.trap_case(STATUS_TRAP | reason)))
            return

        def machine(target: int, arguments) -> list[tuple[int, int]]:
            return [
                (self.variables[ValueRef.parameter(target, index)], self.value(argument))
                for index, argument in enumerate(arguments)
                if ValueRef.parameter(target, index) in self.variables
            ]

        if terminator.kind == TerminatorKind.BRANCH:
            (target, arguments), = terminator.edges
            for variable, value in machine(target, arguments):
                self.raw("Store", variable, value)
            self.store_state(self.m.constant(self.case_of[(target, 0)]))
            return
        (true_target, true_arguments), (false_target, false_arguments) = terminator.edges
        condition = self.flag(terminator.values[0])
        taken = machine(true_target, true_arguments)
        other = machine(false_target, false_arguments)
        if true_target == false_target:
            stores = [(variable, self.ins("Select", self.uint, condition, value, alternative)) for (variable, value), (_same, alternative) in zip(taken, other)]
        else:
            # Each side keeps the other side's parameters unchanged: a block
            # dominated by the untaken target may still read them.
            stores = [(variable, self.ins("Select", self.uint, condition, value, self.ins("Load", self.uint, variable))) for variable, value in taken]
            stores += [(variable, self.ins("Select", self.uint, condition, self.ins("Load", self.uint, variable), value)) for variable, value in other]
        for variable, value in stores:
            self.raw("Store", variable, value)
        cases = (self.m.constant(self.case_of[(true_target, 0)]), self.m.constant(self.case_of[(false_target, 0)]))
        self.store_state(self.ins("Select", self.uint, condition, *cases))


# -- Vulkan launch harness (tests and evidence only; not part of an artifact) --

_VK_API_1_1 = (1 << 22) | (1 << 12)  # VK_MAKE_API_VERSION(0, 1, 1, 0)

@dataclass(frozen=True)
class SpirvLaunch:
    buffers: tuple[bytes, ...]
    status: int
    device: str
    driver: str
    seconds: float


def vulkan_device() -> str | None:
    """Name of the first Vulkan device with a compute queue, or None."""
    try:
        import vulkan as vk

        instance = vk.vkCreateInstance(vk.VkInstanceCreateInfo(pApplicationInfo=vk.VkApplicationInfo(apiVersion=_VK_API_1_1)), None)
    except Exception:  # no loader, no ICD, or no bindings
        return None
    try:
        devices = vk.vkEnumeratePhysicalDevices(instance)
        return vk.vkGetPhysicalDeviceProperties(devices[0]).deviceName if devices else None
    finally:
        vk.vkDestroyInstance(instance, None)


def run_spirv_kernel(kernel: SpirvKernel, buffers: Sequence[bytes], count: int) -> SpirvLaunch:
    """Dispatch ``count`` invocations; each buffer must be exactly its binding's extent."""
    import time

    import vulkan as vk

    if len(buffers) != len(kernel.bindings) or any(len(data) != binding.extent for data, binding in zip(buffers, kernel.bindings)):
        raise ValueError("launch buffers must match the kernel's bindings and extents")
    if not 0 <= count < 1 << 30:
        raise ValueError("invocation count must be below 2^30 (own-element offsets must not wrap)")
    instance = vk.vkCreateInstance(vk.VkInstanceCreateInfo(pApplicationInfo=vk.VkApplicationInfo(apiVersion=_VK_API_1_1)), None)
    try:
        physical = vk.vkEnumeratePhysicalDevices(instance)[0]
        properties = vk.vkGetPhysicalDeviceProperties(physical)
        family = next(index for index, item in enumerate(vk.vkGetPhysicalDeviceQueueFamilyProperties(physical)) if item.queueFlags & vk.VK_QUEUE_COMPUTE_BIT)
        queue_info = vk.VkDeviceQueueCreateInfo(queueFamilyIndex=family, queueCount=1, pQueuePriorities=[1.0])
        device_info = vk.VkDeviceCreateInfo(pQueueCreateInfos=[queue_info])
        device = vk.vkCreateDevice(physical, device_info, None)
        queue = vk.vkGetDeviceQueue(device, family, 0)
        memory_properties = vk.vkGetPhysicalDeviceMemoryProperties(physical)
        wanted = vk.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | vk.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT
        contents = [*buffers, bytes(4)]
        allocations = []
        for data in contents:
            buffer = vk.vkCreateBuffer(device, vk.VkBufferCreateInfo(size=len(data), usage=vk.VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, sharingMode=vk.VK_SHARING_MODE_EXCLUSIVE), None)
            requirements = vk.vkGetBufferMemoryRequirements(device, buffer)
            kind = next(
                index for index in range(memory_properties.memoryTypeCount)
                if requirements.memoryTypeBits & (1 << index) and memory_properties.memoryTypes[index].propertyFlags & wanted == wanted
            )
            memory = vk.vkAllocateMemory(device, vk.VkMemoryAllocateInfo(allocationSize=requirements.size, memoryTypeIndex=kind), None)
            vk.vkBindBufferMemory(device, buffer, memory, 0)
            mapped = vk.vkMapMemory(device, memory, 0, len(data), 0)
            vk.ffi.memmove(mapped, data, len(data))
            vk.vkUnmapMemory(device, memory)
            allocations.append((buffer, memory, len(data)))
        bindings = [vk.VkDescriptorSetLayoutBinding(binding=index, descriptorType=vk.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, descriptorCount=1, stageFlags=vk.VK_SHADER_STAGE_COMPUTE_BIT) for index in range(len(contents))]
        set_layout = vk.vkCreateDescriptorSetLayout(device, vk.VkDescriptorSetLayoutCreateInfo(pBindings=bindings), None)
        layout = vk.vkCreatePipelineLayout(device, vk.VkPipelineLayoutCreateInfo(
            pSetLayouts=[set_layout], pPushConstantRanges=[vk.VkPushConstantRange(stageFlags=vk.VK_SHADER_STAGE_COMPUTE_BIT, offset=0, size=4)],
        ), None)
        shader = vk.vkCreateShaderModule(device, vk.VkShaderModuleCreateInfo(codeSize=len(kernel.module), pCode=kernel.module), None)
        # Keep every nested create-info alive across the call (the bindings
        # copy structs by value, and nested strings must outlive the copy).
        stage = vk.VkPipelineShaderStageCreateInfo(stage=vk.VK_SHADER_STAGE_COMPUTE_BIT, module=shader, pName="main")
        pipeline_info = vk.VkComputePipelineCreateInfo(stage=stage, layout=layout, basePipelineIndex=-1)
        pipeline = vk.vkCreateComputePipelines(device, None, 1, [pipeline_info], None)[0]
        pool = vk.vkCreateDescriptorPool(device, vk.VkDescriptorPoolCreateInfo(maxSets=1, pPoolSizes=[vk.VkDescriptorPoolSize(type=vk.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, descriptorCount=len(contents))]), None)
        descriptor = vk.vkAllocateDescriptorSets(device, vk.VkDescriptorSetAllocateInfo(descriptorPool=pool, pSetLayouts=[set_layout]))[0]
        buffer_infos = [vk.VkDescriptorBufferInfo(buffer=buffer, offset=0, range=size) for buffer, _memory, size in allocations]
        writes = [
            vk.VkWriteDescriptorSet(dstSet=descriptor, dstBinding=index, descriptorType=vk.VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, pBufferInfo=[info])
            for index, info in enumerate(buffer_infos)
        ]
        vk.vkUpdateDescriptorSets(device, len(contents), writes, 0, None)
        command_pool = vk.vkCreateCommandPool(device, vk.VkCommandPoolCreateInfo(queueFamilyIndex=family), None)
        command = vk.vkAllocateCommandBuffers(device, vk.VkCommandBufferAllocateInfo(commandPool=command_pool, level=vk.VK_COMMAND_BUFFER_LEVEL_PRIMARY, commandBufferCount=1))[0]
        vk.vkBeginCommandBuffer(command, vk.VkCommandBufferBeginInfo(flags=vk.VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT))
        vk.vkCmdBindPipeline(command, vk.VK_PIPELINE_BIND_POINT_COMPUTE, pipeline)
        vk.vkCmdBindDescriptorSets(command, vk.VK_PIPELINE_BIND_POINT_COMPUTE, layout, 0, 1, [descriptor], 0, None)
        vk.vkCmdPushConstants(command, layout, vk.VK_SHADER_STAGE_COMPUTE_BIT, 0, 4, vk.ffi.new("uint32_t[1]", [count]))
        vk.vkCmdDispatch(command, (count + kernel.local_size - 1) // kernel.local_size, 1, 1)
        vk.vkEndCommandBuffer(command)
        fence = vk.vkCreateFence(device, vk.VkFenceCreateInfo(), None)
        start = time.perf_counter()
        submit = vk.VkSubmitInfo(pCommandBuffers=[command])
        vk.vkQueueSubmit(queue, 1, [submit], fence)
        vk.vkWaitForFences(device, 1, [fence], vk.VK_TRUE, 10 ** 11)
        seconds = time.perf_counter() - start
        results = []
        for _buffer, memory, size in allocations:
            mapped = vk.vkMapMemory(device, memory, 0, size, 0)
            results.append(bytes(mapped[:size]))
            vk.vkUnmapMemory(device, memory)
        vk.vkDestroyFence(device, fence, None)
        vk.vkDestroyCommandPool(device, command_pool, None)
        vk.vkDestroyDescriptorPool(device, pool, None)
        vk.vkDestroyPipeline(device, pipeline, None)
        vk.vkDestroyShaderModule(device, shader, None)
        vk.vkDestroyPipelineLayout(device, layout, None)
        vk.vkDestroyDescriptorSetLayout(device, set_layout, None)
        for buffer, memory, _size in allocations:
            vk.vkDestroyBuffer(device, buffer, None)
            vk.vkFreeMemory(device, memory, None)
        vk.vkDestroyDevice(device, None)
        driver = f"{properties.driverVersion:#x}"
        return SpirvLaunch(tuple(results[:-1]), struct.unpack("<I", results[-1])[0], properties.deviceName, driver, seconds)
    finally:
        vk.vkDestroyInstance(instance, None)


def reference_dispatch(reader: StoreReader, kernel_cid: bytes, buffers: Sequence[bytes], count: int) -> tuple[tuple[bytes, ...], int]:
    """Run each invocation on the reference executor, in index order, over shared storage.

    For a kernel that satisfies ``SPIRV-KERNEL-OWN-ELEMENT`` the order cannot
    matter.  Returns the final buffers and the status word a device would hold.
    """
    from xax_compiler import XaxTrap, _RuntimeEffect, _RuntimePointer, _RuntimeResource, _RuntimeStorage, _decode_resource_type, execute

    resolve = store_resolver(reader)
    bindings, _graph = _kernel_interface(resolve(kernel_cid), resolve)
    _graph_object, parameters, _returns = _decode_function_interface(resolve(kernel_cid), resolve)
    storages = [_RuntimeStorage(bytearray(data)) for data in buffers]
    status = 0
    for invocation in range(count):
        arguments: list[object] = [invocation]
        for index, storage in enumerate(storages):
            view = _decode_resource_type(resolve(parameters[2 + 3 * index]))
            arguments += [_RuntimePointer(storage, 0), _RuntimeResource(view.kind, view.state, storage), _RuntimeEffect(storage)]
        try:
            execute(reader, kernel_cid, arguments, fuel=10_000_000)
        except XaxTrap as trap:
            code = STATUS_BOUNDS if trap.payload == b"memory-check" else STATUS_TRAP | trap.reason
            status = max(status, code)
    return tuple(bytes(storage.data) for storage in storages), status
