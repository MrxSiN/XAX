from __future__ import annotations

from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    constant,
    function,
    graph_fragment,
    object_with_refs,
    write_store,
    x86_64_windows_target,
)
from xax_x86_64 import compile_native


def _reader(functions, objects):
    target = x86_64_windows_target()
    module = object_with_refs(Kind.MODULE, [*functions, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    reader = StoreReader(write_store(root.cid, [*objects, *functions, target, module, root]))
    return reader, target


def _function_bytes(image, function_cid):
    offsets = dict(image.function_offsets)
    start = offsets[function_cid]
    end = min((offset for cid, offset in image.function_offsets if offset > start), default=len(image.code))
    return image.code[start:end].rstrip(b"\x90")


def test_simple_add_stays_entirely_in_registers():
    b32 = bits_type(32)
    graph = graph_fragment(
        [
            Block(
                (b32, b32),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    entry = function(graph, (b32, b32), (b32,))
    reader, target = _reader([entry], [b32, graph])
    image = compile_native(reader, entry.cid, target.cid)

    # add ecx, edx; mov eax, ecx; ret
    assert image.code == bytes.fromhex("01d189c8c3")


def test_arithmetic_chain_reuses_register_residency():
    b32 = bits_type(32)
    graph = graph_fragment(
        [
            Block(
                (b32, b32, b32),
                (
                    Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),
                    Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 2)), (b32,)),
                ),
                Terminator.return_((ValueRef.node_result(0, 1),)),
            )
        ]
    )
    entry = function(graph, (b32, b32, b32), (b32,))
    reader, target = _reader([entry], [b32, graph])
    code = compile_native(reader, entry.cid, target.cid).code

    assert b"\x48\x81\xec" not in code  # no frame
    assert code == bytes.fromhex("01d14401c189c8c3")


def test_simple_conditional_uses_register_edge_moves_without_stack_slots():
    b1, b32 = bits_type(1), bits_type(32)
    graph = graph_fragment(
        [
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
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(1, 0),)),
            ),
            Block(
                (b32, b32),
                (Node(Operation.SUB_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(2, 0),)),
            ),
        ]
    )
    entry = function(graph, (b1, b32, b32), (b32,))
    reader, target = _reader([entry], [b1, b32, graph])
    code = compile_native(reader, entry.cid, target.cid).code

    assert b"\x48\x81\xec" not in code
    assert b"\x24" not in code  # no rsp-SIB stack load/store encoding


def test_direct_call_uses_abi_argument_and_result_registers_without_spill_reload():
    b32 = bits_type(32)
    callee_graph = graph_fragment(
        [
            Block(
                (b32, b32),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    callee = function(callee_graph, (b32, b32), (b32,))
    caller_graph = graph_fragment(
        [
            Block(
                (b32, b32),
                (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,), entity=callee),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (b32, b32), (b32,))
    reader, target = _reader([callee, caller], [b32, callee_graph, caller_graph])
    image = compile_native(reader, caller.cid, target.cid)
    code = _function_bytes(image, caller.cid)

    # Windows x64 requires 32-byte shadow space; alignment makes the frame 0x28.
    # There are no argument spills/reloads: call follows the frame allocation.
    assert code[:7] == bytes.fromhex("4881ec28000000")
    assert code[7] == 0xE8
    assert code[-8:] == bytes.fromhex("4881c428000000c3")
    assert len(code) == 20


def test_register_pressure_spills_only_after_caller_saved_pool_is_exhausted():
    b32 = bits_type(32)
    constants = [constant(b32, value) for value in range(1, 8)]
    nodes = [Node(Operation.CONSTANT, (), (b32,), entity=item) for item in constants]
    current = ValueRef.node_result(0, 0)
    for index in range(1, len(constants)):
        nodes.append(Node(Operation.ADD_WRAP, (current, ValueRef.node_result(0, index)), (b32,)))
        current = ValueRef.node_result(0, len(nodes) - 1)
    graph = graph_fragment([Block((), tuple(nodes), Terminator.return_((current,)))])
    entry = function(graph, (), (b32,))
    reader, target = _reader([entry], [b32, *constants, graph])
    code = compile_native(reader, entry.cid, target.cid).code

    assert code.startswith(bytes.fromhex("4881ec"))
    # Genuine pressure creates both a spill store and reload through rsp.
    assert b"\x24" in code
