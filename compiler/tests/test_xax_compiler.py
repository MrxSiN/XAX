import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from blake3 import blake3

from xax_compiler import (
    aarch64_baremetal_target,
    analyze_realtime,
    atomic_capability,
    AtomicFamily,
    AtomicLitmusEvent,
    AtomicOrder,
    AtomicRmwKind,
    AtomicScope,
    AtomicSupport,
    Block,
    CompareExchangeStrength,
    CompileTimeBudget,
    CompileTimeEvaluator,
    CompileTimeInput,
    CompileTimeResult,
    Cursor,
    EffectDomain,
    Kind,
    MemoryEvent,
    Node,
    NonsemanticRecord,
    Operation,
    OpaqueKind,
    MetaCapability,
    Permission,
    RecursionMember,
    ResourceFlags,
    RealtimeProfile,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    XaxTrap,
    bits_type,
    constant,
    decode_object,
    decode_native_target,
    derive_effect_summary,
    effect_type,
    execute,
    execute_group_member,
    function,
    graph_fragment,
    memory_effect_type,
    materialize_compile_time,
    object_with_refs,
    opaque_type,
    pointer_type,
    recursion_group,
    resource_type,
    semantic_cid,
    stack_owner_type,
    target,
    uleb,
    verify_store,
    validate_atomic_litmus,
    validate_handler_entry,
    validate_memory_events,
    validate_realtime_profile,
    wasm32_target,
    write_store,
    x86_64_windows_target,
    zigzag,
)
from xax_aarch64 import compile_aarch64, run_aarch64_qemu
from xax_x86_64 import compile_native, run_native_isolated
from xax_wasm import compile_wasm, run_wasm_isolated


NODE = shutil.which("node") or str(Path(sys.executable).parents[1] / "node" / "bin" / "node.exe")


def atomic_fixture(target_object=None):
    b1 = bits_type(1)
    b32 = bits_type(32)
    pointer = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.ATOMIC_STORE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(AtomicOrder.RELEASE, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_LOAD, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 0)), (b32, effect), attributes=(AtomicOrder.ACQUIRE, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_RMW, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 2, 1)), (b32, effect), attributes=(AtomicRmwKind.ADD_WRAP, AtomicOrder.ACQ_REL, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_CMPXCHG, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 3, 0), ValueRef.parameter(0, 2), ValueRef.node_result(0, 3, 1)), (b32, b1, effect), attributes=(AtomicOrder.SEQ_CST, AtomicOrder.ACQUIRE, AtomicScope.SYSTEM, 4, CompareExchangeStrength.STRONG)),
        Node(Operation.ATOMIC_FENCE, (ValueRef.node_result(0, 4, 2),), (effect,), attributes=(AtomicOrder.SEQ_CST, AtomicScope.SYSTEM)),
        Node(Operation.ATOMIC_STORE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 2), ValueRef.node_result(0, 5, 0)), (effect,), attributes=(AtomicOrder.SEQ_CST, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_LOAD, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 6, 0)), (b32, effect), attributes=(AtomicOrder.SEQ_CST, AtomicScope.SYSTEM, 4)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 7, 1)), ()),
    )
    graph = graph_fragment([Block((b32, b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, 7, 0),)))])
    entry = function(graph, (b32, b32, b32), (b32,))
    members = [entry] + ([target_object] if target_object is not None else [])
    module = object_with_refs(Kind.MODULE, members)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b1, b32, pointer, owner, effect, graph, entry, module, root]
    if target_object is not None:
        objects.append(target_object)
    return StoreReader(write_store(root.cid, objects)), entry


def resource_lifecycle_fixture(target_object=None):
    b32 = bits_type(32)
    filesystem = effect_type(EffectDomain.FILESYSTEM, 7)
    opened = resource_type(2, 1, flags=ResourceFlags.ACQUIRABLE, instance=11, transitions=(2,))
    closed = resource_type(2, 2, flags=ResourceFlags.PARTITIONABLE | ResourceFlags.RELEASABLE, instance=11)
    nodes = (
        Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (opened, filesystem)),
        Node(Operation.RESOURCE_TRANSITION, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (closed, filesystem)),
        Node(Operation.RESOURCE_SPLIT, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)), (closed, closed, filesystem)),
        Node(Operation.RESOURCE_JOIN, (ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 1), ValueRef.node_result(0, 2, 2)), (closed, filesystem)),
        Node(Operation.RESOURCE_TRANSFER, (ValueRef.node_result(0, 3, 0), ValueRef.node_result(0, 3, 1)), (closed, filesystem)),
        Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 4, 0), ValueRef.node_result(0, 4, 1)), (filesystem,)),
    )
    graph = graph_fragment(
        [Block((b32, filesystem), nodes, Terminator.return_((ValueRef.parameter(0, 0), ValueRef.node_result(0, 5, 0))))]
    )
    entry = function(graph, (b32, filesystem), (b32, filesystem))
    referenced = [entry] + ([target_object] if target_object is not None else [])
    module = object_with_refs(Kind.MODULE, referenced)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b32, filesystem, opened, closed, graph, entry, module, root]
    if target_object is not None:
        objects.append(target_object)
    return StoreReader(write_store(root.cid, objects)), entry, (b32, filesystem, opened, closed)


def generic_resource_call_fixture(target_object=None):
    b32 = bits_type(32)
    effect = effect_type(EffectDomain.IO, 2)
    handle = resource_type(4, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE)
    callee_graph = graph_fragment(
        [Block((handle, effect), (Node(Operation.RESOURCE_TRANSFER, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (handle, effect)),), Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1))))]
    )
    callee = function(callee_graph, (handle, effect), (handle, effect))
    caller_graph = graph_fragment(
        [
            Block(
                (b32, effect),
                (
                    Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (handle, effect)),
                    Node(Operation.CALL_DIRECT, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (handle, effect), entity=callee),
                    Node(Operation.RESOURCE_RELEASE, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)), (effect,)),
                ),
                Terminator.return_((ValueRef.parameter(0, 0), ValueRef.node_result(0, 2, 0))),
            )
        ]
    )
    caller = function(caller_graph, (b32, effect), (b32, effect))
    referenced = [callee, caller] + ([target_object] if target_object is not None else [])
    module = object_with_refs(Kind.MODULE, referenced)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b32, effect, handle, callee_graph, callee, caller_graph, caller, module, root]
    if target_object is not None:
        objects.append(target_object)
    return StoreReader(write_store(root.cid, objects)), caller


def fixture():
    b32 = bits_type(32)
    one = constant(b32, 1)
    module = object_with_refs(Kind.MODULE, [b32, one])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return root, [b32, one, module, root]


def graph_fixture():
    b32 = bits_type(32)
    add = Node(
        Operation.ADD_WRAP,
        (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)),
        (b32,),
    )
    graph = graph_fragment(
        [Block((b32, b32), (add,), Terminator.return_((ValueRef.node_result(0, 0),)))]
    )
    fn = function(graph, (b32, b32), (b32,))
    module = object_with_refs(Kind.MODULE, [fn])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return root, [b32, graph, fn, module, root]


def all_kinds_fixture():
    b32 = bits_type(32)
    one = constant(b32, 1)
    add = Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,))
    graph = graph_fragment([Block((b32, b32), (add,), Terminator.return_((ValueRef.node_result(0, 0),)))])
    fn = function(graph, (b32, b32), (b32,))
    recursive_graph = graph_fragment(
        [
            Block(
                (b32,),
                (Node(Operation.CALL_GROUP_MEMBER, (ValueRef.parameter(0, 0),), (b32,), member=0),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    group = recursion_group([RecursionMember(recursive_graph, (b32,), (b32,))])
    target_object = target(b"fixture-target")
    module = object_with_refs(Kind.MODULE, [b32, one, fn, group, target_object])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return root, [b32, one, graph, fn, recursive_graph, group, target_object, module, root]


def direct_call_fixture():
    b8 = bits_type(8)
    add_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    add = function(add_graph, (b8, b8), (b8,))
    caller_graph = graph_fragment(
        [
            Block(
                (b8, b8),
                (
                    Node(
                        Operation.CALL_DIRECT,
                        (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)),
                        (b8,),
                        entity=add,
                    ),
                ),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    caller = function(caller_graph, (b8, b8), (b8,))
    module = object_with_refs(Kind.MODULE, [add, caller])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return root, [b8, add_graph, add, caller_graph, caller, module, root], caller


def resource_call_fixture(caller_nodes=None):
    b8 = bits_type(8)
    pointer = pointer_type(b8, alignment=1)
    owner = stack_owner_type()
    effect = memory_effect_type()
    callee_graph = graph_fragment(
        [Block((owner, effect), (), Terminator.return_((ValueRef.parameter(0, 0), ValueRef.parameter(0, 1))))]
    )
    callee = function(callee_graph, (owner, effect), (owner, effect))
    nodes = caller_nodes(callee, pointer, owner, effect) if caller_nodes else (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(1, 1)),
        Node(
            Operation.CALL_DIRECT,
            (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2)),
            (owner, effect),
            entity=callee,
        ),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)), ()),
    )
    caller_graph = graph_fragment([Block((), nodes, Terminator.return_())])
    caller = function(caller_graph, (), ())
    module = object_with_refs(Kind.MODULE, [callee, caller])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b8, pointer, owner, effect, callee_graph, callee, caller_graph, caller, module, root]
    return StoreReader(write_store(root.cid, objects)), caller


def resource_store_call_fixture(permission=Permission.READ_WRITE, extent=4):
    b32 = bits_type(32)
    pointer = pointer_type(b32, permission, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    store = Node(
        Operation.STORE_BITS_LE,
        (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
        (effect,),
        attributes=(4, 4),
    )
    callee_graph = graph_fragment(
        [Block(
            (pointer, b32, owner, effect),
            (store,),
            Terminator.return_((ValueRef.parameter(0, 2), ValueRef.node_result(0, 0))),
        )]
    )
    callee = function(callee_graph, (pointer, b32, owner, effect), (owner, effect))
    caller_nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(extent, 4)),
        Node(
            Operation.CALL_DIRECT,
            (
                ValueRef.node_result(0, 0, 0),
                ValueRef.parameter(0, 0),
                ValueRef.node_result(0, 0, 1),
                ValueRef.node_result(0, 0, 2),
            ),
            (owner, effect),
            entity=callee,
        ),
        Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 1)),
            (b32, effect),
            attributes=(4, 4),
        ),
        Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 2, 1)),
            (),
        ),
    )
    caller_graph = graph_fragment(
        [Block((b32,), caller_nodes, Terminator.return_((ValueRef.node_result(0, 2, 0),)))]
    )
    caller = function(caller_graph, (b32,), (b32,))
    module = object_with_refs(Kind.MODULE, [callee, caller])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b32, pointer, owner, effect, callee_graph, callee, caller_graph, caller, module, root]
    return StoreReader(write_store(root.cid, objects)), caller, callee, (b32, pointer, owner, effect)


def resource_load_call_fixture(permission=Permission.READ_WRITE, extent=4, initialize=True):
    b32 = bits_type(32)
    pointer = pointer_type(b32, permission, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    load = Node(
        Operation.LOAD_BITS_LE,
        (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
        (b32, effect),
        attributes=(4, 4),
    )
    callee_graph = graph_fragment(
        [Block(
            (pointer, owner, effect),
            (load,),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1))),
        )]
    )
    callee = function(callee_graph, (pointer, owner, effect), (b32, owner, effect))
    alloc = Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(extent, 4))
    if initialize:
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
            (effect,),
            attributes=(4, 4),
        )
        call = Node(
            Operation.CALL_DIRECT,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 0)),
            (b32, owner, effect),
            entity=callee,
        )
        post_load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 2, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        end = Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 2, 1), ValueRef.node_result(0, 3, 1)),
            (),
        )
        caller_nodes = (alloc, store, call, post_load, end)
        caller_returns = (b32, b32)
        terminator = Terminator.return_((ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 3, 0)))
    else:
        call = Node(
            Operation.CALL_DIRECT,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2)),
            (b32, owner, effect),
            entity=callee,
        )
        end = Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 1, 1), ValueRef.node_result(0, 1, 2)),
            (),
        )
        caller_nodes = (alloc, call, end)
        caller_returns = (b32,)
        terminator = Terminator.return_((ValueRef.node_result(0, 1, 0),))
    caller_graph = graph_fragment([Block((b32,), caller_nodes, terminator)])
    caller = function(caller_graph, (b32,), caller_returns)
    module = object_with_refs(Kind.MODULE, [callee, caller])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b32, pointer, owner, effect, callee_graph, callee, caller_graph, caller, module, root]
    return StoreReader(write_store(root.cid, objects)), caller, callee, (b32, pointer, owner, effect)


def resource_store_load_call_fixture(permission=Permission.READ_WRITE, extent=4):
    b32 = bits_type(32)
    pointer = pointer_type(b32, permission, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    store = Node(
        Operation.STORE_BITS_LE,
        (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
        (effect,),
        attributes=(4, 4),
    )
    load = Node(
        Operation.LOAD_BITS_LE,
        (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 0)),
        (b32, effect),
        attributes=(4, 4),
    )
    callee_graph = graph_fragment([Block(
        (pointer, b32, owner, effect),
        (store, load),
        Terminator.return_((ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 2), ValueRef.node_result(0, 1, 1))),
    )])
    callee = function(callee_graph, (pointer, b32, owner, effect), (b32, owner, effect))
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(extent, 4)),
        Node(
            Operation.CALL_DIRECT,
            (
                ValueRef.node_result(0, 0, 0),
                ValueRef.parameter(0, 0),
                ValueRef.node_result(0, 0, 1),
                ValueRef.node_result(0, 0, 2),
            ),
            (b32, owner, effect),
            entity=callee,
        ),
        Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 2)),
            (b32, effect),
            attributes=(4, 4),
        ),
        Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 1, 1), ValueRef.node_result(0, 2, 1)),
            (),
        ),
    )
    caller_graph = graph_fragment([Block(
        (b32,),
        nodes,
        Terminator.return_((ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 2, 0))),
    )])
    caller = function(caller_graph, (b32,), (b32, b32))
    module = object_with_refs(Kind.MODULE, [callee, caller])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b32, pointer, owner, effect, callee_graph, callee, caller_graph, caller, module, root]
    return StoreReader(write_store(root.cid, objects)), caller, callee, (b32, pointer, owner, effect)


def resource_access_sequence_call_fixture(
    sequence, permission=Permission.READ_WRITE, initialize_before_call=None
):
    if not sequence or any(access not in "SL" for access in sequence):
        raise ValueError("sequence must contain only S/L accesses")
    b32 = bits_type(32)
    pointer = pointer_type(b32, permission, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    has_store = "S" in sequence
    has_load = "L" in sequence
    if has_store:
        parameters = (pointer, b32, owner, effect)
        owner_parameter = 2
        effect_parameter = 3
    else:
        parameters = (pointer, owner, effect)
        owner_parameter = 1
        effect_parameter = 2
    callee_nodes = []
    frontier = ValueRef.parameter(0, effect_parameter)
    last_load = None
    for access in sequence:
        node_index = len(callee_nodes)
        if access == "S":
            callee_nodes.append(Node(
                Operation.STORE_BITS_LE,
                (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), frontier),
                (effect,),
                attributes=(4, 4),
            ))
            frontier = ValueRef.node_result(0, node_index, 0)
        else:
            callee_nodes.append(Node(
                Operation.LOAD_BITS_LE,
                (ValueRef.parameter(0, 0), frontier),
                (b32, effect),
                attributes=(4, 4),
            ))
            last_load = ValueRef.node_result(0, node_index, 0)
            frontier = ValueRef.node_result(0, node_index, 1)
    if has_load:
        callee_returns = (b32, owner, effect)
        callee_term = Terminator.return_((last_load, ValueRef.parameter(0, owner_parameter), frontier))
    else:
        callee_returns = (owner, effect)
        callee_term = Terminator.return_((ValueRef.parameter(0, owner_parameter), frontier))
    callee_graph = graph_fragment([Block(parameters, tuple(callee_nodes), callee_term)])
    callee = function(callee_graph, parameters, callee_returns)

    caller_nodes = [Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4))]
    call_effect = ValueRef.node_result(0, 0, 2)
    if initialize_before_call is None:
        initialize_before_call = sequence[0] == "L"
    if initialize_before_call:
        caller_nodes.append(Node(
            Operation.STORE_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), call_effect),
            (effect,),
            attributes=(4, 4),
        ))
        call_effect = ValueRef.node_result(0, 1, 0)
    call_index = len(caller_nodes)
    call_operands = [ValueRef.node_result(0, 0, 0)]
    if has_store:
        call_operands.append(ValueRef.parameter(0, 0))
    call_operands.extend((ValueRef.node_result(0, 0, 1), call_effect))
    caller_nodes.append(Node(
        Operation.CALL_DIRECT,
        tuple(call_operands),
        callee_returns,
        entity=callee,
    ))
    owner_result = 1 if has_load else 0
    effect_result = 2 if has_load else 1
    post_load_index = len(caller_nodes)
    caller_nodes.append(Node(
        Operation.LOAD_BITS_LE,
        (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, call_index, effect_result)),
        (b32, effect),
        attributes=(4, 4),
    ))
    end_index = len(caller_nodes)
    caller_nodes.append(Node(
        Operation.STACK_END,
        (ValueRef.node_result(0, call_index, owner_result), ValueRef.node_result(0, post_load_index, 1)),
        (),
    ))
    if has_load:
        caller_returns = (b32, b32)
        caller_term = Terminator.return_((ValueRef.node_result(0, call_index, 0), ValueRef.node_result(0, post_load_index, 0)))
    else:
        caller_returns = (b32,)
        caller_term = Terminator.return_((ValueRef.node_result(0, post_load_index, 0),))
    caller_graph = graph_fragment([Block((b32,), tuple(caller_nodes), caller_term)])
    caller = function(caller_graph, (b32,), caller_returns)
    module = object_with_refs(Kind.MODULE, [callee, caller])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b32, pointer, owner, effect, callee_graph, callee, caller_graph, caller, module, root]
    return StoreReader(write_store(root.cid, objects)), caller, callee


def stack_memory_fixture(permission=Permission.READ_WRITE, target_object=None):
    b32 = bits_type(32)
    pointer = pointer_type(b32, permission, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    nodes = (
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
        Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 1)),
            (),
        ),
    )
    graph = graph_fragment(
        [Block((b32,), nodes, Terminator.return_((ValueRef.node_result(0, 2),)))]
    )
    fn = function(graph, (b32,), (b32,))
    module = object_with_refs(Kind.MODULE, [fn, *((target_object,) if target_object else ())])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b32, pointer, owner, effect, graph, fn, *((target_object,) if target_object else ()), module, root]
    return StoreReader(write_store(root.cid, objects)), fn, (b32, pointer, owner, effect), nodes


def native_branch_fixture(target_factory=x86_64_windows_target):
    b1, b32 = bits_type(1), bits_type(32)
    add_graph = graph_fragment(
        [
            Block(
                (b32, b32),
                (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ]
    )
    add = function(add_graph, (b32, b32), (b32,))
    entry_graph = graph_fragment(
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
                (
                    Node(
                        Operation.CALL_DIRECT,
                        (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)),
                        (b32,),
                        entity=add,
                    ),
                ),
                Terminator.return_((ValueRef.node_result(1, 0),)),
            ),
            Block(
                (b32, b32),
                (Node(Operation.SUB_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 1)), (b32,)),),
                Terminator.return_((ValueRef.node_result(2, 0),)),
            ),
        ]
    )
    entry = function(entry_graph, (b1, b32, b32), (b32,))
    target_object = target_factory()
    module = object_with_refs(Kind.MODULE, [add, entry, target_object])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [b1, b32, add_graph, add, entry_graph, entry, target_object, module, root]
    return StoreReader(write_store(root.cid, objects)), entry, target_object


def compile_time_fixture():
    b1, b32 = bits_type(1), bits_type(32)
    type_ref, constant_ref = opaque_type(OpaqueKind.TYPE), opaque_type(OpaqueKind.CONSTANT)
    target_ref, function_ref = opaque_type(OpaqueKind.TARGET), opaque_type(OpaqueKind.FUNCTION)
    five = constant(b32, 5)
    target_object = x86_64_windows_target()
    nodes = (
        Node(Operation.META_TYPE_BITS_WIDTH, (ValueRef.parameter(0, 0),), (b32,)),
        Node(Operation.META_CONSTANT_VALUE, (ValueRef.parameter(0, 1),), (b32,)),
        Node(Operation.META_TARGET_SUPPORTS, (ValueRef.parameter(0, 2),), (b1,), attributes=(Operation.ADD_WRAP,)),
        Node(Operation.META_DECLARED_INPUT, (), (b32,), attributes=(0,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (b32,)),
        Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 4), ValueRef.node_result(0, 3)), (b32,)),
        Node(
            Operation.META_MATERIALIZE_CONSTANT_FUNCTION,
            (ValueRef.parameter(0, 0), ValueRef.node_result(0, 5)),
            (function_ref,),
        ),
    )
    graph = graph_fragment(
        [Block((type_ref, constant_ref, target_ref), nodes, Terminator.return_((ValueRef.node_result(0, 6), ValueRef.node_result(0, 0), ValueRef.node_result(0, 2))))]
    )
    entry = function(graph, (type_ref, constant_ref, target_ref), (function_ref, b32, b1))
    module = object_with_refs(Kind.MODULE, (entry, target_object))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = (b1, b32, type_ref, constant_ref, target_ref, function_ref, graph, entry, target_object, module, root)
    return StoreReader(write_store(root.cid, objects)), entry, b32, five, target_object


class EncodingTests(unittest.TestCase):
    def test_uleb_and_zigzag(self):
        for value in (0, 1, 127, 128, 16_383, 16_384, 2**64 - 1):
            cursor = Cursor(uleb(value))
            self.assertEqual(cursor.uleb(), value)
            cursor.end()
        self.assertEqual([zigzag(n) for n in (0, -1, 1, -2, 2)], [0, 1, 2, 3, 4])
        self.assertEqual([Cursor(uleb(n)).zigzag() for n in range(5)], [0, -1, 1, -2, 2])

    def test_boolean_rejects_other_values(self):
        self.assertFalse(Cursor(b"\x00").boolean())
        self.assertTrue(Cursor(b"\x01").boolean())
        with self.assertRaisesRegex(XaxError, "XAX.CANON.BOOL"):
            Cursor(b"\x02").boolean()

    def test_noncanonical_uleb_rejected(self):
        with self.assertRaisesRegex(XaxError, "XAX.CANON.ULEB_NON_MINIMAL"):
            Cursor(b"\x80\x00").uleb()

    def test_unterminated_uleb_rejected(self):
        with self.assertRaisesRegex(XaxError, "XAX.CANON.ULEB_UNTERMINATED"):
            Cursor(b"\x80").uleb()

    def test_object_cid_roundtrip(self):
        obj = bits_type(64)
        self.assertEqual(decode_object(obj.envelope()), obj)
        self.assertEqual(obj.cid, semantic_cid(obj.kind, 1, (), obj.body))

    def test_cid_mismatch_rejected(self):
        obj = bits_type(32)
        data = bytearray(obj.envelope())
        data[1] ^= 1
        with self.assertRaisesRegex(XaxError, "XAX.IDENTITY.CID_MISMATCH"):
            decode_object(bytes(data))


class BuildTests(unittest.TestCase):
    def test_wheel_build_is_reproducible(self):
        project = Path(__file__).parents[1]
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = "946684800"
        with tempfile.TemporaryDirectory() as temporary:
            wheels = []
            for run in ("a", "b"):
                shutil.rmtree(project / "build", ignore_errors=True)
                output = Path(temporary) / run
                output.mkdir()
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "wheel",
                        str(project),
                        "--no-deps",
                        "--no-build-isolation",
                        "--wheel-dir",
                        str(output),
                    ],
                    check=True,
                    capture_output=True,
                    env=environment,
                )
                wheels.append(next(output.glob("*.whl")).read_bytes())
        self.assertEqual(wheels[0], wheels[1])
        with zipfile.ZipFile(io.BytesIO(wheels[0])) as archive:
            for module in ("xax_artifact", "xax_aarch64", "xax_build", "xax_compiler", "xax_platform", "xax_strings", "xax_wasm", "xax_wasm_legacy", "xax_workspace", "xax_x86_64"):
                self.assertEqual(archive.read(f"{module}.py"), (project / "src" / f"{module}.py").read_bytes())


class StoreTests(unittest.TestCase):
    fixture_path = Path(__file__).parent / "fixtures" / "c0_all_kinds.xax.hex"

    def test_canonical_roundtrip_and_lookup(self):
        root, objects = fixture()
        encoded = write_store(root.cid, reversed(objects))
        reader = StoreReader(encoded)
        self.assertEqual(reader.get(root.cid), root)
        verify_store(reader)
        self.assertEqual(reader.canonical_bytes(), encoded)

    def test_bad_magic_rejected(self):
        root, objects = fixture()
        encoded = bytearray(write_store(root.cid, objects))
        encoded[0] = 0
        with self.assertRaisesRegex(XaxError, "XAX.CONTAINER.MAGIC"):
            StoreReader(bytes(encoded))

    def test_digest_mismatch_rejected(self):
        root, objects = fixture()
        encoded = bytearray(write_store(root.cid, objects))
        encoded[-5] ^= 1
        with self.assertRaisesRegex(XaxError, "XAX.INTEGRITY.STORE_DIGEST"):
            StoreReader(bytes(encoded))

    def test_missing_reference_rejected(self):
        missing = bytes(range(32))
        root = SemanticObject.create(Kind.PROGRAM_ROOT, b"\x01\x00", [missing])
        reader = StoreReader(write_store(root.cid, [root]))
        with self.assertRaisesRegex(XaxError, "XAX.IDENTITY.OBJECT_MISSING"):
            verify_store(reader)

    def test_invalid_reference_index_rejected(self):
        root = SemanticObject.create(Kind.PROGRAM_ROOT, b"\x01\x00")
        reader = StoreReader(write_store(root.cid, [root]))
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.REF_INDEX"):
            verify_store(reader)

    def test_unreachable_object_rejected(self):
        root = SemanticObject.create(Kind.PROGRAM_ROOT, b"\x00")
        unused = bits_type(8)
        reader = StoreReader(write_store(root.cid, [root, unused]))
        with self.assertRaisesRegex(XaxError, "XAX.IDENTITY.UNREACHABLE_OBJECT"):
            verify_store(reader)

    def test_external_fixture_covers_all_core_kinds(self):
        root, objects = all_kinds_fixture()
        expected = bytes.fromhex(self.fixture_path.read_text(encoding="ascii"))
        manifest = json.loads(self.fixture_path.with_name("c0_all_kinds.json").read_text(encoding="utf-8"))
        self.assertEqual(write_store(root.cid, objects), expected)
        self.assertEqual(len(expected), manifest["byte_length"])
        self.assertEqual(root.cid.hex(), manifest["root_cid"])
        self.assertEqual(
            [(obj.kind.name.lower(), obj.cid.hex()) for obj in sorted(objects, key=lambda obj: obj.cid)],
            [(obj["kind"], obj["cid"]) for obj in manifest["objects"]],
        )
        reader = StoreReader(expected)
        verify_store(reader)
        self.assertEqual({obj.kind for obj in reader.objects()}, set(Kind) - {Kind.PACKAGE, Kind.BUILD, Kind.CALL_CONTRACT})
        self.assertEqual(reader.canonical_bytes(), expected)

    def test_duplicate_reference_table_rejected(self):
        duplicate = bytes(32)
        body = b"\x01\x20"
        payload = bytes(32) + b"\x04\x01\x02" + duplicate + duplicate + uleb(len(body)) + body
        with self.assertRaisesRegex(XaxError, "XAX.CANON.REFERENCE_TABLE"):
            decode_object(uleb(len(payload)) + payload)

    def test_out_of_order_reference_table_rejected(self):
        body = b"\x01\x20"
        payload = bytes(32) + b"\x04\x01\x02" + bytes([1]) * 32 + bytes(32) + uleb(len(body)) + body
        with self.assertRaisesRegex(XaxError, "XAX.CANON.REFERENCE_TABLE"):
            decode_object(uleb(len(payload)) + payload)

    def test_unknown_kind_and_schema_rejected(self):
        unknown_kind = bytes(32) + b"\x63\x01\x00\x00"
        with self.assertRaisesRegex(XaxError, "XAX.SCHEMA.KIND"):
            decode_object(uleb(len(unknown_kind)) + unknown_kind)
        body = b"\x01\x20"
        cid = semantic_cid(Kind.TYPE, 2, (), body)
        unknown_schema = cid + b"\x04\x02\x00" + uleb(len(body)) + body
        with self.assertRaisesRegex(XaxError, "XAX.SCHEMA.VERSION"):
            decode_object(uleb(len(unknown_schema)) + unknown_schema)

    def test_unsupported_header_fields_rejected(self):
        root, objects = fixture()
        encoded = bytearray(write_store(root.cid, objects))
        cursor = Cursor(encoded)
        cursor.take(4)
        major = cursor.pos; cursor.uleb()
        cursor.uleb()
        suite = cursor.pos; cursor.uleb()
        cursor.take(32); cursor.uleb(); cursor.uleb()
        flags = cursor.pos
        for offset, code in (
            (major, "XAX.CONTAINER.MAJOR"),
            (suite, "XAX.CONTAINER.HASH_SUITE"),
            (flags, "XAX.CONTAINER.FEATURE"),
        ):
            malformed = encoded.copy()
            malformed[offset] = 2 if offset != flags else 1
            with self.subTest(code=code), self.assertRaisesRegex(XaxError, code):
                StoreReader(bytes(malformed))

    def test_record_order_rejected(self):
        root, objects = fixture()
        encoded = write_store(root.cid, objects)
        cursor = Cursor(encoded)
        cursor.take(4)
        cursor.uleb(); cursor.uleb(); cursor.uleb(); cursor.take(32)
        count = cursor.uleb(); cursor.uleb(); cursor.uleb()
        prefix = encoded[:cursor.pos]
        records = []
        for _ in range(count):
            start = cursor.pos
            cursor.take(cursor.uleb())
            records.append(encoded[start:cursor.pos])
        malformed = prefix + b"".join(reversed(records)) + encoded[cursor.pos:]
        with self.assertRaisesRegex(XaxError, "XAX.CANON.RECORD_ORDER"):
            StoreReader(malformed)

    def test_duplicate_semantic_record_rejected(self):
        root, objects = fixture()
        encoded = write_store(root.cid, objects)
        cursor = Cursor(encoded)
        cursor.take(4)
        cursor.uleb(); cursor.uleb(); cursor.uleb(); cursor.take(32)
        count_offset = cursor.pos
        count = cursor.uleb(); cursor.uleb(); cursor.uleb()
        prefix = bytearray(encoded[:cursor.pos])
        prefix[count_offset] = count + 1
        records = []
        for _ in range(count):
            start = cursor.pos
            cursor.take(cursor.uleb())
            records.append(encoded[start:cursor.pos])
        malformed = bytes(prefix) + records[0] + b"".join(records) + encoded[cursor.pos:]
        with self.assertRaisesRegex(XaxError, "XAX.CANON.RECORD_ORDER"):
            StoreReader(malformed)

    def test_index_mismatch_rejected(self):
        root, objects = fixture()
        malformed = bytearray(write_store(root.cid, objects))
        cursor = Cursor(malformed)
        cursor.take(4)
        cursor.uleb(); cursor.uleb(); cursor.uleb(); cursor.take(32)
        count = cursor.uleb(); cursor.uleb(); cursor.uleb()
        for _ in range(count):
            cursor.take(cursor.uleb())
        cursor.uleb()
        malformed[cursor.pos + 32] ^= 1
        malformed[-36:-4] = blake3(malformed[:-36]).digest()
        with self.assertRaisesRegex(XaxError, "XAX.CANON.INDEX"):
            StoreReader(bytes(malformed))

    def test_truncated_store_rejected(self):
        root, objects = fixture()
        with self.assertRaises(XaxError):
            StoreReader(write_store(root.cid, objects)[:-1])

    def test_nonsemantic_metadata_preserves_semantic_identity(self):
        root, objects = fixture()
        plain = write_store(root.cid, objects)
        annotated = write_store(
            root.cid,
            objects,
            [NonsemanticRecord(2, b"layout"), NonsemanticRecord(1, b"debug-name")],
        )
        reader = StoreReader(annotated)
        verify_store(reader)
        self.assertNotEqual(plain, annotated)
        self.assertEqual(reader.root_cid, root.cid)
        self.assertEqual(
            reader.nonsemantic_records,
            tuple(sorted(reader.nonsemantic_records, key=lambda record: record.envelope())),
        )
        self.assertEqual(reader.canonical_bytes(), annotated)


class GraphTests(unittest.TestCase):
    def test_arithmetic_function_verifies(self):
        root, objects = graph_fixture()
        verify_store(StoreReader(write_store(root.cid, objects)))

    def test_operation_arity_rejected(self):
        b32 = bits_type(32)
        bad = Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0),), (b32,))
        graph = graph_fragment([Block((b32,), (bad,), Terminator.return_())])
        fn = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.OP_ARITY"):
            verify_store(StoreReader(write_store(root.cid, [b32, graph, fn, module, root])))

    def test_forward_ssa_use_rejected(self):
        b32 = bits_type(32)
        first = Node(
            Operation.ADD_WRAP,
            (ValueRef.node_result(0, 1), ValueRef.parameter(0, 0)),
            (b32,),
        )
        second = Node(
            Operation.ADD_WRAP,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 0)),
            (b32,),
        )
        graph = graph_fragment([Block((b32,), (first, second), Terminator.return_())])
        fn = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.SSA_DOMINANCE"):
            verify_store(StoreReader(write_store(root.cid, [b32, graph, fn, module, root])))

    def test_conditional_branch_arguments_verify(self):
        b1, b32 = bits_type(1), bits_type(32)
        graph = graph_fragment(
            [
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
                Block((b32,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
                Block((b32,), (), Terminator.return_((ValueRef.parameter(2, 0),))),
            ]
        )
        fn = function(graph, (b1, b32), (b32,))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        verify_store(StoreReader(write_store(root.cid, [b1, b32, graph, fn, module, root])))

    def test_branch_argument_mismatch_rejected(self):
        b32 = bits_type(32)
        graph = graph_fragment(
            [
                Block((), (), Terminator.branch(1)),
                Block((b32,), (), Terminator.return_()),
            ]
        )
        fn = function(graph, (), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.BRANCH_ARGUMENTS"):
            verify_store(StoreReader(write_store(root.cid, [b32, graph, fn, module, root])))

    def test_bad_branch_target_rejected(self):
        graph = graph_fragment([Block((), (), Terminator.branch(1))])
        fn = function(graph, (), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.BRANCH_TARGET"):
            verify_store(StoreReader(write_store(root.cid, [graph, fn, module, root])))

    def test_entry_contract_rejected(self):
        b32 = bits_type(32)
        graph = graph_fragment([Block((b32,), (), Terminator.return_())])
        fn = function(graph, (), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.ENTRY_CONTRACT"):
            verify_store(StoreReader(write_store(root.cid, [b32, graph, fn, module, root])))

    def test_return_contract_rejected(self):
        b32 = bits_type(32)
        graph = graph_fragment([Block((b32,), (), Terminator.return_((ValueRef.parameter(0, 0),)))])
        fn = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.RETURN_CONTRACT"):
            verify_store(StoreReader(write_store(root.cid, [b32, graph, fn, module, root])))

    def test_recursive_group_member_call_verifies(self):
        root, objects = all_kinds_fixture()
        verify_store(StoreReader(write_store(root.cid, objects)))

    def test_invalid_recursion_member_rejected_deterministically(self):
        b32 = bits_type(32)
        graph = graph_fragment(
            [
                Block(
                    (b32,),
                    (Node(Operation.CALL_GROUP_MEMBER, (ValueRef.parameter(0, 0),), (b32,), member=1),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                )
            ]
        )
        group = recursion_group([RecursionMember(graph, (b32,), (b32,))])
        module = object_with_refs(Kind.MODULE, [group])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        encoded = write_store(root.cid, [b32, graph, group, module, root])
        diagnostics = []
        for _ in range(2):
            with self.assertRaisesRegex(XaxError, "XAX.STRUCT.RECURSION_MEMBER") as caught:
                verify_store(StoreReader(encoded))
            diagnostics.append(caught.exception.diagnostic)
        self.assertEqual(diagnostics[0], diagnostics[1])


class MemoryTests(unittest.TestCase):
    @staticmethod
    def reader(nodes, types, parameters=(), returns=(), terminator=None):
        graph = graph_fragment([Block(tuple(parameters), tuple(nodes), terminator or Terminator.return_())])
        fn = function(graph, parameters, returns)
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        objects = [*types, graph, fn, module, root]
        return StoreReader(write_store(root.cid, objects)), fn

    def test_stack_store_load_executes_and_roundtrips(self):
        reader, fn, _, _ = stack_memory_fixture()
        verify_store(reader)
        encoded = reader.canonical_bytes()
        self.assertEqual(len(encoded), 1030)
        self.assertEqual(reader.root_cid.hex(), "41d276b7d29615423856fe617314ff2952075eceb4c0103e73fa89d63ad53c66")
        self.assertEqual(fn.cid.hex(), "a73f64f3d1540cf8527a2a7f21fa87455b0a82f3937b4d96b0a1f4976b99313b")
        self.assertEqual(StoreReader(encoded).canonical_bytes(), encoded)
        self.assertEqual(execute(reader, fn.cid, (0xAABBCCDD,)), (0xAABBCCDD,))

    def test_owner_and_effect_pass_through_direct_call_executes(self):
        reader, caller = resource_call_fixture()
        verify_store(reader)
        self.assertEqual(execute(reader, caller.cid, ()), ())

    def test_resource_pass_through_preserves_existing_pure_body(self):
        b8 = bits_type(8)
        zero = constant(b8, 0)
        owner = stack_owner_type()
        effect = memory_effect_type()
        pure = Node(Operation.CONSTANT, (), (b8,), entity=zero)
        graph = graph_fragment([Block(
            (owner, effect),
            (pure,),
            Terminator.return_((ValueRef.parameter(0, 0), ValueRef.parameter(0, 1))),
        )])
        fn = function(graph, (owner, effect), (owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b8, zero, owner, effect, graph, fn, module, root]))
        verify_store(reader)

    def test_resource_store_contract_rejects_extra_pure_node(self):
        b32 = bits_type(32)
        zero = constant(b32, 0)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        pure = Node(Operation.CONSTANT, (), (b32,), entity=zero)
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
            (effect,),
            attributes=(4, 4),
        )
        graph = graph_fragment([Block(
            (pointer, b32, owner, effect),
            (pure, store),
            Terminator.return_((ValueRef.parameter(0, 2), ValueRef.node_result(0, 1, 0))),
        )])
        fn = function(graph, (pointer, b32, owner, effect), (owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, zero, pointer, owner, effect, graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.ENTRY_CONTRACT"):
            verify_store(reader)

    def test_resource_store_load_interface_rejects_store_only_body(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
            (effect,),
            attributes=(4, 4),
        )
        graph = graph_fragment([Block(
            (pointer, b32, owner, effect),
            (store,),
            Terminator.return_((ValueRef.parameter(0, 1), ValueRef.parameter(0, 2), ValueRef.node_result(0, 0, 0))),
        )])
        fn = function(graph, (pointer, b32, owner, effect), (b32, owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.RESOURCE_DROP"):
            verify_store(reader)

    def test_pointer_data_store_direct_call_executes(self):
        reader, caller, _, _ = resource_store_call_fixture()
        verify_store(reader)
        encoded = reader.canonical_bytes()
        self.assertEqual(StoreReader(encoded).canonical_bytes(), encoded)
        self.assertEqual(execute(reader, caller.cid, (0xAABBCCDD,)), (0xAABBCCDD,))

    def test_pointer_data_store_call_requires_sufficient_extent(self):
        reader, _, _, _ = resource_store_call_fixture(extent=2)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.BOUNDS"):
            verify_store(reader)

    def test_pointer_data_store_call_requires_write_permission(self):
        reader, _, _, _ = resource_store_call_fixture(permission=Permission.READ)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PERMISSION"):
            verify_store(reader)

    def test_pointer_data_store_call_requires_declared_alignment(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=1)
        owner = stack_owner_type()
        effect = memory_effect_type()
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
            (effect,),
            attributes=(4, 4),
        )
        graph = graph_fragment([Block(
            (pointer, b32, owner, effect),
            (store,),
            Terminator.return_((ValueRef.parameter(0, 2), ValueRef.node_result(0, 0))),
        )])
        fn = function(graph, (pointer, b32, owner, effect), (owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.ALIGNMENT"):
            verify_store(reader)

    def test_pointer_data_store_call_requires_matching_provenance(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
            (effect,),
            attributes=(4, 4),
        )
        callee_graph = graph_fragment([Block(
            (pointer, b32, owner, effect),
            (store,),
            Terminator.return_((ValueRef.parameter(0, 2), ValueRef.node_result(0, 0))),
        )])
        callee = function(callee_graph, (pointer, b32, owner, effect), (owner, effect))
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(
                Operation.CALL_DIRECT,
                (
                    ValueRef.node_result(0, 0, 0),
                    ValueRef.parameter(0, 0),
                    ValueRef.node_result(0, 1, 1),
                    ValueRef.node_result(0, 1, 2),
                ),
                (owner, effect),
                entity=callee,
            ),
        )
        graph = graph_fragment([Block((b32,), nodes, Terminator.return_())])
        caller = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [callee, caller])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, callee_graph, callee, graph, caller, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PROVENANCE"):
            verify_store(reader)

    def test_pointer_data_load_direct_call_executes_and_continues(self):
        reader, caller, _, _ = resource_load_call_fixture()
        verify_store(reader)
        encoded = reader.canonical_bytes()
        self.assertEqual(StoreReader(encoded).canonical_bytes(), encoded)
        self.assertEqual(execute(reader, caller.cid, (0xAABBCCDD,)), (0xAABBCCDD, 0xAABBCCDD))

    def test_pointer_data_load_call_rejects_uninitialized_range(self):
        reader, _, _, _ = resource_load_call_fixture(initialize=False)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.UNINITIALIZED"):
            verify_store(reader)

    def test_pointer_data_load_call_requires_requested_range_initialized(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        callee_graph = graph_fragment([Block(
            (pointer, owner, effect),
            (load,),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1))),
        )])
        callee = function(callee_graph, (pointer, owner, effect), (b32, owner, effect))
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(8, 4)),
            Node(
                Operation.STORE_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
                (effect,),
                attributes=(4, 4),
            ),
            Node(Operation.ADDRESS_OFFSET, (ValueRef.node_result(0, 0, 0),), (pointer,), attributes=(4,)),
            Node(
                Operation.CALL_DIRECT,
                (ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 0)),
                (b32, owner, effect),
                entity=callee,
            ),
        )
        graph = graph_fragment([Block((b32,), nodes, Terminator.return_())])
        caller = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [callee, caller])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, callee_graph, callee, graph, caller, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.UNINITIALIZED"):
            verify_store(reader)

    def test_pointer_data_load_call_requires_sufficient_extent(self):
        reader, _, _, _ = resource_load_call_fixture(extent=2)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.BOUNDS"):
            verify_store(reader)

    def test_pointer_data_load_call_requires_read_permission(self):
        reader, _, _, _ = resource_load_call_fixture(permission=Permission.WRITE)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PERMISSION"):
            verify_store(reader)

    def test_pointer_data_load_call_requires_declared_alignment(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=1)
        owner = stack_owner_type()
        effect = memory_effect_type()
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        graph = graph_fragment([Block(
            (pointer, owner, effect),
            (load,),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1))),
        )])
        fn = function(graph, (pointer, owner, effect), (b32, owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.ALIGNMENT"):
            verify_store(reader)

    def test_pointer_data_load_call_requires_matching_provenance(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        callee_graph = graph_fragment([Block(
            (pointer, owner, effect),
            (load,),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1))),
        )])
        callee = function(callee_graph, (pointer, owner, effect), (b32, owner, effect))
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(
                Operation.STORE_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
                (effect,),
                attributes=(4, 4),
            ),
            Node(
                Operation.CALL_DIRECT,
                (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 1), ValueRef.node_result(0, 1, 2)),
                (b32, owner, effect),
                entity=callee,
            ),
        )
        graph = graph_fragment([Block((b32,), nodes, Terminator.return_())])
        caller = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [callee, caller])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, callee_graph, callee, graph, caller, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PROVENANCE"):
            verify_store(reader)

    def test_pointer_data_load_call_owner_is_linear(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        callee_graph = graph_fragment([Block(
            (pointer, owner, effect),
            (load,),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1))),
        )])
        callee = function(callee_graph, (pointer, owner, effect), (b32, owner, effect))
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(
                Operation.STORE_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
                (effect,),
                attributes=(4, 4),
            ),
            Node(
                Operation.CALL_DIRECT,
                (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 0)),
                (b32, owner, effect),
                entity=callee,
            ),
            Node(
                Operation.CALL_DIRECT,
                (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 0)),
                (b32, owner, effect),
                entity=callee,
            ),
        )
        graph = graph_fragment([Block((b32,), nodes, Terminator.return_())])
        caller = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [callee, caller])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, callee_graph, callee, graph, caller, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.USE_AFTER_LIFETIME"):
            verify_store(reader)

    def test_pointer_data_load_call_successor_effect_is_linear(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        callee_graph = graph_fragment([Block(
            (pointer, owner, effect),
            (load,),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1))),
        )])
        callee = function(callee_graph, (pointer, owner, effect), (b32, owner, effect))
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(
                Operation.STORE_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
                (effect,),
                attributes=(4, 4),
            ),
            Node(
                Operation.CALL_DIRECT,
                (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 0)),
                (b32, owner, effect),
                entity=callee,
            ),
            Node(
                Operation.LOAD_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 2, 2)),
                (b32, effect),
                attributes=(4, 4),
            ),
            Node(
                Operation.LOAD_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 2, 2)),
                (b32, effect),
                attributes=(4, 4),
            ),
        )
        graph = graph_fragment([Block((b32,), nodes, Terminator.return_())])
        caller = function(graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [callee, caller])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, callee_graph, callee, graph, caller, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.EFFECT_FORK"):
            verify_store(reader)

    def test_pointer_data_store_load_direct_call_executes_and_continues(self):
        reader, caller, _, _ = resource_store_load_call_fixture()
        verify_store(reader)
        encoded = reader.canonical_bytes()
        self.assertEqual(StoreReader(encoded).canonical_bytes(), encoded)
        self.assertEqual(execute(reader, caller.cid, (0xAABBCCDD,)), (0xAABBCCDD, 0xAABBCCDD))

    def test_bounded_store_sequence_direct_call_executes_and_continues(self):
        reader, caller, _ = resource_access_sequence_call_fixture("SSS")
        verify_store(reader)
        self.assertEqual(execute(reader, caller.cid, (0x11223344,)), (0x11223344,))

    def test_bounded_load_sequence_direct_call_executes_and_continues(self):
        reader, caller, _ = resource_access_sequence_call_fixture("LLL")
        verify_store(reader)
        self.assertEqual(execute(reader, caller.cid, (0x55667788,)), (0x55667788, 0x55667788))

    def test_bounded_mixed_access_sequence_direct_call_executes_and_continues(self):
        reader, caller, _ = resource_access_sequence_call_fixture("SLSL")
        verify_store(reader)
        encoded = reader.canonical_bytes()
        self.assertEqual(StoreReader(encoded).canonical_bytes(), encoded)
        self.assertEqual(execute(reader, caller.cid, (0xA1B2C3D4,)), (0xA1B2C3D4, 0xA1B2C3D4))

    def test_load_first_mixed_access_summary_requires_and_accepts_initialized_range(self):
        reader, caller, _ = resource_access_sequence_call_fixture("LSL")
        verify_store(reader)
        encoded = reader.canonical_bytes()
        self.assertEqual(StoreReader(encoded).canonical_bytes(), encoded)
        self.assertEqual(execute(reader, caller.cid, (0x0BADF00D,)), (0x0BADF00D, 0x0BADF00D))

    def test_load_first_mixed_access_summary_rejects_uninitialized_caller(self):
        reader, _, _ = resource_access_sequence_call_fixture("LSL", initialize_before_call=False)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.UNINITIALIZED"):
            verify_store(reader)

    def test_load_first_mixed_access_summary_requires_read_write_permission(self):
        for permission in (Permission.READ, Permission.WRITE):
            with self.subTest(permission=permission):
                reader, _, _ = resource_access_sequence_call_fixture("LSL", permission=permission)
                with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PERMISSION"):
                    verify_store(reader)

    def test_bounded_access_sequence_limit_is_inclusive(self):
        reader, caller, _ = resource_access_sequence_call_fixture("S" * 8)
        verify_store(reader)
        self.assertEqual(execute(reader, caller.cid, (0x01020304,)), (0x01020304,))

    def test_bounded_access_sequence_limit_rejected(self):
        reader, _, _ = resource_access_sequence_call_fixture("S" * 9)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.ENTRY_CONTRACT"):
            verify_store(reader)

    def test_bounded_mixed_sequence_requires_final_load(self):
        reader, _, _ = resource_access_sequence_call_fixture("SLS")
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.ENTRY_CONTRACT"):
            verify_store(reader)

    def test_pointer_data_store_load_call_requires_read_write_permission(self):
        for permission in (Permission.READ, Permission.WRITE):
            with self.subTest(permission=permission):
                reader, _, _, _ = resource_store_load_call_fixture(permission=permission)
                with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PERMISSION"):
                    verify_store(reader)

    def test_pointer_data_store_load_callee_rejects_load_before_store(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 3)),
            (b32, effect),
            attributes=(4, 4),
        )
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1)),
            (effect,),
            attributes=(4, 4),
        )
        graph = graph_fragment([Block(
            (pointer, b32, owner, effect),
            (load, store),
            Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 2), ValueRef.node_result(0, 1, 0))),
        )])
        fn = function(graph, (pointer, b32, owner, effect), (b32, owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.UNINITIALIZED"):
            verify_store(reader)

    def test_pointer_data_store_load_callee_rejects_effect_fork(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
            (effect,),
            attributes=(4, 4),
        )
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 3)),
            (b32, effect),
            attributes=(4, 4),
        )
        graph = graph_fragment([Block(
            (pointer, b32, owner, effect),
            (store, load),
            Terminator.return_((ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 2), ValueRef.node_result(0, 1, 1))),
        )])
        fn = function(graph, (pointer, b32, owner, effect), (b32, owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.EFFECT_FORK"):
            verify_store(reader)

    def test_pointer_data_store_load_callee_must_return_loaded_value(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)),
            (effect,),
            attributes=(4, 4),
        )
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 0)),
            (b32, effect),
            attributes=(4, 4),
        )
        graph = graph_fragment([Block(
            (pointer, b32, owner, effect),
            (store, load),
            Terminator.return_((ValueRef.parameter(0, 1), ValueRef.parameter(0, 2), ValueRef.node_result(0, 1, 1))),
        )])
        fn = function(graph, (pointer, b32, owner, effect), (b32, owner, effect))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.ENTRY_CONTRACT"):
            verify_store(reader)

    def test_resource_entry_drop_rejected(self):
        owner, effect = stack_owner_type(), memory_effect_type()
        for terminator in (Terminator.return_(), Terminator.trap(b"drop")):
            with self.subTest(terminator=terminator.kind):
                graph = graph_fragment([Block((owner, effect), (), terminator)])
                fn = function(graph, (owner, effect), ())
                module = object_with_refs(Kind.MODULE, [fn])
                root = object_with_refs(Kind.PROGRAM_ROOT, [module])
                reader = StoreReader(write_store(root.cid, [owner, effect, graph, fn, module, root]))
                with self.assertRaisesRegex(XaxError, "XAX.MEMORY.RESOURCE_DROP"):
                    verify_store(reader)

    def test_resource_direct_call_duplicate_rejected(self):
        def duplicate(callee, pointer, owner, effect):
            operands = (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2))
            return (
                Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(1, 1)),
                Node(Operation.CALL_DIRECT, operands, (owner, effect), entity=callee),
                Node(Operation.CALL_DIRECT, operands, (owner, effect), entity=callee),
                Node(Operation.STACK_END, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)), ()),
            )

        reader, _ = resource_call_fixture(duplicate)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.USE_AFTER_LIFETIME"):
            verify_store(reader)

    def test_resource_direct_call_wrong_result_order_rejected(self):
        def wrong_order(callee, pointer, owner, effect):
            return (
                Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(1, 1)),
                Node(
                    Operation.CALL_DIRECT,
                    (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2)),
                    (effect, owner),
                    entity=callee,
                ),
            )

        reader, _ = resource_call_fixture(wrong_order)
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.CALL_CONTRACT"):
            verify_store(reader)

    def test_out_of_order_initialization_ranges_merge(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(8, 4)),
            Node(Operation.ADDRESS_OFFSET, (ValueRef.node_result(0, 0, 0),), (pointer,), attributes=(4,)),
            Node(
                Operation.STORE_BITS_LE,
                (ValueRef.node_result(0, 1), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 2)),
                (effect,),
                attributes=(4, 4),
            ),
            Node(
                Operation.STORE_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 2)),
                (effect,),
                attributes=(4, 4),
            ),
            Node(
                Operation.LOAD_BITS_LE,
                (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 3)),
                (b32, effect),
                attributes=(4, 4),
            ),
            Node(
                Operation.STACK_END,
                (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 4, 1)),
                (),
            ),
        )
        reader, fn = self.reader(
            nodes,
            (b32, pointer, owner, effect),
            (b32, b32),
            (b32,),
            Terminator.return_((ValueRef.node_result(0, 4),)),
        )
        verify_store(reader)
        self.assertEqual(execute(reader, fn.cid, (11, 22)), (11,))

    def test_uninitialized_load_rejected(self):
        _, _, types, nodes = stack_memory_fixture()
        b32, _, _, effect = types
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        end = Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 1, 1)),
            (),
        )
        reader, _ = self.reader(
            (nodes[0], load, end),
            types,
            returns=(b32,),
            terminator=Terminator.return_((ValueRef.node_result(0, 1),)),
        )
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.UNINITIALIZED"):
            verify_store(reader)

    def test_out_of_bounds_access_rejected(self):
        _, _, types, nodes = stack_memory_fixture()
        b32, _, _, effect = types
        unaligned_pointer = pointer_type(b32, alignment=1)
        offset = Node(
            Operation.ADDRESS_OFFSET,
            (ValueRef.node_result(0, 0, 0),),
            (unaligned_pointer,),
            attributes=(1,),
        )
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.node_result(0, 1), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
            (effect,),
            attributes=(4, 1),
        )
        reader, _ = self.reader((nodes[0], offset, store), (*types, unaligned_pointer), (b32,))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.BOUNDS"):
            verify_store(reader)

    def test_misaligned_access_rejected(self):
        _, _, types, nodes = stack_memory_fixture()
        b32, _, _, effect = types
        pointer2 = pointer_type(b32, alignment=2)
        offset = Node(
            Operation.ADDRESS_OFFSET,
            (ValueRef.node_result(0, 0, 0),),
            (pointer2,),
            attributes=(2,),
        )
        store = Node(
            Operation.STORE_BITS_LE,
            (ValueRef.node_result(0, 1), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)),
            (effect,),
            attributes=(4, 4),
        )
        reader, _ = self.reader((nodes[0], offset, store), (*types, pointer2), (b32,))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.ALIGNMENT"):
            verify_store(reader)

    def test_write_without_permission_rejected(self):
        reader, _, _, _ = stack_memory_fixture(Permission.READ)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PERMISSION"):
            verify_store(reader)

    def test_use_after_lifetime_rejected(self):
        _, _, types, nodes = stack_memory_fixture()
        b32, _, _, effect = types
        end = Node(
            Operation.STACK_END,
            (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2)),
            (),
        )
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        reader, _ = self.reader((nodes[0], end, load), types)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.USE_AFTER_LIFETIME"):
            verify_store(reader)

    def test_effect_fork_rejected(self):
        _, _, types, nodes = stack_memory_fixture()
        b32, _, _, effect = types
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 2)),
            (b32, effect),
            attributes=(4, 4),
        )
        reader, _ = self.reader((nodes[0], nodes[1], load), types, (b32,))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.EFFECT_FORK"):
            verify_store(reader)

    def test_missing_lifetime_end_rejected(self):
        _, _, types, nodes = stack_memory_fixture()
        reader, _ = self.reader((nodes[0],), types)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.LIFETIME_LEAK"):
            verify_store(reader)

    def test_effect_cannot_replace_owner(self):
        _, _, types, nodes = stack_memory_fixture()
        _, pointer, _, effect = types
        malformed_alloc = Node(Operation.STACK_ALLOC, (), (pointer, effect, effect), attributes=(4, 4))
        reader, _ = self.reader((malformed_alloc,), types)
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.OWNER_TYPE"):
            verify_store(reader)

    def test_unproved_pointer_parameter_rejected(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, alignment=4)
        effect = memory_effect_type()
        load = Node(
            Operation.LOAD_BITS_LE,
            (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)),
            (b32, effect),
            attributes=(4, 4),
        )
        reader, _ = self.reader((load,), (b32, pointer, effect), (pointer, effect))
        with self.assertRaisesRegex(XaxError, "XAX.MEMORY.PROVENANCE"):
            verify_store(reader)

    def test_unsupported_memory_operation_rejected(self):
        node = Node(255, (), ())
        reader, _ = self.reader((node,), ())
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.OPERATION"):
            verify_store(reader)


class ResourceEffectTests(unittest.TestCase):
    def reader(self, nodes, types, parameters=None, returns=None, terminator=None):
        b32, effect, opened, closed = types
        parameters = parameters or (b32, effect)
        returns = returns or (b32, effect)
        terminator = terminator or Terminator.return_((ValueRef.parameter(0, 0), ValueRef.node_result(0, len(nodes) - 1, 0)))
        graph = graph_fragment([Block(parameters, tuple(nodes), terminator)])
        entry = function(graph, parameters, returns)
        module = object_with_refs(Kind.MODULE, [entry])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        return StoreReader(write_store(root.cid, [*types, graph, entry, module, root])), entry

    def test_lifecycle_split_join_executes_and_summarizes(self):
        reader, entry, _ = resource_lifecycle_fixture()
        verify_store(reader)
        result = execute(reader, entry.cid, (42, None))
        self.assertEqual(result[0], 42)
        summary = derive_effect_summary(reader, entry.cid)
        self.assertEqual(summary.domains, ((EffectDomain.FILESYSTEM, 7),))
        self.assertTrue(summary.may_return)
        self.assertFalse(summary.may_trap)

    def test_resource_crosses_block_parameter(self):
        b32 = bits_type(32)
        effect = effect_type(EffectDomain.NETWORK, 3)
        handle = resource_type(3, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE)
        graph = graph_fragment(
            [
                Block(
                    (b32, effect),
                    (Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (handle, effect)),),
                    Terminator.branch(1, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1))),
                ),
                Block(
                    (b32, handle, effect),
                    (Node(Operation.RESOURCE_RELEASE, (ValueRef.parameter(1, 1), ValueRef.parameter(1, 2)), (effect,)),),
                    Terminator.return_((ValueRef.parameter(1, 0), ValueRef.node_result(1, 0, 0))),
                ),
            ]
        )
        entry = function(graph, (b32, effect), (b32, effect))
        module = object_with_refs(Kind.MODULE, [entry])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, effect, handle, graph, entry, module, root]))
        verify_store(reader)
        self.assertEqual(execute(reader, entry.cid, (9, None))[0], 9)

    def test_independent_effect_instances_are_not_serialized(self):
        b32 = bits_type(32)
        filesystem = effect_type(EffectDomain.FILESYSTEM, 1)
        network = effect_type(EffectDomain.NETWORK, 2)
        graph = graph_fragment(
            [
                Block(
                    (b32, filesystem, network),
                    (
                        Node(Operation.EFFECT_STEP, (ValueRef.parameter(0, 2),), (network,)),
                        Node(Operation.EFFECT_STEP, (ValueRef.parameter(0, 1),), (filesystem,)),
                    ),
                    Terminator.return_((ValueRef.parameter(0, 0), ValueRef.node_result(0, 1), ValueRef.node_result(0, 0))),
                )
            ]
        )
        entry = function(graph, (b32, filesystem, network), (b32, filesystem, network))
        module = object_with_refs(Kind.MODULE, [entry])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, filesystem, network, graph, entry, module, root]))
        verify_store(reader)
        self.assertEqual(execute(reader, entry.cid, (5, None, None))[0], 5)

    def test_direct_call_uses_explicit_resource_effect_contract(self):
        reader, caller = generic_resource_call_fixture()
        verify_store(reader)
        self.assertEqual(execute(reader, caller.cid, (17, None))[0], 17)

    def test_duplicate_and_drop_rejected(self):
        reader, _, types = resource_lifecycle_fixture()
        _, effect, opened, _ = types
        acquire = Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (opened, effect))
        first = Node(Operation.RESOURCE_TRANSFER, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (opened, effect))
        duplicate = Node(Operation.RESOURCE_TRANSFER, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1, 1)), (opened, effect))
        bad, _ = self.reader((acquire, first, duplicate), types)
        with self.assertRaisesRegex(XaxError, "XAX.RESOURCE.DUPLICATE"):
            verify_store(bad)

        dropped, _ = self.reader(
            (acquire,),
            types,
            returns=(types[0],),
            terminator=Terminator.return_((ValueRef.parameter(0, 0),)),
        )
        with self.assertRaisesRegex(XaxError, "XAX.RESOURCE.DROP"):
            verify_store(dropped)

    def test_invalid_transition_and_linear_discard_rejected(self):
        _, _, types = resource_lifecycle_fixture()
        _, effect, opened, closed = types
        no_transition = resource_type(2, 1, flags=ResourceFlags.ACQUIRABLE, instance=11)
        acquire = Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (no_transition, effect))
        transition = Node(Operation.RESOURCE_TRANSITION, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (closed, effect))
        bad, _ = self.reader((acquire, transition), (types[0], effect, no_transition, closed))
        with self.assertRaisesRegex(XaxError, "XAX.RESOURCE.INVALID_TRANSITION"):
            verify_store(bad)

        acquire = Node(Operation.RESOURCE_ACQUIRE, (ValueRef.parameter(0, 1),), (opened, effect))
        discard = Node(Operation.RESOURCE_DISCARD, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)), (effect,))
        bad, _ = self.reader((acquire, discard), types)
        with self.assertRaisesRegex(XaxError, "XAX.RESOURCE.DISCARD_LINEAR"):
            verify_store(bad)

    def test_proof_only_lifecycle_erases_from_all_backends(self):
        for target_factory, compile_ in (
            (x86_64_windows_target, compile_native),
            (aarch64_baremetal_target, compile_aarch64),
            (wasm32_target, compile_wasm),
        ):
            target_object = target_factory()
            reader, entry, _ = resource_lifecycle_fixture(target_object)
            image = compile_(reader, entry.cid, target_object.cid)
            ranges = tuple(item for item in image.semantic_ranges if item.node_index is not None)
            self.assertFalse(any(item.node_index in range(6) for item in ranges))

    def test_resource_effect_call_abi_erases_from_all_backends(self):
        for target_factory, compile_ in (
            (x86_64_windows_target, compile_native),
            (aarch64_baremetal_target, compile_aarch64),
            (wasm32_target, compile_wasm),
        ):
            target_object = target_factory()
            reader, entry = generic_resource_call_fixture(target_object)
            image = compile_(reader, entry.cid, target_object.cid)
            self.assertEqual(image.parameter_widths, (32,))
            self.assertEqual(image.return_widths, (32,))
            self.assertEqual(len(getattr(image, "function_offsets", getattr(image, "function_indices", ()))), 1)


class AtomicRealtimeTests(unittest.TestCase):
    def test_atomic_families_verify_and_execute(self):
        reader, entry = atomic_fixture()
        verify_store(reader)
        self.assertEqual(execute(reader, entry.cid, (5, 3, 11)), (11,))

    def test_compare_exchange_reports_old_value_and_success(self):
        b1, b32 = bits_type(1), bits_type(32)
        pointer, owner, effect = pointer_type(b32, Permission.READ_WRITE, 4), stack_owner_type(), memory_effect_type()
        target_object = x86_64_windows_target()
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(Operation.ATOMIC_STORE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(AtomicOrder.RELAXED, AtomicScope.SYSTEM, 4)),
            Node(Operation.ATOMIC_CMPXCHG, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0)), (b32, b1, effect), attributes=(AtomicOrder.ACQ_REL, AtomicOrder.ACQUIRE, AtomicScope.SYSTEM, 4, CompareExchangeStrength.WEAK)),
            Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 2, 2)), ()),
        )
        graph = graph_fragment([Block((b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, 2, 1),)))])
        entry = function(graph, (b32, b32), (b1,))
        module = object_with_refs(Kind.MODULE, [entry, target_object])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b1, b32, pointer, owner, effect, graph, entry, target_object, module, root]))
        self.assertEqual(execute(reader, entry.cid, (5, 11)), (1,))
        self.assertEqual(run_native_isolated(compile_native(reader, entry.cid, target_object.cid), (5, 11)), (1,))

    def test_atomic_rmw_preserves_wrapping_arithmetic(self):
        b32 = bits_type(32)
        pointer, owner, effect = pointer_type(b32, Permission.READ_WRITE, 4), stack_owner_type(), memory_effect_type()
        target_object = x86_64_windows_target()
        nodes = (
            Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
            Node(Operation.ATOMIC_STORE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(AtomicOrder.RELAXED, AtomicScope.SYSTEM, 4)),
            Node(Operation.ATOMIC_RMW, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0)), (b32, effect), attributes=(AtomicRmwKind.ADD_WRAP, AtomicOrder.RELAXED, AtomicScope.SYSTEM, 4)),
            Node(Operation.ATOMIC_LOAD, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 2, 1)), (b32, effect), attributes=(AtomicOrder.RELAXED, AtomicScope.SYSTEM, 4)),
            Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 3, 1)), ()),
        )
        graph = graph_fragment([Block((b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, 3, 0),)))])
        entry = function(graph, (b32, b32), (b32,))
        module = object_with_refs(Kind.MODULE, [entry, target_object])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, entry, target_object, module, root]))
        self.assertEqual(execute(reader, entry.cid, (0xFFFFFFFF, 2)), (1,))
        self.assertEqual(run_native_isolated(compile_native(reader, entry.cid, target_object.cid), (0xFFFFFFFF, 2)), (1,))

    def test_atomic_order_legality_rejects_invalid_combinations(self):
        b32 = bits_type(32)
        pointer = pointer_type(b32, Permission.READ_WRITE, 4)
        owner = stack_owner_type()
        effect = memory_effect_type()

        def reject(operation, operands, results, attributes, code="XAX.ATOMIC.ORDER"):
            nodes = (
                Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
                Node(operation, operands, results, attributes=attributes),
            )
            graph = graph_fragment([Block((b32,), nodes, Terminator.trap())])
            entry = function(graph, (b32,), ())
            module = object_with_refs(Kind.MODULE, [entry])
            root = object_with_refs(Kind.PROGRAM_ROOT, [module])
            reader = StoreReader(write_store(root.cid, [b32, pointer, owner, effect, graph, entry, module, root]))
            with self.assertRaisesRegex(XaxError, code):
                verify_store(reader)

        ptr = ValueRef.node_result(0, 0, 0)
        frontier = ValueRef.node_result(0, 0, 2)
        reject(Operation.ATOMIC_LOAD, (ptr, frontier), (b32, effect), (AtomicOrder.RELEASE, AtomicScope.SYSTEM, 4))
        reject(Operation.ATOMIC_STORE, (ptr, ValueRef.parameter(0, 0), frontier), (effect,), (AtomicOrder.ACQUIRE, AtomicScope.SYSTEM, 4))
        reject(Operation.ATOMIC_FENCE, (frontier,), (effect,), (AtomicOrder.RELAXED, AtomicScope.SYSTEM))

        for order in (AtomicOrder.RELAXED, AtomicOrder.ACQUIRE, AtomicOrder.SEQ_CST):
            atomic_capability(decode_native_target(x86_64_windows_target()), 1, 32, 4, AtomicFamily.LOAD, order, AtomicScope.SYSTEM)
        for order in (AtomicOrder.RELAXED, AtomicOrder.RELEASE, AtomicOrder.SEQ_CST):
            atomic_capability(decode_native_target(x86_64_windows_target()), 1, 32, 4, AtomicFamily.STORE, order, AtomicScope.SYSTEM)
        for order in AtomicOrder:
            atomic_capability(decode_native_target(x86_64_windows_target()), 1, 32, 4, AtomicFamily.RMW, order, AtomicScope.SYSTEM)
        for order in (AtomicOrder.ACQUIRE, AtomicOrder.RELEASE, AtomicOrder.ACQ_REL, AtomicOrder.SEQ_CST):
            atomic_capability(decode_native_target(x86_64_windows_target()), 0, 0, 1, AtomicFamily.FENCE, order, AtomicScope.SYSTEM)
        with self.assertRaises(XaxError) as caught:
            atomic_capability(decode_native_target(x86_64_windows_target()), 1, 32, 4, AtomicFamily.CMPXCHG, AtomicOrder.RELEASE, AtomicScope.SYSTEM, AtomicOrder.ACQUIRE)
        self.assertEqual(caught.exception.diagnostic.rule, "ATOMIC-CMPXCHG-FAILURE-NOT-STRONGER")

    def test_target_atomic_capability_is_explicit(self):
        x86 = decode_native_target(x86_64_windows_target())
        supported = atomic_capability(x86, 1, 32, 4, AtomicFamily.RMW, AtomicOrder.ACQ_REL, AtomicScope.SYSTEM)
        self.assertEqual(supported.support, AtomicSupport.NATIVE)
        self.assertEqual(atomic_capability(x86, 1, 32, 2, AtomicFamily.RMW, AtomicOrder.ACQ_REL, AtomicScope.SYSTEM).support, AtomicSupport.UNSUPPORTED)
        self.assertEqual(atomic_capability(x86, 1, 16, 4, AtomicFamily.RMW, AtomicOrder.ACQ_REL, AtomicScope.SYSTEM).support, AtomicSupport.UNSUPPORTED)
        self.assertEqual(atomic_capability(x86, 1, 32, 4, AtomicFamily.RMW, AtomicOrder.ACQ_REL, AtomicScope.DEVICE).support, AtomicSupport.UNSUPPORTED)
        wasm = decode_native_target(wasm32_target())
        unsupported = atomic_capability(wasm, 1, 32, 4, AtomicFamily.RMW, AtomicOrder.ACQ_REL, AtomicScope.SYSTEM)
        self.assertEqual(unsupported.support, AtomicSupport.UNSUPPORTED)

    def test_x86_atomic_lowering_executes_without_runtime_assist(self):
        target_object = x86_64_windows_target()
        reader, entry = atomic_fixture(target_object)
        image = compile_native(reader, entry.cid, target_object.cid, RealtimeProfile())
        self.assertEqual(run_native_isolated(image, (5, 3, 11)), (11,))
        self.assertEqual(len(image.function_offsets), 1)

    def test_unsupported_target_rejects_atomic_lowering(self):
        target_object = wasm32_target()
        reader, entry = atomic_fixture(target_object)
        with self.assertRaisesRegex(XaxError, "XAX.WASM.UNSUPPORTED_OPERATION"):
            compile_wasm(reader, entry.cid, target_object.cid)

    def test_race_validation_and_litmus_subset(self):
        with self.assertRaisesRegex(XaxError, "XAX.CONCURRENCY.DATA_RACE"):
            validate_memory_events(
                (
                    MemoryEvent(0, "x", 0, 4, True, False),
                    MemoryEvent(1, "x", 0, 4, False, False),
                )
            )
        ordered = validate_memory_events(
            (
                MemoryEvent(0, "x", 0, 4, True, False),
                MemoryEvent(1, "x", 0, 4, False, False, (0,)),
            )
        )
        self.assertIn((0, 1), ordered)
        validate_memory_events((MemoryEvent(0, "x", 0, 4, True, True), MemoryEvent(1, "x", 0, 4, False, True)))

        litmus = validate_atomic_litmus(
            (
                AtomicLitmusEvent(0, "flag", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(1, "flag", AtomicFamily.LOAD, AtomicOrder.ACQUIRE, reads_from=0),
                AtomicLitmusEvent(0, "seq", AtomicFamily.STORE, AtomicOrder.SEQ_CST),
                AtomicLitmusEvent(1, "seq", AtomicFamily.LOAD, AtomicOrder.SEQ_CST, reads_from=2),
            )
        )
        self.assertIn((0, 1), litmus.happens_before)
        self.assertEqual(litmus.modification_order, (("flag", (0,)), ("seq", (2,))))
        self.assertEqual(litmus.seq_cst_order, (2, 3))

        release_sequence = validate_atomic_litmus(
            (
                AtomicLitmusEvent(0, "x", AtomicFamily.STORE, AtomicOrder.RELEASE),
                AtomicLitmusEvent(1, "x", AtomicFamily.RMW, AtomicOrder.RELAXED, reads_from=0),
                AtomicLitmusEvent(2, "x", AtomicFamily.LOAD, AtomicOrder.ACQUIRE, reads_from=1),
            )
        )
        self.assertIn((0, 2), release_sequence.happens_before)

        weak_failure = AtomicLitmusEvent(
            0,
            "x",
            AtomicFamily.CMPXCHG,
            AtomicOrder.ACQ_REL,
            reads_from=0,
            failure_order=AtomicOrder.ACQUIRE,
            strength=CompareExchangeStrength.WEAK,
            succeeded=False,
            spurious_failure=True,
        )
        validate_atomic_litmus((AtomicLitmusEvent(1, "x", AtomicFamily.STORE, AtomicOrder.RELEASE), weak_failure))
        with self.assertRaises(XaxError) as caught:
            validate_atomic_litmus(
                (
                    AtomicLitmusEvent(1, "x", AtomicFamily.STORE, AtomicOrder.RELEASE),
                    AtomicLitmusEvent(
                        0,
                        "x",
                        AtomicFamily.CMPXCHG,
                        AtomicOrder.ACQ_REL,
                        reads_from=0,
                        failure_order=AtomicOrder.ACQUIRE,
                        strength=CompareExchangeStrength.STRONG,
                        succeeded=False,
                        spurious_failure=True,
                    ),
                )
            )
        self.assertEqual(caught.exception.diagnostic.rule, "ATOMIC-LITMUS-SPURIOUS-FAILURE")

    def test_strict_realtime_profile_rejects_unknowns(self):
        target_object = x86_64_windows_target()
        reader, entry = atomic_fixture(target_object)
        properties = analyze_realtime(reader, entry.cid, target_object)
        validate_realtime_profile(properties)
        self.assertEqual((properties.stack_upper_bound, properties.retry_bound, properties.progress), (4, 0, "lock_free"))

        unknown = analyze_realtime(reader, entry.cid)
        with self.assertRaisesRegex(XaxError, "XAX.REALTIME.PROFILE"):
            validate_realtime_profile(unknown)

        with self.assertRaises(XaxError) as caught:
            validate_realtime_profile(properties, RealtimeProfile(require_bounded_interrupt_mask=True))
        self.assertEqual(caught.exception.diagnostic.rule, "REALTIME-INTERRUPT-MASK-BOUNDED")
        self.assertIsNone(properties.target_timing_bound)
        self.assertIsNone(properties.target_cost_estimate)

        loop = graph_fragment([Block((), (), Terminator.branch(0))])
        function_object = function(loop, (), ())
        module = object_with_refs(Kind.MODULE, [function_object])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        loop_reader = StoreReader(write_store(root.cid, [loop, function_object, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.REALTIME.PROFILE"):
            validate_realtime_profile(analyze_realtime(loop_reader, function_object.cid, target_object))

    def test_handler_contract_is_target_driven(self):
        target_object = x86_64_windows_target()
        effect = effect_type(EffectDomain.ATOMIC)
        graph = graph_fragment(
            [Block((effect,), (Node(Operation.EFFECT_STEP, (ValueRef.parameter(0, 0),), (effect,)),), Terminator.return_((ValueRef.node_result(0, 0),)))]
        )
        entry = function(graph, (effect,), (effect,))
        module = object_with_refs(Kind.MODULE, [entry, target_object])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [effect, graph, entry, target_object, module, root]))
        contract = validate_handler_entry(reader, entry.cid, target_object, 1)
        self.assertEqual(contract.allowed_effect_domains, (EffectDomain.MEMORY, EffectDomain.ATOMIC))
        self.assertEqual(contract.stack_bound, 4096)
        self.assertEqual((contract.nesting_policy, contract.reentrancy_policy), (1, 1))

        network = effect_type(EffectDomain.NETWORK)
        bad_graph = graph_fragment(
            [Block((network,), (Node(Operation.EFFECT_STEP, (ValueRef.parameter(0, 0),), (network,)),), Terminator.return_((ValueRef.node_result(0, 0),)))]
        )
        bad_entry = function(bad_graph, (network,), (network,))
        bad_module = object_with_refs(Kind.MODULE, [bad_entry, target_object])
        bad_root = object_with_refs(Kind.PROGRAM_ROOT, [bad_module])
        bad_reader = StoreReader(write_store(bad_root.cid, [network, bad_graph, bad_entry, target_object, bad_module, bad_root]))
        with self.assertRaisesRegex(XaxError, "XAX.HANDLER.EFFECT"):
            validate_handler_entry(bad_reader, bad_entry.cid, target_object, 1)


class CompileTimeTests(unittest.TestCase):
    capabilities = tuple(MetaCapability)

    def test_deterministic_evaluation_cache_and_materialization(self):
        reader, entry, b32, five, target_object = compile_time_fixture()
        evaluator = CompileTimeEvaluator()
        declared = (CompileTimeInput(b"build-number", b32, 7),)
        first = evaluator.evaluate(reader, entry.cid, (b32, five, target_object), capabilities=self.capabilities, inputs=declared)
        second = evaluator.evaluate(
            reader,
            entry.cid,
            (b32, five, target_object),
            capabilities=reversed(self.capabilities),
            inputs=declared,
            budget=CompileTimeBudget(0, 0, 0, 0, 0),
        )
        self.assertFalse(first.cache_hit)
        self.assertTrue(second.cache_hit)
        self.assertEqual(first.key, second.key)
        self.assertEqual(tuple(obj.cid for obj in first.created_objects), tuple(obj.cid for obj in second.created_objects))
        generated, width, supported = first.values
        self.assertEqual((width, supported), (32, 1))
        candidate = materialize_compile_time(reader, first)
        self.assertEqual(execute(candidate, generated.cid, ()), (44,))
        image = compile_native(candidate, generated.cid, target_object.cid)
        self.assertEqual(run_native_isolated(image, ()), (44,))

    def test_capabilities_and_declared_inputs_are_explicit(self):
        reader, entry, b32, five, target_object = compile_time_fixture()
        with self.assertRaisesRegex(XaxError, "XAX.META.CAPABILITY"):
            CompileTimeEvaluator().evaluate(reader, entry.cid, (b32, five, target_object), inputs=(CompileTimeInput(b"x", b32, 1),))
        with self.assertRaisesRegex(XaxError, "XAX.META.INPUT"):
            CompileTimeEvaluator().evaluate(
                reader,
                entry.cid,
                (b32, five, target_object),
                capabilities=self.capabilities,
                inputs=(CompileTimeInput(b"host-clock", b32, 1, reproducible=False),),
            )
        result = CompileTimeEvaluator().evaluate(
            reader,
            entry.cid,
            (b32, five, target_object),
            capabilities=self.capabilities,
            inputs=(CompileTimeInput(b"host-clock", b32, 1, reproducible=False),),
            reproducible=False,
        )
        self.assertEqual(result.values[1:], (32, 1))

    def test_memo_key_tracks_semantic_inputs_and_tool_identities(self):
        reader, entry, b32, five, target_object = compile_time_fixture()
        evaluator = CompileTimeEvaluator()

        def key(*, target_value=target_object, input_value=1, evaluator_identity=b"e1", verifier_identity=b"v1"):
            return evaluator.evaluate(
                reader,
                entry.cid,
                (b32, five, target_value),
                capabilities=self.capabilities,
                inputs=(CompileTimeInput(b"x", b32, input_value),),
                evaluator_identity=evaluator_identity,
                verifier_identity=verifier_identity,
            ).key

        base = key()
        self.assertNotEqual(base, key(input_value=2))
        self.assertNotEqual(base, key(target_value=wasm32_target()))
        self.assertNotEqual(base, key(evaluator_identity=b"e2"))
        self.assertNotEqual(base, key(verifier_identity=b"v2"))

    def test_budget_failures_do_not_publish_or_cache(self):
        reader, entry, b32, five, target_object = compile_time_fixture()
        arguments = (b32, five, target_object)
        inputs = (CompileTimeInput(b"x", b32, 1),)
        budgets = (
            CompileTimeBudget(0, 64, 1 << 20, 1_024, 10_000),
            CompileTimeBudget(100_000, 64, 0, 1_024, 10_000),
            CompileTimeBudget(100_000, 64, 1 << 20, 2, 10_000),
            CompileTimeBudget(100_000, 64, 1 << 20, 1_024, 0),
        )
        for budget in budgets:
            evaluator = CompileTimeEvaluator()
            with self.assertRaisesRegex(XaxError, "XAX.META.BUDGET"):
                evaluator.evaluate(reader, entry.cid, arguments, capabilities=self.capabilities, inputs=inputs, budget=budget)
            self.assertEqual(evaluator.cache_size, 0)
            self.assertEqual(reader.root_cid, StoreReader(reader.canonical_bytes()).root_cid)

        b32_local = bits_type(32)
        recursive_graph = graph_fragment(
            [Block((b32_local,), (Node(Operation.CALL_GROUP_MEMBER, (ValueRef.parameter(0, 0),), (b32_local,), member=0),), Terminator.return_((ValueRef.node_result(0, 0),)))]
        )
        group = recursion_group((RecursionMember(recursive_graph, (b32_local,), (b32_local,)),))
        module = object_with_refs(Kind.MODULE, (group,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        recursive_reader = StoreReader(write_store(root.cid, (b32_local, recursive_graph, group, module, root)))
        evaluator = CompileTimeEvaluator()
        with self.assertRaisesRegex(XaxError, "XAX.META.BUDGET") as caught:
            evaluator.evaluate(recursive_reader, group.cid, (1,), member_index=0, budget=CompileTimeBudget(call_depth=2))
        self.assertEqual(caught.exception.diagnostic.rule, "META-CALL-DEPTH")
        self.assertEqual(evaluator.cache_size, 0)

    def test_runtime_only_operations_are_rejected_at_compile_time(self):
        reader, entry, _, _ = stack_memory_fixture()
        with self.assertRaisesRegex(XaxError, "XAX.META.STAGE"):
            CompileTimeEvaluator().evaluate(reader, entry.cid, (1,))

    def test_materialization_verifier_barrier_preserves_original(self):
        reader, _, _, _, _ = compile_time_fixture()
        original_root = reader.root_cid
        invalid = SemanticObject.create(Kind.FUNCTION, b"")
        result = CompileTimeResult(b"bad", (invalid,), (invalid,), 0, 0)
        with self.assertRaises(XaxError):
            materialize_compile_time(reader, result)
        self.assertEqual(reader.root_cid, original_root)
        verify_store(reader)


class NativeTests(unittest.TestCase):
    def test_target_package_and_native_branch_call_execute(self):
        reader, entry, target_object = native_branch_fixture()
        description = decode_native_target(target_object)
        self.assertEqual(description.identity, b"x86_64-windows-load-image-v2")
        first = compile_native(reader, entry.cid, target_object.cid)
        second = compile_native(reader, entry.cid, target_object.cid)
        self.assertEqual(first.code, second.code)
        self.assertEqual(len(first.code), 76)
        self.assertEqual(hashlib.sha256(first.code).hexdigest(), "9d9b6fa21c3a8d617ee86726d41a68228407bf401028d8aeed7e3afb527a09c7")
        self.assertEqual(target_object.cid.hex(), "24e312c773b777ac4dd892b39a9477f1758ff8bf05d7708bfb8282120a9ded56")
        self.assertEqual(run_native_isolated(first, (1, 7, 9)), (16,))
        self.assertEqual(run_native_isolated(first, (0, 7, 9)), (0xFFFFFFFE,))

    def test_stack_memory_executes_natively(self):
        target_object = x86_64_windows_target()
        reader, function_object, _, _ = stack_memory_fixture(target_object=target_object)
        image = compile_native(reader, function_object.cid, target_object.cid)
        self.assertEqual(len(image.code), 43)
        self.assertEqual(hashlib.sha256(image.code).hexdigest(), "39505b6c6f8474757b9ffb0887a67f3d8bb25e570cb96004671012ec383012c3")
        self.assertEqual(run_native_isolated(image, (0xAABBCCDD,)), (0xAABBCCDD,))

    def test_unsupported_native_width_rejected(self):
        b8 = bits_type(8)
        graph = graph_fragment(
            [
                Block(
                    (b8, b8),
                    (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                )
            ]
        )
        fn = function(graph, (b8, b8), (b8,))
        target_object = x86_64_windows_target()
        module = object_with_refs(Kind.MODULE, [fn, target_object])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b8, graph, fn, target_object, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.NATIVE.BITS"):
            compile_native(reader, fn.cid, target_object.cid)


class Aarch64Tests(unittest.TestCase):
    def test_target_package_and_branch_call_execute(self):
        reader, entry, target_object = native_branch_fixture(aarch64_baremetal_target)
        description = decode_native_target(target_object)
        self.assertEqual(description.identity, b"aarch64-baremetal-load-image-v1")
        first = compile_aarch64(reader, entry.cid, target_object.cid)
        second = compile_aarch64(reader, entry.cid, target_object.cid)
        self.assertEqual(first.code, second.code)
        self.assertEqual((len(first.code), first.entry_offset), (84, 16))
        self.assertEqual(hashlib.sha256(first.code).hexdigest(), "d8ad44348b693d48822171fda02435edc4a1fde6f82e70bbcf6b0ef488e79866")
        self.assertEqual(target_object.cid.hex(), "0af5a0c8db7996951be281cf7ab22a7ee158287c43f195c9518f782f5832e355")
        self.assertEqual(run_aarch64_qemu(first, (1, 7, 9)), (16,))
        self.assertEqual(run_aarch64_qemu(first, (0, 7, 9)), (0xFFFFFFFE,))

    def test_stack_memory_executes(self):
        target_object = aarch64_baremetal_target()
        reader, function_object, _, _ = stack_memory_fixture(target_object=target_object)
        image = compile_aarch64(reader, function_object.cid, target_object.cid)
        self.assertEqual((len(image.code), image.entry_offset), (20, 0))
        self.assertEqual(hashlib.sha256(image.code).hexdigest(), "47c9196cb52575dd7fb97a8abb800d4e8fc03eff510361f9d7a092d7638c48d1")
        self.assertEqual(run_aarch64_qemu(image, (0xAABBCCDD,)), (0xAABBCCDD,))


class WasmTests(unittest.TestCase):
    def test_subword_arithmetic_has_no_x86_width_restriction(self):
        b8 = bits_type(8)
        graph = graph_fragment([Block((b8, b8), (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),), Terminator.return_((ValueRef.node_result(0, 0),)))])
        fn = function(graph, (b8, b8), (b8,))
        target_object = wasm32_target()
        module = object_with_refs(Kind.MODULE, [fn, target_object])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b8, graph, fn, target_object, module, root]))
        self.assertEqual(run_wasm_isolated(compile_wasm(reader, fn.cid, target_object.cid), (250, 10), NODE), (4,))

    def test_target_package_and_branch_call_execute(self):
        reader, entry, target_object = native_branch_fixture(wasm32_target)
        description = decode_native_target(target_object)
        self.assertEqual(description.identity, b"wasm32-core-module-v1")
        first = compile_wasm(reader, entry.cid, target_object.cid)
        second = compile_wasm(reader, entry.cid, target_object.cid)
        self.assertEqual(first.module, second.module)
        self.assertEqual(len(first.module), 185)
        self.assertEqual(hashlib.sha256(first.module).hexdigest(), "39fde1ae42dbebe790b3b1820eb19e31c7cf548b508687cc7d263147618332f8")
        self.assertEqual(target_object.cid.hex(), "946143a04b0b1ba8ed7312af6c85f70cbb4f71644fb20f7aea3be8ed06da41ed")
        self.assertEqual(run_wasm_isolated(first, (1, 7, 9), NODE), (16,))
        self.assertEqual(run_wasm_isolated(first, (0, 7, 9), NODE), (0xFFFFFFFE,))

    def test_stack_memory_executes(self):
        target_object = wasm32_target()
        reader, function_object, _, _ = stack_memory_fixture(target_object=target_object)
        image = compile_wasm(reader, function_object.cid, target_object.cid)
        self.assertEqual(len(image.module), 78)
        self.assertEqual(hashlib.sha256(image.module).hexdigest(), "0191ce4817c61cc96256f82c665dccca06f11d774925f57c25bdeb6a6137693e")
        self.assertEqual(run_wasm_isolated(image, (0xAABBCCDD,), NODE), (0xAABBCCDD,))


class ExecutionTests(unittest.TestCase):
    def test_recursion_group_member_executes(self):
        b1, b32 = bits_type(1), bits_type(32)
        one = constant(b1, 1)
        # m(done, x) = done ? x : other(1, x); both members have the same erased shape, so either order is canonical.
        members = []
        for callee in (1, 0):
            graph = graph_fragment(
                [
                    Block((b1, b32), (), Terminator.conditional_branch(ValueRef.parameter(0, 0), 1, (ValueRef.parameter(0, 1),), 2, (ValueRef.parameter(0, 1),))),
                    Block((b32,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
                    Block(
                        (b32,),
                        (
                            Node(Operation.CONSTANT, (), (b1,), entity=one),
                            Node(Operation.CALL_GROUP_MEMBER, (ValueRef.node_result(2, 0), ValueRef.parameter(2, 0)), (b32,), member=callee),
                        ),
                        Terminator.return_((ValueRef.node_result(2, 1),)),
                    ),
                ]
            )
            members.append(RecursionMember(graph, (b1, b32), (b32,)))
        group = recursion_group(members)
        module = object_with_refs(Kind.MODULE, [group])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        objects = {o.cid: o for o in [b1, b32, one, *(m.graph for m in members), group, module, root]}
        reader = StoreReader(write_store(root.cid, objects.values()))
        self.assertEqual(execute_group_member(reader, group.cid, 1, (0, 42)), (42,))

    def test_recursive_execution_shares_fuel(self):
        root, objects = all_kinds_fixture()
        group = next(obj for obj in objects if obj.kind == Kind.RECURSION_GROUP)
        reader = StoreReader(write_store(root.cid, objects))
        with self.assertRaisesRegex(XaxError, "XAX.EXEC.FUEL"):
            execute_group_member(reader, group.cid, 0, (1,), fuel=3)

    def test_wrapping_arithmetic_and_direct_call(self):
        root, objects, caller = direct_call_fixture()
        encoded = write_store(root.cid, objects)
        fixture_path = Path(__file__).parent / "fixtures" / "m2_direct_call.xax.hex"
        manifest = json.loads(fixture_path.with_name("m2_direct_call.json").read_text(encoding="utf-8"))
        self.assertEqual(encoded, bytes.fromhex(fixture_path.read_text(encoding="ascii")))
        self.assertEqual(root.cid.hex(), manifest["root_cid"])
        self.assertEqual(caller.cid.hex(), manifest["entry_function_cid"])
        reader = StoreReader(encoded)
        self.assertEqual(execute(reader, caller.cid, (250, 10)), (4,))

    def test_constant_executes(self):
        b32 = bits_type(32)
        forty_two = constant(b32, 42)
        graph = graph_fragment(
            [
                Block(
                    (),
                    (Node(Operation.CONSTANT, (), (b32,), entity=forty_two),),
                    Terminator.return_((ValueRef.node_result(0, 0),)),
                )
            ]
        )
        fn = function(graph, (), (b32,))
        module = object_with_refs(Kind.MODULE, [fn, forty_two])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, forty_two, graph, fn, module, root]))
        self.assertEqual(execute(reader, fn.cid, ()), (42,))

    def test_conditional_branch_executes(self):
        b1, b32 = bits_type(1), bits_type(32)
        graph = graph_fragment(
            [
                Block(
                    (b1, b32, b32),
                    (),
                    Terminator.conditional_branch(
                        ValueRef.parameter(0, 0),
                        1,
                        (ValueRef.parameter(0, 1),),
                        2,
                        (ValueRef.parameter(0, 2),),
                    ),
                ),
                Block((b32,), (), Terminator.return_((ValueRef.parameter(1, 0),))),
                Block((b32,), (), Terminator.return_((ValueRef.parameter(2, 0),))),
            ]
        )
        fn = function(graph, (b1, b32, b32), (b32,))
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b1, b32, graph, fn, module, root]))
        self.assertEqual(execute(reader, fn.cid, (1, 7, 9)), (7,))
        self.assertEqual(execute(reader, fn.cid, (0, 7, 9)), (9,))

    def test_trap_executes_explicitly(self):
        graph = graph_fragment([Block((), (), Terminator.trap(b"boom"))])
        fn = function(graph, (), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [graph, fn, module, root]))
        with self.assertRaises(XaxTrap) as caught:
            execute(reader, fn.cid, ())
        self.assertEqual(caught.exception.payload, b"boom")

    def test_bad_call_contract_rejected(self):
        b32 = bits_type(32)
        callee_graph = graph_fragment([Block((b32, b32), (), Terminator.return_())])
        callee = function(callee_graph, (b32, b32), ())
        caller_graph = graph_fragment(
            [
                Block(
                    (b32,),
                    (Node(Operation.CALL_DIRECT, (ValueRef.parameter(0, 0),), (), entity=callee),),
                    Terminator.return_(),
                )
            ]
        )
        caller = function(caller_graph, (b32,), ())
        module = object_with_refs(Kind.MODULE, [callee, caller])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        with self.assertRaisesRegex(XaxError, "XAX.STRUCT.CALL_CONTRACT"):
            verify_store(StoreReader(write_store(root.cid, [b32, callee_graph, callee, caller_graph, caller, module, root])))

    def test_loop_is_bounded_by_fuel(self):
        graph = graph_fragment([Block((), (), Terminator.branch(0))])
        fn = function(graph, (), ())
        module = object_with_refs(Kind.MODULE, [fn])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [graph, fn, module, root]))
        with self.assertRaisesRegex(XaxError, "XAX.EXEC.FUEL"):
            execute(reader, fn.cid, (), fuel=2)


if __name__ == "__main__":
    unittest.main()

