"""Deterministic M8 atomic artifact/execution record; deliberately non-timing."""

from __future__ import annotations

import hashlib
import json

from xax_compiler import (
    AtomicOrder,
    AtomicRmwKind,
    AtomicScope,
    Block,
    CompareExchangeStrength,
    Kind,
    Node,
    Operation,
    Permission,
    StoreReader,
    Terminator,
    ValueRef,
    bits_type,
    execute,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    pointer_type,
    stack_owner_type,
    write_store,
    x86_64_windows_target,
)
from xax_x86_64 import compile_native, run_native_isolated


def main() -> None:
    b1, b32 = bits_type(1), bits_type(32)
    pointer, owner, effect = pointer_type(b32, Permission.READ_WRITE, 4), stack_owner_type(), memory_effect_type()
    target = x86_64_windows_target()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4)),
        Node(Operation.ATOMIC_STORE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(AtomicOrder.RELEASE, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_RMW, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0)), (b32, effect), attributes=(AtomicRmwKind.ADD_WRAP, AtomicOrder.ACQ_REL, AtomicScope.SYSTEM, 4)),
        Node(Operation.ATOMIC_CMPXCHG, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 2, 0), ValueRef.parameter(0, 2), ValueRef.node_result(0, 2, 1)), (b32, b1, effect), attributes=(AtomicOrder.SEQ_CST, AtomicOrder.ACQUIRE, AtomicScope.SYSTEM, 4, CompareExchangeStrength.STRONG)),
        Node(Operation.ATOMIC_FENCE, (ValueRef.node_result(0, 3, 2),), (effect,), attributes=(AtomicOrder.SEQ_CST, AtomicScope.SYSTEM)),
        Node(Operation.ATOMIC_LOAD, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 4, 0)), (b32, effect), attributes=(AtomicOrder.SEQ_CST, AtomicScope.SYSTEM, 4)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 5, 1)), ()),
    )
    graph = graph_fragment([Block((b32, b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, 5, 0),)))])
    entry = function(graph, (b32, b32, b32), (b32,))
    module = object_with_refs(Kind.MODULE, (entry, target))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (b1, b32, pointer, owner, effect, graph, entry, target, module, root)))
    image = compile_native(reader, entry.cid, target.cid)
    arguments = (5, 3, 11)
    record = {
        "artifact_bytes": len(image.code),
        "artifact_sha256": hashlib.sha256(image.code).hexdigest(),
        "reference_result": execute(reader, entry.cid, arguments)[0],
        "native_result": run_native_isolated(image, arguments)[0],
        "runtime_assists": [],
        "target_cid": target.cid.hex(),
    }
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
