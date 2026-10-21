"""S15e.7a (ADR-321): accelerator deployment build requests for the differential tests of the XAX general program.

``accel_case(rng)`` gives a snapshot store built from ``test_xax_accelerator.accelerator_fixture`` (either M13 target
package), unchanged or with one change ``compile_accelerator`` rejects: a target with no operation contracts, an extra
host parameter, a second block, a trap, a non-target node, a repeated or missing synchronization step, or a request for
another artifact.
"""

from __future__ import annotations

import random

from xax_accelerator import coherent_grid_accelerator_target
from xax_build import ArtifactKind, build_profile, build_request, package, resolve_packages, snapshot_store, trust_policy
from xax_compiler import (AtomicScope, Block, EffectDomain, Kind, Node, Operation, ResourceFlags, SemanticObject, Terminator, ValueRef,
                          bits_type, effect_type, function, graph_fragment, object_with_refs, resource_type, simt32_accelerator_target)

CHANGES = ("none", "none", "coherent", "no_contracts", "extra_parameter", "two_blocks", "trap", "plain_node", "repeat_sync",
           "drop_sync", "artifact")


def _no_contracts(target: SemanticObject) -> SemanticObject:
    """The target with its operation contracts removed (the body's last field is their count, then the contracts)."""
    from xax_compiler import Cursor, uleb

    cursor = Cursor(target.body, "")
    identity = cursor.byte_string()
    fields = [cursor.uleb() for _ in range(6)]
    operations = [cursor.uleb() for _ in range(cursor.uleb())]
    terminators = [cursor.uleb() for _ in range(cursor.uleb())]
    lane, groups = cursor.uleb(), cursor.uleb()
    scopes = [cursor.uleb() for _ in range(cursor.uleb())]
    spaces = []
    for _ in range(cursor.uleb()):
        start = cursor.pos
        for _field in range(4):
            cursor.uleb()
        for _list in range(2):
            for _ in range(cursor.uleb()):
                cursor.uleb()
        cursor.take(2)
        spaces.append(bytes(target.body[start:cursor.pos]))
    body = bytearray(uleb(len(identity)) + identity + b"".join(uleb(value) for value in fields))
    for values in (operations, terminators):
        body += uleb(len(values)) + b"".join(uleb(value) for value in values)
    body += uleb(lane) + uleb(groups) + uleb(len(scopes)) + b"".join(uleb(value) for value in scopes)
    body += uleb(len(spaces)) + b"".join(spaces) + uleb(0)
    return SemanticObject.create(Kind.TARGET, bytes(body))


def _nodes(target, b32, effect, host, device):
    """``accelerator_fixture``'s six deployment steps on ``target``."""
    op = lambda inputs, results, attributes: Node(Operation.TARGET_OP, inputs, results, entity=target, attributes=attributes)  # noqa: E731
    p, n = ValueRef.parameter, ValueRef.node_result
    return [
        op((p(0, 2),), (host, effect), (1, AtomicScope.DEVICE, 1, 1)),
        op((p(0, 0), n(0, 0, 0), n(0, 0, 1)), (device, effect), (2, AtomicScope.DEVICE, 1, 2)),
        op((p(0, 1), n(0, 1, 0), n(0, 1, 1)), (device, effect), (3, AtomicScope.DEVICE, 2, 2)),
        op((n(0, 2, 0), n(0, 2, 1)), (device, effect), (4, AtomicScope.DEVICE, 2, 2)),
        op((n(0, 3, 0), n(0, 3, 1)), (b32, host, effect), (5, AtomicScope.DEVICE, 2, 1)),
        op((n(0, 4, 1), n(0, 4, 2)), (effect,), (6, AtomicScope.DEVICE, 1, 1)),
    ]


def _renumbered(nodes, mapping):
    """Each node with its node-result operands renumbered by ``mapping`` (old index -> new index)."""
    def fix(ref):
        return ValueRef.node_result(0, mapping(ref.index), ref.result) if ref.tag == 1 else ref

    return [Node(node.operation, tuple(fix(ref) for ref in node.operands), node.result_types, entity=node.entity, attributes=node.attributes)
            for node in nodes], fix


def accel_case(rng: random.Random):
    """A snapshot store (``StoreReader``) and the change made (a change the target or store cannot carry is drawn
    again)."""
    from xax_compiler import XaxError

    while True:
        try:
            return _case(rng, rng.choice(CHANGES))
        except XaxError:
            continue


def _case(rng: random.Random, change: str):
    b32, effect = bits_type(32), effect_type(EffectDomain.DEVICE, 1)
    host = resource_type(1001, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE, transitions=(2,))
    device = resource_type(1001, 2, flags=ResourceFlags.RELEASABLE, transitions=(1,))
    target = coherent_grid_accelerator_target() if change == "coherent" else simt32_accelerator_target()
    nodes = _nodes(target, b32, effect, host, device)
    parameters = [b32, b32, effect]
    values = (ValueRef.node_result(0, 4, 0), ValueRef.node_result(0, 5, 0))
    extra_blocks = []
    if change == "no_contracts":
        target = _no_contracts(target)
        nodes = []
        values = (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2))
    terminator = Terminator.return_(values)
    if change == "extra_parameter":
        parameters.append(b32)
    elif change == "two_blocks":
        terminator = Terminator.branch(1, values)
        extra_blocks.append(Block((b32, effect), (), Terminator.return_((ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)))))
    elif change == "trap":
        terminator = Terminator.trap()
    elif change == "plain_node":
        at = rng.randrange(len(nodes) + 1)
        plain = Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,))
        moved, fix = _renumbered(nodes, lambda index: index + 1 if index >= at else index)
        nodes = [*nodes[:at], plain, *moved[at:]]
        terminator = Terminator.return_(tuple(fix(ref) for ref in values))
    elif change == "repeat_sync":
        again = Node(Operation.TARGET_OP, (ValueRef.node_result(0, 3, 0), ValueRef.node_result(0, 3, 1)), (device, effect), entity=target,
                     attributes=(4, AtomicScope.DEVICE, 2, 2))
        moved, fix = _renumbered(nodes, lambda index: index + 1 if index >= 3 else index)
        nodes = [*nodes[:4], again, *moved[4:]]
        terminator = Terminator.return_(tuple(fix(ref) for ref in values))
    elif change == "drop_sync":
        moved, fix = _renumbered(nodes, lambda index: index - 1 if index >= 3 else index)
        nodes = [*nodes[:3], *moved[4:]]
        terminator = Terminator.return_(tuple(fix(ref) for ref in values))
    graph = graph_fragment([Block(tuple(parameters), tuple(nodes), terminator), *extra_blocks])
    entry = function(graph, tuple(parameters), (b32, effect))
    module = object_with_refs(Kind.MODULE, (b32, effect, host, device, entry, target))
    app = package(b"m13-accelerator-app", (module,), build_entries=((b"deployment", entry),))
    profile, policy = build_profile(), trust_policy()
    artifact = ArtifactKind.NATIVE_IMAGE if change == "artifact" else ArtifactKind.ACCELERATOR_DEPLOYMENT
    request = build_request(app, b"deployment", target, profile, requested_artifacts=(artifact,))
    candidates = (b32, effect, host, device, target, graph, entry, module, app, profile, policy, request)
    return snapshot_store(resolve_packages(request, candidates, policy, b"m13-resolver-v1"), candidates), change
