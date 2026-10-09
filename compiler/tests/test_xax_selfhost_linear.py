"""S6a (ADR-142): XAX proves resource and effect linearity exactly when the bootstrap accepts it.

Random resource lifecycles (acquire, transition, split, transfer, join,
release) over straight-line and branching control flow, and their
linearity mutations (a duplicated use, a dropped resource, a resource passed
on one conditional edge only, a cross-block use without a block parameter,
joins of non-siblings or of one piece twice, a join whose pieces pass a block
parameter), must give the same outcome and exact diagnostic whether the XAX
linear-flow proof is used or not; the proof must never hold for a graph the
bootstrap pass rejects, and it must hold for the valid straight-line ones.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

from xax_compiler import (
    EffectDomain, IntCompare, Operation, ResourceFlags, XaxError, bits_type, effect_type, resource_type,
)
from xax_graph_builder import GraphBuilder

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B32 = bits_type(1), bits_type(32)
FS = effect_type(EffectDomain.FILESYSTEM, 7)
OPENED = resource_type(2, 1, flags=ResourceFlags.ACQUIRABLE, instance=11, transitions=(2,))
CLOSED = resource_type(2, 2, flags=ResourceFlags.PARTITIONABLE | ResourceFlags.RELEASABLE, instance=11)
MUTATIONS = (None, None, None, "duplicate", "drop", "one_edge", "cross_block", "cross_terminator", "join_strangers", "join_same", "join_through_parameter")


def _program(rng: random.Random, mutation: str | None):
    graph = GraphBuilder()
    graph.track(B1, B32, FS, OPENED, CLOSED)
    entry = graph.block(B32, FS)
    x, effect = entry.params
    opened, effect = entry.op(Operation.RESOURCE_ACQUIRE, (effect,), (OPENED, FS))
    resource, effect = entry.op(Operation.RESOURCE_TRANSITION, (opened, effect), (CLOSED, FS))
    block = entry
    if mutation in ("join_strangers", "join_same", "join_through_parameter") or rng.random() < 0.5:
        left, right, effect = block.op(Operation.RESOURCE_SPLIT, (resource, effect), (CLOSED, CLOSED, FS))
        if rng.random() < 0.5:
            left, effect = block.op(Operation.RESOURCE_TRANSFER, (left, effect), (CLOSED, FS))
        if mutation == "join_strangers":
            # Two splits joined crosswise: every piece is used once, but no join gets two siblings.
            extra, effect = block.op(Operation.RESOURCE_ACQUIRE, (effect,), (OPENED, FS))
            extra, effect = block.op(Operation.RESOURCE_TRANSITION, (extra, effect), (CLOSED, FS))
            a, b, effect = block.op(Operation.RESOURCE_SPLIT, (extra, effect), (CLOSED, CLOSED, FS))
            crossed, effect = block.op(Operation.RESOURCE_JOIN, (right, b, effect), (CLOSED, FS))
            effect = block.op1(Operation.RESOURCE_RELEASE, (crossed, effect), FS)
            right = a
        if mutation == "join_same":
            right = left
        if mutation == "join_through_parameter":
            follow = graph.block(B32, CLOSED, CLOSED, FS)
            block.br(follow, x, left, right, effect)
            block = follow
            x, left, right, effect = follow.params
        pieces = (right, left) if rng.random() < 0.5 else (left, right)
        resource, effect = block.op(Operation.RESOURCE_JOIN, (*pieces, effect), (CLOSED, FS))
    if rng.random() < 0.5 or mutation in ("one_edge", "cross_block", "cross_terminator"):
        # Branch: each side receives the resource and frontier, releases, and returns (or traps).
        condition = block.op1(Operation.INT_COMPARE, (x, block.const(B32, rng.randrange(8))), B1, attributes=(IntCompare.ULT,))
        sides = [graph.block(B32, CLOSED, FS), graph.block(B32, FS) if mutation == "one_edge" else graph.block(B32, CLOSED, FS)]
        arguments = [(x, resource, effect), (x, effect) if mutation == "one_edge" else (x, resource, effect)]
        block.cbr(condition, sides[0], arguments[0], sides[1], arguments[1])
        for index, side in enumerate(sides):
            if mutation == "one_edge" and index == 1:
                value, frontier = side.params
                side.ret(value, frontier)
                continue
            value, carried, frontier = side.params
            if mutation == "cross_block" and index == 0:
                carried = resource  # the entry's value, not this block's parameter
            if mutation == "cross_terminator" and index == 0:
                # The entry's resource continues from this block's terminator instead of a parameter.
                frontier = side.op1(Operation.RESOURCE_RELEASE, (carried, frontier), FS)
                tail = graph.block(B32, CLOSED, FS)
                side.br(tail, value, resource, frontier)
                tail_value, tail_resource, tail_frontier = tail.params
                tail.ret(tail_value, tail.op1(Operation.RESOURCE_RELEASE, (tail_resource, tail_frontier), FS))
                continue
            frontier = side.op1(Operation.RESOURCE_RELEASE, (carried, frontier), FS)
            side.ret(value, frontier)
    else:
        effect = block.op1(Operation.RESOURCE_RELEASE, (resource, effect), FS)
        if mutation == "duplicate":
            effect = block.op1(Operation.RESOURCE_RELEASE, (resource, effect), FS)
        if mutation == "drop":
            fresh, effect = block.op(Operation.RESOURCE_ACQUIRE, (effect,), (OPENED, FS))
            del fresh
        block.ret(x, effect)
    return graph.function((B32, FS), (B32, FS)), tuple(graph.objects.values())


def _outcome(function, objects, use_proof: bool, native):
    import xax_compiler
    from xax_compiler import _decode_function_interface, _parse_graph

    saved = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED)
    xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = native, True
    xax_compiler._PARSED_GRAPHS.clear()
    proven = []
    original = type(native).linear_flow

    def recording(self):
        proven.append(original(self))
        return proven[-1] if use_proof else False

    original_rejection = type(native).linear_rejection

    def rejection(self):  # S8 (ADR-248): the bootstrap alone decides when the proof is off
        return original_rejection(self) if use_proof else None

    type(native).linear_flow = recording
    type(native).linear_rejection = rejection
    table = {item.cid: item for item in (*objects, function)}
    try:
        parsed = _parse_graph(_decode_function_interface(function, table.__getitem__)[0], table.__getitem__)
        return ("accept", parsed.returns), bool(proven and proven[-1])
    except XaxError as error:
        d = error.diagnostic
        return ("reject", d.code, d.rule, d.entity, repr(d.expected), repr(d.actual)), bool(proven and proven[-1])
    finally:
        type(native).linear_flow = original
        type(native).linear_rejection = original_rejection
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = saved
        xax_compiler._PARSED_GRAPHS.clear()


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostLinearFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_typing import NativeTyping

        cls.native = NativeTyping()

    def test_lifecycles_agree_with_the_bootstrap(self):
        rng = random.Random(142)
        outcomes, proven_valid, valid = {}, 0, 0
        for trial in range(400):
            mutation = MUTATIONS[trial % len(MUTATIONS)]
            function, objects = _program(rng, mutation)
            with_proof, proven = _outcome(function, objects, True, self.native)
            bootstrap, _ = _outcome(function, objects, False, self.native)
            with self.subTest(trial=trial, mutation=mutation):
                self.assertEqual(with_proof, bootstrap)
                if bootstrap[0] == "reject":
                    self.assertFalse(proven, "XAX proved linearity of a graph the bootstrap rejects")
            key = (mutation, bootstrap[0] if bootstrap[0] == "accept" else bootstrap[2])
            outcomes[key] = outcomes.get(key, 0) + 1
            if bootstrap[0] == "accept" and mutation != "join_through_parameter":
                valid += 1
                proven_valid += proven
        self.assertGreater(valid, 100)
        self.assertEqual(proven_valid, valid)
        rejected_rules = {rule for (_mutation, rule) in outcomes if rule != "accept"}
        self.assertTrue({"RESOURCE-LINEAR-CONTINUATION", "RESOURCE-JOIN-SIBLINGS", "RESOURCE-EXPLICIT-BLOCK-PARAMETER"} <= rejected_rules, outcomes)


if __name__ == "__main__":
    unittest.main()
