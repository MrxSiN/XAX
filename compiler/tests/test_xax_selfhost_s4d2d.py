"""S4d.2d (ADR-139): the XAX facts engine decides target operations, records, and links exactly.

Every record/link program of the link suites (valid, and each forged step)
and random byte, attribute, and type mutations of a target-operation graph
must verify or reject with the same exact diagnostic, and the same pointer
extents, whether the engine runs or not; the engine must accept the valid
programs itself.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest
from pathlib import Path

from xax_compiler import Kind, Operation, SemanticObject, XaxError

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling suites' program builders
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _parsed(function, objects):
    from xax_compiler import _decode_function_interface, _parse_graph

    table = {item.cid: item for item in objects}
    resolve = table.__getitem__
    try:
        parsed = _parse_graph(_decode_function_interface(function, resolve)[0], resolve)
    except XaxError as error:
        return ("reject", error.diagnostic.code, error.diagnostic.rule)
    return ("accept", parsed.pointer_extents, parsed.returns)


class _Counting:
    """Counts the engine's acceptances while installed."""

    def __enter__(self):
        from xax_selfhost_typing import NativeTyping

        self.accepted = 0
        self.original = NativeTyping.facts

        def counting(self_, values):
            result = self.original(self_, values)
            self.accepted += bool(result[0])
            return result

        NativeTyping.facts = counting
        return self

    def __exit__(self, *_exc):
        from xax_selfhost_typing import NativeTyping

        NativeTyping.facts = self.original


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostS4d2dTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_typing import NativeTyping

        cls.native = NativeTyping()

    def agree(self, function, objects):
        from test_xax_selfhost_facts import _engine

        with _engine(None):
            expected = _parsed(function, objects)
        with _engine(self.native), _Counting() as counting:
            actual = _parsed(function, objects)
        self.assertEqual(actual, expected)
        return expected[0], counting.accepted

    def test_link_programs_agree_with_the_bootstrap(self):
        import test_xax_links as links

        cases = [links.program(None), *(links.program(mutation) for mutation in sorted(links.LinkVerifierTests.REJECTIONS)),
                 links.program("null-follow"), links.calling_program(), links.calling_program(pass_table=True),
                 links.table_calling_program(), links.table_calling_program(wrong_arena=True),
                 links.table_calling_program(callee_options=dict(declare=False)),
                 links.table_calling_program(callee_options=dict(declare_on="offset"))]
        valid = accepted = 0
        for function, _target, objects in cases:
            with self.subTest(function=function.cid.hex()[:12]):
                outcome, engine = self.agree(function, objects)
                if outcome == "accept":
                    valid += 1
                    accepted += engine > 0
        self.assertEqual(valid, 4)
        self.assertEqual(accepted, valid)

    def test_target_operation_mutations_agree_with_the_bootstrap(self):
        rng = random.Random(139)
        outcomes = {"accept": 0, "reject": 0}
        accepted = 0
        for trial in range(240):
            function, objects = _target_program(rng, trial)
            outcome, engine = self.agree(function, objects)
            outcomes[outcome] += 1
            accepted += outcome == "accept" and engine > 0
        self.assertGreater(outcomes["reject"], 50)
        self.assertGreater(outcomes["accept"], 10)
        self.assertEqual(accepted, outcomes["accept"])


def _target_program(rng: random.Random, trial: int):
    """The accelerator fixture's graph, unchanged (every fourth trial) or with one change: a target body
    byte, a node attribute, a node result type, or a dropped operand."""
    from xax_compiler import (
        AtomicScope, Block, EffectDomain, Node, ResourceFlags, Terminator, ValueRef, bits_type, effect_type, function, graph_fragment,
        resource_type, simt32_accelerator_target,
    )

    b32 = bits_type(32)
    device_effect = effect_type(EffectDomain.DEVICE, 1)
    host_buffer = resource_type(1001, 1, flags=ResourceFlags.ACQUIRABLE | ResourceFlags.RELEASABLE, transitions=(2,))
    device_buffer = resource_type(1001, 2, flags=ResourceFlags.RELEASABLE, transitions=(1,))
    pool = (b32, device_effect, host_buffer, device_buffer, bits_type(64), effect_type(EffectDomain.DEVICE, 2), resource_type(1001, 3, transitions=(1,)))
    target = simt32_accelerator_target()
    kind = trial % 4 if trial % 4 else None
    if kind == 1:
        body = bytearray(target.body)
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 2, 3, 4, 5, 32, 64, 127, 128, 255, body[position] ^ 1, body[position] + 1 & 0xFF))
        target = SemanticObject.create(Kind.TARGET, bytes(body), [])
    device = AtomicScope.DEVICE
    specs = [  # (operands, results, attributes)
        ([ValueRef.parameter(0, 2)], [host_buffer, device_effect], [1, device, 1, 1]),
        ([ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1)], [device_buffer, device_effect], [2, device, 1, 2]),
        ([ValueRef.parameter(0, 1), ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 1, 1)], [device_buffer, device_effect], [3, device, 2, 2]),
        ([ValueRef.node_result(0, 2, 0), ValueRef.node_result(0, 2, 1)], [device_buffer, device_effect], [4, device, 2, 2]),
        ([ValueRef.node_result(0, 3, 0), ValueRef.node_result(0, 3, 1)], [b32, host_buffer, device_effect], [5, device, 2, 1]),
        ([ValueRef.node_result(0, 4, 1), ValueRef.node_result(0, 4, 2)], [device_effect], [6, device, 1, 1]),
    ]
    node_index = rng.randrange(len(specs))
    operands, results, attributes = specs[node_index]
    if kind == 2:
        attributes[rng.randrange(4)] = rng.choice((0, 1, 2, 3, 4, 7))
    elif kind == 3 and rng.random() < 0.7:
        results[rng.randrange(len(results))] = rng.choice(pool)
    elif kind == 3:
        operands.pop(rng.randrange(len(operands)))
    nodes = tuple(Node(Operation.TARGET_OP, tuple(ops), tuple(res), entity=target, attributes=tuple(attrs)) for ops, res, attrs in specs)
    returns = (specs[4][1][0], specs[5][1][0])
    graph = graph_fragment((Block((b32, b32, device_effect), nodes, Terminator.return_((ValueRef.node_result(0, 4, 0), ValueRef.node_result(0, 5, 0)))),))
    entry = function(graph, (b32, b32, device_effect), returns)
    return entry, (*pool, target, graph, entry)


if __name__ == "__main__":
    unittest.main()
