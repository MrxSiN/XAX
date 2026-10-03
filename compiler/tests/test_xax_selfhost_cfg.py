"""Self-hosting step S3d (ADR-121): control-flow analysis is XAX on the production path."""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_compiler as compiler
from xax_selfhost_cfg import DEFER, REJECT, STORE_PATH, NativeCfg, build_cfg_program

NATIVE = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _bootstrap(entry, successors):
    """The bootstrap algorithm, verbatim from ``_parse_graph_uncached``."""
    n = len(successors)
    predecessors = [set() for _ in successors]
    for index, targets in enumerate(successors):
        for target in targets:
            if target >= n:
                return None
            predecessors[target].add(index)
    dominators = [set(range(n)) for _ in successors]
    dominators[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for index in range(n):
            if index == entry:
                continue
            new = {index}
            if predecessors[index]:
                new |= set.intersection(*(dominators[p] for p in predecessors[index]))
            if new != dominators[index]:
                dominators[index] = new
                changed = True
    order, visited, walk = [], {entry}, [(entry, 0)]
    while walk:
        current, cursor = walk[-1]
        if cursor < len(successors[current]):
            walk[-1] = (current, cursor + 1)
            successor = successors[current][cursor]
            if successor not in visited:
                visited.add(successor)
                walk.append((successor, 0))
        else:
            order.append(current)
            walk.pop()
    order.reverse()
    order.extend(index for index in range(n) if index not in visited)
    return order, dominators


class CfgStoreTests(unittest.TestCase):
    def test_committed_store_regenerates(self):
        building = compiler._CFG_BUILDING
        compiler._CFG_BUILDING = True
        try:
            reader, _function = build_cfg_program()
        finally:
            compiler._CFG_BUILDING = building
        self.assertEqual(reader.data, STORE_PATH.read_bytes())


@unittest.skipUnless(NATIVE, "the native leaf runs on Linux x86-64")
class NativeCfgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = NativeCfg()

    def test_random_graphs_match_the_bootstrap(self):
        rng = random.Random(20261003)
        for trial in range(400):
            n = rng.choice((1, 2, 3, 5, 8, 13, 40, 64, 65, 130))
            successors = [[rng.randrange(n) for _ in range(rng.choice((0, 1, 1, 2, 2, 3)))] for _ in range(n)]
            entry = rng.randrange(n)
            status, order, dominators, _valid = self.cfg.analyze(entry, successors)
            with self.subTest(trial=trial, n=n):
                self.assertEqual(status, 0)
                self.assertEqual((order, dominators), _bootstrap(entry, successors))

    def test_value_uses_match_the_bootstrap_value_type(self):
        """S3e: a use is valid exactly when the bootstrap ``value_type`` accepts it."""
        rng = random.Random(42)
        outcomes = set()
        for trial in range(300):
            n = rng.choice((1, 2, 4, 9, 70))
            successors = [[rng.randrange(n) for _ in range(rng.choice((0, 1, 2)))] for _ in range(n)]
            entry = rng.randrange(n)
            tables = [(rng.randrange(4), tuple(rng.randrange(3) for _ in range(rng.randrange(5)))) for _ in range(n)]
            _order, dominators = _bootstrap(entry, successors)
            uses = []
            for _ in range(rng.randrange(1, 6)):
                use_block = rng.randrange(n)
                use_node = rng.randrange(len(tables[use_block][1]) + 1)
                tag = rng.randrange(2)
                block = rng.randrange(n + 1)  # n is out of range
                uses.append((use_block, use_node, tag, block, rng.randrange(5), rng.randrange(4) if tag else 0))

            def accepted(use):
                use_block, use_node, tag, block, index, result = use
                if block >= n:
                    return False
                parameters, results = tables[block]
                if tag == 0 and index >= parameters:
                    return False
                if tag == 1 and (index >= len(results) or result >= results[index] or (block == use_block and index >= use_node)):
                    return False
                return block == use_block or block in dominators[use_block]

            expected = all(accepted(use) for use in uses)
            status, _order, _dominators, valid = self.cfg.analyze(entry, successors, (tables, uses))
            with self.subTest(trial=trial):
                self.assertEqual((status, valid), (0, expected))
            outcomes.add(expected)
        self.assertEqual(outcomes, {True, False})

    def test_bad_branch_target_rejects(self):
        self.assertEqual(self.cfg.analyze(0, [[1], [7]])[0], REJECT)
        self.assertIsNone(_bootstrap(0, [[1], [7]]))

    def test_oversized_graph_defers(self):
        self.assertEqual(self.cfg.analyze(0, [[] for _ in range(70000)])[0], DEFER)

    def test_production_parse_uses_it(self):
        self.assertIsNotNone(compiler._native_cfg())


if __name__ == "__main__":
    unittest.main()
