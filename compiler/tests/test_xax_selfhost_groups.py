"""S6b.3 (ADR-146): XAX decides recursion groups, group member functions, and targets exactly when the bootstrap accepts.

Random recursion groups (one to three members calling each other, in random
member order, with members that tie on their reference lists or are byte
for byte equal), their member functions, and every built-in target, plus
mutations (group, member function, and target body bytes, a member index
past the group, group calls with another interface, members no call
reaches), are verified with the XAX store verifier's verdicts used and not
used.  The outcome and exact diagnostic must be identical, no verdict may
hold for the object the bootstrap rejects, and every group, member function,
and general or concurrency-profile target of the valid stores is proven.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling suites' program builders

import xax_compiler as X
from xax_compiler import IntCompare, Kind, Operation, RecursionMember, SemanticObject, StoreReader, XaxError, bits_type, object_with_refs, write_store
from xax_graph_builder import GraphBuilder

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32 = bits_type(1), bits_type(8), bits_type(32)
TARGETS = tuple(maker for name, maker in sorted(vars(X).items()) if name.endswith("_target") and callable(maker) and not name.startswith("_")
                and name not in ("call_target", "decode_native_target"))
MUTATIONS = (None, None, None, "group_byte", "member_index", "member_byte", "call_type", "unreached", "target_byte")


def _member(spec, renumber):
    """A member graph from ``(base value, [(callee, B8 result?)...])`` with callees renumbered."""
    from test_xax_recursion import _graph, _group_call

    base_value, calls = spec
    graph = GraphBuilder()
    graph.track(B1, B8, B32)
    entry = graph.block(B32)
    base, recurse = graph.block(), graph.block(B32)
    (n,) = entry.params
    entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)), base, (), recurse, (n,))
    base.ret(base.const(B32, base_value))
    (m,) = recurse.params
    smaller = recurse.op1(Operation.SUB_WRAP, (m, recurse.const(B32, 1)), B32)
    total = None
    for callee, narrow in calls:
        if narrow:
            (inner,) = _group_call(recurse, renumber[callee], (smaller,), (B8,))
            inner = recurse.op1(Operation.INT_ZERO_EXTEND, (inner,), B32)
        else:
            (inner,) = _group_call(recurse, renumber[callee], (smaller,), (B32,))
        total = inner if total is None else recurse.op1(Operation.ADD_WRAP, (total, inner), B32)
    recurse.ret(total)
    fragment = _graph(graph)
    return RecursionMember(fragment, (B32,), (B32,)), [*graph.objects.values(), fragment]


def _members(rng: random.Random, mutation: str | None):
    """Group members, in canonical order when one exists (most of the time) so that most groups are valid."""
    from itertools import permutations

    count = rng.randrange(1, 4)
    tied = rng.random() < 0.4
    narrow = lambda: mutation == "call_type" and rng.random() < 0.5  # noqa: E731
    # A ring of calls (member i calls i + 1) makes one strongly connected component; extra calls vary the shape.
    specs = [(1 if tied else rng.randrange(4), [((index + 1) % count, narrow()), *((rng.randrange(count), narrow()) for _ in range(rng.randrange(2)))])
             for index in range(count)]
    for _base, calls in specs:
        rng.shuffle(calls)
    if mutation == "unreached" and count > 1:
        specs[-1] = (specs[-1][0], [(count - 1, False)])  # calls only itself: not one strongly connected component
    orders = list(permutations(range(count))) if rng.random() < 0.8 else [tuple(range(count))]
    for order in orders:  # order[k]: the spec placed at member k
        renumber = {old: new for new, old in enumerate(order)}
        built = [_member(specs[old], renumber) for old in order]
        members = [member for member, _items in built]
        objects = [item for _member_, items in built for item in items]
        table = {item.cid: item for item in (*objects, B1, B8, B32)}
        try:
            canonical = X.canonical_recursion_order(members, table.__getitem__) == tuple(range(count))
        except (XaxError, ValueError):
            canonical = False
        if canonical:
            break
    return members, objects


def _store(rng: random.Random, mutation: str | None):
    members, objects = _members(rng, mutation)
    count = len(members)
    group = X.recursion_group(members)
    if mutation == "group_byte":
        body = bytearray(group.body)
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 2, 3, 127, body[position] ^ 1))
        group = SemanticObject.create(Kind.RECURSION_GROUP, bytes(body), list(group.references))
    functions = [X.group_member_function(group, index) for index in range(count)]
    if mutation == "member_index":
        functions.append(X.group_member_function(group, count + rng.randrange(2)))
    if mutation == "member_byte":
        body = bytearray(functions[0].body)
        body[rng.randrange(len(body))] = rng.choice((1, 5, 127, 200))
        functions[0] = SemanticObject.create(Kind.FUNCTION, bytes(body), list(functions[0].references))
    target = rng.choice(TARGETS)()
    if mutation == "target_byte":
        body = bytearray(target.body)
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 2, 3, 4, 127, body[position] ^ 1, body[position] + 1 & 255))
        target = SemanticObject.create(Kind.TARGET, bytes(body), list(target.references))
    module = object_with_refs(Kind.MODULE, [group, *functions, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    candidates = {item.cid: item for item in (*objects, B1, B8, B32, group, *functions, target, module, root)}
    stored, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid in stored or cid not in candidates:
            continue
        stored[cid] = candidates[cid]
        pending.extend(stored[cid].references)
    try:
        return StoreReader(write_store(root.cid, list(stored.values())))
    except XaxError:
        return None


def _verify(reader, use_xax: bool):
    saved = X._xax_verify_store
    if not use_xax:
        X._xax_verify_store = lambda _reader, _objects: (False, {})
    X._PARSED_GRAPHS.clear()
    try:
        X.verify_store(reader)
        return ("accept",)
    except XaxError as error:
        return ("reject", error.diagnostic.code, error.diagnostic.rule, error.diagnostic.entity)
    finally:
        X._xax_verify_store = saved


def _general_or_concurrency(target) -> bool:
    """A profile-1 or profile-2 target (or an identity-only carrier): the ones XAX decides."""
    length, at = target.body[0], 1
    return len(target.body) == at + length or target.body[at + length] in (1, 2)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostGroupTests(unittest.TestCase):
    def test_groups_and_targets_agree_with_the_bootstrap(self):
        rng = random.Random(146)
        valid = rejected = 0
        decided = {Kind.RECURSION_GROUP: [0, 0], Kind.FUNCTION: [0, 0], Kind.TARGET: [0, 0]}
        rules = set()
        for trial in range(220):
            mutation = MUTATIONS[trial % len(MUTATIONS)]
            reader = _store(rng, mutation)
            if reader is None:
                continue
            bootstrap = _verify(reader, False)
            with self.subTest(trial=trial, mutation=mutation):
                self.assertEqual(_verify(reader, True), bootstrap)
                objects = {item.cid: item for item in reader.objects()}
                _store_ok, proven = X._xax_verify_store(reader, objects)
                if bootstrap[0] == "reject":
                    rejected += 1
                    rules.add(bootstrap[2])
                    failing = bytes.fromhex(bootstrap[3]) if len(bootstrap[3]) == 64 else None
                    self.assertNotIn(failing, proven, "XAX proved the object the bootstrap rejects")
                    continue
                valid += 1
                for item in objects.values():
                    if item.kind in decided and (item.kind != Kind.TARGET or _general_or_concurrency(item)):
                        decided[item.kind][0] += item.cid in proven
                        decided[item.kind][1] += 1
        self.assertGreater(valid, 80)
        self.assertGreater(rejected, 60)
        for kind, (proven_count, total) in decided.items():
            self.assertEqual(proven_count, total, kind.name)
        self.assertTrue({"GRAPH-RECURSION-ORDER", "GRAPH-RECURSION-SCC", "GRAPH-CALL-CONTRACT", "GRAPH-RECURSION-MEMBER"} <= rules, rules)

    def test_every_builtin_target_agrees(self):
        for maker in TARGETS:
            target = maker()
            objects = {target.cid: target}
            words = __import__("xax_selfhost_verify").object_table(list(objects.values()), [0])
            self.assertIsNotNone(words)
            with self.subTest(target=maker.__name__):
                try:
                    X.decode_native_target(target, allow_carrier=True)
                    valid = True
                except XaxError:
                    valid = False
                module = object_with_refs(Kind.MODULE, [target])
                root = object_with_refs(Kind.PROGRAM_ROOT, [module])
                reader = StoreReader(write_store(root.cid, [target, module, root]))
                _store_ok, proven = X._xax_verify_store(reader, {item.cid: item for item in reader.objects()})
                if not valid:
                    self.assertNotIn(target.cid, proven)
                elif _general_or_concurrency(target):
                    self.assertIn(target.cid, proven)


if __name__ == "__main__":
    unittest.main()
