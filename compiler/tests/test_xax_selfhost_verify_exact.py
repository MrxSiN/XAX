"""S15b.1-S15b.2 (ADR-288, ADR-289): the general driver's ``verify`` rejects exactly as ``verify_store`` does.

The production compiler's ``verify`` command runs as a process with no Python inside.  On mutated stores it must
accept exactly what ``verify_store`` accepts and, when it rejects, write the bootstrap's own diagnostic (code, entity,
rule, expected, actual, dependencies, repair neighborhood), in ``verify_store``'s order: missing references, object
rejections after the graphs they parse first, types and constants, the store's rootedness last.  Graph checks not yet
rendered keep the driver's own record (``XAX.DRIVER.VERIFY``); a decline makes no claim.

* Object sites: the stores of ``test_xax_selfhost_render`` (functions, groups, contracts, lists, targets, packages and
  build objects), with one object's body or references mutated.
* Types and constants: ``test_xax_selfhost_objects``'s random types of every form and constants, mutated, in a module.
* Graphs (S15b.3, ADR-292): ``test_xax_selfhost_typing``'s one-node graphs of every covered operation and
  ``test_xax_selfhost_linear``'s resource programs with their mutations, as function stores; none of their rejections
  declines (S15b.3d, ADR-297; since ADR-311 none in any corpus here).
* Invalid uses (S15b.3c, ADR-295): the same programs with one operand pointed at a value that does not exist or does not
  dominate its use, and ``test_xax_selfhost_s8_graphs``'s use variants.
* Memory facts (S15b.3b, ADR-293): ``test_xax_selfhost_facts``'s stack and view programs with their mutations and its
  typed-access, heap-view, atomic, record/link, and address variants.
* Declarations and stack-owner entries (S15b.3d, ADR-313): ``fixtures/declared_rejections``, the stores the C-interop,
  lend-entry, Android, web, JVM-callback, accelerator and recursion tests reject with a rule that quotes a decoded
  declaration (foreign function, call contract, code-address type, target operation) or a stack-owner entry's block;
  each file is named by the rule.
"""

from __future__ import annotations

import os
import platform
import random
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_compiler import Kind, StoreReader, XaxError, object_with_refs, write_store
from xax_selfhost_diagnostics import decode_record

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def resource_callee_program(rng: random.Random):
    """S15b.3e (ADR-318): a caller threading one stack owner through calls to several resource callees (pass-through,
    store and load contracts, some with a graph the verifier rejects) in a random order, with an optional fault of its
    own (a typing or an uninitialized-load rejection) at a random place; ``(store bytes, callee count)``."""
    from xax_compiler import (Block, Node, Operation, Terminator, ValueRef, bits_type, constant, function, graph_fragment,
                              memory_effect_type, pointer_type, stack_owner_type)

    b8, b32 = bits_type(8), bits_type(32)
    pointer, owner, effect = pointer_type(b32, alignment=4), stack_owner_type(), memory_effect_type()
    constants = [constant(b8, value) for value in range(4)]
    objects = [b8, b32, pointer, owner, effect, *constants]

    def made(kind: str, variant: int):
        pure = tuple(Node(Operation.CONSTANT, (), (b8,), entity=constants[k]) for k in range(variant))
        bad = (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b8,)),) if kind.endswith("bad") else ()
        if kind.startswith("pass"):
            block = Block((owner, effect), pure + bad, Terminator.return_((ValueRef.parameter(0, 0), ValueRef.parameter(0, 1))))
            interface = ((owner, effect), (owner, effect))
        elif kind.startswith("store"):
            store = Node(Operation.STORE_BITS_LE, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3)), (effect,), attributes=(4, 4))
            block = Block((pointer, b32, owner, effect), (store,) + bad, Terminator.return_((ValueRef.parameter(0, 2), ValueRef.node_result(0, 0))))
            interface = ((pointer, b32, owner, effect), (owner, effect))
        else:
            load = Node(Operation.LOAD_BITS_LE, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 2)), (b32, effect), attributes=(4, 4))
            block = Block((pointer, owner, effect), (load,) + bad, Terminator.return_((ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 0, 1))))
            interface = ((pointer, owner, effect), (b32, owner, effect))
        graph = graph_fragment([block])
        objects.append(graph)
        return function(graph, *interface), kind

    kinds = ("pass", "pass", "pass", "store", "store", "load") + (("pass_bad", "store_bad", "load_bad") if rng.random() < 0.4 else ())
    pool = [made(rng.choice(kinds), variant) for variant in rng.sample(range(4), rng.randrange(2, 5))]
    called = {}
    nodes = [Node(Operation.STACK_ALLOC, (), (pointer, owner, effect), attributes=(4, 4))]
    own, eff = ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2)
    calls = rng.randrange(2, 7)
    fault_at = rng.randrange(calls + 1) if rng.random() < 0.5 else None
    fault = rng.choice(("typing", "uninitialized"))
    for k in range(calls + 1):
        if k == fault_at:
            if fault == "typing":
                nodes.append(Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), own), (b32,)))
            else:
                nodes.append(Node(Operation.LOAD_BITS_LE, (ValueRef.node_result(0, 0, 0), eff), (b32, effect), attributes=(4, 4)))
                eff = ValueRef.node_result(0, len(nodes) - 1, 1)
        if k == calls:
            break
        callee, kind = rng.choice(pool)
        called[callee.cid] = callee
        at = len(nodes)
        if kind.startswith("pass"):
            nodes.append(Node(Operation.CALL_DIRECT, (own, eff), (owner, effect), entity=callee))
            own, eff = ValueRef.node_result(0, at, 0), ValueRef.node_result(0, at, 1)
        elif kind.startswith("store"):
            nodes.append(Node(Operation.CALL_DIRECT, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), own, eff), (owner, effect), entity=callee))
            own, eff = ValueRef.node_result(0, at, 0), ValueRef.node_result(0, at, 1)
        else:
            nodes.append(Node(Operation.CALL_DIRECT, (ValueRef.node_result(0, 0, 0), own, eff), (b32, owner, effect), entity=callee))
            own, eff = ValueRef.node_result(0, at, 1), ValueRef.node_result(0, at, 2)
    nodes.append(Node(Operation.STACK_END, (own, eff), ()))
    caller_graph = graph_fragment([Block((b32,), tuple(nodes), Terminator.return_((ValueRef.parameter(0, 0),)))])
    caller = function(caller_graph, (b32,), (b32,))
    members = [caller, *called.values()]
    rng.shuffle(members)
    module = object_with_refs(Kind.MODULE, members)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    table = {item.cid: item for item in (*objects, *called.values(), caller_graph, caller, module, root)}
    reached, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in reached and cid in table:
            reached[cid] = table[cid]
            pending.extend(table[cid].references)
    return write_store(root.cid, list(reached.values())), len(called)


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver runs on Linux x86-64 only")
class VerifyExactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 600
        cls.directory = tempfile.mkdtemp()

    def driver_outcome(self, data: bytes):
        store, output = (os.path.join(self.directory, name) for name in ("store.xax", "out.bin"))
        Path(store).write_bytes(data)
        if os.path.exists(output):
            os.unlink(output)
        status = self.driver.verify(store, output)
        if status == 1:
            produced = Path(output).read_bytes()
            return "rejected", decode_record([int.from_bytes(produced[k:k + 8], "little") for k in range(0, len(produced), 8)])
        return {0: "accepted", 2: "declined", 3: "failed"}[status], None

    def check(self, reader, tally):
        X._PARSED_GRAPHS.clear()
        try:
            X.verify_store(reader)
            expected = None
        except XaxError as error:
            expected = error.diagnostic
        except (IndexError, KeyError, TypeError, ValueError):
            tally["host_error"] += 1  # the host fails without a diagnostic: no reference to compare with
            return
        kind, diagnostic = self.driver_outcome(reader.data)
        if expected is None:
            self.assertIn(kind, ("accepted", "declined"))
            tally["accepted" if kind == "accepted" else "declined"] += 1
            return
        self.assertIn(kind, ("rejected", "declined"))  # never accepted
        if kind == "declined":
            tally["declined"] += 1
            tally["declined_rejection"] = tally.get("declined_rejection", 0) + 1
        elif diagnostic.code == "XAX.DRIVER.VERIFY":
            tally["driver_record"] += 1
        else:
            self.assertEqual(diagnostic, expected)
            tally["exact"] += 1

    def test_object_sites(self):
        from test_xax_selfhost_render import _bases, _mutated

        rng = random.Random(288)
        bases = _bases(rng)
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for trial in range(int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240"))):
            objects, root = bases[trial % len(bases)]
            for _round in range(1 + rng.randrange(2)):
                objects, root = _mutated(rng, objects, root)
            try:
                reader = StoreReader(write_store(root, list(objects.values())))
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(trial=trial):
                self.check(reader, tally)
        self.assertEqual(tally.get("declined_rejection", 0), 0, tally)  # S15b.3d (ADR-311)
        self.assertGreater(tally["exact"], 100, tally)

    def test_declared_rejections(self):
        """S15b.3d (ADR-313): every fixture rejects with its rule, and the driver writes the bootstrap's exact record."""
        fixtures = sorted((Path(__file__).parent / "fixtures" / "declared_rejections").glob("*.xax"))
        self.assertEqual(len(fixtures), 36)
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for path in fixtures:
            with self.subTest(fixture=path.name):
                reader = StoreReader(path.read_bytes())
                X._PARSED_GRAPHS.clear()
                with self.assertRaises(XaxError) as raised:
                    X.verify_store(reader)
                self.assertEqual(raised.exception.diagnostic.rule, path.stem.split("_", 1)[1])
                self.check(reader, tally)
        self.assertEqual(tally["exact"], len(fixtures), tally)

    def test_types_and_constants(self):
        from test_xax_selfhost_objects import _sample

        rng = random.Random(289)
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for trial in range(int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240"))):
            made, objects = _sample(rng)
            module = object_with_refs(Kind.MODULE, [made])
            root = object_with_refs(Kind.PROGRAM_ROOT, [module])
            stored = {item.cid: item for item in (*objects, module, root)}
            try:
                reader = StoreReader(write_store(root.cid, list(stored.values())))
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(trial=trial):
                self.check(reader, tally)
        self.assertEqual(tally.get("declined_rejection", 0), 0, tally)  # S15b.3d (ADR-311)
        self.assertGreater(tally["exact"], 40, tally)

    @staticmethod
    def stored(function, objects):
        module = object_with_refs(Kind.MODULE, [function])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        table = {item.cid: item for item in (*objects, function, module, root)}
        reached, pending = {}, [root.cid]
        while pending:
            cid = pending.pop()
            if cid not in reached and cid in table:
                reached[cid] = table[cid]
                pending.extend(table[cid].references)
        return StoreReader(write_store(root.cid, list(reached.values())))

    def test_graphs(self):
        from test_xax_selfhost_linear import MUTATIONS, _program
        from test_xax_selfhost_typing import CALLEE_OBJECTS, CONSTANTS, POOL, _samples
        from xax_graph_builder import GraphBuilder

        stored = self.stored
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        trials = int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240"))
        for index, sample in enumerate(_samples(trials, seed=290)):
            operation, operand_types, result_types, attributes, *entity = sample
            graph = GraphBuilder()
            block = graph.block(*operand_types)
            results = block.op(operation, tuple(block.params), tuple(result_types), attributes=tuple(attributes), entity=entity[0] if entity else None)
            block.ret(*results)
            try:
                function = graph.function(tuple(operand_types), tuple(result_types))
                reader = stored(function, (*graph.objects.values(), *POOL, *CONSTANTS, *CALLEE_OBJECTS))
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(sample=index):
                self.check(reader, tally)
        rng = random.Random(290)
        for trial in range(trials // 2):
            function, objects = _program(rng, MUTATIONS[trial % len(MUTATIONS)])
            try:
                reader = stored(function, objects)
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(program=trial):
                self.check(reader, tally)
        self.assertGreater(tally["exact"], 60, tally)
        # S15b.3d (ADR-297): a type or constant reached inside the parse, and a sum operation's type of another form,
        # are rendered too: every rejection here is decided.
        self.assertEqual(tally.get("declined_rejection", 0), 0, tally)

    def test_memory(self):
        import test_xax_selfhost_facts as F

        programs = []
        rng = random.Random(291)
        trials = int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240"))
        programs += [F._program(rng, F.MUTATIONS[trial % len(F.MUTATIONS)]) for trial in range(trials // 4)]
        programs += [F._view_program(rng, F.VIEW_MUTATIONS[trial % len(F.VIEW_MUTATIONS)]) for trial in range(trials // 4)]
        variants = {
            F._typed_program: ("load_type", "store_type", "store_effect_type", "checked_alignment", "checked_offset", "checked_load_type",
                               "checked_store_type", "checked_effect_type", "rebase_width", "rebase_authority", "rebase_extent",
                               "rebase_alignment", "return_order"),
            F._heap_program: ("view_bounds", "view_alignment", "view_token_type", "view_effect_type", "view_owner", "dealloc_offset",
                              "dealloc_twice", "foreign_fork", "use_after_free"),
            F._atomic_program: ("valid", "uninitialized", "read_only", "misaligned", "forked", "effect_type", "result_type", "value_type",
                                "cmpxchg_result", "fence_effect", "fence_forked", "order_enum", "order_legal", "scope_enum", "rmw_kind",
                                "fence_order", "cmpxchg_stronger", "cmpxchg_failure", "cmpxchg_failure_enum", "cmpxchg_strength"),
            F._record_program: ("valid", "link_record_only", "record_extent", "pointer_store_local", "link_make_record", "link_make_type",
                                "follow_authority", "follow_alignment"),
            F._address_program: ("valid", "authority", "element", "alignment"),
        }
        programs += [make(variant) for make, names in variants.items() for variant in names]
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for index, (function, objects) in enumerate(programs):
            try:
                reader = self.stored(function, objects)
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(program=index):
                self.check(reader, tally)
        self.assertEqual(tally.get("declined_rejection", 0), 0, tally)  # S15b.3d (ADR-311)
        self.assertGreater(tally["exact"], 40, tally)

    def test_uses(self):
        import dataclasses
        from unittest import mock

        import test_xax_selfhost_facts as F
        import test_xax_selfhost_s8_graphs as S8
        from test_xax_selfhost_linear import MUTATIONS, _program
        from xax_compiler import ValueRef
        from xax_graph_builder import GraphBuilder

        rng = random.Random(295)
        build = GraphBuilder.function

        def mutated(graph, parameters, returns):
            """One node's operand pointed at an invalid value (a missing block, parameter, node, or result; a later
            node of its block; a value of another block)."""
            nodes = [(block, n) for block in graph.blocks for n, node in enumerate(block.nodes) if node.operands]
            if nodes:
                block, n = rng.choice(nodes)
                node = block.nodes[n]
                k = rng.randrange(len(node.operands))
                choices = [ValueRef.parameter(len(graph.blocks) + 2, 0), ValueRef.parameter(block.index, len(block.parameter_types) + 1),
                           ValueRef.node_result(block.index, len(block.nodes) + 3, 0), ValueRef.node_result(block.index, n, 0)]
                if n + 1 < len(block.nodes):
                    choices.append(ValueRef.node_result(block.index, n + 1, 0))
                choices += [ValueRef.node_result(other.index, 0, 0) for other in graph.blocks if other is not block and other.nodes]
                operands = list(node.operands)
                operands[k] = rng.choice(choices)
                block.nodes[n] = dataclasses.replace(node, operands=tuple(operands))
            return build(graph, parameters, returns)

        programs = [S8._use(variant) for variant in S8.USES if variant != "target"]
        trials = int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240"))
        with mock.patch.object(GraphBuilder, "function", mutated):
            programs += [_program(rng, MUTATIONS[trial % len(MUTATIONS)]) for trial in range(trials // 4)]
            programs += [F._program(rng, F.MUTATIONS[trial % len(F.MUTATIONS)]) for trial in range(trials // 4)]
            programs += [F._view_program(rng, F.VIEW_MUTATIONS[trial % len(F.VIEW_MUTATIONS)]) for trial in range(trials // 8)]
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for index, (function, objects) in enumerate(programs):
            try:
                reader = self.stored(function, objects)
            except (XaxError, ValueError, KeyError):
                continue
            with self.subTest(program=index):
                self.check(reader, tally)
        self.assertEqual(tally["driver_record"], 0, tally)
        self.assertEqual(tally.get("declined_rejection", 0), 0, tally)  # S15b.3d (ADR-311)
        self.assertGreater(tally["exact"], 40, tally)

    def test_resource_callees(self):
        """S15b.3e (ADR-318): graphs calling several different resource callees before their own decision get the
        bootstrap's outcome: each callee's graph is parsed at its first call, in the caller's order."""
        rng = random.Random(318)
        tally = dict.fromkeys(("accepted", "exact", "driver_record", "declined", "host_error"), 0)
        for trial in range(int(os.environ.get("XAX_VERIFY_EXACT_TRIALS", "240")) // 2):
            data, _callees = resource_callee_program(rng)
            with self.subTest(trial=trial):
                self.check(StoreReader(data), tally)
        self.assertEqual(tally["declined"], 0, tally)
        self.assertEqual(tally["driver_record"], 0, tally)
        self.assertGreater(tally["exact"], 20, tally)
        self.assertGreater(tally["accepted"], 10, tally)


if __name__ == "__main__":
    unittest.main()
