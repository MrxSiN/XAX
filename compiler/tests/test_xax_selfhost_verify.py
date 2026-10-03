"""S6b.2 (ADR-144): the XAX store verifier decides functions, reference lists, call contracts, and rootedness.

Random function stores (straight-line and branching graphs returning
parameters, node results, or constants; several functions per module), call
contracts, and their mutations (function and reference-list body bytes,
swapped interface types, return values of another type, boolean bytes,
unreachable objects) are verified with the XAX store verifier's verdicts used
and not used.  The outcome and exact diagnostic must be identical, a verdict
must never hold for an object the bootstrap rejects, and the verifier must
prove every function, list, and contract of the valid stores.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

from xax_compiler import (
    EffectDomain, IntCompare, Kind, Operation, SemanticObject, StoreReader, XaxError, bits_type, call_contract, effect_type, object_with_refs,
    write_store,
)
from xax_graph_builder import GraphBuilder

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32 = bits_type(1), bits_type(8), bits_type(32)
IO = effect_type(EffectDomain.IO, 2)
MUTATIONS = (None, None, None, "function_byte", "return_type", "list_byte", "contract_flag", "unreachable")


def _function(rng: random.Random):
    graph = GraphBuilder()
    graph.track(B1, B8, B32)
    entry = graph.block(B32, B32)
    a, b = entry.params
    value = entry.op1(rng.choice((Operation.ADD_WRAP, Operation.BIT_XOR, Operation.MUL_WRAP)), (a, b), B32)
    if rng.random() < 0.5:
        condition = entry.op1(Operation.INT_COMPARE, (value, entry.const(B32, rng.randrange(9))), B1, attributes=(IntCompare.ULT,))
        left, right = graph.block(B32), graph.block(B32)
        entry.cbr(condition, left, (value,), right, (a,))
        left.ret(left.op1(Operation.ADD_WRAP, (left.params[0], left.const(B32, 1)), B32))
        right.ret(right.params[0])
    else:
        entry.ret(rng.choice((value, a, entry.const(B32, rng.randrange(1 << 32)))))
    function = graph.function((B32, B32), (B32,))
    return function, list(graph.objects.values())


def _store(rng: random.Random, mutation: str | None):
    functions, objects = [], []
    for _ in range(rng.randrange(1, 4)):
        function, items = _function(rng)
        functions.append(function)
        objects += items
    contract = call_contract((B32, IO), (B32, IO), may_return=True, may_trap=rng.random() < 0.5)
    members = [*functions, contract]
    if mutation == "function_byte":
        target = functions[0]
        body = bytearray(target.body)
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 2, 3, 127, 200, body[position] ^ 1))
        mutated = SemanticObject.create(Kind.FUNCTION, bytes(body), list(target.references))
        members[0] = mutated
    if mutation == "return_type":
        target = functions[0]
        _graph, *_rest = target.references
        graph_object = next(item for item in objects if item.cid in target.references and item.kind == Kind.GRAPH_FRAGMENT)
        from xax_compiler import function as make_function

        members[0] = make_function(graph_object, (B32, B32), (B8,))
        objects.append(B8)
    if mutation == "contract_flag":
        body = bytearray(contract.body)
        body[-1 if rng.random() < 0.5 else -2] = rng.choice((2, 7, 255))
        members[-1] = SemanticObject.create(Kind.CALL_CONTRACT, bytes(body), list(contract.references))
    module = object_with_refs(Kind.MODULE, members)
    if mutation == "list_byte":
        body = bytearray(module.body)
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 5, 127, body[position] ^ 1))
        module = SemanticObject.create(Kind.MODULE, bytes(body), list(module.references))
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    candidates = {item.cid: item for item in (*objects, B32, IO, *members, module, root)}
    stored, pending = {}, [root.cid]
    while pending:  # the objects reachable from the root
        cid = pending.pop()
        if cid in stored or cid not in candidates:
            continue
        stored[cid] = candidates[cid]
        pending.extend(stored[cid].references)
    if mutation == "unreachable":
        stray = bits_type(rng.choice((3, 5, 7, 11)))
        stored[stray.cid] = stray
    try:
        return StoreReader(write_store(root.cid, list(stored.values())))
    except XaxError:
        return None


def _verify(reader, use_xax: bool):
    import xax_compiler

    saved = xax_compiler._xax_verify_store
    if not use_xax:
        xax_compiler._xax_verify_store = lambda _reader, _objects: (False, {})
    xax_compiler._PARSED_GRAPHS.clear()
    try:
        xax_compiler.verify_store(reader)
        return ("accept",)
    except XaxError as error:
        return ("reject", error.diagnostic.code, error.diagnostic.rule, error.diagnostic.entity)
    finally:
        xax_compiler._xax_verify_store = saved


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostStoreVerifierTests(unittest.TestCase):
    def test_stores_agree_with_the_bootstrap(self):
        import xax_compiler

        rng = random.Random(144)
        valid = proven_valid = rejected = 0
        for trial in range(160):
            mutation = MUTATIONS[trial % len(MUTATIONS)]
            reader = _store(rng, mutation)
            if reader is None:
                continue
            bootstrap = _verify(reader, False)
            with self.subTest(trial=trial, mutation=mutation):
                self.assertEqual(_verify(reader, True), bootstrap)
                objects = {item.cid: item for item in reader.objects()}
                store_ok, proven = xax_compiler._xax_verify_store(reader, objects)
                if bootstrap[0] == "reject":
                    rejected += 1
                    failing = bytes.fromhex(bootstrap[3]) if len(bootstrap[3]) == 64 else None
                    self.assertNotIn(failing, proven, "XAX proved the object the bootstrap rejects")
                    if bootstrap[2] in ("ID-ROOTED-STORE", "ID-MERKLE-ACYCLIC"):
                        self.assertFalse(store_ok)
                else:
                    valid += 1
                    expected = {cid for cid, item in objects.items() if item.kind in (Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.CALL_CONTRACT)}
                    proven_valid += store_ok and expected <= set(proven)
        self.assertGreater(valid, 40)
        self.assertGreater(rejected, 30)
        self.assertEqual(proven_valid, valid)


if __name__ == "__main__":
    unittest.main()
