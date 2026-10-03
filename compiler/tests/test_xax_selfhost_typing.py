"""S4/S4b (ADR-132, ADR-133): the XAX typing rules agree with the bootstrap verifier.

Soundness: every node the XAX function proves is accepted by the bootstrap
(run with the native path off).  Coverage: well-typed nodes of every covered
family are proven.  Negative vectors: wrong arity, mismatched types, out-of-range
kinds and amounts, and a non-canonical type body are never proven.
"""

from __future__ import annotations

import contextlib
import platform
import random
import sys
import unittest
from types import SimpleNamespace

from xax_compiler import FloatFormat, Kind, Operation, SemanticObject, XaxError, array_type, bits_type, float_type, sum_type, tuple_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B1, B8, B32, B64, B100, B200 = (bits_type(width) for width in (1, 8, 32, 64, 100, 200))
F32, F64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
PAIR = tuple_type((B32, B32))
OVERLONG = SemanticObject.create(Kind.TYPE, bytes((1, 0x88, 0x00)))  # bits<8> with an overlong width
TRIPLE = tuple_type((B8, F64, B8))
ARRAY3, ARRAY0 = array_type(B32, 3), array_type(B8, 0)
NESTED = tuple_type((PAIR, B8))  # an aggregate element: left to the bootstrap
SUM3, SUM1 = sum_type((B8, B32, F64)), sum_type((B64,))
ELEMENTS = {PAIR: (B32, B32), TRIPLE: (B8, F64, B8), ARRAY3: (B32,) * 3, ARRAY0: (), NESTED: (PAIR, B8)}
VARIANTS = {SUM3: (B8, B32, F64), SUM1: (B64,)}
POOL = (B1, B8, B32, B64, B100, B200, F32, F64, PAIR, OVERLONG, TRIPLE, ARRAY3, ARRAY0, NESTED, SUM3, SUM1)


@contextlib.contextmanager
def _typing_path(native):
    """Verify with ``native`` as the typing function (None: bootstrap only), parse cache cleared."""
    import xax_compiler

    saved = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED)
    xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = native, True
    xax_compiler._PARSED_GRAPHS.clear()
    try:
        yield
    finally:
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = saved
        xax_compiler._PARSED_GRAPHS.clear()


def _bootstrap_accepts(operation, operand_types, result_types, attributes) -> bool:
    with _typing_path(None):
        return _accepts(operation, operand_types, result_types, attributes)


def _accepts(operation, operand_types, result_types, attributes) -> bool:
    graph = GraphBuilder()
    block = graph.block(*operand_types)
    results = block.op(operation, tuple(block.params), tuple(result_types), attributes=tuple(attributes))
    block.ret(*results)
    try:
        entry = graph.function(tuple(operand_types), tuple(result_types))
        program_store(entry, x86_64_linux_exec_target(), (*graph.objects.values(), *POOL))
    except (XaxError, ValueError):
        return False
    return True


def _samples(count: int, seed: int = 132):
    from xax_selfhost_typing import COVERED, FLOAT_COMPARE_KINDS, INT_COMPARE_KINDS

    rng = random.Random(seed)
    operations = sorted(COVERED)
    samples = []
    for _ in range(count):
        operation = rng.choice(operations)
        if operation in (Operation.AGGREGATE_MAKE, Operation.AGGREGATE_GET, Operation.SUM_MAKE, Operation.SUM_TAG, Operation.SUM_GET):
            samples.append(_aggregate_sample(rng, operation))
            continue
        operands = rng.choice((1, 2, 2, 3)) if rng.random() < 0.15 else (1 if operation in (Operation.INT_TRUNCATE, Operation.INT_ZERO_EXTEND, Operation.ROTATE_RIGHT, Operation.UINT_TO_FLOAT, Operation.SINT_TO_FLOAT, Operation.FLOAT_TO_UINT_TRUNC, Operation.FLOAT_TO_SINT_TRUNC, Operation.FLOAT_CONVERT) else 2)
        results = 2 if rng.random() < 0.05 else 1
        wants_attribute = operation in (Operation.ROTATE_RIGHT, Operation.FLOAT_COMPARE, Operation.INT_COMPARE)
        attribute_count = rng.choice((0, 1, 2)) if rng.random() < 0.1 else int(wants_attribute)
        limit = {Operation.INT_COMPARE: INT_COMPARE_KINDS, Operation.FLOAT_COMPARE: FLOAT_COMPARE_KINDS}.get(operation, 70)
        attributes = tuple(rng.randrange(0, limit + 2) for _ in range(attribute_count))
        first = rng.choice(POOL)
        # Mostly coherent types, so the proven side is exercised, with random noise.
        operand_types = tuple(first if rng.random() < 0.8 else rng.choice(POOL) for _ in range(operands))
        result = first if rng.random() < 0.5 else rng.choice(POOL)
        samples.append((operation, operand_types, (result,) * results, attributes))
    return samples


def _aggregate_sample(rng, operation):
    noise = lambda: rng.choice(POOL)  # noqa: E731
    attributes = (rng.randrange(0, 5),) if rng.random() < 0.9 else rng.choice(((), (0, 0)))
    if operation == Operation.AGGREGATE_MAKE:
        owner = rng.choice(tuple(ELEMENTS))
        operands = tuple(item if rng.random() < 0.9 else noise() for item in ELEMENTS[owner])
        if rng.random() < 0.1:
            operands = operands[:-1] if operands else (noise(),)
        return operation, operands, (owner,), () if rng.random() < 0.9 else (0,)
    if operation == Operation.AGGREGATE_GET:
        owner = rng.choice(tuple(ELEMENTS)) if rng.random() < 0.9 else noise()
        elements = ELEMENTS.get(owner, ())
        index = attributes[0] if attributes else 0
        result = elements[index] if index < len(elements) and rng.random() < 0.8 else noise()
        return operation, (owner,), (result,), attributes
    owner = rng.choice(tuple(VARIANTS)) if rng.random() < 0.9 else noise()
    variants = VARIANTS.get(owner, ())
    index = attributes[0] if attributes else 0
    variant = variants[index] if index < len(variants) and rng.random() < 0.8 else noise()
    if operation == Operation.SUM_MAKE:
        return operation, (variant,), (owner,), attributes
    if operation == Operation.SUM_GET:
        return operation, (owner,), (variant,), attributes
    return operation, (owner,), (rng.choice((B1, B8, B32, F32, PAIR)),), () if rng.random() < 0.9 else (1,)


def _native_verdicts(native, samples):
    from xax_selfhost_typing import marshal, type_info_from

    objects = {item.cid: item for item in POOL}
    nodes = [SimpleNamespace(operation=operation, operands=operand_types, results=tuple(item.cid for item in result_types), attributes=attributes) for operation, operand_types, result_types, attributes in samples]
    words, keys = marshal([SimpleNamespace(nodes=nodes)], lambda _block, node: tuple(item.cid for item in samples[node][1]), type_info_from(objects.__getitem__))
    status, verdicts = native.check(words, len(keys))
    return status, dict(zip((node for _block, node in keys), verdicts))


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostTypingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_typing import NativeTyping

        cls.native = NativeTyping()

    def test_proven_nodes_are_accepted_by_the_bootstrap(self):
        from xax_selfhost_typing import PROVEN

        samples = _samples(1000)
        status, verdicts = _native_verdicts(self.native, samples)
        self.assertEqual(status, 0)
        proven = accepted = aggregates = 0
        for index, sample in enumerate(samples):
            accepts = _bootstrap_accepts(*sample)
            if verdicts[index] == PROVEN:
                proven += 1
                aggregates += any(item in ELEMENTS or item in VARIANTS for item in (*sample[1], *sample[2]))
                self.assertTrue(accepts, sample)
            # Every accepted sample is proven unless it involves a nested aggregate.
            elif accepts and NESTED not in (*sample[1], *sample[2]):
                self.fail(f"accepted but not proven: {sample}")
            accepted += accepts
        self.assertGreater(proven, 80)
        self.assertGreater(aggregates, 30)

    def test_each_family_proves_its_well_typed_node(self):
        from xax_selfhost_typing import NOT_COVERED, NOT_PROVEN, PROVEN

        good = [
            (Operation.ADD_WRAP, (B32, B32), (B32,), ()),
            (Operation.UREM, (B200, B200), (B200,), ()),
            (Operation.INT_TRUNCATE, (B64,), (B8,), ()),
            (Operation.INT_ZERO_EXTEND, (B1,), (B32,), ()),
            (Operation.ROTATE_RIGHT, (B64,), (B64,), (63,)),
            (Operation.FLOAT_DIV, (F64, F64), (F64,), ()),
            (Operation.FLOAT_COMPARE, (F32, F32), (B1,), (6,)),
            (Operation.SINT_TO_FLOAT, (B64,), (F32,), ()),
            (Operation.FLOAT_TO_UINT_TRUNC, (F64,), (B8,), ()),
            (Operation.FLOAT_CONVERT, (F32,), (F64,), ()),
            (Operation.INT_COMPARE, (B8, B8), (B1,), (10,)),
            (Operation.AGGREGATE_MAKE, (B8, F64, B8), (TRIPLE,), ()),
            (Operation.AGGREGATE_MAKE, (B32, B32, B32), (ARRAY3,), ()),
            (Operation.AGGREGATE_MAKE, (), (ARRAY0,), ()),
            (Operation.AGGREGATE_GET, (TRIPLE,), (F64,), (1,)),
            (Operation.AGGREGATE_GET, (ARRAY3,), (B32,), (2,)),
            (Operation.SUM_MAKE, (B32,), (SUM3,), (1,)),
            (Operation.SUM_TAG, (SUM3,), (B8,), ()),
            (Operation.SUM_TAG, (SUM1,), (B1,), ()),
            (Operation.SUM_GET, (SUM3,), (F64,), (2,)),
        ]
        bad = [
            (Operation.ADD_WRAP, (B32, B64), (B32,), ()),
            (Operation.ADD_WRAP, (B32, B32), (B32,), (1,)),
            (Operation.INT_TRUNCATE, (B8,), (B8,), ()),
            (Operation.INT_ZERO_EXTEND, (B32,), (B8,), ()),
            (Operation.ROTATE_RIGHT, (B64,), (B64,), (64,)),
            (Operation.FLOAT_ADD, (B32, B32), (B32,), ()),
            (Operation.FLOAT_COMPARE, (F32, F64), (B1,), (1,)),
            (Operation.FLOAT_COMPARE, (F32, F32), (B1,), (7,)),
            (Operation.UINT_TO_FLOAT, (B100,), (F64,), ()),
            (Operation.INT_COMPARE, (B32, B32), (B8,), (1,)),
            (Operation.INT_COMPARE, (B32, B32), (B1,), (0,)),
            (Operation.INT_COMPARE, (PAIR, PAIR), (B1,), (1,)),
            (Operation.ADD_WRAP, (OVERLONG, OVERLONG), (OVERLONG,), ()),
            (Operation.AGGREGATE_MAKE, (B8, B8, F64), (TRIPLE,), ()),
            (Operation.AGGREGATE_MAKE, (B32, B32), (ARRAY3,), ()),
            (Operation.AGGREGATE_GET, (ARRAY3,), (B32,), (3,)),
            (Operation.AGGREGATE_GET, (SUM3,), (B8,), (0,)),
            (Operation.SUM_MAKE, (B8,), (SUM3,), (1,)),
            (Operation.SUM_TAG, (SUM3,), (B1,), ()),
            (Operation.SUM_GET, (SUM3,), (B8,), (3,)),
        ]
        status, verdicts = _native_verdicts(self.native, good + bad)
        self.assertEqual(status, 0)
        for index, sample in enumerate(good):
            self.assertEqual(verdicts[index], PROVEN, sample)
            self.assertTrue(_bootstrap_accepts(*sample), sample)
        for index, sample in enumerate(bad, start=len(good)):
            self.assertEqual(verdicts[index], NOT_PROVEN, sample)
            self.assertFalse(_bootstrap_accepts(*sample), sample)
        self.assertNotIn(NOT_COVERED, verdicts.values())

    def test_committed_store_is_the_built_program(self):
        import xax_compiler
        from xax_selfhost_typing import STORE_PATH, build_typing_program

        building = xax_compiler._TYPING_BUILDING
        xax_compiler._TYPING_BUILDING = True
        try:
            reader, _function = build_typing_program()
        finally:
            xax_compiler._TYPING_BUILDING = building
        self.assertEqual(reader.data, STORE_PATH.read_bytes())

    def test_production_path_gives_identical_results(self):
        """With the native path on, stores verify and reject exactly as without it."""
        samples = _samples(200, seed=7)
        baseline = [_bootstrap_accepts(*sample) for sample in samples]
        with _typing_path(self.native):
            self.assertEqual([_accepts(*sample) for sample in samples], baseline)
        self.assertTrue(any(baseline) and not all(baseline))

if __name__ == "__main__":
    unittest.main()
