"""S4/S4b/S4c (ADR-132 to ADR-134): the XAX typing rules agree with the bootstrap verifier.

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

from xax_compiler import (
    EffectDomain, FloatFormat, Kind, Operation, ResourceFlags, SemanticObject, XaxError, array_type, bits_type, effect_type,
    float_type, opaque_type, resource_type, sum_type, tuple_type, x86_64_linux_exec_target,
)
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
IO, IO2, TIME = effect_type(EffectDomain.IO), effect_type(EffectDomain.IO, 2), effect_type(EffectDomain.TIME)
EFFECTS = (IO, IO2, TIME)
F = ResourceFlags
R1 = resource_type(5, 1, flags=F.ACQUIRABLE | F.RELEASABLE, transitions=(2, 3))
R2 = resource_type(5, 2, flags=F.RELEASABLE, transitions=(1,))
R3 = resource_type(5, 3, flags=F.ACQUIRABLE | F.RELEASABLE)
R_AFFINE = resource_type(5, 2, flags=F.AFFINE, transitions=(1,))
R_PART = resource_type(6, 1, flags=F.PARTITIONABLE | F.RELEASABLE)
R_OTHER = resource_type(7, 2, instance=3, flags=F.AFFINE | F.ACQUIRABLE, transitions=(1,))
RESOURCES = (R1, R2, R3, R_AFFINE, R_PART, R_OTHER)
OPAQUES = {kind: opaque_type(kind) for kind in range(1, 8)}
EFFECT_ZERO = SemanticObject.create(Kind.TYPE, bytes((3, 2, 0)))  # explicit instance 0: not canonical
OWNER_LONG = SemanticObject.create(Kind.TYPE, bytes((4, 1, 1, 4, 0, 0)))  # the stack owner's long form: not canonical
UNSORTED = SemanticObject.create(Kind.TYPE, bytes((4, 5, 1, 4, 0, 2, 3, 2)))  # transitions out of order
POOL = (
    B1, B8, B32, B64, B100, B200, F32, F64, PAIR, OVERLONG, TRIPLE, ARRAY3, ARRAY0, NESTED, SUM3, SUM1,
    *EFFECTS, *RESOURCES, *OPAQUES.values(), EFFECT_ZERO, OWNER_LONG, UNSORTED,
)


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
    return _outcome(None, operation, operand_types, result_types, attributes) is None


def _outcome(native, operation, operand_types, result_types, attributes):
    """None when the one-node store verifies, else the exact (code, rule, entity) of its rejection."""
    with _typing_path(native):
        graph = GraphBuilder()
        block = graph.block(*operand_types)
        results = block.op(operation, tuple(block.params), tuple(result_types), attributes=tuple(attributes))
        block.ret(*results)
        try:
            entry = graph.function(tuple(operand_types), tuple(result_types))
            program_store(entry, x86_64_linux_exec_target(), (*graph.objects.values(), *POOL))
        except XaxError as error:
            return error.diagnostic.code, error.diagnostic.rule, error.diagnostic.entity
        except ValueError as error:
            return "ValueError", str(error), None
        return None


# Rules raised by the per-node typing checks the XAX function replaces.
TYPING_RULES = frozenset({
    "GRAPH-OP-ARITY", "GRAPH-OP-TYPE", "INT-WIDTH-CONTRACT", "INT-TRUNCATE-NARROWS", "INT-ZERO-EXTEND-WIDENS", "INT-ROTATE-CONTRACT",
    "INT-ROTATE-TYPE", "INT-ROTATE-AMOUNT", "FLOAT-BINARY-CONTRACT", "FLOAT-BINARY-TYPE", "FLOAT-COMPARE-CONTRACT", "FLOAT-COMPARE-OPERANDS",
    "FLOAT-COMPARE-RESULT", "FLOAT-COMPARE-KIND", "INT-COMPARE-CONTRACT", "INT-COMPARE-LINK-EQUALITY", "INT-COMPARE-TYPE", "INT-COMPARE-KIND",
    "AGGREGATE-MAKE-CONTRACT", "AGGREGATE-MAKE-TYPE", "AGGREGATE-MAKE-ELEMENTS", "AGGREGATE-GET-CONTRACT", "AGGREGATE-GET-TYPE",
    "AGGREGATE-GET-INDEX", "SUM-MAKE-CONTRACT", "SUM-MAKE-VARIANT", "SUM-TAG-CONTRACT", "SUM-TAG-WIDTH", "SUM-GET-CONTRACT", "SUM-GET-VARIANT",
    "RESOURCE-EFFECT-OP-CONTRACT", "EFFECT-DOMAIN-INSTANCE-UNIQUE", "RESOURCE-ACQUIRE-ALLOWED", "RESOURCE-TERMINAL-ALLOWED",
    "RESOURCE-PARTITIONABLE", "RESOURCE-STATE-TRANSITION", "RESOURCE-PARTITION-CONTRACT", "META-OP-ARITY", "META-OPERAND-TYPE",
    "META-RESULT-TYPE", "META-VERIFY-RESULT", "META-TARGET-SUPPORT-RESULT", "META-TARGET-OPERATION",
})


def _samples(count: int, seed: int = 132):
    from xax_selfhost_typing import COVERED, FLOAT_COMPARE_KINDS, INT_COMPARE_KINDS, META_RULES, RESOURCE_COUNTS

    rng = random.Random(seed)
    operations = sorted(COVERED)
    samples = []
    for _ in range(count):
        operation = rng.choice(operations)
        if operation in (Operation.AGGREGATE_MAKE, Operation.AGGREGATE_GET, Operation.SUM_MAKE, Operation.SUM_TAG, Operation.SUM_GET):
            samples.append(_aggregate_sample(rng, operation))
            continue
        if operation in RESOURCE_COUNTS or operation == Operation.EFFECT_STEP:
            samples.append(_resource_sample(rng, operation))
            continue
        if operation in META_RULES:
            samples.append(_meta_sample(rng, operation))
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


def _resource_sample(rng, operation):
    noise = lambda: rng.choice(POOL)  # noqa: E731
    sometimes = lambda value: value if rng.random() < 0.88 else noise()  # noqa: E731
    attributes = () if rng.random() < 0.95 else (0,)
    if operation == Operation.EFFECT_STEP:
        chosen = rng.sample((*EFFECTS, EFFECT_ZERO), rng.randrange(1, 4))
        if rng.random() < 0.1:
            chosen.append(chosen[0])
        return operation, tuple(chosen), tuple(sometimes(item) for item in chosen), attributes
    effect = rng.choice((*EFFECTS, EFFECT_ZERO))
    source = rng.choice((*RESOURCES, OWNER_LONG, UNSORTED))
    after = sometimes(effect)
    if operation == Operation.RESOURCE_ACQUIRE:
        return operation, (effect,), (source, after), attributes
    if operation == Operation.RESOURCE_TRANSFER:
        return operation, (source, effect), (sometimes(source), after), attributes
    if operation == Operation.RESOURCE_TRANSITION:
        return operation, (source, effect), (rng.choice(RESOURCES), after), attributes
    if operation in (Operation.RESOURCE_RELEASE, Operation.RESOURCE_DISCARD):
        return operation, (source, effect), (after,), attributes
    if operation == Operation.RESOURCE_SPLIT:
        return operation, (source, effect), (sometimes(source), source, after), attributes
    return operation, (source, sometimes(source), effect), (source, after), attributes


def _meta_sample(rng, operation):
    from xax_selfhost_typing import META_RULES

    kinds, result_count, attribute_count, rule = META_RULES[operation]
    operands = tuple((rng.choice((B8, B32)) if kind is None else OPAQUES[kind]) if rng.random() < 0.9 else rng.choice(POOL) for kind in kinds)
    result = {"bits": rng.choice((B8, B32, B64)), "bit": B1}.get(rule) if isinstance(rule, str) else OPAQUES[rule]
    if rng.random() < 0.15:
        result = rng.choice(POOL)
    attributes = tuple(rng.choice((1, int(Operation.ADD_WRAP), 9999)) for _ in range(attribute_count))
    if rng.random() < 0.05:
        attributes = (*attributes, 0)
    return operation, operands, (result,) * result_count, attributes


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

        samples = _samples(2000)
        status, verdicts = _native_verdicts(self.native, samples)
        self.assertEqual(status, 0)
        proven = accepted = aggregates = proofs = 0
        for index, sample in enumerate(samples):
            baseline = _outcome(None, *sample)
            accepts = baseline is None
            if verdicts[index] == PROVEN:
                proven += 1
                aggregates += any(item in ELEMENTS or item in VARIANTS for item in (*sample[1], *sample[2]))
                proofs += any(item in EFFECTS or item in RESOURCES or item in OPAQUES.values() for item in (*sample[1], *sample[2]))
                # A proven node skips the bootstrap typing checks; any rejection must then come
                # from a later pass (linear flow, resource siblings) and be the same diagnostic.
                self.assertEqual(_outcome(self.native, *sample), baseline, sample)
                if not accepts:
                    self.assertNotIn(baseline[1], TYPING_RULES, sample)
            # Every accepted sample is proven unless it involves a nested aggregate.
            elif accepts and NESTED not in (*sample[1], *sample[2]):
                self.fail(f"accepted but not proven: {sample}")
            accepted += accepts
        self.assertGreater(proven, 150)
        self.assertGreater(aggregates, 30)
        self.assertGreater(proofs, 60)

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
            (Operation.RESOURCE_ACQUIRE, (IO,), (R1, IO), ()),
            (Operation.RESOURCE_TRANSITION, (R1, IO), (R2, IO), ()),
            (Operation.RESOURCE_TRANSFER, (R_OTHER, TIME), (R_OTHER, TIME), ()),
            (Operation.RESOURCE_RELEASE, (R2, IO2), (IO2,), ()),
            (Operation.RESOURCE_DISCARD, (R_AFFINE, IO), (IO,), ()),
            (Operation.EFFECT_STEP, (IO, TIME), (IO, TIME), ()),
            (Operation.META_FUNCTION_GRAPH, (OPAQUES[3],), (OPAQUES[5],), ()),
            (Operation.META_GRAPH_NODE_COUNT, (OPAQUES[5], B32), (B64,), ()),
            (Operation.META_TARGET_SUPPORTS, (OPAQUES[4],), (B1,), (int(Operation.ADD_WRAP),)),
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
            (Operation.RESOURCE_ACQUIRE, (IO,), (R2, IO), ()),
            (Operation.RESOURCE_ACQUIRE, (IO,), (R1, TIME), ()),
            (Operation.RESOURCE_TRANSITION, (R2, IO), (R3, IO), ()),
            (Operation.RESOURCE_TRANSITION, (R1, IO), (R_AFFINE, IO), ()),
            (Operation.RESOURCE_RELEASE, (R_AFFINE, IO), (IO,), ()),
            (Operation.RESOURCE_RELEASE, (UNSORTED, IO), (IO,), ()),
            (Operation.RESOURCE_DISCARD, (R1, EFFECT_ZERO), (EFFECT_ZERO,), ()),
            (Operation.EFFECT_STEP, (IO, TIME), (TIME, IO), ()),
            (Operation.META_FUNCTION_GRAPH, (OPAQUES[3],), (OPAQUES[6],), ()),
            (Operation.META_TARGET_SUPPORTS, (OPAQUES[4],), (B1,), (9999,)),
            (Operation.META_VERIFY_SEMANTICS, (OPAQUES[6],), (B8,), ()),
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
        """With the native path on, every store verifies or rejects with exactly the bootstrap's diagnostic."""
        samples = _samples(400, seed=7)
        baseline = [_outcome(None, *sample) for sample in samples]
        self.assertEqual([_outcome(self.native, *sample) for sample in samples], baseline)
        self.assertTrue(any(item is None for item in baseline) and not all(item is None for item in baseline))

if __name__ == "__main__":
    unittest.main()
