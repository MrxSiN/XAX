"""S6b (ADR-143): XAX decides type and constant objects exactly when the bootstrap accepts them.

Random type objects of every form (bits, pointer, effect, resource, opaque,
opaque identity, float, tuple, array, sum, link) and constants (bits, float,
null link), plus random body mutations of them, are given to the XAX typing
program's object verdicts.  A verdict must never hold for an object that
``_verify_type`` or ``_decode_constant`` rejects, and it must hold for every
valid generated object of the decoded forms.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

from xax_compiler import (
    EffectDomain, FloatFormat, Kind, OpaqueKind, Permission, ResourceFlags, SemanticObject, XaxError, array_type, bits_type, constant,
    effect_type, float_constant, float_type, link_type, null_link, opaque_identity_type, opaque_type, pointer_type, resource_type, sum_type,
    tuple_type,
)

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _scalar(rng: random.Random):
    choice = rng.randrange(5)
    if choice == 0:
        return bits_type(rng.choice((1, 7, 8, 13, 32, 64, 200, 4095)))
    if choice == 1:
        return float_type(rng.choice((FloatFormat.BINARY32, FloatFormat.BINARY64)))
    if choice == 2:
        return opaque_type(rng.choice(list(OpaqueKind)))
    if choice == 3:
        return opaque_identity_type(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40))))
    return link_type()


def _proof(rng: random.Random):
    if rng.random() < 0.5:
        return effect_type(rng.choice(list(EffectDomain)), rng.choice((0, 0, 3)))
    flags = rng.choice((ResourceFlags.LINEAR, ResourceFlags.AFFINE, ResourceFlags.RELEASABLE | ResourceFlags.ACQUIRABLE))
    return resource_type(rng.randrange(2, 9), 1, flags=flags, instance=rng.randrange(3), transitions=tuple(sorted(rng.sample((2, 3, 5), rng.randrange(3)))))


def _value(rng: random.Random, depth: int = 0):
    """A random value type with its dependencies: ``(object, dependencies)``."""
    choice = rng.randrange(8 if depth < 2 else 1)
    if choice <= 3:
        item = _scalar(rng)
        return item, [item]
    if choice == 4:
        element, dependencies = _value(rng, depth + 1)
        made = pointer_type(element, rng.choice((Permission.READ, Permission.WRITE, Permission.READ_WRITE)), rng.choice((1, 4, 8)), space=rng.choice((1, 2)))
        return made, [*dependencies, made]
    if choice == 5:
        element, dependencies = _value(rng, depth + 1)
        made = array_type(element, rng.randrange(0, 9))
        return made, [*dependencies, made]
    parts, dependencies = [], []
    for _ in range(rng.randrange(1, 4)):
        part, more = _value(rng, depth + 1)
        parts.append(part)
        dependencies += more
    made = tuple_type(parts) if choice == 6 else sum_type(parts)
    return made, [*dependencies, made]


def _sample(rng: random.Random):
    """``(object, every object it needs)``, possibly mutated."""
    roll = rng.random()
    if roll < 0.15:
        made = _proof(rng)
        objects = [made]
    elif roll < 0.35:
        kind = rng.randrange(3)
        if kind == 0:
            width = rng.choice((1, 5, 8, 16, 33, 64))
            value_type = bits_type(width)
            made = constant(value_type, rng.getrandbits(width))
        elif kind == 1:
            value_type = float_type(rng.choice((FloatFormat.BINARY32, FloatFormat.BINARY64)))
            made = float_constant(value_type, rng.choice((0.0, -1.5, 3.25e10, float("inf"))))
        else:
            value_type, made = link_type(), null_link()
        objects = [value_type, made]
    else:
        made, objects = _value(rng)
    if rng.random() < 0.45:
        body = bytearray(made.body)
        if body and rng.random() < 0.7:
            position = rng.randrange(len(body))
            body[position] = rng.choice((0, 1, 2, 3, 11, 127, 128, 255, body[position] ^ (1 << rng.randrange(8))))
        elif rng.random() < 0.5:
            body.append(rng.randrange(256))
        elif body:
            del body[-1]
        references = list(made.references)
        if references and rng.random() < 0.15:
            references = references[:-1]
        mutated = SemanticObject.create(made.kind, bytes(body), references)
        objects = [item for item in objects if item.cid != made.cid] + [mutated]
        made = mutated
    return made, objects


def _bootstrap_accepts(obj, table) -> bool:
    import xax_compiler

    saved = set(xax_compiler._XAX_VALID_OBJECTS)
    xax_compiler._XAX_VALID_OBJECTS.clear()
    try:
        if obj.kind == Kind.TYPE:
            xax_compiler._verify_type(obj, table.__getitem__)
        else:
            xax_compiler._decode_constant(obj, table.__getitem__)
        return True
    except (XaxError, KeyError):
        return False
    finally:
        xax_compiler._XAX_VALID_OBJECTS.update(saved)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostObjectVerdictTests(unittest.TestCase):
    def test_object_verdicts_agree_with_the_bootstrap(self):
        from xax_selfhost_typing import NativeTyping, marshal, type_info_from

        native = NativeTyping()
        rng = random.Random(143)
        accepted = proven = rejected = 0
        for _batch in range(24):
            samples = [_sample(rng) for _ in range(25)]
            table = {item.cid: item for _made, objects in samples for item in objects}
            words, listed = marshal([], lambda *_args: None, type_info_from(table.__getitem__), objects=[made.cid for made, _objects in samples])
            verdicts = native.object_verdicts(words, listed)
            for made, _objects in samples:
                valid = _bootstrap_accepts(made, table)
                with self.subTest(body=made.body.hex(), kind=made.kind.name):
                    if made.cid in verdicts:
                        self.assertTrue(valid, "XAX proved an object the bootstrap rejects")
                if valid:
                    accepted += 1
                    proven += made.cid in verdicts
                else:
                    rejected += 1
        self.assertGreater(rejected, 60)
        self.assertGreater(accepted, 250)
        self.assertEqual(proven, accepted)


if __name__ == "__main__":
    unittest.main()
