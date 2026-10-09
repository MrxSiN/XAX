"""S8 (ADR-251): the XAX store verifier decides every target object, valid or not, with the bootstrap's diagnostic.

Every built-in target is mutated (a byte set, removed, inserted, swapped, or the body cut short); each mutated
target is either proven or rejected by XAX itself, and the outcome equals the Python bootstrap's alone.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_compiler as X
from xax_compiler import Kind, SemanticObject, StoreReader, XaxError, object_with_refs, write_store

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
TARGETS = tuple(maker for name, maker in sorted(vars(X).items()) if name.endswith("_target") and callable(maker) and not name.startswith("_")
                and name not in ("call_target", "decode_native_target"))


def _mutate(rng: random.Random, body: bytes) -> bytes:
    body = bytearray(body)
    choice = rng.randrange(6)
    if choice == 0:
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 2, 3, 4, 5, 7, 9, 12, 32, 127, 128, 255, body[position] ^ 1, body[position] + 1 & 255, body[position] - 1 & 255))
    elif choice == 1 and len(body) > 1:
        del body[rng.randrange(len(body))]
    elif choice == 2:
        body.insert(rng.randrange(len(body) + 1), rng.choice((0, 1, 2, 0x80, 0xFF)))
    elif choice == 3 and len(body) > 1:
        position = rng.randrange(len(body) - 1)
        body[position], body[position + 1] = body[position + 1], body[position]
    elif choice == 4:
        del body[rng.randrange(len(body)):]
    else:
        body += bytes((rng.randrange(256),))
    return bytes(body)


def _outcomes(target):
    module = object_with_refs(Kind.MODULE, [target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    reader = StoreReader(write_store(root.cid, [target, module, root]))
    saved = X._xax_verify_store
    X._xax_verify_store = lambda _reader, _objects: (False, {})
    try:
        X.verify_store(reader)
        bootstrap = ("accept",)
    except XaxError as error:
        d = error.diagnostic
        bootstrap = ("reject", d.code, d.rule, d.entity, repr(d.expected), repr(d.actual))
    finally:
        X._xax_verify_store = saved
    _store_ok, proven = X._xax_verify_store(reader, {item.cid: item for item in reader.objects()})
    return bootstrap, proven.get(target.cid)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class XaxTargetDecisionTests(unittest.TestCase):
    def test_every_mutated_target_is_decided_by_xax(self):
        rng = random.Random(248)
        rules, decided = set(), 0
        for maker in TARGETS:
            original = maker()
            for trial in range(24):
                body = _mutate(rng, original.body) if trial else original.body
                if not body:
                    continue
                target = SemanticObject.create(Kind.TARGET, body, [])
                bootstrap, verdict = _outcomes(target)
                with self.subTest(target=maker.__name__, trial=trial, body=body.hex()):
                    if bootstrap[0] == "accept":
                        self.assertIs(verdict, True)
                        continue
                    rules.add(bootstrap[2])
                    self.assertIsInstance(verdict, X._XaxRejection)
                    self.assertEqual((verdict[0], verdict[1], repr(verdict[2]), repr(verdict[3])), (bootstrap[1], bootstrap[2], *bootstrap[4:]))
                    decided += 1
        self.assertGreater(decided, 100)
        self.assertTrue({"TARGET-PLATFORM-ENUM", "TARGET-ACCELERATOR-ENUM", "SER-ULEB-TERMINATED"} <= rules, rules)


if __name__ == "__main__":
    unittest.main()
