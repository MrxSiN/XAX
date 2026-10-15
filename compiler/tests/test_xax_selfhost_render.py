"""S15b.1 (ADR-288): the store verifier renders every object rejection exactly as the bootstrap's diagnostic.

Valid stores holding every structural kind (functions, recursion groups, call contracts, module and root lists, every
builtin target, packages, profiles, trust policies, signatures, requests, snapshots, provenance) are mutated: one
object's body bytes are changed, cut, extended, or deleted, or its references dropped, added, or swapped, and every
object referring to it is rebuilt.  After each XAX store verification the verifier's bank is decoded and compared,
diagnostic for diagnostic (code, entity, rule, expected, actual, with their Python types), with the host's rendering of
the same records (``xax_selfhost_render.expected_bank``).
"""

from __future__ import annotations

import os
import platform
import random
import sys
import unittest

import xax_compiler as X
from xax_compiler import Kind, SemanticObject, StoreReader, XaxError, object_with_refs, write_store

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
MUTABLE = (Kind.FUNCTION, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.TARGET, Kind.PACKAGE, Kind.BUILD,
           Kind.GRAPH_FRAGMENT)


def _rebuilt(objects: dict, root: bytes, old: bytes, new: SemanticObject):
    """``objects`` with ``old`` replaced by ``new`` and every object reaching it rebuilt; the new root."""
    mapping = {old: new}
    changed = True
    while changed:
        changed = False
        for cid, obj in list(objects.items()):
            if cid in mapping or not any(ref in mapping for ref in obj.references):
                continue
            references = [mapping[ref].cid if ref in mapping else ref for ref in obj.references]
            mapping[cid] = SemanticObject.create(obj.kind, obj.body, references)
            changed = True
    result = {cid: obj for cid, obj in objects.items() if cid not in mapping}
    for item in mapping.values():
        result[item.cid] = item
    return result, (mapping[root].cid if root in mapping else root)


def _mutated(rng: random.Random, objects: dict, root: bytes):
    candidates = [obj for obj in objects.values() if obj.kind in MUTABLE]
    target = rng.choice(candidates)
    body, references = bytearray(target.body), list(target.references)
    action = rng.randrange(12)
    starts = [k for k in range(len(body)) if k == 0 or body[k - 1] < 128]  # ULEB starts, if the body were all ULEBs
    if action >= 9 and starts:
        # A field rewritten (a small value, re-encoded) or two neighbouring fields swapped: reaches the canonical rules.
        k = rng.choice(starts)
        end = next((j + 1 for j in range(k, len(body)) if body[j] < 128), len(body))
        if action == 11:
            after = next((j + 1 for j in range(end, len(body)) if body[j] < 128), len(body))
            body[k:after] = body[end:after] + body[k:end]
        else:
            body[k:end] = X.uleb(rng.choice((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 32, 64, 128, 255, 1001)))
    elif action == 0 and body:
        body[rng.randrange(len(body))] = rng.choice((0, 1, 2, 3, 5, 127, 128, 255, rng.randrange(256)))
    elif action == 1 and body:
        del body[rng.randrange(len(body)):]
    elif action == 2:
        body.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 3))))
    elif action == 3 and body:
        del body[rng.randrange(len(body))]
    elif action == 4 and body:
        body.insert(rng.randrange(len(body) + 1), rng.choice((0, 1, 128, 255)))
    elif action == 5 and references:
        del references[rng.randrange(len(references))]
    elif action == 6:
        references.insert(rng.randrange(len(references) + 1), rng.choice(list(objects)))
    elif action == 7 and references:
        references[rng.randrange(len(references))] = rng.choice(list(objects))
    elif action == 8 and references:
        references[rng.randrange(len(references))] = bytes(rng.randrange(256) for _ in range(32))  # missing
    else:
        body.append(0)
    replacement = SemanticObject.create(target.kind, bytes(body), references)
    return _rebuilt(objects, root, target.cid, replacement)


def _crafted_targets():
    """Targets whose fields are consistent except for one profile rule (single mutations rarely reach these)."""
    u = X.uleb
    identity = b"crafted"

    def head(profile, arch, abi, image_format, word=64, pointer=64):
        return u(len(identity)) + identity + b"".join(u(value) for value in (profile, arch, abi, image_format, word, pointer))

    aarch64 = u(16) + u(0) + u(8) + bytes(range(8)) + u(0) + u(2) + bytes((9, 10))  # stack, shadow, AAPCS64 registers
    empty = u(0) + u(0)  # operations, terminators

    def handler(kind, stack=4096):
        return b"".join(u(value) for value in (kind, 1, 0, 0, 1, 1, 1)) + u(1) + u(1) + u(stack) + u(1)

    def concurrency(*handlers):
        return u(0) + u(0) + u(0) + u(len(handlers)) + b"".join(handlers)

    bodies = [head(1, 3, 4, X.ANDROID_ELF_FORMAT) + aarch64 + empty,
              head(4, 3, X.AARCH64_LINUX_ABI, X.AARCH64_LINUX_ELF_EXEC_FORMAT) + aarch64 + empty + u(0),
              head(4, 3, 3, 1) + aarch64 + empty + u(0),
              head(X.BOARD_PROFILE, 3, 3, 1) + aarch64 + empty + concurrency() + u(0),
              head(2, 3, 3, 1) + aarch64 + empty + concurrency(handler(2), handler(1)),
              head(2, 3, 3, 1) + aarch64 + empty + concurrency(handler(1, 0))]
    accelerator = bytearray(X.simt32_accelerator_target().body)

    def skip_uleb(at):
        while accelerator[at] >= 128:
            at += 1
        return at + 1

    at = 1 + accelerator[0]
    for _field in range(6):
        at = skip_uleb(at)
    for _list in range(2):
        count, at = accelerator[at], at + 1
        for _item in range(count):
            at = skip_uleb(at)
    lane = bytes(accelerator)
    bodies.append(lane[:at] + u(0) + lane[at + 1:])  # lane width 0 (``TARGET-ACCELERATOR-TOPOLOGY``)
    return [SemanticObject.create(Kind.TARGET, body, []) for body in bodies]


def _bases(rng: random.Random):
    """``(objects, root)`` stores: groups and targets, every builtin target, call contracts, build closures."""
    from test_xax_selfhost_build import LEAF_FORMS, _closure_store, _leaf, _package
    from test_xax_selfhost_groups import TARGETS, _store

    bases = []
    for _ in range(3):
        reader = _store(rng, None)
        if reader is not None:
            bases.append(({obj.cid: obj for obj in reader.objects()}, reader.root_cid))
    targets = [maker() for maker in TARGETS] + [X.simt32_accelerator_target(), X.aarch64_baremetal_general_target(), X.oi07_coherent_dma_target(),
                                                X.x86_64_windows_general_target(), X.wasm32_target(), X.jvm_classfile_target()]
    targets = list({item.cid: item for item in targets}.values())
    b8, b32 = X.bits_type(8), X.bits_type(32)
    contracts = [X.call_contract((b8, b32), (b32,), may_return=True, may_trap=False), X.call_contract((), (), may_return=False, may_trap=True)]
    module = object_with_refs(Kind.MODULE, [*targets, *contracts, b8, b32])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    bases.append(({item.cid: item for item in (*targets, *contracts, b8, b32, module, root)}, root.cid))
    for target in [*targets, *_crafted_targets()]:  # one target each: its mutations reach the deeper target rules
        bases.append(({target.cid: target}, target.cid))
    for mutation in ("group_byte", "call_type", "member_byte", "member_index"):
        reader = _store(rng, mutation)
        if reader is not None:
            bases.append(({obj.cid: obj for obj in reader.objects()}, reader.root_cid))
    for broken in (None, None, "grant", "binding", "entry", "closure", "unsigned", "provenance", "extra"):
        proof, objects, _parts = _closure_store(rng, broken)
        reached, pending = {}, [proof.cid]
        by_cid = {item.cid: item for item in objects}
        while pending:
            cid = pending.pop()
            if cid not in reached and cid in by_cid:
                reached[cid] = by_cid[cid]
                pending.extend(by_cid[cid].references)
        bases.append((reached, proof.cid))
    for _ in range(2):
        built, objects = _package(rng)
        bases.append(({item.cid: item for item in objects}, built.cid))
    for form in LEAF_FORMS:
        leaf = _leaf(rng, form, signed=built)
        objects = leaf if isinstance(leaf, (list, tuple)) else [leaf]
        root = objects[-1]
        reached, pending = {}, [root.cid]
        by_cid = {item.cid: item for item in (*objects, built, *_package_items(built, bases))}
        while pending:
            cid = pending.pop()
            if cid not in reached and cid in by_cid:
                reached[cid] = by_cid[cid]
                pending.extend(by_cid[cid].references)
        bases.append((reached, root.cid))
    return bases


def _package_items(built, bases):
    for objects, root in bases:
        if root == built.cid:
            return objects.values()
    return ()


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the store verifier runs natively on Linux x86-64")
class RenderTests(unittest.TestCase):
    def test_mutated_stores_render_exactly(self):
        import xax_selfhost_render as R
        import xax_selfhost_verify as V

        original = V.NativeStoreVerifier.verify_with_rejections
        state = {"listed": None}

        def checked(verifier, words, count, groups=()):
            result, rejections = original(verifier, words, count, groups)
            if result is not None and state["listed"] is not None and len(state["listed"]) == count:
                R.compare(state["listed"], verifier._out, rejections)
            return result, rejections

        verify = X._xax_verify_store

        def remember(reader, objects):
            state["listed"] = list(objects.values())
            try:
                return verify(reader, objects)
            finally:
                state["listed"] = None

        before = dict(R.STATS)
        V.NativeStoreVerifier.verify_with_rejections, X._xax_verify_store = checked, remember
        try:
            rng = random.Random(287)
            bases = _bases(rng)
            for trial in range(int(os.environ.get("XAX_RENDER_TRIALS", "6000"))):
                objects, root = bases[trial % len(bases)]
                for _round in range(0 if trial < len(bases) else 1 + rng.randrange(3)):  # every base once as it is
                    objects, root = _mutated(rng, objects, root)
                try:
                    reader = StoreReader(write_store(root, list(objects.values())))
                except (XaxError, ValueError, KeyError):
                    continue
                X._PARSED_GRAPHS.clear()
                try:
                    X.verify_store(reader)
                except (XaxError, IndexError, KeyError, TypeError, ValueError):
                    pass  # not XaxError: the host's eager rendering (or decoding) of a record the bootstrap never reaches
        finally:
            V.NativeStoreVerifier.verify_with_rejections, X._xax_verify_store = original, verify
        compared = {key: R.STATS[key] - before[key] for key in R.STATS}
        self.assertEqual((compared["diff"], compared["unrendered"]), (0, 0), compared)
        self.assertGreater(compared["same"], 500)


if __name__ == "__main__":
    unittest.main()
