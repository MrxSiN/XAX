"""S6b.4 (ADR-149): XAX decides packages and build objects exactly when the bootstrap accepts.

Random packages (one to three modules, exact and logical dependencies, build
entries, feature and configuration schemas, capabilities), build profiles
(modes, levels, grants), trust policies, signatures, and optimization
policies are stored on their own (the object as the store root) and, valid,
as one package store.  Their bodies are also mutated (bytes changed, swapped,
truncated, or appended).  Verification with and without the XAX store
verifier's verdicts must give the same outcome and exact diagnostic, no
verdict may hold for an object the bootstrap rejects, and every package and
leaf build object of a valid store must be proven.

Requests, snapshots, and provenance (S6b.4b) are generated with valid and
broken cross-object facts (entries, binding names and types, dependency
closures by exact root and logical identity, grants, signature coverage,
provenance closure) and also mutated.
"""

from __future__ import annotations

import platform
import random
import sys
import unittest

import xax_compiler as X
from xax_build import (
    ArtifactKind,
    BuildCapability,
    BuildCapabilityKind,
    BuildMode,
    CapabilityGrant,
    DependencyRequirement,
    TypedBinding,
    build_profile,
    build_request,
    optimization_policy,
    package,
    provenance,
    signature,
    snapshot,
    trust_policy,
)
from xax_compiler import x86_64_linux_exec_target, Block, Kind, Node, Operation, SemanticObject, StoreReader, Terminator, ValueRef, XaxError, bits_type, constant, function, graph_fragment, object_with_refs, write_store

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
LEAF_FORMS = (1, 4, 6, 7)  # profile, trust policy, signature, optimization policy


def _name(rng: random.Random) -> bytes:
    return bytes(rng.choice(b"abcxyz-./\x00\xff") for _ in range(rng.randrange(1, 5)))


def _distinct(rng: random.Random, count: int) -> list[bytes]:
    names: set[bytes] = set()
    while len(names) < count:
        names.add(_name(rng))
    return list(names)


def _module(rng: random.Random, seed: int):
    width = rng.choice((8, 16, 32, 64))
    bits = bits_type(width)
    value = constant(bits, seed % (1 << width))
    graph = graph_fragment((Block((), (Node(Operation.CONSTANT, (), (bits,), entity=value),), Terminator.return_((ValueRef.node_result(0, 0),))),))
    entry = function(graph, (), (bits,))
    module = object_with_refs(Kind.MODULE, (bits, value, entry))
    return module, entry, bits, (bits, value, graph, entry, module)


def _capabilities(rng: random.Random) -> list[BuildCapability]:
    picked = {(rng.randrange(1, 10), _name(rng) if rng.random() < 0.7 else b"") for _ in range(rng.randrange(4))}
    return [BuildCapability(BuildCapabilityKind(kind), scope) for kind, scope in picked]


def _package(rng: random.Random, dependencies_from=()):
    objects, modules, entries, types = [], [], [], []
    for index in range(rng.randrange(1, 4)):
        module, entry, bits, items = _module(rng, rng.randrange(1 << 30) + index)
        objects += items
        modules.append(module)
        entries.append(entry)
        types.append(bits)
    names = _distinct(rng, 3 * len(entries))
    dependencies = [DependencyRequirement.exact(item) for item in dependencies_from if rng.random() < 0.7]
    dependencies += [DependencyRequirement.logical(name) for name in _distinct(rng, rng.randrange(3))]
    built = package(
        _name(rng),
        modules,
        dependencies=dependencies,
        build_entries=[(names[i], entry) for i, entry in enumerate(entries) if rng.random() < 0.8],
        feature_types=[(names[len(entries) + i], bits) for i, bits in enumerate(types) if rng.random() < 0.5],
        configuration_types=[(names[2 * len(entries) + i], bits) for i, bits in enumerate(types) if rng.random() < 0.5],
        capabilities=_capabilities(rng),
    )
    return built, [*objects, *dependencies_from, built]


def _leaf(rng: random.Random, form: int, signed=None):
    if form == 1:
        grants = {CapabilityGrant(_name(rng), capability) for capability in _capabilities(rng)}
        return build_profile(rng.choice(list(BuildMode)), optimization=rng.randrange(300), verification=rng.randrange(3), grants=grants)
    if form == 4:
        required = rng.random() < 0.5
        return trust_policy(
            require_package_signatures=required, require_provenance_signature=rng.random() < 0.3,
            accepted_algorithms=_distinct(rng, rng.randrange(1 if required else 0, 3)), accepted_signers=_distinct(rng, rng.randrange(1 if required else 0, 3)),
        )
    if form == 6:
        return signature(signed, _name(rng), _name(rng), _name(rng))
    return optimization_policy(pass_iterations=rng.randrange(1, 9), search_steps=rng.randrange(1000), deterministic=rng.random() < 0.5)


def _mutate(rng: random.Random, obj: SemanticObject) -> SemanticObject:
    body = bytearray(obj.body)
    choice = rng.randrange(5)
    if choice == 0 and body:
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 2, 3, 7, 9, 10, 127, 128, 255, body[position] ^ 1, body[position] + 1 & 255))
    elif choice == 1 and len(body) > 1:
        position = rng.randrange(len(body) - 1)
        body[position], body[position + 1] = body[position + 1], body[position]
    elif choice == 2 and body:
        del body[rng.randrange(len(body)):]
    elif choice == 3:
        body += bytes((rng.randrange(256),))
    else:
        body.insert(rng.randrange(len(body) + 1), rng.choice((0, 1, 0x80)))
    return SemanticObject.create(obj.kind, bytes(body), list(obj.references))


def _store(root: SemanticObject, objects) -> StoreReader | None:
    by_cid = {item.cid: item for item in (*objects, root)}
    stored, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid in stored or cid not in by_cid:
            continue
        stored[cid] = by_cid[cid]
        pending.extend(stored[cid].references)
    try:
        return StoreReader(write_store(root.cid, list(stored.values())))
    except (XaxError, ValueError):
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
        d = error.diagnostic
        return ("reject", d.code, d.rule, d.entity, repr(d.expected), repr(d.actual))
    except ValueError as error:  # constructor-level rules (empty identities) raise ValueError in the bootstrap
        return ("value-error", str(error))
    finally:
        X._xax_verify_store = saved


def _decided(item: SemanticObject) -> bool:
    return item.kind == Kind.PACKAGE or (item.kind == Kind.BUILD and item.body[:1] and item.body[0] in LEAF_FORMS)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostBuildObjectTests(unittest.TestCase):
    def test_packages_and_leaf_build_forms_agree_with_the_bootstrap(self):
        rng = random.Random(149)
        valid = rejected = 0
        proven_count = decided_count = 0
        rules = set()
        for trial in range(260):
            dependency, dependency_objects = _package(rng)
            app, objects = _package(rng, (dependency,) if rng.random() < 0.6 else ())
            objects = [*dependency_objects, *objects]
            form = LEAF_FORMS[trial % len(LEAF_FORMS)]
            leaf = _leaf(rng, form, signed=app)
            subject = rng.choice((app, leaf))
            mutated = trial % 3 != 0
            if mutated:
                subject = _mutate(rng, subject)
            reader = _store(subject, [*objects, leaf])
            if reader is None:
                continue
            bootstrap = _verify(reader, False)
            with self.subTest(trial=trial, form=form, mutated=mutated):
                self.assertEqual(_verify(reader, True), bootstrap)
                stored = {item.cid: item for item in reader.objects()}
                _store_ok, proven = X._xax_verify_store(reader, stored)
                if bootstrap[0] != "accept":
                    rejected += 1
                    rules.add(bootstrap[2] if bootstrap[0] == "reject" else "ValueError")
                    self.assertNotIn(subject.cid, proven, "XAX proved the object the bootstrap rejects")
                    continue
                valid += 1
                for item in stored.values():
                    if _decided(item):
                        decided_count += 1
                        proven_count += item.cid in proven
        self.assertGreater(valid, 80)
        self.assertGreater(rejected, 80)
        self.assertEqual(proven_count, decided_count)
        self.assertGreaterEqual(len(rules), 8, rules)


def _closure_store(rng: random.Random, broken: str | None):
    """A provenance-rooted store: request, snapshot, and provenance over two or three packages."""
    width = rng.choice((8, 32))
    bits, other = bits_type(width), bits_type(64 if width == 8 else 16)
    dep_module, _dep_entry, _bits, dep_items = _module(rng, rng.randrange(1 << 20))
    dep_caps = _capabilities(rng)
    dependency = package(b"dep" if broken != "ambiguous" else b"twin", (dep_module,), capabilities=dep_caps)
    module, entry, _b, items = _module(rng, rng.randrange(1 << 20))
    twin = None
    if broken == "ambiguous":
        twin_module, _e, _b2, twin_items = _module(rng, rng.randrange(1 << 20) + 7)
        twin = package(b"twin", (twin_module,))
        items = [*items, *twin_items]
    requirement = DependencyRequirement.exact(dependency) if rng.random() < 0.5 and broken != "ambiguous" else DependencyRequirement.logical(b"dep" if broken != "ambiguous" else b"twin")
    app_caps = _capabilities(rng)
    app = package(b"app", (module,), dependencies=(requirement,), build_entries=((b"main", entry),),
                  feature_types=((b"f", bits),), configuration_types=((b"c", other),), capabilities=app_caps)
    declared = [(b"app", cap) for cap in app_caps] + [(dependency_identity, cap) for dependency_identity in (b"dep",) for cap in dep_caps if broken != "ambiguous"]
    grants = {CapabilityGrant(identity, cap) for identity, cap in rng.sample(declared, min(len(declared), rng.randrange(3)))}
    if broken == "grant":
        grants.add(CapabilityGrant(b"app", BuildCapability(BuildCapabilityKind.PUBLISH, b"undeclared-" + _name(rng))))
    profile = build_profile(grants=grants)
    target = x86_64_linux_exec_target()
    feature_value = constant(bits if broken != "binding" else other, 1)
    config_value = constant(other, 2)
    request = build_request(app, b"main" if broken != "entry" else b"missing", target, profile,
                            features=(TypedBinding(b"f", feature_value),), configuration=(TypedBinding(b"c", config_value),),
                            requested_artifacts=rng.sample(list(ArtifactKind), rng.randrange(1, 3)))
    packages = [app, dependency] + ([twin] if twin is not None else [])
    if broken == "closure":
        packages = [app]
    if broken == "extra":  # listed but unreachable from the request's package
        extra_module, _e, _b3, extra_items = _module(rng, rng.randrange(1 << 20) + 11)
        packages.append(package(b"extra", (extra_module,)))
        items = [*items, *extra_items, packages[-1]]
    required = rng.random() < 0.4
    policy = trust_policy(require_package_signatures=required, accepted_algorithms=(b"ed25519",), accepted_signers=(b"me",))
    signed = packages if (required and broken != "unsigned") else rng.sample(packages, rng.randrange(len(packages) + 1))
    if broken == "unsigned":
        signed = packages[:1]
        policy = trust_policy(require_package_signatures=True, accepted_algorithms=(b"ed25519",), accepted_signers=(b"me",))
    signatures = [signature(item, b"ed25519", b"me", _name(rng)) for item in signed]
    if broken == "foreign_signature":
        signatures.append(signature(profile, b"ed25519", b"me", b"x"))
    digests = sorted({bytes(rng.randrange(256) for _ in range(32)) for _ in range(rng.randrange(3))})
    snap = snapshot(request, b"resolver", policy, packages, signatures=signatures, external_digests=digests)
    other_request = request if broken != "provenance" else build_request(app, b"main", target, build_profile(), features=(TypedBinding(b"f", feature_value),), configuration=(TypedBinding(b"c", config_value),))
    proof = provenance(snap, other_request, target, profile, bytes(32), bytes(range(32)), bytes(32), _name(rng))
    objects = [*dep_items, dependency, *items, app, bits, other, feature_value, config_value, profile, target, request, policy, *signatures, snap, proof, other_request]
    if twin is not None:
        objects.append(twin)
    return proof, objects, (request, snap, proof)


CLOSURE_BREAKS = (None, None, "grant", "binding", "entry", "closure", "ambiguous", "unsigned", "foreign_signature", "provenance", "extra")


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostClosureTests(unittest.TestCase):
    def test_requests_snapshots_and_provenance_agree_with_the_bootstrap(self):
        rng = random.Random(1492)
        valid = rejected = 0
        decided = {2: [0, 0], 3: [0, 0], 5: [0, 0]}
        rules = set()
        for trial in range(176):
            broken = CLOSURE_BREAKS[trial % len(CLOSURE_BREAKS)]
            try:
                root, objects, closure = _closure_store(rng, broken)
            except (ValueError, XaxError):
                continue
            mutated = trial % 4 == 3
            if mutated:
                root = _mutate(rng, rng.choice(closure))
            reader = _store(root, objects)
            if reader is None:
                continue
            bootstrap = _verify(reader, False)
            with self.subTest(trial=trial, broken=broken, mutated=mutated):
                self.assertEqual(_verify(reader, True), bootstrap)
                stored = {item.cid: item for item in reader.objects()}
                _store_ok, proven = X._xax_verify_store(reader, stored)
                # A verdict is a claim about one object: the bootstrap must accept that object on its own.
                for cid in proven:
                    if stored[cid].kind == Kind.BUILD:
                        X.verify_object(stored[cid], reader.get)
                if bootstrap[0] != "accept":
                    rejected += 1
                    rules.add(bootstrap[2] if bootstrap[0] == "reject" else "ValueError")
                    continue
                valid += 1
                for item in stored.values():
                    if item.kind == Kind.BUILD and item.body[0] in decided:
                        decided[item.body[0]][0] += item.cid in proven
                        decided[item.body[0]][1] += 1
        self.assertGreater(valid, 25)
        self.assertGreater(rejected, 60)
        for form, (proven_count, total) in decided.items():
            self.assertGreater(total, 0, form)
            self.assertEqual(proven_count, total, form)
        self.assertTrue({"SNAPSHOT-EXACT-CLOSURE", "BUILD-GRANT-DECLARED", "BUILD-BINDING-TYPE", "BUILD-ENTRY-DECLARED", "TRUST-SNAPSHOT-COVERAGE",
                         "TRUST-SIGNATURE-PACKAGE", "PROVENANCE-EXACT-CLOSURE", "RESOLVE-LOGICAL-IDENTITY", "RESOLVE-EXACT-ROOT"} <= rules, rules)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostTargetProfileTests(unittest.TestCase):
    def test_accelerator_platform_and_board_targets_agree_with_the_bootstrap(self):
        """S6b.4c: every built-in profile 3/4/5 target, and 40 mutations of each, decided exactly when the bootstrap accepts."""
        from xax_board import qemu_virt_board

        makers = [maker for name, maker in sorted(vars(X).items()) if name.endswith("_target") and callable(maker) and not name.startswith("_")
                  and name not in ("call_target", "decode_native_target")] + [qemu_virt_board]
        rng = random.Random(14903)
        profiles, accepted, rejected = set(), 0, 0
        for maker in makers:
            original = maker()
            length = original.body[0]
            if len(original.body) <= 1 + length or original.body[1 + length] not in (3, 4, 5):
                continue
            profiles.add(original.body[1 + length])
            for trial in range(41):
                target = original if trial == 0 else _mutate(rng, original)
                module = object_with_refs(Kind.MODULE, [target])
                root = object_with_refs(Kind.PROGRAM_ROOT, [module])
                try:
                    reader = StoreReader(write_store(root.cid, [target, module, root]))
                except XaxError:
                    continue
                try:
                    X.decode_native_target(target, allow_carrier=True)
                    valid = True
                except XaxError:
                    valid = False
                with self.subTest(target=maker.__name__, trial=trial):
                    bootstrap = _verify(reader, False)
                    self.assertEqual(_verify(reader, True), bootstrap)
                    _store_ok, proven = X._xax_verify_store(reader, {item.cid: item for item in reader.objects()})
                    if not valid:
                        rejected += 1
                        verdict = proven.get(target.cid)
                        if isinstance(verdict, X._XaxRejection):
                            # S8c.23 (ADR-241): XAX rejected the target itself, with the bootstrap's diagnostic.
                            self.assertEqual((verdict[0], verdict[1], repr(verdict[2]), repr(verdict[3])), (bootstrap[1], bootstrap[2], *bootstrap[4:]))
                        else:
                            self.assertNotIn(target.cid, proven)
                    else:
                        accepted += 1
                        self.assertIn(target.cid, proven)
        self.assertEqual(profiles, {3, 4, 5})
        self.assertGreater(accepted, 10)
        self.assertGreater(rejected, 100)


def _glue_store(rng: random.Random, mutation: str | None):
    """A function whose graph has a trap block (a random, sometimes non-canonical payload) and a constant; mutated
    graph bodies or reference lists."""
    from xax_graph_builder import GraphBuilder

    from xax_compiler import IntCompare

    b1, b32 = bits_type(1), bits_type(32)
    graph = GraphBuilder()
    graph.track(b1, b32)
    entry = graph.block(b32)
    (n,) = entry.params
    trap_block, done = graph.block(), graph.block()
    entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(b32, rng.randrange(9))), b1, attributes=(IntCompare.ULT,)), trap_block, (), done, ())
    payload = rng.choice((b"", b"\x01", b"\x02", b"\x01\xaa", b"\x00\x07", b"\x81\x01", b"\xff\xff\x03", b"\x80\x00", b"\x00", b"\x80\x80\x80",
                          b"\xff\xff\x07", b"\x80", bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4)))))
    # The builder only takes canonical payloads: build with a same-length placeholder, then patch the body.
    placeholder = (b"\x01" + b"\xa5" * (len(payload) - 1)) if payload else b""
    trap_block.trap(placeholder)
    done.ret(done.op1(Operation.ADD_WRAP, (n, done.const(b32, 1)), b32))
    built = graph.function((b32,), (b32,))
    objects = list(graph.objects.values())
    fragment = next(item for item in objects if item.kind == Kind.GRAPH_FRAGMENT)
    if payload != placeholder:
        at = fragment.body.rindex(placeholder)
        fragment = SemanticObject.create(Kind.GRAPH_FRAGMENT, fragment.body[:at] + payload + fragment.body[at + len(payload):], list(fragment.references))
        mutation = mutation or "payload"
    if mutation == "graph_byte":
        body = bytearray(fragment.body)
        position = rng.randrange(len(body))
        body[position] = rng.choice((0, 1, 2, 3, 4, 0x80, 0xFF, body[position] ^ 1))
        fragment = SemanticObject.create(Kind.GRAPH_FRAGMENT, bytes(body), list(fragment.references))
    elif mutation == "extra_reference":
        fragment = SemanticObject.create(Kind.GRAPH_FRAGMENT, fragment.body, sorted({*fragment.references, bits_type(64).cid}))
        objects.append(bits_type(64))
    if mutation is not None:
        built = function(fragment, (b32,), (b32,))
        objects.append(fragment)
    module = object_with_refs(Kind.MODULE, [built])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return _store(root, [*objects, built, module]), fragment


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class SelfhostGraphGlueTests(unittest.TestCase):
    def test_graph_references_and_trap_payloads_agree_with_the_bootstrap(self):
        """S6b.4d: XAX decides a graph's type references, reference use, and trap payloads exactly when the bootstrap accepts them."""
        rng = random.Random(14904)
        glued = accepted = rejected = 0
        rules = set()
        for trial in range(240):
            mutation = (None, None, "graph_byte", "extra_reference")[trial % 4]
            reader, fragment = _glue_store(rng, mutation)
            if reader is None:
                continue
            X._XAX_GLUE_GRAPHS.discard(fragment.cid)
            bootstrap = _verify(reader, False)
            X._XAX_GLUE_GRAPHS.discard(fragment.cid)
            with self.subTest(trial=trial, mutation=mutation):
                self.assertEqual(_verify(reader, True), bootstrap)
                if fragment.cid in X._XAX_GLUE_GRAPHS:
                    glued += 1
                    # A glue verdict claims the bootstrap's own checks pass on this graph.
                    X._XAX_GLUE_GRAPHS.discard(fragment.cid)
                    X._PARSED_GRAPHS.clear()
                    X._graph_syntax_from_stream(fragment, reader.get, X._native_graph_decoder().decode(fragment.body, len(fragment.references))[1])
                if bootstrap[0] == "accept":
                    accepted += 1
                else:
                    rejected += 1
                    rules.add(bootstrap[2])
        self.assertGreater(accepted, 60)
        self.assertGreater(rejected, 60)
        self.assertGreaterEqual(glued, accepted)
        self.assertIn("TRAP-PAYLOAD-CANONICAL", rules)
        self.assertIn("SER-REFS-DIRECT-ONLY", rules)


if __name__ == "__main__":
    unittest.main()
