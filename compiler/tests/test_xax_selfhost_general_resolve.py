"""S13c (ADR-283): the general driver resolves a build request's packages and writes the snapshot store.

``resolve <request store> <snapshot store>`` makes, in one Linux process with no Python inside, what
``snapshot_store(resolve_packages(request, candidates, policy, RESOLVER_IDENTITY), candidates)`` makes when the
candidates are the request store's objects and the policy is the driver's (the default trust policy): it verifies the
store (S10e), selects the packages in ``resolve_packages``'s order, derives the policy's and the snapshot's CIDs with the
S2 hash, and writes the store with the S9 writer.  Differential: the store bytes, or the exact diagnostic of a logical
identity no candidate or several candidates have.  A root that is no build request and a profile with grants decline.
The snapshot it writes is one ``build`` (S13a) builds.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_build import (
    BuildCapability, BuildCapabilityKind, CapabilityGrant, DependencyRequirement, build_profile, build_request, package, resolve_packages,
    snapshot_store,
)
from xax_selfhost_diagnostics import decode_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def request_store(request, objects) -> X.StoreReader:
    """The canonical store of ``request`` and everything it reaches among ``objects``."""
    by_cid = {item.cid: item for item in (*objects, request)}
    reached, pending = {}, [request.cid]
    while pending:
        cid = pending.pop()
        if cid not in reached:
            reached[cid] = by_cid[cid]
            pending.extend(by_cid[cid].references)
    return X.StoreReader.from_objects(request.cid, reached.values())


def expected(reader):
    from xax_selfhost_resolve import POLICY, RESOLVER_IDENTITY

    candidates = (*reader.objects(), POLICY)
    try:
        return "store", snapshot_store(resolve_packages(reader.get(reader.root_cid), candidates, POLICY, RESOLVER_IDENTITY), candidates).data
    except X.XaxError as error:
        return "rejected", error.diagnostic


def _program(value: int = 7):
    from test_xax_linux import _status_program
    from test_xax_selfhost_general_build import _parts

    program, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), value))
    objects, entry = _parts(program)
    return objects, entry, target


def _request(objects, entry, target, *, dependencies=(), extra=(), profile=None):
    module = X.object_with_refs(X.Kind.MODULE, (entry,))
    app = package(b"app", (module,), build_entries=((b"image", entry),), dependencies=dependencies)
    request = build_request(app, b"image", target, profile or build_profile())
    return request_store(request, (*objects, module, app, target, profile or build_profile(), *extra))


def _library(name: bytes, value: int, dependencies=()):
    module = X.object_with_refs(X.Kind.MODULE, (X.constant(X.bits_type(32), value), X.bits_type(32)))
    return package(name, (module,), dependencies=dependencies), (module, X.constant(X.bits_type(32), value), X.bits_type(32))


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class GeneralResolveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 600
        cls.directory = tempfile.mkdtemp()

    def run_resolve(self, data: bytes):
        store, output = (os.path.join(self.directory, name) for name in ("request.xax", "snapshot.xax"))
        Path(store).write_bytes(data)
        if os.path.exists(output):
            os.unlink(output)
        status = self.driver.resolve(store, output)
        produced = Path(output).read_bytes() if os.path.exists(output) else None
        if status == 0:
            return "store", produced
        if status == 1:
            return "rejected", decode_record([int.from_bytes(produced[k:k + 8], "little") for k in range(0, len(produced), 8)])
        return {2: "declined", 3: "failed"}[status], produced

    def assertResolve(self, reader):
        outcome = self.run_resolve(reader.data)
        self.assertEqual(outcome, expected(reader))
        return outcome

    def test_a_request_without_dependencies(self):
        self.assertEqual(self.assertResolve(_request(*_program()))[0], "store")

    def test_dependencies(self):
        """Exact roots and logical identities, in ``resolve_packages``'s order."""
        objects, entry, target = _program()
        base, base_objects = _library(b"base", 1)
        middle, middle_objects = _library(b"middle", 2, dependencies=(DependencyRequirement.exact(base),))
        cases = {
            "exact": ((DependencyRequirement.exact(middle),), (middle, *middle_objects, base, *base_objects)),
            "exact and logical": ((DependencyRequirement.exact(middle), DependencyRequirement.logical(b"base")),
                                  (middle, *middle_objects, base, *base_objects)),
        }
        for name, (dependencies, extra) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.assertResolve(_request(objects, entry, target, dependencies=dependencies, extra=extra))[0], "store")

    def test_logical_identity_rejections(self):
        objects, entry, target = _program()
        one, one_objects = _library(b"twin", 1)
        two, two_objects = _library(b"twin", 2)
        cases = {
            "XAX.RESOLVE.MISSING": ((DependencyRequirement.logical(b"absent"),), ()),
            "XAX.RESOLVE.AMBIGUOUS": ((DependencyRequirement.exact(one), DependencyRequirement.exact(two), DependencyRequirement.logical(b"twin")),
                                      (one, *one_objects, two, *two_objects)),
        }
        for code, (dependencies, extra) in cases.items():
            with self.subTest(code):
                kind, diagnostic = self.assertResolve(_request(objects, entry, target, dependencies=dependencies, extra=extra))
                self.assertEqual((kind, diagnostic.code, diagnostic.rule), ("rejected", code, "RESOLVE-LOGICAL-IDENTITY"))

    def test_declines(self):
        objects, entry, target = _program()
        program = _request(objects, entry, target)
        grant = CapabilityGrant(b"app", BuildCapability(BuildCapabilityKind.READ_OBJECT))
        cases = {
            "a program store": _program_store(),
            "a profile with grants": _request(objects, entry, target, profile=build_profile(grants=(grant,))),
        }
        self.assertEqual(self.run_resolve(program.data)[0], "store")
        for name, reader in cases.items():
            with self.subTest(name):
                self.assertEqual(self.run_resolve(reader.data), ("declined", None))

    def test_the_snapshot_builds(self):
        """``resolve`` then ``build``, both XAX processes: the artifact is ``build``'s."""
        from xax_artifact import XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1
        from xax_build import build

        kind, snapshot = self.run_resolve(_request(*_program(9)).data)
        self.assertEqual(kind, "store")
        snapshot_path, artifact, provenance = (os.path.join(self.directory, name) for name in ("built.xax", "artifact.bin", "provenance.bin"))
        Path(snapshot_path).write_bytes(snapshot)
        self.assertEqual(self.driver.build(snapshot_path, artifact, provenance), 0)
        reader = X.StoreReader(snapshot)
        root = reader.get(reader.root_cid)
        request = next(cid for cid in root.references if reader.get(cid).kind == X.Kind.BUILD and reader.get(cid).body[0] == 2)
        result = build(reader, request, compiler_identity=XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1)
        self.assertEqual(Path(artifact).read_bytes(), result.artifact)
        self.assertEqual(Path(provenance).read_bytes(), result.provenance.envelope())

    def test_an_invalid_store_never_resolves(self):
        data = _request(*_program()).data
        seen = set()
        for offset in range(64, len(data) - 64, max(1, len(data) // 40)):
            mutated = data[:offset] + bytes(((data[offset] + 1) & 0xFF,)) + data[offset + 1:]
            try:
                X.verify_store(X.StoreReader(mutated))
                continue
            except (X.XaxError, ValueError):
                pass
            outcome = self.run_resolve(mutated)
            self.assertIn(outcome[0], ("rejected", "declined"))
            seen.add(outcome[0])
        self.assertIn("rejected", seen)


def _program_store():
    from test_xax_linux import _status_program

    return _status_program(lambda b: b.const(X.bits_type(32), 7))[0]


if __name__ == "__main__":
    unittest.main()
