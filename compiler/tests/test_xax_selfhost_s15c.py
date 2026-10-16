"""S15c (ADR-299 to ADR-302): the general driver's remaining build paths, decided in XAX.

* Profile grants (S15c.1): ``resolve`` checks every grant over the selected packages as ``decode_snapshot`` does; a
  grant no selected package with its identity declares is ``BUILD-GRANT-DECLARED``, rendered by XAX with the
  snapshot's CID.
* External inputs (S15c.2): ``resolve`` and ``build`` take input files after their own arguments; the driver hashes
  them (BLAKE3, as ``verify_external_bytes``), sorts them and drops repeats; ``resolve`` records their digests in the
  snapshot and ``build`` requires them to be exactly the snapshot's (``BUILD-EXTERNAL-COMPLETE``).
* Signatures (S15c.3): under a policy requiring package signatures, ``build`` verifies each package's signatures with
  the driver's verifier (``xax_ed25519.signature_verifier``, in XAX) in ``_validate_trust``'s order.
* Capacities (S15c.4): a file or object past the driver's capacity is the driver's own ``XAX.DRIVER.CAPACITY``.
* Signed resolution (S15c.5): ``resolve-trusted`` resolves under the policy and signatures of a trust file
  (``xax_selfhost_resolve.trust_file``), as ``resolve_packages`` with ``signature_verifier``; its snapshot names the
  policy and the trusted signatures, and ``build`` accepts it.

Differential: ``resolve_packages``/``snapshot_store`` with the same external inputs, and ``build`` with the same
inputs and ``signature_verifier``: the store or artifact bytes, the provenance, or the exact diagnostic.
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
import xax_ed25519 as ED
from blake3 import blake3
from xax_artifact import XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1
from xax_build import (
    BuildCapability, BuildCapabilityKind, CapabilityGrant, DependencyRequirement, Resolution, build, build_profile, build_request, package,
    resolve_packages, signature, snapshot, snapshot_store, trust_policy,
)
from xax_selfhost_diagnostics import decode_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def resolve_expected(reader, inputs=()):
    from xax_selfhost_resolve import POLICY, RESOLVER_IDENTITY

    candidates = (*reader.objects(), POLICY)
    try:
        resolution = resolve_packages(reader.get(reader.root_cid), candidates, POLICY, RESOLVER_IDENTITY,
                                      external_inputs={blake3(value).digest(): value for value in inputs})
        return "store", snapshot_store(resolution, candidates).data
    except X.XaxError as error:
        return "rejected", error.diagnostic


def trusted_expected(reader, trust: bytes, inputs=()):
    from xax_selfhost_resolve import RESOLVER_IDENTITY, parse_trust_file

    policy, signatures = parse_trust_file(trust)
    try:
        resolution = resolve_packages(reader.get(reader.root_cid), tuple(reader.objects()), policy, RESOLVER_IDENTITY, signatures=signatures,
                                      signature_verifier=ED.signature_verifier, external_inputs={blake3(value).digest(): value for value in inputs})
        return "store", snapshot_store(resolution, (*reader.objects(), policy, *signatures)).data
    except X.XaxError as error:
        return "rejected", error.diagnostic


def build_expected(reader, inputs=()):
    from test_xax_selfhost_general_build import _request_root

    try:
        result = build(reader, _request_root(reader), compiler_identity=XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1,
                       external_inputs={blake3(value).digest(): value for value in inputs}, signature_verifier=ED.signature_verifier)
    except X.XaxError as error:
        return "rejected", error.diagnostic
    return "image", result.artifact, result.provenance.envelope()


class _Fixture:
    """A status program's parts, its package, and stores made from them."""

    def __init__(self):
        from test_xax_linux import _status_program
        from test_xax_selfhost_general_build import _parts
        from test_xax_selfhost_general_resolve import _library

        program, _entry, self.target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        self.objects, self.entry = _parts(program)
        self.module = X.object_with_refs(X.Kind.MODULE, (self.entry,))
        self.base, self.base_objects = _library(b"base", 1)

    def app(self, capabilities=(), dependencies=()):
        return package(b"app", (self.module,), build_entries=((b"image", self.entry),), dependencies=dependencies, capabilities=capabilities)

    def request_store(self, *, capabilities=(), grants=(), dependencies=(), extra=()):
        from test_xax_selfhost_general_resolve import request_store

        app, profile = self.app(capabilities, dependencies), build_profile(grants=grants)
        request = build_request(app, b"image", self.target, profile)
        return request_store(request, (*self.objects, self.module, app, self.target, profile, *extra))

    def signed_snapshot(self, signatures, policy, packages=None, extra=()):
        """A snapshot store with exactly ``signatures`` (made directly: the Python resolver keeps trusted ones only)."""
        packages = packages or (self.app(),)
        profile = build_profile()
        request = build_request(packages[0], b"image", self.target, profile)
        made = snapshot(request, b"resolver-v1", policy, packages, signatures=signatures)
        everything = (*self.objects, self.module, *packages, *extra, self.target, profile, policy, request, *signatures)
        return snapshot_store(Resolution(tuple(sorted(packages, key=lambda o: o.cid)), tuple(sorted(signatures, key=lambda o: o.cid)), made),
                              everything)


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class S15cTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 600
        cls.directory = Path(tempfile.mkdtemp())
        cls.f = _Fixture()

    def _inputs(self, values):
        paths = []
        for k, value in enumerate(values):
            path = self.directory / f"input{k}.bin"
            path.write_bytes(value)
            paths.append(path)
        return paths

    @staticmethod
    def _record(data: bytes):
        return decode_record([int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)])

    def run_resolve(self, data: bytes, inputs=()):
        request, output = self.directory / "request.xax", self.directory / "snapshot.xax"
        request.write_bytes(data)
        output.unlink(missing_ok=True)
        status = self.driver.resolve(request, output, *self._inputs(inputs))
        produced = output.read_bytes() if output.exists() else None
        return ("store", produced) if status == 0 else ("rejected", self._record(produced)) if status == 1 else (status, produced)

    def run_build(self, data: bytes, inputs=()):
        snapshot_path, artifact, provenance = (self.directory / name for name in ("built.xax", "artifact.bin", "provenance.bin"))
        snapshot_path.write_bytes(data)
        for path in (artifact, provenance):
            path.unlink(missing_ok=True)
        status = self.driver.build(snapshot_path, artifact, provenance, *self._inputs(inputs))
        if status == 0:
            return "image", artifact.read_bytes(), provenance.read_bytes()
        return ("rejected", self._record(artifact.read_bytes())) if status == 1 else (status,)

    def assertResolve(self, reader, inputs=()):
        outcome = self.run_resolve(reader.data, inputs)
        self.assertEqual(outcome, resolve_expected(reader, inputs))
        return outcome

    def assertBuild(self, reader, inputs=()):
        outcome = self.run_build(reader.data, inputs)
        self.assertEqual(outcome, build_expected(reader, inputs))
        return outcome

    def test_grants(self):
        f = self.f
        read = BuildCapability(BuildCapabilityKind.READ_OBJECT)
        granted = CapabilityGrant(b"app", read)
        cases = {
            "declared": (f.request_store(capabilities=(read,), grants=(granted,)), "store"),
            "undeclared": (f.request_store(grants=(granted,)), "BUILD-GRANT-DECLARED"),
            "another scope": (f.request_store(capabilities=(BuildCapability(BuildCapabilityKind.READ_OBJECT, b"x"),), grants=(granted,)),
                              "BUILD-GRANT-DECLARED"),
            "unknown identity": (f.request_store(capabilities=(read,), grants=(CapabilityGrant(b"zz", BuildCapability(BuildCapabilityKind.NETWORK, b"h")),)),
                                 "BUILD-GRANT-DECLARED"),
            "a dependency": (f.request_store(grants=(CapabilityGrant(b"base", BuildCapability(BuildCapabilityKind.CLOCK)),),
                                             dependencies=(DependencyRequirement.exact(f.base),), extra=(f.base, *f.base_objects)),
                             "BUILD-GRANT-DECLARED"),
            "the second of two": (f.request_store(capabilities=(read,), grants=(
                granted, CapabilityGrant(b"app", BuildCapability(BuildCapabilityKind.SIGN, b"\x00\xff")))), "BUILD-GRANT-DECLARED"),
        }
        for name, (reader, expected) in cases.items():
            with self.subTest(name):
                outcome = self.assertResolve(reader)
                self.assertEqual(outcome[0] if outcome[0] == "store" else outcome[1].rule, expected)

    def test_external_inputs(self):
        f = self.f
        request = f.request_store()
        values = (b"x", b"hello", b"x", bytes(70000))
        kind, snapshot_bytes = self.assertResolve(request, values)
        self.assertEqual(kind, "store")
        self.assertEqual(self.assertResolve(request, (b"",))[0], "store")
        built = X.StoreReader(snapshot_bytes)
        self.assertEqual(self.assertBuild(built, values[1:])[0], "image")
        for name, given in {"missing": (), "wrong": (b"x", b"other"), "extra": (*values, b"more")}.items():
            with self.subTest(name):
                kind, diagnostic = self.assertBuild(built, given)
                self.assertEqual((kind, diagnostic.rule), ("rejected", "BUILD-EXTERNAL-COMPLETE"))

    def test_signatures(self):
        f = self.f
        a, b = b"\x01" * 32, b"\x02" * 32
        key_a, key_b = ED.public_key(a), ED.public_key(b)
        app = f.app()
        policy = trust_policy(require_package_signatures=True, accepted_algorithms=(ED.ALGORITHM,), accepted_signers=(key_a,))
        good = signature(app, ED.ALGORITHM, key_a, ED.sign(a, app.cid))
        forged = signature(app, ED.ALGORITHM, key_a, ED.sign(b, app.cid))
        cases = {
            "valid": ((good,), policy, "image"),
            "forged": ((forged,), policy, "TRUST-SIGNATURE-REQUIRED"),
            "an untrusted signer": ((signature(app, ED.ALGORITHM, key_b, ED.sign(b, app.cid)),), policy, "TRUST-SIGNATURE-REQUIRED"),
            "valid and forged": ((good, forged), policy, "TRUST-SNAPSHOT-SIGNATURES"),
            "another algorithm": ((signature(app, b"test", key_a, b"x"),),
                                  trust_policy(require_package_signatures=True, accepted_algorithms=(b"test",), accepted_signers=(key_a,)),
                                  "TRUST-SIGNATURE-REQUIRED"),
            "a short key": ((signature(app, ED.ALGORITHM, key_a[:31], bytes(64)),),
                            trust_policy(require_package_signatures=True, accepted_algorithms=(ED.ALGORITHM,), accepted_signers=(key_a[:31],)),
                            "TRUST-SIGNATURE-REQUIRED"),
        }
        rng = random.Random(301)
        for trial in range(6):
            value = bytearray(ED.sign(a, app.cid))
            value[rng.randrange(64)] ^= 1 << rng.randrange(8)
            mutated = signature(app, ED.ALGORITHM, key_a, bytes(value))
            cases[f"mutated {trial}"] = (((mutated, good) if trial % 2 else (mutated,)), policy,
                                         "TRUST-SNAPSHOT-SIGNATURES" if trial % 2 else "TRUST-SIGNATURE-REQUIRED")
        two = f.app(dependencies=(DependencyRequirement.exact(f.base),))
        both = trust_policy(require_package_signatures=True, accepted_algorithms=(ED.ALGORITHM,), accepted_signers=(key_a, key_b))
        signed_two = (signature(two, ED.ALGORITHM, key_a, ED.sign(a, two.cid)), signature(f.base, ED.ALGORITHM, key_b, ED.sign(b, f.base.cid)))
        for name, (signatures, chosen, expected) in cases.items():
            with self.subTest(name):
                outcome = self.assertBuild(f.signed_snapshot(signatures, chosen))
                self.assertEqual(outcome[0] if outcome[0] == "image" else outcome[1].rule, expected)
        with self.subTest("two packages"):
            self.assertEqual(self.assertBuild(f.signed_snapshot(signed_two, both, (two, f.base), f.base_objects))[0], "image")
        with self.subTest("a dependency signed by the wrong key"):
            badly = (signed_two[0], signature(f.base, ED.ALGORITHM, key_b, ED.sign(a, f.base.cid)))
            outcome = self.assertBuild(f.signed_snapshot(badly, both, (two, f.base), f.base_objects))
            self.assertEqual(outcome[1].rule, "TRUST-SIGNATURE-REQUIRED")

    def test_trusted_resolution(self):
        """S15c.5 (ADR-309): the snapshot ``resolve_packages`` makes under the trust file's policy and signatures, or
        its exact rejection; a signed snapshot then builds.  A malformed trust file declines."""
        from xax_selfhost_resolve import POLICY, trust_file

        f = self.f
        a, b = b"\x01" * 32, b"\x02" * 32
        key_a, key_b = ED.public_key(a), ED.public_key(b)
        app, request = f.app(), f.request_store()
        policy = trust_policy(require_package_signatures=True, accepted_algorithms=(ED.ALGORITHM,), accepted_signers=(key_a,))
        good = signature(app, ED.ALGORITHM, key_a, ED.sign(a, app.cid))
        other = signature(app, ED.ALGORITHM, key_b, ED.sign(b, app.cid))
        two = f.app(dependencies=(DependencyRequirement.exact(f.base),))
        with_base = f.request_store(dependencies=(DependencyRequirement.exact(f.base),), extra=(f.base, *f.base_objects))
        signed_two = signature(two, ED.ALGORITHM, key_a, ED.sign(a, two.cid))
        signed_base = signature(f.base, ED.ALGORITHM, key_a, ED.sign(a, f.base.cid))
        cases = {
            "the driver's policy": (request, trust_file(POLICY, (good,)), "store"),
            "signed": (request, trust_file(policy, (good,)), "store"),
            "an untrusted one too": (request, trust_file(policy, (good, other)), "store"),
            "forged": (request, trust_file(policy, (signature(app, ED.ALGORITHM, key_a, ED.sign(b, app.cid)),)), "TRUST-SIGNATURE-REQUIRED"),
            "an untrusted signer": (request, trust_file(policy, (other,)), "TRUST-SIGNATURE-REQUIRED"),
            "unsigned": (request, trust_file(policy), "TRUST-SIGNATURE-REQUIRED"),
            "an unsigned dependency": (with_base, trust_file(policy, (signed_two,)), "TRUST-SIGNATURE-REQUIRED"),
            "a signed dependency": (with_base, trust_file(policy, (signed_two, signed_base)), "store"),
        }
        trust = self.directory / "trust.bin"
        for name, (reader, data, expected) in cases.items():
            with self.subTest(name):
                trust.write_bytes(data)
                output = self.directory / "snapshot.xax"
                output.unlink(missing_ok=True)
                (self.directory / "request.xax").write_bytes(reader.data)
                status = self.driver.resolve_trusted(self.directory / "request.xax", output, trust, *self._inputs((b"input",)))
                produced = output.read_bytes() if output.exists() else None
                outcome = ("store", produced) if status == 0 else ("rejected", self._record(produced)) if status == 1 else (status, produced)
                self.assertEqual(outcome, trusted_expected(reader, data, (b"input",)))
                self.assertEqual(outcome[0] if outcome[0] == "store" else outcome[1].rule, expected)
                if outcome[0] == "store":
                    self.assertEqual(self.assertBuild(X.StoreReader(produced), (b"input",))[0], "image")
        for name, data in {"empty": b"", "truncated": trust_file(policy, (good,))[:-3], "no policy first": good.envelope() + policy.envelope()}.items():
            with self.subTest(name):
                trust.write_bytes(data)
                (self.directory / "request.xax").write_bytes(request.data)
                self.assertEqual(self.driver.resolve_trusted(self.directory / "request.xax", self.directory / "snapshot.xax", trust), 2)

    def test_capacities(self):
        large = self.directory / "large.bin"
        large.write_bytes(bytes(33 << 20))
        output = self.directory / "out.bin"
        for command, arguments, entity in (("verify", (large, output), "store"),
                                           ("resolve", (self.directory / "request.xax", output, large), "external-input")):
            (self.directory / "request.xax").write_bytes(self.f.request_store().data)
            with self.subTest(command):
                output.unlink(missing_ok=True)
                self.assertEqual(self.driver._process(command, *arguments), 1)
                diagnostic = self._record(output.read_bytes())
                self.assertEqual((diagnostic.code, diagnostic.entity, diagnostic.rule, diagnostic.actual),
                                 ("XAX.DRIVER.CAPACITY", entity, "DRIVER-FILE-CAPACITY", "larger"))

    def test_argument_counts(self):
        """Input files follow ``build`` and ``resolve`` only, at most ``INPUTS_LIMIT`` of them (100 since the evolution
        ledger's first transaction, S15d.3); anything else FAILED."""
        from xax_selfhost_evolution import INPUTS_LIMIT

        request = self.directory / "request.xax"
        request.write_bytes(self.f.request_store().data)
        output = self.directory / "out.bin"
        self.assertEqual(self.driver._process("verify", request, output, request), 3)
        self.assertEqual(self.driver._process("inspect", request, output, request), 3)
        self.assertEqual(self.driver._process("resolve", request), 3)
        self.assertEqual(self.driver._process("resolve", request, output, *([request] * (INPUTS_LIMIT + 1))), 3)


if __name__ == "__main__":
    unittest.main()
