"""S13a (ADR-281): the general driver builds a canonical build request and writes its provenance.

``build <snapshot store> <artifact> <provenance>`` makes, in one Linux process with no Python inside, what
``xax_build.build(reader, request_root)`` makes for the snapshot's request: it verifies the store (S10e), reads the
snapshot (its request, its trust policy, its external inputs), the request (package, build entry, target, profile,
requested artifacts), and the package's build entry, lowers that entry for the request's Linux x86-64 target with the
general backend program, hashes the artifact with the S2 hash, and writes the canonical provenance object (its CID
re-derived with the S2 hash).  Differential: the artifact bytes and the provenance object's envelope equal
``build(..., compiler_identity=XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1)``'s, and every rejection ``build`` makes on these
paths is the driver's, with the exact diagnostic.  S15e.1 (ADR-308): a RISC-V raw image target is lowered by the XAX
RISC-V backend program; S15e.2 (ADR-315): a Linux AArch64 ELF profile by the XAX AArch64 program.  What ``build`` makes on other paths (Android packages, Windows DLLs, other targets) the driver
declines.  The driver is given no external inputs and verifies no signatures, which is
``build`` called without them.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
from xax_artifact import XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1
from xax_build import (
    ArtifactKind, BuildCache, BuildForm, DependencyRequirement, _build_form, build, build_profile, build_request, decode_provenance,
    decode_snapshot, package, resolve_packages, snapshot_store, trust_policy,
)
from xax_selfhost_diagnostics import decode_record

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _request_root(reader) -> bytes:
    """The request ``build`` is asked for: the snapshot's (the driver takes no other); a root that is no snapshot
    names none."""
    root = reader.get(reader.root_cid)
    if root.kind == X.Kind.BUILD and _build_form(root) == BuildForm.SNAPSHOT:
        return decode_snapshot(root, reader.get).request_root
    return bytes(32)


def _expected(reader, external_inputs=None):
    from xax_ed25519 import signature_verifier

    try:
        result = build(reader, _request_root(reader), compiler_identity=XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1, external_inputs=external_inputs,
                       signature_verifier=signature_verifier)
    except X.XaxError as error:
        return "rejected", error.diagnostic
    return "image", result.artifact, result.provenance.envelope()


def _program(objects, entries, target, *, artifacts=(ArtifactKind.NATIVE_IMAGE,), entry=b"image", policy=None, packages=(),
             dependencies=(), external_inputs=None, signatures=(), verifier=None):
    """A snapshot store: ``entries`` (name -> function) packaged with every function in one module, built for
    ``target``."""
    module = X.object_with_refs(X.Kind.MODULE, tuple(entries.values()))
    app = package(b"app", (module,), build_entries=tuple(entries.items()), dependencies=dependencies)
    profile, policy = build_profile(), policy or trust_policy()
    request = build_request(app, entry, target, profile, requested_artifacts=artifacts)
    everything = (*objects, *entries.values(), module, app, *packages, target, profile, policy, request)
    resolution = resolve_packages(request, everything, policy, b"resolver-v1", signatures=signatures, signature_verifier=verifier,
                                  external_inputs=external_inputs)
    return snapshot_store(resolution, (*everything, *signatures))


def _parts(reader):
    """A Linux test program's objects (no module or root) and its root entry."""
    module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
    entry = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)
    objects = tuple(item for item in reader.objects() if item.kind not in (X.Kind.MODULE, X.Kind.PROGRAM_ROOT))
    return objects, entry


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: the driver image runs on Linux x86-64 only")
class GeneralBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from xax_selfhost_driver import NativeGeneralDriver

        cls.driver = NativeGeneralDriver()
        cls.driver.timeout = 600  # a driver that does not end fails the test
        cls.directory = tempfile.mkdtemp()

    def run_build(self, data: bytes):
        snapshot, artifact, provenance = (os.path.join(self.directory, name) for name in ("snapshot.xax", "artifact.bin", "provenance.bin"))
        Path(snapshot).write_bytes(data)
        for path in (artifact, provenance):
            if os.path.exists(path):
                os.unlink(path)
        status = self.driver.build(snapshot, artifact, provenance)
        produced = Path(artifact).read_bytes() if os.path.exists(artifact) else None
        if status == 0:
            return "image", produced, Path(provenance).read_bytes()
        self.assertFalse(os.path.exists(provenance))
        if status == 1:
            return "rejected", decode_record([int.from_bytes(produced[k:k + 8], "little") for k in range(0, len(produced), 8)])
        self.assertIsNone(produced)
        return {2: "declined", 3: "failed"}[status], None

    def assertBuild(self, reader):
        """The driver's outcome equals ``build``'s; an image's provenance is a valid canonical object."""
        outcome = self.run_build(reader.data)
        self.assertEqual(outcome, _expected(reader))
        if outcome[0] == "image":
            record = X.decode_object(outcome[2], "provenance")
            view = decode_provenance(record, X.store_resolver(reader))
            self.assertEqual(view.compiler_identity, XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1)
            result = build(reader, view.request_root, compiler_identity=XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1)
            cache = BuildCache()
            cache.put(result)
            self.assertEqual(cache.get(result.key, reader), outcome[1])  # the provenance authenticates the artifact
        return outcome

    def test_linux_executables(self):
        """Static and dynamic executables, each the bootstrap's bytes with its provenance."""
        from benchmarks.jsonmin import build_jsonmin
        from test_xax_linux import _crc_program, _status_program

        reader, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        programs = {"status": (reader, target), "crc": _crc_program(X.x86_64_linux_dynamic_exec_target())[::2]}
        jsonmin = build_jsonmin()
        programs["jsonmin"] = (jsonmin.reader, jsonmin.target)
        for name, (program, target) in programs.items():
            with self.subTest(name):
                objects, entry = _parts(program)
                self.assertEqual(self.assertBuild(_program(objects, {b"image": entry}, target))[0], "image")

    def test_the_artifact_runs(self):
        from test_xax_linux import _status_program
        from xax_linux import run_linux_executable

        reader, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        objects, entry = _parts(reader)
        kind, artifact, _provenance = self.run_build(_program(objects, {b"image": entry}, target).data)
        self.assertEqual(kind, "image")
        self.assertEqual(run_linux_executable(artifact).returncode, 7)

    def test_the_request_names_the_entry(self):
        """Several build entries, a dependency package, and feature and configuration bindings: the request's entry is
        built."""
        from test_xax_build import fixture

        target = X.x86_64_linux_exec_target()
        objects, _app, request, _profile, policy = fixture(target=target, dependency=DependencyRequirement.logical(b"library"),
                                                           feature_schema=True)
        library_module = X.object_with_refs(X.Kind.MODULE, (X.bits_type(32),))
        everything = (*objects, library_module, package(b"library", (library_module,)))
        reader = snapshot_store(resolve_packages(request, everything, policy, b"resolver-v1"), everything)
        self.assertEqual(self.assertBuild(reader)[0], "image")
        from test_xax_linux import _status_program

        first, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 3))
        second, _entry, _target, _ = _status_program(lambda b: b.const(X.bits_type(32), 5))
        (one, a), (two, b) = _parts(first), _parts(second)
        for name in (b"a", b"b"):
            with self.subTest(name):
                reader = _program((*one, *two), {b"a": a, b"b": b}, target, entry=name)
                self.assertEqual(self.assertBuild(reader)[0], "image")

    def test_the_root_must_be_a_snapshot(self):
        from test_xax_linux import _status_program

        program, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        kind, diagnostic = self.assertBuild(program)
        self.assertEqual((kind, diagnostic.rule, diagnostic.actual), ("rejected", "BUILD-KIND", "PROGRAM_ROOT"))
        objects, entry = _parts(program)
        snapshot = _program(objects, {b"image": entry}, target)
        request = snapshot.get(_request_root(snapshot))
        reachable, pending = {}, [request.cid]
        while pending:
            item = snapshot.get(pending.pop())
            if item.cid not in reachable:
                reachable[item.cid] = item
                pending.extend(item.references)
        reader = X.StoreReader.from_objects(request.cid, reachable.values())
        kind, diagnostic = self.assertBuild(reader)
        self.assertEqual((kind, diagnostic.rule, diagnostic.actual), ("rejected", "BUILD-SNAPSHOT-ROOT", "REQUEST"))

    def test_external_inputs_and_signatures(self):
        """Without the input files ``build`` rejects; a signature whose algorithm is not Ed25519 is never trusted."""
        from blake3 import blake3
        from test_xax_build import fake_signature
        from test_xax_linux import _status_program

        program, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        objects, entry = _parts(program)
        inputs = {blake3(value).digest(): value for value in (b"one", b"two")}
        kind, diagnostic = self.assertBuild(_program(objects, {b"image": entry}, target, external_inputs=inputs))
        self.assertEqual((kind, diagnostic.rule), ("rejected", "BUILD-EXTERNAL-COMPLETE"))
        policy = trust_policy(require_package_signatures=True, accepted_algorithms=(b"test-blake3",), accepted_signers=(b"test-key",))
        module = X.object_with_refs(X.Kind.MODULE, (entry,))
        app = package(b"app", (module,), build_entries=((b"image", entry),))
        kind, diagnostic = self.assertBuild(_program(objects, {b"image": entry}, target, policy=policy, signatures=(fake_signature(app),),
                                                     verifier=lambda *_: True))
        self.assertEqual((kind, diagnostic.rule), ("rejected", "TRUST-SIGNATURE-REQUIRED"))

    def test_requested_artifacts(self):
        """A Linux profile makes a native image only; the container is made, and its rejections come, first."""
        from test_xax_linux import _crc_program, _status_program

        program, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        objects, entry = _parts(program)
        for artifacts in ((ArtifactKind.ACCELERATOR_DEPLOYMENT,), (ArtifactKind.NATIVE_IMAGE, ArtifactKind.JVM_LIBRARY_JAR)):
            with self.subTest(artifacts):
                kind, diagnostic = self.assertBuild(_program(objects, {b"image": entry}, target, artifacts=artifacts))
                self.assertEqual((kind, diagnostic.rule), ("rejected", "BUILD-ARTIFACT-SUPPORTED"))
        reader, _entry, target = _crc_program(X.x86_64_linux_exec_target())
        objects, entry = _parts(reader)
        kind, diagnostic = self.assertBuild(_program(objects, {b"image": entry}, target, artifacts=(ArtifactKind.JVM_LIBRARY_JAR,)))
        self.assertEqual((kind, diagnostic.rule), ("rejected", "SYSV-C-REQUIRES-DYNAMIC-PROFILE"))

    def test_riscv_images(self):
        """S15e.1 (ADR-308): a RISC-V raw image target is lowered by the XAX RISC-V backend program; the artifact
        (the code words, little-endian) and its provenance are the bootstrap's, and the requested artifacts are
        checked before lowering, with ``build``'s three-name expectation."""
        from xax_graph_builder import GraphBuilder
        from test_xax_linux import _status_program
        from test_xax_riscv64 import aggregate_program

        b64 = X.bits_type(64)
        graph = GraphBuilder()
        block = graph.block(b64, b64)
        x, y = block.params
        block.ret(block.op1(X.Operation.MUL_WRAP, (block.op1(X.Operation.ADD_WRAP, (x, y), b64), block.const(b64, 7)), b64))
        function, objects = graph.function((b64, b64), (b64,)), (*graph.objects.values(), b64)
        for target in (X.riscv64_baremetal_target(), X.riscv64_views_target()):
            with self.subTest(target.cid.hex()):
                self.assertEqual(self.assertBuild(_program(objects, {b"image": function}, target))[0], "image")
        entry, aggregate_objects, _reference = aggregate_program()
        self.assertEqual(self.assertBuild(_program(aggregate_objects, {b"image": entry}, X.riscv64_views_target()))[0], "image")
        for artifacts in ((ArtifactKind.ACCELERATOR_DEPLOYMENT,), (ArtifactKind.NATIVE_IMAGE, ArtifactKind.JVM_LIBRARY_JAR)):
            with self.subTest(artifacts):
                kind, diagnostic = self.assertBuild(_program(objects, {b"image": function}, X.riscv64_baremetal_target(), artifacts=artifacts))
                self.assertEqual((kind, diagnostic.rule), ("rejected", "BUILD-ARTIFACT-SUPPORTED"))
        program, _entry, _target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        linux_objects, linux_entry = _parts(program)
        self.assertEqual(self.assertBuild(_program(linux_objects, {b"image": linux_entry}, X.riscv64_baremetal_target()))[0], "rejected")

    def test_linux_aarch64_executables(self):
        """S15e.2 (ADR-315): a Linux AArch64 ELF profile is lowered by the XAX AArch64 program; static and dynamic
        executables are the bootstrap's bytes with their provenance, a request for another artifact is
        ``BUILD-ARTIFACT-SUPPORTED`` after the container."""
        from test_xax_linux_aarch64 import _status_program, _write_program

        programs = {
            "status": _status_program(lambda b: b.const(X.bits_type(32), 7))[::2],
            "dynamic status": _status_program(lambda b: b.const(X.bits_type(32), 9), dynamic=True)[::2],
            "write": _write_program(b"hello\n")[::2],
        }
        for name, (program, target) in programs.items():
            with self.subTest(name):
                objects, entry = _parts(program)
                self.assertEqual(self.assertBuild(_program(objects, {b"image": entry}, target))[0], "image")
        program, target = programs["status"]
        objects, entry = _parts(program)
        kind, diagnostic = self.assertBuild(_program(objects, {b"image": entry}, target, artifacts=(ArtifactKind.JVM_LIBRARY_JAR,)))
        self.assertEqual((kind, diagnostic.rule), ("rejected", "BUILD-ARTIFACT-SUPPORTED"))

    def test_linux_aarch64_artifact_runs(self):
        from test_xax_linux_aarch64 import _status_program
        from xax_linux_aarch64 import aarch64_runner, run_linux_aarch64_executable

        if aarch64_runner() is None:
            self.skipTest("requires an AArch64 Linux host or qemu-aarch64")
        program, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        objects, entry = _parts(program)
        kind, artifact, _provenance = self.run_build(_program(objects, {b"image": entry}, target).data)
        self.assertEqual(kind, "image")
        self.assertEqual(run_linux_aarch64_executable(artifact).returncode, 7)

    def test_windows_pe_executables(self):
        """S15e.3 (ADR-317): the Windows PE32+ profile is lowered by the XAX general x86-64 program: the executable is
        the bootstrap's bytes (``build`` with the XAX programs opted out) with its provenance; a Linux process entry
        is the bootstrap's rejection."""
        from test_xax_linux import _status_program
        from test_xax_pe import hosted_fixture, thread_callback_fixture

        for name, fixture in (("hosted", hosted_fixture), ("thread", thread_callback_fixture)):
            with self.subTest(name):
                reader, _entry, target = fixture()
                objects, entry = _parts(reader)
                program = _program(tuple(item for item in objects if item.cid != target.cid), {b"image": entry}, target)
                outcome = self.assertBuild(program)
                self.assertEqual(outcome[0], "image")
                self.assertEqual(outcome[1], compile_pe_executable(reader, entry.cid, target, frontend="python"))
        program, _entry, _target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        objects, entry = _parts(program)
        self.assertEqual(self.assertBuild(_program(objects, {b"image": entry}, X.x86_64_windows_pe_target()))[0], "rejected")

    def test_other_paths_decline(self):
        """Android packages, Windows DLLs, and targets other than the Linux x86-64, Linux AArch64, Windows PE32+ and
        RISC-V raw profiles are ``build``'s other paths: the driver declines and writes nothing."""
        from test_xax_linux import _status_program

        program, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        objects, entry = _parts(program)
        cases = {
            "android": _program(objects, {b"image": entry}, target, artifacts=(ArtifactKind.ANDROID_UNSIGNED_APK,)),
            "dll": _program(objects, {b"image": entry}, target, artifacts=(ArtifactKind.WINDOWS_DLL,)),
            "views": _program(objects, {b"image": entry}, X.x86_64_views_exec_target()),
            "riscv dll": _program(objects, {b"image": entry}, X.riscv64_baremetal_target(), artifacts=(ArtifactKind.WINDOWS_DLL,)),
        }
        for name, reader in cases.items():
            with self.subTest(name):
                self.assertEqual(self.run_build(reader.data), ("declined", None))

    def test_an_invalid_store_never_builds(self):
        """A snapshot ``verify_store`` rejects gives the driver's verification record or a decline, never an
        artifact."""
        from test_xax_linux import _status_program

        program, _entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        objects, entry = _parts(program)
        data = bytearray(_program(objects, {b"image": entry}, target).data)
        seen = set()
        for offset in range(64, len(data) - 64, max(1, len(data) // 40)):
            mutated = bytes(data[:offset]) + bytes(((data[offset] + 1) & 0xFF,)) + bytes(data[offset + 1:])
            try:
                X.verify_store(X.StoreReader(mutated))
                continue
            except (X.XaxError, ValueError):
                pass
            outcome = self.run_build(mutated)
            self.assertIn(outcome[0], ("rejected", "declined"))
            seen.add(outcome[0])
        self.assertIn("rejected", seen)

    def test_commands(self):
        """``lower`` is S12e.2's path; an unknown command or argument count fails."""
        from xax_selfhost_driver import target_package
        from test_xax_linux import _status_program
        from xax_linux import compile_linux_executable

        program, entry, target, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
        store, package_path, output = (os.path.join(self.directory, name) for name in ("store.xax", "target.xax", "out.bin"))
        Path(store).write_bytes(program.data)
        Path(package_path).write_bytes(target_package(target))
        self.assertEqual(self.driver.run(store, package_path, output), 0)
        self.assertEqual(Path(output).read_bytes(), compile_linux_executable(program, entry.cid, target.cid).data)
        self.assertEqual(self.driver._process("compile", store, package_path, output), 3)
        self.assertEqual(self.driver._process(store, package_path, output), 3)


if __name__ == "__main__":
    unittest.main()
