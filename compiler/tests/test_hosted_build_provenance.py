"""Hosted-platform artifacts come out of the canonical build service with provenance (ADR-177).

Linux ELF executables, Windows PE32+, the browser page, and SPIR-V modules used to be emitted only by direct calls;
the build service now makes the same bytes and records them in provenance.
"""
import unittest

from blake3 import blake3

from test_xax_spirv import collatz_kernel
from test_xax_build import fixture
from xax_build import (
    ArtifactKind, build, build_profile, build_request, decode_provenance, package, resolve_packages, snapshot_store, trust_policy,
)
from xax_compiler import (
    Kind, aarch64_linux_exec_target, object_with_refs, spirv_vulkan_compute_target, store_resolver, wasm32_browser_target,
    x86_64_linux_dynamic_exec_target, x86_64_linux_exec_target, x86_64_windows_pe_target,
)


def _service(objects, entry, target):
    """``(build result, snapshot reader, entry cid)`` for ``entry`` packaged alone and built for ``target``."""
    module = object_with_refs(Kind.MODULE, (entry,))
    app = package(b"app", (module,), build_entries=((b"image", entry),))
    profile, policy = build_profile(), trust_policy()
    request = build_request(app, b"image", target, profile, requested_artifacts=(ArtifactKind.NATIVE_IMAGE,))
    everything = (*objects, module, app, target, profile, policy, request)
    reader = snapshot_store(resolve_packages(request, everything, policy, b"resolver-v1"), everything)
    return build(reader, request.cid), reader, entry.cid


def _fixture_parts(target):
    objects, _app, _request, _profile, _policy = fixture(target=target)
    entry = next(obj for obj in objects if obj.kind == Kind.FUNCTION)
    return tuple(obj for obj in objects if obj.kind not in (Kind.MODULE, Kind.PACKAGE, Kind.BUILD, Kind.TARGET)), entry


class HostedBuildProvenanceTests(unittest.TestCase):
    def _check(self, target, direct):
        objects, entry = _fixture_parts(target)
        result, reader, entry_cid = _service(objects, entry, target)
        self.assertEqual(result.artifact, direct(reader, entry_cid, target))
        view = decode_provenance(result.provenance, store_resolver(reader))
        self.assertEqual(view.artifact_digest, blake3(result.artifact).digest())
        self.assertEqual(build(reader, view.request_root), result)  # deterministic

    def test_linux_x86_64_executables(self):
        from xax_linux import compile_linux_executable

        for target in (x86_64_linux_exec_target(), x86_64_linux_dynamic_exec_target()):
            self._check(target, lambda reader, cid, target: compile_linux_executable(reader, cid, target.cid).data)

    def test_linux_aarch64_executable(self):
        from xax_linux_aarch64 import compile_linux_aarch64_executable

        target = aarch64_linux_exec_target()
        self._check(target, lambda reader, cid, target: compile_linux_aarch64_executable(reader, cid, target.cid).data)

    def test_windows_pe(self):
        from xax_pe import emit_pe_executable
        from xax_x86_64 import compile_native_bound_target

        self._check(x86_64_windows_pe_target(), lambda reader, cid, target: emit_pe_executable(compile_native_bound_target(reader, cid, target)))

    def test_browser_page(self):
        from benchmarks.browser_fib import fib_page_program
        from xax_wasm import compile_wasm_bound_target
        from xax_web import emit_browser_page

        program, start, target = fib_page_program()
        objects = tuple(obj for obj in program.objects() if obj.kind not in (Kind.PROGRAM_ROOT, Kind.MODULE) and obj.cid != target.cid)
        result, reader, cid = _service(objects, start, target)
        self.assertEqual(result.artifact, emit_browser_page(compile_wasm_bound_target(reader, cid, target)))
        self.assertEqual(result.artifact, emit_browser_page(compile_wasm_bound_target(program, start.cid, wasm32_browser_target())))

    def test_spirv_module(self):
        from xax_spirv import compile_spirv_kernel

        program, kernel, spirv = collatz_kernel(64)
        target = spirv_vulkan_compute_target()
        objects = tuple(obj for obj in program.objects() if obj.kind not in (Kind.PROGRAM_ROOT, Kind.MODULE) and obj.cid != target.cid)
        result, reader, cid = _service(objects, kernel, target)
        self.assertEqual(result.artifact, compile_spirv_kernel(reader, cid, target.cid).artifact_bytes)


if __name__ == "__main__":
    unittest.main()
