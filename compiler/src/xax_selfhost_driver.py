"""Self-hosting step S10 (ADR-264, ADR-265): the compiler driver as one XAX program.

``xax_x86_64_views.compile_x86_64_views`` turns a program store into machine code: Python reads the store, the XAX
decoders check it, Python builds the backend's object table (``xax_riscv64._object_table``), and the XAX backend
lowers it.  This module makes that whole path one XAX function on the ``x86_64-linux-views-v2`` profile:

    drive(arguments: ptr<b8,READ,space 2>, heap_view<ARGUMENTS_EXTENT>, memory, filesystem, memory x BUFFERS)
        -> (the same values, bits<64> status)

``arguments`` holds three NUL-terminated paths: the program store, a target-package store (its root is the target
object), and the output file.  The driver owns every buffer (``mmap`` and ``heap.view``, released with ``munmap``),
does its own file I/O (``openat``, ``read``, ``write``, ``close``), and calls the committed XAX components directly
(S15c.4, ADR-302: a file or object past the driver's capacity is rejected with ``XAX.DRIVER.CAPACITY``):

* the store decoder (S3/S8a) and the S2 hash decide the container, its digest, and each object envelope and CID
  (S8b.1), in store order, as ``StoreReader`` and ``get`` do;
* the graph decoder (S3c/S8b.2) streams each graph fragment;
* the target package's root must be a target whose identity is a views profile (the check
  ``compile_x86_64_views`` makes, with its diagnostic);
* the XAX x86-64 backend (S7) lowers the root module's first function with the target, deciding its legality.

The output file receives the image's code (status ``IMAGE``) or the first rejection's diagnostic record as
little-endian 64-bit words (status ``REJECTED``, ``xax_selfhost_diagnostics.decode_record``).  ``DECLINED`` means
an input beyond a component's capacity or one a component defers; ``FAILED`` an I/O error.  S10e (ADR-266): before
lowering, the driver verifies the store semantically (``xax_selfhost_semantic``).

S11 (ADR-267): the store's entry is ``main``, the Linux process entry for ``x86_64-linux-views-exec-v1``: it copies
``argv[1..3]`` into an arguments view, calls ``drive``, and ends the process with ``exit_group(status)`` (``FAILED``
unless there are exactly three paths and each fits).  Under that profile the driver writes the static ELF64
executable (``xax_x86_64_views.views_executable``) instead of the bare code, so the driver lowers itself to the
executable it runs as.

S13a (ADR-281): the general driver's first argument is a command.  ``lower <store> <target package> <output>`` is the
path above.  ``build <snapshot store> <artifact> <provenance>`` is ``xax_build.build`` for the snapshot's request:
after verification it reads the snapshot, its request, and the package's build entry, makes ``build``'s rejections
(the root, external inputs, required signatures, requested artifacts) with its exact diagnostics, lowers the entry for
the request's Linux x86-64 ELF target, and writes the artifact and the canonical provenance object's envelope, the
digest and the CID derived with the S2 hash.  ``build``'s other paths (other targets)
decline.  S15e.6h.3 (ADR-356): an APK on an Android shared-object target is the Android program's, called
twice (the roots, then the APK).  S15e.6i.1 (ADR-357): ``build-signed <snapshot> <artifact> <provenance> <transport>
[inputs]`` is ``build`` with one SIGN effect (the package's only SIGN capability, the transport file's bytes); a signed
APK is signed by the XAX APK signer program, which makes ``build``'s signing rejections.

W2 (ADR-361): both driver stores are frozen.  The Python builder that made them is deleted; this module loads the
committed stores and runs them as processes.  They change only by ledger transactions (``xax_selfhost_evolution``).
"""

from __future__ import annotations

from pathlib import Path

from xax_compiler import Kind, SemanticObject, StoreReader
from xax_native import bootstrap_dir

STORE_PATH = bootstrap_dir() / "xax_compiler_driver.xax"
GENERAL_STORE_PATH = bootstrap_dir() / "xax_compiler_driver_general.xax"  # S12e.2 (ADR-276)
IMAGE, REJECTED, DECLINED, FAILED = 0, 1, 2, 3
# The general driver's commands, argv[1] (S13a, ADR-281; S13b, ADR-282), with the file arguments each takes.
LOWER, BUILD, VERIFY, INSPECT, RESOLVE, EDIT, TRUSTED = 0, 1, 2, 3, 4, 5, 6  # (S13c, ADR-283: ``resolve``; S15d.1, ADR-304: ``edit``;


def load_driver_program(general: bool = False) -> tuple[StoreReader, SemanticObject]:
    from xax_native import verify_component_store

    reader = StoreReader((GENERAL_STORE_PATH if general else STORE_PATH).read_bytes())
    verify_component_store(reader, "compiler-driver-general" if general else "compiler-driver")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def target_package(target: SemanticObject) -> bytes:
    """A target-package store: ``target`` as the root object."""
    from xax_compiler import write_store

    return write_store(target.cid, [target])


class NativeDriver:
    """S11 (ADR-267): the driver as a Linux process.  The image (lowered by the XAX backend for
    ``x86_64-linux-views-exec-v1``) is written once as its static ELF64 executable; ``run`` executes it with the three
    paths as its arguments and returns its exit status.  No Python runs inside the process."""

    timeout = None  # seconds per process; None waits

    def __init__(self, image=None) -> None:
        from xax_compiler import x86_64_views_exec_target
        from xax_x86_64_views import compile_x86_64_views, views_executable

        if image is None:
            reader, function = load_driver_program()
            image = compile_x86_64_views(reader, function.cid, x86_64_views_exec_target(), backend="xax")
        self.image = image
        self._install(views_executable(image))

    def _install(self, executable: bytes) -> None:
        import os
        import tempfile

        self.executable = executable
        self._directory = tempfile.TemporaryDirectory(prefix="xax-driver-")
        self.path = Path(self._directory.name) / "xax-driver"
        self.path.write_bytes(self.executable)
        os.chmod(self.path, 0o755)

    def run(self, store_path: str | Path, target_path: str | Path, output_path: str | Path) -> int:
        """The process's exit status (``IMAGE`` .. ``FAILED``); a negative value is the signal that ended it."""
        return self._process(store_path, target_path, output_path)

    def _process(self, *arguments: str | Path) -> int:
        import subprocess

        return subprocess.run([str(self.path), *(str(item) for item in arguments)], check=False, timeout=self.timeout).returncode


class NativeGeneralDriver(NativeDriver):
    """S13a (ADR-281), S13b (ADR-282): the general driver as a Linux process.  Its first argument is the command:
    ``lower`` (a program store, a target package, the output), ``build`` (a build snapshot store, the artifact, its
    provenance), ``verify`` or ``inspect`` (a store, the output), ``resolve`` (a request store, the snapshot store).
    S15c.2 (ADR-300): ``build`` and ``resolve`` take external input files after their own arguments, up to
    ``xax_selfhost_evolution.INPUTS_LIMIT`` in the committed compiler (S15d.3, ADR-306)."""

    def __init__(self, image=None) -> None:
        """``image``: the driver as the views backend lowered it (``compile_x86_64_views``).  None (ADR-382): the pinned
        seed, the compiler the driver store built itself into, checked against its pin (``xax_selfhost_seed``); the
        views profile cannot lower the driver since it uses ``growable.load.bits.le`` (ledger 0009)."""
        if image is not None:
            super().__init__(image)
            return
        import hashlib

        from xax_selfhost_seed import SEED_PATH, SEED_SHA256

        executable = SEED_PATH.read_bytes()
        if hashlib.sha256(executable).hexdigest() != SEED_SHA256:
            raise RuntimeError(f"{SEED_PATH} is not the pinned seed {SEED_SHA256}")
        self.image = None
        self._install(executable)

    def run(self, store_path: str | Path, target_path: str | Path, output_path: str | Path) -> int:
        return self._process("lower", store_path, target_path, output_path)

    def build(self, snapshot_path: str | Path, artifact_path: str | Path, provenance_path: str | Path, *inputs: str | Path) -> int:
        """The exit status; on ``IMAGE`` the artifact and the provenance object's envelope are written, on ``REJECTED``
        the diagnostic record is in the artifact's file.  ``inputs``: the external input files (S15c.2)."""
        return self._process("build", snapshot_path, artifact_path, provenance_path, *inputs)

    def build_signed(self, snapshot_path: str | Path, artifact_path: str | Path, provenance_path: str | Path, transport_path: str | Path,
                     *inputs: str | Path) -> int:
        """S15e.6i.1 (ADR-357): ``build`` with one SIGN effect, the package's only SIGN capability, whose value is the
        transport file's bytes (``xax_apk_signing.encode_private_signing_capability``)."""
        return self._process("build-signed", snapshot_path, artifact_path, provenance_path, transport_path, *inputs)

    def verify(self, store_path: str | Path, output_path: str | Path) -> int:
        """S13b: ``IMAGE`` (an empty output) when the store verifies; ``REJECTED`` with the diagnostic record."""
        return self._process("verify", store_path, output_path)

    def inspect(self, store_path: str | Path, output_path: str | Path) -> int:
        """S13b: on ``IMAGE`` the verified store's inspection record (``decode_inspection``)."""
        return self._process("inspect", store_path, output_path)

    def resolve(self, request_path: str | Path, snapshot_path: str | Path, *inputs: str | Path) -> int:
        """S13c: on ``IMAGE`` the snapshot store for the request store's request (``xax_selfhost_resolve``); S15c.2: its
        external input digests are those of ``inputs``."""
        return self._process("resolve", request_path, snapshot_path, *inputs)

    def resolve_trusted(self, request_path: str | Path, snapshot_path: str | Path, trust_path: str | Path, *inputs: str | Path) -> int:
        """S15c.5 (ADR-309): ``resolve`` under the trust file's policy and signatures
        (``xax_selfhost_resolve.trust_file``)."""
        return self._process("resolve-trusted", request_path, snapshot_path, trust_path, *inputs)

    def view(self, store_path: str | Path, selector_path: str | Path, output_path: str | Path) -> int:
        """S16a (ADR-360): ``edit`` with a view selector: on ``IMAGE`` the store's functions (an empty selector) or function
        ``F<n>`` with workspace-local handles, as text."""
        return self._process("edit", store_path, selector_path, output_path)

    def apply(self, store_path: str | Path, batch_path: str | Path, output_path: str | Path) -> int:
        """S16a (ADR-360): ``edit`` with a batch (``R <root>``, ``F<n>``, edits): on ``IMAGE`` the store its edits make;
        ``REJECTED`` with the diagnostic record."""
        return self._process("edit", store_path, batch_path, output_path)

    def explain(self, store_path: str | Path, record_path: str | Path, output_path: str | Path) -> int:
        """S16a (ADR-360): ``edit`` with a diagnostic record: on ``IMAGE`` its text (any verified store serves)."""
        return self._process("edit", store_path, record_path, output_path)


def decode_inspection(data: bytes) -> dict:
    """``xaxc inspect``'s JSON object from the record ``inspect`` wrote (little-endian words): the root CID, then per
    object in store order its kind, reference count, CID, and reference CIDs.  It renders words (CID words to hex, a
    kind number to its lowercase name) and decides nothing."""
    words = [int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)]
    position = 0

    def take(count: int):
        nonlocal position
        position += count
        return words[position - count:position]

    def cid() -> str:
        return b"".join(word.to_bytes(8, "big") for word in take(4)).hex()

    root = cid()
    (count,) = take(1)
    objects = []
    for _ in range(count):
        kind, references = take(2)
        objects.append({"cid": cid(), "kind": Kind(kind).name.lower(), "references": [cid() for _ in range(references)]})
    if position != len(words):
        raise ValueError(f"inspection record has {len(words) - position} trailing words")
    return {"root_cid": root, "objects": objects}
