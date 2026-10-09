"""Running XAX-lowered helper images inside this process: authority record, W^X mappings, cache entries.

Tooling, not XAX semantics.  Several compiler components (hashing, store and graph decoding, CFG, typing, the store
verifier, the views backends) have an XAX-hosted native image and a Python bootstrap path.  ``AUTHORITY`` records,
per component, which one actually ran and why:

    {component, requested_authority, actual_authority, fallback_occurred, fallback_reason,
     semantic_root, native_artifact_digest}

With ``XAX_REQUIRE_NATIVE=1`` a fallback raises ``NativeFallback`` instead, so evidence that claims XAX-hosted
execution cannot silently come from the Python path.  An explicit opt-out (``XAX_<COMPONENT>_PYTHON=1``) requests
Python and is never an error.
"""

from __future__ import annotations

import ctypes
import hashlib
import mmap
import os
import platform
import stat
import sys
import sysconfig
import tempfile
from pathlib import Path

AUTHORITY: dict[str, dict] = {}


def bootstrap_dir() -> Path:
    """The canonical compiler stores: ``compiler/bootstrap`` in a source checkout, ``<prefix>/share/xax/bootstrap``
    in an installed wheel (``pyproject.toml`` data-files)."""
    checkout = Path(__file__).resolve().parents[1] / "bootstrap"
    return checkout if checkout.is_dir() else Path(sysconfig.get_path("data")) / "share" / "xax" / "bootstrap"


class NativeFallback(Exception):  # not RuntimeError/OSError/ValueError: loaders catch those to fall back
    """A component fell back to Python while ``XAX_REQUIRE_NATIVE=1``."""


def native_host() -> str | None:
    """None when this host runs native XAX helper images, else why not."""
    if not (sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")):
        return f"native XAX helper images run on Linux x86-64 only (host: {sys.platform} {platform.machine()})"
    return None


def _entry(component: str, actual: str, reason: str | None, requested: str = "xax") -> dict:
    entry = AUTHORITY.setdefault(component, {"component": component, "semantic_root": None, "native_artifact_digest": None})
    entry.update(requested_authority=requested, actual_authority=actual, fallback_occurred=requested != actual, fallback_reason=reason)
    return entry


def fallback(component: str, reason: str, opt_out: str | None = None, requested: str | None = None) -> None:
    """Record that ``component`` runs on the Python path; raise under ``XAX_REQUIRE_NATIVE=1`` unless Python was
    requested (an opt-out set, or ``requested="python"`` for a path that is Python by design)."""
    requested = requested or ("python" if opt_out and os.environ.get(opt_out) == "1" else "xax")
    _entry(component, "python", reason, requested)
    if requested == "xax" and os.environ.get("XAX_REQUIRE_NATIVE") == "1":
        raise NativeFallback(f"{component}: XAX-hosted execution required but fell back to Python: {reason}")


def usable(component: str, store_path: Path, opt_out: str) -> bool:
    """Whether ``component``'s native image may run here; a False answer is recorded as a fallback."""
    if os.environ.get(opt_out) == "1":
        reason = f"{opt_out}=1"
    else:
        reason = native_host() or (None if store_path.exists() else f"canonical store {store_path.name} not found")
    if reason is not None:
        fallback(component, reason, opt_out)
        return False
    return True


def loaded(component: str, semantic_root: bytes, code: bytes) -> None:
    """Record that ``component``'s native XAX image (``code``, lowered from ``semantic_root``) is the one running."""
    entry = _entry(component, "xax", None)
    entry.update(semantic_root=semantic_root.hex(), native_artifact_digest=hashlib.sha256(code).hexdigest())


def declined(component: str, count: int) -> None:
    """Count inputs a loaded native component declined, which the Python bootstrap then decided (accept or reject).
    Declines are the S-ladder's design (rejections and diagnostics stay Python, S7b), so they never raise."""
    entry = AUTHORITY.setdefault(component, {"component": component})
    entry["declined_inputs"] = entry.get("declined_inputs", 0) + count


# -- executable memory -------------------------------------------------------------------------------------------


def writable_mapping(size: int) -> tuple[mmap.mmap, int]:
    """``(mapping, address)``: fresh anonymous read-write memory; ``seal`` it before calling into it."""
    if not hasattr(mmap, "PROT_EXEC"):
        raise RuntimeError("host mmap does not expose executable mappings")
    mapping = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    return mapping, ctypes.addressof(ctypes.c_char.from_buffer(mapping))


def seal(address: int, size: int) -> None:
    """Make a ``writable_mapping`` read+execute only (W^X): it is never writable and executable at once."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
    if libc.mprotect(address, size, mmap.PROT_READ | mmap.PROT_EXEC) != 0:
        raise OSError(ctypes.get_errno(), "mprotect(PROT_READ | PROT_EXEC) failed")


def zeroed_array(element, count: int):
    """A ctypes array of ``count`` zero ``element``s backed by an anonymous private mapping (ADR-248).

    ``(element * count)()`` zero-fills its whole extent eagerly and keeps every page resident; the component views
    are hundreds of MiB, most of which a call never touches.  The kernel zero-fills a mapped page on first touch
    instead, so the contents every caller sees are identical (all zero until written, never re-zeroed between
    calls, as before) while untouched pages cost neither time nor resident memory.  The array keeps its mapping
    alive (``_mapping``; ``from_buffer`` also holds an export, so the mapping cannot be closed under it)."""
    flags = {"flags": mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS} if hasattr(mmap, "MAP_ANONYMOUS") else {}
    mapping = mmap.mmap(-1, max(count * ctypes.sizeof(element), 1), **flags)
    array = (element * count).from_buffer(mapping)
    array._mapping = mapping
    return array


def executable_mapping(code: bytes) -> tuple[mmap.mmap, int]:
    """``(mapping, address)`` of ``code`` in sealed read+execute memory.  Keep ``mapping`` alive while calling."""
    mapping, address = writable_mapping(len(code))
    mapping.write(code)
    seal(address, len(code))
    return mapping, address


# -- authenticated on-disk image cache ---------------------------------------------------------------------------

CACHE_MAGIC = b"XAXNC2\0\0"
_HEADER = len(CACHE_MAGIC) + 32 + 8 + 8 + 32  # magic, key, entry offset, code length, code digest


def cache_dir() -> Path | None:
    """The image cache directory, or None when it is unsafe to execute code from (shared or foreign-owned)."""
    directory = Path(os.environ.get("XAX_NATIVE_CACHE", Path.home() / ".cache" / "xax-native"))
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        status = directory.stat()
    except OSError:
        return None
    if hasattr(os, "getuid") and (status.st_uid != os.getuid() or status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        return None
    return directory


def cache_read(path: Path, key: bytes) -> tuple[bytes, int] | None:
    """``(code, entry offset)`` when ``path`` is a well-formed entry for exactly ``key`` whose code digest matches."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < _HEADER or data[:8] != CACHE_MAGIC or data[8:40] != key:
        return None
    entry_offset, length = int.from_bytes(data[40:48], "little"), int.from_bytes(data[48:56], "little")
    code = data[_HEADER:]
    if len(code) != length or entry_offset >= max(length, 1) or hashlib.sha256(code).digest() != data[56:88]:
        return None
    return code, entry_offset


def cache_entry(key: bytes, code: bytes, entry_offset: int) -> bytes:
    return CACHE_MAGIC + key + entry_offset.to_bytes(8, "little") + len(code).to_bytes(8, "little") + hashlib.sha256(code).digest() + code


def cache_write(path: Path, data: bytes) -> bool:
    """Publish ``data`` at ``path`` atomically: written whole to a private temporary file in the same directory,
    then renamed over ``path`` (ADR-250).  Concurrent writers of one entry race only on the rename, and every entry
    is a deterministic function of its key, so a reader sees either no file or one complete entry, never a torn one
    (``cache_read`` also re-checks the code digest).  False when the cache is unwritable, which only costs the next
    process a rebuild."""
    name = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".tmp-", delete=False) as handle:
            name = handle.name
            handle.write(data)
        os.replace(name, path)
        return True
    except OSError:
        if name is not None:
            try:
                os.unlink(name)
            except OSError:
                pass
        return False


# -- verified component stores (ADR-222) -----------------------------------------------------------------------

VERIFIED_MAGIC = b"XAXVS1\0\0"
_VERIFIER_IDENTITY: bytes | None = None
_VERIFIED_IN_PROCESS: set[bytes] = set()  # sha256 of the store bytes verify_component_store accepted in this process


def verifier_identity() -> bytes:
    """sha256 over every compiler source module and canonical bootstrap store: everything ``verify_store`` reads.

    A verified-store record is valid only for the exact verifier that produced it; any source or store change
    (including a regenerated helper store) changes this identity, so stale records are never consulted."""
    global _VERIFIER_IDENTITY
    if _VERIFIER_IDENTITY is None:
        digest = hashlib.sha256(VERIFIED_MAGIC)
        here = Path(__file__).resolve().parent
        sources = sorted({*here.glob("xax_*.py"), *here.glob("blake3.py")})  # the compiler's modules (pyproject py-modules)
        stores = sorted(bootstrap_dir().glob("*.xax"))
        for path in (*sources, *stores):
            digest.update(path.name.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
        _VERIFIER_IDENTITY = digest.digest()
    return _VERIFIER_IDENTITY


def verify_component_store(reader, name: str) -> None:
    """``verify_store(reader)`` for a committed compiler-component store, memoized in the native image cache.

    The first process to verify these exact store bytes with this exact verifier writes an authenticated record
    (``verified-<name>-<key>.bin``) next to the component's native image; later processes find it and skip the
    re-verification, which dominated cold start (ADR-222).  The record grants nothing the cache does not already
    hold: ``cache_dir`` only returns a private directory that already supplies executable images.  Without a
    usable cache, or with ``XAX_NATIVE_REVERIFY=1``, the store is verified every time."""
    from xax_compiler import verify_store

    store_digest = hashlib.sha256(reader.data).digest()
    directory = cache_dir() if os.environ.get("XAX_NATIVE_REVERIFY") != "1" else None
    if directory is None:
        verify_store(reader)
        _VERIFIED_IN_PROCESS.add(store_digest)
        return
    key = hashlib.sha256(VERIFIED_MAGIC + verifier_identity() + store_digest).digest()
    path = directory / f"verified-{name}-{key.hex()}.bin"
    record = VERIFIED_MAGIC + key
    try:
        if path.read_bytes() == record:
            entry = AUTHORITY.setdefault(f"verification:{name}", {"component": f"verification:{name}"})
            entry.update(store_verification="memoized", record=path.name)
            _VERIFIED_IN_PROCESS.add(store_digest)
            return
    except OSError:
        pass
    verify_store(reader)
    _VERIFIED_IN_PROCESS.add(store_digest)
    cache_write(path, record)  # only after verify_store accepted; an unwritable cache only costs a re-verification


def component_store_verified(reader) -> bool:
    """Whether ``verify_component_store`` accepted exactly ``reader``'s bytes in this process (ADR-250).  Lowering a
    component's image then need not run ``verify_store`` on the same bytes a second time."""
    return hashlib.sha256(reader.data).digest() in _VERIFIED_IN_PROCESS


# -- preparing component images ahead of the first verification (ADR-250) ----------------------------------------

# The XAX-hosted components a verification loads, in the order a first verification loads them.  The hash and both
# decoders are lowered by the bootstrap generator while they are built; loading cfg brings in the x86-64 views
# backend, which lowers every later image.
PREPARE_DECODERS = ("blake3-hash", "store-decoder", "graph-decoder")
PREPARE_COMPONENTS = (*PREPARE_DECODERS, "cfg", "x86-64-views-backend", "typing", "store-verifier")
# The opt-outs of the components that accelerate verification and lowering.  A ``prepare`` child sets those of the
# components it is not preparing, so it never loads (and lowers) another child's image; a store's verdict, its
# verified-store record and every lowered image are the same bytes on either path (the Python bootstrap decides
# whatever the XAX components decline), and a first verification already verifies the typing and backend stores
# with them unloaded.
_PREPARE_OPT_OUTS = {"cfg": "XAX_CFG_PYTHON", "typing": "XAX_TYPING_PYTHON", "store-verifier": "XAX_VERIFY_PYTHON"}
# ``prepare(parallel=True)``'s stages: each is a list of concurrent children ``(components, store only)``.
_PREPARE_STAGES = (
    ((PREPARE_DECODERS, False),),
    ((("cfg", "x86-64-views-backend"), False), (("typing",), True), (("store-verifier",), True)),
    ((("typing",), False), (("store-verifier",), False)),
)
_PREPARE_MARK = "XAX-PREPARE "
_STORE_NAMES = {"cfg": "cfg", "typing": "typing", "store-verifier": "store-verifier", "x86-64-views-backend": "xax_x86_64_backend"}


def _load_component(component: str):
    """Load ``component`` the way a verification does (its ``_native_*`` loader); the loaded object, or None."""
    import xax_compiler

    if component == "blake3-hash":
        import blake3

        return blake3._native_hasher()
    if component == "store-decoder":
        return xax_compiler._native_store_decoder()
    if component == "graph-decoder":
        return xax_compiler._native_graph_decoder()
    if component == "cfg":
        return xax_compiler._native_cfg()
    if component == "typing":
        return xax_compiler._native_typing()
    if component == "store-verifier":
        from xax_selfhost_verify import native_store_verifier

        return native_store_verifier()
    if component == "x86-64-views-backend":
        from xax_selfhost_x86_64_backend import native_backend

        return native_backend()
    raise ValueError(f"unknown component {component!r}; expected one of {PREPARE_COMPONENTS}")


def _load_store(component: str):
    """Load and verify ``component``'s committed store only (no image), writing its verified-store record."""
    if component == "cfg":
        from xax_selfhost_cfg import load_cfg_program as load
    elif component == "typing":
        from xax_selfhost_typing import load_typing_program as load
    elif component == "store-verifier":
        from xax_selfhost_verify import load_verifier_program as load
    elif component == "x86-64-views-backend":
        from xax_selfhost_x86_64_backend import load_backend_program as load
    else:
        raise ValueError(f"{component!r} has no separately verified store stage")
    return load()


def _prepare_here(component: str, fresh: bool = False, store_only: bool = False) -> dict:
    """Load one component (or, with ``store_only``, verify its store) in this process; say how it was obtained."""
    import time

    lowering = f"lowering:{component}"
    lowered_before = lowering in AUTHORITY
    already = AUTHORITY.get(component, {}).get("actual_authority") == "xax"
    start = time.perf_counter()
    try:
        if store_only:
            _load_store(component)
            loaded_object, reason = True, None
        else:
            loaded_object = _load_component(component)
            reason = None if loaded_object is not None else (AUTHORITY.get(component, {}).get("fallback_reason") or "not loaded")
    except NativeFallback as error:
        loaded_object, reason = None, str(error)
    except Exception as error:  # noqa: BLE001 - reported per component, never raised past prepare
        loaded_object, reason = None, f"{type(error).__name__}: {error}"
    seconds = round(time.perf_counter() - start, 3)
    if loaded_object is None:
        status = "unavailable"
    elif store_only:
        record = AUTHORITY.get(f"verification:{_STORE_NAMES[component]}", {})
        status = "memoized" if record.get("store_verification") == "memoized" else "verified"
    elif lowering in AUTHORITY and (fresh or not lowered_before):
        status = "lowered"
    elif already and not fresh:
        status = "loaded"
    else:
        status = "cached"
    result = {"component": component, "status": status, "seconds": seconds, "pid": os.getpid()}
    if not store_only:
        result.update(authority=AUTHORITY.get(component), lowering=AUTHORITY.get(lowering))
    if reason is not None:
        result["reason"] = reason
    return result


def _prepare_child(components: list[str], store_only: bool = False) -> None:
    """Child-process entry for ``prepare(parallel=True)``: prepare ``components`` in order and print the results."""
    import json

    import xax_compiler  # noqa: F401 - the loaders need the finished module

    results = [_prepare_here(component, fresh=True, store_only=store_only) for component in components]
    print(_PREPARE_MARK + json.dumps(results), flush=True)


def _prepare_process(components: list[str], directory: Path, timeout: float | None, store_only: bool = False) -> list[dict]:
    import json
    import subprocess
    import time

    here = str(Path(__file__).resolve().parent)
    opt_outs = {variable: "1" for component, variable in _PREPARE_OPT_OUTS.items() if component not in components or store_only}
    environment = {**os.environ, "XAX_NATIVE_CACHE": str(directory), **opt_outs}
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (here, environment.get("PYTHONPATH"))))
    command = [sys.executable, "-c", f"import xax_native; xax_native._prepare_child({list(components)!r}, {store_only!r})"]
    start = time.perf_counter()
    try:
        completed = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        reason, completed = f"{type(error).__name__}: {error}", None
    if completed is not None:
        for line in reversed(completed.stdout.splitlines()):
            if line.startswith(_PREPARE_MARK):
                return json.loads(line[len(_PREPARE_MARK):])
        reason = f"exit {completed.returncode}: {(completed.stderr or completed.stdout).strip()[-2000:]}"
    seconds = round(time.perf_counter() - start, 3)
    return [{"component": component, "status": "failed", "seconds": seconds, "reason": reason} for component in components]


def _in_parallel(jobs: list) -> list[dict]:
    """Run ``jobs`` (zero-argument callables returning result lists) concurrently; their results, concatenated."""
    from concurrent.futures import ThreadPoolExecutor

    if not jobs:
        return []
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        return [result for batch in pool.map(lambda job: job(), jobs) for result in batch]


def prepare(parallel: bool = False, components=None, timeout: float | None = None) -> dict[str, dict]:
    """Lower every missing XAX-hosted component image into the image cache before a host's first verification.

    Host surface (``xax_contract``, ADR-250).  A first verification otherwise loads each component in turn,
    verifying its store and lowering its image when the cache (``XAX_NATIVE_CACHE``) lacks them.  ``prepare`` does
    that work up front and leaves the cache holding every image and verified-store record, so later processes
    start warm.  It changes nothing XAX means: an image and a record are the same bytes whichever process made them.

    Sequential (the default), the components load in this process in ``PREPARE_COMPONENTS`` order and stay loaded.
    With ``parallel=True`` the work runs in child processes, in three stages (``_PREPARE_STAGES``): (1) one child
    readies the hash and both decoders (``PREPARE_DECODERS``), which every later stage reads; (2) concurrently, one
    child lowers the x86-64 views backend and the cfg image while one child per remaining component verifies its
    store; (3) concurrently, one child per remaining component lowers its image with that backend.  Cache entries are published by atomic rename
    (``cache_write``) only after their store verified, so concurrent processes, other hosts' first verifications
    included, never read a torn or unverified entry.

    Returns ``{component: {status, seconds, total_seconds, pid, authority, lowering, store?, reason?}}``.
    ``status`` is ``"cached"`` (the image was already in the cache), ``"lowered"`` (lowered now), ``"loaded"``
    (already loaded in this process), ``"unavailable"`` (this host cannot run it, or it fell back; ``reason`` says
    why) or ``"failed"`` (its child process failed).  ``seconds`` is the component's own load time, ``total_seconds``
    the whole call's wall time; ``store`` (parallel only) is stage 2's result (``status`` ``"verified"`` or
    ``"memoized"``).  ``authority`` and ``lowering`` are the ``AUTHORITY`` entries of the process that loaded the
    component.  Under ``XAX_REQUIRE_NATIVE=1`` a fallback is reported as ``"unavailable"``, never raised."""
    import time

    selected = list(PREPARE_COMPONENTS if components is None else components)
    for component in selected:
        if component not in PREPARE_COMPONENTS:
            raise ValueError(f"unknown component {component!r}; expected one of {PREPARE_COMPONENTS}")
    selected = [component for component in PREPARE_COMPONENTS if component in selected]
    directory = cache_dir()
    reason = native_host() or (None if directory is not None or not parallel else "no usable image cache directory (XAX_NATIVE_CACHE)")
    if reason is not None:
        return {component: {"component": component, "status": "unavailable", "seconds": 0.0, "total_seconds": 0.0, "reason": reason}
                for component in selected}
    start = time.perf_counter()
    stores, results = {}, []
    if not parallel:
        results = [_prepare_here(component) for component in selected]
    else:
        for stage in _PREPARE_STAGES:
            jobs = [(tuple(component for component in components if component in selected), store_only) for components, store_only in stage]
            jobs = [(components, store_only) for components, store_only in jobs if components]
            batches = _in_parallel([(lambda components=components, store_only=store_only: [
                {**result, "store_only": store_only} for result in _prepare_process(components, directory, timeout, store_only)])
                for components, store_only in jobs])
            for result in batches:
                if result.pop("store_only"):
                    stores[result["component"]] = result
                else:
                    results.append(result)
    total = round(time.perf_counter() - start, 3)
    prepared = {}
    for result in results:
        prepared[result["component"]] = {**result, "total_seconds": total}
        if result["component"] in stores:
            prepared[result["component"]]["store"] = stores[result["component"]]
    return {component: prepared[component] for component in selected}
