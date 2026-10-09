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


# -- verified component stores (ADR-222) -----------------------------------------------------------------------

VERIFIED_MAGIC = b"XAXVS1\0\0"
_VERIFIER_IDENTITY: bytes | None = None


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

    directory = cache_dir() if os.environ.get("XAX_NATIVE_REVERIFY") != "1" else None
    if directory is None:
        verify_store(reader)
        return
    key = hashlib.sha256(VERIFIED_MAGIC + verifier_identity() + hashlib.sha256(reader.data).digest()).digest()
    path = directory / f"verified-{name}-{key.hex()}.bin"
    record = VERIFIED_MAGIC + key
    try:
        if path.read_bytes() == record:
            entry = AUTHORITY.setdefault(f"verification:{name}", {"component": f"verification:{name}"})
            entry.update(store_verification="memoized", record=path.name)
            return
    except OSError:
        pass
    verify_store(reader)
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
            handle.write(record)
        os.replace(handle.name, path)
    except OSError:
        pass  # an unwritable cache only costs the next process a re-verification
