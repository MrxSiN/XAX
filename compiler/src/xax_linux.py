"""Linux x86-64 hosted platform package and direct ELF64 executable emitter.

Everything here is explicit platform/ABI contract data or artifact packaging:

* syscalls are ordinary typed ``linux-x86_64-syscall-v1`` foreign declarations
  whose identity carries the exact register template (no libc, no wrappers);
* the process-entry contract is the only compiler-generated code: it calls the
  XAX entry and passes its returned status to ``exit_group`` (syscall 231);
* the executable is a static ELF64 ``ET_EXEC`` with one read/execute load
  segment and a non-executable stack marker.  No interpreter, dynamic section,
  relocation, libc, allocator, or runtime is emitted.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable

from xax_artifact import ArtifactSemanticRange
from xax_compiler import (
    EffectDomain,
    ForeignAllocatorContract,
    ForeignDeallocatorContract,
    Kind,
    LINUX_X86_64_SYSCALL_ABI,
    Permission,
    SemanticObject,
    StoreReader,
    X86_64_LINUX_ABI,
    X86_64_LINUX_ELF_EXEC_FORMAT,
    _decode_function_interface,
    _is_proof_type,
    bits_type,
    decode_bits_width,
    decode_native_target,
    effect_type,
    fail,
    foreign_function_symbol,
    heap_owner_type,
    heap_view_type,
    memory_effect_type,
    pointer_type,
    store_resolver,
)
from xax_x86_64 import NativeImage, compile_native, encode_syscall_name

# Linux x86-64 syscall numbers and flag values used by this package.
SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_MMAP, SYS_MUNMAP, SYS_OPENAT, SYS_EXIT_GROUP = 0, 1, 3, 9, 11, 257, 231
AT_FDCWD = (1 << 32) - 100  # int -100 as the 32-bit argument the kernel reads
PROT_READ_WRITE = 3
MAP_PRIVATE_ANONYMOUS = 0x22
PAGE_SIZE = 4096

_LIBRARY = b"linux"


@dataclass(frozen=True)
class LinuxApi:
    """Typed Linux x86-64 syscall surface.  Heap memory uses address space 2."""

    b8: SemanticObject
    b32: SemanticObject
    b64: SemanticObject
    bytes_rw: SemanticObject
    bytes_read: SemanticObject
    memory_effect: SemanticObject
    filesystem_effect: SemanticObject
    heap_owner: SemanticObject
    read: SemanticObject
    write: SemanticObject
    openat: SemanticObject
    close: SemanticObject
    mmap_anonymous: SemanticObject

    def munmap_view(self, view_pointer: SemanticObject, extent: int) -> SemanticObject:
        """``munmap`` of one whole proven heap view; the length is the exact view extent."""
        return foreign_function_symbol(
            _LIBRARY, encode_syscall_name(SYS_MUNMAP, ("$0", extent)),
            (view_pointer, heap_view_type(extent), self.memory_effect), (self.b64, self.memory_effect),
            abi=LINUX_X86_64_SYSCALL_ABI, deallocator=ForeignDeallocatorContract(0, 1),
        )

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (
            self.b8, self.b32, self.b64, self.bytes_rw, self.bytes_read,
            self.memory_effect, self.filesystem_effect, self.heap_owner,
        )

    @property
    def symbols(self) -> tuple[SemanticObject, ...]:
        return (self.read, self.write, self.openat, self.close, self.mmap_anonymous)


def linux_api() -> LinuxApi:
    b8, b32, b64 = bits_type(8), bits_type(32), bits_type(64)
    bytes_rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
    bytes_read = pointer_type(b8, Permission.READ, 1, space=2)
    memory = memory_effect_type()
    filesystem = effect_type(EffectDomain.FILESYSTEM, 0)
    heap = heap_owner_type()

    def syscall(number: int, inputs, outputs, arguments=None, **contracts) -> SemanticObject:
        return foreign_function_symbol(
            _LIBRARY, encode_syscall_name(number, arguments), inputs, outputs,
            abi=LINUX_X86_64_SYSCALL_ABI, **contracts,
        )

    # Every kernel result is the exact 64-bit rax value (-errno on failure).
    # Calls that read or write program memory are ordered by the memory effect.
    read = syscall(SYS_READ, (b32, bytes_rw, b64, filesystem, memory), (b64, filesystem, memory))
    write = syscall(SYS_WRITE, (b32, bytes_read, b64, filesystem, memory), (b64, filesystem, memory))
    openat = syscall(SYS_OPENAT, (b32, bytes_read, b32, b32, filesystem, memory), (b64, filesystem, memory))
    close = syscall(SYS_CLOSE, (b32, filesystem), (b64, filesystem))
    # Private anonymous mappings are zero-filled by the kernel; the fixed
    # template makes that guarantee part of the declaration identity.
    mmap_anonymous = syscall(
        SYS_MMAP, (b64, memory), (bytes_rw, heap, memory),
        (0, "$0", PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, (1 << 64) - 1, 0),
        allocator=ForeignAllocatorContract((0,), 0, 1, PAGE_SIZE, True),
    )
    return LinuxApi(b8, b32, b64, bytes_rw, bytes_read, memory, filesystem, heap, read, write, openat, close, mmap_anonymous)


# Process-entry adapter (x86-64 Linux):
#   sub rsp, 32        ; x64 home area; RSP%16 == 0 at process entry
#   call entry         ; XAX entry returns its status in eax
#   mov edi, eax
#   mov eax, 231       ; exit_group
#   syscall
#   ud2                ; exit_group does not return
_ENTRY_CALL_OFFSET = 4


def _process_entry(entry_displacement: int) -> bytes:
    return (
        b"\x48\x83\xec\x20"
        + b"\xe8" + entry_displacement.to_bytes(4, "little", signed=True)
        + b"\x89\xc7"
        + b"\xb8" + SYS_EXIT_GROUP.to_bytes(4, "little")
        + b"\x0f\x05\x0f\x0b"
    )


_STUB_SIZE = 32  # stub padded so the XAX image starts 16-byte aligned
_BASE_ADDRESS = 0x400000
_ELF_HEADER_SIZE = 64
_PROGRAM_HEADER_SIZE = 56
_PROGRAM_HEADER_COUNT = 2
_CODE_OFFSET = _ELF_HEADER_SIZE + _PROGRAM_HEADER_SIZE * _PROGRAM_HEADER_COUNT  # 176, 16-aligned


@dataclass(frozen=True)
class LinuxExecutable:
    data: bytes
    image: NativeImage
    target_cid: bytes
    semantic_ranges: tuple[ArtifactSemanticRange, ...]

    @property
    def artifact_bytes(self) -> bytes:
        return self.data

    @property
    def entry_offset(self) -> int:
        return _CODE_OFFSET

    parameter_widths: tuple[int, ...] = ()
    return_widths: tuple[int, ...] = (32,)


def emit_linux_elf_executable(image: NativeImage) -> tuple[bytes, int]:
    """Return ``(ELF bytes, file offset of the XAX image)`` for a compiled entry image."""
    stub = _process_entry(_STUB_SIZE + image.entry_offset - (_ENTRY_CALL_OFFSET + 5))
    code = stub.ljust(_STUB_SIZE, b"\xcc") + image.code
    file_size = _CODE_OFFSET + len(code)
    header = (
        b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            2,  # ET_EXEC
            62,  # EM_X86_64
            1,
            _BASE_ADDRESS + _CODE_OFFSET,
            _ELF_HEADER_SIZE,
            0,  # no section headers: nothing beyond the load image is emitted
            0,
            _ELF_HEADER_SIZE,
            _PROGRAM_HEADER_SIZE,
            _PROGRAM_HEADER_COUNT,
            64,
            0,
            0,
        )
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, _BASE_ADDRESS, _BASE_ADDRESS, file_size, file_size, PAGE_SIZE)  # PT_LOAD R+X
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)  # PT_GNU_STACK R+W
    return header + load + stack + code, _CODE_OFFSET + _STUB_SIZE


def validate_process_entry(reader: StoreReader, entry_cid: bytes) -> None:
    """Entry contract: only erased proof parameters, one bits<8|32> status, proof results."""
    resolve = store_resolver(reader)
    entry = resolve(entry_cid)
    if entry.kind != Kind.FUNCTION:
        fail("XAX.LINUX.ENTRY", entry_cid.hex(), "LINUX-ENTRY-FUNCTION", Kind.FUNCTION.name, entry.kind.name)
    _graph, parameters, returns = _decode_function_interface(entry, resolve)
    machine_parameters = [cid for cid in parameters if not _is_proof_type(resolve(cid))]
    machine_returns = [cid for cid in returns if not _is_proof_type(resolve(cid))]
    status_ok = len(machine_returns) == 1 and resolve(machine_returns[0]).body[:1] == b"\x01" and decode_bits_width(resolve(machine_returns[0])) in (8, 32)
    if machine_parameters or not status_ok:
        fail(
            "XAX.LINUX.ENTRY", entry_cid.hex(), "LINUX-PROCESS-ENTRY-CONTRACT",
            "fn(proof...) -> (bits<8|32>, proof...)", [len(machine_parameters), [cid.hex() for cid in machine_returns]],
        )


def compile_linux_executable(reader: StoreReader, entry_cid: bytes, target_cid: bytes) -> LinuxExecutable:
    resolve = store_resolver(reader)
    target = resolve(target_cid)
    description = decode_native_target(target)
    if (description.abi, description.image_format) != (X86_64_LINUX_ABI, X86_64_LINUX_ELF_EXEC_FORMAT):
        fail("XAX.LINUX.TARGET", target_cid.hex(), "LINUX-ELF-EXEC-TARGET", [X86_64_LINUX_ABI, X86_64_LINUX_ELF_EXEC_FORMAT], [description.abi, description.image_format])
    validate_process_entry(reader, entry_cid)
    image = compile_native(reader, entry_cid, target_cid)
    data, image_offset = emit_linux_elf_executable(image)
    ranges = tuple(
        ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, image_offset + item.start, image_offset + item.end)
        for item in image.semantic_ranges
    )
    return LinuxExecutable(data, image, target_cid, ranges)


def run_linux_executable(
    data: bytes,
    *,
    cwd: str | os.PathLike[str] | None = None,
    stdin: bytes = b"",
    timeout: float = 60.0,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> subprocess.CompletedProcess:
    """Test harness only: write the artifact to a temporary file and execute it."""
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "xax-program")
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, 0o755)
        return runner([path], cwd=cwd, input=stdin, capture_output=True, timeout=timeout, check=False)
