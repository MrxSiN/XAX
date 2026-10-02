"""Linux x86-64 hosted platform package and direct ELF64 executable emitter.

Everything here is explicit platform/ABI contract data or artifact packaging:

* syscalls are ordinary typed ``linux-x86_64-syscall-v1`` foreign declarations
  whose identity carries the exact register template (no libc, no wrappers);
* the process-entry contract is the only compiler-generated code: it calls the
  XAX entry and passes its returned status to ``exit_group`` (syscall 231);
* ``x86_64-linux-elf-exec-v1`` emits a static ELF64 ``ET_EXEC`` with one
  read/execute load segment and a non-executable stack marker: no interpreter,
  dynamic section, relocation, libc, allocator, or runtime;
* ``x86_64-linux-elf-dynexec-v1`` explicitly requests the system dynamic
  loader: ``PT_INTERP``, ``DT_NEEDED`` derived only from declared
  ``sysv-x86_64-c`` imports, and bind-now GOT relocations.  It adds no libc
  dependency of its own; a library pulls in only what its soname requires.
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
    SYSV_X86_64_C_ABI,
    Permission,
    SemanticObject,
    StoreReader,
    X86_64_LINUX_ABI,
    X86_64_LINUX_ELF_DYNAMIC_FORMAT,
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
from xax_elf import c_string_table, dynamic, hash_section, program_header, rela, symbol
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


def c_function(library: bytes, name: bytes, inputs, outputs) -> SemanticObject:
    """Typed ``sysv-x86_64-c`` import of ``name`` from the shared library ``library`` (a DT_NEEDED soname)."""
    return foreign_function_symbol(library, name, inputs, outputs, abi=SYSV_X86_64_C_ABI)


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


_STUB_SIZE = 32  # adapter padded so the XAX image starts 16-byte aligned
_BASE_ADDRESS = 0x400000
_ELF_HEADER_SIZE = 64
_PROGRAM_HEADER_SIZE = 56
_SYMBOL_SIZE = 24
_RELA_SIZE = 24
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR, PT_GNU_STACK = 1, 2, 3, 6, 0x6474E551
PF_R, PF_W, PF_X = 4, 2, 1
R_X86_64_GLOB_DAT = 6
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 0, 1, 4, 5, 6, 7, 8, 9, 10, 11
DT_FLAGS, DF_BIND_NOW, DT_FLAGS_1, DF_1_NOW = 30, 8, 0x6FFFFFFB, 1
# Fixed by the x86_64-linux-elf-dynexec-v1 profile identity, never inferred.
DYNAMIC_INTERPRETER = b"/lib64/ld-linux-x86-64.so.2"


@dataclass(frozen=True)
class LinuxExecutable:
    data: bytes
    image: NativeImage
    target_cid: bytes
    semantic_ranges: tuple[ArtifactSemanticRange, ...]
    entry_offset: int  # file offset of the process-entry adapter
    needed: tuple[bytes, ...] = ()
    parameter_widths: tuple[int, ...] = ()
    return_widths: tuple[int, ...] = (32,)

    @property
    def artifact_bytes(self) -> bytes:
        return self.data


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _elf_header(entry_address: int, program_headers: int) -> bytes:
    return b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8) + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        62,  # EM_X86_64
        1,
        entry_address,
        _ELF_HEADER_SIZE,
        0,  # no section headers: nothing beyond the load image is emitted
        0,
        _ELF_HEADER_SIZE,
        _PROGRAM_HEADER_SIZE,
        program_headers,
        64,
        0,
        0,
    )


def _adapter_and_image(image: NativeImage) -> bytearray:
    stub = _process_entry(_STUB_SIZE + image.entry_offset - (_ENTRY_CALL_OFFSET + 5))
    return bytearray(stub.ljust(_STUB_SIZE, b"\xcc") + image.code)


_STACK_HEADER = program_header(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16)


def _emit_static(image: NativeImage) -> tuple[bytes, int, tuple[bytes, ...]]:
    code_offset = _ELF_HEADER_SIZE + 2 * _PROGRAM_HEADER_SIZE  # 176, 16-aligned
    code = _adapter_and_image(image)
    file_size = code_offset + len(code)
    load = program_header(PT_LOAD, PF_R | PF_X, 0, _BASE_ADDRESS, file_size, file_size, PAGE_SIZE)
    return _elf_header(_BASE_ADDRESS + code_offset, 2) + load + _STACK_HEADER + bytes(code), code_offset, ()


def _emit_dynamic(image: NativeImage) -> tuple[bytes, int, tuple[bytes, ...]]:
    """ET_EXEC with PT_INTERP, DT_NEEDED from declared imports, and bind-now GOT slots."""
    imports = sorted({(library, name) for _offset, library, name in image.foreign_calls})
    names = [name for _library, name in imports]
    if len(set(names)) != len(names):
        # ELF symbol lookup is global, so one name cannot be bound to two libraries.
        fail("XAX.LINUX.IMPORT", "elf", "LINUX-IMPORT-SYMBOL-UNIQUE", "one library per imported symbol", [list(item) for item in imports])
    needed = tuple(sorted({library for library, _name in imports}))
    strings, string_offsets = c_string_table((*needed, *names))
    interpreter = DYNAMIC_INTERPRETER + b"\x00"
    header_count = 6
    interp_offset = _ELF_HEADER_SIZE + header_count * _PROGRAM_HEADER_SIZE
    symtab_offset = _align(interp_offset + len(interpreter), 8)
    strtab_offset = symtab_offset + _SYMBOL_SIZE * (len(names) + 1)
    hash_bytes = hash_section((b"", *names))
    hash_offset = _align(strtab_offset + len(strings), 8)
    rela_offset = _align(hash_offset + len(hash_bytes), 8)
    code_offset = _align(rela_offset + _RELA_SIZE * len(names), 16)
    code = _adapter_and_image(image)
    text_end = code_offset + len(code)
    rw_offset = _align(text_end, 8)
    rw_address = _align(_BASE_ADDRESS + text_end, PAGE_SIZE) + rw_offset % PAGE_SIZE
    address = lambda offset: _BASE_ADDRESS + offset  # the R+X segment maps file offset 0 at the base
    entries = [(DT_NEEDED, string_offsets[library]) for library in needed] + [
        (DT_HASH, address(hash_offset)), (DT_STRTAB, address(strtab_offset)), (DT_SYMTAB, address(symtab_offset)),
        (DT_STRSZ, len(strings)), (DT_SYMENT, _SYMBOL_SIZE), (DT_RELA, address(rela_offset)),
        (DT_RELASZ, _RELA_SIZE * len(names)), (DT_RELAENT, _RELA_SIZE),
        (DT_FLAGS, DF_BIND_NOW), (DT_FLAGS_1, DF_1_NOW), (DT_NULL, 0),
    ]
    dynamic_bytes = b"".join(dynamic(tag, value) for tag, value in entries)
    got_address = rw_address + len(dynamic_bytes)
    slot = {name: got_address + 8 * index for index, name in enumerate(names)}
    for position, _library, name in image.foreign_calls:
        site = code_offset + _STUB_SIZE + position
        code[site - code_offset : site - code_offset + 4] = (slot[name] - (address(site) + 4)).to_bytes(4, "little", signed=True)
    symbols = bytes(_SYMBOL_SIZE) + b"".join(symbol(string_offsets[name], 0x12, 0, 0, 0, 0) for name in names)  # GLOBAL FUNC, undefined
    relocations = b"".join(rela(slot[name], index + 1, R_X86_64_GLOB_DAT) for index, name in enumerate(names))
    rw_size = len(dynamic_bytes) + 8 * len(names)
    headers = b"".join((
        program_header(PT_PHDR, PF_R, _ELF_HEADER_SIZE, address(_ELF_HEADER_SIZE), header_count * _PROGRAM_HEADER_SIZE, header_count * _PROGRAM_HEADER_SIZE, 8),
        program_header(PT_INTERP, PF_R, interp_offset, address(interp_offset), len(interpreter), len(interpreter), 1),
        program_header(PT_LOAD, PF_R | PF_X, 0, _BASE_ADDRESS, text_end, text_end, PAGE_SIZE),
        program_header(PT_LOAD, PF_R | PF_W, rw_offset, rw_address, rw_size, rw_size, PAGE_SIZE),
        program_header(PT_DYNAMIC, PF_R | PF_W, rw_offset, rw_address, len(dynamic_bytes), len(dynamic_bytes), 8),
        _STACK_HEADER,
    ))
    out = bytearray(_elf_header(address(code_offset), header_count) + headers)
    for offset, blob in ((interp_offset, interpreter), (symtab_offset, symbols), (strtab_offset, strings), (hash_offset, hash_bytes), (rela_offset, relocations), (code_offset, bytes(code))):
        out.extend(bytes(offset - len(out)))
        out.extend(blob)
    out.extend(bytes(rw_offset - len(out)))
    out.extend(dynamic_bytes + bytes(8 * len(names)))
    return bytes(out), code_offset, needed


def emit_linux_elf_executable(image: NativeImage, *, dynamic_loader: bool = False) -> tuple[bytes, int, tuple[bytes, ...]]:
    """Return ``(ELF bytes, adapter file offset, DT_NEEDED libraries)``.

    The dynamic loader appears only when the target profile requests it; a
    static profile with foreign C imports is rejected, never silently upgraded.
    """
    if image.foreign_calls and not dynamic_loader:
        fail("XAX.LINUX.DYNAMIC_REQUIRED", "elf", "LINUX-DYNAMIC-LOADER-EXPLICIT", "x86_64-linux-elf-dynexec-v1", "static profile with C imports")
    return _emit_dynamic(image) if dynamic_loader else _emit_static(image)


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
    description = decode_native_target(resolve(target_cid))
    formats = (X86_64_LINUX_ELF_EXEC_FORMAT, X86_64_LINUX_ELF_DYNAMIC_FORMAT)
    if description.abi != X86_64_LINUX_ABI or description.image_format not in formats:
        fail("XAX.LINUX.TARGET", target_cid.hex(), "LINUX-ELF-EXEC-TARGET", [X86_64_LINUX_ABI, list(formats)], [description.abi, description.image_format])
    validate_process_entry(reader, entry_cid)
    image = compile_native(reader, entry_cid, target_cid)
    data, adapter_offset, needed = emit_linux_elf_executable(image, dynamic_loader=description.image_format == X86_64_LINUX_ELF_DYNAMIC_FORMAT)
    image_offset = adapter_offset + _STUB_SIZE
    ranges = tuple(
        ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, image_offset + item.start, image_offset + item.end)
        for item in image.semantic_ranges
    )
    return LinuxExecutable(data, image, target_cid, ranges, adapter_offset, needed)


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
