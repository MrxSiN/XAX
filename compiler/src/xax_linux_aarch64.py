"""Linux AArch64 hosted platform package and direct ELF64 executable emitter (ADR-123).

The same AAPCS64 lowerer serves bare metal, Android, and this profile; Linux
adds only explicit contract data and artifact packaging:

* syscalls are typed ``linux-aarch64-syscall-v1`` declarations whose identity
  carries the exact register template (the x86-64 template format, ADR-085),
  so no argument is ever supplied implicitly;
* each referenced syscall gets one compiler-generated thunk (argument
  placement from the template, ``mov x8, #nr``, ``svc #0``, ``ret``).  A
  declared allocator contract adds the explicit nullable projection of the
  kernel's ``-4095..-1`` error range, exactly as on x86-64;
* ``e_entry`` is an 8-byte compiler-generated stub, ``bl entry`` then
  ``brk``: the entry function ends the process with an explicit
  ``exit_group``, and returning from it is an explicit trap (ADR-076);
* ``aarch64-linux-elf-exec-v1`` is a static ELF64 ``ET_EXEC``: no interpreter,
  dynamic section, relocation, libc, allocator, or runtime;
* ``aarch64-linux-elf-dynexec-v1`` explicitly requests the glibc dynamic loader:
  ``PT_INTERP``, ``DT_NEEDED`` derived only from declared ``aapcs64-linux-c``
  imports, bind-now ``R_AARCH64_GLOB_DAT`` GOT slots, and one
  ``adrp``/``ldr``/``br`` thunk per imported symbol.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import platform
import struct
from dataclasses import dataclass
from typing import Callable

from xax_aarch64 import Aarch64Bundle, _move_immediate, compile_aarch64_bundle_bound_target
from xax_artifact import ArtifactSemanticRange
from xax_compiler import (
    AAPCS64_LINUX_C_ABI,
    AARCH64_LINUX_ABI,
    AARCH64_LINUX_ELF_DYNAMIC_FORMAT,
    AARCH64_LINUX_ELF_EXEC_FORMAT,
    EffectDomain,
    FOREIGN_FUNCTION_PREFIX,
    ForeignAllocatorContract,
    ForeignDeallocatorContract,
    Kind,
    LINUX_AARCH64_SYSCALL_ABI,
    Permission,
    SemanticObject,
    StoreReader,
    bits_type,
    decode_foreign_function,
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
from xax_linux import LinuxApi, validate_process_entry
from xax_x86_64 import decode_syscall_name, encode_syscall_name

# Linux generic (asm-generic/unistd.h) syscall numbers used by this package.
SYS_OPENAT, SYS_CLOSE, SYS_READ, SYS_WRITE, SYS_EXIT_GROUP, SYS_MUNMAP, SYS_MMAP = 56, 57, 63, 64, 94, 215, 222
AT_FDCWD = (1 << 32) - 100
PROT_READ_WRITE = 3
MAP_PRIVATE_ANONYMOUS = 0x22
PAGE_SIZE = 4096
SEGMENT_ALIGN = 0x10000  # valid for 4, 16, and 64 KiB kernel page sizes
_LIBRARY = b"linux"
DYNAMIC_INTERPRETER = b"/lib/ld-linux-aarch64.so.1"
# Return-from-entry trap (brk immediate "XA").
_BRK_ENTRY_RETURNED = 0x5841
_SVC0, _RET = 0xD4000001, 0xD65F03C0
# Allocator projection: cmn x0, #4095; csel x0, xzr, x0, hs.
_KERNEL_ERROR_TO_NULL = (0xB13FFC1F, 0x9A8023E0)
_SYSCALL_STAGING = 9  # x9..x14 hold the incoming operands while the template places them


def _syscall(number: int, inputs, outputs, arguments=None, **contracts) -> SemanticObject:
    return foreign_function_symbol(_LIBRARY, encode_syscall_name(number, arguments), inputs, outputs, abi=LINUX_AARCH64_SYSCALL_ABI, **contracts)


def c_function(library: bytes, name: bytes, inputs, outputs) -> SemanticObject:
    """Typed ``aapcs64-linux-c`` import of ``name`` from ``library`` (a DT_NEEDED soname)."""
    return foreign_function_symbol(library, name, inputs, outputs, abi=AAPCS64_LINUX_C_ABI)


@dataclass(frozen=True)
class LinuxAarch64Api(LinuxApi):
    """The :class:`LinuxApi` surface with AArch64 syscall numbers and convention."""

    def munmap_view(self, view_pointer: SemanticObject, extent: int) -> SemanticObject:
        return _syscall(
            SYS_MUNMAP, (view_pointer, heap_view_type(extent), self.memory_effect), (self.b64, self.memory_effect),
            ("$0", extent), deallocator=ForeignDeallocatorContract(0, 1),
        )

    @property
    def types(self) -> tuple[SemanticObject, ...]:
        return (
            self.b8, self.b32, self.b64, self.bytes_rw, self.bytes_read,
            self.memory_effect, self.filesystem_effect, self.process_effect, self.heap_owner,
        )


def linux_aarch64_api() -> LinuxAarch64Api:
    b8, b32, b64 = bits_type(8), bits_type(32), bits_type(64)
    bytes_rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
    bytes_read = pointer_type(b8, Permission.READ, 1, space=2)
    memory = memory_effect_type()
    filesystem = effect_type(EffectDomain.FILESYSTEM, 0)
    process = effect_type(EffectDomain.SYSCALL, 0)
    heap = heap_owner_type()
    return LinuxAarch64Api(
        b8, b32, b64, bytes_rw, bytes_read, memory, filesystem, process, heap,
        _syscall(SYS_READ, (b32, bytes_rw, b64, filesystem, memory), (b64, filesystem, memory)),
        _syscall(SYS_WRITE, (b32, bytes_read, b64, filesystem, memory), (b64, filesystem, memory)),
        _syscall(SYS_OPENAT, (b32, bytes_read, b32, b32, filesystem, memory), (b64, filesystem, memory)),
        _syscall(SYS_CLOSE, (b32, filesystem), (b64, filesystem)),
        _syscall(
            SYS_MMAP, (b64, memory), (bytes_rw, heap, memory),
            (0, "$0", PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, (1 << 64) - 1, 0),
            allocator=ForeignAllocatorContract((0,), 0, 1, PAGE_SIZE, True),
        ),
        _syscall(SYS_EXIT_GROUP, (b32, process), (process,)),
        None, None,  # C-callable XAX entries are not part of this profile yet
    )


@dataclass(frozen=True)
class LinuxAarch64Executable:
    data: bytes
    bundle: Aarch64Bundle
    target_cid: bytes
    semantic_ranges: tuple[ArtifactSemanticRange, ...]
    needed: tuple[bytes, ...] = ()

    @property
    def artifact_bytes(self) -> bytes:
        return self.data


def _words(*words: int) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in words)


def _mov(destination: int, source: int) -> int:
    return 0xAA0003E0 | (source << 16) | destination  # orr Xd, xzr, Xm


def _bl(position: int, target: int) -> int:
    displacement = (target - position) // 4
    if not -(1 << 25) <= displacement < 1 << 25:
        fail("XAX.LINUX_AARCH64.CALL", "elf", "AARCH64-CALL-RANGE", "signed imm26", displacement)
    return 0x94000000 | (displacement & 0x3FFFFFF)


def syscall_thunk(name: bytes, allocator: bool) -> bytes:
    """Compiler-generated ``linux-aarch64-syscall-v1`` adapter.

    The AAPCS64 call delivers the machine operands in x0..x(k-1); the
    template places each operand or exact literal in x0..x5, then ``svc``.
    """
    text = name.decode("ascii", "replace")
    template = text.partition(":")[2]
    operands = sum(1 for item in template.split(",") if item.startswith("$")) if template else 0
    number, arguments = decode_syscall_name(name, operands)
    words: list[int] = []
    if template:
        words.extend(_mov(_SYSCALL_STAGING + index, index) for index in range(operands))
        for register, argument in enumerate(arguments):
            if isinstance(argument, str):
                words.append(_mov(register, _SYSCALL_STAGING + int(argument[1:])))
            else:
                words.extend(_move_immediate(register, argument, 64))
    words.extend(_move_immediate(8, number, 64))
    words.append(_SVC0)
    if allocator:
        words.extend(_KERNEL_ERROR_TO_NULL)
    words.append(_RET)
    return _words(*words)


def _foreign_declarations(reader: StoreReader) -> dict[tuple[bytes, bytes], object]:
    found = {}
    for obj in reader.objects():
        if obj.kind == Kind.TARGET and not obj.references and FOREIGN_FUNCTION_PREFIX in obj.body[:40]:
            try:
                declaration = decode_foreign_function(obj)
            except Exception:  # an ordinary target package, not a declaration
                continue
            found[(declaration.library, declaration.name)] = declaration
    return found


_ELF_HEADER_SIZE, _PROGRAM_HEADER_SIZE, _SYMBOL_SIZE, _RELA_SIZE = 64, 56, 24, 24
_BASE_ADDRESS = 0x400000
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR, PT_GNU_STACK = 1, 2, 3, 6, 0x6474E551
PF_R, PF_W, PF_X = 4, 2, 1
R_AARCH64_GLOB_DAT = 1025
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 0, 1, 4, 5, 6, 7, 8, 9, 10, 11
DT_FLAGS, DF_BIND_NOW, DT_FLAGS_1, DF_1_NOW = 30, 8, 0x6FFFFFFB, 1
_STACK_HEADER = program_header(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16)


def _elf_header(entry_address: int, program_headers: int) -> bytes:
    return b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8) + struct.pack(
        "<HHIQQQIHHHHHH", 2, 183, 1, entry_address, _ELF_HEADER_SIZE, 0, 0,
        _ELF_HEADER_SIZE, _PROGRAM_HEADER_SIZE, program_headers, 64, 0, 0,
    )


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _text(bundle: Aarch64Bundle, entry_cid: bytes, declarations, text_offset: int, import_thunk: Callable[[int, bytes], bytes] | None):
    """Stub + thunks + bundle, with every foreign BL patched to its thunk.

    Returns ``(text, bundle offset within text, C import thunk offsets)``.
    """
    text = bytearray(16)  # stub, padded
    thunks: dict[tuple[bytes, bytes], int] = {}
    imports: dict[bytes, int] = {}
    for _position, library, name in bundle.foreign_calls:
        key = (library, name)
        if key in thunks:
            continue
        declaration = declarations[key]
        thunks[key] = len(text)
        if declaration.abi == LINUX_AARCH64_SYSCALL_ABI:
            text += syscall_thunk(name, declaration.allocator is not None)
        else:
            imports[name] = len(text)
            text += bytes(12)  # adrp/ldr/br, patched once the GOT is placed
        text += bytes(-len(text) % 16)
    code_base = len(text)
    text += bundle.code
    entry = code_base + dict(bundle.function_offsets)[entry_cid]
    text[0:8] = _words(_bl(0, entry), 0xD4200000 | (_BRK_ENTRY_RETURNED << 5))
    for position, library, name in bundle.foreign_calls:
        site = code_base + position
        text[site:site + 4] = _bl(site, thunks[(library, name)]).to_bytes(4, "little")
    return text, code_base, imports


def emit_linux_aarch64_executable(bundle: Aarch64Bundle, entry_cid: bytes, declarations, *, dynamic_loader: bool) -> tuple[bytes, int, tuple[bytes, ...]]:
    """Return ``(ELF bytes, file offset of the bundle code, DT_NEEDED libraries)``."""
    c_imports = sorted({(library, name) for _p, library, name in bundle.foreign_calls if declarations[(library, name)].abi == AAPCS64_LINUX_C_ABI})
    if c_imports and not dynamic_loader:
        fail("XAX.LINUX.DYNAMIC_REQUIRED", "elf", "LINUX-DYNAMIC-LOADER-EXPLICIT", "aarch64-linux-elf-dynexec-v1", "static profile with C imports")
    if not dynamic_loader:
        code_offset = _ELF_HEADER_SIZE + 2 * _PROGRAM_HEADER_SIZE  # 176, 16-aligned
        text, code_base, _ = _text(bundle, entry_cid, declarations, code_offset, None)
        file_size = code_offset + len(text)
        load = program_header(PT_LOAD, PF_R | PF_X, 0, _BASE_ADDRESS, file_size, file_size, SEGMENT_ALIGN)
        return _elf_header(_BASE_ADDRESS + code_offset, 2) + load + _STACK_HEADER + bytes(text), code_offset + code_base, ()
    names = [name for _library, name in c_imports]
    if len(set(names)) != len(names):
        fail("XAX.LINUX.IMPORT", "elf", "LINUX-IMPORT-SYMBOL-UNIQUE", "one library per imported symbol", [list(item) for item in c_imports])
    needed = tuple(sorted({library for library, _name in c_imports}))
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
    text, code_base, import_thunks = _text(bundle, entry_cid, declarations, code_offset, None)
    text_end = code_offset + len(text)
    rw_offset = _align(text_end, 8)
    rw_address = _align(_BASE_ADDRESS + text_end, SEGMENT_ALIGN) + rw_offset % SEGMENT_ALIGN
    address = lambda offset: _BASE_ADDRESS + offset
    entries = [(DT_NEEDED, string_offsets[library]) for library in needed] + [
        (DT_HASH, address(hash_offset)), (DT_STRTAB, address(strtab_offset)), (DT_SYMTAB, address(symtab_offset)),
        (DT_STRSZ, len(strings)), (DT_SYMENT, _SYMBOL_SIZE), (DT_RELA, address(rela_offset)),
        (DT_RELASZ, _RELA_SIZE * len(names)), (DT_RELAENT, _RELA_SIZE),
        (DT_FLAGS, DF_BIND_NOW), (DT_FLAGS_1, DF_1_NOW), (DT_NULL, 0),
    ]
    dynamic_bytes = b"".join(dynamic(tag, value) for tag, value in entries)
    got_address = rw_address + len(dynamic_bytes)
    slot = {name: got_address + 8 * index for index, name in enumerate(names)}
    for name, offset in import_thunks.items():
        pc = address(code_offset + offset)
        page_delta = ((slot[name] & ~0xFFF) - (pc & ~0xFFF)) >> 12
        adrp = 0x90000000 | ((page_delta & 0x3) << 29) | (((page_delta >> 2) & 0x7FFFF) << 5) | 16
        ldr = 0xF9400000 | (((slot[name] & 0xFFF) // 8) << 10) | (16 << 5) | 16
        text[offset:offset + 12] = _words(adrp, ldr, 0xD61F0000 | (16 << 5))
    symbols = bytes(_SYMBOL_SIZE) + b"".join(symbol(string_offsets[name], 0x12, 0, 0, 0, 0) for name in names)
    relocations = b"".join(rela(slot[name], index + 1, R_AARCH64_GLOB_DAT) for index, name in enumerate(names))
    rw_size = len(dynamic_bytes) + 8 * len(names)
    headers = b"".join((
        program_header(PT_PHDR, PF_R, _ELF_HEADER_SIZE, address(_ELF_HEADER_SIZE), header_count * _PROGRAM_HEADER_SIZE, header_count * _PROGRAM_HEADER_SIZE, 8),
        program_header(PT_INTERP, PF_R, interp_offset, address(interp_offset), len(interpreter), len(interpreter), 1),
        program_header(PT_LOAD, PF_R | PF_X, 0, _BASE_ADDRESS, text_end, text_end, SEGMENT_ALIGN),
        program_header(PT_LOAD, PF_R | PF_W, rw_offset, rw_address, rw_size, rw_size, SEGMENT_ALIGN),
        program_header(PT_DYNAMIC, PF_R | PF_W, rw_offset, rw_address, len(dynamic_bytes), len(dynamic_bytes), 8),
        _STACK_HEADER,
    ))
    out = bytearray(_elf_header(address(code_offset), header_count) + headers)
    for offset, blob in ((interp_offset, interpreter), (symtab_offset, symbols), (strtab_offset, strings), (hash_offset, hash_bytes), (rela_offset, relocations), (code_offset, bytes(text))):
        out.extend(bytes(offset - len(out)))
        out.extend(blob)
    out.extend(bytes(rw_offset - len(out)))
    out.extend(dynamic_bytes + bytes(8 * len(names)))
    return bytes(out), code_offset + code_base, needed


def compile_linux_aarch64_executable(reader: StoreReader, entry_cid: bytes, target_cid: bytes) -> LinuxAarch64Executable:
    resolve = store_resolver(reader)
    target_object = resolve(target_cid)
    description = decode_native_target(target_object)
    formats = (AARCH64_LINUX_ELF_EXEC_FORMAT, AARCH64_LINUX_ELF_DYNAMIC_FORMAT)
    if description.architecture != 3 or description.abi != AARCH64_LINUX_ABI or description.image_format not in formats:
        fail("XAX.LINUX.TARGET", target_cid.hex(), "LINUX-AARCH64-ELF-EXEC-TARGET", [3, AARCH64_LINUX_ABI, list(formats)], [description.architecture, description.abi, description.image_format])
    validate_process_entry(reader, entry_cid)
    bundle = compile_aarch64_bundle_bound_target(reader, (entry_cid,), target_object)
    data, code_offset, needed = emit_linux_aarch64_executable(
        bundle, entry_cid, _foreign_declarations(reader), dynamic_loader=description.image_format == AARCH64_LINUX_ELF_DYNAMIC_FORMAT,
    )
    ranges = tuple(
        ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, code_offset + item.start, code_offset + item.end)
        for item in bundle.semantic_ranges
    )
    return LinuxAarch64Executable(data, bundle, target_cid, ranges, needed)


SYSROOT = "/usr/aarch64-linux-gnu"


def aarch64_runner() -> list[str] | None:
    """Native execution on an AArch64 Linux host, else ``qemu-aarch64`` user mode, else ``None``."""
    if platform.machine() in ("aarch64", "arm64"):
        return []
    qemu = shutil.which("qemu-aarch64")
    return [qemu, "-L", SYSROOT] if qemu else None


def run_linux_aarch64_executable(
    data: bytes,
    *,
    cwd: str | os.PathLike[str] | None = None,
    stdin: bytes = b"",
    timeout: float = 60.0,
    arguments: tuple[str, ...] = (),
) -> subprocess.CompletedProcess:
    """Test harness only: execute the artifact natively or under qemu-aarch64 user mode."""
    runner = aarch64_runner()
    if runner is None:
        raise RuntimeError("no AArch64 Linux execution host (native or qemu-aarch64)")
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "xax-program")
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, 0o755)
        return subprocess.run([*runner, path, *arguments], cwd=cwd, input=stdin, capture_output=True, timeout=timeout, check=False)
