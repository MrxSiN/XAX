"""Run one export of an XAX Android arm64 shared object under Unicorn with stubbed imports.

Host test tooling (EXECUTED under emulation, never device evidence): the ELF's
``PT_LOAD`` segments are mapped at a fixed base, every ``R_AARCH64_GLOB_DAT``
slot is pointed at a per-symbol ``ret`` stub, and a Python handler per symbol
observes ``x0..x7`` and supplies the return value.  Only the relocation form the
XAX emitter produces is accepted.
"""
from __future__ import annotations

import struct
from typing import Callable

BASE = 0x1000000
STUBS = 0x3000000
SENTINEL = 0x4000000
STACK_TOP = 0x6000000
HEAP = 0x7000000
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ = 0, 5, 6, 7, 8
R_AARCH64_GLOB_DAT = 1025

Handler = Callable[["Machine"], int]


class Machine:
    """What a stub handler sees: registers and memory of the running emulation."""

    def __init__(self, uc):
        from unicorn import arm64_const as arm

        self._uc, self._arm = uc, arm

    def x(self, index: int) -> int:
        return self._uc.reg_read(self._arm.UC_ARM64_REG_X0 + index)

    def read(self, address: int, size: int) -> bytes:
        return bytes(self._uc.mem_read(address, size))

    def write(self, address: int, data: bytes) -> None:
        self._uc.mem_write(address, data)


def _dynamic(data: bytes, phdrs) -> dict[int, int]:
    _type, offset, _vaddr, size = next(item for item in phdrs if item[0] == PT_DYNAMIC)
    entries = {}
    for index in range(size // 16):
        tag, value = struct.unpack_from("<qQ", data, offset + 16 * index)
        if tag == DT_NULL:
            break
        entries[tag] = value
    return entries


def run_export(elf: bytes, export: bytes, arguments: tuple[int, ...], handlers: dict[bytes, Handler],
               *, heap: bytes = b"") -> tuple[int, list[tuple[bytes, tuple[int, ...]]]]:
    """Call ``export(arguments...)``; return (x0, [(symbol, x0..x7) per import call])."""
    import unicorn
    from unicorn import arm64_const as arm

    if elf[:4] != b"\x7fELF" or struct.unpack_from("<H", elf, 18)[0] != 183:
        raise ValueError("not an AArch64 ELF")
    phoff, = struct.unpack_from("<Q", elf, 32)
    phentsize, phnum = struct.unpack_from("<HH", elf, 54)
    phdrs = []
    for index in range(phnum):
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from("<IIQQQQQQ", elf, phoff + index * phentsize)
        phdrs.append((p_type, p_offset, p_vaddr, p_filesz if p_type == PT_DYNAMIC else (p_filesz, p_memsz)))
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    top = max(vaddr + sizes[1] for kind, _offset, vaddr, sizes in phdrs if kind == PT_LOAD)
    uc.mem_map(BASE, (top + 0xFFFF) & ~0xFFFF)
    for kind, offset, vaddr, sizes in phdrs:
        if kind == PT_LOAD:
            uc.mem_write(BASE + vaddr, elf[offset:offset + sizes[0]])
    dynamic = _dynamic(elf, phdrs)
    # The emitter's dynamic addresses are file offsets equal to virtual addresses (one image).
    symtab, strtab = dynamic[DT_SYMTAB], dynamic[DT_STRTAB]

    def symbol(index: int) -> tuple[bytes, int]:
        st_name, _info, _other, _shndx, st_value, _size = struct.unpack_from("<IBBHQQ", elf, symtab + 24 * index)
        end = elf.index(b"\0", strtab + st_name)
        return elf[strtab + st_name:end], st_value

    for base in (STUBS, SENTINEL, HEAP):
        uc.mem_map(base, 0x100000)
    uc.mem_map(STACK_TOP - 0x100000, 0x100000)
    if heap:
        uc.mem_write(HEAP, heap)
    names: dict[int, bytes] = {}
    for index in range(dynamic.get(DT_RELASZ, 0) // 24):
        r_offset, r_info, _addend = struct.unpack_from("<QQq", elf, dynamic[DT_RELA] + 24 * index)
        if r_info & 0xFFFFFFFF != R_AARCH64_GLOB_DAT:
            raise ValueError("unsupported relocation")
        name, _value = symbol(r_info >> 32)
        stub = STUBS + 4 * len(names)
        names[stub] = name
        uc.mem_write(stub, struct.pack("<I", 0xD65F03C0))  # ret
        uc.mem_write(BASE + r_offset, struct.pack("<Q", stub))
    entry = None
    index = 1
    while symtab + 24 * index < strtab:
        name, value = symbol(index)
        if name == export and value:
            entry = BASE + value
        index += 1
    if entry is None:
        raise ValueError(f"export {export!r} not found")
    trace: list[tuple[bytes, tuple[int, ...]]] = []
    machine = Machine(uc)

    def on_stub(emulator, address, _size, _user):
        name = names[address]
        trace.append((name, tuple(machine.x(i) for i in range(8))))
        handler = handlers.get(name)
        if handler is None:
            raise AssertionError(f"unexpected import call {name!r}")
        emulator.reg_write(arm.UC_ARM64_REG_X0, handler(machine) & 0xFFFFFFFFFFFFFFFF)

    uc.hook_add(unicorn.UC_HOOK_CODE, on_stub, begin=STUBS, end=STUBS + 4 * max(len(names), 1))
    uc.reg_write(arm.UC_ARM64_REG_CPACR_EL1, 3 << 20)
    uc.reg_write(arm.UC_ARM64_REG_SP, STACK_TOP)
    uc.reg_write(arm.UC_ARM64_REG_LR, SENTINEL)
    for register, value in enumerate(arguments):
        uc.reg_write(arm.UC_ARM64_REG_X0 + register, value)
    uc.emu_start(entry, SENTINEL, count=1_000_000)
    if uc.reg_read(arm.UC_ARM64_REG_PC) != SENTINEL:
        raise RuntimeError("export did not return")
    return uc.reg_read(arm.UC_ARM64_REG_X0), trace
