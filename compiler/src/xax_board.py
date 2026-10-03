"""Bare-metal board package and image for QEMU ``virt`` (AArch64) (ADR-128, U1.6).

Everything here is explicit board contract data or compiler-generated
glue; the XAX kernel gains nothing:

* the board package ``aarch64-qemu-virt-v1`` (architecture 3, bare-metal ABI 3,
  board profile 5, format 8) lists the AArch64 general operations plus
  ``target`` operations for this board's registers: the PL011 UART data
  register, the GICv2 distributor and CPU interface, the virtual timer system
  registers, ``wfi``, IRQ masking, and PSCI ``SYSTEM_OFF``.  Every one consumes
  and returns the board's device effect, so device accesses stay ordered;
* one interrupt handler contract: event 1 = IRQ at EL1, entered with IRQs
  masked (no nesting), caller-saved registers saved by the generated entry,
  device effects only, a 1 KiB stack bound, ``eret`` return;
* the image is an ELF64 ``ET_EXEC`` at ``LOAD_ADDRESS``.  Its only generated
  code is the reset stub (stack pointer to the board-declared stack top,
  ``VBAR_EL1`` to the vector table, ``bl reset``) and a 2 KiB vector table
  whose current-EL IRQ slot saves x0-x18 and x30, calls the handler, restores,
  and returns with ``eret``.  Every other exception slot, a ``brk`` trap, and
  a returning reset entry print ``!`` on the UART and power off: no hidden
  recovery path.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from xax_aarch64 import _move_immediate, compile_aarch64_bundle_bound_target
from xax_compiler import (
    AARCH64_BOARD_ELF_FORMAT,
    AARCH64_GENERAL_OPERATIONS,
    AARCH64_INTEGER_COMPLETION_OPERATIONS,
    AtomicFamily,
    AtomicScope,
    BOARD_PROFILE,
    EffectDomain,
    HandlerEntryContract,
    Kind,
    Operation,
    SemanticObject,
    StoreReader,
    TargetOperationContract,
    TargetValueConstraint,
    TargetValueConstraintKind,
    _decode_function_interface,
    _is_proof_type,
    decode_native_target,
    effect_type,
    fail,
    store_resolver,
    uleb,
    validate_handler_entry,
)
from xax_elf import program_header

IDENTITY = b"aarch64-qemu-virt-v1"
LOAD_ADDRESS = 0x40080000
STACK_TOP = 0x40800000  # board-declared RAM below 128 MiB; not part of the image
UART_DATA = 0x09000000
GICD, GICC = 0x08000000, 0x08010000
VIRTUAL_TIMER_IRQ = 27
PSCI_SYSTEM_OFF = 0x84000008
EVENT_IRQ = 1

# Package-local operation ids (TARGET_OP attribute 0) and lowering classes.
UART_PUT, GICD_CTLR, GICD_ISENABLER0, GICC_CTLR, GICC_PMR, GICC_IAR, GICC_EOIR = 1, 2, 3, 4, 5, 6, 7
CNTFRQ, CNTV_TVAL, CNTV_CTL, IRQ_UNMASK, IRQ_MASK, WAIT_FOR_INTERRUPT, POWER_OFF = 8, 9, 10, 11, 12, 13, 14
MMIO_STORE8, MMIO_STORE32, MMIO_LOAD32, SYSREG_READ, SYSREG_WRITE, INSTRUCTION, PSCI_OFF = 1, 2, 3, 4, 5, 6, 7
SYSREG_CNTFRQ_EL0, SYSREG_CNTV_TVAL_EL0, SYSREG_CNTV_CTL_EL0 = 0x5F00, 0x5F18, 0x5F19
MSR_DAIFCLR_IRQ, MSR_DAIFSET_IRQ, WFI = 0xD50342FF, 0xD50342DF, 0xD503207F

DEVICE = effect_type(EffectDomain.DEVICE, 1)
_DEVICE = TargetValueConstraint(TargetValueConstraintKind.EFFECT, EffectDomain.DEVICE, 1)
_B8, _B32, _B64 = (TargetValueConstraint(TargetValueConstraintKind.BITS, width) for width in (8, 32, 64))


def _contract(operation: int, lowering: int, encoding: int, operands, results) -> TargetOperationContract:
    return TargetOperationContract(operation, lowering, encoding, operands, results, (AtomicScope.SYSTEM,), 0, 0, False, False)


CONTRACTS = (
    _contract(UART_PUT, MMIO_STORE8, UART_DATA, (_B8, _DEVICE), (_DEVICE,)),
    _contract(GICD_CTLR, MMIO_STORE32, GICD, (_B32, _DEVICE), (_DEVICE,)),
    _contract(GICD_ISENABLER0, MMIO_STORE32, GICD + 0x100, (_B32, _DEVICE), (_DEVICE,)),
    _contract(GICC_CTLR, MMIO_STORE32, GICC, (_B32, _DEVICE), (_DEVICE,)),
    _contract(GICC_PMR, MMIO_STORE32, GICC + 0x4, (_B32, _DEVICE), (_DEVICE,)),
    _contract(GICC_IAR, MMIO_LOAD32, GICC + 0xC, (_DEVICE,), (_B32, _DEVICE)),
    _contract(GICC_EOIR, MMIO_STORE32, GICC + 0x10, (_B32, _DEVICE), (_DEVICE,)),
    _contract(CNTFRQ, SYSREG_READ, SYSREG_CNTFRQ_EL0, (_DEVICE,), (_B64, _DEVICE)),
    _contract(CNTV_TVAL, SYSREG_WRITE, SYSREG_CNTV_TVAL_EL0, (_B64, _DEVICE), (_DEVICE,)),
    _contract(CNTV_CTL, SYSREG_WRITE, SYSREG_CNTV_CTL_EL0, (_B64, _DEVICE), (_DEVICE,)),
    _contract(IRQ_UNMASK, INSTRUCTION, MSR_DAIFCLR_IRQ, (_DEVICE,), (_DEVICE,)),
    _contract(IRQ_MASK, INSTRUCTION, MSR_DAIFSET_IRQ, (_DEVICE,), (_DEVICE,)),
    _contract(WAIT_FOR_INTERRUPT, INSTRUCTION, WFI, (_DEVICE,), (_DEVICE,)),
    _contract(POWER_OFF, PSCI_OFF, PSCI_SYSTEM_OFF, (_DEVICE,), (_DEVICE,)),
)
IRQ_HANDLER = HandlerEntryContract(EVENT_IRQ, 1, 1, 0, 0, 0, 1, (EffectDomain.DEVICE,), 1024, 1)


def qemu_virt_board() -> SemanticObject:
    operations = tuple(sorted({
        1, 2, 3, *range(5, 20), *(int(value) for value in AARCH64_GENERAL_OPERATIONS),
        *AARCH64_INTEGER_COMPLETION_OPERATIONS, int(Operation.TARGET_OP),
    }))
    terminators = (1, 2, 3, 4)
    body = bytearray(uleb(len(IDENTITY)) + IDENTITY)
    for value in (BOARD_PROFILE, 3, 3, AARCH64_BOARD_ELF_FORMAT, 64, 64, 16, 0):
        body.extend(uleb(value))
    body.extend(uleb(8) + bytes(range(8)) + uleb(0) + uleb(2) + bytes((9, 10)))
    body.extend(uleb(len(operations)) + b"".join(uleb(value) for value in operations))
    body.extend(uleb(len(terminators)) + bytes(terminators))
    # Concurrency section: no atomics yet; one IRQ handler contract.
    body.extend(uleb(0) + uleb(0) + uleb(0) + uleb(1))
    handler = IRQ_HANDLER
    for value in (handler.event_kind, handler.entry_abi, handler.privilege, handler.priority, handler.nesting_policy, handler.reentrancy_policy, handler.saved_machine_state):
        body.extend(uleb(value))
    body.extend(uleb(len(handler.allowed_effect_domains)) + b"".join(uleb(domain) for domain in handler.allowed_effect_domains))
    body.extend(uleb(handler.stack_bound) + uleb(handler.return_contract))
    # Target operation section.
    body.extend(uleb(len(CONTRACTS)))
    for contract in CONTRACTS:
        body.extend(uleb(contract.operation_id) + uleb(contract.semantic_code) + uleb(contract.encoding_opcode))
        for constraints in (contract.operands, contract.results):
            body.extend(uleb(len(constraints)))
            for item in constraints:
                body.extend(uleb(item.kind) + uleb(item.primary) + uleb(item.secondary))
        body.extend(uleb(len(contract.supported_scopes)) + b"".join(uleb(scope) for scope in contract.supported_scopes))
        body.extend(uleb(contract.source_space) + uleb(contract.destination_space))
        body.extend(bytes((contract.synchronizes, contract.may_block)) + uleb(0))
    return SemanticObject.create(Kind.TARGET, bytes(body))


def board_operation_words(semantic_code: int, encoding: int, value_register: int, scratch: int) -> list[int]:
    """AArch64 words for one board operation; ``value_register`` holds the operand or receives the result."""
    if semantic_code in (MMIO_STORE8, MMIO_STORE32, MMIO_LOAD32):
        words = list(_move_immediate(scratch, encoding, 64))
        opcode = {MMIO_STORE8: 0x39000000, MMIO_STORE32: 0xB9000000, MMIO_LOAD32: 0xB9400000}[semantic_code]
        return [*words, opcode | (scratch << 5) | value_register]
    if semantic_code == SYSREG_READ:
        return [0xD5300000 | (encoding << 5) | value_register]
    if semantic_code == SYSREG_WRITE:
        return [0xD5100000 | (encoding << 5) | value_register]
    if semantic_code == INSTRUCTION:
        return [encoding]
    if semantic_code == PSCI_OFF:
        return [*_move_immediate(0, encoding, 64), 0xD4000002]  # hvc #0 (does not return)
    fail("XAX.BOARD.OPERATION", "board", "BOARD-OPERATION-LOWERING", [MMIO_STORE8, PSCI_OFF], semantic_code)


@dataclass(frozen=True)
class BoardImage:
    data: bytes
    code: bytes
    target_cid: bytes

    @property
    def artifact_bytes(self) -> bytes:
        return self.data


def _words(*words: int) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in words)


def _bl(position: int, target: int) -> int:
    return 0x94000000 | (((target - position) // 4) & 0x3FFFFFF)


def _fault_stub() -> list[int]:
    """Print ``!`` on the UART and power off (unexpected exception or trap)."""
    return [*_move_immediate(1, UART_DATA, 64), *_move_immediate(2, 0x21, 32), 0x39000022, *_move_immediate(0, PSCI_SYSTEM_OFF, 64), 0xD4000002, 0x14000000]


def _irq_slot(handler_position: int, slot_position: int) -> list[int]:
    """Save x0-x18 and x30, call the handler, restore, ``eret`` (IRQs stay masked: no nesting)."""
    words = [0xD10283FF]  # sub sp, sp, #160
    pairs = [(0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15), (16, 17), (18, 30)]
    for index, (first, second) in enumerate(pairs):
        words.append(0xA9000000 | ((index * 2) << 15) | (second << 10) | (31 << 5) | first)  # stp
    call = len(words)
    words.append(0)
    for index, (first, second) in enumerate(pairs):
        words.append(0xA9400000 | ((index * 2) << 15) | (second << 10) | (31 << 5) | first)  # ldp
    words += [0x910283FF, 0xD69F03E0]  # add sp, sp, #160; eret
    words[call] = _bl(slot_position + call * 4, handler_position)
    if len(words) * 4 > 0x80:
        raise AssertionError("IRQ slot exceeds 128 bytes")
    return words


def _validate_reset(reader: StoreReader, reset_cid: bytes) -> None:
    resolve = store_resolver(reader)
    function = resolve(reset_cid)
    if function.kind != Kind.FUNCTION:
        fail("XAX.BOARD.ENTRY", reset_cid.hex(), "BOARD-RESET-FUNCTION", Kind.FUNCTION.name, function.kind.name)
    _graph, parameters, returns = _decode_function_interface(function, resolve)
    if any(not _is_proof_type(resolve(cid)) for cid in (*parameters, *returns)):
        fail("XAX.BOARD.ENTRY", reset_cid.hex(), "BOARD-RESET-PROOF-ONLY", "fn(device effect...) -> (device effect...)", [cid.hex() for cid in (*parameters, *returns)])


def compile_board_image(reader: StoreReader, reset_cid: bytes, irq_handler_cid: bytes, target_cid: bytes) -> BoardImage:
    resolve = store_resolver(reader)
    target = resolve(target_cid)
    description = decode_native_target(target)
    if description.identity != IDENTITY:
        fail("XAX.BOARD.TARGET", target_cid.hex(), "BOARD-TARGET", IDENTITY.decode(), description.identity.decode("ascii", "replace"))
    _validate_reset(reader, reset_cid)
    validate_handler_entry(reader, irq_handler_cid, target, EVENT_IRQ)
    bundle = compile_aarch64_bundle_bound_target(reader, (reset_cid, irq_handler_cid), target)
    offsets = dict(bundle.function_offsets)
    if bundle.foreign_calls:
        fail("XAX.BOARD.IMPORTS", "board", "BOARD-NO-FOREIGN-CALLS", 0, len(bundle.foreign_calls))
    # Layout: [reset stub][fault stub] padded to 2 KiB, [vector table, 2 KiB], [bundle].
    stack = list(_move_immediate(0, STACK_TOP, 64))
    adr_at, bl_at = (len(stack) + 1) * 4, (len(stack) + 4) * 4
    stub = [*stack, 0x9100001F, 0, 0xD518C000, 0xD5033FDF, 0, 0]  # mov sp, x0; adr x0, vectors; msr vbar_el1, x0; isb; bl reset; b fault
    fault_at = len(stub) * 4
    text = bytearray(_words(*stub) + _words(*_fault_stub()))
    text += bytes(-len(text) % 2048)
    vectors_at = len(text)
    code_at = vectors_at + 2048
    text += bytes(2048)
    for slot in range(16):
        position = vectors_at + slot * 0x80
        if slot == 5:  # current EL with SP_ELx, IRQ
            words = _irq_slot(code_at + offsets[irq_handler_cid], position)
        else:
            words = [0x14000000 | (((fault_at - position) // 4) & 0x3FFFFFF)]  # b fault
        text[position:position + 4 * len(words)] = _words(*words)
    text += bundle.code
    displacement = vectors_at - adr_at
    text[adr_at:adr_at + 4] = (0x10000000 | ((displacement & 0x3) << 29) | (((displacement >> 2) & 0x7FFFF) << 5)).to_bytes(4, "little")
    text[bl_at:bl_at + 4] = _bl(bl_at, code_at + offsets[reset_cid]).to_bytes(4, "little")
    text[bl_at + 4:bl_at + 8] = (0x14000000 | (((fault_at - bl_at - 4) // 4) & 0x3FFFFFF)).to_bytes(4, "little")
    header_size = 64 + 56
    file_offset = 128  # p_offset ≡ p_vaddr (mod 16): the board loader needs no page alignment
    elf_header = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8) + struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, LOAD_ADDRESS, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    load = program_header(1, 5, file_offset, LOAD_ADDRESS, len(text), len(text), 16)
    data = elf_header + load + bytes(file_offset - header_size) + bytes(text)
    return BoardImage(data, bytes(text), target_cid)


def run_board_image(image: BoardImage, *, timeout: float = 30.0) -> subprocess.CompletedProcess:
    """Test harness only: boot the image on QEMU ``virt`` with the UART on stdout."""
    qemu = shutil.which("qemu-system-aarch64")
    if qemu is None:
        raise RuntimeError("needs qemu-system-aarch64")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "board.elf"
        path.write_bytes(image.data)
        return subprocess.run(
            [qemu, "-M", "virt", "-cpu", "cortex-a57", "-m", "128M", "-nographic", "-net", "none", "-monitor", "none", "-kernel", str(path)],
            capture_output=True, timeout=timeout, check=False,
        )
