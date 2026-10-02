"""Minimal direct Android arm64-v8a ET_DYN emitter for the XAX prototype.

This module intentionally is not a general linker.  It consumes the existing
register-resident AArch64 lowering, resolves local XAX calls at compile time,
and emits only the dynamic ELF structures required by the referenced exports
and foreign calls.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from xax_elf import (
    c_string_table as _c_string_table,
    sysv_hash as _sysv_hash,
    hash_section as _hash_section,
    section_header as _section_header,
    program_header as _program_header,
    symbol as _symbol,
    dynamic as _dynamic,
    rela as _rela,
)
from xax_aarch64 import Aarch64Bundle, compile_aarch64_bundle_bound_target
from xax_compiler import (
    Cursor,
    Kind,
    SemanticObject,
    StoreReader,
    android_arm64_shared_target,
    decode_android_export,
    decode_native_target,
    fail,
    target,
    uleb,
)

ELF_PAGE_ALIGNMENT = 0x4000
EM_AARCH64 = 183
ET_DYN = 3
EV_CURRENT = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2
PF_R = 4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STB_GLOBAL = 1
STT_FUNC = 2
SHN_UNDEF = 0

DT_NULL = 0
DT_NEEDED = 1
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14

R_AARCH64_GLOB_DAT = 1025

ANDROID_TARGET_IDENTITY = b"android-arm64-v8a-shared-v3"
ANDROID_GENERAL_TARGET_IDENTITY = b"android-arm64-v8a-shared-v4"

ANDROID_ACTIVITY_UI_PREFIX = b"android-activity-ui-v1"
ANDROID_ACTIVITY_RESOURCE_UI_PREFIX = b"android-activity-resource-ui-v1"
ANDROID_ACTIVITY_METHOD_UI_PREFIX = b"android-activity-method-ui-v1"
ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX = b"android-activity-argument-method-ui-v1"


@dataclass(frozen=True)
class AndroidActivityUiDescription:
    activity_class_descriptor: str
    listener_class_descriptor: str
    initial_button_text: str
    click_button_text: str


@dataclass(frozen=True)
class AndroidActivityResourceUiDescription:
    activity_class_descriptor: str
    listener_class_descriptor: str
    initial_button_resource: str
    click_button_resource: str


@dataclass(frozen=True)
class AndroidActivityMethodUiDescription:
    activity_class_descriptor: str
    listener_class_descriptor: str
    initial_text_method_name: str
    initial_text_method_result: str
    click_button_text: str


@dataclass(frozen=True)
class AndroidActivityArgumentMethodUiDescription:
    activity_class_descriptor: str
    listener_class_descriptor: str
    initial_text_method_name: str
    initial_text_method_argument: str
    click_button_text: str


def _android_ui_bytes(value: str, name: str) -> bytes:
    if not value or "\x00" in value:
        raise ValueError(f"{name} must be nonempty and NUL-free")
    return value.encode("utf-8")


def android_activity_ui_semantics(
    *,
    activity_class_descriptor: str = "Lxax/generated/XaxActivity;",
    listener_class_descriptor: str = "Lxax/generated/XaxOnClickListener;",
    initial_button_text: str = "XAX",
    click_button_text: str = "Clicked",
) -> SemanticObject:
    """Create authoritative content-addressed Android Activity UI semantics.

    This is an identity-only target/platform carrier. It adds no Android concept
    to the XAX kernel and has no runtime representation by itself.
    """

    values = (
        _android_ui_bytes(activity_class_descriptor, "activity class descriptor"),
        _android_ui_bytes(listener_class_descriptor, "listener class descriptor"),
        _android_ui_bytes(initial_button_text, "initial button text"),
        _android_ui_bytes(click_button_text, "click button text"),
    )
    for descriptor in values[:2]:
        if not (descriptor.startswith(b"L") and descriptor.endswith(b";") and b"." not in descriptor):
            raise ValueError("Android UI class identities must be DEX class descriptors")
    identity = bytearray(ANDROID_ACTIVITY_UI_PREFIX)
    for value in values:
        identity.extend(uleb(len(value)) + value)
    return target(bytes(identity))


def decode_android_activity_ui(obj: SemanticObject) -> AndroidActivityUiDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-UI-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-UI-CARRIER")
    if not identity.startswith(ANDROID_ACTIVITY_UI_PREFIX):
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-UI-IDENTITY", ANDROID_ACTIVITY_UI_PREFIX.decode(), identity[:32].hex())
    cursor = Cursor(identity[len(ANDROID_ACTIVITY_UI_PREFIX):], obj.cid.hex())
    raw = tuple(cursor.byte_string() for _ in range(4))
    cursor.end("ANDROID-UI-IDENTITY")
    try:
        values = tuple(item.decode("utf-8") for item in raw)
    except UnicodeDecodeError:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-UI-UTF8", "canonical UTF-8", [item.hex() for item in raw])
    try:
        canonical = android_activity_ui_semantics(
            activity_class_descriptor=values[0],
            listener_class_descriptor=values[1],
            initial_button_text=values[2],
            click_button_text=values[3],
        )
    except ValueError as error:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-UI-FIELDS", "valid Android UI fields", str(error))
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-UI-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return AndroidActivityUiDescription(*values)


def lower_android_activity_ui(obj: SemanticObject):
    """Lower one Android UI semantic carrier into the bounded DEX bridge pair."""

    from xax_dex import activity_button_bridge_spec, click_text_listener_bridge_spec

    view = decode_android_activity_ui(obj)
    return (
        activity_button_bridge_spec(
            view.activity_class_descriptor,
            listener_class_descriptor=view.listener_class_descriptor,
            button_text=view.initial_button_text,
        ),
        click_text_listener_bridge_spec(
            view.listener_class_descriptor,
            text=view.click_button_text,
            native_library=None,
        ),
    )


def android_activity_method_ui_semantics(
    *,
    activity_class_descriptor: str = "Lxax/generated/XaxActivity;",
    listener_class_descriptor: str = "Lxax/generated/XaxOnClickListener;",
    initial_text_method_name: str = "hookTarget",
    initial_text_method_result: str = "Original",
    click_button_text: str = "Clicked",
) -> SemanticObject:
    """Activity UI whose initial visible text comes from one managed XAX method.

    The method is a bounded zero-argument public instance method returning one
    constant Java String.  This provides an exact controlled target for managed
    hook experiments without Java/Kotlin source or an assumed third-party method
    contract.
    """

    values = (
        _android_ui_bytes(activity_class_descriptor, "activity class descriptor"),
        _android_ui_bytes(listener_class_descriptor, "listener class descriptor"),
        _android_ui_bytes(initial_text_method_name, "initial text method name"),
        _android_ui_bytes(initial_text_method_result, "initial text method result"),
        _android_ui_bytes(click_button_text, "click button text"),
    )
    for descriptor in values[:2]:
        if not (descriptor.startswith(b"L") and descriptor.endswith(b";") and b"." not in descriptor):
            raise ValueError("Android UI class identities must be DEX class descriptors")
    method = initial_text_method_name
    if any(ch in method for ch in "\x00/.;["):
        raise ValueError("Android managed UI method name must be a valid DEX member name")
    identity = bytearray(ANDROID_ACTIVITY_METHOD_UI_PREFIX)
    for value in values:
        identity.extend(uleb(len(value)) + value)
    return target(bytes(identity))


def decode_android_activity_method_ui(obj: SemanticObject) -> AndroidActivityMethodUiDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-METHOD-UI-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-METHOD-UI-CARRIER")
    if not identity.startswith(ANDROID_ACTIVITY_METHOD_UI_PREFIX):
        fail(
            "XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-METHOD-UI-IDENTITY",
            ANDROID_ACTIVITY_METHOD_UI_PREFIX.decode(), identity[:40].hex(),
        )
    cursor = Cursor(identity[len(ANDROID_ACTIVITY_METHOD_UI_PREFIX):], obj.cid.hex())
    raw = tuple(cursor.byte_string() for _ in range(5))
    cursor.end("ANDROID-METHOD-UI-IDENTITY")
    try:
        values = tuple(item.decode("utf-8") for item in raw)
        canonical = android_activity_method_ui_semantics(
            activity_class_descriptor=values[0],
            listener_class_descriptor=values[1],
            initial_text_method_name=values[2],
            initial_text_method_result=values[3],
            click_button_text=values[4],
        )
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-METHOD-UI-FIELDS", "valid managed-method UI fields", str(error))
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-METHOD-UI-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return AndroidActivityMethodUiDescription(*values)


def lower_android_activity_method_ui(obj: SemanticObject):
    from dataclasses import replace
    from xax_dex import (
        DexActivityUiSpec,
        DexConstantStringMethod,
        activity_button_bridge_spec,
        click_text_listener_bridge_spec,
    )

    view = decode_android_activity_method_ui(obj)
    base = activity_button_bridge_spec(
        view.activity_class_descriptor,
        listener_class_descriptor=view.listener_class_descriptor,
        button_text="placeholder",  # replaced below; never emitted.
    )
    activity = replace(
        base,
        activity_ui=DexActivityUiSpec(
            view.listener_class_descriptor,
            button_text_method_name=view.initial_text_method_name,
        ),
        constant_string_methods=(
            DexConstantStringMethod(view.initial_text_method_name, view.initial_text_method_result),
        ),
    )
    listener = click_text_listener_bridge_spec(
        view.listener_class_descriptor,
        text=view.click_button_text,
        native_library=None,
    )
    return activity, listener


def android_activity_argument_method_ui_semantics(
    *,
    activity_class_descriptor: str = "Lcom/example/target/XaxActivity;",
    listener_class_descriptor: str = "Lcom/example/target/XaxOnClickListener;",
    initial_text_method_name: str = "hookTarget",
    initial_text_method_argument: str = "OriginalArg",
    click_button_text: str = "Clicked",
) -> SemanticObject:
    """Controlled one-String-argument managed method used by hook evidence.

    The generated method is exactly ``String hookTarget(String value)`` and
    returns its input argument. The Activity invokes it with one canonical
    string to make argument replacement externally observable without source
    code in Java/Kotlin.
    """

    values = (
        _android_ui_bytes(activity_class_descriptor, "activity class descriptor"),
        _android_ui_bytes(listener_class_descriptor, "listener class descriptor"),
        _android_ui_bytes(initial_text_method_name, "initial text method name"),
        _android_ui_bytes(initial_text_method_argument, "initial text method argument"),
        _android_ui_bytes(click_button_text, "click button text"),
    )
    for descriptor in values[:2]:
        if not (descriptor.startswith(b"L") and descriptor.endswith(b";") and b"." not in descriptor):
            raise ValueError("Android UI class identities must be DEX class descriptors")
    method = initial_text_method_name
    if any(ch in method for ch in "\x00/.;["):
        raise ValueError("Android managed UI method name must be a valid DEX member name")
    identity = bytearray(ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX)
    for value in values:
        identity.extend(uleb(len(value)) + value)
    return target(bytes(identity))


def decode_android_activity_argument_method_ui(obj: SemanticObject) -> AndroidActivityArgumentMethodUiDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-ARG-METHOD-UI-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-ARG-METHOD-UI-CARRIER")
    if not identity.startswith(ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX):
        fail(
            "XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-ARG-METHOD-UI-IDENTITY",
            ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX.decode(), identity[:48].hex(),
        )
    cursor = Cursor(identity[len(ANDROID_ACTIVITY_ARGUMENT_METHOD_UI_PREFIX):], obj.cid.hex())
    raw = tuple(cursor.byte_string() for _ in range(5))
    cursor.end("ANDROID-ARG-METHOD-UI-IDENTITY")
    try:
        values = tuple(item.decode("utf-8") for item in raw)
        canonical = android_activity_argument_method_ui_semantics(
            activity_class_descriptor=values[0],
            listener_class_descriptor=values[1],
            initial_text_method_name=values[2],
            initial_text_method_argument=values[3],
            click_button_text=values[4],
        )
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-ARG-METHOD-UI-FIELDS", "valid argument-method UI fields", str(error))
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-ARG-METHOD-UI-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return AndroidActivityArgumentMethodUiDescription(*values)


def lower_android_activity_argument_method_ui(obj: SemanticObject):
    from dataclasses import replace
    from xax_dex import (
        DexActivityUiSpec,
        DexEchoStringMethod,
        activity_button_bridge_spec,
        click_text_listener_bridge_spec,
    )

    view = decode_android_activity_argument_method_ui(obj)
    base = activity_button_bridge_spec(
        view.activity_class_descriptor,
        listener_class_descriptor=view.listener_class_descriptor,
        button_text="placeholder",
    )
    activity = replace(
        base,
        activity_ui=DexActivityUiSpec(
            view.listener_class_descriptor,
            button_text_method_name=view.initial_text_method_name,
            button_text_method_argument=view.initial_text_method_argument,
        ),
        echo_string_methods=(DexEchoStringMethod(view.initial_text_method_name),),
    )
    listener = click_text_listener_bridge_spec(
        view.listener_class_descriptor,
        text=view.click_button_text,
        native_library=None,
    )
    return activity, listener




def android_activity_resource_ui_semantics(
    *,
    activity_class_descriptor: str = "Lxax/generated/XaxActivity;",
    listener_class_descriptor: str = "Lxax/generated/XaxOnClickListener;",
    initial_button_resource: str = "app_name",
    click_button_resource: str = "clicked",
) -> SemanticObject:
    """Create Android UI semantics that explicitly references resource entry names."""

    values = (
        _android_ui_bytes(activity_class_descriptor, "activity class descriptor"),
        _android_ui_bytes(listener_class_descriptor, "listener class descriptor"),
        _android_ui_bytes(initial_button_resource, "initial button resource"),
        _android_ui_bytes(click_button_resource, "click button resource"),
    )
    for descriptor in values[:2]:
        if not (descriptor.startswith(b"L") and descriptor.endswith(b";") and b"." not in descriptor):
            raise ValueError("Android UI class identities must be DEX class descriptors")
    from xax_resources import AndroidStringResource
    AndroidStringResource(initial_button_resource, "validate")
    AndroidStringResource(click_button_resource, "validate")
    identity = bytearray(ANDROID_ACTIVITY_RESOURCE_UI_PREFIX)
    for value in values:
        identity.extend(uleb(len(value)) + value)
    return target(bytes(identity))


def decode_android_activity_resource_ui(obj: SemanticObject) -> AndroidActivityResourceUiDescription:
    if obj.kind != Kind.TARGET or obj.references:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-RESOURCE-UI-CARRIER", Kind.TARGET.name, obj.kind.name)
    outer = Cursor(obj.body, obj.cid.hex())
    identity = outer.byte_string()
    outer.end("ANDROID-RESOURCE-UI-CARRIER")
    if not identity.startswith(ANDROID_ACTIVITY_RESOURCE_UI_PREFIX):
        fail(
            "XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-RESOURCE-UI-IDENTITY",
            ANDROID_ACTIVITY_RESOURCE_UI_PREFIX.decode(), identity[:40].hex(),
        )
    cursor = Cursor(identity[len(ANDROID_ACTIVITY_RESOURCE_UI_PREFIX):], obj.cid.hex())
    raw = tuple(cursor.byte_string() for _ in range(4))
    cursor.end("ANDROID-RESOURCE-UI-IDENTITY")
    try:
        values = tuple(item.decode("utf-8") for item in raw)
        canonical = android_activity_resource_ui_semantics(
            activity_class_descriptor=values[0],
            listener_class_descriptor=values[1],
            initial_button_resource=values[2],
            click_button_resource=values[3],
        )
    except (UnicodeDecodeError, ValueError) as error:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-RESOURCE-UI-FIELDS", "valid resource-backed Android UI fields", str(error))
    if canonical.cid != obj.cid:
        fail("XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-RESOURCE-UI-CANONICAL", canonical.cid.hex(), obj.cid.hex())
    return AndroidActivityResourceUiDescription(*values)


def lower_android_activity_resource_ui(obj: SemanticObject, resources_obj: SemanticObject):
    """Resolve semantic resource names to exact IDs and lower the managed bridge pair."""

    from xax_dex import activity_button_resource_bridge_spec, click_resource_listener_bridge_spec
    from xax_resources import decode_android_resources_semantics, resource_id

    view = decode_android_activity_resource_ui(obj)
    resources = decode_android_resources_semantics(resources_obj)
    try:
        initial_id = resource_id(view.initial_button_resource, resources)
        click_id = resource_id(view.click_button_resource, resources)
    except KeyError as error:
        fail(
            "XAX.ANDROID.UI", obj.cid.hex(), "ANDROID-RESOURCE-UI-NAME",
            [item.name for item in resources.strings], str(error.args[0]),
        )
    return (
        activity_button_resource_bridge_spec(
            view.activity_class_descriptor,
            listener_class_descriptor=view.listener_class_descriptor,
            button_text_resource_id=initial_id,
        ),
        click_resource_listener_bridge_spec(
            view.listener_class_descriptor,
            text_resource_id=click_id,
            native_library=None,
        ),
    )


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _encode_adrp(register: int, pc: int, target: int) -> int:
    page_delta = (target & ~0xFFF) - (pc & ~0xFFF)
    if page_delta % 0x1000:
        raise AssertionError("ADRP page delta")
    imm = page_delta // 0x1000
    if not -(1 << 20) <= imm < (1 << 20):
        fail("XAX.ANDROID.ADRP", "elf", "ANDROID-ADRP-RANGE", "signed 21-bit pages", imm)
    encoded = imm & 0x1FFFFF
    return 0x90000000 | ((encoded & 0x3) << 29) | (((encoded >> 2) & 0x7FFFF) << 5) | register


def _encode_ldr_x(destination: int, base: int, target: int) -> int:
    page_offset = target & 0xFFF
    if page_offset % 8:
        fail("XAX.ANDROID.GOT", "elf", "ANDROID-GOT-ALIGNMENT", "8-byte aligned", page_offset)
    return 0xF9400000 | ((page_offset // 8) << 10) | (base << 5) | destination


def _encode_br(register: int) -> int:
    return 0xD61F0000 | (register << 5)


@dataclass(frozen=True)
class AndroidExport:
    name: bytes
    function_cid: bytes

    def __post_init__(self) -> None:
        if not self.name or b"\x00" in self.name:
            raise ValueError("export name must be nonempty and NUL-free")
        if len(self.function_cid) != 32:
            raise ValueError("function CID must be 32 bytes")


@dataclass(frozen=True)
class AndroidElfMetrics:
    file_bytes: int
    text_bytes: int
    rodata_bytes: int
    data_bytes: int
    bss_bytes: int
    load_segments: int
    exported_symbols: int
    imported_symbols: int
    dynamic_relocations: int
    needed_libraries: int
    constructors: int
    tls_entries: int


@dataclass(frozen=True)
class AndroidSharedObject:
    data: bytes
    target_cid: bytes
    exports: tuple[AndroidExport, ...]
    imports: tuple[tuple[bytes, bytes], ...]
    metrics: AndroidElfMetrics
    text_offset: int
    function_offsets: tuple[tuple[bytes, int], ...]

    @property
    def artifact_bytes(self) -> bytes:
        return self.data


@dataclass(frozen=True)
class AndroidElfView:
    elf_class: int
    data_encoding: int
    elf_type: int
    machine: int
    load_alignments: tuple[int, ...]
    exports: tuple[bytes, ...]
    imports: tuple[bytes, ...]
    needed: tuple[bytes, ...]
    relocation_count: int
    has_init_array: bool
    has_fini_array: bool
    has_tls: bool
    text_offset: int
    text_size: int


def emit_android_elf(
    bundle: Aarch64Bundle,
    exports: Sequence[AndroidExport],
    *,
    soname: bytes = b"libxaxmodule.so",
    rodata: bytes = b"",
    data: bytes = b"",
    bss_bytes: int = 0,
) -> AndroidSharedObject:
    if not exports:
        raise ValueError("Android shared object requires at least one explicit export")
    exports = tuple(sorted(exports, key=lambda item: item.name))
    if len({item.name for item in exports}) != len(exports):
        raise ValueError("duplicate export name")
    function_offsets = dict(bundle.function_offsets)
    for item in exports:
        if item.function_cid not in function_offsets:
            fail("XAX.ANDROID.EXPORT", item.name.decode("ascii", "replace"), "ANDROID-EXPORT-FUNCTION-REACHABLE", "compiled function CID", item.function_cid.hex())
    if not soname or b"\x00" in soname or bss_bytes < 0:
        raise ValueError("invalid SONAME/BSS size")

    referenced_imports = sorted({(library, name) for _position, library, name in bundle.foreign_calls})
    by_name: dict[bytes, bytes] = {}
    for library, name in referenced_imports:
        previous = by_name.setdefault(name, library)
        if previous != library:
            fail("XAX.ANDROID.IMPORT", name.decode("ascii", "replace"), "ANDROID-IMPORT-UNAMBIGUOUS", previous.decode("ascii", "replace"), library.decode("ascii", "replace"))

    text = bytearray(bundle.code)
    while len(text) % 16:
        text.extend((0xD503201F).to_bytes(4, "little"))
    thunk_offsets: dict[bytes, int] = {}
    for _library, name in referenced_imports:
        if name in thunk_offsets:
            continue
        thunk_offsets[name] = len(text)
        text.extend(b"\x00" * 12)  # ADRP x16; LDR x16,[x16,#off]; BR x16

    # Foreign calls branch to local PIC thunks.  Dynamic lookup occurs only in
    # the referenced GOT slot; internal/local calls remain direct BL.
    for position, _library, name in bundle.foreign_calls:
        displacement = thunk_offsets[name] - position
        if displacement % 4 or not -(1 << 27) <= displacement < (1 << 27):
            fail("XAX.ANDROID.CALL", name.decode("ascii", "replace"), "ANDROID-LOCAL-THUNK-RANGE", "BL imm26", displacement)
        text[position:position + 4] = (0x94000000 | ((displacement // 4) & 0x3FFFFFF)).to_bytes(4, "little")

    export_names = [item.name for item in exports]
    import_names = sorted(by_name)
    needed_libraries = sorted({library for library, _name in referenced_imports})
    dynstr, string_offsets = _c_string_table([soname, *export_names, *import_names, *needed_libraries])
    symbol_names = [b"", *export_names, *import_names]
    hash_bytes = _hash_section(symbol_names)
    dynsym_size = 24 * len(symbol_names)
    rela_size = 24 * len(import_names)

    phnum = 4
    elf_header_size = 64
    program_header_size = 56
    cursor = elf_header_size + phnum * program_header_size
    hash_offset = _align(cursor, 8)
    dynsym_offset = _align(hash_offset + len(hash_bytes), 8)
    dynstr_offset = dynsym_offset + dynsym_size
    rela_offset = _align(dynstr_offset + len(dynstr), 8)
    text_offset = _align(rela_offset + rela_size, 16)
    rodata_offset = _align(text_offset + len(text), 16)
    rx_end = rodata_offset + len(rodata)
    rw_offset = _align(rx_end, ELF_PAGE_ALIGNMENT)
    got_offset = rw_offset
    got_size = 8 * len(import_names)
    data_offset = _align(got_offset + got_size, 8)

    dynamic_entry_count = 6 + len(needed_libraries) + 1  # base + needed + null
    if import_names:
        dynamic_entry_count += 3
    dynamic_offset = _align(data_offset + len(data), 8)
    dynamic_size = dynamic_entry_count * 16
    rw_file_end = dynamic_offset + dynamic_size
    bss_offset = _align(rw_file_end, 8)
    rw_mem_end = bss_offset + bss_bytes

    text_address = text_offset
    hash_address = hash_offset
    dynsym_address = dynsym_offset
    dynstr_address = dynstr_offset
    rela_address = rela_offset
    got_address = got_offset
    dynamic_address = dynamic_offset

    # Patch import thunks now that GOT virtual addresses are known.
    import_index_by_name = {name: index for index, name in enumerate(import_names)}
    for name, thunk_offset in thunk_offsets.items():
        target = got_address + import_index_by_name[name] * 8
        pc = text_address + thunk_offset
        words = (
            _encode_adrp(16, pc, target),
            _encode_ldr_x(16, 16, target),
            _encode_br(16),
        )
        text[thunk_offset:thunk_offset + 12] = b"".join(word.to_bytes(4, "little") for word in words)

    # Function sizes are exact to the next compiled function start, excluding
    # import thunks.  The final function ends at the pre-thunk bundle length.
    ordered_functions = sorted(bundle.function_offsets, key=lambda item: item[1])
    function_sizes: dict[bytes, int] = {}
    for index, (cid, offset) in enumerate(ordered_functions):
        end = ordered_functions[index + 1][1] if index + 1 < len(ordered_functions) else len(bundle.code)
        function_sizes[cid] = max(0, end - offset)

    dynsym = bytearray(_symbol(0, 0, 0, 0, 0, 0))
    text_section_index = 5
    for item in exports:
        dynsym.extend(_symbol(string_offsets[item.name], (STB_GLOBAL << 4) | STT_FUNC, 0, text_section_index, text_address + function_offsets[item.function_cid], function_sizes[item.function_cid]))
    import_symbol_index: dict[bytes, int] = {}
    for name in import_names:
        import_symbol_index[name] = len(dynsym) // 24
        dynsym.extend(_symbol(string_offsets[name], (STB_GLOBAL << 4) | STT_FUNC, 0, SHN_UNDEF, 0, 0))

    rela = bytearray()
    for index, name in enumerate(import_names):
        rela.extend(_rela(got_address + index * 8, import_symbol_index[name], R_AARCH64_GLOB_DAT))

    dynamic = bytearray()
    for library in needed_libraries:
        dynamic.extend(_dynamic(DT_NEEDED, string_offsets[library]))
    dynamic.extend(_dynamic(DT_HASH, hash_address))
    dynamic.extend(_dynamic(DT_STRTAB, dynstr_address))
    dynamic.extend(_dynamic(DT_SYMTAB, dynsym_address))
    dynamic.extend(_dynamic(DT_STRSZ, len(dynstr)))
    dynamic.extend(_dynamic(DT_SYMENT, 24))
    dynamic.extend(_dynamic(DT_SONAME, string_offsets[soname]))
    if import_names:
        dynamic.extend(_dynamic(DT_RELA, rela_address))
        dynamic.extend(_dynamic(DT_RELASZ, len(rela)))
        dynamic.extend(_dynamic(DT_RELAENT, 24))
    dynamic.extend(_dynamic(DT_NULL, 0))
    if len(dynamic) != dynamic_size:
        raise AssertionError((len(dynamic), dynamic_size))

    section_names = [
        b"", b".hash", b".dynsym", b".dynstr", b".rela.dyn", b".text", b".rodata",
        b".got", b".data", b".bss", b".dynamic", b".shstrtab",
    ]
    shstrtab, sh_name = _c_string_table(section_names[1:])
    shstrtab_offset = rw_file_end
    shoff = _align(shstrtab_offset + len(shstrtab), 8)
    shnum = len(section_names)
    shstrndx = 11
    file_size = shoff + shnum * 64

    ident = bytearray(b"\x7fELF")
    ident.extend(bytes((ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0, 0)))
    ident.extend(b"\x00" * (16 - len(ident)))
    elf_header = bytes(ident) + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_DYN,
        EM_AARCH64,
        EV_CURRENT,
        0,
        64,
        shoff,
        0,
        elf_header_size,
        program_header_size,
        phnum,
        64,
        shnum,
        shstrndx,
    )

    rx_filesz = rx_end
    rw_filesz = rw_file_end - rw_offset
    rw_memsz = rw_mem_end - rw_offset
    program_headers = b"".join((
        _program_header(PT_LOAD, PF_R | PF_X, 0, 0, rx_filesz, rx_filesz, ELF_PAGE_ALIGNMENT),
        _program_header(PT_LOAD, PF_R | PF_W, rw_offset, rw_offset, rw_filesz, rw_memsz, ELF_PAGE_ALIGNMENT),
        _program_header(PT_DYNAMIC, PF_R | PF_W, dynamic_offset, dynamic_address, dynamic_size, dynamic_size, 8),
        _program_header(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16),
    ))

    section_headers = [bytes(64)]
    section_headers.append(_section_header(sh_name[b".hash"], SHT_HASH, SHF_ALLOC, hash_address, hash_offset, len(hash_bytes), 2, 0, 4, 4))
    section_headers.append(_section_header(sh_name[b".dynsym"], SHT_DYNSYM, SHF_ALLOC, dynsym_address, dynsym_offset, len(dynsym), 3, 1, 8, 24))
    section_headers.append(_section_header(sh_name[b".dynstr"], SHT_STRTAB, SHF_ALLOC, dynstr_address, dynstr_offset, len(dynstr), 0, 0, 1, 0))
    section_headers.append(_section_header(sh_name[b".rela.dyn"], SHT_RELA, SHF_ALLOC, rela_address, rela_offset, len(rela), 2, 0, 8, 24))
    section_headers.append(_section_header(sh_name[b".text"], SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, text_address, text_offset, len(text), 0, 0, 16, 0))
    section_headers.append(_section_header(sh_name[b".rodata"], SHT_PROGBITS, SHF_ALLOC, rodata_offset, rodata_offset, len(rodata), 0, 0, 16, 0))
    section_headers.append(_section_header(sh_name[b".got"], SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, got_address, got_offset, got_size, 0, 0, 8, 8))
    section_headers.append(_section_header(sh_name[b".data"], SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, data_offset, data_offset, len(data), 0, 0, 8, 0))
    section_headers.append(_section_header(sh_name[b".bss"], SHT_NOBITS, SHF_ALLOC | SHF_WRITE, bss_offset, bss_offset, bss_bytes, 0, 0, 8, 0))
    section_headers.append(_section_header(sh_name[b".dynamic"], SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynamic_address, dynamic_offset, len(dynamic), 3, 0, 8, 16))
    section_headers.append(_section_header(sh_name[b".shstrtab"], SHT_STRTAB, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0))

    out = bytearray(file_size)
    out[:64] = elf_header
    out[64:64 + len(program_headers)] = program_headers
    out[hash_offset:hash_offset + len(hash_bytes)] = hash_bytes
    out[dynsym_offset:dynsym_offset + len(dynsym)] = dynsym
    out[dynstr_offset:dynstr_offset + len(dynstr)] = dynstr
    out[rela_offset:rela_offset + len(rela)] = rela
    out[text_offset:text_offset + len(text)] = text
    out[rodata_offset:rodata_offset + len(rodata)] = rodata
    # GOT is initially zero and populated only by Android dynamic relocations.
    out[data_offset:data_offset + len(data)] = data
    out[dynamic_offset:dynamic_offset + len(dynamic)] = dynamic
    out[shstrtab_offset:shstrtab_offset + len(shstrtab)] = shstrtab
    out[shoff:shoff + len(section_headers) * 64] = b"".join(section_headers)

    metrics = AndroidElfMetrics(
        len(out), len(text), len(rodata), len(data), bss_bytes, 2, len(exports), len(import_names), len(import_names), len(needed_libraries), 0, 0
    )
    return AndroidSharedObject(bytes(out), bundle.target_cid, exports, tuple(referenced_imports), metrics, text_offset, bundle.function_offsets)


def compile_android_shared(
    reader: StoreReader,
    exports: Sequence[AndroidExport | SemanticObject],
    *,
    target_object: SemanticObject | None = None,
    soname: bytes = b"libxaxmodule.so",
    rodata: bytes = b"",
    data: bytes = b"",
    bss_bytes: int = 0,
) -> AndroidSharedObject:
    target_object = target_object or android_arm64_shared_target()
    normalized_exports: list[AndroidExport] = []
    for item in exports:
        if isinstance(item, AndroidExport):
            normalized_exports.append(item)
        else:
            decoded = decode_android_export(item)
            normalized_exports.append(AndroidExport(decoded.name, decoded.function_cid))
    exports = tuple(normalized_exports)
    description = decode_native_target(target_object)
    if description.identity not in (ANDROID_TARGET_IDENTITY, ANDROID_GENERAL_TARGET_IDENTITY) or (description.architecture, description.abi, description.image_format) != (3, 4, 4):
        fail(
            "XAX.ANDROID.TARGET", target_object.cid.hex(), "ANDROID-ARM64-SHARED-TARGET",
            [ANDROID_TARGET_IDENTITY.decode(), ANDROID_GENERAL_TARGET_IDENTITY.decode()],
            description.identity.decode("ascii", "replace"),
        )
    function_cids = tuple(dict.fromkeys(item.function_cid for item in exports))
    bundle = compile_aarch64_bundle_bound_target(reader, function_cids, target_object)
    return emit_android_elf(bundle, exports, soname=soname, rodata=rodata, data=data, bss_bytes=bss_bytes)


def inspect_android_elf(data: bytes) -> AndroidElfView:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    elf_class, encoding = data[4], data[5]
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 54)
    load_alignments = []
    has_tls = False
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, _flags, _poff, _vaddr, _paddr, _filesz, _memsz, align = struct.unpack_from("<IIQQQQQQ", data, offset)
        if p_type == PT_LOAD:
            load_alignments.append(align)
        if p_type == 7:  # PT_TLS
            has_tls = True
    sections = []
    for index in range(shnum):
        values = struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
        sections.append(values)
    shstr = sections[shstrndx]
    shstr_data = data[shstr[4]:shstr[4] + shstr[5]]
    def section_name(item) -> bytes:
        start = item[0]
        end = shstr_data.find(b"\x00", start)
        return shstr_data[start:end]
    by_name = {section_name(item): item for item in sections}
    dynstr_item = by_name[b".dynstr"]
    dynstr = data[dynstr_item[4]:dynstr_item[4] + dynstr_item[5]]
    dynsym_item = by_name[b".dynsym"]
    exports: list[bytes] = []
    imports: list[bytes] = []
    for offset in range(dynsym_item[4] + 24, dynsym_item[4] + dynsym_item[5], 24):
        name_offset, info, _other, shndx, _value, _size = struct.unpack_from("<IBBHQQ", data, offset)
        end = dynstr.find(b"\x00", name_offset)
        name = dynstr[name_offset:end]
        if (info >> 4) == STB_GLOBAL and (info & 0xF) == STT_FUNC:
            (imports if shndx == SHN_UNDEF else exports).append(name)
    dynamic_item = by_name[b".dynamic"]
    needed = []
    for offset in range(dynamic_item[4], dynamic_item[4] + dynamic_item[5], 16):
        tag, value = struct.unpack_from("<QQ", data, offset)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            end = dynstr.find(b"\x00", value)
            needed.append(dynstr[value:end])
    rela_item = by_name[b".rela.dyn"]
    text_item = by_name[b".text"]
    return AndroidElfView(
        elf_class,
        encoding,
        elf_type,
        machine,
        tuple(load_alignments),
        tuple(exports),
        tuple(imports),
        tuple(needed),
        rela_item[5] // 24,
        b".init_array" in by_name,
        b".fini_array" in by_name,
        has_tls,
        text_item[4],
        text_item[5],
    )


def validate_with_readelf(path: str | os.PathLike[str]) -> str:
    readelf = shutil.which("readelf") or shutil.which("llvm-readelf")
    if not readelf:
        return ""
    command = [readelf, "-h", "-l", "-S", "-d", "-s", "-r", str(path)]
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return result.stdout


def write_modern_libxposed_fixture(
    directory: str | os.PathLike[str],
    shared_object: AndroidSharedObject,
    *,
    library_name: str = "libxaxmodule.so",
    scope: str = "com.example.target",
) -> Path:
    """Write a packaging-only modern libxposed Android fixture.

    Gradle packages the already generated native library.  It never compiles XAX
    through CMake/ndk-build and carries no legacy assets/xposed_init metadata.
    """
    root = Path(directory)
    jni = root / "app" / "src" / "main" / "jniLibs" / "arm64-v8a"
    meta = root / "app" / "src" / "main" / "resources" / "META-INF" / "xposed"
    res = root / "app" / "src" / "main" / "res" / "values"
    for item in (jni, meta, res):
        item.mkdir(parents=True, exist_ok=True)
    (jni / library_name).write_bytes(shared_object.data)
    (meta / "native_init.list").write_text(library_name + "\n", encoding="utf-8")
    (meta / "module.prop").write_text("minApiVersion=101\ntargetApiVersion=102\nstaticScope=true\n", encoding="utf-8")
    (meta / "scope.list").write_text(scope + "\n", encoding="utf-8")
    (res / "strings.xml").write_text(
        '<resources>\n    <string name="app_name">XAX Native Fixture</string>\n    <string name="app_description">XAX generated native libxposed fixture</string>\n</resources>\n',
        encoding="utf-8",
    )
    manifest = root / "app" / "src" / "main" / "AndroidManifest.xml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '  <application android:label="@string/app_name" android:description="@string/app_description" android:hasCode="false"/>\n'
        '</manifest>\n',
        encoding="utf-8",
    )
    (root / "settings.gradle.kts").write_text('pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }\ndependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }\nrootProject.name = "xax-native-fixture"\ninclude(":app")\n', encoding="utf-8")
    (root / "build.gradle.kts").write_text('plugins { id("com.android.application") version "8.7.3" apply false }\n', encoding="utf-8")
    (root / "app" / "build.gradle.kts").write_text(
        'plugins { id("com.android.application") }\n'
        'android {\n'
        '  namespace = "org.xax.nativefixture"\n'
        '  compileSdk = 35\n'
        '  defaultConfig { applicationId = "org.xax.nativefixture"; minSdk = 23; targetSdk = 35; versionCode = 1; versionName = "1" }\n'
        '  packaging { resources { merges += "META-INF/xposed/*" } }\n'
        '}\n',
        encoding="utf-8",
    )
    return root
