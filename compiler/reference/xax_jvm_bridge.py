"""Native code plus a generated JVM bridge: the second OI-35 strategy (ADR-165).

The program is compiled for ``x86_64-linux-elf-exec-v1`` (syscalls only, no
C imports, position-independent code) and packaged as an x86-64 ``ET_DYN``
JNI library.  Two compiler-generated adapters connect it to HotSpot (UR-001):

* native side: the existing SysV entry adapter (ADR-102), exported as the
  JNI symbol ``Java_<class>_<method>``; it maps the SysV arguments to the
  XAX internal convention and reserves the shadow space;
* managed side: a bridge class with a ``static native`` method of the
  matching descriptor, a ``<clinit>`` that calls ``System.loadLibrary``,
  and, for a process entry, a ``main`` that ends the JVM with the status
  the entry returns (``System.exit``).

The JNI entry takes ``JNIEnv*`` and the ``jclass`` as two 64-bit parameters,
which the program may ignore, then up to two integer parameters, and returns
at most one integer.  No JNI function is called: objects never cross, so the
bridge needs no reference management.  The library has no relocations, no
``DT_NEEDED``, and a non-executable stack.  A trap in the native code is a
fault in a JNI frame: HotSpot ends the process abnormally (no exception).
"""

from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass

from xax_compiler import (
    X86_64_LINUX_ABI,
    X86_64_LINUX_ELF_EXEC_FORMAT,
    Kind,
    StoreReader,
    _decode_function_interface,
    _is_proof_type,
    decode_native_target,
    fail,
    store_resolver,
)
from xax_elf import c_string_table, dynamic, hash_section, program_header, symbol
from xax_jvm import _ZIP_DATE, _Method, _Pool, _class_file, _u2
from xax_x86_64 import NativeImage, _sysv_entry_adapter, _value_width, compile_native

BRIDGE_IDENTITY = b"jvm-jni-x86_64-linux-bridge-v1"
_ELF_HEADER_SIZE, _PROGRAM_HEADER_SIZE, _SYMBOL_SIZE = 64, 56, 24
_PAGE = 4096
PT_LOAD, PT_DYNAMIC, PT_GNU_STACK = 1, 2, 0x6474E551
PF_R, PF_W, PF_X = 4, 2, 1
DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_SONAME = 0, 4, 5, 6, 10, 11, 14
_DESCRIPTOR = {1: "Z", 8: "B", 16: "S", 32: "I", 64: "J"}


@dataclass(frozen=True)
class JniBridge:
    library: bytes  # the ET_DYN JNI library
    library_name: str  # System.loadLibrary name: the file is lib<name>.so
    bridge_class: bytes  # the generated managed bridge
    jar: bytes  # the bridge class in a deterministic JAR (Main-Class for a process entry)
    class_name: str
    method: str
    descriptor: str
    symbol: str  # the exported JNI symbol
    image: NativeImage
    adapter_bytes: int  # the generated native entry adapter

    @property
    def generated_adapter_bytes(self) -> int:
        """Native entry adapter plus the bridge class: everything not compiled from the program."""
        return self.adapter_bytes + len(self.bridge_class)


def jni_mangle(text: str) -> str:
    """JNI short-name mangling for ASCII names (``/`` → ``_``, ``_`` → ``_1``)."""
    out = []
    for character in text:
        if character == "/":
            out.append("_")
        elif character == "_":
            out.append("_1")
        elif character.isascii() and character.isalnum():
            out.append(character)
        else:
            out.append(f"_0{ord(character):04x}")
    return "".join(out)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def emit_jni_library(code: bytes, exports: tuple[tuple[str, int, int], ...], soname: str) -> bytes:
    """An x86-64 ``ET_DYN`` exporting ``(name, code offset, size)`` functions from position-independent ``code``."""
    names = [name.encode("ascii") for name, _offset, _size in exports]
    strings, string_offsets = c_string_table((soname.encode("ascii"), *names))
    header_count = 4
    symtab_offset = _ELF_HEADER_SIZE + header_count * _PROGRAM_HEADER_SIZE
    strtab_offset = symtab_offset + _SYMBOL_SIZE * (len(names) + 1)
    hash_bytes = hash_section((b"", *names))
    hash_offset = _align(strtab_offset + len(strings), 8)
    code_offset = _align(hash_offset + len(hash_bytes), 16)
    text_end = code_offset + len(code)
    symbols = bytes(_SYMBOL_SIZE) + b"".join(
        symbol(string_offsets[name], 0x12, 0, 1, code_offset + offset, size)  # GLOBAL FUNC, defined (any section index but UNDEF/ABS)
        for name, (_text, offset, size) in zip(names, exports)
    )
    rw_offset = _align(text_end, 8)
    rw_address = _align(text_end, _PAGE) + rw_offset % _PAGE
    entries = (
        (DT_SONAME, string_offsets[soname.encode("ascii")]), (DT_HASH, hash_offset), (DT_STRTAB, strtab_offset),
        (DT_SYMTAB, symtab_offset), (DT_STRSZ, len(strings)), (DT_SYMENT, _SYMBOL_SIZE), (DT_NULL, 0),
    )
    dynamic_bytes = b"".join(dynamic(tag, value) for tag, value in entries)
    headers = b"".join((
        program_header(PT_LOAD, PF_R | PF_X, 0, 0, text_end, text_end, _PAGE),
        program_header(PT_LOAD, PF_R | PF_W, rw_offset, rw_address, len(dynamic_bytes), len(dynamic_bytes), _PAGE),
        program_header(PT_DYNAMIC, PF_R | PF_W, rw_offset, rw_address, len(dynamic_bytes), len(dynamic_bytes), 8),
        program_header(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16),
    ))
    elf_header = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8) + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, _ELF_HEADER_SIZE, 0, 0, _ELF_HEADER_SIZE, _PROGRAM_HEADER_SIZE, header_count, 64, 0, 0,
    )  # ET_DYN, EM_X86_64, no entry, no section headers
    out = bytearray(elf_header + headers)
    for offset, blob in ((symtab_offset, symbols), (strtab_offset, strings), (hash_offset, hash_bytes), (code_offset, code), (rw_offset, dynamic_bytes)):
        out.extend(bytes(offset - len(out)))
        out.extend(blob)
    return bytes(out)


def _bridge_class(class_name: str, method: str, descriptor: str, library_name: str, main: bool) -> bytes:
    pool = _Pool()
    load = pool.method("java/lang/System", "loadLibrary", "(Ljava/lang/String;)V")
    clinit = bytes((0x13,)) + _u2(pool.string(library_name)) + bytes((0xB8,)) + _u2(load) + bytes((0xB1,))  # ldc_w; invokestatic
    methods = [
        _Method("<clinit>", "()V", clinit, 1, 0, (), (), (), access=0x0008),
        _Method(method, descriptor, b"", 0, 0, (), (), (), access=0x0109),  # public static native
    ]
    if main:
        body = bytes((0xB8,)) + _u2(pool.method(class_name, method, descriptor))
        body += bytes((0xB8,)) + _u2(pool.method("java/lang/System", "exit", "(I)V")) + bytes((0xB1,))
        methods.append(_Method("main", "([Ljava/lang/String;)V", body, 1, 1, (), (), ()))
    return _class_file(class_name, methods, pool)[0]


def _jar(class_name: str, class_bytes: bytes, main: bool) -> bytes:
    manifest = b"Manifest-Version: 1.0\r\nCreated-By: " + BRIDGE_IDENTITY + b"\r\n"
    if main:
        manifest += b"Main-Class: " + class_name.replace("/", ".").encode("ascii") + b"\r\n"
    manifest += b"\r\n"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in (("META-INF/MANIFEST.MF", manifest), (class_name + ".class", class_bytes)):
            info = zipfile.ZipInfo(name, _ZIP_DATE)
            info.external_attr = 0o100644 << 16
            info.create_system = 0
            archive.writestr(info, data)
    return out.getvalue()


def compile_jni_bridge(
    reader: StoreReader, entry_cid: bytes, target_cid: bytes, *, class_name: str = "xax/Native", method: str = "run",
    library_name: str = "xaxnative", process_entry: bool = False,
) -> JniBridge:
    """Compile ``entry`` to a JNI library and generate its bridge class."""
    resolve = store_resolver(reader)
    target = decode_native_target(resolve(target_cid))
    where = entry_cid.hex()
    if target.abi != X86_64_LINUX_ABI or target.image_format != X86_64_LINUX_ELF_EXEC_FORMAT:
        fail("XAX.JNI.TARGET", target_cid.hex(), "JNI-BRIDGE-TARGET", "x86_64-linux-elf-exec-v1", [target.abi, target.image_format])
    entry = resolve(entry_cid)
    if entry.kind != Kind.FUNCTION:
        fail("XAX.JNI.ENTRY", where, "JNI-ENTRY-FUNCTION", Kind.FUNCTION.name, entry.kind.name)
    _graph, parameters, returns = _decode_function_interface(entry, resolve)
    parameter_widths = [_value_width(resolve, cid) for cid in parameters if not _is_proof_type(resolve(cid))]
    return_widths = [_value_width(resolve, cid) for cid in returns if not _is_proof_type(resolve(cid))]
    if (
        parameter_widths[:2] != [64, 64] or len(parameter_widths) > 4 or len(return_widths) > 1
        or any(width not in _DESCRIPTOR for width in (*parameter_widths[2:], *return_widths))
    ):
        fail("XAX.JNI.ENTRY", where, "JNI-ENTRY-SIGNATURE", "(env: bits<64>, class: bits<64>, <=2 integers) -> <=1 integer", [parameter_widths, return_widths])
    result = _DESCRIPTOR[return_widths[0]] if return_widths else "V"
    if process_entry and (parameter_widths[2:] or result != "I"):
        fail("XAX.JNI.ENTRY", where, "JNI-PROCESS-ENTRY", "(env, class) -> bits<32> status", [parameter_widths, return_widths])
    descriptor = "(" + "".join(_DESCRIPTOR[width] for width in parameter_widths[2:]) + ")" + result
    image = compile_native(reader, entry_cid, target_cid)
    if image.imports:
        fail("XAX.JNI.ENTRY", where, "JNI-NO-IMPORTS", "syscalls only", [name.decode("ascii", "replace") for _p, _l, name in image.imports])
    adapter, call = _sysv_entry_adapter(entry, resolve, target)
    code = bytearray(image.code)
    code.extend(b"\x90" * (_align(len(code), 16) - len(code)))
    adapter_offset = len(code)
    code.extend(adapter)
    site = adapter_offset + call
    code[site:site + 4] = (image.entry_offset - (site + 4)).to_bytes(4, "little", signed=True)
    jni_symbol = f"Java_{jni_mangle(class_name)}_{jni_mangle(method)}"
    library = emit_jni_library(bytes(code), ((jni_symbol, adapter_offset, len(adapter)),), f"lib{library_name}.so")
    bridge = _bridge_class(class_name, method, descriptor, library_name, process_entry)
    return JniBridge(library, library_name, bridge, _jar(class_name, bridge, process_entry), class_name, method, descriptor, jni_symbol, image, len(adapter))
