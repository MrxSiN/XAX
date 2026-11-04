"""S15e.6g.1 (ADR-336): the DEX writer of the JVM-to-DEX lowering (``xax_dex_jvm.write_dex``) as an XAX program.

The program takes the lowered classes (their descriptors, access, superclass, interfaces, fields, and methods with their
code units, a unit either a 16-bit value or a symbolic string, type, field or method reference) and writes the one DEX
039 file as the bootstrap does: the strings (every referenced string and type, ordered by UTF-16 code units), the types,
the interned prototypes, the field and method references (each ordered and distinct), the code items in class and
method order with every symbolic unit resolved, the type lists (prototype parameters and interfaces, shared when equal),
the MUTF-8 string data, the class data (static and instance fields, direct and virtual methods, each by index), the map
list, the identifier sections, the header, the SHA-1 signature and the Adler-32 checksum.  A duplicate class or an index
past 16 bits (the bootstrap's ``XAX.DEX.*`` failures) makes the program decline.  It shares the bridge program's
helpers (``xax_selfhost_dex.HELPERS``).

Input (64-bit words; a string is its UTF-16 unit count and units; a prototype its return, parameter count and
parameters): the class count; per class its descriptor, access, superclass flag and superclass, interfaces (count,
strings), fields (count; name, type, access), methods (count; name, prototype, access, code flag, then the register,
in and out counts and the units: count; each a kind (0 value, 1 string, 2 type, 3 field: class, name, type; 4 method:
class, name, prototype) and its value or reference).
Output: the status (1) and the image record ``[1, 0, length, bytes packed eight to a word]`` at ``IMAGE_AT``.
"""

from __future__ import annotations

from xax_native import bootstrap_dir
from xax_selfhost_general_image import IMAGE_AT
from xax_selfhost_views_backend import NativeProgram

STORE_PATH = bootstrap_dir() / "xax_dex_writer.xax"
OUT = IMAGE_AT + 3
ACC_PRIVATE, ACC_STATIC, ACC_CONSTRUCTOR = 0x0002, 0x0008, 0x10000


_PROGRAM = NativeProgram(STORE_PATH, "dex-writer")
load_dex_writer_program = _PROGRAM.load
OPT_OUT = "XAX_DEX_WRITER_PYTHON"


def write_dex_with_xax(classes, *, required: bool = False) -> bytes | None:
    """The DEX bytes the XAX program writes for ``xax_dex_jvm.DexClassDef`` items, or None where it cannot run or
    declines (unless ``required``)."""
    import os

    import xax_dex as D
    import xax_native

    def text(value: str) -> list[int]:
        units = D._utf16_units(value)
        return [len(units), *units]

    def proto(returns: str, parameters) -> list[int]:
        return [*text(returns), len(parameters), *(w for item in parameters for w in text(item))]

    words = [len(classes)]
    for item in classes:
        words += [*text(item.descriptor), item.access, *([1, *text(item.superclass)] if item.superclass else [0]), len(item.interfaces)]
        for name in item.interfaces:
            words += text(name)
        words.append(len(item.fields))
        for field in item.fields:
            words += [*text(field.name), *text(field.type), field.access]
        words.append(len(item.methods))
        for method in item.methods:
            words += [*text(method.name), *proto(method.returns, method.parameters), method.access]
            if method.code is None:
                words.append(0)
                continue
            code = method.code
            words += [1, code.registers, code.ins, code.outs, len(code.units)]
            for unit in code.units:
                if not isinstance(unit, tuple):
                    words += [0, unit]
                    continue
                kind, key = unit
                if kind == "string":
                    words += [1, *text(key)]
                elif kind == "type":
                    words += [2, *text(key)]
                elif kind == "field":
                    words += [3, *text(key[0]), *text(key[1]), *text(key[2])]
                else:
                    words += [4, *text(key[0]), *text(key[1]), *proto(key[2], key[3])]
    if any(not 0 <= word < 1 << 63 for word in words):
        return None
    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    data = None
    if native is not None:
        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None
            head = read(IMAGE_AT, 3)
            packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
            return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]]

        data = native.run(words, collect)
        if data is None:
            xax_native.declined("dex-writer", 1)
    if data is None and required:
        raise RuntimeError("the XAX DEX writer program is unavailable or declined")
    return data
