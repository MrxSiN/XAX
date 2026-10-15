"""S7b (ADR-179): rejection diagnostics decided and written by XAX programs.

A backend program that rejects its input writes one diagnostic record into its output
view and sets the status word to ``REJECT``.  The record is the stable machine payload of
``xax_compiler.Diagnostic``: code, entity, rule, expected, and actual, each a typed value.
The XAX program decides every field; ``decode_diagnostic`` only renders words (packed
bytes to text, CID words to hex, a terminator code to its ``TerminatorKind``) and decides
nothing.

Record layout (output-view words): ``DIAG_AT`` holds the cursor (the word after the
record); the record follows as ``code, entity, rule, expected, actual`` (S15b: optionally then the dependencies and
the repair neighborhood, each a list), where a value is

    INT n | STR length packed-bytes... | LIST count values... | NONE | CID w0 w1 w2 w3 | TERMINATOR n |
    WIDE low high | FORMAT template-STR count values... | HEX length packed-bytes... | TUPLE count values... |
    KIND n | BYTES length packed-bytes... | ENUM enum n | OBJECT class count values... | BOOL n | NAME enum n |
    DICT count (key value)... | SINT n

Text and HEX bytes are packed eight per word, little-endian; a CID is four big-endian 64-bit words; WIDE is the
integer ``high * 2**64 + low`` (a ULEB can carry 70 bits); FORMAT is ``template.format(*values)`` -- the program
chooses the template and the values, the host only renders; HEX renders bytes as lowercase hex.  S15b (ADR-288): BYTES
renders the bytes themselves; ENUM is member ``n`` of ``ENUMS[enum]`` and NAME its name; OBJECT is
``OBJECTS[class](*values)``; BOOL is ``bool(n)``.
"""

from __future__ import annotations

from xax_compiler import Diagnostic, Kind, TerminatorKind
from xax_selfhost_facts import E, NONE

REJECT = 2
DIAG_AT = 11 << 20
T_INT, T_STR, T_LIST, T_NONE, T_CID, T_TERMINATOR, T_WIDE, T_FORMAT, T_HEX, T_TUPLE, T_KIND, T_BYTES, T_ENUM, T_OBJECT, T_BOOL, T_NAME = range(16)
T_DICT, T_SINT = 16, 17  # S15b.3 (ADR-292): ``{key: value}`` (count, then key and value pairs); a signed 64-bit integer
# S15b (ADR-288): the enumerations and value classes a record can name (by position; append only).
ENUM_NAMES = ("Kind", "BuildForm", "BuildMode", "BuildCapabilityKind", "ArtifactKind", "OptimizationObjective", "AtomicScope", "AtomicFamily",
              "EffectDomain", "TargetValueConstraintKind", "Operation", "TerminatorKind", "OpaqueKind", "Permission", "IntCompare",
              "AtomicRmwKind", "CompareExchangeStrength")
OBJECT_NAMES = ("BuildCapability", "AcceleratorMemorySpace", "_EffectType")


# -- XAX side: builders that emit the record-writing nodes --------------------------------------

def put(e: E, word) -> None:
    cursor = e.ld(DIAG_AT)
    e.st(cursor, word)
    e.st(DIAG_AT, e.add(cursor, 1))


def text(e: E, value: str) -> None:
    data = value.encode("ascii")
    put(e, T_STR)
    put(e, len(data))
    for start in range(0, len(data), 8):
        put(e, int.from_bytes(data[start:start + 8], "little"))


def integer(e: E, value) -> None:
    put(e, T_INT)
    put(e, value)


def tagged(e: E, tag: int, value) -> None:
    put(e, tag)
    put(e, value)


def none(e: E) -> None:
    put(e, T_NONE)


def cid(e: E, words) -> None:
    put(e, T_CID)
    for word in words:
        put(e, word)


def begin(e: E) -> None:
    e.st(DIAG_AT, DIAG_AT + 1)


def reject_unless(e: E, condition, write) -> None:
    """Unless ``condition``: write the record (``write()`` emits code, entity, rule, expected, actual), set the
    status word to ``REJECT``, and give ``NONE`` (every caller propagates it)."""
    def rejected():
        begin(e)
        write()
        e.st(0, REJECT)
        e.give(NONE)

    e.if_(e.not_(condition), rejected)


# -- host side: rendering ---------------------------------------------------------------------------

def decode_diagnostic(read) -> Diagnostic | None:
    """The ``Diagnostic`` a program wrote when its status word is ``REJECT`` (``read(start word, count)``), else
    None."""
    (status,) = read(0, 1)
    if status != REJECT:
        return None
    (end,) = read(DIAG_AT, 1)
    return decode_record(read(DIAG_AT + 1, end - DIAG_AT - 1))


def _registered(name: str):
    import xax_build
    import xax_compiler

    return getattr(xax_compiler, name, None) or getattr(xax_build, name)


def _packed(words, length: int) -> bytes:
    return b"".join(word.to_bytes(8, "little") for word in words)[:length]


def decode_record(words) -> Diagnostic:
    """Render the record ``words`` (64-bit) into a ``Diagnostic``."""
    position = 0

    def value():
        nonlocal position
        tag = words[position]
        position += 1
        if tag == T_NONE:
            return None
        if tag == T_CID:
            position += 4
            return b"".join(word.to_bytes(8, "big") for word in words[position - 4:position]).hex()
        if tag in (T_STR, T_HEX, T_BYTES):
            length = words[position]
            count = (length + 7) // 8
            data = _packed(words[position + 1:position + 1 + count], length)
            position += 1 + count
            # S15b.4 (ADR-294): a text the bootstrap quotes with ``decode("ascii", "replace")`` carries its raw bytes.
            return data.decode("ascii", "replace") if tag == T_STR else data.hex() if tag == T_HEX else data
        if tag in (T_ENUM, T_NAME):
            position += 2
            member = _registered(ENUM_NAMES[words[position - 2]])(words[position - 1])
            return member if tag == T_ENUM else member.name
        if tag == T_DICT:
            count = words[position]
            position += 1
            pairs = [(value(), value()) for _ in range(count)]
            return dict(pairs)
        if tag == T_SINT:
            position += 1
            return words[position - 1] - (1 << 64) if words[position - 1] >> 63 else words[position - 1]
        if tag == T_OBJECT:
            name, count = words[position], words[position + 1]
            position += 2
            return _registered(OBJECT_NAMES[name])(*(value() for _ in range(count)))
        if tag in (T_LIST, T_TUPLE):
            count = words[position]
            position += 1
            items = [value() for _ in range(count)]
            return items if tag == T_LIST else tuple(items)
        if tag == T_WIDE:
            position += 2
            return words[position - 1] << 64 | words[position - 2]
        if tag == T_FORMAT:
            template = value()
            count = words[position]
            position += 1
            return template.format(*(value() for _ in range(count)))
        number = words[position]
        position += 1
        return {T_INT: int, T_TERMINATOR: TerminatorKind, T_KIND: Kind, T_BOOL: bool}[tag](number)

    code, entity, rule, expected, actual = (value() for _ in range(5))
    related = ()
    if position < len(words):  # S15b (ADR-288): the dependencies and the repair neighborhood
        related = (tuple(value()), tuple(value()))
    if position != len(words):
        raise ValueError(f"diagnostic record has {len(words) - position} trailing words")
    return Diagnostic(code, entity, rule, expected, actual, *related)


__all__ = ["DIAG_AT", "NONE", "REJECT", "begin", "cid", "decode_diagnostic", "decode_record", "integer", "none", "put", "reject_unless", "tagged", "text"]
