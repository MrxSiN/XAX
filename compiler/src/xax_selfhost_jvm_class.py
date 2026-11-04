"""S15e.5 (ADR-327): ``xax_jvm``'s class file and JAR container as XAX functions.

Byte buffers are records ``[data, length, capacity]`` in the arena, one byte per word.  The constant pool
(``_Pool``) keeps its entries' bytes in one buffer and, per pool index, the entry's place there; an entry is found
again by its bytes (equal keys give equal bytes: the tag and the indices it names fix them).  Per index it also keeps
what ``_operand_stack_depth`` reads from the entry: a method's argument and result slots, a field's size.  The class
file (``_class_file``, ``_serialize_method``) and the deterministic stored JAR (``_jar``: the manifest, then the
class, CRC-32 over each, the 1980-01-01 date) are written byte for byte as the bootstrap writes them.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE
from xax_selfhost_views_backend import _call, _ok

BUF_WORDS = 3  # data, length, capacity
B_DATA, B_LEN, B_CAP = range(3)
# Pool record: the bytes buffer, the next index, per index the entry start and length in the bytes, its argument slots
# (a method: parameters, plus the receiver for an instance call is the caller's), result slots, and field size.
(P_BYTES, P_COUNT, P_START, P_LENGTH, P_ARGS, P_RESULT, P_FIELD, P_SCRATCH) = range(8)


# -- buffers ------------------------------------------------------------------------------------------------------

def buffer(e: E, name: str, capacity):
    """A new buffer record into ``name`` (NONE: the arena is exhausted, the caller declines)."""
    p = e.p
    e.var(name, e.alloc(BUF_WORDS))
    _ok(e, e.ne(p[name], NONE))
    e.var(f"{name}_d", e.alloc(capacity))
    _ok(e, e.ne(p[f"{name}_d"], NONE))
    e.st(e.add(p[name], B_DATA), p[f"{name}_d"])
    e.st(e.add(p[name], B_LEN), 0)
    e.st(e.add(p[name], B_CAP), capacity)
    return p[name]


def blen(e: E, buf):
    return e.ld(e.add(buf, B_LEN))


def bdata(e: E, buf):
    return e.ld(e.add(buf, B_DATA))


def bat(e: E, buf, index):
    return e.ld(e.add(bdata(e, buf), index))


def put(e: E, buf, word, n: int):
    _call(e, "jb_put", buf, word, n)


def u1(e: E, buf, word):
    put(e, buf, word, 1)


def u2(e: E, buf, word):
    put(e, buf, word, 2)


def u4(e: E, buf, word):
    put(e, buf, e.and_(word, 0xFFFFFFFF), 4)


def le(e: E, buf, word, n: int):
    _call(e, "jb_le", buf, word, n)


def append(e: E, buf, data, n):
    _call(e, "jb_append", buf, data, n)


def text(e: E, buf, value: str):
    """Literal ASCII text into ``buf``."""
    for start in range(0, len(value), 8):
        chunk = value[start:start + 8].encode("ascii")
        put(e, buf, int.from_bytes(chunk, "big"), len(chunk))


# -- CRC-32 (zlib's, reflected 0xEDB88320) --------------------------------------------------------------------------


# -- the constant pool ----------------------------------------------------------------------------------------------

def _pf(e: E, pool, field: int):
    return e.ld(e.add(pool, field))


def scratch(e: E, pool):
    """The pool's scratch buffer, emptied."""
    s = _pf(e, pool, P_SCRATCH)
    e.st(e.add(s, B_LEN), 0)
    return s


# -- texts ----------------------------------------------------------------------------------------------------------

def literal(e: E, name: str, value: str):
    """A byte array holding ``value`` into ``name`` and ``name_n``."""
    p = e.p
    e.var(name, e.alloc(len(value) + 1))
    _ok(e, e.ne(p[name], NONE))
    for k, ch in enumerate(value.encode("ascii")):
        e.st(e.add(p[name], k), ch)
    e.var(f"{name}_n", len(value))


