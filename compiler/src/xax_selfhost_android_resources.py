"""S15e.6c (ADR-336): the binary Android resources (``xax_manifest.emit_binary_manifest``, ``xax_resources.emit_resources_arsc``)
as an XAX program.

One program, two modes.  Mode 0 is the binary ``AndroidManifest.xml``: the element tree of the manifest specification
(``uses-sdk``, the platform declarations' permissions and features, the application with its activity and launcher
filter, the receivers and services sorted by their class names, the declared components), the resource map (the base
attributes, ``debuggable`` when the manifest is, the declaration attributes the tree uses) in resource-ID order, the
UTF-8 string pool (the resource names first, then every other string sorted by its bytes), the namespace, the elements
with their attributes sorted (no namespace first, then by resource ID, then by name) and their typed values.  Mode 1 is
the bounded ``resources.arsc``: the value pool (the distinct values sorted by their bytes), the package with its
UTF-16 name, the type and key pools, the type spec and the default-configuration type chunk.

The Python front doors keep the specifications' own checks (they are host errors) and the carriers' decoding, and ask
this program first; ``XAX_GENERAL_FRONTEND_DIFF=1`` compares the two.  A string past the pools' 15-bit length bound (the
bootstrap's error) makes the program decline.

Input (64-bit words; a string is its UTF-8 byte count, then one byte per word):
mode 0: package, activity class, version code, min SDK, target SDK, launcher, debuggable; the application class
(present flag, then the string); the receivers (count; each class, exported, action present flag, then the action); the
services (count; each class, exported); the declarations present flag, then the permissions (count; each name, max SDK,
never-for-location), the features (count; each name, required) and the components (count; each kind (0 service,
1 receiver), class, exported, foreground present flag, foreground flags, the action count and the actions).
mode 1: package, the entry count, each entry's name and value (the specification's order).
Output: the status (1) and the image record ``[1, 0, length, bytes packed eight to a word]`` at ``IMAGE_AT``.
"""

from __future__ import annotations

from xax_compiler import x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_general_image import IMAGE_AT, IMAGE_END
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_android_resources.xax"
OUT = IMAGE_AT + 3  # the packed bytes
STATE_AT = 110 << 20
(G_CUR, G_EV, G_NEV, G_ORD, G_NORD) = (STATE_AT + k for k in range(5))
G_STR = STATE_AT + 16  # the constant strings' handles
NO_INDEX = 0xFFFFFFFF
TYPE_STRING, TYPE_INT_DEC, TYPE_INT_HEX, TYPE_INT_BOOLEAN = 0x03, 0x10, 0x11, 0x12
ATTRS = 6  # attributes an element has at most
A_WORDS = 5  # an attribute: namespace flag, name, type, value, resource ID
(A_NS, A_NAME, A_TYPE, A_VALUE, A_RES) = range(A_WORDS)

ANDROID_URI = "http://schemas.android.com/apk/res/android"
# The resource map's candidates in resource-ID order: (name, ID, when: 0 always, 1 a debuggable manifest, 2 used).
RESOURCE_ATTRIBUTES = (
    ("name", 0x01010003, 0), ("hasCode", 0x0101000C, 0), ("debuggable", 0x0101000F, 1), ("exported", 0x01010010, 0),
    ("minSdkVersion", 0x0101020C, 0), ("versionCode", 0x0101021B, 0), ("targetSdkVersion", 0x01010270, 0),
    ("maxSdkVersion", 0x01010271, 2), ("required", 0x0101028E, 2), ("foregroundServiceType", 0x01010599, 2),
    ("usesPermissionFlags", 0x01010644, 2),
)
RES_ID = {name: value for name, value, _when in RESOURCE_ATTRIBUTES}
CONSTANTS = (
    "android", ANDROID_URI, "manifest", "package", "uses-sdk", "uses-permission", "uses-feature", "application",
    "activity", "intent-filter", "action", "category", "receiver", "service", "android.intent.action.MAIN",
    "android.intent.category.LAUNCHER", "string", *(name for name, _id, _when in RESOURCE_ATTRIBUTES),
)
CONST = {text: k for k, text in enumerate(CONSTANTS)}
USES_PERMISSION_NEVER_FOR_LOCATION = 0x10000


def _shift_bytes(e: E, k):
    """``256 ** k`` for ``k`` in 0..7."""
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(k, q), 1 << (8 * q), result)
    return result


def _down(e: E, j: str, test, body):
    """``while j > 0 and test(): body()``, with ``test`` (a call reading element ``j - 1``) evaluated only while
    ``j > 0``: ``both`` evaluates every operand, so a plain condition would compare a word before the array."""
    go = f"{j}_go"
    e.var(go, 1)
    e.while_(lambda: e.ne(e.p[go], 0), lambda: e.if_(e.eq(e.p[j], 0), lambda: e.set(go, 0),
                                                       lambda: e.if_(e.ne(test(), 0), body, lambda: e.set(go, 0))))


def _put_fn(tables):
    """``put(byte)``: the next output byte (the running length is the record's length word)."""
    def build(e: E):
        p = e.p
        e.var("pb_pos", e.ld(IMAGE_AT + 2))
        e.var("pb_at", e.add(OUT, e.udiv(p["pb_pos"], 8)))
        _ok(e, e.lt(p["pb_at"], IMAGE_END))
        e.var("pb_k", e.urem(p["pb_pos"], 8))
        e.if_(e.eq(p["pb_k"], 0), lambda: e.st(p["pb_at"], p["byte"]),
              lambda: e.st(p["pb_at"], e.or_(e.ld(p["pb_at"]), e.mul(p["byte"], _shift_bytes(e, p["pb_k"])))))
        e.st(IMAGE_AT + 2, e.add(p["pb_pos"], 1))
        e.give(1)
    return _function(("byte",), build, tables)


def put(e: E, byte):
    _call(e, "ar_put", byte)


def le(e: E, value, n: int):
    """``n`` little-endian bytes of ``value``."""
    e.var("le_v", value)
    for k in range(n):
        put(e, e.and_(e.udiv(e.p["le_v"], 1 << (8 * k)) if k else e.p["le_v"], 255))


def pos(e: E):
    return e.ld(IMAGE_AT + 2)


def _patch_fn(tables):
    """``patch(at, value)``: the four little-endian bytes of ``value`` over the written bytes at ``at``."""
    def build(e: E):
        p = e.p

        def byte():
            e.var("pt_pos", e.add(p["at"], p["pt_k"]))
            e.var("pt_w", e.add(OUT, e.udiv(p["pt_pos"], 8)))
            e.var("pt_s", _shift_bytes(e, e.urem(p["pt_pos"], 8)))
            e.var("pt_old", e.and_(e.udiv(e.ld(p["pt_w"]), p["pt_s"]), 255))
            e.var("pt_new", e.and_(e.udiv(p["value"], _shift_bytes(e, p["pt_k"])), 255))
            e.st(p["pt_w"], e.add(e.sub(e.ld(p["pt_w"]), e.mul(p["pt_old"], p["pt_s"])), e.mul(p["pt_new"], p["pt_s"])))

        e.for_("pt_k", 0, 4, byte)
        e.give(1)
    return _function(("at", "value"), build, tables)


def _less_fn(tables):
    """1 when string ``a`` sorts before ``b`` (bytes; a prefix first)."""
    def build(e: E):
        p = e.p
        e.var("ls_an", e.ld(p["a"]))
        e.var("ls_bn", e.ld(p["b"]))
        e.var("ls_n", e.sel(e.lt(p["ls_an"], p["ls_bn"]), p["ls_an"], p["ls_bn"]))

        def compare():
            e.var("ls_x", e.ld(e.add(e.add(p["a"], 1), p["ls_k"])))
            e.var("ls_y", e.ld(e.add(e.add(p["b"], 1), p["ls_k"])))
            e.if_(e.lt(p["ls_x"], p["ls_y"]), lambda: e.give(1))
            e.if_(e.lt(p["ls_y"], p["ls_x"]), lambda: e.give(0))

        e.for_("ls_k", 0, p["ls_n"], compare)
        e.give(e.flag(e.lt(p["ls_an"], p["ls_bn"])))
    return _function(("a", "b"), build, tables)


def _same_fn(tables):
    """1 when strings ``a`` and ``b`` have the same bytes."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("sm_k", 1, e.add(e.ld(p["a"]), 1),
               lambda: e.if_(e.ne(e.ld(e.add(p["a"], p["sm_k"])), e.ld(e.add(p["b"], p["sm_k"]))), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _string_fn(tables):
    """``string()``: the input string at the cursor, copied to the arena (its handle), the cursor moved past it."""
    def build(e: E):
        p = e.p
        e.var("sr_at", e.ld(G_CUR))
        e.var("sr_n", e.rd(p["sr_at"]))
        _ok(e, e.le(p["sr_n"], 1 << 24))
        e.var("sr_h", e.alloc(e.add(p["sr_n"], 1)))
        _ok(e, e.ne(p["sr_h"], NONE))
        e.st(p["sr_h"], p["sr_n"])
        e.for_("sr_k", 0, p["sr_n"], lambda: e.st(e.add(e.add(p["sr_h"], 1), p["sr_k"]), e.rd(e.add(e.add(p["sr_at"], 1), p["sr_k"]))))
        e.st(G_CUR, e.add(e.add(p["sr_at"], 1), p["sr_n"]))
        e.give(p["sr_h"])
    return _function((), build, tables)


def _word_fn(tables):
    """``word()``: the input word at the cursor, the cursor moved past it."""
    def build(e: E):
        p = e.p
        e.var("wd_at", e.ld(G_CUR))
        e.st(G_CUR, e.add(p["wd_at"], 1))
        e.give(e.rd(p["wd_at"]))
    return _function((), build, tables)


def _units_fn(tables):
    """The UTF-16 code units of the UTF-8 string ``h`` (a four-byte sequence is a surrogate pair)."""
    def build(e: E):
        p = e.p
        e.var("un_c", 0)

        def each():
            e.var("un_b", e.ld(e.add(e.add(p["h"], 1), p["un_k"])))
            e.if_(e.ne(e.and_(p["un_b"], 0xC0), 0x80), lambda: e.set("un_c", e.add(p["un_c"], 1)))
            e.if_(e.le(0xF0, p["un_b"]), lambda: e.set("un_c", e.add(p["un_c"], 1)))

        e.for_("un_k", 0, e.ld(p["h"]), each)
        e.give(p["un_c"])
    return _function(("h",), build, tables)


def _length_fn(tables):
    """``length(v)``: the pools' one- or two-byte length; declines past 15 bits (the bootstrap's error)."""
    def build(e: E):
        p = e.p
        _ok(e, e.le(p["v"], 0x7FFF))
        e.if_(e.le(p["v"], 0x7F), lambda: put(e, p["v"]),
              lambda: (put(e, e.or_(0x80, e.udiv(p["v"], 256))), put(e, e.and_(p["v"], 255))))
        e.give(1)
    return _function(("v",), build, tables)


def _pool_fn(tables):
    """``pool(arr, n)``: the UTF-8 string pool of the ``n`` string handles at ``arr``."""
    def build(e: E):
        p = e.p
        e.var("pl_start", pos(e))
        for value, n in ((0x0001, 2), (28, 2), (0, 4), (p["n"], 4), (0, 4), (0x100, 4), (e.add(28, e.mul(p["n"], 4)), 4), (0, 4)):
            le(e, value, n)
        e.var("pl_off", 0)

        def offset():
            e.var("pl_h", e.ld(e.add(p["arr"], p["pl_k"])))
            e.var("pl_u", _call(e, "ar_units", p["pl_h"]))
            e.var("pl_b", e.ld(p["pl_h"]))
            _ok(e, e.both(e.le(p["pl_u"], 0x7FFF), e.le(p["pl_b"], 0x7FFF)))
            le(e, p["pl_off"], 4)
            e.set("pl_off", e.add(e.add(p["pl_off"], e.add(p["pl_b"], 3)),
                                  e.add(e.flag(e.lt(0x7F, p["pl_u"])), e.flag(e.lt(0x7F, p["pl_b"])))))

        e.for_("pl_k", 0, p["n"], offset)

        def item():
            e.var("pl_h", e.ld(e.add(p["arr"], p["pl_k"])))
            _call(e, "ar_length", _call(e, "ar_units", p["pl_h"]))
            _call(e, "ar_length", e.ld(p["pl_h"]))
            e.for_("pl_j", 0, e.ld(p["pl_h"]), lambda: put(e, e.ld(e.add(e.add(p["pl_h"], 1), p["pl_j"]))))
            put(e, 0)

        e.for_("pl_k", 0, p["n"], item)
        e.while_(lambda: e.ne(e.urem(e.sub(pos(e), p["pl_start"]), 4), 0), lambda: put(e, 0))
        _call(e, "ar_patch", e.add(p["pl_start"], 4), e.sub(pos(e), p["pl_start"]))
        e.give(1)
    return _function(("arr", "n"), build, tables)


def _sort_fn(tables):
    """``sort(arr, n)``: the ``n`` string handles at ``arr`` sorted by their bytes (stable insertion), duplicates
    dropped; the distinct count."""
    def build(e: E):
        p = e.p

        def insert():
            e.var("so_item", e.ld(e.add(p["arr"], p["so_s"])))
            e.var("so_j", p["so_s"])
            _down(e, "so_j", lambda: _call(e, "ar_less", p["so_item"], e.ld(e.add(p["arr"], e.sub(p["so_j"], 1)))),
                  lambda: (e.st(e.add(p["arr"], p["so_j"]), e.ld(e.add(p["arr"], e.sub(p["so_j"], 1)))), e.set("so_j", e.sub(p["so_j"], 1))))
            e.st(e.add(p["arr"], p["so_j"]), p["so_item"])

        e.for_("so_s", 1, p["n"], insert)
        e.var("so_m", e.sel(e.lt(0, p["n"]), 1, 0))

        def keep():
            e.var("so_h", e.ld(e.add(p["arr"], p["so_k"])))
            e.if_(e.eq(_call(e, "ar_same", p["so_h"], e.ld(e.add(p["arr"], e.sub(p["so_m"], 1)))), 0),
                  lambda: (e.st(e.add(p["arr"], p["so_m"]), p["so_h"]), e.set("so_m", e.add(p["so_m"], 1))))

        e.for_("so_k", 1, p["n"], keep)
        e.give(p["so_m"])
    return _function(("arr", "n"), build, tables)


def _index_fn(tables):
    """The index of the string with ``h``'s bytes among the ``G_NORD`` handles at ``G_ORD`` (it is there)."""
    def build(e: E):
        p = e.p
        e.for_("ix_k", 0, e.ld(G_NORD),
               lambda: e.if_(e.ne(_call(e, "ar_same", p["h"], e.ld(e.add(e.ld(G_ORD), p["ix_k"]))), 0), lambda: e.give(p["ix_k"])))
        e.give(NONE)  # not there: a decline
    return _function(("h",), build, tables)


def _start_fn(tables):
    """``start(name)``: a start event with an empty attribute list (its address)."""
    def build(e: E):
        p = e.p
        e.var("st_list", e.alloc(1 + ATTRS * A_WORDS))
        _ok(e, e.ne(p["st_list"], NONE))
        e.st(p["st_list"], 0)
        e.var("st_n", e.ld(G_NEV))
        e.st(e.add(e.ld(G_EV), e.mul(p["st_n"], 2)), p["name"])
        e.st(e.add(e.add(e.ld(G_EV), e.mul(p["st_n"], 2)), 1), p["st_list"])
        e.st(G_NEV, e.add(p["st_n"], 1))
        e.give(p["st_list"])
    return _function(("name",), build, tables)


def _end_fn(tables):
    """``end(name)``: an end event."""
    def build(e: E):
        p = e.p
        e.var("en_n", e.ld(G_NEV))
        e.st(e.add(e.ld(G_EV), e.mul(p["en_n"], 2)), p["name"])
        e.st(e.add(e.add(e.ld(G_EV), e.mul(p["en_n"], 2)), 1), 0)
        e.st(G_NEV, e.add(p["en_n"], 1))
        e.give(1)
    return _function(("name",), build, tables)


def _attr_fn(tables):
    """``attr(list, ns, name, type, value, res)``: one more attribute in ``list``."""
    def build(e: E):
        p = e.p
        e.var("at_n", e.ld(p["list"]))
        e.var("at_a", e.add(e.add(p["list"], 1), e.mul(p["at_n"], A_WORDS)))
        for field, name in ((A_NS, "ns"), (A_NAME, "name"), (A_TYPE, "type"), (A_VALUE, "value"), (A_RES, "res")):
            e.st(e.add(p["at_a"], field), p[name])
        e.st(p["list"], e.add(p["at_n"], 1))
        e.give(1)
    return _function(("list", "ns", "name", "type", "value", "res"), build, tables)


def _attr_less_fn(tables):
    """1 when attribute ``a`` sorts before ``b``: no namespace first, then by resource ID, then by name."""
    def build(e: E):
        p = e.p
        for field in (A_NS, A_RES):
            e.if_(e.lt(e.ld(e.add(p["a"], field)), e.ld(e.add(p["b"], field))), lambda: e.give(1))
            e.if_(e.lt(e.ld(e.add(p["b"], field)), e.ld(e.add(p["a"], field))), lambda: e.give(0))
        e.give(_call(e, "ar_less", e.ld(e.add(p["a"], A_NAME)), e.ld(e.add(p["b"], A_NAME))))
    return _function(("a", "b"), build, tables)


def _element_fn(tables):
    """``element(name, list)``: the start-element chunk, its attributes sorted."""
    def build(e: E):
        p = e.p
        e.var("el_n", e.ld(p["list"]))
        rec = lambda k: e.add(e.add(p["list"], 1), e.mul(k, A_WORDS))  # noqa: E731

        def insert():  # a stable insertion of the records' five words
            e.var("el_j", p["el_s"])


            def swap():
                for field in range(A_WORDS):
                    e.var("el_t", e.ld(e.add(rec(p["el_j"]), field)))
                    e.st(e.add(rec(p["el_j"]), field), e.ld(e.add(rec(e.sub(p["el_j"], 1)), field)))
                    e.st(e.add(rec(e.sub(p["el_j"], 1)), field), p["el_t"])
                e.set("el_j", e.sub(p["el_j"], 1))

            _down(e, "el_j", lambda: _call(e, "ar_attrless", rec(p["el_j"]), rec(e.sub(p["el_j"], 1))), swap)

        e.for_("el_s", 1, p["el_n"], insert)
        for value, n in ((0x0102, 2), (16, 2), (e.add(36, e.mul(p["el_n"], 20)), 4), (0, 4), (NO_INDEX, 4),
                         (NO_INDEX, 4), (_call(e, "ar_index", p["name"]), 4), (20, 2), (20, 2), (p["el_n"], 2), (0, 2), (0, 2), (0, 2)):
            le(e, value, n)

        def attribute():
            e.var("el_a", rec(p["el_k"]))
            e.var("el_type", e.ld(e.add(p["el_a"], A_TYPE)))
            e.var("el_v", e.ld(e.add(p["el_a"], A_VALUE)))
            e.var("el_ns", NO_INDEX)
            e.if_(e.ne(e.ld(e.add(p["el_a"], A_NS)), 0), lambda: e.set("el_ns", _call(e, "ar_index", e.ld(G_STR + CONST[ANDROID_URI]))))
            e.var("el_raw", NO_INDEX)
            e.if_(e.eq(p["el_type"], TYPE_STRING), lambda: (e.set("el_raw", _call(e, "ar_index", p["el_v"])), e.set("el_v", p["el_raw"])))
            for value, n in ((p["el_ns"], 4), (_call(e, "ar_index", e.ld(e.add(p["el_a"], A_NAME))), 4), (p["el_raw"], 4), (8, 2)):
                le(e, value, n)
            put(e, 0)
            put(e, p["el_type"])
            le(e, e.and_(p["el_v"], 0xFFFFFFFF), 4)

        e.for_("el_k", 0, p["el_n"], attribute)
        e.give(1)
    return _function(("name", "list"), build, tables)


def _used_fn(tables):
    """1 when an attribute of the tree is named ``h`` (a constant's handle)."""
    def build(e: E):
        p = e.p

        def each():
            e.var("us_list", e.ld(e.add(e.add(e.ld(G_EV), e.mul(p["us_k"], 2)), 1)))

            def attributes():
                e.for_("us_j", 0, e.ld(p["us_list"]),
                       lambda: e.if_(e.eq(e.ld(e.add(e.add(e.add(p["us_list"], 1), e.mul(p["us_j"], A_WORDS)), A_NAME)), p["h"]), lambda: e.give(1)))

            e.if_(e.ne(p["us_list"], 0), attributes)

        e.for_("us_k", 0, e.ld(G_NEV), each)
        e.give(0)
    return _function(("h",), build, tables)


def _sort_records_fn(tables):
    """``sort_records(arr, n, words)``: the ``n`` records of ``words`` words at ``arr`` sorted by their first word's
    string (stable insertion)."""
    def build(e: E):
        p = e.p
        rec = lambda k: e.add(p["arr"], e.mul(k, p["words"]))  # noqa: E731

        def insert():
            e.var("sr_j", p["sr_s"])


            def swap():
                e.for_("sr_f", 0, p["words"], lambda: (
                    e.var("sr_t", e.ld(e.add(rec(p["sr_j"]), p["sr_f"]))),
                    e.st(e.add(rec(p["sr_j"]), p["sr_f"]), e.ld(e.add(rec(e.sub(p["sr_j"], 1)), p["sr_f"]))),
                    e.st(e.add(rec(e.sub(p["sr_j"], 1)), p["sr_f"]), p["sr_t"])))
                e.set("sr_j", e.sub(p["sr_j"], 1))

            _down(e, "sr_j", lambda: _call(e, "ar_less", e.ld(rec(p["sr_j"])), e.ld(rec(e.sub(p["sr_j"], 1)))), swap)

        e.for_("sr_s", 1, p["n"], insert)
        e.give(1)
    return _function(("arr", "n", "words"), build, tables)


def _constants(e: E):
    """The constant strings in the arena, their handles at ``G_STR``."""
    for k, text in enumerate(CONSTANTS):
        raw = text.encode("utf-8")
        e.var("cs_h", e.alloc(len(raw) + 1))
        _ok(e, e.ne(e.p["cs_h"], NONE))
        e.st(e.p["cs_h"], len(raw))
        for j, byte in enumerate(raw):
            e.st(e.add(e.p["cs_h"], 1 + j), byte)
        e.st(G_STR + k, e.p["cs_h"])


def S(e: E, text: str):
    return e.ld(G_STR + CONST[text])


def _manifest_fn(tables):
    """Mode 0: the binary manifest."""
    def build(e: E):
        p = e.p
        word = lambda: _call(e, "ar_word")  # noqa: E731
        string = lambda: _call(e, "ar_string")  # noqa: E731
        start = lambda name: _call(e, "ar_start", name)  # noqa: E731
        end = lambda name: _call(e, "ar_end", name)  # noqa: E731

        def attr(lst, ns, name, type_, value, res):
            _call(e, "ar_attr", lst, ns, name, type_, value, res)

        def named(lst, value):
            attr(lst, 1, S(e, "name"), TYPE_STRING, value, RES_ID["name"])

        e.var("pkg", string())
        e.var("act", string())
        e.var("vc", word())
        e.var("min", word())
        e.var("tgt", word())
        e.var("launcher", word())
        e.var("dbg", word())
        e.var("has_app", word())
        e.var("app", 0)
        e.if_(e.ne(p["has_app"], 0), lambda: e.set("app", string()))
        # The receivers and services: records [class, exported, action], sorted by class.
        e.var("nrecv", word())
        _ok(e, e.le(p["nrecv"], 1 << 16))
        e.var("recv", e.alloc(e.add(e.mul(p["nrecv"], 3), 1)))
        _ok(e, e.ne(p["recv"], NONE))

        def receiver():
            e.var("r", e.add(p["recv"], e.mul(p["q"], 3)))
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), word())
            e.st(e.add(p["r"], 2), 0)
            e.if_(e.ne(word(), 0), lambda: e.st(e.add(p["r"], 2), string()))

        e.for_("q", 0, p["nrecv"], receiver)
        _call(e, "ar_sortrec", p["recv"], p["nrecv"], 3)
        e.var("nserv", word())
        _ok(e, e.le(p["nserv"], 1 << 16))
        e.var("serv", e.alloc(e.add(e.mul(p["nserv"], 2), 1)))
        _ok(e, e.ne(p["serv"], NONE))

        def service():
            e.var("r", e.add(p["serv"], e.mul(p["q"], 2)))
            e.st(p["r"], string())
            e.st(e.add(p["r"], 1), word())

        e.for_("q", 0, p["nserv"], service)
        _call(e, "ar_sortrec", p["serv"], p["nserv"], 2)
        e.var("decl", word())
        e.var("ev_cap", e.add(4096, e.mul(e.add(p["nrecv"], p["nserv"]), 8)))
        e.st(G_EV, e.alloc(e.add(e.mul(p["ev_cap"], 2), 1)))
        _ok(e, e.ne(e.ld(G_EV), NONE))
        e.st(G_NEV, 0)

        e.var("l", start(S(e, "manifest")))
        attr(p["l"], 0, S(e, "package"), TYPE_STRING, p["pkg"], 0)
        attr(p["l"], 1, S(e, "versionCode"), TYPE_INT_DEC, p["vc"], RES_ID["versionCode"])
        e.var("l", start(S(e, "uses-sdk")))
        attr(p["l"], 1, S(e, "minSdkVersion"), TYPE_INT_DEC, p["min"], RES_ID["minSdkVersion"])
        attr(p["l"], 1, S(e, "targetSdkVersion"), TYPE_INT_DEC, p["tgt"], RES_ID["targetSdkVersion"])
        end(S(e, "uses-sdk"))
        e.var("ncomp", 0)
        e.var("comp_at", 0)

        def declarations():
            def permission():
                e.var("l", start(S(e, "uses-permission")))
                named(p["l"], string())
                e.var("max", word())
                e.if_(e.ne(p["max"], 0), lambda: attr(p["l"], 1, S(e, "maxSdkVersion"), TYPE_INT_DEC, p["max"], RES_ID["maxSdkVersion"]))
                e.if_(e.ne(word(), 0), lambda: attr(p["l"], 1, S(e, "usesPermissionFlags"), TYPE_INT_HEX, USES_PERMISSION_NEVER_FOR_LOCATION,
                                                    RES_ID["usesPermissionFlags"]))
                end(S(e, "uses-permission"))

            e.for_("q", 0, word(), permission)

            def feature():
                e.var("l", start(S(e, "uses-feature")))
                named(p["l"], string())
                attr(p["l"], 1, S(e, "required"), TYPE_INT_BOOLEAN, e.flag(e.ne(word(), 0)), RES_ID["required"])
                end(S(e, "uses-feature"))

            e.for_("q", 0, word(), feature)
            e.set("ncomp", word())
            e.set("comp_at", e.ld(G_CUR))

        e.if_(e.ne(p["decl"], 0), declarations)
        e.var("l", start(S(e, "application")))
        attr(p["l"], 1, S(e, "hasCode"), TYPE_INT_BOOLEAN, 1, RES_ID["hasCode"])
        e.if_(e.ne(p["dbg"], 0), lambda: attr(p["l"], 1, S(e, "debuggable"), TYPE_INT_BOOLEAN, 1, RES_ID["debuggable"]))
        e.if_(e.ne(p["has_app"], 0), lambda: named(p["l"], p["app"]))

        def activity():
            e.var("l", start(S(e, "activity")))
            named(p["l"], p["act"])
            attr(p["l"], 1, S(e, "exported"), TYPE_INT_BOOLEAN, e.flag(e.ne(p["launcher"], 0)), RES_ID["exported"])

            def launcher():
                start(S(e, "intent-filter"))
                e.var("l", start(S(e, "action")))
                named(p["l"], S(e, "android.intent.action.MAIN"))
                end(S(e, "action"))
                e.var("l", start(S(e, "category")))
                named(p["l"], S(e, "android.intent.category.LAUNCHER"))
                end(S(e, "category"))
                end(S(e, "intent-filter"))

            e.if_(e.ne(p["launcher"], 0), launcher)
            end(S(e, "activity"))

        e.if_(e.ne(e.ld(p["act"]), 0), activity)

        def receiver_element():
            e.var("r", e.add(p["recv"], e.mul(p["q"], 3)))
            e.var("l", start(S(e, "receiver")))
            named(p["l"], e.ld(p["r"]))
            attr(p["l"], 1, S(e, "exported"), TYPE_INT_BOOLEAN, e.flag(e.ne(e.ld(e.add(p["r"], 1)), 0)), RES_ID["exported"])

            def action():
                start(S(e, "intent-filter"))
                e.var("l", start(S(e, "action")))
                named(p["l"], e.ld(e.add(p["r"], 2)))
                end(S(e, "action"))
                end(S(e, "intent-filter"))

            e.if_(e.ne(e.ld(e.add(p["r"], 2)), 0), action)
            end(S(e, "receiver"))

        e.for_("q", 0, p["nrecv"], receiver_element)

        def service_element():
            e.var("r", e.add(p["serv"], e.mul(p["q"], 2)))
            e.var("l", start(S(e, "service")))
            named(p["l"], e.ld(p["r"]))
            attr(p["l"], 1, S(e, "exported"), TYPE_INT_BOOLEAN, e.flag(e.ne(e.ld(e.add(p["r"], 1)), 0)), RES_ID["exported"])
            end(S(e, "service"))

        e.for_("q", 0, p["nserv"], service_element)

        def component():
            e.var("kind", e.sel(e.eq(word(), 0), S(e, "service"), S(e, "receiver")))
            e.var("l", start(p["kind"]))
            named(p["l"], string())
            attr(p["l"], 1, S(e, "exported"), TYPE_INT_BOOLEAN, e.flag(e.ne(word(), 0)), RES_ID["exported"])
            e.var("has_fg", word())
            e.var("fg", word())
            e.if_(e.ne(p["has_fg"], 0), lambda: attr(p["l"], 1, S(e, "foregroundServiceType"), TYPE_INT_HEX, p["fg"], RES_ID["foregroundServiceType"]))
            e.var("nact", word())

            def actions():
                start(S(e, "intent-filter"))

                def each():
                    e.var("l", start(S(e, "action")))
                    named(p["l"], string())
                    end(S(e, "action"))

                e.for_("j", 0, p["nact"], each)
                end(S(e, "intent-filter"))

            e.if_(e.ne(p["nact"], 0), actions)
            end(p["kind"])

        e.for_("q", 0, p["ncomp"], component)
        end(S(e, "application"))
        end(S(e, "manifest"))
        _ok(e, e.le(e.ld(G_NEV), p["ev_cap"]))

        # The resource map: the candidates in ID order.
        e.var("res", e.alloc(len(RESOURCE_ATTRIBUTES) + 1))
        _ok(e, e.ne(p["res"], NONE))
        e.var("nres", 0)
        e.var("cap", e.add(e.mul(e.ld(G_NEV), 1 + 2 * ATTRS), 16))
        e.st(G_ORD, e.alloc(e.add(p["cap"], len(RESOURCE_ATTRIBUTES))))
        _ok(e, e.ne(e.ld(G_ORD), NONE))
        for name, _id, when in RESOURCE_ATTRIBUTES:
            include = e.c(1) if when == 0 else (e.flag(e.ne(p["dbg"], 0)) if when == 1 else _call(e, "ar_used", S(e, name)))
            e.if_(e.ne(include, 0), lambda name=name: (e.st(e.add(e.ld(G_ORD), p["nres"]), S(e, name)),
                                                        e.st(e.add(p["res"], p["nres"]), RES_ID[name]),
                                                        e.set("nres", e.add(p["nres"], 1))))
        # Every other string, sorted by its bytes.
        e.var("all", e.alloc(p["cap"]))
        _ok(e, e.ne(p["all"], NONE))
        e.var("nall", 0)

        def add(h):
            e.st(e.add(p["all"], p["nall"]), h)
            e.set("nall", e.add(p["nall"], 1))

        add(S(e, "android"))
        add(S(e, ANDROID_URI))

        def collect():
            e.var("ce", e.add(e.ld(G_EV), e.mul(p["q"], 2)))
            e.var("cl", e.ld(e.add(p["ce"], 1)))

            def attributes():
                add(e.ld(p["ce"]))

                def each():
                    e.var("ca", e.add(e.add(p["cl"], 1), e.mul(p["j"], A_WORDS)))
                    add(e.ld(e.add(p["ca"], A_NAME)))
                    e.if_(e.ne(e.ld(e.add(p["ca"], A_NS)), 0), lambda: add(S(e, ANDROID_URI)))
                    e.if_(e.eq(e.ld(e.add(p["ca"], A_TYPE)), TYPE_STRING), lambda: add(e.ld(e.add(p["ca"], A_VALUE))))

                e.for_("j", 0, e.ld(p["cl"]), each)

            e.if_(e.ne(p["cl"], 0), attributes)

        e.for_("q", 0, e.ld(G_NEV), collect)
        e.set("nall", _call(e, "ar_sort", p["all"], p["nall"]))
        e.var("nord", p["nres"])

        def tail():
            e.var("th", e.ld(e.add(p["all"], p["q"])))
            e.var("named", 0)
            e.for_("j", 0, p["nres"], lambda: e.if_(e.ne(_call(e, "ar_same", p["th"], e.ld(e.add(e.ld(G_ORD), p["j"]))), 0),
                                                    lambda: e.set("named", 1)))
            e.if_(e.eq(p["named"], 0), lambda: (e.st(e.add(e.ld(G_ORD), p["nord"]), p["th"]), e.set("nord", e.add(p["nord"], 1))))

        e.for_("q", 0, p["nall"], tail)
        e.st(G_NORD, p["nord"])

        # The chunks.
        e.st(IMAGE_AT + 2, 0)
        for value, n in ((0x0003, 2), (8, 2), (0, 4)):
            le(e, value, n)
        _call(e, "ar_pool", e.ld(G_ORD), p["nord"])
        for value, n in ((0x0180, 2), (8, 2), (e.add(8, e.mul(p["nres"], 4)), 4)):
            le(e, value, n)
        e.for_("q", 0, p["nres"], lambda: le(e, e.ld(e.add(p["res"], p["q"])), 4))

        def namespace(kind):
            for value, n in ((kind, 2), (16, 2), (24, 4), (0, 4), (NO_INDEX, 4), (_call(e, "ar_index", S(e, "android")), 4),
                             (_call(e, "ar_index", S(e, ANDROID_URI)), 4)):
                le(e, value, n)

        namespace(0x0100)

        def event():
            e.var("ee", e.add(e.ld(G_EV), e.mul(p["q"], 2)))
            e.var("el", e.ld(e.add(p["ee"], 1)))
            e.if_(e.ne(p["el"], 0), lambda: _call(e, "ar_element", e.ld(p["ee"]), p["el"]),
                  lambda: [le(e, value, n) for value, n in ((0x0103, 2), (16, 2), (24, 4), (0, 4), (NO_INDEX, 4), (NO_INDEX, 4),
                                                             (_call(e, "ar_index", e.ld(p["ee"])), 4))])

        e.for_("q", 0, e.ld(G_NEV), event)
        namespace(0x0101)
        _call(e, "ar_patch", 4, pos(e))
        e.give(1)
    return _function((), build, tables)


def _utf16_fn(tables):
    """``utf16(h)``: the UTF-16LE code units of the UTF-8 string ``h``, then zeros to 256 bytes (the package name's
    field); declines past it."""
    def build(e: E):
        p = e.p
        e.var("u6_start", pos(e))
        e.var("u6_k", 0)
        e.var("u6_n", e.ld(p["h"]))
        byte = lambda k: e.and_(e.ld(e.add(e.add(p["h"], 1), k)), 0x3F)  # noqa: E731

        def each():
            e.var("u6_b", e.ld(e.add(e.add(p["h"], 1), p["u6_k"])))
            e.var("u6_cp", p["u6_b"])
            e.var("u6_len", 1)
            e.if_(e.le(0xC0, p["u6_b"]), lambda: (e.set("u6_cp", e.add(e.mul(e.and_(p["u6_b"], 0x1F), 64), byte(e.add(p["u6_k"], 1)))),
                                                  e.set("u6_len", 2)))
            e.if_(e.le(0xE0, p["u6_b"]), lambda: (e.set("u6_cp", e.add(e.mul(e.and_(p["u6_b"], 0x0F), 4096),
                                                                         e.add(e.mul(byte(e.add(p["u6_k"], 1)), 64), byte(e.add(p["u6_k"], 2))))),
                                                  e.set("u6_len", 3)))
            e.if_(e.le(0xF0, p["u6_b"]), lambda: (e.set("u6_cp", e.add(e.add(e.mul(e.and_(p["u6_b"], 0x07), 1 << 18), e.mul(byte(e.add(p["u6_k"], 1)), 4096)),
                                                                         e.add(e.mul(byte(e.add(p["u6_k"], 2)), 64), byte(e.add(p["u6_k"], 3))))),
                                                  e.set("u6_len", 4)))

            def pair():
                e.var("u6_c", e.sub(p["u6_cp"], 0x10000))
                le(e, e.add(0xD800, e.udiv(p["u6_c"], 1024)), 2)
                le(e, e.add(0xDC00, e.urem(p["u6_c"], 1024)), 2)

            e.if_(e.le(0x10000, p["u6_cp"]), pair, lambda: le(e, p["u6_cp"], 2))
            e.set("u6_k", e.add(p["u6_k"], p["u6_len"]))

        e.while_(lambda: e.lt(p["u6_k"], p["u6_n"]), each)
        _ok(e, e.le(e.sub(pos(e), p["u6_start"]), 254))
        e.while_(lambda: e.lt(e.sub(pos(e), p["u6_start"]), 256), lambda: put(e, 0))
        e.give(1)
    return _function(("h",), build, tables)


def _arsc_fn(tables):
    """Mode 1: the bounded resource table."""
    def build(e: E):
        p = e.p
        e.var("pkg", _call(e, "ar_string"))
        e.var("n", _call(e, "ar_word"))
        _ok(e, e.both(e.lt(0, p["n"]), e.le(p["n"], 1 << 16)))
        e.var("names", e.alloc(e.add(p["n"], 1)))
        e.var("values", e.alloc(e.add(p["n"], 1)))
        e.var("sorted", e.alloc(e.add(p["n"], 1)))
        _ok(e, e.both(e.ne(p["names"], NONE), e.both(e.ne(p["values"], NONE), e.ne(p["sorted"], NONE))))

        def entry():
            e.st(e.add(p["names"], p["q"]), _call(e, "ar_string"))
            e.st(e.add(p["values"], p["q"]), _call(e, "ar_string"))
            e.st(e.add(p["sorted"], p["q"]), e.ld(e.add(p["values"], p["q"])))

        e.for_("q", 0, p["n"], entry)
        e.var("nv", _call(e, "ar_sort", p["sorted"], p["n"]))
        e.st(G_ORD, p["sorted"])
        e.st(G_NORD, p["nv"])
        e.st(IMAGE_AT + 2, 0)
        for value, n in ((0x0002, 2), (12, 2), (0, 4), (1, 4)):
            le(e, value, n)
        _call(e, "ar_pool", p["sorted"], p["nv"])
        e.var("pk", pos(e))
        for value, n in ((0x0200, 2), (288, 2), (0, 4), (0x7F, 4)):
            le(e, value, n)
        _call(e, "ar_utf16", p["pkg"])
        for value, n in ((288, 4), (1, 4), (0, 4), (p["n"], 4), (0, 4)):
            le(e, value, n)
        e.var("types", e.alloc(2))
        _ok(e, e.ne(p["types"], NONE))
        e.st(p["types"], S(e, "string"))
        _call(e, "ar_pool", p["types"], 1)
        _call(e, "ar_patch", e.add(p["pk"], 276), e.sub(pos(e), p["pk"]))
        _call(e, "ar_pool", p["names"], p["n"])
        for value, n in ((0x0202, 2), (16, 2), (e.add(16, e.mul(p["n"], 4)), 4), (1, 1), (0, 1), (0, 2), (p["n"], 4)):
            le(e, value, n)
        e.for_("q", 0, p["n"], lambda: le(e, 0, 4))
        e.var("entries", e.add(48, e.mul(p["n"], 4)))
        for value, n in ((0x0201, 2), (48, 2), (e.add(p["entries"], e.mul(p["n"], 16)), 4), (1, 1), (0, 1), (0, 2), (p["n"], 4),
                         (p["entries"], 4), (28, 4)):
            le(e, value, n)
        e.for_("q", 0, 24, lambda: put(e, 0))
        e.for_("q", 0, p["n"], lambda: le(e, e.mul(p["q"], 16), 4))

        def value():
            for item, n in ((8, 2), (0, 2), (p["q"], 4), (8, 2), (0, 1), (TYPE_STRING, 1),
                            (_call(e, "ar_index", e.ld(e.add(p["values"], p["q"]))), 4)):
                le(e, item, n)

        e.for_("q", 0, p["n"], value)
        _call(e, "ar_patch", e.add(p["pk"], 4), e.sub(pos(e), p["pk"]))
        _call(e, "ar_patch", 4, pos(e))
        e.give(1)
    return _function((), build, tables)


def _frontend(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        _constants(e)
        e.st(G_CUR, 1)
        e.var("mode", e.rd(0))
        _ok(e, e.le(p["mode"], 1))
        e.if_(e.eq(p["mode"], 0), lambda: _call(e, "ar_manifest"), lambda: _call(e, "ar_arsc"))
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


def build_resources_program():
    """``(reader, function)``: the Android resources program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in (("ar_put", _put_fn), ("ar_patch", _patch_fn), ("ar_less", _less_fn), ("ar_same", _same_fn),
                          ("ar_string", _string_fn), ("ar_word", _word_fn), ("ar_units", _units_fn), ("ar_length", _length_fn),
                          ("ar_pool", _pool_fn), ("ar_sort", _sort_fn), ("ar_index", _index_fn), ("ar_start", _start_fn),
                          ("ar_end", _end_fn), ("ar_attr", _attr_fn), ("ar_attrless", _attr_less_fn), ("ar_element", _element_fn),
                          ("ar_used", _used_fn), ("ar_sortrec", _sort_records_fn), ("ar_manifest", _manifest_fn),
                          ("ar_utf16", _utf16_fn), ("ar_arsc", _arsc_fn)):
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_resources_program, "android-resources")
load_resources_program = _PROGRAM.load
write_resources_store = _PROGRAM.write
OPT_OUT = "XAX_ANDROID_RESOURCES_PYTHON"


def _run(words: list[int], required: bool) -> bytes | None:
    import os

    import xax_native

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
            xax_native.declined("android-resources", 1)
    if data is None and required:
        raise RuntimeError("the XAX Android resources program is unavailable or declined")
    return data


def _text(value: str) -> list[int]:
    raw = value.encode("utf-8")
    return [len(raw), *raw]


def manifest_with_xax(spec, *, receivers=(), services=(), application=None, declarations=None, required: bool = False) -> bytes | None:
    """The binary manifest the XAX program writes for checked specifications, or None where it cannot run or declines
    (unless ``required``)."""
    try:
        words = [0, *_text(spec.package_name), *_text(spec.activity_class), spec.version_code, spec.min_sdk, spec.target_sdk,
                 int(bool(spec.launcher)), int(bool(spec.debuggable))]
        words += [0] if application is None else [1, *_text(application.class_name)]
        words.append(len(receivers))
        for item in receivers:
            words += [*_text(item.class_name), int(bool(item.exported))]
            words += [0] if item.action is None else [1, *_text(item.action)]
        words.append(len(services))
        for item in services:
            words += [*_text(item.class_name), int(bool(item.exported))]
        if declarations is None:
            words.append(0)
        else:
            words += [1, len(declarations.permissions)]
            for item in declarations.permissions:
                words += [*_text(item.name), item.max_sdk, int(bool(item.never_for_location))]
            words.append(len(declarations.features))
            for item in declarations.features:
                words += [*_text(item.name), int(bool(item.required))]
            words.append(len(declarations.components))
            for item in declarations.components:
                if item.kind not in ("service", "receiver"):
                    return None
                words += [0 if item.kind == "service" else 1, *_text(item.class_name), int(bool(item.exported)),
                          int(bool(item.foreground_types)), item.foreground_flags, len(item.actions)]
                for action in item.actions:
                    words += _text(action)
    except UnicodeEncodeError:
        return None  # the bootstrap's own error
    if any(not 0 <= word < 1 << 63 for word in words):
        return None
    return _run(words, required)


def arsc_with_xax(spec, *, required: bool = False) -> bytes | None:
    """The ``resources.arsc`` the XAX program writes for a checked specification, or None where it cannot run or
    declines (unless ``required``)."""
    try:
        words = [1, *_text(spec.package_name), len(spec.strings)]
        for item in spec.strings:
            words += [*_text(item.name), *_text(item.value)]
    except UnicodeEncodeError:
        return None
    return _run(words, required)
