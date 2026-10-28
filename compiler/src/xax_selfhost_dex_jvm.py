"""S15e.6g.2 (ADR-336): the JVM class-file to DEX class lowering (``xax_dex_jvm.translate_class``) as an XAX program.

The program parses one class file (the constant pool, the fields, the methods with their ``Code`` and ``StackMapTable``
attributes) and lowers each method as the bootstrap does (``jvm-to-dex-v1``, ADR-259): JVM operand-stack slots and
locals on fixed DEX registers behind the scratch registers, each instruction to the DEX instruction of the same meaning,
an operand beyond a format's reach copied through a scratch register, the locals' descriptors tracked from the frames for
array element forms, branches as 16-bit offsets (or, where one does not fit, every test inverted over a ``goto/32``),
switches with their payloads.  As in the bootstrap a method is lowered first with six scratch registers, again with long
branches where a scratch register or a branch did not fit, and finally with exactly the scratch registers the pass used.
``rename`` maps internal class names wherever they occur.  An unsupported class file (exception handlers, ``jsr``,
``invokedynamic``, a frame with a non-empty stack, an unknown constant) makes the program decline.

Input (64-bit words): the class file (its length, then its bytes packed eight to a word), the renames (count; each the
internal name and its replacement, a string being its UTF-16 unit count and units).
Output: the status (1) and at ``OUT_AT`` the class in ``xax_selfhost_dex_writer``'s input form for one class
``[count, words...]``.
"""

from __future__ import annotations

from xax_compiler import x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_dex_jvm.xax"
STATE_AT = 110 << 20
OUT_AT = 4096
OUT_END = 100 << 20
G = {name: STATE_AT + k for k, name in enumerate((
    "cur", "ba", "bn", "pool", "npool", "renames", "out", "this", "code", "clen", "maxstack", "maxlocals", "frames", "flags", "mname", "mdesc",
    "scratch", "long", "ins", "freebase", "parambase", "registers", "stack", "sdepth", "sn", "locals", "units", "nunits", "labels", "fix", "nfix",
    "pay", "npay", "outs", "used", "next", "retry", "after", "nafter", "popk", "popd", "targets", "tbl", "ucap", "initial", "pcs", "npcs",
    "nout"))}
CONSTANT_TEXTS = {"I": "I", "F": "F", "J": "J", "D": "D", "Z": "Z", "B": "B", "C": "C", "S": "S", "String": "Ljava/lang/String;",
                  "Class": "Ljava/lang/Class;", "Object": "Ljava/lang/Object;", "init": "<init>", "clinit": "<clinit>", "V": "V", "Code": "Code",
                  "StackMapTable": "StackMapTable"}
K = {name: STATE_AT + 128 + k for k, name in enumerate(CONSTANT_TEXTS)}
TBL_AT = STATE_AT + 4096  # the opcode tables (``TABLE`` offsets), one word per opcode
KI, KF, KJ, KD, KA = 1, 2, 3, 4, 5  # value kinds
SCRATCH = 6
ACC_STATIC, ACC_PRIVATE, ACC_CONSTRUCTOR = 0x0008, 0x0002, 0x10000
TABLE = {"binary_op": 0, "binary_kind": 256, "unary_op": 512, "unary_kind": 768, "inverse": 1024, "nofall": 1280}


def _tables() -> dict[str, dict[int, int]]:
    import xax_dex_jvm as D

    kinds = {"I": KI, "F": KF, "J": KJ, "D": KD}
    return {"binary_op": {op: dex for op, (dex, _k) in D._BINARY.items()}, "binary_kind": {op: kinds[k] for op, (_d, k) in D._BINARY.items()},
            "unary_op": {op: dex for op, (dex, _k) in D._UNARY.items()}, "unary_kind": {op: kinds[k] for op, (_d, k) in D._UNARY.items()},
            "inverse": dict(D._INVERSE), "nofall": {op: 1 for op in D._NO_FALLTHROUGH}}


def at(e: E, base, k):
    return e.ld(e.add(base, k))


def g(e: E, name: str):
    return e.ld(G[name])


def sg(e: E, name: str, value):
    e.st(G[name], value)


def wide(e: E, kind):
    return e.either(e.eq(kind, KJ), e.eq(kind, KD))


def size(e: E, kind):
    return e.sel(wide(e, kind), 2, 1)


def sel_kind(e: E, kind, values: dict[int, int]):
    """``values[kind]`` for a value kind (``KI``.. ``KA``)."""
    result = e.c(values[KA])
    for k in (KI, KF, KJ, KD):
        result = e.sel(e.eq(kind, k), values[k], result)
    return result


def MOVE(e, kind):
    return sel_kind(e, kind, {KI: 0x01, KF: 0x01, KJ: 0x04, KD: 0x04, KA: 0x07})


def MOVE_RESULT(e, kind):
    return sel_kind(e, kind, {KI: 0x0A, KF: 0x0A, KJ: 0x0B, KD: 0x0B, KA: 0x0C})


def RETURN(e, kind):
    return sel_kind(e, kind, {KI: 0x0F, KF: 0x0F, KJ: 0x10, KD: 0x10, KA: 0x11})


def signed(e: E, value, bits: int):
    """``value`` (``bits`` wide) sign-extended to 64 bits."""
    return e.sel(e.lt(value, 1 << (bits - 1)), value, e.sub(value, 1 << bits))


# -- bytes and strings --------------------------------------------------------------------------------------------------------

def _byte_fn(tables):
    """``byte(pos)``: the class file's byte at ``pos`` (declines past its end)."""
    def build(e: E):
        p = e.p
        _ok(e, e.lt(p["pos"], g(e, "bn")))
        e.give(at(e, g(e, "ba"), p["pos"]))
    return _function(("pos",), build, tables)


def u1(e: E, pos):
    return _call(e, "dj_byte", pos)


def u2(e: E, pos):
    return e.add(e.mul(u1(e, pos), 256), u1(e, e.add(pos, 1)))


def u4(e: E, pos):
    return e.add(e.mul(u2(e, pos), 65536), u2(e, e.add(pos, 2)))


def _utf8_fn(tables):
    """``utf8(pos, n)``: the ``n`` UTF-8 bytes at ``pos`` as a UTF-16 unit string (declines on what Python's strict
    decoder rejects)."""
    def build(e: E):
        p = e.p
        e.var("u8_h", e.alloc(e.add(p["n"], 2)))
        _ok(e, e.ne(p["u8_h"], NONE))
        e.var("u8_k", 0)
        e.var("u8_m", 0)
        cont = lambda k: e.and_(u1(e, e.add(p["pos"], k)), 0x3F)  # noqa: E731

        def continuation(k):
            _ok(e, e.lt(k, p["n"]))
            _ok(e, e.eq(e.and_(u1(e, e.add(p["pos"], k)), 0xC0), 0x80))

        def unit(value):
            e.st(e.add(e.add(p["u8_h"], 1), p["u8_m"]), value)
            e.set("u8_m", e.add(p["u8_m"], 1))

        def each():
            e.var("u8_b", u1(e, e.add(p["pos"], p["u8_k"])))

            def two():
                continuation(e.add(p["u8_k"], 1))
                e.var("u8_c", e.add(e.mul(e.and_(p["u8_b"], 0x1F), 64), cont(e.add(p["u8_k"], 1))))
                _ok(e, e.le(0x80, p["u8_c"]))
                unit(p["u8_c"])
                e.set("u8_k", e.add(p["u8_k"], 2))

            def three():
                continuation(e.add(p["u8_k"], 1))
                continuation(e.add(p["u8_k"], 2))
                e.var("u8_c", e.add(e.add(e.mul(e.and_(p["u8_b"], 0x0F), 4096), e.mul(cont(e.add(p["u8_k"], 1)), 64)), cont(e.add(p["u8_k"], 2))))
                _ok(e, e.both(e.le(0x800, p["u8_c"]), e.either(e.lt(p["u8_c"], 0xD800), e.le(0xE000, p["u8_c"]))))
                unit(p["u8_c"])
                e.set("u8_k", e.add(p["u8_k"], 3))

            def four():
                for k in (1, 2, 3):
                    continuation(e.add(p["u8_k"], k))
                e.var("u8_c", e.add(e.add(e.mul(e.and_(p["u8_b"], 0x07), 1 << 18), e.mul(cont(e.add(p["u8_k"], 1)), 4096)),
                                    e.add(e.mul(cont(e.add(p["u8_k"], 2)), 64), cont(e.add(p["u8_k"], 3)))))
                _ok(e, e.both(e.le(0x10000, p["u8_c"]), e.le(p["u8_c"], 0x10FFFF)))
                e.var("u8_x", e.sub(p["u8_c"], 0x10000))
                unit(e.add(0xD800, e.udiv(p["u8_x"], 1024)))
                unit(e.add(0xDC00, e.urem(p["u8_x"], 1024)))
                e.set("u8_k", e.add(p["u8_k"], 4))

            e.if_(e.lt(p["u8_b"], 0x80), lambda: (unit(p["u8_b"]), e.set("u8_k", e.add(p["u8_k"], 1))), lambda: e.if_(
                e.both(e.le(0xC2, p["u8_b"]), e.lt(p["u8_b"], 0xE0)), two, lambda: e.if_(
                    e.both(e.le(0xE0, p["u8_b"]), e.lt(p["u8_b"], 0xF0)), three, lambda: e.if_(
                        e.both(e.le(0xF0, p["u8_b"]), e.lt(p["u8_b"], 0xF5)), four, lambda: _ok(e, e.eq(0, 1))))))

        e.while_(lambda: e.lt(p["u8_k"], p["n"]), each)
        e.st(p["u8_h"], p["u8_m"])
        e.give(p["u8_h"])
    return _function(("pos", "n"), build, tables)


def _same_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["a"]), e.ld(p["b"])), lambda: e.give(0))
        e.for_("sm_k", 1, e.add(e.ld(p["a"]), 1), lambda: e.if_(e.ne(at(e, p["a"], p["sm_k"]), at(e, p["b"], p["sm_k"])), lambda: e.give(0)))
        e.give(1)
    return _function(("a", "b"), build, tables)


def _concat_fn(tables):
    """``concat(a, b)``: the string ``a`` followed by ``b`` (a handle 0 is empty)."""
    def build(e: E):
        p = e.p
        e.var("cc_an", e.sel(e.eq(p["a"], 0), 0, e.ld(e.sel(e.eq(p["a"], 0), G["cur"], p["a"]))))
        e.var("cc_bn", e.sel(e.eq(p["b"], 0), 0, e.ld(e.sel(e.eq(p["b"], 0), G["cur"], p["b"]))))
        e.var("cc_h", e.alloc(e.add(e.add(p["cc_an"], p["cc_bn"]), 1)))
        _ok(e, e.ne(p["cc_h"], NONE))
        e.st(p["cc_h"], e.add(p["cc_an"], p["cc_bn"]))
        e.for_("cc_k", 0, p["cc_an"], lambda: e.st(e.add(e.add(p["cc_h"], 1), p["cc_k"]), at(e, p["a"], e.add(p["cc_k"], 1))))
        e.for_("cc_k", 0, p["cc_bn"], lambda: e.st(e.add(e.add(e.add(p["cc_h"], 1), p["cc_an"]), p["cc_k"]), at(e, p["b"], e.add(p["cc_k"], 1))))
        e.give(p["cc_h"])
    return _function(("a", "b"), build, tables)


def _slice_fn(tables):
    """``slice(h, start, end)``: units ``start`` to ``end`` of string ``h``."""
    def build(e: E):
        p = e.p
        e.var("sl_n", e.sub(p["end"], p["start"]))
        e.var("sl_h", e.alloc(e.add(p["sl_n"], 1)))
        _ok(e, e.ne(p["sl_h"], NONE))
        e.st(p["sl_h"], p["sl_n"])
        e.for_("sl_k", 0, p["sl_n"], lambda: e.st(e.add(e.add(p["sl_h"], 1), p["sl_k"]), at(e, p["h"], e.add(e.add(p["start"], p["sl_k"]), 1))))
        e.give(p["sl_h"])
    return _function(("h", "start", "end"), build, tables)


def _single_fn(tables):
    """``single(u)``: the one-unit string ``u``."""
    def build(e: E):
        p = e.p
        e.var("sg_h", e.alloc(2))
        _ok(e, e.ne(p["sg_h"], NONE))
        e.st(p["sg_h"], 1)
        e.st(e.add(p["sg_h"], 1), p["u"])
        e.give(p["sg_h"])
    return _function(("u",), build, tables)


def _rename_fn(tables):
    """``rename(name)``: the internal class name's replacement (``rename``), or ``name``."""
    def build(e: E):
        p = e.p
        e.var("rn_l", g(e, "renames"))
        e.for_("rn_k", 0, e.ld(p["rn_l"]), lambda: e.if_(e.ne(_call(e, "dj_same", at(e, p["rn_l"], e.add(1, e.mul(p["rn_k"], 2))), p["name"]), 0),
                                                         lambda: e.give(at(e, p["rn_l"], e.add(2, e.mul(p["rn_k"], 2))))))
        e.give(p["name"])
    return _function(("name",), build, tables)


def _descriptor_fn(tables):
    """``descriptor(d)``: ``d`` with every ``L<name>;`` renamed."""
    def build(e: E):
        p = e.p
        e.var("ds_out", 0)
        e.var("ds_k", 0)
        e.var("ds_n", e.ld(p["d"]))

        def each():
            e.var("ds_u", at(e, p["d"], e.add(p["ds_k"], 1)))

            def reference():
                e.var("ds_end", e.add(p["ds_k"], 1))
                e.while_(lambda: e.ne(at(e, p["d"], e.add(p["ds_end"], 1)), ord(";")), lambda: (
                    _ok(e, e.lt(e.add(p["ds_end"], 1), p["ds_n"])), e.set("ds_end", e.add(p["ds_end"], 1))))
                e.var("ds_name", _call(e, "dj_rename", _call(e, "dj_slice", p["d"], e.add(p["ds_k"], 1), p["ds_end"])))
                e.set("ds_out", _call(e, "dj_concat", p["ds_out"], _call(e, "dj_concat", _call(e, "dj_single", ord("L")),
                                                                                       _call(e, "dj_concat", p["ds_name"], _call(e, "dj_single", ord(";"))))))
                e.set("ds_k", e.add(p["ds_end"], 1))

            e.if_(e.eq(p["ds_u"], ord("L")), reference, lambda: (e.set("ds_out", _call(e, "dj_concat", p["ds_out"], _call(e, "dj_single", p["ds_u"]))),
                                                                 e.set("ds_k", e.add(p["ds_k"], 1))))

        e.while_(lambda: e.lt(p["ds_k"], p["ds_n"]), each)
        e.give(e.sel(e.eq(p["ds_out"], 0), _call(e, "dj_slice", p["d"], 0, 0), p["ds_out"]))
    return _function(("d",), build, tables)


def _class_type_fn(tables):
    """``class_type(name)``: the renamed descriptor of an internal class name (an array name is its own descriptor)."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(at(e, p["name"], 1), ord("[")), lambda: e.give(_call(e, "dj_descriptor", p["name"])))
        e.give(_call(e, "dj_descriptor", _call(e, "dj_concat", _call(e, "dj_single", ord("L")), _call(e, "dj_concat", p["name"], _call(e, "dj_single", ord(";"))))))
    return _function(("name",), build, tables)


def _descriptor_of_fn(tables):
    """``descriptor_of(name)``: ``L<name>;`` for an internal class name (an array name is itself), not renamed."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(at(e, p["name"], 1), ord("[")), lambda: e.give(p["name"]))
        e.give(_call(e, "dj_concat", _call(e, "dj_single", ord("L")), _call(e, "dj_concat", p["name"], _call(e, "dj_single", ord(";")))))
    return _function(("name",), build, tables)


def _parameters_fn(tables):
    """``parameters(d)``: the method descriptor's parameters and result as ``[n + 1, parameters..., result]``."""
    def build(e: E):
        p = e.p
        e.var("pm_h", e.alloc(e.add(e.ld(p["d"]), 2)))
        _ok(e, e.ne(p["pm_h"], NONE))
        e.var("pm_n", 0)
        e.var("pm_k", 1)  # after "("

        def one():
            e.var("pm_s", p["pm_k"])
            e.while_(lambda: e.eq(at(e, p["d"], e.add(p["pm_k"], 1)), ord("[")), lambda: e.set("pm_k", e.add(p["pm_k"], 1)))
            e.if_(e.eq(at(e, p["d"], e.add(p["pm_k"], 1)), ord("L")), lambda: e.while_(lambda: e.ne(at(e, p["d"], e.add(p["pm_k"], 1)), ord(";")),
                                                                                        lambda: e.set("pm_k", e.add(p["pm_k"], 1))))
            e.set("pm_k", e.add(p["pm_k"], 1))
            e.set("pm_n", e.add(p["pm_n"], 1))
            e.st(e.add(p["pm_h"], p["pm_n"]), _call(e, "dj_slice", p["d"], p["pm_s"], p["pm_k"]))

        e.while_(lambda: e.ne(at(e, p["d"], e.add(p["pm_k"], 1)), ord(")")), one)
        e.set("pm_k", e.add(p["pm_k"], 1))
        e.set("pm_n", e.add(p["pm_n"], 1))
        e.st(e.add(p["pm_h"], p["pm_n"]), _call(e, "dj_slice", p["d"], p["pm_k"], e.ld(p["d"])))
        e.st(p["pm_h"], p["pm_n"])
        e.give(p["pm_h"])
    return _function(("d",), build, tables)


def _kind_fn(tables):
    """``kind(d)``: the value kind of a field or array element descriptor."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["d"]), 1), lambda: e.give(KA))
        e.var("kd_u", at(e, p["d"], 1))
        for chars, kind in (("IZBCS", KI), ("F", KF), ("J", KJ), ("D", KD)):
            for char in chars:
                e.if_(e.eq(p["kd_u"], ord(char)), lambda kind=kind: e.give(kind))
        e.give(KA)
    return _function(("d",), build, tables)


def _variant_fn(tables):
    """``variant(d)``: the aget/iget form of an element or field descriptor (references 2)."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(e.ld(p["d"]), 1), lambda: e.give(2))
        e.var("vr_u", at(e, p["d"], 1))
        for char, variant in (("I", 0), ("F", 0), ("J", 1), ("D", 1), ("Z", 3), ("B", 4), ("C", 5), ("S", 6)):
            e.if_(e.eq(p["vr_u"], ord(char)), lambda variant=variant: e.give(variant))
        e.give(2)
    return _function(("d",), build, tables)


# -- the lowering state: registers and units ----------------------------------------------------------------------------------

def _unit_fn(tables):
    """``unit(kind, value)``: one more code unit (kind 0 a value, 1 a string, 2 a type, 3 a field, 4 a method)."""
    def build(e: E):
        p = e.p
        e.var("un_n", g(e, "nunits"))
        _ok(e, e.lt(p["un_n"], g(e, "ucap")))
        e.st(e.add(g(e, "units"), e.mul(p["un_n"], 2)), p["kind"])
        e.st(e.add(e.add(g(e, "units"), e.mul(p["un_n"], 2)), 1), p["value"])
        sg(e, "nunits", e.add(p["un_n"], 1))
        e.give(1)
    return _function(("kind", "value"), build, tables)


def unit(e: E, value, kind=0):
    _call(e, "dj_unit", kind, value)


def units(e: E, *values):
    for value in values:
        unit(e, value)


def _move_fn(tables):
    """``move(destination, source, kind)``: the move of the narrowest form (none for the same register)."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(p["dst"], p["src"]), lambda: e.give(1))
        e.var("mv_op", MOVE(e, p["kind"]))
        e.if_(e.both(e.lt(p["dst"], 16), e.lt(p["src"], 16)), lambda: unit(e, e.or_(e.or_(e.mul(p["src"], 4096), e.mul(p["dst"], 256)), p["mv_op"])),
              lambda: e.if_(e.lt(p["dst"], 256), lambda: units(e, e.or_(e.mul(p["dst"], 256), e.add(p["mv_op"], 1)), p["src"]),
                            lambda: units(e, e.add(p["mv_op"], 2), p["dst"], p["src"])))
        e.give(1)
    return _function(("dst", "src", "kind"), build, tables)


def move(e: E, dst, src, kind):
    _call(e, "dj_move", dst, src, kind)


def _scratch_fn(tables):
    """``scratch(kind)``: the next scratch register (a retry where the scratch registers are exhausted)."""
    def build(e: E):
        p = e.p
        e.var("sc_r", g(e, "next"))
        sg(e, "next", e.add(p["sc_r"], size(e, p["kind"])))
        e.if_(e.lt(g(e, "scratch"), g(e, "next")), lambda: (sg(e, "retry", 1), e.give(0)))
        e.if_(e.lt(g(e, "used"), g(e, "next")), lambda: sg(e, "used", g(e, "next")))
        e.give(p["sc_r"])
    return _function(("kind",), build, tables)


def _src_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.le(p["reg"], p["limit"]), lambda: e.give(p["reg"]))
        e.var("sr_s", _call(e, "dj_scratch", p["kind"]))
        move(e, p["sr_s"], p["reg"], p["kind"])
        e.give(p["sr_s"])
    return _function(("reg", "kind", "limit"), build, tables)


def src(e: E, reg, kind, limit):
    return _call(e, "dj_src", reg, kind, limit)


def _dst_fn(tables):
    def build(e: E):
        p = e.p
        e.if_(e.le(p["reg"], p["limit"]), lambda: e.give(p["reg"]))
        e.var("dt_s", _call(e, "dj_scratch", p["kind"]))
        e.var("dt_a", e.add(g(e, "after"), e.mul(g(e, "nafter"), 3)))
        e.st(p["dt_a"], p["reg"])
        e.st(e.add(p["dt_a"], 1), p["dt_s"])
        e.st(e.add(p["dt_a"], 2), p["kind"])
        sg(e, "nafter", e.add(g(e, "nafter"), 1))
        e.give(p["dt_s"])
    return _function(("reg", "kind", "limit"), build, tables)


def dst(e: E, reg, kind, limit):
    return _call(e, "dj_dst", reg, kind, limit)


def begin(e: E):
    sg(e, "next", 0)
    sg(e, "nafter", 0)


def _end_fn(tables):
    def build(e: E):
        p = e.p
        e.for_("en_k", 0, g(e, "nafter"), lambda: (e.var("en_a", e.add(g(e, "after"), e.mul(p["en_k"], 3))),
                                                    move(e, e.ld(p["en_a"]), at(e, p["en_a"], 1), at(e, p["en_a"], 2))))
        sg(e, "nafter", 0)
        e.give(1)
    return _function((), build, tables)


def end(e: E):
    _call(e, "dj_end")


def _push_fn(tables):
    """``push(kind, descriptor)``: the register of a new stack entry."""
    def build(e: E):
        p = e.p
        e.var("ps_r", e.add(g(e, "scratch"), g(e, "sdepth")))
        e.var("ps_e", e.add(g(e, "stack"), e.mul(g(e, "sn"), 2)))
        e.st(p["ps_e"], p["kind"])
        e.st(e.add(p["ps_e"], 1), p["desc"])
        sg(e, "sn", e.add(g(e, "sn"), 1))
        sg(e, "sdepth", e.add(g(e, "sdepth"), size(e, p["kind"])))
        _ok(e, e.le(g(e, "sdepth"), g(e, "maxstack")))  # DEX-STACK-DEPTH
        e.give(p["ps_r"])
    return _function(("kind", "desc"), build, tables)


def push(e: E, kind, desc=0):
    return _call(e, "dj_push", kind, desc)


def _pop_fn(tables):
    """``pop()``: the top entry's register (its kind and descriptor in ``popk``, ``popd``)."""
    def build(e: E):
        _ok(e, e.lt(0, g(e, "sn")))  # DEX-STACK-UNDERFLOW
        sg(e, "sn", e.sub(g(e, "sn"), 1))
        e.var("pp_e", e.add(g(e, "stack"), e.mul(g(e, "sn"), 2)))
        sg(e, "popk", e.ld(e.p["pp_e"]))
        sg(e, "popd", at(e, e.p["pp_e"], 1))
        sg(e, "sdepth", e.sub(g(e, "sdepth"), size(e, g(e, "popk"))))
        e.give(e.add(g(e, "scratch"), g(e, "sdepth")))
    return _function((), build, tables)


def pop(e: E, name: str):
    """Pops into the variables ``name``, ``name_k``, ``name_d``."""
    e.var(name, _call(e, "dj_pop"))
    e.var(f"{name}_k", g(e, "popk"))
    e.var(f"{name}_d", g(e, "popd"))


def _local_fn(tables):
    def build(e: E):
        p = e.p
        e.give(e.sel(e.lt(p["index"], g(e, "ins")), e.add(g(e, "parambase"), p["index"]), e.sub(e.add(g(e, "freebase"), p["index"]), g(e, "ins"))))
    return _function(("index",), build, tables)


def local(e: E, index):
    return _call(e, "dj_local", index)


# -- the instruction forms ------------------------------------------------------------------------------------------------------

def _const_fn(tables):
    def build(e: E):
        p = e.p
        begin(e)

        def wide_const():
            e.var("cs_r", dst(e, p["reg"], p["kind"], 255))
            v = p["value"]
            e.if_(e.lt(e.add(v, 0x8000), 0x10000), lambda: units(e, e.or_(e.mul(p["cs_r"], 256), 0x16), e.and_(v, 0xFFFF)), lambda: e.if_(
                e.lt(e.add(v, 1 << 31), 1 << 32), lambda: units(e, e.or_(e.mul(p["cs_r"], 256), 0x17), e.and_(v, 0xFFFF), e.and_(e.udiv(v, 65536), 0xFFFF)),
                lambda: e.if_(e.eq(e.and_(v, 0xFFFFFFFFFFFF), 0), lambda: units(e, e.or_(e.mul(p["cs_r"], 256), 0x19), e.and_(e.udiv(v, 1 << 48), 0xFFFF)),
                              lambda: units(e, e.or_(e.mul(p["cs_r"], 256), 0x18), *(e.and_(e.udiv(v, 1 << shift), 0xFFFF) if shift else e.and_(v, 0xFFFF)
                                                                                    for shift in (0, 16, 32, 48))))))

        def narrow_const():
            e.var("cs_v", signed(e, e.and_(p["value"], 0xFFFFFFFF), 32))
            v = p["cs_v"]

            def wider():
                e.var("cs_r", dst(e, p["reg"], p["kind"], 255))
                e.if_(e.lt(e.add(v, 0x8000), 0x10000), lambda: units(e, e.or_(e.mul(p["cs_r"], 256), 0x13), e.and_(v, 0xFFFF)), lambda: e.if_(
                    e.eq(e.and_(v, 0xFFFF), 0), lambda: units(e, e.or_(e.mul(p["cs_r"], 256), 0x15), e.and_(e.udiv(v, 65536), 0xFFFF)),
                    lambda: units(e, e.or_(e.mul(p["cs_r"], 256), 0x14), e.and_(v, 0xFFFF), e.and_(e.udiv(v, 65536), 0xFFFF))))

            e.if_(e.both(e.lt(e.add(v, 8), 16), e.lt(p["reg"], 16)), lambda: unit(e, e.or_(e.or_(e.mul(e.and_(v, 0xF), 4096), e.mul(p["reg"], 256)), 0x12)),
                  wider)

        e.if_(wide(e, p["kind"]), wide_const, narrow_const)
        end(e)
        e.give(1)
    return _function(("reg", "value", "kind"), build, tables)


def const(e: E, reg, value, kind):
    _call(e, "dj_const", reg, value, kind)


def _x21c_fn(tables):
    def build(e: E):
        p = e.p
        begin(e)
        e.var("xa_r", 0)
        e.if_(e.ne(p["write"], 0), lambda: e.set("xa_r", dst(e, p["reg"], p["kind"], 255)), lambda: e.set("xa_r", src(e, p["reg"], p["kind"], 255)))
        unit(e, e.or_(e.mul(p["xa_r"], 256), p["opc"]))
        unit(e, p["refv"], p["refk"])
        end(e)
        e.give(1)
    return _function(("opc", "reg", "kind", "refk", "refv", "write"), build, tables)


def _x11x_fn(tables):
    def build(e: E):
        p = e.p
        begin(e)
        e.var("xb_r", 0)
        e.if_(e.ne(p["write"], 0), lambda: e.set("xb_r", dst(e, p["reg"], p["kind"], 255)), lambda: e.set("xb_r", src(e, p["reg"], p["kind"], 255)))
        unit(e, e.or_(e.mul(p["xb_r"], 256), p["opc"]))
        end(e)
        e.give(1)
    return _function(("opc", "reg", "kind", "write"), build, tables)


def _x12x_fn(tables):
    def build(e: E):
        p = e.p
        begin(e)
        e.var("xc_b", src(e, p["b"], p["bk"], 15))
        e.var("xc_a", 0)
        e.if_(e.ne(p["aw"], 0), lambda: e.set("xc_a", dst(e, p["a"], p["ak"], 15)), lambda: e.set("xc_a", src(e, p["a"], p["ak"], 15)))
        unit(e, e.or_(e.or_(e.mul(p["xc_b"], 4096), e.mul(p["xc_a"], 256)), p["opc"]))
        e.if_(e.ne(p["refk"], NONE), lambda: unit(e, p["refv"], p["refk"]))
        end(e)
        e.give(1)
    return _function(("opc", "a", "ak", "b", "bk", "refk", "refv", "aw"), build, tables)


def _x23x_fn(tables):
    def build(e: E):
        p = e.p
        begin(e)
        e.var("xd_b", src(e, p["b"], p["bk"], 255))
        e.var("xd_c", src(e, p["c"], p["ck"], 255))
        e.var("xd_a", 0)
        e.if_(e.ne(p["aw"], 0), lambda: e.set("xd_a", dst(e, p["a"], p["ak"], 255)), lambda: e.set("xd_a", src(e, p["a"], p["ak"], 255)))
        units(e, e.or_(e.mul(p["xd_a"], 256), p["opc"]), e.or_(e.mul(p["xd_c"], 256), p["xd_b"]))
        end(e)
        e.give(1)
    return _function(("opc", "a", "ak", "b", "bk", "c", "ck", "aw"), build, tables)


def x21c(e, opc, reg, kind, refk, refv, write):
    _call(e, "dj_x21c", opc, reg, kind, refk, refv, write)


def x11x(e, opc, reg, kind, write=0):
    _call(e, "dj_x11x", opc, reg, kind, write)


def x12x(e, opc, a, ak, b, bk, refk=NONE, refv=0, aw=1):
    _call(e, "dj_x12x", opc, a, ak, b, bk, refk, refv, aw)


def x23x(e, opc, a, ak, b, bk, c, ck, aw=1):
    _call(e, "dj_x23x", opc, a, ak, b, bk, c, ck, aw)


def _fixup_fn(tables):
    """``fixup(start, field, target, width)``: a branch offset resolved once the labels are known."""
    def build(e: E):
        p = e.p
        e.var("fx_a", e.add(g(e, "fix"), e.mul(g(e, "nfix"), 4)))
        for k, name in enumerate(("start", "field", "target", "width")):
            e.st(e.add(p["fx_a"], k), p[name])
        sg(e, "nfix", e.add(g(e, "nfix"), 1))
        e.give(1)
    return _function(("start", "field", "target", "width"), build, tables)


def _goto_fn(tables):
    def build(e: E):
        p = e.p
        e.var("gt_n", g(e, "nunits"))
        e.if_(e.ne(g(e, "long"), 0), lambda: (_call(e, "dj_fixup", p["gt_n"], e.add(p["gt_n"], 1), p["target"], 32), units(e, 0x2A, 0, 0)),
              lambda: (_call(e, "dj_fixup", p["gt_n"], e.add(p["gt_n"], 1), p["target"], 16), units(e, 0x29, 0)))
        e.give(1)
    return _function(("target",), build, tables)


def _branch_fn(tables):
    """``branch(opc, count, a, ak, b, bk, target)``: an if-test of one or two operands."""
    def build(e: E):
        p = e.p
        begin(e)
        e.var("br_first", 0)
        e.if_(e.eq(p["count"], 1), lambda: e.set("br_first", e.or_(e.mul(src(e, p["a"], p["ak"], 255), 256), p["opc"])),
              lambda: (e.var("br_a", src(e, p["a"], p["ak"], 15)), e.var("br_b", src(e, p["b"], p["bk"], 15)),
                       e.set("br_first", e.or_(e.or_(e.mul(p["br_b"], 4096), e.mul(p["br_a"], 256)), p["opc"]))))

        def long_branch():
            units(e, e.or_(e.and_(p["br_first"], 0xFF00), at(e, TBL_AT, e.add(TABLE["inverse"], p["opc"]))), 5)
            _call(e, "dj_goto", p["target"])

        def short_branch():
            e.var("br_n", g(e, "nunits"))
            _call(e, "dj_fixup", p["br_n"], e.add(p["br_n"], 1), p["target"], 16)
            units(e, p["br_first"], 0)

        e.if_(e.ne(g(e, "long"), 0), long_branch, short_branch)
        e.give(1)
    return _function(("opc", "count", "a", "ak", "b", "bk", "target"), build, tables)


# -- the constant pool and members -------------------------------------------------------------------------------------------

def pool(e: E, index, word: int):
    """Word ``word`` (0 the tag, then its fields) of constant pool entry ``index`` (declines past the pool)."""
    _ok(e, e.lt(index, g(e, "npool")))
    return at(e, g(e, "pool"), e.add(e.mul(index, 3), word))


def utf8_entry(e: E, index):
    """The text of a ``CONSTANT_Utf8`` entry (declines on another entry)."""
    _ok(e, e.eq(pool(e, index, 0), 1))
    return pool(e, index, 1)


def _member_fn(tables):
    """``member(index)``: a field or method reference's ``[owner, name, descriptor]`` (internal names, not renamed)."""
    def build(e: E):
        p = e.p
        e.var("mb_h", e.alloc(3))
        _ok(e, e.ne(p["mb_h"], NONE))
        e.var("mb_nat", pool(e, p["index"], 2))
        e.st(p["mb_h"], utf8_entry(e, pool(e, pool(e, p["index"], 1), 1)))
        e.st(e.add(p["mb_h"], 1), utf8_entry(e, pool(e, p["mb_nat"], 1)))
        e.st(e.add(p["mb_h"], 2), utf8_entry(e, pool(e, p["mb_nat"], 2)))
        e.give(p["mb_h"])
    return _function(("index",), build, tables)


def _pool_class_fn(tables):
    """``pool_class(index)``: the renamed descriptor of a ``CONSTANT_Class`` entry."""
    def build(e: E):
        p = e.p
        e.give(_call(e, "dj_classtype", utf8_entry(e, pool(e, p["index"], 1))))
    return _function(("index",), build, tables)


def is_wide_descriptor(e: E, h):
    """``h`` (a descriptor or kind letter; 0 none) is ``J`` or ``D``."""
    return e.both(e.ne(h, 0), e.both(e.eq(e.ld(e.sel(e.eq(h, 0), G["cur"], h)), 1),
                                     e.either(e.eq(at(e, e.sel(e.eq(h, 0), G["cur"], h), 1), ord("J")), e.eq(at(e, e.sel(e.eq(h, 0), G["cur"], h), 1), ord("D")))))


# -- frames -------------------------------------------------------------------------------------------------------------------

LOCALS_EXTRA = 512


def _place_fn(tables):
    """``place(items, n)``: the locals of ``n`` descriptors in order (0: an unknown item), each wide one taking two
    slots."""
    def build(e: E):
        p = e.p
        e.var("pl_h", e.alloc(e.add(g(e, "maxlocals"), LOCALS_EXTRA)))
        _ok(e, e.ne(p["pl_h"], NONE))
        e.for_("pl_k", 0, e.add(g(e, "maxlocals"), LOCALS_EXTRA), lambda: e.st(e.add(p["pl_h"], p["pl_k"]), 0))
        e.var("pl_slot", 0)

        def each():
            e.var("pl_i", at(e, p["items"], p["pl_k"]))
            _ok(e, e.lt(p["pl_slot"], e.add(g(e, "maxlocals"), LOCALS_EXTRA - 2)))
            e.st(e.add(p["pl_h"], p["pl_slot"]), p["pl_i"])
            e.set("pl_slot", e.add(p["pl_slot"], e.sel(is_wide_descriptor(e, p["pl_i"]), 2, 1)))

        e.for_("pl_k", 0, p["n"], each)
        e.give(p["pl_h"])
    return _function(("items", "n"), build, tables)


def _ordered_fn(tables):
    """``ordered(locals)``: the locals' items in slot order up to the last one (``[n, items...]``; 0 for a gap)."""
    def build(e: E):
        p = e.p
        e.var("od_top", NONE)
        e.for_("od_k", 0, e.add(g(e, "maxlocals"), LOCALS_EXTRA), lambda: e.if_(e.ne(at(e, p["locals"], p["od_k"]), 0), lambda: e.set("od_top", p["od_k"])))
        e.var("od_h", e.alloc(e.add(g(e, "maxlocals"), LOCALS_EXTRA + 1)))
        _ok(e, e.ne(p["od_h"], NONE))
        e.var("od_n", 0)
        e.var("od_slot", 0)

        def each():
            e.var("od_i", at(e, p["locals"], p["od_slot"]))
            e.st(e.add(e.add(p["od_h"], 1), p["od_n"]), p["od_i"])
            e.set("od_n", e.add(p["od_n"], 1))
            e.set("od_slot", e.add(p["od_slot"], e.sel(is_wide_descriptor(e, p["od_i"]), 2, 1)))

        e.if_(e.ne(p["od_top"], NONE), lambda: e.while_(lambda: e.le(p["od_slot"], p["od_top"]), each))
        e.st(p["od_h"], p["od_n"])
        e.give(p["od_h"])
    return _function(("locals",), build, tables)


def _copy_locals_fn(tables):
    def build(e: E):
        p = e.p
        e.var("cl_h", e.alloc(e.add(g(e, "maxlocals"), LOCALS_EXTRA)))
        _ok(e, e.ne(p["cl_h"], NONE))
        e.for_("cl_k", 0, e.add(g(e, "maxlocals"), LOCALS_EXTRA), lambda: e.st(e.add(p["cl_h"], p["cl_k"]), at(e, p["locals"], p["cl_k"])))
        e.give(p["cl_h"])
    return _function(("locals",), build, tables)


def _verification_fn(tables):
    """``verification(pos)``: the verification type at ``pos`` as a descriptor (0 for top, null, uninitialized); its
    length in ``popk``."""
    def build(e: E):
        p = e.p
        e.var("vf_t", u1(e, p["pos"]))
        sg(e, "popk", e.sel(e.either(e.eq(p["vf_t"], 7), e.eq(p["vf_t"], 8)), 3, 1))
        e.if_(e.eq(p["vf_t"], 7), lambda: e.give(_call(e, "dj_descof", utf8_entry(e, pool(e, u2(e, e.add(p["pos"], 1)), 1)))))
        for tag, letter in ((1, "I"), (2, "F"), (3, "D"), (4, "J")):
            e.if_(e.eq(p["vf_t"], tag), lambda letter=letter: e.give(e.ld(K[letter])))
        e.give(0)
    return _function(("pos",), build, tables)


def _stack_map_fn(tables):
    """``stack_map(pos, initial)``: the frames of the ``StackMapTable`` at ``pos`` (``frames[pc]``: the locals; only
    frames with an empty stack)."""
    def build(e: E):
        p = e.p
        e.var("smp", e.add(p["pos"], 2))
        e.var("smo", e.sub(0, 1))  # offset -1
        e.var("smc", _call(e, "dj_copylocals", p["initial"]))
        e.var("smitems", e.alloc(e.add(g(e, "maxlocals"), LOCALS_EXTRA + 300)))
        _ok(e, e.ne(p["smitems"], NONE))

        def verification():
            e.var("smv", _call(e, "dj_verification", p["smp"]))
            e.set("smp", e.add(p["smp"], g(e, "popk")))
            return p["smv"]

        def entry():
            e.var("smk", u1(e, p["smp"]))
            e.set("smp", e.add(p["smp"], 1))
            e.var("smd", 0)

            def same():
                e.set("smd", p["smk"])

            def extended():
                e.set("smd", u2(e, p["smp"]))
                e.set("smp", e.add(p["smp"], 2))

            def chop():
                extended()
                e.var("smod", _call(e, "dj_ordered", p["smc"]))
                e.var("smcut", e.sub(251, p["smk"]))
                e.var("smkeep", e.sel(e.lt(p["smcut"], e.ld(p["smod"])), e.sub(e.ld(p["smod"]), p["smcut"]), 0))
                e.set("smc", _call(e, "dj_place", e.add(p["smod"], 1), p["smkeep"]))

            def append():
                extended()
                e.var("smod", _call(e, "dj_ordered", p["smc"]))
                e.for_("smj", 0, e.ld(p["smod"]), lambda: e.st(e.add(p["smitems"], p["smj"]), at(e, p["smod"], e.add(p["smj"], 1))))
                e.var("smn", e.ld(p["smod"]))
                e.for_("smj", 0, e.sub(p["smk"], 251), lambda: (e.st(e.add(p["smitems"], p["smn"]), verification()), e.set("smn", e.add(p["smn"], 1))))
                e.set("smc", _call(e, "dj_place", p["smitems"], p["smn"]))

            def full():
                extended()
                e.var("smcount", u2(e, p["smp"]))
                e.set("smp", e.add(p["smp"], 2))
                _ok(e, e.le(p["smcount"], e.add(g(e, "maxlocals"), 256)))
                e.for_("smj", 0, p["smcount"], lambda: e.st(e.add(p["smitems"], p["smj"]), verification()))
                e.set("smc", _call(e, "dj_place", p["smitems"], p["smcount"]))
                _ok(e, e.eq(u2(e, p["smp"]), 0))  # DEX-FRAME-STACK
                e.set("smp", e.add(p["smp"], 2))

            e.if_(e.lt(p["smk"], 64), same, lambda: e.if_(e.eq(p["smk"], 251), extended, lambda: e.if_(
                e.both(e.le(248, p["smk"]), e.le(p["smk"], 250)), chop, lambda: e.if_(
                    e.both(e.le(252, p["smk"]), e.le(p["smk"], 254)), append, lambda: e.if_(e.eq(p["smk"], 255), full, lambda: _ok(e, e.eq(0, 1)))))))
            e.set("smo", e.add(e.add(p["smo"], p["smd"]), 1))
            _ok(e, e.lt(p["smo"], g(e, "clen")))
            e.st(e.add(g(e, "frames"), p["smo"]), _call(e, "dj_copylocals", p["smc"]))

        e.for_("smq", 0, u2(e, p["pos"]), entry)
        e.give(1)
    return _function(("pos", "initial"), build, tables)


# -- members of the lowering --------------------------------------------------------------------------------------------------

def _rearrange_fn(tables):
    """``rearrange(take, order...)``: the JVM's dup_x/dup2/swap forms; ``order`` is ``count`` indexes at ``order``."""
    def build(e: E):
        p = e.p
        e.var("ra_base", e.sub(g(e, "sn"), p["take"]))
        e.var("ra_saved", e.alloc(e.add(e.mul(p["take"], 3), 1)))
        _ok(e, e.ne(p["ra_saved"], NONE))
        e.for_("ra_k", 0, p["take"], lambda: (e.st(e.add(p["ra_saved"], e.mul(p["ra_k"], 3)), at(e, g(e, "stack"), e.mul(e.add(p["ra_base"], p["ra_k"]), 2))),
                                              e.st(e.add(e.add(p["ra_saved"], e.mul(p["ra_k"], 3)), 1),
                                                   at(e, g(e, "stack"), e.add(e.mul(e.add(p["ra_base"], p["ra_k"]), 2), 1)))))
        e.for_("ra_k", 0, p["take"], lambda: _call(e, "dj_pop"))
        e.var("ra_pos", e.add(g(e, "scratch"), g(e, "sdepth")))
        begin(e)

        def stage():
            e.var("ra_kind", at(e, p["ra_saved"], e.mul(p["ra_k"], 3)))
            e.var("ra_r", _call(e, "dj_scratch", p["ra_kind"]))
            move(e, p["ra_r"], p["ra_pos"], p["ra_kind"])
            e.st(e.add(e.add(p["ra_saved"], e.mul(p["ra_k"], 3)), 2), p["ra_r"])
            e.set("ra_pos", e.add(p["ra_pos"], size(e, p["ra_kind"])))

        e.for_("ra_k", 0, p["take"], stage)

        def each():
            e.var("ra_i", at(e, p["order"], p["ra_k"]))
            e.var("ra_e", e.add(p["ra_saved"], e.mul(p["ra_i"], 3)))
            move(e, push(e, e.ld(p["ra_e"]), at(e, p["ra_e"], 1)), at(e, p["ra_e"], 2), e.ld(p["ra_e"]))

        e.for_("ra_k", 0, p["count"], each)
        e.give(1)
    return _function(("take", "order", "count"), build, tables)


def _invoke_fn(tables):
    def build(e: E):
        p = e.p
        e.var("iv_m", _call(e, "dj_member", p["index"]))
        e.var("iv_ps", _call(e, "dj_parameters", at(e, p["iv_m"], 2)))
        e.var("iv_np", e.sub(e.ld(p["iv_ps"]), 1))
        e.var("iv_result", at(e, p["iv_ps"], e.ld(p["iv_ps"])))
        e.var("iv_recv", e.flag(e.ne(p["opc"], 0xB8)))
        e.for_("iv_k", 0, e.add(p["iv_np"], p["iv_recv"]), lambda: _call(e, "dj_pop"))
        e.var("iv_first", e.add(g(e, "scratch"), g(e, "sdepth")))
        e.var("iv_count", p["iv_recv"])
        e.for_("iv_k", 1, e.add(p["iv_np"], 1), lambda: e.set("iv_count", e.add(p["iv_count"], size(e, _call(e, "dj_kind", at(e, p["iv_ps"], p["iv_k"]))))))
        e.var("iv_dex", e.sel(e.eq(p["opc"], 0xB6), 0x74, e.sel(e.eq(p["opc"], 0xB8), 0x77, 0x78)))

        def special():
            e.var("iv_direct", e.flag(e.either(e.ne(_call(e, "dj_same", at(e, p["iv_m"], 1), e.ld(K["init"])), 0),
                                               e.ne(_call(e, "dj_same", e.ld(p["iv_m"]), g(e, "this")), 0))))
            e.set("iv_dex", e.sel(e.ne(p["iv_direct"], 0), 0x76, 0x75))

        e.if_(e.eq(p["opc"], 0xB7), special)
        _ok(e, e.le(p["iv_count"], 255))  # DEX-INVOKE-ARGUMENTS
        e.var("iv_ref", e.alloc(4))
        _ok(e, e.ne(p["iv_ref"], NONE))
        e.st(p["iv_ref"], _call(e, "dj_classtype", e.ld(p["iv_m"])))
        e.st(e.add(p["iv_ref"], 1), at(e, p["iv_m"], 1))
        e.st(e.add(p["iv_ref"], 2), _call(e, "dj_descriptor", p["iv_result"]))
        e.var("iv_params", e.alloc(e.add(p["iv_np"], 1)))
        _ok(e, e.ne(p["iv_params"], NONE))
        e.st(p["iv_params"], p["iv_np"])
        e.for_("iv_k", 1, e.add(p["iv_np"], 1), lambda: e.st(e.add(p["iv_params"], p["iv_k"]), _call(e, "dj_descriptor", at(e, p["iv_ps"], p["iv_k"]))))
        e.st(e.add(p["iv_ref"], 3), p["iv_params"])
        unit(e, e.or_(e.mul(p["iv_count"], 256), p["iv_dex"]))
        unit(e, p["iv_ref"], 4)
        unit(e, e.sel(e.eq(p["iv_count"], 0), 0, p["iv_first"]))
        e.if_(e.lt(g(e, "outs"), p["iv_count"]), lambda: sg(e, "outs", p["iv_count"]))

        def result():
            e.var("iv_kind", _call(e, "dj_kind", p["iv_result"]))
            e.var("iv_held", e.sel(e.eq(p["iv_kind"], KA), at(e, p["iv_ref"], 2), 0))
            x11x(e, MOVE_RESULT(e, p["iv_kind"]), push(e, p["iv_kind"], p["iv_held"]), p["iv_kind"], 1)

        e.if_(e.eq(_call(e, "dj_same", p["iv_result"], e.ld(K["V"])), 0), result)
        e.give(1)
    return _function(("opc", "index"), build, tables)


def _element_fn(tables):
    """``element(array descriptor, offset)``: the element descriptor an array load or store (``offset`` from its first
    opcode) works on."""
    def build(e: E):
        p = e.p

        def byte_array():
            _ok(e, e.ne(p["array"], 0))
            _ok(e, e.both(e.eq(e.ld(p["array"]), 2), e.both(e.eq(at(e, p["array"], 1), ord("[")),
                                                             e.either(e.eq(at(e, p["array"], 2), ord("B")), e.eq(at(e, p["array"], 2), ord("Z"))))))
            e.give(_call(e, "dj_single", at(e, p["array"], 2)))

        e.if_(e.eq(p["offset"], 5), byte_array)
        e.if_(e.eq(p["offset"], 4), lambda: e.give(e.sel(e.eq(p["array"], 0), e.ld(K["Object"]),
                                                         _call(e, "dj_slice", e.sel(e.eq(p["array"], 0), e.ld(K["Object"]), p["array"]), 1,
                                                               e.ld(e.sel(e.eq(p["array"], 0), e.ld(K["Object"]), p["array"]))))))
        result = e.c(0)
        for k, char in enumerate("IJFD..CS"):
            if char != ".":
                result = e.sel(e.eq(p["offset"], k), e.ld(K[char]), result)
        e.give(result)
    return _function(("array", "offset"), build, tables)


# -- one JVM instruction ----------------------------------------------------------------------------------------------------

def _length_fn(tables):
    """``length(pc)``: the instruction's length at ``pc``."""
    def build(e: E):
        p = e.p
        cb = lambda k: u1(e, e.add(e.add(g(e, "code"), p["pc"]), k))  # noqa: E731
        e.var("ln_op", cb(0))
        o = p["ln_op"]
        for ops, n in (((0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3A, 0xA9, 0xBC), 2),
                       ((0x11, 0x13, 0x14, 0x84, 0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7), 3), ((0xB9, 0xBA, 0xC8), 5), ((0xC5,), 4)):
            hit = e.c(0)
            for op_ in ops:
                hit = e.or_(hit, e.flag(e.eq(o, op_)))
            e.if_(e.ne(hit, 0), lambda n=n: e.give(n))
        e.if_(e.either(e.both(e.le(0x99, o), e.le(o, 0xA8)), e.both(e.le(0xB2, o), e.le(o, 0xB8))), lambda: e.give(3))
        e.if_(e.eq(o, 0xC4), lambda: e.give(e.sel(e.eq(cb(1), 0x84), 6, 4)))

        def switch():
            e.var("ln_base", e.and_(e.add(p["pc"], 4), (1 << 64) - 4))
            s4 = lambda pos: signed(e, u4(e, e.add(g(e, "code"), pos)), 32)  # noqa: E731
            e.if_(e.eq(o, 0xAA), lambda: e.give(e.sub(e.add(e.add(p["ln_base"], 12), e.mul(e.add(e.sub(s4(e.add(p["ln_base"], 8)), s4(e.add(p["ln_base"], 4))), 1), 4)), p["pc"])))
            e.give(e.sub(e.add(e.add(p["ln_base"], 8), e.mul(s4(e.add(p["ln_base"], 4)), 8)), p["pc"]))

        e.if_(e.either(e.eq(o, 0xAA), e.eq(o, 0xAB)), switch)
        e.give(1)
    return _function(("pc",), build, tables)


def _switch_fn(tables):
    """``switch(pc)``: ``[default, n, (key, target)...]`` of the table- or lookupswitch at ``pc``."""
    def build(e: E):
        p = e.p
        s4 = lambda pos: signed(e, u4(e, e.add(g(e, "code"), pos)), 32)  # noqa: E731
        e.var("sw_base", e.and_(e.add(p["pc"], 4), (1 << 64) - 4))
        e.var("sw_table", e.flag(e.eq(u1(e, e.add(g(e, "code"), p["pc"])), 0xAA)))
        e.var("sw_n", 0)
        e.var("sw_low", 0)

        def table():
            e.set("sw_low", s4(e.add(p["sw_base"], 4)))
            e.set("sw_n", e.add(e.sub(s4(e.add(p["sw_base"], 8)), p["sw_low"]), 1))

        e.if_(e.ne(p["sw_table"], 0), table, lambda: e.set("sw_n", s4(e.add(p["sw_base"], 4))))
        _ok(e, e.le(p["sw_n"], 1 << 16))
        e.var("sw_h", e.alloc(e.add(e.mul(p["sw_n"], 2), 2)))
        _ok(e, e.ne(p["sw_h"], NONE))
        e.st(p["sw_h"], e.add(p["pc"], s4(p["sw_base"])))
        e.st(e.add(p["sw_h"], 1), p["sw_n"])

        def case():
            e.var("sw_c", e.add(p["sw_h"], e.add(2, e.mul(p["sw_k"], 2))))
            e.if_(e.ne(p["sw_table"], 0), lambda: (e.st(p["sw_c"], e.add(p["sw_low"], p["sw_k"])),
                                                   e.st(e.add(p["sw_c"], 1), e.add(p["pc"], s4(e.add(e.add(p["sw_base"], 12), e.mul(p["sw_k"], 4)))))),
                  lambda: (e.st(p["sw_c"], s4(e.add(e.add(p["sw_base"], 8), e.mul(p["sw_k"], 8)))),
                           e.st(e.add(p["sw_c"], 1), e.add(p["pc"], s4(e.add(e.add(p["sw_base"], 12), e.mul(p["sw_k"], 8)))))))

        e.for_("sw_k", 0, p["sw_n"], case)
        e.give(p["sw_h"])
    return _function(("pc",), build, tables)


def _dense_fn(tables):
    """1 when the switch's keys are consecutive."""
    def build(e: E):
        p = e.p
        e.if_(e.eq(at(e, p["sw"], 1), 0), lambda: e.give(0))
        e.for_("dn_k", 1, at(e, p["sw"], 1), lambda: e.if_(e.ne(at(e, p["sw"], e.add(2, e.mul(p["dn_k"], 2))), e.add(at(e, p["sw"], 2), p["dn_k"])),
                                                         lambda: e.give(0)))
        e.give(1)
    return _function(("sw",), build, tables)


def _instruction_fn(tables):  # noqa: C901 (one table of JVM instructions, as the bootstrap's)
    def build(e: E):
        p = e.p
        cb = lambda k: u1(e, e.add(e.add(g(e, "code"), p["pc"]), k))  # noqa: E731
        cu2 = lambda k: u2(e, e.add(e.add(g(e, "code"), p["pc"]), k))  # noqa: E731
        cs1 = lambda k: signed(e, cb(k), 8)  # noqa: E731
        cs2 = lambda k: signed(e, cu2(k), 16)  # noqa: E731
        cs4 = lambda k: signed(e, u4(e, e.add(e.add(g(e, "code"), p["pc"]), k)), 32)  # noqa: E731
        e.var("in_op", cb(0))
        o = p["in_op"]
        e.var("in_wide", e.flag(e.eq(o, 0xC4)))
        e.var("in_inner", e.sel(e.ne(p["in_wide"], 0), cb(1), o))
        inner = p["in_inner"]
        done = lambda: e.give(1)  # noqa: E731

        def when(condition, body):
            e.if_(condition, lambda: (body(), done()))

        between = lambda value, low, high: e.both(e.le(low, value), e.le(value, high))  # noqa: E731
        when(e.eq(o, 0x00), lambda: None)
        when(e.eq(o, 0x01), lambda: const(e, push(e, KA), 0, KI))
        when(between(o, 0x02, 0x08), lambda: const(e, push(e, KI), e.sub(o, 3), KI))
        when(between(o, 0x09, 0x0A), lambda: const(e, push(e, KJ), e.sub(o, 9), KJ))
        when(between(o, 0x0B, 0x0D), lambda: const(e, push(e, KF), e.sel(e.eq(o, 0x0B), 0, e.sel(e.eq(o, 0x0C), 0x3F800000, 0x40000000)), KF))
        when(between(o, 0x0E, 0x0F), lambda: const(e, push(e, KD), e.sel(e.eq(o, 0x0E), 0, 0x3FF0000000000000), KD))
        when(e.eq(o, 0x10), lambda: const(e, push(e, KI), cs1(1), KI))
        when(e.eq(o, 0x11), lambda: const(e, push(e, KI), cs2(1), KI))

        def ldc():
            e.var("ld_i", e.sel(e.eq(o, 0x12), cb(1), cu2(1)))
            e.var("ld_t", pool(e, p["ld_i"], 0))
            e.var("ld_kind", sel_kind_tag(e, p["ld_t"]))
            when(e.ne(p["ld_kind"], 0), lambda: const(e, push(e, p["ld_kind"]), pool(e, p["ld_i"], 1), p["ld_kind"]))
            when(e.eq(p["ld_t"], 8), lambda: x21c(e, 0x1A, push(e, KA, e.ld(K["String"])), KA, 1, utf8_entry(e, pool(e, p["ld_i"], 1)), 1))
            when(e.eq(p["ld_t"], 7), lambda: x21c(e, 0x1C, push(e, KA, e.ld(K["Class"])), KA, 2,
                                                  _call(e, "dj_classtype", utf8_entry(e, pool(e, p["ld_i"], 1))), 1))
            _ok(e, e.eq(0, 1))  # DEX-LDC-CONSTANT

        when(between(o, 0x12, 0x14), ldc)

        def load():
            e.var("lo_kind", 0)
            e.var("lo_index", 0)
            e.if_(e.ne(p["in_wide"], 0), lambda: (e.set("lo_kind", load_kind(e, e.sub(inner, 0x15))), e.set("lo_index", cu2(2))), lambda: e.if_(
                e.le(o, 0x19), lambda: (e.set("lo_kind", load_kind(e, e.sub(o, 0x15))), e.set("lo_index", cb(1))),
                lambda: (e.set("lo_kind", load_kind(e, e.udiv(e.sub(o, 0x1A), 4))), e.set("lo_index", e.urem(e.sub(o, 0x1A), 4)))))
            _ok(e, e.lt(p["lo_index"], e.add(g(e, "maxlocals"), LOCALS_EXTRA)))
            e.var("lo_desc", e.sel(e.eq(p["lo_kind"], KA), at(e, g(e, "locals"), p["lo_index"]), 0))
            move(e, push(e, p["lo_kind"], p["lo_desc"]), local(e, p["lo_index"]), p["lo_kind"])

        when(e.either(between(inner, 0x15, 0x19), between(o, 0x1A, 0x2D)), load)

        def store():
            e.var("so_index", e.sel(e.ne(p["in_wide"], 0), cu2(2), e.sel(e.le(o, 0x3A), cb(1), e.urem(e.sub(o, 0x3B), 4))))
            _ok(e, e.lt(p["so_index"], e.add(g(e, "maxlocals"), LOCALS_EXTRA)))
            pop(e, "so_r")
            e.st(e.add(g(e, "locals"), p["so_index"]), e.sel(e.eq(p["so_r_k"], KA), p["so_r_d"], kind_letter(e, p["so_r_k"])))
            move(e, local(e, p["so_index"]), p["so_r"], p["so_r_k"])

        when(e.either(between(inner, 0x36, 0x3A), between(o, 0x3B, 0x4E)), store)

        def array_load():
            pop(e, "al_i")
            pop(e, "al_a")
            e.var("al_e", _call(e, "dj_element", p["al_a_d"], e.sub(o, 0x2E)))
            e.var("al_kind", _call(e, "dj_kind", p["al_e"]))
            e.var("al_res", push(e, p["al_kind"], e.sel(e.eq(p["al_kind"], KA), p["al_e"], 0)))
            x23x(e, e.add(0x44, _call(e, "dj_variant", p["al_e"])), p["al_res"], p["al_kind"], p["al_a"], KA, p["al_i"], KI)

        when(between(o, 0x2E, 0x35), array_load)

        def array_store():
            pop(e, "as_v")
            pop(e, "as_i")
            pop(e, "as_a")
            e.var("as_e", _call(e, "dj_element", p["as_a_d"], e.sub(o, 0x4F)))
            x23x(e, e.add(0x4B, _call(e, "dj_variant", p["as_e"])), p["as_v"], p["as_v_k"], p["as_a"], KA, p["as_i"], KI, 0)

        when(between(o, 0x4F, 0x56), array_store)
        when(e.eq(o, 0x57), lambda: _call(e, "dj_pop"))
        when(e.eq(o, 0x58), lambda: (pop(e, "p2"), e.if_(e.eq(e.flag(wide(e, p["p2_k"])), 0), lambda: _call(e, "dj_pop"))))
        when(e.eq(o, 0x59), lambda: (pop(e, "dp"), push(e, p["dp_k"], p["dp_d"]), move(e, push(e, p["dp_k"], p["dp_d"]), p["dp"], p["dp_k"])))
        top_wide = lambda depth: wide(e, at(e, g(e, "stack"), e.mul(e.sub(g(e, "sn"), depth), 2)))  # noqa: E731

        def rearrange(take, order):
            e.var("rr_o", e.alloc(len(order) + 1))
            _ok(e, e.ne(p["rr_o"], NONE))
            for k, item in enumerate(order):
                e.st(e.add(p["rr_o"], k), item)
            _call(e, "dj_rearrange", take, p["rr_o"], len(order))

        when(e.eq(o, 0x5A), lambda: rearrange(2, (1, 0, 1)))
        when(e.eq(o, 0x5B), lambda: e.if_(top_wide(2), lambda: rearrange(2, (1, 0, 1)), lambda: rearrange(3, (2, 0, 1, 2))))
        when(e.eq(o, 0x5C), lambda: e.if_(top_wide(1), lambda: rearrange(1, (0, 0)), lambda: rearrange(2, (0, 1, 0, 1))))
        when(e.eq(o, 0x5D), lambda: e.if_(top_wide(1), lambda: rearrange(2, (1, 0, 1)), lambda: rearrange(3, (1, 2, 0, 1, 2))))
        when(e.eq(o, 0x5E), lambda: e.if_(top_wide(1), lambda: e.if_(top_wide(2), lambda: rearrange(2, (1, 0, 1)), lambda: rearrange(3, (2, 0, 1, 2))),
                                          lambda: e.if_(top_wide(3), lambda: rearrange(3, (1, 2, 0, 1, 2)), lambda: rearrange(4, (2, 3, 0, 1, 2, 3)))))
        when(e.eq(o, 0x5F), lambda: rearrange(2, (1, 0)))
        table = lambda name, index: at(e, TBL_AT, e.add(TABLE[name], index))  # noqa: E731

        def binary():
            e.var("bi_dex", table("binary_op", o))
            e.var("bi_kind", table("binary_kind", o))
            pop(e, "bi_b")
            pop(e, "bi_a")
            x23x(e, p["bi_dex"], push(e, p["bi_kind"]), p["bi_kind"], p["bi_a"], p["bi_a_k"], p["bi_b"], p["bi_b_k"])

        when(e.both(e.lt(o, 256), e.ne(table("binary_op", e.and_(o, 255)), 0)), binary)

        def unary():
            e.var("un_dex", table("unary_op", o))
            e.var("un_kind", table("unary_kind", o))
            pop(e, "un_a")
            x12x(e, p["un_dex"], push(e, p["un_kind"]), p["un_kind"], p["un_a"], p["un_a_k"])

        when(e.both(e.lt(o, 256), e.ne(table("unary_op", e.and_(o, 255)), 0)), unary)

        def iinc():
            e.var("ii_index", e.sel(e.ne(p["in_wide"], 0), cu2(2), cb(1)))
            e.var("ii_amount", e.sel(e.ne(p["in_wide"], 0), cs2(4), cs1(2)))
            e.var("ii_reg", local(e, p["ii_index"]))
            begin(e)
            e.var("ii_const", _call(e, "dj_scratch", KI))
            units(e, e.or_(e.mul(p["ii_const"], 256), 0x13), e.and_(p["ii_amount"], 0xFFFF))
            e.var("ii_src", src(e, p["ii_reg"], KI, 255))
            e.var("ii_dst", dst(e, p["ii_reg"], KI, 255))
            units(e, e.or_(e.mul(p["ii_dst"], 256), 0x90), e.or_(e.mul(p["ii_const"], 256), p["ii_src"]))
            end(e)

        when(e.eq(inner, 0x84), iinc)
        target2 = lambda: e.add(p["pc"], cs2(1))  # noqa: E731

        def if_zero():
            pop(e, "iz")
            e.var("iz_op", e.sel(e.eq(o, 0xC6), 0x38, e.sel(e.eq(o, 0xC7), 0x39, e.sub(e.add(0x38, o), 0x99))))
            _call(e, "dj_branch", p["iz_op"], 1, p["iz"], p["iz_k"], 0, 0, target2())

        when(e.either(between(o, 0x99, 0x9E), e.either(e.eq(o, 0xC6), e.eq(o, 0xC7))), if_zero)

        def if_compare():
            pop(e, "ic_b")
            pop(e, "ic_a")
            e.var("ic_op", e.sub(e.add(0x32, o), e.sel(e.le(o, 0xA4), 0x9F, 0xA5)))
            _call(e, "dj_branch", p["ic_op"], 2, p["ic_a"], p["ic_a_k"], p["ic_b"], p["ic_b_k"], target2())

        when(between(o, 0x9F, 0xA6), if_compare)
        when(e.eq(o, 0xA7), lambda: _call(e, "dj_goto", target2()))
        when(e.eq(o, 0xC8), lambda: _call(e, "dj_goto", e.add(p["pc"], cs4(1))))

        def switch():
            pop(e, "sw")
            e.var("sw_cases", _call(e, "dj_switch", p["pc"]))

            def cases():
                begin(e)
                e.var("sw_r", src(e, p["sw"], p["sw_k"], 255))
                e.var("sw_pa", e.add(g(e, "pay"), e.mul(g(e, "npay"), 3)))
                e.st(p["sw_pa"], g(e, "nunits"))
                e.st(e.add(p["sw_pa"], 1), e.add(g(e, "nunits"), 1))
                e.st(e.add(p["sw_pa"], 2), p["sw_cases"])
                sg(e, "npay", e.add(g(e, "npay"), 1))
                units(e, e.or_(e.mul(p["sw_r"], 256), e.sel(e.ne(_call(e, "dj_dense", p["sw_cases"]), 0), 0x2B, 0x2C)), 0, 0)

            e.if_(e.ne(at(e, p["sw_cases"], 1), 0), cases)
            _call(e, "dj_goto", e.ld(p["sw_cases"]))

        when(e.either(e.eq(o, 0xAA), e.eq(o, 0xAB)), switch)
        when(between(o, 0xAC, 0xB0), lambda: (pop(e, "rt"), x11x(e, RETURN(e, p["rt_k"]), p["rt"], p["rt_k"])))
        when(e.eq(o, 0xB1), lambda: unit(e, 0x0E))

        def field_access():
            e.var("fa_m", _call(e, "dj_member", cu2(1)))
            e.var("fa_ref", e.alloc(3))
            _ok(e, e.ne(p["fa_ref"], NONE))
            e.st(p["fa_ref"], _call(e, "dj_classtype", e.ld(p["fa_m"])))
            e.st(e.add(p["fa_ref"], 1), at(e, p["fa_m"], 1))
            e.st(e.add(p["fa_ref"], 2), _call(e, "dj_descriptor", at(e, p["fa_m"], 2)))
            e.var("fa_kind", _call(e, "dj_kind", at(e, p["fa_m"], 2)))
            e.var("fa_var", _call(e, "dj_variant", at(e, p["fa_m"], 2)))
            e.var("fa_held", e.sel(e.eq(p["fa_kind"], KA), at(e, p["fa_ref"], 2), 0))
            when(e.eq(o, 0xB2), lambda: x21c(e, e.add(0x60, p["fa_var"]), push(e, p["fa_kind"], p["fa_held"]), p["fa_kind"], 3, p["fa_ref"], 1))
            when(e.eq(o, 0xB3), lambda: (pop(e, "fp"), x21c(e, e.add(0x67, p["fa_var"]), p["fp"], p["fp_k"], 3, p["fa_ref"], 0)))
            when(e.eq(o, 0xB4), lambda: (pop(e, "fg"), x12x(e, e.add(0x52, p["fa_var"]), push(e, p["fa_kind"], p["fa_held"]), p["fa_kind"], p["fg"], KA, 3, p["fa_ref"])))
            pop(e, "fv")
            pop(e, "fi")
            x12x(e, e.add(0x59, p["fa_var"]), p["fv"], p["fv_k"], p["fi"], KA, 3, p["fa_ref"], 0)

        when(between(o, 0xB2, 0xB5), field_access)
        when(between(o, 0xB6, 0xB9), lambda: _call(e, "dj_invoke", o, cu2(1)))

        def new():
            e.var("nw_d", _call(e, "dj_poolclass", cu2(1)))
            x21c(e, 0x22, push(e, KA, p["nw_d"]), KA, 2, p["nw_d"], 1)

        when(e.eq(o, 0xBB), new)

        def new_array():
            e.var("na_d", 0)

            def primitive():
                e.var("na_t", cb(1))
                e.var("na_c", 0)
                for atype, char in ((4, "Z"), (5, "C"), (6, "F"), (7, "D"), (8, "B"), (9, "S"), (10, "I"), (11, "J")):
                    e.if_(e.eq(p["na_t"], atype), lambda char=char: e.set("na_c", ord(char)))
                _ok(e, e.ne(p["na_c"], 0))
                e.set("na_d", _call(e, "dj_concat", _call(e, "dj_single", ord("[")), _call(e, "dj_single", p["na_c"])))

            e.if_(e.eq(o, 0xBC), primitive, lambda: e.set("na_d", _call(e, "dj_concat", _call(e, "dj_single", ord("[")), _call(e, "dj_poolclass", cu2(1)))))
            pop(e, "ns")
            x12x(e, 0x23, push(e, KA, p["na_d"]), KA, p["ns"], KI, 2, p["na_d"])

        when(between(o, 0xBC, 0xBD), new_array)
        when(e.eq(o, 0xBE), lambda: (pop(e, "al"), x12x(e, 0x21, push(e, KI), KI, p["al"], KA)))
        when(e.eq(o, 0xBF), lambda: (pop(e, "th"), x11x(e, 0x27, p["th"], KA)))

        def checkcast():
            e.var("ck_t", _call(e, "dj_poolclass", cu2(1)))
            pop(e, "cc")
            push(e, KA, p["ck_t"])
            begin(e)
            e.var("cc_r", dst(e, p["cc"], KA, 255))
            e.if_(e.ne(p["cc_r"], p["cc"]), lambda: move(e, p["cc_r"], p["cc"], KA))
            unit(e, e.or_(e.mul(p["cc_r"], 256), 0x1F))
            unit(e, p["ck_t"], 2)
            end(e)

        when(e.eq(o, 0xC0), checkcast)
        when(e.eq(o, 0xC1), lambda: (e.var("io_t", _call(e, "dj_poolclass", cu2(1))), pop(e, "io"),
                                     x12x(e, 0x20, push(e, KI), KI, p["io"], KA, 2, p["io_t"])))
        when(e.either(e.eq(o, 0xC2), e.eq(o, 0xC3)), lambda: (pop(e, "mo"), x11x(e, e.sel(e.eq(o, 0xC2), 0x1D, 0x1E), p["mo"], KA)))
        e.give(NONE)  # DEX-UNSUPPORTED-INSTRUCTION
    return _function(("pc",), build, tables)


def load_kind(e: E, index):
    return e.sel(e.eq(index, 0), KI, e.sel(e.eq(index, 1), KJ, e.sel(e.eq(index, 2), KF, e.sel(e.eq(index, 3), KD, KA))))


def kind_letter(e: E, kind):
    return e.sel(e.eq(kind, KI), e.ld(K["I"]), e.sel(e.eq(kind, KF), e.ld(K["F"]), e.sel(e.eq(kind, KJ), e.ld(K["J"]), e.ld(K["D"]))))


def sel_kind_tag(e: E, tag):
    """The value kind of an int, float, long or double pool tag (0 for another)."""
    return e.sel(e.eq(tag, 3), KI, e.sel(e.eq(tag, 4), KF, e.sel(e.eq(tag, 5), KJ, e.sel(e.eq(tag, 6), KD, 0))))


# -- one method ---------------------------------------------------------------------------------------------------------------

def _translate_fn(tables):
    """``translate(scratch, long)``: one pass over the current method (its units, ``used``, ``outs``; ``retry`` where
    a scratch register or a 16-bit branch did not fit)."""
    def build(e: E):
        p = e.p
        cb = lambda pc, k: u1(e, e.add(e.add(g(e, "code"), pc), k))  # noqa: E731
        sg(e, "scratch", p["scratch"])
        sg(e, "long", p["long"])
        sg(e, "freebase", e.add(p["scratch"], g(e, "maxstack")))
        sg(e, "parambase", e.sub(e.add(g(e, "freebase"), g(e, "maxlocals")), g(e, "ins")))
        sg(e, "registers", e.add(e.add(p["scratch"], g(e, "maxstack")), g(e, "maxlocals")))
        for name in ("nunits", "nfix", "npay", "outs", "used", "next", "retry", "nafter", "sn", "sdepth", "npcs"):
            sg(e, name, 0)
        sg(e, "ucap", e.add(e.mul(g(e, "clen"), 16), 64))
        for name, words in (("units", e.mul(g(e, "ucap"), 2)), ("labels", e.add(g(e, "clen"), 1)), ("fix", e.mul(e.add(g(e, "clen"), 1), 4)),
                            ("pay", e.mul(e.add(g(e, "clen"), 1), 3)), ("after", 32), ("stack", e.add(e.mul(g(e, "maxstack"), 2), 4)),
                            ("pcs", e.add(g(e, "clen"), 1)), ("targets", e.add(g(e, "clen"), 1))):
            e.var("tr_h", e.alloc(words))
            _ok(e, e.ne(p["tr_h"], NONE))
            sg(e, name, p["tr_h"])
        e.for_("tr_k", 0, e.add(g(e, "clen"), 1), lambda: (e.st(e.add(g(e, "labels"), p["tr_k"]), NONE), e.st(e.add(g(e, "targets"), p["tr_k"]), 0)))
        sg(e, "locals", _call(e, "dj_copylocals", g(e, "initial")))

        def mark(target):
            e.var("tr_t", target)
            e.if_(e.lt(p["tr_t"], g(e, "clen")), lambda: e.st(e.add(g(e, "targets"), p["tr_t"]), 1))

        # The instructions and the branch targets.
        e.var("tr_pc", 0)

        def scan():
            e.st(e.add(g(e, "pcs"), g(e, "npcs")), p["tr_pc"])
            sg(e, "npcs", e.add(g(e, "npcs"), 1))
            e.var("tr_op", cb(p["tr_pc"], 0))
            o = p["tr_op"]
            e.if_(e.either(e.both(e.le(0x99, o), e.le(o, 0xA7)), e.either(e.eq(o, 0xC6), e.eq(o, 0xC7))),
                  lambda: mark(e.add(p["tr_pc"], signed(e, u2(e, e.add(e.add(g(e, "code"), p["tr_pc"]), 1)), 16))))
            e.if_(e.eq(o, 0xC8), lambda: mark(e.add(p["tr_pc"], signed(e, u4(e, e.add(e.add(g(e, "code"), p["tr_pc"]), 1)), 32))))

            def switch():
                e.var("tr_sw", _call(e, "dj_switch", p["tr_pc"]))
                mark(e.ld(p["tr_sw"]))
                e.for_("tr_c", 0, at(e, p["tr_sw"], 1), lambda: mark(at(e, p["tr_sw"], e.add(3, e.mul(p["tr_c"], 2)))))

            e.if_(e.either(e.eq(o, 0xAA), e.eq(o, 0xAB)), switch)
            _ok(e, e.both(e.ne(o, 0xA8), e.both(e.ne(o, 0xA9), e.ne(o, 0xBA))))  # DEX-UNSUPPORTED-INSTRUCTION
            e.set("tr_pc", e.add(p["tr_pc"], _call(e, "dj_length", p["tr_pc"])))

        e.while_(lambda: e.lt(p["tr_pc"], g(e, "clen")), scan)

        # The instructions lowered in order (code no branch reaches is never lowered).
        e.var("tr_reach", 1)

        def each():
            e.var("tr_at", at(e, g(e, "pcs"), p["tr_k"]))

            def target():
                _ok(e, e.either(e.eq(p["tr_reach"], 0), e.eq(g(e, "sn"), 0)))  # DEX-STACK-AT-TARGET
                sg(e, "sn", 0)
                sg(e, "sdepth", 0)
                e.set("tr_reach", 1)
                e.var("tr_frame", at(e, g(e, "frames"), p["tr_at"]))
                e.if_(e.ne(p["tr_frame"], 0), lambda: sg(e, "locals", _call(e, "dj_copylocals", p["tr_frame"])))

            e.if_(e.ne(at(e, g(e, "targets"), p["tr_at"]), 0), target)
            e.st(e.add(g(e, "labels"), p["tr_at"]), g(e, "nunits"))

            def lower():
                _call(e, "dj_instruction", p["tr_at"])
                e.if_(e.ne(g(e, "retry"), 0), lambda: e.give(1))
                e.set("tr_reach", e.flag(e.eq(at(e, TBL_AT, e.add(TABLE["nofall"], cb(p["tr_at"], 0))), 0)))

            e.if_(e.ne(p["tr_reach"], 0), lower)

        e.for_("tr_k", 0, g(e, "npcs"), each)
        e.give(_call(e, "dj_finish"))
    return _function(("scratch", "long"), build, tables)


def label(e: E, target):
    """The first unit of the instruction at ``target`` (declines where none is)."""
    _ok(e, e.lt(target, g(e, "clen")))
    e.var("lb_v", at(e, g(e, "labels"), target))
    _ok(e, e.ne(e.p["lb_v"], NONE))
    return e.p["lb_v"]


def set_unit(e: E, index, value):
    e.st(e.add(e.add(g(e, "units"), e.mul(index, 2)), 1), value)


def _finish_fn(tables):
    """``finish()``: the branch offsets and the switch payloads (``retry`` where a 16-bit offset does not fit)."""
    def build(e: E):
        p = e.p

        def fixup():
            e.var("fn_f", e.add(g(e, "fix"), e.mul(p["fn_k"], 4)))
            e.var("fn_start", e.ld(p["fn_f"]))
            e.var("fn_field", at(e, p["fn_f"], 1))
            e.var("fn_delta", e.sub(label(e, at(e, p["fn_f"], 2)), p["fn_start"]))

            def short():
                e.if_(e.le(0x10000, e.add(p["fn_delta"], 0x8000)), lambda: (sg(e, "retry", 1), e.give(1)))
                set_unit(e, p["fn_field"], e.and_(p["fn_delta"], 0xFFFF))

            e.if_(e.eq(at(e, p["fn_f"], 3), 16), short, lambda: (set_unit(e, p["fn_field"], e.and_(p["fn_delta"], 0xFFFF)),
                                                                   set_unit(e, e.add(p["fn_field"], 1), e.and_(e.udiv(p["fn_delta"], 65536), 0xFFFF))))

        e.for_("fn_k", 0, g(e, "nfix"), fixup)

        def payload():
            e.var("fp_a", e.add(g(e, "pay"), e.mul(p["fp_k"], 3)))
            e.var("fp_start", e.ld(p["fp_a"]))
            e.var("fp_field", at(e, p["fp_a"], 1))
            e.var("fp_sw", at(e, p["fp_a"], 2))
            e.var("fp_n", at(e, p["fp_sw"], 1))
            e.if_(e.ne(e.urem(g(e, "nunits"), 2), 0), lambda: unit(e, 0))  # nop: a payload starts 4-byte aligned
            e.var("fp_delta", e.sub(g(e, "nunits"), p["fp_start"]))
            set_unit(e, p["fp_field"], e.and_(p["fp_delta"], 0xFFFF))
            set_unit(e, e.add(p["fp_field"], 1), e.and_(e.udiv(p["fp_delta"], 65536), 0xFFFF))
            key = lambda k: at(e, p["fp_sw"], e.add(2, e.mul(k, 2)))  # noqa: E731

            def dense():
                units(e, 0x0100, p["fp_n"], e.and_(key(0), 0xFFFF), e.and_(e.udiv(key(0), 65536), 0xFFFF))

            def sparse():
                units(e, 0x0200, p["fp_n"])
                e.for_("fp_c", 0, p["fp_n"], lambda: units(e, e.and_(key(p["fp_c"]), 0xFFFF), e.and_(e.udiv(key(p["fp_c"]), 65536), 0xFFFF)))

            e.if_(e.ne(_call(e, "dj_dense", p["fp_sw"]), 0), dense, sparse)

            def target():
                e.var("fp_d", e.sub(label(e, at(e, p["fp_sw"], e.add(3, e.mul(p["fp_c"], 2)))), p["fp_start"]))
                units(e, e.and_(p["fp_d"], 0xFFFF), e.and_(e.udiv(p["fp_d"], 65536), 0xFFFF))

            e.for_("fp_c", 0, p["fp_n"], target)

        e.for_("fp_k", 0, g(e, "npay"), payload)
        e.give(1)
    return _function((), build, tables)


# -- input and output ---------------------------------------------------------------------------------------------------------

def _word_fn(tables):
    def build(e: E):
        e.var("wd_at", g(e, "cur"))
        sg(e, "cur", e.add(e.p["wd_at"], 1))
        e.give(e.rd(e.p["wd_at"]))
    return _function((), build, tables)


def _text_fn(tables):
    """``text()``: a string read from the input."""
    def build(e: E):
        p = e.p
        e.var("tx_n", _call(e, "dj_word"))
        _ok(e, e.lt(p["tx_n"], 1 << 24))
        e.var("tx_h", e.alloc(e.add(p["tx_n"], 1)))
        _ok(e, e.ne(p["tx_h"], NONE))
        e.st(p["tx_h"], p["tx_n"])
        e.for_("tx_k", 1, e.add(p["tx_n"], 1), lambda: e.st(e.add(p["tx_h"], p["tx_k"]), _call(e, "dj_word")))
        e.give(p["tx_h"])
    return _function((), build, tables)


def _emit_fn(tables):
    def build(e: E):
        e.var("em_n", g(e, "nout"))
        _ok(e, e.lt(e.add(OUT_AT + 1, e.p["em_n"]), OUT_END))
        e.st(e.add(OUT_AT + 1, e.p["em_n"]), e.p["value"])
        sg(e, "nout", e.add(e.p["em_n"], 1))
        e.give(1)
    return _function(("value",), build, tables)


def emit(e: E, value):
    _call(e, "dj_emit", value)


def _emit_text_fn(tables):
    def build(e: E):
        p = e.p
        emit(e, e.ld(p["h"]))
        e.for_("et_k", 1, e.add(e.ld(p["h"]), 1), lambda: emit(e, at(e, p["h"], p["et_k"])))
        e.give(1)
    return _function(("h",), build, tables)


def emit_text(e: E, h):
    _call(e, "dj_emittext", h)


def skip_attributes(e: E, pos: str):
    """Skips the attribute table at the variable ``pos``."""
    p = e.p
    e.var(f"{pos}_na", u2(e, p[pos]))
    e.set(pos, e.add(p[pos], 2))

    def one():
        utf8_entry(e, u2(e, p[pos]))
        e.set(pos, e.add(e.add(p[pos], 6), u4(e, e.add(p[pos], 2))))
        _ok(e, e.le(p[pos], g(e, "bn")))  # DEX-CLASSFILE-TRUNCATED

    e.for_(f"{pos}_k", 0, p[f"{pos}_na"], one)


def _method_fn(tables):
    """``method(record)``: one method (``[flags, name, descriptor, code position or NONE, code length]``) lowered and
    written out."""
    def build(e: E):
        p = e.p
        e.var("me_flags", e.ld(p["record"]))
        e.var("me_name", at(e, p["record"], 1))
        e.var("me_ps", _call(e, "dj_parameters", at(e, p["record"], 2)))
        e.var("me_np", e.sub(e.ld(p["me_ps"]), 1))
        emit_text(e, p["me_name"])
        emit_text(e, _call(e, "dj_descriptor", at(e, p["me_ps"], e.ld(p["me_ps"]))))
        emit(e, p["me_np"])
        e.for_("me_k", 1, e.add(p["me_np"], 1), lambda: emit_text(e, _call(e, "dj_descriptor", at(e, p["me_ps"], p["me_k"]))))
        e.var("me_access", e.and_(p["me_flags"], 0x1DDF))
        e.if_(e.both(e.ne(e.and_(p["me_flags"], 0x0020), 0), e.eq(e.and_(p["me_flags"], 0x0100), 0)), lambda: e.set("me_access", e.or_(p["me_access"], 0x20000)))
        e.if_(e.either(e.ne(_call(e, "dj_same", p["me_name"], e.ld(K["init"])), 0), e.ne(_call(e, "dj_same", p["me_name"], e.ld(K["clinit"])), 0)),
              lambda: e.set("me_access", e.or_(p["me_access"], ACC_CONSTRUCTOR)))
        emit(e, p["me_access"])
        e.var("me_code", at(e, p["record"], 3))
        e.if_(e.either(e.eq(p["me_code"], NONE), e.eq(at(e, p["record"], 4), 0)), lambda: (emit(e, 0), e.give(1)))

        # The Code attribute: max_stack, max_locals, the code, no exception handlers, the StackMapTable.
        e.var("mc", p["me_code"])
        sg(e, "maxstack", u2(e, p["mc"]))
        sg(e, "maxlocals", u2(e, e.add(p["mc"], 2)))
        sg(e, "clen", u4(e, e.add(p["mc"], 4)))
        sg(e, "code", e.add(p["mc"], 8))
        e.var("mc_at", e.add(e.add(p["mc"], 8), g(e, "clen")))
        _ok(e, e.le(e.add(p["mc_at"], 4), g(e, "bn")))
        _ok(e, e.eq(u2(e, p["mc_at"]), 0))  # DEX-EXCEPTION-TABLE
        e.set("mc_at", e.add(p["mc_at"], 2))
        e.var("me_static", e.flag(e.ne(e.and_(p["me_flags"], ACC_STATIC), 0)))
        e.var("me_items", e.alloc(e.add(p["me_np"], 2)))
        _ok(e, e.ne(p["me_items"], NONE))
        e.var("me_n", 0)
        e.if_(e.eq(p["me_static"], 0), lambda: (e.st(p["me_items"], _call(e, "dj_descof", g(e, "this"))), e.set("me_n", 1)))
        sg(e, "ins", e.sub(1, p["me_static"]))

        def parameter():
            e.var("me_p", at(e, p["me_ps"], p["me_k"]))
            e.st(e.add(p["me_items"], p["me_n"]), p["me_p"])
            e.set("me_n", e.add(p["me_n"], 1))
            sg(e, "ins", e.add(g(e, "ins"), size(e, _call(e, "dj_kind", p["me_p"]))))

        e.for_("me_k", 1, e.add(p["me_np"], 1), parameter)
        sg(e, "initial", _call(e, "dj_place", p["me_items"], p["me_n"]))
        e.var("me_frames", e.alloc(e.add(g(e, "clen"), 1)))
        _ok(e, e.ne(p["me_frames"], NONE))
        e.for_("me_k", 0, e.add(g(e, "clen"), 1), lambda: e.st(e.add(p["me_frames"], p["me_k"]), 0))
        sg(e, "frames", p["me_frames"])

        def attribute():
            e.var("ma_name", u2(e, e.add(p["mc_at"], 2)))
            e.var("ma_size", u4(e, e.add(p["mc_at"], 4)))
            _ok(e, e.lt(p["ma_name"], g(e, "npool")))

            def stack_map():
                e.var("ma_frames", e.alloc(e.add(g(e, "clen"), 1)))
                _ok(e, e.ne(p["ma_frames"], NONE))
                e.for_("ma_k", 0, e.add(g(e, "clen"), 1), lambda: e.st(e.add(p["ma_frames"], p["ma_k"]), 0))
                sg(e, "frames", p["ma_frames"])
                _call(e, "dj_stack_map", e.add(p["mc_at"], 8), g(e, "initial"))

            e.if_(e.eq(pool(e, p["ma_name"], 0), 1), lambda: e.if_(e.ne(_call(e, "dj_same", pool(e, p["ma_name"], 1), e.ld(K["StackMapTable"])), 0), stack_map))
            e.set("mc_at", e.add(e.add(p["mc_at"], 6), p["ma_size"]))

        e.for_("me_k", 0, u2(e, p["mc_at"]), attribute)

        # Six scratch registers, then long branches, then exactly the scratch registers the pass used.
        _call(e, "dj_translate", SCRATCH, 0)
        e.if_(e.ne(g(e, "retry"), 0), lambda: _call(e, "dj_translate", SCRATCH, 1))
        _ok(e, e.eq(g(e, "retry"), 0))
        _call(e, "dj_translate", g(e, "used"), g(e, "long"))
        _ok(e, e.eq(g(e, "retry"), 0))
        for value in (1, g(e, "registers"), g(e, "ins"), g(e, "outs"), g(e, "nunits")):
            emit(e, value)

        def each():
            e.var("mu_kind", at(e, g(e, "units"), e.mul(p["me_k"], 2)))
            e.var("mu_v", at(e, g(e, "units"), e.add(e.mul(p["me_k"], 2), 1)))
            emit(e, p["mu_kind"])

            def method_reference():
                for k in range(3):
                    emit_text(e, at(e, p["mu_v"], k))
                e.var("mu_ps", at(e, p["mu_v"], 3))
                emit(e, e.ld(p["mu_ps"]))
                e.for_("mu_j", 1, e.add(e.ld(p["mu_ps"]), 1), lambda: emit_text(e, at(e, p["mu_ps"], p["mu_j"])))

            e.if_(e.eq(p["mu_kind"], 0), lambda: emit(e, p["mu_v"]), lambda: e.if_(
                e.either(e.eq(p["mu_kind"], 1), e.eq(p["mu_kind"], 2)), lambda: emit_text(e, p["mu_v"]), lambda: e.if_(
                    e.eq(p["mu_kind"], 3), lambda: [emit_text(e, at(e, p["mu_v"], k)) for k in range(3)], method_reference)))

        e.for_("me_k", 0, g(e, "nunits"), each)
        e.give(1)
    return _function(("record",), build, tables)


def _frontend(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        for name in G:
            sg(e, name, 0)
        for name, text in CONSTANT_TEXTS.items():
            e.var("fe_h", e.alloc(len(text) + 1))
            _ok(e, e.ne(p["fe_h"], NONE))
            e.st(p["fe_h"], len(text))
            for k, char in enumerate(text):
                e.st(e.add(p["fe_h"], k + 1), ord(char))
            e.st(K[name], p["fe_h"])
        e.for_("fe_k", 0, 1536, lambda: e.st(e.add(TBL_AT, p["fe_k"]), 0))
        for name, values in _tables().items():
            for index, value in sorted(values.items()):
                e.st(TBL_AT + TABLE[name] + index, value)

        # The class file, one byte to a word; the renames.
        word = lambda: _call(e, "dj_word")  # noqa: E731
        e.var("fe_len", word())
        _ok(e, e.lt(p["fe_len"], 1 << 26))
        e.var("fe_ba", e.alloc(e.add(p["fe_len"], 8)))
        _ok(e, e.ne(p["fe_ba"], NONE))
        sg(e, "ba", p["fe_ba"])
        sg(e, "bn", p["fe_len"])

        def unpack():
            e.var("fe_w", word())
            for k in range(8):
                e.st(e.add(p["fe_ba"], e.add(e.mul(p["fe_q"], 8), k)), e.and_(p["fe_w"], 255))
                e.set("fe_w", e.udiv(p["fe_w"], 256))

        e.for_("fe_q", 0, e.udiv(e.add(p["fe_len"], 7), 8), unpack)
        e.var("fe_nr", word())
        _ok(e, e.lt(p["fe_nr"], 1 << 20))
        e.var("fe_rn", e.alloc(e.add(e.mul(p["fe_nr"], 2), 1)))
        _ok(e, e.ne(p["fe_rn"], NONE))
        e.st(p["fe_rn"], p["fe_nr"])
        e.for_("fe_k", 0, e.mul(p["fe_nr"], 2), lambda: e.st(e.add(e.add(p["fe_rn"], 1), p["fe_k"]), _call(e, "dj_text")))
        sg(e, "renames", p["fe_rn"])

        # The constant pool: [tag, a, b] per entry (a UTF-8 entry's text in a; a long or double's 64 bits in a).
        _ok(e, e.eq(u4(e, 0), 0xCAFEBABE))  # DEX-CLASSFILE-MAGIC
        e.var("fe_count", u2(e, 8))
        e.var("fe_pool", e.alloc(e.add(e.mul(p["fe_count"], 3), 3)))
        _ok(e, e.ne(p["fe_pool"], NONE))
        e.for_("fe_k", 0, e.add(e.mul(p["fe_count"], 3), 3), lambda: e.st(e.add(p["fe_pool"], p["fe_k"]), 0))
        sg(e, "pool", p["fe_pool"])
        sg(e, "npool", p["fe_count"])
        e.var("pos", 10)
        e.var("fe_i", 1)

        def entry():
            e.var("fe_tag", u1(e, p["pos"]))
            e.set("pos", e.add(p["pos"], 1))
            e.var("fe_e", e.add(p["fe_pool"], e.mul(p["fe_i"], 3)))
            e.st(p["fe_e"], p["fe_tag"])
            t = p["fe_tag"]

            def utf8():
                e.var("fe_n", u2(e, p["pos"]))
                e.st(e.add(p["fe_e"], 1), _call(e, "dj_utf8", e.add(p["pos"], 2), p["fe_n"]))
                e.set("pos", e.add(e.add(p["pos"], 2), p["fe_n"]))

            def wide_value():
                e.st(e.add(p["fe_e"], 1), e.add(e.mul(u4(e, p["pos"]), 1 << 32), u4(e, e.add(p["pos"], 4))))
                e.set("pos", e.add(p["pos"], 8))
                e.set("fe_i", e.add(p["fe_i"], 1))

            def pair():
                e.st(e.add(p["fe_e"], 1), u2(e, p["pos"]))
                e.st(e.add(p["fe_e"], 2), u2(e, e.add(p["pos"], 2)))
                e.set("pos", e.add(p["pos"], 4))

            e.if_(e.eq(t, 1), utf8, lambda: e.if_(
                e.either(e.eq(t, 3), e.eq(t, 4)), lambda: (e.st(e.add(p["fe_e"], 1), u4(e, p["pos"])), e.set("pos", e.add(p["pos"], 4))), lambda: e.if_(
                    e.either(e.eq(t, 5), e.eq(t, 6)), wide_value, lambda: e.if_(
                        e.either(e.eq(t, 7), e.eq(t, 8)), lambda: (e.st(e.add(p["fe_e"], 1), u2(e, p["pos"])), e.set("pos", e.add(p["pos"], 2))), lambda: e.if_(
                            e.both(e.le(9, t), e.le(t, 12)), pair, lambda: _ok(e, e.eq(0, 1)))))))  # DEX-CLASSFILE-POOL-TAG
            e.set("fe_i", e.add(p["fe_i"], 1))

        e.while_(lambda: e.lt(p["fe_i"], p["fe_count"]), entry)
        klass = lambda index: utf8_entry(e, pool(e, index, 1))  # noqa: E731

        # The class, its superclass and interfaces.
        e.var("fe_access", u2(e, p["pos"]))
        sg(e, "this", klass(u2(e, e.add(p["pos"], 2))))
        e.var("fe_super", u2(e, e.add(p["pos"], 4)))
        e.var("fe_ni", u2(e, e.add(p["pos"], 6)))
        e.set("pos", e.add(p["pos"], 8))
        emit_text(e, _call(e, "dj_classtype", g(e, "this")))
        emit(e, e.and_(p["fe_access"], 0xFFDF))
        e.if_(e.ne(p["fe_super"], 0), lambda: (emit(e, 1), emit_text(e, _call(e, "dj_classtype", klass(p["fe_super"])))), lambda: emit(e, 0))
        emit(e, p["fe_ni"])
        e.for_("fe_k", 0, p["fe_ni"], lambda: (emit_text(e, _call(e, "dj_classtype", klass(u2(e, p["pos"])))), e.set("pos", e.add(p["pos"], 2))))

        # The fields.
        e.var("fe_nf", u2(e, p["pos"]))
        e.set("pos", e.add(p["pos"], 2))
        emit(e, p["fe_nf"])

        def field():
            e.var("fe_fa", u2(e, p["pos"]))
            emit_text(e, utf8_entry(e, u2(e, e.add(p["pos"], 2))))
            emit_text(e, _call(e, "dj_descriptor", utf8_entry(e, u2(e, e.add(p["pos"], 4)))))
            emit(e, e.and_(p["fe_fa"], 0x50DF))
            e.set("pos", e.add(p["pos"], 6))
            skip_attributes(e, "pos")

        e.for_("fe_k", 0, p["fe_nf"], field)

        # The methods: their records first (the last Code attribute of each), then each lowered.
        e.var("fe_nm", u2(e, p["pos"]))
        e.set("pos", e.add(p["pos"], 2))
        e.var("fe_ms", e.alloc(e.add(e.mul(p["fe_nm"], 5), 1)))
        _ok(e, e.ne(p["fe_ms"], NONE))

        def method():
            e.var("fe_m", e.add(p["fe_ms"], e.mul(p["fe_k"], 5)))
            e.st(p["fe_m"], u2(e, p["pos"]))
            e.st(e.add(p["fe_m"], 1), utf8_entry(e, u2(e, e.add(p["pos"], 2))))
            e.st(e.add(p["fe_m"], 2), utf8_entry(e, u2(e, e.add(p["pos"], 4))))
            e.st(e.add(p["fe_m"], 3), NONE)
            e.st(e.add(p["fe_m"], 4), 0)
            e.set("pos", e.add(p["pos"], 6))
            e.var("fe_na", u2(e, p["pos"]))
            e.set("pos", e.add(p["pos"], 2))

            def attribute():
                e.var("fe_an", utf8_entry(e, u2(e, p["pos"])))
                e.var("fe_al", u4(e, e.add(p["pos"], 2)))
                _ok(e, e.le(e.add(e.add(p["pos"], 6), p["fe_al"]), g(e, "bn")))  # DEX-CLASSFILE-TRUNCATED

                def code():
                    _ok(e, e.le(8, p["fe_al"]))
                    e.st(e.add(p["fe_m"], 3), e.add(p["pos"], 6))
                    e.st(e.add(p["fe_m"], 4), u4(e, e.add(p["pos"], 10)))

                e.if_(e.ne(_call(e, "dj_same", p["fe_an"], e.ld(K["Code"])), 0), code)
                e.set("pos", e.add(e.add(p["pos"], 6), p["fe_al"]))

            e.for_("fe_j", 0, p["fe_na"], attribute)

        e.for_("fe_k", 0, p["fe_nm"], method)
        skip_attributes(e, "pos")
        emit(e, p["fe_nm"])
        e.for_("fe_k", 0, p["fe_nm"], lambda: _call(e, "dj_method", e.add(p["fe_ms"], e.mul(p["fe_k"], 5))))
        e.st(OUT_AT, g(e, "nout"))
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


BUILDERS = (
    ("dj_byte", _byte_fn), ("dj_utf8", _utf8_fn), ("dj_same", _same_fn), ("dj_concat", _concat_fn), ("dj_slice", _slice_fn), ("dj_single", _single_fn),
    ("dj_rename", _rename_fn), ("dj_descriptor", _descriptor_fn), ("dj_classtype", _class_type_fn), ("dj_descof", _descriptor_of_fn),
    ("dj_parameters", _parameters_fn), ("dj_kind", _kind_fn), ("dj_variant", _variant_fn), ("dj_unit", _unit_fn), ("dj_move", _move_fn),
    ("dj_scratch", _scratch_fn), ("dj_src", _src_fn), ("dj_dst", _dst_fn), ("dj_end", _end_fn), ("dj_push", _push_fn), ("dj_pop", _pop_fn),
    ("dj_local", _local_fn), ("dj_const", _const_fn), ("dj_x21c", _x21c_fn), ("dj_x11x", _x11x_fn), ("dj_x12x", _x12x_fn), ("dj_x23x", _x23x_fn),
    ("dj_fixup", _fixup_fn), ("dj_goto", _goto_fn), ("dj_branch", _branch_fn), ("dj_member", _member_fn), ("dj_poolclass", _pool_class_fn),
    ("dj_place", _place_fn), ("dj_ordered", _ordered_fn), ("dj_copylocals", _copy_locals_fn), ("dj_verification", _verification_fn),
    ("dj_stack_map", _stack_map_fn), ("dj_rearrange", _rearrange_fn), ("dj_invoke", _invoke_fn), ("dj_element", _element_fn),
    ("dj_length", _length_fn), ("dj_switch", _switch_fn), ("dj_dense", _dense_fn), ("dj_instruction", _instruction_fn), ("dj_finish", _finish_fn),
    ("dj_translate", _translate_fn), ("dj_word", _word_fn), ("dj_text", _text_fn), ("dj_emit", _emit_fn), ("dj_emittext", _emit_text_fn),
    ("dj_method", _method_fn),
)


def build_dex_jvm_program():
    """``(reader, function)``: the JVM-to-DEX class lowering program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in BUILDERS:
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_dex_jvm_program, "dex-jvm")
load_dex_jvm_program = _PROGRAM.load
write_dex_jvm_store = _PROGRAM.write
OPT_OUT = "XAX_DEX_JVM_PYTHON"


def _utf16(value: str) -> list[int]:
    import xax_dex as D

    units = D._utf16_units(value)
    return [len(units), *units]


def translate_class_with_xax(data: bytes, rename=None, *, required: bool = False):
    """The ``xax_dex_jvm.DexClassDef`` the XAX program lowers ``data`` to, or None where it cannot run or declines
    (unless ``required``)."""
    import os
    import struct

    import xax_dex_jvm as D
    import xax_native

    words = [len(data), *(int.from_bytes(data[k:k + 8].ljust(8, b"\0"), "little") for k in range(0, len(data), 8))]
    renames = dict(rename or {})
    words.append(len(renames))
    for name, replacement in renames.items():
        words += [*_utf16(name), *_utf16(replacement)]
    if any(not 0 <= word < 1 << 64 for word in words):
        return None
    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    result = None
    if native is not None:
        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None
            (count,) = read(OUT_AT, 1)
            return read(OUT_AT + 1, count) if count else []

        out = native.run(words, collect)
        if out is not None:
            result = _decode(list(out), D, struct)
        else:
            xax_native.declined("dex-jvm", 1)
    if result is None and required:
        raise RuntimeError("the XAX JVM-to-DEX lowering program is unavailable or declined")
    return result


def _decode(out: list[int], D, struct):
    position = 0

    def word() -> int:
        nonlocal position
        position += 1
        return out[position - 1]

    def text() -> str:
        n = word()
        units = [word() for _ in range(n)]
        return struct.pack(f"<{n}H", *units).decode("utf-16-le", "surrogatepass")

    descriptor, access = text(), word()
    superclass = text() if word() else None
    interfaces = tuple(text() for _ in range(word()))
    fields = tuple(D.DexFieldDef(text(), text(), word()) for _ in range(word()))
    methods = []
    for _ in range(word()):
        name, returns = text(), text()
        parameters = tuple(text() for _ in range(word()))
        method_access, code = word(), None
        if word():
            registers, ins, outs, count = word(), word(), word(), word()
            units = []
            for _ in range(count):
                kind = word()
                if kind == 0:
                    units.append(word())
                elif kind in (1, 2):
                    units.append(("string" if kind == 1 else "type", text()))
                elif kind == 3:
                    units.append(("field", (text(), text(), text())))
                else:
                    owner, member, result = text(), text(), text()
                    units.append(("method", (owner, member, result, tuple(text() for _ in range(word())))))
            code = D.DexCode(registers, ins, outs, tuple(units))
        methods.append(D.DexMethodDef(name, returns, parameters, method_access, code))
    if position != len(out):
        return None
    return D.DexClassDef(descriptor, access, superclass, interfaces, fields, tuple(methods))
