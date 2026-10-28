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

from xax_compiler import x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_dex import (CAP, CODES, FIELDS, G_CAP, G_CUR, G_F, G_L, G_LO, G_M, G_NC, G_NF, G_NL, G_NM, G_NP, G_NS, G_NT, G_ON, G_OUT, G_P,
                              G_S, G_T, HELPERS, LISTS, METHODS, P_N, P_RANK, P_RET, P_SHORTY, PROTOS, STRINGS, TYPES, align, at, b, fidx, midx,
                              push, sidx, tidx, u16, u32, uleb)
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_general_image import IMAGE_AT, IMAGE_END
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_dex_writer.xax"
OUT = IMAGE_AT + 3
ACC_PRIVATE, ACC_STATIC, ACC_CONSTRUCTOR = 0x0002, 0x0008, 0x10000
# A class record: descriptor, access, superclass (0: none), interfaces [n, types...], field count, fields, method count,
# methods, class data offset.  A field: name, type, access.  A method: name, prototype, access, code (0: none), code
# offset.  A code: registers, ins, outs, unit count, units (kind, value or reference record).
CLASS_WORDS, FIELD_WORDS, METHOD_WORDS = 9, 3, 5


def _frontend(tables):
    def build(e: E):
        p = e.p
        word = lambda: _call(e, "dx_word")  # noqa: E731
        string = lambda: _call(e, "dx_string")  # noqa: E731
        proto = lambda: _call(e, "dx_proto")  # noqa: E731
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        for base, count in (STRINGS, TYPES, PROTOS, METHODS, LISTS, CODES, FIELDS):
            e.st(base, e.alloc(CAP))
            _ok(e, e.ne(e.ld(base), NONE))
            e.st(count, 0)
        e.st(G_CUR, 0)

        def field_reference(cls, name, type_):
            _call(e, "dx_field", cls, name, type_)
            push(e, TYPES, cls)
            push(e, TYPES, type_)
            push(e, STRINGS, name)

        def method_reference(cls, name, proto_record):
            _call(e, "dx_method", cls, name, proto_record)
            push(e, TYPES, cls)
            push(e, STRINGS, name)

        # The classes.
        e.var("ncls", word())
        _ok(e, e.both(e.lt(0, p["ncls"]), e.le(p["ncls"], 1 << 16)))
        e.var("classes", e.alloc(e.add(e.mul(p["ncls"], CLASS_WORDS), 1)))
        _ok(e, e.ne(p["classes"], NONE))

        def klass():
            e.var("c", e.add(p["classes"], e.mul(p["q"], CLASS_WORDS)))
            e.st(p["c"], string())
            e.st(e.add(p["c"], 1), word())
            e.st(e.add(p["c"], 2), 0)
            e.if_(e.ne(word(), 0), lambda: e.st(e.add(p["c"], 2), string()))
            e.var("ni", word())
            _ok(e, e.le(p["ni"], 1 << 16))
            e.var("ifs", e.alloc(e.add(p["ni"], 1)))
            _ok(e, e.ne(p["ifs"], NONE))
            e.st(p["ifs"], p["ni"])
            e.for_("j", 0, p["ni"], lambda: e.st(e.add(e.add(p["ifs"], 1), p["j"]), string()))
            e.st(e.add(p["c"], 3), p["ifs"])
            push(e, TYPES, e.ld(p["c"]))
            e.for_("j", 0, p["ni"], lambda: push(e, TYPES, at(e, p["ifs"], e.add(p["j"], 1))))
            e.if_(e.ne(at(e, p["c"], 2), 0), lambda: push(e, TYPES, at(e, p["c"], 2)))
            e.var("nf", word())
            _ok(e, e.le(p["nf"], 1 << 16))
            e.var("fs", e.alloc(e.add(e.mul(p["nf"], FIELD_WORDS), 1)))
            _ok(e, e.ne(p["fs"], NONE))
            e.st(e.add(p["c"], 4), p["nf"])
            e.st(e.add(p["c"], 5), p["fs"])

            def field():
                e.var("fr", e.add(p["fs"], e.mul(p["j"], FIELD_WORDS)))
                e.st(p["fr"], string())
                e.st(e.add(p["fr"], 1), string())
                e.st(e.add(p["fr"], 2), word())
                field_reference(e.ld(p["c"]), e.ld(p["fr"]), at(e, p["fr"], 1))

            e.for_("j", 0, p["nf"], field)
            e.var("nm", word())
            _ok(e, e.le(p["nm"], 1 << 16))
            e.var("ms", e.alloc(e.add(e.mul(p["nm"], METHOD_WORDS), 1)))
            _ok(e, e.ne(p["ms"], NONE))
            e.st(e.add(p["c"], 6), p["nm"])
            e.st(e.add(p["c"], 7), p["ms"])
            e.st(e.add(p["c"], 8), 0)

            def method():
                e.var("mr", e.add(p["ms"], e.mul(p["j"], METHOD_WORDS)))
                e.st(p["mr"], string())
                e.st(e.add(p["mr"], 1), proto())
                e.st(e.add(p["mr"], 2), word())
                e.st(e.add(p["mr"], 3), 0)
                e.st(e.add(p["mr"], 4), 0)
                method_reference(e.ld(p["c"]), e.ld(p["mr"]), at(e, p["mr"], 1))

                def code():
                    e.var("cd", e.alloc(5))
                    _ok(e, e.ne(p["cd"], NONE))
                    for k in range(3):
                        e.st(e.add(p["cd"], k), word())
                    e.var("nu", word())
                    _ok(e, e.le(p["nu"], 1 << 20))
                    e.var("us", e.alloc(e.add(e.mul(p["nu"], 2), 1)))
                    _ok(e, e.ne(p["us"], NONE))
                    e.st(e.add(p["cd"], 3), p["nu"])
                    e.st(e.add(p["cd"], 4), p["us"])

                    def unit():
                        e.var("uk", word())
                        e.st(e.add(p["us"], e.mul(p["k"], 2)), p["uk"])
                        e.var("uv", 0)

                        def reference(n):
                            e.set("uv", e.alloc(n))
                            _ok(e, e.ne(p["uv"], NONE))

                        e.if_(e.eq(p["uk"], 0), lambda: e.set("uv", word()))
                        e.if_(e.either(e.eq(p["uk"], 1), e.eq(p["uk"], 2)), lambda: e.set("uv", string()))
                        e.if_(e.eq(p["uk"], 1), lambda: push(e, STRINGS, p["uv"]))
                        e.if_(e.eq(p["uk"], 2), lambda: push(e, TYPES, p["uv"]))
                        e.if_(e.eq(p["uk"], 3), lambda: (reference(3), [e.st(e.add(p["uv"], k), string()) for k in range(3)],
                                                         field_reference(e.ld(p["uv"]), at(e, p["uv"], 1), at(e, p["uv"], 2))))
                        e.if_(e.eq(p["uk"], 4), lambda: (reference(3), e.st(p["uv"], string()), e.st(e.add(p["uv"], 1), string()),
                                                         e.st(e.add(p["uv"], 2), proto()),
                                                         method_reference(e.ld(p["uv"]), at(e, p["uv"], 1), at(e, p["uv"], 2))))
                        _ok(e, e.le(p["uk"], 4))
                        e.st(e.add(e.add(p["us"], e.mul(p["k"], 2)), 1), p["uv"])

                    e.for_("k", 0, p["nu"], unit)
                    e.st(e.add(p["mr"], 3), p["cd"])

                e.if_(e.ne(word(), 0), code)

            e.for_("j", 0, p["nm"], method)

        e.for_("q", 0, p["ncls"], klass)
        cls = lambda q, k: at(e, p["classes"], e.add(e.mul(q, CLASS_WORDS), k))  # noqa: E731
        e.for_("q", 1, p["ncls"], lambda: e.for_("j", 0, p["q"], lambda: _ok(e, e.eq(_call(e, "dx_same", cls(p["q"], 0), cls(p["j"], 0)), 0))))
        e.for_("q", 0, e.ld(G_NT), lambda: push(e, STRINGS, e.ld(e.add(e.ld(G_T), p["q"]))))  # every type is a string too

        # The orders and the index capacity.
        e.st(G_NS, _call(e, "dx_sort", e.ld(G_S), e.ld(G_NS)))
        e.st(G_NT, _call(e, "dx_sort", e.ld(G_T), e.ld(G_NT)))
        _call(e, "dx_sortrec", e.ld(G_P), e.ld(G_NP), 0)
        e.for_("q", 0, e.ld(G_NP), lambda: e.st(e.add(e.ld(e.add(e.ld(G_P), p["q"])), P_RANK), p["q"]))
        e.st(G_NF, _call(e, "dx_sortrec", e.ld(G_F), e.ld(G_NF), 3))
        e.st(G_NM, _call(e, "dx_sortrec", e.ld(G_M), e.ld(G_NM), 1))
        for count in (G_NT, G_NP, G_NF, G_NM):
            _ok(e, e.le(e.ld(count), 0xFFFF))
        e.for_("q", 0, e.ld(G_NP), lambda: (e.var("pr", e.ld(e.add(e.ld(G_P), p["q"]))),
                                             e.if_(e.ne(at(e, p["pr"], P_N), 0), lambda: push(e, LISTS, e.add(p["pr"], P_N)))))
        e.for_("q", 0, p["ncls"], lambda: e.if_(e.ne(e.ld(cls(p["q"], 3)), 0), lambda: push(e, LISTS, cls(p["q"], 3))))
        e.st(G_NL, _call(e, "dx_sortrec", e.ld(G_L), e.ld(G_NL), 2))
        e.st(G_LO, e.alloc(e.add(e.ld(G_NL), 1)))
        _ok(e, e.ne(e.ld(G_LO), NONE))

        # The layout: the identifier sections (an empty one at offset 0), then the data.
        e.var("ns", e.ld(G_NS))
        e.var("nt", e.ld(G_NT))
        e.var("npr", e.ld(G_NP))
        e.var("nfl", e.ld(G_NF))
        e.var("nme", e.ld(G_NM))
        e.var("cursor", 0x70)
        offsets = {}
        for name, size, count in (("string", 4, p["ns"]), ("type", 4, p["nt"]), ("proto", 12, p["npr"]), ("field", 8, p["nfl"]),
                                  ("method", 8, p["nme"]), ("class", 32, p["ncls"])):
            e.var(f"{name}_ids", e.sel(e.eq(count, 0), 0, p["cursor"]))
            e.set("cursor", e.add(p["cursor"], e.mul(count, size)))
            offsets[name] = p[f"{name}_ids"]
        e.var("data_off", p["cursor"])
        e.st(G_CAP, e.add(e.mul(e.ld(G_CUR), 64), 1 << 16))
        e.st(G_OUT, e.alloc(e.ld(G_CAP)))
        _ok(e, e.ne(e.ld(G_OUT), NONE))
        e.st(G_ON, 0)
        e.for_("q", 0, p["data_off"], lambda: b(e, 0))

        # The code items, in class and method order.
        align(e)
        e.var("code_start", e.ld(G_ON))
        e.var("ncode", 0)

        def class_codes():
            def method_code():
                e.var("mr", e.add(cls(p["q"], 7), e.mul(p["j"], METHOD_WORDS)))
                e.var("cd", at(e, p["mr"], 3))

                def write():
                    align(e)
                    e.st(e.add(p["mr"], 4), e.ld(G_ON))
                    for k in range(3):
                        u16(e, at(e, p["cd"], k))
                    u16(e, 0)
                    u32(e, 0)
                    u32(e, at(e, p["cd"], 3))

                    def unit():
                        e.var("uk", at(e, at(e, p["cd"], 4), e.mul(p["k"], 2)))
                        e.var("uv", at(e, at(e, p["cd"], 4), e.add(e.mul(p["k"], 2), 1)))
                        e.if_(e.eq(p["uk"], 0), lambda: u16(e, p["uv"]), lambda: e.if_(
                            e.eq(p["uk"], 1), lambda: u16(e, sidx(e, p["uv"])), lambda: e.if_(
                                e.eq(p["uk"], 2), lambda: u16(e, tidx(e, p["uv"])), lambda: e.if_(
                                    e.eq(p["uk"], 3), lambda: u16(e, fidx(e, e.ld(p["uv"]), at(e, p["uv"], 1), at(e, p["uv"], 2))),
                                    lambda: u16(e, midx(e, e.ld(p["uv"]), at(e, p["uv"], 1), at(e, p["uv"], 2)))))))

                    e.for_("k", 0, at(e, p["cd"], 3), unit)
                    e.set("ncode", e.add(p["ncode"], 1))

                e.if_(e.ne(p["cd"], 0), write)

            e.for_("j", 0, cls(p["q"], 6), method_code)

        e.for_("q", 0, p["ncls"], class_codes)

        # The type lists, the string data.
        align(e)
        e.var("lists_start", e.ld(G_ON))

        def type_list():
            align(e)
            e.var("tl", e.ld(e.add(e.ld(G_L), p["q"])))
            e.st(e.add(e.ld(G_LO), p["q"]), e.ld(G_ON))
            u32(e, e.ld(p["tl"]))
            e.for_("j", 0, e.ld(p["tl"]), lambda: u16(e, tidx(e, at(e, p["tl"], e.add(p["j"], 1)))))

        e.for_("q", 0, e.ld(G_NL), type_list)
        e.var("strings_start", e.ld(G_ON))
        e.var("sd", e.alloc(e.add(p["ns"], 1)))
        _ok(e, e.ne(p["sd"], NONE))
        e.for_("q", 0, p["ns"], lambda: (e.st(e.add(p["sd"], p["q"]), e.ld(G_ON)), _call(e, "dx_mutf8", e.ld(e.add(e.ld(G_S), p["q"])))))

        # The class data: fields (static, instance) and methods (direct, virtual), each by index.
        e.var("class_data_start", e.ld(G_ON))
        e.var("nclass_data", 0)
        e.var("group", e.alloc(e.add(e.mul(e.add(e.add(p["nfl"], p["nme"]), 2), 3), 1)))
        _ok(e, e.ne(p["group"], NONE))

        def class_data():
            e.var("cnf", cls(p["q"], 4))
            e.var("cnm", cls(p["q"], 6))

            def group(kind):
                """Fills ``group`` with the class's entries of ``kind`` (0 static fields, 1 instance fields, 2 direct
                methods, 3 virtual methods) as [index, access, code offset] sorted by index; their count."""
                e.var("gn", 0)
                if kind < 2:
                    def each():
                        e.var("gf", e.add(cls(p["q"], 5), e.mul(p["j"], FIELD_WORDS)))
                        static = e.ne(e.and_(at(e, p["gf"], 2), ACC_STATIC), 0)
                        e.if_(static if kind == 0 else e.not_(static), lambda: (
                            e.st(e.add(p["group"], e.mul(p["gn"], 3)), fidx(e, cls(p["q"], 0), e.ld(p["gf"]), at(e, p["gf"], 1))),
                            e.st(e.add(e.add(p["group"], e.mul(p["gn"], 3)), 1), at(e, p["gf"], 2)),
                            e.st(e.add(e.add(p["group"], e.mul(p["gn"], 3)), 2), 0), e.set("gn", e.add(p["gn"], 1))))

                    e.for_("j", 0, p["cnf"], each)
                else:
                    def each():
                        e.var("gm", e.add(cls(p["q"], 7), e.mul(p["j"], METHOD_WORDS)))
                        direct = e.ne(e.and_(at(e, p["gm"], 2), ACC_STATIC | ACC_PRIVATE | ACC_CONSTRUCTOR), 0)
                        e.if_(direct if kind == 2 else e.not_(direct), lambda: (
                            e.st(e.add(p["group"], e.mul(p["gn"], 3)), midx(e, cls(p["q"], 0), e.ld(p["gm"]), at(e, p["gm"], 1))),
                            e.st(e.add(e.add(p["group"], e.mul(p["gn"], 3)), 1), at(e, p["gm"], 2)),
                            e.st(e.add(e.add(p["group"], e.mul(p["gn"], 3)), 2), at(e, p["gm"], 4)), e.set("gn", e.add(p["gn"], 1))))

                    e.for_("j", 0, p["cnm"], each)
                _call(e, "dx_sortentries", p["group"], p["gn"])
                return p["gn"]

            def write():
                e.set("nclass_data", e.add(p["nclass_data"], 1))
                e.st(e.add(e.add(p["classes"], e.mul(p["q"], CLASS_WORDS)), 8), e.ld(G_ON))
                counts = []
                for kind in range(4):
                    e.var(f"count{kind}", group(kind))
                    counts.append(p[f"count{kind}"])
                for count in counts:
                    uleb(e, count)
                for kind in range(4):
                    group(kind)
                    e.var("prev", 0)
                    e.for_("j", 0, p["gn"], lambda kind=kind: (
                        e.var("ge", e.add(p["group"], e.mul(p["j"], 3))), uleb(e, e.sub(e.ld(p["ge"]), p["prev"])), uleb(e, at(e, p["ge"], 1)),
                        *((uleb(e, at(e, p["ge"], 2)),) if kind >= 2 else ()), e.set("prev", e.ld(p["ge"]))))

            e.if_(e.lt(0, e.add(p["cnf"], p["cnm"])), write)

        e.for_("q", 0, p["ncls"], class_data)
        align(e)
        e.var("map", e.ld(G_ON))
        items = [(0x0000, e.c(1), e.c(0))]
        presence = []
        for kind, name, count in ((0x0001, "string", p["ns"]), (0x0002, "type", p["nt"]), (0x0003, "proto", p["npr"]), (0x0004, "field", p["nfl"]),
                                  (0x0005, "method", p["nme"]), (0x0006, "class", p["ncls"])):
            items.append((kind, count, offsets[name]))
            presence.append(count)
        e.var("nlists", e.ld(G_NL))
        tail = [(0x2001, p["ncode"], p["code_start"]), (0x1001, p["nlists"], p["lists_start"]), (0x2002, p["ns"], p["strings_start"]),
                (0x2000, p["nclass_data"], p["class_data_start"])]
        total = e.c(2)
        for count in [*presence, *(count for _kind, count, _offset in tail)]:
            total = e.add(total, e.flag(e.ne(count, 0)))
        u32(e, total)

        def entry(kind, count, offset):
            def write():
                u16(e, kind)
                u16(e, 0)
                u32(e, count)
                u32(e, offset)
            return write

        entry(*items[0])()
        for kind, count, offset in [*items[1:], *tail]:
            e.if_(e.ne(count, 0), entry(kind, count, offset))
        entry(0x1000, 1, p["map"])()
        e.var("size", e.ld(G_ON))

        # The identifier sections and the header.
        set32 = lambda at_, value: _call(e, "dx_set32", at_, value)  # noqa: E731
        e.for_("q", 0, p["ns"], lambda: set32(e.add(p["string_ids"], e.mul(p["q"], 4)), e.ld(e.add(p["sd"], p["q"]))))
        e.for_("q", 0, p["nt"], lambda: set32(e.add(p["type_ids"], e.mul(p["q"], 4)), sidx(e, e.ld(e.add(e.ld(G_T), p["q"])))))

        def proto_id():
            e.var("pr", e.ld(e.add(e.ld(G_P), p["q"])))
            e.var("pa", e.add(p["proto_ids"], e.mul(p["q"], 12)))
            set32(p["pa"], sidx(e, at(e, p["pr"], P_SHORTY)))
            set32(e.add(p["pa"], 4), tidx(e, at(e, p["pr"], P_RET)))
            set32(e.add(p["pa"], 8), _call(e, "dx_listat", e.add(p["pr"], P_N)))

        e.for_("q", 0, p["npr"], proto_id)
        e.for_("q", 0, p["nfl"], lambda: (e.var("fr", e.ld(e.add(e.ld(G_F), p["q"]))), e.var("fa", e.add(p["field_ids"], e.mul(p["q"], 8))),
                                          set32(p["fa"], e.add(tidx(e, e.ld(p["fr"])), e.mul(tidx(e, at(e, p["fr"], 2)), 65536))),
                                          set32(e.add(p["fa"], 4), sidx(e, at(e, p["fr"], 1)))))
        e.for_("q", 0, p["nme"], lambda: (e.var("mr", e.ld(e.add(e.ld(G_M), p["q"]))), e.var("ma", e.add(p["method_ids"], e.mul(p["q"], 8))),
                                          set32(p["ma"], e.add(tidx(e, e.ld(p["mr"])), e.mul(at(e, at(e, p["mr"], 2), P_RANK), 65536))),
                                          set32(e.add(p["ma"], 4), sidx(e, at(e, p["mr"], 1)))))

        def class_def():
            e.var("ca", e.add(p["class_ids"], e.mul(p["q"], 32)))
            e.var("cs", cls(p["q"], 2))
            for k, value in enumerate((tidx(e, cls(p["q"], 0)), cls(p["q"], 1), e.c(0xFFFFFFFF), e.sel(e.eq(e.ld(cls(p["q"], 3)), 0), 0, _call(e, "dx_listat", cls(p["q"], 3))),
                                       e.c(0xFFFFFFFF), e.c(0), cls(p["q"], 8), e.c(0))):
                set32(e.add(p["ca"], 4 * k), value)
            e.if_(e.ne(p["cs"], 0), lambda: set32(e.add(p["ca"], 8), tidx(e, p["cs"])))

        e.for_("q", 0, p["ncls"], class_def)
        for k, byte in enumerate(b"dex\n039\x00"):
            e.st(e.add(e.ld(G_OUT), k), byte)
        header = [p["size"], 0x70, 0x12345678, 0, 0, p["map"]]
        for name, count in (("string", p["ns"]), ("type", p["nt"]), ("proto", p["npr"]), ("field", p["nfl"]), ("method", p["nme"]), ("class", p["ncls"])):
            header += [count, offsets[name]]
        header += [e.sub(p["size"], p["data_off"]), p["data_off"]]
        for k, value in enumerate(header):
            set32(32 + 4 * k, value)
        _call(e, "dx_sign")

        # The image record.
        e.var("pk", e.ld(G_OUT))
        _ok(e, e.lt(e.add(OUT, e.udiv(p["size"], 8)), IMAGE_END))

        def pack():
            e.var("wv", 0)
            for k in range(7, -1, -1):
                e.set("wv", e.add(e.mul(p["wv"], 256), e.sel(e.lt(e.add(e.mul(p["q"], 8), k), p["size"]), e.ld(e.add(p["pk"], e.add(e.mul(p["q"], 8), k))), 0)))
            e.st(e.add(OUT, p["q"]), p["wv"])

        e.for_("q", 0, e.udiv(e.add(p["size"], 7), 8), pack)
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(IMAGE_AT + 2, p["size"])
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


def build_dex_writer_program():
    """``(reader, function)``: the DEX writer program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in HELPERS:
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_dex_writer_program, "dex-writer")
load_dex_writer_program = _PROGRAM.load
write_dex_writer_store = _PROGRAM.write
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
