"""S15e.5f (ADR-332): JVM aggregates and sums in the XAX JVM program (``xax_jvm`` ADR-159).

A tuple, array or sum value is an immutable flattened ``long[]`` (descriptor ``[J``): a scalar field is one slot holding
its raw bits, a nested aggregate its own flattened slots, a sum its tag then its largest variant.  ``jk_flat`` fills
``_flat_size`` for every type object by rounds (types are acyclic, and the DSL has no recursion); a scalar the bootstrap
cannot flatten (a reference: ``JVM-AGGREGATE-SCALAR``) is marked and declines only where a lowering asks for it.

The lowerings follow ``lower_node``: ``AGGREGATE_MAKE``/``SUM_MAKE`` fill a fresh array through a scratch local
(``lastore`` of each scalar's raw bits, ``System.arraycopy`` of a nested one), ``AGGREGATE_GET`` reads a field
(``laload``, or ``Arrays.copyOfRange`` of a nested one), ``SUM_TAG`` the tag, and ``SUM_GET`` traps on another variant.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_jvm_code import D_D, D_F, D_I, D_J, D_NONE
from xax_selfhost_views_backend import G_O, G_PAY, _at, _call, _g, _kind, _ok, _payload_uleb, _reference, _type_form

UNKNOWN, BAD = NONE, NONE - 1
FLAT_TEXT = b"[J"


def _js(e: E, field: int):
    from xax_selfhost_jvm import _js as js

    return js(e, field)


def _flat_fn(tables):
    """``_flat_size`` of every type object into ``J_FLAT`` (``BAD``: not flattenable)."""
    from xax_selfhost_jvm import J_FLAT, _set_js, _store_alloc

    def build(e: E):
        p = e.p
        e.var("fl_t", _store_alloc(e, e.add(_g(e, G_O), 2), "fl_tab"))
        e.for_("fl_o", 0, _g(e, G_O), lambda: e.st(e.add(p["fl_t"], p["fl_o"]), UNKNOWN))
        _set_js(e, J_FLAT, p["fl_t"])

        def get(o):
            return e.ld(e.add(p["fl_t"], o))

        def scalar(o):
            """0 for a proof value; 1 for bits of at most 64 bits, a float, a link or a memory pointer; else BAD."""
            from xax_selfhost_general_frame import _bits_width

            e.var("fl_f", _type_form(e, o))
            e.var("fl_v", BAD)
            e.if_(e.either(e.eq(p["fl_f"], 3), e.eq(p["fl_f"], 4)), lambda: e.set("fl_v", 0))
            e.if_(e.either(e.eq(p["fl_f"], 7), e.eq(p["fl_f"], 11)), lambda: e.set("fl_v", 1))

            def bits():
                _bits_width(e, o, "fl_w")
                e.if_(e.both(e.lt(0, p["fl_w"]), e.le(p["fl_w"], 64)), lambda: e.set("fl_v", 1))

            e.if_(e.eq(p["fl_f"], 1), bits)

            def pointer():
                e.var("fl_pa", e.add(_at(e, G_PAY, o), 1))
                _payload_uleb(e, "fl_pa")
                e.var("fl_el", _reference(e, o, _payload_uleb(e, "fl_pa")))
                e.if_(e.both(e.ne(p["fl_el"], NONE), e.ne(_type_form(e, p["fl_el"]), 6)), lambda: e.set("fl_v", 1))  # an int offset (ADR-156)

            e.if_(e.eq(p["fl_f"], 2), pointer)
            return p["fl_v"]

        e.var("fl_changed", 1)

        def round_():
            e.set("fl_changed", 0)

            def one():
                o = p["fl_o"]

                def compute():
                    e.var("fl_form", _type_form(e, o))
                    e.var("fl_at", e.add(_at(e, G_PAY, o), 1))
                    e.var("fl_r", UNKNOWN)

                    def tuple_():
                        e.var("fl_n", _payload_uleb(e, "fl_at"))
                        e.var("fl_sum", 0)
                        e.for_("fl_k", 0, p["fl_n"], lambda: (e.var("fl_c", get(_reference(e, o, _payload_uleb(e, "fl_at")))), e.if_(
                            e.either(e.eq(p["fl_c"], UNKNOWN), e.eq(p["fl_c"], BAD)), lambda: e.set("fl_sum", p["fl_c"]), lambda: e.if_(
                                e.both(e.ne(p["fl_sum"], UNKNOWN), e.ne(p["fl_sum"], BAD)), lambda: e.set("fl_sum", e.add(p["fl_sum"], p["fl_c"]))))))
                        e.set("fl_r", p["fl_sum"])

                    def array():
                        e.var("fl_c", get(_reference(e, o, _payload_uleb(e, "fl_at"))))
                        e.var("fl_n", _payload_uleb(e, "fl_at"))
                        e.set("fl_r", e.sel(e.either(e.eq(p["fl_c"], UNKNOWN), e.eq(p["fl_c"], BAD)), p["fl_c"], e.mul(p["fl_n"], p["fl_c"])))

                    def sum_():
                        e.var("fl_n", _payload_uleb(e, "fl_at"))
                        e.var("fl_max", 0)
                        e.for_("fl_k", 0, p["fl_n"], lambda: (e.var("fl_c", get(_reference(e, o, _payload_uleb(e, "fl_at")))), e.if_(
                            e.either(e.eq(p["fl_c"], UNKNOWN), e.eq(p["fl_c"], BAD)), lambda: e.set("fl_max", p["fl_c"]), lambda: e.if_(
                                e.both(e.ne(p["fl_max"], UNKNOWN), e.ne(p["fl_max"], BAD), e.lt(p["fl_max"], p["fl_c"])), lambda: e.set("fl_max", p["fl_c"])))))
                        e.set("fl_r", e.sel(e.either(e.eq(p["fl_max"], UNKNOWN), e.eq(p["fl_max"], BAD)), p["fl_max"], e.add(p["fl_max"], 1)))

                    e.if_(e.eq(p["fl_form"], 8), tuple_, lambda: e.if_(e.eq(p["fl_form"], 9), array, lambda: e.if_(
                        e.eq(p["fl_form"], 10), sum_, lambda: e.set("fl_r", scalar(o)))))
                    e.if_(e.ne(p["fl_r"], UNKNOWN), lambda: (e.st(e.add(p["fl_t"], o), p["fl_r"]), e.set("fl_changed", 1)))

                e.if_(e.both(e.eq(_kind(e, o), int(Kind.TYPE)), e.eq(get(o), UNKNOWN)), compute)

            e.for_("fl_o", 0, _g(e, G_O), one)

        e.while_(lambda: e.ne(p["fl_changed"], 0), round_)
        e.give(1)
    return _function((), build, tables)


def flat_size(e: E, t):
    """``_flat_size(t)`` (a type it cannot flatten declines: ``JVM-AGGREGATE-SCALAR`` names a type as its entity, but
    the bootstrap's own check comes from the value type)."""
    from xax_selfhost_jvm import J_FLAT

    p = e.p
    e.var("fs_v", e.ld(e.add(_js(e, J_FLAT), t)))
    _ok(e, e.both(e.ne(p["fs_v"], UNKNOWN), e.ne(p["fs_v"], BAD)))
    return p["fs_v"]


def flat_code(e: E, name: str):
    """The interned ``[J`` descriptor code into ``name``."""
    from xax_selfhost_jvm_class import literal

    p = e.p
    literal(e, f"{name}_t", FLAT_TEXT.decode())
    e.var(name, _call(e, "jk_intern", p[f"{name}_t"], len(FLAT_TEXT)))
    return p[name]


def add_aggregate_functions(add, tables):
    """After ``jk_intern``."""
    add("jk_flat", _flat_fn(tables))
