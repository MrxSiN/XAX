"""S15e.5e (ADR-331): JVM callbacks in the XAX JVM program (``xax_jvm._callbacks``, ADR-161).

``jk_table`` walks the closure's graphs before the methods: the function table (``_indirect_calls``: every
``FUNCTION_ADDRESS`` target, numbered from 1 in CID order) and the callback groups (a ``FUNCTION_ADDRESS`` whose result
points to a ``code-entry:jvm-interface:<interface>.<name>(<descriptor>)`` type): per (name, descriptor) the target
functions in first-seen order, and the interfaces in first-seen order.  A callback value is ``new P(k)``; the class
implements each interface method used, and that method calls the function whose table index ``k`` holds.

``jk_callbacks`` runs after the methods, as ``_callbacks`` does: the groups in (name, descriptor) order, each target's
signature (``JVM-ENTRY-SIGNATURE``), the interface method (``aload_0; getfield k``, a compare per target in table order,
the arguments, ``invokestatic``, the return; the trap) and ``<init>(I)V``.  An indirect call (``CALL_INDIRECT``) and
the shadow stack's rule belong to the general profile (declined).
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_compiler import Operation
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_jvm_code import D_D, D_F, D_I, D_J, D_REF, LOAD, RETURN, SHORT_LOCAL, _pick, kind
from xax_selfhost_views_backend import G_NI, G_PAY, NI_ENTITY, NI_OP, NI_RESULTS, _at, _call, _cid_less, _cid_words, _g, _ok, _payload_uleb, _reference, _type_form

ENTRY_PREFIX = b"code-entry:jvm-interface:"
GROUPS_CAP = 64
G_NAME, G_NAMEN, G_DESC, G_DESCN, G_NT, G_TARGETS = range(6)
GROUP_WORDS = 6
TRAP_MESSAGE = "XAX trap"


def _js(e: E, field: int):
    from xax_selfhost_jvm import _js as js

    return js(e, field)


def _set_js(e: E, field: int, value):
    from xax_selfhost_jvm import _set_js as set_js

    set_js(e, field, value)


def _store(e: E, words, name: str):
    from xax_selfhost_jvm import _store_alloc

    return _store_alloc(e, words, name)


def _same_text(e: E, a, an, b, bn, name: str):
    p = e.p
    e.var(name, e.flag(e.eq(an, bn)))
    e.var(f"{name}_a", a)
    e.var(f"{name}_b", b)
    e.if_(e.ne(p[name], 0), lambda: e.for_(f"{name}_k", 0, an, lambda: e.if_(
        e.ne(e.ld(e.add(p[f"{name}_a"], p[f"{name}_k"])), e.ld(e.add(p[f"{name}_b"], p[f"{name}_k"]))), lambda: e.set(name, 0))))
    return p[name]


def _text_order(e: E, a, an, b, bn, name: str):
    """``name``: -1, 0 or 1 as text ``a`` sorts before, equal to, or after ``b`` (Python ``str`` order on ASCII)."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_a", a)
    e.var(f"{name}_b", b)
    e.var(f"{name}_an", an)
    e.var(f"{name}_bn", bn)
    e.var(f"{name}_n", e.sel(e.lt(an, bn), an, bn))

    def step():
        e.var(f"{name}_x", e.ld(e.add(p[f"{name}_a"], p[f"{name}_k"])))
        e.var(f"{name}_y", e.ld(e.add(p[f"{name}_b"], p[f"{name}_k"])))
        e.if_(e.both(e.eq(p[name], 0), e.ne(p[f"{name}_x"], p[f"{name}_y"])),
              lambda: e.set(name, e.sel(e.lt(p[f"{name}_x"], p[f"{name}_y"]), e.c((1 << 64) - 1), 1)))

    e.for_(f"{name}_k", 0, p[f"{name}_n"], step)
    e.if_(e.eq(p[name], 0), lambda: e.set(name, e.sel(e.lt(p[f"{name}_an"], p[f"{name}_bn"]), e.c((1 << 64) - 1),
                                                      e.sel(e.lt(p[f"{name}_bn"], p[f"{name}_an"]), 1, 0))))
    return p[name]


def _copy_input(e: E, at, n, name: str):
    """``n`` input bytes as words in the class store."""
    p = e.p
    e.var(f"{name}_src", at)
    e.var(f"{name}_n", n)
    e.var(name, _store(e, e.add(p[f"{name}_n"], 1), f"{name}_s"))
    e.for_(f"{name}_k", 0, p[f"{name}_n"], lambda: e.st(e.add(p[name], p[f"{name}_k"]), e.rd(e.add(p[f"{name}_src"], p[f"{name}_k"]))))
    return p[name]


def interface_entry(e: E, element, name: str):
    """``_interface_entry`` of opaque type ``element``'s identity: ``name`` 1 when it is a ``jvm-interface`` code entry,
    with ``name_it``/``name_itn`` the interface, ``name_nm``/``name_nmn`` the method name and ``name_ds``/``name_dsn`` the
    descriptor (input positions).  A malformed entry (``JVM-INTERFACE-ENTRY``, on a text entity) declines."""
    p = e.p
    e.var(name, 0)
    for suffix in ("it", "itn", "nm", "nmn", "ds", "dsn"):
        e.var(f"{name}_{suffix}", 0)
    e.var(f"{name}_at", e.add(_at(e, G_PAY, element), 1))
    e.var(f"{name}_n", _payload_uleb(e, f"{name}_at"))
    starts = e.both(e.le(len(ENTRY_PREFIX), p[f"{name}_n"]), *(e.eq(e.rd(e.add(p[f"{name}_at"], k)), byte) for k, byte in enumerate(ENTRY_PREFIX)))

    def entry():
        e.set(name, 1)
        e.var(f"{name}_t", e.add(p[f"{name}_at"], len(ENTRY_PREFIX)))
        e.var(f"{name}_tn", e.sub(p[f"{name}_n"], len(ENTRY_PREFIX)))
        # ``head, paren, tail = text.partition("(")``; ``interface, _, name = head.rpartition(".")``.
        e.var(f"{name}_open", NONE)
        e.for_(f"{name}_k", 0, p[f"{name}_tn"], lambda: e.if_(e.both(e.eq(p[f"{name}_open"], NONE), e.eq(e.rd(e.add(p[f"{name}_t"], p[f"{name}_k"])), ord("("))),
                                                             lambda: e.set(f"{name}_open", p[f"{name}_k"])))
        _ok(e, e.ne(p[f"{name}_open"], NONE))
        e.var(f"{name}_dot", NONE)
        e.for_(f"{name}_k", 0, p[f"{name}_open"], lambda: e.if_(e.eq(e.rd(e.add(p[f"{name}_t"], p[f"{name}_k"])), ord(".")),
                                                               lambda: e.set(f"{name}_dot", p[f"{name}_k"])))
        _ok(e, e.both(e.ne(p[f"{name}_dot"], NONE), e.lt(0, p[f"{name}_dot"]), e.lt(e.add(p[f"{name}_dot"], 1), p[f"{name}_open"])))
        e.set(f"{name}_it", p[f"{name}_t"])
        e.set(f"{name}_itn", p[f"{name}_dot"])
        e.set(f"{name}_nm", e.add(e.add(p[f"{name}_t"], p[f"{name}_dot"]), 1))
        e.set(f"{name}_nmn", e.sub(e.sub(p[f"{name}_open"], p[f"{name}_dot"]), 1))
        e.set(f"{name}_ds", e.add(p[f"{name}_t"], p[f"{name}_open"]))
        e.set(f"{name}_dsn", e.sub(p[f"{name}_tn"], p[f"{name}_open"]))

    e.if_(starts, entry)
    return p[name]


def _callback_element(e: E, t, name: str):
    """The opaque element of pointer type ``t`` when it is one (else NONE) into ``name``."""
    p = e.p
    e.var(name, NONE)

    def pointer():
        e.var(f"{name}_at", e.add(_at(e, G_PAY, t), 1))
        _payload_uleb(e, f"{name}_at")
        e.var(f"{name}_el", _reference(e, t, _payload_uleb(e, f"{name}_at")))
        _ok(e, e.ne(p[f"{name}_el"], NONE))
        e.if_(e.eq(_type_form(e, p[f"{name}_el"]), 6), lambda: e.set(name, p[f"{name}_el"]))

    e.if_(e.eq(_type_form(e, t), 2), pointer)
    return p[name]


# -- the table and the groups ---------------------------------------------------------------------------------------------

def _table_fn(tables):
    """``_indirect_calls``' table and ``_callbacks``' groups (no diagnostics: those come after the methods)."""
    from xax_selfhost_jvm import J_CBG, J_IFACES, J_NCBG, J_NFN, J_NIFACES, J_NTABLE, J_TABIX, J_TABLE
    from xax_selfhost_views_backend import G_O, G_ORDER

    def build(e: E):
        p = e.p
        n = _js(e, J_NFN)
        order = _g(e, G_ORDER)
        e.var("tb_list", _store(e, e.add(n, 1), "tb_l"))
        e.var("tb_count", 0)
        e.var("tb_groups", _store(e, GROUPS_CAP * GROUP_WORDS + 1, "tb_g"))
        e.var("tb_ng", 0)
        e.var("tb_ifaces", _store(e, GROUPS_CAP * 2 + 1, "tb_i"))
        e.var("tb_ni", 0)

        def function():
            e.var("tb_g", e.ld(_call(e, "interface", e.ld(e.add(order, p["tb_f"])))))
            e.var("tb_s", _at(e, G_PAY, p["tb_g"]))
            e.var("tb_a", e.add(p["tb_s"], 2))

            def block():
                e.set("tb_a", e.add(e.add(p["tb_a"], 1), e.rd(p["tb_a"])))
                e.var("tb_n", e.rd(p["tb_a"]))
                e.set("tb_a", e.add(p["tb_a"], 1))

                def node():
                    e.set("tb_a", _call(e, "node_info", p["tb_a"]))
                    ni = _g(e, G_NI)
                    e.var("tb_op", e.ld(e.add(ni, NI_OP)))
                    _ok(e, e.ne(p["tb_op"], int(Operation.CALL_INDIRECT)))  # indirect calls: the general profile (declined)

                    def address():
                        e.var("tb_fn", _reference(e, p["tb_g"], e.ld(e.add(ni, NI_ENTITY))))
                        _ok(e, e.ne(p["tb_fn"], NONE))
                        e.var("tb_res", _reference(e, p["tb_g"], e.rd(e.add(e.ld(e.add(ni, NI_RESULTS)), 1))))
                        _ok(e, e.ne(p["tb_res"], NONE))
                        e.var("tb_seen", 0)
                        e.for_("tb_k", 0, p["tb_count"], lambda: e.if_(e.eq(e.ld(e.add(p["tb_list"], p["tb_k"])), p["tb_fn"]), lambda: e.set("tb_seen", 1)))
                        e.if_(e.eq(p["tb_seen"], 0), lambda: (e.st(e.add(p["tb_list"], p["tb_count"]), p["tb_fn"]), e.set("tb_count", e.add(p["tb_count"], 1))))
                        e.var("tb_el", _callback_element(e, p["tb_res"], "tb_ce"))
                        e.if_(e.ne(p["tb_el"], NONE), lambda: e.if_(e.ne(interface_entry(e, p["tb_el"], "tb_ie"), 0), callback))

                    def callback():
                        # The interface, first seen first.
                        e.var("tb_found", 0)
                        e.for_("tb_k", 0, p["tb_ni"], lambda: e.if_(_same_input_text(e, p["tb_ie_it"], p["tb_ie_itn"], e.ld(e.add(p["tb_ifaces"], e.mul(p["tb_k"], 2))),
                                                                                     e.ld(e.add(p["tb_ifaces"], e.add(e.mul(p["tb_k"], 2), 1))), "tb_si"),
                                                                    lambda: e.set("tb_found", 1)))

                        def new_interface():
                            _ok(e, e.lt(p["tb_ni"], GROUPS_CAP))
                            e.st(e.add(p["tb_ifaces"], e.mul(p["tb_ni"], 2)), _copy_input(e, p["tb_ie_it"], p["tb_ie_itn"], "tb_ic"))
                            e.st(e.add(p["tb_ifaces"], e.add(e.mul(p["tb_ni"], 2), 1)), p["tb_ie_itn"])
                            e.set("tb_ni", e.add(p["tb_ni"], 1))

                        e.if_(e.eq(p["tb_found"], 0), new_interface)
                        # The group (name, descriptor), first seen first; its targets, first seen first.
                        e.var("tb_gi", NONE)

                        def same_group():
                            e.var("tb_ga", e.add(p["tb_groups"], e.mul(p["tb_k"], GROUP_WORDS)))
                            same = e.both(_same_input_text(e, p["tb_ie_nm"], p["tb_ie_nmn"], e.ld(e.add(p["tb_ga"], G_NAME)), e.ld(e.add(p["tb_ga"], G_NAMEN)), "tb_sn"),
                                          _same_input_text(e, p["tb_ie_ds"], p["tb_ie_dsn"], e.ld(e.add(p["tb_ga"], G_DESC)), e.ld(e.add(p["tb_ga"], G_DESCN)), "tb_sd"))
                            e.if_(same, lambda: e.set("tb_gi", p["tb_k"]))

                        e.for_("tb_k", 0, p["tb_ng"], same_group)

                        def new_group():
                            _ok(e, e.lt(p["tb_ng"], GROUPS_CAP))
                            e.var("tb_na", e.add(p["tb_groups"], e.mul(p["tb_ng"], GROUP_WORDS)))
                            e.st(e.add(p["tb_na"], G_NAME), _copy_input(e, p["tb_ie_nm"], p["tb_ie_nmn"], "tb_nmc"))
                            e.st(e.add(p["tb_na"], G_NAMEN), p["tb_ie_nmn"])
                            e.st(e.add(p["tb_na"], G_DESC), _copy_input(e, p["tb_ie_ds"], p["tb_ie_dsn"], "tb_dsc"))
                            e.st(e.add(p["tb_na"], G_DESCN), p["tb_ie_dsn"])
                            e.st(e.add(p["tb_na"], G_NT), 0)
                            e.st(e.add(p["tb_na"], G_TARGETS), _store(e, e.add(n, 1), "tb_tg"))
                            e.set("tb_gi", p["tb_ng"])
                            e.set("tb_ng", e.add(p["tb_ng"], 1))

                        e.if_(e.eq(p["tb_gi"], NONE), new_group)
                        e.var("tb_gr", e.add(p["tb_groups"], e.mul(p["tb_gi"], GROUP_WORDS)))
                        e.var("tb_tl", e.ld(e.add(p["tb_gr"], G_TARGETS)))
                        e.var("tb_nt", e.ld(e.add(p["tb_gr"], G_NT)))
                        e.var("tb_tseen", 0)
                        e.for_("tb_k", 0, p["tb_nt"], lambda: e.if_(e.eq(e.ld(e.add(p["tb_tl"], p["tb_k"])), p["tb_fn"]), lambda: e.set("tb_tseen", 1)))
                        e.if_(e.eq(p["tb_tseen"], 0), lambda: (e.st(e.add(p["tb_tl"], p["tb_nt"]), p["tb_fn"]), e.st(e.add(p["tb_gr"], G_NT), e.add(p["tb_nt"], 1))))

                    e.if_(e.eq(p["tb_op"], int(Operation.FUNCTION_ADDRESS)), address)

                e.for_("tb_m", 0, p["tb_n"], node)
                e.set("tb_a", _call(e, "term_end", p["tb_a"]))

            e.for_("tb_b", 0, e.rd(p["tb_s"]), block)

        e.for_("tb_f", 0, n, function)
        # The table: CID order, from 1.
        def insert():
            e.var("tb_item", e.ld(e.add(p["tb_list"], p["tb_s2"])))
            e.var("tb_j", p["tb_s2"])
            before = lambda: e.both(e.lt(0, p["tb_j"]), _cid_less(e, _cid_at(e, p["tb_item"]), _cid_at(e, e.ld(e.add(p["tb_list"], e.sub(p["tb_j"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["tb_list"], p["tb_j"]), e.ld(e.add(p["tb_list"], e.sub(p["tb_j"], 1)))), e.set("tb_j", e.sub(p["tb_j"], 1))))
            e.st(e.add(p["tb_list"], p["tb_j"]), p["tb_item"])

        e.for_("tb_s2", 1, p["tb_count"], insert)
        e.var("tb_ix", _store(e, e.add(_g(e, G_O), 2), "tb_x"))  # an index per object, 0 when not addressed
        e.for_("tb_k", 0, _g(e, G_O), lambda: e.st(e.add(p["tb_ix"], p["tb_k"]), 0))
        e.for_("tb_k", 0, p["tb_count"], lambda: e.st(e.add(p["tb_ix"], e.ld(e.add(p["tb_list"], p["tb_k"]))), e.add(p["tb_k"], 1)))
        _set_js(e, J_TABLE, p["tb_list"])
        _set_js(e, J_NTABLE, p["tb_count"])
        _set_js(e, J_TABIX, p["tb_ix"])
        _set_js(e, J_CBG, p["tb_groups"])
        _set_js(e, J_NCBG, p["tb_ng"])
        _set_js(e, J_IFACES, p["tb_ifaces"])
        _set_js(e, J_NIFACES, p["tb_ni"])
        e.give(1)
    return _function((), build, tables)


def _same_input_text(e: E, at, n, text, tn, name: str):
    """1 when the ``n`` input bytes at ``at`` equal the ``tn`` words at ``text``."""
    p = e.p
    e.var(name, e.flag(e.eq(n, tn)))
    e.var(f"{name}_at", at)
    e.var(f"{name}_t", text)
    e.if_(e.ne(p[name], 0), lambda: e.for_(f"{name}_k", 0, n, lambda: e.if_(
        e.ne(e.rd(e.add(p[f"{name}_at"], p[f"{name}_k"])), e.ld(e.add(p[f"{name}_t"], p[f"{name}_k"]))), lambda: e.set(name, 0))))
    return e.ne(p[name], 0)


def _cid_at(e: E, obj):
    from xax_selfhost_views_backend import _cid_at as cid_at

    return cid_at(e, obj)


def table_index(e: E, function):
    from xax_selfhost_jvm import J_TABIX

    return e.ld(e.add(_js(e, J_TABIX), function))


# -- the members ------------------------------------------------------------------------------------------------------------

def _desc_code(e: E, text, n, name: str):
    """A parameter descriptor's code: ``I``/``J``/``F``/``D`` their own, any other text interned (``Z``, ``B``, ``C``
    and ``S`` are verified as class names by the bootstrap's ``verification_type``, and loaded with ``aload``)."""
    p = e.p
    e.var(f"{name}_t", text)
    e.var(f"{name}_n", n)
    e.var(name, NONE)
    e.var(f"{name}_c", e.ld(p[f"{name}_t"]))
    for letter, code in (("I", D_I), ("J", D_J), ("F", D_F), ("D", D_D)):
        e.if_(e.both(e.eq(p[f"{name}_n"], 1), e.eq(p[f"{name}_c"], ord(letter))), lambda code=code: e.set(name, code))
    e.if_(e.eq(p[name], NONE), lambda: e.set(name, _call(e, "jk_intern", p[f"{name}_t"], p[f"{name}_n"])))
    return p[name]


def _put_desc_text(e: E, d):
    """A diagnostic string of descriptor code ``d``."""
    from xax_selfhost_jvm_foreign import _desc_letter, _put_text, ref_text

    p = e.p
    e.var("pdt_d", d)
    e.if_(e.lt(p["pdt_d"], D_REF), lambda: _desc_letter(e, p["pdt_d"]), lambda: _put_text(e, ref_text(e, p["pdt_d"])[0], ref_text(e, p["pdt_d"])[1]))


def _callbacks_fn(tables):
    """``_callbacks`` after the methods: per group in (name, descriptor) order, the interface method's record, then
    ``<init>(I)V``; nothing without groups."""
    from xax_selfhost_jvm import (
        J_CBG, J_CLASSNAME, J_ENTRY_INDEX, J_NCBG, J_POOL, KIND_CB, KIND_INIT, MR_BARE, MR_CLEN, MR_CODE, MR_FIDX, MR_FRAMES, MR_FTYPES, MR_KIND,
        MR_LINES, MR_LOCALS, MR_NFRAMES, MR_NFTYPES, MR_NLINES, MR_STACK, _add_record,
    )
    from xax_selfhost_jvm_class import bdata, blen, buffer, klass_literal, method_literal, u1, u2, utf8_literal
    from xax_selfhost_general_view import G_CIDX

    def build(e: E):
        p = e.p
        e.if_(e.eq(_js(e, J_NCBG), 0), lambda: e.give(1))
        pool = _js(e, J_POOL)
        groups = _js(e, J_CBG)
        e.var("cb_ng", _js(e, J_NCBG))
        # The groups in (name, descriptor) order (an insertion sort of their indices).
        e.var("cb_order", e.alloc(e.add(p["cb_ng"], 1)))
        _ok(e, e.ne(p["cb_order"], NONE))
        e.for_("cb_k", 0, p["cb_ng"], lambda: e.st(e.add(p["cb_order"], p["cb_k"]), p["cb_k"]))

        def group_at(index):
            return e.add(groups, e.mul(index, GROUP_WORDS))

        def insert():
            e.var("cb_item", e.ld(e.add(p["cb_order"], p["cb_s"])))
            e.var("cb_j", p["cb_s"])

            def before():
                e.var("cb_x", group_at(p["cb_item"]))
                e.var("cb_y", group_at(e.ld(e.add(p["cb_order"], e.sub(p["cb_j"], 1)))))
                e.var("cb_by", 0)

                def compare():
                    e.var("cb_on", _text_order(e, e.ld(e.add(p["cb_x"], G_NAME)), e.ld(e.add(p["cb_x"], G_NAMEN)),
                                               e.ld(e.add(p["cb_y"], G_NAME)), e.ld(e.add(p["cb_y"], G_NAMEN)), "cb_tn"))
                    e.var("cb_od", _text_order(e, e.ld(e.add(p["cb_x"], G_DESC)), e.ld(e.add(p["cb_x"], G_DESCN)),
                                               e.ld(e.add(p["cb_y"], G_DESC)), e.ld(e.add(p["cb_y"], G_DESCN)), "cb_td"))
                    e.set("cb_by", e.flag(e.either(e.eq(p["cb_on"], e.c((1 << 64) - 1)), e.both(e.eq(p["cb_on"], 0), e.eq(p["cb_od"], e.c((1 << 64) - 1))))))

                e.if_(e.lt(0, p["cb_j"]), compare)
                return p["cb_by"]

            e.var("cb_go", before())
            e.while_(lambda: e.ne(p["cb_go"], 0), lambda: (e.st(e.add(p["cb_order"], p["cb_j"]), e.ld(e.add(p["cb_order"], e.sub(p["cb_j"], 1)))),
                                                           e.set("cb_j", e.sub(p["cb_j"], 1)), e.set("cb_go", before())))
            e.st(e.add(p["cb_order"], p["cb_j"]), p["cb_item"])

        e.for_("cb_s", 1, p["cb_ng"], insert)
        # ``this``: L<class>; (the frames' first local).
        e.var("cb_this", e.alloc(24))
        _ok(e, e.ne(p["cb_this"], NONE))
        e.st(p["cb_this"], ord("L"))
        e.for_("cb_k", 0, 21, lambda: e.st(e.add(e.add(p["cb_this"], 1), p["cb_k"]), e.ld(e.add(_js(e, J_CLASSNAME), p["cb_k"]))))
        e.st(e.add(p["cb_this"], 22), ord(";"))
        e.var("cb_thiscode", _call(e, "jk_intern", p["cb_this"], 23))

        def group():
            from xax_selfhost_jvm_foreign import param_slots

            e.var("cb_gi", e.ld(e.add(p["cb_order"], p["cb_q"])))
            e.var("cb_g", group_at(p["cb_gi"]))
            # ``_parse_method_descriptor(descriptor)``: a malformed one is the bootstrap's (on a text entity: declined).
            e.var("cb_mb", _call(e, "jk_parse", e.ld(e.add(p["cb_g"], G_DESC)), e.ld(e.add(p["cb_g"], G_DESCN))))
            from xax_selfhost_jvm_foreign import MB_NP, MB_PARAMS, MB_RES, MB_RESN, PARAM_WORDS

            e.var("cb_np", e.ld(e.add(p["cb_mb"], MB_NP)))
            e.var("cb_params", e.ld(e.add(p["cb_mb"], MB_PARAMS)))
            e.var("cb_res", e.ld(e.add(p["cb_mb"], MB_RES)))
            e.var("cb_resn", e.ld(e.add(p["cb_mb"], MB_RESN)))
            e.var("cb_codes", e.alloc(e.add(p["cb_np"], 1)))
            e.var("cb_slotof", e.alloc(e.add(p["cb_np"], 1)))
            _ok(e, e.both(e.ne(p["cb_codes"], NONE), e.ne(p["cb_slotof"], NONE)))
            e.var("cb_slot", 1)

            def parameter():
                e.st(e.add(p["cb_slotof"], p["cb_k"]), p["cb_slot"])
                e.set("cb_slot", e.add(p["cb_slot"], param_slots(e, p["cb_params"], p["cb_k"])))
                e.st(e.add(p["cb_codes"], p["cb_k"]), _desc_code(e, e.ld(e.add(p["cb_params"], e.mul(p["cb_k"], PARAM_WORDS))),
                                                              e.ld(e.add(p["cb_params"], e.add(e.mul(p["cb_k"], PARAM_WORDS), 1))), "cb_dc"))

            e.for_("cb_k", 0, p["cb_np"], parameter)
            e.var("cb_rv", e.flag(e.both(e.eq(p["cb_resn"], 1), e.eq(e.ld(p["cb_res"]), ord("V")))))
            e.var("cb_rz", e.flag(e.both(e.eq(p["cb_resn"], 1), e.eq(e.ld(p["cb_res"]), ord("Z")))))
            e.var("cb_rcode", NONE)
            e.if_(e.eq(p["cb_rv"], 0), lambda: e.set("cb_rcode", _desc_code(e, p["cb_res"], p["cb_resn"], "cb_rc")))
            # The targets in table order.
            e.var("cb_tl", e.ld(e.add(p["cb_g"], G_TARGETS)))
            e.var("cb_nt", e.ld(e.add(p["cb_g"], G_NT)))

            def sort_target():
                e.var("cb_ti", e.ld(e.add(p["cb_tl"], p["cb_s"])))
                e.var("cb_tj", p["cb_s"])
                e.while_(lambda: e.both(e.lt(0, p["cb_tj"]), e.lt(table_index(e, p["cb_ti"]), table_index(e, e.ld(e.add(p["cb_tl"], e.sub(p["cb_tj"], 1)))))),
                         lambda: (e.st(e.add(p["cb_tl"], p["cb_tj"]), e.ld(e.add(p["cb_tl"], e.sub(p["cb_tj"], 1)))), e.set("cb_tj", e.sub(p["cb_tj"], 1))))
                e.st(e.add(p["cb_tl"], p["cb_tj"]), p["cb_ti"])

            e.for_("cb_s", 1, p["cb_nt"], sort_target)
            buffer(e, "cb_code", 1 << 16)
            e.var("cb_frames", _store(e, e.add(p["cb_nt"], 1), "cb_fr"))

            def target():
                e.var("cb_t", e.ld(e.add(p["cb_tl"], p["cb_q2"])))
                _call(e, "jk_cb_signature", p["cb_t"], p["cb_g"], p["cb_codes"], p["cb_np"], p["cb_rcode"], p["cb_rz"])
                e.var("cb_fx", e.ld(e.add(_g(e, G_CIDX), p["cb_t"])))
                u1(e, p["cb_code"], 0x2A)
                u1(e, p["cb_code"], 0xB4)
                e.var("cb_k_name", utf8_literal(e, pool, "k", "cb_kn"))
                e.var("cb_k_desc", utf8_literal(e, pool, "I", "cb_kd"))
                u2(e, p["cb_code"], _call(e, "jp_ref2", pool, 9, _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)),
                                          _call(e, "jp_ref2", pool, 12, p["cb_k_name"], p["cb_k_desc"], 0, 0), 0, 1))
                _int_constant(e, p["cb_code"], table_index(e, p["cb_t"]))
                e.var("cb_at", blen(e, p["cb_code"]))
                u1(e, p["cb_code"], 0xA0)
                u2(e, p["cb_code"], 0)
                e.var("cb_entry", e.flag(e.eq(p["cb_fx"], _js(e, J_ENTRY_INDEX))))
                for wide_pass in (0, 1):
                    def load(wide_pass=wide_pass):
                        e.var("cb_lc", e.ld(e.add(p["cb_codes"], p["cb_k"])))
                        two = e.either(e.eq(p["cb_lc"], D_J), e.eq(p["cb_lc"], D_D))
                        take = e.sel(e.ne(p["cb_entry"], 0), e.flag(e.eq(wide_pass, 0)), e.flag(e.eq(e.flag(two), wide_pass)))

                        def emit():
                            e.var("cb_ls", e.ld(e.add(p["cb_slotof"], p["cb_k"])))
                            e.var("cb_lop", _pick(e, kind(e, p["cb_lc"]), LOAD))
                            _ok(e, e.le(p["cb_ls"], 255))  # ``bytes((opcode, slot))`` past 255: the bootstrap's own failure
                            e.if_(e.le(p["cb_ls"], 3), lambda: u1(e, p["cb_code"], e.add(_pick(e, p["cb_lop"], SHORT_LOCAL), p["cb_ls"])),
                                  lambda: (u1(e, p["cb_code"], p["cb_lop"]), u1(e, p["cb_code"], p["cb_ls"])))

                        e.if_(e.ne(take, 0), emit)

                    e.for_("cb_k", 0, p["cb_np"], load)
                u1(e, p["cb_code"], 0xB8)
                u2(e, p["cb_code"], _call(e, "jl_own_method", 1, p["cb_fx"]))
                u1(e, p["cb_code"], e.sel(e.ne(p["cb_rz"], 0), 0xAC, e.sel(e.ne(p["cb_rv"], 0), 0xB1, _pick(e, kind(e, p["cb_rcode"]), RETURN))))
                e.var("cb_next", blen(e, p["cb_code"]))
                e.var("cb_delta", e.sub(p["cb_next"], p["cb_at"]))
                _ok(e, e.le(p["cb_delta"], 0x7FFF))
                e.st(e.add(bdata(e, p["cb_code"]), e.add(p["cb_at"], 1)), e.and_(e.udiv(p["cb_delta"], 256), 255))
                e.st(e.add(bdata(e, p["cb_code"]), e.add(p["cb_at"], 2)), e.and_(p["cb_delta"], 255))
                e.st(e.add(p["cb_frames"], p["cb_q2"]), p["cb_next"])

            e.for_("cb_q2", 0, p["cb_nt"], target)
            # The trap: new Error("XAX trap"); athrow.
            u1(e, p["cb_code"], 0xBB)
            u2(e, p["cb_code"], klass_literal(e, pool, "java/lang/Error", "cb_err"))
            u1(e, p["cb_code"], 0x59)
            u1(e, p["cb_code"], 0x13)
            u2(e, p["cb_code"], _call(e, "jp_ref1", pool, 8, utf8_literal(e, pool, TRAP_MESSAGE, "cb_tm")))
            u1(e, p["cb_code"], 0xB7)
            u2(e, p["cb_code"], method_literal(e, pool, "java/lang/Error", "<init>", "(Ljava/lang/String;)V", "cb_ei"))
            u1(e, p["cb_code"], 0xBF)
            e.var("cb_n", blen(e, p["cb_code"]))
            _ok(e, e.le(p["cb_n"], 0xFFFF))
            e.var("cb_bytes", _store(e, e.add(p["cb_n"], 1), "cb_by2"))
            e.for_("cb_k", 0, p["cb_n"], lambda: e.st(e.add(p["cb_bytes"], p["cb_k"]), e.ld(e.add(bdata(e, p["cb_code"]), p["cb_k"]))))
            e.var("cb_ft", _store(e, e.add(p["cb_np"], 2), "cb_ftt"))
            e.st(p["cb_ft"], p["cb_thiscode"])
            e.for_("cb_k", 0, p["cb_np"], lambda: e.st(e.add(e.add(p["cb_ft"], 1), p["cb_k"]), e.ld(e.add(p["cb_codes"], p["cb_k"]))))
            e.var("cb_stack", e.add(p["cb_slot"], 2))
            _add_record(e, {MR_KIND: KIND_CB, MR_FIDX: p["cb_gi"], MR_CODE: p["cb_bytes"], MR_CLEN: p["cb_n"],
                            MR_STACK: e.sel(e.lt(p["cb_stack"], 4), 4, p["cb_stack"]), MR_LOCALS: p["cb_slot"], MR_FRAMES: p["cb_frames"],
                            MR_NFRAMES: p["cb_nt"], MR_FTYPES: p["cb_ft"], MR_NFTYPES: e.add(p["cb_np"], 1), MR_LINES: 0, MR_NLINES: 0, MR_BARE: NONE})

        e.for_("cb_q", 0, p["cb_ng"], group)
        # <init>(I)V: aload_0; invokespecial Object.<init>; aload_0; iload_1; putfield k; return.
        e.var("cb_oi", method_literal(e, pool, "java/lang/Object", "<init>", "()V", "cb_om"))
        e.var("cb_kf", _call(e, "jp_ref2", pool, 9, _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)),
                             _call(e, "jp_ref2", pool, 12, utf8_literal(e, pool, "k", "cb_kn2"), utf8_literal(e, pool, "I", "cb_kd2"), 0, 0), 0, 1))
        e.var("cb_init", _store(e, 11, "cb_in"))
        for k, byte in enumerate((0x2A, 0xB7, None, None, 0x2A, 0x1B, 0xB5, None, None, 0xB1)):
            if byte is not None:
                e.st(e.add(p["cb_init"], k), byte)
        for k, index in ((2, "cb_oi"), (7, "cb_kf")):
            e.st(e.add(p["cb_init"], k), e.and_(e.udiv(p[index], 256), 255))
            e.st(e.add(p["cb_init"], k + 1), e.and_(p[index], 255))
        _add_record(e, {MR_KIND: KIND_INIT, MR_FIDX: 0, MR_CODE: p["cb_init"], MR_CLEN: 10, MR_STACK: 2, MR_LOCALS: 2, MR_FRAMES: 0,
                        MR_NFRAMES: 0, MR_FTYPES: 0, MR_NFTYPES: 0, MR_LINES: 0, MR_NLINES: 0, MR_BARE: NONE})
        e.give(1)
    return _function((), build, tables)


def _int_constant(e: E, buf, value):
    """``_int_constant``: ``iconst``, ``bipush``, ``sipush``, else ``ldc_w`` (table indices are positive)."""
    from xax_selfhost_jvm import J_POOL
    from xax_selfhost_jvm_class import u1, u2

    p = e.p
    e.var("ic2_v", value)
    e.if_(e.le(p["ic2_v"], 5), lambda: u1(e, buf, e.add(0x03, p["ic2_v"])), lambda: e.if_(
        e.le(p["ic2_v"], 127), lambda: (u1(e, buf, 0x10), u1(e, buf, p["ic2_v"])), lambda: e.if_(
            e.le(p["ic2_v"], 32767), lambda: (u1(e, buf, 0x11), u2(e, buf, p["ic2_v"])), lambda: (
                u1(e, buf, 0x13), u2(e, buf, _call(e, "jp_number", _js(e, J_POOL), 3, p["ic2_v"]))))))


def _signature_check_fn(tables):
    """``_callbacks``' check of target ``t`` against its group: the function's machine parameters are the interface
    method's, its returns the result (or ``Z`` from one ``bits<1>``), else ``JVM-ENTRY-SIGNATURE``."""
    from xax_selfhost_jvm_foreign import _put_text, vdesc
    from xax_selfhost_x86_64_general import _proof

    def build(e: E):
        p = e.p
        e.var("sc_i", _call(e, "interface", p["t"]))
        e.var("sc_np", e.ld(e.add(p["sc_i"], 1)))
        e.var("sc_rt", e.add(e.add(p["sc_i"], 2), p["sc_np"]))
        e.var("sc_nr", e.ld(p["sc_rt"]))
        e.var("sc_fp", e.alloc(e.add(p["sc_np"], 1)))
        e.var("sc_fr", e.alloc(e.add(p["sc_nr"], 1)))
        _ok(e, e.both(e.ne(p["sc_fp"], NONE), e.ne(p["sc_fr"], NONE)))
        e.var("sc_mp", 0)
        e.var("sc_mr", 0)
        e.for_("sc_k", 0, p["sc_np"], lambda: (e.var("sc_d", vdesc(e, e.ld(e.add(e.add(p["sc_i"], 2), p["sc_k"])))), e.if_(
            e.ne(p["sc_d"], 0), lambda: (e.st(e.add(p["sc_fp"], p["sc_mp"]), p["sc_d"]), e.set("sc_mp", e.add(p["sc_mp"], 1))))))
        e.for_("sc_k", 0, p["sc_nr"], lambda: (e.var("sc_d", vdesc(e, e.ld(e.add(e.add(p["sc_rt"], 1), p["sc_k"])))), e.if_(
            e.ne(p["sc_d"], 0), lambda: (e.st(e.add(p["sc_fr"], p["sc_mr"]), p["sc_d"]), e.set("sc_mr", e.add(p["sc_mr"], 1))))))
        _ok(e, e.le(p["sc_mr"], 1))  # JVM-SINGLE-RESULT: the bootstrap's
        e.var("sc_ok", e.flag(e.eq(p["sc_mp"], p["n"])))
        e.for_("sc_k", 0, p["sc_mp"], lambda: e.if_(e.both(e.lt(p["sc_k"], p["n"]), e.ne(e.ld(e.add(p["sc_fp"], p["sc_k"])), e.ld(e.add(p["codes"], p["sc_k"])))),
                                                    lambda: e.set("sc_ok", 0)))
        same_returns = e.sel(e.eq(p["rcode"], NONE), e.flag(e.eq(p["sc_mr"], 0)), e.flag(e.both(e.eq(p["sc_mr"], 1), e.eq(e.ld(p["sc_fr"]), p["rcode"]))))
        e.var("sc_rok", same_returns)

        def boolean():
            # ``result == "Z"`` and one ``I`` return whose first declared return type is ``bits<1>``.
            from xax_selfhost_general_frame import _bits_width

            e.if_(e.both(e.eq(p["sc_mr"], 1), e.eq(e.ld(p["sc_fr"]), D_I), e.lt(0, p["sc_nr"])), lambda: (
                e.var("sc_first", e.ld(e.add(p["sc_rt"], 1))),
                _ok(e, e.eq(_type_form(e, p["sc_first"]), 1)),  # decode_bits_width of another type: the bootstrap's own failure
                _bits_width(e, p["sc_first"], "sc_bw"),
                e.if_(e.eq(p["sc_bw"], 1), lambda: e.set("sc_rok", 1))))

        e.if_(e.both(e.eq(p["sc_rok"], 0), e.ne(p["rz"], 0)), boolean)

        def write():
            D.text(e, "XAX.JVM.ENTRY")
            D.cid(e, _cid_words(e, p["t"]))
            D.text(e, "JVM-ENTRY-SIGNATURE")
            # ``f"{name}{descriptor}"``
            from xax_selfhost_general_dll import _pack_begin, _pack_byte, _pack_end

            e.var("sc_nm", e.ld(e.add(p["g"], G_NAME)))
            e.var("sc_nmn", e.ld(e.add(p["g"], G_NAMEN)))
            e.var("sc_ds", e.ld(e.add(p["g"], G_DESC)))
            e.var("sc_dsn", e.ld(e.add(p["g"], G_DESCN)))
            _pack_begin(e, D.T_STR, e.add(p["sc_nmn"], p["sc_dsn"]))
            e.for_("sc_q", 0, p["sc_nmn"], lambda: _pack_byte(e, e.ld(e.add(p["sc_nm"], p["sc_q"]))))
            e.for_("sc_q", 0, p["sc_dsn"], lambda: _pack_byte(e, e.ld(e.add(p["sc_ds"], p["sc_q"]))))
            _pack_end(e)
            D.put(e, D.T_LIST)
            D.put(e, 2)
            for array, count in (("sc_fp", "sc_mp"), ("sc_fr", "sc_mr")):
                D.put(e, D.T_LIST)
                D.put(e, p[count])
                e.for_("sc_q", 0, p[count], lambda array=array: _put_desc_text(e, e.ld(e.add(p[array], p["sc_q"]))))

        D.reject_unless(e, e.both(e.ne(p["sc_ok"], 0), e.ne(p["sc_rok"], 0)), write)
        e.give(1)
    return _function(("t", "g", "codes", "n", "rcode", "rz"), build, tables)


def add_callback_functions(add, tables):
    """After the foreign functions (``jk_intern``, ``jk_parse``) and ``jl_own_method``."""
    for name, builder in (("jk_table", _table_fn), ("jk_cb_signature", _signature_check_fn), ("jk_callbacks", _callbacks_fn)):
        add(name, builder(tables))
