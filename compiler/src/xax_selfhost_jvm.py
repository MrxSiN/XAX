"""S15e.5 (ADR-327): JVM class files and JARs built by an XAX program (stage S15e.5a).

``xax_jvm.compile_jvm_bound_target`` decides, in this order: the entry is a FUNCTION, the target is architecture 5,
a process entry takes and returns only proof values, the closure (direct callees, depth first) with the target's
operation and terminator lists, the methods in closure CID order (``entry`` and ``f<k>``, internal descriptors put
one-slot parameters first), each method's code (``xax_selfhost_jvm_emit``), the shared members, ``main`` for an
executable JAR, the class file, and the deterministic stored JAR.

S15e.5a lowers the integer subset of ``jvm-classfile-v1`` (wrapping arithmetic, bitwise operations, rotations, width
changes, unsigned division and remainder, integer compares, constants, direct calls, resource operations); a float,
a foreign call, a memory or general profile, or anything the bootstrap would reject declines (the bootstrap builds).

Input: the general program's object table (``general_object_table``) followed by one word, 1 for a process entry.
Output: the image record at ``IMAGE_AT``: the status (1), the JAR's length and its bytes packed eight to a word.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation, x86_64_linux_exec_target
from xax_graph_builder import program_store
import xax_selfhost_diagnostics as D
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_general_view import G_BCOUNT, G_BENTRY, G_BLIST, G_CIDX, G_FKEYN, G_LIFT_ENTRY, G_VCOUNT, _globals
from xax_selfhost_jvm_class import (
    B_DATA, B_LEN, P_BYTES, P_COUNT, POOL_CAP, append, append_buf, bdata, blen, buffer, le, literal, method_literal, pool_new, put, text,
    u1, u2, u4, utf8_literal, klass_literal,
)
from xax_selfhost_jvm_code import (
    C_BUF, C_ENDED, C_FIX, C_LABELS, C_LINES, C_NFIX, C_NLINES, C_PENDING, C_POOL, C_READS, C_STORED, C_TARGET, C_VSDESC, C_VSLOT, CODE_CAP,
    D_D, D_F, D_I, D_J, D_NONE, D_REF, M_STATE, _m, _set_m, op,
)
from xax_selfhost_jvm_method import (
    BL_BASE, BL_DEF, BL_INC, BL_LIVE, BL_ORDER, BL_PLACED, BL_REACH, BL_RESOLVED, BL_UP, M_ACROSS, M_ENTRY, M_FRAMED, M_FREED, M_FTYPES,
    M_GEND, M_HINT, M_INTER, M_ISENTRY, M_KEPTNONE, M_LABELN, M_MAXCALL, M_MAXLOC, M_MAXSLOTS, M_NB, M_NEEDS_PK, M_NEXT, M_NFTYPES, M_NN,
    M_NORDER, M_NRET, M_NV, M_ONE, M_PASS, M_PEND, M_RETTYPES, M_SOCC, M_STYPE, M_T, M_TRACK, M_TRAPUSED, M_TYPED, M_WORK, N_COPY, N_ELIM,
    N_LINE, STATE_WORDS, T_CAP, V_KEPT, V_SINGLE, VALUE_TABLES,
)
from xax_selfhost_views_backend import (
    _FN, CID_WORDS, G_ERASED, G_IFACE, G_NI, G_O, G_ORDER, G_PAY, G_REC, G_REFS, G_S, G_SUP, G_SUPT, G_TW, GLOBALS, NI_ENTITY, NI_OP,
    NativeProgram, _at, _call, _cid_at, _cid_less, _cid_words, _find, _g, _kind, _node_info, _ok, _payload_uleb, _reference, _term_end,
    _type_form,
)
from xax_selfhost_x86_64_general import (
    COUNT_AT, FRAME, F_AT, F_BLOCKS, F_FN, F_GRAPH, F_NODES, GENERAL_ARENA_AT, GENERAL_ARENA_END, G_ENTRY, G_FRAMES, G_GROUPOF, G_LALIGN,
    G_LSIZE, G_LSTACK, G_MEMBERS, G_MTAB, ORDER_AT, _group_interface, _proof, _text_at, group_member_tables,
)

STORE_PATH = bootstrap_dir() / "xax_jvm_general.xax"
JVM_ARCHITECTURE = 5
V1_IDENTITY = b"jvm-classfile-v1"
PROFILE_IDENTITIES = (b"jvm-classfile-memory-v1", b"jvm-classfile-general-v1")  # a process entry there is threaded (declined)
J_STATE = 211  # GLOBALS slot: the class state record
(J_POOL, J_ENTRY_INDEX, J_NFN, J_NAMES, J_DESCS, J_ARGS, J_RESULT, J_METHODS, J_NMETHODS, J_STORE, J_STORE_LEN, J_PK, J_PROCESS,
 J_CLASSNAME, J_SCRATCH, J_REFS, J_NREFS, J_TABLE, J_NTABLE, J_TABIX, J_CBG, J_NCBG, J_IFACES, J_NIFACES) = range(24)
J_WORDS = 24
METHOD_WORDS = 13  # kind, fidx, code, code length, max stack, max locals, frames, frame count, frame types, their count, lines, line count, bare frame
(MR_KIND, MR_FIDX, MR_CODE, MR_CLEN, MR_STACK, MR_LOCALS, MR_FRAMES, MR_NFRAMES, MR_FTYPES, MR_NFTYPES, MR_LINES, MR_NLINES, MR_BARE) = range(13)
STORE_CAP = 1 << 24
KIND_FN, KIND_PK, KIND_MAIN, KIND_CB, KIND_INIT = range(5)  # a callback's interface method and ``<init>(I)V`` (ADR-331)
SIGNATURE_CAP = 1024  # a method descriptor's characters (a longer one declines)
VERIFICATION = {D_I: 1, D_J: 2 + 2, 3: 2, 4: 3}  # I 1, J 4, F 2, D 3; Top 0


def _reject(e: E, condition, code: str, rule: str, entity, expected, actual):
    """Unless ``condition``: the bootstrap's rejection ``code``/``rule`` on object ``entity``."""
    def write():
        D.text(e, code)
        D.cid(e, _cid_words(e, entity))
        D.text(e, rule)
        expected()
        actual()
    D.reject_unless(e, condition, write)


def _js(e: E, field: int):
    return e.ld(e.add(e.ld(GLOBALS + J_STATE), field))


def _set_js(e: E, field: int, value):
    e.st(e.add(e.ld(GLOBALS + J_STATE), field), value)


def _store_alloc(e: E, words, name: str):
    """Persistent words for the class (the method store survives the per-method arena resets)."""
    p = e.p
    e.var(name, e.add(_js(e, J_STORE), _js(e, J_STORE_LEN)))
    _ok(e, e.le(e.add(_js(e, J_STORE_LEN), words), STORE_CAP))
    _set_js(e, J_STORE_LEN, e.add(_js(e, J_STORE_LEN), words))
    return p[name]


# -- descriptors ------------------------------------------------------------------------------------------------------------

def _jvm_desc(e: E, type_obj, name: str):
    """``_jvm_type`` into ``name`` (``jk_vdesc``)."""
    from xax_selfhost_jvm_foreign import vdesc

    e.var(name, vdesc(e, type_obj))


def _desc_char(e: E, d):
    """The descriptor letter of ``d`` (``V`` for none)."""
    return e.sel(e.eq(d, D_I), ord("I"), e.sel(e.eq(d, D_J), ord("J"), e.sel(e.eq(d, D_F), ord("F"), e.sel(e.eq(d, D_D), ord("D"), ord("V")))))


def _two(e: E, d):
    return e.either(e.eq(d, D_J), e.eq(d, D_D))


def _signature_fn(tables):
    """Function ``f``'s method descriptor (closure index ``fidx``) into the class state: ``(params)result``, the
    one-slot parameters first unless it is the entry; its argument and result slots."""
    def build(e: E):
        p = e.p
        e.var("sg_i", _call(e, "interface", p["f"]))
        e.var("sg_np", e.ld(e.add(p["sg_i"], 1)))
        e.var("sg_rt", e.add(e.add(p["sg_i"], 2), p["sg_np"]))
        e.var("sg_text", _store_alloc(e, SIGNATURE_CAP, "sg_t"))
        e.var("sg_n", 0)
        e.var("sg_slots", 0)
        e.var("sg_entry", e.flag(e.eq(p["fidx"], _js(e, J_ENTRY_INDEX))))

        def put_char(ch):
            _ok(e, e.lt(p["sg_n"], SIGNATURE_CAP))
            e.st(e.add(p["sg_text"], p["sg_n"]), ch)
            e.set("sg_n", e.add(p["sg_n"], 1))

        def put_desc(d):
            from xax_selfhost_jvm_foreign import ref_text

            e.var("sg_pd", d)
            e.if_(e.lt(p["sg_pd"], D_REF), lambda: put_char(_desc_char(e, p["sg_pd"])), lambda: (
                e.var("sg_rtx", ref_text(e, p["sg_pd"])[0]), e.var("sg_rtn", ref_text(e, p["sg_pd"])[1]),
                e.for_("sg_q", 0, p["sg_rtn"], lambda: put_char(e.ld(e.add(p["sg_rtx"], p["sg_q"]))))))

        put_char(ord("("))
        for wide_pass in (0, 1):
            def parameter(wide_pass=wide_pass):
                _jvm_desc(e, e.ld(e.add(e.add(p["sg_i"], 2), p["sg_k"])), "sg_d")
                take = e.sel(e.ne(p["sg_entry"], 0), e.flag(e.eq(wide_pass, 0)), e.flag(e.eq(e.flag(_two(e, p["sg_d"])), wide_pass)))
                e.if_(e.both(e.ne(p["sg_d"], D_NONE), e.ne(take, 0)), lambda: (put_desc(p["sg_d"]),
                                                                                e.set("sg_slots", e.add(p["sg_slots"], e.sel(_two(e, p["sg_d"]), 2, 1)))))

            e.for_("sg_k", 0, p["sg_np"], parameter)
        put_char(ord(")"))
        # The machine result: at most one (JVM-SINGLE-RESULT: declined); borrowed views given back need heap views (declined).
        e.var("sg_result", D_NONE)
        e.var("sg_count", 0)

        def returned():
            _jvm_desc(e, e.ld(e.add(e.add(p["sg_rt"], 1), p["sg_k"])), "sg_rd")
            e.if_(e.ne(p["sg_rd"], D_NONE), lambda: (e.set("sg_result", p["sg_rd"]), e.set("sg_count", e.add(p["sg_count"], 1))))

        e.for_("sg_k", 0, e.ld(p["sg_rt"]), returned)
        _ok(e, e.le(p["sg_count"], 1))
        put_desc(p["sg_result"])
        e.st(e.add(_js(e, J_DESCS), e.mul(p["fidx"], 2)), p["sg_text"])
        e.st(e.add(_js(e, J_DESCS), e.add(e.mul(p["fidx"], 2), 1)), p["sg_n"])
        e.st(e.add(_js(e, J_ARGS), p["fidx"]), p["sg_slots"])
        e.st(e.add(_js(e, J_RESULT), p["fidx"]), e.sel(e.eq(p["sg_result"], D_NONE), 0, e.sel(_two(e, p["sg_result"]), 2, 1)))
        # The name: ``entry``, else ``f<fidx>``.
        e.var("sg_name", _store_alloc(e, 24, "sg_nm"))
        e.var("sg_nn", 0)

        def name_char(ch):
            e.st(e.add(p["sg_name"], p["sg_nn"]), ch)
            e.set("sg_nn", e.add(p["sg_nn"], 1))

        def entry_name():
            for ch in b"entry":
                name_char(ch)

        def numbered():
            name_char(ord("f"))
            e.var("sg_digits", 1)
            e.while_(lambda: e.le(e.mul(p["sg_digits"], 10), p["fidx"]), lambda: e.set("sg_digits", e.mul(p["sg_digits"], 10)))
            e.while_(lambda: e.lt(0, p["sg_digits"]), lambda: (name_char(e.add(ord("0"), e.urem(e.udiv(p["fidx"], p["sg_digits"]), 10))),
                                                              e.set("sg_digits", e.udiv(p["sg_digits"], 10))))

        e.if_(e.ne(p["sg_entry"], 0), entry_name, numbered)
        e.st(e.add(_js(e, J_NAMES), e.mul(p["fidx"], 2)), p["sg_name"])
        e.st(e.add(_js(e, J_NAMES), e.add(e.mul(p["fidx"], 2), 1)), p["sg_nn"])
        e.give(1)
    return _function(("f", "fidx"), build, tables)


def _own_method_fn(tables):
    """``pool.method(class_name, name, descriptor)``: ``kind`` 0 the shared ``xax$pk(II)J``, 1 closure function
    ``fidx``'s method."""
    from xax_selfhost_jvm_class import _pf

    def build(e: E):
        p = e.p
        pool = _js(e, J_POOL)
        e.var("om_c", _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)))

        def pk():
            e.var("om_n", utf8_literal(e, pool, "xax$pk", "om_pn"))
            e.var("om_d", utf8_literal(e, pool, "(II)J", "om_pd"))
            e.var("om_a", 2)
            e.var("om_r", 2)

        def own():
            e.var("om_n", _call(e, "jp_utf8", pool, e.ld(e.add(_js(e, J_NAMES), e.mul(p["fidx"], 2))), e.ld(e.add(_js(e, J_NAMES), e.add(e.mul(p["fidx"], 2), 1)))))
            e.var("om_d", _call(e, "jp_utf8", pool, e.ld(e.add(_js(e, J_DESCS), e.mul(p["fidx"], 2))), e.ld(e.add(_js(e, J_DESCS), e.add(e.mul(p["fidx"], 2), 1)))))
            e.var("om_a", e.ld(e.add(_js(e, J_ARGS), p["fidx"])))
            e.var("om_r", e.ld(e.add(_js(e, J_RESULT), p["fidx"])))

        e.var("om_n", 0)
        e.var("om_d", 0)
        e.var("om_a", 0)
        e.var("om_r", 0)
        e.if_(e.eq(p["kind"], 0), pk, own)
        e.var("om_nt", _call(e, "jp_ref2", pool, 12, p["om_n"], p["om_d"], 0, 0))
        e.give(_call(e, "jp_ref2", pool, 10, p["om_c"], p["om_nt"], p["om_a"], p["om_r"]))
    return _function(("kind", "fidx"), build, tables)


# -- one method ------------------------------------------------------------------------------------------------------------

def _tables(e: E, n, fields, name: str):
    p = e.p
    for field in fields:
        e.var(name, e.alloc(e.add(n, 2)))
        _ok(e, e.ne(p[name], NONE))
        _set_m(e, field, p[name])


def _analyses(e: E):
    """One pass's analyses (the tracked count sizes the liveness and interference)."""
    p = e.p
    for name in ("jm_constants", "jm_aliases", "jm_needed", "jm_facts", "jm_inlined"):
        _call(e, name)
    e.var("ms_t", _call(e, "jm_tracked"))
    nb = _m(e, M_NB)
    for field, words in ((BL_UP, e.mul(nb, p["ms_t"])), (BL_DEF, e.mul(nb, p["ms_t"])), (BL_LIVE, e.mul(nb, p["ms_t"])),
                         (M_INTER, e.mul(p["ms_t"], p["ms_t"])), (M_ACROSS, p["ms_t"]), (M_FRAMED, p["ms_t"])):
        e.var("ms_a", e.alloc(e.add(words, 2)))
        _ok(e, e.ne(p["ms_a"], NONE))
        _set_m(e, field, p["ms_a"])
    for name in ("jm_liveness", "jm_interference", "jm_hints", "jm_slots"):
        _call(e, name)
    _set_m(e, M_MAXLOC, _m(e, M_GEND))
    _set_m(e, M_SCRATCH_SLOT(), _m(e, M_GEND))


def M_SCRATCH_SLOT():
    from xax_selfhost_jvm_method import M_SCRATCH

    return M_SCRATCH


def _reset_code(e: E):
    p = e.p
    e.st(e.add(_m(e, C_BUF), B_LEN), 0)
    e.for_("rc_l", 0, _m(e, M_LABELN_CAP()), lambda: (e.st(e.add(_m(e, C_LABELS), p["rc_l"]), NONE), e.st(e.add(_m(e, C_TARGET), p["rc_l"]), 0)))
    for field, word in ((C_NFIX, 0), (C_PENDING, NONE), (C_STORED, NONE), (C_NLINES, 0), (C_ENDED, 0), (M_LABELN, 0), (M_TRAPUSED, 0), (M_MAXCALL, 0),
                        (M_ONE, 0)):
        _set_m(e, field, word)


def M_LABELN_CAP():
    from xax_selfhost_jvm_code import C_NLABELS

    return C_NLABELS


def _emit_pass(e: E):
    """The pass's code: 1 when the definite assignment asks for kept parameters (the pass is retried)."""
    p = e.p
    _reset_code(e)
    e.var("ep_retry", _call(e, "je_assignment"))
    e.if_(e.ne(p["ep_retry"], 0), lambda: e.give(1))

    def nop():
        e.var("ep_entered", 0)
        e.for_("ep_bi", 0, _m(e, M_NB), lambda: e.if_(e.both(e.eq(p["ep_bi"], _m(e, M_ENTRY)), e.lt(0, _v_inc(e, p["ep_bi"]))), lambda: e.set("ep_entered", 1)))
        e.if_(e.ne(p["ep_entered"], 0), lambda: op(e, 0x00))

    e.if_(e.eq(blen(e, _m(e, C_BUF)), 0), nop)
    _call(e, "je_layout")
    _call(e, "je_blocks")
    e.give(0)


def _v_inc(e: E, b):
    from xax_selfhost_jvm_method import _v

    return _v(e, BL_INC, b)


def _method_fn(tables):
    """Closure function ``f`` (index ``fidx``): its method code in the method store."""
    from xax_selfhost_general_ranges import _block_at
    from xax_selfhost_general_view import B_NNODES, B_POS, _f

    def build(e: E):
        p = e.p
        e.var("mt_mark", e.hd(H_ARENA))
        _globals(e, G_VCOUNT, 0)
        _globals(e, G_FKEYN, 0)
        e.var("mt_blocks", _call(e, "lift", p["f"], p["fidx"]))
        e.var("mt_n", e.rd(_at(e, G_PAY, e.ld(_call(e, "interface", p["f"])))))
        _globals(e, G_BENTRY, _g(e, G_LIFT_ENTRY))
        e.var("mt_list", e.alloc(e.add(p["mt_n"], 1)))
        _ok(e, e.ne(p["mt_list"], NONE))
        e.for_("mt_q", 0, p["mt_n"], lambda: e.st(e.add(p["mt_list"], p["mt_q"]), e.ld(e.add(p["mt_blocks"], p["mt_q"]))))
        _globals(e, G_BLIST, p["mt_list"])
        _globals(e, G_BCOUNT, p["mt_n"])
        _call(e, "positions")
        # The method state.
        e.var("mt_state", e.alloc(STATE_WORDS + 2))
        _ok(e, e.ne(p["mt_state"], NONE))
        e.st(GLOBALS + M_STATE, p["mt_state"])
        e.for_("mt_k", 0, STATE_WORDS, lambda: e.st(e.add(p["mt_state"], p["mt_k"]), 0))
        nv = _g(e, G_VCOUNT)
        _set_m(e, M_NV, nv)
        _set_m(e, M_NB, p["mt_n"])
        e.var("mt_nn", 0)
        from xax_selfhost_jvm_method import _set_v

        _tables(e, p["mt_n"], (BL_BASE, BL_INC, BL_REACH, BL_RESOLVED, BL_PLACED, BL_ORDER), "mt_bt")
        e.for_("mt_q", 0, p["mt_n"], lambda: (_set_v(e, BL_BASE, p["mt_q"], p["mt_nn"]), e.set("mt_nn", e.add(p["mt_nn"], _f(e, _block_at(e, p["mt_q"]), B_NNODES)))))
        _set_m(e, M_NN, p["mt_nn"])
        _tables(e, nv, (*range(VALUE_TABLES_FIRST(), VALUE_TABLES_FIRST() + len(VALUE_TABLES)), C_VSLOT, C_VSDESC, C_READS), "mt_vt")
        _tables(e, p["mt_nn"], (N_ELIM, N_COPY, N_LINE), "mt_nt")
        e.var("mt_work", e.alloc(WORK()))
        _ok(e, e.ne(p["mt_work"], NONE))
        _set_m(e, M_WORK, p["mt_work"])
        _tables(e, T_CAP, (M_TRACK,), "mt_tr")
        _set_m(e, M_MAXSLOTS, e.add(e.mul(nv, 2), 16))
        _tables(e, e.add(e.mul(nv, 2), 16), (M_STYPE, M_FREED, M_TYPED, M_FTYPES), "mt_st")
        _tables(e, 2 << 16, (M_SOCC,), "mt_so")
        _tables(e, 2 << 17, (M_HINT,), "mt_hi")
        _set_m(e, M_ENTRY, _f(e, _g(e, G_BENTRY), B_POS))
        _set_m(e, M_ISENTRY, e.flag(e.eq(p["fidx"], _js(e, J_ENTRY_INDEX))))
        # The return types' descriptors.
        e.var("mt_i", _call(e, "interface", p["f"]))
        e.var("mt_rt", e.add(e.add(p["mt_i"], 2), e.ld(e.add(p["mt_i"], 1))))
        e.var("mt_nret", e.ld(p["mt_rt"]))
        _set_m(e, M_NRET, p["mt_nret"])
        _tables(e, p["mt_nret"], (M_RETTYPES,), "mt_rtt")
        e.for_("mt_k", 0, p["mt_nret"], lambda: (_jvm_desc(e, e.ld(e.add(e.add(p["mt_rt"], 1), p["mt_k"])), "mt_rd"),
                                                 e.st(e.add(_m(e, M_RETTYPES), p["mt_k"]), p["mt_rd"])))
        # The code state.
        buffer(e, "mt_code", CODE_CAP)
        _set_m(e, C_BUF, p["mt_code"])
        e.var("mt_nl", e.add(e.add(e.mul(p["mt_n"], 2), 2), p["mt_nn"]))
        _set_m(e, M_LABELN_CAP(), p["mt_nl"])
        _tables(e, p["mt_nl"], (C_LABELS, C_TARGET), "mt_lb")
        _tables(e, e.mul(e.add(e.mul(p["mt_nn"], 4), e.mul(p["mt_n"], 4)), 2), (C_FIX,), "mt_fx")
        _tables(e, e.mul(e.add(p["mt_nn"], 2), 2), (C_LINES,), "mt_ln")
        _set_m(e, C_POOL, _js(e, J_POOL))
        _call(e, "jm_types")
        # Pass 1 counts each value's reads in a throwaway pool (the pool is restored after it).
        from xax_selfhost_jvm_class import _pf

        pool = _js(e, J_POOL)
        e.var("mt_pc", _pf(e, pool, P_COUNT))
        e.var("mt_pb", blen(e, _pf(e, pool, P_BYTES)))
        _set_m(e, M_PASS, 1)
        _set_m(e, M_KEPTNONE, 1)
        e.for_("mt_v", 0, nv, lambda: (_set_v(e, C_READS, p["mt_v"], 0), _set_v(e, V_SINGLE, p["mt_v"], 0), _set_v(e, V_KEPT, p["mt_v"], 0)))
        _analyses(e)
        _ok(e, e.eq(_emit_pass_call(e), 0))  # the counting pass's KeepParameters escapes the bootstrap: declined
        _call(e, "je_finish")
        e.st(e.add(pool, P_COUNT), p["mt_pc"])
        e.st(e.add(_pf(e, pool, P_BYTES), B_LEN), p["mt_pb"])
        from xax_selfhost_jvm_method import _v

        e.for_("mt_v", 0, nv, lambda: (_set_v(e, V_SINGLE, p["mt_v"], e.flag(e.eq(_v(e, C_READS, p["mt_v"]), 1))), _set_v(e, C_READS, p["mt_v"], 0)))
        # Pass 2, retried while the definite assignment keeps parameters.
        _set_m(e, M_PASS, 2)
        _set_m(e, M_KEPTNONE, 0)
        _set_m(e, M_NEEDS_PK, 0)  # the counting pass's needs are a scratch set; every pass-2 attempt's are the class's
        e.var("mt_retry", 1)
        e.while_(lambda: e.ne(p["mt_retry"], 0), lambda: (_analyses(e), e.set("mt_retry", _emit_pass_call(e))))
        e.if_(e.ne(_m(e, M_NEEDS_PK), 0), lambda: _set_js(e, J_PK, 1))
        _call(e, "je_finish")
        _call(e, "jk_record", KIND_FN, p["fidx"])
        e.set_hd(H_ARENA, p["mt_mark"])
        e.give(1)
    return _function(("f", "fidx"), build, tables)


def VALUE_TABLES_FIRST():
    from xax_selfhost_jvm_method import V_DESC

    return V_DESC


def WORK():
    from xax_selfhost_jvm_emit import WORK_WORDS

    return WORK_WORDS


def _emit_pass_call(e: E):
    return _call(e, "jk_emit_pass")


def _emit_pass_fn(tables):
    def build(e: E):
        _emit_pass(e)
    return _function((), build, tables)


# -- the finished code, the frames, the method record ------------------------------------------------------------------------

def _finish_fn(tables):
    """``code.finish``: the line table without repeated starts, the fixups bound (JVM-BRANCH-RANGE, JVM-METHOD-CODE-SIZE:
    declined), the frame offsets (sorted, distinct) of the branch targets, and the operand stack's depth."""
    from xax_selfhost_jvm_method import M_FOLLOW, M_SCRATCH

    def build(e: E):
        p = e.p
        # Lines: a repeated start keeps its last line.
        e.var("fn_lines", _m(e, C_LINES))
        e.var("fn_out", 0)

        def line():
            e.var("fn_pc", e.ld(e.add(p["fn_lines"], e.mul(p["fn_i"], 2))))
            e.var("fn_ln", e.ld(e.add(p["fn_lines"], e.add(e.mul(p["fn_i"], 2), 1))))
            e.if_(e.both(e.lt(0, p["fn_out"]), e.eq(e.ld(e.add(p["fn_lines"], e.mul(e.sub(p["fn_out"], 1), 2))), p["fn_pc"])),
                  lambda: e.st(e.add(p["fn_lines"], e.add(e.mul(e.sub(p["fn_out"], 1), 2), 1)), p["fn_ln"]), lambda: (
                      e.st(e.add(p["fn_lines"], e.mul(p["fn_out"], 2)), p["fn_pc"]), e.st(e.add(p["fn_lines"], e.add(e.mul(p["fn_out"], 2), 1)), p["fn_ln"]),
                      e.set("fn_out", e.add(p["fn_out"], 1))))

        e.for_("fn_i", 0, _m(e, C_NLINES), line)
        _set_m(e, C_NLINES, p["fn_out"])
        # Fixups.
        e.var("fn_code", bdata(e, _m(e, C_BUF)))

        def fixup():
            e.var("fn_at", e.ld(e.add(_m(e, C_FIX), e.mul(p["fn_k"], 2))))
            e.var("fn_to", e.ld(e.add(_m(e, C_LABELS), e.ld(e.add(_m(e, C_FIX), e.add(e.mul(p["fn_k"], 2), 1))))))
            _ok(e, e.ne(p["fn_to"], NONE))
            e.var("fn_delta", e.sub(p["fn_to"], p["fn_at"]))
            e.var("fn_biased", e.add(p["fn_delta"], 0x8000))
            _ok(e, e.lt(e.and_(p["fn_biased"], (1 << 64) - 1), 0x10000))  # JVM-BRANCH-RANGE
            e.st(e.add(p["fn_code"], e.add(p["fn_at"], 1)), e.and_(e.udiv(e.and_(p["fn_delta"], 0xFFFF), 256), 255))
            e.st(e.add(p["fn_code"], e.add(p["fn_at"], 2)), e.and_(p["fn_delta"], 255))

        e.for_("fn_k", 0, _m(e, C_NFIX), fixup)
        _ok(e, e.le(blen(e, _m(e, C_BUF)), 0xFFFF))  # JVM-METHOD-CODE-SIZE
        # Frames: the targets' offsets, sorted and distinct.
        e.var("fn_frames", e.alloc(e.add(_m(e, M_LABELN_CAP()), 2)))
        _ok(e, e.ne(p["fn_frames"], NONE))
        e.var("fn_nf", 0)

        def target():
            e.var("fn_pos", e.ld(e.add(_m(e, C_LABELS), p["fn_l"])))
            _ok(e, e.ne(p["fn_pos"], NONE))  # a target never marked: the bootstrap's KeyError
            e.var("fn_j", p["fn_nf"])
            e.var("fn_dup", 0)
            e.for_("fn_q", 0, p["fn_nf"], lambda: e.if_(e.eq(e.ld(e.add(p["fn_frames"], p["fn_q"])), p["fn_pos"]), lambda: e.set("fn_dup", 1)))

            def insert():
                e.while_(lambda: e.both(e.lt(0, p["fn_j"]), e.lt(p["fn_pos"], e.ld(e.add(p["fn_frames"], e.sub(p["fn_j"], 1))))), lambda: (
                    e.st(e.add(p["fn_frames"], p["fn_j"]), e.ld(e.add(p["fn_frames"], e.sub(p["fn_j"], 1)))), e.set("fn_j", e.sub(p["fn_j"], 1))))
                e.st(e.add(p["fn_frames"], p["fn_j"]), p["fn_pos"])
                e.set("fn_nf", e.add(p["fn_nf"], 1))

            e.if_(e.eq(p["fn_dup"], 0), insert)

        e.for_("fn_l", 0, _m(e, M_LABELN_CAP()), lambda: e.if_(e.ne(e.ld(e.add(_m(e, C_TARGET), p["fn_l"])), 0), target))
        _set_m(e, FINISH_FRAMES(), p["fn_frames"])
        _set_m(e, FINISH_NFRAMES(), p["fn_nf"])
        e.var("fn_depth", _call(e, "jc_depth", p["fn_frames"], p["fn_nf"]))
        e.var("fn_stack", 8)
        e.if_(e.lt(p["fn_stack"], e.add(_m(e, M_MAXCALL), 2)), lambda: e.set("fn_stack", e.add(_m(e, M_MAXCALL), 2)))
        e.if_(e.lt(p["fn_stack"], p["fn_depth"]), lambda: e.set("fn_stack", p["fn_depth"]))
        _set_m(e, FINISH_STACK(), p["fn_stack"])
        e.give(1)
    return _function((), build, tables)


def FINISH_FRAMES():
    from xax_selfhost_jvm_method import M_NEEDZ

    return M_NEEDZ


def FINISH_NFRAMES():
    from xax_selfhost_jvm_method import M_PSLOTS

    return M_PSLOTS


def FINISH_STACK():
    from xax_selfhost_jvm_method import M_FOLLOW

    return M_FOLLOW


def _copy_words(e: E, source, count, name: str):
    """``count`` words copied to the method store; its address into ``name``."""
    p = e.p
    _store_alloc(e, e.add(count, 1), name)
    e.for_(f"{name}_k", 0, count, lambda: e.st(e.add(p[name], p[f"{name}_k"]), e.ld(e.add(source, p[f"{name}_k"]))))
    return p[name]


def _record_fn(tables):
    """A method record (``kind``, ``fidx``) with the finished code, frames, frame types and lines."""
    def build(e: E):
        p = e.p
        e.var("rc_i", _js(e, J_NMETHODS))
        _ok(e, e.lt(p["rc_i"], 1 << 16))
        e.var("rc_at", e.add(_js(e, J_METHODS), e.mul(p["rc_i"], METHOD_WORDS)))
        e.st(e.add(p["rc_at"], MR_KIND), p["kind"])
        e.st(e.add(p["rc_at"], MR_FIDX), p["fidx"])
        e.st(e.add(p["rc_at"], MR_CODE), _copy_words(e, bdata(e, _m(e, C_BUF)), blen(e, _m(e, C_BUF)), "rc_code"))
        e.st(e.add(p["rc_at"], MR_CLEN), blen(e, _m(e, C_BUF)))
        e.st(e.add(p["rc_at"], MR_STACK), _m(e, FINISH_STACK()))
        e.st(e.add(p["rc_at"], MR_LOCALS), _m(e, M_MAXLOC))
        e.st(e.add(p["rc_at"], MR_FRAMES), _copy_words(e, _m(e, FINISH_FRAMES()), _m(e, FINISH_NFRAMES()), "rc_fr"))
        e.st(e.add(p["rc_at"], MR_NFRAMES), _m(e, FINISH_NFRAMES()))
        e.st(e.add(p["rc_at"], MR_FTYPES), _copy_words(e, _m(e, M_FTYPES), _m(e, M_NFTYPES), "rc_ft"))
        e.st(e.add(p["rc_at"], MR_NFTYPES), _m(e, M_NFTYPES))
        e.st(e.add(p["rc_at"], MR_LINES), _copy_words(e, _m(e, C_LINES), e.mul(_m(e, C_NLINES), 2), "rc_ln"))
        e.st(e.add(p["rc_at"], MR_NLINES), _m(e, C_NLINES))
        e.var("rc_trap", e.ld(e.add(_m(e, C_LABELS), e.mul(_m(e, M_NB), 2))))
        e.st(e.add(p["rc_at"], MR_BARE), e.sel(e.ne(_m(e, M_TRAPUSED), 0), p["rc_trap"], NONE))
        _set_js(e, J_NMETHODS, e.add(p["rc_i"], 1))
        e.give(1)
    return _function(("kind", "fidx"), build, tables)


def _fixed_method(e: E, kind: int, code: list, max_stack: int, max_locals: int):
    """A record for a generated member whose code is ``code`` (ints, or ``("pool", ...)`` placeholders already
    resolved by the caller into ``jf_*`` variables)."""


# -- the class file and the JAR ---------------------------------------------------------------------------------------------

def _serialize_fn(tables):
    """``_serialize_method`` of method record ``k`` into ``out``."""
    from xax_selfhost_jvm_method import ST_TOP

    def build(e: E):
        p = e.p
        pool = _js(e, J_POOL)
        e.var("se_at", e.add(_js(e, J_METHODS), e.mul(p["k"], METHOD_WORDS)))

        def f(field):
            return e.ld(e.add(p["se_at"], field))

        buffer(e, "se_attrs", 1 << 20)
        e.var("se_nattrs", 0)

        def frames():
            buffer(e, "se_body", 1 << 18)
            u2(e, p["se_body"], f(MR_NFRAMES))
            e.var("se_prev", NONE)
            # ``locals_blob`` first, as the bootstrap makes it (its Class entries) before any frame.
            buffer(e, "se_lb", 1 << 16)

            def verification():
                from xax_selfhost_jvm_foreign import ref_text

                e.var("se_ty", e.ld(e.add(f(MR_FTYPES), p["se_t"])))

                def reference():
                    e.var("se_rx", ref_text(e, p["se_ty"])[0])
                    e.var("se_rn", ref_text(e, p["se_ty"])[1])
                    e.var("se_l", e.flag(e.eq(e.ld(p["se_rx"]), ord("L"))))  # ``Lname;`` names ``name``; an array itself
                    u1(e, p["se_lb"], 7)
                    u2(e, p["se_lb"], _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, e.add(p["se_rx"], p["se_l"]), e.sub(p["se_rn"], e.mul(p["se_l"], 2)))))

                e.if_(e.lt(p["se_ty"], D_REF), lambda: u1(e, p["se_lb"], e.sel(e.eq(p["se_ty"], D_I), 1, e.sel(e.eq(p["se_ty"], D_J), 4, e.sel(
                    e.eq(p["se_ty"], D_F), 2, e.sel(e.eq(p["se_ty"], D_D), 3, 0))))), reference)

            e.for_("se_t", 0, f(MR_NFTYPES), verification)

            def entry():
                e.var("se_off", e.ld(e.add(f(MR_FRAMES), p["se_i"])))
                e.var("se_delta", e.sub(e.sub(p["se_off"], e.sel(e.eq(p["se_prev"], NONE), e.c((1 << 64) - 1), p["se_prev"])), 1))

                def full():
                    u1(e, p["se_body"], 255)
                    u2(e, p["se_body"], p["se_delta"])
                    u2(e, p["se_body"], f(MR_NFTYPES))
                    append_buf(e, p["se_body"], p["se_lb"])
                    u2(e, p["se_body"], 0)

                e.if_(e.eq(p["se_off"], f(MR_BARE)), lambda: (u1(e, p["se_body"], 255), u2(e, p["se_body"], p["se_delta"]), u2(e, p["se_body"], 0),
                                                            u2(e, p["se_body"], 0)), lambda: e.if_(
                    e.eq(p["se_prev"], NONE), full, lambda: e.if_(e.lt(p["se_delta"], 64), lambda: u1(e, p["se_body"], p["se_delta"]),
                                                                  lambda: (u1(e, p["se_body"], 251), u2(e, p["se_body"], p["se_delta"])))))
                e.set("se_prev", p["se_off"])

            e.for_("se_i", 0, f(MR_NFRAMES), entry)
            u2(e, p["se_attrs"], utf8_literal(e, pool, "StackMapTable", "se_smt"))
            u4(e, p["se_attrs"], blen(e, p["se_body"]))
            append_buf(e, p["se_attrs"], p["se_body"])
            e.set("se_nattrs", e.add(p["se_nattrs"], 1))

        e.if_(e.ne(f(MR_NFRAMES), 0), frames)

        def lines():
            buffer(e, "se_lb", 1 << 18)
            u2(e, p["se_lb"], f(MR_NLINES))
            e.for_("se_i", 0, f(MR_NLINES), lambda: (u2(e, p["se_lb"], e.ld(e.add(f(MR_LINES), e.mul(p["se_i"], 2)))),
                                                    e.var("se_ln", e.ld(e.add(f(MR_LINES), e.add(e.mul(p["se_i"], 2), 1)))),
                                                    u2(e, p["se_lb"], e.sel(e.lt(0xFFFF, p["se_ln"]), 0xFFFF, p["se_ln"]))))
            u2(e, p["se_attrs"], utf8_literal(e, pool, "LineNumberTable", "se_lnt"))
            u4(e, p["se_attrs"], blen(e, p["se_lb"]))
            append_buf(e, p["se_attrs"], p["se_lb"])
            e.set("se_nattrs", e.add(p["se_nattrs"], 1))

        e.if_(e.ne(f(MR_NLINES), 0), lines)
        buffer(e, "se_code", 1 << 20)
        u2(e, p["se_code"], f(MR_STACK))
        u2(e, p["se_code"], f(MR_LOCALS))
        u4(e, p["se_code"], f(MR_CLEN))
        append(e, p["se_code"], f(MR_CODE), f(MR_CLEN))
        u2(e, p["se_code"], 0)
        u2(e, p["se_code"], p["se_nattrs"])
        append_buf(e, p["se_code"], p["se_attrs"])
        e.var("se_ci", utf8_literal(e, pool, "Code", "se_cd"))
        # The name and descriptor.
        e.var("se_kind", f(MR_KIND))

        def names():
            e.if_(e.eq(p["se_kind"], KIND_FN), lambda: (
                e.var("se_fi", f(MR_FIDX)),
                e.var("se_ni", _call(e, "jp_utf8", pool, e.ld(e.add(_js(e, J_NAMES), e.mul(p["se_fi"], 2))), e.ld(e.add(_js(e, J_NAMES), e.add(e.mul(p["se_fi"], 2), 1))))),
                e.var("se_di", _call(e, "jp_utf8", pool, e.ld(e.add(_js(e, J_DESCS), e.mul(p["se_fi"], 2))), e.ld(e.add(_js(e, J_DESCS), e.add(e.mul(p["se_fi"], 2), 1)))))))
            e.if_(e.eq(p["se_kind"], KIND_PK), lambda: (e.var("se_ni", utf8_literal(e, pool, "xax$pk", "se_pn")), e.var("se_di", utf8_literal(e, pool, "(II)J", "se_pd"))))
            e.if_(e.eq(p["se_kind"], KIND_MAIN), lambda: (e.var("se_ni", utf8_literal(e, pool, "main", "se_mn")),
                                                          e.var("se_di", utf8_literal(e, pool, "([Ljava/lang/String;)V", "se_md"))))

            def callback():
                from xax_selfhost_jvm_callback import G_DESC, G_DESCN, G_NAME, G_NAMEN, GROUP_WORDS

                e.var("se_g", e.add(_js(e, J_CBG), e.mul(f(MR_FIDX), GROUP_WORDS)))
                e.var("se_ni", _call(e, "jp_utf8", pool, e.ld(e.add(p["se_g"], G_NAME)), e.ld(e.add(p["se_g"], G_NAMEN))))
                e.var("se_di", _call(e, "jp_utf8", pool, e.ld(e.add(p["se_g"], G_DESC)), e.ld(e.add(p["se_g"], G_DESCN))))

            e.if_(e.eq(p["se_kind"], KIND_CB), callback)
            e.if_(e.eq(p["se_kind"], KIND_INIT), lambda: (e.var("se_ni", utf8_literal(e, pool, "<init>", "se_in")),
                                                          e.var("se_di", utf8_literal(e, pool, "(I)V", "se_id"))))

        e.var("se_ni", 0)
        e.var("se_di", 0)
        names()
        u2(e, p["out"], e.sel(e.either(e.eq(p["se_kind"], KIND_CB), e.eq(p["se_kind"], KIND_INIT)), 0x0001, 0x0009))
        u2(e, p["out"], p["se_ni"])
        u2(e, p["out"], p["se_di"])
        u2(e, p["out"], 1)
        u2(e, p["out"], p["se_ci"])
        u4(e, p["out"], blen(e, p["se_code"]))
        append_buf(e, p["out"], p["se_code"])
        e.give(1)
    return _function(("k", "out"), build, tables)


def _class_fn(tables):
    """The shared members, ``main`` for an executable JAR, then ``_class_file`` and ``_jar`` into the image record."""
    from xax_selfhost_general_image import IMAGE_AT, IMAGE_END

    def build(e: E):
        p = e.p
        pool = _js(e, J_POOL)
        # The callbacks make their pool entries before the shared members (``_callbacks`` runs first) but follow them.
        e.var("cl_cb0", _js(e, J_NMETHODS))
        _call(e, "jk_callbacks")
        e.var("cl_ncb", e.sub(_js(e, J_NMETHODS), p["cl_cb0"]))

        # The shared xax$pk member: iload_0; Integer.toUnsignedLong; iload_1; i2l; bipush 32; lshl; lor; lreturn.
        def pk():
            e.var("cl_tu", method_literal(e, pool, "java/lang/Integer", "toUnsignedLong", "(I)J", "cl_tu_m"))
            _fixed(e, KIND_PK, [0x1A, 0xB8, ("cl_tu", 2), 0x1B, 0x85, 0x10, 32, 0x79, 0x81, 0xAD], 5, 2)

            def rotate():
                # The pk record (last) moves before the callback records.
                e.var("cl_methods_at", _js(e, J_METHODS))
                e.var("cl_last", e.sub(_js(e, J_NMETHODS), 1))
                e.var("cl_tmp", e.alloc(METHOD_WORDS + 1))
                _ok(e, e.ne(p["cl_tmp"], NONE))
                e.for_("cl_w", 0, METHOD_WORDS, lambda: e.st(e.add(p["cl_tmp"], p["cl_w"]), e.ld(e.add(e.add(p["cl_methods_at"], e.mul(p["cl_last"], METHOD_WORDS)), p["cl_w"]))))
                e.var("cl_r", p["cl_last"])
                e.while_(lambda: e.lt(p["cl_cb0"], p["cl_r"]), lambda: (
                    e.for_("cl_w", 0, METHOD_WORDS, lambda: e.st(e.add(e.add(p["cl_methods_at"], e.mul(p["cl_r"], METHOD_WORDS)), p["cl_w"]),
                                                                e.ld(e.add(e.add(p["cl_methods_at"], e.mul(e.sub(p["cl_r"], 1), METHOD_WORDS)), p["cl_w"])))),
                    e.set("cl_r", e.sub(p["cl_r"], 1))))
                e.for_("cl_w", 0, METHOD_WORDS, lambda: e.st(e.add(e.add(p["cl_methods_at"], e.mul(p["cl_cb0"], METHOD_WORDS)), p["cl_w"]), e.ld(e.add(p["cl_tmp"], p["cl_w"]))))

            e.if_(e.ne(p["cl_ncb"], 0), rotate)

        e.if_(e.ne(_js(e, J_PK), 0), pk)

        def main():
            e.var("cl_en", _call(e, "jl_own_method", 1, _js(e, J_ENTRY_INDEX)))
            _fixed(e, KIND_MAIN, [0xB8, ("cl_en", 2), 0xB1], 0, 1)

        e.if_(e.ne(_js(e, J_PROCESS), 0), main)
        # The class file: this class, the super class, the source file attribute's names, the methods (they finish the
        # pool), then the head before them.
        e.var("cl_this", _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)))
        # The interfaces the callbacks implement, then the private final ``k`` field (ADR-331).
        buffer(e, "cl_ifs", 1 << 10)
        e.for_("cl_q", 0, _js(e, J_NIFACES), lambda: u2(e, p["cl_ifs"], _call(e, "jp_ref1", pool, 7, _call(
            e, "jp_utf8", pool, e.ld(e.add(_js(e, J_IFACES), e.mul(p["cl_q"], 2))), e.ld(e.add(_js(e, J_IFACES), e.add(e.mul(p["cl_q"], 2), 1)))))))
        buffer(e, "cl_fields", 64)
        e.var("cl_nf", e.flag(e.lt(0, _js(e, J_NCBG))))

        def field_k():
            u2(e, p["cl_fields"], 0x0012)
            u2(e, p["cl_fields"], utf8_literal(e, pool, "k", "cl_fk"))
            u2(e, p["cl_fields"], utf8_literal(e, pool, "I", "cl_fi"))
            u2(e, p["cl_fields"], 0)

        e.if_(e.ne(p["cl_nf"], 0), field_k)
        e.var("cl_super", klass_literal(e, pool, "java/lang/Object", "cl_obj"))
        e.var("cl_sf", utf8_literal(e, pool, "SourceFile", "cl_sfn"))
        e.var("cl_sv", utf8_literal(e, pool, "XAX", "cl_sfv"))
        buffer(e, "cl_methods", 1 << 23)
        e.for_("cl_k", 0, _js(e, J_NMETHODS), lambda: _call(e, "jk_serialize", p["cl_k"], p["cl_methods"]))
        buffer(e, "cl_class", 1 << 23)
        put(e, p["cl_class"], 0xCAFEBABE, 4)
        u2(e, p["cl_class"], 0)
        u2(e, p["cl_class"], 61)
        from xax_selfhost_jvm_class import _pf

        u2(e, p["cl_class"], _pf(e, pool, P_COUNT))
        append_buf(e, p["cl_class"], _pf(e, pool, P_BYTES))
        for word in (0x0031, p["cl_this"], p["cl_super"], _js(e, J_NIFACES)):
            u2(e, p["cl_class"], word)
        append_buf(e, p["cl_class"], p["cl_ifs"])
        u2(e, p["cl_class"], p["cl_nf"])
        append_buf(e, p["cl_class"], p["cl_fields"])
        u2(e, p["cl_class"], _js(e, J_NMETHODS))
        append_buf(e, p["cl_class"], p["cl_methods"])
        u2(e, p["cl_class"], 1)
        u2(e, p["cl_class"], p["cl_sf"])
        u4(e, p["cl_class"], 2)
        u2(e, p["cl_class"], p["cl_sv"])
        # The JAR: the manifest, then the class, stored, each with its CRC-32; the central directory; the end record.
        buffer(e, "cl_mf", 256)
        text(e, p["cl_mf"], "Manifest-Version: 1.0\r\nCreated-By: xax-jvm-classfile-v1\r\n")

        def main_class():
            text(e, p["cl_mf"], "Main-Class: ")
            e.for_("cl_q", 0, 21, lambda: (e.var("cl_ch", e.ld(e.add(_js(e, J_CLASSNAME), p["cl_q"]))), u1(e, p["cl_mf"], e.sel(e.eq(p["cl_ch"], ord("/")), ord("."), p["cl_ch"]))))
            text(e, p["cl_mf"], "\r\n")

        e.if_(e.ne(_js(e, J_PROCESS), 0), main_class)
        text(e, p["cl_mf"], "\r\n")
        buffer(e, "cl_name", 64)
        e.for_("cl_q", 0, 21, lambda: u1(e, p["cl_name"], e.ld(e.add(_js(e, J_CLASSNAME), p["cl_q"]))))
        text(e, p["cl_name"], ".class")
        literal(e, "cl_mfn", "META-INF/MANIFEST.MF")
        buffer(e, "cl_jar", 1 << 24)
        buffer(e, "cl_cd", 1 << 12)
        entries = (("cl_mf", "cl_mfn_buf"), ("cl_class", "cl_name"))
        buffer(e, "cl_mfn_buf", 64)
        append(e, p["cl_mfn_buf"], p["cl_mfn"], p["cl_mfn_n"])
        for data, name in entries:
            e.var("cl_off", blen(e, p["cl_jar"]))
            e.var("cl_crc", _call(e, "jb_crc", bdata(e, p[data]), blen(e, p[data])))
            for buf, central in ((p["cl_jar"], False), (p["cl_cd"], True)):
                le(e, buf, 0x02014B50 if central else 0x04034B50, 4)
                if central:
                    le(e, buf, 20, 2)  # version made by
                le(e, buf, 20, 2)  # version needed
                le(e, buf, 0, 2)  # flags
                le(e, buf, 0, 2)  # stored
                le(e, buf, 0, 2)  # time
                le(e, buf, 0x21, 2)  # 1980-01-01
                le(e, buf, p["cl_crc"], 4)
                le(e, buf, blen(e, p[data]), 4)
                le(e, buf, blen(e, p[data]), 4)
                le(e, buf, blen(e, p[name]), 2)
                le(e, buf, 0, 2)  # extra
                if central:
                    le(e, buf, 0, 2)  # comment
                    le(e, buf, 0, 2)  # disk
                    le(e, buf, 0, 2)  # internal attributes
                    le(e, buf, 0o100644 << 16, 4)
                    le(e, buf, p["cl_off"], 4)
                append_buf(e, buf, p[name])
                if not central:
                    append_buf(e, buf, p[data])
        e.var("cl_cdoff", blen(e, p["cl_jar"]))
        append_buf(e, p["cl_jar"], p["cl_cd"])
        le(e, p["cl_jar"], 0x06054B50, 4)
        le(e, p["cl_jar"], 0, 4)
        le(e, p["cl_jar"], 2, 2)
        le(e, p["cl_jar"], 2, 2)
        le(e, p["cl_jar"], blen(e, p["cl_cd"]), 4)
        le(e, p["cl_jar"], p["cl_cdoff"], 4)
        le(e, p["cl_jar"], 0, 2)
        # The record.
        e.var("cl_n", blen(e, p["cl_jar"]))
        _ok(e, e.lt(e.add(IMAGE_AT, e.add(e.udiv(p["cl_n"], 8), 4)), IMAGE_END))
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, p["cl_n"])
        e.var("cl_jd", bdata(e, p["cl_jar"]))

        def word():
            e.var("cl_w", 0)
            e.var("cl_wt", 1)
            e.for_("cl_b", 0, 8, lambda: (e.var("cl_ix", e.add(e.mul(p["cl_q"], 8), p["cl_b"])), e.if_(e.lt(p["cl_ix"], p["cl_n"]), lambda: e.set(
                "cl_w", e.add(p["cl_w"], e.mul(e.ld(e.add(p["cl_jd"], p["cl_ix"])), p["cl_wt"])))), e.set("cl_wt", e.mul(p["cl_wt"], 256))))
            e.st(e.add(IMAGE_AT + 2, p["cl_q"]), p["cl_w"])

        e.for_("cl_q", 0, e.udiv(e.add(p["cl_n"], 7), 8), word)
        e.give(1)
    return _function((), build, tables)


def _add_record(e: E, fields: dict):
    """Append a method record with ``fields`` (``MR_*`` -> word)."""
    p = e.p
    e.var("ar_i", _js(e, J_NMETHODS))
    e.var("ar_at", e.add(_js(e, J_METHODS), e.mul(p["ar_i"], METHOD_WORDS)))
    for field, word in fields.items():
        e.st(e.add(p["ar_at"], field), word)
    _set_js(e, J_NMETHODS, e.add(p["ar_i"], 1))


def _fixed(e: E, kind: int, code: list, max_stack: int, max_locals: int):
    """A record for a generated member (code bytes, a ``(name, 2)`` item a pool index variable)."""
    p = e.p
    n = sum(item[1] if isinstance(item, tuple) else 1 for item in code)
    e.var("fx_code", _store_alloc(e, n + 1, "fx_c"))
    k = 0
    for item in code:
        if isinstance(item, tuple):
            e.st(e.add(p["fx_code"], k), e.and_(e.udiv(p[item[0]], 256), 255))
            e.st(e.add(p["fx_code"], k + 1), e.and_(p[item[0]], 255))
            k += 2
        else:
            e.st(e.add(p["fx_code"], k), item)
            k += 1
    e.var("fx_i", _js(e, J_NMETHODS))
    e.var("fx_at", e.add(_js(e, J_METHODS), e.mul(p["fx_i"], METHOD_WORDS)))
    for field, word in ((MR_KIND, kind), (MR_FIDX, 0), (MR_CODE, p["fx_code"]), (MR_CLEN, n), (MR_STACK, max_stack), (MR_LOCALS, max_locals),
                        (MR_FRAMES, 0), (MR_NFRAMES, 0), (MR_FTYPES, 0), (MR_NFTYPES, 0), (MR_LINES, 0), (MR_NLINES, 0), (MR_BARE, NONE)):
        e.st(e.add(p["fx_at"], field), word)
    _set_js(e, J_NMETHODS, e.add(p["fx_i"], 1))


# -- the front end ----------------------------------------------------------------------------------------------------------

def _node(tables):
    """The closure's check of the node just read (``G_NI``) in graph ``g``: the target's operation list (another
    declines), and a direct callee or an addressed function to visit (NONE-1: none)."""
    def build(e: E):
        p = e.p
        ni = _g(e, G_NI)
        e.var("nraw", e.ld(e.add(ni, NI_OP)))
        _ok(e, e.ne(p["nraw"], int(Operation.CALL_GROUP_MEMBER)))  # recursion groups: the bootstrap (S15e.5a)
        op_ = p["nraw"]
        supported = e.both(e.lt(op_, 256), e.ne(_at(e, G_SUP, e.sel(e.lt(op_, 256), op_, 0)), 0))
        _ok(e, supported)  # JVM-OP-TARGET-SUPPORTED: the bootstrap's
        e.var("nvisit", NONE - 1)

        def address():
            # ``pending.append(node.entity)``: callable through the function table (ADR-159), erased or not.
            e.var("na", _reference(e, p["g"], e.ld(e.add(ni, NI_ENTITY))))
            _ok(e, e.both(e.ne(p["na"], NONE), e.eq(_kind(e, p["na"]), int(Kind.FUNCTION))))
            e.if_(e.eq(e.ld(e.add(_g(e, G_TW), p["na"])), 0), lambda: e.set("nvisit", p["na"]))

        e.if_(e.eq(op_, int(Operation.FUNCTION_ADDRESS)), address)

        def callee():
            entity = e.ld(e.add(ni, NI_ENTITY))
            _ok(e, e.ne(entity, NONE))
            e.var("nc", _reference(e, p["g"], entity))
            _ok(e, e.both(e.ne(p["nc"], NONE), e.eq(_kind(e, p["nc"]), int(Kind.FUNCTION))))
            fresh = e.eq(e.ld(e.add(_g(e, G_TW), p["nc"])), 0)
            e.if_(e.both(fresh, e.eq(_call(e, "erased", p["nc"]), 0)), lambda: e.set("nvisit", p["nc"]))

        e.if_(e.eq(op_, int(Operation.CALL_DIRECT)), callee)
        e.give(p["nvisit"])
    return _function(("g", "f"), build, tables)


def _push(e: E, f):
    p = e.p
    e.var("vf", f)
    e.st(e.add(_g(e, G_TW), p["vf"]), 1)
    e.st(e.add(_g(e, G_ORDER), _g(e, G_MEMBERS)), p["vf"])
    e.st(GLOBALS + G_MEMBERS, e.add(_g(e, G_MEMBERS), 1))
    e.var("vg", e.ld(_call(e, "interface", p["vf"])))
    _ok(e, e.eq(_kind(e, p["vg"]), int(Kind.GRAPH_FRAGMENT)))
    e.var("vs", _at(e, G_PAY, p["vg"]))
    e.var("vframe", e.add(_g(e, G_FRAMES), e.mul(p["depth"], FRAME)))
    blocks = e.rd(p["vs"])
    _ok(e, e.ne(blocks, 0))
    first = e.add(p["vs"], 2)
    nodes_at = e.add(e.add(first, 1), e.rd(first))
    for field, value in ((F_FN, p["vf"]), (F_GRAPH, p["vg"]), (F_BLOCKS, blocks), (F_NODES, e.rd(nodes_at)), (F_AT, e.add(nodes_at, 1))):
        e.st(e.add(p["vframe"], field), value)
    e.set("depth", e.add(p["depth"], 1))


def _frontend(tables):
    from xax_selfhost_general_view import G_AUDIT, G_CAND, G_FKEYS, G_GEXT, G_STAMP, G_VIEW_OUT, VIEW_AT
    from xax_selfhost_aarch64_lower import VCAP
    from xax_selfhost_general_view import G_VEXT, G_VTYPE, G_VPROD, G_VREAD, G_VMULTI, G_VFWD, G_VPARAM, G_VSTAMP, G_VSTAMP2, G_VPOS

    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        S = e.rd(0)
        e.st(GLOBALS + G_S, S)
        e.var("ra", 1 + CID_WORDS)

        def skip():
            references = e.rd(e.add(p["ra"], 1))
            payload_at = e.add(e.add(e.add(p["ra"], 2), e.mul(references, CID_WORDS)), CID_WORDS)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))

        e.for_("o", 0, e.add(S, 1), skip)
        e.var("extras_at", p["ra"])
        e.var("total", e.add(e.add(S, 1), e.rd(p["extras_at"])))
        total = p["total"]
        for slot in (G_REC, G_PAY, G_TW, G_ERASED, G_IFACE, G_ORDER, G_REFS, G_LSIZE, G_LALIGN, G_LSTACK, G_MTAB, G_GROUPOF):
            table = e.alloc(e.add(total, 2))
            _ok(e, e.ne(table, NONE))
            e.st(GLOBALS + slot, table)
        frames = e.alloc(e.mul(e.add(total, 2), FRAME))
        _ok(e, e.ne(frames, NONE))
        e.st(GLOBALS + G_FRAMES, frames)
        for slot, size in ((G_SUP, 256), (G_SUPT, 8), (G_NI, 8)):
            table = e.alloc(size)
            _ok(e, e.ne(table, NONE))
            e.st(GLOBALS + slot, table)
            e.for_("q", 0, size, lambda table=table: e.st(e.add(table, p["q"]), 0))

        def record():
            o = p["o"]
            e.st(e.add(_g(e, G_REC), o), p["ra"])
            references = e.rd(e.add(p["ra"], 1))
            payload_at = e.add(e.add(e.add(p["ra"], 2), e.mul(references, CID_WORDS)), CID_WORDS)
            e.st(e.add(_g(e, G_PAY), o), e.add(payload_at, 1))
            for slot in (G_ERASED, G_IFACE, G_MTAB, G_GROUPOF):
                e.st(e.add(_g(e, slot), o), NONE)
            for slot in (G_TW, G_LSIZE, G_LALIGN):
                e.st(e.add(_g(e, slot), o), 0)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))
            e.if_(e.eq(o, S), lambda: e.set("ra", e.add(p["ra"], 1)))

        e.set("ra", 1 + CID_WORDS)
        e.for_("o", 0, total, record)
        e.var("ext_at", p["ra"])
        e.st(GLOBALS + G_O, S)
        e.var("target", e.call(_FN["find"], _cid_at(e, S)))
        e.if_(e.eq(p["target"], NONE), lambda: e.set("target", S))
        e.st(GLOBALS + G_O, total)
        O = _g(e, G_O)

        def resolve():
            o = p["o"]
            count = e.rd(e.add(_at(e, G_REC, o), 1))
            e.var("refs", e.alloc(e.add(count, 1)))
            _ok(e, e.ne(p["refs"], NONE))
            e.st(e.add(_g(e, G_REFS), o), p["refs"])
            first = e.add(_at(e, G_REC, o), 2)
            e.for_("k", 0, count, lambda: e.st(e.add(p["refs"], p["k"]), e.call(_FN["find"], e.add(first, e.mul(p["k"], CID_WORDS)))))

        e.for_("o", 0, O, resolve)
        group_member_tables(e, O)

        # The target: architecture 5, a JVM class-file profile (v1, memory or general: they lower alike; the memory
        # members and the threaded launcher decline), its operation and terminator lists.
        from xax_selfhost_x86_64_general import _bytes_equal

        target = p["target"]
        _ok(e, e.eq(_kind(e, target), int(Kind.TARGET)))
        e.var("ta", _at(e, G_PAY, target))
        e.var("t_idlen", _payload_uleb(e, "ta"))
        e.var("t_v1", e.flag(_bytes_equal(e, p["ta"], p["t_idlen"], V1_IDENTITY)))
        _ok(e, e.either(e.ne(p["t_v1"], 0), *(_bytes_equal(e, p["ta"], p["t_idlen"], identity) for identity in PROFILE_IDENTITIES)))
        e.set("ta", e.add(p["ta"], p["t_idlen"]))
        fields = [_payload_uleb(e, "ta") for _ in range(6)]
        e.var("t_arch", fields[1])
        _ok(e, e.eq(p["t_arch"], JVM_ARCHITECTURE))
        for table in (G_SUP, G_SUPT):
            e.var("tcount", _payload_uleb(e, "ta"))
            e.for_("q", 0, p["tcount"], lambda table=table: (lambda value: (_ok(e, e.lt(value, 256 if table == G_SUP else 8)), e.st(e.add(_g(e, table), value), 1)))(
                _payload_uleb(e, "ta")))

        # The entry: a FUNCTION (JVM-ENTRY-FUNCTION: the bootstrap's).
        e.var("entry", e.call(_FN["find"], 1))
        _ok(e, e.ne(p["entry"], NONE))
        entry = p["entry"]
        def kind_name():
            for kind in Kind:
                e.if_(e.eq(_kind(e, entry), int(kind)), lambda kind=kind: D.text(e, kind.name))

        _ok(e, e.either(*(e.eq(_kind(e, entry), int(kind)) for kind in Kind)))
        _reject(e, e.eq(_kind(e, entry), int(Kind.FUNCTION)), "XAX.JVM.FUNCTION", "JVM-ENTRY-FUNCTION", entry,
                lambda: D.text(e, Kind.FUNCTION.name), kind_name)
        e.st(GLOBALS + G_ENTRY, entry)

        # The sections after the objects: pointer extents (skipped), the audit word, the trap heads (skipped), the
        # process-entry flag.
        e.var("sx", p["ext_at"])
        e.var("sx_n", e.rd(p["sx"]))
        e.set("sx", e.add(p["sx"], 1))
        e.for_("q", 0, p["sx_n"], lambda: e.set("sx", e.add(e.add(e.add(p["sx"], CID_WORDS), 1), e.mul(e.rd(e.add(p["sx"], CID_WORDS)), 5))))
        e.set("sx", e.add(p["sx"], 1))  # the audit word
        e.var("sx_t", e.rd(p["sx"]))
        e.set("sx", e.add(p["sx"], 1))

        def trap_graph():
            e.var("sx_b", e.rd(e.add(p["sx"], CID_WORDS)))
            e.set("sx", e.add(e.add(p["sx"], CID_WORDS), 1))
            e.for_("q2", 0, p["sx_b"], lambda: e.set("sx", e.add(e.add(p["sx"], 2), e.rd(e.add(p["sx"], 1)))))

        e.for_("q", 0, p["sx_t"], trap_graph)
        e.var("process", e.rd(p["sx"]))
        _ok(e, e.either(e.eq(p["process"], 0), e.ne(p["t_v1"], 0)))  # ``threaded``: the launcher (declined)

        # The class state.
        e.var("js", e.alloc(J_WORDS + 2))
        _ok(e, e.ne(p["js"], NONE))
        e.st(GLOBALS + J_STATE, p["js"])
        e.var("js_store", e.alloc(STORE_CAP + 2))
        _ok(e, e.ne(p["js_store"], NONE))
        _set_js(e, J_STORE, p["js_store"])
        _set_js(e, J_STORE_LEN, 0)
        _set_js(e, J_PROCESS, p["process"])
        _set_js(e, J_PK, 0)
        _set_js(e, J_NMETHODS, 0)
        from xax_selfhost_jvm_foreign import REFS_CAP

        _set_js(e, J_REFS, _store_alloc(e, 2 * REFS_CAP + 2, "js_refs"))
        _set_js(e, J_NREFS, 0)

        def contract():
            """``validate_process_entry``: no machine parameter or result (each a bits value of at most 64 bits here;
            any other machine type, or a second machine result, declines: the bootstrap decides)."""
            e.var("pe_i", _call(e, "interface", entry))
            e.var("pe_np", e.ld(e.add(p["pe_i"], 1)))
            e.var("pe_rt", e.add(e.add(p["pe_i"], 2), p["pe_np"]))
            e.var("pe_b", _call(e, "borrowed", entry))
            e.var("pe_mp", 0)
            e.var("pe_mr", 0)

            def param(q):
                return e.ld(e.add(e.add(p["pe_i"], 2), q))

            def ret(q):
                return e.ld(e.add(e.add(p["pe_rt"], 1), q))

            def machine_ret(q):
                return e.both(e.not_(_proof(e, ret(q))), e.eq(e.ld(e.add(p["pe_b"], q)), NONE))

            def width(t):
                e.var("pe_at", e.add(_at(e, G_PAY, t), 1))
                return _payload_uleb(e, "pe_at")

            def bits(t):
                e.var("pe_t", t)
                _ok(e, e.eq(_type_form(e, p["pe_t"]), 1))
                _ok(e, e.le(width(p["pe_t"]), 64))

            e.for_("q", 0, p["pe_np"], lambda: e.if_(e.not_(_proof(e, param(p["q"]))), lambda: (bits(param(p["q"])), e.set("pe_mp", e.add(p["pe_mp"], 1)))))
            e.for_("q", 0, e.ld(p["pe_rt"]), lambda: e.if_(machine_ret(p["q"]), lambda: (bits(ret(p["q"])), e.set("pe_mr", e.add(p["pe_mr"], 1)))))
            _ok(e, e.le(p["pe_mr"], 1))  # JVM-SINGLE-RESULT: the bootstrap's

            def descriptor(t):
                e.var("pe_t", t)
                e.if_(e.le(width(p["pe_t"]), 32), lambda: D.text(e, "I"), lambda: D.text(e, "J"))

            def actual():
                D.put(e, D.T_LIST)
                D.put(e, 2)
                D.put(e, D.T_LIST)
                D.put(e, p["pe_mp"])
                e.for_("q", 0, p["pe_np"], lambda: e.if_(e.not_(_proof(e, param(p["q"]))), lambda: descriptor(param(p["q"]))))
                D.put(e, D.T_LIST)
                D.put(e, p["pe_mr"])
                e.for_("q", 0, e.ld(p["pe_rt"]), lambda: e.if_(machine_ret(p["q"]), lambda: descriptor(ret(p["q"]))))

            _reject(e, e.both(e.eq(p["pe_mp"], 0), e.eq(p["pe_mr"], 0)), "XAX.JVM.ENTRY", "JVM-PROCESS-ENTRY-CONTRACT", entry,
                    lambda: D.text(e, "fn(proof...) -> (proof...)"), actual)

        e.if_(e.ne(p["process"], 0), contract)  # JVM-PROCESS-ENTRY-CONTRACT: the bootstrap's

        # The closure, depth first; then the CID order.
        e.st(GLOBALS + G_MEMBERS, 0)
        e.var("depth", 0)
        _push(e, entry)

        def step():
            e.var("fr", e.add(_g(e, G_FRAMES), e.mul(e.sub(p["depth"], 1), FRAME)))
            fr = p["fr"]

            def node():
                e.st(e.add(fr, F_NODES), e.sub(e.ld(e.add(fr, F_NODES)), 1))
                e.var("nat0", e.ld(e.add(fr, F_AT)))
                e.st(e.add(fr, F_AT), _call(e, "node_info", p["nat0"]))
                e.var("visit", _call(e, "jf_node", e.ld(e.add(fr, F_GRAPH)), e.ld(e.add(fr, F_FN))))
                e.if_(e.ne(p["visit"], NONE - 1), lambda: _push(e, p["visit"]))

            def terminator():
                e.var("tat", e.ld(e.add(fr, F_AT)))
                e.var("tkind", e.rd(p["tat"]))
                _ok(e, e.both(e.lt(p["tkind"], 8), e.ne(_at(e, G_SUPT, e.sel(e.lt(p["tkind"], 8), p["tkind"], 0)), 0)))
                e.set("tat", _call(e, "term_end", p["tat"]))
                e.st(e.add(fr, F_BLOCKS), e.sub(e.ld(e.add(fr, F_BLOCKS)), 1))

                def next_block():
                    e.var("tnodes", e.add(e.add(p["tat"], 1), e.rd(p["tat"])))
                    e.st(e.add(fr, F_NODES), e.rd(p["tnodes"]))
                    e.st(e.add(fr, F_AT), e.add(p["tnodes"], 1))

                e.if_(e.ne(e.ld(e.add(fr, F_BLOCKS)), 0), next_block, lambda: e.set("depth", e.sub(p["depth"], 1)))

            e.if_(e.ne(e.ld(e.add(fr, F_NODES)), 0), node, terminator)

        e.while_(lambda: e.ne(p["depth"], 0), step)
        order = _g(e, G_ORDER)
        e.var("members", _g(e, G_MEMBERS))

        def insert():
            e.var("item", e.ld(e.add(order, p["s"])))
            e.var("j", p["s"])
            before = lambda: e.both(e.lt(0, p["j"]), _cid_less(e, _cid_at(e, p["item"]), _cid_at(e, e.ld(e.add(order, e.sub(p["j"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(order, p["j"]), e.ld(e.add(order, e.sub(p["j"], 1)))), e.set("j", e.sub(p["j"], 1))))
            e.st(e.add(order, p["j"]), p["item"])

        e.for_("s", 1, p["members"], insert)
        e.st(COUNT_AT, p["members"])
        e.for_("q", 0, p["members"], lambda: [e.st(e.add(e.add(ORDER_AT, e.mul(p["q"], CID_WORDS)), k), word)
                                              for k, word in enumerate(_cid_words(e, e.ld(e.add(order, p["q"]))))])

        # The view tables (``lift``), the closure indices, the class name ``xax/P`` + the entry CID's first 16 hex digits.
        for slot in (G_VEXT, G_VTYPE, G_VPROD, G_VREAD, G_VMULTI, G_VFWD, G_VPARAM, G_VSTAMP, G_VSTAMP2, G_VPOS):
            table = e.alloc(VCAP + 1)
            _ok(e, e.ne(table, NONE))
            _globals(e, slot, table)
        keys = e.alloc(VCAP + 2)
        _ok(e, e.ne(keys, NONE))
        _globals(e, G_FKEYS, keys)
        for slot in (G_GEXT, G_CIDX, G_CAND):
            table = e.alloc(e.add(total, 2))
            _ok(e, e.ne(table, NONE))
            _globals(e, slot, table)
            e.for_("vp_o", 0, total, lambda table=table: e.st(e.add(table, p["vp_o"]), NONE))
        _globals(e, G_STAMP, 1)
        _globals(e, G_AUDIT, 0)
        _globals(e, G_VIEW_OUT, VIEW_AT)
        e.for_("vp_q", 0, p["members"], lambda: e.st(e.add(_g(e, G_CIDX), e.ld(e.add(order, p["vp_q"]))), p["vp_q"]))
        _set_js(e, J_NFN, p["members"])
        _set_js(e, J_ENTRY_INDEX, e.ld(e.add(_g(e, G_CIDX), entry)))
        for field in (J_NAMES, J_DESCS):
            e.var("js_t", e.alloc(e.add(e.mul(p["members"], 2), 2)))
            _ok(e, e.ne(p["js_t"], NONE))
            _set_js(e, field, p["js_t"])
        for field in (J_ARGS, J_RESULT):
            e.var("js_t", e.alloc(e.add(p["members"], 2)))
            _ok(e, e.ne(p["js_t"], NONE))
            _set_js(e, field, p["js_t"])
        from xax_selfhost_jvm_callback import GROUPS_CAP

        e.var("js_m", e.alloc(e.add(e.mul(e.add(p["members"], 6 + GROUPS_CAP), METHOD_WORDS), 2)))
        _ok(e, e.ne(p["js_m"], NONE))
        _set_js(e, J_METHODS, p["js_m"])
        e.var("js_name", _store_alloc(e, 24, "js_nm"))
        for k, ch in enumerate(b"xax/P"):
            e.st(e.add(p["js_name"], k), ch)
        e.var("js_cw", _cid_words(e, entry)[0])
        e.for_("q", 0, 16, lambda: (e.var("js_nib", e.and_(e.udiv(p["js_cw"], e.sel(e.lt(p["q"], 16), _nibble_power(e, p["q"]), 1)), 15)),
                                    e.st(e.add(p["js_name"], e.add(5, p["q"])), e.add(p["js_nib"], e.sel(e.lt(p["js_nib"], 10), ord("0"), ord("a") - 10)))))
        _set_js(e, J_CLASSNAME, p["js_name"])
        pool_new(e, "js_pool")
        _set_js(e, J_POOL, p["js_pool"])
        e.for_("q", 0, p["members"], lambda: _call(e, "jk_signature", e.ld(e.add(order, p["q"])), p["q"]))
        _call(e, "jk_table")  # ``_indirect_calls``' function table and the callback groups (ADR-331)
        # Each method, in closure order.
        e.for_("q", 0, p["members"], lambda: _call(e, "jk_method", e.ld(e.add(order, p["q"])), p["q"]))
        _call(e, "jk_class")
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


def _nibble_power(e: E, q):
    """``16 ** (15 - q)``: the first CID word's ``q``-th hex digit (most significant first)."""
    return _call(e, "jm_pow2", e.mul(e.sub(15, q), 4))


def build_jvm_program():
    """``(reader, function)``: the JVM program's store and its entry."""
    from xax_selfhost_aarch64_lower import add_lower_functions as add_view_functions_a64
    from xax_selfhost_jvm_class import add_class_functions
    from xax_selfhost_jvm_code import add_code_functions
    from xax_selfhost_jvm_emit import add_emit_functions
    from xax_selfhost_jvm_lower import add_lower_functions
    from xax_selfhost_jvm_method import add_method_functions

    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("find", _find(tables))
    add("text_at", _text_at(tables))
    add("node_info", _node_info(tables))
    add("term_end", _term_end(tables))
    add("interface", _group_interface(tables))
    from xax_selfhost_views_backend import _borrowed, _erased

    add("erased", _erased(tables))
    add("borrowed", _borrowed(tables))
    from xax_selfhost_general_view import _candidate, _lift, _node_callee, _positions, _replace_uses, _resolve

    for name, builder in (("lift", _lift), ("resolve", _resolve), ("replace_uses", _replace_uses), ("node_callee", _node_callee),
                          ("candidate", _candidate), ("positions", _positions)):
        add(name, builder(tables))
    add("jf_node", _node(tables))
    add_class_functions(add, tables)
    add_code_functions(add, tables)
    from xax_selfhost_jvm_foreign import add_foreign_functions

    add_foreign_functions(add, tables)
    add_method_functions(add, tables)
    add("jk_signature", _signature_fn(tables))
    add("jl_own_method", _own_method_fn(tables))
    from xax_selfhost_jvm_callback import add_callback_functions

    add_callback_functions(add, tables)
    add_lower_functions(add, tables)
    add_emit_functions(add, tables)
    add("jk_emit_pass", _emit_pass_fn(tables))
    add("je_finish", _finish_fn(tables))
    add("jk_record", _record_fn(tables))
    add("jk_method", _method_fn(tables))
    add("jk_serialize", _serialize_fn(tables))
    add("jk_class", _class_fn(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_jvm_program, "jvm-general")
load_jvm_program = _PROGRAM.load
write_jvm_store = _PROGRAM.write
OPT_OUT = "XAX_JVM_GENERAL_PYTHON"


def native_jvm():
    return _PROGRAM.native(OPT_OUT)


def jvm_with_xax(reader, function_cid: bytes, target_object, *, process_entry: bool = False, required: bool = False) -> bytes | None:
    """The JAR the XAX program builds for a verified store, or None when it cannot run or declines (unless
    ``required``)."""
    import xax_native
    from xax_compiler import XaxError, fail
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_general_image import IMAGE_AT
    from xax_selfhost_x86_64_general import general_object_table

    native = native_jvm()
    table = None if native is None else general_object_table(reader, function_cid, target_object)
    jar = None
    if table is not None:
        words = list(table[0]) + [int(process_entry)]

        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None, decode_diagnostic(read)
            head = read(IMAGE_AT, 2)
            if head[0] != 1:
                return None, None
            packed = read(IMAGE_AT + 2, (head[1] + 7) // 8)
            return b"".join(word.to_bytes(8, "little") for word in packed)[:head[1]], None

        outcome = native.run(words, collect)
        jar, diagnostic = outcome if outcome is not None else (None, None)
        if diagnostic is not None:
            raise XaxError(diagnostic)
    if jar is None:
        if native is not None:
            xax_native.declined("jvm-general", 1)
        if required:
            fail("XAX.JVM.GENERAL", function_cid.hex(), "JVM-XAX-GENERAL", "built by the XAX JVM program", "unavailable or declined")
    return jar


def jvm_jar(reader, function_cid: bytes, target_object, *, process_entry: bool = False, frontend: str = "auto") -> bytes:
    """``build``'s JAR for a JVM target (S15e.5, ADR-327): the XAX JVM program's where it runs and decides
    (``"auto"``; ``"xax"`` requires it), else ``compile_jvm_bound_target``'s.  With ``XAX_GENERAL_FRONTEND_DIFF=1``
    the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_jvm import compile_jvm_bound_target

    def reference() -> bytes:
        return compile_jvm_bound_target(reader, function_cid, target_object, process_entry=process_entry).jar

    if frontend == "python":
        return reference()
    jar = jvm_with_xax(reader, function_cid, target_object, process_entry=process_entry, required=frontend == "xax")
    if jar is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15e.5: the bootstrap rejects ({error.diagnostic.rule}) a JAR the XAX program wrote") from error
        if jar != expected:
            raise AssertionError("S15e.5 JARs disagree")
    return jar
