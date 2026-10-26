"""S15e.5h (ADR-336): ``xax_jvm._indirect_calls`` in the XAX JVM program (ADR-159).

A function pointer is the table index of an addressed function (1-based, CID order; ``jk_table``).  Each indirect-call
contract (CID order) has a dispatcher ``xax$i<k>(index, args...)`` that calls the addressed function of exactly the
contract's types with that index, and traps for any other index.  A call lowers to the index, the machine arguments
in order, and ``invokestatic`` of its contract's dispatcher.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_view import N_GRAPH, N_NOPS, N_NRES, N_OPSAT, _f, _operand, _output
from xax_selfhost_jvm_code import D_D, D_F, D_I, D_J, D_NONE, D_REF, LOAD, RETURN, SHORT_LOCAL, _pick, kind
from xax_selfhost_views_backend import G_PAY, _at, _call, _ok, _payload_uleb, _reference

CONTRACTS_CAP = 256
SIGNATURE_CAP = 1024


def _js(e: E, field: int):
    from xax_selfhost_jvm import _js as js

    return js(e, field)


def _set_js(e: E, field: int, value):
    from xax_selfhost_jvm import _set_js as set_js

    set_js(e, field, value)


def collect_contract(e: E, contract):
    """``contracts.setdefault``: the contract object, first seen once (sorted by CID after the walk)."""
    from xax_selfhost_jvm import J_CONTRACTS, J_NCONTRACTS

    p = e.p
    e.var("cc_c", contract)
    _ok(e, e.ne(p["cc_c"], NONE))
    e.var("cc_seen", 0)
    e.for_("cc_k", 0, _js(e, J_NCONTRACTS), lambda: e.if_(e.eq(e.ld(e.add(_js(e, J_CONTRACTS), p["cc_k"])), p["cc_c"]), lambda: e.set("cc_seen", 1)))

    def add():
        _ok(e, e.lt(_js(e, J_NCONTRACTS), CONTRACTS_CAP))
        e.st(e.add(_js(e, J_CONTRACTS), _js(e, J_NCONTRACTS)), p["cc_c"])
        _set_js(e, J_NCONTRACTS, e.add(_js(e, J_NCONTRACTS), 1))

    e.if_(e.eq(p["cc_seen"], 0), add)


def contract_types(e: E, contract, name: str):
    """``_decode_call_contract``'s inputs and outputs: ``name`` a record [n inputs, inputs..., n outputs, outputs...]."""
    p = e.p
    e.var(f"{name}_c", contract)
    e.var(f"{name}_at", _at(e, G_PAY, p[f"{name}_c"]))
    e.var(f"{name}_ni", _payload_uleb(e, f"{name}_at"))
    e.var(name, e.alloc(e.add(p[f"{name}_ni"], 66)))
    _ok(e, e.ne(p[name], NONE))
    e.st(p[name], p[f"{name}_ni"])
    e.for_(f"{name}_k", 0, p[f"{name}_ni"], lambda: e.st(e.add(e.add(p[name], 1), p[f"{name}_k"]), _reference(e, p[f"{name}_c"], _payload_uleb(e, f"{name}_at"))))
    e.var(f"{name}_no", _payload_uleb(e, f"{name}_at"))
    _ok(e, e.le(p[f"{name}_no"], 64))
    e.var(f"{name}_o", e.add(e.add(p[name], 1), p[f"{name}_ni"]))
    e.st(p[f"{name}_o"], p[f"{name}_no"])
    e.for_(f"{name}_k", 0, p[f"{name}_no"], lambda: e.st(e.add(e.add(p[f"{name}_o"], 1), p[f"{name}_k"]), _reference(e, p[f"{name}_c"], _payload_uleb(e, f"{name}_at"))))
    return p[name]


def _signatures_fn(tables):
    """Sort the contracts by CID; each dispatcher's descriptor ``(I`` + the machine inputs + ``)`` + the machine output
    (more than one machine output: views given back may be elided, declined), its argument and result slots."""
    from xax_selfhost_jvm import J_CONTRACTS, J_DISPATCH, J_NCONTRACTS, _desc_char, _store_alloc, _two
    from xax_selfhost_jvm_foreign import ref_text, vdesc
    from xax_selfhost_views_backend import _cid_at
    from xax_selfhost_jvm import _cid_less

    def build(e: E):
        p = e.p
        n = _js(e, J_NCONTRACTS)
        e.var("ds_list", _js(e, J_CONTRACTS))

        def insert():
            e.var("ds_item", e.ld(e.add(p["ds_list"], p["ds_s"])))
            e.var("ds_j", p["ds_s"])
            before = lambda: e.both(e.lt(0, p["ds_j"]), _cid_less(e, _cid_at(e, p["ds_item"]), _cid_at(e, e.ld(e.add(p["ds_list"], e.sub(p["ds_j"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["ds_list"], p["ds_j"]), e.ld(e.add(p["ds_list"], e.sub(p["ds_j"], 1)))), e.set("ds_j", e.sub(p["ds_j"], 1))))
            e.st(e.add(p["ds_list"], p["ds_j"]), p["ds_item"])

        e.for_("ds_s", 1, n, insert)
        # Per contract: descriptor text, length, argument slots, result slots, the types record.
        e.var("ds_out", _store_alloc(e, e.add(e.mul(n, 5), 1), "ds_o"))
        _set_js(e, J_DISPATCH, p["ds_out"])

        def one():
            e.var("ds_t", contract_types(e, e.ld(e.add(p["ds_list"], p["ds_k"])), "ds_ty"))
            e.var("ds_text", _store_alloc(e, SIGNATURE_CAP, "ds_tx"))
            e.var("ds_n", 0)
            e.var("ds_slots", 1)

            def put_char(ch):
                _ok(e, e.lt(p["ds_n"], SIGNATURE_CAP))
                e.st(e.add(p["ds_text"], p["ds_n"]), ch)
                e.set("ds_n", e.add(p["ds_n"], 1))

            def put_desc(d):
                e.var("ds_pd", d)
                e.if_(e.lt(p["ds_pd"], D_REF), lambda: put_char(_desc_char(e, p["ds_pd"])), lambda: (
                    e.var("ds_rtx", ref_text(e, p["ds_pd"])[0]), e.var("ds_rtn", ref_text(e, p["ds_pd"])[1]),
                    e.for_("ds_q", 0, p["ds_rtn"], lambda: put_char(e.ld(e.add(p["ds_rtx"], p["ds_q"]))))))

            put_char(ord("("))
            put_char(ord("I"))

            def parameter():
                e.var("ds_d", vdesc(e, e.ld(e.add(e.add(p["ds_t"], 1), p["ds_q2"]))))
                e.if_(e.ne(p["ds_d"], D_NONE), lambda: (put_desc(p["ds_d"]), e.set("ds_slots", e.add(p["ds_slots"], e.sel(_two(e, p["ds_d"]), 2, 1)))))

            e.for_("ds_q2", 0, e.ld(p["ds_t"]), parameter)
            put_char(ord(")"))
            e.var("ds_o", e.add(e.add(p["ds_t"], 1), e.ld(p["ds_t"])))
            e.var("ds_result", D_NONE)
            e.var("ds_count", 0)
            e.for_("ds_q2", 0, e.ld(p["ds_o"]), lambda: (e.var("ds_rd", vdesc(e, e.ld(e.add(e.add(p["ds_o"], 1), p["ds_q2"])))), e.if_(
                e.ne(p["ds_rd"], D_NONE), lambda: (e.set("ds_result", p["ds_rd"]), e.set("ds_count", e.add(p["ds_count"], 1))))))
            _ok(e, e.le(p["ds_count"], 1))
            put_desc(p["ds_result"])
            e.var("ds_at", e.add(p["ds_out"], e.mul(p["ds_k"], 5)))
            for k, word in enumerate((p["ds_text"], p["ds_n"], p["ds_slots"], e.sel(e.eq(p["ds_result"], D_NONE), 0, e.sel(_two(e, p["ds_result"]), 2, 1)),
                                      p["ds_t"])):
                e.st(e.add(p["ds_at"], k), word)

        e.for_("ds_k", 0, n, one)
        e.give(1)
    return _function((), build, tables)


def _dispatcher_ref_fn(tables):
    """``pool.method(class_name, f"xax$i{k}", descriptor)``."""
    from xax_selfhost_jvm import J_CLASSNAME, J_DISPATCH, J_POOL

    def build(e: E):
        p = e.p
        pool = _js(e, J_POOL)
        e.var("dr_at", e.add(_js(e, J_DISPATCH), e.mul(p["k"], 5)))
        e.var("dr_c", _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)))
        e.var("dr_name", e.alloc(32))
        _ok(e, e.ne(p["dr_name"], NONE))
        for q, ch in enumerate(b"xax$i"):
            e.st(e.add(p["dr_name"], q), ch)
        e.var("dr_nn", e.add(5, _decimal(e, p["dr_name"], 5, p["k"])))
        e.var("dr_n", _call(e, "jp_utf8", pool, p["dr_name"], p["dr_nn"]))
        e.var("dr_d", _call(e, "jp_utf8", pool, e.ld(p["dr_at"]), e.ld(e.add(p["dr_at"], 1))))
        e.var("dr_nt", _call(e, "jp_ref2", pool, 12, p["dr_n"], p["dr_d"], 0, 0))
        e.give(_call(e, "jp_ref2", pool, 10, p["dr_c"], p["dr_nt"], e.ld(e.add(p["dr_at"], 2)), e.ld(e.add(p["dr_at"], 3))))
    return _function(("k",), build, tables)


def _decimal(e: E, out, at, value):
    """``str(value)`` at ``out + at``; its length."""
    p = e.p
    e.var("dc_v", value)
    e.var("dc_p", 1)
    e.var("dc_n", 1)
    e.while_(lambda: e.le(e.mul(p["dc_p"], 10), p["dc_v"]), lambda: (e.set("dc_p", e.mul(p["dc_p"], 10)), e.set("dc_n", e.add(p["dc_n"], 1))))
    e.for_("dc_q", 0, p["dc_n"], lambda: (e.st(e.add(out, e.add(at, p["dc_q"])), e.add(ord("0"), e.urem(e.udiv(p["dc_v"], p["dc_p"]), 10))),
                                          e.set("dc_p", e.udiv(p["dc_p"], 10))))
    return p["dc_n"]


def contract_number(e: E, contract):
    """The contract's place in CID order."""
    from xax_selfhost_jvm import J_CONTRACTS, J_NCONTRACTS

    p = e.p
    e.var("cn_c", contract)
    e.var("cn_k", NONE)
    e.for_("cn_q", 0, _js(e, J_NCONTRACTS), lambda: e.if_(e.eq(e.ld(e.add(_js(e, J_CONTRACTS), p["cn_q"])), p["cn_c"]), lambda: e.set("cn_k", p["cn_q"])))
    _ok(e, e.ne(p["cn_k"], NONE))
    return p["cn_k"]


def indirect_node(e: E, node):
    """``CALL_INDIRECT``: the index, the machine arguments in order, the dispatcher; the one machine result kept."""
    from xax_selfhost_jvm_lower import K_DISPATCH, K_GET, K_OP, K_PUT, _sdesc, _slot
    from xax_selfhost_jvm_memory import Fwd
    from xax_selfhost_jvm_method import M_MAXCALL, V_NEEDED, _desc, _pick_slots, _v
    from xax_selfhost_jvm_code import _m, _set_m

    p = e.p
    e.var("ic_k", contract_number(e, _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1)))))
    e.var("ic_slots", 1)
    e.for_("ic_q", 1, _f(e, node, N_NOPS), lambda: e.if_(e.ne(_desc(e, _operand(e, node, p["ic_q"])), D_NONE), lambda: e.set(
        "ic_slots", e.add(p["ic_slots"], _pick_slots(e, _desc(e, _operand(e, node, p["ic_q"])))))))
    e.if_(e.lt(_m(e, M_MAXCALL), p["ic_slots"]), lambda: _set_m(e, M_MAXCALL, p["ic_slots"]))
    # The machine results: at most one (views given back declined with the contract's second machine output).
    e.var("ic_res", NONE)
    e.var("ic_nres", 0)
    e.for_("ic_r", 0, _f(e, node, N_NRES), lambda: (e.var("ic_rv", _output(e, node, p["ic_r"])), e.if_(e.ne(_slot(e, p["ic_rv"]), NONE), lambda: (
        e.if_(e.eq(p["ic_res"], NONE), lambda: e.set("ic_res", p["ic_rv"])), e.set("ic_nres", e.add(p["ic_nres"], 1))))))
    _ok(e, e.le(p["ic_nres"], 1))
    s = Fwd(e)

    def operands():
        e.var("ic_q2", _f(e, node, N_NOPS))
        e.while_(lambda: e.lt(1, p["ic_q2"]), lambda: (e.set("ic_q2", e.sub(p["ic_q2"], 1)), e.if_(
            e.ne(_desc(e, _operand(e, node, p["ic_q2"])), D_NONE), lambda: _call(e, "jl_push", K_GET, _operand(e, node, p["ic_q2"]), 0, 0, 0))))

    s(K_GET, _operand(e, node, 0))
    s.do(operands)
    s(K_DISPATCH, p["ic_k"])
    s.when(lambda: e.ne(p["ic_res"], NONE), lambda t: t.when(lambda: e.ne(_v(e, V_NEEDED, p["ic_res"]), 0), lambda u: u(K_PUT, p["ic_res"]),
                                                             lambda u: u(K_OP, e.sel(e.eq(_pick_slots(e, _sdesc(e, p["ic_res"])), 2), 0x58, 0x57), 1)))
    s.push()


def _dispatchers_fn(tables):
    """``_indirect_calls``' ``build``: per contract, the candidates (addressed functions of exactly its types, in table
    order) each tested against the index, then the trap."""
    from xax_selfhost_jvm import (
        J_CONTRACTS, J_DISPATCH, J_ENTRY_INDEX, J_NCONTRACTS, J_NTABLE, J_POOL, J_TABLE, KIND_NAMED, MR_BARE, MR_CLEN, MR_CODE, MR_FIDX,
        MR_FRAMES, MR_FTYPES, MR_KIND, MR_LINES, MR_LOCALS, MR_NFRAMES, MR_NFTYPES, MR_NLINES, MR_STACK, _add_record, _store_alloc,
    )
    from xax_selfhost_jvm_callback import TRAP_MESSAGE, _int_constant, table_index
    from xax_selfhost_jvm_class import bdata, blen, buffer, klass_literal, method_literal, u1, u2, utf8_literal
    from xax_selfhost_jvm_foreign import vdesc
    from xax_selfhost_general_view import G_CIDX
    from xax_selfhost_views_backend import _g

    def build(e: E):
        p = e.p
        pool = _js(e, J_POOL)

        def contract():
            e.var("dp_at", e.add(_js(e, J_DISPATCH), e.mul(p["dp_k"], 5)))
            e.var("dp_t", e.ld(e.add(p["dp_at"], 4)))
            e.var("dp_ni", e.ld(p["dp_t"]))
            e.var("dp_o", e.add(e.add(p["dp_t"], 1), p["dp_ni"]))
            e.var("dp_no", e.ld(p["dp_o"]))
            # The machine parameters' codes and slots (from 1), the result code.
            e.var("dp_codes", e.alloc(e.add(p["dp_ni"], 1)))
            e.var("dp_slotof", e.alloc(e.add(p["dp_ni"], 1)))
            _ok(e, e.both(e.ne(p["dp_codes"], NONE), e.ne(p["dp_slotof"], NONE)))
            e.var("dp_np", 0)
            e.var("dp_slot", 1)

            def parameter():
                e.var("dp_d", vdesc(e, e.ld(e.add(e.add(p["dp_t"], 1), p["dp_q"]))))

                def machine():
                    e.st(e.add(p["dp_codes"], p["dp_np"]), p["dp_d"])
                    e.st(e.add(p["dp_slotof"], p["dp_np"]), p["dp_slot"])
                    e.set("dp_slot", e.add(p["dp_slot"], e.sel(e.either(e.eq(p["dp_d"], D_J), e.eq(p["dp_d"], D_D)), 2, 1)))
                    e.set("dp_np", e.add(p["dp_np"], 1))

                e.if_(e.ne(p["dp_d"], D_NONE), machine)

            e.for_("dp_q", 0, p["dp_ni"], parameter)
            e.var("dp_rcode", D_NONE)
            e.for_("dp_q", 0, p["dp_no"], lambda: (e.var("dp_rd", vdesc(e, e.ld(e.add(e.add(p["dp_o"], 1), p["dp_q"])))), e.if_(
                e.ne(p["dp_rd"], D_NONE), lambda: e.set("dp_rcode", p["dp_rd"]))))
            buffer(e, "dp_code", 1 << 16)
            e.var("dp_frames", _store_alloc(e, e.add(_js(e, J_NTABLE), 1), "dp_fr"))
            e.var("dp_nf", 0)

            def candidate():
                e.var("dp_f", e.ld(e.add(_js(e, J_TABLE), p["dp_c"])))
                e.var("dp_i", _call(e, "interface", p["dp_f"]))
                e.var("dp_fn", e.ld(e.add(p["dp_i"], 1)))
                e.var("dp_frt", e.add(e.add(p["dp_i"], 2), p["dp_fn"]))
                e.var("dp_same", e.flag(e.both(e.eq(p["dp_fn"], p["dp_ni"]), e.eq(e.ld(p["dp_frt"]), p["dp_no"]))))
                e.if_(e.ne(p["dp_same"], 0), lambda: (
                    e.for_("dp_q", 0, p["dp_ni"], lambda: e.if_(e.ne(e.ld(e.add(e.add(p["dp_i"], 2), p["dp_q"])), e.ld(e.add(e.add(p["dp_t"], 1), p["dp_q"]))),
                                                              lambda: e.set("dp_same", 0))),
                    e.for_("dp_q", 0, p["dp_no"], lambda: e.if_(e.ne(e.ld(e.add(e.add(p["dp_frt"], 1), p["dp_q"])), e.ld(e.add(e.add(p["dp_o"], 1), p["dp_q"]))),
                                                              lambda: e.set("dp_same", 0)))))

                def emit():
                    from xax_selfhost_jvm_code import LOAD as LOADS

                    e.var("dp_fx", e.ld(e.add(_g(e, G_CIDX), p["dp_f"])))
                    u1(e, p["dp_code"], 0x1A)  # iload_0
                    _int_constant(e, p["dp_code"], table_index(e, p["dp_f"]))
                    e.var("dp_jat", blen(e, p["dp_code"]))
                    u1(e, p["dp_code"], 0xA0)
                    u2(e, p["dp_code"], 0)
                    e.var("dp_entry", e.flag(e.eq(p["dp_fx"], _js(e, J_ENTRY_INDEX))))
                    for wide_pass in (0, 1):
                        def load(wide_pass=wide_pass):
                            e.var("dp_lc", e.ld(e.add(p["dp_codes"], p["dp_q"])))
                            two = e.either(e.eq(p["dp_lc"], D_J), e.eq(p["dp_lc"], D_D))
                            take = e.sel(e.ne(p["dp_entry"], 0), e.flag(e.eq(wide_pass, 0)), e.flag(e.eq(e.flag(two), wide_pass)))

                            def one():
                                e.var("dp_ls", e.ld(e.add(p["dp_slotof"], p["dp_q"])))
                                e.var("dp_lop", _pick(e, kind(e, p["dp_lc"]), LOADS))
                                _ok(e, e.le(p["dp_ls"], 255))
                                e.if_(e.le(p["dp_ls"], 3), lambda: u1(e, p["dp_code"], e.add(_pick(e, p["dp_lop"], SHORT_LOCAL), p["dp_ls"])),
                                      lambda: (u1(e, p["dp_code"], p["dp_lop"]), u1(e, p["dp_code"], p["dp_ls"])))

                            e.if_(e.ne(take, 0), one)

                        e.for_("dp_q", 0, p["dp_np"], load)
                    u1(e, p["dp_code"], 0xB8)
                    u2(e, p["dp_code"], _call(e, "jl_own_method", 1, p["dp_fx"]))
                    u1(e, p["dp_code"], e.sel(e.eq(p["dp_rcode"], D_NONE), 0xB1, _pick(e, kind(e, p["dp_rcode"]), RETURN)))
                    e.var("dp_next", blen(e, p["dp_code"]))
                    e.var("dp_delta", e.sub(p["dp_next"], p["dp_jat"]))
                    _ok(e, e.le(p["dp_delta"], 0x7FFF))
                    e.st(e.add(bdata(e, p["dp_code"]), e.add(p["dp_jat"], 1)), e.and_(e.udiv(p["dp_delta"], 256), 255))
                    e.st(e.add(bdata(e, p["dp_code"]), e.add(p["dp_jat"], 2)), e.and_(p["dp_delta"], 255))
                    e.st(e.add(p["dp_frames"], p["dp_nf"]), p["dp_next"])
                    e.set("dp_nf", e.add(p["dp_nf"], 1))

                e.if_(e.ne(p["dp_same"], 0), emit)

            e.for_("dp_c", 0, _js(e, J_NTABLE), candidate)
            u1(e, p["dp_code"], 0xBB)
            u2(e, p["dp_code"], klass_literal(e, pool, "java/lang/Error", "dp_err"))
            u1(e, p["dp_code"], 0x59)
            u1(e, p["dp_code"], 0x13)
            u2(e, p["dp_code"], _call(e, "jp_ref1", pool, 8, utf8_literal(e, pool, TRAP_MESSAGE, "dp_tm")))
            u1(e, p["dp_code"], 0xB7)
            u2(e, p["dp_code"], method_literal(e, pool, "java/lang/Error", "<init>", "(Ljava/lang/String;)V", "dp_ei"))
            u1(e, p["dp_code"], 0xBF)
            e.var("dp_n", blen(e, p["dp_code"]))
            e.var("dp_bytes", _store_alloc(e, e.add(p["dp_n"], 1), "dp_by"))
            e.for_("dp_q", 0, p["dp_n"], lambda: e.st(e.add(p["dp_bytes"], p["dp_q"]), e.ld(e.add(bdata(e, p["dp_code"]), p["dp_q"]))))
            # Frames: the index and the parameters.
            e.var("dp_ft", _store_alloc(e, e.add(p["dp_np"], 2), "dp_ftt"))
            e.st(p["dp_ft"], D_I)
            e.for_("dp_q", 0, p["dp_np"], lambda: e.st(e.add(e.add(p["dp_ft"], 1), p["dp_q"]), e.ld(e.add(p["dp_codes"], p["dp_q"]))))
            # The name record: ``xax$i<k>``, the descriptor, public static.
            e.var("dp_nm", _store_alloc(e, 32, "dp_nms"))
            for q, ch in enumerate(b"xax$i"):
                e.st(e.add(p["dp_nm"], q), ch)
            e.var("dp_nmn", e.add(5, _decimal(e, p["dp_nm"], 5, p["dp_k"])))
            e.var("dp_nr", _store_alloc(e, 6, "dp_nrs"))
            for q, word in enumerate((p["dp_nm"], p["dp_nmn"], e.ld(p["dp_at"]), e.ld(e.add(p["dp_at"], 1)), 0x0009)):
                e.st(e.add(p["dp_nr"], q), word)
            e.var("dp_stack", e.add(p["dp_slot"], 2))
            _add_record(e, {MR_KIND: KIND_NAMED, MR_FIDX: p["dp_nr"], MR_CODE: p["dp_bytes"], MR_CLEN: p["dp_n"],
                            MR_STACK: e.sel(e.lt(p["dp_stack"], 4), 4, p["dp_stack"]), MR_LOCALS: p["dp_slot"], MR_FRAMES: p["dp_frames"],
                            MR_NFRAMES: p["dp_nf"], MR_FTYPES: p["dp_ft"], MR_NFTYPES: e.add(p["dp_np"], 1), MR_LINES: 0, MR_NLINES: 0, MR_BARE: NONE})

        e.for_("dp_k", 0, _js(e, J_NCONTRACTS), contract)
        e.give(1)
    return _function((), build, tables)


def _dispatch_task_fn(tables):
    def build(e: E):
        from xax_selfhost_jvm_code import op, raw

        op(e, 0xB8)
        e.var("dt_ix", _call(e, "jl_dispatcher_ref", e.p["k"]))
        raw(e, e.p["dt_ix"], 2)
        e.give(1)
    return _function(("k",), build, tables)


def add_indirect_functions(add, tables):
    add("jk_dispatch_signatures", _signatures_fn(tables))
    add("jl_dispatcher_ref", _dispatcher_ref_fn(tables))
    add("jl_dispatch", _dispatch_task_fn(tables))
    add("jk_dispatchers", _dispatchers_fn(tables))
