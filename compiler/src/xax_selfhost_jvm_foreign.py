"""S15e.5c (ADR-329): JVM reference types and platform calls in the XAX JVM program.

``xax_jvm._jvm_type`` gives a pointer to an identity-qualified opaque type ``jvm-ref:<descriptor>`` the reference
descriptor itself.  Here a reference descriptor is a code ``D_REF + k``: the class's ``k``-th distinct descriptor text
(``jk_intern``), so equal descriptors are equal codes and slot typing stays integer comparison.

``jk_member`` is ``_foreign_member`` for the call kinds (``jvm-invokestatic``, ``-invokevirtual``, ``-getstatic``,
``-invokeinterface``, ``-invokestatic-interface``): the carrier's ABI (``JVM-FOREIGN-ABI``), the member text
(``JVM-FIELD-MEMBER``, ``JVM-METHOD-MEMBER``), the method descriptor (``JVM-METHOD-DESCRIPTOR``), the receiver of a
virtual or interface call, the arity (``JVM-FOREIGN-ARITY``) and each machine type against its descriptor
(``JVM-FOREIGN-DESCRIPTOR-TYPE``), each rejection written as the bootstrap's.  The object kinds (``jvm-new`` ...), the
memory class and a type the bootstrap cannot represent decline.

A member record (``MB_*``) holds its texts as words, one byte each: the class, the name, the descriptor, and per
parameter its text (the receiver ``L<class>;`` included) for the narrowing conversions and the arity diagnostic.
"""

from __future__ import annotations

from xax_compiler import (
    JVM_FOREIGN_ABIS, JVM_GETSTATIC_ABI, JVM_INVOKEINTERFACE_ABI, JVM_INVOKESTATIC_ABI, JVM_INVOKESTATIC_INTERFACE_ABI,
    JVM_INVOKEVIRTUAL_ABI,
)
import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_jvm_code import D_D, D_F, D_I, D_J, D_NONE, D_REF
from xax_selfhost_views_backend import (
    _FOREIGN_PREFIX, G_PAY, _at, _call, _cid_words, _ok, _payload_uleb, _reference, _type_form,
)

REFERENCE_PREFIX = b"jvm-ref:"
MEMORY_CLASS = b"xax/jvm/Memory"
REFS_CAP = 4096
CALL_ABIS = {JVM_INVOKESTATIC_ABI: 0xB8, JVM_INVOKEVIRTUAL_ABI: 0xB6, JVM_GETSTATIC_ABI: 0xB2, JVM_INVOKEINTERFACE_ABI: 0xB9,
             JVM_INVOKESTATIC_INTERFACE_ABI: 0xB8}
(MB_OP, MB_IFACE, MB_CLS, MB_CLSN, MB_NAME, MB_NAMEN, MB_DESC, MB_DESCN, MB_NP, MB_PARAMS, MB_RES, MB_RESN, MB_ARGS, MB_RSLOTS,
 MB_CARRIER) = range(15)
MB_WORDS = 15
PARAM_WORDS = 2  # a parameter's text and its length
NARROW = {ord("B"): 0x91, ord("C"): 0x92, ord("S"): 0x93}
NARROW_WIDTH = {ord("Z"): 1, ord("B"): 8, ord("C"): 16, ord("S"): 16, ord("I"): 32, ord("J"): 64}


def _js(e: E, field: int):
    from xax_selfhost_jvm import _js as js

    return js(e, field)


def _copy_input(e: E, at, n, name: str):
    """The ``n`` input bytes at ``at`` as words in a fresh array ``name``."""
    p = e.p
    e.var(f"{name}_src", at)
    e.var(f"{name}_n", n)
    e.var(name, e.alloc(e.add(p[f"{name}_n"], 1)))
    _ok(e, e.ne(p[name], NONE))
    e.for_(f"{name}_k", 0, p[f"{name}_n"], lambda: e.st(e.add(p[name], p[f"{name}_k"]), e.rd(e.add(p[f"{name}_src"], p[f"{name}_k"]))))
    return p[name]


# -- interned reference descriptors -------------------------------------------------------------------------------------

def _intern_fn(tables):
    """``jk_intern(text, n)``: the code of the descriptor text (``n`` words): an equal one's, else a new one (its text
    copied into the class store)."""
    from xax_selfhost_jvm import J_NREFS, J_REFS, _set_js, _store_alloc

    def build(e: E):
        p = e.p
        e.var("in_refs", _js(e, J_REFS))
        e.var("in_count", _js(e, J_NREFS))

        def compare():
            e.var("in_at", e.add(p["in_refs"], e.mul(p["in_k"], 2)))
            e.var("in_same", e.flag(e.eq(e.ld(e.add(p["in_at"], 1)), p["n"])))
            e.var("in_t", e.ld(p["in_at"]))
            e.if_(e.ne(p["in_same"], 0), lambda: e.for_("in_q", 0, p["n"], lambda: e.if_(
                e.ne(e.ld(e.add(p["in_t"], p["in_q"])), e.ld(e.add(p["text"], p["in_q"]))), lambda: e.set("in_same", 0))))
            e.if_(e.ne(p["in_same"], 0), lambda: e.give(e.add(D_REF, p["in_k"])))

        e.for_("in_k", 0, p["in_count"], compare)
        _ok(e, e.lt(p["in_count"], REFS_CAP))
        e.var("in_copy", _store_alloc(e, e.add(p["n"], 1), "in_c"))
        e.for_("in_q", 0, p["n"], lambda: e.st(e.add(p["in_copy"], p["in_q"]), e.ld(e.add(p["text"], p["in_q"]))))
        e.st(e.add(p["in_refs"], e.mul(p["in_count"], 2)), p["in_copy"])
        e.st(e.add(p["in_refs"], e.add(e.mul(p["in_count"], 2), 1)), p["n"])
        _set_js(e, J_NREFS, e.add(p["in_count"], 1))
        e.give(e.add(D_REF, p["in_count"]))
    return _function(("text", "n"), build, tables)


def ref_text(e: E, code):
    """(text, length) of reference code ``code``."""
    from xax_selfhost_jvm import J_REFS

    at = e.add(_js(e, J_REFS), e.mul(e.sub(code, D_REF), 2))
    return e.ld(at), e.ld(e.add(at, 1))


# -- value types ----------------------------------------------------------------------------------------------------------

def _vdesc_fn(tables):
    """``_jvm_type`` of TYPE ``t``: ``D_NONE`` for a proof value, ``D_I``/``D_J`` for bits of at most 64 bits, ``D_F``/
    ``D_D`` for floats, a reference code for a pointer to ``jvm-ref:<descriptor>``; anything else (a memory pointer, a
    callback interface, an aggregate, a sum, a link, a wider value) declines."""
    from xax_selfhost_general_frame import _bits_width, _float_width

    def build(e: E):
        p = e.p
        e.var("vd_form", _type_form(e, p["t"]))
        e.if_(e.either(e.eq(p["vd_form"], 3), e.eq(p["vd_form"], 4)), lambda: e.give(D_NONE))

        def bits():
            _bits_width(e, p["t"], "vd_w")
            _ok(e, e.both(e.lt(0, p["vd_w"]), e.le(p["vd_w"], 64)))
            e.give(e.sel(e.le(p["vd_w"], 32), D_I, D_J))

        e.if_(e.eq(p["vd_form"], 1), bits)

        def floating():
            _float_width(e, p["t"], "vd_fw")
            e.give(e.sel(e.eq(p["vd_fw"], 32), D_F, D_D))

        e.if_(e.eq(p["vd_form"], 7), floating)
        _ok(e, e.eq(p["vd_form"], 2))
        e.var("vd_at", e.add(_at(e, G_PAY, p["t"]), 1))
        _payload_uleb(e, "vd_at")  # the address space
        e.var("vd_el", _reference(e, p["t"], _payload_uleb(e, "vd_at")))
        _ok(e, e.ne(p["vd_el"], NONE))
        _ok(e, e.eq(_type_form(e, p["vd_el"]), 6))  # else a memory pointer: the memory profile (declined)
        e.var("vd_id", e.add(_at(e, G_PAY, p["vd_el"]), 1))
        e.var("vd_n", _payload_uleb(e, "vd_id"))
        _ok(e, e.lt(len(REFERENCE_PREFIX), p["vd_n"]))
        for k, byte in enumerate(REFERENCE_PREFIX):
            _ok(e, e.eq(e.rd(e.add(p["vd_id"], k)), byte))
        e.var("vd_text", _copy_input(e, e.add(p["vd_id"], len(REFERENCE_PREFIX)), e.sub(p["vd_n"], len(REFERENCE_PREFIX)), "vd_tx"))
        e.give(_call(e, "jk_intern", p["vd_text"], p["vd_tx_n"]))
    return _function(("t",), build, tables)


def vdesc(e: E, t):
    return _call(e, "jk_vdesc", t)


# -- the foreign member ---------------------------------------------------------------------------------------------------

def _find_byte(e: E, text, n, byte: int, name: str):
    """``name``: the first index of ``byte`` in the ``n`` words at ``text``, else NONE."""
    p = e.p
    e.var(name, NONE)
    e.for_(f"{name}_k", 0, n, lambda: e.if_(e.both(e.eq(p[name], NONE), e.eq(e.ld(e.add(text, p[f"{name}_k"])), byte)),
                                            lambda: e.set(name, p[f"{name}_k"])))
    return p[name]


def _put_text(e: E, text, n):
    """A diagnostic string from ``n`` words of text (one byte each)."""
    from xax_selfhost_general_dll import _pack_begin, _pack_byte, _pack_end

    p = e.p
    e.var("pt_text", text)
    e.var("pt_n", n)
    _pack_begin(e, D.T_STR, p["pt_n"])
    e.for_("pt_k", 0, p["pt_n"], lambda: _pack_byte(e, e.ld(e.add(p["pt_text"], p["pt_k"]))))
    _pack_end(e)


def _reject(e: E, condition, code: str, rule: str, carrier, expected, actual):
    def write():
        D.text(e, code)
        D.cid(e, _cid_words(e, carrier))
        D.text(e, rule)
        expected()
        actual()
    D.reject_unless(e, condition, write)


def _member_fn(tables):
    """``_foreign_member`` of carrier ``c`` for the call kinds: the member record, or NONE (rejected or declined)."""
    def build(e: E):
        p = e.p
        c = p["c"]
        e.var("mb", e.alloc(MB_WORDS + 1))
        _ok(e, e.ne(p["mb"], NONE))
        mb = p["mb"]

        def field(k):
            return e.ld(e.add(mb, k))

        def set_field(k, value):
            e.st(e.add(mb, k), value)

        set_field(MB_CARRIER, c)
        # decode_foreign_function: the identity, then the ABI, library and name strings, the inputs and the outputs.
        e.var("fm_at", _at(e, G_PAY, c))
        e.var("fm_idn", _payload_uleb(e, "fm_at"))
        e.var("fm_end", e.add(p["fm_at"], p["fm_idn"]))
        _ok(e, e.lt(len(_FOREIGN_PREFIX), p["fm_idn"]))
        for k, byte in enumerate(_FOREIGN_PREFIX):
            _ok(e, e.eq(e.rd(e.add(p["fm_at"], k)), byte))
        e.set("fm_at", e.add(p["fm_at"], len(_FOREIGN_PREFIX)))
        for part in ("abi", "lib", "sym"):
            e.var(f"fm_{part}n", _payload_uleb(e, "fm_at"))
            e.var(f"fm_{part}", p["fm_at"])
            e.set("fm_at", e.add(p["fm_at"], p[f"fm_{part}n"]))
        e.var("fm_nin", _payload_uleb(e, "fm_at"))
        e.var("fm_ins", p["fm_at"])
        e.set("fm_at", e.add(p["fm_at"], e.mul(p["fm_nin"], 32)))
        e.var("fm_nout", _payload_uleb(e, "fm_at"))
        e.var("fm_outs", p["fm_at"])
        e.set("fm_at", e.add(p["fm_at"], e.mul(p["fm_nout"], 32)))
        _ok(e, e.eq(p["fm_at"], p["fm_end"]))  # an allocator or deallocator contract: not a JVM call (declined)
        _ok(e, e.both(e.lt(0, p["fm_abin"]), e.lt(0, p["fm_libn"]), e.lt(0, p["fm_symn"])))  # FOREIGN-FUNCTION-NONEMPTY: the bootstrap's

        def abi_is(abi: bytes):
            from xax_selfhost_x86_64_general import _bytes_equal

            return _bytes_equal(e, p["fm_abi"], p["fm_abin"], abi)

        e.var("fm_known", 0)
        for abi in JVM_FOREIGN_ABIS:
            e.if_(abi_is(abi), lambda: e.set("fm_known", 1))

        def abi_expected():
            D.put(e, D.T_LIST)
            D.put(e, len(JVM_FOREIGN_ABIS))
            for abi in JVM_FOREIGN_ABIS:
                D.text(e, abi.decode())

        def abi_actual():
            from xax_selfhost_general_dll import _input_bytes

            _input_bytes(e, D.T_STR, p["fm_abi"], p["fm_abin"], "fm_ap")

        _reject(e, e.ne(p["fm_known"], 0), "XAX.FOREIGN.ABI", "JVM-FOREIGN-ABI", c, abi_expected, abi_actual)
        # The class and member texts (``decode("ascii")``: another byte is the bootstrap's own failure, declined).
        e.var("fm_cls", _copy_input(e, p["fm_lib"], p["fm_libn"], "fm_cl"))
        e.var("fm_mem", _copy_input(e, p["fm_sym"], p["fm_symn"], "fm_me"))
        e.for_("fm_k", 0, p["fm_libn"], lambda: _ok(e, e.lt(e.ld(e.add(p["fm_cls"], p["fm_k"])), 128)))
        e.for_("fm_k", 0, p["fm_symn"], lambda: _ok(e, e.lt(e.ld(e.add(p["fm_mem"], p["fm_k"])), 128)))
        e.var("fm_call", 0)
        for abi, opcode in CALL_ABIS.items():
            e.if_(abi_is(abi), lambda opcode=opcode: (e.set("fm_call", 1), set_field(MB_OP, opcode)))
        _ok(e, e.ne(p["fm_call"], 0))  # an object kind (S15e.5c): declined
        _ok(e, e.not_(_bytes_equal_words(e, p["fm_cls"], p["fm_libn"], MEMORY_CLASS)))  # the memory class: declined
        set_field(MB_IFACE, e.flag(e.either(abi_is(JVM_INVOKEINTERFACE_ABI), abi_is(JVM_INVOKESTATIC_INTERFACE_ABI))))
        set_field(MB_CLS, p["fm_cls"])
        set_field(MB_CLSN, p["fm_libn"])
        e.var("fm_params", e.alloc(e.mul(e.add(p["fm_symn"], 2), PARAM_WORDS)))
        _ok(e, e.ne(p["fm_params"], NONE))
        set_field(MB_PARAMS, p["fm_params"])
        set_field(MB_NP, 0)

        def add_param(text, n):
            e.var("fm_np", field(MB_NP))
            e.st(e.add(p["fm_params"], e.mul(p["fm_np"], PARAM_WORDS)), text)
            e.st(e.add(p["fm_params"], e.add(e.mul(p["fm_np"], PARAM_WORDS), 1)), n)
            set_field(MB_NP, e.add(p["fm_np"], 1))

        def static_field():
            e.var("fm_colon", _find_byte(e, p["fm_mem"], p["fm_symn"], ord(":"), "fm_cf"))
            _reject(e, e.ne(p["fm_colon"], NONE), "XAX.JVM.DESCRIPTOR", "JVM-FIELD-MEMBER", c, lambda: D.text(e, "name:descriptor"),
                    lambda: _put_text(e, p["fm_mem"], p["fm_symn"]))
            set_field(MB_NAME, p["fm_mem"])
            set_field(MB_NAMEN, p["fm_colon"])
            set_field(MB_DESC, e.add(e.add(p["fm_mem"], p["fm_colon"]), 1))
            set_field(MB_DESCN, e.sub(e.sub(p["fm_symn"], p["fm_colon"]), 1))
            set_field(MB_RES, field(MB_DESC))
            set_field(MB_RESN, field(MB_DESCN))

        def method():
            e.var("fm_open", _find_byte(e, p["fm_mem"], p["fm_symn"], ord("("), "fm_of"))
            _reject(e, e.ne(p["fm_open"], NONE), "XAX.JVM.DESCRIPTOR", "JVM-METHOD-MEMBER", c, lambda: D.text(e, "name(descriptor)"),
                    lambda: _put_text(e, p["fm_mem"], p["fm_symn"]))
            set_field(MB_NAME, p["fm_mem"])
            set_field(MB_NAMEN, p["fm_open"])
            e.var("fm_desc", e.add(p["fm_mem"], p["fm_open"]))
            e.var("fm_descn", e.sub(p["fm_symn"], p["fm_open"]))
            set_field(MB_DESC, p["fm_desc"])
            set_field(MB_DESCN, p["fm_descn"])

            def descriptor_actual():
                _put_text(e, p["fm_desc"], p["fm_descn"])

            # ``descriptor[1:].split(")", 1)``: the parameters up to the first ``)``, the result after it.
            e.var("fm_close", _find_byte(e, e.add(p["fm_desc"], 1), e.sub(p["fm_descn"], 1), ord(")"), "fm_cl2"))
            _reject(e, e.ne(p["fm_close"], NONE), "XAX.JVM.DESCRIPTOR", "JVM-METHOD-DESCRIPTOR", c, lambda: D.text(e, "(params)return"),
                    descriptor_actual)
            e.var("fm_inner", e.add(p["fm_desc"], 1))
            e.var("fm_innern", p["fm_close"])
            set_field(MB_RES, e.add(e.add(p["fm_inner"], p["fm_innern"]), 1))
            set_field(MB_RESN, e.sub(e.sub(p["fm_descn"], p["fm_innern"]), 2))
            # The receiver of a virtual or interface call: ``L<class>;``.
            e.var("fm_recv", e.flag(e.either(abi_is(JVM_INVOKEVIRTUAL_ABI), abi_is(JVM_INVOKEINTERFACE_ABI))))

            def receiver():
                e.var("fm_rt", e.alloc(e.add(p["fm_libn"], 3)))
                _ok(e, e.ne(p["fm_rt"], NONE))
                e.st(p["fm_rt"], ord("L"))
                e.for_("fm_k", 0, p["fm_libn"], lambda: e.st(e.add(e.add(p["fm_rt"], 1), p["fm_k"]), e.ld(e.add(p["fm_cls"], p["fm_k"]))))
                e.st(e.add(e.add(p["fm_rt"], 1), p["fm_libn"]), ord(";"))
                add_param(p["fm_rt"], e.add(p["fm_libn"], 2))

            e.if_(e.ne(p["fm_recv"], 0), receiver)
            e.var("fm_i", 0)

            def one():
                e.var("fm_start", p["fm_i"])

                def char(k):
                    return e.ld(e.add(p["fm_inner"], k))

                # ``while inner[index] == "["`` past the end: the bootstrap's IndexError (declined).
                e.while_(lambda: e.both(e.lt(p["fm_i"], p["fm_innern"]), e.eq(char(p["fm_i"]), ord("["))), lambda: e.set("fm_i", e.add(p["fm_i"], 1)))
                _ok(e, e.lt(p["fm_i"], p["fm_innern"]))
                e.var("fm_ch", char(p["fm_i"]))

                def klass():
                    e.var("fm_semi", _find_byte(e, e.add(p["fm_inner"], p["fm_i"]), e.sub(p["fm_innern"], p["fm_i"]), ord(";"), "fm_sm"))
                    _reject(e, e.ne(p["fm_semi"], NONE), "XAX.JVM.DESCRIPTOR", "JVM-METHOD-DESCRIPTOR", c,
                            lambda: D.text(e, "terminated class descriptor"), descriptor_actual)
                    e.set("fm_i", e.add(e.add(p["fm_i"], p["fm_semi"]), 1))

                def primitive():
                    _reject(e, e.either(*(e.eq(p["fm_ch"], ord(ch)) for ch in "ZBCSIJFD")), "XAX.JVM.DESCRIPTOR", "JVM-METHOD-DESCRIPTOR", c,
                            lambda: D.text(e, "field descriptors"), descriptor_actual)
                    e.set("fm_i", e.add(p["fm_i"], 1))

                e.if_(e.eq(p["fm_ch"], ord("L")), klass, primitive)
                add_param(e.add(p["fm_inner"], p["fm_start"]), e.sub(p["fm_i"], p["fm_start"]))

            e.while_(lambda: e.lt(p["fm_i"], p["fm_innern"]), one)

        e.if_(abi_is(JVM_GETSTATIC_ABI), static_field, method)
        # The machine inputs and outputs (proof values dropped), the arity, and each type against its descriptor.
        e.var("fm_mins", e.alloc(e.add(p["fm_nin"], 1)))
        e.var("fm_mouts", e.alloc(e.add(p["fm_nout"], 1)))
        _ok(e, e.both(e.ne(p["fm_mins"], NONE), e.ne(p["fm_mouts"], NONE)))
        for group in ("in", "out"):
            def machine(group=group):
                from xax_selfhost_general_wasm import _type_by_cid
                from xax_selfhost_x86_64_general import _proof

                e.var(f"fm_{group}t_at", e.add(p[f"fm_{group}s"], e.mul(p["fm_q"], 32)))
                _type_by_cid(e, p[f"fm_{group}t_at"], f"fm_{group}t")
                e.if_(e.not_(_proof(e, p[f"fm_{group}t"])), lambda: (
                    e.st(e.add(p[f"fm_m{group}s"], p[f"fm_m{group}"]), p[f"fm_{group}t"]), e.set(f"fm_m{group}", e.add(p[f"fm_m{group}"], 1))))

            e.var(f"fm_m{group}", 0)
            e.for_("fm_q", 0, p[f"fm_n{group}"], machine)
        e.var("fm_void", e.flag(e.both(e.eq(field(MB_RESN), 1), e.eq(e.ld(field(MB_RES)), ord("V")))))
        arity = e.both(e.lt(0, field(MB_NAMEN)), e.eq(p["fm_min"], field(MB_NP)), e.eq(p["fm_mout"], e.sub(1, p["fm_void"])))

        def arity_expected():
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.put(e, D.T_LIST)
            D.put(e, field(MB_NP))
            e.for_("fm_k", 0, field(MB_NP), lambda: _put_text(e, e.ld(e.add(p["fm_params"], e.mul(p["fm_k"], PARAM_WORDS))),
                                                              e.ld(e.add(p["fm_params"], e.add(e.mul(p["fm_k"], PARAM_WORDS), 1)))))
            _put_text(e, field(MB_RES), field(MB_RESN))

        def arity_actual():
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.integer(e, p["fm_min"])
            D.integer(e, p["fm_mout"])

        _reject(e, arity, "XAX.JVM.FOREIGN", "JVM-FOREIGN-ARITY", c, arity_expected, arity_actual)

        def check(text, n, t):
            e.var("fm_ct", text)
            e.var("fm_cn", n)
            e.var("fm_ty", t)
            e.var("fm_match", _call(e, "jk_matches", p["fm_ct"], p["fm_cn"], p["fm_ty"]))
            _reject(e, e.ne(p["fm_match"], 0), "XAX.JVM.FOREIGN", "JVM-FOREIGN-DESCRIPTOR-TYPE", c, lambda: _put_text(e, p["fm_ct"], p["fm_cn"]),
                    lambda: D.cid(e, _cid_words(e, p["fm_ty"])))

        e.for_("fm_k", 0, field(MB_NP), lambda: check(e.ld(e.add(p["fm_params"], e.mul(p["fm_k"], PARAM_WORDS))),
                                                       e.ld(e.add(p["fm_params"], e.add(e.mul(p["fm_k"], PARAM_WORDS), 1))),
                                                       e.ld(e.add(p["fm_mins"], p["fm_k"]))))
        e.if_(e.eq(p["fm_void"], 0), lambda: check(field(MB_RES), field(MB_RESN), e.ld(p["fm_mouts"])))
        # The slots ``_descriptor_slots`` gives a method descriptor (receiver excluded), and its result's.
        e.var("fm_slots", 0)
        e.var("fm_first", e.flag(e.either(abi_is(JVM_INVOKEVIRTUAL_ABI), abi_is(JVM_INVOKEINTERFACE_ABI))))
        e.for_("fm_k", p["fm_first"], field(MB_NP), lambda: e.set("fm_slots", e.add(p["fm_slots"], param_slots(e, p["fm_params"], p["fm_k"]))))
        set_field(MB_ARGS, p["fm_slots"])
        e.var("fm_r0", e.ld(field(MB_RES)))
        set_field(MB_RSLOTS, e.sel(e.ne(p["fm_void"], 0), 0, e.sel(e.both(e.eq(field(MB_RESN), 1), e.either(
            e.eq(p["fm_r0"], ord("J")), e.eq(p["fm_r0"], ord("D")))), 2, 1)))
        e.give(mb)
    return _function(("c",), build, tables)


def param_slots(e: E, params, k):
    """``_slots`` of parameter ``k``: 2 for ``J`` and ``D``, else 1."""
    text = e.ld(e.add(params, e.mul(k, PARAM_WORDS)))
    n = e.ld(e.add(params, e.add(e.mul(k, PARAM_WORDS), 1)))
    first = e.ld(text)
    return e.sel(e.both(e.eq(n, 1), e.either(e.eq(first, ord("J")), e.eq(first, ord("D")))), 2, 1)


def _bytes_equal_words(e: E, text, n, data: bytes):
    """1 when the ``n`` words at ``text`` are ``data``."""
    return e.both(e.eq(n, len(data)), *(e.eq(e.ld(e.add(text, k)), byte) for k, byte in enumerate(data))) if data else e.eq(n, 0)


def _matches_fn(tables):
    """``_descriptor_matches(jvm, t)``: the narrow descriptors take bits of their width, ``F``/``D`` floats, a class or
    array descriptor the equal reference (``_jvm_type`` first: a type it cannot represent declines)."""
    def build(e: E):
        p = e.p
        e.var("dm_x", vdesc(e, p["t"]))
        e.var("dm_ch", e.ld(p["text"]))
        e.var("dm_one", e.flag(e.eq(p["n"], 1)))

        def narrow():
            from xax_selfhost_general_frame import _bits_width

            e.var("dm_want", 0)
            for ch, width in NARROW_WIDTH.items():
                e.if_(e.eq(p["dm_ch"], ch), lambda width=width: e.set("dm_want", width))
            _bits_width(e, p["t"], "dm_w")
            e.give(e.flag(e.both(e.either(e.eq(p["dm_x"], D_I), e.eq(p["dm_x"], D_J)), e.eq(p["dm_w"], p["dm_want"]))))

        e.if_(e.both(e.ne(p["dm_one"], 0), e.either(*(e.eq(p["dm_ch"], ch) for ch in NARROW_WIDTH))), narrow)
        e.if_(e.both(e.ne(p["dm_one"], 0), e.eq(p["dm_ch"], ord("F"))), lambda: e.give(e.flag(e.eq(p["dm_x"], D_F))))
        e.if_(e.both(e.ne(p["dm_one"], 0), e.eq(p["dm_ch"], ord("D"))), lambda: e.give(e.flag(e.eq(p["dm_x"], D_D))))
        e.if_(e.lt(p["dm_x"], D_REF), lambda: e.give(0))
        e.var("dm_rt", ref_text(e, p["dm_x"])[0])
        e.var("dm_rn", ref_text(e, p["dm_x"])[1])
        e.var("dm_same", e.flag(e.eq(p["dm_rn"], p["n"])))
        e.if_(e.ne(p["dm_same"], 0), lambda: e.for_("dm_k", 0, p["n"], lambda: e.if_(
            e.ne(e.ld(e.add(p["dm_rt"], p["dm_k"])), e.ld(e.add(p["text"], p["dm_k"]))), lambda: e.set("dm_same", 0))))
        e.give(p["dm_same"])
    return _function(("text", "n", "t"), build, tables)


def add_foreign_functions(add, tables):
    """Before the method analyses (``jm_types`` asks ``jk_vdesc``)."""
    for name, builder in (("jk_intern", _intern_fn), ("jk_vdesc", _vdesc_fn), ("jk_matches", _matches_fn), ("jk_member", _member_fn)):
        add(name, builder(tables))
