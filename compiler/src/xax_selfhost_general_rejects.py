"""Self-hosting step S15b.4 (ADR-294): the general x86-64 program's code generation rejections on malformed or extreme
inputs, with the bootstrap's exact diagnostics.

ADR-280 left these rules declined: where the bootstrap fails, the program made no claim.  The functions here write the
bootstrap's diagnostic instead, through ``reject_at`` (only when every earlier function's code was the program's, so
the bootstrap reached the same point):

* encodability (``xax_x86_64``'s encoders): a frame access, an indexed or atomic access, or an ``xmm`` access past
  ``disp32`` (NATIVE-MEMORY-ENCODABLE, NATIVE-INDEXED-MEMORY-ENCODABLE, NATIVE-ATOMIC-ENCODABLE, NATIVE-XMM-MEMORY), a
  checked bound past ``imm32`` (NATIVE-CHECKED-BOUND-ENCODABLE), and an ``and`` mask past 32 bits (NATIVE-AND-IMM32);
* calls: more than one machine result on the frame path (NATIVE-CALL-ARITY), and on the register path a value that
  has no location (NATIVE-VALUE-LOCATION: a second machine result is never defined);
* foreign calls: a declaration of an ABI the path does not own (NATIVE-FOREIGN-ABI), a syscall with more than one
  machine result (SYSCALL-ONE-RESULT), a syscall name ``decode_syscall_name`` rejects (SYSCALL-TEMPLATE-CANONICAL,
  SYSCALL-TEMPLATE-OPERANDS), and a startup read of another name (LINUX-STARTUP-NAME);
* pointer widths on the frame path (NATIVE-POINTER-ELEMENT-WIDTH, NATIVE-ADDRESS-POINTER-WIDTH);
* the dynamic container: one symbol imported from two libraries (LINUX-IMPORT-SYMBOL-UNIQUE).

A text the bootstrap renders with ``decode("ascii", "replace")`` is written as its raw bytes, which the record's
``STR`` decoding renders the same way.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import G_PAY, _at

# Encodability rejections, by ``which``: (code, rule, expected, how many actual words; 1 is the bare value).
ENCODING_RULES = (
    ("XAX.NATIVE.MEMORY_ENCODING", "NATIVE-MEMORY-ENCODABLE", "4/8-byte access with disp32", 2),
    ("XAX.NATIVE.MEMORY_ENCODING", "NATIVE-INDEXED-MEMORY-ENCODABLE", "4/8-byte access with rsp+index+disp32", 2),
    ("XAX.NATIVE.MEMORY_ENCODING", "NATIVE-CHECKED-BOUND-ENCODABLE", "0..2^31-1", 1),
    ("XAX.NATIVE.ATOMIC_ENCODING", "NATIVE-ATOMIC-ENCODABLE", "aligned 4/8-byte access with disp32", 2),
    ("XAX.NATIVE.FLOAT_ENCODING", "NATIVE-XMM-MEMORY", "f32/f64 stack access", 3),
    ("XAX.NATIVE.IMMEDIATE", "NATIVE-AND-IMM32", "0..2^32-1", 1),
)
MEMORY, INDEXED, CHECKED_BOUND, ATOMIC, XMM, AND_IMM32 = range(len(ENCODING_RULES))
# Pointer-width rejections on the frame path, by ``which``: (code, rule).
POINTER_WIDTH_RULES = (("XAX.NATIVE.POINTER_WIDTH", "NATIVE-POINTER-ELEMENT-WIDTH"), ("XAX.NATIVE.ADDRESS_WIDTH", "NATIVE-ADDRESS-POINTER-WIDTH"))
POINTER_ELEMENT_WIDTH, ADDRESS_POINTER_WIDTH = range(2)
# Foreign declarations: their ABI classes, and what each path owns (``xax_x86_64_regalloc``: NATIVE-FOREIGN-ABI).
SYSV_C, SYSCALL, STARTUP, WIN64_C = b"sysv-x86_64-c", b"linux-x86_64-syscall-v1", b"linux-x86_64-startup-v1", b"win64-c"
ABI_OTHER, ABI_SYSV_C, ABI_SYSCALL, ABI_STARTUP, ABI_WIN64_C = range(5)
REGISTER_OWNED = (SYSV_C, SYSCALL, STARTUP)
STARTUP_EXPECTED = "argc|arg_length|arg_copy|envc|env_length|env_copy|auxv_value"
SYSCALL_ARGUMENTS = 6  # ``_SYSCALL_ARGUMENT_REGISTERS``


def _signed(e: E, value):
    """An integer as Python holds it: a word with the top bit set is a negative number."""
    e.if_(e.le(1 << 63, value), lambda: (D.put(e, D.T_SINT), D.put(e, value)), lambda: D.integer(e, value))


def _ascii(e: E, at, length, name: str):
    """``name``: 1 when the ``length`` input bytes from ``at`` are ASCII."""
    p = e.p
    e.var(name, 1)
    e.for_(f"{name}_k", 0, length, lambda: e.if_(e.le(128, e.rd(e.add(at, p[f"{name}_k"]))), lambda: e.set(name, 0)))


def _packed(e: E, tag: int, at, length):
    """``tag`` (STR, HEX, or BYTES) of the ``length`` input bytes from ``at``, eight to a word."""
    p = e.p
    D.put(e, tag)
    D.put(e, length)
    e.var("pk_n", length)
    e.var("pk_at", at)

    def word():
        e.var("pk_w", 0)
        e.var("pk_j", 8)
        e.while_(lambda: e.ne(p["pk_j"], 0), lambda: (
            e.set("pk_j", e.sub(p["pk_j"], 1)),
            e.var("pk_i", e.add(e.mul(p["pk_q"], 8), p["pk_j"])),
            e.set("pk_w", e.add(e.mul(p["pk_w"], 256), e.sel(e.lt(p["pk_i"], p["pk_n"]), e.rd(e.add(p["pk_at"], p["pk_i"])), 0)))))
        D.put(e, p["pk_w"])

    e.for_("pk_q", 0, e.udiv(e.add(p["pk_n"], 7), 8), word)


def foreign_identity(e: E, obj, name: str):
    """The foreign declaration ``obj``'s identity (``foreign-function-v1``): ``name`` its ABI class (``ABI_*``),
    ``name_abi``/``name_alen`` its ABI bytes, ``name_at``/``name_len`` its symbol name, in the input words."""
    from xax_selfhost_views_backend import _FOREIGN_PREFIX, _payload_uleb

    p = e.p
    e.var(name, ABI_OTHER)
    e.var(f"{name}_ok", 1)
    e.var(f"{name}_cur", _at(e, G_PAY, obj))
    _payload_uleb(e, f"{name}_cur")
    for k, value in enumerate(_FOREIGN_PREFIX):
        e.if_(e.ne(e.rd(e.add(p[f"{name}_cur"], k)), value), lambda: e.set(f"{name}_ok", 0))
    e.set(f"{name}_cur", e.add(p[f"{name}_cur"], len(_FOREIGN_PREFIX)))
    e.var(f"{name}_alen", _payload_uleb(e, f"{name}_cur"))
    e.var(f"{name}_abi", p[f"{name}_cur"])
    e.set(f"{name}_cur", e.add(p[f"{name}_cur"], p[f"{name}_alen"]))
    e.set(f"{name}_cur", e.add(_payload_uleb(e, f"{name}_cur"), p[f"{name}_cur"]))  # the library
    e.var(f"{name}_len", _payload_uleb(e, f"{name}_cur"))
    e.var(f"{name}_at", p[f"{name}_cur"])
    for kind, abi in ((ABI_SYSV_C, SYSV_C), (ABI_SYSCALL, SYSCALL), (ABI_STARTUP, STARTUP), (ABI_WIN64_C, WIN64_C)):
        e.var(f"{name}_m", e.flag(e.both(e.ne(p[f"{name}_ok"], 0), e.eq(p[f"{name}_alen"], len(abi)))))
        for k, value in enumerate(abi):
            e.if_(e.ne(e.rd(e.add(p[f"{name}_abi"], k)), value), lambda: e.set(f"{name}_m", 0))
        e.if_(e.ne(p[f"{name}_m"], 0), lambda kind=kind: e.set(name, kind))


def _encoding_reject_fn(tables):
    """The bootstrap's encodability rejection ``which`` (``ENCODING_RULES``) of the actual words ``a``, ``b``, ``c``."""
    def build(e: E):
        from xax_selfhost_general_emit import reject_at

        p = e.p

        def write():
            for which, (code, rule, expected, count) in enumerate(ENCODING_RULES):
                def one(code=code, rule=rule, expected=expected, count=count):
                    D.text(e, code)
                    D.text(e, "x86_64")
                    D.text(e, rule)
                    D.text(e, expected)
                    if count == 1:
                        _signed(e, p["a"])
                    else:
                        D.put(e, D.T_LIST)
                        D.put(e, count)
                        for word in ("a", "b", "c")[:count]:
                            _signed(e, p[word])

                e.if_(e.eq(p["which"], which), one)

        reject_at(e, write)
    return _function(("which", "a", "b", "c"), build, tables)


def encoding_reject(e: E, which: int, *words):
    """Reject with ``ENCODING_RULES[which]``; gives NONE (the caller's ``_call`` then stops)."""
    from xax_selfhost_views_backend import _call

    _call(e, "encoding_reject", which, *(tuple(words) + (0, 0, 0))[:3])


def _pointer_width_reject_fn(tables):
    """The frame path's pointer-width rejection ``which`` (``POINTER_WIDTH_RULES``) of function ``f``'s graph."""
    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p

        def write():
            for which, (code, rule) in enumerate(POINTER_WIDTH_RULES):
                e.if_(e.eq(p["which"], which), lambda code=code: D.text(e, code))
            D.cid(e, graph_cid_words(e, p["f"]))
            for which, (code, rule) in enumerate(POINTER_WIDTH_RULES):
                e.if_(e.eq(p["which"], which), lambda rule=rule: D.text(e, rule))
            D.integer(e, p["expected"])
            D.integer(e, p["actual"])

        reject_at(e, write)
    return _function(("which", "expected", "actual", "f"), build, tables)


def _abi_reject_fn(tables):
    """NATIVE-FOREIGN-ABI of declaration ``obj`` in function ``f``: ``frame`` 1, the frame path, expects ``win64-c`` (its
    call path is the Win64 one); 0 the register path the ABIs it owns on Linux; 2 (S15e.3) the register path on Windows,
    ``[win64-c]``."""
    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p
        foreign_identity(e, p["obj"], "ar")

        def write():
            D.text(e, "XAX.FOREIGN.ABI")
            D.cid(e, graph_cid_words(e, p["f"]))
            D.text(e, "NATIVE-FOREIGN-ABI")
            e.if_(e.eq(p["frame"], 1), lambda: D.text(e, WIN64_C.decode()), lambda: e.if_(e.eq(p["frame"], 2), lambda: (
                D.put(e, D.T_LIST), D.put(e, 1), D.text(e, WIN64_C.decode())), lambda: (
                D.put(e, D.T_LIST), D.put(e, len(REGISTER_OWNED)), [D.text(e, abi.decode()) for abi in REGISTER_OWNED])))
            _packed(e, D.T_STR, p["ar_abi"], p["ar_alen"])

        reject_at(e, write)
    return _function(("obj", "f", "frame"), build, tables)


def _one_result_reject_fn(tables):
    """SYSCALL-ONE-RESULT of function ``f``: a syscall node with ``results`` results, more than one of them machine."""
    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p

        def write():
            D.text(e, "XAX.NATIVE.FOREIGN_ABI")
            D.cid(e, graph_cid_words(e, p["f"]))
            D.text(e, "SYSCALL-ONE-RESULT")
            D.integer(e, 1)
            D.integer(e, p["results"])

        reject_at(e, write)
    return _function(("f", "results"), build, tables)


def _startup_name_reject_fn(tables):
    """LINUX-STARTUP-NAME of declaration ``obj`` in function ``f``: a startup read of another name."""
    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p
        foreign_identity(e, p["obj"], "sn")

        def write():
            D.text(e, "XAX.NATIVE.STARTUP")
            D.cid(e, graph_cid_words(e, p["f"]))
            D.text(e, "LINUX-STARTUP-NAME")
            D.text(e, STARTUP_EXPECTED)
            _packed(e, D.T_STR, p["sn_at"], p["sn_len"])

        reject_at(e, write)
    return _function(("obj", "f"), build, tables)


def _template_reject_fn(tables):
    """``decode_syscall_name``'s rejection of syscall declaration ``obj``'s name for ``m`` machine operands
    (SYSCALL-TEMPLATE-CANONICAL, then SYSCALL-TEMPLATE-OPERANDS); declines when the name is valid (another check
    stopped the program's lowering)."""
    def build(e: E):
        from xax_selfhost_general_emit import reject_at

        p = e.p
        m = p["m"]
        foreign_identity(e, p["obj"], "tr")
        start, length = p["tr_at"], p["tr_len"]
        e.var("tr_end", e.add(start, length))
        e.var("tr_pos", start)
        e.var("tr_canon", 1)
        _ascii(e, start, length, "tr_text")
        e.if_(e.eq(p["tr_text"], 0), lambda: e.set("tr_canon", 0))

        def byte():
            inside = e.lt(p["tr_pos"], p["tr_end"])
            return e.sel(inside, e.rd(e.sel(inside, p["tr_pos"], start)), 256)

        def digits(name: str, limit: int):
            """Decimal digits at ``tr_pos``: ``name`` (``name_o`` 1 above ``limit``), their count ``name_n``, the
            first ``name_f``; a canonical decimal is ``name_c``."""
            e.var(name, 0)
            e.var(f"{name}_n", 0)
            e.var(f"{name}_o", 0)
            e.var(f"{name}_f", byte())

            def step():
                e.var("tr_d", e.sub(byte(), 48))
                fits = e.le(p[name], e.udiv(e.sub(limit, p["tr_d"]), 10))
                e.if_(fits, lambda: e.set(name, e.add(e.mul(p[name], 10), p["tr_d"])), lambda: e.set(f"{name}_o", 1))
                e.set(f"{name}_n", e.add(p[f"{name}_n"], 1))
                e.set("tr_pos", e.add(p["tr_pos"], 1))

            e.while_(lambda: e.both(e.le(48, byte()), e.le(byte(), 57)), step)
            e.var(f"{name}_c", e.flag(e.both(e.ne(p[f"{name}_n"], 0), e.either(e.eq(p[f"{name}_n"], 1), e.ne(p[f"{name}_f"], 48)),
                                             e.eq(p[f"{name}_o"], 0))))

        digits("tr_nr", (1 << 31) - 1)
        e.if_(e.eq(p["tr_nr_c"], 0), lambda: e.set("tr_canon", 0))
        e.var("tr_items", 0)
        e.var("tr_refs", 0)  # "$k" items
        e.var("tr_fresh", 1)  # each reference is below ``m`` and named once
        e.var("tr_used", 0)
        e.var("tr_template", 0)

        def template():
            e.set("tr_template", 1)
            e.set("tr_pos", e.add(p["tr_pos"], 1))
            e.var("tr_go", 1)

            def item():
                e.set("tr_items", e.add(p["tr_items"], 1))

                def reference():
                    e.set("tr_pos", e.add(p["tr_pos"], 1))
                    digits("tr_k", 1 << 20)  # any digits (``str.isdigit``); a large index names no operand
                    e.if_(e.eq(p["tr_k_n"], 0), lambda: e.set("tr_canon", 0))
                    e.set("tr_refs", e.add(p["tr_refs"], 1))
                    bit = e.c(0)
                    for k in range(SYSCALL_ARGUMENTS):
                        bit = e.add(bit, e.mul(e.flag(e.eq(p["tr_k"], k)), 1 << k))
                    e.var("tr_bit", bit)
                    e.if_(e.both(e.eq(p["tr_k_o"], 0), e.lt(p["tr_k"], m), e.ne(p["tr_bit"], 0), e.eq(e.and_(p["tr_used"], p["tr_bit"]), 0)),
                          lambda: e.set("tr_used", e.or_(p["tr_used"], p["tr_bit"])), lambda: e.set("tr_fresh", 0))

                def literal():
                    digits("tr_lit", (1 << 64) - 1)
                    e.if_(e.eq(p["tr_lit_c"], 0), lambda: e.set("tr_canon", 0))

                e.if_(e.eq(byte(), 36), reference, literal)  # "$"
                e.if_(e.le(p["tr_end"], p["tr_pos"]), lambda: e.set("tr_go", 0), lambda: e.if_(
                    e.eq(byte(), 44), lambda: e.set("tr_pos", e.add(p["tr_pos"], 1)), lambda: (e.set("tr_canon", 0), e.set("tr_go", 0))))  # ","

            e.while_(lambda: e.both(e.ne(p["tr_go"], 0), e.ne(p["tr_canon"], 0)), item)
            e.if_(e.lt(SYSCALL_ARGUMENTS, p["tr_items"]), lambda: e.set("tr_canon", 0))  # ``encode_syscall_name`` takes at most six

        e.if_(e.lt(p["tr_pos"], p["tr_end"]), lambda: e.if_(e.eq(byte(), 58), template, lambda: e.set("tr_canon", 0)))  # ":"
        # SYSCALL-TEMPLATE-OPERANDS: the references are exactly 0..m-1 (no template: the operands in order, at most six).
        operands = e.sel(e.ne(p["tr_template"], 0), e.flag(e.both(e.eq(p["tr_refs"], m), e.ne(p["tr_fresh"], 0))), e.flag(e.le(m, SYSCALL_ARGUMENTS)))
        e.var("tr_operands", operands)
        e.if_(e.both(e.ne(p["tr_canon"], 0), e.ne(p["tr_operands"], 0)), lambda: e.give(NONE))  # a valid template

        def arguments():
            """``list(arguments)``: each "$k" as written, each literal as its number; without a template "$0".."$m-1"."""
            def listed():
                e.set("tr_pos", e.add(e.add(start, p["tr_nr_n"]), 1))
                D.put(e, D.T_LIST)
                D.put(e, p["tr_items"])

                def item():
                    def reference():
                        e.var("tr_from", p["tr_pos"])
                        e.set("tr_pos", e.add(p["tr_pos"], 1))
                        digits("tr_k", 1 << 20)
                        _packed(e, D.T_STR, p["tr_from"], e.sub(p["tr_pos"], p["tr_from"]))

                    def literal():
                        digits("tr_lit", (1 << 64) - 1)
                        D.integer(e, p["tr_lit"])

                    e.if_(e.eq(byte(), 36), reference, literal)
                    e.set("tr_pos", e.add(p["tr_pos"], 1))  # past the ","

                e.for_("tr_q", 0, p["tr_items"], item)

            def ordered():
                D.put(e, D.T_LIST)
                D.put(e, m)
                e.for_("tr_q", 0, m, lambda: (D.put(e, D.T_FORMAT), D.text(e, "${}"), D.put(e, 1), D.integer(e, p["tr_q"])))

            e.if_(e.ne(p["tr_template"], 0), listed, ordered)

        def write():
            D.text(e, "XAX.FOREIGN.SYSCALL")
            _packed(e, D.T_HEX, start, length)
            e.if_(e.eq(p["tr_canon"], 0), lambda: (D.text(e, "SYSCALL-TEMPLATE-CANONICAL"), D.text(e, "nr or nr:arg,..."),
                                                   _packed(e, D.T_STR, start, length)),
                  lambda: (D.text(e, "SYSCALL-TEMPLATE-OPERANDS"), D.put(e, D.T_FORMAT), D.text(e, "each of {} machine operands exactly once"),
                           D.put(e, 1), D.integer(e, m), arguments()))

        reject_at(e, write)
    return _function(("obj", "m"), build, tables)


def _arity_reject_fn(tables):
    """NATIVE-CALL-ARITY of function ``f``: a call node with ``arguments`` machine arguments (a hidden result pointer
    counted) and ``results`` machine results, more than one."""
    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p

        def write():
            D.text(e, "XAX.NATIVE.ABI")
            D.cid(e, graph_cid_words(e, p["f"]))
            D.text(e, "NATIVE-CALL-ARITY")
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.text(e, "Win64 stack arguments")
            D.integer(e, 1)
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.integer(e, p["arguments"])
            D.integer(e, p["results"])

        reject_at(e, write)
    return _function(("arguments", "results", "f"), build, tables)


LOCATION_EXPECTED = ("register, spill, or home", "register or spill")  # ``ensure``, ``location``


def _location_reject_fn(tables):
    """NATIVE-VALUE-LOCATION of view value ``value`` in function ``f`` (``which``: ``LOCATION_EXPECTED``)."""
    from xax_selfhost_general_view import G_VPOS, POS_BLOCK, POS_INDEX, _vf

    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p
        e.var("lr_pos", _vf(e, G_VPOS, p["value"]))
        e.if_(e.eq(p["lr_pos"], NONE), lambda: e.give(NONE))

        def write():
            D.text(e, "XAX.NATIVE.VALUE")
            D.cid(e, graph_cid_words(e, p["f"]))
            D.text(e, "NATIVE-VALUE-LOCATION")
            for which, expected in enumerate(LOCATION_EXPECTED):
                e.if_(e.eq(p["which"], which), lambda expected=expected: D.text(e, expected))
            D.put(e, D.T_LIST)
            D.put(e, 3)
            D.integer(e, e.and_(e.udiv(p["lr_pos"], POS_BLOCK), (1 << 22) - 1))
            D.integer(e, e.and_(e.udiv(p["lr_pos"], POS_INDEX), (1 << 24) - 1))
            D.integer(e, e.and_(p["lr_pos"], (1 << 16) - 1))

        reject_at(e, write)
    return _function(("value", "which", "f"), build, tables)


def _imports_reject_fn(tables):
    """LINUX-IMPORT-SYMBOL-UNIQUE: the ``n`` distinct imports (declarations at ``names``, sorted by library and
    symbol), each quoted as ``[library, symbol]``."""
    def build(e: E):
        from xax_selfhost_general_emit import reject_at
        from xax_selfhost_general_image import _foreign_strings

        p = e.p

        def write():
            D.text(e, "XAX.LINUX.IMPORT")
            D.text(e, "elf")
            D.text(e, "LINUX-IMPORT-SYMBOL-UNIQUE")
            D.text(e, "one library per imported symbol")
            D.put(e, D.T_LIST)
            D.put(e, p["n"])

            def pair():
                _foreign_strings(e, e.ld(e.add(p["names"], p["ir_k"])), "ir")
                D.put(e, D.T_LIST)
                D.put(e, 2)
                _packed(e, D.T_BYTES, p["ir_lib"], p["ir_libn"])
                _packed(e, D.T_BYTES, p["ir_sym"], p["ir_symn"])

            e.for_("ir_k", 0, p["n"], pair)

        reject_at(e, write)
    return _function(("names", "n"), build, tables)


COM_PREFIX, VTABLE = b"com:", b"vtable:"
COM_MALFORMED = NONE - 1  # ``com_method_slot``'s -1


def _com_method_fn(tables):
    """``com_method_slot`` of ``win64-c`` declaration ``obj`` (S15e.3, ADR-317): NONE for an ordinary import (its library
    is not ``com:...``), the vtable slot of a well-formed COM method (``vtable:<k>``, canonical decimal below 2**24, a
    named interface, a ``bits<64>`` first input), else ``COM_MALFORMED``."""
    from xax_compiler import bits_type
    from xax_selfhost_general_image import _foreign_strings
    from xax_selfhost_views_backend import _payload_uleb

    first_input = bits_type(64).cid

    def build(e: E):
        p = e.p
        _foreign_strings(e, p["obj"], "cm")
        e.var("cm_com", e.flag(e.le(len(COM_PREFIX), p["cm_libn"])))
        e.if_(e.ne(p["cm_com"], 0), lambda: [e.if_(e.ne(e.rd(e.add(p["cm_lib"], k)), byte), lambda: e.set("cm_com", 0))
                                             for k, byte in enumerate(COM_PREFIX)])
        e.if_(e.eq(p["cm_com"], 0), lambda: e.give(NONE))
        # ``decode_com_slot``: the digits after ``vtable:``, no leading zero but ``0`` itself, below 2**24.
        e.var("cm_ok", e.flag(e.lt(len(VTABLE), p["cm_symn"])))
        e.if_(e.ne(p["cm_ok"], 0), lambda: [e.if_(e.ne(e.rd(e.add(p["cm_sym"], k)), byte), lambda: e.set("cm_ok", 0)) for k, byte in enumerate(VTABLE)])
        e.var("cm_slot", 0)
        e.var("cm_digits", e.sub(p["cm_symn"], len(VTABLE)))

        def digit():
            e.var("cm_d", e.rd(e.add(e.add(p["cm_sym"], len(VTABLE)), p["cm_k"])))
            e.if_(e.either(e.lt(p["cm_d"], 48), e.lt(57, p["cm_d"])), lambda: e.set("cm_ok", 0))
            e.if_(e.both(e.eq(p["cm_k"], 0), e.eq(p["cm_d"], 48), e.lt(1, p["cm_digits"])), lambda: e.set("cm_ok", 0))
            e.if_(e.lt(p["cm_slot"], 1 << 24), lambda: e.set("cm_slot", e.add(e.mul(p["cm_slot"], 10), e.sub(p["cm_d"], 48))))

        e.if_(e.ne(p["cm_ok"], 0), lambda: e.for_("cm_k", 0, p["cm_digits"], digit))
        e.if_(e.le(1 << 24, p["cm_slot"]), lambda: e.set("cm_ok", 0))
        e.if_(e.le(p["cm_libn"], len(COM_PREFIX)), lambda: e.set("cm_ok", 0))
        # The first input: the identity's inputs follow the name (their count, then 32-byte CIDs).
        e.var("cm_at", e.add(p["cm_sym"], p["cm_symn"]))
        e.var("cm_inputs", _payload_uleb(e, "cm_at"))
        e.if_(e.eq(p["cm_inputs"], 0), lambda: e.set("cm_ok", 0), lambda: [
            e.if_(e.ne(e.rd(e.add(p["cm_at"], k)), byte), lambda: e.set("cm_ok", 0)) for k, byte in enumerate(first_input)])
        e.give(e.sel(e.ne(p["cm_ok"], 0), p["cm_slot"], COM_MALFORMED))
    return _function(("obj",), build, tables)


def _com_reject_fn(tables):
    """WIN64-COM-METHOD of declaration ``obj`` in function ``f`` (a malformed COM method), quoting its name."""
    from xax_selfhost_general_image import _foreign_strings

    def build(e: E):
        from xax_selfhost_general_emit import graph_cid_words, reject_at

        p = e.p
        _foreign_strings(e, p["obj"], "cr")

        def write():
            D.text(e, "XAX.FOREIGN.ABI")
            D.cid(e, graph_cid_words(e, p["f"]))
            D.text(e, "WIN64-COM-METHOD")
            D.text(e, "vtable:<k> and a bits<64> interface pointer first")
            _packed(e, D.T_STR, p["cr_sym"], p["cr_symn"])

        reject_at(e, write)
    return _function(("obj", "f"), build, tables)


def add_reject_functions(add, tables):
    add("com_method", _com_method_fn(tables))
    add("com_reject", _com_reject_fn(tables))
    add("encoding_reject", _encoding_reject_fn(tables))
    add("pointer_width_reject", _pointer_width_reject_fn(tables))
    add("abi_reject", _abi_reject_fn(tables))
    add("one_result_reject", _one_result_reject_fn(tables))
    add("startup_name_reject", _startup_name_reject_fn(tables))
    add("template_reject", _template_reject_fn(tables))
    add("imports_reject", _imports_reject_fn(tables))
    add("arity_reject", _arity_reject_fn(tables))
    add("location_reject", _location_reject_fn(tables))
