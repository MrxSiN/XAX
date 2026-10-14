"""Self-hosting step S12a (ADR-268): the general x86-64 backend's front end as XAX semantics.

``xax_linux.compile_linux_executable`` lowers an ordinary program for ``x86_64-linux-elf-exec-v1`` (and the
dynamic-loader profile) with the general x86-64 backend (``xax_x86_64``).  Before any code is generated, the
bootstrap decides, in this order:

1. the target: its ABI must be the Linux x86-64 ABI and its image format an ELF executable
   (``LINUX-ELF-EXEC-TARGET``);
2. the process entry: a function (``LINUX-ENTRY-FUNCTION``) with no machine parameters and at most one machine
   result, a ``bits<N>`` (``LINUX-PROCESS-ENTRY-CONTRACT``);
3. the function closure (``xax_x86_64._function_closure``), depth first from the entry: per function the machine
   arity (``NATIVE-ABI-ARITY``, a hidden aggregate result counting as an argument) and every machine value's target
   ABI layout (``NATIVE-ABI-VALUE``, and ``ABI-LAYOUT-VALUE-TYPE`` for an aggregate component without one); per node
   in block order the target's operation list (``NATIVE-OP-TARGET-SUPPORTED``), a code address's foreign entry ABI
   (``SYSV-ENTRY-TARGET``, ``WIN64-ENTRY-TARGET``), and the visit of a called or addressed function that is not an
   erased proof function; per block the target's terminator list (``NATIVE-TERMINATOR-TARGET-SUPPORTED``);
4. the image's function order: the closure by CID.

This module builds one XAX program that decides all of it and writes either the order (as CIDs) or the exact
``Diagnostic`` record of the first rejection (``xax_selfhost_diagnostics``).  Its input is the views backends' object
table (``xax_riscv64._object_table``): every store object with its references and identity as CIDs, graph fragments
as XAX graph-decoder streams; the program finds the target and the entry and resolves every reference itself.  It runs
on a verified store: ``compile_linux_executable`` verifies first (ADR-268).  It declines (and the bootstrap decides)
when the closure reaches a recursion-group member, an entry ABI name is not ASCII, or an input exceeds its capacity.

Later S12 steps add the lowering view (inlining), the register-resident lowering, and image assembly to this program.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation, TerminatorKind, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
import xax_selfhost_diagnostics as D
from xax_selfhost_general_view import add_view_functions, views_prologue
from xax_selfhost_views_backend import (
    _FN, ARENA_AT, ARENA_END, CID_WORDS, G_ERASED, G_IFACE, G_NI, G_O, G_ORDER, G_PAY, G_REC, G_REFS, G_S, G_SUP, G_SUP_AT,
    G_SUPT, G_SUPT_AT, G_TW, GLOBALS, NI_ATTRIBUTES, NI_ENTITY, NI_OP, NI_RESULTS, NativeProgram, _at, _borrowed, _call,
    _cid_at, _cid_less, _cid_words, _erased, _find, _g, _interface, _kind, _node_info, _ok, _payload_uleb, _reference,
    _target_list, _term_end, _type_form, _type_width,
)

STORE_PATH = bootstrap_dir() / "xax_x86_64_general.xax"
OK = 1
COUNT_AT, ORDER_AT = 1, 16  # output words: the closure's size, then each function's four CID words in image order
# Front-end state beyond the views backends' globals (``GLOBALS + slot``).
(G_LSIZE, G_LALIGN, G_LSTACK, G_TABI, G_TFMT, G_NARGS, G_GENERAL, G_EA_AT, G_EA_N, G_FRAMES, G_TARGET, G_ENTRY,
 G_MEMBERS, G_MTAB, G_GROUPOF) = range(21, 36)
FRAME = 5  # a closure frame: function, graph, stream cursor, blocks left, nodes left in the current block
F_FN, F_GRAPH, F_AT, F_BLOCKS, F_NODES = range(FRAME)

LINUX_ABI = 5
ELF_FORMATS = (5, 6)  # X86_64_LINUX_ELF_EXEC_FORMAT, X86_64_LINUX_ELF_DYNAMIC_FORMAT
REGISTER_ARCHITECTURES = (1, 3)
OTHER_ARCHITECTURES = (2, 4, 5, 6, 7)  # AArch64, Wasm, JVM, RISC-V 64, SPIR-V: no register fields
LAYOUT_FORMS = (1, 2, 7, 8, 9, 10)
AGGREGATE_FORMS = (8, 9, 10)
LINK_BYTES, SUM_TAG_BYTES = 8, 4
CODE_ENTRY = b"code-entry:"
SYSV_C, LEND, WIN64_C = b"sysv-x86_64-c", b"sysv-x86_64-c-lend", b"win64-c"
# Foreign entry classes of a code-address type.
EA_NONE, EA_SYSV, EA_LEND, EA_WIN64, EA_OTHER = range(5)

# The bootstrap's rejections this program decides: (code, rule) by site.
RULES = (
    ("XAX.LINUX.TARGET", "LINUX-ELF-EXEC-TARGET"),
    ("XAX.LINUX.ENTRY", "LINUX-ENTRY-FUNCTION"),
    ("XAX.LINUX.ENTRY", "LINUX-PROCESS-ENTRY-CONTRACT"),
    ("XAX.NATIVE.ABI", "NATIVE-ABI-ARITY"),
    ("XAX.NATIVE.VALUE", "NATIVE-ABI-VALUE"),
    ("XAX.ABI.LAYOUT", "ABI-LAYOUT-VALUE-TYPE"),
    ("XAX.NATIVE.UNSUPPORTED_OPERATION", "NATIVE-OP-TARGET-SUPPORTED"),
    ("XAX.NATIVE.FOREIGN_ENTRY", "SYSV-ENTRY-TARGET"),
    ("XAX.NATIVE.FOREIGN_ENTRY", "WIN64-ENTRY-TARGET"),
    ("XAX.NATIVE.UNSUPPORTED_TERMINATOR", "NATIVE-TERMINATOR-TARGET-SUPPORTED"),
)
SITE = {rule: site for site, (_code, rule) in enumerate(RULES)}
ABI_ARITY_EXPECTED = "Win64 stack arguments"
ABI_VALUE_EXPECTED = "scalar <=64 bits or aggregate with a target ABI layout"
LAYOUT_EXPECTED = "bits, pointer, float, tuple, array, or sum"
ENTRY_CONTRACT_EXPECTED = "fn(proof...) -> (bits<N>?, proof...)"


# -- record writers ---------------------------------------------------------------------------------

def _diagnostic(tables):
    """The record's code, entity CID (object ``entity``), and rule for ``site``: one copy of each text."""
    def build(e: E):
        p = e.p
        for site, (code, _rule) in enumerate(RULES):
            e.if_(e.eq(p["site"], site), lambda code=code: D.text(e, code))
        D.cid(e, _cid_words(e, p["entity"]))
        for site, (_code, rule) in enumerate(RULES):
            e.if_(e.eq(p["site"], site), lambda rule=rule: D.text(e, rule))
        e.give(1)
    return _function(("site", "entity"), build, tables)


def _reject(e: E, condition, rule: str, entity, expected, actual):
    """Unless ``condition``: reject under ``rule`` on object ``entity``; ``expected()``/``actual()`` write the values."""
    def write():
        e.call(_FN["diagnostic"], SITE[rule], entity)
        expected()
        actual()
    D.reject_unless(e, condition, write)


def _text_at(tables):
    """A STR value of the ``n`` input bytes (one per word) at ``at``, packed eight to a word."""
    def build(e: E):
        p = e.p
        D.put(e, D.T_STR)
        D.put(e, p["n"])

        def word():
            e.var("tw_word", 0)
            e.var("tw_weight", 1)

            def byte():
                index = e.add(e.mul(p["tw_k"], 8), p["tw_j"])
                e.if_(e.lt(index, p["n"]), lambda: e.set("tw_word", e.add(p["tw_word"], e.mul(e.rd(e.add(p["at"], index)), p["tw_weight"]))))
                e.set("tw_weight", e.mul(p["tw_weight"], 256))

            e.for_("tw_j", 0, 8, byte)
            D.put(e, p["tw_word"])

        e.for_("tw_k", 0, e.udiv(e.add(p["n"], 7), 8), word)
        e.give(1)
    return _function(("at", "n"), build, tables)


def _ascii(e: E, at, n, name: str):
    """Set ``name`` to 0 unless every byte of the ``n`` at input word ``at`` is ASCII."""
    e.var(name, 1)
    e.for_(f"{name}_k", 0, n, lambda: e.if_(e.le(128, e.rd(e.add(at, e.p[f"{name}_k"]))), lambda: e.set(name, 0)))


def _bytes_equal(e: E, at, n, data: bytes):
    """The ``n`` input bytes at ``at`` are ``data``."""
    return e.both(e.eq(n, len(data)), *(e.eq(e.rd(e.add(at, k)), byte) for k, byte in enumerate(data)))


def _starts_with(e: E, at, n, data: bytes):
    return e.both(e.le(len(data), n), *(e.eq(e.rd(e.add(at, k)), byte) for k, byte in enumerate(data)))


# -- ABI layouts ------------------------------------------------------------------------------------

def _layout(tables):
    """``abi_layout`` of TYPE object ``t`` (pointer bytes 8): its size, the alignment memoised in ``G_LALIGN``; NONE on
    a rejection (a component without a layout, ``ABI-LAYOUT-VALUE-TYPE``) or a decline.  Components are laid out
    depth first in their order, with an explicit stack, so the first component the bootstrap's recursion would reject
    is the one rejected."""
    def build(e: E):
        p = e.p
        sizes, aligns, stack = _g(e, G_LSIZE), _g(e, G_LALIGN), _g(e, G_LSTACK)
        e.if_(e.ne(e.ld(e.add(aligns, p["t"])), 0), lambda: e.give(e.ld(e.add(sizes, p["t"]))))
        e.var("ld", 1)
        e.st(stack, p["t"])

        def done(size, alignment):
            e.st(e.add(sizes, p["lo"]), size)
            e.st(e.add(aligns, p["lo"]), alignment)
            e.set("ld", e.sub(p["ld"], 1))

        def push(item):
            _ok(e, e.lt(p["ld"], _g(e, G_O)))
            e.st(e.add(stack, p["ld"]), item)
            e.set("ld", e.add(p["ld"], 1))

        def member(k):
            """The object index of a component reference (a verified type)."""
            item = _reference(e, p["lo"], k)
            _ok(e, e.both(e.ne(item, NONE), e.eq(_kind(e, item), int(Kind.TYPE)), e.ne(e.rd(e.sub(_at(e, G_PAY, item), 1)), 0)))
            return item

        def step():
            e.var("lo", e.ld(e.add(stack, e.sub(p["ld"], 1))))
            e.var("lpay", _at(e, G_PAY, p["lo"]))
            e.var("lat", p["lpay"])
            e.var("lform", _payload_uleb(e, "lat"))
            form = p["lform"]

            def bits():
                e.var("lw", _payload_uleb(e, "lat"))
                w = p["lw"]
                size = e.sel(e.le(w, 8), 1, e.sel(e.le(w, 16), 2, e.sel(e.le(w, 32), 4, e.sel(e.le(w, 64), 8, e.mul(8, e.udiv(e.add(w, 63), 64))))))
                e.var("lsize", size)
                done(p["lsize"], e.sel(e.lt(p["lsize"], 8), p["lsize"], 8))

            def float_():
                size = e.sel(e.eq(_payload_uleb(e, "lat"), 1), 4, 8)
                e.var("lsize", size)
                done(p["lsize"], p["lsize"])

            def components(count_first: bool):
                """Tuple (count, refs) or sum (count, refs): lay out every component, then this one."""
                e.var("lcount", _payload_uleb(e, "lat"))
                e.var("lrefs", p["lat"])
                e.var("lmissing", NONE)

                def scan():
                    e.var("lref", _payload_uleb(e, "lat"))
                    e.var("litem", member(p["lref"]))
                    e.if_(e.both(e.eq(p["lmissing"], NONE), e.eq(e.ld(e.add(aligns, p["litem"])), 0)), lambda: e.set("lmissing", p["litem"]))

                e.for_("lq", 0, p["lcount"], scan)

                def complete():
                    e.set("lat", p["lrefs"])
                    e.var("lcursor", 0)
                    e.var("lalign", 1)
                    e.var("lmax", 0)

                    def each():
                        e.var("litem", member(_payload_uleb(e, "lat")))
                        size, alignment = e.ld(e.add(sizes, p["litem"])), e.ld(e.add(aligns, p["litem"]))
                        e.var("lis", size)
                        e.var("lia", alignment)
                        aligned = e.mul(e.udiv(e.add(p["lcursor"], e.sub(p["lia"], 1)), p["lia"]), p["lia"])
                        e.set("lcursor", e.add(aligned, p["lis"]))
                        e.if_(e.lt(p["lalign"], p["lia"]), lambda: e.set("lalign", p["lia"]))
                        e.if_(e.lt(p["lmax"], p["lis"]), lambda: e.set("lmax", p["lis"]))

                    e.for_("lq", 0, p["lcount"], each)
                    if count_first:  # tuple
                        done(e.mul(e.udiv(e.add(p["lcursor"], e.sub(p["lalign"], 1)), p["lalign"]), p["lalign"]), p["lalign"])
                    else:  # sum: tag, then the payload at its alignment
                        _ok(e, e.ne(p["lcount"], 0))
                        e.var("lsa", e.sel(e.lt(p["lalign"], SUM_TAG_BYTES), SUM_TAG_BYTES, p["lalign"]))
                        e.var("lpo", e.mul(e.udiv(e.add(SUM_TAG_BYTES, e.sub(p["lalign"], 1)), p["lalign"]), p["lalign"]))
                        done(e.mul(e.udiv(e.add(e.add(p["lpo"], p["lmax"]), e.sub(p["lsa"], 1)), p["lsa"]), p["lsa"]), p["lsa"])

                e.if_(e.eq(p["lmissing"], NONE), complete, lambda: push(p["lmissing"]))

            def array():
                e.var("litem", member(_payload_uleb(e, "lat")))
                e.var("lcount", _payload_uleb(e, "lat"))

                def complete():
                    size, alignment = e.ld(e.add(sizes, p["litem"])), e.ld(e.add(aligns, p["litem"]))
                    e.var("lis", size)
                    e.var("lia", alignment)
                    _ok(e, e.both(e.lt(p["lcount"], 1 << 32), e.lt(p["lis"], 1 << 31)))
                    # Each element's size is a multiple of its alignment, so element k sits at k * size.
                    empty = e.eq(p["lcount"], 0)
                    done(e.mul(p["lcount"], p["lis"]), e.sel(empty, 1, p["lia"]))

                e.if_(e.eq(e.ld(e.add(aligns, p["litem"])), 0), lambda: push(p["litem"]), complete)

            def reject():
                _reject(e, e.eq(1, 0), "ABI-LAYOUT-VALUE-TYPE", p["lo"],
                        lambda: D.text(e, LAYOUT_EXPECTED), lambda: D.integer(e, form))

            e.if_(e.eq(form, 1), bits, lambda: e.if_(e.eq(form, 2), lambda: done(8, 8), lambda: e.if_(
                e.eq(form, 7), float_, lambda: e.if_(e.eq(form, 11), lambda: done(LINK_BYTES, LINK_BYTES), lambda: e.if_(
                    e.eq(form, 8), lambda: components(True), lambda: e.if_(e.eq(form, 9), array, lambda: e.if_(
                        e.eq(form, 10), lambda: components(False), reject)))))))

        e.while_(lambda: e.ne(p["ld"], 0), step)
        e.give(e.ld(e.add(sizes, p["t"])))
    return _function(("t",), build, tables)


# -- function interfaces, recursion groups included ------------------------------------------------------

def _group_interface(tables):
    """``_decode_function_interface`` of a verified function (ADR-125 group members included):
    ``[graph, P, types, R, types]`` (cached); a member function's record is its group member's, and its group goes
    to ``G_GROUPOF``.  NONE for an unlisted object."""
    def build(e: E):
        p = e.p
        f = p["f"]
        cached = _at(e, G_IFACE, f)
        e.if_(e.ne(cached, NONE), lambda: e.give(cached))
        _ok(e, e.eq(_kind(e, f), int(Kind.FUNCTION)))
        e.var("ia", _at(e, G_PAY, f))
        carrier = _reference(e, f, _payload_uleb(e, "ia"))
        e.var("carrier", carrier)
        _ok(e, e.ne(p["carrier"], NONE))
        e.var("source", f)  # the object whose references the interface names

        def member():
            e.var("imember", _payload_uleb(e, "ia"))
            e.st(e.add(_g(e, G_GROUPOF), f), p["carrier"])
            e.set("source", p["carrier"])
            e.set("ia", _at(e, G_PAY, p["carrier"]))
            e.var("icount", _payload_uleb(e, "ia"))
            _ok(e, e.lt(p["imember"], p["icount"]))

            def skip():
                _payload_uleb(e, "ia")
                e.var("iskip", _payload_uleb(e, "ia"))
                e.for_("iq", 0, p["iskip"], lambda: _payload_uleb(e, "ia"))
                e.set("iskip", _payload_uleb(e, "ia"))
                e.for_("iq", 0, p["iskip"], lambda: _payload_uleb(e, "ia"))

            e.for_("ik", 0, p["imember"], skip)
            e.set("carrier", _reference(e, p["carrier"], _payload_uleb(e, "ia")))
            _ok(e, e.ne(p["carrier"], NONE))

        e.if_(e.eq(_kind(e, p["carrier"]), int(Kind.RECURSION_GROUP)), member)
        _ok(e, e.eq(_kind(e, p["carrier"]), int(Kind.GRAPH_FRAGMENT)))
        params = _payload_uleb(e, "ia")
        e.var("np", params)
        e.var("record", e.alloc(e.add(p["np"], 2)))
        _ok(e, e.ne(p["record"], NONE))
        e.st(p["record"], p["carrier"])
        e.st(e.add(p["record"], 1), p["np"])
        e.for_("q", 0, p["np"], lambda: e.st(e.add(e.add(p["record"], 2), p["q"]), _reference(e, p["source"], _payload_uleb(e, "ia"))))
        returns = _payload_uleb(e, "ia")
        e.var("nr", returns)
        e.var("rec2", e.alloc(e.add(p["nr"], 1)))
        _ok(e, e.both(e.ne(p["rec2"], NONE), e.eq(p["rec2"], e.add(e.add(p["record"], 2), p["np"]))))  # contiguous
        e.st(p["rec2"], p["nr"])
        e.for_("q", 0, p["nr"], lambda: e.st(e.add(e.add(p["rec2"], 1), p["q"]), _reference(e, p["source"], _payload_uleb(e, "ia"))))
        e.st(e.add(_g(e, G_IFACE), f), p["record"])
        e.give(p["record"])
    return _function(("f",), build, tables)


# -- per function -------------------------------------------------------------------------------------

def _proof(e: E, t):
    """``_is_proof_type``: an effect or resource type."""
    return e.eq(_type_width(e, t), 0)


def _prologue(tables):
    """``_function_closure``'s checks of function ``f`` before its graph: machine arity and every machine value's
    layout.  1, or NONE (rejected or declined)."""
    def build(e: E):
        p = e.p
        iface = _call(e, "interface", p["f"])
        e.var("pi", iface)
        e.var("pnp", e.ld(e.add(p["pi"], 1)))
        e.var("prt", e.add(e.add(p["pi"], 2), p["pnp"]))
        e.var("pnr", e.ld(p["prt"]))
        e.var("pb", _call(e, "borrowed", p["f"]))

        def param(q):
            return e.ld(e.add(e.add(p["pi"], 2), q))

        def ret(q):
            return e.ld(e.add(e.add(p["prt"], 1), q))

        def machine_return(q):
            return e.both(e.not_(_proof(e, ret(q))), e.eq(e.ld(e.add(p["pb"], q)), NONE))

        e.var("pmp", 0)
        e.for_("q", 0, p["pnp"], lambda: e.if_(e.not_(_proof(e, param(p["q"]))), lambda: e.set("pmp", e.add(p["pmp"], 1))))
        e.var("pmr", 0)
        e.var("pfirst", NONE)
        e.for_("q", 0, p["pnr"], lambda: e.if_(machine_return(p["q"]), lambda: (
            e.if_(e.eq(p["pmr"], 0), lambda: e.set("pfirst", ret(p["q"]))), e.set("pmr", e.add(p["pmr"], 1)))))
        # A Win64 by-reference result (an aggregate not of 1, 2, 4, or 8 bytes) takes the first argument position.
        e.var("phidden", 0)

        def first_result():
            form = _type_form(e, p["pfirst"])
            e.var("pform", form)

            def aggregate():
                size = _call(e, "layout", p["pfirst"])
                e.var("psize", size)
                e.if_(e.not_(e.either(*(e.eq(p["psize"], n) for n in (1, 2, 4, 8)))), lambda: e.set("phidden", 1))

            e.if_(e.either(*(e.eq(p["pform"], f) for f in AGGREGATE_FORMS)), aggregate)

        e.if_(e.ne(p["pmr"], 0), first_result)
        general = e.ne(_g(e, G_GENERAL), 0)
        e.var("pgeneral", e.flag(general))
        too_many = e.both(e.eq(p["pgeneral"], 0), e.lt(_g(e, G_NARGS), e.add(p["pmp"], p["phidden"])))

        def arity_expected():
            D.put(e, D.T_LIST)
            D.put(e, 2)
            e.if_(e.ne(p["pgeneral"], 0), lambda: D.text(e, ABI_ARITY_EXPECTED), lambda: D.integer(e, _g(e, G_NARGS)))
            D.integer(e, 1)

        def arity_actual():
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.integer(e, e.add(p["pmp"], p["phidden"]))
            D.integer(e, p["pmr"])

        _reject(e, e.not_(e.either(e.lt(1, p["pmr"]), too_many)), "NATIVE-ABI-ARITY", p["f"], arity_expected, arity_actual)

        def value_actual():
            D.put(e, D.T_LIST)
            D.put(e, e.add(p["pnp"], p["pnr"]))
            e.for_("vq", 0, p["pnp"], lambda: D.cid(e, _cid_words(e, param(p["vq"]))))
            e.for_("vq", 0, p["pnr"], lambda: D.cid(e, _cid_words(e, ret(p["vq"]))))

        def check(t):
            e.var("ct", t)
            e.var("cform", _type_form(e, p["ct"]))
            e.var("cbad", 1)

            def laid_out():
                size = _call(e, "layout", p["ct"])
                e.var("csize", size)
                aggregate = e.either(*(e.eq(p["cform"], f) for f in AGGREGATE_FORMS))
                e.set("cbad", e.flag(e.both(e.not_(aggregate), e.lt(8, p["csize"]))))

            e.if_(e.either(*(e.eq(p["cform"], f) for f in LAYOUT_FORMS)), laid_out)
            _reject(e, e.eq(p["cbad"], 0), "NATIVE-ABI-VALUE", p["f"], lambda: D.text(e, ABI_VALUE_EXPECTED), value_actual)

        e.for_("q", 0, p["pnp"], lambda: e.if_(e.not_(_proof(e, param(p["q"]))), lambda: check(param(p["q"]))))
        e.for_("q", 0, p["pnr"], lambda: e.if_(machine_return(p["q"]), lambda: check(ret(p["q"]))))
        e.give(1)
    return _function(("f",), build, tables)


def _entry_abi(tables):
    """``foreign_entry_abi`` of TYPE ``t``: a pointer whose element is an identity-qualified opaque type naming a code
    entry gives its class (``EA_*``; for ``EA_OTHER`` the ABI's input position and length go to ``G_EA_AT``/``G_EA_N``);
    any other type gives ``EA_NONE``."""
    def build(e: E):
        p = e.p
        e.if_(e.ne(_type_form(e, p["t"]), 2), lambda: e.give(EA_NONE))
        e.var("ea", e.add(_at(e, G_PAY, p["t"]), 1))
        _payload_uleb(e, "ea")  # address space
        e.var("eel", _reference(e, p["t"], _payload_uleb(e, "ea")))
        _ok(e, e.ne(p["eel"], NONE))
        e.if_(e.ne(_type_form(e, p["eel"]), 6), lambda: e.give(EA_NONE))
        e.var("ea", e.add(_at(e, G_PAY, p["eel"]), 1))
        e.var("en", _payload_uleb(e, "ea"))
        at, n = p["ea"], p["en"]
        lend = CODE_ENTRY + LEND + b":"
        e.if_(_starts_with(e, at, n, lend), lambda: e.give(EA_LEND))
        e.if_(e.not_(_starts_with(e, at, n, CODE_ENTRY)), lambda: e.give(EA_NONE))
        e.var("ea_at", e.add(at, len(CODE_ENTRY)))
        e.var("ea_n", e.sub(n, len(CODE_ENTRY)))
        e.if_(_bytes_equal(e, p["ea_at"], p["ea_n"], SYSV_C), lambda: e.give(EA_SYSV))
        e.if_(_bytes_equal(e, p["ea_at"], p["ea_n"], WIN64_C), lambda: e.give(EA_WIN64))
        e.st(GLOBALS + G_EA_AT, p["ea_at"])
        e.st(GLOBALS + G_EA_N, p["ea_n"])
        e.give(EA_OTHER)
    return _function(("t",), build, tables)


def _node(tables):
    """``_function_closure``'s checks of the node just read (``G_NI``) in graph ``g`` of function ``f``: the target's
    operation list and a code address's foreign entry ABI.  In a group member's graph ``call.group_member`` is a
    direct call of member ``member`` of the same group (``parse_function_graph``).  The function it visits (an
    unvisited, non-erased callee or addressed function) or NONE-1 when there is none; NONE when rejected or
    declined."""
    def build(e: E):
        p = e.p
        ni = _g(e, G_NI)
        raw = e.ld(e.add(ni, NI_OP))
        e.var("nraw", raw)
        group_call = e.eq(p["nraw"], int(Operation.CALL_GROUP_MEMBER))
        e.var("nop", e.sel(group_call, int(Operation.CALL_DIRECT), p["nraw"]))
        op = p["nop"]
        supported = e.both(e.lt(op, 256), e.ne(_at(e, G_SUP, e.sel(e.lt(op, 256), op, 0)), 0))
        _reject(e, supported, "NATIVE-OP-TARGET-SUPPORTED", p["g"], lambda: _target_list(e, G_SUP_AT), lambda: D.integer(e, op))

        def address():
            results = e.ld(e.add(ni, NI_RESULTS))
            _ok(e, e.ne(e.rd(results), 0))
            e.var("nt", _reference(e, p["g"], e.rd(e.add(results, 1))))
            _ok(e, e.ne(p["nt"], NONE))
            e.var("nabi", _call(e, "entry_abi", p["nt"]))
            abi = _g(e, G_TABI)
            sysv = e.either(e.eq(p["nabi"], EA_SYSV), e.eq(p["nabi"], EA_LEND))

            def sysv_expected():
                D.put(e, D.T_LIST)
                D.put(e, 2)
                D.text(e, SYSV_C.decode())
                D.integer(e, LINUX_ABI)

            def sysv_actual():
                D.put(e, D.T_LIST)
                D.put(e, 2)
                e.if_(e.eq(p["nabi"], EA_SYSV), lambda: D.text(e, SYSV_C.decode()), lambda: D.text(e, LEND.decode()))
                D.integer(e, abi)

            _reject(e, e.not_(e.both(sysv, e.ne(abi, LINUX_ABI))), "SYSV-ENTRY-TARGET", p["g"], sysv_expected, sysv_actual)
            _reject(e, e.not_(e.both(e.eq(p["nabi"], EA_WIN64), e.eq(abi, LINUX_ABI))), "WIN64-ENTRY-TARGET", p["g"],
                    lambda: D.text(e, "x86-64 Windows ABI"), lambda: D.integer(e, abi))

            def other():
                at, n = _g(e, G_EA_AT), _g(e, G_EA_N)
                e.var("nat", at)
                e.var("nn", n)
                _ascii(e, p["nat"], p["nn"], "nascii")
                _ok(e, e.ne(p["nascii"], 0))  # ``decode("ascii", "replace")`` text the record cannot carry
                _reject(e, e.eq(1, 0), "SYSV-ENTRY-TARGET", p["g"], lambda: D.text(e, "x86-64 foreign entry ABI"),
                        lambda: _call(e, "text_at", p["nat"], p["nn"]))

            e.if_(e.eq(p["nabi"], EA_OTHER), other)

        e.if_(e.eq(op, int(Operation.FUNCTION_ADDRESS)), address)
        e.var("nvisit", NONE - 1)

        def callee():
            e.var("nc", NONE)

            def direct():
                entity = e.ld(e.add(ni, NI_ENTITY))
                _ok(e, e.ne(entity, NONE))
                e.set("nc", _reference(e, p["g"], entity))

            def sibling():
                group = e.ld(e.add(_g(e, G_GROUPOF), p["f"]))
                e.var("ngroup", group)
                _ok(e, e.ne(p["ngroup"], NONE))
                members = e.ld(e.add(_g(e, G_MTAB), p["ngroup"]))
                e.var("nmembers", members)
                _ok(e, e.both(e.ne(p["nmembers"], NONE), e.lt(p["member"], e.ld(p["nmembers"]))))
                e.set("nc", e.ld(e.add(e.add(p["nmembers"], 1), p["member"])))

            e.if_(e.eq(p["nraw"], int(Operation.CALL_GROUP_MEMBER)), sibling, direct)
            _ok(e, e.ne(p["nc"], NONE))

            def function():
                fresh = e.eq(e.ld(e.add(_g(e, G_TW), p["nc"])), 0)
                e.if_(e.both(fresh, e.eq(_call(e, "erased", p["nc"]), 0)), lambda: e.set("nvisit", p["nc"]))

            e.if_(e.eq(_kind(e, p["nc"]), int(Kind.FUNCTION)), function)

        e.if_(e.either(e.eq(op, int(Operation.CALL_DIRECT)), e.eq(op, int(Operation.FUNCTION_ADDRESS))), callee)
        e.give(p["nvisit"])
    return _function(("g", "f", "member"), build, tables)


# -- the program --------------------------------------------------------------------------------------

def _push(e: E, f):
    """Visit function ``f``: mark it, record it, run its prologue checks, and open a frame at its first block."""
    p = e.p
    e.var("vf", f)
    e.st(e.add(_g(e, G_TW), p["vf"]), 1)
    e.st(e.add(_g(e, G_ORDER), _g(e, G_MEMBERS)), p["vf"])
    e.st(GLOBALS + G_MEMBERS, e.add(_g(e, G_MEMBERS), 1))
    _call(e, "prologue", p["vf"])
    e.var("vg", e.ld(_call(e, "interface", p["vf"])))
    stream = _at(e, G_PAY, p["vg"])
    e.var("vs", stream)
    e.var("vframe", e.add(_g(e, G_FRAMES), e.mul(p["depth"], FRAME)))
    blocks = e.rd(p["vs"])
    _ok(e, e.ne(blocks, 0))
    first = e.add(p["vs"], 2)
    nodes_at = e.add(e.add(first, 1), e.rd(first))  # past the first block's parameters
    for field, value in ((F_FN, p["vf"]), (F_GRAPH, p["vg"]), (F_BLOCKS, blocks), (F_NODES, e.rd(nodes_at)), (F_AT, e.add(nodes_at, 1))):
        e.st(e.add(p["vframe"], field), value)
    e.set("depth", e.add(p["depth"], 1))


def _frontend(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, ARENA_AT + 64)
        e.set_hd(H_ARENA_END, ARENA_END)
        S = e.rd(0)
        e.st(GLOBALS + G_S, S)
        # The store's objects, the bound target, then the count and records of the group member functions the store
        # does not hold (``general_object_table``).
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
        e.var("ra", 1 + CID_WORDS)

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
            e.if_(e.eq(o, S), lambda: e.set("ra", e.add(p["ra"], 1)))  # past the extras count

        e.set("ra", 1 + CID_WORDS)
        e.for_("o", 0, total, record)
        e.var("ext_at", p["ra"])  # S12b: the verifier's pointer extents per graph follow the object records
        from xax_selfhost_typing import IN_WORDS

        _ok(e, e.le(p["ra"], IN_WORDS))
        e.st(GLOBALS + G_O, S)
        e.var("target", e.call(_FN["find"], _cid_at(e, S)))
        e.if_(e.eq(p["target"], NONE), lambda: e.set("target", S))
        e.st(GLOBALS + G_TARGET, p["target"])
        # Every listed object, the appended target and member functions included (the target's duplicate record at S,
        # when the store holds the target, is never named: ``find`` locates the stored one first).
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

        # Group member functions by (group, member) (ADR-125): ``[count, member function...]`` per recursion group.
        def member_function():
            o = p["o"]
            e.var("mg", _reference(e, o, 0))

            def listed():
                e.var("ma", _at(e, G_PAY, o))
                _ok(e, e.eq(_payload_uleb(e, "ma"), 0))
                e.var("mk", _payload_uleb(e, "ma"))
                e.var("mtable", e.ld(e.add(_g(e, G_MTAB), p["mg"])))

                def create():
                    e.var("mga", _at(e, G_PAY, p["mg"]))
                    e.var("mcount", _payload_uleb(e, "mga"))
                    e.set("mtable", e.alloc(e.add(p["mcount"], 1)))
                    _ok(e, e.ne(p["mtable"], NONE))
                    e.st(p["mtable"], p["mcount"])
                    e.for_("mq", 0, p["mcount"], lambda: e.st(e.add(e.add(p["mtable"], 1), p["mq"]), NONE))
                    e.st(e.add(_g(e, G_MTAB), p["mg"]), p["mtable"])

                e.if_(e.eq(p["mtable"], NONE), create)
                e.if_(e.lt(p["mk"], e.ld(p["mtable"])), lambda: e.st(e.add(e.add(p["mtable"], 1), p["mk"]), o))

            one = e.eq(e.rd(e.add(_at(e, G_REC, o), 1)), 1)
            e.if_(e.both(e.eq(_kind(e, o), int(Kind.FUNCTION)), one, e.ne(p["mg"], NONE)), lambda: e.if_(
                e.eq(_kind(e, p["mg"]), int(Kind.RECURSION_GROUP)), listed))

        e.for_("o", 0, O, lambda: e.if_(e.ne(e.rd(e.add(_at(e, G_REC, p["o"]), 1)), 0), member_function))

        # 1. The target (``decode_native_target``'s fields up to the terminator list, of a verified target object).
        target = p["target"]
        _ok(e, e.eq(_kind(e, target), int(Kind.TARGET)))
        e.var("ta", _at(e, G_PAY, target))
        identity = _payload_uleb(e, "ta")
        e.set("ta", e.add(p["ta"], identity))  # past the identity bytes
        fields = [_payload_uleb(e, "ta") for _ in range(6)]  # profile, architecture, abi, format, word, pointer bits
        e.var("t_arch", fields[1])
        e.var("t_abi", fields[2])
        e.var("t_fmt", fields[3])
        e.st(GLOBALS + G_TABI, p["t_abi"])
        e.st(GLOBALS + G_TFMT, p["t_fmt"])
        e.st(GLOBALS + G_NARGS, 0)

        def registers():
            _payload_uleb(e, "ta")  # stack alignment
            _payload_uleb(e, "ta")  # shadow space
            e.var("t_nargs", _payload_uleb(e, "ta"))
            e.st(GLOBALS + G_NARGS, p["t_nargs"])
            e.for_("q", 0, p["t_nargs"], lambda: _payload_uleb(e, "ta"))
            _payload_uleb(e, "ta")  # result register
            e.var("t_nscratch", _payload_uleb(e, "ta"))
            e.for_("q", 0, p["t_nscratch"], lambda: _payload_uleb(e, "ta"))

        arch = p["t_arch"]
        _ok(e, e.either(*(e.eq(arch, a) for a in (*REGISTER_ARCHITECTURES, *OTHER_ARCHITECTURES))))
        e.if_(e.either(*(e.eq(arch, a) for a in REGISTER_ARCHITECTURES)), registers)
        for table, slot, limit in ((G_SUP, G_SUP_AT, 256), (G_SUPT, G_SUPT_AT, 8)):
            e.st(GLOBALS + slot, p["ta"])
            e.var("tcount", _payload_uleb(e, "ta"))
            e.for_("q", 0, p["tcount"], lambda table=table, limit=limit: (lambda value: (_ok(e, e.lt(value, limit)), e.st(e.add(_g(e, table), value), 1)))(
                _payload_uleb(e, "ta")))
        sup = _g(e, G_SUP)
        e.st(GLOBALS + G_GENERAL, e.flag(e.either(*(e.ne(e.ld(e.add(sup, int(op))), 0) for op in (Operation.FLOAT_ADD, Operation.AGGREGATE_MAKE, Operation.SUM_MAKE)))))

        def target_expected():
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.integer(e, LINUX_ABI)
            D.put(e, D.T_LIST)
            D.put(e, len(ELF_FORMATS))
            for value in ELF_FORMATS:
                D.integer(e, value)

        def target_actual():
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.integer(e, p["t_abi"])
            D.integer(e, p["t_fmt"])

        linux = e.both(e.eq(p["t_abi"], LINUX_ABI), e.either(*(e.eq(p["t_fmt"], f) for f in ELF_FORMATS)))
        _reject(e, linux, "LINUX-ELF-EXEC-TARGET", target, target_expected, target_actual)

        # 2. The process entry (``validate_process_entry``).
        e.var("entry", e.call(_FN["find"], 1))
        _ok(e, e.ne(p["entry"], NONE))
        entry = p["entry"]
        e.st(GLOBALS + G_ENTRY, entry)

        def kind_name():
            for kind in Kind:
                e.if_(e.eq(_kind(e, entry), int(kind)), lambda kind=kind: D.text(e, kind.name))

        _ok(e, e.either(*(e.eq(_kind(e, entry), int(kind)) for kind in Kind)))
        _reject(e, e.eq(_kind(e, entry), int(Kind.FUNCTION)), "LINUX-ENTRY-FUNCTION", entry, lambda: D.text(e, Kind.FUNCTION.name), kind_name)
        e.var("ei", _call(e, "interface", entry))
        e.var("enp", e.ld(e.add(p["ei"], 1)))
        e.var("ert", e.add(e.add(p["ei"], 2), p["enp"]))
        e.var("emp", 0)
        e.for_("q", 0, p["enp"], lambda: e.if_(e.not_(_proof(e, e.ld(e.add(e.add(p["ei"], 2), p["q"])))), lambda: e.set("emp", e.add(p["emp"], 1))))
        e.var("emr", 0)
        e.var("einteger", 1)

        def entry_return():
            t = e.ld(e.add(e.add(p["ert"], 1), p["q"]))
            e.var("et", t)

            def machine():
                e.set("emr", e.add(p["emr"], 1))
                e.if_(e.ne(_type_form(e, p["et"]), 1), lambda: e.set("einteger", 0))

            e.if_(e.not_(_proof(e, p["et"])), machine)

        e.for_("q", 0, e.ld(p["ert"]), entry_return)

        def contract_actual():
            D.put(e, D.T_LIST)
            D.put(e, 2)
            D.integer(e, p["emp"])
            D.put(e, D.T_LIST)
            D.put(e, p["emr"])

            def each():
                t = e.ld(e.add(e.add(p["ert"], 1), p["q"]))
                e.var("et", t)
                e.if_(e.not_(_proof(e, p["et"])), lambda: D.cid(e, _cid_words(e, p["et"])))

            e.for_("q", 0, e.ld(p["ert"]), each)

        contract = e.both(e.eq(p["emp"], 0), e.le(p["emr"], 1), e.ne(p["einteger"], 0))
        _reject(e, contract, "LINUX-PROCESS-ENTRY-CONTRACT", entry, lambda: D.text(e, ENTRY_CONTRACT_EXPECTED), contract_actual)

        # 3. The closure, depth first in the bootstrap's order.
        e.st(GLOBALS + G_MEMBERS, 0)
        e.var("depth", 0)
        _push(e, entry)

        def step():
            e.var("fr", e.add(_g(e, G_FRAMES), e.mul(e.sub(p["depth"], 1), FRAME)))
            fr = p["fr"]

            def node():
                e.st(e.add(fr, F_NODES), e.sub(e.ld(e.add(fr, F_NODES)), 1))
                e.var("nat0", e.ld(e.add(fr, F_AT)))
                e.var("nmember", e.rd(e.add(p["nat0"], 1)))  # ``call.group_member``'s member index (else unused)
                e.st(e.add(fr, F_AT), _call(e, "node_info", p["nat0"]))
                e.var("visit", _call(e, "node", e.ld(e.add(fr, F_GRAPH)), e.ld(e.add(fr, F_FN)), p["nmember"]))
                e.if_(e.ne(p["visit"], NONE - 1), lambda: _push(e, p["visit"]))

            def terminator():
                e.var("tat", e.ld(e.add(fr, F_AT)))
                kind = e.rd(p["tat"])
                e.var("tkind", kind)
                supported = e.both(e.lt(p["tkind"], 8), e.ne(_at(e, G_SUPT, e.sel(e.lt(p["tkind"], 8), p["tkind"], 0)), 0))
                _reject(e, supported, "NATIVE-TERMINATOR-TARGET-SUPPORTED", e.ld(e.add(fr, F_GRAPH)), lambda: _target_list(e, G_SUPT_AT),
                        lambda: D.tagged(e, D.T_TERMINATOR, p["tkind"]))
                e.set("tat", _call(e, "term_end", p["tat"]))
                e.st(e.add(fr, F_BLOCKS), e.sub(e.ld(e.add(fr, F_BLOCKS)), 1))

                def next_block():
                    nodes_at = e.add(e.add(p["tat"], 1), e.rd(p["tat"]))
                    e.var("tnodes", nodes_at)
                    e.st(e.add(fr, F_NODES), e.rd(p["tnodes"]))
                    e.st(e.add(fr, F_AT), e.add(p["tnodes"], 1))

                e.if_(e.ne(e.ld(e.add(fr, F_BLOCKS)), 0), next_block, lambda: e.set("depth", e.sub(p["depth"], 1)))

            e.if_(e.ne(e.ld(e.add(fr, F_NODES)), 0), node, terminator)

        e.while_(lambda: e.ne(p["depth"], 0), step)

        # 4. The image order: the closure by CID.
        order = _g(e, G_ORDER)
        members = _g(e, G_MEMBERS)
        e.var("members", members)

        def insert():
            e.var("item", e.ld(e.add(order, p["s"])))
            e.var("j", p["s"])
            before = lambda: e.both(e.lt(0, p["j"]), _cid_less(e, _cid_at(e, p["item"]), _cid_at(e, e.ld(e.add(order, e.sub(p["j"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(order, p["j"]), e.ld(e.add(order, e.sub(p["j"], 1)))), e.set("j", e.sub(p["j"], 1))))
            e.st(e.add(order, p["j"]), p["item"])

        e.for_("s", 1, p["members"], insert)
        _ok(e, e.lt(e.add(ORDER_AT, e.mul(p["members"], CID_WORDS)), D.DIAG_AT))
        e.st(COUNT_AT, p["members"])

        def out():
            for k, word in enumerate(_cid_words(e, e.ld(e.add(order, p["q"])))):
                e.st(e.add(e.add(ORDER_AT, e.mul(p["q"], CID_WORDS)), k), word)

        e.for_("q", 0, p["members"], out)
        # S12b: the lowering view of every closure function, in image order.
        views_prologue(e, total, order, p["members"])
        e.st(0, OK)
        e.give(1)
    return _function((), build, tables)


def build_general_program():
    """``(reader, function)``: the general backend program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("find", _find(tables))
    add("diagnostic", _diagnostic(tables))
    add("text_at", _text_at(tables))
    add("node_info", _node_info(tables))
    add("term_end", _term_end(tables))
    add("interface", _group_interface(tables))
    add("erased", _erased(tables))
    add("borrowed", _borrowed(tables))
    add("layout", _layout(tables))
    add("entry_abi", _entry_abi(tables))
    add("prologue", _prologue(tables))
    add("node", _node(tables))
    add_view_functions(add, tables)
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_general_program, "x86-64-general-frontend")
load_general_program = _PROGRAM.load
write_general_store = _PROGRAM.write
OPT_OUT = "XAX_GENERAL_FRONTEND_PYTHON"


def native_general():
    """The shared native front-end program, or None where it cannot run."""
    return _PROGRAM.native(OPT_OUT)


def collect_order(read) -> list[bytes] | None:
    """The function CIDs in image order the program wrote, or None (declined or rejected)."""
    (status,) = read(0, 1)
    if status != OK:
        return None
    (count,) = read(COUNT_AT, 1)
    words = read(ORDER_AT, count * CID_WORDS)
    return [b"".join(word.to_bytes(8, "big") for word in words[k:k + CID_WORDS]) for k in range(0, len(words), CID_WORDS)]


def general_object_table(reader, entry_cid: bytes, target_object, audit: bool = False):
    """``(words, member functions)``: the views backends' object table (``object_table_words``), then the count and
    records of every recursion group member function (``group_member_function``) the store does not hold, so the
    program can name each group member a ``call.group_member`` reaches; None when a graph cannot be streamed.  The
    host only enumerates the members' canonical identities; the program decides which are reached."""
    from xax_compiler import Kind, Cursor, group_member_function
    from xax_riscv64 import _cid_words, object_table_words

    words = object_table_words(reader, entry_cid, target_object)
    if words is None:
        return None
    stored = {obj.cid for obj in reader.objects()}
    extras = []
    for obj in reader.objects():
        if obj.kind == Kind.RECURSION_GROUP:
            for member in range(Cursor(obj.body, obj.cid.hex()).uleb()):
                function = group_member_function(obj, member)
                if function.cid not in stored:
                    extras.append(function)
    words.append(len(extras))
    for obj in extras:
        words += [int(obj.kind), len(obj.references)]
        for cid in obj.references:
            words += _cid_words(cid)
        words += [*_cid_words(obj.cid), len(obj.body), *obj.body]
    # S12b: the verifier's pointer extents of every graph fragment (``_parse_graph(...).pointer_extents``).
    from xax_compiler import _parse_graph, store_resolver

    resolve = store_resolver(reader)
    graphs = [obj for obj in reader.objects() if obj.kind == Kind.GRAPH_FRAGMENT]
    words.append(len(graphs))
    for obj in graphs:
        extents = _parse_graph(obj, resolve).pointer_extents
        words += [*_cid_words(obj.cid), len(extents)]
        for ref, extent in extents:
            words += [ref.tag, ref.block, ref.index, ref.result, extent]
    words.append(int(audit))  # S12c.1: write every value's range bound (tests)
    return words, {obj.cid: obj for obj in extras}


def general_with_xax(reader, entry_cid: bytes, target_object, required: bool = False, audit: bool = False):
    """S12a-S12c.1: ``(closure, views, prefetches)`` as the XAX program decides them for a verified store: the entry's
    closure in image order and, per function CID, its lowering view (``xax_inline.inline_leaf_calls``, then the
    prefetch rewrite) rebuilt from the program's words, and its prefetch marks (absent where the host selects them).  It raises the ``XaxError`` the program wrote when it rejects.  None when the program cannot run or
    declines (the bootstrap then decides), unless ``required``."""
    import xax_native
    from xax_compiler import XaxError, fail, store_resolver
    from xax_selfhost_diagnostics import decode_diagnostic

    native = native_general()
    table = None if native is None else general_object_table(reader, entry_cid, target_object, audit)
    words, members = table if table is not None else (None, {})

    def collect(read):
        order = collect_order(read)
        return order, (None if order is None else _view_words(read)), decode_diagnostic(read)

    outcome = None if words is None else native.run(words, collect)
    order, view_words, diagnostic = outcome if outcome is not None else (None, None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    if order is None:
        if native is not None:
            xax_native.declined("x86-64-general-frontend", 1)
        if required:
            fail("XAX.X86_64.GENERAL_FRONTEND", entry_cid.hex(), "X86_64-XAX-GENERAL-FRONTEND", "accepted by the XAX general front end",
                 "unavailable or declined")
        return None
    resolve = store_resolver(reader)
    closure = tuple(members[cid] if cid in members else resolve(cid) for cid in order)
    views, prefetches, audits = rebuild_views(view_words, closure, resolve, audit)
    return (closure, views, prefetches, *audits) if audit else (closure, views, prefetches)


def closure_with_xax(reader, entry_cid: bytes, target_object, required: bool = False):
    """S12a: the functions of the entry's closure in image order (``general_with_xax``), or None."""
    result = general_with_xax(reader, entry_cid, target_object, required)
    return None if result is None else result[0]


def _view_words(read) -> list[int]:
    """The view region the program wrote (up to its cursor)."""
    from xax_selfhost_general_view import G_VIEW_OUT, VIEW_AT
    from xax_selfhost_views_backend import GLOBALS

    (end,) = read(GLOBALS + G_VIEW_OUT, 1)
    return read(VIEW_AT, end - VIEW_AT)


ANALYSIS_UNDECIDED, ANALYSIS_INELIGIBLE, ANALYSIS_DONE = range(3)


def _read_analysis(take, value, block_count: int):
    """A function's S12c.2 analysis record (``xax_selfhost_general_regalloc._write_analysis``): None when undecided,
    ``"ineligible"``, or the analyses in ``xax_x86_64_regalloc.ANALYSIS_AUDIT``'s normal form (``analysis_form``)."""
    (status,) = take()
    if status == ANALYSIS_UNDECIDED:
        return None
    if status == ANALYSIS_INELIGIBLE:
        return "ineligible"

    def _table(fields):
        result = {}
        for _ in range(take()[0]):
            ref = value()
            result[ref] = fields()
        return result

    def flags():
        return tuple(take(take()[0]))

    record = {}
    record["widths"] = _table(lambda: take()[0])
    record["has_call"] = take()[0]
    record["stack_storage"] = [(value(), *take(2)) for _ in range(take()[0])]
    record["nonzero"] = set(_table(lambda: None))
    record["fused"] = {block: index for block, index in enumerate(take(block_count)) if index != NONE}
    branch_tables = {}
    for block in range(block_count):
        if take()[0]:
            subject = value()
            entries = bytes(take(take()[0]))
            branch_tables[block] = (subject, entries, frozenset(flags()))
    record["branch_tables"] = branch_tables
    membership = {}
    for block in range(block_count):
        if take()[0]:
            subject = value()
            low, mask = take(2)
            membership[block] = (subject, low, mask, frozenset(flags()))
    record["membership"] = membership
    record["folded"] = _table(lambda: (value(), take()[0]))
    record["scaled"] = _table(lambda: (value(), take()[0]))
    record["erased"] = set(_table(lambda: None))
    record["rmw"] = _table(lambda: take()[0])
    record["rmw_erased"] = set(_table(lambda: None))
    record["value_tables"] = _table(lambda: (value(), bytes(take(take()[0]))))
    record["member_values"] = _table(lambda: (value(), *take(2)))
    record["compare_load"] = _table(lambda: (value(), value() if take()[0] else None, *take(2)))
    record["edge_sunk"] = _table(lambda: (value(), (lambda word: word - (1 << 64) if word >= 1 << 63 else word)(take()[0])))
    record["call_aliases"] = _table(lambda: value())
    uses = {}
    for block in range(block_count):
        entries = []
        for _ in range(take()[0]):
            ref = value()
            entries.append((ref, tuple(take(take()[0]))))
        uses[block] = entries
    record["uses"] = uses
    record["homes"] = [value() for _ in range(take()[0])]
    record["pinned"] = _table(lambda: take()[0])
    record["loop_headers"] = set(take(take()[0]))
    record["allocatable"] = tuple(take(take()[0]))
    pairs = take(2 * take()[0])
    record["hoisted"] = dict(zip(pairs[0::2], pairs[1::2]))
    record["shadow"], record["edge_spill_base"] = take(2)
    record["home_offset"] = _table(lambda: take()[0])
    record["parameter_slot"] = _table(lambda: take()[0])
    record["stack_offset"] = _table(lambda: take()[0])
    record["dynamic_spill_base"] = take()[0]
    return record


def analysis_form(analyses) -> dict | str:
    """``xax_x86_64_regalloc.ANALYSIS_AUDIT``'s dict in the form ``_read_analysis`` gives (``"ineligible"`` for None)."""
    if analyses is None:
        return "ineligible"
    form = dict(analyses)
    form["has_call"] = int(analyses["has_call"])
    form["uses"] = {block: list(uses.items()) for block, uses in analyses["uses"].items()}
    form["branch_tables"] = {block: (subject, table, frozenset(indices)) for block, (subject, table, indices) in analyses["branch_tables"].items()}
    form["membership"] = {block: (subject, low, mask, frozenset(tree)) for block, (subject, low, mask, tree) in analyses["membership"].items()}
    form["value_tables"] = {ref: (subject, bytes(table)) for ref, (subject, table) in analyses["value_tables"].items()}
    form["loop_headers"] = set(analyses["loop_headers"])
    return form


def rebuild_views(words, closure, resolve, audit: bool = False):
    """Each function's lowering view from the program's view words (``xax_selfhost_general_view``): nodes and blocks
    are taken from the graphs they came from and given the program's operands, as ``xax_inline._lower`` does.  The
    host decides nothing here."""
    from dataclasses import replace

    from xax_compiler import Terminator, TerminatorKind, ValueRef, parse_function_graph

    graphs: dict[int, object] = {}

    def graph(index: int):
        if index not in graphs:
            graphs[index] = parse_function_graph(closure[index], resolve)
        return graphs[index]

    position = 0

    def take(count: int = 1):
        nonlocal position
        position += count
        return words[position - count:position]

    def value():
        tag, block, index, result = take(4)
        return ValueRef(tag, block, index, result)

    views, prefetches, bounds, analyses = {}, {}, {}, {}
    while position < len(words):
        (fidx, entry, count) = take(3)
        blocks = []
        for _ in range(count):
            kind0, fn, bb, nn, node_count = take(5)
            origin = graph(fn).blocks[bb]
            parameters = origin.parameters if kind0 == 0 else origin.nodes[nn].results
            nodes = []
            for _ in range(node_count):
                nf, nb, nn2, operand_count = take(4)
                nodes.append(replace(graph(nf).blocks[nb].nodes[nn2], operands=tuple(value() for _ in range(operand_count))))
            kind, pfn, pb, value_count = take(4)
            values = tuple(value() for _ in range(value_count))
            edges = []
            for _ in range(take()[0]):
                target, argument_count = take(2)
                edges.append((target, tuple(value() for _ in range(argument_count))))
            payload = b"" if pfn == NONE else graph(pfn).blocks[pb].terminator.payload
            blocks.append(type(origin)(tuple(parameters), tuple(nodes), Terminator(TerminatorKind(kind), values, tuple(edges), payload)))
        extents = tuple((value(), take()[0]) for _ in range(take()[0]))
        views[closure[fidx].cid] = replace(graph(fidx), entry=entry, blocks=tuple(blocks), member_spans=(), pointer_extents=extents)
        # S12c.1: the prefetch marks the program selected (absent: the host selects them).
        (decided, count) = take(2)
        marks = {}
        for _ in range(count):
            head = value()
            marks[head] = tuple((value(), take()[0]) for _ in range(take()[0]))
        if decided:
            prefetches[closure[fidx].cid] = marks
        if audit and take()[0]:  # every value's bound (None for none), in view order
            view = views[closure[fidx].cid]
            refs = [ref for b, block in enumerate(view.blocks) for ref in (
                *(ValueRef.parameter(b, k) for k in range(len(block.parameters))),
                *(ValueRef.node_result(b, n, r) for n, node in enumerate(block.nodes) for r in range(len(node.results))))]
            bounds[closure[fidx].cid] = {ref: (None if none else bound) for ref, (none, bound) in zip(refs, (take(2) for _ in refs))}
        if audit:
            analyses[closure[fidx].cid] = _read_analysis(take, value, len(views[closure[fidx].cid].blocks))
    return views, prefetches, (bounds, analyses) if audit else bounds


__all__ = ["RULES", "build_general_program", "closure_with_xax", "general_with_xax", "rebuild_views", "load_general_program", "native_general", "write_general_store"]
