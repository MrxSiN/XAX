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

from xax_compiler import Kind, Operation, TerminatorKind
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, NONE, _function
import xax_selfhost_diagnostics as D
from xax_selfhost_views_backend import (
    _FN, CID_WORDS, G_NI, G_O, G_PAY, G_SUP, G_SUP_AT, G_TW, NI_ENTITY, NI_OP, NI_RESULTS, NativeProgram, _at, _call, _cid_words, _g, _kind, _ok, _payload_uleb, _reference, _target_list, _type_form, _type_width)

STORE_PATH = bootstrap_dir() / "xax_x86_64_general.xax"
OK = 1
COUNT_AT, ORDER_AT = 1, 16  # output words: the closure's size, then each function's four CID words in image order
# Front-end state beyond the views backends' globals (``GLOBALS + slot``).
(G_LSIZE, G_LALIGN, G_LSTACK, G_TABI, G_TFMT, G_NARGS, G_GENERAL, G_EA_AT, G_EA_N, G_FRAMES, G_TARGET, G_ENTRY,
 G_MEMBERS, G_MTAB, G_GROUPOF) = range(21, 36)
# S15e.3 (ADR-317): 1 for the Windows PE32+ profile (``_hosted_container``'s ``x86_64-windows-pe-v1``), 0 for Linux.
G_WINDOWS = 63
# S15f.2 (ADR-324): 1 for a Windows load image (architecture 1, ABI 1, format 1, not the PE profile): the Win64 frame path
# without the register-resident lowering, the hosted register path or a container; the image is the code alone.
G_RAWWIN = 190
LINUX_REQUEST = 2  # the audit word's Linux-executable bit (``general_object_table(linux=True)``)

LINUX_ABI = 5
LAYOUT_FORMS = (1, 2, 7, 8, 9, 10)
AGGREGATE_FORMS = (8, 9, 10)
LINK_BYTES, SUM_TAG_BYTES = 8, 4
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
    ("XAX.NATIVE.FUNCTION", "NATIVE-ENTRY-FUNCTION"),  # S15e.3: ``_compile_native_with_target``'s entry, on Windows
)
SITE = {rule: site for site, (_code, rule) in enumerate(RULES)}
ABI_ARITY_EXPECTED = "Win64 stack arguments"
ABI_VALUE_EXPECTED = "scalar <=64 bits or aggregate with a target ABI layout"
LAYOUT_EXPECTED = "bits, pointer, float, tuple, array, or sum"


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


def _ascii(e: E, at, n, name: str):
    """Set ``name`` to 0 unless every byte of the ``n`` at input word ``at`` is ASCII."""
    e.var(name, 1)
    e.for_(f"{name}_k", 0, n, lambda: e.if_(e.le(128, e.rd(e.add(at, e.p[f"{name}_k"]))), lambda: e.set(name, 0)))


# -- ABI layouts ------------------------------------------------------------------------------------

def _pointer_bytes(e: E):
    """8, or 4 on the browser Wasm path (S15e.4, ADR-322: ``abi_layout(..., pointer_bytes=4)``)."""
    from xax_selfhost_general_wasm import W_ON

    return e.sel(e.ne(e.ld(W_ON), 0), 4, 8)


def _layout(tables, wasm: bool = False):
    """``abi_layout`` of TYPE object ``t`` (pointer bytes 8; with ``wasm``, 4 on the browser Wasm path, S15e.4): its size,
    the alignment memoised in ``G_LALIGN``; NONE on a rejection (a component without a layout, ``ABI-LAYOUT-VALUE-TYPE``) or a decline.  Components are laid out
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

            e.if_(e.eq(form, 1), bits, lambda: e.if_(e.eq(form, 2), lambda: done(*((_pointer_bytes(e),) * 2 if wasm else (8, 8))), lambda: e.if_(
                e.eq(form, 7), float_, lambda: e.if_(e.eq(form, 11), lambda: done(LINK_BYTES, LINK_BYTES), lambda: e.if_(
                    e.eq(form, 8), lambda: components(True), lambda: e.if_(e.eq(form, 9), array, lambda: e.if_(
                        e.eq(form, 10), lambda: components(False), reject)))))))

        e.while_(lambda: e.ne(p["ld"], 0), step)
        e.give(e.ld(e.add(sizes, p["t"])))
    return _function(("t",), build, tables)


# -- function interfaces, recursion groups included ------------------------------------------------------


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


_PROGRAM = NativeProgram(STORE_PATH, "x86-64-general-frontend")
load_general_program = _PROGRAM.load
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


def general_object_table(reader, entry_cid: bytes, target_object, audit: bool = False, linux: bool = False):
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
    words.append(int(audit) | (LINUX_REQUEST if linux else 0))  # S12c.1: write every value's range bound (tests); a Linux request
    # S12d: trap terminators' payload heads (the stream carries only their length and body offset): per graph with a
    # nonempty trap payload, its CID, the count, and per such block its index and the payload's first three bytes.
    traps = []
    for obj in graphs:
        blocks = [(index, block.terminator.payload) for index, block in enumerate(_parse_graph(obj, resolve).blocks)
                  if block.terminator.kind == TerminatorKind.TRAP and block.terminator.payload]
        if blocks:
            traps.append((obj, blocks))
    words.append(len(traps))
    for obj, blocks in traps:
        words += [*_cid_words(obj.cid), len(blocks)]
        for index, payload in blocks:
            head = bytes(payload[:3])
            words += [index, len(head), *head]
    return words, {obj.cid: obj for obj in extras}


def general_with_xax(reader, entry_cid: bytes, target_object, required: bool = False, audit: bool = False, linux: bool = True):
    """S12a-S12c.1: ``(closure, views, prefetches)`` as the XAX program decides them for a verified store: the entry's
    closure in image order and, per function CID, its lowering view (``xax_inline.inline_leaf_calls``, then the
    prefetch rewrite) rebuilt from the program's words, and its prefetch marks (absent where the host selects them).  It raises the ``XaxError`` the program wrote when it rejects.  None when the program cannot run or
    declines (the bootstrap then decides), unless ``required``.  ``linux``: a Linux executable is requested (the PE and
    raw-image hosts pass False: the target's own profile decides)."""
    import xax_native
    from xax_compiler import XaxError, fail, store_resolver
    from xax_selfhost_diagnostics import decode_diagnostic

    native = native_general()
    table = None if native is None else general_object_table(reader, entry_cid, target_object, audit, linux)
    words, members = table if table is not None else (None, {})

    def collect(read):
        order = collect_order(read)
        return order, (None if order is None else _view_words(read)), decode_diagnostic(read), (None if order is None else _image_words(read))

    outcome = None if words is None else native.run(words, collect)
    order, view_words, diagnostic, image_words = outcome if outcome is not None else (None, None, None, None)
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
    views, prefetches, code, audits = rebuild_views(view_words, closure, resolve, audit)
    result = GeneralResult((closure, views, prefetches, code, *audits) if audit else (closure, views, prefetches, code))
    result.image = _read_image(image_words, closure, code)
    return result


class GeneralResult(tuple):
    """``general_with_xax``'s tuple, with ``image``: the S12e image and container (``_read_image``), or None."""
    image = None


def _image_words(read):
    """The S12e record's words (``xax_selfhost_general_image``), up to the program's cursor."""
    from xax_selfhost_general_image import I_CURSOR, IMAGE_AT, IMAGE_END
    from xax_selfhost_general_regalloc import G_RA
    from xax_selfhost_views_backend import GLOBALS

    (table,) = read(GLOBALS + G_RA, 1)
    (end,) = read(table + I_CURSOR, 1)
    return read(IMAGE_AT, end - IMAGE_AT) if IMAGE_AT < end <= IMAGE_END else []


def _read_image(words, closure, code):
    """``(NativeImage fields, ELF bytes, code file offset, DT_NEEDED)`` from the S12e record, or None."""
    from xax_artifact import ArtifactSemanticRange

    if not words or words[0] != 1:
        return None
    position = 1

    def take(count=1):
        nonlocal position
        position += count
        return words[position - count:position]

    def packed():
        (length,) = take()
        return b"".join(word.to_bytes(8, "little") for word in take((length + 7) // 8))[:length]

    def text():
        (length,) = take()
        return bytes(take(length))

    image_code = packed()
    elf = packed()
    code_offset, entry_offset, members = take(3)
    offsets = take(members)
    imports = []
    for _ in range(take()[0]):
        (position_,) = take()
        imports.append((position_, text(), text()))
    needed = tuple(text() for _ in range(take()[0]))
    ranges = []
    for function, base in zip(closure, offsets):
        fragment = code[function.cid]
        ranges.append(ArtifactSemanticRange(function.cid, None, None, base, base + len(fragment[0])))
        ranges.extend(ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, base + item.start, base + item.end) for item in fragment[2])
    return {"code": image_code, "entry_offset": entry_offset, "function_offsets": tuple((f.cid, o) for f, o in zip(closure, offsets)),
            "semantic_ranges": tuple(ranges), "imports": tuple(imports), "elf": elf, "code_offset": code_offset, "needed": needed}


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


EMIT_UNDECIDED, EMIT_NONE, EMIT_DONE = range(3)
SYSV_ENTRY_LABEL = b"E"  # ``xax_x86_64._SYSV_ENTRY_LABEL``


def _read_emission(take, function):
    """A function's S12d emission record (``xax_selfhost_general_emit.write_emission``): None when not decided,
    ``"none"`` when the bootstrap's register-resident lowering returns None, else ``(code, calls, ranges)`` as
    ``compile_register_resident`` returns them."""
    from xax_artifact import ArtifactSemanticRange

    (status,) = take()
    if status == EMIT_UNDECIDED:
        return None
    if status == EMIT_NONE:
        return "none"
    (length,) = take()
    words = take((length + 7) // 8)
    data = b"".join(word.to_bytes(8, "little") for word in words)[:length]
    calls = []
    for _ in range(take()[0]):
        offset, prefixed, *cid = take(6)
        target = b"".join(word.to_bytes(8, "big") for word in cid)
        calls.append((offset, SYSV_ENTRY_LABEL + target if prefixed else target))
    ranges = tuple(ArtifactSemanticRange(function.cid, *take(4)) for _ in range(take()[0]))
    return data, tuple(calls), ranges


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

    views, prefetches, bounds, analyses, code = {}, {}, {}, {}, {}
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
        # The verifier's table is sorted by value reference (``_parse_graph``); the program lists it in position order.
        extents = tuple(sorted(((value(), take()[0]) for _ in range(take()[0])), key=lambda item: (item[0].tag, item[0].block, item[0].index, item[0].result)))
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
        # S12d (ADR-272): the register-resident code the program emitted.
        emitted = _read_emission(take, closure[fidx])
        if emitted is not None:
            code[closure[fidx].cid] = emitted
    return views, prefetches, code, (bounds, analyses) if audit else bounds


__all__ = ["RULES", "closure_with_xax", "general_with_xax", "rebuild_views", "load_general_program", "native_general"]


def x86_64_raw_image(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s image for a Windows load-image target (S15f.2, ADR-324): the XAX general program's code where it runs
    and decides (``"auto"``; ``"xax"`` requires it), else ``compile_native_bound_target``'s.  With
    ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_x86_64 import compile_native_bound_target

    def reference() -> bytes:
        return compile_native_bound_target(reader, function_cid, target_object).code

    if frontend == "python":
        return reference()
    result = general_with_xax(reader, function_cid, target_object, required=frontend == "xax", linux=False)
    image = None if result is None or result.image is None else result.image["elf"]
    if image is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15f.2: the bootstrap rejects ({error.diagnostic.rule}) an image the XAX program wrote") from error
        if image != expected:
            raise AssertionError("S15f.2 Windows load images disagree")
    return image
