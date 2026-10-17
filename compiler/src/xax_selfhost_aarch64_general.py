"""Self-hosting step S15e.2 (ADR-315): Linux AArch64 executables built by an XAX program.

``xax_linux_aarch64.compile_linux_aarch64_executable`` builds ``aarch64-linux-elf-exec-v1`` (and the dynamic-loader
profile) programs.  Before any code it decides, in this order:

1. the target: architecture 3, the Linux AArch64 ABI, an ELF executable format (``LINUX-AARCH64-ELF-EXEC-TARGET``);
2. the process entry (``validate_process_entry``, shared with x86-64: ``LINUX-ENTRY-FUNCTION``,
   ``LINUX-PROCESS-ENTRY-CONTRACT``);
3. the function closure (``xax_aarch64._function_closure``), depth first from the entry: per function (the Linux
   profiles are ``_general_aarch64_target``) every machine value's AAPCS64 layout and at most one machine result
   (``AARCH64-ABI-RETURNS``); per node in block order the target's operation list
   (``AARCH64-OP-TARGET-SUPPORTED``) and the visit of a called function that is not an erased proof function; per
   block the target's terminator list (``AARCH64-TERMINATOR-TARGET-SUPPORTED``);
4. the image's function order: the closure by CID.

Then each function is lowered (``xax_aarch64._compile_function``): on the Linux profiles first by the function-wide
register allocator (``xax_aarch64_regalloc.compile_linux_function``) over the lowering view
(``xax_inline.inline_leaf_calls``, the same view the x86-64 program builds, ``xax_selfhost_general_view``).

This module builds the program: the front end here, the view from ``xax_selfhost_general_view``, value ranges from
``xax_selfhost_general_ranges``, and the AArch64 lowering, image and ELF container from
``xax_selfhost_aarch64_lower``.  Its input is the general program's object table
(``xax_selfhost_x86_64_general.general_object_table``).  A function the register allocator returns None for is
lowered on the frame path (``xax_selfhost_aarch64_frame``, S15e.2b).  Where the bootstrap would take another path (the
legacy register path, a code address, an indirect call, an atomic operation) the program declines and the bootstrap
builds.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
import xax_selfhost_diagnostics as D
from xax_selfhost_views_backend import (
    _FN, ARENA_END, CID_WORDS, G_ERASED, G_IFACE, G_NI, G_O, G_ORDER, G_PAY, G_REC, G_REFS, G_S, G_SUP, G_SUP_AT,
    G_SUPT, G_SUPT_AT, G_TW, GLOBALS, NI_ENTITY, NI_OP, NativeProgram, _at, _borrowed, _call, _cid_at, _cid_less,
    _cid_words, _erased, _find, _g, _kind, _node_info, _ok, _payload_uleb, _reference, _target_list, _term_end, _type_form,
)
from xax_selfhost_x86_64_general import (
    COUNT_AT, ENTRY_CONTRACT_EXPECTED, FRAME, F_AT, F_BLOCKS, F_FN, F_GRAPH, F_NODES, GENERAL_ARENA_AT, G_ENTRY, G_FRAMES,
    G_GROUPOF, G_LALIGN, G_LSIZE, G_LSTACK, G_MEMBERS, G_MTAB, G_NARGS, G_TABI, G_TARGET, G_TFMT, ORDER_AT, OK, _group_interface,
    _proof, _text_at, group_member_tables,
)

STORE_PATH = bootstrap_dir() / "xax_aarch64_general.xax"
AARCH64 = 3
LINUX_AARCH64_ABI = 5
ELF_FORMATS = (6, 7)  # AARCH64_LINUX_ELF_EXEC_FORMAT, AARCH64_LINUX_ELF_DYNAMIC_FORMAT
DECLINE_OPERATIONS = (int(Operation.FUNCTION_ADDRESS),)  # code addresses: the bootstrap's bundle carries their fixups

# The bootstrap's rejections this program decides: (code, rule) by site.
RULES = (
    ("XAX.LINUX.TARGET", "LINUX-AARCH64-ELF-EXEC-TARGET"),
    ("XAX.LINUX.ENTRY", "LINUX-ENTRY-FUNCTION"),
    ("XAX.LINUX.ENTRY", "LINUX-PROCESS-ENTRY-CONTRACT"),
    ("XAX.AARCH64.ABI", "AARCH64-ABI-RETURNS"),
    ("XAX.AARCH64.UNSUPPORTED_OPERATION", "AARCH64-OP-TARGET-SUPPORTED"),
    ("XAX.AARCH64.UNSUPPORTED_TERMINATOR", "AARCH64-TERMINATOR-TARGET-SUPPORTED"),
    ("XAX.FOREIGN.ABI", "AARCH64-FOREIGN-ABI"),  # during code generation (``_require_foreign_abi``)
    ("XAX.AARCH64.FRAME", "AARCH64-FRAME-SIZE"),  # S15e.2b (ADR-316): the frame path's layout
)
SITE = {rule: site for site, (_code, rule) in enumerate(RULES)}


def _diagnostic(tables):
    """The record's code, entity CID (object ``entity``), and rule for ``site``."""
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
    """Unless ``condition``: reject under ``rule`` on object ``entity``."""
    def write():
        e.call(_FN["diagnostic"], SITE[rule], entity)
        expected()
        actual()
    D.reject_unless(e, condition, write)


def _prologue(tables):
    """``_function_closure``'s checks of function ``f`` before its graph, on a ``_general_aarch64_target``: every
    machine value's AAPCS64 layout (a value without one declines: the bootstrap's AARCH64-ABI-VALUE), then at most
    one machine result (``AARCH64-ABI-RETURNS``).  1, or NONE (rejected or declined)."""
    def build(e: E):
        p = e.p
        e.var("pi", _call(e, "interface", p["f"]))
        e.var("pnp", e.ld(e.add(p["pi"], 1)))
        e.var("prt", e.add(e.add(p["pi"], 2), p["pnp"]))
        e.var("pnr", e.ld(p["prt"]))
        e.var("pb", _call(e, "borrowed", p["f"]))

        def param(q):
            return e.ld(e.add(e.add(p["pi"], 2), q))

        def ret(q):
            return e.ld(e.add(e.add(p["prt"], 1), q))

        def scalar(t):
            _call(e, "abi_layout", t)  # S15e.2b (ADR-316): floats, products and sums are laid out too

        e.for_("q", 0, p["pnp"], lambda: e.if_(e.not_(_proof(e, param(p["q"]))), lambda: scalar(param(p["q"]))))
        e.var("pmr", 0)
        e.for_("q", 0, p["pnr"], lambda: e.if_(e.both(e.not_(_proof(e, ret(p["q"]))), e.eq(e.ld(e.add(p["pb"], p["q"])), NONE)), lambda: (
            scalar(ret(p["q"])), e.set("pmr", e.add(p["pmr"], 1)))))
        _reject(e, e.le(p["pmr"], 1), "AARCH64-ABI-RETURNS", p["f"], lambda: D.integer(e, 1), lambda: D.integer(e, p["pmr"]))
        e.give(1)
    return _function(("f",), build, tables)


def _node(tables):
    """``_function_closure``'s checks of the node just read (``G_NI``) in graph ``g`` of function ``f``: the target's
    operation list, and the visit of a called function.  In a group member's graph ``call.group_member`` is a direct
    call of member ``member`` of the same group (``parse_function_graph``, S15e.2b).  The function it visits, NONE-1
    when there is none, NONE when rejected or declined (a code address: the bootstrap decides)."""
    def build(e: E):
        p = e.p
        ni = _g(e, G_NI)
        e.var("nraw", e.ld(e.add(ni, NI_OP)))
        e.var("nop", e.sel(e.eq(p["nraw"], int(Operation.CALL_GROUP_MEMBER)), int(Operation.CALL_DIRECT), p["nraw"]))
        op = p["nop"]
        _ok(e, e.not_(e.either(*(e.eq(op, item) for item in DECLINE_OPERATIONS))))
        supported = e.both(e.lt(op, 256), e.ne(_at(e, G_SUP, e.sel(e.lt(op, 256), op, 0)), 0))
        _reject(e, supported, "AARCH64-OP-TARGET-SUPPORTED", p["g"], lambda: _target_list(e, G_SUP_AT), lambda: D.integer(e, op))
        e.var("nvisit", NONE - 1)

        def callee():
            e.var("nc", NONE)

            def direct():
                entity = e.ld(e.add(ni, NI_ENTITY))
                _ok(e, e.ne(entity, NONE))
                e.set("nc", _reference(e, p["g"], entity))

            def sibling():
                e.var("ngroup", e.ld(e.add(_g(e, G_GROUPOF), p["f"])))
                _ok(e, e.ne(p["ngroup"], NONE))
                e.var("nmembers", e.ld(e.add(_g(e, G_MTAB), p["ngroup"])))
                _ok(e, e.both(e.ne(p["nmembers"], NONE), e.lt(p["member"], e.ld(p["nmembers"]))))
                e.set("nc", e.ld(e.add(e.add(p["nmembers"], 1), p["member"])))

            e.if_(e.eq(p["nraw"], int(Operation.CALL_GROUP_MEMBER)), sibling, direct)
            _ok(e, e.both(e.ne(p["nc"], NONE), e.eq(_kind(e, p["nc"]), int(Kind.FUNCTION))))
            fresh = e.eq(e.ld(e.add(_g(e, G_TW), p["nc"])), 0)
            e.if_(e.both(fresh, e.eq(_call(e, "erased", p["nc"]), 0)), lambda: e.set("nvisit", p["nc"]))

        e.if_(e.eq(op, int(Operation.CALL_DIRECT)), callee)
        e.give(p["nvisit"])
    return _function(("g", "f", "member"), build, tables)


def _push(e: E, f):
    """Visit function ``f``: mark it, record it, run its prologue checks, and open a frame at its first block."""
    p = e.p
    e.var("vf", f)
    e.st(e.add(_g(e, G_TW), p["vf"]), 1)
    e.st(e.add(_g(e, G_ORDER), _g(e, G_MEMBERS)), p["vf"])
    e.st(GLOBALS + G_MEMBERS, e.add(_g(e, G_MEMBERS), 1))
    _call(e, "prologue", p["vf"])
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
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, ARENA_END)
        S = e.rd(0)
        e.st(GLOBALS + G_S, S)
        e.var("ra", 1 + CID_WORDS)

        def skip():
            references = e.rd(e.add(p["ra"], 1))
            payload_at = e.add(e.add(e.add(p["ra"], 2), e.mul(references, CID_WORDS)), CID_WORDS)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))

        e.for_("o", 0, e.add(S, 1), skip)
        # The store's objects, the bound target, then the group member functions the store does not hold (S15e.2b).
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
            e.if_(e.eq(o, S), lambda: e.set("ra", e.add(p["ra"], 1)))  # past the extras count

        e.set("ra", 1 + CID_WORDS)
        e.for_("o", 0, total, record)
        e.var("ext_at", p["ra"])
        from xax_selfhost_typing import IN_WORDS

        _ok(e, e.le(p["ra"], IN_WORDS))
        e.st(GLOBALS + G_O, S)
        e.var("target", e.call(_FN["find"], _cid_at(e, S)))
        e.if_(e.eq(p["target"], NONE), lambda: e.set("target", S))
        e.st(GLOBALS + G_TARGET, p["target"])
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

        # 1. The target (``decode_native_target``'s fields up to the terminator list).
        target = p["target"]
        _ok(e, e.eq(_kind(e, target), int(Kind.TARGET)))
        e.var("ta", _at(e, G_PAY, target))
        identity = _payload_uleb(e, "ta")
        e.set("ta", e.add(p["ta"], identity))
        fields = [_payload_uleb(e, "ta") for _ in range(6)]  # profile, architecture, abi, format, word, pointer bits
        e.var("t_arch", fields[1])
        e.var("t_abi", fields[2])
        e.var("t_fmt", fields[3])
        e.st(GLOBALS + G_TABI, p["t_abi"])
        e.st(GLOBALS + G_TFMT, p["t_fmt"])
        e.st(GLOBALS + G_NARGS, 0)
        _ok(e, e.eq(p["t_arch"], AARCH64))  # another architecture never reaches this program

        def target_expected():
            D.put(e, D.T_LIST)
            D.put(e, 3)
            D.integer(e, AARCH64)
            D.integer(e, LINUX_AARCH64_ABI)
            D.put(e, D.T_LIST)
            D.put(e, len(ELF_FORMATS))
            for value in ELF_FORMATS:
                D.integer(e, value)

        def target_actual():
            D.put(e, D.T_LIST)
            D.put(e, 3)
            D.integer(e, p["t_arch"])
            D.integer(e, p["t_abi"])
            D.integer(e, p["t_fmt"])

        linux = e.both(e.eq(p["t_abi"], LINUX_AARCH64_ABI), e.either(*(e.eq(p["t_fmt"], f) for f in ELF_FORMATS)))
        _reject(e, linux, "LINUX-AARCH64-ELF-EXEC-TARGET", target, target_expected, target_actual)
        _payload_uleb(e, "ta")  # stack alignment
        _payload_uleb(e, "ta")  # shadow space
        e.var("t_nargs", _payload_uleb(e, "ta"))
        e.st(GLOBALS + G_NARGS, p["t_nargs"])
        e.for_("q", 0, p["t_nargs"], lambda: _payload_uleb(e, "ta"))
        _payload_uleb(e, "ta")  # result register
        e.var("t_nscratch", _payload_uleb(e, "ta"))
        e.for_("q", 0, p["t_nscratch"], lambda: _payload_uleb(e, "ta"))
        for table, slot, limit in ((G_SUP, G_SUP_AT, 256), (G_SUPT, G_SUPT_AT, 8)):
            e.st(GLOBALS + slot, p["ta"])
            e.var("tcount", _payload_uleb(e, "ta"))
            e.for_("q", 0, p["tcount"], lambda table=table, limit=limit: (lambda value: (_ok(e, e.lt(value, limit)), e.st(e.add(_g(e, table), value), 1)))(
                _payload_uleb(e, "ta")))
        # The Linux profiles are ``_general_aarch64_target`` (floats, aggregates or sums); another target: the bootstrap.
        sup = _g(e, G_SUP)
        _ok(e, e.either(*(e.ne(e.ld(e.add(sup, int(op))), 0) for op in (Operation.FLOAT_ADD, Operation.AGGREGATE_MAKE, Operation.SUM_MAKE))))

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
            e.var("et", e.ld(e.add(e.add(p["ert"], 1), p["q"])))

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
                e.var("et", e.ld(e.add(e.add(p["ert"], 1), p["q"])))
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
                e.var("tkind", e.rd(p["tat"]))
                supported = e.both(e.lt(p["tkind"], 8), e.ne(_at(e, G_SUPT, e.sel(e.lt(p["tkind"], 8), p["tkind"], 0)), 0))
                _reject(e, supported, "AARCH64-TERMINATOR-TARGET-SUPPORTED", e.ld(e.add(fr, F_GRAPH)), lambda: _target_list(e, G_SUPT_AT),
                        lambda: D.tagged(e, D.T_TERMINATOR, p["tkind"]))
                e.set("tat", _call(e, "term_end", p["tat"]))
                e.st(e.add(fr, F_BLOCKS), e.sub(e.ld(e.add(fr, F_BLOCKS)), 1))

                def next_block():
                    e.var("tnodes", e.add(e.add(p["tat"], 1), e.rd(p["tat"])))
                    e.st(e.add(fr, F_NODES), e.rd(p["tnodes"]))
                    e.st(e.add(fr, F_AT), e.add(p["tnodes"], 1))

                e.if_(e.ne(e.ld(e.add(fr, F_BLOCKS)), 0), next_block, lambda: e.set("depth", e.sub(p["depth"], 1)))

            e.if_(e.ne(e.ld(e.add(fr, F_NODES)), 0), node, terminator)

        e.while_(lambda: e.ne(p["depth"], 0), step)

        # 4. The image order: the closure by CID.
        order = _g(e, G_ORDER)
        e.var("members", _g(e, G_MEMBERS))

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
        # Each closure function's lowering view and code, in image order (``xax_selfhost_aarch64_lower``).
        from xax_selfhost_aarch64_lower import lower_closure

        lower_closure(e, total, order, p["members"])
        e.give(1)
    return _function((), build, tables)


def build_aarch64_program():
    """``(reader, function)``: the AArch64 program's store and its entry."""
    from xax_selfhost_aarch64_lower import add_lower_functions

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
    from xax_selfhost_x86_64_general import _layout

    add("abi_layout", _layout(tables))
    add("prologue", _prologue(tables))
    add("node", _node(tables))
    add_lower_functions(add, tables)
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_aarch64_program, "aarch64-general")
load_aarch64_program = _PROGRAM.load
write_aarch64_store = _PROGRAM.write
OPT_OUT = "XAX_AARCH64_GENERAL_PYTHON"


def native_aarch64():
    """The native AArch64 program, or None where it cannot run."""
    return _PROGRAM.native(OPT_OUT)


def _read_record(read):
    """The image record's words (``xax_selfhost_aarch64_image``), up to the program's cursor."""
    from xax_selfhost_general_image import I_CURSOR, IMAGE_AT
    from xax_selfhost_general_regalloc import G_RA

    (table,) = read(GLOBALS + G_RA, 1)
    (end,) = read(table + I_CURSOR, 1)
    return read(IMAGE_AT, end - IMAGE_AT) if IMAGE_AT < end <= IMAGE_AT + (5 << 20) else []


def _executable(words, closure, reader, target_cid: bytes):
    """The ``LinuxAarch64Executable`` of the record, or None when it says "not decided"."""
    from xax_aarch64 import Aarch64Bundle
    from xax_artifact import ArtifactSemanticRange
    from xax_linux_aarch64 import LinuxAarch64Executable

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

    code = packed()
    elf = packed()
    code_offset, _entry, members = take(3)
    placed = []
    for function in closure[:members]:
        base, length, count = take(3)
        flat = take(4 * count)
        nodes = [ArtifactSemanticRange(function.cid, *flat[k:k + 2], base + flat[k + 2], base + flat[k + 3]) for k in range(0, len(flat), 4)]
        placed.append((function.cid, base, length, nodes))
    foreign = []
    for _ in range(take()[0]):
        (at,) = take()
        foreign.append((at, text(), text()))
    needed = tuple(text() for _ in range(take()[0]))
    placed.sort(key=lambda item: item[0])
    ranges = []
    for cid, base, length, nodes in placed:
        ranges.append(ArtifactSemanticRange(cid, None, None, base, base + length))
        ranges.extend(nodes)
    bundle = Aarch64Bundle(code, target_cid, tuple((cid, base) for cid, base, _length, _nodes in placed), tuple(foreign), tuple(ranges))
    file_ranges = tuple(ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, code_offset + item.start, code_offset + item.end)
                        for item in ranges)
    return LinuxAarch64Executable(elf, bundle, target_cid, file_ranges, needed)


def aarch64_with_xax(reader, entry_cid: bytes, target_object, required: bool = False):
    """The executable the XAX program builds for a verified store, or None when it cannot run or declines (the
    bootstrap then builds), unless ``required``.  It raises the ``XaxError`` the program wrote when it rejects."""
    import xax_native
    from xax_compiler import XaxError, fail, store_resolver
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_x86_64_general import collect_order, general_object_table

    native = native_aarch64()
    table = None if native is None else general_object_table(reader, entry_cid, target_object)
    words, members = table if table is not None else (None, {})

    def collect(read):
        order = collect_order(read)
        return order, decode_diagnostic(read), (None if order is None else _read_record(read))

    outcome = None if words is None else native.run(words, collect)
    order, diagnostic, record = outcome if outcome is not None else (None, None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    executable = None
    if order is not None:
        resolve = store_resolver(reader)
        closure = tuple(members[cid] if cid in members else resolve(cid) for cid in order)
        executable = _executable(record, closure, reader, target_object.cid)
    if executable is None:
        if native is not None:
            xax_native.declined("aarch64-general", 1)
        if required:
            fail("XAX.AARCH64.GENERAL", entry_cid.hex(), "AARCH64-XAX-GENERAL", "built by the XAX AArch64 program", "unavailable or declined")
    return executable
