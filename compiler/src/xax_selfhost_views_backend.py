"""The instruction-set-neutral half of the XAX views-profile backends (ADR-141, ADR-145, ADR-151, ADR-152).

The XAX RISC-V backend (``xax_selfhost_riscv64_backend``) and the XAX x86-64 backend
(``xax_selfhost_x86_64_backend``) are each one XAX program built from these builders and
their own instruction-set hooks:

* the front end (S5b): store objects and graph-decoder streams to the internal stream --
  the closure, interfaces, widths, constants, view and aggregate aliases, and order;
* the per-function analysis (S5a): block liveness over bitsets, interval hulls, and a
  linear scan over the ISA's allocatable registers, then the frame's slots;
* parallel edge copies through temporaries; and
* the program driver: setup, one function at a time, jump patching, outputs.

An ISA supplies ``ARCHITECTURE``, ``ALLOCATABLE``, ``ARGUMENT_REGISTERS``, ``T0``,
``CODE_LIMIT``, and the hooks ``declare``, ``on_call``, ``saved_end``, ``frame_size``,
``prologue``, ``trap``, ``jump``, ``skip_target_machine``, and ``patch``, plus the XAX
functions the shared code calls by name (``frame``, ``read``, ``write``, ``block``, ...).
"""

from __future__ import annotations

from xax_compiler import Operation, RESOURCE_EFFECT_OPERATIONS, TerminatorKind
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, HEADER, NONE, _function
from xax_selfhost_typing import IN_WORDS
import xax_selfhost_diagnostics as D

# Output regions (word indices of the output view).
# ADR-218: regions resized from measured use (the typing program: 3.5M code words, 19k jumps, 179k ranges) so the
# arena, which the largest function's liveness bitsets nearly filled, gains 3M words.
WORDS_AT, WORDS_LIMIT = 1 << 20, 5 << 20  # code: one word per RISC-V instruction or x86-64 byte
JUMPS_AT, JUMPS_LIMIT = 6 << 20, 1 << 19  # 3 words per jump
RANGES_AT, RANGES_LIMIT = (6 << 20) + (1 << 19), 2 << 20  # 5 words per range
META_AT = (8 << 20) + (1 << 19)  # entry machine parameter and return widths; the function order
STREAM_AT, STREAM_END = 9 << 20, 13 << 20  # the front end's internal stream (S5a format), read by the code generator
# S6c: the arena takes the rest; each function's scratch is reclaimed after it is lowered.
ARENA_AT, ARENA_END = 13 << 20, HEADER - 1
# Backend state in the header (after the argument words).
(S_COUNT, S_JUMPS, S_RANGES, S_FN, S_OFFSETS, S_REG, S_SLOT, S_WIDTH, S_TRAP, S_TRAP_USED, S_POW, S_FRAME, S_TEMPS,
 S_SAVED, S_BLOCK_LABELS, S_FALSE_LABELS, S_BASE, S_BLOCK_AT, S_LEVELS, S_AGG) = range(44, 64)
# ADR-151: the function's ``[outgoing argument bytes, hidden result pointer slot, result area table, area base]``.
A_OUT, A_POINTER, A_AREAS, A_BASE = range(4)
MAX_FIELDS = 255
OK = 1


# -- arithmetic (constant shifts become multiplies and unsigned divides) ------------------------

def _shl(e: E, value, amount: int):
    return e.mul(value, 1 << amount)


def _field(e: E, value, low: int, width: int):
    """Bits ``low .. low + width`` of ``value``."""
    return e.and_(e.udiv(value, 1 << low) if low else value, (1 << width) - 1)


def _ors(e: E, *parts):
    result = parts[0]
    for part in parts[1:]:
        result = e.or_(result, part)
    return result


def _xor(e: E, x, y):
    return e.bin(Operation.BIT_XOR, x, y)


def _signed_lt(e: E, x, y):
    """Signed ``x < y`` on two's-complement words."""
    bias = 1 << 63
    return e.lt(_xor(e, x, bias), _xor(e, y, bias))


def _sar(e: E, value, amount: int):
    """Arithmetic shift right by a constant."""
    logical = e.udiv(value, 1 << amount)
    fill = ((1 << 64) - 1) ^ ((1 << (64 - amount)) - 1)
    return e.or_(logical, e.sel(e.lt(value, 1 << 63), 0, fill))


# -- registry and value helpers --------------------------------------------------------------------

def _ok(e: E, condition):
    """Decline (NONE) unless ``condition``."""
    e.if_(e.not_(condition), lambda: e.give(NONE))


def _diagnostics(isa) -> str | None:
    """The ISA's diagnostic family (``XAX.<family>.*`` codes, ``<family>-*`` rules) when its program decides target
    legality and writes rejection diagnostics (S7b, ADR-179); None when it declines instead."""
    return getattr(isa, "DIAGNOSTICS", None)


# The views lowering's rejection rules (S7b): ``<family>-<rule>`` with code ``XAX.<family>.<code>``.
VIEWS_RULES = (
    ("OP-TARGET-SUPPORTED", "UNSUPPORTED_OPERATION"), ("TERMINATOR-TARGET-SUPPORTED", "UNSUPPORTED_TERMINATOR"), ("VALUE-BITS", "VALUE"),
    ("AGGREGATE-RESULT", "ABI"), ("AGGREGATE-VALUE", "UNSUPPORTED_OPERATION"), ("AGGREGATE-USE", "UNSUPPORTED_OPERATION"),
    ("SINGLE-RESULT", "ABI"), ("CHECKED-ACCESS", "UNSUPPORTED_OPERATION"), ("OP-LOWERED", "UNSUPPORTED_OPERATION"),
)
_RULE_SITES = {rule: site for site, (rule, _code) in enumerate(VIEWS_RULES)}


def _legal(e: E, isa, condition, rule: str, entity, expected, actual, deferred: bool = False):
    """A target-legality check.  With a diagnostic family the program rejects under ``rule`` (``VIEWS_RULES``) on
    ``entity`` (an object index) with the values ``expected()`` and ``actual()`` write; without one it declines,
    exactly as ``_ok``.  A ``deferred`` check records only the first failure and lets lowering go on: ``_program``
    rejects with it after the code is laid out, where the bootstrap makes that check (after its layout limits)."""
    if _diagnostics(isa) is None:
        _ok(e, condition)
        return

    def write():
        e.call(_FN["diagnostic"], _RULE_SITES[rule], entity)
        expected()
        actual()

    if not deferred:
        D.reject_unless(e, condition, write)
        return

    def record():
        D.begin(e)
        write()
        e.st(GLOBALS + G_PENDING, 1)

    e.if_(e.both(e.not_(condition), e.eq(_g(e, G_PENDING), 0)), record)


def _diagnostic(tables, isa):
    """The record's code, entity CID, and rule for rule ``site`` on object ``entity``: one copy of each text."""
    family = _diagnostics(isa)

    def build(e: E):
        p = e.p
        for part in ("code", "rule"):
            for site, (rule, code) in enumerate(VIEWS_RULES):
                value = f"XAX.{family}.{code}" if part == "code" else f"{family}-{rule}"
                e.if_(e.eq(p["site"], site), lambda value=value: D.text(e, value))
            if part == "code":
                D.cid(e, _cid_words(e, p["entity"]))
        e.give(1)
    return _function(("site", "entity"), build, tables)


_FN: dict = {}


def _call(e: E, name, *arguments):
    result = e.call(_FN[name], *arguments)
    _ok(e, e.ne(result, NONE))
    return result


def _value(e: E, field: int, value):
    return e.ld(e.add(e.hd(field), value))


def _target(e: E, value, t0: int):
    """The register a value is computed in: its allocation, or ``t0``."""
    register = _value(e, S_REG, value)
    return e.sel(e.ne(register, 0), register, t0)


def _bit(e: E, value):
    return e.ld(e.add(e.hd(S_POW), e.urem(value, 64)))


def _has(e: E, bitset, value):
    return e.ne(e.and_(e.ld(e.add(bitset, e.udiv(value, 64))), _bit(e, value)), 0)


def _put(e: E, bitset, value):
    word = e.add(bitset, e.udiv(value, 64))
    e.st(word, e.or_(e.ld(word), _bit(e, value)))


# -- one function ---------------------------------------------------------------------------------

def _compile_function(tables, isa):
    """Lower the function at stream ``cursor`` (index ``index``); the cursor after it, or NONE."""
    def build(e: E):
        p = e.p
        index = p["index"]
        e.set_hd(S_FN, index)
        B, entry, V = (e.ld(e.add(p["cursor"], k)) for k in range(3))
        _ok(e, e.both(e.ne(B, 0), e.lt(entry, B)))
        e.var("V", V)
        e.var("B", B)
        words = e.add(e.udiv(e.add(V, 63), 64), 1)
        e.var("W", words)

        def array(name, size, fill=0):
            e.var(name, e.alloc(size))
            _ok(e, e.ne(p[name], NONE))
            e.for_("fill_k", 0, size, lambda: e.st(e.add(p[name], p["fill_k"]), fill))
            return p[name]

        # The label slots outlive the function (the jumps are patched at the end); the rest of its arena is
        # reclaimed when it is lowered, so each function, not the whole program, must fit the arena.
        array("block_labels", e.add(B, 1), NONE)
        array("false_labels", e.add(B, 1), NONE)
        e.set_hd(S_BLOCK_LABELS, p["block_labels"])
        e.set_hd(S_FALSE_LABELS, p["false_labels"])
        array("trap", 1, NONE)
        e.set_hd(S_TRAP, p["trap"])
        e.var("mark", e.hd(H_ARENA))
        for name in ("width", "reg", "slot", "rank", "lo", "hi"):
            array(name, e.add(V, 1), NONE if name == "lo" else 0)
        e.set_hd(S_WIDTH, p["width"])
        e.set_hd(S_REG, p["reg"])
        e.set_hd(S_SLOT, p["slot"])
        array("area", e.add(V, 1), NONE)  # an aggregate call result's area, relative to the area base
        e.var("areas", 0)
        e.var("sret", 0)
        e.var("out", 0)
        isa.declare(e, p)
        for name in ("block_at", "base", "params", "order", "bstart", "bend", "nodes_at", "term_at"):
            array(name, e.add(B, 1))
        for name in ("uses", "defs", "lin", "lout", "pmask"):
            array(name, e.add(e.mul(B, words), 1))
        e.set_hd(S_TRAP_USED, 0)

        # Pass 1: block positions, value ids, widths, and the largest parameter count.
        e.var("at", e.add(p["cursor"], 3))
        e.var("next_id", 0)
        e.var("max_params", 0)

        def place():
            b = p["b"]
            e.st(e.add(p["block_at"], b), p["at"])
            e.st(e.add(p["base"], b), p["next_id"])
            count = e.ld(p["at"])
            e.st(e.add(p["params"], b), count)
            e.if_(e.lt(p["max_params"], count), lambda: e.set("max_params", count))
            e.for_("q", 0, count, lambda: (e.st(e.add(p["width"], e.add(p["next_id"], p["q"])), e.ld(e.add(e.add(p["at"], 1), p["q"]))),
                                           _put(e, e.add(p["pmask"], e.mul(b, p["W"])), e.add(p["next_id"], p["q"]))))
            e.set("next_id", e.add(p["next_id"], count))
            e.set("at", e.add(e.add(p["at"], 1), count))
            nodes = e.ld(p["at"])
            e.st(e.add(p["nodes_at"], b), e.add(p["at"], 1))
            e.set("at", e.add(p["at"], 1))

            def node():
                results = e.ld(e.add(p["at"], 1))
                e.for_("q", 0, results, lambda: e.st(e.add(p["width"], e.add(p["next_id"], p["q"])), e.ld(e.add(e.add(p["at"], 2), p["q"]))))
                operands_at = e.add(e.add(p["at"], 2), results)
                attributes_at = e.add(e.add(operands_at, 1), e.ld(operands_at))
                e.var("pl_attrs", attributes_at)
                hidden = e.both(e.eq(e.ld(p["at"]), int(Operation.CALL_DIRECT)), e.eq(e.ld(p["pl_attrs"]), 1))
                e.if_(hidden, lambda: (e.st(e.add(p["area"], p["next_id"]), p["areas"]),
                                       e.set("areas", e.add(p["areas"], e.mul(8, e.ld(e.add(p["pl_attrs"], 1)))))))
                e.set("next_id", e.add(p["next_id"], results))
                e.set("at", e.add(e.add(e.add(p["pl_attrs"], 1), e.ld(p["pl_attrs"])), 1))

            e.for_("m", 0, nodes, node)
            e.st(e.add(p["term_at"], b), p["at"])
            values = e.ld(e.add(p["at"], 1))
            e.var("pl_values", values)
            e.if_(e.eq(e.ld(p["at"]), int(TerminatorKind.RETURN)), lambda: e.for_("q", 0, p["pl_values"], lambda: e.if_(
                e.eq(e.ld(e.add(e.add(e.add(p["at"], 2), p["pl_values"]), p["q"])), 2), lambda: e.set("sret", 1))))
            e.set("at", e.add(e.add(p["at"], 2), e.mul(values, 2)))
            edges = e.ld(p["at"])
            e.set("at", e.add(p["at"], 1))
            e.for_("x", 0, edges, lambda: e.set("at", e.add(e.add(p["at"], 2), e.ld(e.add(p["at"], 1)))))

        e.for_("b", 0, B, place)
        _ok(e, e.eq(p["next_id"], V))
        e.set_hd(S_BLOCK_AT, p["block_at"])
        e.set_hd(S_BASE, p["base"])
        e.var("after", p["at"])

        # Linear-scan ranks: (tag, block, index, result) order -- parameters first, then node results.
        e.var("ordinal", 0)
        for parameters in (True, False):
            def ranks(parameters=parameters):
                b = p["b"]
                base, count = e.ld(e.add(p["base"], b)), e.ld(e.add(p["params"], b))
                end = e.sel(e.lt(e.add(b, 1), B), e.ld(e.add(p["base"], e.add(b, 1))), V)
                low, high = (base, e.add(base, count)) if parameters else (e.add(base, count), end)
                e.for_("q", low, high, lambda: (e.st(e.add(p["rank"], p["q"]), p["ordinal"]), e.set("ordinal", e.add(p["ordinal"], 1))))

            e.for_("b", 0, B, ranks)
        # Block order: the entry, then the others by index.
        e.st(p["order"], entry)
        e.var("o", 1)
        e.for_("b", 0, B, lambda: e.if_(e.ne(p["b"], entry), lambda: (e.st(e.add(p["order"], p["o"]), p["b"]), e.set("o", e.add(p["o"], 1)))))

        # Positions, uses, and definitions.
        def touch(value, position):
            lo, hi = e.add(p["lo"], value), e.add(p["hi"], value)
            e.if_(e.either(e.eq(e.ld(lo), NONE), e.lt(position, e.ld(lo))), lambda: e.st(lo, position))
            e.if_(e.lt(e.ld(hi), position), lambda: e.st(hi, position))

        def use(b, value, position):
            touch(value, position)
            defs = e.add(p["defs"], e.mul(b, p["W"]))
            e.if_(e.not_(_has(e, defs, value)), lambda: _put(e, e.add(p["uses"], e.mul(b, p["W"])), value))

        e.var("pos", 0)

        def walk():
            b = e.ld(e.add(p["order"], p["k"]))
            e.var("wb", b)
            e.st(e.add(p["bstart"], b), p["pos"])
            base = e.ld(e.add(p["base"], b))
            e.var("vid", base)
            defs = e.add(p["defs"], e.mul(b, p["W"]))
            e.for_("q", 0, e.ld(e.add(p["params"], b)), lambda: (_put(e, defs, p["vid"]), touch(p["vid"], p["pos"]), e.set("vid", e.add(p["vid"], 1))))
            e.var("na_at", e.ld(e.add(p["nodes_at"], b)))
            nodes = e.ld(e.sub(p["na_at"], 1))

            def node():
                e.set("pos", e.add(p["pos"], 1))
                at = p["na_at"]
                results = e.ld(e.add(at, 1))
                operands_at = e.add(e.add(at, 2), results)
                e.for_("q", 0, e.ld(operands_at), lambda: use(p["wb"], e.ld(e.add(e.add(operands_at, 1), p["q"])), p["pos"]))
                walk_attrs = e.add(e.add(operands_at, 1), e.ld(operands_at))
                e.var("wk_attrs", walk_attrs)

                def outgoing():
                    e.var("wk_n", e.flag(e.eq(e.ld(p["wk_attrs"]), 1)))
                    e.for_("q", 0, e.ld(operands_at), lambda: e.if_(e.ne(e.ld(e.add(p["width"], e.ld(e.add(e.add(operands_at, 1), p["q"])))), 0), lambda: e.set(
                        "wk_n", e.add(p["wk_n"], 1))))
                    e.if_(e.lt(e.add(p["out"], isa.ARGUMENT_REGISTERS * 8), e.mul(8, p["wk_n"])), lambda: e.set("out", e.sub(e.mul(8, p["wk_n"]), isa.ARGUMENT_REGISTERS * 8)))
                    isa.on_call(e, p)

                extra = e.ld(e.add(e.add(p["wk_attrs"], 1), e.ld(p["wk_attrs"])))
                e.if_(e.both(e.eq(e.ld(at), int(Operation.CALL_DIRECT)), e.ne(extra, NONE)), outgoing)
                e.for_("q", 0, results, lambda: (_put(e, defs, p["vid"]), touch(p["vid"], p["pos"]), e.set("vid", e.add(p["vid"], 1))))
                attributes_at = e.add(e.add(operands_at, 1), e.ld(operands_at))
                e.set("na_at", e.add(e.add(e.add(attributes_at, 1), e.ld(attributes_at)), 1))

            e.for_("m", 0, nodes, node)
            e.set("pos", e.add(p["pos"], 1))
            term = e.ld(e.add(p["term_at"], b))
            values = e.ld(e.add(term, 1))
            e.for_("q", 0, values, lambda: use(p["wb"], e.ld(e.add(e.add(term, 2), p["q"])), p["pos"]))
            e.var("edge_at", e.add(e.add(e.add(term, 2), e.mul(values, 2)), 1))

            def edge():
                at = p["edge_at"]
                arguments = e.ld(e.add(at, 1))
                e.for_("q", 0, arguments, lambda: use(p["wb"], e.ld(e.add(e.add(at, 2), p["q"])), p["pos"]))
                e.set("edge_at", e.add(e.add(at, 2), arguments))

            e.for_("x", 0, e.ld(e.sub(p["edge_at"], 1)), edge)
            e.st(e.add(p["bend"], b), p["pos"])
            e.set("pos", e.add(p["pos"], 1))

        e.for_("k", 0, B, walk)

        # Liveness to a fixpoint: out = U (live_in[t] - params[t]), in = uses | (out - defs).
        e.var("changed", 1)

        def iterate():
            e.set("changed", 0)

            def block():
                b = e.ld(e.add(p["order"], e.sub(e.sub(B, 1), p["k"])))
                e.var("lb", b)
                term = e.ld(e.add(p["term_at"], b))
                values = e.ld(e.add(term, 1))
                edges_at = e.add(e.add(term, 2), e.mul(values, 2))

                def word():
                    w = p["w"]
                    e.var("out_word", 0)
                    e.var("e_at", e.add(edges_at, 1))

                    def edge():
                        t = e.ld(p["e_at"])
                        live = e.ld(e.add(e.add(p["lin"], e.mul(t, p["W"])), w))
                        own = e.ld(e.add(e.add(p["pmask"], e.mul(t, p["W"])), w))
                        e.set("out_word", e.or_(p["out_word"], e.and_(live, _xor(e, own, (1 << 64) - 1))))
                        e.set("e_at", e.add(e.add(p["e_at"], 2), e.ld(e.add(p["e_at"], 1))))

                    e.for_("x", 0, e.ld(edges_at), edge)
                    offset = e.add(e.mul(p["lb"], p["W"]), w)
                    defs = e.ld(e.add(p["defs"], offset))
                    new_in = e.or_(e.ld(e.add(p["uses"], offset)), e.and_(p["out_word"], _xor(e, defs, (1 << 64) - 1)))
                    e.if_(e.either(e.ne(new_in, e.ld(e.add(p["lin"], offset))), e.ne(p["out_word"], e.ld(e.add(p["lout"], offset)))), lambda: (
                        e.st(e.add(p["lin"], offset), new_in), e.st(e.add(p["lout"], offset), p["out_word"]), e.set("changed", 1)))

                e.for_("w", 0, p["W"], word)

            e.for_("k", 0, B, block)

        e.while_(lambda: e.ne(p["changed"], 0), iterate)

        def boundaries():
            b = p["b"]

            def word():
                live_in = e.ld(e.add(e.add(p["lin"], e.mul(b, p["W"])), p["w"]))
                live_out = e.ld(e.add(e.add(p["lout"], e.mul(b, p["W"])), p["w"]))

                def bit():
                    value = e.add(e.mul(p["w"], 64), p["z"])
                    mask = e.ld(e.add(e.hd(S_POW), p["z"]))
                    e.if_(e.ne(e.and_(live_in, mask), 0), lambda: touch(value, e.ld(e.add(p["bstart"], b))))
                    e.if_(e.ne(e.and_(live_out, mask), 0), lambda: touch(value, e.ld(e.add(p["bend"], b))))

                e.if_(e.ne(e.or_(live_in, live_out), 0), lambda: e.for_("z", 0, 64, bit))

            e.for_("w", 0, p["W"], word)

        e.for_("b", 0, B, boundaries)

        # Linear scan over machine values sorted by (start, end, rank).
        sorted_ = array("sorted", e.add(V, 1))
        e.var("n", 0)

        def before(x, y):
            lo_x, lo_y = e.ld(e.add(p["lo"], x)), e.ld(e.add(p["lo"], y))
            hi_x, hi_y = e.ld(e.add(p["hi"], x)), e.ld(e.add(p["hi"], y))
            rank_x, rank_y = e.ld(e.add(p["rank"], x)), e.ld(e.add(p["rank"], y))
            return e.either(e.lt(lo_x, lo_y), e.both(e.eq(lo_x, lo_y), e.either(e.lt(hi_x, hi_y), e.both(e.eq(hi_x, hi_y), e.lt(rank_x, rank_y)))))

        def insert():
            value = p["v"]

            def add():
                e.var("j", p["n"])
                e.while_(lambda: e.both(e.ne(p["j"], 0), before(value, e.ld(e.add(sorted_, e.sub(p["j"], 1))))), lambda: (
                    e.st(e.add(sorted_, p["j"]), e.ld(e.add(sorted_, e.sub(p["j"], 1)))), e.set("j", e.sub(p["j"], 1))))
                e.st(e.add(sorted_, p["j"]), value)
                e.set("n", e.add(p["n"], 1))

            e.if_(e.ne(e.ld(e.add(p["width"], value)), 0), add)

        e.for_("v", 0, V, insert)
        active = array("active", 16)
        e.var("active_n", 0)
        e.var("free", sum(1 << r for r in isa.ALLOCATABLE))

        def scan():
            value = e.ld(e.add(sorted_, p["s"]))
            start, end = e.ld(e.add(p["lo"], value)), e.ld(e.add(p["hi"], value))
            # Expire intervals that ended before this one starts.
            e.var("keep", 0)

            def expire():
                item = e.ld(e.add(active, p["a"]))
                e.if_(e.lt(e.ld(e.add(p["hi"], item)), start), lambda: e.set("free", e.or_(p["free"], _bit(e, e.ld(e.add(p["reg"], item))))), lambda: (
                    e.st(e.add(active, p["keep"]), item), e.set("keep", e.add(p["keep"], 1))))

            e.for_("a", 0, p["active_n"], expire)
            e.set("active_n", p["keep"])

            def assign():
                e.var("pick", 0)
                for register in reversed(isa.ALLOCATABLE):
                    e.if_(e.ne(e.and_(p["free"], 1 << register), 0), lambda register=register: e.set("pick", register))
                e.st(e.add(p["reg"], value), p["pick"])
                e.set("free", e.and_(p["free"], _xor(e, _bit(e, p["pick"]), (1 << 64) - 1)))
                e.st(e.add(active, p["active_n"]), value)
                e.set("active_n", e.add(p["active_n"], 1))

            def spill():
                e.var("furthest", 0)

                def pick():
                    item, best = e.ld(e.add(active, p["a"])), e.ld(e.add(active, p["furthest"]))
                    hi_i, hi_b = e.ld(e.add(p["hi"], item)), e.ld(e.add(p["hi"], best))
                    later = e.either(e.lt(hi_b, hi_i), e.both(e.eq(hi_b, hi_i), e.lt(e.ld(e.add(p["rank"], best)), e.ld(e.add(p["rank"], item)))))
                    e.if_(later, lambda: e.set("furthest", p["a"]))

                e.for_("a", 1, p["active_n"], pick)
                victim = e.ld(e.add(active, p["furthest"]))

                def steal():
                    e.st(e.add(p["reg"], value), e.ld(e.add(p["reg"], victim)))
                    e.st(e.add(p["reg"], victim), 0)
                    e.st(e.add(active, p["furthest"]), value)

                e.if_(e.lt(end, e.ld(e.add(p["hi"], victim))), steal)

            e.if_(e.ne(p["free"], 0), assign, spill)

        e.for_("s", 0, p["n"], scan)

        # Frame: the ISA's base area, the saved registers in use (ascending), spill slots, edge temporaries.
        e.var("used", 0)
        e.for_("v", 0, V, lambda: e.if_(e.ne(e.ld(e.add(p["reg"], p["v"])), 0), lambda: e.set("used", e.or_(p["used"], _bit(e, e.ld(e.add(p["reg"], p["v"])))))))
        saved = array("saved_at", 32)
        e.set_hd(S_SAVED, saved)
        e.var("nsaved", 0)
        for register in isa.ALLOCATABLE:
            e.if_(e.ne(e.and_(p["used"], 1 << register), 0), lambda register=register: (
                e.st(e.add(saved, p["nsaved"]), register), e.set("nsaved", e.add(p["nsaved"], 1))))
        e.var("frame_cursor", isa.saved_end(e, p))
        e.for_("v", 0, V, lambda: e.if_(e.both(e.ne(e.ld(e.add(p["width"], p["v"])), 0), e.eq(e.ld(e.add(p["reg"], p["v"])), 0)), lambda: (
            e.st(e.add(p["slot"], p["v"]), p["frame_cursor"]), e.set("frame_cursor", e.add(p["frame_cursor"], 8)))))
        e.set_hd(S_TEMPS, p["frame_cursor"])
        # Then the hidden result pointer (a function returning an aggregate), then the result areas (ADR-151).
        e.var("pointer_slot", e.add(p["frame_cursor"], e.mul(8, p["max_params"])))
        e.var("area_base", e.add(p["pointer_slot"], e.mul(8, p["sret"])))
        frame = isa.frame_size(e, e.add(p["area_base"], p["areas"]))
        e.var("frame", frame)
        e.set_hd(S_FRAME, frame)
        record = array("agg", 4)
        for field, name in ((A_OUT, "out"), (A_POINTER, "pointer_slot"), (A_AREAS, "area"), (A_BASE, "area_base")):
            e.st(e.add(record, field), p[name])
        e.set_hd(S_AGG, record)
        entry_base = e.ld(e.add(p["base"], entry))

        isa.prologue(e, p, index, saved, entry_base, entry)

        # Blocks in order.
        e.for_("k", 0, B, lambda: _ok(e, e.ne(e.call(_FN["block"], e.ld(e.add(p["order"], p["k"])), e.ld(e.add(p["base"], e.ld(e.add(p["order"], p["k"])))), ), NONE)))

        e.if_(e.ne(e.hd(S_TRAP_USED), 0), lambda: isa.trap(e))
        e.set_hd(H_ARENA, p["mark"])
        e.give(p["after"])
    return _function(("cursor", "index"), build, tables)


def _location(e: E, value):
    register = _value(e, S_REG, value)
    return e.sel(e.ne(register, 0), register, e.add(1 << 32, _value(e, S_SLOT, value)))


def _copy_edge(tables, isa):
    """Edge arguments into the target's parameters (through the temporaries when a destination is also a source)."""
    def build(e: E):
        p = e.p
        at = p["edge"]  # [target, argument count, argument ids]
        target, count = e.ld(at), e.ld(e.add(at, 1))
        base = p["target_base"]
        moves = e.alloc(e.add(e.mul(count, 2), 1))
        _ok(e, e.ne(moves, NONE))
        e.var("moves_n", 0)

        def collect():
            destination, argument = e.add(base, p["q"]), e.ld(e.add(e.add(at, 2), p["q"]))
            needed = e.both(e.ne(_value(e, S_WIDTH, destination), 0), e.ne(_location(e, destination), _location(e, argument)))
            e.if_(needed, lambda: (e.st(e.add(moves, e.mul(p["moves_n"], 2)), destination), e.st(e.add(moves, e.add(e.mul(p["moves_n"], 2), 1)), argument),
                                   e.set("moves_n", e.add(p["moves_n"], 1))))

        e.for_("q", 0, count, collect)
        e.var("conflict", 0)

        def check():
            destination = _location(e, e.ld(e.add(moves, e.mul(p["q"], 2))))
            e.for_("r", 0, p["moves_n"], lambda: e.if_(e.eq(destination, _location(e, e.ld(e.add(moves, e.add(e.mul(p["r"], 2), 1))))), lambda: e.set("conflict", 1)))

        e.for_("q", 0, p["moves_n"], check)
        temporaries = e.hd(S_TEMPS)

        def through():
            e.for_("q", 0, p["moves_n"], lambda: _call(e, "frame", 1, _call(e, "read", e.ld(e.add(moves, e.add(e.mul(p["q"], 2), 1))), isa.T0),
                                                        e.add(temporaries, e.mul(8, p["q"]))))

            def back():
                destination = e.ld(e.add(moves, e.mul(p["q"], 2)))
                register = _target(e, destination, isa.T0)
                _call(e, "frame", 0, register, e.add(temporaries, e.mul(8, p["q"])))
                _call(e, "write", destination, register)

            e.for_("q", 0, p["moves_n"], back)

        def direct():
            e.for_("q", 0, p["moves_n"], lambda: _call(e, "write", e.ld(e.add(moves, e.mul(p["q"], 2))), _call(e, "read", e.ld(e.add(moves, e.add(e.mul(p["q"], 2), 1))), isa.T0)))

        e.if_(e.ne(p["conflict"], 0), through, direct)
        isa.jump(e, e.add(e.hd(S_BLOCK_LABELS), target))
        e.give(1)
    return _function(("edge", "target_base"), build, tables)


# -- S5b: the front end (store objects and graph-decoder streams to the internal stream) -------------
#
# Input view: ``O, entry object, target object``, then per object ``[kind, reference count, reference object
# indices (NONE: not listed), CID as four big-endian words, payload length, payload]``.  The payload is the body,
# one byte per word, for types, constants, functions, and targets; a graph fragment's is the S3c graph-decoder
# stream (``xax_selfhost_graph``); other kinds have none.

GLOBALS = ARENA_AT  # the front end's table pointers (the first arena words)
(G_REC, G_PAY, G_TW, G_FIDX, G_ERASED, G_IFACE, G_SUP, G_SUPT, G_NI, G_O, G_ORDER, G_F, G_OUT, G_WIDTHS, G_FAR, G_SUP_AT, G_SUPT_AT, G_S,
 G_REFS, G_PENDING) = range(20)
CID_WORDS = 4
NI_OP, NI_ENTITY, NI_OPERANDS, NI_RESULTS, NI_ATTRIBUTES = range(5)
ENTITY_CODES = (5, 6, 30, 41, 42, 43)
ATTRIBUTE_CODES = (7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 52, 53, 55, 56, 57,
                   61, 63, 64, 65, 66, 73, 74, 75, 76)


def _g(e: E, slot: int):
    return e.ld(GLOBALS + slot)


def _at(e: E, table: int, index):
    return e.ld(e.add(_g(e, table), index))


def _reference(e: E, obj, k):
    """Object index of ``obj``'s ``k``-th reference (NONE when that object is not listed), resolved by ``_find``."""
    return e.ld(e.add(_at(e, G_REFS, obj), k))


def _cid_at(e: E, obj):
    """The input position of object ``obj``'s own CID words (after its kind, reference count, and reference CIDs)."""
    record = _at(e, G_REC, obj)
    return e.add(e.add(record, 2), e.mul(e.rd(e.add(record, 1)), CID_WORDS))


def _cid_less(e: E, x_at, y_at):
    """The CID at input position ``x_at`` sorts before the one at ``y_at`` (four big-endian words)."""
    result, equal = e.c(0), e.c(1)
    for k in range(CID_WORDS):
        wx, wy = e.rd(e.add(x_at, k)), e.rd(e.add(y_at, k))
        result = e.or_(result, e.flag(e.both(e.ne(equal, 0), e.lt(wx, wy))))
        equal = e.flag(e.both(e.ne(equal, 0), e.eq(wx, wy)))
    return e.ne(result, 0)


def _cid_equal(e: E, x_at, y_at):
    return e.both(*(e.eq(e.rd(e.add(x_at, k)), e.rd(e.add(y_at, k))) for k in range(CID_WORDS)))


def _find(tables):
    """S7b.2: the object index whose CID is the one at input position ``at``, or NONE.  Store objects are in CID
    order (a verified store), so they are searched by bisection; the bound target follows them when the store does
    not hold it."""
    def build(e: E):
        p = e.p
        e.var("lo", 0)
        e.var("hi", _g(e, G_S))

        def halve():
            e.var("mid", e.udiv(e.add(p["lo"], p["hi"]), 2))
            e.if_(_cid_less(e, _cid_at(e, p["mid"]), p["at"]), lambda: e.set("lo", e.add(p["mid"], 1)), lambda: e.set("hi", p["mid"]))

        e.while_(lambda: e.lt(p["lo"], p["hi"]), halve)
        e.if_(e.lt(p["lo"], _g(e, G_S)), lambda: e.if_(_cid_equal(e, _cid_at(e, p["lo"]), p["at"]), lambda: e.give(p["lo"])))
        appended = e.both(e.lt(_g(e, G_S), _g(e, G_O)), _cid_equal(e, _cid_at(e, _g(e, G_S)), p["at"]))
        e.give(e.sel(appended, _g(e, G_S), NONE))
    return _function(("at",), build, tables)


def _kind(e: E, obj):
    return e.rd(_at(e, G_REC, obj))


def _cid_words(e: E, obj):
    """The four big-endian CID words of object ``obj``."""
    at = _cid_at(e, obj)
    return [e.rd(e.add(at, k)) for k in range(CID_WORDS)]


def _in_set(e: E, value, codes):
    return e.either(*(e.eq(value, code) for code in codes))


def _payload_uleb(e: E, name: str):
    """Read a ULEB at input word ``p[name]`` (one byte per word) and advance it."""
    from xax_selfhost_facts import _uleb

    p = e.p
    value, size, ok = _uleb(e, p[name])
    _ok(e, ok)
    e.set(name, e.add(p[name], size))
    return value


def _node_info(tables):
    """Graph-decoder node record at ``at``: fields into the NI scratch words; returns the next record."""
    def build(e: E):
        p = e.p
        ni = _g(e, G_NI)
        e.var("at", p["at"])
        operation = e.rd(p["at"])
        e.st(e.add(ni, NI_OP), operation)
        e.set("at", e.add(p["at"], 1))
        e.if_(e.eq(operation, int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("at", e.add(p["at"], 3)))
        e.st(e.add(ni, NI_ENTITY), NONE)
        e.if_(_in_set(e, operation, ENTITY_CODES), lambda: (e.st(e.add(ni, NI_ENTITY), e.rd(p["at"])), e.set("at", e.add(p["at"], 1))))
        e.st(e.add(ni, NI_OPERANDS), p["at"])
        count = e.rd(p["at"])
        e.set("at", e.add(p["at"], 1))
        e.for_("q", 0, count, lambda: e.set("at", e.add(e.add(p["at"], 3), e.flag(e.eq(e.rd(p["at"]), 1)))))
        e.st(e.add(ni, NI_RESULTS), p["at"])
        e.set("at", e.add(e.add(p["at"], 1), e.rd(p["at"])))
        e.st(e.add(ni, NI_ATTRIBUTES), NONE)
        e.if_(_in_set(e, operation, ATTRIBUTE_CODES), lambda: (e.st(e.add(ni, NI_ATTRIBUTES), p["at"]), e.set("at", e.add(e.add(p["at"], 1), e.rd(p["at"])))))
        e.give(p["at"])
    return _function(("at",), build, tables)


def _skip_values(e: E, name: str):
    """Advance ``p[name]`` past ``[count, values]``."""
    p = e.p
    count = e.rd(p[name])
    e.set(name, e.add(p[name], 1))
    e.for_("sv", 0, count, lambda: e.set(name, e.add(e.add(p[name], 3), e.flag(e.eq(e.rd(p[name]), 1)))))


def _term_end(tables):
    """The position after the terminator at ``at``."""
    def build(e: E):
        p = e.p
        kind = e.rd(p["at"])
        e.var("at", e.add(p["at"], 1))

        def edge():
            e.set("at", e.add(p["at"], 1))
            _skip_values(e, "at")

        def conditional():
            e.set("at", e.add(e.add(p["at"], 3), e.flag(e.eq(e.rd(p["at"]), 1))))
            edge()
            edge()

        e.if_(e.eq(kind, 1), edge, lambda: e.if_(e.eq(kind, 2), conditional, lambda: e.if_(
            e.eq(kind, 3), lambda: _skip_values(e, "at"), lambda: e.set("at", e.add(p["at"], 2)))))
        e.give(p["at"])
    return _function(("at",), build, tables)


def _type_width(e: E, obj):
    """``_machine_width``: bits width <= 64, 0 for a proof value (effect or resource), else NONE."""
    from xax_compiler import Kind

    p = e.p
    e.var("tw", NONE)

    def typed():
        pay = _at(e, G_PAY, obj)
        first = e.rd(pay)
        e.if_(e.either(e.eq(first, 3), e.eq(first, 4)), lambda: e.set("tw", 0))
        e.if_(e.eq(first, 2), lambda: e.set("tw", 64))  # views profile: a pointer is one 64-bit address

        def bits():
            e.var("tw_at", e.add(pay, 1))
            width = _payload_uleb(e, "tw_at")
            e.if_(e.both(e.ne(width, 0), e.le(width, 64)), lambda: e.set("tw", width))

        e.if_(e.eq(first, 1), bits)

    known = e.lt(obj, _g(e, G_O))
    listed = e.sel(known, obj, 0)
    nonempty = e.ne(e.rd(e.sub(_at(e, G_PAY, listed), 1)), 0)
    e.if_(e.both(known, e.eq(_kind(e, listed), int(Kind.TYPE)), nonempty), typed)
    return p["tw"]


def _interface(tables):
    """``_decode_function_interface`` of a verified function: ``[graph, P, types, R, types]`` (cached); NONE for a
    group member or an unlisted graph."""
    from xax_compiler import Kind

    def build(e: E):
        p = e.p
        f = p["f"]
        cached = _at(e, G_IFACE, f)
        e.if_(e.ne(cached, NONE), lambda: e.give(cached))
        _ok(e, e.eq(_kind(e, f), int(Kind.FUNCTION)))
        e.var("ia", _at(e, G_PAY, f))
        graph = _reference(e, f, _payload_uleb(e, "ia"))
        e.var("graph", graph)
        _ok(e, e.both(e.ne(p["graph"], NONE), e.eq(_kind(e, p["graph"]), int(Kind.GRAPH_FRAGMENT))))
        params = _payload_uleb(e, "ia")
        e.var("np", params)
        e.var("record", e.alloc(e.add(p["np"], 2)))
        _ok(e, e.ne(p["record"], NONE))
        e.st(p["record"], p["graph"])
        e.st(e.add(p["record"], 1), p["np"])
        e.for_("q", 0, p["np"], lambda: e.st(e.add(e.add(p["record"], 2), p["q"]), _reference(e, f, _payload_uleb(e, "ia"))))
        returns = _payload_uleb(e, "ia")
        e.var("nr", returns)
        e.var("rec2", e.alloc(e.add(p["nr"], 1)))
        _ok(e, e.both(e.ne(p["rec2"], NONE), e.eq(p["rec2"], e.add(e.add(p["record"], 2), p["np"]))))  # contiguous
        e.st(p["rec2"], p["nr"])
        e.for_("q", 0, p["nr"], lambda: e.st(e.add(e.add(p["rec2"], 1), p["q"]), _reference(e, f, _payload_uleb(e, "ia"))))
        e.st(e.add(_g(e, G_IFACE), f), p["record"])
        e.give(p["record"])
    return _function(("f",), build, tables)


def _erased(tables):
    """``_is_erased_proof_function``: proof-only interface and one block of resource/effect nodes returning."""
    def build(e: E):
        p = e.p
        f = p["f"]
        cached = _at(e, G_ERASED, f)
        e.if_(e.ne(cached, NONE), lambda: e.give(cached))
        iface = _call(e, "interface", f)
        e.var("erased", 1)
        params = e.ld(e.add(iface, 1))
        returns_at = e.add(e.add(iface, 2), params)
        e.for_("q", 0, params, lambda: e.if_(e.ne(_type_width(e, e.ld(e.add(e.add(iface, 2), p["q"]))), 0), lambda: e.set("erased", 0)))
        e.for_("q", 0, e.ld(returns_at), lambda: e.if_(e.ne(_type_width(e, e.ld(e.add(e.add(returns_at, 1), p["q"]))), 0), lambda: e.set("erased", 0)))

        def shape():
            stream = _at(e, G_PAY, e.ld(iface))
            e.if_(e.ne(e.rd(stream), 1), lambda: e.set("erased", 0))

            def one_block():
                e.var("ea", e.add(e.add(stream, 3), e.rd(e.add(stream, 2))))
                nodes = e.rd(p["ea"])
                e.set("ea", e.add(p["ea"], 1))

                def node():
                    e.set("ea", _call(e, "node_info", p["ea"]))
                    e.if_(e.not_(_in_set(e, e.ld(e.add(_g(e, G_NI), NI_OP)), tuple(int(op) for op in RESOURCE_EFFECT_OPERATIONS))), lambda: e.set("erased", 0))

                e.for_("m", 0, nodes, node)
                e.if_(e.ne(e.rd(p["ea"]), int(TerminatorKind.RETURN)), lambda: e.set("erased", 0))

            e.if_(e.ne(p["erased"], 0), one_block)

        e.if_(e.ne(p["erased"], 0), shape)
        e.st(e.add(_g(e, G_ERASED), f), p["erased"])
        e.give(p["erased"])
    return _function(("f",), build, tables)


def _type_form(e: E, obj):
    """The first payload byte of listed, nonempty TYPE ``obj`` (NONE otherwise)."""
    from xax_compiler import Kind

    known = e.lt(obj, _g(e, G_O))
    listed = e.sel(known, obj, 0)
    pay = _at(e, G_PAY, listed)
    typed = e.both(known, e.eq(_kind(e, listed), int(Kind.TYPE)), e.ne(e.rd(e.sub(pay, 1)), 0))
    return e.sel(typed, e.rd(e.sel(typed, pay, 0)), NONE)


def _view_extent(e: E, obj):
    """``_heap_view_info``: the instance (extent) of heap-view type ``obj``; 0 when it is not a heap view."""
    p = e.p
    e.var("vx", 0)

    def resource():
        pay = _at(e, G_PAY, obj)
        e.var("vx_at", e.add(pay, 1))
        e.var("vx_end", e.add(pay, e.rd(e.sub(pay, 1))))
        kind = _payload_uleb(e, "vx_at")
        e.var("vx_kind", kind)
        state = _payload_uleb(e, "vx_at")
        e.var("vx_state", state)

        def described():
            _payload_uleb(e, "vx_at")  # flags
            instance = _payload_uleb(e, "vx_at")
            e.if_(e.both(e.eq(p["vx_kind"], 0x101), e.either(e.eq(p["vx_state"], 1), e.eq(p["vx_state"], 2))), lambda: e.set("vx", instance))

        e.if_(e.lt(p["vx_at"], p["vx_end"]), described)

    e.if_(e.eq(_type_form(e, obj), 4), resource)
    return p["vx"]


def _borrowed(tables):
    """``borrowed_view_returns`` of function ``f``: ``R`` words, return position -> parameter position (NONE when the
    return stays a machine value)."""
    def build(e: E):
        p = e.p
        iface = _call(e, "interface", p["f"])
        e.var("bi", iface)
        e.var("bnp", e.ld(e.add(p["bi"], 1)))
        e.var("brt", e.add(e.add(p["bi"], 2), p["bnp"]))
        e.var("bnr", e.ld(p["brt"]))
        e.var("bout", e.alloc(e.add(e.add(p["bnr"], p["bnp"]), 1)))
        _ok(e, e.ne(p["bout"], NONE))
        e.var("bused", e.add(p["bout"], p["bnr"]))
        e.for_("q", 0, p["bnr"], lambda: e.st(e.add(p["bout"], p["q"]), NONE))
        e.for_("q", 0, p["bnp"], lambda: e.st(e.add(p["bused"], p["q"]), 0))
        e.var("bmachine", 0)
        e.for_("q", 0, p["bnr"], lambda: e.if_(e.ne(_type_width(e, e.ld(e.add(e.add(p["brt"], 1), p["q"]))), 0),
                                              lambda: e.set("bmachine", e.add(p["bmachine"], 1))))
        e.var("bfound", 0)
        e.var("btype", 0)

        def pair():
            def returned():
                e.set("btype", e.ld(e.add(e.add(p["brt"], 1), p["r"])))

                def view():
                    e.set("bfound", 0)

                    def match():
                        e.st(e.add(p["bused"], p["j"]), 1)
                        e.st(e.add(p["bout"], e.sub(p["r"], 1)), e.sub(p["j"], 1))
                        e.set("bfound", 1)

                    e.for_("j", 1, p["bnp"], lambda: e.if_(e.both(e.eq(p["bfound"], 0), e.eq(e.ld(e.add(p["bused"], p["j"])), 0),
                                                                  e.eq(e.ld(e.add(e.add(p["bi"], 2), p["j"])), p["btype"])), match))

                e.if_(e.ne(_view_extent(e, p["btype"]), 0), view)

            e.for_("r", 1, p["bnr"], returned)

        e.if_(e.lt(1, p["bmachine"]), pair)
        e.give(p["bout"])
    return _function(("f",), build, tables)


def _aggregate(tables):
    """``_aggregate_fields`` (ADR-151): the field count of TYPE ``t``, a tuple or array of ``bits<N <= 64>``; 0 otherwise."""
    def build(e: E):
        p = e.p
        obj = p["t"]
        form = _type_form(e, obj)
        e.var("ag_form", form)
        e.var("ag_count", 0)
        e.var("ag_ok", 1)

        def scalar(field):
            known = e.ne(field, NONE)
            width = _type_width(e, e.sel(known, field, 0))
            return e.both(known, e.eq(_type_form(e, e.sel(known, field, 0)), 1), e.ne(width, 0), e.le(width, 64))

        def tuple_():
            e.var("ag_at", e.add(_at(e, G_PAY, obj), 1))
            e.set("ag_count", _payload_uleb(e, "ag_at"))
            e.for_("q", 0, p["ag_count"], lambda: e.if_(e.not_(scalar(_reference(e, obj, _payload_uleb(e, "ag_at")))), lambda: e.set("ag_ok", 0)))

        def array_():
            e.var("ag_at", e.add(_at(e, G_PAY, obj), 1))
            element = _reference(e, obj, _payload_uleb(e, "ag_at"))
            e.var("ag_element", element)
            e.set("ag_count", _payload_uleb(e, "ag_at"))
            e.if_(e.not_(scalar(p["ag_element"])), lambda: e.set("ag_ok", 0))

        e.if_(e.eq(p["ag_form"], 8), tuple_, lambda: e.if_(e.eq(p["ag_form"], 9), array_))
        e.give(e.sel(e.both(e.ne(p["ag_ok"], 0), e.ne(p["ag_count"], 0), e.le(p["ag_count"], MAX_FIELDS)), p["ag_count"], 0))
    return _function(("t",), build, tables)


def _result_fields(tables, isa=None):
    """``_result_fields``: the field count when function ``f`` returns an aggregate (its only non-proof result), 0 when
    it returns none; rejects (or, without diagnostics, declines) on any other mix."""
    def build(e: E):
        p = e.p
        iface = _call(e, "interface", p["f"])
        e.var("rf_at", e.add(e.add(iface, 2), e.ld(e.add(iface, 1))))
        e.var("rf", 0)
        e.var("rf_n", 0)
        e.var("rf_machine", 0)

        def each():
            returned = e.ld(e.add(e.add(p["rf_at"], 1), p["q"]))
            e.var("rf_t", returned)
            e.var("rf_k", _call(e, "aggregate", p["rf_t"]))
            e.if_(e.ne(p["rf_k"], 0), lambda: (e.set("rf", p["rf_k"]), e.set("rf_n", e.add(p["rf_n"], 1))),
                  lambda: e.if_(e.ne(_type_width(e, p["rf_t"]), 0), lambda: e.set("rf_machine", 1)))

        e.for_("q", 0, e.ld(p["rf_at"]), each)
        _legal(e, isa, e.either(e.eq(p["rf_n"], 0), e.both(e.eq(p["rf_n"], 1), e.eq(p["rf_machine"], 0))), "AGGREGATE-RESULT", p["f"],
               lambda: D.text(e, "one aggregate and proof values only"), lambda: D.integer(e, e.ld(p["rf_at"])))
        e.give(p["rf"])
    return _function(("f",), build, tables)


VALUE_BITS = "bits<N <= 64> or a proof value"


def _target_list(e: E, slot: int):
    """The target's operation (or terminator) list, in its payload order, as a diagnostic LIST of INTs."""
    p = e.p
    e.var("dg_at", _g(e, slot))
    e.var("dg_n", _payload_uleb(e, "dg_at"))
    D.put(e, D.T_LIST)
    D.put(e, p["dg_n"])
    e.for_("dg_q", 0, p["dg_n"], lambda: D.integer(e, _payload_uleb(e, "dg_at")))


def _emit_out(e: E, value):
    at = _g(e, G_OUT)
    e.if_(e.lt(at, STREAM_END), lambda: e.st(at, value))  # past the end: nothing is written, and the front end declines
    e.st(GLOBALS + G_OUT, e.add(at, 1))


def _legality(e: E, isa, f, stream, raw_value_id, value_id):
    """S7b (ADR-179): every target-legality check the bootstrap generator makes for function ``f`` once its closure
    is accepted, in the bootstrap's order (``xax_views_lowering.result_fields`` and ``Aggregates``, ``machine_width``
    over the values, then the lowering's checks in block order), so the first rejection is the bootstrap's.

    Reads ``_translate``'s analysis: value bases (``base``, ``first``, ``node_base``), view extents (``ext``),
    aliases (``alias``), ``aggregate.make`` operand lists (``made``), and aggregate values (``aggv``)."""
    p = e.p
    where = p["graph"]

    def made_aggregate(value):
        return e.both(e.ne(e.ld(e.add(p["made"], value)), NONE), e.ne(e.ld(e.add(p["aggv"], value)), 0))

    def type_at(position):
        return _reference(e, p["graph"], e.rd(position))

    # Block positions in the decoder stream.
    e.var("lg_pos", e.alloc(e.add(p["B"], 1)))
    _ok(e, e.ne(p["lg_pos"], NONE))
    e.var("lg_at", e.add(stream, 2))

    def locate():
        e.st(e.add(p["lg_pos"], p["lg_b"]), p["lg_at"])
        e.set("lg_at", e.add(e.add(p["lg_at"], 1), e.rd(p["lg_at"])))
        e.var("lg_nc", e.rd(p["lg_at"]))
        e.set("lg_at", e.add(p["lg_at"], 1))
        e.for_("lg_m", 0, p["lg_nc"], lambda: e.set("lg_at", _call(e, "node_info", p["lg_at"])))
        e.set("lg_at", _call(e, "term_end", p["lg_at"]))

    e.for_("lg_b", 0, p["B"], locate)

    def visit(block, on_parameter=None, on_node=None, on_terminator=None):
        """Walk block ``block``: ``on_parameter(type position, value id)``, ``on_node()`` with the node's fields in
        ``lg_op``, ``lg_entity``, ``lg_ops``, ``lg_results``, ``lg_attrs``, ``lg_id``, and ``on_terminator(position)``."""
        e.var("lg_at", e.ld(e.add(p["lg_pos"], block)))
        e.var("lg_pc", e.rd(p["lg_at"]))
        if on_parameter is not None:
            e.for_("lg_q", 0, p["lg_pc"], lambda: on_parameter(e.add(e.add(p["lg_at"], 1), p["lg_q"]), e.add(e.ld(e.add(p["base"], block)), p["lg_q"])))
        e.set("lg_at", e.add(e.add(p["lg_at"], 1), p["lg_pc"]))
        e.var("lg_nc", e.rd(p["lg_at"]))
        e.set("lg_at", e.add(p["lg_at"], 1))
        e.var("lg_node", e.ld(e.add(p["first"], block)))

        def node():
            e.var("lg_next", _call(e, "node_info", p["lg_at"]))
            ni = _g(e, G_NI)  # read every field first: helpers below reuse the scratch words
            for name, field in (("lg_op", NI_OP), ("lg_entity", NI_ENTITY), ("lg_ops", NI_OPERANDS), ("lg_results", NI_RESULTS), ("lg_attrs", NI_ATTRIBUTES)):
                e.var(name, e.ld(e.add(ni, field)))
            e.var("lg_id", e.ld(e.add(p["node_base"], p["lg_node"])))
            if on_node is not None:
                on_node()
            e.set("lg_at", p["lg_next"])
            e.set("lg_node", e.add(p["lg_node"], 1))

        e.for_("lg_k", 0, p["lg_nc"], node)
        if on_terminator is not None:
            on_terminator(p["lg_at"])

    def each_block(body):
        e.for_("lg_block", 0, p["B"], lambda: body(p["lg_block"]))

    def operands_each(body):
        """``body(raw value id)`` for every operand of the current node."""
        e.var("lg_oa", e.add(p["lg_ops"], 1))
        e.for_("lg_o", 0, e.rd(p["lg_ops"]), lambda: body(raw_value_id("lg_oa")))

    def callee():
        return _reference(e, p["graph"], p["lg_entity"])

    def kept_call():
        """The current node is a direct call whose callee is not an erased proof function."""
        e.var("lg_kept", 0)
        e.if_(e.eq(p["lg_op"], int(Operation.CALL_DIRECT)), lambda: e.set("lg_kept", e.flag(e.eq(_call(e, "erased", callee()), 0))))
        return e.ne(p["lg_kept"], 0)

    def aggregate_value(actual):
        return lambda: (D.text(e, "made or call-returned aggregate"), actual())

    def aggregate_use(actual):
        return lambda: (D.text(e, "aggregate.get or a return"), actual())

    # (a) ``result_fields`` of the function itself.
    e.var("lg_own", _call(e, "result_fields", f))
    e.var("lg_borrowed", _call(e, "borrowed", f))

    # (b) ``Aggregates``, first loop: aggregate block parameters and aggregate results.
    def aggregate_parameter(position, _value):
        _legal(e, isa, e.eq(_call(e, "aggregate", type_at(position)), 0), "AGGREGATE-VALUE", where,
               aggregate_value(lambda: D.text(e, "block parameter")), lambda: None)

    def aggregate_result():
        def result():
            def aggregate():
                e.if_(e.eq(p["lg_op"], int(Operation.AGGREGATE_MAKE)), lambda: None, lambda: e.if_(
                    kept_call(), lambda: _call(e, "result_fields", callee()),
                    lambda: _legal(e, isa, e.eq(0, 1), "AGGREGATE-VALUE", where,
                                   aggregate_value(lambda: D.integer(e, p["lg_op"])), lambda: None)))

            e.if_(e.ne(e.ld(e.add(p["aggv"], e.add(p["lg_id"], p["lg_r"]))), 0), aggregate)

        e.for_("lg_r", 0, e.rd(p["lg_results"]), result)

    each_block(lambda block: visit(block, on_parameter=aggregate_parameter, on_node=aggregate_result))

    # (b) second loop: every other use of an aggregate.
    def aggregate_operand():
        def other():
            operands_each(lambda value: _legal(e, isa, e.eq(e.ld(e.add(p["aggv"], value)), 0), "AGGREGATE-USE", where,
                                               aggregate_use(lambda: D.integer(e, p["lg_op"])), lambda: None))

        e.if_(e.either(e.eq(p["lg_op"], int(Operation.AGGREGATE_GET)), e.eq(p["lg_op"], int(Operation.AGGREGATE_MAKE))), lambda: None, other)

    def aggregate_terminator(at):
        e.var("lg_ta", e.add(at, 1))
        e.var("lg_kind", e.rd(at))
        e.var("lg_bad", 0)

        def argument(value):
            e.if_(e.ne(e.ld(e.add(p["aggv"], value)), 0), lambda: e.set("lg_bad", 1))

        def edge_values():
            e.set("lg_ta", e.add(p["lg_ta"], 1))  # past the target block
            count = e.rd(p["lg_ta"])
            e.var("lg_ec", count)
            e.set("lg_ta", e.add(p["lg_ta"], 1))
            e.for_("lg_v", 0, p["lg_ec"], lambda: argument(raw_value_id("lg_ta")))

        def returned():
            e.var("lg_rc", e.rd(p["lg_ta"]))
            e.set("lg_ta", e.add(p["lg_ta"], 1))

            def value(v):
                e.var("lg_rv", v)
                aggregate = e.ne(e.ld(e.add(p["aggv"], p["lg_rv"])), 0)
                made = e.ne(e.ld(e.add(p["made"], p["lg_rv"])), NONE)
                e.if_(e.both(aggregate, e.either(e.not_(made), e.eq(p["lg_own"], 0))), lambda: e.set("lg_bad", 1))

            e.for_("lg_v", 0, p["lg_rc"], lambda: value(raw_value_id("lg_ta")))

        e.if_(e.eq(p["lg_kind"], int(TerminatorKind.BRANCH)), edge_values, lambda: e.if_(
            e.eq(p["lg_kind"], int(TerminatorKind.CONDITIONAL_BRANCH)), lambda: (argument(raw_value_id("lg_ta")), edge_values(), edge_values()),
            lambda: e.if_(e.eq(p["lg_kind"], int(TerminatorKind.RETURN)), returned)))
        _legal(e, isa, e.eq(p["lg_bad"], 0), "AGGREGATE-USE", where,
               aggregate_use(lambda: D.tagged(e, D.T_TERMINATOR, p["lg_kind"])), lambda: None)

    each_block(lambda block: visit(block, on_node=aggregate_operand, on_terminator=aggregate_terminator))

    # (c) ``machine_width`` of every block parameter and every result that is not elided.
    def elided(r):
        """Result ``r`` of the current node is elided: an aggregate, a borrowed view a call gives back, or an
        ``aggregate.get`` of a made aggregate."""
        e.var("lg_el", e.flag(e.ne(e.ld(e.add(p["aggv"], e.add(p["lg_id"], r))), 0)))
        e.if_(e.both(e.eq(p["lg_op"], int(Operation.CALL_DIRECT)), e.ne(e.ld(e.add(p["alias"], e.add(p["lg_id"], r))), NONE)), lambda: e.set("lg_el", 1))

        def get():
            e.var("lg_ga", e.add(p["lg_ops"], 1))
            e.if_(made_aggregate(raw_value_id("lg_ga")), lambda: e.set("lg_el", 1))

        e.if_(e.eq(p["lg_op"], int(Operation.AGGREGATE_GET)), get)
        return e.ne(p["lg_el"], 0)

    def width(position):
        e.var("lg_wt", type_at(position))
        _legal(e, isa, e.ne(_type_width(e, p["lg_wt"]), NONE), "VALUE-BITS", where, lambda: D.text(e, VALUE_BITS),
               lambda: D.cid(e, _cid_words(e, p["lg_wt"])))

    def result_widths():
        e.for_("lg_r", 0, e.rd(p["lg_results"]), lambda: e.if_(elided(p["lg_r"]), lambda: None,
                                                                 lambda: width(e.add(e.add(p["lg_results"], 1), p["lg_r"]))))

    each_block(lambda block: visit(block, on_parameter=lambda position, _value: width(position), on_node=result_widths))

    # (d) The lowering's checks, in block order: the entry block, then the others.
    def lowered():
        def call():
            e.var("lg_mr", 0)
            e.for_("lg_r", 0, e.rd(p["lg_results"]), lambda: e.if_(elided(p["lg_r"]), lambda: None, lambda: e.if_(
                e.ne(_type_width(e, type_at(e.add(e.add(p["lg_results"], 1), p["lg_r"]))), 0), lambda: e.set("lg_mr", e.add(p["lg_mr"], 1)))))
            _legal(e, isa, e.le(p["lg_mr"], 1), "SINGLE-RESULT", where, lambda: D.integer(e, 1), lambda: D.integer(e, p["lg_mr"]))

        def checked():
            e.var("lg_size", e.rd(e.add(p["lg_attrs"], 1)))
            e.var("lg_pa", e.add(p["lg_ops"], 1))
            e.var("lg_ext", e.ld(e.add(p["ext"], value_id("lg_pa"))))
            size_ok = e.either(*(e.eq(p["lg_size"], size) for size in (1, 2, 4, 8)))

            def actual():
                D.put(e, D.T_LIST)
                D.put(e, 2)
                D.integer(e, p["lg_size"])
                e.if_(e.eq(p["lg_ext"], 0), lambda: D.none(e), lambda: D.integer(e, p["lg_ext"]))

            _legal(e, isa, e.both(size_ok, e.ne(p["lg_ext"], 0)), "CHECKED-ACCESS", where,
                   lambda: D.text(e, "1/2/4/8-byte access through a view pointer"), actual)

        def other():
            _legal(e, isa, _in_set(e, p["lg_op"], isa.LOWERED), "OP-LOWERED", where,
                   lambda: D.text(e, isa.LOWERED_NAME), lambda: D.integer(e, p["lg_op"]))

        checked_access = e.either(e.eq(p["lg_op"], int(Operation.CHECKED_LOAD_BITS_LE)), e.eq(p["lg_op"], int(Operation.CHECKED_STORE_BITS_LE)))
        e.if_(e.eq(p["lg_op"], int(Operation.CALL_DIRECT)), lambda: e.if_(kept_call(), call), lambda: e.if_(checked_access, checked, other))

    def single_return(at):
        def returned():
            e.var("lg_mr", 0)
            iface = _call(e, "interface", f)
            e.var("lg_rt", e.add(e.add(iface, 2), e.ld(e.add(iface, 1))))
            e.for_("lg_q", 0, e.rd(e.add(at, 1)), lambda: e.if_(e.both(
                e.ne(_type_width(e, e.ld(e.add(e.add(p["lg_rt"], 1), p["lg_q"]))), 0), e.eq(e.ld(e.add(p["lg_borrowed"], p["lg_q"])), NONE)),
                lambda: e.set("lg_mr", e.add(p["lg_mr"], 1))))
            _legal(e, isa, e.le(p["lg_mr"], 1), "SINGLE-RESULT", where, lambda: D.integer(e, 1), lambda: D.integer(e, p["lg_mr"]))

        e.if_(e.both(e.eq(e.rd(at), int(TerminatorKind.RETURN)), e.eq(p["lg_own"], 0)), returned)

    entry_block = e.rd(e.add(stream, 1))
    e.var("lg_entry", entry_block)
    visit(p["lg_entry"], on_node=lowered, on_terminator=single_return)
    each_block(lambda block: e.if_(e.ne(block, p["lg_entry"]), lambda: visit(block, on_node=lowered, on_terminator=single_return)))


def _translate(tables, isa=None):
    """One closure function into the internal stream (the S5a format) at ``G_OUT``; with a diagnostic family it first
    decides the function's target legality (``_legality``)."""
    from xax_compiler import Kind

    def build(e: E):
        p = e.p
        f = p["f"]
        iface = _call(e, "interface", f)
        graph = e.ld(iface)
        e.var("graph", graph)
        stream = _at(e, G_PAY, graph)
        B, entry = e.rd(stream), e.rd(e.add(stream, 1))
        e.var("B", B)
        # Pass A: value bases per block and per node.
        e.var("base", e.alloc(e.add(B, 1)))
        e.var("first", e.alloc(e.add(B, 1)))
        e.var("node_base", e.alloc(e.add(e.rd(e.sub(_at(e, G_PAY, graph), 1)), 1)))  # at most one node per stream word
        _ok(e, e.both(e.ne(p["base"], NONE), e.ne(p["first"], NONE), e.ne(p["node_base"], NONE)))
        e.var("pa", e.add(stream, 2))
        e.var("id", 0)
        e.var("nodes", 0)

        def block_a():
            b = p["b"]
            e.st(e.add(p["base"], b), p["id"])
            params = e.rd(p["pa"])
            e.set("id", e.add(p["id"], params))
            e.set("pa", e.add(e.add(p["pa"], 1), params))
            count = e.rd(p["pa"])
            e.set("pa", e.add(p["pa"], 1))
            e.st(e.add(p["first"], b), p["nodes"])

            def node():
                e.st(e.add(p["node_base"], p["nodes"]), p["id"])
                e.set("pa", _call(e, "node_info", p["pa"]))
                e.set("id", e.add(p["id"], e.rd(e.ld(e.add(_g(e, G_NI), NI_RESULTS)))))
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            e.set("pa", _call(e, "term_end", p["pa"]))

        e.for_("b", 0, B, block_a)
        _emit_out(e, B)
        _emit_out(e, entry)
        _emit_out(e, p["id"])

        def width_of(reference):
            width = _type_width(e, _reference(e, p["graph"], reference))
            _ok(e, e.ne(width, NONE))
            return width

        def raw_value_id(name: str):
            """The value at ``p[name]`` as a value id; advances past it."""
            at = p[name]
            tag, block, index = e.rd(at), e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
            e.var("vid_out", e.add(e.ld(e.add(p["base"], block)), index))
            e.if_(e.eq(tag, 1), lambda: e.set("vid_out", e.add(e.ld(e.add(p["node_base"], e.add(e.ld(e.add(p["first"], block)), index))), e.rd(e.add(at, 3)))))
            e.set(name, e.add(e.add(at, 3), e.flag(e.eq(tag, 1))))
            return p["vid_out"]

        # Pass A2 (views profile, ADR-145): pointer extents from the following heap-view type, and each borrowed view a
        # direct call gives back aliased to the pointer passed in (``_pointer_extents``, ``_rewrite_borrowed_views``).
        e.var("ext", e.alloc(e.add(p["id"], 1)))
        e.var("alias", e.alloc(e.add(p["id"], 1)))
        # ADR-151: an ``aggregate.make`` result's operand list (input position), and which values are aggregates.
        e.var("made", e.alloc(e.add(p["id"], 1)))
        e.var("aggv", e.alloc(e.add(p["id"], 1)))
        _ok(e, e.both(e.ne(p["ext"], NONE), e.ne(p["alias"], NONE), e.ne(p["made"], NONE), e.ne(p["aggv"], NONE)))
        e.for_("q", 0, p["id"], lambda: (e.st(e.add(p["ext"], p["q"]), 0), e.st(e.add(p["alias"], p["q"]), NONE),
                                         e.st(e.add(p["made"], p["q"]), NONE), e.st(e.add(p["aggv"], p["q"]), 0)))

        def scan(types_at, count, first_id):
            """Extents of ``count`` types at input ``types_at`` whose values start at id ``first_id``."""
            e.var("sc_at", types_at)
            e.var("sc_id", first_id)

            def pair():
                extent = _view_extent(e, _reference(e, p["graph"], e.rd(e.add(e.add(p["sc_at"], p["k"]), 1))))
                e.var("sc_ext", extent)
                pointer = e.eq(_type_form(e, _reference(e, p["graph"], e.rd(e.add(p["sc_at"], p["k"])))), 2)
                e.if_(e.both(e.ne(p["sc_ext"], 0), pointer), lambda: e.st(e.add(p["ext"], e.add(p["sc_id"], p["k"])), p["sc_ext"]))

            e.for_("k", 0, e.sub(e.add(count, e.flag(e.eq(count, 0))), 1), pair)

        e.set("pa", e.add(stream, 2))
        e.set("nodes", 0)

        def block_a2():
            params = e.rd(p["pa"])
            scan(e.add(p["pa"], 1), params, e.ld(e.add(p["base"], p["b"])))
            e.set("pa", e.add(e.add(p["pa"], 1), e.rd(p["pa"])))
            count = e.rd(p["pa"])
            e.set("pa", e.add(p["pa"], 1))

            def node():
                e.set("pa", _call(e, "node_info", p["pa"]))
                ni = _g(e, G_NI)
                e.var("a2_op", e.ld(e.add(ni, NI_OP)))
                e.var("a2_entity", e.ld(e.add(ni, NI_ENTITY)))
                e.var("a2_ops", e.ld(e.add(ni, NI_OPERANDS)))
                e.var("a2_results", e.ld(e.add(ni, NI_RESULTS)))
                e.var("a2_id", e.ld(e.add(p["node_base"], p["nodes"])))
                scan(e.add(p["a2_results"], 1), e.rd(p["a2_results"]), p["a2_id"])
                e.for_("r", 0, e.rd(p["a2_results"]), lambda: e.if_(
                    e.ne(_call(e, "aggregate", _reference(e, p["graph"], e.rd(e.add(e.add(p["a2_results"], 1), p["r"])))), 0),
                    lambda: e.st(e.add(p["aggv"], e.add(p["a2_id"], p["r"])), 1)))
                e.if_(e.eq(p["a2_op"], int(Operation.AGGREGATE_MAKE)), lambda: e.st(e.add(p["made"], p["a2_id"]), p["a2_ops"]))

                def call():
                    e.var("a2_callee", _reference(e, p["graph"], p["a2_entity"]))
                    _ok(e, e.ne(p["a2_callee"], NONE))

                    def kept():
                        e.var("a2_map", _call(e, "borrowed", p["a2_callee"]))

                        def aliased():
                            e.var("a2_at", e.add(p["a2_ops"], 1))
                            e.for_("j", 0, e.ld(e.add(p["a2_map"], p["r"])), lambda: raw_value_id("a2_at"))
                            e.st(e.add(p["alias"], e.add(p["a2_id"], p["r"])), raw_value_id("a2_at"))

                        e.for_("r", 0, e.rd(p["a2_results"]), lambda: e.if_(e.ne(e.ld(e.add(p["a2_map"], p["r"])), NONE), aliased))

                    e.if_(e.eq(_call(e, "erased", p["a2_callee"]), 0), kept)

                e.if_(e.eq(p["a2_op"], int(Operation.CALL_DIRECT)), call)
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            e.set("pa", _call(e, "term_end", p["pa"]))

        e.for_("b", 0, B, block_a2)

        # Pass A3 (ADR-151): ``aggregate.get`` of a made aggregate is that field.
        e.set("pa", e.add(stream, 2))
        e.set("nodes", 0)

        def block_a3():
            e.set("pa", e.add(e.add(p["pa"], 1), e.rd(p["pa"])))
            count = e.rd(p["pa"])
            e.set("pa", e.add(p["pa"], 1))

            def node():
                e.set("pa", _call(e, "node_info", p["pa"]))
                ni = _g(e, G_NI)

                def get():
                    e.var("a3_at", e.add(e.ld(e.add(ni, NI_OPERANDS)), 1))
                    e.var("a3_agg", raw_value_id("a3_at"))
                    e.var("a3_index", e.rd(e.add(e.ld(e.add(ni, NI_ATTRIBUTES)), 1)))

                    def field():
                        e.var("a3_field_at", e.add(e.ld(e.add(p["made"], p["a3_agg"])), 1))
                        e.for_("j", 0, p["a3_index"], lambda: raw_value_id("a3_field_at"))
                        e.st(e.add(p["alias"], e.ld(e.add(p["node_base"], p["nodes"]))), raw_value_id("a3_field_at"))

                    e.if_(e.ne(e.ld(e.add(p["made"], p["a3_agg"])), NONE), field)

                e.if_(e.eq(e.ld(e.add(ni, NI_OP)), int(Operation.AGGREGATE_GET)), get)
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            e.set("pa", _call(e, "term_end", p["pa"]))

        e.for_("b", 0, B, block_a3)

        def value_id(name: str):
            """``raw_value_id`` through the borrowed-view aliases."""
            e.var("vid_c", raw_value_id(name))
            e.while_(lambda: e.ne(e.ld(e.add(p["alias"], p["vid_c"])), NONE), lambda: e.set("vid_c", e.ld(e.add(p["alias"], p["vid_c"]))))
            return p["vid_c"]

        def values(name: str, emit=True, scalar=None):
            """Emit ``[count, value ids]``; ``scalar`` (a condition) declines on an aggregate value (ADR-151)."""
            count = e.rd(p[name])
            e.set(name, e.add(p[name], 1))
            if emit:
                _emit_out(e, count)

            def each():
                e.var("vv_id", value_id(name))
                if scalar is not None:
                    _ok(e, e.either(e.not_(scalar()), e.eq(e.ld(e.add(p["aggv"], p["vv_id"])), 0)))
                _emit_out(e, p["vv_id"])

            e.for_("vv", 0, count, each)
            return count

        if _diagnostics(isa):
            _legality(e, isa, f, stream, raw_value_id, value_id)

        # Pass B: the stream.
        e.set("pa", e.add(stream, 2))
        e.set("nodes", 0)
        e.var("own", _call(e, "borrowed", f))
        e.var("own_fields", _call(e, "result_fields", f))
        returns_at = e.add(e.add(iface, 2), e.ld(e.add(iface, 1)))

        def block_b():
            params = e.rd(p["pa"])
            _emit_out(e, params)
            e.for_("q", 0, params, lambda: _emit_out(e, width_of(e.rd(e.add(e.add(p["pa"], 1), p["q"])))))
            e.set("pa", e.add(e.add(p["pa"], 1), params))
            count = e.rd(p["pa"])
            e.set("pa", e.add(p["pa"], 1))
            _emit_out(e, count)

            def node():
                e.var("next_node", _call(e, "node_info", p["pa"]))
                ni = _g(e, G_NI)
                operation, entity = e.ld(e.add(ni, NI_OP)), e.ld(e.add(ni, NI_ENTITY))
                results_at, attributes_at = e.ld(e.add(ni, NI_RESULTS)), e.ld(e.add(ni, NI_ATTRIBUTES))
                e.var("na_ops", e.ld(e.add(ni, NI_OPERANDS)))
                _emit_out(e, operation)
                results = e.rd(results_at)
                _emit_out(e, results)
                e.var("nb_id", e.ld(e.add(p["node_base"], p["nodes"])))
                e.var("nb_results", results_at)
                e.var("nb_op", operation)
                aggregate_node = e.either(e.eq(p["nb_op"], int(Operation.AGGREGATE_MAKE)), e.eq(p["nb_op"], int(Operation.CALL_DIRECT)))
                e.var("nb_aggregate_node", e.flag(aggregate_node))

                def result_width():
                    alias = e.ld(e.add(p["alias"], e.add(p["nb_id"], p["q"])))
                    aggregate = e.ne(e.ld(e.add(p["aggv"], e.add(p["nb_id"], p["q"]))), 0)
                    e.var("nb_agg", e.flag(aggregate))
                    # An aggregate (made or call-returned, ADR-151) and an aliased value are no machine values.
                    e.if_(e.ne(p["nb_agg"], 0), lambda: _ok(e, e.ne(p["nb_aggregate_node"], 0)))
                    e.if_(e.either(e.ne(alias, NONE), e.ne(p["nb_agg"], 0)), lambda: _emit_out(e, 0),
                          lambda: _emit_out(e, width_of(e.rd(e.add(e.add(p["nb_results"], 1), p["q"])))))

                e.for_("q", 0, results, result_width)
                e.var("op0_at", e.add(p["na_ops"], 1))
                e.var("op0", NONE)
                e.if_(e.ne(e.rd(p["na_ops"]), 0), lambda: e.set("op0", value_id("op0_at")))
                values("na_ops", scalar=lambda: e.both(e.ne(p["nb_op"], int(Operation.AGGREGATE_GET)), e.ne(p["nb_op"], int(Operation.AGGREGATE_MAKE))))
                e.var("nb_fields", 0)

                def hidden():
                    callee = _reference(e, p["graph"], entity)
                    e.var("nb_callee", callee)
                    _ok(e, e.ne(p["nb_callee"], NONE))
                    e.if_(e.eq(_call(e, "erased", p["nb_callee"]), 0), lambda: e.set("nb_fields", _call(e, "result_fields", p["nb_callee"])))

                e.if_(e.eq(p["nb_op"], int(Operation.CALL_DIRECT)), hidden)
                e.if_(e.ne(p["nb_fields"], 0), lambda: (_emit_out(e, 1), _emit_out(e, p["nb_fields"])), lambda: e.if_(
                    e.eq(attributes_at, NONE), lambda: _emit_out(e, 0), lambda: (
                        _emit_out(e, e.rd(attributes_at)), e.for_("q", 0, e.rd(attributes_at), lambda: _emit_out(e, e.rd(e.add(e.add(attributes_at, 1), p["q"])))))))
                e.var("extra", 0)

                def constant():
                    obj = _reference(e, p["graph"], entity)
                    _ok(e, e.both(e.ne(obj, NONE), e.eq(_kind(e, obj), int(Kind.CONSTANT))))
                    e.var("ca", _at(e, G_PAY, obj))
                    _payload_uleb(e, "ca")
                    length = _payload_uleb(e, "ca")
                    e.var("clen", length)
                    _ok(e, e.le(p["clen"], 8))
                    e.var("factor", 1)
                    e.for_("q", 0, p["clen"], lambda: (e.set("extra", e.add(p["extra"], e.mul(e.rd(e.add(p["ca"], p["q"])), p["factor"]))),
                                                       e.set("factor", e.mul(p["factor"], 256))))

                def call():
                    callee = _reference(e, p["graph"], entity)
                    e.var("callee", callee)
                    _ok(e, e.ne(p["callee"], NONE))
                    erased = _call(e, "erased", p["callee"])
                    e.if_(e.ne(erased, 0), lambda: e.set("extra", NONE), lambda: (
                        _ok(e, e.ne(_at(e, G_FIDX, p["callee"]), NONE)), e.set("extra", _at(e, G_FIDX, p["callee"]))))

                def checked():
                    known = e.ne(p["op0"], NONE)
                    extent = e.ld(e.add(p["ext"], e.sel(known, p["op0"], 0)))
                    e.set("extra", e.sel(e.both(known, e.ne(extent, 0)), extent, NONE))

                e.if_(e.eq(operation, int(Operation.CONSTANT)), constant, lambda: e.if_(e.eq(operation, int(Operation.CALL_DIRECT)), call, lambda: e.if_(
                    e.either(e.eq(operation, int(Operation.CHECKED_LOAD_BITS_LE)), e.eq(operation, int(Operation.CHECKED_STORE_BITS_LE))), checked)))
                _emit_out(e, p["extra"])
                e.set("pa", p["next_node"])
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            kind = e.rd(p["pa"])
            e.var("tk", kind)
            e.set("pa", e.add(p["pa"], 1))
            _emit_out(e, kind)

            def edge_out():
                _emit_out(e, e.rd(p["pa"]))
                e.set("pa", e.add(p["pa"], 1))
                values("pa", scalar=lambda: e.eq(0, 0))

            def branch():
                _emit_out(e, 0)
                _emit_out(e, 1)
                edge_out()

            def conditional():
                _emit_out(e, 1)
                _emit_out(e, value_id("pa"))
                _emit_out(e, 0)
                _emit_out(e, 2)
                edge_out()
                edge_out()

            def aggregate_returns():
                # ADR-151: the made aggregate expands to its fields (flag 2, stored to the result area); the other
                # returned values are proof values.
                count = e.rd(p["pa"])
                e.var("rc", count)
                e.set("pa", e.add(p["pa"], 1))
                e.var("rv_at", p["pa"])
                e.var("rx", 0)

                def counted():
                    e.var("rx_id", value_id("rv_at"))
                    fields = e.ld(e.add(p["made"], p["rx_id"]))
                    e.set("rx", e.add(p["rx"], e.sel(e.ne(fields, NONE), e.rd(e.sel(e.ne(fields, NONE), fields, 0)), 1)))

                e.for_("vv", 0, p["rc"], counted)
                _emit_out(e, p["rx"])
                for pass_ in ("values", "flags"):
                    e.set("rv_at", p["pa"])

                    def emitted(pass_=pass_):
                        e.var("rx_id", value_id("rv_at"))
                        e.var("rx_made", e.ld(e.add(p["made"], p["rx_id"])))

                        def fields():
                            e.var("rx_field_at", e.add(p["rx_made"], 1))
                            if pass_ == "values":
                                e.for_("j", 0, e.rd(p["rx_made"]), lambda: _emit_out(e, value_id("rx_field_at")))
                            else:
                                e.for_("j", 0, e.rd(p["rx_made"]), lambda: _emit_out(e, 2))

                        def proof():
                            declared = e.lt(p["vv"], e.ld(returns_at))
                            position = e.sel(declared, p["vv"], 0)
                            _ok(e, e.both(declared, e.eq(_type_width(e, e.ld(e.add(e.add(returns_at, 1), position))), 0)))
                            _emit_out(e, p["rx_id"] if pass_ == "values" else 0)

                        e.if_(e.ne(p["rx_made"], NONE), fields, proof)

                    e.for_("vv", 0, p["rc"], emitted)
                e.set("pa", p["rv_at"])
                _emit_out(e, 0)

            def returns():
                count = e.rd(p["pa"])
                e.var("rc", count)
                e.set("pa", e.add(p["pa"], 1))
                _emit_out(e, p["rc"])
                e.var("rv_at", p["pa"])
                e.for_("vv", 0, p["rc"], lambda: _emit_out(e, value_id("pa")))
                def flag():
                    declared = e.lt(p["q"], e.ld(returns_at))
                    position = e.sel(declared, p["q"], 0)
                    machine = e.both(declared, e.ne(_type_width(e, e.ld(e.add(e.add(returns_at, 1), position))), 0),
                                     e.eq(e.ld(e.add(p["own"], position)), NONE))  # an elided borrowed view is no machine value
                    _emit_out(e, e.flag(machine))

                e.for_("q", 0, p["rc"], flag)
                _emit_out(e, 0)

            def trap():
                e.set("pa", e.add(p["pa"], 2))
                _emit_out(e, 0)
                _emit_out(e, 0)

            e.if_(e.eq(kind, 1), branch, lambda: e.if_(e.eq(kind, 2), conditional, lambda: e.if_(
                e.eq(kind, 3), lambda: e.if_(e.ne(p["own_fields"], 0), aggregate_returns, returns), trap)))

        e.for_("b", 0, B, block_b)
        e.give(1)
    return _function(("f",), build, tables)


def _frontend(tables, isa):
    """The closure, the target's operation sets, the function order, and the internal stream."""
    from xax_compiler import Kind

    def build(e: E):
        p = e.p
        # S7b.2: the store's objects in store order, then the bound target; references and identities are CIDs.
        if _diagnostics(isa):
            e.st(GLOBALS + G_PENDING, 0)
        S = e.rd(0)
        e.st(GLOBALS + G_S, S)
        for slot in (G_REC, G_PAY, G_TW, G_FIDX, G_ERASED, G_IFACE, G_ORDER, G_REFS):
            table = e.alloc(e.add(S, 2))
            _ok(e, e.ne(table, NONE))
            e.st(GLOBALS + slot, table)
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
            for slot in (G_FIDX, G_ERASED, G_IFACE):
                e.st(e.add(_g(e, slot), o), NONE)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))

        e.for_("o", 0, e.add(S, 1), record)
        _ok(e, e.le(p["ra"], IN_WORDS))
        # The bound target is the store's object of that CID, else the record after the store's objects.
        e.st(GLOBALS + G_O, S)  # ``_find`` over the store's objects only
        e.var("target", e.call(_FN["find"], _cid_at(e, S)))
        e.if_(e.eq(p["target"], NONE), lambda: (e.set("target", S), e.st(GLOBALS + G_O, e.add(S, 1))))
        O = _g(e, G_O)
        e.var("entry", e.call(_FN["find"], 1))
        _ok(e, e.both(e.ne(p["entry"], NONE), e.eq(_kind(e, p["entry"]), int(Kind.FUNCTION))))

        def resolve():
            o = p["o"]
            count = e.rd(e.add(_at(e, G_REC, o), 1))
            e.var("refs", e.alloc(e.add(count, 1)))
            _ok(e, e.ne(p["refs"], NONE))
            e.st(e.add(_g(e, G_REFS), o), p["refs"])
            first = e.add(_at(e, G_REC, o), 2)
            e.for_("k", 0, count, lambda: e.st(e.add(p["refs"], p["k"]), e.call(_FN["find"], e.add(first, e.mul(p["k"], CID_WORDS)))))

        e.for_("o", 0, O, resolve)
        target = p["target"]
        # The target's operation and terminator sets (a verified package of the ISA's architecture).
        e.var("ta", _at(e, G_PAY, target))
        identity = _payload_uleb(e, "ta")
        e.set("ta", e.add(p["ta"], identity))
        fields = [_payload_uleb(e, "ta") for _ in range(6)]
        e.var("arch", fields[1])
        _ok(e, e.eq(p["arch"], isa.ARCHITECTURE))
        isa.skip_target_machine(e)
        for table in (G_SUP, G_SUPT):
            if _diagnostics(isa):
                e.st(GLOBALS + (G_SUP_AT if table == G_SUP else G_SUPT_AT), p["ta"])  # the list a rejection quotes
            count = _payload_uleb(e, "ta")
            e.var("tcount", count)
            e.for_("q", 0, p["tcount"], lambda table=table: (lambda value: (_ok(e, e.lt(value, 256 if table == G_SUP else 8)), e.st(e.add(_g(e, table), value), 1)))(
                _payload_uleb(e, "ta")))
        e.st(GLOBALS + G_FAR, _at(e, G_SUP, int(Operation.CHECKED_LOAD_BITS_LE)))  # views profile: far jumps
        # The closure from the entry (callees that are not erased proof functions).
        work = e.alloc(e.add(O, 1))
        _ok(e, e.ne(work, NONE))
        e.var("work", work)
        e.var("wn", 1)
        e.st(p["work"], p["entry"])
        e.var("members", 0)
        visited = _g(e, G_TW)  # reused as visited flags
        e.for_("o", 0, O, lambda: e.st(e.add(visited, p["o"]), 0))

        def visit():
            e.set("wn", e.sub(p["wn"], 1))
            f = e.ld(e.add(p["work"], p["wn"]))
            e.var("cf", f)

            def fresh():
                e.st(e.add(visited, p["cf"]), 1)
                e.st(e.add(_g(e, G_ORDER), p["members"]), p["cf"])
                e.set("members", e.add(p["members"], 1))
                iface = _call(e, "interface", p["cf"])
                e.var("cg", e.ld(iface))
                stream = _at(e, G_PAY, p["cg"])
                e.var("wa", e.add(stream, 2))

                def block():
                    e.set("wa", e.add(e.add(p["wa"], 1), e.rd(p["wa"])))
                    count = e.rd(p["wa"])
                    e.set("wa", e.add(p["wa"], 1))

                    def node():
                        e.set("wa", _call(e, "node_info", p["wa"]))
                        ni = _g(e, G_NI)
                        operation = e.ld(e.add(ni, NI_OP))
                        _legal(e, isa, e.both(e.lt(operation, 256), e.ne(_at(e, G_SUP, e.sel(e.lt(operation, 256), operation, 0)), 0)),
                               "OP-TARGET-SUPPORTED", p["cg"], lambda: _target_list(e, G_SUP_AT),
                               lambda: D.integer(e, operation))

                        def callee():
                            e.var("cc", _reference(e, p["cg"], e.ld(e.add(ni, NI_ENTITY))))
                            _ok(e, e.both(e.ne(p["cc"], NONE), e.eq(_kind(e, p["cc"]), int(Kind.FUNCTION))))
                            e.if_(e.both(e.eq(_call(e, "erased", p["cc"]), 0), e.eq(e.ld(e.add(visited, p["cc"])), 0)), lambda: (
                                e.st(e.add(p["work"], p["wn"]), p["cc"]), e.set("wn", e.add(p["wn"], 1)), _ok(e, e.le(p["wn"], O))))

                        e.if_(e.eq(operation, int(Operation.CALL_DIRECT)), callee)

                    e.for_("m", 0, count, node)
                    kind = e.rd(p["wa"])
                    _legal(e, isa, e.both(e.lt(kind, 8), e.ne(_at(e, G_SUPT, e.sel(e.lt(kind, 8), kind, 0)), 0)),
                           "TERMINATOR-TARGET-SUPPORTED", p["cg"], lambda: _target_list(e, G_SUPT_AT),
                           lambda: D.tagged(e, D.T_TERMINATOR, kind))
                    e.set("wa", _call(e, "term_end", p["wa"]))

                e.for_("b", 0, e.rd(stream), block)

            e.if_(e.eq(e.ld(e.add(visited, p["cf"])), 0), fresh)

        e.while_(lambda: e.ne(p["wn"], 0), visit)
        # Order: the entry, then the others by CID.
        order = _g(e, G_ORDER)
        e.for_("q", 0, p["members"], lambda: e.if_(e.eq(e.ld(e.add(order, p["q"])), p["entry"]), lambda: (
            e.st(e.add(order, p["q"]), e.ld(order)), e.st(order, p["entry"]))))

        def cid_before(x, y):
            return _cid_less(e, _cid_at(e, x), _cid_at(e, y))

        def insert():
            e.var("item", e.ld(e.add(order, p["s"])))
            e.var("j", p["s"])
            e.while_(lambda: e.both(e.lt(1, p["j"]), cid_before(p["item"], e.ld(e.add(order, e.sub(p["j"], 1))))), lambda: (
                e.st(e.add(order, p["j"]), e.ld(e.add(order, e.sub(p["j"], 1)))), e.set("j", e.sub(p["j"], 1))))
            e.st(e.add(order, p["j"]), p["item"])

        e.for_("s", 2, p["members"], insert)
        e.for_("q", 0, p["members"], lambda: e.st(e.add(_g(e, G_FIDX), e.ld(e.add(order, p["q"]))), p["q"]))
        e.st(GLOBALS + G_F, p["members"])
        # The internal stream.
        e.st(GLOBALS + G_OUT, STREAM_AT)
        _emit_out(e, p["members"])
        e.for_("q", 0, p["members"], lambda: _call(e, "translate", e.ld(e.add(order, p["q"]))))
        _ok(e, e.lt(_g(e, G_OUT), STREAM_END))
        # The entry's machine parameter and return widths.
        iface = _call(e, "interface", p["entry"])
        widths = e.alloc(e.add(e.add(e.ld(e.add(iface, 1)), e.ld(e.add(e.add(iface, 2), e.ld(e.add(iface, 1))))), 4))
        _ok(e, e.ne(widths, NONE))
        e.st(GLOBALS + G_WIDTHS, widths)
        e.var("wc", 0)
        e.var("wbase", widths)
        for part in range(2):
            def lists(part=part):
                at = e.add(iface, 1) if part == 0 else e.add(e.add(iface, 2), e.ld(e.add(iface, 1)))
                e.var("wcount_at", p["wc"])
                e.set("wc", e.add(p["wc"], 1))
                e.var("machine", 0)

                def each():
                    width = _type_width(e, e.ld(e.add(e.add(at, 1), p["q"])))
                    e.var("ew", width)
                    if _diagnostics(isa):  # ``machine_width`` of the entry's interface (S7b)
                        e.var("ew_type", e.ld(e.add(e.add(at, 1), p["q"])))
                    _legal(e, isa, e.ne(p["ew"], NONE), "VALUE-BITS", p["entry"], lambda: D.text(e, VALUE_BITS),
                           lambda: D.cid(e, _cid_words(e, p["ew_type"])), deferred=True)
                    e.if_(e.ne(p["ew"], 0), lambda: (e.st(e.add(widths, p["wc"]), p["ew"]), e.set("wc", e.add(p["wc"], 1)), e.set("machine", e.add(p["machine"], 1))))

                e.for_("q", 0, e.ld(at), each)
                e.st(e.add(widths, p["wcount_at"]), p["machine"])

            lists()
        e.give(1)
    return _function((), build, tables)


# -- the program -----------------------------------------------------------------------------------

def _program(tables, compile_function, isa):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, ARENA_AT + 64)  # the front end's GLOBALS come first
        e.set_hd(H_ARENA_END, ARENA_END)
        e.set_hd(S_COUNT, 0)
        e.set_hd(S_JUMPS, 0)
        e.set_hd(S_RANGES, 0)
        powers = e.alloc(64)
        e.var("power", 1)
        e.for_("z", 0, 64, lambda: (e.st(e.add(powers, p["z"]), p["power"]), e.set("power", e.mul(p["power"], 2))))
        e.set_hd(S_POW, powers)
        e.set_hd(S_LEVELS, e.alloc(32))
        _ok(e, e.ne(e.call(_FN["frontend"]), NONE))
        functions = e.ld(STREAM_AT)
        offsets = e.alloc(e.add(functions, 1))
        _ok(e, e.ne(offsets, NONE))
        e.set_hd(S_OFFSETS, offsets)
        e.for_("f", 0, functions, lambda: e.st(e.add(offsets, p["f"]), NONE))
        e.var("cursor", STREAM_AT + 1)

        def each():
            e.set("cursor", e.call(compile_function, p["cursor"], p["f"]))
            _ok(e, e.ne(p["cursor"], NONE))
            _ok(e, e.lt(e.hd(S_COUNT), isa.CODE_LIMIT))

        e.for_("f", 0, functions, each)
        isa.patch(e)
        # S7b.2: the image record -- each function's CID and code range, in layout order.
        e.var("image", e.alloc(e.mul(functions, CID_WORDS + 1)))
        _ok(e, e.ne(p["image"], NONE))

        def describe():
            at = e.add(p["image"], e.mul(p["f"], CID_WORDS + 1))
            for k, word in enumerate(_cid_words(e, e.ld(e.add(_g(e, G_ORDER), p["f"])))):
                e.st(e.add(at, k), word)
            last = e.eq(e.add(p["f"], 1), functions)
            e.st(e.add(at, CID_WORDS), e.sel(last, e.hd(S_COUNT), e.ld(e.add(offsets, e.sel(last, 0, e.add(p["f"], 1))))))

        e.for_("f", 0, functions, describe)
        if _diagnostics(isa):  # a deferred rejection (``_legal``) wins over the finished image
            e.if_(e.ne(_g(e, G_PENDING), 0), lambda: (e.st(0, D.REJECT), e.give(NONE)))
        e.st(1, e.hd(S_COUNT))
        e.st(2, e.hd(S_RANGES))
        e.st(3, offsets)
        e.st(4, p["image"])
        e.st(5, _g(e, G_WIDTHS))
        e.st(0, OK)
        e.give(1)
    return _function((), build, tables)


# -- outputs and native execution ---------------------------------------------------------------------

def collect_program_output(read):
    """A backend program's result from its output view, read as ``read(start word, count)`` wherever it ran:
    ``(code units, function CIDs in layout order, their start and end offsets in code units, node ranges by layout
    position, entry parameter widths, entry return widths)``, or None (declined).  A code unit is a RISC-V instruction
    word or an x86-64 byte.  Every field is the program's (S7b.2); this only reads words."""
    status, count, ranges, offsets_at, image_at, widths_at = read(0, 6)
    if status != OK:
        return None
    (functions,) = read(STREAM_AT, 1)
    code = read(WORDS_AT, count)
    image = read(image_at, functions * (CID_WORDS + 1))
    records = [image[k:k + CID_WORDS + 1] for k in range(0, len(image), CID_WORDS + 1)]
    cids = [b"".join(word.to_bytes(8, "big") for word in record[:CID_WORDS]) for record in records]
    offsets = list(zip(read(offsets_at, functions), (record[CID_WORDS] for record in records)))
    flat = read(RANGES_AT, 5 * ranges)
    (parameters,) = read(widths_at, 1)
    parameter_widths = tuple(read(widths_at + 1, parameters))
    returns_at = widths_at + 1 + parameters
    (returns,) = read(returns_at, 1)
    return_widths = tuple(read(returns_at + 1, returns))
    return code, cids, offsets, [tuple(flat[k : k + 5]) for k in range(0, len(flat), 5)], parameter_widths, return_widths


class NativeProgram:
    """A backend program's committed store, its x86-64 image (``host_image``, cached on disk), and an in-process
    runner."""

    def __init__(self, store_path, build, cache_name: str) -> None:
        self.store_path, self.build, self.cache_name = store_path, build, cache_name
        self._native: list = []
        self._building = False

    def load(self):
        """``(reader, function)``: the committed store (or a fresh build when it is absent) and its entry."""
        from xax_compiler import Kind, StoreReader

        if not self.store_path.exists():
            return self.build()
        from xax_native import verify_component_store

        reader = StoreReader(self.store_path.read_bytes())
        verify_component_store(reader, self.store_path.stem)
        module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
        function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
        return reader, function

    def write(self) -> bytes:
        import xax_compiler

        building = xax_compiler._TYPING_BUILDING
        xax_compiler._TYPING_BUILDING = True  # the helper graphs are verified by the bootstrap while it is built
        try:
            reader, _function = self.build()
            self.store_path.write_bytes(reader.data)
        finally:
            xax_compiler._TYPING_BUILDING = building
        return reader.data

    def image(self) -> tuple[bytes, int]:
        """``(machine code, entry offset)``: lowered for this host by the XAX x86-64 backend (ADR-152)."""
        from xax_selfhost_x86_64_backend import host_image

        return host_image(*self.load(), self.cache_name)

    def native(self, opt_out: str):
        """The shared in-process runner, or None where it cannot run (or when ``opt_out`` is set to 1)."""
        import os
        import platform
        import sys

        if self._building:
            return None  # its own image is being made: the bootstrap generator lowers it
        if not self._native:
            import xax_native

            usable = xax_native.usable(self.cache_name, self.store_path, opt_out)
            self._building = True
            try:
                self._native.append(_NativeRunner(*self.image()) if usable else None)
            except (OSError, RuntimeError, ValueError) as error:
                self._native.append(None)
                xax_native.fallback(self.cache_name, f"native image failed to load: {error!r}")
            finally:
                self._building = False
        return self._native[0]


class _NativeRunner:
    """Calls a views program ``(in view, out view)`` through the Win64 thunk; serialised by a lock."""

    def __init__(self, code: bytes, entry_offset: int) -> None:
        import ctypes
        import mmap
        import threading

        from xax_selfhost_typing import OUT_WORDS
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        blob = thunk + code
        from xax_native import executable_mapping

        self._mapping, base = executable_mapping(blob)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self._in = (ctypes.c_uint64 * IN_WORDS)()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def run(self, words: list[int], collect):
        """``collect(read)`` after running on input ``words``; None when the words do not fit."""
        import ctypes

        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            return collect(lambda start, count: list(out[start : start + count]))
