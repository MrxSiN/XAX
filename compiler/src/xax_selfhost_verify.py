"""Self-hosting steps S6b.2 and S6b.3 (ADR-144, ADR-146): store-level and object-level verification as XAX semantics.

One XAX program, run natively like the typing program (ADR-132), reads every
store object (the S5b object table: kind, reference indices, CID, and the
body bytes; for a graph fragment the S3c XAX graph-decoder stream, then its
body bytes) and decides, with the bootstrap's rules:

* functions (``_verify_function``): for an ordinary graph, the exact
  interface body, a graph-fragment carrier, parameter and return types that
  are types the XAX object verdicts proved (ADR-143), exact reference use, no
  group member calls, and the graph contract (the entry block's parameters
  are the interface's, and every ``return`` returns values of its types); for
  a group member function, ``[group, member]`` naming a proven group and a
  member it has;
* recursion groups (``_verify_recursion_group``): the member list, each
  member graph's contract, every ``call.group_member`` naming a member and
  matching its interface, one recursive strongly connected component, and
  the canonical member order (member keys: graph reference CIDs, the graph
  bytes without member-call spans, parameter and return types);
* targets (``decode_native_target``): identity-only carriers and the general
  and concurrency profiles of every supported architecture;
* module and program-root reference lists (``_verify_reference_list``);
* call contracts (``_decode_call_contract``);
* the store: every object reachable from the root, no reference cycle.

Its output is a verdict per object (each proven function's graph object, each
proven group's member graphs) and a store verdict.  A verdict holds only when
the bootstrap accepts; every other object, and every rejection, takes the
bootstrap path and its exact diagnostic.  Accelerator, platform, and board
targets and build objects stay with the bootstrap.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import platform
import sys
import threading
from pathlib import Path

from xax_compiler import Kind, Operation, TerminatorKind, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, HEADER, NONE, _function, _uleb
from xax_selfhost_typing import IN_WORDS, OUT_WORDS

STORE_PATH = Path(__file__).resolve().parents[1] / "bootstrap" / "xax_store_verifier.xax"
VERDICTS_AT, GRAPHS_AT, ARENA_AT = 1 << 20, 6 << 20, 12 << 20
OK = 1
ENTITY_CODES = (5, 6, 30, 41, 42, 43)
ATTRIBUTE_CODES = (7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 52, 53, 55, 56, 57,
                   61, 63, 64, 65, 66, 73, 74, 75, 76)
MODULE_CHILDREN = (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT)
# Globals (the first arena words): table pointers.
GLOBALS = ARENA_AT
G_REC, G_O, G_TYPEOK, G_MARK = range(4)
_FN: dict = {}


def _g(e: E, slot: int):
    return e.ld(GLOBALS + slot)


def _rec(e: E, obj):
    return e.ld(e.add(_g(e, G_REC), obj))


def _kind(e: E, obj):
    return e.rd(_rec(e, obj))


def _references(e: E, obj):
    return e.rd(e.add(_rec(e, obj), 1))


def _reference(e: E, obj, k):
    return e.rd(e.add(e.add(_rec(e, obj), 2), k))


def _payload(e: E, obj):
    return e.add(e.add(e.add(_rec(e, obj), 2), _references(e, obj)), 5)


def _type_ok(e: E, obj):
    return e.both(e.lt(obj, _g(e, G_O)), e.ne(e.rd(e.add(_g(e, G_TYPEOK), e.sel(e.lt(obj, _g(e, G_O)), obj, 0))), 0))


DECLINE_SITES: list[str] = []  # diagnosis: out[2] names the check that gave the last 0 verdict


def _no(e: E, condition):
    """Verdict 0 when ``condition``."""
    import inspect

    frame = inspect.stack()[1]
    code = len(DECLINE_SITES) + 1
    DECLINE_SITES.append(f"{frame.function}:{frame.lineno}")
    e.if_(condition, lambda: (e.st(2, code), e.give(0)))


def _read(e: E, name: str, end):
    """A canonical ULEB at ``p[name]``, inside ``end``; advances it (verdict 0 otherwise)."""
    p = e.p
    value, size, ok = _uleb(e, p[name])
    _no(e, e.not_(ok))
    e.set(name, e.add(p[name], size))
    _no(e, e.lt(end, p[name]))
    e.var(f"{name}_value", value)
    return p[f"{name}_value"]


def _clear_marks(e: E, count):
    p = e.p
    e.for_("mk", 0, count, lambda: e.st(e.add(_g(e, G_MARK), p["mk"]), 0))


def _mark(e: E, index):
    e.st(e.add(_g(e, G_MARK), index), 1)


def _all_marked(e: E, count):
    p = e.p
    e.var("marked", 1)
    e.for_("mk", 0, count, lambda: e.if_(e.eq(e.ld(e.add(_g(e, G_MARK), p["mk"])), 0), lambda: e.set("marked", 0)))
    return p["marked"]


def _type_reference(e: E, obj, name: str, end):
    """A reference index read at ``p[name]`` naming a proven type; marks it and returns the object."""
    p = e.p
    index = _read(e, name, end)
    e.var(f"{name}_index", index)
    _no(e, e.le(_references(e, obj), p[f"{name}_index"]))
    target = _reference(e, obj, p[f"{name}_index"])
    e.var(f"{name}_target", target)
    _no(e, e.not_(_type_ok(e, p[f"{name}_target"])))
    _mark(e, p[f"{name}_index"])
    return p[f"{name}_target"]


def _node_end(e: E, at):
    """The position after the graph-decoder node record at ``at``, and the record's fields."""
    p = e.p
    e.var("ne_at", at)
    operation = e.rd(p["ne_at"])
    e.var("ne_op", operation)
    e.set("ne_at", e.add(p["ne_at"], 1))
    e.if_(e.eq(p["ne_op"], int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("ne_at", e.add(p["ne_at"], 3)))
    e.if_(e.either(*(e.eq(p["ne_op"], code) for code in ENTITY_CODES)), lambda: e.set("ne_at", e.add(p["ne_at"], 1)))
    count = e.rd(p["ne_at"])
    e.set("ne_at", e.add(p["ne_at"], 1))
    e.for_("nq", 0, count, lambda: e.set("ne_at", e.add(e.add(p["ne_at"], 3), e.flag(e.eq(e.rd(p["ne_at"]), 1)))))
    e.var("ne_results", p["ne_at"])
    e.set("ne_at", e.add(e.add(p["ne_at"], 1), e.rd(p["ne_at"])))
    e.if_(e.either(*(e.eq(p["ne_op"], code) for code in ATTRIBUTE_CODES)), lambda: e.set("ne_at", e.add(e.add(p["ne_at"], 1), e.rd(p["ne_at"]))))
    return p["ne_at"]


def _skip_values(e: E, name: str):
    p = e.p
    count = e.rd(p[name])
    e.set(name, e.add(p[name], 1))
    e.for_("sv", 0, count, lambda: e.set(name, e.add(e.add(p[name], 3), e.flag(e.eq(e.rd(p[name]), 1)))))


def _interface(e: E, obj, name: str, end):
    """Parameter and return types read at ``p[name]`` into a new ``[P, types, R, types]`` record."""
    p = e.p
    e.var(f"{name}_if", e.alloc(e.add(e.sub(end, p[name]), 3)))  # at most one type per body byte
    _no(e, e.eq(p[f"{name}_if"], NONE))
    record = p[f"{name}_if"]
    e.var(f"{name}_np", _read(e, name, end))
    e.st(record, p[f"{name}_np"])
    e.for_("q", 0, p[f"{name}_np"], lambda: e.st(e.add(e.add(p[f"{name}_if"], 1), p["q"]), _type_reference(e, obj, name, end)))
    e.var(f"{name}_rt", e.add(e.add(p[f"{name}_if"], 1), p[f"{name}_np"]))
    e.st(p[f"{name}_rt"], _read(e, name, end))
    e.for_("q", 0, e.ld(p[f"{name}_rt"]), lambda: e.st(e.add(e.add(p[f"{name}_rt"], 1), p["q"]), _type_reference(e, obj, name, end)))
    return p[f"{name}_if"]


def _function_ok(tables):
    """``_verify_function``: 1 (and the graph object, or NONE for a group member function, in GRAPHS) or 0."""
    def build(e: E):
        p = e.p
        f = p["f"]
        references = _references(e, f)
        e.var("refs", references)
        e.var("fa", _payload(e, f))
        end = e.add(p["fa"], e.rd(e.sub(p["fa"], 1)))
        e.var("fend", end)
        _clear_marks(e, p["refs"])
        graph_index = _read(e, "fa", p["fend"])
        e.var("gi", graph_index)
        _no(e, e.le(p["refs"], p["gi"]))
        e.var("graph", _reference(e, f, p["gi"]))
        _no(e, e.eq(p["graph"], NONE))

        def member_function():
            # ``decode_group_member_function``: [group, member], the group proven (S6b.3), member < its size.
            e.var("member", _read(e, "fa", p["fend"]))
            _no(e, e.ne(p["fa"], p["fend"]))
            _no(e, e.ne(e.ld(e.add(VERDICTS_AT, p["graph"])), 1))
            _no(e, e.le(e.ld(e.ld(e.add(GRAPHS_AT, p["graph"]))), p["member"]))
            e.st(e.add(GRAPHS_AT, f), NONE)
            e.give(1)

        e.if_(e.both(e.eq(p["refs"], 1), e.eq(_kind(e, p["graph"]), int(Kind.RECURSION_GROUP))), member_function)
        _no(e, e.ne(_kind(e, p["graph"]), int(Kind.GRAPH_FRAGMENT)))
        _mark(e, p["gi"])
        e.var("iface", _interface(e, f, "fa", p["fend"]))
        _no(e, e.ne(p["fa"], p["fend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        _no(e, e.ne(e.call(_FN["graph"], p["graph"], p["iface"], NONE, NONE), 1))
        e.st(e.add(GRAPHS_AT, f), p["graph"])
        e.give(1)
    return _function(("f",), build, tables)


def _graph_ok(tables):
    """The graph contract of ``g`` against interface record ``iface`` (``_verify_graph_contract``).  Outside a group
    (``members`` NONE) no node is a group member call; in a group (``members`` = ``[count, interface records]``)
    each member call names a member and has its interface, and the calls are written to ``calls`` as
    ``[count, (member, body span start, body span end) in node order]``."""
    def build(e: E):
        p = e.p
        g = p["g"]
        e.var("np", e.ld(p["iface"]))
        e.var("lists", e.add(p["iface"], 1))
        e.var("nr", e.ld(e.add(p["lists"], p["np"])))
        e.var("returns", e.add(e.add(p["lists"], p["np"]), 1))
        stream = _payload(e, g)
        e.var("gs", stream)
        e.var("B", e.rd(p["gs"]))
        e.var("entry", e.rd(e.add(p["gs"], 1)))
        _no(e, e.le(p["B"], p["entry"]))
        e.var("blocks", e.alloc(e.add(p["B"], 1)))
        e.var("firsts", e.alloc(e.add(p["B"], 1)))
        e.var("node_at", e.alloc(e.add(e.rd(e.sub(p["gs"], 1)), 1)))
        e.var("results_at", e.alloc(e.add(e.rd(e.sub(p["gs"], 1)), 1)))  # each node's result list
        e.var("term_at", e.alloc(e.add(p["B"], 1)))  # each block's terminator
        _no(e, e.either(e.eq(p["blocks"], NONE), e.eq(p["firsts"], NONE), e.eq(p["node_at"], NONE), e.eq(p["results_at"], NONE), e.eq(p["term_at"], NONE)))
        e.var("ga", e.add(p["gs"], 2))
        e.var("nodes", 0)

        def place():
            e.st(e.add(p["blocks"], p["b"]), p["ga"])
            e.set("ga", e.add(e.add(p["ga"], 1), e.rd(p["ga"])))
            count = e.rd(p["ga"])
            e.set("ga", e.add(p["ga"], 1))
            e.st(e.add(p["firsts"], p["b"]), p["nodes"])

            def node():
                e.st(e.add(p["node_at"], p["nodes"]), p["ga"])
                _no(e, e.both(e.eq(p["members"], NONE), e.eq(e.rd(p["ga"]), int(Operation.CALL_GROUP_MEMBER))))
                e.set("ga", _node_end(e, p["ga"]))
                e.st(e.add(p["results_at"], p["nodes"]), p["ne_results"])
                e.set("nodes", e.add(p["nodes"], 1))

            e.for_("m", 0, count, node)
            e.st(e.add(p["term_at"], p["b"]), p["ga"])
            kind = e.rd(p["ga"])
            e.set("ga", e.add(p["ga"], 1))

            def edge():
                e.set("ga", e.add(p["ga"], 1))
                _skip_values(e, "ga")

            def conditional():
                e.set("ga", e.add(e.add(p["ga"], 3), e.flag(e.eq(e.rd(p["ga"]), 1))))
                edge()
                edge()

            e.if_(e.eq(kind, 1), edge, lambda: e.if_(e.eq(kind, 2), conditional, lambda: e.if_(
                e.eq(kind, 3), lambda: _skip_values(e, "ga"), lambda: e.set("ga", e.add(p["ga"], 2)))))

        e.for_("b", 0, p["B"], place)
        # Entry parameters: exactly the interface's parameter types.
        entry_at = e.ld(e.add(p["blocks"], p["entry"]))
        _no(e, e.ne(e.rd(entry_at), p["np"]))
        e.for_("q", 0, p["np"], lambda: _no(e, e.ne(_reference(e, g, e.rd(e.add(e.add(entry_at, 1), p["q"]))), e.ld(e.add(p["lists"], p["q"])))))

        def value_type(name: str):
            """The type object of the value at ``p[name]`` (advanced past it)."""
            at = p[name]
            tag, block, index = e.rd(at), e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
            _no(e, e.le(p["B"], block))
            block_at = e.ld(e.add(p["blocks"], block))
            e.var("vt_ref", NONE)

            def parameter():
                _no(e, e.le(e.rd(block_at), index))
                e.set("vt_ref", e.rd(e.add(e.add(block_at, 1), index)))

            def result():
                count_at = e.add(e.add(block_at, 1), e.rd(block_at))
                _no(e, e.le(e.rd(count_at), index))
                results = e.ld(e.add(p["results_at"], e.add(e.ld(e.add(p["firsts"], block)), index)))
                which = e.rd(e.add(at, 3))
                _no(e, e.le(e.rd(results), which))
                e.set("vt_ref", e.rd(e.add(e.add(results, 1), which)))

            e.if_(e.eq(tag, 0), parameter, result)
            e.set(name, e.add(e.add(at, 3), e.flag(e.eq(tag, 1))))
            return _reference(e, g, p["vt_ref"])

        # Every return: the interface's return types.
        def returns_of():
            e.var("ra", e.ld(e.add(p["term_at"], p["b"])))

            def returning():
                e.set("ra", e.add(p["ra"], 1))
                _no(e, e.ne(e.rd(p["ra"]), p["nr"]))
                e.set("ra", e.add(p["ra"], 1))
                e.for_("q", 0, p["nr"], lambda: _no(e, e.ne(value_type("ra"), e.ld(e.add(p["returns"], p["q"])))))

            e.if_(e.eq(e.rd(p["ra"]), int(TerminatorKind.RETURN)), returning)

        e.for_("b", 0, p["B"], returns_of)

        def member_calls():
            # ``_verify_recursion_group``: a member index in range, the member's parameter and result types.
            e.var("mc", 0)

            def check():
                at = e.ld(e.add(p["node_at"], p["nn"]))
                e.var("mc_at", at)

                def group_call():
                    e.var("gm", e.rd(e.add(p["mc_at"], 1)))
                    _no(e, e.le(e.ld(p["members"]), p["gm"]))
                    e.var("gm_if", e.ld(e.add(e.add(p["members"], 1), p["gm"])))
                    e.var("gm_np", e.ld(p["gm_if"]))
                    e.var("ma", e.add(p["mc_at"], 4))
                    _no(e, e.ne(e.rd(p["ma"]), p["gm_np"]))
                    e.set("ma", e.add(p["ma"], 1))
                    e.for_("q", 0, p["gm_np"], lambda: _no(e, e.ne(value_type("ma"), e.ld(e.add(e.add(p["gm_if"], 1), p["q"])))))
                    e.var("gm_rt", e.add(e.add(p["gm_if"], 1), p["gm_np"]))
                    e.var("gm_results", e.ld(e.add(p["results_at"], p["nn"])))
                    _no(e, e.ne(e.rd(p["gm_results"]), e.ld(p["gm_rt"])))
                    e.for_("q", 0, e.ld(p["gm_rt"]), lambda: _no(e, e.ne(_reference(e, g, e.rd(e.add(e.add(p["gm_results"], 1), p["q"]))),
                                                                          e.ld(e.add(e.add(p["gm_rt"], 1), p["q"])))))
                    slot = e.add(e.add(p["calls"], 1), e.mul(p["mc"], 3))
                    e.st(slot, p["gm"])
                    e.st(e.add(slot, 1), e.rd(e.add(p["mc_at"], 2)))
                    e.st(e.add(slot, 2), e.rd(e.add(p["mc_at"], 3)))
                    e.set("mc", e.add(p["mc"], 1))

                e.if_(e.eq(e.rd(p["mc_at"]), int(Operation.CALL_GROUP_MEMBER)), group_call)

            e.for_("nn", 0, p["nodes"], check)
            e.st(p["calls"], p["mc"])

        e.if_(e.ne(p["members"], NONE), member_calls)
        e.give(1)
    return _function(("g", "iface", "members", "calls"), build, tables)


def _cid_word(e: E, obj, k):
    return e.rd(e.add(e.add(e.add(_rec(e, obj), 2), _references(e, obj)), k))


def _group_ok(tables):
    """``_verify_recursion_group``: the member list (``_decode_recursion_group``), each member graph's contract and
    member calls, one recursive strongly connected component, and the canonical member order.  The order check
    compares member keys by their graphs' reference CIDs; a tie there (decided by the erased graph bytes in the
    bootstrap) gives 0.  GRAPHS holds ``[count, member graphs]`` for a proven group."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("ga", _payload(e, o))
        end = e.add(p["ga"], e.rd(e.sub(p["ga"], 1)))
        e.var("gend", end)
        _clear_marks(e, p["refs"])
        e.var("count", _read(e, "ga", p["gend"]))
        _no(e, e.eq(p["count"], 0))
        e.var("table", e.alloc(e.add(p["count"], 1)))  # [count, interface records]
        e.var("graphs", e.alloc(e.add(p["count"], 1)))  # [count, graph objects]
        e.var("callsof", e.alloc(e.add(p["count"], 1)))
        _no(e, e.either(e.eq(p["table"], NONE), e.eq(p["graphs"], NONE), e.eq(p["callsof"], NONE)))
        e.st(p["table"], p["count"])
        e.st(p["graphs"], p["count"])

        def member():
            e.var("gi", _read(e, "ga", p["gend"]))
            _no(e, e.le(p["refs"], p["gi"]))
            e.var("mg", _reference(e, o, p["gi"]))
            _no(e, e.either(e.eq(p["mg"], NONE), e.ne(_kind(e, p["mg"]), int(Kind.GRAPH_FRAGMENT))))
            _mark(e, p["gi"])
            e.st(e.add(e.add(p["graphs"], 1), p["i"]), p["mg"])
            e.st(e.add(e.add(p["table"], 1), p["i"]), _interface(e, o, "ga", p["gend"]))

        e.for_("i", 0, p["count"], member)
        _no(e, e.ne(p["ga"], p["gend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))

        def contract():
            g = e.ld(e.add(e.add(p["graphs"], 1), p["i"]))
            e.var("cg", g)
            e.var("buffer", e.alloc(e.add(e.rd(e.sub(_payload(e, p["cg"]), 1)), 1)))  # at most one call per stream word
            _no(e, e.eq(p["buffer"], NONE))
            e.st(e.add(p["callsof"], p["i"]), p["buffer"])
            _no(e, e.ne(e.call(_FN["graph"], p["cg"], e.ld(e.add(e.add(p["table"], 1), p["i"])), p["table"], p["buffer"]), 1))

        e.for_("i", 0, p["count"], contract)
        # ``_canonical_recursion_order``: breadth-first discovery from every start reaches every member.
        _no(e, e.both(e.eq(p["count"], 1), e.eq(e.ld(e.ld(p["callsof"])), 0)))
        e.var("order0", e.alloc(e.add(p["count"], 1)))
        e.var("order", e.alloc(e.add(p["count"], 1)))
        e.var("position", e.alloc(e.add(p["count"], 1)))
        _no(e, e.either(e.eq(p["order0"], NONE), e.eq(p["order"], NONE), e.eq(p["position"], NONE)))

        def discover(start, order):
            e.for_("k", 0, p["count"], lambda: e.st(e.add(p["position"], p["k"]), NONE))
            e.st(order, start)
            e.st(e.add(p["position"], start), 0)
            e.var("found", 1)
            e.var("bk", 0)

            def visit():
                e.var("vb", e.ld(e.add(p["callsof"], e.ld(e.add(order, p["bk"])))))

                def callee():
                    e.var("vc", e.ld(e.add(e.add(p["vb"], 1), e.mul(p["c"], 3))))

                    def add():
                        e.st(e.add(p["position"], p["vc"]), p["found"])
                        e.st(e.add(order, p["found"]), p["vc"])
                        e.set("found", e.add(p["found"], 1))

                    e.if_(e.eq(e.ld(e.add(p["position"], p["vc"])), NONE), add)

                e.for_("c", 0, e.ld(p["vb"]), callee)
                e.set("bk", e.add(p["bk"], 1))

            e.while_(lambda: e.lt(p["bk"], p["found"]), visit)
            _no(e, e.ne(p["found"], p["count"]))

        # The stored order must be the discovery order from member 0 (otherwise its descriptor is not the identity's).
        discover(0, p["order0"])
        e.for_("k", 0, p["count"], lambda: _no(e, e.ne(e.ld(e.add(p["order0"], p["k"])), p["k"])))

        # Erased member graphs (``_recursion_shape``): body bytes without the member-call spans.
        e.var("erased", e.alloc(e.add(p["count"], 1)))
        _no(e, e.eq(p["erased"], NONE))

        def erase():
            stream = _payload(e, e.ld(e.add(e.add(p["graphs"], 1), p["i"])))
            e.var("eb", e.add(stream, e.rd(e.sub(stream, 1))))  # [body length, body bytes]
            e.var("ex", e.alloc(e.add(e.rd(p["eb"]), 1)))
            _no(e, e.eq(p["ex"], NONE))
            e.var("en", 0)
            e.var("epos", 0)

            def copy(stop):
                def byte():
                    e.st(e.add(e.add(p["ex"], 1), p["en"]), e.rd(e.add(e.add(p["eb"], 1), p["cp"])))
                    e.set("en", e.add(p["en"], 1))

                e.for_("cp", p["epos"], stop, byte)

            e.var("espans", e.ld(e.add(p["callsof"], p["i"])))

            def span():
                slot = e.add(e.add(p["espans"], 1), e.mul(p["sp"], 3))
                e.var("sstart", e.ld(e.add(slot, 1)))
                e.var("send", e.ld(e.add(slot, 2)))
                copy(p["sstart"])
                e.set("epos", p["send"])

            e.for_("sp", 0, e.ld(p["espans"]), span)
            copy(e.rd(p["eb"]))
            e.st(p["ex"], p["en"])
            e.st(e.add(p["erased"], p["i"]), p["ex"])

        e.for_("i", 0, p["count"], erase)

        def lexicographic(count_a, count_b, item_a, item_b, cid: bool):
            """Fold one tuple comparison into ``kd`` (0 equal so far, 1 less, 2 greater): items, then lengths."""
            e.var("lx_a", count_a)
            e.var("lx_b", count_b)
            e.var("lx_n", e.sel(e.lt(p["lx_a"], p["lx_b"]), p["lx_a"], p["lx_b"]))

            def element():
                e.var("xa", item_a(p["lx"]))
                e.var("xb", item_b(p["lx"]))
                if cid:
                    _no(e, e.either(e.eq(p["xa"], NONE), e.eq(p["xb"], NONE)))

                    def word():
                        e.var("wa", _cid_word(e, p["xa"], p["w"]))
                        e.var("wb", _cid_word(e, p["xb"], p["w"]))
                        e.if_(e.both(e.eq(p["kd"], 0), e.lt(p["wa"], p["wb"])), lambda: e.set("kd", 1))
                        e.if_(e.both(e.eq(p["kd"], 0), e.lt(p["wb"], p["wa"])), lambda: e.set("kd", 2))

                    e.if_(e.ne(p["xa"], p["xb"]), lambda: e.for_("w", 0, 4, word))  # distinct objects have distinct CIDs
                else:
                    e.if_(e.lt(p["xa"], p["xb"]), lambda: e.set("kd", 1))
                    e.if_(e.lt(p["xb"], p["xa"]), lambda: e.set("kd", 2))

            e.for_("lx", 0, p["lx_n"], lambda: e.if_(e.eq(p["kd"], 0), element))
            e.if_(e.both(e.eq(p["kd"], 0), e.lt(p["lx_a"], p["lx_b"])), lambda: e.set("kd", 1))
            e.if_(e.both(e.eq(p["kd"], 0), e.lt(p["lx_b"], p["lx_a"])), lambda: e.set("kd", 2))

        def key_compare(a, b):
            """``kd`` for member keys ``(graph references, erased graph, parameters, returns)`` of ``a`` and ``b``."""
            e.var("ka", e.ld(e.add(e.add(p["graphs"], 1), a)))
            e.var("kb", e.ld(e.add(e.add(p["graphs"], 1), b)))
            lexicographic(_references(e, p["ka"]), _references(e, p["kb"]), lambda k: _reference(e, p["ka"], k), lambda k: _reference(e, p["kb"], k), True)
            e.var("xea", e.ld(e.add(p["erased"], a)))
            e.var("xeb", e.ld(e.add(p["erased"], b)))
            e.if_(e.eq(p["kd"], 0), lambda: lexicographic(e.ld(p["xea"]), e.ld(p["xeb"]), lambda k: e.ld(e.add(e.add(p["xea"], 1), k)),
                                                          lambda k: e.ld(e.add(e.add(p["xeb"], 1), k)), False))
            e.var("ia", e.ld(e.add(e.add(p["table"], 1), a)))
            e.var("ib", e.ld(e.add(e.add(p["table"], 1), b)))
            e.if_(e.eq(p["kd"], 0), lambda: lexicographic(e.ld(p["ia"]), e.ld(p["ib"]), lambda k: e.ld(e.add(e.add(p["ia"], 1), k)),
                                                          lambda k: e.ld(e.add(e.add(p["ib"], 1), k)), True))
            e.var("ira", e.add(e.add(p["ia"], 1), e.ld(p["ia"])))
            e.var("irb", e.add(e.add(p["ib"], 1), e.ld(p["ib"])))
            e.if_(e.eq(p["kd"], 0), lambda: lexicographic(e.ld(p["ira"]), e.ld(p["irb"]), lambda k: e.ld(e.add(e.add(p["ira"], 1), k)),
                                                          lambda k: e.ld(e.add(e.add(p["irb"], 1), k)), True))

        def start():
            discover(p["s"], p["order"])
            # This start's descriptor must not be below the identity's (member 0's): compare position by position.
            e.var("cmp", 0)

            def position():
                e.var("pa", e.ld(e.add(p["order"], p["k"])))
                e.var("kd", 0)
                e.if_(e.ne(p["pa"], p["k"]), lambda: key_compare(p["pa"], p["k"]))
                e.var("pba", e.ld(e.add(p["callsof"], p["pa"])))
                e.var("pbb", e.ld(e.add(p["callsof"], p["k"])))
                # Then the renumbered callees: this start's positions against the identity's (the member indices).
                e.if_(e.eq(p["kd"], 0), lambda: lexicographic(
                    e.ld(p["pba"]), e.ld(p["pbb"]), lambda c: e.ld(e.add(p["position"], e.ld(e.add(e.add(p["pba"], 1), e.mul(c, 3))))),
                    lambda c: e.ld(e.add(e.add(p["pbb"], 1), e.mul(c, 3))), False))
                _no(e, e.eq(p["kd"], 1))  # a smaller descriptor: the bootstrap rejects the order
                e.if_(e.eq(p["kd"], 2), lambda: e.set("cmp", 1))

            e.for_("k", 0, p["count"], lambda: e.if_(e.eq(p["cmp"], 0), position))

        e.for_("s", 1, p["count"], start)
        e.st(e.add(GRAPHS_AT, o), p["graphs"])
        e.give(1)
    return _function(("o",), build, tables)


X86_64_MACHINES = ((1, 1), (5, 5), (5, 6))  # (abi, image format); 64-bit words and pointers, stack 16, shadow 32
AARCH64_MACHINES = ((3, 1), (5, 6), (5, 7))  # Android and board formats need profiles 4 and 5


def _sorted_list(e: E, name: str, end, low: int, high):
    """A ``[count, values]`` list at ``p[name]`` of strictly increasing values in ``low..high`` (verdict 0 otherwise)."""
    p = e.p
    e.var("sl_count", _read(e, name, end))
    e.var("sl_prev", 0)  # the previous value + 1

    def item():
        e.var("sl_item", _read(e, name, end))
        _no(e, e.either(e.lt(p["sl_item"], low), e.lt(high, p["sl_item"]), e.le(e.add(p["sl_item"], 1), p["sl_prev"])))
        e.set("sl_prev", e.add(p["sl_item"], 1))

    e.for_("sl_q", 0, p["sl_count"], item)


def _target_ok(tables):
    """``decode_native_target(allow_carrier=True)`` for identity-only carriers and profile-1 (general) and
    profile-2 (concurrency: atomics and handler entries) native targets; accelerator, platform, and board profiles
    give 0."""
    from xax_compiler import (
        AtomicFamily, AtomicScope, EffectDomain, JVM_ABI, JVM_ARCHITECTURE, JVM_JAR_FORMAT, RISCV64_ARCHITECTURE, RISCV64_LP64_ABI, RISCV64_RAW_FORMAT, SPIRV_ARCHITECTURE,
        SPIRV_MODULE_FORMAT, SPIRV_VULKAN_ABI, TerminatorKind,
    )

    operations = sorted(int(item) for item in Operation)
    terminators = sorted(int(item) for item in TerminatorKind)
    assert operations == list(range(1, len(operations) + 1)) and terminators == list(range(1, len(terminators) + 1))

    def build(e: E):
        p = e.p
        o = p["o"]
        _no(e, e.ne(_references(e, o), 0))
        e.var("ta", _payload(e, o))
        end = e.add(p["ta"], e.rd(e.sub(p["ta"], 1)))
        e.var("tend", end)
        e.var("ilen", _read(e, "ta", p["tend"]))
        _no(e, e.eq(p["ilen"], 0))
        _no(e, e.lt(e.sub(p["tend"], p["ta"]), p["ilen"]))
        e.set("ta", e.add(p["ta"], p["ilen"]))
        e.if_(e.eq(p["ta"], p["tend"]), lambda: e.give(1))  # an identity-only carrier
        e.var("profile", _read(e, "ta", p["tend"]))
        _no(e, e.both(e.ne(p["profile"], 1), e.ne(p["profile"], 2)))
        for name in ("arch", "abi", "format", "word", "pointer"):
            e.var(name, _read(e, "ta", p["tend"]))
        e.var("stack", 1)
        e.var("shadow", 0)

        def registers(arguments, scratch):
            e.set("stack", _read(e, "ta", p["tend"]))
            e.set("shadow", _read(e, "ta", p["tend"]))
            _no(e, e.ne(_read(e, "ta", p["tend"]), len(arguments)))
            for register in arguments:
                _no(e, e.ne(_read(e, "ta", p["tend"]), register))
            _no(e, e.ne(_read(e, "ta", p["tend"]), 0))  # the result register
            _no(e, e.ne(_read(e, "ta", p["tend"]), len(scratch)))
            for register in scratch:
                _no(e, e.ne(_read(e, "ta", p["tend"]), register))

        e.if_(e.eq(p["arch"], 1), lambda: registers((1, 2, 8, 9), (10, 11)))
        e.if_(e.eq(p["arch"], 3), lambda: registers(tuple(range(8)), (9, 10)))
        _sorted_list(e, "ta", p["tend"], 1, len(operations))  # sorted, unique, known operation codes (1..n)
        _sorted_list(e, "ta", p["tend"], 1, len(terminators))

        def concurrency():
            _sorted_list(e, "ta", p["tend"], 1, NONE)  # atomic widths
            _sorted_list(e, "ta", p["tend"], 1, len(AtomicScope))
            _sorted_list(e, "ta", p["tend"], 1, len(AtomicFamily))
            e.var("handlers", _read(e, "ta", p["tend"]))
            e.var("event", 0)  # the previous event kind + 1

            def handler():
                e.var("kind", _read(e, "ta", p["tend"]))
                _no(e, e.both(e.ne(p["event"], 0), e.le(e.add(p["kind"], 1), p["event"])))  # sorted unique event kinds
                e.set("event", e.add(p["kind"], 1))
                for _field in range(6):
                    _read(e, "ta", p["tend"])
                _sorted_list(e, "ta", p["tend"], 1, len(EffectDomain))
                _no(e, e.eq(_read(e, "ta", p["tend"]), 0))  # stack bound
                _read(e, "ta", p["tend"])

            e.for_("h", 0, p["handlers"], handler)

        e.if_(e.eq(p["profile"], 2), concurrency)
        _no(e, e.ne(p["ta"], p["tend"]))

        def machine(abi, image_format, word, pointer):
            return e.both(e.eq(p["abi"], abi), e.eq(p["format"], image_format), e.eq(p["word"], word), e.eq(p["pointer"], pointer))

        def x86_64():
            _no(e, e.not_(e.either(*(machine(abi, image_format, 64, 64) for abi, image_format in X86_64_MACHINES))))
            _no(e, e.either(e.ne(p["stack"], 16), e.ne(p["shadow"], 32)))

        def aarch64():
            _no(e, e.not_(e.either(*(machine(abi, image_format, 64, 64) for abi, image_format in AARCH64_MACHINES))))
            _no(e, e.both(e.eq(p["abi"], 5), e.ne(p["profile"], 1)))  # aarch64 Linux: profile 1
            _no(e, e.either(e.ne(p["stack"], 16), e.ne(p["shadow"], 0)))

        known = {
            1: x86_64,
            3: aarch64,
            2: lambda: _no(e, e.not_(machine(2, 2, 64, 32))),
            RISCV64_ARCHITECTURE: lambda: _no(e, e.either(e.ne(p["profile"], 1), e.not_(machine(RISCV64_LP64_ABI, RISCV64_RAW_FORMAT, 64, 64)))),
            SPIRV_ARCHITECTURE: lambda: _no(e, e.either(e.ne(p["profile"], 1), e.not_(machine(SPIRV_VULKAN_ABI, SPIRV_MODULE_FORMAT, 32, 32)))),
            JVM_ARCHITECTURE: lambda: _no(e, e.either(e.ne(p["profile"], 1), e.not_(machine(JVM_ABI, JVM_JAR_FORMAT, 64, 64)))),
        }
        e.var("decided", 0)
        for architecture, check in known.items():
            e.if_(e.eq(p["arch"], architecture), lambda check=check: (check(), e.set("decided", 1)))
        _no(e, e.eq(p["decided"], 0))  # architecture 4 needs profile 3; others are unsupported
        e.give(1)
    return _function(("o",), build, tables)


def _list_ok(tables, allowed):
    """``_verify_reference_list``: indices 0..n-1 in order, exact end, children of allowed kinds."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("la", _payload(e, o))
        end = e.add(p["la"], e.rd(e.sub(p["la"], 1)))
        e.var("lend", end)
        count = _read(e, "la", p["lend"])
        e.var("lcount", count)
        _no(e, e.ne(p["lcount"], _references(e, o)))
        e.for_("q", 0, p["lcount"], lambda: _no(e, e.ne(_read(e, "la", p["lend"]), p["q"])))
        _no(e, e.ne(p["la"], p["lend"]))

        def child():
            target = _reference(e, o, p["q"])
            _no(e, e.eq(target, NONE))
            _no(e, e.not_(e.either(*(e.eq(_kind(e, target), int(kind)) for kind in allowed))))

        e.for_("q", 0, p["lcount"], child)
        e.give(1)
    return _function(("o",), build, tables)


def _contract_ok(tables):
    """``_decode_call_contract``: proven input and output types, two canonical booleans, exact use."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("ca", _payload(e, o))
        end = e.add(p["ca"], e.rd(e.sub(p["ca"], 1)))
        e.var("cend", end)
        _clear_marks(e, p["refs"])
        for _part in range(2):
            e.var("ccount", _read(e, "ca", p["cend"]))
            e.for_("q", 0, p["ccount"], lambda: _type_reference(e, o, "ca", p["cend"]))
        for _flag in range(2):
            _no(e, e.le(p["cend"], p["ca"]))
            _no(e, e.lt(1, e.rd(p["ca"])))
            e.set("ca", e.add(p["ca"], 1))
        _no(e, e.ne(p["ca"], p["cend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        e.give(1)
    return _function(("o",), build, tables)


def _program(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.st(1, 0)
        e.set_hd(H_ARENA, ARENA_AT + 16)
        e.set_hd(H_ARENA_END, HEADER - 1)
        O = e.rd(0)
        e.var("O", O)
        e.st(GLOBALS + G_O, p["O"])
        for slot, size in ((G_REC, p["O"]), (G_MARK, 1 << 16)):
            table = e.alloc(e.add(size, 1))
            e.if_(e.eq(table, NONE), lambda: e.give(NONE))
            e.st(GLOBALS + slot, table)
        e.var("ra", 2)

        def record():
            e.st(e.add(_g(e, G_REC), p["o"]), p["ra"])
            references = e.rd(e.add(p["ra"], 1))
            e.if_(e.lt(1 << 16, references), lambda: e.give(NONE))
            payload_at = e.add(e.add(e.add(p["ra"], 2), references), 4)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))
            e.if_(e.eq(_kind(e, p["o"]), int(Kind.GRAPH_FRAGMENT)),
                  lambda: e.set("ra", e.add(e.add(p["ra"], 1), e.rd(p["ra"]))))  # [body length, body bytes]

        e.for_("o", 0, p["O"], record)
        e.if_(e.lt(IN_WORDS, e.add(p["ra"], p["O"])), lambda: e.give(NONE))
        e.st(GLOBALS + G_TYPEOK, p["ra"])  # the proven-type flags follow the records

        # Per-object verdicts: recursion groups first (group member functions need theirs).
        def verdict(groups: bool):
            o = p["o"]
            kind = _kind(e, o)
            e.var("verdict", 0)
            if groups:
                e.if_(e.eq(kind, int(Kind.RECURSION_GROUP)), lambda: e.set("verdict", e.call(_FN["group"], o)))
            else:
                e.if_(e.eq(kind, int(Kind.FUNCTION)), lambda: e.set("verdict", e.call(_FN["function"], o)))
                e.if_(e.eq(kind, int(Kind.MODULE)), lambda: e.set("verdict", e.call(_FN["module"], o)))
                e.if_(e.eq(kind, int(Kind.PROGRAM_ROOT)), lambda: e.set("verdict", e.call(_FN["root"], o)))
                e.if_(e.eq(kind, int(Kind.CALL_CONTRACT)), lambda: e.set("verdict", e.call(_FN["contract"], o)))
                e.if_(e.eq(kind, int(Kind.TARGET)), lambda: e.set("verdict", e.call(_FN["target"], o)))
            this_pass = e.eq(kind, int(Kind.RECURSION_GROUP)) if groups else e.ne(kind, int(Kind.RECURSION_GROUP))
            e.if_(this_pass, lambda: e.st(e.add(VERDICTS_AT, o), e.sel(e.eq(p["verdict"], 1), 1, 0)))

        e.for_("o", 0, p["O"], lambda: verdict(True))
        e.for_("o", 0, p["O"], lambda: verdict(False))
        # The store: everything reachable from the root, no cycle (iterative depth-first search).
        root = e.rd(1)
        e.var("root", root)
        colour = e.alloc(e.add(p["O"], 1))
        stack = e.alloc(e.add(e.mul(p["O"], 2), 2))
        e.var("colour", colour)
        e.var("stack", stack)
        e.if_(e.either(e.eq(p["colour"], NONE), e.eq(p["stack"], NONE), e.le(p["O"], p["root"])), lambda: e.give(1))
        e.for_("o", 0, p["O"], lambda: e.st(e.add(p["colour"], p["o"]), 0))
        e.var("depth", 1)
        e.st(p["stack"], p["root"])
        e.st(e.add(p["stack"], 1), 0)
        e.st(e.add(p["colour"], p["root"]), 1)
        e.var("store_ok", 1)

        def step():
            top = e.add(p["stack"], e.mul(e.sub(p["depth"], 1), 2))
            node, child = e.ld(top), e.ld(e.add(top, 1))
            e.var("sn", node)

            def descend():
                target = _reference(e, p["sn"], child)
                e.st(e.add(top, 1), e.add(child, 1))
                e.var("st", target)

                def visit():
                    state = e.ld(e.add(p["colour"], p["st"]))
                    e.if_(e.eq(state, 1), lambda: e.set("store_ok", 0))

                    def push():
                        e.st(e.add(p["colour"], p["st"]), 1)
                        slot = e.add(p["stack"], e.mul(p["depth"], 2))
                        e.st(slot, p["st"])
                        e.st(e.add(slot, 1), 0)
                        e.set("depth", e.add(p["depth"], 1))

                    e.if_(e.eq(state, 0), push)

                e.if_(e.either(e.eq(p["st"], NONE), e.le(p["O"], p["st"])), lambda: e.set("store_ok", 0), visit)

            def finish():
                e.st(e.add(p["colour"], p["sn"]), 2)
                e.set("depth", e.sub(p["depth"], 1))

            e.if_(e.lt(child, _references(e, p["sn"])), descend, finish)

        e.while_(lambda: e.both(e.ne(p["depth"], 0), e.ne(p["store_ok"], 0)), step)
        e.for_("o", 0, p["O"], lambda: e.if_(e.ne(e.ld(e.add(p["colour"], p["o"])), 2), lambda: e.set("store_ok", 0)))
        e.st(1, p["store_ok"])
        e.st(0, OK)
        e.give(1)
    return _function((), build, tables)


def build_verifier_program():
    tables = None
    objects: list = []

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    add("graph", _graph_ok(tables))
    add("group", _group_ok(tables))
    add("function", _function_ok(tables))
    add("target", _target_ok(tables))
    add("module", _list_ok(tables, MODULE_CHILDREN))
    add("root", _list_ok(tables, (Kind.MODULE,)))
    add("contract", _contract_ok(tables))
    program = add("program", _program(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


def write_verifier_store() -> bytes:
    import xax_compiler

    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True
    try:
        reader, _function = build_verifier_program()
        STORE_PATH.write_bytes(reader.data)
    finally:
        xax_compiler._TYPING_BUILDING = building
    return reader.data


def load_verifier_program():
    from xax_compiler import StoreReader, verify_store

    if not STORE_PATH.exists():
        return build_verifier_program()
    reader = StoreReader(STORE_PATH.read_bytes())
    verify_store(reader)
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def _native_image() -> tuple[bytes, int]:
    import hashlib
    import tempfile

    from xax_x86_64 import compile_native

    sources = Path(__file__).resolve().parent
    digest = hashlib.sha256(STORE_PATH.read_bytes() if STORE_PATH.exists() else b"")
    for name in ("xax_compiler.py", "xax_x86_64.py", "xax_x86_64_regalloc.py"):
        digest.update((sources / name).read_bytes())
    cache = Path(os.environ.get("XAX_NATIVE_CACHE", Path.home() / ".cache" / "xax-native"))
    entry = cache / f"store-verifier-{digest.hexdigest()}.bin"
    try:
        data = entry.read_bytes()
        return data[8:], int.from_bytes(data[:8], "little")
    except OSError:
        pass
    reader, function = load_verifier_program()
    target = next(item for item in reader.objects() if item.kind == Kind.TARGET)
    image = compile_native(reader, function.cid, target.cid)
    try:
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as handle:
            handle.write(image.entry_offset.to_bytes(8, "little") + image.code)
        os.replace(handle.name, entry)
    except OSError:
        pass
    return image.code, image.entry_offset


class NativeStoreVerifier:
    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        code, entry_offset = _native_image()
        thunk = _SYSV_TO_WIN64_THUNK + bytes(-len(_SYSV_TO_WIN64_THUNK) % 16)
        blob = thunk + code
        self._mapping = mmap.mmap(-1, len(blob), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self._mapping.write(blob)
        base = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self._in = (ctypes.c_uint64 * IN_WORDS)()
        self._out = (ctypes.c_uint64 * OUT_WORDS)()
        self._slots = (ctypes.c_uint64 * 4)()
        self._xmm = ctypes.c_uint64()
        self._lock = threading.Lock()

    def verify(self, words: list[int], count: int, groups=()):
        """``(store verdict, per-object verdicts, per-object graph words, {group: member graphs})``, or None when it
        cannot run.  A proven function's graph word is its graph object (NONE for a group member function); a proven
        group's (``groups`` lists their positions) points at ``[count, member graphs]``."""
        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            if out[0] != OK:
                return None
            verdicts, graphs = list(out[VERDICTS_AT : VERDICTS_AT + count]), list(out[GRAPHS_AT : GRAPHS_AT + count])
            members = {o: tuple(out[graphs[o] + 1 : graphs[o] + 1 + out[graphs[o]]]) for o in groups if verdicts[o] == 1}
            return out[1] == 1, verdicts, graphs, members


def object_table(objects, head: list[int]) -> list[int] | None:
    """The S5b object table (``head`` first): kind, reference indices, CID, payload (graph-decoder stream for
    graphs, body bytes otherwise); None when a graph body cannot be streamed."""
    from xax_compiler import _native_graph_decoder

    decoder = _native_graph_decoder()
    if decoder is None:
        return None
    index = {obj.cid: position for position, obj in enumerate(objects)}
    words = [len(objects), *head]
    for obj in objects:
        words += [int(obj.kind), len(obj.references), *(index.get(cid, NONE) for cid in obj.references)]
        words += [int.from_bytes(obj.cid[offset:offset + 8], "big") for offset in range(0, 32, 8)]
        if obj.kind == Kind.GRAPH_FRAGMENT:
            if len(obj.body) > decoder.capacity:
                return None
            status, stream = decoder.decode(obj.body, len(obj.references))
            if status != 0:
                return None
            payload = list(stream)
            words += [len(payload), *payload, len(obj.body), *obj.body]  # the body bytes (recursion-group keys)
            continue
        elif obj.kind in (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.CALL_CONTRACT, Kind.RECURSION_GROUP):
            payload = list(obj.body)
        else:
            payload = []
        words += [len(payload), *payload]
    return words


_NATIVE: list = []
_BUILDING: list = []


def native_store_verifier():
    """The shared native store verifier, or None where it cannot run (or while it is being loaded: its own
    store is verified by the bootstrap)."""
    if _BUILDING:
        return None
    if not _NATIVE:
        usable = (sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
                  and os.environ.get("XAX_VERIFY_PYTHON") != "1" and STORE_PATH.exists())
        _BUILDING.append(True)
        try:
            _NATIVE.append(NativeStoreVerifier() if usable else None)
        except (OSError, RuntimeError, ValueError):
            _NATIVE.append(None)
        finally:
            _BUILDING.clear()
    return _NATIVE[0]
