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
* targets (``decode_native_target``): identity-only carriers, the general,
  concurrency, and platform profiles of every supported architecture, the
  accelerator profile, and the AArch64 board profile (S6b.4c);
* packages and build objects (S6b.4a/b): packages, profiles, trust
  policies, signatures, optimization policies, then requests, snapshots, and
  provenance, each later pass reading the earlier verdicts;
* every graph fragment's per-graph glue (S6b.4d): type references naming
  proven types, resolved entities, exact reference use, canonical trap
  payloads;
* module and program-root reference lists (``_verify_reference_list``);
* call contracts (``_decode_call_contract``);
* the store: every object reachable from the root, no reference cycle.

Its output is a verdict per object (each proven function's graph object, each
proven group's member graphs) and a store verdict.  A verdict holds only when
the bootstrap accepts; every other object, and every rejection, takes the
bootstrap path and its exact diagnostic.
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

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_store_verifier.xax"
VERDICTS_AT, GRAPHS_AT, ARENA_AT = 1 << 20, 6 << 20, 12 << 20
REJECTS_AT, REJECT_WORDS = 3 << 20, 4  # S8c.19 (ADR-237): a rejected object's record: site, three payload words
OK = 1
REJECTED = 2  # an object verdict: the bootstrap rejects this object with the recorded diagnostic
ENTITY_CODES = (5, 6, 30, 41, 42, 43)
ATTRIBUTE_CODES = (7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 52, 53, 55, 56, 57,
                   61, 63, 64, 65, 66, 73, 74, 75, 76)
MODULE_CHILDREN = (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT)
# Globals (the first arena words): table pointers.
GLOBALS = ARENA_AT
G_REC, G_O, G_TYPEOK, G_MARK, G_LIST = range(5)  # G_LIST: a graph contract mismatch's quoted types (S8c.20)
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


# S8c.19 (ADR-237): object rejections the bootstrap's ``verify_object`` raises, in its order, once the object's own
# references all resolve (its OBJECT_MISSING checks come first).
OBJECT_SITES = ("LIST_TRAILING", "LIST_REF_INDEX", "LIST_REFERENCE_BODY", "LIST_CHILD_KIND",
                "CONTRACT_REF_INDEX", "CONTRACT_TRUNCATED", "CONTRACT_BOOL", "CONTRACT_TRAILING", "CONTRACT_UNUSED",
                # S8c.20 (ADR-238): functions.  The last three come after the bootstrap parses the graph (payload word 0:
                # the graph object), so the host parses it first.
                "FUNCTION_REF_INDEX", "FUNCTION_MEMBER_TRAILING", "FUNCTION_MEMBER_RANGE", "FUNCTION_CARRIER", "FUNCTION_TRAILING",
                "FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT", "FUNCTION_UNUSED",
                # S8c.21 (ADR-239): recursion-group member lists (``_decode_recursion_group``, before any member parses).
                "GROUP_EMPTY", "GROUP_REF_INDEX", "GROUP_CARRIER", "GROUP_TRAILING", "GROUP_UNUSED",
                # S8c.22 (ADR-240): after member graphs parse (payload: graphs to parse first, quoted list, [count, graphs]).
                "GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT", "GROUP_MEMBER_RANGE", "GROUP_CALL_CONTRACT", "GROUP_SCC",
                # S8c.23 (ADR-241): targets (``decode_native_target``).
                "TARGET_REFERENCES", "TARGET_IDENTITY_TRUNCATED", "TARGET_IDENTITY_EMPTY", "TARGET_ARCHITECTURE", "TARGET_TRAILING",
                "TARGET_PROFILE", "TARGET_X86_64", "TARGET_RISCV64", "TARGET_SPIRV", "TARGET_JVM", "TARGET_WASM32", "TARGET_AARCH64",
                "TARGET_ANDROID", "TARGET_AARCH64_LINUX", "TARGET_BAREMETAL", "TARGET_BOARD", "TARGET_ACCELERATOR")
AFTER_PARSE = ("FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT", "FUNCTION_UNUSED")
GROUP_AFTER_PARSE = ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT", "GROUP_MEMBER_RANGE", "GROUP_CALL_CONTRACT", "GROUP_SCC")
S = {name: index + 1 for index, name in enumerate(OBJECT_SITES)}


def _reject(e: E, condition, obj, site: int, *payload):
    """Verdict REJECTED (with the record) when ``condition`` (None: unconditionally)."""
    def record():
        at = e.add(REJECTS_AT, e.mul(obj, REJECT_WORDS))
        e.st(at, site)
        for index, word in enumerate(payload):
            e.st(e.add(at, index + 1), word)
        e.give(REJECTED)

    if condition is None:
        record()
    else:
        e.if_(condition, record)


def _resolved(e: E, obj):
    """1 when every reference of ``obj`` names a stored object."""
    p = e.p
    e.var("resolved", 1)
    e.for_("rq", 0, _references(e, obj), lambda: e.if_(e.eq(_reference(e, obj, p["rq"]), NONE), lambda: e.set("resolved", 0)))
    return p["resolved"]


def _list_copy(e: E, count, word):
    """``[count, word(0) .. word(count - 1)]`` in the arena (a rejection quotes it); NONE when it cannot."""
    p = e.p
    e.var("copy", e.alloc(e.add(count, 1)))
    e.if_(e.ne(p["copy"], NONE), lambda: (e.st(p["copy"], count), e.for_("cq", 0, count, lambda: e.st(e.add(p["copy"], e.add(p["cq"], 1)), word(p["cq"])))))
    return p["copy"]


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


def _type_reference(e: E, obj, name: str, end, reject_site=None):
    """A reference index read at ``p[name]`` naming a proven type; marks it and returns the object.

    ``reject_site``: an index out of range is that rejection (``GRAPH-REF-INDEX``) instead of a decline."""
    p = e.p
    index = _read(e, name, end)
    e.var(f"{name}_index", index)
    if reject_site is not None:
        _reject(e, e.le(_references(e, obj), p[f"{name}_index"]), obj, reject_site, _references(e, obj), p[f"{name}_index"])
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


def _interface(e: E, obj, name: str, end, reject_site=None):
    """Parameter and return types read at ``p[name]`` into a new ``[P, types, R, types]`` record."""
    p = e.p
    e.var(f"{name}_if", e.alloc(e.add(e.sub(end, p[name]), 3)))  # at most one type per body byte
    _no(e, e.eq(p[f"{name}_if"], NONE))
    record = p[f"{name}_if"]
    e.var(f"{name}_np", _read(e, name, end))
    e.st(record, p[f"{name}_np"])
    e.for_("q", 0, p[f"{name}_np"], lambda: e.st(e.add(e.add(p[f"{name}_if"], 1), p["q"]), _type_reference(e, obj, name, end, reject_site)))
    e.var(f"{name}_rt", e.add(e.add(p[f"{name}_if"], 1), p[f"{name}_np"]))
    e.st(p[f"{name}_rt"], _read(e, name, end))
    e.for_("q", 0, e.ld(p[f"{name}_rt"]), lambda: e.st(e.add(e.add(p[f"{name}_rt"], 1), p["q"]), _type_reference(e, obj, name, end, reject_site)))
    return p[f"{name}_if"]


def _function_ok(tables):
    """``_verify_function``: 1 (and the graph object, or NONE for a group member function, in GRAPHS) or 0."""
    def build(e: E):
        p = e.p
        f = p["f"]
        _no(e, e.eq(_resolved(e, f), 0))
        references = _references(e, f)
        e.var("refs", references)
        e.var("fa", _payload(e, f))
        end = e.add(p["fa"], e.rd(e.sub(p["fa"], 1)))
        e.var("fend", end)
        _clear_marks(e, p["refs"])
        graph_index = _read(e, "fa", p["fend"])
        e.var("gi", graph_index)
        _reject(e, e.le(p["refs"], p["gi"]), f, S["FUNCTION_REF_INDEX"], p["refs"], p["gi"])
        e.var("graph", _reference(e, f, p["gi"]))
        _no(e, e.eq(p["graph"], NONE))

        def member_function():
            # ``decode_group_member_function``: [group, member], the group proven (S6b.3), member < its size.
            e.var("member", _read(e, "fa", p["fend"]))
            _reject(e, e.ne(p["fa"], p["fend"]), f, S["FUNCTION_MEMBER_TRAILING"], e.sub(p["fend"], p["fa"]))
            _no(e, e.ne(e.ld(e.add(VERDICTS_AT, p["graph"])), 1))
            size = e.ld(e.ld(e.add(GRAPHS_AT, p["graph"])))
            _reject(e, e.le(size, p["member"]), f, S["FUNCTION_MEMBER_RANGE"], size, p["member"])
            e.st(e.add(GRAPHS_AT, f), NONE)
            e.give(1)

        e.if_(e.both(e.eq(p["refs"], 1), e.eq(_kind(e, p["graph"]), int(Kind.RECURSION_GROUP))), member_function)
        _no(e, e.eq(_kind(e, p["graph"]), int(Kind.RECURSION_GROUP)))
        _reject(e, e.ne(_kind(e, p["graph"]), int(Kind.GRAPH_FRAGMENT)), f, S["FUNCTION_CARRIER"], _kind(e, p["graph"]))
        _mark(e, p["gi"])
        e.var("iface", _interface(e, f, "fa", p["fend"], S["FUNCTION_REF_INDEX"]))
        _reject(e, e.ne(p["fa"], p["fend"]), f, S["FUNCTION_TRAILING"], e.sub(p["fend"], p["fa"]))
        # After the bootstrap's graph parse: the graph contract, then the references used.
        e.var("contract", e.call(_FN["graph"], p["graph"], p["iface"], NONE, NONE))
        _reject(e, e.eq(p["contract"], 3), f, S["FUNCTION_ENTRY_CONTRACT"], p["graph"], _g(e, G_LIST))
        _reject(e, e.eq(p["contract"], 4), f, S["FUNCTION_RETURN_CONTRACT"], p["graph"], _g(e, G_LIST))
        _no(e, e.ne(p["contract"], 1))
        _reject(e, e.eq(_all_marked(e, p["refs"]), 0), f, S["FUNCTION_UNUSED"], p["graph"], _list_copy(e, p["refs"], lambda k: e.ld(e.add(_g(e, G_MARK), k))))
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
        # Entry parameters: exactly the interface's parameter types (3, with [P, interface types, E, entry types] in
        # G_LIST, when they differ).
        entry_at = e.ld(e.add(p["blocks"], p["entry"]))
        e.var("entry_n", e.rd(entry_at))
        e.var("entry_ok", e.flag(e.eq(p["entry_n"], p["np"])))
        e.for_("q", 0, p["entry_n"], lambda: e.if_(e.both(e.lt(p["q"], p["np"]), e.ne(_reference(e, g, e.rd(e.add(e.add(entry_at, 1), p["q"]))), e.ld(e.add(p["lists"], p["q"])))),
                                                  lambda: e.set("entry_ok", 0)))

        def entry_mismatch():
            quoted = e.alloc(e.add(e.add(p["np"], p["entry_n"]), 2))
            e.var("quoted", quoted)
            _no(e, e.eq(p["quoted"], NONE))
            e.st(p["quoted"], p["np"])
            e.for_("q", 0, p["np"], lambda: e.st(e.add(e.add(p["quoted"], 1), p["q"]), e.ld(e.add(p["lists"], p["q"]))))
            e.st(e.add(e.add(p["quoted"], 1), p["np"]), p["entry_n"])
            e.for_("q", 0, p["entry_n"], lambda: e.st(e.add(e.add(e.add(p["quoted"], 2), p["np"]), p["q"]), _reference(e, g, e.rd(e.add(e.add(entry_at, 1), p["q"])))))
            e.st(GLOBALS + G_LIST, p["quoted"])
            e.give(3)

        e.if_(e.eq(p["entry_ok"], 0), entry_mismatch)

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
                # 4, with [R, interface types, K, returned types] in G_LIST, when a return's types differ.
                e.set("ra", e.add(p["ra"], 1))
                e.var("rk", e.rd(p["ra"]))
                e.set("ra", e.add(p["ra"], 1))
                e.var("rquoted", e.alloc(e.add(e.add(p["nr"], p["rk"]), 2)))
                _no(e, e.eq(p["rquoted"], NONE))
                e.st(p["rquoted"], p["nr"])
                e.for_("q", 0, p["nr"], lambda: e.st(e.add(e.add(p["rquoted"], 1), p["q"]), e.ld(e.add(p["returns"], p["q"]))))
                e.st(e.add(e.add(p["rquoted"], 1), p["nr"]), p["rk"])
                e.var("rsame", e.flag(e.eq(p["rk"], p["nr"])))

                def each_returned():
                    e.var("rt_type", value_type("ra"))
                    e.st(e.add(e.add(e.add(p["rquoted"], 2), p["nr"]), p["q"]), p["rt_type"])
                    e.if_(e.either(e.le(p["nr"], p["q"]), e.ne(p["rt_type"], e.ld(e.add(p["returns"], e.sel(e.lt(p["q"], p["nr"]), p["q"], 0))))),
                          lambda: e.set("rsame", 0))

                e.for_("q", 0, p["rk"], each_returned)
                e.if_(e.eq(p["rsame"], 0), lambda: (e.st(GLOBALS + G_LIST, p["rquoted"]), e.give(4)))

            e.if_(e.eq(e.rd(p["ra"]), int(TerminatorKind.RETURN)), returning)

        e.for_("b", 0, p["B"], returns_of)

        def member_calls():
            # ``_verify_recursion_group``: a member index in range, the member's parameter and result types.
            e.var("mc", 0)

            def check():
                at = e.ld(e.add(p["node_at"], p["nn"]))
                e.var("mc_at", at)

                def group_call():
                    # 5 (G_LIST: the member) for a member out of range; 6 (G_LIST: [P, parameters, R, returns, A, operand types,
                    # K, result types]) for a call whose types differ from the member's interface.
                    e.var("gm", e.rd(e.add(p["mc_at"], 1)))
                    e.if_(e.le(e.ld(p["members"]), p["gm"]), lambda: (e.st(GLOBALS + G_LIST, p["gm"]), e.give(5)))
                    e.var("gm_if", e.ld(e.add(e.add(p["members"], 1), p["gm"])))
                    e.var("gm_np", e.ld(p["gm_if"]))
                    e.var("gm_rt", e.add(e.add(p["gm_if"], 1), p["gm_np"]))
                    e.var("gm_results", e.ld(e.add(p["results_at"], p["nn"])))
                    e.var("ma", e.add(p["mc_at"], 4))
                    e.var("gm_na", e.rd(p["ma"]))
                    e.set("ma", e.add(p["ma"], 1))
                    e.var("gm_nk", e.rd(p["gm_results"]))
                    e.var("gm_nr", e.ld(p["gm_rt"]))
                    e.var("cq", e.alloc(e.add(e.add(e.add(p["gm_np"], p["gm_nr"]), e.add(p["gm_na"], p["gm_nk"])), 4)))
                    _no(e, e.eq(p["cq"], NONE))
                    e.var("cw", p["cq"])

                    def put(word):
                        e.st(p["cw"], word)
                        e.set("cw", e.add(p["cw"], 1))

                    put(p["gm_np"])
                    e.for_("q", 0, p["gm_np"], lambda: put(e.ld(e.add(e.add(p["gm_if"], 1), p["q"]))))
                    put(p["gm_nr"])
                    e.for_("q", 0, p["gm_nr"], lambda: put(e.ld(e.add(e.add(p["gm_rt"], 1), p["q"]))))
                    put(p["gm_na"])
                    e.var("gm_same", e.flag(e.both(e.eq(p["gm_na"], p["gm_np"]), e.eq(p["gm_nk"], p["gm_nr"]))))

                    def operand():
                        e.var("gm_t", value_type("ma"))
                        put(p["gm_t"])
                        e.if_(e.either(e.le(p["gm_np"], p["q"]), e.ne(p["gm_t"], e.ld(e.add(e.add(p["gm_if"], 1), e.sel(e.lt(p["q"], p["gm_np"]), p["q"], 0))))),
                              lambda: e.set("gm_same", 0))

                    e.for_("q", 0, p["gm_na"], operand)
                    put(p["gm_nk"])

                    def result():
                        e.var("gm_r", _reference(e, g, e.rd(e.add(e.add(p["gm_results"], 1), p["q"]))))
                        put(p["gm_r"])
                        e.if_(e.either(e.le(p["gm_nr"], p["q"]), e.ne(p["gm_r"], e.ld(e.add(e.add(p["gm_rt"], 1), e.sel(e.lt(p["q"], p["gm_nr"]), p["q"], 0))))),
                              lambda: e.set("gm_same", 0))

                    e.for_("q", 0, p["gm_nk"], result)
                    e.if_(e.eq(p["gm_same"], 0), lambda: (e.st(GLOBALS + G_LIST, p["cq"]), e.give(6)))
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
        _no(e, e.eq(_resolved(e, o), 0))
        e.var("count", _read(e, "ga", p["gend"]))
        _reject(e, e.eq(p["count"], 0), o, S["GROUP_EMPTY"])
        e.var("table", e.alloc(e.add(p["count"], 1)))  # [count, interface records]
        e.var("graphs", e.alloc(e.add(p["count"], 1)))  # [count, graph objects]
        e.var("callsof", e.alloc(e.add(p["count"], 1)))
        _no(e, e.either(e.eq(p["table"], NONE), e.eq(p["graphs"], NONE), e.eq(p["callsof"], NONE)))
        e.st(p["table"], p["count"])
        e.st(p["graphs"], p["count"])

        def member():
            e.var("gi", _read(e, "ga", p["gend"]))
            _reject(e, e.le(p["refs"], p["gi"]), o, S["GROUP_REF_INDEX"], p["refs"], p["gi"])
            e.var("mg", _reference(e, o, p["gi"]))
            _no(e, e.eq(p["mg"], NONE))
            _reject(e, e.ne(_kind(e, p["mg"]), int(Kind.GRAPH_FRAGMENT)), o, S["GROUP_CARRIER"], _kind(e, p["mg"]))
            _mark(e, p["gi"])
            e.st(e.add(e.add(p["graphs"], 1), p["i"]), p["mg"])
            e.st(e.add(e.add(p["table"], 1), p["i"]), _interface(e, o, "ga", p["gend"], S["GROUP_REF_INDEX"]))

        e.for_("i", 0, p["count"], member)
        _reject(e, e.ne(p["ga"], p["gend"]), o, S["GROUP_TRAILING"], e.sub(p["gend"], p["ga"]))
        _reject(e, e.eq(_all_marked(e, p["refs"]), 0), o, S["GROUP_UNUSED"], _list_copy(e, p["refs"], lambda k: e.ld(e.add(_g(e, G_MARK), k))))

        def contract():
            g = e.ld(e.add(e.add(p["graphs"], 1), p["i"]))
            e.var("cg", g)
            e.var("buffer", e.alloc(e.add(e.rd(e.sub(_payload(e, p["cg"]), 1)), 1)))  # at most one call per stream word
            _no(e, e.eq(p["buffer"], NONE))
            e.st(e.add(p["callsof"], p["i"]), p["buffer"])
            e.var("gcode", e.call(_FN["graph"], p["cg"], e.ld(e.add(e.add(p["table"], 1), p["i"])), p["table"], p["buffer"]))
            parsed = e.add(p["i"], 1)  # the bootstrap parses member graphs one by one, checking each before the next
            for code, site in ((3, "GROUP_ENTRY_CONTRACT"), (4, "GROUP_RETURN_CONTRACT"), (5, "GROUP_MEMBER_RANGE"), (6, "GROUP_CALL_CONTRACT")):
                _reject(e, e.eq(p["gcode"], code), o, S[site], parsed, _g(e, G_LIST), p["graphs"])
            _no(e, e.ne(p["gcode"], 1))

        e.for_("i", 0, p["count"], contract)

        def scc():
            """``GRAPH-RECURSION-SCC`` quoting every member's callees: ``[count, (n, callees) per member]``."""
            e.var("sccq", e.alloc(e.add(e.rd(e.sub(_payload(e, o), 1)), e.add(e.mul(p["count"], 2), 2))))
            _no(e, e.eq(p["sccq"], NONE))
            e.st(p["sccq"], p["count"])
            e.var("sw", e.add(p["sccq"], 1))

            def member_calls(member):
                calls = e.ld(e.add(p["callsof"], member))
                e.st(p["sw"], e.ld(calls))
                e.set("sw", e.add(p["sw"], 1))
                e.for_("sc", 0, e.ld(calls), lambda: (e.st(p["sw"], e.ld(e.add(e.add(calls, 1), e.mul(p["sc"], 3)))), e.set("sw", e.add(p["sw"], 1))))

            e.for_("sm", 0, p["count"], lambda: member_calls(p["sm"]))
            _reject(e, None, o, S["GROUP_SCC"], p["count"], p["sccq"], p["graphs"])
        # ``_canonical_recursion_order``: breadth-first discovery from every start reaches every member.
        e.if_(e.both(e.eq(p["count"], 1), e.eq(e.ld(e.ld(p["callsof"])), 0)), scc)
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
            e.if_(e.ne(p["found"], p["count"]), scc)  # some start reaches only part of the group

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
    """``decode_native_target(allow_carrier=True)``: identity-only carriers; general (1), concurrency (2), and
    platform (4) targets of every supported architecture; accelerator (3) targets of the accelerator
    architecture; and AArch64 board (5) targets.  An accelerator profile on another architecture gives 0."""
    from xax_compiler import (
        AARCH64_BOARD_ELF_FORMAT, ANDROID_ELF_FORMAT, ANDROID_ELF_PACKED_FORMAT, AtomicFamily, AtomicScope, BOARD_PROFILE, EffectDomain, JVM_ABI,
        JVM_ARCHITECTURE, JVM_JAR_FORMAT, RISCV64_ARCHITECTURE, RISCV64_LP64_ABI, RISCV64_RAW_FORMAT, SPIRV_ARCHITECTURE, SPIRV_MODULE_FORMAT,
        SPIRV_VULKAN_ABI, TargetValueConstraintKind, TerminatorKind,
    )

    operations = sorted(int(item) for item in Operation)
    terminators = sorted(int(item) for item in TerminatorKind)
    assert operations == list(range(1, len(operations) + 1)) and terminators == list(range(1, len(terminators) + 1))
    scopes, domains, constraint_kinds = len(AtomicScope), len(EffectDomain), len(TargetValueConstraintKind)
    assert [int(item) for item in AtomicScope] == list(range(1, scopes + 1)) and [int(item) for item in EffectDomain] == list(range(1, domains + 1))

    known_architectures = (1, 2, 3, 4, JVM_ARCHITECTURE, RISCV64_ARCHITECTURE, SPIRV_ARCHITECTURE)

    def build(e: E):
        p = e.p
        o = p["o"]
        _no(e, e.eq(_resolved(e, o), 0))
        _reject(e, e.ne(_references(e, o), 0), o, S["TARGET_REFERENCES"])
        e.var("ta", _payload(e, o))
        end = e.add(p["ta"], e.rd(e.sub(p["ta"], 1)))
        e.var("tend", end)
        e.var("ilen", _read(e, "ta", p["tend"]))
        _reject(e, e.lt(e.sub(p["tend"], p["ta"]), p["ilen"]), o, S["TARGET_IDENTITY_TRUNCATED"], p["ilen"], e.sub(p["tend"], p["ta"]))
        _reject(e, e.eq(p["ilen"], 0), o, S["TARGET_IDENTITY_EMPTY"])
        e.set("ta", e.add(p["ta"], p["ilen"]))
        e.if_(e.eq(p["ta"], p["tend"]), lambda: e.give(1))  # an identity-only carrier
        e.var("profile", _read(e, "ta", p["tend"]))
        for name in ("arch", "abi", "format", "word", "pointer"):
            e.var(name, _read(e, "ta", p["tend"]))
        _reject(e, e.not_(e.either(*(e.eq(p["arch"], code) for code in known_architectures))), o, S["TARGET_ARCHITECTURE"], p["arch"])
        _no(e, e.both(e.eq(p["profile"], 3), e.ne(p["arch"], 4)))  # accelerator fields elsewhere: left to the bootstrap
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
            _sorted_list(e, "ta", p["tend"], 1, scopes)
            _sorted_list(e, "ta", p["tend"], 1, len(AtomicFamily))
            e.var("handlers", _read(e, "ta", p["tend"]))
            e.var("event", 0)  # the previous event kind + 1

            def handler():
                e.var("kind", _read(e, "ta", p["tend"]))
                _no(e, e.both(e.ne(p["event"], 0), e.le(e.add(p["kind"], 1), p["event"])))  # sorted unique event kinds
                e.set("event", e.add(p["kind"], 1))
                for _field in range(6):
                    _read(e, "ta", p["tend"])
                _sorted_list(e, "ta", p["tend"], 1, domains)
                _no(e, e.eq(_read(e, "ta", p["tend"]), 0))  # stack bound
                _read(e, "ta", p["tend"])

            e.for_("h", 0, p["handlers"], handler)

        def flag_byte():
            _no(e, e.le(p["tend"], p["ta"]))
            _no(e, e.lt(1, e.rd(p["ta"])))
            e.set("ta", e.add(p["ta"], 1))

        def contracts(strict: bool, accelerator: bool):
            """Target-operation contracts; ``strict`` adds the platform or accelerator canonical rules."""
            e.var("ccount", _read(e, "ta", p["tend"]))
            if strict:
                _no(e, e.eq(p["ccount"], 0))
            e.var("cprev", 0)

            def contract():
                e.var("cid_", _read(e, "ta", p["tend"]))
                if strict:
                    _no(e, e.le(e.add(p["cid_"], 1), p["cprev"]))
                    e.set("cprev", e.add(p["cid_"], 1))
                e.var("csem", _read(e, "ta", p["tend"]))
                e.var("cenc", _read(e, "ta", p["tend"]))
                if strict:
                    _no(e, e.eq(p["csem"], 0))
                if strict and accelerator:
                    _no(e, e.lt(255, p["cenc"]))
                for _signature in range(2):
                    e.var("vcount", _read(e, "ta", p["tend"]))

                    def constraint():
                        e.var("vk", _read(e, "ta", p["tend"]))
                        e.var("vp", _read(e, "ta", p["tend"]))
                        e.var("vs", _read(e, "ta", p["tend"]))
                        _no(e, e.either(e.lt(p["vk"], 1), e.lt(constraint_kinds, p["vk"])))
                        if strict:
                            bad = e.either(
                                e.both(e.eq(p["vk"], 1), e.either(e.eq(p["vp"], 0), e.ne(p["vs"], 0))),
                                e.both(e.eq(p["vk"], 2), e.either(e.eq(p["vp"], 0), e.eq(p["vs"], 0))),
                                e.both(e.eq(p["vk"], 3), e.either(e.eq(p["vp"], 0), e.lt(domains, p["vp"]))),
                                e.both(e.lt(3, p["vk"]), e.either(e.ne(p["vp"], 0), e.ne(p["vs"], 0))),
                            )
                            _no(e, bad)

                    e.for_("vq", 0, p["vcount"], constraint)
                if strict:
                    _no(e, e.eq(e.rd(p["ta"]), 0))  # nonempty scopes
                    e.var("csl", p["ta"])
                    _sorted_list(e, "ta", p["tend"], 1, scopes)
                    if accelerator:
                        # A subset of the accelerator's scopes.
                        e.var("cn", _read(e, "csl", p["tend"]))
                        e.for_("cq", 0, p["cn"], lambda: _no(e, e.eq(e.and_(p["accmask"], e.sel(e.eq(_read(e, "csl", p["tend"]), 1), 1, e.sel(e.eq(p["csl_value"], 2), 2, 4))), 0)))
                else:
                    e.var("sc2", _read(e, "ta", p["tend"]))
                    e.for_("sq2", 0, p["sc2"], lambda: _no(e, e.either(e.lt(_read(e, "ta", p["tend"]), 1), e.lt(scopes, p["ta_value"]))))
                e.var("csrc", _read(e, "ta", p["tend"]))
                e.var("cdst", _read(e, "ta", p["tend"]))
                if strict and accelerator:
                    for name in ("csrc", "cdst"):
                        e.var("member", 0)
                        e.for_("mq", 0, p["spaces"], lambda name=name: e.if_(e.eq(e.ld(e.add(p["space_ids"], p["mq"])), p[name]), lambda: e.set("member", 1)))
                        _no(e, e.eq(p["member"], 0))
                flag_byte()
                flag_byte()
                _start, length = _string(e, "ta", p["tend"])
                if strict:
                    _no(e, e.both(e.ne(length, 0), e.ne(length, 32)))

            e.for_("cq_", 0, p["ccount"], contract)

        def accelerator():
            for name in ("lane", "groups"):
                e.var(name, _read(e, "ta", p["tend"]))
                _no(e, e.eq(p[name], 0))
            # Accelerator scopes: strictly increasing, nonempty; their bit mask for the contract subset rule.
            _no(e, e.eq(e.rd(p["ta"]), 0))
            e.var("asl", p["ta"])
            _sorted_list(e, "ta", p["tend"], 1, scopes)
            e.var("accmask", 0)
            e.var("an", _read(e, "asl", p["tend"]))
            e.for_("aq", 0, p["an"], lambda: e.set("accmask", e.or_(p["accmask"], e.sel(e.eq(_read(e, "asl", p["tend"]), 1), 1, e.sel(e.eq(p["asl_value"], 2), 2, 4)))))
            e.var("spaces", _read(e, "ta", p["tend"]))
            _no(e, e.eq(p["spaces"], 0))
            e.var("space_ids", e.alloc(e.add(p["spaces"], 1)))
            _no(e, e.eq(p["space_ids"], NONE))
            e.var("sprev", 0)

            def space():
                e.var("sid", _read(e, "ta", p["tend"]))
                _no(e, e.le(e.add(p["sid"], 1), p["sprev"]))
                e.set("sprev", e.add(p["sid"], 1))
                e.st(e.add(p["space_ids"], p["spq"]), p["sid"])
                for name in ("abits", "ubits", "align"):
                    e.var(name, _read(e, "ta", p["tend"]))
                    _no(e, e.eq(p[name], 0))
                _no(e, e.not_(e.power_of_two(p["align"])))
                _sorted_list(e, "ta", p["tend"], 1, NONE)  # access widths
                _sorted_list(e, "ta", p["tend"], 1, scopes)  # visibility scopes
                flag_byte()
                flag_byte()

            e.for_("spq", 0, p["spaces"], space)
            contracts(True, True)

        e.if_(e.either(e.eq(p["profile"], 2), e.eq(p["profile"], BOARD_PROFILE)), concurrency)
        e.if_(e.eq(p["profile"], 3), accelerator)
        e.if_(e.eq(p["profile"], 4), lambda: contracts(True, False))
        e.if_(e.eq(p["profile"], BOARD_PROFILE), lambda: contracts(False, False))
        _reject(e, e.ne(p["ta"], p["tend"]), o, S["TARGET_TRAILING"], e.sub(p["tend"], p["ta"]))
        _reject(e, e.either(e.lt(p["profile"], 1), e.lt(BOARD_PROFILE, p["profile"])), o, S["TARGET_PROFILE"], p["profile"])

        def machine(abi, image_format, word, pointer):
            return e.both(e.eq(p["abi"], abi), e.eq(p["format"], image_format), e.eq(p["word"], word), e.eq(p["pointer"], pointer))

        def fields(site):
            """Reject at ``site`` quoting the machine record (profile, abi, format, word, pointer, stack, shadow)."""
            def record():
                e.var("mq", e.alloc(8))
                _no(e, e.eq(p["mq"], NONE))
                for k, name in enumerate(("profile", "abi", "format", "word", "pointer", "stack", "shadow")):
                    e.st(e.add(p["mq"], k), p[name])
                _reject(e, None, o, S[site], p["mq"])
            return record

        def x86_64():
            allowed = e.either(*(machine(abi, image_format, 64, 64) for abi, image_format in X86_64_MACHINES))
            e.if_(e.not_(e.both(allowed, e.eq(p["stack"], 16), e.eq(p["shadow"], 32))), fields("TARGET_X86_64"))

        def aarch64():
            machines = (*AARCH64_MACHINES, (4, ANDROID_ELF_FORMAT), (4, ANDROID_ELF_PACKED_FORMAT), (3, AARCH64_BOARD_ELF_FORMAT))
            allowed = e.either(*(machine(abi, image_format, 64, 64) for abi, image_format in machines))
            e.if_(e.not_(e.both(allowed, e.eq(p["stack"], 16), e.eq(p["shadow"], 0))), fields("TARGET_AARCH64"))
            e.if_(e.both(e.eq(p["abi"], 4), e.ne(p["profile"], 4)), fields("TARGET_ANDROID"))  # Android: profile 4
            e.if_(e.both(e.eq(p["abi"], 5), e.ne(p["profile"], 1)), fields("TARGET_AARCH64_LINUX"))  # aarch64 Linux: profile 1
            e.if_(e.both(e.eq(p["abi"], 3), e.ne(p["profile"], 1), e.ne(p["profile"], 2), e.ne(p["profile"], BOARD_PROFILE)), fields("TARGET_BAREMETAL"))
            e.if_(e.ne(e.flag(e.eq(p["format"], AARCH64_BOARD_ELF_FORMAT)), e.flag(e.eq(p["profile"], BOARD_PROFILE))), fields("TARGET_BOARD"))

        def five(site, profile, abi, image_format, word, pointer):
            return lambda: e.if_(e.either(e.ne(p["profile"], profile), e.not_(machine(abi, image_format, word, pointer))), fields(site))

        known = {
            1: x86_64,
            3: aarch64,
            2: lambda: e.if_(e.not_(machine(2, 2, 64, 32)), fields("TARGET_WASM32")),
            4: five("TARGET_ACCELERATOR", 3, 4, 3, 32, 64),
            RISCV64_ARCHITECTURE: five("TARGET_RISCV64", 1, RISCV64_LP64_ABI, RISCV64_RAW_FORMAT, 64, 64),
            SPIRV_ARCHITECTURE: five("TARGET_SPIRV", 1, SPIRV_VULKAN_ABI, SPIRV_MODULE_FORMAT, 32, 32),
            JVM_ARCHITECTURE: five("TARGET_JVM", 1, JVM_ABI, JVM_JAR_FORMAT, 64, 64),
        }
        e.var("decided", 0)
        for architecture, check in known.items():
            e.if_(e.eq(p["arch"], architecture), lambda check=check: (check(), e.set("decided", 1)))
        _no(e, e.eq(p["decided"], 0))  # an unsupported architecture
        e.give(1)
    return _function(("o",), build, tables)


# -- S6b.4d (ADR-149): per-graph glue -----------------------------------------------------

def _glue_ok(tables):
    """The checks ``_graph_syntax_from_stream`` adds to the S3c stream: every parameter and result type reference
    names a proven type, every entity reference resolves, every reference is used, and every trap payload is
    empty or a canonical u16 ULEB reason with optional target bytes (``decode_trap_payload``)."""
    def build(e: E):
        p = e.p
        g = p["g"]
        e.var("refs", _references(e, g))
        _clear_marks(e, p["refs"])
        e.var("gs", _payload(e, g))
        e.var("body_len_at", e.add(p["gs"], e.rd(e.sub(p["gs"], 1))))
        e.var("body_at", e.add(p["body_len_at"], 1))
        e.var("B", e.rd(p["gs"]))
        e.var("ga", e.add(p["gs"], 2))
        for name in ("ti", "tobj", "pc", "nc", "opc", "ei", "oc", "rc", "kind", "ac", "vc", "tsize", "tat", "b0", "b1", "b2", "aq", "aq_stop", "vq", "vq_stop"):
            e.var(name, 0)

        def type_reference():
            e.var("ti", e.rd(p["ga"]))
            e.set("ga", e.add(p["ga"], 1))
            _no(e, e.le(p["refs"], p["ti"]))
            e.var("tobj", _reference(e, g, p["ti"]))
            _no(e, e.eq(p["tobj"], NONE))
            _no(e, e.not_(_type_ok(e, p["tobj"])))
            _mark(e, p["ti"])

        def skip_value():
            e.set("ga", e.add(e.add(p["ga"], 3), e.flag(e.eq(e.rd(p["ga"]), 1))))

        def block():
            e.var("pc", e.rd(p["ga"]))
            e.set("ga", e.add(p["ga"], 1))
            e.for_("pq", 0, p["pc"], type_reference)
            e.var("nc", e.rd(p["ga"]))
            e.set("ga", e.add(p["ga"], 1))

            def node():
                e.var("opc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.if_(e.eq(p["opc"], int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("ga", e.add(p["ga"], 3)))

                def entity():
                    e.var("ei", e.rd(p["ga"]))
                    e.set("ga", e.add(p["ga"], 1))
                    _no(e, e.le(p["refs"], p["ei"]))
                    _no(e, e.eq(_reference(e, g, p["ei"]), NONE))
                    _mark(e, p["ei"])

                e.if_(e.either(*(e.eq(p["opc"], code) for code in ENTITY_CODES)), entity)
                e.var("oc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("oq", 0, p["oc"], skip_value)
                e.var("rc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("rq", 0, p["rc"], type_reference)
                e.if_(e.either(*(e.eq(p["opc"], code) for code in ATTRIBUTE_CODES)), lambda: e.set("ga", e.add(e.add(p["ga"], 1), e.rd(p["ga"]))))

            e.for_("nq", 0, p["nc"], node)
            e.var("kind", e.rd(p["ga"]))
            e.set("ga", e.add(p["ga"], 1))

            def edge():
                e.set("ga", e.add(p["ga"], 1))
                e.var("ac", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("aq", 0, p["ac"], skip_value)

            def trap():
                e.var("tsize", e.rd(p["ga"]))
                e.var("tat", e.add(p["body_at"], e.rd(e.add(p["ga"], 1))))
                e.set("ga", e.add(p["ga"], 2))
                # decode_trap_payload: empty, or a minimal ULEB of at most three bytes naming a reason <= 0xFFFF
                # (a zero reason only with target bytes), then the target bytes.
                b0, b1, b2 = (e.rd(e.add(p["tat"], k)) for k in range(3))
                e.var("b0", b0)
                e.var("b1", b1)
                e.var("b2", b2)
                one = e.lt(p["b0"], 128)
                two = e.both(e.le(128, p["b0"]), e.lt(1, p["tsize"]), e.lt(p["b1"], 128), e.ne(p["b1"], 0))
                three = e.both(e.le(128, p["b0"]), e.le(128, p["b1"]), e.lt(2, p["tsize"]), e.lt(p["b2"], 128), e.ne(p["b2"], 0),
                               e.le(e.add(e.add(e.sub(p["b0"], 128), e.mul(e.sub(p["b1"], 128), 128)), e.mul(p["b2"], 16384)), 0xFFFF))
                zero_alone = e.both(e.eq(p["tsize"], 1), e.eq(p["b0"], 0))
                e.if_(e.ne(p["tsize"], 0), lambda: _no(e, e.either(e.not_(e.either(one, two, three)), zero_alone)))

            e.if_(e.eq(p["kind"], 1), edge)
            e.if_(e.eq(p["kind"], 2), lambda: (skip_value(), edge(), edge()))
            def returning():
                e.set("vc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("vq", 0, p["vc"], skip_value)

            e.if_(e.eq(p["kind"], 3), returning)
            e.if_(e.eq(p["kind"], 4), trap)

        e.for_("b", 0, p["B"], block)
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        e.give(1)
    return _function(("g",), build, tables)


# -- S6b.4a (ADR-149): packages and the leaf build forms ---------------------------------------

def _string(e: E, name: str, end):
    """A ``[ULEB length, bytes]`` byte string at ``p[name]`` inside ``end``: ``(start, length)`` variables; advances."""
    p = e.p
    length = _read(e, name, end)
    e.var(f"{name}_slen", length)
    e.var(f"{name}_sat", p[name])
    _no(e, e.lt(e.sub(end, p[name]), p[f"{name}_slen"]))
    e.set(name, e.add(p[name], p[f"{name}_slen"]))
    return p[f"{name}_sat"], p[f"{name}_slen"]


def _bytes_less_fn(tables):
    """1 when the byte string at ``a`` (``a_len`` bytes) sorts strictly before the one at ``b`` (Python ``bytes`` order)."""
    def build(e: E):
        p = e.p
        e.var("lx_min", e.sel(e.lt(p["a_len"], p["b_len"]), p["a_len"], p["b_len"]))
        e.var("lx_k", 0)
        e.var("lx_r", 2)  # 0 less, 1 greater, 2 undecided

        def step():
            x, y = e.rd(e.add(p["a"], p["lx_k"])), e.rd(e.add(p["b"], p["lx_k"]))
            e.var("lx_x", x)
            e.var("lx_y", y)
            e.if_(e.lt(p["lx_x"], p["lx_y"]), lambda: e.set("lx_r", 0))
            e.if_(e.lt(p["lx_y"], p["lx_x"]), lambda: e.set("lx_r", 1))
            e.set("lx_k", e.add(p["lx_k"], 1))

        e.while_(lambda: e.both(e.lt(p["lx_k"], p["lx_min"]), e.eq(p["lx_r"], 2)), step)
        e.if_(e.eq(p["lx_r"], 2), lambda: e.set("lx_r", e.sel(e.lt(p["a_len"], p["b_len"]), 0, 1)))
        e.give(e.sel(e.eq(p["lx_r"], 0), 1, 0))
    return _function(("a", "b", "a_len", "b_len"), build, tables)


def _cid_less_fn(tables):
    """1 when object ``x``'s CID sorts strictly before object ``y``'s (four big-endian words)."""
    def build(e: E):
        p = e.p
        e.var("cl_r", 2)
        for k in range(4):
            def word(k=k):
                e.var("cl_x", _cid_word(e, p["x"], k))
                e.var("cl_y", _cid_word(e, p["y"], k))
                e.if_(e.lt(p["cl_x"], p["cl_y"]), lambda: e.set("cl_r", 0))
                e.if_(e.lt(p["cl_y"], p["cl_x"]), lambda: e.set("cl_r", 1))
            e.if_(e.eq(p["cl_r"], 2), word)
        e.give(e.sel(e.eq(p["cl_r"], 0), 1, 0))
    return _function(("x", "y"), build, tables)


def _object_reference(e: E, obj, name: str, end, kind: int | None):
    """A reference index read at ``p[name]`` naming a stored object (of ``kind`` when given); marks it."""
    p = e.p
    e.var(f"{name}_ri", _read(e, name, end))
    _no(e, e.le(_references(e, obj), p[f"{name}_ri"]))
    e.var(f"{name}_ro", _reference(e, obj, p[f"{name}_ri"]))
    _no(e, e.eq(p[f"{name}_ro"], NONE))
    if kind is not None:
        _no(e, e.ne(_kind(e, p[f"{name}_ro"]), kind))
    _mark(e, p[f"{name}_ri"])
    return p[f"{name}_ro"]


def _strictly_after(e: E, name: str, start, length, first):
    """``(start, length)`` must sort strictly after the previous string remembered under ``name`` (unless ``first``)."""
    p = e.p
    e.if_(e.not_(first), lambda: _no(e, e.ne(e.call(_FN["bytes_less"], p[f"{name}_ps"], start, p[f"{name}_pl"], length), 1)))
    e.var(f"{name}_ps", start)
    e.var(f"{name}_pl", length)


def _capability(e: E, name: str, end, prefix: str):
    """A build capability ``[kind 1..9, scope bytes]`` read into ``prefix``_kind/_cs/_cl."""
    p = e.p
    e.var(f"{prefix}_kind", _read(e, name, end))
    _no(e, e.either(e.lt(p[f"{prefix}_kind"], 1), e.lt(9, p[f"{prefix}_kind"])))
    start, length = _string(e, name, end)
    e.var(f"{prefix}_cs", start)
    e.var(f"{prefix}_cl", length)


def _package_ok(tables):
    """``decode_package``: identity, canonical modules, dependencies, named build entries and schemas,
    capabilities, exact end and exact reference use."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("pa", _payload(e, o))
        e.var("pend", e.add(p["pa"], e.rd(e.sub(p["pa"], 1))))
        _clear_marks(e, p["refs"])
        start, length = _string(e, "pa", p["pend"])
        e.var("p_is", start)
        e.var("p_il", length)
        _no(e, e.eq(p["p_il"], 0))
        e.var("mcount", _read(e, "pa", p["pend"]))
        _no(e, e.eq(p["mcount"], 0))

        def module():
            e.var("mobj", _object_reference(e, o, "pa", p["pend"], int(Kind.MODULE)))
            e.if_(e.ne(p["mq"], 0), lambda: _no(e, e.ne(e.call(_FN["cid_less"], p["mprev"], p["mobj"]), 1)))
            e.var("mprev", p["mobj"])

        e.var("mprev", 0)
        e.for_("mq", 0, p["mcount"], module)
        # Dependencies sort by key: exact (0x01 + root CID) before logical (0x02 + ULEB length + identity).
        e.var("p_deps", p["pa"])
        e.var("dcount", _read(e, "pa", p["pend"]))
        e.var("dform", 0)  # the previous form; 0 before the first
        e.var("dobj", 0)
        e.var("dps", 0)
        e.var("dpl", 0)

        def dependency():
            e.var("form", _read(e, "pa", p["pend"]))
            _no(e, e.both(e.ne(p["form"], 1), e.ne(p["form"], 2)))
            _no(e, e.lt(p["form"], p["dform"]))

            def exact():
                e.var("dnew", _object_reference(e, o, "pa", p["pend"], int(Kind.PACKAGE)))
                e.if_(e.eq(p["dform"], 1), lambda: _no(e, e.ne(e.call(_FN["cid_less"], p["dobj"], p["dnew"]), 1)))
                e.set("dobj", p["dnew"])

            def logical():
                e.var("dkey", p["pa"])  # the key is the encoded string: ULEB length, then bytes
                _ds, dl = _string(e, "pa", p["pend"])
                _no(e, e.eq(dl, 0))
                e.var("dklen", e.sub(p["pa"], p["dkey"]))
                e.if_(e.eq(p["dform"], 2), lambda: _no(e, e.ne(e.call(_FN["bytes_less"], p["dps"], p["dkey"], p["dpl"], p["dklen"]), 1)))
                e.set("dps", p["dkey"])
                e.set("dpl", p["dklen"])

            e.if_(e.eq(p["form"], 1), exact, logical)
            e.set("dform", p["form"])

        e.for_("dq", 0, p["dcount"], dependency)
        e.var("p_entries", p["pa"])
        for collection, kind in (("ce", Kind.FUNCTION), ("cf", Kind.TYPE), ("cc", Kind.TYPE)):
            e.var(f"{collection}_count", _read(e, "pa", p["pend"]))

            def entry(collection=collection, kind=kind):
                start, length = _string(e, "pa", p["pend"])
                e.var(f"{collection}_ns", start)
                e.var(f"{collection}_nl", length)
                _no(e, e.eq(p[f"{collection}_nl"], 0))
                _object_reference(e, o, "pa", p["pend"], int(kind))
                _strictly_after(e, collection, p[f"{collection}_ns"], p[f"{collection}_nl"], e.eq(p[f"{collection}_q"], 0))

            e.var(f"{collection}_ps", 0)
            e.var(f"{collection}_pl", 0)
            e.for_(f"{collection}_q", 0, p[f"{collection}_count"], entry)
        e.var("p_caps", p["pa"])
        e.var("kcount", _read(e, "pa", p["pend"]))
        e.var("kprev", 0)

        def capability():
            # (kind, scope) strictly increasing.
            _capability(e, "pa", p["pend"], "k")

            def ordered():
                _no(e, e.lt(p["k_kind"], p["kprev"]))
                e.if_(e.eq(p["kprev"], p["k_kind"]), lambda: _no(e, e.ne(e.call(_FN["bytes_less"], p["kps"], p["k_cs"], p["kpl"], p["k_cl"]), 1)))

            e.if_(e.ne(p["kq"], 0), ordered)
            e.set("kprev", p["k_kind"])
            e.var("kps", p["k_cs"])
            e.var("kpl", p["k_cl"])

        e.var("kps", 0)
        e.var("kpl", 0)
        e.for_("kq", 0, p["kcount"], capability)
        _no(e, e.ne(p["pa"], p["pend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        # For requests and snapshots: [identity start, identity length, dependencies, entries, capabilities].
        e.var("prec", e.alloc(5))
        _no(e, e.eq(p["prec"], NONE))
        for slot, name in enumerate(("p_is", "p_il", "p_deps", "p_entries", "p_caps")):
            e.st(e.add(p["prec"], slot), p[name])
        e.st(e.add(GRAPHS_AT, o), p["prec"])
        e.give(1)
    return _function(("o",), build, tables)


def _build_ok(tables):
    """The leaf build forms: profile (``decode_profile``), trust policy, signature, and optimization policy.
    Requests, snapshots, and provenance give 0 here: later passes decide them (S6b.4b)."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("ba", _payload(e, o))
        e.var("bend", e.add(p["ba"], e.rd(e.sub(p["ba"], 1))))
        _clear_marks(e, p["refs"])
        e.var("form", _read(e, "ba", p["bend"]))

        def finish():
            _no(e, e.ne(p["ba"], p["bend"]))
            _no(e, e.eq(_all_marked(e, p["refs"]), 0))
            e.give(1)

        def profile():
            e.var("mode", _read(e, "ba", p["bend"]))
            _no(e, e.either(e.lt(p["mode"], 1), e.lt(3, p["mode"])))
            _read(e, "ba", p["bend"])  # optimization level
            _read(e, "ba", p["bend"])  # verification level
            e.st(e.add(GRAPHS_AT, o), p["ba"])  # for snapshots: where the grants start
            e.var("gcount", _read(e, "ba", p["bend"]))
            e.var("gis", 0)
            e.var("gil", 0)
            e.var("gkind", 0)
            e.var("gcs", 0)
            e.var("gcl", 0)

            def grant():
                start, length = _string(e, "ba", p["bend"])
                e.var("nis", start)
                e.var("nil", length)
                _no(e, e.eq(p["nil"], 0))
                _capability(e, "ba", p["bend"], "g")

                def ordered():
                    # (identity, kind, scope) strictly increasing.
                    e.var("gless", e.call(_FN["bytes_less"], p["gis"], p["nis"], p["gil"], p["nil"]))
                    e.var("gmore", e.call(_FN["bytes_less"], p["nis"], p["gis"], p["nil"], p["gil"]))
                    _no(e, e.ne(p["gmore"], 0))

                    def same_identity():
                        _no(e, e.lt(p["g_kind"], p["gkind"]))
                        e.if_(e.eq(p["g_kind"], p["gkind"]), lambda: _no(e, e.ne(e.call(_FN["bytes_less"], p["gcs"], p["g_cs"], p["gcl"], p["g_cl"]), 1)))

                    e.if_(e.eq(p["gless"], 0), same_identity)

                e.if_(e.ne(p["gq"], 0), ordered)
                e.set("gis", p["nis"])
                e.set("gil", p["nil"])
                e.set("gkind", p["g_kind"])
                e.set("gcs", p["g_cs"])
                e.set("gcl", p["g_cl"])

            e.for_("gq", 0, p["gcount"], grant)
            finish()

        def trust():
            for flag in ("rp", "rv"):
                _no(e, e.le(p["bend"], p["ba"]))
                e.var(flag, e.rd(p["ba"]))
                _no(e, e.lt(1, p[flag]))
                e.set("ba", e.add(p["ba"], 1))
            for name in ("al", "si"):
                e.var(f"{name}_count", _read(e, "ba", p["bend"]))

                def item(name=name):
                    start, length = _string(e, "ba", p["bend"])
                    e.var(f"{name}_s", start)
                    e.var(f"{name}_l", length)
                    _no(e, e.eq(p[f"{name}_l"], 0))
                    _strictly_after(e, name, p[f"{name}_s"], p[f"{name}_l"], e.eq(p[f"{name}_q"], 0))

                e.var(f"{name}_ps", 0)
                e.var(f"{name}_pl", 0)
                e.for_(f"{name}_q", 0, p[f"{name}_count"], item)
            e.st(e.add(GRAPHS_AT, o), p["rp"])  # for snapshots: package signatures required
            required = e.either(e.ne(p["rp"], 0), e.ne(p["rv"], 0))
            _no(e, e.both(required, e.either(e.eq(p["al_count"], 0), e.eq(p["si_count"], 0))))
            finish()

        def signature():
            e.st(e.add(GRAPHS_AT, o), _object_reference(e, o, "ba", p["bend"], None))  # the signed object
            for _field in range(3):
                _start, length = _string(e, "ba", p["bend"])
                _no(e, e.eq(length, 0))
            finish()

        def optimization():
            _no(e, e.ne(_read(e, "ba", p["bend"]), 1))  # objective: code size
            for _value in range(8):
                _read(e, "ba", p["bend"])
            _no(e, e.le(p["bend"], p["ba"]))
            _no(e, e.lt(1, e.rd(p["ba"])))
            e.set("ba", e.add(p["ba"], 1))
            _no(e, e.ne(p["refs"], 0))
            finish()

        e.if_(e.eq(p["form"], 1), profile)
        e.if_(e.eq(p["form"], 4), trust)
        e.if_(e.eq(p["form"], 6), signature)
        e.if_(e.eq(p["form"], 7), optimization)
        e.give(0)
    return _function(("o",), build, tables)


# -- S6b.4b (ADR-149): requests, snapshots, provenance --------------------------------------

def _form_of(e: E, obj):
    """The build form of a BUILD object (its first body byte; every form is below 128)."""
    return e.rd(_payload(e, obj))


def _verdict(e: E, obj):
    return e.ld(e.add(VERDICTS_AT, obj))


def _aux(e: E, obj):
    return e.ld(e.add(GRAPHS_AT, obj))


def _same_bytes(e: E, a, a_len, b, b_len):
    return e.both(e.eq(a_len, b_len), e.eq(e.call(_FN["bytes_less"], a, b, a_len, b_len), 0), e.eq(e.call(_FN["bytes_less"], b, a, b_len, a_len), 0))


def _request_ok(tables):
    """``decode_request``: a proven package with the entry, target, profile, bindings matching the package's
    schemas name for name with constants of the schema types, canonical artifacts, exact use."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("ra", _payload(e, o))
        e.var("rend", e.add(p["ra"], e.rd(e.sub(p["ra"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.ne(_read(e, "ra", p["rend"]), 2))
        e.var("pkg", _object_reference(e, o, "ra", p["rend"], int(Kind.PACKAGE)))
        _no(e, e.ne(_verdict(e, p["pkg"]), 1))
        start, length = _string(e, "ra", p["rend"])
        e.var("es", start)
        e.var("el", length)
        e.var("tgt", _object_reference(e, o, "ra", p["rend"], int(Kind.TARGET)))
        e.var("prof", _object_reference(e, o, "ra", p["rend"], int(Kind.BUILD)))
        _no(e, e.ne(_form_of(e, p["prof"]), 1))
        # The package (proven) lists its entries, feature schemas, and configuration schemas from p_entries on.
        e.var("q", e.ld(e.add(_aux(e, p["pkg"]), 3)))
        e.var("qend", e.add(e.add(_payload(e, p["pkg"]), e.rd(e.sub(_payload(e, p["pkg"]), 1))), 0))
        e.var("found", 0)

        def entry():
            start, length = _string(e, "q", p["qend"])
            e.var("ns", start)
            e.var("nl", length)
            _read(e, "q", p["qend"])
            e.if_(_same_bytes(e, p["ns"], p["nl"], p["es"], p["el"]), lambda: e.set("found", 1))

        e.var("entries", _read(e, "q", p["qend"]))
        e.for_("eq_", 0, p["entries"], entry)
        _no(e, e.eq(p["found"], 0))
        for schema in ("feature", "configuration"):
            e.var("scount", _read(e, "q", p["qend"]))
            e.var("bcount", _read(e, "ra", p["rend"]))
            _no(e, e.ne(p["scount"], p["bcount"]))

            def binding():
                start, length = _string(e, "ra", p["rend"])
                e.var("bs", start)
                e.var("bl", length)
                e.var("value", _object_reference(e, o, "ra", p["rend"], None))
                start, length = _string(e, "q", p["qend"])
                e.var("ss", start)
                e.var("sl", length)
                e.var("si", _read(e, "q", p["qend"]))
                e.var("stype", _reference(e, p["pkg"], p["si"]))
                _no(e, e.not_(_same_bytes(e, p["bs"], p["bl"], p["ss"], p["sl"])))
                # ``_constant_type``: the value is a constant whose type reference is the schema's type.
                _no(e, e.ne(_kind(e, p["value"]), int(Kind.CONSTANT)))
                e.var("ca", _payload(e, p["value"]))
                e.var("cend", e.add(p["ca"], e.rd(e.sub(p["ca"], 1))))
                e.var("ct", _read(e, "ca", p["cend"]))
                _no(e, e.le(_references(e, p["value"]), p["ct"]))
                _no(e, e.ne(_reference(e, p["value"], p["ct"]), p["stype"]))

            e.for_(f"b_{schema}", 0, p["bcount"], binding)
        e.var("acount", _read(e, "ra", p["rend"]))
        _no(e, e.eq(p["acount"], 0))
        e.var("aprev", 0)

        def artifact():
            e.var("art", _read(e, "ra", p["rend"]))
            _no(e, e.either(e.lt(p["art"], 1), e.lt(6, p["art"]), e.le(p["art"], p["aprev"])))
            e.set("aprev", p["art"])

        e.for_("aq", 0, p["acount"], artifact)
        _no(e, e.ne(p["ra"], p["rend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        e.var("rrec", e.alloc(3))  # [package, target, profile]
        _no(e, e.eq(p["rrec"], NONE))
        e.st(p["rrec"], p["pkg"])
        e.st(e.add(p["rrec"], 1), p["tgt"])
        e.st(e.add(p["rrec"], 2), p["prof"])
        e.st(e.add(GRAPHS_AT, o), p["rrec"])
        e.give(1)
    return _function(("o",), build, tables)


def _listed(e: E, items, count, obj):
    """The position of ``obj`` in the ``count`` words at ``items``, or NONE."""
    p = e.p
    e.var("ls_at", NONE)
    e.for_("ls_q", 0, count, lambda: e.if_(e.eq(e.ld(e.add(items, p["ls_q"])), obj), lambda: e.set("ls_at", p["ls_q"])))
    return p["ls_at"]


def _snapshot_ok(tables):
    """``decode_snapshot``: header kinds, canonical package, signature, and digest lists, exact use; a proven
    request whose package is listed, an exact dependency closure, declared grants, and signature coverage."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("sa", _payload(e, o))
        e.var("send", e.add(p["sa"], e.rd(e.sub(p["sa"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.ne(_read(e, "sa", p["send"]), 3))
        e.var("req", _object_reference(e, o, "sa", p["send"], int(Kind.BUILD)))
        _no(e, e.ne(_form_of(e, p["req"]), 2))
        _start, length = _string(e, "sa", p["send"])
        _no(e, e.eq(length, 0))
        e.var("pol", _object_reference(e, o, "sa", p["send"], int(Kind.BUILD)))
        _no(e, e.ne(_form_of(e, p["pol"]), 4))
        for name, kind, form in (("pk", Kind.PACKAGE, None), ("sg", Kind.BUILD, 6)):
            e.var(f"{name}_count", _read(e, "sa", p["send"]))
            e.var(f"{name}_items", e.alloc(e.add(p[f"{name}_count"], 1)))
            _no(e, e.eq(p[f"{name}_items"], NONE))

            def item(name=name, kind=kind, form=form):
                e.var(f"{name}_obj", _object_reference(e, o, "sa", p["send"], int(kind)))
                if form is not None:
                    _no(e, e.ne(_form_of(e, p[f"{name}_obj"]), form))
                _no(e, e.ne(_verdict(e, p[f"{name}_obj"]), 1))
                e.if_(e.ne(p[f"{name}_q"], 0), lambda: _no(e, e.ne(e.call(_FN["cid_less"], e.ld(e.add(p[f"{name}_items"], e.sub(p[f"{name}_q"], 1))), p[f"{name}_obj"]), 1)))
                e.st(e.add(p[f"{name}_items"], p[f"{name}_q"]), p[f"{name}_obj"])

            e.for_(f"{name}_q", 0, p[f"{name}_count"], item)
        e.var("dcount", _read(e, "sa", p["send"]))

        def digest():
            _no(e, e.lt(e.sub(p["send"], p["sa"]), 32))
            e.if_(e.ne(p["dq"], 0), lambda: _no(e, e.ne(e.call(_FN["bytes_less"], e.sub(p["sa"], 32), p["sa"], 32, 32), 1)))
            e.set("sa", e.add(p["sa"], 32))

        e.for_("dq", 0, p["dcount"], digest)
        _no(e, e.ne(p["sa"], p["send"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        _no(e, e.ne(_verdict(e, p["req"]), 1))
        _no(e, e.ne(_verdict(e, p["pol"]), 1))
        e.var("rrec", _aux(e, p["req"]))
        e.var("root", e.ld(p["rrec"]))
        e.var("prof", e.ld(e.add(p["rrec"], 2)))
        _no(e, e.ne(_verdict(e, p["prof"]), 1))
        _no(e, e.eq(_listed(e, p["pk_items"], p["pk_count"], p["root"]), NONE))
        # The dependency closure from the request's package is exactly the listed packages.
        e.var("seen", e.alloc(e.add(p["pk_count"], 1)))
        e.var("queue", e.alloc(e.add(p["pk_count"], 1)))
        _no(e, e.either(e.eq(p["seen"], NONE), e.eq(p["queue"], NONE)))
        e.for_("z", 0, p["pk_count"], lambda: e.st(e.add(p["seen"], p["z"]), 0))
        e.var("head", 0)
        e.var("tail", 0)

        def enqueue(position):
            e.var("eqp", position)
            e.if_(e.eq(e.ld(e.add(p["seen"], p["eqp"])), 0), lambda: (
                e.st(e.add(p["seen"], p["eqp"]), 1),
                e.st(e.add(p["queue"], p["tail"]), p["eqp"]),
                e.set("tail", e.add(p["tail"], 1)),
            ))

        enqueue(_listed(e, p["pk_items"], p["pk_count"], p["root"]))

        def visit():
            e.var("cur", e.ld(e.add(p["pk_items"], e.ld(e.add(p["queue"], p["head"])))))
            e.set("head", e.add(p["head"], 1))
            e.var("crec", _aux(e, p["cur"]))
            e.var("w", e.ld(e.add(p["crec"], 2)))
            e.var("wend", e.add(_payload(e, p["cur"]), e.rd(e.sub(_payload(e, p["cur"]), 1))))
            e.var("deps", _read(e, "w", p["wend"]))

            def dependency():
                e.var("dform", _read(e, "w", p["wend"]))

                def exact():
                    e.var("dpos", _listed(e, p["pk_items"], p["pk_count"], _reference(e, p["cur"], _read(e, "w", p["wend"]))))
                    _no(e, e.eq(p["dpos"], NONE))
                    enqueue(p["dpos"])

                def logical():
                    start, length = _string(e, "w", p["wend"])
                    e.var("lis", start)
                    e.var("lil", length)
                    e.var("matches", 0)
                    e.var("match", 0)

                    def candidate():
                        e.var("other", _aux(e, e.ld(e.add(p["pk_items"], p["mq"]))))
                        e.if_(_same_bytes(e, e.ld(p["other"]), e.ld(e.add(p["other"], 1)), p["lis"], p["lil"]),
                              lambda: (e.set("matches", e.add(p["matches"], 1)), e.set("match", p["mq"])))

                    e.for_("mq", 0, p["pk_count"], candidate)
                    _no(e, e.ne(p["matches"], 1))
                    enqueue(p["match"])

                e.if_(e.eq(p["dform"], 1), exact, logical)

            e.for_("dk", 0, p["deps"], dependency)

        e.while_(lambda: e.lt(p["head"], p["tail"]), visit)
        _no(e, e.ne(p["tail"], p["pk_count"]))
        # Every profile grant names listed packages, each declaring the capability.
        e.var("g", _aux(e, p["prof"]))
        e.var("gend", e.add(_payload(e, p["prof"]), e.rd(e.sub(_payload(e, p["prof"]), 1))))
        e.var("grants", _read(e, "g", p["gend"]))

        def grant():
            start, length = _string(e, "g", p["gend"])
            e.var("gis", start)
            e.var("gil", length)
            e.var("gkind", _read(e, "g", p["gend"]))
            start, length = _string(e, "g", p["gend"])
            e.var("gcs", start)
            e.var("gcl", length)
            e.var("gfound", 0)

            def package_view():
                e.var("pv", e.ld(e.add(p["pk_items"], p["pq"])))
                e.var("pvr", _aux(e, p["pv"]))

                def declared():
                    e.set("gfound", 1)
                    e.var("c", e.ld(e.add(p["pvr"], 4)))
                    e.var("cend", e.add(_payload(e, p["pv"]), e.rd(e.sub(_payload(e, p["pv"]), 1))))
                    e.var("caps", _read(e, "c", p["cend"]))
                    e.var("has", 0)

                    def capability():
                        e.var("ck", _read(e, "c", p["cend"]))
                        start, length = _string(e, "c", p["cend"])
                        e.var("cs", start)
                        e.var("cl", length)
                        e.if_(e.both(e.eq(p["ck"], p["gkind"]), _same_bytes(e, p["cs"], p["cl"], p["gcs"], p["gcl"])), lambda: e.set("has", 1))

                    e.for_("cq", 0, p["caps"], capability)
                    _no(e, e.eq(p["has"], 0))

                e.if_(_same_bytes(e, e.ld(p["pvr"]), e.ld(e.add(p["pvr"], 1)), p["gis"], p["gil"]), declared)

            e.for_("pq", 0, p["pk_count"], package_view)
            _no(e, e.eq(p["gfound"], 0))

        e.for_("gq", 0, p["grants"], grant)
        # Signatures sign listed packages; a policy requiring package signatures covers every one.
        e.var("signed", e.alloc(e.add(p["pk_count"], 1)))
        _no(e, e.eq(p["signed"], NONE))
        e.for_("z", 0, p["pk_count"], lambda: e.st(e.add(p["signed"], p["z"]), 0))

        def signature():
            e.var("spos", _listed(e, p["pk_items"], p["pk_count"], _aux(e, e.ld(e.add(p["sg_items"], p["sq"])))))
            _no(e, e.eq(p["spos"], NONE))
            e.st(e.add(p["signed"], p["spos"]), 1)

        e.for_("sq", 0, p["sg_count"], signature)
        e.if_(e.ne(_aux(e, p["pol"]), 0), lambda: e.for_("z", 0, p["pk_count"], lambda: _no(e, e.eq(e.ld(e.add(p["signed"], p["z"])), 0))))
        e.st(e.add(GRAPHS_AT, o), p["req"])
        e.give(1)
    return _function(("o",), build, tables)


def _provenance_ok(tables):
    """``decode_provenance``: snapshot, request, target, profile; three digests and a producer; the exact closure."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("va", _payload(e, o))
        e.var("vend", e.add(p["va"], e.rd(e.sub(p["va"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.ne(_read(e, "va", p["vend"]), 5))
        e.var("snap", _object_reference(e, o, "va", p["vend"], int(Kind.BUILD)))
        e.var("req", _object_reference(e, o, "va", p["vend"], int(Kind.BUILD)))
        e.var("tgt", _object_reference(e, o, "va", p["vend"], int(Kind.TARGET)))
        e.var("prof", _object_reference(e, o, "va", p["vend"], int(Kind.BUILD)))
        _no(e, e.either(e.ne(_form_of(e, p["snap"]), 3), e.ne(_form_of(e, p["req"]), 2), e.ne(_form_of(e, p["prof"]), 1)))
        _no(e, e.lt(e.sub(p["vend"], p["va"]), 96))
        e.set("va", e.add(p["va"], 96))
        _string(e, "va", p["vend"])
        _no(e, e.ne(p["va"], p["vend"]))
        _no(e, e.eq(_all_marked(e, p["refs"]), 0))
        _no(e, e.either(e.ne(_verdict(e, p["snap"]), 1), e.ne(_verdict(e, p["req"]), 1)))
        _no(e, e.ne(_aux(e, p["snap"]), p["req"]))
        e.var("rrec", _aux(e, p["req"]))
        _no(e, e.either(e.ne(e.ld(e.add(p["rrec"], 1)), p["tgt"]), e.ne(e.ld(e.add(p["rrec"], 2)), p["prof"])))
        e.give(1)
    return _function(("o",), build, tables)


def _list_ok(tables, allowed):
    """``_verify_reference_list``: indices 0..n-1 in order, exact end, children of allowed kinds."""
    def build(e: E):
        p = e.p
        o = p["o"]
        _no(e, e.eq(_resolved(e, o), 0))
        refs = _references(e, o)
        e.var("lrefs", refs)
        e.var("la", _payload(e, o))
        end = e.add(p["la"], e.rd(e.sub(p["la"], 1)))
        e.var("lend", end)
        count = _read(e, "la", p["lend"])
        e.var("lcount", count)
        # The indices (as the bootstrap reads them, before its end check), kept for the diagnostics.
        e.var("lindices", e.alloc(e.add(p["lcount"], 1)))
        _no(e, e.eq(p["lindices"], NONE))
        e.st(p["lindices"], p["lcount"])
        e.for_("q", 0, p["lcount"], lambda: e.st(e.add(p["lindices"], e.add(p["q"], 1)), _read(e, "la", p["lend"])))
        _reject(e, e.ne(p["la"], p["lend"]), o, S["LIST_TRAILING"], e.sub(p["lend"], p["la"]))
        e.var("lout", 0)
        e.for_("q", 0, p["lcount"], lambda: e.if_(e.le(p["lrefs"], e.ld(e.add(p["lindices"], e.add(p["q"], 1)))), lambda: e.set("lout", 1)))
        _reject(e, e.ne(p["lout"], 0), o, S["LIST_REF_INDEX"], p["lrefs"], p["lindices"])
        e.var("lorder", e.flag(e.eq(p["lcount"], p["lrefs"])))
        e.for_("q", 0, p["lcount"], lambda: e.if_(e.ne(e.ld(e.add(p["lindices"], e.add(p["q"], 1))), p["q"]), lambda: e.set("lorder", 0)))
        _reject(e, e.eq(p["lorder"], 0), o, S["LIST_REFERENCE_BODY"], p["lrefs"], p["lindices"])

        def child():
            target = _reference(e, o, p["q"])
            _reject(e, e.not_(e.either(*(e.eq(_kind(e, target), int(kind)) for kind in allowed))), o, S["LIST_CHILD_KIND"], _kind(e, target))

        e.for_("q", 0, p["lcount"], child)
        e.give(1)
    return _function(("o",), build, tables)


def _contract_ok(tables):
    """``_decode_call_contract``: proven input and output types, two canonical booleans, exact use."""
    def build(e: E):
        p = e.p
        o = p["o"]
        _no(e, e.eq(_resolved(e, o), 0))
        e.var("refs", _references(e, o))
        e.var("ca", _payload(e, o))
        end = e.add(p["ca"], e.rd(e.sub(p["ca"], 1)))
        e.var("cend", end)
        _clear_marks(e, p["refs"])

        def type_reference():
            index = _read(e, "ca", p["cend"])
            e.var("ca_index", index)
            _reject(e, e.le(p["refs"], p["ca_index"]), o, S["CONTRACT_REF_INDEX"], p["refs"], p["ca_index"])
            _no(e, e.not_(_type_ok(e, _reference(e, o, p["ca_index"]))))  # the bootstrap verifies the type itself
            _mark(e, p["ca_index"])

        for _part in range(2):
            e.var("ccount", _read(e, "ca", p["cend"]))
            e.for_("q", 0, p["ccount"], type_reference)
        for _flag in range(2):
            _reject(e, e.le(p["cend"], p["ca"]), o, S["CONTRACT_TRUNCATED"])
            _reject(e, e.lt(1, e.rd(p["ca"])), o, S["CONTRACT_BOOL"], e.rd(p["ca"]))
            e.set("ca", e.add(p["ca"], 1))
        _reject(e, e.ne(p["ca"], p["cend"]), o, S["CONTRACT_TRAILING"], e.sub(p["cend"], p["ca"]))
        _reject(e, e.eq(_all_marked(e, p["refs"]), 0), o, S["CONTRACT_UNUSED"], _list_copy(e, p["refs"], lambda k: e.ld(e.add(_g(e, G_MARK), k))))
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
                e.if_(e.eq(kind, int(Kind.PACKAGE)), lambda: e.set("verdict", e.call(_FN["package"], o)))
                e.if_(e.eq(kind, int(Kind.BUILD)), lambda: e.set("verdict", e.call(_FN["build"], o)))
                e.if_(e.eq(kind, int(Kind.GRAPH_FRAGMENT)), lambda: e.set("verdict", e.call(_FN["glue"], o)))
            this_pass = e.eq(kind, int(Kind.RECURSION_GROUP)) if groups else e.ne(kind, int(Kind.RECURSION_GROUP))
            e.if_(this_pass, lambda: e.st(e.add(VERDICTS_AT, o), e.sel(e.eq(p["verdict"], 1), 1, e.sel(e.eq(p["verdict"], REJECTED), REJECTED, 0))))

        e.for_("o", 0, p["O"], lambda: verdict(True))
        e.for_("o", 0, p["O"], lambda: verdict(False))
        # Requests, then snapshots, then provenance: each reads the verdicts and records of the ones before.
        for form, name in ((2, "request"), (3, "snapshot"), (5, "provenance")):
            def later(form=form, name=name):
                o = p["o"]
                e.if_(e.both(e.eq(_kind(e, o), int(Kind.BUILD)), e.eq(_form_of(e, o), form)), lambda: e.st(e.add(VERDICTS_AT, o), e.sel(e.eq(e.call(_FN[name], o), 1), 1, 0)))

            e.for_("o", 0, p["O"], later)
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
    DECLINE_SITES.clear()  # decline codes are baked into the store: number them per build, not per process
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
    add("bytes_less", _bytes_less_fn(tables))
    add("cid_less", _cid_less_fn(tables))
    add("package", _package_ok(tables))
    add("build", _build_ok(tables))
    add("request", _request_ok(tables))
    add("snapshot", _snapshot_ok(tables))
    add("provenance", _provenance_ok(tables))
    add("glue", _glue_ok(tables))
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
    from xax_compiler import StoreReader

    if not STORE_PATH.exists():
        return build_verifier_program()
    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "store-verifier")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def _native_image() -> tuple[bytes, int]:
    """``(machine code, entry offset)``, lowered for this host by the XAX x86-64 backend and cached (ADR-152)."""
    from xax_selfhost_x86_64_backend import host_image

    return host_image(*load_verifier_program(), "store-verifier")


class NativeStoreVerifier:
    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        code, entry_offset = _native_image()
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

    def verify(self, words: list[int], count: int, groups=()):
        """``(store verdict, per-object verdicts, per-object graph words, {group: member graphs})``, or None when it
        cannot run.  A proven function's graph word is its graph object (NONE for a group member function); a proven
        group's (``groups`` lists their positions) points at ``[count, member graphs]``."""
        return self.verify_with_rejections(words, count, groups)[0]

    def verify_with_rejections(self, words: list[int], count: int, groups=()):
        """``verify``'s result and the rejected objects' records (``collect_rejections``)."""
        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None, {}
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            read = lambda start, length: list(out[start : start + length])  # noqa: E731
            result = collect_verdicts(read, count, groups)
            return result, ({} if result is None else collect_rejections(read, result[1]))


def collect_verdicts(read, count: int, groups=()):
    """The program's result from its output view, read as ``read(start word, count)`` wherever it ran (natively
    or as a RISC-V image, S6c): ``(store verdict, verdicts, graph words, {group: member graphs})``, or None."""
    status, store = read(0, 2)
    if status != OK:
        return None
    verdicts, graphs = read(VERDICTS_AT, count), read(GRAPHS_AT, count)
    members = {o: tuple(read(graphs[o] + 1, read(graphs[o], 1)[0])) for o in groups if verdicts[o] == 1}
    return store == 1, verdicts, graphs, members


LIST_SITES = ("LIST_REF_INDEX", "LIST_REFERENCE_BODY", "CONTRACT_UNUSED", "FUNCTION_UNUSED", "GROUP_UNUSED")  # a payload word is a [count, words] list
TARGET_SCALAR_SITES = ("TARGET_REFERENCES", "TARGET_IDENTITY_TRUNCATED", "TARGET_IDENTITY_EMPTY", "TARGET_ARCHITECTURE", "TARGET_TRAILING",
                       "TARGET_PROFILE")  # the other target sites quote the machine record at payload word 0
PAIR_SITES = ("FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT")  # payload word 1 is [n, words, m, words]


def collect_rejections(read, verdicts):
    """``{object: (site, payload words, quoted list or None)}`` for every REJECTED verdict."""
    rejections = {}
    for o, verdict in enumerate(verdicts):
        if verdict != REJECTED:
            continue
        site, *payload = read(REJECTS_AT + REJECT_WORDS * o, REJECT_WORDS)
        listed = None
        name = OBJECT_SITES[site - 1] if 0 < site <= len(OBJECT_SITES) else None
        if name in LIST_SITES:
            at = payload[0] if name in ("CONTRACT_UNUSED", "GROUP_UNUSED") else payload[1]
            listed = read(at + 1, read(at, 1)[0])
        elif name in GROUP_AFTER_PARSE:
            graphs = read(payload[2] + 1, payload[0])
            if name in ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT"):
                first = read(payload[1], 1)[0]
                second = read(payload[1] + 1 + first, 1)[0]
                listed = read(payload[1], first + second + 2)
            elif name == "GROUP_MEMBER_RANGE":
                listed = [read(payload[2], 1)[0]]
            elif name == "GROUP_CALL_CONTRACT":
                words, at = [], payload[1]
                for _part in range(4):
                    n = read(at, 1)[0]
                    words.append(read(at + 1, n))
                    at += n + 1
                listed = words
            elif name == "GROUP_SCC":
                words, at = [], payload[1] + 1
                for _member in range(read(payload[1], 1)[0]):
                    n = read(at, 1)[0]
                    words.append(read(at + 1, n))
                    at += n + 1
                listed = words
            rejections[o] = (site, payload, listed, graphs)
            continue
        elif name is not None and name.startswith("TARGET_") and name not in TARGET_SCALAR_SITES:
            listed = read(payload[0], 7)
        elif name in PAIR_SITES:
            first = read(payload[1], 1)[0]
            second = read(payload[1] + 1 + first, 1)[0]
            listed = read(payload[1], first + second + 2)
        rejections[o] = (site, payload, listed)
    return rejections


def _target_diagnostic(obj, name, x, y, machine):
    """S8c.23: ``decode_native_target``'s diagnostics (``machine``: profile, abi, format, word, pointer, stack, shadow)."""
    import xax_compiler as X

    if name == "TARGET_REFERENCES":
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", [], [cid.hex() for cid in obj.references]
    if name == "TARGET_IDENTITY_TRUNCATED":
        return "XAX.CANON.TRUNCATED", "SER-BOUNDS", f"{x} available bytes", y
    if name == "TARGET_IDENTITY_EMPTY":
        return "XAX.STRUCT.TARGET_IDENTITY", "TARGET-IDENTITY-NONEMPTY", ">= 1 byte", 0
    if name == "TARGET_ARCHITECTURE":
        return ("XAX.TARGET.ARCHITECTURE", "TARGET-ARCHITECTURE-SUPPORTED",
                [1, 2, 3, 4, X.JVM_ARCHITECTURE, X.RISCV64_ARCHITECTURE, X.SPIRV_ARCHITECTURE], x)
    if name == "TARGET_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "TARGET-NATIVE-BODY", 0, x
    if name == "TARGET_PROFILE":
        return "XAX.TARGET.PROFILE", "TARGET-PROFILE-SUPPORTED", [1, 2, 3, 4, X.BOARD_PROFILE], x
    profile, abi, image_format, word, pointer, stack, shadow = machine
    if name == "TARGET_X86_64":
        allowed = ((1, 1, 64, 64, 16, 32), (X.X86_64_LINUX_ABI, X.X86_64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 32),
                   (X.X86_64_LINUX_ABI, X.X86_64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 32))
        return "XAX.TARGET.MACHINE", "TARGET-X86-64-PROFILE", [list(item) for item in allowed], [abi, image_format, word, pointer, stack, shadow]
    if name == "TARGET_AARCH64":
        allowed = ((3, 1, 64, 64, 16, 0), (4, X.ANDROID_ELF_FORMAT, 64, 64, 16, 0), (4, X.ANDROID_ELF_PACKED_FORMAT, 64, 64, 16, 0),
                   (X.AARCH64_LINUX_ABI, X.AARCH64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 0), (X.AARCH64_LINUX_ABI, X.AARCH64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 0),
                   (3, X.AARCH64_BOARD_ELF_FORMAT, 64, 64, 16, 0))
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-PROFILE", [list(item) for item in allowed], [abi, image_format, word, pointer, stack, shadow]
    if name == "TARGET_ANDROID":
        return "XAX.TARGET.MACHINE", "TARGET-ANDROID-PROFILE", 4, profile
    if name == "TARGET_AARCH64_LINUX":
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-LINUX-PROFILE", 1, profile
    if name == "TARGET_BAREMETAL":
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-BAREMETAL-PROFILE", [1, 2, X.BOARD_PROFILE], profile
    if name == "TARGET_BOARD":
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-BOARD-PROFILE", "board format with board profile", [image_format, profile]
    if name == "TARGET_WASM32":
        return "XAX.TARGET.MACHINE", "TARGET-WASM32-CORE", [2, 2, 64, 32], [abi, image_format, word, pointer]
    rule, expected = {
        "TARGET_RISCV64": ("TARGET-RISCV64-RAW", [1, X.RISCV64_LP64_ABI, X.RISCV64_RAW_FORMAT, 64, 64]),
        "TARGET_SPIRV": ("TARGET-SPIRV-COMPUTE", [1, X.SPIRV_VULKAN_ABI, X.SPIRV_MODULE_FORMAT, 32, 32]),
        "TARGET_JVM": ("TARGET-JVM-CLASSFILE", [1, X.JVM_ABI, X.JVM_JAR_FORMAT, 64, 64]),
        "TARGET_ACCELERATOR": ("TARGET-ACCELERATOR-PROFILE", [3, 4, 3, 32, 64]),
    }[name]
    return "XAX.TARGET.MACHINE", rule, expected, [profile, abi, image_format, word, pointer]


def object_diagnostic(obj, record, objects=()):
    """S8c.19: the bootstrap's ``(code, rule, expected, actual)`` for a rejected object (rendering only: the verifier
    decided the check and its values).  ``objects``: the object table, for quoted object indices."""
    site, (x, y, _z), listed = record[:3]
    name = OBJECT_SITES[site - 1]
    if name.startswith("TARGET_"):
        return _target_diagnostic(obj, name, x, y, listed)
    if name in ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT"):
        first = listed[1:1 + listed[0]]
        second = listed[2 + listed[0]:2 + listed[0] + listed[1 + listed[0]]]
        if name == "GROUP_ENTRY_CONTRACT":
            return "XAX.STRUCT.ENTRY_CONTRACT", "GRAPH-ENTRY-CONTRACT", [objects[i].cid.hex() for i in first], [objects[i].cid.hex() for i in second]
        return "XAX.STRUCT.RETURN_CONTRACT", "GRAPH-RETURN-CONTRACT", [objects[i].cid.hex() for i in first], [objects[i].cid.hex() for i in second]
    if name == "GROUP_MEMBER_RANGE":
        return "XAX.STRUCT.RECURSION_MEMBER", "GRAPH-RECURSION-MEMBER", f"< {listed[0]}", y
    if name == "GROUP_CALL_CONTRACT":
        quote = lambda indices: [objects[i].cid.hex() for i in indices]  # noqa: E731
        parameters, returns, operands, results = listed
        return ("XAX.STRUCT.CALL_CONTRACT", "GRAPH-CALL-CONTRACT", [quote(parameters), quote(returns)], [quote(operands), quote(results)])
    if name == "GROUP_SCC":
        return "XAX.STRUCT.RECURSION_SCC", "GRAPH-RECURSION-SCC", "one recursive strongly connected component", [list(calls) for calls in listed]
    hexes = lambda indices: [objects[index].cid.hex() for index in indices]  # noqa: E731
    if name == "GROUP_EMPTY":
        return "XAX.STRUCT.RECURSION_GROUP_EMPTY", "GRAPH-RECURSION-GROUP-NONEMPTY", ">= 1", 0
    if name == "GROUP_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {x}", y
    if name == "GROUP_CARRIER":
        return "XAX.STRUCT.FUNCTION_GRAPH", "GRAPH-FUNCTION-CARRIER", Kind.GRAPH_FRAGMENT.name, Kind(x).name
    if name == "GROUP_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "RECURSION-GROUP-BODY", 0, x
    if name == "GROUP_UNUSED":
        used = {obj.references[k].hex() for k, marked in enumerate(listed) if marked}
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in obj.references), sorted(used)
    if name in ("FUNCTION_REF_INDEX", "FUNCTION_MEMBER_RANGE"):
        rule = "GRAPH-REF-INDEX" if name == "FUNCTION_REF_INDEX" else "GRAPH-RECURSION-MEMBER"
        return ("XAX.STRUCT.REF_INDEX" if name == "FUNCTION_REF_INDEX" else "XAX.STRUCT.RECURSION_MEMBER"), rule, f"< {x}", y
    if name in ("FUNCTION_MEMBER_TRAILING", "FUNCTION_TRAILING"):
        return "XAX.CANON.TRAILING_BYTES", "FUNCTION-GROUP-MEMBER-BODY" if name == "FUNCTION_MEMBER_TRAILING" else "FUNCTION-BODY", 0, x
    if name == "FUNCTION_CARRIER":
        return "XAX.STRUCT.FUNCTION_GRAPH", "GRAPH-FUNCTION-CARRIER", Kind.GRAPH_FRAGMENT.name, Kind(x).name
    if name in ("FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT"):
        first = listed[1:1 + listed[0]]
        second = listed[2 + listed[0]:2 + listed[0] + listed[1 + listed[0]]]
        if name == "FUNCTION_ENTRY_CONTRACT":
            return "XAX.STRUCT.ENTRY_CONTRACT", "GRAPH-ENTRY-CONTRACT", hexes(first), hexes(second)
        return "XAX.STRUCT.RETURN_CONTRACT", "GRAPH-RETURN-CONTRACT", hexes(first), hexes(second)
    if name == "FUNCTION_UNUSED":
        used = {obj.references[k].hex() for k, marked in enumerate(listed) if marked}
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in obj.references), sorted(used)
    if name == "LIST_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "SCHEMA-BODY", 0, x
    if name == "LIST_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {x}", tuple(listed)
    if name == "LIST_REFERENCE_BODY":
        return "XAX.CANON.REFERENCE_BODY", "SER-REF-BODY-CANONICAL", tuple(range(x)), tuple(listed)
    if name == "LIST_CHILD_KIND":
        allowed = MODULE_CHILDREN if obj.kind == Kind.MODULE else (Kind.MODULE,)
        return "XAX.STRUCT.CHILD_KIND", "GRAPH-CHILD-KIND", sorted(kind.name for kind in allowed), Kind(x).name
    if name == "CONTRACT_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {x}", y
    if name == "CONTRACT_TRUNCATED":
        return "XAX.CANON.TRUNCATED", "SER-BOUNDS", "1 available bytes", 0
    if name == "CONTRACT_BOOL":
        return "XAX.CANON.BOOL", "SER-BOOL-CANONICAL", "00 or 01", f"{x:02x}"
    if name == "CONTRACT_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "CALL-CONTRACT-BODY", 0, x
    if name == "CONTRACT_UNUSED":
        used = sorted(obj.references[k].hex() for k, marked in enumerate(listed) if marked)
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in obj.references), used
    raise ValueError(f"unknown object rejection site {site}")


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
        elif obj.kind in (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.CALL_CONTRACT, Kind.RECURSION_GROUP,
                          Kind.PACKAGE, Kind.BUILD):
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
        import xax_native

        usable = xax_native.usable("store-verifier", STORE_PATH, "XAX_VERIFY_PYTHON")
        _BUILDING.append(True)
        try:
            _NATIVE.append(NativeStoreVerifier() if usable else None)
        except (OSError, RuntimeError, ValueError) as error:
            _NATIVE.append(None)
            xax_native.fallback("store-verifier", f"native image failed to load: {error!r}")
        finally:
            _BUILDING.clear()
    return _NATIVE[0]
