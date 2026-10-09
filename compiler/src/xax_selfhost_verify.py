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
REJECTS_AT, REJECT_WORDS = 3 << 20, 8  # S8c.19 (ADR-237): a rejected object's record: site, payload words
OK = 1
STORE_FAULT = 5  # S8 (ADR-251): the store's own rejection: 1 a cycle (word 6: the object re-entered), 2 unreachable objects (word 6: the colours)
REJECTED = 2  # an object verdict: the bootstrap rejects this object with the recorded diagnostic
ENTITY_CODES = (5, 6, 30, 41, 42, 43)
ATTRIBUTE_CODES = (7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 52, 53, 55, 56, 57,
                   61, 63, 64, 65, 66, 73, 74, 75, 76)
MODULE_CHILDREN = (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT)
# Globals (the first arena words): table pointers.
GLOBALS = ARENA_AT
G_REC, G_O, G_TYPEOK, G_MARK, G_LIST, G_ULEB_STATUS, G_ULEB_SIZE, G_EXIT, G_SINK, G_GROUP_SIZE = range(10)  # G_LIST: a graph contract mismatch's quoted types (S8c.20)
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


def _graph_rejected(e: E, graph):
    """S8 (ADR-251): the XAX graph decoder rejected this graph's body; its payload is the stream prefix before the
    rejection (the word after the body bytes)."""
    stream = _payload(e, graph)
    body_len_at = e.add(stream, e.rd(e.sub(stream, 1)))
    return e.ne(e.rd(e.add(e.add(body_len_at, 1), e.rd(body_len_at))), 0)


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
                # S8 (ADR-251): a member call in an ordinary function's graph (payload: the graph).
                "FUNCTION_GROUP_CONTEXT",
                # S8c.21 (ADR-239): recursion-group member lists (``_decode_recursion_group``, before any member parses).
                "GROUP_EMPTY", "GROUP_REF_INDEX", "GROUP_CARRIER", "GROUP_TRAILING", "GROUP_UNUSED",
                # S8c.22 (ADR-240): after member graphs parse (payload: graphs to parse first, quoted list, [count, graphs]).
                "GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT", "GROUP_MEMBER_RANGE", "GROUP_CALL_CONTRACT", "GROUP_SCC",
                # S8 (ADR-251): the canonical member order (payload: count, the canonical order, graphs).
                "GROUP_ORDER",
                # S8c.23 (ADR-241): targets (``decode_native_target``).
                "TARGET_REFERENCES", "TARGET_IDENTITY_TRUNCATED", "TARGET_IDENTITY_EMPTY", "TARGET_ARCHITECTURE", "TARGET_TRAILING",
                "TARGET_PROFILE", "TARGET_X86_64", "TARGET_RISCV64", "TARGET_SPIRV", "TARGET_JVM", "TARGET_WASM32", "TARGET_AARCH64",
                "TARGET_ANDROID", "TARGET_AARCH64_LINUX", "TARGET_BAREMETAL", "TARGET_BOARD", "TARGET_ACCELERATOR",
                # S8 (ADR-251): per-graph glue (raised inside the graph parse, wherever it is first reached).
                "GRAPH_TRAP_PAYLOAD", "GRAPH_UNUSED",
                # S8 (ADR-251): any body's malformed ULEB (status, body offset, size); a target section's ENUM diagnostic
                # (section, kind, value); target canonical rules (payload: the recorded words, their count, item, check, sub).
                "BODY_ULEB", "TARGET_SECTION", "TARGET_X86_REGISTERS", "TARGET_AAPCS64_REGISTERS", "TARGET_ACC_TOPOLOGY",
                "TARGET_ACC_SCOPES", "TARGET_ACC_SPACES", "TARGET_ACC_SPACE", "TARGET_ACC_OPERATIONS", "TARGET_ACC_CONTRACT",
                "TARGET_PLATFORM_OPERATIONS", "TARGET_PLATFORM_CONTRACT", "TARGET_OPERATIONS", "TARGET_TERMINATORS",
                "TARGET_ATOMIC_WIDTHS", "TARGET_ATOMIC_CAPABILITIES", "TARGET_HANDLER_ORDER", "TARGET_HANDLER",
                # S8: a reference naming no stored object (payload: the reference's index).
                "OBJECT_MISSING",
                # S8: cursor faults in any body (take: size, available; bool: the byte; trailing: rule, bytes left), build
                # references (count, index), build enums (enum, value), and build rules (rule, recorded words, their count,
                # item, extra).
                "BODY_TAKE", "BODY_BOOL", "BODY_TRAILING", "BUILD_REF_INDEX", "BUILD_ENUM", "BUILD_RULE",
                # S8: ``_build_form`` of another object (payload: the object): its BUILD-KIND diagnostic, or its own form
                # rejection.
                "BUILD_KIND_OF", "OTHER_OBJECT")
AFTER_PARSE = ("FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT", "FUNCTION_UNUSED", "FUNCTION_GROUP_CONTEXT")
GROUP_AFTER_PARSE = ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT", "GROUP_MEMBER_RANGE", "GROUP_CALL_CONTRACT", "GROUP_SCC", "GROUP_ORDER")
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


def _read(e: E, name: str, end, obj=None, start=None):
    """A canonical ULEB at ``p[name]``, inside ``end``; advances it (verdict 0 otherwise).  S8 (ADR-251): with ``obj``
    and its body ``start``, a malformed ULEB rejects ``obj`` as ``Cursor.uleb`` does (``BODY_ULEB``)."""
    p = e.p
    if obj is not None:
        return _strict(e, name, end, obj, start)
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


def _type_reference(e: E, obj, name: str, end, reject_site=None, start=None):
    """A reference index read at ``p[name]`` naming a proven type; marks it and returns the object.

    ``reject_site``: an index out of range is that rejection (``GRAPH-REF-INDEX``) instead of a decline."""
    p = e.p
    index = _read(e, name, end, obj if start is not None else None, start)
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


def _interface(e: E, obj, name: str, end, reject_site=None, start=None):
    """Parameter and return types read at ``p[name]`` into a new ``[P, types, R, types]`` record."""
    p = e.p
    e.var(f"{name}_if", e.alloc(e.add(e.sub(end, p[name]), 3)))  # at most one type per body byte
    _no(e, e.eq(p[f"{name}_if"], NONE))
    record = p[f"{name}_if"]
    strict = obj if start is not None else None
    e.var(f"{name}_np", _read(e, name, end, strict, start))
    e.st(record, p[f"{name}_np"])
    e.for_("q", 0, p[f"{name}_np"], lambda: e.st(e.add(e.add(p[f"{name}_if"], 1), p["q"]), _type_reference(e, obj, name, end, reject_site, start)))
    e.var(f"{name}_rt", e.add(e.add(p[f"{name}_if"], 1), p[f"{name}_np"]))
    e.st(p[f"{name}_rt"], _read(e, name, end, strict, start))
    e.for_("q", 0, e.ld(p[f"{name}_rt"]), lambda: e.st(e.add(e.add(p[f"{name}_rt"], 1), p["q"]), _type_reference(e, obj, name, end, reject_site, start)))
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
        e.var("fbody", p["fa"])
        end = e.add(p["fa"], e.rd(e.sub(p["fa"], 1)))
        e.var("fend", end)
        _clear_marks(e, p["refs"])
        graph_index = _read(e, "fa", p["fend"], f, p["fbody"])
        e.var("gi", graph_index)
        _reject(e, e.le(p["refs"], p["gi"]), f, S["FUNCTION_REF_INDEX"], p["refs"], p["gi"])
        e.var("graph", _reference(e, f, p["gi"]))
        _no(e, e.eq(p["graph"], NONE))

        def member_function():
            # ``decode_group_member_function``: [group, member], the group proven (S6b.3), member < its size.
            e.var("member", _read(e, "fa", p["fend"], f, p["fbody"]))
            _reject(e, e.ne(p["fa"], p["fend"]), f, S["FUNCTION_MEMBER_TRAILING"], e.sub(p["fend"], p["fa"]))
            # S8 (ADR-251): ``_decode_recursion_group`` is all the bootstrap runs here (the group verifies itself).
            size = e.ld(e.add(_g(e, G_GROUP_SIZE), p["graph"]))
            _no(e, e.eq(size, NONE))
            _reject(e, e.le(size, p["member"]), f, S["FUNCTION_MEMBER_RANGE"], size, p["member"])
            e.st(e.add(GRAPHS_AT, f), NONE)
            e.give(1)

        e.if_(e.both(e.eq(p["refs"], 1), e.eq(_kind(e, p["graph"]), int(Kind.RECURSION_GROUP))), member_function)
        _no(e, e.eq(_kind(e, p["graph"]), int(Kind.RECURSION_GROUP)))
        _reject(e, e.ne(_kind(e, p["graph"]), int(Kind.GRAPH_FRAGMENT)), f, S["FUNCTION_CARRIER"], _kind(e, p["graph"]))
        _mark(e, p["gi"])
        e.var("iface", _interface(e, f, "fa", p["fend"], S["FUNCTION_REF_INDEX"], p["fbody"]))
        _reject(e, e.ne(p["fa"], p["fend"]), f, S["FUNCTION_TRAILING"], e.sub(p["fend"], p["fa"]))
        # After the bootstrap's graph parse: the graph contract, then the references used.  A graph the decoder
        # rejected raises in that parse (its glue decides what precedes the rejection).
        _no(e, _graph_rejected(e, p["graph"]))
        e.var("contract", e.call(_FN["graph"], p["graph"], p["iface"], NONE, NONE))
        _reject(e, e.eq(p["contract"], 7), f, S["FUNCTION_GROUP_CONTEXT"], p["graph"])
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
                # S8 (ADR-251): a member call outside a group: ``_verify_function``'s GROUP-CALL-CONTEXT (code 7).
                e.if_(e.both(e.eq(p["members"], NONE), e.eq(e.rd(p["ga"]), int(Operation.CALL_GROUP_MEMBER))), lambda: e.set("context", 1))
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

        e.var("context", 0)
        e.for_("b", 0, p["B"], place)
        e.if_(e.ne(p["context"], 0), lambda: e.give(7))
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
        e.var("gbody", p["ga"])
        end = e.add(p["ga"], e.rd(e.sub(p["ga"], 1)))
        e.var("gend", end)
        _clear_marks(e, p["refs"])
        _no(e, e.eq(_resolved(e, o), 0))
        e.var("count", _read(e, "ga", p["gend"], o, p["gbody"]))
        _reject(e, e.eq(p["count"], 0), o, S["GROUP_EMPTY"])
        # At most one member per body byte: a larger count faults on a read first.
        e.var("cap", e.add(e.sel(e.lt(p["count"], e.sub(p["gend"], p["ga"])), p["count"], e.sub(p["gend"], p["ga"])), 1))
        e.var("table", e.alloc(p["cap"]))  # [count, interface records]
        e.var("graphs", e.alloc(p["cap"]))  # [count, graph objects]
        e.var("callsof", e.alloc(p["cap"]))
        _no(e, e.either(e.eq(p["table"], NONE), e.eq(p["graphs"], NONE), e.eq(p["callsof"], NONE)))
        e.st(p["table"], p["count"])
        e.st(p["graphs"], p["count"])

        def member():
            e.var("gi", _read(e, "ga", p["gend"], o, p["gbody"]))
            _reject(e, e.le(p["refs"], p["gi"]), o, S["GROUP_REF_INDEX"], p["refs"], p["gi"])
            e.var("mg", _reference(e, o, p["gi"]))
            _no(e, e.eq(p["mg"], NONE))
            _reject(e, e.ne(_kind(e, p["mg"]), int(Kind.GRAPH_FRAGMENT)), o, S["GROUP_CARRIER"], _kind(e, p["mg"]))
            _mark(e, p["gi"])
            e.st(e.add(e.add(p["graphs"], 1), p["i"]), p["mg"])
            e.st(e.add(e.add(p["table"], 1), p["i"]), _interface(e, o, "ga", p["gend"], S["GROUP_REF_INDEX"], p["gbody"]))

        e.for_("i", 0, p["count"], member)
        _reject(e, e.ne(p["ga"], p["gend"]), o, S["GROUP_TRAILING"], e.sub(p["gend"], p["ga"]))
        _reject(e, e.eq(_all_marked(e, p["refs"]), 0), o, S["GROUP_UNUSED"], _list_copy(e, p["refs"], lambda k: e.ld(e.add(_g(e, G_MARK), k))))
        e.st(e.add(_g(e, G_GROUP_SIZE), o), p["count"])  # ``_decode_recursion_group`` accepts

        def contract():
            g = e.ld(e.add(e.add(p["graphs"], 1), p["i"]))
            e.var("cg", g)
            _no(e, _graph_rejected(e, p["cg"]))
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

        # S8 (ADR-251): the canonical order is the smallest descriptor over every start (the first start on a tie);
        # start 0's order and positions are the first best.
        e.var("bestord", e.alloc(e.add(p["count"], 1)))
        e.var("bestpos", e.alloc(e.add(p["count"], 1)))
        e.var("candpos", e.alloc(e.add(p["count"], 1)))
        _no(e, e.either(e.eq(p["bestord"], NONE), e.eq(p["bestpos"], NONE), e.eq(p["candpos"], NONE)))
        discover(0, p["order0"])
        e.for_("k", 0, p["count"], lambda: (e.st(e.add(p["bestord"], p["k"]), e.ld(e.add(p["order0"], p["k"]))),
                                            e.st(e.add(p["bestpos"], p["k"]), e.ld(e.add(p["position"], p["k"])))))

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

        def compare(order_a, position_a, order_b, position_b):
            """``kd`` for two candidate orders' descriptors (``position_*``: member -> its position in that order)."""
            e.var("kd", 0)

            def position():
                e.var("pa", e.ld(e.add(order_a, p["k"])))
                e.var("pb", e.ld(e.add(order_b, p["k"])))
                e.if_(e.ne(p["pa"], p["pb"]), lambda: key_compare(p["pa"], p["pb"]))
                e.var("pba", e.ld(e.add(p["callsof"], p["pa"])))
                e.var("pbb", e.ld(e.add(p["callsof"], p["pb"])))
                # Then the renumbered callees.
                e.if_(e.eq(p["kd"], 0), lambda: lexicographic(
                    e.ld(p["pba"]), e.ld(p["pbb"]), lambda c: position_a(e.ld(e.add(e.add(p["pba"], 1), e.mul(c, 3)))),
                    lambda c: position_b(e.ld(e.add(e.add(p["pbb"], 1), e.mul(c, 3)))), False))

            e.for_("k", 0, p["count"], lambda: e.if_(e.eq(p["kd"], 0), position))
            return p["kd"]

        def start():
            discover(p["s"], p["order"])
            e.for_("k", 0, p["count"], lambda: e.st(e.add(p["candpos"], p["k"]), e.ld(e.add(p["position"], p["k"]))))
            compare(p["order"], lambda m: e.ld(e.add(p["candpos"], m)), p["bestord"], lambda m: e.ld(e.add(p["bestpos"], m)))
            e.if_(e.eq(p["kd"], 1), lambda: e.for_("k", 0, p["count"], lambda: (
                e.st(e.add(p["bestord"], p["k"]), e.ld(e.add(p["order"], p["k"]))),
                e.st(e.add(p["bestpos"], p["k"]), e.ld(e.add(p["candpos"], p["k"]))))))

        e.for_("s", 1, p["count"], start)
        # The stored order's descriptor (the identity's) must be the canonical one.
        e.var("identity", e.alloc(e.add(p["count"], 1)))
        _no(e, e.eq(p["identity"], NONE))
        e.for_("k", 0, p["count"], lambda: e.st(e.add(p["identity"], p["k"]), p["k"]))
        compare(p["bestord"], lambda m: e.ld(e.add(p["bestpos"], m)), p["identity"], lambda m: m)
        _reject(e, e.ne(p["kd"], 0), o, S["GROUP_ORDER"], p["count"], _list_copy(e, p["count"], lambda k: e.ld(e.add(p["bestord"], k))), p["graphs"])
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


def _uleb10_fn(tables):
    """S8 (ADR-251): ``Cursor.uleb`` at input word ``at`` inside ``end``: the value, with G_ULEB_STATUS 0 (canonical),
    1 (unterminated: the body ends first), 2 (non-minimal), 3 (more than ten bytes), or 4 (a ten-byte value, which
    may not fit a word) and G_ULEB_SIZE (the bytes read)."""
    def build(e: E):
        p = e.p
        e.var("u_value", 0)
        e.var("u_scale", 1)
        e.var("u_status", 3)
        e.var("u_size", 10)
        e.var("u_k", 0)
        e.var("u_go", 1)

        def step():
            position = e.add(p["at"], p["u_k"])

            def inside():
                e.var("u_byte", e.rd(position))
                e.set("u_value", e.add(p["u_value"], e.mul(e.and_(p["u_byte"], 127), p["u_scale"])))
                e.set("u_scale", e.mul(p["u_scale"], 128))

                def ends():
                    e.set("u_status", e.sel(e.both(e.eq(p["u_byte"], 0), e.ne(p["u_k"], 0)), 2, e.sel(e.eq(p["u_k"], 9), 4, 0)))
                    e.set("u_size", e.add(p["u_k"], 1))
                    e.set("u_go", 0)

                e.if_(e.lt(p["u_byte"], 128), ends)

            def outside():
                e.set("u_status", 1)
                e.set("u_size", p["u_k"])
                e.set("u_go", 0)

            e.if_(e.lt(position, p["end"]), inside, outside)
            e.set("u_k", e.add(p["u_k"], 1))

        e.while_(lambda: e.both(e.ne(p["u_go"], 0), e.lt(p["u_k"], 10)), step)
        e.st(GLOBALS + G_ULEB_STATUS, p["u_status"])
        e.st(GLOBALS + G_ULEB_SIZE, p["u_size"])
        e.give(p["u_value"])
    return _function(("at", "end"), build, tables)


def _strict_read_fn(tables):
    """S8 (ADR-251): ``Cursor.uleb`` of object ``o``'s body at ``at`` (inside ``end``, the body starting at ``start``),
    the value stored at ``slot``.  G_EXIT is 1 to go on, or the caller's verdict: REJECTED with the record written
    (``BODY_ULEB``, or inside target section ``region`` its ``TARGET_SECTION``), or 0 (a ten-byte value: declined).
    G_ULEB_SIZE: the bytes read."""
    def build(e: E):
        p = e.p
        e.var("sv", e.call(_FN["uleb10"], p["at"], p["end"]))
        e.var("ss", _g(e, G_ULEB_STATUS))
        e.st(p["slot"], p["sv"])
        e.st(GLOBALS + G_EXIT, e.sel(e.eq(p["ss"], 0), 1, e.sel(e.eq(p["ss"], 4), 0, REJECTED)))

        def record():
            at = e.add(REJECTS_AT, e.mul(p["o"], REJECT_WORDS))
            e.if_(e.eq(p["region"], 0), lambda: (e.st(at, S["BODY_ULEB"]), e.st(e.add(at, 1), p["ss"]), e.st(e.add(at, 2), e.sub(p["at"], p["start"])),
                                                 e.st(e.add(at, 3), _g(e, G_ULEB_SIZE))),
                  lambda: (e.st(at, S["TARGET_SECTION"]), e.st(e.add(at, 1), p["region"]), e.st(e.add(at, 2), p["ss"]), e.st(e.add(at, 3), 0)))

        e.if_(e.both(e.ne(p["ss"], 0), e.ne(p["ss"], 4)), record)
        e.give(p["sv"])
    return _function(("o", "at", "end", "start", "region", "slot"), build, tables)


def _strict(e: E, name: str, end, obj, start, region=0, slot=None):
    """A strict ``Cursor.uleb`` at ``p[name]`` through ``_strict_read_fn``: the value (also stored at ``slot``); a
    malformed ULEB returns the caller's verdict."""
    p = e.p
    e.var(f"{name}_value", e.call(_FN["tread"], obj, p[name], end, start, region, GLOBALS + G_SINK if slot is None else slot))
    e.if_(e.ne(_g(e, G_EXIT), 1), lambda: e.give(_g(e, G_EXIT)))
    e.set(name, e.add(p[name], _g(e, G_ULEB_SIZE)))
    return p[f"{name}_value"]


def _target_ok(tables):
    """``decode_native_target(allow_carrier=True)``, decided in full (S8, ADR-251): the body is read in the
    bootstrap's order, every value recorded in a word list (a rejection quotes it); a malformed field rejects where
    the cursor fails (inside a concurrency, accelerator, or platform section, with that section's ENUM diagnostic,
    as the bootstrap's ``except ValueError`` reports it); the canonical rules are then checked in the bootstrap's
    order."""
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
    assert [int(item) for item in AtomicFamily] == list(range(1, len(AtomicFamily) + 1))
    assert [int(item) for item in TargetValueConstraintKind] == list(range(1, constraint_kinds + 1))

    known_architectures = (1, 2, 3, 4, JVM_ARCHITECTURE, RISCV64_ARCHITECTURE, SPIRV_ARCHITECTURE)
    state = ("region", "words", "wn", "rv", "rs", "rz", "bv", "prev", "bad", "count", "regs_bad", "topo_bad", "ascope_bad", "accmask",
             "spaces", "space_ids", "sid_bad", "space_bad", "opid_bad", "contract_bad", "contract_check", "contract_sub", "ops_bad",
             "terms_bad", "widths_bad", "caps_bad", "event_bad", "handler_bad", "stack", "shadow", "lane", "groups")

    def build(e: E):
        p = e.p
        o = p["o"]
        _no(e, e.eq(_resolved(e, o), 0))
        _reject(e, e.ne(_references(e, o), 0), o, S["TARGET_REFERENCES"])
        e.var("ta", _payload(e, o))
        e.var("tbody", p["ta"])
        e.var("tend", e.add(p["ta"], e.rd(e.sub(p["ta"], 1))))
        for name in state:
            e.var(name, 0)
        for name in ("space_bad", "contract_bad", "handler_bad"):
            e.set(name, NONE)
        e.set("words", e.alloc(e.add(e.sub(p["tend"], p["ta"]), 4)))
        _no(e, e.eq(p["words"], NONE))

        def record(value):
            e.st(e.add(p["words"], p["wn"]), value)
            e.set("wn", e.add(p["wn"], 1))

        def read():
            """The next ULEB (recorded); a malformed one rejects."""
            e.set("rv", _strict(e, "ta", p["tend"], o, p["tbody"], p["region"], e.add(p["words"], p["wn"])))
            e.set("wn", e.add(p["wn"], 1))
            return p["rv"]

        def enum(name, high, kind):
            """``Enum(read())`` inside a section: an unknown value rejects with the enum's message."""
            e.var(name, read())
            e.if_(e.either(e.eq(p[name], 0), e.lt(high, p[name])), lambda: _reject(e, None, o, S["TARGET_SECTION"], p["region"], kind, p[name]))
            return p[name]

        def take_byte(name):
            e.if_(e.le(p["tend"], p["ta"]), lambda: _reject(e, None, o, S["TARGET_SECTION"], p["region"], 5, 0))
            e.var(name, e.rd(p["ta"]))
            e.set("ta", e.add(p["ta"], 1))
            record(p[name])

        def flags():
            """Two ``take(1)`` flags, then the section's BOOL check (reported as its ENUM diagnostic)."""
            take_byte("flag_a")
            take_byte("flag_b")
            e.if_(e.either(e.lt(1, p["flag_a"]), e.lt(1, p["flag_b"])), lambda: _reject(e, None, o, S["TARGET_SECTION"], p["region"], 6, 0))

        def byte_string():
            e.var("blen", read())
            e.if_(e.lt(e.sub(p["tend"], p["ta"]), p["blen"]), lambda: _reject(e, None, o, S["TARGET_SECTION"], p["region"], 5, 0))
            e.set("ta", e.add(p["ta"], p["blen"]))
            return p["blen"]

        def increasing(name, value, low=None):
            """Track a strictly increasing list in ``prev`` (value + 1); set ``name`` when it is not (or below ``low``)."""
            bad = e.both(e.ne(p["prev"], 0), e.le(e.add(value, 1), p["prev"]))
            if low is not None:
                bad = e.either(bad, e.lt(value, low))
            e.if_(bad, lambda: e.set(name, 1))
            e.set("prev", e.add(value, 1))

        e.var("ilen", read())
        _reject(e, e.lt(e.sub(p["tend"], p["ta"]), p["ilen"]), o, S["TARGET_IDENTITY_TRUNCATED"], p["ilen"], e.sub(p["tend"], p["ta"]))
        _reject(e, e.eq(p["ilen"], 0), o, S["TARGET_IDENTITY_EMPTY"])
        e.set("ta", e.add(p["ta"], p["ilen"]))
        e.if_(e.eq(p["ta"], p["tend"]), lambda: e.give(1))  # an identity-only carrier
        for name in ("profile", "arch", "abi", "format", "word", "pointer"):
            e.var(name, read())
        _reject(e, e.not_(e.either(*(e.eq(p["arch"], code) for code in known_architectures))), o, S["TARGET_ARCHITECTURE"], p["arch"])
        e.set("stack", 1)

        def registers(arguments, scratch):
            e.set("stack", read())
            e.set("shadow", read())

            def exact(name, expected):
                """``tuple(cursor.uleb() for _ in range(cursor.uleb()))``: ``regs_bad`` unless it is ``expected``."""
                e.var(f"{name}_n", read())
                e.if_(e.ne(p[f"{name}_n"], len(expected)), lambda: e.set("regs_bad", 1))

                def item():
                    e.var("rg", read())
                    wanted = e.c(NONE)
                    for k in reversed(range(len(expected))):
                        wanted = e.sel(e.eq(p[f"{name}_q"], k), expected[k], wanted)
                    e.if_(e.ne(p["rg"], wanted), lambda: e.set("regs_bad", 1))

                e.for_(f"{name}_q", 0, p[f"{name}_n"], item)

            exact("ra", arguments)
            e.if_(e.ne(read(), 0), lambda: e.set("regs_bad", 1))  # the result register
            exact("rsc", scratch)

        e.if_(e.eq(p["arch"], 1), lambda: registers((1, 2, 8, 9), (10, 11)))
        e.if_(e.eq(p["arch"], 3), lambda: registers(tuple(range(8)), (9, 10)))

        def plain_list(flag, high, low=1):
            """``tuple(cursor.uleb() for _ in range(cursor.uleb()))``: ``flag`` set unless strictly increasing in low..high."""
            e.set("count", read())
            e.set("prev", 0)

            def item():
                e.var("li", read())
                increasing(flag, p["li"], low)
                if high is not None:
                    e.if_(e.lt(high, p["li"]), lambda: e.set(flag, 1))

            e.for_("lq", 0, p["count"], item)

        plain_list("ops_bad", len(operations))
        plain_list("terms_bad", len(terminators))

        def concurrency():
            plain_list("widths_bad", None)
            e.set("region", 1)
            for kind, high in ((7, scopes), (8, len(AtomicFamily))):
                e.set("count", read())
                e.set("prev", 0)
                e.for_(f"cq{kind}", 0, p["count"], lambda kind=kind, high=high: increasing("caps_bad", enum("cv", high, kind)))
            e.var("handlers", read())
            e.var("event_prev", 0)

            def handler():
                e.var("hkind", read())
                e.if_(e.both(e.ne(p["event_prev"], 0), e.le(e.add(p["hkind"], 1), p["event_prev"])), lambda: e.set("event_bad", 1))
                e.set("event_prev", e.add(p["hkind"], 1))
                for _field in range(6):
                    read()
                e.set("bad", 0)
                e.set("count", read())
                e.set("prev", 0)
                e.for_("dq", 0, p["count"], lambda: increasing("bad", enum("dv", domains, 9)))
                e.if_(e.eq(read(), 0), lambda: e.set("bad", 1))  # the stack bound
                read()
                e.if_(e.both(e.ne(p["bad"], 0), e.eq(p["handler_bad"], NONE)), lambda: e.set("handler_bad", p["h"]))

            e.for_("h", 0, p["handlers"], handler)
            e.set("region", 0)

        def contracts(section: int):
            """Target-operation contracts: section 2 accelerator, 3 platform, 4 board (no canonical rules)."""
            e.set("region", 2 if section == 2 else 3)
            e.var("ccount", read())
            e.var("cprev", 0)
            if section != 4:
                e.if_(e.eq(p["ccount"], 0), lambda: e.set("opid_bad", 1))

            def fault(check, sub=0):
                def mark():
                    e.set("contract_bad", p["ci"])
                    e.set("contract_check", check)
                    e.set("contract_sub", sub)
                return lambda: e.if_(e.eq(p["contract_bad"], NONE), mark)

            def contract():
                e.var("cop", read())
                e.if_(e.both(e.ne(p["cprev"], 0), e.le(e.add(p["cop"], 1), p["cprev"])), lambda: e.set("opid_bad", 1))
                e.set("cprev", e.add(p["cop"], 1))
                e.var("csem", read())
                e.var("cenc", read())
                if section == 2:
                    e.if_(e.either(e.eq(p["csem"], 0), e.lt(255, p["cenc"])), fault(1))
                e.var("cn_index", 0)
                e.var("cn_bad", NONE)
                for _signature in range(2):
                    e.var("vcount", read())

                    def constraint():
                        e.var("vk", enum("vk_", constraint_kinds, 10))
                        e.var("vp", read())
                        e.var("vs", read())
                        bad = e.either(
                            e.both(e.eq(p["vk"], 1), e.either(e.eq(p["vp"], 0), e.ne(p["vs"], 0))),
                            e.both(e.eq(p["vk"], 2), e.either(e.eq(p["vp"], 0), e.eq(p["vs"], 0))),
                            e.both(e.eq(p["vk"], 3), e.either(e.eq(p["vp"], 0), e.lt(domains, p["vp"]))),
                            e.both(e.lt(3, p["vk"]), e.either(e.ne(p["vp"], 0), e.ne(p["vs"], 0))),
                        )
                        e.if_(e.both(bad, e.eq(p["cn_bad"], NONE)), lambda: e.set("cn_bad", p["cn_index"]))
                        e.set("cn_index", e.add(p["cn_index"], 1))

                    e.for_("vq", 0, p["vcount"], constraint)
                e.set("bad", 0)
                e.set("count", read())
                e.if_(e.eq(p["count"], 0), lambda: e.set("bad", 1))
                e.set("prev", 0)
                e.var("csub", 0)  # 1 when a scope is not one of the accelerator's

                def scope():
                    e.var("sv", enum("sv_", scopes, 7))
                    increasing("bad", p["sv"])
                    e.if_(e.eq(e.and_(p["accmask"], e.sel(e.eq(p["sv"], 1), 1, e.sel(e.eq(p["sv"], 2), 2, 4))), 0), lambda: e.set("csub", 1))

                e.for_("csq", 0, p["count"], scope)
                e.var("csrc", read())
                e.var("cdst", read())
                flags()
                e.var("cdep", byte_string())
                dependency = e.both(e.ne(p["cdep"], 0), e.ne(p["cdep"], 32))
                if section == 2:
                    e.if_(e.either(e.ne(p["bad"], 0), e.ne(p["csub"], 0)), fault(2))
                    for name in ("csrc", "cdst"):
                        e.var("member", 0)
                        e.for_("mq", 0, p["spaces"], lambda name=name: e.if_(e.eq(e.ld(e.add(p["space_ids"], p["mq"])), p[name]), lambda: e.set("member", 1)))
                        e.if_(e.eq(p["member"], 0), fault(3))
                    e.if_(e.ne(p["cn_bad"], NONE), lambda: fault(4, p["cn_bad"])())
                    e.if_(dependency, fault(5))
                elif section == 3:
                    e.if_(e.either(e.eq(p["csem"], 0), e.ne(p["bad"], 0)), fault(1))
                    e.if_(e.ne(p["cn_bad"], NONE), lambda: fault(2, p["cn_bad"])())
                    e.if_(dependency, fault(3))

            e.for_("ci", 0, p["ccount"], contract)
            e.set("region", 0)

        def accelerator():
            e.set("lane", read())
            e.set("groups", read())
            e.if_(e.either(e.eq(p["lane"], 0), e.eq(p["groups"], 0)), lambda: e.set("topo_bad", 1))
            e.set("region", 2)
            e.set("count", read())
            e.if_(e.eq(p["count"], 0), lambda: e.set("ascope_bad", 1))
            e.set("prev", 0)

            def scope():
                e.var("av", enum("av_", scopes, 7))
                increasing("ascope_bad", p["av"])
                e.set("accmask", e.or_(p["accmask"], e.sel(e.eq(p["av"], 1), 1, e.sel(e.eq(p["av"], 2), 2, 4))))

            e.for_("aq", 0, p["count"], scope)
            e.set("spaces", read())
            e.if_(e.eq(p["spaces"], 0), lambda: e.set("sid_bad", 1))
            e.set("space_ids", e.alloc(e.add(e.sel(e.lt(p["spaces"], e.sub(p["tend"], p["ta"])), p["spaces"], e.sub(p["tend"], p["ta"])), 1)))
            _no(e, e.eq(p["space_ids"], NONE))
            e.var("sprev", 0)

            def space():
                e.var("sid", read())
                e.if_(e.both(e.ne(p["sprev"], 0), e.le(e.add(p["sid"], 1), p["sprev"])), lambda: e.set("sid_bad", 1))
                e.set("sprev", e.add(p["sid"], 1))
                e.st(e.add(p["space_ids"], p["spq"]), p["sid"])
                e.set("bad", 0)
                for name in ("abits", "ubits", "align"):
                    e.var(name, read())
                    e.if_(e.eq(p[name], 0), lambda: e.set("bad", 1))
                e.if_(e.not_(e.power_of_two(p["align"])), lambda: e.set("bad", 1))
                e.set("count", read())
                e.set("prev", 0)
                e.for_("wq", 0, p["count"], lambda: increasing("bad", read(), 1))  # access widths
                e.set("count", read())
                e.set("prev", 0)
                e.for_("vq_", 0, p["count"], lambda: increasing("bad", enum("vv", scopes, 7)))  # visibility scopes
                flags()
                e.if_(e.both(e.ne(p["bad"], 0), e.eq(p["space_bad"], NONE)), lambda: e.set("space_bad", p["spq"]))

            e.for_("spq", 0, p["spaces"], space)
            contracts(2)

        e.if_(e.either(e.eq(p["profile"], 2), e.eq(p["profile"], BOARD_PROFILE)), concurrency)
        e.if_(e.eq(p["profile"], 3), accelerator)
        e.if_(e.eq(p["profile"], 4), lambda: contracts(3))
        e.if_(e.eq(p["profile"], BOARD_PROFILE), lambda: contracts(4))
        _reject(e, e.ne(p["ta"], p["tend"]), o, S["TARGET_TRAILING"], e.sub(p["tend"], p["ta"]))
        _reject(e, e.either(e.lt(p["profile"], 1), e.lt(BOARD_PROFILE, p["profile"])), o, S["TARGET_PROFILE"], p["profile"])

        def quoted(site, index=0, check=0, sub=0):
            """Reject at ``site`` quoting the recorded words (and the failing item)."""
            return lambda: _reject(e, None, o, S[site], p["words"], p["wn"], index, check, sub)

        def machine(abi, image_format, word, pointer):
            return e.both(e.eq(p["abi"], abi), e.eq(p["format"], image_format), e.eq(p["word"], word), e.eq(p["pointer"], pointer))

        def fields(site):
            """Reject at ``site`` quoting the machine record (profile, abi, format, word, pointer, stack, shadow)."""
            def record_machine():
                e.var("mq", e.alloc(8))
                _no(e, e.eq(p["mq"], NONE))
                for k, name in enumerate(("profile", "abi", "format", "word", "pointer", "stack", "shadow")):
                    e.st(e.add(p["mq"], k), p[name])
                _reject(e, None, o, S[site], p["mq"])
            return record_machine

        def x86_64():
            allowed = e.either(*(machine(abi, image_format, 64, 64) for abi, image_format in X86_64_MACHINES))
            e.if_(e.not_(e.both(allowed, e.eq(p["stack"], 16), e.eq(p["shadow"], 32))), fields("TARGET_X86_64"))
            e.if_(e.ne(p["regs_bad"], 0), quoted("TARGET_X86_REGISTERS"))

        def aarch64():
            machines = (*AARCH64_MACHINES, (4, ANDROID_ELF_FORMAT), (4, ANDROID_ELF_PACKED_FORMAT), (3, AARCH64_BOARD_ELF_FORMAT))
            allowed = e.either(*(machine(abi, image_format, 64, 64) for abi, image_format in machines))
            e.if_(e.not_(e.both(allowed, e.eq(p["stack"], 16), e.eq(p["shadow"], 0))), fields("TARGET_AARCH64"))
            e.if_(e.both(e.eq(p["abi"], 4), e.ne(p["profile"], 4)), fields("TARGET_ANDROID"))  # Android: profile 4
            e.if_(e.both(e.eq(p["abi"], 5), e.ne(p["profile"], 1)), fields("TARGET_AARCH64_LINUX"))  # aarch64 Linux: profile 1
            e.if_(e.both(e.eq(p["abi"], 3), e.ne(p["profile"], 1), e.ne(p["profile"], 2), e.ne(p["profile"], BOARD_PROFILE)), fields("TARGET_BAREMETAL"))
            e.if_(e.ne(e.flag(e.eq(p["format"], AARCH64_BOARD_ELF_FORMAT)), e.flag(e.eq(p["profile"], BOARD_PROFILE))), fields("TARGET_BOARD"))
            e.if_(e.ne(p["regs_bad"], 0), quoted("TARGET_AAPCS64_REGISTERS"))

        def five(site, profile, abi, image_format, word, pointer):
            return lambda: e.if_(e.either(e.ne(p["profile"], profile), e.not_(machine(abi, image_format, word, pointer))), fields(site))

        def accelerator_rules():
            five("TARGET_ACCELERATOR", 3, 4, 3, 32, 64)()
            e.if_(e.ne(p["topo_bad"], 0), quoted("TARGET_ACC_TOPOLOGY"))
            e.if_(e.ne(p["ascope_bad"], 0), quoted("TARGET_ACC_SCOPES"))
            e.if_(e.ne(p["sid_bad"], 0), quoted("TARGET_ACC_SPACES"))
            e.if_(e.ne(p["space_bad"], NONE), quoted("TARGET_ACC_SPACE", p["space_bad"]))
            e.if_(e.ne(p["opid_bad"], 0), quoted("TARGET_ACC_OPERATIONS"))
            e.if_(e.ne(p["contract_bad"], NONE), quoted("TARGET_ACC_CONTRACT", p["contract_bad"], p["contract_check"], p["contract_sub"]))

        known = {
            1: x86_64,
            3: aarch64,
            2: lambda: e.if_(e.not_(machine(2, 2, 64, 32)), fields("TARGET_WASM32")),
            4: accelerator_rules,
            RISCV64_ARCHITECTURE: five("TARGET_RISCV64", 1, RISCV64_LP64_ABI, RISCV64_RAW_FORMAT, 64, 64),
            SPIRV_ARCHITECTURE: five("TARGET_SPIRV", 1, SPIRV_VULKAN_ABI, SPIRV_MODULE_FORMAT, 32, 32),
            JVM_ARCHITECTURE: five("TARGET_JVM", 1, JVM_ABI, JVM_JAR_FORMAT, 64, 64),
        }
        for architecture, check in known.items():
            e.if_(e.eq(p["arch"], architecture), check)

        def platform_rules():
            e.if_(e.ne(p["opid_bad"], 0), quoted("TARGET_PLATFORM_OPERATIONS"))
            e.if_(e.ne(p["contract_bad"], NONE), quoted("TARGET_PLATFORM_CONTRACT", p["contract_bad"], p["contract_check"], p["contract_sub"]))

        e.if_(e.eq(p["profile"], 4), platform_rules)
        for flag, site in (("ops_bad", "TARGET_OPERATIONS"), ("terms_bad", "TARGET_TERMINATORS"), ("widths_bad", "TARGET_ATOMIC_WIDTHS"),
                           ("caps_bad", "TARGET_ATOMIC_CAPABILITIES"), ("event_bad", "TARGET_HANDLER_ORDER")):
            e.if_(e.ne(p[flag], 0), quoted(site))
        e.if_(e.ne(p["handler_bad"], NONE), quoted("TARGET_HANDLER", p["handler_bad"]))
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
        e.var("all_resolved", _resolved(e, g))  # a rejection needs every reference stored (the parse resolves them)
        e.var("gs", _payload(e, g))
        e.var("body_len_at", e.add(p["gs"], e.rd(e.sub(p["gs"], 1))))
        e.var("body_at", e.add(p["body_len_at"], 1))
        e.var("prefix", e.flag(_graph_rejected(e, g)))
        e.var("gend", e.add(p["gs"], e.rd(e.sub(p["gs"], 1))))
        # S8 (ADR-251): over a rejected graph's prefix, the checks run until the prefix ends (the decoder's
        # rejection follows in body order); the stream of an accepted graph never ends early.
        need = lambda words: e.if_(e.lt(p["gend"], e.add(p["ga"], words)), lambda: e.give(0))  # noqa: E731
        e.var("ga", p["gs"])
        need(2)
        e.var("B", e.rd(p["gs"]))
        e.set("ga", e.add(p["gs"], 2))
        for name in ("ti", "tobj", "pc", "nc", "opc", "ei", "oc", "rc", "kind", "ac", "vc", "tsize", "tat", "b0", "b1", "b2", "aq", "aq_stop", "vq", "vq_stop", "trap_error"):
            e.var(name, 0)

        def type_reference():
            need(1)
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
            need(1)
            e.var("pc", e.rd(p["ga"]))
            e.set("ga", e.add(p["ga"], 1))
            e.for_("pq", 0, p["pc"], type_reference)
            need(1)
            e.var("nc", e.rd(p["ga"]))
            e.set("ga", e.add(p["ga"], 1))

            def node():
                need(1)
                e.var("opc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.if_(e.eq(p["opc"], int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("ga", e.add(p["ga"], 3)))

                def entity():
                    need(1)
                    e.var("ei", e.rd(p["ga"]))
                    e.set("ga", e.add(p["ga"], 1))
                    _no(e, e.le(p["refs"], p["ei"]))
                    _no(e, e.eq(_reference(e, g, p["ei"]), NONE))
                    _mark(e, p["ei"])

                e.if_(e.either(*(e.eq(p["opc"], code) for code in ENTITY_CODES)), entity)
                need(1)
                e.var("oc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("oq", 0, p["oc"], skip_value)
                need(1)
                e.var("rc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("rq", 0, p["rc"], type_reference)
                e.if_(e.either(*(e.eq(p["opc"], code) for code in ATTRIBUTE_CODES)), lambda: e.set("ga", e.add(e.add(p["ga"], 1), e.rd(p["ga"]))))

            e.for_("nq", 0, p["nc"], node)
            need(1)
            e.var("kind", e.rd(p["ga"]))
            e.set("ga", e.add(p["ga"], 1))

            def edge():
                need(2)
                e.set("ga", e.add(p["ga"], 1))
                e.var("ac", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("aq", 0, p["ac"], skip_value)

            def trap():
                need(2)
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
                # decode_trap_payload's messages, in its order: 1 non-canonical ULEB, 2 over 16 bits, 3 zero alone,
                # 4 unterminated.
                e.set("trap_error", 0)
                e.if_(e.both(e.lt(p["b0"], 128), e.eq(p["tsize"], 1), e.eq(p["b0"], 0)), lambda: e.set("trap_error", 3))
                e.if_(e.both(e.le(128, p["b0"]), e.lt(1, p["tsize"]), e.lt(p["b1"], 128), e.eq(p["b1"], 0)), lambda: e.set("trap_error", 1))
                e.if_(e.both(e.le(128, p["b0"]), e.le(128, p["b1"]), e.lt(2, p["tsize"]), e.lt(p["b2"], 128)),
                      lambda: e.if_(e.eq(p["b2"], 0), lambda: e.set("trap_error", 1), lambda: e.if_(e.not_(three), lambda: e.set("trap_error", 2))))
                e.if_(e.not_(e.either(one, two, three, e.eq(p["trap_error"], 1), e.eq(p["trap_error"], 2))), lambda: e.set("trap_error", 4))
                e.if_(e.both(e.ne(p["tsize"], 0), e.ne(p["trap_error"], 0)),
                      lambda: (_no(e, e.eq(p["all_resolved"], 0)), _reject(e, None, g, S["GRAPH_TRAP_PAYLOAD"], p["trap_error"], p["b"])))

            e.if_(e.eq(p["kind"], 1), edge)
            e.if_(e.eq(p["kind"], 2), lambda: (skip_value(), edge(), edge()))
            def returning():
                need(1)
                e.set("vc", e.rd(p["ga"]))
                e.set("ga", e.add(p["ga"], 1))
                e.for_("vq", 0, p["vc"], skip_value)

            e.if_(e.eq(p["kind"], 3), returning)
            e.if_(e.eq(p["kind"], 4), trap)

        e.for_("b", 0, p["B"], block)
        _no(e, e.ne(p["prefix"], 0))  # the decoder's rejection, not reference use, comes next
        _no(e, e.eq(p["all_resolved"], 0))
        _reject(e, e.eq(_all_marked(e, p["refs"]), 0), g, S["GRAPH_UNUSED"], _list_copy(e, p["refs"], lambda k: e.ld(e.add(_g(e, G_MARK), k))))
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


def _recorder(e: E, obj, at: str, end, start):
    """S8 (ADR-251): ``Cursor`` reads of ``obj``'s body at ``p[at]`` that reject exactly where the cursor fails and
    record what they read (a rejection quotes the words: values, string offsets, reference indices)."""
    p = e.p
    e.var("rw", e.alloc(e.add(e.mul(e.sub(end, p[at]), 2), 4)))
    _no(e, e.eq(p["rw"], NONE))
    e.var("rn", 0)

    def record(value):
        e.st(e.add(p["rw"], p["rn"]), value)
        e.set("rn", e.add(p["rn"], 1))

    def read():
        e.var("rd_", _strict(e, at, end, obj, start, 0, e.add(p["rw"], p["rn"])))
        e.set("rn", e.add(p["rn"], 1))
        return p["rd_"]

    def string():
        """``byte_string``: ``(input position, length)``; records the length and the body offset."""
        e.var("sl_", read())
        e.if_(e.lt(e.sub(end, p[at]), p["sl_"]), lambda: _reject(e, None, obj, S["BODY_TAKE"], p["sl_"], e.sub(end, p[at])))
        record(e.sub(p[at], start))
        e.var("ss_", p[at])
        e.set(at, e.add(p[at], p["sl_"]))
        return p["ss_"], p["sl_"]

    def reference():
        """``_reference``: the named object (recorded: the index); marks it."""
        e.var("ri_", read())
        _reject(e, e.le(_references(e, obj), p["ri_"]), obj, S["BUILD_REF_INDEX"], _references(e, obj), p["ri_"])
        e.var("ro_", _reference(e, obj, p["ri_"]))
        _no(e, e.eq(p["ro_"], NONE))
        _mark(e, p["ri_"])
        return p["ro_"]

    def byte():
        e.if_(e.le(end, p[at]), lambda: _reject(e, None, obj, S["BODY_TAKE"], 1, 0))
        e.var("rb_", e.rd(p[at]))
        e.set(at, e.add(p[at], 1))
        record(p["rb_"])
        return p["rb_"]

    def boolean():
        e.var("bo_", byte())
        _reject(e, e.lt(1, p["bo_"]), obj, S["BODY_BOOL"], p["bo_"])
        return p["bo_"]

    def take(size):
        e.if_(e.lt(e.sub(end, p[at]), size), lambda: _reject(e, None, obj, S["BODY_TAKE"], size, e.sub(end, p[at])))
        record(e.sub(p[at], start))
        e.set(at, e.add(p[at], size))

    def enum(high, which):
        """``_enum``: a value in 1..high, else ``XAX.BUILD.ENUM`` (``which``: the enum)."""
        e.var("en_", read())
        _reject(e, e.either(e.eq(p["en_"], 0), e.lt(high, p["en_"])), obj, S["BUILD_ENUM"], which, p["en_"])
        return p["en_"]

    def rule(code, condition=None, item=0, extra=0, entity=NONE, more=0):
        """A build rule broken: rejects quoting the recorded words (``entity``: the object the diagnostic names, when
        it is not ``obj``)."""
        _reject(e, condition, obj, S["BUILD_RULE"], code, p["rw"], p["rn"], item, extra, entity, more)

    def finish(body_rule):
        """``_finish``: no trailing bytes (``body_rule``), every reference used."""
        _reject(e, e.ne(p[at], end), obj, S["BODY_TRAILING"], body_rule, e.sub(end, p[at]))
        e.if_(e.eq(_all_marked(e, _references(e, obj)), 0),
              lambda: rule(BUILD_REFS_EXACT, None, _list_copy(e, _references(e, obj), lambda k: e.ld(e.add(_g(e, G_MARK), k)))))

    return dict(read=read, string=string, reference=reference, byte=byte, boolean=boolean, take=take, enum=enum, rule=rule, finish=finish)


# S8 (ADR-251): build rules (``BUILD_RULE`` payload word 0), the bodies' trailing-byte rules, and the enums.
(BUILD_IDENTITY, BUILD_MODULES, BUILD_MODULE_KIND, BUILD_MODULES_CANONICAL, BUILD_EXACT_KIND, BUILD_DEPENDENCY_FORM,
 BUILD_DEPENDENCIES_CANONICAL, BUILD_NAMED_REFERENCE, BUILD_NAMES_CANONICAL, BUILD_CAPABILITIES_CANONICAL, BUILD_REFS_EXACT,
 BUILD_GRANTS_CANONICAL, BUILD_ALGORITHMS_CANONICAL, BUILD_SIGNERS_CANONICAL, BUILD_TRUST_NONEMPTY, BUILD_TRUST_REQUIRED,
 BUILD_SIGNATURE_NONEMPTY, BUILD_OPT_REFERENCES,
 BUILD_REQUEST_KINDS, BUILD_ENTRY_DECLARED, BUILD_BINDINGS_CANONICAL, BUILD_BINDINGS_COMPLETE, BUILD_TYPED_VALUE, BUILD_CONSTANT_TYPE,
 BUILD_BINDING_TYPE, BUILD_ARTIFACTS_CANONICAL, BUILD_ARTIFACT_REQUIRED, BUILD_SNAPSHOT_HEADER, BUILD_SNAPSHOT_PACKAGE_KIND,
 BUILD_SNAPSHOT_SIGNATURE_KIND, BUILD_SNAPSHOT_PACKAGES_CANONICAL, BUILD_SNAPSHOT_SIGNATURES_CANONICAL, BUILD_SNAPSHOT_EXTERNAL_CANONICAL,
 BUILD_SNAPSHOT_ROOT, BUILD_RESOLVE_EXACT, BUILD_RESOLVE_LOGICAL, BUILD_SNAPSHOT_CLOSURE, BUILD_GRANT_DECLARED, BUILD_SIGNATURE_PACKAGE,
 BUILD_SIGNATURE_COVERAGE, BUILD_PROVENANCE_KINDS, BUILD_PROVENANCE_CLOSURE) = range(1, 43)
BODY_RULES = ("BUILD-BODY", "BUILD-OPTIMIZATION-POLICY-BODY", "TARGET-NATIVE-BODY")
BUILD_ENUMS = ("BuildForm", "BuildMode", "BuildCapabilityKind", "ArtifactKind", "OptimizationObjective")


def _package_ok(tables):
    """``decode_package``, decided in full (S8): identity, canonical modules, dependencies, named build entries and
    schemas, capabilities, exact end and exact reference use."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("pa", _payload(e, o))
        e.var("pbody", p["pa"])
        e.var("pend", e.add(p["pa"], e.rd(e.sub(p["pa"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.eq(_resolved(e, o), 0))
        r = _recorder(e, o, "pa", p["pend"], p["pbody"])
        start, length = r["string"]()
        e.var("p_is", start)
        e.var("p_il", length)
        r["rule"](BUILD_IDENTITY, e.eq(p["p_il"], 0))
        e.var("mcount", r["read"]())
        e.var("mlist", e.alloc(e.add(e.sel(e.lt(p["mcount"], e.sub(p["pend"], p["pa"])), p["mcount"], e.sub(p["pend"], p["pa"])), 1)))
        _no(e, e.eq(p["mlist"], NONE))
        e.for_("mq", 0, p["mcount"], lambda: e.st(e.add(p["mlist"], p["mq"]), r["reference"]()))
        r["rule"](BUILD_MODULES, e.eq(p["mcount"], 0))
        e.var("mbad", NONE)
        e.for_("mq", 0, p["mcount"], lambda: e.if_(e.both(e.eq(p["mbad"], NONE), e.ne(_kind(e, e.ld(e.add(p["mlist"], p["mq"]))), int(Kind.MODULE))),
                                                   lambda: e.set("mbad", p["mq"])))
        e.if_(e.ne(p["mbad"], NONE), lambda: r["rule"](BUILD_MODULE_KIND, None, p["mbad"], _kind(e, e.ld(e.add(p["mlist"], p["mbad"])))))
        e.var("mok", 1)
        e.for_("mq", 1, p["mcount"], lambda: e.if_(e.ne(e.call(_FN["cid_less"], e.ld(e.add(p["mlist"], e.sub(p["mq"], 1))), e.ld(e.add(p["mlist"], p["mq"]))), 1),
                                                   lambda: e.set("mok", 0)))
        r["rule"](BUILD_MODULES_CANONICAL, e.eq(p["mok"], 0))
        # Dependencies sort by key: exact (0x01 + root CID) before logical (0x02 + ULEB length + identity).
        e.var("p_deps", p["pa"])
        e.var("dcount", r["read"]())
        e.var("dform", 0)  # the previous form; 0 before the first
        e.var("dobj", 0)
        e.var("dps", 0)
        e.var("dpl", 0)
        e.var("dok", 1)

        def dependency():
            e.var("form", r["read"]())

            def exact():
                e.var("dnew", r["reference"]())
                e.if_(e.ne(_kind(e, p["dnew"]), int(Kind.PACKAGE)), lambda: r["rule"](BUILD_EXACT_KIND, None, 0, _kind(e, p["dnew"])))
                e.if_(e.eq(p["dform"], 2), lambda: e.set("dok", 0))
                e.if_(e.both(e.eq(p["dform"], 1), e.ne(e.call(_FN["cid_less"], p["dobj"], p["dnew"]), 1)), lambda: e.set("dok", 0))
                e.set("dobj", p["dnew"])

            def logical():
                e.var("dkey", p["pa"])  # the key is the encoded string: ULEB length, then bytes
                _ds, dl = r["string"]()
                _no(e, e.eq(dl, 0))  # ``DependencyRequirement`` raises ValueError: left to the bootstrap
                e.var("dklen", e.sub(p["pa"], p["dkey"]))
                e.if_(e.both(e.eq(p["dform"], 2), e.ne(e.call(_FN["bytes_less"], p["dps"], p["dkey"], p["dpl"], p["dklen"]), 1)), lambda: e.set("dok", 0))
                e.set("dps", p["dkey"])
                e.set("dpl", p["dklen"])

            e.if_(e.both(e.ne(p["form"], 1), e.ne(p["form"], 2)), lambda: r["rule"](BUILD_DEPENDENCY_FORM, None, 0, p["form"]))
            e.if_(e.eq(p["form"], 1), exact, logical)
            e.set("dform", p["form"])

        e.for_("dq", 0, p["dcount"], dependency)
        r["rule"](BUILD_DEPENDENCIES_CANONICAL, e.eq(p["dok"], 0))
        e.var("p_entries", p["pa"])
        for number, (collection, kind) in enumerate((("ce", Kind.FUNCTION), ("cf", Kind.TYPE), ("cc", Kind.TYPE))):
            e.var(f"{collection}_count", r["read"]())
            e.var(f"{collection}_ok", 1)

            def entry(collection=collection, kind=kind, number=number):
                start, length = r["string"]()
                e.var(f"{collection}_ns", start)
                e.var(f"{collection}_nl", length)
                e.var("child", r["reference"]())
                e.if_(e.either(e.eq(p[f"{collection}_nl"], 0), e.ne(_kind(e, p["child"]), int(kind))),
                      lambda: r["rule"](BUILD_NAMED_REFERENCE, None, number, p[f"{collection}_q"]))
                e.if_(e.both(e.ne(p[f"{collection}_q"], 0),
                             e.ne(e.call(_FN["bytes_less"], p[f"{collection}_ps"], p[f"{collection}_ns"], p[f"{collection}_pl"], p[f"{collection}_nl"]), 1)),
                      lambda: e.set(f"{collection}_ok", 0))
                e.set(f"{collection}_ps", p[f"{collection}_ns"])
                e.set(f"{collection}_pl", p[f"{collection}_nl"])

            e.var(f"{collection}_ps", 0)
            e.var(f"{collection}_pl", 0)
            e.for_(f"{collection}_q", 0, p[f"{collection}_count"], entry)
            r["rule"](BUILD_NAMES_CANONICAL, e.eq(p[f"{collection}_ok"], 0), number)
        e.var("p_caps", p["pa"])
        e.var("kcount", r["read"]())
        e.var("kprev", 0)
        e.var("kok", 1)

        def capability():
            # (kind, scope) strictly increasing.
            e.var("k_kind", r["enum"](9, 3))
            start, length = r["string"]()
            e.var("k_cs", start)
            e.var("k_cl", length)

            def ordered():
                e.if_(e.lt(p["k_kind"], p["kprev"]), lambda: e.set("kok", 0))
                e.if_(e.both(e.eq(p["kprev"], p["k_kind"]), e.ne(e.call(_FN["bytes_less"], p["kps"], p["k_cs"], p["kpl"], p["k_cl"]), 1)),
                      lambda: e.set("kok", 0))

            e.if_(e.ne(p["kq"], 0), ordered)
            e.set("kprev", p["k_kind"])
            e.set("kps", p["k_cs"])
            e.set("kpl", p["k_cl"])

        e.var("kps", 0)
        e.var("kpl", 0)
        e.for_("kq", 0, p["kcount"], capability)
        r["rule"](BUILD_CAPABILITIES_CANONICAL, e.eq(p["kok"], 0))
        r["finish"](0)
        # For requests and snapshots: [identity start, identity length, dependencies, entries, capabilities].
        e.var("prec", e.alloc(5))
        _no(e, e.eq(p["prec"], NONE))
        for slot, name in enumerate(("p_is", "p_il", "p_deps", "p_entries", "p_caps")):
            e.st(e.add(p["prec"], slot), p[name])
        e.st(e.add(GRAPHS_AT, o), p["prec"])
        e.give(1)
    return _function(("o",), build, tables)


def _build_ok(tables):
    """``_build_form`` and the leaf build forms, decided in full (S8): profile (``decode_profile``), trust policy,
    signature, and optimization policy.  Requests, snapshots, and provenance give 0 here: later passes decide them
    (S6b.4b)."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("ba", _payload(e, o))
        e.var("bbody", p["ba"])
        e.var("bend", e.add(p["ba"], e.rd(e.sub(p["ba"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.eq(_resolved(e, o), 0))
        r = _recorder(e, o, "ba", p["bend"], p["bbody"])
        e.var("form", r["enum"](7, 1))
        e.if_(e.either(e.eq(p["form"], 2), e.eq(p["form"], 3), e.eq(p["form"], 5)), lambda: e.give(0))  # later passes

        def finish():
            r["finish"](0)
            e.give(1)

        def profile():
            r["enum"](3, 2)  # the build mode
            r["read"]()  # optimization level
            r["read"]()  # verification level
            e.st(e.add(GRAPHS_AT, o), p["ba"])  # for snapshots: where the grants start
            e.var("gcount", r["read"]())
            for name in ("gis", "gil", "gkind", "gcs", "gcl"):
                e.var(name, 0)
            e.var("gok", 1)

            def grant():
                start, length = r["string"]()
                e.var("nis", start)
                e.var("nil", length)
                e.var("g_kind", r["enum"](9, 3))
                start, length = r["string"]()
                e.var("g_cs", start)
                e.var("g_cl", length)
                _no(e, e.eq(p["nil"], 0))  # ``CapabilityGrant`` raises ValueError: left to the bootstrap

                def ordered():
                    # (identity, kind, scope) strictly increasing.
                    e.var("gless", e.call(_FN["bytes_less"], p["gis"], p["nis"], p["gil"], p["nil"]))
                    e.var("gmore", e.call(_FN["bytes_less"], p["nis"], p["gis"], p["nil"], p["gil"]))
                    e.if_(e.ne(p["gmore"], 0), lambda: e.set("gok", 0))

                    def same_identity():
                        e.if_(e.lt(p["g_kind"], p["gkind"]), lambda: e.set("gok", 0))
                        e.if_(e.both(e.eq(p["g_kind"], p["gkind"]), e.ne(e.call(_FN["bytes_less"], p["gcs"], p["g_cs"], p["gcl"], p["g_cl"]), 1)),
                              lambda: e.set("gok", 0))

                    e.if_(e.both(e.eq(p["gless"], 0), e.eq(p["gmore"], 0)), same_identity)

                e.if_(e.ne(p["gq"], 0), ordered)
                e.set("gis", p["nis"])
                e.set("gil", p["nil"])
                e.set("gkind", p["g_kind"])
                e.set("gcs", p["g_cs"])
                e.set("gcl", p["g_cl"])

            e.for_("gq", 0, p["gcount"], grant)
            r["rule"](BUILD_GRANTS_CANONICAL, e.eq(p["gok"], 0))
            finish()

        def trust():
            e.var("rp", r["boolean"]())
            e.var("rv", r["boolean"]())
            e.var("tempty", 0)
            for name in ("al", "si"):
                e.var(f"{name}_count", r["read"]())
                e.var(f"{name}_ok", 1)

                def item(name=name):
                    start, length = r["string"]()
                    e.var(f"{name}_s", start)
                    e.var(f"{name}_l", length)
                    e.if_(e.eq(p[f"{name}_l"], 0), lambda: e.set("tempty", 1))
                    e.if_(e.both(e.ne(p[f"{name}_q"], 0), e.ne(e.call(_FN["bytes_less"], p[f"{name}_ps"], p[f"{name}_s"], p[f"{name}_pl"], p[f"{name}_l"]), 1)),
                          lambda: e.set(f"{name}_ok", 0))
                    e.set(f"{name}_ps", p[f"{name}_s"])
                    e.set(f"{name}_pl", p[f"{name}_l"])

                e.var(f"{name}_ps", 0)
                e.var(f"{name}_pl", 0)
                e.for_(f"{name}_q", 0, p[f"{name}_count"], item)
            r["rule"](BUILD_ALGORITHMS_CANONICAL, e.eq(p["al_ok"], 0))
            r["rule"](BUILD_SIGNERS_CANONICAL, e.eq(p["si_ok"], 0))
            r["rule"](BUILD_TRUST_NONEMPTY, e.ne(p["tempty"], 0))
            required = e.either(e.ne(p["rp"], 0), e.ne(p["rv"], 0))
            r["rule"](BUILD_TRUST_REQUIRED, e.both(required, e.either(e.eq(p["al_count"], 0), e.eq(p["si_count"], 0))))
            e.st(e.add(GRAPHS_AT, o), p["rp"])  # for snapshots: package signatures required
            finish()

        def signature():
            e.st(e.add(GRAPHS_AT, o), r["reference"]())  # the signed object
            e.var("sempty", 0)
            for _field in range(3):
                _start, length = r["string"]()
                e.if_(e.eq(length, 0), lambda: e.set("sempty", 1))
            r["rule"](BUILD_SIGNATURE_NONEMPTY, e.ne(p["sempty"], 0))
            finish()

        def optimization():
            r["enum"](1, 5)  # objective: code size
            for _value in range(8):
                r["read"]()
            r["boolean"]()
            _reject(e, e.ne(p["ba"], p["bend"]), o, S["BODY_TRAILING"], 1, e.sub(p["bend"], p["ba"]))
            r["rule"](BUILD_OPT_REFERENCES, e.ne(p["refs"], 0))
            e.give(1)

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


def _listed(e: E, items, count, obj):
    """The position of ``obj`` in the ``count`` words at ``items``, or NONE."""
    p = e.p
    e.var("ls_at", NONE)
    e.for_("ls_q", 0, count, lambda: e.if_(e.eq(e.ld(e.add(items, p["ls_q"])), obj), lambda: e.set("ls_at", p["ls_q"])))
    return p["ls_at"]


def _form_site(e: E, x):
    """1 when ``x`` (a BUILD object) is rejected for its form (``_build_form`` raises its diagnostic): the form enum or
    a malformed form ULEB."""
    at = e.add(REJECTS_AT, e.mul(x, REJECT_WORDS))
    site, first, second = e.ld(at), e.ld(e.add(at, 1)), e.ld(e.add(at, 2))
    return e.both(e.eq(_verdict(e, x), REJECTED), e.either(e.both(e.eq(site, S["BUILD_ENUM"]), e.eq(first, 1)),
                                                             e.both(e.eq(site, S["BODY_ULEB"]), e.eq(second, 0))))


def _build_form_of(e: E, o, x, name: str):
    """``_build_form(x)`` called while verifying ``o``: rejects ``o`` with x's BUILD-KIND diagnostic, or with x's own
    form rejection (``OTHER_OBJECT``); otherwise the form (a single canonical byte 1..7), or a decline."""
    p = e.p
    _reject(e, e.ne(_kind(e, x), int(Kind.BUILD)), o, S["BUILD_KIND_OF"], x)
    e.if_(_form_site(e, x), lambda: _reject(e, None, o, S["OTHER_OBJECT"], x))
    e.var(name, _form_of(e, x))
    _no(e, e.either(e.eq(p[name], 0), e.lt(7, p[name])))  # a form the verifier has no verdict for: left to the bootstrap
    return p[name]


def _request_ok(tables):
    """``decode_request``, decided in full (S8): the header and its reference kinds, a proven package declaring the
    entry, bindings matching the package's schemas name for name with constants of the schema types, canonical
    artifacts, exact end and use.  A rejected package or binding value whose own diagnostic the bootstrap raises
    (in a nested decoder) is left to that object's rejection."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("ra", _payload(e, o))
        e.var("rbody", p["ra"])
        e.var("rend", e.add(p["ra"], e.rd(e.sub(p["ra"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.eq(_resolved(e, o), 0))
        r = _recorder(e, o, "ra", p["rend"], p["rbody"])
        _no(e, e.ne(r["enum"](7, 1), 2))
        e.var("pkg", r["reference"]())
        start, length = r["string"]()
        e.var("es", start)
        e.var("el", length)
        e.var("tgt", r["reference"]())
        e.var("prof", r["reference"]())
        e.var("pform", _build_form_of(e, o, p["prof"], "pform"))
        r["rule"](BUILD_REQUEST_KINDS, e.either(e.ne(_kind(e, p["pkg"]), int(Kind.PACKAGE)), e.ne(_kind(e, p["tgt"]), int(Kind.TARGET)), e.ne(p["pform"], 1)),
                  _kind(e, p["pkg"]), _kind(e, p["tgt"]), NONE, p["pform"])
        _no(e, e.ne(_verdict(e, p["pkg"]), 1))  # ``decode_package``: a rejected package raises its own diagnostic
        # The package (proven) lists its entries, feature schemas, and configuration schemas from p_entries on.
        e.var("q", e.ld(e.add(_aux(e, p["pkg"]), 3)))
        e.var("qend", e.add(_payload(e, p["pkg"]), e.rd(e.sub(_payload(e, p["pkg"]), 1))))
        e.var("found", 0)

        def entry():
            start, length = _string(e, "q", p["qend"])
            e.var("ns", start)
            e.var("nl", length)
            _read(e, "q", p["qend"])
            e.if_(_same_bytes(e, p["ns"], p["nl"], p["es"], p["el"]), lambda: e.set("found", 1))

        e.var("entries", _read(e, "q", p["qend"]))
        e.for_("eq_", 0, p["entries"], entry)
        r["rule"](BUILD_ENTRY_DECLARED, e.eq(p["found"], 0))
        for number, schema in enumerate(("feature", "configuration")):
            e.var("bcount", r["read"]())
            e.var("blist", e.alloc(e.add(e.mul(e.sel(e.lt(p["bcount"], e.sub(p["rend"], p["ra"])), p["bcount"], e.sub(p["rend"], p["ra"])), 3), 1)))
            _no(e, e.eq(p["blist"], NONE))
            e.var("bok", 1)

            def binding():
                at = e.add(p["blist"], e.mul(p["bq"], 3))
                start, length = r["string"]()
                e.var("bs", start)
                e.var("bl", length)
                e.st(at, p["bs"])
                e.st(e.add(at, 1), p["bl"])
                e.st(e.add(at, 2), r["reference"]())
                e.if_(e.both(e.ne(p["bq"], 0), e.ne(e.call(_FN["bytes_less"], e.ld(e.sub(at, 3)), p["bs"], e.ld(e.sub(at, 2)), p["bl"]), 1)),
                      lambda: e.set("bok", 0))

            e.for_("bq", 0, p["bcount"], binding)
            r["rule"](BUILD_BINDINGS_CANONICAL, e.eq(p["bok"], 0), number)
            # Complete: the same (sorted, unique) names as the package's schema; then each value's type.
            e.var("scount", _read(e, "q", p["qend"]))
            e.var("sstart", p["q"])
            e.var("same", e.flag(e.eq(p["scount"], p["bcount"])))

            def compare():
                start, length = _string(e, "q", p["qend"])
                e.var("ss", start)
                e.var("sl", length)
                _read(e, "q", p["qend"])
                at = e.add(p["blist"], e.mul(p["cq_"], 3))
                e.if_(e.not_(_same_bytes(e, e.ld(at), e.ld(e.add(at, 1)), p["ss"], p["sl"])), lambda: e.set("same", 0))

            e.if_(e.ne(p["same"], 0), lambda: e.for_("cq_", 0, p["scount"], compare))
            r["rule"](BUILD_BINDINGS_COMPLETE, e.eq(p["same"], 0), number)
            e.set("q", p["sstart"])

            def typed():
                e.var("value", e.ld(e.add(e.add(p["blist"], e.mul(p["tq"], 3)), 2)))
                start, length = _string(e, "q", p["qend"])
                e.var("si", _read(e, "q", p["qend"]))
                e.var("stype", _reference(e, p["pkg"], p["si"]))
                # ``_constant_type``: a constant whose first ULEB names its type reference.
                r["rule"](BUILD_TYPED_VALUE, e.ne(_kind(e, p["value"]), int(Kind.CONSTANT)), _kind(e, p["value"]), 0, p["value"])
                e.var("ca", _payload(e, p["value"]))
                e.var("cend", e.add(p["ca"], e.rd(e.sub(p["ca"], 1))))
                e.var("ct", _read(e, "ca", p["cend"]))  # a malformed index: the constant's own cursor diagnostic (left to the bootstrap)
                r["rule"](BUILD_CONSTANT_TYPE, e.le(_references(e, p["value"]), p["ct"]), _references(e, p["value"]), p["ct"], p["value"])
                r["rule"](BUILD_BINDING_TYPE, e.ne(_reference(e, p["value"], p["ct"]), p["stype"]), p["stype"], _reference(e, p["value"], p["ct"]))

            e.for_("tq", 0, p["bcount"], typed)
        e.var("acount", r["read"]())
        e.var("aprev", 0)
        e.var("aok", 1)

        def artifact():
            e.var("art", r["enum"](6, 4))
            e.if_(e.le(p["art"], p["aprev"]), lambda: e.set("aok", 0))
            e.set("aprev", p["art"])

        e.for_("aq", 0, p["acount"], artifact)
        r["rule"](BUILD_ARTIFACTS_CANONICAL, e.eq(p["aok"], 0))
        r["rule"](BUILD_ARTIFACT_REQUIRED, e.eq(p["acount"], 0))
        r["finish"](0)
        e.var("rrec", e.alloc(3))  # [package, target, profile]
        _no(e, e.eq(p["rrec"], NONE))
        e.st(p["rrec"], p["pkg"])
        e.st(e.add(p["rrec"], 1), p["tgt"])
        e.st(e.add(p["rrec"], 2), p["prof"])
        e.st(e.add(GRAPHS_AT, o), p["rrec"])
        e.give(1)
    return _function(("o",), build, tables)


def _snapshot_ok(tables):
    """``decode_snapshot``, decided in full (S8): the header (resolver identity, request and trust-policy forms), the
    package, signature, and digest lists (kinds, then canonical order), exact end and use; then, over the proven
    request, packages, profile, policy, and signatures: the root package, the dependency closure (in the bootstrap's
    depth-first order, naming the package whose dependency does not resolve), declared grants, and signatures."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("sa", _payload(e, o))
        e.var("sbody", p["sa"])
        e.var("send", e.add(p["sa"], e.rd(e.sub(p["sa"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.eq(_resolved(e, o), 0))
        r = _recorder(e, o, "sa", p["send"], p["sbody"])
        _no(e, e.ne(r["enum"](7, 1), 3))
        e.var("req", r["reference"]())
        _start, length = r["string"]()
        e.var("rid", length)
        e.var("pol", r["reference"]())

        def header():
            e.var("qform", _build_form_of(e, o, p["req"], "qform"))
            r["rule"](BUILD_SNAPSHOT_HEADER, e.ne(p["qform"], 2), _kind(e, p["req"]), _kind(e, p["pol"]))
            e.var("lform", _build_form_of(e, o, p["pol"], "lform"))
            r["rule"](BUILD_SNAPSHOT_HEADER, e.ne(p["lform"], 4), _kind(e, p["req"]), _kind(e, p["pol"]))

        e.if_(e.eq(p["rid"], 0), lambda: r["rule"](BUILD_SNAPSHOT_HEADER, None, _kind(e, p["req"]), _kind(e, p["pol"])), header)
        for name in ("pk", "sg"):
            e.var(f"{name}_count", r["read"]())
            e.var(f"{name}_items", e.alloc(e.add(e.sel(e.lt(p[f"{name}_count"], e.sub(p["send"], p["sa"])), p[f"{name}_count"], e.sub(p["send"], p["sa"])), 1)))
            _no(e, e.eq(p[f"{name}_items"], NONE))
            e.for_(f"{name}_q", 0, p[f"{name}_count"], lambda name=name: e.st(e.add(p[f"{name}_items"], p[f"{name}_q"]), r["reference"]()))
        e.var("dcount", r["read"]())
        e.var("dstart", p["sa"])
        e.for_("dq", 0, p["dcount"], lambda: r["take"](32))
        e.var("kbad", 0)
        e.for_("pk_q", 0, p["pk_count"], lambda: e.if_(e.ne(_kind(e, e.ld(e.add(p["pk_items"], p["pk_q"]))), int(Kind.PACKAGE)), lambda: e.set("kbad", 1)))
        r["rule"](BUILD_SNAPSHOT_PACKAGE_KIND, e.ne(p["kbad"], 0))
        # ``_build_form`` of every signature, in order: the first that raises does; else any other form rejects.
        e.var("fbad", 0)

        def signature_form():
            e.var("sgx", e.ld(e.add(p["sg_items"], p["sg_q"])))
            _build_form_of(e, o, p["sgx"], "sgform")
            e.if_(e.ne(p["sgform"], 6), lambda: e.set("fbad", 1))

        e.for_("sg_q", 0, p["sg_count"], signature_form)
        r["rule"](BUILD_SNAPSHOT_SIGNATURE_KIND, e.ne(p["fbad"], 0))
        for name, rule in (("pk", BUILD_SNAPSHOT_PACKAGES_CANONICAL), ("sg", BUILD_SNAPSHOT_SIGNATURES_CANONICAL)):
            e.var("cok", 1)
            e.for_(f"{name}_q", 1, p[f"{name}_count"], lambda name=name: e.if_(
                e.ne(e.call(_FN["cid_less"], e.ld(e.add(p[f"{name}_items"], e.sub(p[f"{name}_q"], 1))), e.ld(e.add(p[f"{name}_items"], p[f"{name}_q"]))), 1),
                lambda: e.set("cok", 0)))
            r["rule"](rule, e.eq(p["cok"], 0))
        e.var("cok", 1)
        e.for_("dq", 1, p["dcount"], lambda: e.if_(
            e.ne(e.call(_FN["bytes_less"], e.add(p["dstart"], e.mul(e.sub(p["dq"], 1), 32)), e.add(p["dstart"], e.mul(p["dq"], 32)), 32, 32), 1),
            lambda: e.set("cok", 0)))
        r["rule"](BUILD_SNAPSHOT_EXTERNAL_CANONICAL, e.eq(p["cok"], 0))
        r["finish"](0)
        # Nested decoders: a rejected request or package raises its own diagnostic (left to its rejection).
        _no(e, e.ne(_verdict(e, p["req"]), 1))
        e.for_("pk_q", 0, p["pk_count"], lambda: _no(e, e.ne(_verdict(e, e.ld(e.add(p["pk_items"], p["pk_q"]))), 1)))
        e.var("rrec", _aux(e, p["req"]))
        e.var("root", e.ld(p["rrec"]))
        e.var("prof", e.ld(e.add(p["rrec"], 2)))
        e.var("rootpos", _listed(e, p["pk_items"], p["pk_count"], p["root"]))
        r["rule"](BUILD_SNAPSHOT_ROOT, e.eq(p["rootpos"], NONE), 0, 0, NONE, p["root"])
        # The dependency closure, in ``decode_snapshot``'s order: a stack of packages, each package's dependencies in
        # order (a dependency that does not resolve rejects, naming its package).
        e.var("seen", e.alloc(e.add(p["pk_count"], 1)))
        e.var("stack", e.alloc(e.add(e.mul(p["pk_count"], e.add(e.mul(p["pk_count"], 2), 1)), 2)))  # each package's dependencies once
        e.var("matches_at", e.alloc(e.add(p["pk_count"], 1)))
        _no(e, e.either(e.eq(p["seen"], NONE), e.eq(p["stack"], NONE), e.eq(p["matches_at"], NONE)))
        e.for_("z", 0, p["pk_count"], lambda: e.st(e.add(p["seen"], p["z"]), 0))
        e.var("depth", 1)
        e.st(p["stack"], p["rootpos"])

        def visit():
            e.set("depth", e.sub(p["depth"], 1))
            e.var("curpos", e.ld(e.add(p["stack"], p["depth"])))

            def expand():
                e.st(e.add(p["seen"], p["curpos"]), 1)
                e.var("cur", e.ld(e.add(p["pk_items"], p["curpos"])))
                e.var("crec", _aux(e, p["cur"]))
                e.var("w", e.ld(e.add(p["crec"], 2)))
                e.var("wend", e.add(_payload(e, p["cur"]), e.rd(e.sub(_payload(e, p["cur"]), 1))))
                e.var("deps", _read(e, "w", p["wend"]))

                def dependency():
                    e.var("dform", _read(e, "w", p["wend"]))

                    def exact():
                        e.var("dobj", _reference(e, p["cur"], _read(e, "w", p["wend"])))
                        e.var("dpos", _listed(e, p["pk_items"], p["pk_count"], p["dobj"]))
                        r["rule"](BUILD_RESOLVE_EXACT, e.eq(p["dpos"], NONE), p["dobj"], 0, p["cur"])
                        e.st(e.add(p["stack"], p["depth"]), p["dpos"])
                        e.set("depth", e.add(p["depth"], 1))

                    def logical():
                        start, length = _string(e, "w", p["wend"])
                        e.var("lis", start)
                        e.var("lil", length)
                        e.var("matches", 0)
                        e.var("match", 0)

                        def candidate():
                            e.var("other", _aux(e, e.ld(e.add(p["pk_items"], p["mq"]))))

                            def matched():
                                e.st(e.add(p["matches_at"], e.add(p["matches"], 1)), e.ld(e.add(p["pk_items"], p["mq"])))
                                e.set("matches", e.add(p["matches"], 1))
                                e.set("match", p["mq"])

                            e.if_(_same_bytes(e, e.ld(p["other"]), e.ld(e.add(p["other"], 1)), p["lis"], p["lil"]), matched)

                        e.for_("mq", 0, p["pk_count"], candidate)
                        e.st(p["matches_at"], p["matches"])
                        r["rule"](BUILD_RESOLVE_LOGICAL, e.ne(p["matches"], 1), p["matches_at"], 0, p["cur"])
                        e.st(e.add(p["stack"], p["depth"]), p["match"])
                        e.set("depth", e.add(p["depth"], 1))

                    e.if_(e.eq(p["dform"], 1), exact, logical)

                e.for_("dk", 0, p["deps"], dependency)

            e.if_(e.eq(e.ld(e.add(p["seen"], p["curpos"])), 0), expand)

        e.while_(lambda: e.ne(p["depth"], 0), visit)
        e.var("reached", 0)
        e.for_("z", 0, p["pk_count"], lambda: e.set("reached", e.add(p["reached"], e.ld(e.add(p["seen"], p["z"])))))
        r["rule"](BUILD_SNAPSHOT_CLOSURE, e.ne(p["reached"], p["pk_count"]), _list_copy(e, p["pk_count"], lambda k: e.ld(e.add(p["seen"], k))))
        _no(e, e.either(e.ne(_verdict(e, p["prof"]), 1), e.ne(_verdict(e, p["pol"]), 1)))  # ``decode_profile``, ``decode_trust_policy``
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
            e.var("gmissing", 0)

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
                    e.if_(e.eq(p["has"], 0), lambda: e.set("gmissing", 1))

                e.if_(_same_bytes(e, e.ld(p["pvr"]), e.ld(e.add(p["pvr"], 1)), p["gis"], p["gil"]), declared)

            e.for_("pq", 0, p["pk_count"], package_view)
            r["rule"](BUILD_GRANT_DECLARED, e.either(e.eq(p["gfound"], 0), e.ne(p["gmissing"], 0)), p["gq"], 0, NONE, p["prof"])

        e.for_("gq", 0, p["grants"], grant)
        e.for_("sg_q", 0, p["sg_count"], lambda: _no(e, e.ne(_verdict(e, e.ld(e.add(p["sg_items"], p["sg_q"]))), 1)))  # ``decode_signature``
        # Signatures sign listed packages; a policy requiring package signatures covers every one.
        e.var("signed", e.alloc(e.add(p["pk_count"], 1)))
        _no(e, e.eq(p["signed"], NONE))
        e.for_("z", 0, p["pk_count"], lambda: e.st(e.add(p["signed"], p["z"]), 0))
        e.var("unsigned", 0)

        def signature():
            e.var("spos", _listed(e, p["pk_items"], p["pk_count"], _aux(e, e.ld(e.add(p["sg_items"], p["sq"])))))
            e.if_(e.eq(p["spos"], NONE), lambda: e.set("unsigned", 1), lambda: e.st(e.add(p["signed"], p["spos"]), 1))

        e.for_("sq", 0, p["sg_count"], signature)
        r["rule"](BUILD_SIGNATURE_PACKAGE, e.ne(p["unsigned"], 0))
        e.var("uncovered", 0)
        e.if_(e.ne(_aux(e, p["pol"]), 0), lambda: e.for_("z", 0, p["pk_count"], lambda: e.if_(e.eq(e.ld(e.add(p["signed"], p["z"])), 0), lambda: e.set("uncovered", 1))))
        r["rule"](BUILD_SIGNATURE_COVERAGE, e.ne(p["uncovered"], 0))
        e.st(e.add(GRAPHS_AT, o), p["req"])
        e.give(1)
    return _function(("o",), build, tables)


def _provenance_ok(tables):
    """``decode_provenance``, decided in full (S8): snapshot, request, target, profile (their forms and kinds); three
    digests and a producer; exact end and use; then, over the proven snapshot and request, the exact closure."""
    def build(e: E):
        p = e.p
        o = p["o"]
        e.var("refs", _references(e, o))
        e.var("va", _payload(e, o))
        e.var("vbody", p["va"])
        e.var("vend", e.add(p["va"], e.rd(e.sub(p["va"], 1))))
        _clear_marks(e, p["refs"])
        _no(e, e.eq(_resolved(e, o), 0))
        r = _recorder(e, o, "va", p["vend"], p["vbody"])
        _no(e, e.ne(r["enum"](7, 1), 5))
        for name in ("snap", "req", "tgt", "prof"):
            e.var(name, r["reference"]())
        kinds = lambda: r["rule"](BUILD_PROVENANCE_KINDS, None)  # noqa: E731

        def request_form():
            e.var("qform", _build_form_of(e, o, p["req"], "qform"))
            e.if_(e.ne(p["qform"], 2), kinds, lambda: e.if_(e.ne(_kind(e, p["tgt"]), int(Kind.TARGET)), kinds, lambda: (
                e.var("fform", _build_form_of(e, o, p["prof"], "fform")), e.if_(e.ne(p["fform"], 1), kinds))))

        e.var("sform", _build_form_of(e, o, p["snap"], "sform"))
        e.if_(e.ne(p["sform"], 3), kinds, request_form)
        for _digest in range(3):
            r["take"](32)
        r["string"]()
        r["finish"](0)
        _no(e, e.either(e.ne(_verdict(e, p["snap"]), 1), e.ne(_verdict(e, p["req"]), 1)))  # ``decode_snapshot``, ``decode_request``
        e.var("rrec", _aux(e, p["req"]))
        r["rule"](BUILD_PROVENANCE_CLOSURE, e.either(e.ne(_aux(e, p["snap"]), p["req"]), e.ne(e.ld(e.add(p["rrec"], 1)), p["tgt"]),
                                                     e.ne(e.ld(e.add(p["rrec"], 2)), p["prof"])),
                  _aux(e, p["snap"]), e.ld(e.add(p["rrec"], 1)), NONE, e.ld(e.add(p["rrec"], 2)))
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
        e.var("lbody", p["la"])
        end = e.add(p["la"], e.rd(e.sub(p["la"], 1)))
        e.var("lend", end)
        count = _read(e, "la", p["lend"], o, p["lbody"])
        e.var("lcount", count)
        # The indices (as the bootstrap reads them, before its end check), kept for the diagnostics; at most one per
        # body byte (a larger count fails on a read first).
        e.var("lindices", e.alloc(e.add(e.sel(e.lt(p["lcount"], e.sub(p["lend"], p["la"])), p["lcount"], e.sub(p["lend"], p["la"])), 1)))
        _no(e, e.eq(p["lindices"], NONE))
        e.st(p["lindices"], p["lcount"])
        e.for_("q", 0, p["lcount"], lambda: e.st(e.add(p["lindices"], e.add(p["q"], 1)), _read(e, "la", p["lend"], o, p["lbody"])))
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
        e.var("cbody", p["ca"])
        end = e.add(p["ca"], e.rd(e.sub(p["ca"], 1)))
        e.var("cend", end)
        _clear_marks(e, p["refs"])

        def type_reference():
            index = _read(e, "ca", p["cend"], o, p["cbody"])
            e.var("ca_index", index)
            _reject(e, e.le(p["refs"], p["ca_index"]), o, S["CONTRACT_REF_INDEX"], p["refs"], p["ca_index"])
            _no(e, e.not_(_type_ok(e, _reference(e, o, p["ca_index"]))))  # the bootstrap verifies the type itself
            _mark(e, p["ca_index"])

        for _part in range(2):
            e.var("ccount", _read(e, "ca", p["cend"], o, p["cbody"]))
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
        e.st(STORE_FAULT, 0)
        e.st(STORE_FAULT + 2, 0)
        e.set_hd(H_ARENA, ARENA_AT + 16)
        e.set_hd(H_ARENA_END, HEADER - 1)
        O = e.rd(0)
        e.var("O", O)
        e.st(GLOBALS + G_O, p["O"])
        for slot, size in ((G_REC, p["O"]), (G_MARK, 1 << 16), (G_GROUP_SIZE, p["O"])):
            table = e.alloc(e.add(size, 1))
            e.if_(e.eq(table, NONE), lambda: e.give(NONE))
            e.st(GLOBALS + slot, table)
        # S8 (ADR-251): a recursion group's member count once its member list decodes (NONE before or without that).
        e.for_("o", 0, p["O"], lambda: e.st(e.add(_g(e, G_GROUP_SIZE), p["o"]), NONE))
        e.var("ra", 2)

        def record():
            e.st(e.add(_g(e, G_REC), p["o"]), p["ra"])
            references = e.rd(e.add(p["ra"], 1))
            e.if_(e.lt(1 << 16, references), lambda: e.give(NONE))
            payload_at = e.add(e.add(e.add(p["ra"], 2), references), 4)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))
            e.if_(e.eq(_kind(e, p["o"]), int(Kind.GRAPH_FRAGMENT)),
                  lambda: e.set("ra", e.add(e.add(p["ra"], 2), e.rd(p["ra"]))))  # [body length, body bytes, decoder rejected]

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
                def decide():
                    e.var("later", e.call(_FN[name], o))
                    e.st(e.add(VERDICTS_AT, o), e.sel(e.eq(p["later"], 1), 1, e.sel(e.eq(p["later"], REJECTED), REJECTED, 0)))

                e.if_(e.both(e.eq(_kind(e, o), int(Kind.BUILD)), e.eq(_form_of(e, o), form)), decide)

            e.for_("o", 0, p["O"], later)
        # S8 (ADR-251): an object naming a missing object (``verify_object`` resolves its references, in order,
        # right after the CID check): rejected with that reference.
        # Every missing reference is listed too, ``[n, (object, reference index) ...]`` at word STORE_FAULT + 2: the
        # bootstrap resolves references from many decoders, and each such resolution fails on a listed one.
        e.var("missing_list", e.alloc(e.add(e.mul(p["O"], 2), 1)))
        e.var("missing_n", 0)

        def missing():
            o = p["o"]
            e.var("first_missing", NONE)

            def note():
                e.if_(e.eq(p["first_missing"], NONE), lambda: e.set("first_missing", p["mk"]))
                e.if_(e.both(e.ne(p["missing_list"], NONE), e.lt(p["missing_n"], p["O"])), lambda: (
                    e.st(e.add(p["missing_list"], e.add(e.mul(p["missing_n"], 2), 1)), o),
                    e.st(e.add(p["missing_list"], e.add(e.mul(p["missing_n"], 2), 2)), p["mk"]),
                    e.set("missing_n", e.add(p["missing_n"], 1))))

            e.for_("mk", 0, _references(e, o), lambda: e.if_(e.eq(_reference(e, o, p["mk"]), NONE), note))

            def reject():
                at = e.add(REJECTS_AT, e.mul(o, REJECT_WORDS))
                e.st(at, S["OBJECT_MISSING"])
                e.st(e.add(at, 1), p["first_missing"])
                e.st(e.add(VERDICTS_AT, o), REJECTED)

            e.if_(e.ne(p["first_missing"], NONE), reject)

        e.for_("o", 0, p["O"], missing)
        e.if_(e.ne(p["missing_list"], NONE), lambda: (e.st(p["missing_list"], p["missing_n"]), e.st(STORE_FAULT + 2, p["missing_list"])))
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
                    # S8 (ADR-251): a cycle, re-entering this object (the bootstrap's ``visit`` order).
                    e.if_(e.eq(state, 1), lambda: (e.set("store_ok", 0), e.st(STORE_FAULT, 1), e.st(STORE_FAULT + 1, p["st"])))

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
        e.var("searched", p["store_ok"])
        e.for_("o", 0, p["O"], lambda: e.if_(e.ne(e.ld(e.add(p["colour"], p["o"])), 2), lambda: e.set("store_ok", 0)))
        # S8: unreachable objects (the reachable ones are coloured 2).
        e.if_(e.both(e.ne(p["searched"], 0), e.eq(p["store_ok"], 0)), lambda: (e.st(STORE_FAULT, 2), e.st(STORE_FAULT + 1, p["colour"])))
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

    add("uleb10", _uleb10_fn(tables))
    add("tread", _strict_read_fn(tables))
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
        from xax_native import executable_mapping, zeroed_array

        self._mapping, base = executable_mapping(blob)
        self._call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(base)
        self._entry = base + len(thunk) + entry_offset
        self._in = zeroed_array(ctypes.c_uint64, IN_WORDS)
        self._out = zeroed_array(ctypes.c_uint64, OUT_WORDS)
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
            if result is None:
                return None, {}
            rejections = collect_rejections(read, result[1])
            store = store_rejection(read, count)
            if store is not None:
                rejections["store"] = store
            at = read(STORE_FAULT + 2, 1)[0]
            if at:  # S8: every missing reference, as (object, reference index)
                pairs = read(at + 1, 2 * read(at, 1)[0])
                rejections["missing"] = tuple(zip(pairs[::2], pairs[1::2]))
            return result, rejections


def store_rejection(read, count: int):
    """S8 (ADR-251): the store rejection the program decided: ``("cycle", object)``, ``("unreachable", reachable
    objects)``, or None."""
    fault, at = read(STORE_FAULT, 2)
    if fault == 1:
        return "cycle", at
    if fault == 2:
        return "unreachable", tuple(o for o, colour in enumerate(read(at, count)) if colour == 2)
    return None


def collect_verdicts(read, count: int, groups=()):
    """The program's result from its output view, read as ``read(start word, count)`` wherever it ran (natively
    or as a RISC-V image, S6c): ``(store verdict, verdicts, graph words, {group: member graphs})``, or None."""
    status, store = read(0, 2)
    if status != OK:
        return None
    verdicts, graphs = read(VERDICTS_AT, count), read(GRAPHS_AT, count)
    members = {o: tuple(read(graphs[o] + 1, read(graphs[o], 1)[0])) for o in groups if verdicts[o] == 1}
    return store == 1, verdicts, graphs, members


TRAP_ERRORS = ("non-canonical trap reason ULEB", "portable trap reason exceeds 16 bits",
               "zero trap reason uses the empty canonical payload", "unterminated or oversized portable trap reason")  # decode_trap_payload
LIST_SITES = ("LIST_REF_INDEX", "LIST_REFERENCE_BODY", "CONTRACT_UNUSED", "FUNCTION_UNUSED", "GROUP_UNUSED", "GRAPH_UNUSED")  # a payload word is a [count, words] list
TARGET_SCALAR_SITES = ("TARGET_REFERENCES", "TARGET_IDENTITY_TRUNCATED", "TARGET_IDENTITY_EMPTY", "TARGET_ARCHITECTURE", "TARGET_TRAILING",
                       "TARGET_PROFILE")  # the other target sites quote the machine record at payload word 0
TARGET_SCALAR_SITES += ("TARGET_SECTION",)
TARGET_WORD_SITES = ("TARGET_X86_REGISTERS", "TARGET_AAPCS64_REGISTERS", "TARGET_ACC_TOPOLOGY", "TARGET_ACC_SCOPES", "TARGET_ACC_SPACES",
                     "TARGET_ACC_SPACE", "TARGET_ACC_OPERATIONS", "TARGET_ACC_CONTRACT", "TARGET_PLATFORM_OPERATIONS", "TARGET_PLATFORM_CONTRACT",
                     "TARGET_OPERATIONS", "TARGET_TERMINATORS", "TARGET_ATOMIC_WIDTHS", "TARGET_ATOMIC_CAPABILITIES", "TARGET_HANDLER_ORDER",
                     "TARGET_HANDLER")  # payload: the target's recorded words (quoted), their count, item, check, sub
ULEB_FAULTS = (("XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED"), ("XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL"),
               ("XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED"))
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
            at = payload[0] if name in ("CONTRACT_UNUSED", "GROUP_UNUSED", "GRAPH_UNUSED") else payload[1]
            listed = read(at + 1, read(at, 1)[0])
        elif name in GROUP_AFTER_PARSE:
            graphs = read(payload[2] + 1, payload[0])
            if name in ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT"):
                first = read(payload[1], 1)[0]
                second = read(payload[1] + 1 + first, 1)[0]
                listed = read(payload[1], first + second + 2)
            elif name == "GROUP_MEMBER_RANGE":
                listed = [read(payload[2], 1)[0]]
            elif name == "GROUP_ORDER":
                listed = read(payload[1] + 1, read(payload[1], 1)[0])
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
        elif name in TARGET_WORD_SITES:
            listed = read(payload[0], payload[1])
        elif name == "BUILD_RULE":
            listed = read(payload[1], payload[2])
            if payload[0] in (BUILD_REFS_EXACT, BUILD_RESOLVE_LOGICAL, BUILD_SNAPSHOT_CLOSURE):
                listed = (listed, read(payload[3] + 1, read(payload[3], 1)[0]))
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


def _uleb_diagnostic(obj, status, at, size):
    """``Cursor.uleb``'s diagnostic for the ULEB the verifier found malformed (status 1 unterminated, 2 non-minimal,
    3 more than ten bytes) at body offset ``at``."""
    from xax_compiler import uleb

    code, rule = ULEB_FAULTS[status - 1]
    if status == 1:
        return code, rule, "terminating byte", "end of input"
    if status == 3:
        return code, rule, "at most 10 bytes", "more than 10 bytes"
    encoded = bytes(obj.body[at:at + size])
    value = sum((byte & 0x7F) << (7 * k) for k, byte in enumerate(encoded))
    return code, rule, uleb(value).hex(), encoded.hex()


SECTIONS = (("XAX.TARGET.CONCURRENCY", "TARGET-CONCURRENCY-ENUM", "known atomic/handler values"),
            ("XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-ENUM", "known scope/value-constraint values"),
            ("XAX.TARGET.PLATFORM", "TARGET-PLATFORM-ENUM", "known scope/value-constraint values"))


def _target_section_diagnostic(section, kind, value):
    """A fault inside a target section: the bootstrap's ``except ValueError`` reports ``str(error)``: a cursor
    diagnostic's code (kinds 1-3 ULEB, 5 truncated), the section's own BOOL code (6), or an enum's message (7-10)."""
    from xax_compiler import AtomicFamily, AtomicScope, EffectDomain, TargetValueConstraintKind

    code, rule, expected = SECTIONS[section - 1]
    if kind <= 3:
        actual = ULEB_FAULTS[kind - 1][0]
    elif kind == 5:
        actual = "XAX.CANON.TRUNCATED"
    elif kind == 6:
        actual = code
    else:
        enum = (AtomicScope, AtomicFamily, EffectDomain, TargetValueConstraintKind)[kind - 7]
        actual = f"{value} is not a valid {enum.__qualname__}"
    return code, rule, expected, actual


def target_fields(words):
    """The target's fields from the verifier's recorded words (in read order, identity length first): a structuring
    of values the verifier read, for quoting."""
    from xax_compiler import (
        AcceleratorMemorySpace, AtomicFamily, AtomicScope, BOARD_PROFILE, EffectDomain, HandlerEntryContract, TargetValueConstraint,
        TargetValueConstraintKind,
    )

    stream = iter(words[1:])
    take = stream.__next__

    def many(make=lambda value: value):
        return tuple(make(take()) for _ in range(take()))

    f = {"profile": take(), "arch": take(), "abi": take(), "format": take(), "word": take(), "pointer": take()}
    f.update(args=(), result=None, scratch=(), widths=(), scopes=(), families=(), handlers=(), lane=0, groups=0, acc_scopes=(), spaces=(),
             contracts=())
    if f["arch"] in (1, 3):
        f.update(stack=take(), shadow=take(), args=many())
        f.update(result=take(), scratch=many())
    f.update(operations=many(), terminators=many())

    def contracts():
        items = []
        for _ in range(take()):
            operation_id, semantic, encoding = take(), take(), take()
            operands, results = (tuple(TargetValueConstraint(TargetValueConstraintKind(take()), take(), take()) for _ in range(take())) for _signature in range(2))
            scopes_ = many(AtomicScope)
            source, destination, synchronizes, may_block, dependency = take(), take(), take(), take(), take()
            items.append({"id": operation_id, "semantic": semantic, "encoding": encoding, "constraints": (*operands, *results), "scopes": scopes_,
                          "source": source, "destination": destination, "dependency": dependency})
        return tuple(items)

    if f["profile"] in (2, BOARD_PROFILE):
        f.update(widths=many(), scopes=many(AtomicScope), families=many(AtomicFamily))
        handlers = []
        for _ in range(take()):
            fields = tuple(take() for _ in range(7))
            domains = many(EffectDomain)
            handlers.append(HandlerEntryContract(*fields, domains, take(), take()))
        f["handlers"] = tuple(handlers)
    if f["profile"] == 3:
        f.update(lane=take(), groups=take(), acc_scopes=many(AtomicScope))
        spaces = []
        for _ in range(take()):
            identity, address_bits, unit_bits, alignment = take(), take(), take(), take()
            widths, visibility = many(), many(AtomicScope)
            spaces.append(AcceleratorMemorySpace(identity, address_bits, unit_bits, alignment, widths, visibility, bool(take()), bool(take())))
        f.update(spaces=tuple(spaces), contracts=contracts())
    if f["profile"] in (4, BOARD_PROFILE):
        f["contracts"] = contracts()
    return f


def _target_rule_diagnostic(name, words, item, check, sub):
    """The bootstrap's diagnostic for a canonical target rule the verifier found broken (``item``: the failing space,
    contract, or handler; ``check``/``sub``: which contract check, and which constraint)."""
    f = target_fields(words)
    if name == "TARGET_X86_REGISTERS":
        return "XAX.TARGET.ABI", "TARGET-WINDOWS-X64-REGISTERS", [[1, 2, 8, 9], 0, [10, 11]], [list(f["args"]), f["result"], list(f["scratch"])]
    if name == "TARGET_AAPCS64_REGISTERS":
        return "XAX.TARGET.ABI", "TARGET-AAPCS64-REGISTERS", [list(range(8)), 0, [9, 10]], [list(f["args"]), f["result"], list(f["scratch"])]
    if name == "TARGET_ACC_TOPOLOGY":
        return "XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-TOPOLOGY", "positive lane width and max groups", [f["lane"], f["groups"]]
    if name == "TARGET_ACC_SCOPES":
        return "XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-SCOPES-CANONICAL", "sorted unique nonempty scopes", f["acc_scopes"]
    space_ids = tuple(space.identity for space in f["spaces"])
    if name == "TARGET_ACC_SPACES":
        return "XAX.TARGET.MEMORY_SPACE", "TARGET-MEMORY-SPACES-CANONICAL", "sorted unique nonempty memory spaces", space_ids
    if name == "TARGET_ACC_SPACE":
        return ("XAX.TARGET.MEMORY_SPACE", "TARGET-MEMORY-SPACE-CONTRACT", "positive widths, power-of-two alignment, canonical widths/scopes",
                f["spaces"][item])
    operation_ids = tuple(contract["id"] for contract in f["contracts"])
    if name in ("TARGET_ACC_OPERATIONS", "TARGET_PLATFORM_OPERATIONS"):
        if name == "TARGET_ACC_OPERATIONS":
            return "XAX.TARGET.OPERATION", "TARGET-OPERATIONS-CONTRACT-CANONICAL", "sorted unique nonempty target operation IDs", operation_ids
        return "XAX.TARGET.PLATFORM", "TARGET-PLATFORM-OPERATIONS-CANONICAL", "sorted unique nonempty target operation IDs", operation_ids
    if name in ("TARGET_ACC_CONTRACT", "TARGET_PLATFORM_CONTRACT"):
        contract = f["contracts"][item]
        accelerator = name == "TARGET_ACC_CONTRACT"
        code = "XAX.TARGET.OPERATION" if accelerator else "XAX.TARGET.PLATFORM"
        prefix = "TARGET-OPERATION" if accelerator else "TARGET-PLATFORM"
        check = check if accelerator else (1, 4, 5)[check - 1]  # platform checks: contract, constraint, dependency
        if check == 1:
            if accelerator:
                return code, "TARGET-OPERATION-ENCODING", "positive semantic code and byte opcode", [contract["semantic"], contract["encoding"]]
            return code, "TARGET-PLATFORM-OPERATION-CONTRACT", "positive semantic code and canonical scopes", contract["id"]
        if check == 2:
            return code, "TARGET-OPERATION-SCOPES", f["acc_scopes"], contract["scopes"]
        if check == 3:
            return code, "TARGET-OPERATION-MEMORY-SPACES", sorted(set(space_ids)), [contract["source"], contract["destination"]]
        if check == 4:
            constraint = contract["constraints"][sub]
            return (code, f"{prefix}-VALUE-CONSTRAINT", "canonical bits/resource/effect constraint",
                    [constraint.kind.value, constraint.primary, constraint.secondary])
        return code, f"{prefix}-RUNTIME-DEPENDENCY", "empty or 32-byte identity", contract["dependency"]
    if name == "TARGET_OPERATIONS":
        return "XAX.TARGET.OPERATIONS", "TARGET-OPERATIONS-CANONICAL", "sorted supported operation IDs", f["operations"]
    if name == "TARGET_TERMINATORS":
        return "XAX.TARGET.TERMINATORS", "TARGET-TERMINATORS-CANONICAL", "sorted supported terminator IDs", f["terminators"]
    if name == "TARGET_ATOMIC_WIDTHS":
        return "XAX.TARGET.ATOMICS", "TARGET-ATOMIC-WIDTHS-CANONICAL", "sorted positive widths", f["widths"]
    if name == "TARGET_ATOMIC_CAPABILITIES":
        return "XAX.TARGET.ATOMICS", "TARGET-ATOMIC-CAPABILITIES-CANONICAL", "sorted unique scopes/families", [f["scopes"], f["families"]]
    if name == "TARGET_HANDLER_ORDER":
        return "XAX.TARGET.HANDLER", "TARGET-HANDLER-ENTRIES-CANONICAL", "sorted unique event kinds", [entry.event_kind for entry in f["handlers"]]
    entry = f["handlers"][item]
    return ("XAX.TARGET.HANDLER", "TARGET-HANDLER-CONTRACT", "sorted unique effect domains and positive stack bound",
            [entry.allowed_effect_domains, entry.stack_bound])


def object_entity(obj, record, objects):
    """S8: the CID a rejection's diagnostic names when it is not ``obj`` (a missing reference, another object's
    ``_build_form``, a build rule about another object), else None.  ``OTHER_OBJECT`` takes that object's diagnostic."""
    site, payload = record[0], record[1]
    name = OBJECT_SITES[site - 1]
    if name == "OBJECT_MISSING":
        return obj.references[payload[0]]
    if name in ("BUILD_KIND_OF", "OTHER_OBJECT"):
        return objects[payload[0]].cid
    if name == "BUILD_RULE" and payload[5] != NONE:
        return objects[payload[5]].cid
    return None


def _build_rule_diagnostic(obj, rule, words, item, extra, objects, more=0):
    """The bootstrap's diagnostic for a build rule the verifier found broken, quoting the values it read (``words``:
    read order; strings as length and body offset, references as indices)."""
    from xax_build import BuildCapability, BuildCapabilityKind
    from xax_compiler import uleb

    if rule == BUILD_REFS_EXACT:
        _words, marks = words
        return ("XAX.CANON.UNUSED_REFERENCE", "BUILD-REFS-EXACT", tuple(range(len(obj.references))),
                tuple(k for k, marked in enumerate(marks) if marked))
    if rule >= BUILD_REQUEST_KINDS:
        return _composite_rule_diagnostic(obj, rule, words, item, extra, objects, more)
    stream = iter(words)
    take = stream.__next__
    kind_of = {item.cid: item.kind for item in objects}

    def string():
        length, at = take(), take()
        return bytes(obj.body[at:at + length])

    def strings():
        return tuple(string() for _ in range(take()))

    if obj.kind == Kind.BUILD:
        take()  # the form
    if rule == BUILD_IDENTITY:
        return "XAX.PACKAGE.IDENTITY", "PACKAGE-LOGICAL-IDENTITY", "nonempty bytes", "empty"
    if rule == BUILD_MODULES:
        return "XAX.PACKAGE.MODULE", "PACKAGE-MODULES", ">= 1", 0
    if rule == BUILD_MODULE_KIND:
        return "XAX.PACKAGE.MODULE", "PACKAGE-MODULE-KIND", Kind.MODULE.name, Kind(extra).name
    if rule == BUILD_EXACT_KIND:
        return "XAX.PACKAGE.DEPENDENCY", "PACKAGE-EXACT-KIND", Kind.PACKAGE.name, Kind(extra).name
    if rule == BUILD_DEPENDENCY_FORM:
        return "XAX.PACKAGE.DEPENDENCY", "PACKAGE-DEPENDENCY-FORM", [1, 2], extra
    canonical = lambda name, keys: ("XAX.BUILD.CANONICAL", name, "sorted unique values", tuple(keys))  # noqa: E731
    if obj.kind == Kind.PACKAGE:
        string()  # the logical identity
        modules = tuple(obj.references[take()] for _ in range(take()))
        if rule == BUILD_MODULES_CANONICAL:
            return canonical("PACKAGE-MODULES-CANONICAL", modules)
        keys = []
        for _ in range(take()):
            form = take()
            keys.append(b"\x01" + obj.references[take()] if form == 1 else b"\x02" + (lambda value: uleb(len(value)) + value)(string()))
        if rule == BUILD_DEPENDENCIES_CANONICAL:
            return canonical("PACKAGE-DEPENDENCIES-CANONICAL", keys)
        for number, expected_kind in enumerate((Kind.FUNCTION, Kind.TYPE, Kind.TYPE)):
            names = []
            for position in range(take()):
                name, child = string(), obj.references[take()]
                if rule == BUILD_NAMED_REFERENCE and (number, position) == (item, extra):
                    return ("XAX.PACKAGE.SCHEMA", "PACKAGE-NAMED-REFERENCE", ["nonempty", expected_kind.name], [name.hex(), kind_of[child].name])
                names.append(name)
            if rule == BUILD_NAMES_CANONICAL and number == item:
                return canonical("PACKAGE-NAMES-CANONICAL", names)
        capabilities = []
        for _ in range(take()):
            kind = take()
            capabilities.append(BuildCapability(BuildCapabilityKind(kind), string()))
        return canonical("PACKAGE-CAPABILITIES-CANONICAL", capabilities)
    if rule == BUILD_GRANTS_CANONICAL:
        take(), take(), take()  # mode, optimization, verification
        keys = []
        for _ in range(take()):
            identity, kind = string(), BuildCapabilityKind(take())
            keys.append((identity, kind, string()))
        return canonical("BUILD-GRANTS-CANONICAL", keys)
    if rule in (BUILD_ALGORITHMS_CANONICAL, BUILD_SIGNERS_CANONICAL, BUILD_TRUST_NONEMPTY, BUILD_TRUST_REQUIRED):
        take(), take()  # the two flags
        algorithms, signers = strings(), strings()
        if rule == BUILD_ALGORITHMS_CANONICAL:
            return canonical("TRUST-ALGORITHMS-CANONICAL", algorithms)
        if rule == BUILD_SIGNERS_CANONICAL:
            return canonical("TRUST-SIGNERS-CANONICAL", signers)
        if rule == BUILD_TRUST_NONEMPTY:
            return "XAX.TRUST.EMPTY", "TRUST-IDENTITY-NONEMPTY", "nonempty identities", "empty"
        return "XAX.TRUST.EMPTY", "TRUST-REQUIRED-SETS", "accepted algorithms and signers", [algorithms, signers]
    if rule == BUILD_SIGNATURE_NONEMPTY:
        take()  # the signed object
        return "XAX.TRUST.SIGNATURE", "TRUST-SIGNATURE-NONEMPTY", "nonempty fields", [string().hex() for _ in range(3)]
    if rule == BUILD_OPT_REFERENCES:
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", [], [cid.hex() for cid in obj.references]
    raise ValueError(f"unknown build rule {rule}")


def _composite_rule_diagnostic(obj, rule, words, item, extra, objects, more):
    """S8: requests, snapshots, and provenance (``_build_rule_diagnostic``).  Values the verifier read are quoted from
    its words; lists it read from proven packages, profiles, and signatures are quoted from their decoded views."""
    import xax_build as B

    listed, quoted = words if isinstance(words, tuple) else (words, None)
    by_cid = {item_.cid: item_ for item_ in objects}
    resolve = by_cid.__getitem__
    h = lambda index: objects[index].cid.hex()  # noqa: E731
    stream = iter(listed)
    take = stream.__next__

    def string():
        length, at = take(), take()
        return bytes(obj.body[at:at + length])

    canonical = lambda name, keys: ("XAX.BUILD.CANONICAL", name, "sorted unique values", tuple(keys))  # noqa: E731
    if rule == BUILD_REQUEST_KINDS:
        return ("XAX.BUILD.REQUEST", "BUILD-REQUEST-REFERENCE-KINDS", [Kind.PACKAGE.name, Kind.TARGET.name, B.BuildForm.PROFILE.name],
                [Kind(item).name, Kind(extra).name, B.BuildForm(more).name])
    if rule == BUILD_TYPED_VALUE:
        return "XAX.BUILD.VALUE", "BUILD-TYPED-VALUE", Kind.CONSTANT.name, Kind(item).name
    if rule == BUILD_CONSTANT_TYPE:
        return "XAX.STRUCT.REF_INDEX", "BUILD-CONSTANT-TYPE", f"< {item}", extra
    if rule == BUILD_BINDING_TYPE:
        return "XAX.BUILD.VALUE_TYPE", "BUILD-BINDING-TYPE", h(item), h(extra)
    if rule == BUILD_ARTIFACT_REQUIRED:
        return "XAX.BUILD.ARTIFACT", "BUILD-ARTIFACT-REQUIRED", ">= 1", 0
    if rule in (BUILD_ENTRY_DECLARED, BUILD_BINDINGS_CANONICAL, BUILD_BINDINGS_COMPLETE, BUILD_ARTIFACTS_CANONICAL):
        take()  # the form
        package_object = resolve(obj.references[take()])
        entry = string()
        take(), take()  # target, profile
        view = B.decode_package(package_object, resolve)
        if rule == BUILD_ENTRY_DECLARED:
            return "XAX.BUILD.ENTRY", "BUILD-ENTRY-DECLARED", [name.hex() for name, _ in view.build_entries], entry.hex()
        for number, schema in enumerate((view.feature_types, view.configuration_types)):
            names = []
            for _ in range(take()):
                names.append(string())
                take()  # the value
            if rule == BUILD_BINDINGS_CANONICAL and number == item:
                return canonical("BUILD-BINDINGS-CANONICAL", names)
            if rule == BUILD_BINDINGS_COMPLETE and number == item:
                return ("XAX.BUILD.INPUT_CLOSURE", "BUILD-BINDINGS-COMPLETE", sorted(name.hex() for name in dict(schema)),
                        sorted(name.hex() for name in names))
        return canonical("BUILD-ARTIFACTS-CANONICAL", (B.ArtifactKind(take()) for _ in range(take())))
    if rule in (BUILD_PROVENANCE_KINDS, BUILD_PROVENANCE_CLOSURE):
        take()  # the form
        snapshot, request, target, profile = (resolve(obj.references[take()]) for _ in range(4))
        if rule == BUILD_PROVENANCE_KINDS:
            return ("XAX.PROVENANCE.REFERENCE", "PROVENANCE-REFERENCE-KINDS", "snapshot/request/target/profile",
                    [snapshot.kind.name, request.kind.name, target.kind.name, profile.kind.name])
        return ("XAX.PROVENANCE.CLOSURE", "PROVENANCE-EXACT-CLOSURE", [h(item), h(extra), h(more)],
                [request.cid.hex(), target.cid.hex(), profile.cid.hex()])
    # Snapshots.
    take()  # the form
    request = resolve(obj.references[take()])
    identity = string()
    policy = resolve(obj.references[take()])
    if rule == BUILD_SNAPSHOT_HEADER:
        return "XAX.SNAPSHOT.HEADER", "SNAPSHOT-HEADER", "request, resolver identity, trust policy", [request.kind.name, identity.hex(), policy.kind.name]
    if rule == BUILD_RESOLVE_EXACT:
        return "XAX.RESOLVE.MISSING", "RESOLVE-EXACT-ROOT", h(item), "missing"
    if rule == BUILD_RESOLVE_LOGICAL:
        matches = sorted(objects[index].cid for index in quoted)
        return ("XAX.RESOLVE.AMBIGUOUS" if matches else "XAX.RESOLVE.MISSING", "RESOLVE-LOGICAL-IDENTITY", "exactly one candidate",
                [cid.hex() for cid in matches])
    packages = tuple(resolve(obj.references[take()]) for _ in range(take()))
    signatures = tuple(resolve(obj.references[take()]) for _ in range(take()))
    if rule == BUILD_SNAPSHOT_PACKAGE_KIND:
        return "XAX.SNAPSHOT.PACKAGE", "SNAPSHOT-PACKAGE-KIND", Kind.PACKAGE.name, [item_.kind.name for item_ in packages]
    if rule == BUILD_SNAPSHOT_SIGNATURE_KIND:
        return ("XAX.SNAPSHOT.SIGNATURE", "SNAPSHOT-SIGNATURE-KIND", B.BuildForm.SIGNATURE.name,
                [B.BuildForm(item_.body[0]).name for item_ in signatures])
    if rule == BUILD_SNAPSHOT_PACKAGES_CANONICAL:
        return canonical("SNAPSHOT-PACKAGES-CANONICAL", (item_.cid for item_ in packages))
    if rule == BUILD_SNAPSHOT_SIGNATURES_CANONICAL:
        return canonical("SNAPSHOT-SIGNATURES-CANONICAL", (item_.cid for item_ in signatures))
    if rule == BUILD_SNAPSHOT_EXTERNAL_CANONICAL:
        return canonical("SNAPSHOT-EXTERNAL-CANONICAL", (bytes(obj.body[at:at + 32]) for at in (take() for _ in range(take()))))
    if rule == BUILD_SNAPSHOT_ROOT:
        return "XAX.SNAPSHOT.ROOT", "SNAPSHOT-ROOT-PACKAGE", h(more), "missing"
    if rule == BUILD_SNAPSHOT_CLOSURE:
        reached = [item_ for item_, seen in zip(packages, quoted) if seen]
        return "XAX.SNAPSHOT.CLOSURE", "SNAPSHOT-EXACT-CLOSURE", sorted(item_.cid.hex() for item_ in reached), sorted(item_.cid.hex() for item_ in packages)
    if rule == BUILD_GRANT_DECLARED:
        grant = B.decode_profile(objects[more]).grants[item]
        identities = list(dict.fromkeys(B.decode_package(item_, resolve).logical_identity for item_ in packages))
        return "XAX.BUILD.CAPABILITY", "BUILD-GRANT-DECLARED", [identity_.hex() for identity_ in identities], [grant.logical_identity.hex(), grant.capability]
    signed = [B.decode_signature(item_, resolve).signed_root.hex() for item_ in signatures]
    if rule == BUILD_SIGNATURE_PACKAGE:
        return "XAX.TRUST.SNAPSHOT", "TRUST-SIGNATURE-PACKAGE", [item_.cid.hex() for item_ in packages], signed
    if rule == BUILD_SIGNATURE_COVERAGE:
        return "XAX.TRUST.REQUIRED", "TRUST-SNAPSHOT-COVERAGE", [item_.cid.hex() for item_ in packages], signed
    raise ValueError(f"unknown build rule {rule}")


def object_diagnostic(obj, record, objects=()):
    """S8c.19: the bootstrap's ``(code, rule, expected, actual)`` for a rejected object (rendering only: the verifier
    decided the check and its values).  ``objects``: the object table, for quoted object indices."""
    site, payload, listed = record[:3]
    x, y = payload[:2]
    name = OBJECT_SITES[site - 1]
    if name == "OBJECT_MISSING":
        return "XAX.IDENTITY.OBJECT_MISSING", "ID-REFERENCE-RESOLVED", "stored object", "missing"
    if name == "BODY_TAKE":
        return "XAX.CANON.TRUNCATED", "SER-BOUNDS", f"{x} available bytes", y
    if name == "BODY_BOOL":
        return "XAX.CANON.BOOL", "SER-BOOL-CANONICAL", "00 or 01", f"{x:02x}"
    if name == "BODY_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", BODY_RULES[x], 0, y
    if name == "BUILD_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "BUILD-REF-INDEX", f"< {x}", y
    if name == "BUILD_ENUM":
        import xax_build

        enum = getattr(xax_build, BUILD_ENUMS[x - 1])
        rule = ("BUILD-FORM", "BUILD-MODE", "BUILD-CAPABILITY-KIND", "BUILD-ARTIFACT-KIND", "OPT-OBJECTIVE")[x - 1]
        return "XAX.BUILD.ENUM", rule, sorted(item.value for item in enum), y
    if name == "BUILD_RULE":
        return _build_rule_diagnostic(obj, x, listed, payload[3], payload[4], objects, payload[6])
    if name == "BUILD_KIND_OF":
        return "XAX.BUILD.KIND", "BUILD-KIND", Kind.BUILD.name, objects[x].kind.name
    if name == "BODY_ULEB":
        return _uleb_diagnostic(obj, x, y, payload[2])
    if name in TARGET_WORD_SITES:
        return _target_rule_diagnostic(name, listed, *payload[2:5])
    if name == "TARGET_SECTION":
        return _target_section_diagnostic(x, y, payload[2])
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
    if name == "GROUP_ORDER":
        return "XAX.CANON.RECURSION_ORDER", "GRAPH-RECURSION-ORDER", list(listed), list(range(len(listed)))
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
    if name == "GRAPH_TRAP_PAYLOAD":
        return "XAX.CONTROL.TRAP_PAYLOAD", "TRAP-PAYLOAD-CANONICAL", "empty or canonical u16 ULEB reason with optional target bytes", TRAP_ERRORS[x - 1]
    if name in ("GROUP_UNUSED", "GRAPH_UNUSED"):
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
    if name == "FUNCTION_GROUP_CONTEXT":
        return "XAX.STRUCT.GROUP_CALL_CONTEXT", "GRAPH-GROUP-CALL-CONTEXT", Kind.RECURSION_GROUP.name, Kind.FUNCTION.name
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
            status, stream, diagnostic = decoder.decode_with_diagnostic(obj.body, len(obj.references), obj.cid)
            if status != 0 and diagnostic is None:
                return None
            payload = list(stream)  # S8 (ADR-251): a rejected body's stream prefix, flagged after the body bytes
            words += [len(payload), *payload, len(obj.body), *obj.body, int(status != 0)]  # the body bytes (recursion-group keys)
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
