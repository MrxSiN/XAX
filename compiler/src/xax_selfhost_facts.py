"""Self-hosting step S4d.2 (ADR-137): the verifier's memory-fact passes as XAX semantics.

The bootstrap verifier (``_parse_graph_uncached``) tracks, per value, pointer
facts (storage, element, permission, offset, extent, alignment, alias class,
window, record, link target), owner facts, and memory-effect facts (storage and
initialized byte intervals), per block the live and ended storages, and per
edge the facts carried into the target's parameters.  Blocks are visited in
reverse postorder; back edges contribute their previous pass's facts, and
passes repeat until the block-entry facts reach a fixpoint.

This module builds the same analysis as XAX functions.  It is called by the
XAX typing function (``xax_selfhost_typing``) after typing, over a facts
section of the same input stream, and either *accepts* the graph (every node
it was given is one it models, every check holds, and the passes converge) or
declines.  Acceptance is one-sided: the engine accepts only what the
bootstrap accepts, with the same pointer extents; on decline the bootstrap
passes run and raise the exact diagnostic.  Stage S4d.2b models stack
storage (``stack.alloc``, ``stack.end``, ``address.offset``, ``load/store.bits.le``,
``pointer.cast``), memory frontiers through direct calls, and every
non-memory node; anything else declines.

Facts section (input words): V values, S storage sites, E edges, B blocks,
entry block, the block order (B words), S site kinds, then per block in index
order: parameter value base, parameter count P and P type indices, node count
and per node ``[operation, typing key, entity, site, result value base,
attribute count, attributes, operand count, operand value ids, operand type
indices, result count, result type indices]``, the terminator ``[kind, value
count, value ids, edge count, per edge: target, edge id, argument count,
argument value ids]``, and the incoming edge ids ``[count, ids]``.  ``NONE``
marks an absent index.
"""

from __future__ import annotations

import xax_selfhost_typing as _T
from xax_compiler import IntCompare, Operation, Permission, TerminatorKind
from xax_selfhost_cfg import MEM
from xax_selfhost_typing import IN_POINTER, IN_VIEW, IN_WORDS, OUT_POINTER, OUT_VIEW, OUT_WORDS
from xax_structured import B1, B32, B64, Proc

NONE = 0xFFFFFFFF
VIEWS = ("ip", "iv", "im", "op", "ov", "om")
VIEW_TYPES = (IN_POINTER, IN_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
# Header words at the end of the output view.
HEADER = OUT_WORDS - 64
(H_STATUS, H_FACTS_AT, H_V, H_S, H_E, H_B, H_ENTRY, H_NODES, H_VALUES, H_SITES, H_BLOCKS, H_EDGES, H_ARENA, H_ARENA_END,
 H_VISIT, H_PASS, H_ORDER, H_EXTENTS, H_STALE, H_COUNT, H_TABLE, H_LIST, H_KINDS, H_ENTRY_FACTS, H_CIDS, H_REASON, H_NODE,
 H_RENTRY, H_RENTRY_SEED_INIT, H_RENTRY_LAST, H_LINEAR) = range(31)
# Decline sites: H_REASON names the check that declined (``DECLINE_SITES[code]``: "file:line"), for diagnosis only.
DECLINE_SITES: list[str] = []
ACCEPTED = 1
# Arguments past the second travel in header words (the native ABI takes four machine arguments,
# two of which are the view pointers); a callee reads them before anything else.
H_ARG = 32
REGISTER_ARGUMENTS = 2
# S8c.8 (ADR-221): exact memory rejections.  The engine records the first failing check that is one of the
# bootstrap's own memory checks (``MEMORY_SITES``), where it fails (pass, block, node; the node count for the
# terminator), and its payload; production raises that diagnostic at the same point of its fact passes.
H_CUROP, H_MNODE, H_CURBLOCK, H_REJECT, H_RPASS, H_RBLOCK, H_RNODE = range(34, 41)
H_RPAY = 41  # payload words H_RPAY .. H_RPAY + 5
MEMORY_SITES = (
    "PROVENANCE_PROVEN", "LIFETIME_LIVE", "OP_CONTRACT", "ACCESS_SIZE", "POINTER_ELEMENT_SIZE", "ALIGNMENT", "BOUNDS",
    "READ_PERMISSION", "WRITE_PERMISSION", "EFFECT_PROVEN", "EFFECT_LINEAR", "EFFECT_PROVENANCE", "INITIALIZED",
    "ADDRESS_BOUNDS", "LIFETIME_LEAK", "OWNER_PROVEN", "OWNER_LIVE", "ALLOCATION_ALIGNMENT",
    # S8c.9 (ADR-226): checked accesses, and the type checks of loads and stores.
    "LOAD_TYPE", "STORE_TYPE", "STORE_EFFECT_TYPE", "CHECKED_ALIGNMENT", "CHECKED_OFFSET", "CHECKED_LOAD_TYPE", "CHECKED_STORE_TYPE",
    "CHECKED_EFFECT_TYPE", "CHECKED_INITIALIZED",
    # S8c.10 (ADR-227): rebase windows.
    "REBASE_ADDRESS_WIDTH", "REBASE_AUTHORITY", "REBASE_EXTENT", "REBASE_ALIGNMENT",
    # S8c.11 (ADR-228): returned views.
    "RETURN_WHOLE", "RETURN_INITIALIZED", "LINK_RETURN_TARGET", "RETURN_ORDER",
)
M = {name: index + 1 for index, name in enumerate(MEMORY_SITES)}
# Per-value fields (each an array of V words).
(PK, PST, PEL, PPERM, POFF, PEXT, PALIGN, PALIAS, PWIN, PREC, PLT, PLR, PSTAMP, OST, OSTAMP, EST, EIV, ESTAMP, ECON, OCON) = range(20)
# S4d.2c: heap allocation facts (pass-stamped), and each value's defining node record (NONE: a parameter).
(HSTAMP, HST, HSIZE, HZERO, HALIGN, DEF) = range(20, 26)
ECOP = 26  # S8c.8: the operation that consumed a frontier (``effect_consumers``), set with ECON
VALUE_FIELDS = 27
POINTER_WORDS = 12  # PK..PLR
SLOT = POINTER_WORDS + 3  # pointer fact, owner storage, effect storage, effect intervals
NO_POINTER, POINTER, LINK = 0, 1, 2
SITE_STACK, SITE_BORROWED, SITE_NODE, SITE_CALL = 0, 1, 2, 3
SUPPORTED = frozenset({Operation.STACK_ALLOC, Operation.STACK_END, Operation.ADDRESS_OFFSET, Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE, Operation.POINTER_CAST})


class E:
    """Helpers over a :class:`Proc` whose last six names are the input and output view triples."""

    def __init__(self, proc: Proc, tables):
        self.p = proc
        self.tables = tables  # typing table indices (module xax_selfhost_typing)

    # -- values ------------------------------------------------------------------
    def c(self, value: int):
        return self.p.const(value & ((1 << 64) - 1), B64)

    def v(self, value):
        return self.c(value) if isinstance(value, int) else value

    def bin(self, operation, x, y):
        return self.p.op1(operation, (self.v(x), self.v(y)), B64)

    def add(self, x, y):
        return self.bin(Operation.ADD_WRAP, x, y)

    def sub(self, x, y):
        return self.bin(Operation.SUB_WRAP, x, y)

    def mul(self, x, y):
        return self.bin(Operation.MUL_WRAP, x, y)

    def and_(self, x, y):
        return self.bin(Operation.BIT_AND, x, y)

    def or_(self, x, y):
        return self.bin(Operation.BIT_OR, x, y)

    def udiv(self, x, y):
        return self.bin(Operation.UDIV, x, y)

    def urem(self, x, y):
        return self.bin(Operation.UREM, x, y)

    def cmp(self, kind, x, y):
        return self.p.op1(Operation.INT_COMPARE, (self.v(x), self.v(y)), B1, attributes=(kind,))

    def eq(self, x, y):
        return self.cmp(IntCompare.EQ, x, y)

    def ne(self, x, y):
        return self.cmp(IntCompare.NE, x, y)

    def lt(self, x, y):
        return self.cmp(IntCompare.ULT, x, y)

    def le(self, x, y):
        return self.cmp(IntCompare.ULE, x, y)

    def flag(self, condition):
        return self.p.op1(Operation.INT_ZERO_EXTEND, (condition,), B64)

    def both(self, *conditions):
        # 64-bit flags: the native frame path lowers bitwise operations on bits<32> and bits<64> only.
        result = self.flag(conditions[0])
        for item in conditions[1:]:
            result = self.and_(result, self.flag(item))
        return self.ne(result, 0)

    def either(self, *conditions):
        result = self.flag(conditions[0])
        for item in conditions[1:]:
            result = self.or_(result, self.flag(item))
        return self.ne(result, 0)

    def not_(self, condition):
        return self.eq(self.flag(condition), 0)

    def sel(self, condition, if_true, if_false):
        if_true, if_false = self.v(if_true), self.v(if_false)
        return self.add(if_false, self.mul(self.flag(condition), self.sub(if_true, if_false)))

    def power_of_two(self, value):
        return self.both(self.ne(value, 0), self.eq(self.and_(value, self.sub(value, 1)), 0))

    # -- memory --------------------------------------------------------------------
    def _offset(self, index, limit: int):
        index = self.v(index)
        clamped = self.sel(self.lt(index, limit), index, limit - 1)
        return self.p.op1(Operation.INT_TRUNCATE, (self.mul(clamped, 8),), B32)

    def rd(self, index):
        p = self.p
        value, p["im"] = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["ip"], self._offset(index, IN_WORDS), p["im"]), (B64, MEM), attributes=(8, 1))
        return value

    def ld(self, index):
        p = self.p
        value, p["om"] = p.op(Operation.CHECKED_LOAD_BITS_LE, (p["op"], self._offset(index, OUT_WORDS), p["om"]), (B64, MEM), attributes=(8, 1))
        return value

    def st(self, index, value):
        p = self.p
        p["om"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["op"], self._offset(index, OUT_WORDS), self.v(value), p["om"]), MEM, attributes=(8, 1))

    def hd(self, field: int):
        return self.ld(HEADER + field)

    def set_hd(self, field: int, value):
        self.st(HEADER + field, value)

    def table(self, table: int, type_index):
        """A typing table entry (0 outside the table)."""
        count = self.hd(H_COUNT)
        valid = self.lt(type_index, count)
        index = self.sel(valid, type_index, 0)
        return self.mul(self.flag(valid), self.ld(self.add(self.add(self.hd(H_TABLE), self.mul(count, table)), index)))

    def value(self, field: int, value_id):
        return self.ld(self.add(self.add(self.hd(H_VALUES), self.mul(self.hd(H_V), field)), value_id))

    def set_value(self, field: int, value_id, word):
        self.st(self.add(self.add(self.hd(H_VALUES), self.mul(self.hd(H_V), field)), value_id), word)

    # -- control ---------------------------------------------------------------------
    def var(self, name: str, value=0):
        """Declare ``name`` (or reassign it when already in scope).

        A value another variable already holds is bound as a fresh copy (``value + 0``): two variables never
        share one SSA value, so block arguments never pass one value twice (the x86-64 register-resident
        lowering has lost such a copy across later control flow; see the S6b.2 handoff note)."""
        value = self.v(value)
        if not isinstance(value, int) and any(held == value for other, held in self.p.vars.items() if other != name):
            value = self.add(value, 0)
        if name in self.p.types:
            self.p[name] = value
        else:
            self.p.let(name, B64, value)

    def set(self, name: str, value):
        self.p[name] = self.v(value)

    def if_(self, condition, then, otherwise=None):
        self.p.if_(condition, lambda _p: then(), (lambda _p: otherwise()) if otherwise is not None else None)

    def while_(self, condition, body):
        self.p.while_(lambda _p: condition(), lambda _p: body())

    def for_(self, name: str, start, stop, body):
        """``for name in range(start, stop)``; ``stop`` is evaluated once."""
        self.var(name, start)
        limit = f"{name}_stop"
        self.var(limit, stop)
        self.while_(lambda: self.lt(self.p[name], self.p[limit]), lambda: (body(), self.set(name, self.add(self.p[name], 1))))

    def views(self):
        return tuple(self.p[name] for name in VIEWS)

    def take_views(self, values):
        for name, value in zip(VIEWS, values):
            self.p[name] = value

    def call(self, function, *arguments):
        values = [self.v(item) for item in arguments]
        for index, value in enumerate(values[REGISTER_ARGUMENTS:]):
            self.set_hd(H_ARG + index, value)
        results = self.p.op(Operation.CALL_DIRECT, (*values[:REGISTER_ARGUMENTS], *self.views()), (B64, *VIEW_TYPES), entity=function)
        self.take_views(results[1:])
        return results[0]

    def give(self, value):
        """Return ``value`` and the views from the current path."""
        self.p.ret(self.v(value), *self.views())

    def alloc(self, words):
        """Bump-allocate ``words`` from the arena; NONE when it is exhausted (the caller declines)."""
        start = self.hd(H_ARENA)
        end = self.add(start, words)
        self.set_hd(H_ARENA, end)
        return self.sel(self.le(end, self.hd(H_ARENA_END)), start, NONE)


def _function(name_arguments, build, tables):
    """An XAX helper ``f(arguments..., views) -> (bits<64>, views)``."""
    proc = Proc((*((name, B64) for name in name_arguments[:REGISTER_ARGUMENTS]), *zip(VIEWS, VIEW_TYPES)))
    e = E(proc, tables)
    for index, name in enumerate(name_arguments[REGISTER_ARGUMENTS:]):
        e.var(name, e.hd(H_ARG + index))
    build(e)
    function = proc.function((B64, *VIEW_TYPES))
    return function, tuple(proc.graph.objects.values())


# -- interval lists: [count, start0, end0, ...], sorted, disjoint, never touching ----------------

def _covers(tables):
    def build(e: E):
        p = e.p
        e.var("found", 0)
        e.for_("k", 0, e.ld(p["list"]), lambda: e.if_(
            e.both(e.le(e.ld(e.add(p["list"], e.add(1, e.mul(p["k"], 2)))), p["start"]), e.le(p["end"], e.ld(e.add(p["list"], e.add(2, e.mul(p["k"], 2)))))),
            lambda: e.set("found", 1)))
        e.give(p["found"])
    return _function(("list", "start", "end"), build, tables)


def _insert(tables):
    """``_merge_interval``: the list with [start, end) added and coalesced (``old_start <= last_end`` joins)."""
    def build(e: E):
        p = e.p
        count = e.ld(p["list"])
        e.var("out", e.alloc(e.add(e.mul(e.add(count, 1), 2), 1)))
        e.if_(e.eq(p["out"], NONE), lambda: e.give(NONE))
        e.var("n", 0)
        e.var("pending", 1)  # the new interval, not yet placed

        def push(start, end):
            # Append (start, end), joining the last interval when start <= its end.
            def join():
                last_end = e.add(p["out"], e.mul(p["n"], 2))
                e.if_(e.lt(e.ld(last_end), end), lambda: e.st(last_end, end))

            def append():
                e.st(e.add(p["out"], e.add(1, e.mul(p["n"], 2))), start)
                e.st(e.add(p["out"], e.add(2, e.mul(p["n"], 2))), end)
                e.set("n", e.add(p["n"], 1))

            e.if_(e.both(e.ne(p["n"], 0), e.le(start, e.ld(e.add(p["out"], e.mul(p["n"], 2))))), join, append)

        def each():
            old_start = e.ld(e.add(p["list"], e.add(1, e.mul(p["k"], 2))))
            old_end = e.ld(e.add(p["list"], e.add(2, e.mul(p["k"], 2))))
            # Tuples sort by (start, end): the new one goes first when it is smaller.
            smaller = e.either(e.lt(p["start"], old_start), e.both(e.eq(p["start"], old_start), e.lt(p["end"], old_end)))
            e.if_(e.both(e.ne(p["pending"], 0), smaller), lambda: (push(p["start"], p["end"]), e.set("pending", 0)))
            push(old_start, old_end)

        e.for_("k", 0, count, each)
        e.if_(e.ne(p["pending"], 0), lambda: push(p["start"], p["end"]))
        e.st(p["out"], p["n"])
        e.give(p["out"])
    return _function(("list", "start", "end"), build, tables)


def _intersect(tables, insert):
    """``_intersect_intervals``: pairwise overlaps, coalesced."""
    def build(e: E):
        p = e.p
        e.var("out", e.alloc(1))
        e.if_(e.eq(p["out"], NONE), lambda: e.give(NONE))
        e.st(p["out"], 0)

        def each_left():
            left_start = e.ld(e.add(p["left"], e.add(1, e.mul(p["i"], 2))))
            left_end = e.ld(e.add(p["left"], e.add(2, e.mul(p["i"], 2))))

            def each_right():
                right_start = e.ld(e.add(p["right"], e.add(1, e.mul(p["j"], 2))))
                right_end = e.ld(e.add(p["right"], e.add(2, e.mul(p["j"], 2))))
                start = e.sel(e.lt(left_start, right_start), right_start, left_start)
                end = e.sel(e.lt(left_end, right_end), left_end, right_end)

                def add():
                    e.set("out", e.call(insert, p["out"], start, end))
                    e.if_(e.eq(p["out"], NONE), lambda: e.give(NONE))

                e.if_(e.lt(start, end), add)

            e.for_("j", 0, e.ld(p["right"]), each_right)

        e.for_("i", 0, e.ld(p["left"]), each_left)
        e.give(p["out"])
    return _function(("left", "right"), build, tables)


def _list_equal(tables):
    def build(e: E):
        p = e.p
        count = e.ld(p["left"])
        e.var("same", e.flag(e.eq(count, e.ld(p["right"]))))
        e.if_(e.eq(p["same"], 0), lambda: e.give(0))
        e.for_("k", 1, e.add(e.mul(count, 2), 1), lambda: e.if_(e.ne(e.ld(e.add(p["left"], p["k"])), e.ld(e.add(p["right"], p["k"]))), lambda: e.set("same", 0)))
        e.give(p["same"])
    return _function(("left", "right"), build, tables)


# -- block-fact records: [k, k slots of SLOT words, ended (S words), live (S words)] ----------------

def _record_size(e: E, k):
    return e.add(e.add(1, e.mul(k, SLOT)), e.mul(e.hd(H_S), 2))


def _slot(e: E, record, index, word: int):
    return e.add(e.add(record, e.add(1, e.mul(index, SLOT))), word)


def _sets(e: E, record, which: int):
    """Base of the ended (0) or live (1) site set of ``record``."""
    k = e.ld(record)
    return e.add(e.add(record, e.add(1, e.mul(k, SLOT))), e.mul(e.hd(H_S), which))


def _empty_record(tables):
    def build(e: E):
        p = e.p
        e.var("record", e.alloc(_record_size(e, p["k"])))
        e.if_(e.eq(p["record"], NONE), lambda: e.give(NONE))
        e.st(p["record"], p["k"])

        def clear():
            for word in range(SLOT):
                e.st(_slot(e, p["record"], p["i"], word), NONE if word in (PST, PREC, PLT, PLR, POINTER_WORDS, POINTER_WORDS + 1) else 0)

        e.for_("i", 0, p["k"], clear)
        e.for_("s", 0, e.mul(e.hd(H_S), 2), lambda: e.st(e.add(_sets(e, p["record"], 0), p["s"]), 0))
        e.give(p["record"])
    return _function(("k",), build, tables)


def _pointer_equal(e: E, left, right):
    """Pointer words of two slots (or a slot and a value's fields) equal: a conjunction."""
    result = None
    for word in range(POINTER_WORDS):
        same = e.eq(left(word), right(word))
        result = same if result is None else e.both(result, same)
    return result


def _merge(tables, empty, intersect):
    """``_merge_block_facts``: the meet of ``count`` records listed at ``list``, for ``k`` parameters."""
    def build(e: E):
        p = e.p
        e.var("record", e.call(empty, p["k"]))
        e.if_(e.eq(p["record"], NONE), lambda: e.give(NONE))
        e.if_(e.eq(p["count"], 0), lambda: e.give(p["record"]))
        first = lambda: e.ld(p["list"])  # noqa: E731

        def each_index():
            i = p["i"]
            # Pointer facts: all equal, or all links naming at most one non-null target.
            e.var("equal", e.flag(e.ne(e.ld(_slot(e, first(), i, PK)), NO_POINTER)))
            e.var("links", 1)
            e.var("targets", 0)
            e.var("target_storage", NONE)
            e.var("target_record", NONE)

            def each_record():
                record = e.ld(e.add(p["list"], p["r"]))
                same = _pointer_equal(e, lambda w: e.ld(_slot(e, record, i, w)), lambda w: e.ld(_slot(e, first(), i, w)))
                e.if_(e.not_(same), lambda: e.set("equal", 0))
                kind = e.ld(_slot(e, record, i, PK))
                e.if_(e.ne(kind, LINK), lambda: e.set("links", 0))
                storage, link_record = e.ld(_slot(e, record, i, PST)), e.ld(_slot(e, record, i, PREC))

                def target():
                    known = e.both(e.eq(storage, p["target_storage"]), e.eq(link_record, p["target_record"]))
                    e.if_(e.both(e.ne(p["targets"], 0), known), lambda: None, lambda: (
                        e.set("targets", e.add(p["targets"], 1)), e.set("target_storage", storage), e.set("target_record", link_record)))

                e.if_(e.both(e.eq(kind, LINK), e.ne(storage, NONE)), target)

            e.for_("r", 0, p["count"], each_record)

            def copy_first():
                for word in range(POINTER_WORDS):
                    e.st(_slot(e, p["record"], i, word), e.ld(_slot(e, first(), i, word)))

            def join_link():
                e.st(_slot(e, p["record"], i, PK), LINK)
                e.st(_slot(e, p["record"], i, PST), p["target_storage"])
                e.st(_slot(e, p["record"], i, PREC), p["target_record"])

            e.if_(e.ne(p["equal"], 0), copy_first, lambda: e.if_(e.both(e.ne(p["links"], 0), e.eq(p["targets"], 1)), join_link))
            # Owners: all equal.
            owner = e.ld(_slot(e, first(), i, POINTER_WORDS))
            e.var("owner_same", e.flag(e.ne(owner, NONE)))
            e.for_("r", 0, p["count"], lambda: e.if_(e.ne(e.ld(_slot(e, e.ld(e.add(p["list"], p["r"])), i, POINTER_WORDS)), owner), lambda: e.set("owner_same", 0)))
            e.if_(e.ne(p["owner_same"], 0), lambda: e.st(_slot(e, p["record"], i, POINTER_WORDS), owner))
            # Effects: one storage on every edge; initialized bytes intersect.
            storage = e.ld(_slot(e, first(), i, POINTER_WORDS + 1))
            e.var("effect_same", e.flag(e.ne(storage, NONE)))
            e.for_("r", 0, p["count"], lambda: e.if_(e.ne(e.ld(_slot(e, e.ld(e.add(p["list"], p["r"])), i, POINTER_WORDS + 1)), storage), lambda: e.set("effect_same", 0)))

            def effect():
                e.var("intervals", e.ld(_slot(e, first(), i, POINTER_WORDS + 2)))

                def narrow():
                    e.set("intervals", e.call(intersect, p["intervals"], e.ld(_slot(e, e.ld(e.add(p["list"], p["r"])), i, POINTER_WORDS + 2))))
                    e.if_(e.eq(p["intervals"], NONE), lambda: e.give(NONE))

                e.for_("r", 1, p["count"], narrow)
                e.st(_slot(e, p["record"], i, POINTER_WORDS + 1), storage)
                e.st(_slot(e, p["record"], i, POINTER_WORDS + 2), p["intervals"])

            e.if_(e.ne(p["effect_same"], 0), effect)

        e.for_("i", 0, p["k"], each_index)

        def each_site():
            e.var("ended", 0)
            e.var("live", 0)

            def gather():
                record = e.ld(e.add(p["list"], p["r"]))
                e.set("ended", e.or_(p["ended"], e.ld(e.add(_sets(e, record, 0), p["s"]))))
                e.set("live", e.or_(p["live"], e.ld(e.add(_sets(e, record, 1), p["s"]))))

            e.for_("r", 0, p["count"], gather)
            e.st(e.add(_sets(e, p["record"], 0), p["s"]), p["ended"])
            e.st(e.add(_sets(e, p["record"], 1), p["s"]), p["live"])

        e.for_("s", 0, e.hd(H_S), each_site)
        e.give(p["record"])
    return _function(("list", "count", "k"), build, tables)


def _record_equal(tables, list_equal):
    def build(e: E):
        p = e.p
        k = e.ld(p["left"])
        e.var("same", e.flag(e.eq(k, e.ld(p["right"]))))
        e.if_(e.eq(p["same"], 0), lambda: e.give(0))

        def each_index():
            for word in range(POINTER_WORDS + 2):
                e.if_(e.ne(e.ld(_slot(e, p["left"], p["i"], word)), e.ld(_slot(e, p["right"], p["i"], word))), lambda: e.set("same", 0))
            has_effect = e.ne(e.ld(_slot(e, p["left"], p["i"], POINTER_WORDS + 1)), NONE)
            e.if_(has_effect, lambda: e.if_(e.eq(e.call(list_equal, e.ld(_slot(e, p["left"], p["i"], POINTER_WORDS + 2)), e.ld(_slot(e, p["right"], p["i"], POINTER_WORDS + 2))), 0), lambda: e.set("same", 0)))

        e.for_("i", 0, k, each_index)
        e.for_("s", 0, e.mul(e.hd(H_S), 2), lambda: e.if_(e.ne(e.ld(e.add(_sets(e, p["left"], 0), p["s"])), e.ld(e.add(_sets(e, p["right"], 0), p["s"]))), lambda: e.set("same", 0)))
        e.give(p["same"])
    return _function(("left", "right"), build, tables)


# -- node handlers: (cursor, block) -> next cursor, or NONE to decline ---------------------------------

class _Node:
    """Field accessors for the node record at ``cursor``."""

    def __init__(self, e: E):
        self.e = e
        p = e.p
        cursor = p["cursor"]
        self.op, self.key, self.entity, self.site, self.base, self.na = (e.rd(e.add(cursor, k)) for k in range(6))
        self.attrs_at = e.add(cursor, 6)
        self.no = e.rd(e.add(self.attrs_at, self.na))
        self.vids_at = e.add(e.add(self.attrs_at, self.na), 1)
        self.tids_at = e.add(self.vids_at, self.no)
        self.nr = e.rd(e.add(self.tids_at, self.no))
        self.rt_at = e.add(e.add(self.tids_at, self.no), 1)
        self.aux_at = e.add(self.rt_at, self.nr)  # [count, words]
        self.next = e.add(e.add(self.aux_at, 1), e.rd(self.aux_at))

    def attr(self, index: int):
        return self.e.rd(self.e.add(self.attrs_at, index))

    def vid(self, index: int):
        return self.e.rd(self.e.add(self.vids_at, index))

    def tid(self, index: int):
        return self.e.rd(self.e.add(self.tids_at, index))

    def rtid(self, index: int):
        return self.e.rd(self.e.add(self.rt_at, index))

    def shape(self, operands: int, results: int, attributes: int):
        e = self.e
        return e.both(e.eq(self.no, operands), e.eq(self.nr, results), e.eq(self.na, attributes))


def _site_word(e: E, which: int, site):
    """ALLOC (0) or ENDED (1) flag word of ``site``."""
    return e.add(e.add(e.hd(H_SITES), e.mul(e.hd(H_S), which)), site)


def _ended(e: E, site):
    return e.ne(e.ld(_site_word(e, 1, site)), 0)


def _decline(e: E):
    e.give(NONE)


def _require(e: E, condition):
    import inspect

    frame = inspect.stack()[1]
    code = len(DECLINE_SITES)
    DECLINE_SITES.append(f"{frame.function}:{frame.lineno}")
    def decline():
        # The innermost check names the reason (callers propagate NONE through their own checks).
        e.if_(e.eq(e.hd(H_REASON), 0), lambda: e.set_hd(H_REASON, code + 1))
        _decline(e)

    e.if_(e.not_(condition), decline)


def _reject(e: E, condition, site: int, *payload, renderable=None):
    """``_require`` for a check that is exactly one of the bootstrap's memory checks, in its order: on failure the engine
    also records the rejection (site, position, payload) unless an earlier check already failed.  A failure whose
    diagnostic would quote something the host cannot render (``renderable`` false) only declines."""
    import inspect

    frame = inspect.stack()[1]
    code = len(DECLINE_SITES)
    DECLINE_SITES.append(f"{frame.function}:{frame.lineno}")

    def record():
        e.set_hd(H_REASON, code + 1)
        e.set_hd(H_REJECT, site)
        for field, value in ((H_RPASS, e.hd(H_PASS)), (H_RBLOCK, e.hd(H_CURBLOCK)), (H_RNODE, e.hd(H_MNODE))):
            e.set_hd(field, value)
        for index, word in enumerate(payload):
            e.set_hd(H_RPAY + index, word)

    def reject():
        first = e.eq(e.hd(H_REASON), 0)
        e.if_(first if renderable is None else e.both(first, renderable), record,
              lambda: e.if_(first, lambda: e.set_hd(H_REASON, code + 1)))
        _decline(e)

    e.if_(e.not_(condition), reject)


def _renderable(e: E, site):
    """A storage the host renders as the bootstrap's storage tuple (call-result storages are not)."""
    return e.ne(e.rd(e.add(e.hd(H_KINDS), site)), SITE_CALL)


def _consumed(e: E, value_id):
    """Mark a frontier consumed by the current node (``effect_consumers[value] = operation``)."""
    e.set_value(ECON, value_id, e.hd(H_VISIT))
    e.set_value(ECOP, value_id, e.hd(H_CUROP))


def _pointer(e: E, value_id, exact: bool = False):
    """``pointer()``: a live local pointer fact (declines otherwise; ``exact``: rejects as the bootstrap does)."""
    if not exact:
        _require(e, e.both(e.eq(e.value(PSTAMP, value_id), e.hd(H_PASS)), e.eq(e.value(PK, value_id), POINTER)))
        _require(e, e.not_(_ended(e, e.value(PST, value_id))))
        return
    _reject(e, e.both(e.eq(e.value(PSTAMP, value_id), e.hd(H_PASS)), e.eq(e.value(PK, value_id), POINTER)), M["PROVENANCE_PROVEN"], value_id)
    storage = e.value(PST, value_id)
    _reject(e, e.not_(_ended(e, storage)), M["LIFETIME_LIVE"], storage, renderable=_renderable(e, storage))


def _consume_effect(e: E, value_id, storage, exact: bool = False):
    """``consume_effect()``: this block's unconsumed frontier of ``storage``; returns its intervals."""
    visit = e.hd(H_VISIT)
    if exact:
        _reject(e, e.eq(e.value(ESTAMP, value_id), visit), M["EFFECT_PROVEN"], value_id)
        _reject(e, e.ne(e.value(ECON, value_id), visit), M["EFFECT_LINEAR"], e.value(ECOP, value_id), e.hd(H_CUROP))
        fact = e.value(EST, value_id)
        _reject(e, e.eq(fact, storage), M["EFFECT_PROVENANCE"], storage, fact,
                renderable=e.both(_renderable(e, storage), _renderable(e, fact)))
    else:
        _require(e, e.both(e.eq(e.value(ESTAMP, value_id), visit), e.ne(e.value(ECON, value_id), visit), e.eq(e.value(EST, value_id), storage)))
    _consumed(e, value_id)
    return e.value(EIV, value_id)


def _set_pointer(e: E, value_id, fields: dict):
    for word in range(POINTER_WORDS):
        e.set_value(word, value_id, fields[word])
    e.set_value(PSTAMP, value_id, e.hd(H_PASS))


def _set_effect(e: E, value_id, storage, intervals):
    e.set_value(EST, value_id, storage)
    e.set_value(EIV, value_id, intervals)
    e.set_value(ESTAMP, value_id, e.hd(H_VISIT))


def _element_size(e: E, element, attribute_size):
    """``element_size``: bytes of an addressable element, or 0 (not addressable)."""
    width = e.table(_T.WIDTH, element)
    form = e.table(_T.FORMAT, element)
    whole = e.both(e.ne(width, 0), e.eq(e.urem(width, 8), 0))
    pointer_size = e.sel(e.either(e.eq(attribute_size, 4), e.eq(attribute_size, 8)), attribute_size, 0)
    size = e.sel(whole, e.udiv(width, 8), e.sel(e.eq(form, 1), 4, e.sel(e.eq(form, 2), 8, 0)))
    size = e.sel(e.ne(e.table(_T.LINK, element), 0), 8, size)
    return e.sel(e.ne(e.table(_T.PTR, element), 0), pointer_size, size)


def _access_size(e: E, element, size):
    """``element_size`` and the access-size check.  A non-pointer element the program cannot size makes the bootstrap
    raise its own element diagnostic: that only declines."""
    pointer_element = e.ne(e.table(_T.PTR, element), 0)
    expected = _element_size(e, element, 0)
    _reject(e, e.either(e.not_(pointer_element), e.eq(size, 4), e.eq(size, 8)), M["POINTER_ELEMENT_SIZE"], size)
    _require(e, e.either(pointer_element, e.ne(expected, 0)))
    _reject(e, e.either(pointer_element, e.eq(size, expected)), M["ACCESS_SIZE"], expected, size)


def _access(e: E, value_id, size, alignment, exact: bool = False):
    element, extent = e.value(PEL, value_id), e.value(PEXT, value_id)
    if exact:
        _access_size(e, element, size)
        offset = e.value(POFF, value_id)
        _reject(e, e.both(e.power_of_two(alignment), e.le(alignment, e.value(PALIGN, value_id)), e.eq(e.urem(offset, e.sel(e.eq(alignment, 0), 1, alignment)), 0)),
                M["ALIGNMENT"], alignment, offset)
        _reject(e, e.le(size, extent), M["BOUNDS"], size, extent)
        return
    _require(e, e.eq(size, _element_size(e, element, size)))
    _require(e, e.both(e.ne(size, 0), e.power_of_two(alignment), e.le(alignment, e.value(PALIGN, value_id)), e.eq(e.urem(e.value(POFF, value_id), alignment), 0)))
    _require(e, e.le(size, extent))


def _mod(e: E, value, modulus):
    """``value % modulus`` (the modulus is nonzero wherever the result matters)."""
    return e.urem(value, e.sel(e.eq(modulus, 0), 1, modulus))


def _field_layout(e: E, field):
    """``abi_layout`` of a record field: ``(size, alignment, valid)``; valid fields are whole-byte bits, float, or link."""
    link = e.ne(e.table(_T.LINK, field), 0)
    float_format = e.table(_T.FORMAT, field)
    width = e.table(_T.WIDTH, field)
    bits = e.both(e.ne(width, 0), e.eq(e.urem(width, 8), 0))
    bits_size = e.sel(e.le(width, 8), 1, e.sel(e.le(width, 16), 2, e.sel(e.le(width, 32), 4, e.sel(
        e.le(width, 64), 8, e.mul(8, e.udiv(e.add(width, 63), 64))))))
    size = e.sel(link, 8, e.sel(e.ne(float_format, 0), e.sel(e.eq(float_format, 1), 4, 8), bits_size))
    alignment = e.sel(link, 8, e.sel(e.ne(float_format, 0), size, e.sel(e.lt(bits_size, 8), bits_size, 8)))
    return size, alignment, e.either(link, e.ne(float_format, 0), bits)


def _layout(tables):
    """``_record_layout``: 0 for a non-tuple element; a tuple's size (``upto`` NONE) or field ``upto``'s offset.

    Declines (NONE) where the bootstrap raises: an undecodable tuple or a field that is not whole-byte
    bits, float, or link."""
    def build(e: E):
        p = e.p
        element = p["element"]
        e.if_(e.ne(e.table(_T.FORMB, element), 8), lambda: e.give(0))
        _require(e, e.eq(e.table(_T.AGGREGATE, element), 8))
        items, count = e.table(_T.ITEMS, element), e.table(_T.COUNT, element)
        e.var("at", 0)
        e.var("widest", 1)
        e.var("found", NONE)

        def each():
            size, alignment, valid = _field_layout(e, e.ld(e.add(items, p["f"])))
            _require(e, valid)
            e.set("at", e.and_(e.add(p["at"], e.sub(alignment, 1)), e.sub(0, alignment)))
            e.if_(e.eq(p["f"], p["upto"]), lambda: e.set("found", p["at"]))
            e.set("at", e.add(p["at"], size))
            e.if_(e.lt(p["widest"], alignment), lambda: e.set("widest", alignment))

        e.for_("f", 0, count, each)
        e.if_(e.ne(p["upto"], NONE), lambda: e.give(p["found"]))
        e.give(e.and_(e.add(p["at"], e.sub(p["widest"], 1)), e.sub(0, p["widest"])))
    return _function(("element", "upto"), build, tables)


_LAYOUT: list = []
_LINEAR: list = []
_HAS_LINK: list = []
_WINDOW: list = []
_DEPENDENTS: list = []


def _record_bytes(e: E, element):
    """A record element's stride (0: not a record); declines where ``_record_layout`` raises."""
    size = e.call(_LAYOUT[0], element, NONE)
    _require(e, e.ne(size, NONE))
    return size


def _has_link_function(tables):
    """``_record_has_link``: 1 when a tuple record has a link field (declines on an undecodable tuple)."""
    def build(e: E):
        p = e.p
        record = p["record"]
        e.if_(e.ne(e.table(_T.FORMB, record), 8), lambda: e.give(0))
        _require(e, e.eq(e.table(_T.AGGREGATE, record), 8))
        items = e.table(_T.ITEMS, record)
        e.var("linked", 0)
        e.for_("f", 0, e.table(_T.COUNT, record), lambda: e.if_(e.ne(e.table(_T.LINK, e.ld(e.add(items, p["f"]))), 0), lambda: e.set("linked", 1)))
        e.give(p["linked"])
    return _function(("record",), build, tables)


def _has_link(e: E, record):
    linked = e.call(_HAS_LINK[0], record)
    _require(e, e.ne(linked, NONE))
    return linked


def _dependents_function(tables):
    """``_check_link_dependents``: no live storage still links into ``storage`` (1), else NONE."""
    def build(e: E):
        p = e.p
        storage = p["storage"]

        def each():
            v = p["v"]
            dependent = e.both(e.eq(e.value(PSTAMP, v), e.hd(H_PASS)), e.eq(e.value(PK, v), POINTER), e.eq(e.value(PLT, v), storage),
                               e.ne(e.value(PST, v), storage))
            e.if_(dependent, lambda: _require(e, _ended(e, e.value(PST, v))))

        e.for_("v", 0, e.hd(H_V), each)
        e.give(1)
    return _function(("storage",), build, tables)


def _check_dependents(e: E, storage):
    _require(e, e.ne(e.call(_DEPENDENTS[0], storage), NONE))


def _window_function(tables, covers):
    """``_window_initialized``: 1 when an access of ``size`` at every window position reads initialized bytes.

    Gaps lying entirely in record padding (shorter than a record, touching no field byte) are allowed."""
    def build(e: E):
        p = e.p
        intervals, value, size = p["intervals"], p["value"], p["size"]
        start = e.value(POFF, value)
        end = e.add(e.add(start, e.value(PWIN, value)), size)
        e.if_(e.ne(e.call(covers, intervals, start, end), 0), lambda: e.give(1))
        e.if_(e.eq(e.value(PWIN, value), 0), lambda: e.give(0))
        record = e.value(PREC, value)
        stride = _record_bytes(e, record)
        e.if_(e.eq(stride, 0), lambda: e.give(0))
        items, count = e.table(_T.ITEMS, record), e.table(_T.COUNT, record)

        def padding_only(low, high, flag):
            """Sets ``flag`` to 1 when [low, high) is shorter than a record and touches no field byte."""
            e.var(flag, e.flag(e.lt(e.sub(high, low), stride)))

            def each_byte():
                offset = _mod(e, p["byte"], stride)
                e.var("field_at", 0)

                def each_field():
                    field_size, alignment, _valid = _field_layout(e, e.ld(e.add(items, p["g"])))
                    e.set("field_at", e.and_(e.add(p["field_at"], e.sub(alignment, 1)), e.sub(0, alignment)))
                    inside = e.both(e.le(p["field_at"], offset), e.lt(offset, e.add(p["field_at"], field_size)))
                    e.if_(inside, lambda: e.set(flag, 0))
                    e.set("field_at", e.add(p["field_at"], field_size))

                e.for_("g", 0, count, each_field)

            e.if_(e.ne(p[flag], 0), lambda: e.for_("byte", low, high, each_byte))

        e.var("cursor", start)
        e.var("ok", 1)
        e.var("stop", 0)

        def each_interval():
            low = e.ld(e.add(intervals, e.add(1, e.mul(p["k"], 2))))
            high = e.ld(e.add(intervals, e.add(2, e.mul(p["k"], 2))))

            def visit():
                def inside():
                    def gap():
                        padding_only(p["cursor"], low, "gap_ok")
                        e.if_(e.eq(p["gap_ok"], 0), lambda: (e.set("ok", 0), e.set("stop", 1)))

                    e.if_(e.lt(p["cursor"], low), gap)
                    e.if_(e.both(e.eq(p["stop"], 0), e.lt(p["cursor"], high)), lambda: e.set("cursor", high))

                e.if_(e.le(end, low), lambda: e.set("stop", 1), inside)

            e.if_(e.both(e.eq(p["stop"], 0), e.lt(p["cursor"], high)), visit)

        e.for_("k", 0, e.ld(intervals), each_interval)
        e.if_(e.eq(p["ok"], 0), lambda: e.give(0))
        e.if_(e.le(end, p["cursor"]), lambda: e.give(1))
        padding_only(p["cursor"], end, "tail_ok")
        e.give(p["tail_ok"])
    return _function(("intervals", "value", "size"), build, tables)


def _link_fact(e: E, value_id, storage, record):
    """A ``_LinkFact``: null (``storage`` NONE) or a record start of ``storage``; canonical like a merged link."""
    fields = {word: 0 for word in range(POINTER_WORDS)}
    fields.update({PK: LINK, PST: storage, PREC: record, PLT: NONE, PLR: NONE})
    _set_pointer(e, value_id, fields)


def _loaded_link(e: E, source, result):
    """``loaded_link``: a link field holds null or a record start of the view's link target."""
    e.if_(e.both(e.ne(e.table(_T.LINK, e.value(PEL, source)), 0), e.ne(e.value(PLT, source), NONE)),
          lambda: _link_fact(e, result, e.value(PLT, source), e.value(PLR, source)))


def _stored_provenance(e: E, stored, destination):
    """``stored_pointer_provenance``: links hold null or a link into the destination's target; no local pointers."""
    current = e.eq(e.value(PSTAMP, stored), e.hd(H_PASS))

    def link_field():
        target = e.both(e.eq(e.value(PST, stored), e.value(PLT, destination)), e.eq(e.value(PREC, stored), e.value(PLR, destination)))
        _require(e, e.both(current, e.eq(e.value(PK, stored), LINK), e.either(e.eq(e.value(PST, stored), NONE), target)))

    e.if_(e.ne(e.table(_T.LINK, e.value(PEL, destination)), 0), link_field,
          lambda: _require(e, e.not_(e.both(current, e.eq(e.value(PK, stored), POINTER)))))


def _view_record(e: E, element, extent):
    """``view_record``: no link element; a record view spans whole records."""
    _require(e, e.eq(e.table(_T.LINK, element), 0))
    stride = _record_bytes(e, element)
    _require(e, e.eq(_mod(e, extent, stride), 0))


def _stack_alloc(tables):
    def build(e: E):
        n = _Node(e)
        _reject(e, n.shape(0, 3, 2), M["OP_CONTRACT"], n.no, n.nr, n.na)
        extent, alignment = n.attr(0), n.attr(1)
        pointer_type = n.rtid(0)
        _require(e, e.both(e.ne(extent, 0), e.power_of_two(alignment), e.ne(e.table(_T.PTR, pointer_type), 0), e.eq(e.table(_T.PSPACE, pointer_type), 1)))
        element, permission = e.table(_T.PELEM, pointer_type), e.table(_T.PPERM, pointer_type)
        _reject(e, e.le(e.table(_T.PALIGN, pointer_type), alignment), M["ALLOCATION_ALIGNMENT"], alignment, e.table(_T.PALIGN, pointer_type))
        _require(e, e.both(e.ne(e.table(_T.STACKOWNER, n.rtid(1)), 0), e.ne(e.table(_T.MEMEFFECT, n.rtid(2)), 0)))
        _view_record(e, element, extent)
        site = n.site
        _require(e, e.not_(e.both(e.ne(e.ld(_site_word(e, 0, site)), 0), e.not_(_ended(e, site)))))
        e.st(_site_word(e, 0, site), 1)
        e.st(_site_word(e, 1, site), 0)
        _set_pointer(e, n.base, {PK: POINTER, PST: site, PEL: element, PPERM: permission, POFF: 0, PEXT: extent, PALIGN: alignment, PALIAS: site, PWIN: 0, PREC: element, PLT: site, PLR: element})
        owner = e.add(n.base, 1)
        e.set_value(OST, owner, site)
        e.set_value(OSTAMP, owner, e.hd(H_VISIT))
        empty = e.alloc(1)
        _require(e, e.ne(empty, NONE))
        e.st(empty, 0)
        _set_effect(e, e.add(n.base, 2), site, empty)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _stack_end(tables):
    def build(e: E):
        n = _Node(e)
        visit = e.hd(H_VISIT)
        _reject(e, n.shape(2, 0, 0), M["OP_CONTRACT"], n.no, n.nr, n.na)
        owner = n.vid(0)
        _reject(e, e.eq(e.value(OSTAMP, owner), visit), M["OWNER_PROVEN"], owner)
        storage = e.value(OST, owner)
        _reject(e, e.both(e.ne(e.value(OCON, owner), visit), e.not_(_ended(e, storage))), M["OWNER_LIVE"], storage, renderable=_renderable(e, storage))
        _require(e, e.both(e.ne(e.table(_T.STACKOWNER, n.tid(0)), 0), e.ne(e.table(_T.MEMEFFECT, n.tid(1)), 0)))
        _consume_effect(e, n.vid(1), storage, exact=True)
        e.set_value(OCON, owner, visit)
        _check_dependents(e, storage)
        e.st(_site_word(e, 1, storage), 1)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _address_offset(tables):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source, exact=True)
        _reject(e, n.shape(1, 1, 1), M["OP_CONTRACT"], n.no, n.nr, n.na)
        offset, extent = n.attr(0), e.value(PEXT, source)
        _reject(e, e.le(offset, extent), M["ADDRESS_BOUNDS"], extent, offset)
        result_type = n.rtid(0)
        _require(e, e.ne(e.table(_T.PTR, result_type), 0))
        element, permission, alignment = e.table(_T.PELEM, result_type), e.table(_T.PPERM, result_type), e.table(_T.PALIGN, result_type)
        source_alignment = e.value(PALIGN, source)
        low = e.and_(offset, e.sub(0, offset))  # the largest power of two dividing offset
        actual = e.sel(e.eq(offset, 0), source_alignment, e.sel(e.lt(low, source_alignment), low, source_alignment))
        source_element = e.value(PEL, source)
        stride = _record_bytes(e, source_element)
        e.var("remaining", e.sub(extent, offset))

        def field():
            # Field address (ADR-097): an exact field offset, extent clamped to the field.
            e.var("field_found", 0)
            items = e.table(_T.ITEMS, source_element)

            def each():
                at = e.call(_LAYOUT[0], source_element, e.p["fi"])
                e.if_(e.both(e.eq(at, offset), e.eq(e.ld(e.add(items, e.p["fi"])), element)), lambda: e.set("field_found", 1))

            e.for_("fi", 0, e.table(_T.COUNT, source_element), each)
            _require(e, e.ne(e.p["field_found"], 0))
            e.set("remaining", _field_layout(e, element)[0])

        e.if_(e.both(e.ne(stride, 0), e.ne(element, source_element)), field, lambda: e.if_(
            e.ne(stride, 0), lambda: _require(e, e.eq(_mod(e, offset, stride), 0)), lambda: _require(e, e.eq(element, source_element))))
        source_permission = e.value(PPERM, source)
        _require(e, e.eq(e.and_(permission, source_permission), permission))
        _require(e, e.le(alignment, actual))
        fields = {word: e.value(word, source) for word in range(POINTER_WORDS)}
        fields.update({PEL: element, PPERM: permission, POFF: e.add(e.value(POFF, source), offset), PEXT: e.p["remaining"], PALIGN: actual})
        _set_pointer(e, n.base, fields)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _load(tables, covers):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source, exact=True)
        _reject(e, n.shape(2, 2, 2), M["OP_CONTRACT"], n.no, n.nr, n.na)
        size = n.attr(0)
        _access(e, source, size, n.attr(1), exact=True)
        _reject(e, e.ne(e.and_(e.value(PPERM, source), int(Permission.READ)), 0), M["READ_PERMISSION"], e.value(PPERM, source))
        storage = e.value(PST, source)
        intervals = _consume_effect(e, n.vid(1), storage, exact=True)
        _reject(e, e.both(e.eq(n.rtid(0), e.value(PEL, source)), e.ne(e.table(_T.MEMEFFECT, n.tid(1)), 0), e.eq(n.rtid(1), n.tid(1))),
                M["LOAD_TYPE"], e.value(PEL, source), n.tid(1), n.rtid(0), n.rtid(1))
        _reject(e, e.eq(e.call(_WINDOW[0], intervals, source, size), 1), M["INITIALIZED"], e.value(POFF, source), e.value(PWIN, source), size, intervals)
        _loaded_link(e, source, n.base)
        _set_effect(e, e.add(n.base, 1), storage, intervals)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _store(tables, insert):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source, exact=True)
        _reject(e, n.shape(3, 1, 2), M["OP_CONTRACT"], n.no, n.nr, n.na)
        size = n.attr(0)
        _access(e, source, size, n.attr(1), exact=True)
        _reject(e, e.ne(e.and_(e.value(PPERM, source), int(Permission.WRITE)), 0), M["WRITE_PERMISSION"], e.value(PPERM, source))
        _reject(e, e.eq(n.tid(1), e.value(PEL, source)), M["STORE_TYPE"], e.value(PEL, source), n.tid(1))
        _stored_provenance(e, n.vid(1), source)
        storage = e.value(PST, source)
        intervals = _consume_effect(e, n.vid(2), storage, exact=True)
        _reject(e, e.both(e.ne(e.table(_T.MEMEFFECT, n.tid(2)), 0), e.eq(n.rtid(0), n.tid(2))), M["STORE_EFFECT_TYPE"], n.rtid(0))
        start = e.value(POFF, source)
        e.var("merged", intervals)  # a windowed store initializes an unknown position: nothing new

        def place():
            e.set("merged", e.call(insert, intervals, start, e.add(start, size)))
            _require(e, e.ne(e.p["merged"], NONE))

        e.if_(e.eq(e.value(PWIN, source), 0), place)
        _set_effect(e, n.base, storage, e.p["merged"])
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _pointer_cast(tables):
    def build(e: E):
        p = e.p
        n = _Node(e)
        _require(e, n.shape(1, 1, 0))
        source_type, result_type = n.tid(0), n.rtid(0)
        _require(e, e.both(e.ne(e.table(_T.PTR, source_type), 0), e.ne(e.table(_T.PTR, result_type), 0)))
        element, permission, alignment = e.table(_T.PELEM, result_type), e.table(_T.PPERM, result_type), e.table(_T.PALIGN, result_type)
        _require(e, e.both(
            e.eq(e.table(_T.PSPACE, source_type), e.table(_T.PSPACE, result_type)), e.eq(element, e.table(_T.PELEM, source_type)),
            e.eq(e.and_(permission, e.table(_T.PPERM, source_type)), permission), e.le(alignment, e.table(_T.PALIGN, source_type)),
        ))
        source = n.vid(0)

        def propagate():
            _require(e, e.not_(_ended(e, e.value(PST, source))))
            fields = {word: e.value(word, source) for word in range(POINTER_WORDS)}
            fact_alignment = e.value(PALIGN, source)
            fields.update({PEL: element, PPERM: permission, PALIGN: e.sel(e.lt(fact_alignment, alignment), fact_alignment, alignment)})
            _set_pointer(e, n.base, fields)

        e.if_(e.both(e.eq(e.value(PSTAMP, source), e.hd(H_PASS)), e.eq(e.value(PK, source), POINTER)), propagate)
        del p
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


# -- S4d.2c: heap views, checked accesses, address and rebase, foreign calls, view-passing calls -------

def _uleb(e: E, at):
    """``(value, size, ok)``: a canonical ULEB of at most five bytes at input word ``at`` (as the typing decoder)."""
    data = [e.rd(e.add(at, k)) for k in range(_T.ULEB_BYTES)]
    value, size, ok = e.c(0), e.c(0), e.c(0)
    continuing = e.c(1)
    for length in range(1, len(data) + 1):
        last = data[length - 1]
        ends = e.flag(e.both(e.ne(continuing, 0), e.lt(last, 128), e.ne(last, 0) if length > 1 else e.eq(0, 0)))
        total = e.c(0)
        for index in range(length):
            low = data[index] if index == length - 1 else e.sub(data[index], 128)
            total = e.add(total, e.mul(low, 1 << (7 * index)))
        value = e.add(value, e.mul(ends, total))
        size = e.add(size, e.mul(ends, length))
        ok = e.or_(ok, ends)
        continuing = e.flag(e.both(e.ne(continuing, 0), e.le(128, last), e.lt(last, 256)))
    return value, size, e.ne(ok, 0)


def _heap_view(e: E, type_index):
    """``_heap_view_info`` is not None: resource kind 0x101, state 1 or 2, extent >= 1."""
    state = e.table(_T.RSTATE, type_index)
    return e.both(e.ne(e.table(_T.RESOURCE, type_index), 0), e.eq(e.table(_T.RKIND, type_index), 0x101),
                  e.either(e.eq(state, 1), e.eq(state, 2)), e.ne(e.table(_T.RINSTANCE, type_index), 0))


def _heap_owner(e: E, type_index):
    return e.both(e.ne(e.table(_T.RESOURCE, type_index), 0), e.eq(e.table(_T.RKIND, type_index), 0x100))


def _triples_valid(e: E, count, at):
    """``_heap_view_triples`` does not raise: every view token has a space-2 pointer before it and a memory effect after."""
    p = e.p

    def each():
        index = p["q"]

        def check():
            _require(e, e.both(e.ne(index, 0), e.lt(e.add(index, 1), count)))
            before, after = e.rd(e.add(at, e.sub(index, 1))), e.rd(e.add(at, e.add(index, 1)))
            _require(e, e.both(e.ne(e.table(_T.PTR, before), 0), e.eq(e.table(_T.PSPACE, before), 2), e.ne(e.table(_T.MEMEFFECT, after), 0)))

        e.if_(_heap_view(e, e.rd(e.add(at, index))), check)

    e.for_("q", 0, count, each)


def _end_views(tables):
    """``_end_heap_views``: a live view token consumed by any other node ends its storage."""
    def build(e: E):
        p = e.p
        n = _Node(e)
        visit = e.hd(H_VISIT)

        def each():
            value, type_ = n.vid(0) if False else e.rd(e.add(n.vids_at, p["j"])), e.rd(e.add(n.tids_at, p["j"]))

            def end():
                e.set_value(OCON, value, visit)
                e.st(_site_word(e, 1, e.value(OST, value)), 1)

            e.if_(e.both(e.eq(e.value(OSTAMP, value), visit), e.ne(e.value(OCON, value), visit), _heap_view(e, type_)), end)

        e.for_("j", 0, n.no, each)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _checked(tables, covers, load: bool):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source, exact=True)
        _reject(e, n.shape(3, 2, 2) if load else n.shape(4, 1, 2), M["OP_CONTRACT"], n.no, n.nr, n.na)
        element = e.value(PEL, source)
        size = n.attr(0)
        _access_size(e, element, size)
        _reject(e, e.eq(n.attr(1), 1), M["CHECKED_ALIGNMENT"], n.attr(1))
        offset_width = e.table(_T.WIDTH, n.tid(1))
        _require(e, e.ne(offset_width, 0))  # not bits: the bootstrap raises its own decode diagnostic
        _reject(e, e.eq(offset_width, 32), M["CHECKED_OFFSET"], offset_width)
        permission = e.value(PPERM, source)
        if load:
            _reject(e, e.ne(e.and_(permission, int(Permission.READ)), 0), M["READ_PERMISSION"], permission)
            _reject(e, e.eq(n.rtid(0), element), M["CHECKED_LOAD_TYPE"], element, n.rtid(0))
            effect_index = 2
        else:
            _reject(e, e.ne(e.and_(permission, int(Permission.WRITE)), 0), M["WRITE_PERMISSION"], permission)
            _reject(e, e.eq(n.tid(2), element), M["CHECKED_STORE_TYPE"], element, n.tid(2))
            _stored_provenance(e, n.vid(2), source)
            effect_index = 3
        storage = e.value(PST, source)
        intervals = _consume_effect(e, n.vid(effect_index), storage, exact=True)
        effect_type = n.tid(effect_index)
        _reject(e, e.both(e.ne(e.table(_T.MEMEFFECT, effect_type), 0), e.eq(n.rtid(1 if load else 0), effect_type)),
                M["CHECKED_EFFECT_TYPE"], n.nr, n.rtid(0), n.rtid(1))
        if load:
            start = e.value(POFF, source)
            view_end = e.add(e.add(start, e.value(PWIN, source)), e.value(PEXT, source))
            _reject(e, e.ne(e.call(covers, intervals, start, view_end), 0), M["CHECKED_INITIALIZED"], start, view_end, intervals)
            _loaded_link(e, source, n.base)
        _set_effect(e, e.add(n.base, 1 if load else 0), storage, intervals)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _heap_view_node(tables):
    def build(e: E):
        p = e.p
        n = _Node(e)
        # An optional fourth operand names the whole record view this storage's links point into.
        e.var("link_target", NONE)
        e.var("link_record", NONE)

        def targeted():
            target = n.vid(3)
            _pointer(e, target)
            target_element = e.value(PEL, target)
            _require(e, e.ne(_record_bytes(e, target_element), 0))
            _require(e, e.both(e.eq(target_element, e.value(PREC, target)), e.eq(e.value(POFF, target), 0), e.eq(e.value(PWIN, target), 0)))
            e.set("link_target", e.value(PST, target))
            e.set("link_record", e.value(PREC, target))

        e.if_(e.eq(n.no, 4), targeted)
        _require(e, e.either(n.shape(3, 3, 2), n.shape(4, 3, 2)))
        extent, alignment = n.attr(0), n.attr(1)
        raw, token, allocation_effect = n.vid(0), n.vid(1), n.vid(2)
        visit, pass_id = e.hd(H_VISIT), e.hd(H_PASS)
        _require(e, e.eq(e.value(HSTAMP, raw), pass_id))
        site, size = e.value(HST, raw), e.value(HSIZE, raw)
        _require(e, e.both(e.eq(e.value(OSTAMP, token), visit), e.eq(e.value(OST, token), site), e.ne(e.value(OCON, token), visit), _heap_owner(e, n.tid(1))))
        _require(e, e.ne(e.table(_T.MEMEFFECT, n.tid(2)), 0))
        _require(e, e.both(e.ne(e.value(DEF, raw), NONE), e.eq(e.value(DEF, allocation_effect), e.value(DEF, raw))))
        _require(e, e.both(e.ne(size, NONE), e.ne(extent, 0), e.le(extent, size)))
        _require(e, e.both(e.power_of_two(alignment), e.le(alignment, e.value(HALIGN, raw))))
        pointer_type = n.rtid(0)
        _require(e, e.both(e.ne(e.table(_T.PTR, pointer_type), 0), e.eq(e.table(_T.PSPACE, pointer_type), 2)))
        element, permission = e.table(_T.PELEM, pointer_type), e.table(_T.PPERM, pointer_type)
        _require(e, e.le(e.table(_T.PALIGN, pointer_type), alignment))
        view = n.rtid(1)
        zeroed = e.value(HZERO, raw)
        _require(e, e.both(_heap_view(e, view), e.eq(e.table(_T.RINSTANCE, view), extent), e.eq(e.flag(e.eq(e.table(_T.RSTATE, view), 1)), zeroed)))
        _require(e, e.ne(e.table(_T.MEMEFFECT, n.rtid(2)), 0))
        _view_record(e, element, extent)
        storage = n.site
        e.st(_site_word(e, 1, storage), 0)
        e.set_value(OCON, token, visit)
        targeted_ = e.ne(p["link_target"], NONE)
        _set_pointer(e, n.base, {PK: POINTER, PST: storage, PEL: element, PPERM: permission, POFF: 0, PEXT: extent, PALIGN: alignment, PALIAS: storage, PWIN: 0,
                                 PREC: element, PLT: e.sel(targeted_, p["link_target"], storage), PLR: e.sel(targeted_, p["link_record"], element)})
        e.set_value(OST, e.add(n.base, 1), storage)
        e.set_value(OSTAMP, e.add(n.base, 1), visit)
        _set_effect(e, e.add(n.base, 2), storage, _initialized_list(e, zeroed, extent))
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _initialized_list(e: E, initialized, extent):
    """A fresh interval list: [(0, extent)] when ``initialized``, else empty."""
    p = e.p
    e.var("fresh", e.alloc(3))
    _require(e, e.ne(p["fresh"], NONE))
    e.st(p["fresh"], e.flag(e.ne(initialized, 0)))
    e.st(e.add(p["fresh"], 1), 0)
    e.st(e.add(p["fresh"], 2), extent)
    return p["fresh"]


def _pointer_address(tables):
    def build(e: E):
        n = _Node(e)
        _require(e, n.shape(1, 1, 1))
        _require(e, e.both(e.eq(n.attr(0), 1), e.ne(e.table(_T.PTR, n.tid(0)), 0)))
        width = e.table(_T.WIDTH, n.rtid(0))
        _require(e, e.either(e.eq(width, 32), e.eq(width, 64)))
        source = n.vid(0)
        live = e.both(e.eq(e.value(PSTAMP, source), e.hd(H_PASS)), e.eq(e.value(PK, source), POINTER))
        e.if_(live, lambda: _require(e, e.not_(_ended(e, e.value(PST, source)))))
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _pointer_rebase(tables):
    def build(e: E):
        n = _Node(e)
        _reject(e, n.shape(2, 1, 1), M["OP_CONTRACT"], n.no, n.nr, n.na)
        view = n.vid(0)
        _pointer(e, view, exact=True)
        extent = n.attr(0)
        width = e.table(_T.WIDTH, n.tid(1))
        _require(e, e.ne(width, 0))  # not bits: the bootstrap's own decode diagnostic
        _reject(e, e.either(e.eq(width, 32), e.eq(width, 64)), M["REBASE_ADDRESS_WIDTH"], width)
        view_type, result_type = n.tid(0), n.rtid(0)
        _require(e, e.both(e.ne(e.table(_T.PTR, view_type), 0), e.ne(e.table(_T.PTR, result_type), 0)))
        element, permission, alignment = e.table(_T.PELEM, result_type), e.table(_T.PPERM, result_type), e.table(_T.PALIGN, result_type)
        view_extent = e.value(PEXT, view)
        _reject(e, e.both(
            e.eq(e.table(_T.PSPACE, view_type), e.table(_T.PSPACE, result_type)), e.eq(element, e.value(PEL, view)),
            e.eq(e.and_(permission, e.value(PPERM, view)), permission),
        ), M["REBASE_AUTHORITY"], e.value(PEL, view), e.value(PPERM, view), element, permission)
        _reject(e, e.both(e.ne(extent, 0), e.le(extent, view_extent)), M["REBASE_EXTENT"], view_extent, extent)
        _reject(e, e.le(alignment, e.value(PALIGN, view)), M["REBASE_ALIGNMENT"], e.value(PALIGN, view), alignment)
        stride = _record_bytes(e, element)
        _require(e, e.both(e.eq(_mod(e, alignment, stride), 0), e.eq(_mod(e, e.value(POFF, view), stride), 0)))
        fields = {word: e.value(word, view) for word in range(POINTER_WORDS)}
        fields.update({PEL: element, PPERM: permission, PEXT: extent, PALIGN: alignment, PWIN: e.sub(e.add(e.value(PWIN, view), view_extent), extent)})
        _set_pointer(e, n.base, fields)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


# A foreign declaration record (arena): [inputs n, n type indices, outputs m, m type indices,
#   allocator?, size count, size indices (count), pointer output, token output, alignment, zeroed,
#   deallocator?, pointer input, token input].

def _foreign_declaration(tables):
    """``decode_foreign_function`` and the ABI check: a declaration record, or NONE."""
    from xax_compiler import FOREIGN_ABIS, FOREIGN_FUNCTION_PREFIX, Kind

    def build(e: E):
        p = e.p
        entity = p["entity"]
        count = e.hd(H_COUNT)
        _require(e, e.lt(entity, count))
        position = e.ld(e.add(e.add(e.hd(H_TABLE), e.mul(count, _T.POSITION)), entity))
        kind, references, length = (e.rd(e.add(position, k)) for k in range(3))
        _require(e, e.both(e.eq(kind, int(Kind.TARGET)), e.eq(references, 0)))
        base = e.add(position, 3)
        end = e.add(base, length)
        identity_length, size, ok = _uleb(e, base)
        _require(e, ok)
        e.var("at", e.add(base, size))
        _require(e, e.eq(e.add(p["at"], identity_length), end))
        for offset, byte in enumerate(FOREIGN_FUNCTION_PREFIX):
            _require(e, e.eq(e.rd(e.add(p["at"], offset)), byte))
        e.set("at", e.add(p["at"], len(FOREIGN_FUNCTION_PREFIX)))

        def blob():
            """A nonempty byte string; returns (start, length)."""
            blob_length, blob_size, blob_ok = _uleb(e, p["at"])
            _require(e, e.both(blob_ok, e.ne(blob_length, 0)))
            start = e.add(p["at"], blob_size)
            e.set("at", e.add(start, blob_length))
            _require(e, e.le(p["at"], end))
            return start, blob_length

        abi_start, abi_length = blob()
        known = None
        for abi in FOREIGN_ABIS:
            same = e.eq(abi_length, len(abi))
            for offset, byte in enumerate(abi):
                same = e.both(same, e.eq(e.rd(e.add(abi_start, offset)), byte))
            known = same if known is None else e.either(known, same)
        _require(e, known)
        blob()  # library
        blob()  # name
        e.var("record", e.alloc(e.add(length, 16)))
        _require(e, e.ne(p["record"], NONE))
        from xax_compiler import SYSV_X86_64_C_ABI

        sysv = e.eq(abi_length, len(SYSV_X86_64_C_ABI))
        for offset, byte in enumerate(SYSV_X86_64_C_ABI):
            sysv = e.both(sysv, e.eq(e.rd(e.add(abi_start, offset)), byte))
        e.st(p["record"], e.flag(sysv))
        e.var("out", e.add(p["record"], 1))
        cids = e.hd(H_CIDS)

        def interface():
            n_types, n_size, n_ok = _uleb(e, p["at"])
            _require(e, n_ok)
            e.set("at", e.add(p["at"], n_size))
            e.st(p["out"], n_types)
            e.set("out", e.add(p["out"], 1))

            def each():
                words = []
                for word in range(4):
                    value = e.c(0)
                    for byte in range(8):
                        value = e.add(value, e.mul(e.rd(e.add(p["at"], 8 * word + byte)), 1 << (8 * byte)))
                    words.append(value)
                e.var("found", NONE)

                def match():
                    same = None
                    for word in range(4):
                        here = e.eq(e.rd(e.add(cids, e.add(e.mul(p["c"], 4), word))), words[word])
                        same = here if same is None else e.both(same, here)
                    e.if_(same, lambda: e.set("found", p["c"]))

                e.for_("c", 0, count, match)
                e.st(p["out"], p["found"])
                e.set("out", e.add(p["out"], 1))
                e.set("at", e.add(p["at"], 32))
                _require(e, e.le(p["at"], end))

            e.for_("i", 0, n_types, each)
            return n_types

        inputs = interface()
        outputs = interface()

        def contract(tag: int, body):
            present = e.both(e.lt(p["at"], end), e.eq(e.rd(p["at"]), tag))
            e.st(p["out"], e.flag(present))
            e.set("out", e.add(p["out"], 1))
            e.if_(present, lambda: (e.set("at", e.add(p["at"], 1)), body()))

        def field():
            value, value_size, value_ok = _uleb(e, p["at"])
            _require(e, value_ok)
            e.set("at", e.add(p["at"], value_size))
            e.st(p["out"], value)
            e.set("out", e.add(p["out"], 1))
            return value

        def allocator():
            sizes = field()
            _require(e, e.ne(sizes, 0))
            e.for_("s", 0, sizes, lambda: _require(e, e.lt(field(), inputs)))
            pointer_output, token_output, alignment, zeroed = field(), field(), field(), field()
            _require(e, e.both(e.le(zeroed, 1), e.lt(pointer_output, outputs), e.lt(token_output, outputs), e.power_of_two(alignment)))

        def deallocator():
            pointer_input, token_input = field(), field()
            _require(e, e.both(e.lt(pointer_input, inputs), e.lt(token_input, inputs)))

        contract(1, allocator)
        contract(2, deallocator)
        _require(e, e.eq(p["at"], end))
        e.give(p["record"])
    return _function(("entity",), build, tables)


def _constant_value(e: E, value_id):
    """``_constant_operand``: (value, ok) for a ``constant`` node's bits value of at most eight bytes."""
    from xax_compiler import Kind

    p = e.p
    e.var("constant", 0)
    e.var("constant_ok", 0)
    definer = e.value(DEF, value_id)

    def decode():
        entity = e.rd(e.add(definer, 2))
        count = e.hd(H_COUNT)

        def known():
            position = e.ld(e.add(e.add(e.hd(H_TABLE), e.mul(count, _T.POSITION)), entity))
            base = e.add(position, 3)
            length = e.rd(e.add(position, 2))
            value_type = e.rd(e.add(base, length))
            data_length = e.rd(e.add(base, 1))
            data = e.add(base, 2)
            bits = e.both(e.eq(e.rd(position), int(Kind.CONSTANT)), e.ne(e.table(_T.WIDTH, value_type), 0), e.le(data_length, 8), e.eq(e.add(data_length, 2), length))
            value = e.c(0)
            for byte in range(8):
                value = e.add(value, e.mul(e.mul(e.flag(e.lt(byte, data_length)), e.rd(e.add(data, byte))), 1 << (8 * byte)))
            e.if_(bits, lambda: (e.set("constant", value), e.set("constant_ok", 1)))

        e.if_(e.lt(entity, count), known)

    e.if_(e.both(e.ne(definer, NONE), e.eq(e.rd(definer), int(Operation.CONSTANT))), decode)
    return p["constant"], p["constant_ok"]


def _call_foreign(tables, declaration, end_views):
    def build(e: E):
        p = e.p
        n = _Node(e)
        visit, pass_id = e.hd(H_VISIT), e.hd(H_PASS)
        _require(e, e.ne(n.entity, NONE))
        e.var("decl", e.call(declaration, n.entity))
        _require(e, e.ne(p["decl"], NONE))
        sysv = e.ld(p["decl"])
        decl = e.add(p["decl"], 1)
        inputs = e.ld(decl)
        outputs_at = e.add(e.add(decl, 1), inputs)
        outputs = e.ld(outputs_at)
        _require(e, e.both(e.eq(n.no, inputs), e.eq(n.nr, outputs)))
        e.for_("j", 0, inputs, lambda: _require(e, e.eq(n.tid(0) if False else e.rd(e.add(n.tids_at, p["j"])), e.ld(e.add(e.add(decl, 1), p["j"])))))
        e.for_("j", 0, outputs, lambda: _require(e, e.eq(e.rd(e.add(n.rt_at, p["j"])), e.ld(e.add(e.add(outputs_at, 1), p["j"])))))
        # ``_verify_lend_entries``: a lend entry goes only to a sysv call lending it a whole initialized view
        # of its extent with that storage's frontier, and returning a memory frontier.
        e.var("memory_out", 0)
        e.for_("j", 0, outputs, lambda: e.if_(e.ne(e.table(_T.MEMEFFECT, e.rd(e.add(n.rt_at, p["j"]))), 0), lambda: e.set("memory_out", 1)))

        def lend_check():
            view = _lend_view(e, e.rd(e.add(n.tids_at, p["j"])), "lend")

            def lent():
                _require(e, _heap_view(e, view))
                extent = e.table(_T.RINSTANCE, view)
                e.var("lent", 0)

                def effect_operand():
                    effect_ref = e.rd(e.add(n.vids_at, p["k"]))

                    def pointer_operand():
                        value = e.rd(e.add(n.vids_at, p["m"]))
                        whole = e.both(e.eq(e.value(PSTAMP, value), pass_id), e.eq(e.value(PK, value), POINTER), e.eq(e.value(POFF, value), 0),
                                       e.eq(e.value(PWIN, value), 0), e.eq(e.value(PEXT, value), extent), e.not_(_ended(e, e.value(PST, value))),
                                       e.eq(e.value(PST, value), e.value(EST, effect_ref)))
                        e.if_(whole, lambda: e.if_(e.ne(e.call(_COVERS[0], e.value(EIV, effect_ref), 0, extent), 0), lambda: e.set("lent", 1)))

                    e.if_(e.both(e.ne(e.table(_T.MEMEFFECT, e.rd(e.add(n.tids_at, p["k"]))), 0), e.eq(e.value(ESTAMP, effect_ref), visit)),
                          lambda: e.for_("m", 0, inputs, pointer_operand))

                e.if_(e.both(e.ne(sysv, 0), e.ne(p["memory_out"], 0)), lambda: e.for_("k", 0, inputs, effect_operand))
                _require(e, e.ne(p["lent"], 0))

            e.if_(e.ne(view, NONE), lent)

        e.for_("j", 0, inputs, lend_check)
        # Operands naming ended storage reject.
        e.for_("j", 0, inputs, lambda: _require(e, e.not_(e.both(
            e.eq(e.value(PSTAMP, e.rd(e.add(n.vids_at, p["j"]))), pass_id), e.eq(e.value(PK, e.rd(e.add(n.vids_at, p["j"]))), POINTER),
            _ended(e, e.value(PST, e.rd(e.add(n.vids_at, p["j"]))))))))
        allocator_at = e.add(e.add(outputs_at, 1), outputs)
        sizes = e.ld(e.add(allocator_at, 1))
        has_allocator = e.ne(e.ld(allocator_at), 0)
        deallocator_at = e.sel(has_allocator, e.add(e.add(allocator_at, 6), sizes), e.add(allocator_at, 1))
        e.var("released", NONE)

        def deallocate():
            pointer_ref = e.rd(e.add(n.vids_at, e.ld(e.add(deallocator_at, 1))))
            token_index = e.ld(e.add(deallocator_at, 2))
            token_ref = e.rd(e.add(n.vids_at, token_index))
            token_type = e.rd(e.add(n.tids_at, token_index))
            _require(e, e.both(e.eq(e.value(OSTAMP, token_ref), visit), e.ne(e.value(OCON, token_ref), visit)))
            owner = e.value(OST, token_ref)

            def view():
                _require(e, e.both(e.eq(e.value(PSTAMP, pointer_ref), pass_id), e.eq(e.value(PK, pointer_ref), POINTER), e.eq(e.value(PST, pointer_ref), owner),
                                   e.eq(e.value(POFF, pointer_ref), 0), e.eq(e.value(PWIN, pointer_ref), 0)))
                e.set("released", owner)

            def heap():
                _require(e, _heap_owner(e, token_type))
                _require(e, e.both(e.eq(e.value(HSTAMP, pointer_ref), pass_id), e.eq(e.value(HST, pointer_ref), owner)))

            e.if_(_heap_view(e, token_type), view, heap)
            e.set_value(OCON, token_ref, visit)

        e.if_(e.ne(e.ld(deallocator_at), 0), deallocate)
        e.call(end_views, p["cursor"], p["block"])
        # Foreign code could write arbitrary bytes into link fields (ADR-097): link-bearing storage may only be released.
        e.var("linked_any", 0)

        def linked_value():
            v = p["v"]
            e.if_(e.both(e.eq(e.value(PSTAMP, v), pass_id), e.eq(e.value(PK, v), POINTER)), lambda: e.if_(
                e.ne(_has_link(e, e.value(PREC, v)), 0), lambda: e.set("linked_any", 1)))

        e.for_("v", 0, e.hd(H_V), linked_value)

        def linked_inputs():
            def each_effect():
                value = e.rd(e.add(n.vids_at, p["j"]))
                storage = e.value(EST, value)

                def reached():
                    e.var("linked", 0)
                    e.for_("v", 0, e.hd(H_V), lambda: e.if_(e.both(
                        e.eq(e.value(PSTAMP, p["v"]), pass_id), e.eq(e.value(PK, p["v"]), POINTER), e.eq(e.value(PST, p["v"]), storage)), lambda: e.if_(
                        e.ne(_has_link(e, e.value(PREC, p["v"])), 0), lambda: e.set("linked", 1))))
                    _require(e, e.either(e.eq(p["linked"], 0), e.eq(storage, p["released"])))

                e.if_(e.both(e.ne(e.table(_T.MEMEFFECT, e.rd(e.add(n.tids_at, p["j"]))), 0), e.eq(e.value(ESTAMP, value), visit)), reached)

            e.for_("j", 0, inputs, each_effect)

        e.if_(e.ne(p["linked_any"], 0), linked_inputs)
        # Memory frontiers: each input is consumed; the k-th carries its fact to the k-th memory output.
        e.var("k", 0)
        e.var("r", 0)

        def each_input():
            value, type_ = e.rd(e.add(n.vids_at, p["j"])), e.rd(e.add(n.tids_at, p["j"]))

            def frontier():
                def with_fact():
                    _require(e, e.ne(e.value(ECON, value), visit))
                    _consumed(e, value)

                    # The k-th memory output: scan results for it.
                    e.var("seen", 0)
                    e.var("target", NONE)

                    def find():
                        e.if_(e.ne(e.table(_T.MEMEFFECT, e.rd(e.add(n.rt_at, p["r"]))), 0), lambda: (
                            e.if_(e.eq(p["seen"], p["k"]), lambda: e.set("target", p["r"])), e.set("seen", e.add(p["seen"], 1))))

                    e.for_("r", 0, n.nr, find)
                    storage = e.value(EST, value)
                    e.if_(e.both(e.ne(p["target"], NONE), e.ne(storage, p["released"]), e.not_(_ended(e, storage))),
                          lambda: _set_effect(e, e.add(n.base, p["target"]), storage, e.value(EIV, value)))

                e.if_(e.eq(e.value(ESTAMP, value), visit), with_fact)
                e.set("k", e.add(p["k"], 1))

            e.if_(e.ne(e.table(_T.MEMEFFECT, type_), 0), frontier)

        e.for_("j", 0, inputs, each_input)
        e.if_(e.ne(p["released"], NONE), lambda: (_check_dependents(e, p["released"]), e.st(_site_word(e, 1, p["released"]), 1)))

        def allocate():
            pointer_output, token_output = e.ld(e.add(e.add(allocator_at, 2), sizes)), e.ld(e.add(e.add(allocator_at, 3), sizes))
            alignment, zeroed = e.ld(e.add(e.add(allocator_at, 4), sizes)), e.ld(e.add(e.add(allocator_at, 5), sizes))
            pointer_type = e.rd(e.add(n.rt_at, pointer_output))
            _require(e, e.both(e.ne(e.table(_T.PTR, pointer_type), 0), e.eq(e.table(_T.PSPACE, pointer_type), 2)))
            _require(e, _heap_owner(e, e.rd(e.add(n.rt_at, token_output))))
            e.var("size", 1)
            e.var("known_size", 1)

            def factor():
                value, ok = _constant_value(e, e.rd(e.add(n.vids_at, e.ld(e.add(e.add(allocator_at, 2), p["s"])))))
                e.if_(e.eq(ok, 0), lambda: e.set("known_size", 0))
                # Products past 2^62 decline (the bootstrap's integers are unbounded).
                e.if_(e.both(e.ne(ok, 0), e.ne(value, 0)), lambda: _require(e, e.le(p["size"], e.udiv(1 << 62, value))))
                e.set("size", e.mul(p["size"], value))

            e.for_("s", 0, sizes, factor)
            site = n.site
            pointer_value = e.add(n.base, pointer_output)
            e.set_value(HSTAMP, pointer_value, pass_id)
            e.set_value(HST, pointer_value, site)
            e.set_value(HSIZE, pointer_value, e.sel(e.ne(p["known_size"], 0), p["size"], NONE))
            e.set_value(HZERO, pointer_value, zeroed)
            e.set_value(HALIGN, pointer_value, alignment)
            token_value = e.add(n.base, token_output)
            e.set_value(OST, token_value, site)
            e.set_value(OSTAMP, token_value, visit)

        e.if_(has_allocator, allocate)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


PASSED = 5  # passed-view slot: token type, storage, link record, used, link target


def _view_call(e: E, n, types_at, count, results_at, result_count, insert_effect=None, declared_at=None):
    """``_verify_heap_view_call``: borrow whole views across the call and re-establish returned ones.

    ``declared_at``: the callee's entry ``link_target`` declarations ``[count, (view, target) pairs]``
    (NONE when they could not be read), or None (no declarations)."""
    p = e.p
    visit, pass_id = e.hd(H_VISIT), e.hd(H_PASS)
    _triples_valid(e, count, types_at)
    _triples_valid(e, result_count, results_at)
    declared_count = e.c(0) if declared_at is None else e.rd(declared_at)
    # Passed views: (token type, storage, link record, used, link target) in a scratch list.
    e.var("passed", e.alloc(e.add(e.mul(count, PASSED), 1)))
    _require(e, e.ne(p["passed"], NONE))
    e.var("passed_n", 0)

    def each_input():
        index = p["q"]

        def borrow():
            pointer_ref, token_ref, effect_ref = (e.rd(e.add(n.vids_at, e.add(index, d))) for d in (-1, 0, 1))
            view_type = e.rd(e.add(types_at, index))
            extent = e.table(_T.RINSTANCE, view_type)
            _require(e, e.both(e.eq(e.value(OSTAMP, token_ref), visit), e.ne(e.value(OCON, token_ref), visit)))
            owner = e.value(OST, token_ref)
            _require(e, e.both(e.eq(e.value(PSTAMP, pointer_ref), pass_id), e.eq(e.value(PK, pointer_ref), POINTER), e.eq(e.value(PST, pointer_ref), owner),
                               e.eq(e.value(POFF, pointer_ref), 0), e.eq(e.value(PWIN, pointer_ref), 0)))
            _require(e, e.ne(declared_count, NONE))
            e.var("declared_target", NONE)
            if declared_at is not None:
                e.for_("dk", 0, declared_count, lambda: e.if_(e.eq(e.rd(e.add(declared_at, e.add(1, e.mul(p["dk"], 2)))), e.sub(index, 1)), lambda: e.set(
                    "declared_target", e.rd(e.add(declared_at, e.add(2, e.mul(p["dk"], 2)))))))

            def declared():
                _require(e, e.lt(p["declared_target"], n.no))
                target = e.rd(e.add(n.vids_at, p["declared_target"]))
                _require(e, e.both(e.eq(e.value(PSTAMP, target), pass_id), e.eq(e.value(PK, target), POINTER),
                                   e.eq(e.value(PLT, pointer_ref), e.value(PST, target)), e.eq(e.value(PLR, pointer_ref), e.value(PREC, target))))

            e.if_(e.ne(p["declared_target"], NONE), declared, lambda: _require(e, e.either(
                e.eq(_has_link(e, e.value(PREC, pointer_ref)), 0), e.eq(e.value(PLT, pointer_ref), e.value(PST, pointer_ref)))))
            _require(e, e.both(e.eq(e.value(ESTAMP, effect_ref), visit), e.eq(e.value(EST, effect_ref), owner)))
            _require(e, e.not_(_ended(e, owner)))
            _require(e, e.ne(e.value(ECON, effect_ref), visit))
            initialized = e.eq(e.table(_T.RSTATE, view_type), 1)
            e.if_(initialized, lambda: _require(e, e.ne(e.call(insert_effect, e.value(EIV, effect_ref), 0, extent), 0)))
            e.set_value(OCON, token_ref, visit)
            _consumed(e, effect_ref)
            slot = e.add(p["passed"], e.mul(p["passed_n"], PASSED))
            e.st(slot, view_type)
            e.st(e.add(slot, 1), owner)
            e.st(e.add(slot, 2), e.value(PLR, pointer_ref))
            e.st(e.add(slot, 3), 0)
            e.st(e.add(slot, 4), e.value(PLT, pointer_ref))
            e.set("passed_n", e.add(p["passed_n"], 1))

        e.if_(_heap_view(e, e.rd(e.add(types_at, index))), borrow)

    e.for_("q", 0, count, each_input)

    def each_output():
        index = p["q"]

        def give_back():
            view_type = e.rd(e.add(results_at, index))
            extent = e.table(_T.RINSTANCE, view_type)
            _require(e, e.ne(declared_count, NONE))
            e.var("storage", e.add(n.site, index))  # a new view: site (block, node, index)
            e.var("link_record", NONE)
            e.var("link_target", NONE)

            def match():
                slot = e.add(p["passed"], e.mul(p["m"], PASSED))
                e.if_(e.both(e.eq(p["storage"], e.add(n.site, index)), e.eq(e.ld(e.add(slot, 3)), 0), e.eq(e.ld(slot), view_type)), lambda: (
                    e.set("storage", e.ld(e.add(slot, 1))), e.set("link_record", e.ld(e.add(slot, 2))), e.set("link_target", e.ld(e.add(slot, 4))),
                    e.st(e.add(slot, 3), 1)))

            e.for_("m", 0, p["passed_n"], match)
            pointer_type = e.rd(e.add(results_at, e.sub(index, 1)))
            element = e.table(_T.PELEM, pointer_type)
            # A returned borrowed view keeps the caller's link target (callees return only self-targeted new views).
            fresh = e.eq(p["storage"], e.add(n.site, index))
            link_record = e.sel(fresh, element, p["link_record"])
            link_target = e.sel(fresh, p["storage"], p["link_target"])
            base = n.base
            _set_pointer(e, e.add(base, e.sub(index, 1)), {
                PK: POINTER, PST: p["storage"], PEL: element, PPERM: e.table(_T.PPERM, pointer_type), POFF: 0, PEXT: extent,
                PALIGN: e.table(_T.PALIGN, pointer_type), PALIAS: p["storage"], PWIN: 0, PREC: element, PLT: link_target, PLR: link_record,
            })
            e.set_value(OST, e.add(base, index), p["storage"])
            e.set_value(OSTAMP, e.add(base, index), visit)
            _set_effect(e, e.add(base, e.add(index, 1)), p["storage"], _initialized_list(e, e.flag(e.eq(e.table(_T.RSTATE, view_type), 1)), extent))

        e.if_(_heap_view(e, e.rd(e.add(results_at, index))), give_back)

    e.for_("q", 0, result_count, each_output)
    # Views not given back were released by the callee: their storage ends, after every live storage
    # linking into it has ended too.
    released = lambda: e.eq(e.ld(e.add(e.add(p["passed"], e.mul(p["m"], PASSED)), 3)), 0)  # noqa: E731
    storage_of = lambda: e.ld(e.add(e.add(p["passed"], e.mul(p["m"], PASSED)), 1))  # noqa: E731
    e.for_("m", 0, p["passed_n"], lambda: e.if_(released(), lambda: e.st(_site_word(e, 1, storage_of()), 1)))
    e.for_("m", 0, p["passed_n"], lambda: e.if_(released(), lambda: _check_dependents(e, storage_of())))


def _view_slot(e: E, count, at, position):
    """1 when ``position`` lies in a view triple of the ``count`` types at ``at``."""
    p = e.p
    e.var("in_slot", 0)

    def each():
        index = p["z"]
        near = e.both(e.le(index, e.add(position, 1)), e.le(position, e.add(index, 1)))
        e.if_(e.both(_heap_view(e, e.rd(e.add(at, index))), near), lambda: e.set("in_slot", 1))

    e.for_("z", 0, count, each)
    return p["in_slot"]


def _call_direct(tables, covers):
    """A direct call's fact effects: memory frontiers, view borrowing (stack resource contracts: a later stage)."""
    def build(e: E):
        p = e.p
        n = _Node(e)
        e.var("resource", 0)
        e.var("stack", 0)

        def scan(count, at):
            def each():
                cid = e.rd(e.add(at, p["j"]))
                outside = e.eq(_view_slot(e, count, at, p["j"]), 0)
                memory = e.both(e.ne(e.table(_T.MEMEFFECT, cid), 0), outside)
                e.if_(e.either(e.ne(e.table(_T.STACKOWNER, cid), 0), memory), lambda: e.set("resource", 1))
                e.if_(e.either(e.ne(e.table(_T.STACKOWNER, cid), 0), e.eq(e.table(_T.FORMB, cid), 2)), lambda: e.set("stack", 1))
            e.for_("j", 0, count, each)

        scan(n.no, n.tids_at)
        scan(n.nr, n.rt_at)
        e.if_(e.both(e.ne(p["resource"], 0), e.ne(p["stack"], 0)), lambda: _resource_call(e, n))

        def frontier():
            visit = e.hd(H_VISIT)

            def each():
                value = e.rd(e.add(n.vids_at, p["j"]))

                def consume():
                    _require(e, e.ne(e.value(ECON, value), visit))
                    _consumed(e, value)

                e.if_(e.both(e.ne(e.table(_T.MEMEFFECT, e.rd(e.add(n.tids_at, p["j"]))), 0), e.eq(e.value(ESTAMP, value), visit)), consume)

            e.for_("j", 0, n.no, each)

        e.if_(e.both(e.ne(p["resource"], 0), e.eq(p["stack"], 0)), frontier)
        # Aux words: [count, summary blocks, operation count, operations, declaration count, pairs] (or [0]).
        declared_at = e.sel(e.eq(e.rd(n.aux_at), 0), n.aux_at, e.add(e.add(n.aux_at, 3), e.rd(e.add(n.aux_at, 2))))
        _view_call(e, n, n.tids_at, n.no, n.rt_at, n.nr, covers, declared_at)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _resource_call(e: E, n):
    """A direct call through a stack resource contract (the callee's single block summarized)."""
    p = e.p
    visit = e.hd(H_VISIT)
    aux_count = e.rd(n.aux_at)
    blocks, operations = e.rd(e.add(n.aux_at, 1)), e.rd(e.add(n.aux_at, 2))
    single = e.flag(e.both(e.ne(aux_count, 0), e.eq(blocks, 1)))
    body = _body_shape(e, lambda k: e.rd(e.add(e.add(n.aux_at, 3), k)), e.mul(single, operations))
    kind, permission, requires_initialized, initializes = _resource_contract(e, n.tids_at, n.no, n.rt_at, n.nr, single, body)
    _require(e, e.ne(kind, R_NONE))
    e.var("has_pointer", e.flag(e.ne(kind, R_PASS)))
    owner_operand = e.sel(e.eq(kind, R_PASS), 0, e.sel(e.eq(kind, R_LOAD), 1, 2))
    effect_operand = e.add(owner_operand, 1)
    owner_result = e.sel(e.either(e.eq(kind, R_PASS), e.eq(kind, R_STORE)), 0, 1)
    effect_result = e.add(owner_result, 1)
    pointer_ref = n.vid(0)
    e.var("size", 0)
    e.var("offset", 0)

    def with_pointer():
        _require(e, e.both(e.eq(e.value(PSTAMP, pointer_ref), e.hd(H_PASS)), e.eq(e.value(PK, pointer_ref), POINTER)))
        _require(e, e.both(e.not_(_ended(e, e.value(PST, pointer_ref))), e.eq(e.value(PWIN, pointer_ref), 0)))
        width = e.table(_T.WIDTH, e.value(PEL, pointer_ref))
        _require(e, e.ne(width, 0))
        e.set("size", e.udiv(e.add(width, 7), 8))
        e.set("offset", e.value(POFF, pointer_ref))
        _require(e, e.le(p["size"], e.value(PEXT, pointer_ref)))
        _require(e, e.eq(e.and_(e.value(PPERM, pointer_ref), permission), permission))

    e.if_(e.ne(p["has_pointer"], 0), with_pointer)
    owner_ref = e.rd(e.add(n.vids_at, owner_operand))
    effect_ref = e.rd(e.add(n.vids_at, effect_operand))
    _require(e, e.both(e.eq(e.value(OSTAMP, owner_ref), visit), e.ne(e.value(OCON, owner_ref), visit)))
    storage = e.value(OST, owner_ref)
    _require(e, e.not_(_ended(e, storage)))
    e.if_(e.ne(p["has_pointer"], 0), lambda: _require(e, e.eq(e.value(PST, pointer_ref), storage)))
    _require(e, e.both(e.eq(e.value(ESTAMP, effect_ref), visit), e.eq(e.value(EST, effect_ref), storage)))
    e.var("intervals", e.value(EIV, effect_ref))
    e.if_(e.both(e.ne(p["has_pointer"], 0), e.ne(requires_initialized, 0)), lambda: _require(
        e, e.ne(e.call(_COVERS[0], p["intervals"], p["offset"], e.add(p["offset"], p["size"])), 0)))
    _require(e, e.ne(e.value(ECON, effect_ref), visit))
    e.set_value(OCON, owner_ref, visit)
    _consumed(e, effect_ref)
    e.set_value(OST, e.add(n.base, owner_result), storage)
    e.set_value(OSTAMP, e.add(n.base, owner_result), visit)

    def initialize():
        e.set("intervals", e.call(_INSERT[0], p["intervals"], p["offset"], e.add(p["offset"], p["size"])))
        _require(e, e.ne(p["intervals"], NONE))

    e.if_(e.both(e.ne(p["has_pointer"], 0), e.ne(initializes, 0)), initialize)
    _set_effect(e, e.add(n.base, effect_result), storage, p["intervals"])


_COVERS: list = []
_INSERT: list = []


def _call_group(tables, covers):
    """``call.group_member``: memory only as whole view triples, borrowed like a direct call."""
    def build(e: E):
        p = e.p
        n = _Node(e)

        def check(count, at):
            def each():
                cid = e.rd(e.add(at, p["j"]))
                memory = e.either(e.ne(e.table(_T.STACKOWNER, cid), 0), e.ne(e.table(_T.MEMEFFECT, cid), 0), e.eq(e.table(_T.FORMB, cid), 2))
                e.if_(memory, lambda: _require(e, e.ne(_view_slot(e, count, at, p["j"]), 0)))
            e.for_("j", 0, count, each)

        check(n.no, n.tids_at)
        check(n.nr, n.rt_at)
        _view_call(e, n, n.tids_at, n.no, n.rt_at, n.nr, covers)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


# -- S4d.2d: atomics and raw loads ----------------------------------------------------------------------

ATOMIC_SHAPES = {
    Operation.ATOMIC_LOAD: (2, 2, 3, 1), Operation.ATOMIC_STORE: (3, 1, 3, 2),
    Operation.ATOMIC_RMW: (3, 2, 4, 2), Operation.ATOMIC_CMPXCHG: (4, 3, 5, 3),
}  # operands, results, attributes, effect operand index
ATOMIC_ORDERS = {
    Operation.ATOMIC_LOAD: (1, 2, 5), Operation.ATOMIC_STORE: (1, 3, 5), Operation.ATOMIC_RMW: (1, 2, 3, 4, 5), Operation.ATOMIC_CMPXCHG: (1, 2, 3, 4, 5),
}  # ``_ATOMIC_ORDERS``: relaxed 1, acquire 2, release 3, acq_rel 4, seq_cst 5
FENCE_ORDERS = (2, 3, 4, 5)
READ_STRENGTH = {1: 0, 3: 0, 2: 1, 4: 1, 5: 2}  # compare-exchange: the failure order is no stronger
SCOPES = (1, 2, 3)
UNSAFE_DOMAIN = 10
MAX_ACCESSES = 8  # MAX_RESOURCE_CALL_ACCESSES


def _one_of(e: E, value, codes):
    return e.either(*(e.eq(value, code) for code in codes))


def _atomic(tables, covers, insert, operation):
    operands, results, attributes, effect_index = ATOMIC_SHAPES[operation]

    def build(e: E):
        p = e.p
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source)
        _require(e, n.shape(operands, results, attributes))
        if operation == Operation.ATOMIC_RMW:
            kind, order, scope, alignment = (n.attr(k) for k in range(4))
            _require(e, e.both(_one_of(e, kind, (1, 2)), _one_of(e, order, ATOMIC_ORDERS[operation])))
        elif operation == Operation.ATOMIC_CMPXCHG:
            success, failure, scope, alignment, strength = (n.attr(k) for k in range(5))
            _require(e, e.both(_one_of(e, success, ATOMIC_ORDERS[operation]), _one_of(e, failure, (1, 2, 5)), _one_of(e, strength, (1, 2))))
            strength_of = lambda order: e.add(e.flag(e.either(e.eq(order, 2), e.eq(order, 4))), e.mul(e.flag(e.eq(order, 5)), 2))  # noqa: E731
            _require(e, e.le(strength_of(failure), strength_of(success)))
        else:
            order, scope, alignment = (n.attr(k) for k in range(3))
            _require(e, _one_of(e, order, ATOMIC_ORDERS[operation]))
        _require(e, _one_of(e, scope, SCOPES))
        element = e.value(PEL, source)
        width = e.table(_T.WIDTH, element)
        _require(e, e.ne(width, 0))
        size = e.udiv(e.add(width, 7), 8)
        _access(e, source, size, alignment)
        storage = e.value(PST, source)
        intervals = _consume_effect(e, n.vid(effect_index), storage)
        effect_type = n.tid(effect_index)
        _require(e, e.both(e.ne(e.table(_T.MEMEFFECT, effect_type), 0), e.eq(n.rtid(results - 1), effect_type)))
        permission = e.value(PPERM, source)
        if operation != Operation.ATOMIC_LOAD:
            _require(e, e.ne(e.and_(permission, int(Permission.WRITE)), 0))
        if operation != Operation.ATOMIC_STORE:
            _require(e, e.ne(e.and_(permission, int(Permission.READ)), 0))
        for index in range(1, effect_index):
            _require(e, e.eq(n.tid(index), element))
        if operation in (Operation.ATOMIC_LOAD, Operation.ATOMIC_RMW):
            _require(e, e.eq(n.rtid(0), element))
        if operation == Operation.ATOMIC_CMPXCHG:
            _require(e, e.both(e.eq(n.rtid(0), element), e.eq(e.table(_T.WIDTH, n.rtid(1)), 1)))
        _require(e, e.both(e.eq(e.value(PWIN, source), 0), e.eq(e.table(_T.LINK, element), 0)))
        start = e.value(POFF, source)
        if operation != Operation.ATOMIC_STORE:
            _require(e, e.ne(e.call(covers, intervals, start, e.add(start, size)), 0))
        e.var("next_list", e.call(insert, intervals, start, e.add(start, size)))
        _require(e, e.ne(p["next_list"], NONE))
        _set_effect(e, e.add(n.base, results - 1), storage, p["next_list"])
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _atomic_fence(tables):
    def build(e: E):
        n = _Node(e)
        _require(e, n.shape(1, 1, 2))
        _require(e, e.both(_one_of(e, n.attr(0), FENCE_ORDERS), _one_of(e, n.attr(1), SCOPES)))
        _require(e, e.both(e.eq(e.table(_T.FORMB, n.tid(0)), 3), e.eq(n.rtid(0), n.tid(0))))
        frontier = n.vid(0)

        def carry():
            storage = e.value(EST, frontier)
            intervals = _consume_effect(e, frontier, storage)
            _set_effect(e, n.base, storage, intervals)

        e.if_(e.eq(e.value(ESTAMP, frontier), e.hd(H_VISIT)), carry)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _raw_load(tables, covers):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source)
        _require(e, n.shape(3, 3, 3))
        size, alignment, waivers = n.attr(0), n.attr(1), n.attr(2)
        _require(e, e.both(e.ne(waivers, 0), e.eq(e.and_(waivers, ~3 & ((1 << 64) - 1)), 0)))
        element = e.value(PEL, source)
        _require(e, e.both(e.ne(size, 0), e.eq(size, _element_size(e, element, size)), e.le(size, e.value(PEXT, source))))
        _require(e, e.both(e.ne(e.and_(e.value(PPERM, source), int(Permission.READ)), 0), e.eq(n.rtid(0), element)))
        e.if_(e.eq(e.and_(waivers, 1), 0), lambda: _require(e, e.both(
            e.power_of_two(alignment), e.le(alignment, e.value(PALIGN, source)), e.eq(e.urem(e.value(POFF, source), alignment), 0))))
        storage = e.value(PST, source)
        intervals = _consume_effect(e, n.vid(1), storage)
        unsafe = n.tid(2)
        _require(e, e.both(e.ne(e.table(_T.MEMEFFECT, n.tid(1)), 0), e.ne(e.table(_T.EFFECT, unsafe), 0), e.eq(e.table(_T.EDOMAIN, unsafe), UNSAFE_DOMAIN)))
        _require(e, e.both(e.eq(n.rtid(1), n.tid(1)), e.eq(n.rtid(2), unsafe)))
        start = e.value(POFF, source)
        e.if_(e.eq(e.and_(waivers, 2), 0), lambda: _require(e, e.ne(e.call(covers, intervals, start, e.add(e.add(start, e.value(PWIN, source)), size)), 0)))
        _set_effect(e, e.add(n.base, 1), storage, intervals)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


# -- S4d.2d: records and links (ADR-097, ADR-099, ADR-101) ---------------------------------------

def _link_make(tables):
    """``link_make``: a link names one whole record of its storage."""
    def build(e: E):
        n = _Node(e)
        _require(e, n.shape(1, 1, 0))
        source = n.vid(0)
        _pointer(e, source)
        element = e.value(PEL, source)
        stride = _record_bytes(e, element)
        _require(e, e.both(e.ne(stride, 0), e.eq(element, e.value(PREC, source))))
        _require(e, e.both(e.eq(_mod(e, e.value(POFF, source), stride), 0), e.le(stride, e.value(PEXT, source)),
                           e.either(e.eq(e.value(PWIN, source), 0), e.eq(_mod(e, e.value(PALIGN, source), stride), 0))))
        _require(e, e.ne(e.table(_T.LINK, n.rtid(0)), 0))
        _link_fact(e, n.base, e.value(PST, source), e.value(PREC, source))
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _link_follow(tables):
    """``link_follow``: a non-null link of this storage reloads one record, with no range check."""
    def build(e: E):
        n = _Node(e)
        _require(e, n.shape(2, 1, 0))
        view, link = n.vid(0), n.vid(1)
        _pointer(e, view)
        element_of_view = e.value(PEL, view)
        stride = _record_bytes(e, element_of_view)
        _require(e, e.both(e.ne(stride, 0), e.eq(element_of_view, e.value(PREC, view)), e.eq(e.value(POFF, view), 0), e.eq(e.value(PWIN, view), 0)))
        _require(e, e.both(e.eq(e.value(PSTAMP, link), e.hd(H_PASS)), e.eq(e.value(PK, link), LINK),
                           e.eq(e.value(PST, link), e.value(PST, view)), e.eq(e.value(PREC, link), e.value(PREC, view))))
        view_type, result_type = n.tid(0), n.rtid(0)
        _require(e, e.both(e.ne(e.table(_T.PTR, view_type), 0), e.ne(e.table(_T.PTR, result_type), 0)))
        element, permission, alignment = e.table(_T.PELEM, result_type), e.table(_T.PPERM, result_type), e.table(_T.PALIGN, result_type)
        record_alignment = e.and_(stride, e.sub(0, stride))  # the largest power of two dividing the stride
        actual = e.sel(e.lt(e.value(PALIGN, view), record_alignment), e.value(PALIGN, view), record_alignment)
        _require(e, e.both(e.eq(e.table(_T.PSPACE, view_type), e.table(_T.PSPACE, result_type)), e.eq(element, element_of_view),
                           e.eq(e.and_(permission, e.value(PPERM, view)), permission), e.le(alignment, actual)))
        fields = {word: e.value(word, view) for word in range(POINTER_WORDS)}
        fields.update({PEL: element, PPERM: permission, POFF: 0, PEXT: stride, PALIGN: actual, PWIN: e.sub(e.value(PEXT, view), stride)})
        _set_pointer(e, n.base, fields)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _link_target(tables):
    """``link_target`` (proof only): borrowed view operand 0 links into borrowed view operand 1."""
    def build(e: E):
        p = e.p
        n = _Node(e)
        _require(e, n.shape(2, 0, 0))
        view, target = n.vid(0), n.vid(1)
        _pointer(e, view)
        _pointer(e, target)
        params_at = e.ld(_block_word(e, p["block"], B_PARAMS))
        base, count = e.rd(params_at), e.rd(e.add(params_at, 1))
        own = lambda value: e.both(e.eq(e.value(DEF, value), NONE), e.le(base, value), e.lt(value, e.add(base, count)))  # noqa: E731
        borrowed = lambda value: e.eq(e.rd(e.add(e.hd(H_KINDS), e.value(PST, value))), SITE_BORROWED)  # noqa: E731
        _require(e, e.both(own(view), own(target), borrowed(view), borrowed(target)))
        _require(e, e.both(e.ne(_has_link(e, e.value(PREC, view)), 0), e.ne(_record_bytes(e, e.value(PREC, target)), 0),
                           e.eq(e.value(PLT, view), e.value(PST, target))))
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _constant(tables):
    """A typing-proven constant; a link constant is the null link."""
    def build(e: E):
        n = _Node(e)
        _require(e, e.ne(n.key, NONE))
        e.if_(e.both(e.eq(n.nr, 1), e.ne(e.table(_T.LINK, n.rtid(0)), 0)), lambda: _link_fact(e, n.base, NONE, NONE))
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


# -- S4d.2d: stack resource call contracts (``_resource_call_candidates`` and ``_summarize_resource_contract``) --
# Contract kinds and their operand/result positions.
R_NONE, R_PASS, R_STORE, R_LOAD, R_MIXED = range(5)
RESOURCE_SHAPES = {  # pointer operand (None), owner operand, effect operand, owner result, effect result, return count
    R_PASS: (None, 0, 1, 0, 1, 2), R_STORE: (0, 2, 3, 0, 1, 2), R_LOAD: (0, 1, 2, 1, 2, 3), R_MIXED: (0, 2, 3, 1, 2, 3),
}
STORE_OP, LOAD_OP = int(Operation.STORE_BITS_LE), int(Operation.LOAD_BITS_LE)


def _body_shape(e: E, operation_at, count):
    """``(all stores, all loads, mixed body)`` flags of a single block's operations (``operation_at(k)``)."""
    p = e.p
    e.var("stores", 0)
    e.var("loads", 0)
    e.var("others", 0)

    def each():
        operation = operation_at(p["u"])
        e.if_(e.eq(operation, STORE_OP), lambda: e.set("stores", e.add(p["stores"], 1)), lambda: e.if_(
            e.eq(operation, LOAD_OP), lambda: e.set("loads", e.add(p["loads"], 1)), lambda: e.set("others", e.add(p["others"], 1))))

    e.for_("u", 0, count, each)
    sized = e.both(e.le(1, count), e.le(count, MAX_ACCESSES))
    all_stores = e.flag(e.both(sized, e.eq(p["stores"], count)))
    all_loads = e.flag(e.both(sized, e.eq(p["loads"], count)))
    last_load = e.eq(operation_at(e.sub(count, 1)), LOAD_OP)
    mixed = e.flag(e.both(sized, e.le(2, count), last_load, e.ne(p["stores"], 0), e.ne(p["loads"], 0), e.eq(p["others"], 0)))
    first_load = e.flag(e.both(e.ne(count, 0), e.eq(operation_at(0), LOAD_OP)))
    return all_stores, all_loads, mixed, first_load


def _resource_contract(e: E, parameters_at, parameters, returns_at, returns, single_block, body):
    """The unique summarized contract: ``(kind, required permission, requires initialized, initializes)``.

    ``returns_at`` None matches any returns (entry contracts); ``body`` is ``_body_shape``'s result.
    """
    p = e.p
    param = lambda k: e.rd(e.add(parameters_at, k))  # noqa: E731
    owner, memory = (lambda t: e.ne(e.table(_T.STACKOWNER, t), 0)), (lambda t: e.ne(e.table(_T.MEMEFFECT, t), 0))
    pointer_ok = e.both(e.eq(e.table(_T.FORMB, param(0)), 2), e.ne(e.table(_T.PTR, param(0)), 0))
    element = e.table(_T.PELEM, param(0))
    two = e.both(e.eq(parameters, 2), owner(param(0)), memory(param(1)))
    four = e.both(e.eq(parameters, 4), pointer_ok, e.eq(param(1), element), owner(param(2)), memory(param(3)))
    three = e.both(e.eq(parameters, 3), pointer_ok, owner(param(1)), memory(param(2)))

    def returns_are(*expected):
        if returns_at is None:
            return e.eq(0, 0)
        same = e.eq(returns, len(expected))
        for k, value in enumerate(expected):
            same = e.both(same, e.eq(e.rd(e.add(returns_at, k)), value))
        return same

    all_stores, all_loads, mixed, first_load = body
    candidates = (
        (R_PASS, e.both(two, returns_are(param(0), param(1))), e.c(1)),
        (R_STORE, e.both(four, returns_are(param(2), param(3))), all_stores),
        (R_MIXED, e.both(four, returns_are(element, param(2), param(3))), mixed),
        (R_LOAD, e.both(three, returns_are(element, param(1), param(2))), all_loads),
    )
    e.var("contract", R_NONE)
    e.var("contracts", 0)
    for kind, candidate, matches in candidates:
        e.if_(e.both(candidate, e.ne(single_block, 0), e.ne(matches, 0)), lambda kind=kind: (e.set("contract", kind), e.set("contracts", e.add(p["contracts"], 1))))
    e.if_(e.ne(p["contracts"], 1), lambda: e.set("contract", R_NONE))
    permission = e.sel(e.ne(all_stores, 0), int(Permission.WRITE), e.sel(e.ne(all_loads, 0), int(Permission.READ), int(Permission.READ_WRITE)))
    initializes = e.flag(e.ne(p["stores"], 0))
    return p["contract"], permission, first_load, initializes


# -- S4d.2d: function interfaces, code-entry identities, function.address, lend entries, call.indirect -------

def _known_type(e: E, type_index):
    """A type the typing decoders validated (``_verify_type`` accepts it)."""
    return e.either(*(e.ne(e.table(table, type_index), 0) for table in (
        _T.WIDTH, _T.FORMAT, _T.LINK, _T.AGGREGATE, _T.EFFECT, _T.RESOURCE, _T.OPAQUE, _T.PTR, _T.OPID)))


def _object_kind(e: E, entry):
    count = e.hd(H_COUNT)
    valid = e.lt(entry, count)
    position = e.ld(e.add(e.add(e.hd(H_TABLE), e.mul(count, _T.POSITION)), e.sel(valid, entry, 0)))
    return e.mul(e.flag(valid), e.rd(position))


def _object_position(e: E, entry):
    count = e.hd(H_COUNT)
    return e.ld(e.add(e.add(e.hd(H_TABLE), e.mul(count, _T.POSITION)), e.sel(e.lt(entry, count), entry, 0)))


def _cid_lookup(e: E, at, name: str):
    """The type-table index of the 32-byte CID at input bytes ``at`` (NONE when absent)."""
    p = e.p
    words = []
    for word in range(4):
        value = e.c(0)
        for byte in range(8):
            value = e.add(value, e.mul(e.rd(e.add(at, 8 * word + byte)), 1 << (8 * byte)))
        words.append(value)
    e.var(name, NONE)
    cids = e.hd(H_CIDS)

    def match():
        same = None
        for word in range(4):
            here = e.eq(e.rd(e.add(cids, e.add(e.mul(p["cid_k"], 4), word))), words[word])
            same = here if same is None else e.both(same, here)
        e.if_(same, lambda: e.set(name, p["cid_k"]))

    e.for_("cid_k", 0, e.hd(H_COUNT), match)
    return p[name]


def _interface(tables):
    """``_decode_function_interface`` of a fragment function: a record [P, P types, R, R types], or NONE."""
    from xax_compiler import Kind

    def build(e: E):
        p = e.p
        entity = p["entity"]
        _require(e, e.eq(_object_kind(e, entity), int(Kind.FUNCTION)))
        position = _object_position(e, entity)
        references, length = e.rd(e.add(position, 1)), e.rd(e.add(position, 2))
        base = e.add(position, 3)
        end = e.add(base, length)
        graph, graph_size, graph_ok = _uleb(e, base)
        _require(e, e.both(graph_ok, e.lt(graph, references)))
        _require(e, e.eq(_object_kind(e, e.rd(e.add(end, graph))), int(Kind.GRAPH_FRAGMENT)))
        e.var("record", e.alloc(e.add(length, 4)))
        _require(e, e.ne(p["record"], NONE))
        e.var("at", e.add(base, graph_size))
        e.var("out", p["record"])
        for _list in range(2):
            count, size, ok = _uleb(e, p["at"])
            _require(e, ok)
            e.set("at", e.add(p["at"], size))
            e.st(p["out"], count)
            e.set("out", e.add(p["out"], 1))

            def each():
                reference, width, reference_ok = _uleb(e, p["at"])
                _require(e, e.both(reference_ok, e.lt(reference, references), e.le(e.add(p["at"], width), end)))
                type_ = e.rd(e.add(end, reference))
                _require(e, _known_type(e, type_))
                e.st(p["out"], type_)
                e.set("out", e.add(p["out"], 1))
                e.set("at", e.add(p["at"], width))

            e.for_("i", 0, count, each)
        _require(e, e.eq(p["at"], end))
        e.give(p["record"])
    return _function(("entity",), build, tables)


def _identity(e: E, type_index):
    """(start, length) of an opaque identity type's bytes in the input."""
    position = _object_position(e, type_index)
    base = e.add(position, 3)
    length, size, _ok = _uleb(e, e.add(base, 1))
    return e.add(e.add(base, 1), size), length


def _prefixed(e: E, start, length, prefix: bytes):
    same = e.le(len(prefix), length)
    for offset, byte in enumerate(prefix):
        same = e.both(same, e.eq(e.rd(e.add(start, offset)), byte))
    return same


def _lend_view(e: E, pointer_type, name: str):
    """``lend_entry_view``: for a lend-entry pointer type, the view type index (NONE when not a lend entry);
    sets ``name + '_pointer'`` to the view pointer type index."""
    from xax_compiler import _LEND_ENTRY_PREFIX

    p = e.p
    e.var(name, NONE)
    e.var(name + "_pointer", NONE)
    element = e.table(_T.PELEM, pointer_type)

    def check():
        start, length = _identity(e, element)

        def found():
            e.set(name + "_pointer", _cid_lookup(e, e.add(start, len(_LEND_ENTRY_PREFIX)), name + "_vp"))
            e.set(name, _cid_lookup(e, e.add(start, len(_LEND_ENTRY_PREFIX) + 32), name + "_v"))

        e.if_(e.both(_prefixed(e, start, length, _LEND_ENTRY_PREFIX), e.eq(length, len(_LEND_ENTRY_PREFIX) + 64)), found)

    e.if_(e.both(e.ne(e.table(_T.PTR, pointer_type), 0), e.ne(e.table(_T.OPID, element), 0)), check)
    return p[name]


def _function_address(tables, interface):
    from xax_compiler import FOREIGN_ENTRY_ABIS, WASM32_BROWSER_EVENT_ABI, _CODE_ENTRY_PREFIX, _LEND_ENTRY_PREFIX, Kind

    def build(e: E):
        p = e.p
        n = _Node(e)
        _require(e, e.both(e.ne(n.entity, NONE), e.eq(_object_kind(e, n.entity), int(Kind.FUNCTION))))
        _require(e, e.both(e.eq(n.no, 0), e.eq(n.nr, 1)))
        result_type = n.rtid(0)
        _require(e, e.ne(e.table(_T.PTR, result_type), 0))
        element = e.table(_T.PELEM, result_type)

        def entry():
            start, length = _identity(e, element)
            e.var("iface", e.call(interface, n.entity))
            parameters_of = lambda: e.ld(p["iface"])  # noqa: E731

            def lend():
                # ``_lend_entry_admissible``
                view = _lend_view(e, result_type, "lv")
                _require(e, e.both(e.ne(view, NONE), e.ne(p["iface"], NONE)))
                count = parameters_of()
                params = e.add(p["iface"], 1)
                returns_at = e.add(e.add(params, count), 1)
                param = lambda k: e.ld(e.add(params, k))  # noqa: E731
                _require(e, e.le(3, count))
                _require(e, e.both(e.eq(param(e.sub(count, 3)), p["lv_pointer"]), e.eq(param(e.sub(count, 2)), view), e.ne(e.table(_T.MEMEFFECT, param(e.sub(count, 1))), 0)))
                _require(e, e.both(_heap_view(e, view), e.eq(e.table(_T.RSTATE, view), 1), e.ne(e.table(_T.PTR, p["lv_pointer"]), 0), e.eq(e.table(_T.PPERM, p["lv_pointer"]), 1)))
                e.for_("j", 0, e.sub(count, 3), lambda: _require(e, e.not_(_one_of(e, e.table(_T.FORMB, param(p["j"])), (3, 4)))))
                _require(e, e.eq(e.ld(e.sub(returns_at, 1)), 4))
                for k in range(3):
                    _require(e, e.eq(e.ld(e.add(returns_at, 1 + k)), param(e.add(e.sub(count, 3), k))))
                _require(e, e.eq(e.table(_T.FORMB, e.ld(returns_at)), 1))

            def code():
                _require(e, e.ne(p["iface"], NONE))
                count = parameters_of()
                params = e.add(p["iface"], 1)
                returns_count = e.ld(e.add(params, count))
                returns_at = e.add(e.add(params, count), 1)
                abi_start, abi_length = e.add(start, len(_CODE_ENTRY_PREFIX)), e.sub(length, len(_CODE_ENTRY_PREFIX))
                browser = e.both(e.eq(abi_length, len(WASM32_BROWSER_EVENT_ABI)), _prefixed(e, abi_start, abi_length, WASM32_BROWSER_EVENT_ABI))

                def host():
                    _require(e, e.eq(count, returns_count))
                    e.for_("j", 0, count, lambda: _require(e, e.both(
                        e.eq(e.ld(e.add(params, p["j"])), e.ld(e.add(returns_at, p["j"]))), e.ne(e.table(_T.EFFECT, e.ld(e.add(params, p["j"]))), 0),
                        e.eq(e.table(_T.MEMEFFECT, e.ld(e.add(params, p["j"]))), 0))))

                def foreign():
                    known = None
                    for abi in FOREIGN_ENTRY_ABIS:
                        same = e.both(e.eq(abi_length, len(abi)), _prefixed(e, abi_start, abi_length, abi))
                        known = same if known is None else e.either(known, same)
                    _require(e, known)
                    e.for_("j", 0, count, lambda: _require(e, e.not_(_one_of(e, e.table(_T.FORMB, e.ld(e.add(params, p["j"]))), (3, 4)))))
                    e.for_("j", 0, returns_count, lambda: _require(e, e.not_(_one_of(e, e.table(_T.FORMB, e.ld(e.add(returns_at, p["j"]))), (3, 4)))))

                e.if_(browser, host, foreign)

            e.if_(_prefixed(e, start, length, _LEND_ENTRY_PREFIX), lend, lambda: e.if_(_prefixed(e, start, length, _CODE_ENTRY_PREFIX), code, lambda: _decline(e)))

        e.if_(e.ne(e.table(_T.OPID, element), 0), entry, lambda: _require(e, e.eq(e.table(_T.OPAQUE, element), 3)))
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _call_indirect(tables):
    """``call.indirect``: a bounded call contract, and the stack proof when a local pointer crosses it."""
    from xax_compiler import Kind

    def build(e: E):
        p = e.p
        n = _Node(e)
        visit, pass_id = e.hd(H_VISIT), e.hd(H_PASS)
        _require(e, e.both(e.ne(n.entity, NONE), e.eq(_object_kind(e, n.entity), int(Kind.CALL_CONTRACT)), e.ne(n.no, 0)))
        position = _object_position(e, n.entity)
        references, length = e.rd(e.add(position, 1)), e.rd(e.add(position, 2))
        base = e.add(position, 3)
        end = e.add(base, length)
        # Contract body: inputs, outputs (type references), may_return, may_trap; every reference used.
        e.var("at", base)
        e.var("used", 0)
        lists = []
        for which in range(2):
            count, size, ok = _uleb(e, p["at"])
            _require(e, ok)
            e.set("at", e.add(p["at"], size))
            e.var(f"list{which}", e.alloc(e.add(count, 1)))
            _require(e, e.ne(p[f"list{which}"], NONE))
            e.st(p[f"list{which}"], count)

            def each(which=which):
                reference, width, reference_ok = _uleb(e, p["at"])
                _require(e, e.both(reference_ok, e.lt(reference, references), e.le(e.add(p["at"], width), end)))
                type_ = e.rd(e.add(end, reference))
                _require(e, _known_type(e, type_))
                e.st(e.add(p[f"list{which}"], e.add(p["j"], 1)), type_)
                e.set("at", e.add(p["at"], width))

            e.for_("j", 0, count, each)
            lists.append(p[f"list{which}"])
        _require(e, e.both(e.le(e.rd(p["at"]), 1), e.le(e.rd(e.add(p["at"], 1)), 1), e.eq(e.add(p["at"], 2), end)))
        # Every reference is used by some input or output.
        def referenced():
            target = e.rd(e.add(end, p["r"]))
            e.var("hit", 0)
            for which in range(2):
                e.for_("j", 0, e.ld(p[f"list{which}"]), lambda which=which: e.if_(e.eq(e.ld(e.add(p[f"list{which}"], e.add(p["j"], 1))), target), lambda: e.set("hit", 1)))
            _require(e, e.ne(p["hit"], 0))

        e.for_("r", 0, references, referenced)
        inputs, outputs = p["list0"], p["list1"]
        callee = n.tid(0)
        _require(e, e.both(e.ne(e.table(_T.PTR, callee), 0), e.eq(e.table(_T.OPAQUE, e.table(_T.PELEM, callee)), 3)))
        _require(e, e.both(e.eq(e.sub(n.no, 1), e.ld(inputs)), e.eq(n.nr, e.ld(outputs))))
        e.for_("j", 0, e.ld(inputs), lambda: _require(e, e.eq(e.rd(e.add(n.tids_at, e.add(p["j"], 1))), e.ld(e.add(inputs, e.add(p["j"], 1))))))
        e.for_("j", 0, e.ld(outputs), lambda: _require(e, e.eq(e.rd(e.add(n.rt_at, p["j"])), e.ld(e.add(outputs, e.add(p["j"], 1))))))
        # The stack proof: one local pointer, its owner, and its frontier cross the call together.
        e.var("pointers", 0)
        e.var("pointer_value", NONE)

        def find_pointer():
            value = e.rd(e.add(n.vids_at, e.add(p["j"], 1)))
            e.if_(e.both(e.eq(e.value(PSTAMP, value), pass_id), e.eq(e.value(PK, value), POINTER)), lambda: (
                e.set("pointers", e.add(p["pointers"], 1)), e.set("pointer_value", value)))

        e.for_("j", 0, e.ld(inputs), find_pointer)

        def proof():
            _require(e, e.eq(p["pointers"], 1))
            owners_in, owners_out = e.c(0), e.c(0)
            e.var("owner_in", NONE)
            e.var("owner_out", NONE)
            e.var("owners_in", 0)
            e.var("owners_out", 0)
            e.for_("j", 0, e.ld(inputs), lambda: e.if_(e.ne(e.table(_T.STACKOWNER, e.ld(e.add(inputs, e.add(p["j"], 1)))), 0), lambda: (
                e.set("owners_in", e.add(p["owners_in"], 1)), e.set("owner_in", p["j"]))))
            e.for_("j", 0, e.ld(outputs), lambda: e.if_(e.ne(e.table(_T.STACKOWNER, e.ld(e.add(outputs, e.add(p["j"], 1)))), 0), lambda: (
                e.set("owners_out", e.add(p["owners_out"], 1)), e.set("owner_out", p["j"]))))
            del owners_in, owners_out
            _require(e, e.both(e.eq(p["owners_in"], 1), e.eq(p["owners_out"], 1)))
            storage = e.value(PST, p["pointer_value"])
            _require(e, e.not_(_ended(e, storage)))
            owner_ref = e.rd(e.add(n.vids_at, e.add(p["owner_in"], 1)))
            e.var("effects", 0)
            e.var("effect_in", NONE)

            def find_effect():
                type_ = e.ld(e.add(inputs, e.add(p["j"], 1)))
                value = e.rd(e.add(n.vids_at, e.add(p["j"], 1)))
                e.if_(e.both(e.ne(e.table(_T.MEMEFFECT, type_), 0), e.eq(e.value(ESTAMP, value), visit), e.eq(e.value(EST, value), storage)), lambda: (
                    e.set("effects", e.add(p["effects"], 1)), e.set("effect_in", p["j"])))

            e.for_("j", 0, e.ld(inputs), find_effect)
            _require(e, e.eq(p["effects"], 1))
            effect_type = e.ld(e.add(inputs, e.add(p["effect_in"], 1)))
            effect_ref = e.rd(e.add(n.vids_at, e.add(p["effect_in"], 1)))
            e.var("effect_outs", 0)
            e.var("effect_out", NONE)
            e.for_("j", 0, e.ld(outputs), lambda: e.if_(e.both(e.eq(e.ld(e.add(outputs, e.add(p["j"], 1))), effect_type), e.ne(e.table(_T.MEMEFFECT, effect_type), 0)), lambda: (
                e.set("effect_outs", e.add(p["effect_outs"], 1)), e.set("effect_out", p["j"]))))
            _require(e, e.eq(p["effect_outs"], 1))
            _require(e, e.both(e.eq(e.value(OSTAMP, owner_ref), visit), e.eq(e.value(OST, owner_ref), storage)))
            _require(e, e.both(e.ne(e.value(OCON, owner_ref), visit), e.ne(e.value(ECON, effect_ref), visit)))
            e.set_value(OCON, owner_ref, visit)
            _consumed(e, effect_ref)
            e.set_value(OST, e.add(n.base, p["owner_out"]), storage)
            e.set_value(OSTAMP, e.add(n.base, p["owner_out"]), visit)
            _set_effect(e, e.add(n.base, p["effect_out"]), storage, e.value(EIV, effect_ref))

        e.if_(e.ne(p["pointers"], 0), proof)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


# -- blocks ------------------------------------------------------------------------------------------
# Per-block table words: parameters position, nodes position, terminator position, incoming position,
# current seed record, previous seed record.
BLOCK_WORDS = 6
B_PARAMS, B_NODES, B_TERM, B_INCOMING, B_SEED, B_PREVIOUS = range(BLOCK_WORDS)
# Per-edge table words: current exit, its pass, previous exit, previous valid.
EDGE_WORDS = 4
E_EXIT, E_PASS, E_PREVIOUS, E_VALID = range(EDGE_WORDS)
# Nodes whose operands are not ended by ``_end_heap_views`` afterwards (they borrow or release views themselves).
VIEW_KEEPING = (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.HEAP_VIEW)


def _block_word(e: E, block, word: int):
    return e.add(e.add(e.hd(H_BLOCKS), e.mul(block, BLOCK_WORDS)), word)


def _edge_word(e: E, edge, word: int):
    return e.add(e.add(e.hd(H_EDGES), e.mul(edge, EDGE_WORDS)), word)


def _node_dispatch(tables, handlers, end_views):
    """One node: typing proven where the typing function covers it, its fact effects, then ended views."""
    def build(e: E):
        p = e.p
        cursor = p["cursor"]
        operation, key = e.rd(cursor), e.rd(e.add(cursor, 1))
        e.set_hd(H_NODE, cursor)  # diagnosis: the node being modelled
        e.set_hd(H_CUROP, operation)
        # A node the typing function covers must be proven by it.
        e.if_(e.ne(key, NONE), lambda: _require(e, e.eq(e.ld(e.add(2, key)), _T.PROVEN)))
        e.var("next", NONE)
        e.var("handled", 0)
        for code, handler in handlers.items():
            e.if_(e.eq(operation, int(code)), lambda handler=handler: (e.set("next", e.call(handler, cursor, p["block"])), e.set("handled", 1)))
        _require(e, e.ne(p["next"], NONE) if False else e.either(e.ne(p["handled"], 0), e.ne(key, NONE)))
        e.if_(e.ne(p["handled"], 0), lambda: _require(e, e.ne(p["next"], NONE)), lambda: e.set("next", _Node(e).next))
        # Any node without a view-keeping contract ends the live views whose tokens it consumes.
        keeping = e.either(*(e.eq(operation, int(code)) for code in VIEW_KEEPING))
        e.if_(e.not_(keeping), lambda: e.call(end_views, cursor, p["block"]))
        e.give(p["next"])
    return _function(("cursor", "block"), build, tables)


def _return_views(e: E, term, values, covers):
    """``_verify_heap_view_return``: returned views are whole, live, and give borrowed views back in order."""
    p = e.p
    visit, pass_id = e.hd(H_VISIT), e.hd(H_PASS)
    ids_at, types_at = e.add(term, 2), e.add(e.add(term, 2), values)
    _triples_valid(e, values, types_at)
    entry_params = e.ld(_block_word(e, e.hd(H_ENTRY), B_PARAMS))
    entry_count, entry_types = e.rd(e.add(entry_params, 1)), e.add(entry_params, 2)
    # Borrowed views given back so far, per entry view position (flags in a scratch list).
    e.var("given", e.alloc(e.add(entry_count, 1)))
    _require(e, e.ne(p["given"], NONE))
    e.for_("g", 0, entry_count, lambda: e.st(e.add(p["given"], p["g"]), 0))

    def each():
        index = p["q"]

        def check():
            pointer_ref, token_ref, effect_ref = (e.rd(e.add(ids_at, e.add(index, d))) for d in (-1, 0, 1))
            view_type = e.rd(e.add(types_at, index))
            extent = e.table(_T.RINSTANCE, view_type)
            # S8c.11: exact only without a resource entry contract (the bootstrap checks that contract first).
            plain = e.eq(e.hd(H_RENTRY), R_NONE)
            whole = (M["RETURN_WHOLE"], token_ref, pointer_ref, effect_ref)
            _reject(e, e.both(e.eq(e.value(OSTAMP, token_ref), visit), e.ne(e.value(OCON, token_ref), visit)), *whole, renderable=plain)
            owner = e.value(OST, token_ref)
            _reject(e, e.not_(_ended(e, owner)), *whole, renderable=plain)
            _reject(e, e.both(e.eq(e.value(PSTAMP, pointer_ref), pass_id), e.eq(e.value(PK, pointer_ref), POINTER), e.eq(e.value(PST, pointer_ref), owner),
                              e.eq(e.value(POFF, pointer_ref), 0), e.eq(e.value(PWIN, pointer_ref), 0), e.eq(e.value(PEXT, pointer_ref), extent)), *whole, renderable=plain)
            _reject(e, e.both(e.eq(e.value(ESTAMP, effect_ref), visit), e.eq(e.value(EST, effect_ref), owner), e.ne(e.value(ECON, effect_ref), visit)), *whole, renderable=plain)
            e.if_(e.eq(e.table(_T.RSTATE, view_type), 1), lambda: _reject(
                e, e.ne(e.call(covers, e.value(EIV, effect_ref), 0, extent), 0), M["RETURN_INITIALIZED"], extent, e.value(EIV, effect_ref), renderable=plain))
            # Order: the next borrowed view of this type, else not a borrowed view at all.
            e.var("expected", NONE)
            e.var("borrowed", 0)

            def scan():
                g = p["g"]
                is_view = _heap_view(e, e.rd(e.add(entry_types, g)))
                e.if_(e.both(is_view, e.eq(e.add(1, g), owner)), lambda: e.set("borrowed", 1))
                e.if_(e.both(is_view, e.eq(p["expected"], NONE), e.eq(e.ld(e.add(p["given"], g)), 0), e.eq(e.rd(e.add(entry_types, g)), view_type)),
                      lambda: (e.set("expected", g), e.st(e.add(p["given"], g), 1)))

            e.for_("g", 0, entry_count, scan)
            target = e.value(PLT, pointer_ref)
            e.if_(e.eq(p["borrowed"], 0), lambda: _reject(e, e.either(
                e.eq(_has_link(e, e.value(PREC, pointer_ref)), 0), e.eq(target, owner)), M["LINK_RETURN_TARGET"], target,
                renderable=e.both(plain, _renderable(e, target))))
            expected = e.sel(e.ne(p["expected"], NONE), e.add(1, p["expected"]), NONE)
            order = (M["RETURN_ORDER"], expected, owner)
            e.if_(e.ne(p["expected"], NONE), lambda: _reject(e, e.eq(owner, e.add(1, p["expected"])), *order, renderable=e.both(plain, _renderable(e, owner))),
                  lambda: _reject(e, e.eq(p["borrowed"], 0), *order, renderable=e.both(plain, _renderable(e, owner))))

        e.if_(_heap_view(e, e.rd(e.add(types_at, index))), check)

    e.for_("q", 0, values, each)


def _block(tables, merge, empty, node, covers):
    def build(e: E):
        p = e.p
        block = p["block"]
        params_at = e.ld(_block_word(e, block, B_PARAMS))
        base, count = e.rd(params_at), e.rd(e.add(params_at, 1))
        # Arriving facts: the entry's own, then every incoming edge (this pass, else the previous one).
        lists = e.hd(H_LIST)
        e.var("n", 0)

        def arrive(record):
            e.st(e.add(lists, p["n"]), record)
            e.set("n", e.add(p["n"], 1))

        e.if_(e.eq(block, e.hd(H_ENTRY)), lambda: arrive(e.hd(H_ENTRY_FACTS)))
        incoming_at = e.ld(_block_word(e, block, B_INCOMING))

        def each_edge():
            edge = e.rd(e.add(incoming_at, e.add(1, p["k"])))

            def earlier():
                e.set_hd(H_STALE, 1)
                e.if_(e.ne(e.ld(_edge_word(e, edge, E_VALID)), 0), lambda: arrive(e.ld(_edge_word(e, edge, E_PREVIOUS))))

            e.if_(e.eq(e.ld(_edge_word(e, edge, E_PASS)), e.hd(H_PASS)), lambda: arrive(e.ld(_edge_word(e, edge, E_EXIT))), earlier)

        e.for_("k", 0, e.rd(incoming_at), each_edge)
        e.var("seeds", e.call(merge, lists, p["n"], count))
        _require(e, e.ne(p["seeds"], NONE))
        e.st(_block_word(e, block, B_SEED), p["seeds"])
        visit = e.add(e.hd(H_VISIT), 1)
        e.set_hd(H_VISIT, visit)
        pass_id = e.hd(H_PASS)

        def seed_parameter():
            value = e.add(base, p["i"])
            for word in range(POINTER_WORDS):
                e.set_value(word, value, e.ld(_slot(e, p["seeds"], p["i"], word)))
            e.set_value(PSTAMP, value, e.sel(e.ne(e.ld(_slot(e, p["seeds"], p["i"], PK)), NO_POINTER), pass_id, 0))
            owner = e.ld(_slot(e, p["seeds"], p["i"], POINTER_WORDS))
            e.set_value(OST, value, owner)
            e.set_value(OSTAMP, value, e.sel(e.ne(owner, NONE), visit, 0))
            storage = e.ld(_slot(e, p["seeds"], p["i"], POINTER_WORDS + 1))
            e.set_value(EST, value, storage)
            e.set_value(EIV, value, e.ld(_slot(e, p["seeds"], p["i"], POINTER_WORDS + 2)))
            e.set_value(ESTAMP, value, e.sel(e.ne(storage, NONE), visit, 0))

        e.for_("i", 0, count, seed_parameter)
        e.if_(e.both(e.eq(block, e.hd(H_ENTRY)), e.ne(e.hd(H_RENTRY), R_NONE)), lambda: _seed_resource_entry(e, base))

        def seed_site():
            e.st(_site_word(e, 0, p["s"]), e.ld(e.add(_sets(e, p["seeds"], 1), p["s"])))
            e.st(_site_word(e, 1, p["s"]), e.ld(e.add(_sets(e, p["seeds"], 0), p["s"])))

        e.for_("s", 0, e.hd(H_S), seed_site)
        # Nodes.
        nodes_at = e.ld(_block_word(e, block, B_NODES))
        e.var("cursor", e.add(nodes_at, 1))

        e.set_hd(H_CURBLOCK, block)

        def each_node():
            e.set_hd(H_MNODE, p["m"])
            e.set("cursor", e.call(node, p["cursor"], block))
            _require(e, e.ne(p["cursor"], NONE))

        e.for_("m", 0, e.rd(nodes_at), each_node)
        e.set_hd(H_MNODE, e.rd(nodes_at))
        # Terminator: no live storage at a return or trap; returned views; then every edge's exit facts.
        term = e.ld(_block_word(e, block, B_TERM))
        kind, values = e.rd(term), e.rd(e.add(term, 1))
        leaving = e.either(e.eq(kind, int(TerminatorKind.RETURN)), e.eq(kind, int(TerminatorKind.TRAP)))
        # S8c.8: a leak rejects when every storage either list names is one the host renders.
        e.var("leak", 0)
        e.var("plain", 1)

        def each_site():
            listed = e.either(e.ne(e.ld(_site_word(e, 0, p["s"])), 0), _ended(e, p["s"]))
            e.if_(e.both(e.ne(e.ld(_site_word(e, 0, p["s"])), 0), e.not_(_ended(e, p["s"]))), lambda: e.set("leak", 1))
            e.if_(e.both(listed, e.not_(_renderable(e, p["s"]))), lambda: e.set("plain", 0))

        e.for_("s", 0, e.hd(H_S), each_site)
        _reject(e, e.not_(e.both(leaving, e.ne(p["leak"], 0))), M["LIFETIME_LEAK"], renderable=e.ne(p["plain"], 0))
        e.if_(e.eq(kind, int(TerminatorKind.RETURN)), lambda: _return_views(e, term, values, covers))
        e.if_(e.ne(e.hd(H_RENTRY), R_NONE), lambda: _return_resource_entry(e, term, values))
        edges_count_at = e.add(e.add(term, 2), e.mul(values, 2))
        e.var("edge_at", e.add(edges_count_at, 1))

        def each_exit():
            at = p["edge_at"]
            edge, count_ = e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
            e.var("exit", e.call(empty, count_))
            _require(e, e.ne(p["exit"], NONE))

            def each_argument():
                value = e.rd(e.add(e.add(at, 3), p["j"]))
                e.if_(e.both(e.eq(e.value(PSTAMP, value), pass_id), e.ne(e.value(PK, value), NO_POINTER)), lambda: [
                    e.st(_slot(e, p["exit"], p["j"], word), e.value(word, value)) for word in range(POINTER_WORDS)])
                e.if_(e.both(e.eq(e.value(OSTAMP, value), visit), e.ne(e.value(OCON, value), visit)),
                      lambda: e.st(_slot(e, p["exit"], p["j"], POINTER_WORDS), e.value(OST, value)))

                def effect():
                    e.st(_slot(e, p["exit"], p["j"], POINTER_WORDS + 1), e.value(EST, value))
                    e.st(_slot(e, p["exit"], p["j"], POINTER_WORDS + 2), e.value(EIV, value))

                e.if_(e.both(e.eq(e.value(ESTAMP, value), visit), e.ne(e.value(ECON, value), visit)), effect)

            e.for_("j", 0, count_, each_argument)

            def each_site():
                ended = e.ld(_site_word(e, 1, p["s"]))
                e.st(e.add(_sets(e, p["exit"], 0), p["s"]), ended)
                e.st(e.add(_sets(e, p["exit"], 1), p["s"]), e.flag(e.both(e.ne(e.ld(_site_word(e, 0, p["s"])), 0), e.eq(ended, 0))))

            e.for_("s", 0, e.hd(H_S), each_site)
            e.st(_edge_word(e, edge, E_EXIT), p["exit"])
            e.st(_edge_word(e, edge, E_PASS), pass_id)
            e.set("edge_at", e.add(e.add(at, 3), count_))

        e.for_("x", 0, e.rd(edges_count_at), each_exit)
        e.give(1)
    return _function(("block",), build, tables)


def _entry_facts(e: E, empty, entry_params):
    """``_entry_heap_view_facts``: each borrowed view triple of the entry seeds its own storage (-2, index)."""
    p = e.p
    count, types = e.rd(e.add(entry_params, 1)), e.add(entry_params, 2)
    _triples_valid(e, count, types)
    e.var("entry_facts", e.call(empty, count))
    _require(e, e.ne(p["entry_facts"], NONE))
    record = p["entry_facts"]

    def each():
        index = p["i"]

        def seed():
            view_type, pointer_type = e.rd(e.add(types, index)), e.rd(e.add(types, e.sub(index, 1)))
            storage = e.add(1, index)
            element = e.table(_T.PELEM, pointer_type)
            fields = {PK: POINTER, PST: storage, PEL: element, PPERM: e.table(_T.PPERM, pointer_type), POFF: 0, PEXT: e.table(_T.RINSTANCE, view_type),
                      PALIGN: e.table(_T.PALIGN, pointer_type), PALIAS: storage, PWIN: 0, PREC: element, PLT: storage, PLR: element}
            for word, value in fields.items():
                e.st(_slot(e, record, e.sub(index, 1), word), value)
            e.st(_slot(e, record, index, POINTER_WORDS), storage)
            e.st(_slot(e, record, e.add(index, 1), POINTER_WORDS + 1), storage)
            e.st(_slot(e, record, e.add(index, 1), POINTER_WORDS + 2), _initialized_list(e, e.flag(e.eq(e.table(_T.RSTATE, view_type), 1)), e.table(_T.RINSTANCE, view_type)))

        e.if_(_heap_view(e, e.rd(e.add(types, index))), seed)

    e.for_("i", 0, count, each)
    # ``link_target`` declarations of the entry block: a borrowed view links into another borrowed view.
    base = e.rd(entry_params)
    nodes_at = e.ld(_block_word(e, e.hd(H_ENTRY), B_NODES))
    e.var("cursor", e.add(nodes_at, 1))

    def each_node():
        n = _Node(e)
        view_value, target_value = n.vid(0), n.vid(1)
        parameter = lambda value: e.both(e.eq(e.value(DEF, value), NONE), e.le(base, value), e.lt(value, e.add(base, count)))  # noqa: E731
        is_declaration = e.both(e.eq(n.op, int(Operation.LINK_TARGET)), e.eq(n.no, 2), parameter(view_value), parameter(target_value))

        def declare():
            view, target = e.sub(view_value, base), e.sub(target_value, base)
            pointers = e.both(e.eq(e.ld(_slot(e, record, view, PK)), POINTER), e.eq(e.ld(_slot(e, record, target, PK)), POINTER), e.ne(view, target))
            e.if_(pointers, lambda: (e.st(_slot(e, record, view, PLT), e.ld(_slot(e, record, target, PST))),
                                     e.st(_slot(e, record, view, PLR), e.ld(_slot(e, record, target, PREC)))))

        e.if_(is_declaration, declare)
        e.set("cursor", n.next)

    e.for_("d", 0, e.rd(nodes_at), each_node)
    return record


def _entry_contract(e: E, entry_params, entry_count):
    """A stack-owner entry: one block whose operations select a unique resource contract (``_resource_entry_contract``)."""
    p = e.p
    _require(e, e.eq(e.hd(H_B), 1))
    nodes_at = e.ld(_block_word(e, e.hd(H_ENTRY), B_NODES))
    count = e.rd(nodes_at)
    e.var("operations", e.alloc(e.add(count, 1)))
    _require(e, e.ne(p["operations"], NONE))
    e.var("walk", e.add(nodes_at, 1))
    e.var("last_base", NONE)

    def each():
        record = p["walk"]
        e.st(e.add(p["operations"], p["c"]), e.rd(record))
        e.set("last_base", e.rd(e.add(record, 4)))
        attributes = e.rd(e.add(record, 5))
        attrs_end = e.add(e.add(record, 6), attributes)
        results_at = e.add(e.add(attrs_end, 1), e.mul(e.rd(attrs_end), 2))
        aux_at = e.add(e.add(results_at, 1), e.rd(results_at))
        e.set("walk", e.add(e.add(aux_at, 1), e.rd(aux_at)))

    e.for_("c", 0, count, each)
    body = _body_shape(e, lambda k: e.ld(e.add(p["operations"], k)), count)
    kind, _permission, requires_initialized, _initializes = _resource_contract(e, e.add(entry_params, 2), entry_count, None, None, e.c(1), body)
    _require(e, e.ne(kind, R_NONE))
    e.set_hd(H_RENTRY, kind)
    e.set_hd(H_RENTRY_SEED_INIT, requires_initialized)
    e.set_hd(H_RENTRY_LAST, p["last_base"])


def _seed_resource_entry(e: E, base):
    """The entry's own storage (-1, 0) = site 0: its owner and frontier, and the pointer it lends (if any)."""
    kind = e.hd(H_RENTRY)
    visit = e.hd(H_VISIT)
    params_at = e.ld(_block_word(e, e.hd(H_ENTRY), B_PARAMS))
    types = e.add(params_at, 2)
    owner_operand = e.sel(e.eq(kind, R_PASS), 0, e.sel(e.eq(kind, R_LOAD), 1, 2))
    e.set_value(OST, e.add(base, owner_operand), 0)
    e.set_value(OSTAMP, e.add(base, owner_operand), visit)
    e.var("entry_extent", 0)

    def lend_pointer():
        pointer_type = e.rd(types)
        element = e.table(_T.PELEM, pointer_type)
        width = e.table(_T.WIDTH, element)
        _require(e, e.ne(width, 0))
        e.set("entry_extent", e.udiv(e.add(width, 7), 8))
        _set_pointer(e, base, {PK: POINTER, PST: 0, PEL: element, PPERM: e.table(_T.PPERM, pointer_type), POFF: 0, PEXT: e.p["entry_extent"],
                               PALIGN: e.table(_T.PALIGN, pointer_type), PALIAS: 0, PWIN: 0, PREC: element, PLT: NONE, PLR: NONE})

    e.if_(e.ne(kind, R_PASS), lend_pointer)
    _set_effect(e, e.add(base, e.add(owner_operand, 1)), 0, _initialized_list(e, e.flag(e.both(e.ne(kind, R_PASS), e.ne(e.hd(H_RENTRY_SEED_INIT), 0))), e.p["entry_extent"]))


def _return_resource_entry(e: E, term, values):
    """A stack-owner entry returns its live owner and frontier (and, for a mixed body, its final load first)."""
    kind = e.hd(H_RENTRY)
    visit = e.hd(H_VISIT)
    ids_at = e.add(term, 2)
    count = e.sel(e.either(e.eq(kind, R_PASS), e.eq(kind, R_STORE)), 2, 3)
    _require(e, e.both(e.eq(e.rd(term), int(TerminatorKind.RETURN)), e.eq(values, count)))
    owner_result = e.sel(e.either(e.eq(kind, R_PASS), e.eq(kind, R_STORE)), 0, 1)
    owner_ref, effect_ref = e.rd(e.add(ids_at, owner_result)), e.rd(e.add(ids_at, e.add(owner_result, 1)))
    e.if_(e.eq(kind, R_MIXED), lambda: _require(e, e.both(e.ne(e.hd(H_RENTRY_LAST), NONE), e.eq(e.rd(ids_at), e.hd(H_RENTRY_LAST)))))
    _require(e, e.both(e.eq(e.value(OSTAMP, owner_ref), visit), e.eq(e.value(OST, owner_ref), 0), e.ne(e.value(OCON, owner_ref), visit)))
    _require(e, e.both(e.eq(e.value(ESTAMP, effect_ref), visit), e.eq(e.value(EST, effect_ref), 0), e.ne(e.value(ECON, effect_ref), visit)))


def _engine(tables, block, empty, record_equal):
    """The facts engine: layout, entry facts, passes to a fixpoint, and the pointer extents."""
    def build(e: E):
        p = e.p
        e.set_hd(H_STATUS, 0)
        e.set_hd(H_REASON, 0)
        e.set_hd(H_REJECT, 0)
        e.set_hd(H_LINEAR, 0)
        _require(e, e.ne(e.rd(e.hd(H_FACTS_AT)), 0))  # no facts section: nothing to decide
        at = e.add(e.hd(H_FACTS_AT), 1)
        for field, offset in ((H_V, 0), (H_S, 1), (H_E, 2), (H_B, 3), (H_ENTRY, 4)):
            e.set_hd(field, e.rd(e.add(at, offset)))
        V, S, E_, B = e.hd(H_V), e.hd(H_S), e.hd(H_E), e.hd(H_B)
        e.set_hd(H_ORDER, e.add(at, 5))
        e.set_hd(H_KINDS, e.add(e.add(at, 5), B))
        values = e.hd(H_LIST)  # the typing function's first free word
        sites = e.add(values, e.mul(V, VALUE_FIELDS))
        blocks = e.add(sites, e.mul(S, 2))
        edges = e.add(blocks, e.mul(B, BLOCK_WORDS))
        extents = e.add(edges, e.mul(E_, EDGE_WORDS))
        lists = e.add(extents, V)
        arena = e.add(e.add(lists, E_), 1)
        _require(e, e.lt(arena, HEADER - 4096))
        for field, value in ((H_VALUES, values), (H_SITES, sites), (H_BLOCKS, blocks), (H_EDGES, edges), (H_EXTENTS, extents), (H_LIST, lists), (H_ARENA, arena)):
            e.set_hd(field, value)
        e.set_hd(H_ARENA_END, HEADER - 1)
        e.set_hd(H_VISIT, 0)
        e.set_hd(H_PASS, 0)
        e.for_("w", values, arena, lambda: e.st(p["w"], 0))
        e.for_("v", 0, V, lambda: e.set_value(DEF, p["v"], NONE))
        # Block positions, and each node result's defining record.
        e.var("cursor", e.add(e.hd(H_KINDS), S))

        def place():
            b = p["b"]
            e.st(_block_word(e, b, B_PARAMS), p["cursor"])
            parameters = e.rd(e.add(p["cursor"], 1))
            nodes_at = e.add(e.add(p["cursor"], 2), parameters)
            e.st(_block_word(e, b, B_NODES), nodes_at)
            e.set("cursor", e.add(nodes_at, 1))

            def skip_node():
                record = p["cursor"]
                attributes = e.rd(e.add(record, 5))
                attrs_end = e.add(e.add(record, 6), attributes)
                operands = e.rd(attrs_end)
                results_at = e.add(e.add(attrs_end, 1), e.mul(operands, 2))
                results = e.rd(results_at)
                result_base = e.rd(e.add(record, 4))
                e.for_("r", 0, results, lambda: e.set_value(DEF, e.add(result_base, p["r"]), record))
                aux_at = e.add(e.add(results_at, 1), results)
                e.set("cursor", e.add(e.add(aux_at, 1), e.rd(aux_at)))

            e.for_("m", 0, e.rd(nodes_at), skip_node)
            e.st(_block_word(e, b, B_TERM), p["cursor"])
            term_values = e.rd(e.add(p["cursor"], 1))
            edges_at = e.add(e.add(p["cursor"], 2), e.mul(term_values, 2))
            e.var("at", e.add(edges_at, 1))
            e.for_("x", 0, e.rd(edges_at), lambda: e.set("at", e.add(e.add(p["at"], 3), e.rd(e.add(p["at"], 2)))))
            e.st(_block_word(e, b, B_INCOMING), p["at"])
            e.set("cursor", e.add(e.add(p["at"], 1), e.rd(p["at"])))

        e.for_("b", 0, B, place)
        e.set_hd(H_CIDS, p["cursor"])
        e.set_hd(H_LINEAR, e.call(_LINEAR[0]))
        # Entry facts (borrowed views); a stack-owner entry parameter (resource entry contracts) declines.
        entry_params = e.ld(_block_word(e, e.hd(H_ENTRY), B_PARAMS))
        entry_count = e.rd(e.add(entry_params, 1))
        e.set_hd(H_RENTRY, R_NONE)
        e.var("stack_entry", 0)
        e.for_("i", 0, entry_count, lambda: e.if_(e.ne(e.table(_T.STACKOWNER, e.rd(e.add(e.add(entry_params, 2), p["i"]))), 0), lambda: e.set("stack_entry", 1)))
        e.if_(e.ne(p["stack_entry"], 0), lambda: _entry_contract(e, entry_params, entry_count))
        e.set_hd(H_ENTRY_FACTS, _entry_facts(e, empty, entry_params))
        # Passes.
        e.var("passes", 0)
        e.var("done", 0)

        def one_pass():
            e.set("passes", e.add(p["passes"], 1))
            _require(e, e.le(p["passes"], e.add(e.mul(B, 2), 2)))
            e.set_hd(H_PASS, p["passes"])
            e.set_hd(H_STALE, 0)
            e.for_("o", 0, B, lambda: _require(e, e.ne(e.call(block, e.rd(e.add(e.hd(H_ORDER), p["o"]))), NONE)))
            e.var("same", e.flag(e.ne(p["passes"], 1)))
            e.if_(e.ne(p["same"], 0), lambda: e.for_("b", 0, B, lambda: e.if_(
                e.eq(e.call(record_equal, e.ld(_block_word(e, p["b"], B_SEED)), e.ld(_block_word(e, p["b"], B_PREVIOUS))), 0), lambda: e.set("same", 0))))

            def rotate():
                e.for_("b", 0, B, lambda: e.st(_block_word(e, p["b"], B_PREVIOUS), e.ld(_block_word(e, p["b"], B_SEED))))

                def each_edge():
                    current = e.flag(e.eq(e.ld(_edge_word(e, p["d"], E_PASS)), p["passes"]))
                    e.st(_edge_word(e, p["d"], E_PREVIOUS), e.ld(_edge_word(e, p["d"], E_EXIT)))
                    e.st(_edge_word(e, p["d"], E_VALID), current)

                e.for_("d", 0, E_, each_edge)

            e.if_(e.either(e.eq(e.hd(H_STALE), 0), e.ne(p["same"], 0)), lambda: e.set("done", 1), rotate)

        e.while_(lambda: e.eq(p["done"], 0), one_pass)
        # Pointer extents of the final pass (global_pointers' pointer facts).
        e.for_("v", 0, V, lambda: e.st(e.add(extents, p["v"]), e.sel(
            e.both(e.eq(e.value(PSTAMP, p["v"]), p["passes"]), e.eq(e.value(PK, p["v"]), POINTER)), e.add(e.value(PEXT, p["v"]), 1), 0)))
        e.set_hd(H_STATUS, ACCEPTED)
        e.give(1)
    return _function((), build, tables)


# -- S6a (ADR-142): ``_verify_linear_flow`` -----------------------------------------------------------

def _linear_flow(tables):
    """1 when ``_verify_linear_flow`` accepts the graph, else 0 (the bootstrap pass then runs and diagnoses).

    Proof values (effects and resources) are consumed once: by one node of their block, or by exactly one
    continuation of their block's terminator (one per conditional edge; none after a trap for effects).  Proof
    parameters of non-entry blocks have predecessors that pass them.  ``resource.join`` is accepted when both
    pieces come from results 0 and 1 of one ``resource.split`` through transfers and transitions, and no walk
    from them passes a non-entry block parameter (where the bootstrap's origin comparison depends on its path)."""
    def build(e: E):
        p = e.p
        V, B = e.hd(H_V), e.hd(H_B)
        proof = lambda type_index: e.either(e.eq(e.table(_T.FORMB, type_index), 3), e.eq(e.table(_T.FORMB, type_index), 4))  # noqa: E731
        names = ("vtype", "vblock", "nuse", "nbad", "ttotal", "tlocal", "tedge0", "tedge1", "eargs")
        for name in names:
            e.var(name, e.alloc(e.add(V, 1)))
            e.if_(e.eq(p[name], NONE), lambda: e.give(0))
            e.for_("z", 0, V, lambda name=name: e.st(e.add(p[name], p["z"]), 0))
        e.set("eargs", e.alloc(e.add(e.hd(H_E), 1)))
        e.if_(e.eq(p["eargs"], NONE), lambda: e.give(0))
        cell = lambda name, value: e.add(p[name], value)  # noqa: E731
        bump = lambda name, value: e.st(cell(name, value), e.add(e.ld(cell(name, value)), 1))  # noqa: E731

        # Types, defining blocks, and use counts.
        def each_block():
            b = p["b"]
            params_at = e.ld(_block_word(e, b, B_PARAMS))
            base, count = e.rd(params_at), e.rd(e.add(params_at, 1))
            e.for_("q", 0, count, lambda: (e.st(cell("vtype", e.add(base, p["q"])), e.rd(e.add(e.add(params_at, 2), p["q"]))),
                                           e.st(cell("vblock", e.add(base, p["q"])), b)))
            nodes_at = e.ld(_block_word(e, b, B_NODES))
            e.var("cursor", e.add(nodes_at, 1))

            def node():
                n = _Node(e)
                e.for_("q", 0, n.nr, lambda: (e.st(cell("vtype", e.add(n.base, p["q"])), n.rtid(p["q"])), e.st(cell("vblock", e.add(n.base, p["q"])), b)))

                def use():
                    value = n.vid(p["q"])
                    bump("nuse", value)
                    e.if_(e.ne(e.ld(cell("vblock", value)), b), lambda: e.st(cell("nbad", value), 1))

                e.for_("q", 0, n.no, use)
                e.set("cursor", n.next)

            e.for_("m", 0, e.rd(nodes_at), node)
            term = e.ld(_block_word(e, b, B_TERM))
            values = e.rd(e.add(term, 1))

            def term_use(value, edge):
                bump("ttotal", value)
                e.if_(e.eq(e.ld(cell("vblock", value)), b), lambda: (
                    bump("tlocal", value),
                    e.if_(e.eq(edge, 0), lambda: bump("tedge0", value)),
                    e.if_(e.eq(edge, 1), lambda: bump("tedge1", value))))

            e.for_("q", 0, values, lambda: term_use(e.rd(e.add(e.add(term, 2), p["q"])), NONE))
            e.var("edge_at", e.add(e.add(e.add(term, 2), e.mul(values, 2)), 1))

            def edge():
                at = p["edge_at"]
                arguments = e.rd(e.add(at, 2))
                e.st(cell("eargs", e.rd(e.add(at, 1))), arguments)
                e.for_("q", 0, arguments, lambda: term_use(e.rd(e.add(e.add(at, 3), p["q"])), p["x"]))
                e.set("edge_at", e.add(e.add(at, 3), arguments))

            e.for_("x", 0, e.rd(e.sub(p["edge_at"], 1)), edge)

        e.for_("b", 0, B, each_block)
        # Proof parameters of non-entry blocks: predecessors that pass them.
        def parameters():
            b = p["b"]
            params_at = e.ld(_block_word(e, b, B_PARAMS))
            incoming = e.ld(_block_word(e, b, B_INCOMING))
            predecessors = e.rd(incoming)

            def parameter():
                def check():
                    e.if_(e.eq(predecessors, 0), lambda: e.give(0))
                    e.for_("k", 0, predecessors, lambda: e.if_(e.le(e.ld(cell("eargs", e.rd(e.add(incoming, e.add(1, p["k"]))))), p["q"]), lambda: e.give(0)))

                e.if_(proof(e.rd(e.add(e.add(params_at, 2), p["q"]))), check)

            e.for_("q", 0, e.rd(e.add(params_at, 1)), parameter)

        e.for_("b", 0, B, lambda: e.if_(e.ne(p["b"], e.hd(H_ENTRY)), parameters))

        # One continuation per proof value.
        def value():
            v = p["v"]
            type_index = e.ld(cell("vtype", v))
            uses, total, local = e.ld(cell("nuse", v)), e.ld(cell("ttotal", v)), e.ld(cell("tlocal", v))

            def check():
                e.if_(e.both(e.ne(uses, 0), e.ne(total, 0)), lambda: e.give(0))

                def by_node():
                    e.if_(e.either(e.ne(uses, 1), e.ne(e.ld(cell("nbad", v)), 0)), lambda: e.give(0))

                def by_terminator():
                    e.if_(e.ne(local, total), lambda: e.give(0))
                    kind = e.rd(e.ld(_block_word(e, e.ld(cell("vblock", v)), B_TERM)))
                    conditional = e.eq(kind, int(TerminatorKind.CONDITIONAL_BRANCH))
                    effect_trap = e.both(e.eq(kind, int(TerminatorKind.TRAP)), e.eq(e.table(_T.FORMB, type_index), 3))
                    e.if_(conditional, lambda: e.if_(e.either(e.ne(e.ld(cell("tedge0", v)), 1), e.ne(e.ld(cell("tedge1", v)), 1)), lambda: e.give(0)),
                          lambda: e.if_(effect_trap, lambda: e.if_(e.ne(local, 0), lambda: e.give(0)), lambda: e.if_(e.ne(local, 1), lambda: e.give(0))))

                e.if_(e.ne(uses, 0), by_node, by_terminator)

            e.if_(proof(type_index), check)

        e.for_("v", 0, V, value)

        # resource.join: both pieces from one split (results 0 and 1), with path-independent origins.
        def defining(value):
            return e.value(DEF, value)

        def trace(name, through_split):
            """Follow ``p[name]`` back through transfers and transitions (and splits when ``through_split``);
            returns 0 when the walk meets a non-entry block parameter."""
            e.var(f"{name}_ok", 1)
            e.var(f"{name}_go", 1)

            def step():
                record = defining(p[name])

                def parameter():
                    e.if_(e.ne(e.ld(cell("vblock", p[name])), e.hd(H_ENTRY)), lambda: e.set(f"{name}_ok", 0))
                    e.set(f"{name}_go", 0)

                def node_result():
                    operation = e.rd(record)
                    passing = e.either(e.eq(operation, int(Operation.RESOURCE_TRANSFER)), e.eq(operation, int(Operation.RESOURCE_TRANSITION)))
                    if through_split:
                        passing = e.either(passing, e.eq(operation, int(Operation.RESOURCE_SPLIT)))
                    na = e.rd(e.add(record, 5))
                    first_operand = e.rd(e.add(e.add(record, 7), na))
                    e.if_(passing, lambda: e.set(name, first_operand), lambda: e.set(f"{name}_go", 0))

                e.if_(e.eq(record, NONE), parameter, node_result)

            e.while_(lambda: e.ne(p[f"{name}_go"], 0), step)
            return p[f"{name}_ok"]

        def joins():
            b = p["b"]
            nodes_at = e.ld(_block_word(e, b, B_NODES))
            e.set("cursor", e.add(nodes_at, 1))

            def node():
                n = _Node(e)

                def join():
                    e.if_(e.lt(n.no, 2), lambda: e.give(0))
                    e.var("left", n.vid(0))
                    e.var("right", n.vid(1))
                    e.if_(e.eq(trace("left", False), 0), lambda: e.give(0))
                    e.if_(e.eq(trace("right", False), 0), lambda: e.give(0))
                    left_record, right_record = defining(p["left"]), defining(p["right"])
                    e.if_(e.either(e.eq(left_record, NONE), e.ne(left_record, right_record)), lambda: e.give(0))
                    e.if_(e.ne(e.rd(left_record), int(Operation.RESOURCE_SPLIT)), lambda: e.give(0))
                    base = e.rd(e.add(left_record, 4))
                    pieces = e.add(e.sub(p["left"], base), e.sub(p["right"], base))
                    e.if_(e.either(e.ne(pieces, 1), e.eq(p["left"], p["right"])), lambda: e.give(0))
                    na = e.rd(e.add(left_record, 5))
                    e.var("inner", e.rd(e.add(e.add(left_record, 7), na)))
                    e.if_(e.eq(trace("inner", True), 0), lambda: e.give(0))

                e.if_(e.eq(n.op, int(Operation.RESOURCE_JOIN)), join)
                e.set("cursor", n.next)

            e.for_("m", 0, e.rd(nodes_at), node)

        e.var("cursor", 0)
        e.for_("b", 0, B, joins)
        e.give(1)
    return _function((), build, tables)


def facts_storages(blocks, entry):
    """S8c.8: the bootstrap's storage tuple for each engine site, in ``_facts_section``'s order (None: a call result)."""
    from xax_compiler import Operation as Op

    storages = [(-1, 0), *((-2, index) for index in range(len(blocks[entry].parameters)))]
    for block_index, block in enumerate(blocks):
        for node_index, node in enumerate(block.nodes):
            if node.operation in (Op.STACK_ALLOC, Op.HEAP_VIEW, Op.CALL_FOREIGN):
                storages.append((block_index, node_index))
            elif node.operation in (Op.CALL_DIRECT, Op.CALL_GROUP_MEMBER):
                storages.extend([None] * len(node.results))
    return storages


_CONTRACTS = {
    Operation.LOAD_BITS_LE: (2, 2, 2), Operation.STORE_BITS_LE: (3, 1, 2), Operation.ADDRESS_OFFSET: (1, 1, 1),
    Operation.STACK_END: (2, 0, 0), Operation.STACK_ALLOC: (0, 3, 2),
    Operation.CHECKED_LOAD_BITS_LE: (3, 2, 2), Operation.CHECKED_STORE_BITS_LE: (4, 1, 2), Operation.POINTER_REBASE: (2, 1, 1),
}


def memory_diagnostic(site: int, payload, operation, refs, storages, read, cids=()):
    """S8c.8: the bootstrap's ``(code, rule, expected, actual)`` for an engine rejection record.  Rendering only: the
    engine decided the check and its values; ``refs``/``storages`` map its value and site ids to the bootstrap's
    ``ValueRef``s and storage tuples, and ``read(word)`` reads its output view."""
    name = MEMORY_SITES[site - 1]
    x, y, z, w = payload[:4]
    h = lambda index: cids[index].hex()  # noqa: E731
    intervals = lambda at: tuple((read(at + 1 + 2 * k), read(at + 2 + 2 * k)) for k in range(read(at)))  # noqa: E731
    ref = lambda value: [refs[value].block, refs[value].index, refs[value].result]  # noqa: E731
    if name == "PROVENANCE_PROVEN":
        return "XAX.MEMORY.PROVENANCE", "MEMORY-PROVENANCE-PROVEN", "local stack pointer", ref(x)
    if name == "LIFETIME_LIVE":
        return "XAX.MEMORY.USE_AFTER_LIFETIME", "MEMORY-LIFETIME-LIVE", "live storage", storages[x]
    if name == "OWNER_LIVE":
        return "XAX.MEMORY.USE_AFTER_LIFETIME", "MEMORY-LIFETIME-LIVE", "live storage owner", storages[x]
    if name == "OP_CONTRACT":
        return "XAX.MEMORY.CONTRACT", "MEMORY-OP-CONTRACT", _CONTRACTS[Operation(operation)], (x, y, z)
    if name == "ACCESS_SIZE":
        return "XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE", x, y
    if name == "POINTER_ELEMENT_SIZE":
        return "XAX.MEMORY.ACCESS_SIZE", "MEMORY-POINTER-ELEMENT-SIZE", [4, 8], x
    if name == "ALIGNMENT":
        return "XAX.MEMORY.ALIGNMENT", "MEMORY-ALIGNMENT", f"aligned to {x}", y
    if name == "BOUNDS":
        return "XAX.MEMORY.BOUNDS", "MEMORY-BOUNDS", f"at least {x} bytes", y
    if name in ("READ_PERMISSION", "WRITE_PERMISSION"):
        kind = "read" if name == "READ_PERMISSION" else "write"
        return "XAX.MEMORY.PERMISSION", f"MEMORY-{kind.upper()}-PERMISSION", kind, x
    if name == "EFFECT_PROVEN":
        return "XAX.MEMORY.EFFECT", "MEMORY-EFFECT-PROVEN", "local memory frontier", ref(x)
    if name == "EFFECT_LINEAR":
        code = "XAX.MEMORY.USE_AFTER_LIFETIME" if x == Operation.STACK_END else "XAX.MEMORY.EFFECT_FORK"
        return code, "MEMORY-EFFECT-LINEAR", "one consumer", Operation(y).name
    if name == "EFFECT_PROVENANCE":
        return "XAX.MEMORY.PROVENANCE", "MEMORY-EFFECT-PROVENANCE", storages[x], storages[y]
    if name == "INITIALIZED":
        return "XAX.MEMORY.UNINITIALIZED", "MEMORY-INITIALIZED", [x, x + y + z], intervals(w)
    if name == "LOAD_TYPE":
        return "XAX.MEMORY.VALUE_TYPE", "MEMORY-LOAD-TYPE", [h(x), h(y)], [h(z), h(w)]
    if name == "STORE_TYPE":
        return "XAX.MEMORY.VALUE_TYPE", "MEMORY-STORE-TYPE", h(x), h(y)
    if name == "STORE_EFFECT_TYPE":
        return "XAX.MEMORY.EFFECT_TYPE", "MEMORY-EFFECT-TYPE", "one matching effect<memory> result", [h(x)]
    if name == "CHECKED_ALIGNMENT":
        return "XAX.MEMORY.CHECKED_ALIGNMENT", "MEMORY-CHECKED-ALIGNMENT-BOOTSTRAP", 1, x
    if name == "CHECKED_OFFSET":
        return "XAX.MEMORY.CHECKED_OFFSET", "MEMORY-CHECKED-OFFSET-BITS", 32, x
    if name == "CHECKED_LOAD_TYPE":
        return "XAX.MEMORY.VALUE_TYPE", "MEMORY-CHECKED-LOAD-TYPE", h(x), h(y)
    if name == "CHECKED_STORE_TYPE":
        return "XAX.MEMORY.VALUE_TYPE", "MEMORY-CHECKED-STORE-TYPE", h(x), h(y)
    if name == "CHECKED_EFFECT_TYPE":
        return "XAX.MEMORY.EFFECT_TYPE", "MEMORY-EFFECT-TYPE", "matching effect<memory> continuation", [h(item) for item in (y, z)[:x]]
    if name == "REBASE_ADDRESS_WIDTH":
        return "XAX.MEMORY.REBASE", "MEMORY-REBASE-ADDRESS-WIDTH", [32, 64], x
    if name == "REBASE_AUTHORITY":
        return "XAX.MEMORY.REBASE", "MEMORY-REBASE-NO-AUTHORITY-GAIN", [h(x), y], [h(z), w]
    if name == "REBASE_EXTENT":
        return "XAX.MEMORY.BOUNDS", "MEMORY-REBASE-EXTENT", f"1..{x}", y
    if name == "REBASE_ALIGNMENT":
        return "XAX.MEMORY.ALIGNMENT", "MEMORY-REBASE-ALIGNMENT", f"<= {x}", y
    if name == "RETURN_WHOLE":
        return "XAX.MEMORY.HEAP_VIEW", "HEAP-VIEW-RETURN-WHOLE", "live base pointer, view, and matching effect", [refs[x].index, refs[y].index, refs[z].index]
    if name == "RETURN_INITIALIZED":
        return "XAX.MEMORY.UNINITIALIZED", "HEAP-VIEW-RETURN-INITIALIZED", [0, x], intervals(y)
    if name == "LINK_RETURN_TARGET":
        return "XAX.MEMORY.LINK", "MEMORY-LINK-RETURN-TARGET", "a new view returned must link into itself", storages[x]
    if name == "RETURN_ORDER":
        return "XAX.MEMORY.HEAP_VIEW", "HEAP-VIEW-RETURN-ORDER", None if x == NONE else storages[x], storages[y]
    if name == "CHECKED_INITIALIZED":
        return "XAX.MEMORY.UNINITIALIZED", "MEMORY-CHECKED-LOAD-INITIALIZED-VIEW", [x, y], intervals(z)
    if name == "ADDRESS_BOUNDS":
        return "XAX.MEMORY.BOUNDS", "MEMORY-ADDRESS-BOUNDS", f"<= {x}", y
    if name == "LIFETIME_LEAK":
        sites, count = read(HEADER + H_SITES), read(HEADER + H_S)
        listed = lambda which: sorted(storages[k] for k in range(count) if read(sites + count * which + k))  # noqa: E731
        return "XAX.MEMORY.LIFETIME_LEAK", "MEMORY-LIFETIME-EXPLICIT-END", listed(0), listed(1)
    if name == "OWNER_PROVEN":
        return "XAX.MEMORY.OWNER", "MEMORY-OWNER-PROVEN", "local stack owner", ref(x)
    if name == "ALLOCATION_ALIGNMENT":
        return "XAX.MEMORY.ALIGNMENT", "MEMORY-ALIGNMENT", f"<= {x}", y
    raise ValueError(f"unknown memory rejection site {site}")


def build_engine():
    """The facts engine and its helpers: ``(engine function, every object)``."""
    DECLINE_SITES.clear()  # decline codes are baked into the store: number them per build, not per process
    tables = None
    objects: list = []

    def add(made):
        function, items = made
        objects.extend(items)
        return function

    covers = add(_covers(tables))
    insert = add(_insert(tables))
    _COVERS[:] = [covers]
    _INSERT[:] = [insert]
    _LAYOUT[:] = [add(_layout(tables))]
    _HAS_LINK[:] = [add(_has_link_function(tables))]
    _DEPENDENTS[:] = [add(_dependents_function(tables))]
    _WINDOW[:] = [add(_window_function(tables, covers))]
    _LINEAR[:] = [add(_linear_flow(tables))]
    intersect = add(_intersect(tables, insert))
    list_equal = add(_list_equal(tables))
    empty = add(_empty_record(tables))
    merge = add(_merge(tables, empty, intersect))
    record_equal = add(_record_equal(tables, list_equal))
    end_views = add(_end_views(tables))
    declaration = add(_foreign_declaration(tables))
    interface = add(_interface(tables))
    handlers = {
        Operation.STACK_ALLOC: add(_stack_alloc(tables)),
        Operation.STACK_END: add(_stack_end(tables)),
        Operation.ADDRESS_OFFSET: add(_address_offset(tables)),
        Operation.LOAD_BITS_LE: add(_load(tables, covers)),
        Operation.STORE_BITS_LE: add(_store(tables, insert)),
        Operation.POINTER_CAST: add(_pointer_cast(tables)),
        Operation.CALL_DIRECT: add(_call_direct(tables, covers)),
        Operation.CHECKED_LOAD_BITS_LE: add(_checked(tables, covers, True)),
        Operation.CHECKED_STORE_BITS_LE: add(_checked(tables, covers, False)),
        Operation.HEAP_VIEW: add(_heap_view_node(tables)),
        Operation.POINTER_ADDRESS: add(_pointer_address(tables)),
        Operation.POINTER_REBASE: add(_pointer_rebase(tables)),
        Operation.CALL_FOREIGN: add(_call_foreign(tables, declaration, end_views)),
        Operation.CALL_GROUP_MEMBER: add(_call_group(tables, covers)),
        Operation.ATOMIC_FENCE: add(_atomic_fence(tables)),
        Operation.FUNCTION_ADDRESS: add(_function_address(tables, interface)),
        Operation.CALL_INDIRECT: add(_call_indirect(tables)),
        Operation.RAW_LOAD_BITS_LE: add(_raw_load(tables, covers)),
        **{operation: add(_atomic(tables, covers, insert, operation)) for operation in ATOMIC_SHAPES},
    }
    from xax_selfhost_target import _target_op

    handlers[Operation.TARGET_OP] = add(_target_op(tables))
    handlers[Operation.LINK_MAKE] = add(_link_make(tables))
    handlers[Operation.LINK_FOLLOW] = add(_link_follow(tables))
    handlers[Operation.LINK_TARGET] = add(_link_target(tables))
    handlers[Operation.CONSTANT] = add(_constant(tables))
    node = add(_node_dispatch(tables, handlers, end_views))
    block = add(_block(tables, merge, empty, node, covers))
    engine = add(_engine(tables, block, empty, record_equal))
    return engine, tuple(objects)
