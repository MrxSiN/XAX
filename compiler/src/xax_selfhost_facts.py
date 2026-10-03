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
from xax_selfhost_cfg import IN_POINTER, IN_VIEW, IN_WORDS, MEM, OUT_POINTER, OUT_VIEW, OUT_WORDS
from xax_structured import B1, B32, B64, Proc

NONE = 0xFFFFFFFF
VIEWS = ("ip", "iv", "im", "op", "ov", "om")
VIEW_TYPES = (IN_POINTER, IN_VIEW, MEM, OUT_POINTER, OUT_VIEW, MEM)
# Header words at the end of the output view.
HEADER = OUT_WORDS - 64
(H_STATUS, H_FACTS_AT, H_V, H_S, H_E, H_B, H_ENTRY, H_NODES, H_VALUES, H_SITES, H_BLOCKS, H_EDGES, H_ARENA, H_ARENA_END,
 H_VISIT, H_PASS, H_ORDER, H_EXTENTS, H_STALE, H_COUNT, H_TABLE, H_LIST, H_KINDS, H_ENTRY_FACTS) = range(24)
ACCEPTED = 1
# Arguments past the second travel in header words (the native ABI takes four machine arguments,
# two of which are the view pointers); a callee reads them before anything else.
H_ARG = 32
REGISTER_ARGUMENTS = 2
# Per-value fields (each an array of V words).
(PK, PST, PEL, PPERM, POFF, PEXT, PALIGN, PALIAS, PWIN, PREC, PLT, PLR, PSTAMP, OST, OSTAMP, EST, EIV, ESTAMP, ECON, OCON) = range(20)
VALUE_FIELDS = 20
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
        """Declare ``name`` (or reassign it when already in scope)."""
        if name in self.p.types:
            self.p[name] = self.v(value)
        else:
            self.p.let(name, B64, self.v(value))

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
        self.next = e.add(self.rt_at, self.nr)

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
    e.if_(e.not_(condition), lambda: _decline(e))


def _pointer(e: E, value_id):
    """``pointer()``: a live local pointer fact (declines otherwise)."""
    p = e.p
    _require(e, e.both(e.eq(e.value(PSTAMP, value_id), e.hd(H_PASS)), e.eq(e.value(PK, value_id), POINTER)))
    _require(e, e.not_(_ended(e, e.value(PST, value_id))))


def _consume_effect(e: E, value_id, storage):
    """``consume_effect()``: this block's unconsumed frontier of ``storage``; returns its intervals."""
    visit = e.hd(H_VISIT)
    _require(e, e.both(e.eq(e.value(ESTAMP, value_id), visit), e.ne(e.value(ECON, value_id), visit), e.eq(e.value(EST, value_id), storage)))
    e.set_value(ECON, value_id, visit)
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


def _access(e: E, value_id, size, alignment):
    element, extent = e.value(PEL, value_id), e.value(PEXT, value_id)
    _require(e, e.eq(size, _element_size(e, element, size)))
    _require(e, e.both(e.ne(size, 0), e.power_of_two(alignment), e.le(alignment, e.value(PALIGN, value_id)), e.eq(e.urem(e.value(POFF, value_id), alignment), 0)))
    _require(e, e.le(size, extent))


def _not_record(e: E, element):
    """Stage S4d.2b models non-record elements only (records, links: later stages)."""
    _require(e, e.ne(e.table(_T.AGGREGATE, element), 8))


def _stack_alloc(tables):
    def build(e: E):
        n = _Node(e)
        _require(e, n.shape(0, 3, 2))
        extent, alignment = n.attr(0), n.attr(1)
        pointer_type = n.rtid(0)
        _require(e, e.both(e.ne(extent, 0), e.power_of_two(alignment), e.ne(e.table(_T.PTR, pointer_type), 0), e.eq(e.table(_T.PSPACE, pointer_type), 1)))
        element, permission = e.table(_T.PELEM, pointer_type), e.table(_T.PPERM, pointer_type)
        _require(e, e.le(e.table(_T.PALIGN, pointer_type), alignment))
        _require(e, e.both(e.ne(e.table(_T.STACKOWNER, n.rtid(1)), 0), e.ne(e.table(_T.MEMEFFECT, n.rtid(2)), 0)))
        _require(e, e.eq(e.table(_T.LINK, element), 0))
        _not_record(e, element)
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
        _require(e, n.shape(2, 0, 0))
        owner = n.vid(0)
        _require(e, e.both(e.eq(e.value(OSTAMP, owner), visit), e.ne(e.value(OCON, owner), visit)))
        storage = e.value(OST, owner)
        _require(e, e.not_(_ended(e, storage)))
        _require(e, e.both(e.ne(e.table(_T.STACKOWNER, n.tid(0)), 0), e.ne(e.table(_T.MEMEFFECT, n.tid(1)), 0)))
        _consume_effect(e, n.vid(1), storage)
        e.set_value(OCON, owner, visit)
        e.st(_site_word(e, 1, storage), 1)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _address_offset(tables):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source)
        _require(e, n.shape(1, 1, 1))
        offset, extent = n.attr(0), e.value(PEXT, source)
        _require(e, e.le(offset, extent))
        result_type = n.rtid(0)
        _require(e, e.ne(e.table(_T.PTR, result_type), 0))
        element, permission, alignment = e.table(_T.PELEM, result_type), e.table(_T.PPERM, result_type), e.table(_T.PALIGN, result_type)
        source_alignment = e.value(PALIGN, source)
        low = e.and_(offset, e.sub(0, offset))  # the largest power of two dividing offset
        actual = e.sel(e.eq(offset, 0), source_alignment, e.sel(e.lt(low, source_alignment), low, source_alignment))
        _not_record(e, e.value(PEL, source))
        _require(e, e.eq(element, e.value(PEL, source)))
        source_permission = e.value(PPERM, source)
        _require(e, e.eq(e.and_(permission, source_permission), permission))
        _require(e, e.le(alignment, actual))
        fields = {word: e.value(word, source) for word in range(POINTER_WORDS)}
        fields.update({PEL: element, PPERM: permission, POFF: e.add(e.value(POFF, source), offset), PEXT: e.sub(extent, offset), PALIGN: actual})
        _set_pointer(e, n.base, fields)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _load(tables, covers):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source)
        _require(e, n.shape(2, 2, 2))
        size = n.attr(0)
        _access(e, source, size, n.attr(1))
        _require(e, e.ne(e.and_(e.value(PPERM, source), int(Permission.READ)), 0))
        storage = e.value(PST, source)
        intervals = _consume_effect(e, n.vid(1), storage)
        _require(e, e.both(e.eq(n.rtid(0), e.value(PEL, source)), e.ne(e.table(_T.MEMEFFECT, n.tid(1)), 0), e.eq(n.rtid(1), n.tid(1))))
        _require(e, e.eq(e.value(PWIN, source), 0))  # windows: a later stage
        start = e.value(POFF, source)
        _require(e, e.ne(e.call(covers, intervals, start, e.add(start, size)), 0))
        _require(e, e.eq(e.table(_T.LINK, e.value(PEL, source)), 0))
        _set_effect(e, e.add(n.base, 1), storage, intervals)
        e.give(n.next)
    return _function(("cursor", "block"), build, tables)


def _store(tables, insert):
    def build(e: E):
        n = _Node(e)
        source = n.vid(0)
        _pointer(e, source)
        _require(e, n.shape(3, 1, 2))
        size = n.attr(0)
        _access(e, source, size, n.attr(1))
        _require(e, e.ne(e.and_(e.value(PPERM, source), int(Permission.WRITE)), 0))
        _require(e, e.eq(n.tid(1), e.value(PEL, source)))
        _require(e, e.eq(e.table(_T.LINK, e.value(PEL, source)), 0))
        stored = n.vid(1)
        _require(e, e.not_(e.both(e.eq(e.value(PSTAMP, stored), e.hd(H_PASS)), e.eq(e.value(PK, stored), POINTER))))
        storage = e.value(PST, source)
        intervals = _consume_effect(e, n.vid(2), storage)
        _require(e, e.both(e.ne(e.table(_T.MEMEFFECT, n.tid(2)), 0), e.eq(n.rtid(0), n.tid(2))))
        _require(e, e.eq(e.value(PWIN, source), 0))
        start = e.value(POFF, source)
        merged = e.call(insert, intervals, start, e.add(start, size))
        _require(e, e.ne(merged, NONE))
        _set_effect(e, n.base, storage, merged)
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


def _call_direct(tables):
    """A direct call's fact effects: a memory frontier passed through (``frontier_only``); stack resources decline."""
    def build(e: E):
        p = e.p
        n = _Node(e)
        e.var("resource", 0)
        e.var("stack", 0)

        def scan(count, at):
            def each():
                cid = e.rd(e.add(at, p["j"]))
                e.if_(e.either(e.ne(e.table(_T.STACKOWNER, cid), 0), e.ne(e.table(_T.MEMEFFECT, cid), 0)), lambda: e.set("resource", 1))
                e.if_(e.either(e.ne(e.table(_T.STACKOWNER, cid), 0), e.ne(e.table(_T.PTR, cid), 0)), lambda: e.set("stack", 1))
            e.for_("j", 0, count, each)

        scan(n.no, n.tids_at)
        scan(n.nr, n.rt_at)
        _require(e, e.either(e.eq(p["resource"], 0), e.eq(p["stack"], 0)))  # resource contracts: a later stage

        def frontier():
            visit = e.hd(H_VISIT)

            def each():
                value = e.rd(e.add(n.vids_at, p["j"]))

                def consume():
                    _require(e, e.ne(e.value(ECON, value), visit))
                    e.set_value(ECON, value, visit)

                e.if_(e.both(e.ne(e.table(_T.MEMEFFECT, e.rd(e.add(n.tids_at, p["j"]))), 0), e.eq(e.value(ESTAMP, value), visit)), consume)

            e.for_("j", 0, n.no, each)

        e.if_(e.ne(p["resource"], 0), frontier)
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
TYPING_COVERED_CALLS = (Operation.CALL_DIRECT, Operation.CONSTANT)


def _block_word(e: E, block, word: int):
    return e.add(e.add(e.hd(H_BLOCKS), e.mul(block, BLOCK_WORDS)), word)


def _edge_word(e: E, edge, word: int):
    return e.add(e.add(e.hd(H_EDGES), e.mul(edge, EDGE_WORDS)), word)


def _node_dispatch(tables, handlers):
    """One node: typing proven where the typing function covers it, then its fact effects."""
    def build(e: E):
        p = e.p
        cursor = p["cursor"]
        operation, key = e.rd(cursor), e.rd(e.add(cursor, 1))
        # A node the typing function covers must be proven by it.
        e.if_(e.ne(key, NONE), lambda: _require(e, e.eq(e.ld(e.add(2, key)), _T.PROVEN)))
        for code, handler in handlers.items():
            e.if_(e.eq(operation, int(code)), lambda handler=handler: e.give(e.call(handler, cursor, p["block"])))
        # Any other node: modelled only when typing covers it.  It has no fact effects here:
        # a constant's null-link fact cannot arise, because graphs with links decline.
        _require(e, e.ne(key, NONE))
        e.give(_Node(e).next)
    return _function(("cursor", "block"), build, tables)


def _block(tables, merge, empty, node):
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

        def seed_site():
            e.st(_site_word(e, 0, p["s"]), e.ld(e.add(_sets(e, p["seeds"], 1), p["s"])))
            e.st(_site_word(e, 1, p["s"]), e.ld(e.add(_sets(e, p["seeds"], 0), p["s"])))

        e.for_("s", 0, e.hd(H_S), seed_site)
        # Nodes.
        nodes_at = e.ld(_block_word(e, block, B_NODES))
        e.var("cursor", e.add(nodes_at, 1))

        def each_node():
            e.set("cursor", e.call(node, p["cursor"], block))
            _require(e, e.ne(p["cursor"], NONE))

        e.for_("m", 0, e.rd(nodes_at), each_node)
        # Terminator: no live storage at a return or trap; then the exit facts of every edge.
        term = e.ld(_block_word(e, block, B_TERM))
        kind, values = e.rd(term), e.rd(e.add(term, 1))
        leaving = e.either(e.eq(kind, int(TerminatorKind.RETURN)), e.eq(kind, int(TerminatorKind.TRAP)))
        e.for_("s", 0, e.hd(H_S), lambda: _require(e, e.not_(e.both(leaving, e.ne(e.ld(_site_word(e, 0, p["s"])), 0), e.not_(_ended(e, p["s"]))))))
        e.var("edge_at", e.add(e.add(term, 3), values))

        def each_exit():
            at = p["edge_at"]
            edge, count_ = e.rd(e.add(at, 1)), e.rd(e.add(at, 2))
            e.var("exit", e.call(empty, count_))
            _require(e, e.ne(p["exit"], NONE))

            def each_argument():
                value = e.rd(e.add(e.add(at, 3), p["j"]))
                e.if_(e.both(e.eq(e.value(PSTAMP, value), pass_id), e.ne(e.value(PK, value), NO_POINTER)), lambda: [
                    e.st(_slot(e, p["exit"], p["j"], word), e.value(word, value)) for word in range(POINTER_WORDS)])
                e.if_(e.both(e.eq(e.value(OSTAMP, value), e.hd(H_VISIT)), e.ne(e.value(OCON, value), e.hd(H_VISIT))),
                      lambda: e.st(_slot(e, p["exit"], p["j"], POINTER_WORDS), e.value(OST, value)))

                def effect():
                    e.st(_slot(e, p["exit"], p["j"], POINTER_WORDS + 1), e.value(EST, value))
                    e.st(_slot(e, p["exit"], p["j"], POINTER_WORDS + 2), e.value(EIV, value))

                e.if_(e.both(e.eq(e.value(ESTAMP, value), e.hd(H_VISIT)), e.ne(e.value(ECON, value), e.hd(H_VISIT))), effect)

            e.for_("j", 0, count_, each_argument)

            def each_site():
                ended = e.ld(_site_word(e, 1, p["s"]))
                e.st(e.add(_sets(e, p["exit"], 0), p["s"]), ended)
                e.st(e.add(_sets(e, p["exit"], 1), p["s"]), e.flag(e.both(e.ne(e.ld(_site_word(e, 0, p["s"])), 0), e.eq(ended, 0))))

            e.for_("s", 0, e.hd(H_S), each_site)
            e.st(_edge_word(e, edge, E_EXIT), p["exit"])
            e.st(_edge_word(e, edge, E_PASS), pass_id)
            e.set("edge_at", e.add(e.add(at, 3), count_))

        e.for_("x", 0, e.rd(e.add(e.add(term, 2), values)), each_exit)
        e.give(1)
    return _function(("block",), build, tables)


def _engine(tables, block, empty, record_equal):
    """The facts engine: layout, entry facts, passes to a fixpoint, and the pointer extents."""
    def build(e: E):
        p = e.p
        e.set_hd(H_STATUS, 0)
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
        # Stage S4d.2b declines graphs with links, heap views, heap owners, or a stack-owner entry.
        def each_type():
            t = p["t"]
            _require(e, e.eq(e.table(_T.LINK, t), 0))
            _require(e, e.not_(e.both(e.ne(e.table(_T.RESOURCE, t), 0), e.either(e.eq(e.table(_T.RKIND, t), 0x100), e.eq(e.table(_T.RKIND, t), 0x101)))))
        e.for_("t", 0, e.hd(H_COUNT), each_type)
        # Block positions.
        e.var("cursor", e.add(e.hd(H_KINDS), S))

        def place():
            b = p["b"]
            e.st(_block_word(e, b, B_PARAMS), p["cursor"])
            parameters = e.rd(e.add(p["cursor"], 1))
            nodes_at = e.add(e.add(p["cursor"], 2), parameters)
            e.st(_block_word(e, b, B_NODES), nodes_at)
            e.set("cursor", e.add(nodes_at, 1))

            def skip_node():
                e.p.let("skip", B64, e.rd(e.add(p["cursor"], 5)))
                attrs_end = e.add(e.add(p["cursor"], 6), p["skip"])
                operands = e.rd(attrs_end)
                results_at = e.add(e.add(attrs_end, 1), e.mul(operands, 2))
                e.set("cursor", e.add(e.add(results_at, 1), e.rd(results_at)))

            e.for_("m", 0, e.rd(nodes_at), skip_node)
            e.st(_block_word(e, b, B_TERM), p["cursor"])
            term_values = e.rd(e.add(p["cursor"], 1))
            e.var("at", e.add(e.add(p["cursor"], 3), term_values))
            e.for_("x", 0, e.rd(e.add(e.add(p["cursor"], 2), term_values)), lambda: e.set("at", e.add(e.add(p["at"], 3), e.rd(e.add(p["at"], 2)))))
            e.st(_block_word(e, b, B_INCOMING), p["at"])
            e.set("cursor", e.add(e.add(p["at"], 1), e.rd(p["at"])))

        e.for_("b", 0, B, place)
        # Entry facts (stage S4d.2b: no borrowed views) and no stack-owner entry parameter.
        entry_params = e.ld(_block_word(e, e.hd(H_ENTRY), B_PARAMS))
        entry_count = e.rd(e.add(entry_params, 1))
        e.for_("i", 0, entry_count, lambda: _require(e, e.eq(e.table(_T.STACKOWNER, e.rd(e.add(e.add(entry_params, 2), p["i"]))), 0)))
        e.var("entry_facts", e.call(empty, entry_count))
        _require(e, e.ne(p["entry_facts"], NONE))
        e.set_hd(H_ENTRY_FACTS, p["entry_facts"])
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


def build_engine():
    """The facts engine and its helpers: ``(engine function, every object)``."""
    tables = None
    objects: list = []

    def add(made):
        function, items = made
        objects.extend(items)
        return function

    covers = add(_covers(tables))
    insert = add(_insert(tables))
    intersect = add(_intersect(tables, insert))
    list_equal = add(_list_equal(tables))
    empty = add(_empty_record(tables))
    merge = add(_merge(tables, empty, intersect))
    record_equal = add(_record_equal(tables, list_equal))
    handlers = {
        Operation.STACK_ALLOC: add(_stack_alloc(tables)),
        Operation.STACK_END: add(_stack_end(tables)),
        Operation.ADDRESS_OFFSET: add(_address_offset(tables)),
        Operation.LOAD_BITS_LE: add(_load(tables, covers)),
        Operation.STORE_BITS_LE: add(_store(tables, insert)),
        Operation.POINTER_CAST: add(_pointer_cast(tables)),
        Operation.CALL_DIRECT: add(_call_direct(tables)),
    }
    node = add(_node_dispatch(tables, handlers))
    block = add(_block(tables, merge, empty, node))
    engine = add(_engine(tables, block, empty, record_equal))
    return engine, tuple(objects)
