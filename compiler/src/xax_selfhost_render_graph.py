"""Self-hosting step S15b.3 (ADR-292): a graph's rejection in ``_parse_graph``'s order, decided and rendered by XAX.

The typing program (with its facts engine) makes every decision ``_parse_graph`` raises once the graph's syntax, glue,
and control flow hold: each covered node's typing verdict and rejection record, each terminator's, the facts engine's
memory rejection (its pass, block, and node), and the linear-flow verdict.  The host applied the order: the fact passes
over the blocks in reverse postorder, a memory rejection at its node, a node's typing rejection, a terminator's, a later
pass's memory rejection, and linear flow last (with every pass skipped when the engine, or the typing program alone,
proves the graph).  The typing program's last phase (``outcome``) now applies that order itself and writes the outcome
at ``OUTCOME_AT`` of its output view:

* ``G_ACCEPT``: ``_parse_graph`` accepts;
* ``G_REJECT``: the first rejection, as a diagnostic record (``xax_selfhost_diagnostics``) from ``RECORD_AT``: its code,
  its entity when it is not the graph (``O_ENTITY``), then its rule, expected, and actual; the general compiler driver
  writes the graph's CID as the entity otherwise;
* ``G_DECLINE``: the bootstrap would decide the next check (a node or terminator the typing program did not cover, an
  entry that holds a stack owner, an engine that declined, a record this phase does not render): no claim.

Rendered: every typing site (``xax_selfhost_typing._render_sites``), the bits/float decoders' rejections of a node's
type (``cross_diagnostic``), the terminator records (``GRAPH-CBR-CONDITION``, ``GRAPH-BLOCK-PARAMETERS``), an operation
code outside the vocabulary, the linear-flow rejections (``_linear_diagnostic``), and (S15b.3b, ADR-293) the facts
engine's memory rejections (``memory_diagnostic``) except those that quote a declaration's decoded body (foreign, lend,
target-operation, and bounded indirect-call contracts) or a stack-owner entry's contract: those decline.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
import xax_selfhost_render as R
import xax_selfhost_typing as T
from xax_compiler import (
    _ATOMIC_ORDERS, CHECKED_BYTE_VIEW_WIDTHS, AtomicFamily, AtomicOrder, AtomicRmwKind, AtomicScope, CompareExchangeStrength, FloatCompare,
    IntCompare, Kind, OpaqueKind, Operation, TargetValueConstraintKind, TerminatorKind,
)
from xax_selfhost_facts import (
    H_CIDS, H_FACTS_AT, H_LA, H_LB, H_LINEAR, H_LREJ, H_RBLOCK, H_REJECT, H_RNODE, H_RPASS, H_RPAY, H_S, H_SITES, H_STATUS, HEADER, M,
    MEMORY_SITES, ACCEPTED, NONE, _CONTRACTS, E, _function,
)

OUTCOME_AT = T.DIAGNOSTICS - (1 << 23)
O_STATUS, O_CURSOR, O_ENTITY, O_BAD = range(4)
# S15b.3c (ADR-295): where in the first pass the outcome was decided (``order position << 32 | node``; a terminator's
# node is the block's node count; ``POS_LATE`` after the first pass), and the mode the driver sets before the typing
# program runs: 1 for a graph trimmed at its invalid uses, whose first pass the bootstrap runs node by node.
O_POS, O_MODE = 4, 5
POS_LATE = 1 << 63
RECORD_AT, RECORD_END = OUTCOME_AT + 8, OUTCOME_AT + (1 << 21)
ARRAYS_AT, ARRAYS_END = OUTCOME_AT + (1 << 21), OUTCOME_AT + (6 << 20)  # the shape's arrays (below the terminator records)
G_ACCEPT, G_REJECT, G_DECLINE = 0, 1, 2
ENTITY_GRAPH, ENTITY_WRITTEN = 0, 1
ENGINE_OPERATIONS = tuple(int(item) for item in Operation if item not in T.COVERED)  # checked by the facts engine's rules
_FN: dict = {}


class TypeTable:
    """The typing stream's type entries: their count and CIDs (the facts section's little-endian CID words)."""

    def __init__(self, e: E):
        self.e = e

    def objects(self):
        return self.e.rd(0)

    def cid_word(self, t, k):
        e = self.e
        word = e.rd(e.add(e.add(e.hd(H_CIDS), e.mul(t, 4)), k))
        swapped = e.c(0)
        for j in range(8):
            swapped = e.add(swapped, e.mul(e.and_(e.udiv(word, 1 << (8 * j)), 255), 1 << (8 * (7 - j))))
        return swapped

    def body(self, t):
        e = self.e
        return e.add(e.ld(e.add(e.add(T.TABLE, e.mul(e.rd(0), T.POSITION)), t)), 3)


def _field(e: E, table: int, owner):
    """The typing program's per-type table word (``NativeTyping.rejection``'s ``field``)."""
    return e.ld(e.add(e.add(T.TABLE, e.mul(e.rd(0), table)), owner))


class _Context:
    """``_Rendering``: a record's quoted values, written as values."""

    def __init__(self, e: E, w: R.Writer):
        self.e, self.w = e, w

    def h(self, index):
        self.w.cid(index)

    def items(self, owner, emit):
        """``r.items(owner)``: a decoded aggregate's or sum's element indices; ``emit(count, item(i))``."""
        e, p = self.e, self.e.p
        e.var("it_shape", _field(e, T.AGGREGATE, owner))
        e.var("it_len", _field(e, T.COUNT, owner))
        e.var("it_at", _field(e, T.ITEMS, owner))
        emit(p["it_len"], lambda i: e.ld(e.sel(e.eq(p["it_shape"], T.ARRAY), p["it_at"], e.add(p["it_at"], i))))

    def hexes_items(self, owner):
        self.items(owner, lambda count, item: self.w.seq(D.T_LIST, count, lambda i: self.h(item(i))))

    def listing(self, owner):
        """``[len(items), [h(item) ...]]``."""
        def emit(count, item):
            self.w.put(D.T_LIST)
            self.w.put(2)
            self.w.integer(count)
            self.w.seq(D.T_LIST, count, lambda i: self.h(item(i)))
        self.items(owner, emit)

    def operands(self, position):
        e = self.e
        return e.rd(e.add(position, 1)), lambda i: e.rd(e.add(e.add(position, 6), i))

    def results(self, position):
        e = self.e
        return e.rd(e.add(position, 2)), lambda i: e.rd(e.add(e.add(e.add(position, 6), e.rd(e.add(position, 1))), i))

    def hexes(self, counted, tag=D.T_LIST):
        count, item = counted
        self.w.seq(tag, count, lambda i: self.h(item(i)))

    def cid_tuple(self, counted):
        """``tuple(r.cids[i] for i in ...)``: the CIDs as bytes."""
        count, item = counted
        self.w.seq(D.T_TUPLE, count, lambda i: self.w.cid_bytes(item(i)))

    def interface(self, at):
        """``r.interface(at)``: ``[parameters], [returns]`` (type indices) from the output words."""
        e = self.e
        return ((e.ld(at), lambda i: e.ld(e.add(e.add(at, 1), i))),
                (e.ld(e.add(e.add(at, 1), e.ld(at))), lambda i: e.ld(e.add(e.add(e.add(at, 2), e.ld(at)), i))))


def _sites(c: _Context):
    """``xax_selfhost_typing._render_sites``: ``{site: (code, rule, expected(x, y, z), actual(x, y, z))}``."""
    e, w = c.e, c.w
    const = lambda value: lambda x, y, z: w.const(value)  # noqa: E731
    triple = lambda x, y, z: (w.put(D.T_LIST), w.put(3), w.integer(x), w.integer(y), w.integer(z))  # noqa: E731
    contract = lambda code, rule, expected: (code, rule, const(expected), triple)  # noqa: E731

    def pair(first, second):
        return lambda x, y, z: (w.put(D.T_LIST), w.put(2), first(x, y, z), second(x, y, z))

    h = lambda pick: lambda x, y, z: c.h(pick(x, y, z))  # noqa: E731
    X, Y, Z = (lambda x, y, z: x), (lambda x, y, z: y), (lambda x, y, z: z)  # noqa: E731
    integer = lambda pick: lambda x, y, z: w.integer(pick(x, y, z))  # noqa: E731

    def opaque_name(x, y, z):
        for kind in OpaqueKind:
            e.if_(e.eq(x, int(kind)), lambda kind=kind: w.text(f"opaque<{kind.name.lower()}>"))

    sites = {
        T.SITE_OP_ARITY: contract("XAX.STRUCT.OP_ARITY", "GRAPH-OP-ARITY", "2 inputs, 1 result, 0 attributes"),
        T.SITE_OP_TYPE: ("XAX.STRUCT.OP_TYPE", "GRAPH-OP-TYPE", pair(h(X), h(X)), pair(h(Y), h(Z))),
        T.SITE_INT_WIDTH_CONTRACT: contract("XAX.INT.WIDTH", "INT-WIDTH-CONTRACT", [1, 1, 0]),
        T.SITE_INT_TRUNCATE_NARROWS: ("XAX.INT.WIDTH", "INT-TRUNCATE-NARROWS", lambda x, y, z: w.fmt("result < {}", x), integer(Y)),
        T.SITE_INT_ZERO_EXTEND_WIDENS: ("XAX.INT.WIDTH", "INT-ZERO-EXTEND-WIDENS", lambda x, y, z: w.fmt("result > {}", x), integer(Y)),
        T.SITE_ROTATE_CONTRACT: contract("XAX.INT.ROTATE", "INT-ROTATE-CONTRACT", [1, 1, 1]),
        T.SITE_ROTATE_TYPE: ("XAX.INT.ROTATE", "INT-ROTATE-TYPE", h(X), lambda x, y, z: (w.put(D.T_LIST), w.put(1), c.h(y))),
        T.SITE_ROTATE_AMOUNT: ("XAX.INT.ROTATE", "INT-ROTATE-AMOUNT", lambda x, y, z: w.fmt("0..{}", e.sub(x, 1)), integer(Y)),
        T.SITE_FLOAT_BINARY_CONTRACT: contract("XAX.FLOAT.CONTRACT", "FLOAT-BINARY-CONTRACT", [2, 1, 0]),
        T.SITE_FLOAT_BINARY_TYPE: ("XAX.FLOAT.TYPE", "FLOAT-BINARY-TYPE", pair(h(X), h(X)), pair(h(Y), h(Z))),
        T.SITE_FLOAT_COMPARE_CONTRACT: contract("XAX.FLOAT.CONTRACT", "FLOAT-COMPARE-CONTRACT", [2, 1, 1]),
        T.SITE_FLOAT_COMPARE_OPERANDS: ("XAX.FLOAT.TYPE", "FLOAT-COMPARE-OPERANDS", const("matching float types"), pair(h(X), h(Y))),
        T.SITE_FLOAT_COMPARE_RESULT: ("XAX.FLOAT.TYPE", "FLOAT-COMPARE-RESULT", const("bits<1>"), h(X)),
        T.SITE_FLOAT_COMPARE_KIND: ("XAX.FLOAT.COMPARE", "FLOAT-COMPARE-KIND", const([item.value for item in FloatCompare]), integer(X)),
        T.SITE_INT_COMPARE_CONTRACT: contract("XAX.INT.COMPARE", "INT-COMPARE-CONTRACT", [2, 1, 1]),
        T.SITE_INT_COMPARE_LINK_EQUALITY: ("XAX.INT.COMPARE", "INT-COMPARE-LINK-EQUALITY", const([IntCompare.EQ, IntCompare.NE]), integer(X)),
        T.SITE_INT_COMPARE_TYPE: ("XAX.INT.COMPARE", "INT-COMPARE-TYPE", lambda x, y, z: (w.put(D.T_LIST), w.put(2), c.h(x), w.text("bits<1>")),
                                  lambda x, y, z: (w.put(D.T_LIST), w.put(2), pair(h(X), h(Y))(x, y, z), c.h(z))),
        T.SITE_INT_COMPARE_KIND: ("XAX.INT.COMPARE", "INT-COMPARE-KIND", const([item.value for item in IntCompare]), integer(X)),
        T.SITE_FLOAT_CONVERT_CONTRACT: contract("XAX.FLOAT.CONTRACT", "FLOAT-CONVERT-CONTRACT", [1, 1, 0]),
        T.SITE_AGGREGATE_MAKE_CONTRACT: ("XAX.AGGREGATE.CONTRACT", "AGGREGATE-MAKE-CONTRACT", const("operands -> one aggregate result"), triple),
        T.SITE_AGGREGATE_MAKE_TYPE: ("XAX.AGGREGATE.TYPE", "AGGREGATE-MAKE-TYPE", const(["tuple", "array"]), integer(X)),
        T.SITE_AGGREGATE_MAKE_ELEMENTS: ("XAX.AGGREGATE.TYPE", "AGGREGATE-MAKE-ELEMENTS", lambda x, y, z: c.hexes_items(x),
                                         lambda x, y, z: c.hexes(c.operands(y))),
        T.SITE_AGGREGATE_GET_CONTRACT: contract("XAX.AGGREGATE.CONTRACT", "AGGREGATE-GET-CONTRACT", [1, 1, 1]),
        T.SITE_AGGREGATE_GET_TYPE: ("XAX.AGGREGATE.TYPE", "AGGREGATE-GET-TYPE", const(["tuple", "array"]), integer(X)),
        T.SITE_AGGREGATE_GET_INDEX: ("XAX.AGGREGATE.INDEX", "AGGREGATE-GET-INDEX", lambda x, y, z: c.listing(x), pair(integer(Y), h(Z))),
        T.SITE_SUM_MAKE_CONTRACT: contract("XAX.SUM.CONTRACT", "SUM-MAKE-CONTRACT", [1, 1, 1]),
        T.SITE_SUM_MAKE_VARIANT: ("XAX.SUM.VARIANT", "SUM-MAKE-VARIANT", lambda x, y, z: c.listing(x), pair(integer(Y), h(Z))),
        T.SITE_SUM_TAG_CONTRACT: contract("XAX.SUM.CONTRACT", "SUM-TAG-CONTRACT", [1, 1, 0]),
        T.SITE_SUM_TAG_WIDTH: ("XAX.SUM.TAG", "SUM-TAG-WIDTH", lambda x, y, z: w.fmt(">= {} bits", x), integer(Y)),
        T.SITE_SUM_GET_CONTRACT: contract("XAX.SUM.CONTRACT", "SUM-GET-CONTRACT", [1, 1, 1]),
        T.SITE_SUM_GET_VARIANT: ("XAX.SUM.VARIANT", "SUM-GET-VARIANT", lambda x, y, z: c.listing(x), pair(integer(Y), h(Z))),
        T.SITE_META_OPERAND_TYPE: ("XAX.META.CONTRACT", "META-OPERAND-TYPE", opaque_name, h(Y)),
        T.SITE_META_RESULT_TYPE: ("XAX.META.CONTRACT", "META-RESULT-TYPE", opaque_name, h(Y)),
        T.SITE_META_VERIFY_RESULT: ("XAX.META.CONTRACT", "META-VERIFY-RESULT", const("bits<1>"), h(X)),
        T.SITE_META_TARGET_SUPPORT_RESULT: ("XAX.META.CONTRACT", "META-TARGET-SUPPORT-RESULT", const("bits<1>"), lambda x, y, z: w.fmt("bits<{}>", x)),
        T.SITE_META_TARGET_OPERATION: ("XAX.META.CONTRACT", "META-TARGET-OPERATION", const(list(Operation)), integer(X)),
    }
    resource = ("XAX.RESOURCE.CONTRACT", "RESOURCE-EFFECT-OP-CONTRACT")

    def step_match(x, y, z):
        w.put(D.T_LIST)
        w.put(2)
        c.cid_tuple(c.operands(x))
        c.cid_tuple(c.results(x))

    def effects(x, y, z):
        count, item = c.operands(x)

        def effect(i):
            w.tagged(D.T_OBJECT, R.OBJECT["_EffectType"], 2)
            w.member("EffectDomain", _field(e, T.EDOMAIN, item(i)))
            w.integer(_field(e, T.EINST, item(i)))

        w.seq(D.T_TUPLE, count, effect)

    def counts(x, y, z):
        for operation, value in T.RESOURCE_COUNTS.items():
            e.if_(e.eq(z, int(operation)), lambda value=value: w.const(value))

    def transitions(owner):
        e.var("tr_start", _field(e, T.TSTART, owner))
        w.seq(D.T_LIST, _field(e, T.TCOUNT, owner), lambda i: w.integer(e.ld(e.add(e.p["tr_start"], i))))

    def transition_expected(x, y, z):
        w.tagged(D.T_DICT, 3)
        w.text("kind")
        w.integer(_field(e, T.RKIND, x))
        w.text("from")
        w.integer(_field(e, T.RSTATE, x))
        w.text("to")
        transitions(x)

    def transition_actual(x, y, z):
        w.tagged(D.T_DICT, 2)
        w.text("kind")
        w.integer(_field(e, T.RKIND, y))
        w.text("state")
        w.integer(_field(e, T.RSTATE, y))

    sites.update({
        T.SITE_RES_NO_ATTRIBUTES: (*resource, const("no attributes"), lambda x, y, z: (w.put(D.T_TUPLE), w.put(1), w.integer(x))),
        T.SITE_RES_STEP_MATCH: (*resource, const("one or more matching effect inputs/results"), step_match),
        T.SITE_RES_EXPECT_EFFECT: (*resource, const("effect<D>"), h(X)),
        T.SITE_RES_EFFECT_UNIQUE: ("XAX.EFFECT.FORK", "EFFECT-DOMAIN-INSTANCE-UNIQUE", const("distinct domain instances"), effects),
        T.SITE_RES_COUNTS: (*resource, counts, lambda x, y, z: (w.put(D.T_TUPLE), w.put(2), w.integer(x), w.integer(y))),
        T.SITE_RES_CONTINUATION: (*resource, const("matching effect continuation"), pair(h(X), h(Y))),
        T.SITE_RES_EXPECT_RESOURCE: (*resource, const("resource<K,state>"), h(X)),
        T.SITE_RES_ACQUIRE_ALLOWED: ("XAX.RESOURCE.ACQUIRE_STATE", "RESOURCE-ACQUIRE-ALLOWED", const(True), const(False)),
        T.SITE_RES_RELEASE_ALLOWED: ("XAX.RESOURCE.RELEASE_STATE", "RESOURCE-TERMINAL-ALLOWED", const("releasable"),
                                     lambda x, y, z: w.integer(_field(e, T.RFLAGS, x))),
        T.SITE_RES_DISCARD_ALLOWED: ("XAX.RESOURCE.DISCARD_LINEAR", "RESOURCE-TERMINAL-ALLOWED", const("affine"),
                                     lambda x, y, z: w.integer(_field(e, T.RFLAGS, x))),
        T.SITE_RES_JOIN_MATCH: (*resource, const("two matching pieces and one matching joined resource"), step_match),
        T.SITE_RES_JOIN_PARTITIONABLE: ("XAX.RESOURCE.JOIN", "RESOURCE-PARTITIONABLE", const(True), const(False)),
        T.SITE_RES_TRANSFER_SAME: (*resource, const("same resource type"), pair(h(X), h(Y))),
        T.SITE_RES_TRANSITION: ("XAX.RESOURCE.INVALID_TRANSITION", "RESOURCE-STATE-TRANSITION", transition_expected, transition_actual),
        T.SITE_RES_SPLIT: ("XAX.RESOURCE.SPLIT", "RESOURCE-PARTITION-CONTRACT", const("partitionable resource -> two matching pieces"),
                           lambda x, y, z: (w.put(D.T_LIST), w.put(3), w.integer(_field(e, T.RFLAGS, x)), c.h(y), c.h(z))),
        T.SITE_CONSTANT_TARGET_NONE: ("XAX.STRUCT.CONSTANT_TARGET", "GRAPH-CONSTANT-TARGET", const(Kind.CONSTANT.name), const(None)),
        T.SITE_CONSTANT_TARGET_KIND: ("XAX.STRUCT.CONSTANT_TARGET", "GRAPH-CONSTANT-TARGET", const(Kind.CONSTANT.name),
                                      lambda x, y, z: w.name("Kind", x)),
        T.SITE_CONSTANT_CONTRACT: ("XAX.STRUCT.CONSTANT_CONTRACT", "GRAPH-CONSTANT-CONTRACT",
                                   lambda x, y, z: (w.put(D.T_LIST), w.put(2), w.seq(D.T_LIST, 0, lambda i: None), w.put(D.T_LIST), w.put(1), c.h(x)),
                                   lambda x, y, z: (w.put(D.T_LIST), w.put(2), c.hexes(c.operands(y)), c.hexes(c.results(y)))),
        T.SITE_CALL_TARGET_NONE: ("XAX.STRUCT.CALL_TARGET", "GRAPH-CALL-TARGET", const(Kind.FUNCTION.name), const(None)),
        T.SITE_CALL_TARGET_KIND: ("XAX.STRUCT.CALL_TARGET", "GRAPH-CALL-TARGET", const(Kind.FUNCTION.name), lambda x, y, z: w.name("Kind", x)),
        T.SITE_CALL_CONTRACT: ("XAX.STRUCT.CALL_CONTRACT", "GRAPH-CALL-CONTRACT",
                               lambda x, y, z: (w.put(D.T_LIST), w.put(2), [c.hexes(part) for part in c.interface(x)]),
                               lambda x, y, z: (w.put(D.T_LIST), w.put(2), c.hexes(c.operands(y)), c.hexes(c.results(y)))),
    })
    for index, (kinds, result_count, attribute_count, _rule) in enumerate(T.META_RULES.values()):
        expected = (len(kinds), result_count, attribute_count)
        sites[T.SITE_META_ARITY + index] = ("XAX.META.CONTRACT", "META-OP-ARITY", const(expected),
                                            lambda x, y, z: (w.put(D.T_TUPLE), w.put(3), w.integer(x), w.integer(y), w.integer(z)))
    for name in ("UINT", "SINT"):
        sites[getattr(T, f"SITE_{name}_TO_FLOAT_CONTRACT")] = contract("XAX.FLOAT.CONTRACT", f"{name}-TO-FLOAT-CONTRACT", [1, 1, 0])
        sites[getattr(T, f"SITE_{name}_TO_FLOAT_WIDTH")] = ("XAX.FLOAT.CONVERT", f"{name}-TO-FLOAT-WIDTH", const("bits<=64"), h(X))
        sites[getattr(T, f"SITE_FLOAT_TO_{name}_CONTRACT")] = contract("XAX.FLOAT.CONTRACT", f"FLOAT-TO-{name}-CONTRACT", [1, 1, 0])
        sites[getattr(T, f"SITE_FLOAT_TO_{name}_WIDTH")] = ("XAX.FLOAT.CONVERT", f"FLOAT-TO-{name}-WIDTH", const("bits<=64"), h(X))
    assert set(sites) == set(T._SITES), set(T._SITES) ^ set(sites)
    return sites


# -- the record writer ----------------------------------------------------------------------------------------------

def _writer(e: E) -> R.Writer:
    return R.Writer(e, TypeTable(e), OUTCOME_AT + O_CURSOR, RECORD_END, OUTCOME_AT + O_BAD, functions=_FN)


def _begin(e: E):
    """A fresh record (entity: the graph unless ``entity()`` writes another)."""
    e.st(OUTCOME_AT + O_CURSOR, RECORD_AT)
    e.st(OUTCOME_AT + O_ENTITY, ENTITY_GRAPH)
    e.st(OUTCOME_AT + O_BAD, 0)


def _four(e: E, w: R.Writer, code: str, rule: str, expected, actual, entity=None):
    """``code [entity] rule expected actual`` (``expected``/``actual``/``entity``: emitters)."""
    w.text(code)
    if entity is not None:
        e.st(OUTCOME_AT + O_ENTITY, ENTITY_WRITTEN)
        entity()
    w.text(rule)
    expected()
    actual()


def _non_minimal(e: E, w: R.Writer, at, size):
    """``uleb(value).hex()`` of the ``size`` input bytes from word ``at``: the encoding without trailing zero groups."""
    p = e.p
    e.var("nm_last", 0)
    e.for_("nm_k", 0, size, lambda: e.if_(e.ne(e.and_(e.rd(e.add(at, p["nm_k"])), 127), 0), lambda: e.set("nm_last", p["nm_k"])))
    w.packed(D.T_HEX, e.add(p["nm_last"], 1), lambda byte: e.for_("nm_q", 0, e.add(p["nm_last"], 1), lambda: byte(e.sel(
        e.eq(p["nm_q"], p["nm_last"]), e.and_(e.rd(e.add(at, p["nm_q"])), 127), e.rd(e.add(at, p["nm_q"]))))))


NODE_PARTS = 4  # the sites' renderers, in this many functions: one function of them all is more than the facts engine decides


def _node_record(e: E):
    """Node ``key``'s record words: ``site`` and ``x``/``y``/``z``."""
    p = e.p
    at = e.add(T.DIAGNOSTICS, e.mul(p["key"], 4))
    e.var("site", e.ld(at))
    for k, name in enumerate(("x", "y", "z")):
        e.var(name, e.ld(e.add(at, k + 1)))
    return p["x"], p["y"], p["z"]


def _node_part(tables, part: int):
    """The renderers of every ``NODE_PARTS``-th typing site from ``part``; gives 1 when one wrote the record."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        c = _Context(e, w)
        x, y, z = _node_record(e)
        e.var("written", 0)
        for site, (code, rule, expected, actual) in list(_sites(c).items())[part::NODE_PARTS]:
            e.if_(e.eq(p["site"], site), lambda code=code, rule=rule, expected=expected, actual=actual: (
                _four(e, w, code, rule, lambda: expected(x, y, z), lambda: actual(x, y, z)), e.set("written", 1)))
        e.give(p["written"])
    return _function(("key",), build, tables)


def _node_cross(tables):
    """``cross_diagnostic``: a node's type the bits or float decoder rejects; gives 1 when written."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        c = _Context(e, w)
        x, _y, _z = _node_record(e)
        e.var("written", 0)

        def cross(bits: bool):
            rule = "TYPE-BITS" if bits else "TYPE-FLOAT"
            e.var("cs_stat", _field(e, T.XSTAT, x))
            e.var("cs_a", _field(e, T.XA, x))
            e.var("cs_b", _field(e, T.XB, x))
            stat, xa, xb = p["cs_stat"], p["cs_a"], p["cs_b"]
            entity = lambda: c.h(x)  # noqa: E731
            pair_ = lambda: (w.put(D.T_LIST), w.put(2), w.integer(xa), w.integer(xb))  # noqa: E731
            cases = [
                (e.eq(stat, 6), "XAX.TYPE.EXPECTED", rule, lambda: w.text(Kind.TYPE.name), lambda: w.name("Kind", xa)),
                (e.eq(stat, 1), "XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED", lambda: w.text("terminating byte"), lambda: w.text("end of input")),
                (e.eq(stat, 3), "XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED", lambda: w.text("at most 10 bytes"), lambda: w.text("more than 10 bytes")),
                (e.eq(stat, 2), "XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL", lambda: _non_minimal(e, w, e.add(TypeTable(e).body(x), xa), xb),
                 lambda: w.body_bytes(D.T_HEX, x, xa, xb)),
                (e.eq(stat, 5), "XAX.CANON.TRAILING_BYTES", "TYPE-BODY", lambda: w.integer(0), lambda: w.integer(xa)),
            ]
            e.var("cs_done", 0)
            for condition, code, rule_, expected, actual in cases:
                e.if_(e.both(e.eq(p["cs_done"], 0), condition), lambda code=code, rule_=rule_, expected=expected, actual=actual: (
                    _four(e, w, code, rule_, expected, actual, entity), e.set("cs_done", 1)))
            if bits:
                e.if_(e.eq(p["cs_done"], 0), lambda: _four(e, w, "XAX.TYPE.BITS", "TYPE-BITS", lambda: w.text("form=1,width>=1"), pair_, entity))
            else:
                e.if_(e.both(e.eq(p["cs_done"], 0), e.ne(xb, 1), e.ne(xb, 2)), lambda: (
                    _four(e, w, "XAX.TYPE.FLOAT", "TYPE-FLOAT-FORMAT", lambda: w.const([1, 2]), lambda: w.integer(xb), entity), e.set("cs_done", 1)))
                e.if_(e.eq(p["cs_done"], 0), lambda: _four(e, w, "XAX.TYPE.FLOAT", "TYPE-FLOAT", lambda: w.text("form=7,known format"), pair_, entity))
            e.set("written", 1)

        e.if_(e.eq(p["site"], T.SITE_CROSS_BITS), lambda: cross(True))
        e.if_(e.eq(p["site"], T.SITE_CROSS_FLOAT), lambda: cross(False))
        e.give(p["written"])
    return _function(("key",), build, tables)


def _node(tables):
    """Node ``key``'s typing rejection (``NativeTyping.rejection``); gives 1 when written, 0 otherwise."""
    def build(e: E):
        p = e.p
        _begin(e)
        e.var("written", 0)
        for name in (*(f"node{part}" for part in range(NODE_PARTS)), "node_cross"):
            e.set("written", e.or_(p["written"], e.call(_FN[name], p["key"])))
        e.give(e.sel(e.ne(e.ld(OUTCOME_AT + O_BAD), 0), 0, e.flag(e.ne(p["written"], 0))))
    return _function(("key",), build, tables)


# -- the graph's shape, from the facts section ------------------------------------------------------------------------

class _Shape:
    """Arrays over the facts section (``_facts_section``): each block's position and node count, each node's
    position, each terminator's position, and each value's ``ValueRef`` and type, from ``ARRAYS_AT``.  ``ok`` is 0
    without a facts section or when the arrays do not fit."""

    def __init__(self, e: E):
        self.e = e
        p = e.p
        e.var("F", e.hd(H_FACTS_AT))
        F = p["F"]
        e.var("sh_arena", ARRAYS_AT)
        e.var("sh_values", e.rd(e.add(F, 1)))
        e.var("sh_sites", e.rd(e.add(F, 2)))
        e.var("sh_blocks", e.rd(e.add(F, 4)))
        e.var("sh_entry", e.rd(e.add(F, 5)))
        e.var("sh_order", e.add(F, 6))
        e.var("sh_body", e.add(e.add(e.add(F, 6), p["sh_blocks"]), p["sh_sites"]))
        e.var("sh_ok", e.flag(e.eq(e.rd(F), 1)))  # a graph's facts section
        for name, count in (("bpos", p["sh_blocks"]), ("bnodes", p["sh_blocks"]), ("nbase", p["sh_blocks"]), ("tpos", p["sh_blocks"]),
                            ("vb", p["sh_values"]), ("vi", p["sh_values"]), ("vr", p["sh_values"]), ("vtag", p["sh_values"]),
                            ("vty", p["sh_values"])):
            e.var(f"sh_{name}", self._alloc(count))
        e.var("sh_nodes", 0)
        e.if_(e.ne(p["sh_ok"], 0), self._walk_counts)
        e.var("sh_npos", self._alloc(p["sh_nodes"]))
        e.if_(e.ne(p["sh_ok"], 0), self._walk)

    def _alloc(self, count):
        e, p = self.e, self.e.p
        e.var("sa_start", p["sh_arena"])
        e.set("sh_arena", e.add(e.add(p["sh_arena"], count), 1))
        e.if_(e.either(e.lt(ARRAYS_END, p["sh_arena"]), e.lt(1 << 40, count)), lambda: e.set("sh_ok", 0))
        return p["sa_start"]

    def _walk_counts(self):
        """Node counts (to size the node array)."""
        e, p = self.e, self.e.p
        e.var("sw_c", p["sh_body"])

        def block():
            e.set("sw_c", e.add(e.add(p["sw_c"], 2), e.rd(e.add(p["sw_c"], 1))))
            e.var("sw_n", e.rd(p["sw_c"]))
            e.set("sw_c", e.add(p["sw_c"], 1))
            e.set("sh_nodes", e.add(p["sh_nodes"], p["sw_n"]))
            e.for_("sw_k", 0, p["sw_n"], lambda: e.set("sw_c", self._skip_node(p["sw_c"])))
            e.set("sw_c", self._skip_terminator(p["sw_c"]))

        e.for_("sw_b", 0, p["sh_blocks"], block)

    def _skip_node(self, c):
        e = self.e
        attrs_end = e.add(e.add(c, 6), e.rd(e.add(c, 5)))
        operands = e.rd(attrs_end)
        results_at = e.add(e.add(attrs_end, 1), e.mul(operands, 2))
        aux_at = e.add(e.add(results_at, 1), e.rd(results_at))
        return e.add(e.add(aux_at, 1), e.rd(aux_at))

    def _skip_terminator(self, c):
        e, p = self.e, self.e.p
        values = e.rd(e.add(c, 1))
        e.var("st_at", e.add(e.add(e.add(c, 2), e.mul(values, 2)), 1))
        e.for_("st_k", 0, e.rd(e.sub(p["st_at"], 1)), lambda: e.set("st_at", e.add(e.add(p["st_at"], 3), e.rd(e.add(p["st_at"], 2)))))
        return e.add(e.add(p["st_at"], 1), e.rd(p["st_at"]))

    def _walk(self):
        e, p = self.e, self.e.p
        e.var("sw_c", p["sh_body"])
        e.var("sw_total", 0)

        def value(v, tag, block, index, result, type_):
            for name, word in (("vtag", tag), ("vb", block), ("vi", index), ("vr", result), ("vty", type_)):
                e.st(e.add(p[f"sh_{name}"], v), word)

        def block():
            b, c = p["sw_b"], p["sw_c"]
            e.st(e.add(p["sh_bpos"], b), c)
            e.var("sw_first", e.rd(c))
            e.var("sw_np", e.rd(e.add(c, 1)))
            e.for_("sw_i", 0, p["sw_np"], lambda: value(e.add(p["sw_first"], p["sw_i"]), 0, b, p["sw_i"], 0, e.rd(e.add(e.add(p["sw_c"], 2), p["sw_i"]))))
            e.set("sw_c", e.add(e.add(p["sw_c"], 2), p["sw_np"]))
            e.var("sw_n", e.rd(p["sw_c"]))
            e.set("sw_c", e.add(p["sw_c"], 1))
            e.st(e.add(p["sh_bnodes"], b), p["sw_n"])
            e.st(e.add(p["sh_nbase"], b), p["sw_total"])

            def node():
                n, c_ = p["sw_k"], p["sw_c"]
                e.st(e.add(p["sh_npos"], e.add(p["sw_total"], n)), c_)
                attrs_end = e.add(e.add(c_, 6), e.rd(e.add(c_, 5)))
                results_at = e.add(e.add(attrs_end, 1), e.mul(e.rd(attrs_end), 2))
                e.var("sw_ra", results_at)
                e.var("sw_fr", e.rd(e.add(c_, 4)))
                e.for_("sw_r", 0, e.rd(p["sw_ra"]), lambda: value(e.add(p["sw_fr"], p["sw_r"]), 1, b, n, p["sw_r"],
                                                                     e.rd(e.add(e.add(p["sw_ra"], 1), p["sw_r"]))))
                e.set("sw_c", self._skip_node(p["sw_c"]))

            e.for_("sw_k", 0, p["sw_n"], node)
            e.set("sw_total", e.add(p["sw_total"], p["sw_n"]))
            e.st(e.add(p["sh_tpos"], b), p["sw_c"])
            e.set("sw_c", self._skip_terminator(p["sw_c"]))

        e.for_("sw_b", 0, p["sh_blocks"], block)

    def word(self, name: str, index):
        return self.e.ld(self.e.add(self.e.p[f"sh_{name}"], index))

    def node_pos(self, b, n):
        return self.word("npos", self.e.add(self.word("nbase", b), n))

    def node_operands(self, pos):
        """``(count, value id of operand i)`` of the node at facts position ``pos``."""
        e = self.e
        attrs_end = e.add(e.add(pos, 6), e.rd(e.add(pos, 5)))
        return e.rd(attrs_end), lambda i: e.rd(e.add(e.add(attrs_end, 1), i))


# -- terminators and linear flow ----------------------------------------------------------------------------------

def _terminator_record(e: E, w: R.Writer, c: _Context, b, blocks):
    """Block ``b``'s typing terminator record: ``GRAPH-CBR-CONDITION`` or ``GRAPH-BLOCK-PARAMETERS`` (from the marshal's
    block section, located by the program's ``places`` table)."""
    p = e.p
    record = e.sub(T.TERMINATOR_RECORDS, e.mul(b, 4))
    e.var("tr_site", e.ld(record))
    e.var("tr_edge", e.ld(e.add(record, 1)))
    e.var("tr_condition", e.ld(e.add(record, 2)))
    places = e.add(e.add(e.add(T.TABLE, e.mul(e.rd(0), T.TABLES)), T.MARKS), T.TYPING_WORDS)  # the program's ``places``
    e.var("tr_places", places)
    e.if_(e.eq(p["tr_site"], 1), lambda: _four(e, w, "XAX.STRUCT.CONDITION_TYPE", "GRAPH-CBR-CONDITION", lambda: w.text("bits<1>"),
                                                lambda: c.h(p["tr_condition"])))

    def arguments():
        position = e.ld(e.add(p["tr_places"], b))
        e.var("ta_at", e.add(e.add(e.add(position, 2), e.rd(e.add(position, 1))), 3))  # the first edge
        e.for_("ta_k", 0, p["tr_edge"], lambda: e.set("ta_at", e.add(e.add(p["ta_at"], 2), e.rd(e.add(p["ta_at"], 1)))))
        e.var("ta_target", e.ld(e.add(p["tr_places"], e.rd(p["ta_at"]))))
        expected = lambda: w.seq(D.T_LIST, e.rd(e.add(p["ta_target"], 1)), lambda i: c.h(e.rd(e.add(e.add(p["ta_target"], 2), i))))  # noqa: E731
        actual = lambda: w.seq(D.T_LIST, e.rd(e.add(p["ta_at"], 1)), lambda i: c.h(e.rd(e.add(e.add(p["ta_at"], 2), i))))  # noqa: E731
        _four(e, w, "XAX.STRUCT.BRANCH_ARGUMENTS", "GRAPH-BLOCK-PARAMETERS", expected, actual)

    e.if_(e.eq(p["tr_site"], 2), arguments)


def _linear(tables):
    """``_linear_diagnostic`` of the engine's linear-flow rejection; gives 1 when written."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        c = _Context(e, w)
        shape = _Shape(e)
        _begin(e)
        e.var("lcode", e.hd(H_LREJ))
        e.var("la", e.hd(H_LA))
        e.var("lb", e.hd(H_LB))
        e.var("written", 0)
        code, a, b = p["lcode"], p["la"], p["lb"]
        const = lambda value: lambda: w.const(value)  # noqa: E731

        def done(code_, rule, expected, actual):
            _four(e, w, code_, rule, expected, actual)
            e.set("written", 1)

        e.if_(e.eq(code, 1), lambda: done("XAX.RESOURCE.UNREACHABLE_PARAMETER", "RESOURCE-BLOCK-PREDECESSOR", const("at least one"), const(0)))
        e.if_(e.eq(code, 2), lambda: done("XAX.RESOURCE.BLOCK_FLOW", "RESOURCE-BLOCK-ARGUMENT", lambda: w.integer(a), lambda: w.integer(b)))
        e.if_(e.eq(code, 3), lambda: done("XAX.RESOURCE.DUPLICATE", "RESOURCE-LINEAR-CONTINUATION", const("one continuation"),
                                          const("node and terminator")))
        value = lambda: (shape.word("vtag", a), shape.word("vb", a), shape.word("vi", a), shape.word("vr", a))  # noqa: E731

        def same(value_id):
            """The value id equals the linear record's value."""
            return e.eq(value_id, a)

        def node_uses(emit):
            """``uses``: ``(block, node)`` per operand equal to the value, in block and node order."""
            def block():
                def node():
                    count, operand = shape.node_operands(shape.node_pos(p["lu_b"], p["lu_n"]))
                    e.for_("lu_o", 0, count, lambda: e.if_(same(operand(p["lu_o"])), lambda: emit(p["lu_b"], p["lu_n"])))
                e.for_("lu_n", 0, shape.word("bnodes", p["lu_b"]), node)
            e.for_("lu_b", 0, p["sh_blocks"], block)

        def terms(emit, only_block=None):
            """``terms``: ``(block, edge)`` per edge argument equal to the value, then ``(block, -1)`` per returned one."""
            def block():
                t = shape.word("tpos", p["lt_b"])
                e.var("lt_t", t)
                values = e.rd(e.add(p["lt_t"], 1))
                e.var("lt_v", values)
                e.var("lt_at", e.add(e.add(e.add(p["lt_t"], 2), e.mul(values, 2)), 1))

                def edge():
                    args = e.rd(e.add(p["lt_at"], 2))
                    e.for_("lt_a", 0, args, lambda: e.if_(same(e.rd(e.add(e.add(p["lt_at"], 3), p["lt_a"]))), lambda: emit(p["lt_b"], p["lt_e"])))
                    e.set("lt_at", e.add(e.add(p["lt_at"], 3), args))

                e.for_("lt_e", 0, e.rd(e.sub(p["lt_at"], 1)), edge)
                e.for_("lt_r", 0, p["lt_v"], lambda: e.if_(same(e.rd(e.add(e.add(p["lt_t"], 2), p["lt_r"]))), lambda: emit(p["lt_b"], e.c(-1))))

            if only_block is None:
                e.for_("lt_b", 0, p["sh_blocks"], block)
            else:
                e.var("lt_b", only_block)
                block()

        def counted(producer, write):
            """A list of what ``producer(emit)`` emits: counted first, then written."""
            e.var("cn_n", 0)
            producer(lambda *_items: e.set("cn_n", e.add(p["cn_n"], 1)))
            w.put(D.T_LIST)
            w.put(p["cn_n"])
            producer(write)

        def pair_tuple(first, second):
            w.put(D.T_TUPLE)
            w.put(2)
            w.integer(first)
            w.tagged(D.T_SINT, second)

        e.if_(e.eq(code, 4), lambda: done("XAX.RESOURCE.DUPLICATE", "RESOURCE-LINEAR-CONTINUATION", const("one same-block consumer"),
                                          lambda: counted(node_uses, lambda block_, node_: (w.put(D.T_TUPLE), w.put(2), w.integer(block_),
                                                                                             w.integer(node_)))))
        e.if_(e.eq(code, 5), lambda: done("XAX.RESOURCE.BLOCK_FLOW", "RESOURCE-EXPLICIT-BLOCK-PARAMETER", lambda: w.integer(value()[1]),
                                          lambda: counted(terms, pair_tuple)))
        local = lambda emit: terms(emit, value()[1])  # noqa: E731

        def per_edge():
            w.put(D.T_LIST)
            w.put(2)
            for edge_ in range(2):
                e.var("pe_n", 0)
                local(lambda block_, edge_value, edge_=edge_: e.if_(e.eq(edge_value, edge_), lambda: e.set("pe_n", e.add(p["pe_n"], 1))))
                w.integer(p["pe_n"])

        def local_count():
            e.var("lc_n", 0)
            local(lambda *_items: e.set("lc_n", e.add(p["lc_n"], 1)))
            w.integer(p["lc_n"])

        e.if_(e.eq(code, 6), lambda: done("XAX.RESOURCE.DROP", "RESOURCE-EACH-CONTROL-PATH", const([1, 1]), per_edge))
        e.if_(e.eq(code, 7), lambda: done("XAX.EFFECT.FORK", "EFFECT-TRAP-END", const(0), local_count))

        def continuation():
            t = shape.word("vty", a)
            pos = _field(e, T.POSITION, t)
            resource = e.both(e.eq(e.rd(pos), int(Kind.TYPE)), e.ne(e.rd(e.add(pos, 2)), 0), e.eq(e.rd(e.add(pos, 3)), 4))
            e.if_(resource, lambda: done("XAX.RESOURCE.DROP", "RESOURCE-LINEAR-CONTINUATION", const(1), local_count),
                  lambda: done("XAX.EFFECT.FORK", "RESOURCE-LINEAR-CONTINUATION", const(1), local_count))

        e.if_(e.eq(code, 8), continuation)

        def origin(start):
            """``_join_origins``' ``origin`` of value ``start``: a chain of splits, each quoting the origin of its operand."""
            e.var("og_v", start)
            e.var("og_more", 1)

            def step():
                tag, block_, index, result = (shape.word(name, p["og_v"]) for name in ("vtag", "vb", "vi", "vr"))
                e.var("og_tag", tag)
                e.var("og_b", block_)
                e.var("og_i", index)
                e.var("og_r", result)
                e.var("og_pos", shape.node_pos(p["og_b"], p["og_i"]))
                e.var("og_op", e.sel(e.eq(p["og_tag"], 0), 0, e.rd(p["og_pos"])))
                count, operand = shape.node_operands(p["og_pos"])
                op = p["og_op"]

                def finish(*words):
                    w.put(D.T_TUPLE)
                    w.put(len(words))
                    for word in words:
                        w.text(word) if isinstance(word, str) else w.integer(word)
                    e.set("og_more", 0)

                e.if_(e.eq(p["og_tag"], 0), lambda: finish("parameter", p["og_i"]), lambda: e.if_(
                    e.eq(op, int(Operation.RESOURCE_ACQUIRE)), lambda: finish("acquire", p["og_b"], p["og_i"]), lambda: e.if_(
                        e.either(e.eq(op, int(Operation.RESOURCE_TRANSFER)), e.eq(op, int(Operation.RESOURCE_TRANSITION))),
                        lambda: e.set("og_v", operand(0)), lambda: e.if_(
                            e.eq(op, int(Operation.RESOURCE_SPLIT)), lambda: (
                                w.put(D.T_TUPLE), w.put(5), w.text("split"), w.integer(p["og_b"]), w.integer(p["og_i"]), w.integer(p["og_r"]),
                                e.set("og_v", operand(0))), lambda: e.if_(
                                e.eq(op, int(Operation.RESOURCE_JOIN)), lambda: finish("join", p["og_b"], p["og_i"]),
                                lambda: finish("opaque", p["og_b"], p["og_i"], p["og_r"]))))))

            e.while_(lambda: e.ne(p["og_more"], 0), step)

        def join():
            e.var("jn_pos", shape.node_pos(a, b))
            count, operand = shape.node_operands(p["jn_pos"])
            e.var("jn_left", operand(0))
            e.var("jn_right", operand(1))
            w.put(D.T_LIST)
            w.put(2)
            origin(p["jn_left"])
            origin(p["jn_right"])

        e.if_(e.eq(code, 9), lambda: done("XAX.RESOURCE.JOIN", "RESOURCE-JOIN-SIBLINGS", const("two pieces from one split"), join))
        e.give(e.sel(e.either(e.eq(p["sh_ok"], 0), e.ne(e.ld(OUTCOME_AT + O_BAD), 0)), 0, p["written"]))
    return _function((), build, tables)


# -- memory rejections (S15b.3b) ----------------------------------------------------------------------------------

# ``memory_diagnostic``'s sites that quote a declaration's decoded body, a stack-owner entry's contract, or a CID only
# the host computes: the bootstrap decides them (a decline).
DECLINED_MEMORY_SITES = ("FOREIGN_ENTRY", "FOREIGN_ABI", "FOREIGN_CONTRACT", "INDIRECT_BOUNDED_CONTRACT", "LEND_VIEW_LENT", "TARGET_DEFINED",
                         "TARGET_SCOPE_SUPPORTED", "TARGET_SPACES", "ENTRY_BODY", "ENTRY_TRANSFER_RETURN", "ENTRY_TRANSFER_COUNT",
                         "ENTRY_LOAD_RESULT", "ENTRY_TRANSFER_PAIR")


def _bad(e: E):
    e.st(OUTCOME_AT + O_BAD, 1)


def _storage(tables):
    """``storages[site]`` (``facts_storages``): ``(-1, 0)`` the stack, ``(-2, i)`` an entry parameter, ``(block, node)``
    of a stack allocation, heap view, or foreign call, None for a call result; past the sites the host cannot render it."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        shape = _Shape(e)
        e.if_(e.le(p["sh_sites"], p["site"]), lambda: _bad(e))
        e.var("sg_kind", e.rd(e.add(e.add(e.add(p["F"], 6), p["sh_blocks"]), e.sel(e.lt(p["site"], p["sh_sites"]), p["site"], 0))))
        pair = lambda first, second: (w.put(D.T_TUPLE), w.put(2), first(), w.integer(second))  # noqa: E731
        e.if_(e.eq(p["sg_kind"], 0), lambda: pair(lambda: w.tagged(D.T_SINT, e.c(-1)), 0))
        e.if_(e.eq(p["sg_kind"], 1), lambda: pair(lambda: w.tagged(D.T_SINT, e.c(-2)), e.sub(p["site"], 1)))
        e.if_(e.eq(p["sg_kind"], 3), lambda: w.put(D.T_NONE))

        def node():
            e.var("sg_b", 0)
            e.var("sg_n", 0)
            e.for_("sg_wb", 0, p["sh_blocks"], lambda: e.for_("sg_wn", 0, shape.word("bnodes", p["sg_wb"]), lambda: e.if_(
                e.eq(e.rd(e.add(shape.node_pos(p["sg_wb"], p["sg_wn"]), 3)), p["site"]), lambda: (e.set("sg_b", p["sg_wb"]), e.set("sg_n", p["sg_wn"])))))
            pair(lambda: w.integer(p["sg_b"]), p["sg_n"])

        e.if_(e.eq(p["sg_kind"], 2), node)
        e.give(0)
    return _function(("site",), build, tables)


def _ref(tables):
    """``[refs[value].block, refs[value].index, refs[value].result][:fields]`` (``fields`` 4: ``[tag, block, index]``;
    5: ``refs[value].index``)."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        shape = _Shape(e)
        e.if_(e.le(p["sh_values"], p["value"]), lambda: _bad(e))
        e.var("rf_v", e.sel(e.lt(p["value"], p["sh_values"]), p["value"], 0))
        word = lambda name: w.integer(shape.word(name, p["rf_v"]))  # noqa: E731
        e.if_(e.eq(p["fields"], 5), lambda: word("vi"), lambda: e.if_(e.eq(p["fields"], 4), lambda: (
            w.put(D.T_LIST), w.put(3), word("vtag"), word("vb"), word("vi")), lambda: (
            w.put(D.T_LIST), w.put(p["fields"]), word("vb"), word("vi"), e.if_(e.eq(p["fields"], 3), lambda: word("vr")))))
        e.give(0)
    return _function(("value", "fields"), build, tables)


def _intervals(tables):
    """``tuple((read(at + 1 + 2k), read(at + 2 + 2k)) for k in range(read(at)))``."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        w.seq(D.T_TUPLE, e.ld(p["at"]), lambda k: (w.put(D.T_TUPLE), w.put(2), w.integer(e.ld(e.add(e.add(p["at"], 1), e.mul(k, 2)))),
                                                     w.integer(e.ld(e.add(e.add(p["at"], 2), e.mul(k, 2))))))
        e.give(0)
    return _function(("at",), build, tables)


MEMORY_PARTS = 8  # the sites' renderers, in this many functions (each edge of one function of them all carries more
# values than the facts engine's arena holds)


def _memory(tables):
    """``memory_diagnostic`` of the facts engine's rejection record, as ``_xax_memory_fail`` raises it; gives 1 when
    written, 0 when the host could not render it or the site declines."""
    def build(e: E):
        p = e.p
        _begin(e)
        # ``operation_of(block, node)``: the rejected node's operation (``OP_CONTRACT`` quotes its contract).
        shape = _Shape(e)
        e.var("mb", e.hd(H_RBLOCK))
        e.var("mn", e.hd(H_RNODE))
        e.var("mop", 0)
        e.if_(e.both(e.ne(p["sh_ok"], 0), e.lt(p["mb"], p["sh_blocks"])), lambda: e.if_(
            e.lt(p["mn"], shape.word("bnodes", p["mb"])), lambda: e.set("mop", e.rd(shape.node_pos(p["mb"], p["mn"])))))
        e.var("written", 0)
        for part in range(MEMORY_PARTS):
            e.set("written", e.or_(p["written"], e.call(_FN[f"memory{part}"], p["mop"])))
        e.give(e.sel(e.either(e.eq(p["sh_ok"], 0), e.ne(e.ld(OUTCOME_AT + O_BAD), 0)), 0, e.flag(e.ne(p["written"], 0))))
    return _function((), build, tables)


def _memory_part(tables, part: int):
    """The renderers of every ``MEMORY_PARTS``-th memory site from ``part`` (``mop``: the rejected node's operation);
    gives 1 when one wrote the record."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        c = _Context(e, w)
        e.var("msite", e.hd(H_REJECT))
        for k, name in enumerate(("x", "y", "z", "w4", "p4", "p5")):
            e.var(name, e.hd(H_RPAY + k))
        x, y, z, w4 = p["x"], p["y"], p["z"], p["w4"]
        e.var("written", 0)
        e.var("F", e.hd(H_FACTS_AT))
        e.var("sh_sites", e.rd(e.add(p["F"], 2)))
        e.var("sh_blocks", e.rd(e.add(p["F"], 4)))

        const = lambda value: lambda: w.const(value)  # noqa: E731
        integer = lambda value: lambda: w.integer(value)  # noqa: E731
        h = lambda index: lambda: c.h(index)  # noqa: E731
        storage = lambda site: lambda: e.call(_FN["storage"], site)  # noqa: E731
        maybe = lambda word, emit: lambda: e.if_(e.eq(word, NONE), lambda: w.put(D.T_NONE), emit)  # noqa: E731
        when = lambda flag, emit: lambda: e.if_(e.ne(flag, 0), emit, lambda: w.put(D.T_NONE))  # noqa: E731
        intervals = lambda at: lambda: e.call(_FN["intervals"], at)  # noqa: E731
        fmt = lambda template, value: lambda: w.fmt(template, value)  # noqa: E731

        def ref(value, fields=3):
            return lambda: e.call(_FN["ref"], value, fields)

        def listing(*items):
            return lambda: (w.put(D.T_LIST), w.put(len(items)), [item() for item in items])

        def total(*values):
            """``sum(values)`` (Python's integers do not wrap: a carry is a value the record cannot hold)."""
            result = values[0]
            for value in values[1:]:
                summed = e.add(result, value)
                e.if_(e.lt(summed, result), lambda: _bad(e))
                result = summed
            return result

        def member(enum, value, render):
            """``render(enum(value))``; a value outside the enumeration raises ``ValueError`` in the host."""
            def emit():
                for item in enum:
                    e.if_(e.eq(value, int(item)), lambda item=item: render(item))
                e.if_(e.not_(e.either(*(e.eq(value, int(item)) for item in enum))), lambda: _bad(e))
            return emit

        lower = lambda enum, value: member(enum, value, lambda item: w.text(item.name.lower()))  # noqa: E731

        def contract_expected():
            for operation, counts in _CONTRACTS.items():
                e.if_(e.eq(p["mop"], int(operation)), lambda counts=counts: w.const(counts))
            e.if_(e.eq(p["mop"], int(Operation.HEAP_VIEW)), lambda: e.if_(e.eq(x, 4), lambda: w.const((4, 3, 2)), lambda: w.const((3, 3, 2))))
            e.if_(e.not_(e.either(*(e.eq(p["mop"], int(operation)) for operation in (*_CONTRACTS, Operation.HEAP_VIEW)))), lambda: _bad(e))

        def leak(which):
            """``sorted(storages[k] for k in range(count) if marked)``: entry parameters ``(-2, i)``, the stack
            ``(-1, 0)``, then nodes in order; a marked call result (None) does not sort."""
            def emit():
                e.var("lk_sites", e.add(e.hd(H_SITES), e.mul(e.hd(H_S), which)))
                e.var("lk_count", e.hd(H_S))
                marked = lambda k: e.ne(e.ld(e.add(p["lk_sites"], k)), 0)  # noqa: E731
                kind = lambda k: e.rd(e.add(e.add(e.add(p["F"], 6), p["sh_blocks"]), k))  # noqa: E731
                e.var("lk_n", 0)
                e.for_("lk_k", 0, p["lk_count"], lambda: e.if_(marked(p["lk_k"]), lambda: (
                    e.set("lk_n", e.add(p["lk_n"], 1)), e.if_(e.eq(kind(p["lk_k"]), 3), lambda: _bad(e)))))
                w.put(D.T_LIST)
                w.put(p["lk_n"])
                for wanted in (1, 0, 2):
                    e.for_("lk_q", 0, p["lk_count"], lambda wanted=wanted: e.if_(
                        e.both(marked(p["lk_q"]), e.eq(kind(p["lk_q"]), wanted)), lambda: e.call(_FN["storage"], p["lk_q"])))
            return emit

        def legal_orders():
            for family, orders in _ATOMIC_ORDERS.items():
                e.if_(e.eq(x, int(family)), lambda orders=orders: w.const([item.name.lower() for item in orders]))
            e.if_(e.not_(e.either(*(e.eq(x, int(family)) for family in _ATOMIC_ORDERS))), lambda: _bad(e))

        def field_offsets():
            w.seq(D.T_LIST, e.ld(x), lambda k: (w.put(D.T_LIST), w.put(2), w.integer(e.ld(e.add(e.add(x, 1), e.mul(k, 2)))),
                                                 c.h(e.ld(e.add(e.add(x, 2), e.mul(k, 2))))))

        def checked_effect():
            e.var("ce_n", e.sel(e.lt(x, 2), x, 2))  # ``(y, z)[:x]``
            w.put(D.T_LIST)
            w.put(p["ce_n"])
            e.if_(e.le(1, p["ce_n"]), h(y))
            e.if_(e.le(2, p["ce_n"]), h(z))

        def widened():
            """``bits_type(8 * z).cid``: the graph's own type entry that is exactly ``bits<8 * z>`` (a type with no
            references whose body is form 1 and the width, read whole); without one, a CID only the host computes."""
            e.var("wd_t", NONE)
            e.for_("wd_k", 0, e.rd(0), lambda: e.if_(e.both(
                e.eq(e.rd(_field(e, T.POSITION, p["wd_k"])), int(Kind.TYPE)), e.eq(e.rd(e.add(_field(e, T.POSITION, p["wd_k"]), 1)), 0),
                e.eq(_field(e, T.XSTAT, p["wd_k"]), 0), e.eq(_field(e, T.XA, p["wd_k"]), 1), e.eq(_field(e, T.XB, p["wd_k"]), e.mul(z, 8))),
                lambda: e.set("wd_t", p["wd_k"])))
            e.if_(e.eq(p["wd_t"], NONE), lambda: _bad(e), lambda: c.h(p["wd_t"]))

        def checked_type():
            e.if_(e.ne(w4, 0), widened, h(x))

        def operation_name():
            e.if_(e.both(e.le(1, y), e.le(y, max(int(item) for item in Operation))), lambda: w.name("Operation", y), lambda: _bad(e))

        def atomic_values():
            e.if_(e.lt(4, y), lambda: _bad(e))  # ``payload[2:2 + y]``: at most the four payload words past ``y``
            w.seq(D.T_LIST, e.sel(e.lt(y, 4), y, 4), lambda k: c.h(e.ld(e.add(HEADER + H_RPAY + 2, k))))

        def target_type():
            w.put(D.T_LIST)
            w.put(5)
            e.if_(e.eq(x, 0), lambda: w.text("operand"), lambda: e.if_(e.eq(x, 1), lambda: w.text("result"), lambda: _bad(e)))
            w.integer(y)
            lower(TargetValueConstraintKind, z)()
            w.integer(w4)
            w.integer(p["p4"])

        pair_list = lambda first, second: listing(first, second)  # noqa: E731
        sites = {
            "PROVENANCE_PROVEN": ("XAX.MEMORY.PROVENANCE", "MEMORY-PROVENANCE-PROVEN", const("local stack pointer"), ref(x)),
            "LIFETIME_LIVE": ("XAX.MEMORY.USE_AFTER_LIFETIME", "MEMORY-LIFETIME-LIVE", const("live storage"), storage(x)),
            "OWNER_LIVE": ("XAX.MEMORY.USE_AFTER_LIFETIME", "MEMORY-LIFETIME-LIVE", const("live storage owner"), storage(x)),
            "OP_CONTRACT": ("XAX.MEMORY.CONTRACT", "MEMORY-OP-CONTRACT", contract_expected,
                            lambda: (w.put(D.T_TUPLE), w.put(3), w.integer(x), w.integer(y), w.integer(z))),
            "ACCESS_SIZE": ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-ACCESS-SIZE",
                            lambda: e.if_(e.eq(x, NONE), lambda: w.const(list(CHECKED_BYTE_VIEW_WIDTHS)), lambda: w.integer(x)), integer(y)),
            "POINTER_ELEMENT_SIZE": ("XAX.MEMORY.ACCESS_SIZE", "MEMORY-POINTER-ELEMENT-SIZE", const([4, 8]), integer(x)),
            "ALIGNMENT": ("XAX.MEMORY.ALIGNMENT", "MEMORY-ALIGNMENT", fmt("aligned to {}", x), integer(y)),
            "BOUNDS": ("XAX.MEMORY.BOUNDS", "MEMORY-BOUNDS", fmt("at least {} bytes", x), integer(y)),
            "READ_PERMISSION": ("XAX.MEMORY.PERMISSION", "MEMORY-READ-PERMISSION", const("read"), integer(x)),
            "WRITE_PERMISSION": ("XAX.MEMORY.PERMISSION", "MEMORY-WRITE-PERMISSION", const("write"), integer(x)),
            "EFFECT_PROVEN": ("XAX.MEMORY.EFFECT", "MEMORY-EFFECT-PROVEN", const("local memory frontier"), ref(x)),
            "EFFECT_PROVENANCE": ("XAX.MEMORY.PROVENANCE", "MEMORY-EFFECT-PROVENANCE", storage(x), storage(y)),
            "INITIALIZED": ("XAX.MEMORY.UNINITIALIZED", "MEMORY-INITIALIZED", lambda: listing(integer(x), integer(total(x, y, z)))(), intervals(w4)),
            "LOAD_TYPE": ("XAX.MEMORY.VALUE_TYPE", "MEMORY-LOAD-TYPE", pair_list(h(x), h(y)), pair_list(h(z), h(w4))),
            "STORE_TYPE": ("XAX.MEMORY.VALUE_TYPE", "MEMORY-STORE-TYPE", h(x), h(y)),
            "STORE_EFFECT_TYPE": ("XAX.MEMORY.EFFECT_TYPE", "MEMORY-EFFECT-TYPE", const("one matching effect<memory> result"), listing(h(x))),
            "CHECKED_ALIGNMENT": ("XAX.MEMORY.CHECKED_ALIGNMENT", "MEMORY-CHECKED-ALIGNMENT-BOOTSTRAP", const(1), integer(x)),
            "CHECKED_OFFSET": ("XAX.MEMORY.CHECKED_OFFSET", "MEMORY-CHECKED-OFFSET-BITS", const(32), integer(x)),
            "CHECKED_LOAD_TYPE": ("XAX.MEMORY.VALUE_TYPE", "MEMORY-CHECKED-LOAD-TYPE", checked_type, h(y)),
            "CHECKED_STORE_TYPE": ("XAX.MEMORY.VALUE_TYPE", "MEMORY-CHECKED-STORE-TYPE", checked_type, h(y)),
            "CHECKED_EFFECT_TYPE": ("XAX.MEMORY.EFFECT_TYPE", "MEMORY-EFFECT-TYPE", const("matching effect<memory> continuation"), checked_effect),
            "REBASE_ADDRESS_WIDTH": ("XAX.MEMORY.REBASE", "MEMORY-REBASE-ADDRESS-WIDTH", const([32, 64]), integer(x)),
            "REBASE_AUTHORITY": ("XAX.MEMORY.REBASE", "MEMORY-REBASE-NO-AUTHORITY-GAIN", pair_list(h(x), integer(y)), pair_list(h(z), integer(w4))),
            "REBASE_EXTENT": ("XAX.MEMORY.BOUNDS", "MEMORY-REBASE-EXTENT", fmt("1..{}", x), integer(y)),
            "REBASE_ALIGNMENT": ("XAX.MEMORY.ALIGNMENT", "MEMORY-REBASE-ALIGNMENT", fmt("<= {}", x), integer(y)),
            "RETURN_WHOLE": ("XAX.MEMORY.HEAP_VIEW", "HEAP-VIEW-RETURN-WHOLE", const("live base pointer, view, and matching effect"),
                             listing(ref(x, 5), ref(y, 5), ref(z, 5))),
            "RETURN_INITIALIZED": ("XAX.MEMORY.UNINITIALIZED", "HEAP-VIEW-RETURN-INITIALIZED", pair_list(const(0), integer(x)), intervals(y)),
            "LINK_RETURN_TARGET": ("XAX.MEMORY.LINK", "MEMORY-LINK-RETURN-TARGET", const("a new view returned must link into itself"), storage(x)),
            "RETURN_ORDER": ("XAX.MEMORY.HEAP_VIEW", "HEAP-VIEW-RETURN-ORDER", maybe(x, storage(x)), storage(y)),
            "LINK_TARGET_ROOT": ("XAX.MEMORY.LINK", "MEMORY-LINK-TARGET-ROOT-VIEW", const("a whole record view"), pair_list(integer(x), integer(y))),
            "VIEW_ALLOCATION": ("XAX.MEMORY.PROVENANCE", "HEAP-VIEW-ALLOCATION-PROVEN", const("foreign allocator pointer result"), ref(x)),
            "VIEW_OWNER": ("XAX.MEMORY.OWNER", "HEAP-VIEW-OWNER-PROVEN", storage(x), maybe(y, storage(y))),
            "VIEW_ALLOCATOR_EFFECT": ("XAX.MEMORY.EFFECT_TYPE", "HEAP-VIEW-ALLOCATOR-EFFECT", const("effect<memory>"), h(x)),
            "VIEW_ALLOCATOR_EFFECT_PROVEN": ("XAX.MEMORY.PROVENANCE", "HEAP-VIEW-ALLOCATOR-EFFECT-PROVEN", ref(x, 2), ref(y, 2)),
            "VIEW_STATIC_SIZE": ("XAX.MEMORY.BOUNDS", "HEAP-VIEW-STATIC-SIZE", const("constant allocator size"), const(None)),
            "VIEW_BOUNDS": ("XAX.MEMORY.BOUNDS", "HEAP-VIEW-BOUNDS", fmt("1..{}", x), integer(y)),
            "VIEW_ALIGNMENT": ("XAX.MEMORY.ALIGNMENT", "HEAP-VIEW-ALIGNMENT", fmt("power of two <= {}", x), integer(y)),
            "VIEW_TOKEN_TYPE": ("XAX.MEMORY.HEAP_VIEW", "HEAP-VIEW-TOKEN-TYPE",
                                pair_list(integer(x), lambda: w.tagged(D.T_BOOL, e.flag(e.ne(y, 0)))), h(z)),
            "VIEW_EFFECT_TYPE": ("XAX.MEMORY.EFFECT_TYPE", "MEMORY-EFFECT-TYPE", const("effect<memory>"), h(x)),
            "DEALLOCATE_OWNER": ("XAX.MEMORY.OWNER", "HEAP-DEALLOCATE-OWNER-PROVEN", const("live heap owner or heap view"), ref(x)),
            "DEALLOCATE_VIEW_BASE": ("XAX.MEMORY.PROVENANCE", "HEAP-DEALLOCATE-VIEW-BASE", storage(x), when(y, pair_list(storage(z), integer(w4)))),
            "DEALLOCATE_OWNER_TYPE": ("XAX.MEMORY.OWNER", "HEAP-DEALLOCATE-OWNER-TYPE", const("heap owner or heap view"), h(x)),
            "DEALLOCATE_ALLOCATION": ("XAX.MEMORY.PROVENANCE", "HEAP-DEALLOCATE-ALLOCATION", storage(x), maybe(y, storage(y))),
            "FOREIGN_EFFECT_LINEAR": ("XAX.MEMORY.EFFECT_FORK", "MEMORY-EFFECT-LINEAR", const("one consumer"), const(Operation.CALL_FOREIGN.name)),
            "VIEW_CALL_OWNER": ("XAX.MEMORY.OWNER", "HEAP-VIEW-CALL-OWNER", const("live heap view"), ref(x)),
            "VIEW_CALL_BASE": ("XAX.MEMORY.PROVENANCE", "HEAP-VIEW-CALL-BASE", storage(x), when(y, pair_list(storage(z), integer(w4)))),
            "VIEW_CALL_DECLARED_TARGET": ("XAX.MEMORY.LINK", "MEMORY-LINK-CALL-TARGET", const("the declared target view"), maybe(x, storage(x))),
            "VIEW_CALL_SELF_TARGET": ("XAX.MEMORY.LINK", "MEMORY-LINK-CALL-TARGET", const("a view whose links point into itself"), maybe(x, storage(x))),
            "VIEW_CALL_EFFECT_PROVENANCE": ("XAX.MEMORY.PROVENANCE", "MEMORY-EFFECT-PROVENANCE", storage(x), when(y, storage(z))),
            "CALL_EFFECT_LINEAR": ("XAX.MEMORY.EFFECT_FORK", "MEMORY-EFFECT-LINEAR", const("one consumer"), const(Operation.CALL_DIRECT.name)),
            "VIEW_CALL_INITIALIZED": ("XAX.MEMORY.UNINITIALIZED", "HEAP-VIEW-CALL-INITIALIZED", pair_list(const(0), integer(x)), intervals(y)),
            "GROUP_CALL_VIEWS_ONLY": ("XAX.MEMORY.GROUP_CALL", "GROUP-CALL-MEMORY-VIEWS-ONLY", const("memory only as whole heap-view triples"), h(x)),
            "INDIRECT_STACK_POINTERS": ("XAX.CALL.INDIRECT", "INDIRECT-CALL-STACK-POINTERS", const(1), integer(x)),
            "INDIRECT_STACK_OWNERS": ("XAX.CALL.INDIRECT", "INDIRECT-CALL-STACK-PROOF", const("one stack owner input and matching output"),
                                      pair_list(lambda: e.if_(e.ne(x, 0), listing(integer(y)), const([])),
                                                lambda: e.if_(e.ne(z, 0), listing(integer(w4)), const([])))),
            "INDIRECT_POINTER_LIVE": ("XAX.MEMORY.PROVENANCE", "MEMORY-PROVENANCE-PROVEN", const("live local stack pointer"), ref(x)),
            "INDIRECT_STACK_EFFECT_INPUT": ("XAX.CALL.INDIRECT", "INDIRECT-CALL-STACK-PROOF", const("one provenance-matching stack effect input"), const([])),
            "INDIRECT_STACK_EFFECT_OUTPUT": ("XAX.CALL.INDIRECT", "INDIRECT-CALL-STACK-PROOF", const("one matching stack effect output"), const([])),
            "INDIRECT_STACK_PROVENANCE": ("XAX.MEMORY.PROVENANCE", "INDIRECT-CALL-STACK-PROVENANCE", storage(x), when(y, storage(z))),
            "INDIRECT_EFFECT_LINEAR": ("XAX.MEMORY.EFFECT_FORK", "MEMORY-EFFECT-LINEAR", const("one consumer"), const(Operation.CALL_INDIRECT.name)),
            "OP_SUPPORTED": ("XAX.STRUCT.OPERATION", "GRAPH-OP-SUPPORTED", const(list(Operation)), integer(x)),
            "STACK_OWNER_TYPE": ("XAX.MEMORY.OWNER_TYPE", "MEMORY-OWNER-TYPE", const("resource<stack-storage,live>"), h(x)),
            "STACK_EFFECT_TYPE": ("XAX.MEMORY.EFFECT_TYPE", "MEMORY-EFFECT-TYPE", const("effect<memory>"), h(x)),
            "ADDRESS_WAIVER": ("XAX.MEMORY.ADDRESS_EXPOSE", "MEMORY-ADDRESS-EXPOSE-WAIVER", const(1), integer(x)),
            "ADDRESS_WIDTH": ("XAX.MEMORY.ADDRESS_EXPOSE", "MEMORY-ADDRESS-WIDTH", const([32, 64]), integer(x)),
            "RAW_WAIVER": ("XAX.MEMORY.RAW_WAIVER", "MEMORY-RAW-WAIVER", const("nonzero subset of alignment|initialization"), integer(x)),
            "RAW_UNSAFE_EFFECT": ("XAX.MEMORY.RAW_EFFECT", "MEMORY-RAW-UNSAFE-EFFECT", const(["effect<memory>", "effect<unsafe>"]), pair_list(h(x), h(y))),
            "RAW_EFFECT_CONTINUATION": ("XAX.MEMORY.RAW_EFFECT", "MEMORY-RAW-EFFECT-CONTINUATION", pair_list(h(x), h(y)), pair_list(h(z), h(w4))),
            "CALL_POINTER_PROVEN": ("XAX.MEMORY.PROVENANCE", "MEMORY-PROVENANCE-PROVEN", const("live local stack pointer"), ref(x)),
            "CALL_REBASE_STATIC": ("XAX.MEMORY.REBASE", "MEMORY-REBASE-STATIC-ONLY", const("statically positioned pointer"), integer(x)),
            "CALL_POINTER_BOUNDS": ("XAX.MEMORY.BOUNDS", "MEMORY-CALL-POINTER-BOUNDS", fmt("at least {} bytes", x), integer(y)),
            "CALL_PERMISSION": ("XAX.MEMORY.PERMISSION", "MEMORY-CALL-PERMISSION", integer(x), integer(y)),
            "CALL_OWNER_PROVEN": ("XAX.MEMORY.OWNER", "MEMORY-OWNER-PROVEN", const("live stack owner"), ref(x)),
            "CALL_POINTER_PROVENANCE": ("XAX.MEMORY.PROVENANCE", "MEMORY-CALL-POINTER-PROVENANCE", storage(x), storage(y)),
            "CALL_EFFECT_PROVENANCE": ("XAX.MEMORY.PROVENANCE", "MEMORY-EFFECT-PROVENANCE", storage(x), maybe(y, storage(y))),
            "CALL_INITIALIZED": ("XAX.MEMORY.UNINITIALIZED", "MEMORY-CALL-INITIALIZED", lambda: listing(integer(x), integer(total(x, y)))(), intervals(z)),
            "INDIRECT_TARGET": ("XAX.CALL.INDIRECT", "INDIRECT-CALL-TARGET", const("function pointer operand"), const(0)),
            "INDIRECT_TARGET_TYPE": ("XAX.CALL.INDIRECT", "INDIRECT-CALL-TARGET-TYPE", const("ptr<opaque<function>>"), h(x)),
            "ATOMIC_MEMORY_EFFECT": ("XAX.ATOMIC.CONTRACT", "ATOMIC-MEMORY-EFFECT", const("matching effect<memory> continuation"), pair_list(h(x), h(y))),
            "ATOMIC_WRITE_PERMISSION": ("XAX.MEMORY.PERMISSION", "ATOMIC-WRITE-PERMISSION", const("write"), integer(x)),
            "ATOMIC_READ_PERMISSION": ("XAX.MEMORY.PERMISSION", "ATOMIC-READ-PERMISSION", const("read"), integer(x)),
            "ATOMIC_VALUE_TYPE": ("XAX.ATOMIC.CONTRACT", "ATOMIC-VALUE-TYPE", h(x), atomic_values),
            "ATOMIC_RESULT_TYPE": ("XAX.ATOMIC.CONTRACT", "ATOMIC-RESULT-TYPE", h(x), listing(h(y))),
            "ATOMIC_CMPXCHG_RESULT": ("XAX.ATOMIC.CONTRACT", "ATOMIC-CMPXCHG-RESULT", pair_list(h(x), const("bits<1>")), pair_list(h(y), h(z))),
            "ATOMIC_REBASE": ("XAX.MEMORY.REBASE", "MEMORY-REBASE-STATIC-ONLY", const("statically positioned pointer"), integer(x)),
            "ATOMIC_LINK": ("XAX.MEMORY.LINK", "MEMORY-LINK-NO-ATOMICS", const("non-link element"), h(x)),
            "ATOMIC_FENCE_EFFECT": ("XAX.ATOMIC.CONTRACT", "ATOMIC-FENCE-EFFECT", const("one matching effect frontier"),
                                    pair_list(lambda: (w.put(D.T_TUPLE), w.put(1), w.cid_bytes(x)), lambda: (w.put(D.T_TUPLE), w.put(1), w.cid_bytes(y)))),
            "ATOMIC_INITIALIZED": ("XAX.MEMORY.UNINITIALIZED", "ATOMIC-INITIALIZED", lambda: listing(integer(x), integer(total(x, y)))(), intervals(z)),
            "LINK_MAKE_RECORD": ("XAX.MEMORY.LINK", "MEMORY-LINK-MAKE-RECORD", const("pointer to a storage record"), h(x)),
            "LINK_MAKE_START": ("XAX.MEMORY.LINK", "MEMORY-LINK-MAKE-RECORD-START", fmt("record start (stride {})", x),
                                listing(integer(y), integer(z), integer(w4))),
            "LINK_MAKE_TYPE": ("XAX.MEMORY.LINK", "MEMORY-LINK-MAKE-TYPE", const("link"), h(x)),
            "LINK_FOLLOW_ROOT": ("XAX.MEMORY.LINK", "MEMORY-LINK-FOLLOW-ROOT-VIEW", const("the storage's whole record view"), pair_list(integer(x), integer(y))),
            "LINK_FOLLOW_PROVENANCE": ("XAX.MEMORY.LINK", "MEMORY-LINK-FOLLOW-PROVENANCE", storage(x), when(y, maybe(z, storage(z)))),
            "LINK_FOLLOW_AUTHORITY": ("XAX.MEMORY.LINK", "MEMORY-LINK-FOLLOW-NO-AUTHORITY-GAIN", pair_list(h(x), integer(y)), pair_list(h(z), integer(w4))),
            "LINK_FOLLOW_ALIGNMENT": ("XAX.MEMORY.ALIGNMENT", "MEMORY-LINK-FOLLOW-ALIGNMENT", fmt("<= {}", x), integer(y)),
            "LINK_TARGET_PARAMETERS": ("XAX.MEMORY.LINK", "MEMORY-LINK-TARGET-DECLARATION", const("two borrowed view parameters of the entry block"),
                                       pair_list(ref(x, 4), ref(y, 4))),
            "LINK_TARGET_RECORDS": ("XAX.MEMORY.LINK", "MEMORY-LINK-TARGET-DECLARATION", const("a link-bearing view and a record view"),
                                    pair_list(maybe(x, h(x)), maybe(y, h(y)))),
            "LINK_STORE_PROVENANCE": ("XAX.MEMORY.LINK", "MEMORY-LINK-STORE-PROVENANCE", const("null or a link into this storage"), when(x, maybe(y, storage(y)))),
            "POINTER_STORE_LOCAL": ("XAX.MEMORY.PROVENANCE", "MEMORY-POINTER-STORE-LOCAL-PROVENANCE", const("provenance-free pointer"),
                                    lambda: _storage_pair(e, w, x)),
            "LINK_RECORD_ONLY": ("XAX.MEMORY.RECORD", "MEMORY-LINK-RECORD-ONLY", const("record element with link fields"), h(x)),
            "RECORD_EXTENT": ("XAX.MEMORY.RECORD", "MEMORY-RECORD-EXTENT", fmt("multiple of {}", x), integer(y)),
            "RECORD_FIELD_OFFSET": ("XAX.MEMORY.RECORD", "MEMORY-RECORD-FIELD-OFFSET", field_offsets, pair_list(integer(y), h(z))),
            "RECORD_OFFSET_STRIDE": ("XAX.MEMORY.RECORD", "MEMORY-RECORD-OFFSET-STRIDE", fmt("multiple of {}", x), integer(y)),
            "ADDRESS_AUTHORITY": ("XAX.MEMORY.PERMISSION", "MEMORY-ADDRESS-NO-AUTHORITY-GAIN", pair_list(h(x), integer(y)), pair_list(h(z), integer(w4))),
            "ADDRESS_ALIGNMENT": ("XAX.MEMORY.ALIGNMENT", "MEMORY-ADDRESS-ALIGNMENT", fmt("<= {}", x), integer(y)),
            "BYTE_ADDRESSABLE": ("XAX.MEMORY.VALUE_TYPE", "MEMORY-BYTE-ADDRESSABLE-VALUE", const("bits or float scalar with whole-byte width"), h(x)),
            "LINK_STORAGE_FOREIGN": ("XAX.MEMORY.LINK", "MEMORY-LINK-STORAGE-FOREIGN", const("deallocation only"), storage(x)),
            "LINK_TARGET_OUTLIVES": ("XAX.MEMORY.LINK", "MEMORY-LINK-TARGET-OUTLIVES", const("dependent storage ended first"), pair_list(storage(x), storage(y))),
            "CHECKED_INITIALIZED": ("XAX.MEMORY.UNINITIALIZED", "MEMORY-CHECKED-LOAD-INITIALIZED-VIEW", pair_list(integer(x), integer(y)), intervals(z)),
            "ADDRESS_BOUNDS": ("XAX.MEMORY.BOUNDS", "MEMORY-ADDRESS-BOUNDS", fmt("<= {}", x), integer(y)),
            "LIFETIME_LEAK": ("XAX.MEMORY.LIFETIME_LEAK", "MEMORY-LIFETIME-EXPLICIT-END", leak(0), leak(1)),
            "OWNER_PROVEN": ("XAX.MEMORY.OWNER", "MEMORY-OWNER-PROVEN", const("local stack owner"), ref(x)),
            "ALLOCATION_ALIGNMENT": ("XAX.MEMORY.ALIGNMENT", "MEMORY-ALIGNMENT", fmt("<= {}", x), integer(y)),
            "ATOMIC_RMW_KIND": ("XAX.ATOMIC.RMW", "ATOMIC-RMW-KIND", const(list(AtomicRmwKind)), fmt("{} is not a valid AtomicRmwKind", x)),
            "ATOMIC_CMPXCHG_STRENGTH": ("XAX.ATOMIC.CMPXCHG", "ATOMIC-CMPXCHG-STRENGTH", const(list(CompareExchangeStrength)),
                                        fmt("{} is not a valid CompareExchangeStrength", x)),
            "ATOMIC_SCOPE_ENUM": ("XAX.ATOMIC.SCOPE", "ATOMIC-SCOPE-ENUM", const(list(AtomicScope)), fmt("{} is not a valid AtomicScope", x)),
            "ATOMIC_ORDER_ENUM": ("XAX.ATOMIC.ORDER", "ATOMIC-ORDER-ENUM", const("portable atomic family/order"), fmt("{} is not a valid AtomicOrder", x),
                                  const("atomic")),
            "ATOMIC_ORDER_LEGAL": ("XAX.ATOMIC.ORDER", "ATOMIC-ORDER-LEGAL", legal_orders, lower(AtomicOrder, y), lower(AtomicFamily, x)),
            "ATOMIC_FAILURE_ORDER": ("XAX.ATOMIC.ORDER", "ATOMIC-CMPXCHG-FAILURE-ORDER", const(["relaxed", "acquire", "seq_cst"]), lower(AtomicOrder, x),
                                     const("cmpxchg")),
            "ATOMIC_FAILURE_STRONGER": ("XAX.ATOMIC.ORDER", "ATOMIC-CMPXCHG-FAILURE-NOT-STRONGER", lower(AtomicOrder, x), lower(AtomicOrder, y),
                                        const("cmpxchg")),
            "TARGET_ATTRIBUTES": ("XAX.TARGET.OPERATION", "TARGET-OPERATION-ATTRIBUTES", const(4), integer(x)),
            "TARGET_SCOPE_ENUM": ("XAX.TARGET.OPERATION", "TARGET-OPERATION-SCOPE-ENUM", const([item.value for item in AtomicScope]), integer(x)),
            "TARGET_ARITY": ("XAX.TARGET.OPERATION", "TARGET-OPERATION-ARITY", pair_list(integer(x), integer(y)), pair_list(integer(z), integer(w4))),
            "TARGET_TYPE": ("XAX.TARGET.OPERATION", "TARGET-OPERATION-TYPE", target_type, h(p["p5"])),
        }
        assert set(sites) | set(DECLINED_MEMORY_SITES) | {"EFFECT_LINEAR"} == set(MEMORY_SITES), set(MEMORY_SITES) - set(sites)

        def effect_linear():
            code = lambda name: lambda: _four(e, w, name, "MEMORY-EFFECT-LINEAR", const("one consumer"), operation_name)  # noqa: E731
            e.if_(e.eq(x, int(Operation.STACK_END)), code("XAX.MEMORY.USE_AFTER_LIFETIME"), code("XAX.MEMORY.EFFECT_FORK"))
            e.set("written", 1)

        if part == 0:
            e.if_(e.eq(p["msite"], M["EFFECT_LINEAR"]), effect_linear)
        for name, (code, rule, expected, actual, *entity) in list(sites.items())[part::MEMORY_PARTS]:
            e.if_(e.eq(p["msite"], M[name]), lambda code=code, rule=rule, expected=expected, actual=actual, entity=entity: (
                _four(e, w, code, rule, expected, actual, entity[0] if entity else None), e.set("written", 1)))
        e.give(p["written"])
    return _function(("mop",), build, tables)


def _storage_pair(e: E, w: R.Writer, site):
    """``list(storages[site][:2])``: the storage's two words as a list (a call result's None does not slice)."""
    p = e.p
    e.var("sp_kind", e.rd(e.add(e.add(e.add(p["F"], 6), p["sh_blocks"]), e.sel(e.lt(site, p["sh_sites"]), site, 0))))
    e.if_(e.either(e.le(p["sh_sites"], site), e.eq(p["sp_kind"], 3)), lambda: _bad(e))
    # ``storages[site]`` as a tuple, rewritten in place as a list: its tag word is the first one the call writes.
    e.var("sp_at", e.ld(OUTCOME_AT + O_CURSOR))
    e.call(_FN["storage"], site)
    e.if_(e.ne(e.ld(p["sp_at"]), D.T_NONE), lambda: e.st(p["sp_at"], D.T_LIST))


# -- the outcome ------------------------------------------------------------------------------------------------------

def _outcome(tables):
    """``_parse_graph``'s outcome over the typing program's decisions, in its order (see the module docstring)."""
    def build(e: E):
        p = e.p
        w = _writer(e)
        c = _Context(e, w)
        e.st(OUTCOME_AT + O_STATUS, G_DECLINE)
        e.var("here", 0)  # the first pass's position (``O_POS``)
        e.st(OUTCOME_AT + O_POS, 0)
        e.var("keys", e.rd(e.ld(T.PASS_NODES_AT)))
        shape = _Shape(e)
        blocks, entry = p["sh_blocks"], p["sh_entry"]
        e.var("verdicts", e.add(2, p["keys"]))  # block verdicts, then the memory-free flag
        clear = e.both(e.lt(e.add(e.add(p["verdicts"], blocks), 2), OUTCOME_AT), e.lt(ARRAYS_END, e.sub(T.TERMINATOR_RECORDS, e.mul(blocks, 4))))
        e.var("term", NONE)  # G_ACCEPT, G_REJECT, G_DECLINE once decided
        e.if_(e.either(e.eq(p["sh_ok"], 0), e.not_(clear)), lambda: e.set("term", G_DECLINE))

        def decide(status):
            e.set("term", status)
            e.st(OUTCOME_AT + O_POS, p["here"])

        def reject(write):
            """``write()`` gives 1 when it wrote the record, else the outcome is a decline."""
            e.var("rj", write())
            decide(e.sel(e.ne(p["rj"], 0), G_REJECT, G_DECLINE))

        # skip_passes: the typing program alone, or the facts engine with every terminator typed, proves the graph.
        e.var("proven", 0)
        e.for_("pv", 0, p["keys"], lambda: e.if_(e.eq(e.ld(e.add(2, p["pv"])), T.PROVEN), lambda: e.set("proven", e.add(p["proven"], 1))))
        e.var("terms_proven", 1)
        e.for_("pt", 0, blocks, lambda: e.if_(e.ne(e.ld(e.add(p["verdicts"], p["pt"])), T.PROVEN), lambda: e.set("terms_proven", 0)))
        fact_free = e.both(e.eq(e.ld(e.add(p["verdicts"], blocks)), 1), e.eq(p["proven"], p["sh_nodes"]), e.ne(p["terms_proven"], 0))
        engine = e.eq(e.hd(H_STATUS), ACCEPTED)
        e.var("skip", e.flag(e.either(fact_free, e.both(engine, e.ne(p["terms_proven"], 0)))))
        e.if_(e.ne(e.ld(OUTCOME_AT + O_MODE), 0), lambda: e.set("skip", 0))  # a trimmed graph: the bootstrap's passes run
        e.var("memory", e.hd(H_REJECT))  # the engine's rejection site (0: none)
        at = lambda pass_, block_, node_: e.both(e.ne(p["memory"], 0), e.eq(e.hd(H_RPASS), pass_), e.eq(e.hd(H_RBLOCK), block_),  # noqa: E731
                                                 e.eq(e.hd(H_RNODE), node_))

        def memory():
            reject(lambda: e.call(_FN["memory"]))

        def linear():
            e.if_(e.ne(e.hd(H_LREJ), 0), lambda: reject(lambda: e.call(_FN["linear"])), lambda: e.if_(
                e.eq(e.hd(H_LINEAR), 1), lambda: decide(G_ACCEPT), lambda: decide(G_DECLINE)))

        # The facts engine decided memory (it accepted, or found the first memory rejection), or no type the fact
        # system tracks occurs (memory-free: the bootstrap's fact checks record and reject nothing).
        e.var("engine_ok", e.flag(e.either(engine, e.ne(p["memory"], 0))))
        memory_free = e.eq(e.ld(e.add(p["verdicts"], blocks)), 1)

        def passes():
            e.if_(e.both(e.eq(p["engine_ok"], 0), e.not_(memory_free)), lambda: decide(G_DECLINE))

            def block():
                b = e.rd(e.add(p["sh_order"], p["po"]))
                e.var("pb", b)
                e.set("here", e.mul(p["po"], 1 << 32))

                def stack_entry():
                    e.var("se_pos", shape.word("bpos", p["pb"]))
                    e.for_("se_k", 0, e.rd(e.add(p["se_pos"], 1)), lambda: e.if_(
                        e.ne(_field(e, T.STACKOWNER, e.rd(e.add(e.add(p["se_pos"], 2), p["se_k"]))), 0), lambda: decide(G_DECLINE)))

                e.if_(e.eq(p["pb"], entry), stack_entry)

                def node():
                    e.set("here", e.add(e.mul(p["po"], 1 << 32), p["pn"]))
                    pos = shape.node_pos(p["pb"], p["pn"])
                    e.var("np", pos)
                    e.var("nop", e.rd(p["np"]))
                    e.var("nkey", e.rd(e.add(p["np"], 1)))
                    known = e.both(e.le(1, p["nop"]), e.le(p["nop"], max(int(item) for item in Operation)))

                    def unsupported():
                        _begin(e)
                        _four(e, w, "XAX.STRUCT.OPERATION", "GRAPH-OP-SUPPORTED", lambda: w.const(list(Operation)), lambda: w.integer(p["nop"]))
                        decide(G_REJECT)

                    memory_here = at(1, p["pb"], p["pn"])
                    # The engine's operation-code rejection comes before the bootstrap's own check.
                    e.if_(e.both(memory_here, e.eq(p["memory"], M["OP_SUPPORTED"])), memory)
                    e.if_(e.eq(p["term"], NONE), lambda: e.if_(e.eq(p["nop"], 0), lambda: decide(G_DECLINE), lambda: e.if_(e.not_(known), unsupported)))

                    def typed():
                        verdict = e.ld(e.add(2, p["nkey"]))
                        e.var("nv", verdict)
                        e.if_(e.eq(p["nv"], T.REJECTED), lambda: reject(lambda: e.call(_FN["node"], p["nkey"])), lambda: e.if_(
                            e.ne(p["nv"], T.PROVEN), lambda: decide(G_DECLINE)))

                    def checks():
                        e.if_(at(1, p["pb"], p["pn"]), memory)
                        engine_domain = e.both(e.ne(p["engine_ok"], 0), e.either(*(e.eq(p["nop"], code) for code in ENGINE_OPERATIONS)))
                        e.if_(e.eq(p["term"], NONE), lambda: e.if_(e.ne(p["nkey"], NONE), typed, lambda: e.if_(
                            e.not_(engine_domain), lambda: decide(G_DECLINE))))

                    e.if_(e.eq(p["term"], NONE), checks)

                e.for_("pn", 0, shape.word("bnodes", p["pb"]), lambda: e.if_(e.eq(p["term"], NONE), node))

                def terminator():
                    e.set("here", e.add(e.mul(p["po"], 1 << 32), shape.word("bnodes", p["pb"])))
                    e.if_(at(1, p["pb"], shape.word("bnodes", p["pb"])), memory)  # a stack-owner entry's late ones decline above
                    record = e.ld(e.sub(T.TERMINATOR_RECORDS, e.mul(p["pb"], 4)))

                    def written():
                        _begin(e)
                        _terminator_record(e, w, c, p["pb"], blocks)
                        decide(e.sel(e.ne(e.ld(OUTCOME_AT + O_BAD), 0), G_DECLINE, G_REJECT))

                    e.if_(e.eq(p["term"], NONE), lambda: e.if_(e.ne(record, 0), written, lambda: e.if_(
                        e.ne(e.ld(e.add(p["verdicts"], p["pb"])), T.PROVEN), lambda: decide(G_DECLINE))))

                e.if_(e.eq(p["term"], NONE), terminator)

            e.for_("po", 0, blocks, lambda: e.if_(e.eq(p["term"], NONE), block))
            e.set("here", POS_LATE)
            # Past the first pass: the engine's rejection in a later pass, else every check held (later passes
            # repeat them) and linear flow decides.
            e.if_(e.eq(p["term"], NONE), lambda: e.if_(e.ne(p["memory"], 0), memory, linear))

        e.if_(e.eq(p["term"], NONE), lambda: e.if_(e.ne(p["skip"], 0), lambda: (e.set("here", POS_LATE), linear()), passes))
        e.st(OUTCOME_AT + O_STATUS, e.sel(e.eq(p["term"], NONE), G_DECLINE, p["term"]))
        e.give(0)
    return _function((), build, tables)


def build_functions(tables=None):
    """``(outcome function, objects)``: the outcome and its helpers, for the typing program."""
    objects = []

    def add(name, made):
        function, items = made
        _FN[name] = function
        objects.extend(items)

    add("put", R.put_function(OUTCOME_AT + O_CURSOR, RECORD_END))
    add("cid", _function(("o",), R.cid_function(TypeTable, _FN), tables))
    for part in range(NODE_PARTS):
        add(f"node{part}", _node_part(tables, part))
    add("node_cross", _node_cross(tables))
    add("node", _node(tables))
    add("linear", _linear(tables))
    add("storage", _storage(tables))
    add("ref", _ref(tables))
    add("intervals", _intervals(tables))
    for part in range(MEMORY_PARTS):
        add(f"memory{part}", _memory_part(tables, part))
    add("memory", _memory(tables))
    add("outcome", _outcome(tables))
    return _FN["outcome"], tuple(objects)


# -- host side ---------------------------------------------------------------------------------------------------------

def decode_outcome(read, graph_cid: bytes):
    """``("accept", None)``, ``("reject", Diagnostic)``, or ``("decline", None)`` from the typing program's output
    (``read(start, count)``)."""
    status, cursor, entity = read(OUTCOME_AT, 3)
    if status == G_ACCEPT:
        return "accept", None
    if status != G_REJECT:
        return "decline", None
    words = read(RECORD_AT, cursor - RECORD_AT)
    if entity == ENTITY_GRAPH:
        code_end = 2 + (words[1] + 7) // 8  # the code: STR length packed-bytes
        words = [*words[:code_end], D.T_CID, *(int.from_bytes(graph_cid[k:k + 8], "big") for k in range(0, 32, 8)), *words[code_end:]]
    return "reject", D.decode_record(words)
