"""Self-hosting step S15d.1 (ADR-304): semantic transactions on a canonical store, as XAX functions.

The production compiler's ``edit <store> <edit record> <output store>`` applies a transaction to a verified store and
writes the store it makes, as ``xax_workspace.Workspace.commit`` does for the same mutations: each mutated graph is
re-encoded, every transitive user (graph, function, module, program root, package, build request) is rebuilt with its
references in CID order and its body re-indexed, unreachable objects are dropped, and the S9 writer writes the store.
These functions have the S10e helper convention (``xax_selfhost_facts._function``): the input view is the store
verifier's object table (``index_objects`` located each record in ``OBJAT``), the output view the driver's workspace,
from ``EB`` on.

The edit record (``RECORD_MAGIC``), a tooling carrier, not program source:

    magic "XAXEDIT1" | expected root CID (32 bytes; all zero: no root precondition) | ULEB count | mutation*
    mutation: ULEB kind | function CID (32 bytes) | ULEB block | ULEB node | operands
      SET_OPERATION (1): ULEB expected operation, ULEB operation   (``SetOperation``: wrapping add, sub, mul)
      SET_CONSTANT (2):  ULEB expected value, ULEB value             (``SetConstant``: an integer constant node)
    S15d.4a (ADR-312): REPLACE_REFERENCE (3): owner CID, old child CID, new child CID; then the supplied objects.
    S15d.4b (ADR-314), the workspace's structural mutations, a value being ``ULEB tag (0 parameter, 1 node result, 2 an
    insertion's result) | ULEB block or local id | ULEB index or result | (tag 1) ULEB result``:
      REPLACE_USE (4):     ULEB operand, expected value, value                         (``ReplaceUse``)
      DELETE_NODE (5):     nothing more                                                 (``DeleteNode``)
      INSERT_NODE (6):     ULEB local id, ULEB operation, ULEB count, values, result type CID, ULEB has value
                           [ULEB value], ULEB attribute count, ULEBs; inserted before the node (``InsertPureNode``)
      SET_RESULT_TYPE (7): ULEB result, expected type CID, type CID                     (``SetResultType``)
      DISCONNECT_EDGE (8), CONNECT_EDGE (9): the node field is the edge; ULEB argument, value

A mutation names its node by the function's CID and the node's block and position, so a changed function is stale by
construction; the expected root and the expected operation or value are its other preconditions.

* ``begin`` parses the record, checks every precondition with the workspace's diagnostics, makes each new constant,
  and marks the affected objects (the mutated graphs and their transitive users).  The structural preconditions are
  the workspace's (``_mutate_function``), quoted exactly; the candidate's verification is ``verify``'s, run on ``edit``'s output
  (the workspace's commit verifies inside the transaction).
* ``next`` gives the next object whose references are all final: a new constant, then each affected object once
  all its affected references are done.  It writes the object's CID preimage (after the domain) at ``PRE`` and where
  the driver puts its CID (``E_SLOT``).
* ``reach`` marks the old objects the new root still reaches (``COPY``): with the new objects, the output store.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_compiler import ATTRIBUTE_OPERATIONS, ENTITY_OPERATIONS, Kind, Operation, uleb
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_semantic import _cid_word, _kind, _nrefs, _payload, _ref

RECORD_MAGIC = b"XAXEDIT1"
SET_OPERATION, SET_CONSTANT, REPLACE_REFERENCE = 1, 2, 3
# S15d.4b (ADR-314): the workspace's graph mutations (``xax_workspace``'s ReplaceUse, DeleteNode, InsertPureNode,
# SetResultType, DisconnectEdgeArgument, ConnectEdgeArgument), each naming its node or edge by function CID and block.
REPLACE_USE, DELETE_NODE, INSERT_NODE, SET_RESULT_TYPE, DISCONNECT_EDGE, CONNECT_EDGE = 4, 5, 6, 7, 8, 9
STRUCTURAL = (REPLACE_USE, DELETE_NODE, INSERT_NODE, SET_RESULT_TYPE, DISCONNECT_EDGE, CONNECT_EDGE)
VALUE_PARAMETER, VALUE_RESULT, VALUE_INSERTED = 0, 1, 2  # a record value: its tag, then block and index (and result), or local id and result
EB = 52 << 20  # workspace words
(E_STATUS, E_LENGTH, E_MUTATIONS, E_EXTRAS, E_EXTRAS_DONE, E_OBJECTS, E_SLOT, E_KIND, E_NREFS, E_REFS_AT, E_BODY_AT, E_BODY_LENGTH,
 E_PRE_LENGTH, E_OBJECT, E_ROOT, E_AFFECTED, E_PRE_AT, E_NEW, E_BATCH_LENGTH, E_PRE_END) = range(20)
OK, REJECT, MORE, DONE = 0, 1, 2, 3
EC = EB  # control words (64)
OPF = EB + 64  # per operation code: 1 entity, 2 attributes
MUT = EB + 256  # 12 words per mutation: kind, function, graph, block, node, expected, value, extra, then (S15d.4b) four more
MUT_WORDS, MUT_LIMIT = 12, 256
# S15d.4b (ADR-314): a structural mutation's row: field 5 the record word of its payload, field 6 its operand, result,
# argument or local id, field 7 located (its node's operation + 2^32), then a new constant (``M_EXTRA``), and what the
# locating scan found: a count (operands, results, an edge's arguments), a comparison (1 equal, 2 differs; a deleted
# node's first use; the old result type + 1), and a value (a use's result; the block's edge count).
M_EXTRA, M_COUNT, M_FOUND, M_USE = 8, 9, 10, 11
NODE_KINDS = (SET_OPERATION, SET_CONSTANT, REPLACE_USE, DELETE_NODE, INSERT_NODE, SET_RESULT_TYPE)
INSERTABLE = (Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP, Operation.BIT_AND, Operation.BIT_OR,
              Operation.BIT_XOR, Operation.INT_COMPARE, Operation.INT_ZERO_EXTEND, Operation.INT_TRUNCATE)  # ``xax_workspace._INSERTABLE``
PURE = (Operation.CONSTANT, Operation.ADD_WRAP, Operation.SUB_WRAP, Operation.MUL_WRAP)  # what DeleteNode removes
# 16 words per new object of the transaction's own: type, length, value, alias, CID (4) for a new constant; S15d.4a
# (ADR-312): a supplied object has X_SUPPLIED set and its kind, reference count, references, body length and body (record
# words), and whether ``reach`` reached it.
EXTRA = MUT + MUT_WORDS * MUT_LIMIT
EXTRA_WORDS = 16
X_SUPPLIED, X_KIND, X_NREFS, X_REFS, X_BODY_LENGTH, X_BODY, X_REACHED = range(8, 15)
# S15d.4b: a new constant whose type the record names (an inserted constant, a constant node's new result type): field
# 0 is NONE and ``X_TYPE_AT`` the record word of that type's CID (resolved once the supplied objects have CIDs).
X_TYPE_AT = 15
ENTITY_AT = EXTRA + EXTRA_WORDS * MUT_LIMIT  # per mutation: its node's entity reference index + 1 (0: none)
STATE = EB + (1 << 17)  # per object: 0 untouched, 1 affected, 2 rebuilt
NEWCID = STATE + (1 << 16)  # 4 words per object
ALIAS = NEWCID + (1 << 18)  # per object: the old object whose CID its new version has, or NONE
COPY = ALIAS + (1 << 16)  # per object: 1 when the output store keeps it
RSTART = COPY + (1 << 16)  # per rebuilt object: its new references' sources
RCOUNT = RSTART + (1 << 16)
REFL = RCOUNT + (1 << 16)  # the sources: an object position, or EXTRA_TAG + extra index
REFL_LIMIT = 1 << 20
RC_LIMIT = 1 << 16  # distinct references of one object
SR = REFL + REFL_LIMIT  # an object's references, sorted and distinct: CID (4 words) and source
SRS = SR + 4 * RC_LIMIT
STACK = SRS + RC_LIMIT  # reachability
BODY = STACK + (1 << 17)  # the re-encoded body, one byte per word
BODY_LIMIT = 1 << 22
PRE = BODY + BODY_LIMIT  # every new object's CID preimage after the domain, one byte per word, in order
PRE_LIMIT = 1 << 24
NEWT = PRE + PRE_LIMIT  # per new object: preimage start, length, references at, count, body at, length, kind, object, alias
NEWT_WORDS, NEWT_LIMIT = 9, 1 << 16
BATCH = NEWT + NEWT_WORDS * NEWT_LIMIT  # the S9 writer's batch, one byte per word (``xax_selfhost_writer``'s layout)
BATCH_LIMIT = (1 << 26) - 4096  # the writer's input view less its slack (S15e.4, ADR-322: 64 MiB, the writer's since ADR-319)
BATCH_AT = 58  # control word: the batch bytes written
EXTRA_TAG = 1 << 40
# The edit record, one byte per word (S15d.4a: past the batch, room for supplied objects).
EIN, EIN_LIMIT = 238 << 20, 16 << 20  # S15e.4 (ADR-322): above the batch, far above the typing tables (from 128M words)
assert ENTITY_AT + MUT_LIMIT <= STATE and BATCH + BATCH_LIMIT <= EIN and EIN + EIN_LIMIT <= __import__("xax_selfhost_facts").HEADER
ENTITY = sorted(int(op) for op in ENTITY_OPERATIONS)
ATTRIBUTE = sorted(int(op) for op in ATTRIBUTE_OPERATIONS)
WRAPPING = (int(Operation.ADD_WRAP), int(Operation.SUB_WRAP), int(Operation.MUL_WRAP))
LOCATE, COLLECT, EMIT = 0, 1, 2  # (S15d.4b: SKIP, 3, below)


def _ctrl(e: E, field: int):
    return e.ld(EC + field)


def _set(e: E, field: int, value):
    e.st(EC + field, value)


def _graph_body(e: E, o):
    """``(length, first byte word)`` of graph ``o``'s body (after its stream in the object table)."""
    pay = _payload(e, o)
    at = e.add(e.add(pay, 1), e.rd(pay))
    return e.rd(at), e.add(at, 1)


def _plain_body(e: E, o):
    pay = _payload(e, o)
    return e.rd(pay), e.add(pay, 1)


def _body_of(e: E, o, name: str):
    """Declare ``{name}_length`` and ``{name}_at``: object ``o``'s body."""
    p = e.p
    e.var(f"{name}_length", 0)
    e.var(f"{name}_at", 0)

    def graph():
        length, at = _graph_body(e, o)
        e.set(f"{name}_length", length)
        e.set(f"{name}_at", at)

    def plain():
        length, at = _plain_body(e, o)
        e.set(f"{name}_length", length)
        e.set(f"{name}_at", at)

    e.if_(e.eq(_kind(e, o), int(Kind.GRAPH_FRAGMENT)), graph, plain)
    return p[f"{name}_length"], p[f"{name}_at"]


# The cursor lives in control words, so the scanners are functions of their own: ``CUR`` (the object table word read
# next), ``OUT`` (the ``BODY`` word written next), ``MODE`` (LOCATE, COLLECT, EMIT).
CUR, OUT, MODE, KEY, HIT, RCUR = 48, 49, 50, 52, 56, 57
# S15d.4b: a value being written (tag, then two or three fields), and the graph being scanned; SKIP scans a deleted
# node without collecting or writing anything.
V_TAG, V_A, V_B, V_C, GRAPH_CUR = 20, 21, 22, 23, 24
SKIP = 3
_F: dict = {}


def _call(e: E, name: str, *arguments):
    return e.call(_F[name], *arguments)


def _put(e: E, value):
    e.var("put_at", _ctrl(e, OUT))
    e.st(e.add(BODY, e.p["put_at"]), value)
    _set(e, OUT, e.add(e.p["put_at"], 1))


def _uleb_read_function():
    """The next ULEB at ``CUR``; ``CUR`` moves past it."""
    def build(e: E):
        p = e.p
        e.var("cur", _ctrl(e, CUR))
        e.var("u_value", 0)
        e.var("u_shift", 1)
        e.var("u_more", 1)

        def step():
            e.var("u_byte", e.rd(p["cur"]))
            e.set("u_value", e.add(p["u_value"], e.mul(e.and_(p["u_byte"], 127), p["u_shift"])))
            e.set("u_shift", e.mul(p["u_shift"], 128))
            e.set("u_more", e.flag(e.le(128, p["u_byte"])))
            e.set("cur", e.add(p["cur"], 1))

        e.while_(lambda: e.ne(p["u_more"], 0), step)
        _set(e, CUR, p["cur"])
        e.give(p["u_value"])
    return _function((), build, None)


def _put_uleb_function():
    def build(e: E):
        p = e.p
        e.var("pu", p["value"])
        e.var("pu_more", 1)

        def step():
            e.var("pu_low", e.and_(p["pu"], 127))
            e.set("pu", e.udiv(p["pu"], 128))
            _put(e, e.add(p["pu_low"], e.mul(e.flag(e.ne(p["pu"], 0)), 128)))
            e.set("pu_more", e.flag(e.ne(p["pu"], 0)))

        e.while_(lambda: e.ne(p["pu_more"], 0), step)
        e.give(0)
    return _function(("value",), build, None)


def _copy_uleb_function():
    """The next ULEB's value; copied to ``BODY`` in EMIT mode."""
    def build(e: E):
        p = e.p
        e.var("cv", _call(e, "uleb_read"))
        e.if_(e.eq(_ctrl(e, MODE), EMIT), lambda: _call(e, "put_uleb", p["cv"]))
        e.give(p["cv"])
    return _function((), build, None)


def _copy_string_function():
    """A length-prefixed byte string, copied in EMIT mode."""
    def build(e: E):
        p = e.p
        e.var("cs_n", _call(e, "copy_uleb"))
        e.var("cs_at", _ctrl(e, CUR))
        e.if_(e.eq(_ctrl(e, MODE), EMIT), lambda: e.for_("cs_k", 0, p["cs_n"], lambda: _put(e, e.rd(e.add(p["cs_at"], p["cs_k"])))))
        _set(e, CUR, e.add(p["cs_at"], p["cs_n"]))
        e.give(0)
    return _function((), build, None)


def _source_cid(e: E, source, k: int):
    """CID word ``k`` of a reference source's current version: a new constant's, a rebuilt object's, or an old one's."""
    extra = e.le(EXTRA_TAG, source)
    index = e.sub(source, EXTRA_TAG)
    rebuilt = e.eq(e.ld(e.add(STATE, source)), 2)
    return e.sel(extra, e.ld(e.add(e.add(EXTRA, e.mul(index, EXTRA_WORDS)), 4 + k)),
                 e.sel(rebuilt, e.ld(e.add(e.add(NEWCID, e.mul(source, 4)), k)), _cid_word(e, source, k)))


def _search_function():
    """Binary search of the CID in ``KEY`` among the ``EC + 41`` sorted references at ``SR``: its position (or where
    it goes); ``HIT`` is 1 when present."""
    def build(e: E):
        p = e.p
        for k in range(4):
            e.var(f"key{k}", _ctrl(e, KEY + k))
        e.var("lo", 0)
        e.var("hi", e.ld(EC + 41))
        e.var("hit", 0)

        def step():
            e.var("mid", e.udiv(e.add(p["lo"], p["hi"]), 2))
            at = e.add(SR, e.mul(p["mid"], 4))
            e.var("below", 0)  # the entry is below the key
            e.var("same", 1)
            for k in range(4):
                e.var(f"c{k}", e.ld(e.add(at, k)))
                e.if_(e.ne(p["same"], 0), lambda k=k: e.if_(e.lt(p[f"c{k}"], p[f"key{k}"]), lambda: (e.set("below", 1), e.set("same", 0)),
                                                            lambda: e.if_(e.lt(p[f"key{k}"], p[f"c{k}"]), lambda: e.set("same", 0))))
            e.if_(e.ne(p["same"], 0), lambda: (e.set("hit", 1), e.set("lo", p["mid"]), e.set("hi", p["mid"])),
                  lambda: e.if_(e.ne(p["below"], 0), lambda: e.set("lo", e.add(p["mid"], 1)), lambda: e.set("hi", p["mid"])))

        e.while_(lambda: e.lt(p["lo"], p["hi"]), step)
        _set(e, HIT, p["hit"])
        e.give(p["lo"])
    return _function((), build, None)


def _insert_function():
    """Add the current version of ``source`` to the sorted references at ``SR`` (``EC + 41`` of them), once; past
    ``RC_LIMIT`` of them ``EC + 43`` is set."""
    def build(e: E):
        p = e.p
        for k in range(4):
            _set(e, KEY + k, _source_cid(e, p["source"], k))
        e.var("ipos", _call(e, "search"))

        def place():
            e.var("it", e.ld(EC + 41))
            e.if_(e.le(RC_LIMIT, p["it"]), lambda: e.st(EC + 43, 1))

            def shift():
                e.set("it", e.sub(p["it"], 1))
                for k in range(4):
                    e.st(e.add(e.add(SR, e.mul(e.add(p["it"], 1), 4)), k), e.ld(e.add(e.add(SR, e.mul(p["it"], 4)), k)))
                e.st(e.add(SRS, e.add(p["it"], 1)), e.ld(e.add(SRS, p["it"])))

            e.while_(lambda: e.both(e.lt(p["ipos"], p["it"]), e.eq(e.ld(EC + 43), 0)), shift)

            def write():
                for k in range(4):
                    e.st(e.add(e.add(SR, e.mul(p["ipos"], 4)), k), _ctrl(e, KEY + k))
                e.st(e.add(SRS, p["ipos"]), p["source"])
                e.st(EC + 41, e.add(e.ld(EC + 41), 1))

            e.if_(e.eq(e.ld(EC + 43), 0), write)

        e.if_(e.both(e.eq(_ctrl(e, HIT), 0), e.eq(e.ld(EC + 43), 0)), place)
        e.give(0)
    return _function(("source",), build, None)


def _resolve_function():
    """S15d.4a (ADR-312): the source of the CID in ``KEY``: the store's object with it (binary search: the store lists
    its objects by CID), else the supplied object whose CID ``next`` derived, else ``NONE``."""
    def build(e: E):
        p = e.p
        for k in range(4):
            e.var(f"key{k}", _ctrl(e, KEY + k))
        e.var("lo", 0)
        e.var("hi", _ctrl(e, E_OBJECTS))
        e.var("found", NONE)

        def step():
            e.var("mid", e.udiv(e.add(p["lo"], p["hi"]), 2))
            e.var("below", 0)
            e.var("same", 1)
            for k in range(4):
                e.var(f"c{k}", _cid_word(e, p["mid"], k))
                e.if_(e.ne(p["same"], 0), lambda k=k: e.if_(e.lt(p[f"c{k}"], p[f"key{k}"]), lambda: (e.set("below", 1), e.set("same", 0)),
                                                            lambda: e.if_(e.lt(p[f"key{k}"], p[f"c{k}"]), lambda: e.set("same", 0))))
            e.if_(e.ne(p["same"], 0), lambda: (e.set("found", p["mid"]), e.set("lo", p["hi"])),
                  lambda: e.if_(e.ne(p["below"], 0), lambda: e.set("lo", e.add(p["mid"], 1)), lambda: e.set("hi", p["mid"])))

        e.while_(lambda: e.lt(p["lo"], p["hi"]), step)

        def supplied():
            def each():
                e.var("rrow", e.add(EXTRA, e.mul(p["rx"], EXTRA_WORDS)))
                e.var("rsame", e.ld(e.add(p["rrow"], X_SUPPLIED)))
                for k in range(4):
                    e.set("rsame", e.and_(p["rsame"], e.flag(e.eq(e.ld(e.add(p["rrow"], 4 + k)), p[f"key{k}"]))))
                e.if_(e.ne(p["rsame"], 0), lambda: e.set("found", e.add(EXTRA_TAG, p["rx"])))

            e.for_("rx", 0, _ctrl(e, E_EXTRAS_DONE), each)

        e.if_(e.eq(p["found"], NONE), supplied)
        e.give(p["found"])
    return _function((), build, None)


def _replaced_function():
    """S15d.4a: the source owner ``o``'s reference to ``source`` names after the transaction: a ``REPLACE_REFERENCE``'s
    new child (found by ``resolve``; a missing one is EDIT-REFERENCE-TARGET), else ``source``."""
    def build(e: E):
        p = e.p
        e.var("out", p["source"])

        def each():
            def hit():
                for k in range(4):
                    e.var(f"nw{k}", 0)
                    for j in range(8):
                        e.set(f"nw{k}", e.add(e.mul(p[f"nw{k}"], 256), e.ld(e.add(_mutation(e, p["rq"], 5), 8 * k + j))))
                    _set(e, KEY + k, p[f"nw{k}"])
                e.var("target", _call(e, "resolve"))
                e.if_(e.eq(p["target"], NONE), lambda: _reject(
                    e, "XAX.WORKSPACE.RELATION_CONFLICT", lambda: _cid_of(e, p["o"]), "EDIT-REFERENCE-TARGET",
                    lambda: D.text(e, "an object of the store or of the record"), lambda: _record_cid(e, _mutation(e, p["rq"], 5))))
                e.if_(e.ne(p["target"], NONE), lambda: e.set("out", p["target"]))

            e.if_(e.both(e.eq(_mutation(e, p["rq"], 0), REPLACE_REFERENCE), e.eq(_mutation(e, p["rq"], 1), p["o"]),
                         e.eq(_mutation(e, p["rq"], 3), p["source"])), hit)

        e.for_("rq", 0, _ctrl(e, E_MUTATIONS), each)
        e.give(p["out"])
    return _function(("o", "source"), build, None)


def _reference_function():
    """One reference index in the body of object ``o``: COLLECT inserts its source's CID among the sorted references
    (``SR``); EMIT writes the index of its CID there.  ``extra``: the new constant replacing it (NONE: none).  Gives the
    old index."""
    def build(e: E):
        p = e.p
        e.var("ri", _call(e, "uleb_read"))
        e.var("rsrc", e.sel(e.ne(p["extra"], NONE), e.add(EXTRA_TAG, p["extra"]), _ref(e, p["o"], p["ri"])))
        e.if_(e.eq(p["extra"], NONE), lambda: e.set("rsrc", _call(e, "replaced", p["o"], p["rsrc"])))
        e.var("rmode", _ctrl(e, MODE))
        e.if_(e.eq(p["rmode"], COLLECT), lambda: _call(e, "insert", p["rsrc"]))

        def emit():
            for k in range(4):
                _set(e, KEY + k, _source_cid(e, p["rsrc"], k))
            _call(e, "put_uleb", _call(e, "search"))

        e.if_(e.eq(p["rmode"], EMIT), emit)
        e.give(p["ri"])
    return _function(("o", "extra"), build, None)


def _record_uleb_function():
    """The edit record's next ULEB at ``RCUR`` (a workspace word); a ULEB past the record or past 64 bits is
    EDIT-RECORD-ULEB."""
    def build(e: E):
        p = e.p
        e.var("at", _ctrl(e, RCUR))
        e.var("end", e.add(EIN, _ctrl(e, E_LENGTH)))
        e.var("value", 0)
        e.var("shift", 1)
        e.var("more", 1)

        def malformed():
            _reject(e, "XAX.EDIT.RECORD", lambda: D.text(e, "edit"), "EDIT-RECORD-ULEB", lambda: D.text(e, "xax-edit-v1"),
                    lambda: D.integer(e, e.sub(p["at"], EIN)))
            e.set("more", 0)

        def step():
            e.if_(e.either(e.le(p["end"], p["at"]), e.eq(p["shift"], 0)), malformed)  # past the record; an eleventh byte

            def read():
                e.var("byte", e.ld(p["at"]))
                e.set("at", e.add(p["at"], 1))
                # The tenth byte carries bit 63 only.
                e.if_(e.both(e.eq(p["shift"], 1 << 63), e.lt(1, e.and_(p["byte"], 127))), malformed, lambda: (
                    e.set("value", e.add(p["value"], e.mul(e.and_(p["byte"], 127), p["shift"]))),
                    e.set("shift", e.mul(p["shift"], 128)),
                    e.set("more", e.flag(e.le(128, p["byte"])))))

            e.if_(e.ne(p["more"], 0), read)

        e.while_(lambda: e.both(e.ne(p["more"], 0), e.eq(_ctrl(e, E_STATUS), OK)), step)
        _set(e, RCUR, p["at"])
        e.give(p["value"])
    return _function((), build, None)


def _mutation(e: E, m, field: int):
    return e.ld(e.add(e.add(MUT, e.mul(m, MUT_WORDS)), field))


def _row(e: E, m, field: int):
    return e.add(e.add(MUT, e.mul(m, MUT_WORDS)), field)


# -- S15d.4b (ADR-314): the workspace's graph mutations ----------------------------------------------------------------

def _record_value_function():
    """The record's value at ``RCUR`` into ``V_TAG``.. ``V_C`` (``V_C`` 0 for a parameter); ``RCUR`` moves past it."""
    def build(e: E):
        p = e.p
        e.var("vt", _call(e, "record_uleb"))
        e.var("va", _call(e, "record_uleb"))
        e.var("vb", _call(e, "record_uleb"))
        e.var("vc", 0)
        e.if_(e.eq(p["vt"], VALUE_RESULT), lambda: e.set("vc", _call(e, "record_uleb")))
        for field, name in ((V_TAG, "vt"), (V_A, "va"), (V_B, "vb"), (V_C, "vc")):
            _set(e, field, p[name])
        e.give(p["vt"])
    return _function((), build, None)


def _count_rows_function():
    """How many rows of mutation ``kind`` name graph ``GRAPH_CUR``'s block ``block`` (the node counts of a re-encoded
    block move by its insertions less its deletions)."""
    def build(e: E):
        p = e.p
        e.var("cn", 0)
        e.for_("cq", 0, _ctrl(e, E_MUTATIONS), lambda: e.if_(e.both(
            e.eq(_mutation(e, p["cq"], 0), p["kind"]), e.eq(_mutation(e, p["cq"], 2), _ctrl(e, GRAPH_CUR)), e.eq(_mutation(e, p["cq"], 3), p["block"])),
            lambda: e.set("cn", e.add(p["cn"], 1))))
        e.give(p["cn"])
    return _function(("kind", "block"), build, None)


def _remap_function():
    """Node ``index`` of block ``block`` after the transaction (``_mutate_function``'s ``remap_value``): moved up by the
    insertions anchored at or before it, down by the deletions before it.  ``strict``: insertions strictly before it
    (an inserted node's own place, ``inserted_value``)."""
    def build(e: E):
        p = e.p
        e.var("rn", p["index"])
        e.var("rstrict", e.ld(EC + 25))

        def each():
            same = e.both(e.eq(_mutation(e, p["rq"], 2), _ctrl(e, GRAPH_CUR)), e.eq(_mutation(e, p["rq"], 3), p["block"]))
            e.var("rk", _mutation(e, p["rq"], 0))
            e.var("rat", _mutation(e, p["rq"], 4))
            e.var("rsame", e.flag(same))
            e.if_(e.both(e.ne(p["rsame"], 0), e.eq(p["rk"], INSERT_NODE), e.either(e.lt(p["rat"], p["index"]), e.both(e.eq(p["rat"], p["index"]), e.eq(p["rstrict"], 0)))),
                  lambda: e.set("rn", e.add(p["rn"], 1)))
            e.if_(e.both(e.ne(p["rsame"], 0), e.eq(p["rk"], DELETE_NODE), e.lt(p["rat"], p["index"])), lambda: e.set("rn", e.sub(p["rn"], 1)))

        e.for_("rq", 0, _ctrl(e, E_MUTATIONS), each)
        e.give(p["rn"])
    return _function(("block", "index"), build, None)


def _local_function():
    """The row of the insertion with transaction-local id ``local`` in graph ``GRAPH_CUR``, or NONE."""
    def build(e: E):
        p = e.p
        e.var("lr", NONE)
        e.for_("lq", 0, _ctrl(e, E_MUTATIONS), lambda: e.if_(e.both(
            e.eq(_mutation(e, p["lq"], 0), INSERT_NODE), e.eq(_mutation(e, p["lq"], 2), _ctrl(e, GRAPH_CUR)), e.eq(_mutation(e, p["lq"], 6), p["local"])),
            lambda: e.set("lr", p["lq"])))
        e.give(p["lr"])
    return _function(("local",), build, None)


def _emit_value_function():
    """Write the value in ``V_TAG``.. (EMIT mode): a parameter as it is, a node result remapped, a transaction-local
    insertion's result as that node's result."""
    def build(e: E):
        p = e.p
        e.var("et", _ctrl(e, V_TAG))
        e.var("ea", _ctrl(e, V_A))
        e.var("eb", _ctrl(e, V_B))
        e.var("ec", _ctrl(e, V_C))

        def write():
            def parameter():
                for value in (0, p["ea"], p["eb"]):
                    _call(e, "put_uleb", value)

            def result():
                e.st(EC + 25, 0)
                e.var("ei", _call(e, "remap", p["ea"], p["eb"]))
                for value in (1, p["ea"], p["ei"], p["ec"]):
                    _call(e, "put_uleb", value)

            def inserted():
                e.var("er", _call(e, "local", p["ea"]))
                e.if_(e.eq(p["er"], NONE), lambda: e.st(EC + 26, 1))  # checked before: never here
                e.var("erow", e.sel(e.eq(p["er"], NONE), 0, p["er"]))
                e.st(EC + 25, 1)
                e.var("ei", _call(e, "remap", _mutation(e, p["erow"], 3), _mutation(e, p["erow"], 4)))
                for value in (1, _mutation(e, p["erow"], 3), p["ei"], p["eb"]):
                    _call(e, "put_uleb", value)

            e.if_(e.eq(p["et"], VALUE_PARAMETER), parameter, lambda: e.if_(e.eq(p["et"], VALUE_RESULT), result, inserted))

        e.if_(e.eq(_ctrl(e, MODE), EMIT), write)
        e.give(0)
    return _function((), build, None)


def _read_value_function():
    """The body's value at ``CUR`` into ``V_TAG``.. (nothing written)."""
    def build(e: E):
        p = e.p
        e.var("wt", _call(e, "uleb_read"))
        _set(e, V_TAG, p["wt"])
        _set(e, V_A, _call(e, "uleb_read"))
        _set(e, V_B, _call(e, "uleb_read"))
        _set(e, V_C, 0)
        e.if_(e.eq(p["wt"], 1), lambda: _set(e, V_C, _call(e, "uleb_read")))
        e.give(p["wt"])
    return _function((), build, None)


def _emit_ref_function():
    """A reference to ``source`` written as the current version's index: COLLECT inserts its CID among the sorted
    references, EMIT writes its index (other modes nothing)."""
    def build(e: E):
        p = e.p
        e.var("em", _ctrl(e, MODE))
        e.if_(e.eq(p["em"], COLLECT), lambda: _call(e, "insert", p["source"]))

        def emit():
            for k in range(4):
                _set(e, KEY + k, _source_cid(e, p["source"], k))
            _call(e, "put_uleb", _call(e, "search"))

        e.if_(e.eq(p["em"], EMIT), emit)
        e.give(0)
    return _function(("source",), build, None)


def _type_source_function():
    """The object whose CID is the record's 32 bytes at ``at`` (the store's, or a supplied one's once it has its CID);
    NONE when neither holds it."""
    def build(e: E):
        p = e.p
        for k in range(4):
            e.var(f"tw{k}", 0)
            for j in range(8):
                e.set(f"tw{k}", e.add(e.mul(p[f"tw{k}"], 256), e.ld(e.add(p["at"], 8 * k + j))))
            _set(e, KEY + k, p[f"tw{k}"])
        e.give(_call(e, "resolve"))
    return _function(("at",), build, None)


def _emit_insert_function():
    """Insertion row ``m``'s node, written (COLLECT: its references collected): its operation, its constant (a new
    object), its operands (record values), its one result type, its attributes."""
    def build(e: E):
        p = e.p
        e.var("in_row", p["m"])
        _set(e, RCUR, _mutation(e, p["in_row"], 5))
        e.var("iop", _call(e, "record_uleb"))
        e.var("imode", _ctrl(e, MODE))
        e.if_(e.eq(p["imode"], EMIT), lambda: _call(e, "put_uleb", p["iop"]))
        e.if_(e.eq(p["iop"], int(Operation.CONSTANT)), lambda: _call(e, "emit_ref", e.add(EXTRA_TAG, _mutation(e, p["in_row"], M_EXTRA))))
        e.var("in", _call(e, "record_uleb"))
        e.if_(e.eq(p["imode"], EMIT), lambda: _call(e, "put_uleb", p["in"]))

        def operand():
            _call(e, "record_value")
            e.var("irc", _ctrl(e, RCUR))
            _call(e, "emit_value")
            _set(e, RCUR, p["irc"])

        e.for_("iq", 0, p["in"], operand)
        e.var("itype_at", _ctrl(e, RCUR))
        _set(e, RCUR, e.add(p["itype_at"], 32))
        e.if_(e.eq(p["imode"], EMIT), lambda: _call(e, "put_uleb", 1))
        e.var("itype", _call(e, "type_source", p["itype_at"]))
        e.if_(e.eq(p["itype"], NONE), lambda: _reject(
            e, "XAX.WORKSPACE.HANDLE", lambda: _record_cid(e, p["itype_at"]), "WORKSPACE-HANDLE-GENERATION",
            lambda: D.text(e, "type at the current root"), lambda: D.text(e, "unbound or stale")))
        e.if_(e.ne(p["itype"], NONE), lambda: _call(e, "emit_ref", p["itype"]))
        e.var("ihas", _call(e, "record_uleb"))
        e.if_(e.ne(p["ihas"], 0), lambda: _call(e, "record_uleb"))
        e.var("iattrs", _call(e, "record_uleb"))

        def attributes():
            e.if_(e.eq(p["imode"], EMIT), lambda: _call(e, "put_uleb", p["iattrs"]))
            e.for_("ia", 0, p["iattrs"], lambda: (e.var("iav", _call(e, "record_uleb")), e.if_(e.eq(p["imode"], EMIT), lambda: _call(e, "put_uleb", p["iav"]))))

        e.if_(e.ne(e.and_(e.ld(e.add(OPF, e.sel(e.lt(p["iop"], 128), p["iop"], 0))), 2), 0), attributes)
        e.give(0)
    return _function(("m",), build, None)


def _note_use_function():
    """LOCATE: the value in ``V_TAG``.. read at body word ``at`` uses a node a ``DELETE_NODE`` row deletes: the row's
    ``M_FOUND`` keeps the first such use (``at`` + 1).  A use in a node the transaction deletes too does not count."""
    def build(e: E):
        p = e.p
        e.var("nu_tag", _ctrl(e, V_TAG))
        e.var("nu_block", _ctrl(e, V_A))
        e.var("nu_node", _ctrl(e, V_B))

        def each():
            e.if_(e.both(e.eq(_mutation(e, p["nq"], 0), DELETE_NODE), e.eq(_mutation(e, p["nq"], 2), _ctrl(e, GRAPH_CUR)),
                         e.eq(_mutation(e, p["nq"], 3), p["nu_block"]), e.eq(_mutation(e, p["nq"], 4), p["nu_node"]),
                         e.eq(_mutation(e, p["nq"], M_FOUND), 0)), lambda: e.st(_row(e, p["nq"], M_FOUND), e.add(p["at"], 1)))

        e.if_(e.both(e.eq(p["nu_tag"], VALUE_RESULT), e.eq(p["deleted"], 0)), lambda: e.for_("nq", 0, _ctrl(e, E_MUTATIONS), each))
        e.give(0)
    return _function(("at", "deleted"), build, None)


def _same_value_function():
    """1 when the record's value at ``at`` is the value in ``V_TAG``.. (which it leaves as the record's)."""
    def build(e: E):
        p = e.p
        for field in (V_TAG, V_A, V_B, V_C):
            e.var(f"sv{field}", _ctrl(e, field))
        _set(e, RCUR, p["at"])
        _call(e, "record_value")
        e.var("sv_same", 1)
        for field in (V_TAG, V_A, V_B, V_C):
            e.set("sv_same", e.and_(p["sv_same"], e.flag(e.eq(_ctrl(e, field), p[f"sv{field}"]))))
        e.give(p["sv_same"])
    return _function(("at",), build, None)


def _edge_row_function():
    """The row of an edge mutation of ``kind`` on graph ``GRAPH_CUR``'s block ``block``, edge ``edge``, argument ``arg``,
    or NONE; with ``arg`` NONE, how many name that edge."""
    def build(e: E):
        p = e.p
        e.var("er_row", NONE)
        e.var("er_count", 0)

        def each():
            e.if_(e.both(e.eq(_mutation(e, p["eq"], 0), p["kind"]), e.eq(_mutation(e, p["eq"], 2), _ctrl(e, GRAPH_CUR)),
                         e.eq(_mutation(e, p["eq"], 3), p["block"]), e.eq(_mutation(e, p["eq"], M_EXTRA), p["edge"])), lambda: (
                e.set("er_count", e.add(p["er_count"], 1)),
                e.if_(e.eq(_mutation(e, p["eq"], 6), p["arg"]), lambda: e.set("er_row", p["eq"]))))

        e.for_("eq", 0, _ctrl(e, E_MUTATIONS), each)
        e.give(e.sel(e.eq(p["arg"], NONE), p["er_count"], p["er_row"]))
    return _function(("kind", "block", "edge", "arg"), build, None)


def _scan_value_function():
    """A value of the body at ``CUR``: LOCATE notes a deleted node's use, EMIT writes it remapped."""
    def build(e: E):
        p = e.p
        e.var("sv_at", _ctrl(e, CUR))
        _call(e, "read_value")
        e.if_(e.eq(_ctrl(e, MODE), LOCATE), lambda: _call(e, "note_use", p["sv_at"], p["deleted"]), lambda: _call(e, "emit_value"))
        e.give(0)
    return _function(("deleted",), build, None)


def _scan_edge_function():
    """A terminator edge of graph ``GRAPH_CUR``'s block ``block`` from ``CUR``: its target and arguments, with the
    transaction's disconnections and connections (S15d.4b); LOCATE records the edge's argument count (``M_FOUND`` + 1)
    and each disconnection's comparison (``M_USE``; the argument's body word + 1 in ``ENTITY_AT``)."""
    def build(e: E):
        p = e.p
        e.var("xm", _ctrl(e, MODE))
        _call(e, "copy_uleb")  # the target
        e.var("xn", _call(e, "uleb_read"))

        def counts():
            def each():
                e.if_(e.both(e.lt(SET_RESULT_TYPE, _mutation(e, p["xq"], 0)),
                             e.eq(_mutation(e, p["xq"], 2), _ctrl(e, GRAPH_CUR)), e.eq(_mutation(e, p["xq"], 3), p["block"]),
                             e.eq(_mutation(e, p["xq"], M_EXTRA), p["edge"])), lambda: e.st(_row(e, p["xq"], M_FOUND), e.add(p["xn"], 1)))

            e.for_("xq", 0, _ctrl(e, E_MUTATIONS), each)

        e.if_(e.eq(p["xm"], LOCATE), counts)
        e.if_(e.eq(p["xm"], EMIT), lambda: _call(e, "put_uleb", e.sub(e.add(p["xn"], _call(e, "edge_row", CONNECT_EDGE, p["block"], p["edge"], NONE)),
                                                                   _call(e, "edge_row", DISCONNECT_EDGE, p["block"], p["edge"], NONE))))

        def argument():
            e.var("xc", _call(e, "edge_row", CONNECT_EDGE, p["block"], p["edge"], p["xa"]))

            def connect():
                _set(e, RCUR, _mutation(e, p["xc"], 5))
                _call(e, "record_value")
                _call(e, "emit_value")

            e.if_(e.both(e.ne(p["xc"], NONE), e.eq(p["xm"], EMIT)), connect)

            def existing():
                e.var("xat", _ctrl(e, CUR))
                _call(e, "read_value")
                e.var("xd", _call(e, "edge_row", DISCONNECT_EDGE, p["block"], p["edge"], p["xa"]))

                def locate():
                    _call(e, "note_use", p["xat"], 0)

                    def compare():
                        e.var("xsame", _call(e, "same_value", _mutation(e, p["xd"], 5)))
                        e.st(_row(e, p["xd"], M_USE), e.sub(2, p["xsame"]))
                        e.st(e.add(ENTITY_AT, p["xd"]), e.add(p["xat"], 1))

                    e.if_(e.ne(p["xd"], NONE), compare)

                e.if_(e.eq(p["xm"], LOCATE), locate, lambda: e.if_(e.eq(p["xd"], NONE), lambda: _call(e, "emit_value")))

            e.if_(e.lt(p["xa"], p["xn"]), existing)

        e.for_("xa", 0, e.add(p["xn"], 1), argument)
        e.give(0)
    return _function(("block", "edge"), build, None)


def _scan_graph_function():
    """``graph_fragment``'s body grammar over graph ``o`` from ``CUR``, applying its mutations.  In LOCATE mode it
    records each mutated node's operation (``MUT`` field 7) and its entity's reference index (``ENTITY_AT``), and
    (S15d.4b) what the structural mutations check: operand and result counts, an operand's comparison, a deleted node's
    first use, a result's old type, an edge's counts.  COLLECT and EMIT insert nodes before their anchors, skip deleted
    ones, and write every value remapped."""
    def build(e: E):
        p = e.p
        e.var("mode", _ctrl(e, MODE))
        _set(e, GRAPH_CUR, p["o"])
        e.var("nblocks", _call(e, "copy_uleb"))
        _call(e, "copy_uleb")  # the entry block
        e.var("gb", 0)

        def block():
            e.var("np", _call(e, "copy_uleb"))
            e.for_("gp", 0, p["np"], lambda: _call(e, "reference", p["o"], NONE))
            e.var("nn", _call(e, "uleb_read"))
            e.if_(e.eq(p["mode"], EMIT), lambda: _call(e, "put_uleb", e.sub(e.add(p["nn"], _call(e, "count_rows", INSERT_NODE, p["gb"])),
                                                                          _call(e, "count_rows", DELETE_NODE, p["gb"]))))
            e.var("gn", 0)

            def node():
                e.var("gm", NONE)
                e.for_("mq", 0, _ctrl(e, E_MUTATIONS), lambda: e.if_(e.both(
                    e.eq(_mutation(e, p["mq"], 2), p["o"]), e.eq(_mutation(e, p["mq"], 3), p["gb"]), e.eq(_mutation(e, p["mq"], 4), p["gn"]),
                    e.lt(_mutation(e, p["mq"], 0), DISCONNECT_EDGE), e.ne(_mutation(e, p["mq"], 0), REPLACE_REFERENCE)),
                    lambda: e.set("gm", p["mq"])))
                e.var("gk", 0)
                e.if_(e.ne(p["gm"], NONE), lambda: e.set("gk", _mutation(e, p["gm"], 0)))

                def inserted():  # the inserted node comes before its anchor, which is otherwise unchanged
                    e.if_(e.eq(p["mode"], LOCATE), lambda: e.st(_row(e, p["gm"], 7), 1 << 32), lambda: _call(e, "emit_insert", p["gm"]))
                    e.set("gm", NONE)
                    e.set("gk", 0)

                e.if_(e.eq(p["gk"], INSERT_NODE), inserted)
                e.var("gmr", e.sel(e.eq(p["gm"], NONE), 0, p["gm"]))
                e.var("gdel", e.flag(e.eq(p["gk"], DELETE_NODE)))
                e.if_(e.both(e.ne(p["gdel"], 0), e.ne(p["mode"], LOCATE)), lambda: _set(e, MODE, SKIP))
                e.var("gop", _call(e, "uleb_read"))
                e.var("gout", p["gop"])
                e.var("edited", e.flag(e.ne(p["gm"], NONE)))
                e.if_(e.both(e.eq(p["gk"], SET_OPERATION), e.ne(p["mode"], LOCATE)), lambda: e.set("gout", _mutation(e, p["gmr"], 6)))
                e.if_(e.both(e.ne(p["edited"], 0), e.eq(p["mode"], LOCATE)), lambda: e.st(_row(e, p["gmr"], 7), e.add(p["gop"], 1 << 32)))  # located
                e.if_(e.eq(_ctrl(e, MODE), EMIT), lambda: _call(e, "put_uleb", p["gout"]))
                e.var("gflags", e.ld(e.add(OPF, e.sel(e.lt(p["gop"], 128), p["gop"], 0))))
                e.if_(e.eq(p["gop"], int(Operation.CALL_GROUP_MEMBER)), lambda: _call(e, "copy_uleb"))

                def entity():
                    e.var("gx", NONE)
                    e.if_(e.both(e.eq(p["gk"], SET_CONSTANT), e.ne(p["mode"], LOCATE)), lambda: e.set("gx", _mutation(e, p["gmr"], 7)))
                    e.if_(e.both(e.eq(p["gk"], SET_RESULT_TYPE), e.ne(p["mode"], LOCATE)), lambda: e.set("gx", _mutation(e, p["gmr"], M_EXTRA)))
                    e.var("gent", _call(e, "reference", p["o"], p["gx"]))
                    e.if_(e.both(e.ne(p["edited"], 0), e.eq(p["mode"], LOCATE)), lambda: e.st(e.add(ENTITY_AT, p["gmr"]), e.add(p["gent"], 1)))

                e.if_(e.ne(e.and_(p["gflags"], 1), 0), entity)
                e.var("guse", e.flag(e.eq(p["gk"], REPLACE_USE)))
                e.var("gno", _call(e, "copy_uleb"))
                e.if_(e.both(e.ne(p["guse"], 0), e.eq(p["mode"], LOCATE)), lambda: e.st(_row(e, p["gmr"], M_COUNT), p["gno"]))

                def operand():
                    e.var("ghit", e.flag(e.both(e.ne(p["guse"], 0), e.eq(_mutation(e, p["gmr"], 6), p["go"]))))

                    def replaced():
                        def locate():
                            e.var("gat", _ctrl(e, CUR))
                            _call(e, "read_value")
                            _call(e, "note_use", p["gat"], p["gdel"])
                            e.var("gsame", _call(e, "same_value", _mutation(e, p["gmr"], 5)))
                            e.st(_row(e, p["gmr"], M_FOUND), e.sub(2, p["gsame"]))
                            e.st(_row(e, p["gmr"], M_USE), p["gat"])

                        def replace():
                            _call(e, "read_value")
                            _set(e, RCUR, _mutation(e, p["gmr"], 5))
                            _call(e, "record_value")  # the expected value
                            _call(e, "record_value")
                            _call(e, "emit_value")

                        e.if_(e.eq(p["mode"], LOCATE), locate, replace)

                    e.if_(e.ne(p["ghit"], 0), replaced, lambda: _call(e, "scan_value", p["gdel"]))

                e.for_("go", 0, p["gno"], operand)
                e.var("gtype", e.flag(e.eq(p["gk"], SET_RESULT_TYPE)))
                e.var("gnr", _call(e, "copy_uleb"))
                e.if_(e.both(e.ne(p["gtype"], 0), e.eq(p["mode"], LOCATE)), lambda: e.st(_row(e, p["gmr"], M_COUNT), p["gnr"]))

                def result():
                    def retyped():
                        def locate():
                            e.var("gold", _call(e, "uleb_read"))
                            e.st(_row(e, p["gmr"], M_FOUND), e.add(_ref(e, p["o"], p["gold"]), 1))

                        def retype():
                            _call(e, "uleb_read")
                            e.var("gnew_at", e.add(_mutation(e, p["gmr"], 5), 32))
                            e.var("gnew", _call(e, "type_source", p["gnew_at"]))
                            e.if_(e.eq(p["gnew"], NONE), lambda: _reject(
                                e, "XAX.WORKSPACE.HANDLE", lambda: _record_cid(e, p["gnew_at"]), "WORKSPACE-HANDLE-GENERATION",
                                lambda: D.text(e, "type at the current root"), lambda: D.text(e, "unbound or stale")),
                                  lambda: _call(e, "emit_ref", p["gnew"]))

                        e.if_(e.eq(p["mode"], LOCATE), locate, retype)

                    e.if_(e.both(e.ne(p["gtype"], 0), e.eq(_mutation(e, p["gmr"], 6), p["gr"])), retyped,
                          lambda: _call(e, "reference", p["o"], NONE))

                e.for_("gr", 0, p["gnr"], result)
                e.if_(e.ne(e.and_(p["gflags"], 2), 0), lambda: e.for_("ga", 0, _call(e, "copy_uleb"), lambda: _call(e, "copy_uleb")))
                _set(e, MODE, p["mode"])
                e.set("gn", e.add(p["gn"], 1))

            e.while_(lambda: e.lt(p["gn"], p["nn"]), node)
            e.var("tk", _call(e, "copy_uleb"))

            def edges():
                """LOCATE: the block's edge mutations are located when it has a node (their handle) and see its edge count."""
                e.var("tedges", e.sel(e.eq(p["tk"], 1), 1, e.sel(e.eq(p["tk"], 2), 2, 0)))

                def each():
                    e.if_(e.both(e.lt(SET_RESULT_TYPE, _mutation(e, p["tq"], 0)), e.eq(_mutation(e, p["tq"], 2), p["o"]),
                                 e.eq(_mutation(e, p["tq"], 3), p["gb"]), e.lt(0, p["nn"])), lambda: (
                        e.st(_row(e, p["tq"], 7), 1 << 32), e.st(_row(e, p["tq"], M_COUNT), p["tedges"])))

                e.for_("tq", 0, _ctrl(e, E_MUTATIONS), each)

            e.if_(e.eq(p["mode"], LOCATE), edges)
            e.if_(e.eq(p["tk"], 1), lambda: _call(e, "scan_edge", p["gb"], 0))
            e.if_(e.eq(p["tk"], 2), lambda: (_call(e, "scan_value", 0), _call(e, "scan_edge", p["gb"], 0), _call(e, "scan_edge", p["gb"], 1)))
            e.if_(e.eq(p["tk"], 3), lambda: e.for_("tr", 0, _call(e, "copy_uleb"), lambda: _call(e, "scan_value", 0)))
            e.if_(e.eq(p["tk"], 4), lambda: _call(e, "copy_string"))
            e.set("gb", e.add(p["gb"], 1))

        e.while_(lambda: e.lt(p["gb"], p["nblocks"]), block)
        e.give(0)
    return _function(("o",), build, None)


def _scan_other_function():
    """The reference-carrying bodies of a function, a package, and a build request, from ``CUR``."""
    def build(e: E):
        p = e.p
        e.var("kind", _kind(e, p["o"]))
        ref = lambda: _call(e, "reference", p["o"], NONE)  # noqa: E731

        def function_():
            ref()
            e.for_("fp", 0, _call(e, "copy_uleb"), ref)
            e.for_("fr", 0, _call(e, "copy_uleb"), ref)

        def package():
            _call(e, "copy_string")
            # Modules: their indices ascend with their CIDs; the emitted one-byte indices are sorted again.
            e.var("pm_count", _call(e, "copy_uleb"))
            e.var("pm_out", _ctrl(e, OUT))
            e.for_("pm", 0, p["pm_count"], ref)

            def sort_modules():
                def inner():
                    e.var("ps_a", e.ld(e.add(BODY, e.add(p["pm_out"], p["ps_j"]))))
                    e.var("ps_b", e.ld(e.add(BODY, e.add(e.add(p["pm_out"], p["ps_j"]), 1))))
                    e.if_(e.lt(p["ps_b"], p["ps_a"]), lambda: (e.st(e.add(BODY, e.add(p["pm_out"], p["ps_j"])), p["ps_b"]),
                                                               e.st(e.add(BODY, e.add(e.add(p["pm_out"], p["ps_j"]), 1)), p["ps_a"])))

                e.for_("ps_i", 0, p["pm_count"], lambda: e.for_("ps_j", 0, e.sub(e.sub(p["pm_count"], 1), p["ps_i"]), inner))

            e.if_(e.eq(_ctrl(e, MODE), EMIT), sort_modules)

            def dependency():
                e.var("pd_form", _call(e, "copy_uleb"))
                e.if_(e.eq(p["pd_form"], 1), ref, lambda: _call(e, "copy_string"))

            e.for_("pd", 0, _call(e, "copy_uleb"), dependency)
            for name in ("pe", "pf", "pc"):
                e.for_(name, 0, _call(e, "copy_uleb"), lambda: (_call(e, "copy_string"), ref()))
            e.for_("pk", 0, _call(e, "copy_uleb"), lambda: (_call(e, "copy_uleb"), _call(e, "copy_string")))

        def request():
            _call(e, "copy_uleb")  # the form
            ref()
            _call(e, "copy_string")
            ref()
            ref()
            for name in ("rf", "rc"):
                e.for_(name, 0, _call(e, "copy_uleb"), lambda: (_call(e, "copy_string"), ref()))
            e.for_("ra", 0, _call(e, "copy_uleb"), lambda: _call(e, "copy_uleb"))

        e.if_(e.eq(p["kind"], int(Kind.FUNCTION)), function_)
        e.if_(e.eq(p["kind"], int(Kind.PACKAGE)), package)
        e.if_(e.eq(p["kind"], int(Kind.BUILD)), request)
        e.give(0)
    return _function(("o",), build, None)


# -- S15d.4b: each structural mutation's preconditions, in the workspace's order (``xax_workspace._mutate_function``) ---

def _relation(e: E):
    """The value in ``V_TAG``.. as the workspace quotes it (``_value_relation``): tag, block, index, result."""
    D.put(e, D.T_TUPLE)
    D.put(e, 4)
    for field in (V_TAG, V_A, V_B, V_C):
        D.integer(e, _ctrl(e, field))


def _at_most(e: E, template: str, value):
    D.put(e, D.T_FORMAT)
    D.text(e, template)
    D.put(e, 1)
    D.integer(e, value)


def _names(e: E, operations):
    D.put(e, D.T_LIST)
    D.put(e, len(operations))
    for operation in operations:
        D.text(e, operation.name)


def _operation_name(e: E, value):
    D.put(e, D.T_NAME)
    D.put(e, D.ENUM_NAMES.index("Operation"))
    D.put(e, value)


def _new_constant(e: E, m, type_at, value, field: int):
    """A new constant of the type the record names at ``type_at`` (resolved by ``next``), kept at row field ``field``."""
    p = e.p
    e.var("nc_x", _ctrl(e, E_EXTRAS))
    e.var("nc_row", e.add(EXTRA, e.mul(p["nc_x"], EXTRA_WORDS)))
    for at, word in ((0, NONE), (1, 0), (2, value), (3, NONE), (X_SUPPLIED, 0), (X_TYPE_AT, type_at)):
        e.st(e.add(p["nc_row"], at), word)
    e.st(_row(e, m, field), p["nc_x"])
    _set(e, E_EXTRAS, e.add(p["nc_x"], 1))


def _check_local_function():
    """The record's value at ``at`` of row ``m``: a transaction-local one names an insertion in the same graph, and
    its first result (WORKSPACE-INSERT-LOCAL-VALUE, WORKSPACE-INSERT-LOCAL-RESULT); ``RCUR`` moves past it."""
    def build(e: E):
        p = e.p
        _set(e, RCUR, p["at"])
        e.var("cl_tag", _call(e, "record_value"))
        e.var("cl_a", _ctrl(e, V_A))
        e.var("cl_b", _ctrl(e, V_B))
        e.var("cl_after", _ctrl(e, RCUR))

        def local():
            _set(e, GRAPH_CUR, _mutation(e, p["m"], 2))
            e.var("cl_row", _call(e, "local", p["cl_a"]))

            def missing():
                _reject(e, "XAX.WORKSPACE.RELATION_CONFLICT", lambda: _cid_of(e, _mutation(e, p["m"], 1)), "WORKSPACE-INSERT-LOCAL-VALUE",
                        lambda: D.text(e, "transaction-local inserted result in the same function"),
                        lambda: (D.put(e, D.T_FORMAT), D.text(e, "I{}.R{}"), D.put(e, 2), D.integer(e, p["cl_a"]), D.integer(e, p["cl_b"])))

            e.if_(e.eq(p["cl_row"], NONE), missing, lambda: e.if_(e.ne(p["cl_b"], 0), lambda: _reject(
                e, "XAX.WORKSPACE.RELATION_CONFLICT", lambda: _cid_of(e, _mutation(e, p["m"], 1)), "WORKSPACE-INSERT-LOCAL-RESULT",
                lambda: D.integer(e, 0), lambda: D.integer(e, p["cl_b"]))))

        e.if_(e.eq(p["cl_tag"], VALUE_INSERTED), local)
        _set(e, RCUR, p["cl_after"])
        e.give(0)
    return _function(("m", "at"), build, None)


def _check_use_function():
    def build(e: E):
        p = e.p
        e.var("cu_index", _mutation(e, p["m"], 6))
        e.var("cu_count", _mutation(e, p["m"], M_COUNT))
        entity = lambda: _cid_of(e, _mutation(e, p["m"], 1))  # noqa: E731

        def stale():
            def expected():
                _set(e, RCUR, _mutation(e, p["m"], 5))
                _call(e, "record_value")
                _relation(e)

            def actual():
                _set(e, CUR, _mutation(e, p["m"], M_USE))
                _call(e, "read_value")
                _relation(e)

            _reject(e, "XAX.WORKSPACE.RELATION_CONFLICT", entity, "WORKSPACE-OPERAND-PRECONDITION", expected, actual)

        def value():
            _set(e, RCUR, _mutation(e, p["m"], 5))
            _call(e, "record_value")
            _call(e, "check_local", p["m"], _ctrl(e, RCUR))

        e.if_(e.le(p["cu_count"], p["cu_index"]), lambda: _reject(
            e, "XAX.WORKSPACE.RELATION_CONFLICT", entity, "WORKSPACE-OPERAND-INDEX", lambda: _at_most(e, "< {}", p["cu_count"]),
            lambda: D.integer(e, p["cu_index"])), lambda: e.if_(e.eq(_mutation(e, p["m"], M_FOUND), 2), stale, value))
        e.give(0)
    return _function(("m",), build, None)


def _check_delete_function():
    def build(e: E):
        p = e.p
        e.var("cd_op", e.sub(_mutation(e, p["m"], 7), 1 << 32))
        e.var("cd_use", _mutation(e, p["m"], M_FOUND))
        entity = lambda: _cid_of(e, _mutation(e, p["m"], 1))  # noqa: E731

        def used():
            def actual():
                _set(e, CUR, e.sub(p["cd_use"], 1))
                _call(e, "read_value")
                _relation(e)

            _reject(e, "XAX.WORKSPACE.DELETE_USE_CONFLICT", entity, "WORKSPACE-DELETE-NODE-UNUSED", lambda: D.text(e, "zero semantic uses"), actual)

        e.if_(e.not_(e.either(*(e.eq(p["cd_op"], int(op)) for op in PURE))), lambda: _reject(
            e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", entity, "WORKSPACE-DELETE-PURE-NODE", lambda: _names(e, PURE),
            lambda: _operation_name(e, p["cd_op"])), lambda: e.if_(e.ne(p["cd_use"], 0), used))
        e.give(0)
    return _function(("m",), build, None)


def _check_insert_function():
    def build(e: E):
        p = e.p
        entity = lambda: _cid_of(e, _mutation(e, p["m"], 1))  # noqa: E731
        _set(e, RCUR, _mutation(e, p["m"], 5))
        e.var("ci_op", _call(e, "record_uleb"))
        e.var("ci_n", _call(e, "record_uleb"))
        e.var("ci_values", _ctrl(e, RCUR))
        e.for_("ci_q", 0, p["ci_n"], lambda: _call(e, "record_value"))
        e.var("ci_type", _ctrl(e, RCUR))
        _set(e, RCUR, e.add(p["ci_type"], 32))
        e.var("ci_has", _call(e, "record_uleb"))
        e.var("ci_value", 0)
        e.if_(e.ne(p["ci_has"], 0), lambda: e.set("ci_value", _call(e, "record_uleb")))
        e.var("ci_constant", e.flag(e.eq(p["ci_op"], int(Operation.CONSTANT))))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        e.if_(e.not_(e.either(*(e.eq(p["ci_op"], int(op)) for op in INSERTABLE))), lambda: _reject(
            e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", entity, "WORKSPACE-INSERT-PURE-NODE", lambda: _names(e, INSERTABLE),
            lambda: _operation_name(e, p["ci_op"])))
        e.if_(e.both(running(), e.ne(p["ci_constant"], 0), e.eq(p["ci_has"], 0)), lambda: _reject(
            e, "XAX.WORKSPACE.INVALID_VALUE", entity, "WORKSPACE-INSERT-CONSTANT-VALUE", lambda: D.text(e, "integer constant value"),
            lambda: D.none(e)))
        e.if_(e.both(running(), e.eq(p["ci_constant"], 0), e.ne(p["ci_has"], 0)), lambda: _reject(
            e, "XAX.WORKSPACE.INVALID_VALUE", entity, "WORKSPACE-INSERT-CONSTANT-ABSENT", lambda: D.none(e), lambda: D.integer(e, p["ci_value"])))
        e.if_(e.both(running(), e.ne(p["ci_constant"], 0)), lambda: _new_constant(e, p["m"], p["ci_type"], p["ci_value"], M_EXTRA))
        e.var("ci_at", p["ci_values"])

        def operand():
            _call(e, "check_local", p["m"], p["ci_at"])
            e.set("ci_at", _ctrl(e, RCUR))

        e.for_("ci_o", 0, e.sel(running(), p["ci_n"], 0), lambda: e.if_(running(), operand))
        e.give(0)
    return _function(("m",), build, None)


def _check_result_function():
    def build(e: E):
        p = e.p
        entity = lambda: _cid_of(e, _mutation(e, p["m"], 1))  # noqa: E731
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        e.var("cr_index", _mutation(e, p["m"], 6))
        e.var("cr_count", _mutation(e, p["m"], M_COUNT))
        e.var("cr_at", _mutation(e, p["m"], 5))
        e.var("cr_op", e.sub(_mutation(e, p["m"], 7), 1 << 32))
        e.if_(e.le(p["cr_count"], p["cr_index"]), lambda: _reject(
            e, "XAX.WORKSPACE.RELATION_CONFLICT", entity, "WORKSPACE-RESULT-INDEX", lambda: _at_most(e, "< {}", p["cr_count"]),
            lambda: D.integer(e, p["cr_index"])))

        def precondition():
            e.var("cr_old", e.sub(_mutation(e, p["m"], M_FOUND), 1))
            e.var("cr_same", 1)
            for k in range(4):
                e.var(f"cr_w{k}", 0)
                for j in range(8):
                    e.set(f"cr_w{k}", e.add(e.mul(p[f"cr_w{k}"], 256), e.ld(e.add(p["cr_at"], 8 * k + j))))
                e.set("cr_same", e.and_(p["cr_same"], e.flag(e.eq(p[f"cr_w{k}"], _cid_word(e, p["cr_old"], k)))))
            e.if_(e.eq(p["cr_same"], 0), lambda: _reject(
                e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", entity, "WORKSPACE-RESULT-TYPE-PRECONDITION", lambda: _record_cid(e, p["cr_at"]),
                lambda: _cid_of(e, p["cr_old"])))

        e.if_(running(), precondition)

        def constant():
            e.if_(e.either(e.ne(p["cr_index"], 0), e.ne(p["cr_count"], 1)), lambda: _reject(
                e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", entity, "WORKSPACE-CONSTANT-SINGLE-RESULT", lambda: D.integer(e, 0),
                lambda: D.integer(e, p["cr_index"])))

            def value():
                e.var("cr_entity", _ref(e, _mutation(e, p["m"], 2), e.sub(e.ld(e.add(ENTITY_AT, p["m"])), 1)))
                clen, cat = _plain_body(e, p["cr_entity"])
                e.var("cr_body", cat)
                e.var("cr_bytes", e.rd(e.add(p["cr_body"], 1)))
                e.if_(e.lt(8, p["cr_bytes"]), lambda: _reject(
                    e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", entity, "EDIT-CONSTANT-BITS", lambda: D.text(e, "an integer constant of at most 64 bits"),
                    lambda: D.integer(e, p["cr_bytes"])))
                e.var("cr_value", 0)
                e.for_("cr_b", 0, e.sel(running(), p["cr_bytes"], 0), lambda: e.set("cr_value", e.add(p["cr_value"], e.mul(
                    e.rd(e.add(e.add(p["cr_body"], 2), p["cr_b"])), _pow256(e, p["cr_b"])))))
                e.if_(running(), lambda: _new_constant(e, p["m"], e.add(p["cr_at"], 32), p["cr_value"], M_EXTRA))

            e.if_(running(), value)

        e.if_(e.both(running(), e.eq(p["cr_op"], int(Operation.CONSTANT))), constant)
        e.give(0)
    return _function(("m",), build, None)


def _check_edge_function():
    def build(e: E):
        p = e.p
        entity = lambda: _cid_of(e, _mutation(e, p["m"], 1))  # noqa: E731
        e.var("ce_kind", _mutation(e, p["m"], 0))
        e.var("ce_edge", _mutation(e, p["m"], M_EXTRA))
        e.var("ce_edges", _mutation(e, p["m"], M_COUNT))
        e.var("ce_arg", _mutation(e, p["m"], 6))
        e.var("ce_args", e.sub(_mutation(e, p["m"], M_FOUND), 1))

        def disconnect():
            def stale():
                def expected():
                    _set(e, RCUR, _mutation(e, p["m"], 5))
                    _call(e, "record_value")
                    _relation(e)

                def actual():
                    _set(e, CUR, e.sub(e.ld(e.add(ENTITY_AT, p["m"])), 1))
                    _call(e, "read_value")
                    _relation(e)

                _reject(e, "XAX.WORKSPACE.RELATION_CONFLICT", entity, "WORKSPACE-EDGE-ARGUMENT-PRECONDITION", expected, actual)

            e.if_(e.le(p["ce_args"], p["ce_arg"]), lambda: _reject(
                e, "XAX.WORKSPACE.RELATION_CONFLICT", entity, "WORKSPACE-EDGE-ARGUMENT-INDEX", lambda: _at_most(e, "< {}", p["ce_args"]),
                lambda: D.integer(e, p["ce_arg"])), lambda: e.if_(e.eq(_mutation(e, p["m"], M_USE), 2), stale))

        def connect():
            e.if_(e.lt(p["ce_args"], p["ce_arg"]), lambda: _reject(
                e, "XAX.WORKSPACE.RELATION_CONFLICT", entity, "WORKSPACE-EDGE-ARGUMENT-INDEX", lambda: _at_most(e, "<= {}", p["ce_args"]),
                lambda: D.integer(e, p["ce_arg"])), lambda: _call(e, "check_local", p["m"], _mutation(e, p["m"], 5)))

        e.if_(e.le(p["ce_edges"], p["ce_edge"]), lambda: _reject(
            e, "XAX.WORKSPACE.CONTAINMENT_CONFLICT", entity, "WORKSPACE-TERMINATOR-EDGE", lambda: _at_most(e, "< {}", p["ce_edges"]),
            lambda: D.integer(e, p["ce_edge"])), lambda: e.if_(e.eq(p["ce_kind"], DISCONNECT_EDGE), disconnect, connect))
        e.give(0)
    return _function(("m",), build, None)


def _check_structural_function():
    """Row ``m``'s preconditions, by its kind."""
    def build(e: E):
        p = e.p
        e.var("cs_kind", _mutation(e, p["m"], 0))
        for kind, name in ((REPLACE_USE, "check_use"), (DELETE_NODE, "check_delete"), (INSERT_NODE, "check_insert"),
                           (SET_RESULT_TYPE, "check_result"), (DISCONNECT_EDGE, "check_edge"), (CONNECT_EDGE, "check_edge")):
            e.if_(e.eq(p["cs_kind"], kind), lambda name=name: _call(e, name, p["m"]))
        e.give(0)
    return _function(("m",), build, None)


def _reject(e: E, code: str, entity, rule: str, expected, actual):
    D.begin(e)
    D.text(e, code)
    entity()
    D.text(e, rule)
    expected()
    actual()
    _set(e, E_STATUS, REJECT)


def _cid_of(e: E, o):
    D.cid(e, [_cid_word(e, o, k) for k in range(4)])


def _record_cid(e: E, at):
    """A CID quoted from the edit record at word ``at`` (32 bytes)."""
    words = []
    for k in range(4):
        value = e.c(0)
        for j in range(8):
            value = e.add(e.mul(value, 256), e.ld(e.add(at, 8 * k + j)))
        words.append(value)
    D.cid(e, words)


def _begin(tables):
    """``begin``'s stages, each its own function (a function's block arguments carry every variable in scope)."""
    def parse(e: E):
        p = e.p
        _set(e, E_STATUS, OK)
        _set(e, E_EXTRAS, 0)
        _set(e, E_EXTRAS_DONE, 0)
        _set(e, E_MUTATIONS, 0)
        e.st(EC + 42, 0)  # the new references' sources written so far
        _set(e, E_NEW, 0)
        _set(e, E_PRE_END, 0)
        e.var("objects", e.rd(0))
        e.var("root", e.rd(1))
        _set(e, E_OBJECTS, p["objects"])
        _set(e, E_ROOT, p["root"])
        for op in range(128):
            e.st(OPF + op, (1 if op in ENTITY else 0) + (2 if op in ATTRIBUTE else 0))
        e.for_("z", 0, p["objects"], lambda: (e.st(e.add(STATE, p["z"]), 0), e.st(e.add(ALIAS, p["z"]), NONE), e.st(e.add(COPY, p["z"]), 0)))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        e.var("length", _ctrl(e, E_LENGTH))
        e.var("at", EIN)

        def malformed(rule: str):
            def write():
                _reject(e, "XAX.EDIT.RECORD", lambda: D.text(e, "edit"), rule, lambda: D.text(e, "xax-edit-v1"), lambda: D.integer(e, e.sub(p["at"], EIN)))
            return write

        def need(count, rule: str):
            e.if_(e.both(running(), e.lt(e.add(EIN, p["length"]), e.add(p["at"], count))), malformed(rule))

        def byte():
            value = e.ld(p["at"])
            e.set("at", e.add(p["at"], 1))
            return value

        def uleb(name: str):
            _set(e, RCUR, p["at"])
            e.var(name, _call(e, "record_uleb"))
            e.set("at", _ctrl(e, RCUR))
            return p[name]

        need(len(RECORD_MAGIC) + 32, "EDIT-RECORD-MAGIC")

        def magic():
            e.var("magic_ok", 1)
            for k, value in enumerate(RECORD_MAGIC):
                e.set("magic_ok", e.and_(p["magic_ok"], e.flag(e.eq(e.ld(EIN + k), value))))
            e.if_(e.eq(p["magic_ok"], 0), malformed("EDIT-RECORD-MAGIC"))
            e.set("at", EIN + len(RECORD_MAGIC))

        e.if_(running(), magic)

        def expected_root():
            e.var("any_root", 1)
            e.var("same_root", 1)
            for k in range(4):
                e.var(f"er{k}", 0)
                for j in range(8):
                    e.set(f"er{k}", e.add(e.mul(p[f"er{k}"], 256), e.ld(EIN + len(RECORD_MAGIC) + 8 * k + j)))
                e.set("any_root", e.and_(p["any_root"], e.flag(e.eq(p[f"er{k}"], 0))))
                e.set("same_root", e.and_(p["same_root"], e.flag(e.eq(p[f"er{k}"], _cid_word(e, p["root"], k)))))
            e.if_(e.both(e.eq(p["any_root"], 0), e.eq(p["same_root"], 0)), lambda: _reject(
                e, "XAX.WORKSPACE.STALE_ROOT", lambda: D.text(e, "R0"), "WORKSPACE-EXPECTED-ROOT",
                lambda: _record_cid(e, EIN + len(RECORD_MAGIC)), lambda: _cid_of(e, p["root"])))
            e.set("at", EIN + len(RECORD_MAGIC) + 32)

        e.if_(running(), expected_root)
        e.var("count", 0)
        e.if_(running(), lambda: e.set("count", uleb("mutation_count")))
        e.if_(e.both(running(), e.lt(MUT_LIMIT, p["count"])), malformed("EDIT-RECORD-COUNT"))
        e.var("mi", 0)

        def record_words(at, name: str):
            """The four big-endian words of the CID at record word ``at``."""
            for k in range(4):
                e.var(f"{name}{k}", 0)
                for j in range(8):
                    e.set(f"{name}{k}", e.add(e.mul(p[f"{name}{k}"], 256), e.ld(e.add(at, 8 * k + j))))

        def replace():
            """S15d.4a (ADR-312): ``REPLACE_REFERENCE``: the owner by its CID, the old child among its references; the new
            child (an object of the store or one the record supplies) is found once the supplied objects have CIDs."""
            need(96, "EDIT-RECORD-TARGET")
            e.var("owner_at", p["at"])
            e.set("at", e.add(p["at"], 96))

            def located():
                record_words(p["owner_at"], "ow")
                e.var("owner", NONE)
                e.for_("fo", 0, p["objects"], lambda: e.if_(e.both(*(e.eq(_cid_word(e, p["fo"], k), p[f"ow{k}"]) for k in range(4))),
                                                            lambda: e.set("owner", p["fo"])))
                e.if_(e.eq(p["owner"], NONE), lambda: _reject(
                    e, "XAX.WORKSPACE.HANDLE", lambda: _record_cid(e, p["owner_at"]), "WORKSPACE-HANDLE-GENERATION",
                    lambda: D.text(e, "object at the current root"), lambda: D.text(e, "unbound or stale")))

                def child():
                    record_words(e.add(p["owner_at"], 32), "oc")
                    e.var("old", NONE)
                    e.for_("fc", 0, _nrefs(e, p["owner"]), lambda: e.if_(e.both(*(e.eq(_cid_word(e, _ref(e, p["owner"], p["fc"]), k), p[f"oc{k}"])
                                                                                 for k in range(4))), lambda: e.set("old", _ref(e, p["owner"], p["fc"]))))
                    e.if_(e.eq(p["old"], NONE), lambda: _reject(
                        e, "XAX.WORKSPACE.RELATION_CONFLICT", lambda: _record_cid(e, p["owner_at"]), "EDIT-REFERENCE-PRECONDITION",
                        lambda: _record_cid(e, e.add(p["owner_at"], 32)), lambda: D.text(e, "not a reference of the object")))

                    def row():
                        e.var("dup", 0)
                        e.for_("dq", 0, p["mi"], lambda: e.if_(e.both(
                            e.eq(_mutation(e, p["dq"], 0), REPLACE_REFERENCE), e.eq(_mutation(e, p["dq"], 2), p["owner"]), e.eq(_mutation(e, p["dq"], 3), p["old"])),
                            lambda: e.set("dup", 1)))
                        e.if_(e.ne(p["dup"], 0), lambda: _reject(
                            e, "XAX.WORKSPACE.DUPLICATE_MUTATION", lambda: _record_cid(e, p["owner_at"]), "WORKSPACE-MUTATION-TARGET-UNIQUE",
                            lambda: D.text(e, "one replacement per reference"), lambda: D.text(e, "duplicate")))
                        def write():
                            fields = (REPLACE_REFERENCE, p["owner"], p["owner"], p["old"], NONE, e.add(p["owner_at"], 64), 0, 0)
                            for field, value in enumerate(fields):
                                e.st(e.add(p["row"], field), value)
                            e.st(e.add(ENTITY_AT, p["mi"]), 0)
                            _set(e, E_MUTATIONS, e.add(p["mi"], 1))

                        e.if_(running(), write)

                    e.if_(running(), row)

                e.if_(running(), child)

            e.if_(running(), located)

        def mutation():
            row = e.add(MUT, e.mul(p["mi"], MUT_WORDS))
            e.var("row", row)
            e.var("mkind", uleb("m_kind"))
            e.if_(e.both(running(), e.either(e.eq(p["mkind"], 0), e.lt(CONNECT_EDGE, p["mkind"]))), malformed("EDIT-RECORD-KIND"))
            e.if_(e.both(running(), e.eq(p["mkind"], REPLACE_REFERENCE)), replace, lambda: e.if_(running(), node_mutation))
            e.set("mi", e.add(p["mi"], 1))

        def node_mutation():
            need(32, "EDIT-RECORD-TARGET")
            e.var("target_at", p["at"])
            e.set("at", e.add(p["at"], 32))
            # The function with that CID.
            for k in range(4):
                e.var(f"tw{k}", 0)
                for j in range(8):
                    e.set(f"tw{k}", e.add(e.mul(p[f"tw{k}"], 256), e.ld(e.add(p["target_at"], 8 * k + j))))
            e.var("function", NONE)
            e.for_("fo", 0, p["objects"], lambda: e.if_(e.both(*(e.eq(_cid_word(e, p["fo"], k), p[f"tw{k}"]) for k in range(4))),
                                                        lambda: e.set("function", p["fo"])))
            e.var("mblock", uleb("m_block"))
            e.var("mnode", uleb("m_node"))
            e.var("mexpected", 0)  # S15d.4b: a structural row's payload (record word)
            e.var("mvalue", 0)  # and its operand, result, argument or local id
            e.var("medge", NONE)

            def plain():
                e.set("mexpected", uleb("m_expected"))
                e.set("mvalue", uleb("m_value"))

            def skip_value():
                _set(e, RCUR, p["at"])
                e.if_(e.both(e.lt(VALUE_INSERTED, _call(e, "record_value")), running()), malformed("EDIT-RECORD-VALUE"))
                e.set("at", _ctrl(e, RCUR))

            def use():
                e.set("mvalue", uleb("u_operand"))
                e.set("mexpected", p["at"])
                skip_value()
                e.if_(running(), skip_value)

            def insert():
                e.set("mvalue", uleb("i_local"))
                e.set("mexpected", p["at"])
                uleb("i_operation")
                e.var("i_count", uleb("i_operands"))
                e.var("i_q", 0)
                e.while_(lambda: e.both(e.lt(p["i_q"], p["i_count"]), running()), lambda: (skip_value(), e.set("i_q", e.add(p["i_q"], 1))))
                need(32, "EDIT-RECORD-TARGET")
                e.set("at", e.add(p["at"], 32))
                e.var("i_has", 0)
                e.if_(running(), lambda: e.set("i_has", uleb("i_has_value")))
                e.if_(e.both(running(), e.ne(p["i_has"], 0)), lambda: uleb("i_value"))
                e.var("i_attrs", 0)
                e.if_(running(), lambda: e.set("i_attrs", uleb("i_attributes")))
                e.var("i_a", 0)
                e.while_(lambda: e.both(e.lt(p["i_a"], p["i_attrs"]), running()), lambda: (uleb("i_attribute"), e.set("i_a", e.add(p["i_a"], 1))))

            def retype():
                e.set("mvalue", uleb("t_result"))
                need(64, "EDIT-RECORD-TARGET")
                e.set("mexpected", p["at"])
                e.set("at", e.add(p["at"], 64))

            def edge():
                e.set("mvalue", uleb("x_argument"))
                e.set("mexpected", p["at"])
                skip_value()
                e.set("medge", p["mnode"])
                e.set("mnode", 0)  # an edge's handle is its block's first node

            e.if_(e.lt(p["mkind"], REPLACE_REFERENCE), plain)
            e.if_(e.eq(p["mkind"], REPLACE_USE), use)
            e.if_(e.eq(p["mkind"], INSERT_NODE), insert)
            e.if_(e.eq(p["mkind"], SET_RESULT_TYPE), retype)
            e.if_(e.lt(SET_RESULT_TYPE, p["mkind"]), edge)

            def located():
                e.if_(e.either(e.eq(p["function"], NONE), e.ne(_kind(e, e.sel(e.eq(p["function"], NONE), 0, p["function"])), int(Kind.FUNCTION))),
                      lambda: _reject(e, "XAX.WORKSPACE.HANDLE", lambda: _record_cid(e, p["target_at"]), "WORKSPACE-HANDLE-GENERATION",
                                      lambda: D.text(e, "function at the current root"), lambda: D.text(e, "unbound or stale")))

                def graph():
                    length, at = _plain_body(e, p["function"])
                    e.var("fcur", at)
                    e.var("gidx", 0)
                    e.var("gidx_shift", 1)
                    e.var("gidx_more", 1)

                    def step():
                        e.var("gb_byte", e.rd(p["fcur"]))
                        e.set("gidx", e.add(p["gidx"], e.mul(e.and_(p["gb_byte"], 127), p["gidx_shift"])))
                        e.set("gidx_shift", e.mul(p["gidx_shift"], 128))
                        e.set("gidx_more", e.flag(e.le(128, p["gb_byte"])))
                        e.set("fcur", e.add(p["fcur"], 1))

                    e.while_(lambda: e.ne(p["gidx_more"], 0), step)
                    e.var("graph", _ref(e, p["function"], p["gidx"]))
                    e.var("dup", 0)
                    e.var("pair", 0)  # S15d.4b: one disconnection and one connection of the same edge argument share a handle

                    def same():
                        e.set("dup", e.add(p["dup"], 1))
                        e.var("dk", _mutation(e, p["dq"], 0))
                        e.if_(e.both(e.lt(SET_RESULT_TYPE, p["dk"]), e.lt(SET_RESULT_TYPE, p["mkind"]), e.ne(p["dk"], p["mkind"]),
                                     e.eq(_mutation(e, p["dq"], M_EXTRA), p["medge"]), e.eq(_mutation(e, p["dq"], 6), p["mvalue"])),
                              lambda: e.set("pair", e.add(p["pair"], 1)))

                    e.for_("dq", 0, p["mi"], lambda: e.if_(e.both(
                        e.eq(_mutation(e, p["dq"], 2), p["graph"]), e.eq(_mutation(e, p["dq"], 3), p["mblock"]), e.eq(_mutation(e, p["dq"], 4), p["mnode"]),
                        e.ne(_mutation(e, p["dq"], 0), REPLACE_REFERENCE)), same))
                    e.if_(e.either(e.lt(1, p["dup"]), e.both(e.eq(p["dup"], 1), e.eq(p["pair"], 0))), lambda: _reject(
                        e, "XAX.WORKSPACE.DUPLICATE_MUTATION", lambda: _record_cid(e, p["target_at"]), "WORKSPACE-MUTATION-TARGET-UNIQUE",
                        lambda: D.text(e, "one mutation per node, except one matching disconnect/connect edge-argument pair"), lambda: D.text(e, "duplicate")))
                    e.var("lid", 0)

                    def local_id():
                        e.for_("lq", 0, p["mi"], lambda: e.if_(e.both(e.eq(_mutation(e, p["lq"], 0), INSERT_NODE), e.eq(_mutation(e, p["lq"], 6), p["mvalue"])),
                                                                lambda: e.set("lid", 1)))
                        e.if_(e.ne(p["lid"], 0), lambda: _reject(
                            e, "XAX.WORKSPACE.DUPLICATE_MUTATION", lambda: (D.put(e, D.T_FORMAT), D.text(e, "I{}"), D.put(e, 1), D.integer(e, p["mvalue"])),
                            "WORKSPACE-INSERT-LOCAL-ID-UNIQUE", lambda: D.text(e, "one inserted node per transaction-local id"), lambda: D.text(e, "duplicate")))

                    e.if_(e.both(running(), e.eq(p["mkind"], INSERT_NODE)), local_id)
                    for field, value in enumerate((p["mkind"], p["function"], p["graph"], p["mblock"], p["mnode"], p["mexpected"], p["mvalue"], 0,
                                                   p["medge"], 0, 0, 0)):
                        e.st(e.add(p["row"], field), value)
                    e.st(e.add(ENTITY_AT, p["mi"]), 0)
                    _set(e, E_MUTATIONS, e.add(p["mi"], 1))

                e.if_(running(), graph)

            e.if_(running(), located)

        e.while_(lambda: e.both(e.lt(p["mi"], p["count"]), running()), mutation)

        def supplied():
            """S15d.4a (ADR-312): the objects the record supplies, each kept as a new object of the transaction's own."""
            e.var("supplied", uleb("s_count"))
            e.if_(e.both(running(), e.lt(MUT_LIMIT, p["supplied"])), malformed("EDIT-RECORD-COUNT"))
            e.if_(e.both(running(), e.eq(p["supplied"], 0)), malformed("EDIT-RECORD-END"))  # an empty section is no section
            e.var("si", 0)

            def one():
                e.var("xe", _ctrl(e, E_EXTRAS))
                e.var("xrow", e.add(EXTRA, e.mul(p["xe"], EXTRA_WORDS)))
                e.var("s_kind_v", uleb("s_kind"))
                e.var("s_refs_v", uleb("s_refs"))
                e.if_(e.both(running(), e.lt(EIN_LIMIT, p["s_refs_v"])), malformed("EDIT-RECORD-OBJECT"))
                need(e.mul(e.sel(running(), p["s_refs_v"], 0), 32), "EDIT-RECORD-OBJECT")
                e.var("s_refs_at", p["at"])
                e.set("at", e.add(p["at"], e.mul(e.sel(running(), p["s_refs_v"], 0), 32)))
                e.var("s_body_v", 0)
                e.if_(running(), lambda: e.set("s_body_v", uleb("s_body")))
                need(e.sel(running(), p["s_body_v"], 0), "EDIT-RECORD-OBJECT")
                e.var("s_body_at", p["at"])
                e.set("at", e.add(p["at"], e.sel(running(), p["s_body_v"], 0)))

                def keep():
                    e.st(e.add(p["xrow"], 3), NONE)  # no alias yet
                    for field, value in ((X_SUPPLIED, 1), (X_KIND, p["s_kind_v"]), (X_NREFS, p["s_refs_v"]), (X_REFS, p["s_refs_at"]),
                                         (X_BODY_LENGTH, p["s_body_v"]), (X_BODY, p["s_body_at"]), (X_REACHED, 0)):
                        e.st(e.add(p["xrow"], field), value)
                    _set(e, E_EXTRAS, e.add(p["xe"], 1))

                e.if_(running(), keep)
                e.set("si", e.add(p["si"], 1))

            e.while_(lambda: e.both(e.lt(p["si"], p["supplied"]), running()), one)

        e.if_(e.both(running(), e.lt(p["at"], e.add(EIN, p["length"]))), supplied)
        e.if_(e.both(running(), e.ne(p["at"], e.add(EIN, p["length"]))), malformed("EDIT-RECORD-END"))
        e.if_(e.both(running(), e.eq(p["count"], 0)), lambda: _reject(
            e, "XAX.WORKSPACE.EMPTY_TRANSACTION", lambda: D.text(e, "R0"), "WORKSPACE-MUTATION-NONEMPTY", lambda: D.text(e, ">= 1 mutation"),
            lambda: D.integer(e, 0)))

        e.give(_ctrl(e, E_STATUS))

    def locate(e: E):
        p = e.p
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("root", _ctrl(e, E_ROOT))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        # Locate every mutated node (one pass per mutated graph) and check its preconditions.
        def check(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            length, at = _graph_body(e, p["cm_graph"])
            e.var("cm_at", at)
            e.var("cm_seen", e.ld(e.add(p["cm_row"], 7)))

            def scan():
                _set(e, CUR, p["cm_at"])
                _set(e, MODE, LOCATE)
                _call(e, "scan_graph", p["cm_graph"])

            e.if_(e.eq(p["cm_seen"], 0), scan)  # a graph with several mutations is scanned once
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def missing():
                _reject(e, "XAX.WORKSPACE.HANDLE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-NODE-INDEX",
                        lambda: D.text(e, "a node of the function's graph"),
                        lambda: (D.put(e, D.T_LIST), D.put(e, 2), D.integer(e, _mutation(e, m, 3)), D.integer(e, _mutation(e, m, 4))))

            e.if_(e.eq(p["cm_located"], 0), missing)

        def precondition(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def preconditions():
                e.var("cm_op", e.sub(p["cm_located"], 1 << 32))
                e.var("cm_kind", _mutation(e, m, 0))

                def operation():
                    def conflict():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-PRECONDITION",
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, _mutation(e, m, 5))),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], _mutation(e, m, 5)), conflict)
                    wrapping = lambda value: e.either(*(e.eq(value, op) for op in WRAPPING))  # noqa: E731

                    def unsupported():
                        _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-CONTRACT-PRESERVED",
                                lambda: D.text(e, "wrapping arithmetic replacement"), lambda: D.integer(e, _mutation(e, m, 6)))

                    e.if_(e.both(running(), e.not_(e.both(wrapping(_mutation(e, m, 6)), wrapping(p["cm_op"])))), unsupported)

                def constant():
                    def not_constant():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-NODE",
                                lambda: D.text(e, Operation.CONSTANT.name),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], int(Operation.CONSTANT)), not_constant)

                    def value():
                        e.var("cm_entity", _ref(e, p["cm_graph"], e.sub(e.ld(e.add(ENTITY_AT, m)), 1)))
                        clen, cat = _plain_body(e, p["cm_entity"])
                        e.var("cm_at", cat)
                        e.var("cm_bytes", e.rd(e.add(p["cm_at"], 1)))  # after the type's reference index (0)
                        e.var("cm_type", _ref(e, p["cm_entity"], 0))
                        tlen, tat = _plain_body(e, p["cm_type"])
                        e.var("cm_form", e.rd(tat))
                        e.var("cm_width", e.rd(e.add(tat, 1)))  # bits<N>, N < 128 (one ULEB byte)

                        def unsupported():
                            _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "EDIT-CONSTANT-BITS",
                                    lambda: D.text(e, "an integer constant of at most 64 bits"), lambda: D.integer(e, p["cm_bytes"]))

                        e.if_(e.either(e.ne(p["cm_form"], 1), e.lt(8, p["cm_bytes"]), e.le(128, p["cm_width"])), unsupported)

                        def checked():
                            e.var("cm_old", 0)
                            e.for_("cb", 0, p["cm_bytes"], lambda: e.set("cm_old", e.add(p["cm_old"], e.mul(
                                e.rd(e.add(e.add(p["cm_at"], 2), p["cb"])), _pow256(e, p["cb"])))))

                            def stale():
                                _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-PRECONDITION",
                                        lambda: D.integer(e, _mutation(e, m, 5)), lambda: D.integer(e, p["cm_old"]))

                            e.if_(e.ne(p["cm_old"], _mutation(e, m, 5)), stale)
                            e.var("cm_value", _mutation(e, m, 6))
                            fits = e.either(e.le(64, p["cm_width"]), e.lt(p["cm_value"], _pow2(e, e.sel(e.lt(p["cm_width"], 64), p["cm_width"], 0))))

                            def range_():
                                _reject(e, "XAX.WORKSPACE.INVALID_VALUE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-RANGE",
                                        lambda: (D.put(e, D.T_FORMAT), D.text(e, "value fitting {}"), D.put(e, 1), _cid_of(e, p["cm_type"])),
                                        lambda: D.integer(e, p["cm_value"]))

                            e.if_(e.both(running(), e.not_(fits)), range_)

                            def extra():
                                e.var("xe", _ctrl(e, E_EXTRAS))
                                e.var("xrow", e.add(EXTRA, e.mul(p["xe"], EXTRA_WORDS)))
                                e.st(p["xrow"], p["cm_type"])
                                e.st(e.add(p["xrow"], 1), p["cm_bytes"])
                                e.st(e.add(p["xrow"], 2), p["cm_value"])
                                e.st(e.add(p["xrow"], 3), NONE)
                                e.st(e.add(p["xrow"], X_SUPPLIED), 0)
                                e.st(e.add(p["cm_row"], 7), p["xe"])
                                _set(e, E_EXTRAS, e.add(p["xe"], 1))

                            e.if_(running(), extra)

                        e.if_(running(), checked)

                    e.if_(running(), value)

                e.if_(e.eq(p["cm_kind"], SET_OPERATION), operation, lambda: e.if_(
                    e.eq(p["cm_kind"], SET_CONSTANT), constant, lambda: _call(e, "check_structural", m)))

            e.if_(running(), preconditions)

        e.for_("cmq", 0, e.sel(running(), _ctrl(e, E_MUTATIONS), 0), lambda: e.if_(
            e.both(running(), e.ne(_mutation(e, p["cmq"], 0), REPLACE_REFERENCE)), lambda: check(p["cmq"])))
        e.give(_ctrl(e, E_STATUS))

    def affected_stage(e: E):
        p = e.p
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("root", _ctrl(e, E_ROOT))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        # The affected objects: the mutated graphs and every transitive user.
        def affected():
            e.for_("ag", 0, _ctrl(e, E_MUTATIONS), lambda: e.st(e.add(STATE, _mutation(e, p["ag"], 2)), 1))
            e.var("changed", 1)

            def sweep():
                e.set("changed", 0)

                def each():
                    def users():
                        e.var("hit", 0)
                        e.for_("ar", 0, _nrefs(e, p["ao"]), lambda: e.if_(e.ne(_ref(e, p["ao"], p["ar"]), NONE), lambda: e.if_(
                            e.eq(e.ld(e.add(STATE, _ref(e, p["ao"], p["ar"]))), 1), lambda: e.set("hit", 1))))
                        e.if_(e.ne(p["hit"], 0), lambda: (e.st(e.add(STATE, p["ao"]), 1), e.set("changed", 1)))

                    e.if_(e.eq(e.ld(e.add(STATE, p["ao"])), 0), users)

                e.for_("ao", 0, p["objects"], each)

            e.while_(lambda: e.ne(p["changed"], 0), sweep)
            e.var("count_affected", 0)

            def kind_check():
                def check_one():
                    e.set("count_affected", e.add(p["count_affected"], 1))
                    e.var("ak", _kind(e, p["kc"]))
                    e.var("ak_supported", e.flag(e.either(*(e.eq(p["ak"], int(kind)) for kind in (Kind.GRAPH_FRAGMENT, Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT,
                                                                                 Kind.PACKAGE)))))
                    blen, bat = _plain_body(e, p["kc"])
                    e.var("ak_request", e.flag(e.both(e.eq(p["ak"], int(Kind.BUILD)), e.eq(e.rd(bat), 2))))

                    def group():
                        _reject(e, "XAX.WORKSPACE.TOPOLOGY", lambda: _cid_of(e, p["kc"]), "WORKSPACE-RECURSION-REBUILD",
                                lambda: D.text(e, "non-recursive direct-call users"), lambda: D.text(e, Kind.RECURSION_GROUP.name))

                    def other():
                        _reject(e, "XAX.WORKSPACE.TOPOLOGY", lambda: _cid_of(e, p["kc"]), "WORKSPACE-SUPPORTED-USER",
                                lambda: D.text(e, "graph, function, module, program root, package, or build request"),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Kind")), D.put(e, p["ak"])))

                    e.if_(running(), lambda: e.if_(e.eq(p["ak"], int(Kind.RECURSION_GROUP)), group,
                                                   lambda: e.if_(e.both(e.eq(p["ak_supported"], 0), e.eq(p["ak_request"], 0)), other)))

                e.if_(e.eq(e.ld(e.add(STATE, p["kc"])), 1), check_one)

            e.for_("kc", 0, p["objects"], kind_check)
            _set(e, E_AFFECTED, p["count_affected"])

        e.if_(running(), affected)
        e.give(_ctrl(e, E_STATUS))

    def check_stage(e: E):
        p = e.p
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("root", _ctrl(e, E_ROOT))
        running = lambda: e.eq(_ctrl(e, E_STATUS), OK)  # noqa: E731
        # Locate every mutated node (one pass per mutated graph) and check its preconditions.
        def check(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            length, at = _graph_body(e, p["cm_graph"])
            e.var("cm_at", at)
            e.var("cm_seen", e.ld(e.add(p["cm_row"], 7)))

            def scan():
                _set(e, CUR, p["cm_at"])
                _set(e, MODE, LOCATE)
                _call(e, "scan_graph", p["cm_graph"])

            e.if_(e.eq(p["cm_seen"], 0), scan)  # a graph with several mutations is scanned once
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def missing():
                _reject(e, "XAX.WORKSPACE.HANDLE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-NODE-INDEX",
                        lambda: D.text(e, "a node of the function's graph"),
                        lambda: (D.put(e, D.T_LIST), D.put(e, 2), D.integer(e, _mutation(e, m, 3)), D.integer(e, _mutation(e, m, 4))))

            e.if_(e.eq(p["cm_located"], 0), missing)

        def precondition(m):
            e.var("cm_row", e.add(MUT, e.mul(m, MUT_WORDS)))
            e.var("cm_graph", _mutation(e, m, 2))
            e.var("cm_located", e.ld(e.add(p["cm_row"], 7)))

            def preconditions():
                e.var("cm_op", e.sub(p["cm_located"], 1 << 32))
                e.var("cm_kind", _mutation(e, m, 0))

                def operation():
                    def conflict():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-PRECONDITION",
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, _mutation(e, m, 5))),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], _mutation(e, m, 5)), conflict)
                    wrapping = lambda value: e.either(*(e.eq(value, op) for op in WRAPPING))  # noqa: E731

                    def unsupported():
                        _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-OP-CONTRACT-PRESERVED",
                                lambda: D.text(e, "wrapping arithmetic replacement"), lambda: D.integer(e, _mutation(e, m, 6)))

                    e.if_(e.both(running(), e.not_(e.both(wrapping(_mutation(e, m, 6)), wrapping(p["cm_op"])))), unsupported)

                def constant():
                    def not_constant():
                        _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-NODE",
                                lambda: D.text(e, Operation.CONSTANT.name),
                                lambda: (D.put(e, D.T_NAME), D.put(e, D.ENUM_NAMES.index("Operation")), D.put(e, p["cm_op"])))

                    e.if_(e.ne(p["cm_op"], int(Operation.CONSTANT)), not_constant)

                    def value():
                        e.var("cm_entity", _ref(e, p["cm_graph"], e.sub(e.ld(e.add(ENTITY_AT, m)), 1)))
                        clen, cat = _plain_body(e, p["cm_entity"])
                        e.var("cm_at", cat)
                        e.var("cm_bytes", e.rd(e.add(p["cm_at"], 1)))  # after the type's reference index (0)
                        e.var("cm_type", _ref(e, p["cm_entity"], 0))
                        tlen, tat = _plain_body(e, p["cm_type"])
                        e.var("cm_form", e.rd(tat))
                        e.var("cm_width", e.rd(e.add(tat, 1)))  # bits<N>, N < 128 (one ULEB byte)

                        def unsupported():
                            _reject(e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: _cid_of(e, _mutation(e, m, 1)), "EDIT-CONSTANT-BITS",
                                    lambda: D.text(e, "an integer constant of at most 64 bits"), lambda: D.integer(e, p["cm_bytes"]))

                        e.if_(e.either(e.ne(p["cm_form"], 1), e.lt(8, p["cm_bytes"]), e.le(128, p["cm_width"])), unsupported)

                        def checked():
                            e.var("cm_old", 0)
                            e.for_("cb", 0, p["cm_bytes"], lambda: e.set("cm_old", e.add(p["cm_old"], e.mul(
                                e.rd(e.add(e.add(p["cm_at"], 2), p["cb"])), _pow256(e, p["cb"])))))

                            def stale():
                                _reject(e, "XAX.WORKSPACE.ATTRIBUTE_CONFLICT", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-PRECONDITION",
                                        lambda: D.integer(e, _mutation(e, m, 5)), lambda: D.integer(e, p["cm_old"]))

                            e.if_(e.ne(p["cm_old"], _mutation(e, m, 5)), stale)
                            e.var("cm_value", _mutation(e, m, 6))
                            fits = e.either(e.le(64, p["cm_width"]), e.lt(p["cm_value"], _pow2(e, e.sel(e.lt(p["cm_width"], 64), p["cm_width"], 0))))

                            def range_():
                                _reject(e, "XAX.WORKSPACE.INVALID_VALUE", lambda: _cid_of(e, _mutation(e, m, 1)), "WORKSPACE-CONSTANT-RANGE",
                                        lambda: (D.put(e, D.T_FORMAT), D.text(e, "value fitting {}"), D.put(e, 1), _cid_of(e, p["cm_type"])),
                                        lambda: D.integer(e, p["cm_value"]))

                            e.if_(e.both(running(), e.not_(fits)), range_)

                            def extra():
                                e.var("xe", _ctrl(e, E_EXTRAS))
                                e.var("xrow", e.add(EXTRA, e.mul(p["xe"], EXTRA_WORDS)))
                                e.st(p["xrow"], p["cm_type"])
                                e.st(e.add(p["xrow"], 1), p["cm_bytes"])
                                e.st(e.add(p["xrow"], 2), p["cm_value"])
                                e.st(e.add(p["xrow"], 3), NONE)
                                e.st(e.add(p["xrow"], X_SUPPLIED), 0)
                                e.st(e.add(p["cm_row"], 7), p["xe"])
                                _set(e, E_EXTRAS, e.add(p["xe"], 1))

                            e.if_(running(), extra)

                        e.if_(running(), checked)

                    e.if_(running(), value)

                e.if_(e.eq(p["cm_kind"], SET_OPERATION), operation, lambda: e.if_(
                    e.eq(p["cm_kind"], SET_CONSTANT), constant, lambda: _call(e, "check_structural", m)))

            e.if_(running(), preconditions)

        # The workspace checks the users' topology before each node's precondition.
        e.for_("cpq", 0, e.sel(running(), _ctrl(e, E_MUTATIONS), 0), lambda: e.if_(
            e.both(running(), e.ne(_mutation(e, p["cpq"], 0), REPLACE_REFERENCE)), lambda: precondition(p["cpq"])))
        e.give(_ctrl(e, E_STATUS))

    stages = [_function((), stage, tables) for stage in (parse, locate, affected_stage, check_stage)]

    def build(e: E):
        # S16a (ADR-360): after ``ws_command``, a view's or an explanation's text (``W_TEXT`` 1) or the workspace's
        # rejection (2) is the outcome; an applied batch is an edit record like any other.
        e.if_(e.ne(_wctrl(e, W_TEXT), 0), lambda: e.give(_ctrl(e, E_STATUS)))
        _set(e, E_STATUS, OK)
        for function, _items in stages:
            e.if_(e.eq(_ctrl(e, E_STATUS), OK), lambda function=function: e.call(function))
        e.give(_ctrl(e, E_STATUS))
    function, items = _function((), build, tables)
    return function, tuple(item for _function_, objects in stages for item in objects) + items


def _pow256(e: E, k):
    """``256 ** k`` for ``k`` below 8."""
    result = e.c(1)
    for bit in range(3):
        result = e.mul(result, e.sel(e.ne(e.and_(e.udiv(k, 1 << bit), 1), 0), 256 ** (1 << bit), 1))
    return result


def _pow2(e: E, k):
    """``2 ** k`` for ``k`` below 64."""
    result = e.c(1)
    for bit in range(6):
        result = e.mul(result, e.sel(e.ne(e.and_(e.udiv(k, 1 << bit), 1), 0), (1 << (1 << bit)) & ((1 << 64) - 1), 1))
    return result


def _pre_uleb(e: E, value):
    p = e.p
    e.var("pv", value)
    e.var("pv_more", 1)

    def step():
        e.var("pv_low", e.and_(p["pv"], 127))
        e.set("pv", e.udiv(p["pv"], 128))
        e.st(e.add(PRE, p["pre"]), e.add(p["pv_low"], e.mul(e.flag(e.ne(p["pv"], 0)), 128)))
        e.set("pre", e.add(p["pre"], 1))
        e.set("pv_more", e.flag(e.ne(p["pv"], 0)))

    e.while_(lambda: e.ne(p["pv_more"], 0), step)


def _pre_byte(e: E, value):
    p = e.p
    e.st(e.add(PRE, p["pre"]), value)
    e.set("pre", e.add(p["pre"], 1))


def _pre_cid(e: E, words):
    for word in words:
        for j in range(8):
            _pre_byte(e, e.and_(e.udiv(word, 1 << (8 * (7 - j))), 255))


def _next(tables):
    def build(e: E):
        p = e.p
        e.if_(e.eq(_wctrl(e, W_TEXT), 1), lambda: e.give(DONE))  # S16a: a view or an explanation edits nothing
        e.var("objects", _ctrl(e, E_OBJECTS))
        e.var("pre_start", _ctrl(e, E_PRE_END))
        e.var("pre", p["pre_start"])
        e.var("result", DONE)

        def header(kind, nrefs):
            _set(e, E_KIND, kind)
            _set(e, E_NREFS, nrefs)
            _pre_uleb(e, kind)
            _pre_byte(e, 1)
            _pre_uleb(e, nrefs)
            _set(e, E_REFS_AT, p["pre"])

        def body_from(at_word, length):
            _set(e, E_BODY_LENGTH, length)
            _pre_uleb(e, length)
            _set(e, E_BODY_AT, p["pre"])
            e.for_("bq", 0, length, lambda: _pre_byte(e, e.ld(e.add(at_word, p["bq"]))))

        def supplied_extra():
            """S15d.4a: a supplied object's preimage, from the record."""
            for name, field in (("xkind", X_KIND), ("xnrefs", X_NREFS), ("xrefs", X_REFS), ("xbody", X_BODY), ("xblen", X_BODY_LENGTH)):
                e.var(name, e.ld(e.add(p["xrow"], field)))  # names: values cross blocks only so
            header(p["xkind"], p["xnrefs"])
            e.for_("xr", 0, e.mul(p["xnrefs"], 32), lambda: _pre_byte(e, e.ld(e.add(p["xrefs"], p["xr"]))))
            body_from(p["xbody"], p["xblen"])
            _set(e, E_SLOT, e.add(p["xrow"], 4))
            _set(e, E_OBJECT, e.add(EXTRA_TAG, p["x"]))
            _set(e, E_EXTRAS_DONE, e.add(p["x"], 1))
            e.set("result", MORE)

        def extra():
            e.var("x", _ctrl(e, E_EXTRAS_DONE))
            e.var("xrow", e.add(EXTRA, e.mul(p["x"], EXTRA_WORDS)))
            e.if_(e.ne(e.ld(e.add(p["xrow"], X_SUPPLIED)), 0), supplied_extra, constant_extra)

        def constant_extra():
            e.var("xtype", e.ld(p["xrow"]))

            def typed():
                """S15d.4b: the type the record names (the store's or a supplied one, which has its CID by now)."""
                e.var("xtat", e.ld(e.add(p["xrow"], X_TYPE_AT)))
                e.set("xtype", _call(e, "type_source", p["xtat"]))
                e.var("xvalue0", e.ld(e.add(p["xrow"], 2)))

                def found():
                    e.var("xform", 0)
                    e.var("xwidth", 0)

                    def given():
                        e.var("xbody", e.ld(e.add(e.add(EXTRA, e.mul(e.sub(p["xtype"], EXTRA_TAG), EXTRA_WORDS)), X_BODY)))
                        e.set("xform", e.ld(p["xbody"]))
                        e.set("xwidth", e.ld(e.add(p["xbody"], 1)))

                    def stored():
                        tlen, tat = _plain_body(e, p["xtype"])
                        e.var("xtat2", tat)
                        e.set("xform", e.rd(p["xtat2"]))
                        e.set("xwidth", e.rd(e.add(p["xtat2"], 1)))

                    e.if_(e.le(EXTRA_TAG, p["xtype"]), given, stored)
                    e.if_(e.either(e.ne(p["xform"], 1), e.eq(p["xwidth"], 0), e.lt(64, p["xwidth"])), lambda: _reject(
                        e, "XAX.WORKSPACE.UNSUPPORTED_MUTATION", lambda: D.cid(e, [_source_cid(e, p["xtype"], k) for k in range(4)]), "EDIT-CONSTANT-BITS",
                        lambda: D.text(e, "an integer constant of at most 64 bits"), lambda: D.integer(e, p["xwidth"])))
                    fits = e.either(e.eq(p["xwidth"], 64), e.lt(p["xvalue0"], _pow2(e, e.sel(e.lt(p["xwidth"], 64), p["xwidth"], 0))))
                    e.if_(e.both(e.eq(_ctrl(e, E_STATUS), OK), e.not_(fits)), lambda: _reject(
                        e, "XAX.WORKSPACE.INVALID_VALUE", lambda: D.text(e, "edit"), "WORKSPACE-CONSTANT-RANGE",
                        lambda: (D.put(e, D.T_FORMAT), D.text(e, "value fitting {}"), D.put(e, 1), D.cid(e, [_source_cid(e, p["xtype"], k) for k in range(4)])),
                        lambda: D.integer(e, p["xvalue0"])))
                    e.st(p["xrow"], p["xtype"])
                    e.st(e.add(p["xrow"], 1), e.udiv(e.add(p["xwidth"], 7), 8))

                e.if_(e.eq(p["xtype"], NONE), lambda: _reject(
                    e, "XAX.WORKSPACE.HANDLE", lambda: _record_cid(e, p["xtat"]), "WORKSPACE-HANDLE-GENERATION",
                    lambda: D.text(e, "type at the current root"), lambda: D.text(e, "unbound or stale")), found)

            e.if_(e.eq(p["xtype"], NONE), typed)
            e.if_(e.eq(_ctrl(e, E_STATUS), OK), made_constant)

        def made_constant():
            e.var("xtype2", e.ld(p["xrow"]))
            header(int(Kind.CONSTANT), 1)
            _pre_cid(e, [_source_cid(e, p["xtype2"], k) for k in range(4)])
            e.var("xbytes", e.ld(e.add(p["xrow"], 1)))
            e.var("xvalue", e.ld(e.add(p["xrow"], 2)))
            _set(e, E_BODY_LENGTH, e.add(p["xbytes"], 2))
            _pre_uleb(e, e.add(p["xbytes"], 2))
            _set(e, E_BODY_AT, p["pre"])
            _pre_byte(e, 0)
            _pre_byte(e, p["xbytes"])
            e.for_("xb", 0, p["xbytes"], lambda: _pre_byte(e, e.and_(e.udiv(p["xvalue"], _pow256(e, p["xb"])), 255)))
            _set(e, E_SLOT, e.add(p["xrow"], 4))
            _set(e, E_OBJECT, e.add(EXTRA_TAG, p["x"]))
            _set(e, E_EXTRAS_DONE, e.add(p["x"], 1))
            e.set("result", MORE)

        def objects_():
            # The first affected object whose affected references are all rebuilt.
            e.var("ready", NONE)
            e.var("o", 0)

            def find():
                def candidate():
                    e.var("blocked", 0)
                    e.for_("nr", 0, _nrefs(e, p["o"]), lambda: e.if_(e.ne(_ref(e, p["o"], p["nr"]), NONE), lambda: e.if_(
                        e.eq(e.ld(e.add(STATE, _ref(e, p["o"], p["nr"]))), 1), lambda: e.set("blocked", 1))))

                    def replacement():
                        """S15d.4a: a replacement child of the store's that is itself rebuilt comes first."""
                        e.var("rn", _call(e, "replaced", p["o"], _mutation(e, p["bq"], 3)))
                        e.if_(e.both(e.lt(p["rn"], EXTRA_TAG), e.ne(p["rn"], NONE)), lambda: e.if_(
                            e.eq(e.ld(e.add(STATE, p["rn"])), 1), lambda: e.set("blocked", 1)))

                    e.for_("bq", 0, _ctrl(e, E_MUTATIONS), lambda: e.if_(e.both(
                        e.eq(_mutation(e, p["bq"], 0), REPLACE_REFERENCE), e.eq(_mutation(e, p["bq"], 1), p["o"])), replacement))
                    e.if_(e.eq(p["blocked"], 0), lambda: e.set("ready", p["o"]))

                e.if_(e.eq(e.ld(e.add(STATE, p["o"])), 1), candidate)
                e.set("o", e.add(p["o"], 1))

            e.while_(lambda: e.both(e.lt(p["o"], p["objects"]), e.eq(p["ready"], NONE)), find)
            e.if_(e.ne(p["ready"], NONE), lambda: rebuild(p["ready"]))

        def rebuild(o):
            e.var("ro", o)
            o = p["ro"]
            e.var("rkind", _kind(e, o))
            e.st(EC + 41, 0)  # the sorted references so far
            e.st(EC + 43, 0)  # 1: more references than ``RC_LIMIT``
            # A comparison is kept as a 64-bit flag across control flow: the general backend's register-resident lowering
            # does not carry a ``bits<1>`` value from one branch's block into a later one.
            e.var("is_module", e.flag(e.either(e.eq(p["rkind"], int(Kind.MODULE)), e.eq(p["rkind"], int(Kind.PROGRAM_ROOT)))))

            def module_refs():
                e.for_("mr", 0, _nrefs(e, o), lambda: _module_ref(e, o, p["mr"]))

            def collect():
                _set(e, MODE, COLLECT)
                length, at = _body_of(e, o, "rb")
                _set(e, CUR, at)
                e.if_(e.eq(p["rkind"], int(Kind.GRAPH_FRAGMENT)), lambda: _call(e, "scan_graph", o), lambda: _call(e, "scan_other", o))

            e.if_(e.ne(p["is_module"], 0), module_refs, collect)
            e.if_(e.ne(e.ld(EC + 43), 0), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: _cid_of(e, o), "DRIVER-EDIT-CAPACITY",
                                                           lambda: D.integer(e, RC_LIMIT), lambda: D.text(e, "larger")))
            e.var("m", e.ld(EC + 41))
            # The new references' sources, for ``reach``.
            e.var("rl", e.ld(EC + 42))
            e.st(e.add(RSTART, o), p["rl"])
            e.st(e.add(RCOUNT, o), p["m"])
            e.for_("rs", 0, p["m"], lambda: e.st(e.add(REFL, e.add(p["rl"], p["rs"])), e.ld(e.add(SRS, p["rs"]))))
            e.st(EC + 42, e.add(p["rl"], p["m"]))
            # The body, re-encoded with the new indices.
            _set(e, OUT, 0)

            def module_body():
                _call(e, "put_uleb", p["m"])
                e.for_("mb", 0, p["m"], lambda: _call(e, "put_uleb", p["mb"]))

            def emit():
                _set(e, MODE, EMIT)
                length, at = _body_of(e, o, "eb")
                _set(e, CUR, at)
                e.if_(e.eq(p["rkind"], int(Kind.GRAPH_FRAGMENT)), lambda: _call(e, "scan_graph", o), lambda: _call(e, "scan_other", o))

            e.if_(e.ne(p["is_module"], 0), module_body, emit)
            header(p["rkind"], p["m"])
            e.for_("hc", 0, p["m"], lambda: _pre_cid(e, [e.ld(e.add(e.add(SR, e.mul(p["hc"], 4)), k)) for k in range(4)]))
            body_from(BODY, _ctrl(e, OUT))
            _set(e, E_SLOT, e.add(NEWCID, e.mul(o, 4)))
            _set(e, E_OBJECT, o)
            e.st(e.add(STATE, o), 2)
            e.set("result", MORE)

        def full():
            _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "edit"), "DRIVER-EDIT-CAPACITY", lambda: D.integer(e, PRE_LIMIT), lambda: D.text(e, "larger"))

        room = e.both(e.le(e.add(p["pre_start"], BODY_LIMIT + 32 * RC_LIMIT + 64), PRE_LIMIT), e.lt(_ctrl(e, E_NEW), NEWT_LIMIT))
        e.if_(e.not_(room), full, lambda: e.if_(e.lt(_ctrl(e, E_EXTRAS_DONE), _ctrl(e, E_EXTRAS)), extra, objects_))
        _set(e, E_PRE_AT, e.add(PRE, p["pre_start"]))
        _set(e, E_PRE_LENGTH, e.sub(p["pre"], p["pre_start"]))
        _set(e, E_PRE_END, p["pre"])

        def log():
            e.var("nt", _ctrl(e, E_NEW))
            e.var("ntrow", e.add(NEWT, e.mul(p["nt"], NEWT_WORDS)))
            for field, value in enumerate((p["pre_start"], e.sub(p["pre"], p["pre_start"]), _ctrl(e, E_REFS_AT), _ctrl(e, E_NREFS), _ctrl(e, E_BODY_AT),
                                           _ctrl(e, E_BODY_LENGTH), _ctrl(e, E_KIND), _ctrl(e, E_OBJECT), 0)):
                e.st(e.add(p["ntrow"], field), value)
            _set(e, E_NEW, e.add(p["nt"], 1))

        e.if_(e.eq(_ctrl(e, E_STATUS), REJECT), lambda: e.set("result", DONE))  # S15d.4b: a type or value found wanting
        e.if_(e.eq(p["result"], MORE), log)
        e.give(p["result"])
    return _function((), build, tables)


def _module_ref(e: E, o, k):
    """A module's or program root's reference ``k`` (S15d.4a: or its replacement), collected."""
    e.var("mref", _call(e, "replaced", o, _ref(e, o, k)))
    _call(e, "insert", e.p["mref"])


def _reach(tables):
    """``COPY``: the old objects the new root reaches, through rebuilt objects' new references (an alias is the old
    object whose CID a new one has) and old objects' own references."""
    def build(e: E):
        p = e.p
        e.var("sp", 0)

        def push(source):
            e.st(e.add(STACK, p["sp"]), source)
            e.set("sp", e.add(p["sp"], 1))

        push(_ctrl(e, E_ROOT))

        def visit():
            e.set("sp", e.sub(p["sp"], 1))
            e.var("s", e.ld(e.add(STACK, p["sp"])))

            def extra():
                e.var("xrow", e.add(EXTRA, e.mul(e.sub(p["s"], EXTRA_TAG), EXTRA_WORDS)))
                e.var("xa", e.ld(e.add(p["xrow"], 3)))
                e.if_(e.ne(p["xa"], NONE), lambda: push(p["xa"]))

                def supplied():
                    """S15d.4a: a supplied object nothing aliases is written; its references are reached (each an object
                    of the store or another supplied one; anything else is EDIT-OBJECT-REFERENCE)."""
                    e.st(e.add(p["xrow"], X_REACHED), 1)
                    e.var("xrefs", e.ld(e.add(p["xrow"], X_REFS)))

                    def each():
                        for k in range(4):
                            e.var(f"xw{k}", 0)
                            for j in range(8):
                                e.set(f"xw{k}", e.add(e.mul(p[f"xw{k}"], 256), e.ld(e.add(p["xrefs"], e.add(e.mul(p["xq"], 32), 8 * k + j)))))
                            _set(e, KEY + k, p[f"xw{k}"])
                        e.var("xs", _call(e, "resolve"))
                        e.if_(e.eq(p["xs"], NONE), lambda: _reject(
                            e, "XAX.WORKSPACE.RELATION_CONFLICT", lambda: D.text(e, "edit"), "EDIT-OBJECT-REFERENCE",
                            lambda: D.text(e, "an object of the store or of the record"), lambda: _record_cid(e, e.add(p["xrefs"], e.mul(p["xq"], 32)))),
                              lambda: push(p["xs"]))

                    e.for_("xq", 0, e.ld(e.add(p["xrow"], X_NREFS)), each)

                e.if_(e.both(e.eq(p["xa"], NONE), e.ne(e.ld(e.add(p["xrow"], X_SUPPLIED)), 0), e.eq(e.ld(e.add(p["xrow"], X_REACHED)), 0)), supplied)

            def object_():
                e.var("st", e.ld(e.add(STATE, p["s"])))
                e.var("al", e.ld(e.add(ALIAS, p["s"])))

                def rebuilt():
                    def fresh():
                        e.st(e.add(COPY, p["s"]), 2)  # visited: its new version is written by the driver, not copied
                        e.for_("rr", 0, e.ld(e.add(RCOUNT, p["s"])), lambda: push(e.ld(e.add(REFL, e.add(e.ld(e.add(RSTART, p["s"])), p["rr"])))))

                    e.if_(e.ne(p["al"], NONE), lambda: e.if_(e.ne(p["al"], p["s"]), lambda: push(p["al"]), lambda: old()), fresh)

                def old():
                    def first():
                        e.st(e.add(COPY, p["s"]), 1)
                        e.for_("or", 0, _nrefs(e, p["s"]), lambda: push(_ref(e, p["s"], p["or"])))

                    e.if_(e.eq(e.ld(e.add(COPY, p["s"])), 0), first)

                e.if_(e.both(e.eq(p["st"], 2), e.eq(e.ld(e.add(COPY, p["s"])), 0)), rebuilt, lambda: e.if_(e.ne(p["st"], 2), old))

            e.if_(e.le(EXTRA_TAG, p["s"]), extra, object_)

        e.while_(lambda: e.ne(p["sp"], 0), visit)
        e.give(0)
    return _function((), build, tables)


def _place(tables):
    """After the driver wrote the newest object's CID at ``E_SLOT``: when an object of the store already has that CID,
    the new object is an alias of it (it is not written again)."""
    def build(e: E):
        p = e.p
        e.var("slot", _ctrl(e, E_SLOT))
        for k in range(4):
            e.var(f"key{k}", e.ld(e.add(p["slot"], k)))
        e.var("lo", 0)
        e.var("hi", _ctrl(e, E_OBJECTS))
        e.var("found", NONE)

        def step():
            e.var("mid", e.udiv(e.add(p["lo"], p["hi"]), 2))
            e.var("below", 0)
            e.var("same", 1)
            for k in range(4):
                e.var(f"c{k}", _cid_word(e, p["mid"], k))
                e.if_(e.ne(p["same"], 0), lambda k=k: e.if_(e.lt(p[f"c{k}"], p[f"key{k}"]), lambda: (e.set("below", 1), e.set("same", 0)),
                                                            lambda: e.if_(e.lt(p[f"key{k}"], p[f"c{k}"]), lambda: e.set("same", 0))))
            e.if_(e.ne(p["same"], 0), lambda: (e.set("found", p["mid"]), e.set("lo", p["hi"])),
                  lambda: e.if_(e.ne(p["below"], 0), lambda: e.set("lo", e.add(p["mid"], 1)), lambda: e.set("hi", p["mid"])))

        e.while_(lambda: e.lt(p["lo"], p["hi"]), step)

        def alias():
            e.var("made", _ctrl(e, E_OBJECT))
            e.if_(e.le(EXTRA_TAG, p["made"]), lambda: e.st(e.add(e.add(EXTRA, e.mul(e.sub(p["made"], EXTRA_TAG), EXTRA_WORDS)), 3), p["found"]),
                  lambda: e.st(e.add(ALIAS, p["made"]), p["found"]))
            e.st(e.add(e.add(NEWT, e.mul(e.sub(_ctrl(e, E_NEW), 1), NEWT_WORDS)), 8), 1)

        e.if_(e.ne(p["found"], NONE), alias)

        def earlier():
            """A new object equal to an earlier new one (two mutations making the same constant) is written once."""
            e.var("last", e.sub(_ctrl(e, E_NEW), 1))

            def compare():
                e.var("row", e.add(NEWT, e.mul(p["eq"], NEWT_WORDS)))
                e.var("object", e.ld(e.add(p["row"], 7)))
                e.var("other", e.sel(e.le(EXTRA_TAG, p["object"]), e.add(e.add(EXTRA, e.mul(e.sub(p["object"], EXTRA_TAG), EXTRA_WORDS)), 4),
                                     e.add(NEWCID, e.mul(p["object"], 4))))
                e.var("same", e.flag(e.eq(e.ld(e.add(p["row"], 8)), 0)))
                for k in range(4):
                    e.set("same", e.and_(p["same"], e.flag(e.eq(e.ld(e.add(p["other"], k)), p[f"key{k}"]))))
                def same():
                    e.st(e.add(e.add(NEWT, e.mul(p["last"], NEWT_WORDS)), 8), 1)
                    # S15d.4a: a rebuilt object equal to a supplied one is written as that supplied object, reached.
                    e.if_(e.le(EXTRA_TAG, p["object"]), lambda: e.st(e.add(e.add(EXTRA, e.mul(e.sub(p["object"], EXTRA_TAG), EXTRA_WORDS)), X_REACHED), 1))

                e.if_(e.ne(p["same"], 0), same)

            e.for_("eq", 0, p["last"], compare)

        e.if_(e.eq(p["found"], NONE), earlier)
        e.give(0)
    return _function((), build, tables)


def _batch_byte(e: E, value):
    e.var("bb_at", e.ld(EC + BATCH_AT))
    e.st(e.add(BATCH, e.p["bb_at"]), value)
    e.st(EC + BATCH_AT, e.add(e.p["bb_at"], 1))


def _batch_word(e: E, value):
    e.var("bw_value", value)
    for k in range(8):
        _batch_byte(e, e.and_(e.udiv(e.p["bw_value"], 1 << (8 * k)), 255))


def _batch_cid(e: E, words):
    for word in words:
        e.var("bc_word", word)
        for j in range(8):
            _batch_byte(e, e.and_(e.udiv(e.p["bc_word"], 1 << (8 * (7 - j))), 255))


def _batch(tables):
    """The S9 writer's batch (one byte per word at ``BATCH``): the count, a zero, the end, the root's CID, then each new
    object that is no alias (from its preimage) and each old object ``reach`` kept (from the object table)."""
    def build(e: E):
        p = e.p
        e.st(EC + BATCH_AT, 24)
        e.var("root", _ctrl(e, E_ROOT))
        e.var("root_alias", e.ld(e.add(ALIAS, p["root"])))
        e.var("root_new", e.flag(e.both(e.eq(e.ld(e.add(STATE, p["root"])), 2), e.eq(p["root_alias"], NONE))))
        e.var("root_old", e.sel(e.eq(p["root_alias"], NONE), p["root"], p["root_alias"]))
        e.if_(e.ne(p["root_new"], 0), lambda: _batch_cid(e, [e.ld(e.add(e.add(NEWCID, e.mul(p["root"], 4)), k)) for k in range(4)]),
              lambda: _batch_cid(e, [_cid_word(e, p["root_old"], k) for k in range(4)]))
        e.var("count", 0)
        e.var("full", 0)

        def fits(more):
            return e.le(e.add(e.ld(EC + BATCH_AT), more), BATCH_LIMIT)

        def new_object():
            e.var("row", e.add(NEWT, e.mul(p["nq"], NEWT_WORDS)))

            def write():
                e.var("n_pre", e.add(PRE, e.ld(p["row"])))
                e.var("n_refs", e.ld(e.add(p["row"], 3)))
                e.var("n_body", e.ld(e.add(p["row"], 5)))
                e.var("n_object", e.ld(e.add(p["row"], 7)))
                e.var("n_slot", e.sel(e.le(EXTRA_TAG, p["n_object"]), e.add(e.add(EXTRA, e.mul(e.sub(p["n_object"], EXTRA_TAG), EXTRA_WORDS)), 4),
                                      e.add(NEWCID, e.mul(p["n_object"], 4))))

                def body():
                    _batch_word(e, e.ld(e.add(p["row"], 6)))
                    _batch_word(e, 1)
                    _batch_word(e, p["n_refs"])
                    _batch_word(e, p["n_body"])
                    _batch_cid(e, [e.ld(e.add(p["n_slot"], k)) for k in range(4)])
                    e.var("n_ra", e.add(PRE, e.ld(e.add(p["row"], 2))))
                    e.for_("nr", 0, e.mul(p["n_refs"], 32), lambda: _batch_byte(e, e.ld(e.add(p["n_ra"], p["nr"]))))
                    e.var("n_ba", e.add(PRE, e.ld(e.add(p["row"], 4))))
                    e.for_("nb", 0, p["n_body"], lambda: _batch_byte(e, e.ld(e.add(p["n_ba"], p["nb"]))))
                    e.set("count", e.add(p["count"], 1))

                e.if_(fits(e.add(64, e.add(e.mul(p["n_refs"], 32), p["n_body"]))), body, lambda: e.set("full", 1))

            # S15d.4a: a supplied object ``reach`` did not reach is not written.
            e.var("n_obj", e.ld(e.add(p["row"], 7)))
            e.var("n_xrow", e.add(EXTRA, e.mul(e.sel(e.le(EXTRA_TAG, p["n_obj"]), e.sub(p["n_obj"], EXTRA_TAG), 0), EXTRA_WORDS)))
            e.var("n_unreached", e.flag(e.both(e.le(EXTRA_TAG, p["n_obj"]), e.ne(e.ld(e.add(p["n_xrow"], X_SUPPLIED)), 0),
                                               e.eq(e.ld(e.add(p["n_xrow"], X_REACHED)), 0))))
            e.if_(e.both(e.eq(e.ld(e.add(p["row"], 8)), 0), e.eq(p["n_unreached"], 0)), write)

        e.for_("nq", 0, _ctrl(e, E_NEW), new_object)

        def old_object():
            def write():
                e.var("o_refs", _nrefs(e, p["oq"]))
                e.var("o_graph", e.flag(e.eq(_kind(e, p["oq"]), int(Kind.GRAPH_FRAGMENT))))
                glen, gat = _graph_body(e, p["oq"])
                plen, pat = _plain_body(e, p["oq"])
                e.var("o_len", e.sel(e.ne(p["o_graph"], 0), glen, plen))
                e.var("o_at", e.sel(e.ne(p["o_graph"], 0), gat, pat))

                def body():
                    _batch_word(e, _kind(e, p["oq"]))
                    _batch_word(e, 1)
                    _batch_word(e, p["o_refs"])
                    _batch_word(e, p["o_len"])
                    _batch_cid(e, [_cid_word(e, p["oq"], k) for k in range(4)])
                    e.for_("or_", 0, p["o_refs"], lambda: _batch_cid(e, [_cid_word(e, _ref(e, p["oq"], p["or_"]), k) for k in range(4)]))
                    e.for_("ob", 0, p["o_len"], lambda: _batch_byte(e, e.rd(e.add(p["o_at"], p["ob"]))))
                    e.set("count", e.add(p["count"], 1))

                e.if_(fits(e.add(64, e.add(e.mul(p["o_refs"], 32), p["o_len"]))), body, lambda: e.set("full", 1))

            e.if_(e.eq(e.ld(e.add(COPY, p["oq"])), 1), write)

        e.for_("oq", 0, _ctrl(e, E_OBJECTS), old_object)
        e.var("end", e.ld(EC + BATCH_AT))
        e.st(EC + BATCH_AT, 0)
        _batch_word(e, p["count"])
        _batch_word(e, 0)
        _batch_word(e, p["end"])
        _set(e, E_BATCH_LENGTH, p["end"])
        e.if_(e.ne(p["full"], 0), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "edit"), "DRIVER-SNAPSHOT-CAPACITY",
                                                  lambda: D.integer(e, BATCH_LIMIT), lambda: D.text(e, "larger")))
        e.give(0)
    return _function((), build, tables)


# -- S16a (ADR-360): the native workspace: ``view`` and ``apply`` ------------------------------------------------------
#
# ``view <store> <selector> <output>`` writes, as text, the store's functions (an empty selector) or one function
# (``F<n>``) with workspace-local handles: ``N<i>`` its nodes in block order, ``P<i>`` its block parameters in block
# order, ``T<i>`` its types in order of first appearance (signature, then block parameters and node results).  The
# first line is the root CID, the freshness token.  ``apply <store> <batch> <output>`` reads a batch in those handles
# (``R <root CID>``, ``F<n>``, then edits) and translates it into this module's edit record, which ``edit``'s engine
# applies: every old value a mutation's preconditions need is read from the store, as ``LocalMutationSession`` does.
# Both read the store through the verifier's object table; nothing here is program source.
WSC = EB + 192  # 64 control words (past the operation flags at ``OPF``)
(W_LEN, W_OUT, W_FN, W_GRAPH, W_SELECT, W_NBLOCKS, W_ENTRY, W_NODES, W_PARAMS, W_TYPES, W_TCUR, W_RCUR, W_TOK_AT, W_TOK_LEN,
 W_SEEK_B, W_SEEK_N, W_S_OP, W_S_ENTITY, W_S_NO, W_S_NR, W_S_FOUND, W_H_KIND, W_H_NUM, W_H_RES, W_INT, W_COUNT, W_MBLOCK,
 W_MNODE, W_FUNCTIONS, W_S_EDGES, W_MEMBER) = range(31)
WS_IN, WS_IN_LIMIT = EIN + (8 << 20), 8 << 20  # the selector or batch text, one byte per word
WS_TMP = EIN + (4 << 20)  # ``apply``: the mutations, before their count is known
TALIAS = STATE  # per object: its type handle + 1 (0: none yet)
FORD = ALIAS  # per object: its function handle + 1 (0: not a function)
TLIST = NEWCID  # per type handle: its object
NSTART, PSTART = RSTART, RCOUNT  # per block: its first node's and first parameter's handle number
SEEKV, SEEKR, SEEKE = SRS, STACK, SR  # the sought node's operand values (4 words each), result types; its block's edges
EDGE_ARGUMENTS = 1 << 14  # per edge, at ``SEEKE``: count, then 4 words per argument
OPERATION_ENUM = D.ENUM_NAMES.index("Operation")
WS_LIMIT = 1 << 16  # objects, blocks (the per-object and per-block tables)
SPACE = (32, 9, 10, 13)
VIEW_VERBS = {"const": "set-constant", "op": "set-op", "operand": "replace-operand", "edge": "set-edge", "type": "set-type"}


def _wctrl(e: E, field: int):
    return e.ld(WSC + field)


def _wset(e: E, field: int, value):
    e.st(WSC + field, value)


def _out(e: E, value):
    _call(e, "ws_out", value)


def _out_text(e: E, text: str):
    for byte in text.encode("ascii"):
        _out(e, byte)


def _ws_reject(e: E, rule: str, expected: str):
    """A batch or selector the workspace does not accept: the offset of the token it stopped at."""
    _reject(e, "XAX.WORKSPACE.BATCH", lambda: D.text(e, "batch"), rule, lambda: D.text(e, expected),
            lambda: D.integer(e, _wctrl(e, W_TOK_AT)))


def _ws_running(e: E):
    return e.eq(_ctrl(e, E_STATUS), OK)


def _ws_out_function():
    """One output byte at ``BATCH`` (``view``'s text, one byte per word); past ``BATCH_LIMIT`` the view rejects."""
    def build(e: E):
        p = e.p
        e.var("wo", _wctrl(e, W_OUT))
        e.if_(e.lt(p["wo"], BATCH_LIMIT), lambda: (e.st(e.add(BATCH, p["wo"]), p["value"]), _wset(e, W_OUT, e.add(p["wo"], 1))),
              lambda: e.if_(_ws_running(e), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "view"), "DRIVER-VIEW-CAPACITY",
                                                             lambda: D.integer(e, BATCH_LIMIT), lambda: D.text(e, "larger"))))
        e.give(0)
    return _function(("value",), build, None)


def _ws_decimal_function():
    """``value`` in decimal."""
    def build(e: E):
        p = e.p
        e.var("dv", p["value"])
        e.var("dn", 0)

        def digit():
            e.st(e.add(WSC + 40, p["dn"]), e.add(48, e.urem(p["dv"], 10)))
            e.set("dv", e.udiv(p["dv"], 10))
            e.set("dn", e.add(p["dn"], 1))

        digit()
        e.while_(lambda: e.ne(p["dv"], 0), digit)
        e.while_(lambda: e.ne(p["dn"], 0), lambda: (e.set("dn", e.sub(p["dn"], 1)), _out(e, e.ld(e.add(WSC + 40, p["dn"])))))
        e.give(0)
    return _function(("value",), build, None)


def _ws_hex_function():
    """The 16 hexadecimal digits of ``value``, most significant first."""
    def build(e: E):
        p = e.p
        e.var("hx", p["value"])
        for k in range(16):
            e.var("hd", e.and_(e.udiv(p["hx"], 1 << (4 * (15 - k))) if k < 15 else p["hx"], 15))
            _out(e, e.add(p["hd"], e.sel(e.lt(p["hd"], 10), 48, 87)))
        e.give(0)
    return _function(("value",), build, None)


def _ws_cid_function():
    """Object ``o``'s CID, 64 hexadecimal digits."""
    def build(e: E):
        p = e.p
        for k in range(4):
            _call(e, "ws_hex", _cid_word(e, p["o"], k))
        e.give(0)
    return _function(("o",), build, None)


def _ws_operation_function():
    """Operation ``code``'s name (``op<n>`` for a code with none), from the enumeration table (``ws_enum_names``)."""
    def build(e: E):
        p = e.p
        e.var("oslot", e.add(OPERATION_ENUM * 128, e.sel(e.lt(p["code"], 128), p["code"], 0)))
        e.var("on", e.sel(e.lt(p["code"], 128), e.ld(e.add(ENUM_LENGTH, p["oslot"])), 0))
        e.var("oat", e.ld(e.add(ENUM_AT, p["oslot"])))

        def lowered():
            """The member name in lower case, ``_`` as ``.``."""
            def byte():
                e.var("ob", _call(e, "ws_byte_of", e.ld(e.add(ENUM_NAMES_AT, e.udiv(e.add(p["oat"], p["ok"]), 8))), e.urem(e.add(p["oat"], p["ok"]), 8)))
                _out(e, e.sel(e.eq(p["ob"], 95), 46, e.sel(e.both(e.le(65, p["ob"]), e.le(p["ob"], 90)), e.add(p["ob"], 32), p["ob"])))

            e.for_("ok", 0, p["on"], byte)

        e.if_(e.eq(p["on"], 0), lambda: (_out_text(e, "op"), _call(e, "ws_decimal", p["code"])), lowered)
        e.give(0)
    return _function(("code",), build, None)


def _ws_type_function():
    """Type object ``t``'s handle number, assigned on first appearance when ``assign`` is set."""
    def build(e: E):
        p = e.p
        e.var("ta", e.ld(e.add(TALIAS, p["t"])))

        def assign():
            e.var("tn", _wctrl(e, W_TYPES))
            e.st(e.add(TLIST, p["tn"]), p["t"])
            e.st(e.add(TALIAS, p["t"]), e.add(p["tn"], 1))
            _wset(e, W_TYPES, e.add(p["tn"], 1))
            e.set("ta", e.add(p["tn"], 1))

        e.if_(e.both(e.eq(p["ta"], 0), e.ne(p["assign"], 0)), assign)
        e.give(e.sub(p["ta"], 1))
    return _function(("t", "assign"), build, None)


def _ws_type_out_function():
    """``T<n>`` for type object ``t``."""
    def build(e: E):
        p = e.p
        _out(e, 84)
        _call(e, "ws_decimal", e.sub(e.ld(e.add(TALIAS, p["t"])), 1))
        e.give(0)
    return _function(("t",), build, None)


def _ws_value_function():
    """The value in ``V_TAG``.. as a handle: ``P<i>``, ``N<i>`` or ``N<i>.R<k>``."""
    def build(e: E):
        p = e.p
        e.var("vt", _ctrl(e, V_TAG))
        e.if_(e.eq(p["vt"], 0), lambda: (_out(e, 80), _call(e, "ws_decimal", e.add(e.ld(e.add(PSTART, _ctrl(e, V_A))), _ctrl(e, V_B)))),
              lambda: e.if_(e.eq(p["vt"], 1), lambda: (
                  _out(e, 78), _call(e, "ws_decimal", e.add(e.ld(e.add(NSTART, _ctrl(e, V_A))), _ctrl(e, V_B))),
                  e.if_(e.ne(_ctrl(e, V_C), 0), lambda: (_out_text(e, ".R"), _call(e, "ws_decimal", _ctrl(e, V_C))))),
                  lambda: _out(e, 63)))
        e.give(0)
    return _function((), build, None)


def _ws_constant_function():
    """Constant object ``c``'s value: decimal up to 8 bytes, else ``0x`` and its bytes, most significant first; with
    ``print`` unset only the low 64 bits are given."""
    def build(e: E):
        p = e.p
        length, at = _plain_body(e, p["c"])
        e.var("ca", at)
        e.var("ce", e.add(at, length))
        e.while_(lambda: e.le(128, e.rd(p["ca"])), lambda: e.set("ca", e.add(p["ca"], 1)))  # the type reference
        e.set("ca", e.add(p["ca"], 1))
        e.var("cn", 0)
        e.var("cs", 1)
        e.var("cm", 1)

        def size():
            e.var("cb", e.rd(p["ca"]))
            e.set("cn", e.add(p["cn"], e.mul(e.and_(p["cb"], 127), p["cs"])))
            e.set("cs", e.mul(p["cs"], 128))
            e.set("ca", e.add(p["ca"], 1))
            e.set("cm", e.flag(e.le(128, p["cb"])))

        e.while_(lambda: e.ne(p["cm"], 0), size)
        e.var("cv", 0)
        e.for_("ck", 0, e.sel(e.lt(p["cn"], 8), p["cn"], 8), lambda: e.set(
            "cv", e.add(p["cv"], e.mul(e.rd(e.add(p["ca"], p["ck"])), _call(e, "ws_pow256", p["ck"])))))

        def wide():
            _out_text(e, "0x")
            e.var("cw", p["cn"])

            def byte():
                e.set("cw", e.sub(p["cw"], 1))
                e.var("cbyte", e.rd(e.add(p["ca"], p["cw"])))
                for shift in (16, 1):
                    e.var("cnib", e.and_(e.udiv(p["cbyte"], shift), 15))
                    _out(e, e.add(p["cnib"], e.sel(e.lt(p["cnib"], 10), 48, 87)))

            e.while_(lambda: e.ne(p["cw"], 0), byte)

        e.if_(e.ne(p["print"], 0), lambda: e.if_(e.lt(8, p["cn"]), wide, lambda: _call(e, "ws_decimal", p["cv"])))
        e.give(p["cv"])
    return _function(("c", "print"), build, None)


def _ws_pow256_function():
    def build(e: E):
        p = e.p
        e.var("pw", 1)
        e.for_("pk", 0, p["k"], lambda: e.set("pw", e.mul(p["pw"], 256)))
        e.give(p["pw"])
    return _function(("k",), build, None)


def _ws_type_text_function():
    """Type object ``t``: ``bits<w>``, or ``form<f>`` and its CID."""
    def build(e: E):
        p = e.p
        length, at = _plain_body(e, p["t"])
        e.var("tf", e.rd(at))
        e.if_(e.both(e.eq(p["tf"], 1), e.lt(e.rd(e.add(at, 1)), 128)), lambda: (_out_text(e, "bits"), _call(e, "ws_decimal", e.rd(e.add(at, 1)))),
              lambda: e.if_(e.both(e.eq(p["tf"], 1), e.eq(length, 3)), lambda: (
                  _out_text(e, "bits"), _call(e, "ws_decimal", e.add(e.and_(e.rd(e.add(at, 1)), 127), e.mul(e.rd(e.add(at, 2)), 128)))),
                  lambda: (_out_text(e, "form"), _call(e, "ws_decimal", e.and_(p["tf"], 127)), _out(e, 32), _call(e, "ws_cid", p["t"]))))
        e.give(0)
    return _function(("t",), build, None)


def _ws_interface_function():
    """Function ``W_FN``'s graph into ``W_GRAPH`` and its signature's types; printed (``(T..)->(T..)``) with ``print``.
    A recursion group's member is not a graph of its own: NONE."""
    def build(e: E):
        p = e.p
        e.var("io", _wctrl(e, W_FN))
        length, at = _plain_body(e, p["io"])
        _set(e, CUR, at)
        e.var("ig", _ref(e, p["io"], _call(e, "uleb_read")))
        _wset(e, W_GRAPH, p["ig"])
        e.if_(e.ne(_kind(e, p["ig"]), int(Kind.GRAPH_FRAGMENT)), lambda: e.give(NONE))
        for close in (False, True):
            e.if_(e.ne(p["print"], 0), lambda: _out(e, 40))
            e.var("icount", _call(e, "uleb_read"))

            def each():
                e.var("it", _ref(e, p["io"], _call(e, "uleb_read")))
                _call(e, "ws_type", p["it"], e.flag(e.eq(p["print"], 0)))
                e.if_(e.ne(p["print"], 0), lambda: (e.if_(e.ne(p["ik"], 0), lambda: _out(e, 44)), _call(e, "ws_type_out", p["it"])))

            e.for_("ik", 0, p["icount"], each)
            e.if_(e.ne(p["print"], 0), lambda close=close: _out_text(e, ")\n" if close else ")->"))
        e.give(p["ig"])
    return _function(("print",), build, None)


def _ws_edge_function():
    """A terminator edge at ``CUR``: ``B<t>(..)`` printed with ``print``; with ``seek`` its arguments at ``SEEKE``."""
    def build(e: E):
        p = e.p
        e.var("et", _call(e, "uleb_read"))
        e.var("en", _call(e, "uleb_read"))
        e.var("eslot", e.add(SEEKE, e.mul(p["slot"], EDGE_ARGUMENTS)))
        e.if_(e.ne(p["seek"], 0), lambda: e.st(p["eslot"], p["en"]))
        e.if_(e.ne(p["print"], 0), lambda: (_out(e, 66), _call(e, "ws_decimal", p["et"]), _out(e, 40)))

        def argument():
            _call(e, "read_value")
            e.if_(e.ne(p["print"], 0), lambda: (e.if_(e.ne(p["ea"], 0), lambda: _out(e, 44)), _call(e, "ws_value")))
            e.if_(e.both(e.ne(p["seek"], 0), e.lt(e.mul(e.add(p["ea"], 1), 4), EDGE_ARGUMENTS)), lambda: [
                e.st(e.add(e.add(p["eslot"], e.add(1, e.mul(p["ea"], 4))), k), _ctrl(e, field)) for k, field in enumerate((V_TAG, V_A, V_B, V_C))])

        e.for_("ea", 0, p["en"], argument)
        e.if_(e.ne(p["print"], 0), lambda: _out(e, 41))
        e.give(0)
    return _function(("print", "seek", "slot"), build, None)


def _ws_walk_function():
    """Graph ``W_GRAPH``'s body: ``mode`` 0 numbers its blocks' nodes and parameters (``NSTART``, ``PSTART``) and its
    types; 1 prints it; 2 records node ``W_SEEK_N`` of block ``W_SEEK_B`` (``W_S_*``, ``SEEKV``, ``SEEKR``) and the
    block's edges (``SEEKE``)."""
    def build(e: E):
        p = e.p
        e.var("wm", p["mode"])
        e.var("wpr", e.flag(e.eq(p["wm"], 1)))
        e.var("wg", _wctrl(e, W_GRAPH))
        _length, at = _graph_body(e, p["wg"])
        _set(e, CUR, at)
        e.var("wnb", _call(e, "uleb_read"))
        e.var("wentry", _call(e, "uleb_read"))
        _wset(e, W_NBLOCKS, p["wnb"])
        _wset(e, W_ENTRY, p["wentry"])
        e.if_(e.both(e.eq(p["wm"], 0), e.lt(WS_LIMIT - 2, p["wnb"])), lambda: _reject(
            e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "view"), "DRIVER-VIEW-CAPACITY", lambda: D.integer(e, WS_LIMIT - 2),
            lambda: D.integer(e, p["wnb"])))
        e.if_(e.both(e.ne(p["wpr"], 0), e.ne(p["wentry"], 0)), lambda: (_out_text(e, "entry B"), _call(e, "ws_decimal", p["wentry"]), _out(e, 10)))
        e.var("wni", 0)
        e.var("wpi", 0)
        e.var("wb", 0)

        def block():
            e.var("wblock_seek", e.flag(e.both(e.eq(p["wm"], 2), e.eq(p["wb"], _wctrl(e, W_SEEK_B)))))
            e.if_(e.eq(p["wm"], 0), lambda: (e.st(e.add(NSTART, p["wb"]), p["wni"]), e.st(e.add(PSTART, p["wb"]), p["wpi"])))
            e.var("wnp", _call(e, "uleb_read"))
            e.if_(e.ne(p["wpr"], 0), lambda: (_out(e, 66), _call(e, "ws_decimal", p["wb"]), _out(e, 40)))

            def parameter():
                e.var("wpt", _ref(e, p["wg"], _call(e, "uleb_read")))
                _call(e, "ws_type", p["wpt"], e.flag(e.eq(p["wm"], 0)))
                e.if_(e.ne(p["wpr"], 0), lambda: (e.if_(e.ne(p["wk"], 0), lambda: _out(e, 44)), _out(e, 80), _call(e, "ws_decimal", p["wpi"]),
                                                  _out(e, 58), _call(e, "ws_type_out", p["wpt"])))
                e.set("wpi", e.add(p["wpi"], 1))

            e.for_("wk", 0, p["wnp"], parameter)
            e.if_(e.ne(p["wpr"], 0), lambda: _out_text(e, ")\n"))
            e.var("wnn", _call(e, "uleb_read"))

            def node():
                e.var("wop", _call(e, "uleb_read"))
                e.var("wmember", 0)
                e.if_(e.eq(p["wop"], int(Operation.CALL_GROUP_MEMBER)), lambda: e.set("wmember", _call(e, "uleb_read")))
                e.var("wflags", e.ld(e.add(OPF, e.sel(e.lt(p["wop"], 128), p["wop"], 0))))
                e.var("wseek", e.flag(e.both(e.ne(p["wblock_seek"], 0), e.eq(p["wn"], _wctrl(e, W_SEEK_N)))))
                e.if_(e.ne(p["wpr"], 0), lambda: (_out(e, 78), _call(e, "ws_decimal", p["wni"]), _out(e, 32), _call(e, "ws_operation", p["wop"])))
                e.var("went", NONE)

                def entity():
                    e.set("went", _ref(e, p["wg"], _call(e, "uleb_read")))

                    def shown():
                        e.var("wford", e.ld(e.add(FORD, p["went"])))
                        e.if_(e.eq(p["wop"], int(Operation.CONSTANT)), lambda: (_out(e, 32), _call(e, "ws_constant", p["went"], 1)),
                              lambda: e.if_(e.ne(p["wford"], 0), lambda: (_out_text(e, " entity=F"), _call(e, "ws_decimal", e.sub(p["wford"], 1))),
                                            lambda: (_out_text(e, " entity="), _call(e, "ws_cid", p["went"]))))

                    e.if_(e.ne(p["wpr"], 0), shown)

                e.if_(e.ne(e.and_(p["wflags"], 1), 0), entity)
                e.if_(e.both(e.ne(p["wpr"], 0), e.eq(p["wop"], int(Operation.CALL_GROUP_MEMBER))), lambda: (
                    _out_text(e, " member="), _call(e, "ws_decimal", p["wmember"])))
                e.var("wno", _call(e, "uleb_read"))

                def operand():
                    _call(e, "read_value")
                    e.if_(e.ne(p["wpr"], 0), lambda: (_out(e, 32), _call(e, "ws_value")))
                    e.if_(e.both(e.ne(p["wseek"], 0), e.lt(p["wo"], RC_LIMIT // 4)), lambda: [
                        e.st(e.add(e.add(SEEKV, e.mul(p["wo"], 4)), k), _ctrl(e, field)) for k, field in enumerate((V_TAG, V_A, V_B, V_C))])

                e.for_("wo", 0, p["wno"], operand)
                e.var("wnr", _call(e, "uleb_read"))
                e.if_(e.both(e.ne(p["wpr"], 0), e.ne(p["wnr"], 0)), lambda: _out_text(e, " ->"))

                def result():
                    e.var("wrt", _ref(e, p["wg"], _call(e, "uleb_read")))
                    _call(e, "ws_type", p["wrt"], e.flag(e.eq(p["wm"], 0)))
                    e.if_(e.ne(p["wpr"], 0), lambda: (_out(e, e.sel(e.eq(p["wr"], 0), 32, 44)), _call(e, "ws_type_out", p["wrt"])))
                    e.if_(e.both(e.ne(p["wseek"], 0), e.lt(p["wr"], 1 << 16)), lambda: e.st(e.add(SEEKR, p["wr"]), p["wrt"]))

                e.for_("wr", 0, p["wnr"], result)

                def attributes():
                    e.var("wna", _call(e, "uleb_read"))
                    e.if_(e.both(e.ne(p["wpr"], 0), e.ne(p["wna"], 0)), lambda: _out_text(e, " ["))

                    def attribute():
                        e.var("wav", _call(e, "uleb_read"))
                        e.if_(e.ne(p["wpr"], 0), lambda: (e.if_(e.ne(p["wak"], 0), lambda: _out(e, 44)), _call(e, "ws_decimal", p["wav"])))

                    e.for_("wak", 0, p["wna"], attribute)
                    e.if_(e.both(e.ne(p["wpr"], 0), e.ne(p["wna"], 0)), lambda: _out(e, 93))

                e.if_(e.ne(e.and_(p["wflags"], 2), 0), attributes)
                e.if_(e.ne(p["wpr"], 0), lambda: _out(e, 10))
                e.if_(e.ne(p["wseek"], 0), lambda: (_wset(e, W_S_OP, p["wop"]), _wset(e, W_S_ENTITY, p["went"]), _wset(e, W_S_NO, p["wno"]),
                                                     _wset(e, W_S_NR, p["wnr"]), _wset(e, W_S_FOUND, 1)))
                e.set("wni", e.add(p["wni"], 1))

            e.for_("wn", 0, p["wnn"], node)
            e.var("wtk", _call(e, "uleb_read"))
            e.if_(e.ne(p["wblock_seek"], 0), lambda: _wset(e, W_S_EDGES, e.sel(e.eq(p["wtk"], 1), 1, e.sel(e.eq(p["wtk"], 2), 2, 0))))
            e.if_(e.eq(p["wtk"], 1), lambda: (e.if_(e.ne(p["wpr"], 0), lambda: _out_text(e, "br ")),
                                              _call(e, "ws_edge", p["wpr"], p["wblock_seek"], 0)))

            def conditional():
                _call(e, "read_value")
                e.if_(e.ne(p["wpr"], 0), lambda: (_out_text(e, "cbr "), _call(e, "ws_value"), _out(e, 32)))
                _call(e, "ws_edge", p["wpr"], p["wblock_seek"], 0)
                e.if_(e.ne(p["wpr"], 0), lambda: _out(e, 32))
                _call(e, "ws_edge", p["wpr"], p["wblock_seek"], 1)

            e.if_(e.eq(p["wtk"], 2), conditional)

            def returned():
                e.if_(e.ne(p["wpr"], 0), lambda: _out_text(e, "ret"))
                e.for_("wv", 0, _call(e, "uleb_read"), lambda: (_call(e, "read_value"), e.if_(e.ne(p["wpr"], 0), lambda: (_out(e, 32), _call(e, "ws_value")))))

            e.if_(e.eq(p["wtk"], 3), returned)

            def trap():
                e.if_(e.ne(p["wpr"], 0), lambda: _out_text(e, "trap"))
                e.var("wtn", _call(e, "uleb_read"))
                _set(e, CUR, e.add(_ctrl(e, CUR), p["wtn"]))

            e.if_(e.eq(p["wtk"], 4), trap)
            e.if_(e.ne(p["wpr"], 0), lambda: _out(e, 10))
            e.set("wb", e.add(p["wb"], 1))

        e.while_(lambda: e.both(e.lt(p["wb"], p["wnb"]), _ws_running(e)), block)

        def totals():
            e.st(e.add(NSTART, p["wnb"]), p["wni"])
            e.st(e.add(PSTART, p["wnb"]), p["wpi"])
            _wset(e, W_NODES, p["wni"])
            _wset(e, W_PARAMS, p["wpi"])

        e.if_(e.eq(p["wm"], 0), totals)
        e.give(0)
    return _function(("mode",), build, None)


def _ws_prepare_function():
    """The tables every view needs: operation flags and names, no type handles yet, each function's handle; the
    count of functions in ``W_FUNCTIONS``.  More objects than ``WS_LIMIT`` reject."""
    def build(e: E):
        p = e.p
        _set(e, E_STATUS, OK)
        _set(e, MODE, LOCATE)
        # The operation flags (``OPF``, as ``edit_begin`` sets them) from two 128-bit masks.
        for mask, (low, high) in enumerate(((sum(1 << op for op in ENTITY if op < 64), sum(1 << (op - 64) for op in ENTITY if 64 <= op < 128)),
                                            (sum(1 << op for op in ATTRIBUTE if op < 64), sum(1 << (op - 64) for op in ATTRIBUTE if 64 <= op < 128)))):
            e.st(WSC + 48 + 2 * mask, low)
            e.st(WSC + 49 + 2 * mask, high)

        def flags():
            e.var("pf_bits", 0)
            for mask in (0, 1):
                e.var("pf_word", e.ld(e.add(WSC + 48 + 2 * mask, e.udiv(p["pfo"], 64))))
                e.for_("pf_k", 0, e.urem(p["pfo"], 64), lambda: e.set("pf_word", e.udiv(p["pf_word"], 2)))
                e.set("pf_bits", e.add(p["pf_bits"], e.mul(e.and_(p["pf_word"], 1), mask + 1)))
            e.st(e.add(OPF, p["pfo"]), p["pf_bits"])

        e.for_("pfo", 0, 128, flags)
        _call(e, "ws_enum_names")
        e.var("po", e.rd(0))
        e.if_(e.lt(WS_LIMIT, p["po"]), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "view"), "DRIVER-VIEW-CAPACITY",
                                                        lambda: D.integer(e, WS_LIMIT), lambda: D.integer(e, p["po"])))
        e.var("pf", 0)

        def each():
            e.st(e.add(TALIAS, p["pz"]), 0)
            e.var("pfun", e.flag(e.eq(_kind(e, p["pz"]), int(Kind.FUNCTION))))
            e.set("pf", e.add(p["pf"], p["pfun"]))
            e.st(e.add(FORD, p["pz"]), e.mul(p["pfun"], p["pf"]))

        e.for_("pz", 0, e.sel(_ws_running(e), p["po"], 0), each)
        _wset(e, W_FUNCTIONS, p["pf"])
        _wset(e, W_TYPES, 0)
        _wset(e, W_OUT, 0)
        e.give(0)
    return _function((), build, None)


def _ws_function_function():
    """Function handle ``n``'s object (NONE when there is none)."""
    def build(e: E):
        p = e.p
        e.var("fo", NONE)
        e.for_("fz", 0, e.rd(0), lambda: e.if_(e.eq(e.ld(e.add(FORD, p["fz"])), e.add(p["n"], 1)), lambda: e.set("fo", p["fz"])))
        e.give(p["fo"])
    return _function(("n",), build, None)


def _ws_token_function():
    """The next token of the request text from ``W_TCUR``: 0 at its end, 2 for ``;``, else 1 with ``W_TOK_AT``/``W_TOK_LEN``."""
    def build(e: E):
        p = e.p
        e.var("ta", _wctrl(e, W_TCUR))
        e.var("te", _wctrl(e, W_LEN))

        def space(at):
            byte = e.ld(e.add(WS_IN, at))
            return e.either(*(e.eq(byte, value) for value in SPACE))

        e.while_(lambda: e.both(e.lt(p["ta"], p["te"]), space(p["ta"])), lambda: e.set("ta", e.add(p["ta"], 1)))
        e.var("tkind", 0)
        _wset(e, W_TOK_AT, p["ta"])

        def semicolon():
            e.set("tkind", 2)
            e.set("ta", e.add(p["ta"], 1))

        def word():
            e.set("tkind", 1)
            e.var("ts", p["ta"])
            e.while_(lambda: e.both(e.lt(p["ta"], p["te"]), e.not_(space(p["ta"])), e.ne(e.ld(e.add(WS_IN, p["ta"])), 59)),
                     lambda: e.set("ta", e.add(p["ta"], 1)))
            _wset(e, W_TOK_LEN, e.sub(p["ta"], p["ts"]))

        e.if_(e.lt(p["ta"], p["te"]), lambda: e.if_(e.eq(e.ld(e.add(WS_IN, p["ta"])), 59), semicolon, word))
        _wset(e, W_TCUR, p["ta"])
        e.give(p["tkind"])
    return _function((), build, None)


def _ws_is(e: E, text: str):
    """The current token is ``text``."""
    at = _wctrl(e, W_TOK_AT)
    return e.both(e.eq(_wctrl(e, W_TOK_LEN), len(text)),
                  *(e.eq(e.ld(e.add(WS_IN, e.add(at, k))), byte) for k, byte in enumerate(text.encode("ascii"))))


def _ws_number_function():
    """The token's characters from ``from`` as a number (decimal, or hexadecimal after ``0x``) into ``W_INT``: 1, or 0
    when they are not one (or there are none)."""
    def build(e: E):
        p = e.p
        e.var("na", e.add(_wctrl(e, W_TOK_AT), p["from"]))
        e.var("ne", e.add(_wctrl(e, W_TOK_AT), _wctrl(e, W_TOK_LEN)))
        e.var("nv", 0)
        e.var("nok", e.flag(e.lt(p["na"], p["ne"])))
        e.var("nbase", 10)
        e.if_(e.both(e.lt(e.add(p["na"], 2), p["ne"]), e.eq(e.ld(e.add(WS_IN, p["na"])), 48), e.eq(e.ld(e.add(WS_IN, e.add(p["na"], 1))), 120)),
              lambda: (e.set("nbase", 16), e.set("na", e.add(p["na"], 2))))
        e.var("ndigits", 0)

        def digit():
            e.var("nc", e.ld(e.add(WS_IN, p["na"])))
            e.var("nd", e.sel(e.both(e.le(48, p["nc"]), e.le(p["nc"], 57)), e.sub(p["nc"], 48),
                              e.sel(e.both(e.eq(p["nbase"], 16), e.le(97, p["nc"]), e.le(p["nc"], 102)), e.sub(p["nc"], 87), 99)))
            e.if_(e.lt(p["nd"], p["nbase"]), lambda: e.set("nv", e.add(e.mul(p["nv"], p["nbase"]), p["nd"])), lambda: e.set("nok", 0))
            e.set("ndigits", e.add(p["ndigits"], 1))
            e.set("na", e.add(p["na"], 1))

        e.while_(lambda: e.both(e.lt(p["na"], p["ne"]), e.ne(p["nok"], 0)), digit)
        e.if_(e.lt(e.sel(e.eq(p["nbase"], 16), 16, 19), p["ndigits"]), lambda: e.set("nok", 0))
        _wset(e, W_INT, p["nv"])
        e.give(p["nok"])
    return _function(("from",), build, None)


def _ws_handle_function():
    """The token as a handle: its letter (``W_H_KIND``), number (``W_H_NUM``) and result (``.R<k>``, ``W_H_RES``); 1, or
    0 when it is not one."""
    def build(e: E):
        p = e.p
        e.var("ha", _wctrl(e, W_TOK_AT))
        e.var("hn", _wctrl(e, W_TOK_LEN))
        _wset(e, W_H_KIND, e.ld(e.add(WS_IN, p["ha"])))
        _wset(e, W_H_RES, 0)
        e.var("hdot", p["hn"])
        e.for_("hk", 1, p["hn"], lambda: e.if_(e.both(e.eq(p["hdot"], p["hn"]), e.eq(e.ld(e.add(WS_IN, e.add(p["ha"], p["hk"]))), 46)),
                                                lambda: e.set("hdot", p["hk"])))
        e.var("hok", 0)

        def parse():
            # The number is the characters before the dot: parse them as a token of their own.
            _wset(e, W_TOK_LEN, p["hdot"])
            e.set("hok", _call(e, "ws_number", 1))
            _wset(e, W_H_NUM, _wctrl(e, W_INT))

            def result():
                _wset(e, W_TOK_LEN, p["hn"])
                e.var("hr_ok", e.flag(e.both(e.lt(e.add(p["hdot"], 2), p["hn"]), e.eq(e.ld(e.add(WS_IN, e.add(p["ha"], e.add(p["hdot"], 1)))), 82))))
                e.if_(e.ne(p["hr_ok"], 0), lambda: (e.set("hok", e.and_(p["hok"], _call(e, "ws_number", e.add(p["hdot"], 2)))),
                                                    _wset(e, W_H_RES, _wctrl(e, W_INT))), lambda: e.set("hok", 0))

            e.if_(e.lt(p["hdot"], p["hn"]), result)
            _wset(e, W_TOK_LEN, p["hn"])

        e.if_(e.lt(1, p["hn"]), parse)
        e.give(p["hok"])
    return _function((), build, None)


def _ws_locate_function():
    """Node handle ``n``'s block and position (``W_MBLOCK``, ``W_MNODE``); 0 when the function has no such node."""
    def build(e: E):
        p = e.p
        e.var("lb", 0)
        e.var("lfound", 0)
        e.while_(lambda: e.both(e.lt(p["lb"], _wctrl(e, W_NBLOCKS)), e.eq(p["lfound"], 0)), lambda: e.if_(
            e.lt(p["n"], e.ld(e.add(NSTART, e.add(p["lb"], 1)))),
            lambda: (e.set("lfound", e.flag(e.le(e.ld(e.add(NSTART, p["lb"])), p["n"]))),
                     _wset(e, W_MBLOCK, p["lb"]), _wset(e, W_MNODE, e.sub(p["n"], e.ld(e.add(NSTART, p["lb"]))))),
            lambda: e.set("lb", e.add(p["lb"], 1))))
        e.give(p["lfound"])
    return _function(("n",), build, None)


def _ws_parameter_function():
    """Parameter handle ``n``'s block (``W_MBLOCK``) and index (``W_MNODE``); 0 when there is none."""
    def build(e: E):
        p = e.p
        e.var("qb", 0)
        e.var("qfound", 0)
        e.while_(lambda: e.both(e.lt(p["qb"], _wctrl(e, W_NBLOCKS)), e.eq(p["qfound"], 0)), lambda: e.if_(
            e.lt(p["n"], e.ld(e.add(PSTART, e.add(p["qb"], 1)))),
            lambda: (e.set("qfound", 1), _wset(e, W_MBLOCK, p["qb"]), _wset(e, W_MNODE, e.sub(p["n"], e.ld(e.add(PSTART, p["qb"]))))),
            lambda: e.set("qb", e.add(p["qb"], 1))))
        e.give(p["qfound"])
    return _function(("n",), build, None)


def _ws_seek_function():
    """Node ``n`` of block ``b``, read (``ws_walk``'s mode 2)."""
    def build(e: E):
        p = e.p
        _wset(e, W_SEEK_B, p["b"])
        _wset(e, W_SEEK_N, p["n"])
        _wset(e, W_S_FOUND, 0)
        _wset(e, W_S_EDGES, 0)
        _call(e, "ws_walk", 2)
        e.give(_wctrl(e, W_S_FOUND))
    return _function(("b", "n"), build, None)


def _ws_record_byte_function():
    def build(e: E):
        p = e.p
        e.var("rb", _wctrl(e, W_RCUR))
        e.if_(e.lt(p["rb"], 4 << 20), lambda: (e.st(e.add(WS_TMP, p["rb"]), p["value"]), _wset(e, W_RCUR, e.add(p["rb"], 1))),
              lambda: e.if_(_ws_running(e), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "apply"), "DRIVER-FILE-CAPACITY",
                                                             lambda: D.integer(e, 4 << 20), lambda: D.text(e, "larger"))))
        e.give(0)
    return _function(("value",), build, None)


def _ws_record_uleb_function():
    def build(e: E):
        p = e.p
        e.var("ru", p["value"])
        e.var("ru_more", 1)

        def step():
            e.var("ru_low", e.and_(p["ru"], 127))
            e.set("ru", e.udiv(p["ru"], 128))
            _call(e, "ws_record_byte", e.add(p["ru_low"], e.mul(e.flag(e.ne(p["ru"], 0)), 128)))
            e.set("ru_more", e.flag(e.ne(p["ru"], 0)))

        e.while_(lambda: e.ne(p["ru_more"], 0), step)
        e.give(0)
    return _function(("value",), build, None)


def _ws_record_cid_function():
    """Object ``o``'s CID, 32 bytes (each word most significant byte first)."""
    def build(e: E):
        p = e.p
        for k in range(4):
            e.var("rcw", _cid_word(e, p["o"], k))
            for j in range(8):
                _call(e, "ws_record_byte", e.and_(e.udiv(p["rcw"], 1 << (8 * (7 - j))), 255) if j < 7 else e.and_(p["rcw"], 255))
        e.give(0)
    return _function(("o",), build, None)


def _ws_record_value_function():
    """A record value (``_record_value``): tag, then block and index (and result), or local id and result."""
    def build(e: E):
        p = e.p
        _call(e, "ws_record_uleb", p["tag"])
        _call(e, "ws_record_uleb", p["a"])
        _call(e, "ws_record_uleb", p["b"])
        e.if_(e.eq(p["tag"], VALUE_RESULT), lambda: _call(e, "ws_record_uleb", p["c"]))
        e.give(0)
    return _function(("tag", "a", "b", "c"), build, None)


def _ws_operand_value_function():
    """The token as a value handle into ``V_TAG``..: ``P<i>``, ``N<i>``/``N<i>.R<k>``, ``@<id>``/``@<id>.R<k>``; 0 when
    it names none of the function's."""
    def build(e: E):
        p = e.p
        e.var("vok", _call(e, "ws_handle"))
        e.var("vkind", _wctrl(e, W_H_KIND))
        e.var("vnum", _wctrl(e, W_H_NUM))

        def parameter():
            e.set("vok", e.and_(e.flag(e.eq(_wctrl(e, W_H_RES), 0)), _call(e, "ws_parameter", p["vnum"])))
            _set(e, V_TAG, VALUE_PARAMETER)
            _set(e, V_A, _wctrl(e, W_MBLOCK))
            _set(e, V_B, _wctrl(e, W_MNODE))
            _set(e, V_C, 0)

        def node():
            e.set("vok", _call(e, "ws_locate", p["vnum"]))
            _set(e, V_TAG, VALUE_RESULT)
            _set(e, V_A, _wctrl(e, W_MBLOCK))
            _set(e, V_B, _wctrl(e, W_MNODE))
            _set(e, V_C, _wctrl(e, W_H_RES))

        def inserted():
            _set(e, V_TAG, VALUE_INSERTED)
            _set(e, V_A, p["vnum"])
            _set(e, V_B, _wctrl(e, W_H_RES))
            _set(e, V_C, 0)

        e.if_(e.ne(p["vok"], 0), lambda: e.if_(e.eq(p["vkind"], 80), parameter, lambda: e.if_(
            e.eq(p["vkind"], 78), node, lambda: e.if_(e.eq(p["vkind"], 64), inserted, lambda: e.set("vok", 0)))))
        e.give(p["vok"])
    return _function((), build, None)


def _ws_view_function():
    """``view``: the selector text at ``WS_IN`` (``W_LEN`` bytes) to the view at ``BATCH`` (``W_OUT`` bytes)."""
    def build(e: E):
        p = e.p
        _call(e, "ws_prepare")
        _wset(e, W_TCUR, 0)
        e.var("vroot", e.rd(1))
        e.var("vkind", e.sel(_ws_running(e), _call(e, "ws_token"), 0))
        _out_text(e, "R ")
        _call(e, "ws_cid", p["vroot"])
        _out(e, 10)

        def listing():
            def each():
                e.var("lf", e.sub(e.ld(e.add(FORD, p["lz"])), 1))
                _out(e, 70)
                _call(e, "ws_decimal", p["lf"])
                _out(e, 32)
                _call(e, "ws_cid", p["lz"])
                _wset(e, W_FN, p["lz"])
                e.var("lg", _call(e, "ws_interface", 0))
                e.if_(e.eq(p["lg"], NONE), lambda: _out_text(e, " group-member"))
                _out(e, 10)

            e.for_("lz", 0, e.rd(0), lambda: e.if_(e.ne(e.ld(e.add(FORD, p["lz"])), 0), each))

        def one():
            e.var("vok", e.flag(e.both(e.ne(_call(e, "ws_handle"), 0), e.eq(_wctrl(e, W_H_KIND), 70), e.eq(_wctrl(e, W_H_RES), 0))))
            e.if_(e.eq(p["vok"], 0), lambda: _ws_reject(e, "WORKSPACE-VIEW-SELECTOR", "F<n>"))

            def shown():
                e.var("vf", _call(e, "ws_function", _wctrl(e, W_H_NUM)))
                e.if_(e.eq(p["vf"], NONE), lambda: _reject(
                    e, "XAX.WORKSPACE.HANDLE", lambda: D.text(e, "F"), "WORKSPACE-VIEW-FUNCTION",
                    lambda: _at_most(e, "< {}", _wctrl(e, W_FUNCTIONS)), lambda: D.integer(e, _wctrl(e, W_H_NUM))))

                def view():
                    _wset(e, W_FN, p["vf"])
                    e.var("vg", _call(e, "ws_interface", 0))
                    e.if_(e.eq(p["vg"], NONE), lambda: _reject(
                        e, "XAX.WORKSPACE.UNSUPPORTED", lambda: _cid_of(e, p["vf"]), "WORKSPACE-VIEW-GROUP-MEMBER",
                        lambda: D.text(e, "a function with a graph of its own"), lambda: D.text(e, "a recursion group's member")))

                    def walked():
                        _call(e, "ws_walk", 0)

                        def printed():
                            _out(e, 70)
                            _call(e, "ws_decimal", _wctrl(e, W_H_NUM))
                            _out(e, 32)
                            _call(e, "ws_cid", p["vf"])
                            _out(e, 10)
                            _call(e, "ws_interface", 1)
                            _call(e, "ws_walk", 1)

                            def type_line():
                                e.var("vt", e.ld(e.add(TLIST, p["vk"])))
                                _call(e, "ws_type_out", p["vt"])
                                _out(e, 32)
                                _call(e, "ws_type_text", p["vt"])
                                _out(e, 10)

                            e.for_("vk", 0, _wctrl(e, W_TYPES), type_line)

                        e.if_(_ws_running(e), printed)

                    e.if_(_ws_running(e), walked)

                e.if_(_ws_running(e), view)

            e.if_(_ws_running(e), shown)

        e.if_(_ws_running(e), lambda: e.if_(e.eq(p["vkind"], 0), listing, lambda: e.if_(e.eq(p["vkind"], 1), one, lambda: _ws_reject(
            e, "WORKSPACE-VIEW-SELECTOR", "F<n>"))))
        e.if_(_ws_running(e), lambda: e.if_(e.ne(_call(e, "ws_token"), 0), lambda: _ws_reject(e, "WORKSPACE-VIEW-SELECTOR", "one handle")))
        e.give(_ctrl(e, E_STATUS))
    return _function((), build, None)


BATCH_REJECTS = (("ROOT", "R"), ("ROOT", "64 hexadecimal digits"), ("FUNCTION", "F<n>"), ("FUNCTION", "F<n> of a function with a graph"),
                 ("HANDLE", "N<i>"), ("HANDLE", "N<i> of the function"), ("INTEGER", "an integer"), ("VALUE", "P<i>, N<i>, N<i>.R<k> or @<id>"),
                 ("VALUE", "a value of the function"), ("NODE", "a constant node"), ("OPERATION", "an operation"),
                 ("OPERATION", "add.wrap, sub.wrap or mul.wrap"), ("OPERAND", "an operand of the node"), ("NODE", "a single-result anchor"),
                 ("EDGE", "an edge argument of the anchor's block"), ("TYPE", "T<i> or a result index"), ("TYPE", "T<i>"),
                 ("TYPE", "a result index for a node without one result"), ("TYPE", "a result of the node"), ("TYPE", "T<i> of the function's view"),
                 ("FORM", "const, op, operand, delete, insert-constant, edge or type"), ("COUNT", f"at most {MUT_LIMIT} mutations"))
(R_ROOT, R_ROOT_HEX, R_FUNCTION, R_FUNCTION_GRAPH, R_HANDLE, R_HANDLE_NODE, R_INTEGER, R_VALUE, R_VALUE_OF, R_CONSTANT, R_OPERATION,
 R_OPERATION_WRAP, R_OPERAND, R_ANCHOR, R_EDGE, R_TYPE_OR_INDEX, R_TYPE, R_TYPE_INDEX, R_TYPE_RESULT, R_TYPE_VIEW, R_FORM, R_COUNT) = range(len(BATCH_REJECTS))
W_SAVE_B, W_SAVE_N, W_S_TYPE = 35, 36, 37  # ``apply``'s node across a value handle; a parsed type's object


BR_AT, BR_WORDS = REFL + (1 << 18), 24  # per batch rejection: rule length, 7 rule words, expected length, 15 expected words


def _ws_batch_reject_function():
    """Batch rejection ``index`` of ``BATCH_REJECTS`` (once: the first decides): code ``XAX.WORKSPACE.BATCH``, entity
    ``batch``, the rule and expected text from a table, and the offset of the token it stopped at."""
    def packed(text: str):
        data = text.encode("ascii")
        return len(data), [int.from_bytes(data[k:k + 8].ljust(8, b"\0"), "little") for k in range(0, len(data), 8)]

    def build(e: E):
        p = e.p

        def reject():
            for index, (rule, expected) in enumerate(BATCH_REJECTS):
                at = BR_AT + index * BR_WORDS
                for offset, text, room in ((0, "WORKSPACE-BATCH-" + rule, 7), (8, expected, 15)):
                    length, words = packed(text)
                    assert len(words) <= room
                    e.st(at + offset, length)
                    for k, word in enumerate(words):
                        e.st(at + offset + 1 + k, word)
            D.begin(e)
            D.text(e, "XAX.WORKSPACE.BATCH")
            D.text(e, "batch")
            e.var("br_at", e.add(BR_AT, e.mul(p["index"], BR_WORDS)))
            for offset in (0, 8):
                e.var("br_n", e.ld(e.add(p["br_at"], offset)))
                D.put(e, D.T_STR)
                D.put(e, p["br_n"])
                e.for_("br_k", 0, e.udiv(e.add(p["br_n"], 7), 8), lambda offset=offset: D.put(e, e.ld(e.add(p["br_at"], e.add(offset + 1, p["br_k"])))))
            D.integer(e, _wctrl(e, W_TOK_AT))
            _set(e, E_STATUS, REJECT)

        e.if_(_ws_running(e), reject)
        e.give(0)
    return _function(("index",), build, None)


def _batch_reject(e: E, index: int):
    _call(e, "ws_batch_reject", index)


def _ws_expect_function():
    """The next token, which must be a word (else rejection ``index``): 1 when it is."""
    def build(e: E):
        p = e.p
        e.var("xk", 0)
        e.if_(_ws_running(e), lambda: e.set("xk", e.flag(e.eq(_call(e, "ws_token"), 1))))
        e.if_(e.both(_ws_running(e), e.eq(p["xk"], 0)), lambda: _call(e, "ws_batch_reject", p["index"]))
        e.give(p["xk"])
    return _function(("index",), build, None)


def _ws_node_token_function():
    """The next token, a node handle of the function, located (``W_MBLOCK``, ``W_MNODE``) and read (``ws_seek``)."""
    def build(e: E):
        p = e.p
        _call(e, "ws_expect", R_HANDLE)
        e.var("nh_ok", 0)
        e.if_(_ws_running(e), lambda: e.if_(e.ne(_call(e, "ws_handle"), 0), lambda: e.if_(
            e.both(e.eq(_wctrl(e, W_H_KIND), 78), e.eq(_wctrl(e, W_H_RES), 0)), lambda: e.set("nh_ok", _call(e, "ws_locate", _wctrl(e, W_H_NUM))))))
        e.if_(e.both(_ws_running(e), e.eq(p["nh_ok"], 0)), lambda: _batch_reject(e, R_HANDLE_NODE))

        def seek():
            e.var("nh_b", _wctrl(e, W_MBLOCK))
            e.var("nh_n", _wctrl(e, W_MNODE))
            _call(e, "ws_seek", p["nh_b"], p["nh_n"])
            _wset(e, W_MBLOCK, p["nh_b"])
            _wset(e, W_MNODE, p["nh_n"])

        e.if_(_ws_running(e), seek)
        e.give(0)
    return _function((), build, None)


def _ws_number_token_function():
    """The next token, an integer, into ``W_INT`` (rejection ``R_INTEGER``)."""
    def build(e: E):
        _call(e, "ws_expect", R_INTEGER)
        e.if_(e.both(_ws_running(e), e.eq(_call(e, "ws_number", 0), 0)), lambda: _batch_reject(e, R_INTEGER))
        e.give(_wctrl(e, W_INT))
    return _function((), build, None)


def _ws_value_token_function():
    """The next token, a value handle, into ``V_TAG``..; the located node (``W_MBLOCK``/``W_MNODE``) is kept."""
    def build(e: E):
        _wset(e, W_SAVE_B, _wctrl(e, W_MBLOCK))
        _wset(e, W_SAVE_N, _wctrl(e, W_MNODE))
        _call(e, "ws_expect", R_VALUE)
        e.if_(e.both(_ws_running(e), e.eq(_call(e, "ws_operand_value"), 0)), lambda: _batch_reject(e, R_VALUE_OF))
        _wset(e, W_MBLOCK, _wctrl(e, W_SAVE_B))
        _wset(e, W_MNODE, _wctrl(e, W_SAVE_N))
        e.give(0)
    return _function((), build, None)


def _ws_type_current_function():
    """The current token, a type handle of the view: its object into ``W_S_TYPE`` (rejection ``R_TYPE_VIEW``)."""
    def build(e: E):
        p = e.p
        e.var("tc_ok", 0)
        e.if_(e.ne(_call(e, "ws_handle"), 0), lambda: e.set("tc_ok", e.flag(e.both(
            e.eq(_wctrl(e, W_H_KIND), 84), e.eq(_wctrl(e, W_H_RES), 0), e.lt(_wctrl(e, W_H_NUM), _wctrl(e, W_TYPES))))))
        e.if_(e.eq(p["tc_ok"], 0), lambda: _batch_reject(e, R_TYPE_VIEW),
              lambda: _wset(e, W_S_TYPE, e.ld(e.add(TLIST, _wctrl(e, W_H_NUM)))))
        e.give(0)
    return _function((), build, None)


def _ws_head_function():
    """A mutation's kind, function, block and node (``W_MBLOCK``/``W_MNODE``), counted."""
    def build(e: E):
        p = e.p
        _call(e, "ws_record_uleb", p["kind"])
        _call(e, "ws_record_cid", _wctrl(e, W_FN))
        _call(e, "ws_record_uleb", _wctrl(e, W_MBLOCK))
        _call(e, "ws_record_uleb", _wctrl(e, W_MNODE))
        _wset(e, W_COUNT, e.add(_wctrl(e, W_COUNT), 1))
        e.give(0)
    return _function(("kind",), build, None)


def _stored_value(e: E, at):
    """A value ``ws_walk`` stored (4 words at ``at``), as the record writes it."""
    e.var("sv_at", at)
    _call(e, "ws_record_value", e.ld(e.p["sv_at"]), e.ld(e.add(e.p["sv_at"], 1)), e.ld(e.add(e.p["sv_at"], 2)), e.ld(e.add(e.p["sv_at"], 3)))


def _new_value(e: E):
    _call(e, "ws_record_value", _ctrl(e, V_TAG), _ctrl(e, V_A), _ctrl(e, V_B), _ctrl(e, V_C))


def _ws_tr_constant_function():
    """``const N V``: SET_CONSTANT with the node's value."""
    def build(e: E):
        p = e.p
        running = lambda: _ws_running(e)  # noqa: E731
        _call(e, "ws_node_token")
        e.if_(e.both(running(), e.ne(_wctrl(e, W_S_OP), int(Operation.CONSTANT))), lambda: _batch_reject(e, R_CONSTANT))
        e.var("kc_old", 0)
        e.if_(running(), lambda: e.set("kc_old", _call(e, "ws_constant", _wctrl(e, W_S_ENTITY), 0)))
        e.var("kc_new", _call(e, "ws_number_token"))
        e.if_(running(), lambda: (_call(e, "ws_head", SET_CONSTANT), _call(e, "ws_record_uleb", p["kc_old"]), _call(e, "ws_record_uleb", p["kc_new"])))
        e.give(0)
    return _function((), build, None)


def _ws_tr_operation_function():
    """``op N OP``: SET_OPERATION with the node's operation (the wrapping three)."""
    def build(e: E):
        p = e.p
        running = lambda: _ws_running(e)  # noqa: E731
        _call(e, "ws_node_token")
        _call(e, "ws_expect", R_OPERATION)
        e.var("ko_new", NONE)

        def find():
            for name in ("add.wrap", "sub.wrap", "mul.wrap"):
                e.if_(_ws_is(e, name), lambda name=name: e.set("ko_new", int(Operation[name.upper().replace(".", "_")])))
            e.if_(e.eq(p["ko_new"], NONE), lambda: _batch_reject(e, R_OPERATION_WRAP))

        e.if_(running(), find)
        e.if_(running(), lambda: (_call(e, "ws_head", SET_OPERATION), _call(e, "ws_record_uleb", _wctrl(e, W_S_OP)), _call(e, "ws_record_uleb", p["ko_new"])))
        e.give(0)
    return _function((), build, None)


def _ws_tr_operand_function():
    """``operand N K VALUE``: REPLACE_USE with the operand's value."""
    def build(e: E):
        p = e.p
        running = lambda: _ws_running(e)  # noqa: E731
        _call(e, "ws_node_token")
        e.var("ku_k", _call(e, "ws_number_token"))
        e.if_(e.both(running(), e.le(_wctrl(e, W_S_NO), p["ku_k"])), lambda: _batch_reject(e, R_OPERAND))
        _call(e, "ws_value_token")

        def write():
            _call(e, "ws_head", REPLACE_USE)
            _call(e, "ws_record_uleb", p["ku_k"])
            _stored_value(e, e.add(SEEKV, e.mul(p["ku_k"], 4)))
            _new_value(e)

        e.if_(running(), write)
        e.give(0)
    return _function((), build, None)


def _ws_tr_delete_function():
    """``delete N``: DELETE_NODE."""
    def build(e: E):
        _call(e, "ws_node_token")
        e.if_(_ws_running(e), lambda: _call(e, "ws_head", DELETE_NODE))
        e.give(0)
    return _function((), build, None)


def _ws_tr_insert_function():
    """``insert-constant N ID V``: INSERT_NODE, a constant of N's single result type before N."""
    def build(e: E):
        p = e.p
        running = lambda: _ws_running(e)  # noqa: E731
        _call(e, "ws_node_token")
        e.var("ki_type", NONE)
        e.if_(running(), lambda: e.if_(e.eq(_wctrl(e, W_S_NR), 1), lambda: e.set("ki_type", e.ld(SEEKR)), lambda: _batch_reject(e, R_ANCHOR)))
        e.var("ki_id", _call(e, "ws_number_token"))
        e.var("ki_value", _call(e, "ws_number_token"))

        def write():
            _call(e, "ws_head", INSERT_NODE)
            for value in (p["ki_id"], int(Operation.CONSTANT), 0):
                _call(e, "ws_record_uleb", value)
            _call(e, "ws_record_cid", p["ki_type"])
            for value in (1, p["ki_value"], 0):
                _call(e, "ws_record_uleb", value)

        e.if_(running(), write)
        e.give(0)
    return _function((), build, None)


def _ws_tr_edge_function():
    """``edge N E A VALUE``: DISCONNECT_EDGE (the argument's value) then CONNECT_EDGE, on N's block."""
    def build(e: E):
        p = e.p
        running = lambda: _ws_running(e)  # noqa: E731
        _call(e, "ws_node_token")
        e.var("ke_mb", _wctrl(e, W_MBLOCK))
        e.var("ke_edge", _call(e, "ws_number_token"))
        e.var("ke_arg", _call(e, "ws_number_token"))
        e.if_(e.both(running(), e.either(e.le(_wctrl(e, W_S_EDGES), p["ke_edge"]), e.le(
            e.ld(e.add(SEEKE, e.mul(e.sel(e.lt(p["ke_edge"], 2), p["ke_edge"], 0), EDGE_ARGUMENTS))), p["ke_arg"]))),
            lambda: _batch_reject(e, R_EDGE))
        _call(e, "ws_value_token")

        def write():
            for kind in (DISCONNECT_EDGE, CONNECT_EDGE):
                for value in (kind,):
                    _call(e, "ws_record_uleb", value)
                _call(e, "ws_record_cid", _wctrl(e, W_FN))
                for value in (p["ke_mb"], p["ke_edge"], p["ke_arg"]):
                    _call(e, "ws_record_uleb", value)
                if kind == DISCONNECT_EDGE:
                    _stored_value(e, e.add(e.add(SEEKE, e.mul(p["ke_edge"], EDGE_ARGUMENTS)), e.add(1, e.mul(p["ke_arg"], 4))))
                else:
                    _new_value(e)
                _wset(e, W_COUNT, e.add(_wctrl(e, W_COUNT), 1))

        e.if_(running(), write)
        e.give(0)
    return _function((), build, None)


def _ws_tr_type_function():
    """``type N T`` or ``type N K T``: SET_RESULT_TYPE with the result's type."""
    def build(e: E):
        p = e.p
        running = lambda: _ws_running(e)  # noqa: E731
        _call(e, "ws_node_token")
        _call(e, "ws_expect", R_TYPE_OR_INDEX)
        e.var("kt_result", 0)
        e.var("kt_indexed", e.flag(e.both(running(), e.ne(e.ld(e.add(WS_IN, _wctrl(e, W_TOK_AT))), 84))))

        def indexed():
            e.if_(e.eq(_call(e, "ws_number", 0), 0), lambda: _batch_reject(e, R_TYPE_OR_INDEX))
            e.set("kt_result", _wctrl(e, W_INT))
            _call(e, "ws_expect", R_TYPE)

        e.if_(e.ne(p["kt_indexed"], 0), indexed)
        e.if_(e.both(running(), e.eq(p["kt_indexed"], 0), e.ne(_wctrl(e, W_S_NR), 1)), lambda: _batch_reject(e, R_TYPE_INDEX))
        e.if_(e.both(running(), e.le(_wctrl(e, W_S_NR), p["kt_result"])), lambda: _batch_reject(e, R_TYPE_RESULT))
        e.if_(running(), lambda: _call(e, "ws_type_current"))

        def write():
            _call(e, "ws_head", SET_RESULT_TYPE)
            _call(e, "ws_record_uleb", p["kt_result"])
            _call(e, "ws_record_cid", e.ld(e.add(SEEKR, p["kt_result"])))
            _call(e, "ws_record_cid", _wctrl(e, W_S_TYPE))

        e.if_(running(), write)
        e.give(0)
    return _function((), build, None)


def _ws_translate_function():
    """``apply``: the batch text at ``WS_IN`` (``W_LEN`` bytes) to an edit record at ``EIN`` (``E_LENGTH``), or a
    rejection.  Header ``R <root CID>`` (the expected root) and ``F<n>`` (the function the handles name), then edits,
    ``;`` or white space between them:

        const N V | op N OP | operand N K VALUE | delete N | insert-constant ANCHOR ID V | edge ANCHOR E A VALUE
        | type N T | type N K T

    (``set-constant``, ``set-op``, ``replace-operand``, ``set-edge`` and ``set-type`` too).  A value is ``P<i>``,
    ``N<i>``, ``N<i>.R<k>``, or ``@<id>`` (``.R<k>``) for an insertion's result; ``T<i>`` a type of the function's
    view.  Each mutation's old operation, value, operand, edge argument or type comes from the store."""
    verbs = (("const", "ws_tr_constant"), ("set-constant", "ws_tr_constant"), ("op", "ws_tr_operation"), ("set-op", "ws_tr_operation"),
             ("operand", "ws_tr_operand"), ("replace-operand", "ws_tr_operand"), ("delete", "ws_tr_delete"), ("insert-constant", "ws_tr_insert"),
             ("edge", "ws_tr_edge"), ("set-edge", "ws_tr_edge"), ("type", "ws_tr_type"), ("set-type", "ws_tr_type"))

    def build(e: E):
        p = e.p
        _call(e, "ws_prepare")
        _wset(e, W_TCUR, 0)
        _wset(e, W_RCUR, 0)
        _wset(e, W_COUNT, 0)
        running = lambda: _ws_running(e)  # noqa: E731
        for k, byte in enumerate(RECORD_MAGIC):
            e.st(EIN + k, byte)
        # The header: the expected root, 64 hexadecimal digits, into the record after its magic.
        _call(e, "ws_expect", R_ROOT)
        e.if_(e.both(running(), e.not_(_ws_is(e, "R"))), lambda: _batch_reject(e, R_ROOT))
        _call(e, "ws_expect", R_ROOT_HEX)

        def root():
            e.if_(e.ne(_wctrl(e, W_TOK_LEN), 64), lambda: _batch_reject(e, R_ROOT_HEX))
            e.var("rta", _wctrl(e, W_TOK_AT))

            def byte():
                for half in (0, 1):
                    e.var(f"rc{half}", e.ld(e.add(WS_IN, e.add(p["rta"], e.add(e.mul(p["rk"], 2), half)))))
                    e.var(f"rd{half}", e.sel(e.both(e.le(48, p[f"rc{half}"]), e.le(p[f"rc{half}"], 57)), e.sub(p[f"rc{half}"], 48),
                                             e.sel(e.both(e.le(97, p[f"rc{half}"]), e.le(p[f"rc{half}"], 102)), e.sub(p[f"rc{half}"], 87), 99)))
                e.if_(e.either(e.lt(15, p["rd0"]), e.lt(15, p["rd1"])), lambda: _batch_reject(e, R_ROOT_HEX))
                e.st(e.add(EIN + len(RECORD_MAGIC), p["rk"]), e.add(e.mul(p["rd0"], 16), p["rd1"]))

            e.for_("rk", 0, e.sel(running(), 32, 0), byte)

        e.if_(running(), root)

        def fresh():
            """The expected root is checked before any handle: a stale batch is stale, whatever its handles name."""
            e.var("tr_root", e.rd(1))
            e.var("tr_same", 1)
            for k in range(4):
                e.var("tr_word", 0)
                for j in range(8):
                    e.set("tr_word", e.add(e.mul(p["tr_word"], 256), e.ld(EIN + len(RECORD_MAGIC) + 8 * k + j)))
                e.set("tr_same", e.and_(p["tr_same"], e.flag(e.eq(p["tr_word"], _cid_word(e, p["tr_root"], k)))))
            e.if_(e.eq(p["tr_same"], 0), lambda: _reject(
                e, "XAX.WORKSPACE.STALE_ROOT", lambda: D.text(e, "R0"), "WORKSPACE-EXPECTED-ROOT",
                lambda: _record_cid(e, EIN + len(RECORD_MAGIC)), lambda: _cid_of(e, p["tr_root"])))

        e.if_(running(), fresh)
        _call(e, "ws_expect", R_FUNCTION)

        def function():
            e.var("tfn", NONE)
            e.if_(e.ne(_call(e, "ws_handle"), 0), lambda: e.if_(e.both(e.eq(_wctrl(e, W_H_KIND), 70), e.eq(_wctrl(e, W_H_RES), 0)),
                                                                lambda: e.set("tfn", _call(e, "ws_function", _wctrl(e, W_H_NUM)))))
            e.if_(e.eq(p["tfn"], NONE), lambda: _batch_reject(e, R_FUNCTION_GRAPH), lambda: _wset(e, W_FN, p["tfn"]))
            e.if_(e.both(running(), e.eq(_call(e, "ws_interface", 0), NONE)), lambda: _batch_reject(e, R_FUNCTION_GRAPH))
            e.if_(running(), lambda: _call(e, "ws_walk", 0))

        e.if_(running(), function)
        e.var("tgo", e.flag(running()))

        def mutation():
            e.var("tk", _call(e, "ws_token"))
            e.if_(e.eq(p["tk"], 0), lambda: e.set("tgo", 0))

            def verb():
                e.var("tverb", 0)
                for index, (word, _handler) in enumerate(verbs):
                    e.if_(_ws_is(e, word), lambda index=index: e.set("tverb", index + 1))
                e.if_(e.eq(p["tverb"], 0), lambda: _batch_reject(e, R_FORM))
                for index, (_word, handler) in enumerate(verbs):
                    e.if_(e.both(running(), e.eq(p["tverb"], index + 1)), lambda handler=handler: _call(e, handler))
                e.if_(e.both(running(), e.lt(MUT_LIMIT, _wctrl(e, W_COUNT))), lambda: _batch_reject(e, R_COUNT))

            e.if_(e.eq(p["tk"], 1), verb)
            e.if_(e.ne(_ctrl(e, E_STATUS), OK), lambda: e.set("tgo", 0))

        e.while_(lambda: e.ne(p["tgo"], 0), mutation)

        def assemble():
            # The count after the header, then the mutations.
            e.var("ta", EIN + len(RECORD_MAGIC) + 32)
            e.var("tcount", _wctrl(e, W_COUNT))
            e.var("tmore", 1)

            def count_byte():
                e.var("tlow", e.and_(p["tcount"], 127))
                e.set("tcount", e.udiv(p["tcount"], 128))
                e.st(p["ta"], e.add(p["tlow"], e.mul(e.flag(e.ne(p["tcount"], 0)), 128)))
                e.set("ta", e.add(p["ta"], 1))
                e.set("tmore", e.flag(e.ne(p["tcount"], 0)))

            e.while_(lambda: e.ne(p["tmore"], 0), count_byte)
            e.for_("tq", 0, _wctrl(e, W_RCUR), lambda: e.st(e.add(p["ta"], p["tq"]), e.ld(e.add(WS_TMP, p["tq"]))))
            _set(e, E_LENGTH, e.sub(e.add(p["ta"], _wctrl(e, W_RCUR)), EIN))

        e.if_(running(), assemble)
        e.give(_ctrl(e, E_STATUS))
    return _function((), build, None)


# -- S16a (ADR-360): ``explain <record> <output>``: a diagnostic record as text -----------------------------------------
# Every command that rejects writes ``xax_selfhost_diagnostics``' record (tagged words); ``explain`` renders it as
# ``code``, ``entity``, ``rule``, ``expected`` and ``actual`` lines (then ``dependencies`` and ``repair`` when the record
# has them), each value as ``decode_record`` reads it: lists ``[..]``, tuples ``(..)``, dicts ``{k: v}``, an enumeration
# member ``Enum.NAME`` and a name ``NAME``, a value class ``Name(..)``, a template with its ``{}`` filled.
XREC = WS_IN  # the record's words (``ws_command`` packs them from ``edit``'s record area)
XSTACK = EIN + (12 << 20)  # per open value: kind, remaining items, items done, template word, template length, template byte
XFRAME = 6
X_LIST, X_TUPLE, X_DICT, X_OBJECT, X_FORMAT = range(5)
ENUM_AT = REFL + (1 << 19) + 4096  # per enumeration and member (128 each): its name's first byte in the name blob
ENUM_LENGTH = ENUM_AT + 32 * 128
OBJECT_ENUM = len(D.ENUM_NAMES)  # the value classes' names, as members 1.. of one more enumeration
ENUM_NAMES_AT = REFL + (1 << 16)  # the names, NUL after each, eight bytes per word


def _enum_tables():
    """``(member counts per enumeration, the name blob)``: every enumeration a record can name, members 1.. dense."""
    counts, blob = [], bytearray()
    groups = [[member.name for member in sorted(D._registered(name), key=int)] for name in D.ENUM_NAMES] + [list(D.OBJECT_NAMES)]
    for index, names in enumerate(groups):
        if index < len(D.ENUM_NAMES):
            assert [int(member) for member in sorted(D._registered(D.ENUM_NAMES[index]), key=int)] == list(range(1, len(names) + 1))
        counts.append(len(names))
        for name in names:
            blob += name.encode("ascii") + b"\0"
    return counts, bytes(blob)


def _ws_enum_names_function():
    """Every enumeration member's name a record can name (``xax_selfhost_diagnostics.ENUM_NAMES``), the value classes'
    (``OBJECT_NAMES``, enumeration ``OBJECT_ENUM``), and the operations': ``ENUM_AT``/``ENUM_LENGTH`` per member."""
    counts, blob = _enum_tables()

    def build(e: E):
        p = e.p
        for k in range(0, len(blob), 8):
            e.st(ENUM_NAMES_AT + k // 8, int.from_bytes(blob[k:k + 8].ljust(8, b"\0"), "little"))
        for index, count in enumerate(counts):  # past every member slot (enumerations 0..30)
            e.st(ENUM_LENGTH + 31 * 128 + index, count)
        e.for_("en_z", 0, 31 * 128, lambda: e.st(e.add(ENUM_LENGTH, p["en_z"]), 0))
        e.var("en_at", 0)

        def enumeration():
            e.var("en_count", e.ld(e.add(ENUM_LENGTH + 31 * 128, p["en_e"])))

            def member():
                e.var("en_start", p["en_at"])
                e.while_(lambda: e.ne(_call(e, "ws_byte_of", e.ld(e.add(ENUM_NAMES_AT, e.udiv(p["en_at"], 8))), e.urem(p["en_at"], 8)), 0),
                         lambda: e.set("en_at", e.add(p["en_at"], 1)))
                e.var("en_slot", e.add(e.mul(p["en_e"], 128), e.add(p["en_m"], 1)))
                e.st(e.add(ENUM_AT, p["en_slot"]), p["en_start"])
                e.st(e.add(ENUM_LENGTH, p["en_slot"]), e.sub(p["en_at"], p["en_start"]))
                e.set("en_at", e.add(p["en_at"], 1))

            e.for_("en_m", 0, p["en_count"], member)

        e.for_("en_e", 0, len(counts), enumeration)
        e.give(0)
    return _function((), build, None)


def _ws_byte_of_function():
    """Byte ``k`` (0 the least significant) of ``word``; every division is by a constant."""
    def build(e: E):
        p = e.p
        e.var("bo", p["word"])
        e.for_("bk", 0, p["k"], lambda: e.set("bo", e.udiv(p["bo"], 256)))
        e.give(e.and_(p["bo"], 255))
    return _function(("word", "k"), build, None)


def _ws_name_out_function():
    """The name at byte ``at`` of the name blob (``length`` bytes)."""
    def build(e: E):
        p = e.p
        e.for_("nk", 0, p["length"], lambda: (e.var("nb", e.add(p["at"], p["nk"])),
                                                _out(e, _call(e, "ws_byte_of", e.ld(e.add(ENUM_NAMES_AT, e.udiv(p["nb"], 8))), e.urem(p["nb"], 8)))))
        e.give(0)
    return _function(("at", "length"), build, None)


X_P, X_END, X_DEPTH, X_BAD = 31, 32, 33, 34  # ``explain``'s control words (``WSC``): the next record word, its end, open values, malformed


def _x(e: E, field: int):
    return _wctrl(e, field)


def _x_frame(e: E, field: int):
    return e.add(XSTACK, e.add(e.mul(e.sub(_x(e, X_DEPTH), 1), XFRAME), field))


def _ws_x_word_function():
    """The record's next word (past its end the record is malformed)."""
    def build(e: E):
        p = e.p
        e.var("xw", 0)
        e.var("xw_at", _x(e, X_P))
        e.if_(e.lt(p["xw_at"], _x(e, X_END)), lambda: (e.set("xw", e.ld(p["xw_at"])), _wset(e, X_P, e.add(p["xw_at"], 1))),
              lambda: _wset(e, X_BAD, 1))
        e.give(p["xw"])
    return _function((), build, None)


def _ws_x_template_function():
    """The innermost open template's bytes up to its next ``{..}`` (past it), or to its end."""
    def build(e: E):
        p = e.p
        e.var("xt_at", e.ld(_x_frame(e, 3)))
        e.var("xt_n", e.ld(_x_frame(e, 4)))
        e.var("xt_k", e.ld(_x_frame(e, 5)))
        e.var("xt_go", 1)

        def byte():
            e.var("xt_byte", _call(e, "ws_byte_of", e.ld(e.add(p["xt_at"], e.udiv(p["xt_k"], 8))), e.urem(p["xt_k"], 8)))
            e.set("xt_k", e.add(p["xt_k"], 1))

            def placeholder():
                e.set("xt_go", 0)
                e.var("xt_close", 0)

                def skip():
                    e.var("xt_b2", _call(e, "ws_byte_of", e.ld(e.add(p["xt_at"], e.udiv(p["xt_k"], 8))), e.urem(p["xt_k"], 8)))
                    e.set("xt_k", e.add(p["xt_k"], 1))
                    e.set("xt_close", e.flag(e.eq(p["xt_b2"], 125)))

                e.while_(lambda: e.both(e.eq(p["xt_close"], 0), e.lt(p["xt_k"], p["xt_n"])), skip)

            e.if_(e.eq(p["xt_byte"], 123), placeholder, lambda: _out(e, p["xt_byte"]))

        e.while_(lambda: e.both(e.ne(p["xt_go"], 0), e.lt(p["xt_k"], p["xt_n"])), byte)
        e.st(_x_frame(e, 5), p["xt_k"])
        e.give(0)
    return _function((), build, None)


def _ws_x_packed_function():
    """``count`` packed bytes of the record: themselves, or (``hexadecimal``) two hexadecimal digits each."""
    def build(e: E):
        p = e.p
        e.var("xb_k", 0)
        e.var("xb_word", 0)

        def each():
            e.if_(e.eq(e.urem(p["xb_k"], 8), 0), lambda: e.set("xb_word", _call(e, "ws_x_word")))
            e.var("xb_byte", _call(e, "ws_byte_of", p["xb_word"], e.urem(p["xb_k"], 8)))

            def hexed():
                for shift in (16, 1):
                    e.var("xb_nib", e.and_(e.udiv(p["xb_byte"], shift), 15))
                    _out(e, e.add(p["xb_nib"], e.sel(e.lt(p["xb_nib"], 10), 48, 87)))

            e.if_(e.ne(p["hexadecimal"], 0), hexed, lambda: _out(e, p["xb_byte"]))
            e.set("xb_k", e.add(p["xb_k"], 1))

        e.while_(lambda: e.both(e.lt(p["xb_k"], p["count"]), e.eq(_x(e, X_BAD), 0)), each)
        e.give(0)
    return _function(("count", "hexadecimal"), build, None)


def _ws_x_enum_function():
    """Member ``member`` of enumeration ``enum``: its name, ``Enum.`` first when ``qualified``."""
    def build(e: E):
        p = e.p

        def qualify():
            for index, name in enumerate(D.ENUM_NAMES):
                e.if_(e.eq(p["enum"], index), lambda name=name: _out_text(e, name + "."))

        e.if_(e.ne(p["qualified"], 0), qualify)
        e.var("xe_slot", e.add(e.mul(e.sel(e.lt(p["enum"], 32), p["enum"], 0), 128), e.sel(e.lt(p["member"], 128), p["member"], 0)))
        e.var("xe_len", e.sel(e.both(e.le(p["enum"], OBJECT_ENUM), e.lt(p["member"], 128)), e.ld(e.add(ENUM_LENGTH, p["xe_slot"])), 0))
        e.if_(e.eq(p["xe_len"], 0), lambda: _call(e, "ws_decimal", p["member"]),
              lambda: _call(e, "ws_name_out", e.ld(e.add(ENUM_AT, p["xe_slot"])), p["xe_len"]))
        e.give(0)
    return _function(("enum", "member", "qualified"), build, None)


def _ws_x_open_function():
    """A value of ``count`` items opens (``kind``, ``X_LIST``..)."""
    def build(e: E):
        p = e.p
        e.var("xo_depth", _x(e, X_DEPTH))
        e.if_(e.le(64, p["xo_depth"]), lambda: _wset(e, X_BAD, 1), lambda: (
            e.st(e.add(XSTACK, e.mul(p["xo_depth"], XFRAME)), p["kind"]),
            e.st(e.add(XSTACK, e.add(e.mul(p["xo_depth"], XFRAME), 1)), p["count"]),
            e.st(e.add(XSTACK, e.add(e.mul(p["xo_depth"], XFRAME), 2)), 0),
            _wset(e, X_DEPTH, e.add(p["xo_depth"], 1))))
        e.give(0)
    return _function(("kind", "count"), build, None)


def _ws_x_item_function():
    """One tagged value of the record: an atom is written; a list, tuple, dict, value class or template opens."""
    def build(e: E):
        p = e.p
        e.var("xtag", _call(e, "ws_x_word"))
        tag = p["xtag"]
        word = lambda: _call(e, "ws_x_word")  # noqa: E731

        def case(value: int, body):
            e.if_(e.eq(tag, value), body)

        case(D.T_INT, lambda: _call(e, "ws_decimal", word()))
        case(D.T_SINT, lambda: (e.var("xs", word()), e.if_(e.le(1 << 63, p["xs"]), lambda: (_out(e, 45), _call(e, "ws_decimal", e.sub(0, p["xs"]))),
                                                          lambda: _call(e, "ws_decimal", p["xs"]))))
        case(D.T_BOOL, lambda: e.if_(e.ne(word(), 0), lambda: _out_text(e, "True"), lambda: _out_text(e, "False")))
        case(D.T_NONE, lambda: _out_text(e, "None"))
        case(D.T_CID, lambda: [_call(e, "ws_hex", word()) for _ in range(4)])
        case(D.T_STR, lambda: _call(e, "ws_x_packed", word(), 0))
        case(D.T_HEX, lambda: _call(e, "ws_x_packed", word(), 1))
        case(D.T_BYTES, lambda: _call(e, "ws_x_packed", word(), 1))
        case(D.T_WIDE, lambda: (e.var("xlow", word()), _out_text(e, "0x"), _call(e, "ws_hex", word()), _call(e, "ws_hex", p["xlow"])))
        case(D.T_KIND, lambda: (_out_text(e, "Kind."), _call(e, "ws_x_enum", D.ENUM_NAMES.index("Kind"), word(), 0)))
        case(D.T_TERMINATOR, lambda: (_out_text(e, "TerminatorKind."), _call(e, "ws_x_enum", D.ENUM_NAMES.index("TerminatorKind"), word(), 0)))
        for tag_value, qualified in ((D.T_ENUM, 1), (D.T_NAME, 0)):
            case(tag_value, lambda qualified=qualified: (e.var("xenum", word()), _call(e, "ws_x_enum", p["xenum"], word(), qualified)))
        case(D.T_LIST, lambda: (_call(e, "ws_x_open", X_LIST, word()), _out(e, 91)))
        case(D.T_TUPLE, lambda: (_call(e, "ws_x_open", X_TUPLE, word()), _out(e, 40)))
        case(D.T_DICT, lambda: (_call(e, "ws_x_open", X_DICT, e.mul(word(), 2)), _out(e, 123)))

        def object_():
            e.var("xclass", word())
            _call(e, "ws_x_enum", OBJECT_ENUM, e.add(p["xclass"], 1), 0)
            _call(e, "ws_x_open", X_OBJECT, word())
            _out(e, 40)

        case(D.T_OBJECT, object_)

        def format_():
            # The template is a string value: its words are kept in place and filled as the values come.
            e.if_(e.ne(word(), D.T_STR), lambda: _wset(e, X_BAD, 1))
            e.var("xf_n", word())
            e.var("xf_at", _x(e, X_P))
            _wset(e, X_P, e.add(p["xf_at"], e.udiv(e.add(p["xf_n"], 7), 8)))
            _call(e, "ws_x_open", X_FORMAT, word())

            def opened():
                e.st(_x_frame(e, 3), p["xf_at"])
                e.st(_x_frame(e, 4), p["xf_n"])
                e.st(_x_frame(e, 5), 0)
                _call(e, "ws_x_template")

            e.if_(e.eq(_x(e, X_BAD), 0), opened)

        case(D.T_FORMAT, format_)
        e.if_(e.lt(D.T_SINT, tag), lambda: _wset(e, X_BAD, 1))
        e.give(0)
    return _function((), build, None)


def _ws_x_value_function():
    """One value of the record, with every value it contains."""
    def build(e: E):
        p = e.p
        e.var("xv_go", 1)
        running = lambda: e.both(e.ne(p["xv_go"], 0), e.eq(_x(e, X_BAD), 0))  # noqa: E731

        def step():
            def in_frame():
                e.var("xf_kind", e.ld(_x_frame(e, 0)))
                e.var("xf_left", e.ld(_x_frame(e, 1)))
                e.var("xf_done", e.ld(_x_frame(e, 2)))

                def close():
                    for kind, closer in ((X_LIST, 93), (X_TUPLE, 41), (X_DICT, 125), (X_OBJECT, 41)):
                        e.if_(e.eq(p["xf_kind"], kind), lambda closer=closer: _out(e, closer))
                    e.if_(e.eq(p["xf_kind"], X_FORMAT), lambda: _call(e, "ws_x_template"))
                    _wset(e, X_DEPTH, e.sub(_x(e, X_DEPTH), 1))
                    e.if_(e.eq(_x(e, X_DEPTH), 0), lambda: e.set("xv_go", 0))

                def next_item():
                    def separator():
                        e.if_(e.eq(p["xf_kind"], X_FORMAT), lambda: _call(e, "ws_x_template"),
                              lambda: e.if_(e.both(e.eq(p["xf_kind"], X_DICT), e.eq(e.urem(p["xf_done"], 2), 1)), lambda: _out_text(e, ": "),
                                            lambda: _out_text(e, ", ")))

                    e.if_(e.ne(p["xf_done"], 0), separator)
                    e.st(_x_frame(e, 1), e.sub(p["xf_left"], 1))
                    e.st(_x_frame(e, 2), e.add(p["xf_done"], 1))
                    _call(e, "ws_x_item")

                e.if_(e.eq(p["xf_left"], 0), close, next_item)

            e.if_(e.eq(_x(e, X_DEPTH), 0), lambda: (_call(e, "ws_x_item"), e.if_(e.eq(_x(e, X_DEPTH), 0), lambda: e.set("xv_go", 0))), in_frame)

        e.while_(running, step)
        e.give(0)
    return _function((), build, None)


def _ws_explain_function():
    """``explain``: the record's words at ``XREC`` (``W_LEN`` of them) to text at ``BATCH`` (``W_OUT`` bytes)."""
    labels = ("code", "entity", "rule", "expected", "actual", "dependencies", "repair")

    def build(e: E):
        p = e.p
        _set(e, E_STATUS, OK)
        _wset(e, W_OUT, 0)
        _call(e, "ws_enum_names")
        _wset(e, X_P, XREC)
        _wset(e, X_END, e.add(XREC, _wctrl(e, W_LEN)))
        _wset(e, X_DEPTH, 0)
        _wset(e, X_BAD, 0)
        for index, label in enumerate(labels):
            def line(label=label):
                _out_text(e, label + " ")
                _call(e, "ws_x_value")
                _out(e, 10)

            if index < 5:
                e.if_(e.eq(_x(e, X_BAD), 0), line)
            else:
                e.if_(e.both(e.eq(_x(e, X_BAD), 0), e.lt(_x(e, X_P), _x(e, X_END))), line)
        e.if_(e.either(e.ne(_x(e, X_BAD), 0), e.lt(_x(e, X_P), _x(e, X_END))), lambda: _reject(
            e, "XAX.WORKSPACE.RECORD", lambda: D.text(e, "explain"), "WORKSPACE-EXPLAIN-RECORD", lambda: D.text(e, "a diagnostic record"),
            lambda: D.integer(e, e.sub(_x(e, X_P), XREC))))
        e.give(_ctrl(e, E_STATUS))
    return _function((), build, None)


W_MODE, W_TEXT = 38, 39  # ``ws_command``: what ``edit``'s input was (``WS_EDIT``..); 1 text written, 2 rejected, else 0
WS_EDIT, WS_VIEW, WS_APPLY, WS_EXPLAIN = 0, 1, 2, 3


def _ws_pack(e: E, source, count, target):
    """``count`` bytes (one per word from ``source``) as little-endian words from ``target`` (``target <= source``)."""
    p = e.p
    e.var("pk_q", 0)

    def word():
        e.var("pk_word", 0)
        e.var("pk_scale", 1)
        e.var("pk_k", 0)
        e.while_(lambda: e.both(e.lt(p["pk_k"], 8), e.lt(e.add(e.mul(p["pk_q"], 8), p["pk_k"]), count)), lambda: (
            e.set("pk_word", e.add(p["pk_word"], e.mul(e.ld(e.add(source, e.add(e.mul(p["pk_q"], 8), p["pk_k"]))), p["pk_scale"]))),
            e.set("pk_scale", e.mul(p["pk_scale"], 256)), e.set("pk_k", e.add(p["pk_k"], 1))))
        e.st(e.add(target, p["pk_q"]), p["pk_word"])
        e.set("pk_q", e.add(p["pk_q"], 1))

    e.while_(lambda: e.lt(e.mul(p["pk_q"], 8), count), word)


def _ws_command_function():
    """S16a (ADR-360): what ``edit``'s input (one byte per word from ``EIN``, ``E_LENGTH`` of them) is, and the
    workspace's part of it.  An edit record (``RECORD_MAGIC``) is ``edit``'s; a diagnostic record (its first word a
    string tag) is explained; a text whose first word is ``R`` is a batch, translated into an edit record in place;
    any other text is a view selector.  ``view``'s and ``explain``'s text leaves packed eight bytes a word from
    ``BATCH`` (``W_OUT`` bytes) with ``W_TEXT`` 1; a rejection leaves ``W_TEXT`` 2 (``edit_begin`` passes both on)."""
    def build(e: E):
        p = e.p
        e.var("cm_n", _ctrl(e, E_LENGTH))
        _set(e, E_STATUS, OK)
        _wset(e, W_TEXT, 0)
        e.var("cm_magic", e.flag(e.le(len(RECORD_MAGIC), p["cm_n"])))
        for k, byte in enumerate(RECORD_MAGIC):
            e.set("cm_magic", e.and_(p["cm_magic"], e.flag(e.eq(e.ld(EIN + k), byte))))
        e.var("cm_record", e.flag(e.both(e.le(8, p["cm_n"]), e.eq(e.urem(p["cm_n"], 8), 0), e.eq(e.ld(EIN), D.T_STR))))
        for k in range(1, 8):
            e.set("cm_record", e.and_(p["cm_record"], e.flag(e.eq(e.ld(EIN + k), 0))))
        e.var("cm_at", 0)
        e.while_(lambda: e.both(e.lt(p["cm_at"], p["cm_n"]), e.either(*(e.eq(e.ld(e.add(EIN, p["cm_at"])), byte) for byte in SPACE))),
                 lambda: e.set("cm_at", e.add(p["cm_at"], 1)))
        e.var("cm_batch", e.flag(e.both(e.lt(p["cm_at"], p["cm_n"]), e.eq(e.ld(e.add(EIN, e.sel(e.lt(p["cm_at"], p["cm_n"]), p["cm_at"], 0))), 82))))
        e.var("cm_mode", e.sel(e.ne(p["cm_magic"], 0), WS_EDIT, e.sel(e.ne(p["cm_record"], 0), WS_EXPLAIN, e.sel(e.ne(p["cm_batch"], 0), WS_APPLY, WS_VIEW))))
        _wset(e, W_MODE, p["cm_mode"])

        def workspace():
            e.if_(e.lt(WS_IN_LIMIT, p["cm_n"]), lambda: _reject(e, "XAX.DRIVER.CAPACITY", lambda: D.text(e, "workspace-text"), "DRIVER-FILE-CAPACITY",
                                                                lambda: D.integer(e, WS_IN_LIMIT), lambda: D.text(e, "larger")))

            def text():
                e.for_("cm_k", 0, p["cm_n"], lambda: e.st(e.add(WS_IN, p["cm_k"]), e.ld(e.add(EIN, p["cm_k"]))))
                _wset(e, W_LEN, p["cm_n"])

            def record():
                _ws_pack(e, EIN, p["cm_n"], XREC)
                _wset(e, W_LEN, e.udiv(p["cm_n"], 8))

            e.if_(_ws_running(e), lambda: e.if_(e.eq(p["cm_mode"], WS_EXPLAIN), record, text))
            for mode, name in ((WS_VIEW, "ws_view"), (WS_APPLY, "ws_translate"), (WS_EXPLAIN, "ws_explain")):
                e.if_(e.both(_ws_running(e), e.eq(p["cm_mode"], mode)), lambda name=name: _call(e, name))
            e.if_(e.both(_ws_running(e), e.ne(p["cm_mode"], WS_APPLY)), lambda: (_ws_pack(e, BATCH, _wctrl(e, W_OUT), BATCH), _wset(e, W_TEXT, 1)))
            e.if_(e.not_(_ws_running(e)), lambda: _wset(e, W_TEXT, 2))

        e.if_(e.ne(p["cm_mode"], WS_EDIT), workspace)
        e.give(_ctrl(e, E_STATUS))
    return _function((), build, None)


WS_HELPERS = (("ws_out", _ws_out_function),
              ("ws_decimal", _ws_decimal_function),
              ("ws_byte_of", _ws_byte_of_function),
              ("ws_name_out", _ws_name_out_function),
              ("ws_enum_names", _ws_enum_names_function),
              ("ws_hex", _ws_hex_function),
              ("ws_cid", _ws_cid_function),
              ("ws_operation", _ws_operation_function),
              ("ws_type", _ws_type_function),
              ("ws_type_out", _ws_type_out_function),
              ("ws_value", _ws_value_function),
              ("ws_pow256", _ws_pow256_function),
              ("ws_constant", _ws_constant_function),
              ("ws_type_text", _ws_type_text_function),
              ("ws_interface", _ws_interface_function),
              ("ws_edge", _ws_edge_function),
              ("ws_walk", _ws_walk_function),
              ("ws_prepare", _ws_prepare_function),
              ("ws_function", _ws_function_function),
              ("ws_token", _ws_token_function),
              ("ws_number", _ws_number_function),
              ("ws_handle", _ws_handle_function),
              ("ws_locate", _ws_locate_function),
              ("ws_parameter", _ws_parameter_function),
              ("ws_seek", _ws_seek_function),
              ("ws_record_byte", _ws_record_byte_function),
              ("ws_record_uleb", _ws_record_uleb_function),
              ("ws_record_cid", _ws_record_cid_function),
              ("ws_record_value", _ws_record_value_function),
              ("ws_operand_value", _ws_operand_value_function),
              ("ws_batch_reject", _ws_batch_reject_function), ("ws_expect", _ws_expect_function), ("ws_node_token", _ws_node_token_function),
              ("ws_number_token", _ws_number_token_function), ("ws_value_token", _ws_value_token_function),
              ("ws_type_current", _ws_type_current_function), ("ws_head", _ws_head_function), ("ws_tr_constant", _ws_tr_constant_function),
              ("ws_tr_operation", _ws_tr_operation_function), ("ws_tr_operand", _ws_tr_operand_function), ("ws_tr_delete", _ws_tr_delete_function),
              ("ws_tr_insert", _ws_tr_insert_function), ("ws_tr_edge", _ws_tr_edge_function), ("ws_tr_type", _ws_tr_type_function),
              ("ws_x_word", _ws_x_word_function),
              ("ws_x_template", _ws_x_template_function),
              ("ws_x_packed", _ws_x_packed_function),
              ("ws_x_enum", _ws_x_enum_function),
              ("ws_x_open", _ws_x_open_function),
              ("ws_x_item", _ws_x_item_function),
              ("ws_x_value", _ws_x_value_function))


def build_functions():
    """``{name: function}`` and the objects they need."""
    functions, objects = {}, []
    for name, builder in (("record_uleb", _record_uleb_function), ("uleb_read", _uleb_read_function), ("put_uleb", _put_uleb_function), ("copy_uleb", _copy_uleb_function),
                          ("copy_string", _copy_string_function), ("search", _search_function), ("insert", _insert_function),
                          ("resolve", _resolve_function), ("replaced", _replaced_function),
                          ("reference", _reference_function), ("record_value", _record_value_function), ("count_rows", _count_rows_function),
                          ("remap", _remap_function), ("local", _local_function), ("emit_value", _emit_value_function), ("read_value", _read_value_function),
                          ("emit_ref", _emit_ref_function), ("type_source", _type_source_function), ("emit_insert", _emit_insert_function),
                          ("note_use", _note_use_function), ("same_value", _same_value_function), ("edge_row", _edge_row_function),
                          ("scan_value", _scan_value_function), ("scan_edge", _scan_edge_function),
                          ("scan_graph", _scan_graph_function), ("scan_other", _scan_other_function),
                          ("check_local", _check_local_function), ("check_use", _check_use_function), ("check_delete", _check_delete_function),
                          ("check_insert", _check_insert_function), ("check_result", _check_result_function), ("check_edge", _check_edge_function),
                          ("check_structural", _check_structural_function)):
        _F[name], items = builder()
        objects.extend(items)
    for name, builder in (("edit_begin", _begin), ("edit_next", _next), ("edit_place", _place), ("edit_reach", _reach), ("edit_batch", _batch)):
        function, items = builder(None)
        functions[name] = function
        objects.extend(items)
    # S16a (ADR-360): the native workspace's ``view`` and ``apply``.
    for name, builder in WS_HELPERS:
        _F[name], items = builder()
        objects.extend(items)
    for name, builder in (("ws_view", _ws_view_function), ("ws_translate", _ws_translate_function), ("ws_explain", _ws_explain_function),
                          ("ws_command", _ws_command_function)):
        functions[name], items = builder()
        _F[name] = functions[name]
        objects.extend(items)
    return functions, tuple(objects)


def _record_value(value) -> bytes:
    """A ``ValueRef`` or ``TransactionValueRef`` as record ULEBs."""
    from xax_workspace import TransactionValueRef

    if isinstance(value, TransactionValueRef):
        return uleb(VALUE_INSERTED) + uleb(value.insertion) + uleb(value.result)
    if value.tag == 0:
        return uleb(VALUE_PARAMETER) + uleb(value.block) + uleb(value.index)
    return uleb(VALUE_RESULT) + uleb(value.block) + uleb(value.index) + uleb(value.result)


def edit_record(mutations, expected_root: bytes = bytes(32), objects=()) -> bytes:
    """The edit record for ``mutations``: ``(kind, function CID, block, node, expected, value)`` for an operation or a
    constant, ``(REPLACE_REFERENCE, owner CID, old child CID, new child CID)`` for a reference (S15d.4a); ``objects``,
    the new objects the transaction supplies (``SemanticObject``s, each written as its kind, references and body).
    S15d.4b (ADR-314), values being ``ValueRef``s or ``TransactionValueRef``s:
    ``(REPLACE_USE, function, block, node, operand, expected value, value)``, ``(DELETE_NODE, function, block, node)``,
    ``(INSERT_NODE, function, block, anchor node, local id, operation, operand values, result type CID, constant value
    or None, attributes)``, ``(SET_RESULT_TYPE, function, block, node, result, expected type CID, type CID)``,
    ``(DISCONNECT_EDGE, function, block, edge, argument, expected value)``, ``(CONNECT_EDGE, function, block, edge,
    argument, value)``."""
    data = bytearray(RECORD_MAGIC + expected_root + uleb(len(mutations)))
    for kind, *fields in mutations:
        data += uleb(kind)
        if kind == REPLACE_REFERENCE:
            owner, old, new = fields
            data += owner + old + new
        elif kind == REPLACE_USE:
            function_cid, block, node, operand, expected, value = fields
            data += function_cid + uleb(block) + uleb(node) + uleb(operand) + _record_value(expected) + _record_value(value)
        elif kind == DELETE_NODE:
            function_cid, block, node = fields
            data += function_cid + uleb(block) + uleb(node)
        elif kind == INSERT_NODE:
            function_cid, block, node, local, operation, operands, result_type, value, attributes = fields
            data += function_cid + uleb(block) + uleb(node) + uleb(local) + uleb(int(operation)) + uleb(len(operands))
            for item in operands:
                data += _record_value(item)
            data += result_type + (uleb(0) if value is None else uleb(1) + uleb(value)) + uleb(len(attributes))
            for item in attributes:
                data += uleb(item)
        elif kind == SET_RESULT_TYPE:
            function_cid, block, node, result, expected_type, value_type = fields
            data += function_cid + uleb(block) + uleb(node) + uleb(result) + expected_type + value_type
        elif kind in (DISCONNECT_EDGE, CONNECT_EDGE):
            function_cid, block, edge, argument, value = fields
            data += function_cid + uleb(block) + uleb(edge) + uleb(argument) + _record_value(value)
        else:
            function_cid, block, node, expected, value = fields
            data += function_cid + uleb(block) + uleb(node) + uleb(expected) + uleb(value)
    if objects:
        data += uleb(len(objects))
        for item in objects:
            data += uleb(int(item.kind)) + uleb(len(item.references)) + b"".join(item.references) + uleb(len(item.body)) + item.body
    return bytes(data)


def parse_record(record: bytes, with_objects: bool = False):
    """``(expected root or None, mutations)`` of a well-formed record (``edit_record``'s tuples); with ``with_objects``
    also the supplied objects."""
    from xax_compiler import Cursor, Kind as K, SemanticObject, ValueRef
    from xax_workspace import TransactionValueRef

    if record[:len(RECORD_MAGIC)] != RECORD_MAGIC:
        raise ValueError("not an edit record")
    root = record[len(RECORD_MAGIC):len(RECORD_MAGIC) + 32]
    cursor = Cursor(record[len(RECORD_MAGIC) + 32:], "edit")

    def value():
        tag = cursor.uleb()
        if tag == VALUE_INSERTED:
            return TransactionValueRef(cursor.uleb(), cursor.uleb())
        if tag == VALUE_PARAMETER:
            return ValueRef.parameter(cursor.uleb(), cursor.uleb())
        if tag == VALUE_RESULT:
            return ValueRef.node_result(cursor.uleb(), cursor.uleb(), cursor.uleb())
        raise ValueError("value tag")

    mutations = []
    for _ in range(cursor.uleb()):
        kind = cursor.uleb()
        if kind == REPLACE_REFERENCE:
            mutations.append((kind, cursor.take(32), cursor.take(32), cursor.take(32)))
            continue
        function_cid = cursor.take(32)
        if kind == REPLACE_USE:
            mutations.append((kind, function_cid, cursor.uleb(), cursor.uleb(), cursor.uleb(), value(), value()))
        elif kind == DELETE_NODE:
            mutations.append((kind, function_cid, cursor.uleb(), cursor.uleb()))
        elif kind == INSERT_NODE:
            block, node, local, operation = (cursor.uleb() for _ in range(4))
            operands = tuple(value() for _ in range(cursor.uleb()))
            result_type = cursor.take(32)
            constant_value = cursor.uleb() if cursor.uleb() else None
            attributes = tuple(cursor.uleb() for _ in range(cursor.uleb()))
            mutations.append((kind, function_cid, block, node, local, operation, operands, result_type, constant_value, attributes))
        elif kind == SET_RESULT_TYPE:
            mutations.append((kind, function_cid, cursor.uleb(), cursor.uleb(), cursor.uleb(), cursor.take(32), cursor.take(32)))
        elif kind in (DISCONNECT_EDGE, CONNECT_EDGE):
            mutations.append((kind, function_cid, cursor.uleb(), cursor.uleb(), cursor.uleb(), value()))
        else:
            mutations.append((kind, function_cid, cursor.uleb(), cursor.uleb(), cursor.uleb(), cursor.uleb()))
    objects = []
    if cursor.remaining:
        start = cursor.pos
        count = cursor.uleb()
        if not count:  # an empty section is no section: the record ends before it
            cursor.pos = start
            cursor.end("EDIT-RECORD-END")
        for _ in range(count):
            kind = K(cursor.uleb())
            references = tuple(cursor.take(32) for _ in range(cursor.uleb()))
            objects.append(SemanticObject.create(kind, cursor.take(cursor.uleb()), references))
    cursor.end("EDIT-RECORD-END")
    parsed = (None if root == bytes(32) else root), tuple(mutations)
    return (*parsed, tuple(objects)) if with_objects else parsed


def workspace_mutations(reader, mutations, objects=()):
    """S15d.4b (ADR-314): the ``xax_workspace`` transaction a record's mutations name, against ``Workspace(reader)``:
    each node by its handle (an edge by its block's first node's), each type by its handle, a new type (a supplied
    ``bits<N>``) by its literal.  Gives ``(workspace, mutations)``."""
    from xax_compiler import Cursor, Operation, StoreReader, decode_bits_width
    from xax_workspace import (
        ConnectEdgeArgument, DeleteNode, DisconnectEdgeArgument, InsertPureNode, ReplaceUse, SetConstant, SetOperation, SetResultType, Workspace,
    )

    workspace = Workspace(reader)
    given = {item.cid: item for item in objects}

    def handle(function_cid, block, node):
        graph = reader.get(reader.get(function_cid).references[Cursor(reader.get(function_cid).body, "").uleb()])
        from xax_compiler import _parse_graph
        parsed = _parse_graph(graph, reader.get)
        if block >= len(parsed.blocks) or node >= len(parsed.blocks[block].nodes):
            raise ValueError("no such node")  # the engine rejects it (WORKSPACE-NODE-INDEX); the workspace has no handle
        position = sum(len(parsed.blocks[b].nodes) for b in range(block)) + node
        return workspace.function_nodes(function_cid, 1 << 20).entities[position].handle

    bound = set()

    def type_handle(cid, function_cid, literal=True):
        """A type's handle: bound by querying the function's nodes' neighborhoods (a supplied ``bits<N>``: its
        literal, which only an insertion takes)."""
        if function_cid not in bound:
            bound.add(function_cid)
            for entity in workspace.function_nodes(function_cid, 1 << 20).entities:
                workspace.neighborhood(entity.handle, 1 << 10)
        for name, binding in workspace._type_bindings.items():
            if binding[0] == cid:
                return name
        source = given.get(cid) or (reader.get(cid) if cid in reader.object_cids else None)
        if literal and source is not None:
            return f"bits<{decode_bits_width(source)}>"
        raise ValueError("unbound type")

    made = []
    for kind, *fields in mutations:
        if kind == SET_OPERATION:
            function_cid, block, node, expected, value = fields
            made.append(SetOperation(handle(function_cid, block, node), Operation(expected), Operation(value)))
        elif kind == SET_CONSTANT:
            function_cid, block, node, expected, value = fields
            made.append(SetConstant(handle(function_cid, block, node), expected, value))
        elif kind == REPLACE_USE:
            function_cid, block, node, operand, expected, value = fields
            made.append(ReplaceUse(handle(function_cid, block, node), operand, expected, value))
        elif kind == DELETE_NODE:
            function_cid, block, node = fields
            made.append(DeleteNode(handle(function_cid, block, node), block, node))
        elif kind == INSERT_NODE:
            function_cid, block, node, local, operation, operands, result_type, value, attributes = fields
            made.append(InsertPureNode(handle(function_cid, block, node), block, node, local, Operation(operation), operands,
                                       type_handle(result_type, function_cid), value, attributes))
        elif kind == SET_RESULT_TYPE:
            function_cid, block, node, result, expected_type, value_type = fields
            made.append(SetResultType(handle(function_cid, block, node), result, type_handle(expected_type, function_cid, False),
                                      type_handle(value_type, function_cid, False)))
        elif kind == DISCONNECT_EDGE:
            function_cid, block, edge, argument, value = fields
            made.append(DisconnectEdgeArgument(handle(function_cid, block, 0), block, edge, argument, value))
        elif kind == CONNECT_EDGE:
            function_cid, block, edge, argument, value = fields
            made.append(ConnectEdgeArgument(handle(function_cid, block, 0), block, edge, argument, value))
        else:
            raise ValueError("no workspace mutation")
    return workspace, tuple(made)


def apply_reference(reader, record: bytes):
    """The store ``edit`` makes from ``reader`` for a well-formed, applicable ``record``, computed in Python: the
    reference the XAX engine is compared with (``tests/test_xax_selfhost_edit.py``), equal to ``Workspace.commit`` for
    the same mutations.  It checks the root and each node's expected operation or value, and nothing else."""
    from xax_compiler import Cursor, SemanticObject, StoreReader, ref_body, write_store

    root, mutations, supplied = parse_record(record, with_objects=True)
    if root is not None and root != reader.root_cid:
        raise ValueError("stale root")
    if any(kind in STRUCTURAL for kind, *_fields in mutations):
        # S15d.4b (ADR-314): the workspace's own commit is the reference (its verification included).
        from xax_workspace import RootRef, Transaction

        workspace, made = workspace_mutations(reader, mutations, supplied)
        result = workspace.commit(Transaction(RootRef(0), made))
        if not result.committed:
            raise ValueError(f"workspace rejected: {result.diagnostic.rule}")
        return StoreReader(workspace.reader.data)
    objects = {item.cid: item for item in reader.objects()}
    edits: dict[bytes, dict[tuple[int, int], tuple]] = {}
    extras: dict[tuple[bytes, int, int], SemanticObject] = {}
    replaced: dict[bytes, dict[bytes, bytes]] = {}  # S15d.4a: owner -> {old child: new child}
    given = {item.cid: item for item in supplied}
    for kind, *fields in mutations:
        if kind == REPLACE_REFERENCE:
            owner, old, new = fields
            if owner not in objects or old not in objects[owner].references or (new not in objects and new not in given):
                raise ValueError("reference precondition")
            replaced.setdefault(owner, {})[old] = new
            continue
        function_cid, block, node, expected, value = fields
        function_object = objects[function_cid]
        graph = objects[function_object.references[Cursor(function_object.body, "").uleb()]]
        edits.setdefault(graph.cid, {})[(block, node)] = (kind, expected, value)

    def scan(owner: SemanticObject, on_reference, emit: bool) -> bytes:
        cursor, out = Cursor(owner.body, owner.cid.hex()), bytearray()
        edited = edits.get(owner.cid, {})

        def copy():
            number = cursor.uleb()
            out.extend(uleb(number))
            return number

        def string():
            out.extend(cursor.take(copy()))

        def reference(site=None):
            out.extend(on_reference(cursor.uleb(), site))

        def value():
            tag = copy()
            copy()
            copy()
            if tag == 1:
                copy()

        if owner.kind == Kind.GRAPH_FRAGMENT:
            blocks = copy()
            copy()
            for b in range(blocks):
                for _ in range(copy()):
                    reference()
                for n in range(copy()):
                    operation = cursor.uleb()
                    mutation = edited.get((b, n))
                    if mutation is not None and mutation[0] == SET_OPERATION:
                        if operation != mutation[1]:
                            raise ValueError("operation precondition")
                        out.extend(uleb(mutation[2]))
                    else:
                        out.extend(uleb(operation))
                    if operation == int(Operation.CALL_GROUP_MEMBER):
                        copy()
                    if operation in ENTITY:
                        reference((b, n) if mutation is not None and mutation[0] == SET_CONSTANT else None)
                    for _ in range(copy()):
                        value()
                    for _ in range(copy()):
                        reference()
                    if operation in ATTRIBUTE:
                        for _ in range(copy()):
                            copy()
                terminator = copy()
                if terminator == 1:
                    copy()
                    for _ in range(copy()):
                        value()
                elif terminator == 2:
                    value()
                    for _edge in range(2):
                        copy()
                        for _ in range(copy()):
                            value()
                elif terminator == 3:
                    for _ in range(copy()):
                        value()
                elif terminator == 4:
                    string()
        elif owner.kind == Kind.FUNCTION:
            reference()
            for _ in range(copy()):
                reference()
            for _ in range(copy()):
                reference()
        elif owner.kind == Kind.BUILD:
            copy()
            reference()
            string()
            reference()
            reference()
            for _ in range(2):
                for _ in range(copy()):
                    string()
                    reference()
            for _ in range(copy()):
                copy()
        elif owner.kind == Kind.PACKAGE:
            string()
            modules = [cursor.uleb() for _ in range(cursor.uleb())]
            out.extend(uleb(len(modules)))
            for encoded in sorted((on_reference(index, None) for index in modules), key=lambda item: Cursor(item, "").uleb()):
                out.extend(encoded)
            for _ in range(copy()):
                if copy() == 1:
                    reference()
                else:
                    string()
            for _ in range(3):
                for _ in range(copy()):
                    string()
                    reference()
            for _ in range(copy()):
                copy()
                string()
        else:
            raise ValueError(f"unsupported user {owner.kind.name}")
        cursor.end("EDIT-SCAN")
        return bytes(out)

    users: dict[bytes, list[bytes]] = {}
    for item in objects.values():
        for child in item.references:
            users.setdefault(child, []).append(item.cid)
    affected, pending = set(edits) | set(replaced), [*edits, *replaced]
    while pending:
        for user in users.get(pending.pop(), ()):
            if user not in affected:
                affected.add(user)
                pending.append(user)
    for cid in affected:
        if objects[cid].kind not in (Kind.GRAPH_FRAGMENT, Kind.FUNCTION, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.PACKAGE, Kind.BUILD):
            raise ValueError(f"unsupported user {objects[cid].kind.name}")
    # The new constants.
    for graph_cid, nodes in edits.items():
        def locate(index, site, graph_cid=graph_cid):
            if site is not None:
                old = objects[objects[graph_cid].references[index]]
                kind, expected, value = edits[graph_cid][site]
                if int.from_bytes(old.body[2:], "little") != expected:
                    raise ValueError("constant precondition")
                extras[(graph_cid, *site)] = SemanticObject.create(Kind.CONSTANT, old.body[:2] + value.to_bytes(old.body[1], "little"), old.references)
            return b""
        scan(objects[graph_cid], locate, False)
    new: dict[bytes, SemanticObject] = {}

    def current(cid: bytes) -> bytes:
        return new[cid].cid if cid in new else cid

    def child(owner: bytes, cid: bytes) -> bytes:
        """The child an owner's reference names after the transaction (its replacement, at its current version)."""
        return current(replaced.get(owner, {}).get(cid, cid))

    done: set[bytes] = set()
    while len(done) < len(affected):
        for cid in sorted(affected):
            owner = objects[cid]
            children = [replaced.get(cid, {}).get(item, item) for item in owner.references]
            if cid in done or any(item in affected and item not in done for item in children):
                continue
            if owner.kind in (Kind.MODULE, Kind.PROGRAM_ROOT):
                references = sorted({child(cid, item) for item in owner.references})
                body = ref_body(range(len(references)))
            elif owner.kind in (Kind.PACKAGE, Kind.BUILD):
                from xax_build import rebuild_package_object

                def replacement(reference):
                    selected = replaced.get(cid, {}).get(reference, reference)
                    return new[selected] if selected in new else given[selected] if selected in given else objects[selected]

                rebuilt = rebuild_package_object(owner, objects.__getitem__, replacement)
                references, body = rebuilt.references, rebuilt.body
            else:
                collected: list[bytes] = []

                def collect(index, site, owner=owner):
                    extra = extras.get((owner.cid, *site)) if site is not None else None
                    collected.append(extra.cid if extra is not None else child(owner.cid, owner.references[index]))
                    return b""

                scan(owner, collect, False)
                references = sorted(set(collected))
                order = iter(collected)
                body = scan(owner, lambda _index, _site: uleb(references.index(next(order))), True)
            new[cid] = SemanticObject.create(owner.kind, body, references)
            done.add(cid)
    pool = {**objects, **given, **{item.cid: item for item in new.values()}, **{item.cid: item for item in extras.values()}}
    root_cid = current(reader.root_cid)
    reached, pending = {}, [root_cid]
    while pending:
        cid = pending.pop()
        if cid not in reached:
            reached[cid] = pool[cid]
            pending.extend(pool[cid].references)
    return StoreReader(write_store(root_cid, tuple(reached.values())))


__all__ = ["EB", "RECORD_MAGIC", "REPLACE_REFERENCE", "SET_CONSTANT", "SET_OPERATION", "apply_reference", "build_functions", "edit_record",
           "parse_record"]
