"""S15e.5 (ADR-327): the lowering of ``xax_jvm._compile_method_pass`` as XAX functions (stage S15e.5a).

``get``, ``put`` and ``lower_node`` call each other recursively in the bootstrap (an expression tree is lowered where
it is read; a short-circuit condition jumps through its operands).  Here they are tasks on an explicit stack
(``jl_run``): a task's expansion pushes its steps in reverse, and every condition that reads the deferred values is
evaluated when the task is reached, so the bytes and the pool entries come in the bootstrap's order.

Task kinds (``K_*``, five words each: kind and four arguments): ``GET`` a value; ``NODE`` lower a node; ``OP`` a few
constant bytes; ``ICONST``/``LCONST``; ``PUT`` a value; ``MASK`` (descriptor, width); ``CALL`` an internal method
(callee function); ``JAVA`` a fixed ``java.lang`` method or the shared ``xax$pk``; ``BRANCH`` (opcode, label);
``MARK`` (label); ``JUMP`` (condition, when, label); ``STORE`` (descriptor, slot); ``GETLONG`` (value, width, signed);
``FCONST`` (raw bits, width).
"""

from __future__ import annotations

from xax_compiler import FloatCompare, IntCompare, Operation, RESOURCE_EFFECT_OPERATIONS
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_ranges import _attribute, _block_at, _node_at
from xax_selfhost_general_regalloc import _callee_object, _eop
from xax_selfhost_general_view import (
    N_NOPS, N_NRES, B_EDGES, B_INPUTS, B_KIND, B_NEDGES, B_NNODES, B_NP, B_NVALUES, B_VALUES, BRANCH, CONDITIONAL, EDGE, RETURN, _f, _operand, _output,
)
from xax_selfhost_jvm_class import B_LEN, bdata, blen
from xax_selfhost_jvm_code import (
    C_BUF, C_ENDED, C_FIX, C_LABELS, C_LINES, C_NFIX, C_NLINES, C_PENDING, C_POOL, C_READS, C_STORED, C_TARGET, C_VSDESC, C_VSLOT, D_D, D_F, D_I, D_J,
    D_NONE, GOTO, LOAD, RETURN as RETURN_OPS, SLOT_LATE, STORE, ZERO, _bx, _flush, _in, _length, _m, _pick, _set_m, branch, iconst, invoke,
    fconst, lconst, local, mark, op, opx, raw,
)
from xax_selfhost_jvm_method import (
    BL_BASE, BL_INC, BL_NPRED, BL_ORDER, BL_PLACED, BL_PRED, BL_RESOLVED, M_ENTRY, M_FN, M_FOLLOW, M_FREED, M_GEND, M_ISENTRY, M_KEPTNONE,
    M_LABELN, M_MAXCALL, M_MAXLOC, M_NB, M_NEEDS_PK, M_NEEDZ, M_NEXT, M_NORDER, M_NRET, M_NV, M_PASS, M_PEND, M_PSLOTS, M_RETTYPES,
    M_ONE, M_SCRATCH, M_STYPE, M_TRAPUSED, M_TYPED, M_WORK, N_LINE, OP, ST_FREED, ST_TOP, V_ALIAS, V_CONST, V_COPYOF, V_CVAL, V_DESC, V_FOLDED,
    V_FUSED, V_IMPLICIT, V_INLINED, V_KEPT, V_KW, V_SINGLE, _def, _desc, _each_edge, _node_id, _pick_slots, _pow2, _result0, _set_v,
    _target_index, _v, _width, canon, carried, copy_like, late, repacked, sole_user, _call_none,
)
from xax_selfhost_views_backend import _FN, _call, _g, _ok

TASK_W = 5
(K_GET, K_NODE, K_OP, K_ICONST, K_LCONST, K_PUT, K_MASK, K_CALL, K_JAVA, K_BRANCH, K_MARK, K_JUMP, K_STORE, K_GETLONG, K_FCONST) = range(1, 16)
# The fixed methods a lowering calls (``K_JAVA``): owner, name, descriptor.
JAVA = (
    ("java/lang/Integer", "toUnsignedLong", "(I)J"),
    ("java/lang/Long", "divideUnsigned", "(JJ)J"),
    ("java/lang/Long", "remainderUnsigned", "(JJ)J"),
    ("java/lang/Long", "rotateRight", "(JI)J"),
    ("java/lang/Integer", "rotateRight", "(II)I"),
    (None, "xax$pk", "(II)J"),  # the class's own shared member
)
J_TOUNSIGNED, J_LDIV, J_LREM, J_LROTR, J_IROTR, J_PK = range(6)
RELATION = {IntCompare.EQ: 0, IntCompare.NE: 1, IntCompare.ULT: 2, IntCompare.SLT: 2, IntCompare.ULE: 5, IntCompare.SLE: 5,
            IntCompare.UGT: 4, IntCompare.SGT: 4, IntCompare.UGE: 3, IntCompare.SGE: 3}
EQ_, NE_, LT_, GE_, GT_, LE_ = range(6)
FLOAT_RELATION = {FloatCompare.EQ: EQ_, FloatCompare.NE: NE_, FloatCompare.LT: LT_, FloatCompare.LE: LE_, FloatCompare.GT: GT_,
                  FloatCompare.GE: GE_}
BRANCH_IF_NOT = {EQ_: 0x9A, NE_: 0x99, LT_: 0x9C, GE_: 0x9B, GT_: 0x9E, LE_: 0x9D}
INT_BRANCH_IF_NOT = {EQ_: 0xA0, NE_: 0x9F, LT_: 0xA2, GE_: 0xA1, GT_: 0xA4, LE_: 0xA3}
INVERSE = {0x99: 0x9A, 0x9A: 0x99, 0x9B: 0x9C, 0x9C: 0x9B, 0x9D: 0x9E, 0x9E: 0x9D, 0x9F: 0xA0, 0xA0: 0x9F, 0xA1: 0xA2, 0xA2: 0xA1, 0xA3: 0xA4,
           0xA4: 0xA3}
SIGNED = tuple(int(k) for k in (IntCompare.SLT, IntCompare.SLE, IntCompare.SGT, IntCompare.SGE))
ARITH_OPCODE = {OP["ADD_WRAP"]: (0x60, 0x61), OP["SUB_WRAP"]: (0x64, 0x65), OP["MUL_WRAP"]: (0x68, 0x69), OP["BIT_AND"]: (0x7E, 0x7F),
                OP["BIT_OR"]: (0x80, 0x81), OP["BIT_XOR"]: (0x82, 0x83)}
MAY_RAISE = tuple(int(op) for op in (Operation.CALL_DIRECT, Operation.CALL_FOREIGN, Operation.UDIV, Operation.UREM))
TRAP_LABEL = 0  # labels: block b is b, false stub NB + b, the trap 2 NB, a fresh one 2 NB + 1 + k


def _slot(e: E, value):
    return _v(e, C_VSLOT, value)


def _sdesc(e: E, value):
    return _v(e, C_VSDESC, value)


def _trap_label(e: E):
    return e.mul(_m(e, M_NB), 2)


def _fresh(e: E, name: str):
    e.var(name, e.add(e.add(e.mul(_m(e, M_NB), 2), 1), _m(e, M_LABELN)))
    _set_m(e, M_LABELN, e.add(_m(e, M_LABELN), 1))
    return e.p[name]


# -- the task stack -------------------------------------------------------------------------------------------------------

class Steps:
    """A sequence of tasks pushed in reverse (so they run in order)."""

    def __init__(self, e: E):
        self.e = e
        self.items = []

    def add(self, kind: int, *arguments):
        self.items.append((kind, arguments))
        return self

    def push(self):
        e = self.e
        for kind, arguments in reversed(self.items):
            words = list(arguments) + [0] * (4 - len(arguments))
            _call(e, "jl_push", kind, *words)


def _push_fn(tables):
    def build(e: E):
        p = e.p
        e.var("pu_top", _m(e, M_ONE))
        _ok(e, e.lt(p["pu_top"], 1 << 18))
        e.var("pu_at", e.add(_stack(e), e.mul(p["pu_top"], TASK_W)))
        for k, name in enumerate(("kind", "a", "b", "c", "d")):
            e.st(e.add(p["pu_at"], k), p[name])
        _set_m(e, M_ONE, e.add(p["pu_top"], 1))
        e.give(1)
    return _function(("kind", "a", "b", "c", "d"), build, tables)


def _stack(e: E):
    from xax_selfhost_jvm_method import M_WORK

    return e.add(_m(e, M_WORK), 1 << 20)


def _desc_get(e: E, value):
    """The descriptor ``get(value)`` returns (copies keep their operand's)."""
    return _sdesc(e, canon(e, value))


# -- get, put, constants, masks -------------------------------------------------------------------------------------------

def _get_task(e: E, value):
    """``get``: through copies sharing a local; a constant rematerialized, a tree lowered here, else the value from
    the stack (pending), duplicated before its delayed store, or loaded."""
    p = e.p
    e.var("gt_r", canon(e, value))

    def through():
        e.var("gt_c", _v(e, V_COPYOF, p["gt_r"]))
        e.var("gt_go", 0)

        def compare():
            e.var("gt_cc", canon(e, p["gt_c"]))
            e.if_(e.both(e.ne(_slot(e, p["gt_r"]), NONE), e.ne(_slot(e, p["gt_r"]), SLOT_LATE), e.eq(_slot(e, p["gt_r"]), _slot(e, p["gt_cc"]))),
                  lambda: (e.set("gt_r", p["gt_cc"]), e.set("gt_go", 1)))

        e.if_(e.ne(p["gt_c"], NONE), compare)
        return p["gt_go"]

    e.var("gt_more", 1)
    e.while_(lambda: e.ne(p["gt_more"], 0), lambda: e.set("gt_more", through()))
    _ok(e, e.ne(_slot(e, p["gt_r"]), NONE))  # JVM-VALUE-MACHINE: the bootstrap's
    e.var("gt_d", _sdesc(e, p["gt_r"]))

    def constant():
        e.if_(e.eq(p["gt_d"], D_I), lambda: iconst(e, _v(e, V_CVAL, p["gt_r"])), lambda: lconst(e, _v(e, V_CVAL, p["gt_r"])))

    def tree():
        _call(e, "jl_push", K_NODE, _def(e, p["gt_r"]), 0, 0, 0)

    def stored_dup():
        _set_m(e, C_STORED, NONE)
        opx(e, e.sel(e.eq(_pick_slots(e, p["gt_d"]), 2), 0x5C, 0x59), 1)
        local(e, True, p["gt_d"], _slot(e, p["gt_r"]))

    def read():
        _set_v(e, C_READS, p["gt_r"], e.add(_v(e, C_READS, p["gt_r"]), 1))
        e.if_(e.eq(_m(e, C_PENDING), p["gt_r"]), lambda: _set_m(e, C_PENDING, NONE), lambda: e.if_(
            e.eq(_m(e, C_STORED), p["gt_r"]), stored_dup, lambda: local(e, False, p["gt_d"], _slot(e, p["gt_r"]))))

    e.if_(e.ne(_v(e, V_CONST, p["gt_r"]), 0), constant, lambda: e.if_(e.ne(_v(e, V_INLINED, p["gt_r"]), 0), tree, read))


def _put_task(e: E, value):
    p = e.p
    e.var("pt_r", value)

    def defer():
        _flush(e)
        single = e.both(e.eq(_m(e, M_PASS), 2), e.ne(_v(e, V_SINGLE, p["pt_r"]), 0), e.eq(_v(e, V_IMPLICIT, p["pt_r"]), 0))
        e.if_(single, lambda: _set_m(e, C_PENDING, p["pt_r"]), lambda: _set_m(e, C_STORED, p["pt_r"]))

    e.if_(e.eq(_v(e, V_INLINED, p["pt_r"]), 0), defer)


def _mask_task(e: E, desc, width):
    p = e.p
    e.var("mk_d", desc)
    e.var("mk_w", width)
    e.if_(e.both(e.eq(p["mk_d"], D_I), e.lt(p["mk_w"], 32)), lambda: (iconst(e, e.sub(_pow2(e, p["mk_w"]), 1)), op(e, 0x7E)), lambda: e.if_(
        e.both(e.eq(p["mk_d"], D_J), e.lt(p["mk_w"], 64)), lambda: (lconst(e, e.sub(_pow2(e, p["mk_w"]), 1)), op(e, 0x7F))))


def _java_task(e: E, which):
    """``invokestatic`` of a fixed method (its Methodref made now, as the bootstrap's ``pool.method`` call is)."""
    from xax_selfhost_jvm_class import method_literal

    p = e.p
    e.var("jv_w", which)
    op(e, 0xB8)
    for k, (owner, name, descriptor) in enumerate(JAVA):
        def one(owner=owner, name=name, descriptor=descriptor):
            if owner is None:
                e.var("jv_i", _call(e, "jl_own_method", 0, 0))
            else:
                e.var("jv_i", method_literal(e, _m(e, C_POOL), owner, name, descriptor, "jv_ml"))
            raw(e, p["jv_i"], 2)

        e.if_(e.eq(p["jv_w"], k), one)


def _get_long_task(e: E, value, width, signed):
    """``get_as_long``: a constant transformed and pushed as a long; else ``get`` then sign- or zero-extension, or the
    sign flip that turns unsigned order into signed order."""
    p = e.p
    e.var("gl_v", value)
    e.var("gl_w", width)
    e.var("gl_s", signed)

    def constant():
        e.var("gl_c", _v(e, V_CVAL, p["gl_v"]))
        e.if_(e.both(e.ne(p["gl_s"], 0), e.ne(e.and_(e.udiv(p["gl_c"], _pow2(e, e.sub(p["gl_w"], 1))), 1), 0)),
              lambda: e.set("gl_c", e.sub(p["gl_c"], _pow2(e, p["gl_w"]))), lambda: e.if_(
                  e.both(e.eq(p["gl_s"], 0), e.eq(p["gl_w"], 64)), lambda: e.set("gl_c", _bx(e, p["gl_c"], 1 << 63))))
        _call(e, "jl_push", K_LCONST, p["gl_c"], 0, 0, 0)

    def computed():
        e.var("gl_d", _desc_get(e, p["gl_v"]))
        steps = []

        def signed_steps():
            e.var("gl_storage", e.sel(e.eq(p["gl_d"], D_I), 32, 64))

            def extend():
                _call(e, "jl_push", K_OP, e.sel(e.eq(p["gl_d"], D_I), 0x7A, 0x7B), 1, 0, 0)
                _call(e, "jl_push", K_ICONST, e.sub(p["gl_storage"], p["gl_w"]), 0, 0, 0)
                _call(e, "jl_push", K_OP, e.sel(e.eq(p["gl_d"], D_I), 0x78, 0x79), 1, 0, 0)
                _call(e, "jl_push", K_ICONST, e.sub(p["gl_storage"], p["gl_w"]), 0, 0, 0)

            # Pushed in reverse: the i2l last, after the extension.
            e.if_(e.eq(p["gl_d"], D_I), lambda: _call(e, "jl_push", K_OP, 0x85, 1, 0, 0))
            e.if_(e.lt(p["gl_w"], p["gl_storage"]), extend)

        def unsigned_steps():
            def from_int():
                e.if_(e.eq(p["gl_w"], 32), lambda: (_call(e, "jl_push", K_OP, 0x7F, 1, 0, 0), _call(e, "jl_push", K_LCONST, 0xFFFFFFFF, 0, 0, 0)))
                _call(e, "jl_push", K_OP, 0x85, 1, 0, 0)

            e.if_(e.eq(p["gl_d"], D_I), from_int, lambda: e.if_(e.eq(p["gl_w"], 64), lambda: (
                _call(e, "jl_push", K_OP, 0x83, 1, 0, 0), _call(e, "jl_push", K_LCONST, 1 << 63, 0, 0, 0))))

        e.if_(e.ne(p["gl_s"], 0), signed_steps, unsigned_steps)
        _call(e, "jl_push", K_GET, p["gl_v"], 0, 0, 0)

    e.if_(e.ne(_v(e, V_CONST, p["gl_v"]), 0), constant, computed)


# -- compares ---------------------------------------------------------------------------------------------------------

def _relation(e: E, kind):
    return _pick(e, kind, {int(k): v for k, v in RELATION.items()})


def _relation_of(e: E, node, name: str):
    """``_INT_RELATION``/``_FLOAT_RELATION`` of a compare node's kind into ``name`` (another float kind: the
    bootstrap's KeyError, declined)."""
    p = e.p
    e.var(f"{name}_k", _attribute(e, node, 0))
    e.var(f"{name}_fl", e.flag(e.eq(_eop(e, node), OP["FLOAT_COMPARE"])))
    e.if_(e.ne(p[f"{name}_fl"], 0), lambda: _ok(e, _in(e, p[f"{name}_k"], tuple(int(k) for k in FLOAT_RELATION))))
    e.var(name, e.sel(e.ne(p[f"{name}_fl"], 0), _pick(e, p[f"{name}_k"], {int(k): v for k, v in FLOAT_RELATION.items()}), _relation(e, p[f"{name}_k"])))
    return p[name]


def _float_cmp(e: E, desc, nan_high=None):
    """``fcmpl``/``fcmpg``/``dcmpl``/``dcmpg`` (``nan_high`` None: the ``l`` forms)."""
    if nan_high is None:
        return e.sel(e.eq(desc, D_F), 0x95, 0x97)
    return e.sel(e.eq(desc, D_F), e.sel(nan_high, 0x96, 0x95), e.sel(nan_high, 0x98, 0x97))


def _compare_to_int(e: E, node, prefix: str):
    """``compare_to_int``: its steps pushed (in reverse, after the caller's); the relation into ``prefix``."""
    p = e.p
    _relation_of(e, node, prefix)

    def floating():
        # The NaN result that makes each ordered relation false and NE true.
        e.var(f"{prefix}_fd", _desc_get(e, _operand(e, node, 0)))
        nan_high = e.either(e.eq(p[prefix], LT_), e.eq(p[prefix], LE_))
        Steps(e).add(K_GET, _operand(e, node, 0)).add(K_GET, _operand(e, node, 1)).add(K_OP, _float_cmp(e, p[f"{prefix}_fd"], nan_high), 1).push()

    e.if_(e.ne(p[f"{prefix}_fl"], 0), floating, lambda: _int_compare_to_int(e, node, prefix))


def _int_compare_to_int(e: E, node, prefix: str):
    p = e.p
    _width(e, _operand(e, node, 0), f"{prefix}_w")
    e.var(f"{prefix}_signed", e.flag(_in(e, p[f"{prefix}_k"], SIGNED)))
    eqne = e.both(e.le(p[prefix], NE_), e.eq(_sdesc(e, _operand(e, node, 0)), D_J))
    # Pushed in reverse: lcmp after both operands.
    _call(e, "jl_push", K_OP, 0x94, 1, 0, 0)  # lcmp
    e.if_(eqne, lambda: (_call(e, "jl_push", K_GET, _operand(e, node, 1), 0, 0, 0), _call(e, "jl_push", K_GET, _operand(e, node, 0), 0, 0, 0)),
          lambda: (_call(e, "jl_push", K_GETLONG, _operand(e, node, 1), p[f"{prefix}_w"], p[f"{prefix}_signed"], 0),
                   _call(e, "jl_push", K_GETLONG, _operand(e, node, 0), p[f"{prefix}_w"], p[f"{prefix}_signed"], 0)))


def _compare_result_pushes(e: E, relation):
    """``_compare_result`` (pushed in reverse)."""
    p = e.p
    e.var("cr_rel", relation)

    def seq(*items):
        for kind, word in reversed(items):
            _call(e, "jl_push", kind, word, 1, 0, 0) if kind == K_OP else _call(e, "jl_push", kind, word, 0, 0, 0)

    e.if_(e.eq(p["cr_rel"], EQ_), lambda: seq((K_ICONST, 1), (K_OP, 0x7E), (K_ICONST, 1), (K_OP, 0x82)))
    e.if_(e.eq(p["cr_rel"], NE_), lambda: seq((K_ICONST, 1), (K_OP, 0x7E)))
    e.if_(e.eq(p["cr_rel"], LT_), lambda: seq((K_ICONST, 31), (K_OP, 0x7C)))
    e.if_(e.eq(p["cr_rel"], GT_), lambda: seq((K_OP, 0x74), (K_ICONST, 31), (K_OP, 0x7C)))
    e.if_(e.eq(p["cr_rel"], LE_), lambda: seq((K_OP, 0x74), (K_ICONST, 31), (K_OP, 0x7C), (K_ICONST, 1), (K_OP, 0x82)))
    e.if_(e.eq(p["cr_rel"], GE_), lambda: seq((K_ICONST, 31), (K_OP, 0x7C), (K_ICONST, 1), (K_OP, 0x82)))


def _int_branch_if_not(e: E, node, prefix: str):
    """``int_branch_if_not``: its steps pushed (in reverse, after the caller's branch) and the opcode into ``prefix``
    (NONE: the long path)."""
    p = e.p
    e.var(prefix, NONE)
    e.var(f"{prefix}_a", _operand(e, node, 0))
    e.var(f"{prefix}_b", _operand(e, node, 1))
    e.var(f"{prefix}_kind", _attribute(e, node, 0))
    e.var(f"{prefix}_rel", _relation(e, p[f"{prefix}_kind"]))
    _width(e, p[f"{prefix}_a"], f"{prefix}_w")
    e.var(f"{prefix}_signed", e.flag(_in(e, p[f"{prefix}_kind"], SIGNED)))

    def int_path():
        e.var(f"{prefix}_flip", e.flag(e.both(e.eq(p[f"{prefix}_signed"], 0), e.eq(p[f"{prefix}_w"], 32), e.lt(NE_, p[f"{prefix}_rel"]))))

        def zero():
            e.set(prefix, _pick(e, p[f"{prefix}_rel"], BRANCH_IF_NOT))
            _call(e, "jl_push", K_GET, p[f"{prefix}_a"], 0, 0, 0)

        def pairwise():
            e.set(prefix, _pick(e, p[f"{prefix}_rel"], INT_BRANCH_IF_NOT))
            # The second operand's steps first (pushed in reverse), then the first's.
            for name in (f"{prefix}_b", f"{prefix}_a"):
                def operand(name=name):
                    e.var(f"{prefix}_o", p[name])
                    e.var(f"{prefix}_src", e.sel(e.ne(_v(e, V_INLINED, p[f"{prefix}_o"]), 0), _def(e, p[f"{prefix}_o"]), NONE))
                    flip = e.ne(p[f"{prefix}_flip"], 0)

                    def constant():
                        _call(e, "jl_push", K_ICONST, _bx(e, _v(e, V_CVAL, p[f"{prefix}_o"]), 1 << 31), 0, 0, 0)

                    def offset_source():
                        e.var(f"{prefix}_add", e.flag(e.eq(_eop(e, p[f"{prefix}_src"]), OP["ADD_WRAP"])))
                        e.var(f"{prefix}_off", _v(e, V_CVAL, _operand(e, p[f"{prefix}_src"], 1)))
                        _call(e, "jl_push", K_OP, 0x60, 1, 0, 0)
                        _call(e, "jl_push", K_ICONST, e.and_(e.sel(e.ne(p[f"{prefix}_add"], 0), e.add(1 << 31, p[f"{prefix}_off"]),
                                                                    e.sub(1 << 31, p[f"{prefix}_off"])), 0xFFFFFFFF), 0, 0, 0)
                        _call(e, "jl_push", K_GET, _operand(e, p[f"{prefix}_src"], 0), 0, 0, 0)

                    def plain():
                        e.if_(flip, lambda: (_call(e, "jl_push", K_OP, 0x82, 1, 0, 0), _call(e, "jl_push", K_ICONST, 0x80000000, 0, 0, 0)))
                        _call(e, "jl_push", K_GET, p[f"{prefix}_o"], 0, 0, 0)

                    is_offset = e.both(flip, e.ne(p[f"{prefix}_src"], NONE), _in(e, _eop(e, e.sel(e.ne(p[f"{prefix}_src"], NONE), p[f"{prefix}_src"], node)),
                                                                                (OP["ADD_WRAP"], OP["SUB_WRAP"])))
                    e.if_(e.both(flip, e.ne(_v(e, V_CONST, p[f"{prefix}_o"]), 0)), constant, lambda: e.if_(is_offset, lambda: e.if_(
                        e.ne(_v(e, V_CONST, _operand(e, p[f"{prefix}_src"], 1)), 0), offset_source, plain), plain))

                operand()

        zero_case = e.both(e.eq(p[f"{prefix}_flip"], 0), e.ne(_v(e, V_CONST, p[f"{prefix}_b"]), 0), e.eq(_v(e, V_CVAL, p[f"{prefix}_b"]), 0))
        e.if_(zero_case, zero, pairwise)

    e.if_(e.both(e.eq(_sdesc(e, p[f"{prefix}_a"]), D_I), e.not_(e.both(e.ne(p[f"{prefix}_signed"], 0), e.lt(p[f"{prefix}_w"], 32)))), int_path)


# -- lower_node ---------------------------------------------------------------------------------------------------------------

def _signed_small(e: E, value):
    """-128 <= signed32(value) <= 127."""
    biased = _bx(e, e.and_(value, 0xFFFFFFFF), 1 << 31)
    return e.both(e.le((1 << 31) - 128, biased), e.le(biased, (1 << 31) + 127))


def _pack_operands(e: E, node, prefix: str):
    """``pack_operands``: ``prefix`` the low operand (NONE when not this pattern), ``prefix_hc`` 1 with ``prefix_hv`` the
    high half's constant, else ``prefix_h`` the high operand."""
    p = e.p
    e.var(prefix, NONE)
    e.var(f"{prefix}_hc", 0)
    e.var(f"{prefix}_hv", 0)
    e.var(f"{prefix}_h", NONE)
    _width(e, _output(e, node, 0), f"{prefix}_w")

    def inlined_def(value):
        return e.sel(e.ne(_v(e, V_INLINED, value), 0), _def(e, value), NONE)

    def i32(value, name):
        _width(e, value, f"{name}_w")
        return e.both(e.eq(_sdesc(e, value), D_I), e.eq(e.p[f"{name}_w"], 32))

    for order in ((0, 1), (1, 0)):
        def attempt(order=order):
            e.var(f"{prefix}_lr", _operand(e, node, order[0]))
            e.var(f"{prefix}_hr", _operand(e, node, order[1]))

            def high_constant():
                e.var(f"{prefix}_low", inlined_def(p[f"{prefix}_lr"]))

                def low_ok():
                    e.var(f"{prefix}_lo", _operand(e, p[f"{prefix}_low"], 0))
                    e.if_(e.both(e.ne(_slot(e, p[f"{prefix}_lo"]), NONE), i32(p[f"{prefix}_lo"], f"{prefix}_li")), lambda: (
                        e.set(prefix, p[f"{prefix}_lo"]), e.set(f"{prefix}_hc", 1), e.set(f"{prefix}_hv", e.udiv(_v(e, V_CVAL, p[f"{prefix}_hr"]), 1 << 32))))

                e.if_(e.ne(p[f"{prefix}_low"], NONE), lambda: e.if_(e.eq(_eop(e, p[f"{prefix}_low"]), OP["INT_ZERO_EXTEND"]), low_ok))

            def halves():
                e.var(f"{prefix}_low", inlined_def(p[f"{prefix}_lr"]))
                e.var(f"{prefix}_high", inlined_def(p[f"{prefix}_hr"]))

                def shapes():
                    e.var(f"{prefix}_wid", inlined_def(_operand(e, p[f"{prefix}_high"], 0)))

                    def widened():
                        e.var(f"{prefix}_x", _operand(e, p[f"{prefix}_low"], 0))
                        e.var(f"{prefix}_y", _operand(e, p[f"{prefix}_wid"], 0))
                        e.if_(e.both(e.ne(_slot(e, p[f"{prefix}_x"]), NONE), e.ne(_slot(e, p[f"{prefix}_y"]), NONE), i32(p[f"{prefix}_x"], f"{prefix}_xi"),
                                     i32(p[f"{prefix}_y"], f"{prefix}_yi")), lambda: (e.set(prefix, p[f"{prefix}_x"]), e.set(f"{prefix}_h", p[f"{prefix}_y"])))

                    e.if_(e.ne(p[f"{prefix}_wid"], NONE), lambda: e.if_(e.eq(_eop(e, p[f"{prefix}_wid"]), OP["INT_ZERO_EXTEND"]), widened))

                ok = e.both(e.ne(p[f"{prefix}_low"], NONE), e.ne(p[f"{prefix}_high"], NONE))
                e.if_(ok, lambda: e.if_(e.both(e.eq(_eop(e, p[f"{prefix}_low"]), OP["INT_ZERO_EXTEND"]), e.eq(_eop(e, p[f"{prefix}_high"]), OP["ROTATE_RIGHT"]),
                                               e.eq(_attribute(e, p[f"{prefix}_high"], 0), 32)), shapes))

            e.if_(e.eq(p[prefix], NONE), lambda: e.if_(
                e.both(e.ne(_v(e, V_CONST, p[f"{prefix}_hr"]), 0), e.eq(e.and_(_v(e, V_CVAL, p[f"{prefix}_hr"]), 0xFFFFFFFF), 0)), high_constant, halves))

        attempt()
    e.if_(e.not_(e.both(e.eq(_eop(e, node), OP["BIT_OR"]), e.eq(p[f"{prefix}_w"], 64))), lambda: e.set(prefix, NONE))


def _node_task(e: E, node):
    """``lower_node`` for the S15e.5a operations (another declines)."""
    p = e.p
    e.var("nd_n", node)
    node = p["nd_n"]
    e.var("nd_op", _eop(e, node))
    opv = p["nd_op"]
    e.var("nd_b", _f(e, node, 1))  # N_B: the node's block in the function's graph
    e.var("nd_line", _v(e, N_LINE, _node_id(e, p["nd_b"], node)))
    e.var("nd_start", _length(e))

    def line():
        e.var("ln_i", _m(e, C_NLINES))
        e.st(e.add(_m(e, C_LINES), e.mul(p["ln_i"], 2)), p["nd_start"])
        e.st(e.add(_m(e, C_LINES), e.add(e.mul(p["ln_i"], 2), 1)), p["nd_line"])
        _set_m(e, C_NLINES, e.add(p["ln_i"], 1))

    e.if_(_in(e, opv, MAY_RAISE), line)
    e.var("nd_r", _result0(e, node))
    result = p["nd_r"]
    r_ok = e.ne(result, NONE)
    e.if_(e.both(r_ok, e.ne(_v(e, V_FOLDED, e.sel(r_ok, result, 0)), 0)), lambda: e.give(1))

    def repack_case():
        e.var("nd_rp", repacked(e, node))
        e.if_(e.ne(p["nd_rp"], NONE), lambda: (_call(e, "jl_push", K_PUT, result, 0, 0, 0), _call(e, "jl_push", K_GET, p["nd_rp"], 0, 0, 0), e.give(1)))

    e.if_(e.both(r_ok, e.ne(_v(e, V_INLINED, e.sel(r_ok, result, 0)), 0)), repack_case)
    e.var("nd_pk", NONE)
    e.var("nd_pk_hc", 0)
    e.var("nd_pk_hv", 0)
    e.var("nd_pk_h", NONE)
    e.if_(e.eq(opv, OP["BIT_OR"]), lambda: _pack_operands(e, node, "nd_pk"))

    def pack():
        _set_m(e, M_NEEDS_PK, 1)
        _call(e, "jl_push", K_PUT, result, 0, 0, 0)
        _call(e, "jl_push", K_JAVA, J_PK, 0, 0, 0)
        e.if_(e.ne(p["nd_pk_hc"], 0), lambda: _call(e, "jl_push", K_ICONST, p["nd_pk_hv"], 0, 0, 0), lambda: _call(e, "jl_push", K_GET, p["nd_pk_h"], 0, 0, 0))
        _call(e, "jl_push", K_GET, p["nd_pk"], 0, 0, 0)
        e.give(1)

    e.if_(e.ne(p["nd_pk"], NONE), pack)

    # iinc: x = x +- c in one int local.
    def iinc_check():
        e.var("ii_a", canon(e, _operand(e, node, 0)))
        e.var("ii_c", canon(e, _operand(e, node, 1)))
        _width(e, result, "ii_w")
        e.var("ii_delta", e.sel(e.eq(opv, OP["ADD_WRAP"]), _v(e, V_CVAL, p["ii_c"]), e.sub(0, _v(e, V_CVAL, p["ii_c"]))))
        ok = e.both(e.eq(_sdesc(e, result), D_I), e.eq(p["ii_w"], 32), e.ne(_v(e, V_CONST, p["ii_c"]), 0), e.ne(_slot(e, result), SLOT_LATE),
                    e.eq(_slot(e, result), _slot(e, p["ii_a"])), _signed_small(e, p["ii_delta"]), e.ne(_m(e, C_PENDING), p["ii_a"]),
                    e.not_(e.both(e.eq(_m(e, M_PASS), 2), e.ne(_v(e, V_SINGLE, result), 0), e.eq(_v(e, V_IMPLICIT, result), 0))))

        def emit():
            _flush(e)
            _set_v(e, C_READS, p["ii_a"], e.add(_v(e, C_READS, p["ii_a"]), 1))
            e.var("ii_slot", _slot(e, result))
            e.if_(e.le(p["ii_slot"], 0xFF), lambda: opx(e, e.add(e.add(0x840000, e.mul(p["ii_slot"], 256)), e.and_(p["ii_delta"], 0xFF)), 3),
                  lambda: (op(e, 0xC4, 0x84), raw(e, e.add(e.mul(p["ii_slot"], 1 << 16), e.and_(p["ii_delta"], 0xFFFF)), 4)))
            e.give(1)

        e.if_(ok, emit)

    e.if_(_in(e, opv, (OP["ADD_WRAP"], OP["SUB_WRAP"])), iinc_check)

    def arithmetic():
        _width(e, result, "ar_w")
        e.var("ar_first", _operand(e, node, 0))
        e.var("ar_second", _operand(e, node, 1))
        e.if_(e.both(e.eq(_m(e, C_PENDING), p["ar_second"]), e.ne(opv, OP["SUB_WRAP"])), lambda: (
            e.var("ar_t", p["ar_first"]), e.set("ar_first", p["ar_second"]), e.set("ar_second", p["ar_t"])))
        e.var("ar_d", _desc_get(e, p["ar_first"]))
        wide = e.eq(p["ar_d"], D_J)
        _call(e, "jl_push", K_PUT, result, 0, 0, 0)
        e.if_(_in(e, opv, (OP["ADD_WRAP"], OP["SUB_WRAP"], OP["MUL_WRAP"])), lambda: _call(e, "jl_push", K_MASK, p["ar_d"], p["ar_w"], 0, 0))
        code = e.c(0)
        for opcode, (narrow, wide_op) in ARITH_OPCODE.items():
            code = e.sel(e.eq(opv, opcode), e.sel(wide, wide_op, narrow), code)
        _call(e, "jl_push", K_OP, code, 1, 0, 0)
        _call(e, "jl_push", K_GET, p["ar_second"], 0, 0, 0)
        _call(e, "jl_push", K_GET, p["ar_first"], 0, 0, 0)
        e.give(1)

    e.if_(_in(e, opv, tuple(ARITH_OPCODE)), arithmetic)

    def division():
        _width(e, result, "dv_w")
        e.var("dv_divide", e.flag(e.eq(opv, OP["UDIV"])))
        e.var("dv_y", _operand(e, node, 1))
        e.var("dv_x", _operand(e, node, 0))
        e.var("dv_c", e.sel(e.ne(_v(e, V_CONST, p["dv_y"]), 0), _v(e, V_CVAL, p["dv_y"]), 0))
        _call(e, "jl_push", K_PUT, result, 0, 0, 0)

        def power():
            e.var("dv_d", _desc_get(e, p["dv_x"]))
            e.var("dv_log", 0)
            e.while_(lambda: e.ne(_pow2(e, p["dv_log"]), p["dv_c"]), lambda: e.set("dv_log", e.add(p["dv_log"], 1)))
            e.if_(e.ne(p["dv_divide"], 0), lambda: (_call(e, "jl_push", K_OP, e.sel(e.eq(p["dv_d"], D_J), 0x7D, 0x7C), 1, 0, 0),
                                                     _call(e, "jl_push", K_ICONST, p["dv_log"], 0, 0, 0)),
                  lambda: (_call(e, "jl_push", K_OP, e.sel(e.eq(p["dv_d"], D_J), 0x7F, 0x7E), 1, 0, 0),
                           e.if_(e.eq(p["dv_d"], D_I), lambda: _call(e, "jl_push", K_ICONST, e.sub(p["dv_c"], 1), 0, 0, 0),
                                 lambda: _call(e, "jl_push", K_LCONST, e.sub(p["dv_c"], 1), 0, 0, 0))))
            _call(e, "jl_push", K_GET, p["dv_x"], 0, 0, 0)

        def wide64():
            _call(e, "jl_push", K_JAVA, e.sel(e.ne(p["dv_divide"], 0), J_LDIV, J_LREM), 0, 0, 0)
            _call(e, "jl_push", K_GET, p["dv_y"], 0, 0, 0)
            _call(e, "jl_push", K_GET, p["dv_x"], 0, 0, 0)

        def wide32():
            _call(e, "jl_push", K_OP, e.add(e.mul(e.sel(e.ne(p["dv_divide"], 0), 0x6D, 0x71), 256), 0x88), 2, 0, 0)
            _call(e, "jl_push", K_GETLONG, p["dv_y"], 32, 0, 0)
            _call(e, "jl_push", K_GETLONG, p["dv_x"], 32, 0, 0)

        def narrow():
            e.var("dv_d", _desc_get(e, p["dv_x"]))
            _call(e, "jl_push", K_OP, e.add(e.sel(e.ne(p["dv_divide"], 0), 0x6C, 0x70), e.flag(e.eq(p["dv_d"], D_J))), 1, 0, 0)
            _call(e, "jl_push", K_GET, p["dv_y"], 0, 0, 0)
            _call(e, "jl_push", K_GET, p["dv_x"], 0, 0, 0)

        e.if_(e.both(e.ne(p["dv_c"], 0), e.eq(e.and_(p["dv_c"], e.sub(p["dv_c"], 1)), 0)), power, lambda: e.if_(
            e.eq(p["dv_w"], 64), wide64, lambda: e.if_(e.eq(p["dv_w"], 32), wide32, narrow)))
        e.give(1)

    e.if_(_in(e, opv, (OP["UDIV"], OP["UREM"])), division)

    def rotate():
        _width(e, result, "rt_w")
        e.var("rt_amount", _attribute(e, node, 0))
        e.var("rt_x", _operand(e, node, 0))
        e.var("rt_src", _def(e, p["rt_x"]))
        e.var("rt_reader", sole_user(e, result))
        e.var("rt_long", e.flag(e.eq(p["rt_w"], 64)))
        e.var("rt_d", _desc_get(e, p["rt_x"]))
        e.var("rt_w3264", e.flag(_in(e, p["rt_w"], (32, 64))))
        e.var("rt_form", 0)  # 0 nothing, 1 shl, 2 ushr, 3 intrinsic, 4 the general form

        def shifts():
            e.var("rt_sw", 64)
            e.if_(e.ne(p["rt_src"], NONE), lambda: e.if_(e.eq(_eop(e, p["rt_src"]), OP["INT_ZERO_EXTEND"]), lambda: _width(e, _operand(e, p["rt_src"], 0), "rt_sw")))
            e.var("rt_rw", 64)
            e.if_(e.ne(p["rt_reader"], NONE), lambda: e.if_(e.eq(_eop(e, p["rt_reader"]), OP["INT_TRUNCATE"]), lambda: _width(e, _output(e, p["rt_reader"], 0), "rt_rw")))
            e.set("rt_form", 4)
            e.if_(e.ne(p["rt_w3264"], 0), lambda: e.set("rt_form", 3))
            e.if_(e.both(e.ne(p["rt_w3264"], 0), e.ne(p["rt_reader"], NONE), e.le(p["rt_rw"], e.sub(p["rt_w"], p["rt_amount"]))), lambda: e.if_(
                e.eq(_eop(e, e.sel(e.ne(p["rt_reader"], NONE), p["rt_reader"], node)), OP["INT_TRUNCATE"]), lambda: e.set("rt_form", 2)))
            e.if_(e.both(e.ne(p["rt_w3264"], 0), e.ne(p["rt_src"], NONE), e.le(p["rt_sw"], p["rt_amount"])), lambda: e.if_(
                e.eq(_eop(e, e.sel(e.ne(p["rt_src"], NONE), p["rt_src"], node)), OP["INT_ZERO_EXTEND"]), lambda: e.set("rt_form", 1)))

        e.if_(e.ne(p["rt_amount"], 0), shifts)
        _call(e, "jl_push", K_PUT, result, 0, 0, 0)
        e.if_(e.eq(p["rt_form"], 1), lambda: (_call(e, "jl_push", K_OP, e.sel(e.ne(p["rt_long"], 0), 0x79, 0x78), 1, 0, 0),
                                               _call(e, "jl_push", K_ICONST, e.sub(p["rt_w"], p["rt_amount"]), 0, 0, 0)))
        e.if_(e.eq(p["rt_form"], 2), lambda: (_call(e, "jl_push", K_OP, e.sel(e.ne(p["rt_long"], 0), 0x7D, 0x7C), 1, 0, 0),
                                               _call(e, "jl_push", K_ICONST, p["rt_amount"], 0, 0, 0)))
        e.if_(e.eq(p["rt_form"], 3), lambda: (_call(e, "jl_push", K_JAVA, e.sel(e.ne(p["rt_long"], 0), J_LROTR, J_IROTR), 0, 0, 0),
                                               _call(e, "jl_push", K_ICONST, p["rt_amount"], 0, 0, 0)))

        def general():
            e.var("rt_dl", e.flag(e.eq(p["rt_d"], D_J)))
            _call(e, "jl_push", K_MASK, p["rt_d"], p["rt_w"], 0, 0)
            _call(e, "jl_push", K_OP, e.sel(e.ne(p["rt_dl"], 0), 0x81, 0x80), 1, 0, 0)
            _call(e, "jl_push", K_OP, e.sel(e.ne(p["rt_dl"], 0), 0x79, 0x78), 1, 0, 0)
            _call(e, "jl_push", K_ICONST, e.sub(p["rt_w"], p["rt_amount"]), 0, 0, 0)
            _call(e, "jl_push", K_GET, p["rt_x"], 0, 0, 0)
            _call(e, "jl_push", K_OP, e.sel(e.ne(p["rt_dl"], 0), 0x7D, 0x7C), 1, 0, 0)
            _call(e, "jl_push", K_ICONST, p["rt_amount"], 0, 0, 0)

        e.if_(e.eq(p["rt_form"], 4), general)
        _call(e, "jl_push", K_GET, p["rt_x"], 0, 0, 0)
        e.give(1)

    e.if_(e.eq(opv, OP["ROTATE_RIGHT"]), rotate)

    def coalesced():
        e.if_(e.eq(_slot(e, _operand(e, node, 0)), _slot(e, result)), lambda: e.give(1))

    e.if_(copy_like(e, p["nd_b"], node), coalesced)

    def extension():
        _width(e, _operand(e, node, 0), "ex_sw")
        _width(e, result, "ex_dw")
        e.var("ex_x", _operand(e, node, 0))
        e.var("ex_sd", _desc_get(e, p["ex_x"]))
        e.var("ex_dd", _sdesc(e, result))
        _call(e, "jl_push", K_PUT, result, 0, 0, 0)
        e.var("ex_kw", e.sel(e.ne(_v(e, V_KW, p["ex_x"]), NONE), _v(e, V_KW, p["ex_x"]), 64))
        e.if_(e.both(e.eq(opv, OP["INT_TRUNCATE"]), e.lt(p["ex_dw"], p["ex_kw"])), lambda: _call(e, "jl_push", K_MASK, p["ex_dd"], p["ex_dw"], 0, 0))

        def widen():
            e.var("ex_reader", sole_user(e, result))
            e.var("ex_rot", 0)
            e.if_(e.ne(p["ex_reader"], NONE), lambda: e.if_(e.both(e.eq(_eop(e, p["ex_reader"]), OP["ROTATE_RIGHT"]), e.eq(_attribute(e, p["ex_reader"], 0), 32)),
                                                            lambda: (_width(e, _output(e, p["ex_reader"], 0), "ex_rw"), e.set("ex_rot", e.flag(e.eq(p["ex_rw"], 64))))))
            e.if_(e.ne(p["ex_rot"], 0), lambda: _call(e, "jl_push", K_OP, 0x85, 1, 0, 0), lambda: e.if_(
                e.eq(p["ex_sw"], 32), lambda: _call(e, "jl_push", K_JAVA, J_TOUNSIGNED, 0, 0, 0), lambda: _call(e, "jl_push", K_OP, 0x85, 1, 0, 0)))

        e.if_(e.both(e.eq(p["ex_sd"], D_J), e.eq(p["ex_dd"], D_I)), lambda: _call(e, "jl_push", K_OP, 0x88, 1, 0, 0), lambda: e.if_(
            e.both(e.eq(p["ex_sd"], D_I), e.eq(p["ex_dd"], D_J)), widen))
        _call(e, "jl_push", K_GET, p["ex_x"], 0, 0, 0)
        e.give(1)

    e.if_(_in(e, opv, (OP["INT_TRUNCATE"], OP["INT_ZERO_EXTEND"])), extension)
    _float_nodes(e, node, opv, result)
    e.if_(e.eq(opv, OP["CONSTANT"]), lambda: e.give(1))  # integer constants: every use rematerializes them

    def compare():
        e.if_(e.ne(_v(e, V_FUSED, result), 0), lambda: e.give(1))
        _call(e, "jl_push", K_PUT, result, 0, 0, 0)
        _relation_of(e, node, "cm_rel")

        def xor_form():
            e.if_(e.eq(p["cm_rel"], EQ_), lambda: (_call(e, "jl_push", K_OP, 0x82, 1, 0, 0), _call(e, "jl_push", K_ICONST, 1, 0, 0, 0)))
            _call(e, "jl_push", K_OP, 0x7C, 1, 0, 0)
            _call(e, "jl_push", K_ICONST, 31, 0, 0, 0)
            _call(e, "jl_push", K_OP, 0x82597480, 4, 0, 0)
            _call(e, "jl_push", K_GET, _operand(e, node, 1), 0, 0, 0)
            _call(e, "jl_push", K_GET, _operand(e, node, 0), 0, 0, 0)

        def long_form():
            # _compare_result after compare_to_int: both pushed in reverse.
            _compare_result_relation(e, node)

        e.if_(e.both(e.eq(p["cm_rel_fl"], 0), e.le(p["cm_rel"], NE_), e.eq(_sdesc(e, _operand(e, node, 0)), D_I)), xor_form, long_form)
        e.give(1)

    e.if_(_in(e, opv, (OP["INT_COMPARE"], OP["FLOAT_COMPARE"])), compare)

    def call():
        _callee_object(e, node, "cl_callee")
        _ok(e, e.ne(p["cl_callee"], NONE))
        e.if_(e.ne(_call(e, "erased", p["cl_callee"]), 0), lambda: e.give(1))
        e.var("cl_fidx", _callee_index(e, p["cl_callee"]))
        e.var("cl_nres", 0)
        e.var("cl_res", NONE)
        e.for_("cl_r", 0, _f(e, node, N_NRES), lambda: (e.var("cl_rv", _output(e, node, p["cl_r"])), e.if_(e.ne(_slot(e, p["cl_rv"]), NONE), lambda: (
            e.if_(e.eq(p["cl_res"], NONE), lambda: e.set("cl_res", p["cl_rv"])), e.set("cl_nres", e.add(p["cl_nres"], 1))))))
        _ok(e, e.le(p["cl_nres"], 1))  # JVM-SINGLE-RESULT: the bootstrap's
        e.var("cl_keep", e.flag(e.ne(p["cl_res"], NONE)))

        def keep():
            from xax_selfhost_jvm_method import V_NEEDED

            e.if_(e.ne(_v(e, V_NEEDED, p["cl_res"]), 0), lambda: _call(e, "jl_push", K_PUT, p["cl_res"], 0, 0, 0),
                  lambda: _call(e, "jl_push", K_OP, e.sel(e.eq(_pick_slots(e, _sdesc(e, p["cl_res"])), 2), 0x58, 0x57), 1, 0, 0))

        e.if_(e.ne(p["cl_keep"], 0), keep)
        _call(e, "jl_push", K_CALL, p["cl_fidx"], 0, 0, 0)
        # The machine operands, in the callee's order (one-slot values first unless the callee is the entry).
        e.var("cl_entry", e.flag(e.eq(p["cl_fidx"], _entry_index(e))))
        e.var("cl_slots", 0)
        for wide_pass in (1, 0):
            def push_operands(wide_pass=wide_pass):
                e.var("cl_k", _f(e, node, N_NOPS))

                def one():
                    e.set("cl_k", e.sub(p["cl_k"], 1))
                    e.var("cl_o", _operand(e, node, p["cl_k"]))
                    e.var("cl_od", _desc(e, p["cl_o"]))
                    two = e.eq(_pick_slots(e, p["cl_od"]), 2)
                    take = e.sel(e.ne(p["cl_entry"], 0), e.flag(e.eq(wide_pass, 0)), e.flag(e.eq(e.flag(two), wide_pass)))
                    e.if_(e.both(e.ne(p["cl_od"], D_NONE), e.ne(take, 0)), lambda: (
                        _call(e, "jl_push", K_GET, p["cl_o"], 0, 0, 0), e.set("cl_slots", e.add(p["cl_slots"], _pick_slots(e, p["cl_od"])))))

                e.while_(lambda: e.lt(0, p["cl_k"]), one)

            push_operands()
        e.if_(e.lt(_m(e, M_MAXCALL), p["cl_slots"]), lambda: _set_m(e, M_MAXCALL, p["cl_slots"]))
        e.give(1)

    e.if_(e.eq(opv, OP["CALL_DIRECT"]), call)
    _ok(e, _in(e, opv, tuple(sorted(int(op) for op in RESOURCE_EFFECT_OPERATIONS))))  # another: the bootstrap
    e.give(1)


FLOAT_ARITHMETIC = {OP["FLOAT_ADD"]: (0x62, 0x63), OP["FLOAT_SUB"]: (0x66, 0x67), OP["FLOAT_MUL"]: (0x6A, 0x6B), OP["FLOAT_DIV"]: (0x6E, 0x6F)}


def _pow2_bits(e: E, k, width, negative: bool):
    """The raw bits of ``(-)2**k`` as a binary32 (``width`` 32) or binary64."""
    single = e.add((1 << 31) if negative else 0, e.mul(e.add(127, k), 1 << 23))
    double = e.add((1 << 63) if negative else 0, e.mul(e.add(1023, k), 1 << 52))
    return e.sel(e.eq(width, 32), single, double)


def _float_nodes(e: E, node, opv, result):
    """The float lowerings: constants (raw bits), arithmetic, ``FLOAT_CONVERT``, integer to float (unsigned 64-bit
    values halve with a sticky bit, convert and double), and the trapping truncations (NaN and the range checks
    branch to the trap)."""
    p = e.p

    def constant():
        from xax_selfhost_jvm_method import _constant_value

        e.var("fk_d", _sdesc(e, result))

        def floating():
            _constant_value(e, node, "fk_v")
            Steps(e).add(K_FCONST, p["fk_v"], e.sel(e.eq(p["fk_d"], D_F), 32, 64)).add(K_PUT, result).push()
            e.give(1)

        e.if_(_in(e, p["fk_d"], (D_F, D_D)), floating)

    e.if_(e.eq(opv, OP["CONSTANT"]), constant)

    def arithmetic():
        e.var("fa_d", _desc_get(e, _operand(e, node, 0)))
        code = e.c(0)
        for opcode, (single, double) in FLOAT_ARITHMETIC.items():
            code = e.sel(e.eq(opv, opcode), e.sel(e.eq(p["fa_d"], D_D), double, single), code)
        Steps(e).add(K_GET, _operand(e, node, 0)).add(K_GET, _operand(e, node, 1)).add(K_OP, code, 1).add(K_PUT, result).push()
        e.give(1)

    e.if_(_in(e, opv, tuple(FLOAT_ARITHMETIC)), arithmetic)

    def convert():
        e.var("fv_s", _desc_get(e, _operand(e, node, 0)))
        e.var("fv_differ", e.flag(e.ne(p["fv_s"], _sdesc(e, result))))
        _call(e, "jl_push", K_PUT, result, 0, 0, 0)
        e.if_(e.ne(p["fv_differ"], 0), lambda: _call(e, "jl_push", K_OP, e.sel(e.eq(p["fv_s"], D_F), 0x8D, 0x90), 1, 0, 0))
        _call(e, "jl_push", K_GET, _operand(e, node, 0), 0, 0, 0)
        e.give(1)

    e.if_(e.eq(opv, OP["FLOAT_CONVERT"]), convert)

    def to_float():
        e.var("tf_x", _operand(e, node, 0))
        _width(e, p["tf_x"], "tf_w")
        e.var("tf_signed", e.flag(e.eq(opv, OP["SINT_TO_FLOAT"])))
        e.var("tf_f", e.flag(e.eq(_sdesc(e, result), D_F)))
        l2 = e.sel(e.ne(p["tf_f"], 0), 0x89, 0x8A)

        def halving():
            e.var("tf_neg", _fresh(e, "tf_ng"))
            e.var("tf_done", _fresh(e, "tf_dn"))
            x = p["tf_x"]
            Steps(e).add(K_GET, x).add(K_LCONST, 0).add(K_OP, 0x94, 1).add(K_BRANCH, 0x9B, p["tf_neg"]) \
                .add(K_GET, x).add(K_OP, l2, 1).add(K_PUT, result).add(K_BRANCH, GOTO, p["tf_done"]) \
                .add(K_MARK, p["tf_neg"]) \
                .add(K_GET, x).add(K_ICONST, 1).add(K_OP, 0x7D, 1).add(K_GET, x).add(K_LCONST, 1).add(K_OP, 0x7F81, 2) \
                .add(K_OP, l2, 1).add(K_OP, e.sel(e.ne(p["tf_f"], 0), 0x5962, 0x5C63), 2).add(K_PUT, result) \
                .add(K_MARK, p["tf_done"]).push()

        def direct():
            e.var("tf_long", e.flag(e.either(e.eq(_sdesc(e, p["tf_x"]), D_J), e.both(e.eq(p["tf_w"], 32), e.eq(p["tf_signed"], 0)))))
            _call(e, "jl_push", K_PUT, result, 0, 0, 0)
            e.if_(e.ne(p["tf_long"], 0), lambda: (
                _call(e, "jl_push", K_OP, l2, 1, 0, 0), _call(e, "jl_push", K_GETLONG, p["tf_x"], p["tf_w"], p["tf_signed"], 0)), lambda: (
                _call(e, "jl_push", K_OP, e.sel(e.ne(p["tf_f"], 0), 0x86, 0x87), 1, 0, 0),
                e.if_(e.both(e.ne(p["tf_signed"], 0), e.lt(p["tf_w"], 32)), lambda: (
                    Steps(e).add(K_ICONST, e.sub(32, p["tf_w"])).add(K_OP, 0x78, 1).add(K_ICONST, e.sub(32, p["tf_w"])).add(K_OP, 0x7A, 1).push())),
                _call(e, "jl_push", K_GET, p["tf_x"], 0, 0, 0)))

        e.if_(e.both(e.eq(p["tf_signed"], 0), e.eq(p["tf_w"], 64)), halving, direct)
        e.give(1)

    e.if_(_in(e, opv, (OP["UINT_TO_FLOAT"], OP["SINT_TO_FLOAT"])), to_float)

    def truncation():
        _set_m(e, M_TRAPUSED, 1)
        e.var("tr_x", _operand(e, node, 0))
        e.var("tr_s", _sdesc(e, p["tr_x"]))
        e.var("tr_sw", e.sel(e.eq(p["tr_s"], D_F), 32, 64))
        _width(e, result, "tr_w")
        e.var("tr_d", _sdesc(e, result))
        e.var("tr_signed", e.flag(e.eq(opv, OP["FLOAT_TO_SINT_TRUNC"])))
        e.var("tr_trap", _trap_label(e))
        x = p["tr_x"]
        cmpl = _float_cmp(e, p["tr_s"])
        to_long = e.sel(e.eq(p["tr_s"], D_F), 0x8C, 0x8F)
        to_int = e.sel(e.eq(p["tr_s"], D_F), 0x8B, 0x8E)

        def against(steps, bits, branch_op):
            steps.add(K_GET, x).add(K_FCONST, bits, p["tr_sw"]).add(K_OP, cmpl, 1).add(K_BRANCH, branch_op, p["tr_trap"])

        def signed():
            # v <= lower - 1 when that is exact in the source format, else v < lower; then v >= 2^(w-1).
            e.var("tr_mb", e.sel(e.eq(p["tr_sw"], 32), 23, 52))
            e.var("tr_exact", e.flag(e.le(p["tr_w"], e.add(p["tr_mb"], 1))))
            e.var("tr_lb", _pow2_bits(e, 1, p["tr_sw"], True))  # w = 1: lower - 1 = -2
            # -(2^(w-1) + 1): the exponent w - 1 and the lowest fraction bit at w - 1 (exact only).
            e.if_(e.both(e.lt(1, p["tr_w"]), e.ne(p["tr_exact"], 0)), lambda: e.set("tr_lb", e.add(
                _pow2_bits(e, e.sub(p["tr_w"], 1), p["tr_sw"], True), _pow2(e, e.sub(p["tr_mb"], e.sub(p["tr_w"], 1))))))
            e.var("tr_low", e.sel(e.ne(p["tr_exact"], 0), p["tr_lb"], _pow2_bits(e, e.sub(p["tr_w"], 1), p["tr_sw"], True)))
            steps = Steps(e).add(K_GET, x).add(K_GET, x).add(K_OP, cmpl, 1).add(K_BRANCH, 0x9A, p["tr_trap"])
            against(steps, p["tr_low"], e.sel(e.ne(p["tr_exact"], 0), 0x9E, 0x9B))
            against(steps, _pow2_bits(e, e.sub(p["tr_w"], 1), p["tr_sw"], False), 0x9C)
            steps.add(K_GET, x).add(K_OP, e.sel(e.eq(p["tr_d"], D_I), to_int, to_long), 1).add(K_MASK, p["tr_d"], p["tr_w"]).add(K_PUT, result).push()

        def unsigned():
            # The tail first (the task stack runs the last pushed first): then the NaN and range checks before it.
            def wide():
                e.var("tr_small", _fresh(e, "tr_sm"))
                e.var("tr_done", _fresh(e, "tr_dn"))
                top = _pow2_bits(e, 63, p["tr_sw"], False)
                Steps(e).add(K_GET, x).add(K_FCONST, top, p["tr_sw"]).add(K_OP, cmpl, 1).add(K_BRANCH, 0x9B, p["tr_small"]) \
                    .add(K_GET, x).add(K_FCONST, top, p["tr_sw"]).add(K_OP, e.add(e.mul(e.sel(e.eq(p["tr_s"], D_F), 0x66, 0x67), 256), to_long), 2) \
                    .add(K_LCONST, 1 << 63).add(K_OP, 0x83, 1).add(K_PUT, result).add(K_BRANCH, GOTO, p["tr_done"]) \
                    .add(K_MARK, p["tr_small"]).add(K_GET, x).add(K_OP, to_long, 1).add(K_PUT, result).add(K_MARK, p["tr_done"]).push()

            def narrow_int():
                Steps(e).add(K_GET, x).add(K_OP, e.sel(e.eq(p["tr_w"], 32), e.add(e.mul(to_long, 256), 0x88), to_int),
                                          e.sel(e.eq(p["tr_w"], 32), 2, 1)).add(K_PUT, result).push()

            e.if_(e.eq(p["tr_w"], 64), wide, lambda: e.if_(e.eq(p["tr_d"], D_I), narrow_int, lambda: Steps(e).add(K_GET, x).add(K_OP, to_long, 1).add(
                K_PUT, result).push()))
            steps = Steps(e).add(K_GET, x).add(K_GET, x).add(K_OP, cmpl, 1).add(K_BRANCH, 0x9A, p["tr_trap"])
            against(steps, 0, 0x9B)
            against(steps, _pow2_bits(e, p["tr_w"], p["tr_sw"], False), 0x9C)
            steps.push()

        e.if_(e.ne(p["tr_signed"], 0), signed, unsigned)
        e.give(1)

    e.if_(_in(e, opv, (OP["FLOAT_TO_UINT_TRUNC"], OP["FLOAT_TO_SINT_TRUNC"])), truncation)


def _compare_result_relation(e: E, node):
    """``relation = compare_to_int(node); _compare_result(relation)`` (pushed in reverse: the result first)."""
    _compare_result_pushes(e, _relation_of(e, node, "cq_r"))
    _compare_to_int(e, node, "cq")


def _callee_index(e: E, callee):
    """The callee's closure index (``G_CIDX``)."""
    from xax_selfhost_general_view import G_CIDX

    return e.ld(e.add(_g(e, G_CIDX), callee))


def _entry_index(e: E):
    from xax_selfhost_jvm import J_ENTRY_INDEX, _js

    return _js(e, J_ENTRY_INDEX)


def _jump_task(e: E, condition, when, label):
    """``jump_if``: an OR/AND tree of booleans short-circuits; a compare branches on its relation; else ``ifne``/
    ``ifeq``."""
    p = e.p
    e.var("jp_c", canon(e, condition))
    e.var("jp_when", when)
    e.var("jp_label", label)
    e.var("jp_n", e.sel(late(e, p["jp_c"]), _def(e, p["jp_c"]), NONE))
    e.var("jp_k", 0)  # 1 boolean tree, 2 compare, 0 plain
    e.var("jp_op", 0)
    e.var("jp_w", 0)

    def kind():
        e.var("jp_op", _eop(e, p["jp_n"]))
        _width(e, _output(e, p["jp_n"], 0), "jp_w")
        e.if_(e.both(_in(e, p["jp_op"], (OP["BIT_OR"], OP["BIT_AND"])), e.eq(p["jp_w"], 1)), lambda: e.set("jp_k", 1))
        e.if_(_in(e, p["jp_op"], (OP["INT_COMPARE"], OP["FLOAT_COMPARE"])), lambda: e.set("jp_k", 2))

    e.if_(e.ne(p["jp_n"], NONE), kind)

    def tree():
        e.var("jp_first", _operand(e, p["jp_n"], 0))
        e.var("jp_second", _operand(e, p["jp_n"], 1))
        e.var("jp_or", e.flag(e.eq(p["jp_op"], OP["BIT_OR"])))
        e.if_(e.eq(p["jp_or"], p["jp_when"]), lambda: (
            _call(e, "jl_push", K_JUMP, p["jp_second"], p["jp_when"], p["jp_label"], 0),
            _call(e, "jl_push", K_JUMP, p["jp_first"], p["jp_when"], p["jp_label"], 0)), lambda: (
            e.var("jp_skip", _fresh(e, "jp_s")),
            _call(e, "jl_push", K_MARK, p["jp_skip"], 0, 0, 0),
            _call(e, "jl_push", K_JUMP, p["jp_second"], p["jp_when"], p["jp_label"], 0),
            _call(e, "jl_push", K_JUMP, p["jp_first"], e.sub(1, p["jp_when"]), p["jp_skip"], 0)))

    def compare():
        # The branch first (pushed in reverse), its opcode decided by the compare's own steps.
        e.var("jp_at", _m(e, M_ONE))
        _call(e, "jl_push", K_BRANCH, 0, p["jp_label"], 0, 0)
        _int_branch_if_not(e, p["jp_n"], "jp_bin")

        def long_path():
            _compare_to_int(e, p["jp_n"], "jq")
            e.set("jp_bin", _pick(e, p["jq"], BRANCH_IF_NOT))

        e.if_(e.eq(p["jp_bin"], NONE), long_path)
        e.var("jp_op2", e.sel(e.ne(p["jp_when"], 0), _pick(e, p["jp_bin"], INVERSE), p["jp_bin"]))
        e.st(e.add(e.add(_stack(e), e.mul(p["jp_at"], 5)), 1), p["jp_op2"])

    def plain():
        _call(e, "jl_push", K_BRANCH, e.sel(e.ne(p["jp_when"], 0), 0x9A, 0x99), p["jp_label"], 0, 0)
        _call(e, "jl_push", K_GET, p["jp_c"], 0, 0, 0)

    e.if_(e.eq(p["jp_k"], 1), tree, lambda: e.if_(e.eq(p["jp_k"], 2), compare, plain))


def _run_fn(tables):
    """Run the task stack until it is empty."""
    def build(e: E):
        p = e.p

        def step():
            e.var("rn_top", e.sub(_m(e, M_ONE), 1))
            _set_m(e, M_ONE, p["rn_top"])
            e.var("rn_at", e.add(_stack(e), e.mul(p["rn_top"], TASK_W)))
            e.var("rn_kind", e.ld(p["rn_at"]))
            e.var("rn_a", e.ld(e.add(p["rn_at"], 1)))
            e.var("rn_b", e.ld(e.add(p["rn_at"], 2)))
            e.var("rn_c", e.ld(e.add(p["rn_at"], 3)))
            kind = p["rn_kind"]
            e.if_(e.eq(kind, K_GET), lambda: _call(e, "jl_get", p["rn_a"]))
            e.if_(e.eq(kind, K_NODE), lambda: _call(e, "jl_node", p["rn_a"]))
            e.if_(e.eq(kind, K_OP), lambda: opx(e, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_ICONST), lambda: iconst(e, p["rn_a"]))
            e.if_(e.eq(kind, K_LCONST), lambda: lconst(e, p["rn_a"]))
            e.if_(e.eq(kind, K_PUT), lambda: _put_task(e, p["rn_a"]))
            e.if_(e.eq(kind, K_MASK), lambda: _mask_task(e, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_CALL), lambda: _call(e, "jl_call", p["rn_a"]))
            e.if_(e.eq(kind, K_JAVA), lambda: _call(e, "jl_java", p["rn_a"]))
            e.if_(e.eq(kind, K_BRANCH), lambda: branch(e, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_MARK), lambda: mark(e, p["rn_a"]))
            e.if_(e.eq(kind, K_JUMP), lambda: _call(e, "jl_jump", p["rn_a"], p["rn_b"], p["rn_c"]))
            e.if_(e.eq(kind, K_STORE), lambda: local(e, True, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_GETLONG), lambda: _call(e, "jl_getlong", p["rn_a"], p["rn_b"], p["rn_c"]))
            e.if_(e.eq(kind, K_FCONST), lambda: fconst(e, p["rn_a"], p["rn_b"]))

        e.while_(lambda: e.lt(p["base"], _m(e, M_ONE)), step)
        e.give(1)
    return _function(("base",), build, tables)


def run(e: E, kind: int, a=0, b=0, c=0):
    """Push one task and run the stack down to where it was."""
    p = e.p
    e.var("ru_base", _m(e, M_ONE))
    _call(e, "jl_push", kind, a, b, c, 0)
    _call(e, "jl_run", p["ru_base"])


def _get_fn(tables):
    def build(e: E):
        _get_task(e, e.p["value"])
        e.give(1)
    return _function(("value",), build, tables)


def _node_fn(tables):
    def build(e: E):
        _node_task(e, e.p["node"])
        if e.p.block is not None:
            e.give(1)
    return _function(("node",), build, tables)


def _jump_fn(tables):
    def build(e: E):
        _jump_task(e, e.p["condition"], e.p["when"], e.p["label"])
        e.give(1)
    return _function(("condition", "when", "label"), build, tables)


def _getlong_fn(tables):
    def build(e: E):
        _get_long_task(e, e.p["value"], e.p["width"], e.p["signed"])
        e.give(1)
    return _function(("value", "width", "signed"), build, tables)


def _java_fn(tables):
    def build(e: E):
        _java_task(e, e.p["which"])
        e.give(1)
    return _function(("which",), build, tables)


def _call_method_fn(tables):
    """``invokestatic`` of closure function ``fidx``'s method (its name and descriptor from the class state)."""
    def build(e: E):
        p = e.p
        op(e, 0xB8)
        e.var("cm_i", _call(e, "jl_own_method", 1, p["fidx"]))
        raw(e, p["cm_i"], 2)
        e.give(1)
    return _function(("fidx",), build, tables)


def add_lower_functions(add, tables):
    for name, builder in (("jl_push", _push_fn), ("jl_get", _get_fn), ("jl_getlong", _getlong_fn), ("jl_java", _java_fn),
                          ("jl_call", _call_method_fn), ("jl_jump", _jump_fn), ("jl_node", _node_fn), ("jl_run", _run_fn)):
        add(name, builder(tables))
