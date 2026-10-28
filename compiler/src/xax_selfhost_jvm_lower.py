"""S15e.5 (ADR-327): the lowering of ``xax_jvm._compile_method_pass`` as XAX functions (stage S15e.5a).

``get``, ``put`` and ``lower_node`` call each other recursively in the bootstrap (an expression tree is lowered where
it is read; a short-circuit condition jumps through its operands).  Here they are tasks on an explicit stack
(``jl_run``): a task's expansion pushes its steps in reverse, and every condition that reads the deferred values is
evaluated when the task is reached, so the bytes and the pool entries come in the bootstrap's order.

Task kinds (``K_*``, five words each: kind and four arguments): ``GET`` a value; ``NODE`` lower a node; ``OP`` a few
constant bytes; ``ICONST``/``LCONST``; ``PUT`` a value; ``MASK`` (descriptor, width); ``CALL`` an internal method
(callee function); ``JAVA`` a fixed ``java.lang`` method or the shared ``xax$pk``; ``BRANCH`` (opcode, label);
``MARK`` (label); ``JUMP`` (condition, when, label); ``STORE`` (descriptor, slot); ``GETLONG`` (value, width, signed);
``FCONST`` (raw bits, width); ``FOREIGN`` (member record): a platform call's opcode and pool entry; ``CALLBACK`` (table index): ``new P(k)``; ``LOAD`` (descriptor, slot);
S15e.5g: ``FIELDM`` the ``M`` field; ``OWN`` (index) a generated memory member; ``BYTEM`` (load, maximum) a checked byte
member; ``STRING`` (text, length) ``ldc`` of a String.
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
(K_GET, K_NODE, K_OP, K_ICONST, K_LCONST, K_PUT, K_MASK, K_CALL, K_JAVA, K_BRANCH, K_MARK, K_JUMP, K_STORE, K_GETLONG, K_FCONST,
 K_FOREIGN, K_CALLBACK, K_LOAD, K_FIELDM, K_OWN, K_BYTEM, K_STRING, K_DISPATCH) = range(1, 24)
# The fixed methods a lowering calls (``K_JAVA``): owner, name, descriptor.
JAVA = (
    ("java/lang/Integer", "toUnsignedLong", "(I)J"),
    ("java/lang/Long", "divideUnsigned", "(JJ)J"),
    ("java/lang/Long", "remainderUnsigned", "(JJ)J"),
    ("java/lang/Long", "rotateRight", "(JI)J"),
    ("java/lang/Integer", "rotateRight", "(II)I"),
    (None, "xax$pk", "(II)J"),  # the class's own shared member
    ("java/lang/Float", "floatToRawIntBits", "(F)I"),
    ("java/lang/Double", "doubleToRawLongBits", "(D)J"),
    ("java/lang/Float", "intBitsToFloat", "(I)F"),
    ("java/lang/Double", "longBitsToDouble", "(J)D"),
    ("java/lang/System", "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V"),
    ("java/util/Arrays", "copyOfRange", "([JII)[J"),
    ("java/lang/Long", "compareUnsigned", "(JJ)I"),
    ("java/lang/String", "getBytes", "(II[BI)V"),  # invokevirtual (S15e.5g)
    ("java/util/Arrays", "fill", "([BIIB)V"),  # stack storage (S15e.5h)
)
J_TOUNSIGNED, J_LDIV, J_LREM, J_LROTR, J_IROTR, J_PK, J_F2I, J_D2L, J_I2F, J_L2D, J_ARRAYCOPY, J_COPYRANGE, J_COMPAREU, J_GETBYTES, J_FILL = range(15)
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
# ``_MAY_RAISE``.
MAY_RAISE = tuple(int(op) for op in (Operation.CALL_INDIRECT, Operation.SUM_GET, Operation.LINK_FOLLOW, Operation.CALL_DIRECT,
                                     Operation.CALL_FOREIGN, Operation.UDIV, Operation.UREM, Operation.LOAD_BITS_LE, Operation.STORE_BITS_LE,
                                     Operation.CHECKED_LOAD_BITS_LE, Operation.CHECKED_STORE_BITS_LE))
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


def _java_task(e: E, which, opcode=0):
    """``invokestatic`` (or ``opcode``) of a fixed method (its Methodref made now, as the bootstrap's ``pool.method``
    call is)."""
    from xax_selfhost_jvm_class import method_literal

    p = e.p
    e.var("jv_w", which)
    opx(e, e.sel(e.eq(opcode, 0), 0xB8, opcode), 1)
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

    def raises():
        from xax_selfhost_jvm_memory import freeing, static_bound

        # A checked access that cannot trap and the memory class's free (a constant) take no line (ADR-157).
        static_bound(e, node, "nd_sb")
        freeing(e, node, "nd_fr")
        e.if_(e.both(e.eq(p["nd_sb"], 0), e.eq(p["nd_fr"], 0)), line)

    e.if_(_in(e, opv, MAY_RAISE), raises)
    e.var("nd_r", _result0(e, node))
    result = p["nd_r"]
    r_ok = e.ne(result, NONE)
    e.if_(e.both(r_ok, e.ne(_v(e, V_FOLDED, e.sel(r_ok, result, 0)), 0)), lambda: e.give(1))

    def runs():
        from xax_selfhost_jvm_memory import run_head
        from xax_selfhost_jvm_method import N_INRUN, N_RUN

        e.var("nd_id", _node_id(e, p["nd_b"], node))
        e.if_(e.ne(_v(e, N_INRUN, p["nd_id"]), 0), lambda: e.give(1))  # stored by the first node of its string run
        e.if_(e.ne(_v(e, N_RUN, p["nd_id"]), 0), lambda: (run_head(e, node, p["nd_b"], _v(e, N_RUN, p["nd_id"])), e.give(1)))

    e.if_(e.eq(opv, OP["CHECKED_STORE_BITS_LE"]), runs)

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

    e.if_(e.both(copy_like(e, p["nd_b"], node), e.ne(opv, OP["HEAP_VIEW"])), coalesced)

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
        e.var("cl_el", _call(e, "borrowed", p["cl_callee"]))  # views given back (ADR-101): not machine results
        e.var("cl_nres", 0)
        e.var("cl_res", NONE)
        e.for_("cl_r", 0, _f(e, node, N_NRES), lambda: (e.var("cl_rv", _output(e, node, p["cl_r"])), e.if_(
            e.both(e.ne(_slot(e, p["cl_rv"]), NONE), e.eq(e.ld(e.add(p["cl_el"], p["cl_r"])), NONE)), lambda: (
                e.if_(e.eq(p["cl_res"], NONE), lambda: e.set("cl_res", p["cl_rv"])), e.set("cl_nres", e.add(p["cl_nres"], 1))))))
        _ok(e, e.le(p["cl_nres"], 1))  # JVM-SINGLE-RESULT: the bootstrap's

        def given_back():
            """A view given back that is read and lives in another local than the one passed: copied (in reverse)."""
            from xax_selfhost_jvm_method import V_NEEDED

            e.var("cl_g", _f(e, node, N_NRES))

            def one():
                e.set("cl_g", e.sub(p["cl_g"], 1))
                e.var("cl_gp", e.ld(e.add(p["cl_el"], p["cl_g"])))

                def check():
                    e.var("cl_gv", _output(e, node, p["cl_g"]))
                    e.var("cl_go", _operand(e, node, p["cl_gp"]))
                    e.if_(e.both(e.ne(_v(e, V_NEEDED, p["cl_gv"]), 0), e.ne(_slot(e, p["cl_gv"]), NONE), e.ne(_slot(e, p["cl_gv"]), _slot(e, p["cl_go"]))),
                          lambda: (_call(e, "jl_push", K_PUT, p["cl_gv"], 0, 0, 0), _call(e, "jl_push", K_GET, p["cl_go"], 0, 0, 0)))

                e.if_(e.ne(p["cl_gp"], NONE), check)

            e.while_(lambda: e.lt(0, p["cl_g"]), one)

        given_back()
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
    e.if_(e.eq(opv, OP["CALL_FOREIGN"]), lambda: _foreign_node(e, node))

    def address():
        # A callback (ADR-161): an instance of this class whose interface method calls the function; a plain code
        # address (a table index) belongs to the general profile (declined).
        from xax_selfhost_general_view import N_GRAPH, N_OPSAT
        from xax_selfhost_jvm_callback import table_index
        from xax_selfhost_jvm_code import D_REF
        from xax_selfhost_views_backend import _reference

        e.var("fa_fn", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
        _ok(e, e.ne(p["fa_fn"], NONE))
        # A plain code address: the function's table index (never 0), S15e.5h.
        e.if_(e.lt(_sdesc(e, result), D_REF), lambda: (Steps(e).add(K_ICONST, table_index(e, p["fa_fn"])).add(K_PUT, result).push(), e.give(1)))
        Steps(e).add(K_CALLBACK, table_index(e, p["fa_fn"])).add(K_PUT, result).push()
        e.give(1)

    e.if_(e.eq(opv, OP["FUNCTION_ADDRESS"]), address)
    _aggregate_nodes(e, node, opv, result)
    # The memory, general-profile and indirect-call lowerings are their own function (a graph's size, S15e.5j).
    e.if_(e.ne(_call(e, "jl_memnode", node), 0), lambda: e.give(1))
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


def _foreign_node(e: E, node):
    """A platform call (``jk_member``'s call kinds): each machine operand (narrowed to a ``B``/``C``/``S`` parameter),
    the opcode and its pool entry, a ``B``/``S`` result masked (the JVM returns those sign-extended), and the one
    machine result stored (``_store_call_result``)."""
    from xax_selfhost_general_view import N_GRAPH, N_OPSAT
    from xax_selfhost_jvm_foreign import MB_KIND, MB_NP, MB_PARAMS, MB_RES, MB_RESN, NARROW, OK_CALL, OK_NEW, PARAM_WORDS
    from xax_selfhost_views_backend import _reference

    p = e.p
    e.var("fn_c", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
    _ok(e, e.ne(p["fn_c"], NONE))
    e.var("fn_mb", _call(e, "jk_member", p["fn_c"]))
    mb = p["fn_mb"]

    def memory():
        _call(e, "jl_memcall", node, mb)
        e.give(1)

    from xax_selfhost_jvm_foreign import MB_MEMORY

    e.if_(e.ne(e.ld(e.add(mb, MB_MEMORY)), 0), memory)
    # The machine results with a local: at most one (JVM-SINGLE-RESULT on entity "call": declined).
    e.var("fn_nres", 0)
    e.var("fn_res", NONE)
    e.for_("fn_r", 0, _f(e, node, N_NRES), lambda: (e.var("fn_rv", _output(e, node, p["fn_r"])), e.if_(e.ne(_slot(e, p["fn_rv"]), NONE), lambda: (
        e.if_(e.eq(p["fn_res"], NONE), lambda: e.set("fn_res", p["fn_rv"])), e.set("fn_nres", e.add(p["fn_nres"], 1))))))
    _ok(e, e.le(p["fn_nres"], 1))

    def keep():
        # ``_store_call_result(..., keep)``: stored, or dropped when nothing reads it.
        from xax_selfhost_jvm_method import V_NEEDED

        e.if_(e.ne(_v(e, V_NEEDED, p["fn_res"]), 0), lambda: _call(e, "jl_push", K_PUT, p["fn_res"], 0, 0, 0),
              lambda: _call(e, "jl_push", K_OP, e.sel(e.eq(_pick_slots(e, _sdesc(e, p["fn_res"])), 2), 0x58, 0x57), 1, 0, 0))

    e.if_(e.ne(p["fn_res"], NONE), keep)
    e.var("fn_r0", e.ld(e.ld(e.add(mb, MB_RES))))
    e.if_(e.both(e.eq(e.ld(e.add(mb, MB_RESN)), 1), e.either(e.eq(p["fn_r0"], ord("B")), e.eq(p["fn_r0"], ord("S")))),
          lambda: _call(e, "jl_push", K_MASK, D_I, e.sel(e.eq(p["fn_r0"], ord("B")), 8, 16), 0, 0))
    _call(e, "jl_push", K_FOREIGN, mb, 0, 0, 0)
    e.var("fn_kind", e.ld(e.add(mb, MB_KIND)))
    # The machine operands in reverse (zip with the parameters: the arity matched); narrowed for a call or ``new``.
    e.var("fn_m", 0)
    e.for_("fn_k", 0, _f(e, node, N_NOPS), lambda: e.if_(e.ne(_desc(e, _operand(e, node, p["fn_k"])), D_NONE), lambda: e.set("fn_m", e.add(p["fn_m"], 1))))
    e.var("fn_k", _f(e, node, N_NOPS))
    e.var("fn_slots", e.sel(e.eq(p["fn_kind"], OK_CALL), 0, 2))

    def one():
        e.set("fn_k", e.sub(p["fn_k"], 1))
        e.var("fn_o", _operand(e, node, p["fn_k"]))

        def machine():
            e.set("fn_m", e.sub(p["fn_m"], 1))

            def paired():
                e.var("fn_pt", e.add(e.ld(e.add(mb, MB_PARAMS)), e.mul(p["fn_m"], PARAM_WORDS)))
                e.var("fn_pc", e.ld(e.ld(p["fn_pt"])))
                e.var("fn_narrow", 0)
                narrows = e.either(e.eq(p["fn_kind"], OK_CALL), e.eq(p["fn_kind"], OK_NEW))
                for ch, opcode in NARROW.items():
                    e.if_(e.both(narrows, e.eq(e.ld(e.add(p["fn_pt"], 1)), 1), e.eq(p["fn_pc"], ch)), lambda opcode=opcode: e.set("fn_narrow", opcode))
                e.if_(e.ne(p["fn_narrow"], 0), lambda: _call(e, "jl_push", K_OP, p["fn_narrow"], 1, 0, 0))
                _call(e, "jl_push", K_GET, p["fn_o"], 0, 0, 0)
                e.set("fn_slots", e.add(p["fn_slots"], _pick_slots(e, _desc_get(e, p["fn_o"]))))

            e.if_(e.lt(p["fn_m"], e.ld(e.add(mb, MB_NP))), paired)

        e.if_(e.ne(_desc(e, p["fn_o"]), D_NONE), machine)

    e.while_(lambda: e.lt(0, p["fn_k"]), one)
    e.if_(e.eq(p["fn_kind"], OK_NEW), lambda: _call(e, "jl_push", K_FOREIGN, mb, 1, 0, 0))  # new; dup
    e.if_(e.lt(_m(e, M_MAXCALL), p["fn_slots"]), lambda: _set_m(e, M_MAXCALL, p["fn_slots"]))
    e.give(1)


class Reverse:
    """Tasks pushed now, run last pushed first: a lowering written back to front."""

    def __init__(self, e: E):
        self.e = e

    def __call__(self, kind: int, *arguments):
        words = list(arguments) + [0] * (4 - len(arguments))
        _call(self.e, "jl_push", kind, *words)


def _to_long(e: E, push, d):
    """``to_long`` (pushed in reverse): the raw bits of the scalar on the stack as a long."""
    e.if_(e.eq(d, D_I), lambda: push(K_OP, 0x85, 1))
    e.if_(e.eq(d, D_F), lambda: (push(K_OP, 0x85, 1), push(K_JAVA, J_F2I)))
    e.if_(e.eq(d, D_D), lambda: push(K_JAVA, J_D2L))


def _from_long(e: E, push, d):
    """``from_long`` (pushed in reverse)."""
    e.if_(e.eq(d, D_I), lambda: push(K_OP, 0x88, 1))
    e.if_(e.eq(d, D_F), lambda: (push(K_JAVA, J_I2F), push(K_OP, 0x88, 1)))
    e.if_(e.eq(d, D_D), lambda: push(K_JAVA, J_L2D))


def _aggregate_nodes(e: E, node, opv, result):
    """``AGGREGATE_MAKE``, ``SUM_MAKE``, ``AGGREGATE_GET``, ``SUM_TAG``, ``SUM_GET`` (ADR-159), pushed in reverse."""
    from xax_selfhost_jvm_aggregate import flat_code, flat_size
    from xax_selfhost_jvm_emit import _scratch_slot
    from xax_selfhost_jvm_method import _type
    from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb, _reference, _type_form

    p = e.p
    push = Reverse(e)

    def flat():
        return flat_code(e, "ag_flat")

    def store_field(buf, offset, value):
        """``store_field`` (in reverse): a nested value's ``System.arraycopy``, else ``lastore`` of the raw bits."""
        e.var("sf_v", value)
        e.var("sf_off", offset)
        e.var("sf_d", _desc(e, p["sf_v"]))
        e.var("sf_fl", flat())

        def nested():
            push(K_JAVA, J_ARRAYCOPY)
            push(K_ICONST, flat_size(e, _type(e, p["sf_v"])))
            push(K_ICONST, p["sf_off"])
            push(K_LOAD, p["sf_fl"], buf)
            push(K_ICONST, 0)
            push(K_GET, p["sf_v"])

        def scalar():
            push(K_OP, 0x50, 1)
            _to_long(e, push, p["sf_d"])
            push(K_GET, p["sf_v"])
            push(K_ICONST, p["sf_off"])
            push(K_LOAD, p["sf_fl"], buf)

        e.if_(e.ne(p["sf_d"], D_NONE), lambda: e.if_(e.eq(p["sf_d"], p["sf_fl"]), nested, scalar))

    def make():
        e.var("mk_fl", flat())
        _scratch_slot(e, p["mk_fl"], "mk_buf")
        push(K_PUT, result)
        push(K_LOAD, p["mk_fl"], p["mk_buf"])

        def sum_make():
            store_field(p["mk_buf"], 1, _operand(e, node, 0))
            push(K_OP, 0x50, 1)
            push(K_LCONST, _attribute(e, node, 0))
            push(K_ICONST, 0)
            push(K_LOAD, p["mk_fl"], p["mk_buf"])

        def aggregate_make():
            # The fields' offsets first (forwards), then each field's steps (backwards).
            e.var("mk_n", _f(e, node, N_NOPS))
            e.var("mk_offs", e.alloc(e.add(p["mk_n"], 1)))
            _ok(e, e.ne(p["mk_offs"], NONE))
            e.var("mk_off", 0)
            e.for_("mk_k", 0, p["mk_n"], lambda: (e.st(e.add(p["mk_offs"], p["mk_k"]), p["mk_off"]),
                                                  e.set("mk_off", e.add(p["mk_off"], flat_size(e, _type(e, _operand(e, node, p["mk_k"])))))))
            e.var("mk_k2", p["mk_n"])
            e.while_(lambda: e.lt(0, p["mk_k2"]), lambda: (e.set("mk_k2", e.sub(p["mk_k2"], 1)),
                                                           store_field(p["mk_buf"], e.ld(e.add(p["mk_offs"], p["mk_k2"])), _operand(e, node, p["mk_k2"]))))

        e.if_(e.eq(opv, OP["SUM_MAKE"]), sum_make, aggregate_make)
        push(K_STORE, p["mk_fl"], p["mk_buf"])
        push(K_OP, 0xBC0B, 2)  # newarray long
        push(K_ICONST, flat_size(e, _type(e, result)))
        e.give(1)

    e.if_(_in(e, opv, (OP["AGGREGATE_MAKE"], OP["SUM_MAKE"])), make)

    def load_field(source, offset, t):
        """``load_field`` (in reverse): ``Arrays.copyOfRange`` of a nested value, else ``laload`` and ``from_long``."""
        e.var("lf_s", source)
        e.var("lf_off", offset)
        e.var("lf_d", _desc(e, result))

        def nested():
            push(K_JAVA, J_COPYRANGE)
            push(K_ICONST, e.add(p["lf_off"], flat_size(e, t)))
            push(K_ICONST, p["lf_off"])

        def scalar():
            _from_long(e, push, p["lf_d"])
            push(K_OP, 0x2F, 1)
            push(K_ICONST, p["lf_off"])

        e.if_(e.eq(p["lf_d"], flat()), nested, scalar)
        push(K_GET, p["lf_s"])

    def get():
        # The fields: a tuple's elements, an array's element repeated; the offset of field ``attribute``.
        e.var("gt_t", _type(e, _operand(e, node, 0)))
        e.var("gt_form", _type_form(e, p["gt_t"]))
        e.var("gt_at", e.add(_at(e, G_PAY, p["gt_t"]), 1))
        e.var("gt_index", _attribute(e, node, 0))
        e.var("gt_off", 0)

        def tuple_():
            e.var("gt_n", _payload_uleb(e, "gt_at"))
            e.for_("gt_k", 0, p["gt_n"], lambda: (e.var("gt_el", _reference(e, p["gt_t"], _payload_uleb(e, "gt_at"))), e.if_(
                e.lt(p["gt_k"], p["gt_index"]), lambda: e.set("gt_off", e.add(p["gt_off"], flat_size(e, p["gt_el"]))))))

        def array():
            e.var("gt_el", _reference(e, p["gt_t"], _payload_uleb(e, "gt_at")))
            e.set("gt_off", e.mul(p["gt_index"], flat_size(e, p["gt_el"])))

        e.if_(e.eq(p["gt_form"], 8), tuple_, lambda: (_ok(e, e.eq(p["gt_form"], 9)), array()))
        push(K_PUT, result)
        load_field(_operand(e, node, 0), p["gt_off"], _type(e, result))
        e.give(1)

    e.if_(e.eq(opv, OP["AGGREGATE_GET"]), get)

    def tag():
        push(K_PUT, result)
        e.if_(e.eq(_sdesc(e, result), D_I), lambda: push(K_OP, 0x88, 1))
        push(K_OP, 0x2F, 1)
        push(K_ICONST, 0)
        push(K_GET, _operand(e, node, 0))
        e.give(1)

    e.if_(e.eq(opv, OP["SUM_TAG"]), tag)

    def variant():
        _set_m(e, M_TRAPUSED, 1)
        push(K_PUT, result)
        load_field(_operand(e, node, 0), 1, _type(e, result))
        push(K_BRANCH, 0xA0, _trap_label(e))
        push(K_ICONST, _attribute(e, node, 0))
        push(K_OP, 0x2F88, 2)
        push(K_ICONST, 0)
        push(K_GET, _operand(e, node, 0))
        e.give(1)

    e.if_(e.eq(opv, OP["SUM_GET"]), variant)


def _callback_task(e: E, index):
    """``new P; dup; iconst k; invokespecial P.<init>(I)V``."""
    from xax_selfhost_jvm import J_CLASSNAME
    from xax_selfhost_jvm_class import utf8_literal
    from xax_selfhost_jvm_foreign import _js

    p = e.p
    e.var("ck_k", index)
    pool = _m(e, C_POOL)
    op(e, 0xBB)
    raw(e, _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)), 2)
    op(e, 0x59)
    iconst(e, p["ck_k"])
    op(e, 0xB7)
    e.var("ck_cls", _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)))
    e.var("ck_nt", _call(e, "jp_ref2", pool, 12, utf8_literal(e, pool, "<init>", "ck_in"), utf8_literal(e, pool, "(I)V", "ck_id"), 0, 0))
    raw(e, _call(e, "jp_ref2", pool, 10, p["ck_cls"], p["ck_nt"], 1, 0), 2)


def _foreign_task(e: E, mb, phase):
    """A platform member's instructions (``phase`` 1: ``new``'s ``new``/``dup`` before its operands).  A call: the
    opcode, then (as ``lookup(class, name, descriptor)`` after ``code.op``) the Fieldref, Methodref or
    InterfaceMethodref, and ``invokeinterface``'s count and zero; an object kind: its instruction and Class, Methodref,
    Fieldref or String entry (``_object_member``'s lowering)."""
    from xax_selfhost_jvm_foreign import (
        ARRAY_LOAD, FIELD_OPS, MB_ARGS, MB_CLS, MB_CLSN, MB_DESC, MB_DESCN, MB_FSIZE, MB_IFACE, MB_KIND, MB_NAME, MB_NAMEN, MB_NP, MB_OP,
        MB_RES, MB_RESN, MB_RSLOTS, NEWARRAY_TYPE, OK_ALEN, OK_ALOAD, OK_ASTORE, OK_CALL, OK_CHECKCAST, OK_INSTANCEOF, OK_LDC, OK_MULTI,
        OK_NEW, OK_NEWARRAY,
    )

    p = e.p
    e.var("ft_mb", mb)
    e.var("ft_phase", phase)

    def f(k):
        return e.ld(e.add(p["ft_mb"], k))

    pool = _m(e, C_POOL)
    e.var("ft_kind", f(MB_KIND))

    def utf8(text, n):
        return _call(e, "jp_utf8", pool, text, n)

    def klass(text, n):
        return _call(e, "jp_ref1", pool, 7, utf8(text, n))

    def ref(tag, cls_text, cls_n, name_text, name_n, desc_text, desc_n, args, result):
        e.var("ft_cls", klass(cls_text, cls_n))
        e.var("ft_nt", _call(e, "jp_ref2", pool, 12, utf8(name_text, name_n), utf8(desc_text, desc_n), 0, 0))
        return _call(e, "jp_ref2", pool, tag, p["ft_cls"], p["ft_nt"], args, result)

    def head():
        op(e, 0xBB)
        raw(e, klass(f(MB_CLS), f(MB_CLSN)), 2)
        op(e, 0x59)

    def call():
        e.var("ft_op", f(MB_OP))
        opx(e, p["ft_op"], 1)
        e.var("ft_tag", e.sel(e.eq(p["ft_op"], 0xB2), 9, e.sel(e.ne(f(MB_IFACE), 0), 11, 10)))
        e.var("ft_ix", ref(p["ft_tag"], f(MB_CLS), f(MB_CLSN), f(MB_NAME), f(MB_NAMEN), f(MB_DESC), f(MB_DESCN),
                           e.sel(e.eq(p["ft_op"], 0xB2), 0, f(MB_ARGS)), e.sel(e.eq(p["ft_op"], 0xB2), f(MB_FSIZE), f(MB_RSLOTS))))
        raw(e, p["ft_ix"], 2)
        e.if_(e.eq(p["ft_op"], 0xB9), lambda: raw(e, e.mul(e.add(f(MB_ARGS), 1), 256), 2))

    def new():
        op(e, 0xB7)
        e.var("ft_init", ref(10, f(MB_CLS), f(MB_CLSN), f(MB_NAME), f(MB_NAMEN), f(MB_DESC), f(MB_DESCN), f(MB_ARGS), 0))
        raw(e, p["ft_init"], 2)

    def single(text, n, table: dict, default):
        """``table[text]`` for a one-character text, else ``default``."""
        e.var("ft_c", e.sel(e.eq(n, 1), e.ld(text), 0))
        return _pick(e, p["ft_c"], table, default)

    def new_array():
        e.var("ft_t", single(f(MB_CLS), f(MB_CLSN), NEWARRAY_TYPE, 0))

        def objects():
            # ``element[1:-1]`` for a class descriptor, else the array descriptor itself.
            e.var("ft_l", e.flag(e.eq(e.ld(f(MB_CLS)), ord("L"))))
            op(e, 0xBD)
            raw(e, klass(e.add(f(MB_CLS), p["ft_l"]), e.sub(f(MB_CLSN), e.mul(p["ft_l"], 2))), 2)

        e.if_(e.ne(p["ft_t"], 0), lambda: opx(e, e.add(0xBC00, p["ft_t"]), 2), objects)

    def multi():
        op(e, 0xC5)
        raw(e, klass(f(MB_CLS), f(MB_CLSN)), 2)
        opx(e, f(MB_NP), 1)

    def array_access():
        e.var("ft_load", single(e.add(f(MB_CLS), 1), e.sub(f(MB_CLSN), 1), ARRAY_LOAD, 0x32))
        opx(e, e.add(p["ft_load"], e.sel(e.eq(p["ft_kind"], OK_ASTORE), 0x21, 0)), 1)

    def ldc():
        _call(e, "jc_ldc", _call(e, "jp_ref1", pool, 8, utf8(f(MB_NAME), f(MB_NAMEN))))

    def field():
        opx(e, _pick(e, p["ft_kind"], FIELD_OPS), 1)
        raw(e, ref(9, f(MB_CLS), f(MB_CLSN), f(MB_NAME), f(MB_NAMEN), f(MB_DESC), f(MB_DESCN), 0, f(MB_FSIZE)), 2)

    def type_check():
        e.var("ft_res", f(MB_RES))
        e.var("ft_resn", f(MB_RESN))
        e.var("ft_l2", e.flag(e.both(e.eq(p["ft_kind"], OK_CHECKCAST), e.eq(e.ld(p["ft_res"]), ord("L")))))
        opx(e, e.sel(e.eq(p["ft_kind"], OK_CHECKCAST), 0xC0, 0xC1), 1)
        # instanceof names the class itself; checkcast its result descriptor (``result[1:-1]`` for a class).
        e.if_(e.eq(p["ft_kind"], OK_INSTANCEOF), lambda: raw(e, klass(f(MB_CLS), f(MB_CLSN)), 2), lambda: raw(
            e, klass(e.add(p["ft_res"], p["ft_l2"]), e.sub(p["ft_resn"], e.mul(p["ft_l2"], 2))), 2))

    def tail():
        k = p["ft_kind"]
        e.if_(e.eq(k, OK_CALL), call)
        e.if_(e.eq(k, OK_NEW), new)
        e.if_(e.eq(k, OK_NEWARRAY), new_array)
        e.if_(e.eq(k, OK_MULTI), multi)
        e.if_(e.either(e.eq(k, OK_ALOAD), e.eq(k, OK_ASTORE)), array_access)
        e.if_(e.eq(k, OK_ALEN), lambda: op(e, 0xBE))
        e.if_(e.eq(k, OK_LDC), ldc)
        e.if_(_in(e, k, tuple(FIELD_OPS)), field)
        e.if_(e.either(e.eq(k, OK_CHECKCAST), e.eq(k, OK_INSTANCEOF)), type_check)

    e.if_(e.ne(p["ft_phase"], 0), head, tail)


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
            e.if_(e.eq(kind, K_JAVA), lambda: _call(e, "jl_java", p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_BRANCH), lambda: branch(e, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_MARK), lambda: mark(e, p["rn_a"]))
            e.if_(e.eq(kind, K_JUMP), lambda: _call(e, "jl_jump", p["rn_a"], p["rn_b"], p["rn_c"]))
            e.if_(e.eq(kind, K_STORE), lambda: local(e, True, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_GETLONG), lambda: _call(e, "jl_getlong", p["rn_a"], p["rn_b"], p["rn_c"]))
            e.if_(e.eq(kind, K_FCONST), lambda: fconst(e, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_FOREIGN), lambda: _foreign_task(e, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_CALLBACK), lambda: _callback_task(e, p["rn_a"]))
            e.if_(e.eq(kind, K_LOAD), lambda: local(e, False, p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_FIELDM), lambda: _field_m_task(e))
            e.if_(e.eq(kind, K_DISPATCH), lambda: _call(e, "jl_dispatch", p["rn_a"]))
            e.if_(e.eq(kind, K_OWN), lambda: _call(e, "jl_own", p["rn_a"]))
            e.if_(e.eq(kind, K_BYTEM), lambda: _call(e, "jl_bytem", p["rn_a"], p["rn_b"]))
            e.if_(e.eq(kind, K_STRING), lambda: _call(e, "jc_ldc", _call(e, "jp_ref1", _m(e, C_POOL), 8, _call(e, "jp_utf8", _m(e, C_POOL), p["rn_a"], p["rn_b"]))))

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
        _java_task(e, e.p["which"], e.p["opcode"])
        e.give(1)
    return _function(("which", "opcode"), build, tables)


def _own_ref(e: E, name, name_n, descriptor, descriptor_n, args, result):
    """``pool.method(class_name, name, descriptor)``: the class, the name and descriptor, the Methodref."""
    from xax_selfhost_jvm import J_CLASSNAME
    from xax_selfhost_jvm_foreign import _js

    p = e.p
    pool = _m(e, C_POOL)
    e.var("or_c", _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)))
    e.var("or_n", _call(e, "jp_utf8", pool, name, name_n))
    e.var("or_d", _call(e, "jp_utf8", pool, descriptor, descriptor_n))
    e.var("or_nt", _call(e, "jp_ref2", pool, 12, p["or_n"], p["or_d"], 0, 0))
    return _call(e, "jp_ref2", pool, 10, p["or_c"], p["or_nt"], args, result)


def _own_fn(tables):
    """``invokestatic`` of a generated memory member (``OWN``)."""
    from xax_selfhost_jvm_class import literal
    from xax_selfhost_jvm_memory import OWN, descriptor_slots

    def build(e: E):
        p = e.p
        op(e, 0xB8)
        for k, (name, descriptor) in enumerate(OWN):
            def one(name=name, descriptor=descriptor):
                literal(e, "ow_n", name)
                literal(e, "ow_d", descriptor)
                args, result = descriptor_slots(descriptor)
                e.var("ow_i", _own_ref(e, p["ow_n"], len(name), p["ow_d"], len(descriptor), args, result))
                raw(e, p["ow_i"], 2)

            e.if_(e.eq(p["which"], k), one)
        e.give(1)
    return _function(("which",), build, tables)


def _byte_member_fn(tables):
    """``invokestatic xax$l<max>(II)I`` (``load``) or ``xax$s<max>(III)V``."""
    from xax_selfhost_jvm_class import literal
    from xax_selfhost_jvm_memory import hex_text

    def build(e: E):
        p = e.p
        op(e, 0xB8)
        hex_text(e, p["maximum"], "bm_h")
        e.var("bm_name", e.alloc(e.add(p["bm_h_n"], 6)))
        _ok(e, e.ne(p["bm_name"], NONE))
        for k, ch in enumerate(b"xax$"):
            e.st(e.add(p["bm_name"], k), ch)
        e.st(e.add(p["bm_name"], 4), e.sel(e.ne(p["load"], 0), ord("l"), ord("s")))
        e.for_("bm_k", 0, p["bm_h_n"], lambda: e.st(e.add(p["bm_name"], e.add(5, p["bm_k"])), e.ld(e.add(p["bm_h"], p["bm_k"]))))
        literal(e, "bm_dl", "(II)I")
        literal(e, "bm_ds", "(III)V")
        load = e.ne(p["load"], 0)
        e.var("bm_i", _own_ref(e, p["bm_name"], e.add(p["bm_h_n"], 5), e.sel(load, p["bm_dl"], p["bm_ds"]), e.sel(load, 5, 6),
                                e.sel(load, 2, 3), e.sel(load, 1, 0)))
        raw(e, p["bm_i"], 2)
        e.give(1)
    return _function(("load", "maximum"), build, tables)


def _field_s(e: E, opcode: int):
    """``getstatic``/``putstatic S`` (the shadow stack's top, ADR-159)."""
    from xax_selfhost_jvm import J_CLASSNAME
    from xax_selfhost_jvm_class import utf8_literal
    from xax_selfhost_jvm_foreign import _js

    p = e.p
    pool = _m(e, C_POOL)
    op(e, opcode)
    e.var("fs_c", _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)))
    e.var("fs_nt", _call(e, "jp_ref2", pool, 12, utf8_literal(e, pool, "S", "fs_sn"), utf8_literal(e, pool, "I", "fs_sd"), 0, 0))
    raw(e, _call(e, "jp_ref2", pool, 9, p["fs_c"], p["fs_nt"], 0, 1), 2)


def _field_m_task(e: E):
    """``getstatic M`` (``memory_field``)."""
    from xax_selfhost_jvm import J_CLASSNAME
    from xax_selfhost_jvm_class import utf8_literal
    from xax_selfhost_jvm_foreign import _js

    p = e.p
    pool = _m(e, C_POOL)
    op(e, 0xB2)
    e.var("fm_c", _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21)))
    e.var("fm_nt", _call(e, "jp_ref2", pool, 12, utf8_literal(e, pool, "M", "fm_mn"), utf8_literal(e, pool, "[B", "fm_md"), 0, 0))
    raw(e, _call(e, "jp_ref2", pool, 9, p["fm_c"], p["fm_nt"], 0, 1), 2)


def _call_method_fn(tables):
    """``invokestatic`` of closure function ``fidx``'s method (its name and descriptor from the class state)."""
    def build(e: E):
        p = e.p
        op(e, 0xB8)
        e.var("cm_i", _call(e, "jl_own_method", 1, p["fidx"]))
        raw(e, p["cm_i"], 2)
        e.give(1)
    return _function(("fidx",), build, tables)


def _memory_node_fn(tables):
    """1 when ``node`` is a memory, general-profile or indirect-call operation (its steps pushed), else 0."""
    def build(e: E):
        from xax_selfhost_jvm_memory import general_nodes, memory_nodes

        p = e.p
        e.var("mn_op", _eop(e, p["node"]))
        e.var("mn_r", _result0(e, p["node"]))
        memory_nodes(e, p["node"], p["mn_op"], p["mn_r"])
        general_nodes(e, p["node"], p["mn_op"], p["mn_r"])

        def indirect():
            from xax_selfhost_jvm_indirect import indirect_node

            indirect_node(e, p["node"])
            e.give(1)

        e.if_(e.eq(p["mn_op"], int(Operation.CALL_INDIRECT)), indirect)
        e.give(0)
    return _function(("node",), build, tables)


def _memory_call_fn(tables):
    def build(e: E):
        from xax_selfhost_jvm_memory import member_key, memory_call

        memory_call(e, e.p["node"], e.p["mb"], member_key(e, e.p["mb"]))
    return _function(("node", "mb"), build, tables)


def add_lower_functions(add, tables):
    for name, builder in (("jl_push", _push_fn), ("jl_get", _get_fn), ("jl_getlong", _getlong_fn), ("jl_java", _java_fn), ("jl_own", _own_fn),
                          ("jl_memnode", _memory_node_fn), ("jl_memcall", _memory_call_fn),
                          ("jl_bytem", _byte_member_fn),
                          ("jl_call", _call_method_fn), ("jl_jump", _jump_fn), ("jl_node", _node_fn), ("jl_run", _run_fn)):
        add(name, builder(tables))
