"""S15e.5g (ADR-336): the memory profile in the XAX JVM program (``jvm-classfile-memory-v1``, ADR-156).

The memory operations' lowering (``_compile_method_pass``: heap views, address offsets, pointer casts, addresses and
rebases, little-endian loads and stores, the ``xax/jvm/Memory`` members, the constant byte runs), the members a class
then needs (``_memory_methods``: ``<clinit>``, ``xax$alloc``, the checked byte members, ``xax$ix``, the loads and
stores, ``free``/``read``/``write``) and its ``M``/``H`` fields.

The generated members are fixed bytecode around constant-pool entries.  Their templates are made at build time by
running ``xax_jvm._memory_methods`` itself against a recording pool: every pool call (in call order, each member's
own) and every code position that holds a pool index are kept, with the members' branch offsets, frames and frame
locals.  The XAX program makes the same pool entries in the same order and writes the template's bytes, so a member
cannot drift from the bootstrap's.  Two values vary per class: ``<clinit>``'s initial memory size and a checked byte
member's bound (its name and its ``Integer`` constant); the templates carry sentinels for them.
"""

from __future__ import annotations

import struct

CLASS = "xax/P\x00class"  # the generated class (its name is the program's: ``J_CLASSNAME``)
INITIAL_SENTINEL = 0x5A5A5A5A  # ``<clinit>``'s ``int_const(initial)`` (> 127: always ``ldc_w``)
BOUND_SENTINEL = 0x123456  # a checked byte member's maximum (``maximum ^ 2^31``: always ``ldc_w``)

# The needs a class records (``needs`` in the bootstrap), as bits; the checked byte members are a list.
(N_MEMORY, N_LD1, N_LD2, N_LD4, N_LD8, N_ST2, N_ST4, N_ST8, N_IX, N_ALLOC, N_FREE, N_READ, N_WRITE, N_STACK) = (1 << k for k in range(14))
MEMBER_NEEDS = {"alloc(J)I": N_ALLOC, "free(I)J": N_FREE, "read(IIJ)J": N_READ, "write(IIJ)J": N_WRITE}
MEMBER_NAMES = {"alloc(J)I": "xax$alloc", "free(I)J": "xax$free", "read(IIJ)J": "xax$read", "write(IIJ)J": "xax$write"}
# The member templates in the bootstrap's order, each with the need that asks for it.
ORDER = (("<clinit>", N_MEMORY), ("xax$alloc", N_ALLOC), ("xax$ld1", N_LD1), ("bl", 0), ("bs", 0), ("xax$ix", N_IX), ("xax$free", N_FREE),
         ("xax$read", N_READ), ("xax$write", N_WRITE), ("xax$ld2", N_LD2), ("xax$st2", N_ST2), ("xax$ld4", N_LD4), ("xax$st4", N_ST4),
         ("xax$ld8", N_LD8), ("xax$st8", N_ST8))


class _Placeholder(int):
    """A pool call's result: the index the XAX program computes (``seq`` is the call's order)."""

    def __new__(cls, seq: int, call: tuple):
        value = int.__new__(cls, 0)
        value.seq, value.call = seq, call
        return value


class _PlaceholderBytes(bytes):
    """``_u2`` of a placeholder: two zero bytes standing for its index."""

    placeholder: _Placeholder


class _RecordingPool:
    """``xax_jvm._Pool``'s interface: each call recorded, its result a placeholder."""

    def __init__(self) -> None:
        self.calls: list[_Placeholder] = []

    def _record(self, *call):
        placeholder = _Placeholder(len(self.calls), call)
        self.calls.append(placeholder)
        return placeholder

    def utf8(self, text):
        return self._record("utf8", text)

    def klass(self, name):
        return self._record("klass", name)

    def string(self, text):
        return self._record("string", text)

    def integer(self, value):
        return self._record("integer", value & 0xFFFFFFFF)

    def long(self, value):
        return self._record("long", value & ((1 << 64) - 1))

    def method(self, owner, name, descriptor):
        return self._record("method", owner, name, descriptor)

    def field(self, owner, name, descriptor):
        return self._record("field", owner, name, descriptor)


def memory_templates(stack: bool) -> dict:
    """``{"preamble": calls, member: template}``: a template is (name, descriptor, bytes, slots, calls, frames,
    frame locals, max stack, max locals) where ``slots`` are (byte position, call sequence) and ``calls`` the pool calls
    the member makes, in order."""
    import xax_jvm

    pool = _RecordingPool()
    starts: list[tuple[str, int]] = []
    base = xax_jvm._Code

    class Recording(base):
        def __init__(self, where: str) -> None:
            super().__init__(where)
            self.slots: list[tuple[int, int]] = []
            starts.append((where, len(pool.calls)))

        def raw(self, blob: bytes) -> None:
            if isinstance(blob, _PlaceholderBytes):
                self.slots.append((len(self.buf), blob.placeholder.seq))
            super().raw(blob)

        def finish(self):
            code, frames = super().finish()
            return (code, tuple(self.slots)), frames

    original_u2 = xax_jvm._u2

    def u2(value):
        if isinstance(value, _Placeholder):
            blob = _PlaceholderBytes(b"\x00\x00")
            blob.placeholder = value
            return blob
        return original_u2(value)

    needs = {"memory", "alloc(J)I", "ld1", f"bl:{BOUND_SENTINEL:x}", f"bs:{BOUND_SENTINEL:x}", "ix", "free(I)J", "read(IIJ)J", "write(IIJ)J",
             "ld2", "st2", "ld4", "st4", "ld8", "st8"}
    if stack:
        needs.add("stack")
    xax_jvm._Code, xax_jvm._u2 = Recording, u2
    try:
        methods = xax_jvm._memory_methods(pool, CLASS, needs, INITIAL_SENTINEL)
    finally:
        xax_jvm._Code, xax_jvm._u2 = base, original_u2
    bounds = [index for _where, index in starts] + [len(pool.calls)]
    out: dict = {"preamble": tuple(call.call for call in pool.calls[: bounds[0]])}
    keys = {f"xax$l{BOUND_SENTINEL:x}": "bl", f"xax$s{BOUND_SENTINEL:x}": "bs"}
    for position, method in enumerate(methods):
        (code, slots), frames = method.code, method.frames
        own = range(bounds[position], bounds[position + 1])
        for _at, seq in slots:
            assert seq in own or seq < bounds[0], (method.name, seq)  # a member's indices are its own or the preamble's
        assert method.access == 0x0009 and not method.lines
        out[keys.get(method.name, method.name)] = (
            method.name, method.descriptor, code, slots, tuple((seq, pool.calls[seq].call) for seq in own), frames, method.frame_locals,
            method.max_stack, method.max_locals)
    return out


def descriptor_slots(descriptor: str) -> tuple[int, int]:
    from xax_jvm import _descriptor_slots

    return _descriptor_slots(descriptor)


def check_templates() -> None:
    """The templates rebuilt with a real pool equal ``_memory_methods`` (both stack variants)."""
    import xax_jvm

    for stack in (False, True):
        templates = memory_templates(stack)
        needs = {"memory", "alloc(J)I", "ld1", "bl:3f", "bs:3f", "ix", "free(I)J", "read(IIJ)J", "write(IIJ)J", "ld2", "st2", "ld4", "st4",
                 "ld8", "st8"} | ({"stack"} if stack else set())
        reference_pool = xax_jvm._Pool()
        reference = xax_jvm._memory_methods(reference_pool, "xax/P0123456789abcdef", needs, 70000)
        pool = xax_jvm._Pool()

        def make(call, maximum=None):
            kind, *args = call
            args = ["xax/P0123456789abcdef" if arg == CLASS else arg for arg in args]
            if kind == "integer" and args[0] == INITIAL_SENTINEL:
                args[0] = 70000
            if kind == "integer" and args[0] == BOUND_SENTINEL ^ (1 << 31):
                args[0] = maximum ^ (1 << 31)
            return getattr(pool, kind)(*args)

        indices = {seq: make(call) for seq, call in enumerate(templates["preamble"])}
        rebuilt = []
        for key, _need in ORDER:
            name, descriptor, code, slots, calls, frames, frame_locals, max_stack, max_locals = templates[key]
            for seq, call in calls:
                indices[seq] = make(call, 0x3F)
            blob = bytearray(code)
            for at, seq in slots:
                blob[at:at + 2] = struct.pack(">H", indices[seq])
            if key in ("bl", "bs"):
                name = name.replace(f"{BOUND_SENTINEL:x}", "3f")
            rebuilt.append((name, descriptor, bytes(blob), frames, frame_locals, max_stack, max_locals))
        assert rebuilt == [(m.name, m.descriptor, m.code, m.frames, m.frame_locals, m.max_stack, m.max_locals) for m in reference]
        assert pool.data == reference_pool.data and pool.count == reference_pool.count


# == the XAX program ======================================================================================================

from xax_compiler import Operation  # noqa: E402
from xax_selfhost_facts import E, NONE, _function  # noqa: E402
from xax_selfhost_views_backend import _call, _ok  # noqa: E402

OWN = (("xax$ld1", "(I)I"), ("xax$ld2", "(I)I"), ("xax$ld4", "(I)I"), ("xax$ld8", "(I)J"), ("xax$st2", "(II)V"), ("xax$st4", "(II)V"),
       ("xax$st8", "(IJ)V"), ("xax$ix", "(II)I"), ("xax$alloc", "(J)I"), ("xax$read", "(IIJ)J"), ("xax$write", "(IIJ)J"))
OWN_INDEX = {name: k for k, (name, _descriptor) in enumerate(OWN)}
LOAD_NEED = {1: N_LD1, 2: N_LD2, 4: N_LD4, 8: N_LD8}
STORE_NEED = {2: N_ST2, 4: N_ST4, 8: N_ST8}
BYTES_CAP = 4096  # checked byte members per method or class


def hex_text(e: E, value, name: str):
    """``f"{value:x}"`` as words into ``name`` and ``name_n``."""
    p = e.p
    e.var(f"{name}_v", value)
    e.var(name, e.alloc(18))
    _ok(e, e.ne(p[name], NONE))
    e.var(f"{name}_n", 1)
    e.while_(lambda: e.both(e.lt(p[f"{name}_n"], 16), e.le(_call(e, "jm_pow2", e.mul(p[f"{name}_n"], 4)), p[f"{name}_v"])),
             lambda: e.set(f"{name}_n", e.add(p[f"{name}_n"], 1)))

    def digit():
        e.var(f"{name}_d", e.and_(e.udiv(p[f"{name}_v"], _call(e, "jm_pow2", e.mul(e.sub(e.sub(p[f"{name}_n"], 1), p[f"{name}_k"]), 4))), 15))
        e.st(e.add(p[name], p[f"{name}_k"]), e.add(p[f"{name}_d"], e.sel(e.lt(p[f"{name}_d"], 10), ord("0"), ord("a") - 10)))

    e.for_(f"{name}_k", 0, p[f"{name}_n"], digit)
    return p[name], p[f"{name}_n"]


def hex_less(e: E, a, b):
    """``f"{a:x}" < f"{b:x}"`` (strings: the shorter prefix first)."""
    return _call(e, "jm_hexless", a, b)


def _hex_less_fn(tables):
    def build(e: E):
        p = e.p
        hex_text(e, p["a"], "hl_a")
        hex_text(e, p["b"], "hl_b")
        e.var("hl_n", e.sel(e.lt(p["hl_a_n"], p["hl_b_n"]), p["hl_a_n"], p["hl_b_n"]))

        def compare():
            e.var("hl_x", e.ld(e.add(p["hl_a"], p["hl_k"])))
            e.var("hl_y", e.ld(e.add(p["hl_b"], p["hl_k"])))
            e.if_(e.lt(p["hl_x"], p["hl_y"]), lambda: e.give(1))
            e.if_(e.lt(p["hl_y"], p["hl_x"]), lambda: e.give(0))

        e.for_("hl_k", 0, p["hl_n"], compare)
        e.give(e.flag(e.lt(p["hl_a_n"], p["hl_b_n"])))
    return _function(("a", "b"), build, tables)


# -- the method's needs ---------------------------------------------------------------------------------------------------

def need(e: E, bits):
    from xax_selfhost_jvm_code import _m, _set_m
    from xax_selfhost_jvm_method import M_MNEEDS

    _set_m(e, M_MNEEDS, e.or_(_m(e, M_MNEEDS), bits))


def _need_byte_fn(tables):
    """The checked byte member (``load`` 1: ``xax$l<max>``, else ``xax$s<max>``) added to the method's set."""
    from xax_selfhost_jvm_code import _m, _set_m
    from xax_selfhost_jvm_method import M_MBYTES, M_MNBYTES

    def build(e: E):
        p = e.p
        e.var("nb_list", _m(e, M_MBYTES))
        e.var("nb_n", _m(e, M_MNBYTES))
        e.for_("nb_k", 0, p["nb_n"], lambda: e.if_(e.both(e.eq(e.ld(e.add(p["nb_list"], e.mul(p["nb_k"], 2))), p["load"]),
                                                           e.eq(e.ld(e.add(p["nb_list"], e.add(e.mul(p["nb_k"], 2), 1))), p["maximum"])), lambda: e.give(1)))
        _ok(e, e.lt(p["nb_n"], BYTES_CAP))
        e.st(e.add(p["nb_list"], e.mul(p["nb_n"], 2)), p["load"])
        e.st(e.add(p["nb_list"], e.add(e.mul(p["nb_n"], 2), 1)), p["maximum"])
        _set_m(e, M_MNBYTES, e.add(p["nb_n"], 1))
        e.give(1)
    return _function(("load", "maximum"), build, tables)


# -- facts the lowering reads -----------------------------------------------------------------------------------------------

def static_bound(e: E, node, name: str):
    """``statically_in_bounds``: a checked access at a constant index inside its view (it cannot trap), into
    ``name``."""
    from xax_selfhost_general_ranges import _attribute
    from xax_selfhost_general_regalloc import _eop
    from xax_selfhost_general_view import _operand
    from xax_selfhost_jvm_method import OP, V_CONST, V_CVAL, _v

    p = e.p
    e.var(name, 0)

    def constant_index():
        e.var(f"{name}_x", _call(e, "extent", _operand(e, node, 0)))
        e.var(f"{name}_s", _attribute(e, node, 0))
        e.set(name, e.flag(e.both(e.le(p[f"{name}_s"], p[f"{name}_x"]), e.le(_v(e, V_CVAL, _operand(e, node, 1)), e.sub(p[f"{name}_x"], p[f"{name}_s"])))))

    e.if_(e.either(e.eq(_eop(e, node), OP["CHECKED_LOAD_BITS_LE"]), e.eq(_eop(e, node), OP["CHECKED_STORE_BITS_LE"])), lambda: e.if_(
        e.ne(_v(e, V_CONST, _operand(e, node, 1)), 0), constant_index))
    return p[name]


def _runs_fn(tables):
    """String runs (ADR-157): checked one-byte stores of constant ASCII bytes to consecutive constant indices of one
    view, each consuming the previous one's memory (its only use), at least three: ``N_RUN`` of the first is the count,
    ``N_INRUN`` marks the others.  Nodes whose result is a constant emit nothing and are skipped."""
    from xax_selfhost_general_ranges import _attribute, _block_at, _node_at
    from xax_selfhost_general_regalloc import _eop
    from xax_selfhost_general_view import B_NNODES, _f, _operand, _output
    from xax_selfhost_jvm_code import _m
    from xax_selfhost_jvm_method import M_NB, M_NN, N_INRUN, N_RUN, OP, V_CONST, V_CVAL, V_USES, _node_id, _result0, _set_v, _v

    def build(e: E):
        p = e.p
        e.for_("ru_i", 0, _m(e, M_NN), lambda: (_set_v(e, N_RUN, p["ru_i"], 0), _set_v(e, N_INRUN, p["ru_i"], 0)))
        e.var("ru_members", e.alloc(e.add(_m(e, M_NN), 2)))
        _ok(e, e.ne(p["ru_members"], NONE))
        e.var("ru_count", 0)

        def close():
            def mark():
                _set_v(e, N_RUN, _node_id(e, p["ru_bi"], e.ld(p["ru_members"])), p["ru_count"])
                e.for_("ru_q", 1, p["ru_count"], lambda: _set_v(e, N_INRUN, _node_id(e, p["ru_bi"], e.ld(e.add(p["ru_members"], p["ru_q"]))), 1))

            e.if_(e.le(3, p["ru_count"]), mark)
            e.set("ru_count", 0)

        def block():
            e.var("ru_b", _block_at(e, p["ru_bi"]))
            e.set("ru_count", 0)

            def node():
                e.var("ru_n", _node_at(e, p["ru_b"], p["ru_m"]))
                e.var("ru_r0", _result0(e, p["ru_n"]))
                n = p["ru_n"]

                def candidate():
                    e.var("ru_fits", 0)

                    def store():
                        static_bound(e, n, "ru_sb")
                        e.var("ru_v", _operand(e, n, 2))
                        e.set("ru_fits", e.flag(e.both(e.ne(p["ru_sb"], 0), e.ne(_v(e, V_CONST, p["ru_v"]), 0), e.lt(0, _v(e, V_CVAL, p["ru_v"])),
                                                      e.lt(_v(e, V_CVAL, p["ru_v"]), 0x80))))

                    e.if_(e.both(e.eq(_eop(e, n), OP["CHECKED_STORE_BITS_LE"]), e.eq(_attribute(e, n, 0), 1)), store)

                    def follows():
                        e.var("ru_prev", e.ld(e.add(p["ru_members"], e.sub(p["ru_count"], 1))))
                        prev = p["ru_prev"]
                        ok = e.both(e.eq(_operand(e, n, 0), _operand(e, prev, 0)),
                                    e.eq(_v(e, V_CVAL, _operand(e, n, 1)), e.add(_v(e, V_CVAL, _operand(e, prev, 1)), 1)),
                                    e.eq(_operand(e, n, 3), _output(e, prev, 0)), e.eq(_v(e, V_USES, _operand(e, n, 3)), 1))
                        e.if_(e.not_(ok), close)

                    e.if_(e.both(e.ne(p["ru_fits"], 0), e.lt(0, p["ru_count"])), follows)
                    e.if_(e.ne(p["ru_fits"], 0), lambda: (e.st(e.add(p["ru_members"], p["ru_count"]), n), e.set("ru_count", e.add(p["ru_count"], 1))),
                          close)

                e.if_(e.not_(e.both(e.ne(p["ru_r0"], NONE), e.ne(_v(e, V_CONST, e.sel(e.ne(p["ru_r0"], NONE), p["ru_r0"], 0)), 0))), candidate)

            e.for_("ru_m", 0, _f(e, p["ru_b"], B_NNODES), node)
            close()

        e.for_("ru_bi", 0, _m(e, M_NB), block)
        e.give(1)
    return _function((), build, tables)


def freeing(e: E, node, name: str):
    """``freeing(node)``: the memory class's ``free`` (lowered to a constant, it cannot raise), into ``name``."""
    from xax_selfhost_general_regalloc import _eop
    from xax_selfhost_general_view import N_GRAPH, N_OPSAT, _f
    from xax_selfhost_jvm_method import OP
    from xax_selfhost_views_backend import _reference

    p = e.p
    e.var(name, 0)

    def foreign():
        e.var(f"{name}_c", _reference(e, _f(e, node, N_GRAPH), e.rd(e.sub(_f(e, node, N_OPSAT), 1))))
        _ok(e, e.ne(p[f"{name}_c"], NONE))
        e.set(name, e.flag(e.eq(member_key(e, _call(e, "jk_member", p[f"{name}_c"])), 2)))

    e.if_(e.eq(_eop(e, node), OP["CALL_FOREIGN"]), foreign)
    return p[name]


KEYS = ("alloc(J)I", "free(I)J", "read(IIJ)J", "write(IIJ)J")  # sorted, as ``JVM-MEMORY-MEMBER`` lists them


def member_key(e: E, mb):
    """For a memory-class member record: 1 + its key's index in ``KEYS``; 0 for another member or another class."""
    return _call(e, "jm_memkey", mb)


def _member_key_fn(tables):
    from xax_selfhost_jvm_foreign import MB_DESCN, MB_MEMORY, MB_NAME, MB_NAMEN

    def build(e: E):
        p = e.p
        e.if_(e.eq(e.ld(e.add(p["mb"], MB_MEMORY)), 0), lambda: e.give(0))
        # The member text: the name and its descriptor follow each other.
        e.var("mk_t", e.ld(e.add(p["mb"], MB_NAME)))
        e.var("mk_n", e.add(e.ld(e.add(p["mb"], MB_NAMEN)), e.ld(e.add(p["mb"], MB_DESCN))))
        for k, key in enumerate(KEYS):
            same = e.both(e.eq(p["mk_n"], len(key)), *(e.eq(e.ld(e.add(p["mk_t"], q)), ord(ch)) for q, ch in enumerate(key)))
            e.if_(same, lambda k=k: e.give(k + 1))
        e.give(0)
    return _function(("mb",), build, tables)


# -- the lowering -----------------------------------------------------------------------------------------------------------

def memory_nodes(e: E, node, opv, result):
    """``lower_node`` for the memory operations (pushed in reverse, each ending the node)."""
    from xax_selfhost_general_ranges import _attribute
    from xax_selfhost_general_view import N_NOPS, N_NRES, _f, _operand, _output
    from xax_selfhost_jvm_code import D_D, D_F, D_I, D_J, _m, _set_m
    from xax_selfhost_jvm_lower import (
        J_COMPAREU, J_D2L, J_F2I, J_I2F, J_L2D, J_TOUNSIGNED, K_BRANCH, K_BYTEM, K_FIELDM, K_GET, K_ICONST, K_JAVA, K_LCONST, K_MASK, K_OP,
        K_OWN, K_PUT, Reverse, _desc_get, _sdesc, _slot, _trap_label,
    )
    from xax_selfhost_jvm_method import M_TRAPUSED, OP, _type, _width
    from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb, _reference, _type_form

    p = e.p
    push = Reverse(e)

    def trap_used():
        _set_m(e, M_TRAPUSED, 1)

    def zero_extended(value, width):
        """``get_zero_extended`` (in reverse)."""
        e.var("zx_v", value)
        e.var("zx_w", width)
        e.if_(e.eq(_desc_get(e, p["zx_v"]), D_I), lambda: e.if_(e.eq(p["zx_w"], 32), lambda: push(K_JAVA, J_TOUNSIGNED), lambda: push(K_OP, 0x85, 1)))
        push(K_GET, p["zx_v"])

    def heap_view():
        trap_used()
        need(e, N_MEMORY)
        e.if_(e.ne(_slot(e, _operand(e, node, 0)), _slot(e, result)), lambda: (push(K_PUT, result), push(K_GET, _operand(e, node, 0))))
        push(K_BRANCH, 0x99, _trap_label(e))
        push(K_GET, _operand(e, node, 0))
        e.give(1)

    e.if_(e.eq(opv, OP["HEAP_VIEW"]), heap_view)

    def offset():
        push(K_PUT, result)
        push(K_OP, 0x60, 1)
        push(K_ICONST, _attribute(e, node, 0))
        push(K_GET, _operand(e, node, 0))
        e.give(1)

    e.if_(e.eq(opv, OP["ADDRESS_OFFSET"]), offset)
    e.if_(e.eq(opv, OP["POINTER_CAST"]), lambda: (push(K_PUT, result), push(K_GET, _operand(e, node, 0)), e.give(1)))

    def address():
        push(K_PUT, result)
        e.if_(e.eq(_sdesc(e, result), D_J), lambda: push(K_OP, 0x85, 1))  # offsets are below 2^31: i2l is the zero extension
        push(K_GET, _operand(e, node, 0))
        e.give(1)

    e.if_(e.eq(opv, OP["POINTER_ADDRESS"]), address)

    def rebase():
        # ADR-092: trap unless 0 <= address - view <= extent - window and the distance is a multiple of the alignment.
        trap_used()
        e.var("rb_view", _operand(e, node, 0))
        e.var("rb_addr", _operand(e, node, 1))
        _width(e, p["rb_addr"], "rb_w")
        e.var("rb_ext", _call(e, "extent", p["rb_view"]))
        e.var("rb_win", _attribute(e, node, 0))
        e.var("rb_t", _type(e, result))
        e.var("rb_at", e.add(_at(e, G_PAY, p["rb_t"]), 1))
        _payload_uleb(e, "rb_at")  # the space
        _payload_uleb(e, "rb_at")  # the element
        _payload_uleb(e, "rb_at")  # the permission
        e.var("rb_align", _payload_uleb(e, "rb_at"))
        trap = _trap_label(e)
        push(K_PUT, result)
        push(K_OP, 0x88, 1)
        zero_extended(p["rb_addr"], p["rb_w"])

        def span():
            push(K_BRANCH, 0x9D, trap)
            push(K_JAVA, J_COMPAREU)
            push(K_LCONST, e.sub(p["rb_ext"], p["rb_win"]))

        def negative():
            push(K_BRANCH, 0x9A, trap)
            push(K_ICONST, 1)
            push(K_OP, 0x58, 1)

        e.if_(e.le(p["rb_win"], p["rb_ext"]), span, negative)

        def aligned():
            push(K_BRANCH, 0x9A, trap)
            push(K_OP, 0x94, 1)
            push(K_LCONST, 0)
            push(K_OP, 0x7F, 1)
            push(K_LCONST, e.sub(p["rb_align"], 1))
            push(K_OP, 0x5C, 1)

        e.if_(e.lt(1, p["rb_align"]), aligned)
        push(K_OP, 0x8565, 2)
        push(K_GET, p["rb_view"])
        zero_extended(p["rb_addr"], p["rb_w"])
        e.give(1)

    e.if_(e.eq(opv, OP["POINTER_REBASE"]), rebase)

    def access():
        need(e, N_MEMORY)
        e.var("ma_checked", e.flag(e.either(e.eq(opv, OP["CHECKED_LOAD_BITS_LE"]), e.eq(opv, OP["CHECKED_STORE_BITS_LE"]))))
        e.var("ma_load", e.flag(e.either(e.eq(opv, OP["LOAD_BITS_LE"]), e.eq(opv, OP["CHECKED_LOAD_BITS_LE"]))))
        e.var("ma_size", _attribute(e, node, 0))
        _ok(e, e.either(*(e.eq(p["ma_size"], size) for size in (1, 2, 4, 8))))  # JVM-MEMORY-WIDTH: the bootstrap's
        e.var("ma_ptr", _operand(e, node, 0))
        e.var("ma_value", e.sel(e.ne(p["ma_load"], 0), result, _operand(e, node, e.sel(e.ne(p["ma_checked"], 0), 2, 1))))
        e.var("ma_index", e.sel(e.ne(p["ma_checked"], 0), _operand(e, node, 1), NONE))
        e.var("ma_iw", 64)
        e.var("ma_max", 0)
        e.var("ma_helper", 0)
        e.var("ma_mode", 0)  # checked: 1 always traps, 2 the helper, 3 compared here

        def checked():
            _width(e, p["ma_index"], "ma_iw0")
            e.set("ma_iw", p["ma_iw0"])
            e.var("ma_ext", _call(e, "extent", p["ma_ptr"]))
            e.set("ma_max", e.sub(p["ma_ext"], p["ma_size"]))
            e.var("ma_neg", e.flag(e.lt(p["ma_ext"], p["ma_size"])))
            e.if_(e.ne(p["ma_neg"], 0), lambda: e.set("ma_mode", 1), lambda: e.if_(
                e.both(e.le(p["ma_iw"], 32), e.lt(p["ma_max"], 1 << 31)), lambda: (e.set("ma_mode", 2), e.set("ma_helper", 1)), lambda: e.set("ma_mode", 3)))
            e.if_(e.ne(p["ma_mode"], 2), trap_used)

        e.if_(e.ne(p["ma_checked"], 0), checked)
        e.var("ma_desc", e.sel(e.ne(p["ma_load"], 0), _sdesc(e, result), _desc_get(e, p["ma_value"])))
        e.var("ma_vt", _type(e, p["ma_value"]))
        e.var("ma_float", e.flag(e.eq(_type_form(e, p["ma_vt"]), 7)))
        e.var("ma_vw", 64)
        e.if_(e.eq(p["ma_float"], 0), lambda: (_width(e, p["ma_value"], "ma_vw0"), e.set("ma_vw", p["ma_vw0"])))
        trap = _trap_label(e)

        def push_address():
            """``push_address`` (in reverse)."""
            def helper():
                push(K_OP, 0x60, 1)
                push(K_OWN, OWN_INDEX["xax$ix"])
                push(K_ICONST, p["ma_max"])
                push(K_GET, p["ma_index"])

            def plain_checked():
                push(K_OP, 0x60, 1)
                e.if_(e.eq(_desc_get(e, p["ma_index"]), D_J), lambda: push(K_OP, 0x88, 1))
                push(K_GET, p["ma_index"])

            e.if_(e.ne(p["ma_helper"], 0), lambda: (need(e, N_IX), helper()), lambda: e.if_(e.ne(p["ma_checked"], 0), plain_checked))
            push(K_GET, p["ma_ptr"])

        def byte_member():
            # Byte accesses through generated members (ADR-157): one call per access.
            def load_tail():
                push(K_PUT, result)
                e.if_(e.lt(p["ma_vw"], 8), lambda: push(K_MASK, p["ma_desc"], p["ma_vw"]))
                e.if_(e.eq(p["ma_desc"], D_J), lambda: push(K_OP, 0x85, 1))

            e.if_(e.ne(p["ma_load"], 0), load_tail)
            e.if_(e.ne(p["ma_helper"], 0), lambda: (push(K_BYTEM, p["ma_load"], p["ma_max"]), _call(e, "jm_needbyte", p["ma_load"], p["ma_max"])),
                  lambda: (push(K_OWN, OWN_INDEX["xax$ld1"]), need(e, N_LD1)))
            e.if_(e.ne(p["ma_helper"], 0), lambda: push(K_GET, p["ma_index"]))
            push(K_GET, p["ma_ptr"])

            def value_first():
                e.if_(e.eq(_desc_get(e, p["ma_value"]), D_J), lambda: push(K_OP, 0x88, 1))
                push(K_GET, p["ma_value"])

            e.if_(e.eq(p["ma_load"], 0), value_first)

        def wide_load():
            mem_access(e, True, p["ma_size"], p["ma_vt"], result, push_address)

        def wide_store():
            mem_access(e, False, p["ma_size"], p["ma_vt"], p["ma_value"], push_address)

        members = e.both(e.eq(p["ma_size"], 1), e.either(e.ne(p["ma_helper"], 0), e.both(e.ne(p["ma_load"], 0), e.eq(p["ma_checked"], 0))))
        e.if_(members, byte_member, lambda: e.if_(e.ne(p["ma_load"], 0), wide_load, wide_store))

        # The bound check before the access (``maximum < 0`` always traps; a wide index is compared here).
        def compared():
            push(K_BRANCH, 0x9D, trap)
            e.if_(e.lt(63, p["ma_iw"]), lambda: push(K_JAVA, J_COMPAREU), lambda: push(K_OP, 0x94, 1))
            push(K_LCONST, p["ma_max"])
            zero_extended(p["ma_index"], p["ma_iw"])

        e.if_(e.eq(p["ma_mode"], 1), lambda: (push(K_BRANCH, 0x9A, trap), push(K_ICONST, 1)))
        e.if_(e.eq(p["ma_mode"], 3), compared)
        e.give(1)

    e.if_(_in_ops(e, opv, ("LOAD_BITS_LE", "STORE_BITS_LE", "CHECKED_LOAD_BITS_LE", "CHECKED_STORE_BITS_LE")), access)


def _in_ops(e: E, opv, names):
    return e.either(*(e.eq(opv, int(getattr(Operation, name))) for name in names))


def run_head(e: E, node, b, count):
    """The first store of a string run: ``text.getBytes(0, n, M, p + i)`` (each char's low byte, in order)."""
    from xax_selfhost_general_ranges import _block_at, _node_at
    from xax_selfhost_general_view import B_NNODES, _f, _operand
    from xax_selfhost_jvm_lower import J_GETBYTES, K_FIELDM, K_GET, K_ICONST, K_JAVA, K_OP, K_STRING, Reverse
    from xax_selfhost_jvm_method import V_CONST, V_CVAL, _result0, _v

    p = e.p
    need(e, N_MEMORY)
    e.var("rh_n", count)
    e.var("rh_text", e.alloc(e.add(p["rh_n"], 1)))
    _ok(e, e.ne(p["rh_text"], NONE))
    e.var("rh_b", _block_at(e, b))
    e.var("rh_k", 0)
    e.var("rh_on", 0)

    def collect():
        e.var("rh_x", _node_at(e, p["rh_b"], p["rh_m"]))
        e.if_(e.eq(p["rh_x"], node), lambda: e.set("rh_on", 1))
        e.var("rh_r0", _result0(e, p["rh_x"]))
        constant = e.both(e.ne(p["rh_r0"], NONE), e.ne(_v(e, V_CONST, e.sel(e.ne(p["rh_r0"], NONE), p["rh_r0"], 0)), 0))
        e.if_(e.both(e.ne(p["rh_on"], 0), e.lt(p["rh_k"], p["rh_n"]), e.not_(constant)), lambda: (
            e.st(e.add(p["rh_text"], p["rh_k"]), _v(e, V_CVAL, _operand(e, p["rh_x"], 2))), e.set("rh_k", e.add(p["rh_k"], 1))))

    e.for_("rh_m", 0, _f(e, p["rh_b"], B_NNODES), collect)
    push = Reverse(e)
    push(K_JAVA, J_GETBYTES, 0xB6)
    push(K_OP, 0x60, 1)
    push(K_ICONST, _v(e, V_CVAL, _operand(e, node, 1)))
    push(K_GET, _operand(e, node, 0))
    push(K_FIELDM)
    push(K_ICONST, p["rh_n"])
    push(K_ICONST, 0)
    push(K_STRING, p["rh_text"], p["rh_n"])


def memory_call(e: E, node, mb, key):
    """A memory-class member (``key`` 1 + its index in ``KEYS``): ``free`` is the constant 0 (blocks are never reused,
    ADR-156); the others call their generated member, the machine operands first; the one machine result kept."""
    from xax_selfhost_general_view import N_GRAPH, N_NOPS, N_NRES, _f, _operand, _output
    from xax_selfhost_jvm_code import D_NONE, _m, _set_m
    from xax_selfhost_jvm_lower import K_GET, K_OP, K_OWN, K_PUT, Reverse, _desc_get, _slot
    from xax_selfhost_jvm_method import M_MAXCALL, V_NEEDED, _desc, _pick_slots, _v
    from xax_selfhost_views_backend import _cid_words
    import xax_selfhost_diagnostics as D

    p = e.p
    e.var("mc_key", key)
    e.var("mc_graph", _f(e, node, N_GRAPH))

    def write():
        from xax_selfhost_jvm_foreign import MB_DESCN, MB_NAME, MB_NAMEN, _put_text

        D.text(e, "XAX.JVM.FOREIGN")
        D.cid(e, _cid_words(e, p["mc_graph"]))
        D.text(e, "JVM-MEMORY-MEMBER")
        D.put(e, D.T_LIST)
        D.put(e, len(KEYS))
        for text in KEYS:
            D.text(e, text)
        _put_text(e, e.ld(e.add(mb, MB_NAME)), e.add(e.ld(e.add(mb, MB_NAMEN)), e.ld(e.add(mb, MB_DESCN))))

    D.reject_unless(e, e.ne(p["mc_key"], 0), write)
    need(e, N_MEMORY)
    push = Reverse(e)

    def free():
        e.var("mc_r0", _output(e, node, 0))
        e.if_(e.both(e.ne(_slot(e, p["mc_r0"]), NONE), e.ne(_v(e, V_NEEDED, p["mc_r0"]), 0)), lambda: (push(K_PUT, p["mc_r0"]), push(K_OP, 0x09, 1)))
        e.give(1)

    e.if_(e.eq(p["mc_key"], 2), free)
    need(e, _pick_need(e, p["mc_key"]))
    # The one machine result (JVM-SINGLE-RESULT on entity "call": declined), kept.
    e.var("mc_nres", 0)
    e.var("mc_res", NONE)
    e.for_("mc_r", 0, _f(e, node, N_NRES), lambda: (e.var("mc_rv", _output(e, node, p["mc_r"])), e.if_(e.ne(_slot(e, p["mc_rv"]), NONE), lambda: (
        e.if_(e.eq(p["mc_res"], NONE), lambda: e.set("mc_res", p["mc_rv"])), e.set("mc_nres", e.add(p["mc_nres"], 1))))))
    _ok(e, e.le(p["mc_nres"], 1))
    e.if_(e.ne(p["mc_res"], NONE), lambda: e.if_(e.ne(_v(e, V_NEEDED, p["mc_res"]), 0), lambda: push(K_PUT, p["mc_res"]), lambda: push(
        K_OP, e.sel(e.eq(_pick_slots(e, _desc(e, p["mc_res"])), 2), 0x58, 0x57), 1)))
    push(K_OWN, e.sel(e.eq(p["mc_key"], 1), OWN_INDEX["xax$alloc"], e.sel(e.eq(p["mc_key"], 3), OWN_INDEX["xax$read"], OWN_INDEX["xax$write"])))
    e.var("mc_slots", 0)
    e.var("mc_k", _f(e, node, N_NOPS))

    def operand():
        e.set("mc_k", e.sub(p["mc_k"], 1))
        e.var("mc_o", _operand(e, node, p["mc_k"]))
        e.if_(e.ne(_desc(e, p["mc_o"]), D_NONE), lambda: (push(K_GET, p["mc_o"]), e.set("mc_slots", e.add(p["mc_slots"], _pick_slots(e, _desc_get(e, p["mc_o"]))))))

    e.while_(lambda: e.lt(0, p["mc_k"]), operand)
    e.if_(e.lt(_m(e, M_MAXCALL), p["mc_slots"]), lambda: _set_m(e, M_MAXCALL, p["mc_slots"]))
    e.give(1)


def _pick_need(e: E, key):
    return e.sel(e.eq(key, 1), N_ALLOC, e.sel(e.eq(key, 3), N_READ, N_WRITE))


# -- the class: the merged needs, the initial memory, the members ------------------------------------------------------------

STACK_BYTES = 1 << 20
INITIAL_MEMORY = 1 << 16


def _merge_fn(tables):
    """The method's needs and checked byte members join the class's."""
    from xax_selfhost_jvm import J_BYTES, J_NBYTES, J_NEEDS, _js, _set_js
    from xax_selfhost_jvm_code import _m
    from xax_selfhost_jvm_method import M_MBYTES, M_MNBYTES, M_MNEEDS

    def build(e: E):
        p = e.p
        _set_js(e, J_NEEDS, e.or_(_js(e, J_NEEDS), _m(e, M_MNEEDS)))

        def one():
            e.var("mg_load", e.ld(e.add(_m(e, M_MBYTES), e.mul(p["mg_k"], 2))))
            e.var("mg_max", e.ld(e.add(_m(e, M_MBYTES), e.add(e.mul(p["mg_k"], 2), 1))))
            e.var("mg_list", _js(e, J_BYTES))
            e.var("mg_n", _js(e, J_NBYTES))
            e.var("mg_found", 0)
            e.for_("mg_q", 0, p["mg_n"], lambda: e.if_(e.both(e.eq(e.ld(e.add(p["mg_list"], e.mul(p["mg_q"], 2))), p["mg_load"]),
                                                               e.eq(e.ld(e.add(p["mg_list"], e.add(e.mul(p["mg_q"], 2), 1))), p["mg_max"])),
                                                        lambda: e.set("mg_found", 1)))

            def add():
                _ok(e, e.lt(p["mg_n"], BYTES_CAP))
                e.st(e.add(p["mg_list"], e.mul(p["mg_n"], 2)), p["mg_load"])
                e.st(e.add(p["mg_list"], e.add(e.mul(p["mg_n"], 2), 1)), p["mg_max"])
                _set_js(e, J_NBYTES, e.add(p["mg_n"], 1))

            e.if_(e.eq(p["mg_found"], 0), add)

        e.for_("mg_k", 0, _m(e, M_MNBYTES), one)
        e.give(1)
    return _function((), build, tables)


def initial_scan(e: E):
    """``_initial_memory``'s part of this function (after ``lift``): every ``alloc`` of the memory class whose size is
    a constant node adds that size, 16-aligned, to the class's total; a stack allocation marks the class."""
    from xax_selfhost_general_regalloc import _eop
    from xax_selfhost_general_view import N_GRAPH, N_OPSAT, _f, _operand
    from xax_selfhost_jvm import J_INIT, J_STACKS, _js, _set_js
    from xax_selfhost_jvm_method import OP, _constant_value, _def, _each_node, _is_param
    from xax_selfhost_views_backend import _FOREIGN_PREFIX, G_PAY, _at, _payload_uleb, _reference
    from xax_selfhost_x86_64_general import _bytes_equal

    p = e.p

    def node(b, n, m):
        def foreign():
            e.var("is_c", _reference(e, _f(e, n, N_GRAPH), e.rd(e.sub(_f(e, n, N_OPSAT), 1))))
            _ok(e, e.ne(p["is_c"], NONE))
            e.var("is_at", _at(e, G_PAY, p["is_c"]))
            _payload_uleb(e, "is_at")  # the identity's length
            e.set("is_at", e.add(p["is_at"], len(_FOREIGN_PREFIX)))
            for part in ("abi", "lib", "sym"):
                e.var(f"is_{part}n", _payload_uleb(e, "is_at"))
                e.var(f"is_{part}", p["is_at"])
                e.set("is_at", e.add(p["is_at"], p[f"is_{part}n"]))
            alloc = e.both(_bytes_equal(e, p["is_lib"], p["is_libn"], b"xax/jvm/Memory"), _bytes_equal(e, p["is_sym"], p["is_symn"], b"alloc(J)I"))

            def sized():
                e.var("is_size", _operand(e, n, 0))
                e.var("is_src", e.sel(_is_param(e, p["is_size"]), NONE, _def(e, p["is_size"])))

                def constant():
                    _constant_value(e, p["is_src"], "is_v")
                    _set_js(e, J_INIT, e.add(e.and_(e.add(_js(e, J_INIT), 15), e.c((1 << 64) - 16)), p["is_v"]))

                e.if_(e.ne(p["is_src"], NONE), lambda: e.if_(e.eq(_eop(e, p["is_src"]), OP["CONSTANT"]), constant))

            e.if_(alloc, sized)

        e.if_(e.eq(_eop(e, n), OP["CALL_FOREIGN"]), foreign)
        e.if_(e.eq(_eop(e, n), int(Operation.STACK_ALLOC)), lambda: _set_js(e, J_STACKS, 1))

    _each_node(e, node, "isn")


def _members_fn(tables):
    """``_memory_methods``: the members the class needs, in the bootstrap's order, from the build-time templates."""
    from xax_selfhost_jvm import J_BYTES, J_CLASSNAME, J_INIT, J_NBYTES, J_NEEDS, J_POOL, J_STACKS, KIND_NAMED, _add_record, _js, _set_js
    from xax_selfhost_jvm import (MR_BARE, MR_CLEN, MR_CODE, MR_FIDX, MR_FRAMES, MR_FTYPES, MR_KIND, MR_LINES, MR_LOCALS, MR_NFRAMES, MR_NFTYPES,
                                  MR_NLINES, MR_STACK, _store_alloc)
    from xax_selfhost_jvm_class import klass_literal, literal, utf8_literal
    from xax_selfhost_jvm_code import D_I, D_J

    plain, stacked = memory_templates(False), memory_templates(True)

    def build(e: E):
        p = e.p
        pool = _js(e, J_POOL)
        e.var("me_needs", _js(e, J_NEEDS))
        e.if_(e.ne(e.and_(p["me_needs"], N_LD8), 0), lambda: e.set("me_needs", e.or_(p["me_needs"], N_LD4)))
        e.if_(e.ne(e.and_(p["me_needs"], N_ST8), 0), lambda: e.set("me_needs", e.or_(p["me_needs"], N_ST4)))
        e.var("me_stack", e.flag(e.ne(e.and_(p["me_needs"], N_STACK), 0)))
        e.var("me_total", e.add(_js(e, J_INIT), e.sel(e.ne(_js(e, J_STACKS), 0), STACK_BYTES, 0)))
        e.var("me_initial", e.sel(e.lt(p["me_total"], 1 << 30), p["me_total"], 1 << 30))
        e.if_(e.lt(p["me_initial"], INITIAL_MEMORY), lambda: e.set("me_initial", INITIAL_MEMORY))
        e.var("me_bound", 0)  # a checked byte member's maximum

        def own_class():
            return _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21))

        def klass(name: str, var: str):
            return own_class() if name == CLASS else klass_literal(e, pool, name, var)

        def make(call, var: str):
            kind, *args = call
            if kind == "field" or kind == "method":
                owner, name, descriptor = args
                e.var(f"{var}_c", klass(owner, f"{var}_o"))
                e.var(f"{var}_nt", _call(e, "jp_ref2", pool, 12, utf8_literal(e, pool, name, f"{var}_n"), utf8_literal(e, pool, descriptor, f"{var}_d"), 0, 0))
                if kind == "field":
                    return _call(e, "jp_ref2", pool, 9, p[f"{var}_c"], p[f"{var}_nt"], 0, 2 if descriptor in ("J", "D") else 1)
                arguments, result = descriptor_slots(descriptor)
                return _call(e, "jp_ref2", pool, 10, p[f"{var}_c"], p[f"{var}_nt"], arguments, result)
            if kind == "klass":
                return klass(args[0], var)
            if kind == "string":
                return _call(e, "jp_ref1", pool, 8, utf8_literal(e, pool, args[0], var))
            if kind == "integer":
                value = args[0]
                if value == INITIAL_SENTINEL:
                    value = p["me_initial"]
                elif value == BOUND_SENTINEL ^ (1 << 31):
                    value = _bx(e, p["me_bound"], 1 << 31)
                return _call(e, "jp_number", pool, 3, value)
            assert kind == "long", call
            return _call(e, "jp_number", pool, 5, args[0])

        for seq, call in enumerate(plain["preamble"]):
            e.var(f"me_p{seq}", make(call, f"me_pc{seq}"))

        def emit(template, tag: str, name_text=None):
            name, descriptor, code, slots, calls, frames, frame_locals, max_stack, max_locals = template
            for seq, call in calls:
                e.var(f"me_{tag}{seq}", make(call, f"me_{tag}c{seq}"))
            e.var(f"me_{tag}_code", _store_alloc(e, len(code) + 1, f"me_{tag}_cs"))
            at = p[f"me_{tag}_code"]
            filled = {position for start, _seq in slots for position in (start, start + 1)}
            for k, byte in enumerate(code):
                if k not in filled:
                    e.st(e.add(at, k), byte)
            for start, seq in slots:
                index = p[f"me_{tag}{seq}"] if any(seq == own for own, _call in calls) else p[f"me_p{seq}"]
                e.st(e.add(at, start), e.and_(e.udiv(index, 256), 255))
                e.st(e.add(at, start + 1), e.and_(index, 255))
            e.var(f"me_{tag}_fr", _store_alloc(e, len(frames) + 1, f"me_{tag}_fs"))
            for k, offset in enumerate(frames):
                e.st(e.add(p[f"me_{tag}_fr"], k), offset)
            e.var(f"me_{tag}_ft", _store_alloc(e, len(frame_locals) + 1, f"me_{tag}_ts"))
            for k, local in enumerate(frame_locals):
                if local in ("I", "J"):
                    e.st(e.add(p[f"me_{tag}_ft"], k), D_I if local == "I" else D_J)
                else:
                    literal(e, f"me_{tag}_lt{k}", local)
                    e.st(e.add(p[f"me_{tag}_ft"], k), _call(e, "jk_intern", p[f"me_{tag}_lt{k}"], len(local)))
            e.var(f"me_{tag}_nm", _store_alloc(e, 6, f"me_{tag}_ns"))
            if name_text is None:
                literal(e, f"me_{tag}_name", name)
                name_text = (p[f"me_{tag}_name"], len(name))
            literal(e, f"me_{tag}_desc", descriptor)
            for k, word in enumerate((name_text[0], name_text[1], p[f"me_{tag}_desc"], len(descriptor), 0x0009)):
                e.st(e.add(p[f"me_{tag}_nm"], k), word)
            _add_record(e, {MR_KIND: KIND_NAMED, MR_FIDX: p[f"me_{tag}_nm"], MR_CODE: at, MR_CLEN: len(code), MR_STACK: max_stack,
                            MR_LOCALS: max_locals, MR_FRAMES: p[f"me_{tag}_fr"], MR_NFRAMES: len(frames), MR_FTYPES: p[f"me_{tag}_ft"],
                            MR_NFTYPES: len(frame_locals), MR_LINES: 0, MR_NLINES: 0, MR_BARE: NONE})

        def bytes_of(load: int, key: str):
            """Every checked byte member of one kind, in the order of their bounds' hex texts."""
            e.var(f"me_{key}_list", _js(e, J_BYTES))
            e.var(f"me_{key}_n", _js(e, J_NBYTES))
            e.var(f"me_{key}_done", e.alloc(e.add(p[f"me_{key}_n"], 1)))
            _ok(e, e.ne(p[f"me_{key}_done"], NONE))
            e.for_(f"me_{key}_z", 0, p[f"me_{key}_n"], lambda: e.st(e.add(p[f"me_{key}_done"], p[f"me_{key}_z"]), 0))

            def entry(q, field):
                return e.ld(e.add(p[f"me_{key}_list"], e.add(e.mul(q, 2), field)))

            def pick():
                e.var(f"me_{key}_best", NONE)

                def consider():
                    q = p[f"me_{key}_q"]
                    e.if_(e.both(e.eq(e.ld(e.add(p[f"me_{key}_done"], q)), 0), e.eq(entry(q, 0), load)), lambda: e.if_(
                        e.either(e.eq(p[f"me_{key}_best"], NONE), e.ne(hex_less(e, entry(q, 1), entry(e.sel(e.eq(p[f"me_{key}_best"], NONE), q, p[f"me_{key}_best"]), 1)), 0)),
                        lambda: e.set(f"me_{key}_best", q)))

                e.for_(f"me_{key}_q", 0, p[f"me_{key}_n"], consider)

                def one():
                    e.st(e.add(p[f"me_{key}_done"], p[f"me_{key}_best"]), 1)
                    e.set("me_bound", entry(p[f"me_{key}_best"], 1))
                    hex_text(e, p["me_bound"], f"me_{key}_hx")
                    e.var(f"me_{key}_nmt", e.alloc(e.add(p[f"me_{key}_hx_n"], 6)))
                    _ok(e, e.ne(p[f"me_{key}_nmt"], NONE))
                    for k, ch in enumerate(f"xax${'l' if load else 's'}".encode()):
                        e.st(e.add(p[f"me_{key}_nmt"], k), ch)
                    e.for_(f"me_{key}_hk", 0, p[f"me_{key}_hx_n"], lambda: e.st(e.add(p[f"me_{key}_nmt"], e.add(5, p[f"me_{key}_hk"])),
                                                                                e.ld(e.add(p[f"me_{key}_hx"], p[f"me_{key}_hk"]))))
                    emit(plain[key], key, (p[f"me_{key}_nmt"], e.add(p[f"me_{key}_hx_n"], 5)))

                e.if_(e.ne(p[f"me_{key}_best"], NONE), one)
                return p[f"me_{key}_best"]

            e.var(f"me_{key}_go", 1)
            e.while_(lambda: e.ne(p[f"me_{key}_go"], 0), lambda: e.set(f"me_{key}_go", e.flag(e.ne(pick(), NONE))))

        for key, need_bit in ORDER:
            if key == "<clinit>":
                e.if_(e.ne(p["me_stack"], 0), lambda: emit(stacked[key], "cs"), lambda: emit(plain[key], "cp"))
            elif key in ("bl", "bs"):
                bytes_of(1 if key == "bl" else 0, key)
            else:
                tag = key.replace("xax$", "")
                e.if_(e.ne(e.and_(p["me_needs"], need_bit), 0), lambda key=key, tag=tag: emit(plain[key], tag))
        e.give(1)
    return _function((), build, tables)


def _bx(e: E, x, y):
    from xax_selfhost_jvm_code import _bx as bx

    return bx(e, x, y)


def add_memory_functions(add, tables):
    for name, builder in (("jm_hexless", _hex_less_fn), ("jm_needbyte", _need_byte_fn), ("jm_runs", _runs_fn), ("jm_memkey", _member_key_fn),
                          ("jm_merge", _merge_fn), ("jk_members", _members_fn), ("jk_launcher", _launcher_fn)):
        add(name, builder(tables))


def mem_access(e: E, load: bool, size, vt, value, push_address, custom=None):
    """``memory_access`` (pushed in reverse): a little-endian access of ``size`` bytes at the pushed address of a value
    of type ``vt``: a load into ``value`` (its result), or a store of ``value`` (or of what ``custom()`` pushes, in
    reverse, with descriptor ``custom_desc``)."""
    from xax_selfhost_jvm_method import type_width
    from xax_selfhost_jvm_code import D_D, D_F, D_I, D_J
    from xax_selfhost_jvm_lower import J_D2L, J_F2I, J_I2F, J_L2D, K_FIELDM, K_GET, K_JAVA, K_LCONST, K_MASK, K_OP, K_OWN, K_PUT, Reverse, _desc_get, _sdesc
    from xax_selfhost_views_backend import _type_form

    p = e.p
    push = Reverse(e)
    e.var("mx_size", size)
    e.var("mx_vt", vt)
    e.var("mx_v", value)
    e.var("mx_float", e.flag(e.eq(_type_form(e, p["mx_vt"]), 7)))
    e.var("mx_vw", 64)
    e.if_(e.eq(p["mx_float"], 0), lambda: (type_width(e, p["mx_vt"], "mx_vw0"), e.set("mx_vw", p["mx_vw0"])))
    sized = lambda table: e.sel(e.eq(p["mx_size"], 2), table[2], e.sel(e.eq(p["mx_size"], 4), table[4], table[8]))  # noqa: E731
    if load:
        e.var("mx_d", _sdesc(e, p["mx_v"]))
        push(K_PUT, p["mx_v"])
        e.if_(e.both(e.eq(p["mx_float"], 0), e.lt(p["mx_vw"], e.mul(p["mx_size"], 8))), lambda: push(K_MASK, p["mx_d"], p["mx_vw"]))

        def byte():
            e.if_(e.eq(p["mx_d"], D_J), lambda: push(K_OP, 0x85, 1))
            push(K_OP, 0x7E, 1)
            push(K_ICONST_(), 0xFF)
            push(K_OP, 0x33, 1)
            push_address()
            push(K_FIELDM)

        def member():
            e.if_(e.ne(p["mx_float"], 0), lambda: push(K_JAVA, e.sel(e.eq(p["mx_size"], 4), J_I2F, J_L2D)), lambda: e.if_(
                e.both(e.eq(p["mx_d"], D_J), e.ne(p["mx_size"], 8)), lambda: (
                    push(K_OP, 0x7F, 1), push(K_LCONST, e.sub(_call(e, "jm_pow2", e.mul(p["mx_size"], 8)), 1)), push(K_OP, 0x85, 1)), lambda: e.if_(
                    e.both(e.eq(p["mx_d"], D_I), e.eq(p["mx_size"], 8)), lambda: push(K_OP, 0x88, 1))))
            push(K_OWN, sized({2: OWN_INDEX["xax$ld2"], 4: OWN_INDEX["xax$ld4"], 8: OWN_INDEX["xax$ld8"]}))
            push_address()
            need(e, sized(LOAD_NEED))

        e.if_(e.eq(p["mx_size"], 1), byte, member)
        return

    def value_steps():
        if custom is None:
            push(K_GET, p["mx_v"])
        else:
            custom()

    e.var("mx_d", _desc_get(e, p["mx_v"]) if custom is None else p["custom_desc"])

    def byte():
        push(K_OP, 0x54, 1)
        e.if_(e.eq(p["mx_d"], D_J), lambda: push(K_OP, 0x88, 1))
        value_steps()
        push_address()
        push(K_FIELDM)

    def member():
        push(K_OWN, sized({2: OWN_INDEX["xax$st2"], 4: OWN_INDEX["xax$st4"], 8: OWN_INDEX["xax$st8"]}))
        d = p["mx_d"]
        e.if_(e.eq(d, D_F), lambda: push(K_JAVA, J_F2I), lambda: e.if_(e.eq(d, D_D), lambda: push(K_JAVA, J_D2L), lambda: e.if_(
            e.both(e.eq(p["mx_size"], 8), e.eq(d, D_I)), lambda: push(K_OP, 0x85, 1), lambda: e.if_(
                e.both(e.ne(p["mx_size"], 8), e.eq(d, D_J)), lambda: push(K_OP, 0x88, 1)))))
        value_steps()
        push_address()
        need(e, sized(STORE_NEED))

    e.if_(e.eq(p["mx_size"], 1), byte, member)


def K_ICONST_():
    from xax_selfhost_jvm_lower import K_ICONST

    return K_ICONST


class Fwd:
    """Tasks written in order, pushed in reverse when done: ``s(kind, *arguments)``, ``s.do(fn)`` (``fn`` pushes its
    own tasks in reverse), ``s.when(condition, then, otherwise)`` (each given a fresh ``Fwd``)."""

    def __init__(self, e: E):
        self.e = e
        self.items = []

    def __call__(self, kind: int, *arguments):
        self.items.append(("task", kind, arguments))
        return self

    def do(self, fn):
        self.items.append(("do", fn))
        return self

    def when(self, condition, then, otherwise=None):
        self.items.append(("when", condition, then, otherwise))
        return self

    def push(self):
        e = self.e
        for item in reversed(self.items):
            if item[0] == "task":
                words = list(item[2]) + [0] * (4 - len(item[2]))
                _call(e, "jl_push", item[1], *words)
            elif item[0] == "do":
                item[1]()
            else:
                _condition, then, otherwise = item[1], item[2], item[3]

                def branch(builder):
                    inner = Fwd(e)
                    builder(inner)
                    inner.push()

                e.if_(_condition(), lambda: branch(then), (lambda: branch(otherwise)) if otherwise is not None else None)


# -- the general profile (S15e.5h) ----------------------------------------------------------------------------------------

def general_nodes(e: E, node, opv, result):
    """Stack storage (zero-filled at its frame offset), links, raw loads, atomics (one XAX thread: each is its
    sequential effect on the linear memory, ADR-160), pushed in reverse."""
    from xax_selfhost_general_ranges import _attribute
    from xax_selfhost_jvm_method import type_width
    from xax_selfhost_general_view import _f, _operand, _output
    from xax_selfhost_jvm_code import D_J, _m, _set_m
    from xax_selfhost_jvm_lower import (
        EQ_, J_FILL, K_BRANCH, K_FIELDM, K_GET, K_ICONST, K_JAVA, K_LOAD, K_MARK, K_OP, K_PUT, Reverse, _compare_result_pushes, _desc_get,
        _fresh, _sdesc, _trap_label,
    )
    from xax_selfhost_jvm_method import M_FSLOT, M_TRAPUSED, N_FOFF, OP, _node_id, _type, _v
    from xax_selfhost_views_backend import G_PAY, _at, _payload_uleb, _reference

    p = e.p
    push = Reverse(e)

    def stack():
        need(e, e.c(N_MEMORY | N_STACK))
        e.var("sa_off", _v(e, N_FOFF, _node_id(e, _f(e, node, 1), node)))
        e.var("sa_fp", _m(e, M_FSLOT))
        from xax_selfhost_jvm_code import D_I

        push(K_PUT, result)
        push(K_OP, 0x60, 1)
        push(K_ICONST, p["sa_off"])
        push(K_LOAD, D_I, p["sa_fp"])
        push(K_JAVA, J_FILL)
        push(K_ICONST, 0)
        push(K_OP, 0x60, 1)
        push(K_ICONST, e.add(p["sa_off"], _attribute(e, node, 0)))
        push(K_LOAD, D_I, p["sa_fp"])
        push(K_OP, 0x60, 1)
        push(K_ICONST, p["sa_off"])
        push(K_LOAD, D_I, p["sa_fp"])
        push(K_FIELDM)
        e.give(1)

    e.if_(e.eq(opv, int(Operation.STACK_ALLOC)), stack)
    e.if_(_in_ops(e, opv, ("STACK_END", "LINK_TARGET", "ATOMIC_FENCE")), lambda: e.give(1))  # proof only
    e.if_(e.eq(opv, int(Operation.LINK_MAKE)), lambda: (push(K_PUT, result), push(K_GET, _operand(e, node, 0)), e.give(1)))

    def follow():
        _set_m(e, M_TRAPUSED, 1)
        push(K_PUT, result)
        push(K_GET, _operand(e, node, 1))
        push(K_BRANCH, 0x99, _trap_label(e))
        push(K_GET, _operand(e, node, 1))
        e.give(1)

    e.if_(e.eq(opv, int(Operation.LINK_FOLLOW)), follow)

    def raw():
        need(e, N_MEMORY)
        e.var("rl_p", _operand(e, node, 0))
        mem_access(e, True, _attribute(e, node, 0), _type(e, result), result, lambda: push(K_GET, p["rl_p"]))
        e.give(1)

    e.if_(e.eq(opv, int(Operation.RAW_LOAD_BITS_LE)), raw)

    def atomic():
        need(e, N_MEMORY)
        e.var("at_p", _operand(e, node, 0))
        e.var("at_pt", _type(e, p["at_p"]))
        e.var("at_pa", e.add(_at(e, G_PAY, p["at_pt"]), 1))
        _payload_uleb(e, "at_pa")  # the space
        e.var("at_el", _reference(e, p["at_pt"], _payload_uleb(e, "at_pa")))
        _ok(e, e.ne(p["at_el"], NONE))
        type_width(e, p["at_el"], "at_w")
        e.var("at_size", e.udiv(e.add(p["at_w"], 7), 8))
        at = lambda: push(K_GET, p["at_p"])  # noqa: E731

        e.if_(e.eq(opv, int(Operation.ATOMIC_LOAD)), lambda: (mem_access(e, True, p["at_size"], p["at_el"], result, at), e.give(1)))
        e.if_(e.eq(opv, int(Operation.ATOMIC_STORE)), lambda: (mem_access(e, False, p["at_size"], p["at_el"], _operand(e, node, 1), at), e.give(1)))

        def rmw():
            from xax_compiler import AtomicRmwKind

            def exchange():
                mem_access(e, False, p["at_size"], p["at_el"], _operand(e, node, 1), at)

            def add():
                e.var("custom_desc", _desc_get(e, result))

                def added():
                    """``get(result); get(value); add; mask``: pushed in reverse."""
                    push(K_MASK_(), p["custom_desc"], p["at_w"])
                    push(K_OP, e.sel(e.eq(p["custom_desc"], D_J), 0x61, 0x60), 1)
                    push(K_GET, _operand(e, node, 1))
                    push(K_GET, result)

                mem_access(e, False, p["at_size"], p["at_el"], result, at, added)

            e.if_(e.eq(_attribute(e, node, 0), int(AtomicRmwKind.EXCHANGE)), exchange, add)
            mem_access(e, True, p["at_size"], p["at_el"], result, at)
            e.give(1)

        e.if_(e.eq(opv, int(Operation.ATOMIC_RMW)), rmw)

        def cmpxchg():
            e.var("cx_exp", _operand(e, node, 1))
            e.var("cx_des", _operand(e, node, 2))
            e.var("cx_same", _fresh(e, "cx_l"))
            e.var("cx_long", e.flag(e.eq(_desc_get(e, result), D_J)))
            push(K_PUT, _output(e, node, 1))

            def tail_long():
                _compare_result_pushes(e, EQ_)
                push(K_OP, 0x94, 1)

            def tail_int():
                Fwd(e)(K_OP, 0x82597480, 4)(K_ICONST, 31)(K_OP, 0x7C, 1)(K_ICONST, 1)(K_OP, 0x82, 1).push()

            e.if_(e.ne(p["cx_long"], 0), tail_long, tail_int)
            push(K_GET, p["cx_exp"])
            push(K_GET, result)
            push(K_MARK, p["cx_same"])
            mem_access(e, False, p["at_size"], p["at_el"], p["cx_des"], at)
            e.if_(e.ne(p["cx_long"], 0), lambda: (push(K_BRANCH, 0x9A, p["cx_same"]), push(K_OP, 0x94, 1)), lambda: push(K_BRANCH, 0xA0, p["cx_same"]))
            push(K_GET, p["cx_exp"])
            push(K_GET, result)
            mem_access(e, True, p["at_size"], p["at_el"], result, at)
            e.give(1)

        e.if_(e.eq(opv, int(Operation.ATOMIC_CMPXCHG)), cmpxchg)

    e.if_(_in_ops(e, opv, ("ATOMIC_LOAD", "ATOMIC_STORE", "ATOMIC_RMW", "ATOMIC_CMPXCHG")), atomic)


def K_MASK_():
    from xax_selfhost_jvm_lower import K_MASK

    return K_MASK


# -- the threaded launcher (S15e.5i) ------------------------------------------------------------------------------------------

# ``<init>`` and ``run`` are byte strings in the bootstrap (no ``_Code``): their pool index positions, by call order.
LAUNCHER_RAW_SLOTS = {"<init>": ((2, 1),), "run": ((1, 2), (5, 0))}


def launcher_templates() -> tuple:
    """``_threaded_launcher``'s pool calls (in order) and its three members as (name, descriptor, bytes, slots,
    max stack, max locals, access)."""
    import xax_jvm

    pool = _RecordingPool()
    base, original_u2 = xax_jvm._Code, xax_jvm._u2
    slots: list[tuple[int, int]] = []

    class Recording(base):
        def raw(self, blob: bytes) -> None:
            if isinstance(blob, _PlaceholderBytes):
                slots.append((len(self.buf), blob.placeholder.seq))
            super().raw(blob)

    def u2(value):
        if isinstance(value, _Placeholder):
            blob = _PlaceholderBytes(b"\x00\x00")
            blob.placeholder = value
            return blob
        return original_u2(value)

    xax_jvm._Code, xax_jvm._u2 = Recording, u2
    try:
        methods = xax_jvm._threaded_launcher(pool, CLASS, "entry")
    finally:
        xax_jvm._Code, xax_jvm._u2 = base, original_u2
    out = []
    for method in methods:
        assert not method.frames and not method.lines
        own = tuple(slots) if method.name == "main" else LAUNCHER_RAW_SLOTS[method.name]
        for at, _seq in own:
            assert method.code[at:at + 2] == b"\x00\x00"
        out.append((method.name, method.descriptor, method.code, own, method.max_stack, method.max_locals, method.access))
    return tuple(call.call for call in pool.calls), tuple(out)


def check_launcher() -> None:
    """The launcher rebuilt from its template with a real pool equals ``_threaded_launcher``."""
    import xax_jvm

    calls, members = launcher_templates()
    reference_pool, pool = xax_jvm._Pool(), xax_jvm._Pool()
    reference = xax_jvm._threaded_launcher(reference_pool, "xax/P0123456789abcdef", "entry")
    indices = [getattr(pool, kind)(*["xax/P0123456789abcdef" if arg == CLASS else arg for arg in args]) for kind, *args in calls]
    rebuilt = []
    for name, descriptor, code, own, max_stack, max_locals, access in members:
        blob = bytearray(code)
        for at, seq in own:
            blob[at:at + 2] = struct.pack(">H", indices[seq])
        rebuilt.append((name, descriptor, bytes(blob), max_stack, max_locals, access))
    assert rebuilt == [(m.name, m.descriptor, m.code, m.max_stack, m.max_locals, m.access) for m in reference]
    assert pool.data == reference_pool.data


def _launcher_fn(tables):
    """``_threaded_launcher``: ``main`` starts ``run`` on a thread with ``ENTRY_STACK_BYTES`` of stack and joins it."""
    from xax_selfhost_jvm import (J_CLASSNAME, J_POOL, KIND_NAMED, MR_BARE, MR_CLEN, MR_CODE, MR_FIDX, MR_FRAMES, MR_FTYPES, MR_KIND, MR_LINES,
                                  MR_LOCALS, MR_NFRAMES, MR_NFTYPES, MR_NLINES, MR_STACK, _add_record, _js, _store_alloc)
    from xax_selfhost_jvm_class import klass_literal, literal, utf8_literal

    calls, members = launcher_templates()

    def build(e: E):
        p = e.p
        pool = _js(e, J_POOL)

        def klass(name: str, var: str):
            if name == CLASS:
                return _call(e, "jp_ref1", pool, 7, _call(e, "jp_utf8", pool, _js(e, J_CLASSNAME), 21))
            return klass_literal(e, pool, name, var)

        for seq, (kind, *args) in enumerate(calls):
            var = f"la_{seq}"
            if kind == "method":
                owner, name, descriptor = args
                e.var(f"{var}_c", klass(owner, f"{var}_o"))
                e.var(f"{var}_nt", _call(e, "jp_ref2", pool, 12, utf8_literal(e, pool, name, f"{var}_n"), utf8_literal(e, pool, descriptor, f"{var}_d"), 0, 0))
                arguments, result = descriptor_slots(descriptor)
                e.var(var, _call(e, "jp_ref2", pool, 10, p[f"{var}_c"], p[f"{var}_nt"], arguments, result))
            elif kind == "klass":
                e.var(var, klass(args[0], f"{var}_k"))
            elif kind == "string":
                e.var(var, _call(e, "jp_ref1", pool, 8, utf8_literal(e, pool, args[0], f"{var}_s")))
            else:
                assert kind == "long"
                e.var(var, _call(e, "jp_number", pool, 5, args[0]))
        for k, (name, descriptor, code, own, max_stack, max_locals, access) in enumerate(members):
            e.var(f"la_m{k}", _store_alloc(e, len(code) + 1, f"la_mc{k}"))
            at = p[f"la_m{k}"]
            filled = {position for start, _seq in own for position in (start, start + 1)}
            for q, byte in enumerate(code):
                if q not in filled:
                    e.st(e.add(at, q), byte)
            for start, seq in own:
                e.st(e.add(at, start), e.and_(e.udiv(p[f"la_{seq}"], 256), 255))
                e.st(e.add(at, start + 1), e.and_(p[f"la_{seq}"], 255))
            literal(e, f"la_n{k}", name)
            literal(e, f"la_d{k}", descriptor)
            e.var(f"la_r{k}", _store_alloc(e, 6, f"la_rs{k}"))
            for q, word in enumerate((p[f"la_n{k}"], len(name), p[f"la_d{k}"], len(descriptor), access)):
                e.st(e.add(p[f"la_r{k}"], q), word)
            _add_record(e, {MR_KIND: KIND_NAMED, MR_FIDX: p[f"la_r{k}"], MR_CODE: at, MR_CLEN: len(code), MR_STACK: max_stack, MR_LOCALS: max_locals,
                            MR_FRAMES: 0, MR_NFRAMES: 0, MR_FTYPES: 0, MR_NFTYPES: 0, MR_LINES: 0, MR_NLINES: 0, MR_BARE: NONE})
        e.give(1)
    return _function((), build, tables)
