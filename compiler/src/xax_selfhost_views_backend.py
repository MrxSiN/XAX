"""The instruction-set-neutral half of the XAX views-profile backends (ADR-141, ADR-145, ADR-151, ADR-152).

The XAX RISC-V backend (``xax_selfhost_riscv64_backend``) and the XAX x86-64 backend
(``xax_selfhost_x86_64_backend``) are each one XAX program built from these builders and
their own instruction-set hooks:

* the front end (S5b): store objects and graph-decoder streams to the internal stream --
  the closure, interfaces, widths, constants, view and aggregate aliases, and order;
* the per-function analysis (S5a): block liveness over bitsets, interval hulls, and a
  linear scan over the ISA's allocatable registers, then the frame's slots;
* parallel edge copies through temporaries; and
* the program driver: setup, one function at a time, jump patching, outputs.

An ISA supplies ``ARCHITECTURE``, ``ALLOCATABLE``, ``ARGUMENT_REGISTERS``, ``T0``,
``CODE_LIMIT``, and the hooks ``declare``, ``on_call``, ``saved_end``, ``frame_size``,
``prologue``, ``trap``, ``jump``, ``skip_target_machine``, and ``patch``, plus the XAX
functions the shared code calls by name (``frame``, ``read``, ``write``, ``block``, ...).
"""

from __future__ import annotations

from xax_compiler import Operation
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, HEADER, NONE, _function
from xax_selfhost_typing import IN_WORDS
import xax_selfhost_diagnostics as D

# Output regions (word indices of the output view).
# ADR-218: regions resized from measured use (the typing program: 3.5M code words, 19k jumps, 179k ranges) so the
# arena, which the largest function's liveness bitsets nearly filled, gains 3M words.
WORDS_AT, WORDS_LIMIT = 1 << 20, 5 << 20  # code: one word per RISC-V instruction or x86-64 byte
JUMPS_AT, JUMPS_LIMIT = 6 << 20, 1 << 19  # 3 words per jump
# ADR-276: the ranges and the stream doubled, so the general driver (the S10 driver with the general x86-64 backend
# program: 856k ranges, a 9M-word stream) fits; the stream starts after the diagnostic record (DIAG_AT), and the arena
# keeps 36M words.
RANGES_AT, RANGES_LIMIT = (6 << 20) + (1 << 19), 4 << 20  # 5 words per range
META_AT = (10 << 20) + (1 << 19)  # entry machine parameter and return widths; the function order
# ADR-266: the stream holds the compiler driver's closure (5M words); the output view doubled to 64M words.
STREAM_AT, STREAM_END = 12 << 20, 28 << 20  # the front end's internal stream (S5a format), read by the code generator
# S6c: the arena takes the rest; each function's scratch is reclaimed after it is lowered.
ARENA_AT, ARENA_END = 28 << 20, HEADER - 1
# Backend state in the header (after the argument words).
(S_COUNT, S_JUMPS, S_RANGES, S_FN, S_OFFSETS, S_REG, S_SLOT, S_WIDTH, S_TRAP, S_TRAP_USED, S_POW, S_FRAME, S_TEMPS,
 S_SAVED, S_BLOCK_LABELS, S_FALSE_LABELS, S_BASE, S_BLOCK_AT, S_LEVELS, S_AGG) = range(44, 64)
# ADR-151: the function's ``[outgoing argument bytes, hidden result pointer slot, result area table, area base]``.
A_OUT, A_POINTER, A_AREAS, A_BASE = range(4)
MAX_FIELDS = 255
OK = 1


# -- arithmetic (constant shifts become multiplies and unsigned divides) ------------------------

def _shl(e: E, value, amount: int):
    return e.mul(value, 1 << amount)


def _field(e: E, value, low: int, width: int):
    """Bits ``low .. low + width`` of ``value``."""
    return e.and_(e.udiv(value, 1 << low) if low else value, (1 << width) - 1)


def _ors(e: E, *parts):
    result = parts[0]
    for part in parts[1:]:
        result = e.or_(result, part)
    return result


def _xor(e: E, x, y):
    return e.bin(Operation.BIT_XOR, x, y)


def _sar(e: E, value, amount: int):
    """Arithmetic shift right by a constant."""
    logical = e.udiv(value, 1 << amount)
    fill = ((1 << 64) - 1) ^ ((1 << (64 - amount)) - 1)
    return e.or_(logical, e.sel(e.lt(value, 1 << 63), 0, fill))


# -- registry and value helpers --------------------------------------------------------------------

def _ok(e: E, condition):
    """Decline (NONE) unless ``condition``."""
    e.if_(e.not_(condition), lambda: e.give(NONE))


def _diagnostics(isa) -> str | None:
    """The ISA's diagnostic family (``XAX.<family>.*`` codes, ``<family>-*`` rules) when its program decides target
    legality and writes rejection diagnostics (S7b, ADR-179); None when it declines instead."""
    return getattr(isa, "DIAGNOSTICS", None)


# The views lowering's rejection rules (S7b): ``<family>-<rule>`` with code ``XAX.<family>.<code>``.
VIEWS_RULES = (
    ("OP-TARGET-SUPPORTED", "UNSUPPORTED_OPERATION"), ("TERMINATOR-TARGET-SUPPORTED", "UNSUPPORTED_TERMINATOR"), ("VALUE-BITS", "VALUE"),
    ("AGGREGATE-RESULT", "ABI"), ("AGGREGATE-VALUE", "UNSUPPORTED_OPERATION"), ("AGGREGATE-USE", "UNSUPPORTED_OPERATION"),
    ("SINGLE-RESULT", "ABI"), ("CHECKED-ACCESS", "UNSUPPORTED_OPERATION"), ("OP-LOWERED", "UNSUPPORTED_OPERATION"),
    ("CHECKED-BYTE-VIEW-WIDTH", "UNSUPPORTED_OPERATION"),  # ADR-231: an ISA without byte-view widening
)
# ADR-231: the expected value of ``<ISA>-CHECKED-BYTE-VIEW-WIDTH`` (an ISA whose wide loads may fault when misaligned).
BYTE_VIEW_WIDTH_EXPECTED = "1-byte checked access on a byte view (no misaligned wide access on this target)"


def _rules(isa) -> tuple[tuple[str, str], ...]:
    """The family's rules: the shared views rules, then the ISA's own (``EXTRA_RULES``, e.g. S10a's syscalls)."""
    return (*VIEWS_RULES, *getattr(isa, "EXTRA_RULES", ()))


def _diagnostic(tables, isa):
    """The record's code, entity CID, and rule for rule ``site`` on object ``entity``: one copy of each text."""
    family = _diagnostics(isa)

    def build(e: E):
        p = e.p
        for part in ("code", "rule"):
            for site, (rule, code) in enumerate(_rules(isa)):
                value = f"XAX.{family}.{code}" if part == "code" else f"{family}-{rule}"
                e.if_(e.eq(p["site"], site), lambda value=value: D.text(e, value))
            if part == "code":
                D.cid(e, _cid_words(e, p["entity"]))
        e.give(1)
    return _function(("site", "entity"), build, tables)


_FN: dict = {}


def _call(e: E, name, *arguments):
    result = e.call(_FN[name], *arguments)
    _ok(e, e.ne(result, NONE))
    return result


def _value(e: E, field: int, value):
    return e.ld(e.add(e.hd(field), value))


def _target(e: E, value, t0: int):
    """The register a value is computed in: its allocation, or ``t0``."""
    register = _value(e, S_REG, value)
    return e.sel(e.ne(register, 0), register, t0)


def _bit(e: E, value):
    return e.ld(e.add(e.hd(S_POW), e.urem(value, 64)))


def _put(e: E, bitset, value):
    word = e.add(bitset, e.udiv(value, 64))
    e.st(word, e.or_(e.ld(word), _bit(e, value)))


# -- one function ---------------------------------------------------------------------------------


# -- S5b: the front end (store objects and graph-decoder streams to the internal stream) -------------
#
# Input view: ``O, entry object, target object``, then per object ``[kind, reference count, reference object
# indices (NONE: not listed), CID as four big-endian words, payload length, payload]``.  The payload is the body,
# one byte per word, for types, constants, functions, and targets; a graph fragment's is the S3c graph-decoder
# stream (``xax_selfhost_graph``); other kinds have none.

GLOBALS = ARENA_AT  # the front end's table pointers (the first arena words)
(G_REC, G_PAY, G_TW, G_FIDX, G_ERASED, G_IFACE, G_SUP, G_SUPT, G_NI, G_O, G_ORDER, G_F, G_OUT, G_WIDTHS, G_FAR, G_SUP_AT, G_SUPT_AT, G_S,
 G_REFS, G_PENDING, G_PROCESS) = range(21)
CID_WORDS = 4
NI_OP, NI_ENTITY, NI_OPERANDS, NI_RESULTS, NI_ATTRIBUTES = range(5)


def _g(e: E, slot: int):
    return e.ld(GLOBALS + slot)


def _at(e: E, table: int, index):
    return e.ld(e.add(_g(e, table), index))


def _reference(e: E, obj, k):
    """Object index of ``obj``'s ``k``-th reference (NONE when that object is not listed), resolved by ``_find``."""
    return e.ld(e.add(_at(e, G_REFS, obj), k))


def _cid_at(e: E, obj):
    """The input position of object ``obj``'s own CID words (after its kind, reference count, and reference CIDs)."""
    record = _at(e, G_REC, obj)
    return e.add(e.add(record, 2), e.mul(e.rd(e.add(record, 1)), CID_WORDS))


def _cid_less(e: E, x_at, y_at):
    """The CID at input position ``x_at`` sorts before the one at ``y_at`` (four big-endian words)."""
    result, equal = e.c(0), e.c(1)
    for k in range(CID_WORDS):
        wx, wy = e.rd(e.add(x_at, k)), e.rd(e.add(y_at, k))
        result = e.or_(result, e.flag(e.both(e.ne(equal, 0), e.lt(wx, wy))))
        equal = e.flag(e.both(e.ne(equal, 0), e.eq(wx, wy)))
    return e.ne(result, 0)


def _cid_equal(e: E, x_at, y_at):
    return e.both(*(e.eq(e.rd(e.add(x_at, k)), e.rd(e.add(y_at, k))) for k in range(CID_WORDS)))


def _find(tables):
    """S7b.2: the object index whose CID is the one at input position ``at``, or NONE.  Store objects are in CID
    order (a verified store), so they are searched by bisection; the bound target follows them when the store does
    not hold it."""
    def build(e: E):
        p = e.p
        e.var("lo", 0)
        e.var("hi", _g(e, G_S))

        def halve():
            e.var("mid", e.udiv(e.add(p["lo"], p["hi"]), 2))
            e.if_(_cid_less(e, _cid_at(e, p["mid"]), p["at"]), lambda: e.set("lo", e.add(p["mid"], 1)), lambda: e.set("hi", p["mid"]))

        e.while_(lambda: e.lt(p["lo"], p["hi"]), halve)
        e.if_(e.lt(p["lo"], _g(e, G_S)), lambda: e.if_(_cid_equal(e, _cid_at(e, p["lo"]), p["at"]), lambda: e.give(p["lo"])))
        appended = e.both(e.lt(_g(e, G_S), _g(e, G_O)), _cid_equal(e, _cid_at(e, _g(e, G_S)), p["at"]))
        e.give(e.sel(appended, _g(e, G_S), NONE))
    return _function(("at",), build, tables)


def _kind(e: E, obj):
    return e.rd(_at(e, G_REC, obj))


def _cid_words(e: E, obj):
    """The four big-endian CID words of object ``obj``."""
    at = _cid_at(e, obj)
    return [e.rd(e.add(at, k)) for k in range(CID_WORDS)]


def _payload_uleb(e: E, name: str):
    """Read a ULEB at input word ``p[name]`` (one byte per word) and advance it."""
    from xax_selfhost_facts import _uleb

    p = e.p
    value, size, ok = _uleb(e, p[name])
    _ok(e, ok)
    e.set(name, e.add(p[name], size))
    return value


def _type_width(e: E, obj):
    """``_machine_width``: bits width <= 64, 0 for a proof value (effect or resource), else NONE."""
    from xax_compiler import Kind

    p = e.p
    e.var("tw", NONE)

    def typed():
        pay = _at(e, G_PAY, obj)
        first = e.rd(pay)
        e.if_(e.either(e.eq(first, 3), e.eq(first, 4)), lambda: e.set("tw", 0))
        e.if_(e.eq(first, 2), lambda: e.set("tw", 64))  # views profile: a pointer is one 64-bit address

        def bits():
            e.var("tw_at", e.add(pay, 1))
            width = _payload_uleb(e, "tw_at")
            e.if_(e.both(e.ne(width, 0), e.le(width, 64)), lambda: e.set("tw", width))

        e.if_(e.eq(first, 1), bits)

    known = e.lt(obj, _g(e, G_O))
    listed = e.sel(known, obj, 0)
    nonempty = e.ne(e.rd(e.sub(_at(e, G_PAY, listed), 1)), 0)
    e.if_(e.both(known, e.eq(_kind(e, listed), int(Kind.TYPE)), nonempty), typed)
    return p["tw"]


def _type_form(e: E, obj):
    """The first payload byte of listed, nonempty TYPE ``obj`` (NONE otherwise)."""
    from xax_compiler import Kind

    known = e.lt(obj, _g(e, G_O))
    listed = e.sel(known, obj, 0)
    pay = _at(e, G_PAY, listed)
    typed = e.both(known, e.eq(_kind(e, listed), int(Kind.TYPE)), e.ne(e.rd(e.sub(pay, 1)), 0))
    return e.sel(typed, e.rd(e.sel(typed, pay, 0)), NONE)


def _view_extent(e: E, obj):
    """``_heap_view_info``: the instance (extent) of heap-view type ``obj``; 0 when it is not a heap view."""
    p = e.p
    e.var("vx", 0)

    def resource():
        pay = _at(e, G_PAY, obj)
        e.var("vx_at", e.add(pay, 1))
        e.var("vx_end", e.add(pay, e.rd(e.sub(pay, 1))))
        kind = _payload_uleb(e, "vx_at")
        e.var("vx_kind", kind)
        state = _payload_uleb(e, "vx_at")
        e.var("vx_state", state)

        def described():
            _payload_uleb(e, "vx_at")  # flags
            instance = _payload_uleb(e, "vx_at")
            e.if_(e.both(e.eq(p["vx_kind"], 0x101), e.either(e.eq(p["vx_state"], 1), e.eq(p["vx_state"], 2))), lambda: e.set("vx", instance))

        e.if_(e.lt(p["vx_at"], p["vx_end"]), described)

    e.if_(e.eq(_type_form(e, obj), 4), resource)
    return p["vx"]


def _aggregate(tables):
    """``_aggregate_fields`` (ADR-151): the field count of TYPE ``t``, a tuple or array of ``bits<N <= 64>``; 0 otherwise."""
    def build(e: E):
        p = e.p
        obj = p["t"]
        form = _type_form(e, obj)
        e.var("ag_form", form)
        e.var("ag_count", 0)
        e.var("ag_ok", 1)

        def scalar(field):
            known = e.ne(field, NONE)
            width = _type_width(e, e.sel(known, field, 0))
            return e.both(known, e.eq(_type_form(e, e.sel(known, field, 0)), 1), e.ne(width, 0), e.le(width, 64))

        def tuple_():
            e.var("ag_at", e.add(_at(e, G_PAY, obj), 1))
            e.set("ag_count", _payload_uleb(e, "ag_at"))
            e.for_("q", 0, p["ag_count"], lambda: e.if_(e.not_(scalar(_reference(e, obj, _payload_uleb(e, "ag_at")))), lambda: e.set("ag_ok", 0)))

        def array_():
            e.var("ag_at", e.add(_at(e, G_PAY, obj), 1))
            element = _reference(e, obj, _payload_uleb(e, "ag_at"))
            e.var("ag_element", element)
            e.set("ag_count", _payload_uleb(e, "ag_at"))
            e.if_(e.not_(scalar(p["ag_element"])), lambda: e.set("ag_ok", 0))

        e.if_(e.eq(p["ag_form"], 8), tuple_, lambda: e.if_(e.eq(p["ag_form"], 9), array_))
        e.give(e.sel(e.both(e.ne(p["ag_ok"], 0), e.ne(p["ag_count"], 0), e.le(p["ag_count"], MAX_FIELDS)), p["ag_count"], 0))
    return _function(("t",), build, tables)


def _target_list(e: E, slot: int):
    """The target's operation (or terminator) list, in its payload order, as a diagnostic LIST of INTs."""
    p = e.p
    e.var("dg_at", _g(e, slot))
    e.var("dg_n", _payload_uleb(e, "dg_at"))
    D.put(e, D.T_LIST)
    D.put(e, p["dg_n"])
    e.for_("dg_q", 0, p["dg_n"], lambda: D.integer(e, _payload_uleb(e, "dg_at")))


# S10a (ADR-264): a lowered syscall's template record (arena words): number, argument count, allocator flag (S10b,
# ADR-265: a nullable allocator result), then per argument (tag, value): tag 0 names machine operand ``value``, tag 1
# is the literal ``value``.
SYSCALL_HEADER = 3
SYSCALL_RECORD = SYSCALL_HEADER + 2 * 6
_FOREIGN_PREFIX = b"foreign-function-v1"
_SYSCALL_ABI = b"linux-x86_64-syscall-v1"
# S11 (ADR-267): a startup read's record is ``(STARTUP_*, operands, 0, (0, k)...)`` (``xax_x86_64_views.STARTUP_READS``).
_STARTUP_ABI = b"linux-x86_64-startup-v1"
assert len(_STARTUP_ABI) == len(_SYSCALL_ABI)


def _syscall(tables, abi: bytes = _SYSCALL_ABI):
    """``xax_x86_64_views.syscall_template`` for declaration object ``obj`` and ``m`` machine operands: the template
    record (``SYSCALL_RECORD``), or 0 when the views profile does not lower the call (a declaration of another ABI,
    or a template ``decode_syscall_name`` rejects).  The caller checks the result count; the verifier has already
    checked the declaration's heap contracts, which are only skipped here (an allocator's flag is recorded).  S11: a
    ``linux-x86_64-startup-v1`` declaration of a read in ``STARTUP_READS`` with its machine operands and no heap
    contract gives the startup record.  S15e.2 (ADR-315): ``abi`` another syscall ABI (``linux-aarch64-syscall-v1``),
    without startup reads."""
    from xax_x86_64_views import STARTUP_READS

    def build(e: E):
        p = e.p
        e.var("sy_ok", 1)
        e.var("sy_at", _at(e, G_PAY, p["obj"]))
        e.var("sy_end", 0)
        e.set("sy_end", e.add(_payload_uleb(e, "sy_at"), p["sy_at"]))

        def same(data: bytes):
            for k, value in enumerate(data):
                e.if_(e.ne(e.rd(e.add(p["sy_at"], k)), value), lambda: e.set("sy_ok", 0))
            e.set("sy_at", e.add(p["sy_at"], len(data)))

        # The identity: the prefix, the ABI, the library, the name, the input and output CIDs, then the heap contracts.
        same(_FOREIGN_PREFIX)
        e.if_(e.ne(_payload_uleb(e, "sy_at"), len(abi)), lambda: e.give(0))
        if abi == _SYSCALL_ABI:
            e.var("sy_startup", p["sy_ok"])
            for k, (syscall_byte, startup_byte) in enumerate(zip(_SYSCALL_ABI, _STARTUP_ABI)):
                byte_at = e.rd(e.add(p["sy_at"], k))
                e.var("sy_b", byte_at)
                e.if_(e.ne(p["sy_b"], syscall_byte), lambda: e.set("sy_ok", 0))
                e.if_(e.ne(p["sy_b"], startup_byte), lambda: e.set("sy_startup", 0))
        else:
            e.var("sy_startup", 0)
            for k, syscall_byte in enumerate(abi):
                e.if_(e.ne(e.rd(e.add(p["sy_at"], k)), syscall_byte), lambda: e.set("sy_ok", 0))
        e.set("sy_at", e.add(p["sy_at"], len(abi)))
        e.if_(e.both(e.eq(p["sy_ok"], 0), e.eq(p["sy_startup"], 0)), lambda: e.give(0))
        e.set("sy_at", e.add(_payload_uleb(e, "sy_at"), p["sy_at"]))
        e.var("sy_len", _payload_uleb(e, "sy_at"))
        e.var("sy_pos", p["sy_at"])
        e.var("sy_stop", e.add(p["sy_at"], p["sy_len"]))
        e.set("sy_at", p["sy_stop"])
        for _group in range(2):
            e.set("sy_at", e.add(e.mul(_payload_uleb(e, "sy_at"), 32), p["sy_at"]))
        e.var("sy_alloc", 0)

        def allocator():  # tag 1: size inputs, pointer output, token output, alignment, zeroed
            _payload_uleb(e, "sy_at")
            e.for_("sy_q", 0, _payload_uleb(e, "sy_at"), lambda: _payload_uleb(e, "sy_at"))
            for _field in range(4):
                _payload_uleb(e, "sy_at")
            e.set("sy_alloc", 1)

        def deallocator():  # tag 2: pointer input, token input
            for _field in range(3):
                _payload_uleb(e, "sy_at")
            e.set("sy_alloc", 2)

        e.if_(e.both(e.lt(p["sy_at"], p["sy_end"]), e.eq(e.rd(p["sy_at"]), 1)), allocator)
        e.if_(e.both(e.lt(p["sy_at"], p["sy_end"]), e.eq(e.rd(p["sy_at"]), 2)), deallocator)
        e.if_(e.ne(p["sy_at"], p["sy_end"]), lambda: e.give(0))
        e.var("sy_rec", e.alloc(SYSCALL_RECORD))
        _ok(e, e.ne(p["sy_rec"], NONE))

        def startup():
            """The read named ``sy_pos .. sy_stop``, with exactly its machine operands, in operand order."""
            e.if_(e.ne(p["sy_alloc"], 0), lambda: e.give(0))
            for name, (number, operands) in STARTUP_READS.items():
                def named(name=name):
                    for k, value in enumerate(name):
                        e.if_(e.ne(e.rd(e.add(p["sy_pos"], k)), value), lambda: e.set("sy_named", 0))

                e.var("sy_named", e.flag(e.both(e.eq(p["sy_len"], len(name)), e.eq(p["m"], operands))))
                e.if_(e.ne(p["sy_named"], 0), named)

                def record(number=number, operands=operands):
                    for slot, value in enumerate((number, operands, 0, *(word for k in range(operands) for word in (0, k)))):
                        e.st(e.add(p["sy_rec"], slot), value)
                    e.give(p["sy_rec"])

                e.if_(e.ne(p["sy_named"], 0), record)
            e.give(0)

        e.if_(e.eq(p["sy_ok"], 0), startup)
        e.set("sy_alloc", e.flag(e.eq(p["sy_alloc"], 1)))

        def byte():
            """The name byte at ``sy_pos``; 256 past its end."""
            inside = e.lt(p["sy_pos"], p["sy_stop"])
            return e.sel(inside, e.rd(e.sel(inside, p["sy_pos"], p["sy_at"])), 256)

        def number(name: str, limit: int):
            """Digits at ``sy_pos``: ``name`` (valid unless ``name_o``: above ``limit``), their count ``name_n``, the
            first ``name_f``."""
            e.var(name, 0)
            e.var(f"{name}_n", 0)
            e.var(f"{name}_o", 0)
            e.var(f"{name}_f", byte())

            def step():
                d = e.sub(byte(), 48)
                e.var("sy_d", d)
                fits = e.le(p[name], e.udiv(e.sub(limit, p["sy_d"]), 10))
                e.if_(fits, lambda: e.set(name, e.add(e.mul(p[name], 10), p["sy_d"])), lambda: e.set(f"{name}_o", 1))
                e.set(f"{name}_n", e.add(p[f"{name}_n"], 1))
                e.set("sy_pos", e.add(p["sy_pos"], 1))

            e.while_(lambda: e.both(e.le(48, byte()), e.le(byte(), 57)), step)

        def canonical(name: str):
            """A nonempty decimal without a leading zero, at most ``limit``."""
            return e.both(e.ne(p[f"{name}_n"], 0), e.either(e.eq(p[f"{name}_n"], 1), e.ne(p[f"{name}_f"], 48)), e.eq(p[f"{name}_o"], 0))

        number("sy_nr", (1 << 31) - 1)
        e.if_(e.not_(canonical("sy_nr")), lambda: e.set("sy_ok", 0))
        e.st(p["sy_rec"], p["sy_nr"])
        e.st(e.add(p["sy_rec"], 2), p["sy_alloc"])
        e.var("sy_n", 0)

        def put(tag, value):
            """Argument ``sy_n``; a seventh is invalid (Linux x86-64 syscalls take at most six)."""
            def store():
                at = e.add(p["sy_rec"], e.add(SYSCALL_HEADER, e.mul(p["sy_n"], 2)))
                e.st(at, tag)
                e.st(e.add(at, 1), value)
                e.set("sy_n", e.add(p["sy_n"], 1))

            e.if_(e.lt(p["sy_n"], 6), store, lambda: e.set("sy_ok", 0))

        def operands_in_order():
            e.if_(e.lt(6, p["m"]), lambda: e.set("sy_ok", 0), lambda: e.for_("sy_k", 0, p["m"], lambda: put(0, p["sy_k"])))

        def template():
            e.set("sy_pos", e.add(p["sy_pos"], 1))
            e.var("sy_used", 0)  # bit k: machine operand k is named (k < 6 for any valid template)
            e.var("sy_refs", 0)
            e.var("sy_go", 1)

            def item():
                def reference():
                    e.set("sy_pos", e.add(p["sy_pos"], 1))
                    number("sy_k", 1000)  # "$" and any digits, leading zeros included (``str.isdigit``)
                    bit = e.c(0)
                    for k in range(6):
                        bit = e.add(bit, e.mul(e.flag(e.eq(p["sy_k"], k)), 1 << k))
                    e.var("sy_bit", bit)
                    fresh = e.both(e.ne(p["sy_k_n"], 0), e.lt(p["sy_k"], p["m"]), e.ne(p["sy_bit"], 0), e.eq(e.and_(p["sy_used"], p["sy_bit"]), 0))
                    e.if_(fresh, lambda: (e.set("sy_used", e.or_(p["sy_used"], p["sy_bit"])), e.set("sy_refs", e.add(p["sy_refs"], 1))),
                          lambda: e.set("sy_ok", 0))
                    put(0, p["sy_k"])

                def literal():
                    number("sy_lit", (1 << 64) - 1)
                    e.if_(e.not_(canonical("sy_lit")), lambda: e.set("sy_ok", 0))
                    put(1, p["sy_lit"])

                e.if_(e.eq(byte(), 36), reference, literal)  # "$"
                e.if_(e.le(p["sy_stop"], p["sy_pos"]), lambda: e.set("sy_go", 0), lambda: e.if_(
                    e.eq(byte(), 44), lambda: e.set("sy_pos", e.add(p["sy_pos"], 1)), lambda: (e.set("sy_ok", 0), e.set("sy_go", 0))))  # ","

            e.while_(lambda: e.both(e.ne(p["sy_go"], 0), e.ne(p["sy_ok"], 0)), item)
            e.if_(e.ne(p["sy_refs"], p["m"]), lambda: e.set("sy_ok", 0))

        e.if_(e.le(p["sy_stop"], p["sy_pos"]), operands_in_order, lambda: e.if_(e.eq(byte(), 58), template, lambda: e.set("sy_ok", 0)))  # ":"
        e.st(e.add(p["sy_rec"], 1), p["sy_n"])
        e.give(e.mul(e.flag(e.ne(p["sy_ok"], 0)), p["sy_rec"]))
    return _function(("obj", "m"), build, tables)


def stream(isa):
    """The ISA's internal stream region (an ISA may keep a larger one above its arena)."""
    return getattr(isa, "STREAM_AT", STREAM_AT), getattr(isa, "STREAM_END", STREAM_END)


# -- the program -----------------------------------------------------------------------------------

def _program(tables, compile_function, isa):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, ARENA_AT + 64)  # the front end's GLOBALS come first
        e.set_hd(H_ARENA_END, getattr(isa, "ARENA_END", ARENA_END))  # an ISA may keep fixed regions above its arena
        e.set_hd(S_COUNT, 0)
        e.set_hd(S_JUMPS, 0)
        e.set_hd(S_RANGES, 0)
        powers = e.alloc(64)
        e.var("power", 1)
        e.for_("z", 0, 64, lambda: (e.st(e.add(powers, p["z"]), p["power"]), e.set("power", e.mul(p["power"], 2))))
        e.set_hd(S_POW, powers)
        e.set_hd(S_LEVELS, e.alloc(32))
        _ok(e, e.ne(e.call(_FN["frontend"]), NONE))
        functions = e.ld(stream(isa)[0])
        offsets = e.alloc(e.add(functions, 1))
        _ok(e, e.ne(offsets, NONE))
        e.set_hd(S_OFFSETS, offsets)
        e.for_("f", 0, functions, lambda: e.st(e.add(offsets, p["f"]), NONE))
        e.var("cursor", stream(isa)[0] + 1)

        def each():
            e.set("cursor", e.call(compile_function, p["cursor"], p["f"]))
            _ok(e, e.ne(p["cursor"], NONE))
            _ok(e, e.lt(e.hd(S_COUNT), isa.CODE_LIMIT))

        e.for_("f", 0, functions, each)
        isa.patch(e)
        # S7b.2: the image record -- each function's CID and code range, in layout order.
        e.var("image", e.alloc(e.mul(functions, CID_WORDS + 1)))
        _ok(e, e.ne(p["image"], NONE))

        def describe():
            at = e.add(p["image"], e.mul(p["f"], CID_WORDS + 1))
            for k, word in enumerate(_cid_words(e, e.ld(e.add(_g(e, G_ORDER), p["f"])))):
                e.st(e.add(at, k), word)
            last = e.eq(e.add(p["f"], 1), functions)
            e.st(e.add(at, CID_WORDS), e.sel(last, e.hd(S_COUNT), e.ld(e.add(offsets, e.sel(last, 0, e.add(p["f"], 1))))))

        e.for_("f", 0, functions, describe)
        if _diagnostics(isa):  # a deferred rejection (``_legal``) wins over the finished image
            e.if_(e.ne(_g(e, G_PENDING), 0), lambda: (e.st(0, D.REJECT), e.give(NONE)))
        e.st(1, e.hd(S_COUNT))
        e.st(2, e.hd(S_RANGES))
        e.st(3, offsets)
        e.st(4, p["image"])
        e.st(5, _g(e, G_WIDTHS))
        e.st(0, OK)
        e.give(1)
    return _function((), build, tables)


# -- outputs and native execution ---------------------------------------------------------------------

def collect_program_output(read, read_code=None, read_ranges=None, stream_at=STREAM_AT):
    """A backend program's result from its output view, read as ``read(start word, count)`` wherever it ran:
    ``(code units, function CIDs in layout order, their start and end offsets in code units, node ranges by layout
    position, entry parameter widths, entry return widths)``, or None (declined).  A code unit is a RISC-V instruction
    word or an x86-64 byte.  Every field is the program's (S7b.2); this only reads words.  ``read_code(count)`` and
    ``read_ranges(count)`` read an ISA's packed encodings (ADR-266: the x86-64 program packs both)."""
    status, count, ranges, offsets_at, image_at, widths_at = read(0, 6)
    if status != OK:
        return None
    (functions,) = read(stream_at, 1)
    code = read(WORDS_AT, count) if read_code is None else read_code(count)
    image = read(image_at, functions * (CID_WORDS + 1))
    records = [image[k:k + CID_WORDS + 1] for k in range(0, len(image), CID_WORDS + 1)]
    cids = [b"".join(word.to_bytes(8, "big") for word in record[:CID_WORDS]) for record in records]
    offsets = list(zip(read(offsets_at, functions), (record[CID_WORDS] for record in records)))
    if read_ranges is None:
        flat = read(RANGES_AT, 5 * ranges)
        node_ranges = [tuple(flat[k : k + 5]) for k in range(0, len(flat), 5)]
    else:
        node_ranges = read_ranges(ranges)
    (parameters,) = read(widths_at, 1)
    parameter_widths = tuple(read(widths_at + 1, parameters))
    returns_at = widths_at + 1 + parameters
    (returns,) = read(returns_at, 1)
    return_widths = tuple(read(returns_at + 1, returns))
    return code, cids, offsets, node_ranges, parameter_widths, return_widths


class NativeProgram:
    """A backend program's committed store (frozen, W2: ADR-361), its x86-64 image (``host_image``, cached on disk), and
    an in-process runner."""

    def __init__(self, store_path, cache_name: str) -> None:
        self.store_path, self.cache_name = store_path, cache_name
        self._native: list = []
        self._building = False

    def load(self):
        """``(reader, function)``: the committed store and its entry."""
        from xax_compiler import Kind, StoreReader
        from xax_native import verify_component_store

        reader = StoreReader(self.store_path.read_bytes())
        verify_component_store(reader, self.store_path.stem)
        module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
        function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
        return reader, function

    def image(self) -> tuple[bytes, int]:
        """``(machine code, entry offset)``: lowered for this host by the XAX x86-64 backend (ADR-152)."""
        from xax_selfhost_x86_64_backend import host_image

        return host_image(*self.load(), self.cache_name)

    def native(self, opt_out: str):
        """The shared in-process runner, or None where it cannot run (or when ``opt_out`` is set to 1)."""
        import os
        import platform
        import sys

        if self._building:
            return None  # its own image is being made: the bootstrap generator lowers it
        if not self._native:
            import xax_native

            usable = xax_native.usable(self.cache_name, self.store_path, opt_out)
            self._building = True
            try:
                self._native.append(_NativeRunner(*self.image()) if usable else None)
            except (OSError, RuntimeError, ValueError) as error:
                self._native.append(None)
                xax_native.fallback(self.cache_name, f"native image failed to load: {error!r}")
            finally:
                self._building = False
        return self._native[0]


class _NativeRunner:
    """Calls a views program ``(in view, out view)`` through the Win64 thunk; serialised by a lock."""

    def __init__(self, code: bytes, entry_offset: int) -> None:
        import ctypes
        import mmap
        import threading

        from xax_selfhost_typing import OUT_WORDS
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

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

    def run(self, words: list[int], collect):
        """``collect(read)`` after running on input ``words``; None when the words do not fit."""
        import ctypes

        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            return collect(lambda start, count: list(out[start : start + count]))
