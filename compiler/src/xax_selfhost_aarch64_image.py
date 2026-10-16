"""Self-hosting step S15e.2 (ADR-315): the AArch64 bundle and its Linux ELF64 container as XAX functions.

``xax_aarch64.compile_aarch64_bundle_bound_target`` and ``xax_linux_aarch64.emit_linux_aarch64_executable`` after the
per-function code (``xax_selfhost_aarch64_emit``): the text is a 16-byte entry stub (``bl`` to the entry, then
``brk #0x5841``), one thunk per distinct foreign symbol in call order (a ``linux-aarch64-syscall-v1`` template, or
three words an ``aapcs64-linux-c`` import binds to its GOT slot), each padded to 16 bytes with zeros, then the bundle:
every closure function in CID order at a 16-byte boundary (``nop`` padding), its direct calls bound, its foreign calls
branched to their thunks.  The container is the static ``ET_EXEC`` (one read/execute segment) or, for
``aarch64-linux-elf-dynexec-v1``, the dynamic one (``PT_INTERP``, ``DT_NEEDED``, a one-bucket hash, ``GLOB_DAT``
relocations, bind-now GOT slots).

Each function's code is staged as it is emitted (``a64_image_add``); the assembly runs once every closure function
is emitted.  Where the bootstrap fails (a call out of ``bl`` range, an import symbol in two libraries) or a capacity is
reached, the record says "not decided" and the host assembles.

The record is ``xax_selfhost_general_image``'s at ``IMAGE_AT`` (the driver reads its status, code and ELF the same
way): the status, the bundle code (before the foreign calls are bound), the ELF bytes, the bundle's file offset, the
entry's bundle offset, then per closure function (image order) its bundle offset, code length, and node ranges
(block, node, start, end), the foreign calls (bundle position, library, name), and the ``DT_NEEDED`` libraries.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_image import (
    BASE_ADDRESS, DT_FLAGS, DT_FLAGS_1, DT_HASH, DT_NEEDED, DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_STRSZ, DT_STRTAB, DT_SYMENT,
    DT_SYMTAB, DF_1_NOW, DF_BIND_NOW, ELF_HEADER, I_COUNT, I_CURSOR, I_ELEN, I_ELF, I_IMG, I_LEN, I_NNEEDED, I_OK, I_OUT, IMAGE_AT,
    IMAGE_BUFFER_AT, PF_R, PF_W, PF_X, PROGRAM_HEADER, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_PHDR, RELA, SYMBOL, _align, _cid_less, _elf,
    _foreign_strings, _less_input, _out, _out_bytes, _out_input, _program_header, _same_input, _stack_header,
)
from xax_selfhost_general_regalloc import _ra, _set_ra
from xax_selfhost_views_backend import _FN, _call, _g, _ok

# The staging area (each function's code as emitted, one byte per word) and the text, at the general program's image
# buffer (between the diagnostic record and the views backend's globals).
STAGE_AT, STAGE_CAP = IMAGE_BUFFER_AT, 6 << 20
TEXT_AT, TEXT_CAP = IMAGE_BUFFER_AT + (6 << 20), 6 << 20
FUNCTIONS, CALLS, RANGES, THUNKS = 1 << 16, 1 << 18, 1 << 19, 1 << 12
FN_WORDS = 7  # per closure function: stage start, length, first call, calls, first range, ranges, bundle offset
# State (``_ra`` slots: the x86-64 image's, which this program does not otherwise use).
(J_FNS, J_STAGED, J_CALLS, J_NCALLS, J_RANGES, J_NRANGES, J_ORDER, J_THUNKS, J_NTHUNKS, J_BASE, J_NAMES, J_NNAMES, J_NEEDED,
 J_ENTRY) = range(240, 254)
SEGMENT_ALIGN = 0x10000
INTERPRETER = b"/lib/ld-linux-aarch64.so.1\x00"
R_AARCH64_GLOB_DAT = 1025
DYNAMIC_FORMAT = 7
NOP, BRK_ENTRY_RETURNED, SVC0, RET = 0xD503201F, 0x5841, 0xD4000001, 0xD65F03C0
KERNEL_ERROR_TO_NULL = (0xB13FFC1F, 0x9A8023E0)
SYSCALL_STAGING = 9


def _put_text(e: E, word, n):
    """Append the ``n`` low bytes of ``word`` (little endian) to the text."""
    p = e.p
    e.var("pt_len", _ra(e, I_LEN))
    _ok(e, e.le(e.add(p["pt_len"], n), TEXT_CAP))
    e.var("pt_w", word)
    e.for_("pt_k", 0, n, lambda: (e.st(e.add(e.add(TEXT_AT, p["pt_len"]), p["pt_k"]), e.and_(p["pt_w"], 255)), e.set("pt_w", e.udiv(p["pt_w"], 256))))
    _set_ra(e, I_LEN, e.add(p["pt_len"], n))


def _patch(e: E, at, word):
    """Overwrite the text word at byte ``at``."""
    p = e.p
    e.var("pa_w", word)
    e.var("pa_at", e.add(TEXT_AT, at))
    e.for_("pa_k", 0, 4, lambda: (e.st(e.add(p["pa_at"], p["pa_k"]), e.and_(p["pa_w"], 255)), e.set("pa_w", e.udiv(p["pa_w"], 256))))


def _fn(e: E, fidx, field: int):
    return e.add(e.add(_ra(e, J_FNS), e.mul(fidx, FN_WORDS)), field)


def _bl(e: E, position, target):
    """``bl`` from text byte ``position`` to ``target`` (both 4-aligned); NONE out of the signed 26-bit range."""
    displacement = e.sub(e.add(target, 1 << 40), position)  # biased: 2^40 + target - position
    in_range = e.both(e.le((1 << 40) - (1 << 27), displacement), e.lt(displacement, (1 << 40) + (1 << 27)))
    return e.sel(in_range, e.add(0x94000000, e.and_(e.udiv(e.sub(displacement, (1 << 40) - (1 << 28)), 4), 0x3FFFFFF)), NONE)


# -- staging -----------------------------------------------------------------------------------------------------------

def image_prologue(e: E):
    """The staging tables (once, before the views)."""
    for slot, words in ((J_FNS, FN_WORDS * FUNCTIONS), (J_CALLS, 3 * CALLS), (J_RANGES, 4 * RANGES), (J_ORDER, FUNCTIONS), (J_THUNKS, 3 * THUNKS),
                        (J_NAMES, THUNKS), (J_NEEDED, THUNKS)):
        at = e.alloc(words)
        _ok(e, e.ne(at, NONE))
        _set_ra(e, slot, at)
    for slot in (J_STAGED, J_NCALLS, J_NRANGES, I_COUNT, I_LEN, I_ELEN, I_NNEEDED, I_ELF):
        _set_ra(e, slot, 0)
    _set_ra(e, I_IMG, TEXT_AT)
    _set_ra(e, I_OK, 1)


def _image_add_fn(tables):
    """Stage function ``fidx``'s emitted code, its calls (position, callee or declaration, 1 when foreign), and its node
    ranges; ``I_OK`` falls when a capacity is reached (the host then assembles)."""
    from xax_selfhost_aarch64_emit import X_CALLS, X_CODE, X_LEN, X_NCALLS, X_NRANGES, X_RANGES, _a

    def build(e: E):
        p = e.p
        e.var("sa_start", _ra(e, J_STAGED))
        e.var("sa_n", _a(e, X_LEN))
        e.var("sa_fits", e.flag(e.both(e.le(e.add(p["sa_start"], p["sa_n"]), STAGE_CAP), e.le(e.add(_ra(e, J_NCALLS), _a(e, X_NCALLS)), CALLS),
                                       e.le(e.add(_ra(e, J_NRANGES), _a(e, X_NRANGES)), RANGES), e.lt(p["fidx"], FUNCTIONS))))
        e.if_(e.eq(p["sa_fits"], 0), lambda: (_set_ra(e, I_OK, 0), e.give(0)))
        e.for_("sa_k", 0, p["sa_n"], lambda: e.st(e.add(STAGE_AT, e.add(p["sa_start"], p["sa_k"])), e.ld(e.add(_a(e, X_CODE), p["sa_k"]))))
        _set_ra(e, J_STAGED, e.add(p["sa_start"], p["sa_n"]))
        for field, value in ((0, p["sa_start"]), (1, p["sa_n"]), (2, _ra(e, J_NCALLS)), (3, _a(e, X_NCALLS)), (4, _ra(e, J_NRANGES)), (5, _a(e, X_NRANGES))):
            e.st(_fn(e, p["fidx"], field), value)

        def call():
            e.var("sa_src", e.add(_a(e, X_CALLS), e.mul(p["sa_k"], 2)))
            e.var("sa_t", e.ld(e.add(p["sa_src"], 1)))
            e.var("sa_dst", e.add(_ra(e, J_CALLS), e.mul(e.add(_ra(e, J_NCALLS), p["sa_k"]), 3)))
            e.var("sa_foreign", e.flag(e.le(1 << 40, p["sa_t"])))
            e.st(p["sa_dst"], e.ld(p["sa_src"]))
            e.st(e.add(p["sa_dst"], 1), e.sub(p["sa_t"], e.mul(p["sa_foreign"], 1 << 40)))
            e.st(e.add(p["sa_dst"], 2), p["sa_foreign"])

        e.for_("sa_k", 0, _a(e, X_NCALLS), call)
        _set_ra(e, J_NCALLS, e.add(_ra(e, J_NCALLS), _a(e, X_NCALLS)))
        e.var("sa_r", e.add(_ra(e, J_RANGES), e.mul(_ra(e, J_NRANGES), 4)))
        e.for_("sa_k", 0, e.mul(_a(e, X_NRANGES), 4), lambda: e.st(e.add(p["sa_r"], p["sa_k"]), e.ld(e.add(_a(e, X_RANGES), p["sa_k"]))))
        _set_ra(e, J_NRANGES, e.add(_ra(e, J_NRANGES), _a(e, X_NRANGES)))
        _set_ra(e, I_COUNT, e.add(_ra(e, I_COUNT), 1))
        e.give(1)
    return _function(("fidx",), build, tables)


# -- thunks ------------------------------------------------------------------------------------------------------------

def _thunk_fn(tables):
    """``syscall_thunk``: declaration ``obj``'s template (operands staged in x9.., each argument placed in x0..x5, a
    literal by ``movz``/``movk``), the number in x8, ``svc #0``, an allocator's error made null, ``ret``.  Declined (the
    host fails) for a template ``decode_syscall_name`` rejects."""
    def build(e: E):
        p = e.p
        _foreign_strings(e, p["obj"], "th_f")
        e.var("th_template", 0)
        e.var("th_m", 0)

        def scan():
            e.var("th_b", e.rd(e.add(p["th_f_sym"], p["th_k"])))
            e.if_(e.eq(p["th_b"], 58), lambda: e.set("th_template", 1))  # ":"
            e.if_(e.both(e.ne(p["th_template"], 0), e.eq(p["th_b"], 36)), lambda: e.set("th_m", e.add(p["th_m"], 1)))  # "$"

        e.for_("th_k", 0, p["th_f_symn"], scan)
        e.var("th_rec", e.call(_FN["a64_syscall"], p["obj"], p["th_m"]))
        _ok(e, e.both(e.ne(p["th_rec"], NONE), e.ne(p["th_rec"], 0)))

        def movimm(register, value):
            """``xax_aarch64._move_immediate(register, value, 64)``: ``movz`` of the low half, ``movk`` of each other nonzero half."""
            e.var("th_v", value)
            _put_text(e, e.add(e.add(0xD2800000, e.mul(e.and_(p["th_v"], 0xFFFF), 32)), register), 4)
            for half in (1, 2, 3):
                e.var("th_part", e.and_(e.udiv(p["th_v"], 1 << (16 * half)), 0xFFFF))
                e.if_(e.ne(p["th_part"], 0), lambda half=half: _put_text(e, e.add(e.add(0xF2800000 + (half << 21), e.mul(p["th_part"], 32)), register), 4))

        def template():
            # ``mov x(9 + k), xk`` for each operand.
            e.for_("th_k", 0, p["th_m"], lambda: _put_text(e, e.add(e.add(0xAA0003E0, e.mul(p["th_k"], 1 << 16)), e.add(SYSCALL_STAGING, p["th_k"])), 4))

            def argument():
                e.var("th_at", e.add(e.add(p["th_rec"], 3), e.mul(p["th_r"], 2)))
                e.var("th_tag", e.ld(p["th_at"]))
                e.var("th_val", e.ld(e.add(p["th_at"], 1)))
                e.if_(e.eq(p["th_tag"], 0), lambda: _put_text(e, e.add(e.add(0xAA0003E0, e.mul(e.add(SYSCALL_STAGING, p["th_val"]), 1 << 16)), p["th_r"]), 4),
                      lambda: movimm(p["th_r"], p["th_val"]))

            e.for_("th_r", 0, e.ld(e.add(p["th_rec"], 1)), argument)

        e.if_(e.ne(p["th_template"], 0), template)
        movimm(8, e.ld(p["th_rec"]))
        _put_text(e, SVC0, 4)
        e.if_(e.ne(e.ld(e.add(p["th_rec"], 2)), 0), lambda: [_put_text(e, word, 4) for word in KERNEL_ERROR_TO_NULL])
        _put_text(e, RET, 4)
        e.give(1)
    return _function(("obj",), build, tables)


# -- the bundle and the text --------------------------------------------------------------------------------------------

def _image_finish_fn(tables):
    """The text (stub, thunks, the bundle with its calls bound), the record's code, then the container."""
    from xax_selfhost_aarch64_emit import ABI_C_CLASS, ABI_SYSCALL_CLASS, _foreign_class
    from xax_selfhost_views_backend import G_ORDER
    from xax_selfhost_x86_64_general import G_ENTRY, G_TFMT

    def build(e: E):
        p = e.p
        members = p["members"]
        order = _ra(e, J_ORDER)
        e.var("if_order", order)
        # The bundle order: the closure functions by CID.
        e.for_("if_k", 0, members, lambda: e.st(e.add(p["if_order"], p["if_k"]), p["if_k"]))
        obj = lambda fidx: e.ld(e.add(_g(e, G_ORDER), fidx))  # noqa: E731

        def insert():
            e.var("if_item", e.ld(e.add(p["if_order"], p["if_s"])))
            e.var("if_j", p["if_s"])
            before = lambda: e.both(e.lt(0, p["if_j"]), _cid_less(e, obj(p["if_item"]), obj(e.ld(e.add(p["if_order"], e.sub(p["if_j"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["if_order"], p["if_j"]), e.ld(e.add(p["if_order"], e.sub(p["if_j"], 1)))), e.set("if_j", e.sub(p["if_j"], 1))))
            e.st(e.add(p["if_order"], p["if_j"]), p["if_item"])

        e.for_("if_s", 1, members, insert)
        # The stub's 16 bytes, then one thunk per distinct (library, name) in bundle call order.
        _set_ra(e, I_LEN, 0)
        _put_text(e, 0, 8)
        _put_text(e, 0, 8)
        e.var("if_thunks", _ra(e, J_THUNKS))  # (declaration, text offset, C import) per thunk
        e.var("if_nt", 0)
        e.var("if_dynamic", e.flag(e.eq(_g(e, G_TFMT), DYNAMIC_FORMAT)))

        def function_calls(body):
            def each_function():
                e.var("if_f", e.ld(e.add(p["if_order"], p["if_q"])))
                e.var("if_c0", e.ld(_fn(e, p["if_f"], 2)))
                e.for_("if_c", 0, e.ld(_fn(e, p["if_f"], 3)), lambda: (
                    e.var("if_cat", e.add(_ra(e, J_CALLS), e.mul(e.add(p["if_c0"], p["if_c"]), 3))), body()))

            e.for_("if_q", 0, members, each_function)

        def thunk_for():
            e.var("if_decl", e.ld(e.add(p["if_cat"], 1)))
            _foreign_strings(e, p["if_decl"], "if_a")
            e.var("if_found", NONE)

            def compare():
                e.var("if_other", e.ld(e.add(p["if_thunks"], e.mul(p["if_j"], 3))))
                _foreign_strings(e, p["if_other"], "if_b")
                _same_input(e, p["if_a_lib"], p["if_a_libn"], p["if_b_lib"], p["if_b_libn"], "if_sl")
                _same_input(e, p["if_a_sym"], p["if_a_symn"], p["if_b_sym"], p["if_b_symn"], "if_ss")

                def same():
                    # ``_foreign_declarations`` keeps one declaration per (library, name): two would need the store's order.
                    _ok(e, e.eq(p["if_other"], p["if_decl"]))
                    e.set("if_found", p["if_j"])

                e.if_(e.both(e.ne(p["if_sl"], 0), e.ne(p["if_ss"], 0)), same)

            e.for_("if_j", 0, p["if_nt"], compare)

            def make():
                _ok(e, e.lt(p["if_nt"], THUNKS))
                e.var("if_tat", e.add(p["if_thunks"], e.mul(p["if_nt"], 3)))
                e.st(p["if_tat"], p["if_decl"])
                e.st(e.add(p["if_tat"], 1), _ra(e, I_LEN))
                e.var("if_class", _foreign_class(e, p["if_decl"], "if_abi"))
                e.st(e.add(p["if_tat"], 2), e.flag(e.eq(p["if_class"], ABI_C_CLASS)))
                e.set("if_nt", e.add(p["if_nt"], 1))
                e.if_(e.eq(p["if_class"], ABI_SYSCALL_CLASS), lambda: _call(e, "a64_thunk", p["if_decl"]), lambda: (
                    _ok(e, e.both(e.eq(p["if_class"], ABI_C_CLASS), e.ne(p["if_dynamic"], 0))), _put_text(e, 0, 8), _put_text(e, 0, 4)))
                e.while_(lambda: e.ne(e.and_(_ra(e, I_LEN), 15), 0), lambda: _put_text(e, 0, 1))

            e.if_(e.eq(p["if_found"], NONE), make)

        function_calls(lambda: e.if_(e.ne(e.ld(e.add(p["if_cat"], 2)), 0), thunk_for))
        _set_ra(e, J_NTHUNKS, p["if_nt"])
        # The bundle: each function at a 16-byte boundary.
        e.var("if_base", _ra(e, I_LEN))
        _set_ra(e, J_BASE, p["if_base"])

        def place():
            e.var("if_f", e.ld(e.add(p["if_order"], p["if_q"])))
            e.while_(lambda: e.ne(e.and_(_ra(e, I_LEN), 15), 0), lambda: _put_text(e, NOP, 4))
            e.st(_fn(e, p["if_f"], 6), e.sub(_ra(e, I_LEN), p["if_base"]))
            e.var("if_n", e.ld(_fn(e, p["if_f"], 1)))
            e.var("if_len", _ra(e, I_LEN))
            _ok(e, e.le(e.add(p["if_len"], p["if_n"]), TEXT_CAP))
            e.var("if_from", e.add(STAGE_AT, e.ld(_fn(e, p["if_f"], 0))))
            e.for_("if_k", 0, p["if_n"], lambda: e.st(e.add(e.add(TEXT_AT, p["if_len"]), p["if_k"]), e.ld(e.add(p["if_from"], p["if_k"]))))
            _set_ra(e, I_LEN, e.add(p["if_len"], p["if_n"]))

        e.for_("if_q", 0, members, place)

        def direct():
            from xax_selfhost_general_view import G_CIDX

            e.var("if_site", e.add(e.add(p["if_base"], e.ld(_fn(e, p["if_f"], 6))), e.ld(p["if_cat"])))
            e.var("if_callee", e.ld(e.add(_g(e, G_CIDX), e.ld(e.add(p["if_cat"], 1)))))
            _ok(e, e.ne(p["if_callee"], NONE))
            e.var("if_word", _bl(e, p["if_site"], e.add(p["if_base"], e.ld(_fn(e, p["if_callee"], 6)))))
            _ok(e, e.ne(p["if_word"], NONE))  # the bootstrap fails (AARCH64-CALL-RANGE)
            _patch(e, p["if_site"], p["if_word"])

        function_calls(lambda: e.if_(e.eq(e.ld(e.add(p["if_cat"], 2)), 0), direct))
        # The record's status and bundle code (the foreign calls not yet bound).
        _set_ra(e, I_CURSOR, IMAGE_AT)
        _out(e, 1)
        _out(e, e.sub(_ra(e, I_LEN), p["if_base"]))
        _out_bytes(e, e.add(TEXT_AT, p["if_base"]), e.sub(_ra(e, I_LEN), p["if_base"]))
        # The stub, and every foreign call branched to its thunk.
        from xax_selfhost_general_view import G_CIDX

        e.var("if_entry", e.ld(_fn(e, e.ld(e.add(_g(e, G_CIDX), _g(e, G_ENTRY))), 6)))
        _set_ra(e, J_ENTRY, p["if_entry"])
        e.var("if_stub", _bl(e, 0, e.add(p["if_base"], p["if_entry"])))
        _ok(e, e.ne(p["if_stub"], NONE))
        _patch(e, 0, p["if_stub"])
        _patch(e, 4, 0xD4200000 | (BRK_ENTRY_RETURNED << 5))

        def foreign():
            e.var("if_site", e.add(e.add(p["if_base"], e.ld(_fn(e, p["if_f"], 6))), e.ld(p["if_cat"])))
            e.var("if_decl", e.ld(e.add(p["if_cat"], 1)))
            e.var("if_thunk", NONE)
            e.for_("if_j", 0, p["if_nt"], lambda: e.if_(e.eq(e.ld(e.add(p["if_thunks"], e.mul(p["if_j"], 3))), p["if_decl"]),
                                                        lambda: e.set("if_thunk", e.ld(e.add(p["if_thunks"], e.add(e.mul(p["if_j"], 3), 1))))))
            _ok(e, e.ne(p["if_thunk"], NONE))
            e.var("if_word", _bl(e, p["if_site"], p["if_thunk"]))
            _ok(e, e.ne(p["if_word"], NONE))  # the bootstrap fails (AARCH64-CALL-RANGE)
            _patch(e, p["if_site"], p["if_word"])

        function_calls(lambda: e.if_(e.ne(e.ld(e.add(p["if_cat"], 2)), 0), foreign))
        e.if_(e.ne(p["if_dynamic"], 0), lambda: _call(e, "a64_elf_dynamic"), lambda: _call(e, "a64_elf_static"))
        e.give(1)
    return _function(("members",), build, tables)


# -- the container ---------------------------------------------------------------------------------------------------

def _elf_header(e: E, entry, headers):
    _elf(e, 0x00010102464C457F, 8)  # \x7fELF, 64-bit, little endian, version 1, System V
    _elf(e, 0, 8)
    _elf(e, 2 | (183 << 16) | (1 << 32), 8)  # ET_EXEC, EM_AARCH64, version 1
    _elf(e, entry, 8)
    _elf(e, ELF_HEADER, 8)  # e_phoff
    _elf(e, 0, 8)  # e_shoff
    _elf(e, 0, 4)  # e_flags
    _elf(e, ELF_HEADER | (PROGRAM_HEADER << 16), 4)
    _elf(e, e.add(headers, 64 << 16), 4)  # e_phnum, e_shentsize
    _elf(e, 0, 4)  # e_shnum, e_shstrndx


def _copy_text(e: E):
    p = e.p
    e.for_("ct_k", 0, _ra(e, I_LEN), lambda: _elf(e, e.ld(e.add(TEXT_AT, p["ct_k"])), 1))


def _elf_static_fn(tables):
    """``emit_linux_aarch64_executable``'s static profile: the header, one read/execute load segment from offset 0,
    a non-executable stack, the text (entered at its stub)."""
    def build(e: E):
        code_offset = ELF_HEADER + 2 * PROGRAM_HEADER
        _set_ra(e, I_ELEN, 0)
        e.var("es_size", e.add(code_offset, _ra(e, I_LEN)))
        _elf_header(e, BASE_ADDRESS + code_offset, 2)
        _program_header(e, PT_LOAD, PF_R | PF_X, 0, BASE_ADDRESS, e.p["es_size"], SEGMENT_ALIGN)
        _stack_header(e)
        _copy_text(e)
        _set_ra(e, I_OUT, e.add(code_offset, _ra(e, J_BASE)))
        _set_ra(e, I_NNEEDED, 0)
        _set_ra(e, J_NNAMES, 0)
        e.give(1)
    return _function((), build, tables)


def _elf_dynamic_fn(tables):
    """The dynamic profile: ``PT_INTERP``, ``DT_NEEDED`` from the C imports, bind-now GOT slots bound by ``GLOB_DAT``,
    each import's thunk an ``adrp``/``ldr``/``br`` through its slot."""
    def build(e: E):
        p = e.p
        e.var("ed_thunks", _ra(e, J_THUNKS))
        # The distinct C imports' declarations, sorted by (library, name); the names must be unique.
        e.var("ed_names", _ra(e, J_NAMES))
        e.var("ed_nn", 0)
        e.for_("ed_k", 0, _ra(e, J_NTHUNKS), lambda: e.if_(e.ne(e.ld(e.add(p["ed_thunks"], e.add(e.mul(p["ed_k"], 3), 2))), 0), lambda: (
            e.st(e.add(p["ed_names"], p["ed_nn"]), e.ld(e.add(p["ed_thunks"], e.mul(p["ed_k"], 3)))), e.set("ed_nn", e.add(p["ed_nn"], 1)))))

        def pair_less(a, b, name):
            _foreign_strings(e, a, f"{name}_x")
            _foreign_strings(e, b, f"{name}_y")
            _less_input(e, p[f"{name}_x_lib"], p[f"{name}_x_libn"], p[f"{name}_y_lib"], p[f"{name}_y_libn"], f"{name}_l")
            _same_input(e, p[f"{name}_x_lib"], p[f"{name}_x_libn"], p[f"{name}_y_lib"], p[f"{name}_y_libn"], f"{name}_e")
            _less_input(e, p[f"{name}_x_sym"], p[f"{name}_x_symn"], p[f"{name}_y_sym"], p[f"{name}_y_symn"], f"{name}_s")
            return e.either(e.ne(p[f"{name}_l"], 0), e.both(e.ne(p[f"{name}_e"], 0), e.ne(p[f"{name}_s"], 0)))

        def insert():
            e.var("ed_item", e.ld(e.add(p["ed_names"], p["ed_s"])))
            e.var("ed_j", p["ed_s"])
            e.var("ed_go", 1)

            def step():
                e.set("ed_go", 0)

                def check():
                    e.var("ed_prev", e.ld(e.add(p["ed_names"], e.sub(p["ed_j"], 1))))
                    e.if_(pair_less(p["ed_item"], p["ed_prev"], "ed_pl"), lambda: (
                        e.st(e.add(p["ed_names"], p["ed_j"]), p["ed_prev"]), e.set("ed_j", e.sub(p["ed_j"], 1)), e.set("ed_go", 1)))

                e.if_(e.lt(0, p["ed_j"]), check)

            e.while_(lambda: e.ne(p["ed_go"], 0), step)
            e.st(e.add(p["ed_names"], p["ed_j"]), p["ed_item"])

        e.for_("ed_s", 1, p["ed_nn"], insert)
        # A name in two libraries: the bootstrap fails (LINUX-IMPORT-SYMBOL-UNIQUE).
        e.for_("ed_k", 0, p["ed_nn"], lambda: e.for_("ed_j", e.add(p["ed_k"], 1), p["ed_nn"], lambda: (
            _foreign_strings(e, e.ld(e.add(p["ed_names"], p["ed_k"])), "ed_u"),
            _foreign_strings(e, e.ld(e.add(p["ed_names"], p["ed_j"])), "ed_v"),
            _same_input(e, p["ed_u_sym"], p["ed_u_symn"], p["ed_v_sym"], p["ed_v_symn"], "ed_us"),
            _ok(e, e.eq(p["ed_us"], 0)))))
        # The needed libraries: distinct, sorted.
        e.var("ed_needed", _ra(e, J_NEEDED))
        e.var("ed_nd", 0)

        def library():
            e.var("ed_obj", e.ld(e.add(p["ed_names"], p["ed_k"])))
            _foreign_strings(e, p["ed_obj"], "ed_a")
            e.var("ed_dup", 0)

            def compare():
                _foreign_strings(e, e.ld(e.add(p["ed_needed"], p["ed_j"])), "ed_b")
                _same_input(e, p["ed_a_lib"], p["ed_a_libn"], p["ed_b_lib"], p["ed_b_libn"], "ed_sl")
                e.if_(e.ne(p["ed_sl"], 0), lambda: e.set("ed_dup", 1))

            e.for_("ed_j", 0, p["ed_nd"], compare)
            e.if_(e.eq(p["ed_dup"], 0), lambda: (e.st(e.add(p["ed_needed"], p["ed_nd"]), p["ed_obj"]), e.set("ed_nd", e.add(p["ed_nd"], 1))))

        e.for_("ed_k", 0, p["ed_nn"], library)
        _set_ra(e, I_NNEEDED, p["ed_nd"])
        _set_ra(e, J_NNAMES, p["ed_nn"])
        # The string table (``c_string_table``): "\0", the libraries, then the names, each once.
        e.var("ed_strings", e.alloc(1 << 16))
        e.var("ed_slen", 1)
        e.var("ed_offsets", e.alloc(e.add(e.add(p["ed_nd"], p["ed_nn"]), 1)))
        _ok(e, e.both(e.ne(p["ed_strings"], NONE), e.ne(p["ed_offsets"], NONE)))
        e.st(p["ed_strings"], 0)

        def string(start, length, slot):
            e.var("st_start", start)
            e.var("st_n", length)
            e.var("st_found", NONE)
            e.var("st_q", 0)

            def scan():
                e.var("st_same", 1)
                e.for_("st_k", 0, p["st_n"], lambda: e.if_(e.either(e.le(p["ed_slen"], e.add(p["st_q"], p["st_k"])),
                                                                     e.ne(e.ld(e.add(p["ed_strings"], e.add(p["st_q"], p["st_k"]))), e.rd(e.add(p["st_start"], p["st_k"])))),
                                                           lambda: e.set("st_same", 0)))
                starts = e.either(e.eq(p["st_q"], 1), e.eq(e.ld(e.add(p["ed_strings"], e.sub(p["st_q"], 1))), 0))
                ends = e.both(e.lt(e.add(p["st_q"], p["st_n"]), p["ed_slen"]), e.eq(e.ld(e.add(p["ed_strings"], e.add(p["st_q"], e.sel(e.lt(e.add(p["st_q"], p["st_n"]), p["ed_slen"]), p["st_n"], 0)))), 0))
                e.if_(e.both(e.eq(p["st_found"], NONE), e.ne(p["st_same"], 0), starts, ends), lambda: e.set("st_found", p["st_q"]))
                e.set("st_q", e.add(p["st_q"], 1))

            e.while_(lambda: e.lt(p["st_q"], p["ed_slen"]), scan)

            def add():
                _ok(e, e.lt(e.add(e.add(p["ed_slen"], p["st_n"]), 1), 1 << 16))
                e.set("st_found", p["ed_slen"])
                e.for_("st_k", 0, p["st_n"], lambda: e.st(e.add(p["ed_strings"], e.add(p["ed_slen"], p["st_k"])), e.rd(e.add(p["st_start"], p["st_k"]))))
                e.st(e.add(p["ed_strings"], e.add(p["ed_slen"], p["st_n"])), 0)
                e.set("ed_slen", e.add(e.add(p["ed_slen"], p["st_n"]), 1))

            e.if_(e.eq(p["st_found"], NONE), add)
            e.st(e.add(p["ed_offsets"], slot), p["st_found"])

        def needed_string():
            _foreign_strings(e, e.ld(e.add(p["ed_needed"], p["ed_k"])), "ed_a")
            string(p["ed_a_lib"], p["ed_a_libn"], p["ed_k"])

        e.for_("ed_k", 0, p["ed_nd"], needed_string)

        def name_string():
            _foreign_strings(e, e.ld(e.add(p["ed_names"], p["ed_k"])), "ed_a")
            string(p["ed_a_sym"], p["ed_a_symn"], e.add(p["ed_nd"], p["ed_k"]))

        e.for_("ed_k", 0, p["ed_nn"], name_string)
        # Layout.
        headers = 6
        interp_offset = ELF_HEADER + headers * PROGRAM_HEADER
        e.var("ed_symtab", _align(e, interp_offset + len(INTERPRETER), 8))
        e.var("ed_strtab", e.add(p["ed_symtab"], e.mul(e.add(p["ed_nn"], 1), SYMBOL)))
        e.var("ed_hashlen", e.mul(e.add(3, e.add(p["ed_nn"], 1)), 4))
        e.var("ed_hash", _align(e, e.add(p["ed_strtab"], p["ed_slen"]), 8))
        e.var("ed_rela", _align(e, e.add(p["ed_hash"], p["ed_hashlen"]), 8))
        e.var("ed_code", _align(e, e.add(p["ed_rela"], e.mul(p["ed_nn"], RELA)), 16))
        e.var("ed_text_end", e.add(p["ed_code"], _ra(e, I_LEN)))
        e.var("ed_rw", _align(e, p["ed_text_end"], 8))
        e.var("ed_rw_address", e.add(_align(e, e.add(BASE_ADDRESS, p["ed_text_end"]), SEGMENT_ALIGN), e.and_(p["ed_rw"], SEGMENT_ALIGN - 1)))
        e.var("ed_dyn_n", e.add(p["ed_nd"], 11))
        e.var("ed_dyn_size", e.mul(p["ed_dyn_n"], 16))
        e.var("ed_got", e.add(p["ed_rw_address"], p["ed_dyn_size"]))

        # Each import thunk through its GOT slot: ``adrp x16``, ``ldr x16, [x16, #lo]``, ``br x16``.
        def bind():
            e.var("ed_tat", e.add(p["ed_thunks"], e.mul(p["ed_k"], 3)))

            def thunk():
                e.var("ed_decl", e.ld(p["ed_tat"]))
                e.var("ed_slot", NONE)
                e.for_("ed_j", 0, p["ed_nn"], lambda: e.if_(e.eq(e.ld(e.add(p["ed_names"], p["ed_j"])), p["ed_decl"]), lambda: e.set("ed_slot", p["ed_j"])))
                _ok(e, e.ne(p["ed_slot"], NONE))
                e.var("ed_address", e.add(p["ed_got"], e.mul(p["ed_slot"], 8)))
                e.var("ed_offset", e.ld(e.add(p["ed_tat"], 1)))
                e.var("ed_pc", e.add(BASE_ADDRESS, e.add(p["ed_code"], p["ed_offset"])))
                e.var("ed_pages", e.udiv(e.sub(e.and_(p["ed_address"], (1 << 64) - 4096), e.and_(p["ed_pc"], (1 << 64) - 4096)), 4096))
                _patch(e, p["ed_offset"], e.add(e.add(0x90000000 + 16, e.mul(e.and_(p["ed_pages"], 3), 1 << 29)), e.mul(e.and_(e.udiv(p["ed_pages"], 4), 0x7FFFF), 32)))
                _patch(e, e.add(p["ed_offset"], 4), e.add(0xF9400000 + (16 << 5) + 16, e.mul(e.udiv(e.and_(p["ed_address"], 0xFFF), 8), 1 << 10)))
                _patch(e, e.add(p["ed_offset"], 8), 0xD61F0000 | (16 << 5))

            e.if_(e.ne(e.ld(e.add(p["ed_tat"], 2)), 0), thunk)

        e.for_("ed_k", 0, _ra(e, J_NTHUNKS), bind)
        # The file.
        _set_ra(e, I_ELEN, 0)
        _elf_header(e, e.add(BASE_ADDRESS, p["ed_code"]), headers)
        _program_header(e, PT_PHDR, PF_R, ELF_HEADER, BASE_ADDRESS + ELF_HEADER, headers * PROGRAM_HEADER, 8)
        _program_header(e, PT_INTERP, PF_R, interp_offset, BASE_ADDRESS + interp_offset, len(INTERPRETER), 1)
        _program_header(e, PT_LOAD, PF_R | PF_X, 0, BASE_ADDRESS, p["ed_text_end"], SEGMENT_ALIGN)
        e.var("ed_rw_size", e.add(p["ed_dyn_size"], e.mul(p["ed_nn"], 8)))
        _program_header(e, PT_LOAD, PF_R | PF_W, p["ed_rw"], p["ed_rw_address"], p["ed_rw_size"], SEGMENT_ALIGN)
        _program_header(e, PT_DYNAMIC, PF_R | PF_W, p["ed_rw"], p["ed_rw_address"], p["ed_dyn_size"], 8)
        _stack_header(e)
        for byte in INTERPRETER:
            _elf(e, byte, 1)

        def fill(offset):
            e.while_(lambda: e.lt(_ra(e, I_ELEN), offset), lambda: _elf(e, 0, 1))

        fill(p["ed_symtab"])
        _elf(e, 0, SYMBOL)

        def sym():
            _elf(e, e.ld(e.add(p["ed_offsets"], e.add(p["ed_nd"], p["ed_k"]))), 4)
            _elf(e, 0x12, 4)  # st_info GLOBAL FUNC, st_other 0, st_shndx 0
            _elf(e, 0, 8)
            _elf(e, 0, 8)

        e.for_("ed_k", 0, p["ed_nn"], sym)
        e.for_("ed_k", 0, p["ed_slen"], lambda: _elf(e, e.ld(e.add(p["ed_strings"], p["ed_k"])), 1))
        fill(p["ed_hash"])
        _elf(e, e.add(1, e.mul(e.add(p["ed_nn"], 1), 1 << 32)), 8)  # nbucket 1, nchain
        _elf(e, e.sel(e.eq(p["ed_nn"], 0), 0, 1), 4)  # the bucket: symbol 1
        _elf(e, 0, 4)  # chain[0]
        e.for_("ed_k", 1, e.add(p["ed_nn"], 1), lambda: _elf(e, e.sel(e.lt(p["ed_k"], p["ed_nn"]), e.add(p["ed_k"], 1), 0), 4))
        fill(p["ed_rela"])

        def relocation():
            _elf(e, e.add(p["ed_got"], e.mul(p["ed_k"], 8)), 8)
            _elf(e, e.add(R_AARCH64_GLOB_DAT, e.mul(e.add(p["ed_k"], 1), 1 << 32)), 8)
            _elf(e, 0, 8)

        e.for_("ed_k", 0, p["ed_nn"], relocation)
        fill(p["ed_code"])
        _copy_text(e)
        fill(p["ed_rw"])
        e.for_("ed_k", 0, p["ed_nd"], lambda: (_elf(e, DT_NEEDED, 8), _elf(e, e.ld(e.add(p["ed_offsets"], p["ed_k"])), 8)))
        for tag, value in ((DT_HASH, e.add(BASE_ADDRESS, p["ed_hash"])), (DT_STRTAB, e.add(BASE_ADDRESS, p["ed_strtab"])),
                           (DT_SYMTAB, e.add(BASE_ADDRESS, p["ed_symtab"])), (DT_STRSZ, p["ed_slen"]), (DT_SYMENT, SYMBOL),
                           (DT_RELA, e.add(BASE_ADDRESS, p["ed_rela"])), (DT_RELASZ, e.mul(p["ed_nn"], RELA)), (DT_RELAENT, RELA),
                           (DT_FLAGS, DF_BIND_NOW), (DT_FLAGS_1, DF_1_NOW), (DT_NULL, 0)):
            _elf(e, tag, 8)
            _elf(e, value, 8)
        e.for_("ed_k", 0, p["ed_nn"], lambda: _elf(e, 0, 8))
        _set_ra(e, I_OUT, e.add(p["ed_code"], _ra(e, J_BASE)))
        e.give(1)
    return _function((), build, tables)


# -- the record --------------------------------------------------------------------------------------------------

def _image_record_fn(tables):
    """The rest of the record after the bundle code ``a64_image_finish`` wrote: the ELF, the offsets, every function's
    placement and node ranges, the foreign calls, the needed libraries."""
    def build(e: E):
        p = e.p
        _out(e, _ra(e, I_ELEN))
        _out_bytes(e, _ra(e, I_ELF), _ra(e, I_ELEN))
        _out(e, _ra(e, I_OUT))
        _out(e, _ra(e, J_ENTRY))
        _out(e, p["members"])

        def function():
            _out(e, e.ld(_fn(e, p["ir_k"], 6)))
            _out(e, e.ld(_fn(e, p["ir_k"], 1)))
            _out(e, e.ld(_fn(e, p["ir_k"], 5)))
            e.var("ir_r", e.add(_ra(e, J_RANGES), e.mul(e.ld(_fn(e, p["ir_k"], 4)), 4)))
            e.for_("ir_j", 0, e.mul(e.ld(_fn(e, p["ir_k"], 5)), 4), lambda: _out(e, e.ld(e.add(p["ir_r"], p["ir_j"]))))

        e.for_("ir_k", 0, p["members"], function)
        # The foreign calls in bundle order.
        e.var("ir_n", 0)
        e.var("ir_count_at", _ra(e, I_CURSOR))
        _out(e, 0)

        def each_function():
            e.var("ir_f", e.ld(e.add(_ra(e, J_ORDER), p["ir_q"])))
            e.var("ir_c0", e.ld(_fn(e, p["ir_f"], 2)))

            def call():
                e.var("ir_at", e.add(_ra(e, J_CALLS), e.mul(e.add(p["ir_c0"], p["ir_c"]), 3)))

                def foreign():
                    _out(e, e.add(e.ld(_fn(e, p["ir_f"], 6)), e.ld(p["ir_at"])))
                    _foreign_strings(e, e.ld(e.add(p["ir_at"], 1)), "ir_s")
                    _out_input(e, p["ir_s_lib"], p["ir_s_libn"])
                    _out_input(e, p["ir_s_sym"], p["ir_s_symn"])
                    e.set("ir_n", e.add(p["ir_n"], 1))

                e.if_(e.ne(e.ld(e.add(p["ir_at"], 2)), 0), foreign)

            e.for_("ir_c", 0, e.ld(_fn(e, p["ir_f"], 3)), call)

        e.for_("ir_q", 0, p["members"], each_function)
        e.st(p["ir_count_at"], p["ir_n"])
        _out(e, _ra(e, I_NNEEDED))

        def each_needed():
            _foreign_strings(e, e.ld(e.add(_ra(e, J_NEEDED), p["ir_k"])), "ir_d")
            _out_input(e, p["ir_d_lib"], p["ir_d_libn"])

        e.for_("ir_k", 0, _ra(e, I_NNEEDED), each_needed)
        e.give(1)
    return _function(("members",), build, tables)


def image_after_views(e: E, members):
    """After every function is emitted: assemble and write the record, or record "not decided"."""
    p = e.p
    e.var("ia_ok", e.flag(e.both(e.ne(_ra(e, I_OK), 0), e.eq(_ra(e, I_COUNT), members))))

    def assemble():
        e.var("ia_elf", e.alloc(TEXT_CAP + (1 << 16)))
        e.if_(e.eq(p["ia_elf"], NONE), lambda: e.set("ia_ok", 0), lambda: _set_ra(e, I_ELF, p["ia_elf"]))
        e.if_(e.ne(p["ia_ok"], 0), lambda: e.if_(e.eq(e.call(_FN["a64_image_finish"], members), NONE), lambda: e.set("ia_ok", 0)))
        e.if_(e.ne(p["ia_ok"], 0), lambda: e.if_(e.eq(e.call(_FN["a64_image_record"], members), NONE), lambda: e.set("ia_ok", 0)))

    e.if_(e.ne(p["ia_ok"], 0), assemble)
    e.if_(e.eq(p["ia_ok"], 0), lambda: (_set_ra(e, I_CURSOR, IMAGE_AT), _out(e, 0)))


def add_image_functions(add, tables):
    from xax_selfhost_aarch64_emit import SYSCALL_ABI
    from xax_selfhost_views_backend import _syscall

    add("a64_syscall", _syscall(tables, SYSCALL_ABI))
    add("a64_image_add", _image_add_fn(tables))
    add("a64_thunk", _thunk_fn(tables))
    add("a64_elf_static", _elf_static_fn(tables))
    add("a64_elf_dynamic", _elf_dynamic_fn(tables))
    add("a64_image_finish", _image_finish_fn(tables))
    add("a64_image_record", _image_record_fn(tables))
