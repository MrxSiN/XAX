"""S12e (ADR-273): the general x86-64 backend's image assembly and Linux ELF64 container as XAX functions.

``xax_x86_64._compile_native_with_target`` after the per-function code (S12d): each function placed at a 16-byte
boundary (``nop`` padding) in image order, the SysV entry adapters of the addressed functions after them (in label
order), every call and address fixup bound, and each foreign call recorded as an import; then ``xax_linux``'s
container: the static ``ET_EXEC`` (one read/execute segment) or, for ``x86_64-linux-elf-dynexec-v1``, the dynamic
one (``PT_INTERP``, ``DT_NEEDED``, a one-bucket hash, ``GLOB_DAT`` relocations, bind-now GOT slots).

The program assembles only when it emitted every function of the closure (S12d); otherwise the record says "not
decided" and the host assembles.  Where the bootstrap fails (an entry adapter's signature, an import symbol in two
libraries (S15b.4: its diagnostic), a static profile with imports) the program declines and the bootstrap reports the error.

The record is written at ``IMAGE_AT``: the status, the image code (before the container binds its imports), the ELF
bytes, the code's file offset, the entry offset, each function's offset, the imports (position, library, name), and
the ``DT_NEEDED`` libraries.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_general_regalloc import _ra, _set_ra
from xax_selfhost_views_backend import _FN, G_PAY, GLOBALS, _at, _call, _cid_words, _g, _ok

IMAGE_AT, IMAGE_END = 6 << 20, 11 << 20
IMAGE_CAP = 4 << 22  # image bytes (one per word); S14a (ADR-284): the compiler's own image; S15b (ADR-291): 12 MiB; S15e.2 (ADR-315): 16 MiB
# S15d.0 (ADR-303): the code image's buffer sits at a fixed place the general program does not otherwise use (between
# the diagnostic record and the views backend's globals), so it no longer takes arena words and the views can grow.
IMAGE_BUFFER_AT = 12 << 20
assert IMAGE_BUFFER_AT + IMAGE_CAP <= GLOBALS  # the buffer ends where the globals begin
IMAGE_CALLS = 1 << 16
# State (``_ra`` slots after the emission's register words).
(I_IMG, I_LEN, I_OK, I_COUNT, I_BASES, I_CALLS, I_NCALLS, I_ADAPT, I_NADAPT, I_IMPORTS, I_NIMPORTS, I_ENTRY, I_ELF, I_ELEN, I_OUT,
 I_NEEDED, I_NNEEDED, I_NAMES, I_NNAMES, I_SNAP, I_CURSOR, I_ADSTART) = range(210, 232)
ARGUMENT_REGISTERS = (1, 2, 8, 9)
SYSV_REGISTERS = (7, 6, 2, 1, 8, 9)
BASE_ADDRESS, PAGE = 0x400000, 4096
ELF_HEADER, PROGRAM_HEADER, SYMBOL, RELA = 64, 56, 24, 24
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_PHDR, PT_GNU_STACK = 1, 2, 3, 6, 0x6474E551
PF_R, PF_W, PF_X = 4, 2, 1
INTERPRETER = b"/lib64/ld-linux-x86-64.so.2\x00"
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT = 0, 1, 4, 5, 6, 7, 8, 9, 10, 11
DT_FLAGS, DF_BIND_NOW, DT_FLAGS_1, DF_1_NOW = 30, 8, 0x6FFFFFFB, 1
R_X86_64_GLOB_DAT = 6
DYNAMIC_FORMAT = 6


def _put(e: E, buffer_slot: int, length_slot: int, cap: int, word, n):
    """Append the ``n`` low bytes of ``word`` (little endian) to a byte buffer (one byte per word)."""
    p = e.p
    e.var("pu_len", _ra(e, length_slot))
    _ok(e, e.le(e.add(p["pu_len"], n), cap))
    e.var("pu_w", word)
    e.var("pu_at", e.add(_ra(e, buffer_slot), p["pu_len"]))
    e.for_("pu_k", 0, n, lambda: (e.st(e.add(p["pu_at"], p["pu_k"]), e.and_(p["pu_w"], 255)), e.set("pu_w", e.udiv(p["pu_w"], 256))))
    _set_ra(e, length_slot, e.add(p["pu_len"], n))


def _img(e: E, word, n):
    _put(e, I_IMG, I_LEN, IMAGE_CAP, word, n)


def _patch(e: E, at, word, n):
    """Overwrite ``n`` bytes of the image at ``at``."""
    p = e.p
    e.var("pa_w", word)
    e.var("pa_at", e.add(_ra(e, I_IMG), at))
    e.for_("pa_k", 0, n, lambda: (e.st(e.add(p["pa_at"], p["pa_k"]), e.and_(p["pa_w"], 255)), e.set("pa_w", e.udiv(p["pa_w"], 256))))


def _pad(e: E, byte: int, alignment: int):
    e.while_(lambda: e.ne(e.and_(_ra(e, I_LEN), alignment - 1), 0), lambda: _img(e, byte, 1))


def _image_add_fn(tables):
    """Place function ``fidx``'s emitted code (``xax_selfhost_general_emit``'s buffers) and keep its fixups."""
    from xax_selfhost_general_emit import E_CALLS, E_CLEN, E_CODE, E_NCALLS

    def build(e: E):
        p = e.p
        _pad(e, 0x90, 16)
        e.var("ia_base", _ra(e, I_LEN))
        e.st(e.add(_ra(e, I_BASES), p["fidx"]), p["ia_base"])
        e.var("ia_code", _ra(e, E_CODE))
        e.var("ia_n", _ra(e, E_CLEN))
        _ok(e, e.le(e.add(p["ia_base"], p["ia_n"]), IMAGE_CAP))
        e.var("ia_img", e.add(_ra(e, I_IMG), p["ia_base"]))
        e.for_("ia_k", 0, p["ia_n"], lambda: e.st(e.add(p["ia_img"], p["ia_k"]), e.ld(e.add(p["ia_code"], p["ia_k"]))))
        _set_ra(e, I_LEN, e.add(p["ia_base"], p["ia_n"]))

        def call():
            e.var("ia_src", e.add(_ra(e, E_CALLS), e.mul(p["ia_k"], 3)))
            e.var("ia_m", _ra(e, I_NCALLS))
            _ok(e, e.lt(p["ia_m"], IMAGE_CALLS))
            e.var("ia_dst", e.add(_ra(e, I_CALLS), e.mul(p["ia_m"], 3)))
            e.st(p["ia_dst"], e.add(p["ia_base"], e.ld(p["ia_src"])))
            e.st(e.add(p["ia_dst"], 1), e.ld(e.add(p["ia_src"], 1)))
            e.st(e.add(p["ia_dst"], 2), e.ld(e.add(p["ia_src"], 2)))
            _set_ra(e, I_NCALLS, e.add(p["ia_m"], 1))

        e.for_("ia_k", 0, _ra(e, E_NCALLS), call)
        _set_ra(e, I_COUNT, e.add(_ra(e, I_COUNT), 1))
        e.give(1)
    return _function(("fidx",), build, tables)


def _cid_less(e: E, a, b):
    """CID of object ``a`` sorts before object ``b``'s (big-endian words)."""
    wa, wb = _cid_words(e, a), _cid_words(e, b)
    result = e.c(0)
    decided = e.c(0)
    for x, y in zip(wa, wb):
        result = e.add(result, e.mul(e.flag(e.eq(decided, 0)), e.flag(e.lt(x, y))))
        decided = e.or_(decided, e.flag(e.ne(x, y)))
    return e.ne(result, 0)


def _type_width_class(e: E, type_obj, name: str):
    """``name``: the SysV integer-class width of ``type_obj`` (bits 1..64, a pointer or link 64), NONE otherwise."""
    from xax_selfhost_general_regalloc import _machine_width

    e.var(name, _machine_width(e, type_obj))


def _adapter_fn(tables):
    """``_sysv_entry_adapter(function f)`` appended to the image; its ``call`` fixup position is returned."""
    from xax_selfhost_general_regalloc import _proof_type

    def build(e: E):
        p = e.p
        e.var("ad_i", _call(e, "interface", p["f"]))
        e.var("ad_np", e.ld(e.add(p["ad_i"], 1)))
        e.var("ad_rt", e.add(e.add(p["ad_i"], 2), p["ad_np"]))
        e.var("ad_nr", e.ld(p["ad_rt"]))
        e.var("ad_elided", _call(e, "borrowed", p["f"]))
        # The machine parameters' widths (at most four, each 8/16/32/64) and at most one machine result.
        e.var("ad_widths", e.alloc(8))
        _ok(e, e.ne(p["ad_widths"], NONE))
        e.var("ad_n", 0)

        def machine_parameter(k):
            return e.not_(_proof_type(e, e.ld(e.add(e.add(p["ad_i"], 2), k))))

        def machine_return(k):
            return e.both(e.not_(_proof_type(e, e.ld(e.add(e.add(p["ad_rt"], 1), k)))), e.eq(e.ld(e.add(p["ad_elided"], k)), NONE))

        def signature():
            """S12f.2 (ADR-278): ``_sysv_entry_adapter``'s rejection, naming the machine parameter and result types."""
            import xax_selfhost_diagnostics as D
            from xax_selfhost_general_emit import reject_at

            def write():
                D.text(e, "XAX.NATIVE.FOREIGN_ENTRY")
                D.cid(e, _cid_words(e, p["f"]))
                D.text(e, "SYSV-ENTRY-SIGNATURE")
                D.text(e, "<=4 integer/pointer parameters of 8/16/32/64 bits, <=1 integer/pointer result")
                D.put(e, D.T_LIST)
                D.put(e, 2)
                for side, (count, base, machine) in enumerate(((p["ad_np"], e.add(p["ad_i"], 2), machine_parameter),
                                                               (p["ad_nr"], e.add(p["ad_rt"], 1), machine_return))):
                    at, n, k = f"sg_base{side}", f"sg_n{side}", f"sg_k{side}"
                    e.var(at, base)
                    e.var(n, 0)
                    e.for_(k, 0, count, lambda machine=machine, n=n, k=k: e.if_(machine(p[k]), lambda: e.set(n, e.add(p[n], 1))))
                    D.put(e, D.T_LIST)
                    D.put(e, p[n])
                    e.for_(k, 0, count, lambda machine=machine, at=at, k=k: e.if_(machine(p[k]), lambda: D.cid(e, _cid_words(e, e.ld(e.add(p[at], p[k]))))))

            reject_at(e, write)

        def parameter():
            e.var("ad_t", e.ld(e.add(e.add(p["ad_i"], 2), p["ad_k"])))

            def machine():
                _type_width_class(e, p["ad_t"], "ad_w")
                good = e.either(*(e.eq(p["ad_w"], w) for w in (8, 16, 32, 64)))
                e.if_(e.not_(e.both(good, e.lt(p["ad_n"], 4))), signature)
                e.st(e.add(p["ad_widths"], p["ad_n"]), p["ad_w"])
                e.set("ad_n", e.add(p["ad_n"], 1))

            e.if_(e.not_(_proof_type(e, p["ad_t"])), machine)

        e.for_("ad_k", 0, p["ad_np"], parameter)
        e.var("ad_r", 0)

        def returned():
            e.var("ad_t", e.ld(e.add(e.add(p["ad_rt"], 1), p["ad_k"])))

            def machine():
                _type_width_class(e, p["ad_t"], "ad_w")
                e.if_(e.eq(p["ad_w"], NONE), signature)
                e.set("ad_r", e.add(p["ad_r"], 1))

            e.if_(e.both(e.not_(_proof_type(e, p["ad_t"])), e.eq(e.ld(e.add(p["ad_elided"], p["ad_k"])), NONE)), machine)

        e.for_("ad_k", 0, p["ad_nr"], returned)
        e.if_(e.lt(1, p["ad_r"]), signature)
        _pad(e, 0x90, 16)
        _set_ra(e, I_ADSTART, _ra(e, I_LEN))
        _img(e, 0x28EC8348, 4)  # sub rsp, 40
        e.var("ad_k", p["ad_n"])

        def move():
            e.set("ad_k", e.sub(p["ad_k"], 1))
            dst = _select(e, p["ad_k"], ARGUMENT_REGISTERS)
            src = _select(e, p["ad_k"], SYSV_REGISTERS)
            e.var("ad_d", dst)
            e.var("ad_s", src)
            e.var("ad_wk", e.ld(e.add(p["ad_widths"], p["ad_k"])))
            rex = e.add(e.add(0x40, e.mul(e.flag(e.le(8, p["ad_d"])), 4)), e.flag(e.le(8, p["ad_s"])))
            e.var("ad_rex", rex)
            modrm = e.add(e.add(0xC0, e.mul(e.and_(p["ad_d"], 7), 8)), e.and_(p["ad_s"], 7))
            e.var("ad_m", modrm)

            def wide():
                _img(e, e.add(e.add(e.or_(p["ad_rex"], 8), 0x8B00), e.mul(p["ad_m"], 1 << 16)), 3)

            def dword():
                e.if_(e.ne(p["ad_rex"], 0x40), lambda: _img(e, p["ad_rex"], 1))
                _img(e, e.add(0x8B, e.mul(p["ad_m"], 256)), 2)

            def word():
                e.if_(e.ne(p["ad_rex"], 0x40), lambda: _img(e, p["ad_rex"], 1))
                _img(e, e.add(0xB70F, e.mul(p["ad_m"], 1 << 16)), 3)

            def byte():
                _img(e, p["ad_rex"], 1)  # REX selects sil/dil
                _img(e, e.add(0xB60F, e.mul(p["ad_m"], 1 << 16)), 3)

            e.if_(e.eq(p["ad_wk"], 64), wide, lambda: e.if_(e.eq(p["ad_wk"], 32), dword, lambda: e.if_(e.eq(p["ad_wk"], 16), word, byte)))

        e.while_(lambda: e.ne(p["ad_k"], 0), move)
        _img(e, 0xE8, 1)
        e.var("ad_call", _ra(e, I_LEN))
        _img(e, 0, 4)
        _img(e, 0xC328C48348, 5)  # add rsp, 40; ret
        e.give(p["ad_call"])
    return _function(("f",), build, tables)


def _select(e: E, index, items):
    result = e.c(items[-1])
    for position in range(len(items) - 2, -1, -1):
        result = e.sel(e.eq(index, position), items[position], result)
    return result


def _foreign_strings(e: E, obj, name: str):
    """``decode_foreign_function``'s library and name of declaration ``obj``: input positions and lengths in
    ``name_lib``/``name_libn`` and ``name_sym``/``name_symn``."""
    from xax_selfhost_views_backend import _FOREIGN_PREFIX, _payload_uleb

    p = e.p
    e.var(f"{name}_at", _at(e, G_PAY, obj))
    _payload_uleb(e, f"{name}_at")
    e.set(f"{name}_at", e.add(p[f"{name}_at"], len(_FOREIGN_PREFIX)))
    e.set(f"{name}_at", e.add(_payload_uleb(e, f"{name}_at"), p[f"{name}_at"]))  # the ABI
    e.var(f"{name}_libn", _payload_uleb(e, f"{name}_at"))
    e.var(f"{name}_lib", p[f"{name}_at"])
    e.set(f"{name}_at", e.add(p[f"{name}_at"], p[f"{name}_libn"]))
    e.var(f"{name}_symn", _payload_uleb(e, f"{name}_at"))
    e.var(f"{name}_sym", p[f"{name}_at"])


def _same_input(e: E, a, an, b, bn, name: str):
    """``name``: 1 when the input byte strings at ``a`` (``an`` bytes) and ``b`` are equal."""
    p = e.p
    e.var(name, e.flag(e.eq(an, bn)))
    e.var(f"{name}_a", a)
    e.var(f"{name}_b", b)
    e.if_(e.ne(p[name], 0), lambda: e.for_(f"{name}_k", 0, an, lambda: e.if_(
        e.ne(e.rd(e.add(p[f"{name}_a"], p[f"{name}_k"])), e.rd(e.add(p[f"{name}_b"], p[f"{name}_k"]))), lambda: e.set(name, 0))))


def _less_input(e: E, a, an, b, bn, name: str):
    """``name``: 1 when input byte string ``a`` sorts before ``b`` (bytes comparison)."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_d", 0)
    e.var(f"{name}_a", a)
    e.var(f"{name}_b", b)
    e.var(f"{name}_an", an)
    e.var(f"{name}_bn", bn)
    e.var(f"{name}_n", e.sel(e.lt(an, bn), an, bn))

    def step():
        e.var(f"{name}_x", e.rd(e.add(p[f"{name}_a"], p[f"{name}_k"])))
        e.var(f"{name}_y", e.rd(e.add(p[f"{name}_b"], p[f"{name}_k"])))
        e.if_(e.both(e.eq(p[f"{name}_d"], 0), e.ne(p[f"{name}_x"], p[f"{name}_y"])),
              lambda: (e.set(f"{name}_d", 1), e.set(name, e.flag(e.lt(p[f"{name}_x"], p[f"{name}_y"])))))

    e.for_(f"{name}_k", 0, p[f"{name}_n"], step)
    e.if_(e.eq(p[f"{name}_d"], 0), lambda: e.set(name, e.flag(e.lt(p[f"{name}_an"], p[f"{name}_bn"]))))


def _image_finish_fn(tables):
    """The SysV entry adapters, the fixups, the imports, then the ELF container (``IMAGE_AT`` record)."""
    from xax_selfhost_general_view import G_CIDX
    from xax_selfhost_x86_64_general import G_ENTRY, G_TFMT

    def build(e: E):
        p = e.p
        calls = _ra(e, I_CALLS)
        e.var("if_calls", calls)
        e.var("if_n", _ra(e, I_NCALLS))
        at = lambda k, f: e.add(p["if_calls"], e.add(e.mul(k, 3), f))  # noqa: E731  (position, object, SysV entry label)
        # Adapters: the distinct SysV entry labels, by CID.
        e.var("if_adapt", _ra(e, I_ADAPT))
        e.var("if_na", 0)

        def label():
            e.var("if_obj", e.ld(at(p["if_k"], 1)))
            e.var("if_seen", 0)
            e.for_("if_j", 0, p["if_na"], lambda: e.if_(e.eq(e.ld(e.add(p["if_adapt"], e.mul(p["if_j"], 2))), p["if_obj"]), lambda: e.set("if_seen", 1)))
            e.if_(e.eq(p["if_seen"], 0), lambda: (_ok(e, e.lt(p["if_na"], 1 << 12)), e.st(e.add(p["if_adapt"], e.mul(p["if_na"], 2)), p["if_obj"]),
                                                  e.set("if_na", e.add(p["if_na"], 1))))

        e.for_("if_k", 0, p["if_n"], lambda: e.if_(e.ne(e.ld(at(p["if_k"], 2)), 0), label))

        def insert():
            e.var("if_item", e.ld(e.add(p["if_adapt"], e.mul(p["if_s"], 2))))
            e.var("if_j", p["if_s"])
            before = lambda: e.both(e.lt(0, p["if_j"]), _cid_less(e, p["if_item"], e.ld(e.add(p["if_adapt"], e.mul(e.sub(p["if_j"], 1), 2)))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["if_adapt"], e.mul(p["if_j"], 2)), e.ld(e.add(p["if_adapt"], e.mul(e.sub(p["if_j"], 1), 2)))),
                                      e.set("if_j", e.sub(p["if_j"], 1))))
            e.st(e.add(p["if_adapt"], e.mul(p["if_j"], 2)), p["if_item"])

        e.for_("if_s", 1, p["if_na"], insert)

        def adapter():
            e.var("if_obj", e.ld(e.add(p["if_adapt"], e.mul(p["if_k"], 2))))
            e.var("if_fx", e.ld(e.add(_g(e, G_CIDX), p["if_obj"])))
            _ok(e, e.ne(p["if_fx"], NONE))
            e.var("if_call", _call(e, "image_adapter", p["if_obj"]))
            _ok(e, e.ne(p["if_call"], NONE))
            e.st(e.add(e.add(p["if_adapt"], e.mul(p["if_k"], 2)), 1), _ra(e, I_ADSTART))
            e.var("if_target", e.ld(e.add(_ra(e, I_BASES), p["if_fx"])))
            _patch(e, p["if_call"], e.and_(e.sub(p["if_target"], e.add(p["if_call"], 4)), 0xFFFFFFFF), 4)

        e.for_("if_k", 0, p["if_na"], adapter)
        # Fixups and imports, in function then call order.
        e.var("if_imports", _ra(e, I_IMPORTS))
        e.var("if_ni", 0)

        def fixup():
            e.var("if_pos", e.ld(at(p["if_k"], 0)))
            e.var("if_obj", e.ld(at(p["if_k"], 1)))
            e.var("if_target", NONE)

            def labelled():
                e.for_("if_j", 0, p["if_na"], lambda: e.if_(e.eq(e.ld(e.add(p["if_adapt"], e.mul(p["if_j"], 2))), p["if_obj"]),
                                                            lambda: e.set("if_target", e.ld(e.add(e.add(p["if_adapt"], e.mul(p["if_j"], 2)), 1)))))

            def plain():
                e.var("if_fx", e.ld(e.add(_g(e, G_CIDX), p["if_obj"])))
                e.if_(e.ne(p["if_fx"], NONE), lambda: e.set("if_target", e.ld(e.add(_ra(e, I_BASES), p["if_fx"]))))

            e.if_(e.ne(e.ld(at(p["if_k"], 2)), 0), labelled, plain)

            def bind():
                _patch(e, p["if_pos"], e.and_(e.sub(p["if_target"], e.add(p["if_pos"], 4)), 0xFFFFFFFF), 4)

            def imported():
                _ok(e, e.lt(p["if_ni"], IMAGE_CALLS))
                e.st(e.add(p["if_imports"], e.mul(p["if_ni"], 2)), p["if_pos"])
                e.st(e.add(e.add(p["if_imports"], e.mul(p["if_ni"], 2)), 1), p["if_obj"])
                e.set("if_ni", e.add(p["if_ni"], 1))

            e.if_(e.ne(p["if_target"], NONE), bind, imported)

        e.for_("if_k", 0, p["if_n"], fixup)
        _set_ra(e, I_NIMPORTS, p["if_ni"])
        e.var("if_entry", e.ld(e.add(_ra(e, I_BASES), e.ld(e.add(_g(e, G_CIDX), _g(e, G_ENTRY))))))
        _set_ra(e, I_ENTRY, p["if_entry"])
        e.var("if_dynamic", e.flag(e.eq(_g(e, G_TFMT), DYNAMIC_FORMAT)))
        _ok(e, e.either(e.ne(p["if_dynamic"], 0), e.eq(p["if_ni"], 0)))  # the bootstrap fails (LINUX-DYNAMIC-LOADER-EXPLICIT)
        e.if_(e.ne(p["if_dynamic"], 0), lambda: _call(e, "elf_dynamic"), lambda: _call(e, "elf_static"))
        e.give(1)
    return _function((), build, tables)


# -- the container ---------------------------------------------------------------------------------------------------

def _elf(e: E, word, n):
    _put(e, I_ELF, I_ELEN, IMAGE_CAP + (1 << 16), word, n)


def _elf_header(e: E, entry, headers):
    _elf(e, 0x00010102464C457F, 8)  # \x7fELF, 64-bit, little endian, version 1, System V
    _elf(e, 0, 8)
    _elf(e, 2 | (62 << 16) | (1 << 32), 8)  # ET_EXEC, EM_X86_64, version 1
    _elf(e, entry, 8)
    _elf(e, ELF_HEADER, 8)  # e_phoff
    _elf(e, 0, 8)  # e_shoff
    _elf(e, 0, 4)  # e_flags
    _elf(e, ELF_HEADER | (PROGRAM_HEADER << 16), 4)
    _elf(e, e.add(headers, 64 << 16), 4)  # e_phnum, e_shentsize
    _elf(e, 0, 4)  # e_shnum, e_shstrndx


def _program_header(e: E, kind, flags, offset, address, size, align):
    _elf(e, kind | (flags << 32) if isinstance(kind, int) and isinstance(flags, int) else e.add(kind, e.mul(flags, 1 << 32)), 8)
    _elf(e, offset, 8)
    _elf(e, address, 8)
    _elf(e, address, 8)
    _elf(e, size, 8)
    _elf(e, size, 8)
    _elf(e, align, 8)


def _stack_header(e: E):
    _program_header(e, PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 16)


def _copy_image(e: E):
    p = e.p
    e.var("ci_img", _ra(e, I_IMG))
    e.for_("ci_k", 0, _ra(e, I_LEN), lambda: _elf(e, e.ld(e.add(p["ci_img"], p["ci_k"])), 1))


def _elf_static_fn(tables):
    """``_emit_static``: the header, one read/execute load segment from offset 0, a non-executable stack, the code."""
    def build(e: E):
        code_offset = ELF_HEADER + 2 * PROGRAM_HEADER
        _set_ra(e, I_ELEN, 0)
        e.var("es_size", e.add(code_offset, _ra(e, I_LEN)))
        _elf_header(e, e.add(BASE_ADDRESS + code_offset, _ra(e, I_ENTRY)), 2)
        _program_header(e, PT_LOAD, PF_R | PF_X, 0, BASE_ADDRESS, e.p["es_size"], PAGE)
        _stack_header(e)
        _copy_image(e)
        _set_ra(e, I_OUT, code_offset)
        _set_ra(e, I_NNEEDED, 0)
        e.give(1)
    return _function((), build, tables)


def _align(e: E, value, alignment: int):
    return e.and_(e.add(value, alignment - 1), (1 << 64) - alignment)


def _elf_dynamic_fn(tables):
    """``_emit_dynamic``: ``PT_INTERP``, ``DT_NEEDED`` from the imports, bind-now GOT slots bound by ``GLOB_DAT``."""
    def build(e: E):
        p = e.p
        imports = _ra(e, I_IMPORTS)
        e.var("ed_imp", imports)
        e.var("ed_ni", _ra(e, I_NIMPORTS))
        # The distinct (library, name) pairs, sorted; the names must be unique.
        e.var("ed_names", _ra(e, I_NAMES))  # (declaration object) per distinct pair
        e.var("ed_nn", 0)

        def distinct():
            e.var("ed_obj", e.ld(e.add(p["ed_imp"], e.add(e.mul(p["ed_k"], 2), 1))))
            _foreign_strings(e, p["ed_obj"], "ed_a")
            e.var("ed_dup", 0)

            def compare():
                _foreign_strings(e, e.ld(e.add(p["ed_names"], p["ed_j"])), "ed_b")
                _same_input(e, p["ed_a_lib"], p["ed_a_libn"], p["ed_b_lib"], p["ed_b_libn"], "ed_sl")
                _same_input(e, p["ed_a_sym"], p["ed_a_symn"], p["ed_b_sym"], p["ed_b_symn"], "ed_ss")
                e.if_(e.both(e.ne(p["ed_sl"], 0), e.ne(p["ed_ss"], 0)), lambda: e.set("ed_dup", 1))

            e.for_("ed_j", 0, p["ed_nn"], compare)
            e.if_(e.eq(p["ed_dup"], 0), lambda: (e.st(e.add(p["ed_names"], p["ed_nn"]), p["ed_obj"]), e.set("ed_nn", e.add(p["ed_nn"], 1))))

        e.for_("ed_k", 0, p["ed_ni"], distinct)

        def pair_less(a, b, name):
            """(library, name) of declaration ``a`` sorts before ``b``'s."""
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

        # A name in two libraries (sorted by (library, name), the two need not be adjacent): LINUX-IMPORT-SYMBOL-UNIQUE.
        e.var("ed_repeated", 0)
        e.for_("ed_k", 0, p["ed_nn"], lambda: e.for_("ed_j", e.add(p["ed_k"], 1), p["ed_nn"], lambda: (
            _foreign_strings(e, e.ld(e.add(p["ed_names"], p["ed_k"])), "ed_u"),
            _foreign_strings(e, e.ld(e.add(p["ed_names"], p["ed_j"])), "ed_v"),
            _same_input(e, p["ed_u_sym"], p["ed_u_symn"], p["ed_v_sym"], p["ed_v_symn"], "ed_us"),
            e.if_(e.ne(p["ed_us"], 0), lambda: e.set("ed_repeated", 1)))))
        e.if_(e.ne(p["ed_repeated"], 0), lambda: _call(e, "imports_reject", p["ed_names"], p["ed_nn"]))
        # The needed libraries: distinct, sorted (the declarations of their first pairs, in pair order).
        e.var("ed_needed", _ra(e, I_NEEDED))
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
        _set_ra(e, I_NNAMES, p["ed_nn"])
        # The string table: "\0", the libraries, then the names (each once; an empty string is the leading NUL).
        e.var("ed_strings", e.alloc(1 << 16))
        e.var("ed_slen", 1)
        e.var("ed_offsets", e.alloc(e.add(e.add(p["ed_nd"], p["ed_nn"]), 1)))
        _ok(e, e.both(e.ne(p["ed_strings"], NONE), e.ne(p["ed_offsets"], NONE)))
        e.st(p["ed_strings"], 0)

        def string(start, length, slot):
            """Append the input string (or find it already there) and keep its offset in ``ed_offsets[slot]``."""
            e.var("st_start", start)
            e.var("st_n", length)
            e.var("st_found", NONE)
            # An earlier identical string (``c_string_table`` adds each once).
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
        e.var("ed_rw_address", e.add(_align(e, e.add(BASE_ADDRESS, p["ed_text_end"]), PAGE), e.and_(p["ed_rw"], PAGE - 1)))
        e.var("ed_dyn_n", e.add(p["ed_nd"], 11))
        e.var("ed_dyn_size", e.mul(p["ed_dyn_n"], 16))
        e.var("ed_got", e.add(p["ed_rw_address"], p["ed_dyn_size"]))

        def slot_of(obj, name):
            """The GOT slot of declaration ``obj``'s name (its index among the sorted pairs)."""
            _foreign_strings(e, obj, f"{name}_x")
            e.var(name, NONE)

            def each():
                _foreign_strings(e, e.ld(e.add(p["ed_names"], p[f"{name}_k"])), f"{name}_y")
                _same_input(e, p[f"{name}_x_sym"], p[f"{name}_x_symn"], p[f"{name}_y_sym"], p[f"{name}_y_symn"], f"{name}_s")
                e.if_(e.both(e.eq(p[name], NONE), e.ne(p[f"{name}_s"], 0)), lambda: e.set(name, p[f"{name}_k"]))

            e.for_(f"{name}_k", 0, p["ed_nn"], each)

        # Bind each import site to its GOT slot (in the image before the container copies it).
        _set_ra(e, I_ELEN, 0)

        def bind():
            e.var("ed_pos", e.ld(e.add(p["ed_imp"], e.mul(p["ed_k"], 2))))
            slot_of(e.ld(e.add(p["ed_imp"], e.add(e.mul(p["ed_k"], 2), 1))), "ed_slot")
            site = e.add(BASE_ADDRESS, e.add(p["ed_code"], p["ed_pos"]))
            _patch(e, p["ed_pos"], e.and_(e.sub(e.add(p["ed_got"], e.mul(p["ed_slot"], 8)), e.add(site, 4)), 0xFFFFFFFF), 4)

        # The image record keeps the code before binding: copy it first.
        _call(e, "image_snapshot")
        e.for_("ed_k", 0, p["ed_ni"], bind)
        # The file.
        _elf_header(e, e.add(e.add(BASE_ADDRESS, p["ed_code"]), _ra(e, I_ENTRY)), headers)
        _program_header(e, PT_PHDR, PF_R, ELF_HEADER, BASE_ADDRESS + ELF_HEADER, headers * PROGRAM_HEADER, 8)
        _program_header(e, PT_INTERP, PF_R, interp_offset, BASE_ADDRESS + interp_offset, len(INTERPRETER), 1)
        _program_header(e, PT_LOAD, PF_R | PF_X, 0, BASE_ADDRESS, p["ed_text_end"], PAGE)
        e.var("ed_rw_size", e.add(p["ed_dyn_size"], e.mul(p["ed_nn"], 8)))
        _program_header(e, PT_LOAD, PF_R | PF_W, p["ed_rw"], p["ed_rw_address"], p["ed_rw_size"], PAGE)
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
            _elf(e, e.add(R_X86_64_GLOB_DAT, e.mul(e.add(p["ed_k"], 1), 1 << 32)), 8)
            _elf(e, 0, 8)

        e.for_("ed_k", 0, p["ed_nn"], relocation)
        fill(p["ed_code"])
        _copy_image(e)
        fill(p["ed_rw"])
        e.for_("ed_k", 0, p["ed_nd"], lambda: (_elf(e, DT_NEEDED, 8), _elf(e, e.ld(e.add(p["ed_offsets"], p["ed_k"])), 8)))
        for tag, value in ((DT_HASH, e.add(BASE_ADDRESS, p["ed_hash"])), (DT_STRTAB, e.add(BASE_ADDRESS, p["ed_strtab"])),
                           (DT_SYMTAB, e.add(BASE_ADDRESS, p["ed_symtab"])), (DT_STRSZ, p["ed_slen"]), (DT_SYMENT, SYMBOL),
                           (DT_RELA, e.add(BASE_ADDRESS, p["ed_rela"])), (DT_RELASZ, e.mul(p["ed_nn"], RELA)), (DT_RELAENT, RELA),
                           (DT_FLAGS, DF_BIND_NOW), (DT_FLAGS_1, DF_1_NOW), (DT_NULL, 0)):
            _elf(e, tag, 8)
            _elf(e, value, 8)
        e.for_("ed_k", 0, p["ed_nn"], lambda: _elf(e, 0, 8))
        _set_ra(e, I_OUT, p["ed_code"])
        e.give(1)
    return _function((), build, tables)


def _image_snapshot_fn(tables):
    """Keep the image code before the container binds its imports (``NativeImage.code``)."""
    def build(e: E):
        p = e.p
        e.var("sn_n", _ra(e, I_LEN))
        e.var("sn_at", e.alloc(e.add(p["sn_n"], 1)))
        _ok(e, e.ne(p["sn_at"], NONE))
        e.for_("sn_k", 0, p["sn_n"], lambda: e.st(e.add(p["sn_at"], p["sn_k"]), e.ld(e.add(_ra(e, I_IMG), p["sn_k"]))))
        _set_ra(e, I_SNAP, p["sn_at"])
        e.give(1)
    return _function((), build, tables)


# -- the record --------------------------------------------------------------------------------------------------

def _out(e: E, word):
    p = e.p
    e.var("io_at", _ra(e, I_CURSOR))
    _ok(e, e.lt(p["io_at"], IMAGE_END))
    e.st(p["io_at"], word)
    _set_ra(e, I_CURSOR, e.add(p["io_at"], 1))


def _out_bytes(e: E, base, count):
    """``count`` bytes from ``base`` (one per word), packed eight to a word."""
    p = e.p
    e.var("ob_base", base)
    e.var("ob_n", count)

    def word():
        e.var("ob_w", 0)
        e.var("ob_j", 8)
        e.while_(lambda: e.ne(p["ob_j"], 0), lambda: (
            e.set("ob_j", e.sub(p["ob_j"], 1)),
            e.var("ob_i", e.add(e.mul(p["ob_k"], 8), p["ob_j"])),
            e.set("ob_w", e.add(e.mul(p["ob_w"], 256), e.sel(e.lt(p["ob_i"], p["ob_n"]), e.ld(e.add(p["ob_base"], e.sel(e.lt(p["ob_i"], p["ob_n"]), p["ob_i"], 0))), 0)))))
        _out(e, p["ob_w"])

    e.for_("ob_k", 0, e.udiv(e.add(p["ob_n"], 7), 8), word)


def _out_input(e: E, start, count):
    """An input byte string: its length, then its bytes one per word."""
    p = e.p
    e.var("oi_s", start)
    e.var("oi_n", count)
    _out(e, p["oi_n"])
    e.for_("oi_k", 0, p["oi_n"], lambda: _out(e, e.rd(e.add(p["oi_s"], p["oi_k"]))))


def _image_record_fn(tables):
    """The ``IMAGE_AT`` record: ``status`` (1 assembled, 0 not decided), then the image and container."""
    from xax_selfhost_x86_64_general import G_TFMT

    def build(e: E):
        p = e.p
        _set_ra(e, I_CURSOR, IMAGE_AT)
        _out(e, p["status"])
        e.if_(e.eq(p["status"], 0), lambda: e.give(1))
        e.var("ir_code", e.sel(e.eq(_g(e, G_TFMT), DYNAMIC_FORMAT), _ra(e, I_SNAP), _ra(e, I_IMG)))
        _out(e, _ra(e, I_LEN))
        _out_bytes(e, p["ir_code"], _ra(e, I_LEN))
        _out(e, _ra(e, I_ELEN))
        _out_bytes(e, _ra(e, I_ELF), _ra(e, I_ELEN))
        _out(e, _ra(e, I_OUT))
        _out(e, _ra(e, I_ENTRY))
        _out(e, p["members"])
        e.for_("ir_k", 0, p["members"], lambda: _out(e, e.ld(e.add(_ra(e, I_BASES), p["ir_k"]))))
        e.var("ir_ni", _ra(e, I_NIMPORTS))
        _out(e, p["ir_ni"])

        def each_import():
            e.var("ir_at", e.add(_ra(e, I_IMPORTS), e.mul(p["ir_k"], 2)))
            _out(e, e.ld(p["ir_at"]))
            _foreign_strings(e, e.ld(e.add(p["ir_at"], 1)), "ir_f")
            _out_input(e, p["ir_f_lib"], p["ir_f_libn"])
            _out_input(e, p["ir_f_sym"], p["ir_f_symn"])

        e.for_("ir_k", 0, p["ir_ni"], each_import)
        _out(e, _ra(e, I_NNEEDED))

        def each_needed():
            _foreign_strings(e, e.ld(e.add(_ra(e, I_NEEDED), p["ir_k"])), "ir_n")
            _out_input(e, p["ir_n_lib"], p["ir_n_libn"])

        e.for_("ir_k", 0, _ra(e, I_NNEEDED), each_needed)
        e.give(1)
    return _function(("status", "members"), build, tables)


def image_prologue(e: E):
    """Allocate the image buffers (once, before the views)."""
    _set_ra(e, I_IMG, IMAGE_BUFFER_AT)
    for slot, words in ((I_BASES, 1 << 16), (I_CALLS, 3 * IMAGE_CALLS), (I_ADAPT, 2 << 12), (I_IMPORTS, 2 * IMAGE_CALLS),
                        (I_NEEDED, 1 << 12), (I_NAMES, IMAGE_CALLS)):
        at = e.alloc(words)
        _ok(e, e.ne(at, NONE))
        _set_ra(e, slot, at)
    for slot in (I_LEN, I_COUNT, I_NCALLS, I_NIMPORTS, I_ELEN, I_NNEEDED, I_ELF):  # S15c.5a: the ELF buffer comes after the views
        _set_ra(e, slot, 0)
    _set_ra(e, I_OK, 1)


def image_after_views(e: E, members):
    """After every view: assemble when the program emitted every function, then write the record."""
    p = e.p
    e.var("ia_ok", e.flag(e.both(e.ne(_ra(e, I_OK), 0), e.eq(_ra(e, I_COUNT), members))))

    def assemble():
        # S15c.5a (ADR-310): the container's buffer is taken here, after the views released their scratch, not before
        # them: it is 12.6M words, and the largest function's scratch needs them.
        e.var("ia_elf", e.alloc(IMAGE_CAP + (1 << 16)))
        e.if_(e.eq(p["ia_elf"], NONE), lambda: e.set("ia_ok", 0), lambda: _set_ra(e, I_ELF, p["ia_elf"]))
        e.if_(e.ne(p["ia_ok"], 0), assemble_now)

    def assemble_now():
        e.var("ia_r", e.call(_FN["image_finish"]))
        e.if_(e.eq(p["ia_r"], NONE), lambda: e.set("ia_ok", 0))

    e.if_(e.ne(p["ia_ok"], 0), assemble)
    _call(e, "image_record", p["ia_ok"], members)


def add_image_functions(add, tables):
    add("image_add", _image_add_fn(tables))
    add("image_adapter", _adapter_fn(tables))
    add("image_snapshot", _image_snapshot_fn(tables))
    add("elf_static", _elf_static_fn(tables))
    add("elf_dynamic", _elf_dynamic_fn(tables))
    add("image_finish", _image_finish_fn(tables))
    add("image_record", _image_record_fn(tables))
