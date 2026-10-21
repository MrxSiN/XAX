"""Self-hosting step S15e.3b (ADR-320): Windows PE32+ DLLs decided and written by the general x86-64 program.

``xax_build._build_windows_dll`` builds a ``WINDOWS_DLL`` request on the ``x86_64-windows-pe-v1`` profile.  Before it
lowers anything it reads the package's modules in order and, of every reference-free ``TARGET`` member, decodes the
``windows-pe-export-v1`` exports (``WINDOWS-EXPORT-NAME``), the ``windows-pe-forward-v1`` loader forwards
(``WINDOWS-FORWARD-IDENTITY``) and the ``windows-pe-dllmain-v1`` entry; sorts the exports and the forwards; requires
the build entry to be exported (``WINDOWS-DLL-ENTRY-EXPORTED``) and at most one DllMain (``WINDOWS-DLLMAIN-UNIQUE``);
checks DllMain's signature (``WINDOWS-DLLMAIN-SIGNATURE``) and that its call closure, depth first from a stack, makes no
indirect call and no foreign call outside ``kernel32.dll``'s allowlist (``WINDOWS-DLLMAIN-LOADER-LOCK``).  It then
compiles the entry's closure and, after it, each export's and DllMain's (``extra_roots``: each root's new functions by
CID), and ``emit_pe_dll`` requires distinct names (``PE-EXPORT-UNIQUE``) and a NUL-free DLL name
(``PE-EXPORT-DLL-NAME``) before it writes the container with an export directory (``.edata``).

The driver gives the general program the request instead of the entry (``xax_selfhost_request``'s ``B_DLL``): the
program finds the package, the entry and the plan itself (``dll_plan``), checks each further root (``dll_root``),
orders each root's closure (``dll_sort``), and the PE writer (``xax_selfhost_general_image._pe_fn``) adds the export
section (``dll_edata``) after the checks of ``dll_names``.  A carrier the bootstrap cannot decode (a truncated or
over-long identity, a COM declaration on DllMain's path, a name it renders with replacement characters) declines.
"""

from __future__ import annotations

from xax_build import DLLMAIN_FOREIGN_ALLOWLIST
from xax_compiler import WINDOWS_DLLMAIN_PREFIX, WINDOWS_EXPORT_PREFIX, WINDOWS_FORWARD_PREFIX, Kind, Operation
import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import (
    _FOREIGN_PREFIX, CID_WORDS, G_NI, G_O, G_PAY, G_REC, GLOBALS, NI_ENTITY, NI_OP, _at, _call, _cid_words, _g, _kind, _ok,
    _payload_uleb, _reference, _type_form, _type_width,
)

# Fixed words after the front end's globals (the general program's arena starts far above them).
DLL_AT = GLOBALS + 64
(D_ON, D_PACKAGE, D_NROOTS, D_ROOTS, D_EXPORTS, D_NEXPORTS, D_FORWARDS, D_NFORWARDS, D_MAIN, D_ROOT) = (DLL_AT + k for k in range(10))
ENTRY_WORDS = 4  # an export: name position, name length, function object, 0; a forward: name position, length, target position, length
DLL_SUFFIX = b".dll"
KERNEL32 = b"kernel32.dll"
ALLOWED = tuple(sorted(DLLMAIN_FOREIGN_ALLOWLIST))
LOADER_LOCK_EXPECTED = "no indirect calls from DllMain"
SIGNATURE_EXPECTED = "fn(b64, b32, b64, proof...) -> (b32, proof...)"


# -- packed byte values in a diagnostic record ---------------------------------------------------------------------

def _pack_begin(e: E, tag: int, length):
    D.put(e, tag)
    D.put(e, length)
    e.var("pk_word", 0)
    e.var("pk_weight", 1)


def _pack_byte(e: E, byte):
    p = e.p
    e.set("pk_word", e.add(p["pk_word"], e.mul(byte, p["pk_weight"])))
    e.set("pk_weight", e.mul(p["pk_weight"], 256))
    e.if_(e.eq(p["pk_weight"], 0), lambda: (D.put(e, p["pk_word"]), e.set("pk_word", 0), e.set("pk_weight", 1)))


def _pack_input(e: E, at, n, name: str):
    p = e.p
    e.var(f"{name}_at", at)
    e.for_(f"{name}_k", 0, n, lambda: _pack_byte(e, e.rd(e.add(p[f"{name}_at"], p[f"{name}_k"]))))


def _pack_end(e: E):
    p = e.p
    e.if_(e.ne(p["pk_weight"], 1), lambda: D.put(e, p["pk_word"]))


def _input_bytes(e: E, tag: int, at, n, name: str):
    _pack_begin(e, tag, n)
    _pack_input(e, at, n, name)
    _pack_end(e)


def _starts(e: E, at, n, data: bytes, name: str):
    """``name``: 1 when the ``n`` input bytes at ``at`` start with ``data``."""
    p = e.p
    e.var(name, e.flag(e.le(len(data), n)))
    e.var(f"{name}_at", at)
    e.if_(e.ne(p[name], 0), lambda: [e.if_(e.ne(e.rd(e.add(p[f"{name}_at"], k)), byte), lambda: e.set(name, 0)) for k, byte in enumerate(data)])


def _identity(e: E, obj, name: str):
    """A reference-free TARGET's identity (``Cursor(body).byte_string()``): ``name_at``/``name_n``, and ``name_rest``: the
    body bytes after it."""
    p = e.p
    e.var(f"{name}_at", _at(e, G_PAY, obj))
    e.var(f"{name}_len", e.rd(e.sub(p[f"{name}_at"], 1)))
    e.var(f"{name}_end", e.add(p[f"{name}_at"], p[f"{name}_len"]))
    e.var(f"{name}_n", _payload_uleb(e, f"{name}_at"))
    _ok(e, e.le(e.add(p[f"{name}_at"], p[f"{name}_n"]), p[f"{name}_end"]))
    e.var(f"{name}_rest", e.sub(p[f"{name}_end"], e.add(p[f"{name}_at"], p[f"{name}_n"])))


def _trailing(e: E, obj, remaining, rule: str):
    """``Cursor.end(rule)``: no bytes may remain (``XAX.CANON.TRAILING_BYTES``, expected 0, the count left)."""
    p = e.p
    e.var("tr_left", remaining)

    def write():
        D.text(e, "XAX.CANON.TRAILING_BYTES")
        D.cid(e, _cid_words(e, obj))
        D.text(e, rule)
        D.integer(e, 0)
        D.integer(e, p["tr_left"])

    D.reject_unless(e, e.eq(p["tr_left"], 0), write)


def _object_of_cid(e: E, at, name: str):
    """``name``: the object whose CID is the 32 input bytes at ``at`` (NONE when the store holds none)."""
    p = e.p
    for k in range(CID_WORDS):
        word = e.c(0)
        for j in range(8):
            word = e.add(e.mul(word, 256), e.rd(e.add(at, 8 * k + j)))
        e.var(f"{name}_w{k}", word)
    e.var(name, NONE)

    def each():
        words = _cid_words(e, p[f"{name}_o"])
        same = e.both(*(e.eq(word, p[f"{name}_w{k}"]) for k, word in enumerate(words)))
        e.if_(e.both(same, e.eq(p[name], NONE)), lambda: e.set(name, p[f"{name}_o"]))

    e.for_(f"{name}_o", 0, _g(e, G_O), each)


def _less_bytes(e: E, a, an, b, bn, name: str):
    """``name``: 1 when input bytes ``a`` (``an``) sort before ``b`` (``bn``); ``name_eq``: 1 when they are equal."""
    p = e.p
    e.var(name, 0)
    e.var(f"{name}_d", 0)
    for suffix, value in (("a", a), ("b", b), ("an", an), ("bn", bn)):
        e.var(f"{name}_{suffix}", value)
    e.var(f"{name}_n", e.sel(e.lt(p[f"{name}_an"], p[f"{name}_bn"]), p[f"{name}_an"], p[f"{name}_bn"]))

    def step():
        e.var(f"{name}_x", e.rd(e.add(p[f"{name}_a"], p[f"{name}_k"])))
        e.var(f"{name}_y", e.rd(e.add(p[f"{name}_b"], p[f"{name}_k"])))
        e.if_(e.both(e.eq(p[f"{name}_d"], 0), e.ne(p[f"{name}_x"], p[f"{name}_y"])),
              lambda: (e.set(f"{name}_d", 1), e.set(name, e.flag(e.lt(p[f"{name}_x"], p[f"{name}_y"])))))

    e.for_(f"{name}_k", 0, p[f"{name}_n"], step)
    e.var(f"{name}_eq", e.flag(e.both(e.eq(p[f"{name}_d"], 0), e.eq(p[f"{name}_an"], p[f"{name}_bn"]))))
    e.if_(e.eq(p[f"{name}_d"], 0), lambda: e.set(name, e.flag(e.lt(p[f"{name}_an"], p[f"{name}_bn"]))))


def _entry(e: E, table, k, field):
    return e.ld(e.add(e.add(table, e.mul(k, ENTRY_WORDS)), field))


# -- the plan --------------------------------------------------------------------------------------------------------

def _forward_target(e: E, at, n, name: str):
    """``name``: 1 when the input bytes match ``[A-Za-z0-9_-]{1,64}\\.[A-Za-z_][A-Za-z0-9_]{0,127}`` (``_FORWARD_TARGET``)."""
    p = e.p
    e.var(f"{name}_at", at)
    e.var(f"{name}_n", n)
    e.var(f"{name}_dot", NONE)
    e.for_(f"{name}_k", 0, p[f"{name}_n"], lambda: e.if_(e.both(e.eq(p[f"{name}_dot"], NONE), e.eq(e.rd(e.add(p[f"{name}_at"], p[f"{name}_k"])), ord("."))),
                                                         lambda: e.set(f"{name}_dot", p[f"{name}_k"])))
    e.var(name, e.flag(e.both(e.ne(p[f"{name}_dot"], NONE), e.le(1, p[f"{name}_dot"]), e.le(p[f"{name}_dot"], 64),
                              e.le(e.add(p[f"{name}_dot"], 2), p[f"{name}_n"]), e.le(e.sub(p[f"{name}_n"], p[f"{name}_dot"]), 129))))

    def char(byte, letters_only_first):
        upper = e.both(e.le(ord("A"), byte), e.le(byte, ord("Z")))
        lower = e.both(e.le(ord("a"), byte), e.le(byte, ord("z")))
        digit = e.both(e.le(ord("0"), byte), e.le(byte, ord("9")))
        return e.either(upper, lower, digit, e.eq(byte, ord("_"))) if not letters_only_first else e.either(upper, lower, e.eq(byte, ord("_")))

    def each():
        e.var(f"{name}_c", e.rd(e.add(p[f"{name}_at"], p[f"{name}_k"])))
        c = p[f"{name}_c"]
        module = e.both(e.lt(p[f"{name}_k"], p[f"{name}_dot"]), e.not_(e.either(char(c, False), e.eq(c, ord("-")))))
        first = e.both(e.eq(p[f"{name}_k"], e.add(p[f"{name}_dot"], 1)), e.not_(char(c, True)))
        rest = e.both(e.lt(e.add(p[f"{name}_dot"], 1), p[f"{name}_k"]), e.not_(char(c, False)))
        e.if_(e.either(module, first, rest), lambda: e.set(name, 0))

    e.if_(e.ne(p[name], 0), lambda: e.for_(f"{name}_k", 0, p[f"{name}_n"], each))


def _dll_plan(tables):
    """``_build_windows_dll``'s decisions before lowering, for build request ``dq``: the build entry's function (given),
    the plan in ``DLL_AT``; NONE when rejected or declined."""
    def build(e: E):
        p = e.p
        e.st(D_ON, 1)
        rq = p["dq"]
        e.var("da", _at(e, G_PAY, rq))
        _payload_uleb(e, "da")  # the form
        e.var("dpkg", _reference(e, rq, _payload_uleb(e, "da")))
        _ok(e, e.ne(p["dpkg"], NONE))
        e.var("den", _payload_uleb(e, "da"))  # the build entry's name
        e.var("den_at", p["da"])
        e.st(D_PACKAGE, p["dpkg"])
        # The package: its logical identity, modules, dependencies, then the build entries (``decode_package``).
        e.var("pa", _at(e, G_PAY, p["dpkg"]))
        e.var("pid_n", _payload_uleb(e, "pa"))
        e.set("pa", e.add(p["pa"], p["pid_n"]))
        e.var("pmods", _payload_uleb(e, "pa"))
        e.var("pmods_at", p["pa"])
        e.for_("dm", 0, p["pmods"], lambda: _payload_uleb(e, "pa"))

        def dependency():
            form = _payload_uleb(e, "pa")
            e.var("dform", form)
            e.if_(e.eq(p["dform"], 1), lambda: _payload_uleb(e, "pa"), lambda: e.set("pa", e.add(_payload_uleb(e, "pa"), p["pa"])))

        e.for_("dd", 0, _payload_uleb(e, "pa"), dependency)
        e.var("droot", NONE)

        def build_entry():
            e.var("ben", _payload_uleb(e, "pa"))
            e.var("ben_at", p["pa"])
            e.set("pa", e.add(p["pa"], p["ben"]))
            e.var("bei", _payload_uleb(e, "pa"))
            _less_bytes(e, p["ben_at"], p["ben"], p["den_at"], p["den"], "bcmp")
            e.if_(e.ne(p["bcmp_eq"], 0), lambda: e.set("droot", _reference(e, p["dpkg"], p["bei"])))

        e.for_("db", 0, _payload_uleb(e, "pa"), build_entry)
        _ok(e, e.ne(p["droot"], NONE))
        e.st(D_ROOT, p["droot"])
        # The members, modules in order and each module's references in order.
        e.var("dlimit", e.add(_g(e, G_O), 1))
        for slot in (D_EXPORTS, D_FORWARDS):
            e.var("dtable", e.alloc(e.mul(p["dlimit"], ENTRY_WORDS)))
            _ok(e, e.ne(p["dtable"], NONE))
            e.st(slot, p["dtable"])
        e.var("droots", e.alloc(e.mul(p["dlimit"], 2)))  # the roots, then (``dll_names``) the names in order
        _ok(e, e.ne(p["droots"], NONE))
        e.st(D_ROOTS, p["droots"])
        e.var("dne", 0)
        e.var("dnf", 0)
        e.var("dnm", 0)
        e.st(D_MAIN, NONE)

        def member():
            e.var("dc", _reference(e, p["dmod"], p["dr"]))
            _ok(e, e.ne(p["dc"], NONE))
            plain = e.both(e.eq(_kind(e, p["dc"]), int(Kind.TARGET)), e.eq(e.rd(e.add(_at(e, G_REC, p["dc"]), 1)), 0))

            def target():
                _identity(e, p["dc"], "di")
                _starts(e, p["di_at"], p["di_n"], WINDOWS_EXPORT_PREFIX, "dx")
                _starts(e, p["di_at"], p["di_n"], WINDOWS_FORWARD_PREFIX, "dw")
                _starts(e, p["di_at"], p["di_n"], WINDOWS_DLLMAIN_PREFIX, "dl")

                def export():
                    # ``decode_windows_export``: the carrier holds the identity alone; a name, the function's CID.
                    _trailing(e, p["dc"], p["di_rest"], "WINDOWS-EXPORT-CARRIER")
                    e.var("xa", e.add(p["di_at"], len(WINDOWS_EXPORT_PREFIX)))
                    e.var("xn", _payload_uleb(e, "xa"))
                    e.var("xend", e.add(p["di_at"], p["di_n"]))
                    _ok(e, e.le(e.add(e.add(p["xa"], p["xn"]), 32), p["xend"]))  # truncated: ``Cursor.take`` (declined)
                    _trailing(e, p["dc"], e.sub(p["xend"], e.add(e.add(p["xa"], p["xn"]), 32)), "WINDOWS-EXPORT-IDENTITY")
                    e.var("xok", e.flag(e.ne(p["xn"], 0)))
                    e.for_("xk", 0, p["xn"], lambda: e.if_(e.either(e.eq(e.rd(e.add(p["xa"], p["xk"])), 0), e.le(128, e.rd(e.add(p["xa"], p["xk"])))),
                                                           lambda: e.set("xok", 0)))

                    def bad_name():
                        D.text(e, "XAX.WINDOWS.EXPORT")
                        D.cid(e, _cid_words(e, p["dc"]))
                        D.text(e, "WINDOWS-EXPORT-NAME")
                        D.text(e, "nonempty NUL-free ASCII")
                        _input_bytes(e, D.T_BYTES, p["xa"], p["xn"], "xb")

                    D.reject_unless(e, e.ne(p["xok"], 0), bad_name)
                    _object_of_cid(e, e.add(p["xa"], p["xn"]), "xf")
                    _ok(e, e.ne(p["xf"], NONE))  # a CID the store does not hold: ``resolve`` fails later
                    e.var("xt", e.add(e.ld(D_EXPORTS), e.mul(p["dne"], ENTRY_WORDS)))
                    for field, value in enumerate((p["xa"], p["xn"], p["xf"], 0)):
                        e.st(e.add(p["xt"], field), value)
                    e.set("dne", e.add(p["dne"], 1))

                def forward():
                    # ``decode_windows_forward``: a name and a ``module.Symbol`` target; nothing after them.
                    e.var("fa", e.add(p["di_at"], len(WINDOWS_FORWARD_PREFIX)))
                    e.var("fn", _payload_uleb(e, "fa"))
                    e.var("fn_at", p["fa"])
                    e.set("fa", e.add(p["fa"], p["fn"]))
                    _ok(e, e.le(p["fa"], e.add(p["di_at"], p["di_n"])))
                    e.var("ft", _payload_uleb(e, "fa"))
                    e.var("ft_at", p["fa"])
                    e.var("fend", e.add(p["di_at"], p["di_n"]))
                    _ok(e, e.le(e.add(p["fa"], p["ft"]), p["fend"]))
                    _trailing(e, p["dc"], e.sub(p["fend"], e.add(p["fa"], p["ft"])), "WINDOWS-FORWARD-IDENTITY")
                    _forward_target(e, p["ft_at"], p["ft"], "fre")

                    def bad_forward():
                        D.text(e, "XAX.WINDOWS.EXPORT")
                        D.cid(e, _cid_words(e, p["dc"]))
                        D.text(e, "WINDOWS-FORWARD-IDENTITY")
                        D.text(e, "name and module.Symbol")
                        D.put(e, D.T_LIST)
                        D.put(e, 2)
                        _input_bytes(e, D.T_BYTES, p["fn_at"], p["fn"], "fb")
                        _input_bytes(e, D.T_BYTES, p["ft_at"], p["ft"], "fc")

                    D.reject_unless(e, e.both(e.ne(p["fn"], 0), e.ne(p["fre"], 0)), bad_forward)
                    e.var("fw", e.add(e.ld(D_FORWARDS), e.mul(p["dnf"], ENTRY_WORDS)))
                    for field, value in enumerate((p["fn_at"], p["fn"], p["ft_at"], p["ft"])):
                        e.st(e.add(p["fw"], field), value)
                    e.set("dnf", e.add(p["dnf"], 1))

                def dllmain():
                    # ``decode_windows_dllmain``: the prefix and a CID.
                    def bad_main():
                        D.text(e, "XAX.WINDOWS.EXPORT")
                        D.cid(e, _cid_words(e, p["dc"]))
                        D.text(e, "WINDOWS-DLLMAIN-IDENTITY")
                        D.text(e, "prefix + function CID")
                        e.var("mh", e.sel(e.lt(p["di_n"], 32), p["di_n"], 32))
                        _input_bytes(e, D.T_HEX, p["di_at"], p["mh"], "mb")

                    D.reject_unless(e, e.eq(p["di_n"], len(WINDOWS_DLLMAIN_PREFIX) + 32), bad_main)
                    _object_of_cid(e, e.add(p["di_at"], len(WINDOWS_DLLMAIN_PREFIX)), "mf")
                    _ok(e, e.ne(p["mf"], NONE))
                    e.st(D_MAIN, p["mf"])
                    e.set("dnm", e.add(p["dnm"], 1))

                e.if_(e.ne(p["dx"], 0), export, lambda: e.if_(e.ne(p["dw"], 0), forward, lambda: e.if_(e.ne(p["dl"], 0), dllmain)))

            e.if_(plain, target)

        def module():
            e.var("dmod", _reference(e, p["dpkg"], _payload_uleb(e, "pmods_at")))
            _ok(e, e.ne(p["dmod"], NONE))
            e.for_("dr", 0, e.rd(e.add(_at(e, G_REC, p["dmod"]), 1)), member)

        e.for_("dmi", 0, p["pmods"], module)
        e.st(D_NEXPORTS, p["dne"])
        e.st(D_NFORWARDS, p["dnf"])

        # ``exports.sort()`` (name, then function CID) and ``forwards.sort()`` (name, then target).
        def sort(table, count, second_cid: bool):
            e.var("st_table", table)

            def insert():
                e.var("st_j", p["st_s"])
                e.var("st_go", 1)

                def less():
                    a, b = e.add(p["st_table"], e.mul(p["st_j"], ENTRY_WORDS)), e.add(p["st_table"], e.mul(e.sub(p["st_j"], 1), ENTRY_WORDS))
                    e.var("st_a", a)
                    e.var("st_b", b)
                    _less_bytes(e, e.ld(p["st_a"]), e.ld(e.add(p["st_a"], 1)), e.ld(p["st_b"]), e.ld(e.add(p["st_b"], 1)), "sn")
                    e.var("st_less", p["sn"])
                    if second_cid:
                        def by_cid():
                            from xax_selfhost_general_image import _cid_less

                            e.set("st_less", e.flag(_cid_less(e, e.ld(e.add(p["st_a"], 2)), e.ld(e.add(p["st_b"], 2)))))
                    else:
                        def by_cid():
                            _less_bytes(e, e.ld(e.add(p["st_a"], 2)), e.ld(e.add(p["st_a"], 3)), e.ld(e.add(p["st_b"], 2)), e.ld(e.add(p["st_b"], 3)), "sm")
                            e.set("st_less", p["sm"])
                    e.if_(e.ne(p["sn_eq"], 0), by_cid)
                    e.set("st_go", p["st_less"])

                def swap():
                    for field in range(ENTRY_WORDS):
                        e.var("st_t", e.ld(e.add(p["st_a"], field)))
                        e.st(e.add(p["st_a"], field), e.ld(e.add(p["st_b"], field)))
                        e.st(e.add(p["st_b"], field), p["st_t"])
                    e.set("st_j", e.sub(p["st_j"], 1))

                e.while_(lambda: e.both(e.lt(0, p["st_j"]), e.ne(p["st_go"], 0)), lambda: (less(), e.if_(e.ne(p["st_go"], 0), swap)))

            e.for_("st_s", 1, count, insert)

        sort(e.ld(D_EXPORTS), p["dne"], True)
        sort(e.ld(D_FORWARDS), p["dnf"], False)

        # ``function_root in {cid for _, cid in exports}`` and at most one DllMain.
        e.var("dexported", 0)
        e.for_("dk", 0, p["dne"], lambda: e.if_(e.eq(_entry(e, e.ld(D_EXPORTS), p["dk"], 2), p["droot"]), lambda: e.set("dexported", 1)))
        e.var("pid_at", _at(e, G_PAY, p["dpkg"]))
        _payload_uleb(e, "pid_at")

        def not_exported():
            D.text(e, "XAX.BUILD.ARTIFACT")
            _input_bytes(e, D.T_HEX, p["pid_at"], p["pid_n"], "wa")
            D.text(e, "WINDOWS-DLL-ENTRY-EXPORTED")
            D.text(e, "the build entry is an export")
            D.cid(e, _cid_words(e, p["droot"]))

        D.reject_unless(e, e.ne(p["dexported"], 0), not_exported)

        def mains():
            D.text(e, "XAX.BUILD.ARTIFACT")
            _input_bytes(e, D.T_HEX, p["pid_at"], p["pid_n"], "wb")
            D.text(e, "WINDOWS-DLLMAIN-UNIQUE")
            D.text(e, "at most one DllMain")
            D.integer(e, p["dnm"])

        D.reject_unless(e, e.le(p["dnm"], 1), mains)
        e.if_(e.ne(e.ld(D_MAIN), NONE), lambda: _call(e, "dll_main", e.ld(D_MAIN)))
        # The further roots: the exports' functions in order, then DllMain.
        e.for_("dk", 0, p["dne"], lambda: e.st(e.add(p["droots"], p["dk"]), _entry(e, e.ld(D_EXPORTS), p["dk"], 2)))
        e.st(D_NROOTS, p["dne"])
        e.if_(e.ne(e.ld(D_MAIN), NONE), lambda: (e.st(e.add(p["droots"], p["dne"]), e.ld(D_MAIN)), e.st(D_NROOTS, e.add(p["dne"], 1))))
        e.give(p["droot"])
    return _function(("dq",), build, tables)


def _dll_main(tables):
    """``_check_dllmain`` for DllMain ``dm``: its machine signature, then its call closure (a stack: the last call
    pushed is visited first; every direct call is pushed, visited or not) for indirect and foreign calls."""
    from xax_selfhost_x86_64_general import _proof

    def build(e: E):
        p = e.p
        _ok(e, e.eq(_kind(e, p["dm"]), int(Kind.FUNCTION)))  # ``_decode_function_interface`` fails otherwise
        e.var("mi", _call(e, "interface", p["dm"]))
        e.var("mnp", e.ld(e.add(p["mi"], 1)))
        e.var("mrt", e.add(e.add(p["mi"], 2), p["mnp"]))
        e.var("mok", 1)
        e.var("mk", 0)  # machine values seen

        def width_is(t, width):
            return e.both(e.eq(_type_form(e, t), 1), e.eq(_type_width(e, t), width))

        def parameter():
            e.var("mt", e.ld(e.add(e.add(p["mi"], 2), p["mq"])))

            def machine():
                e.if_(e.eq(p["mk"], 0), lambda: e.if_(e.not_(width_is(p["mt"], 64)), lambda: e.set("mok", 0)))
                e.if_(e.eq(p["mk"], 1), lambda: e.if_(e.not_(width_is(p["mt"], 32)), lambda: e.set("mok", 0)))
                e.if_(e.eq(p["mk"], 2), lambda: e.if_(e.not_(width_is(p["mt"], 64)), lambda: e.set("mok", 0)))
                e.set("mk", e.add(p["mk"], 1))

            e.if_(e.not_(_proof(e, p["mt"])), machine)

        e.for_("mq", 0, p["mnp"], parameter)
        e.if_(e.ne(p["mk"], 3), lambda: e.set("mok", 0))
        e.set("mk", 0)

        def result():
            e.var("mt", e.ld(e.add(e.add(p["mrt"], 1), p["mq"])))

            def machine():
                e.if_(e.eq(p["mk"], 0), lambda: e.if_(e.not_(width_is(p["mt"], 32)), lambda: e.set("mok", 0)))
                e.set("mk", e.add(p["mk"], 1))

            e.if_(e.not_(_proof(e, p["mt"])), machine)

        e.for_("mq", 0, e.ld(p["mrt"]), result)
        e.if_(e.ne(p["mk"], 1), lambda: e.set("mok", 0))

        def signature():
            D.text(e, "XAX.BUILD.ARTIFACT")
            D.cid(e, _cid_words(e, p["dm"]))
            D.text(e, "WINDOWS-DLLMAIN-SIGNATURE")
            D.text(e, SIGNATURE_EXPECTED)
            D.none(e)

        D.reject_unless(e, e.ne(p["mok"], 0), signature)
        # The call closure: ``pending`` a stack, ``seen`` per object.
        e.var("mlimit", e.add(_g(e, G_O), 1))
        e.var("mseen", e.alloc(p["mlimit"]))
        _ok(e, e.ne(p["mseen"], NONE))
        e.for_("mq", 0, p["mlimit"], lambda: e.st(e.add(p["mseen"], p["mq"]), 0))
        e.var("mcap", e.mul(p["mlimit"], 16))
        e.var("mstack", e.alloc(p["mcap"]))
        _ok(e, e.ne(p["mstack"], NONE))
        e.st(p["mstack"], p["dm"])
        e.var("msp", 1)

        def visit():
            e.set("msp", e.sub(p["msp"], 1))
            e.var("mf", e.ld(e.add(p["mstack"], p["msp"])))

            def fresh():
                e.st(e.add(p["mseen"], p["mf"]), 1)
                _ok(e, e.eq(_kind(e, p["mf"]), int(Kind.FUNCTION)))
                e.var("mg", e.ld(_call(e, "interface", p["mf"])))
                e.var("ms", _at(e, G_PAY, p["mg"]))
                e.var("mblocks", e.rd(p["ms"]))
                e.var("mat", e.add(p["ms"], 2))  # the first block's parameters

                def block():
                    e.set("mat", e.add(e.add(p["mat"], 1), e.rd(p["mat"])))  # past the parameters
                    e.var("mnodes", e.rd(p["mat"]))
                    e.set("mat", e.add(p["mat"], 1))

                    def node():
                        e.set("mat", _call(e, "node_info", p["mat"]))
                        e.var("mop", e.ld(e.add(_g(e, G_NI), NI_OP)))

                        def direct():
                            e.var("mc", _reference(e, p["mg"], e.ld(e.add(_g(e, G_NI), NI_ENTITY))))
                            _ok(e, e.both(e.ne(p["mc"], NONE), e.lt(p["msp"], p["mcap"])))
                            e.st(e.add(p["mstack"], p["msp"]), p["mc"])
                            e.set("msp", e.add(p["msp"], 1))

                        def indirect():
                            D.text(e, "XAX.BUILD.ARTIFACT")
                            D.cid(e, _cid_words(e, p["mf"]))
                            D.text(e, "WINDOWS-DLLMAIN-LOADER-LOCK")
                            D.text(e, LOADER_LOCK_EXPECTED)
                            D.none(e)

                        def foreign():
                            e.var("md", _reference(e, p["mg"], e.ld(e.add(_g(e, G_NI), NI_ENTITY))))
                            _ok(e, e.ne(p["md"], NONE))
                            _ok(e, e.both(e.eq(_kind(e, p["md"]), int(Kind.TARGET)), e.eq(e.rd(e.add(_at(e, G_REC, p["md"]), 1)), 0)))
                            _identity(e, p["md"], "mx")
                            _starts(e, p["mx_at"], p["mx_n"], _FOREIGN_PREFIX, "mfp")
                            _ok(e, e.both(e.ne(p["mfp"], 0), e.eq(p["mx_rest"], 0)))  # a COM or other declaration: ``decode_foreign_function`` fails
                            from xax_selfhost_general_image import _foreign_strings

                            _foreign_strings(e, p["md"], "ml")
                            e.var("mkern", e.flag(e.eq(p["ml_libn"], len(KERNEL32))))

                            def lowered(k, byte):
                                c = e.rd(e.add(p["ml_lib"], k))
                                return e.sel(e.both(e.le(ord("A"), c), e.le(c, ord("Z"))), e.add(c, 32), c)

                            e.if_(e.ne(p["mkern"], 0), lambda: [e.if_(e.ne(lowered(k, byte), byte), lambda: e.set("mkern", 0)) for k, byte in enumerate(KERNEL32)])
                            e.var("mallow", 0)
                            for name in ALLOWED:
                                e.if_(e.both(e.eq(p["ml_symn"], len(name)), *(e.eq(e.rd(e.add(p["ml_sym"], k)), byte) for k, byte in enumerate(name))),
                                      lambda: e.set("mallow", 1))
                            from xax_selfhost_x86_64_general import _ascii

                            _ascii(e, p["ml_lib"], p["ml_libn"], "mal")
                            _ascii(e, p["ml_sym"], p["ml_symn"], "mas")

                            def outside():
                                _ok(e, e.both(e.ne(p["mal"], 0), e.ne(p["mas"], 0)))  # ``decode("ascii", "replace")``
                                D.begin(e)
                                D.text(e, "XAX.BUILD.ARTIFACT")
                                D.cid(e, _cid_words(e, p["mf"]))
                                D.text(e, "WINDOWS-DLLMAIN-LOADER-LOCK")
                                D.put(e, D.T_LIST)
                                D.put(e, len(ALLOWED))
                                for name in ALLOWED:
                                    D.text(e, name.decode())
                                _pack_begin(e, D.T_STR, e.add(e.add(p["ml_libn"], p["ml_symn"]), 1))
                                _pack_input(e, p["ml_lib"], p["ml_libn"], "mpl")
                                _pack_byte(e, ord("!"))
                                _pack_input(e, p["ml_sym"], p["ml_symn"], "mps")
                                _pack_end(e)
                                e.st(0, D.REJECT)
                                e.give(NONE)

                            e.if_(e.either(e.eq(p["mkern"], 0), e.eq(p["mallow"], 0)), outside)

                        e.if_(e.eq(p["mop"], int(Operation.CALL_DIRECT)), direct)
                        D.reject_unless(e, e.ne(p["mop"], int(Operation.CALL_INDIRECT)), indirect)
                        e.if_(e.eq(p["mop"], int(Operation.CALL_FOREIGN)), foreign)

                    e.for_("mn", 0, p["mnodes"], node)
                    e.set("mat", _call(e, "term_end", p["mat"]))

                e.for_("mb", 0, p["mblocks"], block)

            e.if_(e.eq(e.ld(e.add(p["mseen"], p["mf"])), 0), fresh)

        e.while_(lambda: e.ne(p["msp"], 0), visit)
        e.give(1)
    return _function(("dm",), build, tables)


def _dll_root(tables):
    """``_compile_native_with_target``'s check of a further root ``dr``: a function (``NATIVE-ENTRY-FUNCTION``)."""
    def build(e: E):
        p = e.p

        def kind_name():
            for kind in Kind:
                e.if_(e.eq(_kind(e, p["dr"]), int(kind)), lambda kind=kind: D.text(e, kind.name))

        _ok(e, e.either(*(e.eq(_kind(e, p["dr"]), int(kind)) for kind in Kind)))

        def wrong():
            D.text(e, "XAX.NATIVE.FUNCTION")
            D.cid(e, _cid_words(e, p["dr"]))
            D.text(e, "NATIVE-ENTRY-FUNCTION")
            D.text(e, Kind.FUNCTION.name)
            kind_name()

        D.reject_unless(e, e.eq(_kind(e, p["dr"]), int(Kind.FUNCTION)), wrong)
        e.give(1)
    return _function(("dr",), build, tables)


def _dll_sort(tables):
    """Sort ``order[start:end]`` by CID (``_function_closure``'s ``sorted(functions)`` of one root's new functions)."""
    from xax_selfhost_views_backend import G_ORDER, _cid_at, _cid_less

    def build(e: E):
        p = e.p
        order = _g(e, G_ORDER)
        e.var("so", order)

        def insert():
            e.var("sitem", e.ld(e.add(p["so"], p["ss"])))
            e.var("sj", p["ss"])
            before = lambda: e.both(e.lt(p["start"], p["sj"]), _cid_less(e, _cid_at(e, p["sitem"]), _cid_at(e, e.ld(e.add(p["so"], e.sub(p["sj"], 1))))))  # noqa: E731
            e.while_(before, lambda: (e.st(e.add(p["so"], p["sj"]), e.ld(e.add(p["so"], e.sub(p["sj"], 1)))), e.set("sj", e.sub(p["sj"], 1))))
            e.st(e.add(p["so"], p["sj"]), p["sitem"])

        e.for_("ss", e.add(p["start"], 1), p["end"], insert)
        e.give(1)
    return _function(("start", "end"), build, tables)


# -- ``emit_pe_dll``: names, then the export section -----------------------------------------------------------------

def _names(e: E, k, name: str):
    """Entry ``k`` of the merged names (exports first, then forwards): ``name_at``/``name_n``."""
    p = e.p
    e.var(f"{name}_x", e.flag(e.lt(k, e.ld(D_NEXPORTS))))
    e.var(f"{name}_r", e.sel(e.ne(p[f"{name}_x"], 0), e.add(e.ld(D_EXPORTS), e.mul(k, ENTRY_WORDS)),
                             e.add(e.ld(D_FORWARDS), e.mul(e.sub(k, e.ld(D_NEXPORTS)), ENTRY_WORDS))))
    e.var(f"{name}_at", e.ld(p[f"{name}_r"]))
    e.var(f"{name}_n", e.ld(e.add(p[f"{name}_r"], 1)))


def _dll_names(tables):
    """``emit_pe_dll``'s checks: one or more distinct names (``PE-EXPORT-UNIQUE``), a NUL-free DLL name
    (``PE-EXPORT-DLL-NAME``); then the merged entries sorted by name for the export directory (``ORDER``: entry
    indices, in ``D_ROOTS`` past the roots)."""
    from xax_selfhost_general_emit import reject_at
    from xax_selfhost_x86_64_general import G_TARGET

    def build(e: E):
        p = e.p
        e.var("nn", e.add(e.ld(D_NEXPORTS), e.ld(D_NFORWARDS)))
        e.var("nuniq", e.flag(e.lt(0, p["nn"])))

        def pair():
            _names(e, p["ni"], "na")
            _names(e, p["nj"], "nb")
            _less_bytes(e, p["na_at"], p["na_n"], p["nb_at"], p["nb_n"], "nc")
            e.if_(e.ne(p["nc_eq"], 0), lambda: e.set("nuniq", 0))

        e.for_("ni", 0, p["nn"], lambda: e.for_("nj", e.add(p["ni"], 1), p["nn"], pair))

        def duplicate():
            D.text(e, "XAX.PE.EXPORT")
            D.cid(e, _cid_words(e, _g(e, G_TARGET)))
            D.text(e, "PE-EXPORT-UNIQUE")
            D.text(e, "one or more distinct names")
            D.put(e, D.T_LIST)
            D.put(e, p["nn"])

            def each():
                _names(e, p["nq"], "nd")
                _input_bytes(e, D.T_BYTES, p["nd_at"], p["nd_n"], "ne")

            e.for_("nq", 0, p["nn"], each)

        e.if_(e.eq(p["nuniq"], 0), lambda: reject_at(e, duplicate))
        e.var("npa", _at(e, G_PAY, e.ld(D_PACKAGE)))
        e.var("npn", _payload_uleb(e, "npa"))
        e.var("nnul", 0)
        e.for_("nk", 0, p["npn"], lambda: e.if_(e.eq(e.rd(e.add(p["npa"], p["nk"])), 0), lambda: e.set("nnul", 1)))

        def nul():
            D.text(e, "XAX.PE.EXPORT")
            D.cid(e, _cid_words(e, _g(e, G_TARGET)))
            D.text(e, "PE-EXPORT-DLL-NAME")
            D.text(e, "nonempty NUL-free")
            _pack_begin(e, D.T_BYTES, e.add(p["npn"], len(DLL_SUFFIX)))
            _pack_input(e, p["npa"], p["npn"], "nw")
            for byte in DLL_SUFFIX:
                _pack_byte(e, byte)
            _pack_end(e)

        e.if_(e.ne(p["nnul"], 0), lambda: reject_at(e, nul))
        # The merged names in name order (distinct: exports first, then forwards, by insertion).
        e.var("nsorted", e.add(e.ld(D_ROOTS), e.add(e.ld(D_NROOTS), 1)))
        e.for_("nk", 0, p["nn"], lambda: e.st(e.add(p["nsorted"], p["nk"]), p["nk"]))

        def insert():
            e.var("nsj", p["nss"])
            e.var("nsgo", 1)

            def less():
                _names(e, e.ld(e.add(p["nsorted"], p["nsj"])), "nx")
                _names(e, e.ld(e.add(p["nsorted"], e.sub(p["nsj"], 1))), "ny")
                _less_bytes(e, p["nx_at"], p["nx_n"], p["ny_at"], p["ny_n"], "nz")
                e.set("nsgo", p["nz"])

            def swap():
                e.var("nst", e.ld(e.add(p["nsorted"], p["nsj"])))
                e.st(e.add(p["nsorted"], p["nsj"]), e.ld(e.add(p["nsorted"], e.sub(p["nsj"], 1))))
                e.st(e.add(p["nsorted"], e.sub(p["nsj"], 1)), p["nst"])
                e.set("nsj", e.sub(p["nsj"], 1))

            e.while_(lambda: e.both(e.lt(0, p["nsj"]), e.ne(p["nsgo"], 0)), lambda: (less(), e.if_(e.ne(p["nsgo"], 0), swap)))

        e.for_("nss", 1, p["nn"], insert)
        e.give(1)
    return _function((), build, tables)


def edata_length(e: E, name: str):
    """``name``: the export section's byte length (``xax_pe._export_section``)."""
    p = e.p
    e.var(f"{name}_n", e.add(e.ld(D_NEXPORTS), e.ld(D_NFORWARDS)))
    e.var(f"{name}_pa", _at(e, G_PAY, e.ld(D_PACKAGE)))
    e.var(name, e.add(e.add(40, e.mul(p[f"{name}_n"], 10)), e.add(_payload_uleb(e, f"{name}_pa"), len(DLL_SUFFIX) + 1)))
    e.for_(f"{name}_k", 0, e.ld(D_NEXPORTS), lambda: e.set(name, e.add(p[name], e.add(_entry(e, e.ld(D_EXPORTS), p[f"{name}_k"], 1), 1))))
    e.for_(f"{name}_k", 0, e.ld(D_NFORWARDS), lambda: e.set(name, e.add(p[name], e.add(e.add(
        _entry(e, e.ld(D_FORWARDS), p[f"{name}_k"], 1), _entry(e, e.ld(D_FORWARDS), p[f"{name}_k"], 3)), 2))))


def _dll_edata(tables):
    """``xax_pe._export_section(rva, dll_name, exports)``: the directory, address, name and ordinal tables, then the
    DLL name and each name (a forward's ``module.Symbol`` after its name), appended to the container."""
    from xax_selfhost_general_image import I_BASES, _elf
    from xax_selfhost_general_regalloc import _ra
    from xax_selfhost_general_view import G_CIDX

    def build(e: E):
        p = e.p
        rva = p["erva"]
        e.var("en", e.add(e.ld(D_NEXPORTS), e.ld(D_NFORWARDS)))
        e.var("esorted", e.add(e.ld(D_ROOTS), e.add(e.ld(D_NROOTS), 1)))
        e.var("efun", e.add(rva, 40))
        e.var("enames", e.add(p["efun"], e.mul(p["en"], 4)))
        e.var("eords", e.add(p["enames"], e.mul(p["en"], 4)))
        e.var("estr", e.add(p["eords"], e.mul(p["en"], 2)))
        e.var("epa", _at(e, G_PAY, e.ld(D_PACKAGE)))
        e.var("epn", _payload_uleb(e, "epa"))
        for value, size in ((0, 4), (0, 4), (0, 2), (0, 2), (p["estr"], 4), (1, 4), (p["en"], 4), (p["en"], 4), (p["efun"], 4),
                            (p["enames"], 4), (p["eords"], 4)):
            _elf(e, value, size)
        # Addresses: an export's function in ``.text``, a forward's target string.
        e.var("eoff", e.add(p["epn"], len(DLL_SUFFIX) + 1))

        def address():
            e.var("eidx", e.ld(e.add(p["esorted"], p["ek"])))
            _names(e, p["eidx"], "ea")

            def export():
                e.var("ef", e.ld(e.add(p["ea_r"], 2)))
                e.var("efx", e.ld(e.add(_g(e, G_CIDX), p["ef"])))
                _ok(e, e.ne(p["efx"], NONE))
                _elf(e, e.add(p["etext"], e.ld(e.add(_ra(e, I_BASES), p["efx"]))), 4)
                e.set("eoff", e.add(p["eoff"], e.add(p["ea_n"], 1)))

            def forward():
                e.set("eoff", e.add(p["eoff"], e.add(p["ea_n"], 1)))
                _elf(e, e.add(p["estr"], p["eoff"]), 4)
                e.set("eoff", e.add(p["eoff"], e.add(e.ld(e.add(p["ea_r"], 3)), 1)))

            e.if_(e.ne(p["ea_x"], 0), export, forward)

        e.for_("ek", 0, p["en"], address)
        e.set("eoff", e.add(p["epn"], len(DLL_SUFFIX) + 1))

        def name_pointer():
            e.var("eidx", e.ld(e.add(p["esorted"], p["ek"])))
            _names(e, p["eidx"], "eb")
            _elf(e, e.add(p["estr"], p["eoff"]), 4)
            e.set("eoff", e.add(p["eoff"], e.add(p["eb_n"], 1)))
            e.if_(e.eq(p["eb_x"], 0), lambda: e.set("eoff", e.add(p["eoff"], e.add(e.ld(e.add(p["eb_r"], 3)), 1))))

        e.for_("ek", 0, p["en"], name_pointer)
        e.for_("ek", 0, p["en"], lambda: _elf(e, p["ek"], 2))
        e.for_("ek", 0, p["epn"], lambda: _elf(e, e.rd(e.add(p["epa"], p["ek"])), 1))
        for byte in DLL_SUFFIX + b"\0":
            _elf(e, byte, 1)

        def strings():
            e.var("eidx", e.ld(e.add(p["esorted"], p["ek"])))
            _names(e, p["eidx"], "ec")
            e.for_("ej", 0, p["ec_n"], lambda: _elf(e, e.rd(e.add(p["ec_at"], p["ej"])), 1))
            _elf(e, 0, 1)

            def target():
                e.var("etat", e.ld(e.add(p["ec_r"], 2)))
                e.for_("ej", 0, e.ld(e.add(p["ec_r"], 3)), lambda: _elf(e, e.rd(e.add(p["etat"], p["ej"])), 1))
                _elf(e, 0, 1)

            e.if_(e.eq(p["ec_x"], 0), target)

        e.for_("ek", 0, p["en"], strings)
        e.give(1)
    return _function(("erva", "etext"), build, tables)


def add_dll_functions(add, tables):
    add("dll_main", _dll_main(tables))
    add("dll_plan", _dll_plan(tables))
    add("dll_root", _dll_root(tables))
    add("dll_sort", _dll_sort(tables))
    add("dll_names", _dll_names(tables))
    add("dll_edata", _dll_edata(tables))
