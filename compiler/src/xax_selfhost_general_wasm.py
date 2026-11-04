"""Self-hosting step S15e.4 (ADR-322): the browser page's WebAssembly module and page written by the general program.

``xax_build.build`` makes the artifact of a ``wasm32-browser-v1`` target (architecture 2) with
``xax_wasm.compile_wasm_bound_target`` (its general profile: ``_function_closure``, the foreign carriers, the event
entries, ``_memory_layout``, the command container, ``_compile_function`` per function in CID order) and
``xax_web.emit_browser_page``.  The general x86-64 program takes this path for such a target
(``xax_selfhost_request.PATH_WASM_PAGE``): ``wasm`` decides the same rejections in the same order (``WASM-ABI-VALUE``,
``WASM-OP-TARGET-SUPPORTED``, ``WASM-FUNCTION-ADDRESS-EVENT-ENTRY``, ``WASM-TERMINATOR-TARGET-SUPPORTED``,
``WASM-REENTRANT-FRAME``, ``WASM-FOREIGN-ABI``, ``ABI-LAYOUT-VALUE-TYPE``, ``WASM-STATIC-MEMORY-LIMIT``,
``WASI-START-NO-MACHINE-VALUES``, the lowering's own, ``WEB-IMPORT-DECLARED``) and writes the page, byte for byte, as
the image record's container bytes.  Aggregate layouts are ``abi_layout``'s with 4-byte pointers (``W_ON``).  Values
the bootstrap would turn into an invalid module or a host exception (bits wider than 64, non-power-of-two
alignments, 32-bit immediates outside 32 bits, non-ASCII names) and capacities past the program's buffers decline.
"""

from __future__ import annotations

from xax_selfhost_facts import E, NONE
from xax_selfhost_views_backend import GLOBALS, G_PAY, _FOREIGN_PREFIX, _at, _call, _ok, _payload_uleb, _type_form

WA = GLOBALS + 192
(W_ON, W_F, W_G, W_B, W_ENTRY, W_BLK, W_NODE, W_NV, W_VAL, W_IDS, W_IFACE, W_FUNCS, W_NF, W_FIDX, W_ACT, W_DONE, W_REC,
 W_STACK, W_DEPTH, W_CARR, W_NCARR, W_IMPIDX, W_EVT, W_EVL, W_NEVT, W_CURSOR, W_LOC, W_NLOC, W_PC, W_SCR, W_CUR, W_SIGS,
 W_NSIGS, W_TYIDX, W_IMPTY, W_SPAN, W_EF, W_THR, W_KIND) = (WA + k for k in range(39))
BUF = WA + 40  # buffers: base, length, capacity
CODE, BODIES, MODULE, PART, PAGE = (BUF + 3 * k for k in range(5))
assert PAGE + 3 <= GLOBALS + 256
NODE_W = 10
I32, I64, F32, F64 = 0x7F, 0x7E, 0x7D, 0x7C
AGGREGATES = (8, 9, 10)
# ``xax_web``: the library, the declared bindings (sorted, as ``WEB-IMPORT-DECLARED`` lists them) and their host code.

LOAD = {(32, 1): 0x2D, (32, 2): 0x2F, (32, 4): 0x28, (64, 1): 0x31, (64, 2): 0x33, (64, 4): 0x35, (64, 8): 0x29}
STORE = {(32, 1): 0x3A, (32, 2): 0x3B, (32, 4): 0x36, (64, 1): 0x3C, (64, 2): 0x3D, (64, 4): 0x3E, (64, 8): 0x37}
FLOAT_COMPARE = {1: 0, 2: 1, 3: 2, 5: 3, 4: 4, 6: 5}  # FloatCompare -> offset from eq


# -- small helpers --------------------------------------------------------------------------------

def _rec(e: E, table_slot, index, width, field):
    return e.ld(e.add(e.add(e.ld(table_slot), e.mul(index, width)), field))


def _node(e: E, k, field):
    return _rec(e, W_NODE, k, NODE_W, field)


def _list(e: E, slot, k):
    return e.ld(e.add(e.ld(slot), k))


def _proof(e: E, t):
    form = _type_form(e, t)
    return e.either(e.eq(form, 3), e.eq(form, 4))


def _bits_width(e: E, t, name: str):
    """``decode_bits_width`` (a verified bits type) into ``name``."""
    e.var(f"{name}_at", e.add(_at(e, G_PAY, t), 1))
    e.var(name, _payload_uleb(e, f"{name}_at"))
    return e.p[name]


def _float_width(e: E, t):
    return e.sel(e.eq(e.rd(e.add(_at(e, G_PAY, t), 1)), 1), 32, 64)


def _width(e: E, t, name: str):
    """``_width``: bits and float widths, 32 for pointers, links and aggregates, NONE otherwise."""
    p = e.p
    e.var(f"{name}_f", _type_form(e, t))
    e.var(name, NONE)
    e.if_(e.eq(p[f"{name}_f"], 1), lambda: e.set(name, _bits_width(e, t, f"{name}_b")))
    e.if_(e.eq(p[f"{name}_f"], 7), lambda: e.set(name, _float_width(e, t)))
    e.if_(e.either(*(e.eq(p[f"{name}_f"], f) for f in (2, 11, 8, 9, 10))), lambda: e.set(name, 32))
    return p[name]


def _aggregate(e: E, t):
    form = _type_form(e, t)
    return e.either(*(e.eq(form, f) for f in AGGREGATES))


def _table(e: E, key_conditions):
    """The value of the first ``(condition, value)`` pair whose condition holds, else 0."""
    result = e.c(0)
    for condition, value in reversed(key_conditions):
        result = e.sel(condition, value, result)
    return result


# -- byte buffers: the current one is ``W_CUR``'s ------------------------------------------------

def _use(e: E, buf):
    e.st(W_CUR, buf)


def _b(e: E, byte):
    _call(e, "wa_b", byte)


def _bytes(e: E, data: bytes):
    for start in range(0, len(data), 7):
        chunk = data[start:start + 7]
        _call(e, "wa_bs", int.from_bytes(chunk, "little"), len(chunk))


def _u(e: E, value):
    _call(e, "wa_u", value)


def _mask(e: E, width):
    _call(e, "wa_mask", width)


# -- the function index ----------------------------------------------------------------------------


# -- the closure -------------------------------------------------------------------------------


# -- imports and event entries ---------------------------------------------------------------------

def _declaration(e: E, carrier, name: str):
    """``decode_foreign_function``: ``name_abi``/``name_abin``, ``name_lib``/``name_libn``, ``name_sym``/``name_symn``, and
    ``name_types`` (the input count's position) of a carrier (declines unless it has the prefix)."""
    p = e.p
    e.var(f"{name}_at", _at(e, G_PAY, carrier))
    _payload_uleb(e, f"{name}_at")
    for k, byte in enumerate(_FOREIGN_PREFIX):
        _ok(e, e.eq(e.rd(e.add(p[f"{name}_at"], k)), byte))
    e.set(f"{name}_at", e.add(p[f"{name}_at"], len(_FOREIGN_PREFIX)))
    for field in ("abi", "lib", "sym"):
        e.var(f"{name}_{field}n", _payload_uleb(e, f"{name}_at"))
        e.var(f"{name}_{field}", p[f"{name}_at"])
        e.set(f"{name}_at", e.add(p[f"{name}_at"], p[f"{name}_{field}n"]))
    e.var(f"{name}_types", p[f"{name}_at"])


# -- static memory -----------------------------------------------------------------------------------


# -- locals and pointer extents ----------------------------------------------------------------------


# -- the nodes -------------------------------------------------------------------------------------


# -- the module ----------------------------------------------------------------------------------


def _digits(e: E, value, name: str):
    """The number of decimal digits of ``value``."""
    p = e.p
    e.var(f"{name}_n", 1)
    e.var(f"{name}_d", 10)
    e.while_(lambda: e.le(p[f"{name}_d"], value), lambda: (e.set(f"{name}_n", e.add(p[f"{name}_n"], 1)), e.set(f"{name}_d", e.mul(p[f"{name}_d"], 10))))
    return p[f"{name}_n"]


# -- the page --------------------------------------------------------------------------------------

ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def wasm_page_with_xax(reader, function_cid: bytes, target_object, required: bool = False) -> bytes | None:
    """The page the general program writes for a verified store (``xax_selfhost_general_accel.accelerator_with_xax``'s
    shape)."""
    from xax_selfhost_general_accel import accelerator_with_xax

    return accelerator_with_xax(reader, function_cid, target_object, required)


def browser_page(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s browser page: S15e.4 (ADR-322) decided by the XAX general program where it runs and decides (``"auto"``;
    ``"xax"`` requires it), else ``xax_wasm.compile_wasm_bound_target`` and ``xax_web.emit_browser_page``.  With
    ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_wasm import compile_wasm_bound_target
    from xax_web import emit_browser_page

    def reference() -> bytes:
        return emit_browser_page(compile_wasm_bound_target(reader, function_cid, target_object))

    if frontend == "python":
        return reference()
    page = wasm_page_with_xax(reader, function_cid, target_object, required=frontend == "xax")
    if page is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15e.4: the bootstrap rejects ({error.diagnostic.rule}) a page the XAX program wrote") from error
        if page != expected:
            raise AssertionError("S15e.4 browser pages disagree")
    return page


def wasm_module(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s module for an architecture-2 target other than the browser page (S15f.1, ADR-324): the XAX general
    program where it runs and decides (``"auto"``; ``"xax"`` requires it), else ``compile_wasm_bound_target``.  With
    ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_wasm import compile_wasm_bound_target

    def reference() -> bytes:
        return compile_wasm_bound_target(reader, function_cid, target_object).artifact_bytes

    if frontend == "python":
        return reference()
    module = wasm_page_with_xax(reader, function_cid, target_object, required=frontend == "xax")
    if module is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15f.1: the bootstrap rejects ({error.diagnostic.rule}) a module the XAX program wrote") from error
        if module != expected:
            raise AssertionError("S15f.1 Wasm modules disagree")
    return module
