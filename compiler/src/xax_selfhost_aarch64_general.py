"""Self-hosting step S15e.2 (ADR-315): Linux AArch64 executables built by an XAX program.

``xax_linux_aarch64.compile_linux_aarch64_executable`` builds ``aarch64-linux-elf-exec-v1`` (and the dynamic-loader
profile) programs.  Before any code it decides, in this order:

1. the target: architecture 3, the Linux AArch64 ABI, an ELF executable format (``LINUX-AARCH64-ELF-EXEC-TARGET``);
2. the process entry (``validate_process_entry``, shared with x86-64: ``LINUX-ENTRY-FUNCTION``,
   ``LINUX-PROCESS-ENTRY-CONTRACT``);
3. the function closure (``xax_aarch64._function_closure``), depth first from the entry: per function (the Linux
   profiles are ``_general_aarch64_target``) every machine value's AAPCS64 layout and at most one machine result
   (``AARCH64-ABI-RETURNS``); per node in block order the target's operation list
   (``AARCH64-OP-TARGET-SUPPORTED``) and the visit of a called function that is not an erased proof function; per
   block the target's terminator list (``AARCH64-TERMINATOR-TARGET-SUPPORTED``);
4. the image's function order: the closure by CID.

Then each function is lowered (``xax_aarch64._compile_function``): on the Linux profiles first by the function-wide
register allocator (``xax_aarch64_regalloc.compile_linux_function``) over the lowering view
(``xax_inline.inline_leaf_calls``, the same view the x86-64 program builds, ``xax_selfhost_general_view``).

This module builds the program: the front end here, the view from ``xax_selfhost_general_view``, value ranges from
``xax_selfhost_general_ranges``, and the AArch64 lowering, image and ELF container from
``xax_selfhost_aarch64_lower``.  Its input is the general program's object table
(``xax_selfhost_x86_64_general.general_object_table``).  A function the register allocator returns None for is
lowered on the frame path (``xax_selfhost_aarch64_frame``, S15e.2b).  Where the bootstrap would take another path (the
legacy register path, a code address, an indirect call, an atomic operation) the program declines and the bootstrap
builds.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, NONE, _function
import xax_selfhost_diagnostics as D
from xax_selfhost_views_backend import (
    _FN, G_NI, G_PAY, G_SUP, G_SUP_AT, G_TW, GLOBALS, NI_ENTITY, NI_OP, NI_RESULTS, NativeProgram, _at, _call, _cid_words, _g, _kind, _ok, _payload_uleb, _reference, _target_list, _type_form)
from xax_selfhost_aarch64_frame import G_A64ANDROID
from xax_selfhost_x86_64_general import G_GROUPOF, G_MTAB, _proof

STORE_PATH = bootstrap_dir() / "xax_aarch64_general.xax"
AARCH64 = 3
DECLINE_OPERATIONS = (int(Operation.FUNCTION_ADDRESS),)  # code addresses: the bootstrap's bundle carries their fixups

# The bootstrap's rejections this program decides: (code, rule) by site.
RULES = (
    ("XAX.LINUX.TARGET", "LINUX-AARCH64-ELF-EXEC-TARGET"),
    ("XAX.LINUX.ENTRY", "LINUX-ENTRY-FUNCTION"),
    ("XAX.LINUX.ENTRY", "LINUX-PROCESS-ENTRY-CONTRACT"),
    ("XAX.AARCH64.ABI", "AARCH64-ABI-RETURNS"),
    ("XAX.AARCH64.UNSUPPORTED_OPERATION", "AARCH64-OP-TARGET-SUPPORTED"),
    ("XAX.AARCH64.UNSUPPORTED_TERMINATOR", "AARCH64-TERMINATOR-TARGET-SUPPORTED"),
    ("XAX.FOREIGN.ABI", "AARCH64-FOREIGN-ABI"),  # during code generation (``_require_foreign_abi``)
    ("XAX.AARCH64.FRAME", "AARCH64-FRAME-SIZE"),  # S15e.2b (ADR-316): the frame path's layout
    # S15e.6h.1 (ADR-354): ``_require_android_entry`` of an Android bundle's code address.
    ("XAX.AARCH64.FOREIGN_ENTRY", "AARCH64-FOREIGN-ENTRY-TARGET"),
    ("XAX.AARCH64.FOREIGN_ENTRY", "AARCH64-ENTRY-SIGNATURE"),
)
SITE = {rule: site for site, (_code, rule) in enumerate(RULES)}


def _diagnostic(tables):
    """The record's code, entity CID (object ``entity``), and rule for ``site``."""
    def build(e: E):
        p = e.p
        for site, (code, _rule) in enumerate(RULES):
            e.if_(e.eq(p["site"], site), lambda code=code: D.text(e, code))
        D.cid(e, _cid_words(e, p["entity"]))
        for site, (_code, rule) in enumerate(RULES):
            e.if_(e.eq(p["site"], site), lambda rule=rule: D.text(e, rule))
        e.give(1)
    return _function(("site", "entity"), build, tables)


def _reject(e: E, condition, rule: str, entity, expected, actual):
    """Unless ``condition``: reject under ``rule`` on object ``entity``."""
    def write():
        e.call(_FN["diagnostic"], SITE[rule], entity)
        expected()
        actual()
    D.reject_unless(e, condition, write)


def _prologue(tables):
    """``_function_closure``'s checks of function ``f`` before its graph, on a ``_general_aarch64_target``: every
    machine value's AAPCS64 layout (a value without one declines: the bootstrap's AARCH64-ABI-VALUE), then at most
    one machine result (``AARCH64-ABI-RETURNS``).  1, or NONE (rejected or declined)."""
    def build(e: E):
        p = e.p
        e.var("pi", _call(e, "interface", p["f"]))
        e.var("pnp", e.ld(e.add(p["pi"], 1)))
        e.var("prt", e.add(e.add(p["pi"], 2), p["pnp"]))
        e.var("pnr", e.ld(p["prt"]))
        e.var("pb", _call(e, "borrowed", p["f"]))

        def param(q):
            return e.ld(e.add(e.add(p["pi"], 2), q))

        def ret(q):
            return e.ld(e.add(e.add(p["prt"], 1), q))

        def scalar(t):
            _call(e, "abi_layout", t)  # S15e.2b (ADR-316): floats, products and sums are laid out too

        def register(t):
            """S15f.4 (ADR-325): on a target that is not ``_general_aarch64_target`` a machine value is a bits value of
            at most 64 bits or a pointer in one register; anything else (the bootstrap's AARCH64-ABI) declines."""
            e.var("pform", _type_form(e, t))
            e.var("pat", e.add(_at(e, G_PAY, e.sel(e.eq(p["pform"], 1), t, 0)), 1))
            _ok(e, e.either(e.eq(p["pform"], 2), e.both(e.eq(p["pform"], 1), e.le(_payload_uleb(e, "pat"), 64))))

        from xax_selfhost_aarch64_frame import _general

        e.var("pgeneral", _general(e))
        e.var("pmp", 0)
        e.for_("q", 0, p["pnp"], lambda: e.if_(e.not_(_proof(e, param(p["q"]))), lambda: (
            e.set("pmp", e.add(p["pmp"], 1)), e.if_(e.ne(p["pgeneral"], 0), lambda: scalar(param(p["q"])), lambda: register(param(p["q"]))))))
        e.var("pmr", 0)
        e.for_("q", 0, p["pnr"], lambda: e.if_(e.both(e.not_(_proof(e, ret(p["q"]))), e.eq(e.ld(e.add(p["pb"], p["q"])), NONE)), lambda: (
            e.if_(e.ne(p["pgeneral"], 0), lambda: scalar(ret(p["q"])), lambda: register(ret(p["q"]))), e.set("pmr", e.add(p["pmr"], 1)))))
        e.if_(e.eq(p["pgeneral"], 0), lambda: _ok(e, e.both(e.le(p["pmp"], 8), e.le(p["pmr"], 1))))
        _reject(e, e.le(p["pmr"], 1), "AARCH64-ABI-RETURNS", p["f"], lambda: D.integer(e, 1), lambda: D.integer(e, p["pmr"]))
        e.give(1)
    return _function(("f",), build, tables)


def _node(tables):
    """``_function_closure``'s checks of the node just read (``G_NI``) in graph ``g`` of function ``f``: the target's
    operation list, and the visit of a called function.  In a group member's graph ``call.group_member`` is a direct
    call of member ``member`` of the same group (``parse_function_graph``, S15e.2b).  The function it visits, NONE-1
    when there is none, NONE when rejected or declined (a code address: the bootstrap decides)."""
    def build(e: E):
        p = e.p
        ni = _g(e, G_NI)
        e.var("nraw", e.ld(e.add(ni, NI_OP)))
        e.var("nop", e.sel(e.eq(p["nraw"], int(Operation.CALL_GROUP_MEMBER)), int(Operation.CALL_DIRECT), p["nraw"]))
        op = p["nop"]
        e.var("nandroid", e.ld(GLOBALS + G_A64ANDROID))
        _ok(e, e.either(e.not_(e.either(*(e.eq(op, item) for item in DECLINE_OPERATIONS))), e.ne(p["nandroid"], 0)))
        supported = e.both(e.lt(op, 256), e.ne(_at(e, G_SUP, e.sel(e.lt(op, 256), op, 0)), 0))
        _reject(e, supported, "AARCH64-OP-TARGET-SUPPORTED", p["g"], lambda: _target_list(e, G_SUP_AT), lambda: D.integer(e, op))
        e.var("nvisit", NONE - 1)

        def callee():
            e.var("nc", NONE)

            def direct():
                entity = e.ld(e.add(ni, NI_ENTITY))
                _ok(e, e.ne(entity, NONE))
                e.set("nc", _reference(e, p["g"], entity))

            def sibling():
                e.var("ngroup", e.ld(e.add(_g(e, G_GROUPOF), p["f"])))
                _ok(e, e.ne(p["ngroup"], NONE))
                e.var("nmembers", e.ld(e.add(_g(e, G_MTAB), p["ngroup"])))
                _ok(e, e.both(e.ne(p["nmembers"], NONE), e.lt(p["member"], e.ld(p["nmembers"]))))
                e.set("nc", e.ld(e.add(e.add(p["nmembers"], 1), p["member"])))

            e.if_(e.eq(p["nraw"], int(Operation.CALL_GROUP_MEMBER)), sibling, direct)
            _ok(e, e.both(e.ne(p["nc"], NONE), e.eq(_kind(e, p["nc"]), int(Kind.FUNCTION))))
            fresh = e.eq(e.ld(e.add(_g(e, G_TW), p["nc"])), 0)
            e.if_(e.both(fresh, e.eq(_call(e, "erased", p["nc"]), 0)), lambda: e.set("nvisit", p["nc"]))

        e.if_(e.eq(op, int(Operation.CALL_DIRECT)), callee)

        def address():
            """S15e.6h.1: ``function.address`` on an Android bundle visits the addressed function (erased or not) after
            ``_require_android_entry``'s checks of a code-entry type (``a64_android_entry``)."""
            entity = e.ld(e.add(ni, NI_ENTITY))
            _ok(e, e.ne(entity, NONE))
            e.var("na", _reference(e, p["g"], entity))
            _ok(e, e.both(e.ne(p["na"], NONE), e.eq(_kind(e, p["na"]), int(Kind.FUNCTION))))
            e.var("nres", e.ld(e.add(ni, NI_RESULTS)))
            _ok(e, e.le(1, e.rd(p["nres"])))
            e.var("nrtype", _reference(e, p["g"], e.rd(e.add(p["nres"], 1))))
            _ok(e, e.ne(p["nrtype"], NONE))
            _call(e, "a64_android_entry", p["nrtype"], p["na"], p["g"])
            e.if_(e.eq(e.ld(e.add(_g(e, G_TW), p["na"])), 0), lambda: e.set("nvisit", p["na"]))

        e.if_(e.both(e.eq(op, int(Operation.FUNCTION_ADDRESS)), e.ne(p["nandroid"], 0)), address)
        e.give(p["nvisit"])
    return _function(("g", "f", "member"), build, tables)


_PROGRAM = NativeProgram(STORE_PATH, "aarch64-general")
OPT_OUT = "XAX_AARCH64_GENERAL_PYTHON"


def native_aarch64():
    """The native AArch64 program, or None where it cannot run."""
    return _PROGRAM.native(OPT_OUT)


def _read_record(read):
    """The image record's words (``xax_selfhost_aarch64_image``), up to the program's cursor."""
    from xax_selfhost_general_image import I_CURSOR, IMAGE_AT, IMAGE_END
    from xax_selfhost_general_regalloc import G_RA

    (table,) = read(GLOBALS + G_RA, 1)
    (end,) = read(table + I_CURSOR, 1)
    return read(IMAGE_AT, end - IMAGE_AT) if IMAGE_AT < end <= IMAGE_END else []


def _parsed_record(words, closure, target_cid: bytes):
    """``(bundle, ELF bytes, the bundle's file offset, needed libraries)`` of the record, or None when it says "not
    decided"."""
    from xax_aarch64 import Aarch64Bundle
    from xax_artifact import ArtifactSemanticRange

    if not words or words[0] != 1:
        return None
    position = 1

    def take(count=1):
        nonlocal position
        position += count
        return words[position - count:position]

    def packed():
        (length,) = take()
        return b"".join(word.to_bytes(8, "little") for word in take((length + 7) // 8))[:length]

    def text():
        (length,) = take()
        return bytes(take(length))

    code = packed()
    elf = packed()
    code_offset, _entry, members = take(3)
    placed = []
    for function in closure[:members]:
        base, length, count = take(3)
        flat = take(4 * count)
        nodes = [ArtifactSemanticRange(function.cid, *flat[k:k + 2], base + flat[k + 2], base + flat[k + 3]) for k in range(0, len(flat), 4)]
        placed.append((function.cid, base, length, nodes))
    foreign = []
    for _ in range(take()[0]):
        (at,) = take()
        foreign.append((at, text(), text()))
    needed = tuple(text() for _ in range(take()[0]))
    placed.sort(key=lambda item: item[0])
    ranges = []
    for cid, base, length, nodes in placed:
        ranges.append(ArtifactSemanticRange(cid, None, None, base, base + length))
        ranges.extend(nodes)
    bundle = Aarch64Bundle(code, target_cid, tuple((cid, base) for cid, base, _length, _nodes in placed), tuple(foreign), tuple(ranges))
    return bundle, elf, code_offset, needed


def _executable(words, closure, reader, target_cid: bytes):
    """The ``LinuxAarch64Executable`` of the record, or None when it says "not decided"."""
    from xax_artifact import ArtifactSemanticRange
    from xax_linux_aarch64 import LinuxAarch64Executable

    parsed = _parsed_record(words, closure, target_cid)
    if parsed is None:
        return None
    bundle, elf, code_offset, needed = parsed
    file_ranges = tuple(ArtifactSemanticRange(item.function_cid, item.block_index, item.node_index, code_offset + item.start, code_offset + item.end)
                        for item in bundle.semantic_ranges)
    return LinuxAarch64Executable(elf, bundle, target_cid, file_ranges, needed)


def aarch64_with_xax(reader, entry_cid: bytes, target_object, required: bool = False):
    """The executable the XAX program builds for a verified store, or None when it cannot run or declines (the
    bootstrap then builds), unless ``required``.  It raises the ``XaxError`` the program wrote when it rejects."""
    import xax_native
    from xax_compiler import XaxError, fail, store_resolver
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_x86_64_general import collect_order, general_object_table

    native = native_aarch64()
    table = None if native is None else general_object_table(reader, entry_cid, target_object)
    words, members = table if table is not None else (None, {})

    def collect(read):
        order = collect_order(read)
        return order, decode_diagnostic(read), (None if order is None else _read_record(read))

    outcome = None if words is None else native.run(words, collect)
    order, diagnostic, record = outcome if outcome is not None else (None, None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    executable = None
    if order is not None:
        resolve = store_resolver(reader)
        closure = tuple(members[cid] if cid in members else resolve(cid) for cid in order)
        executable = _executable(record, closure, reader, target_object.cid)
    if executable is None:
        if native is not None:
            xax_native.declined("aarch64-general", 1)
        if required:
            fail("XAX.AARCH64.GENERAL", entry_cid.hex(), "AARCH64-XAX-GENERAL", "built by the XAX AArch64 program", "unavailable or declined")
    return executable


def aarch64_raw_image(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s image for a bare-metal AArch64 load-image target (S15f.4, ADR-325): the XAX AArch64 program's
    bundle code where it runs and decides (``"auto"``; ``"xax"`` requires it), else
    ``compile_aarch64_bound_target``'s.  With ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    import xax_native
    from xax_aarch64 import compile_aarch64_bound_target
    from xax_compiler import XaxError, fail
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_x86_64_general import collect_order, general_object_table

    def reference() -> bytes:
        return compile_aarch64_bound_target(reader, function_cid, target_object).artifact_bytes

    if frontend == "python":
        return reference()
    native = native_aarch64()
    table = None if native is None else general_object_table(reader, function_cid, target_object)
    words = None if table is None else table[0]

    def collect(read):
        order = collect_order(read)
        return order, decode_diagnostic(read), (None if order is None else _read_record(read))

    outcome = None if words is None else native.run(words, collect)
    order, diagnostic, record = outcome if outcome is not None else (None, None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    image = None
    if order is not None and record and record[0] == 1:
        code_length = record[1]
        at = 2 + (code_length + 7) // 8
        length = record[at]
        image = b"".join(word.to_bytes(8, "little") for word in record[at + 1:at + 1 + (length + 7) // 8])[:length]
    if image is None:
        if native is not None:
            xax_native.declined("aarch64-general", 1)
        if frontend == "xax":
            fail("XAX.AARCH64.GENERAL", function_cid.hex(), "AARCH64-XAX-GENERAL", "built by the XAX AArch64 program", "unavailable or declined")
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15f.4: the bootstrap rejects ({error.diagnostic.rule}) an image the XAX program wrote") from error
        if image != expected:
            raise AssertionError("S15f.4 bare-metal AArch64 images disagree")
    return image


def android_bundle_with_xax(reader, function_cids, target_object, required: bool = False):
    """S15e.6h.1 (ADR-354): ``compile_aarch64_bundle_bound_target`` of an Android shared object's export functions as
    the XAX program builds it (the program reads the roots after the trap heads), or None when it cannot run or
    declines, unless ``required``.  It raises the ``XaxError`` the program wrote when it rejects."""
    import xax_native
    from xax_compiler import XaxError, fail, store_resolver
    from xax_riscv64 import _cid_words
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_x86_64_general import collect_order, general_object_table

    roots = tuple(dict.fromkeys(function_cids))
    native = native_aarch64() if roots else None
    table = None if native is None else general_object_table(reader, roots[0], target_object)
    words, members = table if table is not None else (None, {})
    if words is not None:
        words = [*words, len(roots), *(word for cid in roots for word in _cid_words(cid))]

    def collect(read):
        order = collect_order(read)
        return order, decode_diagnostic(read), (None if order is None else _read_record(read))

    outcome = None if words is None else native.run(words, collect)
    order, diagnostic, record = outcome if outcome is not None else (None, None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    bundle = None
    if order is not None:
        resolve = store_resolver(reader)
        closure = tuple(members[cid] if cid in members else resolve(cid) for cid in order)
        parsed = _parsed_record(record, closure, target_object.cid)
        bundle = None if parsed is None else parsed[0]
    if bundle is None:
        if native is not None:
            xax_native.declined("aarch64-general", 1)
        if required:
            fail("XAX.AARCH64.GENERAL", roots[0].hex() if roots else "bundle", "AARCH64-XAX-GENERAL", "built by the XAX AArch64 program",
                 "unavailable or declined")
    return bundle
