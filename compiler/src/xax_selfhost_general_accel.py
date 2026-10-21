"""Self-hosting step S15e.7a (ADR-321): accelerator deployment packets decided and written by the general program.

``xax_build.build`` makes an ``ACCELERATOR_DEPLOYMENT`` for a target of architecture 4 (image format 3) with
``xax_accelerator.compile_accelerator``: the target must declare target operations (``ACCELERATOR-TARGET-PROFILE``);
the entry is one block (``ACCELERATOR-SINGLE-BLOCK``) ending in a return (``ACCELERATOR-RETURN``) with the host
interface ``(bits<32>, bits<32>, effect<device,1>) -> (bits<32>, effect<device,1>)`` (``ACCELERATOR-HOST-INTERFACE``),
whose nodes are all ``target`` operations of that target (``ACCELERATOR-TARGET-OPS-ONLY``) in the deployment sequence
of semantic codes 1..6 (``ACCELERATOR-DEPLOY-SEQUENCE``); then the packet: ``MAGIC``, the format, the target's and the
entry's CIDs, the lane width and group count, the memory spaces, the runtime dependencies, and per node its encoding
opcode, semantic code, scope, spaces and flags.

The general x86-64 program takes this path when the driver gives it such a target (``xax_selfhost_request``'s
``PATH_ACCELERATOR``): ``accelerator`` decides and writes the packet as the image record's container bytes, the way the
ELF file is written, so the driver's ``build`` stores it and names it in the provenance.  A target operation contract
with a runtime dependency (the bootstrap requires the caller to allow it; ``build`` allows none) declines.
"""

from __future__ import annotations

from xax_accelerator import M13_DEPLOYMENT_FORMAT, MAGIC
from xax_compiler import BOARD_PROFILE, Kind, Operation, TerminatorKind
import xax_selfhost_diagnostics as D
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_views_backend import (
    G_NI, G_PAY, NI_ATTRIBUTES, NI_ENTITY, NI_OP, _at, _call, _cid_words, _kind, _ok, _payload_uleb, _reference,
)

CONTRACT_WORDS = 6  # operation id, semantic code, encoding opcode, synchronizes, may block, runtime dependency length
HOST_INTERFACE = ["bits<32>", "bits<32>", "effect<device,1>", "->", "bits<32>", "effect<device,1>"]
SEQUENCE = (1, 2, 3, 4, 5, 6)
BITS32 = (1, 32)  # ``bits_type(32).body``
DEVICE_ONE = (3, 4, 1)  # ``effect_type(EffectDomain.DEVICE, 1).body``


def _body_is(e: E, obj, data: tuple[int, ...]):
    """``obj`` is a reference-free TYPE whose body is exactly ``data``."""
    from xax_selfhost_views_backend import G_REC

    pay = _at(e, G_PAY, obj)
    return e.both(e.eq(_kind(e, obj), int(Kind.TYPE)), e.eq(e.rd(e.add(_at(e, G_REC, obj), 1)), 0), e.eq(e.rd(e.sub(pay, 1)), len(data)),
                  *(e.eq(e.rd(e.add(pay, k)), byte) for k, byte in enumerate(data)))


def _skip_list(e: E, name: str):
    _payload_uleb_count = _payload_uleb(e, name)
    e.var(f"{name}_c", _payload_uleb_count)
    e.for_(f"{name}_q", 0, e.p[f"{name}_c"], lambda: _payload_uleb(e, name))


def _accelerator(tables):
    """``compile_accelerator`` for entry function ``af`` and target ``at_``: 1 with the packet in the image record,
    NONE when rejected or declined."""
    from xax_selfhost_general_image import IMAGE_AT

    def build(e: E):
        p = e.p
        target = p["at_"]
        # ``decode_native_target``'s fields (a verified target object).
        e.var("ta", _at(e, G_PAY, target))
        e.set("ta", e.add(_payload_uleb(e, "ta"), p["ta"]))  # past the identity
        e.var("tprofile", _payload_uleb(e, "ta"))
        e.var("tarch", _payload_uleb(e, "ta"))
        for _field in range(4):  # ABI, format, word and pointer bits
            _payload_uleb(e, "ta")
        _ok(e, e.eq(p["tarch"], 4))
        _skip_list(e, "ta")  # operations
        _skip_list(e, "ta")  # terminators

        def atomics():
            _skip_list(e, "ta")
            _skip_list(e, "ta")
            _skip_list(e, "ta")

            def handler():
                for _field in range(7):
                    _payload_uleb(e, "ta")
                _skip_list(e, "ta")
                _payload_uleb(e, "ta")
                _payload_uleb(e, "ta")

            e.for_("th", 0, _payload_uleb(e, "ta"), handler)

        e.if_(e.either(e.eq(p["tprofile"], 2), e.eq(p["tprofile"], BOARD_PROFILE)), atomics)
        e.var("lane", 0)
        e.var("groups", 0)
        e.var("nspaces", 0)
        e.var("spaces", e.alloc(256))
        _ok(e, e.ne(p["spaces"], NONE))
        e.var("contracts", e.alloc(256 * CONTRACT_WORDS))
        _ok(e, e.ne(p["contracts"], NONE))
        e.var("ncontracts", 0)

        def contract():
            _ok(e, e.lt(p["ncontracts"], 256))
            e.var("cw", e.add(p["contracts"], e.mul(p["ncontracts"], CONTRACT_WORDS)))
            for field in range(3):  # operation id, semantic code, encoding opcode
                e.st(e.add(p["cw"], field), _payload_uleb(e, "ta"))
            _ok(e, e.lt(e.ld(e.add(p["cw"], 2)), 256))  # ``bytes((opcode,))`` fails otherwise (declined)

            def constraint():
                for _field in range(3):
                    _payload_uleb(e, "ta")

            e.for_("tc", 0, _payload_uleb(e, "ta"), constraint)  # inputs
            e.for_("tc", 0, _payload_uleb(e, "ta"), constraint)  # outputs
            _skip_list(e, "ta")  # scopes
            _payload_uleb(e, "ta")  # source space
            _payload_uleb(e, "ta")  # destination space
            e.st(e.add(p["cw"], 3), e.rd(p["ta"]))
            e.st(e.add(p["cw"], 4), e.rd(e.add(p["ta"], 1)))
            e.set("ta", e.add(p["ta"], 2))
            e.var("tdep", _payload_uleb(e, "ta"))
            e.st(e.add(p["cw"], 5), p["tdep"])
            e.set("ta", e.add(p["ta"], p["tdep"]))
            e.set("ncontracts", e.add(p["ncontracts"], 1))

        def accelerator_fields():
            e.set("lane", _payload_uleb(e, "ta"))
            e.set("groups", _payload_uleb(e, "ta"))
            _skip_list(e, "ta")  # scopes

            def space():
                _ok(e, e.lt(p["nspaces"], 256))
                e.st(e.add(p["spaces"], p["nspaces"]), _payload_uleb(e, "ta"))
                for _field in range(3):
                    _payload_uleb(e, "ta")
                _skip_list(e, "ta")  # widths
                _skip_list(e, "ta")  # visibility
                e.set("ta", e.add(p["ta"], 2))
                e.set("nspaces", e.add(p["nspaces"], 1))

            e.for_("ts", 0, _payload_uleb(e, "ta"), space)
            e.for_("tk", 0, _payload_uleb(e, "ta"), contract)

        e.if_(e.eq(p["tprofile"], 3), accelerator_fields)
        e.if_(e.either(e.eq(p["tprofile"], 4), e.eq(p["tprofile"], BOARD_PROFILE)), lambda: e.for_("tk", 0, _payload_uleb(e, "ta"), contract))

        def head(code: str, entity, rule: str):
            D.text(e, code)
            D.cid(e, _cid_words(e, entity))
            D.text(e, rule)

        def profile():
            head("XAX.ACCELERATOR.TARGET", target, "ACCELERATOR-TARGET-PROFILE")
            D.integer(e, 4)
            D.integer(e, p["tarch"])

        D.reject_unless(e, e.ne(p["ncontracts"], 0), profile)
        # The entry: its interface, its graph's single block and return.
        f = p["af"]
        e.var("ai", _call(e, "interface", f))
        e.var("ag", e.ld(p["ai"]))
        e.var("anp", e.ld(e.add(p["ai"], 1)))
        e.var("art", e.add(e.add(p["ai"], 2), p["anp"]))
        e.var("as_", _at(e, G_PAY, p["ag"]))
        e.var("ablocks", e.rd(p["as_"]))
        e.var("aentry", e.rd(e.add(p["as_"], 1)))

        def single():
            head("XAX.ACCELERATOR.CFG", f, "ACCELERATOR-SINGLE-BLOCK")
            for value in ([1, 0], [p["ablocks"], p["aentry"]]):
                D.put(e, D.T_LIST)
                D.put(e, 2)
                for item in value:
                    D.integer(e, item)

        D.reject_unless(e, e.both(e.eq(p["ablocks"], 1), e.eq(p["aentry"], 0)), single)
        e.var("aat", e.add(p["as_"], 2))
        e.set("aat", e.add(e.add(p["aat"], 1), e.rd(p["aat"])))  # past the parameters
        e.var("anodes", e.rd(p["aat"]))
        e.set("aat", e.add(p["aat"], 1))
        e.var("anodes_at", p["aat"])
        e.for_("an", 0, p["anodes"], lambda: e.set("aat", _call(e, "node_info", p["aat"])))
        e.var("akind", e.rd(p["aat"]))

        def returns():
            head("XAX.ACCELERATOR.CFG", f, "ACCELERATOR-RETURN")
            D.text(e, TerminatorKind.RETURN.name)
            for kind in TerminatorKind:
                e.if_(e.eq(p["akind"], int(kind)), lambda kind=kind: D.text(e, kind.name))

        _ok(e, e.both(e.le(1, p["akind"]), e.le(p["akind"], 4)))
        D.reject_unless(e, e.eq(p["akind"], int(TerminatorKind.RETURN)), returns)
        e.var("anr", e.ld(p["art"]))
        param = lambda k: e.ld(e.add(e.add(p["ai"], 2), k))  # noqa: E731
        result = lambda k: e.ld(e.add(e.add(p["art"], 1), k))  # noqa: E731
        e.var("ahost", e.flag(e.both(e.eq(p["anp"], 3), e.eq(p["anr"], 2))))

        def typed():
            e.set("ahost", e.flag(e.both(_body_is(e, param(0), BITS32), _body_is(e, param(1), BITS32), _body_is(e, param(2), DEVICE_ONE),
                                         _body_is(e, result(0), BITS32), e.eq(result(1), param(2)))))

        e.if_(e.ne(p["ahost"], 0), typed)

        def interface():
            head("XAX.ACCELERATOR.ABI", f, "ACCELERATOR-HOST-INTERFACE")
            D.put(e, D.T_LIST)
            D.put(e, len(HOST_INTERFACE))
            for item in HOST_INTERFACE:
                D.text(e, item)
            D.put(e, D.T_LIST)
            D.put(e, e.add(p["anp"], p["anr"]))
            e.for_("aq", 0, p["anp"], lambda: D.cid(e, _cid_words(e, param(p["aq"]))))
            e.for_("aq", 0, p["anr"], lambda: D.cid(e, _cid_words(e, result(p["aq"]))))

        D.reject_unless(e, e.ne(p["ahost"], 0), interface)
        # The nodes: target operations of this target, their contracts, the deployment sequence.
        e.var("encoded", e.alloc(e.add(e.mul(p["anodes"], 6), 1)))
        _ok(e, e.ne(p["encoded"], NONE))
        e.set("aat", p["anodes_at"])

        def node():
            e.set("aat", _call(e, "node_info", p["aat"]))
            e.var("aop", e.ld(e.add(_g_ni(e), NI_OP)))
            e.var("aent", NONE)
            e.if_(e.eq(p["aop"], int(Operation.TARGET_OP)), lambda: e.set("aent", _reference(e, p["ag"], e.ld(e.add(_g_ni(e), NI_ENTITY)))))

            def other():
                head("XAX.ACCELERATOR.OPERATION", p["ag"], "ACCELERATOR-TARGET-OPS-ONLY")
                D.text(e, Operation.TARGET_OP.name)
                D.integer(e, p["aop"])

            D.reject_unless(e, e.both(e.eq(p["aop"], int(Operation.TARGET_OP)), e.eq(p["aent"], target)), other)
            e.var("aattr", e.ld(e.add(_g_ni(e), NI_ATTRIBUTES)))
            _ok(e, e.both(e.ne(p["aattr"], NONE), e.eq(e.rd(p["aattr"]), 4)))
            e.var("aid", e.rd(e.add(p["aattr"], 1)))
            e.var("acw", NONE)
            e.for_("ac", 0, p["ncontracts"], lambda: e.if_(e.eq(e.ld(e.add(p["contracts"], e.mul(p["ac"], CONTRACT_WORDS))), p["aid"]),
                                                          lambda: e.set("acw", e.add(p["contracts"], e.mul(p["ac"], CONTRACT_WORDS)))))
            _ok(e, e.ne(p["acw"], NONE))
            _ok(e, e.eq(e.ld(e.add(p["acw"], 5)), 0))  # a runtime dependency ``build`` does not allow: declined
            e.var("aenc", e.add(p["encoded"], e.mul(p["an"], 6)))
            e.st(p["aenc"], e.ld(e.add(p["acw"], 1)))  # semantic code
            e.st(e.add(p["aenc"], 1), e.ld(e.add(p["acw"], 2)))  # encoding opcode
            for k in range(3):  # scope, source and destination spaces
                e.st(e.add(p["aenc"], 2 + k), e.rd(e.add(p["aattr"], 2 + k)))
            e.st(e.add(p["aenc"], 5), e.add(e.ld(e.add(p["acw"], 3)), e.mul(e.ld(e.add(p["acw"], 4)), 256)))

        e.for_("an", 0, p["anodes"], node)
        e.var("aseq", e.flag(e.eq(p["anodes"], len(SEQUENCE))))
        e.for_("an", 0, p["anodes"], lambda: e.if_(e.ne(e.ld(e.add(p["encoded"], e.mul(p["an"], 6))), e.add(p["an"], 1)), lambda: e.set("aseq", 0)))

        def sequence():
            head("XAX.ACCELERATOR.SEQUENCE", p["ag"], "ACCELERATOR-DEPLOY-SEQUENCE")
            D.put(e, D.T_TUPLE)
            D.put(e, len(SEQUENCE))
            for value in SEQUENCE:
                D.integer(e, value)
            D.put(e, D.T_TUPLE)
            D.put(e, p["anodes"])
            e.for_("an", 0, p["anodes"], lambda: D.integer(e, e.ld(e.add(p["encoded"], e.mul(p["an"], 6)))))

        D.reject_unless(e, e.ne(p["aseq"], 0), sequence)
        # The packet, one byte per word, then packed into the image record as its container bytes.
        e.var("pk", e.alloc(e.add(e.add(e.mul(p["anodes"], 64), e.mul(p["nspaces"], 10)), 256)))
        _ok(e, e.ne(p["pk"], NONE))
        e.var("pn", 0)

        def byte(value):
            e.st(e.add(p["pk"], p["pn"]), value)
            e.set("pn", e.add(p["pn"], 1))

        def uleb(value):
            e.var("uv", value)
            e.var("ug", 1)

            def step():
                e.var("ub", e.and_(p["uv"], 127))
                e.set("uv", e.udiv(p["uv"], 128))
                e.if_(e.ne(p["uv"], 0), lambda: byte(e.or_(p["ub"], 128)), lambda: (byte(p["ub"]), e.set("ug", 0)))

            e.while_(lambda: e.ne(p["ug"], 0), step)

        def cid(obj):
            for word in _cid_words(e, obj):
                e.var("cw_w", word)
                for shift in range(7, -1, -1):
                    byte(e.and_(e.udiv(p["cw_w"], 1 << (8 * shift)) if shift else p["cw_w"], 255))

        for value in MAGIC:
            byte(value)
        uleb(M13_DEPLOYMENT_FORMAT)
        cid(target)
        cid(f)
        uleb(p["lane"])
        uleb(p["groups"])
        uleb(p["nspaces"])
        e.for_("aq", 0, p["nspaces"], lambda: uleb(e.ld(e.add(p["spaces"], p["aq"]))))
        uleb(0)  # no runtime dependencies
        uleb(p["anodes"])

        def encode():
            e.var("aenc", e.add(p["encoded"], e.mul(p["an"], 6)))
            byte(e.ld(e.add(p["aenc"], 1)))
            uleb(e.ld(p["aenc"]))
            for k in range(3):
                uleb(e.ld(e.add(p["aenc"], 2 + k)))
            e.var("aflags", e.ld(e.add(p["aenc"], 5)))
            byte(e.and_(p["aflags"], 255))
            byte(e.udiv(p["aflags"], 256))

        e.for_("an", 0, p["anodes"], encode)
        # The image record (``xax_selfhost_general_image._image_record_fn``'s layout): assembled, no code, the packet.
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(IMAGE_AT + 2, p["pn"])
        e.var("rw", 0)

        def word():
            e.var("ww", 0)
            e.var("wj", 8)
            e.while_(lambda: e.ne(p["wj"], 0), lambda: (
                e.set("wj", e.sub(p["wj"], 1)),
                e.var("wi", e.add(e.mul(p["rw"], 8), p["wj"])),
                e.set("ww", e.add(e.mul(p["ww"], 256), e.sel(e.lt(p["wi"], p["pn"]), e.ld(e.add(p["pk"], e.sel(e.lt(p["wi"], p["pn"]), p["wi"], 0))), 0)))))
            e.st(e.add(IMAGE_AT + 3, p["rw"]), p["ww"])
            e.set("rw", e.add(p["rw"], 1))

        e.while_(lambda: e.lt(e.mul(p["rw"], 8), p["pn"]), word)
        e.var("rtail", e.add(IMAGE_AT + 3, p["rw"]))
        for k in range(5):  # out, entry, members, imports, needed: none
            e.st(e.add(p["rtail"], k), 0)
        e.give(1)
    return _function(("af", "at_"), build, tables)


def _g_ni(e: E):
    from xax_selfhost_views_backend import _g

    return _g(e, G_NI)


def add_accelerator_functions(add, tables):
    add("accelerator", _accelerator(tables))


def accelerator_with_xax(reader, function_cid: bytes, target_object, required: bool = False) -> bytes | None:
    """The deployment packet the general program writes for a verified store, or None where it cannot run or declines
    (unless ``required``); it raises the ``XaxError`` the program wrote when it rejects."""
    import xax_native
    from xax_compiler import XaxError, fail
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_general_image import IMAGE_AT
    from xax_selfhost_x86_64_general import general_object_table, native_general

    native = native_general()
    table = None if native is None else general_object_table(reader, function_cid, target_object)

    def collect(read):
        (status,) = read(0, 1)
        if status != 1:
            return None, decode_diagnostic(read)
        assembled, _code, length = read(IMAGE_AT, 3)
        if assembled != 1:
            return None, None
        words = read(IMAGE_AT + 3, (length + 7) // 8)
        return b"".join(word.to_bytes(8, "little") for word in words)[:length], None

    packet, diagnostic = native.run(table[0], collect) if table is not None else (None, None)
    if diagnostic is not None:
        raise XaxError(diagnostic)
    if packet is None:
        if native is not None:
            xax_native.declined("x86-64-general-frontend", 1)
        if required:
            fail("XAX.X86_64.GENERAL_FRONTEND", function_cid.hex(), "X86_64-XAX-GENERAL-FRONTEND", "accepted by the XAX general front end",
                 "unavailable or declined")
    return packet


def accelerator_artifact(reader, function_cid: bytes, target_object, *, frontend: str = "auto") -> bytes:
    """``build``'s accelerator deployment: S15e.7a (ADR-321) decided by the XAX general program where it runs and decides
    (``"auto"``; ``"xax"`` requires it), else ``xax_accelerator.compile_accelerator_bound_target``.  With
    ``XAX_GENERAL_FRONTEND_DIFF=1`` the two must agree."""
    import os

    from xax_accelerator import compile_accelerator_bound_target
    from xax_compiler import XaxError

    def reference() -> bytes:
        return compile_accelerator_bound_target(reader, function_cid, target_object).artifact_bytes

    if frontend == "python":
        return reference()
    packet = accelerator_with_xax(reader, function_cid, target_object, required=frontend == "xax")
    if packet is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15e.7a: the bootstrap rejects ({error.diagnostic.rule}) a deployment the XAX program wrote") from error
        if packet != expected:
            raise AssertionError("S15e.7a accelerator deployments disagree")
    return packet
