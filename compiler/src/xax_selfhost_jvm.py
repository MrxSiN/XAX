"""S15e.5 (ADR-327): JVM class files and JARs built by an XAX program (stage S15e.5a).

``xax_jvm.compile_jvm_bound_target`` decides, in this order: the entry is a FUNCTION, the target is architecture 5,
a process entry takes and returns only proof values, the closure (direct callees, depth first) with the target's
operation and terminator lists, the methods in closure CID order (``entry`` and ``f<k>``, internal descriptors put
one-slot parameters first), each method's code (``xax_selfhost_jvm_emit``), the shared members, ``main`` for an
executable JAR, the class file, and the deterministic stored JAR.

S15e.5a lowers the integer subset of ``jvm-classfile-v1`` (wrapping arithmetic, bitwise operations, rotations, width
changes, unsigned division and remainder, integer compares, constants, direct calls, resource operations); a float,
a foreign call, a memory or general profile, or anything the bootstrap would reject declines (the bootstrap builds).

Input: the general program's object table (``general_object_table``) followed by one word, 1 for a process entry.
Output: the image record at ``IMAGE_AT`` in the general program's layout (so the driver hashes and writes it as it does
an ELF file): the status (1), an empty code section (0), the JAR's length and its bytes packed eight to a word.
"""

from __future__ import annotations

from xax_compiler import Kind, Operation
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, NONE, _function
from xax_selfhost_jvm_code import D_I, D_J
from xax_selfhost_views_backend import (
    G_NI, G_SUP, G_TW, GLOBALS, NI_ENTITY, NI_OP, NativeProgram, _at, _call, _g, _kind, _ok, _reference)

STORE_PATH = bootstrap_dir() / "xax_jvm_general.xax"
JVM_ARCHITECTURE = 5
J_STATE = 211  # GLOBALS slot: the class state record
(J_POOL, J_ENTRY_INDEX, J_NFN, J_NAMES, J_DESCS, J_ARGS, J_RESULT, J_METHODS, J_NMETHODS, J_STORE, J_STORE_LEN, J_PK, J_PROCESS,
 J_CLASSNAME, J_SCRATCH, J_REFS, J_NREFS, J_TABLE, J_NTABLE, J_TABIX, J_CBG, J_NCBG, J_IFACES, J_NIFACES, J_FLAT, J_NEEDS, J_BYTES, J_NBYTES,
 J_V1, J_INIT, J_STACKS, J_CONTRACTS, J_NCONTRACTS, J_DISPATCH) = range(34)
STORE_CAP = 1 << 24
VERIFICATION = {D_I: 1, D_J: 2 + 2, 3: 2, 4: 3}  # I 1, J 4, F 2, D 3; Top 0


def _js(e: E, field: int):
    return e.ld(e.add(e.ld(GLOBALS + J_STATE), field))


def _set_js(e: E, field: int, value):
    e.st(e.add(e.ld(GLOBALS + J_STATE), field), value)


def _store_alloc(e: E, words, name: str):
    """Persistent words for the class (the method store survives the per-method arena resets)."""
    p = e.p
    e.var(name, e.add(_js(e, J_STORE), _js(e, J_STORE_LEN)))
    _ok(e, e.le(e.add(_js(e, J_STORE_LEN), words), STORE_CAP))
    _set_js(e, J_STORE_LEN, e.add(_js(e, J_STORE_LEN), words))
    return p[name]


# -- descriptors ------------------------------------------------------------------------------------------------------------


# -- one method ------------------------------------------------------------------------------------------------------------


def WORK():
    from xax_selfhost_jvm_emit import WORK_WORDS

    return WORK_WORDS


# -- the finished code, the frames, the method record ------------------------------------------------------------------------


def _fixed_method(e: E, kind: int, code: list, max_stack: int, max_locals: int):
    """A record for a generated member whose code is ``code`` (ints, or ``("pool", ...)`` placeholders already
    resolved by the caller into ``jf_*`` variables)."""


# -- the class file and the JAR ---------------------------------------------------------------------------------------------


# -- the front end ----------------------------------------------------------------------------------------------------------

def _node(tables):
    """The closure's check of the node just read (``G_NI``) in graph ``g``: the target's operation list (another
    declines), and a direct callee or an addressed function to visit (NONE-1: none)."""
    def build(e: E):
        p = e.p
        ni = _g(e, G_NI)
        e.var("nraw", e.ld(e.add(ni, NI_OP)))
        # In a group member's graph ``call.group_member`` is a direct call of a member of the same group (S15e.5h).
        e.var("ngroupcall", e.flag(e.eq(p["nraw"], int(Operation.CALL_GROUP_MEMBER))))
        e.var("nop", e.sel(e.ne(p["ngroupcall"], 0), int(Operation.CALL_DIRECT), p["nraw"]))
        op_ = p["nop"]
        supported = e.both(e.lt(op_, 256), e.ne(_at(e, G_SUP, e.sel(e.lt(op_, 256), op_, 0)), 0))
        _ok(e, supported)  # JVM-OP-TARGET-SUPPORTED: the bootstrap's
        e.var("nvisit", NONE - 1)

        def address():
            # ``pending.append(node.entity)``: callable through the function table (ADR-159), erased or not.
            e.var("na", _reference(e, p["g"], e.ld(e.add(ni, NI_ENTITY))))
            _ok(e, e.both(e.ne(p["na"], NONE), e.eq(_kind(e, p["na"]), int(Kind.FUNCTION))))
            e.if_(e.eq(e.ld(e.add(_g(e, G_TW), p["na"])), 0), lambda: e.set("nvisit", p["na"]))

        e.if_(e.eq(op_, int(Operation.FUNCTION_ADDRESS)), address)

        def callee():
            from xax_selfhost_x86_64_general import G_GROUPOF, G_MTAB

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

            e.if_(e.ne(p["ngroupcall"], 0), sibling, direct)
            _ok(e, e.both(e.ne(p["nc"], NONE), e.eq(_kind(e, p["nc"]), int(Kind.FUNCTION))))
            fresh = e.eq(e.ld(e.add(_g(e, G_TW), p["nc"])), 0)
            e.if_(e.both(fresh, e.eq(_call(e, "erased", p["nc"]), 0)), lambda: e.set("nvisit", p["nc"]))

        e.if_(e.eq(op_, int(Operation.CALL_DIRECT)), callee)
        e.give(p["nvisit"])
    return _function(("g", "f", "member"), build, tables)


_PROGRAM = NativeProgram(STORE_PATH, "jvm-general")
OPT_OUT = "XAX_JVM_GENERAL_PYTHON"


def native_jvm():
    return _PROGRAM.native(OPT_OUT)


def jvm_with_xax(reader, function_cid: bytes, target_object, *, process_entry: bool = False, required: bool = False) -> bytes | None:
    """The JAR the XAX program builds for a verified store, or None when it cannot run or declines (unless
    ``required``)."""
    import xax_native
    from xax_compiler import XaxError, fail
    from xax_selfhost_diagnostics import decode_diagnostic
    from xax_selfhost_general_image import IMAGE_AT
    from xax_selfhost_x86_64_general import general_object_table

    native = native_jvm()
    table = None if native is None else general_object_table(reader, function_cid, target_object)
    jar = None
    if table is not None:
        words = list(table[0]) + [int(process_entry)]

        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None, decode_diagnostic(read)
            head = read(IMAGE_AT, 3)
            if head[0] != 1:
                return None, None
            packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
            return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]], None

        outcome = native.run(words, collect)
        jar, diagnostic = outcome if outcome is not None else (None, None)
        if diagnostic is not None:
            raise XaxError(diagnostic)
    if jar is None:
        if native is not None:
            xax_native.declined("jvm-general", 1)
        if required:
            fail("XAX.JVM.GENERAL", function_cid.hex(), "JVM-XAX-GENERAL", "built by the XAX JVM program", "unavailable or declined")
    return jar


def jvm_jar(reader, function_cid: bytes, target_object, *, process_entry: bool = False, frontend: str = "auto") -> bytes:
    """``build``'s JAR for a JVM target (S15e.5, ADR-327): the XAX JVM program's where it runs and decides
    (``"auto"``; ``"xax"`` requires it), else ``compile_jvm_bound_target``'s.  With ``XAX_GENERAL_FRONTEND_DIFF=1``
    the two must agree."""
    import os

    from xax_compiler import XaxError
    from xax_jvm import compile_jvm_bound_target

    def reference() -> bytes:
        return compile_jvm_bound_target(reader, function_cid, target_object, process_entry=process_entry).jar

    if frontend == "python":
        return reference()
    jar = jvm_with_xax(reader, function_cid, target_object, process_entry=process_entry, required=frontend == "xax")
    if jar is None:
        return reference()
    if os.environ.get("XAX_GENERAL_FRONTEND_DIFF") == "1":
        try:
            expected = reference()
        except XaxError as error:
            raise AssertionError(f"S15e.5: the bootstrap rejects ({error.diagnostic.rule}) a JAR the XAX program wrote") from error
        if jar != expected:
            raise AssertionError("S15e.5 JARs disagree")
    return jar
