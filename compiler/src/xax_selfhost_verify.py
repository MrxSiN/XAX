"""Self-hosting steps S6b.2 and S6b.3 (ADR-144, ADR-146): store-level and object-level verification as XAX semantics.

One XAX program, run natively like the typing program (ADR-132), reads every
store object (the S5b object table: kind, reference indices, CID, and the
body bytes; for a graph fragment the S3c XAX graph-decoder stream, then its
body bytes) and decides, with the bootstrap's rules:

* functions (``_verify_function``): for an ordinary graph, the exact
  interface body, a graph-fragment carrier, parameter and return types that
  are types the XAX object verdicts proved (ADR-143), exact reference use, no
  group member calls, and the graph contract (the entry block's parameters
  are the interface's, and every ``return`` returns values of its types); for
  a group member function, ``[group, member]`` naming a proven group and a
  member it has;
* recursion groups (``_verify_recursion_group``): the member list, each
  member graph's contract, every ``call.group_member`` naming a member and
  matching its interface, one recursive strongly connected component, and
  the canonical member order (member keys: graph reference CIDs, the graph
  bytes without member-call spans, parameter and return types);
* targets (``decode_native_target``): identity-only carriers, the general,
  concurrency, and platform profiles of every supported architecture, the
  accelerator profile, and the AArch64 board profile (S6b.4c);
* packages and build objects (S6b.4a/b): packages, profiles, trust
  policies, signatures, optimization policies, then requests, snapshots, and
  provenance, each later pass reading the earlier verdicts;
* every graph fragment's per-graph glue (S6b.4d): type references naming
  proven types, resolved entities, exact reference use, canonical trap
  payloads;
* module and program-root reference lists (``_verify_reference_list``);
* call contracts (``_decode_call_contract``);
* the store: every object reachable from the root, no reference cycle.

Its output is a verdict per object (each proven function's graph object, each
proven group's member graphs) and a store verdict.  A verdict holds only when
the bootstrap accepts; every other object, and every rejection, takes the
bootstrap path and its exact diagnostic.
"""

from __future__ import annotations

import ctypes
import threading

from xax_compiler import Kind
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, HEADER, NONE, _function, _uleb
from xax_selfhost_typing import IN_WORDS, OUT_WORDS

from xax_native import bootstrap_dir  # noqa: E402

STORE_PATH = bootstrap_dir() / "xax_store_verifier.xax"
VERDICTS_AT, GRAPHS_AT, ARENA_AT = 1 << 20, 6 << 20, 12 << 20
REJECTS_AT, REJECT_WORDS = 3 << 20, 8  # S8c.19 (ADR-237): a rejected object's record: site, payload words
OK = 1
STORE_FAULT = 5  # S8 (ADR-251): the store's own rejection: 1 a cycle (word 6: the object re-entered), 2 unreachable objects (word 6: the colours)
REJECTED = 2  # an object verdict: the bootstrap rejects this object with the recorded diagnostic
MODULE_CHILDREN = (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.RECURSION_GROUP, Kind.CALL_CONTRACT)
# Globals (the first arena words): table pointers.
GLOBALS = ARENA_AT
G_REC, G_O, G_TYPEOK, G_MARK, G_LIST, G_ULEB_STATUS, G_ULEB_SIZE, G_EXIT, G_SINK, G_GROUP_SIZE, G_GROUP_REACHED = range(11)  # G_LIST: a graph contract mismatch's quoted types (S8c.20)
_FN: dict = {}


def _g(e: E, slot: int):
    return e.ld(GLOBALS + slot)


def _rec(e: E, obj):
    return e.ld(e.add(_g(e, G_REC), obj))


def _kind(e: E, obj):
    return e.rd(_rec(e, obj))


def _references(e: E, obj):
    return e.rd(e.add(_rec(e, obj), 1))


def _reference(e: E, obj, k):
    return e.rd(e.add(e.add(_rec(e, obj), 2), k))


def _payload(e: E, obj):
    return e.add(e.add(e.add(_rec(e, obj), 2), _references(e, obj)), 5)


def _graph_rejected(e: E, graph):
    """S8 (ADR-251): the XAX graph decoder rejected this graph's body; its payload is the stream prefix before the
    rejection (the word after the body bytes)."""
    stream = _payload(e, graph)
    body_len_at = e.add(stream, e.rd(e.sub(stream, 1)))
    return e.ne(e.rd(e.add(e.add(body_len_at, 1), e.rd(body_len_at))), 0)


def _type_ok(e: E, obj):
    return e.both(e.lt(obj, _g(e, G_O)), e.ne(e.rd(e.add(_g(e, G_TYPEOK), e.sel(e.lt(obj, _g(e, G_O)), obj, 0))), 0))


DECLINE_SITES: list[str] = []  # diagnosis: out[2] names the check that gave the last 0 verdict


def _no(e: E, condition):
    """Verdict 0 when ``condition``."""
    import inspect

    frame = inspect.stack()[1]
    code = len(DECLINE_SITES) + 1
    DECLINE_SITES.append(f"{frame.function}:{frame.lineno}")
    e.if_(condition, lambda: (e.st(2, code), e.give(0)))


# S8c.19 (ADR-237): object rejections the bootstrap's ``verify_object`` raises, in its order, once the object's own
# references all resolve (its OBJECT_MISSING checks come first).
OBJECT_SITES = ("LIST_TRAILING", "LIST_REF_INDEX", "LIST_REFERENCE_BODY", "LIST_CHILD_KIND",
                "CONTRACT_REF_INDEX", "CONTRACT_TRUNCATED", "CONTRACT_BOOL", "CONTRACT_TRAILING", "CONTRACT_UNUSED",
                # S8c.20 (ADR-238): functions.  The last three come after the bootstrap parses the graph (payload word 0:
                # the graph object), so the host parses it first.
                "FUNCTION_REF_INDEX", "FUNCTION_MEMBER_TRAILING", "FUNCTION_MEMBER_RANGE", "FUNCTION_CARRIER", "FUNCTION_TRAILING",
                "FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT", "FUNCTION_UNUSED",
                # S8 (ADR-251): a member call in an ordinary function's graph (payload: the graph).
                "FUNCTION_GROUP_CONTEXT",
                # S8c.21 (ADR-239): recursion-group member lists (``_decode_recursion_group``, before any member parses).
                "GROUP_EMPTY", "GROUP_REF_INDEX", "GROUP_CARRIER", "GROUP_TRAILING", "GROUP_UNUSED",
                # S8c.22 (ADR-240): after member graphs parse (payload: graphs to parse first, quoted list, [count, graphs]).
                "GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT", "GROUP_MEMBER_RANGE", "GROUP_CALL_CONTRACT", "GROUP_SCC",
                # S8 (ADR-251): the canonical member order (payload: count, the canonical order, graphs).
                "GROUP_ORDER",
                # S8c.23 (ADR-241): targets (``decode_native_target``).
                "TARGET_REFERENCES", "TARGET_IDENTITY_TRUNCATED", "TARGET_IDENTITY_EMPTY", "TARGET_ARCHITECTURE", "TARGET_TRAILING",
                "TARGET_PROFILE", "TARGET_X86_64", "TARGET_RISCV64", "TARGET_SPIRV", "TARGET_JVM", "TARGET_WASM32", "TARGET_AARCH64",
                "TARGET_ANDROID", "TARGET_AARCH64_LINUX", "TARGET_BAREMETAL", "TARGET_BOARD", "TARGET_ACCELERATOR",
                # S8 (ADR-251): per-graph glue (raised inside the graph parse, wherever it is first reached).
                "GRAPH_TRAP_PAYLOAD", "GRAPH_UNUSED",
                # S8 (ADR-251): any body's malformed ULEB (status, body offset, size); a target section's ENUM diagnostic
                # (section, kind, value); target canonical rules (payload: the recorded words, their count, item, check, sub).
                "BODY_ULEB", "TARGET_SECTION", "TARGET_X86_REGISTERS", "TARGET_AAPCS64_REGISTERS", "TARGET_ACC_TOPOLOGY",
                "TARGET_ACC_SCOPES", "TARGET_ACC_SPACES", "TARGET_ACC_SPACE", "TARGET_ACC_OPERATIONS", "TARGET_ACC_CONTRACT",
                "TARGET_PLATFORM_OPERATIONS", "TARGET_PLATFORM_CONTRACT", "TARGET_OPERATIONS", "TARGET_TERMINATORS",
                "TARGET_ATOMIC_WIDTHS", "TARGET_ATOMIC_CAPABILITIES", "TARGET_HANDLER_ORDER", "TARGET_HANDLER",
                # S8: a reference naming no stored object (payload: the reference's index).
                "OBJECT_MISSING",
                # S8: cursor faults in any body (take: size, available; bool: the byte; trailing: rule, bytes left), build
                # references (count, index), build enums (enum, value), and build rules (rule, recorded words, their count,
                # item, extra).
                "BODY_TAKE", "BODY_BOOL", "BODY_TRAILING", "BUILD_REF_INDEX", "BUILD_ENUM", "BUILD_RULE",
                # S8: ``_build_form`` of another object (payload: the object): its BUILD-KIND diagnostic, or its own form
                # rejection.
                "BUILD_KIND_OF", "OTHER_OBJECT")
AFTER_PARSE = ("FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT", "FUNCTION_UNUSED", "FUNCTION_GROUP_CONTEXT")
GROUP_AFTER_PARSE = ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT", "GROUP_MEMBER_RANGE", "GROUP_CALL_CONTRACT", "GROUP_SCC", "GROUP_ORDER")
S = {name: index + 1 for index, name in enumerate(OBJECT_SITES)}


def _read(e: E, name: str, end, obj=None, start=None):
    """A canonical ULEB at ``p[name]``, inside ``end``; advances it (verdict 0 otherwise).  S8 (ADR-251): with ``obj``
    and its body ``start``, a malformed ULEB rejects ``obj`` as ``Cursor.uleb`` does (``BODY_ULEB``)."""
    p = e.p
    if obj is not None:
        return _strict(e, name, end, obj, start)
    value, size, ok = _uleb(e, p[name])
    _no(e, e.not_(ok))
    e.set(name, e.add(p[name], size))
    _no(e, e.lt(end, p[name]))
    e.var(f"{name}_value", value)
    return p[f"{name}_value"]


def _cid_word(e: E, obj, k):
    return e.rd(e.add(e.add(e.add(_rec(e, obj), 2), _references(e, obj)), k))


def _strict(e: E, name: str, end, obj, start, region=0, slot=None):
    """A strict ``Cursor.uleb`` at ``p[name]`` through ``_strict_read_fn``: the value (also stored at ``slot``); a
    malformed ULEB returns the caller's verdict."""
    p = e.p
    e.var(f"{name}_value", e.call(_FN["tread"], obj, p[name], end, start, region, GLOBALS + G_SINK if slot is None else slot))
    e.if_(e.ne(_g(e, G_EXIT), 1), lambda: e.give(_g(e, G_EXIT)))
    e.set(name, e.add(p[name], _g(e, G_ULEB_SIZE)))
    return p[f"{name}_value"]


# -- S6b.4d (ADR-149): per-graph glue -----------------------------------------------------


# -- S6b.4a (ADR-149): packages and the leaf build forms ---------------------------------------

def _string(e: E, name: str, end):
    """A ``[ULEB length, bytes]`` byte string at ``p[name]`` inside ``end``: ``(start, length)`` variables; advances."""
    p = e.p
    length = _read(e, name, end)
    e.var(f"{name}_slen", length)
    e.var(f"{name}_sat", p[name])
    _no(e, e.lt(e.sub(end, p[name]), p[f"{name}_slen"]))
    e.set(name, e.add(p[name], p[f"{name}_slen"]))
    return p[f"{name}_sat"], p[f"{name}_slen"]


def _capability(e: E, name: str, end, prefix: str):
    """A build capability ``[kind 1..9, scope bytes]`` read into ``prefix``_kind/_cs/_cl."""
    p = e.p
    e.var(f"{prefix}_kind", _read(e, name, end))
    _no(e, e.either(e.lt(p[f"{prefix}_kind"], 1), e.lt(9, p[f"{prefix}_kind"])))
    start, length = _string(e, name, end)
    e.var(f"{prefix}_cs", start)
    e.var(f"{prefix}_cl", length)


# S8 (ADR-251): build rules (``BUILD_RULE`` payload word 0), the bodies' trailing-byte rules, and the enums.
(BUILD_IDENTITY, BUILD_MODULES, BUILD_MODULE_KIND, BUILD_MODULES_CANONICAL, BUILD_EXACT_KIND, BUILD_DEPENDENCY_FORM,
 BUILD_DEPENDENCIES_CANONICAL, BUILD_NAMED_REFERENCE, BUILD_NAMES_CANONICAL, BUILD_CAPABILITIES_CANONICAL, BUILD_REFS_EXACT,
 BUILD_GRANTS_CANONICAL, BUILD_ALGORITHMS_CANONICAL, BUILD_SIGNERS_CANONICAL, BUILD_TRUST_NONEMPTY, BUILD_TRUST_REQUIRED,
 BUILD_SIGNATURE_NONEMPTY, BUILD_OPT_REFERENCES,
 BUILD_REQUEST_KINDS, BUILD_ENTRY_DECLARED, BUILD_BINDINGS_CANONICAL, BUILD_BINDINGS_COMPLETE, BUILD_TYPED_VALUE, BUILD_CONSTANT_TYPE,
 BUILD_BINDING_TYPE, BUILD_ARTIFACTS_CANONICAL, BUILD_ARTIFACT_REQUIRED, BUILD_SNAPSHOT_HEADER, BUILD_SNAPSHOT_PACKAGE_KIND,
 BUILD_SNAPSHOT_SIGNATURE_KIND, BUILD_SNAPSHOT_PACKAGES_CANONICAL, BUILD_SNAPSHOT_SIGNATURES_CANONICAL, BUILD_SNAPSHOT_EXTERNAL_CANONICAL,
 BUILD_SNAPSHOT_ROOT, BUILD_RESOLVE_EXACT, BUILD_RESOLVE_LOGICAL, BUILD_SNAPSHOT_CLOSURE, BUILD_GRANT_DECLARED, BUILD_SIGNATURE_PACKAGE,
 BUILD_SIGNATURE_COVERAGE, BUILD_PROVENANCE_KINDS, BUILD_PROVENANCE_CLOSURE) = range(1, 43)
BODY_RULES = ("BUILD-BODY", "BUILD-OPTIMIZATION-POLICY-BODY", "TARGET-NATIVE-BODY")
BUILD_ENUMS = ("BuildForm", "BuildMode", "BuildCapabilityKind", "ArtifactKind", "OptimizationObjective")


# -- S6b.4b (ADR-149): requests, snapshots, provenance --------------------------------------

def _form_of(e: E, obj):
    """The build form of a BUILD object (its first body byte; every form is below 128)."""
    return e.rd(_payload(e, obj))


def _verdict(e: E, obj):
    return e.ld(e.add(VERDICTS_AT, obj))


def _program(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.st(1, 0)
        e.st(STORE_FAULT, 0)
        e.st(STORE_FAULT + 2, 0)
        e.set_hd(H_ARENA, ARENA_AT + 16)
        e.set_hd(H_ARENA_END, HEADER - 1)
        O = e.rd(0)
        e.var("O", O)
        e.st(GLOBALS + G_O, p["O"])
        for slot, size in ((G_REC, p["O"]), (G_MARK, 1 << 16), (G_GROUP_SIZE, p["O"]), (G_GROUP_REACHED, p["O"])):
            table = e.alloc(e.add(size, 1))
            e.if_(e.eq(table, NONE), lambda: e.give(NONE))
            e.st(GLOBALS + slot, table)
        # S8 (ADR-251): a recursion group's member count once its member list decodes (NONE before or without that);
        # S15b.3d (ADR-297): the member whose graph the contract checks reached (the count once every member passed).
        e.for_("o", 0, p["O"], lambda: (e.st(e.add(_g(e, G_GROUP_SIZE), p["o"]), NONE), e.st(e.add(_g(e, G_GROUP_REACHED), p["o"]), NONE)))
        e.var("ra", 2)

        def record():
            e.st(e.add(_g(e, G_REC), p["o"]), p["ra"])
            references = e.rd(e.add(p["ra"], 1))
            e.if_(e.lt(1 << 16, references), lambda: e.give(NONE))
            payload_at = e.add(e.add(e.add(p["ra"], 2), references), 4)
            e.set("ra", e.add(e.add(payload_at, 1), e.rd(payload_at)))
            e.if_(e.eq(_kind(e, p["o"]), int(Kind.GRAPH_FRAGMENT)),
                  lambda: e.set("ra", e.add(e.add(p["ra"], 2), e.rd(p["ra"]))))  # [body length, body bytes, decoder rejected]

        e.for_("o", 0, p["O"], record)
        e.if_(e.lt(IN_WORDS, e.add(p["ra"], p["O"])), lambda: e.give(NONE))
        e.st(GLOBALS + G_TYPEOK, p["ra"])  # the proven-type flags follow the records

        # Per-object verdicts: recursion groups first (group member functions need theirs).
        def verdict(groups: bool):
            o = p["o"]
            kind = _kind(e, o)
            e.var("verdict", 0)
            if groups:
                e.if_(e.eq(kind, int(Kind.RECURSION_GROUP)), lambda: e.set("verdict", e.call(_FN["group"], o)))
            else:
                e.if_(e.eq(kind, int(Kind.FUNCTION)), lambda: e.set("verdict", e.call(_FN["function"], o)))
                e.if_(e.eq(kind, int(Kind.MODULE)), lambda: e.set("verdict", e.call(_FN["module"], o)))
                e.if_(e.eq(kind, int(Kind.PROGRAM_ROOT)), lambda: e.set("verdict", e.call(_FN["root"], o)))
                e.if_(e.eq(kind, int(Kind.CALL_CONTRACT)), lambda: e.set("verdict", e.call(_FN["contract"], o)))
                e.if_(e.eq(kind, int(Kind.TARGET)), lambda: e.set("verdict", e.call(_FN["target"], o)))
                e.if_(e.eq(kind, int(Kind.PACKAGE)), lambda: e.set("verdict", e.call(_FN["package"], o)))
                e.if_(e.eq(kind, int(Kind.BUILD)), lambda: e.set("verdict", e.call(_FN["build"], o)))
                e.if_(e.eq(kind, int(Kind.GRAPH_FRAGMENT)), lambda: e.set("verdict", e.call(_FN["glue"], o)))
            this_pass = e.eq(kind, int(Kind.RECURSION_GROUP)) if groups else e.ne(kind, int(Kind.RECURSION_GROUP))
            e.if_(this_pass, lambda: e.st(e.add(VERDICTS_AT, o), e.sel(e.eq(p["verdict"], 1), 1, e.sel(e.eq(p["verdict"], REJECTED), REJECTED, 0))))

        e.for_("o", 0, p["O"], lambda: verdict(True))
        e.for_("o", 0, p["O"], lambda: verdict(False))

        # Requests, then snapshots, then provenance: each reads the verdicts and records of the ones before.
        for form, name in ((2, "request"), (3, "snapshot"), (5, "provenance")):
            def later(form=form, name=name):
                o = p["o"]
                def decide():
                    e.var("later", e.call(_FN[name], o))
                    e.st(e.add(VERDICTS_AT, o), e.sel(e.eq(p["later"], 1), 1, e.sel(e.eq(p["later"], REJECTED), REJECTED, 0)))

                e.if_(e.both(e.eq(_kind(e, o), int(Kind.BUILD)), e.eq(_form_of(e, o), form)), decide)

            e.for_("o", 0, p["O"], later)
        # S8 (ADR-251): an object naming a missing object (``verify_object`` resolves its references, in order,
        # right after the CID check): rejected with that reference.
        # Every missing reference is listed too, ``[n, (object, reference index) ...]`` at word STORE_FAULT + 2: the
        # bootstrap resolves references from many decoders, and each such resolution fails on a listed one.
        e.var("missing_list", e.alloc(e.add(e.mul(p["O"], 2), 1)))
        e.var("missing_n", 0)

        def missing():
            o = p["o"]
            e.var("first_missing", NONE)

            def note():
                e.if_(e.eq(p["first_missing"], NONE), lambda: e.set("first_missing", p["mk"]))
                e.if_(e.both(e.ne(p["missing_list"], NONE), e.lt(p["missing_n"], p["O"])), lambda: (
                    e.st(e.add(p["missing_list"], e.add(e.mul(p["missing_n"], 2), 1)), o),
                    e.st(e.add(p["missing_list"], e.add(e.mul(p["missing_n"], 2), 2)), p["mk"]),
                    e.set("missing_n", e.add(p["missing_n"], 1))))

            e.for_("mk", 0, _references(e, o), lambda: e.if_(e.eq(_reference(e, o, p["mk"]), NONE), note))

            def reject():
                at = e.add(REJECTS_AT, e.mul(o, REJECT_WORDS))
                e.st(at, S["OBJECT_MISSING"])
                e.st(e.add(at, 1), p["first_missing"])
                e.st(e.add(VERDICTS_AT, o), REJECTED)

            e.if_(e.ne(p["first_missing"], NONE), reject)

        e.for_("o", 0, p["O"], missing)
        e.if_(e.ne(p["missing_list"], NONE), lambda: (e.st(p["missing_list"], p["missing_n"]), e.st(STORE_FAULT + 2, p["missing_list"])))
        # The store: everything reachable from the root, no cycle (iterative depth-first search).
        root = e.rd(1)
        e.var("root", root)
        colour = e.alloc(e.add(p["O"], 1))
        stack = e.alloc(e.add(e.mul(p["O"], 2), 2))
        e.var("colour", colour)
        e.var("stack", stack)
        e.if_(e.either(e.eq(p["colour"], NONE), e.eq(p["stack"], NONE), e.le(p["O"], p["root"])), lambda: e.give(1))
        e.for_("o", 0, p["O"], lambda: e.st(e.add(p["colour"], p["o"]), 0))
        e.var("depth", 1)
        e.st(p["stack"], p["root"])
        e.st(e.add(p["stack"], 1), 0)
        e.st(e.add(p["colour"], p["root"]), 1)
        e.var("store_ok", 1)

        def step():
            top = e.add(p["stack"], e.mul(e.sub(p["depth"], 1), 2))
            node, child = e.ld(top), e.ld(e.add(top, 1))
            e.var("sn", node)

            def descend():
                target = _reference(e, p["sn"], child)
                e.st(e.add(top, 1), e.add(child, 1))
                e.var("st", target)

                def visit():
                    state = e.ld(e.add(p["colour"], p["st"]))
                    # S8 (ADR-251): a cycle, re-entering this object (the bootstrap's ``visit`` order).
                    e.if_(e.eq(state, 1), lambda: (e.set("store_ok", 0), e.st(STORE_FAULT, 1), e.st(STORE_FAULT + 1, p["st"])))

                    def push():
                        e.st(e.add(p["colour"], p["st"]), 1)
                        slot = e.add(p["stack"], e.mul(p["depth"], 2))
                        e.st(slot, p["st"])
                        e.st(e.add(slot, 1), 0)
                        e.set("depth", e.add(p["depth"], 1))

                    e.if_(e.eq(state, 0), push)

                e.if_(e.either(e.eq(p["st"], NONE), e.le(p["O"], p["st"])), lambda: e.set("store_ok", 0), visit)

            def finish():
                e.st(e.add(p["colour"], p["sn"]), 2)
                e.set("depth", e.sub(p["depth"], 1))

            e.if_(e.lt(child, _references(e, p["sn"])), descend, finish)

        e.while_(lambda: e.both(e.ne(p["depth"], 0), e.ne(p["store_ok"], 0)), step)
        e.var("searched", p["store_ok"])
        e.for_("o", 0, p["O"], lambda: e.if_(e.ne(e.ld(e.add(p["colour"], p["o"])), 2), lambda: e.set("store_ok", 0)))
        # S8: unreachable objects (the reachable ones are coloured 2).
        e.if_(e.both(e.ne(p["searched"], 0), e.eq(p["store_ok"], 0)), lambda: (e.st(STORE_FAULT, 2), e.st(STORE_FAULT + 1, p["colour"])))
        e.st(1, p["store_ok"])
        # S15b.1 (ADR-288): every rejection rendered as the bootstrap's diagnostic (``xax_selfhost_render``).
        import xax_selfhost_render as R

        R.render_phase(e, _FN["rendering"], VERDICTS_AT, REJECTED)
        e.st(0, OK)
        e.give(1)
    return _function((), build, tables)


def load_verifier_program():
    from xax_compiler import StoreReader

    from xax_native import verify_component_store

    reader = StoreReader(STORE_PATH.read_bytes())
    verify_component_store(reader, "store-verifier")
    module = next(item for item in reader.objects() if item.kind == Kind.MODULE)
    function = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == Kind.FUNCTION)
    return reader, function


def _native_image() -> tuple[bytes, int]:
    """``(machine code, entry offset)``, lowered for this host by the XAX x86-64 backend and cached (ADR-152)."""
    from xax_selfhost_x86_64_backend import host_image

    return host_image(*load_verifier_program(), "store-verifier")


class NativeStoreVerifier:
    def __init__(self) -> None:
        from xax_x86_64 import _SYSV_TO_WIN64_THUNK

        code, entry_offset = _native_image()
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

    def verify(self, words: list[int], count: int, groups=()):
        """``(store verdict, per-object verdicts, per-object graph words, {group: member graphs})``, or None when it
        cannot run.  A proven function's graph word is its graph object (NONE for a group member function); a proven
        group's (``groups`` lists their positions) points at ``[count, member graphs]``."""
        return self.verify_with_rejections(words, count, groups)[0]

    def verify_with_rejections(self, words: list[int], count: int, groups=()):
        """``verify``'s result and the rejected objects' records (``collect_rejections``)."""
        if len(words) > IN_WORDS or any(not 0 <= word < 1 << 64 for word in words):
            return None, {}
        with self._lock:
            self._in[: len(words)] = words
            self._slots[0], self._slots[1] = ctypes.addressof(self._in), ctypes.addressof(self._out)
            self._call(self._entry, ctypes.addressof(self._slots), 4, ctypes.addressof(self._xmm))
            out = self._out
            read = lambda start, length: list(out[start : start + length])  # noqa: E731
            result = collect_verdicts(read, count, groups)
            if result is None:
                return None, {}
            rejections = collect_rejections(read, result[1])
            store = store_rejection(read, count)
            if store is not None:
                rejections["store"] = store
            at = read(STORE_FAULT + 2, 1)[0]
            if at:  # S8: every missing reference, as (object, reference index)
                pairs = read(at + 1, 2 * read(at, 1)[0])
                rejections["missing"] = tuple(zip(pairs[::2], pairs[1::2]))
            return result, rejections


def store_rejection(read, count: int):
    """S8 (ADR-251): the store rejection the program decided: ``("cycle", object)``, ``("unreachable", reachable
    objects)``, or None."""
    fault, at = read(STORE_FAULT, 2)
    if fault == 1:
        return "cycle", at
    if fault == 2:
        return "unreachable", tuple(o for o, colour in enumerate(read(at, count)) if colour == 2)
    return None


def collect_verdicts(read, count: int, groups=()):
    """The program's result from its output view, read as ``read(start word, count)`` wherever it ran (natively
    or as a RISC-V image, S6c): ``(store verdict, verdicts, graph words, {group: member graphs})``, or None."""
    status, store = read(0, 2)
    if status != OK:
        return None
    verdicts, graphs = read(VERDICTS_AT, count), read(GRAPHS_AT, count)
    members = {o: tuple(read(graphs[o] + 1, read(graphs[o], 1)[0])) for o in groups if verdicts[o] == 1}
    return store == 1, verdicts, graphs, members


TRAP_ERRORS = ("non-canonical trap reason ULEB", "portable trap reason exceeds 16 bits",
               "zero trap reason uses the empty canonical payload", "unterminated or oversized portable trap reason")  # decode_trap_payload
LIST_SITES = ("LIST_REF_INDEX", "LIST_REFERENCE_BODY", "CONTRACT_UNUSED", "FUNCTION_UNUSED", "GROUP_UNUSED", "GRAPH_UNUSED")  # a payload word is a [count, words] list
TARGET_SCALAR_SITES = ("TARGET_REFERENCES", "TARGET_IDENTITY_TRUNCATED", "TARGET_IDENTITY_EMPTY", "TARGET_ARCHITECTURE", "TARGET_TRAILING",
                       "TARGET_PROFILE")  # the other target sites quote the machine record at payload word 0
TARGET_SCALAR_SITES += ("TARGET_SECTION",)
TARGET_WORD_SITES = ("TARGET_X86_REGISTERS", "TARGET_AAPCS64_REGISTERS", "TARGET_ACC_TOPOLOGY", "TARGET_ACC_SCOPES", "TARGET_ACC_SPACES",
                     "TARGET_ACC_SPACE", "TARGET_ACC_OPERATIONS", "TARGET_ACC_CONTRACT", "TARGET_PLATFORM_OPERATIONS", "TARGET_PLATFORM_CONTRACT",
                     "TARGET_OPERATIONS", "TARGET_TERMINATORS", "TARGET_ATOMIC_WIDTHS", "TARGET_ATOMIC_CAPABILITIES", "TARGET_HANDLER_ORDER",
                     "TARGET_HANDLER")  # payload: the target's recorded words (quoted), their count, item, check, sub
ULEB_FAULTS = (("XAX.CANON.ULEB_UNTERMINATED", "SER-ULEB-TERMINATED"), ("XAX.CANON.ULEB_NON_MINIMAL", "SER-ULEB-MINIMAL"),
               ("XAX.CANON.ULEB_OVERFLOW", "SER-ULEB-BOUNDED"))
PAIR_SITES = ("FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT")  # payload word 1 is [n, words, m, words]


def collect_rejections(read, verdicts):
    """``{object: (site, payload words, quoted list or None)}`` for every REJECTED verdict."""
    rejections = {}
    for o, verdict in enumerate(verdicts):
        if verdict != REJECTED:
            continue
        site, *payload = read(REJECTS_AT + REJECT_WORDS * o, REJECT_WORDS)
        listed = None
        name = OBJECT_SITES[site - 1] if 0 < site <= len(OBJECT_SITES) else None
        if name in LIST_SITES:
            at = payload[0] if name in ("CONTRACT_UNUSED", "GROUP_UNUSED", "GRAPH_UNUSED") else payload[1]
            listed = read(at + 1, read(at, 1)[0])
        elif name in GROUP_AFTER_PARSE:
            graphs = read(payload[2] + 1, payload[0])
            if name in ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT"):
                first = read(payload[1], 1)[0]
                second = read(payload[1] + 1 + first, 1)[0]
                listed = read(payload[1], first + second + 2)
            elif name == "GROUP_MEMBER_RANGE":
                listed = [read(payload[2], 1)[0]]
            elif name == "GROUP_ORDER":
                listed = read(payload[1] + 1, read(payload[1], 1)[0])
            elif name == "GROUP_CALL_CONTRACT":
                words, at = [], payload[1]
                for _part in range(4):
                    n = read(at, 1)[0]
                    words.append(read(at + 1, n))
                    at += n + 1
                listed = words
            elif name == "GROUP_SCC":
                words, at = [], payload[1] + 1
                for _member in range(read(payload[1], 1)[0]):
                    n = read(at, 1)[0]
                    words.append(read(at + 1, n))
                    at += n + 1
                listed = words
            rejections[o] = (site, payload, listed, graphs)
            continue
        elif name in TARGET_WORD_SITES:
            listed = read(payload[0], payload[1])
        elif name == "BUILD_RULE":
            listed = read(payload[1], payload[2])
            if payload[0] in (BUILD_REFS_EXACT, BUILD_RESOLVE_LOGICAL, BUILD_SNAPSHOT_CLOSURE):
                listed = (listed, read(payload[3] + 1, read(payload[3], 1)[0]))
        elif name is not None and name.startswith("TARGET_") and name not in TARGET_SCALAR_SITES:
            listed = read(payload[0], 7)
        elif name in PAIR_SITES:
            first = read(payload[1], 1)[0]
            second = read(payload[1] + 1 + first, 1)[0]
            listed = read(payload[1], first + second + 2)
        rejections[o] = (site, payload, listed)
    return rejections


def _target_diagnostic(obj, name, x, y, machine):
    """S8c.23: ``decode_native_target``'s diagnostics (``machine``: profile, abi, format, word, pointer, stack, shadow)."""
    import xax_compiler as X

    if name == "TARGET_REFERENCES":
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", [], [cid.hex() for cid in obj.references]
    if name == "TARGET_IDENTITY_TRUNCATED":
        return "XAX.CANON.TRUNCATED", "SER-BOUNDS", f"{x} available bytes", y
    if name == "TARGET_IDENTITY_EMPTY":
        return "XAX.STRUCT.TARGET_IDENTITY", "TARGET-IDENTITY-NONEMPTY", ">= 1 byte", 0
    if name == "TARGET_ARCHITECTURE":
        return ("XAX.TARGET.ARCHITECTURE", "TARGET-ARCHITECTURE-SUPPORTED",
                [1, 2, 3, 4, X.JVM_ARCHITECTURE, X.RISCV64_ARCHITECTURE, X.SPIRV_ARCHITECTURE], x)
    if name == "TARGET_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "TARGET-NATIVE-BODY", 0, x
    if name == "TARGET_PROFILE":
        return "XAX.TARGET.PROFILE", "TARGET-PROFILE-SUPPORTED", [1, 2, 3, 4, X.BOARD_PROFILE], x
    profile, abi, image_format, word, pointer, stack, shadow = machine
    if name == "TARGET_X86_64":
        allowed = ((1, 1, 64, 64, 16, 32), (X.X86_64_LINUX_ABI, X.X86_64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 32),
                   (X.X86_64_LINUX_ABI, X.X86_64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 32))
        return "XAX.TARGET.MACHINE", "TARGET-X86-64-PROFILE", [list(item) for item in allowed], [abi, image_format, word, pointer, stack, shadow]
    if name == "TARGET_AARCH64":
        allowed = ((3, 1, 64, 64, 16, 0), (4, X.ANDROID_ELF_FORMAT, 64, 64, 16, 0), (4, X.ANDROID_ELF_PACKED_FORMAT, 64, 64, 16, 0),
                   (X.AARCH64_LINUX_ABI, X.AARCH64_LINUX_ELF_EXEC_FORMAT, 64, 64, 16, 0), (X.AARCH64_LINUX_ABI, X.AARCH64_LINUX_ELF_DYNAMIC_FORMAT, 64, 64, 16, 0),
                   (3, X.AARCH64_BOARD_ELF_FORMAT, 64, 64, 16, 0))
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-PROFILE", [list(item) for item in allowed], [abi, image_format, word, pointer, stack, shadow]
    if name == "TARGET_ANDROID":
        return "XAX.TARGET.MACHINE", "TARGET-ANDROID-PROFILE", 4, profile
    if name == "TARGET_AARCH64_LINUX":
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-LINUX-PROFILE", 1, profile
    if name == "TARGET_BAREMETAL":
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-BAREMETAL-PROFILE", [1, 2, X.BOARD_PROFILE], profile
    if name == "TARGET_BOARD":
        return "XAX.TARGET.MACHINE", "TARGET-AARCH64-BOARD-PROFILE", "board format with board profile", [image_format, profile]
    if name == "TARGET_WASM32":
        return "XAX.TARGET.MACHINE", "TARGET-WASM32-CORE", [2, 2, 64, 32], [abi, image_format, word, pointer]
    rule, expected = {
        "TARGET_RISCV64": ("TARGET-RISCV64-RAW", [1, X.RISCV64_LP64_ABI, X.RISCV64_RAW_FORMAT, 64, 64]),
        "TARGET_SPIRV": ("TARGET-SPIRV-COMPUTE", [1, X.SPIRV_VULKAN_ABI, X.SPIRV_MODULE_FORMAT, 32, 32]),
        "TARGET_JVM": ("TARGET-JVM-CLASSFILE", [1, X.JVM_ABI, X.JVM_JAR_FORMAT, 64, 64]),
        "TARGET_ACCELERATOR": ("TARGET-ACCELERATOR-PROFILE", [3, 4, 3, 32, 64]),
    }[name]
    return "XAX.TARGET.MACHINE", rule, expected, [profile, abi, image_format, word, pointer]


def _uleb_diagnostic(obj, status, at, size):
    """``Cursor.uleb``'s diagnostic for the ULEB the verifier found malformed (status 1 unterminated, 2 non-minimal,
    3 more than ten bytes) at body offset ``at``."""
    from xax_compiler import uleb

    code, rule = ULEB_FAULTS[status - 1]
    if status == 1:
        return code, rule, "terminating byte", "end of input"
    if status == 3:
        return code, rule, "at most 10 bytes", "more than 10 bytes"
    encoded = bytes(obj.body[at:at + size])
    value = sum((byte & 0x7F) << (7 * k) for k, byte in enumerate(encoded))
    return code, rule, uleb(value).hex(), encoded.hex()


SECTIONS = (("XAX.TARGET.CONCURRENCY", "TARGET-CONCURRENCY-ENUM", "known atomic/handler values"),
            ("XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-ENUM", "known scope/value-constraint values"),
            ("XAX.TARGET.PLATFORM", "TARGET-PLATFORM-ENUM", "known scope/value-constraint values"))


def _target_section_diagnostic(section, kind, value):
    """A fault inside a target section: the bootstrap's ``except ValueError`` reports ``str(error)``: a cursor
    diagnostic's code (kinds 1-3 ULEB, 5 truncated), the section's own BOOL code (6), or an enum's message (7-10)."""
    from xax_compiler import AtomicFamily, AtomicScope, EffectDomain, TargetValueConstraintKind

    code, rule, expected = SECTIONS[section - 1]
    if kind <= 3:
        actual = ULEB_FAULTS[kind - 1][0]
    elif kind == 5:
        actual = "XAX.CANON.TRUNCATED"
    elif kind == 6:
        actual = code
    else:
        enum = (AtomicScope, AtomicFamily, EffectDomain, TargetValueConstraintKind)[kind - 7]
        actual = f"{value} is not a valid {enum.__qualname__}"
    return code, rule, expected, actual


def target_fields(words):
    """The target's fields from the verifier's recorded words (in read order, identity length first): a structuring
    of values the verifier read, for quoting."""
    from xax_compiler import (
        AcceleratorMemorySpace, AtomicFamily, AtomicScope, BOARD_PROFILE, EffectDomain, HandlerEntryContract, TargetValueConstraint,
        TargetValueConstraintKind,
    )

    stream = iter(words[1:])
    take = stream.__next__

    def many(make=lambda value: value):
        return tuple(make(take()) for _ in range(take()))

    f = {"profile": take(), "arch": take(), "abi": take(), "format": take(), "word": take(), "pointer": take()}
    f.update(args=(), result=None, scratch=(), widths=(), scopes=(), families=(), handlers=(), lane=0, groups=0, acc_scopes=(), spaces=(),
             contracts=())
    if f["arch"] in (1, 3):
        f.update(stack=take(), shadow=take(), args=many())
        f.update(result=take(), scratch=many())
    f.update(operations=many(), terminators=many())

    def contracts():
        items = []
        for _ in range(take()):
            operation_id, semantic, encoding = take(), take(), take()
            operands, results = (tuple(TargetValueConstraint(TargetValueConstraintKind(take()), take(), take()) for _ in range(take())) for _signature in range(2))
            scopes_ = many(AtomicScope)
            source, destination, synchronizes, may_block, dependency = take(), take(), take(), take(), take()
            items.append({"id": operation_id, "semantic": semantic, "encoding": encoding, "constraints": (*operands, *results), "scopes": scopes_,
                          "source": source, "destination": destination, "dependency": dependency})
        return tuple(items)

    if f["profile"] in (2, BOARD_PROFILE):
        f.update(widths=many(), scopes=many(AtomicScope), families=many(AtomicFamily))
        handlers = []
        for _ in range(take()):
            fields = tuple(take() for _ in range(7))
            domains = many(EffectDomain)
            handlers.append(HandlerEntryContract(*fields, domains, take(), take()))
        f["handlers"] = tuple(handlers)
    if f["profile"] == 3:
        f.update(lane=take(), groups=take(), acc_scopes=many(AtomicScope))
        spaces = []
        for _ in range(take()):
            identity, address_bits, unit_bits, alignment = take(), take(), take(), take()
            widths, visibility = many(), many(AtomicScope)
            spaces.append(AcceleratorMemorySpace(identity, address_bits, unit_bits, alignment, widths, visibility, bool(take()), bool(take())))
        f.update(spaces=tuple(spaces), contracts=contracts())
    if f["profile"] in (4, BOARD_PROFILE):
        f["contracts"] = contracts()
    return f


def _target_rule_diagnostic(name, words, item, check, sub):
    """The bootstrap's diagnostic for a canonical target rule the verifier found broken (``item``: the failing space,
    contract, or handler; ``check``/``sub``: which contract check, and which constraint)."""
    f = target_fields(words)
    if name == "TARGET_X86_REGISTERS":
        return "XAX.TARGET.ABI", "TARGET-WINDOWS-X64-REGISTERS", [[1, 2, 8, 9], 0, [10, 11]], [list(f["args"]), f["result"], list(f["scratch"])]
    if name == "TARGET_AAPCS64_REGISTERS":
        return "XAX.TARGET.ABI", "TARGET-AAPCS64-REGISTERS", [list(range(8)), 0, [9, 10]], [list(f["args"]), f["result"], list(f["scratch"])]
    if name == "TARGET_ACC_TOPOLOGY":
        return "XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-TOPOLOGY", "positive lane width and max groups", [f["lane"], f["groups"]]
    if name == "TARGET_ACC_SCOPES":
        return "XAX.TARGET.ACCELERATOR", "TARGET-ACCELERATOR-SCOPES-CANONICAL", "sorted unique nonempty scopes", f["acc_scopes"]
    space_ids = tuple(space.identity for space in f["spaces"])
    if name == "TARGET_ACC_SPACES":
        return "XAX.TARGET.MEMORY_SPACE", "TARGET-MEMORY-SPACES-CANONICAL", "sorted unique nonempty memory spaces", space_ids
    if name == "TARGET_ACC_SPACE":
        return ("XAX.TARGET.MEMORY_SPACE", "TARGET-MEMORY-SPACE-CONTRACT", "positive widths, power-of-two alignment, canonical widths/scopes",
                f["spaces"][item])
    operation_ids = tuple(contract["id"] for contract in f["contracts"])
    if name in ("TARGET_ACC_OPERATIONS", "TARGET_PLATFORM_OPERATIONS"):
        if name == "TARGET_ACC_OPERATIONS":
            return "XAX.TARGET.OPERATION", "TARGET-OPERATIONS-CONTRACT-CANONICAL", "sorted unique nonempty target operation IDs", operation_ids
        return "XAX.TARGET.PLATFORM", "TARGET-PLATFORM-OPERATIONS-CANONICAL", "sorted unique nonempty target operation IDs", operation_ids
    if name in ("TARGET_ACC_CONTRACT", "TARGET_PLATFORM_CONTRACT"):
        contract = f["contracts"][item]
        accelerator = name == "TARGET_ACC_CONTRACT"
        code = "XAX.TARGET.OPERATION" if accelerator else "XAX.TARGET.PLATFORM"
        prefix = "TARGET-OPERATION" if accelerator else "TARGET-PLATFORM"
        check = check if accelerator else (1, 4, 5)[check - 1]  # platform checks: contract, constraint, dependency
        if check == 1:
            if accelerator:
                return code, "TARGET-OPERATION-ENCODING", "positive semantic code and byte opcode", [contract["semantic"], contract["encoding"]]
            return code, "TARGET-PLATFORM-OPERATION-CONTRACT", "positive semantic code and canonical scopes", contract["id"]
        if check == 2:
            return code, "TARGET-OPERATION-SCOPES", f["acc_scopes"], contract["scopes"]
        if check == 3:
            return code, "TARGET-OPERATION-MEMORY-SPACES", sorted(set(space_ids)), [contract["source"], contract["destination"]]
        if check == 4:
            constraint = contract["constraints"][sub]
            return (code, f"{prefix}-VALUE-CONSTRAINT", "canonical bits/resource/effect constraint",
                    [constraint.kind.value, constraint.primary, constraint.secondary])
        return code, f"{prefix}-RUNTIME-DEPENDENCY", "empty or 32-byte identity", contract["dependency"]
    if name == "TARGET_OPERATIONS":
        return "XAX.TARGET.OPERATIONS", "TARGET-OPERATIONS-CANONICAL", "sorted supported operation IDs", f["operations"]
    if name == "TARGET_TERMINATORS":
        return "XAX.TARGET.TERMINATORS", "TARGET-TERMINATORS-CANONICAL", "sorted supported terminator IDs", f["terminators"]
    if name == "TARGET_ATOMIC_WIDTHS":
        return "XAX.TARGET.ATOMICS", "TARGET-ATOMIC-WIDTHS-CANONICAL", "sorted positive widths", f["widths"]
    if name == "TARGET_ATOMIC_CAPABILITIES":
        return "XAX.TARGET.ATOMICS", "TARGET-ATOMIC-CAPABILITIES-CANONICAL", "sorted unique scopes/families", [f["scopes"], f["families"]]
    if name == "TARGET_HANDLER_ORDER":
        return "XAX.TARGET.HANDLER", "TARGET-HANDLER-ENTRIES-CANONICAL", "sorted unique event kinds", [entry.event_kind for entry in f["handlers"]]
    entry = f["handlers"][item]
    return ("XAX.TARGET.HANDLER", "TARGET-HANDLER-CONTRACT", "sorted unique effect domains and positive stack bound",
            [entry.allowed_effect_domains, entry.stack_bound])


def object_entity(obj, record, objects):
    """S8: the CID a rejection's diagnostic names when it is not ``obj`` (a missing reference, another object's
    ``_build_form``, a build rule about another object), else None.  ``OTHER_OBJECT`` takes that object's diagnostic."""
    site, payload = record[0], record[1]
    name = OBJECT_SITES[site - 1]
    if name == "OBJECT_MISSING":
        return obj.references[payload[0]]
    if name in ("BUILD_KIND_OF", "OTHER_OBJECT"):
        return objects[payload[0]].cid
    if name == "BUILD_RULE" and payload[5] != NONE:
        return objects[payload[5]].cid
    return None


def _build_rule_diagnostic(obj, rule, words, item, extra, objects, more=0):
    """The bootstrap's diagnostic for a build rule the verifier found broken, quoting the values it read (``words``:
    read order; strings as length and body offset, references as indices)."""
    from xax_build import BuildCapability, BuildCapabilityKind
    from xax_compiler import uleb

    if rule == BUILD_REFS_EXACT:
        _words, marks = words
        return ("XAX.CANON.UNUSED_REFERENCE", "BUILD-REFS-EXACT", tuple(range(len(obj.references))),
                tuple(k for k, marked in enumerate(marks) if marked))
    if rule >= BUILD_REQUEST_KINDS:
        return _composite_rule_diagnostic(obj, rule, words, item, extra, objects, more)
    stream = iter(words)
    take = stream.__next__
    kind_of = {item.cid: item.kind for item in objects}

    def string():
        length, at = take(), take()
        return bytes(obj.body[at:at + length])

    def strings():
        return tuple(string() for _ in range(take()))

    if obj.kind == Kind.BUILD:
        take()  # the form
    if rule == BUILD_IDENTITY:
        return "XAX.PACKAGE.IDENTITY", "PACKAGE-LOGICAL-IDENTITY", "nonempty bytes", "empty"
    if rule == BUILD_MODULES:
        return "XAX.PACKAGE.MODULE", "PACKAGE-MODULES", ">= 1", 0
    if rule == BUILD_MODULE_KIND:
        return "XAX.PACKAGE.MODULE", "PACKAGE-MODULE-KIND", Kind.MODULE.name, Kind(extra).name
    if rule == BUILD_EXACT_KIND:
        return "XAX.PACKAGE.DEPENDENCY", "PACKAGE-EXACT-KIND", Kind.PACKAGE.name, Kind(extra).name
    if rule == BUILD_DEPENDENCY_FORM:
        return "XAX.PACKAGE.DEPENDENCY", "PACKAGE-DEPENDENCY-FORM", [1, 2], extra
    canonical = lambda name, keys: ("XAX.BUILD.CANONICAL", name, "sorted unique values", tuple(keys))  # noqa: E731
    if obj.kind == Kind.PACKAGE:
        string()  # the logical identity
        modules = tuple(obj.references[take()] for _ in range(take()))
        if rule == BUILD_MODULES_CANONICAL:
            return canonical("PACKAGE-MODULES-CANONICAL", modules)
        keys = []
        for _ in range(take()):
            form = take()
            keys.append(b"\x01" + obj.references[take()] if form == 1 else b"\x02" + (lambda value: uleb(len(value)) + value)(string()))
        if rule == BUILD_DEPENDENCIES_CANONICAL:
            return canonical("PACKAGE-DEPENDENCIES-CANONICAL", keys)
        for number, expected_kind in enumerate((Kind.FUNCTION, Kind.TYPE, Kind.TYPE)):
            names = []
            for position in range(take()):
                name, child = string(), obj.references[take()]
                if rule == BUILD_NAMED_REFERENCE and (number, position) == (item, extra):
                    return ("XAX.PACKAGE.SCHEMA", "PACKAGE-NAMED-REFERENCE", ["nonempty", expected_kind.name], [name.hex(), kind_of[child].name])
                names.append(name)
            if rule == BUILD_NAMES_CANONICAL and number == item:
                return canonical("PACKAGE-NAMES-CANONICAL", names)
        capabilities = []
        for _ in range(take()):
            kind = take()
            capabilities.append(BuildCapability(BuildCapabilityKind(kind), string()))
        return canonical("PACKAGE-CAPABILITIES-CANONICAL", capabilities)
    if rule == BUILD_GRANTS_CANONICAL:
        take(), take(), take()  # mode, optimization, verification
        keys = []
        for _ in range(take()):
            identity, kind = string(), BuildCapabilityKind(take())
            keys.append((identity, kind, string()))
        return canonical("BUILD-GRANTS-CANONICAL", keys)
    if rule in (BUILD_ALGORITHMS_CANONICAL, BUILD_SIGNERS_CANONICAL, BUILD_TRUST_NONEMPTY, BUILD_TRUST_REQUIRED):
        take(), take()  # the two flags
        algorithms, signers = strings(), strings()
        if rule == BUILD_ALGORITHMS_CANONICAL:
            return canonical("TRUST-ALGORITHMS-CANONICAL", algorithms)
        if rule == BUILD_SIGNERS_CANONICAL:
            return canonical("TRUST-SIGNERS-CANONICAL", signers)
        if rule == BUILD_TRUST_NONEMPTY:
            return "XAX.TRUST.EMPTY", "TRUST-IDENTITY-NONEMPTY", "nonempty identities", "empty"
        return "XAX.TRUST.EMPTY", "TRUST-REQUIRED-SETS", "accepted algorithms and signers", [algorithms, signers]
    if rule == BUILD_SIGNATURE_NONEMPTY:
        take()  # the signed object
        return "XAX.TRUST.SIGNATURE", "TRUST-SIGNATURE-NONEMPTY", "nonempty fields", [string().hex() for _ in range(3)]
    if rule == BUILD_OPT_REFERENCES:
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", [], [cid.hex() for cid in obj.references]
    raise ValueError(f"unknown build rule {rule}")


def _composite_rule_diagnostic(obj, rule, words, item, extra, objects, more):
    """S8: requests, snapshots, and provenance (``_build_rule_diagnostic``).  Values the verifier read are quoted from
    its words; lists it read from proven packages, profiles, and signatures are quoted from their decoded views."""
    import xax_build as B

    listed, quoted = words if isinstance(words, tuple) else (words, None)
    by_cid = {item_.cid: item_ for item_ in objects}
    resolve = by_cid.__getitem__
    h = lambda index: objects[index].cid.hex()  # noqa: E731
    stream = iter(listed)
    take = stream.__next__

    def string():
        length, at = take(), take()
        return bytes(obj.body[at:at + length])

    canonical = lambda name, keys: ("XAX.BUILD.CANONICAL", name, "sorted unique values", tuple(keys))  # noqa: E731
    if rule == BUILD_REQUEST_KINDS:
        return ("XAX.BUILD.REQUEST", "BUILD-REQUEST-REFERENCE-KINDS", [Kind.PACKAGE.name, Kind.TARGET.name, B.BuildForm.PROFILE.name],
                [Kind(item).name, Kind(extra).name, B.BuildForm(more).name])
    if rule == BUILD_TYPED_VALUE:
        return "XAX.BUILD.VALUE", "BUILD-TYPED-VALUE", Kind.CONSTANT.name, Kind(item).name
    if rule == BUILD_CONSTANT_TYPE:
        return "XAX.STRUCT.REF_INDEX", "BUILD-CONSTANT-TYPE", f"< {item}", extra
    if rule == BUILD_BINDING_TYPE:
        return "XAX.BUILD.VALUE_TYPE", "BUILD-BINDING-TYPE", h(item), h(extra)
    if rule == BUILD_ARTIFACT_REQUIRED:
        return "XAX.BUILD.ARTIFACT", "BUILD-ARTIFACT-REQUIRED", ">= 1", 0
    if rule in (BUILD_ENTRY_DECLARED, BUILD_BINDINGS_CANONICAL, BUILD_BINDINGS_COMPLETE, BUILD_ARTIFACTS_CANONICAL):
        take()  # the form
        package_object = resolve(obj.references[take()])
        entry = string()
        take(), take()  # target, profile
        view = B.decode_package(package_object, resolve)
        if rule == BUILD_ENTRY_DECLARED:
            return "XAX.BUILD.ENTRY", "BUILD-ENTRY-DECLARED", [name.hex() for name, _ in view.build_entries], entry.hex()
        for number, schema in enumerate((view.feature_types, view.configuration_types)):
            names = []
            for _ in range(take()):
                names.append(string())
                take()  # the value
            if rule == BUILD_BINDINGS_CANONICAL and number == item:
                return canonical("BUILD-BINDINGS-CANONICAL", names)
            if rule == BUILD_BINDINGS_COMPLETE and number == item:
                return ("XAX.BUILD.INPUT_CLOSURE", "BUILD-BINDINGS-COMPLETE", sorted(name.hex() for name in dict(schema)),
                        sorted(name.hex() for name in names))
        return canonical("BUILD-ARTIFACTS-CANONICAL", (B.ArtifactKind(take()) for _ in range(take())))
    if rule in (BUILD_PROVENANCE_KINDS, BUILD_PROVENANCE_CLOSURE):
        take()  # the form
        snapshot, request, target, profile = (resolve(obj.references[take()]) for _ in range(4))
        if rule == BUILD_PROVENANCE_KINDS:
            return ("XAX.PROVENANCE.REFERENCE", "PROVENANCE-REFERENCE-KINDS", "snapshot/request/target/profile",
                    [snapshot.kind.name, request.kind.name, target.kind.name, profile.kind.name])
        return ("XAX.PROVENANCE.CLOSURE", "PROVENANCE-EXACT-CLOSURE", [h(item), h(extra), h(more)],
                [request.cid.hex(), target.cid.hex(), profile.cid.hex()])
    # Snapshots.
    take()  # the form
    request = resolve(obj.references[take()])
    identity = string()
    policy = resolve(obj.references[take()])
    if rule == BUILD_SNAPSHOT_HEADER:
        return "XAX.SNAPSHOT.HEADER", "SNAPSHOT-HEADER", "request, resolver identity, trust policy", [request.kind.name, identity.hex(), policy.kind.name]
    if rule == BUILD_RESOLVE_EXACT:
        return "XAX.RESOLVE.MISSING", "RESOLVE-EXACT-ROOT", h(item), "missing"
    if rule == BUILD_RESOLVE_LOGICAL:
        matches = sorted(objects[index].cid for index in quoted)
        return ("XAX.RESOLVE.AMBIGUOUS" if matches else "XAX.RESOLVE.MISSING", "RESOLVE-LOGICAL-IDENTITY", "exactly one candidate",
                [cid.hex() for cid in matches])
    packages = tuple(resolve(obj.references[take()]) for _ in range(take()))
    signatures = tuple(resolve(obj.references[take()]) for _ in range(take()))
    if rule == BUILD_SNAPSHOT_PACKAGE_KIND:
        return "XAX.SNAPSHOT.PACKAGE", "SNAPSHOT-PACKAGE-KIND", Kind.PACKAGE.name, [item_.kind.name for item_ in packages]
    if rule == BUILD_SNAPSHOT_SIGNATURE_KIND:
        return ("XAX.SNAPSHOT.SIGNATURE", "SNAPSHOT-SIGNATURE-KIND", B.BuildForm.SIGNATURE.name,
                [B.BuildForm(item_.body[0]).name for item_ in signatures])
    if rule == BUILD_SNAPSHOT_PACKAGES_CANONICAL:
        return canonical("SNAPSHOT-PACKAGES-CANONICAL", (item_.cid for item_ in packages))
    if rule == BUILD_SNAPSHOT_SIGNATURES_CANONICAL:
        return canonical("SNAPSHOT-SIGNATURES-CANONICAL", (item_.cid for item_ in signatures))
    if rule == BUILD_SNAPSHOT_EXTERNAL_CANONICAL:
        return canonical("SNAPSHOT-EXTERNAL-CANONICAL", (bytes(obj.body[at:at + 32]) for at in (take() for _ in range(take()))))
    if rule == BUILD_SNAPSHOT_ROOT:
        return "XAX.SNAPSHOT.ROOT", "SNAPSHOT-ROOT-PACKAGE", h(more), "missing"
    if rule == BUILD_SNAPSHOT_CLOSURE:
        reached = [item_ for item_, seen in zip(packages, quoted) if seen]
        return "XAX.SNAPSHOT.CLOSURE", "SNAPSHOT-EXACT-CLOSURE", sorted(item_.cid.hex() for item_ in reached), sorted(item_.cid.hex() for item_ in packages)
    if rule == BUILD_GRANT_DECLARED:
        grant = B.decode_profile(objects[more]).grants[item]
        identities = list(dict.fromkeys(B.decode_package(item_, resolve).logical_identity for item_ in packages))
        return "XAX.BUILD.CAPABILITY", "BUILD-GRANT-DECLARED", [identity_.hex() for identity_ in identities], [grant.logical_identity.hex(), grant.capability]
    signed = [B.decode_signature(item_, resolve).signed_root.hex() for item_ in signatures]
    if rule == BUILD_SIGNATURE_PACKAGE:
        return "XAX.TRUST.SNAPSHOT", "TRUST-SIGNATURE-PACKAGE", [item_.cid.hex() for item_ in packages], signed
    if rule == BUILD_SIGNATURE_COVERAGE:
        return "XAX.TRUST.REQUIRED", "TRUST-SNAPSHOT-COVERAGE", [item_.cid.hex() for item_ in packages], signed
    raise ValueError(f"unknown build rule {rule}")


def object_diagnostic(obj, record, objects=()):
    """S8c.19: the bootstrap's ``(code, rule, expected, actual)`` for a rejected object (rendering only: the verifier
    decided the check and its values).  ``objects``: the object table, for quoted object indices."""
    site, payload, listed = record[:3]
    x, y = payload[:2]
    name = OBJECT_SITES[site - 1]
    if name == "OBJECT_MISSING":
        return "XAX.IDENTITY.OBJECT_MISSING", "ID-REFERENCE-RESOLVED", "stored object", "missing"
    if name == "BODY_TAKE":
        return "XAX.CANON.TRUNCATED", "SER-BOUNDS", f"{x} available bytes", y
    if name == "BODY_BOOL":
        return "XAX.CANON.BOOL", "SER-BOOL-CANONICAL", "00 or 01", f"{x:02x}"
    if name == "BODY_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", BODY_RULES[x], 0, y
    if name == "BUILD_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "BUILD-REF-INDEX", f"< {x}", y
    if name == "BUILD_ENUM":
        import xax_build

        enum = getattr(xax_build, BUILD_ENUMS[x - 1])
        rule = ("BUILD-FORM", "BUILD-MODE", "BUILD-CAPABILITY-KIND", "BUILD-ARTIFACT-KIND", "OPT-OBJECTIVE")[x - 1]
        return "XAX.BUILD.ENUM", rule, sorted(item.value for item in enum), y
    if name == "BUILD_RULE":
        return _build_rule_diagnostic(obj, x, listed, payload[3], payload[4], objects, payload[6])
    if name == "BUILD_KIND_OF":
        return "XAX.BUILD.KIND", "BUILD-KIND", Kind.BUILD.name, objects[x].kind.name
    if name == "BODY_ULEB":
        return _uleb_diagnostic(obj, x, y, payload[2])
    if name in TARGET_WORD_SITES:
        return _target_rule_diagnostic(name, listed, *payload[2:5])
    if name == "TARGET_SECTION":
        return _target_section_diagnostic(x, y, payload[2])
    if name.startswith("TARGET_"):
        return _target_diagnostic(obj, name, x, y, listed)
    if name in ("GROUP_ENTRY_CONTRACT", "GROUP_RETURN_CONTRACT"):
        first = listed[1:1 + listed[0]]
        second = listed[2 + listed[0]:2 + listed[0] + listed[1 + listed[0]]]
        if name == "GROUP_ENTRY_CONTRACT":
            return "XAX.STRUCT.ENTRY_CONTRACT", "GRAPH-ENTRY-CONTRACT", [objects[i].cid.hex() for i in first], [objects[i].cid.hex() for i in second]
        return "XAX.STRUCT.RETURN_CONTRACT", "GRAPH-RETURN-CONTRACT", [objects[i].cid.hex() for i in first], [objects[i].cid.hex() for i in second]
    if name == "GROUP_MEMBER_RANGE":
        return "XAX.STRUCT.RECURSION_MEMBER", "GRAPH-RECURSION-MEMBER", f"< {listed[0]}", y
    if name == "GROUP_CALL_CONTRACT":
        quote = lambda indices: [objects[i].cid.hex() for i in indices]  # noqa: E731
        parameters, returns, operands, results = listed
        return ("XAX.STRUCT.CALL_CONTRACT", "GRAPH-CALL-CONTRACT", [quote(parameters), quote(returns)], [quote(operands), quote(results)])
    if name == "GROUP_ORDER":
        return "XAX.CANON.RECURSION_ORDER", "GRAPH-RECURSION-ORDER", list(listed), list(range(len(listed)))
    if name == "GROUP_SCC":
        return "XAX.STRUCT.RECURSION_SCC", "GRAPH-RECURSION-SCC", "one recursive strongly connected component", [list(calls) for calls in listed]
    hexes = lambda indices: [objects[index].cid.hex() for index in indices]  # noqa: E731
    if name == "GROUP_EMPTY":
        return "XAX.STRUCT.RECURSION_GROUP_EMPTY", "GRAPH-RECURSION-GROUP-NONEMPTY", ">= 1", 0
    if name == "GROUP_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {x}", y
    if name == "GROUP_CARRIER":
        return "XAX.STRUCT.FUNCTION_GRAPH", "GRAPH-FUNCTION-CARRIER", Kind.GRAPH_FRAGMENT.name, Kind(x).name
    if name == "GROUP_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "RECURSION-GROUP-BODY", 0, x
    if name == "GRAPH_TRAP_PAYLOAD":
        return "XAX.CONTROL.TRAP_PAYLOAD", "TRAP-PAYLOAD-CANONICAL", "empty or canonical u16 ULEB reason with optional target bytes", TRAP_ERRORS[x - 1]
    if name in ("GROUP_UNUSED", "GRAPH_UNUSED"):
        used = {obj.references[k].hex() for k, marked in enumerate(listed) if marked}
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in obj.references), sorted(used)
    if name in ("FUNCTION_REF_INDEX", "FUNCTION_MEMBER_RANGE"):
        rule = "GRAPH-REF-INDEX" if name == "FUNCTION_REF_INDEX" else "GRAPH-RECURSION-MEMBER"
        return ("XAX.STRUCT.REF_INDEX" if name == "FUNCTION_REF_INDEX" else "XAX.STRUCT.RECURSION_MEMBER"), rule, f"< {x}", y
    if name in ("FUNCTION_MEMBER_TRAILING", "FUNCTION_TRAILING"):
        return "XAX.CANON.TRAILING_BYTES", "FUNCTION-GROUP-MEMBER-BODY" if name == "FUNCTION_MEMBER_TRAILING" else "FUNCTION-BODY", 0, x
    if name == "FUNCTION_CARRIER":
        return "XAX.STRUCT.FUNCTION_GRAPH", "GRAPH-FUNCTION-CARRIER", Kind.GRAPH_FRAGMENT.name, Kind(x).name
    if name in ("FUNCTION_ENTRY_CONTRACT", "FUNCTION_RETURN_CONTRACT"):
        first = listed[1:1 + listed[0]]
        second = listed[2 + listed[0]:2 + listed[0] + listed[1 + listed[0]]]
        if name == "FUNCTION_ENTRY_CONTRACT":
            return "XAX.STRUCT.ENTRY_CONTRACT", "GRAPH-ENTRY-CONTRACT", hexes(first), hexes(second)
        return "XAX.STRUCT.RETURN_CONTRACT", "GRAPH-RETURN-CONTRACT", hexes(first), hexes(second)
    if name == "FUNCTION_GROUP_CONTEXT":
        return "XAX.STRUCT.GROUP_CALL_CONTEXT", "GRAPH-GROUP-CALL-CONTEXT", Kind.RECURSION_GROUP.name, Kind.FUNCTION.name
    if name == "FUNCTION_UNUSED":
        used = {obj.references[k].hex() for k, marked in enumerate(listed) if marked}
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in obj.references), sorted(used)
    if name == "LIST_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "SCHEMA-BODY", 0, x
    if name == "LIST_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {x}", tuple(listed)
    if name == "LIST_REFERENCE_BODY":
        return "XAX.CANON.REFERENCE_BODY", "SER-REF-BODY-CANONICAL", tuple(range(x)), tuple(listed)
    if name == "LIST_CHILD_KIND":
        allowed = MODULE_CHILDREN if obj.kind == Kind.MODULE else (Kind.MODULE,)
        return "XAX.STRUCT.CHILD_KIND", "GRAPH-CHILD-KIND", sorted(kind.name for kind in allowed), Kind(x).name
    if name == "CONTRACT_REF_INDEX":
        return "XAX.STRUCT.REF_INDEX", "GRAPH-REF-INDEX", f"< {x}", y
    if name == "CONTRACT_TRUNCATED":
        return "XAX.CANON.TRUNCATED", "SER-BOUNDS", "1 available bytes", 0
    if name == "CONTRACT_BOOL":
        return "XAX.CANON.BOOL", "SER-BOOL-CANONICAL", "00 or 01", f"{x:02x}"
    if name == "CONTRACT_TRAILING":
        return "XAX.CANON.TRAILING_BYTES", "CALL-CONTRACT-BODY", 0, x
    if name == "CONTRACT_UNUSED":
        used = sorted(obj.references[k].hex() for k, marked in enumerate(listed) if marked)
        return "XAX.CANON.UNUSED_REFERENCE", "SER-REFS-DIRECT-ONLY", sorted(cid.hex() for cid in obj.references), used
    raise ValueError(f"unknown object rejection site {site}")


def object_table(objects, head: list[int]) -> list[int] | None:
    """The S5b object table (``head`` first): kind, reference indices, CID, payload (graph-decoder stream for
    graphs, body bytes otherwise); None when a graph body cannot be streamed."""
    from xax_compiler import _native_graph_decoder

    decoder = _native_graph_decoder()
    if decoder is None:
        return None
    index = {obj.cid: position for position, obj in enumerate(objects)}
    words = [len(objects), *head]
    for obj in objects:
        words += [int(obj.kind), len(obj.references), *(index.get(cid, NONE) for cid in obj.references)]
        words += [int.from_bytes(obj.cid[offset:offset + 8], "big") for offset in range(0, 32, 8)]
        if obj.kind == Kind.GRAPH_FRAGMENT:
            if len(obj.body) > decoder.capacity:
                return None
            status, stream, diagnostic = decoder.decode_with_diagnostic(obj.body, len(obj.references), obj.cid)
            if status != 0 and diagnostic is None:
                return None
            payload = list(stream)  # S8 (ADR-251): a rejected body's stream prefix, flagged after the body bytes
            words += [len(payload), *payload, len(obj.body), *obj.body, int(status != 0)]  # the body bytes (recursion-group keys)
            continue
        elif obj.kind in (Kind.TYPE, Kind.CONSTANT, Kind.FUNCTION, Kind.TARGET, Kind.MODULE, Kind.PROGRAM_ROOT, Kind.CALL_CONTRACT, Kind.RECURSION_GROUP,
                          Kind.PACKAGE, Kind.BUILD):
            payload = list(obj.body)
        else:
            payload = []
        words += [len(payload), *payload]
    return words


_NATIVE: list = []
_BUILDING: list = []


def native_store_verifier():
    """The shared native store verifier, or None where it cannot run (or while it is being loaded: its own
    store is verified by the bootstrap)."""
    if _BUILDING:
        return None
    if not _NATIVE:
        import xax_native

        usable = xax_native.usable("store-verifier", STORE_PATH, "XAX_VERIFY_PYTHON")
        _BUILDING.append(True)
        try:
            _NATIVE.append(NativeStoreVerifier() if usable else None)
        except (OSError, RuntimeError, ValueError) as error:
            _NATIVE.append(None)
            xax_native.fallback("store-verifier", f"native image failed to load: {error!r}")
        finally:
            _BUILDING.clear()
    return _NATIVE[0]
