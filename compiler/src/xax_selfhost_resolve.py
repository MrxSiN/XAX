"""Self-hosting step S13c (ADR-283): package resolution and snapshot formation as XAX functions.

``xax_build.resolve_packages(request, candidates, policy, resolver_identity)`` selects the packages a build request
needs: from the request's package, every dependency in turn, an exact root by its CID and a logical identity by the
one candidate package that has it.  ``snapshot`` then records the request, the resolver, the trust policy, and the
selected packages, and ``snapshot_store`` writes the snapshot's reachable closure as a canonical store.

The general driver's ``resolve <request store> <snapshot store>`` does this in XAX.  A canonical store holds only what
its root reaches (``ID-ROOTED-STORE``), and a module cannot name a package, so the request store's root is the
request and its candidates are the packages it holds; every one of them is reached through the request's package and
exact dependencies.  The resolver is the driver itself: its identity is ``RESOLVER_IDENTITY``, its trust policy the
default one (``xax_build.trust_policy()``: no signature required), and it is given no external inputs.  After its
semantic verification (S10e) the driver calls the two functions here (the S10e helper convention: the verifier's
object table in, the workspace out, control words ``R_*``):

* ``select`` walks the dependencies in ``resolve_packages``'s order (a last-in, first-out stack) and marks each
  selected package (``SELECTED_AT``).  A logical identity that no candidate or several candidates have is
  ``RESOLVE-LOGICAL-IDENTITY``, with the exact diagnostic.  It declines a root that is no build request and a profile
  with grants (``decode_snapshot``'s grant check renders a capability the record cannot carry).
* ``snapshot`` writes the snapshot object's preimage after the domain (``SNAPSHOT_AT``, one byte per word): its kind,
  schema version, references in CID order (the request, the policy, whose CID the driver put in ``R_POLICY``, and
  the selected packages), and its body.

The driver hashes the policy and the snapshot with the S2 hash, marshals the store's objects with the two new ones
for the S9 writer, and writes the store the writer makes.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_build import BuildForm, trust_policy
from xax_compiler import CID_SIZE, Kind, uleb
from xax_selfhost_facts import E, _function
from xax_selfhost_request import B_INPUTS, CTRL, INPUTS_AT, _cid, _Reader
from xax_selfhost_semantic import _cid_word, _kind

RESOLVER_IDENTITY = b"xax-driver-resolver-v1"
POLICY = trust_policy()  # the driver's trust policy: its body is a constant of the program, its CID derived in XAX
# Control words, after ``xax_selfhost_request``'s ``B_*``.
(R_STATUS, R_REQUEST, R_PACKAGES, R_LENGTH) = range(48, 52)
R_POLICY = 52  # the policy's CID, four big-endian words (set by the driver)
R_REFS_AT, R_BODY_AT, R_BODY_LENGTH = 56, 57, 58  # within the snapshot's preimage: its references and its body
# S15c.1 (ADR-299): the first profile grant ``decode_snapshot`` rejects (``NO_GRANT`` when none), and the snapshot's
# CID for its record (four big-endian words, set by the driver).
R_GRANT, R_PROFILE, R_SNAPSHOT_CID = 24, 25, 26  # the CID in words 26 .. 29 (control words 20 .. 31 are otherwise unused)
NO_GRANT = (1 << 64) - 1
ACCEPT, REJECT, DECLINE = 0, 1, 2
SELECTED_AT, STACK_AT, SNAPSHOT_AT = 40 << 20, 41 << 20, 42 << 20  # workspace words
STACK_LIMIT, SNAPSHOT_LIMIT = 1 << 20, 1 << 20


def _ctrl(e: E, field: int):
    return e.ld(CTRL + field)


def _set(e: E, field: int, value):
    e.st(CTRL + field, value)


def _select(tables):
    def build(e: E):
        p = e.p
        r = _Reader(e)
        e.var("outcome", ACCEPT)
        e.var("request", e.rd(1))
        e.var("objects", e.rd(0))
        e.var("package", 0)
        e.var("grants", 0)
        e.var("grants_at", 0)
        _set(e, R_REQUEST, p["request"])
        _set(e, R_GRANT, NO_GRANT)
        running = lambda: e.eq(p["outcome"], ACCEPT)  # noqa: E731

        def decline():
            e.set("outcome", DECLINE)

        e.if_(e.ne(_kind(e, p["request"]), int(Kind.BUILD)), decline)

        def request():
            r.at(p["request"])
            e.if_(e.ne(r.uleb(), int(BuildForm.REQUEST)), decline)
            e.set("package", r.ref("request"))
            r.skip_bytes()  # the build entry
            r.uleb()  # the target
            e.var("profile", r.ref("request"))
            _set(e, R_PROFILE, p["profile"])
            r.at(p["profile"])
            for _field in range(4):  # form, mode, optimization, verification
                r.uleb()
            e.set("grants", r.uleb())
            e.set("grants_at", p["cur"])

        e.if_(running(), request)
        e.for_("clear", 0, p["objects"], lambda: e.st(e.add(SELECTED_AT, p["clear"]), 0))
        e.var("sp", 0)

        def push(value):
            e.if_(e.lt(p["sp"], STACK_LIMIT), lambda: (e.st(e.add(STACK_AT, p["sp"]), value), e.set("sp", e.add(p["sp"], 1))), decline)

        def walk():
            push(p["package"])

            def visit():
                e.set("sp", e.sub(p["sp"], 1))
                e.var("owner", e.ld(e.add(STACK_AT, p["sp"])))

                def select():
                    e.st(e.add(SELECTED_AT, p["owner"]), 1)
                    r.at(p["owner"])
                    r.skip_bytes()  # the logical identity
                    r.repeat("module", r.uleb(), r.uleb)
                    e.var("dependencies", r.uleb())
                    e.var("dependency", 0)

                    def dependency():
                        e.var("form", r.uleb())

                        def logical():
                            e.var("name_length", r.uleb())
                            e.var("name_at", p["cur"])
                            e.set("cur", e.add(p["cur"], p["name_length"]))
                            e.var("saved", p["cur"])
                            e.var("matches", 0)
                            e.var("match", 0)

                            def candidate():
                                def compare():
                                    r.at(p["c"])
                                    e.var("length", r.uleb())
                                    e.var("same", e.flag(e.eq(p["length"], p["name_length"])))
                                    e.for_("k", 0, e.sel(e.ne(p["same"], 0), p["length"], 0), lambda: e.set("same", e.and_(p["same"], e.flag(
                                        e.eq(e.rd(e.add(p["cur"], p["k"])), e.rd(e.add(p["name_at"], p["k"])))))))
                                    e.if_(e.ne(p["same"], 0), lambda: (e.set("matches", e.add(p["matches"], 1)), e.set("match", p["c"])))

                                e.if_(e.eq(_kind(e, p["c"]), int(Kind.PACKAGE)), compare)

                            e.for_("c", 0, p["objects"], candidate)
                            e.set("cur", p["saved"])

                            def reject():
                                D.begin(e)
                                e.if_(e.eq(p["matches"], 0), lambda: D.text(e, "XAX.RESOLVE.MISSING"), lambda: D.text(e, "XAX.RESOLVE.AMBIGUOUS"))
                                _cid(e, p["owner"])
                                D.text(e, "RESOLVE-LOGICAL-IDENTITY")
                                D.text(e, "exactly one candidate")
                                D.put(e, D.T_LIST)
                                D.put(e, p["matches"])

                                def listed():
                                    def same():
                                        r.at(p["m"])
                                        e.var("length", r.uleb())
                                        e.var("same", e.flag(e.eq(p["length"], p["name_length"])))
                                        e.for_("k", 0, e.sel(e.ne(p["same"], 0), p["length"], 0), lambda: e.set("same", e.and_(p["same"], e.flag(
                                            e.eq(e.rd(e.add(p["cur"], p["k"])), e.rd(e.add(p["name_at"], p["k"])))))))
                                        e.if_(e.ne(p["same"], 0), lambda: _cid(e, p["m"]))

                                    e.if_(e.eq(_kind(e, p["m"]), int(Kind.PACKAGE)), same)

                                e.for_("m", 0, p["objects"], listed)  # in store order: the CIDs sorted
                                e.set("outcome", REJECT)

                            e.if_(e.ne(p["matches"], 1), reject, lambda: push(p["match"]))

                        e.if_(e.eq(p["form"], 1), lambda: push(r.ref("owner")), logical)
                        e.set("dependency", e.add(p["dependency"], 1))

                    e.while_(lambda: e.both(e.lt(p["dependency"], p["dependencies"]), running()), dependency)

                e.if_(e.eq(e.ld(e.add(SELECTED_AT, p["owner"])), 0), select)

            e.while_(lambda: e.both(e.ne(p["sp"], 0), running()), visit)

        e.if_(running(), walk)
        e.if_(running(), lambda: _grants(e, r))
        e.var("selected", 0)
        e.for_("o", 0, p["objects"], lambda: e.set("selected", e.add(p["selected"], e.ld(e.add(SELECTED_AT, p["o"])))))
        _set(e, R_PACKAGES, p["selected"])
        _set(e, R_STATUS, p["outcome"])
        e.give(p["outcome"])
    return _function((), build, tables)


def _package_identity(e: E, r: _Reader, package, name: str):
    """The package's logical identity: where its bytes start and its length; the cursor is after it."""
    r.at(package)
    e.var(f"{name}_length", r.uleb())
    e.var(f"{name}_at", e.p["cur"])
    e.set("cur", e.add(e.p["cur"], e.p[f"{name}_length"]))


def _same(e: E, name: str, x_at, x_length, y_at, y_length):
    p = e.p
    e.var(name, e.flag(e.eq(x_length, y_length)))
    e.for_(f"{name}_k", 0, e.sel(e.ne(p[name], 0), x_length, 0), lambda: e.set(name, e.and_(p[name], e.flag(
        e.eq(e.rd(e.add(x_at, p[f"{name}_k"])), e.rd(e.add(y_at, p[f"{name}_k"])))))))
    return p[name]


def _grants(e: E, r: _Reader):
    """``decode_snapshot``'s grant check over the selected packages: the first profile grant whose logical identity
    no selected package has, or which some package with that identity does not declare, in ``R_GRANT``."""
    p = e.p
    e.var("gcur", p["grants_at"])
    e.var("gq", 0)

    def grant():
        e.set("cur", p["gcur"])
        e.var("gi_length", r.uleb())
        e.var("gi_at", p["cur"])
        e.set("cur", e.add(p["cur"], p["gi_length"]))
        e.var("g_kind", r.uleb())
        e.var("gs_length", r.uleb())
        e.var("gs_at", p["cur"])
        e.set("cur", e.add(p["cur"], p["gs_length"]))
        e.set("gcur", p["cur"])
        e.var("found", 0)
        e.var("missing", 0)

        def candidate():
            def has_identity():
                _package_identity(e, r, p["gp"], "gpi")

                def declared():
                    e.set("found", 1)
                    r.repeat("gm", r.uleb(), r.uleb)  # modules
                    r.repeat("gd", r.uleb(), lambda: e.if_(e.eq(r.uleb(), 1), r.uleb, r.skip_bytes))  # dependencies
                    for name in ("ge", "gf", "gc"):  # build entries, features, configuration
                        r.repeat(name, r.uleb(), lambda: (r.skip_bytes(), r.uleb()))
                    e.var("has", 0)

                    def capability():
                        e.var("c_kind", r.uleb())
                        e.var("cs_length", r.uleb())
                        e.var("cs_at", p["cur"])
                        e.set("cur", e.add(p["cur"], p["cs_length"]))
                        e.if_(e.eq(p["c_kind"], p["g_kind"]), lambda: e.set("has", e.or_(p["has"], _same(
                            e, "scope_same", p["cs_at"], p["cs_length"], p["gs_at"], p["gs_length"]))))

                    r.repeat("gcap", r.uleb(), capability)
                    e.if_(e.eq(p["has"], 0), lambda: e.set("missing", 1))

                e.if_(e.ne(_same(e, "identity_same", p["gpi_at"], p["gpi_length"], p["gi_at"], p["gi_length"]), 0), declared)

            e.if_(e.ne(e.ld(e.add(SELECTED_AT, p["gp"])), 0), has_identity)

        e.for_("gp", 0, p["objects"], candidate)
        e.if_(e.either(e.eq(p["found"], 0), e.ne(p["missing"], 0)), lambda: _set(e, R_GRANT, p["gq"]))
        e.set("gq", e.add(p["gq"], 1))

    e.while_(lambda: e.both(e.lt(p["gq"], p["grants"]), e.eq(_ctrl(e, R_GRANT), NO_GRANT)), grant)


def _grant_record(tables):
    """The record of ``decode_snapshot``'s BUILD-GRANT-DECLARED for grant ``R_GRANT``: the snapshot, the selected
    packages' logical identities (each once, in package order), and the grant's identity and capability."""
    def build(e: E):
        p = e.p
        r = _Reader(e)
        e.var("objects", e.rd(0))
        D.begin(e)
        D.text(e, "XAX.BUILD.CAPABILITY")
        D.cid(e, [_ctrl(e, R_SNAPSHOT_CID + k) for k in range(4)])
        D.text(e, "BUILD-GRANT-DECLARED")

        def identities(emit):
            def each():
                def selected():
                    _package_identity(e, r, p["io"], "ii")
                    e.var("first", 1)

                    def earlier():
                        def compare():
                            _package_identity(e, r, p["ij"], "ij_id")
                            e.if_(e.ne(_same(e, "earlier_same", p["ij_id_at"], p["ij_id_length"], p["ii_at"], p["ii_length"]), 0),
                                  lambda: e.set("first", 0))

                        e.if_(e.ne(e.ld(e.add(SELECTED_AT, p["ij"])), 0), compare)

                    e.for_("ij", 0, p["io"], earlier)
                    e.if_(e.ne(p["first"], 0), lambda: emit(p["ii_at"], p["ii_length"]))

                e.if_(e.ne(e.ld(e.add(SELECTED_AT, p["io"])), 0), selected)

            e.for_("io", 0, p["objects"], each)

        e.var("distinct", 0)
        identities(lambda _at, _length: e.set("distinct", e.add(p["distinct"], 1)))
        D.put(e, D.T_LIST)
        D.put(e, p["distinct"])
        identities(lambda at, length: _bytes(e, D.T_HEX, at, length))
        # The grant: its identity and its capability.
        r.at(_ctrl(e, R_PROFILE))
        for _field in range(4):
            r.uleb()
        r.uleb()  # the grant count
        e.for_("gk", 0, _ctrl(e, R_GRANT), lambda: (r.skip_bytes(), r.uleb(), r.skip_bytes()))
        e.var("gi_length", r.uleb())
        e.var("gi_at", p["cur"])
        e.set("cur", e.add(p["cur"], p["gi_length"]))
        e.var("g_kind", r.uleb())
        e.var("gs_length", r.uleb())
        e.var("gs_at", p["cur"])
        D.put(e, D.T_LIST)
        D.put(e, 2)
        _bytes(e, D.T_HEX, p["gi_at"], p["gi_length"])
        D.put(e, D.T_OBJECT)
        D.put(e, D.OBJECT_NAMES.index("BuildCapability"))
        D.put(e, 2)
        D.put(e, D.T_ENUM)
        D.put(e, D.ENUM_NAMES.index("BuildCapabilityKind"))
        D.put(e, p["g_kind"])
        _bytes(e, D.T_BYTES, p["gs_at"], p["gs_length"])
        e.give(0)
    return _function((), build, tables)


def _bytes(e: E, tag: int, at, length):
    """A record value of ``length`` input bytes at ``at``, packed eight per word."""
    p = e.p
    D.put(e, tag)
    D.put(e, length)
    e.var("bw", 0)

    def word():
        e.var("bv", 0)
        for k in reversed(range(8)):
            e.set("bv", e.add(e.mul(p["bv"], 256), e.sel(e.lt(e.add(p["bw"], k), length), e.rd(e.add(at, e.add(p["bw"], k))), 0)))
        D.put(e, p["bv"])
        e.set("bw", e.add(p["bw"], 8))

    e.while_(lambda: e.lt(p["bw"], length), word)


def _snapshot(tables):
    """The snapshot's preimage after the domain; ``R_LENGTH`` its length in bytes."""
    def build(e: E):
        p = e.p
        e.var("at", SNAPSHOT_AT)
        e.var("objects", e.rd(0))
        e.var("request", _ctrl(e, R_REQUEST))

        def byte(value):
            e.st(p["at"], value)
            e.set("at", e.add(p["at"], 1))

        def put_uleb(value):
            e.var("u", value)
            e.var("u_more", 1)

            def step():
                e.var("u_low", e.and_(p["u"], 127))
                e.set("u", e.udiv(p["u"], 128))
                byte(e.add(p["u_low"], e.mul(e.flag(e.ne(p["u"], 0)), 128)))
                e.set("u_more", e.flag(e.ne(p["u"], 0)))

            e.while_(lambda: e.ne(p["u_more"], 0), step)

        def policy_less(o):
            """The policy's CID before object ``o``'s."""
            result = e.lt(_ctrl(e, R_POLICY + 3), _cid_word(e, o, 3))
            for k in (2, 1, 0):
                result = e.either(e.lt(_ctrl(e, R_POLICY + k), _cid_word(e, o, k)),
                                  e.both(e.eq(_ctrl(e, R_POLICY + k), _cid_word(e, o, k)), result))
            return result

        def referenced(o):
            return e.either(e.eq(o, p["request"]), e.ne(e.ld(e.add(SELECTED_AT, o)), 0))

        def cid_bytes(word):
            for j in range(8):
                byte(e.and_(e.udiv(word, 1 << (8 * (7 - j))), 255))

        byte(int(Kind.BUILD))
        byte(1)
        put_uleb(e.add(_ctrl(e, R_PACKAGES), 2))
        _set(e, R_REFS_AT, e.sub(p["at"], SNAPSHOT_AT))
        # The references in CID order (the store's order), the policy at its place; each one's index for the body.
        e.var("index", 0)
        e.var("policy_index", NONE_INDEX)
        e.var("request_index", 0)

        def reference():
            def policy_here():
                e.if_(e.both(e.eq(p["policy_index"], NONE_INDEX), policy_less(p["o"])), lambda: (
                    e.set("policy_index", p["index"]), [cid_bytes(_ctrl(e, R_POLICY + k)) for k in range(4)], e.set("index", e.add(p["index"], 1))))

            def listed():
                policy_here()
                e.if_(e.eq(p["o"], p["request"]), lambda: e.set("request_index", p["index"]))
                for k in range(4):
                    cid_bytes(_cid_word(e, p["o"], k))
                e.st(e.add(STACK_AT, p["o"]), p["index"])  # the package's reference index
                e.set("index", e.add(p["index"], 1))

            e.if_(referenced(p["o"]), listed)

        e.for_("o", 0, p["objects"], reference)
        e.if_(e.eq(p["policy_index"], NONE_INDEX), lambda: (e.set("policy_index", p["index"]), [cid_bytes(_ctrl(e, R_POLICY + k)) for k in range(4)]))
        # The body after its length (the length precedes it in the preimage, so the body is staged and copied).
        e.var("body_at", p["at"])
        byte(int(BuildForm.SNAPSHOT))
        put_uleb(p["request_index"])
        put_uleb(len(RESOLVER_IDENTITY))
        for value in RESOLVER_IDENTITY:
            byte(value)
        put_uleb(p["policy_index"])
        put_uleb(_ctrl(e, R_PACKAGES))
        e.for_("o2", 0, p["objects"], lambda: e.if_(e.ne(e.ld(e.add(SELECTED_AT, p["o2"])), 0),
                                                   lambda: put_uleb(e.ld(e.add(STACK_AT, p["o2"])))))
        byte(0)  # signatures
        put_uleb(_ctrl(e, B_INPUTS))  # S15c.2: the external input digests, sorted (``INPUTS_AT``)
        e.for_("xd", 0, e.mul(_ctrl(e, B_INPUTS), CID_SIZE), lambda: byte(e.ld(e.add(INPUTS_AT, p["xd"]))))
        e.var("body_length", e.sub(p["at"], p["body_at"]))
        # Move the body up past its length's ULEB.
        e.set("at", p["body_at"])
        e.var("shift", 1)
        e.var("probe", e.udiv(p["body_length"], 128))
        e.while_(lambda: e.ne(p["probe"], 0), lambda: (e.set("shift", e.add(p["shift"], 1)), e.set("probe", e.udiv(p["probe"], 128))))
        e.var("q", p["body_length"])
        e.while_(lambda: e.ne(p["q"], 0), lambda: (e.set("q", e.sub(p["q"], 1)),
                                                  e.st(e.add(e.add(p["body_at"], p["shift"]), p["q"]), e.ld(e.add(p["body_at"], p["q"])))))
        put_uleb(p["body_length"])
        _set(e, R_BODY_AT, e.sub(p["at"], SNAPSHOT_AT))
        _set(e, R_BODY_LENGTH, p["body_length"])
        _set(e, R_LENGTH, e.sub(e.add(p["at"], p["body_length"]), SNAPSHOT_AT))
        e.give(0)
    return _function((), build, tables)


NONE_INDEX = (1 << 64) - 1
POLICY_PREIMAGE = uleb(Kind.BUILD) + uleb(1) + uleb(0) + uleb(len(POLICY.body)) + POLICY.body  # after the domain
assert CID_SIZE == 32


def build_functions():
    """``{name: function}`` and the objects they need."""
    functions, objects = {}, []
    for name, builder in (("select", _select), ("snapshot", _snapshot), ("grant_record", _grant_record)):
        function, items = builder(None)
        functions[name] = function
        objects.extend(items)
    return functions, tuple(objects)
