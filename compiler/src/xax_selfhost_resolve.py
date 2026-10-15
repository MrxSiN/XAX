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
from xax_selfhost_request import CTRL, _cid, _Reader
from xax_selfhost_semantic import _cid_word, _kind

RESOLVER_IDENTITY = b"xax-driver-resolver-v1"
POLICY = trust_policy()  # the driver's trust policy: its body is a constant of the program, its CID derived in XAX
# Control words, after ``xax_selfhost_request``'s ``B_*``.
(R_STATUS, R_REQUEST, R_PACKAGES, R_LENGTH) = range(48, 52)
R_POLICY = 52  # the policy's CID, four big-endian words (set by the driver)
R_REFS_AT, R_BODY_AT, R_BODY_LENGTH = 56, 57, 58  # within the snapshot's preimage: its references and its body
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
        _set(e, R_REQUEST, p["request"])
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
            r.at(p["profile"])
            for _field in range(4):  # form, mode, optimization, verification
                r.uleb()
            e.if_(e.ne(r.uleb(), 0), decline)  # grants

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
        e.var("selected", 0)
        e.for_("o", 0, p["objects"], lambda: e.set("selected", e.add(p["selected"], e.ld(e.add(SELECTED_AT, p["o"])))))
        _set(e, R_PACKAGES, p["selected"])
        _set(e, R_STATUS, p["outcome"])
        e.give(p["outcome"])
    return _function((), build, tables)


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
        byte(0)  # external input digests
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
    for name, builder in (("select", _select), ("snapshot", _snapshot)):
        function, items = builder(None)
        functions[name] = function
        objects.extend(items)
    return functions, tuple(objects)
