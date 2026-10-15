"""Self-hosting step S13a (ADR-281): the build request a snapshot store names, and its provenance, as XAX functions.

``xax_build.build(reader, request_root)`` reads a build snapshot store before it lowers anything: the root must be a
snapshot, the snapshot names the request, the external inputs and the trust policy; the request names the package,
its build entry, the target, the profile, and the requested artifacts.  After lowering it records the artifact's
provenance.  The general compiler driver (``xax_selfhost_driver``, command ``build``) makes these decisions with the
two functions here, after its own semantic verification (S10e), so every body they read has been verified.

Both have the S10e helper convention (``xax_selfhost_semantic``): the input view is the store verifier's object table
(``index_objects`` has located each record in ``OBJAT``), the output view the driver's workspace, and the arguments and
results travel in its control words (``B_*``, after the semantic helpers' ``C_*``).

* ``build_request`` reads the snapshot and decides ``build``'s rejections before lowering, each with its exact
  diagnostic record (at ``DIAG_AT`` of the workspace): the root is no build object (``BUILD-KIND``) or no snapshot
  (``BUILD-SNAPSHOT-ROOT``); the snapshot declares external inputs, of which the driver is given none
  (``BUILD-EXTERNAL-COMPLETE``); its trust policy requires package signatures, which the driver does not verify
  (``TRUST-SIGNATURE-REQUIRED``, ``build`` without a signature verifier).  It finds the build entry's function and the
  target, and declines ``build``'s other paths: Android packages, Windows DLLs, and targets other than the Linux
  x86-64 ELF profiles.  ``build`` checks the requested artifacts only after it made the container, so a request for
  anything but one native image writes its record (``BUILD-ARTIFACT-SUPPORTED``) and sets ``B_ARTIFACT``; the driver
  rejects with it only when lowering succeeded.
* ``provenance`` writes the envelope of ``xax_build.provenance``'s object (``ENVELOPE_AT``, one byte per word): its four
  references (snapshot, request, target, profile) in CID order, their indices, the artifact digest the driver put in
  ``B_DIGEST``, the driver's compiler identity, the profile's lowering identity, and an empty producer.  The driver
  hashes the CID preimage (the domain, then the envelope from its kind on) with the S2 hash and writes the CID.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
from xax_artifact import XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1, container_lowering_identity
from xax_build import ArtifactKind, BuildForm
from xax_compiler import CID_SIZE, Kind, uleb
from xax_selfhost_facts import E, _function
from xax_selfhost_semantic import CTRL, _END, _body, _cid_word, _kind, _ref

# Control words: the outcome, the objects found, the artifact flag, the digest (four little-endian words).
(B_STATUS, B_SNAPSHOT, B_REQUEST, B_TARGET, B_PROFILE, B_ENTRY, B_DYNAMIC, B_ARTIFACT) = range(32, 40)
B_DIGEST = 40
ACCEPT, REJECT, DECLINE = 0, 1, 2
GENERAL_IDENTITIES = (b"x86_64-linux-elf-exec-v1", b"x86_64-linux-elf-dynexec-v1")  # ``xax_selfhost_driver``'s
KIND_NAMES = {int(kind): kind.name for kind in Kind}
FORM_NAMES = {int(form): form.name for form in BuildForm}
ARTIFACT_NAMES = {int(kind): kind.name for kind in ArtifactKind}
# Requested artifacts ``build`` makes on its own paths before any target container.
BOOTSTRAP_ARTIFACTS = (ArtifactKind.ANDROID_UNSIGNED_APK, ArtifactKind.ANDROID_SIGNED_APK, ArtifactKind.WINDOWS_DLL)


def _provenance_layout() -> tuple[bytes, dict[str, int]]:
    """The envelope of a provenance object this driver writes (``SemanticObject.envelope``), with zeros where its content
    varies (CID, references, their indices, the digest) and the exec profile's lowering identity; and the offsets of
    those fields."""
    body = (uleb(BuildForm.PROVENANCE) + bytes(4) + bytes(CID_SIZE) + XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1
            + container_lowering_identity(GENERAL_IDENTITIES[0]) + uleb(0))
    payload = bytes(CID_SIZE) + uleb(Kind.BUILD) + uleb(1) + uleb(4) + bytes(4 * CID_SIZE) + uleb(len(body)) + body
    cid = len(uleb(len(payload)))
    references = cid + CID_SIZE + 3
    body_at = references + 4 * CID_SIZE + len(uleb(len(body)))
    return uleb(len(payload)) + payload, {"cid": cid, "kind": cid + CID_SIZE, "references": references, "body": body_at,
                                          "digest": body_at + 5, "lowering": body_at + 5 + 2 * CID_SIZE}


TEMPLATE, _OFFSETS = _provenance_layout()
P_CID, P_KIND, P_REFERENCES, P_BODY, P_DIGEST, P_LOWERING = (_OFFSETS[name] for name in ("cid", "kind", "references", "body", "digest", "lowering"))
ENVELOPE_AT = _END  # the workspace's free words before the diagnostic record
assert ENVELOPE_AT + len(TEMPLATE) <= D.DIAG_AT


def _ctrl(e: E, field: int):
    return e.ld(CTRL + field)


def _set(e: E, field: int, value):
    e.st(CTRL + field, value)


class _Reader:
    """A cursor over object bodies in the input view (one byte per word)."""

    def __init__(self, e: E):
        self.e = e
        e.var("cur", 0)

    def at(self, o):
        """Move to the start of object ``o``'s body."""
        self.e.set("cur", _body(self.e, o)[1])

    def byte(self, offset=0):
        return self.e.rd(self.e.add(self.e.p["cur"], offset))

    def uleb(self):
        e, p = self.e, self.e.p
        e.var("u_value", 0)
        e.var("u_shift", 1)
        e.var("u_more", 1)

        def step():
            e.var("u_byte", e.rd(p["cur"]))
            e.set("u_value", e.add(p["u_value"], e.mul(e.and_(p["u_byte"], 127), p["u_shift"])))
            e.set("u_shift", e.mul(p["u_shift"], 128))
            e.set("u_more", e.flag(e.le(128, p["u_byte"])))
            e.set("cur", e.add(p["cur"], 1))

        e.while_(lambda: e.ne(p["u_more"], 0), step)
        return p["u_value"]

    def ref(self, owner: str):
        """The object position the next ULEB (a reference index of object ``owner``) names."""
        index = self.uleb()
        return _ref(self.e, self.e.p[owner], index)

    def skip_bytes(self):
        length = self.uleb()  # moves the cursor first
        self.e.set("cur", self.e.add(self.e.p["cur"], length))

    def repeat(self, name: str, count, item):
        self.e.for_(name, 0, count, item)


def _cid(e: E, o):
    D.cid(e, [_cid_word(e, o, k) for k in range(4)])


def _name(e: E, value: str, names: dict[int, str]):
    for number, name in names.items():
        e.if_(e.eq(e.p[value], number), lambda name=name: D.text(e, name))


def _reject(e: E, code: str, entity, rule: str, expected, actual):
    D.begin(e)
    D.text(e, code)
    entity()
    D.text(e, rule)
    expected()
    actual()
    e.set("outcome", REJECT)


def _build_request(tables):
    def build(e: E):
        p = e.p
        r = _Reader(e)
        e.var("outcome", ACCEPT)
        e.var("request", 0)
        e.var("snapshot", e.rd(1))
        _set(e, B_SNAPSHOT, p["snapshot"])
        _set(e, B_ARTIFACT, 0)
        _set(e, B_DYNAMIC, 0)
        running = lambda: e.eq(p["outcome"], ACCEPT)  # noqa: E731

        def when(body):
            e.if_(running(), body)

        # ``_snapshot_context``: the root is a snapshot.
        e.var("root_kind", _kind(e, p["snapshot"]))
        e.if_(e.ne(p["root_kind"], int(Kind.BUILD)), lambda: _reject(
            e, "XAX.BUILD.KIND", lambda: _cid(e, p["snapshot"]), "BUILD-KIND", lambda: D.text(e, Kind.BUILD.name),
            lambda: _name(e, "root_kind", KIND_NAMES)))

        def form():
            r.at(p["snapshot"])
            e.var("root_form", r.uleb())
            e.if_(e.ne(p["root_form"], int(BuildForm.SNAPSHOT)), lambda: _reject(
                e, "XAX.BUILD.SNAPSHOT", lambda: _cid(e, p["snapshot"]), "BUILD-SNAPSHOT-ROOT", lambda: D.text(e, BuildForm.SNAPSHOT.name),
                lambda: _name(e, "root_form", FORM_NAMES)))

        when(form)

        def snapshot():
            """The request, the trust policy, the first (smallest) package, and the external input digests."""
            e.set("request", r.ref("snapshot"))
            r.skip_bytes()  # the resolver identity
            e.var("policy", r.ref("snapshot"))
            e.var("packages", r.uleb())
            e.var("first_package", r.ref("snapshot"))  # the request's package is in the closure
            r.repeat("sp", e.sub(p["packages"], 1), r.uleb)
            r.repeat("ss", r.uleb(), r.uleb)  # signatures
            e.var("digests", r.uleb())

            def digests():
                D.put(e, D.T_LIST)
                D.put(e, p["digests"])

                def digest():
                    D.put(e, D.T_HEX)
                    D.put(e, CID_SIZE)
                    for word in range(CID_SIZE // 8):
                        value = e.c(0)
                        for k in reversed(range(8)):
                            value = e.add(e.mul(value, 256), r.byte(e.add(e.mul(p["sd"], CID_SIZE), 8 * word + k)))
                        D.put(e, value)

                e.for_("sd", 0, p["digests"], digest)

            # ``_validate_external_inputs``: the driver is given none.
            e.if_(e.ne(p["digests"], 0), lambda: _reject(
                e, "XAX.BUILD.INPUT_CLOSURE", lambda: D.text(e, "external-inputs"), "BUILD-EXTERNAL-COMPLETE", digests,
                lambda: (D.put(e, D.T_LIST), D.put(e, 0))))

            # ``_validate_trust`` without a signature verifier: the first package has no trusted signature.
            def trust():
                r.at(p["policy"])
                e.if_(e.ne(r.byte(1), 0), lambda: _reject(  # after the one-byte form
                    e, "XAX.TRUST.REQUIRED", lambda: _cid(e, p["first_package"]), "TRUST-SIGNATURE-REQUIRED",
                    lambda: D.text(e, "accepted valid signature"), lambda: D.text(e, "missing")))

            when(trust)

        when(snapshot)

        def request():
            r.at(p["request"])
            r.uleb()  # the form
            e.var("package", r.ref("request"))
            e.var("entry_length", r.uleb())
            e.var("entry_at", p["cur"])
            e.set("cur", e.add(p["cur"], p["entry_length"]))
            _set(e, B_TARGET, r.ref("request"))
            _set(e, B_PROFILE, r.ref("request"))
            _set(e, B_REQUEST, p["request"])
            for name in ("rf", "rc"):  # feature and configuration bindings
                r.repeat(name, r.uleb(), lambda: (r.skip_bytes(), r.uleb()))
            e.var("artifacts", r.uleb())
            e.var("artifacts_at", p["cur"])
            # The package's build entry with the request's name.
            _set(e, B_ENTRY, e.c(-1))
            r.at(p["package"])
            r.skip_bytes()  # the logical identity
            r.repeat("pm", r.uleb(), r.uleb)  # modules
            r.repeat("pd", r.uleb(), lambda: e.if_(e.eq(r.uleb(), 1), r.uleb, r.skip_bytes))  # dependencies

            def build_entry():
                e.var("name_length", r.uleb())
                e.var("name_at", p["cur"])
                e.set("cur", e.add(p["cur"], p["name_length"]))
                e.var("index", r.uleb())
                e.var("same", e.flag(e.eq(p["name_length"], p["entry_length"])))
                e.for_("nq", 0, e.sel(e.ne(p["same"], 0), p["name_length"], 0), lambda: e.set("same", e.and_(p["same"], e.flag(
                    e.eq(e.rd(e.add(p["name_at"], p["nq"])), e.rd(e.add(p["entry_at"], p["nq"])))))))
                e.if_(e.ne(p["same"], 0), lambda: _set(e, B_ENTRY, _ref(e, p["package"], p["index"])))

            r.repeat("pe", r.uleb(), build_entry)
            e.if_(e.eq(_ctrl(e, B_ENTRY), e.c(-1)), lambda: e.set("outcome", DECLINE))

            # ``build``'s own paths come first; the Linux x86-64 profiles are ``_hosted_container``'s.
            e.var("first_kind", e.rd(p["artifacts_at"]))  # artifact kinds are one ULEB byte
            e.if_(e.both(e.eq(p["artifacts"], 1), e.either(*(e.eq(p["first_kind"], int(kind)) for kind in BOOTSTRAP_ARTIFACTS))),
                  lambda: e.set("outcome", DECLINE))
            r.at(_ctrl(e, B_TARGET))
            e.var("linux", 0)
            for identity in GENERAL_IDENTITIES:
                def same(identity=identity):
                    e.var("matched", 1)
                    for k, byte in enumerate(identity):
                        e.set("matched", e.and_(p["matched"], e.flag(e.eq(r.byte(1 + k), byte))))
                    e.set("linux", e.or_(p["linux"], p["matched"]))
                    if identity == GENERAL_IDENTITIES[1]:
                        _set(e, B_DYNAMIC, p["matched"])

                e.if_(e.eq(r.byte(), len(identity)), same)
            e.if_(e.eq(p["linux"], 0), lambda: e.set("outcome", DECLINE))

            # Recorded now, decided after lowering: one native image.
            def artifacts():
                def requested():
                    D.put(e, D.T_LIST)
                    D.put(e, p["artifacts"])
                    e.for_("ak", 0, p["artifacts"], lambda: (e.var("kind_value", e.rd(e.add(p["artifacts_at"], p["ak"]))),
                                                             _name(e, "kind_value", ARTIFACT_NAMES)))

                D.begin(e)
                D.text(e, "XAX.BUILD.ARTIFACT")
                _cid(e, p["request"])
                D.text(e, "BUILD-ARTIFACT-SUPPORTED")
                D.put(e, D.T_LIST)
                D.put(e, 1)
                D.text(e, ArtifactKind.NATIVE_IMAGE.name)
                requested()
                _set(e, B_ARTIFACT, 1)

            native = e.both(e.eq(p["artifacts"], 1), e.eq(p["first_kind"], int(ArtifactKind.NATIVE_IMAGE)))
            e.if_(e.both(running(), e.not_(native)), artifacts)

        when(request)
        _set(e, B_STATUS, p["outcome"])
        e.give(p["outcome"])
    return _function((), build, tables)


def _provenance(tables):
    def build(e: E):
        p = e.p
        for k, byte in enumerate(TEMPLATE):
            e.st(ENVELOPE_AT + k, byte)
        dynamic = container_lowering_identity(GENERAL_IDENTITIES[1])
        e.if_(e.ne(_ctrl(e, B_DYNAMIC), 0), lambda: [e.st(ENVELOPE_AT + P_LOWERING + k, byte) for k, byte in enumerate(dynamic)])
        for word in range(CID_SIZE // 8):
            for k in range(8):
                e.st(ENVELOPE_AT + P_DIGEST + 8 * word + k, e.and_(e.udiv(_ctrl(e, B_DIGEST + word), 1 << (8 * k)), 255))
        fields = (B_SNAPSHOT, B_REQUEST, B_TARGET, B_PROFILE)
        for i, field in enumerate(fields):
            for k in range(4):
                e.var(f"w{i}{k}", _cid_word(e, _ctrl(e, field), k))

        def less(a: int, b: int):
            """CID ``a`` before CID ``b``: unsigned lexicographic order, big-endian words."""
            result = e.lt(p[f"w{a}3"], p[f"w{b}3"])
            for k in (2, 1, 0):
                result = e.either(e.lt(p[f"w{a}{k}"], p[f"w{b}{k}"]), e.both(e.eq(p[f"w{a}{k}"], p[f"w{b}{k}"]), result))
            return result

        for i in range(len(fields)):
            index = e.c(0)
            for j in range(len(fields)):
                if j != i:
                    index = e.add(index, e.flag(less(j, i)))
            e.var(f"index{i}", index)
            e.st(ENVELOPE_AT + P_BODY + 1 + i, p[f"index{i}"])
            at = e.add(ENVELOPE_AT + P_REFERENCES, e.mul(p[f"index{i}"], CID_SIZE))
            for k in range(4):
                for j in range(8):
                    e.st(e.add(at, 8 * k + j), e.and_(e.udiv(p[f"w{i}{k}"], 1 << (8 * (7 - j))), 255))
        e.give(0)
    return _function((), build, tables)


def build_functions():
    """``{name: function}`` and the objects they need."""
    functions, objects = {}, []
    for name, builder in (("build_request", _build_request), ("provenance", _provenance)):
        function, items = builder(None)
        functions[name] = function
        objects.extend(items)
    return functions, tuple(objects)
