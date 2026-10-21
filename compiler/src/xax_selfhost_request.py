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
  x86-64 ELF profiles, (S15e.1, ADR-308) the RISC-V raw image profiles, whose requested artifacts it checks at once,
  and (S15e.2, ADR-315) the Linux AArch64 ELF profiles.  The target's path is ``B_PATH`` (``PATH_*``): the program
  the driver lowers it with.  ``build`` checks the requested artifacts only after it made the container, so a request for
  anything but one native image writes its record (``BUILD-ARTIFACT-SUPPORTED``) and sets ``B_ARTIFACT``; the driver
  rejects with it only when lowering succeeded.
* ``provenance`` writes the envelope of ``xax_build.provenance``'s object (``ENVELOPE_AT``, one byte per word): its four
  references (snapshot, request, target, profile) in CID order, their indices, the artifact digest the driver put in
  ``B_DIGEST``, the driver's compiler identity, the profile's lowering identity, and an empty producer.  The driver
  hashes the CID preimage (the domain, then the envelope from its kind on) with the S2 hash and writes the CID.
"""

from __future__ import annotations

import xax_selfhost_diagnostics as D
import xax_selfhost_ed25519 as ED
from xax_artifact import (ACCELERATOR_LOWERING_IDENTITY_V1, RISCV64_LOWERING_IDENTITY_V1, XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1,
                          container_lowering_identity)
from xax_build import ArtifactKind, BuildForm
from xax_compiler import (
    AARCH64_LINUX_ELF_DYNAMIC_FORMAT, AARCH64_LINUX_ELF_EXEC_FORMAT, AARCH64_LINUX_IDENTITIES, CID_SIZE, RISCV64_ARCHITECTURE,
    RISCV64_RAW_FORMAT, SPIRV_ARCHITECTURE, SPIRV_MODULE_FORMAT, SPIRV_VULKAN_COMPUTE_IDENTITY, X86_64_LINUX_ELF_DYNAMIC_FORMAT,
    X86_64_LINUX_ELF_EXEC_FORMAT, Kind, uleb,
)
from xax_selfhost_facts import E, _function
from xax_ed25519 import ALGORITHM, DOMAIN
from xax_selfhost_semantic import CTRL, _END, _body, _cid_word, _kind, _ref

# Control words: the outcome, the objects found, the artifact flag, the digest (four little-endian words).
(B_STATUS, B_SNAPSHOT, B_REQUEST, B_TARGET, B_PROFILE, B_ENTRY, B_DYNAMIC, B_ARTIFACT) = range(32, 40)
B_DIGEST = 40
# S15c.2 (ADR-300): the input files' digests, sorted and each once, one byte per word (set by the driver).
B_INPUTS = 44
# S15e.1 (ADR-308), S15e.2 (ADR-315): the program the driver lowers the request's target with.
B_PATH = 45
PATH_LINUX_X86_64, PATH_RISCV64_RAW, PATH_LINUX_AARCH64, PATH_WINDOWS_PE = 0, 1, 2, 3
# S15e.7a (ADR-321): an accelerator deployment (architecture 4, image format 3), made by the general program.
PATH_ACCELERATOR = 4
# S15e.7b (ADR-321): the SPIR-V compute profile, a hosted container, made by the general program.
PATH_SPIRV = 5
ACCELERATOR_ARCHITECTURE, ACCELERATOR_FORMAT = 4, 3
# S15e.3b (ADR-320): 1 for a Windows DLL request on the PE profile: ``B_ENTRY`` is then the request itself (the general
# program reads the package's plan, ``xax_selfhost_general_dll``), and the provenance names the DLL container.
B_DLL = 46
DLL_LOWERING = b"x86_64-windows-pe-dll-v1"
INPUTS_AT, INPUTS_LIMIT = 46 << 20, 64  # the builder baseline's bound; the committed compiler's is 100 (ledger 0001, ADR-306)
TRUST_AT = 47 << 20  # S15c.3: per snapshot signature, 1 once it is accepted
ACCEPT, REJECT, DECLINE = 0, 1, 2
NONE_FIELD = 1 << 32  # no architecture: a field no target carries
GENERAL_IDENTITIES = (b"x86_64-linux-elf-exec-v1", b"x86_64-linux-elf-dynexec-v1")  # ``xax_selfhost_driver``'s
# ``_hosted_container``'s profiles the driver builds, by target identity: (identity, path, dynamic loader, architecture,
# image formats); an identity whose native fields are not its profile's declines.
HOSTED_PROFILES = (
    (GENERAL_IDENTITIES[0], PATH_LINUX_X86_64, 0, None, ()),
    (GENERAL_IDENTITIES[1], PATH_LINUX_X86_64, 1, None, ()),
    (AARCH64_LINUX_IDENTITIES[0], PATH_LINUX_AARCH64, 0, 3, (AARCH64_LINUX_ELF_EXEC_FORMAT, AARCH64_LINUX_ELF_DYNAMIC_FORMAT)),
    (AARCH64_LINUX_IDENTITIES[1], PATH_LINUX_AARCH64, 1, 3, (AARCH64_LINUX_ELF_EXEC_FORMAT, AARCH64_LINUX_ELF_DYNAMIC_FORMAT)),
    # S15e.3 (ADR-317): any image format but the Linux x86-64 ELF ones (``_hosted_container`` tries those first).
    (b"x86_64-windows-pe-v1", PATH_WINDOWS_PE, 0, 1, None),
    (SPIRV_VULKAN_COMPUTE_IDENTITY, PATH_SPIRV, 0, SPIRV_ARCHITECTURE, (SPIRV_MODULE_FORMAT,)),  # S15e.7b
)
LINUX_X86_64_FORMATS = (X86_64_LINUX_ELF_EXEC_FORMAT, X86_64_LINUX_ELF_DYNAMIC_FORMAT)
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


def _strings(e: E, r: _Reader, name: str):
    """The cursor's count of byte strings: their count and where the first starts; the cursor moves past them."""
    e.var(f"{name}_count", r.uleb())
    e.var(f"{name}_at", e.p["cur"])
    r.repeat(f"{name}_skip", e.p[f"{name}_count"], r.skip_bytes)


def _listed(e: E, r: _Reader, name: str, at, length):
    """1 when the byte string ``rd[at : at + length]`` is one of the strings ``_strings`` found as ``name``."""
    p = e.p
    e.var(f"{name}_hit", 0)
    e.var(f"{name}_saved", p["cur"])
    e.set("cur", p[f"{name}_at"])

    def each():
        e.var(f"{name}_length", r.uleb())
        e.var(f"{name}_same", e.flag(e.eq(p[f"{name}_length"], length)))
        e.for_(f"{name}_k", 0, e.sel(e.ne(p[f"{name}_same"], 0), length, 0), lambda: e.set(f"{name}_same", e.and_(p[f"{name}_same"], e.flag(
            e.eq(e.rd(e.add(p["cur"], p[f"{name}_k"])), e.rd(e.add(at, p[f"{name}_k"])))))))
        e.set(f"{name}_hit", e.or_(p[f"{name}_hit"], p[f"{name}_same"]))
        e.set("cur", e.add(p["cur"], p[f"{name}_length"]))

    e.for_(f"{name}_each", 0, p[f"{name}_count"], each)
    e.set("cur", p[f"{name}_saved"])
    return p[f"{name}_hit"]


def _trust(e: E, r: _Reader, verify):
    """``_validate_trust`` under a policy requiring package signatures, with ``xax_ed25519.signature_verifier``: in
    CID order, each package needs a signature of it that is trusted (its algorithm and signer accepted, its value
    verified); the trusted signatures must be exactly the snapshot's."""
    p = e.p
    r.at(p["policy"])
    e.set("cur", e.add(p["cur"], 3))  # the form and the two requirement flags
    _strings(e, r, "algorithms")
    _strings(e, r, "signers")
    e.for_("tz", 0, p["signatures"], lambda: e.st(e.add(TRUST_AT, p["tz"]), 0))
    e.var("pcur", p["packages_at"])

    def package():
        e.set("cur", p["pcur"])
        e.var("root", r.ref("snapshot"))
        e.set("pcur", p["cur"])
        e.var("matched", 0)
        e.var("scur", p["signatures_at"])

        def signature():
            e.set("cur", p["scur"])
            e.var("signature_object", r.ref("snapshot"))
            e.set("scur", p["cur"])
            r.at(p["signature_object"])
            r.uleb()  # the form
            e.var("signed", r.ref("signature_object"))

            def candidate():
                fields = []
                for field in ("algorithm", "signer", "value"):
                    e.var(f"{field}_length", r.uleb())
                    e.var(f"{field}_at", p["cur"])
                    e.set("cur", e.add(p["cur"], p[f"{field}_length"]))
                    fields.append(field)
                e.var("trusted", e.and_(_listed(e, r, "algorithms", p["algorithm_at"], p["algorithm_length"]),
                                        _listed(e, r, "signers", p["signer_at"], p["signer_length"])))
                e.var("ed25519", e.flag(e.eq(p["algorithm_length"], len(ALGORITHM))))
                for k, byte in enumerate(ALGORITHM):
                    e.set("ed25519", e.and_(p["ed25519"], e.flag(e.eq(e.rd(e.add(p["algorithm_at"], k)), byte))))
                e.set("trusted", e.and_(p["trusted"], p["ed25519"]))
                e.set("trusted", e.and_(p["trusted"], e.flag(e.both(e.eq(p["signer_length"], 32), e.eq(p["value_length"], 64)))))

                def verified():
                    e.for_("vk", 0, 32, lambda: e.st(e.add(ED.PK_AT, p["vk"]), e.rd(e.add(p["signer_at"], p["vk"]))))
                    e.for_("vs", 0, 64, lambda: e.st(e.add(ED.SIG_AT, p["vs"]), e.rd(e.add(p["value_at"], p["vs"]))))
                    for k, byte in enumerate(DOMAIN):
                        e.st(ED.MSG_AT + k, byte)
                    for word in range(4):
                        e.var(f"root_word{word}", _cid_word(e, p["root"], word))
                        for k in range(8):
                            e.st(ED.MSG_AT + len(DOMAIN) + 8 * word + k, e.and_(e.udiv(p[f"root_word{word}"], 1 << (8 * (7 - k))), 255))
                    e.st(ED.MSG_LENGTH, len(DOMAIN) + CID_SIZE)
                    e.set("trusted", e.call(verify))

                e.if_(e.ne(p["trusted"], 0), verified)

                def accepted():
                    e.set("matched", 1)
                    e.st(e.add(TRUST_AT, p["sq"]), 1)

                e.if_(e.ne(p["trusted"], 0), accepted)

            e.if_(e.eq(p["signed"], p["root"]), candidate)

        e.for_("sq", 0, p["signatures"], signature)
        e.if_(e.eq(p["matched"], 0), lambda: _reject(
            e, "XAX.TRUST.REQUIRED", lambda: _cid(e, p["root"]), "TRUST-SIGNATURE-REQUIRED",
            lambda: D.text(e, "accepted valid signature"), lambda: D.text(e, "missing")))

    e.var("pk", 0)
    e.while_(lambda: e.both(e.lt(p["pk"], p["packages"]), e.eq(p["outcome"], ACCEPT)), lambda: (package(), e.set("pk", e.add(p["pk"], 1))))
    e.var("unaccepted", 0)
    e.for_("tu", 0, p["signatures"], lambda: e.set("unaccepted", e.add(p["unaccepted"], e.flag(e.eq(e.ld(e.add(TRUST_AT, p["tu"])), 0)))))

    def listed(only_accepted: bool):
        def write():
            D.put(e, D.T_LIST)
            D.put(e, e.sub(p["signatures"], p["unaccepted"]) if only_accepted else p["signatures"])
            e.set("cur", p["signatures_at"])

            def each():
                e.var("listed_signature", r.ref("snapshot"))
                if only_accepted:
                    e.if_(e.ne(e.ld(e.add(TRUST_AT, p["lq"])), 0), lambda: _cid(e, p["listed_signature"]))
                else:
                    _cid(e, p["listed_signature"])

            e.for_("lq", 0, p["signatures"], each)
        return write

    e.if_(e.both(e.eq(p["outcome"], ACCEPT), e.ne(p["unaccepted"], 0)), lambda: _reject(
        e, "XAX.TRUST.SNAPSHOT", lambda: D.text(e, "snapshot"), "TRUST-SNAPSHOT-SIGNATURES", listed(False), listed(True)))


def _build_request(tables, verify):
    def build(e: E):
        p = e.p
        r = _Reader(e)
        e.var("outcome", ACCEPT)
        e.var("request", 0)
        e.var("snapshot", e.rd(1))
        _set(e, B_SNAPSHOT, p["snapshot"])
        _set(e, B_ARTIFACT, 0)
        _set(e, B_DYNAMIC, 0)
        _set(e, B_PATH, PATH_LINUX_X86_64)
        _set(e, B_DLL, 0)
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
            e.var("packages_at", p["cur"])
            r.repeat("sp", p["packages"], r.uleb)
            e.var("signatures", r.uleb())
            e.var("signatures_at", p["cur"])
            r.repeat("ss", p["signatures"], r.uleb)
            e.var("digests", r.uleb())
            e.var("digests_at", p["cur"])

            def digests():
                D.put(e, D.T_LIST)
                D.put(e, p["digests"])

                def digest():
                    D.put(e, D.T_HEX)
                    D.put(e, CID_SIZE)
                    for word in range(CID_SIZE // 8):
                        value = e.c(0)
                        for k in reversed(range(8)):
                            value = e.add(e.mul(value, 256), e.rd(e.add(p["digests_at"], e.add(e.mul(p["sd"], CID_SIZE), 8 * word + k))))
                        D.put(e, value)

                e.for_("sd", 0, p["digests"], digest)

            # ``_validate_external_inputs`` (S15c.2): the digests of the input files the driver was given (``INPUTS_AT``,
            # sorted, each once) are the snapshot's.
            e.var("given", _ctrl(e, B_INPUTS))
            e.var("inputs_same", e.flag(e.eq(p["given"], p["digests"])))
            e.for_("ic", 0, e.sel(e.ne(p["inputs_same"], 0), e.mul(p["digests"], CID_SIZE), 0), lambda: e.set("inputs_same", e.and_(
                p["inputs_same"], e.flag(e.eq(e.ld(e.add(INPUTS_AT, p["ic"])), e.rd(e.add(p["digests_at"], p["ic"])))))))

            def given():
                D.put(e, D.T_LIST)
                D.put(e, p["given"])

                def digest():
                    D.put(e, D.T_HEX)
                    D.put(e, CID_SIZE)
                    for word in range(CID_SIZE // 8):
                        value = e.c(0)
                        for k in reversed(range(8)):
                            value = e.add(e.mul(value, 256), e.ld(e.add(INPUTS_AT, e.add(e.mul(p["gd"], CID_SIZE), 8 * word + k))))
                        D.put(e, value)

                e.for_("gd", 0, p["given"], digest)

            e.if_(e.eq(p["inputs_same"], 0), lambda: _reject(
                e, "XAX.BUILD.INPUT_CLOSURE", lambda: D.text(e, "external-inputs"), "BUILD-EXTERNAL-COMPLETE", digests, given))

            # ``_validate_trust`` with the driver's verifier (S15c.3, ``xax_ed25519.signature_verifier``).
            def trust():
                r.at(p["policy"])
                e.if_(e.ne(r.byte(1), 0), lambda: _trust(e, r, verify))

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

            # ``build``'s own paths come first; the Linux x86-64 profiles are ``_hosted_container``'s.  S15e.3b: a Windows DLL
            # on the PE profile is the general program's (decided below, with the target's fields).
            e.var("first_kind", e.rd(p["artifacts_at"]))  # artifact kinds are one ULEB byte
            e.var("dll", e.flag(e.both(e.eq(p["artifacts"], 1), e.eq(p["first_kind"], int(ArtifactKind.WINDOWS_DLL)))))
            e.if_(e.both(e.eq(p["artifacts"], 1), e.eq(p["dll"], 0), e.either(*(e.eq(p["first_kind"], int(kind)) for kind in BOOTSTRAP_ARTIFACTS))),
                  lambda: e.set("outcome", DECLINE))
            r.at(_ctrl(e, B_TARGET))
            e.var("hosted", 0)
            e.var("path", PATH_LINUX_X86_64)
            e.var("profile", len(HOSTED_PROFILES))
            for index, (identity, path, dynamic, _architecture, _formats) in enumerate(HOSTED_PROFILES):
                def same(index=index, identity=identity, path=path, dynamic=dynamic):
                    e.var("matched", 1)
                    for k, byte in enumerate(identity):
                        e.set("matched", e.and_(p["matched"], e.flag(e.eq(r.byte(1 + k), byte))))

                    def found():
                        e.set("hosted", 1)
                        e.set("path", path)
                        _set(e, B_DYNAMIC, dynamic)
                        e.set("profile", index)

                    e.if_(e.ne(p["matched"], 0), found)

                e.if_(e.eq(r.byte(), len(identity)), same)
            # The target's native fields (``decode_native_target``'s order).  S15e.1 (ADR-308): a RISC-V raw image target
            # (architecture 6, format 1) has no container: ``build`` checks the requested artifacts before lowering,
            # against a native image or an Android package.  S15e.2: a hosted profile's identity with other fields declines.
            e.var("riscv", 0)
            e.var("accel", 0)
            e.var("architecture", NONE_FIELD)
            e.var("image_format", NONE_FIELD)
            e.var("target_end", e.add(_body(e, _ctrl(e, B_TARGET))[1], _body(e, _ctrl(e, B_TARGET))[0]))
            r.at(_ctrl(e, B_TARGET))
            r.skip_bytes()  # the identity

            def fields():
                r.uleb()  # the profile
                e.set("architecture", r.uleb())
                r.uleb()  # the ABI
                e.set("image_format", r.uleb())
                e.set("riscv", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], RISCV64_ARCHITECTURE),
                                             e.eq(p["image_format"], RISCV64_RAW_FORMAT))))
                e.set("accel", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], ACCELERATOR_ARCHITECTURE),
                                             e.eq(p["image_format"], ACCELERATOR_FORMAT))))

            e.if_(e.lt(p["cur"], p["target_end"]), fields)
            for index, (_identity, _path, _dynamic, architecture, formats) in enumerate(HOSTED_PROFILES):
                if architecture is not None:
                    listed = (e.either(*(e.eq(p["image_format"], value) for value in formats)) if formats is not None
                              else e.not_(e.either(*(e.eq(p["image_format"], value) for value in LINUX_X86_64_FORMATS))))
                    fits = e.both(e.eq(p["architecture"], architecture), listed)
                    e.if_(e.both(e.eq(p["profile"], index), e.not_(fits)), lambda: e.set("hosted", 0))
            e.if_(e.ne(p["riscv"], 0), lambda: e.set("path", PATH_RISCV64_RAW))
            e.if_(e.ne(p["accel"], 0), lambda: e.set("path", PATH_ACCELERATOR))
            _set(e, B_PATH, p["path"])
            e.if_(e.both(e.eq(p["hosted"], 0), e.eq(p["riscv"], 0), e.eq(p["accel"], 0)), lambda: e.set("outcome", DECLINE))

            def dll():
                """``_build_windows_dll`` (S15e.3b): only on the PE profile (architecture 1, ``x86_64-windows-pe-v1``); any
                other target's ``WINDOWS-DLL-TARGET`` is ``build``'s.  The general program is given the request."""
                pe = e.both(e.ne(p["hosted"], 0), e.eq(p["path"], PATH_WINDOWS_PE))
                e.if_(pe, lambda: (_set(e, B_DLL, 1), _set(e, B_ENTRY, p["request"])), lambda: e.set("outcome", DECLINE))

            e.if_(e.ne(p["dll"], 0), dll)

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

            def riscv_artifacts():
                """``build``'s last branch, before lowering: the expected artifact (a native image; S15e.7a an
                accelerator deployment), or an Android package."""
                D.begin(e)
                D.text(e, "XAX.BUILD.ARTIFACT")
                _cid(e, p["request"])
                D.text(e, "BUILD-ARTIFACT-SUPPORTED")
                D.put(e, D.T_LIST)
                D.put(e, 3)
                e.if_(e.ne(p["accel"], 0), lambda: D.text(e, ArtifactKind.ACCELERATOR_DEPLOYMENT.name), lambda: D.text(e, ArtifactKind.NATIVE_IMAGE.name))
                for kind in (ArtifactKind.ANDROID_UNSIGNED_APK, ArtifactKind.ANDROID_SIGNED_APK):
                    D.text(e, kind.name)
                D.put(e, D.T_LIST)
                D.put(e, p["artifacts"])
                e.for_("rk", 0, p["artifacts"], lambda: (e.var("kind_value", e.rd(e.add(p["artifacts_at"], p["rk"]))),
                                                         _name(e, "kind_value", ARTIFACT_NAMES)))
                e.set("outcome", REJECT)

            native = e.either(e.ne(p["dll"], 0), e.both(e.eq(p["artifacts"], 1), e.eq(p["accel"], 0), e.eq(p["first_kind"], int(ArtifactKind.NATIVE_IMAGE))),
                              e.both(e.eq(p["artifacts"], 1), e.ne(p["accel"], 0), e.eq(p["first_kind"], int(ArtifactKind.ACCELERATOR_DEPLOYMENT))))
            e.if_(e.both(running(), e.not_(native)), lambda: e.if_(e.either(e.ne(p["riscv"], 0), e.ne(p["accel"], 0)), riscv_artifacts, artifacts))

        when(request)
        _set(e, B_STATUS, p["outcome"])
        e.give(p["outcome"])
    return _function((), build, tables)


def _provenance(tables):
    def build(e: E):
        p = e.p
        for k, byte in enumerate(TEMPLATE):
            e.st(ENVELOPE_AT + k, byte)
        # The template holds the first profile's lowering identity; each other path writes its own.
        def lowering(identity: bytes):
            assert len(identity) == CID_SIZE
            for k, byte in enumerate(identity):
                e.st(ENVELOPE_AT + P_LOWERING + k, byte)

        for identity, path, dynamic, _architecture, _formats in HOSTED_PROFILES[1:]:
            e.if_(e.both(e.eq(_ctrl(e, B_PATH), path), e.eq(_ctrl(e, B_DYNAMIC), dynamic)),
                  lambda identity=identity: lowering(container_lowering_identity(identity)))
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_RISCV64_RAW), lambda: lowering(RISCV64_LOWERING_IDENTITY_V1))
        e.if_(e.ne(_ctrl(e, B_DLL), 0), lambda: lowering(container_lowering_identity(DLL_LOWERING)))  # S15e.3b
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_ACCELERATOR), lambda: lowering(ACCELERATOR_LOWERING_IDENTITY_V1))  # S15e.7a
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
    ed_functions, ed_objects = ED.build_functions()
    objects.extend(ed_objects)
    for name, builder in (("build_request", lambda tables: _build_request(tables, ed_functions["verify"])), ("provenance", _provenance)):
        function, items = builder(None)
        functions[name] = function
        objects.extend(items)
    return functions, tuple(objects)
