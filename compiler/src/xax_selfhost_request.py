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
  target, and declines ``build``'s other paths: Android packages on other targets, Windows
  DLLs off the PE profile, and targets other than the Linux x86-64 ELF profiles, (S15e.1, ADR-308) the RISC-V raw image
  profiles, whose requested artifacts it checks at once, (S15e.2, ADR-315) the Linux AArch64 ELF profiles and (S15e.6h.3,
  ADR-356) an APK on an Android shared-object target, whose package's modules it records.  S15e.6i.1 (ADR-357): under
  ``build-signed`` it checks the one SIGN effect as ``validate_build_effects`` does (``_effect``), and for a signed APK it lays
  out the APK signer's input (``_signer_input``): the signer, chained after the Android program, makes ``build``'s
  signing rejections.  The target's path is ``B_PATH`` (``PATH_*``): the program
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
from xax_artifact import (AARCH64_LOWERING_IDENTITY_V1, ACCELERATOR_LOWERING_IDENTITY_V1, ANDROID_SIGNED_APK_LOWERING_IDENTITY_V1, ANDROID_UNSIGNED_APK_LOWERING_IDENTITY_V1, JVM_LOWERING_IDENTITY_V1, RISCV64_LOWERING_IDENTITY_V1, WASM_LOWERING_IDENTITY_V1, X86_64_LOWERING_IDENTITY_V1, XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1,
                          container_lowering_identity)
from xax_build import ArtifactKind, BuildForm
from xax_compiler import (
    AARCH64_LINUX_ELF_DYNAMIC_FORMAT, AARCH64_LINUX_ELF_EXEC_FORMAT, AARCH64_LINUX_IDENTITIES, CID_SIZE, RISCV64_ARCHITECTURE,
    RISCV64_RAW_FORMAT, SPIRV_ARCHITECTURE, SPIRV_MODULE_FORMAT, SPIRV_VULKAN_COMPUTE_IDENTITY, WASM32_BROWSER_IDENTITY, X86_64_LINUX_ELF_DYNAMIC_FORMAT,
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
# S15e.4 (ADR-322): the browser page profile, a hosted container, made by the general program.
PATH_WASM_PAGE = 6
# S15f.1 (ADR-324): a raw Wasm module (architecture 2, image format 2, not the browser page), made by the general program.
PATH_WASM_RAW = 7
WASM_ARCHITECTURE, WASM_FORMAT = 2, 2
# S15f.2 (ADR-324): a Windows load image (architecture 1, image format 1, not the PE profile), made by the general program.
PATH_X86_RAW = 8
X86_ARCHITECTURE, X86_RAW_FORMAT = 1, 1
# S15f.4 (ADR-325): a bare-metal AArch64 load image (architecture 3, the bare-metal ABI 3, image format 1), made by the
# AArch64 program.
PATH_A64_RAW = 9
A64_ARCHITECTURE, A64_BAREMETAL_ABI, A64_RAW_FORMAT = 3, 3, 1
# S15e.5 (ADR-334): a JVM JAR (architecture 5, ``build``'s branch after the hosted containers), made by the JVM program.
PATH_JVM = 10
JVM_ARCHITECTURE, JVM_FORMAT = 5, 1
# 1 when the JVM request asks for an executable JAR (``main``; the entry is a process entry).
B_JVMEXE = 47
# S15e.6h.3 (ADR-356): an unsigned APK on an Android AArch64 shared-object target (architecture 3, ABI 4, image format 4
# or 5), made by the Android program; ``B_NMOD`` and ``B_MODS``: the package's modules (object indices, in order).
PATH_ANDROID = 11
ANDROID_ARCHITECTURE, ANDROID_ABI, ANDROID_FORMATS = 3, 4, (4, 5)
B_NMOD, B_MODS, MAX_MODULES = 48, 49, 14
B_PACKAGE = 63  # the package's object index (its logical identity is the Android program's diagnostic entity)
# S15e.6i.1 (ADR-357): the signing state (workspace words).  ``build-signed`` passes one SIGN effect: the package's only
# SIGN capability with the transport file's bytes as its value (``SG_EFFECT`` 1, the transport's BLAKE3 digest at
# ``SG_DIGEST``, its bytes one per word at ``TRANSPORT_AT``).  ``build_request`` checks it as ``validate_build_effects``
# does and, for a signed APK, lays out the APK signer's transport-mode input (``xax_selfhost_apk_signing``: the effect,
# the scope, the package's identity, the transport) at ``SIGNER_AT`` (``SIGNER_N`` words), which the driver copies to the
# signer after the Android program; the signer makes ``build``'s signing rejections.
SIGN_AT = 50 << 20
SG_EFFECT, SG_SIGNED, SG_TN, SIGNER_N = (SIGN_AT + k for k in range(4))
SG_DIGEST = SIGN_AT + 8
TRANSPORT_AT, TRANSPORT_LIMIT = SIGN_AT + 1024, 1 << 16
SIGNER_AT = SIGN_AT + (1 << 18)
# S15e.6i.2b (ADR-358): the external inputs' bytes, kept by the driver as it hashes them, for the Android program's
# libxposed JVM profile: ``INPUT_BYTES_N`` records, each the digest (32 bytes, a byte a word), the length and the bytes
# packed eight to a word, from ``INPUT_BYTES_AT`` (``INPUT_BYTES_END``: past the last).
INPUT_BYTES_N, INPUT_BYTES_END = SIGN_AT + 4, SIGN_AT + 5
INPUT_BYTES_AT, INPUT_BYTES_LIMIT = 170 << 20, 64 << 20
SIGN_KIND = 7  # ``BuildCapabilityKind.SIGN``
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
    (WASM32_BROWSER_IDENTITY, PATH_WASM_PAGE, 0, 2, (2,)),  # S15e.4
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


def _hex(e: E, at, n, name: str):
    """A hex value (``bytes.hex()``) of the ``n`` input bytes at ``at`` (one per word)."""
    p = e.p
    D.put(e, D.T_HEX)
    D.put(e, n)

    def word():
        e.var(f"{name}_w", 0)
        for k in reversed(range(8)):
            e.var(f"{name}_i", e.add(e.mul(p[f"{name}_q"], 8), k))
            e.set(f"{name}_w", e.add(e.mul(p[f"{name}_w"], 256), e.sel(e.lt(p[f"{name}_i"], n), e.rd(e.add(at, e.sel(e.lt(p[f"{name}_i"], n), p[f"{name}_i"], 0))), 0)))
        D.put(e, p[f"{name}_w"])

    e.for_(f"{name}_q", 0, e.udiv(e.add(n, 7), 8), word)


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


def _stop(e: E):
    """``build_request``'s outcome, now (its status word, then the result)."""
    _set(e, B_STATUS, e.p["outcome"])
    e.give(e.p["outcome"])


def _signer_input(e: E, r: _Reader):
    """S15e.6i.1 (ADR-357): the APK signer's transport-mode input at ``SIGNER_AT``: the mark, the APK from the image record,
    the effect flag, the SIGN scope, the package's identity and the transport (each its length, then a byte a word)."""
    p = e.p
    import xax_selfhost_apk_signing as SGN

    e.var("si_saved", p["cur"])
    e.var("si_at", SIGNER_AT)

    def word(value):
        e.st(p["si_at"], value)
        e.set("si_at", e.add(p["si_at"], 1))

    def string(n, byte, name):
        word(n)
        e.for_(name, 0, n, lambda: word(byte(p[name])))

    word(SGN.TRANSPORT_MARK)
    word(SGN.FROM_IMAGE)
    word(e.ld(SG_EFFECT))
    string(p["scope_n"], lambda k: e.rd(e.add(p["scope_at"], k)), "si_s")
    r.at(_ctrl(e, B_PACKAGE))
    e.var("si_lid_n", r.uleb())
    string(p["si_lid_n"], lambda k: e.rd(e.add(p["cur"], k)), "si_l")
    e.var("si_tn", e.sel(e.ne(e.ld(SG_EFFECT), 0), e.ld(SG_TN), 0))
    string(p["si_tn"], lambda k: e.ld(e.add(TRANSPORT_AT, k)), "si_t")
    e.st(SIGNER_N, e.sub(p["si_at"], SIGNER_AT))
    e.set("cur", p["si_saved"])


def _effect(e: E, r: _Reader):
    """S15e.6i.1 (ADR-357): ``validate_build_effects`` for ``build-signed``'s one SIGN effect (the package's identity,
    its only SIGN capability, the transport): the profile grants it and every snapshot package of that identity declares
    it (``BUILD-CAPABILITY-ISOLATED``); a hermetic reproducible profile declares the transport's digest among the
    external inputs (``BUILD-SIGNING-MATERIAL-DECLARED``).  Not one SIGN capability, or another snapshot package of the
    identity: declined."""
    p = e.p
    e.if_(e.ne(p["signs"], 1), lambda: e.set("outcome", DECLINE))
    e.if_(e.ne(p["outcome"], ACCEPT), lambda: _stop(e))
    e.var("ef_saved", p["cur"])
    r.at(_ctrl(e, B_PACKAGE))
    e.var("lid_n", r.uleb())
    e.var("lid_at", p["cur"])

    def same_identity(at, n, name):
        e.var(name, e.flag(e.eq(n, p["lid_n"])))
        e.for_(f"{name}_k", 0, e.sel(e.ne(p[name], 0), n, 0), lambda: e.set(name, e.and_(p[name], e.flag(
            e.eq(e.rd(e.add(at, p[f"{name}_k"])), e.rd(e.add(p["lid_at"], p[f"{name}_k"])))))))
        return p[name]

    def same_scope(at, n, name):
        e.var(name, e.flag(e.eq(n, p["scope_n"])))
        e.for_(f"{name}_k", 0, e.sel(e.ne(p[name], 0), n, 0), lambda: e.set(name, e.and_(p[name], e.flag(
            e.eq(e.rd(e.add(at, p[f"{name}_k"])), e.rd(e.add(p["scope_at"], p[f"{name}_k"])))))))
        return p[name]

    # The profile's grants.
    r.at(_ctrl(e, B_PROFILE))
    r.uleb()  # the form
    e.var("ef_mode", r.uleb())
    r.uleb()
    r.uleb()
    e.var("granted", 0)

    def grant():
        e.var("gi_n", r.uleb())
        e.var("gi_at", p["cur"])
        e.set("cur", e.add(p["cur"], p["gi_n"]))
        e.var("gk", r.uleb())
        e.var("gs_n", r.uleb())
        e.var("gs_at", p["cur"])
        e.set("cur", e.add(p["cur"], p["gs_n"]))
        e.var("g_hit", e.and_(same_identity(p["gi_at"], p["gi_n"], "g_id"), e.flag(e.eq(p["gk"], SIGN_KIND))))
        e.set("g_hit", e.and_(p["g_hit"], same_scope(p["gs_at"], p["gs_n"], "g_scope")))
        e.set("granted", e.or_(p["granted"], p["g_hit"]))

    r.repeat("eg", r.uleb(), grant)
    # The snapshot's packages of the identity: only the request's package.
    r.at(p["snapshot"])
    r.uleb()  # the form
    r.uleb()  # the request
    r.skip_bytes()  # the resolver identity
    r.uleb()  # the policy
    e.var("ef_packages", r.uleb())
    e.var("same_packages", 0)
    e.var("other_same", 0)

    def snapshot_package():
        e.var("sp_object", r.ref("snapshot"))
        e.var("sp_cur", p["cur"])
        r.at(p["sp_object"])
        e.var("spi_n", r.uleb())
        e.var("sp_same", same_identity(p["cur"], p["spi_n"], "sp_id"))
        e.set("same_packages", e.add(p["same_packages"], p["sp_same"]))
        e.set("other_same", e.or_(p["other_same"], e.and_(p["sp_same"], e.flag(e.ne(p["sp_object"], _ctrl(e, B_PACKAGE))))))
        e.set("cur", p["sp_cur"])

    r.repeat("es", p["ef_packages"], snapshot_package)
    e.if_(e.ne(p["other_same"], 0), lambda: e.set("outcome", DECLINE))
    e.if_(e.ne(p["outcome"], ACCEPT), lambda: _stop(e))

    def lid():
        _hex(e, p["lid_at"], p["lid_n"], "ef_lid")

    e.if_(e.either(e.eq(p["same_packages"], 0), e.eq(p["granted"], 0)), lambda: _reject(
        e, "XAX.BUILD.CAPABILITY", lid, "BUILD-CAPABILITY-ISOLATED", lambda: D.text(e, "declared package-local grant"),
        lambda: (D.put(e, D.T_LIST), D.put(e, 2), D.text(e, "SIGN"), _hex(e, p["scope_at"], p["scope_n"], "ef_scope"))))
    e.if_(e.ne(p["outcome"], ACCEPT), lambda: _stop(e))

    def declared():
        r.at(p["snapshot"])
        r.uleb()
        r.uleb()
        r.skip_bytes()
        r.uleb()
        r.repeat("dz", r.uleb(), r.uleb)
        r.repeat("dy", r.uleb(), r.uleb)
        e.var("ed_digests", r.uleb())
        e.var("ed_at", p["cur"])
        e.var("ed_hit", 0)

        def digest():
            e.var("ed_same", 1)
            e.for_("ed_k", 0, CID_SIZE, lambda: e.set("ed_same", e.and_(p["ed_same"], e.flag(
                e.eq(e.rd(e.add(e.add(p["ed_at"], e.mul(p["ed_q"], CID_SIZE)), p["ed_k"])), e.ld(e.add(SG_DIGEST, p["ed_k"])))))))
            e.set("ed_hit", e.or_(p["ed_hit"], p["ed_same"]))

        e.for_("ed_q", 0, p["ed_digests"], digest)

        def listed():
            D.put(e, D.T_LIST)
            D.put(e, p["ed_digests"])
            e.for_("el", 0, p["ed_digests"], lambda: _hex(e, e.add(p["ed_at"], e.mul(p["el"], CID_SIZE)), CID_SIZE, "el_hex"))

        def actual():
            D.put(e, D.T_HEX)
            D.put(e, CID_SIZE)
            for word in range(CID_SIZE // 8):
                value = e.c(0)
                for k in reversed(range(8)):
                    value = e.add(e.mul(value, 256), e.ld(SG_DIGEST + 8 * word + k))
                D.put(e, value)

        e.if_(e.eq(p["ed_hit"], 0), lambda: _reject(e, "XAX.BUILD.INPUT_CLOSURE", lid, "BUILD-SIGNING-MATERIAL-DECLARED", listed, actual))

    e.if_(e.eq(p["ef_mode"], 1), declared)  # ``BuildMode.HERMETIC_REPRODUCIBLE``
    e.set("cur", p["ef_saved"])


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
            _set(e, B_NMOD, 0)
            _set(e, B_PACKAGE, p["package"])

            def module():
                """S15e.6h.3: the modules' object indices (past ``MAX_MODULES`` only counted: the Android path declines)."""
                e.var("module_ref", r.uleb())
                e.var("nmod", _ctrl(e, B_NMOD))
                e.if_(e.lt(p["nmod"], MAX_MODULES), lambda: e.st(e.add(CTRL + B_MODS, p["nmod"]), _ref(e, p["package"], p["module_ref"])))
                _set(e, B_NMOD, e.add(p["nmod"], 1))

            r.repeat("pm", r.uleb(), module)  # modules
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
            # S15e.6i.1 (ADR-357): the package's SIGN capabilities (their count; the first one's scope).
            for name in ("pf", "pg"):  # feature and configuration schemas
                r.repeat(name, r.uleb(), lambda: (r.skip_bytes(), r.uleb()))
            e.var("signs", 0)
            e.var("scope_n", 0)
            e.var("scope_at", 0)

            def capability():
                e.var("cap_kind", r.uleb())
                e.var("cap_n", r.uleb())
                e.if_(e.both(e.eq(p["cap_kind"], SIGN_KIND), e.eq(p["signs"], 0)), lambda: (e.set("scope_n", p["cap_n"]), e.set("scope_at", p["cur"])))
                e.set("signs", e.add(p["signs"], e.flag(e.eq(p["cap_kind"], SIGN_KIND))))
                e.set("cur", e.add(p["cur"], p["cap_n"]))

            r.repeat("pc", r.uleb(), capability)
            e.if_(e.ne(e.ld(SG_EFFECT), 0), lambda: _effect(e, r))
            e.if_(e.ne(p["outcome"], ACCEPT), lambda: _stop(e))
            e.if_(e.eq(_ctrl(e, B_ENTRY), e.c(-1)), lambda: e.set("outcome", DECLINE))

            # ``build``'s own paths come first; the Linux x86-64 profiles are ``_hosted_container``'s.  S15e.3b: a Windows DLL
            # on the PE profile is the general program's (decided below, with the target's fields).
            e.var("first_kind", e.rd(p["artifacts_at"]))  # artifact kinds are one ULEB byte
            e.var("dll", e.flag(e.both(e.eq(p["artifacts"], 1), e.eq(p["first_kind"], int(ArtifactKind.WINDOWS_DLL)))))
            e.var("apk", e.flag(e.both(e.eq(p["artifacts"], 1), e.either(e.eq(p["first_kind"], int(ArtifactKind.ANDROID_UNSIGNED_APK)),
                                                                           e.eq(p["first_kind"], int(ArtifactKind.ANDROID_SIGNED_APK))))))
            # An APK is decided with the target's fields below (S15e.6h.3); S15e.6i.1: a signed one is then signed.
            e.st(SG_SIGNED, e.flag(e.both(e.eq(p["artifacts"], 1), e.eq(p["first_kind"], int(ArtifactKind.ANDROID_SIGNED_APK)))))
            e.if_(e.ne(e.ld(SG_SIGNED), 0), lambda: _signer_input(e, r))
            e.var("bootstrap_artifact", e.flag(e.both(e.eq(p["artifacts"], 1), e.eq(p["dll"], 0), e.eq(p["apk"], 0),
                                                      e.either(*(e.eq(p["first_kind"], int(kind)) for kind in BOOTSTRAP_ARTIFACTS)))))
            e.if_(e.ne(p["bootstrap_artifact"], 0), lambda: e.set("outcome", DECLINE))
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
            e.var("wasm", 0)  # S15f.1: a raw module, ``build``'s last branch like RISC-V
            e.var("x86raw", 0)  # S15f.2: a Windows load image, likewise
            e.var("a64raw", 0)  # S15f.4: a bare-metal AArch64 image, likewise
            e.var("jvm", 0)  # S15e.5: a JVM JAR (its requested artifacts checked before lowering)
            e.var("abi", NONE_FIELD)
            e.var("accel", 0)
            e.var("architecture", NONE_FIELD)
            e.var("image_format", NONE_FIELD)
            e.var("target_end", e.add(_body(e, _ctrl(e, B_TARGET))[1], _body(e, _ctrl(e, B_TARGET))[0]))
            r.at(_ctrl(e, B_TARGET))
            r.skip_bytes()  # the identity

            def fields():
                r.uleb()  # the profile
                e.set("architecture", r.uleb())
                e.set("abi", r.uleb())
                e.set("image_format", r.uleb())
                e.set("riscv", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], RISCV64_ARCHITECTURE),
                                             e.eq(p["image_format"], RISCV64_RAW_FORMAT))))
                e.set("wasm", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], WASM_ARCHITECTURE),
                                            e.eq(p["image_format"], WASM_FORMAT))))
                e.set("x86raw", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], X86_ARCHITECTURE),
                                              e.eq(p["image_format"], X86_RAW_FORMAT))))
                e.set("a64raw", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], A64_ARCHITECTURE), e.eq(p["abi"], A64_BAREMETAL_ABI),
                                              e.eq(p["image_format"], A64_RAW_FORMAT))))
                e.set("accel", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], ACCELERATOR_ARCHITECTURE),
                                             e.eq(p["image_format"], ACCELERATOR_FORMAT))))
                e.set("jvm", e.flag(e.both(e.eq(p["hosted"], 0), e.eq(p["architecture"], JVM_ARCHITECTURE))))

            e.if_(e.lt(p["cur"], p["target_end"]), fields)
            for index, (_identity, _path, _dynamic, architecture, formats) in enumerate(HOSTED_PROFILES):
                if architecture is not None:
                    listed = (e.either(*(e.eq(p["image_format"], value) for value in formats)) if formats is not None
                              else e.not_(e.either(*(e.eq(p["image_format"], value) for value in LINUX_X86_64_FORMATS))))
                    fits = e.both(e.eq(p["architecture"], architecture), listed)
                    e.if_(e.both(e.eq(p["profile"], index), e.not_(fits)), lambda: e.set("hosted", 0))
            e.if_(e.ne(p["riscv"], 0), lambda: e.set("path", PATH_RISCV64_RAW))
            e.if_(e.ne(p["wasm"], 0), lambda: e.set("path", PATH_WASM_RAW))
            e.if_(e.ne(p["x86raw"], 0), lambda: e.set("path", PATH_X86_RAW))
            e.if_(e.ne(p["a64raw"], 0), lambda: e.set("path", PATH_A64_RAW))
            e.if_(e.ne(p["accel"], 0), lambda: e.set("path", PATH_ACCELERATOR))
            e.if_(e.ne(p["jvm"], 0), lambda: e.set("path", PATH_JVM))
            # Another JVM image format: ``lowering_identity`` has none (the bootstrap's ValueError): declined.
            e.if_(e.both(e.ne(p["jvm"], 0), e.ne(p["image_format"], JVM_FORMAT)), lambda: e.set("outcome", DECLINE))
            # S15e.6h.3 (ADR-356): an unsigned APK on an Android shared-object target, with at most ``MAX_MODULES``
            # modules, is the Android program's; on any other target it is ``build``'s.
            e.var("android", e.flag(e.both(e.ne(p["apk"], 0), e.eq(p["hosted"], 0), e.eq(p["architecture"], ANDROID_ARCHITECTURE),
                                           e.eq(p["abi"], ANDROID_ABI), e.either(*(e.eq(p["image_format"], value) for value in ANDROID_FORMATS)),
                                           e.le(_ctrl(e, B_NMOD), MAX_MODULES))))
            # S15e.6i.2b (ADR-358): an APK on a JVM target is a libxposed JVM module (``build``'s APK branch comes before its
            # JVM branch): the Android program's libxposed JVM profile, given the external inputs' bytes.
            e.if_(e.both(e.ne(p["apk"], 0), e.ne(p["jvm"], 0), e.le(_ctrl(e, B_NMOD), MAX_MODULES)), lambda: (e.set("android", 1), e.set("jvm", 0)))
            e.if_(e.ne(p["android"], 0), lambda: e.set("path", PATH_ANDROID))
            e.if_(e.both(e.ne(p["apk"], 0), e.eq(p["android"], 0)), lambda: e.set("outcome", DECLINE))
            _set(e, B_PATH, p["path"])
            e.if_(e.both(e.eq(p["hosted"], 0), e.eq(p["riscv"], 0), e.eq(p["wasm"], 0), e.eq(p["x86raw"], 0), e.eq(p["a64raw"], 0), e.eq(p["accel"], 0),
                         e.eq(p["jvm"], 0), e.eq(p["android"], 0)),
                  lambda: e.set("outcome", DECLINE))

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

            def jvm_artifacts():
                """``build``'s JVM branch, before compiling: exactly one library or executable JAR."""
                D.begin(e)
                D.text(e, "XAX.BUILD.ARTIFACT")
                _cid(e, p["request"])
                D.text(e, "BUILD-ARTIFACT-SUPPORTED")
                D.put(e, D.T_LIST)
                D.put(e, 2)
                for kind in (ArtifactKind.JVM_LIBRARY_JAR, ArtifactKind.JVM_EXECUTABLE_JAR):
                    D.text(e, kind.name)
                D.put(e, D.T_LIST)
                D.put(e, p["artifacts"])
                e.for_("jk", 0, p["artifacts"], lambda: (e.var("kind_value", e.rd(e.add(p["artifacts_at"], p["jk"]))),
                                                         _name(e, "kind_value", ARTIFACT_NAMES)))
                e.set("outcome", REJECT)

            jar = e.both(e.eq(p["artifacts"], 1), e.either(e.eq(p["first_kind"], int(ArtifactKind.JVM_LIBRARY_JAR)),
                                                            e.eq(p["first_kind"], int(ArtifactKind.JVM_EXECUTABLE_JAR))))
            _set(e, B_JVMEXE, e.flag(e.both(e.eq(p["artifacts"], 1), e.eq(p["first_kind"], int(ArtifactKind.JVM_EXECUTABLE_JAR)))))
            e.if_(e.both(running(), e.ne(p["jvm"], 0), e.not_(jar)), jvm_artifacts)
            native = e.either(e.ne(p["jvm"], 0), e.ne(p["dll"], 0), e.ne(p["android"], 0), e.both(e.eq(p["artifacts"], 1), e.eq(p["accel"], 0), e.eq(p["first_kind"], int(ArtifactKind.NATIVE_IMAGE))),
                              e.both(e.eq(p["artifacts"], 1), e.ne(p["accel"], 0), e.eq(p["first_kind"], int(ArtifactKind.ACCELERATOR_DEPLOYMENT))))
            e.if_(e.both(running(), e.not_(native)), lambda: e.if_(e.either(e.ne(p["riscv"], 0), e.ne(p["wasm"], 0), e.ne(p["x86raw"], 0), e.ne(p["a64raw"], 0), e.ne(p["accel"], 0)), riscv_artifacts,
                                                                       artifacts))

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
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_WASM_RAW), lambda: lowering(WASM_LOWERING_IDENTITY_V1))  # S15f.1
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_X86_RAW), lambda: lowering(X86_64_LOWERING_IDENTITY_V1))  # S15f.2
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_A64_RAW), lambda: lowering(AARCH64_LOWERING_IDENTITY_V1))  # S15f.4
        e.if_(e.ne(_ctrl(e, B_DLL), 0), lambda: lowering(container_lowering_identity(DLL_LOWERING)))  # S15e.3b
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_ACCELERATOR), lambda: lowering(ACCELERATOR_LOWERING_IDENTITY_V1))  # S15e.7a
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_JVM), lambda: lowering(JVM_LOWERING_IDENTITY_V1))  # S15e.5
        e.if_(e.eq(_ctrl(e, B_PATH), PATH_ANDROID), lambda: e.if_(e.ne(e.ld(SG_SIGNED), 0), lambda: lowering(ANDROID_SIGNED_APK_LOWERING_IDENTITY_V1),
                                                                   lambda: lowering(ANDROID_UNSIGNED_APK_LOWERING_IDENTITY_V1)))  # S15e.6h.3, S15e.6i.1
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
