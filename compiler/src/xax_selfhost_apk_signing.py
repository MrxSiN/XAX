"""S15e.6b (ADR-336): APK Signature Scheme v2 (``xax_apk_signing.sign_apk_v2``) as an XAX program.

The deterministic RSA PKCS#1 v1.5 + SHA-256 signature (algorithm 0x0103) over an unsigned, non-ZIP64 APK: the end of
central directory located (as ``_locate_eocd``), the certificate's SubjectPublicKeyInfo taken from its DER (as
``extract_certificate_spki``), the chunked content digest over the entries, the central directory and the end record
(1 MiB chunks, each ``0xA5 || len || chunk`` hashed, then ``0x5A || count || digests``), the signed data, its SHA-256
in a DigestInfo padded to the key size and raised to the private exponent modulo the modulus, the signer, the signing
block, and the signed APK with the end record's central-directory offset moved past the block.

SHA-256 runs over a byte feed (``sx_byte``) into a 64-byte block; the RSA arithmetic uses 32-bit limbs in 64-bit words
(the products fit a word) with Montgomery multiplication.  Anything the bootstrap rejects with a ``ValueError`` (no
end record, multi-disk, a malformed certificate, a key too small) declines here, so ``sign_apk_v2`` raises as before.

Input (64-bit words): the APK's byte count and its bytes packed eight to a word, then the modulus, the private exponent
and the certificate, each a byte count and its bytes one per word (the integers big endian, as the capability encodes
them).  Output: the status (1) and the image record ``[1, 0, length, bytes packed eight to a word]`` at ``IMAGE_AT``.
"""

from __future__ import annotations

import hashlib

from xax_native import bootstrap_dir
from xax_selfhost_facts import E
from xax_selfhost_general_image import IMAGE_AT
from xax_selfhost_views_backend import NativeProgram, _call

STORE_PATH = bootstrap_dir() / "xax_apk_signer.xax"
OUT = IMAGE_AT + 3
MASK32 = 0xFFFFFFFF
V2_BLOCK_ID, ALGORITHM_ID, MAGIC = 0x7109871A, 0x0103, b"APK Sig Block 42"
# S15e.6i.1 (ADR-357): the transport mode, ``build``'s signing of an Android package.  Input word 0 is ``TRANSPORT_MARK``;
# then the APK (its byte count and its bytes packed eight to a word, or ``FROM_IMAGE``: the image record a program wrote
# before, at ``IMAGE_AT`` of the output view), the effect flag (1: one SIGN effect), the SIGN capability's scope (its
# length, then its bytes one per word), the package's logical identity (likewise) and the private signing transport
# (``xax_apk_signing.encode_private_signing_capability``, likewise).  The program makes ``build``'s signing rejections in
# its order (``ANDROID-APK-SIGNING-CAPABILITY`` without the effect, ``ANDROID-APK-SIGNER-IDENTITY`` for a scope that is
# no SHA-256, ``ANDROID-APK-SIGNING-CAPABILITY`` where ``decode_private_signing_capability`` raises,
# ``ANDROID-APK-SIGNER-IDENTITY`` for another certificate), each with its diagnostic; otherwise it signs.
TRANSPORT_MARK, FROM_IMAGE = 1 << 40, 1 << 41


# -- SHA-256 ------------------------------------------------------------------------------------------------------------


# -- the output -------------------------------------------------------------------------------------------------------------


def put(e: E, byte):
    _call(e, "sx_put", byte)


# -- bytes in the arena (one per word) --------------------------------------------------------------------------------------


# -- DER: the certificate's SubjectPublicKeyInfo ------------------------------------------------------------------------------


# -- S15e.6i.1 (ADR-357): the private signing transport --------------------------------------------------------------------


# -- RSA: Montgomery arithmetic over 32-bit limbs ----------------------------------------------------------------------------


# -- the program ----------------------------------------------------------------------------------------------------------


_PROGRAM = NativeProgram(STORE_PATH, "apk-signer")
OPT_OUT = "XAX_APK_SIGNER_PYTHON"


def sign_with_xax(unsigned_apk: bytes, capability, *, required: bool = False) -> bytes | None:
    """The signed APK the XAX program writes, or None where it cannot run or declines (unless ``required``)."""
    import os

    import xax_native

    native = None if os.environ.get(OPT_OUT) == "1" else _PROGRAM.native(OPT_OUT)
    data = None
    if native is not None:
        def minimal(value: int) -> bytes:
            return value.to_bytes((value.bit_length() + 7) // 8, "big")

        padded = unsigned_apk + bytes(-len(unsigned_apk) % 8)
        words = [len(unsigned_apk), *(int.from_bytes(padded[k:k + 8], "little") for k in range(0, len(padded), 8))]
        for field in (minimal(capability.modulus), minimal(capability.private_exponent), bytes(capability.certificate_der)):
            words += [len(field), *field]

        def collect(read):
            (status,) = read(0, 1)
            if status != 1:
                return None
            head = read(IMAGE_AT, 3)
            packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
            return b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]]

        data = native.run(words, collect)
        if data is None:
            xax_native.declined("apk-signer", 1)
    if data is None and required:
        raise RuntimeError("the XAX APK signer program is unavailable or declined")
    return data


def sign_transport_with_xax(unsigned_apk: bytes, transport: bytes, scope: bytes, identity: bytes, *, effect: bool = True):
    """S15e.6i.1 (ADR-357): the transport mode with the APK in its input: ``("signed", apk)``, ``("rejected",
    diagnostic)`` (``build``'s signing rejection for the package ``identity``), or None where the program cannot run or
    declines."""
    from xax_selfhost_diagnostics import decode_diagnostic

    native = _PROGRAM.native(OPT_OUT)
    if native is None:
        return None
    padded = unsigned_apk + bytes(-len(unsigned_apk) % 8)
    words = [TRANSPORT_MARK, len(unsigned_apk), *(int.from_bytes(padded[k:k + 8], "little") for k in range(0, len(padded), 8)), int(effect)]
    for field in (scope, identity, transport):
        words += [len(field), *field]

    def collect(read):
        diagnostic = decode_diagnostic(read)
        if diagnostic is not None:
            return ("rejected", diagnostic)
        (status,) = read(0, 1)
        if status != 1:
            return None
        head = read(IMAGE_AT, 3)
        packed = read(IMAGE_AT + 3, (head[2] + 7) // 8)
        return ("signed", b"".join(word.to_bytes(8, "little") for word in packed)[:head[2]])

    return native.run(words, collect)


del hashlib
