"""Direct deterministic Android APK Signature Scheme v2 signing.

The signing key is supplied as an explicit build capability.  The private
exponent is never serialized into XAX semantic objects or evidence.  This
module implements the deterministic RSA PKCS#1 v1.5 + SHA-256 v2 path directly;
it does not shell out to apksigner/openssl or depend on a signing runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import struct
from typing import Iterable


APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871A
RSA_PKCS1_V1_5_SHA256_ID = 0x0103
CHUNK_SIZE = 1 << 20
EOCD_SIGNATURE = 0x06054B50
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
PRIVATE_SIGNING_CAPABILITY_MAGIC = b"XAX-APK-RSA-CAP-1"


@dataclass(frozen=True)
class RsaSigningCapability:
    """Narrow explicit build capability for one APK signing identity.

    ``private_exponent`` is intentionally excluded from repr.  The certificate
    is public identity material and must contain the same RSA public key.
    """

    modulus: int
    public_exponent: int
    private_exponent: int = field(repr=False)
    certificate_der: bytes

    def __post_init__(self) -> None:
        if self.modulus.bit_length() < 1024 or self.modulus.bit_length() % 8:
            raise ValueError("APK v2 RSA modulus must be at least 1024 bits and byte-aligned")
        if self.public_exponent < 3 or self.public_exponent % 2 == 0:
            raise ValueError("invalid RSA public exponent")
        if not 1 < self.private_exponent < self.modulus:
            raise ValueError("invalid RSA private exponent")
        spki = extract_certificate_spki(self.certificate_der)
        cert_n, cert_e = parse_rsa_spki(spki)
        if (cert_n, cert_e) != (self.modulus, self.public_exponent):
            raise ValueError("APK signing certificate public key does not match signing capability")

    @property
    def key_size_bytes(self) -> int:
        return (self.modulus.bit_length() + 7) // 8

    @property
    def public_key_spki_der(self) -> bytes:
        return extract_certificate_spki(self.certificate_der)

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(self.certificate_der).hexdigest()


def _minimal_uint_bytes(value: int) -> bytes:
    if value <= 0:
        raise ValueError("signing capability integer must be positive")
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def encode_private_signing_capability(capability: RsaSigningCapability) -> bytes:
    """Encode ephemeral signing capability transport bytes.

    These bytes are for the explicit build-effect channel only. They are never
    semantic source, provenance, cache identity, or diagnostic payload.
    """

    fields = (
        _minimal_uint_bytes(capability.modulus),
        _minimal_uint_bytes(capability.public_exponent),
        _minimal_uint_bytes(capability.private_exponent),
        bytes(capability.certificate_der),
    )
    return PRIVATE_SIGNING_CAPABILITY_MAGIC + b"".join(_lp32(field) for field in fields)


def decode_private_signing_capability(data: bytes) -> RsaSigningCapability:
    data = bytes(data)
    if not data.startswith(PRIVATE_SIGNING_CAPABILITY_MAGIC):
        raise ValueError("invalid private signing capability transport")
    cursor = len(PRIVATE_SIGNING_CAPABILITY_MAGIC)
    fields = []
    for _ in range(4):
        field, cursor = _read_lp32(data, cursor, len(data))
        if not field:
            raise ValueError("empty private signing capability field")
        fields.append(field)
    if cursor != len(data):
        raise ValueError("trailing private signing capability bytes")
    return RsaSigningCapability(
        int.from_bytes(fields[0], "big"),
        int.from_bytes(fields[1], "big"),
        int.from_bytes(fields[2], "big"),
        fields[3],
    )


@dataclass(frozen=True)
class ApkV2Inspection:
    file_size: int
    signing_block_offset: int
    signing_block_size: int
    central_directory_offset: int
    central_directory_size: int
    certificate_sha256: str
    signature_algorithm_id: int
    content_digest_sha256: str
    signature_valid: bool
    content_digest_valid: bool
    certificate_key_matches: bool


@dataclass(frozen=True)
class _Eocd:
    offset: int
    central_offset: int
    central_size: int
    comment_length: int


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _lp32(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("APK v2 length-prefixed field exceeds uint32")
    return _u32(len(payload)) + payload


def _lp32_sequence(items: Iterable[bytes]) -> bytes:
    return _lp32(b"".join(_lp32(item) for item in items))


def _read_lp32(data: bytes, offset: int, end: int) -> tuple[bytes, int]:
    if offset + 4 > end:
        raise ValueError("truncated APK v2 length-prefixed field")
    size = struct.unpack_from("<I", data, offset)[0]
    start = offset + 4
    stop = start + size
    if stop > end:
        raise ValueError("APK v2 length-prefixed field exceeds container")
    return data[start:stop], stop


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise ValueError("unsupported DER length")
    if data[offset] == 0:
        raise ValueError("non-canonical DER length")
    size = int.from_bytes(data[offset:offset + count], "big")
    if size < 0x80:
        raise ValueError("non-canonical DER long length")
    return size, offset + count


def _read_der_tlv(data: bytes, offset: int, limit: int | None = None) -> tuple[int, int, int, int]:
    if limit is None:
        limit = len(data)
    if offset >= limit:
        raise ValueError("truncated DER object")
    tag = data[offset]
    size, content = _read_der_length(data, offset + 1)
    end = content + size
    if end > limit:
        raise ValueError("DER object exceeds container")
    return tag, content, end, end


def _der_child_ranges(data: bytes, content: int, end: int) -> tuple[tuple[int, int, int], ...]:
    children: list[tuple[int, int, int]] = []
    cursor = content
    while cursor < end:
        tag, _child_content, child_end, _ = _read_der_tlv(data, cursor, end)
        children.append((tag, cursor, child_end))
        cursor = child_end
    if cursor != end:
        raise ValueError("DER child boundary mismatch")
    return tuple(children)


def extract_certificate_spki(certificate_der: bytes) -> bytes:
    """Extract exact SubjectPublicKeyInfo DER from an X.509 certificate."""

    tag, cert_content, cert_end, _ = _read_der_tlv(certificate_der, 0)
    if tag != 0x30 or cert_end != len(certificate_der):
        raise ValueError("signing certificate must be one canonical DER SEQUENCE")
    certificate_children = _der_child_ranges(certificate_der, cert_content, cert_end)
    if len(certificate_children) != 3 or certificate_children[0][0] != 0x30:
        raise ValueError("malformed X.509 certificate")
    _, tbs_start, tbs_end = certificate_children[0]
    _tag, tbs_content, _tbs_end, _ = _read_der_tlv(certificate_der, tbs_start, tbs_end)
    fields = _der_child_ranges(certificate_der, tbs_content, tbs_end)
    has_version = bool(fields and fields[0][0] == 0xA0)
    spki_index = 6 if has_version else 5
    if len(fields) <= spki_index or fields[spki_index][0] != 0x30:
        raise ValueError("X.509 certificate is missing SubjectPublicKeyInfo")
    _, start, end = fields[spki_index]
    return certificate_der[start:end]


def _der_integer(data: bytes, start: int, end: int) -> int:
    tag, content, stop, _ = _read_der_tlv(data, start, end)
    if tag != 0x02 or stop != end or content >= stop:
        raise ValueError("malformed DER INTEGER")
    raw = data[content:stop]
    if raw[0] & 0x80:
        raise ValueError("negative DER INTEGER unsupported")
    if len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80:
        raise ValueError("non-canonical DER INTEGER")
    return int.from_bytes(raw, "big")


def parse_rsa_spki(spki_der: bytes) -> tuple[int, int]:
    """Return ``(modulus, public_exponent)`` from RSA SubjectPublicKeyInfo."""

    tag, content, end, _ = _read_der_tlv(spki_der, 0)
    if tag != 0x30 or end != len(spki_der):
        raise ValueError("malformed SubjectPublicKeyInfo")
    fields = _der_child_ranges(spki_der, content, end)
    if len(fields) != 2 or fields[0][0] != 0x30 or fields[1][0] != 0x03:
        raise ValueError("unsupported SubjectPublicKeyInfo")
    # rsaEncryption OID 1.2.840.113549.1.1.1 must be present in AlgorithmIdentifier.
    _, alg_start, alg_end = fields[0]
    _tag, alg_content, _alg_stop, _ = _read_der_tlv(spki_der, alg_start, alg_end)
    alg_fields = _der_child_ranges(spki_der, alg_content, alg_end)
    if not alg_fields or alg_fields[0][0] != 0x06:
        raise ValueError("SubjectPublicKeyInfo missing algorithm OID")
    _, oid_start, oid_end = alg_fields[0]
    _tag, oid_content, _oid_stop, _ = _read_der_tlv(spki_der, oid_start, oid_end)
    if spki_der[oid_content:oid_end] != bytes.fromhex("2a864886f70d010101"):
        raise ValueError("APK v2 signer currently supports RSA certificates only")

    _, bit_start, bit_end = fields[1]
    _tag, bit_content, _bit_stop, _ = _read_der_tlv(spki_der, bit_start, bit_end)
    if bit_content >= bit_end or spki_der[bit_content] != 0:
        raise ValueError("RSA SubjectPublicKeyInfo BIT STRING must have zero unused bits")
    rsa = spki_der[bit_content + 1:bit_end]
    tag, rsa_content, rsa_end, _ = _read_der_tlv(rsa, 0)
    if tag != 0x30 or rsa_end != len(rsa):
        raise ValueError("malformed RSA public key")
    ints = _der_child_ranges(rsa, rsa_content, rsa_end)
    if len(ints) != 2:
        raise ValueError("RSA public key must contain modulus and exponent")
    modulus = _der_integer(rsa, ints[0][1], ints[0][2])
    exponent = _der_integer(rsa, ints[1][1], ints[1][2])
    return modulus, exponent


def _locate_eocd(apk: bytes) -> _Eocd:
    # EOCD comment is uint16, so a valid record begins within the final 65557 bytes.
    minimum = max(0, len(apk) - 65557)
    marker = struct.pack("<I", EOCD_SIGNATURE)
    offset = apk.rfind(marker, minimum)
    if offset < 0 or offset + 22 > len(apk):
        raise ValueError("APK has no valid ZIP end-of-central-directory record")
    values = struct.unpack_from("<IHHHHIIH", apk, offset)
    comment = values[7]
    if offset + 22 + comment != len(apk):
        raise ValueError("ZIP EOCD comment length/bounds mismatch")
    if values[1] or values[2] or values[3] != values[4]:
        raise ValueError("multi-disk/ZIP64 APKs are intentionally unsupported")
    central_size, central_offset = values[5], values[6]
    if central_offset + central_size != offset:
        raise ValueError("ZIP central directory bounds mismatch")
    return _Eocd(offset, central_offset, central_size, comment)


def _chunked_content_digest(sections: Iterable[bytes]) -> bytes:
    chunk_digests: list[bytes] = []
    for section in sections:
        for start in range(0, len(section), CHUNK_SIZE):
            chunk = section[start:start + CHUNK_SIZE]
            chunk_digests.append(hashlib.sha256(b"\xA5" + _u32(len(chunk)) + chunk).digest())
    if not chunk_digests:
        raise ValueError("APK v2 digest requires at least one content chunk")
    return hashlib.sha256(b"\x5A" + _u32(len(chunk_digests)) + b"".join(chunk_digests)).digest()


def _rsa_pkcs1_v1_5_sha256_sign(payload: bytes, capability: RsaSigningCapability) -> bytes:
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(payload).digest()
    size = capability.key_size_bytes
    padding = size - len(digest_info) - 3
    if padding < 8:
        raise ValueError("RSA key too small for PKCS#1 v1.5 SHA-256 signature")
    encoded = b"\x00\x01" + b"\xFF" * padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), capability.private_exponent, capability.modulus)
    return signature.to_bytes(size, "big")


def _rsa_pkcs1_v1_5_sha256_verify(payload: bytes, signature: bytes, modulus: int, exponent: int) -> bool:
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    decoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(size, "big")
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(payload).digest()
    padding = size - len(digest_info) - 3
    if padding < 8:
        return False
    return decoded == b"\x00\x01" + b"\xFF" * padding + b"\x00" + digest_info


def _build_v2_value(content_digest: bytes, capability: RsaSigningCapability) -> bytes:
    digest_record = _u32(RSA_PKCS1_V1_5_SHA256_ID) + _lp32(content_digest)
    digests = _lp32_sequence((digest_record,))
    certificates = _lp32_sequence((capability.certificate_der,))
    additional_attributes = _lp32(b"")
    signed_data = digests + certificates + additional_attributes

    signature = _rsa_pkcs1_v1_5_sha256_sign(signed_data, capability)
    signature_record = _u32(RSA_PKCS1_V1_5_SHA256_ID) + _lp32(signature)
    signatures = _lp32_sequence((signature_record,))
    signer = _lp32(signed_data) + signatures + _lp32(capability.public_key_spki_der)
    return _lp32_sequence((signer,))


def _build_signing_block(v2_value: bytes) -> bytes:
    pair = struct.pack("<Q", 4 + len(v2_value)) + _u32(APK_SIGNATURE_SCHEME_V2_BLOCK_ID) + v2_value
    size = len(pair) + 24
    return struct.pack("<Q", size) + pair + struct.pack("<Q", size) + APK_SIG_BLOCK_MAGIC


def sign_apk_v2(unsigned_apk: bytes, capability: RsaSigningCapability) -> bytes:
    """Return a deterministic APK Signature Scheme v2 signed APK.

    Input must be an unsigned, non-ZIP64 APK.  The signature uses deterministic
    RSA PKCS#1 v1.5 + SHA-256 (algorithm ID 0x0103), the algorithm Android's v2
    specification explicitly identifies for deterministic build systems.
    """

    eocd = _locate_eocd(unsigned_apk)
    section1 = unsigned_apk[:eocd.central_offset]
    section3 = unsigned_apk[eocd.central_offset:eocd.offset]
    section4 = unsigned_apk[eocd.offset:]
    content_digest = _chunked_content_digest((section1, section3, section4))
    block = _build_signing_block(_build_v2_value(content_digest, capability))
    new_central_offset = eocd.central_offset + len(block)
    if new_central_offset > 0xFFFFFFFF:
        raise ValueError("ZIP64 is intentionally unsupported")
    patched_eocd = bytearray(section4)
    struct.pack_into("<I", patched_eocd, 16, new_central_offset)
    return section1 + block + section3 + bytes(patched_eocd)


def _parse_signing_block(apk: bytes, central_offset: int) -> tuple[int, dict[int, bytes]]:
    if central_offset < 32 or apk[central_offset - 16:central_offset] != APK_SIG_BLOCK_MAGIC:
        raise ValueError("APK signing block magic is missing")
    size2 = struct.unpack_from("<Q", apk, central_offset - 24)[0]
    start = central_offset - (size2 + 8)
    if start < 0 or start + 8 > central_offset:
        raise ValueError("APK signing block size is invalid")
    size1 = struct.unpack_from("<Q", apk, start)[0]
    if size1 != size2:
        raise ValueError("APK signing block size fields disagree")
    pairs_end = central_offset - 24
    cursor = start + 8
    pairs: dict[int, bytes] = {}
    while cursor < pairs_end:
        if cursor + 8 > pairs_end:
            raise ValueError("truncated APK signing block pair")
        pair_size = struct.unpack_from("<Q", apk, cursor)[0]
        cursor += 8
        if pair_size < 4 or cursor + pair_size > pairs_end:
            raise ValueError("invalid APK signing block pair size")
        pair_id = struct.unpack_from("<I", apk, cursor)[0]
        value = apk[cursor + 4:cursor + pair_size]
        if pair_id in pairs:
            raise ValueError("duplicate APK signing block ID")
        pairs[pair_id] = value
        cursor += pair_size
    if cursor != pairs_end:
        raise ValueError("APK signing block pair boundary mismatch")
    return start, pairs


def _single_lp32_sequence(data: bytes) -> bytes:
    sequence, end = _read_lp32(data, 0, len(data))
    if end != len(data):
        raise ValueError("trailing bytes after APK v2 sequence")
    item, cursor = _read_lp32(sequence, 0, len(sequence))
    if cursor != len(sequence):
        raise ValueError("APK v2 inspector currently requires exactly one signer/item")
    return item


def inspect_apk_v2(apk: bytes) -> ApkV2Inspection:
    """Parse and independently verify the supported one-signer v2 profile."""

    eocd = _locate_eocd(apk)
    block_start, pairs = _parse_signing_block(apk, eocd.central_offset)
    if APK_SIGNATURE_SCHEME_V2_BLOCK_ID not in pairs:
        raise ValueError("APK signing block has no v2 signature")
    signer = _single_lp32_sequence(pairs[APK_SIGNATURE_SCHEME_V2_BLOCK_ID])

    signed_data, cursor = _read_lp32(signer, 0, len(signer))
    signatures_container, cursor = _read_lp32(signer, cursor, len(signer))
    public_key, cursor = _read_lp32(signer, cursor, len(signer))
    if cursor != len(signer):
        raise ValueError("trailing bytes in APK v2 signer")

    signature_record = _single_lp32_sequence(_lp32(signatures_container))
    if len(signature_record) < 8:
        raise ValueError("truncated APK v2 signature record")
    sig_algorithm = struct.unpack_from("<I", signature_record, 0)[0]
    signature, sig_end = _read_lp32(signature_record, 4, len(signature_record))
    if sig_end != len(signature_record) or sig_algorithm != RSA_PKCS1_V1_5_SHA256_ID:
        raise ValueError("unsupported APK v2 signature algorithm")

    digests_container, sd_cursor = _read_lp32(signed_data, 0, len(signed_data))
    certificates_container, sd_cursor = _read_lp32(signed_data, sd_cursor, len(signed_data))
    attributes, sd_cursor = _read_lp32(signed_data, sd_cursor, len(signed_data))
    if sd_cursor != len(signed_data) or attributes:
        raise ValueError("unsupported APK v2 signed-data attributes")

    digest_record = _single_lp32_sequence(_lp32(digests_container))
    if len(digest_record) < 8:
        raise ValueError("truncated APK v2 digest record")
    digest_algorithm = struct.unpack_from("<I", digest_record, 0)[0]
    stored_digest, digest_end = _read_lp32(digest_record, 4, len(digest_record))
    if digest_end != len(digest_record) or digest_algorithm != sig_algorithm:
        raise ValueError("APK v2 digest/signature algorithm lists differ")

    certificate = _single_lp32_sequence(_lp32(certificates_container))
    cert_spki = extract_certificate_spki(certificate)
    certificate_key_matches = cert_spki == public_key
    modulus, exponent = parse_rsa_spki(public_key)
    signature_valid = _rsa_pkcs1_v1_5_sha256_verify(signed_data, signature, modulus, exponent)

    section1 = apk[:block_start]
    section3 = apk[eocd.central_offset:eocd.offset]
    section4 = bytearray(apk[eocd.offset:])
    # v2 digests EOCD as if Central Directory started at the signing-block start.
    struct.pack_into("<I", section4, 16, block_start)
    actual_digest = _chunked_content_digest((section1, section3, bytes(section4)))
    digest_valid = actual_digest == stored_digest

    return ApkV2Inspection(
        file_size=len(apk),
        signing_block_offset=block_start,
        signing_block_size=eocd.central_offset - block_start,
        central_directory_offset=eocd.central_offset,
        central_directory_size=eocd.central_size,
        certificate_sha256=hashlib.sha256(certificate).hexdigest(),
        signature_algorithm_id=sig_algorithm,
        content_digest_sha256=stored_digest.hex(),
        signature_valid=signature_valid,
        content_digest_valid=digest_valid,
        certificate_key_matches=certificate_key_matches,
    )


__all__ = [
    "APK_SIGNATURE_SCHEME_V2_BLOCK_ID",
    "APK_SIG_BLOCK_MAGIC",
    "RSA_PKCS1_V1_5_SHA256_ID",
    "ApkV2Inspection",
    "PRIVATE_SIGNING_CAPABILITY_MAGIC",
    "RsaSigningCapability",
    "decode_private_signing_capability",
    "encode_private_signing_capability",
    "extract_certificate_spki",
    "inspect_apk_v2",
    "parse_rsa_spki",
    "sign_apk_v2",
]
