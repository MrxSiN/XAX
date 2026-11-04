"""S15c.3 (ADR-301): Ed25519 (RFC 8032), the reference for the production compiler's package signature verifier.

The bootstrap's ``xax_build.build`` and ``resolve_packages`` take any signature verifier; the production compiler
(the general driver) verifies the one algorithm its build accepts, ``ALGORITHM`` (``b"ed25519"``), in XAX
(``xax_selfhost_ed25519``).  This module is that algorithm in Python: ``signature_verifier`` is what the bootstrap is
given when its outcome is compared with the driver's, and ``sign`` makes test and tool signatures.

A package signature (``xax_build.signature``) under ``ALGORITHM`` names the signer by its 32-byte public key, and its
64-byte value signs ``message(root)``: the domain ``DOMAIN`` followed by the signed package's CID.  Verification is
RFC 8032 section 5.1.7 without the cofactor: the key and R decode to points with a canonical y below p, S is below
the group order L, and the encoding of [S]B - [k]A equals R's bytes, with k = SHA-512(R || A || M) mod L.
"""

from __future__ import annotations

import hashlib

ALGORITHM = b"ed25519"
DOMAIN = b"xax-package-signature-ed25519-v1\x00"
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
_GY = 4 * pow(5, P - 2, P) % P


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if x & 1 != sign:
        x = P - x
    return x


_GX = _recover_x(_GY, 0)
B = (_GX, _GY, 1, _GX * _GY % P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _multiply(s: int, point):
    result = (0, 1, 1, 0)
    while s:
        if s & 1:
            result = _add(result, point)
        point = _add(point, point)
        s >>= 1
    return result


def _encode(point) -> bytes:
    z = pow(point[2], P - 2, P)
    x, y = point[0] * z % P, point[1] * z % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _decode(data: bytes):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _hash(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def public_key(secret: bytes) -> bytes:
    digest = hashlib.sha512(secret).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    return _encode(_multiply(scalar, B))


def sign_bytes(secret: bytes, message: bytes) -> bytes:
    """RFC 8032 section 5.1.6 for a 32-byte ``secret``."""
    digest = hashlib.sha512(secret).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    key = _encode(_multiply(scalar, B))
    r = _hash(digest[32:] + message) % L
    encoded_r = _encode(_multiply(r, B))
    s = (r + _hash(encoded_r + key + message) % L * scalar) % L
    return encoded_r + s.to_bytes(32, "little")


def verify_bytes(key: bytes, message: bytes, value: bytes) -> bool:
    if len(key) != 32 or len(value) != 64:
        return False
    a = _decode(key)
    if a is None or _decode(value[:32]) is None:
        return False
    s = int.from_bytes(value[32:], "little")
    if s >= L:
        return False
    k = _hash(value[:32] + key + message) % L
    negated = (P - a[0] if a[0] else 0, a[1], 1, (P - a[3]) % P)
    return _encode(_add(_multiply(s, B), _multiply(k, negated))) == value[:32]


def message(root: bytes) -> bytes:
    return DOMAIN + root


def sign(secret: bytes, root: bytes) -> bytes:
    """The 64-byte value of a package signature over the package CID ``root``."""
    return sign_bytes(secret, message(root))


def signature_verifier(algorithm: bytes, signer: bytes, root: bytes, value: bytes) -> bool:
    """``xax_build.SignatureVerifier`` for ``ALGORITHM``: any other algorithm is not verified (False)."""
    return algorithm == ALGORITHM and verify_bytes(signer, message(root), value)


__all__ = ["ALGORITHM", "DOMAIN", "message", "public_key", "sign", "sign_bytes", "signature_verifier", "verify_bytes"]
