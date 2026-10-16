"""Self-hosting step S15c.3 (ADR-301): Ed25519 package signature verification as XAX functions.

``xax_build.build`` verifies a snapshot's package signatures with the verifier it is given; the production compiler
(the general driver) gives it this one: ``xax_ed25519.signature_verifier``, Ed25519 over ``DOMAIN || package CID``
(RFC 8032 section 5.1.7, cofactorless, with S below the group order and canonical point encodings).  The functions
here are that verifier in XAX.  They have the S10e helper convention (``xax_selfhost_facts._function``): every value
lives in words of the output view (the driver's workspace), from ``ED_AT`` on, one byte or one limb per word.

* Field elements of GF(2^255 - 19) are sixteen 16-bit limbs held in two's complement words (the TweetNaCl
  representation); wrapping addition, subtraction and multiplication give a signed limb's bits, and an arithmetic
  shift is a biased unsigned division (``_sar``).
* Points are extended coordinates, four field elements in a row.
* ``sha512`` hashes bytes into 64 bytes; ``verify`` reads the key (``PK_AT``), the signature (``SIG_AT``) and the
  message (``MSG_LENGTH``, ``MSG_AT``) and gives 1 when the signature is valid, else 0.
"""

from __future__ import annotations

from xax_compiler import Operation
from xax_ed25519 import D as _D, L as _L, P as _P, SQRT_M1 as _I, _GX, _GY
from xax_selfhost_facts import E, _function
from xax_structured import B64

ED_AT = 48 << 20  # workspace words
K_AT = ED_AT  # SHA-512 round constants (80)
IV_AT = ED_AT + 80  # SHA-512 initial state (8)
L_AT = ED_AT + 96  # the group order's 32 bytes
CONST_AT = ED_AT + 128  # field constants, 16 limbs each
GF0, GF1, D_, D2, GX, GY, I_ = (CONST_AT + 16 * k for k in range(7))
SCRATCH_AT = ED_AT + 512  # field and point temporaries
SHA_STATE, SHA_W, SHA_BUF = ED_AT + 4096, ED_AT + 4112, ED_AT + 4224
SHA_LIMIT = 2048  # bytes one ``sha512`` call hashes
PK_AT, SIG_AT, MSG_LENGTH, MSG_AT = ED_AT + 8192, ED_AT + 8224, ED_AT + 8288, ED_AT + 8289
MSG_LIMIT = 1024
HASH_AT, X64_AT, SCALAR_AT = ED_AT + 9600, ED_AT + 9664, ED_AT + 9728  # the hash, modL's 64 words, k's bytes
assert SHA_BUF + SHA_LIMIT + 256 <= PK_AT and MSG_AT + MSG_LIMIT + 2 * 64 <= HASH_AT

_K = (
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b,
    0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
    0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8,
    0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
)
_IV = (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
       0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)
MASK = (1 << 64) - 1


def _limbs(value: int) -> tuple[int, ...]:
    return tuple((value >> (16 * k)) & 0xFFFF for k in range(16))


CONSTANTS = {GF0: _limbs(0), GF1: _limbs(1), D_: _limbs(_D), D2: _limbs(2 * _D % _P), GX: _limbs(_GX), GY: _limbs(_GY), I_: _limbs(_I)}


class _Slots:
    """Named scratch words, allocated once at build time."""

    def __init__(self):
        self.at, self.names = SCRATCH_AT, {}

    def __call__(self, name: str, words: int = 16) -> int:
        if name not in self.names:
            self.names[name] = self.at
            self.at += words
        assert self.at <= SHA_STATE
        return self.names[name]


SLOT = _Slots()
POINT = 64  # four field elements


def _xor(e: E, x, y):
    return e.bin(Operation.BIT_XOR, x, y)


def _rotr(e: E, x, n: int):
    return e.p.op1(Operation.ROTATE_RIGHT, (e.v(x),), B64, attributes=(n,))


def _shr(e: E, x, n: int):
    return e.udiv(x, 1 << n)


def _sar(e: E, x, n: int):
    """Arithmetic ``x >> n`` of a two's complement word."""
    return e.sub(e.udiv(e.add(x, 1 << 63), 1 << n), 1 << (63 - n))


# -- field arithmetic (TweetNaCl ``gf``) ------------------------------------------------------------------------------

def _car(e: E, limbs: list) -> list:
    """``car25519`` over sixteen SSA limbs."""
    limbs = list(limbs)
    for i in range(16):
        limbs[i] = e.add(limbs[i], 1 << 16)
        c = _sar(e, limbs[i], 16)
        target = (i + 1) * (i < 15)
        if i == 15:
            limbs[0] = e.add(limbs[0], e.mul(e.sub(c, 1), 38))
        else:
            limbs[target] = e.add(limbs[target], e.sub(c, 1))
        limbs[i] = e.sub(limbs[i], e.mul(c, 1 << 16))
    return limbs


def _load(e: E, at) -> list:
    return [e.ld(e.add(at, k)) for k in range(16)]


def _store(e: E, at, limbs) -> None:
    for k in range(16):
        e.st(e.add(at, k), limbs[k])


def _mul_function():
    def build(e: E):
        p = e.p
        a, b = _load(e, p["a"]), _load(e, p["b"])
        t = [e.c(0) for _ in range(31)]
        for i in range(16):
            for j in range(16):
                t[i + j] = e.add(t[i + j], e.mul(a[i], b[j]))
        for i in range(15):
            t[i] = e.add(t[i], e.mul(t[i + 16], 38))
        _store(e, p["o"], _car(e, _car(e, t[:16])))
        e.give(0)
    return _function(("o", "a", "b"), build, None)


def _add_function(subtract: bool):
    def build(e: E):
        p = e.p
        a, b = _load(e, p["a"]), _load(e, p["b"])
        _store(e, p["o"], [(e.sub if subtract else e.add)(a[k], b[k]) for k in range(16)])
        e.give(0)
    return _function(("o", "a", "b"), build, None)


def _copy_function():
    def build(e: E):
        p = e.p
        _store(e, p["o"], _load(e, p["a"]))
        e.give(0)
    return _function(("o", "a"), build, None)


def _sel_function():
    """``sel25519(p, q, b)``: swap ``p`` and ``q`` when ``b`` is 1."""
    def build(e: E):
        p = e.p
        c = e.sub(0, p["bit"])
        for k in range(16):
            x, y = e.ld(e.add(p["x"], k)), e.ld(e.add(p["y"], k))
            t = e.and_(c, _xor(e, x, y))
            e.st(e.add(p["x"], k), _xor(e, x, t))
            e.st(e.add(p["y"], k), _xor(e, y, t))
        e.give(0)
    return _function(("x", "y", "bit"), build, None)


def _pack_function():
    """``pack25519``: the canonical 32 bytes of a field element (one byte per word at ``out``)."""
    def build(e: E):
        p = e.p
        t = _car(e, _car(e, _car(e, _load(e, p["n"]))))
        for _round in range(2):
            m = [None] * 16
            m[0] = e.sub(t[0], 0xFFED)
            for i in range(1, 15):
                m[i] = e.sub(e.sub(t[i], 0xFFFF), e.and_(_shr(e, m[i - 1], 16), 1))
                m[i - 1] = e.and_(m[i - 1], 0xFFFF)
            m[15] = e.sub(e.sub(t[15], 0x7FFF), e.and_(_shr(e, m[14], 16), 1))
            b = e.and_(_shr(e, m[15], 16), 1)
            m[14] = e.and_(m[14], 0xFFFF)
            c = e.sub(0, e.sub(1, b))  # ``sel25519(t, m, 1 - b)``: take m when b is 0
            t = [_xor(e, t[k], e.and_(c, _xor(e, t[k], m[k]))) for k in range(16)]
        for i in range(16):
            e.st(e.add(p["out"], 2 * i), e.and_(t[i], 0xFF))
            e.st(e.add(p["out"], 2 * i + 1), e.and_(_shr(e, t[i], 8), 0xFF))
        e.give(0)
    return _function(("out", "n"), build, None)


def _unpack_function():
    def build(e: E):
        p = e.p
        limbs = [e.add(e.ld(e.add(p["bytes"], 2 * i)), e.mul(e.ld(e.add(p["bytes"], 2 * i + 1)), 256)) for i in range(16)]
        limbs[15] = e.and_(limbs[15], 0x7FFF)
        _store(e, p["o"], limbs)
        e.give(0)
    return _function(("o", "bytes"), build, None)


def build_functions(test_entries: bool = False):
    """``{name: function}`` and the objects they need; ``verify`` is the entry.  ``test_entries`` adds ``hash``, the
    SHA-512 of the message slots into ``HASH_AT``, for the differential tests."""
    functions, objects = {}, []

    def add(name, made):
        functions[name] = made[0]
        objects.extend(made[1])
        return made[0]

    M = add("mul", _mul_function())
    A = add("add", _add_function(False))
    Z = add("sub", _add_function(True))
    COPY = add("copy", _copy_function())
    SEL = add("sel", _sel_function())
    PACK = add("pack", _pack_function())
    UNPACK = add("unpack", _unpack_function())
    packed_a, packed_b = SLOT("packed_a", 32), SLOT("packed_b", 32)

    def power(name: str, top: int, skipped: tuple[int, ...]):
        """``inv25519`` (top 253, skipping 2 and 4) and ``pow2523`` (top 250, skipping 1)."""
        c = SLOT(f"{name}_c")

        def build(e: E):
            p = e.p
            e.call(COPY, c, p["i"])
            e.var("a", top + 1)

            def step():
                e.set("a", e.sub(p["a"], 1))
                e.call(M, c, c, c)
                e.if_(e.both(*(e.ne(p["a"], value) for value in skipped)), lambda: e.call(M, c, c, p["i"]))

            e.while_(lambda: e.ne(p["a"], 0), step)
            e.call(COPY, p["o"], c)
            e.give(0)
        return add(name, _function(("o", "i"), build, None))

    INV = power("inv", 253, (2, 4))
    POW2523 = power("pow2523", 250, (1,))

    def parity():
        def build(e: E):
            e.call(PACK, packed_a, e.p["a"])
            e.give(e.and_(e.ld(packed_a), 1))
        return add("par", _function(("a",), build, None))

    PAR = parity()

    def differs():
        """``neq25519``: 1 when the two elements' encodings differ."""
        def build(e: E):
            p = e.p
            e.call(PACK, packed_a, p["a"])
            e.call(PACK, packed_b, p["b"])
            e.var("diff", 0)
            e.for_("k", 0, 32, lambda: e.set("diff", e.or_(p["diff"], _xor(e, e.ld(e.add(packed_a, p["k"])), e.ld(e.add(packed_b, p["k"]))))))
            e.give(e.flag(e.ne(p["diff"], 0)))
        return add("neq", _function(("a", "b"), build, None))

    NEQ = differs()
    names = ("a", "b", "c", "d", "t", "e", "f", "g", "h")
    s = {name: SLOT(f"add_{name}") for name in names}

    def point_add():
        """``add(p, q)``: p += q."""
        def build(e: E):
            p = e.p
            P0, P1, P2, P3 = (e.add(p["p"], 16 * k) for k in range(4))
            Q0, Q1, Q2, Q3 = (e.add(p["q"], 16 * k) for k in range(4))
            for name, value in (("p0", P0), ("p1", P1), ("p2", P2), ("p3", P3), ("q0", Q0), ("q1", Q1), ("q2", Q2), ("q3", Q3)):
                e.var(name, value)
            e.call(Z, s["a"], p["p1"], p["p0"])
            e.call(Z, s["t"], p["q1"], p["q0"])
            e.call(M, s["a"], s["a"], s["t"])
            e.call(A, s["b"], p["p0"], p["p1"])
            e.call(A, s["t"], p["q0"], p["q1"])
            e.call(M, s["b"], s["b"], s["t"])
            e.call(M, s["c"], p["p3"], p["q3"])
            e.call(M, s["c"], s["c"], D2)
            e.call(M, s["d"], p["p2"], p["q2"])
            e.call(A, s["d"], s["d"], s["d"])
            e.call(Z, s["e"], s["b"], s["a"])
            e.call(Z, s["f"], s["d"], s["c"])
            e.call(A, s["g"], s["d"], s["c"])
            e.call(A, s["h"], s["b"], s["a"])
            e.call(M, p["p0"], s["e"], s["f"])
            e.call(M, p["p1"], s["h"], s["g"])
            e.call(M, p["p2"], s["g"], s["f"])
            e.call(M, p["p3"], s["e"], s["h"])
            e.give(0)
        return add("point_add", _function(("p", "q"), build, None))

    PADD = point_add()

    def cswap():
        def build(e: E):
            p = e.p
            for k in range(4):
                e.call(SEL, e.add(p["p"], 16 * k), e.add(p["q"], 16 * k), p["bit"])
            e.give(0)
        return add("cswap", _function(("p", "q", "bit"), build, None))

    CSWAP = cswap()
    tx, ty, zi = SLOT("pack_tx"), SLOT("pack_ty"), SLOT("pack_zi")

    def point_pack():
        def build(e: E):
            p = e.p
            e.call(INV, zi, e.add(p["p"], 32))
            e.call(M, tx, p["p"], zi)
            e.call(M, ty, e.add(p["p"], 16), zi)
            e.call(PACK, p["out"], ty)
            e.var("parity", e.call(PAR, tx))
            e.st(e.add(p["out"], 31), _xor(e, e.ld(e.add(p["out"], 31)), e.mul(p["parity"], 128)))
            e.give(0)
        return add("point_pack", _function(("out", "p"), build, None))

    PPACK = point_pack()

    def scalarmult():
        """``scalarmult(p, q, s)``: p = [s]q (q is consumed), s 32 bytes little-endian."""
        def build(e: E):
            p = e.p
            for k, value in enumerate((GF0, GF1, GF1, GF0)):
                e.call(COPY, e.add(p["p"], 16 * k), value)
            e.var("byte", 32)

            def each_byte():
                e.set("byte", e.sub(p["byte"], 1))
                e.var("value", e.ld(e.add(p["s"], p["byte"])))
                e.var("weight", 128)

                def each_bit():
                    e.var("bit", e.and_(e.udiv(p["value"], p["weight"]), 1))
                    e.call(CSWAP, p["p"], p["q"], p["bit"])
                    e.call(PADD, p["q"], p["p"])
                    e.call(PADD, p["p"], p["p"])
                    e.call(CSWAP, p["p"], p["q"], p["bit"])
                    e.set("weight", e.udiv(p["weight"], 2))

                e.while_(lambda: e.ne(p["weight"], 0), each_bit)

            e.while_(lambda: e.ne(p["byte"], 0), each_byte)
            e.give(0)
        return add("scalarmult", _function(("p", "q", "s"), build, None))

    SMULT = scalarmult()
    base = SLOT("base", POINT)

    def scalarbase():
        def build(e: E):
            p = e.p
            e.call(COPY, base, GX)
            e.call(COPY, base + 16, GY)
            e.call(COPY, base + 32, GF1)
            e.call(M, base + 48, GX, GY)
            e.call(SMULT, p["p"], base, p["s"])
            e.give(0)
        return add("scalarbase", _function(("p", "s"), build, None))

    SBASE = scalarbase()
    t_, chk, num, den, den2, den4, den6 = (SLOT(f"unpack_{name}") for name in ("t", "chk", "num", "den", "den2", "den4", "den6"))

    def unpackneg():
        """``unpackneg(r, key)``: r = -A for the key's point A; 1 when the key decodes (y below p; x = 0 with the sign
        bit set does not decode), else 0."""
        def build(e: E):
            p = e.p
            r0, r1, r2, r3 = (e.add(p["r"], 16 * k) for k in range(4))
            for name, value in (("r0", r0), ("r1", r1), ("r2", r2), ("r3", r3)):
                e.var(name, value)
            e.var("ok", 1)
            # y below p: not (byte 0 >= 0xed, bytes 1..30 all 0xff, byte 31 & 0x7f == 0x7f)
            e.var("high", e.flag(e.le(0xED, e.ld(p["key"]))))
            for k in range(1, 31):
                e.set("high", e.and_(p["high"], e.flag(e.eq(e.ld(e.add(p["key"], k)), 0xFF))))
            e.set("high", e.and_(p["high"], e.flag(e.eq(e.and_(e.ld(e.add(p["key"], 31)), 0x7F), 0x7F))))
            e.if_(e.ne(p["high"], 0), lambda: e.set("ok", 0))
            e.call(COPY, p["r2"], GF1)
            e.call(UNPACK, p["r1"], p["key"])
            e.call(M, num, p["r1"], p["r1"])
            e.call(M, den, num, D_)
            e.call(Z, num, num, p["r2"])
            e.call(A, den, p["r2"], den)
            e.call(M, den2, den, den)
            e.call(M, den4, den2, den2)
            e.call(M, den6, den4, den2)
            e.call(M, t_, den6, num)
            e.call(M, t_, t_, den)
            e.call(POW2523, t_, t_)
            e.call(M, t_, t_, num)
            e.call(M, t_, t_, den)
            e.call(M, t_, t_, den)
            e.call(M, p["r0"], t_, den)
            e.call(M, chk, p["r0"], p["r0"])
            e.call(M, chk, chk, den)
            e.if_(e.ne(e.call(NEQ, chk, num), 0), lambda: e.call(M, p["r0"], p["r0"], I_))
            e.call(M, chk, p["r0"], p["r0"])
            e.call(M, chk, chk, den)
            e.if_(e.ne(e.call(NEQ, chk, num), 0), lambda: e.set("ok", 0))
            e.var("sign", _shr(e, e.ld(e.add(p["key"], 31)), 7))
            # x = 0 with the sign bit set does not decode
            e.if_(e.both(e.eq(e.call(NEQ, p["r0"], GF0), 0), e.ne(p["sign"], 0)), lambda: e.set("ok", 0))
            e.if_(e.eq(e.call(PAR, p["r0"]), p["sign"]), lambda: e.call(Z, p["r0"], GF0, p["r0"]))
            e.call(M, p["r3"], p["r0"], p["r1"])
            e.give(p["ok"])
        return add("unpackneg", _function(("r", "key"), build, None))

    UNPACKNEG = unpackneg()

    def mod_l():
        """``modL(r, x)``: r (32 bytes) = x mod L for 64 signed words ``x`` (consumed)."""
        def build(e: E):
            p = e.p
            x = lambda j: e.add(p["x"], j)  # noqa: E731
            e.var("i", 64)

            def outer():
                e.set("i", e.sub(p["i"], 1))
                e.var("carry", 0)
                e.var("xi", e.ld(x(p["i"])))
                e.var("j", e.sub(p["i"], 32))

                def inner():
                    e.var("xj", e.add(e.ld(x(p["j"])), e.sub(p["carry"], e.mul(e.mul(16, p["xi"]), e.ld(e.add(L_AT, e.sub(p["j"], e.sub(p["i"], 32))))))))
                    e.set("carry", _sar(e, e.add(p["xj"], 128), 8))
                    e.st(x(p["j"]), e.sub(p["xj"], e.mul(p["carry"], 256)))
                    e.set("j", e.add(p["j"], 1))

                e.while_(lambda: e.lt(p["j"], e.sub(p["i"], 12)), inner)
                e.st(x(p["j"]), e.add(e.ld(x(p["j"])), p["carry"]))
                e.st(x(p["i"]), 0)

            e.while_(lambda: e.lt(32, p["i"]), outer)
            e.var("carry2", 0)
            e.var("top", _sar(e, e.ld(x(31)), 4))

            def second():
                e.var("xj2", e.add(e.ld(x(p["j2"])), e.sub(p["carry2"], e.mul(p["top"], e.ld(e.add(L_AT, p["j2"]))))))
                e.set("carry2", _sar(e, p["xj2"], 8))
                e.st(x(p["j2"]), e.and_(p["xj2"], 255))

            e.for_("j2", 0, 32, second)
            e.for_("j3", 0, 32, lambda: e.st(x(p["j3"]), e.sub(e.ld(x(p["j3"])), e.mul(p["carry2"], e.ld(e.add(L_AT, p["j3"]))))))

            def final():
                e.st(x(e.add(p["i4"], 1)), e.add(e.ld(x(e.add(p["i4"], 1))), _sar(e, e.ld(x(p["i4"])), 8)))
                e.st(e.add(p["r"], p["i4"]), e.and_(e.ld(x(p["i4"])), 255))

            e.for_("i4", 0, 32, final)
            e.give(0)
        return add("modl", _function(("r", "x"), build, None))

    MODL = mod_l()

    def sha512():
        """SHA-512 of ``n`` bytes at ``msg`` (one per word, ``n`` <= ``SHA_LIMIT``) into 64 bytes at ``out``."""
        def build(e: E):
            p = e.p
            for k, value in enumerate(_K):
                e.st(K_AT + k, value)
            for k, value in enumerate(_IV):
                e.st(SHA_STATE + k, value)
            # The padded message: the bytes, 0x80, zeros, the bit length (16 bytes, big-endian).
            e.var("padded", e.mul(e.udiv(e.add(p["n"], 17 + 127), 128), 128))
            e.for_("z", 0, p["padded"], lambda: e.st(e.add(SHA_BUF, p["z"]), 0))
            e.for_("m", 0, p["n"], lambda: e.st(e.add(SHA_BUF, p["m"]), e.ld(e.add(p["msg"], p["m"]))))
            e.st(e.add(SHA_BUF, p["n"]), 0x80)
            e.var("bits", e.mul(p["n"], 8))
            for k in range(8):
                e.st(e.add(SHA_BUF, e.sub(p["padded"], 1 + k)), e.and_(_shr(e, p["bits"], 8 * k), 0xFF))
            e.var("block", 0)

            def each_block():
                def word(t):
                    value = e.c(0)
                    for k in range(8):
                        value = e.add(e.mul(value, 256), e.ld(e.add(e.add(SHA_BUF, p["block"]), e.add(e.mul(t, 8), k))))
                    return value

                e.for_("t", 0, 16, lambda: e.st(e.add(SHA_W, p["t"]), word(p["t"])))

                def schedule():
                    w15, w2 = e.ld(e.add(SHA_W, e.sub(p["t2"], 15))), e.ld(e.add(SHA_W, e.sub(p["t2"], 2)))
                    s0 = _xor(e, _xor(e, _rotr(e, w15, 1), _rotr(e, w15, 8)), _shr(e, w15, 7))
                    s1 = _xor(e, _xor(e, _rotr(e, w2, 19), _rotr(e, w2, 61)), _shr(e, w2, 6))
                    e.st(e.add(SHA_W, p["t2"]), e.add(e.add(e.ld(e.add(SHA_W, e.sub(p["t2"], 16))), s0),
                                                       e.add(e.ld(e.add(SHA_W, e.sub(p["t2"], 7))), s1)))

                e.for_("t2", 16, 80, schedule)
                letters = "abcdefgh"
                for k, letter in enumerate(letters):
                    e.var(letter, e.ld(SHA_STATE + k))

                def round_():
                    a, b, c, d, f_e, f, g, h = (p[letter] for letter in letters)
                    big1 = _xor(e, _xor(e, _rotr(e, f_e, 14), _rotr(e, f_e, 18)), _rotr(e, f_e, 41))
                    choose = _xor(e, e.and_(f_e, f), e.and_(_xor(e, f_e, MASK), g))
                    t1 = e.add(e.add(e.add(h, big1), e.add(choose, e.ld(e.add(K_AT, p["r"])))), e.ld(e.add(SHA_W, p["r"])))
                    big0 = _xor(e, _xor(e, _rotr(e, a, 28), _rotr(e, a, 34)), _rotr(e, a, 39))
                    majority = _xor(e, _xor(e, e.and_(a, b), e.and_(a, c)), e.and_(b, c))
                    t2 = e.add(big0, majority)
                    e.var("t1", t1)
                    e.var("t2v", t2)
                    e.set("h", g)
                    e.set("g", f)
                    e.set("f", f_e)
                    e.set("e", e.add(d, p["t1"]))
                    e.set("d", c)
                    e.set("c", b)
                    e.set("b", a)
                    e.set("a", e.add(p["t1"], p["t2v"]))

                e.for_("r", 0, 80, round_)
                for k, letter in enumerate(letters):
                    e.st(SHA_STATE + k, e.add(e.ld(SHA_STATE + k), p[letter]))
                e.set("block", e.add(p["block"], 128))

            e.while_(lambda: e.lt(p["block"], p["padded"]), each_block)
            for k in range(8):
                for j in range(8):
                    e.st(e.add(p["out"], 8 * k + j), e.and_(_shr(e, e.ld(SHA_STATE + k), 8 * (7 - j)), 0xFF))
            e.give(0)
        return add("sha512", _function(("out", "msg", "n"), build, None))

    SHA512 = sha512()
    q_point, p_point, r_bytes = SLOT("verify_q", POINT), SLOT("verify_p", POINT), SLOT("verify_r", 32)
    hashed = SLOT("verify_input", MSG_LIMIT + 64)

    def verify():
        def build(e: E):
            p = e.p
            for at, limbs in CONSTANTS.items():
                for k, value in enumerate(limbs):
                    e.st(at + k, value)
            for k, value in enumerate(_L.to_bytes(32, "little")):
                e.st(L_AT + k, value)
            e.var("ok", e.flag(e.le(e.ld(MSG_LENGTH), MSG_LIMIT)))
            # S below L: compare from the most significant byte.
            e.var("below", 0)
            e.var("decided", 0)

            def compare():
                e.var("sb", e.ld(e.add(SIG_AT + 32, p["kb"])))
                e.var("lb", e.ld(e.add(L_AT, p["kb"])))
                e.if_(e.eq(p["decided"], 0), lambda: e.if_(e.lt(p["sb"], p["lb"]), lambda: (e.set("below", 1), e.set("decided", 1)),
                                                           lambda: e.if_(e.lt(p["lb"], p["sb"]), lambda: e.set("decided", 1))))
                e.set("kb", e.sub(p["kb"], 1))

            e.var("kb", 31)
            e.var("left", 32)
            e.while_(lambda: e.ne(p["left"], 0), lambda: (compare(), e.set("left", e.sub(p["left"], 1))))
            e.if_(e.eq(p["below"], 0), lambda: e.set("ok", 0))

            def checked():
                e.if_(e.eq(e.call(UNPACKNEG, q_point, PK_AT), 0), lambda: e.set("ok", 0))

                def rest():
                    # k = SHA-512(R || A || M) mod L
                    e.for_("c1", 0, 32, lambda: e.st(e.add(hashed, p["c1"]), e.ld(e.add(SIG_AT, p["c1"]))))
                    e.for_("c2", 0, 32, lambda: e.st(e.add(hashed + 32, p["c2"]), e.ld(e.add(PK_AT, p["c2"]))))
                    e.var("length", e.ld(MSG_LENGTH))
                    e.for_("c3", 0, p["length"], lambda: e.st(e.add(hashed + 64, p["c3"]), e.ld(e.add(MSG_AT, p["c3"]))))
                    e.call(SHA512, HASH_AT, hashed, e.add(p["length"], 64))
                    e.for_("c4", 0, 64, lambda: e.st(e.add(X64_AT, p["c4"]), e.ld(e.add(HASH_AT, p["c4"]))))
                    e.call(MODL, SCALAR_AT, X64_AT)
                    e.call(SMULT, p_point, q_point, SCALAR_AT)
                    e.call(SBASE, q_point, SIG_AT + 32)
                    e.call(PADD, p_point, q_point)
                    e.call(PPACK, r_bytes, p_point)
                    e.var("diff", 0)
                    e.for_("c5", 0, 32, lambda: e.set("diff", e.or_(p["diff"], _xor(e, e.ld(e.add(r_bytes, p["c5"])), e.ld(e.add(SIG_AT, p["c5"]))))))
                    e.if_(e.ne(p["diff"], 0), lambda: e.set("ok", 0))

                e.if_(e.ne(p["ok"], 0), rest)

            e.if_(e.ne(p["ok"], 0), checked)
            e.give(p["ok"])
        return add("verify", _function((), build, None))

    verify()
    if test_entries:
        def hash_entry(e: E):
            e.call(SHA512, HASH_AT, MSG_AT, e.ld(MSG_LENGTH))
            e.give(0)

        add("hash", _function((), hash_entry, None))
    return functions, tuple(objects)


__all__ = ["ED_AT", "HASH_AT", "MSG_AT", "MSG_LENGTH", "MSG_LIMIT", "PK_AT", "SIG_AT", "build_functions"]
