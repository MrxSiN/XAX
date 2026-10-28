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

from xax_compiler import Operation, x86_64_linux_exec_target
from xax_graph_builder import program_store
from xax_native import bootstrap_dir
from xax_selfhost_facts import E, H_ARENA, H_ARENA_END, NONE, _function
from xax_selfhost_general_image import IMAGE_AT, IMAGE_END
from xax_selfhost_views_backend import _FN, NativeProgram, _call, _ok
from xax_selfhost_x86_64_general import GENERAL_ARENA_AT, GENERAL_ARENA_END

STORE_PATH = bootstrap_dir() / "xax_apk_signer.xax"
OUT = IMAGE_AT + 3
STATE_AT = 110 << 20  # the hash state: H (8), W (64), the block (64), its fill, the message length; then the inputs' places
(S_H, S_W, S_BLOCK, S_FILL, S_LEN) = (0, 8, 72, 136, 137)
G_AT = STATE_AT + 256  # the inputs: APK at, length; modulus, its length; exponent, its length; certificate, its length; limbs
(G_APK, G_APKN, G_N, G_NN, G_D, G_DN, G_C, G_CN, G_K, G_NL, G_NINV) = (G_AT + k for k in range(11))
MASK32 = 0xFFFFFFFF
SHA_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2)
SHA_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
CHUNK_SIZE = 1 << 20
V2_BLOCK_ID, ALGORITHM_ID, MAGIC = 0x7109871A, 0x0103, b"APK Sig Block 42"


def _bx(e: E, x, y):
    return e.bin(Operation.BIT_XOR, x, y)


def _rotr(e: E, x, n: int):
    return e.or_(e.udiv(x, 1 << n), e.and_(e.mul(x, 1 << (32 - n)), MASK32))


def _shift_bytes(e: E, k):
    result = e.c(1)
    for q in range(1, 8):
        result = e.sel(e.eq(k, q), 1 << (8 * q), result)
    return result


def _packed_byte(e: E, at, k):
    """Byte ``k`` of the packed input at word ``at``."""
    return e.and_(e.udiv(e.rd(e.add(at, e.udiv(k, 8))), _shift_bytes(e, e.urem(k, 8))), 255)


# -- SHA-256 ------------------------------------------------------------------------------------------------------------

def _compress_fn(tables):
    """One 64-byte block (``S_BLOCK``) into the state ``S_H``."""
    def build(e: E):
        p = e.p
        w = STATE_AT + S_W
        e.for_("cz_t", 0, 16, lambda: e.st(e.add(w, p["cz_t"]), e.or_(e.or_(e.mul(e.ld(e.add(STATE_AT + S_BLOCK, e.mul(p["cz_t"], 4))), 1 << 24),
                                                                            e.mul(e.ld(e.add(STATE_AT + S_BLOCK + 1, e.mul(p["cz_t"], 4))), 1 << 16)),
                                                                     e.or_(e.mul(e.ld(e.add(STATE_AT + S_BLOCK + 2, e.mul(p["cz_t"], 4))), 1 << 8),
                                                                           e.ld(e.add(STATE_AT + S_BLOCK + 3, e.mul(p["cz_t"], 4)))))))

        def schedule():
            e.var("cz_w15", e.ld(e.add(w, e.sub(p["cz_t"], 15))))
            e.var("cz_w2", e.ld(e.add(w, e.sub(p["cz_t"], 2))))
            s0 = _bx(e, _bx(e, _rotr(e, p["cz_w15"], 7), _rotr(e, p["cz_w15"], 18)), e.udiv(p["cz_w15"], 8))
            s1 = _bx(e, _bx(e, _rotr(e, p["cz_w2"], 17), _rotr(e, p["cz_w2"], 19)), e.udiv(p["cz_w2"], 1024))
            e.st(e.add(w, p["cz_t"]), e.and_(e.add(e.add(e.ld(e.add(w, e.sub(p["cz_t"], 16))), s0), e.add(e.ld(e.add(w, e.sub(p["cz_t"], 7))), s1)), MASK32))

        e.for_("cz_t", 16, 64, schedule)
        names = ("cz_a", "cz_b", "cz_c", "cz_d", "cz_e", "cz_f", "cz_g", "cz_h")
        for k, name in enumerate(names):
            e.var(name, e.ld(STATE_AT + S_H + k))
        e.var("cz_k", 0)

        def round_():
            a, b, c, d, f_e, f, g, h = (p[name] for name in names)
            s1 = _bx(e, _bx(e, _rotr(e, f_e, 6), _rotr(e, f_e, 11)), _rotr(e, f_e, 25))
            ch = _bx(e, e.and_(f_e, f), e.and_(_bx(e, f_e, MASK32), g))
            e.var("cz_t1", e.and_(e.add(e.add(e.add(h, s1), e.add(ch, e.ld(e.add(p["cz_kt"], p["cz_r"])))), e.ld(e.add(w, p["cz_r"]))), MASK32))
            s0 = _bx(e, _bx(e, _rotr(e, a, 2), _rotr(e, a, 13)), _rotr(e, a, 22))
            maj = _bx(e, _bx(e, e.and_(a, b), e.and_(a, c)), e.and_(b, c))
            e.var("cz_t2", e.and_(e.add(s0, maj), MASK32))
            e.set("cz_h", g)
            e.set("cz_g", f)
            e.set("cz_f", f_e)
            e.set("cz_e", e.and_(e.add(d, p["cz_t1"]), MASK32))
            e.set("cz_d", c)
            e.set("cz_c", b)
            e.set("cz_b", a)
            e.set("cz_a", e.and_(e.add(p["cz_t1"], p["cz_t2"]), MASK32))

        e.var("cz_kt", e.ld(G_AT + 32))  # the round constants' place
        e.for_("cz_r", 0, 64, round_)
        for k, name in enumerate(names):
            e.st(STATE_AT + S_H + k, e.and_(e.add(e.ld(STATE_AT + S_H + k), p[name]), MASK32))
        e.give(1)
    return _function((), build, tables)


def sha_init(e: E):
    for k, word in enumerate(SHA_IV):
        e.st(STATE_AT + S_H + k, word)
    e.st(STATE_AT + S_FILL, 0)
    e.st(STATE_AT + S_LEN, 0)


def _byte_fn(tables):
    """``sha_byte(b)``: one message byte."""
    def build(e: E):
        p = e.p
        e.var("sb_f", e.ld(STATE_AT + S_FILL))
        e.st(e.add(STATE_AT + S_BLOCK, p["sb_f"]), p["b"])
        e.st(STATE_AT + S_LEN, e.add(e.ld(STATE_AT + S_LEN), 1))
        e.if_(e.eq(p["sb_f"], 63), lambda: (_call(e, "sx_compress"), e.st(STATE_AT + S_FILL, 0)), lambda: e.st(STATE_AT + S_FILL, e.add(p["sb_f"], 1)))
        e.give(1)
    return _function(("b",), build, tables)


def sha_byte(e: E, b):
    _call(e, "sx_byte", b)


def _final_fn(tables):
    """The padding and length; the digest's 32 bytes to ``out`` (one per word)."""
    def build(e: E):
        p = e.p
        e.var("sf_bits", e.mul(e.ld(STATE_AT + S_LEN), 8))
        sha_byte(e, 0x80)
        e.while_(lambda: e.ne(e.ld(STATE_AT + S_FILL), 56), lambda: sha_byte(e, 0))
        for k in range(8):
            sha_byte(e, e.and_(e.udiv(p["sf_bits"], 1 << (8 * (7 - k))) if k < 7 else p["sf_bits"], 255))
        e.for_("sf_k", 0, 32, lambda: e.st(e.add(p["out"], p["sf_k"]), e.and_(e.udiv(e.ld(e.add(STATE_AT + S_H, e.udiv(p["sf_k"], 4))),
                                                                                  e.sel(e.eq(e.urem(p["sf_k"], 4), 0), 1 << 24, e.sel(e.eq(e.urem(p["sf_k"], 4), 1), 1 << 16,
                                                                                        e.sel(e.eq(e.urem(p["sf_k"], 4), 2), 1 << 8, 1)))), 255)))
        e.give(1)
    return _function(("out",), build, tables)


def _hash_words_fn(tables):
    """``hash(at, n, out)``: SHA-256 of ``n`` bytes one per word at ``at`` into ``out``."""
    def build(e: E):
        p = e.p
        sha_init(e)
        e.for_("hw_k", 0, p["n"], lambda: sha_byte(e, e.ld(e.add(p["at"], p["hw_k"]))))
        _call(e, "sx_final", p["out"])
        e.give(1)
    return _function(("at", "n", "out"), build, tables)


# -- the output -------------------------------------------------------------------------------------------------------------

def _put_fn(tables):
    def build(e: E):
        p = e.p
        e.var("pb_pos", e.ld(IMAGE_AT + 2))
        e.var("pb_at", e.add(OUT, e.udiv(p["pb_pos"], 8)))
        _ok(e, e.lt(p["pb_at"], IMAGE_END))
        e.var("pb_k", e.urem(p["pb_pos"], 8))
        e.if_(e.eq(p["pb_k"], 0), lambda: e.st(p["pb_at"], p["byte"]),
              lambda: e.st(p["pb_at"], e.or_(e.ld(p["pb_at"]), e.mul(p["byte"], _shift_bytes(e, p["pb_k"])))))
        e.st(IMAGE_AT + 2, e.add(p["pb_pos"], 1))
        e.give(1)
    return _function(("byte",), build, tables)


def put(e: E, byte):
    _call(e, "sx_put", byte)


def _copy_fn(tables):
    """``copy(start, stop)``: APK bytes ``start`` to ``stop`` to the output."""
    def build(e: E):
        p = e.p
        e.var("cp_apk", e.ld(G_APK))
        e.for_("cp_k", p["start"], p["stop"], lambda: put(e, _packed_byte(e, p["cp_apk"], p["cp_k"])))
        e.give(1)
    return _function(("start", "stop"), build, tables)


# -- bytes in the arena (one per word) --------------------------------------------------------------------------------------

class Buf:
    """A byte list in the arena: ``[length, bytes...]``."""

    def __init__(self, e: E, name: str, capacity):
        self.e, self.name = e, name
        e.var(name, e.alloc(e.add(capacity, 2)))
        _ok(e, e.ne(e.p[name], NONE))
        e.st(e.p[name], 0)

    @property
    def at(self):
        return self.e.add(self.e.p[self.name], 1)

    @property
    def n(self):
        return self.e.ld(self.e.p[self.name])

    def byte(self, value):
        e = self.e
        e.var(f"{self.name}_n", self.n)
        e.st(e.add(e.add(e.p[self.name], 1), e.p[f"{self.name}_n"]), value)
        e.st(e.p[self.name], e.add(e.p[f"{self.name}_n"], 1))

    def u32(self, value):
        e = self.e
        e.var(f"{self.name}_v", value)
        for k in range(4):
            self.byte(e.and_(e.udiv(e.p[f"{self.name}_v"], 1 << (8 * k)) if k else e.p[f"{self.name}_v"], 255))

    def words(self, at, n):
        """``n`` bytes one per word at ``at``."""
        e = self.e
        e.var(f"{self.name}_src", at)
        e.for_(f"{self.name}_k", 0, n, lambda: self.byte(e.ld(e.add(e.p[f"{self.name}_src"], e.p[f"{self.name}_k"]))))

    def inputs(self, at, n):
        """``n`` input bytes one per word at input word ``at``."""
        e = self.e
        e.var(f"{self.name}_src", at)
        e.for_(f"{self.name}_k", 0, n, lambda: self.byte(e.rd(e.add(e.p[f"{self.name}_src"], e.p[f"{self.name}_k"]))))


# -- DER: the certificate's SubjectPublicKeyInfo ------------------------------------------------------------------------------

def _tlv_fn(tables):
    """``tlv(at, limit)``: the DER object at certificate offset ``at`` (inside ``limit``): ``end`` + 2^32 * content, its
    tag in the word ``G_AT + 40``; declines where ``_read_der_tlv``/``_read_der_length`` raise."""
    def build(e: E):
        p = e.p
        cert, size = e.ld(G_C), e.ld(G_CN)
        e.var("tl_cert", cert)
        e.var("tl_size", size)
        byte = lambda k: e.rd(e.add(p["tl_cert"], k))  # noqa: E731
        _ok(e, e.lt(p["at"], p["limit"]))
        e.st(G_AT + 40, byte(p["at"]))
        e.var("tl_o", e.add(p["at"], 1))
        _ok(e, e.lt(p["tl_o"], p["tl_size"]))
        e.var("tl_first", byte(p["tl_o"]))
        e.set("tl_o", e.add(p["tl_o"], 1))
        e.var("tl_len", p["tl_first"])

        def long():
            e.var("tl_count", e.and_(p["tl_first"], 0x7F))
            _ok(e, e.both(e.ne(p["tl_count"], 0), e.le(p["tl_count"], 4), e.le(e.add(p["tl_o"], p["tl_count"]), p["tl_size"])))
            _ok(e, e.ne(byte(p["tl_o"]), 0))
            e.set("tl_len", 0)
            e.for_("tl_k", 0, p["tl_count"], lambda: e.set("tl_len", e.add(e.mul(p["tl_len"], 256), byte(e.add(p["tl_o"], p["tl_k"])))))
            _ok(e, e.le(0x80, p["tl_len"]))
            e.set("tl_o", e.add(p["tl_o"], p["tl_count"]))

        e.if_(e.le(0x80, p["tl_first"]), long)
        e.var("tl_end", e.add(p["tl_o"], p["tl_len"]))
        _ok(e, e.le(p["tl_end"], p["limit"]))
        e.give(e.add(p["tl_end"], e.mul(p["tl_o"], 1 << 32)))
    return _function(("at", "limit"), build, tables)


def _spki_fn(tables):
    """``extract_certificate_spki``: the SPKI's start + 2^32 * end in the certificate."""
    def build(e: E):
        p = e.p

        def tlv(at, limit, name):
            e.var(name, _call(e, "sx_tlv", at, limit))
            e.var(f"{name}_tag", e.ld(G_AT + 40))
            e.var(f"{name}_end", e.and_(p[name], MASK32))
            e.var(f"{name}_content", e.udiv(p[name], 1 << 32))

        def children(content, end, name, cap):
            """The children's (tag, start, end) into ``name`` (count ``name_n``); declines past ``cap``."""
            e.var(name, e.alloc(3 * cap + 1))
            _ok(e, e.ne(p[name], NONE))
            e.var(f"{name}_n", 0)
            e.var(f"{name}_c", content)

            def child():
                tlv(p[f"{name}_c"], end, f"{name}_t")
                _ok(e, e.lt(p[f"{name}_n"], cap))
                for k, word in enumerate((p[f"{name}_t_tag"], p[f"{name}_c"], p[f"{name}_t_end"])):
                    e.st(e.add(p[name], e.add(e.mul(p[f"{name}_n"], 3), k)), word)
                e.set(f"{name}_n", e.add(p[f"{name}_n"], 1))
                e.set(f"{name}_c", p[f"{name}_t_end"])

            e.while_(lambda: e.lt(p[f"{name}_c"], end), child)

        tlv(0, e.ld(G_CN), "sp_cert")
        _ok(e, e.both(e.eq(p["sp_cert_tag"], 0x30), e.eq(p["sp_cert_end"], e.ld(G_CN))))
        children(p["sp_cert_content"], p["sp_cert_end"], "sp_cc", 8)
        _ok(e, e.both(e.eq(p["sp_cc_n"], 3), e.eq(e.ld(p["sp_cc"]), 0x30)))
        e.var("sp_tbs_start", e.ld(e.add(p["sp_cc"], 1)))
        e.var("sp_tbs_end", e.ld(e.add(p["sp_cc"], 2)))
        tlv(p["sp_tbs_start"], p["sp_tbs_end"], "sp_tbs")
        children(p["sp_tbs_content"], p["sp_tbs_end"], "sp_f", 64)
        e.var("sp_ix", e.sel(e.both(e.lt(0, p["sp_f_n"]), e.eq(e.ld(p["sp_f"]), 0xA0)), 6, 5))
        _ok(e, e.both(e.lt(p["sp_ix"], p["sp_f_n"]), e.eq(e.ld(e.add(p["sp_f"], e.mul(p["sp_ix"], 3))), 0x30)))
        e.give(e.add(e.ld(e.add(p["sp_f"], e.add(e.mul(p["sp_ix"], 3), 1))), e.mul(e.ld(e.add(p["sp_f"], e.add(e.mul(p["sp_ix"], 3), 2))), 1 << 32)))
    return _function((), build, tables)


# -- RSA: Montgomery arithmetic over 32-bit limbs ----------------------------------------------------------------------------

def _mont_fn(tables):
    """``mont(a, b, out)``: ``a * b / R mod n`` (CIOS; ``k`` limbs, ``n`` at ``G_NL``, ``-n^-1 mod 2^32`` at ``G_NINV``)."""
    def build(e: E):
        p = e.p
        e.var("mo_k", e.ld(G_K))
        e.var("mo_n", e.ld(G_NL))
        e.var("mo_inv", e.ld(G_NINV))
        e.var("mo_t", e.alloc(e.add(p["mo_k"], 3)))
        _ok(e, e.ne(p["mo_t"], NONE))
        t = p["mo_t"]
        e.for_("mo_z", 0, e.add(p["mo_k"], 2), lambda: e.st(e.add(t, p["mo_z"]), 0))

        def outer():
            e.var("mo_bi", e.ld(e.add(p["b"], p["mo_i"])))
            e.var("mo_c", 0)

            def inner():
                e.var("mo_s", e.add(e.add(e.ld(e.add(t, p["mo_j"])), e.mul(e.ld(e.add(p["a"], p["mo_j"])), p["mo_bi"])), p["mo_c"]))
                e.st(e.add(t, p["mo_j"]), e.and_(p["mo_s"], MASK32))
                e.set("mo_c", e.udiv(p["mo_s"], 1 << 32))

            e.for_("mo_j", 0, p["mo_k"], inner)
            e.var("mo_s2", e.add(e.ld(e.add(t, p["mo_k"])), p["mo_c"]))
            e.st(e.add(t, p["mo_k"]), e.and_(p["mo_s2"], MASK32))
            e.st(e.add(t, e.add(p["mo_k"], 1)), e.udiv(p["mo_s2"], 1 << 32))
            e.var("mo_m", e.and_(e.mul(e.ld(t), p["mo_inv"]), MASK32))
            e.var("mo_s3", e.add(e.ld(t), e.mul(p["mo_m"], e.ld(p["mo_n"]))))
            e.set("mo_c", e.udiv(p["mo_s3"], 1 << 32))

            def reduce():
                e.var("mo_s4", e.add(e.add(e.ld(e.add(t, p["mo_j"])), e.mul(p["mo_m"], e.ld(e.add(p["mo_n"], p["mo_j"])))), p["mo_c"]))
                e.st(e.add(t, e.sub(p["mo_j"], 1)), e.and_(p["mo_s4"], MASK32))
                e.set("mo_c", e.udiv(p["mo_s4"], 1 << 32))

            e.for_("mo_j", 1, p["mo_k"], reduce)
            e.var("mo_s5", e.add(e.ld(e.add(t, p["mo_k"])), p["mo_c"]))
            e.st(e.add(t, e.sub(p["mo_k"], 1)), e.and_(p["mo_s5"], MASK32))
            e.st(e.add(t, p["mo_k"]), e.add(e.ld(e.add(t, e.add(p["mo_k"], 1))), e.udiv(p["mo_s5"], 1 << 32)))

        e.for_("mo_i", 0, p["mo_k"], outer)
        _call(e, "sx_reduce", t, p["out"])
        e.give(1)
    return _function(("a", "b", "out"), build, tables)


def _reduce_fn(tables):
    """``reduce(t, out)``: ``t`` (``k + 1`` limbs, below ``2n``) minus ``n`` when it is at least ``n``, into ``out``."""
    def build(e: E):
        p = e.p
        e.var("rd_k", e.ld(G_K))
        e.var("rd_n", e.ld(G_NL))
        e.var("rd_ge", e.flag(e.ne(e.ld(e.add(p["t"], p["rd_k"])), 0)))

        def compare():
            e.var("rd_j", p["rd_k"])
            e.var("rd_done", 0)
            e.set("rd_ge", 1)  # equal is at least n

            def step():
                e.set("rd_j", e.sub(p["rd_j"], 1))
                e.var("rd_x", e.ld(e.add(p["t"], p["rd_j"])))
                e.var("rd_y", e.ld(e.add(p["rd_n"], p["rd_j"])))
                e.if_(e.ne(p["rd_x"], p["rd_y"]), lambda: (e.set("rd_ge", e.flag(e.lt(p["rd_y"], p["rd_x"]))), e.set("rd_done", 1)))

            e.while_(lambda: e.both(e.lt(0, p["rd_j"]), e.eq(p["rd_done"], 0)), step)

        e.if_(e.eq(p["rd_ge"], 0), compare)

        def subtract():
            e.var("rd_b", 0)

            def limb():
                e.var("rd_d", e.sub(e.sub(e.add(e.ld(e.add(p["t"], p["rd_q"])), 1 << 32), e.ld(e.add(p["rd_n"], p["rd_q"]))), p["rd_b"]))
                e.st(e.add(p["out"], p["rd_q"]), e.and_(p["rd_d"], MASK32))
                e.set("rd_b", e.sub(1, e.udiv(p["rd_d"], 1 << 32)))

            e.for_("rd_q", 0, p["rd_k"], limb)

        e.if_(e.ne(p["rd_ge"], 0), subtract, lambda: e.for_("rd_q", 0, p["rd_k"], lambda: e.st(e.add(p["out"], p["rd_q"]), e.ld(e.add(p["t"], p["rd_q"])))))
        e.give(1)
    return _function(("t", "out"), build, tables)


def _limbs(e: E, at, n, k, name: str, from_input: bool):
    """The big-endian bytes (``n``, one per word, input or arena) as ``k`` little-endian 32-bit limbs into ``name``."""
    p = e.p
    e.var(name, e.alloc(e.add(k, 2)))
    _ok(e, e.ne(p[name], NONE))
    e.for_(f"{name}_z", 0, e.add(k, 1), lambda: e.st(e.add(p[name], p[f"{name}_z"]), 0))
    read = (lambda q: e.rd(e.add(at, q))) if from_input else (lambda q: e.ld(e.add(at, q)))

    def byte():
        e.var(f"{name}_pos", e.sub(e.sub(n, 1), p[f"{name}_q"]))  # the byte's place from the least significant end
        e.var(f"{name}_l", e.add(p[name], e.udiv(p[f"{name}_pos"], 4)))
        e.st(p[f"{name}_l"], e.or_(e.ld(p[f"{name}_l"]), e.mul(read(p[f"{name}_q"]), e.sel(e.eq(e.urem(p[f"{name}_pos"], 4), 0), 1, e.sel(
            e.eq(e.urem(p[f"{name}_pos"], 4), 1), 1 << 8, e.sel(e.eq(e.urem(p[f"{name}_pos"], 4), 2), 1 << 16, 1 << 24))))))

    e.for_(f"{name}_q", 0, n, byte)
    return p[name]


def _sign_fn(tables):
    """``sign(em, out)``: ``em`` (key-size bytes, one per word) raised to the private exponent modulo the modulus, its
    big-endian bytes into ``out``."""
    def build(e: E):
        p = e.p
        e.var("sg_size", e.ld(G_NN))
        e.var("sg_k", e.udiv(e.add(p["sg_size"], 3), 4))
        e.st(G_K, p["sg_k"])
        e.st(G_NL, _limbs(e, e.ld(G_N), p["sg_size"], p["sg_k"], "sg_n", True))
        n0 = e.ld(e.ld(G_NL))
        e.var("sg_n0", n0)
        _ok(e, e.ne(e.and_(p["sg_n0"], 1), 0))  # an odd modulus
        e.var("sg_x", 1)
        for _ in range(5):
            e.set("sg_x", e.and_(e.mul(p["sg_x"], e.sub(2, e.mul(p["sg_n0"], p["sg_x"]))), MASK32))
        e.st(G_NINV, e.and_(e.sub(1 << 32, p["sg_x"]), MASK32))
        # R^2 mod n: 1 doubled 64 k times modulo n.
        e.var("sg_r2", e.alloc(e.add(p["sg_k"], 2)))
        e.var("sg_tmp", e.alloc(e.add(p["sg_k"], 3)))
        _ok(e, e.both(e.ne(p["sg_r2"], NONE), e.ne(p["sg_tmp"], NONE)))
        e.for_("sg_z", 0, p["sg_k"], lambda: e.st(e.add(p["sg_r2"], p["sg_z"]), 0))
        e.st(p["sg_r2"], 1)

        def double():
            e.var("sg_carry", 0)

            def limb():
                e.var("sg_v", e.add(e.mul(e.ld(e.add(p["sg_r2"], p["sg_q"])), 2), p["sg_carry"]))
                e.st(e.add(p["sg_tmp"], p["sg_q"]), e.and_(p["sg_v"], MASK32))
                e.set("sg_carry", e.udiv(p["sg_v"], 1 << 32))

            e.for_("sg_q", 0, p["sg_k"], limb)
            e.st(e.add(p["sg_tmp"], p["sg_k"]), p["sg_carry"])
            _call(e, "sx_reduce", p["sg_tmp"], p["sg_r2"])

        e.for_("sg_i", 0, e.mul(p["sg_k"], 64), double)
        e.var("sg_m", _limbs(e, p["em"], p["sg_size"], p["sg_k"], "sg_ml", False))
        e.var("sg_one", e.alloc(e.add(p["sg_k"], 2)))
        e.var("sg_acc", e.alloc(e.add(p["sg_k"], 2)))
        e.var("sg_xm", e.alloc(e.add(p["sg_k"], 2)))
        _ok(e, e.both(e.ne(p["sg_one"], NONE), e.ne(p["sg_acc"], NONE), e.ne(p["sg_xm"], NONE)))
        e.for_("sg_z", 0, p["sg_k"], lambda: e.st(e.add(p["sg_one"], p["sg_z"]), 0))
        e.st(p["sg_one"], 1)
        _call(e, "sx_mont", p["sg_m"], p["sg_r2"], p["sg_xm"])
        _call(e, "sx_mont", p["sg_one"], p["sg_r2"], p["sg_acc"])
        e.var("sg_d", e.ld(G_D))

        def bit():
            e.var("sg_byte", e.rd(e.add(p["sg_d"], e.udiv(p["sg_b"], 8))))
            e.var("sg_set", e.and_(e.udiv(p["sg_byte"], e.sel(e.eq(e.urem(p["sg_b"], 8), 0), 128, e.sel(e.eq(e.urem(p["sg_b"], 8), 1), 64, e.sel(
                e.eq(e.urem(p["sg_b"], 8), 2), 32, e.sel(e.eq(e.urem(p["sg_b"], 8), 3), 16, e.sel(e.eq(e.urem(p["sg_b"], 8), 4), 8, e.sel(
                    e.eq(e.urem(p["sg_b"], 8), 5), 4, e.sel(e.eq(e.urem(p["sg_b"], 8), 6), 2, 1)))))))), 1))
            _call(e, "sx_mont", p["sg_acc"], p["sg_acc"], p["sg_acc"])
            e.if_(e.ne(p["sg_set"], 0), lambda: _call(e, "sx_mont", p["sg_acc"], p["sg_xm"], p["sg_acc"]))

        e.for_("sg_b", 0, e.mul(e.ld(G_DN), 8), bit)
        _call(e, "sx_mont", p["sg_acc"], p["sg_one"], p["sg_acc"])
        e.for_("sg_q", 0, p["sg_size"], lambda: (e.var("sg_pos", e.sub(e.sub(p["sg_size"], 1), p["sg_q"])), e.st(e.add(p["out"], p["sg_q"]), e.and_(e.udiv(
            e.ld(e.add(p["sg_acc"], e.udiv(p["sg_pos"], 4))), e.sel(e.eq(e.urem(p["sg_pos"], 4), 0), 1, e.sel(e.eq(e.urem(p["sg_pos"], 4), 1), 1 << 8,
                                                                                                          e.sel(e.eq(e.urem(p["sg_pos"], 4), 2), 1 << 16, 1 << 24)))), 255))))
        e.give(1)
    return _function(("em", "out"), build, tables)


# -- the program ----------------------------------------------------------------------------------------------------------

def _frontend(tables):
    def build(e: E):
        p = e.p
        e.st(0, 0)
        e.set_hd(H_ARENA, GENERAL_ARENA_AT)
        e.set_hd(H_ARENA_END, GENERAL_ARENA_END)
        e.var("kt", e.alloc(66))
        _ok(e, e.ne(p["kt"], NONE))
        for k, word in enumerate(SHA_K):
            e.st(e.add(p["kt"], k), word)
        e.st(G_AT + 32, p["kt"])
        # The inputs.
        e.var("apkn", e.rd(0))
        e.st(G_APK, 1)
        e.st(G_APKN, p["apkn"])
        e.var("at", e.add(1, e.udiv(e.add(p["apkn"], 7), 8)))
        for place, size in ((G_N, G_NN), (G_D, G_DN), (G_C, G_CN)):
            e.st(size, e.rd(p["at"]))
            e.st(place, e.add(p["at"], 1))
            e.set("at", e.add(e.add(p["at"], 1), e.ld(size)))
        apk = lambda k: _packed_byte(e, 1, k)  # noqa: E731
        # ``_locate_eocd``: the last end record in the final 65557 bytes, its comment reaching the end exactly.
        e.var("minimum", e.sel(e.lt(65557, p["apkn"]), e.sub(p["apkn"], 65557), 0))
        e.var("eocd", NONE)
        e.var("scan", e.add(p["apkn"], 1))

        def look():
            e.set("scan", e.sub(p["scan"], 1))
            e.var("pos", e.sub(p["scan"], 1))
            hit = e.both(e.le(e.add(p["pos"], 4), p["apkn"]), e.eq(apk(p["pos"]), 0x50), e.eq(apk(e.add(p["pos"], 1)), 0x4B),
                         e.eq(apk(e.add(p["pos"], 2)), 0x05), e.eq(apk(e.add(p["pos"], 3)), 0x06))
            e.if_(hit, lambda: e.set("eocd", p["pos"]))

        e.while_(lambda: e.both(e.eq(p["eocd"], NONE), e.lt(p["minimum"], p["scan"])), look)
        _ok(e, e.both(e.ne(p["eocd"], NONE), e.le(e.add(p["eocd"], 22), p["apkn"])))

        def field(offset, n):
            value = e.c(0)
            for k in reversed(range(n)):
                value = e.add(e.mul(value, 256), apk(e.add(p["eocd"], offset + k)))
            return value

        e.var("comment", field(20, 2))
        _ok(e, e.eq(e.add(e.add(p["eocd"], 22), p["comment"]), p["apkn"]))
        _ok(e, e.both(e.eq(field(4, 2), 0), e.eq(field(6, 2), 0), e.eq(field(8, 2), field(10, 2))))
        e.var("csize", field(12, 4))
        e.var("coff", field(16, 4))
        _ok(e, e.eq(e.add(p["coff"], p["csize"]), p["eocd"]))
        # The content digest over [0, coff), [coff, eocd), [eocd, end): 1 MiB chunks.
        e.var("digests", e.alloc(e.add(e.mul(e.add(e.udiv(p["apkn"], CHUNK_SIZE), 4), 32), 2)))
        _ok(e, e.ne(p["digests"], NONE))
        e.var("chunks", 0)
        for start, stop in ((0, "coff"), ("coff", "eocd"), ("eocd", "apkn")):
            e.var("sec_a", p[start] if isinstance(start, str) else start)
            e.var("sec_b", p[stop])

            def chunk():
                e.var("ch_n", e.sub(p["sec_b"], p["sec_a"]))
                e.if_(e.lt(CHUNK_SIZE, p["ch_n"]), lambda: e.set("ch_n", CHUNK_SIZE))
                sha_init(e)
                sha_byte(e, 0xA5)
                for k in range(4):
                    sha_byte(e, e.and_(e.udiv(p["ch_n"], 1 << (8 * k)) if k else p["ch_n"], 255))
                e.for_("ch_k", 0, p["ch_n"], lambda: sha_byte(e, apk(e.add(p["sec_a"], p["ch_k"]))))
                _call(e, "sx_final", e.add(p["digests"], e.mul(p["chunks"], 32)))
                e.set("chunks", e.add(p["chunks"], 1))
                e.set("sec_a", e.add(p["sec_a"], p["ch_n"]))

            e.while_(lambda: e.lt(p["sec_a"], p["sec_b"]), chunk)
        _ok(e, e.lt(0, p["chunks"]))
        e.var("content", e.alloc(34))
        _ok(e, e.ne(p["content"], NONE))
        sha_init(e)
        sha_byte(e, 0x5A)
        for k in range(4):
            sha_byte(e, e.and_(e.udiv(p["chunks"], 1 << (8 * k)) if k else p["chunks"], 255))
        e.for_("dg_k", 0, e.mul(p["chunks"], 32), lambda: sha_byte(e, e.ld(e.add(p["digests"], p["dg_k"]))))
        _call(e, "sx_final", p["content"])
        # The signed data: the digests, the certificates, no additional attributes.
        e.var("spki", _call(e, "sx_spki"))
        e.var("spki_a", e.and_(p["spki"], MASK32))
        e.var("spki_b", e.udiv(p["spki"], 1 << 32))
        cert_n = e.ld(G_CN)
        signed = Buf(e, "signed", e.add(cert_n, 128))
        signed.u32(4 + 4 + 4 + 32)  # digests: one record of the algorithm and its 32-byte digest, each length-prefixed
        signed.u32(4 + 4 + 32)
        signed.u32(ALGORITHM_ID)
        signed.u32(32)
        signed.words(p["content"], 32)
        signed.u32(e.add(cert_n, 4))
        signed.u32(cert_n)
        signed.inputs(e.ld(G_C), cert_n)
        signed.u32(0)
        # The signature: SHA-256 of the signed data in a DigestInfo, PKCS#1 v1.5 padded to the key size.
        e.var("size", e.ld(G_NN))
        e.var("padding", e.sub(e.sub(p["size"], len(DIGEST_INFO_PREFIX) + 32), 3))
        _ok(e, e.both(e.le(len(DIGEST_INFO_PREFIX) + 32 + 3 + 8, p["size"])))  # a key too small: the bootstrap's error
        em = Buf(e, "em", p["size"])
        em.byte(0)
        em.byte(1)
        e.for_("em_k", 0, p["padding"], lambda: em.byte(0xFF))
        em.byte(0)
        for byte in DIGEST_INFO_PREFIX:
            em.byte(byte)
        e.var("sd_digest", e.alloc(34))
        _ok(e, e.ne(p["sd_digest"], NONE))
        _call(e, "sx_hash", signed.at, signed.n, p["sd_digest"])
        em.words(p["sd_digest"], 32)
        e.var("signature", e.alloc(e.add(p["size"], 2)))
        _ok(e, e.ne(p["signature"], NONE))
        _call(e, "sx_sign", em.at, p["signature"])
        # The signer, the v2 value, the signing block.
        e.var("spkin", e.sub(p["spki_b"], p["spki_a"]))
        e.var("signer_n", e.add(e.add(e.add(4, signed.n), e.add(16, p["size"])), e.add(4, p["spkin"])))
        e.var("value_n", e.add(4, e.add(4, p["signer_n"])))
        e.var("pair_n", e.add(4, p["value_n"]))
        e.var("block_size", e.add(p["pair_n"], 32))
        e.var("block_total", e.add(p["block_size"], 8))
        _ok(e, e.le(e.add(p["coff"], p["block_total"]), MASK32))
        e.st(IMAGE_AT + 2, 0)
        _call(e, "sx_copy", 0, p["coff"])

        def le(value, n: int):
            e.var("le_v", value)
            for k in range(n):
                put(e, e.and_(e.udiv(p["le_v"], 1 << (8 * k)) if k else p["le_v"], 255))

        le(p["block_size"], 8)
        le(p["pair_n"], 8)
        le(V2_BLOCK_ID, 4)
        le(e.add(4, p["signer_n"]), 4)  # the signers sequence
        le(p["signer_n"], 4)
        le(signed.n, 4)
        e.for_("o_k", 0, signed.n, lambda: put(e, e.ld(e.add(signed.at, p["o_k"]))))
        le(e.add(12, p["size"]), 4)  # the signatures sequence
        le(e.add(8, p["size"]), 4)
        le(ALGORITHM_ID, 4)
        le(p["size"], 4)
        e.for_("o_k", 0, p["size"], lambda: put(e, e.ld(e.add(p["signature"], p["o_k"]))))
        le(p["spkin"], 4)
        e.for_("o_k", p["spki_a"], p["spki_b"], lambda: put(e, e.rd(e.add(e.ld(G_C), p["o_k"]))))
        le(p["block_size"], 8)
        for byte in MAGIC:
            put(e, byte)
        _call(e, "sx_copy", p["coff"], e.add(p["eocd"], 16))
        le(e.add(p["coff"], p["block_total"]), 4)
        _call(e, "sx_copy", e.add(p["eocd"], 20), p["apkn"])
        e.st(IMAGE_AT, 1)
        e.st(IMAGE_AT + 1, 0)
        e.st(0, 1)
        e.give(1)
    return _function((), build, tables)


def build_signer_program():
    """``(reader, function)``: the APK signer program's store and its entry."""
    tables = None
    objects: list = []
    _FN.clear()

    def add(name, made):
        function, items = made
        objects.extend(items)
        _FN[name] = function
        return function

    for name, builder in (("sx_compress", _compress_fn), ("sx_byte", _byte_fn), ("sx_final", _final_fn), ("sx_hash", _hash_words_fn),
                          ("sx_put", _put_fn), ("sx_copy", _copy_fn), ("sx_tlv", _tlv_fn), ("sx_spki", _spki_fn), ("sx_reduce", _reduce_fn),
                          ("sx_mont", _mont_fn), ("sx_sign", _sign_fn)):
        add(name, builder(tables))
    program = add("frontend", _frontend(tables))
    return program_store(program, x86_64_linux_exec_target(), tuple(objects)), program


_PROGRAM = NativeProgram(STORE_PATH, build_signer_program, "apk-signer")
load_signer_program = _PROGRAM.load
write_signer_store = _PROGRAM.write
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


del hashlib
