"""S15e.6i.3 (ADR-359): the XAX Android program reads libxposed JVM module records as ``json.loads`` does, inflates deflated
branding entries as ``zipfile`` does, and takes layer inputs past 20 MB.

Each case gives one record (raw bytes after the carrier prefix) and the build's external inputs to the bootstrap's
lowering (``_build_libxposed_jvm_apk``) and to the program (``android_with_xax``).  They must agree: the same APK, the
same rejection, or a bootstrap failure that is not a diagnostic (its ``ValueError``, ``TypeError``, ``KeyError``,
``struct.error``, ``zlib.error``, ``BadZipFile`` ...) where the program declines.
"""

from __future__ import annotations

import json
import platform
import struct
import sys
import unittest
import zipfile
import zlib
from io import BytesIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_xax_selfhost_android_jvm import PARAMETERS, _manifest  # noqa: E402

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
BASE = {"package": "org.example.module", "module_class": "org.example.Module", "scopes": ["com.example"], "version_code": 7,
        "version_name": "", "min_sdk": 28, "target_sdk": 35, "dex": [], "libraries": [], "natives": [], "fields": []}
DEX = b"dex\n035\x00" + bytes(range(64))
LIBRARY = bytes(range(256)) * 9


def _digest(data: bytes) -> str:
    from blake3 import blake3

    return blake3(data).hexdigest()


def _zip(entries, method=zipfile.ZIP_DEFLATED, level=None) -> bytes:
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in entries.items():
            archive.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), data, compress_type=method, compresslevel=level)
    return out.getvalue()


def _raw_zip(entries) -> bytes:
    """A ZIP of ``(name, method, data as stored, file size, CRC)`` entries, written as given."""
    out, central = bytearray(), bytearray()
    for name, method, data, size, crc in entries:
        encoded = name.encode()
        offset = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, method, 0, 0x21, crc, len(data), size, len(encoded), 0) + encoded + data
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, method, 0, 0x21, crc, len(data), size, len(encoded), 0, 0, 0, 0, 0,
                               offset) + encoded
    return bytes(out + central + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), len(out), 0))


def _bits(text: str) -> bytes:
    """Bits in stream order (each byte from its least significant bit), as raw deflate reads them."""
    text += "0" * (-len(text) % 8)
    return bytes(int(text[k:k + 8][::-1], 2) for k in range(0, len(text), 8))


def _partial(method: int, chunk: bytes) -> bytes:
    """What ``zipfile``'s decompressor for ``method`` gives for a stream cut to ``chunk``."""
    decompressor = zipfile._get_decompressor(method)
    return decompressor.decompress(chunk)


def _raw_deflate(data: bytes, level: int = 6) -> bytes:
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _reader(payload: bytes, v2: bool = False, params=PARAMETERS):
    """A constructed module whose carrier's record is ``payload``."""
    import xax_android_libxposed_jvm as J
    from xax_compiler import target
    from xax_construct import construct

    prefix = J.PREFIX_V2 if v2 else J.PREFIX
    request = {"format": "xax-construct-v1", "platform": "android-libxposed",
               "functions": [{"name": "main", "params": params, "returns": [], "blocks": [{"params": params, "nodes": [], "end": ["ret", []]}]}],
               "package": {"name": "module", "entries": {"app": "main"}, "release": "app",
                           "android": {"package": "org.example.module", "module_class": "org.example.Module", "scopes": ["com.example"],
                                       "version_code": 7}}}
    with mock.patch.object(J, "libxposed_jvm_module_semantics", lambda module: target(prefix + payload)):
        return construct(request).reader


def _parts(reader):
    from xax_build import decode_package, decode_request, decode_snapshot

    snapshot = decode_snapshot(reader.get(reader.root_cid), reader.get)
    request = decode_request(reader.get(snapshot.request_root), reader.get)
    package_view = decode_package(reader.get(request.package_root), reader.get)
    return package_view, reader.get(request.target_root), dict(package_view.build_entries)[request.build_entry]


def _record(**changes) -> bytes:
    return json.dumps({**BASE, **changes}).encode()


@unittest.skipUnless(LINUX_X86_64, "the XAX Android program runs natively on Linux x86-64")
class SelfhostAndroidRecordTests(unittest.TestCase):
    def agree(self, payload: bytes, inputs=None, v2: bool = False, expect: str | None = None):
        """The bootstrap's and the program's outcomes for one record; returns the shared outcome's kind."""
        import xax_android_libxposed_jvm as J
        from xax_compiler import XaxError
        from xax_selfhost_android import android_with_xax

        reader = _reader(payload, v2)
        package_view, target_object, entry = _parts(reader)
        inputs = dict(inputs or {})
        try:
            reference = ("apk", J._build_libxposed_jvm_apk(reader, package_view, target_object, entry, inputs))
        except XaxError as error:
            reference = ("rejected", error.diagnostic)
        except Exception as error:  # noqa: BLE001 - a failure that is not a diagnostic
            reference = ("failed", type(error).__name__)
        try:
            built = android_with_xax(reader, package_view, target_object, entry, external_inputs=inputs)
            outcome = ("declined", None) if built is None else ("apk", built)
        except XaxError as error:
            outcome = ("rejected", error.diagnostic)
        if reference[0] == "failed":
            self.assertEqual(outcome[0], "declined", f"bootstrap failed with {reference[1]}")
        else:
            self.assertEqual(outcome, reference)
        if expect is not None:
            self.assertEqual(reference[0] if reference[0] != "failed" else "failed", expect)
        return reference[0]

    def test_text(self):
        """Non-ASCII text: in every field, by escape and by UTF-8, astral characters, lone surrogates (a DEX string holds
        one; a manifest or an APK name cannot), and the encodings ``json.detect_encoding`` picks."""
        library = _digest(LIBRARY)
        inputs = {bytes.fromhex(library): LIBRARY}
        rich = dict(package="org.exämple.mödule", module_class="org.exämple.Mödüle\U0001F600", scopes=["cöm.example", "中"],
                    version_name="vé", natives=[["Lorg/é/Pölicy;", "chéck\U0001F600", "(Lorg/é/Ä;)I"]],
                    fields=[["Lorg/é/Stäte;", "cöunt", "I"], ["Lorg/a/B;", "x", "Lorg/é/Ä;"]],
                    libraries=[["lib/arm64-v8a/libpölicy.so", library]])
        cases = {
            "utf-8": (_record(**rich), "apk"),
            "escaped": (json.dumps({**BASE, **rich}, ensure_ascii=True).encode(), "apk"),
            "surrogate name": (_record(natives=[["Lorg/a/P;", "a\ud800b", "()V"]]).replace(b"\\ud800", b"\\ud800"), "apk"),
            "surrogate pair escapes": (_record(module_class="org.a.😀"), "apk"),
            "surrogate in an unused field": (json.dumps({**BASE, "version_name": "\udc00", "scopes": ["\ud800x"]}).encode(), "apk"),
            "surrogate in the package": (json.dumps({**BASE, "package": "org.a\udfff"}).encode(), "failed"),
            "surrogate in a library path": (json.dumps({**BASE, "libraries": [["lib/arm64-v8a/a\ud800.so", library]]}).encode(), "failed"),
            "raw surrogate bytes": (_record(version_name="X").replace(b'"X"', b'"\xed\xa0\x80"'), "apk"),
            "utf-8 bom": (b"\xef\xbb\xbf" + _record(**rich), "apk"),
            "utf-16-le": (json.dumps({**BASE, **rich}, ensure_ascii=False).encode("utf-16-le"), "apk"),
            "utf-16-be bom": (json.dumps({**BASE, **rich}, ensure_ascii=False).encode("utf-16"), "apk"),
            "utf-32-be": (json.dumps({**BASE, **rich}, ensure_ascii=False).encode("utf-32-be"), "apk"),
            "utf-32 bom": (json.dumps({**BASE, **rich}, ensure_ascii=False).encode("utf-32"), "apk"),
            "invalid utf-8": (_record(version_name="X").replace(b'"X"', b'"\xc0\x80"'), "failed"),
            "odd utf-16": (_record().decode().encode("utf-16-le") + b"\x00", "failed"),
        }
        for name, (payload, expect) in cases.items():
            with self.subTest(case=name):
                self.agree(payload, inputs, expect=expect)

    def test_values(self):
        """JSON values of every kind where the bootstrap accepts them, and its failures where it does not."""
        dex = _digest(DEX)
        inputs = {bytes.fromhex(dex): DEX}
        cases = {
            "unused values of every kind": (_record(version_name={"a": [1.5, None, True, {"b": -0.0}], "c": 1e400}, extra=[[], {}, "x", -12]), "apk"),
            "boolean version code": (_record(version_code=True), "apk"),
            "float version code": (_record(version_code=5.9), "apk"),
            "float sdks": (_record(min_sdk=28.5, target_sdk=34.99), "apk"),
            "exponent sdk": (b'{"package":"o.e","module_class":"o.M","scopes":["s"],"version_code":1,"version_name":"","min_sdk":2.8e1,'
                             b'"target_sdk":3.5E+1,"dex":[],"libraries":[],"natives":[]}', "apk"),
            "rounds up to 28": (_record(min_sdk=0).replace(b'"min_sdk": 0', b'"min_sdk": 27.9999999999999982236431605997495353221893310546875'), "apk"),
            "just below 28": (_record(min_sdk=0).replace(b'"min_sdk": 0', b'"min_sdk": 27.9999999999999982236431605997495353221893310546874'), "failed"),
            "huge target": (_record(target_sdk=10 ** 30), "failed"),
            "nan": (_record(min_sdk=0).replace(b'"min_sdk": 0', b'"min_sdk": NaN'), "failed"),
            "negative": (_record(version_code=-3), "failed"),
            "string version": (_record(version_code="7"), "failed"),
            "scopes string": (_record(scopes="abc"), "apk"),
            "scopes object": (_record(scopes={"a": 1, "b": None}), "apk"),
            "scopes truthy": (_record(scopes=[1, True, [0], {"k": 0}, 0.5]), "apk"),
            "scopes falsy": (_record(scopes=["a", 0]), "failed"),
            "scopes empty": (_record(scopes=[]), "failed"),
            "dex object": (_record(dex={dex: None}), "apk"),
            "hex whitespace": (_record(dex=[" " + " ".join(dex[k:k + 2] for k in range(0, 64, 2)) + "\n"]), "apk"),
            "hex split": (_record(dex=[dex[:1] + " " + dex[1:]]), "failed"),
            "short digest": (_record(dex=[dex[:62]]), "failed"),
            "natives objects": (_record(natives=[{"Lorg/a/P;": 0, "run": 0, "(J)V": 0}]), "apk"),
            "natives string": (_record(natives=["abc"]), "failed"),
            "natives arity": (_record(natives=[["Lorg/a/P;", "run"]]), "failed"),
            "late native descriptor": (_record(natives=[["Lorg/a/P;", "run", ["(", ")V"]]]), "failed"),
            "late module class": (_record(module_class=["org", "M"]), "failed"),
            "late field": (_record(fields=[["Lorg/a/S;", 5, "I"]]), "failed"),
            "no fields": (json.dumps({key: value for key, value in BASE.items() if key != "fields"}).encode(), "apk"),
            "null fields": (_record(fields=None), "failed"),
            "duplicate keys": (b'{"version_code": "x", ' + _record()[1:], "apk"),
            "missing key": (json.dumps({key: value for key, value in BASE.items() if key != "version_name"}).encode(), "failed"),
            "big integer": (_record(version_name=10 ** 4299), "apk"),
            "too big an integer": (_record(version_name=0).replace(b'"version_name": 0', b'"version_name": ' + b"9" * 4301), "failed"),
            "deep": (_record(version_name=0).replace(b'"version_name": 0', b'"version_name": ' + b"[" * 3000 + b"]" * 3000), "apk"),
            "whitespace": (b" \t\r\n" + _record().replace(b", ", b" ,\n\t ") + b"\n ", "apk"),
            "trailing comma": (_record()[:-1] + b",}", "failed"),
            "leading zero": (_record(version_code=0).replace(b'"version_code": 0', b'"version_code": 07'), "failed"),
            "extra data": (_record() + b" x", "failed"),
            "control character": (_record(version_name="a\nb").replace(b"\\n", b"\n"), "failed"),
            "bad escape": (_record(version_name="X").replace(b'"X"', b'"\\x"'), "failed"),
            "not an object": (b'["package"]', "failed"),
        }
        for name, (payload, expect) in cases.items():
            with self.subTest(case=name):
                self.agree(payload, inputs, expect=expect)

    def test_missing_inputs_first(self):
        """A record the bootstrap fails on only after ``LIBXPOSED-JVM-INPUTS`` is rejected with that diagnostic first."""
        missing = _digest(b"absent")
        for name, change in (("module class", {"module_class": ["org", "M"]}), ("native descriptor", {"natives": [["Lorg/a/P;", "r", ["("]]]}),
                             ("field", {"fields": [["Lorg/a/S;", None, "I"]]}), ("float version code", {"version_code": 1.5})):
            with self.subTest(case=name):
                self.assertEqual(self.agree(_record(dex=[missing], **change)), "rejected")

    def test_branding_rejections(self):
        """``LIBXPOSED-JVM-BRANDING`` quotes ``sorted(record)``: an object's keys, a string's characters, an array's items."""
        cases = {"object": (_record(), True), "string": (b'"a branding c"', False), "strings": (b'["x", "branding", "a"]', False),
                 "numbers": (b"[3, true, 1, -2, false]", True), "null": (b"[null]", True), "empty": (b"[]", True)}
        for name, (payload, v2) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.agree(payload, v2=v2), "rejected")

    def test_deflated_branding(self):
        """Branding archives whose entries are deflated (stored, fixed and dynamic blocks), and the ways ``zipfile`` and
        zlib read or refuse them."""
        manifest = _manifest()
        resources = bytes(range(256)) * 40 + b"resource text " * 500
        values = b"<resources>" + b"<string name='a'>b</string>" * 300 + b"</resources>"
        whole = {"AndroidManifest.xml": manifest, "resources.arsc": resources, "res/values/strings.xml": values}
        stream = _raw_deflate(values)
        crc = zlib.crc32
        archives = {
            "deflated": (_zip(whole), "apk"),
            "level 0 (stored blocks)": (_zip(whole, level=0), "apk"),
            "level 9": (_zip(whole, level=9), "apk"),
            "fixed codes": (_zip({"AndroidManifest.xml": manifest, "res/a.txt": b"ab"}), "apk"),
            "mixed methods": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)),
                                        ("res/v.xml", 8, stream, len(values), crc(values))]), "apk"),
            "truncated stream": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)),
                                           ("res/v.xml", 8, stream[:40], len(zlib.decompressobj(-15).decompress(stream[:40])),
                                            crc(zlib.decompressobj(-15).decompress(stream[:40])))]), "apk"),
            "shorter file size": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)),
                                            ("res/v.xml", 8, stream, 100, crc(values[:100]))]), "apk"),
            "trailing data": (_raw_zip([("AndroidManifest.xml", 8, _raw_deflate(manifest) + b"junk", len(manifest), crc(manifest))]), "apk"),
            "bad crc": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)), ("res/v.xml", 8, stream, len(values), 0)]),
                        "failed"),
            "bad block type": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)), ("res/v.xml", 8, b"\x07\x00", 0, 0)]),
                               "failed"),
            "too far back": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)),
                                       ("res/v.xml", 8, _bits("110" "0000001" "00000"), 0, 0)]), "failed"),
            "deflated manifest": (_raw_zip([("AndroidManifest.xml", 8, _raw_deflate(manifest), len(manifest), crc(manifest))]), "apk"),
            "bzip2": (_zip(whole, method=zipfile.ZIP_BZIP2), "apk"),
            "bzip2 level 1": (_zip(whole, method=zipfile.ZIP_BZIP2, level=1), "apk"),
            "bzip2 runs": (_zip({"AndroidManifest.xml": manifest, "res/r.bin": b"\0" * 70000 + b"ab" * 5000 + bytes(range(256)) * 3},
                                method=zipfile.ZIP_BZIP2), "apk"),
            "lzma": (_zip(whole, method=zipfile.ZIP_LZMA), "apk"),
            "lzma runs": (_zip({"AndroidManifest.xml": manifest, "res/r.bin": b"\0" * 70000 + b"abc" * 5000 + bytes(range(256)) * 3},
                               method=zipfile.ZIP_LZMA), "apk"),
            "lzma short header": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)), ("res/v", 14, b"\x09\x14", 0, 0)]),
                                  "apk"),
            "lzma bad properties": (_raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), crc(manifest)),
                                              ("res/v", 14, b"\x09\x14\x05\x00\xff\x00\x00\x10\x00\x00\x00", 0, 0)]), "failed"),
        }
        for name, (archive, expect) in archives.items():
            with self.subTest(case=name):
                digest = _digest(archive)
                self.assertEqual(self.agree(_record(branding=digest), {bytes.fromhex(digest): archive}, v2=True), expect)

    def test_fuzz(self):
        """Seeded random records (every field given values of random kinds, texts past ASCII, random encodings and byte
        mutations) and random deflated branding entries (levels, strategies, bit flips, truncations, file sizes)."""
        import random

        rng = random.Random(359)
        dex = _digest(DEX)
        texts = ["", "a", "org.example.module", "org..x", "lib/arm64-v8a/libx.so", "Lorg/a/P;", "(I)V", "()V", "é", "\u4e2d\U0001F600",
                 "\ud800", "Lorg/é/Ä;", "branding", "/", ";", "(", dex, " " + dex, dex.upper()]

        def scalar():
            return rng.choice([rng.choice(texts), rng.randrange(-5, 40), rng.choice([28, 35, 7, 0x7FFFFFFF, 2 ** 31, 10 ** 20]),
                               rng.choice([0.0, -0.0, 28.0, 28.5, 1e300, 34.999]), True, False, None])

        def value(depth=0):
            kind = rng.randrange(10)
            if depth < 3 and kind == 0:
                return [value(depth + 1) for _ in range(rng.randrange(4))]
            if depth < 3 and kind == 1:
                return {rng.choice(texts): value(depth + 1) for _ in range(rng.randrange(4))}
            return scalar()

        good = {"package": ["org.example.module", "o.é"], "module_class": ["org.example.Module", "o.Ä"], "scopes": [["a"], "ab", {"x": 1}],
                "version_code": [1, 7, True, 3.5], "version_name": ["", None, 1.5], "min_sdk": [28, 30, 28.5], "target_sdk": [35, 34.9, 10 ** 12],
                "dex": [[], [dex], {dex: 0}], "libraries": [[]], "natives": [[], [["Lorg/a/P;", "r", "(I)V"]], [{"Lo/é;": 0, "ü": 0, "()V": 0}]],
                "fields": [[], [["Lorg/a/S;", "n", "I"]]]}
        for trial in range(160):
            record = {}
            for key, choices in good.items():
                roll = rng.random()
                if roll < 0.08:
                    continue
                record[key] = rng.choice(choices) if roll < 0.8 else value()
            payload = json.dumps(record, ensure_ascii=rng.random() < 0.5, indent=rng.choice([None, 0, 2])).encode("utf-8", "surrogatepass")
            if rng.random() < 0.15:
                payload = payload.decode("utf-8", "surrogatepass").encode(rng.choice(["utf-16-le", "utf-16", "utf-32-be"]), "surrogatepass")
            if rng.random() < 0.15 and payload:
                at = rng.randrange(len(payload))
                payload = payload[:at] + bytes([rng.randrange(256)]) + payload[at + 1:]
            with self.subTest(trial=trial):
                self.agree(payload, {bytes.fromhex(dex): DEX}, v2=rng.random() < 0.1)
        manifest = _manifest()
        for trial in range(160):
            data = bytes(rng.choice(b"abcde<>/ ") for _ in range(rng.randrange(0, 3000))) + rng.randbytes(rng.randrange(0, 200))
            method = rng.choice([8, 8, 12, 14])
            if method == 8:
                compressor = zlib.compressobj(rng.randrange(0, 10), zlib.DEFLATED, -15, 9, rng.choice([0, 1, 2, 3, 4]))
                stream = bytearray(compressor.compress(data) + compressor.flush())
            else:
                with zipfile.ZipFile(BytesIO(_zip({"x": data}, method=method))) as made:
                    info = made.infolist()[0]
                    raw = made.fp.getvalue()
                    begin = info.header_offset + 30 + len(info.filename.encode()) + struct.unpack_from("<H", raw, info.header_offset + 28)[0]
                    stream = bytearray(raw[begin:begin + info.compress_size])
            decompress = (lambda chunk: zlib.decompressobj(-15).decompress(chunk)) if method == 8 else (lambda chunk: _partial(method, chunk))
            size, crc = len(data), zlib.crc32(data)
            roll = rng.random()
            if roll < 0.3 and stream:
                for _ in range(rng.randrange(1, 4)):
                    stream[rng.randrange(len(stream))] ^= 1 << rng.randrange(8)
            elif roll < 0.5:
                stream = stream[:rng.randrange(len(stream) + 1)]
                try:
                    partial = decompress(bytes(stream))
                    size, crc = len(partial), zlib.crc32(partial)
                except Exception:  # noqa: BLE001 - a stream cut where the decoder fails: kept as it is
                    pass
            elif roll < 0.65:
                size = rng.randrange(size + 1)
                crc = zlib.crc32(data[:size])
            archive = _raw_zip([("AndroidManifest.xml", 0, manifest, len(manifest), zlib.crc32(manifest)), ("res/r.bin", method, bytes(stream), size, crc)])
            digest = _digest(archive)
            with self.subTest(archive=trial):
                self.agree(_record(branding=digest), {bytes.fromhex(digest): archive}, v2=True)

    def test_large_inputs(self):
        """A library and a DEX input past the former 20 MB writer region."""
        import random

        rng = random.Random(359)
        library = rng.randbytes(26 << 20)
        dex = b"dex\n035\x00" + rng.randbytes(9 << 20)
        inputs = {bytes.fromhex(_digest(library)): library, bytes.fromhex(_digest(dex)): dex}
        self.assertEqual(self.agree(_record(dex=[_digest(dex)], libraries=[["lib/arm64-v8a/libbig.so", _digest(library)]]), inputs), "apk")


if __name__ == "__main__":
    unittest.main()
