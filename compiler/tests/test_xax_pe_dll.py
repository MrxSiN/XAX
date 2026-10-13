"""ADR-259: PE32+ DLLs with win64-c exports and no DllMain, built from xax-construct-v1."""
from __future__ import annotations

import copy
import platform
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from xax_build import build  # noqa: E402
from xax_construct import construct  # noqa: E402

WINDOWS_X86_64 = sys.platform == "win32" and platform.machine().lower() in ("x86_64", "amd64")


def _dll() -> dict:
    return {
        "format": "xax-construct-v1", "platform": "windows-x86_64", "types": {},
        "functions": [
            {"name": "add2", "params": ["b64", "b64"], "returns": ["b64"],
             "blocks": [{"params": ["b64", "b64"], "nodes": [["add.wrap", ["p0", "p1"], ["b64"]]], "end": ["ret", ["n0"]]}]},
            {"name": "add3", "params": ["b64", "b64", "b64"], "returns": ["b64"],
             "blocks": [{"params": ["b64", "b64", "b64"], "nodes": [
                 ["call.direct", ["p0", "p1"], ["b64"], {"entity": {"fn": "add2"}}],
                 ["call.direct", ["n0", "p2"], ["b64"], {"entity": {"fn": "add2"}}]], "end": ["ret", ["n1"]]}]},
            {"name": "answer", "params": [], "returns": ["b32"],
             "blocks": [{"params": [], "nodes": [], "end": ["ret", [["b32", 42]]]}]}],
        "package": {"name": "xaxdll", "entries": {"lib": "add3"}, "release": "lib",
                    "exports": {"Add3": "add3", "Answer": "answer"}}}


def _export_names(image: bytes) -> list[bytes]:
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    optional = pe + 24
    export_rva = struct.unpack_from("<I", image, optional + 112)[0]
    sections = optional + struct.unpack_from("<H", image, pe + 20)[0]

    def offset(rva: int) -> int:
        for index in range(struct.unpack_from("<H", image, pe + 6)[0]):
            _, vsize, va, _, raw = struct.unpack_from("<8sIIII", image, sections + 40 * index)
            if va <= rva < va + vsize:
                return raw + rva - va
        raise AssertionError(rva)

    count = struct.unpack_from("<I", image, offset(export_rva) + 24)[0]
    names_rva = struct.unpack_from("<I", image, offset(export_rva) + 32)[0]
    return [image[offset(n):image.index(b"\0", offset(n))] for n in struct.unpack_from(f"<{count}I", image, offset(names_rva))]


class PeDllTests(unittest.TestCase):
    def test_structure(self):
        constructed = construct(_dll())
        image = build(constructed.reader, constructed.release_request.cid).artifact
        pe = struct.unpack_from("<I", image, 0x3C)[0]
        self.assertTrue(struct.unpack_from("<H", image, pe + 22)[0] & 0x2000)  # IMAGE_FILE_DLL
        self.assertEqual(struct.unpack_from("<I", image, pe + 24 + 16)[0], 0)  # no DllMain
        self.assertEqual(_export_names(image), [b"Add3", b"Answer"])
        self.assertEqual(image, build(construct(_dll()).reader, construct(_dll()).release_request.cid).artifact)

    def test_rejections(self):
        for mutate in (
            lambda r: r["package"]["exports"].update(Add3="missing"),
            lambda r: r["package"]["exports"].pop("Add3"),  # release entry not exported
            lambda r: r.update(platform="linux-x86_64"),
        ):
            request = _dll()
            mutate(request)
            with self.subTest(), self.assertRaises(ValueError):
                construct(request)

    @unittest.skipUnless(WINDOWS_X86_64, "requires a Windows x86-64 host")
    def test_load_and_call(self):
        import ctypes
        import tempfile

        constructed = construct(copy.deepcopy(_dll()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "xaxdll.dll")
            path.write_bytes(build(constructed.reader, constructed.release_request.cid).artifact)
            library = ctypes.WinDLL(str(path))
            try:
                library.Add3.restype = ctypes.c_uint64
                library.Add3.argtypes = (ctypes.c_uint64,) * 3
                library.Answer.restype = ctypes.c_uint32
                self.assertEqual(library.Add3(1, 2, 2**64 - 1), 2)
                self.assertEqual(library.Add3(10, 20, 30), 60)
                self.assertEqual(library.Answer(), 42)
            finally:
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(library._handle))


if __name__ == "__main__":
    unittest.main()
