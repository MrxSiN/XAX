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


MEM, RW, R = "win32.memory_effect", "win32.bytes_rw", "win32.bytes_read"


def _com(interface: str, slot: int, inputs: list, outputs: list) -> dict:
    return {"entity": {"win32.com": [interface, slot, ["b64", *inputs, MEM], [*outputs, MEM]]}}


def _dxgi_budget() -> dict:
    """ADR-260: CreateDXGIFactory1 (a carrier-declared dxgi.dll import), IDXGIFactory1::EnumAdapters1(0),
    IUnknown::QueryInterface(IDXGIAdapter3), IDXGIAdapter3::QueryVideoMemoryInfo(0, LOCAL) and IUnknown::Release, all from
    XAX; returns the local-segment Budget or 0.  View layout: IIDs at 0/16, out pointers at 32/40/48, the info at 64."""
    free = lambda effect, token: ["call.foreign", ["B0.n1", ["b64", 0], ["b32", 0x8000], token, effect], ["b32", MEM],  # noqa: E731
                           {"entity": {"win32.virtual_free_view": [RW, 4096]}}]
    load = lambda offset, effect: ["checked.load.bits.le", ["B0.n1", ["b32", offset], effect], ["b64", MEM], {"attrs": [8, 1]}]  # noqa: E731
    at = lambda offset: ["address.offset", ["B0.n1"], [RW], {"attrs": [offset]}]  # noqa: E731
    store = lambda offset, value, effect: ["checked.store.bits.le", ["n1", ["b32", offset], ["b64", value], effect], [MEM], {"attrs": [8, 1]}]  # noqa: E731
    return {
        "format": "xax-construct-v1", "platform": "windows-x86_64", "types": {"buf": {"view": 4096}},
        "functions": [{"name": "budget", "params": [MEM], "returns": ["b64", MEM], "blocks": [
            {"params": [MEM], "nodes": [
                ["call.foreign", [["b64", 0], ["b64", 4096], ["b32", 0x3000], ["b32", 4], "p0"],
                 ["win32.heap_ptr_rw", "win32.heap_resource", MEM], {"entity": "win32.virtual_alloc"}],
                ["heap.view", ["n0", "n0.r1", "n0.r2"], [RW, "buf", MEM], {"attrs": [4096, 1]}],
                store(0, 0x4DBAF26F770AAE78, "n1.r2"), store(8, 0x87B3D1833C2529A8, "n2"),  # IID_IDXGIFactory1
                store(16, 0x43101392645967A4, "n3"), store(24, 0xFD933ECE538098A7, "n4"),  # IID_IDXGIAdapter3
                ["pointer.cast", ["n1"], [R]],
                ["address.offset", ["n1"], [RW], {"attrs": [32]}],
                ["call.foreign", ["n6", "n7", "n5"], ["b32", MEM], {"entity": {"win32.import": ["dxgi.dll", "CreateDXGIFactory1", [R, RW, MEM], ["b32", MEM]]}}],
                ["int.compare", ["n8", ["b32", 0]], ["b1"], {"attrs": ["ne"]}]],
             "end": ["cbr", "n9", 6, [["b64", 0], "n8.r1", "n1.r1"], 1, ["n8.r1", "n1.r1"]]},
            {"params": [MEM, "buf"], "nodes": [
                load(32, "p0"), at(40),
                ["call.foreign", ["n0", ["b32", 0], "n1", "n0.r1"], ["b32", MEM], _com("IDXGIFactory1", 12, ["b32", RW], ["b32"])],
                ["int.compare", ["n2", ["b32", 0]], ["b1"], {"attrs": ["ne"]}]],
             "end": ["cbr", "n3", 4, ["n2.r1", "p1"], 2, ["n2.r1", "p1"]]},
            {"params": [MEM, "buf"], "nodes": [
                load(40, "p0"), at(16), ["pointer.cast", ["n1"], [R]], at(48),
                ["call.foreign", ["n0", "n2", "n3", "n0.r1"], ["b32", MEM], _com("IUnknown", 0, [R, RW], ["b32"])],
                ["call.foreign", ["n0", "n4.r1"], ["b32", MEM], _com("IUnknown", 2, [], ["b32"])],
                ["int.compare", ["n4", ["b32", 0]], ["b1"], {"attrs": ["ne"]}]],
             "end": ["cbr", "n6", 4, ["n5.r1", "p1"], 3, ["n5.r1", "p1"]]},
            {"params": [MEM, "buf"], "nodes": [
                load(48, "p0"), at(64),
                ["call.foreign", ["n0", ["b32", 0], ["b32", 0], "n1", "n0.r1"], ["b32", MEM], _com("IDXGIAdapter3", 14, ["b32", "b32", RW], ["b32"])],
                ["call.foreign", ["n0", "n2.r1"], ["b32", MEM], _com("IUnknown", 2, [], ["b32"])],
                load(64, "n3.r1"),
                ["int.compare", ["n2", ["b32", 0]], ["b1"], {"attrs": ["eq"]}],
                ["int.zero.extend", ["n5"], ["b64"]],
                ["mul.wrap", ["n4", "n6"], ["b64"]]],
             "end": ["br", 5, ["n7", "n4.r1", "p1"]]},
            {"params": [MEM, "buf"], "nodes": [], "end": ["br", 5, [["b64", 0], "p0", "p1"]]},
            {"params": ["b64", MEM, "buf"], "nodes": [
                load(32, "p1"),
                ["call.foreign", ["n0", "n0.r1"], ["b32", MEM], _com("IUnknown", 2, [], ["b32"])]],
             "end": ["br", 6, ["p0", "n1.r1", "p2"]]},
            # Owner and effect facts reach a block only through its parameters, so the view token travels with the
            # memory effect; the single exit frees it (one consumer per token).
            {"params": ["b64", MEM, "buf"], "nodes": [free("p1", "p2")], "end": ["ret", ["p0", "n0.r1"]]}]}],
        "package": {"name": "xaxdxgi", "entries": {"lib": "budget"}, "release": "lib", "exports": {"LocalBudget": "budget"}}}


def _oracle_budget() -> int:
    """The same query through ctypes vtable calls: an independent reading of adapter 0's local Budget."""
    import ctypes

    def guid(text: str):
        import uuid
        return (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(text).bytes_le)

    def method(obj, slot: int, *types):
        vtable = ctypes.cast(ctypes.cast(obj, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
        return ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *types)(vtable[slot])

    factory, adapter, adapter3 = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    info = (ctypes.c_uint64 * 4)()
    assert ctypes.windll.dxgi.CreateDXGIFactory1(guid("770aae78-f26f-4dba-a829-253c83d1b387"), ctypes.byref(factory)) == 0
    assert method(factory, 12, ctypes.c_uint, ctypes.c_void_p)(factory, 0, ctypes.byref(adapter)) == 0
    assert method(adapter, 0, ctypes.c_void_p, ctypes.c_void_p)(adapter, guid("645967a4-1392-4310-a798-8053ce3e93fd"), ctypes.byref(adapter3)) == 0
    assert method(adapter3, 14, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p)(adapter3, 0, 0, info) == 0
    for obj in (adapter3, adapter, factory):
        method(obj, 2)(obj)
    return info[0]


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

    def test_com_and_import_declarations(self):
        """ADR-260: the entities decode to win64-c imports and com:<Interface> methods; malformed ones reject."""
        from xax_compiler import bits_type, decode_com_slot, decode_foreign_function, win64_com_method

        constructed = construct(_dxgi_budget())
        image = build(constructed.reader, constructed.release_request.cid).artifact
        self.assertIn(b"dxgi.dll", image)
        self.assertIn(b"CreateDXGIFactory1", image)
        self.assertNotIn(b"vtable:", image)  # methods are vtable reads, never imports
        self.assertNotIn(b"com:", image)
        self.assertIn(bytes.fromhex("488b01ff9070000000"), image)  # mov rax, [rcx]; call [rax + 8*14]
        self.assertEqual((decode_com_slot(b"vtable:14"), decode_com_slot(b"vtable:014"), decode_com_slot(b"slot:1")), (14, None, None))
        for bad in (["../x.dll", "F", [], ["b32"]], ["dxgi.dll", "F;", [], ["b32"]]):
            request = _dll()
            request["functions"][2]["blocks"][0]["nodes"] = [["call.foreign", [], ["b32"], {"entity": {"win32.import": bad}}]]
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                construct(request)
        for bad in (["IUnknown", -1, ["b64"], ["b32"]], ["IUnknown", 2, ["b32"], ["b32"]], ["IUnknown", 2, [], ["b32"]]):
            request = _dll()
            request["functions"][2]["blocks"][0]["nodes"] = [["call.foreign", [], ["b32"], {"entity": {"win32.com": bad}}]]
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                construct(request)
        declaration = decode_foreign_function(win64_com_method(b"IUnknown", 2, (bits_type(64),), ()))
        self.assertEqual((declaration.abi, declaration.library, declaration.name), (b"win64-c", b"com:IUnknown", b"vtable:2"))

    @unittest.skipUnless(WINDOWS_X86_64, "requires a Windows x86-64 host")
    def test_dxgi_budget_from_xax(self):
        import ctypes
        import tempfile

        constructed = construct(_dxgi_budget())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "xaxdxgi.dll")
            path.write_bytes(build(constructed.reader, constructed.release_request.cid).artifact)
            library = ctypes.WinDLL(str(path))
            try:
                library.LocalBudget.restype = ctypes.c_uint64
                budget = library.LocalBudget()
                expected = _oracle_budget()
                self.assertGreater(budget, 0)
                self.assertEqual(budget, expected)
                self.assertEqual(library.LocalBudget(), _oracle_budget())  # no leaked or double-released references
            finally:
                ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(library._handle))


if __name__ == "__main__":
    unittest.main()
