"""Start-up cost of the XAX-hosted components (ADR-248): lazily zeroed views.  None of it changes what a component
computes."""
from __future__ import annotations

import ctypes
import os
import unittest
from pathlib import Path

import xax_native

NATIVE = xax_native.native_host() is None


def _resident_bytes() -> int:
    with open("/proc/self/statm") as handle:
        return int(handle.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


class ZeroedArrayTests(unittest.TestCase):
    """ADR-248: an anonymous mapping gives the same all-zero contents as ``(element * count)()``, page by page."""

    def test_contents_are_zero_until_written(self):
        for element in (ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint8):
            array = xax_native.zeroed_array(element, 3 << 16)
            self.assertEqual(len(array), 3 << 16)
            self.assertEqual(bytes(array), bytes(ctypes.sizeof(array)))
            array[5], array[-1] = 7, 9
            self.assertEqual((array[4], array[5], array[6], array[-1]), (0, 7, 0, 9))
            self.assertEqual(ctypes.addressof(array) % mmap_page(), 0)

    def test_untouched_pages_are_not_resident(self):
        if not Path("/proc/self/statm").exists():
            self.skipTest("UNAVAILABLE: /proc/self/statm")
        before = _resident_bytes()
        array = xax_native.zeroed_array(ctypes.c_uint64, (256 << 20) // 8)  # the typing program's output view
        array[0] = array[len(array) // 2] = array[-1] = 1
        self.assertLess(_resident_bytes() - before, 16 << 20)
        self.assertEqual(sum(array[k] for k in (0, 1, len(array) // 2, len(array) - 2, len(array) - 1)), 3)

    def test_the_array_keeps_its_mapping_alive(self):
        array = xax_native.zeroed_array(ctypes.c_uint64, 1024)
        mapping = array._mapping
        del mapping
        array[1023] = 5
        self.assertEqual(array[1023], 5)
        with self.assertRaises(BufferError):
            array._mapping.close()  # exported to the array: the mapping cannot go away under it

    @unittest.skipUnless(NATIVE, "the native components run on Linux x86-64")
    def test_component_views_are_lazily_zeroed(self):
        import xax_compiler
        from xax_selfhost_verify import native_store_verifier

        components = {"typing": xax_compiler._native_typing(), "store-verifier": native_store_verifier(),
                      "cfg": xax_compiler._native_cfg(), "graph-decoder": xax_compiler._native_graph_decoder(),
                      "store-decoder": xax_compiler._native_store_decoder()}
        for name, component in components.items():
            if component is None:
                continue
            views = [value for value in vars(component).values() if isinstance(value, ctypes.Array) and ctypes.sizeof(value) >= 1 << 20]
            with self.subTest(component=name):
                self.assertGreaterEqual(len(views), 2)
                self.assertTrue(all(hasattr(view, "_mapping") for view in views))


def mmap_page() -> int:
    import mmap

    return mmap.PAGESIZE


if __name__ == "__main__":
    unittest.main()
