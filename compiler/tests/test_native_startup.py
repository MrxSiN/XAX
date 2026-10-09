"""Start-up cost of the XAX-hosted components (ADR-248, ADR-250): lazily zeroed views, atomic cache entries, and
``xax_native.prepare``.  None of it changes what a component computes."""
from __future__ import annotations

import ctypes
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

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


class CacheWriteTests(unittest.TestCase):
    """ADR-250: entries are published whole by rename; a failed write leaves nothing behind."""

    def test_concurrent_writers_publish_one_whole_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "entry.bin"
            payload = os.urandom(1 << 20)
            seen, stop = [], threading.Event()

            def reader():
                while not stop.is_set():
                    try:
                        seen.append(path.read_bytes() == payload)
                    except FileNotFoundError:
                        pass

            watcher = threading.Thread(target=reader)
            watcher.start()
            writers = [threading.Thread(target=xax_native.cache_write, args=(path, payload)) for _ in range(8)]
            for writer in writers:
                writer.start()
            for writer in writers:
                writer.join()
            stop.set()
            watcher.join()
            self.assertEqual(path.read_bytes(), payload)
            self.assertTrue(all(seen))
            self.assertEqual(sorted(item.name for item in Path(directory).iterdir()), ["entry.bin"])

    def test_an_unwritable_cache_reports_false_and_leaves_no_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "entry.bin"
            target.mkdir()  # os.replace cannot put a file over a directory
            self.assertFalse(xax_native.cache_write(target, b"x"))
            self.assertEqual([item.name for item in Path(directory).iterdir()], ["entry.bin"])
            self.assertFalse(xax_native.cache_write(Path(directory) / "missing" / "entry.bin", b"x"))


class PrepareTests(unittest.TestCase):
    """ADR-250: ``prepare`` readies every component image, sequentially in-process or in parallel child processes."""

    def test_unknown_components_are_refused(self):
        with self.assertRaises(ValueError):
            xax_native.prepare(components=["no-such-component"])

    def test_hosts_without_native_images_report_unavailable(self):
        with mock.patch.object(xax_native, "native_host", return_value="not this host"):
            result = xax_native.prepare(parallel=True)
        self.assertEqual(list(result), list(xax_native.PREPARE_COMPONENTS))
        self.assertTrue(all(entry["status"] == "unavailable" and entry["reason"] == "not this host" for entry in result.values()))

    @unittest.skipUnless(NATIVE, "the native components run on Linux x86-64")
    def test_parallel_prepare_leaves_every_image_cached(self):
        result = xax_native.prepare(parallel=True)
        self.assertEqual(list(result), list(xax_native.PREPARE_COMPONENTS))
        for component, entry in result.items():
            with self.subTest(component=component):
                self.assertIn(entry["status"], ("cached", "lowered"), entry.get("reason"))
                self.assertEqual(entry["authority"]["actual_authority"], "xax")
                self.assertFalse(entry["authority"]["fallback_occurred"])
        again = xax_native.prepare(parallel=True)
        self.assertEqual({entry["status"] for entry in again.values()}, {"cached"})
        self.assertEqual({entry["store"]["status"] for entry in again.values() if "store" in entry}, {"memoized"})
        digests = {component: entry["authority"]["native_artifact_digest"] for component, entry in result.items()}
        self.assertEqual({component: entry["authority"]["native_artifact_digest"] for component, entry in again.items()}, digests)

    @unittest.skipUnless(NATIVE, "the native components run on Linux x86-64")
    def test_sequential_prepare_loads_in_this_process(self):
        result = xax_native.prepare()
        for component, entry in result.items():
            with self.subTest(component=component):
                self.assertIn(entry["status"], ("cached", "lowered", "loaded"), entry.get("reason"))
                self.assertEqual(entry["pid"], os.getpid())
        self.assertEqual({entry["status"] for entry in xax_native.prepare().values()}, {"loaded"})

    @unittest.skipUnless(NATIVE, "the native components run on Linux x86-64")
    def test_an_empty_cache_is_filled_with_the_same_images(self):
        """Images lowered by ``prepare``'s children in a fresh cache are the bytes this process loaded."""
        components = list(xax_native.PREPARE_DECODERS)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            with mock.patch.dict(os.environ, {"XAX_NATIVE_CACHE": directory}):
                result = xax_native.prepare(parallel=True, components=components)
            self.assertEqual({entry["status"] for entry in result.values()}, {"lowered"})
            names = sorted(item.name for item in Path(directory).iterdir())
            self.assertFalse([name for name in names if name.startswith(".tmp-")])
            for component in components:
                with self.subTest(component=component):
                    self.assertEqual(sum(name.startswith(component + "-") for name in names), 1)
                    loaded = xax_native.AUTHORITY.get(component)
                    if loaded and loaded.get("actual_authority") == "xax":
                        self.assertEqual(result[component]["authority"]["native_artifact_digest"], loaded["native_artifact_digest"])


if __name__ == "__main__":
    unittest.main()
