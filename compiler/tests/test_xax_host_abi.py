"""xax-host-v1: portable host memory (commit, reserve, free) lowered per x86-64 target.

One program allocates a page, stores four bytes, sums them back, frees the page and exits with the sum.  On Linux it
must compile to exactly the image of the same program written with the mmap/munmap syscall declarations (munmap's
length is the released view type's extent), with the reference and with the XAX general program.  On PE it imports
VirtualAlloc/VirtualFree and runs natively on Windows; the PE program also allocates and frees a page through its own
kernel32 declarations, which the XAX general program imports xax-host-v1 calls through.  Any other name is not owned
by either target (NATIVE-FOREIGN-ABI).
"""

from __future__ import annotations

import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xax_compiler import (
    XAX_HOST_ABI, ForeignAllocatorContract, ForeignDeallocatorContract, Kind, Operation, StoreReader, XaxError, bits_type,
    foreign_function_symbol, heap_view_type, object_with_refs, verify_store, write_store, x86_64_linux_exec_target,
    x86_64_windows_pe_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, run_linux_executable
from xax_platform import win32_kernel32_api

B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)
DATA = b"XAX!"
STATUS = sum(DATA) & 0xFF
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def host_alloc(api, name=b"commit"):
    return foreign_function_symbol(b"host", name, (B64, api.memory_effect), (api.bytes_rw, api.heap_owner, api.memory_effect),
                                   abi=XAX_HOST_ABI, allocator=ForeignAllocatorContract((0,), 0, 1, 4096, True))


def host_free(api, extent, name=None):
    return foreign_function_symbol(b"host", name or b"free", (api.bytes_rw, heap_view_type(extent), api.memory_effect),
                                   (B64, api.memory_effect), abi=XAX_HOST_ABI, deallocator=ForeignDeallocatorContract(0, 1))


def program(host: bool, windows: bool = False, free_name=None):
    """Sum DATA through one heap page; ``host`` picks xax-host-v1 over the Linux syscalls."""
    api = linux_api()
    exit_call = win32_kernel32_api().exit_process if windows else api.exit_group
    allocate = host_alloc(api) if host else api.mmap_anonymous
    release = host_free(api, 4096, free_name) if host else api.munmap_view(api.bytes_rw, 4096)
    graph = GraphBuilder()
    graph.track(*api.types)
    block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), memory), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=allocate)
    pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (api.bytes_rw, heap_view_type(4096), api.memory_effect), attributes=(4096, 1))
    total = block.const(B32, 0)
    for offset, byte in enumerate(DATA):
        address = block.op1(Operation.ADDRESS_OFFSET, (pointer,), api.bytes_rw, attributes=(offset,))
        memory = block.op1(Operation.STORE_BITS_LE, (address, block.const(B8, byte), memory), api.memory_effect, attributes=(1, 1))
    for offset in range(len(DATA)):
        address = block.op1(Operation.ADDRESS_OFFSET, (pointer,), api.bytes_rw, attributes=(offset,))
        got, memory = block.op(Operation.LOAD_BITS_LE, (address, memory), (B8, api.memory_effect), attributes=(1, 1))
        total = block.op1(Operation.ADD_WRAP, (total, block.op1(Operation.INT_ZERO_EXTEND, (got,), B32)), B32)
    _result, memory = block.op(Operation.CALL_FOREIGN, (pointer, view, memory), (B64, api.memory_effect), entity=release)
    kernel32 = ()
    if windows:
        win = win32_kernel32_api()
        page = heap_view_type(4096)
        free = win.virtual_free_view(page, win.heap_ptr_rw)
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 0), block.const(B64, 4096), block.const(B32, 0x3000), block.const(B32, 4), memory),
                                      (win.heap_ptr_rw, win.heap_resource, api.memory_effect), entity=win.virtual_alloc)
        pointer, view, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (win.heap_ptr_rw, page, api.memory_effect), attributes=(4096, 1))
        memory = block.op(Operation.CALL_FOREIGN, (pointer, block.const(B64, 0), block.const(B32, 0x8000), view, memory), (B32, api.memory_effect), entity=free)[1]
        kernel32 = (*win.types, win.virtual_alloc, free)
    status = block.op1(Operation.BIT_AND, (total, block.const(B32, 0xFF)), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=exit_call)
    block.ret(status, process, fs, memory)
    entry = graph.function((api.process_effect, api.filesystem_effect, api.memory_effect), (B32, api.process_effect, api.filesystem_effect, api.memory_effect))
    if not windows:
        target = x86_64_linux_exec_target()
        return program_store(entry, target, tuple(graph.objects.values())), entry, target
    target = x86_64_windows_pe_target()
    module = object_with_refs(Kind.MODULE, [entry, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    by_cid = {o.cid: o for o in (*graph.objects.values(), *kernel32, exit_call, entry, target, module, root)}
    kept, pending = {}, [root.cid]
    while pending:
        cid = pending.pop()
        if cid not in kept:
            kept[cid] = by_cid[cid]
            pending.extend(kept[cid].references)
    return StoreReader(write_store(root.cid, list(kept.values()))), entry, target


class HostAbiTests(unittest.TestCase):
    def test_linux_lowers_to_the_syscall_image(self):
        from xax_selfhost_x86_64_general import native_general

        frontends = ("python", "xax") if native_general() is not None else ("python",)
        for frontend in frontends:
            images = []
            for host in (True, False):
                reader, entry, target = program(host)
                images.append(compile_linux_executable(reader, entry.cid, target.cid, frontend=frontend))
            with self.subTest(frontend=frontend):
                self.assertEqual(images[0].data, images[1].data)
                if LINUX_X86_64:
                    self.assertEqual(run_linux_executable(images[0].data).returncode, STATUS)

    def test_other_names_reject(self):
        from xax_pe import compile_pe_executable

        for windows in (False, True):
            reader, entry, target = program(True, windows=windows, free_name=b"free:4096")
            with self.subTest(windows=windows), self.assertRaises(XaxError) as caught:
                if windows:
                    compile_pe_executable(reader, entry.cid, target, frontend="python")
                else:
                    compile_linux_executable(reader, entry.cid, target.cid, frontend="python")
            self.assertEqual(caught.exception.diagnostic.rule, "NATIVE-FOREIGN-ABI")

    def test_pe_imports_virtual_memory_and_runs(self):
        from xax_pe import compile_pe_executable
        from xax_selfhost_x86_64_general import native_general

        reader, entry, target = program(True, windows=True)
        verify_store(reader)
        for frontend in ("python", "xax") if native_general() is not None else ("python",):
            with self.subTest(frontend=frontend):
                image = compile_pe_executable(reader, entry.cid, target, frontend=frontend)
                self.assertEqual(image.count(b"VirtualAlloc"), 1)
                self.assertEqual(image.count(b"VirtualFree"), 1)
                if sys.platform == "win32":
                    with tempfile.TemporaryDirectory() as work:
                        path = Path(work) / "host.exe"
                        path.write_bytes(image)
                        self.assertEqual(subprocess.run([str(path)], timeout=60).returncode, STATUS)

if __name__ == "__main__":
    unittest.main()
