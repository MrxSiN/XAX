"""Hosted x86-64 Windows PE32+: XAX semantics -> direct executable -> process.

The fixture performs real kernel32 calls through loader-bound imports (console
write from stack storage, heap allocate/free under the verified heap-owner
contract), a direct call into a looping function, and returns the exit code.
"""
from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xax_compiler import (
    Block,
    IntCompare,
    Kind,
    OpaqueKind,
    Node,
    Operation,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    call_contract,
    constant,
    foreign_function_symbol,
    function,
    graph_fragment,
    heap_view_type,
    memory_effect_type,
    object_with_refs,
    opaque_type,
    pointer_type,
    stack_owner_type,
    verify_store,
    write_store,
    x86_64_windows_general_target,
    x86_64_windows_pe_target,
)
from xax_pe import emit_pe_executable
from xax_platform import win32_kernel32_api
from xax_x86_64 import compile_native_bound_target, run_native

R = ValueRef.node_result
P = ValueRef.parameter


def N(node: int, result: int = 0) -> ValueRef:
    return ValueRef.node_result(0, node, result)

WINDOWS_X64 = sys.platform == "win32" and platform.machine().lower() in ("amd64", "x86_64")


def _sum_to():
    """sum_to(n) = 1 + ... + n through a block-parameter loop."""
    b1, b32 = bits_type(1), bits_type(32)
    zero, one = constant(b32, 0), constant(b32, 1)
    graph = graph_fragment([
        Block((b32,), (Node(Operation.CONSTANT, (), (b32,), entity=zero), Node(Operation.CONSTANT, (), (b32,), entity=one)),
              Terminator.branch(1, (R(0, 1), R(0, 0), P(0, 0)))),
        Block((b32, b32, b32), (Node(Operation.INT_COMPARE, (P(1, 0), P(1, 2)), (b1,), attributes=(IntCompare.ULE,)),),
              Terminator.conditional_branch(R(1, 0), 2, (P(1, 0), P(1, 1), P(1, 2)), 3, (P(1, 1),))),
        Block((b32, b32, b32), (Node(Operation.CONSTANT, (), (b32,), entity=one),
                                Node(Operation.ADD_WRAP, (P(2, 1), P(2, 0)), (b32,)),
                                Node(Operation.ADD_WRAP, (P(2, 0), R(2, 0)), (b32,))),
              Terminator.branch(1, (R(2, 2), R(2, 1), P(2, 2)))),
        Block((b32,), (), Terminator.return_((P(3, 0),))),
    ])
    return function(graph, (b32,), (b32,)), [b1, b32, zero, one, graph]


def _squares_sum(api, count=16):
    """Fill a 16 x b32 heap array with i*i in one loop, sum it in another.

    The array is a proven heap view over zero-filled VirtualAlloc pages; every
    access is a checked dynamic-offset load/store; VirtualFree consumes the view.
    """
    b1, b32, b64, mem = bits_type(1), api.b32, api.b64, api.memory_effect
    elem_ptr = pointer_type(b32, 3, 4, space=2)
    view = heap_view_type(64)
    free = api.virtual_free_view(view, elem_ptr)
    c = {v: constant(b32, v) for v in {0, 1, 4, 16, count, 0x3000, 0x8000}}
    c64 = {v: constant(b64, v) for v in (0, 64)}
    K = lambda v: Node(Operation.CONSTANT, (), (b32,), entity=c[v])
    K64 = lambda v: Node(Operation.CONSTANT, (), (b64,), entity=c64[v])
    vptr = R(0, 5, 0)
    blocks = [
        Block((mem,), (
            K64(0), K64(64), K(0x3000), K(4),
            Node(Operation.CALL_FOREIGN, (R(0, 0), R(0, 1), R(0, 2), R(0, 3), P(0, 0)), (api.heap_ptr_rw, api.heap_resource, mem), entity=api.virtual_alloc),
            Node(Operation.HEAP_VIEW, (R(0, 4, 0), R(0, 4, 1), R(0, 4, 2)), (elem_ptr, view, mem), attributes=(64, 16)),
            K(0),
        ), Terminator.branch(1, (R(0, 6), R(0, 5, 1), R(0, 5, 2)))),
        # store loop: (i, view token, memory); `count` > 16 must hit the runtime bounds trap
        Block((b32, view, mem), (K(count), Node(Operation.INT_COMPARE, (P(1, 0), R(1, 0)), (b1,), attributes=(IntCompare.ULT,))),
              Terminator.conditional_branch(R(1, 1), 2, (P(1, 0), P(1, 1), P(1, 2)), 3, (P(1, 1), P(1, 2)))),
        Block((b32, view, mem), (
            K(4), Node(Operation.MUL_WRAP, (P(2, 0), R(2, 0)), (b32,)),
            Node(Operation.MUL_WRAP, (P(2, 0), P(2, 0)), (b32,)),
            Node(Operation.CHECKED_STORE_BITS_LE, (vptr, R(2, 1), R(2, 2), P(2, 2)), (mem,), attributes=(4, 1)),
            K(1), Node(Operation.ADD_WRAP, (P(2, 0), R(2, 4)), (b32,)),
        ), Terminator.branch(1, (R(2, 5), P(2, 1), R(2, 3)))),
        Block((view, mem), (K(0),), Terminator.branch(4, (R(3, 0), R(3, 0), P(3, 0), P(3, 1)))),
        # load loop: (i, acc, view token, memory)
        Block((b32, b32, view, mem), (K(16), Node(Operation.INT_COMPARE, (P(4, 0), R(4, 0)), (b1,), attributes=(IntCompare.ULT,))),
              Terminator.conditional_branch(R(4, 1), 5, (P(4, 0), P(4, 1), P(4, 2), P(4, 3)), 6, (P(4, 1), P(4, 2), P(4, 3)))),
        Block((b32, b32, view, mem), (
            K(4), Node(Operation.MUL_WRAP, (P(5, 0), R(5, 0)), (b32,)),
            Node(Operation.CHECKED_LOAD_BITS_LE, (vptr, R(5, 1), P(5, 3)), (b32, mem), attributes=(4, 1)),
            Node(Operation.ADD_WRAP, (P(5, 1), R(5, 2, 0)), (b32,)),
            K(1), Node(Operation.ADD_WRAP, (P(5, 0), R(5, 4)), (b32,)),
        ), Terminator.branch(4, (R(5, 5), R(5, 3), P(5, 2), R(5, 2, 1)))),
        Block((b32, view, mem), (
            K64(0), K(0x8000),
            Node(Operation.CALL_FOREIGN, (vptr, R(6, 0), R(6, 1), P(6, 1), P(6, 2)), (b32, mem), entity=free),
            Node(Operation.ADD_WRAP, (P(6, 0), R(6, 2, 0)), (b32,)),
        ), Terminator.return_((R(6, 3), R(6, 2, 1)))),
    ]
    graph = graph_fragment(blocks)
    fn = function(graph, (mem,), (b32, mem))
    return fn, [b1, elem_ptr, view, free, *c.values(), *c64.values(), graph]


def _dispatch_table(store_local_pointer=False):
    """A two-entry function-pointer table in stack memory, called through loaded entries.

    add1(10) + times3(10) = 41.  Function addresses are provenance-free, so storing
    and reloading them needs no lifetime coupling (ADR-082).  With
    ``store_local_pointer`` the table also tries to store a stack address (rejected).
    """
    b32 = bits_type(32)
    fn = opaque_type(OpaqueKind.FUNCTION)
    fnptr = pointer_type(fn, 1, 8, space=2)  # READ
    table_ptr = pointer_type(fnptr, 3, 8)    # READ_WRITE stack storage of function pointers
    owner, mem = stack_owner_type(), memory_effect_type()
    one, three, zero, eight, ten = (constant(b32, v) for v in (1, 3, 0, 8, 10))

    def unary(op, k):
        g = graph_fragment([Block((b32,), (Node(Operation.CONSTANT, (), (b32,), entity=k), Node(op, (P(0, 0), R(0, 0)), (b32,))), Terminator.return_((R(0, 1),)))])
        return function(g, (b32,), (b32,)), g

    add1, add1_graph = unary(Operation.ADD_WRAP, one)
    times3, times3_graph = unary(Operation.MUL_WRAP, three)
    contract = call_contract((b32,), (b32,), may_return=True, may_trap=False)
    K = lambda c: Node(Operation.CONSTANT, (), (b32,), entity=c)
    nodes = [
        Node(Operation.FUNCTION_ADDRESS, (), (fnptr,), entity=add1),                                  # 0
        Node(Operation.FUNCTION_ADDRESS, (), (fnptr,), entity=times3),                                # 1
        Node(Operation.STACK_ALLOC, (), (table_ptr, owner, mem), attributes=(16, 8)),                 # 2
        Node(Operation.ADDRESS_OFFSET, (N(2),), (table_ptr,), attributes=(8,)),                       # 3
        Node(Operation.STORE_BITS_LE, (N(2), N(0), N(2, 2)), (mem,), attributes=(8, 8)),              # 4
        Node(Operation.STORE_BITS_LE, (N(3), N(1), N(4)), (mem,), attributes=(8, 8)),                 # 5
        K(zero), K(eight), K(ten),                                                                     # 6 7 8
        Node(Operation.CHECKED_LOAD_BITS_LE, (N(2), N(6), N(5)), (fnptr, mem), attributes=(8, 1)),    # 9
        Node(Operation.CHECKED_LOAD_BITS_LE, (N(2), N(7), N(9, 1)), (fnptr, mem), attributes=(8, 1)), # 10
        Node(Operation.STACK_END, (N(2, 1), N(10, 1)), ()),                                           # 11
        Node(Operation.CALL_INDIRECT, (N(9), N(8)), (b32,), entity=contract),                         # 12
        Node(Operation.CALL_INDIRECT, (N(10), N(8)), (b32,), entity=contract),                        # 13
        Node(Operation.ADD_WRAP, (N(12), N(13)), (b32,)),                                             # 14
    ]
    objects = [b32, fn, fnptr, table_ptr, owner, mem, one, three, zero, eight, ten, add1_graph, add1, times3_graph, times3, contract]
    if store_local_pointer:
        # Store the table's own (local-provenance) address into a pointer slot: OI-37 still open.
        slot_ptr = pointer_type(table_ptr, 3, 8)
        nodes[11:11] = [
            Node(Operation.STACK_ALLOC, (), (slot_ptr, owner, mem), attributes=(8, 8)),
            Node(Operation.STORE_BITS_LE, (N(11), N(2), N(11, 2)), (mem,), attributes=(8, 8)),
        ]
        objects.append(slot_ptr)
    graph = graph_fragment([Block((), tuple(nodes), Terminator.return_((N(len(nodes) - 1),)))])
    fn_dispatch = function(graph, (), (b32,))
    return fn_dispatch, [*objects, graph]


def hosted_fixture(api=None, count=16):
    api = api or win32_kernel32_api()
    b8, b32, b64 = api.b8, api.b32, api.b64
    msg_ptr = pointer_type(b8, 3, 1)  # READ_WRITE
    owner = stack_owner_type()
    loop, loop_objects = _sum_to()
    squares, squares_objects = _squares_sum(api, count)
    dispatch, dispatch_objects = _dispatch_table()
    consts = [
        constant(b32, 0xFFFFFFF5),  # STD_OUTPUT_HANDLE
        constant(b8, ord("X")), constant(b8, ord("A")), constant(b8, ord("\n")),
        constant(b32, 4), constant(b32, 0), constant(b64, 0), constant(b64, 64), constant(b32, 10),
    ]
    std, cx, ca, cnl, four, z32, z64, size, ten = consts
    nodes = (
        Node(Operation.CONSTANT, (), (b32,), entity=std),                                   # 0
        Node(Operation.CALL_FOREIGN, (N(0, 0), P(0, 0)), (b64, api.process_effect), entity=api.get_std_handle),  # 1
        Node(Operation.STACK_ALLOC, (), (msg_ptr, owner, api.memory_effect), attributes=(4, 1)),  # 2
        Node(Operation.ADDRESS_OFFSET, (N(2, 0),), (msg_ptr,), attributes=(1,)),            # 3
        Node(Operation.ADDRESS_OFFSET, (N(2, 0),), (msg_ptr,), attributes=(2,)),            # 4
        Node(Operation.ADDRESS_OFFSET, (N(2, 0),), (msg_ptr,), attributes=(3,)),            # 5
        Node(Operation.CONSTANT, (), (b8,), entity=cx),                                     # 6
        Node(Operation.CONSTANT, (), (b8,), entity=ca),                                     # 7
        Node(Operation.CONSTANT, (), (b8,), entity=cnl),                                    # 8
        Node(Operation.STORE_BITS_LE, (N(2, 0), N(6, 0), N(2, 2)), (api.memory_effect,), attributes=(1, 1)),  # 9
        Node(Operation.STORE_BITS_LE, (N(3, 0), N(7, 0), N(9, 0)), (api.memory_effect,), attributes=(1, 1)),  # 10
        Node(Operation.STORE_BITS_LE, (N(4, 0), N(6, 0), N(10, 0)), (api.memory_effect,), attributes=(1, 1)),  # 11
        Node(Operation.STORE_BITS_LE, (N(5, 0), N(8, 0), N(11, 0)), (api.memory_effect,), attributes=(1, 1)),  # 12
        Node(Operation.POINTER_CAST, (N(2, 0),), (api.byte_ptr_read,)),                    # 13
        Node(Operation.STACK_ALLOC, (), (api.u32_ptr_rw, owner, api.memory_effect), attributes=(4, 4)),  # 14
        Node(Operation.CONSTANT, (), (b32,), entity=four),                                  # 15
        Node(Operation.CONSTANT, (), (b64,), entity=z64),                                   # 16
        Node(Operation.CALL_FOREIGN, (N(1, 0), N(13, 0), N(15, 0), N(14, 0), N(16, 0), P(0, 1), N(14, 2)),
             (b32, api.filesystem_effect, api.memory_effect), entity=api.write_file),       # 17
        Node(Operation.STACK_END, (N(14, 1), N(17, 2)), ()),                                 # 18
        Node(Operation.STACK_END, (N(2, 1), N(12, 0)), ()),                                  # 19
        Node(Operation.CALL_FOREIGN, (N(1, 1),), (b64, api.process_effect), entity=api.get_process_heap),  # 20
        Node(Operation.CONSTANT, (), (b32,), entity=z32),                                   # 21
        Node(Operation.CONSTANT, (), (b64,), entity=size),                                  # 22
        Node(Operation.CALL_FOREIGN, (N(20, 0), N(21, 0), N(22, 0), P(0, 2)),
             (api.heap_ptr_rw, api.heap_resource, api.memory_effect), entity=api.heap_alloc),  # 23
        Node(Operation.CALL_FOREIGN, (N(20, 0), N(21, 0), N(23, 0), N(23, 1), N(23, 2)),
             (b32, api.memory_effect), entity=api.heap_free),                               # 24
        Node(Operation.CONSTANT, (), (b32,), entity=ten),                                   # 25
        Node(Operation.CALL_DIRECT, (N(25, 0),), (b32,), entity=loop),                      # 26
        Node(Operation.ADD_WRAP, (N(26, 0), N(17, 0)), (b32,)),                             # 27
        Node(Operation.ADD_WRAP, (N(27, 0), N(24, 0)), (b32,)),                             # 28
        Node(Operation.CALL_DIRECT, (P(0, 3),), (b32, api.memory_effect), entity=squares),  # 29
        Node(Operation.ADD_WRAP, (N(28, 0), N(29, 0)), (b32,)),                             # 30
        Node(Operation.CALL_DIRECT, (), (b32,), entity=dispatch),                           # 31
        Node(Operation.ADD_WRAP, (N(30, 0), N(31, 0)), (b32,)),                             # 32
        Node(Operation.CALL_FOREIGN, (N(32, 0), N(20, 1)), (api.process_effect,), entity=api.exit_process),  # 33
    )
    # Two independent memory-effect proofs: heap/stack work and the squares array.
    params = (api.process_effect, api.filesystem_effect, api.memory_effect, api.memory_effect)
    graph = graph_fragment([Block(params, nodes, Terminator.return_((N(32, 0), N(33, 0), N(17, 1), N(24, 1), N(29, 1))))])
    entry = function(graph, params, (b32, api.process_effect, api.filesystem_effect, api.memory_effect, api.memory_effect))
    target = x86_64_windows_pe_target()
    module = object_with_refs(Kind.MODULE, [entry, loop, squares, dispatch, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [*api.types, msg_ptr, owner, *consts, *api.symbols, *loop_objects, loop, *squares_objects, squares, *dispatch_objects, dispatch, graph, entry, target, module, root]
    return StoreReader(write_store(root.cid, list({o.cid: o for o in objects}.values()))), entry, target


class HostedPeTests(unittest.TestCase):
    def test_pe_is_deterministic_and_binds_only_declared_imports(self):
        reader, entry, target = hosted_fixture()
        verify_store(reader)
        image = compile_native_bound_target(reader, entry.cid, target)
        names = sorted({name for _, _, name in image.imports})
        self.assertEqual(names, [b"ExitProcess", b"GetProcessHeap", b"GetStdHandle", b"HeapAlloc", b"HeapFree", b"VirtualAlloc", b"VirtualFree", b"WriteFile"])
        pe = emit_pe_executable(image)
        self.assertEqual(pe, emit_pe_executable(compile_native_bound_target(reader, entry.cid, target)))
        self.assertEqual(pe[:2], b"MZ")
        self.assertNotIn(b"msvcrt", pe.lower())
        self.assertNotIn(b"ucrtbase", pe.lower())
        with self.assertRaises(XaxError):
            run_native(image, ())  # raw images cannot satisfy imports

    @unittest.skipUnless(WINDOWS_X64, "requires Windows x86-64 host")
    def test_pe_executes_as_windows_process(self):
        reader, entry, target = hosted_fixture()
        pe = emit_pe_executable(compile_native_bound_target(reader, entry.cid, target))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "xax_hosted.exe"
            path.write_bytes(pe)
            completed = subprocess.run([str(path)], capture_output=True, timeout=30)
        self.assertEqual(completed.stdout, b"XAX\n")
        # sum_to(10) + WriteFile + HeapFree + (sum of i*i, i<16, through the heap array) + VirtualFree
        self.assertEqual(completed.returncode, 55 + 1 + 1 + 1240 + 1 + 41)  # + add1(10) + times3(10) via table

    @unittest.skipUnless(WINDOWS_X64, "requires Windows x86-64 host")
    def test_out_of_bounds_heap_store_traps(self):
        reader, entry, target = hosted_fixture(count=17)
        verify_store(reader)  # dynamic offsets are checked at runtime, not rejected statically
        pe = emit_pe_executable(compile_native_bound_target(reader, entry.cid, target))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "xax_oob.exe"
            path.write_bytes(pe)
            completed = subprocess.run([str(path)], capture_output=True, timeout=30)
        self.assertEqual(completed.returncode & 0xFFFFFFFF, 0xC000001D)  # STATUS_ILLEGAL_INSTRUCTION from ud2

    def test_memory_frontier_call_rejects_effect_fork(self):
        api = win32_kernel32_api()
        squares, objects = _squares_sum(api)
        mem, b32 = api.memory_effect, api.b32
        call = lambda: Node(Operation.CALL_DIRECT, (P(0, 0),), (b32, mem), entity=squares)
        graph = graph_fragment([Block((mem,), (call(), call()), Terminator.return_((N(0, 0), N(1, 1))))])
        entry = function(graph, (mem,), (b32, mem))
        module = object_with_refs(Kind.MODULE, [entry, squares])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        everything = [*api.types, *api.symbols, *objects, squares, graph, entry, module, root]
        reader = StoreReader(write_store(root.cid, list({o.cid: o for o in everything}.values())))
        with self.assertRaises(XaxError) as raised:
            verify_store(reader)
        self.assertIn(raised.exception.diagnostic.rule, ("MEMORY-EFFECT-LINEAR", "RESOURCE-LINEAR-CONTINUATION"))

    def test_store_load_forwarding_respects_branch_targets(self):
        from xax_x86_64 import _Assembler, _load, _store
        asm = _Assembler()
        asm.emit(_store(0, 8)); asm.emit(_load(0, 8))      # same register: reload deleted
        asm.emit(_store(0, 16)); asm.emit(_load(1, 16))    # other register: mov rcx, rax
        asm.emit(_store(0, 24)); asm.label("target"); asm.emit(_load(0, 24))  # branch target kept
        asm.relative(bytes((0xE9,)), "target")
        asm.forward_stores()
        code, _ = asm.finish()
        self.assertEqual(code[:5] + code[5:13], _store(0, 8) + _store(0, 16) + bytes.fromhex("4889c1"))
        self.assertEqual(code[13:23], _store(0, 24) + _load(0, 24))
        self.assertEqual(int.from_bytes(code[-4:], "little", signed=True), 18 - len(code))  # jump still hits the kept load

    def test_hosted_loops_and_heap_views_are_register_resident(self):
        reader, entry, target = hosted_fixture()
        image = compile_native_bound_target(reader, entry.cid, target)
        offsets = sorted(offset for _, offset in image.function_offsets)
        loop, _ = _sum_to()
        start = dict(image.function_offsets)[loop.cid]
        end = next((o for o in offsets if o > start), len(image.code))
        self.assertNotIn(bytes((0x48, 0x81, 0xEC)), image.code[start:end])  # sum_to needs no frame (no sub rsp)

    def test_local_pointer_store_rejects_until_oi37(self):
        dispatch, objects = _dispatch_table(store_local_pointer=True)
        module = object_with_refs(Kind.MODULE, [dispatch])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, list({o.cid: o for o in [*objects, dispatch, module, root]}.values())))
        with self.assertRaises(XaxError) as raised:
            verify_store(reader)
        self.assertEqual(raised.exception.diagnostic.rule, "MEMORY-POINTER-STORE-LOCAL-PROVENANCE")

    def test_foreign_abi_is_owned_by_one_backend(self):
        b32 = bits_type(32)
        android = foreign_function_symbol(b"libc.so", b"getpid", (b32,), (b32,))
        graph = graph_fragment([Block((b32,), (Node(Operation.CALL_FOREIGN, (P(0, 0),), (b32,), entity=android),), Terminator.return_((R(0, 0),)))])
        entry = function(graph, (b32,), (b32,))
        target = x86_64_windows_pe_target()
        module = object_with_refs(Kind.MODULE, [entry, target])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, android, graph, entry, target, module, root]))
        verify_store(reader)
        with self.assertRaises(XaxError) as raised:
            compile_native_bound_target(reader, entry.cid, target)
        self.assertEqual(raised.exception.diagnostic.code, "XAX.FOREIGN.ABI")

    def test_raw_load_image_target_rejects_foreign_calls(self):
        reader, entry, _ = hosted_fixture()
        with self.assertRaises(XaxError):
            compile_native_bound_target(reader, entry.cid, x86_64_windows_general_target())

    def test_pe_entry_must_be_parameterless(self):
        b32 = bits_type(32)
        graph = graph_fragment([Block((b32,), (), Terminator.return_((P(0, 0),)))])
        entry = function(graph, (b32,), (b32,))
        target = x86_64_windows_pe_target()
        module = object_with_refs(Kind.MODULE, [entry, target])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [b32, graph, entry, target, module, root]))
        with self.assertRaises(XaxError):
            emit_pe_executable(compile_native_bound_target(reader, entry.cid, target))


class WineExecutionTests(unittest.TestCase):
    """The hosted fixture under Wine (ADR-095): Wine reimplements the Windows API, it is not Windows."""

    def test_hosted_fixture_executes_and_matches_evidence(self):
        import json
        import tempfile
        from pathlib import Path

        from benchmarks.bench_windows_pe_wine import EVIDENCE_PATH, run_under_wine, wine_executable

        wine = wine_executable()
        if wine is None:
            self.skipTest("wine64 is not installed")
        reader, entry, target = hosted_fixture()
        pe = emit_pe_executable(compile_native_bound_target(reader, entry.cid, target))
        self.assertEqual(json.loads(Path(EVIDENCE_PATH).read_text())["pe_sha256"], hashlib.sha256(pe).hexdigest())
        with tempfile.TemporaryDirectory() as prefix:
            completed = run_under_wine(pe, wine, prefix)
        self.assertEqual((completed.stdout, completed.returncode), (b"XAX\n", 1339 % 256))


class CTwinTests(unittest.TestCase):
    """The C twin of the hosted fixture (MinGW-w64, no CRT) must behave identically under Wine."""

    def test_c_twin_matches_fixture(self):
        import shutil
        import tempfile
        from pathlib import Path

        from benchmarks.bench_windows_pe_c_wine import CC, build_c
        from benchmarks.bench_windows_pe_wine import run_under_wine, wine_executable

        wine = wine_executable()
        if wine is None or shutil.which(CC) is None:
            self.skipTest("wine64 and MinGW-w64 are required")
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as prefix:
            completed = run_under_wine(build_c(Path(directory)).read_bytes(), wine, prefix)
        self.assertEqual((completed.stdout, completed.returncode), (b"XAX\n", 1339 % 256))


def pe_digest() -> str:
    reader, entry, target = hosted_fixture()
    return hashlib.sha256(emit_pe_executable(compile_native_bound_target(reader, entry.cid, target))).hexdigest()


if __name__ == "__main__":
    unittest.main()
