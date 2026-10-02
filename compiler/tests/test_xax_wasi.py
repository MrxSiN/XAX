"""wasm32 WASI command module: XAX semantics -> direct wasm with host imports -> Node WASI host.

The host writes argc/argv-buffer size into XAX stack storage through
``args_sizes_get``; XAX reads them back, runs a looping direct call, and ends
with an explicit ``proc_exit``.
"""
from __future__ import annotations

import shutil
import unittest

from xax_compiler import (
    Block,
    Kind,
    Node,
    Operation,
    Permission,
    StoreReader,
    Terminator,
    ValueRef,
    XaxError,
    bits_type,
    constant,
    foreign_function_symbol,
    function,
    graph_fragment,
    object_with_refs,
    pointer_type,
    stack_owner_type,
    verify_store,
    wasm32_general_target,
    wasm32_wasi_target,
    write_store,
)
from xax_platform import wasi_preview1_api
from xax_wasm import compile_wasm_bound_target, run_wasi_isolated
from test_xax_pe import _sum_to

N = lambda node, result=0: ValueRef.node_result(0, node, result)
P = ValueRef.parameter
ARGS = ("xax", "one", "two")  # argc 3, argv buffer 12 bytes


def wasi_fixture():
    api = wasi_preview1_api()
    b32, ptr, mem = api.b32, api.u32_ptr_rw, api.memory_effect
    owner = stack_owner_type()
    zero, ten, one, four = constant(b32, 0), constant(b32, 10), constant(b32, 1), constant(b32, 4)
    b8 = bits_type(8)
    byte_ptr = pointer_type(b8, Permission.READ_WRITE, 1)
    cx, ca, cnl = constant(b8, ord("X")), constant(b8, ord("A")), constant(b8, ord("\n"))
    loop, loop_objects = _sum_to()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (ptr, owner, mem), attributes=(8, 4)),                       # 0
        Node(Operation.ADDRESS_OFFSET, (N(0),), (ptr,), attributes=(4,)),                              # 1
        Node(Operation.CONSTANT, (), (b32,), entity=zero),                                              # 2
        Node(Operation.STORE_BITS_LE, (N(0), N(2), N(0, 2)), (mem,), attributes=(4, 4)),              # 3
        Node(Operation.STORE_BITS_LE, (N(1), N(2), N(3)), (mem,), attributes=(4, 4)),                 # 4
        Node(Operation.CALL_FOREIGN, (N(0), N(1), N(4)), (b32, mem), entity=api.args_sizes_get),      # 5
        Node(Operation.LOAD_BITS_LE, (N(0), N(5, 1)), (b32, mem), attributes=(4, 4)),                 # 6 argc
        Node(Operation.LOAD_BITS_LE, (N(1), N(6, 1)), (b32, mem), attributes=(4, 4)),                 # 7 buffer size
        Node(Operation.STACK_END, (N(0, 1), N(7, 1)), ()),                                              # 8
        Node(Operation.CONSTANT, (), (b32,), entity=ten),                                               # 9
        Node(Operation.MUL_WRAP, (N(6), N(9)), (b32,)),                                                 # 10
        Node(Operation.ADD_WRAP, (N(10), N(7)), (b32,)),                                                # 11
        Node(Operation.CALL_DIRECT, (N(9),), (b32,), entity=loop),                                     # 12
        Node(Operation.ADD_WRAP, (N(11), N(12)), (b32,)),                                               # 13
        Node(Operation.ADD_WRAP, (N(13), N(5)), (b32,)),                                                # 14 + errno
        # stdout "XAX\n": message bytes, then one iovec holding the message's exposed address.
        Node(Operation.STACK_ALLOC, (), (byte_ptr, owner, mem), attributes=(4, 1)),                  # 15
        Node(Operation.ADDRESS_OFFSET, (N(15),), (byte_ptr,), attributes=(1,)),                        # 16
        Node(Operation.ADDRESS_OFFSET, (N(15),), (byte_ptr,), attributes=(2,)),                        # 17
        Node(Operation.ADDRESS_OFFSET, (N(15),), (byte_ptr,), attributes=(3,)),                        # 18
        Node(Operation.CONSTANT, (), (b8,), entity=cx),                                                 # 19
        Node(Operation.CONSTANT, (), (b8,), entity=ca),                                                 # 20
        Node(Operation.CONSTANT, (), (b8,), entity=cnl),                                                # 21
        Node(Operation.STORE_BITS_LE, (N(15), N(19), N(15, 2)), (mem,), attributes=(1, 1)),           # 22
        Node(Operation.STORE_BITS_LE, (N(16), N(20), N(22)), (mem,), attributes=(1, 1)),              # 23
        Node(Operation.STORE_BITS_LE, (N(17), N(19), N(23)), (mem,), attributes=(1, 1)),              # 24
        Node(Operation.STORE_BITS_LE, (N(18), N(21), N(24)), (mem,), attributes=(1, 1)),              # 25
        Node(Operation.POINTER_ADDRESS, (N(15),), (b32,), attributes=(1,)),                            # 26 exposed
        Node(Operation.STACK_ALLOC, (), (ptr, owner, mem), attributes=(12, 4)),                       # 27 iovec + nwritten
        Node(Operation.ADDRESS_OFFSET, (N(27),), (ptr,), attributes=(4,)),                             # 28
        Node(Operation.ADDRESS_OFFSET, (N(27),), (ptr,), attributes=(8,)),                             # 29
        Node(Operation.CONSTANT, (), (b32,), entity=four),                                              # 30
        Node(Operation.STORE_BITS_LE, (N(27), N(26), N(27, 2)), (mem,), attributes=(4, 4)),           # 31 iov.buf
        Node(Operation.STORE_BITS_LE, (N(28), N(30), N(31)), (mem,), attributes=(4, 4)),              # 32 iov.len
        Node(Operation.STORE_BITS_LE, (N(29), N(2), N(32)), (mem,), attributes=(4, 4)),               # 33 nwritten = 0
        Node(Operation.POINTER_CAST, (N(27),), (api.u32_ptr_read,)),                                   # 34
        Node(Operation.CONSTANT, (), (b32,), entity=one),                                               # 35 fd 1, 1 iovec
        Node(Operation.CALL_FOREIGN, (N(35), N(34), N(35), N(29), N(33), N(25)), (b32, mem, mem), entity=api.fd_write),  # 36
        Node(Operation.STACK_END, (N(27, 1), N(36, 1)), ()),                                            # 37
        Node(Operation.STACK_END, (N(15, 1), N(36, 2)), ()),                                            # 38
        Node(Operation.ADD_WRAP, (N(14), N(36)), (b32,)),                                               # 39 + errno
        Node(Operation.CALL_FOREIGN, (N(39), P(0, 0)), (api.process_effect,), entity=api.proc_exit),   # 40
    )
    graph = graph_fragment([Block((api.process_effect,), nodes, Terminator.return_((N(40),)))])
    entry = function(graph, (api.process_effect,), (api.process_effect,))
    target = wasm32_wasi_target()
    module = object_with_refs(Kind.MODULE, [entry, loop, target])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects = [*api.types, *api.symbols, owner, zero, ten, one, four, b8, byte_ptr, cx, ca, cnl, *loop_objects, loop, graph, entry, target, module, root]
    return StoreReader(write_store(root.cid, list({o.cid: o for o in objects}.values()))), entry, target


class WasiTests(unittest.TestCase):
    def test_module_imports_only_declared_wasi_functions(self):
        reader, entry, target = wasi_fixture()
        verify_store(reader)
        image = compile_wasm_bound_target(reader, entry.cid, target)
        self.assertEqual(image.module, compile_wasm_bound_target(reader, entry.cid, target).module)
        for name in (b"wasi_snapshot_preview1", b"args_sizes_get", b"fd_write", b"proc_exit", b"_start", b"memory"):
            self.assertIn(name, image.module)

    @unittest.skipUnless(shutil.which("node"), "requires Node.js WASI host")
    def test_wasi_command_executes(self):
        reader, entry, target = wasi_fixture()
        code, stdout = run_wasi_isolated(compile_wasm_bound_target(reader, entry.cid, target), ARGS)
        self.assertEqual((code, stdout), (3 * 10 + 12 + 55 + 0 + 0, b"XAX\n"))  # argc*10 + argv bytes + sum_to(10) + errnos

    def test_address_exposure_requires_waiver_and_live_storage(self):
        api = wasi_preview1_api()
        owner = stack_owner_type()
        for waiver, end_first in ((0, False), (1, True)):
            nodes = [Node(Operation.STACK_ALLOC, (), (api.u32_ptr_rw, owner, api.memory_effect), attributes=(4, 4))]
            if end_first:
                nodes.append(Node(Operation.STACK_END, (N(0, 1), N(0, 2)), ()))
            nodes.append(Node(Operation.POINTER_ADDRESS, (N(0),), (api.b32,), attributes=(waiver,)))
            if not end_first:
                nodes.append(Node(Operation.STACK_END, (N(0, 1), N(0, 2)), ()))
            graph = graph_fragment([Block((), tuple(nodes), Terminator.return_((N(1 if not end_first else 2),)))])
            entry = function(graph, (), (api.b32,))
            module = object_with_refs(Kind.MODULE, [entry])
            root = object_with_refs(Kind.PROGRAM_ROOT, [module])
            reader = StoreReader(write_store(root.cid, [api.b32, api.u32_ptr_rw, owner, api.memory_effect, graph, entry, module, root]))
            with self.assertRaises(XaxError) as raised:
                verify_store(reader)
            self.assertEqual(raised.exception.diagnostic.rule, "MEMORY-LIFETIME-LIVE" if end_first else "MEMORY-ADDRESS-EXPOSE-WAIVER")

    def test_core_profile_rejects_foreign_calls(self):
        reader, entry, _ = wasi_fixture()
        with self.assertRaises(XaxError):
            compile_wasm_bound_target(reader, entry.cid, wasm32_general_target())

    def test_wasm_rejects_other_foreign_abi(self):
        api = wasi_preview1_api()
        bad = foreign_function_symbol(b"kernel32.dll", b"ExitProcess", (api.b32, api.process_effect), (api.process_effect,), abi=b"win64-c")
        zero = constant(api.b32, 0)
        graph = graph_fragment([Block((api.process_effect,), (
            Node(Operation.CONSTANT, (), (api.b32,), entity=zero),
            Node(Operation.CALL_FOREIGN, (N(0), P(0, 0)), (api.process_effect,), entity=bad),
        ), Terminator.return_((N(1),)))])
        entry = function(graph, (api.process_effect,), (api.process_effect,))
        target = wasm32_wasi_target()
        module = object_with_refs(Kind.MODULE, [entry, target])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [api.b32, api.process_effect, zero, bad, graph, entry, target, module, root]))
        with self.assertRaises(XaxError) as raised:
            compile_wasm_bound_target(reader, entry.cid, target)
        self.assertEqual(raised.exception.diagnostic.code, "XAX.FOREIGN.ABI")


if __name__ == "__main__":
    unittest.main()
