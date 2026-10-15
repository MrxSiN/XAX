"""S15b.4 (ADR-294): the bootstrap's code generation rejections on malformed or extreme inputs (ADR-280's declined
list) are the general x86-64 program's, with the exact diagnostic.

Each program verifies, and ``compile_linux_executable``'s Python lowering rejects it; ``general_with_xax`` must raise
the same ``Diagnostic``.  The frame path is forced by a float conversion; without it the register path lowers.
"""

from __future__ import annotations

import platform
import sys
import unittest

from xax_compiler import (
    FloatFormat,
    OpaqueKind,
    Operation,
    Permission,
    XaxError,
    bits_type,
    call_contract,
    float_type,
    foreign_function_symbol,
    function_pointer_type,
    memory_effect_type,
    opaque_type,
    pointer_type,
    resource_type,
    verify_store,
    x86_64_linux_dynamic_exec_target,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
import xax_linux
from xax_linux import c_function, compile_linux_executable, linux_api

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B32, B64 = bits_type(32), bits_type(64)
F64 = float_type(FloatFormat.BINARY64)
MEM, OWNER = memory_effect_type(), resource_type(1, 1)


def _process(body, frame=True, target=None, extra=(), objects=()):
    """A process entry running ``body(block, process) -> process``, then exiting (through a float on the frame path)."""
    api = linux_api()
    graph = GraphBuilder()
    graph.track(*api.types, F64, *extra)
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    process = body(block, process)
    value = block.const(B64, 3)
    if frame:
        value = block.op1(Operation.FLOAT_TO_UINT_TRUNC, (block.op1(Operation.UINT_TO_FLOAT, (value,), F64),), B64)
    status = block.op1(Operation.INT_TRUNCATE, (value,), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    parameters = (api.process_effect, api.filesystem_effect)
    function = graph.function(parameters, (B32, *parameters))
    target = target or x86_64_linux_exec_target()
    return program_store(function, target, (*graph.objects.values(), *objects)), function, target


def _syscall(name, inputs, outputs):
    return foreign_function_symbol(xax_linux._LIBRARY, name, inputs, outputs, abi=xax_linux.LINUX_X86_64_SYSCALL_ABI)


def _two_results(block, process):
    process_type = linux_api().process_effect
    declaration = _syscall(b"39", (process_type,), (B64, B64, process_type))
    *_values, process = block.op(Operation.CALL_FOREIGN, (process,), (B64, B64, process_type), entity=declaration)
    return process


def _template(name):
    def body(block, process):
        process_type = linux_api().process_effect
        declaration = _syscall(name, (B64, process_type), (B64, process_type))
        _result, process = block.op(Operation.CALL_FOREIGN, (block.const(B64, 1), process), (B64, process_type), entity=declaration)
        return process
    return body


def _startup(block, process):
    declaration = foreign_function_symbol(xax_linux._LIBRARY, b"bogus", (), (B64,), abi=xax_linux.LINUX_X86_64_STARTUP_ABI)
    block.op1(Operation.CALL_FOREIGN, (), B64, entity=declaration)
    return process


def _two_libraries(block, process):
    for library in (b"libc.so.6", b"libm.so.6"):
        block.op1(Operation.CALL_FOREIGN, (), B32, entity=c_function(library, b"getpid", (), (B32,)))
    return process


def _big_frame(block, process):
    words = pointer_type(B64, Permission.READ_WRITE, 8)
    pointer, owner, memory = block.op(Operation.STACK_ALLOC, (), (words, OWNER, MEM), attributes=(1 << 31, 8))
    memory = block.op1(Operation.STORE_BITS_LE, (pointer, block.const(B64, 7), memory), MEM, attributes=(8, 8))
    _value, memory = block.op(Operation.LOAD_BITS_LE, (pointer, memory), (B64, MEM), attributes=(8, 8))
    block.op(Operation.STACK_END, (owner, memory), ())
    return process


def _heap(middle, view_type, extra=()):
    """mmap, a heap view, ``middle(block, view, memory)``, then a float (the frame path) and munmap."""
    from xax_compiler import heap_view_type

    api = linux_api()
    memory_type = api.memory_effect
    graph = GraphBuilder()
    graph.track(*api.types, F64, *extra)
    block = graph.block(api.process_effect, api.filesystem_effect, memory_type)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, 64), memory), (api.bytes_rw, api.heap_owner, memory_type), entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (view_type, heap_view_type(64), memory_type), attributes=(64, 8))
    memory = middle(block, view, memory)
    value = block.op1(Operation.FLOAT_TO_UINT_TRUNC, (block.op1(Operation.UINT_TO_FLOAT, (block.const(B64, 3),), F64),), B64)
    _result, memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (B64, memory_type), entity=api.munmap_view(view_type, 64))
    status = block.op1(Operation.INT_TRUNCATE, (value,), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    parameters = (api.process_effect, api.filesystem_effect, memory_type)
    function = graph.function(parameters, (B32, *parameters))
    target = x86_64_linux_exec_target()
    return program_store(function, target, tuple(graph.objects.values())), function, target


def _address32():
    words = pointer_type(B64, Permission.READ_WRITE, 8, space=2)

    def middle(block, view, memory):
        block.op1(Operation.POINTER_ADDRESS, (view,), B32, attributes=(1,))
        return memory
    return _heap(middle, words)


def _load4():
    inner = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
    pointers = pointer_type(inner, Permission.READ_WRITE, 8, space=2)

    def middle(block, view, memory):
        _value, memory = block.op(Operation.LOAD_BITS_LE, (view, memory), (inner, linux_api().memory_effect), attributes=(4, 4))
        return memory
    return _heap(middle, pointers, (inner, pointers))


def _two_result_contract(frame):
    """An indirect call whose contract has two machine results."""
    graph = GraphBuilder()
    block = graph.block(B64)
    block.ret(block.params[0])
    callee = graph.function((B64,), (B64,))
    user_graph = GraphBuilder()
    contract = call_contract((B64,), (B64, B64), may_return=True, may_trap=False)
    user_graph.track(contract, function_pointer_type(), opaque_type(OpaqueKind.FUNCTION), F64)
    user = user_graph.block(B32)
    pointer = user.op1(Operation.FUNCTION_ADDRESS, (), function_pointer_type(), entity=callee)
    first, second = user.op(Operation.CALL_INDIRECT, (pointer, user.op1(Operation.INT_ZERO_EXTEND, (user.params[0],), B64)), (B64, B64), entity=contract)
    value = user.op1(Operation.ADD_WRAP, (first, second), B64)
    if frame:
        value = user.op1(Operation.FLOAT_TO_UINT_TRUNC, (user.op1(Operation.UINT_TO_FLOAT, (value,), F64),), B64)
    user.ret(user.op1(Operation.INT_TRUNCATE, (value,), B32))
    caller = user_graph.function((B32,), (B32,))

    def body(block, process):
        block.op1(Operation.CALL_DIRECT, (block.const(B32, 9),), B32, entity=caller)
        return process
    return _process(body, frame=False, objects=(*graph.objects.values(), *user_graph.objects.values(), callee))

CASES = {
    "SYSCALL-ONE-RESULT": lambda: _process(_two_results),
    "SYSCALL-TEMPLATE-CANONICAL": lambda: _process(_template(b"39x")),
    "SYSCALL-TEMPLATE-CANONICAL leading zero": lambda: _process(_template(b"039")),
    "SYSCALL-TEMPLATE-CANONICAL not ASCII": lambda: _process(_template(bytes((51, 57, 255)))),
    "SYSCALL-TEMPLATE-CANONICAL seven arguments": lambda: _process(_template(b"39:$0,1,2,3,4,5,6"), frame=False),
    "SYSCALL-TEMPLATE-OPERANDS twice": lambda: _process(_template(b"39:$0,$0")),
    "SYSCALL-TEMPLATE-OPERANDS missing": lambda: _process(_template(b"39:1"), frame=False),
    "NATIVE-FOREIGN-ABI": lambda: _process(_startup),
    "LINUX-STARTUP-NAME": lambda: _process(_startup, frame=False),
    "LINUX-IMPORT-SYMBOL-UNIQUE": lambda: _process(_two_libraries, target=x86_64_linux_dynamic_exec_target()),
    "NATIVE-ADDRESS-POINTER-WIDTH": _address32,
    "NATIVE-POINTER-ELEMENT-WIDTH": _load4,
    "NATIVE-CALL-ARITY": lambda: _two_result_contract(True),
    "NATIVE-VALUE-LOCATION": lambda: _two_result_contract(False),
    "NATIVE-MEMORY-ENCODABLE": lambda: _process(_big_frame, extra=(OWNER, MEM)),
}


@unittest.skipUnless(LINUX_X86_64, "UNAVAILABLE: native XAX helper images run on Linux x86-64 only")
class GeneralRejectionTests(unittest.TestCase):
    def test_the_bootstraps_rejections_are_the_programs(self):
        from xax_selfhost_x86_64_general import general_with_xax

        for name, make in CASES.items():
            with self.subTest(name):
                reader, entry, target = make()
                verify_store(reader)
                with self.assertRaises(XaxError) as reference:
                    compile_linux_executable(reader, entry.cid, target.cid, frontend="python")
                self.assertEqual(reference.exception.diagnostic.rule, name.split()[0])
                with self.assertRaises(XaxError) as xax:
                    general_with_xax(reader, entry.cid, target, required=True)
                self.assertEqual(xax.exception.diagnostic, reference.exception.diagnostic)


if __name__ == "__main__":
    unittest.main()
