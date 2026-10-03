"""ADR-125: recursion groups are callable through group member functions on every backend."""

from __future__ import annotations

import platform
import shutil
import sys
import unittest

from xax_compiler import (
    Block,
    IntCompare,
    Kind,
    Node,
    Operation,
    Permission,
    RecursionMember,
    StoreReader,
    ValueRef,
    XaxError,
    aarch64_baremetal_general_target,
    aarch64_linux_exec_target,
    bits_type,
    canonical_recursion_order,
    decode_group_member_function,
    execute,
    function,
    graph_fragment,
    group_member_function,
    heap_view_type,
    jvm_classfile_target,
    object_with_refs,
    pointer_type,
    recursion_group,
    riscv64_baremetal_target,
    stack_owner_type,
    target,
    verify_store,
    wasm32_general_target,
    write_store,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store

B1, B8, B32 = bits_type(1), bits_type(8), bits_type(32)
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def _group_call(block, member: int, operands, results):
    """Append ``call.group_member`` (the builder has no helper; group graphs are rare)."""
    block.nodes.append(Node(Operation.CALL_GROUP_MEMBER, tuple(operands), tuple(results), member=member))
    index = len(block.nodes) - 1
    block.owner.track(*results)
    return tuple(ValueRef.node_result(block.index, index, result) for result in range(len(results)))


def _graph(builder: GraphBuilder):
    return graph_fragment([Block(block.parameter_types, tuple(block.nodes), block.terminator) for block in builder.blocks])


def factorial_group():
    """``fact(n) = n == 0 ? 1 : n * fact(n - 1)`` (wrapping 32-bit)."""
    graph = GraphBuilder()
    entry = graph.block(B32)
    base, recurse = graph.block(), graph.block(B32)
    (n,) = entry.params
    entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)), base, (), recurse, (n,))
    base.ret(base.const(B32, 1))
    (m,) = recurse.params
    (inner,) = _group_call(recurse, 0, (recurse.op1(Operation.SUB_WRAP, (m, recurse.const(B32, 1)), B32),), (B32,))
    recurse.ret(recurse.op1(Operation.MUL_WRAP, (m, inner), B32))
    fragment = _graph(graph)
    group = recursion_group([RecursionMember(fragment, (B32,), (B32,))])
    return group, (*graph.objects.values(), fragment, group)


def parity_group():
    """Mutual recursion ``even``/``odd``, in canonical member order.

    Returns ``(group, objects)`` plus the member indices of even and odd.
    """

    def member(base_value: int, callee: int):
        graph = GraphBuilder()
        entry = graph.block(B32)
        base, recurse = graph.block(), graph.block(B32)
        (n,) = entry.params
        entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)), base, (), recurse, (n,))
        base.ret(base.const(B32, base_value))
        (m,) = recurse.params
        (inner,) = _group_call(recurse, callee, (recurse.op1(Operation.SUB_WRAP, (m, recurse.const(B32, 1)), B32),), (B32,))
        recurse.ret(inner)
        fragment = _graph(graph)
        return RecursionMember(fragment, (B32,), (B32,)), (*graph.objects.values(), fragment)

    for even_index in (0, 1):
        odd_index = 1 - even_index
        even, even_objects = member(1, odd_index)
        odd, odd_objects = member(0, even_index)
        members = [even, odd] if even_index == 0 else [odd, even]
        objects = {item.cid: item for item in (*even_objects, *odd_objects)}
        if canonical_recursion_order(members, objects.__getitem__) == (0, 1):
            group = recursion_group(members)
            return (group, (*objects.values(), group)), even_index, odd_index
    raise AssertionError("no canonical order")


def caller(callee, argument_types=(B32,)):
    graph = GraphBuilder()
    block = graph.block(*argument_types)
    block.ret(block.op1(Operation.CALL_DIRECT, block.params, B32, entity=callee))
    return graph.function(argument_types, (B32,)), tuple(graph.objects.values())


def program(group_and_objects, member: int, target_object):
    group, objects = group_and_objects
    entry, extra = caller(group_member_function(group, member))
    return program_store(entry, target_object, (*objects, *extra, group_member_function(group, member))), entry


class GroupMemberFunctionTests(unittest.TestCase):
    def test_identity_is_group_and_member(self):
        group, _objects = factorial_group()
        member = group_member_function(group, 0)
        self.assertEqual(member.kind, Kind.FUNCTION)
        self.assertEqual(member.references, (group.cid,))
        self.assertEqual(member.cid, group_member_function(group, 0).cid)
        self.assertEqual(decode_group_member_function(member, {group.cid: group}.__getitem__), (group, 0))

    def test_reference_execution(self):
        reader, entry = program(factorial_group(), 0, target(b"probe"))
        self.assertEqual(execute(reader, entry.cid, (10,)), (3628800,))
        parity, even, odd = parity_group()
        for member, value, expected in ((even, 10, 1), (even, 7, 0), (odd, 7, 1)):
            reader, entry = program(parity, member, target(b"probe"))
            self.assertEqual(execute(reader, entry.cid, (value,)), (expected,))

    def test_member_out_of_range_rejects(self):
        group, objects = factorial_group()
        entry, extra = caller(group_member_function(group, 3))
        with self.assertRaises(XaxError) as caught:
            program_store(entry, target(b"probe"), (*objects, *extra, group_member_function(group, 3)))
        self.assertEqual(caught.exception.diagnostic.rule, "GRAPH-RECURSION-MEMBER")

    def test_group_call_outside_a_group_still_rejects(self):
        group, objects = factorial_group()
        members = group.references
        fragment = next(item for item in objects if item.kind == Kind.GRAPH_FRAGMENT)
        plain = function(fragment, (B32,), (B32,))
        module = object_with_refs(Kind.MODULE, (plain,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        store = {item.cid: item for item in (*objects, plain, module, root)}
        reader = StoreReader(write_store(root.cid, tuple(store[cid] for cid in store if cid in {root.cid, module.cid, plain.cid, fragment.cid, *members, *fragment.references})))
        with self.assertRaises(XaxError) as caught:
            verify_store(reader)
        self.assertEqual(caught.exception.diagnostic.rule, "GRAPH-GROUP-CALL-CONTEXT")


class BackendRecursionTests(unittest.TestCase):
    def _cases(self, target_object):
        return (
            (program(factorial_group(), 0, target_object), (10,), 3628800),
            (program(parity_group()[0], parity_group()[1], target_object), (25,), 0),
            (program(parity_group()[0], parity_group()[2], target_object), (25,), 1),
        )

    @unittest.skipUnless(shutil.which("node"), "requires node")
    def test_wasm(self):
        from xax_wasm import compile_wasm, run_wasm_isolated

        for (reader, entry), arguments, expected in self._cases(wasm32_general_target()):
            image = compile_wasm(reader, entry.cid, _target_cid(reader))
            self.assertEqual(run_wasm_isolated(image, arguments), (expected,))

    def test_riscv64(self):
        try:
            from xax_riscv64 import compile_riscv64, run_riscv64

            import unicorn  # noqa: F401
        except ImportError:
            self.skipTest("requires unicorn")
        for (reader, entry), arguments, expected in self._cases(riscv64_baremetal_target()):
            self.assertEqual(run_riscv64(compile_riscv64(reader, entry.cid, _target_cid(reader)), arguments), expected)

    @unittest.skipUnless(shutil.which("java"), "requires java")
    def test_jvm(self):
        from xax_jvm import compile_jvm, run_jvm_calls

        for (reader, entry), arguments, expected in self._cases(jvm_classfile_target()):
            self.assertEqual(run_jvm_calls(compile_jvm(reader, entry.cid, _target_cid(reader)), [arguments]), (expected,))

    def test_aarch64(self):
        from xax_aarch64 import compile_aarch64, run_aarch64_qemu

        for (reader, entry), arguments, expected in self._cases(aarch64_baremetal_general_target()):
            try:
                self.assertEqual(run_aarch64_qemu(compile_aarch64(reader, entry.cid, _target_cid(reader)), arguments), (expected,))
            except XaxError as error:
                if "HOST" in error.diagnostic.code:
                    self.skipTest("no AArch64 execution host")
                raise

    def test_wasm_rejects_recursive_frame_storage(self):
        from xax_wasm import compile_wasm

        group, objects = _stack_group()
        entry, extra = caller(group_member_function(group, 0))
        reader = program_store(entry, wasm32_general_target(), (*objects, *extra, group_member_function(group, 0)))
        with self.assertRaises(XaxError) as caught:
            compile_wasm(reader, entry.cid, _target_cid(reader))
        self.assertEqual(caught.exception.diagnostic.rule, "WASM-REENTRANT-FRAME")


def _target_cid(reader: StoreReader) -> bytes:
    module = reader.get(reader.get(reader.root_cid).references[0])
    return next(cid for cid in module.references if reader.get(cid).kind == Kind.TARGET)


def _stack_group():
    """``f(n) = n == 0 ? 0 : load(store(stack, n)) + f(n - 1)``: recursion with a stack slot per activation."""
    from xax_compiler import memory_effect_type, stack_owner_type

    rw = pointer_type(B32, Permission.READ_WRITE, 4)
    graph = GraphBuilder()
    entry = graph.block(B32)
    base, recurse = graph.block(), graph.block(B32)
    (n,) = entry.params
    entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)), base, (), recurse, (n,))
    base.ret(base.const(B32, 0))
    (m,) = recurse.params
    pointer, owner, memory = recurse.op(Operation.STACK_ALLOC, (), (rw, stack_owner_type(), memory_effect_type()), attributes=(4, 4))
    memory = recurse.op1(Operation.STORE_BITS_LE, (pointer, m, memory), memory_effect_type(), attributes=(4, 4))
    value, memory = recurse.op(Operation.LOAD_BITS_LE, (pointer, memory), (B32, memory_effect_type()), attributes=(4, 4))
    recurse.op(Operation.STACK_END, (owner, memory), ())
    (inner,) = _group_call(recurse, 0, (recurse.op1(Operation.SUB_WRAP, (m, recurse.const(B32, 1)), B32),), (B32,))
    recurse.ret(recurse.op1(Operation.ADD_WRAP, (value, inner), B32))
    fragment = _graph(graph)
    group = recursion_group([RecursionMember(fragment, (B32,), (B32,))])
    return group, (*graph.objects.values(), fragment, group)


def _view_sum_group(elements: int):
    """``sum(i, view) = i == n ? 0 : view[i] + sum(i + 1, view)`` over a borrowed read-only view."""
    from xax_compiler import memory_effect_type

    pointer = pointer_type(B32, Permission.READ_WRITE, 4, space=2)
    view, memory = heap_view_type(4 * elements), memory_effect_type()
    graph = GraphBuilder()
    entry = graph.block(B32, pointer, view, memory)
    done, recurse = graph.block(pointer, view, memory), graph.block(B32, pointer, view, memory)
    i, p, v, m = entry.params
    entry.cbr(entry.op1(Operation.INT_COMPARE, (i, entry.const(B32, elements)), B1, attributes=(IntCompare.EQ,)), done, (p, v, m), recurse, (i, p, v, m))
    done.ret(done.const(B32, 0), *done.params)
    i, p, v, m = recurse.params
    value, m = recurse.op(Operation.CHECKED_LOAD_BITS_LE, (p, recurse.op1(Operation.MUL_WRAP, (i, recurse.const(B32, 4)), B32), m), (B32, memory), attributes=(4, 1))
    inner, p, v, m = _group_call(recurse, 0, (recurse.op1(Operation.ADD_WRAP, (i, recurse.const(B32, 1)), B32), p, v, m), (B32, pointer, view, memory))
    recurse.ret(recurse.op1(Operation.ADD_WRAP, (value, inner), B32), p, v, m)
    fragment = _graph(graph)
    group = recursion_group([RecursionMember(fragment, (B32, pointer, view, memory), (B32, pointer, view, memory))])
    return group, (*graph.objects.values(), fragment, group), (pointer, view, memory)


def _linux_view_sum(platform_name: str, elements: int):
    """Process entry: mmap, fill ``1..n``, recursive sum, munmap, ``exit_group(sum & 255)``."""
    if platform_name == "x86_64":
        from xax_linux import compile_linux_executable as compile_, linux_api as api_, run_linux_executable as run_

        target_object = x86_64_linux_exec_target()
    else:
        from xax_linux_aarch64 import compile_linux_aarch64_executable as compile_, linux_aarch64_api as api_, run_linux_aarch64_executable as run_

        target_object = aarch64_linux_exec_target()
    api = api_()
    group, objects, (_pointer, view, memory) = _view_sum_group(elements)
    member = group_member_function(group, 0)
    rw = pointer_type(B32, Permission.READ_WRITE, 4, space=2)
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect, api.memory_effect)
    process, fs, mem = block.params
    raw, owner, mem = block.op(Operation.CALL_FOREIGN, (block.const(bits_type(64), 4 * elements), mem), (api.bytes_rw, api.heap_owner, api.memory_effect), entity=api.mmap_anonymous)
    words, token, mem = block.op(Operation.HEAP_VIEW, (raw, owner, mem), (rw, view, api.memory_effect), attributes=(4 * elements, 4))
    for index in range(elements):
        mem = block.op1(Operation.CHECKED_STORE_BITS_LE, (words, block.const(B32, 4 * index), block.const(B32, index + 1), mem), api.memory_effect, attributes=(4, 1))
    total, words, token, mem = block.op(Operation.CALL_DIRECT, (block.const(B32, 0), words, token, mem), (B32, rw, view, memory), entity=member)
    _r, mem = block.op(Operation.CALL_FOREIGN, (words, token, mem), (bits_type(64), api.memory_effect), entity=api.munmap_view(rw, 4 * elements))
    status = block.op1(Operation.BIT_AND, (total, block.const(B32, 255)), B32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, mem)
    parameters = (api.process_effect, api.filesystem_effect, api.memory_effect)
    entry = graph.function(parameters, (B32, *parameters))
    reader = program_store(entry, target_object, (*api.types, *objects, *graph.objects.values(), member))
    return run_(compile_(reader, entry.cid, target_object.cid).data).returncode


class RecursionOverMemoryTests(unittest.TestCase):
    @unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
    def test_x86_64_linux(self):
        self.assertEqual(_linux_view_sum("x86_64", 16), 136)
        self.assertEqual(_linux_view_sum("x86_64", 1000), (1000 * 1001 // 2) & 255)

    def test_aarch64_linux(self):
        from xax_linux_aarch64 import aarch64_runner

        if aarch64_runner() is None:
            self.skipTest("requires an AArch64 Linux host or qemu-aarch64")
        self.assertEqual(_linux_view_sum("aarch64", 16), 136)

    def test_bare_memory_frontier_through_a_group_call_rejects(self):
        # Stack pointers cannot be member parameters at all (MEMORY-ENTRY-CONTRACT);
        # a bare memory frontier reaches the group-call rule.
        from xax_compiler import memory_effect_type

        memory = memory_effect_type()
        graph = GraphBuilder()
        entry = graph.block(B32, memory)
        base, recurse = graph.block(memory), graph.block(B32, memory)
        n, frontier = entry.params
        entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(B32, 0)), B1, attributes=(IntCompare.EQ,)), base, (frontier,), recurse, (n, frontier))
        base.ret(base.const(B32, 0), *base.params)
        n, frontier = recurse.params
        recurse.ret(*_group_call(recurse, 0, (recurse.op1(Operation.SUB_WRAP, (n, recurse.const(B32, 1)), B32), frontier), (B32, memory)))
        fragment = _graph(graph)
        group = recursion_group([RecursionMember(fragment, (B32, memory), (B32, memory))])
        module = object_with_refs(Kind.MODULE, (group,))
        root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
        objects = {item.cid: item for item in (*graph.objects.values(), fragment, group, module, root)}
        with self.assertRaises(XaxError) as caught:
            verify_store(StoreReader(write_store(root.cid, tuple(objects.values()))))
        self.assertEqual(caught.exception.diagnostic.rule, "GROUP-CALL-MEMORY-VIEWS-ONLY")

if __name__ == "__main__":
    unittest.main()
