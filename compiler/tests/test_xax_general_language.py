import unittest

from xax_compiler import (
    Block, FloatCompare, FloatFormat, IntCompare, Kind, Node, OpaqueKind,
    Operation, Permission, StoreReader, Terminator, ValueRef,
    array_type, bits_type, call_contract, constant, effect_type, execute,
    float_constant, float_type, function, graph_fragment, memory_effect_type,
    object_with_refs, opaque_type, pointer_type, stack_owner_type, struct_type,
    sum_type, tuple_type, verify_store, write_store, x86_64_windows_general_target,
)
from xax_x86_64 import compile_native


def reader_for(entry, objects, target=None):
    members = [entry] + ([target] if target is not None else [])
    module = object_with_refs(Kind.MODULE, members)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    all_objects = list(objects) + [module, root]
    if target is not None and target not in all_objects:
        all_objects.append(target)
    return StoreReader(write_store(root.cid, all_objects))


class GeneralLanguageCompletionTests(unittest.TestCase):
    def test_float_arithmetic_comparison_and_conversions(self):
        b1 = bits_type(1)
        b32 = bits_type(32)
        f32 = float_type(FloatFormat.BINARY32)
        f64 = float_type(FloatFormat.BINARY64)
        target = x86_64_windows_general_target()

        arithmetic_nodes = (
            Node(Operation.FLOAT_ADD, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (f64,)),
            Node(Operation.FLOAT_SUB, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 2)), (f64,)),
            Node(Operation.FLOAT_MUL, (ValueRef.node_result(0, 1), ValueRef.parameter(0, 1)), (f64,)),
            Node(Operation.FLOAT_DIV, (ValueRef.node_result(0, 2), ValueRef.parameter(0, 1)), (f64,)),
        )
        arithmetic_graph = graph_fragment([
            Block((f64, f64, f64), arithmetic_nodes, Terminator.return_((ValueRef.node_result(0, 3),)))
        ])
        arithmetic = function(arithmetic_graph, (f64, f64, f64), (f64,))
        reader = reader_for(arithmetic, [f64, arithmetic_graph, arithmetic], target)
        self.assertEqual(execute(reader, arithmetic.cid, (2.5, 4.0, 1.0)), (5.5,))
        self.assertGreater(len(compile_native(reader, arithmetic.cid, target.cid).code), 0)

        fconst = float_constant(f64, 1.5)
        const_graph = graph_fragment([
            Block((), (Node(Operation.CONSTANT, (), (f64,), entity=fconst),), Terminator.return_((ValueRef.node_result(0, 0),)))
        ])
        const_fn = function(const_graph, (), (f64,))
        reader = reader_for(const_fn, [f64, fconst, const_graph, const_fn], target)
        self.assertEqual(execute(reader, const_fn.cid, ()), (1.5,))
        compile_native(reader, const_fn.cid, target.cid)

        compare_graph = graph_fragment([
            Block(
                (f32, f32),
                (Node(Operation.FLOAT_COMPARE, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b1,), attributes=(FloatCompare.LT,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ])
        compare = function(compare_graph, (f32, f32), (b1,))
        reader = reader_for(compare, [b1, f32, compare_graph, compare], target)
        self.assertEqual(execute(reader, compare.cid, (1.0, 2.0)), (1,))
        compile_native(reader, compare.cid, target.cid)

        to_float_graph = graph_fragment([
            Block((b32,), (Node(Operation.UINT_TO_FLOAT, (ValueRef.parameter(0, 0),), (f64,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
        ])
        to_float = function(to_float_graph, (b32,), (f64,))
        reader = reader_for(to_float, [b32, f64, to_float_graph, to_float], target)
        self.assertEqual(execute(reader, to_float.cid, (17,)), (17.0,))
        compile_native(reader, to_float.cid, target.cid)

        to_int_graph = graph_fragment([
            Block((f64,), (Node(Operation.FLOAT_TO_UINT_TRUNC, (ValueRef.parameter(0, 0),), (b32,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
        ])
        to_int = function(to_int_graph, (f64,), (b32,))
        reader = reader_for(to_int, [b32, f64, to_int_graph, to_int], target)
        self.assertEqual(execute(reader, to_int.cid, (17.75,)), (17,))
        compile_native(reader, to_int.cid, target.cid)

        convert_graph = graph_fragment([
            Block((f64,), (Node(Operation.FLOAT_CONVERT, (ValueRef.parameter(0, 0),), (f32,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
        ])
        convert = function(convert_graph, (f64,), (f32,))
        reader = reader_for(convert, [f32, f64, convert_graph, convert], target)
        self.assertAlmostEqual(execute(reader, convert.cid, (1.1,))[0], 1.1, places=6)
        compile_native(reader, convert.cid, target.cid)

    def test_tuple_struct_and_array_values(self):
        b32 = bits_type(32)
        pair = tuple_type((b32, b32))
        record = struct_type((b32, b32))
        array = array_type(b32, 2)
        target = x86_64_windows_general_target()
        self.assertEqual(record.cid, pair.cid)
        nodes = (
            Node(Operation.AGGREGATE_MAKE, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (pair,)),
            Node(Operation.AGGREGATE_GET, (ValueRef.node_result(0, 0),), (b32,), attributes=(1,)),
            Node(Operation.AGGREGATE_MAKE, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 1)), (array,)),
            Node(Operation.AGGREGATE_GET, (ValueRef.node_result(0, 2),), (b32,), attributes=(0,)),
            Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 1), ValueRef.node_result(0, 3)), (b32,)),
        )
        graph = graph_fragment([Block((b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, 4),)))])
        entry = function(graph, (b32, b32), (b32,))
        reader = reader_for(entry, [b32, pair, array, graph, entry], target)
        self.assertEqual(execute(reader, entry.cid, (7, 11)), (18,))
        compile_native(reader, entry.cid, target.cid)

    def test_sum_tag_branch_and_extract(self):
        b1 = bits_type(1)
        b32 = bits_type(32)
        choice = sum_type((b32, b1))
        zero = constant(b1, 0)
        target = x86_64_windows_general_target()
        entry_nodes = (
            Node(Operation.SUM_MAKE, (ValueRef.parameter(0, 0),), (choice,), attributes=(0,)),
            Node(Operation.SUM_TAG, (ValueRef.node_result(0, 0),), (b1,)),
            Node(Operation.CONSTANT, (), (b1,), entity=zero),
            Node(Operation.INT_COMPARE, (ValueRef.node_result(0, 1), ValueRef.node_result(0, 2)), (b1,), attributes=(IntCompare.EQ,)),
        )
        blocks = (
            Block((b32,), entry_nodes, Terminator.conditional_branch(ValueRef.node_result(0, 3), 1, (ValueRef.node_result(0, 0),), 2, ())),
            Block((choice,), (Node(Operation.SUM_GET, (ValueRef.parameter(1, 0),), (b32,), attributes=(0,)),), Terminator.return_((ValueRef.node_result(1, 0),))),
            Block((), (), Terminator.trap()),
        )
        graph = graph_fragment(blocks)
        entry = function(graph, (b32,), (b32,))
        reader = reader_for(entry, [b1, b32, choice, zero, graph, entry], target)
        self.assertEqual(execute(reader, entry.cid, (99,)), (99,))
        compile_native(reader, entry.cid, target.cid)

    def test_function_value_and_indirect_call(self):
        b32 = bits_type(32)
        opaque_fn = opaque_type(OpaqueKind.FUNCTION)
        fnptr = pointer_type(opaque_fn, Permission.READ, 8, space=2)
        callee_graph = graph_fragment([
            Block((b32, b32), (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),), Terminator.return_((ValueRef.node_result(0, 0),)))
        ])
        callee = function(callee_graph, (b32, b32), (b32,))
        contract = call_contract((b32, b32), (b32,), may_return=True, may_trap=False)
        caller_nodes = (
            Node(Operation.FUNCTION_ADDRESS, (), (fnptr,), entity=callee),
            Node(Operation.CALL_INDIRECT, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,), entity=contract),
        )
        caller_graph = graph_fragment([Block((b32, b32), caller_nodes, Terminator.return_((ValueRef.node_result(0, 1),)))])
        caller = function(caller_graph, (b32, b32), (b32,))
        target = x86_64_windows_general_target()
        reader = reader_for(caller, [b32, opaque_fn, fnptr, callee_graph, callee, contract, caller_graph, caller], target)
        self.assertEqual(execute(reader, caller.cid, (20, 22)), (42,))
        compile_native(reader, caller.cid, target.cid)

    def test_pointer_cast_float_load_store_and_lifetime(self):
        f32 = float_type(FloatFormat.BINARY32)
        rw = pointer_type(f32, Permission.READ_WRITE, 4)
        ro = pointer_type(f32, Permission.READ, 4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        nodes = (
            Node(Operation.STACK_ALLOC, (), (rw, owner, effect), attributes=(4, 4)),
            Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(4, 4)),
            Node(Operation.POINTER_CAST, (ValueRef.node_result(0, 0, 0),), (ro,)),
            Node(Operation.LOAD_BITS_LE, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 1)), (f32, effect), attributes=(4, 4)),
            Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 3, 1)), ()),
        )
        graph = graph_fragment([Block((f32,), nodes, Terminator.return_((ValueRef.node_result(0, 3, 0),)))])
        entry = function(graph, (f32,), (f32,))
        target = x86_64_windows_general_target()
        reader = reader_for(entry, [f32, rw, ro, owner, effect, graph, entry], target)
        self.assertAlmostEqual(execute(reader, entry.cid, (3.25,))[0], 3.25)
        compile_native(reader, entry.cid, target.cid)

    def test_external_pointer_permission_narrowing_is_identity(self):
        b8 = bits_type(8)
        rw = pointer_type(b8, Permission.READ_WRITE, 1, space=2)
        ro = pointer_type(b8, Permission.READ, 1, space=2)
        graph = graph_fragment([
            Block(
                (rw,),
                (Node(Operation.POINTER_CAST, (ValueRef.parameter(0, 0),), (ro,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ])
        entry = function(graph, (rw,), (ro,))
        target = x86_64_windows_general_target()
        reader = reader_for(entry, [b8, rw, ro, graph, entry], target)
        sentinel = 0x12345678
        self.assertEqual(execute(reader, entry.cid, (sentinel,)), (sentinel,))
        compile_native(reader, entry.cid, target.cid)

    def test_checked_dynamic_pointer_offset_load_store(self):
        b32 = bits_type(32)
        ptr = pointer_type(b32, Permission.READ_WRITE, 4)
        owner = stack_owner_type()
        effect = memory_effect_type()
        zero = constant(b32, 0)
        nodes = (
            Node(Operation.STACK_ALLOC, (), (ptr, owner, effect), attributes=(8, 4)),
            Node(Operation.CONSTANT, (), (b32,), entity=zero),
            Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 1), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(4, 4)),
            Node(Operation.ADDRESS_OFFSET, (ValueRef.node_result(0, 0, 0),), (ptr,), attributes=(4,)),
            Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 3), ValueRef.node_result(0, 1), ValueRef.node_result(0, 2)), (effect,), attributes=(4, 4)),
            Node(Operation.CHECKED_STORE_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 1), ValueRef.node_result(0, 4)), (effect,), attributes=(4, 1)),
            Node(Operation.CHECKED_LOAD_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 5)), (b32, effect), attributes=(4, 1)),
            Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 6, 1)), ()),
        )
        graph = graph_fragment([Block((b32, b32), nodes, Terminator.return_((ValueRef.node_result(0, 6, 0),)))])
        entry = function(graph, (b32, b32), (b32,))
        target = x86_64_windows_general_target()
        reader = reader_for(entry, [b32, ptr, owner, effect, zero, graph, entry], target)
        self.assertEqual(execute(reader, entry.cid, (4, 0xDEADBEEF)), (0xDEADBEEF,))
        compile_native(reader, entry.cid, target.cid)

    def test_cyclic_cfg_loop(self):
        b1 = bits_type(1)
        b32 = bits_type(32)
        zero = constant(b32, 0)
        one = constant(b32, 1)
        entry_nodes = (
            Node(Operation.CONSTANT, (), (b32,), entity=zero),
            Node(Operation.CONSTANT, (), (b32,), entity=one),
        )
        loop_nodes = (
            Node(Operation.INT_COMPARE, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 2)), (b1,), attributes=(IntCompare.ULT,)),
        )
        body_nodes = (
            Node(Operation.ADD_WRAP, (ValueRef.parameter(2, 1), ValueRef.parameter(2, 0)), (b32,)),
            Node(Operation.ADD_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 3)), (b32,)),
        )
        blocks = (
            Block((b32,), entry_nodes, Terminator.branch(1, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 1)))),
            Block((b32, b32, b32, b32), loop_nodes, Terminator.conditional_branch(ValueRef.node_result(1, 0), 2, tuple(ValueRef.parameter(1, i) for i in range(4)), 3, (ValueRef.parameter(1, 1),))),
            Block((b32, b32, b32, b32), body_nodes, Terminator.branch(1, (ValueRef.node_result(2, 1), ValueRef.node_result(2, 0), ValueRef.parameter(2, 2), ValueRef.parameter(2, 3)))),
            Block((b32,), (), Terminator.return_((ValueRef.parameter(3, 0),))),
        )
        graph = graph_fragment(blocks)
        entry = function(graph, (b32,), (b32,))
        target = x86_64_windows_general_target()
        reader = reader_for(entry, [b1, b32, zero, one, graph, entry], target)
        self.assertEqual(execute(reader, entry.cid, (5,)), (10,))
        compile_native(reader, entry.cid, target.cid)


class PlatformLibraryCompletionTests(unittest.TestCase):
    def _platform_reader(self, entry, objects):
        from xax_compiler import android_arm64_shared_target
        target = android_arm64_shared_target()
        module = object_with_refs(Kind.MODULE, [entry])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        return StoreReader(write_store(root.cid, list(objects) + [module, root])), target

    def test_explicit_heap_malloc_free_resource_and_effect(self):
        from xax_aarch64 import compile_aarch64_bundle_bound_target
        from xax_platform import posix_android_api
        api = posix_android_api()
        nodes = (
            Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (api.byte_ptr_rw, api.heap_resource, api.memory_effect), entity=api.malloc),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 0, 0), ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 0, 2)), (api.memory_effect,), entity=api.free),
        )
        graph = graph_fragment([Block((api.b64, api.memory_effect), nodes, Terminator.return_((ValueRef.node_result(0, 1, 0),)))])
        entry = function(graph, (api.b64, api.memory_effect), (api.memory_effect,))
        objects = [api.b8, api.b64, api.byte_ptr_rw, api.memory_effect, api.heap_resource, api.malloc, api.free, graph, entry]
        reader, target = self._platform_reader(entry, objects)
        verify_store(reader)
        bundle = compile_aarch64_bundle_bound_target(reader, (entry.cid,), target)
        self.assertEqual(tuple((lib, name) for _, lib, name in bundle.foreign_calls), ((b"libc.so", b"malloc"), (b"libc.so", b"free")))

    def test_file_clock_process_thread_and_socket_contracts_compile(self):
        from xax_aarch64 import compile_aarch64_bundle_bound_target
        from xax_platform import posix_android_api
        api = posix_android_api()
        zero32 = constant(api.b32, 0)
        # Machine parameters stay within AAPCS64's register arguments; proof
        # effects are verifier-only and erase from the ABI.
        params = (
            api.byte_ptr_read, api.byte_ptr_rw, api.function_ptr, api.b64, api.b64,
            api.memory_effect, api.filesystem_effect, api.time_effect,
            api.process_effect, api.thread_effect, api.network_effect,
        )
        nodes = (
            Node(Operation.CONSTANT, (), (api.b32,), entity=zero32),
            Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 0), ValueRef.node_result(0, 0), ValueRef.node_result(0, 0), ValueRef.parameter(0, 6)), (api.b32, api.filesystem_effect), entity=api.open),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3), ValueRef.node_result(0, 1, 1), ValueRef.parameter(0, 5)), (api.b64, api.filesystem_effect, api.memory_effect), entity=api.read),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 1, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 3), ValueRef.node_result(0, 2, 1)), (api.b64, api.filesystem_effect), entity=api.write),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 1, 0), ValueRef.node_result(0, 3, 1)), (api.b32, api.filesystem_effect), entity=api.close),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 7), ValueRef.node_result(0, 2, 2)), (api.b32, api.time_effect, api.memory_effect), entity=api.clock_gettime),
            Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 8),), (api.b32, api.process_effect), entity=api.getpid),
            Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 1), ValueRef.parameter(0, 0), ValueRef.parameter(0, 2), ValueRef.parameter(0, 1), ValueRef.parameter(0, 9), ValueRef.node_result(0, 5, 2)), (api.b32, api.thread_effect, api.memory_effect), entity=api.pthread_create),
            Node(Operation.CALL_FOREIGN, (ValueRef.parameter(0, 4), ValueRef.parameter(0, 1), ValueRef.node_result(0, 7, 1), ValueRef.node_result(0, 7, 2)), (api.b32, api.thread_effect, api.memory_effect), entity=api.pthread_join),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 0), ValueRef.node_result(0, 0), ValueRef.parameter(0, 10)), (api.b32, api.network_effect), entity=api.socket),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 9, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0), ValueRef.node_result(0, 9, 1)), (api.b32, api.network_effect), entity=api.connect),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 9, 0), ValueRef.parameter(0, 0), ValueRef.parameter(0, 3), ValueRef.node_result(0, 0), ValueRef.node_result(0, 10, 1)), (api.b64, api.network_effect), entity=api.send),
            Node(Operation.CALL_FOREIGN, (ValueRef.node_result(0, 9, 0), ValueRef.parameter(0, 1), ValueRef.parameter(0, 3), ValueRef.node_result(0, 0), ValueRef.node_result(0, 11, 1), ValueRef.node_result(0, 8, 2)), (api.b64, api.network_effect, api.memory_effect), entity=api.recv),
        )
        returns = (
            api.b64, api.filesystem_effect, api.time_effect, api.process_effect,
            api.thread_effect, api.network_effect, api.memory_effect,
        )
        term = Terminator.return_((
            ValueRef.node_result(0, 12, 0), ValueRef.node_result(0, 4, 1),
            ValueRef.node_result(0, 5, 1), ValueRef.node_result(0, 6, 1),
            ValueRef.node_result(0, 8, 1), ValueRef.node_result(0, 12, 1),
            ValueRef.node_result(0, 12, 2),
        ))
        graph = graph_fragment([Block(params, nodes, term)])
        entry = function(graph, params, returns)
        objects = [
            api.b8, api.b32, api.b64, api.byte_ptr_read, api.byte_ptr_rw,
            api.function_opaque, api.function_ptr, api.memory_effect, api.filesystem_effect,
            api.time_effect, api.process_effect, api.thread_effect, api.network_effect,
            zero32, api.open, api.read, api.write, api.close, api.clock_gettime, api.getpid,
            api.pthread_create, api.pthread_join, api.socket, api.connect, api.send, api.recv,
            graph, entry,
        ]
        reader, target = self._platform_reader(entry, objects)
        verify_store(reader)
        bundle = compile_aarch64_bundle_bound_target(reader, (entry.cid,), target)
        self.assertEqual(
            tuple(name for _, _, name in bundle.foreign_calls),
            (b"open", b"read", b"write", b"close", b"clock_gettime", b"getpid",
             b"pthread_create", b"pthread_join", b"socket", b"connect", b"send", b"recv"),
        )
        self.assertEqual(api.utf8_string.cid, api.byte_slice.cid)


class SliceLibraryCompletionTests(unittest.TestCase):
    def test_zero_copy_byte_slice_and_utf8_string_length(self):
        from xax_platform import posix_android_api
        api = posix_android_api()
        graph = graph_fragment([
            Block(
                (api.byte_slice,),
                (Node(Operation.AGGREGATE_GET, (ValueRef.parameter(0, 0),), (api.b64,), attributes=(1,)),),
                Terminator.return_((ValueRef.node_result(0, 0),)),
            )
        ])
        entry = function(graph, (api.byte_slice,), (api.b64,))
        module = object_with_refs(Kind.MODULE, [entry])
        root = object_with_refs(Kind.PROGRAM_ROOT, [module])
        reader = StoreReader(write_store(root.cid, [api.b8, api.b64, api.byte_ptr_read, api.byte_slice, graph, entry, module, root]))
        self.assertEqual(execute(reader, entry.cid, ((object(), 5),)), (5,))
        self.assertEqual(api.utf8_string.cid, api.byte_slice.cid)


if __name__ == '__main__':
    unittest.main()
