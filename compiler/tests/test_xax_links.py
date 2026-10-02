"""Record links (ADR-097, OI-41): verified link fields, check-free ``link_follow``.

A small Linux process builds records ``(key: bits<64>, next: link)`` in an
arena and heads ``(head: link)`` in a table whose link target is the arena,
links two records, and walks the list from the head summing keys (exit 42).
Each negative vector changes one step and must be rejected by the verifier
with a specific rule; a null follow traps at run time.
"""

from __future__ import annotations

import platform
import signal
import sys
import unittest

from xax_compiler import (
    IntCompare,
    Operation,
    Permission,
    XaxError,
    bits_type,
    heap_view_type,
    link_type,
    null_link,
    pointer_type,
    tuple_type,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import compile_linux_executable, linux_api, run_linux_executable

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B32, B64 = bits_type(32), bits_type(64)
LINK = link_type()
RECORD = tuple_type((B64, LINK))
HEAD = tuple_type((LINK,))
RECORDS = pointer_type(RECORD, Permission.READ_WRITE, 16, space=2)
HEADS = pointer_type(HEAD, Permission.READ_WRITE, 8, space=2)
KEY = pointer_type(B64, Permission.READ_WRITE, 8, space=2)
NEXT = pointer_type(LINK, Permission.READ_WRITE, 8, space=2)
ARENA, TABLE = 64, 16  # four records, two heads


def program(mutation: str | None = None):
    """Return (function, target, objects); ``mutation`` names the one forged step."""
    api = linux_api()
    mem = api.memory_effect
    graph = GraphBuilder()
    graph.track(*api.types, LINK, RECORD, HEAD, RECORDS, HEADS, KEY, NEXT, bits_type(1))
    block = graph.block(api.process_effect, api.filesystem_effect, mem, mem)
    process, fs, arena_mem, table_mem = block.params

    def mapping(memory, size, pointer, alignment, target=None):
        raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(B64, size), memory), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
        operands = (raw, owner, memory) if target is None else (raw, owner, memory, target)
        return block.op(Operation.HEAP_VIEW, operands, (pointer, heap_view_type(size), mem), attributes=(size, alignment))

    arena, arena_token, arena_mem = mapping(arena_mem, ARENA, RECORDS, 16)
    table, table_token, table_mem = mapping(table_mem, TABLE, HEADS, 8, None if mutation == "untargeted-table" else arena)

    def field(pointer, offset, kind):
        return block.op1(Operation.ADDRESS_OFFSET, (pointer,), kind, attributes=(offset,))

    first = arena
    second = block.op1(Operation.ADDRESS_OFFSET, (arena,), RECORDS, attributes=(8 if mutation == "record-stride" else 16,))
    arena_mem = block.op1(Operation.STORE_BITS_LE, (field(first, 0, KEY), block.const(B64, 40), arena_mem), mem, attributes=(8, 8))
    arena_mem = block.op1(Operation.STORE_BITS_LE, (field(second, 0, KEY), block.const(B64, 2), arena_mem), mem, attributes=(8, 8))
    second_link = block.op1(Operation.LINK_MAKE, (second,), LINK)
    if mutation == "bits-into-link":
        # A bits value cannot be stored through a link-typed field pointer.
        arena_mem = block.op1(Operation.STORE_BITS_LE, (field(first, 8, NEXT), block.const(B64, 0x1000), arena_mem), mem, attributes=(8, 8))
    elif mutation == "wrong-field-offset":
        arena_mem = block.op1(Operation.STORE_BITS_LE, (field(first, 0, NEXT), second_link, arena_mem), mem, attributes=(8, 8))
    elif mutation == "checked-record-store":
        arena_mem = block.op1(Operation.CHECKED_STORE_BITS_LE, (arena, block.const(B32, 8), block.const(B64, 7), arena_mem), mem, attributes=(8, 1))
    else:
        arena_mem = block.op1(Operation.STORE_BITS_LE, (field(first, 8, NEXT), second_link, arena_mem), mem, attributes=(8, 8))
    head_field = field(table, 0, NEXT)
    first_link = block.op1(Operation.LINK_MAKE, (first,), LINK)
    if mutation == "foreign-table-link":
        # A link into the table's own storage is not a link into its target (the arena).
        first_link = block.op1(Operation.LINK_MAKE, (table,), LINK)
    if mutation != "null-follow":  # the head stays zero (null) in that vector
        table_mem = block.op1(Operation.STORE_BITS_LE, (head_field, first_link, table_mem), mem, attributes=(8, 8))
    if mutation == "foreign-write":
        # Foreign code reached with the arena's memory effect could forge link fields.
        _raw, _owner, arena_mem = block.op(Operation.CALL_FOREIGN, (block.const(B64, 4096), arena_mem), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)

    head, table_mem = block.op(Operation.LOAD_BITS_LE, (head_field, table_mem), (LINK, mem), attributes=(8, 8))
    if mutation == "null-follow":
        # Following a loaded link without a null test: verified (the fact is the
        # arena), and the null value traps at run time.
        block.op1(Operation.LINK_FOLLOW, (arena, head), RECORDS)
    view = second if mutation == "non-root-follow" else arena
    tokens = (heap_view_type(ARENA), heap_view_type(TABLE))
    walk = graph.block(api.process_effect, api.filesystem_effect, mem, mem, *tokens, LINK, B64)
    step = graph.block(api.process_effect, api.filesystem_effect, mem, mem, *tokens, LINK, B64)
    done = graph.block(api.process_effect, api.filesystem_effect, mem, mem, *tokens, B64)
    start = (process, fs, arena_mem, table_mem, arena_token, table_token, head, block.const(B64, 0))
    block.br(walk, *start)
    process, fs, arena_mem, table_mem, arena_token, table_token, cursor, total = walk.params
    null = walk.op1(Operation.CONSTANT, (), LINK, entity=null_link())
    carried = (process, fs, arena_mem, table_mem, arena_token, table_token)
    walk.cbr(walk.op1(Operation.INT_COMPARE, (cursor, null), bits_type(1), attributes=(IntCompare.NE,)), step, (*carried, cursor, total), done, (*carried, total))
    process, fs, arena_mem, table_mem, arena_token, table_token, cursor, total = step.params
    node = step.op1(Operation.LINK_FOLLOW, (view, cursor), RECORDS)
    key, arena_mem = step.op(Operation.LOAD_BITS_LE, (step.op1(Operation.ADDRESS_OFFSET, (node,), KEY, attributes=(0,)), arena_mem), (B64, mem), attributes=(8, 8))
    following, arena_mem = step.op(Operation.LOAD_BITS_LE, (step.op1(Operation.ADDRESS_OFFSET, (node,), NEXT, attributes=(8,)), arena_mem), (LINK, mem), attributes=(8, 8))
    step.br(walk, process, fs, arena_mem, table_mem, arena_token, table_token, following, step.op1(Operation.ADD_WRAP, (total, key), B64))
    process, fs, arena_mem, table_mem, arena_token, table_token, total = done.params

    def release(view_, token, memory, pointer, size):
        return done.op(Operation.CALL_FOREIGN, (view_, token, memory), (B64, mem), entity=api.munmap_view(pointer, size))[1]

    if mutation == "target-ends-first":
        arena_mem = release(arena, arena_token, arena_mem, RECORDS, ARENA)
        table_mem = release(table, table_token, table_mem, HEADS, TABLE)
    else:
        table_mem = release(table, table_token, table_mem, HEADS, TABLE)
        arena_mem = release(arena, arena_token, arena_mem, RECORDS, ARENA)
    status = done.op1(Operation.INT_TRUNCATE, (total,), B32)
    process = done.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    done.ret(status, process, fs, arena_mem, table_mem)
    function = graph.function((api.process_effect, api.filesystem_effect, mem, mem), (B32, api.process_effect, api.filesystem_effect, mem, mem))
    return function, x86_64_linux_exec_target(), tuple(graph.objects.values())


class LinkVerifierTests(unittest.TestCase):
    REJECTIONS = {
        "bits-into-link": "MEMORY-STORE-TYPE",
        "wrong-field-offset": "MEMORY-RECORD-FIELD-OFFSET",
        "record-stride": "MEMORY-RECORD-OFFSET-STRIDE",
        "checked-record-store": "MEMORY-BYTE-ADDRESSABLE-VALUE",
        "foreign-table-link": "MEMORY-LINK-STORE-PROVENANCE",
        "untargeted-table": "MEMORY-LINK-STORE-PROVENANCE",
        "non-root-follow": "MEMORY-LINK-FOLLOW-ROOT-VIEW",
        "target-ends-first": "MEMORY-LINK-TARGET-OUTLIVES",
        "foreign-write": "MEMORY-LINK-STORAGE-FOREIGN",
    }

    def test_valid_program_verifies(self):
        program_store(*program())

    def test_forged_links_reject(self):
        for mutation, rule in self.REJECTIONS.items():
            with self.subTest(mutation=mutation):
                with self.assertRaises(XaxError) as raised:
                    program_store(*program(mutation))
                self.assertEqual(raised.exception.diagnostic.rule, rule)

    def test_link_constants_are_null_only(self):
        from xax_compiler import Kind, SemanticObject, _decode_constant, uleb

        forged = SemanticObject.create(Kind.CONSTANT, uleb(0) + uleb(8) + (0x1000).to_bytes(8, "little"), [LINK.cid])
        with self.assertRaises(XaxError) as raised:
            _decode_constant(forged, {LINK.cid: LINK}.__getitem__)
        self.assertEqual(raised.exception.diagnostic.rule, "CONST-LINK-NULL-ONLY")
        self.assertEqual(_decode_constant(null_link(), {LINK.cid: LINK}.__getitem__)[1], 0)


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class LinkExecutionTests(unittest.TestCase):
    def run_program(self, mutation=None):
        function, target, objects = program(mutation)
        return run_linux_executable(compile_linux_executable(program_store(function, target, objects), function.cid, target.cid).data)

    def test_walk_sums_linked_keys(self):
        self.assertEqual(self.run_program().returncode, 42)

    def test_null_follow_traps(self):
        self.assertEqual(self.run_program("null-follow").returncode, -signal.SIGILL)


if __name__ == "__main__":
    unittest.main()
