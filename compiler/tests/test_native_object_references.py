"""Ledger 0015 (ADR-378): ``object <kind> 0x<body> <CID>...`` supplies a canonical object with references.

Store A's pure callee returns the constant 7. Store B's callee returns 7 through a stack slot: it allocates a
``ptr<bits32>`` with its owner token, stores, loads and ends the allocation. A holds neither the pointer type (whose
reference is ``bits32``) nor the stack owner. A batch supplies both with ``object`` (the pointer type with its
reference), then redefines the callee from B's native view, whose type lines name them by CID. Applied with the pinned
seed's ``xaxc edit``, it turns A into exactly B.
"""

from __future__ import annotations

import platform
import tempfile
import unittest
from pathlib import Path

import xax_compiler as X
import xax_selfhost_evolution as EV
from xax_compiler import Operation, Permission, bits_type, memory_effect_type, pointer_type, stack_owner_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import linux_api

B32 = bits_type(32)
POINTER = pointer_type(B32, Permission.READ_WRITE, 4)
OWNER, MEM = stack_owner_type(), memory_effect_type()


def program(through_stack: bool):
    """A Linux entry exiting with the callee's value; the callee's body is the constant, or the stack round trip."""
    api = linux_api()
    pure = GraphBuilder()
    body = pure.block()
    if through_stack:
        pure.track(POINTER, OWNER, MEM, B32)
        p, owner, memory = body.op(Operation.STACK_ALLOC, (), (POINTER, OWNER, MEM), attributes=(4, 4))
        memory = body.op1(Operation.STORE_BITS_LE, (p, body.const(B32, 7), memory), MEM, attributes=(4, 4))
        value, memory = body.op(Operation.LOAD_BITS_LE, (p, memory), (B32, MEM), attributes=(4, 4))
        body.op(Operation.STACK_END, (owner, memory), ())
        body.ret(value)
    else:
        body.ret(body.const(B32, 7))
    callee = pure.function((), (B32,))
    graph = GraphBuilder()
    block = graph.block(api.process_effect, api.filesystem_effect)
    process, fs = block.params
    status = block.op1(Operation.CALL_DIRECT, (), B32, entity=callee)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs)
    entry = graph.function((api.process_effect, api.filesystem_effect), (B32, api.process_effect, api.filesystem_effect))
    return program_store(entry, x86_64_linux_exec_target(), (*pure.objects.values(), *graph.objects.values(), *api.types)), callee


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "the seed runs on Linux x86-64")
class ObjectReferenceTests(unittest.TestCase):
    def test_supplied_pointer_type_with_reference(self):
        before, callee_a = program(False)
        after, callee_b = program(True)
        held = {o.cid for o in before.objects()}
        self.assertNotIn(POINTER.cid, held)
        self.assertIn(B32.cid, held)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            store_a, store_b, selector, view = work / "a.xax", work / "b.xax", work / "sel", work / "view"
            store_a.write_bytes(before.data)
            store_b.write_bytes(after.data)

            def handle(store, reader, cid):
                functions = sorted(o.cid for o in reader.objects() if o.kind == X.Kind.FUNCTION)
                return functions.index(cid)

            selector.write_text(f"F{handle(store_b, after, callee_b.cid)}")
            self.assertEqual(EV.run_compiler(EV.SEED_COMPILER, "edit", store_b, selector, view), 0)
            body = "\n".join(view.read_text().splitlines()[2:])
            supplied = []
            for name, obj in (("owner", OWNER), ("memory", MEM), ("pointer", POINTER)):
                if obj.cid in held:
                    continue
                references = "".join(f" {reference.hex()}" for reference in obj.references)
                supplied.append(f"define @{name}\nobject {int(obj.kind)} 0x{obj.body.hex()}{references}\nend\n")
            n = handle(store_a, before, callee_a.cid)
            batch = work / "batch"
            batch.write_text(f"R {before.root_cid.hex()}\nF{n}\n" + "".join(supplied) + f"define @f\n{body}\nend\nreplace F{n} @f\n")
            out = work / "out.xax"
            self.assertEqual(EV.run_compiler(EV.SEED_COMPILER, "edit", store_a, batch, out), 0)
            self.assertEqual(out.read_bytes(), after.data)


if __name__ == "__main__":
    unittest.main()
