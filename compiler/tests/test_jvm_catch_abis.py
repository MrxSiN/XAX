"""#49 slice 1 (ADR-406 (1)): the three catching JVM ABIs are foreign-call ABIs the verifier accepts.

A declaration ``jvm-invokestatic-catch java/lang/Integer parseInt(Ljava/lang/String;)I`` with outputs ``int`` and
``jvm-ref:Ljava/lang/Throwable;`` verifies (``verify_store``: the reference and, on Linux x86-64, the native typing
program).  The reference JVM backend does not lower it (``JVM-FOREIGN-ABI``; ADR-405 adds no Python); the XAX JVM
program does (#49 parts 2-3), for all three ABIs, and ``test_jvm_catch_run`` runs what it builds.
"""

from __future__ import annotations

import platform
import sys
import unittest

import xax_compiler as X
from xax_compiler import Operation, XaxError, bits_type, foreign_function_symbol, jvm_classfile_target
from xax_graph_builder import GraphBuilder, program_store
from xax_compiler import opaque_identity_type
from xax_jvm import REFERENCE_PREFIX, jvm_reference_type

CATCH_ABIS = (b"jvm-invokestatic-catch", b"jvm-invokevirtual-catch", b"jvm-invokeinterface-catch")
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")


def catching_program(abi: bytes):
    b32 = bits_type(32)
    string, throwable = jvm_reference_type(b"Ljava/lang/String;"), jvm_reference_type(b"Ljava/lang/Throwable;")
    receiver = (string,) if abi == CATCH_ABIS[0] else (jvm_reference_type(b"Ljava/lang/CharSequence;"),)
    member = b"parseInt(Ljava/lang/String;)I" if abi == CATCH_ABIS[0] else b"length()I"
    library = b"java/lang/Integer" if abi == CATCH_ABIS[0] else b"java/lang/CharSequence"
    carrier = foreign_function_symbol(library, member, receiver, (b32, throwable), abi=abi)
    graph = GraphBuilder()
    texts = (b"Ljava/lang/String;", b"Ljava/lang/CharSequence;", b"Ljava/lang/Throwable;")
    graph.track(b32, throwable, *receiver, *(opaque_identity_type(REFERENCE_PREFIX + text) for text in texts))
    block = graph.block(*receiver)
    value, _thrown = block.op(Operation.CALL_FOREIGN, block.params, (b32, throwable), entity=carrier)
    block.ret(value)  # the throwable is unused here
    entry = graph.function(receiver, (b32,))
    target = jvm_classfile_target()
    return entry, target, program_store(entry, target, tuple(graph.objects.values()))


class CatchAbiTests(unittest.TestCase):
    def test_verifier_accepts(self):
        for abi in CATCH_ABIS:
            with self.subTest(abi=abi):
                X.verify_store(catching_program(abi)[2])

    def test_reference_jvm_backend_declines(self):
        from xax_jvm import compile_jvm_bound_target
        entry, target, reader = catching_program(CATCH_ABIS[0])
        with self.assertRaises(XaxError) as raised:
            compile_jvm_bound_target(reader, entry.cid, target)
        self.assertEqual(raised.exception.diagnostic.rule, "JVM-FOREIGN-ABI")

    @unittest.skipUnless(LINUX_X86_64, "the XAX JVM program runs natively on Linux x86-64")
    def test_xax_jvm_program_lowers(self):
        from xax_selfhost_jvm import jvm_jar
        for abi in CATCH_ABIS:
            with self.subTest(abi=abi):
                entry, target, reader = catching_program(abi)
                jar = jvm_jar(reader, entry.cid, target, process_entry=False, frontend="xax")
                self.assertTrue(jar.startswith(b"PK"))


if __name__ == "__main__":
    unittest.main()
