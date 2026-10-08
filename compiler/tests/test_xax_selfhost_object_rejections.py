"""S8c.19 (ADR-237): the XAX store verifier decides object rejections with the bootstrap's diagnostics.

Each case builds a store whose one object breaks one rule of ``verify_object`` (a module or program-root reference
list, a call contract) and checks that the XAX verifier rejects that object itself and that the diagnostic equals
the Python bootstrap's.
"""

from __future__ import annotations

import contextlib
import platform
import sys
import unittest

from xax_compiler import (
    Kind, Operation, SemanticObject, StoreReader, XaxError, bits_type, call_contract, object_with_refs, ref_body, uleb, verify_store, write_store,
)
from xax_graph_builder import GraphBuilder

LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
B8, B32, B64 = bits_type(8), bits_type(32), bits_type(64)


@contextlib.contextmanager
def _verifier(native: bool):
    import xax_selfhost_verify

    saved = list(xax_selfhost_verify._NATIVE)
    if not native:
        xax_selfhost_verify._NATIVE[:] = [None]
    try:
        yield
    finally:
        xax_selfhost_verify._NATIVE[:] = saved


def _outcome(native: bool, root: SemanticObject, objects):
    with _verifier(native):
        try:
            verify_store(StoreReader(write_store(root.cid, tuple(objects))))
        except XaxError as error:
            d = error.diagnostic
            return ("reject", d.code, d.rule, d.entity, repr(d.expected), repr(d.actual))
        return ("accept",)


def _contract(body_of=None, extra=()):
    """A contract ``(b32, b64) -> (b32)``; ``body_of(positions)`` replaces its body, ``extra`` adds references."""
    good = call_contract((B32, B64), (B32,), may_return=True, may_trap=False)
    if body_of is None and not extra:
        return good
    references = tuple(sorted({*good.references, *(item.cid for item in extra)}))
    positions = {cid: index for index, cid in enumerate(references)}
    body = body_of(positions) if body_of is not None else (
        uleb(2) + uleb(positions[B32.cid]) + uleb(positions[B64.cid]) + uleb(1) + uleb(positions[B32.cid]) + b"\x01\x00")
    return SemanticObject.create(Kind.CALL_CONTRACT, body, references)


def _function(variant: str):
    """``(function, objects)``: ``(b32) -> b32`` adding one; ``variant`` rewrites the function object's body."""
    graph = GraphBuilder()
    block = graph.block(B32)
    (x,) = block.params
    block.ret(block.op1(Operation.ADD_WRAP, (x, block.const(B32, 1)), B32))
    function = graph.function((B32,), (B32,))
    objects = [item for item in graph.objects.values() if item.cid != function.cid]
    fragment = next(item for item in objects if item.kind == Kind.GRAPH_FRAGMENT)
    references = tuple(sorted({fragment.cid, B32.cid, *((B64.cid,) if variant in ("function_entry", "function_return", "function_unused") else ())}))
    at = {cid: index for index, cid in enumerate(references)}
    parameters, returns = [B32], [B32]
    if variant == "function_entry":
        parameters = [B64]
    if variant == "function_return":
        returns = [B64]
    if variant == "function_carrier":
        references = (B32.cid,)
        at = {B32.cid: 0, fragment.cid: 0}
    body = (uleb(at[fragment.cid]) + uleb(len(parameters)) + b"".join(uleb(at[item.cid]) for item in parameters)
            + uleb(len(returns)) + b"".join(uleb(at[item.cid]) for item in returns))
    if variant == "function_ref_index":
        body = uleb(7) + body[1:]
    elif variant == "function_type_index":
        body = uleb(at[fragment.cid]) + uleb(1) + uleb(9) + uleb(0)
    elif variant == "function_trailing":
        body += b"\x00"
    if variant.startswith("function_") and variant != "function_valid":
        function = SemanticObject.create(Kind.FUNCTION, body, references)
    return function, objects


def _store(variant: str):
    """``(root, objects)``: a root, one module holding three types and a contract; ``variant`` breaks one object."""
    types = (B8, B32, B64)
    contracts = {
        "contract_ref_index": lambda p: uleb(1) + uleb(9) + uleb(0) + b"\x01\x00",
        "contract_truncated": lambda p: uleb(1) + uleb(p[B32.cid]) + uleb(1) + uleb(p[B32.cid]) + b"\x01",
        "contract_bool": lambda p: uleb(1) + uleb(p[B32.cid]) + uleb(1) + uleb(p[B32.cid]) + b"\x01\x02",
        "contract_trailing": lambda p: uleb(1) + uleb(p[B32.cid]) + uleb(1) + uleb(p[B32.cid]) + b"\x01\x00\x00",
    }
    if variant in contracts:
        contract = _contract(contracts[variant], extra=(B64,))
    elif variant == "contract_unused":
        contract = _contract(extra=(B8,))
    else:
        contract = _contract()
    function, function_objects = _function(variant if variant.startswith("function_") else "function_valid")
    children = (*types, contract, function)
    supporting = tuple(item for item in function_objects if item.kind != Kind.TYPE)  # reached through the function
    module = object_with_refs(Kind.MODULE, children)
    count = len(module.references)
    bodies = {
        "module_trailing": ref_body(range(count)) + b"\x00",
        "module_ref_index": uleb(count) + b"".join(uleb(index) for index in (*range(count - 1), count + 3)),
        "module_order": uleb(count) + b"".join(uleb(index) for index in reversed(range(count))),
        "module_short": uleb(count - 1) + b"".join(uleb(index) for index in range(count - 1)),
    }
    if variant in bodies:
        module = SemanticObject.create(Kind.MODULE, bodies[variant], module.references)
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    objects = [*children, *supporting, module]
    if variant == "root_child_kind":
        root = SemanticObject.create(Kind.PROGRAM_ROOT, ref_body(range(2)), tuple(sorted((module.cid, B8.cid))))
    return root, (*objects, root)


VARIANTS = {
    "module_trailing": "SCHEMA-BODY", "module_ref_index": "GRAPH-REF-INDEX", "module_order": "SER-REF-BODY-CANONICAL",
    "module_short": "SER-REF-BODY-CANONICAL", "root_child_kind": "GRAPH-CHILD-KIND",
    "contract_ref_index": "GRAPH-REF-INDEX", "contract_truncated": "SER-BOUNDS", "contract_bool": "SER-BOOL-CANONICAL",
    "contract_trailing": "CALL-CONTRACT-BODY", "contract_unused": "SER-REFS-DIRECT-ONLY",
    # S8c.20 (ADR-238): functions.
    "function_ref_index": "GRAPH-REF-INDEX", "function_type_index": "GRAPH-REF-INDEX", "function_carrier": "GRAPH-FUNCTION-CARRIER",
    "function_trailing": "FUNCTION-BODY", "function_entry": "GRAPH-ENTRY-CONTRACT", "function_return": "GRAPH-RETURN-CONTRACT",
    "function_unused": "SER-REFS-DIRECT-ONLY",
}


@unittest.skipUnless(LINUX_X86_64, "requires a Linux x86-64 host")
class XaxObjectRejectionTests(unittest.TestCase):
    def test_rejections_match_the_bootstrap_and_are_decided_by_xax(self):
        import xax_selfhost_verify

        decided = []
        original = xax_selfhost_verify.NativeStoreVerifier.verify_with_rejections

        def deciding(self_, *arguments):
            result = original(self_, *arguments)
            decided.append(bool(result[1]))
            return result

        xax_selfhost_verify.NativeStoreVerifier.verify_with_rejections = deciding
        try:
            root, objects = _store("valid")
            self.assertEqual(_outcome(True, root, objects), ("accept",))
            self.assertEqual(_outcome(False, root, objects), ("accept",))
            for variant, rule in VARIANTS.items():
                with self.subTest(variant=variant):
                    root, objects = _store(variant)
                    baseline = _outcome(False, root, objects)
                    decided.clear()
                    self.assertEqual(_outcome(True, root, objects), baseline)
                    self.assertEqual(baseline[:1] + baseline[2:3], ("reject", rule))
                    self.assertTrue(any(decided), variant)
        finally:
            xax_selfhost_verify.NativeStoreVerifier.verify_with_rejections = original


if __name__ == "__main__":
    unittest.main()
