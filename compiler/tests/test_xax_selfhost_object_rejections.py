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
    import xax_compiler
    import xax_selfhost_verify

    saved = list(xax_selfhost_verify._NATIVE)
    saved_typing = (xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED)
    saved_objects = (set(xax_compiler._XAX_VALID_OBJECTS), dict(xax_compiler._XAX_REJECTED_OBJECTS))
    xax_compiler._XAX_VALID_OBJECTS.clear()
    xax_compiler._XAX_REJECTED_OBJECTS.clear()
    xax_compiler._PARSED_GRAPHS.clear()
    if not native:  # the bootstrap alone: no store verifier, no typing program (S8c.24: constants)
        xax_selfhost_verify._NATIVE[:] = [None]
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = None, True
    try:
        yield
    finally:
        xax_selfhost_verify._NATIVE[:] = saved
        xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = saved_typing
        xax_compiler._XAX_VALID_OBJECTS.clear()
        xax_compiler._XAX_VALID_OBJECTS.update(saved_objects[0])
        xax_compiler._XAX_REJECTED_OBJECTS.clear()
        xax_compiler._XAX_REJECTED_OBJECTS.update(saved_objects[1])
        xax_compiler._PARSED_GRAPHS.clear()


def _outcome(native: bool, root: SemanticObject, objects):
    with _verifier(native):
        try:
            verify_store(StoreReader(write_store(root.cid, tuple(objects))))
        except XaxError as error:
            d = error.diagnostic
            return ("reject", d.code, d.rule, d.entity, repr(d.expected), repr(d.actual), d.dependencies, d.repair_neighborhood)
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


GROUP_GRAPHS = ("group_entry", "group_return", "group_member_range", "group_call_contract", "group_scc")


def _group_variant(variant: str):
    """A one-member group whose member graph (or interface) breaks a check made after the graph parses."""
    from test_xax_recursion import _graph, _group_call
    from xax_compiler import IntCompare, RecursionMember, recursion_group

    graph = GraphBuilder()
    entry = graph.block(B32)
    base, recurse = graph.block(), graph.block(B32)
    (n,) = entry.params
    entry.cbr(entry.op1(Operation.INT_COMPARE, (n, entry.const(B32, 0)), bits_type(1), attributes=(IntCompare.EQ,)), base, (), recurse, (n,))
    base.ret(base.const(B32, 1))
    (m,) = recurse.params
    if variant == "group_scc":
        recurse.ret(m)  # no member call: not recursive
    else:
        member = 3 if variant == "group_member_range" else 0
        results = (B64,) if variant == "group_call_contract" else (B32,)
        (inner,) = _group_call(recurse, member, (recurse.op1(Operation.SUB_WRAP, (m, recurse.const(B32, 1)), B32),), results)
        recurse.ret(m if variant == "group_call_contract" else inner)
    graph.track(B64)
    fragment = _graph(graph)
    parameters = (B64,) if variant == "group_entry" else (B32,)
    returns = (B64,) if variant == "group_return" else (B32,)
    group = recursion_group([RecursionMember(fragment, parameters, returns)])
    return group, (*graph.objects.values(), fragment, group)


def _group(variant: str):
    """``(group, member function, objects)``: the factorial group and its member function; ``variant`` rewrites one."""
    from test_xax_recursion import factorial_group
    from xax_compiler import group_member_function

    group, objects = factorial_group() if variant not in GROUP_GRAPHS else _group_variant(variant)
    objects = tuple(item for item in objects if item.cid != group.cid)
    fragment = next(item for item in objects if item.kind == Kind.GRAPH_FRAGMENT)
    references = tuple(sorted({fragment.cid, B32.cid, *((B64.cid,) if variant == "group_unused" else ())}))
    at = {cid: index for index, cid in enumerate(references)}
    body = uleb(1) + uleb(at[fragment.cid]) + uleb(1) + uleb(at[B32.cid]) + uleb(1) + uleb(at[B32.cid])
    bodies = {
        "group_empty": uleb(0),
        "group_ref_index": uleb(1) + uleb(7) + body[2:],
        "group_carrier": uleb(1) + uleb(at[B32.cid]) + body[2:],
        "group_type_index": uleb(1) + uleb(at[fragment.cid]) + uleb(1) + uleb(9) + uleb(0),
        "group_trailing": body + b"\x00",
        "group_unused": body,
    }
    if variant in bodies:
        group = SemanticObject.create(Kind.RECURSION_GROUP, bodies[variant], references)
    member = group_member_function(group, 0)
    if variant == "member_trailing":
        member = SemanticObject.create(Kind.FUNCTION, uleb(0) + uleb(0) + b"\x00", (group.cid,))
    elif variant == "member_range":
        member = SemanticObject.create(Kind.FUNCTION, uleb(0) + uleb(5), (group.cid,))
    return group, member, objects


def _target(variant: str):
    """A target object; ``variant`` rewrites one field of a known target's body (``None`` when it keeps none)."""
    import xax_compiler as X

    bases = {"target_riscv": X.riscv64_baremetal_target, "target_wasm": X.wasm32_target, "target_jvm": X.jvm_classfile_target,
             "target_spirv": X.spirv_vulkan_compute_target, "target_aarch64": X.aarch64_baremetal_target,
             "target_profile": X.riscv64_baremetal_target}
    base = bases.get(variant, X.x86_64_linux_exec_target)()
    body = base.body
    cursor = X.Cursor(body, "test")
    identity = cursor.byte_string()
    head = [cursor.uleb() for _ in range(6)]  # profile, architecture, abi, format, word, pointer
    rest = body[cursor.pos:]
    encode = lambda identity_, head_, rest_: uleb(len(identity_)) + identity_ + b"".join(uleb(item) for item in head_) + rest_  # noqa: E731
    if variant == "target_refs":
        return SemanticObject.create(Kind.TARGET, body, (B8.cid,))
    if variant == "target_identity_empty":
        return SemanticObject.create(Kind.TARGET, encode(b"", head, rest))
    if variant == "target_truncated":
        return SemanticObject.create(Kind.TARGET, uleb(200) + b"short")
    if variant == "target_trailing":
        return SemanticObject.create(Kind.TARGET, body + b"\x00")
    changes = {"target_architecture": (1, 9), "target_profile": (0, 9), "target_x86": (2, 7), "target_riscv": (2, 9), "target_wasm": (4, 32),
               "target_jvm": (2, 9), "target_spirv": (5, 64), "target_aarch64": (2, 7)}
    if variant in changes:
        index, value = changes[variant]
        head[index] = value
        return SemanticObject.create(Kind.TARGET, encode(identity, head, rest))
    return None


def _constant(variant: str):
    """A constant object breaking one value rule of ``_decode_constant`` (None for other variants)."""
    from xax_compiler import float_type, tuple_type

    cases = {
        "constant_bits_length": (B32, b"\x01\x02\x03"),
        "constant_bits_high": (bits_type(4), b"\x30"),
        "constant_float_width": (float_type(1), bytes(8)),
        "constant_float_nan": (float_type(1), (0x7FC00001).to_bytes(4, "little")),
        "constant_link": (None, b"\x01" + bytes(7)),
        "constant_scalar": (tuple_type((B32,)), b"\x00"),
    }
    types = {  # S8c.25 (ADR-243): malformed types, held as a module child
        "type_trailing": uleb(1) + uleb(32) + b"\x00",
        "type_bits_zero": uleb(1) + uleb(0),
        "type_float_format": uleb(7) + uleb(9),
        "type_link_body": uleb(11) + b"\x00",
        "type_form": uleb(40),
        # S8c.26 (ADR-244): opaque, effect, sum, pointer.
        "type_opaque_trailing": uleb(5) + uleb(1) + b"\x00",
        "type_opaque_kind": uleb(5) + uleb(9),
        "type_effect_domain": uleb(3) + uleb(40),
        "type_effect_zero_instance": uleb(3) + uleb(1) + uleb(0),
        "type_sum_empty": uleb(10) + uleb(0),
        # S8c.26 (ADR-244): resource forms.
        "type_resource_owner": uleb(4) + uleb(1) + uleb(2),
        "type_resource_plain": uleb(4) + uleb(1) + uleb(1) + uleb(4) + uleb(0) + uleb(0),
        "type_resource_flags": uleb(4) + uleb(3) + uleb(1) + uleb(64) + uleb(0) + uleb(0),
        "type_resource_trailing": uleb(4) + uleb(3) + uleb(1) + uleb(4) + uleb(0) + uleb(0) + b"\x00",
        # S8c.28 (ADR-246): opaque identity types.
        "type_identity_truncated": uleb(6) + uleb(9) + b"ab",
        "type_identity_trailing": uleb(6) + uleb(2) + b"abc",
        "type_identity_empty": uleb(6) + uleb(0),
    }
    if variant in types:
        return SemanticObject.create(Kind.TYPE, types[variant]), ()
    pointers = {  # [space, element index, permission, alignment] over one reference (b32)
        "type_pointer_index": (1, 4, 3, 4), "type_pointer_permission": (1, 0, 7, 4), "type_pointer_alignment": (1, 0, 3, 3),
        "type_pointer_space": (0, 0, 3, 4),
    }
    if variant in pointers:
        return SemanticObject.create(Kind.TYPE, uleb(2) + b"".join(uleb(item) for item in pointers[variant]), (B32.cid,)), ()
    if variant == "type_array_proof":
        from xax_compiler import memory_effect_type

        effect = memory_effect_type()
        return SemanticObject.create(Kind.TYPE, uleb(9) + uleb(0) + uleb(4), (effect.cid,)), (effect,)
    lists = {  # S8c.27 (ADR-245): tuple (8) and sum (10) items over references (b32, b64) or a memory effect
        "type_tuple_index": (8, (0, 5), False), "type_tuple_trailing": (8, (0, 1), False), "type_sum_variant": (10, (0, 1), True),
        "type_tuple_element": (8, (1, 0), True), "type_tuple_unused": (8, (0,), False),
    }
    if variant in lists:
        from xax_compiler import memory_effect_type

        form, indices, effect = lists[variant]
        extra = memory_effect_type() if effect else B64
        references = tuple(sorted((B32.cid, extra.cid)))
        body = uleb(form) + uleb(len(indices)) + b"".join(uleb(item) for item in indices) + (b"\x00" if variant == "type_tuple_trailing" else b"")
        return SemanticObject.create(Kind.TYPE, body, references), ((extra,) if effect else ())
    bodies = {  # S8c.29 (ADR-247): malformed constant bodies over one b32 reference
        "constant_ref_index": uleb(3) + uleb(4) + bytes(4), "constant_truncated": uleb(0) + uleb(9) + bytes(4),
        "constant_trailing": uleb(0) + uleb(4) + bytes(5),
    }
    if variant in bodies:
        return SemanticObject.create(Kind.CONSTANT, bodies[variant], (B32.cid,)), ()
    if variant == "type_identity_refs":
        return SemanticObject.create(Kind.TYPE, uleb(6) + uleb(2) + b"ab", (B8.cid,)), ()
    if variant in ("type_pointer_proof", "type_pointer_unused"):
        from xax_compiler import memory_effect_type

        element = memory_effect_type() if variant == "type_pointer_proof" else B32
        references = (element.cid,) if variant == "type_pointer_proof" else tuple(sorted((B32.cid, B64.cid)))
        body = uleb(2) + uleb(1) + uleb(references.index(element.cid)) + uleb(3) + uleb(4)
        return SemanticObject.create(Kind.TYPE, body, references), ((element,) if variant == "type_pointer_proof" else ())
    if variant == "type_array_index":
        return SemanticObject.create(Kind.TYPE, uleb(9) + uleb(3) + uleb(4), (B32.cid,)), ()
    if variant == "type_opaque_refs":
        return SemanticObject.create(Kind.TYPE, uleb(5) + uleb(1), (B8.cid,)), ()
    if variant == "type_bits_refs":
        return SemanticObject.create(Kind.TYPE, uleb(1) + uleb(8), (B8.cid,)), ()
    if variant not in cases:
        return None, ()
    from xax_compiler import link_type

    value_type, value = cases[variant]
    value_type = value_type if value_type is not None else link_type()
    return SemanticObject.create(Kind.CONSTANT, uleb(0) + uleb(len(value)) + value, (value_type.cid,)), (value_type, *(
        (B32,) if variant == "constant_scalar" else ()))


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
    group, member, group_objects = _group(variant)
    with_member = not variant.startswith("group_")  # a member function of a broken group fails with the group's diagnostic
    target_object = _target(variant)
    constant_object, constant_types = _constant(variant)
    children = (*types, contract, function, group, *((member,) if with_member else ()), *((target_object,) if target_object else ()),
                *((constant_object,) if constant_object else ()), *constant_types)
    supporting = (*function_objects, *group_objects)  # reached through references
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
    objects = list({item.cid: item for item in (*children, *supporting, module)}.values())
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
    "member_trailing": "FUNCTION-GROUP-MEMBER-BODY", "member_range": "GRAPH-RECURSION-MEMBER",
    # S8c.21 (ADR-239): recursion-group member lists.
    "group_empty": "GRAPH-RECURSION-GROUP-NONEMPTY", "group_ref_index": "GRAPH-REF-INDEX", "group_carrier": "GRAPH-FUNCTION-CARRIER",
    "group_type_index": "GRAPH-REF-INDEX", "group_trailing": "RECURSION-GROUP-BODY", "group_unused": "SER-REFS-DIRECT-ONLY",
    # S8c.22 (ADR-240): group checks after the member graphs parse.
    "group_entry": "GRAPH-ENTRY-CONTRACT", "group_return": "GRAPH-RETURN-CONTRACT", "group_member_range": "GRAPH-RECURSION-MEMBER",
    "group_call_contract": "GRAPH-CALL-CONTRACT", "group_scc": "GRAPH-RECURSION-SCC",
    # S8c.23 (ADR-241): targets.
    "target_refs": "SER-REFS-DIRECT-ONLY", "target_identity_empty": "TARGET-IDENTITY-NONEMPTY", "target_truncated": "SER-BOUNDS",
    "target_trailing": "TARGET-NATIVE-BODY", "target_architecture": "TARGET-ARCHITECTURE-SUPPORTED", "target_profile": "TARGET-PROFILE-SUPPORTED",
    "target_x86": "TARGET-X86-64-PROFILE", "target_riscv": "TARGET-RISCV64-RAW", "target_wasm": "TARGET-WASM32-CORE", "target_jvm": "TARGET-JVM-CLASSFILE",
    "target_spirv": "TARGET-SPIRV-COMPUTE", "target_aarch64": "TARGET-AARCH64-PROFILE",
    # S8c.24 (ADR-242): constants (decided by the XAX typing program).
    "constant_bits_length": "CONST-BITS-WIDTH", "constant_bits_high": "CONST-BITS-WIDTH", "constant_float_width": "CONST-FLOAT-WIDTH",
    "constant_float_nan": "CONST-FLOAT-CANONICAL-NAN", "constant_link": "CONST-LINK-NULL-ONLY", "constant_scalar": "CONST-SCALAR-TYPE",
    # S8c.25 (ADR-243): types.
    "type_trailing": "TYPE-BODY", "type_bits_zero": "TYPE-BITS", "type_float_format": "TYPE-FLOAT-FORMAT", "type_link_body": "TYPE-LINK-CANONICAL",
    "type_form": "TYPE-FORM-SUPPORTED", "type_bits_refs": "TYPE-BITS",
    # S8c.26 (ADR-244): compound forms before their element types.
    "type_opaque_trailing": "TYPE-BODY", "type_opaque_kind": "TYPE-OPAQUE-KIND", "type_opaque_refs": "TYPE-OPAQUE-CANONICAL",
    "type_effect_domain": "TYPE-EFFECT-DOMAIN", "type_effect_zero_instance": "TYPE-EFFECT-CANONICAL", "type_sum_empty": "TYPE-SUM-NONEMPTY",
    "type_pointer_index": "GRAPH-REF-INDEX", "type_pointer_permission": "TYPE-POINTER-PERMISSION", "type_pointer_alignment": "TYPE-POINTER",
    "type_pointer_space": "TYPE-POINTER",
    # S8c.26 (ADR-244): resource and array forms.
    "type_resource_owner": "TYPE-RESOURCE-STACK-OWNER", "type_resource_plain": "TYPE-RESOURCE-CANONICAL", "type_resource_flags": "TYPE-RESOURCE-CANONICAL",
    "type_resource_trailing": "TYPE-BODY", "type_array_proof": "TYPE-ARRAY-VALUE-ELEMENT", "type_array_index": "GRAPH-REF-INDEX",
    # S8c.27 (ADR-245): tuple and sum items.
    "type_tuple_index": "GRAPH-REF-INDEX", "type_tuple_trailing": "TYPE-BODY", "type_sum_variant": "TYPE-SUM-VALUE-VARIANT",
    "type_tuple_element": "TYPE-TUPLE-VALUE-ELEMENT", "type_tuple_unused": "SER-REFS-DIRECT-ONLY",
    # S8c.28 (ADR-246): pointer elements and opaque identity types.
    "type_pointer_proof": "TYPE-POINTER-VALUE-ELEMENT", "type_pointer_unused": "SER-REFS-DIRECT-ONLY",
    "type_identity_truncated": "SER-BOUNDS", "type_identity_trailing": "TYPE-BODY", "type_identity_empty": "TYPE-OPAQUE-IDENTITY-CANONICAL",
    "type_identity_refs": "TYPE-OPAQUE-IDENTITY-CANONICAL",
    # S8c.29 (ADR-247): malformed constant bodies.
    "constant_ref_index": "GRAPH-REF-INDEX", "constant_truncated": "SER-BOUNDS", "constant_trailing": "CONST-BODY",
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

        import xax_selfhost_typing

        original_constants = xax_selfhost_typing.NativeTyping.object_rejections

        def deciding_constants(self_, *arguments):
            result = original_constants(self_, *arguments)
            decided.append(bool(result))
            return result

        xax_selfhost_verify.NativeStoreVerifier.verify_with_rejections = deciding
        xax_selfhost_typing.NativeTyping.object_rejections = deciding_constants
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
            xax_selfhost_typing.NativeTyping.object_rejections = original_constants


if __name__ == "__main__":
    unittest.main()
