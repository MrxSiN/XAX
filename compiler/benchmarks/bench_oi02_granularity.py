"""OI-02 objectization granularity comparison (tooling-only evidence).

Compares five objectizations of the same multi-module programs:

* ``function``: the current canonical store (types, constants, one graph
  fragment and one function object per function, modules, root).
* ``module``: a measurement-only packing where every module becomes one
  content-addressed unit holding the canonical envelopes of the fine objects it
  exclusively owns; objects claimed by several modules go to one ``common``
  unit.  Units reuse ``SemanticObject``/``write_store`` so envelope, reference
  table and index overhead are measured with the real container encoding.  The
  packed store is never verified, persisted or executed as XAX: it is unpacked
  back to the canonical fine objects, which must be byte-identical.
* ``call_indirect``: a measurement-only variant of the function grain where a
  caller's ``CALL_DIRECT`` entity is a nominal declaration (symbol plus
  signature, kind 0 outside the ``Kind`` enum) and each module binds its
  declarations to definitions.  The unchanged verifier and executor run it
  through a resolver that presents the bound definition under the declaration
  CID; binding modules are checked for declaration/definition signature match.
* ``block``: a measurement-only finer grain where a function graph is a small
  skeleton over content-addressed per-block units.  Each block unit carries the
  canonical single-block graph encoding with a block-local reference table.
  Reassembly must reproduce the canonical graph/function CIDs exactly before
  the candidate is verified or executed.
* ``stable_interface_block``: stable local callee declarations reference a
  separately content-addressed canonical ``CallContract`` summary; module
  bindings map declarations to body carriers whose graphs use the same block
  units/skeletons as ``block``.  The summary is derived from the exact function
  interface/control facts and reassembly rejects any summary/body mismatch.

Mutations are produced by rebuilding a program spec with one changed fact, so
unchanged objects retain CIDs by content addressing rather than by tooling.
Deterministic counts/bytes go to the JSON evidence; wall-clock samples are
recorded raw beside them and are not deterministic.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from time import perf_counter_ns

from xax_compiler import (
    CID_SIZE,
    Cursor,
    Block,
    Kind,
    Node,
    Operation,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    ATTRIBUTE_OPERATIONS,
    ENTITY_OPERATIONS,
    TerminatorKind,
    bits_type,
    call_contract,
    constant,
    decode_object,
    execute,
    function,
    graph_fragment,
    object_with_refs,
    semantic_cid,
    uleb,
    verify_object,
    write_store,
    _decode_call_contract,
    _decode_function_interface,
    _execute_function,
    _read_edge,
    _read_value,
)


OUTPUT = Path(__file__).resolve().parent / "oi02_granularity_evidence.json"
B64 = bits_type(64)
MASK = (1 << 64) - 1
TIMING_SAMPLES = 5


# ---------------------------------------------------------------- programs

def project_spec(modules: int, functions: int, topology: str, blocks: int = 1) -> dict:
    """Module m, function f: ``f(a, b) = callee(a, b) * k + c`` (leaf: ``a + b``).

    ``chain``: f calls f-1; each module's f0 calls the previous module's last
    function (deep transitive dependency).  ``star``: every f>0 calls its own
    module's f0 leaf (shallow fan-in, independent modules).  ``blocks=4``
    spreads the same arithmetic over four branch-linked blocks (call, ``* k``,
    ``+ c``, return) so each constant lives in its own block.
    """
    return {
        "modules": modules,
        "functions": functions,
        "topology": topology,
        "blocks": blocks,
        "constants": {(m, f): (m * 31 + f * 7 + 3, f % 3 + 2) for m in range(modules) for f in range(functions)},
        "extra": {},
    }


def service_spec(modules: int = 6, functions: int = 8) -> dict:
    """Layered service-like DAG generated through the ordinary XAX constructors.

    Even functions call a service in the preceding module; odd functions wrap
    the immediately preceding local function.  Module 0 provides the base
    utility layer.  Four blocks per function model request/decode/transform/
    return stages without introducing any source-language representation.
    """
    spec = project_spec(modules, functions, "service", blocks=4)
    callees: dict[tuple[int, int], tuple[int, int] | None] = {}
    for m in range(modules):
        for f in range(functions):
            if m == 0:
                callees[(m, f)] = None if f == 0 else (m, (f - 1) // 2)
            elif f % 2:
                callees[(m, f)] = (m, f - 1)
            else:
                callees[(m, f)] = (m - 1, (f * 3 + m) % functions)
    return {**spec, "callees": callees}


def callee_of(spec: dict, m: int, f: int) -> tuple[int, int] | None:
    if "callees" in spec:
        return spec["callees"][(m, f)]
    if spec["topology"] == "star":
        return (m, 0) if f else None
    if f:
        return (m, f - 1)
    return (m - 1, spec["functions"] - 1) if m else None


# Measurement-only kinds outside the Kind enum, so they can never be mistaken
# for, or decoded as, canonical objects.  All encode in one ULEB byte.
DECLARATION_KIND = 0
STABLE_DECLARATION_KIND = 124
BODY_KIND = 125
BLOCK_KIND = 126
SKELETON_KIND = 127


def declaration(name: tuple[int, int]) -> SemanticObject:
    """Stable callee identity: symbol plus signature ``(b64, b64) -> b64``."""
    return SemanticObject.create(DECLARATION_KIND, uleb(name[0]) + uleb(name[1]) + bytes((2, 0, 0, 1, 0)), [B64.cid])


def interface_summary(blocks: list[Block], parameters: tuple[SemanticObject, ...], returns: tuple[SemanticObject, ...]) -> SemanticObject:
    """Canonical existing CallContract facts needed by callers/verifier only."""
    return call_contract(
        parameters,
        returns,
        may_return=any(block.terminator.kind == TerminatorKind.RETURN for block in blocks),
        may_trap=any(block.terminator.kind == TerminatorKind.TRAP for block in blocks),
    )


def stable_declaration(name: tuple[int, int], summary: SemanticObject) -> SemanticObject:
    """Measurement-only stable logical callee identity bound to one immutable summary."""
    return SemanticObject.create(STABLE_DECLARATION_KIND, uleb(name[0]) + uleb(name[1]) + uleb(0), [summary.cid])


def body_unit(skel: SemanticObject) -> SemanticObject:
    """Measurement-only function body carrier; interface facts live only in the summary."""
    return SemanticObject.create(BODY_KIND, uleb(0), [skel.cid])


def block_unit(block: Block) -> SemanticObject:
    """One block as its own object: the canonical single-block graph encoding
    with a block-local reference table (branch targets stay graph-absolute)."""
    carrier = graph_fragment([block])
    return SemanticObject.create(BLOCK_KIND, carrier.body, carrier.references)


def skeleton(units: list[SemanticObject], entry: int) -> SemanticObject:
    refs = sorted({u.cid for u in units})
    return SemanticObject.create(SKELETON_KIND, uleb(len(units)) + uleb(entry) + b"".join(uleb(refs.index(u.cid)) for u in units), refs)


def build(spec: dict, mode: str = "function") -> tuple[SemanticObject, list[SemanticObject], dict]:
    """Build the program in canonical or measurement-only objectizations."""
    indirect = mode == "indirect"
    stable = mode == "stable_interface_block"
    objects: dict[bytes, SemanticObject] = {B64.cid: B64}
    functions: dict[tuple[int, int], SemanticObject] = {}
    declarations: dict[tuple[int, int], SemanticObject] = {}
    module_objects = []
    callee_names: dict[bytes, tuple[int, int]] = {}

    def add(obj: SemanticObject) -> SemanticObject:
        objects[obj.cid] = obj
        return obj

    def make(name: tuple[int, int], callee: SemanticObject | None, c: int, k: int) -> SemanticObject:
        a, b = ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)
        if callee is not None:
            if stable:
                entity = declarations[callee_names[callee.cid]]
            elif indirect:
                entity = add(declaration(callee_names[callee.cid]))
            else:
                entity = callee
            first = Node(Operation.CALL_DIRECT, (a, b), (B64,), entity=entity)
        else:
            first = Node(Operation.ADD_WRAP, (a, b), (B64,))
        k_node = Node(Operation.CONSTANT, (), (B64,), entity=add(constant(B64, k)))
        c_node = Node(Operation.CONSTANT, (), (B64,), entity=add(constant(B64, c)))
        if spec["blocks"] == 1:
            nodes = (
                first,
                k_node,
                Node(Operation.MUL_WRAP, (ValueRef.node_result(0, 0), ValueRef.node_result(0, 1)), (B64,)),
                c_node,
                Node(Operation.ADD_WRAP, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 3)), (B64,)),
            )
            blocks = [Block((B64, B64), nodes, Terminator.return_((ValueRef.node_result(0, 4),)))]
        else:
            blocks = [
                Block((B64, B64), (first,), Terminator.branch(1, (ValueRef.node_result(0, 0),))),
                Block((B64,), (k_node, Node(Operation.MUL_WRAP, (ValueRef.parameter(1, 0), ValueRef.node_result(1, 0)), (B64,))),
                      Terminator.branch(2, (ValueRef.node_result(1, 1),))),
                Block((B64,), (c_node, Node(Operation.ADD_WRAP, (ValueRef.parameter(2, 0), ValueRef.node_result(2, 0)), (B64,))),
                      Terminator.branch(3, (ValueRef.node_result(2, 1),))),
                Block((B64,), (), Terminator.return_((ValueRef.parameter(3, 0),))),
            ]
        if stable:
            skel = add(skeleton([add(block_unit(block)) for block in blocks], 0))
            summary = add(interface_summary(blocks, (B64, B64), (B64,)))
            declarations[name] = add(stable_declaration(name, summary))
            functions[name] = add(body_unit(skel))
        else:
            graph = add(skeleton([add(block_unit(block)) for block in blocks], 0)) if mode == "block" else add(graph_fragment(blocks))
            functions[name] = add(function(graph, (B64, B64), (B64,)))
        callee_names[functions[name].cid] = name
        return functions[name]

    for m in range(spec["modules"]):
        for f in range(spec["functions"]):
            c, k = spec["constants"][(m, f)]
            callee = callee_of(spec, m, f)
            make((m, f), None if callee is None else functions[callee], c, k)
        members = [functions[(m, f)] for f in range(spec["functions"])]
        for name, (c, k) in sorted(spec["extra"].items()):
            if name[0] == m:
                members.append(make(name, None, c, k))
        if indirect:
            pairs = [(add(declaration(callee_names[fn.cid])).cid, fn.cid) for fn in members]
            refs = sorted({cid for pair in pairs for cid in pair})
            body = uleb(len(pairs)) + b"".join(uleb(refs.index(d)) + uleb(refs.index(f)) for d, f in sorted(pairs))
            module_objects.append(add(SemanticObject.create(Kind.MODULE, body, refs)))
        elif stable:
            pairs = [(declarations[callee_names[fn.cid]].cid, fn.cid) for fn in members]
            refs = sorted({cid for pair in pairs for cid in pair})
            body = uleb(len(pairs)) + b"".join(uleb(refs.index(d)) + uleb(refs.index(f)) for d, f in sorted(pairs))
            module_objects.append(add(SemanticObject.create(Kind.MODULE, body, refs)))
        else:
            module_objects.append(add(object_with_refs(Kind.MODULE, members)))
    root = add(object_with_refs(Kind.PROGRAM_ROOT, module_objects))
    return root, list(objects.values()), functions


def reference_value(spec: dict, m: int, f: int, a: int, b: int) -> int:
    c, k = spec["constants"][(m, f)]
    callee = callee_of(spec, m, f)
    inner = (a + b) & MASK if callee is None else reference_value(spec, *callee, a, b)
    return (inner * k + c) & MASK


# ---------------------------------------------------------- module packing

def pack_modules(root: SemanticObject, objects: list[SemanticObject]) -> tuple[SemanticObject, list[SemanticObject], dict]:
    """Return (root unit, units, fine CID -> unit CID)."""
    by_cid = {obj.cid: obj for obj in objects}
    modules = [by_cid[cid] for cid in root.references]
    listed = {cid: index for index, module in enumerate(modules) for cid in module.references}
    claims: dict[bytes, set[int]] = {}
    for index, module in enumerate(modules):
        stack = list(module.references)
        seen: set[bytes] = set()
        while stack:
            cid = stack.pop()
            if cid in seen or listed.get(cid, index) != index:
                continue
            seen.add(cid)
            claims.setdefault(cid, set()).add(index)
            stack.extend(by_cid[cid].references)
    owner = {cid: (next(iter(who)) if len(who) == 1 else -1) for cid, who in claims.items()}
    groups: dict[int, list[bytes]] = {}
    for cid, group in owner.items():
        groups.setdefault(group, []).append(cid)

    unit_of: dict[bytes, bytes] = {}
    built: dict[int, SemanticObject] = {}

    def unit(group: int) -> SemanticObject:
        if group in built:
            return built[group]
        members = sorted(groups[group])
        deps = {owner[ref] for cid in members for ref in by_cid[cid].references if owner[ref] != group}
        refs = [unit(dep).cid for dep in sorted(deps)]
        body = b"".join(by_cid[cid].envelope() for cid in members)
        built[group] = SemanticObject.create(Kind.MODULE, body, refs)
        for cid in members:
            unit_of[cid] = built[group].cid
        return built[group]

    for group in sorted(groups):
        unit(group)
    root_unit = SemanticObject.create(Kind.PROGRAM_ROOT, b"".join(m.envelope() for m in (*modules, root)),
                                      [u.cid for u in built.values()])
    for obj in (*modules, root):
        unit_of[obj.cid] = root_unit.cid
    return root_unit, [*built.values(), root_unit], unit_of


def unpack(unit: SemanticObject) -> list[SemanticObject]:
    """Decode every canonical fine envelope in a unit; CID mismatch rejects."""
    data, pos, out = unit.body, 0, []
    while pos < len(data):
        start = pos
        length, shift = 0, 0
        while True:
            byte = data[pos]
            pos += 1
            length |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                break
        pos += length
        out.append(decode_object(data[start:pos], "oi02-unit"))
    if pos != len(data):
        raise ValueError("truncated unit")
    return out


# ------------------------------------------------------------ measurements

def binding_resolver(fine: dict[bytes, SemanticObject], bindings: dict[bytes, bytes]):
    """Resolve a declaration to its bound definition's content under the
    declaration's CID, so the unchanged verifier/executor see the call edge."""
    def resolve(cid: bytes) -> SemanticObject:
        if cid not in bindings:
            return fine[cid]
        bound = fine[bindings[cid]]
        return SemanticObject(bound.kind, bound.schema_version, bound.references, bound.body, cid)
    return resolve


def parse_block_unit(unit: SemanticObject, entity) -> Block:
    """Inverse of ``graph_fragment`` for one block; ``entity`` maps a CID to
    the object the canonical graph references."""
    cursor = Cursor(unit.body, "oi02-block")
    if (cursor.uleb(), cursor.uleb()) != (1, 0):
        raise ValueError("block unit must hold exactly one block")
    ref = lambda: entity(unit.references[cursor.uleb()])
    parameters = tuple(ref() for _ in range(cursor.uleb()))
    nodes = []
    for _ in range(cursor.uleb()):
        operation = Operation(cursor.uleb())
        member = cursor.uleb() if operation == Operation.CALL_GROUP_MEMBER else None
        target = ref() if operation in ENTITY_OPERATIONS else None
        operands = tuple(_read_value(cursor) for _ in range(cursor.uleb()))
        results = tuple(ref() for _ in range(cursor.uleb()))
        attributes = tuple(cursor.uleb() for _ in range(cursor.uleb())) if operation in ATTRIBUTE_OPERATIONS else ()
        nodes.append(Node(operation, operands, results, member, target, attributes))
    kind = TerminatorKind(cursor.uleb())
    if kind == TerminatorKind.BRANCH:
        term = Terminator(kind, edges=(_read_edge(cursor),))
    elif kind == TerminatorKind.CONDITIONAL_BRANCH:
        term = Terminator(kind, values=(_read_value(cursor),), edges=(_read_edge(cursor), _read_edge(cursor)))
    elif kind == TerminatorKind.RETURN:
        term = Terminator(kind, values=tuple(_read_value(cursor) for _ in range(cursor.uleb())))
    else:
        term = Terminator(kind, payload=cursor.byte_string())
    cursor.end("OI02-BLOCK")
    return Block(parameters, tuple(nodes), term)


def blocks_from_skeleton(fine: dict[bytes, SemanticObject], skel: SemanticObject, entity) -> tuple[list[Block], int]:
    cursor = Cursor(skel.body, "oi02-skeleton")
    count, entry = cursor.uleb(), cursor.uleb()
    units = [fine[skel.references[cursor.uleb()]] for _ in range(count)]
    cursor.end("OI02-SKELETON")
    if not units or entry >= count or any(unit.kind != BLOCK_KIND for unit in units):
        raise ValueError("invalid block skeleton")
    return [parse_block_unit(unit, entity) for unit in units], entry


def graph_from_skeleton(fine: dict[bytes, SemanticObject], skel: SemanticObject, entity) -> SemanticObject:
    blocks, entry = blocks_from_skeleton(fine, skel, entity)
    return graph_fragment(blocks, entry)


def split_function(fine: dict[bytes, SemanticObject], fn: SemanticObject):
    cursor = Cursor(fn.body, "oi02-function")
    skel = fine[fn.references[cursor.uleb()]]
    params = [fine[fn.references[cursor.uleb()]] for _ in range(cursor.uleb())]
    returns = [fine[fn.references[cursor.uleb()]] for _ in range(cursor.uleb())]
    return skel, params, returns


def reassemble(fine: dict[bytes, SemanticObject], fn_cid: bytes, memo: dict[bytes, SemanticObject]) -> SemanticObject:
    """Rebuild the canonical function (and callees) from block-level objects."""
    if fn_cid not in memo:
        def entity(cid: bytes) -> SemanticObject:
            obj = fine[cid]
            return reassemble(fine, cid, memo) if obj.kind == Kind.FUNCTION else obj
        skel, params, returns = split_function(fine, fine[fn_cid])
        memo[fn_cid] = function(graph_from_skeleton(fine, skel, entity), params, returns)
    return memo[fn_cid]



def stable_declaration_summary(fine: dict[bytes, SemanticObject], decl: SemanticObject) -> SemanticObject:
    if decl.kind != STABLE_DECLARATION_KIND:
        raise ValueError("stable declaration kind mismatch")
    cursor = Cursor(decl.body, "oi02-stable-declaration")
    name = (cursor.uleb(), cursor.uleb())
    summary = fine[decl.references[cursor.uleb()]]
    cursor.end("OI02-STABLE-DECLARATION")
    if summary.kind != Kind.CALL_CONTRACT:
        raise ValueError("stable declaration must reference a CallContract")
    if stable_declaration(name, summary).cid != decl.cid:
        raise ValueError("stable declaration round-trip CID mismatch")
    return summary


def split_body(fine: dict[bytes, SemanticObject], body: SemanticObject) -> SemanticObject:
    if body.kind != BODY_KIND:
        raise ValueError("function body carrier kind mismatch")
    cursor = Cursor(body.body, "oi02-body")
    skel = fine[body.references[cursor.uleb()]]
    cursor.end("OI02-BODY")
    if skel.kind != SKELETON_KIND:
        raise ValueError("function body must reference a skeleton")
    return skel


def reassemble_stable(
    fine: dict[bytes, SemanticObject],
    body_cid: bytes,
    bindings: dict[bytes, bytes],
    decl_of_body: dict[bytes, bytes],
    memo: dict[bytes, SemanticObject],
) -> SemanticObject:
    """Reassemble one stable-summary/body pair into the exact canonical function."""
    if body_cid in memo:
        return memo[body_cid]
    body = fine[body_cid]
    decl = fine[decl_of_body[body_cid]]
    summary = stable_declaration_summary(fine, decl)
    decoded = _decode_call_contract(summary, fine.__getitem__)
    parameters = tuple(fine[cid] for cid in decoded.inputs)
    returns = tuple(fine[cid] for cid in decoded.outputs)

    def entity(cid: bytes) -> SemanticObject:
        obj = fine[cid]
        if obj.kind == STABLE_DECLARATION_KIND:
            if cid not in bindings:
                raise ValueError("unbound stable declaration")
            return reassemble_stable(fine, bindings[cid], bindings, decl_of_body, memo)
        return obj

    skel = split_body(fine, body)
    blocks, entry = blocks_from_skeleton(fine, skel, entity)
    expected_summary = interface_summary(blocks, parameters, returns)
    if expected_summary.cid != summary.cid:
        raise ValueError("stale interface summary")
    memo[body_cid] = function(graph_fragment(blocks, entry), parameters, returns)
    return memo[body_cid]

def representation(spec: dict) -> tuple[dict, dict, dict]:
    """Build all measured objectizations: (representations, canonical fns, indirect fns)."""
    root, objects, fns = build(spec)
    fine = {o.cid: o for o in objects}
    root_unit, units, unit_of = pack_modules(root, objects)
    i_root, i_objects, i_fns = build(spec, "indirect")
    i_fine = {o.cid: o for o in i_objects}
    bindings = {declaration(name).cid: fn.cid for name, fn in i_fns.items()}
    callers: dict[bytes, set[bytes]] = {}
    for fn in i_fns.values():
        for ref in i_fine[graph_of(i_fine, fn.cid)].references:
            if i_fine[ref].kind == DECLARATION_KIND:
                callers.setdefault(ref, set()).add(fn.cid)
    first, i_first = fns[(0, 0)].cid, i_fns[(0, 0)].cid
    identity = lambda objs: {c: [c] for c in objs}
    module_members: dict[bytes, list[bytes]] = {}
    for cid, unit in sorted(unit_of.items()):
        module_members.setdefault(unit, []).append(cid)

    # Block grain: rebuild canonical functions from the block-level bytes alone
    # and require identical CIDs (boundaries must not alter meaning).
    b_root, b_objects, b_fns = build(spec, "block")
    b_fine = {o.cid: o for o in b_objects}
    memo: dict[bytes, SemanticObject] = {}
    for name, fn in b_fns.items():
        if reassemble(b_fine, fn.cid, memo).cid != fns[name].cid:
            raise AssertionError(f"block reassembly differs for {name}")
    graph_of_skel = {split_function(b_fine, b_fine[c])[0].cid: graph_of(fine, canon.cid) for c, canon in memo.items()}
    b_members = {c: [c] for c in b_fine}
    for c, canon in memo.items():
        b_members[c] = [canon.cid]
    for skel_cid, graph_cid in graph_of_skel.items():
        b_members[skel_cid] = [graph_cid]
    unit_graphs: dict[bytes, set[bytes]] = {}
    for skel_cid, graph_cid in graph_of_skel.items():
        for unit_cid in b_fine[skel_cid].references:
            unit_graphs.setdefault(unit_cid, set()).add(graph_cid)
    b_members.update({unit_cid: sorted(graphs) for unit_cid, graphs in unit_graphs.items()})
    b_skel = split_function(b_fine, b_fns[(0, 0)])[0]

    # Stable interface + block body: declarations carry only a stable local key
    # and one separately objectized canonical CallContract.  Bodies carry only a
    # block skeleton.  Reassembly must recover the exact canonical function CID.
    s_root, s_objects, s_bodies = build(spec, "stable_interface_block")
    s_fine = {o.cid: o for o in s_objects}
    s_decls: dict[tuple[int, int], SemanticObject] = {}
    for obj in s_fine.values():
        if obj.kind != STABLE_DECLARATION_KIND:
            continue
        cursor = Cursor(obj.body, "oi02-stable-name")
        name = (cursor.uleb(), cursor.uleb())
        cursor.uleb()
        cursor.end("OI02-STABLE-NAME")
        s_decls[name] = obj
    s_bindings = {s_decls[name].cid: body.cid for name, body in s_bodies.items()}
    s_decl_of_body = {body: decl for decl, body in s_bindings.items()}
    s_memo: dict[bytes, SemanticObject] = {}
    for name, body in s_bodies.items():
        if reassemble_stable(s_fine, body.cid, s_bindings, s_decl_of_body, s_memo).cid != fns[name].cid:
            raise AssertionError(f"stable-interface reassembly differs for {name}")
    s_graph_of_skel = {split_body(s_fine, s_fine[c]).cid: graph_of(fine, canon.cid) for c, canon in s_memo.items()}
    s_members = {c: [c] for c in s_fine}
    for body_cid, canon in s_memo.items():
        s_members[body_cid] = [canon.cid]
    for skel_cid, graph_cid in s_graph_of_skel.items():
        s_members[skel_cid] = [graph_cid]
    s_unit_graphs: dict[bytes, set[bytes]] = {}
    for skel_cid, graph_cid in s_graph_of_skel.items():
        for unit_cid in s_fine[skel_cid].references:
            s_unit_graphs.setdefault(unit_cid, set()).add(graph_cid)
    s_members.update({unit_cid: sorted(graphs) for unit_cid, graphs in s_unit_graphs.items()})
    s_entity_map = {decl: s_memo[body] for decl, body in s_bindings.items()}
    s_body = s_bodies[(0, 0)]
    s_decl = s_decls[(0, 0)]
    s_summary = stable_declaration_summary(s_fine, s_decl)
    s_skel = split_body(s_fine, s_body)

    return {
        "function": {"root": root, "objects": fine, "members": identity(fine), "fine": fine,
                     "resolve": fine.__getitem__, "query_units": [first, graph_of(fine, first)]},
        "module": {"root": root_unit, "objects": {u.cid: u for u in units}, "members": module_members, "fine": fine,
                   "resolve": fine.__getitem__, "query_units": [unit_of[first]], "packed": True},
        "call_indirect": {"root": i_root, "objects": i_fine, "members": identity(i_fine), "fine": i_fine,
                          "resolve": binding_resolver(i_fine, bindings), "bindings": bindings,
                          "callers": callers, "decl_of": {v: k for k, v in bindings.items()},
                          "query_units": [i_first, graph_of(i_fine, i_first)]},
        "block": {"root": b_root, "objects": b_fine, "members": b_members, "fine": {**b_fine, **fine},
                  "resolve": {**b_fine, **fine}.__getitem__, "canonical": fine.__getitem__,
                  "skeleton_of_graph": {g: s for s, g in graph_of_skel.items()},
                  "function_map": {c: canon for c, canon in memo.items()},
                  "entity_map": {c: canon for c, canon in memo.items()},
                  "functions": {name: fn.cid for name, fn in b_fns.items()},
                  "query_units": [b_fns[(0, 0)].cid, b_skel.cid, *b_skel.references]},
        "stable_interface_block": {
            "root": s_root, "objects": s_fine, "members": s_members, "fine": {**s_fine, **fine},
            "resolve": {**s_fine, **fine}.__getitem__, "canonical": fine.__getitem__,
            "skeleton_of_graph": {g: s for s, g in s_graph_of_skel.items()},
            "function_map": {c: canon for c, canon in s_memo.items()}, "entity_map": s_entity_map,
            "stable_bindings": s_bindings, "decl_of_body": s_decl_of_body,
            "functions": {name: body.cid for name, body in s_bodies.items()},
            "declarations": {name: decl.cid for name, decl in s_decls.items()},
            "query_units": [s_decl.cid, s_summary.cid, s_body.cid, s_skel.cid, *s_skel.references],
        },
    }, fns, i_fns


def verify_one(rep: dict, cid: bytes) -> None:
    """Verify one measured unit, reassembling canonical semantics where needed."""
    obj = rep["fine"][cid]
    if "bindings" in rep and obj.kind == Kind.MODULE:
        cursor = Cursor(obj.body, "oi02-binding")
        for _ in range(cursor.uleb()):
            decl, definition = rep["fine"][obj.references[cursor.uleb()]], rep["fine"][obj.references[cursor.uleb()]]
            signature = Cursor(decl.body, "oi02-declaration")
            signature.uleb(), signature.uleb()
            params = tuple(decl.references[signature.uleb()] for _ in range(signature.uleb()))
            returns = tuple(decl.references[signature.uleb()] for _ in range(signature.uleb()))
            signature.end("OI02-DECLARATION")
            if decl.kind != DECLARATION_KIND or rep["bindings"][decl.cid] != definition.cid:
                raise ValueError("binding does not match declaration")
            if _decode_function_interface(definition, rep["resolve"])[1:] != (params, returns):
                raise ValueError("binding signature mismatch")
        cursor.end("OI02-BINDING")
    elif "stable_bindings" in rep and obj.kind == Kind.MODULE:
        cursor = Cursor(obj.body, "oi02-stable-binding")
        for _ in range(cursor.uleb()):
            decl = rep["fine"][obj.references[cursor.uleb()]]
            body = rep["fine"][obj.references[cursor.uleb()]]
            if decl.kind != STABLE_DECLARATION_KIND or body.kind != BODY_KIND:
                raise ValueError("stable binding kind mismatch")
            if rep["stable_bindings"].get(decl.cid) != body.cid or rep["decl_of_body"].get(body.cid) != decl.cid:
                raise ValueError("stable binding does not match declaration")
            stable_declaration_summary(rep["fine"], decl)
            if body.cid not in rep["function_map"]:
                raise ValueError("stable binding body has no checked canonical reassembly")
        cursor.end("OI02-STABLE-BINDING")
    elif "skeleton_of_graph" in rep and cid in rep["skeleton_of_graph"]:
        # Whole-graph checks (dominance, flow) need the graph reassembled first.
        fine = rep["fine"]
        graph = graph_from_skeleton(
            fine,
            fine[rep["skeleton_of_graph"][cid]],
            lambda c: rep["entity_map"].get(c, fine[c]),
        )
        if graph.cid != cid:
            raise ValueError("block reassembly CID mismatch")
        verify_object(graph, rep["canonical"])
    elif "skeleton_of_graph" in rep and obj.kind == BLOCK_KIND:
        block = parse_block_unit(obj, rep["resolve"])
        if block_unit(block).cid != cid:
            raise ValueError("block unit round-trip CID mismatch")
    elif "skeleton_of_graph" in rep and obj.kind == SKELETON_KIND:
        cursor = Cursor(obj.body, "oi02-skeleton-check")
        count, entry = cursor.uleb(), cursor.uleb()
        units = [rep["fine"][obj.references[cursor.uleb()]] for _ in range(count)]
        cursor.end("OI02-SKELETON-CHECK")
        if not units or entry >= count or any(unit.kind != BLOCK_KIND for unit in units):
            raise ValueError("invalid block skeleton")
        if skeleton(units, entry).cid != cid:
            raise ValueError("block skeleton round-trip CID mismatch")
    elif "stable_bindings" in rep and obj.kind == BODY_KIND:
        skel = split_body(rep["fine"], obj)
        if body_unit(skel).cid != cid:
            raise ValueError("body carrier round-trip CID mismatch")
        canonical = rep["function_map"].get(cid)
        if canonical is None:
            raise ValueError("stable body has no checked canonical reassembly")
        verify_object(canonical, rep["canonical"])
    elif "stable_bindings" in rep and obj.kind == STABLE_DECLARATION_KIND:
        stable_declaration_summary(rep["fine"], obj)
    elif "skeleton_of_graph" in rep and obj.kind == Kind.FUNCTION and cid in rep["function_map"]:
        split_function(rep["fine"], obj)
        if SemanticObject.create(obj.kind, obj.body, obj.references).cid != cid:
            raise ValueError("block function CID mismatch")
    elif "skeleton_of_graph" in rep and obj.kind == Kind.FUNCTION:
        verify_object(obj, rep["canonical"])
    elif obj.kind == DECLARATION_KIND:
        if obj.cid != SemanticObject.create(obj.kind, obj.body, obj.references).cid:
            raise ValueError("declaration CID mismatch")
    else:
        verify_object(obj, rep["resolve"])


def store_stats(rep: dict) -> dict:
    store = write_store(rep["root"].cid, rep["objects"].values())
    payload = sum(len(o.envelope()) for o in rep["objects"].values())
    return {"objects": len(rep["objects"]), "store_bytes": len(store), "record_bytes": payload,
            "index_and_container_bytes": len(store) - payload}


def diff(base: dict, cand: dict) -> dict:
    new = set(cand["objects"]) - set(base["objects"])
    gone = set(base["objects"]) - set(cand["objects"])
    kept = set(base["objects"]) & set(cand["objects"])
    frontier = {m for c in new for m in cand["members"][c]}
    interface_only = len(frontier)
    rebound = {d for d, f in cand.get("bindings", {}).items() if base["bindings"].get(d) != f}
    # Conservative: callers' derived call facts read callee bodies, so every
    # transitive caller of a rebound declaration is re-verified.
    pending, seen = list(rebound), set(rebound)
    while pending:
        for caller in cand["callers"].get(pending.pop(), ()):
            frontier.update((caller, graph_of(cand["fine"], caller)))
            if cand["decl_of"][caller] not in seen:
                seen.add(cand["decl_of"][caller])
                pending.append(cand["decl_of"][caller])
    proof_universe = {m for members in cand["members"].values() for m in members}
    return {
        "rewritten_objects": len(new),
        "rewritten_bytes": sum(len(cand["objects"][c].envelope()) for c in new),
        "cid_churn": len(gone),
        "reused_objects": len(kept),
        "reused_bytes": sum(len(base["objects"][c].envelope()) for c in kept),
        "base_bytes": sum(len(o.envelope()) for o in base["objects"].values()),
        "verification_frontier_fine_objects": len(frontier),
        "proof_reused_fine_objects": len(proof_universe - set(frontier)),
        "rebound_declarations": len(rebound),
        "verification_frontier_if_interface_only": interface_only,
    }, new, gone, sorted(frontier)


def graph_of(fine: dict[bytes, SemanticObject], function_cid: bytes) -> bytes:
    return next(cid for cid in fine[function_cid].references if fine[cid].kind == Kind.GRAPH_FRAGMENT)


def query_bytes(rep: dict) -> int:
    """Envelope bytes that must be fetched to read function (0, 0) and its body."""
    return sum(len(rep["objects"][u].envelope()) for u in set(rep["query_units"]))


def time_ns(action) -> list[int]:
    samples = []
    for _ in range(TIMING_SAMPLES):
        started = perf_counter_ns()
        action()
        samples.append(perf_counter_ns() - started)
    return samples


def summary(samples: list[int]) -> dict:
    ordered = sorted(samples)
    median = statistics.median(ordered)
    return {"samples_ns": samples, "count": len(samples), "median_ns": median,
            "p95_ns": ordered[int(0.95 * (len(ordered) - 1))],
            "mad_ns": statistics.median(abs(s - median) for s in ordered)}


def fetch(reader: StoreReader, cid: bytes) -> SemanticObject:
    """Indexed record fetch with the same envelope parse and CID check as
    ``StoreReader.get``, but no kind gate (measurement kinds) and no copy of
    the store tail, so every candidate is timed on the same path."""
    offset, length = reader._index[cid]
    cursor = Cursor(memoryview(reader.data)[offset:], "oi02-fetch")
    cursor.uleb()
    stored = bytes(cursor.take(CID_SIZE))
    kind, version = cursor.uleb(), cursor.uleb()
    refs = tuple(bytes(cursor.take(CID_SIZE)) for _ in range(cursor.uleb()))
    body = bytes(cursor.take(cursor.uleb()))
    if semantic_cid(kind, version, refs, body) != stored:
        raise ValueError("record CID mismatch")
    return SemanticObject(kind, version, refs, body, stored)


def query_timer(rep: dict):
    reader = StoreReader(write_store(rep["root"].cid, rep["objects"].values()))
    units = rep["query_units"]
    if rep.get("packed"):
        def action():
            unpack(fetch(reader, units[0]))
    else:
        def action():
            for unit in units:
                fetch(reader, unit)
    return action


def encode_timer(rep: dict):
    objects = tuple(rep["objects"].values())
    return lambda: write_store(rep["root"].cid, objects)


def decode_timer(rep: dict):
    data = write_store(rep["root"].cid, rep["objects"].values())
    cids = tuple(sorted(rep["objects"]))

    def action():
        reader = StoreReader(data)
        for cid in cids:
            fetch(reader, cid)

    return action


def verify_timer(rep: dict, frontier: list[bytes]):
    def action():
        for cid in frontier:
            verify_one(rep, cid)
    return action


def check_semantics(spec: dict, reps: dict, fns: dict, i_fns: dict) -> None:
    """All granularities are lossless re-framings with identical results."""
    entry = (spec["modules"] - 1, spec["functions"] - 1)
    expected = (reference_value(spec, *entry, 5, 9),)
    fine = reps["function"]["objects"]
    recovered = {o.cid: o for u in reps["module"]["objects"].values() for o in unpack(u)}
    assert recovered == fine, "module packing is not a lossless re-framing"
    # execute() verifies the whole store before running it.
    assert execute(StoreReader(write_store(reps["function"]["root"].cid, recovered.values())), fns[entry].cid, (5, 9)) == expected
    indirect = reps["call_indirect"]
    for cid in indirect["objects"]:
        verify_one(indirect, cid)
    assert _execute_function(i_fns[entry], (5, 9), indirect["resolve"], [100_000]) == expected

    block = reps["block"]
    for cid in block["objects"]:
        verify_one(block, cid)
    block_entry = block["functions"][entry]
    canonical_entry = block["function_map"][block_entry]
    verify_object(canonical_entry, block["canonical"])
    assert _execute_function(canonical_entry, (5, 9), block["canonical"], [100_000]) == expected

    stable = reps["stable_interface_block"]
    for cid in stable["objects"]:
        verify_one(stable, cid)
    stable_entry = stable["functions"][entry]
    canonical_stable_entry = stable["function_map"][stable_entry]
    verify_object(canonical_stable_entry, stable["canonical"])
    assert _execute_function(canonical_stable_entry, (5, 9), stable["canonical"], [100_000]) == expected


def run_case(name: str, spec: dict, mutations: list[tuple[str, dict]], merges: list[tuple[str, str, str]], collect_timing: bool = True) -> dict:
    base, fns, i_fns = representation(spec)
    check_semantics(spec, base, fns, i_fns)
    case = {
        "shape": {"modules": spec["modules"], "functions_per_module": spec["functions"], "blocks_per_function": spec["blocks"]},
        "store": {g: store_stats(base[g]) for g in base},
        "query_read_function_0_0": {g: {"bytes": query_bytes(base[g])} for g in base},
        "mutations": {},
        "merges": {},
    }
    timing = {
        "query_read_function_0_0": ({g: summary(time_ns(query_timer(base[g]))) for g in base} if collect_timing else {}),
        "store_encode": ({g: summary(time_ns(encode_timer(base[g]))) for g in base} if collect_timing else {}),
        "store_decode": ({g: summary(time_ns(decode_timer(base[g]))) for g in base} if collect_timing else {}),
        "verification": {},
    }

    candidates = {}
    for label, change in mutations:
        cand_spec = {**spec, "constants": {**spec["constants"], **change.get("constants", {})},
                     "extra": {**spec["extra"], **change.get("extra", {})}}
        cand, cand_fns, cand_i_fns = representation(cand_spec)
        check_semantics(cand_spec, cand, cand_fns, cand_i_fns)
        record, timing_record = {}, {}
        for g in base:
            stats, new, gone, frontier = diff(base[g], cand[g])
            record[g] = stats
            if collect_timing:
                timing_record[g] = summary(time_ns(verify_timer(cand[g], frontier)))
            candidates.setdefault(label, {})[g] = (new, gone, cand[g])
        case["mutations"][label] = record
        timing["verification"][label] = timing_record

    for label, left, right in merges:
        case["merges"][label] = {}
        for g in base:
            l_new, l_gone, _ = candidates[left][g]
            r_new, r_gone, _ = candidates[right][g]
            both = l_gone & r_gone
            content = {c for c in both if base[g]["objects"][c].kind not in (Kind.PROGRAM_ROOT,)}
            case["merges"][label][g] = {
                "objects_rewritten_by_both": len(both),
                "conflicting_non_root_objects": len(content),
                "conflicting_non_root_bytes": sum(len(base[g]["objects"][c].envelope()) for c in content),
            }
    return case, timing


def cases() -> list[tuple[str, dict, list, list]]:
    out = []
    for topology, modules, functions, blocks in (("chain", 4, 8, 1), ("chain", 8, 16, 1), ("star", 8, 16, 1),
                                                 ("chain", 8, 16, 4), ("star", 8, 16, 4)):
        spec = project_spec(modules, functions, topology, blocks)
        last_m, last_f = modules - 1, functions - 1
        mutations = [
            ("leaf_constant_first_module", {"constants": {(0, 0): (1000, 2)}}),
            ("sibling_constant_first_module", {"constants": {(0, last_f): (2000, 3)}}),
            ("entry_constant_last_module", {"constants": {(last_m, last_f): (3000, 4)}}),
            ("add_function_middle_module", {"extra": {(modules // 2, functions): (77, 5)}}),
        ]
        merges = [
            ("same_module_leaf_vs_sibling", "leaf_constant_first_module", "sibling_constant_first_module"),
            ("different_modules_entry_vs_add", "entry_constant_last_module", "add_function_middle_module"),
        ]
        suffix = "" if blocks == 1 else f"-b{blocks}"
        out.append((f"{topology}-{modules}x{functions}{suffix}", spec, mutations, merges))

    spec = service_spec()
    modules, functions = spec["modules"], spec["functions"]
    mutations = [
        ("leaf_constant_first_module", {"constants": {(0, 0): (1000, 2)}}),
        ("sibling_constant_first_module", {"constants": {(0, functions - 1): (2000, 3)}}),
        ("entry_constant_last_module", {"constants": {(modules - 1, functions - 1): (3000, 4)}}),
        ("add_function_middle_module", {"extra": {(modules // 2, functions): (77, 5)}}),
    ]
    merges = [
        ("same_module_leaf_vs_sibling", "leaf_constant_first_module", "sibling_constant_first_module"),
        ("different_modules_entry_vs_add", "entry_constant_last_module", "add_function_middle_module"),
    ]
    out.append((f"service-{modules}x{functions}-b4", spec, mutations, merges))
    return out


def run(collect_timing: bool = True) -> tuple[dict, dict]:
    evidence, timing = {}, {}
    for name, spec, mutations, merges in cases():
        evidence[name], timing[name] = run_case(name, spec, mutations, merges, collect_timing)
    result = {
        "case": "oi02-objectization-granularity",
        "classification": "tooling-only deterministic accounting over synthetic chain/star stress fixtures plus a generated multi-module service-like DAG; candidates never become canonical store v1",
        "granularities": {
            "function": "current canonical store: type/constant/graph_fragment/function/module/root objects",
            "module": "measurement-only packing: one unit per module of exclusively owned fine envelopes, shared objects in one common unit",
            "call_indirect": "measurement-only: callers reference a nominal declaration (symbol + signature) and each module binds declarations to definitions; verification frontier conservatively includes transitive callers of rebound declarations",
            "block": "measurement-only: each graph fragment becomes a skeleton over per-block units (canonical single-block encoding, block-local reference table); verification reassembles and checks whole graphs",
            "stable_interface_block": "measurement-only: stable callee declaration -> canonical immutable CallContract summary, module binding -> separately objectized block-skeleton body; reassembly must match canonical graph/function CIDs and stale summary/body pairs reject",
        },
        "ai_context": "query/rewrite bytes are binary envelope bytes an agent or cache must receive",
        "model_visible_context_tokens": {"status": "unavailable: no tokenizer/model trial is available in this environment; byte counts are not substituted for model tokens"},
        "cases": evidence,
    }
    return result, timing


if __name__ == "__main__":
    result, timing = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    OUTPUT.with_name("oi02_granularity_timing.json").write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    for name, record in timing.items():
        for g, sample in record["query_read_function_0_0"].items():
            print(name, "query", g, "median_ns", sample["median_ns"])
        for metric in ("store_encode", "store_decode"):
            print(name, metric, {g: sample["median_ns"] for g, sample in record[metric].items()})
        for label, per in record["verification"].items():
            print(name, "verify", label, {g: s["median_ns"] for g, s in per.items()})
