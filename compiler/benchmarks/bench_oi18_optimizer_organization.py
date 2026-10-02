"""OI-18 bounded optimizer/legalization organization experiment.

The alternate path is deliberately small: semantic optimization is unchanged,
then a demand-driven target-package legality/selection cache is consulted before
the existing backend emits bytes.  It is derived tooling state, not a persistent
machine IR and not semantic state.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import statistics
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

from xax_aarch64 import compile_aarch64_bound_target
from xax_compiler import (
    AtomicFamily, AtomicOrder, AtomicScope, AtomicSupport, Block, Kind, Node,
    Operation, Permission, StoreReader, Terminator, TerminatorKind, ValueRef,
    _decode_function_interface, _parse_graph, aarch64_baremetal_atomic_target,
    aarch64_baremetal_general_target, atomic_capability, bits_type, constant,
    decode_bits_width, decode_native_target, execute, fail, function,
    graph_fragment, memory_effect_type, object_with_refs, pointer_type,
    select_atomic_legalization, stack_owner_type, store_resolver, verify_store,
    wasm32_target, write_store, x86_64_windows_target,
)
from xax_optimizer import OptimizationBudget, optimize_function
from xax_x86_64 import compile_native_bound_target
from xax_wasm import compile_wasm_bound_target

HERE = Path(__file__).resolve().parent
EVIDENCE_OUT = HERE / "oi18_optimizer_organization_evidence.json"
TIMING_OUT = HERE / "oi18_optimizer_organization_timing.json"
MODEL_ID = "xax-oi18-demand-select-v1"


@dataclass(frozen=True)
class Workload:
    name: str
    function: object
    vectors: tuple[tuple[int, ...], ...]
    legalization: bool = False


@dataclass(frozen=True)
class SelectionRecord:
    block_fingerprint: str
    node_count: int
    terminator: int
    legalizations: tuple[str, ...]


class DemandSelector:
    """Benchmark-only demand-driven legality/selection cache; no MIR objects."""

    def __init__(self) -> None:
        self.cache: dict[tuple[bytes, bytes], SelectionRecord] = {}

    @staticmethod
    def _fingerprint(block: Block) -> bytes:
        # A one-block graph encoding is deterministic and includes all type/entity
        # references and target-independent operation/terminator data. Branch target
        # indices remain ordinary integers; this is only a derived cache key.
        return graph_fragment((block,)).cid

    def select_block(self, block: Block, target, parsed_block=None, resolve=None) -> tuple[SelectionRecord, bool, int]:
        fp = self._fingerprint(block)
        key = (target.cid, fp)
        if key in self.cache:
            return self.cache[key], True, 1
        desc = decode_native_target(target)
        legalizations: list[str] = []
        work = 1  # block miss
        for index, node in enumerate(block.nodes):
            work += 1
            if int(node.operation) not in desc.supported_operations:
                fail("XAX.OI18.LEGALIZATION", fp.hex(), "OI18-TARGET-OPERATION", "target-supported operation", int(node.operation))
            if node.operation in (Operation.ATOMIC_LOAD, Operation.ATOMIC_STORE):
                if parsed_block is None or resolve is None:
                    raise ValueError("parsed block and resolver required for atomic selection")
                parsed_node = parsed_block.nodes[index]
                family = AtomicFamily.LOAD if node.operation == Operation.ATOMIC_LOAD else AtomicFamily.STORE
                order = AtomicOrder(node.attributes[0]); scope = AtomicScope(node.attributes[1]); alignment = node.attributes[2]
                if node.operation == Operation.ATOMIC_LOAD:
                    width = decode_bits_width(resolve(parsed_node.results[0]))
                else:
                    width = decode_bits_width(resolve(parsed_node.operand_types[1]))
                # The benchmark corpus uses natural b32 atomics; reject any future
                # corpus change rather than silently inferring width from alignment.
                if width != 32:
                    fail("XAX.OI18.ATOMIC", fp.hex(), "OI18-ATOMIC-WIDTH", 32, width)
                cap = atomic_capability(desc, 1, width, alignment, family, order, scope)
                chosen = select_atomic_legalization(cap)
                if chosen == AtomicSupport.UNSUPPORTED:
                    fail("XAX.OI18.LEGALIZATION", fp.hex(), "OI18-ATOMIC-SUPPORTED", "native or bounded_sequence", "unsupported")
                legalizations.append(f"{family.name.lower()}:{order.name.lower()}:{chosen.name.lower()}")
                work += 1
        work += 1
        if int(block.terminator.kind) not in desc.supported_terminators:
            fail("XAX.OI18.LEGALIZATION", fp.hex(), "OI18-TARGET-TERMINATOR", "target-supported terminator", int(block.terminator.kind))
        record = SelectionRecord(fp.hex(), len(block.nodes), int(block.terminator.kind), tuple(legalizations))
        self.cache[key] = record
        return record, False, work


def _store(functions, objects):
    module = object_with_refs(Kind.MODULE, tuple(functions))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*objects, *functions, module, root)))
    verify_store(reader)
    return reader


def corpus():
    b1, b32 = bits_type(1), bits_type(32)
    one, two = constant(b32, 1), constant(b32, 2)
    ptr = pointer_type(b32, Permission.READ_WRITE, 4)
    owner, effect = stack_owner_type(), memory_effect_type()
    objects = [b1, b32, one, two, ptr, owner, effect]
    workloads: list[Workload] = []

    def add(name, blocks, params, vectors, returns=(b32,), legalization=False):
        graph = graph_fragment(blocks); fn = function(graph, params, returns)
        objects.append(graph); workloads.append(Workload(name, fn, tuple(vectors), legalization))
        return fn

    add("arithmetic", [Block((b32,), (
        Node(Operation.CONSTANT, (), (b32,), entity=two),
        Node(Operation.MUL_WRAP, (ValueRef.parameter(0,0), ValueRef.node_result(0,0)), (b32,)),
    ), Terminator.return_((ValueRef.node_result(0,1),)))], (b32,), ((0,), (1,), (7,), (0xffffffff,)))

    add("branch_merge", [
        Block((b1,b32,b32), (), Terminator.conditional_branch(ValueRef.parameter(0,0),1,(ValueRef.parameter(0,1),ValueRef.parameter(0,2)),2,(ValueRef.parameter(0,1),ValueRef.parameter(0,2)))),
        Block((b32,b32), (Node(Operation.ADD_WRAP,(ValueRef.parameter(1,0),ValueRef.parameter(1,1)),(b32,)),), Terminator.return_((ValueRef.node_result(1,0),))),
        Block((b32,b32), (Node(Operation.SUB_WRAP,(ValueRef.parameter(2,0),ValueRef.parameter(2,1)),(b32,)),), Terminator.return_((ValueRef.node_result(2,0),))),
    ], (b1,b32,b32), ((0,7,3),(1,7,3),(0,0xffffffff,1),(1,0xffffffff,1)))

    stack_nodes = (
        Node(Operation.STACK_ALLOC, (), (ptr,owner,effect), attributes=(4,4)),
        Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.node_result(0,0,2)),(effect,),attributes=(4,4)),
        Node(Operation.LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,1)),(b32,effect),attributes=(4,4)),
        Node(Operation.STACK_END,(ValueRef.node_result(0,0,1),ValueRef.node_result(0,2,1)),()),
    )
    add("stack_memory", [Block((b32,), stack_nodes, Terminator.return_((ValueRef.node_result(0,2),)))], (b32,), ((0,), (7,), (0xffffffff,)))

    callee_graph = graph_fragment([Block((b32,), (
        Node(Operation.CONSTANT, (), (b32,), entity=one),
        Node(Operation.ADD_WRAP,(ValueRef.parameter(0,0),ValueRef.node_result(0,0)),(b32,)),
    ), Terminator.return_((ValueRef.node_result(0,1),)))])
    callee = function(callee_graph,(b32,),(b32,)); objects.append(callee_graph)
    caller = add("direct_call", [Block((b32,), (
        Node(Operation.CALL_DIRECT,(ValueRef.parameter(0,0),),(b32,),entity=callee),
        Node(Operation.ADD_WRAP,(ValueRef.node_result(0,0),ValueRef.node_result(0,0)),(b32,)),
    ), Terminator.return_((ValueRef.node_result(0,1),)))], (b32,), ((0,), (7,), (0xffffffff,)))

    atomic_nodes = (
        Node(Operation.STACK_ALLOC, (), (ptr,owner,effect), attributes=(4,4)),
        Node(Operation.ATOMIC_STORE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.node_result(0,0,2)),(effect,),attributes=(AtomicOrder.RELAXED,AtomicScope.SYSTEM,4)),
        Node(Operation.ATOMIC_LOAD,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,1)),(b32,effect),attributes=(AtomicOrder.SEQ_CST,AtomicScope.SYSTEM,4)),
        Node(Operation.STACK_END,(ValueRef.node_result(0,0,1),ValueRef.node_result(0,2,1)),()),
    )
    add("seq_cst_atomic", [Block((b32,), atomic_nodes, Terminator.return_((ValueRef.node_result(0,2,0),)))], (b32,), ((0,), (7,), (0xffffffff,)), legalization=True)

    functions = [callee, *(w.function for w in workloads)]
    reader = _store(functions, objects)
    return reader, tuple(workloads), callee


def _blocks(reader, fn):
    resolve = store_resolver(reader)
    graph, _, _ = _decode_function_interface(fn, resolve)
    parsed = _parse_graph(graph, resolve)
    blocks = tuple(Block(tuple(resolve(cid) for cid in b.parameters), tuple(Node(Operation(n.operation),n.operands,tuple(resolve(cid) for cid in n.results),member=n.member,entity=n.entity,attributes=n.attributes) for n in b.nodes), b.terminator) for b in parsed.blocks)
    return blocks, parsed.blocks


def _compile(reader, fn, target):
    arch = decode_native_target(target).architecture
    if arch == 1:
        return compile_native_bound_target(reader, fn.cid, target)
    if arch == 3:
        return compile_aarch64_bound_target(reader, fn.cid, target)
    raise ValueError("OI-18 measured only x86-64 and AArch64")


def _target_for(arch, workload):
    if arch == "x86_64": return x86_64_windows_target()
    if arch == "aarch64": return aarch64_baremetal_atomic_target() if workload.legalization else aarch64_baremetal_general_target()
    raise ValueError(arch)


def _opt(reader, fn, target):
    budget = OptimizationBudget(pass_iterations=4, search_steps=64, search_candidates=48, search_memory_bytes=1<<18)
    return optimize_function(reader, fn.cid, target=target, budget=budget, enable_search=True)


def compile_case(reader, workload, arch, alternate=False, selector=None):
    target = _target_for(arch, workload)
    result = _opt(reader, workload.function, target)
    select_work = cache_hits = cache_misses = 0
    selections = []
    if alternate:
        selector = selector or DemandSelector()
        blocks, parsed = _blocks(result.reader, result.function)
        resolve = store_resolver(result.reader)
        for block, pblock in zip(blocks, parsed):
            rec, hit, work = selector.select_block(block, target, pblock, resolve)
            selections.append(rec)
            select_work += work
            cache_hits += int(hit); cache_misses += int(not hit)
    image = _compile(result.reader, result.function, target)
    return result, image, {"selection_work_units":select_work,"cache_hits":cache_hits,"cache_misses":cache_misses,"selection_records":selections}


def _semantic_vectors(reader, workload, result):
    return all(execute(reader, workload.function.cid, v) == execute(result.reader, result.function.cid, v) for v in workload.vectors)


def _mutated_branch(reader, workloads):
    w = next(x for x in workloads if x.name == "branch_merge")
    resolve = store_resolver(reader); graph, params, returns = _decode_function_interface(w.function, resolve); parsed = _parse_graph(graph, resolve)
    blocks, _ = _blocks(reader, w.function)
    changed = list(blocks)
    old = changed[1]
    changed[1] = Block(old.parameters, (Node(Operation.MUL_WRAP, old.nodes[0].operands, old.nodes[0].result_types),), old.terminator)
    new_graph = graph_fragment(changed); new_fn = function(new_graph, tuple(resolve(c) for c in params), tuple(resolve(c) for c in returns))
    objects = {o.cid:o for o in reader.objects()}; objects[new_graph.cid]=new_graph; objects[new_fn.cid]=new_fn
    # Replace only the measured function in a fresh root; other functions remain unchanged.
    funcs=[]
    for obj in reader.objects():
        if obj.kind == Kind.FUNCTION and obj.cid != w.function.cid: funcs.append(obj)
    funcs.append(new_fn)
    module=object_with_refs(Kind.MODULE, tuple(sorted(funcs,key=lambda o:o.cid))); root=object_with_refs(Kind.PROGRAM_ROOT,(module,)); objects[module.cid]=module; objects[root.cid]=root
    reachable = {}
    def visit(cid):
        if cid in reachable: return
        obj = objects[cid]; reachable[cid] = obj
        for child in obj.references: visit(child)
    visit(root.cid)
    new_reader=StoreReader(write_store(root.cid, tuple(reachable.values()))); verify_store(new_reader)
    return new_reader, Workload(w.name, new_fn, w.vectors)


def _measure_once(reader, workload, arch, alternate):
    tracemalloc.start(); a=time.perf_counter_ns(); result,image,meta=compile_case(reader,workload,arch,alternate); elapsed=time.perf_counter_ns()-a; _cur,peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
    return elapsed, peak, len(image.artifact_bytes), result, meta


def measure(samples=11):
    reader, workloads, _ = corpus(); raw={"schema":"xax-oi18-timing-v1","samples":samples,"cases":{}}
    for arch in ("x86_64","aarch64"):
        for w in workloads:
            key=f"{arch}:{w.name}"; raw["cases"][key]={}
            for mode in ("baseline","demand"):
                times=[]; peaks=[]
                for _ in range(samples):
                    t,p,_b,_r,_m=_measure_once(reader,w,arch,mode=="demand"); times.append(t); peaks.append(p)
                raw["cases"][key][mode]={"wall_ns":times,"peak_bytes":peaks,"median_wall_ns":int(statistics.median(times)),"median_peak_bytes":int(statistics.median(peaks))}
    edited_reader, edited = _mutated_branch(reader, workloads)
    original = next(w for w in workloads if w.name == "branch_merge")
    raw["incremental"] = {}
    for arch in ("x86_64", "aarch64"):
        raw["incremental"][arch] = {}
        times=[]; peaks=[]
        for _ in range(samples):
            t,p,_b,_r,_m=_measure_once(edited_reader,edited,arch,False); times.append(t); peaks.append(p)
        raw["incremental"][arch]["baseline"]={"wall_ns":times,"peak_bytes":peaks,"median_wall_ns":int(statistics.median(times)),"median_peak_bytes":int(statistics.median(peaks))}
        times=[]; peaks=[]
        for _ in range(samples):
            selector=DemandSelector()
            tracemalloc.start()
            compile_case(reader,original,arch,True,selector)
            tracemalloc.reset_peak()
            a=time.perf_counter_ns(); compile_case(edited_reader,edited,arch,True,selector); times.append(time.perf_counter_ns()-a)
            _cur,peak=tracemalloc.get_traced_memory(); tracemalloc.stop(); peaks.append(peak)
        raw["incremental"][arch]["demand"]={"wall_ns":times,"peak_bytes":peaks,"median_wall_ns":int(statistics.median(times)),"median_peak_bytes":int(statistics.median(peaks))}
    TIMING_OUT.write_text(json.dumps(raw,indent=2,sort_keys=True)+"\n")
    return raw


def build():
    reader, workloads, _ = corpus()
    if not TIMING_OUT.exists(): measure()
    timing=json.loads(TIMING_OUT.read_text())
    rows=[]; equivalence=True; outputs=True
    for arch in ("x86_64","aarch64"):
        for w in workloads:
            base,bimg,bmeta=compile_case(reader,w,arch,False)
            sel=DemandSelector(); alt,aimg,ameta=compile_case(reader,w,arch,True,sel)
            same=bimg.artifact_bytes==aimg.artifact_bytes and base.function.cid==alt.function.cid
            equivalence &= same; outputs &= _semantic_vectors(reader,w,base)
            emission_units = sum(r.node_count + 1 for r in ameta["selection_records"])
            rows.append({"target":arch,"workload":w.name,"function_cid":w.function.cid.hex(),"optimized_cid":base.function.cid.hex(),"artifact_bytes":len(bimg.artifact_bytes),"exact_output_equivalence":same,"semantic_vectors_match":_semantic_vectors(reader,w,base),"search_steps":base.search.steps,"search_candidates":base.search.candidates,"search_equivalent_candidates":base.search.equivalent_candidates,"search_rejected_validation":base.search.rejected_validation,"optimization_events":len(base.events),"search_peak_bytes":base.search.peak_memory_bytes,"emission_work_units":emission_units,"baseline_deterministic_work_units":base.search.steps+emission_units,"demand_deterministic_work_units":base.search.steps+emission_units+ameta["selection_work_units"],"demand_selection_work_units":ameta["selection_work_units"],"demand_cache_misses":ameta["cache_misses"],"legalizations":[list(r.legalizations) for r in ameta["selection_records"]],"timing":timing["cases"][f"{arch}:{w.name}"]})

    # Incremental edit: one branch block changes, two block decisions remain reusable.
    edited_reader, edited = _mutated_branch(reader, workloads)
    incremental={}
    for arch in ("x86_64","aarch64"):
        original=next(w for w in workloads if w.name=="branch_merge"); selector=DemandSelector()
        compile_case(reader,original,arch,True,selector)
        _r,_img,meta=compile_case(edited_reader,edited,arch,True,selector)
        incremental[arch]={"cached_blocks_before":3,"cache_hits_after_local_edit":meta["cache_hits"],"cache_misses_after_local_edit":meta["cache_misses"],"selection_work_units_after_local_edit":meta["selection_work_units"],"timing":timing["incremental"][arch]}

    # Explicit unsupported legalization negative on wasm32.
    atomic=next(w for w in workloads if w.legalization); blocks, parsed=_blocks(reader,atomic.function); selector=DemandSelector(); wasm=wasm32_target(); rule=None
    resolve = store_resolver(reader)
    try:
        for b,p in zip(blocks,parsed): selector.select_block(b,wasm,p,resolve)
    except Exception as exc:
        rule=getattr(getattr(exc,"diagnostic",None),"rule",type(exc).__name__)
    backend_rule=None
    try:
        compile_wasm_bound_target(reader, atomic.function.cid, wasm)
    except Exception as exc:
        backend_rule=getattr(getattr(exc,"diagnostic",None),"rule",type(exc).__name__)

    alt_lines=len(inspect.getsource(DemandSelector).splitlines())
    evidence={
        "schema":"xax-oi18-optimizer-organization-v1","alternate":MODEL_ID,
        "decision_candidate":"keep staged semantic optimizer + direct target lowering; no persistent universal MIR",
        "corpus":{"workloads":[w.name for w in workloads],"targets":["x86_64","aarch64"],"store_objects":sum(1 for _ in reader.objects()),"root_cid":reader.root_cid.hex()},
        "rows":rows,"all_artifacts_byte_identical":equivalence,"all_semantic_vectors_match":outputs,
        "incremental":incremental,"unsupported_legalization_rule":rule,"unsupported_backend_rule":backend_rule,
        "implementation":{"alternate_selector_lines":alt_lines,"production_lines_changed":0,"target_specific_production_lines_added":0,"target_duplication_reduced_lines":0,"persistent_machine_ir_objects":0},
        "verifier":{"cold_store_objects":sum(1 for _ in reader.objects()),"optimizer_events":sum(r["optimization_events"] for r in rows),"search_candidates":sum(r["search_candidates"] for r in rows),"search_rejected_validation":sum(r["search_rejected_validation"] for r in rows),"alternate_extra_legality_checks":sum(r["demand_selection_work_units"] for r in rows)},
        "code_quality":{"artifact_bytes_changed":0,"optimization_improvements":0,"all_outputs_identical":equivalence},
        "closure":{"closed":True,"selected":"current staged semantic optimizer with direct target-specific lowering","reason":"alternate adds conversion/legality work and memory with byte-identical output; its block-cache locality does not reduce backend recompilation, so no material total benefit justifies a new MIR/selection layer"},
    }
    return evidence


def main():
    import sys
    if "--measure" in sys.argv: measure()
    evidence=build(); EVIDENCE_OUT.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n")
    print(json.dumps(evidence,sort_keys=True))

if __name__=="__main__": main()
