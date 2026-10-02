"""OI-06 alias/provenance and checked/raw memory-surface evidence.

The semantic fixtures and size/code measurements are deterministic. Timing samples
are host observations and are never conformance thresholds. ``token_atoms`` counts
ideal token-native semantic atoms (operation/value/type/attribute handles), not a
third-party text tokenizer.
"""
from __future__ import annotations

import json
import platform
import statistics
import time
from pathlib import Path

from xax_compiler import (
    Block, EffectDomain, Kind, Node, Operation, Permission, StoreReader, Terminator,
    ValueRef, bits_type, effect_type, function, graph_fragment, memory_effect_type,
    object_with_refs, pointer_type, stack_owner_type, verify_store, write_store,
    oi06_x86_64_windows_target, oi06_wasm32_target, _decode_function_interface, _parse_graph,
)
from xax_x86_64 import compile_native_bound_target
from xax_wasm import compile_wasm_bound_target, run_wasm_isolated

REPETITIONS = 31


def _pack(objects, graph, entry):
    module = object_with_refs(Kind.MODULE, [entry])
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    return StoreReader(write_store(root.cid, [*objects, graph, entry, module, root])), entry, graph


def two_alias_fixture():
    b32=bits_type(32); p=pointer_type(b32, Permission.READ_WRITE,4); o=stack_owner_type(); e=memory_effect_type()
    n=(
      Node(Operation.STACK_ALLOC,(),(p,o,e),attributes=(4,4)), Node(Operation.STACK_ALLOC,(),(p,o,e),attributes=(4,4)),
      Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.node_result(0,0,2)),(e,),attributes=(4,4)),
      Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,1,0),ValueRef.parameter(0,1),ValueRef.node_result(0,1,2)),(e,),attributes=(4,4)),
      Node(Operation.LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,2,0)),(b32,e),attributes=(4,4)),
      Node(Operation.LOAD_BITS_LE,(ValueRef.node_result(0,1,0),ValueRef.node_result(0,3,0)),(b32,e),attributes=(4,4)),
      Node(Operation.STACK_END,(ValueRef.node_result(0,0,1),ValueRef.node_result(0,4,1)),()),
      Node(Operation.STACK_END,(ValueRef.node_result(0,1,1),ValueRef.node_result(0,5,1)),()),)
    g=graph_fragment([Block((b32,b32),n,Terminator.return_((ValueRef.node_result(0,4,0),)))])
    f=function(g,(b32,b32),(b32,)); return _pack([b32,p,o,e],g,f)


def checked_load_fixture(ordinary=False):
    b32=bits_type(32); p=pointer_type(b32,Permission.READ_WRITE,4); o=stack_owner_type(); e=memory_effect_type()
    nodes=[
      Node(Operation.STACK_ALLOC,(),(p,o,e),attributes=(8,4)),
      Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.node_result(0,0,2)),(e,),attributes=(4,4)),
      Node(Operation.ADDRESS_OFFSET,(ValueRef.node_result(0,0,0),),(p,),attributes=(4,)),
      Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,2,0),ValueRef.parameter(0,1),ValueRef.node_result(0,1,0)),(e,),attributes=(4,4)),]
    if ordinary:
        nodes.append(Node(Operation.LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,3,0)),(b32,e),attributes=(4,1)))
    else:
        nodes.append(Node(Operation.CHECKED_LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,2),ValueRef.node_result(0,3,0)),(b32,e),attributes=(4,1)))
    nodes.append(Node(Operation.STACK_END,(ValueRef.node_result(0,0,1),ValueRef.node_result(0,4,1)),()))
    g=graph_fragment([Block((b32,b32,b32),tuple(nodes),Terminator.return_((ValueRef.node_result(0,4,0),)))])
    f=function(g,(b32,b32,b32),(b32,)); return _pack([b32,p,o,e],g,f)


def checked_store_fixture(ordinary=False):
    b32=bits_type(32); p=pointer_type(b32,Permission.READ_WRITE,4); o=stack_owner_type(); e=memory_effect_type()
    nodes=[Node(Operation.STACK_ALLOC,(),(p,o,e),attributes=(4,4))]
    if ordinary:
        nodes.append(Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,1),ValueRef.node_result(0,0,2)),(e,),attributes=(4,1)))
    else:
        nodes.append(Node(Operation.CHECKED_STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.parameter(0,1),ValueRef.node_result(0,0,2)),(e,),attributes=(4,1)))
    nodes.append(Node(Operation.STACK_END,(ValueRef.node_result(0,0,1),ValueRef.node_result(0,1,0)),()))
    g=graph_fragment([Block((b32,b32),tuple(nodes),Terminator.return_((ValueRef.parameter(0,1),)))])
    f=function(g,(b32,b32),(b32,)); return _pack([b32,p,o,e],g,f)


def raw_load_fixture(ordinary=False):
    b32=bits_type(32); p=pointer_type(b32,Permission.READ_WRITE,4); o=stack_owner_type(); e=memory_effect_type(); u=effect_type(EffectDomain.UNSAFE)
    nodes=[Node(Operation.STACK_ALLOC,(),(p,o,e),attributes=(4,4)),
           Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.node_result(0,0,2)),(e,),attributes=(4,4))]
    if ordinary:
        nodes.append(Node(Operation.LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,1,0)),(b32,e),attributes=(4,4)))
        unsafe_out=ValueRef.parameter(0,1)
    else:
        nodes.append(Node(Operation.RAW_LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,1,0),ValueRef.parameter(0,1)),(b32,e,u),attributes=(4,4,2)))
        unsafe_out=ValueRef.node_result(0,2,2)
    nodes.append(Node(Operation.STACK_END,(ValueRef.node_result(0,0,1),ValueRef.node_result(0,2,1 if not ordinary else 1)),()))
    g=graph_fragment([Block((b32,u),tuple(nodes),Terminator.return_((ValueRef.node_result(0,2,0),unsafe_out)))])
    f=function(g,(b32,u),(b32,u)); return _pack([b32,p,o,e,u],g,f)


def token_atoms(reader, entry):
    objects={o.cid:o for o in reader.objects()}; resolve=objects.__getitem__
    graph_cid,_,_=_decode_function_interface(entry,resolve); graph=_parse_graph(graph_cid,resolve)
    total=0
    for block in graph.blocks:
        total += 1 + len(block.parameters)
        for node in block.nodes:
            total += 1 + len(node.operands) + len(node.results) + len(node.attributes) + (1 if node.entity is not None else 0) + (1 if node.member is not None else 0)
        total += 1 + len(block.terminator.values) + sum(1+len(args) for _,args in block.terminator.edges)
    return total


def median_verify_us(reader):
    data=reader.canonical_bytes(); samples=[]
    for _ in range(REPETITIONS):
        r=StoreReader(data); start=time.perf_counter_ns(); verify_store(r); samples.append((time.perf_counter_ns()-start)/1000)
    return statistics.median(samples), samples


def measure(name, fixture):
    reader,entry,graph=fixture(); verify_store(reader)
    med,samples=median_verify_us(reader)
    native=compile_native_bound_target(reader,entry.cid,oi06_x86_64_windows_target())
    wasm=compile_wasm_bound_target(reader,entry.cid,oi06_wasm32_target())
    return {
      'name':name, 'root_cid':reader.root_cid.hex(), 'graph_cid':graph.cid.hex(),
      'graph_body_bytes':len(graph.body), 'graph_envelope_bytes':len(graph.envelope()),
      'store_bytes':len(reader.canonical_bytes()), 'token_atoms':token_atoms(reader,entry),
      'verify_median_us':med, 'verify_samples_us':samples,
      'x86_64_code_bytes':len(native.code), 'wasm_module_bytes':len(wasm.module),
    }


def collect_evidence():
    rows={r['name']:r for r in [
      measure('two_alias_implicit',two_alias_fixture), measure('ordinary_load',lambda:checked_load_fixture(True)),
      measure('checked_load',lambda:checked_load_fixture(False)), measure('ordinary_store',lambda:checked_store_fixture(True)),
      measure('checked_store',lambda:checked_store_fixture(False)), measure('ordinary_initialized_load',lambda:raw_load_fixture(True)),
      measure('raw_initialized_load',lambda:raw_load_fixture(False)),]}
    checked_reader,checked_entry,_=checked_load_fixture(False)
    wasm=compile_wasm_bound_target(checked_reader,checked_entry.cid,oi06_wasm32_target())
    wasm_results={'offset_0':run_wasm_isolated(wasm,(11,22,0))[0], 'offset_4':run_wasm_isolated(wasm,(11,22,4))[0]}
    # Comparator only: serializing one explicit ULEB alias-class id on each of the
    # two allocation nodes would add exactly one byte/one token-native atom each.
    implicit=rows['two_alias_implicit']
    return {
      'schema':'xax.oi06-memory-surface.v1', 'host':{'python':platform.python_version(),'platform':platform.platform()},
      'repetitions':REPETITIONS,
      'token_metric':'ideal token-native semantic atoms; not a text tokenizer',
      'rows':rows,
      'alias_encoding_comparator':{
        'derived_allocation_identity_extra_graph_bytes':0,'derived_allocation_identity_extra_token_atoms':0,
        'explicit_local_class_id_extra_graph_bytes':2,'explicit_local_class_id_extra_token_atoms':2,
        'precise_alias_classes':2,'basis_graph_bytes':implicit['graph_body_bytes'],
      },
      'checked_surface_comparator':{
        'fused_checked_load_token_atoms':rows['checked_load']['token_atoms'],
        'ordinary_static_load_token_atoms':rows['ordinary_load']['token_atoms'],
        'x86_checked_minus_ordinary_code_bytes':rows['checked_load']['x86_64_code_bytes']-rows['ordinary_load']['x86_64_code_bytes'],
        'wasm_checked_minus_ordinary_module_bytes':rows['checked_load']['wasm_module_bytes']-rows['ordinary_load']['wasm_module_bytes'],
        'checked_store_minus_ordinary_graph_body_bytes':rows['checked_store']['graph_body_bytes']-rows['ordinary_store']['graph_body_bytes'],
        'checked_store_minus_ordinary_token_atoms':rows['checked_store']['token_atoms']-rows['ordinary_store']['token_atoms'],
        'x86_checked_store_minus_ordinary_code_bytes':rows['checked_store']['x86_64_code_bytes']-rows['ordinary_store']['x86_64_code_bytes'],
        'wasm_checked_store_minus_ordinary_module_bytes':rows['checked_store']['wasm_module_bytes']-rows['ordinary_store']['wasm_module_bytes'],
      },
      'raw_surface_comparator':{
        'raw_minus_ordinary_graph_body_bytes':rows['raw_initialized_load']['graph_body_bytes']-rows['ordinary_initialized_load']['graph_body_bytes'],
        'raw_minus_ordinary_token_atoms':rows['raw_initialized_load']['token_atoms']-rows['ordinary_initialized_load']['token_atoms'],
        'x86_raw_minus_ordinary_code_bytes':rows['raw_initialized_load']['x86_64_code_bytes']-rows['ordinary_initialized_load']['x86_64_code_bytes'],
        'wasm_raw_minus_ordinary_module_bytes':rows['raw_initialized_load']['wasm_module_bytes']-rows['ordinary_initialized_load']['wasm_module_bytes'],
      },
      'target_models':{
        'x86_64':'frame-relative native stack with explicit software bounds branch for checked dynamic offset',
        'wasm32':'32-bit linear memory with explicit allocation-view bounds branch before linear-memory access',
        'wasm_execution_results':wasm_results,
      },
    }


def main():
    evidence=collect_evidence(); path=Path(__file__).with_name('oi06_memory_surface_evidence.json'); path.write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n'); print(json.dumps(evidence,indent=2,sort_keys=True))

if __name__=='__main__': main()
