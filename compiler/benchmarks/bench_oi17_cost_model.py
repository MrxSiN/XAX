"""OI-17 target cost-model calibration/evaluation experiment.

All costs here are non-semantic tooling evidence.  Raw hardware samples are
captured separately with --measure; the deterministic evidence build consumes
that fixed sidecar.  No measured value is a timing guarantee.
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from xax_compiler import (
    Block, Kind, Node, Operation, Permission, StoreReader, Terminator, ValueRef,
    bits_type, constant, execute, function, graph_fragment, memory_effect_type,
    object_with_refs, pointer_type, stack_owner_type, verify_store, write_store,
    x86_64_windows_target,
)
from xax_x86_64 import compile_native_bound_target

HERE = Path(__file__).resolve().parent
RAW_OUT = HERE / "oi17_cost_model_raw.json"
EVIDENCE_OUT = HERE / "oi17_cost_model_evidence.json"
MODEL_VERSION = "xax-oi17-cost-model-v1"

@dataclass(frozen=True)
class Case:
    name: str
    family: str
    function: object
    arity: int
    vectors: tuple[tuple[int, ...], ...]
    features: dict[str, float]


def _store(functions, objects):
    module = object_with_refs(Kind.MODULE, tuple(fn for fn in functions))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    reader = StoreReader(write_store(root.cid, (*objects, *functions, module, root)))
    verify_store(reader)
    return reader


def corpus():
    b1, b32 = bits_type(1), bits_type(32)
    two = constant(b32, 2)
    ptr = pointer_type(b32, Permission.READ_WRITE, 4)
    owner = stack_owner_type()
    effect = memory_effect_type()
    objs = [b1, b32, two, ptr, owner, effect]
    cases = []

    def add_case(name, family, blocks, params, arity, vectors, features):
        graph = graph_fragment(blocks)
        fn = function(graph, params, (b32,))
        objs.append(graph)
        cases.append(Case(name, family, fn, arity, tuple(vectors), features))

    # arithmetic: x*2 via add or multiply-by-constant
    add_case("arith_add2", "arithmetic", [Block((b32,), (
        Node(Operation.ADD_WRAP, (ValueRef.parameter(0,0), ValueRef.parameter(0,0)), (b32,)),
    ), Terminator.return_((ValueRef.node_result(0,0),)))], (b32,), 1,
        ((0,), (1,), (7,), (0x7fffffff,), (0xffffffff,)),
        {"add":1,"sub":0,"mul":0,"branch":0,"memory":0,"critical_add":1,"critical_mul":0,"alu_total":1})
    add_case("arith_mul2", "arithmetic", [Block((b32,), (
        Node(Operation.CONSTANT, (), (b32,), entity=two),
        Node(Operation.MUL_WRAP, (ValueRef.parameter(0,0), ValueRef.node_result(0,0)), (b32,)),
    ), Terminator.return_((ValueRef.node_result(0,1),)))], (b32,), 1,
        ((0,), (1,), (7,), (0x7fffffff,), (0xffffffff,)),
        {"add":0,"sub":0,"mul":1,"branch":0,"memory":0,"critical_add":0,"critical_mul":1,"alu_total":1})

    # control: lazy selected arithmetic versus eager compute-both then select.
    lazy = [
        Block((b1,b32,b32), (), Terminator.conditional_branch(ValueRef.parameter(0,0),1,(ValueRef.parameter(0,1),ValueRef.parameter(0,2)),2,(ValueRef.parameter(0,1),ValueRef.parameter(0,2)))),
        Block((b32,b32), (Node(Operation.ADD_WRAP,(ValueRef.parameter(1,0),ValueRef.parameter(1,1)),(b32,)),), Terminator.return_((ValueRef.node_result(1,0),))),
        Block((b32,b32), (Node(Operation.SUB_WRAP,(ValueRef.parameter(2,0),ValueRef.parameter(2,1)),(b32,)),), Terminator.return_((ValueRef.node_result(2,0),))),
    ]
    eager = [
        Block((b1,b32,b32), (
            Node(Operation.ADD_WRAP,(ValueRef.parameter(0,1),ValueRef.parameter(0,2)),(b32,)),
            Node(Operation.SUB_WRAP,(ValueRef.parameter(0,1),ValueRef.parameter(0,2)),(b32,)),
        ), Terminator.conditional_branch(ValueRef.parameter(0,0),1,(ValueRef.node_result(0,0),),2,(ValueRef.node_result(0,1),))),
        Block((b32,), (), Terminator.return_((ValueRef.parameter(1,0),))),
        Block((b32,), (), Terminator.return_((ValueRef.parameter(2,0),))),
    ]
    branch_vectors=((0,7,3),(1,7,3),(0,0xffffffff,1),(1,0xffffffff,1))
    add_case("branch_lazy", "control", lazy, (b1,b32,b32), 3, branch_vectors,
             {"add":1,"sub":1,"mul":0,"branch":1,"memory":0,"critical_add":1,"critical_mul":0,"alu_total":1})
    add_case("branch_eager", "control", eager, (b1,b32,b32), 3, branch_vectors,
             {"add":1,"sub":1,"mul":0,"branch":1,"memory":0,"critical_add":2,"critical_mul":0,"alu_total":2})

    # memory: invisible local stack round-trip versus direct value.
    add_case("mem_direct", "memory", [Block((b32,), (), Terminator.return_((ValueRef.parameter(0,0),)))], (b32,), 1,
             ((0,), (1,), (7,), (0xffffffff,)),
             {"add":0,"sub":0,"mul":0,"branch":0,"memory":0,"critical_add":0,"critical_mul":0,"alu_total":0})
    stack_nodes=(
        Node(Operation.STACK_ALLOC, (), (ptr,owner,effect), attributes=(4,4)),
        Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.node_result(0,0,2)), (effect,), attributes=(4,4)),
        Node(Operation.LOAD_BITS_LE, (ValueRef.node_result(0,0,0),ValueRef.node_result(0,1)), (b32,effect), attributes=(4,4)),
        Node(Operation.STACK_END, (ValueRef.node_result(0,0,1),ValueRef.node_result(0,2,1)), ()),
    )
    add_case("mem_stack_roundtrip", "memory", [Block((b32,), stack_nodes, Terminator.return_((ValueRef.node_result(0,2),)))], (b32,), 1,
             ((0,), (1,), (7,), (0xffffffff,)),
             {"add":0,"sub":0,"mul":0,"branch":0,"memory":2,"critical_add":0,"critical_mul":0,"alu_total":0})

    # same 4*x, dependency chain versus two independent doubles plus final add.
    add_case("dep_chain4x", "dependency", [Block((b32,), (
        Node(Operation.ADD_WRAP,(ValueRef.parameter(0,0),ValueRef.parameter(0,0)),(b32,)),
        Node(Operation.ADD_WRAP,(ValueRef.node_result(0,0),ValueRef.node_result(0,0)),(b32,)),
    ), Terminator.return_((ValueRef.node_result(0,1),)))], (b32,), 1,
        ((0,), (1,), (7,), (0x40000000,), (0xffffffff,)),
        {"add":2,"sub":0,"mul":0,"branch":0,"memory":0,"critical_add":2,"critical_mul":0,"alu_total":2})
    add_case("dep_parallel4x", "dependency", [Block((b32,), (
        Node(Operation.ADD_WRAP,(ValueRef.parameter(0,0),ValueRef.parameter(0,0)),(b32,)),
        Node(Operation.ADD_WRAP,(ValueRef.parameter(0,0),ValueRef.parameter(0,0)),(b32,)),
        Node(Operation.ADD_WRAP,(ValueRef.node_result(0,0),ValueRef.node_result(0,1)),(b32,)),
    ), Terminator.return_((ValueRef.node_result(0,2),)))], (b32,), 1,
        ((0,), (1,), (7,), (0x40000000,), (0xffffffff,)),
        {"add":3,"sub":0,"mul":0,"branch":0,"memory":0,"critical_add":2,"critical_mul":0,"alu_total":3})

    # Calibration-only verified functions. They are measured but excluded from
    # candidate ranking/error evaluation.
    add_case("cal_base", "_cal_base", [Block((b32,b32), (), Terminator.return_((ValueRef.parameter(0,0),)))], (b32,b32), 2, ((7,3),),
             {"add":0,"sub":0,"mul":0,"branch":0,"memory":0,"critical_add":0,"critical_mul":0,"alu_total":0})
    add_nodes=[]
    cur=ValueRef.parameter(0,0)
    for i in range(8):
        add_nodes.append(Node(Operation.ADD_WRAP,(cur,ValueRef.parameter(0,1)),(b32,)))
        cur=ValueRef.node_result(0,i)
    add_case("cal_add8", "_cal_add", [Block((b32,b32), tuple(add_nodes), Terminator.return_((cur,)))], (b32,b32), 2, ((7,3),),
             {"add":8,"sub":0,"mul":0,"branch":0,"memory":0,"critical_add":8,"critical_mul":0,"alu_total":8})
    mul_nodes=[]
    cur=ValueRef.parameter(0,0)
    for i in range(4):
        mul_nodes.append(Node(Operation.MUL_WRAP,(cur,ValueRef.parameter(0,1)),(b32,)))
        cur=ValueRef.node_result(0,i)
    add_case("cal_mul4", "_cal_mul", [Block((b32,b32), tuple(mul_nodes), Terminator.return_((cur,)))], (b32,b32), 2, ((7,3),),
             {"add":0,"sub":0,"mul":4,"branch":0,"memory":0,"critical_add":0,"critical_mul":4,"alu_total":4})
    cal_branch=[
        Block((b1,b32,b32),(),Terminator.conditional_branch(ValueRef.parameter(0,0),1,(ValueRef.parameter(0,1),),2,(ValueRef.parameter(0,2),))),
        Block((b32,),(),Terminator.return_((ValueRef.parameter(1,0),))),
        Block((b32,),(),Terminator.return_((ValueRef.parameter(2,0),))),
    ]
    add_case("cal_branch", "_cal_branch", cal_branch, (b1,b32,b32), 3, ((0,7,3),(1,7,3)),
             {"add":0,"sub":0,"mul":0,"branch":1,"memory":0,"critical_add":0,"critical_mul":0,"alu_total":0})
    mem2=(
        Node(Operation.STACK_ALLOC, (), (ptr,owner,effect), attributes=(4,4)),
        Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.parameter(0,0),ValueRef.node_result(0,0,2)),(effect,),attributes=(4,4)),
        Node(Operation.LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,1)),(b32,effect),attributes=(4,4)),
        Node(Operation.STORE_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,2,0),ValueRef.node_result(0,2,1)),(effect,),attributes=(4,4)),
        Node(Operation.LOAD_BITS_LE,(ValueRef.node_result(0,0,0),ValueRef.node_result(0,3)),(b32,effect),attributes=(4,4)),
        Node(Operation.STACK_END,(ValueRef.node_result(0,0,1),ValueRef.node_result(0,4,1)),()),
    )
    add_case("cal_mem4", "_cal_mem", [Block((b32,b32),mem2,Terminator.return_((ValueRef.node_result(0,4,0),)))], (b32,b32), 2, ((7,3),),
             {"add":0,"sub":0,"mul":0,"branch":0,"memory":4,"critical_add":0,"critical_mul":0,"alu_total":0})

    reader=_store(tuple(c.function for c in cases), tuple(objs))
    return reader, tuple(cases)


def compiled_cases():
    reader, cases=corpus(); target=x86_64_windows_target(); out=[]
    for case in cases:
        image=compile_native_bound_target(reader, case.function.cid, target)
        code=image.artifact_bytes
        outputs=[list(execute(reader, case.function.cid, vector)) for vector in case.vectors]
        out.append((case,code,outputs))
    return reader,target,out


def semantic_checks(compiled):
    by_family={}
    for case,_code,outputs in compiled:
        by_family.setdefault(case.family,[]).append((case,outputs))
    checks={}
    for family,items in by_family.items():
        reference=items[0][1]
        checks[family]=all(outputs==reference for _,outputs in items)
    return checks


def _cpu_identity():
    model="unknown"
    vendor="unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name") and model=="unknown": model=line.split(":",1)[1].strip()
            if line.startswith("vendor_id") and vendor=="unknown": vendor=line.split(":",1)[1].strip()
    except OSError: pass
    return {"system":platform.system(),"machine":platform.machine(),"release":platform.release(),"vendor":vendor,"model":model}


def _c_array(name,data):
    return f"static const unsigned char {name}[]={{"+",".join(f"0x{x:02x}" for x in data)+"};"


def measure(samples=21, iterations=100_000, warmup=50_000):
    if platform.machine().lower() not in ("x86_64","amd64"):
        raise RuntimeError("x86-64 host required")
    cc=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc: raise RuntimeError("C compiler required")
    _reader,target,compiled=compiled_cases()
    arrays="\n".join(_c_array(f"code_{i}",code) for i,(_case,code,_out) in enumerate(compiled))
    ptrinit=",".join(f"map_code(code_{i},sizeof code_{i})" for i in range(len(compiled)))
    arities=",".join(str(case.arity) for case,_code,_out in compiled)
    source=f'''#define _GNU_SOURCE\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <sched.h>\n#include <sys/mman.h>\n#include <time.h>\ntypedef uint32_t (__attribute__((ms_abi))*fn1_t)(uint32_t);\ntypedef uint32_t (__attribute__((ms_abi))*fn2_t)(uint32_t,uint32_t);\ntypedef uint32_t (__attribute__((ms_abi))*fn3_t)(uint32_t,uint32_t,uint32_t);\n{arrays}\nstatic void *map_code(const unsigned char *c,size_t n){{void*m=mmap(NULL,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(m==MAP_FAILED)return NULL;memcpy(m,c,n);__builtin___clear_cache(m,(char*)m+n);return m;}}\nstatic uint64_t ns(void){{struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))exit(4);return(uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;}}\nstatic int pin_first(void){{cpu_set_t s;CPU_ZERO(&s);if(sched_getaffinity(0,sizeof(s),&s))return -1;for(int i=0;i<CPU_SETSIZE;i++)if(CPU_ISSET(i,&s)){{cpu_set_t o;CPU_ZERO(&o);CPU_SET(i,&o);if(!sched_setaffinity(0,sizeof(o),&o))return i;return -2;}}return -3;}}\nint main(void){{void* f[{len(compiled)}]={{{ptrinit}}};int ar[{len(compiled)}]={{{arities}}};for(int i=0;i<{len(compiled)};i++)if(!f[i])return 2;int pinned=pin_first();printf("P %d\\n",pinned);volatile uint32_t sink=0;\nfor(int k=0;k<{len(compiled)};k++){{\n uint32_t s=7; for(int i=0;i<{warmup};i++){{if(ar[k]==1)s=((fn1_t)f[k])(s);else if(ar[k]==2)s=((fn2_t)f[k])(s,3u);else s=((fn3_t)f[k])(s&1u,s,3u);}} sink^=s;\n for(int q=0;q<{samples};q++){{s=(uint32_t)(q+7);uint64_t a=ns();for(int i=0;i<{iterations};i++){{if(ar[k]==1)s=((fn1_t)f[k])(s);else if(ar[k]==2)s=((fn2_t)f[k])(s,3u);else s=((fn3_t)f[k])(s&1u,s,3u);}}uint64_t b=ns();sink^=s;printf("L %d %llu\\n",k,(unsigned long long)(b-a));}}\n for(int q=0;q<{samples};q++){{uint64_t a=ns();for(int i=0;i<{iterations};i+=4){{if(ar[k]==1){{sink^=((fn1_t)f[k])((uint32_t)i);sink^=((fn1_t)f[k])((uint32_t)i+1);sink^=((fn1_t)f[k])((uint32_t)i+2);sink^=((fn1_t)f[k])((uint32_t)i+3);}}else if(ar[k]==2){{sink^=((fn2_t)f[k])((uint32_t)i,3u);sink^=((fn2_t)f[k])((uint32_t)i+1,3u);sink^=((fn2_t)f[k])((uint32_t)i+2,3u);sink^=((fn2_t)f[k])((uint32_t)i+3,3u);}}else{{sink^=((fn3_t)f[k])((uint32_t)i&1u,(uint32_t)i,3u);sink^=((fn3_t)f[k])(((uint32_t)i+1)&1u,(uint32_t)i+1,3u);sink^=((fn3_t)f[k])(((uint32_t)i+2)&1u,(uint32_t)i+2,3u);sink^=((fn3_t)f[k])(((uint32_t)i+3)&1u,(uint32_t)i+3,3u);}}}}uint64_t b=ns();printf("T %d %llu\\n",k,(unsigned long long)(b-a));}}\n}}printf("S %u\\n",(unsigned)sink);return 0;}}\n'''
    with tempfile.TemporaryDirectory(prefix="xax-oi17-") as d:
        src=Path(d)/"bench.c"; exe=Path(d)/"bench"; src.write_text(source)
        cr=subprocess.run([cc,"-O2","-std=c11",str(src),"-o",str(exe)],capture_output=True,text=True,check=False)
        if cr.returncode: raise RuntimeError(cr.stderr)
        rr=subprocess.run([str(exe)],capture_output=True,text=True,check=False,timeout=45)
        if rr.returncode: raise RuntimeError(rr.stderr or f"harness exit {rr.returncode}")
    lat=[[] for _ in compiled]; thr=[[] for _ in compiled]; pinned=None
    for line in rr.stdout.splitlines():
        p=line.split()
        if p[0]=="P": pinned=int(p[1])
        elif p[0]=="L": lat[int(p[1])].append(int(p[2]))
        elif p[0]=="T": thr[int(p[1])].append(int(p[2]))
    def summary(values):
        ordered=sorted(values); med=float(statistics.median(ordered))/iterations
        return {"raw_batch_ns":values,"median_ns_per_call":med,"min_ns_per_call":ordered[0]/iterations,"p10_ns_per_call":ordered[(len(ordered)-1)//10]/iterations,"p90_ns_per_call":ordered[((len(ordered)-1)*9)//10]/iterations,"max_ns_per_call":ordered[-1]/iterations}
    version=subprocess.run([cc,"--version"],capture_output=True,text=True,check=False).stdout.splitlines()
    raw={"schema":"xax-oi17-cost-model-raw-v1","host":_cpu_identity(),"target_cid":target.cid.hex(),"compiler":{"path":cc,"version":version[0] if version else "unknown"},"clock":"CLOCK_MONOTONIC_RAW","pinned_cpu":pinned,"warmup_iterations":warmup,"iterations_per_sample":iterations,"samples":samples,"cases":{}}
    for i,(case,code,_out) in enumerate(compiled):
        raw["cases"][case.name]={"function_cid":case.function.cid.hex(),"code_bytes":len(code),"latency":summary(lat[i]),"throughput":summary(thr[i])}
    RAW_OUT.write_text(json.dumps(raw,indent=2,sort_keys=True)+"\n")
    return raw

STATIC={"base":1.6,"add":0.30,"sub":0.30,"mul":0.85,"branch":0.55,"memory":0.55}

def _predict_static(f):
    return STATIC["base"]+STATIC["add"]*f["add"]+STATIC["sub"]*f["sub"]+STATIC["mul"]*f["mul"]+STATIC["branch"]*f["branch"]+STATIC["memory"]*f["memory"]

def _predict_symbolic(f, objective, coeff=STATIC):
    if objective=="latency":
        alu=coeff["add"]*f["critical_add"]+coeff["mul"]*f["critical_mul"]
    else:
        alu=coeff["add"]*math.ceil(f["alu_total"]/2)+coeff["mul"]*f["mul"]
    return coeff["base"]+alu+coeff["branch"]*f["branch"]+coeff["memory"]*f["memory"]

def _calibrated_coeff(raw, objective):
    obs={k:v[objective]["median_ns_per_call"] for k,v in raw["cases"].items()}
    base=obs["cal_base"]
    add=max(0.001,(obs["cal_add8"]-base)/8)
    mul=max(0.001,(obs["cal_mul4"]-base)/4)
    memory=max(0.001,(obs["cal_mem4"]-base)/4)
    branch=max(0.001,obs["cal_branch"]-base)
    return {"base":base,"add":add,"sub":add,"mul":mul,"branch":branch,"memory":memory}

def _metrics(pred,obs,families):
    errors=[abs(pred[n]-obs[n])/max(obs[n],1e-12) for n in pred]
    correct=0; total=0; details=[]
    for family,names in families.items():
        if len(names)!=2: continue
        a,b=names; po=pred[a]-pred[b]; oo=obs[a]-obs[b]
        ok=(po==0 and oo==0) or (po*oo>0)
        correct+=int(ok); total+=1; details.append({"family":family,"predicted_best":a if pred[a]<pred[b] else b,"observed_best":a if obs[a]<obs[b] else b,"correct":ok})
    return {"pairwise_correct":correct,"pairwise_total":total,"pairwise_accuracy":correct/total if total else None,"mean_normalized_absolute_error":sum(errors)/len(errors),"pairs":details}

def build():
    if not RAW_OUT.exists(): raise RuntimeError("raw measurement missing; run --measure on executable x86-64 hardware")
    raw=json.loads(RAW_OUT.read_text())
    reader,target,compiled=compiled_cases()
    evaluation=tuple(item for item in compiled if not item[0].family.startswith("_cal_"))
    checks=semantic_checks(evaluation)
    if not all(checks.values()): raise RuntimeError("semantic candidate mismatch")
    names=[c.name for c,_,_ in evaluation]; families={}
    for c,_,_ in evaluation: families.setdefault(c.family,[]).append(c.name)
    observations={objective:{n:raw["cases"][n][objective]["median_ns_per_call"] for n in names} for objective in ("latency","throughput")}
    models={}
    for objective in ("latency","throughput"):
        coeff=_calibrated_coeff(raw,objective)
        preds={
            "static_table":{c.name:_predict_static(c.features) for c,_,_ in evaluation},
            "symbolic":{c.name:_predict_symbolic(c.features,objective) for c,_,_ in evaluation},
            "measured_calibrated":{c.name:_predict_symbolic(c.features,objective,coeff) for c,_,_ in evaluation},
        }
        models[objective]={m:{"predictions_ns":p,"metrics":_metrics(p,observations[objective],families)} for m,p in preds.items()}
        models[objective]["measured_calibrated"]["coefficients_ns"]=coeff
    size={c.name:len(code) for c,code,_ in evaluation}
    size_pairs=[]
    for family,names2 in families.items():
        a,b=names2; size_pairs.append({"family":family,"best":a if size[a]<size[b] else (b if size[b]<size[a] else "tie"),"bytes":{a:size[a],b:size[b]}})
    raw_sha=hashlib.sha256(RAW_OUT.read_bytes()).hexdigest()
    cal_id=hashlib.sha256(bytes.fromhex(raw["target_cid"])+json.dumps(raw["host"],sort_keys=True,separators=(",",":")).encode()+MODEL_VERSION.encode()+bytes.fromhex(raw_sha)).hexdigest()
    # One bounded optimizer choice: calibrated latency chooses among dependency-family equivalents.
    dep=families["memory"]
    pred=models["latency"]["measured_calibrated"]["predictions_ns"]
    selected=min(dep,key=lambda n:(pred[n],n)); actual=min(dep,key=lambda n:(observations["latency"][n],n))
    selected_case=next(c for c,_,_ in evaluation if c.name==selected)
    verify_store(reader)
    selection={"family":"memory","selected":selected,"actual_fastest_on_this_run":actual,"verified_before_emission":True,"selected_function_cid":selected_case.function.cid.hex(),"semantic_root_unchanged_by_calibration":reader.root_cid.hex()}
    evidence={
        "schema":"xax-oi17-cost-model-evidence-v1","status":"open","model_version":MODEL_VERSION,
        "target":{"cid":target.cid.hex(),"architecture":"x86-64 Win64 emitted code executed via explicit ms_abi on host"},
        "microarchitecture":raw["host"],"calibration_identity":cal_id,
        "semantic_equivalence":checks,"candidate_count":len(evaluation),"calibration_function_count":len(compiled)-len(evaluation),"family_count":len(families),
        "candidates":[{"name":c.name,"family":c.family,"function_cid":c.function.cid.hex(),"code_bytes":len(code),"features":c.features,"vectors":[list(v) for v in c.vectors],"outputs":out} for c,code,out in evaluation],
        "calibration_functions":[{"name":c.name,"function_cid":c.function.cid.hex(),"code_bytes":len(code)} for c,code,_ in compiled if c.family.startswith("_cal_")],
        "objectives":{"code_size":{"classification":"exact lowering result","pairs":size_pairs},"latency":{"classification":"measured estimate evidence, not guarantee","observed_ns":observations["latency"],"models":models["latency"]},"throughput":{"classification":"measured estimate evidence, not guarantee","observed_ns":observations["throughput"],"models":models["throughput"]}},
        "bounded_optimizer_choice":selection,
        "raw_measurement_sha256":raw_sha,
        "raw_measurement_file":RAW_OUT.name,
        "measurement_policy":{"warmup_iterations":raw["warmup_iterations"],"iterations_per_sample":raw["iterations_per_sample"],"sample_count":raw["samples"],"clock":raw["clock"],"pinned_cpu":raw["pinned_cpu"],"harness_overhead":"common mapped-function call ABI and loop overhead; batch clock overhead is outside per-call loop and not subtracted"},
        "nonsemantic_guards":{"calibration_not_in_semantic_store":True,"cost_change_may_change_build_policy_choice":True,"cost_change_cannot_change_function_cids":True,"timing_guarantee":None},
        "closure":{"closed":False,"remaining":["second materially different real microarchitecture","repeat objective/model evaluation there before choosing a default/fallback"]},
    }
    return evidence

def main():
    if "--measure" in sys.argv: measure(); return
    e=build(); EVIDENCE_OUT.write_text(json.dumps(e,indent=2,sort_keys=True)+"\n"); print(json.dumps(e,indent=2,sort_keys=True))
if __name__=="__main__": main()
