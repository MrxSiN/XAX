"""OI-26 measurement-only bootstrap seed minimization experiment.

The committed M14 seed remains the historical baseline.  Candidate archives are
built deterministically from that frozen seed snapshot.  The selected candidate
removes only statically unreachable top-level implementation units and keeps the
existing verifier/evaluator/serializer semantics; an additional more aggressive
candidate measures the cost of replacing the generic evaluator with seed-specific
execution logic.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile

from blake3 import blake3
from xax_compiler import Block, Kind, Node, Operation, StoreReader, Terminator, TerminatorKind, ValueRef, _parse_graph, bits_type, function, graph_fragment, object_with_refs, write_store

HERE = Path(__file__).resolve().parent
COMPILER = HERE.parent
BOOTSTRAP = COMPILER / "bootstrap"
BASELINE_SEED = BOOTSTRAP / "m14_seed_runtime.pyz"
M14_PROGRAM = BOOTSTRAP / "m14_selfhost_compiler.xax"
M11_PROGRAM = BOOTSTRAP / "m11_compiler_subset.xax"
M11_BUNDLE = BOOTSTRAP / "m11_bootstrap_bundle.xax"
EVIDENCE = HERE / "oi26_seed_minimization_evidence.json"
TIMING = HERE / "oi26_seed_minimization_timing.json"
REACHABILITY = BOOTSTRAP / "oi26_seed_reachability.json"

VARIANT_PATHS = {
    "entry_pruned": BOOTSTRAP / "m14_seed_entry_pruned.pyz",
    "reachable_pruned": BOOTSTRAP / "m14_seed_reachable.pyz",
    "specialized_subset": BOOTSTRAP / "m14_seed_specialized.pyz",
}

SHEBANG = b"#!/usr/bin/env python3\n"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
ALLOWED_KIND_NAMES = ("TYPE", "GRAPH_FRAGMENT", "FUNCTION", "MODULE", "PROGRAM_ROOT")
ALLOWED_OPERATION_NAMES = (
    "ADD_WRAP",
    "MUL_WRAP",
    "CALL_DIRECT",
    "META_CANONICAL_STORE",
    "META_VERIFY_SEMANTICS",
    "META_MATERIALIZE_PROGRAM",
)
ALLOWED_TERMINATOR_NAMES = ("RETURN", "CONDITIONAL_BRANCH")
M11_VECTORS = (
    (0, 0, 0),
    (0, 1, 2),
    (0, 0xFFFFFFFF, 2),
    (1, 3, 4),
    (1, 0xFFFFFFFF, 2),
    (1, 0x80000000, 2),
)

GENERIC_MAIN = r'''from pathlib import Path
import json
import sys
from xax_compiler import CompileTimeBudget,CompileTimeEvaluator,Kind,MetaCapability,Operation,StoreReader,_parse_graph,verify_store
ALLOWED_KINDS=frozenset((Kind.TYPE,Kind.GRAPH_FRAGMENT,Kind.FUNCTION,Kind.MODULE,Kind.PROGRAM_ROOT))
ALLOWED_OPS=frozenset((Operation.ADD_WRAP,Operation.MUL_WRAP,Operation.CALL_DIRECT,Operation.META_CANONICAL_STORE,Operation.META_VERIFY_SEMANTICS,Operation.META_MATERIALIZE_PROGRAM))

def gate(r):
    objects=tuple(r.objects())
    for o in objects:
        if o.kind not in ALLOWED_KINDS:
            raise ValueError("XAX.SEED.UNSUPPORTED_KIND:"+o.kind.name)
    verify_store(r)
    for o in objects:
        if o.kind==Kind.GRAPH_FRAGMENT:
            g=_parse_graph(o,r.get)
            for b in g.blocks:
                for n in b.nodes:
                    op=Operation(n.operation)
                    if op not in ALLOWED_OPS:
                        raise ValueError("XAX.SEED.UNSUPPORTED_OP:"+op.name)

def locate(r):
    root=r.get(r.root_cid)
    if root.kind!=Kind.PROGRAM_ROOT:
        raise ValueError("XAX.SEED.ROOT_KIND")
    ms=tuple(r.get(c) for c in root.references if r.get(c).kind==Kind.MODULE)
    if len(ms)!=1:
        raise ValueError("XAX.SEED.MODULE_COUNT")
    fs=tuple(r.get(c) for c in ms[0].references if r.get(c).kind==Kind.FUNCTION)
    if len(fs)!=1:
        raise ValueError("XAX.SEED.FUNCTION_COUNT")
    return fs[0]

def evaluator():
    return CompileTimeEvaluator()

def eval_function(r,e,args,caps=()):
    return evaluator().evaluate(r,e.cid,args,capabilities=caps,budget=CompileTimeBudget(steps=1<<20,call_depth=64,memory_bytes=64<<20,semantic_objects=1<<16,graph_nodes=1<<20),evaluator_identity=b"xax-m14-meta-evaluator-v1",verifier_identity=b"xax-verifier-v1").values

def main():
    if len(sys.argv)<3:
        raise SystemExit("usage")
    command=sys.argv[1]
    source=Path(sys.argv[2]).read_bytes()
    r=StoreReader(source); gate(r); e=locate(r)
    if command=="rebuild":
        if len(sys.argv)!=4: raise SystemExit("usage")
        values=eval_function(r,e,(e,),(MetaCapability.CONSTRUCT_SEMANTICS,MetaCapability.SERIALIZE_SEMANTICS,MetaCapability.VERIFY_SEMANTICS))
        if len(values)!=1 or not isinstance(values[0],bytes): raise ValueError("XAX.SEED.RESULT")
        Path(sys.argv[3]).write_bytes(values[0]); return 0
    if command=="eval-m11":
        raw=sys.argv[3:]
        if not raw or len(raw)%3: raise SystemExit("usage")
        results=[]
        for off in range(0,len(raw),3):
            args=tuple(int(x,0) for x in raw[off:off+3]); results.append(list(eval_function(r,e,args)))
        print(json.dumps({"results":results},sort_keys=True)); return 0
    raise SystemExit("unknown command")
if __name__=="__main__": raise SystemExit(main())
'''

SPECIALIZED_MAIN = r'''from pathlib import Path
import json
import sys
from xax_compiler import Kind,Operation,StoreReader,TerminatorKind,_decode_function_interface,_parse_graph,decode_bits_width,object_with_refs,verify_object,verify_store,write_store
ALLOWED_KINDS=frozenset((Kind.TYPE,Kind.GRAPH_FRAGMENT,Kind.FUNCTION,Kind.MODULE,Kind.PROGRAM_ROOT))
ALLOWED_OPS=frozenset((Operation.ADD_WRAP,Operation.MUL_WRAP,Operation.CALL_DIRECT,Operation.META_CANONICAL_STORE,Operation.META_VERIFY_SEMANTICS,Operation.META_MATERIALIZE_PROGRAM))

def gate(r):
    objects=tuple(r.objects())
    for o in objects:
        if o.kind not in ALLOWED_KINDS:
            raise ValueError("XAX.SEED.UNSUPPORTED_KIND:"+o.kind.name)
    verify_store(r)
    for o in objects:
        if o.kind==Kind.GRAPH_FRAGMENT:
            g=_parse_graph(o,r.get)
            for b in g.blocks:
                for n in b.nodes:
                    op=Operation(n.operation)
                    if op not in ALLOWED_OPS:
                        raise ValueError("XAX.SEED.UNSUPPORTED_OP:"+op.name)

def locate(r):
    root=r.get(r.root_cid)
    if root.kind!=Kind.PROGRAM_ROOT: raise ValueError("XAX.SEED.ROOT_KIND")
    ms=tuple(r.get(c) for c in root.references if r.get(c).kind==Kind.MODULE)
    if len(ms)!=1: raise ValueError("XAX.SEED.MODULE_COUNT")
    fs=tuple(r.get(c) for c in ms[0].references if r.get(c).kind==Kind.FUNCTION)
    if len(fs)!=1: raise ValueError("XAX.SEED.FUNCTION_COUNT")
    return fs[0]

def reach(root,resolve):
    out={}; pending=[root.cid]
    while pending:
        cid=pending.pop()
        if cid in out: continue
        item=resolve(cid); out[cid]=item; pending.extend(item.references)
    return out

def evaluate(fn,args,objects):
    def resolve(cid): return objects[cid]
    graph,params,returns=_decode_function_interface(fn,resolve); parsed=_parse_graph(graph,resolve)
    if len(args)!=len(params): raise ValueError("XAX.SEED.ARG_COUNT")
    values={}; block_index=parsed.entry; block_args=tuple(args)
    def read(v): return values[(v.tag,v.block,v.index,v.result)]
    while True:
        block=parsed.blocks[block_index]
        for i,v in enumerate(block_args): values[(0,block_index,i,0)]=v
        for ni,node in enumerate(block.nodes):
            op=Operation(node.operation); operands=tuple(read(v) for v in node.operands)
            if op in (Operation.ADD_WRAP,Operation.MUL_WRAP):
                width=decode_bits_width(resolve(node.results[0])); mask=(1<<width)-1
                result=(operands[0]+operands[1] if op==Operation.ADD_WRAP else operands[0]*operands[1])&mask; results=(result,)
            elif op==Operation.CALL_DIRECT:
                results=evaluate(node.entity,operands,objects)
            elif op==Operation.META_MATERIALIZE_PROGRAM:
                module=object_with_refs(Kind.MODULE,(operands[0],)); root=object_with_refs(Kind.PROGRAM_ROOT,(module,)); objects[module.cid]=module; objects[root.cid]=root; results=(root,)
            elif op==Operation.META_VERIFY_SEMANTICS:
                reached=reach(operands[0],resolve)
                for item in reached.values(): verify_object(item,resolve)
                results=(1,)
            elif op==Operation.META_CANONICAL_STORE:
                reached=reach(operands[0],resolve); results=(write_store(operands[0].cid,reached.values()),)
            else: raise ValueError("XAX.SEED.UNSUPPORTED_OP:"+op.name)
            for ri,v in enumerate(results): values[(1,block_index,ni,ri)]=v
        term=block.terminator
        if term.kind==TerminatorKind.RETURN: return tuple(read(v) for v in term.values)
        if term.kind!=TerminatorKind.CONDITIONAL_BRANCH: raise ValueError("XAX.SEED.UNSUPPORTED_CONTROL")
        edge=term.edges[0 if read(term.values[0]) else 1]; block_index=edge[0]; block_args=tuple(read(v) for v in edge[1])

def main():
    if len(sys.argv)<3: raise SystemExit("usage")
    command=sys.argv[1]; source=Path(sys.argv[2]).read_bytes(); r=StoreReader(source); gate(r); entry=locate(r); objects={o.cid:o for o in r.objects()}
    if command=="rebuild":
        if len(sys.argv)!=4: raise SystemExit("usage")
        values=evaluate(entry,(entry,),objects)
        if len(values)!=1 or not isinstance(values[0],bytes): raise ValueError("XAX.SEED.RESULT")
        Path(sys.argv[3]).write_bytes(values[0]); return 0
    if command=="eval-m11":
        raw=sys.argv[3:]
        if not raw or len(raw)%3: raise SystemExit("usage")
        results=[]
        for off in range(0,len(raw),3):
            args=tuple(int(x,0) for x in raw[off:off+3]); results.append(list(evaluate(entry,args,dict(objects))))
        print(json.dumps({"results":results},sort_keys=True)); return 0
    raise SystemExit("unknown command")
if __name__=="__main__": raise SystemExit(main())
'''


def _seed_entries() -> dict[str, bytes]:
    with zipfile.ZipFile(BASELINE_SEED, "r") as archive:
        return {info.filename: archive.read(info.filename) for info in archive.infolist()}


def _defined_names(statement: ast.stmt) -> tuple[str, ...]:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return (statement.name,)
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return tuple(alias.asname or (alias.name.split(".")[0] if isinstance(statement, ast.Import) else alias.name) for alias in statement.names)
    targets = statement.targets if isinstance(statement, ast.Assign) else (statement.target,) if isinstance(statement, ast.AnnAssign) else ()
    return tuple(target.id for target in targets if isinstance(target, ast.Name))


def _static_slice(source: bytes, roots: frozenset[str]) -> tuple[bytes, tuple[str, ...], int]:
    text = source.decode("utf-8")
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    entries: list[tuple[ast.stmt, tuple[str, ...]]] = []
    definitions: dict[str, list[int]] = {}
    for index, statement in enumerate(tree.body):
        names = _defined_names(statement)
        entries.append((statement, names))
        for name in names:
            definitions.setdefault(name, []).append(index)
    keep = {
        index
        for index, (statement, _names) in enumerate(entries)
        if isinstance(statement, ast.ImportFrom) and statement.module == "__future__"
    }
    needed = set(roots)
    while True:
        before = (len(keep), len(needed))
        for name in tuple(needed):
            for index in definitions.get(name, ()):
                if index in keep:
                    continue
                keep.add(index)
                for item in ast.walk(entries[index][0]):
                    if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load):
                        needed.add(item.id)
        if before == (len(keep), len(needed)):
            break
    chunks: list[str] = []
    selected_names: set[str] = set()
    for index, (statement, names) in enumerate(entries):
        if index not in keep:
            continue
        start = min([statement.lineno, *(item.lineno for item in getattr(statement, "decorator_list", ()))])
        chunks.append("".join(lines[start - 1 : statement.end_lineno]).rstrip() + "\n")
        selected_names.update(names)
    output = "\n".join(chunks).encode("utf-8")
    compile(output, "xax_compiler.py", "exec")
    return output, tuple(sorted(selected_names)), len(keep)


def _deterministic_pyz(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    buffer.write(SHEBANG)
    with zipfile.ZipFile(buffer, "a", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in ("__main__.py", "blake3.py", "xax_compiler.py"):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, entries[name])
    return buffer.getvalue()


def build_variants() -> tuple[dict[str, bytes], dict[str, dict]]:
    baseline = _seed_entries()
    compiler_source = baseline["xax_compiler.py"]
    generic_roots = frozenset(
        {
            "CompileTimeBudget",
            "CompileTimeEvaluator",
            "Kind",
            "MetaCapability",
            "Operation",
            "StoreReader",
            "_parse_graph",
            "verify_store",
        }
    )
    specialized_roots = frozenset(
        {
            "Kind",
            "Operation",
            "StoreReader",
            "TerminatorKind",
            "_decode_function_interface",
            "_parse_graph",
            "decode_bits_width",
            "object_with_refs",
            "verify_object",
            "verify_store",
            "write_store",
        }
    )
    sliced_generic, generic_names, generic_statements = _static_slice(compiler_source, generic_roots)
    sliced_specialized, specialized_names, specialized_statements = _static_slice(compiler_source, specialized_roots)
    variants = {
        "entry_pruned": _deterministic_pyz({"__main__.py": GENERIC_MAIN.encode(), "blake3.py": baseline["blake3.py"], "xax_compiler.py": compiler_source}),
        "reachable_pruned": _deterministic_pyz({"__main__.py": GENERIC_MAIN.encode(), "blake3.py": baseline["blake3.py"], "xax_compiler.py": sliced_generic}),
        "specialized_subset": _deterministic_pyz({"__main__.py": SPECIALIZED_MAIN.encode(), "blake3.py": baseline["blake3.py"], "xax_compiler.py": sliced_specialized}),
    }
    meta = {
        "entry_pruned": {"compiler_source_bytes": len(compiler_source), "compiler_source_lines": compiler_source.count(b"\n"), "selected_top_level_statements": None, "selected_top_level_names": None, "seed_specific_evaluator_lines": 0},
        "reachable_pruned": {"compiler_source_bytes": len(sliced_generic), "compiler_source_lines": sliced_generic.count(b"\n"), "selected_top_level_statements": generic_statements, "selected_top_level_names": generic_names, "seed_specific_evaluator_lines": 0},
        "specialized_subset": {"compiler_source_bytes": len(sliced_specialized), "compiler_source_lines": sliced_specialized.count(b"\n"), "selected_top_level_statements": specialized_statements, "selected_top_level_names": specialized_names, "seed_specific_evaluator_lines": _function_lines(SPECIALIZED_MAIN, "evaluate")},
    }
    return variants, meta


def _function_lines(source: str, name: str) -> int:
    tree = ast.parse(source)
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef) and statement.name == name:
            return statement.end_lineno - statement.lineno + 1
    raise KeyError(name)


def _features(path: Path) -> dict:
    reader = StoreReader(path.read_bytes())
    kinds: dict[str, int] = {}
    operations: dict[str, int] = {}
    terminators: dict[str, int] = {}
    for obj in reader.objects():
        kinds[obj.kind.name] = kinds.get(obj.kind.name, 0) + 1
        if obj.kind == Kind.GRAPH_FRAGMENT:
            graph = _parse_graph(obj, reader.get)
            for block in graph.blocks:
                terminators[TerminatorKind(block.terminator.kind).name] = terminators.get(TerminatorKind(block.terminator.kind).name, 0) + 1
                for node in block.nodes:
                    name = Operation(node.operation).name
                    operations[name] = operations.get(name, 0) + 1
    return {"root": reader.root_cid.hex(), "bytes": len(reader.data), "objects": sum(kinds.values()), "object_kinds": kinds, "operations": operations, "terminators": terminators}


def _run_archive(seed_data: bytes, command: str, source: bytes, extra: tuple[str, ...] = (), *, measure: bool = False) -> dict:
    with tempfile.TemporaryDirectory(prefix="xax-oi26-run-") as directory:
        root = Path(directory)
        seed = root / "seed.pyz"
        input_path = root / "input.xax"
        output_path = root / "output.xax"
        seed.write_bytes(seed_data)
        input_path.write_bytes(source)
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        cmd = [sys.executable, str(seed), command, str(input_path)]
        if command == "rebuild":
            cmd.append(str(output_path))
        else:
            cmd.extend(extra)
        rss_kb = None
        actual = cmd
        time_bin = shutil.which("time")
        if measure and time_bin and Path(time_bin).name == "time":
            actual = [time_bin, "-f", "XAX_OI26_RSS_KB=%M", *cmd]
        start = time.perf_counter_ns()
        completed = subprocess.run(actual, cwd=root, env=environment, check=False, capture_output=True, text=True)
        elapsed = time.perf_counter_ns() - start
        stderr_lines = completed.stderr.splitlines()
        if measure and stderr_lines and stderr_lines[-1].startswith("XAX_OI26_RSS_KB="):
            try:
                rss_kb = int(stderr_lines[-1].split("=", 1)[1])
                stderr_lines = stderr_lines[:-1]
            except ValueError:
                pass
        output = output_path.read_bytes() if output_path.exists() else b""
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": "\n".join(stderr_lines).strip(),
            "wall_ns": elapsed,
            "peak_rss_kb": rss_kb,
            "output": output,
        }




def _unsupported_operation_program() -> bytes:
    b32 = bits_type(32)
    graph = graph_fragment((Block((b32, b32), (Node(Operation.SUB_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b32,)),), Terminator.return_((ValueRef.node_result(0, 0),))),))
    entry = function(graph, (b32, b32), (b32,))
    module = object_with_refs(Kind.MODULE, (entry,))
    root = object_with_refs(Kind.PROGRAM_ROOT, (module,))
    return write_store(root.cid, (b32, graph, entry, module, root))

def _m11_expected(vector: tuple[int, int, int]) -> int:
    selector, lhs, rhs = vector
    return ((lhs * rhs) if selector else (lhs + rhs)) & 0xFFFFFFFF


def validate_candidate(seed_data: bytes) -> dict:
    program14 = M14_PROGRAM.read_bytes()
    first = _run_archive(seed_data, "rebuild", program14)
    second = _run_archive(seed_data, "rebuild", first["output"]) if first["returncode"] == 0 else {"returncode": -1, "output": b"", "stderr": "first rebuild failed"}
    flat = tuple(str(value) for vector in M11_VECTORS for value in vector)
    suite = _run_archive(seed_data, "eval-m11", M11_PROGRAM.read_bytes(), flat)
    parsed = json.loads(suite["stdout"]) if suite["returncode"] == 0 else {}
    suite_results = parsed.get("results", [])
    vectors = []
    for index, vector in enumerate(M11_VECTORS):
        actual = suite_results[index][0] if index < len(suite_results) and suite_results[index] else None
        vectors.append({"arguments": list(vector), "expected": _m11_expected(vector), "actual": actual, "matches": actual == _m11_expected(vector)})
    unsupported_kind = _run_archive(seed_data, "rebuild", M11_BUNDLE.read_bytes())
    unsupported_op = _run_archive(seed_data, "eval-m11", _unsupported_operation_program(), ("1", "2", "3"))
    corrupted = bytearray(program14); corrupted[len(corrupted)//2] ^= 1
    corruption = _run_archive(seed_data, "rebuild", bytes(corrupted))
    return {
        "m14_first_rebuild": first["returncode"] == 0 and first["output"] == program14,
        "m14_second_rebuild": second["returncode"] == 0 and second["output"] == program14,
        "m11_vectors": vectors,
        "m11_all_match": all(item["matches"] for item in vectors),
        "unsupported_build_bundle_rejected": unsupported_kind["returncode"] != 0,
        "unsupported_build_bundle_diagnostic": unsupported_kind["stderr"].splitlines()[-1] if unsupported_kind["stderr"] else "",
        "unsupported_operation_rejected": unsupported_op["returncode"] != 0,
        "unsupported_operation_diagnostic": unsupported_op["stderr"].splitlines()[-1] if unsupported_op["stderr"] else "",
        "corrupt_store_rejected": corruption["returncode"] != 0,
        "corrupt_output_bytes": len(corruption["output"]),
    }


def _timing(seed_data: bytes, samples: int = 2) -> dict:
    wall: list[int] = []
    rss: list[int] = []
    program = M14_PROGRAM.read_bytes()
    for _ in range(samples):
        result = _run_archive(seed_data, "rebuild", program, measure=True)
        if result["returncode"] != 0 or result["output"] != program:
            raise RuntimeError(result["stderr"] or "seed timing run failed")
        wall.append(result["wall_ns"])
        if result["peak_rss_kb"] is not None:
            rss.append(result["peak_rss_kb"])
    ordered = sorted(wall)
    return {
        "samples": samples,
        "wall_ns": ordered,
        "median_wall_ns": int(statistics.median(ordered)),
        "min_wall_ns": ordered[0],
        "max_wall_ns": ordered[-1],
        "peak_rss_kb": sorted(rss),
        "median_peak_rss_kb": int(statistics.median(rss)) if rss else None,
    }


def _reachability_report(meta: dict[str, dict]) -> dict:
    m11 = _features(M11_PROGRAM)
    m11_bundle = _features(M11_BUNDLE)
    m14 = _features(M14_PROGRAM)
    baseline_entries = _seed_entries()
    return {
        "format": "xax-oi26-seed-reachability-v1",
        "approved_entrypoints": {
            "m11_b0_b1_component": "load canonical m11_compiler_subset.xax; verify; evaluate six arithmetic vectors",
            "m14_semantic_image": "load canonical m14_selfhost_compiler.xax; verify; execute materialize->verify->canonical-store call graph",
        },
        "semantic_features": {
            "accepted_object_kinds": list(ALLOWED_KIND_NAMES),
            "accepted_operations": list(ALLOWED_OPERATION_NAMES),
            "accepted_terminators": list(ALLOWED_TERMINATOR_NAMES),
            "m11_program": m11,
            "m11_build_snapshot_inventory_only": m11_bundle,
            "m14_program": m14,
        },
        "implementation_dependencies": {
            "hash": {"module": "blake3.py", "bundled_source_bytes": len(baseline_entries["blake3.py"]), "suite": "BLAKE3-256/suite-1"},
            "verifier": ["verify_store", "verify_object", "CID/reference/root reachability", "type/graph/function checks for accepted objects"],
            "serializer": ["write_store", "canonical object/index/trailer encoding"],
            "evaluator": ["CompileTimeEvaluator", "wrapping add/mul", "conditional branch", "direct call", "M14 materialize/verify/canonical-store META ops"],
            "external_runtime": {"python": platform.python_version(), "bundled_in_seed_bytes": False, "external_blake3_package": False},
        },
        "static_reachable_seed_compiler": {
            "selected_candidate": "reachable_pruned",
            "top_level_statement_count": meta["reachable_pruned"]["selected_top_level_statements"],
            "top_level_names": list(meta["reachable_pruned"]["selected_top_level_names"] or ()),
        },
    }


def build_evidence(measure: bool = True) -> tuple[dict, dict, dict[str, bytes], dict]:
    variants, meta = build_variants()
    baseline = BASELINE_SEED.read_bytes()
    all_seeds = {"baseline": baseline, **variants}
    validations = {name: validate_candidate(data) for name, data in variants.items()}
    for name, result in validations.items():
        if not (result["m14_first_rebuild"] and result["m14_second_rebuild"] and result["m11_all_match"] and result["unsupported_build_bundle_rejected"] and result["unsupported_operation_rejected"] and result["corrupt_store_rejected"]):
            raise AssertionError(f"candidate validation failed: {name}: {result}")
    timing = {"host": {"platform": platform.platform(), "python": platform.python_version(), "logical_cpus": os.cpu_count()}, "samples": {}}
    if measure:
        for name, data in all_seeds.items():
            timing["samples"][name] = _timing(data)
    elif TIMING.exists():
        timing = json.loads(TIMING.read_text(encoding="utf-8"))
    reachability = _reachability_report(meta)
    baseline_entries = _seed_entries()
    records = []
    for name, data in all_seeds.items():
        if name == "baseline":
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                source_bytes = sum(info.file_size for info in archive.infolist())
                source_lines = sum(archive.read(info.filename).count(b"\n") for info in archive.infolist() if info.filename.endswith(".py"))
            record_meta = {"compiler_source_bytes": len(baseline_entries["xax_compiler.py"]), "compiler_source_lines": baseline_entries["xax_compiler.py"].count(b"\n"), "selected_top_level_statements": None, "seed_specific_evaluator_lines": 0}
        else:
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                source_bytes = sum(info.file_size for info in archive.infolist())
                source_lines = sum(archive.read(info.filename).count(b"\n") for info in archive.infolist() if info.filename.endswith(".py"))
            record_meta = meta[name]
        records.append({
            "name": name,
            "seed_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "blake3_256": blake3(data).hexdigest(),
            "uncompressed_source_bytes": source_bytes,
            "uncompressed_source_lines": source_lines,
            "compiler_source_bytes": record_meta["compiler_source_bytes"],
            "compiler_source_lines": record_meta["compiler_source_lines"],
            "selected_top_level_statements": record_meta["selected_top_level_statements"],
            "seed_specific_evaluator_lines": record_meta["seed_specific_evaluator_lines"],
            "relative_seed_bytes": round(len(data) / len(baseline), 6),
            "validation": None if name == "baseline" else validations[name],
            "timing": timing["samples"].get(name),
        })
    evidence = {
        "issue": "OI-26",
        "status": "closed",
        "selection": {
            "candidate": "reachable_pruned",
            "rule": "retain the existing generic verifier/evaluator/serializer after static top-level reachability pruning; do not replace them with seed-specific semantic execution solely to save additional archive bytes",
            "reason": "the specialized subset saves additional bytes but adds a new seed-specific evaluator correctness surface; reachable pruning removes unused implementation without adding a second semantic execution path",
        },
        "baseline": {"seed": str(BASELINE_SEED.relative_to(COMPILER.parent)), "bytes": len(baseline), "sha256": hashlib.sha256(baseline).hexdigest()},
        "candidates": records,
        "accepted_subset": {
            "object_kinds": list(ALLOWED_KIND_NAMES),
            "operations": list(ALLOWED_OPERATION_NAMES),
            "terminators": list(ALLOWED_TERMINATOR_NAMES),
            "m11_vectors": len(M11_VECTORS),
            "m14_transition_steps_to_hosted_compiler": 1,
        },
        "dependencies": {
            "suite1_hash_source": "bundled in-tree pure-Python blake3.py",
            "suite1_hash_source_bytes": len(baseline_entries["blake3.py"]),
            "external_blake3_package": False,
            "python_interpreter_required": True,
            "python_interpreter_version_measured": platform.python_version(),
            "python_interpreter_bytes_counted_in_seed": False,
            "repository_pythonpath_required": False,
        },
        "negative_behavior": {
            "excluded_build/package/target snapshot": "reject XAX.SEED.UNSUPPORTED_KIND",
            "excluded SUB_WRAP operation": "reject XAX.SEED.UNSUPPORTED_OP",
            "corrupt canonical store": "reject before output publication",
        },
        "host_observations_nonsemantic": timing["host"],
        "portable_full_suite_required": False,
    }
    return evidence, timing, variants, reachability


def write_artifacts(measure: bool = True) -> dict:
    evidence, timing, variants, reachability = build_evidence(measure)
    for name, data in variants.items():
        VARIANT_PATHS[name].write_bytes(data)
    REACHABILITY.write_text(json.dumps(reachability, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    TIMING.write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-timing", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    evidence, timing, variants, reachability = build_evidence(not args.no_timing)
    if args.write:
        for name, data in variants.items():
            VARIANT_PATHS[name].write_bytes(data)
        REACHABILITY.write_text(json.dumps(reachability, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        TIMING.write_text(json.dumps(timing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
