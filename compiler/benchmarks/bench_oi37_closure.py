"""OI-37 closure measurements (tooling-only evidence; no model is run).

1. Edit cost of switching ``chains`` from arena-index links to
   ``pointer_rebase`` links (ADR-092):
   * rewritten semantic objects (count, envelope bytes, hex-carrier tokens),
     the same carrier metric as OI-03;
   * the node-level delta of the one function graph: nodes removed and
     inserted, rendered compactly as ``[operation, operand refs, attributes]``
     with types elided (reconstructible from the operation), and its tokens.
     This rendering is a measurement view, not XAX source.
2. Verifier cost: ``verify_store`` wall time for both ``chains`` variants,
   and for straight-line graphs with K rebase+load pairs versus K checked
   loads (K = 1, 16, 256), as a per-operation slope.

Token counts are offline ``tiktoken`` counts.  Timings are medians of repeated
runs on this host and are host-dependent.
Run: PYTHONPATH=src:. python -m benchmarks.bench_oi37_closure
"""

from __future__ import annotations

import json
import statistics
import time
from collections import Counter
from pathlib import Path

from benchmarks.linux_chains import build_chains_program
from xax_compiler import (
    Kind,
    Operation,
    Permission,
    _decode_function_interface,
    _parse_graph,
    bits_type,
    heap_view_type,
    pointer_type,
    store_resolver,
    verify_store,
    x86_64_linux_exec_target,
)
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import linux_api

OUTPUT = Path(__file__).resolve().parent / "oi37_closure_evidence.json"
ENCODINGS = ("cl100k_base", "o200k_base")
REPEATS = 15
SCALES = (1, 16, 256)


def _median_seconds(action, repeats: int = REPEATS) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        action()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def _graph_nodes(program) -> list[tuple]:
    resolve = store_resolver(program.reader)
    graph_object, _parameters, _returns = _decode_function_interface(program.entry, resolve)
    graph = _parse_graph(graph_object, resolve)
    return [
        (Operation(node.operation).name, tuple(f"{ref.tag}.{ref.block}.{ref.index}.{ref.result}" for ref in node.operands), tuple(node.attributes))
        for block in graph.blocks for node in block.nodes
    ]


def edit_cost(tokenizers) -> dict:
    index, pointer = build_chains_program(links="index"), build_chains_program(links="pointer")
    old = {item.cid for item in index.reader.objects()}
    rewritten = [item for item in pointer.reader.objects() if item.cid not in old]
    # Operand refs shift with block numbering, so compare by operation and attributes:
    # what a model must emit is the removed and inserted operations.
    before, after = Counter((op, attrs) for op, _refs, attrs in _graph_nodes(index)), Counter((op, attrs) for op, _refs, attrs in _graph_nodes(pointer))
    removed, inserted = before - after, after - before
    delta = [["-", op, list(attrs), count] for (op, attrs), count in sorted(removed.items())] + [["+", op, list(attrs), count] for (op, attrs), count in sorted(inserted.items())]
    delta_text = json.dumps(delta, separators=(",", ":"))
    hex_text = "".join(item.envelope().hex() for item in rewritten)
    return {
        "rewritten_objects": len(rewritten),
        "rewritten_kinds": sorted(Counter(Kind(item.kind).name for item in rewritten).items()),
        "rewritten_bytes": sum(len(item.envelope()) for item in rewritten),
        "rewritten_hex_tokens": {name: len(encoder.encode(hex_text)) for name, encoder in tokenizers.items()},
        "node_delta": delta,
        "node_delta_operations": sum(row[3] for row in delta),
        "node_delta_tokens": {name: len(encoder.encode(delta_text)) for name, encoder in tokenizers.items()},
        "graph_nodes": {"index": len(_graph_nodes(index)), "pointer": len(_graph_nodes(pointer))},
    }


def _straight_line(count: int, rebase: bool):
    """``count`` independent reads from a zeroed 4 KiB heap view, by rebase+load or checked load."""
    api = linux_api()
    b32, b64, mem = api.b32, api.b64, api.memory_effect
    words = pointer_type(b64, Permission.READ_WRITE, 8, space=2)
    graph = GraphBuilder()
    graph.track(*api.types, words)
    block = graph.block(api.process_effect, api.filesystem_effect, mem)
    process, fs, memory = block.params
    raw, owner, memory = block.op(Operation.CALL_FOREIGN, (block.const(b64, 4096), memory), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
    view, token, memory = block.op(Operation.HEAP_VIEW, (raw, owner, memory), (words, heap_view_type(4096), mem), attributes=(4096, 8))
    base = block.op1(Operation.POINTER_ADDRESS, (view,), b64, attributes=(1,)) if rebase else None
    total = block.const(b64, 0)
    for index in range(count):
        offset = (index * 8) % 4096
        if rebase:
            node = block.op1(Operation.POINTER_REBASE, (view, block.op1(Operation.ADD_WRAP, (base, block.const(b64, offset)), b64)), words, attributes=(16,))
            value, memory = block.op(Operation.LOAD_BITS_LE, (node, memory), (b64, mem), attributes=(8, 8))
        else:
            value, memory = block.op(Operation.CHECKED_LOAD_BITS_LE, (view, block.const(b32, offset), memory), (b64, mem), attributes=(8, 1))
        total = block.op1(Operation.ADD_WRAP, (total, value), b64)
    _r, memory = block.op(Operation.CALL_FOREIGN, (view, token, memory), (b64, mem), entity=api.munmap_view(words, 4096))
    status = block.op1(Operation.INT_TRUNCATE, (total,), b32)
    process = block.op1(Operation.CALL_FOREIGN, (status, process), api.process_effect, entity=api.exit_group)
    block.ret(status, process, fs, memory)
    function = graph.function((api.process_effect, api.filesystem_effect, mem), (b32, api.process_effect, api.filesystem_effect, mem))
    return program_store(function, x86_64_linux_exec_target(), tuple(graph.objects.values()))


def verifier_cost() -> dict:
    chains = {links: build_chains_program(links=links).reader for links in ("index", "pointer")}
    scaling = {}
    for kind in ("checked_load", "rebase_load"):
        scaling[kind] = {str(count): round(_median_seconds(lambda reader=_straight_line(count, kind == "rebase_load"): verify_store(reader)) * 1e6, 1) for count in SCALES}
    slope = {kind: round((rows[str(SCALES[-1])] - rows[str(SCALES[0])]) / (SCALES[-1] - SCALES[0]), 2) for kind, rows in scaling.items()}
    return {
        "chains_verify_microseconds": {links: round(_median_seconds(lambda reader=reader: verify_store(reader)) * 1e6, 1) for links, reader in chains.items()},
        "straight_line_verify_microseconds": scaling,
        "microseconds_per_additional_read": slope,
        "repeats": REPEATS,
    }


def run() -> dict:
    import tiktoken

    tokenizers = {name: tiktoken.get_encoding(name) for name in ENCODINGS}
    return {
        "issue": "OI-37",
        "evidence_label": "MEASURED",
        "tokenizer": f"tiktoken {tiktoken.__version__}",
        "model_run": None,
        "edit": "chains links: arena index (checked loads) -> pointer_rebase (ADR-092)",
        "edit_cost": edit_cost(tokenizers),
        "verifier_cost": verifier_cost(),
    }


def main() -> None:
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
