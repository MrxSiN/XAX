"""OI-37 evidence workload: a chained hash table with arena + index links.

Exact behavior (identical to ``linux_filestat_c/chains.c``):

* insert 2^20 xorshift64 keys (seed 0x9E3779B97F4A7C15) into 2^16 buckets
  chosen by the key's top 16 bits; node ``i`` stores ``(key, next)`` and the
  bucket head becomes ``i + 1`` (0 terminates a chain);
* regenerate the same keys and walk each bucket chain until the key is found,
  counting ``found`` and visited nodes ``steps``;
* write ``"<found> <steps>\\n"`` in decimal, release all mappings, and exit
  explicitly with status 0.

The C twin links nodes with real pointers.  ADR-082 admits only
provenance-free pointers in memory, so XAX expresses the links as arena
indices with checked accesses; this workload measures what that costs (OI-37).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from xax_compiler import IntCompare, Operation, Permission, SemanticObject, StoreReader, heap_view_type, pointer_type, x86_64_linux_exec_target
from xax_graph_builder import GraphBuilder, program_store
from xax_linux import LinuxExecutable, compile_linux_executable, linux_api

from benchmarks.linux_graph_kit import Flow, Kit, emit_decimal_line
from benchmarks.linux_harness import build_arms, host_info, measure_arms, method_info, run_output

NODES = 1 << 20
BUCKETS = 1 << 16
SEED = 0x9E3779B97F4A7C15
NODE_BYTES = 16
HERE = Path(__file__).resolve().parent
C_SOURCE = HERE / "linux_filestat_c" / "chains.c"
INDEX_SOURCE = HERE / "linux_filestat_c" / "chains_index.c"
# Diagnostic C twins with XAX's representation (not baselines): they separate
# link-representation cost and bounds-check cost from XAX code generation.
DIAGNOSTICS = (("gcc-O2-index", ()), ("gcc-O2-index-checked", ("-DCHECKED",)))
EVIDENCE = HERE / "oi37_chains_evidence.json"


@dataclass(frozen=True)
class ChainsProgram:
    reader: StoreReader
    entry: SemanticObject
    target: SemanticObject
    block_count: int


def build_chains_program(nodes: int = NODES, buckets: int = BUCKETS) -> ChainsProgram:
    api = linux_api()
    kit = Kit()
    b32, b64 = kit.b32, kit.b64
    const, compare, binary = kit.const, kit.compare, kit.binary
    mem = api.memory_effect
    words = pointer_type(b64, Permission.READ_WRITE, 8, space=2)
    arena_bytes, bucket_bytes, out_bytes = nodes * NODE_BYTES, buckets * 8, 4096
    shift = 64 - (buckets.bit_length() - 1)
    graph = GraphBuilder()
    graph.track(*api.types, words, kit.b1)

    carried = ("proc", "fs", "arena_token", "arena_mem", "bucket_token", "bucket_mem", "out_token", "out_mem")
    types = {
        "proc": api.process_effect, "fs": api.filesystem_effect,
        "arena_token": heap_view_type(arena_bytes), "arena_mem": mem,
        "bucket_token": heap_view_type(bucket_bytes), "bucket_mem": mem,
        "out_token": heap_view_type(out_bytes), "out_mem": mem,
    }
    flow = Flow(graph, carried, types)

    def next_key(block, x):
        """xorshift64: x ^= x<<13; x ^= x>>7; x ^= x<<17 (shifts as exact mul/udiv by 2^k)."""
        x = binary(block, Operation.BIT_XOR, x, binary(block, Operation.MUL_WRAP, x, const(block, 1 << 13)))
        x = binary(block, Operation.BIT_XOR, x, binary(block, Operation.UDIV, x, const(block, 1 << 7)))
        return binary(block, Operation.BIT_XOR, x, binary(block, Operation.MUL_WRAP, x, const(block, 1 << 17)))

    def byte_offset(block, index, scale):
        return block.op1(Operation.INT_TRUNCATE, (binary(block, Operation.MUL_WRAP, index, const(block, scale)),), b32)

    # --- entry: three zero-filled mappings ---------------------------------------------
    entry = graph.block(api.process_effect, api.filesystem_effect, mem, mem, mem)
    process, fs, arena_mem, bucket_mem, out_mem = entry.params

    def mapping(memory, size, pointer_type_, alignment):
        raw, owner, memory = entry.op(Operation.CALL_FOREIGN, (const(entry, size), memory), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
        return entry.op(Operation.HEAP_VIEW, (raw, owner, memory), (pointer_type_, heap_view_type(size), mem), attributes=(size, alignment))

    arena, arena_token, arena_mem = mapping(arena_mem, arena_bytes, words, 8)
    table, bucket_token, bucket_mem = mapping(bucket_mem, bucket_bytes, words, 8)
    out, out_token, out_mem = mapping(out_mem, out_bytes, api.bytes_rw, 1)
    state = {
        "proc": process, "fs": fs, "arena_token": arena_token, "arena_mem": arena_mem,
        "bucket_token": bucket_token, "bucket_mem": bucket_mem, "out_token": out_token, "out_mem": out_mem,
    }

    # --- insert loop -------------------------------------------------------------------
    insert, insert_state = flow.block(("i", b64), ("x", b64))
    insert_body, body_state = flow.block(("i", b64), ("x", b64))
    lookup_start, start_state = flow.block()
    entry.br(insert, *flow.args(insert, {**state, "i": const(entry, 0), "x": const(entry, SEED)}))
    insert.cbr(
        compare(insert, IntCompare.ULT, insert_state["i"], const(insert, nodes)),
        insert_body, flow.args(insert_body, insert_state),
        lookup_start, flow.args(lookup_start, insert_state),
    )
    b = insert_body
    s = body_state
    key = next_key(b, s["x"])
    bucket = byte_offset(b, binary(b, Operation.UDIV, key, const(b, 1 << shift)), 8)
    head, bucket_mem = b.op(Operation.CHECKED_LOAD_BITS_LE, (table, bucket, s["bucket_mem"]), (b64, mem), attributes=(8, 1))
    node = byte_offset(b, s["i"], NODE_BYTES)
    arena_mem = b.op1(Operation.CHECKED_STORE_BITS_LE, (arena, node, key, s["arena_mem"]), mem, attributes=(8, 1))
    link = binary(b, Operation.ADD_WRAP, node, const(b, 8, b32), b32)
    arena_mem = b.op1(Operation.CHECKED_STORE_BITS_LE, (arena, link, head, arena_mem), mem, attributes=(8, 1))
    following = binary(b, Operation.ADD_WRAP, s["i"], const(b, 1))
    bucket_mem = b.op1(Operation.CHECKED_STORE_BITS_LE, (table, bucket, following, bucket_mem), mem, attributes=(8, 1))
    b.br(insert, *flow.args(insert, {**s, "arena_mem": arena_mem, "bucket_mem": bucket_mem, "i": following, "x": key}))

    # --- lookup loop ---------------------------------------------------------------------
    counters = (("j", b64), ("x", b64), ("found", b64), ("steps", b64))
    lookup, lookup_state = flow.block(*counters)
    lookup_body, lookup_body_state = flow.block(*counters)
    walk, walk_state = flow.block(*counters, ("cur", b64))
    step, step_state = flow.block(*counters, ("cur", b64))
    advance, advance_state = flow.block(*counters, ("node", b32))
    format_block, format_state = flow.block(("found", b64), ("steps", b64))
    zero = const(lookup_start, 0)
    lookup_start.br(lookup, *flow.args(lookup, {**start_state, "j": zero, "x": const(lookup_start, SEED), "found": zero, "steps": zero}))
    lookup.cbr(
        compare(lookup, IntCompare.ULT, lookup_state["j"], const(lookup, nodes)),
        lookup_body, flow.args(lookup_body, lookup_state),
        format_block, flow.args(format_block, lookup_state),
    )
    lb = lookup_body
    ls = lookup_body_state
    key = next_key(lb, ls["x"])
    bucket = byte_offset(lb, binary(lb, Operation.UDIV, key, const(lb, 1 << shift)), 8)
    head, bucket_mem = lb.op(Operation.CHECKED_LOAD_BITS_LE, (table, bucket, ls["bucket_mem"]), (b64, mem), attributes=(8, 1))
    following = binary(lb, Operation.ADD_WRAP, ls["j"], const(lb, 1))
    lb.br(walk, *flow.args(walk, {**ls, "bucket_mem": bucket_mem, "x": key, "j": following, "cur": head}))
    walk.cbr(
        compare(walk, IntCompare.NE, walk_state["cur"], const(walk, 0)),
        step, flow.args(step, walk_state),
        lookup, flow.args(lookup, walk_state),
    )
    st = step
    ss = step_state
    node = byte_offset(st, binary(st, Operation.SUB_WRAP, ss["cur"], const(st, 1)), NODE_BYTES)
    stored, arena_mem = st.op(Operation.CHECKED_LOAD_BITS_LE, (arena, node, ss["arena_mem"]), (b64, mem), attributes=(8, 1))
    steps = binary(st, Operation.ADD_WRAP, ss["steps"], const(st, 1))
    st.cbr(
        compare(st, IntCompare.EQ, stored, ss["x"]),
        lookup, flow.args(lookup, {**ss, "arena_mem": arena_mem, "steps": steps, "found": binary(st, Operation.ADD_WRAP, ss["found"], const(st, 1))}),
        advance, flow.args(advance, {**ss, "arena_mem": arena_mem, "steps": steps, "node": node}),
    )
    ad = advance
    ads = advance_state
    link = binary(ad, Operation.ADD_WRAP, ads["node"], const(ad, 8, b32), b32)
    successor, arena_mem = ad.op(Operation.CHECKED_LOAD_BITS_LE, (arena, link, ads["arena_mem"]), (b64, mem), attributes=(8, 1))
    ad.br(walk, *flow.args(walk, {**ads, "arena_mem": arena_mem, "cur": successor}))

    # --- output, release, explicit exit ---------------------------------------------------
    current, current_state = emit_decimal_line(kit, flow, format_block, format_state, ("found", "steps"), out, mem, "out_mem")
    text = current.op1(Operation.POINTER_CAST, (out,), api.bytes_read)
    _written, fs, out_mem = current.op(
        Operation.CALL_FOREIGN, (const(current, 1, b32), text, current.op1(Operation.INT_ZERO_EXTEND, (current_state["pos"],), b64), current_state["fs"], current_state["out_mem"]),
        (b64, api.filesystem_effect, mem), entity=api.write,
    )
    cs = current_state
    _r, arena_mem = current.op(Operation.CALL_FOREIGN, (arena, cs["arena_token"], cs["arena_mem"]), (b64, mem), entity=api.munmap_view(words, arena_bytes))
    _r, bucket_mem = current.op(Operation.CALL_FOREIGN, (table, cs["bucket_token"], cs["bucket_mem"]), (b64, mem), entity=api.munmap_view(words, bucket_bytes))
    _r, out_mem = current.op(Operation.CALL_FOREIGN, (out, cs["out_token"], out_mem), (b64, mem), entity=api.munmap_view(api.bytes_rw, out_bytes))
    status = const(current, 0, b32)
    process = current.op1(Operation.CALL_FOREIGN, (status, cs["proc"]), api.process_effect, entity=api.exit_group)
    current.ret(status, process, fs, arena_mem, bucket_mem, out_mem)

    function = graph.function((api.process_effect, api.filesystem_effect, mem, mem, mem), (b32, api.process_effect, api.filesystem_effect, mem, mem, mem))
    target = x86_64_linux_exec_target()
    reader = program_store(function, target, tuple(graph.objects.values()))
    return ChainsProgram(reader, function, target, len(graph.blocks))


def reference_chains(nodes: int = NODES, buckets: int = BUCKETS) -> bytes:
    """Independent statement of the output contract (pointer-free Python model)."""
    mask = (1 << 64) - 1
    shift = 64 - (buckets.bit_length() - 1)

    def next_key(x: int) -> int:
        x ^= (x << 13) & mask
        x ^= x >> 7
        return x ^ ((x << 17) & mask)

    heads = [0] * buckets
    keys, links = [0] * nodes, [0] * nodes
    x = SEED
    for index in range(nodes):
        x = next_key(x)
        keys[index], links[index] = x, heads[x >> shift]
        heads[x >> shift] = index + 1
    found = steps = 0
    x = SEED
    for _ in range(nodes):
        x = next_key(x)
        current = heads[x >> shift]
        while current:
            steps += 1
            if keys[current - 1] == x:
                found += 1
                break
            current = links[current - 1]
    return f"{found} {steps}\n".encode()


def compile_chains(nodes: int = NODES, buckets: int = BUCKETS) -> tuple[ChainsProgram, LinuxExecutable]:
    program = build_chains_program(nodes, buckets)
    return program, compile_linux_executable(program.reader, program.entry.cid, program.target.cid)


def run_benchmark(repetitions: int, warmup: int) -> dict:
    program, executable = compile_chains()
    expected = reference_chains()
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        artifacts, stripped = build_arms(work, "chains", executable.data, C_SOURCE)

        def validate(arm: str, path: Path) -> bytes:
            output, status = run_output(path, work)
            if (output, status) != (expected, 0):
                raise AssertionError(f"{arm}: {output!r} status {status}")
            return output

        results, output, reference_rss = measure_arms(work, artifacts, stripped, repetitions, warmup, validate)
        diagnostic_artifacts = {"gcc-O2": artifacts["gcc-O2"]}
        for arm, flags in DIAGNOSTICS:
            subprocess.run(["gcc", "-O2", *flags, "-o", str(work / arm), str(INDEX_SOURCE)], check=True)
            diagnostic_artifacts[arm] = work / arm
        diagnostics, _output, _rss = measure_arms(
            work, diagnostic_artifacts, {arm: path.stat().st_size for arm, path in diagnostic_artifacts.items()}, repetitions, warmup, validate,
        )
        diagnostics.pop("gcc-O2")
    xax_time = results["xax"]["wall_seconds_median"]
    attribution = {
        "index_vs_pointer": round(diagnostics["gcc-O2-index"]["wall_seconds_median"] / results["gcc-O2"]["wall_seconds_median"], 3),
        "checked_vs_unchecked_index": round(diagnostics["gcc-O2-index-checked"]["wall_seconds_median"] / diagnostics["gcc-O2-index"]["wall_seconds_median"], 3),
        "xax_vs_checked_index_c": round(xax_time / diagnostics["gcc-O2-index-checked"]["wall_seconds_median"], 3),
    }
    return {
        "format": "xax-oi37-chains-evidence-v1",
        "evidence_label": "MEASURED",
        "workload": f"chained hash table: {NODES} xorshift64 inserts into {BUCKETS} buckets, then {NODES} successful lookups walking chains; XAX links are arena indices with checked access, C links are pointers",
        "output": output.decode(),
        "xax": {
            "program_root": program.reader.root_cid.hex(),
            "entry_function": program.entry.cid.hex(),
            "target": program.target.cid.hex(),
            "graph_blocks": program.block_count,
            "artifact_sha256": hashlib.sha256(executable.data).hexdigest(),
            "artifact_bytes": len(executable.data),
            "link_representation": "b64 arena index + 1 (0 = end); byte offset = (index - 1) * 16, checked against the view extent",
            "runtime_dependencies": [],
        },
        "results": results,
        "diagnostics": diagnostics,
        "attribution": attribution,
        "attribution_note": "all ratios are medians from the same run: representation = C index/C pointer; checks = checked/unchecked C index; codegen = XAX/checked C index (same representation and checks)",
        "host": host_info(),
        "method": method_info(warmup, repetitions, reference_rss),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=31)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--write", action="store_true", help="update the committed evidence JSON")
    arguments = parser.parse_args(argv)
    evidence = run_benchmark(arguments.repetitions, arguments.warmup)
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if arguments.write:
        EVIDENCE.write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
