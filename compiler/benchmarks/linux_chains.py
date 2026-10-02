"""OI-37 evidence workload: a chained hash table with arena + index links.

Exact behavior (identical to ``linux_filestat_c/chains.c``):

* insert 2^20 xorshift64 keys (seed 0x9E3779B97F4A7C15) into 2^16 buckets
  chosen by the key's top 16 bits; node ``i`` stores ``(key, next)`` and the
  bucket head becomes ``i + 1`` (0 terminates a chain);
* regenerate the same keys and walk each bucket chain until the key is found,
  counting ``found`` and visited nodes ``steps``;
* write ``"<found> <steps>\\n"`` in decimal, release all mappings, and exit
  explicitly with status 0.

The C twin links nodes with real pointers.  XAX expresses the links two ways:

* ``links="index"``: arena indices with checked accesses (ADR-082), which
  measured the OI-37 cost (ADR-090);
* ``links="pointer"``: exposed node addresses (``pointer_address``) reloaded
  with ``pointer_rebase`` into the arena view (ADR-092); field reads through
  the rebased 16-byte node are statically in bounds;
* ``links="link"``: the arena is a record view of ``(key: bits<64>, next:
  link)`` and the bucket table a record view of ``(head: link)`` whose link
  target is the arena (ADR-097).  Links are therefore null or arena records,
  so ``link_follow`` needs no range check; each lookup does one checked
  rebase to its bucket and the walk is check-free.
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

from xax_compiler import (
    IntCompare, Operation, Permission, SemanticObject, StoreReader, heap_view_type, link_type, null_link, pointer_type, tuple_type,
    x86_64_linux_exec_target,
)
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
DIAGNOSTICS = (
    ("gcc-O2-index", INDEX_SOURCE, ()),
    ("gcc-O2-index-checked", INDEX_SOURCE, ("-DCHECKED",)),
    ("gcc-O2-pointer-checked", C_SOURCE, ("-DCHECKED",)),
)
EVIDENCE = HERE / "oi37_chains_evidence.json"


@dataclass(frozen=True)
class ChainsProgram:
    reader: StoreReader
    entry: SemanticObject
    target: SemanticObject
    block_count: int


LINKS = ("index", "pointer", "link")


def build_chains_program(nodes: int = NODES, buckets: int = BUCKETS, links: str = "index") -> ChainsProgram:
    if links not in LINKS:
        raise ValueError(f"links must be one of {LINKS}")
    pointer_links = links == "pointer"
    record_links = links == "link"
    api = linux_api()
    kit = Kit()
    b32, b64 = kit.b32, kit.b64
    const, compare, binary = kit.const, kit.compare, kit.binary
    mem = api.memory_effect
    words = pointer_type(b64, Permission.READ_WRITE, 8, space=2)
    link_t = link_type()
    record = tuple_type((b64, link_t))
    records = pointer_type(record, Permission.READ_WRITE, NODE_BYTES, space=2)
    key_field = pointer_type(b64, Permission.READ_WRITE, 8, space=2)
    next_field = pointer_type(link_t, Permission.READ_WRITE, 8, space=2)
    head_record = tuple_type((link_t,))
    heads = pointer_type(head_record, Permission.READ_WRITE, 8, space=2)
    arena_type = records if record_links else words
    table_type = heads if record_links else words
    arena_bytes, bucket_bytes, out_bytes = nodes * NODE_BYTES, buckets * 8, 4096
    shift = 64 - (buckets.bit_length() - 1)
    graph = GraphBuilder()
    graph.track(*api.types, words, kit.b1, link_t, record, records, key_field, next_field, head_record, heads)

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

    def mapping(memory, size, pointer_type_, alignment, link_target=None):
        raw, owner, memory = entry.op(Operation.CALL_FOREIGN, (const(entry, size), memory), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
        operands = (raw, owner, memory) if link_target is None else (raw, owner, memory, link_target)
        return entry.op(Operation.HEAP_VIEW, operands, (pointer_type_, heap_view_type(size), mem), attributes=(size, alignment))

    arena, arena_token, arena_mem = mapping(arena_mem, arena_bytes, arena_type, NODE_BYTES if record_links else 8)
    table, bucket_token, bucket_mem = mapping(bucket_mem, bucket_bytes, table_type, 8, arena if record_links else None)
    out, out_token, out_mem = mapping(out_mem, out_bytes, api.bytes_rw, 1)
    arena_address = entry.op1(Operation.POINTER_ADDRESS, (arena,), b64, attributes=(1,)) if pointer_links or record_links else None

    def record_at(block, index):
        """Record ``index`` of the arena: one checked rebase (ADR-092) onto a record start."""
        address = binary(block, Operation.ADD_WRAP, arena_address, binary(block, Operation.MUL_WRAP, index, const(block, NODE_BYTES)))
        return block.op1(Operation.POINTER_REBASE, (arena, address), records, attributes=(NODE_BYTES,))

    table_address = entry.op1(Operation.POINTER_ADDRESS, (table,), b64, attributes=(1,)) if record_links else None

    def head_at(block, bucket):
        """The link field of bucket ``bucket`` (one checked rebase onto a head record)."""
        address = binary(block, Operation.ADD_WRAP, table_address, binary(block, Operation.MUL_WRAP, bucket, const(block, 8)))
        head_pointer = block.op1(Operation.POINTER_REBASE, (table, address), heads, attributes=(8,))
        return block.op1(Operation.ADDRESS_OFFSET, (head_pointer,), next_field, attributes=(0,))

    def key_of(block, record_pointer):
        return block.op1(Operation.ADDRESS_OFFSET, (record_pointer,), key_field, attributes=(0,))

    def next_of(block, record_pointer):
        return block.op1(Operation.ADDRESS_OFFSET, (record_pointer,), next_field, attributes=(8,))

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
    if record_links:
        bucket_head = head_at(b, binary(b, Operation.UDIV, key, const(b, 1 << shift)))
        head, bucket_mem = b.op(Operation.LOAD_BITS_LE, (bucket_head, s["bucket_mem"]), (link_t, mem), attributes=(8, 8))
        node = record_at(b, s["i"])
        arena_mem = b.op1(Operation.STORE_BITS_LE, (key_of(b, node), key, s["arena_mem"]), mem, attributes=(8, 8))
        arena_mem = b.op1(Operation.STORE_BITS_LE, (next_of(b, node), head, arena_mem), mem, attributes=(8, 8))
        made = b.op1(Operation.LINK_MAKE, (node,), link_t)
        bucket_mem = b.op1(Operation.STORE_BITS_LE, (bucket_head, made, bucket_mem), mem, attributes=(8, 8))
        b.br(insert, *flow.args(insert, {**s, "arena_mem": arena_mem, "bucket_mem": bucket_mem, "i": binary(b, Operation.ADD_WRAP, s["i"], const(b, 1)), "x": key}))
    else:
        bucket = byte_offset(b, binary(b, Operation.UDIV, key, const(b, 1 << shift)), 8)
        head, bucket_mem = b.op(Operation.CHECKED_LOAD_BITS_LE, (table, bucket, s["bucket_mem"]), (b64, mem), attributes=(8, 1))
        node = byte_offset(b, s["i"], NODE_BYTES)
        arena_mem = b.op1(Operation.CHECKED_STORE_BITS_LE, (arena, node, key, s["arena_mem"]), mem, attributes=(8, 1))
        link = binary(b, Operation.ADD_WRAP, node, const(b, 8, b32), b32)
        arena_mem = b.op1(Operation.CHECKED_STORE_BITS_LE, (arena, link, head, arena_mem), mem, attributes=(8, 1))
        following = binary(b, Operation.ADD_WRAP, s["i"], const(b, 1))
        # Index links store i + 1; pointer links store the node's exposed address.
        reference = binary(b, Operation.ADD_WRAP, arena_address, binary(b, Operation.MUL_WRAP, s["i"], const(b, NODE_BYTES))) if pointer_links else following
        bucket_mem = b.op1(Operation.CHECKED_STORE_BITS_LE, (table, bucket, reference, bucket_mem), mem, attributes=(8, 1))
        b.br(insert, *flow.args(insert, {**s, "arena_mem": arena_mem, "bucket_mem": bucket_mem, "i": following, "x": key}))

    # --- lookup loop ---------------------------------------------------------------------
    counters = (("j", b64), ("x", b64), ("found", b64), ("steps", b64))
    lookup, lookup_state = flow.block(*counters)
    lookup_body, lookup_body_state = flow.block(*counters)
    cursor_type = link_t if record_links else b64
    walk, walk_state = flow.block(*counters, ("cur", cursor_type))
    step, step_state = flow.block(*counters, ("cur", cursor_type))
    if links == "index":  # created here so index mode keeps its original block order
        advance, advance_state = flow.block(*counters, ("node", b32))
    elif record_links:  # C's control flow: found++ in its own block; cur->next only when the key differs
        advance, advance_state = flow.block(*counters, ("node", records))
        hit, hit_state = flow.block(*counters)
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
    if record_links:
        head, bucket_mem = lb.op(Operation.LOAD_BITS_LE, (head_at(lb, binary(lb, Operation.UDIV, key, const(lb, 1 << shift))), ls["bucket_mem"]), (link_t, mem), attributes=(8, 8))
        following = binary(lb, Operation.ADD_WRAP, ls["j"], const(lb, 1))
        lb.br(walk, *flow.args(walk, {**ls, "bucket_mem": bucket_mem, "x": key, "j": following, "cur": head}))
    else:
        bucket = byte_offset(lb, binary(lb, Operation.UDIV, key, const(lb, 1 << shift)), 8)
        head, bucket_mem = lb.op(Operation.CHECKED_LOAD_BITS_LE, (table, bucket, ls["bucket_mem"]), (b64, mem), attributes=(8, 1))
        following = binary(lb, Operation.ADD_WRAP, ls["j"], const(lb, 1))
        lb.br(walk, *flow.args(walk, {**ls, "bucket_mem": bucket_mem, "x": key, "j": following, "cur": head}))
    end = walk.op1(Operation.CONSTANT, (), link_t, entity=null_link()) if record_links else const(walk, 0)
    walk.cbr(
        compare(walk, IntCompare.NE, walk_state["cur"], end),
        step, flow.args(step, walk_state),
        lookup, flow.args(lookup, walk_state),
    )
    st = step
    ss = step_state
    if record_links:
        # Check-free (ADR-097): the walk's own null test already proved cur nonzero.
        node = st.op1(Operation.LINK_FOLLOW, (arena, ss["cur"]), records)
        stored, arena_mem = st.op(Operation.LOAD_BITS_LE, (key_of(st, node), ss["arena_mem"]), (b64, mem), attributes=(8, 8))
        steps = binary(st, Operation.ADD_WRAP, ss["steps"], const(st, 1))
        st.cbr(
            compare(st, IntCompare.EQ, stored, ss["x"]),
            hit, flow.args(hit, {**ss, "arena_mem": arena_mem, "steps": steps}),
            advance, flow.args(advance, {**ss, "arena_mem": arena_mem, "steps": steps, "node": node}),
        )
        hit.br(lookup, *flow.args(lookup, {**hit_state, "found": binary(hit, Operation.ADD_WRAP, hit_state["found"], const(hit, 1))}))
        ad, ads = advance, advance_state
        successor, arena_mem = ad.op(Operation.LOAD_BITS_LE, (next_of(ad, ads["node"]), ads["arena_mem"]), (link_t, mem), attributes=(8, 8))
        ad.br(walk, *flow.args(walk, {**ads, "arena_mem": arena_mem, "cur": successor}))
    elif pointer_links:
        # Both fields come from one rebased node; no dynamic offset remains.
        node = st.op1(Operation.POINTER_REBASE, (arena, ss["cur"]), words, attributes=(NODE_BYTES,))
        stored, arena_mem = st.op(Operation.LOAD_BITS_LE, (node, ss["arena_mem"]), (b64, mem), attributes=(8, 8))
        link = st.op1(Operation.ADDRESS_OFFSET, (node,), words, attributes=(8,))
        successor, arena_mem = st.op(Operation.LOAD_BITS_LE, (link, arena_mem), (b64, mem), attributes=(8, 8))
        steps = binary(st, Operation.ADD_WRAP, ss["steps"], const(st, 1))
        st.cbr(
            compare(st, IntCompare.EQ, stored, ss["x"]),
            lookup, flow.args(lookup, {**ss, "arena_mem": arena_mem, "steps": steps, "found": binary(st, Operation.ADD_WRAP, ss["found"], const(st, 1))}),
            walk, flow.args(walk, {**ss, "arena_mem": arena_mem, "steps": steps, "cur": successor}),
        )
    else:
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
    def release_arena():
        return current.op(Operation.CALL_FOREIGN, (arena, cs["arena_token"], cs["arena_mem"]), (b64, mem), entity=api.munmap_view(arena_type, arena_bytes))[1]

    def release_table():
        return current.op(Operation.CALL_FOREIGN, (table, cs["bucket_token"], cs["bucket_mem"]), (b64, mem), entity=api.munmap_view(table_type, bucket_bytes))[1]

    if record_links:  # the table's links target the arena, so the table ends first
        bucket_mem = release_table()
        arena_mem = release_arena()
    else:
        arena_mem = release_arena()
        bucket_mem = release_table()
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


def compile_chains(nodes: int = NODES, buckets: int = BUCKETS, links: str = "index") -> tuple[ChainsProgram, LinuxExecutable]:
    program = build_chains_program(nodes, buckets, links)
    return program, compile_linux_executable(program.reader, program.entry.cid, program.target.cid)


def run_benchmark(repetitions: int, warmup: int) -> dict:
    program, executable = compile_chains()
    pointer_program, pointer_executable = compile_chains(links="pointer")
    link_program, link_executable = compile_chains(links="link")
    expected = reference_chains()
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        artifacts, stripped = build_arms(work, "chains", executable.data, C_SOURCE)
        artifacts["xax-pointer"] = work / "chains-xax-pointer"
        artifacts["xax-pointer"].write_bytes(pointer_executable.data)
        artifacts["xax-pointer"].chmod(0o755)
        stripped["xax-pointer"] = len(pointer_executable.data)  # no section table to strip
        artifacts["xax-link"] = work / "chains-xax-link"
        artifacts["xax-link"].write_bytes(link_executable.data)
        artifacts["xax-link"].chmod(0o755)
        stripped["xax-link"] = len(link_executable.data)

        def validate(arm: str, path: Path) -> bytes:
            output, status = run_output(path, work)
            if (output, status) != (expected, 0):
                raise AssertionError(f"{arm}: {output!r} status {status}")
            return output

        results, output, reference_rss = measure_arms(work, artifacts, stripped, repetitions, warmup, validate)
        diagnostic_artifacts = {"gcc-O2": artifacts["gcc-O2"]}
        for arm, source, flags in DIAGNOSTICS:
            subprocess.run(["gcc", "-O2", *flags, "-o", str(work / arm), str(source)], check=True)
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
        "checked_vs_unchecked_pointer": round(diagnostics["gcc-O2-pointer-checked"]["wall_seconds_median"] / results["gcc-O2"]["wall_seconds_median"], 3),
        "xax_pointer_vs_checked_pointer_c": round(results["xax-pointer"]["wall_seconds_median"] / diagnostics["gcc-O2-pointer-checked"]["wall_seconds_median"], 3),
        "xax_link_vs_gcc_O2_pointer": round(results["xax-link"]["wall_seconds_median"] / results["gcc-O2"]["wall_seconds_median"], 3),
    }
    return {
        "format": "xax-oi37-chains-evidence-v3",
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
        "xax_pointer": {
            "program_root": pointer_program.reader.root_cid.hex(),
            "entry_function": pointer_program.entry.cid.hex(),
            "graph_blocks": pointer_program.block_count,
            "artifact_sha256": hashlib.sha256(pointer_executable.data).hexdigest(),
            "artifact_bytes": len(pointer_executable.data),
            "link_representation": "exposed node address (0 = end) reloaded by pointer_rebase(arena, address, 16): one range+alignment check, then unchecked field loads (ADR-092)",
            "runtime_dependencies": [],
        },
        "xax_link": {
            "program_root": link_program.reader.root_cid.hex(),
            "entry_function": link_program.entry.cid.hex(),
            "graph_blocks": link_program.block_count,
            "artifact_sha256": hashlib.sha256(link_executable.data).hexdigest(),
            "artifact_bytes": len(link_executable.data),
            "link_representation": "record link fields (ADR-097): heads table targets the arena; link_follow is check-free (null test elided by the walk's own test)",
            "runtime_dependencies": [],
        },
        "results": results,
        "diagnostics": diagnostics,
        "attribution": attribution,
        "attribution_note": "all ratios are medians from the same run: representation = C index/C pointer; checks = checked/unchecked C index or pointer; codegen = XAX/C with the same representation and checks",
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
