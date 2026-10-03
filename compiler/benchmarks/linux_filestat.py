"""U1.3 Linux native hosted workload: ``filestat`` as an ordinary XAX semantic graph.

Exact behavior (identical to ``linux_filestat_c/filestat.c``):

* open ``input.dat`` in the working directory read-only;
* read it in 65,536-byte chunks into an anonymous-``mmap`` buffer;
* count bytes, ``\\n`` lines, and whitespace-separated words (space, tab,
  CR, LF), compute 64-bit FNV-1a, keep a 256-entry byte histogram in a
  second anonymous mapping, and fold every chunk into zlib's CRC-32 by
  calling ``crc32`` in the system ``libz.so.1``;
* select the most frequent byte (lowest byte value on ties);
* write ``"<bytes> <lines> <words> <fnv1a> <crc32> <byte>\\n"`` in decimal;
* release both mappings and end the process with an explicit ``exit_group``
  status 0 (2: open failed, 3: read failed).

The graph is built through :mod:`xax_graph_builder`; Python here is only the
construction tool.  The program has no XAX runtime and no libc dependency of
its own; the dynamic loader is requested explicitly by the target profile
and loads only ``libz.so.1`` (and what that library itself needs).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from xax_compiler import IntCompare, Operation, Permission, SemanticObject, StoreReader, bits_type, heap_view_type, pointer_type, x86_64_linux_dynamic_exec_target
from xax_graph_builder import GraphBuilder, program_store

from benchmarks.linux_graph_kit import Flow, Kit, emit_decimal_line
from benchmarks.linux_harness import build_arms, host_info, measure_arms, method_info, run_output
from xax_linux import AT_FDCWD, LinuxApi, LinuxExecutable, c_function, compile_linux_executable, linux_api

BUFFER_BYTES = 65536
TABLE_BYTES = 256 * 8
INPUT_NAME = b"input.dat\0"
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
STATUS_OPEN_FAILED = 2
STATUS_READ_FAILED = 3

HERE = Path(__file__).resolve().parent
C_SOURCE = HERE / "linux_filestat_c" / "filestat.c"
EVIDENCE = HERE / "u1_linux_filestat_evidence.json"


@dataclass(frozen=True)
class FilestatProgram:
    reader: StoreReader
    entry: SemanticObject
    target: SemanticObject
    block_count: int


def build_filestat_program(arch: str = "x86_64") -> FilestatProgram:
    """The same semantic graph for every Linux architecture; only the platform package differs (ADR-123)."""
    if arch == "aarch64":
        from xax_compiler import aarch64_linux_exec_target
        from xax_linux_aarch64 import c_function as aarch64_c_function, linux_aarch64_api

        api: LinuxApi = linux_aarch64_api()
        import_c, target = aarch64_c_function, aarch64_linux_exec_target(dynamic=True)
    else:
        api = linux_api()
        import_c, target = c_function, x86_64_linux_dynamic_exec_target()
    b1 = bits_type(1)
    b8, b32, b64 = api.b8, api.b32, api.b64
    words_rw = pointer_type(b64, Permission.READ_WRITE, 8, space=2)
    zlib_crc32 = import_c(b"libz.so.1", b"crc32", (b64, api.bytes_read, b32, api.memory_effect), (b64, api.memory_effect))
    buffer_view = heap_view_type(BUFFER_BYTES)
    table_view = heap_view_type(TABLE_BYTES)
    mem = api.memory_effect
    graph = GraphBuilder()
    graph.track(*api.types, words_rw, b1)

    carried = ("proc", "fs", "buf_token", "buf_mem", "tab_token", "tab_mem")
    types = {"proc": api.process_effect, "fs": api.filesystem_effect, "buf_token": buffer_view, "buf_mem": mem, "tab_token": table_view, "tab_mem": mem}
    flow = Flow(graph, carried, types)

    # --- entry: two zeroed mappings, the path bytes, and openat -------------------
    entry = graph.block(api.process_effect, api.filesystem_effect, mem, mem)
    process, fs, entry_buf_mem, entry_tab_mem = entry.params
    raw, owner, effect = entry.op(Operation.CALL_FOREIGN, (entry.const(b64, BUFFER_BYTES), entry_buf_mem), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
    buf, buf_token, buf_mem = entry.op(Operation.HEAP_VIEW, (raw, owner, effect), (api.bytes_rw, buffer_view, mem), attributes=(BUFFER_BYTES, 1))
    raw, owner, effect = entry.op(Operation.CALL_FOREIGN, (entry.const(b64, TABLE_BYTES), entry_tab_mem), (api.bytes_rw, api.heap_owner, mem), entity=api.mmap_anonymous)
    tab, tab_token, tab_mem = entry.op(Operation.HEAP_VIEW, (raw, owner, effect), (words_rw, table_view, mem), attributes=(TABLE_BYTES, 8))
    for offset, byte in enumerate(INPUT_NAME):
        if byte:  # the zero-filled mapping already supplies the terminator
            pointer = buf if offset == 0 else entry.op1(Operation.ADDRESS_OFFSET, (buf,), api.bytes_rw, attributes=(offset,))
            buf_mem = entry.op1(Operation.STORE_BITS_LE, (pointer, entry.const(b8, byte), buf_mem), mem, attributes=(1, 1))
    path = buffer_read = entry.op1(Operation.POINTER_CAST, (buf,), api.bytes_read)
    opened, fs, buf_mem = entry.op(
        Operation.CALL_FOREIGN, (entry.const(b32, AT_FDCWD), path, entry.const(b32, 0), entry.const(b32, 0), fs, buf_mem),
        (b64, api.filesystem_effect, mem), entity=api.openat,
    )
    state = {"proc": process, "fs": fs, "buf_token": buf_token, "buf_mem": buf_mem, "tab_token": tab_token, "tab_mem": tab_mem}

    kit = Kit()
    const, compare, binary = kit.const, kit.compare, kit.binary

    exit_block, exit_state = flow.block(("status", b32))
    counters = (("fd", b32), ("bytes", b64), ("lines", b64), ("words", b64), ("hash", b64), ("crc", b64), ("prev_ws", b64))
    read_block, read_state = flow.block(*counters)

    fd_ok = compare(entry, IntCompare.ULT, opened, const(entry, 1 << 31))
    initial = {
        **state, "fd": entry.op1(Operation.INT_TRUNCATE, (opened,), b32), "bytes": const(entry, 0), "lines": const(entry, 0),
        "words": const(entry, 0), "hash": const(entry, FNV_OFFSET), "crc": const(entry, 0), "prev_ws": const(entry, 1),
    }
    entry.cbr(fd_ok, read_block, flow.args(read_block, initial), exit_block, flow.args(exit_block, {**state, "status": const(entry, STATUS_OPEN_FAILED, b32)}))

    # --- read loop -------------------------------------------------------------------
    scan_block, scan_state = flow.block(*counters, ("i", b32), ("n", b32))
    check_block, check_state = flow.block(*counters, ("n64", b64))
    chunk_block, chunk_state = flow.block(*counters, ("n64", b64))
    close_block, close_state = flow.block(*counters)
    count, fs, buf_mem = read_block.op(
        Operation.CALL_FOREIGN, (read_state["fd"], buf, const(read_block, BUFFER_BYTES), read_state["fs"], read_state["buf_mem"]),
        (b64, api.filesystem_effect, mem), entity=api.read,
    )
    after_read = {**read_state, "fs": fs, "buf_mem": buf_mem}
    read_block.cbr(
        compare(read_block, IntCompare.EQ, count, const(read_block, 0)),
        close_block, flow.args(close_block, after_read),
        check_block, flow.args(check_block, {**after_read, "n64": count}),
    )
    check_block.cbr(
        compare(check_block, IntCompare.UGT, check_state["n64"], const(check_block, BUFFER_BYTES)),
        exit_block, flow.args(exit_block, {**check_state, "status": const(check_block, STATUS_READ_FAILED, b32)}),
        chunk_block, flow.args(chunk_block, check_state),
    )
    # External library call: zlib's CRC-32 over each chunk, through the
    # explicitly requested dynamic loader (sysv-x86_64-c, DT_NEEDED libz.so.1).
    chunk_n = chunk_block.op1(Operation.INT_TRUNCATE, (chunk_state["n64"],), b32)
    crc, buf_mem = chunk_block.op(
        Operation.CALL_FOREIGN, (chunk_state["crc"], buffer_read, chunk_n, chunk_state["buf_mem"]), (b64, mem), entity=zlib_crc32,
    )
    chunk_block.br(scan_block, *flow.args(scan_block, {**chunk_state, "crc": crc, "buf_mem": buf_mem, "i": const(chunk_block, 0, b32), "n": chunk_n}))

    # --- per-byte body ---------------------------------------------------------------
    body_block, body_state = flow.block(*counters, ("i", b32), ("n", b32))
    scan_block.cbr(
        compare(scan_block, IntCompare.ULT, scan_state["i"], scan_state["n"]),
        body_block, flow.args(body_block, scan_state),
        read_block, flow.args(read_block, scan_state),
    )
    b = body_block
    s = body_state
    byte, buf_mem = b.op(Operation.CHECKED_LOAD_BITS_LE, (buf, s["i"], s["buf_mem"]), (b8, mem), attributes=(1, 1))
    c = b.op1(Operation.INT_ZERO_EXTEND, (byte,), b64)
    one = const(b, 1)

    def is_byte(value: int):
        return b.op1(Operation.INT_ZERO_EXTEND, (compare(b, IntCompare.EQ, c, const(b, value)),), b64)

    newline = is_byte(10)
    whitespace = binary(b, Operation.BIT_OR, binary(b, Operation.BIT_OR, is_byte(32), newline), binary(b, Operation.BIT_OR, is_byte(9), is_byte(13)))
    word_start = binary(b, Operation.BIT_AND, binary(b, Operation.BIT_XOR, whitespace, one), s["prev_ws"])
    slot = b.op1(Operation.INT_TRUNCATE, (binary(b, Operation.MUL_WRAP, c, const(b, 8)),), b32)
    seen, tab_mem = b.op(Operation.CHECKED_LOAD_BITS_LE, (tab, slot, s["tab_mem"]), (b64, mem), attributes=(8, 1))
    tab_mem = b.op1(Operation.CHECKED_STORE_BITS_LE, (tab, slot, binary(b, Operation.ADD_WRAP, seen, one), tab_mem), mem, attributes=(8, 1))
    updated = {
        **s,
        "buf_mem": buf_mem,
        "tab_mem": tab_mem,
        "bytes": binary(b, Operation.ADD_WRAP, s["bytes"], one),
        "lines": binary(b, Operation.ADD_WRAP, s["lines"], newline),
        "words": binary(b, Operation.ADD_WRAP, s["words"], word_start),
        "hash": binary(b, Operation.MUL_WRAP, binary(b, Operation.BIT_XOR, s["hash"], c), const(b, FNV_PRIME)),
        "prev_ws": whitespace,
        "i": binary(b, Operation.ADD_WRAP, s["i"], const(b, 1, b32), b32),
    }
    b.br(scan_block, *flow.args(scan_block, updated))

    # --- close, then select the most frequent byte -------------------------------------
    results = (("bytes", b64), ("lines", b64), ("words", b64), ("hash", b64), ("crc", b64))
    best_names = (("k", b64), ("best", b64), ("best_count", b64))
    max_block, max_state = flow.block(*results, *best_names)
    status, fs = close_block.op(Operation.CALL_FOREIGN, (close_state["fd"], close_state["fs"]), (b64, api.filesystem_effect), entity=api.close)
    zero = const(close_block, 0)
    close_block.br(max_block, *flow.args(max_block, {**close_state, "fs": fs, "k": zero, "best": zero, "best_count": zero}))

    max_body, max_body_state = flow.block(*results, *best_names)
    format_block, format_state = flow.block(*results, ("best", b64))
    max_block.cbr(
        compare(max_block, IntCompare.ULT, max_state["k"], const(max_block, 256)),
        max_body, flow.args(max_body, max_state),
        format_block, flow.args(format_block, max_state),
    )
    m = max_body
    s = max_body_state
    value, tab_mem = m.op(Operation.CHECKED_LOAD_BITS_LE, (tab, m.op1(Operation.INT_TRUNCATE, (binary(m, Operation.MUL_WRAP, s["k"], const(m, 8)),), b32), s["tab_mem"]), (b64, mem), attributes=(8, 1))
    # Branch-free select: mask is all ones exactly when value > best_count.
    mask = binary(m, Operation.SUB_WRAP, const(m, 0), m.op1(Operation.INT_ZERO_EXTEND, (compare(m, IntCompare.UGT, value, s["best_count"]),), b64))
    choose = lambda old, new: binary(m, Operation.BIT_XOR, old, binary(m, Operation.BIT_AND, binary(m, Operation.BIT_XOR, old, new), mask))
    m.br(max_block, *flow.args(max_block, {
        **s, "tab_mem": tab_mem, "k": binary(m, Operation.ADD_WRAP, s["k"], const(m, 1)),
        "best": choose(s["best"], s["k"]), "best_count": choose(s["best_count"], value),
    }))

    # --- decimal formatting into the (no longer needed) input buffer --------------------
    current, current_state = emit_decimal_line(kit, flow, format_block, format_state, ("bytes", "lines", "words", "hash", "crc", "best"), buf, mem)

    out = current
    _written, fs, buf_mem = out.op(
        Operation.CALL_FOREIGN, (const(out, 1, b32), buffer_read, out.op1(Operation.INT_ZERO_EXTEND, (current_state["pos"],), b64), current_state["fs"], current_state["buf_mem"]),
        (b64, api.filesystem_effect, mem), entity=api.write,
    )
    out.br(exit_block, *flow.args(exit_block, {**current_state, "fs": fs, "buf_mem": buf_mem, "status": const(out, 0, b32)}))

    # --- exit: explicit release of both mappings -----------------------------------------
    e = exit_block
    _r, buf_mem = e.op(Operation.CALL_FOREIGN, (buf, exit_state["buf_token"], exit_state["buf_mem"]), (b64, mem), entity=api.munmap_view(api.bytes_rw, BUFFER_BYTES))
    _r, tab_mem = e.op(Operation.CALL_FOREIGN, (tab, exit_state["tab_token"], exit_state["tab_mem"]), (b64, mem), entity=api.munmap_view(words_rw, TABLE_BYTES))
    # Explicit process exit; the entry never returns (ADR-076).
    process = e.op1(Operation.CALL_FOREIGN, (exit_state["status"], exit_state["proc"]), api.process_effect, entity=api.exit_group)
    e.ret(exit_state["status"], process, exit_state["fs"], buf_mem, tab_mem)

    function = graph.function((api.process_effect, api.filesystem_effect, mem, mem), (b32, api.process_effect, api.filesystem_effect, mem, mem))
    reader = program_store(function, target, tuple(graph.objects.values()))
    return FilestatProgram(reader, function, target, len(graph.blocks))


def reference_filestat(data: bytes) -> bytes:
    """Independent Python statement of the exact output contract."""
    lines = data.count(b"\n")
    words, previous_whitespace, digest = 0, True, FNV_OFFSET
    histogram = [0] * 256
    for byte in data:
        whitespace = byte in (9, 10, 13, 32)
        words += (not whitespace) and previous_whitespace
        previous_whitespace = whitespace
        digest = ((digest ^ byte) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
        histogram[byte] += 1
    best = max(range(256), key=lambda value: (histogram[value], -value))
    return f"{len(data)} {lines} {words} {digest} {zlib.crc32(data)} {best}\n".encode()


def compile_filestat() -> tuple[FilestatProgram, LinuxExecutable]:
    program = build_filestat_program()
    return program, compile_linux_executable(program.reader, program.entry.cid, program.target.cid)


def benchmark_input(size: int) -> bytes:
    """Deterministic text-like corpus: letters, digits, spaces, tabs, CR and LF."""
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + b" " * 12 + b"\n\t\r"
    table = bytes(alphabet[value % len(alphabet)] for value in range(256))
    return hashlib.shake_256(b"xax-u1-filestat").digest(size).translate(table)


def run_benchmark(size: int, repetitions: int, warmup: int) -> dict:
    """Execute the XAX artifact and optimized C baselines on identical input."""
    program, executable = compile_filestat()
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        artifacts, stripped = build_arms(work, "filestat", executable.data, C_SOURCE, ("-lz",))
        data = benchmark_input(size)
        (work / "input.dat").write_bytes(data)
        small = benchmark_input(200_003)
        small_dir = work / "small"
        small_dir.mkdir()
        (small_dir / "input.dat").write_bytes(small)
        expected_small = reference_filestat(small)

        def validate(arm: str, path: Path) -> bytes:
            small_output, small_status = run_output(path, small_dir)
            if small_output != expected_small or small_status != 0:
                raise AssertionError(f"{arm} small-input mismatch: {small_output!r} status {small_status}")
            output, status = run_output(path, work)
            if status != 0:
                raise AssertionError(f"{arm} exited {status}")
            return output

        results, output, reference_rss = measure_arms(work, artifacts, stripped, repetitions, warmup, validate)
    for item in results.values():
        item["throughput_mib_s_median"] = round(size / (1 << 20) / item["wall_seconds_median"], 2)
    return {
        "format": "xax-u1-linux-filestat-evidence-v1",
        "evidence_label": "MEASURED",
        "workload": "filestat: openat/read loop over input.dat, byte/line/word counts, FNV-1a 64, zlib crc32 per chunk (libz.so.1), 256-entry histogram, decimal write",
        "input": {"bytes": size, "generator": "shake_256(b'xax-u1-filestat') translated to a 77-symbol text alphabet", "sha256": hashlib.sha256(data).hexdigest()},
        "output": output.decode(),
        "small_input_reference_check": {"bytes": len(small), "expected": expected_small.decode()},
        "xax": {
            "program_root": program.reader.root_cid.hex(),
            "entry_function": program.entry.cid.hex(),
            "target": program.target.cid.hex(),
            "graph_blocks": program.block_count,
            "artifact_sha256": hashlib.sha256(executable.data).hexdigest(),
            "artifact_bytes": len(executable.data),
            "codegen": "xax_x86_64_regalloc: per-block register allocation with callee-saved registers, rematerialized immediates, cmp+jcc fusion, in-block bounds-check reuse, power-of-two strength reduction",
            "runtime_dependencies": [],
            "dynamic_loader": "/lib64/ld-linux-x86-64.so.2 (requested by x86_64-linux-elf-dynexec-v1)",
            "dt_needed": [item.decode() for item in executable.needed],
        },
        "results": results,
        "host": host_info(zlib=zlib.ZLIB_RUNTIME_VERSION),
        "method": method_info(warmup, repetitions, reference_rss, "-lz"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=32 << 20)
    parser.add_argument("--repetitions", type=int, default=31)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--write", action="store_true", help="update the committed evidence JSON")
    arguments = parser.parse_args(argv)
    evidence = run_benchmark(arguments.size, arguments.repetitions, arguments.warmup)
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if arguments.write:
        EVIDENCE.write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
