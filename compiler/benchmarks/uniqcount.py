"""``uniqcount``: count distinct decimal numbers on standard input (OI-36 application).

Behavior (identical to :func:`reference_uniqcount`): read all of standard
input (at most ``CAPACITY`` bytes); every maximal run of ASCII digits is one
number, taken modulo 2^64; write the count of distinct numbers in decimal
plus ``\\n`` and exit 0.  Input larger than ``CAPACITY`` exits 2 with no
output; more than ``TABLE`` distinct numbers exits 3 with no output.

The program is an ordinary XAX entry function that calls two standard
semantic library packages (ADR-130): ``xax.text`` (``find_digits``,
``parse_u64``, ``format_u64``) and ``xax.collections.hashset_u64`` (``insert``).  It does
not use ``skip_spaces`` or ``contains``; they are absent from its store.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from xax_compiler import IntCompare, Operation, SemanticObject, StoreReader, heap_view_type
from xax_graph_builder import program_store
from xax_stdlib import BYTES, MEM, WORDS, Library, hashset_package, hashset_table_extent, text_package
from xax_structured import B1, B32, B64, Proc

CAPACITY = 1 << 20
CHUNK = 65536
TABLE = 1 << 16
INPUT_EXTENT = CAPACITY + CHUNK
OUTPUT_EXTENT = 32
INPUT_VIEW = (BYTES, heap_view_type(INPUT_EXTENT), MEM)
EXIT_OK, EXIT_TOO_LARGE, EXIT_FULL = 0, 2, 3
GT, EQ, NE = IntCompare.UGT, IntCompare.EQ, IntCompare.NE


@dataclass(frozen=True)
class UniqcountProgram:
    reader: StoreReader
    entry: SemanticObject
    target: SemanticObject
    libraries: tuple[Library, ...]


def libraries() -> tuple[Library, Library, Library]:
    """The three package instances the program uses: input text, output text, set."""
    return text_package(INPUT_EXTENT), text_package(OUTPUT_EXTENT), hashset_package(TABLE)


def build_uniqcount(arch: str = "x86_64") -> UniqcountProgram:
    if arch == "aarch64":
        from xax_compiler import aarch64_linux_exec_target
        from xax_linux_aarch64 import linux_aarch64_api

        api, target = linux_aarch64_api(), aarch64_linux_exec_target()
    else:
        from xax_compiler import x86_64_linux_exec_target
        from xax_linux import linux_api

        api, target = linux_api(), x86_64_linux_exec_target()
    text_in, text_out, sets = libraries()
    memories = ("m1", "m2", "m3")
    proc = Proc((("proc", api.process_effect), ("fs", api.filesystem_effect), *((name, MEM) for name in memories)))

    def mapping(memory: str, extent: int, pointer, name: str):
        raw, owner, effect = proc.op(Operation.CALL_FOREIGN, (proc.const(extent, B64), proc.drop(memory)), (api.bytes_rw, api.heap_owner, MEM), entity=api.mmap_anonymous)
        p, v, m = proc.op(Operation.HEAP_VIEW, (raw, owner, effect), (pointer, heap_view_type(extent), MEM), attributes=(extent, 1 if pointer is BYTES else 8))
        for suffix, value, type_ in (("p", p, pointer), ("v", v, heap_view_type(extent)), ("m", m, MEM)):
            proc.let(name + suffix, type_, value)

    mapping("m1", INPUT_EXTENT, BYTES, "i")
    mapping("m2", hashset_table_extent(TABLE), WORDS, "t")
    mapping("m3", OUTPUT_EXTENT, BYTES, "o")
    proc.let("total", B32, proc.const(0))
    proc.let("go", B1, proc.const(1, B1))
    proc.let("code", B32, proc.const(EXIT_OK))
    base = proc.op1(Operation.POINTER_ADDRESS, (proc["ip"],), B64, attributes=(1,))

    def stop(p: Proc, code: int | None = None) -> None:
        if code is not None:
            p["code"] = p.const(code)
        p["go"] = p.const(0, B1)

    def read_chunk(p: Proc):
        address = p.bin(Operation.ADD_WRAP, base, p.widen(p["total"], B64), B64)
        window = p.op1(Operation.POINTER_REBASE, (p["ip"], address), BYTES, attributes=(CHUNK,))
        count, p["fs"], p["im"] = p.op(Operation.CALL_FOREIGN, (p.const(0), window, p.const(CHUNK, B64), p["fs"], p["im"]), (B64, api.filesystem_effect, MEM), entity=api.read)

        def got(q: Proc):
            q["total"] = q.bin(Operation.ADD_WRAP, q["total"], q.op1(Operation.INT_TRUNCATE, (count,), B32))
            q.if_(q.cmp(GT, q["total"], CAPACITY), lambda r: stop(r, EXIT_TOO_LARGE))

        p.if_(p.cmp(EQ, count, 0, B64), stop, lambda q: q.if_(q.cmp(GT, count, CHUNK, B64), lambda r: stop(r, EXIT_TOO_LARGE), got))

    going = lambda p: p.cmp(NE, p.widen(p["go"]), 0)  # noqa: E731
    proc.while_(going, read_chunk)
    proc.let("pos", B32, proc.const(0))
    proc.let("distinct", B64, proc.const(0, B64))

    def count_numbers(p: Proc):
        p["go"] = p.const(1, B1)

        def step(q: Proc):
            span, q["ip"], q["iv"], q["im"] = q.op(Operation.CALL_DIRECT, (q["pos"], q["total"], q["ip"], q["iv"], q["im"]), (B64, *INPUT_VIEW), entity=text_in["find_digits"])
            start = q.op1(Operation.INT_TRUNCATE, (span,), B32)
            q["pos"] = q.op1(Operation.INT_TRUNCATE, (q.op1(Operation.ROTATE_RIGHT, (span,), B64, attributes=(32,)),), B32)

            def insert(r: Proc):
                value, r["ip"], r["iv"], r["im"] = r.op(Operation.CALL_DIRECT, (start, r["pos"], r["ip"], r["iv"], r["im"]), (B64, *INPUT_VIEW), entity=text_in["parse_u64"])
                added, r["tp"], r["tv"], r["tm"] = r.op(Operation.CALL_DIRECT, (value, r["tp"], r["tv"], r["tm"]), (B32, WORDS, heap_view_type(hashset_table_extent(TABLE)), MEM), entity=sets["insert"])
                r.if_(r.cmp(EQ, added, 2), lambda s: stop(s, EXIT_FULL), lambda s: s.__setitem__("distinct", s.bin(Operation.ADD_WRAP, s["distinct"], s.widen(added, B64), B64)))

            q.if_(q.cmp(EQ, start, q["pos"]), stop, insert)

        p.while_(going, step)

    proc.if_(proc.cmp(EQ, proc["code"], EXIT_OK), count_numbers)

    def report(p: Proc):
        end, p["op"], p["ov"], p["om"] = p.op(Operation.CALL_DIRECT, (p["distinct"], p.const(0), p["op"], p["ov"], p["om"]), (B32, BYTES, heap_view_type(OUTPUT_EXTENT), MEM), entity=text_out["format_u64"])
        p["om"] = p.op1(Operation.CHECKED_STORE_BITS_LE, (p["op"], end, p.const(0x0A, api.b8), p["om"]), MEM, attributes=(1, 1))
        readable = p.op1(Operation.POINTER_CAST, (p["op"],), api.bytes_read)
        _count, p["fs"], p["om"] = p.op(Operation.CALL_FOREIGN, (p.const(1), readable, p.widen(p.bin(Operation.ADD_WRAP, end, 1), B64), p["fs"], p["om"]), (B64, api.filesystem_effect, MEM), entity=api.write)

    proc.if_(proc.cmp(EQ, proc["code"], EXIT_OK), report)
    for name, pointer, extent in (("i", BYTES, INPUT_EXTENT), ("t", WORDS, hashset_table_extent(TABLE)), ("o", BYTES, OUTPUT_EXTENT)):
        _result, proc[name + "m"] = proc.op(Operation.CALL_FOREIGN, (proc[name + "p"], proc[name + "v"], proc[name + "m"]), (B64, MEM), entity=api.munmap_view(pointer, extent))
    process = proc.op1(Operation.CALL_FOREIGN, (proc["code"], proc["proc"]), api.process_effect, entity=api.exit_group)
    proc.ret(proc["code"], process, proc["fs"], proc["im"], proc["tm"], proc["om"])
    entry = proc.function((B32, api.process_effect, api.filesystem_effect, MEM, MEM, MEM))
    objects = (*api.types, *proc.graph.objects.values(), *(item for library in (text_in, text_out, sets) for item in library.objects))
    return UniqcountProgram(program_store(entry, target, objects), entry, target, (text_in, text_out, sets))


def reference_uniqcount(data: bytes) -> tuple[int, bytes]:
    if len(data) > CAPACITY:
        return EXIT_TOO_LARGE, b""
    distinct = {int(run) % (1 << 64) for run in re.findall(rb"[0-9]+", data)}
    if len(distinct - {0}) > TABLE:  # slot TABLE holds key 0
        return EXIT_FULL, b""
    return EXIT_OK, b"%d\n" % len(distinct)
