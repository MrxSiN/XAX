"""Step 4 of the native decode path: resolve a carrier's type and entity names.

The reader (step 3) turns carrier bytes into a tree.  This module turns the names in that tree into
canonical objects, in the shape the native store writer consumes -- ``kind``, ``schema``, references and
body -- one line per occurrence, in walk order::

    resolve.exe <carrier> <listing>

``?`` marks a spec that is not resolved yet (see below), so a run reports its own coverage instead of
claiming completeness.

The oracle is the reference decoder.  For every line the reference resolves, this program's line is
decoded into a ``SemanticObject`` and its CID is compared with ``xax_construct._Builder``'s object for
the same spec, so the claim is about object identity, not about text that happens to agree.

What resolves here
------------------

* a ``b<N>`` type -- body ``01`` then the width,
* an alias declared in the carrier's ``types`` map (recursive, depth-limited, so a cycle is refused, as
  the reference refuses one),
* ``win32.<name>`` -- the platform namespace, embedded as authoring data by ``namespace_blob`` from
  ``xax_platform.win32_kernel32_api`` and ``win32_stdio_api``, read exactly as ``xax_construct`` reads
  them,
* ``{"view": EXTENT}`` -- the heap-view type,
* entities that are ``win32.<name>`` strings: the platform declarations are already in the blob.

What does not, yet
------------------

A *derived* declaration is built from type CIDs at decode time:

* ``{"win32.import": [DLL, SYMBOL, IN, OUT]}`` and ``{"win32.virtual_free_view": [TYPE, EXTENT]}``
  need the type CIDs hashed in the program (graph instantiation), step 4b,
* ``{"fn": NAME}`` needs the constructed functions, step 5.

Those are emitted as ``?`` and counted.  An unknown name is a refusal (exit 11 for a type, 12 for an
entity), never a guess.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import reader as R  # noqa: E402
from xax_compiler import IntCompare, Kind, Operation, SemanticObject, bits_type  # noqa: E402
from xax_platform import win32_kernel32_api, win32_stdio_api  # noqa: E402
from xax_structured import B32, B64  # noqa: E402

HEX = b"0123456789abcdef"
SPACE, NL, COMMA, DASH = 32, 10, 44, 45
PREFIX = b"win32."
UNKNOWN_TYPE, UNKNOWN_ENTITY = 11, 12
TABLE_SCRATCH = 0x800        # ULEB staging, inside the reader's scratch region
DEPTH_LIMIT = 8              # alias chain bound: the reference recurses, this refuses

# table entry, relative to the kind byte
T_KIND, T_SCHEMA, T_COUNT, T_REFS = 0, 1, 5, 9
T_BODY_LEN = T_REFS          # + 32 * count
T_BODY = T_BODY_LEN + 4      # + 32 * count


def namespace_entries() -> dict[str, SemanticObject]:
    """The ``win32.`` names ``xax_construct._Builder`` can reach, in its own namespace order."""
    api = win32_kernel32_api()
    stdio = win32_stdio_api(api)
    entries: dict[str, SemanticObject] = {}
    for namespace in (stdio, api):
        for field in dataclasses.fields(namespace):
            value = getattr(namespace, field.name)
            if isinstance(value, SemanticObject):
                entries.setdefault(field.name, value)
    return entries


def namespace_blob() -> bytes:
    """The embedded table: count, then name, kind, schema, references and body per entry."""
    entries = namespace_entries()
    blob = bytearray(len(entries).to_bytes(4, "little"))
    for name in sorted(entries):
        obj = entries[name]
        key = name.encode()
        blob += len(key).to_bytes(1, "little") + key
        blob += int(obj.kind).to_bytes(1, "little")
        blob += obj.schema_version.to_bytes(4, "little")
        blob += len(obj.references).to_bytes(4, "little")
        for reference in obj.references:
            blob += reference
        blob += len(obj.body).to_bytes(4, "little") + obj.body
    return bytes(blob)


TABLE = namespace_blob()


def walk(environment):
    """Resolve every type occurrence and every platform entity in the parsed carrier."""
    p = environment["p"]
    E = environment
    get = E["get"]
    add, sub, mul, c32 = E["add"], E["sub"], E["mul"], E["c32"]
    eq, ne, lt = E["eq"], E["ne"], E["lt"]
    ld8, ld32, st8, st64 = E["ld8"], E["ld32"], E["st8"], E["st64"]
    byte, out_byte, out_dyn = E["byte"], E["out_byte"], E["out_dyn"]
    fail_if = E["fail"]
    strings, objects, integers = E["STRING"], E["OBJECT"], E["INTEGER"]
    kind_of, start_of, end_of = E["KIND"], E["START"], E["END"]
    first_of, next_of = E["FIRST"], E["NEXT"]

    def flag(value):
        return p.widen(value, B32)

    def div(left, right):
        return p.bin(Operation.UDIV, left, right, B32)

    def rem(left, right):
        return p.bin(Operation.UREM, left, right, B32)

    def gt(left, right):
        return p.cmp(IntCompare.UGT, left, right, B32)

    def ge(left, right):
        return p.cmp(IntCompare.UGE, left, right, B32)

    def zero(value):
        return p.cmp(IntCompare.EQ, value, c32(0), B32)

    def same(left, right):
        return p.cmp(IntCompare.EQ, left, right, B32)

    def fail_here(code):
        p.if_(zero(p["code"]), lambda _p: p.__setitem__("code", c32(code)))

    for name in ("w1", "w2", "w3", "w4", "w5", "w6", "w7", "whead", "wtail", "wub", "wul", "wuc",
                 "wdig", "weqi", "weqc", "wcur", "wval", "wrefi", "wscan", "wname", "wnlen", "wentry",
                 "wfound", "wpick", "wrefs", "wblen", "wdepth", "wmember", "wss", "wse", "wnode", "wmore"):
        p.let(name, B32, c32(0))

    def kind(node):
        return get(node, kind_of)

    def start(node):
        return get(node, start_of)

    def end(node):
        return get(node, end_of)

    def first(node):
        return get(node, first_of)

    def after(node):
        return get(node, next_of)

    def hex_char(value):
        """``0123456789abcdef`` for a computed nibble, without a branch."""
        return add(add(value, c32(48)), mul(flag(ge(value, c32(10))), c32(39)))

    def hexdump(offset, length):
        p["whead"] = offset
        p["wtail"] = add(offset, length)
        p.while_(lambda _p: lt(p["whead"], p["wtail"]),
                 lambda _p: (out_dyn(hex_char(div(flag(ld8(p["whead"])), c32(16)))),
                             out_dyn(hex_char(rem(flag(ld8(p["whead"])), c32(16)))),
                             p.__setitem__("whead", add(p["whead"], c32(1)))))

    def out_fixed(value):
        out_byte(HEX[value >> 4])
        out_byte(HEX[value & 15])

    def emit_table_entry(entry):
        out_dyn(add(c32(48), flag(ld8(entry))))
        out_byte(SPACE)
        out_dyn(add(c32(48), flag(ld8(add(entry, c32(T_SCHEMA))))))
        out_byte(SPACE)
        p["wrefs"] = ld32(add(entry, c32(T_COUNT)))
        p["wrefi"] = c32(0)
        p.while_(lambda _p: lt(p["wrefi"], p["wrefs"]),
                 lambda _p: (p.if_(gt(p["wrefi"], c32(0)), lambda _q: out_byte(COMMA)),
                             hexdump(add(add(entry, c32(T_REFS)), mul(p["wrefi"], c32(32))), c32(32)),
                             p.__setitem__("wrefi", add(p["wrefi"], c32(1)))))
        p.if_(zero(p["wrefs"]), lambda _q: out_byte(DASH))
        out_byte(SPACE)
        p["wblen"] = ld32(add(add(entry, c32(T_BODY_LEN)), mul(p["wrefs"], c32(32))))
        hexdump(add(add(entry, c32(T_BODY)), mul(p["wrefs"], c32(32))), p["wblen"])
        out_byte(NL)

    def uleb(value):
        """Encode ``value`` at the scratch buffer; its length lands in ``wul``."""
        p["wub"] = c32(E["SCRATCH"] + TABLE_SCRATCH)
        p["wul"] = c32(0)
        p["wval"] = value
        p["wuc"] = c32(1)
        p.while_(lambda _p: ne(p["wuc"], 0),
                 lambda _p: (p.__setitem__("wdig", rem(p["wval"], c32(128))),
                             p.__setitem__("wval", div(p["wval"], c32(128))),
                             p.__setitem__("wuc", flag(ne(p["wval"], 0))),
                             st8(add(p["wub"], p["wul"]),
                                 p.op1(Operation.INT_TRUNCATE,
                                       (add(p["wdig"], mul(p["wuc"], c32(128))),), bits_type(8))),
                             p.__setitem__("wul", add(p["wul"], c32(1)))))

    def emit_type_head():
        """``4 1 - ``: a scalar type object, schema 1, no references."""
        out_byte(ord("4"))
        out_byte(SPACE)
        out_byte(ord("1"))
        out_byte(SPACE)
        out_byte(DASH)
        out_byte(SPACE)

    def emit_bits(width):
        emit_type_head()
        out_fixed(0x01)
        uleb(width)
        hexdump(p["wub"], p["wul"])
        out_byte(NL)

    def emit_view(extent):
        emit_type_head()
        for value in (0x04, 0x81, 0x02, 0x01, 0x04):
            out_fixed(value)
        uleb(extent)
        hexdump(p["wub"], p["wul"])
        out_fixed(0x00)
        out_byte(NL)

    def bytes_eq(offset, literal):
        """The input bytes at ``offset`` equal the literal (the literal is compile-time, so unrolled)."""
        terms = [eq(byte(add(offset, c32(index))), value) for index, value in enumerate(literal)]
        if not terms:
            return c32(1)
        return p.all_of(*terms)

    def span_eq(offset, stop, literal):
        """The input span equals the literal (length and every byte)."""
        return p.all_of(bytes_eq(offset, literal), eq(sub(stop, offset), len(literal)))

    def span_prefix(offset, stop, literal):
        """The input span starts with the literal."""
        return p.all_of(bytes_eq(offset, literal), ge(sub(stop, offset), c32(len(literal))))

    def span_eq_span(left_start, left_stop, right_start, right_stop):
        p["weqi"] = c32(0)
        p["weqc"] = c32(0)
        p["wval"] = sub(left_stop, left_start)
        p.while_(lambda _p: lt(p["weqc"], p["wval"]),
                 lambda _p: (p.__setitem__("weqi",
                                           add(p["weqi"], flag(same(byte(add(left_start, p["weqc"])),
                                                                    byte(add(right_start, p["weqc"])))))),
                             p.__setitem__("weqc", add(p["weqc"], c32(1)))))
        return p.all_of(same(p["wval"], sub(right_stop, right_start)), same(p["weqi"], p["wval"]))

    def parse_uint(offset, stop, limit):
        """The decimal integer in the span, into ``wval``; refuses anything else."""
        p["wval"] = c32(0)
        p["wcur"] = offset
        p.while_(lambda _p: lt(p["wcur"], stop),
                 lambda _p: (p.__setitem__("wdig", sub(byte(p["wcur"]), c32(48))),
                             fail_if(gt(p["wdig"], c32(9)), UNKNOWN_TYPE),
                             p.__setitem__("wval", add(mul(p["wval"], c32(10)), p["wdig"])),
                             p.__setitem__("wcur", add(p["wcur"], c32(1)))))
        fail_if(gt(p["wval"], c32(limit)), UNKNOWN_TYPE)

    def lookup(offset, stop):
        """The embedded entry for the name span, into ``wentry`` (0 when absent)."""
        p["wentry"] = c32(0)
        p["wscan"] = c32(E["NS"] + 4)
        p["wcur"] = c32(0)
        p["wname"] = ld32(c32(E["NS"]))
        p.while_(lambda _p: p.all_of(lt(p["wcur"], p["wname"]), zero(p["wentry"])),
                 lambda _p: (p.__setitem__("wnlen", flag(ld8(p["wscan"]))),
                             p.__setitem__("weqi", c32(0)),
                             p.__setitem__("weqc", c32(0)),
                             p.while_(lambda _q: lt(p["weqc"], p["wnlen"]),
                                      lambda _q: (p.__setitem__("weqi",
                                                                add(p["weqi"], flag(same(
                                                                    byte(add(offset, p["weqc"])),
                                                                    flag(ld8(add(add(p["wscan"], c32(1)),
                                                                                p["weqc"]))))))),
                                                  p.__setitem__("weqc", add(p["weqc"], c32(1))))),
                             p.__setitem__("wval", add(add(p["wscan"], c32(1)), p["wnlen"])),
                             p.if_(p.all_of(same(p["weqi"], p["wnlen"]), same(sub(stop, offset), p["wnlen"])),
                                   lambda _q: p.__setitem__("wentry", p["wval"])),
                             p.__setitem__("wrefs", ld32(add(p["wval"], c32(T_COUNT)))),
                             p.__setitem__("wblen", ld32(add(add(p["wval"], c32(T_BODY_LEN)),
                                                             mul(p["wrefs"], c32(32))))),
                             p.__setitem__("wscan", add(add(add(p["wval"], c32(T_BODY)),
                                                           mul(p["wrefs"], c32(32))), p["wblen"])),
                             p.__setitem__("wcur", add(p["wcur"], c32(1)))))
        return p["wentry"]

    def find_member(container, offset, stop):
        """The member node of ``container`` whose key is the span (0 when absent)."""
        p["wfound"] = c32(0)
        p.if_(ne(container, 0),
              lambda _q: (p.__setitem__("wcur", first(container)),
                          p.while_(lambda _r: p.all_of(ne(p["wcur"], 0), zero(p["wfound"])),
                                   lambda _r: (p.if_(span_eq_span(start(p["wcur"]), end(p["wcur"]),
                                                                  offset, stop),
                                                     lambda _s: p.__setitem__("wfound", p["wcur"])),
                                               p.__setitem__("wcur", after(p["wcur"]))))))
        return p["wfound"]

    def nth_value(node, name):
        """The value node of the first member ``name`` of an object (0 when absent)."""
        p["wentry"] = c32(0)
        p.if_(ne(node, 0),
              lambda _q: (p.__setitem__("wcur", first(node)),
                          p.while_(lambda _r: p.all_of(ne(p["wcur"], 0), zero(p["wentry"])),
                                   lambda _r: (p.if_(span_eq(start(p["wcur"]), end(p["wcur"]), name),
                                                     lambda _s: p.__setitem__("wentry",
                                                                              first(p["wcur"]))),
                                               p.__setitem__("wcur", after(p["wcur"]))))))
        return p["wentry"]

    def nth(array, index):
        """The ``index``-th child of an array."""
        p["wpick"] = first(array)
        p["wcur"] = c32(0)
        p.while_(lambda _p: lt(p["wcur"], c32(index)),
                 lambda _p: (p.__setitem__("wpick", after(p["wpick"])),
                             p.__setitem__("wcur", add(p["wcur"], c32(1)))))
        return p["wpick"]

    def emit_platform(offset, stop, code):
        """``win32.<name>``: strip the prefix, look the declaration up, refuse a miss."""
        p.if_(span_prefix(offset, stop, PREFIX),
              lambda _q: (p.__setitem__("wentry", lookup(add(offset, c32(len(PREFIX))), stop)),
                          fail_if(zero(p["wentry"]), code),
                          p.if_(ne(p["wentry"], 0), lambda _r: emit_table_entry(p["wentry"]))),
              lambda _q: fail_here(code))

    def emit_type_node(node):
        p.if_(eq(kind(node), strings),
              lambda _q: emit_type_spec(start(node), end(node)),
              lambda _q: emit_type_object(node))

    def emit_type_spec(offset, stop):
        """Follow the carrier's alias map at run time -- bounded, so a cycle is refused -- then emit."""
        p["wss"] = offset
        p["wse"] = stop
        p["wnode"] = c32(0)
        p["wmore"] = c32(1)
        p["wdepth"] = c32(0)
        p.while_(lambda _p: p.all_of(ne(p["wmore"], 0), lt(p["wdepth"], c32(DEPTH_LIMIT))),
                 lambda _p: (p.__setitem__("wmore", c32(0)),
                             p.__setitem__("wmember", find_member(TYPES, p["wss"], p["wse"])),
                             p.if_(ne(p["wmember"], 0),
                                   lambda _q: p.if_(eq(kind(first(p["wmember"])), strings),
                                                    lambda _r: (p.__setitem__("wss", start(first(p["wmember"]))),
                                                                p.__setitem__("wse", end(first(p["wmember"]))),
                                                                p.__setitem__("wdepth", add(p["wdepth"], c32(1))),
                                                                p.__setitem__("wmore", c32(1))),
                                                    lambda _r: p.__setitem__("wnode", first(p["wmember"]))))))
        fail_if(ne(p["wmore"], 0), UNKNOWN_TYPE)
        p.if_(ne(p["wnode"], 0), lambda _q: emit_type_object(p["wnode"]),
              lambda _q: emit_bits_or_platform(p["wss"], p["wse"]))

    def emit_type_object(node):
        def as_view(_q):
            member = first(node)
            good = p.all_of(ne(member, 0), span_eq(start(member), end(member), b"view"),
                            zero(after(member)), eq(kind(first(member)), integers))
            p.if_(good,
                  lambda _r: (parse_uint(start(first(first(node))), end(first(first(node))), (1 << 28) - 1),
                              emit_view(p["wval"])),
                  lambda _r: fail_here(UNKNOWN_TYPE))

        p.if_(eq(kind(node), objects), as_view, lambda _q: fail_here(UNKNOWN_TYPE))

    def emit_bits_or_platform(offset, stop):
        is_bits = p.all_of(eq(byte(offset), ord("b")), gt(sub(stop, offset), c32(1)))
        p.if_(is_bits, lambda _q: emit_bits_spec(offset, stop),
              lambda _q: emit_platform(offset, stop, UNKNOWN_TYPE))

    def emit_bits_spec(offset, stop):
        fail_if(eq(byte(add(offset, c32(1))), 48), UNKNOWN_TYPE)  # no leading zero
        parse_uint(add(offset, c32(1)), stop, 64)
        fail_if(zero(p["wval"]), UNKNOWN_TYPE)
        emit_bits(p["wval"])

    def emit_entity_node(node):
        p.if_(eq(kind(node), strings),
              lambda _q: emit_platform(start(node), end(node), UNKNOWN_ENTITY),
              lambda _q: (out_byte(ord("?")), out_byte(NL)))

    def each(container, cursor, body):
        p[cursor] = first(container)
        p.while_(lambda _p: ne(p[cursor], 0),
                 lambda _p: (body(p[cursor]), p.__setitem__(cursor, after(p[cursor]))))

    def each_type_list(list_node, cursor):
        p.if_(ne(list_node, 0), lambda _q: each(list_node, cursor, emit_type_node))

    def each_member(container, name, cursor, body):
        """For each member of ``container`` named ``name``, hand its value to ``body``."""
        p.if_(ne(container, 0),
              lambda _q: (p.__setitem__(cursor, first(container)),
                          p.while_(lambda _r: ne(p[cursor], 0),
                                   lambda _r: (p.if_(span_eq(start(p[cursor]), end(p[cursor]), name),
                                                     lambda _s: body(first(p[cursor]))),
                                               p.__setitem__(cursor, after(p[cursor]))))))

    def per_node(node):
        operation = first(node)
        is_const = span_eq(start(operation), end(operation), b"const")
        p.if_(is_const, lambda _q: emit_type_node(nth(node, 1)),
              lambda _q: (each(nth(node, 2), "w5", emit_type_node),
                          p.if_(ne(nth(node, 3), 0),
                                lambda _r: each_member(nth(node, 3), b"entity", "w6", emit_entity_node))))

    def per_block(block):
        each_type_list(nth_value(block, b"params"), "w7")
        nodes = nth_value(block, b"nodes")
        p.if_(ne(nodes, 0), lambda _q: each(nodes, "w4", per_node))

    def per_function(function):
        each_type_list(nth_value(function, b"params"), "w7")
        each_type_list(nth_value(function, b"returns"), "w7")
        blocks = nth_value(function, b"blocks")
        p.if_(ne(blocks, 0), lambda _q: each(blocks, "w3", per_block))

    # the embedded namespace must be in the view before anything is resolved
    for index in range(0, len(TABLE), 8):
        chunk = TABLE[index:index + 8].ljust(8, b"\0")
        st64(c32(E["NS"] + index), p.const(int.from_bytes(chunk, "little"), B64))

    root = p["root"]
    TYPES = nth_value(root, b"types")
    p["wdepth"] = c32(0)
    p.if_(ne(TYPES, 0), lambda _q: each(TYPES, "w1", lambda member: emit_type_node(first(member))))
    functions = nth_value(root, b"functions")
    p.if_(ne(functions, 0), lambda _q: each(functions, "w2", per_function))


def build_resolver():
    return R.build_reader(b"xax-construct-resolve", walk)


# -- the oracle ----------------------------------------------------------------------------------------


def object_of(line: str) -> SemanticObject:
    """Decode one produced line into the object it denotes (the check's own reading of the bytes)."""
    kind, schema, refs, body = line.split(" ")
    references = () if refs == "-" else tuple(bytes.fromhex(item) for item in refs.split(","))
    return SemanticObject.create(Kind(int(kind)), bytes.fromhex(body), references, int(schema))


def reference_line(builder, spec, entity: bool) -> tuple[str, bytes]:
    obj = builder.entity(spec) if entity else builder.type(spec)
    references = ",".join(reference.hex() for reference in obj.references) or "-"
    return f"{int(obj.kind)} {obj.schema_version} {references} {obj.body.hex()}", obj.cid


def expected_lines(request: dict) -> list[tuple[str, bytes]]:
    """The reference's line and CID for each spec the program walks, in the same order."""
    import xax_construct as C

    builder = C._Builder(request)
    lines: list[tuple[str, bytes]] = []
    for _name, spec in request.get("types", {}).items():
        lines.append(reference_line(builder, spec, False))
    for record in request.get("functions", []):
        for spec in list(record.get("params", [])) + list(record.get("returns", [])):
            lines.append(reference_line(builder, spec, False))
        for block in record.get("blocks", []):
            for spec in block.get("params", []):
                lines.append(reference_line(builder, spec, False))
            for node in block.get("nodes", []):
                if node[0] == "const":
                    lines.append(reference_line(builder, node[1], False))
                else:
                    for spec in node[2]:
                        lines.append(reference_line(builder, spec, False))
                    extra = node[3] if len(node) == 4 else {}
                    if "entity" in extra:
                        spec = extra["entity"]
                        if isinstance(spec, dict):
                            lines.append(("?", b""))
                        else:
                            lines.append(reference_line(builder, spec, True))
    return lines


def check(out: Path, carriers: list[Path]) -> int:
    executable, target = out / "resolve.exe", out / "resolve-listing.txt"
    good = True
    for carrier in carriers:
        target.unlink(missing_ok=True)
        result = subprocess.run([str(executable), str(carrier), str(target)],
                                capture_output=True, text=True)
        produced = target.read_text(encoding="ascii").splitlines() if target.exists() else []
        expected = expected_lines(json.loads(carrier.read_text(encoding="ascii")))
        resolved = sum(1 for line, _cid in expected if line != "?")
        deferred = len(expected) - resolved
        if result.returncode != 0 or len(produced) != len(expected):
            good = False
            print(f"carrier   {carrier.name:26} exit={result.returncode} lines={len(produced)}/{len(expected)} DIFF")
            if result.stderr.strip():
                print(f"          {result.stderr.strip()[:200]}")
            continue
        wrong = [index for index, (got, (want, _cid)) in enumerate(zip(produced, expected)) if got != want]
        if not wrong:
            # identity, not text: hash what the program wrote and compare the object's CID
            wrong = [index for index, (got, (_want, cid)) in enumerate(zip(produced, expected))
                     if got != "?" and object_of(got).cid != cid]
        good = good and not wrong
        if wrong:
            index = wrong[0]
            print(f"carrier   {carrier.name:26} exit=0 lines={len(produced)} resolved={resolved} "
                  f"deferred={deferred} DIFF at {wrong[:3]}")
            print(f"          got  {produced[index][:120]}")
            print(f"          want {expected[index][0][:120]}")
        else:
            print(f"carrier   {carrier.name:26} exit=0 lines={len(produced)} resolved={resolved} "
                  f"deferred={deferred} MATCH")
    return 0 if good else 1


def main(argv):
    out = Path(argv[1])
    carriers = [Path(item) for item in argv[2:] if not item.startswith("--")]
    store, snapshot, artifact = build_resolver()
    out.mkdir(parents=True, exist_ok=True)
    (out / "resolve.xax").write_bytes(store.canonical_bytes())
    (out / "resolve-snapshot.xax").write_bytes(snapshot.canonical_bytes())
    (out / "resolve.exe").write_bytes(artifact.artifact)
    entry = next(item for item in store.objects() if item.kind == Kind.FUNCTION)
    print(f"entry     {store.root_cid.hex()}")
    print(f"entry fn  {entry.cid.hex()}")
    print(f"store     {len(store.canonical_bytes())} bytes")
    print(f"artifact  {len(artifact.artifact)} bytes")
    print(f"namespace {len(TABLE)} bytes, {len(namespace_entries())} entries")
    if "--check" in argv:
        return check(out, carriers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
