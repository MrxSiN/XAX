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
* ``win32.<name>`` -- the platform namespace, embedded as authoring data by ``namespace_layout`` from
  ``xax_platform.win32_kernel32_api`` and ``win32_stdio_api``, read exactly as ``xax_construct`` reads
  them,
* ``{"view": EXTENT}`` -- the heap-view type,
* entities that are ``win32.<name>`` strings: the platform declarations are already in the blob,
* ``{"win32.import": [DLL, SYMBOL, IN, OUT]}`` and ``{"win32.virtual_free_view": [TYPE, EXTENT]}`` --
  declarations whose body embeds the *CIDs* of their signature types.  Those CIDs are hashed in the
  program: the object's canonical content (``XAX-SEM-1``, kind, schema, references, body) is staged in
  the view and hashed by ``xax_selfhost_blake3.hash_span_function``, the committed S2 graph over one
  view (a program that owns its memory holds one effect token, so it cannot lend the two views
  ``hash_function`` asks for).
* every function's graph: the constants its nodes carry, the ``GRAPH_FRAGMENT`` (blocks, nodes,
  operands as value references, terminators) and the ``FUNCTION`` that names it, with the reference
  list sorted by CID exactly as ``xax_compiler.graph_fragment`` sorts it.  ``{"fn": NAME}`` resolves to
  the function built earlier in the same walk.

What does not, yet
------------------

The store: this program emits the objects in the writer's batch shape, up to and including the snapshot that
is the canonical store's root; writing the container bytes from them is step 5c.  An unknown name is a
refusal (exit 11 for a type, 12 for an entity, 13 for a malformed graph), never a guess.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import reader as R  # noqa: E402
from xax_compiler import (ATTRIBUTE_OPERATIONS, ENTITY_OPERATIONS, IntCompare, Kind, Operation,  # noqa: E402
                          Permission, SemanticObject, bits_type, constant, heap_view_type, object_with_refs,
                          pointer_type, x86_64_windows_pe_target)
from xax_structured import B32, B64  # noqa: E402
from xax_platform import win32_kernel32_api, win32_stdio_api  # noqa: E402
from xax_selfhost_blake3 import (DIGEST_OFFSET, SCRATCH_EXTENT, SCRATCH_POINTER, SCRATCH_VIEW,  # noqa: E402
                                 hash_span_function)
import xax_selfhost_writer as WR  # noqa: E402

HEX = b"0123456789abcdef"
SPACE, NL, COMMA, DASH = 32, 10, 44, 45
PREFIX = b"win32."
UNKNOWN_TYPE, UNKNOWN_ENTITY = 11, 12
DEPTH_LIMIT = 8              # alias chain bound: the reference recurses, this refuses
DOMAIN = b"XAX-SEM-1"        # the canonical content's domain separator (xax_compiler.semantic_cid)
FF_PREFIX, FF_ABI = b"foreign-function-v1", b"win64-c"
B8 = bits_type(8)

# Regions of the view the resolver stages objects in.  They start past the embedded namespace and the
# name tables, so nothing overlaps the carrier transport, the parsed tree or the tables.  One object's
# canonical content is at most ``CANON_CAP`` bytes (domain, kind, schema, the reference table and the
# body), and the hash's own chaining values and digest have to sit past it: the hash reads the whole
# canonical span while it uses the scratch, so a scratch inside the span would corrupt the digest of
# any object larger than the gap -- which is exactly what a multi-KiB graph is.
CANON = 0xEB0000
CANON_CAP = 0x31000         # domain + kind + schema + REF_CAP refs + REF_CAP * 32 + BODY_CAP
HASH_SCRATCH = CANON + CANON_CAP + 0x1000
DBODY = HASH_SCRATCH + 0x2000   # a declaration's identity, up to a few KiB
DBODY_CAP = 0x10000
DBOFF = 4                   # room for the identity's length prefix (a uleb of at most four bytes)
ALIGNED = pointer_type(B8, Permission.READ_WRITE, 4, space=2)  # the view base, word-aligned
HASH: dict = {}

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


def namespace_layout() -> tuple[bytes, dict[str, int]]:
    """The embedded table and the offset of each entry's kind byte.

    The table is the decode-time lookup for ``win32.<name>``; the offsets let a declaration that names a
    platform type (``b64``, ``b32``, ``memory_effect``) address it without a run-time name scan."""
    entries = namespace_entries()
    blob = bytearray(len(entries).to_bytes(4, "little"))
    offsets: dict[str, int] = {}
    for name in sorted(entries):
        obj = entries[name]
        key = name.encode()
        offsets[name] = len(blob) + 1 + len(key)
        blob += len(key).to_bytes(1, "little") + key
        blob += int(obj.kind).to_bytes(1, "little")
        blob += obj.schema_version.to_bytes(4, "little")
        blob += len(obj.references).to_bytes(4, "little")
        for reference in obj.references:
            blob += reference
        blob += len(obj.body).to_bytes(4, "little") + obj.body
    return bytes(blob), offsets


TABLE, TABLE_OFFSETS = namespace_layout()

# The platform target is a fixed object for the platform this program is authored for, exactly like the
# namespace table above: a carrier names its platform, and one that names another is a refusal (the
# embedded target is the Windows PE target), never a build request that lies about what it builds.
_TARGET = x86_64_windows_pe_target()
assert _TARGET.kind is Kind.TARGET and _TARGET.schema_version == 1 and not _TARGET.references
TARGET_BODY = _TARGET.body
RESOLVER_IDENTITY = b"xax-construct-v1"   # the resolver identity xax_construct.construct names

# Regions the graph encoder stages in.  One view holds the carrier, the canonical area, its hash and
# every buffer one function's graph needs, so encoding a function is one effect token's work.  Each
# region is followed by its neighbour, and each multi-slot region is sized by the cap it enforces, so a
# wider carrier is refused rather than silently overwriting the next region.
BODY = DBODY + DBODY_CAP    # a graph or function body under construction
BODY_CAP = 0x20000
REFS = BODY + BODY_CAP      # the object's distinct references (REF_CAP x 32 bytes)
REF_CAP = 0x800
REF_SLOTS = REFS + REF_CAP * 32     # the reference slots in CID order
REF_POS = REF_SLOTS + REF_CAP * 32  # slot -> its position in that order
OCC = REF_POS + REF_CAP * 4         # the reference occurrences, in body order (OCC_CAP x u32)
OCC_CAP = 0x4000
NODEMAP = OCC + OCC_CAP * 4         # per block: carrier node index -> builder node index
NODE_CAP = 0x2000
BASES = NODEMAP + NODE_CAP * 4      # per block: the node map's base
NODE_COUNT = BASES + 0x800          # per block: the builder's node count
CARRIER = NODE_COUNT + 0x800        # per block: the carrier's node count
PARAMS = CARRIER + 0x800            # a function's parameter CIDs
FUNCTION_SLOTS = 16
RETURNS = PARAMS + FUNCTION_SLOTS * 32   # a function's return CIDs
CUR = RETURNS + FUNCTION_SLOTS * 32      # the CID under construction, or the reference being added
CURTYPE = CUR + 32                  # a constant's type CID
CBODY = CURTYPE + 32                # a constant's body: a width above 64 is refused, so at most 14 bytes
GRAPH_CID = CBODY + 0x40            # the graph a function wraps
MODULE_CID = GRAPH_CID + 32         # the module, for the package's reference
PACKAGE_CID = MODULE_CID + 32       # the package, for the build request
TARGET_CID = PACKAGE_CID + 32       # the platform target, for the build request
PROFILE_CID = TARGET_CID + 32       # the hermetic profile, for the build request
POLICY_CID = PROFILE_CID + 32       # the trust policy the snapshot is resolved against
REQUEST_CID = POLICY_CID + 32       # the build request, for the snapshot's reference
FUNS = REQUEST_CID + 0x40           # function name -> FUNCTION CID, for {"fn": NAME}
FUNS_CAP = 0x1000000 - FUNS         # entries are 33 + name bytes
GA = 0xEA5000               # the operation, comparison and terminator name tables

# The store half's registers.  The walk appends every object it stages to the writer's batch (in the
# batch buffer) and keeps this index in the main view: the distinct CIDs in append order (``SEEN``), a
# CID-sorted permutation of them (``SORT``), each record's batch offset (``ROFF``), the reachability
# marks (``MARK``) and the queue of records still to expand (``QUEUE``), plus one CID copied out of the
# batch for a lookup (``TMPCID``).  They sit between the parse scratch and the embedded namespace, the
# one span of the view that is unused once the tree has been parsed.
# The parser's own regions end at SCRATCH + SCRATCH_CAP (0xD11000) and the embedded namespace starts at
# NS (0xE00000); the store registers live in that gap.  Placing them anywhere below 0xD11000 would
# overwrite the node tables (START/END/FIRST/NEXT) that the walk is still reading.
SEEN = 0xD20000
SEEN_CAP = 0x2000
SORT = SEEN + 32 * SEEN_CAP
ROFF = SORT + 4 * SEEN_CAP
MARK = ROFF + 4 * SEEN_CAP
QUEUE = MARK + SEEN_CAP
TMPCID = QUEUE + 4 * SEEN_CAP
BUCKETS = 0xD7C000                 # 8192 open-addressing buckets: index + 1, 0 = empty
NEXT = BUCKETS + 4 * SEEN_CAP      # the bucket chain, one index per distinct object
BATCH_REFS = 0xD90000              # the sorted references of the object being appended (REF_CAP x 32)
BATCH_AT = 56                      # three header words and the root CID, then the records
BAD_GRAPH = 13
BAD_STORE = 14
# store diagnostics: a refusal names the stage instead of only "the store failed"
BAD_SEEN, BAD_BATCH, BAD_MISS = 20, 21, 23

# the caps have to fit their regions: a build-time invariant, not a run-time surprise
assert HASH_SCRATCH >= CANON + CANON_CAP, "the hash scratch must lie past the canonical span"
assert CANON_CAP >= REF_CAP * 32 + BODY_CAP + 16, "canonical region smaller than the widest object"
assert BODY >= DBODY + DBODY_CAP and FUNS + 512 < 0x1000000, "staging regions overlap"
assert TMPCID + 32 <= BUCKETS and NEXT + 4 * SEEN_CAP <= BATCH_REFS, "store registers overlap"
assert SEEN >= R.SCRATCH + R.SCRATCH_CAP, "the store registers overlap the parser's node tables"
assert BATCH_REFS + REF_CAP * 32 <= R.NS, "the store registers overlap the embedded namespace"
U64_LAST_SAFE = ((1 << 64) - 1 - 9) // 10   # largest accumulator a decimal digit can still extend


def graph_tables() -> tuple[bytes, bytes, bytes]:
    """The name tables the graph encoder looks operations, comparisons and terminators up in.

    An entry is ``u8 length, name, u8 value, u8 flags``: bit 0 says the operation takes an entity, bit
    1 that it takes attributes.  The names are the reference's own spellings, so a name the reference
    does not know is refused here too.
    """
    operations = bytearray()
    for member in Operation:
        name = member.name.lower().replace("_", ".").encode()
        flags = (1 if member in ENTITY_OPERATIONS else 0) | (2 if member in ATTRIBUTE_OPERATIONS else 0)
        operations += bytes((len(name),)) + name + bytes((int(member), flags))
    compares = bytearray()
    for member in IntCompare:
        name = member.name.lower().encode()
        compares += bytes((len(name),)) + name + bytes((int(member), 0))
    terminators = bytearray()
    for name, value in ((b"br", 1), (b"cbr", 2), (b"ret", 3), (b"trap", 4)):
        terminators += bytes((len(name),)) + name + bytes((value, 0))
    return bytes(operations), bytes(compares), bytes(terminators)


OP_TABLE, CMP_TABLE, TERM_TABLE = graph_tables()
GRAPH_BLOB = OP_TABLE + CMP_TABLE + TERM_TABLE


def walk(environment):
    """Resolve every type occurrence and every platform entity in the parsed carrier."""
    p = environment["p"]
    E = environment
    get = E["get"]
    add, sub, mul, c32 = E["add"], E["sub"], E["mul"], E["c32"]
    eq, ne, lt = E["eq"], E["ne"], E["lt"]
    ld8, ld32, st8, st32, st64, ld64 = E["ld8"], E["ld32"], E["st8"], E["st32"], E["st64"], E["ld64"]
    load8, load64 = E["store_load8"], E["store_load64"]
    put8, put64 = E["store_put8"], E["store_put64"]
    spec = E["store_writer"]
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
        # Branchless for the same reason as ``reader.fail_if``: one block per error site is expensive.
        p["code"] = add(p["code"], mul(flag(zero(p["code"])), c32(code)))

    for name in ("w1", "w2", "w3", "w4", "w5", "w6", "w7", "whead", "wtail", "wdig", "weqi", "weqc",
                 "wcur", "wval", "wrefi", "wscan", "wname", "wnlen", "wentry", "wfound", "wpick",
                 "wrefs", "wblen", "wdepth", "wmember", "wss", "wse", "wnode", "wmore", "wcursor",
                 "wsrc", "wcnt", "wkind", "wschema", "wrefn", "wrefsrc", "wbody", "wbodyat",
                 "wcanonlen", "wln", "wdbn", "wdbat", "w8", "w9",
                 # the store half: the batch cursor and the object count, the sorted-index and
                 # reachability registers, and one record's size while it is compacted
                 "bat", "bn", "bi", "bj", "bk", "bmid", "blo", "bhi", "bri", "brfound", "bhead",
                 "btail", "bsrc", "bdst", "bsize", "bnrefs", "bblen", "bmi", "bcount", "bstatus", "breason",
                 "bobj"):
        p.let(name, B32, c32(0))
    # the batch's records start after the three header words and the root CID; a record written at zero
    # would overwrite the header the writer reads first
    p["bat"] = c32(BATCH_AT)

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

    def table_object(entry):
        """The object fields of a table entry: kind, schema, references, body."""
        p["wkind"] = flag(ld8(entry))
        p["wschema"] = flag(ld8(add(entry, c32(T_SCHEMA))))
        p["wrefn"] = ld32(add(entry, c32(T_COUNT)))
        p["wrefsrc"] = add(entry, c32(T_REFS))
        p["wblen"] = ld32(add(add(entry, c32(T_BODY_LEN)), mul(p["wrefn"], c32(32))))
        p["wbody"] = add(add(entry, c32(T_BODY)), mul(p["wrefn"], c32(32)))

    def emit_object():
        """``<kind> <schema> <refs|-> <body>``: the native writer's batch shape."""
        out_dyn(add(c32(48), p["wkind"]))
        out_byte(SPACE)
        out_dyn(add(c32(48), p["wschema"]))
        out_byte(SPACE)
        p["wrefi"] = c32(0)
        p.while_(lambda _p: lt(p["wrefi"], p["wrefn"]),
                 lambda _p: (p.if_(gt(p["wrefi"], c32(0)), lambda _q: out_byte(COMMA)),
                             hexdump(add(p["wrefsrc"], mul(p["wrefi"], c32(32))), c32(32)),
                             p.__setitem__("wrefi", add(p["wrefi"], c32(1)))))
        p.if_(zero(p["wrefn"]), lambda _q: out_byte(DASH))
        out_byte(SPACE)
        hexdump(add(c32(CANON), p["wbodyat"]), p["wblen"])
        out_byte(NL)
        record_staged()

    # -- canonical staging: the content the store writer hashes ---------------------------------

    def canon_put(value):
        """One byte at ``CANON + wcursor``, then one past it."""
        st8(add(c32(CANON), p["wcursor"]), p.const(value, B8))
        p["wcursor"] = add(p["wcursor"], c32(1))

    def uleb_len(value):
        """The encoded length of ``uleb(value)``, into ``wln``.

        ``value`` is a ``b32``, so its encoding is one to five bytes; the length is the count of thresholds
        it reaches.  Counting in a loop would cost a block at every call site."""
        length = c32(1)
        for limit in (1 << 7, 1 << 14, 1 << 21, 1 << 28):
            length = add(length, flag(ge(value, c32(limit))))
        p["wln"] = length
        return p["wln"]

    def write_uleb(value, destination, cursor):
        """Append ``uleb(value)`` at ``destination + p[cursor]`` without a loop.

        ``value`` is a ``b32``, so five bytes always suffice and the five positions are written
        unconditionally; the caller stages what follows at the returned length, so the extra bytes are
        overwritten before they are read, or fall outside the length the object uses.  A loop here would
        cost three blocks at every call site, and call sites are what makes the program expensive to
        verify."""
        p["wval"] = value
        length = c32(1)
        for index in range(5):
            digit = rem(p["wval"], c32(128))
            p["wval"] = div(p["wval"], c32(128))
            more = flag(ne(p["wval"], 0))
            st8(add(add(c32(destination), p[cursor]), c32(index)),
                p.op1(Operation.INT_TRUNCATE, (add(digit, mul(more, c32(128))),), B8))
            if index < 4:
                length = add(length, more)
        p[cursor] = add(p[cursor], length)

    def canon_uleb(value):
        """Append ``uleb(value)`` at ``CANON + wcursor``."""
        write_uleb(value, CANON, "wcursor")

    def canon_copy(offset, count):
        """Copy ``count`` bytes of the view at ``offset`` into the staging area."""
        p["wsrc"], p["wcnt"] = offset, count
        p.while_(lambda _p: ne(p["wcnt"], 0),
                 lambda _p: (st8(add(c32(CANON), p["wcursor"]), ld8(p["wsrc"])),
                             p.__setitem__("wsrc", add(p["wsrc"], c32(1))),
                             p.__setitem__("wcursor", add(p["wcursor"], c32(1))),
                             p.__setitem__("wcnt", sub(p["wcnt"], c32(1)))))

    def canon_begin(kind, schema, nrefs):
        """Start an object's canonical content: domain, kind, schema, reference count."""
        p["wcursor"] = c32(0)
        for value in DOMAIN:
            canon_put(value)
        canon_uleb(kind)
        canon_uleb(schema)
        canon_uleb(nrefs)

    def build_canonical():
        """Stage the object in ``wkind``/``wschema``/``wrefn``; keep the body offset and length."""
        canon_begin(p["wkind"], p["wschema"], p["wrefn"])
        p.if_(ne(p["wrefn"], 0), lambda _q: canon_copy(p["wrefsrc"], mul(p["wrefn"], c32(32))))
        canon_uleb(p["wblen"])
        p["wbodyat"] = p["wcursor"]
        canon_copy(p["wbody"], p["wblen"])
        p["wcanonlen"] = p["wcursor"]

    def set_scalar_object(kind, refs, body_len):
        p["wkind"], p["wschema"], p["wrefn"] = c32(kind), c32(1), c32(refs)
        p["wrefsrc"], p["wbody"] = c32(0), c32(0)
        p["wblen"] = body_len

    def bits_object(width):
        """A ``b<N>`` type: body ``01`` then the width."""
        set_scalar_object(4, 0, add(c32(1), uleb_len(width)))
        canon_begin(c32(4), c32(1), c32(0))
        canon_uleb(p["wblen"])
        p["wbodyat"] = p["wcursor"]
        canon_put(0x01)
        canon_uleb(width)
        p["wcanonlen"] = p["wcursor"]
        record_staged()

    def view_object(extent):
        """A heap-view type: body ``04 81 02 01 04``, extent, ``00``."""
        set_scalar_object(4, 0, add(c32(6), uleb_len(extent)))
        canon_begin(c32(4), c32(1), c32(0))
        canon_uleb(p["wblen"])
        p["wbodyat"] = p["wcursor"]
        for value in (0x04, 0x81, 0x02, 0x01, 0x04):
            canon_put(value)
        canon_uleb(extent)
        canon_put(0x00)
        p["wcanonlen"] = p["wcursor"]
        record_staged()

    def hash_canonical():
        """Hash the staged content; the digest lands at ``HASH_SCRATCH + DIGEST_OFFSET``."""
        # the scratch must lie past the span being hashed, so an object wider than the canonical region
        # is a refusal: hashing it would cover the hash's own chaining values
        fail_if(gt(p["wcanonlen"], c32(CANON_CAP)), BAD_GRAPH)
        base = p.op1(Operation.ADDRESS_OFFSET, (p["vp"],), ALIGNED, attributes=(0,))
        _pointer, view, memory = p.op(
            Operation.CALL_DIRECT,
            (base, p["vv"], p["mem"], p.const(CANON, B64), p.widen(p["wcanonlen"], B64)),
            (ALIGNED, E["view_type"], E["mem_type"]),
            entity=HASH["fn"])
        p["vv"], p["mem"] = view, memory

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

    def parse_u64(offset, stop):
        """The decimal integer in the span, into ``gshift``; refuses non-digits and overflow.

        The constant encoder writes the value little-endian out of a 64-bit shift register, so the
        value is accumulated at 64 bits: every step must keep ``10 * x + digit`` inside ``2**64 - 1``,
        which holds exactly while ``x <= (2**64 - 1 - 9) // 10``."""
        p["gshift"] = p.const(0, B64)
        p["wcur"] = offset
        p.while_(lambda _p: lt(p["wcur"], stop),
                 lambda _p: (p.__setitem__("wdig", sub(byte(p["wcur"]), c32(48))),
                             fail_if(gt(p["wdig"], c32(9)), BAD_GRAPH),
                             fail_if(p.cmp(IntCompare.UGT, p["gshift"],
                                           p.const(U64_LAST_SAFE, B64), B64), BAD_GRAPH),
                             p.__setitem__("gshift",
                                           p.bin(Operation.ADD_WRAP,
                                                 p.bin(Operation.MUL_WRAP, p["gshift"],
                                                        p.const(10, B64), B64),
                                                 p.widen(p["wdig"], B64), B64)),
                             p.__setitem__("wcur", add(p["wcur"], c32(1)))))

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
        """The ``index``-th child of an array; the index is compile-time, so the walk is unrolled."""
        p["wpick"] = first(array)
        for _ in range(index):
            p["wpick"] = after(p["wpick"])
        return p["wpick"]

    def resolve_platform(offset, stop, code):
        """``win32.<name>``: strip the prefix, look the declaration up, refuse a miss."""
        p.if_(span_prefix(offset, stop, PREFIX),
              lambda _q: (p.__setitem__("wentry", lookup(add(offset, c32(len(PREFIX))), stop)),
                          fail_if(zero(p["wentry"]), code),
                          p.if_(ne(p["wentry"], 0),
                                lambda _r: (table_object(p["wentry"]), build_canonical(), record_staged()))),
              lambda _q: fail_here(code))

    def resolve_type_node(node):
        p.if_(eq(kind(node), strings),
              lambda _q: resolve_type_spec(start(node), end(node)),
              lambda _q: resolve_type_object(node))

    def resolve_type_spec(offset, stop):
        """Follow the carrier's alias map at run time -- bounded, so a cycle is refused -- then stage."""
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
        p.if_(ne(p["wnode"], 0), lambda _q: resolve_type_object(p["wnode"]),
              lambda _q: resolve_bits_or_platform(p["wss"], p["wse"]))

    def resolve_type_object(node):
        def as_view(_q):
            member = first(node)
            good = p.all_of(ne(member, 0), span_eq(start(member), end(member), b"view"),
                            zero(after(member)), eq(kind(first(member)), integers))
            p.if_(good,
                  lambda _r: (parse_uint(start(first(first(node))), end(first(first(node))), (1 << 28) - 1),
                              view_object(p["wval"])),
                  lambda _r: fail_here(UNKNOWN_TYPE))

        p.if_(eq(kind(node), objects), as_view, lambda _q: fail_here(UNKNOWN_TYPE))

    def resolve_bits_or_platform(offset, stop):
        is_bits = p.all_of(eq(byte(offset), ord("b")), gt(sub(stop, offset), c32(1)))
        p.if_(is_bits, lambda _q: resolve_bits_spec(offset, stop),
              lambda _q: resolve_platform(offset, stop, UNKNOWN_TYPE))

    def resolve_bits_spec(offset, stop):
        fail_if(eq(byte(add(offset, c32(1))), 48), UNKNOWN_TYPE)  # no leading zero
        parse_uint(add(offset, c32(1)), stop, 64)
        fail_if(zero(p["wval"]), UNKNOWN_TYPE)
        bits_object(p["wval"])

    def resolve_type_digest(node):
        """Stage a type spec and append its CID to the declaration body under construction."""
        resolve_type_node(node)
        hash_canonical()
        db_digest()

    def resolve_platform_digest(name):
        """Append a platform type's CID (from the embedded table) to the body under construction."""
        table_object(c32(E["NS"] + TABLE_OFFSETS[name]))
        build_canonical()
        record_staged()
        hash_canonical()
        db_digest()

    def resolve_view_digest(node):
        """Append the CID of ``{"view": extent}`` to the body under construction."""
        parse_uint(start(node), end(node), (1 << 28) - 1)
        view_object(p["wval"])
        hash_canonical()
        db_digest()

    # -- declaration bodies: an ``import`` embeds the CIDs of its signature types ----------------

    def db_byte(value):
        st8(add(c32(DBODY), p["wdbn"]), value)
        p["wdbn"] = add(p["wdbn"], c32(1))

    def db_put(value):
        db_byte(p.const(value, B8))

    def db_uleb(value):
        write_uleb(value, DBODY, "wdbn")

    def db_raw(blob):
        """Append the bytes as they are (the identity's own prefix carries no length)."""
        for value in blob:
            db_put(value)

    def db_literal(blob):
        """Append ``uleb(len), bytes`` -- the reference's string encoding."""
        db_uleb(c32(len(blob)))
        db_raw(blob)

    def in8(offset):
        """One byte of the carrier at ``offset`` (node spans are offsets into the input)."""
        return p.op1(Operation.INT_TRUNCATE, (byte(offset),), B8)

    def db_span(offset, stop):
        """Append the carrier's byte span as a length-prefixed string."""
        db_uleb(sub(stop, offset))
        p["wsrc"], p["wcnt"] = offset, sub(stop, offset)
        p.while_(lambda _p: ne(p["wcnt"], 0),
                 lambda _p: (db_byte(in8(p["wsrc"])),
                             p.__setitem__("wsrc", add(p["wsrc"], c32(1))),
                             p.__setitem__("wcnt", sub(p["wcnt"], c32(1)))))

    def db_digest():
        """Append the 32-byte digest the last hash left at ``HASH_SCRATCH + DIGEST_OFFSET``."""
        p["wcnt"] = c32(0)
        p.while_(lambda _p: lt(p["wcnt"], c32(32)),
                 lambda _p: (db_byte(ld8(add(c32(HASH_SCRATCH + DIGEST_OFFSET), p["wcnt"]))),
                             p.__setitem__("wcnt", add(p["wcnt"], c32(1)))))

    def finish_declaration():
        """Prepend the identity's length: a TARGET body is ``uleb(len) + identity``."""
        p["wdbn"] = sub(p["wdbn"], c32(DBOFF))
        uleb_len(p["wdbn"])                      # the prefix's own size lands in wln
        p["wcursor"] = c32(0)
        canon_uleb(p["wdbn"])                    # the prefix bytes, at CANON
        p["wdbat"] = sub(c32(DBOFF), p["wln"])
        p["wcnt"] = c32(0)
        p.while_(lambda _p: lt(p["wcnt"], p["wln"]),
                 lambda _p: (st8(add(add(c32(DBODY), p["wdbat"]), p["wcnt"]),
                                 ld8(add(c32(CANON), p["wcnt"]))),
                             p.__setitem__("wcnt", add(p["wcnt"], c32(1)))))

    def declaration_canonical():
        """Stage the finished TARGET as the canonical object its CID covers.

        ``finish_declaration`` leaves the body at ``DBODY + wdbat`` and writes only the length prefix at
        ``CANON``, so a hash of ``CANON`` would cover the wrong bytes; the body has to be staged first.
        """
        p["wkind"], p["wschema"], p["wrefn"] = c32(6), c32(1), c32(0)
        p["wrefsrc"] = c32(0)
        p["wbody"] = add(c32(DBODY), p["wdbat"])
        p["wblen"] = add(p["wdbn"], p["wln"])
        build_canonical()

    def emit_declaration():
        """``6 1 - <body>``: a declaration, schema 1, no references."""
        out_byte(ord("6"))
        out_byte(SPACE)
        out_byte(ord("1"))
        out_byte(SPACE)
        out_byte(DASH)
        out_byte(SPACE)
        hexdump(add(c32(DBODY), p["wdbat"]), add(p["wdbn"], p["wln"]))
        out_byte(NL)
        declaration_canonical()
        record_staged()

    def list_count(array):
        """The number of children of a list node, into ``wcnt``."""
        p["wcnt"] = c32(0)
        p["wcur"] = first(array)
        p.while_(lambda _p: ne(p["wcur"], 0),
                 lambda _p: (p.__setitem__("wcur", after(p["wcur"])),
                             p.__setitem__("wcnt", add(p["wcnt"], c32(1)))))
        return p["wcnt"]

    def declaration_done(emit):
        """Write the declaration line, or leave the staged object for the caller to hash."""
        if emit:
            p.if_(zero(p["code"]), lambda _q: emit_declaration())

    def object_done(emit):
        if emit:
            emit_object()

    def entity_import(member, emit=True):
        """``{"win32.import": [DLL, SYMBOL, IN, OUT]}``: a foreign function with hashed signature CIDs."""
        def shaped(_q):
            items = first(member)
            good = p.all_of(eq(kind(items), E["ARRAY"]),
                            ne(nth(items, 3), 0), zero(after(nth(items, 3))),
                            eq(kind(nth(items, 0)), strings),
                            eq(kind(nth(items, 1)), strings),
                            eq(kind(nth(items, 2)), E["ARRAY"]),
                            eq(kind(nth(items, 3)), E["ARRAY"]))
            p.if_(good,
                  lambda _r: (p.__setitem__("wdbn", c32(DBOFF)),
                              db_raw(FF_PREFIX),
                              db_literal(FF_ABI),
                              db_span(start(nth(items, 0)), end(nth(items, 0))),
                              db_span(start(nth(items, 1)), end(nth(items, 1))),
                              db_uleb(list_count(nth(items, 2))),
                              each(nth(items, 2), "w8", resolve_type_digest),
                              db_uleb(list_count(nth(items, 3))),
                              each(nth(items, 3), "w9", resolve_type_digest),
                              finish_declaration(),
                              declaration_done(emit)),
                  lambda _r: fail_here(UNKNOWN_ENTITY))

        p.if_(eq(kind(first(member)), E["ARRAY"]), shaped, lambda _q: fail_here(UNKNOWN_ENTITY))

    def entity_free_view(member, emit=True):
        """``{"win32.virtual_free_view": [TYPE, EXTENT]}``: VirtualFree over a typed view."""
        def shaped(_q):
            items = first(member)
            good = p.all_of(eq(kind(items), E["ARRAY"]),
                            ne(nth(items, 1), 0), zero(after(nth(items, 1))),
                            eq(kind(nth(items, 1)), integers))
            p.if_(good,
                  lambda _r: (p.__setitem__("wdbn", c32(DBOFF)),
                              db_raw(FF_PREFIX),
                              db_literal(FF_ABI),
                              db_literal(b"kernel32.dll"),
                              db_literal(b"VirtualFree"),
                              db_uleb(c32(5)),
                              resolve_type_digest(nth(items, 0)),
                              resolve_platform_digest("b64"),
                              resolve_platform_digest("b32"),
                              resolve_view_digest(nth(items, 1)),
                              resolve_platform_digest("memory_effect"),
                              db_uleb(c32(2)),
                              resolve_platform_digest("b32"),
                              resolve_platform_digest("memory_effect"),
                              db_uleb(c32(2)),
                              db_uleb(c32(0)),
                              db_uleb(c32(3)),
                              finish_declaration(),
                              declaration_done(emit)),
                  lambda _r: fail_here(UNKNOWN_ENTITY))

        p.if_(eq(kind(first(member)), E["ARRAY"]), shaped, lambda _q: fail_here(UNKNOWN_ENTITY))

    def entity_name(offset, stop, emit=True):
        """``win32.<name>`` used as an entity: a declaration and an effect, never a type."""
        def named(_q):
            p["wentry"] = lookup(add(offset, c32(len(PREFIX))), stop)
            fail_if(zero(p["wentry"]), UNKNOWN_ENTITY)
            p.if_(ne(p["wentry"], 0),
                  lambda _r: (fail_if(same(flag(ld8(p["wentry"])), c32(4)), UNKNOWN_ENTITY),
                              p.if_(zero(p["code"]),
                                    lambda _s: (table_object(p["wentry"]),
                                                build_canonical(),
                                                object_done(emit)))))

        p.if_(span_prefix(offset, stop, PREFIX), named, lambda _q: fail_here(UNKNOWN_ENTITY))

    def entity_object(node, emit=True):
        """A declared entity object: import, free-view, or the function placeholder."""
        def dispatch(_q):
            member = first(node)
            p.if_(p.all_of(ne(member, 0), zero(after(member))),
                  lambda _r: p.if_(span_eq(start(member), end(member), b"win32.import"),
                                   lambda _s: entity_import(member, emit),
                                   lambda _s: p.if_(
                                       span_eq(start(member), end(member), b"win32.virtual_free_view"),
                                       lambda _t: entity_free_view(member, emit),
                                       lambda _t: p.if_(
                                           span_eq(start(member), end(member), b"fn"),
                                           lambda _u: (out_byte(ord("?")), out_byte(NL)),
                                           lambda _u: fail_here(UNKNOWN_ENTITY)))),
                  lambda _r: fail_here(UNKNOWN_ENTITY))

        p.if_(eq(kind(node), objects), dispatch, lambda _q: fail_here(UNKNOWN_ENTITY))

    def emit_type_node(node):
        """Resolve one type occurrence, then write its line (nothing if the resolution refused)."""
        resolve_type_node(node)
        p.if_(zero(p["code"]), lambda _q: emit_object())

    def emit_entity_node(node):
        p.if_(eq(kind(node), strings),
              lambda _q: entity_name(start(node), end(node)),
              lambda _q: entity_object(node))

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

    # -- step 5: graph fragments, functions and their constants --------------------------------

    for name in ("geqi", "gequ", "geqok", "gfound", "gpos", "gnlen", "gval", "gflag", "gend", "gci",
                 "gok", "gres2", "gswap", "gi", "gj", "gmin", "gcur", "gcur2", "gsh",
                 "gmore", "gb2", "gw", "gnbytes", "gslot", "gocc", "grefl", "gmap", "gbase",
                 "gcount", "gbi", "gk", "gwalk", "gopidx", "gconstn", "gconstbase", "gseq", "gop",
                 "gflags", "gmode", "gbcount", "gfuns", "gnpar", "gnret", "gtermbase", "gr",
                 "gc1", "gc2", "gc3", "gc4", "gc5", "gc6", "gc7", "gc8", "gc9", "gfun",
                 "gn", "gtag", "gblock", "gidx", "gres"):
        p.let(name, B32, c32(0))

    # the constant encoder shifts a 64-bit value one byte at a time
    p.let("gshift", B64, p.const(0, B64))

    # The operation, comparison and terminator names are authoring data from the reference enum: the
    # carrier names an operation as text, the store holds its number.
    for index in range(0, len(GRAPH_BLOB), 8):
        chunk = GRAPH_BLOB[index:index + 8].ljust(8, b"\0")
        st64(c32(GA + index), p.const(int.from_bytes(chunk, "little"), B64))

    GO_END = GA + len(OP_TABLE)
    GC_AT = GO_END
    GC_END = GC_AT + len(CMP_TABLE)

    def mixed_eq(abs_start, offset, stop):
        """Do the view's bytes at ``abs_start`` equal the carrier's bytes at ``offset..stop``?"""
        p["geqi"] = c32(0)
        p["geqok"] = c32(1)
        p["gequ"] = sub(stop, offset)
        p.while_(lambda _p: p.all_of(lt(p["geqi"], p["gequ"]), ne(p["geqok"], 0)),
                 lambda _p: (p.if_(p.cmp(IntCompare.NE, flag(ld8(add(abs_start, p["geqi"]))),
                                          byte(add(offset, p["geqi"])), B32),
                                   lambda _q: p.__setitem__("geqok", c32(0))),
                             p.__setitem__("geqi", add(p["geqi"], c32(1)))))
        return ne(p["geqok"], 0)

    def table_find(base, end_at, offset, stop):
        """Look a name span up; ``gval``/``gflag`` hold the entry and ``gfound`` says it is there.

        Entries are laid out back to back as ``len, name, value, flags``, so the next entry starts at
        ``gpos + 3 + len`` where ``len`` is *this entry's* length byte -- not the length of the name
        being looked up."""
        p["gfound"] = c32(0)
        p["gpos"] = c32(base)
        p["gnlen"] = sub(stop, offset)
        p.while_(lambda _p: p.all_of(zero(p["gfound"]), lt(p["gpos"], c32(end_at))),
                 lambda _p: (p.if_(same(flag(ld8(p["gpos"])), p["gnlen"]),
                                   lambda _q: p.if_(mixed_eq(add(p["gpos"], c32(1)), offset, stop),
                                                    lambda _r: (p.__setitem__("gfound", c32(1)),
                                                                p.__setitem__("gval", flag(ld8(add(add(p["gpos"], c32(1)), p["gnlen"])))),
                                                                p.__setitem__("gflag", flag(ld8(add(add(p["gpos"], c32(2)), p["gnlen"]))))))),
                             p.__setitem__("gpos", add(add(p["gpos"], c32(3)), flag(ld8(p["gpos"]))))))

    def digit(at):
        """Is the carrier's byte at ``at`` a decimal digit?"""
        return p.all_of(ge(byte(at), c32(48)), ge(c32(57), byte(at)))

    def require_digit(at, stop):
        """Refuse a non-digit where a decimal run must start."""
        p.if_(ge(at, stop), lambda _q: fail_here(BAD_GRAPH),
              lambda _q: p.if_(same(flag(digit(at)), c32(0)), lambda _r: fail_here(BAD_GRAPH)))

    def number(at, stop):
        """Read a decimal run into ``gval``; ``gend`` lands one past its last digit."""
        p["gval"] = c32(0)
        p["gend"] = at
        p.while_(lambda _p: p.all_of(lt(p["gend"], stop), digit(p["gend"])),
                 lambda _p: (p.__setitem__("gval", add(mul(p["gval"], c32(10)),
                                                       sub(byte(p["gend"]), c32(48)))),
                             p.__setitem__("gend", add(p["gend"], c32(1)))))

    def copy32(src, dst):
        """Copy 32 bytes of the view."""
        p["gci"] = c32(0)
        p.while_(lambda _p: lt(p["gci"], c32(32)),
                 lambda _p: (st8(add(dst, p["gci"]), ld8(add(src, p["gci"]))),
                             p.__setitem__("gci", add(p["gci"], c32(1)))))

    def capture_digest(dst):
        """Copy the last hash's digest to ``dst``."""
        p["gci"] = c32(0)
        p.while_(lambda _p: lt(p["gci"], c32(32)),
                 lambda _p: (st8(add(dst, p["gci"]), ld8(add(c32(HASH_SCRATCH + DIGEST_OFFSET), p["gci"]))),
                             p.__setitem__("gci", add(p["gci"], c32(1)))))

    def cid_eq(left, right):
        """Are the two 32-byte CIDs equal?"""
        p["gci"] = c32(0)
        p["gok"] = c32(1)
        p.while_(lambda _p: lt(p["gci"], c32(32)),
                 lambda _p: (p.if_(p.cmp(IntCompare.NE, flag(ld8(add(left, p["gci"]))),
                                          flag(ld8(add(right, p["gci"]))), B32),
                                   lambda _q: p.__setitem__("gok", c32(0))),
                             p.__setitem__("gci", add(p["gci"], c32(1)))))
        return ne(p["gok"], 0)

    def cid_less(left, right):
        """Is the CID at ``left`` byte-wise less than the one at ``right``?"""
        p["gci"] = c32(0)
        p["gres2"] = c32(0)
        p.while_(lambda _p: p.all_of(lt(p["gci"], c32(32)), zero(p["gres2"])),
                 lambda _p: (p.if_(p.cmp(IntCompare.NE, flag(ld8(add(left, p["gci"]))),
                                          flag(ld8(add(right, p["gci"]))), B32),
                                   lambda _q: p.__setitem__(
                                       "gres2",
                                       add(c32(1), flag(p.cmp(IntCompare.UGE,
                                                              flag(ld8(add(left, p["gci"]))),
                                                              flag(ld8(add(right, p["gci"]))), B32))))),
                             p.__setitem__("gci", add(p["gci"], c32(1)))))
        return same(p["gres2"], c32(1))

    def ref_slot():
        """Find ``CUR`` among the references, or append it; ``gslot`` is its slot."""
        p["gslot"] = c32(0)
        p["gfound"] = c32(0)
        p.while_(lambda _p: p.all_of(zero(p["gfound"]), lt(p["gslot"], p["grefl"])),
                 lambda _p: (p.if_(cid_eq(add(c32(REFS), mul(p["gslot"], c32(32))), c32(CUR)),
                                   lambda _q: p.__setitem__("gfound", c32(1))),
                             p.if_(zero(p["gfound"]),
                                   lambda _q: p.__setitem__("gslot", add(p["gslot"], c32(1))))))
        p.if_(zero(p["gfound"]),
              lambda _q: (fail_if(ge(p["grefl"], c32(REF_CAP)), BAD_GRAPH),
                          copy32(c32(CUR), add(c32(REFS), mul(p["grefl"], c32(32)))),
                          p.__setitem__("gslot", p["grefl"]),
                          p.__setitem__("grefl", add(p["grefl"], c32(1)))))

    def ref_collect():
        """Add ``CUR`` as a reference and log the occurrence for the write pass."""
        ref_slot()
        fail_if(ge(p["gocc"], c32(OCC_CAP)), BAD_GRAPH)
        st32(add(c32(OCC), mul(p["gocc"], c32(4))), p["gslot"])
        p["gocc"] = add(p["gocc"], c32(1))

    def gb_uleb(value):
        """Append ``uleb(value)`` at ``BODY + gcur``."""
        fail_if(ge(add(p["gcur"], c32(5)), c32(BODY_CAP)), BAD_GRAPH)
        write_uleb(value, BODY, "gcur")

    def gb_put(value):
        """One byte of a body at ``BODY + gcur``."""
        fail_if(ge(p["gcur"], c32(BODY_CAP)), BAD_GRAPH)
        st8(add(c32(BODY), p["gcur"]), p.op1(Operation.INT_TRUNCATE, (value,), B8))
        p["gcur"] = add(p["gcur"], c32(1))

    def gb_input(offset, count):
        """Copy ``count`` input bytes from ``offset`` (input-relative) into the body."""
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], count),
                 lambda _p: (gb_put(byte(add(offset, p["gi"]))),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))

    def ref_write():
        """Write the position of the next logged reference."""
        fail_if(ge(p["gocc"], c32(OCC_CAP)), BAD_GRAPH)
        p["gslot"] = ld32(add(c32(OCC), mul(p["gocc"], c32(4))))
        p["gocc"] = add(p["gocc"], c32(1))
        fail_if(ge(p["gslot"], p["grefl"]), BAD_GRAPH)
        gb_uleb(ld32(add(c32(REF_POS), mul(p["gslot"], c32(4)))))

    def sort_refs():
        """Sort the reference slots by CID; ``REF_POS[slot]`` becomes the reference's position."""
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["grefl"]),
                 lambda _p: (st32(add(c32(REF_SLOTS), mul(p["gi"], c32(4))), p["gi"]),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["grefl"]),
                 lambda _p: (p.__setitem__("gmin", p["gi"]),
                             p.__setitem__("gj", add(p["gi"], c32(1))),
                             p.while_(lambda _q: lt(p["gj"], p["grefl"]),
                                      lambda _q: (p.if_(cid_less(add(c32(REFS), mul(ld32(add(c32(REF_SLOTS), mul(p["gj"], c32(4)))), c32(32))),
                                                                 add(c32(REFS), mul(ld32(add(c32(REF_SLOTS), mul(p["gmin"], c32(4)))), c32(32)))),
                                                          lambda _r: p.__setitem__("gmin", p["gj"])),
                                                  p.__setitem__("gj", add(p["gj"], c32(1))))),
                             p.if_(p.cmp(IntCompare.NE, p["gmin"], p["gi"], B32),
                                   lambda _q: (p.__setitem__("gswap", ld32(add(c32(REF_SLOTS), mul(p["gi"], c32(4))))),
                                               st32(add(c32(REF_SLOTS), mul(p["gi"], c32(4))),
                                                    ld32(add(c32(REF_SLOTS), mul(p["gmin"], c32(4))))),
                                               st32(add(c32(REF_SLOTS), mul(p["gmin"], c32(4))), p["gswap"]))),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["grefl"]),
                 lambda _p: (st32(add(c32(REF_POS), mul(ld32(add(c32(REF_SLOTS), mul(p["gi"], c32(4)))), c32(4))), p["gi"]),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))

    def rank_of(cid_at):
        """The position of the CID in the sorted reference list."""
        p["gslot"] = c32(0)
        p["gfound"] = c32(0)
        p.while_(lambda _p: p.all_of(zero(p["gfound"]), lt(p["gslot"], p["grefl"])),
                 lambda _p: (p.if_(cid_eq(add(c32(REFS), mul(p["gslot"], c32(32))), cid_at),
                                   lambda _q: p.__setitem__("gfound", c32(1))),
                             p.if_(zero(p["gfound"]),
                                   lambda _q: p.__setitem__("gslot", add(p["gslot"], c32(1))))))
        fail_if(zero(p["gfound"]), BAD_GRAPH)
        return ld32(add(c32(REF_POS), mul(p["gslot"], c32(4))))

    def cb_put(value):
        """One byte of a constant's body at ``CBODY``."""
        st8(add(c32(CBODY), p["gcur2"]), p.op1(Operation.INT_TRUNCATE, (value,), B8))
        p["gcur2"] = add(p["gcur2"], c32(1))

    def cb_uleb(value):
        """Append ``uleb(value)`` at ``CBODY + gcur2``."""
        write_uleb(value, CBODY, "gcur2")

    def uleb_at(offset):
        """Read a uleb from the view."""
        p["gval"] = c32(0)
        p["gsh"] = c32(1)
        p["gpos"] = offset
        p["gmore"] = c32(1)
        p.while_(lambda _p: ne(p["gmore"], 0),
                 lambda _p: (p.__setitem__("gb2", flag(ld8(p["gpos"]))),
                             p.__setitem__("gval", add(p["gval"], mul(rem(p["gb2"], c32(128)), p["gsh"]))),
                             p.__setitem__("gmore", div(p["gb2"], c32(128))),
                             p.__setitem__("gsh", mul(p["gsh"], c32(128))),
                             p.__setitem__("gpos", add(p["gpos"], c32(1)))))
        return p["gval"]

    def emit_sorted_object(kind_value, schema_value):
        """``<kind> <schema> <sorted refs|-> <body>`` for the object staged at ``BODY``."""
        # kind and schema are compile-time here, so the digits are written exactly; ``48 + kind`` would
        # print one byte and turn BUILD (10) into ``1``
        for digit in str(kind_value):
            out_byte(ord(digit))
        out_byte(SPACE)
        for digit in str(schema_value):
            out_byte(ord(digit))
        out_byte(SPACE)
        p["gr"] = c32(0)
        p.while_(lambda _p: lt(p["gr"], p["grefl"]),
                 lambda _p: (p.if_(gt(p["gr"], c32(0)), lambda _q: out_byte(COMMA)),
                             hexdump(add(c32(REFS), mul(ld32(add(c32(REF_SLOTS), mul(p["gr"], c32(4)))), c32(32))), c32(32)),
                             p.__setitem__("gr", add(p["gr"], c32(1)))))
        p.if_(zero(p["grefl"]), lambda _q: out_byte(DASH))
        out_byte(SPACE)
        hexdump(c32(BODY), p["gcur"])
        out_byte(NL)
        sorted_refs_to(c32(BATCH_REFS))
        append_record(c32(kind_value), c32(schema_value), p["grefl"], c32(BATCH_REFS), c32(BODY), p["gcur"])

    def node_is_const(node):
        """Is this carrier node the ``const`` form?"""
        return span_eq(start(first(node)), end(first(node)), b"const")

    def count_consts(container):
        """Count the inline ``[type, value]`` operands of a list node, into ``gk``."""
        p["gk"] = c32(0)
        p.if_(ne(container, 0),
              lambda _q: (p.__setitem__("gwalk", first(container)),
                          p.while_(lambda _r: ne(p["gwalk"], 0),
                                   lambda _r: (p.if_(eq(kind(p["gwalk"]), E["ARRAY"]),
                                                     lambda _s: p.__setitem__("gk", add(p["gk"], c32(1)))),
                                               p.__setitem__("gwalk", after(p["gwalk"]))))))

    def visit_type(node):
        """A type reference: resolve and collect it, or write its position."""
        p.if_(zero(p["gmode"]),
              lambda _q: (resolve_type_node(node),
                          p.if_(zero(p["code"]),
                                lambda _r: (hash_canonical(), capture_digest(c32(CUR)), ref_collect()))),
              lambda _q: ref_write())

    def visit_constant(type_node, value_node):
        """A ``const``: the constant object (the node's entity), then its type (its result)."""
        def resolved(_q):
            hash_canonical()                     # the type's own digest, not the previous hash's
            capture_digest(c32(CURTYPE))
            constant_object(value_node)
            p.if_(zero(p["code"]),
                  lambda _r: (ref_collect(),
                              copy32(c32(CURTYPE), c32(CUR)),
                              ref_collect()))

        p.if_(zero(p["gmode"]),
              lambda _q: (resolve_type_node(type_node),
                          p.if_(zero(p["code"]), resolved)))

    def constant_object(value_node):
        """Stage a ``CONSTANT``: body ``00``, ``uleb(len)``, then the value little-endian."""
        def staged(_q):
            fail_if(ne(p["wkind"], 4), BAD_GRAPH)
            fail_if(p.cmp(IntCompare.NE, flag(ld8(add(c32(CANON), p["wbodyat"]))), c32(1), B32), BAD_GRAPH)
            p["gw"] = uleb_at(add(add(c32(CANON), p["wbodyat"]), c32(1)))
            fail_if(zero(p["gw"]), BAD_GRAPH)
            fail_if(gt(p["gw"], c32(64)), BAD_GRAPH)
            p["gnbytes"] = div(add(p["gw"], c32(7)), c32(8))
            parse_u64(start(value_node), end(value_node))
            p["gcur2"] = c32(0)
            cb_put(c32(0))
            cb_uleb(p["gnbytes"])
            p["gi"] = c32(0)
            p.while_(lambda _p: lt(p["gi"], p["gnbytes"]),
                     lambda _p: (cb_put(p.bin(Operation.UREM, p["gshift"], p.const(256, B64), B64)),
                                 p.__setitem__("gshift",
                                               p.bin(Operation.UDIV, p["gshift"], p.const(256, B64), B64)),
                                 p.__setitem__("gi", add(p["gi"], c32(1)))))
            canon_begin(c32(5), c32(1), c32(1))
            canon_copy(c32(CURTYPE), c32(32))
            canon_uleb(p["gcur2"])
            canon_copy(c32(CBODY), p["gcur2"])
            p["wcanonlen"] = p["wcursor"]
            hash_canonical()
            capture_digest(c32(CUR))
            append_record(c32(5), c32(1), c32(1), c32(CURTYPE), c32(CBODY), p["gcur2"])
            out_byte(ord("5"))
            out_byte(SPACE)
            out_byte(ord("1"))
            out_byte(SPACE)
            hexdump(c32(CURTYPE), c32(32))
            out_byte(SPACE)
            hexdump(c32(CBODY), p["gcur2"])
            out_byte(NL)

        p.if_(zero(p["code"]), staged)

    def is_function_spec(node):
        """``{"fn": NAME}``: a reference to a function this walk already built."""
        member = first(node)
        return p.all_of(eq(kind(node), objects), ne(member, 0), zero(after(member)),
                        span_eq(start(member), end(member), b"fn"))

    def lookup_function(offset, stop):
        """Find the function whose name is the input span; its CID lands in ``CUR``."""
        p["gpos"] = c32(FUNS)
        p["gfound"] = c32(0)
        p.while_(lambda _p: p.all_of(zero(p["gfound"]),
                                     lt(p["gpos"], add(c32(FUNS), p["gfuns"]))),
                 lambda _p: (p.__setitem__("gnlen", flag(ld8(p["gpos"]))),
                             p.if_(p.all_of(same(p["gnlen"], sub(stop, offset)),
                                            mixed_eq(add(p["gpos"], c32(1)), offset, stop)),
                                   lambda _q: (p.__setitem__("gfound", c32(1)),
                                               copy32(add(p["gpos"], add(c32(1), p["gnlen"])), c32(CUR)))),
                             p.if_(zero(p["gfound"]),
                                   lambda _q: p.__setitem__("gpos", add(add(p["gpos"], c32(33)), p["gnlen"])))))
        fail_if(zero(p["gfound"]), BAD_GRAPH)

    def select_function(node):
        """The CID of the function named ``{"fn": NAME}``, from the function table."""
        member = first(node)
        lookup_function(start(first(member)), end(first(member)))
        p.if_(zero(p["code"]), lambda _q: ref_collect())

    def visit_entity(spec):
        p.if_(zero(p["gmode"]),
              lambda _q: p.if_(eq(kind(spec), strings),
                               lambda _r: visit_entity_name(start(spec), end(spec)),
                               lambda _r: p.if_(is_function_spec(spec),
                                                lambda _s: select_function(spec),
                                                lambda _s: visit_entity_object(spec))),
              lambda _q: ref_write())

    def visit_entity_name(offset, stop):
        def staged(_q):
            entity_name(offset, stop, False)
            p.if_(zero(p["code"]), lambda _r: (hash_canonical(), capture_digest(c32(CUR)), ref_collect()))

        staged(None)

    def visit_entity_object(node):
        def staged(_q):
            entity_object(node, False)
            p.if_(zero(p["code"]),
                  lambda _r: (declaration_canonical(),
                              hash_canonical(),
                              capture_digest(c32(CUR)),
                              ref_collect()))

        staged(None)

    def visit_entity_member(extra):
        """The node's ``entity`` reference, when the carrier carries one."""
        p.if_(ne(extra, 0),
              lambda _q: p.if_(ne(nth_value(extra, b"entity"), 0),
                               lambda _r: visit_entity(nth_value(extra, b"entity"))))

    def parse_operand(offset, stop, here):
        """``p<i>``, ``n<i>``, ``n<i>.r<k>`` or ``B<b>.n<i>`` into ``gtag/gblock/gidx/gres``."""
        p["gpos"] = offset
        p["gblock"] = here
        p["gtag"] = c32(0)
        p["gidx"] = c32(0)
        p["gres"] = c32(0)
        p.if_(same(byte(p["gpos"]), c32(ord("B"))),
              lambda _q: (p.__setitem__("gpos", add(p["gpos"], c32(1))),
                          require_digit(p["gpos"], stop),
                          number(p["gpos"], stop),
                          p.__setitem__("gblock", p["gval"]),
                          p.__setitem__("gpos", p["gend"]),
                          fail_if(ge(p["gpos"], stop), BAD_GRAPH),
                          fail_if(p.cmp(IntCompare.NE, byte(p["gpos"]), c32(ord(".")), B32), BAD_GRAPH),
                          p.__setitem__("gpos", add(p["gpos"], c32(1)))))
        p.if_(same(byte(p["gpos"]), c32(ord("n"))),
              lambda _q: p.__setitem__("gtag", c32(1)),
              lambda _q: p.if_(same(byte(p["gpos"]), c32(ord("p"))),
                               lambda _r: p.__setitem__("gtag", c32(0)),
                               lambda _r: fail_here(BAD_GRAPH)))
        p["gpos"] = add(p["gpos"], c32(1))
        require_digit(p["gpos"], stop)
        number(p["gpos"], stop)
        p["gidx"] = p["gval"]
        p["gpos"] = p["gend"]
        p.if_(lt(p["gpos"], stop),
              lambda _q: (p.__setitem__("gpos", add(p["gpos"], c32(1))),
                          p.if_(p.cmp(IntCompare.NE, byte(p["gpos"]), c32(ord("r")), B32),
                                lambda _r: fail_here(BAD_GRAPH)),
                          p.__setitem__("gpos", add(p["gpos"], c32(1))),
                          require_digit(p["gpos"], stop),
                          number(p["gpos"], stop),
                          p.__setitem__("gres", p["gval"]),
                          p.__setitem__("gpos", p["gend"])))
        fail_if(p.cmp(IntCompare.NE, p["gpos"], stop, B32), BAD_GRAPH)
        p.if_(zero(p["gtag"]), lambda _q: fail_if(ne(p["gres"], 0), BAD_GRAPH))

    def write_const_node():
        """One ``CONSTANT`` node: its entity (the constant), no operands, one result (its type)."""
        gb_uleb(c32(6))
        ref_write()
        gb_uleb(c32(0))
        gb_uleb(c32(1))
        ref_write()

    def write_operand(operand):
        """A named operand becomes a value reference; an inline constant was already a node."""
        def named(_q):
            parse_operand(start(operand), end(operand), p["gbi"])
            gb_uleb(p["gtag"])
            gb_uleb(p["gblock"])
            p.if_(zero(p["gtag"]),
                  lambda _r: gb_uleb(p["gidx"]),
                  lambda _r: (p.if_(ge(p["gbi"], p["gblock"]),
                                    lambda _s: (fail_if(ge(p["gidx"],
                                                           ld32(add(c32(CARRIER),
                                                                    mul(p["gblock"], c32(4))))),
                                                        BAD_GRAPH),
                                                p.__setitem__(
                                                    "gidx",
                                                    ld32(add(c32(NODEMAP),
                                                             add(ld32(add(c32(BASES), mul(p["gblock"], c32(4)))),
                                                                 mul(p["gidx"], c32(4))))))),
                                    lambda _s: fail_here(BAD_GRAPH)),
                              gb_uleb(p["gidx"]),
                              gb_uleb(p["gres"])))

        p.if_(eq(kind(operand), strings), named,
              lambda _q: (gb_uleb(c32(1)),
                          gb_uleb(p["gbi"]),
                          gb_uleb(add(p["gconstbase"], p["gseq"])),
                          gb_uleb(c32(0)),
                          p.__setitem__("gseq", add(p["gseq"], c32(1)))))

    def list_size(container):
        """The number of children of a list node, into ``gn``."""
        p["gn"] = c32(0)
        p.if_(ne(container, 0), lambda _q: (list_count(container), p.__setitem__("gn", p["wcnt"])))
        return p["gn"]

    def write_attribute(attr):
        p.if_(eq(kind(attr), integers),
              lambda _q: (parse_uint(start(attr), end(attr), 0xFFFFFFFF), gb_uleb(p["wval"])),
              lambda _q: (table_find(GC_AT, GC_END, start(attr), end(attr)),
                          fail_if(zero(p["gfound"]), BAD_GRAPH),
                          gb_uleb(p["gval"])))

    def write_attributes(extra):
        """``uleb(count)`` then the attribute values (numbers, or comparison names)."""
        attrs = nth_value(extra, b"attrs")
        gb_uleb(list_size(attrs))
        p.if_(ne(attrs, 0), lambda _q: each(attrs, "gc7", write_attribute))

    def write_plain_node(node):
        """One operation node: operation, entity, operands, results, attributes."""
        name = first(node)
        table_find(GA, GO_END, start(name), end(name))
        fail_if(zero(p["gfound"]), BAD_GRAPH)
        p["gop"] = p["gval"]
        p["gflags"] = p["gflag"]
        gb_uleb(p["gop"])
        p.if_(same(rem(p["gflags"], c32(2)), c32(1)),
              lambda _q: visit_entity_member(nth(node, 3)))
        gb_uleb(list_size(nth(node, 1)))
        p.if_(ne(nth(node, 1), 0), lambda _q: each(nth(node, 1), "gc5", write_operand))
        gb_uleb(list_size(nth(node, 2)))
        p.if_(ne(nth(node, 2), 0), lambda _q: each(nth(node, 2), "gc6", visit_type))
        p.if_(same(rem(div(p["gflags"], c32(2)), c32(2)), c32(1)),
              lambda _q: write_attributes(nth(node, 3)))

    def term_const_node(operand):
        """An inline constant in a terminator operand list is a node before the terminator."""
        p.if_(eq(kind(operand), E["ARRAY"]),
              lambda _q: p.if_(zero(p["gmode"]),
                               lambda _r: (visit_constant(first(operand), after(first(operand))),
                                           p.__setitem__("gk", add(p["gk"], c32(1)))),
                               lambda _r: (write_const_node(),
                                           p.__setitem__("gk", add(p["gk"], c32(1))),
                                           p.__setitem__("gseq", add(p["gseq"], c32(1))))))

    def term_const_list(container):
        p.if_(ne(container, 0), lambda _q: each(container, "gc8", term_const_node))

    def term_list(container):
        """``uleb(count)`` then the operand list's value references (``gseq`` runs across lists)."""
        gb_uleb(list_size(container))
        p.if_(ne(container, 0), lambda _q: each(container, "gc9", write_operand))

    def term_base():
        p["gtermbase"] = sub(ld32(add(c32(NODE_COUNT), mul(p["gbi"], c32(4)))), p["gk"])

    def term_edge(target_node, args):
        """One edge: the target block, then its arguments."""
        fail_if(ne(kind(target_node), integers), BAD_GRAPH)
        number(start(target_node), end(target_node))
        fail_if(p.cmp(IntCompare.NE, p["gend"], end(target_node), B32), BAD_GRAPH)
        gb_uleb(p["gval"])
        term_list(args)

    def terminator(block):
        """The block's terminator; inline constants are nodes before it, in both passes."""
        tail = nth_value(block, b"end")
        head = first(tail)
        p["gk"] = c32(0)
        p["gseq"] = c32(0)

        def ret(_q):
            term_const_list(nth(tail, 1))

            def written(_r):
                term_base()
                gb_uleb(c32(3))
                p["gconstbase"], p["gseq"] = p["gtermbase"], c32(0)
                term_list(nth(tail, 1))
            p.if_(ne(p["gmode"], 0), written)

        def br(_q):
            term_const_list(nth(tail, 2))

            def written(_r):
                term_base()
                gb_uleb(c32(1))
                p["gconstbase"], p["gseq"] = p["gtermbase"], c32(0)
                term_edge(nth(tail, 1), nth(tail, 2))
            p.if_(ne(p["gmode"], 0), written)

        def cbr(_q):
            term_const_node(nth(tail, 1))
            term_const_list(nth(tail, 3))
            term_const_list(nth(tail, 5))

            def written(_r):
                term_base()
                gb_uleb(c32(2))
                p["gconstbase"] = p["gtermbase"]
                p["gseq"] = c32(0)
                write_operand(nth(tail, 1))
                term_edge(nth(tail, 2), nth(tail, 3))
                term_edge(nth(tail, 4), nth(tail, 5))
            p.if_(ne(p["gmode"], 0), written)

        p.if_(span_eq(start(head), end(head), b"ret"), ret,
              lambda _q: p.if_(span_eq(start(head), end(head), b"br"), br,
                               lambda _r: p.if_(span_eq(start(head), end(head), b"cbr"), cbr,
                                                lambda _r: fail_here(BAD_GRAPH))))

    def collect_block(block):
        """Record the block's node map and collect its references."""
        p["gbase"] = p["gmap"]
        st32(add(c32(BASES), mul(p["gbi"], c32(4))), p["gbase"])
        params = nth_value(block, b"params")
        p.if_(ne(params, 0), lambda _q: each(params, "gc2", visit_type))
        p["gcount"] = c32(0)
        p["gj"] = c32(0)
        nodes = nth_value(block, b"nodes")
        p.if_(ne(nodes, 0), lambda _q: each(nodes, "gc3", collect_node))
        fail_if(ge(p["gj"], c32(NODE_CAP)), BAD_GRAPH)
        st32(add(c32(CARRIER), mul(p["gbi"], c32(4))), p["gj"])
        terminator(block)
        p["gcount"] = add(p["gcount"], p["gk"])
        st32(add(c32(NODE_COUNT), mul(p["gbi"], c32(4))), p["gcount"])
        p["gmap"] = add(p["gbase"], mul(p["gj"], c32(4)))
        p["gbi"] = add(p["gbi"], c32(1))

    def collect_node(node):
        """Collect one carrier node's references in body order: constants, entity, results."""
        count_consts(nth(node, 1))
        st32(add(c32(NODEMAP), add(p["gbase"], mul(p["gj"], c32(4)))), add(p["gcount"], p["gk"]))
        p.if_(node_is_const(node),
              lambda _q: visit_constant(nth(node, 1), nth(node, 2)),
              lambda _q: (p.if_(ne(nth(node, 1), 0),
                                lambda _r: each(nth(node, 1), "gc4",
                                                lambda operand: p.if_(eq(kind(operand), E["ARRAY"]),
                                                                      lambda _s: visit_constant(first(operand),
                                                                                                after(first(operand)))))),
                          visit_entity_member(nth(node, 3)),
                          p.if_(ne(nth(node, 2), 0),
                                lambda _r: each(nth(node, 2), "gc6", visit_type))))
        p["gcount"] = add(p["gcount"], add(p["gk"], c32(1)))
        p["gj"] = add(p["gj"], c32(1))

    def write_block(block):
        """Write one block: parameters, node count, nodes, terminator."""
        p["gbase"] = ld32(add(c32(BASES), mul(p["gbi"], c32(4))))
        params = nth_value(block, b"params")
        gb_uleb(list_size(params))
        p.if_(ne(params, 0), lambda _q: each(params, "gc2", visit_type))
        gb_uleb(ld32(add(c32(NODE_COUNT), mul(p["gbi"], c32(4)))))
        p["gj"] = c32(0)
        nodes = nth_value(block, b"nodes")
        p.if_(ne(nodes, 0), lambda _q: each(nodes, "gc3", write_node))
        terminator(block)
        p["gbi"] = add(p["gbi"], c32(1))

    def write_node(node):
        """One carrier node: the inline-constant nodes it needs, then the node itself."""
        count_consts(nth(node, 1))
        p["gconstn"] = p["gk"]
        p["gopidx"] = ld32(add(c32(NODEMAP), add(p["gbase"], mul(p["gj"], c32(4)))))
        p["gconstbase"] = sub(p["gopidx"], p["gconstn"])
        p["gseq"] = c32(0)
        p.if_(p.all_of(ne(nth(node, 1), 0), same(flag(node_is_const(node)), c32(0))),
              lambda _q: each(nth(node, 1), "gc4", lambda operand: p.if_(
                  eq(kind(operand), E["ARRAY"]),
                  lambda _r: (write_const_node(), p.__setitem__("gseq", add(p["gseq"], c32(1)))))))
        # the constants just written occupy ``gconstbase .. gopidx - 1``; the operand list numbers
        # them from zero again (the terminator writer does the same with its own base)
        p["gseq"] = c32(0)
        p.if_(node_is_const(node),
              lambda _q: write_const_node(),
              lambda _q: write_plain_node(node))
        p["gj"] = add(p["gj"], c32(1))

    def collect_function(function):
        """Pass one: resolve every reference the graph needs, and log them in body order."""
        p["grefl"] = c32(0)
        p["gocc"] = c32(0)
        p["gmap"] = c32(0)
        p["gbi"] = c32(0)
        p["gmode"] = c32(0)
        blocks = nth_value(function, b"blocks")
        p.if_(ne(blocks, 0), lambda _q: each(blocks, "gc1", collect_block))
        p["gbcount"] = p["gbi"]

    def emit_staged(kind_value, schema_value):
        """Canonicalise the staged references and body, hash it, and emit the object line.

        The caller has already sorted the references (so the body's ranks are final) and left the body at
        ``BODY[0..gcur]``.  ``CUR`` is left holding the object's CID, which is what the next object that
        references it copies.
        """
        canon_begin(c32(kind_value), c32(schema_value), p["grefl"])
        p["gr"] = c32(0)
        p.while_(lambda _p: lt(p["gr"], p["grefl"]),
                 lambda _p: (canon_copy(add(c32(REFS),
                                            mul(ld32(add(c32(REF_SLOTS), mul(p["gr"], c32(4)))), c32(32))),
                                        c32(32)),
                             p.__setitem__("gr", add(p["gr"], c32(1)))))
        canon_uleb(p["gcur"])
        canon_copy(c32(BODY), p["gcur"])
        p["wcanonlen"] = p["wcursor"]
        hash_canonical()
        capture_digest(c32(CUR))
        emit_sorted_object(kind_value, schema_value)

    def write_graph(function):
        """Pass two: write the body, sort the references, emit the GRAPH_FRAGMENT."""
        p["gmode"] = c32(1)
        p["gocc"] = c32(0)
        p["gcur"] = c32(0)
        p["gbi"] = c32(0)
        sort_refs()
        gb_uleb(p["gbcount"])
        gb_uleb(c32(0))
        blocks = nth_value(function, b"blocks")
        p.if_(ne(blocks, 0), lambda _q: each(blocks, "gc1", write_block))
        canon_begin(c32(7), c32(1), p["grefl"])
        p["gr"] = c32(0)
        p.while_(lambda _p: lt(p["gr"], p["grefl"]),
                 lambda _p: (canon_copy(add(c32(REFS),
                                            mul(ld32(add(c32(REF_SLOTS), mul(p["gr"], c32(4)))), c32(32))),
                                        c32(32)),
                             p.__setitem__("gr", add(p["gr"], c32(1)))))
        canon_uleb(p["gcur"])
        canon_copy(c32(BODY), p["gcur"])
        emit_staged(7, 1)

    def save_param(node):
        # the staging area is fixed, so a signature wider than it is a refusal, not an overwrite
        fail_if(ge(p["gnpar"], c32(FUNCTION_SLOTS)), BAD_GRAPH)
        resolve_type_node(node)
        p.if_(zero(p["code"]),
              lambda _q: (hash_canonical(), capture_digest(add(c32(PARAMS), mul(p["gnpar"], c32(32))))))
        p["gnpar"] = add(p["gnpar"], c32(1))

    def save_return(node):
        fail_if(ge(p["gnret"], c32(FUNCTION_SLOTS)), BAD_GRAPH)
        resolve_type_node(node)
        p.if_(zero(p["code"]),
              lambda _q: (hash_canonical(), capture_digest(add(c32(RETURNS), mul(p["gnret"], c32(32))))))
        p["gnret"] = add(p["gnret"], c32(1))

    def register_function(function):
        """Remember ``name -> FUNCTION CID`` so a later ``{"fn": NAME}`` resolves to it."""
        # the name table is fixed: a carrier with more functions than it holds is a refusal, not an overlap
        fail_if(gt(p["gfuns"], c32(FUNS_CAP - 512)), BAD_GRAPH)
        name = nth_value(function, b"name")
        p["gnlen"] = sub(end(name), start(name))
        st8(add(c32(FUNS), p["gfuns"]), p.op1(Operation.INT_TRUNCATE, (p["gnlen"],), B8))
        p["gfuns"] = add(p["gfuns"], c32(1))
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["gnlen"]),
                 lambda _p: (st8(add(c32(FUNS), add(p["gfuns"], p["gi"])),
                                 # ``start`` is input-relative; ``ld8`` reads the view
                                 ld8(add(add(c32(E["IN"]), start(name)), p["gi"]))),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))
        p["gfuns"] = add(p["gfuns"], p["gnlen"])
        copy32(c32(CUR), add(c32(FUNS), p["gfuns"]))
        p["gfuns"] = add(p["gfuns"], c32(32))

    def write_function(function):
        """The FUNCTION object: its graph, parameters and returns, all by position."""
        p["grefl"] = c32(0)
        copy32(c32(CUR), c32(GRAPH_CID))
        ref_slot()
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["gnpar"]),
                 lambda _p: (copy32(add(c32(PARAMS), mul(p["gi"], c32(32))), c32(CUR)),
                             ref_slot(),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["gnret"]),
                 lambda _p: (copy32(add(c32(RETURNS), mul(p["gi"], c32(32))), c32(CUR)),
                             ref_slot(),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))
        sort_refs()
        p["gcur"] = c32(0)
        gb_uleb(rank_of(c32(GRAPH_CID)))
        gb_uleb(p["gnpar"])
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["gnpar"]),
                 lambda _p: (gb_uleb(rank_of(add(c32(PARAMS), mul(p["gi"], c32(32))))),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))
        gb_uleb(p["gnret"])
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["gnret"]),
                 lambda _p: (gb_uleb(rank_of(add(c32(RETURNS), mul(p["gi"], c32(32))))),
                             p.__setitem__("gi", add(p["gi"], c32(1)))))
        canon_begin(c32(3), c32(1), p["grefl"])
        p["gr"] = c32(0)
        p.while_(lambda _p: lt(p["gr"], p["grefl"]),
                 lambda _p: (canon_copy(add(c32(REFS),
                                            mul(ld32(add(c32(REF_SLOTS), mul(p["gr"], c32(4)))), c32(32))),
                                        c32(32)),
                             p.__setitem__("gr", add(p["gr"], c32(1)))))
        canon_uleb(p["gcur"])
        canon_copy(c32(BODY), p["gcur"])
        emit_staged(3, 1)
        register_function(function)

    # -- the store half: the writer's batch and the reachable closure -----------------------------------

    def trunc32(value):
        return p.op1(Operation.INT_TRUNCATE, (value,), B32)

    def cid_bucket():
        """The bucket of the CID in ``CUR``: its first word is a hash, so its low bits are uniform."""
        return p.bin(Operation.BIT_AND, trunc32(ld64(c32(CUR))), c32(SEEN_CAP - 1), B32)

    def copy_to_batch(source, destination, count):
        """Copy ``count`` bytes of the main view at ``source`` to the batch at ``destination``."""
        p["bmi"] = c32(0)
        p.while_(lambda _p: lt(p["bmi"], count),
                 lambda _p: (put8("batch", add(destination, p["bmi"]), ld8(add(source, p["bmi"]))),
                             p.__setitem__("bmi", add(p["bmi"], c32(1)))))

    def copy_from_batch(source, destination, count):
        """Copy ``count`` bytes of the batch at ``source`` to the main view at ``destination``."""
        p["bmi"] = c32(0)
        p.while_(lambda _p: lt(p["bmi"], count),
                 lambda _p: (st8(add(destination, p["bmi"]), load8("batch", add(source, p["bmi"]))),
                             p.__setitem__("bmi", add(p["bmi"], c32(1)))))

    def move_batch(destination, source, count):
        """Copy ``count`` bytes forward inside the batch (``destination <= source``)."""
        p["bmi"] = c32(0)
        p.while_(lambda _p: lt(p["bmi"], count),
                 lambda _p: (put8("batch", add(destination, p["bmi"]), load8("batch", add(source, p["bmi"]))),
                             p.__setitem__("bmi", add(p["bmi"], c32(1)))))

    def sorted_refs_to(destination):
        """The object's references in CID order, contiguous at ``destination``."""
        p["gr"] = c32(0)
        p.while_(lambda _p: lt(p["gr"], p["grefl"]),
                 lambda _p: (copy32(add(c32(REFS),
                                        mul(ld32(add(c32(REF_SLOTS), mul(p["gr"], c32(4)))), c32(32))),
                                   add(destination, mul(p["gr"], c32(32)))),
                             p.__setitem__("gr", add(p["gr"], c32(1)))))

    def append_record(kind, schema, nrefs, refs_at, body_at, body_len):
        """Append the object whose CID is in ``CUR`` to the writer's batch, once.

        ``SEEN`` holds the distinct CIDs in append order; ``BUCKETS`` and ``NEXT`` chain them by the
        first word of the CID, so an occurrence costs one CID compare rather than a scan of everything
        seen so far.  The references are the contiguous table at ``refs_at`` (sorted and deduplicated
        by the caller) and the body is ``body_len`` bytes at ``body_at``; both are in the main view.
        The record is the writer's own shape: kind, schema, reference count, body length, CID,
        references, body, all 64-bit words little-endian except the CIDs and the body.
        """
        bucket = cid_bucket()
        p["bri"] = ld32(add(c32(BUCKETS), mul(bucket, c32(4))))
        p["brfound"] = c32(0)
        p.while_(lambda _p: p.all_of(ne(p["bri"], 0), eq(p["brfound"], 0)),
                 lambda _p: (p.if_(cid_eq(add(c32(SEEN), mul(sub(p["bri"], c32(1)), c32(32))), c32(CUR)),
                                   lambda _q: p.__setitem__("brfound", c32(1)),
                                   lambda _q: p.__setitem__(
                                       "bri", ld32(add(c32(NEXT), mul(sub(p["bri"], c32(1)), c32(4))))))))

        def add_new(_p):
            fail_if(ge(p["bn"], c32(SEEN_CAP)), BAD_SEEN)
            fail_if(gt(p["bat"], c32(spec["batch_extent"] - 0x10000)), BAD_BATCH)
            copy32(c32(CUR), add(c32(SEEN), mul(p["bn"], c32(32))))
            st32(add(c32(ROFF), mul(p["bn"], c32(4))), p["bat"])
            st32(add(c32(NEXT), mul(p["bn"], c32(4))), ld32(add(c32(BUCKETS), mul(bucket, c32(4)))))
            st32(add(c32(BUCKETS), mul(bucket, c32(4))), add(p["bn"], c32(1)))
            put64("batch", p["bat"], kind)
            put64("batch", add(p["bat"], c32(8)), schema)
            put64("batch", add(p["bat"], c32(16)), nrefs)
            put64("batch", add(p["bat"], c32(24)), body_len)
            copy_to_batch(c32(CUR), add(p["bat"], c32(32)), c32(32))
            p["bri"] = c32(0)
            p.while_(lambda _p: lt(p["bri"], mul(nrefs, c32(32))),
                     lambda _p: (put8("batch", add(add(p["bat"], c32(64)), p["bri"]),
                                      ld8(add(refs_at, p["bri"]))),
                                 p.__setitem__("bri", add(p["bri"], c32(1)))))
            p["bri"] = c32(0)
            p.while_(lambda _p: lt(p["bri"], body_len),
                     lambda _p: (put8("batch",
                                      add(add(p["bat"], c32(64)), add(mul(nrefs, c32(32)), p["bri"])),
                                      ld8(add(body_at, p["bri"]))),
                                 p.__setitem__("bri", add(p["bri"], c32(1)))))
            p["bat"] = add(p["bat"], add(c32(64), add(mul(nrefs, c32(32)), body_len)))
            p["bn"] = add(p["bn"], c32(1))

        p.if_(eq(p["brfound"], 0), add_new)

    def record_staged():
        """Append the object staged in ``wkind``/``wschema``/... at ``CANON`` under its own CID."""
        hash_canonical()
        capture_digest(c32(CUR))
        append_record(p["wkind"], p["wschema"], p["wrefn"], p["wrefsrc"],
                      add(c32(CANON), p["wbodyat"]), p["wblen"])

    def find_record(cid_at):
        """The index in ``SEEN`` of ``cid_at``, by binary search over ``SORT``; a miss is refused."""
        p["blo"], p["bhi"] = c32(0), p["bn"]
        p.while_(lambda _p: lt(p["blo"], p["bhi"]),
                 lambda _p: (p.__setitem__("bmid", div(add(p["blo"], p["bhi"]), c32(2))),
                             p.if_(cid_less(add(c32(SEEN), mul(ld32(add(c32(SORT),
                                                                         mul(p["bmid"], c32(4)))), c32(32))),
                                            cid_at),
                                   lambda _q: p.__setitem__("blo", add(p["bmid"], c32(1))),
                                   lambda _q: p.__setitem__("bhi", p["bmid"]))))
        fail_if(ge(p["blo"], p["bn"]), BAD_MISS)
        fail_if(ne(flag(cid_eq(add(c32(SEEN), mul(ld32(add(c32(SORT), mul(p["blo"], c32(4)))), c32(32))),
                                cid_at)), 1), BAD_MISS)
        # ``blo`` is a position in the sorted index, not the object's index: every caller that marks,
        # enqueues or reads a record has to go through ``SORT``
        p["bobj"] = ld32(add(c32(SORT), mul(p["blo"], c32(4))))

    def expand_record():
        """Mark every reference of the record at the head of the queue, and enqueue the new ones."""
        p["bk"] = ld32(add(c32(QUEUE), mul(p["bhead"], c32(4))))
        p["bhead"] = add(p["bhead"], c32(1))
        p["bsrc"] = ld32(add(c32(ROFF), mul(p["bk"], c32(4))))
        p["bnrefs"] = trunc32(load64("batch", add(p["bsrc"], c32(16))))
        p["bi"] = c32(0)
        p.while_(lambda _p: lt(p["bi"], p["bnrefs"]),
                 lambda _p: (copy_from_batch(add(p["bsrc"], add(c32(64), mul(p["bi"], c32(32)))),
                                             c32(TMPCID), c32(32)),
                             find_record(c32(TMPCID)),
                             p.if_(eq(flag(ld8(add(c32(MARK), p["bobj"]))), 0),
                                   lambda _q: (st8(add(c32(MARK), p["bobj"]), p.const(1, B8)),
                                               st32(add(c32(QUEUE), mul(p["btail"], c32(4))), p["bobj"]),
                                               p.__setitem__("btail", add(p["btail"], c32(1))))),
                             p.__setitem__("bi", add(p["bi"], c32(1)))))

    def compact_record():
        """Move the marked record at ``ROFF[bi]`` down to ``bdst``."""
        p["bsrc"] = ld32(add(c32(ROFF), mul(p["bi"], c32(4))))
        p["bnrefs"] = trunc32(load64("batch", add(p["bsrc"], c32(16))))
        p["bblen"] = trunc32(load64("batch", add(p["bsrc"], c32(24))))
        p["bsize"] = add(c32(64), add(mul(p["bnrefs"], c32(32)), p["bblen"]))
        move_batch(p["bdst"], p["bsrc"], p["bsize"])
        p["bdst"] = add(p["bdst"], p["bsize"])
        p["bcount"] = add(p["bcount"], c32(1))

    def call_writer():
        """Hand the compacted batch to the S9 writer and take the store length it reports."""
        base = p.op1(Operation.POINTER_CAST, (p["batch_p"],), WR.BATCH_POINTER)
        results = p.op(Operation.CALL_DIRECT,
                       (base, p["batch_v"], p["batch_m"],
                        p["written_p"], p["written_v"], p["written_m"],
                        p["scratch_p"], p["scratch_v"], p["scratch_m"],
                        p.const(spec["mode"], B64)),
                       tuple(spec["types"]), entity=spec["function"])
        # the callee takes the three view triples and hands them back: rebind the views and memory
        # proofs (pointers are plain values; the driver's buffers keep theirs, so does this one)
        (p["batch_v"], p["batch_m"]) = results[1], results[2]
        (p["written_v"], p["written_m"]) = results[4], results[5]
        (p["scratch_v"], p["scratch_m"]) = results[7], results[8]
        p["bstatus"] = trunc32(load64("written", c32(spec["status_at"])))
        p["breason"] = trunc32(load64("written", c32(spec["status_at"] + 8)))
        p["code"] = add(p["code"], mul(
            p.widen(p.all_of(eq(p["code"], 0), ne(p["bstatus"], spec["accept"]))),
            add(c32(0x100), add(mul(p["bstatus"], c32(0x40)), p["breason"]))))
        p["store_len"] = trunc32(load64("written", c32(spec["status_at"] + 24)))

    def finish_store():
        """Close the batch, keep the snapshot's reachable closure, compact it, and write the store.

        The batch holds every object the walk staged, in append order; the store holds the ones the
        snapshot can reach (the unresolved aliases and the signature types embedded in declaration
        bodies are staged but unreachable, and the reference store does not hold them either).  The
        marked records are compacted forward in append order, the header is patched, and the writer
        orders them by CID itself.
        """
        # a CID-sorted index: insertion sort, and the comparison stops at the first differing byte
        p["bi"] = c32(0)
        p.while_(lambda _p: lt(p["bi"], p["bn"]),
                 lambda _p: (st32(add(c32(SORT), mul(p["bi"], c32(4))), p["bi"]),
                             p.__setitem__("bi", add(p["bi"], c32(1)))))
        p["bi"] = c32(1)
        p.while_(lambda _p: lt(p["bi"], p["bn"]),
                 lambda _p: (p.__setitem__("bj", p["bi"]),
                             p.while_(lambda _q: p.all_of(
                                          gt(p["bj"], c32(0)),
                                          cid_less(add(c32(SEEN), mul(ld32(add(c32(SORT),
                                                                                 mul(p["bj"], c32(4)))),
                                                                         c32(32))),
                                                   add(c32(SEEN), mul(ld32(add(c32(SORT),
                                                                              mul(sub(p["bj"], c32(1)),
                                                                                  c32(4)))),
                                                                      c32(32))))),
                                      lambda _q: (p.__setitem__("bk", ld32(add(c32(SORT),
                                                                               mul(p["bj"], c32(4))))),
                                                  st32(add(c32(SORT), mul(p["bj"], c32(4))),
                                                       ld32(add(c32(SORT), mul(sub(p["bj"], c32(1)),
                                                                               c32(4))))),
                                                  st32(add(c32(SORT), mul(sub(p["bj"], c32(1)), c32(4))),
                                                       p["bk"]),
                                                  p.__setitem__("bj", sub(p["bj"], c32(1))))),
                             p.__setitem__("bi", add(p["bi"], c32(1)))))
        # the snapshot is the root: mark it, then close over the references
        p["bi"] = c32(0)
        p.while_(lambda _p: lt(p["bi"], p["bn"]),
                 lambda _p: (st8(add(c32(MARK), p["bi"]), p.const(0, B8)),
                             p.__setitem__("bi", add(p["bi"], c32(1)))))
        find_record(c32(CUR))
        st8(add(c32(MARK), p["bobj"]), p.const(1, B8))
        st32(add(c32(QUEUE), c32(0)), p["bobj"])
        p["bhead"], p["btail"] = c32(0), c32(1)
        p.while_(lambda _p: lt(p["bhead"], p["btail"]), lambda _p: expand_record())
        # compact the marked records forward and patch the header
        p["bdst"] = c32(BATCH_AT)
        p["bcount"] = c32(0)
        p["bi"] = c32(0)
        p.while_(lambda _p: lt(p["bi"], p["bn"]),
                 lambda _p: (p.if_(ne(flag(ld8(add(c32(MARK), p["bi"]))), 0),
                                   lambda _q: compact_record()),
                             p.__setitem__("bi", add(p["bi"], c32(1)))))
        put64("batch", c32(0), p["bcount"])
        put64("batch", c32(8), c32(0))
        put64("batch", c32(16), p["bdst"])
        copy_to_batch(c32(CUR), c32(24), c32(32))
        call_writer()

    def package_pass():
        """Step 5b: the platform target, module, package, profile, policy and build request.

        The carrier's ``package`` names one build entry, one release entry and the platform; everything
        else is fixed by the toolchain (the target, the hermetic profile, the trust policy, one native
        image).  The program therefore refuses a carrier that needs more than this pass implements: a
        non-Windows platform or more than one build entry.
        """
        platform = nth_value(p["root"], b"platform")
        fail_if(eq(platform, 0), BAD_GRAPH)
        # the embedded target is the Windows PE target; another platform is refused, not mislabelled
        fail_if(zero(flag(span_eq(start(platform), end(platform), b"windows-x86_64"))), BAD_GRAPH)
        package = nth_value(p["root"], b"package")
        fail_if(eq(package, 0), BAD_GRAPH)
        name = nth_value(package, b"name")
        entries = nth_value(package, b"entries")
        release = nth_value(package, b"release")
        fail_if(eq(name, 0), BAD_GRAPH)
        fail_if(eq(entries, 0), BAD_GRAPH)
        fail_if(eq(release, 0), BAD_GRAPH)
        member = first(entries)
        fail_if(eq(member, 0), BAD_GRAPH)
        # the reference sorts the entry names and supports any number; this pass supports one, so a
        # second entry is a refusal rather than a package with the wrong rank order
        fail_if(ne(after(member), 0), BAD_GRAPH)
        # -- the target: the fixed platform object
        p["grefl"] = c32(0)
        p["gcur"] = c32(0)
        for value in TARGET_BODY:
            gb_put(p.const(value, B32))
        emit_staged(6, 1)
        copy32(c32(CUR), c32(TARGET_CID))
        # -- the module: every constructed function, deduplicated and sorted by CID
        p["grefl"] = c32(0)
        p["gpos"] = c32(FUNS)
        p.while_(lambda _p: lt(p["gpos"], add(c32(FUNS), p["gfuns"])),
                 lambda _p: (p.__setitem__("gnlen", flag(ld8(p["gpos"]))),
                             copy32(add(p["gpos"], add(c32(1), p["gnlen"])), c32(CUR)),
                             ref_slot(),
                             p.__setitem__("gpos", add(add(p["gpos"], c32(33)), p["gnlen"]))))
        sort_refs()
        p["gcur"] = c32(0)
        gb_uleb(p["grefl"])
        p["gi"] = c32(0)
        p.while_(lambda _p: lt(p["gi"], p["grefl"]),
                 lambda _p: (gb_uleb(p["gi"]), p.__setitem__("gi", add(p["gi"], c32(1)))))
        emit_staged(2, 1)
        copy32(c32(CUR), c32(MODULE_CID))
        # -- the package: name, module, the one entry, three empty collections
        p["grefl"] = c32(0)
        copy32(c32(MODULE_CID), c32(CUR))
        ref_slot()
        lookup_function(start(first(member)), end(first(member)))
        p.if_(zero(p["code"]), lambda _q: ref_slot())
        sort_refs()
        p["gcur"] = c32(0)
        p["gnlen"] = sub(end(name), start(name))
        gb_uleb(p["gnlen"])
        gb_input(start(name), p["gnlen"])
        gb_uleb(c32(1))
        gb_uleb(rank_of(c32(MODULE_CID)))
        gb_uleb(c32(0))
        gb_uleb(c32(1))
        p["gnlen"] = sub(end(member), start(member))
        gb_uleb(p["gnlen"])
        gb_input(start(member), p["gnlen"])
        gb_uleb(rank_of(c32(CUR)))
        gb_uleb(c32(0))
        gb_uleb(c32(0))
        gb_uleb(c32(0))
        emit_staged(9, 1)
        copy32(c32(CUR), c32(PACKAGE_CID))
        # -- the profile and the trust policy: fixed forms, no references
        p["grefl"] = c32(0)
        p["gcur"] = c32(0)
        for value in (0x01, 0x01, 0x00, 0x01, 0x00):
            gb_put(p.const(value, B32))
        emit_staged(10, 1)
        copy32(c32(CUR), c32(PROFILE_CID))
        p["grefl"] = c32(0)
        p["gcur"] = c32(0)
        for value in (0x04, 0x00, 0x00, 0x00, 0x00):
            gb_put(p.const(value, B32))
        emit_staged(10, 1)
        copy32(c32(CUR), c32(POLICY_CID))
        # -- the build request: package, release entry, target, profile, one native image
        p["grefl"] = c32(0)
        for cid in (PACKAGE_CID, TARGET_CID, PROFILE_CID):
            copy32(c32(cid), c32(CUR))
            ref_slot()
        sort_refs()
        p["gcur"] = c32(0)
        gb_uleb(c32(2))
        gb_uleb(rank_of(c32(PACKAGE_CID)))
        p["gnlen"] = sub(end(release), start(release))
        gb_uleb(p["gnlen"])
        gb_input(start(release), p["gnlen"])
        gb_uleb(rank_of(c32(TARGET_CID)))
        gb_uleb(rank_of(c32(PROFILE_CID)))
        gb_uleb(c32(0))
        gb_uleb(c32(0))
        gb_uleb(c32(1))
        gb_uleb(c32(1))
        emit_staged(10, 1)
        copy32(c32(CUR), c32(REQUEST_CID))
        # -- the snapshot, which is the canonical store's root: request, resolver identity, policy, the
        #    selected packages (the request's package and its closure), no signatures, no external digests
        p["grefl"] = c32(0)
        for cid in (PACKAGE_CID, POLICY_CID, REQUEST_CID):
            copy32(c32(cid), c32(CUR))
            ref_slot()
        sort_refs()
        p["gcur"] = c32(0)
        gb_uleb(c32(3))
        gb_uleb(rank_of(c32(REQUEST_CID)))
        gb_uleb(c32(len(RESOLVER_IDENTITY)))
        for value in RESOLVER_IDENTITY:
            gb_put(p.const(value, B32))
        gb_uleb(rank_of(c32(POLICY_CID)))
        gb_uleb(c32(1))
        gb_uleb(rank_of(c32(PACKAGE_CID)))
        gb_uleb(c32(0))
        gb_uleb(c32(0))
        emit_staged(10, 1)
        p.if_(zero(p["code"]), lambda _q: finish_store())

    def graph_function(function):
        """One carrier function: its constants, its graph, then the function object."""
        p["gnpar"] = c32(0)
        p["gnret"] = c32(0)
        params = nth_value(function, b"params")
        p.if_(ne(params, 0), lambda _q: each(params, "gc1", save_param))
        returns = nth_value(function, b"returns")
        p.if_(ne(returns, 0), lambda _q: each(returns, "gc1", save_return))
        collect_function(function)
        p.if_(zero(p["code"]), lambda _q: write_graph(function))
        p.if_(zero(p["code"]), lambda _q: write_function(function))

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
    p["gfuns"] = c32(0)
    # ``graph_function`` walks the blocks and the parameter lists itself: its cursors may not be the
    # one this loop carries, or the loop would continue from inside the function it just wrote.
    p.if_(ne(functions, 0), lambda _q: each(functions, "gfun", graph_function))
    # step 5b: the target, module, package, profile, policy and request, once the function table is full
    p.if_(zero(p["code"]), lambda _q: package_pass())


def build_resolver():
    """The resolver: the reader's host, a word-aligned view, the span hash and the S9 writer linked in.

    The writer is a component store of its own; its function and the objects it needs are merged into
    this program's store, and the resolver calls it directly, so the container is written by the one
    verified writer rather than by a second implementation here."""
    hash_at, hash_objects = hash_span_function(ALIGNED, heap_view_type(R.EXTENT), HASH_SCRATCH)
    HASH["fn"] = hash_at
    writer_reader, writer = WR.load_writer_program()
    spec = {
        "function": writer,
        "types": tuple(type_ for _name, type_ in WR.VIEWS),
        "buffers": (("batch", WR.BUF_POINTER, WR.BATCH_VIEW, WR.IN_EXTENT, 1),
                    ("written", WR.BUF_POINTER, WR.BUF_VIEW, WR.BUF_EXTENT, 1),
                    ("scratch", SCRATCH_POINTER, SCRATCH_VIEW, SCRATCH_EXTENT, 4)),
        "batch_extent": WR.IN_EXTENT,
        "mode": WR.MODE_WRITE,
        "status_at": WR.STATUS_AT,
        "accept": WR.ACCEPT,
    }
    component = tuple(item for item in writer_reader.objects()
                      if item.kind not in (Kind.MODULE, Kind.PROGRAM_ROOT, Kind.TARGET))
    return R.build_reader(b"xax-construct-resolve", walk, view_alignment=4,
                          extra_objects=(*hash_objects, *component), store_writer=spec)


# -- the oracle ----------------------------------------------------------------------------------------


def object_of(line: str) -> SemanticObject:
    """Decode one produced line into the object it denotes (the check's own reading of the bytes)."""
    kind, schema, refs, body = line.split(" ")
    references = () if refs == "-" else tuple(bytes.fromhex(item) for item in refs.split(","))
    return SemanticObject.create(Kind(int(kind)), bytes.fromhex(body), references, int(schema))


def object_line(obj: SemanticObject) -> str:
    """One object's line: kind, schema, references, body -- the writer's batch shape."""
    references = ",".join(reference.hex() for reference in obj.references) or "-"
    return f"{int(obj.kind)} {obj.schema_version} {references} {obj.body.hex()}"


def reference_line(builder, spec, entity: bool) -> tuple[str, bytes]:
    obj = builder.entity(spec) if entity else builder.type(spec)
    return object_line(obj), obj.cid


def inline_constants(record: dict):
    """The inline ``[type, value]`` constants of a function, in the encoder's own walk order."""
    found = []
    for block in record.get("blocks", []):
        for node in block.get("nodes", []):
            if node[0] == "const":
                found.append((node[1], node[2]))
            else:
                found.extend((item[0], item[1]) for item in node[1] if isinstance(item, list))
        end = block["end"]
        if end[0] == "ret":
            operands = end[1]
        elif end[0] == "br":
            operands = end[2]
        else:
            operands = [end[1], *end[3], *end[5]]
        found.extend((item[0], item[1]) for item in operands if isinstance(item, list))
    return found


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
                        if isinstance(spec, dict) and "fn" in spec:
                            lines.append(("?", b""))
                        else:
                            lines.append(reference_line(builder, spec, True))
    # step 5: each function's constants, then its graph and its function object
    import xax_construct as C

    for record in request.get("functions", []):
        before = set(builder.objects)
        entry = builder.function(record)
        fresh = [builder.objects[cid] for cid in set(builder.objects) - before]
        for spec, value in inline_constants(record):
            obj = constant(builder.type(spec), value)
            lines.append((object_line(obj), obj.cid))
        graph = next(item for item in fresh if item.kind == Kind.GRAPH_FRAGMENT)
        lines.append((object_line(graph), graph.cid))
        lines.append((object_line(entry), entry.cid))
    # step 5b: the target, module, package, profile, policy and request, in the program's order
    import xax_build as B

    spec = request["package"]
    build_entries = tuple((entry.encode(), builder.functions[function])
                          for entry, function in sorted(spec["entries"].items()))
    module = object_with_refs(Kind.MODULE, tuple(builder.functions.values()))
    app = B.package(spec["name"].encode(), (module,), build_entries=build_entries)
    profile, policy = B.build_profile(), B.trust_policy()
    build = B.build_request(app, spec["release"].encode(), builder.target, profile,
                            requested_artifacts=(builder.artifact,))
    for obj in (builder.target, module, app, profile, policy, build):
        lines.append((object_line(obj), obj.cid))
    # the snapshot is the canonical store's root: the request, the resolver identity, the policy and the
    # selected packages (the request's package and its dependency closure, which is just the package here)
    resolution = B.resolve_packages(
        build,
        (*builder.objects.values(), *builder.platform_types, module, app, builder.target, profile, policy, build),
        policy, b"xax-construct-v1")
    lines.append((object_line(resolution.snapshot), resolution.snapshot.cid))
    return lines


def check(out: Path, carriers: list[Path]) -> int:
    import json

    import xax_construct as C
    from xax_compiler import StoreReader

    executable, target = out / "resolve.exe", out / "resolve-listing.txt"
    store_path = out / "resolve-store.xax"
    good = True
    for carrier in carriers:
        target.unlink(missing_ok=True)
        store_path.unlink(missing_ok=True)
        result = subprocess.run([str(executable), str(carrier), str(target), str(store_path)],
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
        # the container is the oracle's own bytes, not a re-encoding of them
        reference = C.construct(json.loads(carrier.read_text(encoding="ascii"))).reader.canonical_bytes()
        store = store_path.read_bytes() if store_path.exists() else b""
        store_ok = store == reference
        good = good and store_ok
        if store_ok:
            root = StoreReader(store).root_cid
            print(f"store     {carrier.name:26} {len(store):>8} bytes / {len(reference):>8} root {root.hex()[:16]} MATCH")
        else:
            print(f"store     {carrier.name:26} {len(store):>8} bytes / {len(reference):>8} DIFF")
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
