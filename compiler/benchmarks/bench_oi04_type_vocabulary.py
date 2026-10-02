"""OI-04 compact type-vocabulary comparison (tooling-only evidence).

Question: which type forms (common ``bits<N>`` widths, a small float-format
candidate set, other high-frequency forms) should get dedicated pre-interned
IDs instead of structural descriptors referenced by 32-byte CID?

Arms:

* ``structural``: the canonical store, unchanged.
* catalog arms: a measurement-only alias container.  Every reference to a
  catalog type is written as a small catalog index instead of a 32-byte CID,
  and the catalog type objects themselves are omitted.  Decoding expands each
  index to the exact structural descriptor, re-derives every CID and rebuilds
  the canonical store, which must be byte-identical to ``structural``.  The
  catalog therefore never creates a second identity for a type.
* ``cid_dictionary``: a catalog-free measurement-only container.  Any CID
  referenced by at least two semantic objects is placed in a deterministic
  store-wide dictionary and referenced by a small index; one-use CIDs stay
  explicit.  The dictionary is carried in the store, so unlike the fixed type
  catalog it gets no external-vocabulary advantage.  Decoding re-derives every
  object CID and must rebuild byte-identical canonical store bytes.

Binary32/binary64 use the compiler's canonical structural float types.
Binary16/bfloat16 and the two exotic controls remain measurement-only exact
structural descriptors because production semantics do not yet support them.
The representative corpus uses supported floats in verified load/store and ABI
functions and uses every four-format candidate in real function signatures.

AI mutation tasks are deterministic benchmark protocol, never XAX source.  They
compare full structural diagnostic spellings with compact transport aliases and
check both arms against the same exact semantic target CID.  Model/tokenizer
usage is recorded only when an external raw-trial artifact supplies it; this
benchmark never substitutes byte counts for model tokens.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from xax_compiler import (
    CID_SIZE,
    HASH_SUITE,
    MAGIC,
    TRAILER_MAGIC,
    Block,
    Cursor,
    FloatFormat,
    Kind,
    Node,
    Operation,
    Permission,
    SemanticObject,
    StoreReader,
    Terminator,
    ValueRef,
    array_type,
    bits_type,
    blake3,
    call_contract,
    effect_type,
    EffectDomain,
    execute,
    fail,
    float_type as canonical_float_type,
    function,
    graph_fragment,
    memory_effect_type,
    object_with_refs,
    opaque_type,
    OpaqueKind,
    pointer_type,
    stack_owner_type,
    uleb,
    verify_store,
    write_store,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUTPUT = HERE / "oi04_type_vocabulary_evidence.json"
TRIALS = HERE / "oi04_type_mutation_trials.json"
CATALOG_DIGEST_BYTES = CID_SIZE

# ------------------------------------------------------------ float descriptors

# Flags of the measurement-only exact float descriptor used only for formats
# that production does not currently implement.
SIGNED_ZERO, INFINITIES, SUBNORMALS, IEEE_NANS, SINGLE_NAN = 1, 2, 4, 8, 16
IEEE = SIGNED_ZERO | INFINITIES | SUBNORMALS | IEEE_NANS

# name: (radix, precision incl. hidden bit, emax, emin, encoding bits, flags)
FLOAT_FORMATS = {
    "binary16": (2, 11, 15, -14, 16, IEEE),
    "bfloat16": (2, 8, 127, -126, 16, IEEE),
    "binary32": (2, 24, 127, -126, 32, IEEE),
    "binary64": (2, 53, 1023, -1022, 64, IEEE),
    "binary32_ftz": (2, 24, 127, -126, 32, IEEE & ~SUBNORMALS),
    "e4m3fn": (2, 4, 8, -6, 8, SIGNED_ZERO | SUBNORMALS | SINGLE_NAN),
}


def experimental_float_type(radix: int, precision: int, emax: int, emin: int, width: int, flags: int) -> SemanticObject:
    """Measurement-only exact float descriptor for unsupported formats."""
    if radix < 2 or precision < 1 or emin > 0 or emax < 1 or width < 1:
        raise ValueError("malformed float descriptor")
    # Form 11 is deliberately outside the production type-form range 1..10.
    body = uleb(11) + uleb(radix) + uleb(precision) + uleb(emax) + uleb(-emin) + uleb(width) + uleb(flags)
    return SemanticObject.create(Kind.TYPE, body)


def vector_type(element: SemanticObject, lanes: int) -> SemanticObject:
    """Measurement-only structural vec<N,T>; production has no vec type yet."""
    if element.kind != Kind.TYPE or lanes < 1:
        raise ValueError("vector requires a type element and positive lane count")
    return SemanticObject.create(Kind.TYPE, uleb(12) + uleb(lanes), [element.cid])


def float_text(name: str) -> str:
    radix, precision, emax, emin, width, flags = FLOAT_FORMATS[name]
    return f"float<radix={radix},p={precision},emax={emax},emin={emin},w={width},flags={flags}>"


FLOATS = {
    "binary16": experimental_float_type(*FLOAT_FORMATS["binary16"]),
    "bfloat16": experimental_float_type(*FLOAT_FORMATS["bfloat16"]),
    "binary32": canonical_float_type(FloatFormat.BINARY32),
    "binary64": canonical_float_type(FloatFormat.BINARY64),
    "binary32_ftz": experimental_float_type(*FLOAT_FORMATS["binary32_ftz"]),
    "e4m3fn": experimental_float_type(*FLOAT_FORMATS["e4m3fn"]),
}
BITS = {width: bits_type(width) for width in (1, 8, 16, 32, 64)}

# --------------------------------------------------------------------- catalogs

_BITS5 = tuple(BITS[w] for w in (1, 8, 16, 32, 64))
_FLOAT2 = (FLOATS["binary32"], FLOATS["binary64"])
_FLOAT4 = (FLOATS["binary16"], FLOATS["bfloat16"], *_FLOAT2)
_OTHER = (effect_type(EffectDomain.MEMORY), stack_owner_type(), *(opaque_type(kind) for kind in OpaqueKind))

# Catalog index = position.  Order is fixed; appending is the only compatible change.
CATALOGS: dict[str, tuple[SemanticObject, ...]] = {
    "bits5": _BITS5,
    "bits5_float2": _BITS5 + _FLOAT2,
    "bits5_float4": _BITS5 + _FLOAT4,
    "common": _BITS5 + _FLOAT4 + _OTHER,
}


def catalog_digest(catalog: tuple[SemanticObject, ...]) -> bytes:
    return blake3(b"".join(obj.cid for obj in catalog)).digest()


# ---------------------------------------------------------------- alias codec

def alias_envelope(obj: SemanticObject, ids: dict[bytes, int]) -> bytes:
    catalog_refs = sorted(ids[cid] for cid in obj.references if cid in ids)
    explicit = [cid for cid in obj.references if cid not in ids]
    payload = (
        obj.cid + uleb(obj.kind) + uleb(obj.schema_version)
        + uleb(len(catalog_refs)) + b"".join(uleb(i) for i in catalog_refs)
        + uleb(len(explicit)) + b"".join(explicit)
        + uleb(len(obj.body)) + obj.body
    )
    return uleb(len(payload)) + payload


def decode_alias_envelope(payload: bytes, catalog: tuple[SemanticObject, ...], ids: dict[bytes, int]) -> SemanticObject:
    cursor = Cursor(payload, "alias")
    cid = cursor.take(CID_SIZE)
    kind, schema = Kind(cursor.uleb()), cursor.uleb()
    indices = [cursor.uleb() for _ in range(cursor.uleb())]
    if indices != sorted(set(indices)) or any(i >= len(catalog) for i in indices):
        fail("XAX.OI04.CATALOG_INDEX", cid.hex(), "ALIAS-INDEX-SORTED-KNOWN", len(catalog), indices)
    explicit = [cursor.take(CID_SIZE) for _ in range(cursor.uleb())]
    if explicit != sorted(set(explicit)):
        fail("XAX.OI04.CATALOG_EXPLICIT", cid.hex(), "ALIAS-EXPLICIT-SORTED-UNIQUE", "sorted unique CIDs", [ref.hex() for ref in explicit])
    if any(ref in ids for ref in explicit):
        fail("XAX.OI04.CATALOG_EXPLICIT", cid.hex(), "ALIAS-ONE-ENCODING", "catalog index", "explicit CID")
    body = cursor.take(cursor.uleb())
    cursor.end("ALIAS-RECORD")
    obj = SemanticObject.create(kind, body, [catalog[i].cid for i in indices] + explicit, schema)
    if obj.cid != cid:
        fail("XAX.OI04.CID", cid.hex(), "ALIAS-CID-REDERIVED", cid.hex(), obj.cid.hex())
    return obj


def write_alias_store(root_cid: bytes, objects, catalog: tuple[SemanticObject, ...]) -> bytes:
    """Same container layout as ``write_store`` plus a catalog digest; catalog objects omitted."""
    ids = {obj.cid: index for index, obj in enumerate(catalog)}
    ordered = sorted((obj for obj in objects if obj.cid not in ids), key=lambda obj: obj.cid)
    out = bytearray(MAGIC + uleb(1) + uleb(0) + uleb(HASH_SUITE) + catalog_digest(catalog) + root_cid + uleb(len(ordered)) + uleb(0) + uleb(0))
    index = []
    for obj in ordered:
        offset = len(out)
        record = alias_envelope(obj, ids)
        out.extend(record)
        index.append(obj.cid + uleb(offset) + uleb(Cursor(record).uleb()))
    index_bytes = b"".join(index)
    out.extend(uleb(len(index_bytes)) + index_bytes)
    out.extend(blake3(out).digest() + TRAILER_MAGIC)
    return bytes(out)


def read_alias_store(data: bytes, catalog: tuple[SemanticObject, ...]) -> bytes:
    """Expand a catalog alias store only after strict container validation."""
    ids = {obj.cid: index for index, obj in enumerate(catalog)}
    cursor = Cursor(data, "alias-store")
    if cursor.take(4) != MAGIC or (cursor.uleb(), cursor.uleb(), cursor.uleb()) != (1, 0, HASH_SUITE):
        fail("XAX.OI04.HEADER", "alias-store", "ALIAS-HEADER", "XAX\\0 1 0 1", data[:8].hex())
    actual_catalog = cursor.take(CID_SIZE)
    expected_catalog = catalog_digest(catalog)
    if actual_catalog != expected_catalog:
        fail("XAX.OI04.CATALOG", "alias-store", "ALIAS-CATALOG-DIGEST", expected_catalog.hex(), actual_catalog.hex())
    root_cid = cursor.take(CID_SIZE)
    count, nonsemantic_count, flags = cursor.uleb(), cursor.uleb(), cursor.uleb()
    if nonsemantic_count or flags:
        fail("XAX.OI04.HEADER", "alias-store", "ALIAS-NO-METADATA-FLAGS", [0, 0], [nonsemantic_count, flags])
    objects, records, previous = [], [], b""
    for number in range(count):
        offset = cursor.pos
        length = cursor.uleb()
        payload = cursor.take(length)
        obj = decode_alias_envelope(payload, catalog, ids)
        if previous and obj.cid <= previous:
            fail("XAX.OI04.ORDER", f"record:{number}", "ALIAS-RECORDS-SORTED-UNIQUE", f"> {previous.hex()}", obj.cid.hex())
        previous = obj.cid
        objects.append(obj)
        records.append((obj.cid, offset, length))
    index_bytes = cursor.take(cursor.uleb())
    digest_end = cursor.pos
    stored_digest = cursor.take(CID_SIZE)
    trailer = cursor.take(4)
    if trailer != TRAILER_MAGIC:
        fail("XAX.OI04.TRAILER", "alias-store", "ALIAS-TRAILER", TRAILER_MAGIC.hex(), trailer.hex())
    cursor.end("ALIAS-STORE-LENGTH")
    actual_digest = blake3(data[:digest_end]).digest()
    if stored_digest != actual_digest:
        fail("XAX.OI04.DIGEST", "alias-store", "ALIAS-STORE-DIGEST", stored_digest.hex(), actual_digest.hex())
    index_cursor = Cursor(index_bytes, "alias-index")
    indexed = [(index_cursor.take(CID_SIZE), index_cursor.uleb(), index_cursor.uleb()) for _ in range(count)]
    index_cursor.end("ALIAS-INDEX-COUNT")
    if indexed != records:
        fail("XAX.OI04.INDEX_TABLE", "alias-index", "ALIAS-INDEX-MATCHES-RECORDS", records, indexed)
    used = {cid for obj in objects for cid in obj.references if cid in ids}
    objects.extend(obj for obj in catalog if obj.cid in used)
    return write_store(root_cid, objects)


def alias_codec_lines() -> int:
    """Compiler-complexity proxy: source lines of the catalog-alias codec."""
    parts = (catalog_digest, alias_envelope, decode_alias_envelope, write_alias_store, read_alias_store)
    return sum(len(inspect.getsource(part).splitlines()) for part in parts)


# ----------------------------------------------------- store-wide CID dictionary

def reference_dictionary(objects: list[SemanticObject]) -> tuple[bytes, ...]:
    """CIDs referenced by >=2 distinct objects, in deterministic CID order."""
    counts: dict[bytes, int] = {}
    for obj in objects:
        for cid in obj.references:
            counts[cid] = counts.get(cid, 0) + 1
    return tuple(sorted(cid for cid, count in counts.items() if count >= 2))


def dictionary_envelope(obj: SemanticObject, ids: dict[bytes, int]) -> bytes:
    dictionary_refs = sorted(ids[cid] for cid in obj.references if cid in ids)
    explicit = [cid for cid in obj.references if cid not in ids]
    payload = (
        obj.cid + uleb(obj.kind) + uleb(obj.schema_version)
        + uleb(len(dictionary_refs)) + b"".join(uleb(i) for i in dictionary_refs)
        + uleb(len(explicit)) + b"".join(explicit)
        + uleb(len(obj.body)) + obj.body
    )
    return uleb(len(payload)) + payload


def decode_dictionary_envelope(payload: bytes, dictionary: tuple[bytes, ...], ids: dict[bytes, int]) -> SemanticObject:
    cursor = Cursor(payload, "cid-dictionary")
    cid = cursor.take(CID_SIZE)
    kind, schema = Kind(cursor.uleb()), cursor.uleb()
    indices = [cursor.uleb() for _ in range(cursor.uleb())]
    if indices != sorted(set(indices)) or any(i >= len(dictionary) for i in indices):
        fail("XAX.OI04.DICTIONARY_INDEX", cid.hex(), "CID-DICT-INDEX-SORTED-KNOWN", len(dictionary), indices)
    explicit = [cursor.take(CID_SIZE) for _ in range(cursor.uleb())]
    if explicit != sorted(set(explicit)):
        fail("XAX.OI04.DICTIONARY_EXPLICIT", cid.hex(), "CID-DICT-EXPLICIT-SORTED-UNIQUE", "sorted unique CIDs", [ref.hex() for ref in explicit])
    if any(ref in ids for ref in explicit):
        fail("XAX.OI04.DICTIONARY_EXPLICIT", cid.hex(), "CID-DICT-ONE-ENCODING", "dictionary index", "explicit CID")
    body = cursor.take(cursor.uleb())
    cursor.end("CID-DICT-RECORD")
    obj = SemanticObject.create(kind, body, [dictionary[i] for i in indices] + explicit, schema)
    if obj.cid != cid:
        fail("XAX.OI04.DICTIONARY_CID", cid.hex(), "CID-DICT-CID-REDERIVED", cid.hex(), obj.cid.hex())
    return obj


def write_dictionary_store(root_cid: bytes, objects) -> bytes:
    """Measurement-only store with a carried dictionary for repeated references."""
    ordered = sorted(list(objects), key=lambda obj: obj.cid)
    dictionary = reference_dictionary(ordered)
    ids = {cid: index for index, cid in enumerate(dictionary)}
    out = bytearray(
        MAGIC + uleb(1) + uleb(0) + uleb(HASH_SUITE) + root_cid
        + uleb(len(ordered)) + uleb(0) + uleb(0)
        + uleb(len(dictionary)) + b"".join(dictionary)
    )
    index = []
    for obj in ordered:
        offset = len(out)
        record = dictionary_envelope(obj, ids)
        out.extend(record)
        index.append(obj.cid + uleb(offset) + uleb(Cursor(record).uleb()))
    index_bytes = b"".join(index)
    out.extend(uleb(len(index_bytes)) + index_bytes)
    out.extend(blake3(out).digest() + TRAILER_MAGIC)
    return bytes(out)


def read_dictionary_store(data: bytes) -> bytes:
    """Expand the CID-dictionary comparator back to canonical store bytes."""
    cursor = Cursor(data, "cid-dictionary-store")
    if cursor.take(4) != MAGIC or (cursor.uleb(), cursor.uleb(), cursor.uleb()) != (1, 0, HASH_SUITE):
        fail("XAX.OI04.DICTIONARY_HEADER", "cid-dictionary-store", "CID-DICT-HEADER", "XAX\\0 1 0 1", data[:8].hex())
    root_cid = cursor.take(CID_SIZE)
    count, nonsemantic_count, flags = cursor.uleb(), cursor.uleb(), cursor.uleb()
    if nonsemantic_count or flags:
        fail("XAX.OI04.DICTIONARY_HEADER", "cid-dictionary-store", "CID-DICT-NO-METADATA-FLAGS", [0, 0], [nonsemantic_count, flags])
    dictionary = tuple(cursor.take(CID_SIZE) for _ in range(cursor.uleb()))
    if dictionary != tuple(sorted(set(dictionary))):
        fail("XAX.OI04.DICTIONARY", "cid-dictionary-store", "CID-DICT-SORTED-UNIQUE", "strict CID order", [cid.hex() for cid in dictionary])
    ids = {cid: index for index, cid in enumerate(dictionary)}
    objects, records, previous = [], [], b""
    for number in range(count):
        offset = cursor.pos
        length = cursor.uleb()
        payload = cursor.take(length)
        obj = decode_dictionary_envelope(payload, dictionary, ids)
        if previous and obj.cid <= previous:
            fail("XAX.OI04.DICTIONARY_ORDER", f"record:{number}", "CID-DICT-RECORDS-SORTED-UNIQUE", f"> {previous.hex()}", obj.cid.hex())
        previous = obj.cid
        objects.append(obj)
        records.append((obj.cid, offset, length))
    index_bytes = cursor.take(cursor.uleb())
    digest_end = cursor.pos
    stored_digest = cursor.take(CID_SIZE)
    if cursor.take(4) != TRAILER_MAGIC:
        fail("XAX.OI04.DICTIONARY_TRAILER", "cid-dictionary-store", "CID-DICT-TRAILER", TRAILER_MAGIC.hex(), data[-4:].hex())
    cursor.end("CID-DICT-STORE-LENGTH")
    actual_digest = blake3(data[:digest_end]).digest()
    if stored_digest != actual_digest:
        fail("XAX.OI04.DICTIONARY_DIGEST", "cid-dictionary-store", "CID-DICT-STORE-DIGEST", stored_digest.hex(), actual_digest.hex())
    index_cursor = Cursor(index_bytes, "cid-dictionary-index")
    indexed = [(index_cursor.take(CID_SIZE), index_cursor.uleb(), index_cursor.uleb()) for _ in range(count)]
    index_cursor.end("CID-DICT-INDEX-COUNT")
    if indexed != records:
        fail("XAX.OI04.DICTIONARY_INDEX_TABLE", "cid-dictionary-index", "CID-DICT-INDEX-MATCHES-RECORDS", records, indexed)
    expected = reference_dictionary(objects)
    if dictionary != expected:
        fail("XAX.OI04.DICTIONARY", "cid-dictionary-store", "CID-DICT-EXACT-REPEATED-SET", [cid.hex() for cid in expected], [cid.hex() for cid in dictionary])
    return write_store(root_cid, objects)


def dictionary_codec_lines() -> int:
    parts = (reference_dictionary, dictionary_envelope, decode_dictionary_envelope, write_dictionary_store, read_dictionary_store)
    return sum(len(inspect.getsource(part).splitlines()) for part in parts)


# ------------------------------------------------------------------ workloads

def _committed(path: str) -> bytes:
    data = (ROOT / path).read_bytes()
    return bytes.fromhex(data.decode().strip()) if path.endswith(".hex") else data


COMMITTED = (
    "tests/fixtures/c0_all_kinds.xax.hex",
    "tests/fixtures/m2_direct_call.xax.hex",
    "bootstrap/m11_bootstrap_bundle.xax",
    "bootstrap/m11_compiler_subset.xax",
    "bootstrap/m14_selfhost_compiler.xax",
)

# Reverse kernels keep the original synthetic controls so prior integer evidence
# remains comparable.  The representative corpus below is the decision workload.
MIXES = {
    "bits_mixed": [BITS[w] for w in (1, 8, 16, 32, 64, 32, 64, 8)],
    "bits64_only": [BITS[64]] * 8,
    "float_ieee": [FLOATS[n] for n in ("binary32", "binary64", "binary16", "bfloat16", "binary32", "binary64", "binary32", "binary64")],
    "float_exotic": [FLOATS[n] for n in ("binary32_ftz", "e4m3fn", "binary32", "binary64", "binary32_ftz", "e4m3fn", "binary32", "binary64")],
    "float_zero_catalog": [FLOATS[n] for n in ("binary32_ftz", "e4m3fn", "binary32_ftz", "e4m3fn")],
}


def reverse_store(types: list[SemanticObject]) -> tuple[bytes, list[bytes]]:
    objects, functions = {t.cid: t for t in types}, []
    for i, t in enumerate(types):
        arity = (t,) * (i + 2)
        graph = graph_fragment([Block(arity, (), Terminator.return_(tuple(ValueRef.parameter(0, j) for j in reversed(range(i + 2)))))])
        fn = function(graph, arity, arity)
        objects.update(((graph.cid, graph), (fn.cid, fn)))
        functions.append(fn)
    module = object_with_refs(Kind.MODULE, functions)
    root = object_with_refs(Kind.PROGRAM_ROOT, [module])
    objects.update(((module.cid, module), (root.cid, root)))
    return write_store(root.cid, objects.values()), [fn.cid for fn in functions]


def _identity_function(type_object: SemanticObject) -> tuple[SemanticObject, SemanticObject, SemanticObject]:
    graph = graph_fragment([Block((type_object,), (), Terminator.return_((ValueRef.parameter(0, 0),)))])
    fn = function(graph, (type_object,), (type_object,))
    contract = call_contract((type_object,), (type_object,), may_return=True, may_trap=False)
    return graph, fn, contract


def _memory_roundtrip_function(type_object: SemanticObject, size: int) -> tuple[SemanticObject, ...]:
    rw = pointer_type(type_object, Permission.READ_WRITE, size)
    ro = pointer_type(type_object, Permission.READ, size)
    owner = stack_owner_type()
    effect = memory_effect_type()
    nodes = (
        Node(Operation.STACK_ALLOC, (), (rw, owner, effect), attributes=(size, size)),
        Node(Operation.STORE_BITS_LE, (ValueRef.node_result(0, 0, 0), ValueRef.parameter(0, 0), ValueRef.node_result(0, 0, 2)), (effect,), attributes=(size, size)),
        Node(Operation.POINTER_CAST, (ValueRef.node_result(0, 0, 0),), (ro,)),
        Node(Operation.LOAD_BITS_LE, (ValueRef.node_result(0, 2), ValueRef.node_result(0, 1)), (type_object, effect), attributes=(size, size)),
        Node(Operation.STACK_END, (ValueRef.node_result(0, 0, 1), ValueRef.node_result(0, 3, 1)), ()),
    )
    graph = graph_fragment([Block((type_object,), nodes, Terminator.return_((ValueRef.node_result(0, 3, 0),)))])
    fn = function(graph, (type_object,), (type_object,))
    contract = call_contract((type_object,), (type_object,), may_return=True, may_trap=False)
    return rw, ro, owner, effect, graph, fn, contract


def representative_numeric_corpus() -> tuple[dict[str, bytes], dict[str, dict]]:
    """Two-module verified core plus an extended ABI/vec transport workload."""
    objects: dict[bytes, SemanticObject] = {}

    def add(*items: SemanticObject) -> None:
        objects.update((obj.cid, obj) for obj in items)

    f32, f64 = FLOATS["binary32"], FLOATS["binary64"]
    f16, bf16 = FLOATS["binary16"], FLOATS["bfloat16"]
    add(*BITS.values(), f16, bf16, f32, f64)

    # Canonical array aggregates are verifier-supported vector-shaped ABI forms.
    arrays = {
        "a4f32": array_type(f32, 4),
        "a8f32": array_type(f32, 8),
        "a2f64": array_type(f64, 2),
        "a8f16": array_type(f16, 8),
        "a8bf16": array_type(bf16, 8),
    }
    add(*arrays.values())

    # Exact vec forms are measurement-only because production has no vec<N,T> yet.
    vectors = {
        "v4f32": vector_type(f32, 4),
        "v8f32": vector_type(f32, 8),
        "v2f64": vector_type(f64, 2),
        "v8f16": vector_type(f16, 8),
        "v8bf16": vector_type(bf16, 8),
    }
    add(*vectors.values())

    core_members: list[SemanticObject] = []
    for type_object, size in ((f32, 4), (f64, 8)):
        built = _memory_roundtrip_function(type_object, size)
        add(*built)
        core_members.extend((built[-2], built[-1]))  # function + call contract

    # Common pointer permission/address-space forms in real function signatures.
    pointer_forms = {
        "p1rw4f32": pointer_type(f32, Permission.READ_WRITE, 4, space=1),
        "p1r4f32": pointer_type(f32, Permission.READ, 4, space=1),
        "p2rw4f32": pointer_type(f32, Permission.READ_WRITE, 4, space=2),
        "p1rw8f64": pointer_type(f64, Permission.READ_WRITE, 8, space=1),
        "p2r8f64": pointer_type(f64, Permission.READ, 8, space=2),
    }
    add(*pointer_forms.values())
    for type_object in (*pointer_forms.values(), arrays["a4f32"], arrays["a8f32"], arrays["a2f64"]):
        built = _identity_function(type_object)
        add(*built)
        core_members.extend((built[1], built[2]))

    module_core = object_with_refs(Kind.MODULE, core_members)
    add(module_core)
    root_core = object_with_refs(Kind.PROGRAM_ROOT, [module_core])
    add(root_core)
    core_closure = _reachable_objects(root_core.cid, objects)
    core_data = write_store(root_core.cid, core_closure)
    core_reader = StoreReader(core_data)
    verify_store(core_reader)

    # The second module actually uses all four float candidates and exact vector
    # forms in function/call-contract signatures. Unsupported forms stay tooling-only.
    extended_members: list[SemanticObject] = []
    for type_object in (f16, bf16, f32, f64, arrays["a8f16"], arrays["a8bf16"], *vectors.values()):
        built = _identity_function(type_object)
        add(*built)
        extended_members.extend((built[1], built[2]))
    module_extended = object_with_refs(Kind.MODULE, extended_members)
    add(module_extended)
    root_extended = object_with_refs(Kind.PROGRAM_ROOT, [module_core, module_extended])
    add(root_extended)
    extended_data = write_store(root_extended.cid, _reachable_objects(root_extended.cid, objects))

    composition = {
        "numeric_service_verified": {
            "modules": 1,
            "verified": True,
            "float_formats_used": ["binary32", "binary64"],
            "uses": ["function signatures", "call contracts", "stack load/store", "pointer permission/address-space", "array vector-shapes"],
        },
        "numeric_abi_extended": {
            "modules": 2,
            "verified": False,
            "verification_limit": "binary16/bfloat16 and vec<N,T> remain measurement-only unsupported type forms",
            "float_formats_used": ["binary16", "bfloat16", "binary32", "binary64"],
            "uses": ["function signatures", "call contracts", "stack load/store for supported floats", "pointer forms", "array and vec shapes"],
        },
    }
    return {"numeric_service_verified": core_data, "numeric_abi_extended": extended_data}, composition


def _reachable_objects(root_cid: bytes, objects: dict[bytes, SemanticObject]) -> list[SemanticObject]:
    pending, seen = [root_cid], set()
    while pending:
        cid = pending.pop()
        if cid in seen:
            continue
        obj = objects[cid]
        seen.add(cid)
        pending.extend(obj.references)
    return [objects[cid] for cid in seen]


def workloads() -> dict[str, bytes]:
    from benchmarks import bench_oi03_recursion as oi03
    from benchmarks.ai_native import _build, tasks

    result = {Path(path).name.split(".")[0]: _committed(path) for path in COMMITTED}
    for task in tasks():
        result[f"ai_{task.task_id}"] = _build(task.initial, task.result)[0].data
    for name, arm in (("none", "function"), ("mutual", "group")):
        w = oi03.workload(name, arm)
        result[f"oi03_{name}"] = write_store(w["root"].cid, w["objects"])
    for name, types in MIXES.items():
        data, functions = reverse_store(types)
        if name.startswith("bits"):
            reader = StoreReader(data)
            verify_store(reader)
            for i, fn in enumerate(functions):
                args = tuple(j % 2 for j in range(i + 2))
                if execute(reader, fn, args) != args[::-1]:
                    raise AssertionError((name, i))
        result[f"reverse_{name}"] = data
    numeric, _ = representative_numeric_corpus()
    result.update(numeric)
    return result


# ------------------------------------------------------------ AI mutation tasks

def mutation_types() -> dict[str, SemanticObject]:
    f32, f64 = FLOATS["binary32"], FLOATS["binary64"]
    return {
        "u32": BITS[32],
        "u64": BITS[64],
        "f16": FLOATS["binary16"],
        "bf16": FLOATS["bfloat16"],
        "f32": f32,
        "f64": f64,
        "v4f32": vector_type(f32, 4),
        "v8f32": vector_type(f32, 8),
        "p1rw4f32": pointer_type(f32, Permission.READ_WRITE, 4, space=1),
        "p1r4f32": pointer_type(f32, Permission.READ, 4, space=1),
        "p2rw4f32": pointer_type(f32, Permission.READ_WRITE, 4, space=2),
    }


MUTATION_TASKS = (
    ("bit-width", "u32", "u64", "change the bit width from 32 to 64"),
    ("float-format", "f32", "f64", "change the float format from binary32 to binary64"),
    ("float16-format", "f16", "bf16", "change the 16-bit float format from binary16 to bfloat16"),
    ("vector-lanes", "v4f32", "v8f32", "change the vector lane count from 4 to 8"),
    ("pointer-permission", "p1rw4f32", "p1r4f32", "narrow pointer permission from read_write to read"),
    ("pointer-space", "p1rw4f32", "p2rw4f32", "change pointer address space from 1 to 2"),
    ("create-vector", None, "v4f32", "create a 4-lane binary32 vector type"),
    ("invalid-repair", "invalid-pointer", "p1rw4f32", "repair the invalid pointer alignment 3 to alignment 4"),
)


def _structural_spellings() -> dict[str, str]:
    f32 = float_text("binary32")
    return {
        "u32": "bits<32>",
        "u64": "bits<64>",
        "f16": float_text("binary16"),
        "bf16": float_text("bfloat16"),
        "f32": f32,
        "f64": float_text("binary64"),
        "v4f32": f"vec<4,{f32}>",
        "v8f32": f"vec<8,{f32}>",
        "p1rw4f32": f"ptr<space=1,permission=read_write,alignment=4,{f32}>",
        "p1r4f32": f"ptr<space=1,permission=read,alignment=4,{f32}>",
        "p2rw4f32": f"ptr<space=2,permission=read_write,alignment=4,{f32}>",
        "invalid-pointer": f"ptr<space=1,permission=read_write,alignment=3,{f32}>",
    }


def _alias_spellings() -> dict[str, str]:
    return {
        "u32": "u32", "u64": "u64", "f16": "f16", "bf16": "bf16", "f32": "f32", "f64": "f64",
        "v4f32": "v4f32", "v8f32": "v8f32", "p1rw4f32": "p1rw4f32", "p1r4f32": "p1r4f32", "p2rw4f32": "p2rw4f32",
        "invalid-pointer": "p1rw3f32",
    }


def mutation_task_rows() -> list[dict]:
    types = mutation_types()
    spellings = {"structural": _structural_spellings(), "alias": _alias_spellings()}
    rows = []
    for task_id, current, target, request in MUTATION_TASKS:
        target_obj = types[target]
        arms = {}
        for arm in ("structural", "alias"):
            current_text = "none" if current is None else spellings[arm][current]
            target_text = spellings[arm][target]
            view = f"OI04-MUTATION-V1\ncurrent={current_text}\nrequest={request}\nreply=TYPE <type>\n"
            response = f"TYPE {target_text}\n"
            arms[arm] = {"view": view, "view_bytes": len(view.encode()), "target_response": response, "response_bytes": len(response.encode())}
        rows.append({"task_id": task_id, "target_cid": target_obj.cid.hex(), "arms": arms})
    return rows


def check_mutation_response(task_id: str, arm: str, response: str) -> bytes:
    if arm not in ("structural", "alias"):
        raise ValueError("unknown OI-04 mutation arm")
    row = next((item for item in mutation_task_rows() if item["task_id"] == task_id), None)
    if row is None:
        raise ValueError("unknown OI-04 mutation task")
    expected = row["arms"][arm]["target_response"]
    if response != expected:
        raise ValueError("invalid OI-04 type mutation packet")
    return bytes.fromhex(row["target_cid"])


def raw_trial_artifact() -> dict:
    if not TRIALS.exists():
        return {"status": "not_run", "model": None, "tokenizer": None, "trials": []}
    data = json.loads(TRIALS.read_text())
    if data.get("issue") != "OI-04" or not isinstance(data.get("trials"), list):
        raise ValueError("malformed OI-04 trial artifact")
    for row in data["trials"]:
        if row.get("task_id") not in {task[0] for task in MUTATION_TASKS} or row.get("arm") not in ("structural", "alias"):
            raise ValueError("unknown OI-04 model trial cell")
        for field in ("input_tokens", "output_tokens", "total_tokens", "turns", "repairs"):
            value = row.get(field)
            if value is not None and (not isinstance(value, int) or value < 0):
                raise ValueError(f"invalid OI-04 trial {field}")
    return data


def summarize_trials(raw: dict) -> dict:
    rows = raw.get("trials", [])
    result = {}
    for arm in ("structural", "alias"):
        selected = [row for row in rows if row["arm"] == arm]
        successes = [row for row in selected if row.get("pass") is True]
        result[arm] = {
            "trials": len(selected),
            "passes": len(successes),
            "invalid_or_failed": len(selected) - len(successes),
            "repair_turns": sum(row.get("repairs") or 0 for row in selected),
            "successful_total_tokens": sum(row.get("total_tokens") or 0 for row in successes) if successes else None,
            "tokens_per_success": (sum(row.get("total_tokens") or 0 for row in successes) / len(successes)) if successes else None,
        }
    return result


# ---------------------------------------------------------------- measurement

def type_texts() -> dict[str, dict[str, str]]:
    """Diagnostic spellings only; none are canonical XAX source."""
    common = CATALOGS["common"]
    rows = {}
    for width, obj in BITS.items():
        rows[f"bits{width}"] = {"structural": f"bits<{width}>", "short": f"u{width}", "catalog": f"T{common.index(obj)}", "cid": obj.cid.hex()}
    short = {"binary16": "f16", "bfloat16": "bf16", "binary32": "f32", "binary64": "f64", "binary32_ftz": "binary32_ftz", "e4m3fn": "e4m3fn"}
    for name, obj in FLOATS.items():
        rows[name] = {"structural": float_text(name), "short": short[name], "catalog": f"T{common.index(obj)}" if obj in common else float_text(name), "cid": obj.cid.hex()}
    return rows


def _catalog_label(obj: SemanticObject) -> str:
    for width, bits in BITS.items():
        if obj.cid == bits.cid:
            return f"bits{width}"
    for name, float_obj in FLOATS.items():
        if obj.cid == float_obj.cid:
            return name
    if obj.cid == effect_type(EffectDomain.MEMORY).cid:
        return "effect_memory"
    if obj.cid == stack_owner_type().cid:
        return "stack_owner"
    for kind in OpaqueKind:
        if obj.cid == opaque_type(kind).cid:
            return f"opaque_{kind.name.lower()}"
    return obj.cid.hex()


def _reference_hits(objects: list[SemanticObject], catalog: tuple[SemanticObject, ...]) -> list[dict]:
    counts = {obj.cid: 0 for obj in catalog}
    for obj in objects:
        for cid in obj.references:
            if cid in counts:
                counts[cid] += 1
    return [{"index": i, "name": _catalog_label(obj), "cid": obj.cid.hex(), "references": counts[obj.cid]} for i, obj in enumerate(catalog)]


def _aggregate(results: dict[str, dict], names: list[str]) -> dict:
    row = {"workloads": names, "structural_bytes": sum(results[name]["structural_bytes"] for name in names)}
    for catalog_name in CATALOGS:
        row[catalog_name] = {
            "bytes": sum(results[name][catalog_name]["bytes"] for name in names),
            "delta": sum(results[name][catalog_name]["delta"] for name in names),
        }
    row["cid_dictionary"] = {
        "bytes": sum(results[name]["cid_dictionary"]["bytes"] for name in names),
        "delta": sum(results[name]["cid_dictionary"]["delta"] for name in names),
    }
    return row


def run() -> dict:
    results = {}
    for name, data in workloads().items():
        reader = StoreReader(data)
        objects = list(reader.objects())
        types = {obj.cid: obj.body.hex() for obj in objects if obj.kind == Kind.TYPE}
        row = {
            "objects": len(objects),
            "type_objects": len(types),
            "type_references": sum(cid in types for obj in objects for cid in obj.references),
            "type_bodies": sorted(types.values()),
            "structural_bytes": len(data),
        }
        for catalog_name, catalog in CATALOGS.items():
            alias = write_alias_store(reader.root_cid, objects, catalog)
            if read_alias_store(alias, catalog) != data:
                raise AssertionError((name, catalog_name))
            hits = _reference_hits(objects, catalog)
            row[catalog_name] = {
                "bytes": len(alias),
                "delta": len(alias) - len(data),
                "header_digest_bytes": CATALOG_DIGEST_BYTES,
                "entries": len(catalog),
                "entries_hit": sum(item["references"] > 0 for item in hits),
                "entry_hits": hits,
            }
        dictionary_store = write_dictionary_store(reader.root_cid, objects)
        if read_dictionary_store(dictionary_store) != data:
            raise AssertionError((name, "cid_dictionary"))
        dictionary = reference_dictionary(objects)
        dictionary_set = set(dictionary)
        row["cid_dictionary"] = {
            "bytes": len(dictionary_store),
            "delta": len(dictionary_store) - len(data),
            "entries": len(dictionary),
            "table_bytes": len(dictionary) * CID_SIZE,
            "references": sum(cid in dictionary_set for obj in objects for cid in obj.references),
        }
        results[name] = row

    numeric, composition = representative_numeric_corpus()
    for name, data in numeric.items():
        composition[name]["store_bytes"] = len(data)
        composition[name]["root_cid"] = StoreReader(data).root_cid.hex()

    raw_trials = raw_trial_artifact()
    mutation_rows = mutation_task_rows()
    return {
        "issue": "OI-04",
        "canonical_identity": "structural type CID only; catalog/dictionary/AI aliases expand to exact structural objects",
        "model_token_status": raw_trials.get("status", "unknown"),
        "raw_model_trials": raw_trials,
        "model_trial_summary": summarize_trials(raw_trials),
        "catalogs": {
            name: {
                "entries": [{"index": i, "name": _catalog_label(obj), "body": obj.body.hex(), "cid": obj.cid.hex()} for i, obj in enumerate(catalog)],
                "digest": catalog_digest(catalog).hex(),
                "container_digest_overhead_bytes": CATALOG_DIGEST_BYTES,
            }
            for name, catalog in CATALOGS.items()
        },
        "cid_dictionary_policy": {"entry_bytes": CID_SIZE, "minimum_object_reference_count": 2, "order": "CID lexicographic"},
        "codec_source_lines": {"catalog_alias": alias_codec_lines(), "cid_dictionary": dictionary_codec_lines()},
        "float_descriptors": {
            name: {
                "body": obj.body.hex(),
                "envelope_bytes": len(obj.envelope()),
                "production_supported": name in ("binary32", "binary64"),
            }
            for name, obj in FLOATS.items()
        },
        "bits_envelope_bytes": {str(w): len(obj.envelope()) for w, obj in BITS.items()},
        "type_texts": type_texts(),
        "tokenizer_measurements": {"status": "unavailable", "raw": []},
        "mutation_tasks": mutation_rows,
        "representative_corpus": composition,
        "workloads": results,
        "representative_aggregate": _aggregate(results, ["numeric_service_verified", "numeric_abi_extended"]),
    }


def main() -> None:
    result = run()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, row in result["workloads"].items():
        deltas = " ".join(f"{catalog}={row[catalog]['delta']:+5}" for catalog in CATALOGS)
        dictionary = row["cid_dictionary"]
        print(f"{name:24} B={row['structural_bytes']:6} types={row['type_objects']:3} refs={row['type_references']:4} {deltas} cid_dictionary={dictionary['delta']:+6}")
    print("representative aggregate", result["representative_aggregate"])
    print("codec lines", result["codec_source_lines"])
    print("model trials", result["model_trial_summary"])


if __name__ == "__main__":
    main()
