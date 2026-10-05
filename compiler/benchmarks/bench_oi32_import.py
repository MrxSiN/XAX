"""OI-32 evidence: the JVM class-file importer (ADR-166) beside the C header importer (ADR-127).

Measures:

1. **Coverage, latency, size** over all of ``java.base``. Every member of
   every public class in an exported package is requested (``class_requests``)
   and imported with the conservative defaults.  A class's API is its public
   and protected members; protected members are refused (no subclassing). Reported: imported and
   refused counts with reasons, the seconds to load the module and to
   import, declaration bytes, and package objects.
2. **Declaration error rate against curated metadata.** Every hand-built
   member declaration (``jvm-new``, ``-invokestatic``, ``-invokevirtual``,
   ``-invokeinterface``, ``-invokestatic-interface``, ``-getstatic``,
   ``-getfield``, ``-putfield``) that the repository's JVM tests and packages
   define is checked against the JDK's own class files.
   - The importer is given only the curated facts the hand-built declaration
     states: purity, its effect, and callback parameters.
   - Its output must equal the hand-built declaration byte for byte.
   - A mismatch counts as an error. A member the class files refuse is an
     error in the hand-built declaration.
   - The C importer's hand-built reproductions (``test_xax_c_import.py``) are
     counted the same way.
3. **AI tokens** (offline ``tiktoken``; no model runs). For each declaration
   in (2), compare:
   - the request a model writes to import it: the member key plus the
     curated facts;
   - the hand-built declaration in the same compact JSON view (ABI, library,
     name, typed inputs and outputs).

Run: ``PYTHONPATH=src:.:.. python -m benchmarks.bench_oi32_import [--write]`` from ``compiler/``.
"""

from __future__ import annotations

import collections
import hashlib
import importlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

from xax_compiler import (
    AAPCS64_LINUX_C_ABI,
    EffectDomain,
    FloatFormat,
    JVM_GETFIELD_ABI,
    JVM_GETSTATIC_ABI,
    JVM_INVOKEINTERFACE_ABI,
    JVM_INVOKESTATIC_ABI,
    JVM_INVOKESTATIC_INTERFACE_ABI,
    JVM_INVOKEVIRTUAL_ABI,
    JVM_NEW_ABI,
    JVM_PUTFIELD_ABI,
    JVM_PUTSTATIC_ABI,
    Kind,
    SemanticObject,
    bits_type,
    decode_foreign_function,
    float_type,
)
from xax_jvm_import import JvmClassPath, class_requests, import_jvm_members

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "oi32_import_evidence.json"
ENCODINGS = ("cl100k_base", "o200k_base")
MEMBER_ABIS = {
    JVM_NEW_ABI, JVM_INVOKESTATIC_ABI, JVM_INVOKEVIRTUAL_ABI, JVM_INVOKEINTERFACE_ABI, JVM_INVOKESTATIC_INTERFACE_ABI,
    JVM_GETSTATIC_ABI, JVM_GETFIELD_ABI, JVM_PUTFIELD_ABI, JVM_PUTSTATIC_ABI,
}
# Modules whose module-level objects hold the repository's hand-built JVM declarations.
SOURCES = (
    "xax_jvm", "tests.test_xax_jvm", "tests.test_xax_jvm_memory", "tests.test_xax_jvm_general",
    "tests.test_xax_jvm_callbacks", "tests.test_xax_jvm_objects",
)


def _jmods() -> Path:
    return Path(os.path.realpath(shutil.which("javac"))).parents[1] / "jmods"


def _hand_built() -> dict[bytes, tuple[str, SemanticObject, dict[bytes, SemanticObject]]]:
    """Every distinct hand-built JDK member declaration: cid -> (where, declaration, the types it references)."""
    found: dict[bytes, tuple[str, SemanticObject, dict[bytes, SemanticObject]]] = {}
    from xax_jvm import java_base_api

    api = java_base_api()
    candidates = [("xax_jvm.java_base_api", item) for item in api.symbols]
    types = {item.cid: item for item in api.types}
    for name in SOURCES:
        module = importlib.import_module(name)
        for attribute, value in sorted(vars(module).items()):
            if isinstance(value, tuple):  # tuples of types (ELEMENTS, TYPES)
                types.update({item.cid: item for item in value if isinstance(item, SemanticObject) and item.kind == Kind.TYPE})
            elif isinstance(value, SemanticObject):
                if value.kind == Kind.TYPE:
                    types[value.cid] = value
                else:
                    candidates.append((f"{name}.{attribute}", value))
    for where, item in candidates:
        try:
            declaration = decode_foreign_function(item)
        except Exception:
            continue
        if declaration.abi in MEMBER_ABIS and not declaration.library.startswith((b"xax/", b"xaxtest/")):  # JDK members only
            found.setdefault(item.cid, (where, item, types))
    return found


def _type_text(cid: bytes, objects: dict[bytes, SemanticObject]) -> str:
    item = objects.get(cid)
    if item is None:
        return cid.hex()[:8]
    form = item.body[0]
    if form == 1:
        return f"b{item.body[1]}"
    if form == 7:
        return "f32" if item.body[1] == FloatFormat.BINARY32 else "f64"
    if form == 3:
        return "effect:" + EffectDomain(item.body[1]).name.lower()
    if form == 2:
        return "ptr<" + _type_text(item.references[0], objects) + ">"
    if form == 6:
        return item.body[2:].decode("ascii", "replace")
    return f"type:{item.body.hex()}"


def _render(declaration: SemanticObject, objects: dict[bytes, SemanticObject]) -> str:
    decoded = decode_foreign_function(declaration)
    view = {
        "abi": decoded.abi.decode(), "library": decoded.library.decode(), "name": decoded.name.decode(),
        "in": [_type_text(cid, objects) for cid in decoded.inputs], "out": [_type_text(cid, objects) for cid in decoded.outputs],
    }
    return json.dumps(view, separators=(",", ":"))


def _request(declaration: SemanticObject, objects: dict[bytes, SemanticObject]) -> tuple[str, dict]:
    """The importer request and the curated facts a hand-built declaration states."""
    decoded = decode_foreign_function(declaration)
    library, name = decoded.library.decode(), decoded.name.decode()
    key = f"{library}.{name}" + ("=" if decoded.abi in (JVM_PUTFIELD_ABI, JVM_PUTSTATIC_ABI) else "")
    proofs = [cid for cid in decoded.inputs if objects.get(cid) is not None and objects[cid].body[0] == 3]
    facts: dict = {}
    if not proofs:
        facts["pure"] = True
    elif objects[proofs[0]].body[:2] != bytes((3, EffectDomain.IO)) or len(objects[proofs[0]].body) > 2:
        facts["effect"] = objects[proofs[0]]
    if any(b"code-entry:jvm-interface:" in _type_text(cid, objects).encode() for cid in decoded.inputs):
        facts["callbacks"] = True
    return key, facts


def _jvm_error_rate(classpath: JvmClassPath) -> dict:
    rows, errors = [], 0
    for cid, (where, declaration, types) in sorted(_hand_built().items(), key=lambda item: item[1][0]):
        key, facts = _request(declaration, types)
        imported = import_jvm_members(
            classpath, (key,), pure=(key,) if facts.get("pure") else (),
            effects={key: facts["effect"]} if "effect" in facts else None, callbacks=facts.get("callbacks", False),
        )
        result = imported.declarations.get(key)
        status = "byte-identical" if result is not None and result.cid == cid else ("refused: " + imported.refused[key] if result is None else "differs")
        errors += status != "byte-identical"
        rows.append({"where": where, "request": key, "facts": sorted(facts), "status": status})
    return {"declarations": len(rows), "errors": errors, "error_rate": round(errors / len(rows), 4), "rows": rows}


def _c_rows() -> list[tuple[str, SemanticObject, SemanticObject, str, dict]]:
    """The C importer's hand-built reproductions: (label, imported, hand-built, request, facts)."""
    from xax_c_import import import_c_functions
    from xax_linux import c_function, linux_api
    from xax_linux_aarch64 import c_function as aarch64_c_function, linux_aarch64_api

    api, a64 = linux_api(), linux_aarch64_api()
    b32, b64 = bits_type(32), bits_type(64)
    f32, f64 = float_type(FloatFormat.BINARY32), float_type(FloatFormat.BINARY64)
    zlib = import_c_functions(["/usr/include/zlib.h"], b"libz.so.1", ["crc32"])
    math = import_c_functions(["/usr/include/math.h"], b"libm.so.6", ["ldexp", "pow", "sqrtf"], overrides={"ldexp": "pure", "pow": "pure", "sqrtf": "pure"})
    string = import_c_functions(["/usr/include/string.h"], b"libc.so.6", ["strlen"], abi=AAPCS64_LINUX_C_ABI)
    return [
        ("libz crc32", zlib["crc32"], c_function(b"libz.so.1", b"crc32", (b64, api.bytes_read, b32, api.memory_effect), (b64, api.memory_effect)), "crc32", {}),
        ("libm ldexp", math["ldexp"], c_function(b"libm.so.6", b"ldexp", (f64, b32), (f64,)), "ldexp", {"pure": True}),
        ("libm pow", math["pow"], c_function(b"libm.so.6", b"pow", (f64, f64), (f64,)), "pow", {"pure": True}),
        ("libm sqrtf", math["sqrtf"], c_function(b"libm.so.6", b"sqrtf", (f32,), (f32,)), "sqrtf", {"pure": True}),
        ("libc strlen aapcs64", string["strlen"], aarch64_c_function(b"libc.so.6", b"strlen", (a64.bytes_read, a64.memory_effect), (b64, a64.memory_effect)), "strlen", {"abi": "aapcs64"}),
    ], {item.cid: item for item in (*api.types, *a64.types, b32, b64, f32, f64)}


def run() -> dict:
    import tiktoken

    tokenizers = {name: tiktoken.get_encoding(name) for name in ENCODINGS}
    count = lambda text: {name: len(encoder.encode(text)) for name, encoder in tokenizers.items()}  # noqa: E731

    start = time.perf_counter()
    base = JvmClassPath.of(_jmods() / "java.base.jmod")
    load_seconds = time.perf_counter() - start
    public = [name for name in base.class_names() if base.accessible(name)]
    start = time.perf_counter()
    requests = [request for name in public for request in class_requests(base, name)]
    imported = import_jvm_members(base, requests)
    import_seconds = time.perf_counter() - start
    reasons = collections.Counter(imported.refused.values())
    coverage = {
        "module": "java.base", "classes": len(base.class_names()), "public_exported_classes": len(public),
        "exported_packages": len(base.sources[0].exported or ()), "requests": len(requests), "imported": len(imported.declarations),
        "refused": len(imported.refused), "refusal_reasons": dict(sorted(reasons.items())),
        "load_seconds": round(load_seconds, 3), "import_seconds": round(import_seconds, 3),
        "import_microseconds_per_request": round(import_seconds / len(requests) * 1e6, 1),
        "declaration_bytes": sum(len(item.body) for item in imported.declarations.values()),
        "package_objects": len(imported.objects),
        "report_sha256": hashlib.sha256(json.dumps(imported.report, sort_keys=True).encode()).hexdigest(),
    }

    jvm = _jvm_error_rate(JvmClassPath.of(_jmods() / "java.base.jmod", _jmods() / "java.desktop.jmod"))
    c_rows, c_types = _c_rows()
    c_errors = sum(item.cid != hand.cid for _label, item, hand, _request, _facts in c_rows)

    tokens_rows = []
    hand_built = {value[0]: value for value in _hand_built().values()}
    for row in jvm["rows"]:
        _where, declaration, types = hand_built[row["where"]]
        key, facts = _request(declaration, types)
        if "effect" in facts:
            facts["effect"] = _type_text(facts["effect"].cid, {facts["effect"].cid: facts["effect"]})
        tokens_rows.append(("jvm", json.dumps({"import": key, **facts}, separators=(",", ":")), _render(declaration, types)))
    for label, _item, hand, request, facts in c_rows:
        tokens_rows.append(("c", json.dumps({"import": request, **facts}, separators=(",", ":")), _render(hand, c_types)))
    totals = {}
    for ecosystem in ("jvm", "c"):
        chosen = [row for row in tokens_rows if row[0] == ecosystem]
        request_tokens = count("\n".join(row[1] for row in chosen))
        hand_tokens = count("\n".join(row[2] for row in chosen))
        totals[ecosystem] = {
            "declarations": len(chosen), "import_request_tokens": request_tokens, "hand_built_tokens": hand_tokens,
            "request_over_hand_built": {name: round(request_tokens[name] / hand_tokens[name], 3) for name in ENCODINGS},
            "example": {"request": chosen[0][1], "hand_built": chosen[0][2]},
        }
    return {
        "format": "xax-oi32-import-evidence-v1",
        "decision": "ADR-166",
        "evidence_label": "MEASURED (coverage, latency, size, error rate, offline tokens); EXECUTED programs in test_xax_jvm_import.py and test_xax_c_import.py",
        "tokenizer": f"tiktoken {tiktoken.__version__}",
        "java": base.metadata("java/lang/Object").major_version,
        "jvm_coverage": coverage,
        "error_rate": {
            "jvm": {key: jvm[key] for key in ("declarations", "errors", "error_rate")},
            "c": {"declarations": len(c_rows), "errors": c_errors, "error_rate": round(c_errors / len(c_rows), 4)},
            "jvm_rows": jvm["rows"],
        },
        "ai_tokens": totals,
    }


if __name__ == "__main__":
    evidence = run()
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(json.dumps({key: evidence[key] for key in ("jvm_coverage", "ai_tokens")}, indent=1))
    print(json.dumps({key: value for key, value in evidence["error_rate"].items() if key != "jvm_rows"}, indent=1))
    for row in evidence["error_rate"]["jvm_rows"]:
        if row["status"] != "byte-identical":
            print(row)
