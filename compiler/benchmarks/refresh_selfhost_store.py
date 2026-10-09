"""Re-execute, on this Linux x86-64 host, every self-hosting evidence entry that describes one regenerated store.

``bench_selfhost_closure.py`` and ``bench_selfhost_x86_64.py`` measure every helper program; when only one helper's
store changes (ADR-249: the BLAKE3 hash's lent input view), this re-runs exactly that program's B1 entries and the
B3 rows for its store with the same per-entry procedure, leaving every other entry (whose store is unchanged) as
recorded.  It runs with ``XAX_REQUIRE_NATIVE=1`` and records ``xax_native.AUTHORITY`` under ``refreshed``.
Run: ``PYTHONPATH=src python benchmarks/refresh_selfhost_store.py xax_selfhost_blake3 [--write]``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import time
from pathlib import Path

os.environ["XAX_REQUIRE_NATIVE"] = "1"  # a Python fallback is an error here, never XAX evidence
sys.path.insert(0, str(Path(__file__).resolve().parent))

import blake3  # noqa: E402
from bench_selfhost_closure import BOOTSTRAP, PROGRAMS, same_verdicts, verifier_input  # noqa: E402
from bench_selfhost_fixed_point import _emulate  # noqa: E402

HERE = Path(__file__).resolve().parent


def _b1(module_name: str, loader: str, compile_image) -> tuple[dict, object, object]:
    reader, entry = getattr(importlib.import_module(module_name), loader)()
    start = time.perf_counter()
    gen1 = compile_image(reader, entry, "xax")
    gen1_seconds = time.perf_counter() - start
    start = time.perf_counter()
    reference = compile_image(reader, entry, "python")
    reference_seconds = time.perf_counter() - start
    record = {"program": module_name, "store_bytes": len(reader.data), "store_sha256": hashlib.sha256(reader.data).hexdigest(),
              "functions": len(gen1.function_offsets), "code_bytes": len(gen1.code), "image_sha256": hashlib.sha256(gen1.code).hexdigest(),
              "gen1_equals_bootstrap_reference": gen1 == reference,
              "host_s_nonsemantic": {"gen1": round(gen1_seconds, 2), "bootstrap": round(reference_seconds, 2)}}
    return record, reader, gen1


def _replace(items: list, key: str, value: str, record: dict) -> None:
    for index, item in enumerate(items):
        if item[key] == value:
            items[index] = record
            return
    raise KeyError(value)


def refresh(module_name: str) -> dict:
    import xax_compiler as X
    import xax_riscv64 as R
    from xax_selfhost_typing import IN_WORDS, OUT_WORDS
    from xax_selfhost_verify import collect_verdicts, native_store_verifier
    from xax_x86_64_views import compile_x86_64_views

    loader = dict(PROGRAMS)[module_name]
    store = importlib.import_module(module_name).STORE_PATH
    reader = X.StoreReader(store.read_bytes())
    words, listed, groups = verifier_input(reader)
    native = native_store_verifier().verify(words, len(listed), groups)
    refreshed = {}

    # selfhost_closure_evidence.json: B1 (RV64), B3 emulated verifier row, and the emulated BLAKE3 rows.
    rv_target = X.riscv64_views_target()
    rv_record, _reader, rv_image = _b1(module_name, loader, lambda r, e, backend: R.compile_riscv64_bound_target(r, e.cid, rv_target, backend=backend))
    closure = json.loads((HERE / "selfhost_closure_evidence.json").read_text())
    _replace(closure["b1_gen1_images"], "program", module_name, rv_record)
    verifier_image = R.compile_riscv64_bound_target(*(lambda r, e: (r, e.cid))(*importlib.import_module("xax_selfhost_verify").load_verifier_program()), rv_target, backend="xax")
    start = time.perf_counter()
    emulated, instructions = _emulate(verifier_image, words, 8 * IN_WORDS, 8 * OUT_WORDS, lambda read: collect_verdicts(read, len(listed), groups))
    _replace(closure["b3_emulated_verifier"], "store", store.name, {
        "store": store.name, "objects": len(listed), "store_proven": bool(native and native[0]),
        "objects_proven": sum(1 for verdict in (native[1] if native else ()) if verdict == 1),
        "emulated_equals_native": same_verdicts(emulated, native, listed), "emulated_instructions_upper_bound": instructions,
        "host_s_nonsemantic": {"emulated": round(time.perf_counter() - start, 1)}})
    if module_name == "xax_selfhost_blake3":
        from xax_selfhost_blake3 import INPUT_EXTENT, run_riscv64_hash

        hashes = []
        for path in sorted(BOOTSTRAP.glob("*.xax")):
            data = path.read_bytes()
            if len(data) > INPUT_EXTENT:
                continue
            start = time.perf_counter()
            digest = run_riscv64_hash(rv_image, data)
            hashes.append({"store": path.name, "bytes": len(data), "emulated_equals_production": digest == blake3.blake3(data).digest(),
                           "host_s_nonsemantic": round(time.perf_counter() - start, 2)})
        closure["b3_emulated_blake3"] = hashes
    refreshed["selfhost_closure_evidence.json"] = closure

    # selfhost_x86_64_evidence.json: B1 (x86-64 views) and the native verifier row.
    x_target = X.x86_64_views_target()
    x_record, _reader, _image = _b1(module_name, loader, lambda r, e, backend: compile_x86_64_views(r, e.cid, x_target, backend=backend))
    x86 = json.loads((HERE / "selfhost_x86_64_evidence.json").read_text())
    _replace(x86["b1_gen1_images"], "program", module_name, x_record)
    bootstrap_ok = True
    try:
        X.verify_store(reader)
    except X.XaxError:
        bootstrap_ok = False
    _replace(x86["b3_native_verifier"], "store", store.name, {
        "store": store.name, "objects": len(listed), "store_verdict": bool(native and native[0]), "bootstrap_accepts": bootstrap_ok,
        "agrees": bool(native) and native[0] == bootstrap_ok})
    refreshed["selfhost_x86_64_evidence.json"] = x86

    import xax_native

    for evidence in refreshed.values():
        evidence["refreshed"] = {"program": module_name, "store": store.name, "store_sha256": hashlib.sha256(reader.data).hexdigest(),
                                 "reason": "ADR-249: only this store changed; its entries were re-executed natively",
                                 "authority": xax_native.AUTHORITY}
    return refreshed


if __name__ == "__main__":
    results = refresh(sys.argv[1])
    for name, evidence in results.items():
        text = json.dumps(evidence, indent=2) + "\n"
        if "--write" in sys.argv:
            (HERE / name).write_text(text)
    print(json.dumps({name: {"b1": next(e for e in ev["b1_gen1_images"] if e["program"] == sys.argv[1])} for name, ev in results.items()}, indent=1))
