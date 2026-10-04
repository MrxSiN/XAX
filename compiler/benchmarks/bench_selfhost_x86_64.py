"""S7a evidence (ADR-152): the XAX x86-64 backend closes over itself natively on x86-64.

B1: gen1 (the XAX x86-64 backend program) compiles every XAX helper program, itself
included, to the bootstrap generator's image (``xax_x86_64_views``).  B2/B3: the
store verifier's image (the one production now runs) gives the verdicts the
bootstrap's Python verifier gives on every committed store.  B4: gen2 (the backend's
own image, run natively) compiles the backend store to gen2.  Also measured: the
helper images' run time against the images the optimizing bootstrap x86-64 backend
(``xax_x86_64.compile_native``) makes of the same stores, on the same inputs (median of
seven; the input copy is included in both).  Host timings are non-semantic.
Run: ``PYTHONPATH=src python benchmarks/bench_selfhost_x86_64.py [--write]``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_selfhost_closure import PROGRAMS, verifier_input  # noqa: E402

EVIDENCE = Path(__file__).resolve().parent / "selfhost_x86_64_evidence.json"
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
HELPERS = (*PROGRAMS, ("xax_selfhost_x86_64_backend", "load_backend_program"))


def _median(function, repeats=7):
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        function()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def measure() -> dict:
    import xax_compiler as X
    from xax_riscv64 import _object_table
    from xax_selfhost_views_backend import _NativeRunner
    from xax_selfhost_verify import collect_verdicts
    from xax_selfhost_x86_64_backend import collect_output, image_from_backend_output
    from xax_x86_64 import compile_native
    from xax_x86_64_views import compile_x86_64_views

    target = X.x86_64_views_target()
    images, b1 = {}, []
    for module, loader in HELPERS:
        reader, entry = getattr(importlib.import_module(module), loader)()
        start = time.perf_counter()
        gen1 = compile_x86_64_views(reader, entry.cid, target, backend="xax")
        gen1_seconds = time.perf_counter() - start
        start = time.perf_counter()
        reference = compile_x86_64_views(reader, entry.cid, target, backend="python")
        reference_seconds = time.perf_counter() - start
        images[module] = (reader, entry, gen1)
        b1.append({"program": module, "store_bytes": len(reader.data), "functions": len(gen1.function_offsets), "code_bytes": len(gen1.code),
                   "image_sha256": hashlib.sha256(gen1.code).hexdigest(), "gen1_equals_bootstrap_reference": gen1 == reference,
                   "host_s_nonsemantic": {"gen1": round(gen1_seconds, 2), "bootstrap": round(reference_seconds, 2)}})

    verifier_reader, verifier_entry, verifier_image = images["xax_selfhost_verify"]
    verifier = _NativeRunner(verifier_image.code, verifier_image.entry_offset)
    b3 = []
    for path in sorted(BOOTSTRAP.glob("*.xax")):
        reader = X.StoreReader(path.read_bytes())
        words, listed, groups = verifier_input(reader)
        native = verifier.run(words, lambda read: collect_verdicts(read, len(listed), groups))
        bootstrap_ok = True
        try:
            X.verify_store(reader)
        except X.XaxError:
            bootstrap_ok = False
        b3.append({"store": path.name, "objects": len(listed), "store_verdict": bool(native and native[0]), "bootstrap_accepts": bootstrap_ok,
                   "agrees": bool(native) and native[0] == bootstrap_ok})

    backend_reader, backend_entry, gen2 = images["xax_selfhost_x86_64_backend"]
    runner = _NativeRunner(gen2.code, gen2.entry_offset)
    words = _object_table(backend_reader, backend_entry, target)
    start = time.perf_counter()
    gen3 = image_from_backend_output(backend_reader, target, runner.run(words, collect_output))
    b4 = {"compiler": "gen2: the backend's x86-64 image, native", "code_bytes": len(gen2.code), "sha256": hashlib.sha256(gen2.code).hexdigest(),
          "gen3_equals_gen2": gen3 == gen2, "host_s_nonsemantic": round(time.perf_counter() - start, 2)}

    runtime = []
    for module, store in (("xax_selfhost_verify", "xax_op_typing.xax"), ("xax_selfhost_verify", "xax_store_verifier.xax"),
                          ("xax_selfhost_verify", "xax_riscv64_backend.xax")):
        reader, entry, image = images[module]
        target_object = next(item for item in reader.objects() if item.kind == X.Kind.TARGET)
        optimized = compile_native(reader, entry.cid, target_object.cid)
        xax_runner, optimized_runner = _NativeRunner(image.code, image.entry_offset), _NativeRunner(optimized.code, optimized.entry_offset)
        input_reader = X.StoreReader((BOOTSTRAP / store).read_bytes())
        words, listed, groups = verifier_input(input_reader)
        status = lambda read: read(0, 2)  # noqa: E731
        xax_s, optimized_s = _median(lambda: xax_runner.run(words, status)), _median(lambda: optimized_runner.run(words, status))
        runtime.append({"program": module, "input": store, "xax_backend_s": round(xax_s, 4), "optimizing_bootstrap_s": round(optimized_s, 4),
                        "ratio": round(xax_s / optimized_s, 3), "code_bytes": {"xax_backend": len(image.code), "optimizing_bootstrap": len(optimized.code)}})

    return {
        "format": "xax-selfhost-x86-64-evidence-v1",
        "label": "EXECUTED",
        "target_cid": target.cid.hex(),
        "host_nonsemantic": f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
        "b1_gen1_images": b1,
        "b3_native_verifier": b3,
        "b4_native_fixed_point": b4,
        "runtime_vs_optimizing_bootstrap": runtime,
    }


if __name__ == "__main__":
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
