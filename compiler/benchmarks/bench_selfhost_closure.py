"""S6c evidence (ADR-150, ADR-151): the XAX verifier and code generator close over themselves on RV64.

B1: gen1 (the XAX RISC-V backend run natively) compiles every XAX helper
program (CFG analysis, graph and store decoders, encoder, operation typing and
facts, store verifier, the BLAKE3 hash, the backend itself) to the image the
bootstrap generator makes.  The BLAKE3 image, emulated, hashes committed stores
to the production digest.  B2/B3: the store verifier's RISC-V image,
run in the Unicorn RV64 emulator, verifies every committed store (its own
included) with exactly the native production verifier's verdicts.  B4: gen2 (the
backend's own RISC-V image) compiling the verifier store under emulation
reproduces the verifier image byte for byte.  Host timings are non-semantic.
Run: ``PYTHONPATH=src python benchmarks/bench_selfhost_closure.py [--write]``.
"""

from __future__ import annotations

import hashlib
import importlib

import blake3
import json
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_selfhost_fixed_point import _emulate  # noqa: E402

EVIDENCE = Path(__file__).resolve().parent / "selfhost_closure_evidence.json"
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
PROGRAMS = (
    ("xax_selfhost_cfg", "load_cfg_program"),
    ("xax_selfhost_graph", "load_graph_decoder_program"),
    ("xax_selfhost_riscv64", "load_encoder_program"),
    ("xax_selfhost_store", "load_decoder_program"),
    ("xax_selfhost_typing", "load_typing_program"),
    ("xax_selfhost_verify", "load_verifier_program"),
    ("xax_selfhost_blake3", "load_hash_program"),
    ("xax_selfhost_riscv64_backend", "load_backend_program"),
)


def verifier_input(reader, listed=None):
    """The store verifier's input words for ``reader`` (or its objects ``listed``) as ``_xax_verify_store`` builds
    them, the objects, and the group positions; None when a graph body cannot be streamed."""
    import xax_compiler as X
    from xax_selfhost_verify import object_table

    listed = list(reader.objects()) if listed is None else listed
    objects = {obj.cid: obj for obj in listed}
    X._xax_prove_objects(objects, objects.__getitem__)
    index = {obj.cid: position for position, obj in enumerate(listed)}
    table = object_table(listed, [index[reader.root_cid]])
    if table is None:
        return None
    words = table + [int(obj.cid in X._XAX_VALID_OBJECTS) for obj in listed]
    return words, listed, [position for position, obj in enumerate(listed) if obj.kind == X.Kind.RECURSION_GROUP]


def same_verdicts(emulated, native, listed) -> bool:
    """Store and object verdicts, each proven function's graph word, and each proven group's members agree."""
    from xax_compiler import Kind

    return (emulated is not None and native is not None and emulated[0] == native[0] and list(emulated[1]) == list(native[1])
            and all(emulated[2][o] == native[2][o] for o, obj in enumerate(listed) if obj.kind == Kind.FUNCTION and native[1][o] == 1)
            and emulated[3] == native[3])


def measure(include_b4: bool = True) -> dict:
    import xax_compiler as X
    import xax_riscv64 as R
    from xax_selfhost_riscv64_backend import collect_output
    from xax_selfhost_typing import IN_WORDS, OUT_WORDS
    from xax_selfhost_verify import collect_verdicts, native_store_verifier

    target = X.riscv64_views_target()
    images, b1 = {}, []
    for module, loader in PROGRAMS:
        reader, entry = getattr(importlib.import_module(module), loader)()
        start = time.perf_counter()
        gen1 = R.compile_riscv64_bound_target(reader, entry.cid, target, backend="xax")
        gen1_seconds = time.perf_counter() - start
        start = time.perf_counter()
        reference = R.compile_riscv64_bound_target(reader, entry.cid, target, backend="python")
        reference_seconds = time.perf_counter() - start
        images[module] = (reader, entry, gen1)
        b1.append({"program": module, "store_bytes": len(reader.data), "store_sha256": hashlib.sha256(reader.data).hexdigest(),
                   "functions": len(gen1.function_offsets), "code_bytes": len(gen1.code), "image_sha256": hashlib.sha256(gen1.code).hexdigest(),
                   "gen1_equals_bootstrap_reference": gen1 == reference,
                   "host_s_nonsemantic": {"gen1": round(gen1_seconds, 2), "bootstrap": round(reference_seconds, 2)}})

    verifier_reader, verifier_entry, verifier_image = images["xax_selfhost_verify"]
    native = native_store_verifier()
    b3 = []
    for path in sorted(BOOTSTRAP.glob("*.xax")):
        reader = X.StoreReader(path.read_bytes())
        words, listed, groups = verifier_input(reader)
        start = time.perf_counter()
        expected = native.verify(words, len(listed), groups)
        native_seconds = time.perf_counter() - start
        start = time.perf_counter()
        emulated, instructions = _emulate(verifier_image, words, 8 * IN_WORDS, 8 * OUT_WORDS, lambda read: collect_verdicts(read, len(listed), groups))
        emulated_seconds = time.perf_counter() - start
        b3.append({"store": path.name, "objects": len(listed), "store_proven": bool(expected and expected[0]),
                   "objects_proven": sum(1 for verdict in (expected[1] if expected else ()) if verdict == 1),
                   "emulated_equals_native": same_verdicts(emulated, expected, listed),
                   "emulated_instructions_upper_bound": instructions,
                   "host_s_nonsemantic": {"native": round(native_seconds, 3), "emulated": round(emulated_seconds, 1)}})

    from xax_selfhost_blake3 import INPUT_EXTENT, run_riscv64_hash

    hash_image = images["xax_selfhost_blake3"][2]
    hashes = []
    for path in sorted(BOOTSTRAP.glob("*.xax")):
        data = path.read_bytes()
        if len(data) > INPUT_EXTENT:
            continue
        start = time.perf_counter()
        digest = run_riscv64_hash(hash_image, data)
        hashes.append({"store": path.name, "bytes": len(data), "emulated_equals_production": digest == blake3.blake3(data).digest(),
                       "host_s_nonsemantic": round(time.perf_counter() - start, 2)})

    b4 = None
    if include_b4:
        backend_reader, backend_entry, backend_image = images["xax_selfhost_riscv64_backend"]
        words = R._object_table(verifier_reader, verifier_entry, target)
        start = time.perf_counter()
        output, instructions = _emulate(backend_image, words, 8 * IN_WORDS, 8 * OUT_WORDS, collect_output)
        seconds = time.perf_counter() - start
        compiled = None if output is None else R.image_from_backend_output(verifier_reader, target, output)
        b4 = {"compiler": "gen2: the backend's RISC-V image, emulated", "input": "xax_store_verifier.xax",
              "code_bytes": None if compiled is None else len(compiled.code),
              "sha256": None if compiled is None else hashlib.sha256(compiled.code).hexdigest(),
              "equals_gen1_verifier_image": compiled == verifier_image,
              "emulated_instructions_upper_bound": instructions, "host_s_nonsemantic": round(seconds, 1)}

    return {
        "format": "xax-selfhost-closure-evidence-v1",
        "target_cid": target.cid.hex(),
        "host_nonsemantic": f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
        "b1_gen1_images": b1,
        "b3_emulated_verifier": b3,
        "b3_emulated_blake3": hashes,
        "b4_gen2_compiles_verifier": b4,
    }


if __name__ == "__main__":
    evidence = measure(include_b4="--no-b4" not in sys.argv)
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
