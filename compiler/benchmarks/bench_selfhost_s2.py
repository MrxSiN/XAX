"""Self-hosting step S2 evidence (ADR-117): CIDs computed by the XAX-authored BLAKE3 hash.

Compares the XAX hash (one native call per object) with the bootstrap driver
(Python chunking/tree plus the S0 native compression leaf) on object-sized
inputs and on verifying a large canonical store.  Host timings are
non-semantic.  Run: ``PYTHONPATH=src python benchmarks/bench_selfhost_s2.py [--write]``.
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

import blake3
from xax_selfhost_blake3 import STORE_PATH, NativeHasher, load_hash_program

EVIDENCE = Path(__file__).resolve().parent / "selfhost_s2_evidence.json"


def _median(action, repetitions=7) -> float:
    samples = []
    for _ in range(repetitions):
        start = time.perf_counter()
        action()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def measure() -> dict:
    reader, function = load_hash_program()
    hasher = NativeHasher()
    rng = random.Random(3)
    objects = [rng.randbytes(rng.choice((40, 90, 160, 400, 1200, 3000))) for _ in range(3000)]
    agree = sum(hasher.digest(item) == blake3._Blake3(item).digest() for item in objects)
    xax = _median(lambda: [hasher.digest(item) for item in objects])
    driver = _median(lambda: [blake3._Blake3(item).digest() for item in objects])
    large = rng.randbytes(1 << 20)
    xax_large = _median(lambda: hasher.digest(large))
    driver_large = _median(lambda: blake3._Blake3(large).digest(), 3)
    store = STORE_PATH.read_bytes()
    return {
        "format": "xax-selfhost-s2-evidence-v1",
        "component": "BLAKE3-256 hash (chunking, padding, chaining-value tree) over lent views",
        "store": {"path": "compiler/bootstrap/xax_blake3_hash.xax", "bytes": len(store), "sha256": hashlib.sha256(store).hexdigest(), "root_cid": reader.root_cid.hex(), "hash_cid": function.cid.hex()},
        "native_leaf_bytes": hasher.code_size,
        "agreement_with_python_driver": [agree, len(objects)],
        "host_cost_nonsemantic": {
            "host": f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
            "objects": len(objects),
            "object_hashing_ms": {"xax_hash": round(xax * 1e3, 2), "python_driver_with_s0_leaf": round(driver * 1e3, 2), "speedup": round(driver / xax, 2)},
            "one_mib_ms": {"xax_hash": round(xax_large * 1e3, 2), "python_driver_with_s0_leaf": round(driver_large * 1e3, 2)},
        },
    }


if __name__ == "__main__":
    import os

    os.environ["XAX_REQUIRE_NATIVE"] = "1"  # a Python fallback is an error here, never XAX evidence
    evidence = measure()
    evidence["authority"] = __import__("xax_native").AUTHORITY
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
