from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

import blake3 as blake3_module
from xax_native_blake3 import compile_blake3_compress_native, load_blake3_compress_program, native_blake3_compressor


IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)


def _median(samples):
    ordered = sorted(samples)
    return ordered[len(ordered) // 2]


def main() -> None:
    program = load_blake3_compress_program()
    image = compile_blake3_compress_native(program)
    native = native_blake3_compressor()
    cv = IV
    block = tuple((index * 0x9E3779B1 + 0x1234567) & 0xFFFFFFFF for index in range(16))
    args = (cv, block, 0x123456789ABCDEF0, 64, 3)
    expected = blake3_module._compress_python(*args)
    actual = native.compress(*args)
    if actual != expected:
        raise SystemExit("native XAX BLAKE3 compression mismatch")

    for _ in range(100):
        blake3_module._compress_python(*args)
        native.compress(*args)

    leaf_iterations = 5000
    python_leaf_samples = []
    native_leaf_samples = []
    for _ in range(3):
        start = time.perf_counter_ns()
        for _ in range(leaf_iterations):
            blake3_module._compress_python(*args)
        python_leaf_samples.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        for _ in range(leaf_iterations):
            native.compress(*args)
        native_leaf_samples.append(time.perf_counter_ns() - start)

    payload = bytes(range(256)) * 4096
    whole_iterations = 2
    native_object = blake3_module._NATIVE_COMPRESSOR
    attempted = blake3_module._NATIVE_ATTEMPTED
    blake3_module._NATIVE_COMPRESSOR = None
    blake3_module._NATIVE_ATTEMPTED = True
    start = time.perf_counter_ns()
    pure_digest = None
    for _ in range(whole_iterations):
        pure_digest = blake3_module.blake3(payload).digest()
    pure_whole = time.perf_counter_ns() - start
    blake3_module._NATIVE_COMPRESSOR = native_object or native
    blake3_module._NATIVE_ATTEMPTED = True
    start = time.perf_counter_ns()
    native_digest = None
    for _ in range(whole_iterations):
        native_digest = blake3_module.blake3(payload).digest()
    native_whole = time.perf_counter_ns() - start
    blake3_module._NATIVE_COMPRESSOR = native_object or native
    blake3_module._NATIVE_ATTEMPTED = attempted or True
    if native_digest != pure_digest:
        raise SystemExit("whole-hash digest mismatch")

    python_leaf = _median(python_leaf_samples)
    native_leaf = _median(native_leaf_samples)
    evidence = {
        "schema": "xax-native-blake3-evidence-v1",
        "host": {
            "machine": platform.machine(),
            "platform": sys.platform,
            "python": platform.python_version(),
        },
        "semantic": {
            "graph_cid": program.graph.cid.hex(),
            "function_cid": program.function.cid.hex(),
            "target_cid": program.target.cid.hex(),
            "store_root_cid": program.reader.root_cid.hex(),
            "store_bytes": len(bytes(program.reader.data)),
            "native_semantic_ranges": len(image.semantic_ranges),
        },
        "native": {
            "code_bytes": len(image.code),
            "host_abi_thunk_bytes": native.thunk_size,
            "vector_matches_python": True,
        },
        "performance": {
            "leaf_iterations": leaf_iterations,
            "python_leaf_ns": python_leaf,
            "xax_native_leaf_ns": native_leaf,
            "leaf_speedup": python_leaf / native_leaf,
            "whole_payload_bytes": len(payload),
            "whole_iterations": whole_iterations,
            "python_whole_ns": pure_whole,
            "xax_native_whole_ns": native_whole,
            "whole_speedup": pure_whole / native_whole,
        },
        "digest": native_digest.hex(),
    }
    destination = Path(__file__).with_name("xax_native_blake3_evidence.json")
    destination.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
