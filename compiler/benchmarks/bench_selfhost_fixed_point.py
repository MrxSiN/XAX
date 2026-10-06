"""Self-hosting B1-B4 evidence (ADR-145): the XAX RISC-V backend compiles itself to a fixed point.

gen1 is the XAX backend program run natively (x86-64); gen2 is the RISC-V
views-profile image gen1 makes of the backend store (and the bootstrap
reference makes too); gen3 is the image gen2 makes of the same store when run
in the Unicorn RV64 emulator.  Records the store and image hashes, gen2 ==
reference, gen3 == gen2, and the emulated instruction count.  Host timings are
non-semantic.  Run: ``PYTHONPATH=src python benchmarks/bench_selfhost_fixed_point.py [--write]``.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parent / "selfhost_fixed_point_evidence.json"
CHUNK = 10**9


def _emulate(image, words, input_capacity, output_capacity, read_back):
    """``run_riscv64_views`` in ``CHUNK``-instruction slices: ``(result, instructions rounded up to a slice)``."""
    import unicorn
    from unicorn import riscv_const as rv

    import xax_riscv64 as R

    emulator = unicorn.Uc(unicorn.UC_ARCH_RISCV, unicorn.UC_MODE_RISCV64)
    emulator.mem_map(R._CODE_BASE, (len(image.code) + 0xFFF) & -0x1000)
    emulator.mem_write(R._CODE_BASE, image.code)
    emulator.mem_map(R._RETURN_SENTINEL, 0x1000)
    emulator.mem_map(R._STACK_TOP - R._STACK_SIZE, R._STACK_SIZE)
    emulator.mem_map(R._VIEWS_IN_BASE, (input_capacity + 0xFFF) & -0x1000)
    emulator.mem_map(R._VIEWS_OUT_BASE, (output_capacity + 0xFFF) & -0x1000)
    emulator.mem_write(R._VIEWS_IN_BASE, b"".join(int(word).to_bytes(8, "little") for word in words))
    emulator.reg_write(rv.UC_RISCV_REG_SP, R._STACK_TOP)
    emulator.reg_write(rv.UC_RISCV_REG_RA, R._RETURN_SENTINEL)
    emulator.reg_write(rv.UC_RISCV_REG_A0, R._VIEWS_IN_BASE)
    emulator.reg_write(rv.UC_RISCV_REG_A1, R._VIEWS_OUT_BASE)
    pc, slices = R._CODE_BASE + image.entry_offset, 0
    while pc != R._RETURN_SENTINEL:
        emulator.emu_start(pc, R._RETURN_SENTINEL, count=CHUNK)
        pc, slices = emulator.reg_read(rv.UC_RISCV_REG_PC), slices + 1

    def read_words(start, count):
        raw = bytes(emulator.mem_read(R._VIEWS_OUT_BASE + 8 * start, 8 * count)) if count else b""
        return [int.from_bytes(raw[k:k + 8], "little") for k in range(0, len(raw), 8)]

    return read_back(read_words), slices * CHUNK


def measure() -> dict:
    import xax_riscv64 as R
    from xax_compiler import riscv64_views_target
    from xax_selfhost_riscv64_backend import STORE_PATH, collect_output, load_backend_program
    from xax_selfhost_typing import IN_WORDS, OUT_WORDS

    reader, entry = load_backend_program()
    target = riscv64_views_target()
    start = time.perf_counter()
    gen2 = R.compile_riscv64_bound_target(reader, entry.cid, target, backend="xax")
    gen1_seconds = time.perf_counter() - start
    start = time.perf_counter()
    reference = R.compile_riscv64_bound_target(reader, entry.cid, target, backend="python")
    reference_seconds = time.perf_counter() - start
    words = R._object_table(reader, entry, target)
    start = time.perf_counter()
    output, instructions = _emulate(gen2, words, 8 * IN_WORDS, 8 * OUT_WORDS, collect_output)
    gen3_seconds = time.perf_counter() - start
    gen3 = None if output is None else R.image_from_backend_output(reader, target, output)
    store = STORE_PATH.read_bytes()
    return {
        "format": "xax-selfhost-fixed-point-evidence-v1",
        "component": "XAX RISC-V backend program, compiled by itself for the riscv64 views profile",
        "store": {"path": "compiler/bootstrap/xax_riscv64_backend.xax", "bytes": len(store), "sha256": hashlib.sha256(store).hexdigest(),
                  "root_cid": reader.root_cid.hex(), "entry_cid": entry.cid.hex(), "functions": len(gen2.function_offsets)},
        "target_cid": target.cid.hex(),
        "object_table_words": len(words),
        "gen2": {"code_bytes": len(gen2.code), "sha256": hashlib.sha256(gen2.code).hexdigest()},
        "gen2_equals_bootstrap_reference": gen2 == reference,
        "gen3": None if gen3 is None else {"code_bytes": len(gen3.code), "sha256": hashlib.sha256(gen3.code).hexdigest()},
        "gen3_equals_gen2": gen3 == gen2,
        "emulated_instructions_upper_bound": instructions,
        "host_cost_nonsemantic": {
            "host": f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
            "gen1_native_compile_s": round(gen1_seconds, 2),
            "bootstrap_reference_compile_s": round(reference_seconds, 2),
            "gen2_emulated_compile_s": round(gen3_seconds, 1),
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
