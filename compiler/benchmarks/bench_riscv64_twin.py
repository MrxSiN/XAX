"""riscv64 row measurement (ADR-113): XAX raw image versus clang -O2 on the same emulator.

Two kernels with C twins: ``sum_to(n)`` (u32 loop) and the Collatz total-step
kernel shared with the JVM benchmark (u64, nested loops, data-dependent
branch).  Both sides run as raw position-independent RV64IM code in Unicorn;
the metric is the *emulated instruction count* (deterministic, counted per
executed basic block) and the code bytes.  This is not hardware time: there
is no RISC-V hardware on the measuring host.

Run: ``PYTHONPATH=src python benchmarks/bench_riscv64_twin.py [--write]``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tests"))

from xax_compiler import riscv64_baremetal_target  # noqa: E402
from xax_graph_builder import program_store  # noqa: E402
from xax_riscv64 import compile_riscv64_bound_target  # noqa: E402

EVIDENCE = HERE / "riscv64_twin_evidence.json"
CLANG_FLAGS = ["--target=riscv64-unknown-elf", "-march=rv64im", "-mabi=lp64", "-O2", "-ffreestanding", "-fno-builtin", "-mno-relax", "-c"]

C_SOURCES = {
    "sum_to": ("unsigned sum_to(unsigned n) { unsigned s = 0; for (unsigned i = 1; i <= n; i++) s += i; return s; }\n", 32, (1000,)),
    "collatz": (
        "unsigned long kernel(unsigned long n) { unsigned long acc = 0;"
        " for (unsigned long i = 1; i <= n; i++) { unsigned long x = i;"
        " while (x != 1) { if (x & 1) x = 3 * x + 1; else x >>= 1; acc++; } } return acc; }\n",
        64, (300,),
    ),
}


def _xax_kernels():
    from bench_jvm_twin import collatz_kernel
    from test_xax_pe import _sum_to

    sum_to, sum_objects = _sum_to()
    collatz, collatz_graph = collatz_kernel()
    return {"sum_to": (sum_to, sum_objects), "collatz": (collatz, tuple(collatz_graph.objects.values()))}


def _count(code: bytes, arguments: tuple[int, ...], width: int) -> tuple[int, int]:
    import unicorn
    from unicorn import riscv_const as rv

    emulator = unicorn.Uc(unicorn.UC_ARCH_RISCV, unicorn.UC_MODE_RISCV64)
    base, sentinel, stack_top = 0x10000, 0x1000, 0x80000000
    emulator.mem_map(base, (len(code) + 0xFFF) & -0x1000)
    emulator.mem_write(base, code)
    emulator.mem_map(sentinel, 0x1000)
    emulator.mem_map(stack_top - (1 << 20), 1 << 20)
    emulator.reg_write(rv.UC_RISCV_REG_SP, stack_top)
    emulator.reg_write(rv.UC_RISCV_REG_RA, sentinel)
    for register, value in enumerate(arguments):
        emulator.reg_write(rv.UC_RISCV_REG_A0 + register, value)
    executed = [0]

    def block(_uc, address, size, _data):
        if address != sentinel:
            executed[0] += size // 4

    emulator.hook_add(unicorn.UC_HOOK_BLOCK, block)
    emulator.emu_start(base, sentinel, count=500_000_000)
    return emulator.reg_read(rv.UC_RISCV_REG_A0) & ((1 << width) - 1), executed[0]


def _clang_text(source: str) -> tuple[bytes, str]:
    clang, objcopy = shutil.which("clang"), shutil.which("llvm-objcopy")
    with tempfile.TemporaryDirectory() as directory:
        c_path, o_path, bin_path = (os.path.join(directory, name) for name in ("k.c", "k.o", "k.bin"))
        Path(c_path).write_text(source)
        subprocess.run([clang, *CLANG_FLAGS, c_path, "-o", o_path], check=True)
        subprocess.run([objcopy, "-O", "binary", "--only-section=.text", o_path, bin_path], check=True)
        version = subprocess.run([clang, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        return Path(bin_path).read_bytes(), version


def measure() -> dict:
    target = riscv64_baremetal_target()
    rows = {}
    clang_version = ""
    for name, (entry, objects) in _xax_kernels().items():
        source, width, arguments = C_SOURCES[name]
        image = compile_riscv64_bound_target(program_store(entry, target, objects), entry.cid, target)
        xax_result, xax_count = _count(image.code, arguments, width)
        c_code, clang_version = _clang_text(source)
        c_result, c_count = _count(c_code, arguments, width)
        if xax_result != c_result:
            raise AssertionError(f"{name}: results differ {xax_result} != {c_result}")
        rows[name] = {
            "arguments": list(arguments), "result": xax_result,
            "xax": {"code_bytes": len(image.code), "instructions_executed": xax_count},
            "clang_O2": {"code_bytes": len(c_code), "instructions_executed": c_count},
            "ratio_xax_over_clang": {"instructions": round(xax_count / c_count, 2), "code_bytes": round(len(image.code) / len(c_code), 2)},
        }
    import unicorn

    return {
        "format": "xax-riscv64-twin-evidence-v1",
        "label": "MEASURED",
        "metric": "emulated RV64IM instructions executed (Unicorn, per basic block) and code bytes; not hardware time",
        "toolchain": {"clang": clang_version, "flags": " ".join(CLANG_FLAGS), "emulator": f"unicorn {unicorn.__version__}"},
        "xax_lowering": "riscv64-baremetal-raw-v1 first lowering: every value spilled to a frame slot",
        "kernels": rows,
    }


if __name__ == "__main__":
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
