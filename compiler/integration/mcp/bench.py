"""Measure the native server on this host (raw samples; development tooling, not a runtime dependency).

    python compiler/integration/mcp/bench.py <native exe> > evidence.json

Per launch: wall time from process creation to the initialize response (cold start), then the median latency of ping,
tools/list and xax_capabilities round trips, and the process's peak working set (Windows).  These are MCP transport
measurements, not generated-code (R4) benchmarks.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INIT = {"jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "bench", "version": "0"}}}
CALLS = {"ping": {"method": "ping"}, "tools_list": {"method": "tools/list"},
         "capabilities": {"method": "tools/call", "params": {"name": "xax_capabilities", "arguments": {}}}}


class Counters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def peak_working_set(pid: int) -> int:
    kernel32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
    handle = kernel32.OpenProcess(0x1000 | 0x0010, False, pid)  # QUERY_LIMITED_INFORMATION | VM_READ
    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
    kernel32.CloseHandle(handle)
    return counters.PeakWorkingSetSize


def session(command: list[str], rounds: int) -> dict:
    started = time.perf_counter()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def exchange(message: dict) -> dict:
        process.stdin.write(json.dumps(message).encode() + b"\n")
        process.stdin.flush()
        return json.loads(process.stdout.readline())

    assert "result" in exchange(INIT)
    sample = {"initialize_s": time.perf_counter() - started}
    for name, body in CALLS.items():
        times = []
        for k in range(rounds):
            t = time.perf_counter()
            assert "result" in exchange({"jsonrpc": "2.0", "id": k + 1, **body})
            times.append(time.perf_counter() - t)
        sample[f"{name}_median_s"] = statistics.median(times)
    sample["peak_working_set_bytes"] = peak_working_set(process.pid)
    process.stdin.close()
    process.wait(60)
    return sample


def main(argv: list[str]) -> int:
    native = argv[1]
    launches, rounds = 15, 50
    samples = [session([native], rounds) for _ in range(launches)]
    summary = {key: statistics.median(s[key] for s in samples) for key in samples[0]}
    print(json.dumps({"native": native,
                      "host": {"platform": platform.platform(), "machine": platform.machine(),
                               "processor": platform.processor(), "cpu_count": os.cpu_count()},
                      "method": f"{launches} launches; per launch {rounds} round trips per call; "
                                "initialize_s is process creation to initialize response",
                      "summary_medians": summary, "samples": samples}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
