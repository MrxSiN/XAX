"""Test driver outside BBC (BBC's AGENT.md): compile Brainfuck programs with bbc.exe under wine for both targets,
run them (wine / qemu-aarch64) and compare output bytes and exit status with an independent interpreter.

Usage: check.py <bbc.exe> <work directory> [case name ...]
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

TAPE = 2_147_246_080
OUT_LIMIT = 65536


def interpret(source: bytes, data: bytes, steps: int = 50_000_000):
    """(exit status, output) as BBC's profile defines them: 0 on success; a failed run (off the tape, output full)
    is reported as None (the comparison then only requires a non-zero exit)."""
    code = bytes(c for c in source if c in b"><+-.,[]")
    match, stack = {}, []
    for i, c in enumerate(code):
        if c == ord("["):
            stack.append(i)
        elif c == ord("]"):
            if not stack:
                return "invalid", b""
            j = stack.pop(); match[i] = j; match[j] = i
    if stack:
        return "invalid", b""
    tape = bytearray(1 << 16)
    ptr = pc = 0
    out = bytearray()
    inp = 0
    n = 0
    while pc < len(code):
        n += 1
        if n > steps:
            return "timeout", bytes(out)
        c = code[pc]
        if c == 62:
            ptr += 1
            if ptr >= TAPE:
                return None, bytes(out)
            if ptr >= len(tape):
                tape.extend(bytes(len(tape)))
        elif c == 60:
            ptr -= 1
            if ptr < 0:
                return None, bytes(out)
        elif c == 43:
            tape[ptr] = (tape[ptr] + 1) & 255
        elif c == 45:
            tape[ptr] = (tape[ptr] - 1) & 255
        elif c == 46:
            if len(out) >= OUT_LIMIT:
                return None, bytes(out)
            out.append(tape[ptr])
        elif c == 44:
            tape[ptr] = data[inp] if inp < len(data) else 0
            inp += 1
        elif c == 91 and tape[ptr] == 0:
            pc = match[pc]
        elif c == 93 and tape[ptr] != 0:
            pc = match[pc]
        pc += 1
    return 0, bytes(out)


HELLO = b"++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."
CASES = {
    "hello": (HELLO, [b""]),
    "echo": (b",[.,]", [b"", b"abc", bytes(range(1, 256))]),
    "add": (b",>,[<+>-]<.", [b"\x05\x07", b"\xff\x02"]),
    "nested": (b"++++[>++++[>++++<-]<-]>>.", [b""]),
    "left_edge": (b"<", [b""]),
    "reverse": (b">,[>,]<[.<]", [b"hello", b""]),
    "zero_loop": (b"[>+<-]+.", [b""]),
    "multiply": (b",>,<[>[>+>+<<-]>>[<<+>>-]<<<-]>>.", [b"\x06\x07", b"\x10\x10"]),
}


def main():
    bbc, work = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    names = sys.argv[3:] or list(CASES)
    work.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent
    for host in ("bbc-android-arm64.xax", "bbc-windows-x86_64.xax"):
        shutil.copy(here.parents[0] / host if (here.parents[0] / host).exists() else Path("/home/user/XAX/compiler/integration/bfx") / host, work / host)
    shutil.copy(bbc, work / "bbc.exe")
    env = {**os.environ, "WINEDEBUG": "-all"}
    results, passed = [], 0
    for name in names:
        source, inputs = CASES[name]
        for level in ("-O0", "-O1"):
            for target in ("windows-x86_64", "android-arm64"):
                out = f"{name}{level}.{'exe' if target.startswith('windows') else 'elf'}"
                start = time.time()
                compiled = subprocess.run(["wine", "bbc.exe", "compile", target, level, out], input=source, capture_output=True, cwd=work, env=env, timeout=3600)
                seconds = time.time() - start
                row = {"case": name, "level": level, "target": target, "compile_exit": compiled.returncode, "compile_seconds": round(seconds, 2)}
                ok = compiled.returncode == 0 and (work / out).exists()
                if ok:
                    data = (work / out).read_bytes()
                    row["artifact_sha256"] = hashlib.sha256(data).hexdigest(); row["artifact_bytes"] = len(data)
                    runs = []
                    for given in inputs:
                        expected_exit, expected_out = interpret(source, given)
                        if target.startswith("windows"):
                            run = subprocess.run(["wine", out], input=given, capture_output=True, cwd=work, env=env, timeout=600)
                        else:
                            (work / out).chmod(0o755)
                            run = subprocess.run(["qemu-aarch64", str(work / out)], input=given, capture_output=True, cwd=work, timeout=600)
                        good = run.stdout == expected_out and (run.returncode == 0 if expected_exit == 0 else run.returncode != 0)
                        runs.append({"input_sha256": hashlib.sha256(given).hexdigest(), "expected_exit": expected_exit, "exit": run.returncode,
                                     "output_matches": run.stdout == expected_out, "pass": good})
                        ok = ok and good
                    row["runs"] = runs
                else:
                    row["stderr"] = compiled.stderr[-400:].decode("latin-1")
                row["pass"] = ok
                passed += ok
                results.append(row)
                print(json.dumps({k: v for k, v in row.items() if k != "runs"}), flush=True)
    (work / "results.json").write_text(json.dumps({"passed": passed, "total": len(results), "results": results}, indent=1))
    print("passed", passed, "of", len(results))


if __name__ == "__main__":
    main()
