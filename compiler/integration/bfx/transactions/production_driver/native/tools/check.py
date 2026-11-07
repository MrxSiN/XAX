"""Test driver outside BBC (BBC's AGENT.md): compile Brainfuck programs with bbc.exe under wine for both targets,
run them (wine / qemu-aarch64) and compare output bytes and exit status with an independent interpreter; then the
compile error paths (exit statuses and no leftover files).

Usage: check.py <bbc.exe> <work directory> [--bbc <BBC checkout>] [case name ...]
The cases follow the 2026-10-21 campaign (single_process_evidence.json): pilot programs, BBC's tests, both depth-512
programs, negative loops, 60 random programs and capacity cases.
"""
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

TAPE = 2_147_246_080
IO_LIMIT = 65536
OFF_TAPE, OUTPUT_FULL, INPUT_LENGTH = 1, 2, 3  # BBC's run statuses (docs/01_BRAINFUCK_PROFILE.md)


def interpret(source: bytes, data: bytes, steps: int = 50_000_000):
    """(exit status, output) as BBC's profile defines them; "invalid" for unbalanced source, "timeout" past ``steps``."""
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
    if len(data) > IO_LIMIT:
        return INPUT_LENGTH, b""
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
                return OFF_TAPE, bytes(out)
            if ptr >= len(tape):
                tape.extend(bytes(len(tape)))
        elif c == 60:
            ptr -= 1
            if ptr < 0:
                return OFF_TAPE, bytes(out)
        elif c == 43:
            tape[ptr] = (tape[ptr] + 1) & 255
        elif c == 45:
            tape[ptr] = (tape[ptr] - 1) & 255
        elif c == 46:
            if len(out) >= IO_LIMIT:
                return OUTPUT_FULL, bytes(out)
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


def run(command, data=b"", **options):
    """``subprocess.run`` with stdin ``data`` and output captured in files, not pipes: wine's server and services,
    started by a run, inherit its descriptors, so a pipe would never reach end of file."""
    import tempfile

    with tempfile.TemporaryFile() as given, tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        given.write(data)
        given.seek(0)
        done = subprocess.run(command, stdin=given, stdout=out, stderr=err, **options)
        out.seek(0)
        err.seek(0)
        return subprocess.CompletedProcess(command, done.returncode, out.read(), err.read())


def _random_program(rng: random.Random) -> bytes:
    """A balanced program that ends: each loop is entered with a counter, in its own cell to the right of the cells
    the program uses, that only the loop decrements."""
    def block(depth):
        parts = []
        for _ in range(rng.randint(1, 8)):
            if rng.random() < 0.15 and depth < 4:
                far, back = ">" * (depth + 1), "<" * (depth + 1)
                parts.append(far + "+" * rng.randint(1, 6) + "[" + back + block(depth + 1) + far + "-]" + back)
            else:
                parts.append(rng.choice(["+", "-", "+++", "--", ".", ",", "<>", "><"]))
        return "".join(parts)
    return (">" + block(0)).encode()  # one cell of margin for "<>"


def cases(bbc_repo: Path):
    hello = b"++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."
    table = {
        "hello": (hello, [b""]),
        "echo": (b",[.,]", [b"", b"abc", bytes(range(1, 256))]),
        "add": (b",>,[<+>-]<.", [b"\x05\x07", b"\xff\x02"]),
        "nested": (b"++++[>++++[>++++<-]<-]>>.", [b""]),
        "left_edge": (b"<", [b""]),
        "reverse": (b">,[>,]<[.<]", [b"hello", b""]),
        "zero_loop": (b"[>+<-]+.", [b""]),
        "multiply": (b",>,<[>[>+>+<<-]>>[<<+>>-]<<<-]>>.", [b"\x06\x07", b"\x10\x10"]),
    }
    for name in ("basic", "loops", "bounds", "bounds_right"):
        path = bbc_repo / "tests" / f"{name}.bf"
        given = bbc_repo / "tests" / "bfx" / f"{name}.input"
        table[name] = (path.read_bytes(), [given.read_bytes() if given.exists() else b"", b"\x00", b"xyz"])
    table["bounds_right"] = (*table["bounds_right"], (OFF_TAPE, b""))  # crosses the right edge after 2^31 steps
    table["deep512"] = (b"[" * 512 + b"]" * 512 + b"+.", [b""])
    table["deep512active"] = (b">+[" * 512 + b"-]<" * 512 + b"+++.", [b""])
    for k in range(16):
        table[f"neg{k}"] = (b"-" * (k + 1) + b"[>+<-]>.,[-.]", [b"\x03", b"\x00"])
    rng = random.Random(20261107)
    for k in range(60):
        table[f"rand{k}"] = (_random_program(rng), [bytes(rng.randrange(256) for _ in range(8))])
    table["output-overflow"] = (b"+[.]", [b""])
    table["input-limit"] = (b",[.,]", [bytes(IO_LIMIT + 1)])
    table["input-full"] = (b",[>,]<[.<]", [bytes(range(1, 256)) * 257])
    return table


ERROR_PATHS = [  # (name, arguments, source, expected compile exit)
    ("invalid source", ["windows-x86_64", "-O1", "bad.exe"], b"[", 1),
    ("unknown target", ["linux-riscv", "-O1", "bad.exe"], b"+", 4),
    ("unsupported level -O3", ["windows-x86_64", "-O3", "bad.exe"], b"+", 4),
    ("host request missing", ["android-arm64", "-O1", "bad.elf"], b"+", 3),
    ("output directory missing", ["windows-x86_64", "-O1", "missing/bad.exe"], b"+", 3),
]


def _compile(work: Path, env, arguments, source):
    start = time.time()
    compiled = run(["wine", "bbc.exe", "compile", *arguments], source, cwd=work, env=env, timeout=3600)
    return compiled, round(time.time() - start, 2)


def _execute(work: Path, env, target: str, out: str, given: bytes):
    if target.startswith("windows"):
        return run(["wine", out], given, cwd=work, env=env, timeout=600)
    (work / out).chmod(0o755)
    return run(["qemu-aarch64", str(work / out)], given, cwd=work, timeout=600)


def check_case(work: Path, env, name, source, inputs, level, target, expected=None):
    """``expected``: the outcome for every input, for a program the interpreter cannot finish."""
    out = f"{name}{level}.{'exe' if target.startswith('windows') else 'elf'}"
    compiled, seconds = _compile(work, env, [target, level, out], source)
    row = {"case": name, "level": level, "target": target, "source_sha256": hashlib.sha256(source).hexdigest(),
           "compile_exit": compiled.returncode, "compile_seconds": seconds}
    ok = compiled.returncode == 0 and (work / out).exists()
    if not ok:
        row["stderr"] = compiled.stderr[-400:].decode("latin-1")
        row["pass"] = False
        return row
    data = (work / out).read_bytes()
    row["artifact_sha256"], row["artifact_bytes"] = hashlib.sha256(data).hexdigest(), len(data)
    runs = []
    for given in inputs:
        expected_exit, expected_out = expected or interpret(source, given)
        if expected_exit != 0:
            expected_out = b""  # a failed run's output is discarded
        run = _execute(work, env, target, out, given)
        good = run.stdout == expected_out and run.returncode == expected_exit
        runs.append({"input_sha256": hashlib.sha256(given).hexdigest(), "expected_exit": expected_exit, "exit": run.returncode,
                     "expected_output_sha256": hashlib.sha256(expected_out).hexdigest(),
                     "output_sha256": hashlib.sha256(run.stdout).hexdigest(), "pass": good})
        ok = ok and good
    for suffix in ("", ".xax", ".provenance"):
        (work / (out + suffix)).unlink(missing_ok=True)
    row["runs"], row["pass"] = runs, ok
    return row


def check_error_paths(work: Path, env):
    rows = []
    for name, arguments, source, expected in ERROR_PATHS:
        hidden = work / "bbc-android-arm64.xax"
        if name == "host request missing":
            hidden.rename(work / "hidden.xax")
        before = set(os.listdir(work))
        try:
            compiled, _seconds = _compile(work, env, arguments, source)
        finally:
            if name == "host request missing":
                (work / "hidden.xax").rename(hidden)
        leftover = sorted(set(os.listdir(work)) - before)
        rows.append({"case": name, "compile_exit": compiled.returncode, "expected_exit": expected, "leftover_files": leftover,
                     "pass": compiled.returncode == expected and not leftover})
    return rows


def main():
    arguments = sys.argv[1:]
    bbc_repo = Path("/home/user/BBC")
    if "--bbc" in arguments:
        k = arguments.index("--bbc")
        bbc_repo = Path(arguments[k + 1])
        del arguments[k:k + 2]
    bbc, work = Path(arguments[0]).resolve(), Path(arguments[1]).resolve()
    table = cases(bbc_repo)
    names = arguments[2:] or list(table)
    work.mkdir(parents=True, exist_ok=True)
    integration = Path(__file__).resolve().parents[4]  # compiler/integration/bfx
    for host in ("bbc-android-arm64.xax", "bbc-windows-x86_64.xax"):
        shutil.copy(integration / host, work / host)
    shutil.copy(bbc, work / "bbc.exe")
    env = {**os.environ, "WINEDEBUG": "-all"}
    results = []
    for name in names:
        source, inputs, *expected = table[name]
        for level in ("-O0", "-O1"):
            for target in ("android-arm64", "windows-x86_64"):
                row = check_case(work, env, name, source, inputs, level, target, *expected)
                results.append(row)
                print(json.dumps({k: v for k, v in row.items() if k != "runs"}), flush=True)
    errors = check_error_paths(work, env)
    for row in errors:
        print(json.dumps(row), flush=True)
    passed = sum(row["pass"] for row in results)
    summary = {"programs": len(names), "compiles": len(results), "passed": passed,
               "executions": sum(len(row.get("runs", ())) for row in results),
               "execution_mismatches": sum(not run["pass"] for row in results for run in row.get("runs", ())),
               "error_paths_passed": sum(row["pass"] for row in errors), "error_paths": len(errors)}
    (work / "results.json").write_text(json.dumps({**summary, "results": results, "error_path_results": errors}, indent=1))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
