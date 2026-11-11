"""OI-55 probe: signed compares below 32 bits, built by a native xaxc and run, against the reference executor.

usage: oi55_probe.py <xaxc> [widths...]      (run from compiler/ with PYTHONPATH=src:reference:.)
Each program writes 64 flags (8 x 8 operand pairs) as one little-endian word to stdout.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

from xax_compiler import execute
from xax_construct import construct

KINDS = ("slt", "sle", "sgt", "sge", "ult", "eq")
FORMS = ("set", "cbr", "multi", "immr", "imml", "frame-set", "frame-cbr", "main")
M64 = (1 << 64) - 1


def values(width):
    top = 1 << (width - 1)
    return (0, 1, 3, top - 1, top, top + 1, (1 << width) - 1, (0xF1 | (0xABCD << width)) & M64)


def expected(width, kind, left, right):
    mask = (1 << width) - 1
    left, right = left & mask, right & mask
    if kind in ("ult", "eq"):
        return int(left < right if kind == "ult" else left == right)
    sign = lambda v: v - (1 << width) if v >> (width - 1) else v  # noqa: E731
    left, right = sign(left), sign(right)
    return int({"slt": left < right, "sle": left <= right, "sgt": left > right, "sge": left >= right}[kind])


def helper(name, width, kind, form, const=None):
    """fn(b64...) -> b64: the flag of compare(truncate(a), truncate(b)), in the given form."""
    t = f"b{width}"
    count = 5 if form.startswith("frame") else 1 if form in ("immr", "imml") else 2
    params = ["b64"] * count
    if form == "immr":
        nodes = [["int.truncate", ["p0"], [t]], ["int.compare", ["n0", [t, const]], ["b1"], {"attrs": [kind]}]]
    elif form == "imml":
        nodes = [["int.truncate", ["p0"], [t]], ["int.compare", [[t, const], "n0"], ["b1"], {"attrs": [kind]}]]
    else:
        nodes = [["int.truncate", ["p0"], [t]], ["int.truncate", ["p1"], [t]], ["int.compare", ["n0", "n1"], ["b1"], {"attrs": [kind]}]]
    flag = f"n{len(nodes) - 1}"
    if form in ("cbr", "frame-cbr"):
        blocks = [{"params": params, "nodes": nodes, "end": ["cbr", flag, 1, [], 2, []]},
                  {"params": [], "nodes": [], "end": ["ret", [["b64", 1]]]},
                  {"params": [], "nodes": [], "end": ["ret", [["b64", 0]]]}]
    elif form == "multi":
        nodes.append(["int.zero.extend", [flag], ["b64"]])
        blocks = [{"params": params, "nodes": nodes, "end": ["cbr", flag, 1, [], 2, []]},
                  {"params": [], "nodes": [], "end": ["ret", [f"B0.n{len(nodes) - 1}"]]},
                  {"params": [], "nodes": [["add.wrap", [f"B0.n{len(nodes) - 1}", ["b64", 7]], ["b64"]]], "end": ["ret", ["n0"]]}]
    else:
        nodes.append(["int.zero.extend", [flag], ["b64"]])
        blocks = [{"params": params, "nodes": nodes, "end": ["ret", [f"n{len(nodes) - 1}"]]}]
    return {"name": name, "params": params, "returns": ["b64"], "blocks": blocks}


def program(width, kind, form):
    vals = values(width)
    nodes = []

    def add(*node):
        nodes.append(list(node))
        return f"n{len(nodes) - 1}"

    fx = ["linux.process_effect", "linux.filesystem_effect", "mem"]
    heap = add("call.foreign", [["b64", 64], "p2"], ["linux.bytes_rw", "linux.heap_owner", "mem"], {"entity": "linux.mmap_anonymous"})
    view = add("heap.view", [heap, f"{heap}.r1", f"{heap}.r2"], ["linux.bytes_rw", "buf", "mem"], {"attrs": [64, 1]})
    argc = add("call.foreign", [], ["b64"], {"entity": "linux.startup.argc"})
    functions = []
    if form in ("immr", "imml"):
        functions = [helper(f"cmp{j}", width, kind, form, v & ((1 << width) - 1)) for j, v in enumerate(vals)]
    elif form != "main":
        functions = [helper("cmp", width, kind, form)]
    acc = None
    for i, left in enumerate(vals):
        for j, right in enumerate(vals):
            a = add("mul.wrap", [argc, ["b64", left]], ["b64"])
            b = add("mul.wrap", [argc, ["b64", right]], ["b64"])
            if form == "immr":
                flag = add("call.direct", [a], ["b64"], {"entity": {"fn": f"cmp{j}"}})
            elif form == "imml":
                flag = add("call.direct", [b], ["b64"], {"entity": {"fn": f"cmp{i}"}})
            elif form.startswith("frame"):
                flag = add("call.direct", [a, b, argc, argc, argc], ["b64"], {"entity": {"fn": "cmp"}})
            elif form == "main":
                ta, tb = add("int.truncate", [a], [f"b{width}"]), add("int.truncate", [b], [f"b{width}"])
                flag = add("int.zero.extend", [add("int.compare", [ta, tb], ["b1"], {"attrs": [kind]})], ["b64"])
            else:
                flag = add("call.direct", [a, b], ["b64"], {"entity": {"fn": "cmp"}})
            if form == "multi":  # the false arm returned flag + 7
                flag = add("int.compare", [flag, ["b64", 1]], ["b1"], {"attrs": ["eq"]})
                flag = add("int.zero.extend", [flag], ["b64"])
            bit = add("mul.wrap", [flag, ["b64", 1 << (i * 8 + j)]], ["b64"])
            acc = bit if acc is None else add("add.wrap", [acc, bit], ["b64"])
    store = add("checked.store.bits.le", [view, ["b32", 0], acc, f"{view}.r2"], ["mem"], {"attrs": [8, 1]})
    read = add("pointer.cast", [view], ["linux.bytes_read"])
    write = add("call.foreign", [["b32", 1], read, ["b64", 8], "p1", store], ["b64", "linux.filesystem_effect", "mem"], {"entity": "linux.write"})
    unmap = add("call.foreign", [view, f"{view}.r1", f"{write}.r2"], ["b64", "mem"], {"entity": {"linux.munmap_view": ["linux.bytes_rw", 64]}})
    done = add("call.foreign", [["b32", 0], "p0"], ["linux.process_effect"], {"entity": "linux.exit_group"})
    functions.append({"name": "main", "params": fx, "returns": ["b32", *fx],
                      "blocks": [{"params": fx, "nodes": nodes, "end": ["ret", [["b32", 0], done, f"{write}.r1", f"{unmap}.r1"]]}]})
    return {"format": "xax-construct-v1", "platform": "linux-x86_64", "types": {"buf": {"view": 64}, "mem": "linux.memory_effect"},
            "functions": functions, "package": {"name": "probe", "entries": {"app": "main"}, "release": "app"}}


def want(width, kind, form, constructed):
    vals = values(width)
    word = 0
    for i, left in enumerate(vals):
        for j, right in enumerate(vals):
            flag = expected(width, kind, left, right)
            if form in ("set", "cbr"):  # the reference executor is the oracle; the arithmetic above only extends it to main
                assert execute(constructed.reader, constructed.functions["cmp"].cid, (left, right)) in (flag, (flag,), [flag]), (width, kind, form)
            word |= flag << (i * 8 + j)
    return word


def main():
    xaxc = sys.argv[1]
    widths = [int(w) for w in sys.argv[2:]] or [5, 8, 16, 24, 32]
    failures = total = 0
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        for width in widths:
            for kind in KINDS:
                for form in FORMS:
                    constructed = construct(program(width, kind, form))
                    (directory / "p.xax").write_bytes(constructed.reader.data)
                    if xaxc == "reference":  # the Python reference compiler, as a second arm
                        from xax_linux import compile_linux_executable
                        (directory / "p").write_bytes(compile_linux_executable(
                            constructed.reader, constructed.functions["main"].cid, constructed.target.cid, frontend="python").data)
                        built = subprocess.CompletedProcess((), 0)
                    else:
                        built = subprocess.run([xaxc, "build", str(directory / "p.xax"), str(directory / "p"), str(directory / "p.prov")], capture_output=True)
                    total += 1
                    if built.returncode:
                        failures += 1
                        print(f"b{width} {kind} {form}: build status {built.returncode}")
                        continue
                    (directory / "p").chmod(0o755)
                    run = subprocess.run([str(directory / "p")], capture_output=True)
                    got = int.from_bytes(run.stdout, "little") if len(run.stdout) == 8 and run.returncode == 0 else None
                    expect = want(width, kind, form, constructed)
                    if got != expect:
                        failures += 1
                        wrong = "no output" if got is None else f"{bin(got ^ expect).count('1')}/64 pairs wrong"
                        print(f"b{width} {kind} {form}: FAIL {wrong}")
    print(f"{total - failures}/{total} programs equal the reference")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
