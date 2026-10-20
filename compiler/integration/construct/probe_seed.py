"""First step of a native ``construct``: does upstream authoring reproduce the reference objects?

``xax_construct.construct`` decodes a ``xax-construct-v1`` carrier into canonical objects with
``GraphBuilder``.  A native ``construct`` has to produce the *same objects* from the same carrier,
so its authoring primitives must reach the same CIDs.  This check authors one function with
``Proc`` (the idiom the self-hosting components use) from the same semantics the carrier states,
and compares it with the function the reference produces.

Run from the repository root::

    python compiler/integration/construct/probe_seed.py [store.xax]

With a store argument the committed bytes are used as the oracle; without one the carrier is
constructed in-process by ``xax_construct``.  Both routes must yield the same CID.
"""
from __future__ import annotations

import sys
from pathlib import Path

import xax_compiler as X
from xax_platform import win32_kernel32_api
from xax_structured import Proc, B32

# The same program the seed carrier states: ``main(proc, fs) -> (b32, proc, fs)`` calls
# ExitProcess(40) and returns the constant and its effects.
CARRIER = {
    "format": "xax-construct-v1",
    "platform": "windows-x86_64",
    "functions": [{
        "name": "main",
        "params": ["proc", "fs"],
        "returns": ["b32", "proc", "fs"],
        "blocks": [{
            "params": ["proc", "fs"],
            "nodes": [["call.foreign", [["b32", 40], "p0"], ["proc"], {"entity": "win32.exit_process"}]],
            "end": ["ret", [["b32", 40], "n0", "p1"]],
        }],
    }],
    "package": {"name": "xax_mcp_seed", "entries": {"app": "main"}, "release": "app"},
}
TYPES = {"proc": "win32.process_effect", "fs": "win32.filesystem_effect"}


def reference_function():
    from xax_construct import construct

    constructed = construct({**CARRIER, "types": TYPES})
    return next(obj for obj in constructed.reader.objects() if obj.kind == X.Kind.FUNCTION)


def authored_function():
    api = win32_kernel32_api()
    proc = Proc((("proc", api.process_effect), ("fs", api.filesystem_effect)))
    code = proc.const(40, B32)
    (effect,) = proc.op(X.Operation.CALL_FOREIGN, (code, proc["proc"]), (api.process_effect,),
                        entity=api.exit_process)
    proc["proc"] = effect
    proc.ret(proc.const(40, B32), proc["proc"], proc["fs"])
    return proc.function((B32, api.process_effect, api.filesystem_effect))


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        reader = X.StoreReader(Path(argv[1]).read_bytes())
        X.verify_store(reader)
        module = next(obj for obj in reader.objects() if obj.kind == X.Kind.MODULE)
        expected = next(reader.get(cid) for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)
        source = argv[1]
    else:
        expected, source = reference_function(), "xax_construct.construct"
    built = authored_function()
    print(f"oracle   {source}: {expected.cid.hex()}")
    print(f"authored Proc       : {built.cid.hex()}")
    if built.cid != expected.cid:
        print("DIFF")
        return 1
    print("MATCH")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
