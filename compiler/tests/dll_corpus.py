"""S15e.3b (ADR-320): random Windows PE32+ DLL build requests for the differential tests of the XAX general program.

``dll_case(rng)`` gives a snapshot store: a ``xax-construct-v1`` DLL (exports, forwards, and maybe a DllMain whose calls
are allowed, a foreign import outside the loader-lock allowlist, or whose signature is wrong), then sometimes rebuilt
with malformed or extra package members (an export name the decoder rejects, a forward target that is no
``module.Symbol``, a DllMain carrier of the wrong length, two DllMains, a forward named like an export, an export of a
non-function, a package identity with a NUL byte, the members split over two modules, the entry not exported).
"""

from __future__ import annotations

import copy
import random

import xax_compiler as X
from xax_build import ArtifactKind, build_request, package, resolve_packages, snapshot_store
from xax_compiler import (WINDOWS_DLLMAIN_PREFIX, WINDOWS_EXPORT_PREFIX, WINDOWS_FORWARD_PREFIX, Kind, object_with_refs, target, uleb)
from xax_construct import construct

MEM = "win32.memory_effect"
NAMES = ("Add", "Answer", "Mul", "Zeta", "alpha", "Add2", "_x", "Q")
FORWARDS = ("kernelbase.GetTickCount64", "kernel32.Sleep", "ntdll.RtlZeroMemory", "api-ms-win-core-synch-l1-2-0.WakeByAddressAll")


def _base(rng: random.Random) -> dict:
    functions = []
    count = rng.randrange(2, 6)
    for index in range(count):
        kind = rng.choice(("add", "mul", "const", "call")) if index else "add"
        name = f"f{index}"
        if kind == "const":
            functions.append({"name": name, "params": [], "returns": ["b32"],
                              "blocks": [{"params": [], "nodes": [], "end": ["ret", [["b32", rng.randrange(100)]]]}]})
        elif kind == "call":
            callee = rng.choice([f["name"] for f in functions if f["params"] == ["b64", "b64"]])
            functions.append({"name": name, "params": ["b64", "b64"], "returns": ["b64"], "blocks": [{"params": ["b64", "b64"], "nodes": [
                ["call.direct", ["p0", "p1"], ["b64"], {"entity": {"fn": callee}}],
                ["call.direct", ["n0", "p1"], ["b64"], {"entity": {"fn": callee}}]], "end": ["ret", ["n1"]]}]})
        else:
            operation = "add.wrap" if kind == "add" else "mul.wrap"
            functions.append({"name": name, "params": ["b64", "b64"], "returns": ["b64"], "blocks": [{"params": ["b64", "b64"], "nodes": [
                [operation, ["p0", "p1"], ["b64"]], [operation, ["n0", ["b64", rng.randrange(1, 1000)]], ["b64"]]], "end": ["ret", ["n1"]]}]})
    names = rng.sample(NAMES, rng.randrange(1, min(len(NAMES), count) + 1))
    exported = rng.sample([f["name"] for f in functions], len(names)) if len(names) <= count else [f["name"] for f in functions]
    exports = dict(zip(names, exported))
    release = rng.choice(list(exports.values()))
    request = {"format": "xax-construct-v1", "platform": "windows-x86_64", "types": {}, "functions": functions,
               "package": {"name": rng.choice(("xaxdll", "lib", "a-b_c")), "entries": {"lib": release}, "release": "lib", "exports": exports}}
    if rng.random() < 0.5:
        request["package"]["forwards"] = {name: rng.choice(FORWARDS) for name in rng.sample(("Ticks", "Nap", "Zero", "Wake"), rng.randrange(1, 3))}
    if rng.random() < 0.6:
        choice = rng.choice(("plain", "plain", "user32", "allowed", "signature", "calls"))
        params = ["b64", "b32", "b64", MEM] if choice != "signature" else ["b64", "b64", "b64", MEM]
        nodes = [["int.compare", ["p1", [params[1], 1]], ["b1"], {"attrs": ["eq"]}]]
        effect = "p3"
        if choice in ("user32", "allowed"):
            library, symbol = ("user32.dll", "GetForegroundWindow") if choice == "user32" else (rng.choice(("kernel32.dll", "KERNEL32.DLL")), "DisableThreadLibraryCalls")
            nodes.append(["call.foreign", [["b64", 0], "p3"], ["b32", MEM], {"entity": {"win32.import": [library, symbol, ["b64", MEM], ["b32", MEM]]}}])
            effect = "n1.r1"
        if choice == "calls":
            callee = next(f["name"] for f in functions if f["params"] == ["b64", "b64"])
            nodes.append(["call.direct", ["p0", "p2"], ["b64"], {"entity": {"fn": callee}}])
        request["functions"].append({"name": "main", "params": params, "returns": ["b32", MEM], "blocks": [
            {"params": params, "nodes": nodes, "end": ["cbr", "n0", 1, [effect], 2, [effect]]},
            {"params": [MEM], "nodes": [], "end": ["ret", [["b32", 1], "p0"]]},
            {"params": [MEM], "nodes": [], "end": ["ret", [["b32", 0], "p0"]]}]})
        request["package"]["dll_main"] = "main"
    return request


def _rebuilt(constructed, members, identity: bytes | None = None, split: bool = False, entry: bytes = b"lib"):
    """The constructed snapshot with the package's members replaced (``members``: functions and carriers)."""
    reader = constructed.reader
    old = {constructed.package.cid, constructed.release_request.cid, reader.root_cid}
    old |= {item.cid for item in reader.objects() if item.kind == Kind.MODULE}
    carriers = (WINDOWS_EXPORT_PREFIX, WINDOWS_FORWARD_PREFIX, WINDOWS_DLLMAIN_PREFIX)
    kept = [item for item in reader.objects() if item.cid not in old
            and not (item.kind == Kind.TARGET and not item.references and any(X.Cursor(item.body, "").byte_string().startswith(p) for p in carriers))]
    if split and len(members) > 1:
        cut = len(members) // 2
        modules = (object_with_refs(Kind.MODULE, members[:cut]), object_with_refs(Kind.MODULE, members[cut:]))
    else:
        modules = (object_with_refs(Kind.MODULE, members),)
    app = package(identity or b"xaxdll", modules, build_entries=((b"lib", constructed.functions[constructed_release(constructed)]),))
    request = build_request(app, entry, constructed.target, constructed.profile, requested_artifacts=(ArtifactKind.WINDOWS_DLL,))
    everything = (*kept, *(item for item in members if item.kind == Kind.TARGET), *modules, app, request)
    return snapshot_store(resolve_packages(request, everything, constructed.policy, b"xax-construct-v1"), everything)


def constructed_release(constructed) -> str:
    """The name of the constructed function the package's ``lib`` entry names."""
    entry = dict(_entries(constructed.package))[b"lib"]
    return next(name for name, function in constructed.functions.items() if function.cid == entry)


def _entries(package_object):
    """``decode_package``'s build entries (name, CID), read from the body."""
    cursor = X.Cursor(package_object.body, "")
    cursor.byte_string()
    references = package_object.references
    for _ in range(cursor.uleb()):
        cursor.uleb()
    for _ in range(cursor.uleb()):
        if cursor.uleb() == 1:
            cursor.uleb()
        else:
            cursor.byte_string()
    entries = []
    for _ in range(cursor.uleb()):
        name = cursor.byte_string()
        entries.append((name, references[cursor.uleb()]))
    return entries


def dll_case(rng: random.Random):
    """A snapshot store (``StoreReader``) and a short description."""
    request = _base(rng)
    constructed = construct(copy.deepcopy(request))
    if rng.random() < 0.45:
        return constructed.reader, "constructed"
    functions = list(constructed.functions.values())
    exports = [X.windows_export_symbol(constructed.functions[function], name.encode()) for name, function in sorted(request["package"]["exports"].items())]
    forwards = [X.windows_forward_symbol(name.encode(), value.encode()) for name, value in sorted(request["package"].get("forwards", {}).items())]
    mains = [X.windows_dllmain_symbol(constructed.functions["main"])] if "dll_main" in request["package"] else []
    some = rng.choice(functions)
    mutation = rng.choice(("export_nul", "export_empty", "export_high", "forward_bad", "forward_nodot", "main_short", "two_mains",
                           "forward_same", "export_type", "identity_nul", "split", "not_exported", "order", "export_long"))
    identity = None
    if mutation == "export_nul":
        exports.append(target(WINDOWS_EXPORT_PREFIX + uleb(3) + b"a\0b" + some.cid))
    elif mutation == "export_empty":
        exports.append(target(WINDOWS_EXPORT_PREFIX + uleb(0) + some.cid))
    elif mutation == "export_high":
        exports.append(target(WINDOWS_EXPORT_PREFIX + uleb(2) + b"\xc3\xa9" + some.cid))
    elif mutation == "export_long":
        exports.append(target(WINDOWS_EXPORT_PREFIX + uleb(1) + b"Z" + some.cid + b"!"))
    elif mutation == "forward_bad":
        forwards.append(target(WINDOWS_FORWARD_PREFIX + uleb(2) + b"Fx" + uleb(9) + b"C:/x.dll."))
    elif mutation == "forward_nodot":
        forwards.append(target(WINDOWS_FORWARD_PREFIX + uleb(2) + b"Fy" + uleb(7) + b"kernel3"))
    elif mutation == "main_short":
        mains.append(target(WINDOWS_DLLMAIN_PREFIX + some.cid[:31]))
    elif mutation == "two_mains":
        mains += [X.windows_dllmain_symbol(item) for item in rng.sample(functions, 2)]
    elif mutation == "forward_same":
        name = rng.choice(sorted(request["package"]["exports"]))
        forwards.append(X.windows_forward_symbol(name.encode(), b"kernel32.Sleep"))
    elif mutation == "export_type":
        exports.append(target(WINDOWS_EXPORT_PREFIX + uleb(5) + b"AType" + X.bits_type(64).cid))
    elif mutation == "identity_nul":
        identity = b"bad\0name"
    elif mutation == "not_exported":
        release = constructed.functions[constructed_release(constructed)]
        exports = [item for item in exports if X.decode_windows_export(item).function_cid != release.cid]
    members = [*functions, *exports, *forwards, *mains]
    if mutation == "order":
        rng.shuffle(members)
    try:
        reader = _rebuilt(constructed, members, identity=identity, split=mutation == "split" or rng.random() < 0.2)
    except (ValueError, X.XaxError):
        return constructed.reader, "constructed"
    return reader, mutation
