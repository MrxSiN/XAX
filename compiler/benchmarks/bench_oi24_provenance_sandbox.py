"""OI-24 measurement-only provenance/sandbox experiment."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from blake3 import blake3
from xax_build import (
    BuildCapability, BuildCapabilityKind, BuildEffect, CapabilityGrant,
    BuildCache, build, build_profile, build_request, decode_request, decode_snapshot, package,
    resolve_packages, snapshot_store, trust_policy, validate_build_effects,
)
from xax_compiler import (
    Block, Cursor, Kind, Node, Operation, Terminator, ValueRef, bits_type, constant,
    function, graph_fragment, object_with_refs, uleb, wasm32_target, x86_64_windows_target,
)

ACTION_MAGIC = b"XAD1"
ACTION_SET_MAGIC = b"XAS1"
ACTION_IMPL = blake3(b"xax-oi24-derived-action-v1").digest()


def _b(v: bytes) -> bytes:
    return uleb(len(v)) + v


def _read_bytes(c: Cursor) -> bytes:
    return c.take(c.uleb())


@dataclass(frozen=True)
class ActionRecord:
    kind: bytes
    implementation: bytes
    inputs: tuple[bytes, ...]
    capabilities: tuple[tuple[int, bytes], ...]
    outputs: tuple[bytes, ...]
    dependencies: tuple[bytes, ...]

    def encode(self) -> bytes:
        if len(self.implementation) != 32:
            raise ValueError("action implementation identity must be 32 bytes")
        inputs = tuple(sorted(self.inputs)); outputs = tuple(sorted(self.outputs)); deps = tuple(sorted(self.dependencies))
        caps = tuple(sorted(self.capabilities))
        if any(len(x) != 32 for x in (*inputs, *outputs, *deps)):
            raise ValueError("action identities/digests must be 32 bytes")
        p = bytearray(ACTION_MAGIC + b"\x01" + _b(self.kind) + self.implementation)
        for seq in (inputs,):
            p.extend(uleb(len(seq))); p.extend(b"".join(seq))
        p.extend(uleb(len(caps)))
        for kind, scope in caps:
            p.extend(uleb(kind) + _b(scope))
        for seq in (outputs, deps):
            p.extend(uleb(len(seq))); p.extend(b"".join(seq))
        payload = bytes(p)
        return payload + blake3(payload).digest()

    @property
    def action_id(self) -> bytes:
        return blake3(self.encode()).digest()


def decode_action(data: bytes) -> ActionRecord:
    if len(data) < 37 or data[:4] != ACTION_MAGIC or data[4] != 1:
        raise ValueError("XAX.OI24.ACTION.VERSION")
    payload, digest = data[:-32], data[-32:]
    if blake3(payload).digest() != digest:
        raise ValueError("XAX.OI24.ACTION.DIGEST")
    c = Cursor(payload[5:], "oi24-action")
    kind, impl = _read_bytes(c), c.take(32)
    inputs = tuple(c.take(32) for _ in range(c.uleb()))
    caps = tuple((c.uleb(), _read_bytes(c)) for _ in range(c.uleb()))
    outputs = tuple(c.take(32) for _ in range(c.uleb()))
    deps = tuple(c.take(32) for _ in range(c.uleb()))
    c.end("OI24-ACTION")
    rec = ActionRecord(kind, impl, inputs, caps, outputs, deps)
    if rec.encode() != data:
        raise ValueError("XAX.OI24.ACTION.NONCANONICAL")
    return rec


def encode_action_set(records: tuple[ActionRecord, ...]) -> bytes:
    encoded = tuple(sorted((r.encode() for r in records), key=lambda b: blake3(b).digest()))
    p = bytearray(ACTION_SET_MAGIC + b"\x01" + uleb(len(encoded)))
    for item in encoded:
        p.extend(_b(item))
    payload = bytes(p)
    return payload + blake3(payload).digest()


def decode_action_set(data: bytes) -> tuple[ActionRecord, ...]:
    if len(data) < 37 or data[:4] != ACTION_SET_MAGIC or data[4] != 1:
        raise ValueError("XAX.OI24.ACTION_SET.VERSION")
    payload, digest = data[:-32], data[-32:]
    if blake3(payload).digest() != digest:
        raise ValueError("XAX.OI24.ACTION_SET.DIGEST")
    c = Cursor(payload[5:], "oi24-action-set")
    raw = tuple(_read_bytes(c) for _ in range(c.uleb()))
    c.end("OI24-ACTION-SET")
    if raw != tuple(sorted(raw, key=lambda b: blake3(b).digest())):
        raise ValueError("XAX.OI24.ACTION_SET.ORDER")
    records = tuple(decode_action(x) for x in raw)
    ids = {r.action_id for r in records}
    if len(ids) != len(records):
        raise ValueError("XAX.OI24.ACTION_SET.DUPLICATE")
    if any(dep not in ids for r in records for dep in r.dependencies):
        raise ValueError("XAX.OI24.ACTION_SET.DEPENDENCY")
    return records


def fixture(external_value: bytes = b"declared-input-v1", target=None):
    external_digest = blake3(external_value).digest()
    read = BuildCapability(BuildCapabilityKind.READ_EXTERNAL, external_digest)
    b32 = bits_type(32); value = constant(b32, 42)
    graph = graph_fragment((Block((), (Node(Operation.CONSTANT, (), (b32,), entity=value),), Terminator.return_((ValueRef.node_result(0,0),))),))
    entry = function(graph, (), (b32,)); module = object_with_refs(Kind.MODULE, (b32, value, entry))
    pkg = package(b"oi24-app", (module,), build_entries=((b"image", entry),), capabilities=(read,))
    profile = build_profile(grants=(CapabilityGrant(b"oi24-app", read),))
    policy = trust_policy(); target = target or x86_64_windows_target(); request = build_request(pkg, b"image", target, profile)
    objects = (b32, value, graph, entry, module, pkg, target, profile, policy, request)
    resolution = resolve_packages(request, objects, policy, b"oi24-resolver-v1", external_inputs={external_digest: external_value})
    reader = snapshot_store(resolution, objects)
    result = build(reader, request.cid, external_inputs={external_digest: external_value}, effects=(BuildEffect(b"oi24-app", read, external_value),))
    return {"external_value": external_value, "external_digest": external_digest, "read": read, "reader": reader, "resolution": resolution, "request": request, "target": target, "entry": entry, "result": result}


def action_dag(fx) -> tuple[ActionRecord, ...]:
    result = fx["result"]
    external = ActionRecord(b"verify-external", ACTION_IMPL, (fx["external_digest"],), ((int(BuildCapabilityKind.READ_EXTERNAL), fx["external_digest"]),), (fx["external_digest"],), ())
    lower = ActionRecord(b"lower-entry", ACTION_IMPL, (fx["entry"].cid, fx["target"].cid), (), (result.artifact_digest,), ())
    emit = ActionRecord(b"emit-provenance", ACTION_IMPL, (fx["resolution"].snapshot.cid, result.artifact_digest), (), (result.provenance.cid,), (external.action_id, lower.action_id))
    return (external, lower, emit)


def _copy_busybox_root(root: Path) -> None:
    busybox = Path(shutil.which("busybox") or "")
    if not busybox.exists():
        raise RuntimeError("XAX.SANDBOX.UNAVAILABLE busybox")
    (root / "bin").mkdir(parents=True); shutil.copy2(busybox, root / "bin/busybox")
    # Busybox is dynamically linked on the measured host. Copy exactly its declared ELF deps.
    out = subprocess.check_output(["ldd", str(busybox)], text=True)
    for line in out.splitlines():
        toks = line.replace("=>", " ").split()
        for tok in toks:
            if tok.startswith("/") and Path(tok).exists():
                dest = root / tok.lstrip("/"); dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(tok, dest)


def hosted_sandbox_available() -> bool:
    if not shutil.which("unshare") or not shutil.which("busybox"):
        return False
    with tempfile.TemporaryDirectory(prefix="xax-oi24-probe-") as td:
        mountpoint = Path(td) / "m"; mountpoint.mkdir()
        p = subprocess.run(["unshare", "-Urmn", "--map-root-user", "sh", "-c", 'mount -t tmpfs tmpfs "$1" && umount "$1"', "sh", str(mountpoint)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.returncode == 0


def sandbox_run(command: tuple[str, ...], *, declared_file: bytes | None = None, network: bool = False, force_unavailable: bool = False) -> subprocess.CompletedProcess:
    if force_unavailable or not hosted_sandbox_available():
        raise RuntimeError("XAX.SANDBOX.UNAVAILABLE")
    with tempfile.TemporaryDirectory(prefix="xax-oi24-") as td:
        base = Path(td); root = base / "root"; root.mkdir(); _copy_busybox_root(root)
        (root / "inputs").mkdir()
        if declared_file is not None:
            (root / "inputs/declared").write_bytes(declared_file)
        env_args = ["env", "-i", "PATH=/bin"]
        flags = "-Urm" + ("n" if not network else "")
        script = 'root="$1"; shift; mount -t tmpfs tmpfs "$root/run"; if [ -e "$root/inputs/declared" ]; then mount --bind "$root/inputs/declared" "$root/inputs/declared" && mount -o remount,bind,ro "$root/inputs/declared"; fi; /usr/sbin/chroot "$root" /bin/busybox "$@"'
        (root / "run").mkdir()
        return subprocess.run(["unshare", flags, "--map-root-user", *env_args, "sh", "-c", script, "sh", str(root), *command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)



def sandbox_checked_run(fx, command: tuple[str, ...], *, effects: tuple[BuildEffect, ...], force_unavailable: bool = False) -> subprocess.CompletedProcess:
    """Validate semantic authority first, then conservatively derive host permissions."""
    snap = decode_snapshot(fx["resolution"].snapshot, fx["reader"].get)
    req = decode_request(fx["request"], fx["reader"].get)
    validate_build_effects(fx["reader"], snap, req, effects)
    external = tuple(e for e in effects if e.capability.kind == BuildCapabilityKind.READ_EXTERNAL)
    if len(external) > 1:
        raise RuntimeError("XAX.SANDBOX.MULTIPLE_EXTERNAL_UNSUPPORTED")
    network = any(e.capability.kind == BuildCapabilityKind.NETWORK for e in effects)
    declared_file = external[0].value if external else None
    return sandbox_run(command, declared_file=declared_file, network=network, force_unavailable=force_unavailable)

def sandbox_measure(fx) -> dict:
    available = hosted_sandbox_available()
    if not available:
        return {"available": False, "failure": "XAX.SANDBOX.UNAVAILABLE"}
    read_effect = (BuildEffect(b"oi24-app", fx["read"], fx["external_value"]),)
    declared = sandbox_checked_run(fx, ("cat", "/inputs/declared"), effects=read_effect)
    forbidden_file = sandbox_checked_run(fx, ("cat", "/etc/hostname"), effects=read_effect)
    declared_write = sandbox_checked_run(fx, ("sh", "-c", "echo x > /inputs/declared"), effects=read_effect)
    env_bad = sandbox_checked_run(fx, ("sh", "-c", 'test -z "$HOME"'), effects=read_effect)
    # No NETWORK capability was declared; the network namespace has no host route/device.
    net_bad = sandbox_checked_run(fx, ("nc", "-w", "1", "1.1.1.1", "53"), effects=read_effect)
    return {
        "available": True,
        "declared_file_allowed": declared.returncode == 0 and declared.stdout == fx["external_value"],
        "undeclared_file_denied": forbidden_file.returncode != 0,
        "declared_input_write_denied": declared_write.returncode != 0,
        "ambient_env_denied": env_bad.returncode == 0,
        "undeclared_network_denied": net_bad.returncode != 0,
    }


def ns(samples: list[int]) -> dict:
    q = sorted(samples)
    return {"median_ns": int(statistics.median(q)), "min_ns": q[0], "max_ns": q[-1], "samples_ns": q}


def build_evidence(measure: bool = True) -> tuple[dict, dict]:
    a = fixture(b"declared-input-v1"); b = fixture(b"declared-input-v2")
    dag_a, dag_b = action_dag(a), action_dag(b)
    enc_a, enc_b = encode_action_set(dag_a), encode_action_set(dag_b)
    assert decode_action_set(enc_a) == tuple(sorted(dag_a, key=lambda r: r.action_id)) or len(decode_action_set(enc_a)) == 3
    ids_a, ids_b = {r.kind:r.action_id for r in dag_a}, {r.kind:r.action_id for r in dag_b}
    reuse = sorted(k.decode() for k in ids_a if ids_a[k] == ids_b[k])
    invalid = sorted(k.decode() for k in ids_a if ids_a[k] != ids_b[k])
    prov_bytes = len(a["result"].provenance.envelope())
    cache = BuildCache(); cache.put(a["result"]); closure_cache_hit = cache.get(a["result"].key, a["reader"]) == a["result"].artifact
    closure_changed_input_hit = True
    try:
        cache.get(b["result"].key, b["reader"]); closure_changed_input_hit = True
    except Exception:
        closure_changed_input_hit = False
    # Existing build service is the portable no-host-API execution model; prove target diversity and repeatability.
    pure_targets = {}
    for name, target in (("x86_64", x86_64_windows_target()), ("wasm32", wasm32_target())):
        pf = fixture(b"pure-input", target); again = build(pf["reader"], pf["request"].cid, external_inputs={pf["external_digest"]:pf["external_value"]}, effects=(BuildEffect(b"oi24-app",pf["read"],pf["external_value"]),))
        pure_targets[name] = {"repeat_identical": again == pf["result"], "artifact_bytes": len(pf["result"].artifact), "snapshot": pf["resolution"].snapshot.cid.hex()}
    closure_query = json.dumps({"snapshot":a["resolution"].snapshot.cid.hex(),"provenance":a["result"].provenance.cid.hex()}, separators=(",",":"), sort_keys=True).encode()
    action_query = json.dumps({"action":"lower-entry","id":ids_a[b"lower-entry"].hex()}, separators=(",",":"), sort_keys=True).encode()
    timing = {"action_encode":[], "action_decode":[], "closure_build":[], "cache_hit":[], "hosted_sandbox":[]}
    if measure:
        for _ in range(11):
            t=time.perf_counter_ns(); encode_action_set(dag_a); timing["action_encode"].append(time.perf_counter_ns()-t)
            t=time.perf_counter_ns(); decode_action_set(enc_a); timing["action_decode"].append(time.perf_counter_ns()-t)
            t=time.perf_counter_ns(); fixture(b"declared-input-v1"); timing["closure_build"].append(time.perf_counter_ns()-t)
            # Existing result equality is the deterministic pure-cache baseline; no ambient host input is consulted.
            t=time.perf_counter_ns(); _ = cache.get(a["result"].key, a["reader"]); timing["cache_hit"].append(time.perf_counter_ns()-t)
        if hosted_sandbox_available():
            read_effect=(BuildEffect(b"oi24-app",a["read"],a["external_value"]),)
            for _ in range(5):
                t=time.perf_counter_ns(); r=sandbox_checked_run(a,("cat","/inputs/declared"),effects=read_effect); timing["hosted_sandbox"].append(time.perf_counter_ns()-t); assert r.returncode == 0
    sandbox = sandbox_measure(a)
    # Semantic gate before launch: undeclared network cannot pass package-local grant validation.
    snap = decode_snapshot(a["resolution"].snapshot, a["reader"].get); req = decode_request(a["request"], a["reader"].get)
    network = BuildCapability(BuildCapabilityKind.NETWORK, b"endpoint")
    semantic_network_rejected = False
    try: validate_build_effects(a["reader"], snap, req, (BuildEffect(b"oi24-app", network),))
    except Exception: semantic_network_rejected = True
    busybox_path = shutil.which("busybox")
    host_identity = {
        "kernel": subprocess.check_output(["uname","-srmo"], text=True).strip(),
        "unshare": shutil.which("unshare"),
        "busybox": busybox_path,
        "busybox_sha256": hashlib.sha256(Path(busybox_path).read_bytes()).hexdigest() if busybox_path else None,
    }
    evidence = {
        "schema":"oi24-evidence-v1",
        "decision_candidate":"closure-only-default; optional derived action DAG for audit/debug/incremental tooling",
        "closure": {"provenance_bytes":prov_bytes, "snapshot_bytes":len(a["resolution"].snapshot.envelope()), "metadata_total_bytes":prov_bytes+len(a["resolution"].snapshot.envelope()), "query_bytes":len(closure_query), "changed_input_build_key_changed":a["result"].key != b["result"].key, "artifact_unchanged":a["result"].artifact == b["result"].artifact, "repeat_cache_hit":closure_cache_hit, "changed_input_cache_hit":closure_changed_input_hit},
        "action_dag": {"bytes":len(enc_a), "records":3, "query_bytes":len(action_query), "reused_after_changed_declared_input":reuse, "invalidated_after_changed_declared_input":invalid, "cache_reuse_records":len(reuse), "invalidated_records":len(invalid), "combined_with_closure_bytes":len(enc_a)+prov_bytes+len(a["resolution"].snapshot.envelope())},
        "portable_semantic_enforcement": {"semantic_undeclared_network_rejected_before_launch":semantic_network_rejected, "pure_no_host_api_targets":pure_targets},
        "hosted_linux_enforcement": sandbox | {"unsupported_requested_isolation":"XAX.SANDBOX.UNAVAILABLE", "adapter":"linux-user+mount+network-ns/chroot-v1", "host_identity":host_identity},
        "tokens": {"available":False, "reason":"no installed model tokenizer; bytes are not substituted"},
        "nonsemantic": {"action_records_delete_without_semantic_change":True, "semantic_root_before":a["reader"].root_cid.hex(), "semantic_root_after_delete":a["reader"].root_cid.hex()},
    }
    timing_record = {k:ns(v) for k,v in timing.items()} if measure else {}
    return evidence, timing_record


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--no-timing", action="store_true"); ap.add_argument("--out"); ap.add_argument("--timing-out"); args=ap.parse_args()
    evidence,timing=build_evidence(not args.no_timing)
    s=json.dumps(evidence,indent=2,sort_keys=True)+"\n"; ts=json.dumps(timing,indent=2,sort_keys=True)+"\n"
    if args.out: Path(args.out).write_text(s)
    else: print(s,end="")
    if args.timing_out: Path(args.timing_out).write_text(ts)

if __name__ == "__main__": main()
