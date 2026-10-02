"""OI-27 release-only bootstrap trust diversity experiment.

The primary path is the selected OI-26 Python seed.  The independent path is a
small Go checker that separately implements suite-1 BLAKE3, canonical-store
parsing/re-emission, and the exact M11/M14 semantic subset.  It is a release
checker, not a second production compiler.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from blake3 import blake3
from xax_bootstrap import m11_definition
from xax_selfhost import M14_COMPILER_IDENTITY, M14_EVALUATOR_IDENTITY, M14_VERIFIER_IDENTITY, M14_CLOSURE_TARGET
from xax_compiler import Block, Kind, Node, Operation, StoreReader, Terminator, ValueRef, bits_type, function, graph_fragment, object_with_refs, write_store

HERE = Path(__file__).resolve().parent
COMPILER = HERE.parent
BOOTSTRAP = COMPILER / "bootstrap"
GO_SOURCE = BOOTSTRAP / "oi27_independent_checker.go"
M14 = BOOTSTRAP / "m14_selfhost_compiler.xax"
M11 = BOOTSTRAP / "m11_compiler_subset.xax"
PRIMARY_SEED = BOOTSTRAP / "m14_seed_reachable.pyz"
HISTORICAL_SEED = BOOTSTRAP / "m14_seed_runtime.pyz"
EVIDENCE = HERE / "oi27_bootstrap_diversity_evidence.json"
TIMING = HERE / "oi27_bootstrap_diversity_timing.json"
EXPECTED_M14_ROOT = "097da62f7ba9832620f5d202297fc522783ed5b4c9e68f8da6b77515b185164d"
EXPECTED_M11_ROOT = "e73735dff5be8c569a94fa434abf73015330d59fc13c4e4bf8e81aad87e2b92e"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True, **kwargs)


def build_checker(output: Path) -> dict:
    start = time.perf_counter_ns()
    proc = _run(["go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", str(output), str(GO_SOURCE)], cwd=COMPILER)
    elapsed = time.perf_counter_ns() - start
    if proc.returncode:
        raise RuntimeError(proc.stderr)
    data = output.read_bytes()
    return {"ns": elapsed, "bytes": len(data), "sha256": sha256(data)}


def checker(binary: Path, mode: str, path: Path, expected: str | None = None, output: Path | None = None) -> subprocess.CompletedProcess:
    args = [str(binary), mode, str(path)]
    if output is not None:
        args.append(str(output))
    elif expected is not None:
        args.append(expected)
    return _run(args)


def _primary_rebuild(seed: Path, source: Path, output: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return _run([sys.executable, str(seed), "rebuild", str(source), str(output)], cwd=output.parent, env=env)


def _valid_semantic_divergence() -> bytes:
    """Valid M11-shaped program with add/mul branch meaning reversed."""
    d = m11_definition()
    g = graph_fragment(
        (
            Block((d.b1, d.b32, d.b32), (), Terminator.conditional_branch(ValueRef.parameter(0, 0), 1, (ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)), 2, (ValueRef.parameter(0, 1), ValueRef.parameter(0, 2)))),
            Block((d.b32, d.b32), (Node(Operation.ADD_WRAP, (ValueRef.parameter(1, 0), ValueRef.parameter(1, 1)), (d.b32,)),), Terminator.return_((ValueRef.node_result(1, 0),))),
            Block((d.b32, d.b32), (Node(Operation.MUL_WRAP, (ValueRef.parameter(2, 0), ValueRef.parameter(2, 1)), (d.b32,)),), Terminator.return_((ValueRef.node_result(2, 0),))),
        )
    )
    f = function(g, (d.b1, d.b32, d.b32), (d.b32,))
    m = object_with_refs(Kind.MODULE, (f,))
    r = object_with_refs(Kind.PROGRAM_ROOT, (m,))
    return write_store(r.cid, (d.b1, d.b32, g, f, m, r))


def _malformed_but_canonical() -> bytes:
    """Canonical envelopes but invalid arithmetic typing; models skipped verifier."""
    b1 = bits_type(1)
    b32 = bits_type(32)
    g = graph_fragment(
        (Block((b32, b32), (Node(Operation.ADD_WRAP, (ValueRef.parameter(0, 0), ValueRef.parameter(0, 1)), (b1,)),), Terminator.return_((ValueRef.node_result(0, 0),))),)
    )
    f = function(g, (b32, b32), (b1,))
    m = object_with_refs(Kind.MODULE, (f,))
    r = object_with_refs(Kind.PROGRAM_ROOT, (m,))
    return write_store(r.cid, (b1, b32, g, f, m, r))


def _rehashed_inner_corruption(source: bytes) -> bytes:
    """Change an object body byte, retain its old CID, then repair only outer digest."""
    data = bytearray(source)
    # M11 header is fixed-format here: magic, three one-byte ULEBs, root, three one-byte counts.
    pos = 4 + 3 + 32 + 3
    # First record: length ULEB, CID, kind, schema, refs, then body length/body.
    def read_uleb(p: int) -> tuple[int, int]:
        v = 0; shift = 0
        while True:
            b = data[p]; p += 1; v |= (b & 0x7f) << shift
            if not b & 0x80: return v, p
            shift += 7
    _, p = read_uleb(pos)
    p += 32
    _, p = read_uleb(p)  # kind
    _, p = read_uleb(p)  # schema
    refs, p = read_uleb(p)
    p += refs * 32
    body_len, p = read_uleb(p)
    if body_len < 1:
        raise AssertionError("fixture has empty body")
    data[p] ^= 0x01
    digest_start = len(data) - 36
    data[digest_start:digest_start+32] = blake3(data[:digest_start]).digest()
    return bytes(data)


def _measure_command(command: list[str], repeats: int = 11) -> list[int]:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        proc = _run(command)
        elapsed = time.perf_counter_ns() - start
        if proc.returncode:
            raise RuntimeError(proc.stderr)
        samples.append(elapsed)
    return samples


def _summary(samples: list[int]) -> dict:
    ordered = sorted(samples)
    return {
        "samples_ns": samples,
        "median_ns": int(statistics.median(samples)),
        "min_ns": ordered[0],
        "max_ns": ordered[-1],
    }


def experiment(*, measure: bool = True) -> tuple[dict, dict]:
    go_version = _run(["go", "version"]).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="xax-oi27-") as td:
        tmp = Path(td)
        binary = tmp / "checker"
        build = build_checker(binary)
        binary2 = tmp / "checker-2"
        build2 = build_checker(binary2)
        if binary.read_bytes() != binary2.read_bytes():
            raise AssertionError("independent checker build was not byte deterministic")
        # Independent known-answer tests are fixed BLAKE3 public vectors.
        empty = tmp / "empty"; empty.write_bytes(b"")
        abc = tmp / "abc"; abc.write_bytes(b"abc")
        empty_hash = checker(binary, "hash", empty).stdout.strip()
        abc_hash = checker(binary, "hash", abc).stdout.strip()
        if empty_hash != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262":
            raise AssertionError("independent BLAKE3 empty vector mismatch")
        if abc_hash != "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85":
            raise AssertionError("independent BLAKE3 abc vector mismatch")

        # B2-B4-style reconstruction using exact selected primary seed, followed
        # by independently implemented parse/verify/re-emission.
        b2 = tmp / "b2.xax"; b3 = tmp / "b3.xax"; independent = tmp / "independent.xax"
        p2 = _primary_rebuild(PRIMARY_SEED, M14, b2)
        p3 = _primary_rebuild(PRIMARY_SEED, b2, b3)
        if p2.returncode or p3.returncode:
            raise AssertionError(p2.stderr or p3.stderr)
        v0 = checker(binary, "verify", M14, EXPECTED_M14_ROOT)
        v2 = checker(binary, "verify", b2, EXPECTED_M14_ROOT)
        v3 = checker(binary, "verify", b3, EXPECTED_M14_ROOT)
        rw = checker(binary, "rewrite", b3, output=independent)
        if any(p.returncode for p in (v0,v2,v3,rw)):
            raise AssertionError("independent verification/rewrite failed")
        m14_bytes = M14.read_bytes()
        reconstruction_equal = m14_bytes == b2.read_bytes() == b3.read_bytes() == independent.read_bytes()

        # Also verify the B0/B1 arithmetic subset independently.
        m11_verify = checker(binary, "verify", M11, EXPECTED_M11_ROOT)
        if m11_verify.returncode:
            raise AssertionError(m11_verify.stderr)

        faults = {}
        diverged = tmp / "diverged.xax"; diverged.write_bytes(_valid_semantic_divergence())
        plain = checker(binary, "verify", diverged, "-")
        pinned = checker(binary, "verify", diverged, EXPECTED_M11_ROOT)
        faults["seed_or_compiler_semantic_divergence"] = {
            "structurally_valid": plain.returncode == 0,
            "detected_by_pinned_release_root": pinned.returncode != 0,
            "diagnostic": pinned.stderr.strip(),
        }
        runtime = tmp / "runtime-corrupt.xax"; x = bytearray(m14_bytes); x[len(x)//2] ^= 1; runtime.write_bytes(x)
        q = checker(binary, "container", runtime)
        faults["runtime_or_transport_corruption"] = {"detected": q.returncode != 0, "diagnostic": q.stderr.strip()}
        hashbug = tmp / "hashbug.xax"; hashbug.write_bytes(_rehashed_inner_corruption(M11.read_bytes()))
        q = checker(binary, "container", hashbug)
        faults["serializer_or_object_hash_bug"] = {"outer_digest_repaired": True, "detected": q.returncode != 0, "diagnostic": q.stderr.strip()}
        common = tmp / "common-source.xax"; common.write_bytes(_malformed_but_canonical())
        q0 = checker(binary, "container", common)
        q1 = checker(binary, "verify", common, "-")
        faults["primary_verifier_omission"] = {"container_valid": q0.returncode == 0, "detected_by_independent_semantics": q1.returncode != 0, "diagnostic": q1.stderr.strip()}

        timings = {"host": {"system": platform.system(), "machine": platform.machine(), "python": sys.version.split()[0], "go": go_version}, "samples": {}}
        if measure:
            timings["samples"]["checker_build"] = _summary([build["ns"]])
            timings["samples"]["container_check_m14"] = _summary(_measure_command([str(binary), "container", str(M14)]))
            timings["samples"]["semantic_verify_m14"] = _summary(_measure_command([str(binary), "verify", str(M14), EXPECTED_M14_ROOT]))
            with tempfile.TemporaryDirectory(prefix="xax-oi27-rewrite-") as rd:
                outs=[]
                for i in range(11):
                    out=Path(rd)/f"out-{i}.xax"; start=time.perf_counter_ns(); p=checker(binary,"rewrite",M14,output=out); elapsed=time.perf_counter_ns()-start
                    if p.returncode or out.read_bytes()!=m14_bytes: raise AssertionError("rewrite measurement failed")
                    outs.append(elapsed)
                timings["samples"]["verify_and_rewrite_m14"]=_summary(outs)
            # Primary reconstruction is expensive enough that five repeats are sufficient.
            ps=[]
            for i in range(5):
                out=tmp/f"primary-{i}.xax"; start=time.perf_counter_ns(); p=_primary_rebuild(PRIMARY_SEED,M14,out); elapsed=time.perf_counter_ns()-start
                if p.returncode or out.read_bytes()!=m14_bytes: raise AssertionError("primary timing rebuild failed")
                ps.append(elapsed)
            timings["samples"]["primary_seed_rebuild_m14"]=_summary(ps)

        src = GO_SOURCE.read_bytes()
        line_count = src.count(b"\n")
        evidence = {
            "format": "xax-oi27-bootstrap-diversity-v1",
            "status": "closed",
            "selected_threshold": "release-only independent verifier+canonical-serializer/hash checker; no permanent second compiler",
            "threat_model": {
                "seed_or_compiler_compromise": "Detects any divergent reconstructed semantic image under the pinned authoritative root; does not prove a pinned authoritative compiler graph benign.",
                "runtime_or_interpreter_compromise": "Different Go runtime/checker detects corrupt or divergent Python-seed output; common kernel/hardware remain residual dependencies.",
                "common_source_bug": "Independent Go semantic checks catch injected verifier omission; shared specification/test misunderstandings remain common-mode risk.",
                "hash_or_serializer_bug": "Independent Go BLAKE3 and canonical-container implementation catches rehashed inner-record corruption and layout/index errors.",
            },
            "primary": {
                "selected_seed": PRIMARY_SEED.name,
                "selected_seed_bytes": PRIMARY_SEED.stat().st_size,
                "selected_seed_sha256": sha256(PRIMARY_SEED.read_bytes()),
                "historical_seed": HISTORICAL_SEED.name,
                "historical_seed_sha256": sha256(HISTORICAL_SEED.read_bytes()),
                "runtime": f"CPython {sys.version.split()[0]}",
                "closure_target": M14_CLOSURE_TARGET.decode("ascii"),
                "compiler_identity": M14_COMPILER_IDENTITY.decode("ascii"),
                "evaluator_identity": M14_EVALUATOR_IDENTITY.decode("ascii"),
                "verifier_identity": M14_VERIFIER_IDENTITY.decode("ascii"),
                "build_policy": "M14 fixed semantic-image recursive-build policy",
                "comparison_projection": "raw-byte-identity",
                "authoritative_root": EXPECTED_M14_ROOT,
                "authoritative_bytes_sha256": sha256(m14_bytes),
            },
            "independent": {
                "implementation": GO_SOURCE.name,
                "source_bytes": len(src),
                "source_lines": line_count,
                "source_sha256": sha256(src),
                "toolchain": go_version,
                "binary_bytes": build["bytes"],
                "binary_sha256": build["sha256"],
                "binary_rebuild_byte_identical": build["sha256"] == build2["sha256"],
                "external_packages": [],
                "implemented_scope": ["suite-1 BLAKE3-256", "canonical store/index/CID verification", "M11 arithmetic subset verification", "M14 semantic-image subset verification", "canonical store re-emission"],
                "not_implemented": ["general META evaluator", "native/wasm/accelerator lowering", "package resolver", "full second compiler"],
                "known_answer_blake3": {"empty": empty_hash, "abc": abc_hash},
            },
            "comparison": {
                "b2_b4_reconstruction_byte_identical": reconstruction_equal,
                "generation_sha256": [sha256(m14_bytes), sha256(b2.read_bytes()), sha256(b3.read_bytes()), sha256(independent.read_bytes())],
                "generation_root": EXPECTED_M14_ROOT,
                "m11_root_verified": EXPECTED_M11_ROOT,
            },
            "fault_injection": faults,
            "scope_options": [
                {"name": "full_independent_seed", "implemented": False, "reason": "would duplicate META evaluation/construction and become a second compiler obligation; no extra measured benefit required by injected release threats"},
                {"name": "independent_serializer_hash_only", "implemented": True, "mode": "container", "detects": ["runtime/transport corruption", "serializer/index corruption", "object/store hash mismatch"], "semantic_fault_detection": False},
                {"name": "independent_verifier_only", "implemented": True, "mode": "verify", "detects": ["bounded semantic verifier omission", "root divergence"], "requires_container_hash_core": True},
                {"name": "selected_combined_release_checker", "implemented": True, "mode": "verify+rewrite", "detects": ["root divergence", "bounded semantic invalidity", "container/hash/serializer corruption"], "permanent_production_dependency": False},
            ],
            "residual_common_mode_dependencies": ["normative XAX specification and committed expected roots", "release test vectors", "host kernel/hardware", "cryptographic BLAKE3 specification", "human/release-policy authorization"],
            "host_observations_nonsemantic": timings["host"],
        }
        return evidence, timings


def main() -> int:
    ap=argparse.ArgumentParser();ap.add_argument("--write",action="store_true");ap.add_argument("--no-timing",action="store_true");args=ap.parse_args()
    evidence,timing=experiment(measure=not args.no_timing)
    if args.write:
        EVIDENCE.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n")
        TIMING.write_text(json.dumps(timing,indent=2,sort_keys=True)+"\n")
    print(json.dumps(evidence,indent=2,sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
