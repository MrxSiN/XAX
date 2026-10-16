"""S14b (ADR-285): full-compiler generations of the Linux x86-64 production compiler, and their evidence.

The production compiler on Linux x86-64 is the general driver (``xax_compiler_driver_general.xax``).  Its canonical
build request (``xax_selfhost_compiler.compiler_request``) is resolved and built by the compiler itself:

    C0 (seed: the driver lowered by the XAX views backend in a Python host process)
    C_n resolve <request store> -> snapshot store;  C_n build <snapshot> -> C_n+1, provenance P_n+1     (n = 0, 1, 2)

Every step is a process with no Python inside.  Recorded, raw: every executable's and snapshot's digest and size,
which executable produced which, the provenance envelopes, the bootstrap references (the Python resolver's snapshot,
the bootstrap's own compile of the compiler), a positive and negative corpus run by every generation (C0 to C3, with
the bootstrap's outcome where one is defined), a run of C1 with an empty environment, timings and peak RSS.  B levels
are not written here: ``xax_selfhost.bootstrap_status`` derives them from this record.  Runs with
``XAX_REQUIRE_NATIVE=1``.  Run: ``PYTHONPATH=src:tests:.:.. python benchmarks/bench_full_selfhost.py [--write]``.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BOOTSTRAP = HERE.parent / "bootstrap"
EVIDENCE = HERE / "full_selfhost_evidence.json"
sys.path.insert(0, str(HERE.parent / "tests"))
sys.path.insert(0, str(HERE.parent))

STATUS = {0: "image", 1: "rejected", 2: "declined", 3: "failed"}
BOOTSTRAP_DIAGNOSTICS: dict[str, list] = {}  # verify cases: the bootstrap's diagnostic key (``_diagnostic_key``)


def sha(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


def run(executable: Path, arguments: list, outputs: list[Path], environment=None) -> dict:
    """One process: its status, the digests of its outputs, wall time, and peak RSS."""
    for path in outputs:
        if path.exists():
            path.unlink()
    start = time.perf_counter()
    process = subprocess.Popen([str(executable), *(str(item) for item in arguments)], env=environment)
    _pid, status, usage = os.wait4(process.pid, 0)
    seconds = time.perf_counter() - start
    code = os.waitstatus_to_exitcode(status)
    produced = [path.read_bytes() if path.exists() else None for path in outputs]
    return {"status": STATUS.get(code, f"signal {-code}" if code < 0 else f"exit {code}"), "outputs": [sha(item) for item in produced],
            "host_s_nonsemantic": round(seconds, 2), "peak_rss_kib_nonsemantic": usage.ru_maxrss, "_data": produced}


def _outcome(result: dict) -> list:
    return [result["status"], *result["outputs"]]


def corpus(directory: Path):
    """``(name, command, input files {name: bytes}, outputs, reference outcome or None)``: positive and negative."""
    import xax_compiler as X
    from test_xax_linux import _crc_program, _status_program
    from test_xax_selfhost_general import B32, _call, _function, _process, _store
    from test_xax_selfhost_general_build import _expected as build_expected, _parts, _program
    from test_xax_selfhost_general_resolve import _library, _request, expected as resolve_expected
    from blake3 import blake3
    from test_xax_build import fake_signature
    from xax_build import ArtifactKind, DependencyRequirement, package, trust_policy
    from xax_linux import compile_linux_executable
    from xax_selfhost_driver import target_package
    from benchmarks.jsonmin import build_jsonmin
    from benchmarks.linux_chains import build_chains_program

    cases = []

    def root_entry(reader):
        module = next(item for item in reader.objects() if item.kind == X.Kind.MODULE)
        return next(cid for cid in module.references if reader.get(cid).kind == X.Kind.FUNCTION)

    def lower(name, reader, entry_cid, target, kind):
        try:
            reference = ["image", sha(compile_linux_executable(reader, entry_cid, target.cid).data)]
        except X.XaxError as error:
            reference = ["rejected", error.diagnostic.code, error.diagnostic.rule]
        cases.append((name, kind, "lower", {"store": reader.data, "target": target_package(target)}, ["out"], reference))

    status, status_entry, linux, _ = _status_program(lambda b: b.const(X.bits_type(32), 7))
    lower("lower status", status, status_entry.cid, linux, "positive")
    crc, crc_entry, dynamic = _crc_program(X.x86_64_linux_dynamic_exec_target())
    lower("lower crc (dynamic)", crc, crc_entry.cid, dynamic, "positive")
    jsonmin = build_jsonmin()
    lower("lower jsonmin", jsonmin.reader, root_entry(jsonmin.reader), jsonmin.target, "positive")
    chains = build_chains_program(links="index")
    lower("lower chains", chains.reader, root_entry(chains.reader), chains.target, "positive")
    static_crc, static_entry, static = _crc_program(X.x86_64_linux_exec_target())
    lower("lower C import, static profile", static_crc, static_entry.cid, static, "negative")
    pair, items = _function((B32,), (B32, B32), lambda g, b: b.ret(b.params[0], b.params[0]))
    arity, arity_entry = _store(_process([_call(pair, (B32,), (B32, B32))]), linux, *items)
    lower("lower ABI arity", arity, arity_entry.cid, linux, "negative")
    contract, contract_entry = _store(_function((B32,), (B32,), lambda g, b: b.ret(b.params[0])), linux, X.bits_type(64))
    lower("lower process entry contract", contract, contract_entry.cid, linux, "negative")
    views = (BOOTSTRAP / "xax_blake3_compress.xax").read_bytes()
    cases.append(("lower a views program", "positive", "lower", {"store": views, "target": target_package(X.x86_64_views_target())}, ["out"], None))

    for path in sorted(BOOTSTRAP.glob("*.xax")):
        data = path.read_bytes()
        try:
            X.verify_store(X.StoreReader(data))
            reference = ["image", sha(b"")]
        except (X.XaxError, ValueError):
            reference = None
        cases.append((f"verify {path.name}", "positive", "verify", {"store": data}, ["out"], reference))
        if len(data) <= 4 << 20:
            cases.append((f"inspect {path.name}", "positive", "inspect", {"store": data}, ["out"], None))
    for offset in range(0, len(status.data), max(1, len(status.data) // 24)):
        mutated = status.data[:offset] + bytes(((status.data[offset] + 1) & 0xFF,)) + status.data[offset + 1:]
        try:
            X.verify_store(X.StoreReader(mutated))
            continue
        except (X.XaxError, ValueError):
            pass
        cases.append((f"verify mutated status store @{offset}", "negative", "verify", {"store": mutated}, ["out"], None))

    # S15b.1-S15b.2 (ADR-288, ADR-289): verification rejections of objects, types, constants, and the store, chosen by
    # the bootstrap's rule alone (deterministic mutations).  Their bootstrap diagnostics are recorded beside the
    # outcomes (``bootstrap_diagnostic``), not as references: ``xax_selfhost.linux_x86_64_status`` derives B1 from how
    # many of them each generation reproduces exactly; a decline or the driver's own record is no claim.
    from test_xax_selfhost_objects import _sample
    from test_xax_selfhost_render import _bases, _mutated

    object_rules = ("ID-REFERENCE-RESOLVED", "ID-ROOTED-STORE", "GRAPH-CHILD-KIND", "SCHEMA-BODY", "FUNCTION-BODY", "CALL-CONTRACT-BODY",
                    "RECURSION-GROUP-BODY", "TARGET-NATIVE-BODY", "SER-ULEB-TERMINATED", "TARGET-PROFILE-SUPPORTED", "BUILD-KIND", "PACKAGE-NAMED-REFERENCE",
                    "BUILD-REQUEST-REFERENCE-KINDS", "SNAPSHOT-HEADER")
    type_rules = ("TYPE-BITS", "TYPE-FORM-SUPPORTED", "TYPE-BODY", "CONST-BITS-WIDTH", "CONST-BODY", "TYPE-FLOAT-FORMAT", "TYPE-POINTER", "GRAPH-REF-INDEX")
    def entity_kind(reader, entity):
        try:
            return reader.get(bytes.fromhex(entity)).kind
        except (KeyError, ValueError, X.XaxError):
            return None  # the store, or a missing object

    rng, seen = random.Random(288), set()
    bases = _bases(rng)
    for trial in range(400):
        objects, root = bases[trial % len(bases)]
        objects, root = _mutated(rng, objects, root)
        try:
            reader = X.StoreReader(X.write_store(root, list(objects.values())))
            X._PARSED_GRAPHS.clear()
            X.verify_store(reader)
            continue
        except X.XaxError as error:
            diagnostic = error.diagnostic
        except (IndexError, KeyError, TypeError, ValueError):
            continue
        if diagnostic.rule in object_rules and diagnostic.rule not in seen and entity_kind(reader, diagnostic.entity) != X.Kind.GRAPH_FRAGMENT:
            seen.add(diagnostic.rule)
            cases.append((f"verify rejected: {diagnostic.rule}", "negative", "verify", {"store": reader.data}, ["out"], None))
            BOOTSTRAP_DIAGNOSTICS[cases[-1][0]] = _diagnostic_key(diagnostic)
    for trial in range(400):
        made, objects = _sample(rng)
        module = X.object_with_refs(X.Kind.MODULE, [made])
        program = X.object_with_refs(X.Kind.PROGRAM_ROOT, [module])
        try:
            reader = X.StoreReader(X.write_store(program.cid, list({item.cid: item for item in (*objects, module, program)}.values())))
            X._PARSED_GRAPHS.clear()
            X.verify_store(reader)
            continue
        except X.XaxError as error:
            diagnostic = error.diagnostic
        except (IndexError, KeyError, TypeError, ValueError):
            continue
        if diagnostic.rule in type_rules and diagnostic.rule not in seen:
            seen.add(diagnostic.rule)
            cases.append((f"verify rejected: {diagnostic.rule}", "negative", "verify", {"store": reader.data}, ["out"], None))
            BOOTSTRAP_DIAGNOSTICS[cases[-1][0]] = _diagnostic_key(diagnostic)

    # Graph rejections (S15b.3): the S10e mutation corpus of function stores (``test_xax_selfhost_verify``), one case per
    # bootstrap rule, recorded the same way.
    from test_xax_selfhost_verify import MUTATIONS, _store as function_store

    graph_rng = random.Random(266)
    for trial in range(160):
        reader = function_store(graph_rng, MUTATIONS[trial % len(MUTATIONS)])
        if reader is None:
            continue
        try:
            X._PARSED_GRAPHS.clear()
            X.verify_store(reader)
            continue
        except X.XaxError as error:
            diagnostic = error.diagnostic
        except (IndexError, KeyError, TypeError, ValueError):
            continue
        if diagnostic.rule not in seen:
            seen.add(diagnostic.rule)
            cases.append((f"verify rejected: {diagnostic.rule}", "negative", "verify", {"store": reader.data}, ["out"], None))
            BOOTSTRAP_DIAGNOSTICS[cases[-1][0]] = _diagnostic_key(diagnostic)

    def build(name, reader, kind):
        expected = build_expected(reader)
        reference = (["image", sha(expected[1]), sha(expected[2])] if expected[0] == "image" else ["rejected", expected[1].code, expected[1].rule])
        cases.append((name, kind, "build", {"store": reader.data}, ["artifact", "provenance"], reference))

    objects, entry = _parts(status)
    build("build snapshot", _program(objects, {b"image": entry}, linux), "positive")
    build("build: the root is no snapshot", status, "negative")
    build("build: external inputs", _program(objects, {b"image": entry}, linux, external_inputs={blake3(b"x").digest(): b"x"}), "negative")
    module = X.object_with_refs(X.Kind.MODULE, (entry,))
    app = package(b"app", (module,), build_entries=((b"image", entry),))
    policy = trust_policy(require_package_signatures=True, accepted_algorithms=(b"test-blake3",), accepted_signers=(b"test-key",))
    build("build: required signatures", _program(objects, {b"image": entry}, linux, policy=policy, signatures=(fake_signature(app),),
                                                 verifier=lambda *_: True), "negative")
    build("build: an unsupported artifact", _program(objects, {b"image": entry}, linux, artifacts=(ArtifactKind.ACCELERATOR_DEPLOYMENT,)), "negative")

    def resolve(name, reader, kind):
        expected = resolve_expected(reader)
        reference = ["image", sha(expected[1])] if expected[0] == "store" else ["rejected", expected[1].code, expected[1].rule]
        cases.append((name, kind, "resolve", {"store": reader.data}, ["out"], reference))

    base, base_objects = _library(b"base", 1)
    resolve("resolve with dependencies", _request(objects, entry, linux, dependencies=(DependencyRequirement.exact(base), DependencyRequirement.logical(b"base")),
                                                  extra=(base, *base_objects)), "positive")
    resolve("resolve: a missing logical identity", _request(objects, entry, linux, dependencies=(DependencyRequirement.logical(b"absent"),)), "negative")

    # S15c (ADR-299 to ADR-302): grants, external input files, Ed25519 signatures, capacities.
    import xax_ed25519 as ED
    from test_xax_selfhost_s15c import _Fixture, build_expected as build_with, resolve_expected as resolve_with
    from xax_build import BuildCapability, BuildCapabilityKind, CapabilityGrant, signature

    fixture = _Fixture()
    read = BuildCapability(BuildCapabilityKind.READ_OBJECT)

    def resolve_inputs(name, reader, kind, values=()):
        expected = resolve_with(reader, values)
        reference = ["image", sha(expected[1])] if expected[0] == "store" else ["rejected", expected[1].code, expected[1].rule]
        cases.append((name, kind, "resolve", {"store": reader.data}, ["out"], reference, list(values)))
        return expected

    def build_inputs(name, reader, kind, values=()):
        expected = build_with(reader, values)
        reference = (["image", sha(expected[1]), sha(expected[2])] if expected[0] == "image" else ["rejected", expected[1].code, expected[1].rule])
        cases.append((name, kind, "build", {"store": reader.data}, ["artifact", "provenance"], reference, list(values)))

    resolve_inputs("resolve: a declared grant", fixture.request_store(capabilities=(read,), grants=(CapabilityGrant(b"app", read),)), "positive")
    resolve_inputs("resolve: an undeclared grant", fixture.request_store(grants=(CapabilityGrant(b"app", read),)), "negative")
    values = (b"input one", bytes(4096))
    resolved = resolve_inputs("resolve with external inputs", fixture.request_store(), "positive", values)
    build_inputs("build with external inputs", X.StoreReader(resolved[1]), "positive", values)
    build_inputs("build: an external input missing", X.StoreReader(resolved[1]), "negative", values[:1])
    secret = bytes(range(32))
    key, app = ED.public_key(secret), fixture.app()
    ed_policy = trust_policy(require_package_signatures=True, accepted_algorithms=(ED.ALGORITHM,), accepted_signers=(key,))
    build_inputs("build: Ed25519-signed", fixture.signed_snapshot((signature(app, ED.ALGORITHM, key, ED.sign(secret, app.cid)),), ed_policy),
                 "positive")
    build_inputs("build: a forged Ed25519 signature",
                 fixture.signed_snapshot((signature(app, ED.ALGORITHM, key, ED.sign(bytes(32), app.cid)),), ed_policy), "negative")
    cases.append(("verify: a store past the driver's capacity", "negative", "verify", {"store": bytes(33 << 20)}, ["out"], None))
    cases.append(("unknown command", "negative", "compile", {"store": status.data}, ["out"], None))
    return cases


def _diagnostic_key(diagnostic) -> list:
    """A rejection's code, rule, and the digest of the whole diagnostic (entity, values and their types, dependencies,
    repair neighborhood): equal digests are equal diagnostics."""
    whole = (diagnostic.code, diagnostic.entity, diagnostic.rule, diagnostic.expected, diagnostic.actual, tuple(diagnostic.dependencies),
             tuple(diagnostic.repair_neighborhood))
    return [diagnostic.code, diagnostic.rule, sha(repr(whole).encode())]


def run_case(executable: Path, directory: Path, case) -> dict:
    name, _kind, command, inputs, outputs, _reference, *extra = case
    paths = {}
    for key, data in inputs.items():
        paths[key] = directory / f"{key}.xax"
        paths[key].write_bytes(data)
    out = [directory / f"{item}.bin" for item in outputs]
    files = []  # S15c.2: external input files after the outputs
    for k, data in enumerate(extra[0] if extra else ()):
        files.append(directory / f"input{k}.bin")
        files[-1].write_bytes(data)
    arguments = [command, *paths.values(), *out, *files]
    return run(executable, arguments, out)


def measure() -> dict:
    import xax_compiler as X
    import xax_native
    from xax_artifact import XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1
    from xax_build import build, decode_provenance, resolve_packages, snapshot_store
    from xax_linux import compile_linux_executable
    from xax_selfhost_compiler import compiler_request
    from xax_selfhost_driver import GENERAL_STORE_PATH, NativeGeneralDriver, decode_inspection
    from xax_selfhost_resolve import POLICY, RESOLVER_IDENTITY

    directory = Path(tempfile.mkdtemp(prefix="xax-full-selfhost-"))
    driver = X.StoreReader(GENERAL_STORE_PATH.read_bytes())
    request_store, request = compiler_request(driver)
    request_path = directory / "compiler-request.xax"
    request_path.write_bytes(request_store.data)

    # The bootstrap references.
    start = time.perf_counter()
    candidates = (*request_store.objects(), POLICY)
    reference_snapshot = snapshot_store(resolve_packages(request, candidates, POLICY, RESOLVER_IDENTITY), candidates).data
    python_resolve_s = time.perf_counter() - start
    module = next(item for item in driver.objects() if item.kind == X.Kind.MODULE)
    entry = next(driver.get(cid) for cid in module.references if driver.get(cid).kind == X.Kind.FUNCTION)
    start = time.perf_counter()
    reference_compiler = compile_linux_executable(driver, entry.cid, X.x86_64_linux_exec_target().cid, frontend="python").data
    python_compile_s = time.perf_counter() - start

    # C0: the seed.
    start = time.perf_counter()
    seed = NativeGeneralDriver()
    seed_s = time.perf_counter() - start
    executables = [Path(seed.path)]
    generations = []
    for n in range(3):
        producer = executables[-1]
        snapshot_path, artifact, provenance = directory / f"snapshot{n}.xax", directory / f"C{n + 1}", directory / f"P{n + 1}.bin"
        resolved = run(producer, ["resolve", request_path, snapshot_path], [snapshot_path])
        built = run(producer, ["build", snapshot_path, artifact, provenance], [artifact, provenance])
        snapshot_bytes, (artifact_bytes, provenance_bytes) = resolved["_data"][0], built["_data"]
        record = {
            "generation": n + 1, "producer": f"C{n}", "producer_sha256": sha(producer.read_bytes()),
            "resolve": {key: value for key, value in resolved.items() if key != "_data"},
            "build": {key: value for key, value in built.items() if key != "_data"},
            "snapshot_sha256": sha(snapshot_bytes), "snapshot_equals_python_resolver": snapshot_bytes == reference_snapshot,
            "artifact_sha256": sha(artifact_bytes), "artifact_bytes": None if artifact_bytes is None else len(artifact_bytes),
            "provenance_sha256": sha(provenance_bytes),
        }
        if snapshot_bytes is not None and provenance_bytes is not None:
            snapshot = X.StoreReader(snapshot_bytes)
            view = decode_provenance(X.decode_object(provenance_bytes, "provenance"), X.store_resolver(snapshot))
            record["provenance"] = {"cid": X.decode_object(provenance_bytes, "provenance").cid.hex(), "snapshot_root": view.snapshot_root.hex(),
                                    "request_root": view.request_root.hex(), "target_root": view.target_root.hex(), "profile_root": view.profile_root.hex(),
                                    "artifact_digest_blake3": view.artifact_digest.hex(), "compiler_identity": view.compiler_identity.hex(),
                                    "lowering_identity": view.lowering_identity.hex()}
            if n == 0:
                python_build = build(snapshot, view.request_root, compiler_identity=XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1)
                record["equals_python_build"] = python_build.artifact == artifact_bytes and python_build.provenance.envelope() == provenance_bytes
        generations.append(record)
        if built["status"] != "image":
            break
        os.chmod(artifact, 0o755)
        executables.append(artifact)

    # A run of C1 with an empty environment: no PATH, no PYTHONPATH, nothing inherited.
    empty = {}
    if len(executables) > 1:
        bare = run(executables[1], ["resolve", request_path, directory / "bare-snapshot.xax"], [directory / "bare-snapshot.xax"], environment=empty)
        empty_run = {"environment": "empty (no PATH, no PYTHONPATH)", "status": bare["status"], "snapshot_sha256": bare["outputs"][0]}
    else:
        empty_run = None

    # The corpus, run by every generation.
    cases = corpus(directory)
    rows = []
    for case in cases:
        name, kind, command, _inputs, _outputs, reference, *_extra = case
        outcomes = {}
        for index, executable in enumerate(executables):
            result = run_case(executable, directory, case)
            outcome = _outcome(result)
            if result["status"] == "rejected" and result["_data"][0] is not None:
                from xax_selfhost_diagnostics import decode_record

                data = result["_data"][0]
                diagnostic = decode_record([int.from_bytes(data[k:k + 8], "little") for k in range(0, len(data), 8)])
                outcome = ["rejected", *(_diagnostic_key(diagnostic) if command == "verify" else (diagnostic.code, diagnostic.rule))]
            if command == "inspect" and result["status"] == "image":
                outcome = ["image", sha(json.dumps(decode_inspection(result["_data"][0]), sort_keys=True).encode())]
            outcomes[f"C{index}"] = outcome
        row = {"case": name, "kind": kind, "command": command, "outcomes": outcomes, "reference": reference}
        if name in BOOTSTRAP_DIAGNOSTICS:
            row["bootstrap_diagnostic"] = BOOTSTRAP_DIAGNOSTICS[name]
        rows.append(row)

    def elf_interpreter(path: Path) -> bool:
        data = path.read_bytes()
        count, size, offset = int.from_bytes(data[56:58], "little"), int.from_bytes(data[54:56], "little"), int.from_bytes(data[32:40], "little")
        return any(int.from_bytes(data[offset + k * size:offset + k * size + 4], "little") == 3 for k in range(count))

    return {
        "format": "xax-full-selfhost-evidence-v1",
        "label": "EXECUTED",
        "adr": "ADR-285",
        "host_nonsemantic": f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
        "scope": {
            "name": "linux_x86_64_production_compiler",
            "compiler": "the general driver (xax_compiler_driver_general.xax): verify, inspect, resolve, build, lower",
            "targets": ["x86_64-linux-elf-exec-v1", "x86_64-linux-elf-dynexec-v1", "x86_64-linux-views-v1/v2", "x86_64-linux-views-exec-v1"],
            "outside_scope": "every other target and artifact (AArch64, Windows PE, JVM, WebAssembly, Android, SPIR-V, accelerator): Python",
        },
        "spec_revision": "XAX_SPEC.md §16",
        "compiler": {"store": GENERAL_STORE_PATH.name, "store_sha256": sha(driver.data), "semantic_root": driver.root_cid.hex(),
                     "request_store_sha256": sha(request_store.data), "request_root": request.cid.hex(),
                     "target_root": X.x86_64_linux_exec_target().cid.hex(), "resolver_identity": RESOLVER_IDENTITY.decode(),
                     "policy_root": POLICY.cid.hex(), "compiler_identity": XAX_GENERAL_DRIVER_COMPILER_IDENTITY_V1.hex()},
        "seed": {"kind": "the driver store lowered by the XAX views backend for x86_64-linux-views-exec-v1, in a Python host process",
                 "sha256": sha(seed.executable), "bytes": len(seed.executable), "requires_python": True,
                 "host_s_nonsemantic": round(seed_s, 1)},
        "references": {"python_resolver_snapshot_sha256": sha(reference_snapshot), "python_resolve_s_nonsemantic": round(python_resolve_s, 1),
                       "bootstrap_compile_sha256": sha(reference_compiler), "bootstrap_compile_bytes": len(reference_compiler),
                       "bootstrap_compile_s_nonsemantic": round(python_compile_s, 1)},
        "generations": generations,
        "fixed_point": {"comparison": "raw executable bytes (SHA-256)", "artifacts": [item["artifact_sha256"] for item in generations]},
        "empty_environment_run": empty_run,
        "executables_have_interpreter": {f"C{index}": elf_interpreter(path) for index, path in enumerate(executables)},
        "corpus": rows,
        # Recorded gaps (each one keeps a B level from holding; see ``xax_selfhost.bootstrap_status``).
        "rejection_exactness_gaps": [
            ("memory rejections that quote a decoded declaration, a pointer type the memory engine's pointer decoder rejects, and a "
             "stack-owner entry's contract decline (ADR-293, ADR-297); a group member function's own graph check, a missing reference "
             "first reached through another object's graph, and rejections inside nested build decoders decline (ADR-288, ADR-297)"),
        ],
        # S15c (ADR-299 to ADR-302): grants, external input files, Ed25519 verification in ``build``, and capacity
        # rejections are the driver's.  What remains:
        "required_paths_outside_xax": [
            "resolution under a trust policy other than the driver's own: signed snapshots are verified by build (S15c.3) but "
            "only the bootstrap resolver makes them",
        ],
        # S15d.1-S15d.3 (ADR-304 to ADR-306): the compiler changes its own store through ``edit`` and the evolution
        # ledger; what remains:
        "ordinary_evolution": ("the compiler's transaction engine (S15d.1) changes operations and constants only; structural changes "
                               "(nodes, uses, signatures, new functions) still need the Python builders (S15d.4)"),
        "python_dependency": {"production": False, "bootstrap_seed": True, "reference": True, "test_only": True},
        "authority": xax_native.AUTHORITY,
    }


if __name__ == "__main__" and os.environ.get("PYTHONHASHSEED") != "0":
    # The corpus generators iterate sets of bytes: a fixed hash seed makes the cases the same on every run.
    os.execve(sys.executable, [sys.executable, *sys.argv], {**os.environ, "PYTHONHASHSEED": "0"})

if __name__ == "__main__":
    os.environ["XAX_REQUIRE_NATIVE"] = "1"
    evidence = measure()
    text = json.dumps(evidence, indent=2) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
