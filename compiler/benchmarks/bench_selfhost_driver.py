"""S10/S11 evidence (ADR-265, ADR-266, ADR-267): the XAX compiler driver, run as a Linux process, against the in-process
Python-orchestrated path.

For every committed store: the driver's outcome (image or diagnostic) and whether it equals
``compile_x86_64_views`` (the bootstrap generator, after the bootstrap verifier); the driver's wall time (file read,
decoding, semantic verification, object table, lowering, file write) against the in-process path doing the same work
(``StoreReader`` and ``compile_x86_64_views(..., backend="xax")``, whose ``verify_store`` asks the same XAX components
with Python orchestrating them), median of five; the driver's time includes starting its process.  Also: the driver
image is the bootstrap generator's (B1-like), and the self-build loop: the driver executable (gen1) lowers the driver
store to gen2, gen2 to gen3, each a process (component fixed point).  Host timings are non-semantic.  Runs with ``XAX_REQUIRE_NATIVE=1``.
Run: ``PYTHONPATH=src python benchmarks/bench_selfhost_driver.py [--write]``.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parent / "selfhost_driver_evidence.json"
BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"


def _median(function, repeats: int = 5) -> float:
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        function()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def measure() -> dict:
    import xax_compiler as X
    import xax_native
    from xax_selfhost_diagnostics import decode_record
    from xax_selfhost_driver import NativeDriver, load_driver_program, target_package
    from xax_x86_64_views import compile_x86_64_views, views_executable

    reader, function = load_driver_program()
    v1, exec_target = X.x86_64_views_target(), X.x86_64_views_exec_target()
    image = compile_x86_64_views(reader, function.cid, exec_target, backend="xax")
    reference = compile_x86_64_views(reader, function.cid, exec_target, backend="python")
    driver = NativeDriver(image)
    directory = Path(tempfile.mkdtemp())
    targets = {"v1": directory / "v1.xax", "exec": directory / "exec.xax"}
    targets["v1"].write_bytes(target_package(v1))
    targets["exec"].write_bytes(target_package(exec_target))
    output = directory / "out.bin"

    def drive(path: Path, target: str):
        if output.exists():
            output.unlink()
        status = driver.run(path, targets[target], output)
        produced = output.read_bytes() if output.exists() else b""
        return status, produced

    def in_process(data: bytes, target):
        store = X.StoreReader(data)
        module = next(item for item in store.objects() if item.kind == X.Kind.MODULE)
        entry = next(store.get(cid) for cid in module.references if store.get(cid).kind == X.Kind.FUNCTION)
        X._PARSED_GRAPHS.clear()
        X._XAX_VALID_OBJECTS.clear()
        return compile_x86_64_views(store, entry.cid, target, backend="xax")  # the same work: semantic verification included

    rows = []
    for path in sorted(BOOTSTRAP.glob("*.xax")):
        data = path.read_bytes()
        store = X.StoreReader(data)
        module = next(item for item in store.objects() if item.kind == X.Kind.MODULE)
        entry = next(store.get(cid) for cid in module.references if store.get(cid).kind == X.Kind.FUNCTION)
        try:
            expected = ("image", compile_x86_64_views(store, entry.cid, v1, backend="python").code)
        except X.XaxError as error:
            expected = ("rejected", error.diagnostic)
        status, produced = drive(path, "v1")
        if status == 0:
            outcome = ("image", produced)
        elif status == 1:
            outcome = ("rejected", decode_record([int.from_bytes(produced[k:k + 8], "little") for k in range(0, len(produced), 8)]))
        else:
            outcome = (str(status), produced)
        row = {"store": path.name, "store_bytes": len(data), "outcome": outcome[0], "equals_bootstrap": outcome == expected}
        if outcome[0] == "image":
            row["image_sha256"] = hashlib.sha256(produced).hexdigest()
            row["image_bytes"] = len(produced)
            row["host_s_nonsemantic"] = {"xax_driver": round(_median(lambda: drive(path, "v1")), 4),
                                         "python_orchestrated_xax_components": round(_median(lambda: in_process(data, v1)), 4)}
        else:
            row["diagnostic"] = {"code": outcome[1].code, "rule": outcome[1].rule} if outcome[0] == "rejected" else None
        rows.append(row)

    generations, seconds, statuses = [driver.path.read_bytes()], [], []
    generation = driver.path
    for name in ("gen2", "gen3"):
        output = directory / name
        start = time.perf_counter()
        statuses.append(subprocess.run([str(generation), str(BOOTSTRAP / "xax_compiler_driver.xax"), str(targets["exec"]), str(output)], check=False).returncode)
        seconds.append(round(time.perf_counter() - start, 2))
        os.chmod(output, 0o755)
        generations.append(output.read_bytes())
        generation = output
    return {
        "format": "xax-selfhost-driver-evidence-v3",
        "label": "EXECUTED",
        "host_nonsemantic": f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
        "driver": {"store_sha256": hashlib.sha256(reader.data).hexdigest(), "semantic_root": reader.root_cid.hex(),
                   "target_cid": exec_target.cid.hex(), "code_bytes": len(image.code), "image_sha256": hashlib.sha256(image.code).hexdigest(),
                   "executable_bytes": len(generations[0]), "executable_sha256": hashlib.sha256(generations[0]).hexdigest(),
                   "xax_backend_equals_bootstrap_generator": image == reference,
                   "executable_equals_views_executable": generations[0] == views_executable(reference)},
        "stores": rows,
        "self_build_loop": {"gen1": "the driver executable from the XAX backend's image", "gen2_gen3_statuses": statuses,
                            "host_s_nonsemantic": seconds, "gen2_equals_gen1": generations[1] == generations[0],
                            "gen3_equals_gen2": generations[2] == generations[1]},
        "authority": xax_native.AUTHORITY,
    }


if __name__ == "__main__":
    os.environ["XAX_REQUIRE_NATIVE"] = "1"  # a Python fallback is an error here, never XAX evidence
    evidence = measure()
    text = json.dumps(evidence, indent=2, sort_keys=False) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    print(text)
