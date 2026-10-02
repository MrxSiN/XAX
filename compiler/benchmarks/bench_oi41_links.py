"""OI-41 closure measurements: kernel growth and verifier cost of record links (ADR-097).

* Kernel growth: operations and type forms added, new verifier rule names,
  and the source diff of the verifier module against the last commit before
  OI-41 (``cb0b53c``) when git history is available.
* Verifier cost: ``verify_store`` median wall time for the three ``chains``
  variants (index, ``pointer_rebase``, record links).

Performance against C lives in ``oi37_chains_evidence.json`` (``xax-link`` arm).
Timings are host-dependent medians.  No model is run.
Run: PYTHONPATH=src:. python -m benchmarks.bench_oi41_links
"""

from __future__ import annotations

import json
import re
import statistics
import subprocess
import time
from pathlib import Path

from benchmarks.linux_chains import build_chains_program
from xax_compiler import Operation, verify_store

OUTPUT = Path(__file__).resolve().parent / "oi41_links_evidence.json"
SOURCE = Path(__file__).resolve().parents[1] / "src" / "xax_compiler.py"
BASE_COMMIT = "cb0b53c"
REPEATS = 15


def _median_microseconds(action) -> float:
    samples = []
    for _ in range(REPEATS):
        start = time.perf_counter()
        action()
        samples.append(time.perf_counter() - start)
    return round(statistics.median(samples) * 1e6, 1)


def kernel_growth() -> dict:
    text = SOURCE.read_text()
    rules = sorted(set(re.findall(r'"((?:MEMORY-(?:LINK|RECORD|REBASE-RECORD)|CONST-LINK|INT-COMPARE-LINK|TYPE-LINK)[A-Z-]*)"', text)))
    diff = subprocess.run(["git", "diff", "--numstat", BASE_COMMIT, "--", str(SOURCE)], capture_output=True, text=True, check=False).stdout.split()
    return {
        "operations_added": ["LINK_MAKE", "LINK_FOLLOW"],
        "operation_ids": [int(Operation.LINK_MAKE), int(Operation.LINK_FOLLOW)],
        "type_forms_added": {"11": "link (8 bytes on every target; null constant only)"},
        "operation_extended": "heap_view: optional 4th operand naming the link target record view",
        "verifier_rules_added": rules,
        "verifier_source_lines_vs_base": {"base": BASE_COMMIT, "added": int(diff[0]), "removed": int(diff[1])} if len(diff) >= 2 else None,
    }


def verifier_cost() -> dict:
    readers = {links: build_chains_program(links=links).reader for links in ("index", "pointer", "link")}
    return {f"chains_{links}_verify_microseconds": _median_microseconds(lambda reader=reader: verify_store(reader)) for links, reader in readers.items()}


def main() -> None:
    result = {"issue": "OI-41", "evidence_label": "MEASURED", "model_run": None, "kernel_growth": kernel_growth(), "verifier_cost": verifier_cost(), "repeats": REPEATS}
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
