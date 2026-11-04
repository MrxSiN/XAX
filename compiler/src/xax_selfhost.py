"""The bootstrap levels B0-B6 of the production compiler, derived from executed records (``XAX_SPEC.md`` §16.2).

Bootstrap labels are evidence claims.  Nothing here asserts a level: ``bootstrap_status`` computes every level from two
committed records the native compiler produced, ``benchmarks/full_selfhost_evidence.json`` (``bench_full_selfhost``) and
``benchmarks/python_free_seed_evidence.json`` (``bench_python_free_seed``).

W3 (ADR-362): the M14 Python bootstrap is retired.  Until then this module also built the M14 semantic-image META
wrapper (``m14_selfhost_compiler.xax``), executed its recursive generations in Python and fed a Python zipapp seed;
B levels were recorded through ``bootstrap/m14_selfhost_evidence.json``.  The bootstrap seed is now the pinned native
compiler (``bootstrap/seed/xaxc-linux-x86_64``, ADR-286); the wrapper's store stays a frozen corpus program, and the
identities below name it.
"""

from __future__ import annotations

from pathlib import Path

M14_PROGRAM_FILENAME = "m14_selfhost_compiler.xax"  # the frozen META-wrapper corpus store (W3, ADR-362)
M14_COMPILER_IDENTITY = b"xax-m14-semantic-image-compiler-v1"
M14_EVALUATOR_IDENTITY = b"xax-m14-meta-evaluator-v1"
M14_VERIFIER_IDENTITY = b"xax-verifier-v1"
M14_CLOSURE_TARGET = b"xax-semantic-image-v1"

# S14b (ADR-285): the executed generations of the Linux x86-64 production compiler (the general driver).
FULL_SELFHOST_EVIDENCE = Path(__file__).resolve().parents[1] / "benchmarks" / "full_selfhost_evidence.json"
# S15a (ADR-286): the pinned XAX-built seed rebuilding the compiler with no Python reachable.
SEED_EVIDENCE = Path(__file__).resolve().parents[1] / "benchmarks" / "python_free_seed_evidence.json"


def seed_requires_python(full: dict, seed: dict | None) -> bool:
    """False only when ``seed`` records the pinned seed, without an ELF interpreter, rebuilding the compiler of ``full``
    (the same request store, the same executable as its generations) twice with an environment of ``PATH`` alone, on
    which no Python resolves."""
    from xax_selfhost_seed import SEED_SHA256

    if seed is None:
        return full["seed"]["requires_python"]
    compiler = full["generations"][-1]["artifact_sha256"]
    return not (
        seed["seed"]["sha256"] == SEED_SHA256 and not seed["seed"]["has_interpreter"]
        and seed["environment"]["variables"] == ["PATH"] and seed["environment"]["python_on_path"] is None
        and seed["selfbuild_status"] == 0 and seed["request_store_sha256"] == full["compiler"]["request_store_sha256"]
        and all(item["sha256"] == compiler for item in seed["generations"])
    )


def linux_x86_64_status(full: dict, seed: dict | None = None) -> dict:
    """B0-B6 for the Linux x86-64 production compiler, derived from the raw record ``full`` (``bench_full_selfhost``):
    executable digests, which executable produced which, snapshot digests against the Python resolver, the bootstrap's
    own compile, every generation's outcome on the corpus against the bootstrap's, and the recorded gaps.  No level is
    read from the record; each is computed here."""
    import json

    generations = full["generations"]
    produced = [full["seed"]["sha256"], *(item["artifact_sha256"] for item in generations)]
    completed = len(generations) == 3 and all(item["resolve"]["status"] == "image" and item["build"]["status"] == "image" for item in generations)
    chained = completed and all(item["producer_sha256"] == produced[index] for index, item in enumerate(generations))
    snapshots = completed and all(item["snapshot_equals_python_resolver"] for item in generations)
    artifacts = [item["artifact_sha256"] for item in generations]
    corpus = full["corpus"]
    agree = bool(corpus) and all(len(row["outcomes"]) == len(generations) + 1 and len({json.dumps(o) for o in row["outcomes"].values()}) == 1
                                 for row in corpus)
    exact = all(row["reference"] is None or row["outcomes"]["C1"] == row["reference"] for row in corpus)
    # S15b (ADR-288): verification rejections recorded with the bootstrap's diagnostic.  A generation that rejects with
    # another diagnostic disagrees with the bootstrap; one that declines, or writes its own record, makes no claim but
    # is not exact.
    rejecting = [row for row in corpus if row.get("bootstrap_diagnostic")]
    reproduced = lambda row: row["outcomes"].get("C1") == ["rejected", *row["bootstrap_diagnostic"]]  # noqa: E731
    wrong = [row for row in rejecting if row["outcomes"].get("C1", [None])[0] == "rejected" and row["outcomes"]["C1"][1] != "XAX.DRIVER.VERIFY"
             and not reproduced(row)]
    inexact = [row for row in rejecting if not reproduced(row)]
    exact = exact and not wrong
    both = {row["kind"] for row in corpus} >= {"positive", "negative"}
    b0 = bool(generations) and generations[0]["build"]["status"] == "image" and len(generations) > 1 and generations[1]["resolve"]["status"] == "image"
    b2 = chained and snapshots
    b3 = b2 and agree and exact and both
    b4 = b2 and len(set(artifacts)) == 1 and artifacts[0] == full["references"]["bootstrap_compile_sha256"]
    b1 = b2 and not full["rejection_exactness_gaps"] and not inexact
    b5 = b2 and not full["required_paths_outside_xax"] and not any(full["executables_have_interpreter"].values())
    # S15d.4b (ADR-314): ordinary evolution is shown, not stated: the first self-built compiler replayed the ledger,
    # including a structural transaction, to exactly the committed stores, which it verified.
    # W2 (ADR-361), ``xax-evolution-replay-v2``: the stores are frozen; C1 replayed every ledger transaction from the store
    # it started at to the store the ledger records and verified it, and applied a structural probe transaction to the
    # committed driver store, equal to the reference engine's store and verified.
    evolution = full.get("evolution") or {}
    if evolution.get("format") == "xax-evolution-replay-v2":
        probe = evolution.get("probe") or {}
        evolved = (evolution.get("structural") is True and evolution.get("ledger_heads_equal_committed") is True
                   and probe.get("edit", {}).get("status") == "image" and probe.get("equals_reference") is True and probe.get("verify") == "image"
                   and all(item.get("edit", {}).get("status") == "image" and item.get("equals_ledger") is True and item.get("verify") == "image"
                           for item in evolution.get("transactions", ())))
    else:
        evolved = (bool(evolution.get("transactions")) and evolution.get("structural") is True and evolution.get("driver_equals_committed") is True
                   and evolution.get("request_equals_committed") is True and evolution.get("driver_verify") == "image"
                   and evolution.get("request_verify") == "image"
                   and all(item.get("driver_edit", {}).get("status") == "image" and item.get("request_edit", {}).get("status") == "image"
                           for item in evolution["transactions"]))
    b6 = b5 and evolved and not full["ordinary_evolution"]
    blockers = {
        "B0": None if b0 else "the seed did not produce a running compiler",
        "B1": None if b1 else "; ".join([*full["rejection_exactness_gaps"],
                                         *([f"{len(inexact)} of {len(rejecting)} corpus verification rejections are not the bootstrap's exact diagnostic"]
                                           if inexact else [])]) or "no recursive build",
        "B2": None if b2 else "the generations do not chain through resolve and build",
        "B3": None if b3 else "the generations or the bootstrap disagree on the corpus",
        "B4": None if b4 else "the generations are not byte-identical to each other and the bootstrap's compile",
        "B5": None if b5 else "; ".join(full["required_paths_outside_xax"]) or "a required path is not XAX-hosted",
        "B6": None if b6 else full["ordinary_evolution"] or ("B5 does not hold" if not b5 else
                                                             "the self-built compiler did not replay a structural evolution ledger to the committed stores"),
    }
    return {"scope": full["scope"]["compiler"], "outside_scope": full["scope"]["outside_scope"],
            **{f"B{n}": level for n, level in enumerate((b0, b1, b2, b3, b4, b5, b6))},
            "blockers": {level: reason for level, reason in blockers.items() if reason},
            "seed_requires_python": seed_requires_python(full, seed)}

def bootstrap_seed(seed: dict | None, linux: dict | None) -> dict:
    """The bootstrap seed as the Python-free seed record names it."""
    if seed is None:
        return {"kind": "none recorded", "path": None, "bytes": 0, "requires_python": True}
    return {"kind": "native-elf" if not seed["seed"]["has_interpreter"] else "elf-with-interpreter", "path": seed["seed"]["path"],
            "bytes": seed["seed"]["bytes"], "sha256": seed["seed"]["sha256"],
            "requires_python": True if linux is None else linux["seed_requires_python"]}


def bootstrap_status() -> dict:
    """The one derivation of B0-B6 (XAX_SPEC.md 16.2), from the committed executed records; the generated status
    blocks consume it and nothing else asserts a B level.  S-step component fixed points are not B milestones (16.5)."""
    import json

    seed = json.loads(SEED_EVIDENCE.read_text(encoding="utf-8")) if SEED_EVIDENCE.exists() else None
    record = json.loads(FULL_SELFHOST_EVIDENCE.read_text(encoding="utf-8")) if FULL_SELFHOST_EVIDENCE.exists() else None
    linux = linux_x86_64_status(record, seed) if record is not None else None
    # S15g (ADR-358): the Linux x86-64 production compiler builds every target and artifact ``build`` makes (its
    # record's scope has nothing outside it), so the whole production compiler's levels are that compiler's, derived
    # from the same executed record; until then none is established.
    if linux is not None and record["scope"].get("outside_scope") is None:
        reasons = "; ".join(f"{level}: {reason}" for level, reason in linux["blockers"].items())
        full = {**{f"B{level}": linux[f"B{level}"] for level in range(7)},
                "blocker": "derived from the Linux x86-64 production compiler, whose executed record covers every target and artifact "
                           "`build` makes (S15g, ADR-358)" + (f"; {reasons}" if reasons else "")}
    else:
        full = {**{f"B{level}": False for level in range(7)},
                "blocker": "the Linux x86-64 production compiler's executed record does not cover every target and artifact (its "
                           "scope's outside_scope: " + (str(record["scope"].get("outside_scope")) if record is not None else "no record") + ")"}
    return {
        "derivation_source": "xax_selfhost.bootstrap_status",
        "records": ["compiler/benchmarks/full_selfhost_evidence.json", "compiler/benchmarks/python_free_seed_evidence.json"],
        "full_production_compiler": full,
        **({"linux_x86_64_production_compiler": linux} if linux is not None else {}),
        "bootstrap_seed": bootstrap_seed(seed, linux),
    }
