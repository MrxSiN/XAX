"""The reference evaluator of the V1 self-hosting records (``XAX_SPEC.md`` §16.2): B0-B6 from
``benchmarks/full_selfhost_evidence.json`` (``bench_full_selfhost``) and ``benchmarks/python_free_seed_evidence.json``
(``bench_python_free_seed``).

ADR-410: the released B levels are the native ``xax_evidence levels`` of a V2 record (``xax_selfhost_seed.bootstrap_status``);
this module stays only as the oracle ``tests/test_evidence_v2.py`` compares that program with. ADR-433 (3): the V1 record holds only
the pinned seed's corpus outcomes against the live reference; the generations and the replay are read from a V2 record.

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

# S14b (ADR-285), ADR-433 (3): the V1 record, the pinned seed's outcomes on the corpus against the live reference.
FULL_SELFHOST_EVIDENCE = Path(__file__).resolve().parents[1] / "benchmarks" / "full_selfhost_evidence.json"
# S15a (ADR-286): the pinned XAX-built seed rebuilding the compiler with no Python reachable.
SEED_EVIDENCE = Path(__file__).resolve().parents[1] / "benchmarks" / "python_free_seed_evidence.json"
EVIDENCE = Path(__file__).resolve().parents[1] / "bootstrap" / "evidence"


def released_record() -> str:
    """The V2 record of the latest validated release (ADR-410): it holds the generations and the replay."""
    from xax_selfhost_seed import released

    return (EVIDENCE / "records" / f"{released()}.record").read_text(encoding="ascii")


def _record(text: str) -> dict:
    """The facts of a V2 record (``bootstrap/evidence/README.md``) this evaluator reads."""
    facts = {"end": False, "seed": None, "request": None, "generations": [], "contexts": {}, "outcomes": {}, "repeats": {}, "replay": None}
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        if words[0] == "end":
            facts["end"] = True
        elif words[0] == "seed":
            facts["seed"] = (words[1], words[2])
        elif words[0] == "request":
            facts["request"] = words[1]
        elif words[0] == "generation":
            facts["generations"].append(dict(zip(("producer", "resolve", "snapshot", "build", "artifact", "provenance", "interpreter"), words[2:9])))
        elif words[0] == "context":
            facts["contexts"][words[1]] = words[2]
        elif words[0] == "outcome":
            facts["outcomes"].setdefault(words[1], {})[int(words[2])] = words[3:]
        elif words[0] == "repeat":
            facts["repeats"].setdefault(words[1].removesuffix("-r"), {})[int(words[2])] = words[3:]
        elif words[0] == "replay":
            facts["replay"] = words[1:]
    return facts


def _probe(corpus: str) -> tuple[int, str | None]:
    """The structural probe's case index in the frozen corpus and its expected output digest."""
    lines = [line for line in corpus.splitlines() if line.strip() and not line.startswith("#")]
    index = next(k for k, line in enumerate(lines) if line.endswith(" a structural probe (B6)"))
    expect = lines[index].split()[2]
    return index, expect.split(":")[1] if expect.startswith("image:") else None


def seed_requires_python(full: dict, seed: dict | None, record: str | None = None) -> bool:
    """False only when ``seed`` records the pinned seed, without an ELF interpreter, rebuilding the compiler the V2
    ``record``'s last generation built (the same request store as ``full``) twice with an environment of ``PATH`` alone,
    on which no Python resolves.  ADR-382: ``full``'s C0 is that pinned seed, so without ``seed`` nothing shows it."""
    from xax_selfhost_seed import pin

    if seed is None:
        return True
    facts = _record(released_record() if record is None else record)
    compiler = facts["generations"][-1]["artifact"] if facts["generations"] else None
    return not (
        seed["seed"]["sha256"] == pin()[0] and not seed["seed"]["has_interpreter"] and (facts["seed"] or ("", "1"))[1] == "0"
        and seed["environment"]["variables"] == ["PATH"] and seed["environment"]["python_on_path"] is None
        and seed["selfbuild_status"] == 0 and seed["request_store_sha256"] == full["compiler"]["request_store_sha256"]
        and all(item["sha256"] == compiler for item in seed["generations"])
    )


def linux_x86_64_status(full: dict, seed: dict | None = None, record: str | None = None, corpus: str | None = None) -> dict:
    """B0-B6 for the Linux x86-64 production compiler.  ADR-433 (3): the generations, the fixed point, the contexts'
    agreement, the replay and the structural probe come from the V2 ``record`` (default: the latest validated
    release's) and its frozen ``corpus`` (default: ``bootstrap/evidence/CORPUS``); the corpus outcomes against the live
    reference, the reference snapshot, C0's interpreter and the recorded gaps from the V1 record ``full``
    (``bench_full_selfhost``).  No level is read from either record; each is computed here."""
    import json

    facts = _record(released_record() if record is None else record)
    probe_index, probe_digest = _probe((EVIDENCE / "CORPUS").read_text(encoding="ascii") if corpus is None else corpus)
    generations, seed_sha = facts["generations"], (facts["seed"] or ("-", "1"))[0]
    produced = [seed_sha, *(item["artifact"] for item in generations)]
    completed = facts["end"] and bool(generations) and all(item["resolve"] == "0" and item["build"] == "0" for item in generations)
    chained = completed and seed_sha == full["seed"]["sha256"] and all(item["producer"] == produced[k] for k, item in enumerate(generations))
    snapshots = (completed and facts["request"] == full["compiler"]["request_store_sha256"]
                 and all(item["snapshot"] == full["references"]["python_resolver_snapshot_sha256"] for item in generations))
    b0 = completed and (len(generations) > 1 or generations[0]["artifact"] == seed_sha)
    b2 = chained and snapshots
    # The contexts agree: each has every case of the frozen corpus, they are equal, and every repeat is its context's.
    contexts = facts["outcomes"]
    cases = set(range(probe_index + 1))
    agree = (bool(contexts) and all(set(table) == cases for table in contexts.values())
             and len({json.dumps(sorted(table.items())) for table in contexts.values()}) == 1
             and all(context in contexts and all(contexts[context].get(case) == outcome for case, outcome in table.items())
                     for context, table in facts["repeats"].items()))
    rows = full["corpus"]
    exact = all(row["reference"] is None or row["outcomes"].get("C0") == row["reference"] for row in rows)
    # S15b (ADR-288): verification rejections recorded with the bootstrap's diagnostic.  A rejection with another
    # diagnostic disagrees with the bootstrap; a decline, or the driver's own record, makes no claim but is not exact.
    rejecting = [row for row in rows if row.get("bootstrap_diagnostic")]
    reproduced = lambda row: row["outcomes"].get("C0") == ["rejected", *row["bootstrap_diagnostic"]]  # noqa: E731
    wrong = [row for row in rejecting if row["outcomes"].get("C0", [None])[0] == "rejected" and row["outcomes"]["C0"][1] != "XAX.DRIVER.VERIFY"
             and not reproduced(row)]
    inexact = [row for row in rejecting if not reproduced(row)]
    exact = exact and not wrong
    both = {row["kind"] for row in rows} >= {"positive", "negative"}
    # C1's context (the record's context whose compiler is generation 1's artifact) ran the corpus.
    c1 = bool(generations) and generations[0]["artifact"] in facts["contexts"].values()
    b3 = b2 and c1 and agree and exact and both
    # A fixed point: the first generation whose artifact is its producer, every later one equal to it.
    fixed = next((k for k, item in enumerate(generations) if item["artifact"] == item["producer"]), None)
    b4 = b2 and fixed is not None and all(item["artifact"] == generations[fixed]["artifact"] for item in generations[fixed:])
    b1 = b2 and c1 and not full["rejection_exactness_gaps"] and not inexact
    interpreters = [facts["seed"][1] if facts["seed"] else "1", *(item["interpreter"] for item in generations)]
    b5 = (b2 and not full["required_paths_outside_xax"] and all(flag == "0" for flag in interpreters)
          and not any(full["executables_have_interpreter"].values()))
    # W2 (ADR-361), ADR-433 (1): C1 replayed every ledger transaction (the V2 run's replay line), and every context
    # made the structural probe's expected store (the frozen corpus's probe case).
    replay = facts["replay"] or []
    replayed = (len(replay) >= 5 and replay[0] == "0" and replay[1] == "replayed" and replay[2] == replay[4] and replay[2].isdigit()
                and int(replay[2]) >= 1)
    first = [name for name, compiler in facts["contexts"].items() if generations and compiler == generations[0]["artifact"]]
    probed = c1 and probe_digest is not None and all(contexts.get(name, {}).get(probe_index, [None])[:2] == ["0", probe_digest] for name in first)
    b6 = b5 and replayed and probed and not full["ordinary_evolution"]
    blockers = {
        "B0": None if b0 else "the seed did not produce a running compiler",
        "B1": None if b1 else "; ".join([*full["rejection_exactness_gaps"],
                                         *([f"{len(inexact)} of {len(rejecting)} corpus verification rejections are not the bootstrap's exact diagnostic"]
                                           if inexact else [])]) or "no recursive build",
        "B2": None if b2 else "the generations do not chain through resolve and build",
        "B3": None if b3 else "the generations or the bootstrap disagree on the corpus",
        "B4": None if b4 else "the generations do not reach a fixed point",
        "B5": None if b5 else "; ".join(full["required_paths_outside_xax"]) or "a required path is not XAX-hosted",
        "B6": None if b6 else full["ordinary_evolution"] or ("B5 does not hold" if not b5 else
                                                             "the self-built compiler did not replay a structural evolution ledger to the committed stores"),
    }
    return {"scope": full["scope"]["compiler"], "outside_scope": full["scope"]["outside_scope"],
            **{f"B{n}": level for n, level in enumerate((b0, b1, b2, b3, b4, b5, b6))},
            "blockers": {level: reason for level, reason in blockers.items() if reason},
            "seed_requires_python": seed_requires_python(full, seed, record)}
