"""RFC section 4, phase 3: the native evidence program (``bootstrap/evidence``) against the reference evaluator.

On Linux x86-64 with the pinned seed: the committed program is the seed's ``xaxc edit`` of its batch; ``sha`` equals
hashlib; and ``levels`` agrees with the reference evaluator ``xax_selfhost.linux_x86_64_status`` on the committed V1
record and on mutated copies of it. Each V1 record is written as the V2 record, corpus and snapshot list that hold the
same facts (``_v2``): C1's outcomes are the context's, and C0's, C2's and C3's are its repeats.

V2 defines the levels for records the runner writes (``bootstrap/evidence/README.md``), so the mutations change facts
both forms hold: statuses, digests, interpreters, outcomes, the replay and the probe. Two definitions differ on
purpose and are not mutated here: B0 reads the first generation's resolve too, and B4 holds for a fixed point that is
not the seed (RFC section 4).
"""

from __future__ import annotations

import copy
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap"
EVIDENCE = BOOTSTRAP / "evidence"
SEED = BOOTSTRAP / "seed" / "xaxc-linux-x86_64"
BENCHMARKS = BOOTSTRAP.parent / "benchmarks"
LINUX_X86_64 = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
STATUS = {"image": 0, "rejected": 1, "declined": 2, "failed": 3}
PROBE = "ab" * 32


def _v2(full: dict, seed: dict) -> tuple[str, str, str, bool]:
    """The V2 record, corpus and snapshot list holding ``full``'s and ``seed``'s facts, and whether the seed record
    names the pinned seed."""
    from xax_selfhost_seed import SEED_SHA256

    interpreters = full["executables_have_interpreter"]
    lines = ["xax-full-selfhost-evidence-v2", "ledger -", "corpus -", f"seed {full['seed']['sha256']} {int(interpreters['C0'])}",
             f"request {full['compiler']['request_store_sha256']}"]
    for n, item in enumerate(full["generations"], 1):
        snapshot = item["snapshot_sha256"] if item["snapshot_equals_python_resolver"] else "-"
        lines.append(f"generation {n} {item['producer_sha256']} {STATUS.get(item['resolve']['status'], 9)} {snapshot} "
                     f"{STATUS.get(item['build']['status'], 9)} {item['artifact_sha256'] or '-'} {item['provenance_sha256'] or '-'} "
                     f"{int(interpreters[f'C{n}'])}")
    lines.append("fixedpoint -")
    built = (seed["selfbuild_status"] == 0 and not seed["seed"]["has_interpreter"] and seed["environment"]["variables"] == ["PATH"]
             and seed["environment"]["python_on_path"] is None and seed["request_store_sha256"] == full["compiler"]["request_store_sha256"])
    for k, item in enumerate(seed["generations"][:2], 1):
        lines.append(f"empty {k} {0 if built else 1} 0 {item['sha256']}")
    corpus = ["# the V1 record's corpus"]
    rows = full["corpus"]
    for row in rows:
        diagnostic, reference = row.get("bootstrap_diagnostic"), row["reference"]
        expect = (f"diag:{diagnostic[0]}:{diagnostic[1]}:{diagnostic[2]}" if diagnostic else "-" if reference is None
                  else "image:" + ":".join(reference[1:]) if reference[0] == "image" else f"rejected:{reference[1]}:{reference[2]}")
        corpus.append(f"{row['kind']} {row['command']} {expect} 0 0 0 {row['case']}")
    corpus.append(f"positive edit image:{PROBE} 0 0 0 the probe")
    evolution = full["evolution"] or {}
    probe = evolution.get("probe") or {}
    probed = probe.get("edit", {}).get("status") == "image" and probe.get("equals_reference") is True and probe.get("verify") == "image"

    def fields(row, generation):
        outcome = row["outcomes"].get(generation)
        if outcome is None:
            return "- - - - -"
        if outcome[0] == "rejected":
            return f"1 {outcome[3] if row['command'] == 'verify' else '-'} - {outcome[1]} {outcome[2]}"
        digests = [item or "-" for item in outcome[1:3]] + ["-"] * (3 - len(outcome))
        return f"{STATUS.get(outcome[0], 9)} {digests[0]} {digests[1]} - -"

    lines.append(f"context C1 {full['generations'][0]['artifact_sha256'] if full['generations'] else '-'}")
    lines += [f"outcome C1 {i} {fields(row, 'C1')}" for i, row in enumerate(rows)]
    lines.append(f"outcome C1 {len(rows)} {'0 ' + PROBE if probed else '- -'} - - -")
    for generation in (f"C{n}" for n in range(len(full["generations"]) + 1)):
        if generation != "C1":
            lines += [f"repeat C1-r {i} {fields(row, generation)}" for i, row in enumerate(rows)]
    transactions = evolution.get("transactions", ())
    replayed = (evolution.get("format") == "xax-evolution-replay-v2" and evolution.get("structural") is True
                and evolution.get("ledger_heads_equal_committed") is True and not full["ordinary_evolution"]
                and all(item.get("edit", {}).get("status") == "image" and item.get("equals_ledger") is True and item.get("verify") == "image"
                        for item in transactions))
    lines += [f"replay {0 if replayed else 1} replayed {len(transactions) if replayed else 0} of {len(transactions)}", "end"]
    snapshots = f"{full['compiler']['request_store_sha256']} {full['references']['python_resolver_snapshot_sha256']}\n"
    return "\n".join(lines) + "\n", "\n".join(corpus) + "\n", snapshots, seed["seed"]["sha256"] == SEED_SHA256


def _mutations(full: dict, seed: dict):
    """``(name, full, seed)``: the committed records, then one changed fact each."""
    yield "committed", full, seed

    def changed(name, edit, which="full"):
        records = {"full": copy.deepcopy(full), "seed": copy.deepcopy(seed)}
        edit(records[which])
        return name, records["full"], records["seed"]

    rows = full["corpus"]
    image = next(i for i, row in enumerate(rows) if row["reference"] and row["reference"][0] == "image")
    diagnostic = next(i for i, row in enumerate(rows) if row.get("bootstrap_diagnostic"))
    rejected = next(i for i, row in enumerate(rows) if row["reference"] and row["reference"][0] == "rejected")
    yield changed("generation 2 resolve failed", lambda r: r["generations"][1]["resolve"].update(status="failed"))
    yield changed("generation 3 artifact differs", lambda r: r["generations"][2].update(artifact_sha256="cd" * 32))
    yield changed("generation 1 snapshot differs", lambda r: r["generations"][0].update(snapshot_equals_python_resolver=False))
    yield changed("C1 image outcome differs", lambda r: r["corpus"][image]["outcomes"]["C1"].__setitem__(1, "ef" * 32))
    yield changed("C2 image outcome differs", lambda r: r["corpus"][image]["outcomes"]["C2"].__setitem__(1, "ef" * 32))
    yield changed("C1 diagnostic differs", lambda r: r["corpus"][diagnostic]["outcomes"]["C1"].__setitem__(3, "ef" * 32))
    yield changed("C1 rejection rule differs", lambda r: r["corpus"][rejected]["outcomes"]["C1"].__setitem__(2, "OTHER-RULE"))
    yield changed("C3 outcome missing", lambda r: r["corpus"][image]["outcomes"].pop("C3"))
    yield changed("no negative case", lambda r: [row.update(kind="positive") for row in r["corpus"]])
    yield changed("C2 has an interpreter", lambda r: r["executables_have_interpreter"].update(C2=True))
    yield changed("a replayed transaction differs", lambda r: r["evolution"]["transactions"][0].update(equals_ledger=False))
    yield changed("the probe differs", lambda r: r["evolution"]["probe"].update(equals_reference=False))
    yield changed("the seed rebuild failed", lambda r: r.update(selfbuild_status=1), "seed")
    yield changed("the seed has an interpreter", lambda r: r["seed"].update(has_interpreter=True), "seed")
    yield changed("the seed is not the pin", lambda r: r["seed"].update(sha256="12" * 32), "seed")


@unittest.skipUnless(LINUX_X86_64, "the pinned seed runs on Linux x86-64")
class EvidenceProgramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        work = Path(cls.directory.name)
        subprocess.run([str(SEED), "resolve", str(EVIDENCE / "xax_evidence.xax"), str(work / "tool.xax")], check=True)
        subprocess.run([str(SEED), "build", str(work / "tool.xax"), str(work / "xax_evidence"), str(work / "provenance")], check=True)
        (work / "xax_evidence").chmod(0o755)
        cls.tool = work / "xax_evidence"

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_the_store_is_its_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "tool.xax"
            subprocess.run([str(SEED), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"), str(EVIDENCE / "evidence.batch"), str(out)],
                           check=True)
            self.assertEqual(out.read_bytes(), (EVIDENCE / "xax_evidence.xax").read_bytes())

    def test_sha_is_sha256(self):
        for path in (EVIDENCE / "CORPUS", SEED, BOOTSTRAP / "xax_compiler_driver_general.xax"):
            made = subprocess.run([str(self.tool), "sha", str(path)], capture_output=True, check=True).stdout
            self.assertEqual(made, hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
        missing = subprocess.run([str(self.tool), "sha", str(EVIDENCE / "missing")], capture_output=True, check=True).stdout
        self.assertEqual(missing, b"-\n")

    def test_the_corpus_inputs_are_named_by_their_digests(self):
        for path in (EVIDENCE / "inputs").iterdir():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), path.name)

    def test_levels_agree_with_the_reference(self):
        from xax_selfhost import linux_x86_64_status

        full = json.loads((BENCHMARKS / "full_selfhost_evidence.json").read_text(encoding="utf-8"))
        seed = json.loads((BENCHMARKS / "python_free_seed_evidence.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            other = work / "other-seed"
            other.write_bytes(b"not the pinned seed")
            for name, mutated_full, mutated_seed in _mutations(full, seed):
                with self.subTest(name):
                    record, corpus, snapshots, pinned = _v2(mutated_full, mutated_seed)
                    for file, text in (("record", record), ("CORPUS", corpus), ("SNAPSHOTS", snapshots)):
                        (work / file).write_text(text, encoding="ascii")
                    made = subprocess.run([str(self.tool), "levels", str(work / "record"), str(work / "CORPUS"), str(work / "SNAPSHOTS"),
                                           str(SEED if pinned else other)], capture_output=True, check=True).stdout.decode()
                    native = dict(line.split(" ") for line in made.splitlines())
                    reference = linux_x86_64_status(mutated_full, mutated_seed)
                    self.assertEqual({level: native[level] == "1" for level in (f"B{n}" for n in range(7))},
                                     {level: reference[level] for level in (f"B{n}" for n in range(7))})
                    self.assertEqual(native["python"] == "1", reference["seed_requires_python"])
                    if name == "committed":
                        self.assertTrue(all(reference[f"B{n}"] for n in range(7)))


if __name__ == "__main__":
    unittest.main()
