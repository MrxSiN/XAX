"""RFC section 4, phase 3: the native evidence program (``bootstrap/evidence``) against the reference evaluator.

On Linux x86-64 with the pinned seed: the committed program is the seed's ``xaxc edit`` of its batch; ``sha`` equals
hashlib; and ``levels`` agrees with the reference evaluator ``xax_selfhost.linux_x86_64_status`` on the committed
records and on mutated copies of them. ADR-433 (3): the V1 record holds only C0's corpus outcomes, so each case is
written as a V2 record, corpus and snapshot list (``_v2``) whose generation, fixed point and replay lines are the latest
validated release's and whose context C0 (with its ten repeats) is the V1 record's C0. A mutation changes a fact of
the V1 record, of the seed record, or of the written V2 record; both evaluators read the same files.
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


def _v2(full: dict, seed: dict, release: str) -> tuple[str, str, str, bool]:
    """The V2 record, corpus and snapshot list holding ``full``'s and ``seed``'s facts, with the generation, fixed point
    and replay lines of the V2 record ``release`` (ADR-433 (3): V1 no longer runs generations), and whether the seed
    record names the pinned seed."""
    from xax_selfhost_seed import pin

    kept = [line for line in release.splitlines() if line.split(" ", 1)[0] in ("generation", "fixedpoint")]
    replay = next(line for line in release.splitlines() if line.startswith("replay "))
    lines = ["xax-full-selfhost-evidence-v2", "ledger -", "corpus -", f"seed {full['seed']['sha256']} {int(full['executables_have_interpreter']['C0'])}",
             f"request {full['compiler']['request_store_sha256']}", *kept]
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
    corpus.append(f"positive edit image:{PROBE} 0 0 0 edit: a structural probe (B6)")

    def fields(row):
        outcome = row["outcomes"].get("C0")
        if outcome is None:
            return "- - - - -"
        if outcome[0] == "rejected":
            return f"1 {outcome[3] if row['command'] == 'verify' else '-'} - {outcome[1]} {outcome[2]}"
        digests = [item or "-" for item in outcome[1:3]] + ["-"] * (3 - len(outcome))
        return f"{STATUS.get(outcome[0], 9)} {digests[0]} {digests[1]} - -"

    lines.append(f"context C0 {full['seed']['sha256']}")
    lines += [f"outcome C0 {i} {fields(row)}" for i, row in enumerate(rows) if row["outcomes"].get("C0") is not None]
    lines.append(f"outcome C0 {len(rows)} 0 {PROBE} - - -")
    lines += [f"repeat C0-r {i} {fields(row)}" for i, row in enumerate(rows[:10]) if row["outcomes"].get("C0") is not None]
    lines += [replay, "end"]
    snapshots = f"{full['compiler']['request_store_sha256']} {full['references']['python_resolver_snapshot_sha256']}\n"
    return "\n".join(lines) + "\n", "\n".join(corpus) + "\n", snapshots, seed["seed"]["sha256"] == pin()[0]


def _swap(record: str, prefix: str, replace) -> str:
    """``record`` with ``replace(words)`` (a list of words) in place of the one line starting with ``prefix``."""
    lines = record.splitlines()
    (index,) = [k for k, line in enumerate(lines) if line.startswith(prefix)]
    lines[index] = " ".join(replace(lines[index].split()))
    return "\n".join(lines) + "\n"


def _mutations(full: dict, seed: dict):
    """``(name, full, seed, record edit)``: the committed records, then one changed fact each, in the V1 record, the
    seed record or the V2 record written from them."""
    yield "committed", full, seed, None

    def changed(name, edit, which="full"):
        records = {"full": copy.deepcopy(full), "seed": copy.deepcopy(seed)}
        if which == "record":
            return name, records["full"], records["seed"], edit
        edit(records[which])
        return name, records["full"], records["seed"], None

    def word(prefix, k, value):
        return lambda record: _swap(record, prefix, lambda words: [*words[:k], value, *words[k + 1:]])

    rows = full["corpus"]
    image = next(i for i, row in enumerate(rows) if row["reference"] and row["reference"][0] == "image")
    diagnostic = next(i for i, row in enumerate(rows) if row.get("bootstrap_diagnostic"))
    rejected = next(i for i, row in enumerate(rows) if row["reference"] and row["reference"][0] == "rejected")
    yield changed("generation 1 resolve failed", word("generation 1 ", 3, "3"), "record")
    yield changed("generation 1 artifact differs", word("generation 1 ", 6, "cd" * 32), "record")
    yield changed("generation 1 snapshot differs", word("generation 1 ", 4, "-"), "record")
    yield changed("generation 1 has an interpreter", word("generation 1 ", 8, "1"), "record")
    yield changed("a repeat differs", word("repeat C0-r 0 ", 3, "3"), "record")
    yield changed("the replay failed", word("replay ", 1, "1"), "record")
    yield changed("the probe differs", word(f"outcome C0 {len(rows)} ", 4, "ef" * 32), "record")
    yield changed("C0 image outcome differs", lambda r: r["corpus"][image]["outcomes"]["C0"].__setitem__(1, "ef" * 32))
    yield changed("C0 diagnostic differs", lambda r: r["corpus"][diagnostic]["outcomes"]["C0"].__setitem__(3, "ef" * 32))
    yield changed("C0 rejection rule differs", lambda r: r["corpus"][rejected]["outcomes"]["C0"].__setitem__(2, "OTHER-RULE"))
    yield changed("C0 outcome missing", lambda r: r["corpus"][image]["outcomes"].pop("C0"))
    yield changed("no negative case", lambda r: [row.update(kind="positive") for row in r["corpus"]])
    yield changed("C0 has an interpreter", lambda r: r["executables_have_interpreter"].update(C0=True))
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

    def run_tool(self, *arguments) -> bytes:
        """The tool's text: it writes it to a file, its last argument (README.md)."""
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            subprocess.run([str(self.tool), *map(str, arguments), str(out)], capture_output=True, check=True)
            return out.read_bytes()

    def test_the_store_is_its_batch(self):
        """evidence.batch, then driver.batch (2026-11-25: the general driver's entry and host functions); its Windows
        store is generate.sh's output."""
        with tempfile.TemporaryDirectory() as directory:
            first, out, hosted = Path(directory) / "first.xax", Path(directory) / "tool.xax", Path(directory) / "hosted.xax"
            subprocess.run([str(SEED), "edit", str(BOOTSTRAP / "evolution" / "ledger-tool" / "seed.xax"), str(EVIDENCE / "evidence.batch"), str(first)],
                           check=True)
            subprocess.run([str(SEED), "edit", str(first), str(EVIDENCE / "driver.batch"), str(out)], check=True)
            self.assertEqual(out.read_bytes(), (EVIDENCE / "xax_evidence.xax").read_bytes())
            subprocess.run(["sh", str(BOOTSTRAP / "windows" / "generator" / "generate.sh"), str(out), str(hosted)], check=True, capture_output=True, timeout=1800)
            self.assertEqual(hosted.read_bytes(), (EVIDENCE / "xax_evidence_windows.xax").read_bytes())

    def test_sha_is_sha256(self):
        for path in (EVIDENCE / "CORPUS", SEED, BOOTSTRAP / "xax_compiler_driver_general.xax"):
            made = self.run_tool("sha", path)
            self.assertEqual(made, hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
        missing = self.run_tool("sha", EVIDENCE / "missing")
        self.assertEqual(missing, b"-\n")

    def test_the_corpus_inputs_are_named_by_their_digests(self):
        for path in (EVIDENCE / "inputs").iterdir():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), path.name)

    def test_levels_agree_with_the_reference(self):
        from xax_selfhost import linux_x86_64_status, released_record

        full = json.loads((BENCHMARKS / "full_selfhost_evidence.json").read_text(encoding="utf-8"))
        seed = json.loads((BENCHMARKS / "python_free_seed_evidence.json").read_text(encoding="utf-8"))
        release = released_record()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            other = work / "other-seed"
            other.write_bytes(b"not the pinned seed")
            for name, mutated_full, mutated_seed, edit in _mutations(full, seed):
                with self.subTest(name):
                    record, corpus, snapshots, pinned = _v2(mutated_full, mutated_seed, release)
                    record = record if edit is None else edit(record)
                    for file, text in (("record", record), ("CORPUS", corpus), ("SNAPSHOTS", snapshots)):
                        (work / file).write_text(text, encoding="ascii")
                    made = self.run_tool("levels", work / "record", work / "CORPUS", work / "SNAPSHOTS", SEED if pinned else other).decode()
                    native = dict(line.split(" ") for line in made.splitlines())
                    reference = linux_x86_64_status(mutated_full, mutated_seed, record, corpus)
                    self.assertEqual({level: native[level] == "1" for level in (f"B{n}" for n in range(7))},
                                     {level: reference[level] for level in (f"B{n}" for n in range(7))})
                    self.assertEqual(native["python"] == "1", reference["seed_requires_python"])
                    if name == "committed":
                        self.assertTrue(all(reference[f"B{n}"] for n in range(7)))


if __name__ == "__main__":
    unittest.main()
