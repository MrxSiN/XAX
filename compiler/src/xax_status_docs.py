"""Current-status summaries generated from `XAX_REPLACEMENT_MATRIX.json` (tooling; not XAX semantics).

Documents that repeat replacement levels carry a marked block, rewritten here
from the matrix, so the matrix stays the single source of those facts:

    <!-- xax-status:levels -->...<!-- /xax-status:levels -->     one-line summary
    <!-- xax-status:targets -->...<!-- /xax-status:targets -->   per-platform table
    <!-- xax-status:bootstrap -->...<!-- /xax-status:bootstrap --> B0-B6 status, from the derived M14 evidence

``python -m xax_status_docs`` checks every block; ``--write`` regenerates them.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from xax_replacement import LEVELS, load

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "XAX_REPLACEMENT_MATRIX.json"
BOOTSTRAP_EVIDENCE = Path("compiler/bootstrap/m14_selfhost_evidence.json")
BLOCK = re.compile(r"(<!-- xax-status:(levels|targets|bootstrap) -->)(.*?)(<!-- /xax-status:\2 -->)", re.S)


def levels_summary(matrix: dict) -> str:
    """One line grouping platform ids by claimed level, highest first."""
    groups: dict[str, list[str]] = {}
    for row in matrix["platforms"]:
        groups.setdefault(row["level"], []).append(row["id"])
    parts = [f"{level}: {', '.join(sorted(groups[level]))}" for level in reversed(LEVELS[1:]) if level in groups]
    if "NONE" in groups:
        parts.append(f"no level yet: {', '.join(sorted(groups['NONE']))}")
    return "Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): " + "; ".join(parts) + "."


def targets_table(matrix: dict) -> str:
    """Markdown table of every platform row, highest level first, then matrix order."""
    rank = {level: index for index, level in enumerate(LEVELS)}
    rows = sorted(matrix["platforms"], key=lambda row: -rank[row["level"]])
    lines = [
        "",
        "| Target | Matrix id | Level | Status |",
        "|---|---|---|---|",
        *(f"| {row['name']} | `{row['id']}` | {'—' if row['level'] == 'NONE' else row['level']} | {row['summary']} |" for row in rows),
        "",
    ]
    return "\n".join(lines)


def bootstrap_summary(evidence: dict) -> str:
    """One line from ``bootstrap_status`` (``xax_selfhost``) as recorded in the M14 evidence: no hand-written B level."""
    status, seed = evidence["bootstrap_status"], evidence["seed_runtime"]
    full, wrapper = status["full_production_compiler"], status["m14_semantic_image_wrapper"]
    held = [level for level in ("B2", "B3", "B4", "B5", "B6") if wrapper[level]]
    missing = [level for level in ("B2", "B3", "B4", "B5", "B6") if not wrapper[level]]
    established = [f"B{n}" for n in range(7) if full[f"B{n}"]]
    full_text = f"{', '.join(established)} established" if established else "none of B0-B6 is established"
    return (
        f"Bootstrap status (generated from `{BOOTSTRAP_EVIDENCE.as_posix()}`, derived by `{status['derivation_source']}`): "
        f"whole production compiler: {full_text} ({full['blocker']}); "
        f"M14 semantic-image META wrapper: {', '.join(held) or 'none'} hold, {', '.join(missing) or 'none'} do not "
        f"(host-executed {', '.join(wrapper['host_substrate_operations']) or 'nothing'}). "
        "S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). "
        f"Bootstrap seed: {seed['seed_kind']}, {seed['size']:,} bytes, requires Python: {'yes' if seed['requires_python'] else 'no'}."
    )


GENERATORS = {
    "levels": lambda repo: levels_summary(load(repo / MATRIX.name)),
    "targets": lambda repo: targets_table(load(repo / MATRIX.name)),
    "bootstrap": lambda repo: bootstrap_summary(json.loads((repo / BOOTSTRAP_EVIDENCE).read_text(encoding="utf-8"))),
}


def documents(repo: Path = REPO) -> list[Path]:
    """Every Markdown file in the repository that carries a generated status block."""
    return sorted(path for path in repo.rglob("*.md") if ".git" not in path.parts and BLOCK.search(path.read_text(encoding="utf-8")))


def sync(write: bool, repo: Path = REPO) -> list[Path]:
    """Return the documents whose blocks differ from the matrix; rewrite them when ``write``."""
    generated: dict[str, str] = {}

    def block(match) -> str:
        kind = match.group(2)
        if kind not in generated:
            generated[kind] = GENERATORS[kind](repo)
        return match.group(1) + generated[kind] + match.group(4)

    stale = []
    for path in documents(repo):
        text = path.read_text(encoding="utf-8")
        updated = BLOCK.sub(block, text)
        if updated != text:
            stale.append(path)
            if write:
                path.write_text(updated, encoding="utf-8")
    return stale


def main(argv: list[str]) -> int:
    stale = sync("--write" in argv)
    for path in stale:
        print(f"{'updated' if '--write' in argv else 'stale'}: {path.relative_to(REPO)}")
    return 1 if stale and "--write" not in argv else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
