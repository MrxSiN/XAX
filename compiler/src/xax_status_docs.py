"""Current-status summaries generated from `XAX_REPLACEMENT_MATRIX.json` (tooling; not XAX semantics).

Documents that repeat replacement levels carry a marked block, rewritten here
from the matrix, so the matrix stays the single source of those facts:

    <!-- xax-status:levels -->...<!-- /xax-status:levels -->     one-line summary
    <!-- xax-status:targets -->...<!-- /xax-status:targets -->   per-platform table
    <!-- xax-status:bootstrap -->...<!-- /xax-status:bootstrap --> B0-B6 status, derived from the executed records

``python -m xax_status_docs`` checks every block; ``--write`` regenerates them.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from xax_replacement import LEVELS, load

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "XAX_REPLACEMENT_MATRIX.json"
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


def linux_text(linux: dict | None) -> str:
    """The Linux x86-64 production compiler's derived levels (ADR-285), or nothing before its evidence exists."""
    if linux is None:
        return ""
    held = [f"B{n}" for n in range(7) if linux[f"B{n}"]]
    missing = [f"B{n}" for n in range(7) if not linux[f"B{n}"]]
    return (f"Linux x86-64 production compiler (`benchmarks/full_selfhost_evidence.json`): {', '.join(held) or 'none'} hold, "
            f"{', '.join(missing) or 'none'} do not; its seed requires Python: {'yes' if linux['seed_requires_python'] else 'no'}; ")


def bootstrap_summary(status: dict) -> str:
    """One line from ``bootstrap_status`` (``xax_selfhost``), computed from the executed records: no hand-written B level
    (W3, ADR-362: until then it was read from the M14 evidence)."""
    full, seed = status["full_production_compiler"], status["bootstrap_seed"]
    established = [f"B{n}" for n in range(7) if full[f"B{n}"]]
    full_text = f"{', '.join(established)} established" if established else "none of B0-B6 is established"
    records = " and ".join(f"`{item}`" for item in status["records"])
    return (
        f"Bootstrap status (derived by `{status['derivation_source']}` from {records}): "
        f"whole production compiler: {full_text} ({full['blocker']}); "
        f"{linux_text(status.get('linux_x86_64_production_compiler'))}"
        "S-step component fixed points are not B milestones (`XAX_SPEC.md` §16.5). "
        f"Bootstrap seed: {seed['kind']} `{seed['path']}`, {seed['bytes']:,} bytes, requires Python: {'yes' if seed['requires_python'] else 'no'}."
    )


GENERATORS = {
    "levels": lambda repo: levels_summary(load(repo / MATRIX.name)),
    "targets": lambda repo: targets_table(load(repo / MATRIX.name)),
    "bootstrap": lambda repo: bootstrap_summary(__import__("xax_selfhost").bootstrap_status()),
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
