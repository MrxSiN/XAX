"""Current-status summaries generated from `XAX_REPLACEMENT_MATRIX.json` (tooling; not XAX semantics).

Documents that repeat replacement levels carry a marked block, rewritten here
from the matrix, so the matrix stays the single source of those facts:

    <!-- xax-status:levels -->...<!-- /xax-status:levels -->

``python -m xax_status_docs`` checks every block; ``--write`` regenerates them.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from xax_replacement import LEVELS, load

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "XAX_REPLACEMENT_MATRIX.json"
BLOCK = re.compile(r"(<!-- xax-status:levels -->)(.*?)(<!-- /xax-status:levels -->)", re.S)


def levels_summary(matrix: dict) -> str:
    """One line grouping platform ids by claimed level, highest first."""
    groups: dict[str, list[str]] = {}
    for row in matrix["platforms"]:
        groups.setdefault(row["level"], []).append(row["id"])
    parts = [f"{level}: {', '.join(sorted(groups[level]))}" for level in reversed(LEVELS[1:]) if level in groups]
    if "NONE" in groups:
        parts.append(f"no level yet: {', '.join(sorted(groups['NONE']))}")
    return "Replacement levels (generated from `XAX_REPLACEMENT_MATRIX.json`): " + "; ".join(parts) + "."


def documents(repo: Path = REPO) -> list[Path]:
    """Every Markdown file in the repository that carries a levels block."""
    return sorted(path for path in repo.rglob("*.md") if ".git" not in path.parts and BLOCK.search(path.read_text(encoding="utf-8")))


def sync(write: bool, repo: Path = REPO) -> list[Path]:
    """Return the documents whose blocks differ from the matrix; rewrite them when ``write``."""
    summary = levels_summary(load(repo / MATRIX.name))
    stale = []
    for path in documents(repo):
        text = path.read_text(encoding="utf-8")
        updated = BLOCK.sub(lambda match: match.group(1) + summary + match.group(3), text)
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
