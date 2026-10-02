"""Bootstrap-only generator for the committed M11 canonical semantic artifacts."""

from __future__ import annotations

from pathlib import Path

from xax_bootstrap import write_m11_artifacts


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    for path in write_m11_artifacts(here):
        print(path)
