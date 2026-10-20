"""Recompute the XAX toolchain fingerprint the XAX-MCP compatibility matrix records.

    python compiler/integration/mcp/fingerprint.py <XAX checkout>

The fingerprint is sha256 over (file name, sha256(content)) of every ``xax_*.py`` module in ``compiler/src`` (plus
``blake3.py``) and every ``compiler/bootstrap/*.xax`` store, sorted by (suffix, name).  Python modules are hashed with
LF line endings so a CRLF checkout does not change the value; ``.xax`` stores are hashed as they are.  This is the
definition the retired Python adapter used, and it reproduces the values recorded in ``docs/COMPATIBILITY.md``.
"""
from __future__ import annotations

import hashlib
import pathlib
import sys


def toolchain_files(root: pathlib.Path) -> list[pathlib.Path]:
    src = root / "compiler" / "src"
    bootstrap = root / "compiler" / "bootstrap"
    files = [p for p in src.iterdir() if p.suffix == ".py" and (p.name.startswith("xax_") or p.name == "blake3.py")]
    files += sorted(bootstrap.glob("*.xax"))
    return sorted(files, key=lambda p: (p.suffix, p.name))


def fingerprint(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in toolchain_files(root):
        content = path.read_bytes()
        if path.suffix == ".py":
            content = content.replace(b"\r\n", b"\n")
        digest.update(path.name.encode() + b"\0" + hashlib.sha256(content).digest())
    return digest.hexdigest()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    root = pathlib.Path(argv[1]).resolve()
    files = toolchain_files(root)
    print(fingerprint(root))
    print(f"{len(files)} files ({root})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
