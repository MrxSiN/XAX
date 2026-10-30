"""Self-hosting step S15a (ADR-286): the Linux x86-64 production compiler's seed is an XAX-built compiler, not Python.

``bootstrap/seed/`` holds:

* ``xaxc-linux-x86_64``: the production compiler (the general driver) as its own build made it, a static ELF64
  executable with no interpreter, equal to the bootstrap's compile of the same store (ADR-285).  Pinned below.
* ``xax_compiler_request.xax``: the compiler's canonical build request store (``xax_selfhost_compiler.compiler_request``
  of the committed driver store), the input the seed resolves and builds.
* ``selfbuild.sh``: the seed resolves and builds the request into the next compiler, and that compiler does it again;
  only ``sh``, ``dirname``, ``mkdir``, ``chmod``, and ``cmp`` run besides the compilers.

The seed is replaced only by ``rotate_seed``: the current seed builds the current request store, and the pins are then
updated by a reviewed change.  Nothing here builds a compiler in Python.
"""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path

from xax_native import bootstrap_dir

SEED_DIRECTORY = bootstrap_dir() / "seed"
SEED_PATH = SEED_DIRECTORY / "xaxc-linux-x86_64"
REQUEST_PATH = SEED_DIRECTORY / "xax_compiler_request.xax"
SELFBUILD_PATH = SEED_DIRECTORY / "selfbuild.sh"
SEED_SHA256 = "1ea22576962c17eade1039b59ef8136c164a1e6117fb78d9f237194f114a73c6"
SEED_SIZE = 32016091
SELFBUILD_TOOLS = ("sh", "dirname", "mkdir", "chmod", "cmp")


def write_request_store() -> bytes:
    """Rewrite the committed request store from the committed driver store (after the driver store changes)."""
    from xax_selfhost_compiler import compiler_request

    data = compiler_request()[0].data
    REQUEST_PATH.write_bytes(data)
    return data


def rotate_seed() -> tuple[str, int]:
    """Replace the seed with the compiler the current seed builds from the current request store; the new pins
    (``SEED_SHA256``, ``SEED_SIZE``) are then written by hand, in a reviewed change."""
    with tempfile.TemporaryDirectory(prefix="xax-seed-") as directory:
        snapshot, compiler, provenance = (Path(directory) / name for name in ("snapshot.xax", "xaxc", "provenance"))
        for arguments in (("resolve", REQUEST_PATH, snapshot), ("build", snapshot, compiler, provenance)):
            if subprocess.run([str(SEED_PATH), *(str(item) for item in arguments)], check=False).returncode != 0:
                raise RuntimeError(f"the seed's {arguments[0]} failed")
        data = compiler.read_bytes()
    SEED_PATH.write_bytes(data)
    SEED_PATH.chmod(0o755)
    return hashlib.sha256(data).hexdigest(), len(data)


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["write-request"]:
        write_request_store()
    elif sys.argv[1:] == ["rotate-seed"]:
        print(*rotate_seed())
    else:
        raise SystemExit("usage: python -m xax_selfhost_seed write-request | rotate-seed")
