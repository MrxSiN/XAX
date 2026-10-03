"""OI-32 evidence for the C header importer (ADR-127): whole-header coverage, refusals, latency, size.

Imports every function a header declares, so the refusal reasons measure
the importer's exact subset against real APIs.  Hand-built declarations
reproduced byte-for-byte are listed separately; a mismatch would fail.
"""

from __future__ import annotations

import collections
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from xax_c_import import _clang_ast, import_c_functions

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "c_import_evidence.json"
HEADERS = (
    ("zlib.h", b"libz.so.1", ("/usr/include/zlib.h",)),
    ("string.h", b"libc.so.6", ("/usr/include/string.h",)),
    ("stdio.h", b"libc.so.6", ("/usr/include/stdio.h",)),
    ("math.h", b"libm.so.6", ("/usr/include/math.h",)),
)
FLAGS = ("-D_GNU_SOURCE",)


def run() -> dict:
    rows = {}
    for label, library, headers in HEADERS:
        declared = sorted({node["name"] for node in _clang_ast([Path(item) for item in headers], "clang", FLAGS) if node.get("kind") == "FunctionDecl" and not node["name"].startswith("__")})
        start = time.perf_counter()
        imported = import_c_functions(headers, library, declared, flags=FLAGS)
        seconds = time.perf_counter() - start
        reasons = collections.Counter(reason.split(" (")[0].split(":")[0].split(" '")[0] for reason in imported.report["refused"].values())
        rows[label] = {
            "declared_functions": len(declared),
            "imported": len(imported.functions),
            "refused": len(imported.report["refused"]),
            "refusal_reasons": dict(sorted(reasons.items())),
            "import_seconds": round(seconds, 3),
            "declaration_bytes": sum(len(item.declaration.body) for item in imported.functions),
            "package_objects": len(imported.objects),
            "report_sha256": hashlib.sha256(json.dumps(imported.report, sort_keys=True).encode()).hexdigest(),
        }
    return {
        "format": "xax-c-import-evidence-v1",
        "evidence_label": "MEASURED (coverage, latency, size); EXECUTED and byte-identical declarations in test_xax_c_import.py",
        "clang": subprocess.run(["clang", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
        "headers": rows,
        "byte_identical_to_hand_built": ["libz crc32", "libm ldexp", "libm pow (pure)", "libm sqrtf (pure)", "libc strlen (aapcs64-linux-c)"],
    }


if __name__ == "__main__":
    text = json.dumps(run(), indent=2, sort_keys=True) + "\n"
    if "--write" in sys.argv:
        EVIDENCE.write_text(text)
    sys.stdout.write(text)
