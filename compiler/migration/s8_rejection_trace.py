"""S8 (ADR-248): which verifier rejections the Python bootstrap still decides while every XAX program is live.

Run as a pytest plugin over the suite::

    S8_TRACE_OUT=/tmp/s8 PYTHONPATH=src:tests:migration python -m pytest -p s8_rejection_trace tests
    python migration/s8_rejection_trace.py /tmp/s8

Every ``fail()`` under ``verify_store`` or ``StoreReader`` is recorded when the store decoder, the typing program,
and the store verifier are all loaded and no test has forced a bootstrap path (``*_BUILDING`` flags, a replaced
``_xax_verify_store``).  Raises of diagnostics XAX decided (its rejection records) are excluded by site.  S8 is
complete when the report is empty and every reachable ``fail()`` site has a vector XAX decides.
"""

from __future__ import annotations

import atexit
import collections
import os
import sys

OUT = os.environ.get("S8_TRACE_OUT", "/tmp/s8_trace")
_HITS: collections.Counter = collections.Counter()
_TESTS: dict = {}  # site -> a few test node ids that reached it
_CURRENT = [""]
_GENERIC = ("take", "uleb", "boolean", "end", "byte_string", "zigzag", "<genexpr>", "_reference", "_type_reference", "decode_bits_width",
            "decode_float_format", "_read_value")
# Lines that raise a diagnostic an XAX program decided (its rejection records), by function.
XAX_RAISES = {"_parse_graph_uncached", "verify_object", "_verify_type"}


def _live(xax_compiler) -> bool:
    verify = sys.modules.get("xax_selfhost_verify")
    return (xax_compiler._NATIVE_TYPING is not None and verify is not None and bool(verify._NATIVE) and verify._NATIVE[0] is not None
            and getattr(xax_compiler, "_NATIVE_DECODER", None) is not None
            and not any(getattr(xax_compiler, flag, False) for flag in ("_DECODER_BUILDING", "_TYPING_BUILDING", "_CFG_BUILDING", "_GRAPH_DECODER_BUILDING"))
            and getattr(xax_compiler._xax_verify_store, "__name__", "") == "_xax_verify_store" and not verify._BUILDING)


def _install() -> None:
    import xax_compiler

    original = xax_compiler.fail

    def traced(code, entity, rule, *rest, **kw):
        frame = sys._getframe(1)
        under = False
        walk = frame
        while walk is not None:
            if walk.f_code.co_name in ("verify_store", "__init__") and walk.f_code.co_filename.endswith("xax_compiler.py"):
                under = True
                break
            walk = walk.f_back
        if under and _live(xax_compiler) and not getattr(xax_compiler, "_XAX_RAISING", False):
            name = frame.f_code.co_name
            if name in _GENERIC:
                caller = frame.f_back
                while caller is not None and caller.f_code.co_name in _GENERIC:
                    caller = caller.f_back
                name = f"{name}<{caller.f_code.co_name if caller else '?'}:{caller.f_lineno if caller else 0}>"
            key = (os.path.basename(frame.f_code.co_filename), name, frame.f_lineno, rule)
            _HITS[key] += 1
            tests = _TESTS.setdefault(key, [])
            if len(tests) < 3 and _CURRENT[0] not in tests:
                tests.append(_CURRENT[0])
        return original(code, entity, rule, *rest, **kw)

    xax_compiler.fail = traced
    for name, module in list(sys.modules.items()):
        if name.startswith("xax_") and getattr(module, "fail", None) is original:
            module.fail = traced


def pytest_configure(config):  # noqa: ARG001 - pytest hook
    _install()


def pytest_runtest_setup(item):  # pytest hook: the test whose rejections are traced
    _CURRENT[0] = item.nodeid


@atexit.register
def _dump() -> None:
    if _HITS:
        with open(f"{OUT}.{os.getpid()}", "w") as handle:
            for (path, function, line, rule), count in _HITS.items():
                handle.write(f"{path}\t{function}\t{line}\t{rule}\t{count}\n")
        with open(f"{OUT}.tests.{os.getpid()}", "w") as handle:
            for (path, function, line, rule), tests in _TESTS.items():
                handle.write(f"{path}:{line}\t{rule}\t{' '.join(tests)}\n")


def report(prefix: str) -> list[tuple[str, str, int, str, int]]:
    """The merged trace: ``(file, function, line, rule, count)`` sorted by file and line."""
    import glob

    merged: collections.Counter = collections.Counter()
    for path in glob.glob(f"{prefix}.*"):
        if ".tests." in path:
            continue
        for line in open(path):
            file, function, number, rule, count = line.rstrip("\n").split("\t")
            merged[(file, function, int(number), rule)] += int(count)
    return sorted(((*key, count) for key, count in merged.items()), key=lambda row: (row[0], row[2]))


if __name__ == "__main__":
    rows = report(sys.argv[1] if len(sys.argv) > 1 else OUT)
    for file, function, number, rule, count in rows:
        print(f"{file}:{number}\t{function}\t{rule}\t{count}")
    print(f"{len(rows)} bootstrap-decided rejection sites")
