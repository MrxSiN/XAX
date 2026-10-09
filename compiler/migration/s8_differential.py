"""S8 (ADR-251): every rejection the live verifier raises is the bootstrap's own, diagnostic for diagnostic.

Run as a pytest plugin beside ``s8_rejection_trace``::

    PYTHONPATH=src:tests:migration python -m pytest -s -p s8_differential tests

Each ``verify_store`` that raises with the typing program live is verified again with it off (the bootstrap's
typing, facts, and memory checks) and the two diagnostics are compared field by field.  A difference prints a
``DIFF`` line; the run ends with ``S8-DIFFERENTIAL {'same': n, 'diff': m}`` (one line per worker).
"""

from __future__ import annotations

import sys

STATS = {"same": 0, "diff": 0}


def _key(diagnostic):
    if diagnostic is None:
        return None
    return diagnostic.code, diagnostic.entity, diagnostic.rule, repr(diagnostic.expected), repr(diagnostic.actual)


def pytest_configure(config):  # noqa: ARG001 - pytest hook
    import xax_compiler

    original = xax_compiler.verify_store

    def differential(reader, *args, **kwargs):
        try:
            return original(reader, *args, **kwargs)
        except xax_compiler.XaxError as live:
            if xax_compiler._NATIVE_TYPING is None or getattr(xax_compiler, "_TYPING_BUILDING", False):
                raise
            saved = xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED
            xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = None, True
            xax_compiler._PARSED_GRAPHS.clear()
            try:
                original(reader, *args, **kwargs)
                bootstrap = None
            except xax_compiler.XaxError as error:
                bootstrap = error.diagnostic
            finally:
                xax_compiler._NATIVE_TYPING, xax_compiler._TYPING_ATTEMPTED = saved
                xax_compiler._PARSED_GRAPHS.clear()
            if _key(live.diagnostic) == _key(bootstrap):
                STATS["same"] += 1
            else:
                STATS["diff"] += 1
                sys.stderr.write(f"\nDIFF live={_key(live.diagnostic)}\n     bootstrap={_key(bootstrap)}\n")
            raise

    xax_compiler.verify_store = differential
    for name, module in list(sys.modules.items()):
        if name.startswith(("xax_", "test_")) and getattr(module, "verify_store", None) is original:
            module.verify_store = differential


def pytest_collection_finish(session):  # noqa: ARG001 - pytest hook: test modules imported ``verify_store`` by name
    import xax_compiler

    for module in list(sys.modules.values()):
        bound = getattr(module, "verify_store", None)
        if bound is not None and bound is not xax_compiler.verify_store and getattr(bound, "__name__", "") == "verify_store":
            module.verify_store = xax_compiler.verify_store


def pytest_unconfigure(config):  # noqa: ARG001 - pytest hook
    sys.stderr.write(f"\nS8-DIFFERENTIAL {STATS}\n")
