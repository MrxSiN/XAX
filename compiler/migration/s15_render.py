"""S15b.1 (ADR-288): every object rejection the store verifier decides is rendered by it exactly as the bootstrap's.

Run as a pytest plugin::

    PYTHONPATH=src:tests:migration python -m pytest -s -p s15_render tests/...

After each XAX store verification the bank the verifier wrote (``xax_selfhost_render``) is decoded and compared with
the host's rendering of the same records (``object_diagnostic``, ``object_entity``, ``_xax_verify_store``'s store and
``OTHER_OBJECT`` rules).  A difference prints a ``RENDER-DIFF`` line; the run ends with ``S15-RENDER {...}``.
"""

from __future__ import annotations

import sys

from xax_selfhost_render import SITES, STATS, compare  # noqa: F401


def pytest_configure(config):  # noqa: ARG001 - pytest hook
    import xax_selfhost_verify as V

    original = V.NativeStoreVerifier.verify_with_rejections

    def checked(self, words, count, groups=()):
        result, rejections = original(self, words, count, groups)
        listed = getattr(checked, "listed", None)
        if result is not None and listed is not None and len(listed) == count:
            compare(listed, self._out, rejections)
        return result, rejections

    V.NativeStoreVerifier.verify_with_rejections = checked
    import xax_compiler

    verify = xax_compiler._xax_verify_store

    def remember(reader, objects):
        checked.listed = list(objects.values())
        try:
            return verify(reader, objects)
        finally:
            checked.listed = None

    xax_compiler._xax_verify_store = remember


def pytest_unconfigure(config):  # noqa: ARG001 - pytest hook
    sys.stderr.write(f"\nS15-RENDER {STATS}\n")
    from xax_selfhost_verify import OBJECT_SITES

    covered = {name.split(":")[0] for name in SITES}
    sys.stderr.write(f"S15-RENDER sites {dict(sorted(SITES.items()))}\nS15-RENDER uncovered {[name for name in OBJECT_SITES if name not in covered]}\n")
