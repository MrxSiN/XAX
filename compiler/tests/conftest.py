"""Suite scheduling (ADR-433): one xdist group for the tests that parse the driver-sized stores in Python, and no
class-level state kept after its class has run.

A test file in ``DRIVER_SIZED`` reads a 30-74 MB store (the general driver, its request, ``xax_android.xax``,
``bbc.xax``) into the Python reference's ``StoreReader``; a worker then holds several GB. With ``-n N`` the default
``load`` distribution becomes ``loadgroup``, so those files run on one worker, one after another, and the others
spread over the rest. ``setUpClass`` results (readers, corpora, images) stay referenced by their class object for the
whole session; they are dropped once the class's last test has run.
"""

from __future__ import annotations

import gc
from pathlib import Path

import pytest

DRIVER_SIZED = frozenset({
    "test_bbc_windows_host_port.py",
    "test_libxposed_lifecycle.py",
    "test_python_free_seed.py",
    "test_request_tool.py",
    "test_rotate_tool.py",
    "test_store_regeneration.py",
    "test_windows_generator.py",
    "test_xax_selfhost_compiler_fixed_point.py",
    "test_xax_selfhost_evolution.py",
})


def driver_sized(path: Path) -> bool:
    return path.name in DRIVER_SIZED or path.name.startswith("test_xax_selfhost_android")


def pytest_configure(config):
    if getattr(config.option, "dist", None) == "load":
        config.option.dist = "loadgroup"


def pytest_collection_modifyitems(items):
    for item in items:
        if driver_sized(item.path):
            item.add_marker(pytest.mark.xdist_group("driver-sized"))


_CLASS_STATE: dict[type, frozenset[str]] = {}


def pytest_runtest_setup(item):
    if item.cls is not None:
        _CLASS_STATE.setdefault(item.cls, frozenset(vars(item.cls)))


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item, nextitem):
    cls = item.cls
    if cls is None or (nextitem is not None and nextitem.cls is cls):
        return
    for name in set(vars(cls)) - _CLASS_STATE.pop(cls, frozenset(vars(cls))):
        delattr(cls, name)
    gc.collect()
