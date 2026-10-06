"""STORE_REGENERATION: every committed self-hosting store is exactly what its builder makes, on every host.

Building a store is deterministic Python; only *running* the native image needs Linux x86-64 (NATIVE_EXECUTION,
tested elsewhere).  Each store is built twice in one process, so state leaking between builds (decline-site codes
numbered per process rather than per build) also fails here.
"""
import importlib

import pytest

import xax_compiler

BUILDERS = (
    ("xax_selfhost_cfg", "build_cfg_program"),
    ("xax_selfhost_graph", "build_graph_decoder_program"),
    ("xax_selfhost_riscv64", "build_encoder_program"),
    ("xax_selfhost_store", "build_decoder_program"),
    ("xax_selfhost_blake3", "build_hash_program"),
    ("xax_selfhost_typing", "build_typing_program"),
    ("xax_selfhost_verify", "build_verifier_program"),
    ("xax_selfhost_riscv64_backend", "build_backend_program"),
    ("xax_selfhost_x86_64_backend", "build_backend_program"),
)


def _build(module, builder) -> bytes:
    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True  # the helper graphs are verified by the bootstrap while they are built
    try:
        return getattr(module, builder)()[0].data
    finally:
        xax_compiler._TYPING_BUILDING = building


@pytest.mark.parametrize("name,builder", BUILDERS, ids=[name for name, _ in BUILDERS])
def test_committed_store_regenerates_byte_identically(name, builder):
    module = importlib.import_module(name)
    first, second = _build(module, builder), _build(module, builder)
    assert first == second, f"{name}: two builds in one process differ"
    assert first == module.STORE_PATH.read_bytes(), f"{name}: committed store is stale; regenerate it with its write_* function"
    xax_compiler.verify_store(xax_compiler.StoreReader(first))
