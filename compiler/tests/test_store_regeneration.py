"""STORE_REGENERATION: every committed self-hosting store is exactly what its builder makes, on every host (the general
driver: its builder's baseline with the evolution ledger applied, S15d.2).

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
    ("xax_selfhost_writer", "build_writer_program"),
    ("xax_selfhost_driver", "build_driver_program"),
    ("xax_selfhost_blake3", "build_hash_program"),
    ("xax_selfhost_typing", "build_typing_program"),
    ("xax_selfhost_verify", "build_verifier_program"),
    ("xax_selfhost_riscv64_backend", "build_backend_program"),
    ("xax_selfhost_x86_64_backend", "build_backend_program"),
    ("xax_selfhost_x86_64_general", "build_general_program"),
    ("xax_selfhost_aarch64_general", "build_aarch64_program"),  # S15e.2 (ADR-315)
    ("xax_selfhost_jvm", "build_jvm_program"),  # S15e.5 (ADR-327)
    ("xax_selfhost_apk", "build_apk_program"),  # S15e.6a (ADR-340)
    ("xax_selfhost_apk_signing", "build_signer_program"),  # S15e.6b (ADR-341)
    ("xax_selfhost_android_resources", "build_resources_program"),  # S15e.6c (ADR-342)
    ("xax_selfhost_dex", "build_dex_program"),  # S15e.6d (ADR-343, ADR-344, ADR-345)
    ("xax_selfhost_android_elf", "build_android_elf_program"),  # S15e.6e (ADR-346)
    ("xax_selfhost_android_rules", "build_rules_program"),  # S15e.6f.1 (ADR-347)
    ("xax_selfhost_android_managed_rules", "build_managed_rules_program"),  # S15e.6f.2 (ADR-348)
    ("xax_selfhost_dex_writer", "build_dex_writer_program"),  # S15e.6g.1 (ADR-349)
    ("xax_selfhost_dex_jvm", "build_dex_jvm_program"),  # S15e.6g.2 (ADR-350)
    # S15d.2 (ADR-305): the general driver's committed store is its builder's baseline with the evolution ledger applied.
    ("xax_selfhost_evolution", "build_evolved_general", "GENERAL_STORE_PATH"),
)


def _build(module, builder) -> bytes:
    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True  # the helper graphs are verified by the bootstrap while they are built
    try:
        return getattr(module, builder)()[0].data
    finally:
        xax_compiler._TYPING_BUILDING = building


@pytest.mark.parametrize("name,builder,path", [(item + ("STORE_PATH",))[:3] for item in BUILDERS], ids=[item[1] if len(item) > 2 else item[0] for item in BUILDERS])
def test_committed_store_regenerates_byte_identically(name, builder, path):
    module = importlib.import_module(name)
    first, second = _build(module, builder), _build(module, builder)
    assert first == second, f"{name}: two builds in one process differ"
    assert first == getattr(module, path).read_bytes(), f"{name}: committed store is stale; regenerate it with its write_* function"
    xax_compiler.verify_store(xax_compiler.StoreReader(first))
