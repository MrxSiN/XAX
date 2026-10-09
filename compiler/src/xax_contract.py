"""``xax-host-contract-v1``: the versioned interface host integrations may depend on (ADR-225).

The ``xax-compiler`` distribution version does not identify an interface: it stays ``0.1.0`` while the compiler
changes daily.  Integrations outside this repository (build services, tool servers such as an MCP adapter, test
harnesses) depend on the names below and on the formats they produce; everything else is internal and may change
without notice.  Rules: adding a name, a carrier field, or a contract clause bumps ``HOST_CONTRACT_MINOR``;
removing or changing the meaning of one requires a new ``HOST_CONTRACT`` identity.  ``tests/test_xax_contract.py``
fails while a listed name is missing.

Tooling, not semantics: listing an interface here changes nothing about XAX meaning, which stays the canonical
semantic graph.
"""

from __future__ import annotations

import importlib

HOST_CONTRACT = "xax-host-contract-v1"
HOST_CONTRACT_MINOR = 3  # 1: initial surface, including linux.startup carrier entities and linux-x86_64-process-v1;
# 2: byte-view widening of checked accesses (ADR-231); 3: xax_native.prepare, readying component images (ADR-250)

FORMATS = {
    "construct_carrier": "xax-construct-v1",        # xax_construct.FORMAT (ADR-210, ADR-223)
    "linux_process": "linux-x86_64-process-v1",     # xax_linux.process_contract() (ADR-224)
    "linux_startup_abi": "linux-x86_64-startup-v1",  # ADR-094
    "local_edit_grammar": "ADR-200",                 # xax_local_protocol.edit_grammar(), identified by edit_grammar_id()
    # ADR-231: checked.load/store.bits.le sizes on a bits<8> view (the value type is bits<8*size>); a JSON list so the
    # description stays plain data.  RISC-V and SPIR-V reject sizes above 1 on byte views.
    "checked_byte_view_widths": [1, 2, 4, 8],       # xax_compiler.CHECKED_BYTE_VIEW_WIDTHS
}

INTERFACES = {
    "xax_construct": ("FORMAT", "construct", "Constructed"),
    "xax_workspace": ("Workspace", "Transaction", "RootRef", "TransactionResult", "CandidateVerification"),
    "xax_local_protocol": ("LocalMutationSession", "edit_grammar", "edit_grammar_id"),
    "xax_build": ("build", "build_request", "resolve_packages", "snapshot_store", "decode_snapshot", "decode_request",
                  "decode_package", "decode_provenance", "ArtifactKind", "BuildResult"),
    "xax_compiler": ("StoreReader", "XaxError", "Diagnostic", "Kind", "Operation", "verify_store", "decode_native_target",
                     "x86_64_linux_exec_target", "X86_64_LINUX_ABI", "X86_64_LINUX_ELF_EXEC_FORMAT"),
    "xax_linux": ("linux_api", "linux_startup_api", "process_contract", "LINUX_X86_64_PROCESS_CONTRACT"),
    "xax_artifact": ("BOOTSTRAP_COMPILER_IDENTITY_V1",),
    "xax_native": ("AUTHORITY", "verify_component_store", "prepare", "PREPARE_COMPONENTS"),
}


def describe() -> dict:
    """The contract identity, minor revision, formats and interface names, as plain data."""
    return {"contract": HOST_CONTRACT, "minor": HOST_CONTRACT_MINOR, "formats": dict(FORMATS),
            "interfaces": {module: list(names) for module, names in INTERFACES.items()}}


def missing() -> list[str]:
    """Names this checkout fails to provide (empty when the contract holds)."""
    absent = []
    for module, names in INTERFACES.items():
        try:
            loaded = importlib.import_module(module)
        except ImportError:
            absent.append(module)
            continue
        absent += [f"{module}.{name}" for name in names if not hasattr(loaded, name)]
    return absent
