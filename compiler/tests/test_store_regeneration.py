"""STORE_REGENERATION (W2, ADR-361): every committed self-hosting store is frozen and is exactly its evolution ledger's
chain end: its baseline with the ledger's transactions applied, store + transaction = next store, byte for byte.

No Python builder makes these stores any more (``xax_selfhost_evolution``).  On every host: each store's ledger chain is
well formed and ends at the committed bytes; each transaction replayed with the Python reference engine
(``apply_reference``, equal to the production compiler's ``edit``) from the store it started at makes the store it
recorded, where the repository still holds that earlier store; each frozen store verifies.  The request store is still
derived from the driver store, and the helper generators that unit tests compile make the very functions the frozen
driver holds.  On Linux x86-64 ``test_xax_selfhost_evolution`` replays the ledger with ``xaxc edit`` itself.
"""
import platform
import subprocess
import sys

import pytest

import xax_compiler
import xax_selfhost_evolution as EV

FROZEN = EV.frozen_stores()
TRANSACTIONS = EV.ledger().transactions


def test_every_committed_self_hosting_store_is_frozen():
    stores = {path.relative_to(EV.BOOTSTRAP).as_posix() for path in EV.BOOTSTRAP.glob("xax_*.xax")}
    stores.discard("xax_blake3_compress.xax")  # a corpus program (``xax_native_blake3``), not a compiler component
    # W3 (ADR-362): the retired M14 bootstrap's META-wrapper store is a frozen corpus program
    assert stores | {EV.REQUEST_STORE, "m14_selfhost_compiler.xax"} == set(FROZEN)


@pytest.mark.skipif(not (sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")),
                    reason="the native ledger program and the seed that builds it are Linux x86-64 executables")
def test_ledger_chains_end_at_the_committed_stores():
    check = subprocess.run(["sh", str(EV.EVOLUTION_DIRECTORY / "evolve.sh"), "check"], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    for record, store, _before, _after in TRANSACTIONS:
        assert record.is_file(), f"{record.name} ({store}) is missing from bootstrap/evolution"


@pytest.mark.parametrize("index", range(len(TRANSACTIONS)), ids=[f"{t[0].name}:{t[1]}" for t in TRANSACTIONS])
def test_transaction_makes_the_next_store(index):
    record, store, before, after = TRANSACTIONS[index]
    if EV.is_batch(record):  # N0.4 (ADR-372): native batch text; the assembler is the compiler's, test_xax_selfhost_evolution replays it
        pytest.skip(f"NATIVE: {record.name} is a batch, replayed with xaxc edit only")
    data = EV.before_store(store, before)
    if data is None:
        pytest.skip(f"UNAVAILABLE: the repository does not hold {store}'s earlier store {before}")
    made = EV.replay_reference(record, data)
    assert EV.blob_id(made) == after, f"{record.name} on {store} makes {EV.blob_id(made)}, the ledger records {after}"
    if after == EV.ledger().heads()[store]:
        assert made == EV.store_path(store).read_bytes()


@pytest.mark.parametrize("store", FROZEN)
def test_frozen_store_verifies(store):
    xax_compiler.verify_store(xax_compiler.StoreReader(EV.store_path(store).read_bytes()))


def test_the_request_store_is_derived_from_the_driver_store():
    from xax_selfhost_compiler import compiler_request

    assert compiler_request()[0].data == EV.store_path(EV.REQUEST_STORE).read_bytes()


@pytest.mark.parametrize("module", ["xax_selfhost_edit", "xax_selfhost_semantic", "xax_selfhost_ed25519"])
def test_kept_helper_generators_make_the_frozen_functions(module):
    """The edit engine's, the semantic index's and Ed25519's generators stay for their helper-level tests (ADR-361); a
    transaction that changes one of their functions in the driver store fails this until the generator follows it or
    those tests move to the store."""
    import importlib

    building = xax_compiler._TYPING_BUILDING
    xax_compiler._TYPING_BUILDING = True
    try:
        functions, _objects = importlib.import_module(module).build_functions()
    finally:
        xax_compiler._TYPING_BUILDING = building
    driver = {item.cid for item in xax_compiler.StoreReader(EV.GENERAL_STORE_PATH.read_bytes()).objects()}
    assert {name for name, function in functions.items() if function.cid not in driver} == NATIVELY_EVOLVED.get(module, set())


# After N0 (ADR-367) a kept generator does not follow a native transaction: these helpers changed natively (ledger
# 0012: ``define``'s ``object`` form reached ``ws_translate`` and ``ws_command`` through ``ws_tr_define``).
NATIVELY_EVOLVED = {"xax_selfhost_edit": {"ws_translate", "ws_command"}}
